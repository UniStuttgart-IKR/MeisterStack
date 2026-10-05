// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Target-side system activation, rollback, host locks, garbage collection and key rotation.
//!
//! Activation records the previous system and arms a transient rollback timer before
//! changing the profile. `switch` activates immediately; `boot` uses systemd-boot
//! one-shot entries and requires a later reboot. Confirmation and rollback persist
//! intent before changing the machine. Timers do not survive reboot.
//!
//! Runner, Files and Clock provide command, filesystem and time effects for tests.

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use chrono::{DateTime, TimeDelta, Utc};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::effects::{Clock, Entry, Files};
use crate::ids::sha256_hex;
use crate::observation::{BootedKernel, Lock, Txn, TxnState};
use crate::observe::{ACTIVATE_STATUS_SCHEMA, ActivateStatus};
use crate::run::{Cmd, Effect, Expect, Runner};

/// Schema for the target-side transaction record; fleet observations use a separate view.
pub const TXN_SCHEMA: &str = "meister-deploy/activate-txn/1";

/// The profile every NixOS system boots from.
pub const SYSTEM_PROFILE: &str = "/nix/var/nix/profiles/system";

/// What `/run` says about the system that is running and the one that booted.
pub const CURRENT_SYSTEM: &str = "/run/current-system";
pub const BOOTED_SYSTEM: &str = "/run/booted-system";

/// Deadline for short local commands.
const QUICK: Duration = Duration::from_secs(30);

/// Deadline for profile changes and `switch-to-configuration`.
const SWITCH: Duration = Duration::from_secs(900);

/// How long the garbage collector may take. It walks the whole store.
const COLLECT: Duration = Duration::from_secs(3600);

/// Maximum wait for a busy transaction when the rollback timer fires.
/// Allows two switch deadlines plus four short commands.
const DEADLINE_PATIENCE: Duration = Duration::from_secs(2 * 900 + 4 * 30);

/// How often the waiting deadline asks again.
const DEADLINE_POLL: Duration = Duration::from_secs(2);

/// Default `meisterstack.pki.dir` on managed hosts.
pub const DEFAULT_PKI_DIR: &str = "/var/lib/meisterstack/pki";

/// Owner of generated private keys. Keys are created mode 0600, then assigned to this user.
pub const KEY_OWNER: &str = "meister";

/// Fallback PATH for transient rollback units. NixOS commands live in the system profile;
/// the helper binary can supply a different PATH.
pub const SYSTEM_PATH: &str = "/run/current-system/sw/bin";

/// Activation mode, also used when restoring the previous system.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    /// Activate immediately; rollback uses `switch-to-configuration switch`.
    Switch,
    /// The running system is left alone and the next boot is the new one.
    /// The way back is the boot entry, which is why it needs systemd-boot.
    Boot,
}

impl Mode {
    pub fn as_str(self) -> &'static str {
        match self {
            Mode::Switch => "switch",
            Mode::Boot => "boot",
        }
    }

    pub fn parse(text: &str) -> Result<Mode> {
        match text {
            "switch" => Ok(Mode::Switch),
            "boot" => Ok(Mode::Boot),
            other => bail!(
                "{other:?} is not an activation mode. `switch` changes the running system \
                 now; `boot` leaves it alone and makes the new one the next boot."
            ),
        }
    }

    /// The argument `switch-to-configuration` takes for this mode.
    fn switch_argument(self) -> &'static str {
        match self {
            Mode::Switch => "switch",
            Mode::Boot => "boot",
        }
    }
}

impl std::fmt::Display for Mode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.pad(self.as_str())
    }
}

/// Where a machine was before an activation, in the only two terms a way
/// back can be expressed in.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SystemPoint {
    /// Resolved system path. Activation refuses a previous system it cannot resolve.
    pub toplevel: Option<String>,
    pub generation: Option<u64>,
}

/// Audit record for explicitly retiring an inconsistent transaction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ForcedRetirement {
    /// Operator reason retained in the forced-retirement audit record.
    pub reason: String,
    /// The run that asked, where there was one.
    pub run_id: Option<String>,
    pub at: DateTime<Utc>,
    /// The state the record was in when it was put aside.
    pub was: TxnState,
}


/// One transaction, on disk, on the target.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TxnRecord {
    pub schema: String,
    pub id: String,
    /// The run that opened it, so that a second operator can see whose it
    /// is. Optional because a hand-driven activation has no run.
    pub run_id: Option<String>,
    pub previous: SystemPoint,
    pub desired: String,
    pub mode: Mode,
    pub started_at: DateTime<Utc>,
    /// Rollback deadline; absent when `confirm_within` is zero.
    pub deadline: Option<DateTime<Utc>>,
    pub state: TxnState,
    /// Why it is in that state, for the two states that have a reason:
    /// `reverted` and `inconsistent`.
    pub reason: Option<String>,
    /// When the state last moved. The record is the evidence, and evidence
    /// without a time on it is half of one.
    pub changed_at: DateTime<Utc>,
    /// Present only after forced retirement; omitted for compatibility with older records.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retired_by_force: Option<ForcedRetirement>,

}

impl TxnRecord {
    pub fn to_json(&self) -> Result<Vec<u8>> {
        let mut bytes = serde_json::to_vec_pretty(self)
            .map_err(|e| anyhow::anyhow!("writing the transaction record failed: {e}"))?;
        bytes.push(b'\n');
        Ok(bytes)
    }

    pub fn from_json(text: &str, origin: &str) -> Result<TxnRecord> {
        crate::manifest::parse_checked(text, origin, TXN_SCHEMA)
    }

    /// States requiring recovery or a decision before another activation may begin.
    pub fn is_open(&self) -> bool {
        matches!(
            self.state,
            TxnState::Staged
                | TxnState::Pending
                | TxnState::Confirming
                | TxnState::Reverting
                | TxnState::Inconsistent
        )
    }

    /// Serialized transaction-state name.
    pub fn state_word(&self) -> &'static str {
        self.state.as_str_lower()
    }

    /// The transaction as the fleet sees it, through `status --json`.
    pub fn view(&self) -> Txn {
        Txn {
            id: self.id.clone(),
            state: self.state,
            target_system: Some(self.desired.clone()),
            deadline: self.deadline,
            run_id: self.run_id.clone(),
        }
    }
}

/// Restrict transaction IDs to filename-safe ASCII and a bounded length.
fn check_id(id: &str) -> Result<()> {
    let ok = !id.is_empty()
        && id.len() <= 128
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_');
    if !ok {
        bail!(
            "{id:?} is not a transaction id this program will write: a transaction is a file \
             in its own directory, so the id may hold letters, digits, `-` and `_` only, and \
             at most 128 of them."
        );
    }
    Ok(())
}



/// The pid out of a `<id>.deciding` file, which reads `<verb> pid <n> at
/// <time>`. `None` for anything this program did not write.
fn deciding_pid(held: &str) -> Option<u32> {
    let rest = held.split_once(" pid ")?.1;
    let digits = rest.split_whitespace().next()?;
    digits.parse().ok()
}

/// Check local process existence with signal 0; EPERM also means the process exists.
fn is_running(pid: u32) -> bool {
    let Ok(pid) = i32::try_from(pid) else {
        return false;
    };
    if pid <= 0 {
        return false;
    }
    matches!(
        nix::sys::signal::kill(nix::unistd::Pid::from_raw(pid), None),
        Ok(()) | Err(nix::errno::Errno::EPERM)
    )
}

/// Process identity and liveness behind the decision lock, injectable so a test
/// can model a crashed holder and its successor.
pub trait Processes {
    fn own_pid(&self) -> u32;
    fn alive(&self, pid: u32) -> bool;
}

/// This process and the kernel's process table.
pub struct RealProcesses;

impl Processes for RealProcesses {
    fn own_pid(&self) -> u32 {
        std::process::id()
    }

    fn alive(&self, pid: u32) -> bool {
        is_running(pid)
    }
}

/// A live process holds this transaction’s decision lock.
/// The timer retries this typed error; operator requests fail immediately.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BeingDecided {
    pub id: String,
    /// The record as it stands: `<verb> pid <n> at <time>`.
    pub holder: String,
}

impl std::fmt::Display for BeingDecided {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "the transaction {} is being decided right now ({}). A confirm and a revert at \
             once leave the machine on one system and the record saying the other, so this \
             one did nothing.",
            self.id, self.holder
        )
    }
}

impl std::error::Error for BeingDecided {}

/// Caller policy for reverting a transaction in `confirming` state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevertAsker {
    /// Ordinary rollback; refuses an unfinished confirmation.
    Operator,
    /// Deadline rollback; leaves an unfinished confirmation unchanged.
    Deadline,
    /// Explicit override of an unfinished confirmation; requires a reason.
    Force,
}



/// The state of the machine, and the tools to change it.
pub struct Helper<'a> {
    pub runner: &'a dyn Runner,
    pub files: &'a dyn Files,
    pub clock: &'a dyn Clock,
    /// `/var/lib/meisterstack/deploy` on a real host; a temporary directory
    /// in a test. The records and the lock live under it.
    pub deploy_dir: PathBuf,
    /// The system profile. An argument so that a test can move one that is
    /// not this machine's.
    pub profile: PathBuf,
    /// Executable used by the rollback timer. A store path remains stable across activation.
    pub own_exe: PathBuf,
    /// PATH passed to the rollback timer; injected rather than read from the environment.
    pub timer_path: String,
    /// Directory containing this host’s private keys and certificates.
    pub pki_dir: PathBuf,
    /// Who holds a decision lock, and whether that holder still lives.
    pub processes: &'a dyn Processes,
}

impl<'a> Helper<'a> {
    pub fn new(
        runner: &'a dyn Runner,
        files: &'a dyn Files,
        clock: &'a dyn Clock,
        deploy_dir: impl Into<PathBuf>,
        own_exe: impl Into<PathBuf>,
    ) -> Helper<'a> {
        Helper {
            runner,
            files,
            clock,
            deploy_dir: deploy_dir.into(),
            profile: PathBuf::from(SYSTEM_PROFILE),
            own_exe: own_exe.into(),
            timer_path: SYSTEM_PATH.to_string(),
            pki_dir: PathBuf::from(DEFAULT_PKI_DIR),
            processes: &RealProcesses,
        }
    }

    /// The process identity a test models instead of this process's.
    pub fn with_processes(mut self, processes: &'a dyn Processes) -> Helper<'a> {
        self.processes = processes;
        self
    }

    /// Where the keys are, for a host whose `meisterstack.pki.dir` is not
    /// the default and for a test.
    pub fn with_pki_dir(mut self, dir: impl Into<PathBuf>) -> Helper<'a> {
        self.pki_dir = dir.into();
        self
    }

    /// The `PATH` the revert timer runs with. The binary passes its own.
    pub fn with_timer_path(mut self, path: impl Into<String>) -> Helper<'a> {
        let path = path.into();
        if !path.is_empty() {
            self.timer_path = path;
        }
        self
    }

    pub fn with_profile(mut self, profile: impl Into<PathBuf>) -> Helper<'a> {
        self.profile = profile.into();
        self
    }

    pub fn txn_dir(&self) -> PathBuf {
        self.deploy_dir.join("txn")
    }

    pub fn txn_path(&self, id: &str) -> PathBuf {
        self.txn_dir().join(format!("{id}.json"))
    }

    /// Archive suffix excluded from the probe’s `*.json` transaction scan.
    pub fn txn_archive(&self, id: &str) -> PathBuf {
        self.txn_dir().join(format!("{id}.json.done"))
    }

    pub fn lock_dir(&self) -> PathBuf {
        self.deploy_dir.join("lock")
    }

    pub fn lock_path(&self) -> PathBuf {
        self.lock_dir().join("owner.json")
    }

    // -----------------------------------------------------------------
    // status
    // -----------------------------------------------------------------

    /// Report readable host facts; unavailable values remain null.
    pub fn status(&self) -> Result<ActivateStatus> {
        Ok(ActivateStatus {
            schema: ACTIVATE_STATUS_SCHEMA.to_string(),
            current_system: self.resolve(Path::new(CURRENT_SYSTEM)),
            booted_system: self.resolve(Path::new(BOOTED_SYSTEM)),
            // The profile names the intended next system, not the fallback boot default.
            next_boot_system: self.resolve(&self.profile),
            generation: self.generation(),
            kernel_running: self.kernel_running(),
            kernel_booted: self.kernel_booted(),
            open_txns: self.open_txns()?,
            lock: self.read_lock()?,
        })
    }

    /// Resolve up to eight symlink hops, including relative generation links.
    /// Return None when the initial path cannot be read or the hop limit is reached.
    fn resolve(&self, path: &Path) -> Option<String> {
        let mut at = path.to_path_buf();
        let mut followed = 0;
        while followed < 8 {
            match self.files.entry(&at) {
                Ok(Entry::Symlink { target }) => {
                    at = if target.is_absolute() {
                        target
                    } else {
                        at.parent().unwrap_or(Path::new("/")).join(target)
                    };
                    followed += 1;
                }
                // A store path is a directory, which is where the chain ends.
                Ok(_) => return Some(at.display().to_string()),
                // Report a dangling link’s target; `stage` separately checks store validity.
                Err(_) if followed > 0 => return Some(at.display().to_string()),
                Err(_) => return None,
            }
        }
        None
    }

    /// `system-42-link` -> 42. From the unresolved link, because the
    /// resolved one is a store path and carries no generation number.
    fn generation(&self) -> Option<u64> {
        let Ok(Entry::Symlink { target }) = self.files.entry(&self.profile) else {
            return None;
        };
        generation_of(&target)
    }

    fn kernel_running(&self) -> Option<String> {
        let cmd = Cmd::new(Effect::Read, "uname", QUICK).arg("-r");
        self.runner
            .run(&cmd)
            .ok()
            .filter(|out| out.ok())
            .map(|out| out.trimmed().to_string())
            .filter(|s| !s.is_empty())
    }

    /// Read the booted generation’s kernel, initrd and parameter digest as one tuple.
    /// Return None if any field is unavailable; hash parameters to avoid exposing tokens.
    fn kernel_booted(&self) -> Option<BootedKernel> {
        // Resolve the generation first so all three reads use the same store path.
        let booted = PathBuf::from(self.resolve(Path::new(BOOTED_SYSTEM))?);
        let kernel = self.resolve(&booted.join("kernel"))?;
        let initrd = self.resolve(&booted.join("initrd"))?;
        let params = self.files.read(&booted.join("kernel-params")).ok()?;
        Some(BootedKernel {
            kernel_store_path: kernel,
            initrd_store_path: initrd,
            kernel_params_sha256: sha256_hex(&params),
        })
    }

    // -----------------------------------------------------------------
    // the transaction records
    // -----------------------------------------------------------------

    /// Read system transaction JSON files. Malformed JSON becomes `inconsistent`;
    /// files that cannot be read are currently skipped.
    pub fn records(&self) -> Result<Vec<TxnRecord>> {
        let mut out = Vec::new();
        for path in self.files.list_dir(&self.txn_dir())? {
            let Some(name) = path.file_name().map(|n| n.to_string_lossy().into_owned()) else {
                continue;
            };
            let Some(id) = name.strip_suffix(".json") else {
                continue;
            };
            // Key rotation records have their own schema and reader.
            if id.starts_with("keys-") {
                continue;
            }

            let text = match self.files.read_to_string(&path) {
                Ok(text) => text,
                Err(_) => continue,
            };
            match TxnRecord::from_json(&text, &path.display().to_string()) {
                Ok(record) => out.push(record),
                Err(e) => out.push(TxnRecord {
                    schema: TXN_SCHEMA.to_string(),
                    id: id.to_string(),
                    run_id: None,
                    previous: SystemPoint {
                        toplevel: None,
                        generation: None,
                    },
                    desired: String::new(),
                    mode: Mode::Switch,
                    started_at: self.clock.now(),
                    deadline: None,
                    state: TxnState::Inconsistent,
                    reason: Some(format!(
                        "{} could not be read as a transaction record: {e:#}",
                        path.display()
                    )),
                    changed_at: self.clock.now(),
                    retired_by_force: None,
                }),
            }
        }
        Ok(out)
    }

    /// The records that are still in flight, as the fleet sees them.
    fn open_txns(&self) -> Result<Vec<Txn>> {
        Ok(self
            .records()?
            .into_iter()
            .filter(TxnRecord::is_open)
            .map(|r| r.view())
            .collect())
    }

    pub fn record(&self, id: &str) -> Result<TxnRecord> {
        check_id(id)?;
        let path = self.txn_path(id);
        let text = self.files.read_to_string(&path).with_context(|| {
            format!(
                "there is no transaction {id} on this host ({} could not be read)",
                path.display()
            )
        })?;
        TxnRecord::from_json(&text, &path.display().to_string())
    }

    /// Atomically persist a mode-0600 record before dependent host changes.
    fn write_record(&self, record: &TxnRecord) -> Result<()> {
        self.files.create_dir_all(&self.txn_dir())?;
        self.files
            .write_atomic(&self.txn_path(&record.id), &record.to_json()?, 0o600)
    }

    // -----------------------------------------------------------------
    // stage
    // -----------------------------------------------------------------

    /// Check store registration and the NixOS switcher without activating the system.
    /// `nix-store --check-validity` does not rehash closure contents or verify signatures.
    pub fn stage(&self, toplevel: &str) -> Result<()> {
        let cmd = Cmd::new(Effect::Read, "nix-store", SWITCH)
            .arg("--check-validity")
            .arg(toplevel);
        self.runner.run(&cmd).with_context(|| {
            format!(
                "{toplevel} is not here as a whole closure. `nix copy --to ssh-ng://` has to \
                 carry all of it before anything is activated."
            )
        })?;
        let switcher = Path::new(toplevel).join("bin/switch-to-configuration");
        if !self.files.exists(&switcher) {
            bail!(
                "{toplevel} is in the store and is not a NixOS system: it has no \
                 bin/switch-to-configuration, so nothing here could activate it."
            );
        }
        Ok(())
    }

    // -----------------------------------------------------------------
    // activate
    // -----------------------------------------------------------------

    /// Record the previous system and arm rollback before moving the profile.
    /// The transaction’s decision lock covers the forward path. Failed or overdue
    /// activation attempts rollback; failed rollback leaves an inconsistent record.
    /// Boot mode retains the previous default and selects the new generation once.
    #[allow(clippy::too_many_arguments)]
    pub fn activate(
        &self,
        id: &str,
        toplevel: &str,
        mode: Mode,
        confirm_within: u64,
        run_id: Option<&str>,
    ) -> Result<TxnRecord> {
        check_id(id)?;
        self.refuse_if_held(run_id)?;
        if let Some(open) = self.records()?.iter().find(|r| r.is_open()) {
            bail!(
                "this host already has the transaction {} open ({}). One at a time: confirm \
                 it, revert it, or read it with `meister-activate txn show --txn {}`.",
                open.id,
                open.state.as_str_lower(),
                open.id
            );
        }
        self.stage(toplevel)?;

        let previous = SystemPoint {
            toplevel: self.resolve(&self.profile),
            generation: self.generation(),
        };
        if previous.toplevel.is_none() {
            bail!(
                "{} does not resolve to a system, so there would be nothing to roll back to. \
                 A host is installed before it is deployed to.",
                self.profile.display()
            );
        }
        // Boot fallback requires systemd-boot and a known previous generation.
        if mode == Mode::Boot {
            self.require_systemd_boot()?;
            if previous.generation.is_none() {
                bail!(
                    "this host's system profile does not name a generation, so there is no \
                     boot entry to fall back to. Use --mode switch."
                );
            }
        }

        let now = self.clock.now();
        let deadline = (confirm_within > 0).then(|| {
            now + TimeDelta::try_seconds(confirm_within as i64).unwrap_or_else(TimeDelta::zero)
        });
        let mut record = TxnRecord {
            schema: TXN_SCHEMA.to_string(),
            id: id.to_string(),
            run_id: run_id.map(str::to_string),
            previous,
            desired: toplevel.to_string(),
            mode,
            started_at: now,
            deadline,
            state: TxnState::Pending,
            reason: None,
            changed_at: now,
            retired_by_force: None,
        };
        // Hold the decision lock through activation so the timer cannot revert mid-switch.
        // If activation outlasts its deadline, this process performs the rollback.
        self.deciding(id, "activate", || {
            self.write_record(&record)?;

            if deadline.is_some()
                && let Err(e) = self.arm_timer(id, confirm_within)
            {
                // No profile change occurred; close the record because no timer was armed.
                record.state = TxnState::Reverted;
                record.changed_at = self.clock.now();
                record.reason = Some(format!("{e:#}"));
                self.write_record(&record)?;
                return Err(e);
            }

            let previous_name = record
                .previous
                .toplevel
                .clone()
                .unwrap_or_else(|| "its previous system".to_string());
            match self.go_forward(&record) {
                Ok(()) => {
                    let Some(passed) = deadline.filter(|d| self.clock.now() >= *d) else {
                        return Ok(record);
                    };
                    // The switch exceeded its confirmation window; roll back while holding the lock.
                    let because = format!(
                        "the activation itself took until {} and the deadline for confirming \
                         it was {}: nobody could have confirmed it in time",
                        self.clock.now().to_rfc3339(),
                        passed.to_rfc3339()
                    );
                    match self.revert_held(id, Some(&because), RevertAsker::Deadline) {
                        Ok(_) => bail!("{id} was taken back to {previous_name}: {because}."),
                        Err(back) => {
                            record.state = TxnState::Inconsistent;
                            record.changed_at = self.clock.now();
                            record.reason =
                                Some(format!("{because}; and the way back failed: {back:#}"));
                            self.write_record(&record)?;
                            bail!(
                                "{because}, and {id} could not be taken back either ({back:#}); \
                                 this host needs a person"
                            )
                        }
                    }
                }
                Err(e) => {
                    // A failed switch may have moved the profile. Restore it under the same lock;
                    // failed recovery leaves an inconsistent record for operator review.
                    let because = format!("the activation itself failed: {e:#}");
                    match self.revert_held(id, Some(&because), RevertAsker::Operator) {
                        Ok(_) => Err(e.context(format!("{id} was taken back to {previous_name}"))),
                        Err(back) => {
                            record.state = TxnState::Inconsistent;
                            record.changed_at = self.clock.now();
                            record.reason =
                                Some(format!("{because}; and so did the way back: {back:#}"));
                            self.write_record(&record)?;
                            Err(e.context(format!(
                                "and {id} could not be taken back either ({back:#}); this host \
                                 needs a person"
                            )))
                        }
                    }
                }
            }
        })
    }

    /// Move the profile, switch, and in boot mode arrange the menu.
    fn go_forward(&self, record: &TxnRecord) -> Result<()> {
        let set = Cmd::new(Effect::TargetWrite, "nix-env", SWITCH)
            .arg("-p")
            .arg(self.profile.display().to_string())
            .arg("--set")
            .arg(&record.desired);
        self.runner.run(&set)?;

        let switcher = Path::new(&record.desired).join("bin/switch-to-configuration");
        let switch = Cmd::new(Effect::TargetWrite, switcher.display().to_string(), SWITCH)
            .arg(record.mode.switch_argument());
        self.runner.run(&switch)?;

        let generation = self.generation();
        if record.mode == Mode::Boot {
            let new = generation.ok_or_else(|| {
                anyhow::anyhow!(
                    "the system profile does not name a generation after the switch, so the \
                     boot entry to try once cannot be named."
                )
            })?;
            let previous = record.previous.generation.ok_or_else(|| {
                anyhow::anyhow!("this transaction records no previous generation.")
            })?;
            // Override the new loader default with the previous generation, then select
            // the new entry for one boot only.
            self.runner.run(
                &Cmd::new(Effect::TargetWrite, "bootctl", QUICK)
                    .arg("set-default")
                    .arg(entry_of(previous)),
            )?;
            self.runner.run(
                &Cmd::new(Effect::TargetWrite, "bootctl", QUICK)
                    .arg("set-oneshot")
                    .arg(entry_of(new)),
            )?;
        }
        Ok(())
    }

    /// Require systemd-boot for boot-mode activation.
    fn require_systemd_boot(&self) -> Result<()> {
        let cmd = Cmd::new(Effect::Read, "bootctl", QUICK)
            .arg("is-installed")
            .expect(Expect::Codes(vec![0, 1]));
        let out = self.runner.run(&cmd)?;
        if out.ok() && out.trimmed() == "yes" {
            return Ok(());
        }
        bail!(
            "there is no boot fallback on this host: bootctl says systemd-boot is not \
             installed ({}), and a one-shot boot entry is the only way a machine that does \
             not come up can take itself back. Use --mode switch, or confirm this boot by \
             hand after it comes up.",
            if out.trimmed().is_empty() {
                "no answer"
            } else {
                out.trimmed()
            }
        );
    }

    /// Arm a transient rollback timer independent of declared generation units.
    /// It survives activation, but not reboot; boot mode also configures a fallback entry.
    fn arm_timer(&self, id: &str, seconds: u64) -> Result<()> {
        let cmd = Cmd::new(Effect::TargetWrite, "systemd-run", QUICK)
            .arg(format!("--on-active={seconds}"))
            .arg(format!("--unit={}", timer_unit(id)))
            // Unload completed units so the transaction ID can be reused.
            .arg("--collect")
            .arg(format!(
                "--description=meister-deploy reverts the transaction {id} unless it is \
                 confirmed"
            ))
            // Without this the unit gets systemd's own default PATH and
            // finds no `nix-env` — see [`SYSTEM_PATH`].
            .arg(format!("--setenv=PATH={}", self.timer_path))
            .arg(self.own_exe.display().to_string())
            .arg("revert")
            .arg("--txn")
            .arg(id)
            .arg("--deploy-dir")
            .arg(self.deploy_dir.display().to_string())
            .arg("--profile")
            .arg(self.profile.display().to_string())
            // Timer rollback leaves a persisted `confirming` decision unchanged.
            .arg("--by-timer")
            .arg("--because")
            .arg("nobody confirmed this activation before its deadline");
        self.runner.run(&cmd).with_context(|| {
            format!(
                "the revert timer for {id} could not be armed, so this activation has no way \
                 back and was not started."
            )
        })?;
        Ok(())
    }

    /// Stop the timer and reject a subsequent active/activating state.
    /// A missing timer is acceptable.
    fn stop_timer(&self, id: &str) -> Result<()> {
        let unit = timer_unit(id);
        let stop = Cmd::new(Effect::TargetWrite, "systemctl", QUICK)
            .arg("stop")
            .arg(format!("{unit}.timer"))
            .expect(Expect::AnyExit);
        self.runner.run(&stop)?;
        let check = Cmd::new(Effect::Read, "systemctl", QUICK)
            .arg("is-active")
            .arg(format!("{unit}.timer"))
            .expect(Expect::AnyExit);
        let out = self.runner.run(&check)?;
        let state = out.trimmed();
        if state == "active" || state == "activating" {
            bail!(
                "the revert timer {unit}.timer is still {state} after being told to stop. \
                 Nothing else was changed: a confirmation that leaves the timer running \
                 would be taken back by it."
            );
        }
        Ok(())
    }

    // -----------------------------------------------------------------
    // confirm and revert
    // -----------------------------------------------------------------

    /// Serialize decisions for one transaction with an exclusive-create lock file.
    /// A dead local holder can be reclaimed; malformed lock contents require review.
    fn deciding<T>(&self, id: &str, what: &str, f: impl FnOnce() -> Result<T>) -> Result<T> {
        let path = self.txn_dir().join(format!("{id}.deciding"));
        self.files.create_dir_all(&self.txn_dir())?;
        let mine = format!(
            "{what} pid {} at {}",
            self.processes.own_pid(),
            self.clock.now()
        );
        self.hold_decision(id, &path, &mine)?;
        let out = f();
        // Release only a lock whose contents still match this process’s claim.
        match self.files.read_if_present(&path) {
            Ok(Some(held)) if held == mine => {
                if let Err(e) = self.files.remove_file(&path) {
                    eprintln!("note: {} was not removed: {e:#}", path.display());
                }
            }
            Ok(Some(held)) => eprintln!(
                "note: {} is held by {} now, so it was left where it is.",
                path.display(),
                held.trim()
            ),
            Ok(None) => {}
            Err(e) => eprintln!("note: {} could not be read back: {e:#}", path.display()),
        }
        out
    }

    /// Acquire `<id>.deciding`; reclaim a dead holder by renaming its record.
    /// Recheck the claimed record and restore a live holder without overwriting a new lock.
    /// A live PID, including this process’s PID, prevents acquisition.
    fn hold_decision(&self, id: &str, path: &Path, mine: &str) -> Result<()> {
        // Retry boundedly if the holder disappears between create and read.
        for _ in 0..4 {
            let Err(e) = self.files.create_new(path, mine.as_bytes(), 0o600) else {
                return Ok(());
            };
            let Some(held) = self.files.read_if_present(path)? else {
                continue;
            };
            match deciding_pid(&held) {
                Some(pid) if self.processes.alive(pid) => {
                    return Err(BeingDecided {
                        id: id.to_string(),
                        holder: held.trim().to_string(),
                    }
                    .into());
                }
                Some(_) => {}
                None => bail!(
                    "{} exists and is not a record this program wrote ({}), so the transaction \
                     {id} cannot be decided from here ({e:#}). Nothing here removes a file that \
                     might be somebody's lock: read it, and remove it by hand if it is rubbish.",
                    path.display(),
                    held.trim()
                ),
            }
            // Claim the stale record before attempting a fresh exclusive create.
            let claim = path.with_file_name(format!(
                "{id}.deciding.taken-by-{}",
                self.processes.own_pid()
            ));
            if self.files.rename(path, &claim).is_err() {
                // Retry from the start if another contender reclaimed the stale record.
                continue;
            }
            let carried = self.files.read_to_string(&claim).unwrap_or_default();
            if let Some(pid) = deciding_pid(&carried)
                && self.processes.alive(pid)
            {
                match self.files.create_new(path, carried.as_bytes(), 0o600) {
                    Ok(()) => {
                        let _ = self.files.remove_file(&claim);
                        return Err(BeingDecided {
                            id: id.to_string(),
                            holder: carried.trim().to_string(),
                        }
                        .into());
                    }
                    Err(back) => bail!(
                        "the transaction {id} is being decided right now ({}), and its lock could \
                         not be put back on {} ({back:#}) because something else took that name \
                         in the meantime. Nothing was decided; the record that was there is in \
                         {}.",
                        carried.trim(),
                        path.display(),
                        claim.display()
                    ),
                }
            }
            self.files.remove_file(&claim)?;
        }
        bail!(
            "the transaction {id} could not be held for this decision: {} kept changing hands. \
             Nothing was decided.",
            path.display()
        )
    }

    /// Keep it. The intent goes down, then the timer goes, then the record
    /// says so.
    pub fn confirm(&self, id: &str) -> Result<TxnRecord> {
        check_id(id)?;
        self.deciding(id, "confirm", || self.confirm_held(id))
    }

    fn confirm_held(&self, id: &str) -> Result<TxnRecord> {
        let mut record = self.record(id)?;
        match record.state {
            TxnState::Confirmed => return Ok(record),
            TxnState::Reverted => bail!(
                "the transaction {id} was already reverted ({}). A machine that has gone back \
                 is not confirmed afterwards; plan again.",
                record.reason.as_deref().unwrap_or("no reason recorded")
            ),
            // An interrupted rollback may already have moved the profile; finish it before confirming.
            TxnState::Reverting => bail!(
                "a revert of {id} began at {} and did not finish, so this record cannot say \
                 which system this machine is on and nothing here will confirm one. Finish \
                 the way back with `meister-activate revert --txn {id}` — repeating it is \
                 safe, it is the same profile and the same switch — and plan again.",
                record.changed_at
            ),
            TxnState::Inconsistent => bail!(
                "the record of {id} does not say a coherent thing, so there is nothing here \
                 to confirm. Read it with `meister-activate txn show --txn {id}`."
            ),
            // Retrying an unfinished confirmation repeats the same timer and boot-menu operations.
            TxnState::Staged | TxnState::Pending | TxnState::Confirming => {}
        }
        // Persist confirmation intent before stopping the timer so a crash remains recoverable.
        if record.state != TxnState::Confirming {
            record.state = TxnState::Confirming;
            record.changed_at = self.clock.now();
            self.write_record(&record)?;
        }
        if record.deadline.is_some() {
            self.stop_timer(id)?;
        }
        if record.mode == Mode::Boot {
            // After the intended boot, make the selected profile generation the default.
            let generation = self.generation().ok_or_else(|| {
                anyhow::anyhow!(
                    "the system profile does not name a generation, so the boot entry to \
                     make the default cannot be named. The timer is stopped and the record \
                     is untouched."
                )
            })?;
            self.runner.run(
                &Cmd::new(Effect::TargetWrite, "bootctl", QUICK)
                    .arg("set-default")
                    .arg(entry_of(generation)),
            )?;
        }
        record.state = TxnState::Confirmed;
        record.changed_at = self.clock.now();
        self.write_record(&record)?;
        Ok(record)
    }

    /// Restore the previous system; caller policy governs unfinished confirmations.
    pub fn revert(&self, id: &str, because: Option<&str>, asked: RevertAsker) -> Result<TxnRecord> {
        check_id(id)?;
        // A one-shot deadline waits for an active decision; ordinary callers may retry later.
        let started = self.clock.now();
        loop {
            match self.deciding(id, "revert", || self.revert_held(id, because, asked)) {
                Err(e)
                    if asked == RevertAsker::Deadline
                        && e.downcast_ref::<BeingDecided>().is_some() =>
                {
                    let waited = self.clock.now() - started;
                    let patience = TimeDelta::from_std(DEADLINE_PATIENCE)
                        .unwrap_or_else(|_| TimeDelta::zero());
                    if waited > patience {
                        return Err(e.context(format!(
                            "the deadline of {id} waited {} s for that decision to finish and \
                             gave up. The machine was left as it is and the record says what it \
                             said; somebody has to look at what holds the transaction.",
                            waited.num_seconds()
                        )));
                    }
                    self.clock.sleep(DEADLINE_POLL);
                }
                other => return other,
            }
        }
    }

    fn revert_held(
        &self,
        id: &str,
        because: Option<&str>,
        asked: RevertAsker,
    ) -> Result<TxnRecord> {
        let mut record = self.record(id)?;
        match record.state {
            TxnState::Confirmed => bail!(
                "the transaction {id} was confirmed, so it is not reverted: what a machine \
                 was confirmed on is what it runs. Plan the old system again if it has to go \
                 back."
            ),
            // Idempotent on purpose: the timer and an operator can both
            // arrive here, and the second one must not fail a rollout.
            TxnState::Reverted => return Ok(record),
            // The durable confirmation intent distinguishes an interrupted decision from silence.
            TxnState::Confirming => match asked {
                // Confirmation was requested; leave recovery to a repeated confirm or explicit force.
                RevertAsker::Deadline => return Ok(record),
                RevertAsker::Operator => bail!(
                    "a confirmation of {id} was in flight since {} and this revert did \
                     nothing: something decided to keep this system and did not live long \
                     enough to write it down. Finish that decision with `meister-activate \
                     confirm --txn {id}`, which is what a resume does — or, if this machine \
                     has to go back anyway, say `meister-activate revert --txn {id} --force \
                     --because \"<what you found>\"`.",
                    record.changed_at
                ),
                RevertAsker::Force => {}
            },
            // Retry interrupted rollback with the same profile and switcher.
            TxnState::Staged | TxnState::Pending | TxnState::Reverting | TxnState::Inconsistent => {
            }
        }
        // Forced reversal must retain the operator’s reason.
        if asked == RevertAsker::Force && because.map(str::trim).unwrap_or_default().is_empty() {
            bail!(
                "`revert --force` needs `--because <sentence>`: it takes a machine back over \
                 a confirmation somebody began, and the record is the only place that \
                 decision is written down."
            );
        }
        let previous = record.previous.toplevel.clone().ok_or_else(|| {
            anyhow::anyhow!(
                "the record of {id} names no previous system, so there is nothing to go back \
                 to. This needs a person: read it with `meister-activate txn show --txn {id}`."
            )
        })?;

        // Persist rollback intent and reason before changing the timer or profile.
        if record.state != TxnState::Reverting {
            record.state = TxnState::Reverting;
            record.changed_at = self.clock.now();
            record.reason = Some(because.unwrap_or("no reason was given").to_string());
            self.write_record(&record)?;
        }
        // The timer next, so that a revert that takes a while is not
        // started twice.
        if record.deadline.is_some() {
            let _ = self.stop_timer(id);
        }
        let set = Cmd::new(Effect::TargetWrite, "nix-env", SWITCH)
            .arg("-p")
            .arg(self.profile.display().to_string())
            .arg("--set")
            .arg(&previous);
        self.runner.run(&set)?;
        let switcher = Path::new(&previous).join("bin/switch-to-configuration");
        self.runner.run(
            &Cmd::new(Effect::TargetWrite, switcher.display().to_string(), SWITCH)
                .arg(record.mode.switch_argument()),
        )?;
        if record.mode == Mode::Boot {
            // Clear any unconsumed one-shot entry and restore the previous default.
            self.runner.run(
                &Cmd::new(Effect::TargetWrite, "bootctl", QUICK)
                    .arg("set-oneshot")
                    .arg(""),
            )?;
            if let Some(generation) = record.previous.generation {
                self.runner.run(
                    &Cmd::new(Effect::TargetWrite, "bootctl", QUICK)
                        .arg("set-default")
                        .arg(entry_of(generation)),
                )?;
            }
        }

        record.state = TxnState::Reverted;
        record.changed_at = self.clock.now();
        record.reason = Some(because.unwrap_or("no reason was given").to_string());
        self.write_record(&record)?;
        Ok(record)
    }

    /// Archive a finished transaction before removing its live record.
    /// An interrupted archive leaves the live file available to readers.
    pub fn retire(&self, id: &str, run_id: Option<&str>) -> Result<TxnRecord> {
        self.retire_inner(id, run_id, None)
    }

    /// Archive an inconsistent transaction with an explicit reason and audit fields.
    /// Other open states remain protected. This changes records only, not the host system.
    pub fn retire_forced(&self, id: &str, run_id: Option<&str>, reason: &str) -> Result<TxnRecord> {
        self.retire_inner(id, run_id, Some(reason))
    }

    fn retire_inner(
        &self,
        id: &str,
        run_id: Option<&str>,
        forced: Option<&str>,
    ) -> Result<TxnRecord> {
        let mut record = match self.record(id) {
            Ok(record) => record,
            // An existing archive makes repeated retirement idempotent.
            Err(e) => {
                let archive = self.txn_archive(id);
                if !self.files.exists(&archive) {
                    return Err(e);
                }
                return TxnRecord::from_json(
                    &self.files.read_to_string(&archive)?,
                    &archive.display().to_string(),
                );
            }
        };
        if let (Some(asked), Some(owner)) = (run_id, record.run_id.as_deref())
            && asked != owner
        {
            bail!(
                "the transaction {id} belongs to the run {owner} and {asked} asked to retire \
                 it. A record is retired by the run that opened it."
            );
        }
        if record.is_open() {
            match (forced, record.state) {
                (Some(reason), TxnState::Inconsistent) => {
                    let reason = reason.trim();
                    if reason.is_empty() {
                        bail!(
                            "`txn retire --force` needs `--reason <sentence>`: the archive is \
                             the only account of this decision there will ever be."
                        );
                    }
                    record.retired_by_force = Some(ForcedRetirement {
                        reason: reason.to_string(),
                        run_id: run_id.map(str::to_string),
                        at: self.clock.now(),
                        was: record.state,
                    });
                }
                (Some(_), state) => bail!(
                    "the transaction {id} is {} and `--force` does not take that away: the \
                     record is what says this machine may still have to go back. Finish it — \
                     `meister-activate confirm --txn {id}` or `meister-activate revert --txn \
                     {id}` — and retire it afterwards. Only an `inconsistent` record can be \
                     forced aside.",
                    state.as_str_lower()
                ),
                (None, TxnState::Inconsistent) => bail!(
                    "the transaction {id} is inconsistent and is not retired: a record is the \
                     only thing that says a machine may still have to go back. Read it with \
                     `meister-activate txn show --txn {id}`, compare the profile with \
                     /run/current-system and /run/booted-system, and if this record cannot \
                     say anything about the machine any more, put it aside with \
                     `meister-activate txn retire --txn {id} --force --reason \"<what you \
                     found>\"`."
                ),
                (None, state) => bail!(
                    "the transaction {id} is {} and is not retired: a record is the only thing \
                     that says a machine may still have to go back.",
                    state.as_str_lower()
                ),
            }
        }

        self.files
            .write_atomic(&self.txn_archive(id), &record.to_json()?, 0o600)?;
        self.files.remove_file(&self.txn_path(id))?;
        Ok(record)
    }

    // -----------------------------------------------------------------
    // the lock
    // -----------------------------------------------------------------

    /// Read the host lock; malformed JSON currently returns None without removing the file.
    pub fn read_lock(&self) -> Result<Option<Lock>> {
        let path = self.lock_path();
        if !self.files.exists(&path) {
            return Ok(None);
        }
        let text = self.files.read_to_string(&path)?;
        Ok(serde_json::from_str::<Lock>(&text).ok())
    }

    /// Acquire `lock/owner.json` using exclusive create. The containing directory may preexist.
    pub fn lock_acquire(&self, run_id: &str, operator: &str, pid: u32) -> Result<Lock> {
        let record = Lock {
            run_id: run_id.to_string(),
            operator: operator.to_string(),
            pid,
            acquired_at: self.clock.now(),
        };
        let bytes = serde_json::to_vec_pretty(&record)
            .map_err(|e| anyhow::anyhow!("writing the lock record failed: {e}"))?;
        self.files.create_dir_all(&self.lock_dir())?;
        match self.files.create_new(&self.lock_path(), &bytes, 0o600) {
            Ok(()) => Ok(record),
            Err(e) => match self.read_lock()? {
                // The same run and operator may resume with a new workstation PID.
                // Workstation locking supplies process exclusion; the target cannot validate that PID.
                Some(held) if held.run_id == run_id && held.operator == operator => Ok(held),
                Some(held) if held.run_id == run_id => bail!(
                    "this host is held by the run {} as it is carried by {}, and this is {}. \
                     One run is one writer: two operators carrying it write one journal twice \
                     and make it unreadable. Nothing was changed.",
                    held.run_id,
                    held.operator,
                    operator
                ),
                Some(held) => bail!(
                    "this host is held by the run {} since {} (operator {}, pid {}). \
                     Continue that run with `apply --resume {}`, or take it over with \
                     `apply --takeover {}` once you know it is gone. A lock here never \
                     expires by itself.",
                    held.run_id,
                    held.acquired_at,
                    held.operator,
                    held.pid,
                    held.run_id,
                    held.run_id
                ),
                None => bail!(
                    "{} exists and is not a lock record this program wrote ({e:#}). Read it, \
                     and remove it by hand if it is rubbish; nothing here overwrites a file \
                     that might be somebody's lock.",
                    self.lock_path().display()
                ),
            },
        }
    }

    /// Give it back. Only the run that holds it may.
    pub fn lock_release(&self, run_id: &str) -> Result<Option<Lock>> {
        match self.read_lock()? {
            None => Ok(None),
            Some(held) if held.run_id == run_id => {
                self.files.remove_file(&self.lock_path())?;
                Ok(Some(held))
            }
            Some(held) => bail!(
                "the run {run_id} does not hold this host; the run {} does (operator {}). A \
                 lock is released by the run that took it.",
                held.run_id,
                held.operator
            ),
        }
    }

    /// Claim the named run’s lock by rename, then acquire a fresh lock.
    /// Restore a mismatched claim with exclusive create to avoid overwriting another holder.
    pub fn lock_take_over(
        &self,
        of_run: &str,
        run_id: &str,
        operator: &str,
        pid: u32,
    ) -> Result<Lock> {
        let path = self.lock_path();
        if !self.files.exists(&path) {
            return self.lock_acquire(run_id, operator, pid);
        }
        // A takeover may reach the same host through the fleet anchor and its own plan step.
        if let Some(held) = self.read_lock()?
            && held.run_id == run_id
        {
            return Ok(held);
        }

        let claim = path.with_file_name(format!("owner.taken-by-{run_id}.json"));
        self.files.rename(&path, &claim).with_context(|| {
            format!(
                "the lock on this host could not be taken over; another takeover was here \
                 first, or the run gave {} back while you were reading.",
                path.display()
            )
        })?;
        let bytes = self.files.read(&claim)?;
        match serde_json::from_slice::<Lock>(&bytes).ok() {
            Some(held) if held.run_id == of_run => {
                self.files.remove_file(&claim)?;
                self.lock_acquire(run_id, operator, pid)
            }
            // Restore a mismatched claim without replacing a lock acquired in the meantime.
            other => {
                let restored = self.files.create_new(&path, &bytes, 0o600);
                let whose = match &other {
                    Some(held) => format!("by the run {}", held.run_id),
                    None => "by a file this program did not write".to_string(),
                };
                match restored {
                    Ok(()) => {
                        self.files.remove_file(&claim)?;
                        bail!("this host is held {whose}, not by {of_run}. Nothing was taken over.")
                    }
                    Err(e) => bail!(
                        "this host is held {whose}, not by {of_run}, and the lock could not be \
                         put back ({e:#}) because something else took {} meanwhile. Nothing was \
                         taken over; the record that was there is in {}.",
                        path.display(),
                        claim.display()
                    ),
                }
            }
        }
    }

    /// Reject host operations owned by a different run.
    fn refuse_if_held(&self, run_id: Option<&str>) -> Result<()> {
        match self.read_lock()? {
            None => Ok(()),
            Some(held) if Some(held.run_id.as_str()) == run_id => Ok(()),
            Some(held) => bail!(
                "this host is held by the run {} (operator {}, pid {}), and this is {}. \
                 Nothing was changed.",
                held.run_id,
                held.operator,
                held.pid,
                run_id.unwrap_or("no run at all")
            ),
        }
    }

    // -----------------------------------------------------------------
    // gc
    // -----------------------------------------------------------------

    /// Keep the profile generation, a matching booted generation and the newest N others.
    /// Refuse while a readable transaction is open, then delete selected generations and
    /// run garbage collection without `-d`, preserving other profiles’ generations.
    pub fn gc(&self, keep: usize) -> Result<GcOutcome> {
        if let Some(open) = self.records()?.iter().find(|r| r.is_open()) {
            bail!(
                "the transaction {} is {} on this host, and the generation it would roll back \
                 to must not be collected. Confirm it or revert it first.",
                open.id,
                open.state.as_str_lower()
            );
        }
        let generations = self.generations()?;
        let current = self.generation();
        let booted = self.resolve(Path::new(BOOTED_SYSTEM));
        let booted_generation = generations
            .iter()
            .find(|g| booted.is_some() && self.resolve(&self.generation_link(g.number)) == booted)
            .map(|g| g.number);

        let mut keep_set: Vec<u64> = Vec::new();
        keep_set.extend(current);
        keep_set.extend(booted_generation);
        // Retain N additional generations, excluding the profile and booted generations.
        let mut older: Vec<u64> = generations
            .iter()
            .map(|g| g.number)
            .filter(|n| Some(*n) != current && Some(*n) != booted_generation)
            .collect();
        older.sort_unstable_by(|a, b| b.cmp(a));
        keep_set.extend(older.iter().take(keep).copied());
        keep_set.sort_unstable();
        keep_set.dedup();

        let remove: Vec<u64> = generations
            .iter()
            .map(|g| g.number)
            .filter(|n| !keep_set.contains(n))
            .collect();

        if !remove.is_empty() {
            let mut cmd = Cmd::new(Effect::TargetWrite, "nix-env", COLLECT)
                .arg("-p")
                .arg(self.profile.display().to_string())
                .arg("--delete-generations");
            for number in &remove {
                cmd = cmd.arg(number.to_string());
            }
            self.runner.run(&cmd)?;
        }
        self.runner.run(&Cmd::new(
            Effect::TargetWrite,
            "nix-collect-garbage",
            COLLECT,
        ))?;

        // And the archives of finished transactions, of which the newest N
        // are worth keeping for the same reason the generations are.
        let mut archives: Vec<PathBuf> = self
            .files
            .list_dir(&self.txn_dir())?
            .into_iter()
            .filter(|p| p.to_string_lossy().ends_with(".json.done"))
            .collect();
        archives.sort();
        let drop_count = archives.len().saturating_sub(keep);
        let mut archives_removed = 0;
        for path in archives.into_iter().take(drop_count) {
            self.files.remove_file(&path)?;
            archives_removed += 1;
        }

        Ok(GcOutcome {
            kept: keep_set,
            removed: remove,
            archives_removed,
        })
    }

    fn generation_link(&self, number: u64) -> PathBuf {
        let dir = self.profile.parent().unwrap_or(Path::new("/"));
        let name = self
            .profile
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "system".to_string());
        dir.join(format!("{name}-{number}-link"))
    }

    /// The generations of the system profile, as `nix-env` lists them.
    fn generations(&self) -> Result<Vec<Generation>> {
        let cmd = Cmd::new(Effect::Read, "nix-env", QUICK)
            .arg("-p")
            .arg(self.profile.display().to_string())
            .arg("--list-generations");
        let out = self.runner.run(&cmd)?;
        Ok(parse_generations(&out.stdout))
    }

    // Key generation.

    /// Generate a host-local private key and return its CSR and public-key digest.
    /// Reuse an existing key unless replacement is explicit, so retries preserve identity.
    pub fn keygen(&self, subject: &str, kind: KeyKind, replace: bool) -> Result<KeygenOutcome> {
        self.keygen_into(subject, kind, replace, None)
    }

    /// Generate or reuse a suffixed key, such as `.key.next`, beside the active key.
    pub fn keygen_into(
        &self,
        subject: &str,
        kind: KeyKind,
        replace: bool,
        suffix: Option<&str>,
    ) -> Result<KeygenOutcome> {
        let path = self.key_path_with(kind, suffix);
        let had = self.files.exists(&path);

        let (key_pem, created) = if had && !replace {
            // Read, and never printed: what leaves this function is a
            // request and a digest.
            let existing = self.files.read_to_string(&path).with_context(|| {
                format!(
                    "{} is there and could not be read. It is this host's identity; \
                     `keygen --replace` would make a new one, and that is a decision \
                     rather than a repair.",
                    path.display()
                )
            })?;
            (existing, false)
        } else {
            let made = pki::generate_key_and_csr(subject)
                .map_err(|e| anyhow::anyhow!("making a key pair for {subject}: {e}"))?;
            // Create the key atomically with mode 0600; Files enforces dry-run policy.
            self.files
                .create_dir_all(path.parent().unwrap_or_else(|| Path::new(DEFAULT_PKI_DIR)))?;
            self.files
                .write_atomic(&path, made.key_pem.as_bytes(), 0o600)?;
            // Assign the root-created key to its reader through the command runner.
            self.runner.run(
                &Cmd::new(Effect::Key, "chown", QUICK)
                    .arg(format!("{KEY_OWNER}:{KEY_OWNER}"))
                    .arg(path.display().to_string()),
            )?;
            (made.key_pem, true)
        };

        // Generate the CSR from either the reused or newly created key.
        let csr_pem = pki::csr_for_key(&key_pem, subject)
            .map_err(|e| anyhow::anyhow!("making a certificate request for {subject}: {e}"))?;
        let public_key_sha256 = pki::public_key_sha256(&key_pem)
            .map_err(|e| anyhow::anyhow!("naming the public half of {}: {e}", path.display()))?;

        Ok(KeygenOutcome {
            subject: subject.to_string(),
            kind: kind.as_str().to_string(),
            csr_pem,
            public_key_sha256,
            created,
        })
    }

    /// Where a key of this kind lives on this host.
    pub fn key_path(&self, kind: KeyKind) -> PathBuf {
        self.pki_dir.join(format!("{}.key", kind.as_str()))
    }



    /// `<pki.dir>/<kind>.key`, `.key.next` or `.key.prev`.
    pub fn key_path_with(&self, kind: KeyKind, suffix: Option<&str>) -> PathBuf {
        self.pki_dir.join(match suffix {
            Some(suffix) => format!("{}.key.{suffix}", kind.as_str()),
            None => format!("{}.key", kind.as_str()),
        })
    }

    /// `<pki.dir>/<kind>.crt`, `.crt.next` or `.crt.prev`.
    pub fn cert_path_with(&self, kind: KeyKind, suffix: Option<&str>) -> PathBuf {
        self.pki_dir.join(match suffix {
            Some(suffix) => format!("{}.crt.{suffix}", kind.as_str()),
            None => format!("{}.crt", kind.as_str()),
        })
    }

    pub fn keys_record_path(&self, kind: KeyKind) -> PathBuf {
        self.txn_dir().join(format!("keys-{}.json", kind.as_str()))
    }

    /// Infer rotation progress from `.next` and `.prev` files. Completed/reverted records
    /// resolve the state only when no temporary pairs remain. Partial file layouts become
    /// inconsistent; the four switch renames are not an atomic pair replacement.
    pub fn keys_status(&self, kind: KeyKind) -> Result<KeysView> {
        let key_next = self.files.exists(&self.key_path_with(kind, Some("next")));
        let crt_next = self.files.exists(&self.cert_path_with(kind, Some("next")));
        let key_prev = self.files.exists(&self.key_path_with(kind, Some("prev")));
        let crt_prev = self.files.exists(&self.cert_path_with(kind, Some("prev")));
        let prev = key_prev || crt_prev;
        let record = match self.files.read_to_string(&self.keys_record_path(kind)) {
            Ok(text) => match KeysRecord::from_json(
                &text,
                &self.keys_record_path(kind).display().to_string(),
            ) {
                Ok(record) => Some(record),
                Err(e) => {
                    return Ok(KeysView {
                        kind: kind.as_str().to_string(),
                        state: KeysState::Inconsistent,
                        key_next,
                        crt_next,
                        prev,
                        reason: Some(format!(
                            "{} could not be read as a key transaction: {e:#}",
                            self.keys_record_path(kind).display()
                        )),
                        record: None,
                    });
                }
            },
            Err(_) => None,
        };
        // The record wins only where the disk cannot speak: a rotation that
        // was finished or taken back leaves nothing behind either way.
        let finished = record
            .as_ref()
            .filter(|r| matches!(r.state, KeysState::Confirmed | KeysState::Reverted))
            .map(|r| r.state);
        let (state, reason) = match (key_next, crt_next, key_prev, crt_prev) {
            // The switch, whole: the prepared pair is in and the pair it
            // replaced is beside it.
            (false, false, true, true) => (KeysState::Switched, None),
            (true, true, false, false) => (KeysState::Overlap, None),
            (true, false, false, false) => (KeysState::Prepared, None),
            (false, true, false, false) => (
                KeysState::Inconsistent,
                Some(format!(
                    "{} is there and {} is not: a certificate without the key it belongs to.",
                    self.cert_path_with(kind, Some("next")).display(),
                    self.key_path_with(kind, Some("next")).display()
                )),
            ),
            (false, false, false, false) => (finished.unwrap_or(KeysState::None), None),
            // Other layouts containing `.prev` indicate an interrupted switch requiring inspection.
            _ => (
                KeysState::Inconsistent,
                Some(format!(
                    "the {kind} key files on this host are a switch that stopped in the \
                     middle: {}. The pair that was in use is what `.prev` holds; finish it or \
                     put it back by hand, and this tool will not do either on its own.",
                    [
                        self.key_path_with(kind, None),
                        self.cert_path_with(kind, None),
                        self.key_path_with(kind, Some("next")),
                        self.cert_path_with(kind, Some("next")),
                        self.key_path_with(kind, Some("prev")),
                        self.cert_path_with(kind, Some("prev")),
                    ]
                    .iter()
                    .filter(|path| self.files.exists(path))
                    .map(|path| path.display().to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
                )),
            ),
        };
        Ok(KeysView {
            kind: kind.as_str().to_string(),
            state,
            key_next,
            crt_next,
            prev,
            reason,
            record,
        })
    }

    fn write_keys_record(&self, record: &KeysRecord) -> Result<()> {
        self.files.create_dir_all(&self.txn_dir())?;
        let kind = KeyKind::parse(&record.kind)?;
        self.files
            .write_atomic(&self.keys_record_path(kind), &record.to_json()?, 0o600)
    }

    /// Replace a prepared key/certificate pair through four ordered renames.
    /// Move the old certificate and key aside, then install the new key and certificate.
    /// Readers may observe a missing or mismatched pair between renames.
    pub fn keys_switch(&self, kind: KeyKind, run_id: Option<&str>) -> Result<KeysRecord> {
        let key_next = self.key_path_with(kind, Some("next"));
        let crt_next = self.cert_path_with(kind, Some("next"));
        if !self.files.exists(&key_next) || !self.files.exists(&crt_next) {
            bail!(
                "there is no prepared {} pair on this host: {} and {} both have to be there. \
                 `keygen --suffix next` makes the key and the rotation's `overlap` step \
                 delivers the certificate.",
                kind,
                key_next.display(),
                crt_next.display()
            );
        }
        let key = self.key_path_with(kind, None);
        let crt = self.cert_path_with(kind, None);
        let key_prev = self.key_path_with(kind, Some("prev"));
        let crt_prev = self.cert_path_with(kind, Some("prev"));
        let previous = self.digest_of(&crt);

        // Move the old certificate aside before replacing its key.
        if self.files.exists(&crt) {
            self.files.rename(&crt, &crt_prev)?;
        }
        if self.files.exists(&key) {
            self.files.rename(&key, &key_prev)?;
        }
        self.files.rename(&key_next, &key)?;
        self.files.rename(&crt_next, &crt)?;
        // The owner travels with the file, so nothing is chowned here; the
        // key was written 0600 `meister:meister` when it was made.

        let now = self.clock.now();
        let record = KeysRecord {
            schema: KEYS_SCHEMA.to_string(),
            kind: kind.as_str().to_string(),
            state: KeysState::Switched,
            run_id: run_id.map(str::to_string),
            previous_sha256: previous,
            sha256: self.digest_of(&crt),
            started_at: now,
            changed_at: now,
            reason: None,
        };
        self.write_keys_record(&record)?;
        Ok(record)
    }

    /// Restore the `.prev` pair and discard the current pair; retain the rollback reason.
    pub fn keys_revert(&self, kind: KeyKind, because: Option<&str>) -> Result<KeysRecord> {
        let key_prev = self.key_path_with(kind, Some("prev"));
        let crt_prev = self.cert_path_with(kind, Some("prev"));
        if !self.files.exists(&key_prev) || !self.files.exists(&crt_prev) {
            bail!(
                "there is nothing to go back to for {kind}: {} and {} are not both here. A \
                 rotation that has not switched is taken back by deleting the `.next` pair, \
                 and one that has been confirmed cannot be taken back at all.",
                key_prev.display(),
                crt_prev.display()
            );
        }
        let key = self.key_path_with(kind, None);
        let crt = self.cert_path_with(kind, None);
        self.files.remove_file(&crt)?;
        self.files.remove_file(&key)?;
        self.files.rename(&key_prev, &key)?;
        self.files.rename(&crt_prev, &crt)?;

        let now = self.clock.now();
        let mut record = match self.files.read_to_string(&self.keys_record_path(kind)) {
            Ok(text) => KeysRecord::from_json(&text, "the key transaction")
                .unwrap_or_else(|_| KeysRecord::new(kind, None, now)),
            Err(_) => KeysRecord::new(kind, None, now),
        };
        record.state = KeysState::Reverted;
        record.reason = Some(because.unwrap_or("the rotation was taken back").to_string());
        record.sha256 = self.digest_of(&crt);
        record.changed_at = now;
        self.write_keys_record(&record)?;
        Ok(record)
    }

    /// The last step: the pair that was replaced is dropped and the record
    /// says the rotation is over.
    pub fn keys_remove(&self, kind: KeyKind) -> Result<KeysRecord> {
        let key_prev = self.key_path_with(kind, Some("prev"));
        let crt_prev = self.cert_path_with(kind, Some("prev"));
        if !self.files.exists(&key_prev) && !self.files.exists(&crt_prev) {
            bail!(
                "there is no replaced {kind} pair on this host, so this rotation has either \
                 not switched yet or has already been finished."
            );
        }
        self.files.remove_file(&key_prev)?;
        self.files.remove_file(&crt_prev)?;
        let now = self.clock.now();
        let mut record = match self.files.read_to_string(&self.keys_record_path(kind)) {
            Ok(text) => KeysRecord::from_json(&text, "the key transaction")
                .unwrap_or_else(|_| KeysRecord::new(kind, None, now)),
            Err(_) => KeysRecord::new(kind, None, now),
        };
        record.state = KeysState::Confirmed;
        record.changed_at = now;
        record.sha256 = self.digest_of(&self.cert_path_with(kind, None));
        self.write_keys_record(&record)?;
        Ok(record)
    }

    /// Return the certificate/file digest in probe format, or None if reading fails.
    fn digest_of(&self, path: &Path) -> Option<String> {
        self.files
            .read(path)
            .ok()
            .map(|bytes| format!("sha256:{}", crate::ids::sha256_hex(&bytes)))
    }

}



pub const KEYS_SCHEMA: &str = "meister-deploy/activate-keys/1";

/// Observed progress of one key rotation, including inconsistent file layouts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum KeysState {
    /// No rotation is open on this host for this key.
    None,
    /// A new key lies beside the one in use. Nothing reads it yet.
    Prepared,
    /// And a certificate for it lies beside the one in use. Still nothing
    /// reads either.
    Overlap,
    /// The new pair is the pair in use, and the old one is still here.
    Switched,
    /// The old pair is gone. The rotation is over.
    Confirmed,
    /// The old pair is back in use and the new one is gone.
    Reverted,
    /// The disk says something this tool has no rule for.
    Inconsistent,
}

impl KeysState {
    pub fn as_str(self) -> &'static str {
        match self {
            KeysState::None => "none",
            KeysState::Prepared => "prepared",
            KeysState::Overlap => "overlap",
            KeysState::Switched => "switched",
            KeysState::Confirmed => "confirmed",
            KeysState::Reverted => "reverted",
            KeysState::Inconsistent => "inconsistent",
        }
    }
}

impl std::fmt::Display for KeysState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.pad(self.as_str())
    }
}

/// Target-side key rotation record. System transaction enumeration skips `keys-*.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct KeysRecord {
    pub schema: String,
    /// `identity` or `serving`.
    pub kind: String,
    pub state: KeysState,
    /// The run that opened it, so that a second operator can see whose it is.
    pub run_id: Option<String>,
    /// `sha256:<hex>` of the certificate that was in use before the switch.
    pub previous_sha256: Option<String>,
    /// Digest of the current certificate in the read-only probe’s format.
    pub sha256: Option<String>,
    pub started_at: DateTime<Utc>,
    pub changed_at: DateTime<Utc>,
    /// Why, for the two states that have a reason.
    pub reason: Option<String>,
}

impl KeysRecord {
    pub fn new(kind: KeyKind, run_id: Option<&str>, now: DateTime<Utc>) -> KeysRecord {
        KeysRecord {
            schema: KEYS_SCHEMA.to_string(),
            kind: kind.as_str().to_string(),
            state: KeysState::None,
            run_id: run_id.map(str::to_string),
            previous_sha256: None,
            sha256: None,
            started_at: now,
            changed_at: now,
            reason: None,
        }
    }

    pub fn to_json(&self) -> Result<Vec<u8>> {
        let mut bytes = serde_json::to_vec_pretty(self)
            .map_err(|e| anyhow::anyhow!("writing the key transaction failed: {e}"))?;
        bytes.push(b'\n');
        Ok(bytes)
    }

    pub fn from_json(text: &str, origin: &str) -> Result<KeysRecord> {
        crate::manifest::parse_checked(text, origin, KEYS_SCHEMA)
    }
}

/// What `keys status --json` answers with: where the rotation is, and what
/// is on the disk that says so.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct KeysView {
    pub kind: String,
    pub state: KeysState,
    /// `<kind>.key.next` is there.
    pub key_next: bool,
    /// `<kind>.crt.next` is there.
    pub crt_next: bool,
    /// Previous key/certificate pair retained after a switch.
    pub prev: bool,
    /// What makes this inconsistent, when it is.
    pub reason: Option<String>,
    pub record: Option<KeysRecord>,
}



/// Host key purpose: identity for outbound authentication, serving for TLS endpoints.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyKind {
    Identity,
    Serving,
}

impl KeyKind {
    pub fn as_str(self) -> &'static str {
        match self {
            KeyKind::Identity => "identity",
            KeyKind::Serving => "serving",
        }
    }

    pub fn parse(text: &str) -> Result<KeyKind> {
        match text {
            "identity" => Ok(KeyKind::Identity),
            "serving" => Ok(KeyKind::Serving),
            other => bail!(
                "{other:?} is not a key this host keeps. There are two: `identity` (what this \
                 machine dials with) and `serving` (what a client checks this address \
                 against)."
            ),
        }
    }
}

impl std::fmt::Display for KeyKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.pad(self.as_str())
    }
}

/// Public key-generation result. Private key material must never enter this serialized reply.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct KeygenOutcome {
    pub subject: String,
    pub kind: String,
    pub csr_pem: String,
    /// sha256 of the public half, hex. A name for the key that is safe
    /// everywhere the key is not.
    pub public_key_sha256: String,
    /// False when a key was already here and this only made another
    /// request over it.
    pub created: bool,
}

/// One generation of the system profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Generation {
    pub number: u64,
    pub current: bool,
}

/// What `gc` did, for the report and for a test.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GcOutcome {
    pub kept: Vec<u64>,
    pub removed: Vec<u64>,
    pub archives_removed: usize,
}

/// Parse generation numbers from the first field and `(current)` from the listing.
pub fn parse_generations(text: &str) -> Vec<Generation> {
    let mut out = Vec::new();
    for line in text.lines() {
        let mut fields = line.split_whitespace();
        let Some(first) = fields.next() else {
            continue;
        };
        let Ok(number) = first.parse::<u64>() else {
            continue;
        };
        out.push(Generation {
            number,
            current: line.contains("(current)"),
        });
    }
    out
}

/// `system-42-link` -> 42.
fn generation_of(link: &Path) -> Option<u64> {
    let name = link.file_name()?.to_string_lossy().into_owned();
    let rest = name.strip_suffix("-link")?;
    let (_, number) = rest.rsplit_once('-')?;
    number.parse().ok()
}

/// Standard NixOS systemd-boot entry name; specialisation-specific entries are unsupported.
fn entry_of(generation: u64) -> String {
    format!("nixos-generation-{generation}.conf")
}

/// The transient unit that would revert a transaction.
pub fn timer_unit(id: &str) -> String {
    format!("meister-revert-{id}")
}

impl TxnState {
    /// Stable lowercase transaction-state spelling shared by status and diagnostics.
    pub(crate) fn as_str_lower(self) -> &'static str {
        match self {
            TxnState::Staged => "staged",
            TxnState::Pending => "pending",
            // Persisted in-flight states distinguish interrupted decisions from pending activation.
            TxnState::Confirming => "confirming",
            TxnState::Reverting => "reverting",
            TxnState::Confirmed => "confirmed",
            TxnState::Reverted => "reverted",
            TxnState::Inconsistent => "inconsistent",
        }
    }
}

/// A reply for a caller that wanted json. Every verb answers with one, so
/// that `--json` is a property of the program rather than of each verb.
pub fn ok_reply(what: &str, value: serde_json::Value) -> serde_json::Value {
    serde_json::json!({ "ok": true, "what": what, "result": value })
}

#[cfg(test)]
mod crash_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::effects::{FakeClock, MemFiles};
    use crate::run::{Matcher, Output, Policy, StrictFake};

    const TOP: &str = "/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-nixos-system-box-25.11";
    const PREV: &str = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-nixos-system-box-25.11";

    fn clock() -> FakeClock {
        FakeClock::at(crate::fixtures::at("2026-09-22T12:00:00Z"))
    }

    /// A host that runs PREV as generation 41, with the new closure in the
    /// store and the deploy directories in place.
    fn host() -> MemFiles {
        MemFiles::new()
            .given_symlink("/run/current-system", PREV)
            .given_symlink("/run/booted-system", PREV)
            .given_symlink("/nix/var/nix/profiles/system", "system-41-link")
            .given_symlink("/nix/var/nix/profiles/system-41-link", PREV)
            .given_symlink(format!("{PREV}/kernel"), "/nix/store/kkkk-linux/bzImage")
            .given_symlink(format!("{PREV}/initrd"), "/nix/store/kkkk-initrd/initrd")
            .given(format!("{PREV}/kernel-params"), "init=/nix/store/x/init\n")
            .given_exec(format!("{PREV}/bin/switch-to-configuration"), "#!/bin/sh\n")
            .given_exec(format!("{TOP}/bin/switch-to-configuration"), "#!/bin/sh\n")
    }

    /// An empty argument list, spelled so that inference has a type.
    fn none() -> Vec<String> {
        Vec::new()
    }

    fn valid(top: &str) -> Matcher {
        Matcher::exact("nix-store", ["--check-validity", top])
    }

    fn helper<'a>(runner: &'a StrictFake, files: &'a MemFiles, clock: &'a FakeClock) -> Helper<'a> {
        helper_with(runner, files, clock)
    }

    fn helper_with<'a>(
        runner: &'a dyn Runner,
        files: &'a MemFiles,
        clock: &'a FakeClock,
    ) -> Helper<'a> {
        Helper::new(runner, files, clock, "/var/lib/meisterstack/deploy", "/exe")
    }

    /// Fake runner that moves the profile link after `nix-env --set`, exposing the new
    /// generation number to boot-menu operations.
    struct Moving<'a> {
        inner: StrictFake,
        files: &'a MemFiles,
        link: &'a str,
    }

    impl Runner for Moving<'_> {
        fn run(&self, cmd: &Cmd) -> Result<Output> {
            let out = self.inner.run(cmd)?;
            if cmd.program == "nix-env" && cmd.args.iter().any(|a| a == "--set") {
                self.files.symlink_atomic(
                    Path::new(self.link),
                    Path::new("/nix/var/nix/profiles/system"),
                )?;
            }
            Ok(out)
        }

        fn policy(&self) -> Policy {
            self.inner.policy()
        }
    }

    #[test]
    fn status_reads_three_system_facts_and_resolves_two_links_deep() {
        let files = host();
        let runner =
            StrictFake::new().expect(Matcher::exact("uname", ["-r"]), Output::stdout("6.12.41\n"));
        let clock = clock();
        let status = helper(&runner, &files, &clock).status().unwrap();
        assert_eq!(status.schema, ACTIVATE_STATUS_SCHEMA);
        assert_eq!(status.current_system.as_deref(), Some(PREV));
        assert_eq!(status.booted_system.as_deref(), Some(PREV));
        // Through system-41-link, which is the second link in the chain.
        assert_eq!(status.next_boot_system.as_deref(), Some(PREV));
        assert_eq!(status.generation, Some(41));
        assert_eq!(status.kernel_running.as_deref(), Some("6.12.41"));
        let boot = status.kernel_booted.expect("the booted kernel is readable");
        assert_eq!(boot.kernel_store_path, "/nix/store/kkkk-linux/bzImage");
        assert_eq!(
            boot.kernel_params_sha256,
            sha256_hex(b"init=/nix/store/x/init\n")
        );
        assert!(status.open_txns.is_empty());
        assert!(status.lock.is_none());
        runner.verify().unwrap();
    }

    #[test]
    fn what_cannot_be_read_is_null_and_never_a_default() {
        // A machine with nothing: no profile, no /run, no uname.
        let files = MemFiles::new();
        let runner =
            StrictFake::new().expect(Matcher::exact("uname", ["-r"]), Output::failing(1, "no"));
        let clock = clock();
        let status = helper(&runner, &files, &clock).status().unwrap();
        assert!(status.current_system.is_none());
        assert!(status.booted_system.is_none());
        assert!(status.next_boot_system.is_none());
        assert!(status.generation.is_none());
        assert!(status.kernel_running.is_none());
        assert!(status.kernel_booted.is_none());
        runner.verify().unwrap();
    }

    #[test]
    fn a_half_read_boot_triple_is_no_triple() {
        // A missing parameter file invalidates the entire boot tuple.
        let files = MemFiles::new()
            .given_symlink("/run/booted-system", PREV)
            .given_symlink(format!("{PREV}/kernel"), "/nix/store/kkkk-linux/bzImage")
            .given_symlink(format!("{PREV}/initrd"), "/nix/store/kkkk-initrd/initrd");
        let runner =
            StrictFake::new().expect(Matcher::exact("uname", ["-r"]), Output::stdout("6.12.41"));
        let clock = clock();
        assert!(
            helper(&runner, &files, &clock)
                .status()
                .unwrap()
                .kernel_booted
                .is_none()
        );
        runner.verify().unwrap();
    }

    #[test]
    fn stage_asks_for_the_whole_closure_and_writes_nothing() {
        let files = host();
        let runner = StrictFake::new().expect(valid(TOP), Output::stdout(""));
        let clock = clock();
        helper(&runner, &files, &clock).stage(TOP).unwrap();
        runner.verify().unwrap();
        assert!(
            files.attempts().is_empty(),
            "stage wrote something: {:?}",
            files.attempts()
        );
    }

    #[test]
    fn a_store_path_that_is_not_a_system_is_refused_by_name() {
        let files = host();
        let runner =
            StrictFake::new().expect(valid("/nix/store/zzzz-not-a-system"), Output::stdout(""));
        let clock = clock();
        let err = helper(&runner, &files, &clock)
            .stage("/nix/store/zzzz-not-a-system")
            .unwrap_err()
            .to_string();
        assert!(err.contains("bin/switch-to-configuration"), "{err}");
        runner.verify().unwrap();
    }

    /// The whole of a switch-mode activation, in order.
    #[test]
    fn an_activation_writes_the_record_then_arms_the_timer_then_switches() {
        let files = host();
        let runner = StrictFake::new()
            .expect(valid(TOP), Output::stdout(""))
            .expect(
                Matcher::prefix("systemd-run", ["--on-active=300"]),
                Output::stdout(""),
            )
            .expect(
                Matcher::exact(
                    "nix-env",
                    ["-p", "/nix/var/nix/profiles/system", "--set", TOP],
                ),
                Output::stdout(""),
            )
            .expect(
                Matcher::exact(&format!("{TOP}/bin/switch-to-configuration"), ["switch"]),
                Output::stdout(""),
            );
        let clock = clock();
        let helper = helper(&runner, &files, &clock);
        let record = helper
            .activate("run-1", TOP, Mode::Switch, 300, Some("run-1"))
            .unwrap();
        runner.verify().unwrap();

        assert_eq!(record.state, TxnState::Pending);
        assert_eq!(record.previous.toplevel.as_deref(), Some(PREV));
        assert_eq!(record.previous.generation, Some(41));
        assert_eq!(record.desired, TOP);
        assert_eq!(
            record.deadline,
            Some(crate::fixtures::at("2026-09-22T12:05:00Z"))
        );

        // The record was on the disk before the profile moved: the writes and
        // the commands interleave, and the order is what a resume stands on.
        let attempts = files.attempts();
        assert!(
            attempts
                .iter()
                .any(|a| a.contains("write(0600)") && a.contains("txn/run-1.json")),
            "{attempts:?}"
        );
        // And it reads back as the record it wrote.
        assert_eq!(helper.record("run-1").unwrap(), record);
    }

    #[test]
    fn the_timer_command_names_this_binary_and_this_deploy_directory() {
        let files = host();
        let runner = StrictFake::new()
            .expect(valid(TOP), Output::stdout(""))
            .expect(
                Matcher::prefix("systemd-run", ["--on-active=20"]),
                Output::stdout(""),
            )
            .expect(Matcher::prefix("nix-env", ["-p"]), Output::stdout(""))
            .expect(
                Matcher::prefix(&format!("{TOP}/bin/switch-to-configuration"), ["switch"]),
                Output::stdout(""),
            );
        let clock = clock();
        Helper::new(
            &runner,
            &files,
            &clock,
            "/tmp/deploy",
            "/nix/store/exe/bin/x",
        )
        .activate("t1", TOP, Mode::Switch, 20, None)
        .unwrap();
        let line = runner
            .calls()
            .into_iter()
            .find(|c| c.starts_with("systemd-run"))
            .expect("the timer was armed");
        assert!(line.contains("--unit=meister-revert-t1"), "{line}");
        assert!(
            line.contains("--setenv=PATH=/run/current-system/sw/bin"),
            "the timer has to be able to find nix-env: {line}"
        );
        assert!(
            line.contains("/nix/store/exe/bin/x revert --txn t1"),
            "{line}"
        );
        assert!(line.contains("--deploy-dir /tmp/deploy"), "{line}");
        assert!(line.contains("--collect"), "{line}");
        runner.verify().unwrap();
    }

    #[test]
    fn a_switch_that_fails_puts_the_host_back_and_records_why() {
        let files = host();
        let runner = StrictFake::new()
            .expect(valid(TOP), Output::stdout(""))
            .expect(Matcher::prefix("systemd-run", none()), Output::stdout(""))
            .expect(Matcher::prefix("nix-env", ["-p"]), Output::stdout(""))
            .expect(
                Matcher::prefix(&format!("{TOP}/bin/switch-to-configuration"), none()),
                Output::failing(1, "the activation script failed"),
            )
            // Restore both the profile and old system after a failed switch.
            .expect(
                Matcher::exact("systemctl", ["stop", "meister-revert-r2.timer"]),
                Output::stdout(""),
            )
            .expect(
                Matcher::exact("systemctl", ["is-active", "meister-revert-r2.timer"]),
                Output::failing(3, ""),
            )
            .expect(
                Matcher::exact(
                    "nix-env",
                    ["-p", "/nix/var/nix/profiles/system", "--set", PREV],
                ),
                Output::stdout(""),
            )
            .expect(
                Matcher::exact(&format!("{PREV}/bin/switch-to-configuration"), ["switch"]),
                Output::stdout(""),
            );
        let clock = clock();
        let helper = helper(&runner, &files, &clock);
        let err = format!(
            "{:#}",
            helper
                .activate("r2", TOP, Mode::Switch, 300, None)
                .unwrap_err()
        );
        assert!(err.contains("switch-to-configuration"), "{err}");
        assert!(err.contains("was taken back to"), "{err}");
        runner.verify().unwrap();
        let record = helper.record("r2").unwrap();
        assert_eq!(record.state, TxnState::Reverted);
        assert!(
            record
                .reason
                .as_deref()
                .unwrap_or("")
                .contains("the activation itself failed"),
            "{record:?}"
        );
    }

    #[test]
    fn a_host_that_cannot_be_put_back_says_inconsistent_and_not_reverted() {
        let files = host();
        let runner = StrictFake::new()
            .expect(valid(TOP), Output::stdout(""))
            .expect(Matcher::prefix("systemd-run", none()), Output::stdout(""))
            .expect(Matcher::prefix("nix-env", ["-p"]), Output::stdout(""))
            .expect(
                Matcher::prefix(&format!("{TOP}/bin/switch-to-configuration"), none()),
                Output::failing(1, "the activation script failed"),
            )
            .expect(Matcher::prefix("systemctl", ["stop"]), Output::stdout(""))
            .expect(
                Matcher::prefix("systemctl", ["is-active"]),
                Output::failing(3, ""),
            )
            .expect(
                Matcher::prefix("nix-env", ["-p"]),
                Output::failing(1, "the profile could not be moved"),
            );
        let clock = clock();
        let helper = helper(&runner, &files, &clock);
        let err = format!(
            "{:#}",
            helper
                .activate("r5", TOP, Mode::Switch, 300, None)
                .unwrap_err()
        );
        assert!(err.contains("needs a person"), "{err}");
        runner.verify().unwrap();
        let record = helper.record("r5").unwrap();
        assert_eq!(record.state, TxnState::Inconsistent);
        assert!(record.is_open(), "an inconsistent record is still open");
    }

    #[test]
    fn an_activation_whose_timer_cannot_be_armed_never_moves_the_profile() {
        let files = host();
        let runner = StrictFake::new()
            .expect(valid(TOP), Output::stdout(""))
            .expect(
                Matcher::prefix("systemd-run", none()),
                Output::failing(1, "Failed to start transient timer unit"),
            );
        let clock = clock();
        let helper = helper(&runner, &files, &clock);
        let err = format!(
            "{:#}",
            helper
                .activate("r6", TOP, Mode::Switch, 300, None)
                .unwrap_err()
        );
        assert!(err.contains("has no way back and was not started"), "{err}");
        runner.verify().unwrap();
        let record = helper.record("r6").unwrap();
        assert_eq!(record.state, TxnState::Reverted);
        assert!(!record.is_open());
    }

    #[test]
    fn a_second_activation_on_top_of_an_open_one_is_refused() {
        let files = host();
        let runner = StrictFake::new()
            .expect(valid(TOP), Output::stdout(""))
            .expect(Matcher::prefix("systemd-run", none()), Output::stdout(""))
            .expect(Matcher::prefix("nix-env", ["-p"]), Output::stdout(""))
            .expect(
                Matcher::prefix(&format!("{TOP}/bin/switch-to-configuration"), none()),
                Output::stdout(""),
            );
        let clock = clock();
        let helper = helper(&runner, &files, &clock);
        helper.activate("a", TOP, Mode::Switch, 300, None).unwrap();
        let err = helper
            .activate("b", TOP, Mode::Switch, 300, None)
            .unwrap_err()
            .to_string();
        assert!(err.contains("already has the transaction a open"), "{err}");
        assert!(err.contains("pending"), "{err}");
        runner.verify().unwrap();
    }

    #[test]
    fn an_activation_on_a_host_somebody_else_holds_is_refused_before_anything() {
        let files = host();
        let runner = StrictFake::new();
        let clock = clock();
        let helper = helper(&runner, &files, &clock);
        helper.lock_acquire("other", "silas@manacor", 4711).unwrap();
        let err = helper
            .activate("mine", TOP, Mode::Switch, 300, Some("mine"))
            .unwrap_err()
            .to_string();
        assert!(err.contains("held by the run other"), "{err}");
        assert!(err.contains("Nothing was changed"), "{err}");
        // Not one command ran, and no record was written.
        runner.verify().unwrap();
        assert!(helper.record("mine").is_err());
    }

    #[test]
    fn the_run_that_holds_the_host_may_activate_on_it() {
        let files = host();
        let runner = StrictFake::new()
            .expect(valid(TOP), Output::stdout(""))
            .expect(Matcher::prefix("systemd-run", none()), Output::stdout(""))
            .expect(Matcher::prefix("nix-env", ["-p"]), Output::stdout(""))
            .expect(
                Matcher::prefix(&format!("{TOP}/bin/switch-to-configuration"), none()),
                Output::stdout(""),
            );
        let clock = clock();
        let helper = helper(&runner, &files, &clock);
        helper.lock_acquire("mine", "silas@manacor", 1).unwrap();
        helper
            .activate("mine", TOP, Mode::Switch, 300, Some("mine"))
            .unwrap();
        runner.verify().unwrap();
    }

    #[test]
    fn confirm_stops_the_timer_and_then_says_so() {
        let files = host();
        let runner = StrictFake::new()
            .expect(
                Matcher::exact("systemctl", ["stop", "meister-revert-c1.timer"]),
                Output::stdout(""),
            )
            .expect(
                Matcher::exact("systemctl", ["is-active", "meister-revert-c1.timer"]),
                Output::failing(3, "inactive"),
            );
        let clock = clock();
        let helper = helper(&runner, &files, &clock);
        helper.write_record(&pending("c1", Mode::Switch)).unwrap();
        let record = helper.confirm("c1").unwrap();
        assert_eq!(record.state, TxnState::Confirmed);
        runner.verify().unwrap();
    }

    #[test]
    fn a_confirm_whose_timer_will_not_stop_moves_no_machine() {
        let files = host();
        let runner = StrictFake::new()
            .expect(Matcher::prefix("systemctl", ["stop"]), Output::stdout(""))
            .expect(
                Matcher::prefix("systemctl", ["is-active"]),
                Output::stdout("active"),
            );
        let clock = clock();
        let helper = helper(&runner, &files, &clock);
        helper.write_record(&pending("c2", Mode::Switch)).unwrap();
        let err = helper.confirm("c2").unwrap_err().to_string();
        assert!(err.contains("still active"), "{err}");
        // Confirmation intent remains durable even if stopping the timer fails.
        assert_eq!(helper.record("c2").unwrap().state, TxnState::Confirming);
        runner.verify().unwrap();
    }

    #[test]
    fn revert_puts_the_profile_back_and_records_the_reason() {
        let files = host();
        let runner = StrictFake::new()
            .expect(Matcher::prefix("systemctl", ["stop"]), Output::stdout(""))
            .expect(
                Matcher::prefix("systemctl", ["is-active"]),
                Output::failing(3, ""),
            )
            .expect(
                Matcher::exact(
                    "nix-env",
                    ["-p", "/nix/var/nix/profiles/system", "--set", PREV],
                ),
                Output::stdout(""),
            )
            .expect(
                Matcher::exact(&format!("{PREV}/bin/switch-to-configuration"), ["switch"]),
                Output::stdout(""),
            );
        let clock = clock();
        let helper = helper(&runner, &files, &clock);
        helper.write_record(&pending("r1", Mode::Switch)).unwrap();
        let record = helper
            .revert(
                "r1",
                Some("a readiness check failed"),
                RevertAsker::Operator,
            )
            .unwrap();
        assert_eq!(record.state, TxnState::Reverted);
        assert_eq!(record.reason.as_deref(), Some("a readiness check failed"));
        runner.verify().unwrap();
    }


    #[test]
    fn a_confirm_and_a_timer_revert_do_not_both_win() {
        let files = host();
        let runner = StrictFake::new();
        let clock = clock();
        let helper = helper(&runner, &files, &clock);
        helper.write_record(&pending("d1", Mode::Switch)).unwrap();
        // Simulate a live timer process holding the decision lock before profile rollback.
        let held = helper.txn_dir().join("d1.deciding");
        files
            .write_atomic(
                &held,
                format!("revert pid {} at 2026-09-22T12:05:00Z", std::process::id()).as_bytes(),
                0o600,
            )
            .unwrap();
        let err = helper.confirm("d1").unwrap_err().to_string();
        assert!(err.contains("being decided right now"), "{err}");
        assert!(err.contains("revert pid"), "{err}");
        assert_eq!(
            helper.record("d1").unwrap().state,
            TxnState::Pending,
            "nothing was decided"
        );
        // And nothing was run: the timer was never stopped, so the way back
        // is still armed.
        runner.verify().unwrap();
    }


    #[test]
    fn a_decision_whose_process_is_gone_does_not_block_the_next_one() {
        // A dead lock holder must not block recovery.
        let files = host();
        let runner = StrictFake::new()
            .expect(Matcher::prefix("systemctl", ["stop"]), Output::stdout(""))
            .expect(
                Matcher::prefix("systemctl", ["is-active"]),
                Output::failing(3, ""),
            );
        let clock = clock();
        let helper = helper(&runner, &files, &clock);
        helper.write_record(&pending("d2", Mode::Switch)).unwrap();
        let held = helper.txn_dir().join("d2.deciding");
        files
            .write_atomic(
                &held,
                // Positive, and above every `pid_max` a Linux kernel hands
                // out.
                b"confirm pid 2147483646 at 2026-09-22T12:05:00Z",
                0o600,
            )
            .unwrap();
        let record = helper
            .confirm("d2")
            .expect("the stale holder is taken over");
        assert_eq!(record.state, TxnState::Confirmed);
        assert!(
            !files.exists(&held),
            "the decision gives the transaction back"
        );
        runner.verify().unwrap();
    }



    /// A record in the state a crash between the two steps leaves behind.
    fn confirming(id: &str) -> TxnRecord {
        let mut record = pending(id, Mode::Switch);
        record.state = TxnState::Confirming;
        record
    }

    #[test]
    fn a_crash_between_the_timer_stop_and_the_record_leaves_confirming() {
        // Simulate a crash after stopping the timer but before writing `confirmed`.
        let files = host();
        let runner = StrictFake::new()
            // What `status` reads on its way past, before anything here
            // decides anything.
            .expect(Matcher::exact("uname", ["-r"]), Output::stdout("6.12.41\n"))
            .expect(
                Matcher::exact("systemctl", ["stop", "meister-revert-f1.timer"]),
                // A missing timer is accepted when resuming confirmation.
                Output::failing(5, "Failed to stop meister-revert-f1.timer: not loaded."),
            )
            .expect(
                Matcher::exact("systemctl", ["is-active", "meister-revert-f1.timer"]),
                Output::failing(3, "inactive"),
            );
        let clock = clock();
        let helper = helper(&runner, &files, &clock);
        helper.write_record(&confirming("f1")).unwrap();

        // The unfinished decision remains visible as an open transaction.
        let status = helper.status().unwrap();
        assert_eq!(status.open_txns.len(), 1, "{status:?}");
        assert_eq!(status.open_txns[0].state, TxnState::Confirming);
        assert!(helper.record("f1").unwrap().is_open());
        assert_eq!(helper.record("f1").unwrap().state_word(), "confirming");

        // And the confirmation is finished rather than repaired: the same
        // verb, the same work, a record that now says what happened.
        let record = helper.confirm("f1").unwrap();
        assert_eq!(record.state, TxnState::Confirmed);
        assert!(!record.is_open());
        runner.verify().unwrap();
    }

    #[test]
    fn a_confirmation_in_flight_is_finished_not_reverted() {
        // A timer encountering confirmation intent must leave the system unchanged.
        let files = host();
        let timer = StrictFake::new();
        let clock = clock();
        let left_alone = {
            let helper = helper(&timer, &files, &clock);
            helper.write_record(&confirming("f2")).unwrap();
            helper
                .revert(
                    "f2",
                    Some("nobody confirmed this activation before its deadline"),
                    RevertAsker::Deadline,
                )
                .expect("the deadline has nothing to say about a decision that was taken")
        };
        assert_eq!(left_alone.state, TxnState::Confirming);
        assert_eq!(
            helper(&timer, &files, &clock).record("f2").unwrap().state,
            TxnState::Confirming,
            "the record is not rewritten either"
        );
        timer.verify().unwrap();

        // What finishes it is the confirmation itself, whenever it comes:
        // from a resume, or from a person.
        let after = StrictFake::new()
            .expect(Matcher::prefix("systemctl", ["stop"]), Output::stdout(""))
            .expect(
                Matcher::prefix("systemctl", ["is-active"]),
                Output::failing(3, "inactive"),
            );
        let record = helper(&after, &files, &clock).confirm("f2").unwrap();
        assert_eq!(record.state, TxnState::Confirmed);
        after.verify().unwrap();
    }

    #[test]
    fn a_second_confirm_completes_a_confirming_record() {
        // Resume a confirmation interrupted before stopping its timer.
        let files = host();
        let runner = StrictFake::new()
            .expect(
                Matcher::exact("systemctl", ["stop", "meister-revert-f3.timer"]),
                Output::stdout(""),
            )
            .expect(
                Matcher::exact("systemctl", ["is-active", "meister-revert-f3.timer"]),
                Output::failing(3, "inactive"),
            );
        let clock = clock();
        let helper = helper(&runner, &files, &clock);
        helper.write_record(&confirming("f3")).unwrap();
        let record = helper.confirm("f3").unwrap();
        assert_eq!(record.state, TxnState::Confirmed);
        runner.verify().unwrap();

        // And a third one is the answer again and runs nothing at all.
        let quiet = StrictFake::new();
        assert_eq!(
            helper_with(&quiet, &files, &clock)
                .confirm("f3")
                .unwrap()
                .state,
            TxnState::Confirmed
        );
        quiet.verify().unwrap();
    }

    #[test]
    fn a_revert_of_a_confirmation_in_flight_needs_a_person() {
        let files = host();
        let quiet = StrictFake::new();
        let clock = clock();
        {
            let helper = helper(&quiet, &files, &clock);
            helper.write_record(&confirming("f4")).unwrap();
            let err = helper
                .revert("f4", Some("a check failed"), RevertAsker::Operator)
                .unwrap_err()
                .to_string();
            assert!(err.contains("was in flight"), "{err}");
            assert!(err.contains("confirm --txn f4"), "{err}");
            assert!(err.contains("--force"), "{err}");
            // A force still has to say why: the record is the only account
            // of a decision overruled.
            let err = helper
                .revert("f4", None, RevertAsker::Force)
                .unwrap_err()
                .to_string();
            assert!(err.contains("needs `--because"), "{err}");
            assert_eq!(helper.record("f4").unwrap().state, TxnState::Confirming);
        }
        quiet.verify().unwrap();

        // An explicit reason permits the forced rollback.
        let runner = StrictFake::new()
            .expect(Matcher::prefix("systemctl", ["stop"]), Output::stdout(""))
            .expect(
                Matcher::prefix("systemctl", ["is-active"]),
                Output::failing(3, "inactive"),
            )
            .expect(
                Matcher::exact(
                    "nix-env",
                    ["-p", "/nix/var/nix/profiles/system", "--set", PREV],
                ),
                Output::stdout(""),
            )
            .expect(
                Matcher::exact(&format!("{PREV}/bin/switch-to-configuration"), ["switch"]),
                Output::stdout(""),
            );
        let record = helper(&runner, &files, &clock)
            .revert(
                "f4",
                Some("the confirming process is gone and this host must not keep the release"),
                RevertAsker::Force,
            )
            .unwrap();
        assert_eq!(record.state, TxnState::Reverted);
        assert!(record.reason.as_deref().unwrap().contains("must not keep"));
        runner.verify().unwrap();
    }

    #[test]
    fn a_crash_in_the_middle_of_a_revert_leaves_reverting() {
        // A failed profile rollback leaves durable intent and blocks confirmation.
        let files = host();
        let runner = StrictFake::new()
            .expect(Matcher::prefix("systemctl", ["stop"]), Output::stdout(""))
            .expect(
                Matcher::prefix("systemctl", ["is-active"]),
                Output::failing(3, "inactive"),
            )
            .expect(
                Matcher::prefix("nix-env", ["-p"]),
                Output::failing(1, "no space left on device"),
            );
        let clock = clock();
        let helper = helper(&runner, &files, &clock);
        helper.write_record(&pending("f5", Mode::Switch)).unwrap();
        let err = helper
            .revert(
                "f5",
                Some("a readiness check failed"),
                RevertAsker::Operator,
            )
            .unwrap_err()
            .to_string();
        assert!(err.contains("no space left"), "{err}");
        let record = helper.record("f5").unwrap();
        assert_eq!(record.state, TxnState::Reverting);
        assert_eq!(record.reason.as_deref(), Some("a readiness check failed"));
        assert!(record.is_open(), "a way back that stopped is open");
        // Nothing confirms a machine whose way back did not finish.
        let err = helper.confirm("f5").unwrap_err().to_string();
        assert!(err.contains("did not finish"), "{err}");
        assert!(err.contains("revert --txn f5"), "{err}");
        runner.verify().unwrap();
    }



    #[test]
    fn a_second_revert_is_the_same_answer_and_runs_nothing() {
        let files = host();
        let runner = StrictFake::new();
        let clock = clock();
        let helper = helper(&runner, &files, &clock);
        let mut record = pending("r3", Mode::Switch);
        record.state = TxnState::Reverted;
        record.reason = Some("the timer fired".to_string());
        helper.write_record(&record).unwrap();
        let again = helper
            .revert("r3", Some("and then a person"), RevertAsker::Operator)
            .unwrap();
        assert_eq!(again.reason.as_deref(), Some("the timer fired"));
        runner.verify().unwrap();
    }

    #[test]
    fn a_confirmed_transaction_is_not_reverted() {
        let files = host();
        let runner = StrictFake::new();
        let clock = clock();
        let helper = helper(&runner, &files, &clock);
        let mut record = pending("r4", Mode::Switch);
        record.state = TxnState::Confirmed;
        helper.write_record(&record).unwrap();
        let err = helper
            .revert("r4", Some("the timer fired"), RevertAsker::Deadline)
            .unwrap_err();
        assert!(
            err.to_string().contains("was confirmed"),
            "{}",
            err.to_string()
        );
        runner.verify().unwrap();
    }

    #[test]
    fn boot_mode_needs_systemd_boot_and_says_what_grub_can_have() {
        let files = host();
        let runner = StrictFake::new()
            .expect(valid(TOP), Output::stdout(""))
            .expect(
                Matcher::exact("bootctl", ["is-installed"]),
                Output::stdout("no"),
            );
        let clock = clock();
        let err = helper(&runner, &files, &clock)
            .activate("b1", TOP, Mode::Boot, 900, None)
            .unwrap_err()
            .to_string();
        assert!(err.contains("no boot fallback"), "{err}");
        assert!(err.contains("--mode switch"), "{err}");
        runner.verify().unwrap();
    }

    #[test]
    fn a_boot_activation_tries_the_new_entry_once_and_leaves_the_old_default() {
        // After the switch the profile points at generation 42.
        let files = host()
            .given_symlink("/nix/var/nix/profiles/system-42-link", TOP)
            .given_symlink(format!("{TOP}/kernel"), "/nix/store/nnnn-linux/bzImage");
        let runner = StrictFake::new()
            .expect(valid(TOP), Output::stdout(""))
            .expect(
                Matcher::exact("bootctl", ["is-installed"]),
                Output::stdout("yes"),
            )
            .expect(Matcher::prefix("systemd-run", none()), Output::stdout(""))
            .expect(Matcher::prefix("nix-env", ["-p"]), Output::stdout(""))
            .expect(
                Matcher::exact(&format!("{TOP}/bin/switch-to-configuration"), ["boot"]),
                Output::stdout(""),
            )
            .expect(
                Matcher::exact("bootctl", ["set-default", "nixos-generation-41.conf"]),
                Output::stdout(""),
            )
            .expect(
                Matcher::exact("bootctl", ["set-oneshot", "nixos-generation-42.conf"]),
                Output::stdout(""),
            );
        let clock = clock();
        let runner = Moving {
            inner: runner,
            files: &files,
            link: "system-42-link",
        };
        let helper = helper_with(&runner, &files, &clock);
        let record = helper.activate("b2", TOP, Mode::Boot, 900, None).unwrap();
        assert_eq!(record.mode, Mode::Boot);
        // The fallback is the generation it CAME from, read before the move.
        assert_eq!(record.previous.generation, Some(41));
        runner.inner.verify().unwrap();
    }

    #[test]
    fn confirming_a_boot_activation_makes_the_new_entry_the_default() {
        // The machine has rebooted into generation 42 by the time a confirm
        // arrives, which is why the link is where it is in this fixture.
        let files = host().given_symlink("/nix/var/nix/profiles/system-42-link", TOP);
        files
            .symlink_atomic(
                Path::new("system-42-link"),
                Path::new("/nix/var/nix/profiles/system"),
            )
            .unwrap();
        let runner = StrictFake::new()
            .expect(Matcher::prefix("systemctl", ["stop"]), Output::stdout(""))
            .expect(
                Matcher::prefix("systemctl", ["is-active"]),
                Output::failing(3, ""),
            )
            .expect(
                Matcher::exact("bootctl", ["set-default", "nixos-generation-42.conf"]),
                Output::stdout(""),
            );
        let clock = clock();
        let helper = helper(&runner, &files, &clock);
        helper.write_record(&pending("b3", Mode::Boot)).unwrap();
        assert_eq!(helper.confirm("b3").unwrap().state, TxnState::Confirmed);
        runner.verify().unwrap();
    }

    #[test]
    fn a_record_that_does_not_parse_is_inconsistent_and_not_ignored() {
        let files = host().given(
            "/var/lib/meisterstack/deploy/txn/half.json",
            "{\"schema\":\"meister-deploy/activate-txn/1\",\"id\":\"ha",
        );
        let runner = StrictFake::new();
        let clock = clock();
        let records = helper(&runner, &files, &clock).records().unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].state, TxnState::Inconsistent);
        assert_eq!(records[0].id, "half");
        assert!(records[0].is_open());
        runner.verify().unwrap();
    }

    #[test]
    fn a_retired_record_is_not_open_any_more_and_the_glob_does_not_find_it() {
        let files = host();
        let runner = StrictFake::new();
        let clock = clock();
        let helper = helper(&runner, &files, &clock);
        let mut record = pending("done", Mode::Switch);
        record.state = TxnState::Confirmed;
        record.run_id = Some("run-9".to_string());
        helper.write_record(&record).unwrap();
        helper.retire("done", Some("run-9")).unwrap();
        assert!(helper.records().unwrap().is_empty());
        assert!(files.exists(&helper.txn_archive("done")));
        // And the archive's name is not what the read-only probe globs.
        assert!(
            helper
                .txn_archive("done")
                .display()
                .to_string()
                .ends_with(".json.done")
        );
        runner.verify().unwrap();
    }

    #[test]
    fn an_open_record_is_not_retired_and_not_by_another_run() {
        let files = host();
        let runner = StrictFake::new();
        let clock = clock();
        let helper = helper(&runner, &files, &clock);
        let mut record = pending("open", Mode::Switch);
        record.run_id = Some("run-1".to_string());
        helper.write_record(&record).unwrap();
        let err = helper
            .retire("open", Some("run-1"))
            .unwrap_err()
            .to_string();
        assert!(err.contains("is pending and is not retired"), "{err}");

        record.state = TxnState::Confirmed;
        helper.write_record(&record).unwrap();
        let err = helper
            .retire("open", Some("run-2"))
            .unwrap_err()
            .to_string();
        assert!(err.contains("belongs to the run run-1"), "{err}");
        runner.verify().unwrap();
    }



    #[test]
    fn an_inconsistent_record_can_be_put_aside_by_a_person_with_a_sentence() {
        // An inconsistent record requires explicit, audited retirement.
        let files = host();
        let runner = StrictFake::new();
        let clock = clock();
        let helper = helper(&runner, &files, &clock);
        let mut record = pending("stuck", Mode::Switch);
        record.state = TxnState::Inconsistent;
        record.reason = Some("the timer fired and the profile did not move".to_string());
        record.run_id = Some("run-1".to_string());
        helper.write_record(&record).unwrap();

        // Without `--force` the refusal now says the way out.
        let err = helper
            .retire("stuck", Some("run-1"))
            .unwrap_err()
            .to_string();
        assert!(err.contains("--force --reason"), "{err}");

        // Reject an empty reason.
        let err = helper
            .retire_forced("stuck", Some("run-1"), "   ")
            .unwrap_err()
            .to_string();
        assert!(err.contains("needs `--reason"), "{err}");

        let archived = helper
            .retire_forced(
                "stuck",
                Some("run-1"),
                "the profile, current-system and booted-system all name the old system.",
            )
            .expect("a person may put it aside");
        let forced = archived.retired_by_force.expect("the archive says why");
        assert_eq!(forced.was, TxnState::Inconsistent);
        assert_eq!(forced.run_id.as_deref(), Some("run-1"));
        assert!(forced.reason.starts_with("the profile"), "{forced:?}");
        // It is out of the way of the next plan, and it is still readable.
        assert!(helper.records().unwrap().is_empty());
        assert!(files.exists(&helper.txn_archive("stuck")));
        let text = String::from_utf8(files.content(helper.txn_archive("stuck")).unwrap()).unwrap();
        assert!(text.contains("retired_by_force"), "{text}");
        runner.verify().unwrap();
    }

    #[test]
    fn force_does_not_take_away_a_record_that_still_says_what_may_happen() {
        // Forced retirement cannot discard staged or pending rollback state.
        let files = host();
        let runner = StrictFake::new();
        let clock = clock();
        let helper = helper(&runner, &files, &clock);
        for state in [TxnState::Staged, TxnState::Pending] {
            let mut record = pending("open", Mode::Switch);
            record.state = state;
            helper.write_record(&record).unwrap();
            let err = helper
                .retire_forced("open", None, "I would like this to go away.")
                .unwrap_err()
                .to_string();
            assert!(err.contains("does not take that away"), "{state:?}: {err}");
            assert!(err.contains("Only an `inconsistent` record"), "{err}");
        }
        runner.verify().unwrap();
    }

    #[test]
    fn a_record_written_before_this_field_existed_still_reads_back() {
        // Old records omit this optional field; serialization preserves that omission.
        let record = TxnRecord::from_json(
            &serde_json::json!({
                "schema": TXN_SCHEMA,
                "id": "old",
                "run_id": null,
                "previous": {"toplevel": "/nix/store/aaa", "generation": 3},
                "desired": "/nix/store/bbb",
                "mode": "switch",
                "started_at": "2026-09-20T10:00:00Z",
                "deadline": null,
                "state": "confirmed",
                "reason": null,
                "changed_at": "2026-09-20T10:01:00Z"
            })
            .to_string(),
            "a record from before",
        )
        .expect("it reads back");
        assert_eq!(record.retired_by_force, None);
        // And writing it again does not invent the field.
        let text = String::from_utf8(record.to_json().unwrap()).unwrap();
        assert!(!text.contains("retired_by_force"), "{text}");
    }



    #[test]
    fn a_transaction_id_is_a_file_name_and_nothing_more() {
        let files = host();
        let runner = StrictFake::new();
        let clock = clock();
        let helper = helper(&runner, &files, &clock);
        for bad in ["../../etc/shadow", "a/b", "", "a b", "a;rm -rf /"] {
            let err = helper
                .activate(bad, TOP, Mode::Switch, 300, None)
                .unwrap_err()
                .to_string();
            assert!(err.contains("is not a transaction id"), "{bad}: {err}");
        }
        runner.verify().unwrap();
        assert!(files.attempts().is_empty(), "{:?}", files.attempts());
    }

    #[test]
    fn the_lock_is_one_door_and_the_second_run_reads_who_has_it() {
        let files = host();
        let runner = StrictFake::new();
        let clock = clock();
        let helper = helper(&runner, &files, &clock);
        let first = helper.lock_acquire("run-a", "silas@manacor", 42).unwrap();
        assert_eq!(first.run_id, "run-a");
        // The same run again is not an error: it is asking whether it may.
        assert_eq!(
            helper.lock_acquire("run-a", "silas@manacor", 42).unwrap(),
            first
        );
        let err = helper
            .lock_acquire("run-b", "silas@manacor", 43)
            .unwrap_err()
            .to_string();
        assert!(err.contains("held by the run run-a"), "{err}");
        assert!(err.contains("--takeover run-a"), "{err}");
        assert!(err.contains("never expires"), "{err}");

        // And only the holder gives it back.
        let err = helper.lock_release("run-b").unwrap_err().to_string();
        assert!(err.contains("does not hold this host"), "{err}");
        assert!(helper.lock_release("run-a").unwrap().is_some());
        assert!(helper.read_lock().unwrap().is_none());
        runner.verify().unwrap();
    }

    #[test]
    fn the_lock_record_is_exactly_what_the_read_only_probe_parses() {
        // The probe reads owner.json directly into the strict observation Lock schema.
        let files = host();
        let runner = StrictFake::new();
        let clock = clock();
        let helper = helper(&runner, &files, &clock);
        helper.lock_acquire("run-a", "silas@manacor", 42).unwrap();
        let text = String::from_utf8(files.content(helper.lock_path()).unwrap()).unwrap();
        let parsed: Lock = serde_json::from_str(&text).expect("the probe's own parse");
        assert_eq!(parsed.run_id, "run-a");
        assert_eq!(parsed.pid, 42);
        runner.verify().unwrap();
    }

    #[test]
    fn a_takeover_names_the_run_it_takes_over() {
        let files = host();
        let runner = StrictFake::new();
        let clock = clock();
        let helper = helper(&runner, &files, &clock);
        helper.lock_acquire("run-a", "silas@manacor", 1).unwrap();
        let err = helper
            .lock_take_over("run-x", "run-b", "silas@manacor", 2)
            .unwrap_err()
            .to_string();
        assert!(err.contains("held by the run run-a, not by run-x"), "{err}");
        let taken = helper
            .lock_take_over("run-a", "run-b", "silas@manacor", 2)
            .unwrap();
        assert_eq!(taken.run_id, "run-b");
        runner.verify().unwrap();
    }


    #[test]
    fn two_operators_carrying_one_run_do_not_both_hold_the_host() {
        let files = host();
        let runner = StrictFake::new();
        let clock = clock();
        let helper = helper(&runner, &files, &clock);
        let first = helper.lock_acquire("run-a", "silas@manacor", 42).unwrap();
        // A resumed run may carry a new PID on the same workstation.
        assert_eq!(
            helper.lock_acquire("run-a", "silas@manacor", 99).unwrap(),
            first
        );
        // A different operator carrying the same run ID is refused.
        let err = helper
            .lock_acquire("run-a", "leandro@calvia", 7)
            .unwrap_err()
            .to_string();
        assert!(err.contains("as it is carried by silas@manacor"), "{err}");
        assert!(err.contains("one writer"), "{err}");
        assert_eq!(helper.read_lock().unwrap().unwrap(), first);
        runner.verify().unwrap();
    }


    #[test]
    fn two_takeovers_of_one_run_leave_exactly_one_holder_of_the_host() {
        let files = host();
        let runner = StrictFake::new();
        let clock = clock();
        let helper = helper(&runner, &files, &clock);
        helper.lock_acquire("run-a", "silas@manacor", 1).unwrap();
        let winner = helper
            .lock_take_over("run-a", "run-b", "silas@manacor", 2)
            .unwrap();
        assert_eq!(winner.run_id, "run-b");
        // A second takeover must restore the first takeover’s fresh lock.
        let err = helper
            .lock_take_over("run-a", "run-c", "silas@manacor", 3)
            .unwrap_err()
            .to_string();
        assert!(err.contains("held by the run run-b"), "{err}");
        assert!(err.contains("Nothing was taken over"), "{err}");
        assert_eq!(helper.read_lock().unwrap().unwrap(), winner);
        assert!(
            !files.exists(
                &helper
                    .lock_path()
                    .with_file_name("owner.taken-by-run-c.json")
            ),
            "the claim of a takeover that failed is not left lying about"
        );
        runner.verify().unwrap();
    }



    #[test]
    fn a_takeover_of_a_host_the_taking_run_already_holds_is_the_answer_yes() {
        // The fleet anchor and host lock step may attempt the same takeover twice.
        let files = host();
        let runner = StrictFake::new();
        let clock = clock();
        let helper = helper(&runner, &files, &clock);
        let first = helper
            .lock_take_over("run-a", "run-b", "silas@manacor", 2)
            .expect("nobody holds it, so it is taken");
        assert_eq!(first.run_id, "run-b");
        let again = helper
            .lock_take_over("run-a", "run-b", "silas@manacor", 2)
            .expect("the same run asking twice is asking whether it may act");
        assert_eq!(again.run_id, "run-b");
        assert_eq!(again.acquired_at, first.acquired_at, "it was not retaken");
        // And a third run still cannot take it from run-b by naming run-a.
        let err = helper
            .lock_take_over("run-a", "run-c", "silas@manacor", 3)
            .unwrap_err()
            .to_string();
        assert!(err.contains("held by the run run-b, not by run-a"), "{err}");
        runner.verify().unwrap();
    }



    #[test]
    fn gc_keeps_the_current_the_booted_and_n_others() {
        let files = host();
        // The machine runs 41 and booted 38.
        let files = files.given_symlink("/nix/var/nix/profiles/system-38-link", "/nix/store/b38");
        let files = files.given_symlink("/run/booted-system", "/nix/store/b38");
        let runner = StrictFake::new()
            .expect(
                Matcher::exact(
                    "nix-env",
                    ["-p", "/nix/var/nix/profiles/system", "--list-generations"],
                ),
                Output::stdout(
                    "  36   2026-09-01 10:00:00\n  37   2026-09-02 10:00:00\n  \
                     38   2026-09-03 10:00:00\n  39   2026-09-04 10:00:00\n  \
                     40   2026-09-05 10:00:00\n  41   2026-09-06 10:00:00   (current)\n",
                ),
            )
            .expect(
                Matcher::exact(
                    "nix-env",
                    [
                        "-p",
                        "/nix/var/nix/profiles/system",
                        "--delete-generations",
                        "36",
                        "37",
                    ],
                ),
                Output::stdout(""),
            )
            .expect(
                Matcher::exact("nix-collect-garbage", none()),
                Output::stdout(""),
            );
        let clock = clock();
        let outcome = helper(&runner, &files, &clock).gc(2).unwrap();
        assert_eq!(outcome.kept, vec![38, 39, 40, 41]);
        assert_eq!(outcome.removed, vec![36, 37]);
        runner.verify().unwrap();
    }

    #[test]
    fn gc_refuses_while_a_transaction_is_open() {
        let files = host();
        let runner = StrictFake::new();
        let clock = clock();
        let helper = helper(&runner, &files, &clock);
        helper.write_record(&pending("g1", Mode::Switch)).unwrap();
        let err = helper.gc(3).unwrap_err().to_string();
        assert!(err.contains("must not be collected"), "{err}");
        runner.verify().unwrap();
    }

    #[test]
    fn a_dry_run_helper_refuses_every_mutation_before_it_spawns() {
        // The effect classes are not decoration: the same policy that makes
        // `--dry-run` real on the workstation makes it real here.
        let files = host().with_policy(Policy::dry_run());
        let runner = StrictFake::new()
            .with_policy(Policy::dry_run())
            .expect(valid(TOP), Output::stdout(""));
        let clock = clock();
        let err = helper(&runner, &files, &clock)
            .activate("d1", TOP, Mode::Switch, 300, None)
            .unwrap_err()
            .to_string();
        assert!(err.contains("--dry-run"), "{err}");
        runner.verify().unwrap();
    }

    #[test]
    fn a_generation_listing_is_read_by_its_first_field() {
        let parsed = parse_generations(
            "   1   2026-01-01 00:00:00\n  42   2026-09-06 10:00:00   (current)\nrubbish\n",
        );
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[1].number, 42);
        assert!(parsed[1].current);
        assert!(!parsed[0].current);
    }

    #[test]
    fn a_mode_is_one_of_two_words() {
        assert_eq!(Mode::parse("switch").unwrap(), Mode::Switch);
        assert_eq!(Mode::parse("boot").unwrap(), Mode::Boot);
        let err = Mode::parse("reboot").unwrap_err().to_string();
        assert!(err.contains("is not an activation mode"), "{err}");
    }

    #[test]
    fn a_record_round_trips_through_its_own_schema() {
        let record = pending("rt", Mode::Boot);
        let text = String::from_utf8(record.to_json().unwrap()).unwrap();
        assert_eq!(TxnRecord::from_json(&text, "a test").unwrap(), record);
        // Reject records with an unsupported schema.
        let wrong = text.replace(TXN_SCHEMA, "meister-deploy/activate-txn/2");
        let err = TxnRecord::from_json(&wrong, "a test")
            .unwrap_err()
            .to_string();
        assert!(err.contains("activate-txn/2"), "{err}");
    }



    const PKI: &str = "/var/lib/meisterstack/pki";

    fn chown(path: &str) -> Matcher {
        Matcher::exact("chown", ["meister:meister", path])
    }

    /// The property the whole of D10 rests on: the key is made here, it is
    /// written 0600, and what comes back is a request.
    #[test]
    fn a_key_is_made_on_the_host_and_only_a_request_leaves_it() {
        let runner =
            StrictFake::new().expect(chown(&format!("{PKI}/identity.key")), Output::default());
        let files = MemFiles::new();
        let clock = clock();
        let helper = helper(&runner, &files, &clock);
        let out = helper
            .keygen("system:node:n1", KeyKind::Identity, false)
            .unwrap();
        runner.verify().unwrap();

        assert!(out.created);
        assert_eq!(out.subject, "system:node:n1");
        assert_eq!(out.kind, "identity");
        assert!(
            out.csr_pem
                .starts_with("-----BEGIN CERTIFICATE REQUEST-----")
        );
        assert_eq!(out.public_key_sha256.len(), 64);

        // The key is on the host.
        let written =
            String::from_utf8(files.content(format!("{PKI}/identity.key")).unwrap()).unwrap();
        assert!(written.contains("PRIVATE KEY"), "{written}");
        // And in the answer there is no line of it.
        for line in written
            .lines()
            .filter(|l| !l.starts_with("-----") && l.len() > 16)
        {
            assert!(!out.csr_pem.contains(line), "a line of the key travelled");
        }
        let printed = serde_json::to_string(&out).unwrap();
        assert!(!printed.contains("PRIVATE KEY"), "{printed}");
    }

    /// 0600 from the start: created with the mode, not chmod'ed onto a file
    /// that was briefly readable (M0 probe S11, Gate M0 "D1 changed").
    #[test]
    fn the_key_is_written_with_the_mode_it_has_to_have() {
        let runner =
            StrictFake::new().expect(chown(&format!("{PKI}/serving.key")), Output::default());
        let files = MemFiles::new();
        let clock = clock();
        helper(&runner, &files, &clock)
            .keygen("meister-box", KeyKind::Serving, false)
            .unwrap();
        runner.verify().unwrap();
        assert!(
            files
                .attempts()
                .iter()
                .any(|a| a == &format!("write(0600) {PKI}/serving.key")),
            "{:?}",
            files.attempts()
        );
        // And the owner is the user that reads it, set by the one command
        // this function runs.
        assert_eq!(
            runner.calls(),
            vec![format!("chown meister:meister {PKI}/serving.key")]
        );
    }

    /// Retries preserve the key to which an already issued certificate is bound.
    #[test]
    fn a_second_run_keeps_the_key_and_makes_another_request() {
        let first_runner =
            StrictFake::new().expect(chown(&format!("{PKI}/identity.key")), Output::default());
        let files = MemFiles::new();
        let clock = clock();
        let first = helper(&first_runner, &files, &clock)
            .keygen("system:node:n1", KeyKind::Identity, false)
            .unwrap();
        first_runner.verify().unwrap();
        let key = files.content(format!("{PKI}/identity.key")).unwrap();

        // No chown, no write: the second run only reads.
        let runner = StrictFake::new();
        let again = helper(&runner, &files, &clock)
            .keygen("system:node:n1", KeyKind::Identity, false)
            .unwrap();
        runner.verify().unwrap();
        assert!(runner.calls().is_empty(), "{:?}", runner.calls());
        assert!(!again.created);
        assert_eq!(files.content(format!("{PKI}/identity.key")).unwrap(), key);
        assert_eq!(again.public_key_sha256, first.public_key_sha256);
        assert!(
            again
                .csr_pem
                .starts_with("-----BEGIN CERTIFICATE REQUEST-----")
        );
    }

    #[test]
    fn replace_is_the_deliberate_other_answer() {
        let first_runner =
            StrictFake::new().expect(chown(&format!("{PKI}/identity.key")), Output::default());
        let files = MemFiles::new();
        let clock = clock();
        let first = helper(&first_runner, &files, &clock)
            .keygen("system:node:n1", KeyKind::Identity, false)
            .unwrap();
        first_runner.verify().unwrap();

        let runner =
            StrictFake::new().expect(chown(&format!("{PKI}/identity.key")), Output::default());
        let replaced = helper(&runner, &files, &clock)
            .keygen("system:node:n1", KeyKind::Identity, true)
            .unwrap();
        runner.verify().unwrap();
        assert!(replaced.created);
        assert_ne!(replaced.public_key_sha256, first.public_key_sha256);
    }

    /// The two keys are two files, under the names every rendered
    /// configuration of this fleet points at.
    #[test]
    fn the_two_kinds_are_two_files() {
        let runner = StrictFake::new()
            .expect(chown(&format!("{PKI}/identity.key")), Output::default())
            .expect(chown(&format!("{PKI}/serving.key")), Output::default());
        let files = MemFiles::new();
        let clock = clock();
        let helper = helper(&runner, &files, &clock);
        helper
            .keygen("system:cluster:cp", KeyKind::Identity, false)
            .unwrap();
        helper
            .keygen("meister-box", KeyKind::Serving, false)
            .unwrap();
        runner.verify().unwrap();
        assert!(files.content(format!("{PKI}/identity.key")).is_some());
        assert!(files.content(format!("{PKI}/serving.key")).is_some());
        assert_eq!(
            helper.key_path(KeyKind::Identity).display().to_string(),
            format!("{PKI}/identity.key")
        );
        assert!(KeyKind::parse("identity").is_ok());
        assert!(KeyKind::parse("serving").is_ok());
        let err = KeyKind::parse("ca").unwrap_err();
        assert!(err.to_string().contains("identity"), "{err}");
    }

    /// A dry run makes no key: the refusal comes from the file door, before
    /// anything exists.
    #[test]
    fn a_dry_run_makes_nothing() {
        let runner = StrictFake::new().with_policy(Policy::dry_run());
        let files = MemFiles::new().with_policy(Policy::dry_run());
        let clock = clock();
        let err = helper(&runner, &files, &clock)
            .keygen("system:node:n1", KeyKind::Identity, false)
            .unwrap_err();
        assert!(err.to_string().contains("--dry-run"), "{err}");
        assert!(files.content(format!("{PKI}/identity.key")).is_none());
        runner.verify().unwrap();
    }

    /// A key that is there and cannot be read is not a key to replace by
    /// accident.
    #[test]
    fn an_unreadable_key_is_a_sentence_and_not_a_new_identity() {
        let runner = StrictFake::new();
        let files = MemFiles::new().given_other(format!("{PKI}/identity.key"));
        let clock = clock();
        let err = helper(&runner, &files, &clock)
            .keygen("system:node:n1", KeyKind::Identity, false)
            .unwrap_err();
        assert!(err.to_string().contains("--replace"), "{err}");
        runner.verify().unwrap();
    }

    fn pending(id: &str, mode: Mode) -> TxnRecord {
        let now = crate::fixtures::at("2026-09-22T12:00:00Z");
        TxnRecord {
            schema: TXN_SCHEMA.to_string(),
            id: id.to_string(),
            run_id: None,
            previous: SystemPoint {
                toplevel: Some(PREV.to_string()),
                generation: Some(41),
            },
            desired: TOP.to_string(),
            mode,
            started_at: now,
            deadline: Some(now + TimeDelta::try_seconds(300).unwrap()),
            state: TxnState::Pending,
            reason: None,
            changed_at: now,
            retired_by_force: None,
        }
    }



    /// A prepared key lies BESIDE the one in use, and nothing that is
    /// running notices it is there.
    #[test]
    fn a_prepared_key_is_written_next_to_the_one_in_use() {
        let runner = StrictFake::new().expect(
            chown(&format!("{PKI}/identity.key.next")),
            Output::default(),
        );
        let files = MemFiles::new().given(format!("{PKI}/identity.key"), "the key in use\n");
        let clock = clock();
        let made = helper(&runner, &files, &clock)
            .keygen_into("system:node:n1", KeyKind::Identity, true, Some("next"))
            .unwrap();
        runner.verify().unwrap();
        assert!(made.created);
        assert_eq!(
            files.content(format!("{PKI}/identity.key")).unwrap(),
            b"the key in use\n".to_vec(),
            "the key in use was replaced"
        );
        let next = files
            .content(format!("{PKI}/identity.key.next"))
            .expect("the prepared key");
        assert!(String::from_utf8(next).unwrap().contains("PRIVATE KEY"));
        assert!(!made.csr_pem.contains("PRIVATE KEY"));
        // 0600 from the start, like every other key this helper makes: the
        // attempt says with which mode it was created.
        assert!(
            files
                .attempts()
                .iter()
                .any(|a| a == &format!("write(0600) {PKI}/identity.key.next")),
            "{:?}",
            files.attempts()
        );
    }

    /// Repeated preparation reuses the key bound to the pending certificate.
    #[test]
    fn preparing_twice_prepares_one_key() {
        let first = StrictFake::new().expect(
            chown(&format!("{PKI}/identity.key.next")),
            Output::default(),
        );
        let files = MemFiles::new();
        let clock = clock();
        let one = helper(&first, &files, &clock)
            .keygen_into("system:node:n1", KeyKind::Identity, false, Some("next"))
            .unwrap();
        let runner = StrictFake::new();
        let two = helper(&runner, &files, &clock)
            .keygen_into("system:node:n1", KeyKind::Identity, false, Some("next"))
            .unwrap();
        assert!(runner.calls().is_empty(), "{:?}", runner.calls());
        assert!(!two.created);
        assert_eq!(one.public_key_sha256, two.public_key_sha256);
    }

    /// A rotation with a prepared pair, ready to switch.
    fn rotating() -> MemFiles {
        MemFiles::new()
            .given(format!("{PKI}/identity.key"), "old key\n")
            .given(format!("{PKI}/identity.crt"), "old certificate\n")
            .given(format!("{PKI}/identity.key.next"), "new key\n")
            .given(format!("{PKI}/identity.crt.next"), "new certificate\n")
    }

    /// The five states, read off the DISK. The record is the story of a
    /// rotation; the files are what it actually did.
    #[test]
    fn where_a_rotation_got_to_is_read_off_the_disk() {
        let runner = StrictFake::new();
        let clock = clock();

        let nothing = MemFiles::new();
        assert_eq!(
            helper(&runner, &nothing, &clock)
                .keys_status(KeyKind::Identity)
                .unwrap()
                .state,
            KeysState::None
        );

        let prepared = MemFiles::new().given(format!("{PKI}/identity.key.next"), "k\n");
        assert_eq!(
            helper(&runner, &prepared, &clock)
                .keys_status(KeyKind::Identity)
                .unwrap()
                .state,
            KeysState::Prepared
        );

        let overlap = rotating();
        assert_eq!(
            helper(&runner, &overlap, &clock)
                .keys_status(KeyKind::Identity)
                .unwrap()
                .state,
            KeysState::Overlap
        );

        let switched = MemFiles::new()
            .given(format!("{PKI}/identity.key"), "new key\n")
            .given(format!("{PKI}/identity.crt"), "new certificate\n")
            .given(format!("{PKI}/identity.key.prev"), "old key\n")
            .given(format!("{PKI}/identity.crt.prev"), "old certificate\n");
        assert_eq!(
            helper(&runner, &switched, &clock)
                .keys_status(KeyKind::Identity)
                .unwrap()
                .state,
            KeysState::Switched
        );

        // A certificate with no key beside it is a state this tool has no
        // rule for, and it says so rather than guessing.
        let half = MemFiles::new().given(format!("{PKI}/identity.crt.next"), "c\n");
        let view = helper(&runner, &half, &clock)
            .keys_status(KeyKind::Identity)
            .unwrap();
        assert_eq!(view.state, KeysState::Inconsistent);
        assert!(view.reason.unwrap().contains("without the key"));
    }


    #[test]
    fn keys_status_names_every_half_switch() {
        // Check each partial layout between the four switch renames: old certificate aside,
        // old key aside, then new key installed. None is a completed switch.
        let runner = StrictFake::new();
        let clock = clock();
        let key = format!("{PKI}/identity.key");
        let crt = format!("{PKI}/identity.crt");
        let key_next = format!("{PKI}/identity.key.next");
        let crt_next = format!("{PKI}/identity.crt.next");
        let key_prev = format!("{PKI}/identity.key.prev");
        let crt_prev = format!("{PKI}/identity.crt.prev");

        for (after, there) in [
            (
                "the certificate went aside",
                vec![&key, &key_next, &crt_next, &crt_prev],
            ),
            (
                "the key went aside too",
                vec![&key_next, &crt_next, &key_prev, &crt_prev],
            ),
            (
                "the new key came in",
                vec![&key, &crt_next, &key_prev, &crt_prev],
            ),
        ] {
            let files = there.iter().fold(MemFiles::new(), |files, path| {
                files.given((*path).clone(), "x\n")
            });
            let view = helper(&runner, &files, &clock)
                .keys_status(KeyKind::Identity)
                .unwrap();
            assert_eq!(
                view.state,
                KeysState::Inconsistent,
                "after {after} the switch is not finished"
            );
            let reason = view.reason.unwrap_or_default();
            assert!(
                reason.contains("stopped in the middle"),
                "{after}: {reason}"
            );
            // And it says what is on the disk, which is what a person needs.
            for path in &there {
                assert!(reason.contains(path.as_str()), "{after}: {reason}");
            }
        }

        // The one tuple that IS a finished switch still is one.
        let whole = [&key, &crt, &key_prev, &crt_prev]
            .iter()
            .fold(MemFiles::new(), |files, path| {
                files.given((*path).clone(), "x\n")
            });
        assert_eq!(
            helper(&runner, &whole, &clock)
                .keys_status(KeyKind::Identity)
                .unwrap()
                .state,
            KeysState::Switched
        );
    }

    /// The switch: four renames, and the record says what was replaced.
    #[test]
    fn the_switch_puts_the_prepared_pair_in_and_the_old_one_aside() {
        let runner = StrictFake::new();
        let files = rotating();
        let clock = clock();
        let record = helper(&runner, &files, &clock)
            .keys_switch(KeyKind::Identity, Some("run-7"))
            .unwrap();
        assert!(runner.calls().is_empty(), "a switch runs no command");

        assert_eq!(
            files.content(format!("{PKI}/identity.key")).unwrap(),
            b"new key\n".to_vec()
        );
        assert_eq!(
            files.content(format!("{PKI}/identity.crt")).unwrap(),
            b"new certificate\n".to_vec()
        );
        assert_eq!(
            files.content(format!("{PKI}/identity.key.prev")).unwrap(),
            b"old key\n".to_vec()
        );
        assert!(files.content(format!("{PKI}/identity.key.next")).is_none());
        assert_eq!(record.state, KeysState::Switched);
        assert_eq!(record.run_id.as_deref(), Some("run-7"));
        assert_eq!(
            record.previous_sha256,
            Some(format!(
                "sha256:{}",
                crate::ids::sha256_hex(b"old certificate\n")
            ))
        );
        assert_eq!(
            record.sha256,
            Some(format!(
                "sha256:{}",
                crate::ids::sha256_hex(b"new certificate\n")
            ))
        );
        // And it is on the disk, where a resume reads it.
        assert_eq!(
            helper(&runner, &files, &clock)
                .keys_status(KeyKind::Identity)
                .unwrap()
                .record
                .unwrap(),
            record
        );
    }

    /// Half a prepared pair is not a switch.
    #[test]
    fn a_switch_without_a_certificate_is_a_sentence() {
        let runner = StrictFake::new();
        let files = MemFiles::new()
            .given(format!("{PKI}/identity.key"), "old key\n")
            .given(format!("{PKI}/identity.key.next"), "new key\n");
        let clock = clock();
        let err = helper(&runner, &files, &clock)
            .keys_switch(KeyKind::Identity, None)
            .unwrap_err()
            .to_string();
        assert!(err.contains("prepared"), "{err}");
        assert_eq!(
            files.content(format!("{PKI}/identity.key")).unwrap(),
            b"old key\n".to_vec(),
            "nothing was moved"
        );
    }

    /// The way back, and what it leaves: the pair that worked, and a record
    /// that says why the other one did not.
    #[test]
    fn a_revert_puts_the_pair_that_worked_back() {
        let runner = StrictFake::new();
        let files = rotating();
        let clock = clock();
        helper(&runner, &files, &clock)
            .keys_switch(KeyKind::Identity, Some("run-7"))
            .unwrap();
        let record = helper(&runner, &files, &clock)
            .keys_revert(KeyKind::Identity, Some("the session did not come back"))
            .unwrap();

        assert_eq!(
            files.content(format!("{PKI}/identity.key")).unwrap(),
            b"old key\n".to_vec()
        );
        assert_eq!(
            files.content(format!("{PKI}/identity.crt")).unwrap(),
            b"old certificate\n".to_vec()
        );
        assert!(files.content(format!("{PKI}/identity.key.prev")).is_none());
        assert!(files.content(format!("{PKI}/identity.key.next")).is_none());
        assert_eq!(record.state, KeysState::Reverted);
        assert!(record.reason.unwrap().contains("did not come back"));
        assert_eq!(
            helper(&runner, &files, &clock)
                .keys_status(KeyKind::Identity)
                .unwrap()
                .state,
            KeysState::Reverted,
            "the disk is clean again, and the record is what remembers"
        );
    }

    /// And the last step: what the switch replaced goes away.
    #[test]
    fn remove_drops_the_pair_the_switch_replaced() {
        let runner = StrictFake::new();
        let files = rotating();
        let clock = clock();
        helper(&runner, &files, &clock)
            .keys_switch(KeyKind::Identity, Some("run-7"))
            .unwrap();
        let record = helper(&runner, &files, &clock)
            .keys_remove(KeyKind::Identity)
            .unwrap();
        assert_eq!(record.state, KeysState::Confirmed);
        assert!(files.content(format!("{PKI}/identity.key.prev")).is_none());
        assert!(files.content(format!("{PKI}/identity.crt.prev")).is_none());
        assert_eq!(
            files.content(format!("{PKI}/identity.key")).unwrap(),
            b"new key\n".to_vec()
        );
        assert_eq!(
            helper(&runner, &files, &clock)
                .keys_status(KeyKind::Identity)
                .unwrap()
                .state,
            KeysState::Confirmed
        );
        // Repeated removal is rejected.
        assert!(
            helper(&runner, &files, &clock)
                .keys_remove(KeyKind::Identity)
                .is_err()
        );
    }

    /// A key rotation is not a system transaction, and a plan that read it
    /// as one would block the host for ever.
    #[test]
    fn a_key_rotation_is_not_an_open_transaction() {
        let runner = StrictFake::new();
        let files = rotating();
        let clock = clock();
        helper(&runner, &files, &clock)
            .keys_switch(KeyKind::Identity, Some("run-7"))
            .unwrap();
        assert!(
            files
                .content("/var/lib/meisterstack/deploy/txn/keys-identity.json")
                .is_some(),
            "the record is in the transaction directory"
        );
        assert!(
            helper(&runner, &files, &clock)
                .records()
                .unwrap()
                .is_empty(),
            "a key record was read as a system transaction"
        );
        // And through the door a snapshot comes in by. `uname -r` is the
        // one command a status runs.
        let asking =
            StrictFake::new().expect(Matcher::exact("uname", ["-r"]), Output::stdout("6.12.48\n"));
        assert!(
            helper(&asking, &files, &clock)
                .status()
                .unwrap()
                .open_txns
                .is_empty()
        );
    }



    fn deciding_path(helper: &Helper<'_>) -> PathBuf {
        helper.txn_dir().join("run-1.deciding")
    }

    #[test]
    fn a_decision_file_this_program_did_not_write_is_not_replaced() {
        let files = host();
        let runner = StrictFake::new();
        let clock = clock();
        let helper = helper(&runner, &files, &clock);
        let path = deciding_path(&helper);
        files.create_dir_all(&helper.txn_dir()).unwrap();
        files.write_atomic(&path, b"rubbish", 0o600).unwrap();
        let err = helper
            .deciding("run-1", "confirm", || Ok(()))
            .unwrap_err()
            .to_string();
        assert!(err.contains("not a record this program wrote"), "{err}");
        assert_eq!(
            files.read_to_string(&path).unwrap(),
            "rubbish",
            "left as it was"
        );
    }

    #[test]
    fn a_decision_whose_holder_died_is_succeeded_and_given_back_afterwards() {
        let files = host();
        let runner = StrictFake::new();
        let clock = clock();
        let helper = helper(&runner, &files, &clock);
        let path = deciding_path(&helper);
        files.create_dir_all(&helper.txn_dir()).unwrap();
        // Positive, and above every `pid_max` a Linux kernel hands out.
        files
            .write_atomic(
                &path,
                b"revert pid 2147483646 at 2026-09-22 11:00:00 UTC",
                0o600,
            )
            .unwrap();
        let mine = format!("confirm pid {} at ", std::process::id());
        let out = helper
            .deciding("run-1", "confirm", || {
                let held = files.read_to_string(&path).unwrap();
                assert!(held.starts_with(&mine), "{held}");
                Ok(7)
            })
            .unwrap();
        assert_eq!(out, 7);
        assert!(!files.exists(&path), "given back");
        let claim = path.with_file_name(format!("run-1.deciding.taken-by-{}", std::process::id()));
        assert!(!files.exists(&claim), "no claim is left lying about");
    }

    #[test]
    fn a_decision_being_made_by_a_running_process_is_refused_as_such() {
        let files = host();
        let runner = StrictFake::new();
        let clock = clock();
        let helper = helper(&runner, &files, &clock);
        let path = deciding_path(&helper);
        files.create_dir_all(&helper.txn_dir()).unwrap();
        // pid 1 is init: `kill(1, 0)` answers EPERM, which is "running".
        files
            .write_atomic(&path, b"revert pid 1 at 2026-09-22 11:00:00 UTC", 0o600)
            .unwrap();
        let err = helper.deciding("run-1", "confirm", || Ok(())).unwrap_err();
        let held = err
            .downcast_ref::<BeingDecided>()
            .expect("the refusal is the typed one");
        assert_eq!(held.id, "run-1");
        assert!(held.holder.contains("revert pid 1"), "{}", held.holder);
        assert_eq!(
            files.read_to_string(&path).unwrap(),
            "revert pid 1 at 2026-09-22 11:00:00 UTC",
            "left as it was"
        );
    }

    #[test]
    fn a_decision_gives_back_only_its_own_record() {
        let files = host();
        let runner = StrictFake::new();
        let clock = clock();
        let helper = helper(&runner, &files, &clock);
        let path = deciding_path(&helper);
        // Dropping an old guard must preserve its successor's lock record.
        helper
            .deciding("run-1", "confirm", || {
                files
                    .write_atomic(&path, b"revert pid 1 at 2026-09-22 11:30:00 UTC", 0o600)
                    .unwrap();
                Ok(())
            })
            .unwrap();
        assert_eq!(
            files.read_to_string(&path).unwrap(),
            "revert pid 1 at 2026-09-22 11:30:00 UTC"
        );
    }



    /// A runner under which one command takes a while.
    struct Slow<'a> {
        inner: StrictFake,
        clock: &'a FakeClock,
        program: String,
        by: Duration,
    }

    impl Runner for Slow<'_> {
        fn run(&self, cmd: &Cmd) -> Result<Output> {
            let out = self.inner.run(cmd)?;
            if cmd.program == self.program {
                self.clock.advance(self.by);
            }
            Ok(out)
        }

        fn policy(&self) -> Policy {
            self.inner.policy()
        }
    }

    #[test]
    fn an_activation_that_outlasts_its_deadline_is_taken_back_before_it_returns() {
        let files = host();
        let runner = StrictFake::new()
            .expect(valid(TOP), Output::stdout(""))
            .expect(
                Matcher::prefix("systemd-run", ["--on-active=300"]),
                Output::stdout(""),
            )
            .expect(
                Matcher::exact(
                    "nix-env",
                    ["-p", "/nix/var/nix/profiles/system", "--set", TOP],
                ),
                Output::stdout(""),
            )
            .expect(
                Matcher::exact(&format!("{TOP}/bin/switch-to-configuration"), ["switch"]),
                Output::stdout(""),
            )
            // The way back, by the activation itself and not by a timer.
            .expect(Matcher::prefix("systemctl", ["stop"]), Output::stdout(""))
            .expect(
                Matcher::prefix("systemctl", ["is-active"]),
                Output::failing(3, "inactive"),
            )
            .expect(
                Matcher::exact(
                    "nix-env",
                    ["-p", "/nix/var/nix/profiles/system", "--set", PREV],
                ),
                Output::stdout(""),
            )
            .expect(
                Matcher::exact(&format!("{PREV}/bin/switch-to-configuration"), ["switch"]),
                Output::stdout(""),
            );
        let clock = clock();
        // The switch takes 400 s; the confirmation window is 300 s.
        let runner = Slow {
            inner: runner,
            clock: &clock,
            program: format!("{TOP}/bin/switch-to-configuration"),
            by: Duration::from_secs(400),
        };
        let helper = helper_with(&runner, &files, &clock);
        let err = helper
            .activate("run-1", TOP, Mode::Switch, 300, Some("run-1"))
            .unwrap_err()
            .to_string();
        assert!(err.contains("was taken back to"), "{err}");
        assert!(
            err.contains("nobody could have confirmed it in time"),
            "{err}"
        );
        let record = helper.record("run-1").unwrap();
        assert_eq!(record.state, TxnState::Reverted);
        assert!(
            record
                .reason
                .as_deref()
                .unwrap()
                .contains("nobody could have confirmed"),
            "{record:?}"
        );
        assert!(
            !files.exists(&helper.txn_dir().join("run-1.deciding")),
            "the decision lock is given back"
        );
        runner.inner.verify().unwrap();
    }

    #[test]
    fn an_activation_holds_the_decision_lock_while_it_moves_the_machine() {
        let files = host();
        let runner = StrictFake::new()
            .expect(valid(TOP), Output::stdout(""))
            .expect(
                Matcher::prefix("systemd-run", ["--on-active=300"]),
                Output::stdout(""),
            )
            .expect(
                Matcher::exact(
                    "nix-env",
                    ["-p", "/nix/var/nix/profiles/system", "--set", TOP],
                ),
                Output::stdout(""),
            )
            .expect(
                Matcher::exact(&format!("{TOP}/bin/switch-to-configuration"), ["switch"]),
                Output::stdout(""),
            );
        let clock = clock();
        let helper = helper(&runner, &files, &clock);
        helper
            .activate("run-1", TOP, Mode::Switch, 300, Some("run-1"))
            .unwrap();
        runner.verify().unwrap();
        // Check that lock creation precedes the record and removal follows it.
        let attempts = files.attempts();
        let taken = attempts
            .iter()
            .position(|a| a.contains("create_new") && a.contains("run-1.deciding"))
            .expect("the decision lock was taken");
        let written = attempts
            .iter()
            .position(|a| a.contains("write(0600)") && a.contains("txn/run-1.json"))
            .expect("the record was written");
        let given_back = attempts
            .iter()
            .rposition(|a| a.contains("remove") && a.contains("run-1.deciding"))
            .expect("the decision lock was given back");
        assert!(taken < written && written < given_back, "{attempts:?}");
        assert!(!files.exists(&helper.txn_dir().join("run-1.deciding")));
    }

    #[test]
    fn the_deadline_waits_for_a_running_decision_and_an_operator_does_not() {
        let files = host();
        let quiet = StrictFake::new();
        let clock = clock();
        let helper = helper(&quiet, &files, &clock);
        files.create_dir_all(&helper.txn_dir()).unwrap();
        // pid 1 is init: `kill(1, 0)` answers EPERM, which is "running".
        files
            .write_atomic(
                &helper.txn_dir().join("d1.deciding"),
                b"activate pid 1 at 2026-09-22 12:00:00 UTC",
                0o600,
            )
            .unwrap();

        // An operator is told at once.
        let err = helper
            .revert("d1", Some("a check failed"), RevertAsker::Operator)
            .unwrap_err();
        assert!(err.downcast_ref::<BeingDecided>().is_some(), "{err:#}");
        assert!(
            clock.slept().is_empty(),
            "an operator's revert does not wait"
        );

        // The deadline waits as long as the forward path can take, and then
        // says that it did.
        let err = helper
            .revert("d1", Some("nobody confirmed"), RevertAsker::Deadline)
            .unwrap_err();
        assert!(err.downcast_ref::<BeingDecided>().is_some(), "{err:#}");
        assert!(err.to_string().contains("gave up"), "{err:#}");
        let slept: Duration = clock.slept().iter().sum();
        assert!(slept >= DEADLINE_PATIENCE, "{slept:?}");
        // Nothing ran and nothing was written: the machine is as it was.
        quiet.verify().unwrap();
        assert_eq!(
            files
                .read_to_string(&helper.txn_dir().join("d1.deciding"))
                .unwrap(),
            "activate pid 1 at 2026-09-22 12:00:00 UTC"
        );
    }
}
