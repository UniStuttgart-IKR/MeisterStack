// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! What runs ON the target, and why it has to be a program of its own.
//!
//! `meister-activate` is the second binary of this crate (D5). It knows no
//! network, no manifest and no fleet: it moves the system profile of the
//! machine it is on, and it writes down what it did before it does it. The
//! whole rollback story of M2 stands on that record, because the operator's
//! journal can only say what happened up to the line it managed to write —
//! and the interesting failures are the ones where the machine goes away in
//! the middle of the sentence. The target can answer the rest, and this is
//! the program that answers.
//!
//! Three properties are the reason this is not a shell script that `ssh`
//! pipes in:
//!
//! * **The record is written first, durably.** `txn/<id>.json` lands with a
//!   temporary plus rename plus fsync BEFORE the profile moves, so a machine
//!   that dies during `switch-to-configuration` still has a record that says
//!   which generation it came from. A resume asks for that record
//!   ([`crate::receipt::next_step`]) and never repeats an activation blind.
//! * **The way back is armed before the way forward.** The revert timer is a
//!   transient systemd unit, and it is created BEFORE `nix-env --set`. That
//!   is a deliberate departure from the order the lane brief wrote down (it
//!   says "afterwards"): `switch-to-configuration switch` restarts sshd, so
//!   the connection this program runs over can die in the middle of it — and
//!   a revert timer that is armed after the switch is a revert timer that a
//!   cut connection means the machine never gets. V16 ("SSH cut during the
//!   activation, and the target takes itself back") is only true this way
//!   round. The cost is that a failure between arming and switching has to
//!   disarm it again, which [`Helper::activate`] does.
//! * **Nothing decides by itself what is open.** A record is retired by the
//!   run that owns it (`txn retire`), not by reaching a state. So a run that
//!   was interrupted leaves its record behind, which is exactly what makes
//!   the next plan refuse to start over ([`crate::plan`] blocks on any open
//!   transaction) and a resume able to find out what happened.
//!
//! Everything goes through [`Runner`], [`Files`] and [`Clock`], on the
//! target as much as on the workstation: the command lines are then
//! readable in a unit test, which is the only place the ones that reboot a
//! machine can be read at all.

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

/// The transaction record's own schema. Read by this program and by nobody
/// else — the fleet sees it through `status --json`
/// ([`crate::observe::ActivateStatus`]) — but versioned all the same,
/// because it is a file that has to be readable by the NEXT version of this
/// program after a reboot.
pub const TXN_SCHEMA: &str = "meister-deploy/activate-txn/1";

/// The profile every NixOS system boots from.
pub const SYSTEM_PROFILE: &str = "/nix/var/nix/profiles/system";

/// What `/run` says about the system that is running and the one that booted.
pub const CURRENT_SYSTEM: &str = "/run/current-system";
pub const BOOTED_SYSTEM: &str = "/run/booted-system";

/// How long the small local commands may take. A `systemctl is-active` that
/// takes a minute is a machine in trouble, and hanging here would hang the
/// rollout that is waiting for the answer.
const QUICK: Duration = Duration::from_secs(30);

/// How long `switch-to-configuration` may take. It stops and starts every
/// unit of the system; on a host with guests on it that is not quick, and a
/// deadline that cut it off half way would be worse than waiting.
const SWITCH: Duration = Duration::from_secs(900);

/// How long the garbage collector may take. It walks the whole store.
const COLLECT: Duration = Duration::from_secs(3600);

/// Where a managed host keeps its key material (`meisterstack.pki.dir` of
/// `nix/managed.nix`). The directory is created by that profile's tmpfiles
/// rules before anything runs; this is the default so that an operator at a
/// console types no path.
pub const DEFAULT_PKI_DIR: &str = "/var/lib/meisterstack/pki";

/// Who reads a key on a managed host.
///
/// The service user, and therefore the OWNER — `meister:meister 0600` and
/// not `root:meister 0640`, because every key loader in this project
/// refuses a mode with group bits in it (M0 probe S11, Gate M0 "D1
/// changed"). Root reads it anyway.
pub const KEY_OWNER: &str = "meister";

/// What a transient unit gets to find its programs in when nobody says
/// otherwise.
///
/// `systemd-run` gives a transient service systemd's own default PATH —
/// `/usr/bin:/bin` — and on a NixOS host there is no `nix-env` in either
/// (measured: the first run of the VM test reverted nothing and said
/// "nix-env could not be started"). This is the directory every program of
/// a NixOS system is in, and it follows the system profile, so after a
/// revert it is the OLD system's `nix-env` — which is the right one to be
/// holding at that point.
pub const SYSTEM_PATH: &str = "/run/current-system/sw/bin";

/// Which way an activation goes, and therefore which way it comes back.
///
/// Not [`crate::plan::RollbackMode`], which has a third value: `none` is a
/// statement about a step that changes nothing, and "activate in mode none"
/// is not a thing this program can be asked to do.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    /// The running system changes now, and `switch-to-configuration switch`
    /// takes it back when nobody confirms.
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
    /// The store path of the system. Null only on a machine whose profile
    /// could not be read, and then an activation is refused rather than
    /// recorded with a hole in it.
    pub toplevel: Option<String>,
    pub generation: Option<u64>,
}

// --- lane 5C ---
/// Why a record that was still open was put aside anyway.
///
/// Only an `inconsistent` record can get one of these, and only because a
/// person typed a sentence. It travels INTO the archive rather than beside
/// it: an archive that does not say why it exists is a file somebody finds
/// in a year and cannot read.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ForcedRetirement {
    /// What the operator typed. A whole sentence, because it is the only
    /// account of a decision nothing else records.
    pub reason: String,
    /// The run that asked, where there was one.
    pub run_id: Option<String>,
    pub at: DateTime<Utc>,
    /// The state the record was in when it was put aside.
    pub was: TxnState,
}
// --- end lane 5C ---

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
    /// When the revert timer fires. Null when there is none — a
    /// `--confirm-within 0` activation, which is the one an operator drives
    /// by hand.
    pub deadline: Option<DateTime<Utc>>,
    pub state: TxnState,
    /// Why it is in that state, for the two states that have a reason:
    /// `reverted` and `inconsistent`.
    pub reason: Option<String>,
    /// When the state last moved. The record is the evidence, and evidence
    /// without a time on it is half of one.
    pub changed_at: DateTime<Utc>,
    // --- lane 5C ---
    /// Set only by `txn retire --force`, and only on a record the machine
    /// could no longer say anything coherent about. Absent everywhere
    /// else, which is why it is skipped rather than written as null: a
    /// record this program wrote before this field existed has to keep
    /// reading back.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retired_by_force: Option<ForcedRetirement>,
    // --- end lane 5C ---
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

    /// Whether this transaction is still in flight: something was done and
    /// nobody has said how it ended.
    pub fn is_open(&self) -> bool {
        matches!(
            self.state,
            TxnState::Staged | TxnState::Pending | TxnState::Inconsistent
        )
    }

    /// The state in the spelling a sentence and a table use.
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

/// A transaction id has to be a file name and nothing more.
///
/// `--txn ../../../etc/shadow` would otherwise be a path this program
/// writes to as root. The allowed set is what a uuid, a run id and a
/// hand-typed name need and no more.
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
    /// This program, as the revert timer will have to name it. Its own path
    /// rather than `/run/current-system/sw/bin/meister-activate`: the timer
    /// has to survive an activation that changes what that name points at,
    /// and a store path is pinned by the generation that holds it.
    pub own_exe: PathBuf,
    /// The `PATH` the revert timer's unit runs with. A value rather than a
    /// read of this process's environment, so that a test can pin it and so
    /// that this module reads no environment of its own.
    pub timer_path: String,
    /// Where this host's key material lives (`meisterstack.pki.dir`). An
    /// argument for the same reason the profile is one: a test moves a
    /// directory that is not this machine's.
    pub pki_dir: PathBuf,
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
        }
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

    /// Where a retired record goes. Not `<id>.json`, because the read-only
    /// probe of a host globs exactly that name to find what is open
    /// ([`crate::observe::ProbeSpec::script`]) — an archive that answered
    /// that glob would block every plan after a successful run.
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

    /// What this machine is, in the contract lane 2A's probe merges.
    ///
    /// Every field is what could be read and null where it could not: a
    /// helper that guessed a system path would be a helper that made a
    /// rollout act on a guess.
    pub fn status(&self) -> Result<ActivateStatus> {
        Ok(ActivateStatus {
            schema: ACTIVATE_STATUS_SCHEMA.to_string(),
            current_system: self.resolve(Path::new(CURRENT_SYSTEM)),
            booted_system: self.resolve(Path::new(BOOTED_SYSTEM)),
            // The system profile IS the next boot: `switch-to-configuration
            // boot` installs the entry for the generation the profile points
            // at, and a `--mode boot` activation sets the one-shot entry to
            // that same generation. What happens the boot AFTER an
            // unconfirmed one is the previous generation, and that is the
            // transaction's business rather than this field's.
            next_boot_system: self.resolve(&self.profile),
            generation: self.generation(),
            kernel_running: self.kernel_running(),
            kernel_booted: self.kernel_booted(),
            open_txns: self.open_txns()?,
            lock: self.read_lock()?,
        })
    }

    /// Follow a chain of symbolic links to the thing at the end of it.
    ///
    /// `/run/current-system` is one link to a store path; the system profile
    /// is a link to `system-42-link`, which is a link to a store path. Both
    /// have to come out as the store path a release names. `None` for
    /// anything that cannot be read, which on a host that has never been
    /// deployed to is the normal answer.
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
                // A link that points at something that is not there: what the
                // link SAYS is still the answer — a system whose closure has
                // been collected is a fact worth reporting, and whether the
                // path is valid is `stage`'s question, asked with the tool
                // that can answer it. Only a path that was not even a link is
                // nothing.
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

    /// The three fields a release promises about a boot, read off the
    /// generation that actually booted.
    ///
    /// All three or none: the planner compares them as a triple, and a
    /// half-read triple would compare unequal and cost a reboot nobody
    /// needed. `kernel-params` is hashed rather than carried, because the
    /// command line can hold a token and a digest cannot.
    fn kernel_booted(&self) -> Option<BootedKernel> {
        // Through the store path rather than through `/run/booted-system/…`:
        // the three files are IN the generation, and naming them there is
        // what makes the answer a fact about a generation rather than about
        // a symlink that a later activation moves.
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

    /// Every record in the transaction directory, newest name last.
    ///
    /// A file that does not parse is not dropped: it becomes a record in
    /// state `inconsistent`, because a half-written transaction record is
    /// the single most important thing a resume can find — it means a
    /// machine died while writing one, and guessing past it is how the wrong
    /// generation gets confirmed.
    pub fn records(&self) -> Result<Vec<TxnRecord>> {
        let mut out = Vec::new();
        for path in self.files.list_dir(&self.txn_dir())? {
            let Some(name) = path.file_name().map(|n| n.to_string_lossy().into_owned()) else {
                continue;
            };
            let Some(id) = name.strip_suffix(".json") else {
                continue;
            };
            // --- lane 5A ---
            // A key rotation lives in the same directory and is not a
            // system transaction. Reading one here would turn it into an
            // `inconsistent` record — and an inconsistent record blocks
            // every plan for that host, for ever. `keys status` is what
            // reads these.
            if id.starts_with("keys-") {
                continue;
            }
            // --- end lane 5A ---
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

    /// Write a record so that it is on the disk when this returns.
    ///
    /// 0600 and root-owned by the directory it is in: the record says which
    /// generation a machine will roll back to, and a file anybody could edit
    /// would be a file anybody could use to choose that generation.
    fn write_record(&self, record: &TxnRecord) -> Result<()> {
        self.files.create_dir_all(&self.txn_dir())?;
        self.files
            .write_atomic(&self.txn_path(&record.id), &record.to_json()?, 0o600)
    }

    // -----------------------------------------------------------------
    // stage
    // -----------------------------------------------------------------

    /// Is this system here, whole, and is it a system?
    ///
    /// `nix-store --check-validity` rather than the `nix path-info` the lane
    /// brief names: it needs no experimental feature — a host whose
    /// `nix-command` is off would refuse the `path-info` form for a reason
    /// that has nothing to do with the question — and it is the question in
    /// the store's own words.
    ///
    /// It answers for the closure and not only for the top of it, and that
    /// is a property of the store rather than a flag on the command: nix
    /// keeps referential integrity, so a path is registered as valid only
    /// once everything it references is. (The first draft of this asked for
    /// `--recursive`, which `nix-store` does not have; the VM test said so.)
    /// What it does NOT do is re-hash the bytes: that was the `nix copy`'s
    /// job, with `require-sigs = true` behind it (M0 probe S12), and doing
    /// it again here would be the same check with the weaker tool.
    ///
    /// Writes nothing, and that is the point of the verb: a staged host is a
    /// host whose running system has not been touched.
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

    /// Move this machine to a new system, having first written down where it
    /// was and armed the way back.
    ///
    /// The order is the guarantee, and it is this:
    ///
    /// 1. refuse if somebody else holds the host or a transaction is open;
    /// 2. read where the machine is now — the way back is a fact about this
    ///    machine and not something the caller may assert;
    /// 3. write the record, `fsync`ed;
    /// 4. arm the revert timer (see the module documentation for why here
    ///    and not at the end);
    /// 5. move the profile and run `switch-to-configuration`;
    /// 6. in boot mode, point the one-shot entry at the new generation and
    ///    leave the DEFAULT on the old one — which is what makes an
    ///    unconfirmed boot a boot that happens once.
    ///
    /// Anything that fails from step 5 on disarms the timer and marks the
    /// record `reverted` with the reason, because a machine that was not
    /// moved must not be left with a timer that will move it back.
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
        // Boot mode is only a mode where there is a boot menu to put an
        // entry in. Refused BEFORE anything is written, because the whole
        // point of the mode is the way back (D5's documented limit).
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
        self.write_record(&record)?;

        if deadline.is_some()
            && let Err(e) = self.arm_timer(id, confirm_within)
        {
            // Nothing has been touched, so the transaction is closed rather
            // than left pending for a timer that does not exist. `reverted`
            // is the state for "the machine is on `previous`", and never
            // having left it is a case of that.
            record.state = TxnState::Reverted;
            record.changed_at = self.clock.now();
            record.reason = Some(format!("{e:#}"));
            self.write_record(&record)?;
            return Err(e);
        }

        match self.go_forward(&record) {
            Ok(()) => Ok(record),
            Err(e) => {
                // The machine may be half way: the profile can have moved
                // and the switch failed after it. So it is put BACK here
                // rather than left to a timer that may not have been armed —
                // and if that fails too, the record says `inconsistent`,
                // which is what makes a resume stop and ask for a person
                // ([`crate::receipt::next_step`]).
                let because = format!("the activation itself failed: {e:#}");
                match self.revert(id, Some(&because)) {
                    Ok(_) => Err(e.context(format!(
                        "{id} was taken back to {}",
                        record
                            .previous
                            .toplevel
                            .as_deref()
                            .unwrap_or("its previous system")
                    ))),
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
            // The default goes BACK to the old generation and the new one is
            // tried once. `switch-to-configuration boot` has just written
            // loader.conf with the new generation as the default, and leaving
            // it there would mean an unconfirmed boot loop into a system
            // nobody could reach. The EFI variable wins over loader.conf,
            // which is what makes this one command enough.
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

    /// systemd-boot, or a sentence that says what a grub host can have.
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

    /// The transient unit that reverts this transaction when nobody speaks.
    ///
    /// `systemd-run --on-active` and not a timer file: a unit file would be
    /// part of some generation, and this has to belong to neither the old nor
    /// the new one — that is precisely why it survives
    /// `switch-to-configuration`, which stops and starts the units the two
    /// generations declare and knows nothing about this one.
    ///
    /// It does not survive a reboot, and that is the documented limit of the
    /// switch mode's safety net: in boot mode the net is the boot entry.
    fn arm_timer(&self, id: &str, seconds: u64) -> Result<()> {
        let cmd = Cmd::new(Effect::TargetWrite, "systemd-run", QUICK)
            .arg(format!("--on-active={seconds}"))
            .arg(format!("--unit={}", timer_unit(id)))
            // So that the transient unit disappears once it has run: a
            // failed unit that stays loaded is a unit the next activation of
            // the same id cannot create.
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

    /// Stop the timer, and be sure it is stopped.
    ///
    /// Two commands, because `systemctl stop` of a unit that is already gone
    /// exits non-zero and that is not a failure — while a timer that is
    /// still armed after a confirm IS one, and would revert a machine
    /// somebody has just accepted.
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

    /// Keep it. The timer goes first, then the record says so.
    pub fn confirm(&self, id: &str) -> Result<TxnRecord> {
        let mut record = self.record(id)?;
        match record.state {
            TxnState::Confirmed => return Ok(record),
            TxnState::Reverted => bail!(
                "the transaction {id} was already reverted ({}). A machine that has gone back \
                 is not confirmed afterwards; plan again.",
                record.reason.as_deref().unwrap_or("no reason recorded")
            ),
            TxnState::Inconsistent => bail!(
                "the record of {id} does not say a coherent thing, so there is nothing here \
                 to confirm. Read it with `meister-activate txn show --txn {id}`."
            ),
            TxnState::Staged | TxnState::Pending => {}
        }
        if record.deadline.is_some() {
            self.stop_timer(id)?;
        }
        if record.mode == Mode::Boot {
            // The one-shot has been consumed by the boot that got us here;
            // what is left is the default, which still points at the old
            // generation. Making the new one the default is the whole
            // content of "confirmed" in boot mode.
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

    /// Take it back. Called by an operator, by `apply` when a check fails,
    /// and by the timer when nobody says anything at all.
    pub fn revert(&self, id: &str, because: Option<&str>) -> Result<TxnRecord> {
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
            TxnState::Staged | TxnState::Pending | TxnState::Inconsistent => {}
        }
        let previous = record.previous.toplevel.clone().ok_or_else(|| {
            anyhow::anyhow!(
                "the record of {id} names no previous system, so there is nothing to go back \
                 to. This needs a person: read it with `meister-activate txn show --txn {id}`."
            )
        })?;

        // The timer first, so that a revert that takes a while is not
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
            // Clear the one-shot — the machine has not rebooted yet, so the
            // entry that was to be tried once must not be tried at all — and
            // put the default back where it was.
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

    /// The run that owns a record says it is done with it.
    ///
    /// This is what makes "an open transaction" mean "a run that was
    /// interrupted" rather than "a host that has ever been deployed to". The
    /// archive lands before the record goes, so a crash in between leaves
    /// both — and both-present is read as still open, which is the
    /// conservative half of the two.
    pub fn retire(&self, id: &str, run_id: Option<&str>) -> Result<TxnRecord> {
        self.retire_inner(id, run_id, None)
    }

    // --- lane 5C ---
    /// Put an `inconsistent` record aside because a person says so.
    ///
    /// There was no way back out of `inconsistent` (L2 finding N13). The
    /// record refuses to retire, because a record is the only thing that
    /// says a machine may still have to go back; `apply --resume` refuses
    /// too, because the run it was continuing is not the plan in front of
    /// the operator any more. What the lab did was move the file by hand
    /// into /root — a defensible decision, and no way for a tool to leave
    /// it.
    ///
    /// Three things make this narrow rather than a `--force` that means
    /// "stop complaining":
    ///
    /// * Only `inconsistent`. A `staged` or `pending` record says exactly
    ///   what the machine may still do, and taking it away is taking away
    ///   the rollback. Those two are still refused, by name.
    /// * A reason, as a sentence, and the command refuses an empty one.
    /// * The archive says it was forced, who asked, when, and out of which
    ///   state ([`ForcedRetirement`]). The file is the record of the
    ///   decision.
    ///
    /// The machine itself is not touched: no profile is moved, no unit is
    /// started. What this does is stop a dead record from blocking the
    /// next plan.
    pub fn retire_forced(&self, id: &str, run_id: Option<&str>, reason: &str) -> Result<TxnRecord> {
        self.retire_inner(id, run_id, Some(reason))
    }

    fn retire_inner(
        &self,
        id: &str,
        run_id: Option<&str>,
        forced: Option<&str>,
    ) -> Result<TxnRecord> {
        let mut record = self.record(id)?;
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
        // --- end lane 5C ---
        self.files
            .write_atomic(&self.txn_archive(id), &record.to_json()?, 0o600)?;
        self.files.remove_file(&self.txn_path(id))?;
        Ok(record)
    }

    // -----------------------------------------------------------------
    // the lock
    // -----------------------------------------------------------------

    /// Who holds this host, or nobody.
    ///
    /// A file at the lock path that this program did not write is `None`
    /// here and is never overwritten: it might be somebody's lock in a
    /// spelling this version does not know.
    pub fn read_lock(&self) -> Result<Option<Lock>> {
        let path = self.lock_path();
        if !self.files.exists(&path) {
            return Ok(None);
        }
        let text = self.files.read_to_string(&path)?;
        Ok(serde_json::from_str::<Lock>(&text).ok())
    }

    /// Take the host, or say who has it.
    ///
    /// `O_EXCL` on `lock/owner.json` and not `mkdir lock/`, which is what
    /// the lane brief says: the directory is created by the tmpfiles rules of
    /// nix/managed.nix before anything runs, so a `mkdir` of it could never
    /// be the thing two runs race for. An exclusive create of the file
    /// inside it is that thing, and it is the same file the read-only probe
    /// already reads.
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
                // The same run asking twice is asking whether it may act,
                // and the answer is yes.
                //
                // Astra finding F04, 2026-09-23: the run id alone was the
                // whole question, so two operator processes carrying one run
                // both got a yes here. This host cannot judge a pid — the
                // number in the record is a process on a WORKSTATION and
                // `kill(0)` here would ask about a stranger — so what it can
                // ask is who is carrying the run, and it does. The other
                // half of the door is `state::acquire_lock`, which refuses a
                // second live process of one run on the workstation itself;
                // the two together are what makes one run one writer. A pid
                // that differs and an operator that does not is a resume
                // after a kill, and that is the flow this shortcut exists
                // for.
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

    /// Take a named run's lock, deliberately. The id has to match what is
    /// there, so that a takeover cannot take over a run that started while
    /// somebody was reading the refusal.
    ///
    /// Astra finding F04, 2026-09-23: read, remove, create is three steps,
    /// and two takeovers that both read the old owner went through all
    /// three — the loser's `remove_file` taking away the winner's fresh
    /// lock. The claim is a rename to a name of the taker's own, exactly as
    /// in `state::take_over_lock`: a rename of a file that is gone fails, so
    /// of two takers exactly one carries the record away.
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
        // --- lane 5C ---
        // The taking run already has it, so there is nothing to take and the
        // answer is yes — the same answer `lock_acquire` gives a run that
        // asks twice. Asked BEFORE the claim below, because a run that
        // already holds the host must not carry its own lock away.
        //
        // Measured in lab lane L2 (2026-09-23): `apply --takeover <old>` on
        // a host the abandoned run had never locked. The fleet anchor (D6)
        // reaches every control-plane host FIRST, finds no lock, and the
        // takeover falls through to an acquire — so by the time the plan's
        // own `lock` step runs on that same host, it is held by the NEW run,
        // and the helper answered "this host is held by the run <new>, not
        // by <old>. Nothing was taken over." The run took over from itself
        // and the rollout stopped.
        if let Some(held) = self.read_lock()?
            && held.run_id == run_id
        {
            return Ok(held);
        }
        // --- end lane 5C ---
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
            // Not the run that was named, so it goes back exactly as it was.
            // `create_new` and not `write_atomic`: it refuses to overwrite,
            // so a lock somebody took in this window is not lost either.
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

    /// Refuse to touch a host somebody else holds.
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

    /// Keep the running system, the booted one, and the newest N besides
    /// them; collect what nothing points at any more.
    ///
    /// Refuses while a transaction is open, and that is the whole safety of
    /// the verb: the generation an unconfirmed activation would roll back to
    /// is a generation that must not be collected, and no amount of
    /// arithmetic here is worth more than asking the operator to finish what
    /// they started.
    ///
    /// `nix-collect-garbage` without `-d`: deleting old generations of EVERY
    /// profile on the machine — including a user's — is not this program's
    /// business, and the generations it is about have just been named
    /// explicitly.
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
        // The newest N below the current one, so that "keep 3" is three
        // generations somebody can go back to and not three including the
        // one that is running.
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

    // -----------------------------------------------------------------
    // keygen (lane 3B)
    // -----------------------------------------------------------------

    /// Make this host's own key, and hand out a request over it.
    ///
    /// **The private half is made here and stays here.** That is the whole
    /// of D10 and the reason this is a command of the TARGET's helper
    /// rather than a verb of the workstation: a workstation that generated
    /// node keys would be a workstation holding every identity of the
    /// fleet, and its backup would be the fleet.
    ///
    /// Idempotent on purpose. A rollout can be interrupted between the
    /// `ssh` that started this and the answer coming back, and the operator
    /// will run it again. Without `--replace` an existing key is LEFT
    /// ALONE and only a new request is made over it — because a second key
    /// would be a second identity, and the certificate that was issued over
    /// the first one would then be a certificate for a key nobody has.
    ///
    /// `--replace` is what a rotation is made of (M5A) and what a
    /// reinstalled host needs; it is a flag rather than the default for the
    /// same reason.
    pub fn keygen(&self, subject: &str, kind: KeyKind, replace: bool) -> Result<KeygenOutcome> {
        self.keygen_into(subject, kind, replace, None)
    }

    /// The same, beside the key that is in use rather than over it.
    ///
    /// `suffix = Some("next")` writes `<kind>.key.next`, which is how a
    /// rotation begins (lane 5A): the new key lives next to the old one
    /// until somebody has a certificate for it, and nothing that is running
    /// notices it is there.
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
            // 0600 from the start, never chmod'ed onto an existing file:
            // `Files::write_atomic` opens the temporary with the mode and
            // renames it into place, so there is no moment in which this
            // file is readable by anybody but its owner. That is exactly
            // what `pki::pem::write_secret` does, and it goes through this
            // crate's file door instead so that `--dry-run` refuses it and
            // a unit test can watch it (tests/no_direct_effects.rs).
            self.files
                .create_dir_all(path.parent().unwrap_or_else(|| Path::new(DEFAULT_PKI_DIR)))?;
            self.files
                .write_atomic(&path, made.key_pem.as_bytes(), 0o600)?;
            // And the owner is the user that reads it. Root wrote it, so
            // the file was never readable by anybody else in between.
            // `chown` through the runner because there is no door for it —
            // a file's owner is not something `Files` knows about.
            self.runner.run(
                &Cmd::new(Effect::Key, "chown", QUICK)
                    .arg(format!("{KEY_OWNER}:{KEY_OWNER}"))
                    .arg(path.display().to_string()),
            )?;
            (made.key_pem, true)
        };

        // The request is made over the key either way: a fresh key and an
        // existing one are asked the same question, which is what makes a
        // second run of this command an answer rather than a change.
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

    // --- lane 5A: a key beside the one in use ---------------------------

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

    /// Where a rotation of this key has got to.
    ///
    /// The FILES are the truth and the record is the story. A machine that
    /// lost power between the rename and the record would otherwise be a
    /// machine whose record says one thing and whose disk says another, and
    /// the resume would believe the record — so the state is derived from
    /// what is on the disk, and the record is what says whose rotation it
    /// was and why it ended. The two states the files cannot show
    /// (`confirmed`, `reverted`) are the record's alone.
    pub fn keys_status(&self, kind: KeyKind) -> Result<KeysView> {
        let key_next = self.files.exists(&self.key_path_with(kind, Some("next")));
        let crt_next = self.files.exists(&self.cert_path_with(kind, Some("next")));
        let prev = self.files.exists(&self.key_path_with(kind, Some("prev")))
            || self.files.exists(&self.cert_path_with(kind, Some("prev")));
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
        let state = match (key_next, crt_next, prev) {
            (_, _, true) => KeysState::Switched,
            (true, true, false) => KeysState::Overlap,
            (true, false, false) => KeysState::Prepared,
            (false, true, false) => KeysState::Inconsistent,
            (false, false, false) => finished.unwrap_or(KeysState::None),
        };
        let reason = (state == KeysState::Inconsistent).then(|| {
            format!(
                "{} is there and {} is not: a certificate without the key it belongs to.",
                self.cert_path_with(kind, Some("next")).display(),
                self.key_path_with(kind, Some("next")).display()
            )
        });
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

    /// Put the prepared pair in and the one in use aside, in one move.
    ///
    /// Four renames and an order that matters: the CERTIFICATE goes last on
    /// the way in, because a process that reads the pair between the two
    /// renames must never find a new key under an old certificate. The
    /// loaders of this stack read both files at once and refuse a pair that
    /// does not belong together, so the window is a refusal rather than a
    /// wrong identity — but it is still the shorter window that is wanted.
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

        // What is in use goes aside first: a pair that is half replaced is
        // worse than one that is briefly absent, and absent is what a
        // restart of the unit would survive.
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

    /// Put the pair that was in use back, and drop the one that failed.
    ///
    /// The failed pair is not kept: its certificate is in the operator's
    /// repository (that is where it was issued), and its private half is a
    /// key that never served a connection. What IS kept is the record,
    /// which says that a rotation was taken back and why.
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

    /// `sha256:<hex>` of a file, or `None` when it is not there.
    ///
    /// The same shape the read-only probe reports for a public file, so
    /// that a record and a snapshot say the same thing about one
    /// certificate.
    fn digest_of(&self, path: &Path) -> Option<String> {
        self.files
            .read(path)
            .ok()
            .map(|bytes| format!("sha256:{}", crate::ids::sha256_hex(&bytes)))
    }
    // --- end lane 5A ----------------------------------------------------
}

// --- lane 5A: the key transaction ------------------------------------------

pub const KEYS_SCHEMA: &str = "meister-deploy/activate-keys/1";

/// Where a rotation of one key has got to.
///
/// Five states and a sixth for "this does not add up", which is the same
/// shape [`TxnState`] has and for the same reason: a resume decides what to
/// do next from this word, and a word that could mean two things is a word
/// that decides wrongly once.
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

/// One key rotation, on disk, on the target.
///
/// Beside the system transactions and NOT among them: `records()` skips
/// `keys-*.json` on purpose, because an open key rotation is not a reason to
/// refuse to roll a system forward — and a file in `txn/` that the system's
/// own parser cannot read would otherwise make every plan see an
/// `inconsistent` transaction and block the host.
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
    /// And of the one that is in use now. The same shape the read-only probe
    /// reports for a public file, so a record and a snapshot say the same
    /// thing about one certificate.
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
    /// A `.prev` pair is there: the switch happened and nobody has removed
    /// what it replaced.
    pub prev: bool,
    /// What makes this inconsistent, when it is.
    pub reason: Option<String>,
    pub record: Option<KeysRecord>,
}

// --- end lane 5A -----------------------------------------------------------

/// Which of the two keys a managed host holds.
///
/// Two and not one, because they answer different questions: `identity.key`
/// is what this machine DIALS with (`CN=system:…`), `serving.key` is what a
/// client checks this ADDRESS against (`CN=<host name>`, with SANs). The
/// file names are the ones `nix/agent.nix` and `nix/controllers.nix` put
/// into every rendered configuration.
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

/// What `keygen` answers with.
///
/// There is no field for the key and there must not be: this object is
/// printed as json on stdout, travels back over ssh and is read by a
/// workstation that writes parts of it into a repository somebody commits.
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

/// `  42   2026-09-20 11:02:33   (current)` -> 42, current.
///
/// The number is the first field of every line `nix-env
/// --list-generations` prints, and `(current)` marks one of them.
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

/// The systemd-boot entry NixOS writes for a generation.
///
/// The name is NixOS's own (`nixos-generation-<n>.conf`, from the
/// systemd-boot builder). A specialisation adds a suffix, and a host that
/// uses one has no boot fallback here — which is the same class of limit as
/// grub and is documented with it.
fn entry_of(generation: u64) -> String {
    format!("nixos-generation-{generation}.conf")
}

/// The transient unit that would revert a transaction.
pub fn timer_unit(id: &str) -> String {
    format!("meister-revert-{id}")
}

impl TxnState {
    /// The state in the spelling a sentence uses. On the observation type
    /// rather than beside it, because there is one spelling of these five
    /// words and the json is the other half of it.
    pub(crate) fn as_str_lower(self) -> &'static str {
        match self {
            TxnState::Staged => "staged",
            TxnState::Pending => "pending",
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

    /// A runner that moves the profile link the way `nix-env --set` does.
    ///
    /// The boot mode names TWO generations — the one to fall back to and the
    /// one to try once — and the second of them only exists after the
    /// profile has moved. A fake filesystem that cannot change during the
    /// call could not tell the two numbers apart, and a test in which they
    /// are the same number would prove nothing about the thing that matters.
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
        // The kernel link is there and the params file is not: the planner
        // compares three fields, and two of them plus a guess would cost a
        // reboot nobody needed.
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
            // The way back: the timer goes, the profile goes back, and the
            // OLD system's own switcher runs. The profile may have moved
            // already, so this is not optional politeness.
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
    fn a_confirm_whose_timer_will_not_stop_changes_nothing() {
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
        assert_eq!(helper.record("c2").unwrap().state, TxnState::Pending);
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
            .revert("r1", Some("a readiness check failed"))
            .unwrap();
        assert_eq!(record.state, TxnState::Reverted);
        assert_eq!(record.reason.as_deref(), Some("a readiness check failed"));
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
        let again = helper.revert("r3", Some("and then a person")).unwrap();
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
        let err = helper.revert("r4", Some("the timer fired")).unwrap_err();
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

    // --- lane 5C ---

    #[test]
    fn an_inconsistent_record_can_be_put_aside_by_a_person_with_a_sentence() {
        // L2 finding N13. `inconsistent` had no way out: retire refused,
        // `apply --resume` refused (another plan had been built since), and
        // what the lab did was move the file into /root by hand.
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

        // And an empty sentence is not one.
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
        // The narrow half: `staged` and `pending` are the two states in
        // which the record IS the rollback, and no sentence buys them.
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
        // `retired_by_force` is skipped when it is absent, so a record on
        // a machine that was deployed to last week parses unchanged — and
        // `deny_unknown_fields` means the other direction is a sentence
        // rather than a silent drop.
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

    // --- end lane 5C ---

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
        // `observation::Lock` denies unknown fields, and the probe reads
        // owner.json straight into it: a fifth key here would make every
        // observation of a locked host blind to the lock.
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

    // Astra finding F04, 2026-09-23.
    #[test]
    fn two_operators_carrying_one_run_do_not_both_hold_the_host() {
        let files = host();
        let runner = StrictFake::new();
        let clock = clock();
        let helper = helper(&runner, &files, &clock);
        let first = helper.lock_acquire("run-a", "silas@manacor", 42).unwrap();
        // The same run from the same workstation is a resume after a kill,
        // whatever the pid says: the process is gone and the lock it left is
        // the lock of this run.
        assert_eq!(
            helper.lock_acquire("run-a", "silas@manacor", 99).unwrap(),
            first
        );
        // The same run from somewhere else is a second writer, and this host
        // cannot ask a workstation whether a pid is still there — so it asks
        // the only question it can answer.
        let err = helper
            .lock_acquire("run-a", "leandro@calvia", 7)
            .unwrap_err()
            .to_string();
        assert!(err.contains("as it is carried by silas@manacor"), "{err}");
        assert!(err.contains("one writer"), "{err}");
        assert_eq!(helper.read_lock().unwrap().unwrap(), first);
        runner.verify().unwrap();
    }

    // Astra finding F04, 2026-09-23.
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
        // The second takeover read run-a before any of that. It used to
        // remove run-b's fresh lock and take the host as well; now it
        // carries that lock away, sees it is not run-a, and puts it back.
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

    // --- lane 5C ---

    #[test]
    fn a_takeover_of_a_host_the_taking_run_already_holds_is_the_answer_yes() {
        // L2 finding N8. A takeover reaches a host twice: the fleet anchor
        // takes every control-plane host before the walk, and the plan's
        // own `lock` step takes the host again. When the abandoned run
        // never held this host, the first call finds nothing and acquires,
        // and the second one used to answer "this host is held by the run
        // run-b, not by run-a" — the run refused to take over from itself.
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

    // --- end lane 5C ---

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
        // And a record of another schema is a sentence, not a guess.
        let wrong = text.replace(TXN_SCHEMA, "meister-deploy/activate-txn/2");
        let err = TxnRecord::from_json(&wrong, "a test")
            .unwrap_err()
            .to_string();
        assert!(err.contains("activate-txn/2"), "{err}");
    }

    // --- lane 3B: keygen ---------------------------------------------

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

    /// An interrupted rollout runs this again. A second key would be a
    /// second identity, and the certificate issued over the first would be
    /// a certificate for a key nobody has.
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

    // --- lane 5A: rotating a key in phases -----------------------------

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

    /// Asking twice prepares one key: a second one would be a second
    /// identity, and the certificate issued over the first would be a
    /// certificate for a key nobody has.
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
        // Twice is a sentence, not a second removal.
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
}
