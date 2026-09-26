// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Repository state paths, operator lock, journal I/O, and retention. Plans, releases,
//! observations, and receipts are retained under .meister-deploy for inspection and resume.
//!
//! Journal append fsyncs each serialized event; callers record irreversible actions before
//! execution. Readers tolerate an unterminated final record and report it. Resume repairs the
//! tail before appending. Locks have no age-based expiry: a dead local holder can be
//! succeeded for the same run; other ownership changes require explicit takeover.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::{Context, Result, bail};
use chrono::{DateTime, Utc};
use nix::sys::signal::kill;
use nix::unistd::Pid;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::effects::Files;
use crate::ids::sha256_hex;
use crate::observation::Observations;
use crate::receipt::{
    DeploymentReceipt, EventKind, JournalEvent, JournalRef, Operator, parse_journal,
};

/// The directory, relative to the operator's repository.
pub const STATE_DIR: &str = ".meister-deploy";

pub const LOCK_SCHEMA: &str = "meister-deploy/operator-lock/1";

pub const RETIRED_SCHEMA: &str = "meister-deploy/retired/1";

/// Retirement evidence independent of rollout receipts: host, time, observed system, revoked
/// serials, and optional operator reason.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Retired {
    pub schema: String,
    pub host: String,
    pub retired_at: DateTime<Utc>,
    /// The system it was running when it was retired, as the last
    /// observation saw it. `None` when nobody could ask it.
    pub last_system: Option<String>,
    /// The serials this repository took back for it. Empty when it held no
    /// certificate of its own.
    pub identity_serials: Vec<String>,
    pub reason: Option<String>,
}

/// The state directory of one operator repository.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StateDir {
    root: PathBuf,
}

impl StateDir {
    /// `<repo>/.meister-deploy`.
    pub fn in_repo(repo: &Path) -> StateDir {
        StateDir {
            root: repo.join(STATE_DIR),
        }
    }

    /// For a caller that already knows the directory itself.
    pub fn at(root: impl Into<PathBuf>) -> StateDir {
        StateDir { root: root.into() }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn runs_dir(&self) -> PathBuf {
        self.root.join("runs")
    }

    pub fn run_dir(&self, run_id: &str) -> PathBuf {
        self.runs_dir().join(run_id)
    }

    pub fn journal_path(&self, run_id: &str) -> PathBuf {
        self.run_dir(run_id).join("journal.jsonl")
    }

    pub fn receipt_path(&self, run_id: &str) -> PathBuf {
        self.run_dir(run_id).join("receipt.json")
    }

    /// The plan as it was applied, copied in verbatim: a receipt names a
    /// `plan_id`, and a `plan_id` is only worth naming if the plan it names
    /// is still there to read.
    pub fn plan_copy_path(&self, run_id: &str) -> PathBuf {
        self.run_dir(run_id).join("plan.json")
    }

    /// Save the release beside the plan so resume does not depend on an external build-output
    /// file that may be overwritten.
    pub fn release_copy_path(&self, run_id: &str) -> PathBuf {
        self.run_dir(run_id).join("release.json")
    }

    // Verification ledger and report share the run directory with rollout evidence.

    /// `runs/<run-id>/ledger.json`: what a verification made, written
    /// before it was made.
    pub fn verify_ledger_path(&self, run_id: &str) -> PathBuf {
        self.run_dir(run_id).join("ledger.json")
    }

    /// `runs/<run-id>/verify.json`: what it found.
    pub fn verify_path(&self, run_id: &str) -> PathBuf {
        self.run_dir(run_id).join("verify.json")
    }

    pub fn observations_dir(&self) -> PathBuf {
        self.root.join("observations")
    }

    pub fn latest_observation_path(&self) -> PathBuf {
        self.observations_dir().join("latest.json")
    }

    pub fn run_observations_dir(&self, run_id: &str) -> PathBuf {
        self.run_dir(run_id).join("observations")
    }

    pub fn lock_path(&self) -> PathBuf {
        self.root.join("lock")
    }

    pub fn gcroots_dir(&self) -> PathBuf {
        self.root.join("gcroots")
    }

    /// Retirement records used to distinguish deliberate removal from an unexplained
    /// inventory change.
    pub fn retired_dir(&self) -> PathBuf {
        self.root.join("retired")
    }

    pub fn retired_path(&self, host_id: &str) -> PathBuf {
        self.retired_dir().join(format!("{host_id}.json"))
    }

    /// Return a valid retirement record, or None if absent, unreadable, or invalid. Status
    /// remains available when this evidence is missing.
    pub fn read_retired(&self, files: &dyn Files, host_id: &str) -> Option<Retired> {
        let path = self.retired_path(host_id);
        if !files.exists(&path) {
            return None;
        }
        let text = files.read_to_string(&path).ok()?;
        crate::manifest::parse_checked::<Retired>(
            &text,
            &path.display().to_string(),
            RETIRED_SCHEMA,
        )
        .ok()
    }

    pub fn write_retired(&self, files: &dyn Files, record: &Retired) -> Result<PathBuf> {
        let path = self.retired_path(&record.host);
        files.create_dir_all(&self.retired_dir())?;
        let mut bytes = serde_json::to_vec_pretty(record)
            .map_err(|e| anyhow::anyhow!("writing the retirement record failed: {e}"))?;
        bytes.push(b'\n');
        files.write_atomic(&path, &bytes, 0o644)?;
        Ok(path)
    }

    pub fn gcroot_dir(&self, release_id: &str) -> PathBuf {
        self.gcroots_dir().join(release_id)
    }

    pub fn gcroot_path(&self, release_id: &str, name: &str) -> PathBuf {
        self.gcroot_dir(release_id).join(name)
    }

    /// The directories that exist before anything is written into them.
    pub fn create(&self, files: &dyn Files) -> Result<()> {
        files.create_dir_all(&self.root)?;
        files.create_dir_all(&self.runs_dir())?;
        files.create_dir_all(&self.observations_dir())?;
        files.create_dir_all(&self.gcroots_dir())?;
        Ok(())
    }

    /// Make room for one run.
    pub fn begin_run(&self, files: &dyn Files, run_id: &str) -> Result<()> {
        self.create(files)?;
        files.create_dir_all(&self.run_dir(run_id))?;
        files.create_dir_all(&self.run_observations_dir(run_id))?;
        Ok(())
    }

    /// List run entries in filesystem-provider order. RealFiles returns sorted names; UUIDv7
    /// names sort by creation time.
    pub fn runs(&self, files: &dyn Files) -> Result<Vec<String>> {
        Ok(files
            .list_dir(&self.runs_dir())?
            .into_iter()
            .filter_map(|path| {
                path.file_name()
                    .map(|name| name.to_string_lossy().into_owned())
            })
            .collect())
    }

    /// Persist timestamped history plus latest.json; optionally copy it into the run.
    /// Filenames have second precision, so multiple saves in one second replace the same
    /// history entry.
    pub fn save_observation(
        &self,
        files: &dyn Files,
        snapshot: &Observations,
        run_id: Option<&str>,
    ) -> Result<PathBuf> {
        self.create(files)?;
        let bytes = snapshot.to_json()?;
        let name = format!("{}.json", snapshot.taken_at.format("%Y%m%dT%H%M%SZ"));
        let path = self.observations_dir().join(&name);
        files.write_atomic(&path, &bytes, 0o644)?;
        files.write_atomic(&self.latest_observation_path(), &bytes, 0o644)?;
        if let Some(run_id) = run_id {
            files.create_dir_all(&self.run_observations_dir(run_id))?;
            files.write_atomic(
                &self.run_observations_dir(run_id).join(&name),
                &bytes,
                0o644,
            )?;
        }
        Ok(path)
    }

    /// The last snapshot anybody took, for a verb that may not ask.
    pub fn load_latest_observation(&self, files: &dyn Files) -> Result<Observations> {
        let path = self.latest_observation_path();
        if !files.exists(&path) {
            bail!(
                "there is no snapshot in {} to answer from. Run `status` or `plan` without \
                 --offline once, which asks the fleet and leaves one here.",
                self.observations_dir().display()
            );
        }
        let text = files.read_to_string(&path)?;
        Observations::from_json(&text, &path.display().to_string())
    }

    pub fn write_receipt(&self, files: &dyn Files, receipt: &DeploymentReceipt) -> Result<PathBuf> {
        let path = self.receipt_path(&receipt.run_id);
        files.create_dir_all(&self.run_dir(&receipt.run_id))?;
        files.write_atomic(&path, &receipt.to_json()?, 0o644)?;
        Ok(path)
    }

    pub fn read_receipt(&self, files: &dyn Files, run_id: &str) -> Result<DeploymentReceipt> {
        let path = self.receipt_path(run_id);
        let text = files.read_to_string(&path)?;
        DeploymentReceipt::from_json(&text, &path.display().to_string())
    }
}

// ---------------------------------------------------------------------------
// The operator's lock
// ---------------------------------------------------------------------------

/// Repository-level operator lock. Target-side activation locks are separate and represented
/// by observation::Lock.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LockRecord {
    pub schema: String,
    pub run_id: String,
    pub operator: String,
    /// Workstation identity used when determining whether this process can assess the
    /// recorded PID.
    pub workstation: String,
    pub pid: u32,
    pub acquired_at: DateTime<Utc>,
}

impl LockRecord {
    pub fn new(run_id: &str, operator: &Operator, pid: u32, now: DateTime<Utc>) -> LockRecord {
        LockRecord {
            schema: LOCK_SCHEMA.to_string(),
            run_id: run_id.to_string(),
            operator: operator.user.clone(),
            workstation: operator.workstation.clone(),
            pid,
            acquired_at: now,
        }
    }

    fn to_json(&self) -> Result<Vec<u8>> {
        let mut bytes = serde_json::to_vec_pretty(self)
            .map_err(|e| anyhow::anyhow!("writing the lock record as json failed: {e}"))?;
        bytes.push(b'\n');
        Ok(bytes)
    }

    /// What is known about the process that holds this lock.
    pub fn liveness(&self, here: &Operator) -> Liveness {
        if self.workstation != here.workstation {
            return Liveness::Elsewhere;
        }
        // Require a positive pid_t: zero and negative values address process groups, not an
        // individual holder.
        let Ok(pid) = i32::try_from(self.pid) else {
            return Liveness::Unknown;
        };
        if pid <= 0 {
            return Liveness::Unknown;
        }
        // Signal 0: the one question `kill` answers without doing anything.
        // `EPERM` means it exists and is somebody else's, which is still
        // "it exists".
        match kill(Pid::from_raw(pid), None) {
            Ok(()) => Liveness::Running,
            Err(nix::errno::Errno::EPERM) => Liveness::Running,
            Err(nix::errno::Errno::ESRCH) => Liveness::Gone,
            Err(_) => Liveness::Unknown,
        }
    }

    /// The sentence a second operator gets.
    pub fn refusal(&self, here: &Operator, run_id: &str) -> String {
        let liveness = match self.liveness(here) {
            Liveness::Running => "That process is running.".to_string(),
            Liveness::Gone => format!(
                "That process is no longer on this machine, so the run is not continuing here \
                 — but it may have activated a system before it went, and only the targets \
                 know. Look at `meister-deploy report --run {}` and at \
                 `meister-activate txn list` on the hosts it touched.",
                self.run_id
            ),
            Liveness::Elsewhere => format!(
                "It was taken on {}, so whether it is still running cannot be decided from \
                 here.",
                self.workstation
            ),
            Liveness::Unknown => {
                "Whether that process is still running could not be told.".to_string()
            }
        };
        format!(
            "this repository is held by run {} ({}@{}, pid {}, since {}). {liveness} Nothing \
             was done. If you are sure that run is over, continue it with \
             `--resume {}` or take it over with `--takeover {}`; this run is {run_id}.",
            self.run_id,
            self.operator,
            self.workstation,
            self.pid,
            self.acquired_at.to_rfc3339(),
            self.run_id,
            self.run_id
        )
    }
}

/// What can be said about the process named in a lock.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Liveness {
    Running,
    /// Demonstrably not on this machine any more.
    Gone,
    /// The lock was taken on another workstation; nothing can be concluded.
    Elsewhere,
    Unknown,
}

/// Describe the operator using USER/LOGNAME with a UID fallback, plus the local hostname.
pub fn current_operator() -> Operator {
    let user = std::env::var("USER")
        .or_else(|_| std::env::var("LOGNAME"))
        .unwrap_or_else(|_| format!("uid:{}", nix::unistd::getuid()));
    let workstation = nix::unistd::gethostname()
        .ok()
        .and_then(|name| name.into_string().ok())
        .unwrap_or_else(|| "unknown".to_string());
    Operator { user, workstation }
}

/// Create the operator lock exclusively. Matching run/PID is treated as re-entry; a
/// demonstrably dead local holder of the same run can be succeeded. Other holders are
/// refused. No timestamp expires a lock.
pub fn acquire_lock(
    files: &dyn Files,
    state: &StateDir,
    run_id: &str,
    operator: &Operator,
    now: DateTime<Utc>,
) -> Result<LockRecord> {
    state.create(files)?;
    let record = LockRecord::new(run_id, operator, std::process::id(), now);
    let path = state.lock_path();
    match files.create_new(&path, &record.to_json()?, 0o644) {
        Ok(()) => Ok(record),
        Err(e) => {
            // Somebody was faster, or a run is in progress. Which of the two
            // it is, the file says.
            match read_lock(files, state)? {
                // Treat a matching run and PID as re-entry. Workstation is not compared in
                // this branch.
                Some(held) if held.run_id == run_id && held.pid == std::process::id() => Ok(held),
                // Replace a dead local holder before resuming so another resume sees this
                // live process. Unknown or remote liveness does not qualify.
                Some(held)
                    if held.run_id == run_id && held.liveness(operator) == Liveness::Gone =>
                {
                    succeed_dead_holder(files, state, &held, record, operator)
                }
                // A competing or unverifiable holder of the same run cannot be resumed
                // concurrently.
                Some(held) if held.run_id == run_id => {
                    let and = match held.liveness(operator) {
                        Liveness::Running => "That process is running.".to_string(),
                        Liveness::Elsewhere => format!(
                            "It was taken on {}, so whether it is still running cannot be \
                             decided from here.",
                            held.workstation
                        ),
                        Liveness::Unknown | Liveness::Gone => {
                            "Whether that process is still running could not be told.".to_string()
                        }
                    };
                    bail!(
                        "the run {run_id} is already being carried on by the process {} on {} \
                         (operator {}, since {}). {and} Two processes writing one run write \
                         one journal twice and make it unreadable, so this one did nothing. \
                         Wait for that process, or take the run over with `--takeover \
                         {run_id}` once you know it is gone.",
                        held.pid,
                        held.workstation,
                        held.operator,
                        held.acquired_at.to_rfc3339()
                    )
                }
                Some(held) => bail!("{}", held.refusal(operator, run_id)),
                // The file is there and cannot be read as a lock record.
                // Nothing here rewrites it: a file in this place that this
                // tool did not write is the operator's to look at.
                None => bail!(
                    "{} exists and is not a lock record this tool wrote ({e:#}). Read it, and \
                     remove it by hand if it is rubbish; nothing here will overwrite a file \
                     that might be somebody's lock.",
                    path.display()
                ),
            }
        }
    }
}

/// Claim the lock by renaming it, then verify the carried record. Install this process only
/// for the expected dead holder. Restore a conflicting record with create_new so it cannot
/// overwrite a newer lock.
fn succeed_dead_holder(
    files: &dyn Files,
    state: &StateDir,
    dead: &LockRecord,
    mine: LockRecord,
    operator: &Operator,
) -> Result<LockRecord> {
    let path = state.lock_path();
    let claim = path.with_file_name(format!("lock.taken-by-{}.{}", mine.run_id, mine.pid));
    files.rename(&path, &claim).with_context(|| {
        format!(
            "the run {} could not be resumed here: another resume of it took the lock on {} \
             first, or the run gave it back while this one was reading. Nothing was done; \
             look at `meister-deploy report --run {}` and try again.",
            mine.run_id,
            path.display(),
            mine.run_id
        )
    })?;
    let bytes = files.read(&claim)?;
    let carried = serde_json::from_slice::<LockRecord>(&bytes).ok();
    let is_the_dead_one = carried.as_ref().is_some_and(|c| {
        c == dead || (c.run_id == mine.run_id && c.liveness(operator) == Liveness::Gone)
    });
    if is_the_dead_one {
        files.remove_file(&claim)?;
        files
            .create_new(&path, &mine.to_json()?, 0o644)
            .with_context(|| {
                format!(
                    "the run {} could not be resumed here: another process took the lock on \
                     {} while this one was replacing the record of the process that had \
                     died. Nothing was done.",
                    mine.run_id,
                    path.display()
                )
            })?;
        return Ok(mine);
    }
    // Not the dead record: somebody's live lock was carried away. It goes
    // back exactly as it was.
    let whose = match &carried {
        Some(held) => format!(
            "the process {} on {} (operator {})",
            held.pid, held.workstation, held.operator
        ),
        None => "a file this tool did not write".to_string(),
    };
    match files.create_new(&path, &bytes, 0o644) {
        Ok(()) => {
            files.remove_file(&claim)?;
            bail!(
                "the run {} is already being carried on by {whose}: the lock changed hands \
                 while this resume was reading it. Nothing was done.",
                mine.run_id
            )
        }
        Err(e) => bail!(
            "the run {} is being carried on by {whose}, and its lock could not be put back on \
             {} ({e:#}) because something else took that name in the meantime. Nothing was \
             done; the record that was there is in {}.",
            mine.run_id,
            path.display(),
            claim.display()
        ),
    }
}

/// What the lock file says, or `None` when there is none — or when what is
/// there is not a lock record.
pub fn read_lock(files: &dyn Files, state: &StateDir) -> Result<Option<LockRecord>> {
    let path = state.lock_path();
    if !files.exists(&path) {
        return Ok(None);
    }
    let text = files.read_to_string(&path)?;
    Ok(serde_json::from_str::<LockRecord>(&text).ok())
}

/// Give it back. Only the run that holds it may.
pub fn release_lock(files: &dyn Files, state: &StateDir, run_id: &str) -> Result<()> {
    match read_lock(files, state)? {
        None => Ok(()),
        Some(held) if held.run_id == run_id => files.remove_file(&state.lock_path()),
        Some(held) => bail!(
            "run {run_id} does not hold this repository; run {} does ({}@{}). A lock is \
             released by the run that took it.",
            held.run_id,
            held.operator,
            held.workstation
        ),
    }
}

/// Explicitly replace the named run. Rename the lock to claim its current record, verify its
/// run ID, then acquire the replacement. A mismatched record is restored with create_new,
/// preserving any newer lock.
pub fn take_over_lock(
    files: &dyn Files,
    state: &StateDir,
    of_run: &str,
    run_id: &str,
    operator: &Operator,
    now: DateTime<Utc>,
) -> Result<LockRecord> {
    let path = state.lock_path();
    if !files.exists(&path) {
        return acquire_lock(files, state, run_id, operator, now);
    }
    let claim = path.with_file_name(format!("lock.taken-by-{run_id}"));
    files.rename(&path, &claim).with_context(|| {
        format!(
            "the lock on {} could not be taken over; another takeover was here first, or the \
             run gave it back while you were reading.",
            path.display()
        )
    })?;
    let bytes = files.read(&claim)?;
    let taken = serde_json::from_slice::<LockRecord>(&bytes).ok();
    match taken {
        Some(held) if held.run_id == of_run => {
            files.remove_file(&claim)?;
            acquire_lock(files, state, run_id, operator, now)
        }
        // Not the run that was named. It goes back exactly as it was, and
        // `create_new` is what puts it there: it refuses to overwrite, so a
        // lock that somebody took in this window is not lost either.
        other => {
            let restored = files.create_new(&path, &bytes, 0o644);
            let whose = match &other {
                Some(held) => format!("by run {}", held.run_id),
                None => "by a file this tool did not write".to_string(),
            };
            match restored {
                Ok(()) => {
                    // Restoration succeeded; discard the temporary claim.
                    files.remove_file(&claim)?;
                    bail!(
                        "this repository is held {whose}, not by {of_run}. Nothing was taken \
                         over: --takeover names the run it takes over so that it cannot take \
                         over one that started while you were reading."
                    )
                }
                Err(e) => bail!(
                    "this repository is held {whose}, not by {of_run}, and the lock could not \
                     be put back ({e:#}) because something else took {} in the meantime. \
                     Nothing was taken over; the record that was there is in {}.",
                    path.display(),
                    claim.display()
                ),
            }
        }
    }
}

// ---------------------------------------------------------------------------
// The journal
// ---------------------------------------------------------------------------

/// Journal writer carrying run ID, plan ID, sequence counter, and redaction values. Callers
/// must serialize append operations to preserve sequence order on disk.
pub struct Journal {
    path: PathBuf,
    run_id: String,
    plan_id: String,
    seq: AtomicU64,
    redact: Vec<String>,
}

impl Journal {
    /// A new journal for a new run. The first line will be `seq: 1`.
    pub fn new(path: impl Into<PathBuf>, run_id: &str, plan_id: &str) -> Journal {
        Journal {
            path: path.into(),
            run_id: run_id.to_string(),
            plan_id: plan_id.to_string(),
            seq: AtomicU64::new(0),
            redact: Vec::new(),
        }
    }

    /// Continue an existing journal after the last line it holds.
    pub fn resuming(
        path: impl Into<PathBuf>,
        run_id: &str,
        plan_id: &str,
        last_seq: u64,
    ) -> Journal {
        Journal {
            path: path.into(),
            run_id: run_id.to_string(),
            plan_id: plan_id.to_string(),
            seq: AtomicU64::new(last_seq),
            redact: Vec::new(),
        }
    }

    /// Hide this exact value wherever it would appear in a line.
    pub fn hiding(mut self, secret: impl Into<String>) -> Journal {
        let secret = secret.into();
        if !secret.is_empty() {
            self.redact.push(secret);
        }
        self
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn last_seq(&self) -> u64 {
        self.seq.load(Ordering::SeqCst)
    }

    /// Construct an event; append assigns its sequence number and overwrites run/plan
    /// identity.
    pub fn event(&self, kind: EventKind, now: DateTime<Utc>) -> JournalEvent {
        JournalEvent::new(0, now, &self.run_id, &self.plan_id, kind)
    }

    /// Assign a sequence number, redact the serialized line, and append with fsync. Failed
    /// writes consume their number so later folding can report missing evidence.
    pub fn append(&self, files: &dyn Files, event: JournalEvent) -> Result<JournalEvent> {
        let mut event = event;
        event.seq = self.seq.fetch_add(1, Ordering::SeqCst) + 1;
        // The journal owns these two: a line that named another run would
        // make the file unreadable to `fold`, and the caller is not the one
        // who should have to remember.
        event.run_id = self.run_id.clone();
        event.plan_id = self.plan_id.clone();
        let line = redacted(&event.to_line()?, &self.redact);
        files
            .append_fsync(&self.path, &line)
            .with_context(|| format!("the journal line {} could not be written", event.seq))?;
        Ok(event)
    }
}

/// Replace registered secrets in both raw and JSON-escaped forms before writing.
fn redacted(line: &str, secrets: &[String]) -> String {
    let mut out = line.to_string();
    for secret in secrets {
        out = out.replace(secret.as_str(), "***");
        if let Ok(escaped) = serde_json::to_string(secret) {
            let escaped = escaped.trim_matches('"');
            if !escaped.is_empty() {
                out = out.replace(escaped, "***");
            }
        }
    }
    out
}

/// A journal, read back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JournalRead {
    pub events: Vec<JournalEvent>,
    /// The last line, if it was not a whole one. Reported rather than
    /// swallowed: it is the fingerprint of a machine that stopped in the
    /// middle of writing, which is exactly when a resume matters.
    pub torn: Option<String>,
}

impl JournalRead {
    pub fn last_seq(&self) -> u64 {
        self.events.last().map(|e| e.seq).unwrap_or(0)
    }
}

/// Read complete records and report an unterminated tail. A valid final record without
/// newline is retained; an invalid tail is dropped. UTF-8 decoding is lossy before parsing.
pub fn read_journal(files: &dyn Files, path: &Path) -> Result<JournalRead> {
    let text = String::from_utf8_lossy(&files.read(path)?).into_owned();
    let origin = path.display().to_string();
    // A line that is not followed by a newline was not finished: every line
    // this tool writes goes out as line plus newline in ONE write.
    let unterminated = !text.is_empty() && !text.ends_with('\n');
    let mut lines: Vec<&str> = text.lines().collect();
    let mut torn = None;

    if unterminated && let Some(last) = lines.pop() {
        // Retain a valid record missing only its newline, but report the incomplete append.
        match serde_json::from_str::<JournalEvent>(last) {
            Ok(_) => {
                lines.push(last);
                torn = Some(format!(
                    "the last line of {origin} was written without its newline; it parses, so \
                     it is kept, and the run that wrote it did not get any further."
                ));
            }
            Err(e) => {
                torn = Some(format!(
                    "the last line of {origin} is not a whole entry ({e}); it was dropped. \
                     Everything before it is intact."
                ));
            }
        }
    }

    let whole = lines.join("\n");
    let events = parse_journal(&whole, &origin)?;
    Ok(JournalRead { events, torn })
}

/// Repair an unterminated journal before appending: add a newline to a valid last record or
/// drop an invalid fragment. Complete records are not reserialized; input bytes are decoded
/// lossily.
pub fn repair_journal(files: &dyn Files, path: &Path) -> Result<Option<String>> {
    if !files.exists(path) {
        return Ok(None);
    }
    let text = String::from_utf8_lossy(&files.read(path)?).into_owned();
    if text.is_empty() || text.ends_with('\n') {
        return Ok(None);
    }
    let origin = path.display().to_string();
    let cut = text.rfind('\n').map(|i| i + 1).unwrap_or(0);
    let (repaired, what) = match serde_json::from_str::<JournalEvent>(&text[cut..]) {
        Ok(_) => (
            format!("{text}\n"),
            format!(
                "the last line of {origin} was written without its newline; it parses, so it \
                 is kept and the newline is now there. The run that wrote it did not get any \
                 further."
            ),
        ),
        Err(e) => (
            text[..cut].to_string(),
            format!(
                "the last line of {origin} is not a whole entry ({e}); it was dropped and the \
                 file now ends where the last whole line ends. Everything before it is intact."
            ),
        ),
    };
    files.write_atomic(path, repaired.as_bytes(), 0o600)?;
    Ok(Some(what))
}

/// The journal and its digest, as a receipt names them.
pub fn journal_ref(files: &dyn Files, path: &Path) -> Result<JournalRef> {
    let bytes = files.read(path)?;
    Ok(JournalRef {
        path: path.display().to_string(),
        sha256: sha256_hex(&bytes),
    })
}

// Retention separately handles release roots, observation history, and successful completed
// runs. Count and optional age guards must both permit removal. Undated roots and latest.json
// are protected; run removal requires explicit opt-in and recognizes only run_contents'
// allowlist.

/// Default retained release count. Removing a root permits later Nix GC; it does not remove a
/// store path directly.
pub const DEFAULT_KEEP_RELEASES: usize = 3;

/// Suggested age threshold for CLI guidance; Retention::default does not enable the age
/// guard.
pub const DEFAULT_OLDER_THAN_DAYS: i64 = 14;

/// What `gc` was asked to keep.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Retention {
    /// How many releases keep their garbage-collector roots.
    pub keep: usize,
    /// Only releases (and runs) older than this many days may go at all.
    /// `None` is "age does not protect anything", which is what makes
    /// `--keep 0` mean what it says.
    pub older_than_days: Option<i64>,
    /// How many snapshots under `observations/` to keep. `None` leaves them
    /// alone entirely.
    pub observations: Option<usize>,
    /// Whether run directories may be removed at all.
    pub runs: bool,
}

impl Default for Retention {
    fn default() -> Retention {
        Retention {
            keep: DEFAULT_KEEP_RELEASES,
            older_than_days: None,
            observations: None,
            runs: false,
        }
    }
}

/// One thing that would be removed, in the form an operator reads and a
/// carrying-out loop walks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Removal {
    /// What it is called: a release id, a snapshot's file name, a run id.
    pub what: String,
    /// What kind of thing: `release`, `observation`, `run`.
    pub kind: &'static str,
    /// The files to unlink, in order.
    pub files: Vec<PathBuf>,
    /// The directories to remove afterwards, deepest first. Empty for a
    /// single file.
    pub dirs: Vec<PathBuf>,
}

impl Removal {
    /// How much it is: the number of files this would unlink.
    pub fn entries(&self) -> usize {
        self.files.len()
    }
}

/// Something that stays, and the sentence that says why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Kept {
    pub what: String,
    pub kind: &'static str,
    pub why: String,
}

/// Everything one `gc` would do, decided before anything is done.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Sweep {
    pub remove: Vec<Removal>,
    pub keep: Vec<Kept>,
}

impl Sweep {
    pub fn removals_of(&self, kind: &str) -> Vec<&Removal> {
        self.remove.iter().filter(|r| r.kind == kind).collect()
    }

    pub fn kept_of(&self, kind: &str) -> Vec<&Kept> {
        self.keep.iter().filter(|k| k.kind == kind).collect()
    }

    pub fn is_empty(&self) -> bool {
        self.remove.is_empty()
    }
}

/// Compute removals without changing state. Dry-run displays this result; carry_out applies
/// it.
pub fn sweep(
    files: &dyn Files,
    state: &StateDir,
    roots: &[crate::build::RootDir],
    retention: &Retention,
    now: DateTime<Utc>,
) -> Result<Sweep> {
    let mut out = Sweep::default();
    sweep_releases(roots, retention, now, &mut out);
    sweep_observations(files, state, retention, now, &mut out)?;
    sweep_runs(files, state, retention, now, &mut out)?;
    Ok(out)
}

/// Apply the optional age guard. Without it, retention depends only on count and evidence
/// protections.
fn old_enough(created: DateTime<Utc>, retention: &Retention, now: DateTime<Utc>) -> bool {
    match retention.older_than_days {
        None => true,
        Some(days) => now.signed_duration_since(created) >= chrono::Duration::days(days),
    }
}

fn sweep_releases(
    roots: &[crate::build::RootDir],
    retention: &Retention,
    now: DateTime<Utc>,
    out: &mut Sweep,
) {
    // `roots()` sorts oldest last-dated first and undated first, so the
    // newest N are the tail of the dated ones.
    let dated: Vec<&crate::build::RootDir> =
        roots.iter().filter(|r| r.created_at.is_some()).collect();
    let cut = dated.len().saturating_sub(retention.keep);
    for (index, dir) in dated.iter().enumerate() {
        let created = dir.created_at.expect("filtered above");
        if index >= cut {
            out.keep.push(Kept {
                what: dir.release_id.clone(),
                kind: "release",
                why: format!("among the newest {}", retention.keep),
            });
        } else if !old_enough(created, retention, now) {
            out.keep.push(Kept {
                what: dir.release_id.clone(),
                kind: "release",
                why: format!(
                    "made {}, which is inside the {} day(s) this sweep protects",
                    created.to_rfc3339(),
                    retention.older_than_days.unwrap_or(0)
                ),
            });
        } else {
            out.remove.push(Removal {
                what: dir.release_id.clone(),
                kind: "release",
                files: dir
                    .links
                    .iter()
                    .cloned()
                    .chain(std::iter::once(dir.path.join(crate::build::STAMP)))
                    .collect(),
                dirs: vec![dir.path.clone()],
            });
        }
    }
    for dir in roots.iter().filter(|r| r.created_at.is_none()) {
        out.keep.push(Kept {
            what: dir.release_id.clone(),
            kind: "release",
            // The reader knows WHY it could not date this one — no stamp at
            // all, or a stamp it cannot read — and those are not the same
            // thing to somebody deciding what to do about it.
            why: dir
                .undated_because
                .clone()
                .unwrap_or_else(|| "this tool cannot say how old it is".to_string()),
        });
    }
}

fn sweep_observations(
    files: &dyn Files,
    state: &StateDir,
    retention: &Retention,
    now: DateTime<Utc>,
    out: &mut Sweep,
) -> Result<()> {
    let Some(keep) = retention.observations else {
        return Ok(());
    };
    let latest = state.latest_observation_path();
    // Named `<YYYYmmdd>T<HHMMSS>Z.json` by `save_observation`, so a lexical
    // sort is a chronological one — the same property run ids have.
    let mut snapshots: Vec<PathBuf> = files
        .list_dir(&state.observations_dir())?
        .into_iter()
        .filter(|path| path != &latest)
        .collect();
    snapshots.sort();
    let cut = snapshots.len().saturating_sub(keep);
    for (index, path) in snapshots.iter().enumerate() {
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        if index >= cut {
            out.keep.push(Kept {
                what: name,
                kind: "observation",
                why: format!("among the newest {keep}"),
            });
            continue;
        }
        // The name carries the moment it was taken, and that is the only
        // date this tool has for a snapshot; one it cannot read is one it
        // leaves alone.
        match observation_taken_at(&name) {
            Some(taken) if !old_enough(taken, retention, now) => out.keep.push(Kept {
                what: name,
                kind: "observation",
                why: format!(
                    "taken {}, which is inside the {} day(s) this sweep protects",
                    taken.to_rfc3339(),
                    retention.older_than_days.unwrap_or(0)
                ),
            }),
            None => out.keep.push(Kept {
                what: name,
                kind: "observation",
                why: "its name does not say when it was taken".to_string(),
            }),
            Some(_) => out.remove.push(Removal {
                what: name,
                kind: "observation",
                files: vec![path.clone()],
                dirs: Vec::new(),
            }),
        }
    }
    Ok(())
}

/// `20260922T090000Z.json` -> the moment, or `None` for a name this tool did
/// not write.
fn observation_taken_at(name: &str) -> Option<DateTime<Utc>> {
    let stem = name.strip_suffix(".json")?;
    chrono::NaiveDateTime::parse_from_str(stem, "%Y%m%dT%H%M%SZ")
        .ok()
        .map(|naive| naive.and_utc())
}

fn sweep_runs(
    files: &dyn Files,
    state: &StateDir,
    retention: &Retention,
    now: DateTime<Utc>,
    out: &mut Sweep,
) -> Result<()> {
    if !retention.runs {
        return Ok(());
    }
    // `runs()` is chronological because a run id is a uuid v7.
    let runs = state.runs(files)?;
    let cut = runs.len().saturating_sub(retention.keep);
    for (index, run_id) in runs.iter().enumerate() {
        let dir = state.run_dir(run_id);
        if index >= cut {
            out.keep.push(Kept {
                what: run_id.clone(),
                kind: "run",
                why: format!("among the newest {}", retention.keep),
            });
            continue;
        }
        // The receipt decides. No receipt is a run that never ended, and a
        // run that never ended is exactly the one somebody has to read.
        let receipt = match state.read_receipt(files, run_id) {
            Ok(receipt) => receipt,
            Err(_) => {
                out.keep.push(Kept {
                    what: run_id.clone(),
                    kind: "run",
                    why: "it wrote no receipt, so it never ended and its journal is the \
                          only record of what it did"
                        .to_string(),
                });
                continue;
            }
        };
        if receipt.outcome != crate::receipt::Outcome::Success {
            out.keep.push(Kept {
                what: run_id.clone(),
                kind: "run",
                why: format!("it ended {}, which is evidence", receipt.outcome.as_str()),
            });
            continue;
        }
        // When it ENDED, because that is when its evidence stopped being
        // about something happening now. A receipt that says `success` and
        // names no end is a receipt this tool did not write, so it is kept.
        let Some(ended) = receipt.ended_at else {
            out.keep.push(Kept {
                what: run_id.clone(),
                kind: "run",
                why: "its receipt names no end, so this tool cannot say how old it is".to_string(),
            });
            continue;
        };
        if !old_enough(ended, retention, now) {
            out.keep.push(Kept {
                what: run_id.clone(),
                kind: "run",
                why: format!(
                    "it ended {}, which is inside the {} day(s) this sweep protects",
                    ended.to_rfc3339(),
                    retention.older_than_days.unwrap_or(0)
                ),
            });
            continue;
        }
        match run_contents(files, &dir, state, run_id)? {
            Ok(removal) => out.remove.push(removal),
            Err(why) => out.keep.push(Kept {
                what: run_id.clone(),
                kind: "run",
                why,
            }),
        }
    }
    Ok(())
}

/// Collect recognized run files for nonrecursive removal. Unknown entries retain the run. The
/// allowlist currently excludes release.json and verification files written elsewhere in this
/// module.
#[allow(clippy::type_complexity)]
fn run_contents(
    files: &dyn Files,
    dir: &Path,
    state: &StateDir,
    run_id: &str,
) -> Result<std::result::Result<Removal, String>> {
    const KNOWN: [&str; 3] = ["journal.jsonl", "receipt.json", "plan.json"];
    let observations = state.run_observations_dir(run_id);
    let mut to_unlink = Vec::new();
    let mut dirs = Vec::new();
    for entry in files.list_dir(dir)? {
        let name = entry
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        if KNOWN.contains(&name.as_str()) {
            to_unlink.push(entry);
        } else if entry == observations {
            // The snapshots this run took, which are files by construction
            // (`save_observation` writes them and nothing else does).
            to_unlink.extend(files.list_dir(&entry)?);
            dirs.push(entry);
        } else {
            return Ok(Err(format!(
                "{} is not one of the files a run writes (journal.jsonl, receipt.json, \
                 plan.json, observations/), and this tool empties a run directory rather \
                 than deleting it recursively",
                entry.display()
            )));
        }
    }
    dirs.push(dir.to_path_buf());
    Ok(Ok(Removal {
        what: run_id.to_string(),
        kind: "run",
        files: to_unlink,
        dirs,
    }))
}

/// Do what [`sweep`] decided. Removes no store path — whether an
/// unprotected closure goes is `nix store gc`'s decision, and this tool does
/// not make it.
pub fn carry_out(files: &dyn Files, sweep: &Sweep) -> Result<()> {
    for removal in &sweep.remove {
        for path in &removal.files {
            files.remove_file(path)?;
        }
        for dir in &removal.dirs {
            files.remove_dir(dir)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::effects::MemFiles;
    use crate::fixtures::at;
    use crate::observation::{HostObservation, OBSERVATION_SCHEMA};
    use crate::receipt::{HostState, fold};
    use crate::run::Policy;
    use std::collections::BTreeMap;

    fn state() -> StateDir {
        StateDir::in_repo(Path::new("/repo"))
    }

    fn operator() -> Operator {
        Operator {
            user: "silas".to_string(),
            workstation: "manacor".to_string(),
        }
    }

    fn run_id() -> String {
        "0192f0c0-0000-7000-8000-000000000001".to_string()
    }

    fn snapshot() -> Observations {
        Observations {
            schema: OBSERVATION_SCHEMA.to_string(),
            taken_at: at("2026-09-21T12:34:56Z"),
            provisional: false,
            hosts: BTreeMap::from([("box".to_string(), HostObservation::unreachable("not asked"))]),
        }
    }

    #[test]
    fn every_path_of_a_run_is_under_its_own_directory() {
        let state = state();
        let run = run_id();
        assert_eq!(state.root(), Path::new("/repo/.meister-deploy"));
        assert_eq!(
            state.journal_path(&run),
            Path::new("/repo/.meister-deploy/runs")
                .join(&run)
                .join("journal.jsonl")
        );
        for path in [
            state.receipt_path(&run),
            state.plan_copy_path(&run),
            state.run_observations_dir(&run),
        ] {
            assert!(
                path.starts_with(state.run_dir(&run)),
                "{} escapes the run directory",
                path.display()
            );
        }
        assert_eq!(state.lock_path(), Path::new("/repo/.meister-deploy/lock"));
        assert_eq!(
            state.gcroot_path("release-abc", "box"),
            Path::new("/repo/.meister-deploy/gcroots/release-abc/box")
        );
    }

    #[test]
    fn a_snapshot_is_written_where_every_verb_looks_for_it() {
        let files = MemFiles::new();
        let state = state();
        let run = run_id();
        let path = state
            .save_observation(&files, &snapshot(), Some(&run))
            .unwrap();
        assert_eq!(
            path,
            Path::new("/repo/.meister-deploy/observations/20260921T123456Z.json")
        );
        // The same bytes in all three places, so that a copy is a copy.
        let history = files.content(&path).unwrap();
        assert_eq!(
            files.content(state.latest_observation_path()).unwrap(),
            history
        );
        assert_eq!(
            files
                .content(
                    state
                        .run_observations_dir(&run)
                        .join("20260921T123456Z.json")
                )
                .unwrap(),
            history
        );
        // And it reads back as the type the planner takes.
        let read = state.load_latest_observation(&files).unwrap();
        assert_eq!(read, snapshot());
    }

    #[test]
    fn a_directory_with_no_snapshot_says_how_to_make_one() {
        let files = MemFiles::new();
        let err = state()
            .load_latest_observation(&files)
            .unwrap_err()
            .to_string();
        assert!(err.contains("there is no snapshot"), "{err}");
        assert!(err.contains("without --offline"), "{err}");
    }

    #[test]
    fn a_dry_run_writes_no_state_at_all() {
        let files = MemFiles::new().with_policy(Policy::dry_run());
        let state = state();
        let err = state
            .save_observation(&files, &snapshot(), None)
            .unwrap_err()
            .to_string();
        assert!(err.contains("--dry-run"), "{err}");
        // Every attempt is recorded, refused ones included, so "wrote
        // nothing" is a comparison and not a hope.
        assert!(!files.attempts().is_empty());
        assert!(files.paths().is_empty(), "{:?}", files.paths());
    }

    #[test]
    fn the_first_operator_gets_the_lock_and_the_second_gets_a_sentence() {
        let files = MemFiles::new();
        let state = state();
        let first = acquire_lock(
            &files,
            &state,
            &run_id(),
            &operator(),
            at("2026-09-21T12:00:00Z"),
        )
        .expect("nobody held it");
        assert_eq!(first.run_id, run_id());
        assert_eq!(first.workstation, "manacor");
        assert_eq!(first.pid, std::process::id());

        let other = Operator {
            user: "someone".to_string(),
            workstation: "manacor".to_string(),
        };
        let err = acquire_lock(
            &files,
            &state,
            "0192f0c0-0000-7000-8000-000000000002",
            &other,
            at("2026-09-21T12:01:00Z"),
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains(&run_id()), "{err}");
        assert!(err.contains("silas@manacor"), "{err}");
        assert!(err.contains("Nothing was done."), "{err}");
        assert!(err.contains("--takeover"), "{err}");
        // The holder's record is untouched.
        assert_eq!(read_lock(&files, &state).unwrap().unwrap(), first);
    }

    #[test]
    fn the_same_run_asking_twice_is_not_a_second_operator() {
        let files = MemFiles::new();
        let state = state();
        let first = acquire_lock(
            &files,
            &state,
            &run_id(),
            &operator(),
            at("2026-09-21T12:00:00Z"),
        )
        .unwrap();
        let again = acquire_lock(
            &files,
            &state,
            &run_id(),
            &operator(),
            at("2026-09-21T12:05:00Z"),
        )
        .unwrap();
        // This process asking twice, which is what `plan` then `apply` is.
        // A resume after a kill is a DIFFERENT process and is the case
        // `two_processes_of_one_run_do_not_both_hold_the_lock` below draws.
        assert_eq!(first, again, "one process of one run holds one lock");
    }

    // Astra finding F04, 2026-09-23.
    #[test]
    fn two_processes_of_one_run_do_not_both_hold_the_lock() {
        let files = MemFiles::new();
        let state = state();
        // A record of this run, held by a process that is demonstrably
        // running and is not this one: pid 1 is init and is always there.
        let other = LockRecord {
            schema: LOCK_SCHEMA.to_string(),
            run_id: run_id(),
            operator: "silas".to_string(),
            workstation: operator().workstation.clone(),
            pid: 1,
            acquired_at: at("2026-09-21T12:00:00Z"),
        };
        files
            .write_atomic(&state.lock_path(), &other.to_json().unwrap(), 0o644)
            .unwrap();
        let err = acquire_lock(
            &files,
            &state,
            &run_id(),
            &operator(),
            at("2026-09-21T12:05:00Z"),
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("already being carried on"), "{err}");
        assert!(err.contains("unreadable"), "{err}");
        assert!(err.contains("--takeover"), "{err}");
        // And the holder's record is untouched.
        assert_eq!(read_lock(&files, &state).unwrap().unwrap(), other);
    }

    // Astra finding F04, 2026-09-23.
    #[test]
    fn a_resume_after_a_kill_still_takes_the_lock_of_its_own_run() {
        let files = MemFiles::new();
        let state = state();
        // The same shape as above, with the one difference that decides it:
        // the process that took the lock is not on this machine any more.
        let dead = LockRecord {
            schema: LOCK_SCHEMA.to_string(),
            run_id: run_id(),
            operator: "silas".to_string(),
            workstation: operator().workstation.clone(),
            // Positive, and above every `pid_max` a Linux kernel hands out.
            pid: 2_147_483_646,
            acquired_at: at("2026-09-21T12:00:00Z"),
        };
        files
            .write_atomic(&state.lock_path(), &dead.to_json().unwrap(), 0o644)
            .unwrap();
        let held = acquire_lock(
            &files,
            &state,
            &run_id(),
            &operator(),
            at("2026-09-21T12:05:00Z"),
        )
        .expect("a resume of a run whose process is gone may write");
        assert_eq!(held.run_id, run_id());
    }

    // Astra finding F04, 2026-09-23.
    #[test]
    fn two_takeovers_of_one_run_leave_exactly_one_holder() {
        let files = MemFiles::new();
        let state = state();
        let abandoned = acquire_lock(
            &files,
            &state,
            &run_id(),
            &operator(),
            at("2026-09-21T12:00:00Z"),
        )
        .unwrap();
        // The first takeover comes all the way through: it claims the old
        // record, drops it and puts its own lock there.
        let winner = take_over_lock(
            &files,
            &state,
            &abandoned.run_id,
            "run-second",
            &operator(),
            at("2026-09-21T12:01:00Z"),
        )
        .unwrap();
        assert_eq!(winner.run_id, "run-second");
        // A competing takeover must restore a lock belonging to a newer run without
        // overwriting another lock.
        let err = take_over_lock(
            &files,
            &state,
            &abandoned.run_id,
            "run-third",
            &operator(),
            at("2026-09-21T12:02:00Z"),
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("run-second"), "{err}");
        assert!(err.contains("Nothing was taken over"), "{err}");
        let after = read_lock(&files, &state).unwrap().unwrap();
        assert_eq!(after, winner, "the winner still holds the repository");
        assert!(
            !files.exists(&state.lock_path().with_file_name("lock.taken-by-run-third")),
            "the claim of a takeover that failed is not left lying about"
        );
    }

    /// A record of this run whose process is not on this machine any more.
    fn dead_record_of_this_run(workstation: &str) -> LockRecord {
        LockRecord {
            schema: LOCK_SCHEMA.to_string(),
            run_id: run_id(),
            operator: "silas".to_string(),
            workstation: workstation.to_string(),
            // Positive, and above every `pid_max` a Linux kernel hands out.
            pid: 2_147_483_646,
            acquired_at: at("2026-09-21T12:00:00Z"),
        }
    }

    /// A record of this run whose process is running: pid 1 is init, and
    /// `kill(1, 0)` answers EPERM — "it exists and is somebody else's".
    fn live_record_of_this_run() -> LockRecord {
        LockRecord {
            pid: 1,
            ..dead_record_of_this_run(&operator().workstation)
        }
    }

    fn claim_of_this_process() -> PathBuf {
        state().lock_path().with_file_name(format!(
            "lock.taken-by-{}.{}",
            run_id(),
            std::process::id()
        ))
    }

    // Astra finding MD01, 2026-09-25.
    #[test]
    fn a_resume_after_a_kill_puts_its_own_process_into_the_lock() {
        let files = MemFiles::new();
        let state = state();
        let dead = dead_record_of_this_run(&operator().workstation);
        files
            .write_atomic(&state.lock_path(), &dead.to_json().unwrap(), 0o644)
            .unwrap();
        let held = acquire_lock(
            &files,
            &state,
            &run_id(),
            &operator(),
            at("2026-09-21T12:05:00Z"),
        )
        .expect("a resume of a run whose process is gone may write");
        // The lock names THIS process now, not the one that died: a second
        // resume reads a running pid here and is refused.
        assert_eq!(held.pid, std::process::id());
        assert_eq!(held.acquired_at, at("2026-09-21T12:05:00Z"));
        assert_eq!(read_lock(&files, &state).unwrap().unwrap(), held);
        assert!(
            !files.exists(&claim_of_this_process()),
            "no claim is left lying about"
        );
    }

    // Astra finding MD01, 2026-09-25.
    #[test]
    fn a_second_resume_of_a_run_that_is_being_carried_on_is_refused() {
        let files = MemFiles::new();
        let state = state();
        let live = live_record_of_this_run();
        files
            .write_atomic(&state.lock_path(), &live.to_json().unwrap(), 0o644)
            .unwrap();
        let err = acquire_lock(
            &files,
            &state,
            &run_id(),
            &operator(),
            at("2026-09-21T12:05:00Z"),
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("already being carried on"), "{err}");
        assert!(err.contains("That process is running"), "{err}");
        assert_eq!(read_lock(&files, &state).unwrap().unwrap(), live);
    }

    // Astra finding MD01, 2026-09-25: `Elsewhere` is not `Gone`.
    #[test]
    fn a_lock_of_this_run_from_another_workstation_is_not_a_resume_target() {
        let files = MemFiles::new();
        let state = state();
        let elsewhere = dead_record_of_this_run("somewhere-else");
        files
            .write_atomic(&state.lock_path(), &elsewhere.to_json().unwrap(), 0o644)
            .unwrap();
        let err = acquire_lock(
            &files,
            &state,
            &run_id(),
            &operator(),
            at("2026-09-21T12:05:00Z"),
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("somewhere-else"), "{err}");
        assert!(err.contains("cannot be decided from here"), "{err}");
        assert!(err.contains("--takeover"), "{err}");
        assert_eq!(read_lock(&files, &state).unwrap().unwrap(), elsewhere);
    }

    // Astra finding MD01, 2026-09-25: the read said "dead", and by the time
    // of the rename another resume had put its live lock there.
    #[test]
    fn a_resume_that_carries_away_a_live_lock_puts_it_back_and_is_refused() {
        let files = MemFiles::new();
        let state = state();
        let dead = dead_record_of_this_run(&operator().workstation);
        let live = live_record_of_this_run();
        files
            .write_atomic(&state.lock_path(), &live.to_json().unwrap(), 0o644)
            .unwrap();
        let mine = LockRecord::new(
            &run_id(),
            &operator(),
            std::process::id(),
            at("2026-09-21T12:05:00Z"),
        );
        let err = succeed_dead_holder(&files, &state, &dead, mine, &operator())
            .unwrap_err()
            .to_string();
        assert!(err.contains("changed hands"), "{err}");
        assert_eq!(
            read_lock(&files, &state).unwrap().unwrap(),
            live,
            "the live lock is back where it was"
        );
        assert!(!files.exists(&claim_of_this_process()));
    }

    #[test]
    fn a_lock_whose_process_is_gone_says_so_and_is_still_a_lock() {
        let files = MemFiles::new();
        let state = state();
        // pid 1 is init and always alive; a pid this test can be sure is
        // dead is harder to come by, so the record is written by hand with
        // a pid that cannot be running.
        let dead = LockRecord {
            schema: LOCK_SCHEMA.to_string(),
            run_id: run_id(),
            operator: "silas".to_string(),
            workstation: "manacor".to_string(),
            // Positive, and above every `pid_max` a Linux kernel hands
            // out (the ceiling is 2^22).
            pid: 2_147_483_646,
            acquired_at: at("2026-09-21T12:00:00Z"),
        };
        files
            .write_atomic(&state.lock_path(), &dead.to_json().unwrap(), 0o644)
            .unwrap();
        assert_eq!(dead.liveness(&operator()), Liveness::Gone);
        let err = acquire_lock(
            &files,
            &state,
            "0192f0c0-0000-7000-8000-000000000002",
            &operator(),
            at("2026-09-21T12:10:00Z"),
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("no longer on this machine"), "{err}");
        assert!(err.contains("may have activated a system"), "{err}");
        assert!(err.contains("--takeover"), "{err}");
        // Nothing was taken by time or by pity.
        assert_eq!(read_lock(&files, &state).unwrap().unwrap().run_id, run_id());
    }

    #[test]
    fn a_pid_that_is_not_a_process_is_not_a_running_one() {
        // Reject zero and overflowing PIDs so signal-zero checks cannot address a process
        // group.
        for pid in [0, 4_294_967_295, u32::MAX - 1] {
            let record = LockRecord {
                schema: LOCK_SCHEMA.to_string(),
                run_id: run_id(),
                operator: "silas".to_string(),
                workstation: "manacor".to_string(),
                pid,
                acquired_at: at("2026-09-21T12:00:00Z"),
            };
            assert_eq!(
                record.liveness(&operator()),
                Liveness::Unknown,
                "pid {pid} is not a process"
            );
        }
        // And this process is of course running.
        let mine = LockRecord::new(
            &run_id(),
            &operator(),
            std::process::id(),
            at("2026-09-21T12:00:00Z"),
        );
        assert_eq!(mine.liveness(&operator()), Liveness::Running);
    }

    #[test]
    fn the_operator_anchor_is_recorded_where_it_belongs() {
        // Repository lock evidence belongs in run.start; lock.acquire events describe host
        // locks and require a host.
        let files = MemFiles::new();
        let state = state();
        let run = run_id();
        let record = acquire_lock(
            &files,
            &state,
            &run,
            &operator(),
            at("2026-09-21T12:00:00Z"),
        )
        .unwrap();
        let journal = Journal::new(state.journal_path(&run), &run, "plan-abc");
        journal
            .append(
                &files,
                journal
                    .event(EventKind::RunStart, at("2026-09-21T12:00:00Z"))
                    .payload(serde_json::json!({
                        "operator": {"user": record.operator, "workstation": record.workstation},
                        "anchor": {"path": state.lock_path().display().to_string(),
                                   "pid": record.pid}
                    })),
            )
            .unwrap();
        let read = read_journal(&files, &state.journal_path(&run)).unwrap();
        let folded = fold(&read.events).expect("it folds");
        assert_eq!(folded.operator.as_ref().unwrap().user, "silas");
        assert_eq!(
            read.events[0].payload["anchor"]["path"],
            serde_json::json!("/repo/.meister-deploy/lock"),
            "what fold does not read, it carries"
        );
        assert!(folded.hosts.is_empty(), "the anchor is about no host");
    }

    #[test]
    fn a_lock_from_another_workstation_is_not_judged_from_here() {
        let elsewhere = LockRecord {
            schema: LOCK_SCHEMA.to_string(),
            run_id: run_id(),
            operator: "silas".to_string(),
            workstation: "some-other-box".to_string(),
            pid: 1,
            acquired_at: at("2026-09-21T12:00:00Z"),
        };
        assert_eq!(elsewhere.liveness(&operator()), Liveness::Elsewhere);
        let sentence = elsewhere.refusal(&operator(), "0192f0c0-0000-7000-8000-000000000002");
        assert!(sentence.contains("taken on some-other-box"), "{sentence}");
        assert!(!sentence.contains("no longer"), "{sentence}");
    }

    #[test]
    fn a_takeover_names_the_run_it_takes_over() {
        let files = MemFiles::new();
        let state = state();
        acquire_lock(
            &files,
            &state,
            &run_id(),
            &operator(),
            at("2026-09-21T12:00:00Z"),
        )
        .unwrap();
        let mine = "0192f0c0-0000-7000-8000-000000000002";

        let err = take_over_lock(
            &files,
            &state,
            "0192f0c0-0000-7000-8000-00000000000f",
            mine,
            &operator(),
            at("2026-09-21T12:10:00Z"),
        )
        .unwrap_err()
        .to_string();
        assert!(
            err.contains("not by 0192f0c0-0000-7000-8000-00000000000f"),
            "{err}"
        );
        assert_eq!(read_lock(&files, &state).unwrap().unwrap().run_id, run_id());

        let taken = take_over_lock(
            &files,
            &state,
            &run_id(),
            mine,
            &operator(),
            at("2026-09-21T12:10:00Z"),
        )
        .expect("the named run is the one that is there");
        assert_eq!(taken.run_id, mine);
        assert_eq!(taken.acquired_at, at("2026-09-21T12:10:00Z"));
    }

    #[test]
    fn only_the_run_that_took_the_lock_gives_it_back() {
        let files = MemFiles::new();
        let state = state();
        acquire_lock(
            &files,
            &state,
            &run_id(),
            &operator(),
            at("2026-09-21T12:00:00Z"),
        )
        .unwrap();
        let err = release_lock(&files, &state, "0192f0c0-0000-7000-8000-000000000002")
            .unwrap_err()
            .to_string();
        assert!(err.contains("does not hold this repository"), "{err}");
        release_lock(&files, &state, &run_id()).expect("its own run may");
        assert!(read_lock(&files, &state).unwrap().is_none());
        // And releasing a lock that is not there is not an error: the
        // outcome asked for is that it is gone.
        release_lock(&files, &state, &run_id()).expect("gone is gone");
    }

    #[test]
    fn a_file_in_the_lock_place_that_nobody_here_wrote_is_left_alone() {
        let files = MemFiles::new();
        let state = state();
        files
            .write_atomic(&state.lock_path(), b"not json at all\n", 0o644)
            .unwrap();
        let err = acquire_lock(
            &files,
            &state,
            &run_id(),
            &operator(),
            at("2026-09-21T12:00:00Z"),
        )
        .unwrap_err()
        .to_string();
        assert!(
            err.contains("is not a lock record this tool wrote"),
            "{err}"
        );
        assert_eq!(
            files.content(state.lock_path()).unwrap(),
            b"not json at all\n".to_vec(),
            "it was not overwritten"
        );
    }

    #[test]
    fn the_journal_numbers_its_own_lines_and_names_its_own_run() {
        let files = MemFiles::new();
        let state = state();
        let run = run_id();
        state.begin_run(&files, &run).unwrap();
        let journal = Journal::new(state.journal_path(&run), &run, "plan-abc");

        let start = journal
            .append(
                &files,
                journal
                    .event(EventKind::RunStart, at("2026-09-21T12:00:00Z"))
                    .payload(serde_json::json!({
                        "operator": {"user": "silas", "workstation": "manacor"}
                    })),
            )
            .unwrap();
        assert_eq!(start.seq, 1);
        let moved = journal
            .append(
                &files,
                // A caller that names the wrong run does not get to: the
                // journal overwrites both ids.
                JournalEvent::new(
                    99,
                    at("2026-09-21T12:00:01Z"),
                    "another-run",
                    "another-plan",
                    EventKind::HostState,
                )
                .host("box")
                .transition(HostState::Planned, HostState::Preflight),
            )
            .unwrap();
        assert_eq!(moved.seq, 2);
        assert_eq!(moved.run_id, run);
        assert_eq!(moved.plan_id, "plan-abc");

        // What was written is what `fold` reads, and `fold` is strict about
        // both of the things this writer owns.
        let read = read_journal(&files, &state.journal_path(&run)).unwrap();
        assert_eq!(read.torn, None);
        assert_eq!(read.events.len(), 2);
        assert_eq!(read.last_seq(), 2);
        let folded = fold(&read.events).expect("a journal this writer wrote folds");
        assert_eq!(folded.run_id, run);
        assert_eq!(folded.last_seq, 2);
        assert_eq!(folded.hosts["box"].state, HostState::Preflight);
        assert!(folded.breaks.is_empty(), "{:?}", folded.breaks);
    }

    #[test]
    fn a_resumed_journal_continues_after_the_last_line() {
        let files = MemFiles::new();
        let state = state();
        let run = run_id();
        let journal = Journal::new(state.journal_path(&run), &run, "plan-abc");
        journal
            .append(
                &files,
                journal.event(EventKind::RunStart, at("2026-09-21T12:00:00Z")),
            )
            .unwrap();
        journal
            .append(
                &files,
                journal
                    .event(EventKind::LockAcquire, at("2026-09-21T12:00:01Z"))
                    .host("box"),
            )
            .unwrap();

        let read = read_journal(&files, &state.journal_path(&run)).unwrap();
        let again = Journal::resuming(state.journal_path(&run), &run, "plan-abc", read.last_seq());
        let next = again
            .append(
                &files,
                again.event(EventKind::RunEnd, at("2026-09-21T12:30:00Z")),
            )
            .unwrap();
        assert_eq!(next.seq, 3, "a resume does not start the numbering again");
        let read = read_journal(&files, &state.journal_path(&run)).unwrap();
        assert_eq!(read.events.len(), 3);
        fold(&read.events).expect("still one strictly increasing sequence");
    }

    #[test]
    fn exactly_one_torn_last_line_is_tolerated_and_reported() {
        let files = MemFiles::new();
        let state = state();
        let run = run_id();
        let path = state.journal_path(&run);
        let journal = Journal::new(&path, &run, "plan-abc");
        journal
            .append(
                &files,
                journal.event(EventKind::RunStart, at("2026-09-21T12:00:00Z")),
            )
            .unwrap();
        let whole = String::from_utf8(files.content(&path).unwrap()).unwrap();

        // Half a line, the way a machine that lost power leaves one.
        let torn_text = format!("{whole}{{\"seq\":2,\"ts\":\"2026-09-2");
        let torn_files = MemFiles::new().given(path.clone(), torn_text.into_bytes());
        let read = read_journal(&torn_files, &path).unwrap();
        assert_eq!(read.events.len(), 1, "the intact line is still read");
        assert!(
            read.torn
                .as_deref()
                .is_some_and(|t| t.contains("not a whole entry") && t.contains("dropped")),
            "{:?}",
            read.torn
        );
        fold(&read.events).expect("what is left is a journal");
    }

    // Astra finding F05, 2026-09-23.
    #[test]
    fn a_resume_after_a_torn_write_leaves_a_journal_that_folds() {
        // After repairing either tail shape, another append must leave a readable journal.
        for (what, tail, kept) in [
            ("a fragment", "{\"seq\":3,\"ts\":\"2026-09-2", 2usize),
            ("no newline", "", 2usize),
        ] {
            let files = MemFiles::new();
            let state = state();
            let run = run_id();
            let path = state.journal_path(&run);
            let journal = Journal::new(&path, &run, "plan-abc");
            for (seq, kind, host) in [
                (1, EventKind::RunStart, None),
                (2, EventKind::LockAcquire, Some("n1")),
            ] {
                let event = journal.event(kind, at("2026-09-21T12:00:00Z"));
                let event = match host {
                    Some(host) => event.host(host),
                    None => event,
                };
                let written = journal.append(&files, event).unwrap();
                assert_eq!(written.seq, seq);
            }
            let whole = String::from_utf8(files.content(&path).unwrap()).unwrap();
            let broken = if tail.is_empty() {
                // A whole line that lost only its newline.
                whole.trim_end_matches('\n').to_string()
            } else {
                format!("{whole}{tail}")
            };
            let files = MemFiles::new().given(path.clone(), broken.into_bytes());

            let note = repair_journal(&files, &path)
                .unwrap()
                .unwrap_or_else(|| panic!("{what} is something to repair"));
            assert!(note.contains(&path.display().to_string()), "{note}");
            // Nothing is left to report, because nothing is left torn.
            let read = read_journal(&files, &path).unwrap();
            assert_eq!(read.torn, None, "{what}: it was repaired");
            assert_eq!(read.events.len(), kept, "{what}");

            // And now the resume writes its next line, and the file still
            // reads back as what it is.
            let resumed = Journal::resuming(&path, &run, "plan-abc", read.last_seq());
            let next = resumed
                .append(
                    &files,
                    resumed.event(EventKind::RunEnd, at("2026-09-21T12:10:00Z")),
                )
                .unwrap();
            assert_eq!(next.seq, kept as u64 + 1, "{what}");
            let after = read_journal(&files, &path)
                .unwrap_or_else(|e| panic!("{what}: the journal is unreadable: {e:#}"));
            assert_eq!(after.torn, None, "{what}");
            assert_eq!(after.events.len(), kept + 1, "{what}");
            let folded = fold(&after.events).expect("it folds");
            assert!(folded.breaks.is_empty(), "{what}: {:?}", folded.breaks);
        }
    }

    // Astra finding F05, 2026-09-23.
    #[test]
    fn a_journal_cut_inside_a_character_is_still_a_journal() {
        // Invalid UTF-8 in the torn fragment must reach tail repair instead of failing
        // decoding first.
        let files = MemFiles::new();
        let state = state();
        let run = run_id();
        let path = state.journal_path(&run);
        let journal = Journal::new(&path, &run, "plan-abc");
        journal
            .append(
                &files,
                journal.event(EventKind::RunStart, at("2026-09-21T12:00:00Z")),
            )
            .unwrap();
        let mut bytes = files.content(&path).unwrap();
        // The first two bytes of a three-byte character and nothing else.
        bytes.extend_from_slice(b"{\"seq\":2,\"ts\":\"\xe2\x80");
        let files = MemFiles::new().given(path.clone(), bytes);

        let read = read_journal(&files, &path).expect("it is readable");
        assert_eq!(read.events.len(), 1);
        assert!(read.torn.is_some(), "and the fragment is reported");
        assert!(repair_journal(&files, &path).unwrap().is_some());
        let after = read_journal(&files, &path).unwrap();
        assert_eq!(after.torn, None);
        assert_eq!(after.events.len(), 1);
    }

    #[test]
    fn a_whole_last_line_without_its_newline_is_kept_and_still_reported() {
        let files = MemFiles::new();
        let state = state();
        let run = run_id();
        let path = state.journal_path(&run);
        let journal = Journal::new(&path, &run, "plan-abc");
        journal
            .append(
                &files,
                journal.event(EventKind::RunStart, at("2026-09-21T12:00:00Z")),
            )
            .unwrap();
        journal
            .append(
                &files,
                journal.event(EventKind::LockAcquire, at("2026-09-21T12:00:01Z")),
            )
            .unwrap();
        let whole = String::from_utf8(files.content(&path).unwrap()).unwrap();
        let clipped = whole.trim_end_matches('\n').to_string();

        let clipped_files = MemFiles::new().given(path.clone(), clipped.into_bytes());
        let read = read_journal(&clipped_files, &path).unwrap();
        assert_eq!(read.events.len(), 2, "it parsed, so it happened");
        assert!(
            read.torn
                .as_deref()
                .is_some_and(|t| t.contains("without its newline") && t.contains("kept")),
            "{:?}",
            read.torn
        );
    }

    #[test]
    fn a_broken_line_that_is_not_the_last_one_is_not_a_power_cut() {
        let state = state();
        let path = state.journal_path(&run_id());
        let files = MemFiles::new().given(
            path.clone(),
            b"{\"seq\":1,\"ts\":\"2026-09-21T12:00:00Z\",\"run_id\":\"r\",\"plan_id\":\"p\",\
              \"event\":\"run.start\",\"host\":null,\"from\":null,\"to\":null,\"payload\":{}}\n\
              this is not a journal entry\n\
              {\"seq\":3,\"ts\":\"2026-09-21T12:00:02Z\",\"run_id\":\"r\",\"plan_id\":\"p\",\
              \"event\":\"run.end\",\"host\":null,\"from\":null,\"to\":null,\"payload\":{}}\n"
                .to_vec(),
        );
        let err = read_journal(&files, &path).unwrap_err().to_string();
        assert!(err.contains("line 2"), "{err}");
        assert!(err.contains("is not a journal entry"), "{err}");
    }

    #[test]
    fn a_secret_that_reaches_the_journal_is_written_as_stars() {
        let files = MemFiles::new();
        let state = state();
        let run = run_id();
        let key = "-----BEGIN PRIVATE KEY-----\nMIIBsecret\n-----END PRIVATE KEY-----";
        let journal = Journal::new(state.journal_path(&run), &run, "plan-abc").hiding(key);
        journal
            .append(
                &files,
                journal
                    .event(EventKind::ActionEnd, at("2026-09-21T12:00:00Z"))
                    .host("box")
                    .payload(serde_json::json!({
                        "action": 7,
                        "kind": "deliver-secret",
                        "result": "ok",
                        // Redact secrets embedded directly in the payload.
                        "evidence": [format!("wrote {key}")],
                        "cmd_refs": ["ssh box sh -c …"]
                    })),
            )
            .unwrap();
        let text = String::from_utf8(files.content(state.journal_path(&run)).unwrap()).unwrap();
        assert!(!text.contains("MIIBsecret"), "{text}");
        assert!(!text.contains("PRIVATE KEY"), "{text}");
        assert!(text.contains("***"), "{text}");
        // And it is still a journal line.
        let read = read_journal(&files, &state.journal_path(&run)).unwrap();
        assert_eq!(read.events.len(), 1);
        assert_eq!(read.events[0].seq, 1);
    }

    #[test]
    fn the_receipt_names_the_journal_it_was_folded_from() {
        let files = MemFiles::new();
        let state = state();
        let run = run_id();
        let path = state.journal_path(&run);
        let journal = Journal::new(&path, &run, "plan-abc");
        journal
            .append(
                &files,
                journal.event(EventKind::RunStart, at("2026-09-21T12:00:00Z")),
            )
            .unwrap();
        let reference = journal_ref(&files, &path).unwrap();
        assert_eq!(reference.path, path.display().to_string());
        assert_eq!(
            reference.sha256,
            sha256_hex(&files.content(&path).unwrap()),
            "the digest is of the bytes that are there"
        );
        assert_eq!(reference.sha256.len(), 64);
    }

    #[test]
    fn the_runs_of_a_directory_come_back_in_the_order_they_happened() {
        let files = MemFiles::new();
        let state = state();
        // uuid v7 sorts by time, so a lexical listing is a chronological one.
        for run in [
            "0192f0c0-0000-7000-8000-000000000003",
            "0192f0c0-0000-7000-8000-000000000001",
            "0192f0c0-0000-7000-8000-000000000002",
        ] {
            state.begin_run(&files, run).unwrap();
        }
        assert_eq!(
            state.runs(&files).unwrap(),
            vec![
                "0192f0c0-0000-7000-8000-000000000001".to_string(),
                "0192f0c0-0000-7000-8000-000000000002".to_string(),
                "0192f0c0-0000-7000-8000-000000000003".to_string(),
            ]
        );
        // And an empty directory holds no runs rather than being an error.
        assert!(
            StateDir::in_repo(Path::new("/elsewhere"))
                .runs(&files)
                .unwrap()
                .is_empty()
        );
    }

    /// A release's roots on the disk: one link per host, plus the stamp.
    fn with_release(files: MemFiles, id: &str, created: &str) -> MemFiles {
        files
            .given(
                format!("/repo/.meister-deploy/gcroots/{id}/.created"),
                format!("{created}\n").into_bytes(),
            )
            .given_symlink(
                format!("/repo/.meister-deploy/gcroots/{id}/box"),
                format!("/nix/store/{id}-system"),
            )
    }

    fn a_receipt(run_id: &str, outcome: crate::receipt::Outcome, ended: Option<&str>) -> Vec<u8> {
        let receipt = DeploymentReceipt {
            schema: crate::receipt::RECEIPT_SCHEMA.to_string(),
            run_id: run_id.to_string(),
            plan_id: "plan-1".to_string(),
            release_id: "release-1".to_string(),
            started_at: Some(at("2026-09-01T00:00:00Z")),
            ended_at: ended.map(at),
            operator: None,
            outcome,
            hosts: BTreeMap::new(),
            untouched: Vec::new(),
            checks: Vec::new(),
            breaks: Vec::new(),
            journal_path: "journal.jsonl".to_string(),
            journal_sha256: "0".repeat(64),
            stopped: None,
            waiting: None,
        };
        receipt.to_json().unwrap()
    }

    /// A finished run on the disk: the four things a run writes.
    fn with_run(
        files: MemFiles,
        run_id: &str,
        outcome: crate::receipt::Outcome,
        ended: Option<&str>,
    ) -> MemFiles {
        files
            .given(
                format!("/repo/.meister-deploy/runs/{run_id}/journal.jsonl"),
                b"{}\n".to_vec(),
            )
            .given(
                format!("/repo/.meister-deploy/runs/{run_id}/plan.json"),
                b"{}\n".to_vec(),
            )
            .given(
                format!("/repo/.meister-deploy/runs/{run_id}/observations/20260901T000000Z.json"),
                b"{}\n".to_vec(),
            )
            .given(
                format!("/repo/.meister-deploy/runs/{run_id}/receipt.json"),
                a_receipt(run_id, outcome, ended),
            )
    }

    #[test]
    fn a_release_goes_only_when_the_count_and_the_age_both_allow_it() {
        let mut files = MemFiles::new();
        files = with_release(files, "release-old", "2026-09-01T00:00:00Z");
        files = with_release(files, "release-mid", "2026-09-20T00:00:00Z");
        files = with_release(files, "release-new", "2026-09-21T00:00:00Z");
        let state = state();
        let roots = crate::build::roots(&files, &state).unwrap();
        let now = at("2026-09-22T00:00:00Z");

        // Count alone: the newest keeps its roots, the two behind it do not.
        let swept = sweep(
            &files,
            &state,
            &roots,
            &Retention {
                keep: 1,
                ..Retention::default()
            },
            now,
        )
        .unwrap();
        assert_eq!(
            swept
                .removals_of("release")
                .iter()
                .map(|r| r.what.as_str())
                .collect::<Vec<_>>(),
            vec!["release-old", "release-mid"]
        );

        // With an age guard the two guards have to AGREE: `release-mid` is
        // two days old and stays, `release-old` is three weeks old and goes.
        let swept = sweep(
            &files,
            &state,
            &roots,
            &Retention {
                keep: 1,
                older_than_days: Some(DEFAULT_OLDER_THAN_DAYS),
                ..Retention::default()
            },
            now,
        )
        .unwrap();
        assert_eq!(
            swept
                .removals_of("release")
                .iter()
                .map(|r| r.what.as_str())
                .collect::<Vec<_>>(),
            vec!["release-old"]
        );
        let kept: Vec<&str> = swept
            .kept_of("release")
            .iter()
            .map(|k| k.what.as_str())
            .collect();
        assert!(kept.contains(&"release-mid"), "{kept:?}");
        // And the sentence says which of the two guards kept it.
        let why = &swept
            .kept_of("release")
            .iter()
            .find(|k| k.what == "release-mid")
            .unwrap()
            .why;
        assert!(why.contains("14 day(s)"), "{why}");
    }

    #[test]
    fn a_directory_this_tool_cannot_date_is_never_removed() {
        let files = MemFiles::new().given_symlink(
            "/repo/.meister-deploy/gcroots/release-undated/box",
            "/nix/store/xxx-system",
        );
        let state = state();
        let roots = crate::build::roots(&files, &state).unwrap();
        let swept = sweep(
            &files,
            &state,
            &roots,
            &Retention {
                keep: 0,
                ..Retention::default()
            },
            at("2030-01-01T00:00:00Z"),
        )
        .unwrap();
        assert!(swept.removals_of("release").is_empty());
        assert!(
            swept.kept_of("release")[0].why.contains(".created"),
            "{:?}",
            swept.kept_of("release")[0]
        );
    }

    #[test]
    fn a_stamp_this_tool_cannot_read_is_not_the_same_as_no_stamp() {
        // Retain both missing and unreadable stamps, with distinct diagnostics.
        let files = MemFiles::new()
            .given(
                "/repo/.meister-deploy/gcroots/release-edited/.created",
                b"00Z\n".to_vec(),
            )
            .given_symlink(
                "/repo/.meister-deploy/gcroots/release-edited/box",
                "/nix/store/xxx-system",
            )
            .given_symlink(
                "/repo/.meister-deploy/gcroots/release-stampless/box",
                "/nix/store/yyy-system",
            );
        let state = state();
        let roots = crate::build::roots(&files, &state).unwrap();
        let swept = sweep(
            &files,
            &state,
            &roots,
            &Retention {
                keep: 0,
                ..Retention::default()
            },
            at("2030-01-01T00:00:00Z"),
        )
        .unwrap();
        assert!(swept.removals_of("release").is_empty(), "both are kept");
        let why: BTreeMap<&str, &str> = swept
            .kept_of("release")
            .iter()
            .map(|k| (k.what.as_str(), k.why.as_str()))
            .collect();
        assert!(
            why["release-edited"].contains("\"00Z\"")
                && why["release-edited"].contains("not a date"),
            "{:?}",
            why["release-edited"]
        );
        assert!(
            why["release-stampless"].contains("has no .created stamp"),
            "{:?}",
            why["release-stampless"]
        );
    }

    #[test]
    fn carrying_out_a_sweep_drops_the_links_and_never_the_store_path() {
        let files = with_release(MemFiles::new(), "release-old", "2026-09-01T00:00:00Z");
        let state = state();
        let roots = crate::build::roots(&files, &state).unwrap();
        let swept = sweep(
            &files,
            &state,
            &roots,
            &Retention {
                keep: 0,
                ..Retention::default()
            },
            at("2026-09-22T00:00:00Z"),
        )
        .unwrap();
        carry_out(&files, &swept).unwrap();
        assert!(!files.exists(Path::new("/repo/.meister-deploy/gcroots/release-old/box")));
        assert!(
            !files
                .attempts()
                .iter()
                .any(|a| a.contains("/nix/store/release-old-system")),
            "{:?}",
            files.attempts()
        );
    }

    #[test]
    fn snapshots_are_left_alone_unless_a_number_is_given_and_latest_never_goes() {
        let files = MemFiles::new()
            .given(
                "/repo/.meister-deploy/observations/20260901T000000Z.json",
                b"{}".to_vec(),
            )
            .given(
                "/repo/.meister-deploy/observations/20260920T000000Z.json",
                b"{}".to_vec(),
            )
            .given(
                "/repo/.meister-deploy/observations/20260921T000000Z.json",
                b"{}".to_vec(),
            )
            .given(
                "/repo/.meister-deploy/observations/latest.json",
                b"{}".to_vec(),
            );
        let state = state();
        let now = at("2026-09-22T00:00:00Z");

        // Nothing asked, nothing touched.
        let swept = sweep(&files, &state, &[], &Retention::default(), now).unwrap();
        assert!(swept.remove.is_empty());
        assert!(swept.keep.is_empty());

        // The newest one, and `latest.json` is not one of the candidates.
        let swept = sweep(
            &files,
            &state,
            &[],
            &Retention {
                observations: Some(1),
                ..Retention::default()
            },
            now,
        )
        .unwrap();
        assert_eq!(
            swept
                .removals_of("observation")
                .iter()
                .map(|r| r.what.as_str())
                .collect::<Vec<_>>(),
            vec!["20260901T000000Z.json", "20260920T000000Z.json"]
        );

        // The age guard protects a snapshot the count would have taken —
        // asked before anything is carried out, because a sweep is a
        // decision about what is on the disk right now.
        let guarded = sweep(
            &files,
            &state,
            &[],
            &Retention {
                observations: Some(1),
                older_than_days: Some(14),
                ..Retention::default()
            },
            now,
        )
        .unwrap();
        assert!(
            guarded
                .kept_of("observation")
                .iter()
                .any(|k| k.what == "20260920T000000Z.json" && k.why.contains("14 day(s)")),
            "{:?}",
            guarded.kept_of("observation")
        );

        carry_out(&files, &swept).unwrap();
        assert!(files.exists(Path::new("/repo/.meister-deploy/observations/latest.json")));
        assert!(files.exists(Path::new(
            "/repo/.meister-deploy/observations/20260921T000000Z.json"
        )));
    }

    #[test]
    fn a_run_that_is_evidence_is_never_removed() {
        let mut files = MemFiles::new();
        // Oldest first; uuid v7 sorts by time.
        files = with_run(
            files,
            "0192f0c0-0000-7000-8000-000000000001",
            crate::receipt::Outcome::Success,
            Some("2026-09-01T00:00:00Z"),
        );
        files = with_run(
            files,
            "0192f0c0-0000-7000-8000-000000000002",
            crate::receipt::Outcome::Failed,
            Some("2026-09-02T00:00:00Z"),
        );
        files = with_run(
            files,
            "0192f0c0-0000-7000-8000-000000000003",
            crate::receipt::Outcome::Partial,
            Some("2026-09-03T00:00:00Z"),
        );
        // A run that never ended: journal, no receipt.
        files = files.given(
            "/repo/.meister-deploy/runs/0192f0c0-0000-7000-8000-000000000004/journal.jsonl",
            b"{}\n".to_vec(),
        );
        files = with_run(
            files,
            "0192f0c0-0000-7000-8000-000000000005",
            crate::receipt::Outcome::Success,
            Some("2026-09-05T00:00:00Z"),
        );
        let state = state();
        let now = at("2026-09-22T00:00:00Z");

        // Without `--runs` nothing under runs/ is even considered.
        let swept = sweep(
            &files,
            &state,
            &[],
            &Retention {
                keep: 0,
                ..Retention::default()
            },
            now,
        )
        .unwrap();
        assert!(swept.remove.is_empty());

        let swept = sweep(
            &files,
            &state,
            &[],
            &Retention {
                keep: 0,
                runs: true,
                ..Retention::default()
            },
            now,
        )
        .unwrap();
        assert_eq!(
            swept
                .removals_of("run")
                .iter()
                .map(|r| r.what.as_str())
                .collect::<Vec<_>>(),
            vec![
                "0192f0c0-0000-7000-8000-000000000001",
                "0192f0c0-0000-7000-8000-000000000005"
            ],
            "only the two that ended success"
        );
        let why: BTreeMap<&str, &str> = swept
            .kept_of("run")
            .iter()
            .map(|k| (k.what.as_str(), k.why.as_str()))
            .collect();
        assert!(why["0192f0c0-0000-7000-8000-000000000002"].contains("failed"));
        assert!(why["0192f0c0-0000-7000-8000-000000000003"].contains("partial"));
        assert!(why["0192f0c0-0000-7000-8000-000000000004"].contains("no receipt"));

        // Remove only the files represented in this test run.
        carry_out(&files, &swept).unwrap();
        for leftover in [
            "/repo/.meister-deploy/runs/0192f0c0-0000-7000-8000-000000000001/journal.jsonl",
            "/repo/.meister-deploy/runs/0192f0c0-0000-7000-8000-000000000001/receipt.json",
            "/repo/.meister-deploy/runs/0192f0c0-0000-7000-8000-000000000001/observations/20260901T000000Z.json",
        ] {
            assert!(
                !files.exists(Path::new(leftover)),
                "{leftover} is still there"
            );
        }
        assert!(files.exists(Path::new(
            "/repo/.meister-deploy/runs/0192f0c0-0000-7000-8000-000000000002/receipt.json"
        )));
    }

    #[test]
    fn a_run_with_a_file_nobody_here_wrote_stays_whole() {
        let mut files = MemFiles::new();
        files = with_run(
            files,
            "0192f0c0-0000-7000-8000-000000000001",
            crate::receipt::Outcome::Success,
            Some("2026-09-01T00:00:00Z"),
        );
        files = files.given(
            "/repo/.meister-deploy/runs/0192f0c0-0000-7000-8000-000000000001/notes.txt",
            b"why this went wrong\n".to_vec(),
        );
        let state = state();
        let swept = sweep(
            &files,
            &state,
            &[],
            &Retention {
                keep: 0,
                runs: true,
                ..Retention::default()
            },
            at("2026-09-22T00:00:00Z"),
        )
        .unwrap();
        assert!(swept.removals_of("run").is_empty());
        let why = &swept.kept_of("run")[0].why;
        assert!(why.contains("notes.txt"), "{why}");
        assert!(why.contains("recursively"), "{why}");
    }
}
