// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Where a run leaves its evidence, and the one file two operators race for.
//!
//! The pre-v1 tool had no state at all: no journal, no receipt, no lock. A
//! rollout that was interrupted left nothing behind, so "what happened?" was
//! answered by reading a terminal's scrollback and "is somebody else already
//! doing this?" was not answered at all. Everything in here exists to make
//! those two questions answerable by a file (D4, D6).
//!
//! ```text
//! <repo>/.meister-deploy/
//!   lock                        the operator's anchor: one writer per repo
//!   observations/latest.json    the last snapshot, for `status --offline`
//!   observations/<ts>.json      the snapshots, by the moment they were taken
//!   runs/<run-id>/journal.jsonl append-only, one line per event, fsync each
//!   runs/<run-id>/receipt.json  what happened, once it has
//!   runs/<run-id>/plan.json     the plan as it was applied, verbatim
//!   runs/<run-id>/observations/ the snapshots this run took
//!   gcroots/<release-id>/<host> roots, so a released closure survives a gc
//!   snapshots/<content-hash>/   `resolve --dev` materialises here (1C)
//! ```
//!
//! Three properties are worth spelling out.
//!
//! **The journal is written before the thing it describes.** `append_fsync`
//! is one `write` to an `O_APPEND` handle followed by `sync_all`, so a line
//! that says `action.irreversible` is on the disk before the action starts
//! (lane 2C writes it there). That is the whole mechanism behind a resume
//! that does not activate twice.
//!
//! **A reader tolerates exactly one torn line, at the end, and says so.**
//! A machine that lost power in the middle of a `write` leaves a partial
//! last line. Dropping it silently would make a journal that cannot be
//! trusted look like one that can; refusing to read the file at all would
//! throw away the ninety-nine lines that are intact. So the last line is
//! allowed to be broken, it is reported, and a broken line ANYWHERE ELSE is
//! an error — that is not a power cut, that is a file somebody edited.
//!
//! **A lock is never taken by time.** A lock with a dead owner is still a
//! lock: the run that held it may have got as far as activating a system,
//! and the only thing that knows is the target. So the sentence says what
//! is known — including that the process is demonstrably gone, when it can
//! be checked on this machine — and the operator says `--takeover <run-id>`
//! or nothing happens. A timeout here would be this tool deciding that
//! somebody else's rollout is over because it has been quiet.

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

    /// Every run this directory holds, oldest first.
    ///
    /// Oldest first because a run id is a uuid v7: it sorts by the time it
    /// was made, which is what makes a lexical listing a chronological one
    /// and `gc --keep N` a sentence about the last N runs.
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

    /// Write a snapshot, and point `latest.json` at what it says.
    ///
    /// Two copies on purpose: `observations/<ts>.json` is the history and
    /// `latest.json` is what `status --offline` and a `--observation`
    /// without a path read. A symlink would be cheaper and would break the
    /// moment somebody copied the directory without `-a`.
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

/// Who holds the state directory.
///
/// This is the BOOTSTRAP anchor of D6: the single-writer contract for a fleet
/// that has no control plane yet. The per-host locks a rollout takes are a
/// different thing, written by `meister-activate` on the target
/// ([`crate::observation::Lock`]); this one is about two operators in one
/// repository.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LockRecord {
    pub schema: String,
    pub run_id: String,
    pub operator: String,
    /// Which machine the process is on. Without it, a pid is a number that
    /// means something different on every host that shares the directory —
    /// and a state directory on a network filesystem is exactly the case
    /// this field exists for.
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
        // A pid that does not fit in a positive `pid_t` is not a process.
        // It matters more than it looks: `kill` reads 0 as "my process
        // group" and -1 as "everything I may signal", and 4294967295 cast
        // to an i32 IS -1 — so a lock record with a nonsense pid would be
        // reported as a live process rather than as nonsense.
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

/// Who this process is, for a lock record and a receipt.
///
/// The user comes from the environment because that is who an operator is
/// to every other tool they run; the uid is the fallback for a process
/// started without one (a cron job, a systemd unit).
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

/// Take the lock, or say who has it.
///
/// A lock this run already holds is not an error: a verb that acquires
/// twice inside one run — `plan` then `apply --resume` — is asking whether
/// it may write, and the answer is yes.
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
                Some(held) if held.run_id == run_id => Ok(held),
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

/// Take a named run's lock, deliberately.
///
/// The run id has to be passed in and has to match what is there: an
/// operator who types `--takeover` has read the refusal, and quoting the id
/// out of it is how they say which run they mean. A takeover that accepted
/// "whatever is in the file" would take over a run that started in the
/// meantime.
pub fn take_over_lock(
    files: &dyn Files,
    state: &StateDir,
    of_run: &str,
    run_id: &str,
    operator: &Operator,
    now: DateTime<Utc>,
) -> Result<LockRecord> {
    match read_lock(files, state)? {
        None => acquire_lock(files, state, run_id, operator, now),
        Some(held) if held.run_id == of_run => {
            files.remove_file(&state.lock_path())?;
            acquire_lock(files, state, run_id, operator, now)
        }
        Some(held) => bail!(
            "this repository is held by run {}, not by {of_run}. Nothing was taken over: \
             --takeover names the run it takes over so that it cannot take over one that \
             started while you were reading.",
            held.run_id
        ),
    }
}

// ---------------------------------------------------------------------------
// The journal
// ---------------------------------------------------------------------------

/// The writer of one run's journal.
///
/// It owns `seq`, `run_id` and `plan_id` so that no caller can get them
/// wrong: [`crate::receipt::fold`] refuses a journal whose sequence does not
/// strictly increase and one that carries two runs, and both of those are
/// properties of the writer rather than of a convention.
///
/// Secrets: everything this writes goes through the same redaction list the
/// runner uses for a command line. A journal is the file an operator
/// attaches to a ticket.
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

    /// An event of this run, ready to be given a host, a transition and a
    /// payload. Its `seq` is set when it is written and not before: a
    /// sequence number that was handed out and never written would be a gap
    /// [`crate::receipt::fold`] reports as a lost line.
    pub fn event(&self, kind: EventKind, now: DateTime<Utc>) -> JournalEvent {
        JournalEvent::new(0, now, &self.run_id, &self.plan_id, kind)
    }

    /// Write it, durably, and hand back what was written.
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

/// Apply a redaction list to a finished json line.
///
/// Both spellings of every secret: the raw one, and the one json escaping
/// produces. A key with a newline in it appears in a line as `\n`, and a
/// list that only knew the raw form would leave it there.
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

/// Read a journal, tolerating exactly one torn line at the end.
pub fn read_journal(files: &dyn Files, path: &Path) -> Result<JournalRead> {
    let text = files.read_to_string(path)?;
    let origin = path.display().to_string();
    // A line that is not followed by a newline was not finished: every line
    // this tool writes goes out as line plus newline in ONE write.
    let unterminated = !text.is_empty() && !text.ends_with('\n');
    let mut lines: Vec<&str> = text.lines().collect();
    let mut torn = None;

    if unterminated && let Some(last) = lines.pop() {
        // It may still parse — a short line can land whole and lose only its
        // newline. Then it is kept, because it happened, and it is still
        // reported, because the run that wrote it did not get to the next
        // one.
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

/// The journal and its digest, as a receipt names them.
pub fn journal_ref(files: &dyn Files, path: &Path) -> Result<JournalRef> {
    let bytes = files.read(path)?;
    Ok(JournalRef {
        path: path.display().to_string(),
        sha256: sha256_hex(&bytes),
    })
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
        assert_eq!(first, again, "a resume of the same run holds the same lock");
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
        // 4294967295 as an i32 is -1, and `kill(-1, 0)` succeeds: a record
        // with that in it would be read as "the holder is running" — or, if
        // this were ever a real signal rather than signal 0, as something
        // far worse. Zero is `kill(0)`, which is this process's own group.
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
        // 2B's `fold` requires every `lock.acquire` to name a host, because
        // those are the per-host locks a rollout takes. The operator's
        // anchor is not one of those — it is about this repository — so it
        // travels in the `run.start` payload, which `fold` carries through
        // untouched beside the operator it does read.
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
                        // Somebody put the thing itself in the payload. It is
                        // the writer's job that it does not reach the file.
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
}
