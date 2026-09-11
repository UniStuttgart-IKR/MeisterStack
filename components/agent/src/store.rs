// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use agent_api::{
    VmId,
    storage::{SnapshotId, VolumeId},
};
use anyhow::Context;
use redb::{Database, ReadableDatabase, ReadableTable, TableDefinition};

use crate::conditions::{Conditions, DISK_PRESSURE, STORE_UNHEALTHY};
use crate::types::{SnapshotRecord, VmRecord, VolumeRecord};
use tracing::{error, info, warn};

const VMS: TableDefinition<&str, &[u8]> = TableDefinition::new("vms");

/// The volumes this node was told to make, keyed by the control plane's uid.
///
/// A table of its own beside the VMs, and not a field on a VM record, because
/// that is the whole point of the object one tier up: a volume outlives the
/// VM that used it, so it cannot be stored inside one. A record here is the
/// node's memory of bytes it owns with no consumer implied.
const VOLUMES: TableDefinition<&str, &[u8]> = TableDefinition::new("volumes");

/// The snapshots this node was told to take, keyed by the control plane's uid.
///
/// A third table for the same reason the second one exists, one step further:
/// a snapshot outlives the VOLUME it came from — that is the whole of what it
/// is for — so it cannot live inside a volume's record any more than a volume
/// can live inside a VM's.
const SNAPSHOTS: TableDefinition<&str, &[u8]> = TableDefinition::new("snapshots");

/// How long a failed reopen waits before the next operation may try again.
///
/// The backoff, and the whole of it. A disk that is full stays full, and an
/// agent that answered every one of the 180 failures a five-minute window
/// produced with a fresh `Database::create` would spend the outage opening
/// files instead of reporting it. One attempt per window is enough to pick a
/// transient error up within seconds and cheap enough to survive a permanent
/// one.
const REOPEN_COOLDOWN: Duration = Duration::from_secs(2);

/// Whether this error is the one redb only recovers from by being reopened.
///
/// `PreviousIo` is the poison flag itself — "Previous I/O error occurred.
/// Please close and re-open the database" — and `Io` is the error that sets
/// it. Everything else on redb's enums is about the data or about this
/// process (a corrupt page, a value too large, a poisoned lock), and reopening
/// for any of those would be a restart loop over a fault a restart cannot fix.
fn needs_reopen(e: &anyhow::Error) -> bool {
    // A store with no handle at all is the third case, and it is this one
    // seen from one attempt later: the reopen that dropped the poisoned
    // handle could not make a new one, and the next operation is the one that
    // gets to try again.
    e.chain().any(|c| c.is::<Closed>())
        || e.chain().filter_map(storage_error).any(|s| {
            matches!(
                s,
                redb::StorageError::Io(_) | redb::StorageError::PreviousIo
            )
        })
}

/// Whether this error is a full disk, which is a fact about the NODE and not
/// about the database.
fn out_of_space(e: &anyhow::Error) -> bool {
    e.chain().filter_map(storage_error).any(|s| match s {
        redb::StorageError::Io(io) => {
            io.kind() == std::io::ErrorKind::StorageFull
                || io.raw_os_error() == Some(nix::libc::ENOSPC)
        }
        _ => false,
    })
}

/// The storage error inside one link of an error chain, whichever of redb's
/// four wrappers it arrived in.
///
/// Written out rather than matched on the rendered message: every call in this
/// file adds `anyhow` context, so the typed error is still on the chain, and a
/// string match would break the day redb rewords a sentence.
fn storage_error<'a>(
    cause: &'a (dyn std::error::Error + 'static),
) -> Option<&'a redb::StorageError> {
    if let Some(e) = cause.downcast_ref::<redb::StorageError>() {
        return Some(e);
    }
    if let Some(redb::TransactionError::Storage(e)) = cause.downcast_ref::<redb::TransactionError>()
    {
        return Some(e);
    }
    if let Some(redb::TableError::Storage(e)) = cause.downcast_ref::<redb::TableError>() {
        return Some(e);
    }
    if let Some(redb::CommitError::Storage(e)) = cause.downcast_ref::<redb::CommitError>() {
        return Some(e);
    }
    if let Some(redb::DatabaseError::Storage(e)) = cause.downcast_ref::<redb::DatabaseError>() {
        return Some(e);
    }
    None
}

/// The store has no handle at all: a reopen dropped the poisoned one and
/// could not make a new one.
///
/// A type rather than a sentence because `attempt` has to recognise it — this
/// is the state the NEXT operation must try the reopen again from, and a
/// string would make that a match on prose.
#[derive(Debug)]
struct Closed;

impl std::fmt::Display for Closed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("the agent database is closed after an i/o error")
    }
}

impl std::error::Error for Closed {}

pub struct Store {
    /// Behind a lock because it is REPLACED, not because it is shared: redb's
    /// own handle is `Sync` and every operation here took `&self` before. What
    /// the lock protects is the swap in `reopen`.
    ///
    /// `Option`, because redb holds an exclusive lock on the file: a second
    /// handle cannot be made while the first one is alive, so the poisoned one
    /// has to be dropped BEFORE the fresh one is created, and between those
    /// two moments this store has no database. A reopen that fails leaves it
    /// that way — see `Closed`, which is what every operation then says.
    db: RwLock<Option<Database>>,
    /// Kept so the store can open itself again. redb has no "reopen" of its
    /// own — the documented recovery from an I/O error is to drop the handle
    /// and create a new one, and that needs the path.
    path: PathBuf,
    /// What this node says about itself on the heartbeat. The store is one of
    /// the two things that write to it (`conditions::check_cgroup_root` is the
    /// other), because a database nobody can write to is a node that can serve
    /// no command, whatever its heartbeat says.
    conditions: Arc<Conditions>,
    /// How often this store has had to open itself again. Never anything but
    /// zero on a healthy node, which is what makes it worth reading.
    reopens: AtomicU64,
    /// When the last reopen was ATTEMPTED, successful or not. See
    /// `REOPEN_COOLDOWN`.
    last_reopen: Mutex<Option<Instant>>,
}

impl Store {
    /// A store with a condition set of its own, which is what every test and
    /// every tool wants: nobody is listening to it.
    pub fn open(path: &Path) -> anyhow::Result<Self> {
        Self::open_reporting_to(path, Arc::new(Conditions::default()))
    }

    /// The agent's store, saying what it finds out into the node's conditions.
    pub fn open_reporting_to(path: &Path, conditions: Arc<Conditions>) -> anyhow::Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating db directory {}", parent.display()))?;
        }

        let db = Self::open_database(path)?;

        Ok(Self {
            db: RwLock::new(Some(db)),
            path: path.to_path_buf(),
            conditions,
            reopens: AtomicU64::new(0),
            last_reopen: Mutex::new(None),
        })
    }

    /// Open the file and make sure the three tables are there. The same
    /// sequence at start-up and at every reopen, because a handle that has not
    /// been through it is not a handle this store can use.
    fn open_database(path: &Path) -> anyhow::Result<Database> {
        let db = Database::create(path)
            .with_context(|| format!("opening agent db {}", path.display()))?;

        // Create DB if not already existing
        let tx = db.begin_write().context("initializing tables")?;
        tx.open_table(VMS).context("initializing vms table")?;
        tx.open_table(VOLUMES)
            .context("initializing volumes table")?;
        tx.open_table(SNAPSHOTS)
            .context("initializing snapshots table")?;
        tx.commit().context("initializing tables")?;
        Ok(db)
    }

    /// What this node is saying about itself — the set the agent's heartbeat
    /// reads, and the same one every other part of the agent raises into.
    pub fn conditions(&self) -> &Arc<Conditions> {
        &self.conditions
    }

    /// How often this store has had to open itself again since the agent
    /// started.
    pub fn reopens(&self) -> u64 {
        self.reopens.load(Ordering::Relaxed)
    }

    /// One read against the database, reopened once if the handle is poisoned.
    ///
    /// A read that works proves less than a write that works — redb answers
    /// reads out of a page cache — so a successful read clears nothing. It can
    /// still be the operation that NOTICES the poison, and noticing it is what
    /// the reopen is for.
    fn reading<T>(&self, op: impl FnMut(&Database) -> anyhow::Result<T>) -> anyhow::Result<T> {
        self.attempt(false, op)
    }

    /// One write against the database, reopened once if the handle is
    /// poisoned. A write that lands is the proof that this node can serve
    /// commands again, so it is the only thing that clears the conditions.
    fn writing<T>(&self, op: impl FnMut(&Database) -> anyhow::Result<T>) -> anyhow::Result<T> {
        self.attempt(true, op)
    }

    /// The whole of D8's repair.
    ///
    /// redb takes exactly ONE I/O error and then refuses everything with
    /// "Previous I/O error occurred. Please close and re-open the database".
    /// The agent used to do neither: it kept the poisoned handle, every
    /// command after the first failed for as long as the process lived, and
    /// the unit, the session and the heartbeat all went on saying the node was
    /// healthy. So the store reopens itself here, and — because a reopen does
    /// not make room on a full disk — it also SAYS what it found, which is the
    /// half the scheduler one tier up can act on.
    ///
    /// The operation is run again against the fresh handle rather than
    /// reported as failed: it is the same closure over the same borrowed
    /// arguments, and the transaction that failed committed nothing.
    fn attempt<T>(
        &self,
        write: bool,
        mut op: impl FnMut(&Database) -> anyhow::Result<T>,
    ) -> anyhow::Result<T> {
        let failure = match self.once(&mut op) {
            Ok(value) => {
                if write {
                    self.healthy();
                }
                return Ok(value);
            }
            Err(e) if !needs_reopen(&e) => return Err(e),
            Err(e) => e,
        };

        warn!(
            error = %format!("{failure:#}"),
            "the agent database took an i/o error; reopening it"
        );
        if !self.reopen() {
            self.unhealthy(&failure);
            return Err(failure);
        }

        match self.once(&mut op) {
            Ok(value) => {
                info!("the agent database answered again after being reopened");
                if write {
                    self.healthy();
                }
                Ok(value)
            }
            Err(again) => {
                self.unhealthy(&again);
                Err(again)
            }
        }
    }

    /// One run of an operation against whatever handle the store has.
    fn once<T>(&self, op: &mut impl FnMut(&Database) -> anyhow::Result<T>) -> anyhow::Result<T> {
        match &*self.db.read().expect("agent db") {
            Some(db) => op(db),
            None => Err(anyhow::Error::new(Closed)),
        }
    }

    /// Drop the poisoned handle and put a fresh one in its place.
    ///
    /// `false` means no fresh handle is there — either the cooldown says it is
    /// too soon to try again, or the file itself could not be opened, which on
    /// a full disk is exactly what happens. Both leave the old handle in place
    /// and both are the caller's cue to report the failure rather than retry
    /// the operation.
    fn reopen(&self) -> bool {
        {
            let mut last = self.last_reopen.lock().expect("reopen clock");
            if let Some(at) = *last
                && at.elapsed() < REOPEN_COOLDOWN
            {
                return false;
            }
            *last = Some(Instant::now());
        }
        // Held across both halves, so no operation ever runs against the
        // handle that is on its way out and none sees the gap in between.
        let mut slot = self.db.write().expect("agent db");
        // The poisoned handle goes FIRST, and it has to: redb takes an
        // exclusive lock on the file for as long as a `Database` lives, so a
        // second one made beside it would be refused with "database already
        // open" — the reopen would fail for a reason that has nothing to do
        // with the fault it is repairing.
        *slot = None;
        match Self::open_database(&self.path) {
            Ok(fresh) => {
                *slot = Some(fresh);
                let n = self.reopens.fetch_add(1, Ordering::Relaxed) + 1;
                info!(path = %self.path.display(), reopens = n, "agent database reopened");
                true
            }
            Err(e) => {
                warn!(
                    path = %self.path.display(),
                    error = %format!("{e:#}"),
                    "the agent database could not be reopened"
                );
                false
            }
        }
    }

    /// Say what the failure means for this NODE.
    ///
    /// Two conditions and not one, because they are repaired by two different
    /// people: `StoreUnhealthy` is "no command can be served here" and is what
    /// the scheduler has to read, `DiskPressure` is why, and it is what an
    /// operator has to act on. The chaos run produced both at once — the store
    /// was wedged BECAUSE the root disk was full — and reporting only the
    /// first would have sent somebody to the database.
    fn unhealthy(&self, e: &anyhow::Error) {
        if out_of_space(e) {
            self.conditions.raise(
                DISK_PRESSURE,
                format!(
                    "no room left on the filesystem holding {}; this node cannot write its \
                     records or its volumes",
                    self.path.display()
                ),
            );
        }
        self.conditions.raise(
            STORE_UNHEALTHY,
            format!(
                "the agent database at {} is not writable ({e:#}); no command this node is sent \
                 can be recorded",
                self.path.display()
            ),
        );
    }

    /// A write landed, so both statements above have stopped being true.
    fn healthy(&self) {
        self.conditions.clear(STORE_UNHEALTHY);
        self.conditions.clear(DISK_PRESSURE);
    }

    pub fn put(&self, id: &VmId, record: &VmRecord) -> anyhow::Result<()> {
        self.writing(|db| {
            let bytes = serde_json::to_vec(record).context("serializing vm record")?;
            let id_str = id.to_string();

            let tx = db.begin_write().context("begin write")?;
            {
                let mut table = tx.open_table(VMS).context("open vms table")?;
                table
                    .insert(id_str.as_str(), bytes.as_slice())
                    .with_context(|| format!("storing record for vm {id_str}"))?;
            }
            tx.commit().context("commit")?;
            Ok(())
        })
    }

    /// Read, change, write back — inside ONE redb write transaction.
    ///
    /// The reason this exists rather than a get/put pair at the call site:
    /// every interesting caller reads a record, awaits something (a probe of
    /// the VMM's socket, a driver call), and writes back. The record it holds
    /// by then is a snapshot, and stamping the whole thing back drops whatever
    /// landed in between — a Stop from the controller, most of all. redb
    /// serialises write transactions, so a read taken inside one cannot be
    /// stale by the time the same transaction commits.
    ///
    /// `Ok(None)` if the record is gone; the closure is then not called.
    ///
    /// `FnMut` and not `FnOnce` because a transaction that died of an I/O
    /// error is retried against a reopened database (see `attempt`), and the
    /// retry reads the record again before applying this. Nothing is applied
    /// twice to the same record: the first transaction committed nothing.
    pub fn mutate(
        &self,
        id: &VmId,
        mut apply: impl FnMut(&mut VmRecord),
    ) -> anyhow::Result<Option<VmRecord>> {
        self.writing(|db| {
            let id_str = id.to_string();
            let tx = db.begin_write().context("begin write")?;
            let updated = {
                let mut table = tx.open_table(VMS).context("open vms table")?;
                let current = table
                    .get(id_str.as_str())
                    .context("reading record")?
                    .map(|guard| {
                        serde_json::from_slice::<VmRecord>(guard.value())
                            .with_context(|| format!("corrupt record for vm {id_str}"))
                    })
                    .transpose()?;
                match current {
                    None => None,
                    Some(mut record) => {
                        apply(&mut record);
                        let bytes = serde_json::to_vec(&record).context("serializing vm record")?;
                        table
                            .insert(id_str.as_str(), bytes.as_slice())
                            .with_context(|| format!("storing record for vm {id_str}"))?;
                        Some(record)
                    }
                }
            };
            tx.commit().context("commit")?;
            Ok(updated)
        })
    }

    /// One record, or `None` — and a row this build cannot read is `None`.
    ///
    /// The same rule `list` has always followed, stated here as well because
    /// having two of them WAS the defect. `list` skipped a corrupt row and
    /// logged it; `get` returned an error for the very same bytes. So the
    /// node's answer to "do you have this vm" depended on which of the two a
    /// caller happened to hold — a pass over every record walked past it,
    /// while a command about it by id failed with `corrupt record for vm …`,
    /// a sentence that reads like data loss to everyone who does not know
    /// `list_raw` exists.
    ///
    /// **Unknown, not gone.** A row nothing can deserialise describes a vm
    /// this agent cannot manage: it cannot plan for it, report its phase or
    /// tear it down, and every one of those paths already behaves as though
    /// it were absent because `list` hides it. Saying it once, here, is what
    /// makes the readers of this table agree.
    ///
    /// Loud on every read and not once, unlike a condition: `Conditions` is
    /// for what the tier above has to act on, and a record only this node can
    /// see is not that. This is the line somebody greps for with `list_raw`
    /// in their other hand.
    pub fn get(&self, id: &VmId) -> anyhow::Result<Option<VmRecord>> {
        self.reading(|db| {
            let id_str = id.to_string();
            let tx = db.begin_read().context("begin read")?;
            let table = tx.open_table(VMS).context("open vms table")?;

            match table.get(id_str.as_str()).context("reading record")? {
                Some(guard) => match serde_json::from_slice(guard.value()) {
                    Ok(record) => Ok(Some(record)),
                    Err(e) => {
                        error!(vm_id = %id_str, error = %format!("{e:#}"),
                               "corrupt record, treating this vm as unknown; \
                                the bytes are still readable with list_raw");
                        Ok(None)
                    }
                },
                None => Ok(None),
            }
        })
    }

    pub fn list(&self) -> anyhow::Result<Vec<(VmId, VmRecord)>> {
        self.reading(|db| {
            let tx = db.begin_read().context("begin read")?;
            let table = tx.open_table(VMS).context("open vms table")?;

            let mut out = Vec::new();
            for item in table.iter().context("iterating vms table")? {
                let (key, value) = item.context("reading table entry")?;

                let id: VmId = match key.value().parse() {
                    Ok(id) => id,
                    Err(e) => {
                        // excludes corrupt data, for example outdated structs in the db
                        // to debug data use the non-serde list_raw()
                        error!(key = ?key.value(), error = %format!("{e:#}"), "corrupt key, skipping");
                        continue;
                    }
                };

                let record: VmRecord = match serde_json::from_slice(value.value()) {
                    Ok(r) => r,
                    Err(e) => {
                        error!(vm_id = %id, error = %format!("{e:#}"), "corrupt record, skipping");
                        continue;
                    }
                };

                out.push((id, record));
            }
            Ok(out)
        })
    }

    pub fn delete(&self, id: &VmId) -> anyhow::Result<()> {
        self.writing(|db| {
            let id_str = id.to_string();
            let tx = db.begin_write().context("begin write")?;
            {
                let mut table = tx.open_table(VMS).context("open vms table")?;
                table
                    .remove(id_str.as_str())
                    .with_context(|| format!("deleting record for vm {id_str}"))?;
            }
            tx.commit().context("commit")?;
            Ok(())
        })
    }

    // --- volumes ------------------------------------------------------------
    //
    // The same four operations over the second table. Written out rather than
    // made generic over the table and the record type: two tables is not a
    // pattern yet, and the generic version would need a trait whose only
    // purpose is to let two concrete pairs share five lines each.

    pub fn put_volume(&self, id: &VolumeId, record: &VolumeRecord) -> anyhow::Result<()> {
        self.writing(|db| {
            let bytes = serde_json::to_vec(record).context("serializing volume record")?;
            let id_str = id.to_string();
            let tx = db.begin_write().context("begin write")?;
            {
                let mut table = tx.open_table(VOLUMES).context("open volumes table")?;
                table
                    .insert(id_str.as_str(), bytes.as_slice())
                    .with_context(|| format!("storing record for volume {id_str}"))?;
            }
            tx.commit().context("commit")?;
            Ok(())
        })
    }

    /// One volume record, or `None`; a row this build cannot read is `None`.
    /// The rule `get` states at length, one table over.
    pub fn get_volume(&self, id: &VolumeId) -> anyhow::Result<Option<VolumeRecord>> {
        self.reading(|db| {
            let id_str = id.to_string();
            let tx = db.begin_read().context("begin read")?;
            let table = tx.open_table(VOLUMES).context("open volumes table")?;
            match table.get(id_str.as_str()).context("reading record")? {
                Some(guard) => match serde_json::from_slice(guard.value()) {
                    Ok(record) => Ok(Some(record)),
                    Err(e) => {
                        error!(volume_id = %id_str, error = %format!("{e:#}"),
                               "corrupt record, treating this volume as unknown");
                        Ok(None)
                    }
                },
                None => Ok(None),
            }
        })
    }

    /// Every volume record, corrupt ones skipped and logged.
    ///
    /// Skipping is right here and would be wrong for VMs' desired-state
    /// snapshot: a volume this node cannot read is a volume it does not
    /// report, and the tier above reads silence as "does not know" rather
    /// than as "gone". See `StatusReport.volumes`.
    pub fn list_volumes(&self) -> anyhow::Result<Vec<(VolumeId, VolumeRecord)>> {
        self.reading(|db| {
            let tx = db.begin_read().context("begin read")?;
            let table = tx.open_table(VOLUMES).context("open volumes table")?;
            let mut out = Vec::new();
            for item in table.iter().context("iterating volumes table")? {
                let (key, value) = item.context("reading table entry")?;
                let id: VolumeId = match key.value().parse() {
                    Ok(id) => id,
                    Err(e) => {
                        error!(key = ?key.value(), error = %format!("{e:#}"),
                               "corrupt volume key, skipping");
                        continue;
                    }
                };
                match serde_json::from_slice(value.value()) {
                    Ok(record) => out.push((id, record)),
                    Err(e) => {
                        error!(volume_id = %id, error = %format!("{e:#}"),
                               "corrupt volume record, skipping")
                    }
                }
            }
            Ok(out)
        })
    }

    pub fn delete_volume(&self, id: &VolumeId) -> anyhow::Result<()> {
        self.writing(|db| {
            let id_str = id.to_string();
            let tx = db.begin_write().context("begin write")?;
            {
                let mut table = tx.open_table(VOLUMES).context("open volumes table")?;
                table
                    .remove(id_str.as_str())
                    .with_context(|| format!("deleting record for volume {id_str}"))?;
            }
            tx.commit().context("commit")?;
            Ok(())
        })
    }

    // --- snapshots ----------------------------------------------------------
    //
    // The same four again. Still not a pattern worth a trait: what the third
    // table would share with the other two is five lines each, and what it
    // would cost is a trait whose only purpose is to let three concrete pairs
    // share them.

    pub fn put_snapshot(&self, id: &SnapshotId, record: &SnapshotRecord) -> anyhow::Result<()> {
        self.writing(|db| {
            let bytes = serde_json::to_vec(record).context("serializing snapshot record")?;
            let id_str = id.to_string();
            let tx = db.begin_write().context("begin write")?;
            {
                let mut table = tx.open_table(SNAPSHOTS).context("open snapshots table")?;
                table
                    .insert(id_str.as_str(), bytes.as_slice())
                    .with_context(|| format!("storing record for snapshot {id_str}"))?;
            }
            tx.commit().context("commit")?;
            Ok(())
        })
    }

    /// One snapshot record, or `None`; a row this build cannot read is
    /// `None`. The rule `get` states at length, two tables over.
    pub fn get_snapshot(&self, id: &SnapshotId) -> anyhow::Result<Option<SnapshotRecord>> {
        self.reading(|db| {
            let id_str = id.to_string();
            let tx = db.begin_read().context("begin read")?;
            let table = tx.open_table(SNAPSHOTS).context("open snapshots table")?;
            match table.get(id_str.as_str()).context("reading record")? {
                Some(guard) => match serde_json::from_slice(guard.value()) {
                    Ok(record) => Ok(Some(record)),
                    Err(e) => {
                        error!(snapshot_id = %id_str, error = %format!("{e:#}"),
                               "corrupt record, treating this snapshot as unknown");
                        Ok(None)
                    }
                },
                None => Ok(None),
            }
        })
    }

    /// Every snapshot record, corrupt ones skipped and logged — the same rule
    /// `list_volumes` follows and for the same reason: silence up there is
    /// "does not know", never "gone".
    pub fn list_snapshots(&self) -> anyhow::Result<Vec<(SnapshotId, SnapshotRecord)>> {
        self.reading(|db| {
            let tx = db.begin_read().context("begin read")?;
            let table = tx.open_table(SNAPSHOTS).context("open snapshots table")?;
            let mut out = Vec::new();
            for item in table.iter().context("iterating snapshots table")? {
                let (key, value) = item.context("reading table entry")?;
                let id: SnapshotId = match key.value().parse() {
                    Ok(id) => id,
                    Err(e) => {
                        error!(key = ?key.value(), error = %format!("{e:#}"),
                               "corrupt snapshot key, skipping");
                        continue;
                    }
                };
                match serde_json::from_slice(value.value()) {
                    Ok(record) => out.push((id, record)),
                    Err(e) => {
                        error!(snapshot_id = %id, error = %format!("{e:#}"),
                               "corrupt snapshot record, skipping")
                    }
                }
            }
            Ok(out)
        })
    }

    pub fn delete_snapshot(&self, id: &SnapshotId) -> anyhow::Result<()> {
        self.writing(|db| {
            let id_str = id.to_string();
            let tx = db.begin_write().context("begin write")?;
            {
                let mut table = tx.open_table(SNAPSHOTS).context("open snapshots table")?;
                table
                    .remove(id_str.as_str())
                    .with_context(|| format!("deleting record for snapshot {id_str}"))?;
            }
            tx.commit().context("commit")?;
            Ok(())
        })
    }

    pub fn get_raw(&self, id: &VmId) -> anyhow::Result<Option<Vec<u8>>> {
        self.reading(|db| {
            let id_str = id.to_string();
            let tx = db.begin_read().context("begin read")?;
            let table = tx.open_table(VMS).context("open vms table")?;
            Ok(table
                .get(id_str.as_str())
                .context("reading record")?
                .map(|g| g.value().to_vec()))
        })
    }

    pub fn list_raw(&self) -> anyhow::Result<Vec<(String, Vec<u8>)>> {
        self.reading(|db| {
            let tx = db.begin_read().context("begin read")?;
            let table = tx.open_table(VMS).context("open vms table")?;
            let mut out = Vec::new();
            for item in table.iter().context("iterating vms table")? {
                let (key, value) = item.context("reading table entry")?;
                out.push((key.value().to_string(), value.value().to_vec()));
            }
            Ok(out)
        })
    }

    /// A row exactly as given, without asking whether it is a record.
    ///
    /// Tests only, and one kind of test: the ones about what this node does
    /// with a row it cannot read. `put` serialises a `VmRecord`, so through
    /// it only rows that read back can ever be written — and the behaviour
    /// that matters (the overlay reference count counts an unreadable row as
    /// a user rather than passing over it) is unreachable from there.
    #[cfg(test)]
    pub(crate) fn put_raw(&self, key: &str, bytes: &[u8]) -> anyhow::Result<()> {
        self.writing(|db| {
            let tx = db.begin_write().context("begin write")?;
            {
                let mut table = tx.open_table(VMS).context("open vms table")?;
                table
                    .insert(key, bytes)
                    .with_context(|| format!("storing raw row {key}"))?;
            }
            tx.commit().context("commit")?;
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A database file in a directory of this test's own.
    ///
    /// The guard comes back with the path and the caller binds it. The name
    /// used to be built from the pid and the thread id, which is unique for
    /// as long as the process runs and not one moment longer: a pid comes
    /// back, and a run that panicked left its database for whoever got it.
    fn tmp(name: &str) -> (tempfile::TempDir, PathBuf) {
        let temp = tempfile::Builder::new()
            .prefix(&format!("meister-store-{name}-"))
            .tempdir()
            .expect("a temp dir");
        let path = temp.path().join("agent.redb");
        (temp, path)
    }

    /// One I/O error is not the end of the agent.
    ///
    /// The defect this is here for: redb refuses everything after a single
    /// I/O error until the database is closed and opened again, the agent
    /// never did it, and every command on that node failed for twenty hours
    /// while the unit, the session and the heartbeat all said "healthy". The
    /// fake operation here IS that shape — it fails once with `Io` and then
    /// works — and what the store has to do with it is try again on a fresh
    /// handle rather than hand the error up.
    #[test]
    fn an_io_error_reopens_the_database_and_the_operation_runs_again() {
        let (_temp, path) = tmp("reopen");
        let store = Store::open(&path).expect("a store");
        assert_eq!(store.reopens(), 0, "nothing has gone wrong yet");

        let calls = std::cell::Cell::new(0);
        let value = store
            .writing(|_| {
                calls.set(calls.get() + 1);
                match calls.get() {
                    1 => Err(anyhow::Error::new(redb::TransactionError::Storage(
                        redb::StorageError::Io(std::io::Error::from(
                            std::io::ErrorKind::StorageFull,
                        )),
                    ))
                    .context("begin write")),
                    _ => Ok("the record"),
                }
            })
            .expect("the second attempt lands");

        assert_eq!(value, "the record");
        assert_eq!(calls.get(), 2, "the operation was run again, not reported");
        assert_eq!(store.reopens(), 1, "on a handle that was opened again");
        // A write that landed is the proof the node can serve commands, so
        // nothing is left standing on the heartbeat.
        assert!(store.conditions().report().is_empty());

        // And the store still works: the fresh handle has the tables.
        let id = VmId::new_v4();
        assert!(store.get(&id).expect("a read").is_none());
    }

    /// `PreviousIo` — the poison flag itself, which is the error every command
    /// after the first one gets — takes the same road as the `Io` that set it.
    /// Everything else on redb's enums does not: a corrupt page is not
    /// repaired by opening the file again, and retrying it would be a loop.
    #[test]
    fn only_the_two_errors_a_reopen_repairs_cause_one() {
        let io = anyhow::Error::new(redb::StorageError::Io(std::io::Error::from(
            std::io::ErrorKind::StorageFull,
        )))
        .context("commit");
        assert!(needs_reopen(&io));
        assert!(out_of_space(&io), "and it says which disk fault it was");

        let previous = anyhow::Error::new(redb::TransactionError::Storage(
            redb::StorageError::PreviousIo,
        ))
        .context("begin write");
        assert!(needs_reopen(&previous));
        assert!(
            !out_of_space(&previous),
            "the poison flag carries no errno; only the next real attempt does"
        );

        let corrupt = anyhow::Error::new(redb::StorageError::Corrupted("page 7".into()));
        assert!(!needs_reopen(&corrupt));

        let unrelated = anyhow::anyhow!("serializing vm record");
        assert!(!needs_reopen(&unrelated));
    }

    /// A fault that outlives the reopen is what the heartbeat has to carry.
    ///
    /// This is the other half of D8, and the half `node ls` was missing: the
    /// store cannot make room on a full disk, so after it has done what it
    /// can it SAYS what is wrong — `StoreUnhealthy` for the scheduler, which
    /// must stop placing here, and `DiskPressure` for the operator, who has
    /// to go and delete something.
    #[test]
    fn a_fault_that_survives_the_reopen_is_reported_to_the_cluster() {
        let (_temp, path) = tmp("wedged");
        let store = Store::open(&path).expect("a store");
        let full = || {
            Err(
                anyhow::Error::new(redb::TransactionError::Storage(redb::StorageError::Io(
                    std::io::Error::from(std::io::ErrorKind::StorageFull),
                )))
                .context("begin write"),
            )
        };

        let failed = store.writing(|_| full() as anyhow::Result<()>);
        assert!(failed.is_err(), "a full disk is still a failed write");
        assert_eq!(store.reopens(), 1, "and the reopen was tried once");

        let said: Vec<String> = store
            .conditions()
            .report()
            .into_iter()
            .map(|c| c.r#type)
            .collect();
        assert_eq!(said, vec!["DiskPressure", "StoreUnhealthy"]);
        let sentence = store
            .conditions()
            .message(STORE_UNHEALTHY)
            .expect("a sentence");
        assert!(
            sentence.contains("agent.redb"),
            "the sentence names the file: {sentence}"
        );

        // The cooldown: the next failure in the same window does not open the
        // file all over again. A wedged node produced 180 of these in five
        // minutes, and 180 reopens would have been the outage's own load.
        let _ = store.writing(|_| full() as anyhow::Result<()>);
        assert_eq!(store.reopens(), 1, "still one, the cooldown holds");

        // And the moment a write lands, both statements stop being made.
        store
            .delete(&VmId::new_v4())
            .expect("a write on a working disk");
        assert!(store.conditions().report().is_empty());
    }

    /// One rule for a row nothing can read, whichever way it is asked for.
    ///
    /// The defect: `list` skipped a corrupt record and logged it, `get`
    /// returned `corrupt record for vm …`. Two readers of one table with two
    /// answers, so what the node said about a broken row depended on which
    /// call happened to reach it — and `get` is the one every command goes
    /// through, so the sentence an operator saw was the one that reads like
    /// data loss.
    ///
    /// The bytes are untouched either way: `list_raw` still hands them over,
    /// which is what makes "unknown" honest rather than a deletion.
    #[test]
    fn a_record_nothing_can_read_is_unknown_to_every_reader() {
        let (_temp, path) = tmp("corrupt");
        let store = Store::open(&path).expect("a store");

        let broken = VmId::new_v4();
        let intact = VmId::new_v4();
        store
            .put_raw(&broken.to_string(), b"{\"spec\":\"this is not a record\"}")
            .expect("a raw row");
        store
            .put(&intact, &crate::types::VmRecord::blank())
            .expect("a record beside it");

        assert!(
            store.get(&broken).expect("a read, not an error").is_none(),
            "a row this build cannot read is a vm this node does not know"
        );
        let listed: Vec<VmId> = store
            .list()
            .expect("a list")
            .into_iter()
            .map(|r| r.0)
            .collect();
        assert_eq!(listed, vec![intact], "which is what `list` always said");

        // The intact record beside it is untouched: one bad row is not a
        // table this node has stopped reading.
        assert!(store.get(&intact).expect("a read").is_some());

        // And nothing was thrown away. This is the difference between
        // "unknown" and "gone", and it is the whole reason the first may be
        // said at all.
        let raw = store
            .get_raw(&broken)
            .expect("the bytes")
            .expect("still there");
        assert_eq!(raw, b"{\"spec\":\"this is not a record\"}");
    }
}
