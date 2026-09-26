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

// Permanent command receipts also fence delayed commands after VM cleanup.
const MIGRATIONS: TableDefinition<&str, bool> = TableDefinition::new("migration_attempts");

/// Volume records are independent of VM records and may outlive consumers.
const VOLUMES: TableDefinition<&str, &[u8]> = TableDefinition::new("volumes");

/// Snapshot records are independent of their source volume records.
const SNAPSHOTS: TableDefinition<&str, &[u8]> = TableDefinition::new("snapshots");

/// Minimum interval between database reopen attempts.
const REOPEN_COOLDOWN: Duration = Duration::from_secs(2);

/// Retry after reopening for redb I/O errors or a previously failed reopen.
/// Data corruption and unrelated errors do not trigger recovery.
fn needs_reopen(e: &anyhow::Error) -> bool {
    // A failed reopen leaves the store closed until a later attempt succeeds.
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

/// Find typed redb storage errors through their public wrappers.
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

/// A previous reopen dropped the database handle and could not replace it.
#[derive(Debug)]
struct Closed;

impl std::fmt::Display for Closed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("the agent database is closed after an i/o error")
    }
}

impl std::error::Error for Closed {}

/// A VM row for admission and deletion guards, retaining undecodable rows as
/// explicitly present. `get` and `list` omit those rows and cannot establish
/// that a resource has no consumer.
pub enum VmRow {
    /// A decoded record and its parsed VM ID. Boxed to limit enum size.
    Record(VmId, Box<VmRecord>),
    /// A present row with an invalid key or undecodable value; retain its raw key.
    Unreadable(String),
}

pub struct Store {
    /// The lock excludes operations while reopening. `None` means the previous
    /// handle was dropped and a replacement could not be opened.
    db: RwLock<Option<Database>>,
    /// Database path used for reopen attempts.
    path: PathBuf,
    /// Shared conditions updated on database I/O failure and write recovery.
    conditions: Arc<Conditions>,
    /// Number of successful reopens since startup.
    reopens: AtomicU64,
    /// When the last reopen was ATTEMPTED, successful or not. See
    /// `REOPEN_COOLDOWN`.
    last_reopen: Mutex<Option<Instant>>,
}

impl Store {
    /// Open with a private condition set for tests and standalone callers.
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

    /// Open the database and initialize the VM, migration, volume and snapshot tables.
    fn open_database(path: &Path) -> anyhow::Result<Database> {
        let db = Database::create(path)
            .with_context(|| format!("opening agent db {}", path.display()))?;
        // Restrict specs and resource paths to the agent owner, independently of umask.
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
                .with_context(|| format!("closing agent db {} to the owner", path.display()))?;
        }

        // Create DB if not already existing
        let tx = db.begin_write().context("initializing tables")?;
        tx.open_table(VMS).context("initializing vms table")?;
        tx.open_table(MIGRATIONS)
            .context("initializing migration receipts")?;
        tx.open_table(VOLUMES)
            .context("initializing volumes table")?;
        tx.open_table(SNAPSHOTS)
            .context("initializing snapshots table")?;
        tx.commit().context("initializing tables")?;
        Ok(db)
    }

    /// Shared node conditions used by operations and heartbeat reporting.
    pub fn conditions(&self) -> &Arc<Conditions> {
        &self.conditions
    }

    /// How often this store has had to open itself again since the agent
    /// started.
    pub fn reopens(&self) -> u64 {
        self.reopens.load(Ordering::Relaxed)
    }

    /// Retry a poisoned database read after reopening once. Successful reads
    /// may use cached pages, so they do not clear a write-failure condition.
    fn reading<T>(&self, op: impl FnMut(&Database) -> anyhow::Result<T>) -> anyhow::Result<T> {
        self.attempt(false, op)
    }

    /// One write against the database, reopened once if the handle is
    /// poisoned. A write that lands is the proof that this node can serve
    /// commands again, so it is the only thing that clears the conditions.
    fn writing<T>(&self, op: impl FnMut(&Database) -> anyhow::Result<T>) -> anyhow::Result<T> {
        self.attempt(true, op)
    }

    /// Retry once after reopening a database with an I/O error. Failed recovery
    /// raises node conditions; only a successful write clears them. Operations
    /// passed here must tolerate retry against the reopened state.
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

    /// Attempt to replace the database handle, subject to the cooldown.
    /// A cooldown refusal preserves the current slot; an open failure leaves it empty.
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
        // Hold the write lock through replacement so operations cannot use the old handle or a gap.
        let mut slot = self.db.write().expect("agent db");
        // Drop the old handle before reopening: redb holds an exclusive file lock.
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

    /// Raise StoreUnhealthy and, when the error carries ENOSPC, DiskPressure.
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

    /// Claim once, or cancel even before prepare arrives. Receipts outlive VM rows.
    pub fn claim_migration(&self, id: &VmId, attempt: &str, cancel: bool) -> anyhow::Result<bool> {
        anyhow::ensure!(
            !attempt.is_empty(),
            "migration requires an operation identity"
        );
        self.writing(|db| {
            let key = format!("{id}/{attempt}");
            let tx = db.begin_write()?;
            let fresh;
            {
                let mut table = tx.open_table(MIGRATIONS)?;
                fresh = table.get(key.as_str())?.is_none();
                if fresh || cancel {
                    table.insert(key.as_str(), cancel)?;
                }
            }
            tx.commit()?;
            Ok(fresh)
        })
    }

    /// Read, modify and commit within one write transaction to preserve changes
    /// made since an earlier observation. Return `None` without calling `apply`
    /// when absent. The closure may run again after an I/O recovery.
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

    /// Return a decoded record or `None` for an absent or undecodable row.
    /// Undecodable bytes remain stored and are logged. Admission and destructive
    /// guards must use `row` or `rows`, which preserve evidence of unreadable rows.
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

    /// Read a VM row while preserving an undecodable value as `VmRow::Unreadable`.
    pub fn row(&self, id: &VmId) -> anyhow::Result<Option<VmRow>> {
        let id_str = id.to_string();
        Ok(self
            .get_raw(id)?
            .map(|bytes| match serde_json::from_slice::<VmRecord>(&bytes) {
                Ok(record) => VmRow::Record(*id, Box::new(record)),
                Err(e) => {
                    error!(vm_id = %id_str, error = %format!("{e:#}"),
                           "corrupt record; this vm counts as present, not as absent");
                    VmRow::Unreadable(id_str.clone())
                }
            }))
    }

    /// Read all VM rows, retaining invalid keys and undecodable values.
    pub fn rows(&self) -> anyhow::Result<Vec<VmRow>> {
        Ok(self
            .list_raw()?
            .into_iter()
            .map(|(key, bytes)| {
                let decoded = key
                    .parse::<VmId>()
                    .map_err(|e| format!("{e:#}"))
                    .and_then(|id| {
                        serde_json::from_slice::<VmRecord>(&bytes)
                            .map(|record| VmRow::Record(id, Box::new(record)))
                            .map_err(|e| format!("{e:#}"))
                    });
                match decoded {
                    Ok(row) => row,
                    Err(e) => {
                        error!(key = %key, error = %e,
                               "corrupt row; it counts as present, not as absent");
                        VmRow::Unreadable(key)
                    }
                }
            })
            .collect())
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

    // Volume records.

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

    /// List decoded volume records; log and omit unreadable rows.
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

    // Snapshot records.

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

    /// List decoded snapshot records; log and omit unreadable rows.
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

    /// Insert raw bytes for tests of malformed or incompatible persisted rows.
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

    /// Isolate each test database in a temporary directory.
    fn tmp(name: &str) -> (tempfile::TempDir, PathBuf) {
        let temp = tempfile::Builder::new()
            .prefix(&format!("meister-store-{name}-"))
            .tempdir()
            .expect("a temp dir");
        let path = temp.path().join("agent.redb");
        (temp, path)
    }

    /// The store remains owner-only even when backend users share the run directory.
    #[test]
    fn the_store_file_belongs_to_the_owner_alone() {
        use std::os::unix::fs::PermissionsExt;
        let (_temp, path) = tmp("mode");
        let _store = Store::open(&path).expect("a store");
        let mode = std::fs::metadata(&path)
            .expect("the file")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "agent.redb is {mode:o}, not owner-only");
    }

    /// A simulated I/O error reopens the database and retries the operation.
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

    /// Only Io and PreviousIo trigger reopening; reopening cannot repair page corruption.
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

    /// Persistent I/O failure raises conditions and respects the reopen cooldown.
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

        // Repeated failures inside the cooldown must not trigger more database reopens.
        let _ = store.writing(|_| full() as anyhow::Result<()>);
        assert_eq!(store.reopens(), 1, "still one, the cooldown holds");

        // And the moment a write lands, both statements stop being made.
        store
            .delete(&VmId::new_v4())
            .expect("a write on a working disk");
        assert!(store.conditions().report().is_empty());
    }

    /// Decoded readers omit corrupt VM rows while raw reads preserve their bytes.
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

        // Unreadable rows remain intact for later recovery.
        let raw = store
            .get_raw(&broken)
            .expect("the bytes")
            .expect("still there");
        assert_eq!(raw, b"{\"spec\":\"this is not a record\"}");
    }
}
