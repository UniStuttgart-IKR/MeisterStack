// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Manage volumes and snapshots independently of VM lifetime. Storage routing
//! uses the same registry as inline VM disks. Destructive volume operations
//! check persisted VM attachments under the local operations lock; cross-node
//! coordination remains the controller's responsibility.

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use agent_api::storage::{SnapshotId, StorageError, VolumeId, VolumeSpec};
use anyhow::{Context, anyhow, bail};
use tracing::{debug, error, info, instrument, warn};

use crate::drivers::Drivers;
use crate::provision::timed_driver;
use crate::reconcile::{SnapshotReason, VolumeReason};
use crate::store::Store;
use crate::types::{SnapshotRecord, SnapshotRecordPhase, VolumeRecord, VolumeRecordPhase};

/// Report no reason for Ready; use Unrecorded for legacy non-Ready rows.
fn reported_reason(record: &VolumeRecord) -> Option<VolumeReason> {
    match record.phase {
        VolumeRecordPhase::Ready => None,
        _ => record.reason.or(Some(VolumeReason::Unrecorded)),
    }
}

/// The word that goes out beside a snapshot's phase. The volume rule
/// (`reported_reason`), said once more for the other table: `Ready` needs
/// none, and a record from a build before the field may not go out mute.
fn reported_snapshot_reason(record: &SnapshotRecord) -> Option<SnapshotReason> {
    match record.phase {
        SnapshotRecordPhase::Ready => None,
        _ => record.reason.or(Some(SnapshotReason::Unrecorded)),
    }
}

/// Retention for explicit deletion evidence. A later delete of an unknown ID
/// creates another tombstone if the controller still needs acknowledgement.
const TOMBSTONE_TTL: Duration = Duration::from_secs(3600);

/// Volume ownership refusal, distinct from a driver failure for dispatch and logging.
#[derive(Debug)]
pub struct HeldByVm {
    pub volume: VolumeId,
    pub vm: agent_api::VmId,
}

impl std::fmt::Display for HeldByVm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "held by vm {}", self.vm)
    }
}

impl std::error::Error for HeldByVm {}

/// Deletion is blocked by a VM row whose contents cannot be checked for holders.
#[derive(Debug)]
pub struct HeldByUnreadable {
    pub volume: VolumeId,
    /// The key of the row, verbatim. See `store::VmRow::Unreadable`.
    pub key: String,
}

impl std::fmt::Display for HeldByUnreadable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "this node has an unreadable record of vm {}, which may be holding this volume",
            self.key
        )
    }
}

impl std::error::Error for HeldByUnreadable {}

/// A known or possible local consumer that blocks deletion.
enum Holder {
    Vm(agent_api::VmId),
    Unreadable(String),
}

impl Holder {
    /// The refusal this holder is, about `volume`.
    fn refusal(self, volume: VolumeId) -> anyhow::Error {
        match self {
            Holder::Vm(vm) => HeldByVm { volume, vm }.into(),
            Holder::Unreadable(key) => HeldByUnreadable { volume, key }.into(),
        }
    }

    /// What goes in the log line beside the refusal.
    fn said(&self) -> String {
        match self {
            Holder::Vm(vm) => vm.to_string(),
            Holder::Unreadable(key) => format!("{key} (unreadable record)"),
        }
    }
}

/// Independent volume and snapshot operations using the agent store and drivers.
pub struct Volumes {
    store: Arc<Store>,
    drivers: Drivers,
    ops: Arc<tokio::sync::Mutex<()>>,
}

impl Volumes {
    pub fn new(store: Arc<Store>, drivers: Drivers, ops: Arc<tokio::sync::Mutex<()>>) -> Self {
        Self {
            store,
            drivers,
            ops,
        }
    }

    /// Provision from a stored snapshot handle. Persist intent before calling the
    /// provider; an existing volume handle makes a repeated request a no-op.
    #[instrument(skip_all, fields(volume_id = %id, snapshot_id = %snapshot, driver, backend))]
    pub async fn provision_from(
        &self,
        id: VolumeId,
        snapshot: SnapshotId,
        spec: VolumeSpec,
    ) -> anyhow::Result<()> {
        if let Some(existing) = self.store.get_volume(&id)?
            && existing.handle.is_some()
        {
            debug!(backend = %existing.backend(), "volume already provisioned");
            return Ok(());
        }
        // Resolve the snapshot before writing a volume record. A missing source
        // must fail creation rather than fall back to an empty disk.
        let from = self
            .snapshot_handle(&snapshot)?
            .ok_or_else(|| anyhow!("this node has no snapshot {snapshot} to make a volume from"))?;
        let driver_name = spec
            .driver
            .clone()
            .unwrap_or_else(agent_api::storage::default_volume_driver);
        tracing::Span::current().record("driver", driver_name.as_str());
        let driver = self.driver(&driver_name)?;
        self.write(
            id,
            VolumeRecord {
                spec: spec.clone(),
                handle: None,
                phase: VolumeRecordPhase::Provisioning,
                reason: Some(VolumeReason::Working),
                message: None,
                gone_at: None,
            },
        )?;
        match timed_driver(
            &driver_name,
            "provision_from",
            driver.provision_from(&id, &from, &spec),
        )
        .await
        {
            Ok(handle) => {
                tracing::Span::current().record("backend", handle.backend.as_str());
                info!(backend = %handle.backend, size_bytes = handle.size_bytes,
                      "volume provisioned from a snapshot");
                self.write(
                    id,
                    VolumeRecord {
                        spec,
                        handle: Some(handle),
                        phase: VolumeRecordPhase::Ready,
                        reason: None,
                        message: None,
                        gone_at: None,
                    },
                )
            }
            Err(e) => {
                let message = format!("{e:#}");
                warn!(error = %message, "volume provision from snapshot failed");
                self.write(
                    id,
                    VolumeRecord {
                        spec,
                        handle: None,
                        phase: VolumeRecordPhase::Failed,
                        reason: Some(VolumeReason::DriverRefused),
                        message: Some(message),
                        gone_at: None,
                    },
                )?;
                Err(e).context("provisioning volume from a snapshot")
            }
        }
    }

    #[instrument(skip_all, fields(volume_id = %id, driver, backend))]
    pub async fn provision(&self, id: VolumeId, spec: VolumeSpec) -> anyhow::Result<()> {
        let driver_name = spec
            .driver
            .clone()
            .unwrap_or_else(agent_api::storage::default_volume_driver);
        tracing::Span::current().record("driver", driver_name.as_str());

        if let Some(existing) = self.store.get_volume(&id)?
            && let Some(handle) = &existing.handle
        {
            // A committed handle makes repeated provisioning idempotent without probing the backend.
            debug!(backend = %handle.backend, "volume already provisioned");
            if existing.phase != VolumeRecordPhase::Ready {
                self.write(
                    id,
                    VolumeRecord {
                        phase: VolumeRecordPhase::Ready,
                        // Clear stale failure details when returning to Ready.
                        reason: None,
                        message: None,
                        ..existing
                    },
                )?;
            }
            return Ok(());
        }

        let driver = self
            .drivers
            .storage
            .get(&driver_name)
            .cloned()
            .ok_or_else(|| {
                anyhow!("volume driver {driver_name:?} is not configured on this node")
            })?;

        // Persist intent before calling the driver so interrupted creation can retry with the same ID.
        self.write(
            id,
            VolumeRecord {
                spec: spec.clone(),
                handle: None,
                phase: VolumeRecordPhase::Provisioning,
                reason: Some(VolumeReason::Working),
                message: None,
                gone_at: None,
            },
        )?;

        match timed_driver(&driver_name, "provision", driver.provision(&id, &spec)).await {
            Ok(handle) => {
                tracing::Span::current().record("backend", handle.backend.as_str());
                info!(backend = %handle.backend, size_bytes = handle.size_bytes,
                      "volume provisioned");
                self.write(
                    id,
                    VolumeRecord {
                        spec,
                        handle: Some(handle),
                        phase: VolumeRecordPhase::Ready,
                        reason: None,
                        message: None,
                        gone_at: None,
                    },
                )
            }
            Err(e) => {
                let message = format!("{e:#}");
                warn!(error = %message, "volume provision failed");
                // Persist the failure for status reports and return it to the command caller.
                self.write(
                    id,
                    VolumeRecord {
                        spec,
                        handle: None,
                        phase: VolumeRecordPhase::Failed,
                        reason: Some(VolumeReason::DriverRefused),
                        message: Some(message),
                        gone_at: None,
                    },
                )?;
                Err(e).context("provisioning volume")
            }
        }
    }

    /// Delete volume data unless a VM holds it. Unknown IDs also receive a Gone
    /// tombstone so repeated deletion has an explicit acknowledgement.
    #[instrument(skip_all, fields(volume_id = %id))]
    pub async fn deprovision(&self, id: VolumeId) -> anyhow::Result<()> {
        // Hold the VM operations lock through the holder check and backend call.
        // A local create must not attach after the check but before deletion.
        let _guard = self.ops.lock().await;
        if let Some(holder) = self.holder(&id)? {
            // Persisted VM ownership blocks destructive volume cleanup.
            warn!(vm = %holder.said(), "refusing to deprovision a volume a vm is holding");
            return Err(holder.refusal(id));
        }

        let Some(record) = self.store.get_volume(&id)? else {
            debug!("no record; answering Gone, which is the same outcome");
            return self.tombstone(id, None, None);
        };
        if record.phase == VolumeRecordPhase::Gone {
            return Ok(());
        }

        let driver_name = record
            .spec
            .driver
            .clone()
            .unwrap_or_else(agent_api::storage::default_volume_driver);
        let driver = self
            .drivers
            .storage
            .get(&driver_name)
            .cloned()
            .ok_or_else(|| {
                anyhow!("volume driver {driver_name:?} is not configured on this node")
            })?;

        // A crash can leave backend data without a persisted handle. Probe before
        // publishing Gone; a failed probe retains the record for retry.
        let handle = match record.handle.clone() {
            Some(handle) => handle,
            None => {
                let found = timed_driver(&driver_name, "probe", driver.probe(&id, &record.spec))
                    .await
                    .with_context(|| {
                        format!("asking {driver_name} what it holds for volume {id}")
                    })?;
                match found {
                    Some(found) => {
                        warn!(backend = %found.backend,
                              "a record with no handle, and the backend has the bytes after all");
                        found
                    }
                    None => {
                        debug!("no handle, and the backend holds nothing under this id");
                        return self.tombstone(id, Some(record.spec), None);
                    }
                }
            }
        };
        timed_driver(&driver_name, "deprovision", driver.deprovision(&handle))
            .await
            .with_context(|| format!("deprovisioning volume {id} via {driver_name}"))?;
        info!(backend = %handle.backend, "volume deprovisioned");
        self.tombstone(id, Some(record.spec), None)
    }

    /// Forget local ownership without deleting data or emitting Gone. Refuse while
    /// a local VM may hold the volume. Provider forget errors are logged, but the
    /// local volume row is removed even when that cleanup fails.
    #[instrument(skip_all, fields(volume_id = %id))]
    pub async fn forget(&self, id: VolumeId) -> anyhow::Result<()> {
        let _guard = self.ops.lock().await;
        if let Some(holder) = self.holder(&id)? {
            warn!(vm = %holder.said(),
                  "refusing to forget a volume a vm on this node is holding");
            return Err(holder.refusal(id));
        }
        let Some(record) = self.store.get_volume(&id)? else {
            debug!("no record; this node had already forgotten it");
            return Ok(());
        };
        if let Some(handle) = record.handle.clone() {
            let driver_name = record
                .spec
                .driver
                .clone()
                .unwrap_or_else(agent_api::storage::default_volume_driver);
            match self.drivers.storage.get(&driver_name) {
                Some(driver) => {
                    if let Err(e) =
                        timed_driver(&driver_name, "forget", driver.forget(&handle)).await
                    {
                        warn!(backend = %handle.backend, driver = %driver_name,
                              error = %format!("{e:#}"),
                              "the backend would not let go of this volume; the record goes anyway");
                    }
                }
                // A driver this node no longer configures. Nothing here can
                // ask it anything, and the record still has to go.
                None => warn!(driver = %driver_name,
                              "the volume's driver is not configured here; forgetting the record only"),
            }
        }
        self.store.delete_volume(&id)?;
        info!(backend = %record.backend(), "volume forgotten; its data is untouched");
        Ok(())
    }

    /// Create a snapshot under its stable ID, persisting intent first. This method
    /// does not pause writers or hold the VM operations lock; the controller must
    /// coordinate consistency across consumers before requesting the copy.
    #[instrument(skip_all, fields(volume_id = %volume, snapshot_id = %id, driver, backend))]
    pub async fn snapshot(&self, id: SnapshotId, volume: VolumeId) -> anyhow::Result<()> {
        if let Some(existing) = self.store.get_snapshot(&id)?
            && existing.handle.is_some()
        {
            debug!(backend = %existing.backend(), "snapshot already taken");
            if existing.phase != SnapshotRecordPhase::Ready {
                self.store.put_snapshot(
                    &id,
                    &SnapshotRecord {
                        phase: SnapshotRecordPhase::Ready,
                        // Clear stale snapshot failure details when returning to Ready.
                        reason: None,
                        message: None,
                        ..existing
                    },
                )?;
            }
            return Ok(());
        }
        let record = self
            .store
            .get_volume(&volume)?
            .ok_or_else(|| anyhow!("this node has no record of volume {volume}"))?;
        let handle = record
            .handle
            .clone()
            .ok_or_else(|| anyhow!("volume {volume} is known here but has not been provisioned"))?;
        let driver_name = record
            .spec
            .driver
            .clone()
            .unwrap_or_else(agent_api::storage::default_volume_driver);
        tracing::Span::current().record("driver", driver_name.as_str());
        let driver = self.driver(&driver_name)?;

        // Persist snapshot intent before the driver call so interrupted creation can retry.
        let pending = SnapshotRecord {
            volume,
            handle: None,
            driver: driver_name.clone(),
            phase: SnapshotRecordPhase::Creating,
            reason: Some(SnapshotReason::Working),
            message: None,
            gone_at: None,
        };
        self.store.put_snapshot(&id, &pending)?;

        match timed_driver(&driver_name, "snapshot", driver.snapshot(&handle, &id)).await {
            Ok(taken) => {
                tracing::Span::current().record("backend", taken.backend.as_str());
                info!(backend = %taken.backend, size_bytes = taken.size_bytes, "snapshot taken");
                self.store.put_snapshot(
                    &id,
                    &SnapshotRecord {
                        handle: Some(taken),
                        phase: SnapshotRecordPhase::Ready,
                        reason: None,
                        ..pending
                    },
                )
            }
            Err(e) => {
                let message = format!("{e:#}");
                warn!(error = %message, "snapshot failed");
                self.store.put_snapshot(
                    &id,
                    &SnapshotRecord {
                        phase: SnapshotRecordPhase::Failed,
                        reason: Some(SnapshotReason::DriverRefused),
                        message: Some(message),
                        ..pending
                    },
                )?;
                Err(e).context("taking snapshot")
            }
        }
    }

    /// Resize through the provider and persist the returned size, which may exceed
    /// the request due to backend allocation granularity.
    #[instrument(skip_all, fields(volume_id = %id, size_bytes))]
    pub async fn resize(&self, id: VolumeId, size_bytes: u64) -> anyhow::Result<()> {
        let record = self
            .store
            .get_volume(&id)?
            .ok_or_else(|| anyhow!("this node has no record of volume {id}"))?;
        let handle = record
            .handle
            .clone()
            .ok_or_else(|| anyhow!("volume {id} is known here but has not been provisioned"))?;
        let driver_name = record
            .spec
            .driver
            .clone()
            .unwrap_or_else(agent_api::storage::default_volume_driver);
        let driver = self.driver(&driver_name)?;
        let grown = timed_driver(&driver_name, "resize", driver.resize(&handle, size_bytes))
            .await
            .with_context(|| format!("resizing volume {id} via {driver_name}"))?;
        info!(backend = %grown.backend, size_bytes = grown.size_bytes, "volume grown");
        self.write(
            id,
            VolumeRecord {
                handle: Some(grown),
                ..record
            },
        )
    }

    /// Delete a snapshot through its provider. There is no local holder check;
    /// snapshot use by other operations requires external coordination.
    #[instrument(skip_all, fields(snapshot_id = %id))]
    pub async fn drop_snapshot(&self, id: SnapshotId) -> anyhow::Result<()> {
        let Some(record) = self.store.get_snapshot(&id)? else {
            debug!("no record; answering Gone, which is the same outcome");
            return self.snapshot_tombstone(id, None);
        };
        if record.phase == SnapshotRecordPhase::Gone {
            return Ok(());
        }
        let driver = self.driver(&record.driver)?;

        // Probe for a snapshot whose creation may have outlived its handle write.
        // LVM needs the origin handle to locate the snapshot VG; missing evidence
        // or a probe failure retains the record rather than publishing Gone.
        let handle = match record.handle.clone() {
            Some(handle) => handle,
            None => {
                let of = self
                    .store
                    .get_volume(&record.volume)?
                    .and_then(|v| v.handle);
                let found = timed_driver(
                    &record.driver,
                    "probe_snapshot",
                    driver.probe_snapshot(of.as_ref(), &id),
                )
                .await
                .with_context(|| {
                    format!("asking {} what it holds for snapshot {id}", record.driver)
                })?;
                match found {
                    Some(found) => {
                        warn!(backend = %found.backend,
                              "a record with no handle, and the backend has the copy after all");
                        found
                    }
                    None => {
                        debug!("no handle, and the backend holds nothing under this id");
                        return self.snapshot_tombstone(id, Some(record));
                    }
                }
            }
        };
        timed_driver(
            &record.driver,
            "drop_snapshot",
            driver.drop_snapshot(&handle),
        )
        .await
        .with_context(|| format!("dropping snapshot {id} via {}", record.driver))?;
        info!(backend = %handle.backend, "snapshot dropped");
        self.snapshot_tombstone(id, Some(record))
    }

    /// Persist explicit snapshot deletion evidence; absence from a report is inconclusive.
    fn snapshot_tombstone(
        &self,
        id: SnapshotId,
        was: Option<SnapshotRecord>,
    ) -> anyhow::Result<()> {
        let record = SnapshotRecord {
            volume: was.as_ref().map(|r| r.volume).unwrap_or_default(),
            handle: None,
            driver: was
                .map(|r| r.driver)
                .unwrap_or_else(agent_api::storage::default_volume_driver),
            phase: SnapshotRecordPhase::Gone,
            reason: Some(SnapshotReason::Dropped),
            message: None,
            gone_at: Some(SystemTime::now()),
        };
        self.store.put_snapshot(&id, &record)
    }

    /// The snapshot half of the status report, tombstones swept on the way
    /// past exactly as `report` does for volumes.
    pub fn report_snapshots(&self) -> Vec<proto::SnapshotStateReport> {
        let records = match self.store.list_snapshots() {
            Ok(records) => records,
            Err(e) => {
                error!(error = %format!("{e:#}"), "reading snapshot records failed");
                return Vec::new();
            }
        };
        let now = SystemTime::now();
        let mut out = Vec::new();
        for (id, record) in records {
            if let Some(gone_at) = record.gone_at
                && now
                    .duration_since(gone_at)
                    .is_ok_and(|age| age > TOMBSTONE_TTL)
            {
                debug!(snapshot_id = %id, "sweeping an expired tombstone");
                if let Err(e) = self.store.delete_snapshot(&id) {
                    warn!(snapshot_id = %id, error = %format!("{e:#}"),
                          "sweeping the tombstone failed");
                }
                continue;
            }
            out.push(proto::SnapshotStateReport {
                snapshot_id: id.to_string(),
                phase: record.phase.as_str().to_string(),
                backend: record.backend().to_string(),
                size_bytes: record.size_bytes(),
                reason: reported_snapshot_reason(&record)
                    .map(|reason| reason.as_str().to_string())
                    .unwrap_or_default(),
                message: record.message.clone().unwrap_or_default(),
            });
        }
        out
    }

    /// Every snapshot record, for `meister agent snapshot ls`.
    pub fn list_snapshots(&self) -> anyhow::Result<Vec<(SnapshotId, SnapshotRecord)>> {
        self.store.list_snapshots()
    }

    /// The handle of a snapshot this node holds, for a provision that starts
    /// from it. `None` where there is no record or no copy behind it.
    pub fn snapshot_handle(
        &self,
        id: &SnapshotId,
    ) -> anyhow::Result<Option<agent_api::storage::VolumeHandle>> {
        Ok(self.store.get_snapshot(id)?.and_then(|r| r.handle))
    }

    /// One backend by name, or the sentence that says which node this is.
    fn driver(&self, name: &str) -> anyhow::Result<Arc<dyn agent_api::storage::VolumeDriver>> {
        self.drivers
            .storage
            .get(name)
            .cloned()
            .ok_or_else(|| anyhow!("volume driver {name:?} is not configured on this node"))
    }

    /// Collect undetached attachments from readable VM records, regardless of
    /// desired state. This is persisted attachment evidence, not a probe of open
    /// file descriptors. Undecodable rows are omitted, so the set can be incomplete.
    fn open_here(&self) -> anyhow::Result<std::collections::BTreeSet<VolumeId>> {
        let mut open = std::collections::BTreeSet::new();
        for (_, record) in self.store.list()? {
            for volume in record.volumes.iter().filter(|v| !v.detached) {
                open.insert(volume.id());
            }
        }
        Ok(open)
    }

    /// Find a local attachment or unreadable VM row that prevents proving the
    /// volume unused. Unlike reporting, deletion checks retain unreadable rows.
    fn holder(&self, id: &VolumeId) -> anyhow::Result<Option<Holder>> {
        for row in self.store.rows()? {
            match row {
                crate::store::VmRow::Record(vm, record) => {
                    if record.volumes.iter().any(|v| v.id() == *id)
                        || record.unattached_volumes.iter().any(|v| v.id == *id)
                    {
                        return Ok(Some(Holder::Vm(vm)));
                    }
                }
                crate::store::VmRow::Unreadable(key) => {
                    return Ok(Some(Holder::Unreadable(key)));
                }
            }
        }
        Ok(None)
    }

    /// Report volumes and remove expired tombstones during the heartbeat inventory pass.
    pub fn report(&self) -> Vec<proto::VolumeStateReport> {
        let records = match self.store.list_volumes() {
            Ok(records) => records,
            Err(e) => {
                error!(error = %format!("{e:#}"), "reading volume records failed");
                return Vec::new();
            }
        };
        // Read VM attachments once for this report. Currently an inventory error
        // falls back to an empty set, and Store::list skips undecodable rows.
        // Thus open=false can reflect missing evidence rather than a closed writer.
        let open = self.open_here().unwrap_or_else(|e| {
            error!(error = %format!("{e:#}"), "reading the vm records for the open set failed");
            Default::default()
        });
        let now = SystemTime::now();
        let mut out = Vec::new();
        for (id, record) in records {
            if let Some(gone_at) = record.gone_at
                && now
                    .duration_since(gone_at)
                    .is_ok_and(|age| age > TOMBSTONE_TTL)
            {
                debug!(volume_id = %id, "sweeping an expired tombstone");
                if let Err(e) = self.store.delete_volume(&id) {
                    warn!(volume_id = %id, error = %format!("{e:#}"),
                          "sweeping the tombstone failed");
                }
                continue;
            }
            out.push(proto::VolumeStateReport {
                id: id.to_string(),
                phase: record.phase.as_str().to_string(),
                backend: record.backend().to_string(),
                reason: reported_reason(&record)
                    .map(|reason| reason.as_str().to_string())
                    .unwrap_or_default(),
                // Derive open ownership from readable VM records; see `open_here` for limitations.
                open: open.contains(&id),
                message: record.message.clone().unwrap_or_default(),
                // Report measured handle size, including backend rounding after resize.
                // Zero means no handle measurement is available.
                size_bytes: record.handle.as_ref().map(|h| h.size_bytes).unwrap_or(0),
            });
        }
        out
    }

    /// List all local volume records, including deletion tombstones.
    pub fn list(&self) -> anyhow::Result<Vec<(VolumeId, VolumeRecord)>> {
        self.store.list_volumes()
    }

    pub fn get(&self, id: &VolumeId) -> anyhow::Result<Option<VolumeRecord>> {
        self.store.get_volume(id)
    }

    /// Probe stored volumes once at startup. Missing backend data becomes Failed;
    /// recreation requires a subsequent Provision command.
    pub async fn adopt(&self) {
        let records = match self.store.list_volumes() {
            Ok(records) => records,
            Err(e) => {
                error!(error = %format!("{e:#}"), "reading volume records at startup failed");
                return;
            }
        };
        for (id, record) in records {
            let (Some(handle), VolumeRecordPhase::Ready) = (&record.handle, record.phase) else {
                continue;
            };
            let name = record
                .spec
                .driver
                .clone()
                .unwrap_or_else(agent_api::storage::default_volume_driver);
            let Some(driver) = self.drivers.storage.get(&name) else {
                warn!(volume_id = %id, driver = %name,
                      "a stored volume names a driver this node no longer has");
                continue;
            };
            match driver.describe(handle).await {
                Ok(state) => {
                    debug!(volume_id = %id, size_bytes = state.size_bytes, "volume adopted")
                }
                Err(StorageError::NotFound(_)) => {
                    warn!(volume_id = %id, backend = %handle.backend,
                          "a stored volume is not on its backend any more");
                    let message = format!(
                        "the backend has no volume {}; it was there when this node last \
                         wrote the record",
                        handle.backend
                    );
                    if let Err(e) = self.write(
                        id,
                        VolumeRecord {
                            handle: None,
                            phase: VolumeRecordPhase::Failed,
                            // Distinguish lost backend data from a driver refusing a provisioning request.
                            reason: Some(VolumeReason::NotOnBackend),
                            message: Some(message),
                            ..record
                        },
                    ) {
                        warn!(volume_id = %id, error = %format!("{e:#}"),
                              "marking the volume failed did not stick");
                    }
                }
                // Probe errors leave the record unchanged; an unreachable backend does
                // not establish that its data is absent.
                Err(e) => warn!(volume_id = %id, error = %format!("{e:#}"),
                                "could not ask the backend about a stored volume"),
            }
        }
    }

    fn tombstone(
        &self,
        id: VolumeId,
        spec: Option<VolumeSpec>,
        message: Option<String>,
    ) -> anyhow::Result<()> {
        let spec = spec.unwrap_or(VolumeSpec {
            base_image: None,
            size_bytes: 0,
            driver: None,
            params: None,
        });
        self.write(
            id,
            VolumeRecord {
                spec,
                handle: None,
                phase: VolumeRecordPhase::Gone,
                reason: Some(VolumeReason::Deprovisioned),
                message,
                gone_at: Some(SystemTime::now()),
            },
        )
    }

    fn write(&self, id: VolumeId, record: VolumeRecord) -> anyhow::Result<()> {
        self.store.put_volume(&id, &record)
    }
}

/// Deserialize a ProvisionVolume spec with field-specific error context.
pub fn parse_spec(spec_json: &str) -> anyhow::Result<VolumeSpec> {
    if spec_json.is_empty() {
        bail!("provision volume without a spec");
    }
    serde_json::from_str(spec_json).context("invalid volume spec_json")
}

#[cfg(test)]
mod tests {
    use super::*;
    use agent_api::storage::{VolumeAttachment, VolumeHandle};
    use std::collections::HashMap;

    /// Filesystem-backed independent-volume fixture with a local store and no hypervisor.
    fn node(tag: &str) -> (tempfile::TempDir, Volumes, Arc<Store>, std::path::PathBuf) {
        let temp = tempfile::Builder::new()
            .prefix(&format!("meister-vol-{tag}-"))
            .tempdir()
            .expect("a temp dir");
        let root = temp.path().to_path_buf();
        let volumes = root.join("volumes");
        std::fs::create_dir_all(root.join("images")).expect("a temp image dir");
        let driver = filesystem_driver::FilesystemBlockDriver::new(
            filesystem_driver::FilesystemDriverConfig {
                image_dir: root.join("images"),
                volume_dir: volumes.clone(),
                qemu_img: std::path::PathBuf::from("qemu-img"),
                // Nothing here converts anything: these pools are raw files.
                convert: agent_api::base_image::Sandbox::default(),
                host_id: "test-node".into(),
            },
        )
        .expect("the filesystem driver builds");
        let mut storage: HashMap<String, Arc<dyn agent_api::storage::VolumeDriver>> =
            HashMap::new();
        storage.insert("filesystem".to_string(), Arc::new(driver));
        let store = Arc::new(Store::open(&root.join("a.redb")).expect("a store"));
        let drivers = Drivers {
            confiner: Arc::new(cgroup_driver::CgroupV2::new(root.join("cgroup"))),
            hypervisor: None,
            hypervisor_name: None,
            storage,
            networking: None,
            bridge: None,
            announcer: None,
            devices: HashMap::new(),
        };
        (
            temp,
            Volumes::new(
                store.clone(),
                drivers,
                Arc::new(tokio::sync::Mutex::new(())),
            ),
            store,
            volumes,
        )
    }

    fn spec(size_bytes: u64) -> VolumeSpec {
        VolumeSpec {
            base_image: None,
            size_bytes,
            driver: Some("filesystem".into()),
            params: None,
        }
    }

    fn inode(path: &std::path::Path) -> u64 {
        use std::os::unix::fs::MetadataExt;
        std::fs::metadata(path)
            .unwrap_or_else(|e| panic!("stat {}: {e}", path.display()))
            .ino()
    }

    /// Repeated provisioning preserves the volume inode and its data.
    #[tokio::test]
    async fn provisioning_twice_makes_one_volume_and_keeps_its_inode() {
        let (_temp, volumes, _, dir) = node("idempotent");
        let id = VolumeId::new_v4();

        volumes.provision(id, spec(1 << 20)).await.expect("made");
        let path = dir.join(format!("{id}.raw"));
        let first = inode(&path);

        volumes.provision(id, spec(1 << 20)).await.expect("again");
        assert_eq!(
            inode(&path),
            first,
            "a second provision must not re-make it"
        );

        let records = volumes.list().expect("records");
        assert_eq!(records.len(), 1, "one record, not two");
        assert_eq!(records[0].1.phase, VolumeRecordPhase::Ready);
        assert_eq!(records[0].1.backend(), path.to_string_lossy());
    }

    /// Volume ownership records survive reopening the store.
    #[tokio::test]
    async fn a_record_survives_the_store_being_reopened() {
        let (_temp, volumes, store, dir) = node("restart");
        let id = VolumeId::new_v4();
        volumes.provision(id, spec(4096)).await.expect("made");
        let backend = volumes.get(&id).unwrap().unwrap().backend().to_string();
        drop(volumes);
        drop(store);

        let reopened = Store::open(&dir.parent().unwrap().join("a.redb")).expect("reopened");
        let record = reopened
            .get_volume(&id)
            .expect("read")
            .expect("still there");
        assert_eq!(record.phase, VolumeRecordPhase::Ready);
        assert_eq!(record.backend(), backend);
    }

    /// Report each volume with its lifecycle phase and backend name.
    #[tokio::test]
    async fn the_status_report_carries_the_volume_with_its_phase() {
        let (_temp, volumes, _, _) = node("report");
        let id = VolumeId::new_v4();
        volumes.provision(id, spec(4096)).await.expect("made");

        let report = volumes.report();
        assert_eq!(report.len(), 1);
        assert_eq!(report[0].id, id.to_string());
        assert_eq!(report[0].phase, "Ready");
        assert!(report[0].backend.ends_with(".raw"), "{:?}", report[0]);
        assert!(report[0].message.is_empty());
    }

    /// Failure reasons distinguish a refused operation, missing data and completed deletion.
    #[tokio::test]
    async fn a_volume_line_says_which_kind_of_trouble_it_is() {
        let (_temp, volumes, store, dir) = node("reasons");
        let line = |id: &VolumeId| {
            volumes
                .report()
                .into_iter()
                .find(|l| l.id == id.to_string())
                .unwrap_or_else(|| panic!("a line for {id}"))
        };

        // An absent base image makes provisioning fail until the image appears.
        let refused = VolumeId::new_v4();
        let mut asks_for_an_image = spec(4096);
        asks_for_an_image.base_image = Some("not-on-this-node.raw".into());
        volumes
            .provision(refused, asks_for_an_image)
            .await
            .expect_err("there is nothing to copy from");
        assert_eq!(line(&refused).phase, "Failed");
        assert_eq!(line(&refused).reason, "DriverRefused");
        assert!(
            !line(&refused).message.is_empty(),
            "and it says what it said"
        );

        // A volume that was made, and whose bytes are then not there any
        // more. `adopt` is what finds it, at start-up, and what it found is
        // not a refusal.
        let lost = VolumeId::new_v4();
        volumes.provision(lost, spec(4096)).await.expect("made");
        assert_eq!(
            line(&lost).reason,
            "",
            "a Ready volume needs no word and must not send one"
        );
        std::fs::remove_file(dir.join(format!("{lost}.raw"))).expect("the bytes, gone");
        volumes.adopt().await;
        assert_eq!(line(&lost).phase, "Failed");
        assert_eq!(line(&lost).reason, "NotOnBackend");

        // Verify explicit deletion evidence in the report.
        let gone = VolumeId::new_v4();
        volumes.provision(gone, spec(4096)).await.expect("made");
        volumes.deprovision(gone).await.expect("deprovisioned");
        assert_eq!(line(&gone).phase, "Gone");
        assert_eq!(line(&gone).reason, "Deprovisioned");

        // And a record from a build before the word. Its sentence travels on
        // and the word says that nothing wrote one — the line is never mute,
        // which is what keeps a fleet mid-upgrade readable.
        let older = VolumeId::new_v4();
        store
            .put_volume(
                &older,
                &VolumeRecord {
                    spec: spec(4096),
                    handle: None,
                    phase: VolumeRecordPhase::Failed,
                    reason: None,
                    message: Some("what an older build wrote".into()),
                    gone_at: None,
                },
            )
            .expect("a record");
        assert_eq!(line(&older).reason, "Unrecorded");
        assert_eq!(line(&older).message, "what an older build wrote");
    }

    /// Snapshot reports distinguish driver failure, completed deletion and legacy missing reasons.
    #[tokio::test]
    async fn a_snapshot_line_says_which_kind_of_trouble_it_is() {
        let (_temp, volumes, store, dir) = node("snap-reasons");
        let line = |id: &SnapshotId| {
            volumes
                .report_snapshots()
                .into_iter()
                .find(|l| l.snapshot_id == id.to_string())
                .unwrap_or_else(|| panic!("a line for {id}"))
        };

        let disk = VolumeId::new_v4();
        volumes.provision(disk, spec(4096)).await.expect("made");

        // A copy that was taken needs no word.
        let taken = SnapshotId::new_v4();
        volumes.snapshot(taken, disk).await.expect("copied");
        assert_eq!(line(&taken).phase, "Ready");
        assert_eq!(line(&taken).reason, "", "a Ready copy explains itself");

        // And one the backend could not make: the bytes it would have copied
        // are not there any more.
        std::fs::remove_file(dir.join(format!("{disk}.raw"))).expect("the source, gone");
        let refused = SnapshotId::new_v4();
        volumes
            .snapshot(refused, disk)
            .await
            .expect_err("there is nothing left to copy");
        assert_eq!(line(&refused).phase, "Failed");
        assert_eq!(line(&refused).reason, "DriverRefused");
        assert!(
            !line(&refused).message.is_empty(),
            "and it says what it said"
        );

        // Dropping an unknown snapshot produces a Gone tombstone.
        let never = SnapshotId::new_v4();
        volumes.drop_snapshot(never).await.expect("already gone");
        assert_eq!(line(&never).phase, "Gone");
        assert_eq!(line(&never).reason, "Dropped");

        // And a record from a build before the word.
        let older = SnapshotId::new_v4();
        store
            .put_snapshot(
                &older,
                &SnapshotRecord {
                    volume: disk,
                    handle: None,
                    driver: "filesystem".into(),
                    phase: SnapshotRecordPhase::Failed,
                    reason: None,
                    message: Some("what an older build wrote".into()),
                    gone_at: None,
                },
            )
            .expect("a record");
        assert_eq!(line(&older).reason, "Unrecorded");
        assert_eq!(line(&older).message, "what an older build wrote");
    }

    /// Refuse destructive cleanup while persisted VM ownership remains.
    #[tokio::test]
    async fn deprovisioning_a_volume_a_vm_holds_is_refused_and_keeps_the_bytes() {
        let (_temp, volumes, store, dir) = node("held");
        let id = VolumeId::new_v4();
        volumes.provision(id, spec(4096)).await.expect("made");
        let path = dir.join(format!("{id}.raw"));

        // A VM record holding it, exactly as `run_chain` would have left one.
        let vm = agent_api::VmId::new_v4();
        let mut record = empty_vm_record();
        let handle = volumes.get(&id).unwrap().unwrap().handle.unwrap();
        record.volumes.push(agent_api::storage::Volume::attached(
            handle.clone(),
            VolumeAttachment::Path(handle.path()),
        ));
        store.put(&vm, &record).expect("a vm record");

        let err = volumes
            .deprovision(id)
            .await
            .expect_err("a held volume is not deleted");
        assert!(
            err.chain().any(|c| c.is::<HeldByVm>()),
            "the refusal has to be recognisable: {err:#}"
        );
        assert!(format!("{err:#}").contains(&vm.to_string()), "{err:#}");
        assert!(path.exists(), "the bytes are still there");
        assert_eq!(
            volumes.get(&id).unwrap().unwrap().phase,
            VolumeRecordPhase::Ready,
            "and the record did not move"
        );
    }

    fn empty_vm_record() -> crate::types::VmRecord {
        crate::types::VmRecord {
            spec: crate::types::AgentVmSpec {
                vcpus: 1,
                memory_mib: 64,
                boot: crate::types::BootSourceSpec::Firmware {
                    firmware: "fw".into(),
                },
                volumes: vec![],
                nics: vec![],
                devices: vec![],
                images: Vec::new(),
                cloud_init: None,
            },
            desired: Default::default(),
            phase: crate::types::Phase::Provisioned,
            operation: None,
            stop_deadline: None,
            receive_deadline: None,
            send_failed: None,
            migration: None,
            unhealthy: None,
            managed_by_controller: true,
            unattached_volumes: Vec::new(),
            volumes: vec![],
            nics: vec![],
            devices: vec![],
            vmm_pid: None,
            overlay_bridges: Default::default(),
        }
    }

    #[tokio::test]
    async fn deletion_rechecks_holders_after_waiting_for_vm_creation() {
        use std::future::Future;
        use std::task::{Context, Poll, Waker};

        for forget in [false, true] {
            let (_temp, volumes, store, dir) = node("concurrent-holder");
            let id = VolumeId::new_v4();
            volumes.provision(id, spec(4096)).await.unwrap();
            let vm = agent_api::VmId::new_v4();
            let mut record = empty_vm_record();
            let handle = volumes.get(&id).unwrap().unwrap().handle.unwrap();
            record.volumes.push(agent_api::storage::Volume::attached(
                handle.clone(),
                VolumeAttachment::Path(handle.path()),
            ));

            // Local VM creation owns this lock before it starts attaching.
            let guard = volumes.ops.lock().await;
            let deletion = async {
                if forget {
                    volumes.forget(id).await
                } else {
                    volumes.deprovision(id).await
                }
            };
            tokio::pin!(deletion);
            let mut context = Context::from_waker(Waker::noop());
            assert!(matches!(
                deletion.as_mut().poll(&mut context),
                Poll::Pending
            ));
            store.put(&vm, &record).unwrap();
            drop(guard);

            let error = deletion.await.expect_err("the newly attached holder wins");
            assert!(
                error.chain().any(|cause| cause.is::<HeldByVm>()),
                "{error:#}"
            );
            assert!(dir.join(format!("{id}.raw")).exists());
            assert_eq!(
                volumes.get(&id).unwrap().unwrap().phase,
                VolumeRecordPhase::Ready
            );
        }
    }

    /// Deletion removes volume data and emits explicit Gone evidence.
    #[tokio::test]
    async fn deprovision_removes_the_data_and_answers_gone_afterwards() {
        let (_temp, volumes, _, dir) = node("gone");
        let id = VolumeId::new_v4();
        volumes.provision(id, spec(4096)).await.expect("made");
        let path = dir.join(format!("{id}.raw"));
        assert!(path.exists());

        volumes.deprovision(id).await.expect("removed");
        assert!(!path.exists(), "the data is gone");

        let report = volumes.report();
        assert_eq!(report.len(), 1, "the tombstone is still reported");
        assert_eq!(report[0].phase, "Gone");

        // Repeated deletion retains the Gone result.
        volumes.deprovision(id).await.expect("again");
        assert_eq!(volumes.report()[0].phase, "Gone");
    }

    /// Unknown-volume deletion emits a Gone tombstone, including after an older tombstone expires.
    #[tokio::test]
    async fn deprovisioning_an_unknown_volume_answers_gone_rather_than_silence() {
        let (_temp, volumes, _, _) = node("unknown");
        let id = VolumeId::new_v4();
        volumes.deprovision(id).await.expect("the same outcome");
        let report = volumes.report();
        assert_eq!(report.len(), 1);
        assert_eq!(report[0].id, id.to_string());
        assert_eq!(report[0].phase, "Gone");
    }

    /// Adoption marks missing backend data Failed without recreating it.
    #[tokio::test]
    async fn a_volume_the_backend_lost_is_adopted_as_failed() {
        let (_temp, volumes, _, dir) = node("adopt");
        let id = VolumeId::new_v4();
        volumes.provision(id, spec(4096)).await.expect("made");
        std::fs::remove_file(dir.join(format!("{id}.raw"))).expect("somebody removed it");

        volumes.adopt().await;
        let record = volumes.get(&id).unwrap().unwrap();
        assert_eq!(record.phase, VolumeRecordPhase::Failed);
        assert!(record.handle.is_none(), "the stale handle goes with it");
        assert!(
            record
                .message
                .unwrap()
                .contains("the backend has no volume"),
            "the sentence has to say what happened"
        );
    }

    /// Adoption preserves existing Ready volumes.
    #[tokio::test]
    async fn a_volume_that_is_there_survives_adoption_untouched() {
        let (_temp, volumes, _, _) = node("adopt-ok");
        let id = VolumeId::new_v4();
        volumes.provision(id, spec(4096)).await.expect("made");
        let before = volumes.get(&id).unwrap().unwrap();
        volumes.adopt().await;
        let after = volumes.get(&id).unwrap().unwrap();
        assert_eq!(after.phase, VolumeRecordPhase::Ready);
        assert_eq!(after.backend(), before.backend());
    }

    /// Unsupported drivers fail before a volume record is written.
    #[tokio::test]
    async fn a_spec_naming_an_unknown_backend_is_refused() {
        let (_temp, volumes, _, _) = node("unknown-driver");
        let id = VolumeId::new_v4();
        let err = volumes
            .provision(
                id,
                VolumeSpec {
                    driver: Some("lvm-thin".into()),
                    ..spec(4096)
                },
            )
            .await
            .expect_err("this node has no lvm-thin");
        assert!(format!("{err:#}").contains("lvm-thin"), "{err:#}");
    }

    /// The spec a `ProvisionVolume` carries is the agent's own, so the inline
    /// path and the object path reach the driver with one document.
    #[test]
    fn the_command_carries_the_same_spec_the_inline_path_uses() {
        let spec = parse_spec(
            r#"{"base_image":"tiny.raw","size_bytes":1024,
                                  "driver":"filesystem","params":{"a":1}}"#,
        )
        .expect("a spec");
        assert_eq!(spec.base_image.as_deref(), Some("tiny.raw"));
        assert_eq!(spec.driver.as_deref(), Some("filesystem"));
        assert_eq!(spec.params.unwrap()["a"], 1);
        assert!(parse_spec("").is_err(), "an empty document is not a spec");
    }

    /// A handle round-trips through the record, which is what lets a
    /// deprovision after a restart find the bytes it has to remove.
    #[test]
    fn a_record_carries_everything_a_deprovision_needs() {
        let record = VolumeRecord {
            spec: spec(4096),
            handle: Some(VolumeHandle {
                id: VolumeId::nil(),
                backend: "/var/lib/meister/volumes/x.raw".into(),
                size_bytes: 4096,
                params: None,
            }),
            phase: VolumeRecordPhase::Ready,
            reason: None,
            message: None,
            gone_at: None,
        };
        let back: VolumeRecord =
            serde_json::from_str(&serde_json::to_string(&record).unwrap()).unwrap();
        assert_eq!(back.backend(), "/var/lib/meister/volumes/x.raw");
        assert_eq!(back.spec.driver.as_deref(), Some("filesystem"));
    }

    /// The command and the report as they travel: a proto round trip, so
    /// that the id a controller sends is the id this node parses and the
    /// phase this node writes is the string that arrives.
    #[test]
    fn the_volume_commands_and_the_report_round_trip_through_the_proto() {
        use prost::Message;

        let id = VolumeId::new_v4();
        let cmd = proto::Command {
            request_id: "r-1".into(),
            traceparent: String::new(),
            op: Some(proto::command::Op::ProvisionVolume(
                proto::ProvisionVolume {
                    from_snapshot: String::new(),
                    id: id.to_string(),
                    spec_json: r#"{"base_image":null,"size_bytes":1024}"#.into(),
                },
            )),
        };
        let back = proto::Command::decode(cmd.encode_to_vec().as_slice()).unwrap();
        let Some(proto::command::Op::ProvisionVolume(v)) = back.op else {
            panic!("{back:?}")
        };
        assert_eq!(v.id.parse::<VolumeId>().unwrap(), id);
        assert_eq!(parse_spec(&v.spec_json).unwrap().size_bytes, 1024);

        let cmd = proto::Command {
            request_id: "r-2".into(),
            traceparent: String::new(),
            op: Some(proto::command::Op::DeprovisionVolume(
                proto::DeprovisionVolume { id: id.to_string() },
            )),
        };
        let back = proto::Command::decode(cmd.encode_to_vec().as_slice()).unwrap();
        assert!(matches!(
            back.op,
            Some(proto::command::Op::DeprovisionVolume(_))
        ));

        let report = proto::StatusReport {
            snapshots: Vec::new(),
            node: None,
            vms: Vec::new(),
            routers: Vec::new(),
            images: Vec::new(),
            images_complete: false,
            vms_complete: false,
            volumes: vec![proto::VolumeStateReport {
                size_bytes: 0,
                id: id.to_string(),
                phase: VolumeRecordPhase::Ready.as_str().to_string(),
                backend: "/var/lib/meister/volumes/x.raw".into(),
                reason: String::new(),
                open: true,
                message: String::new(),
            }],
            stopping: false,
            migrations: Vec::new(),
        };
        let back = proto::StatusReport::decode(report.encode_to_vec().as_slice()).unwrap();
        assert_eq!(back.volumes[0].phase, "Ready");
        assert_eq!(back.volumes[0].backend, "/var/lib/meister/volumes/x.raw");
        // Preserve the open flag on the wire. Older senders omit it, decoding to false.
        assert!(back.volumes[0].open);

        // A report from an agent that predates the field carries none, and
        // that is "knows of none" rather than "they are gone".
        let old = proto::StatusReport {
            snapshots: Vec::new(),
            node: None,
            vms: Vec::new(),
            routers: Vec::new(),
            images: Vec::new(),
            images_complete: false,
            vms_complete: false,
            volumes: Vec::new(),
            stopping: false,
            migrations: Vec::new(),
        };
        assert!(
            proto::StatusReport::decode(old.encode_to_vec().as_slice())
                .unwrap()
                .volumes
                .is_empty()
        );
    }

    /// Forget removes local ownership without deleting data or emitting a Gone tombstone.
    #[tokio::test]
    async fn forgetting_a_volume_takes_the_record_and_leaves_the_data() {
        let (_temp, volumes, store, dir) = node("forget");
        let id = VolumeId::new_v4();
        volumes
            .provision(id, spec(1024 * 1024))
            .await
            .expect("a volume");
        let file = volumes
            .get(&id)
            .expect("the record")
            .expect("it is there")
            .handle
            .expect("a handle")
            .backend;
        assert!(std::path::Path::new(&file).exists(), "the bytes are here");
        let before = inode(std::path::Path::new(&file));

        volumes.forget(id).await.expect("the node lets go");

        assert!(
            volumes.get(&id).expect("a read").is_none(),
            "the record is gone, not a tombstone: a `Gone` from a node the \
             cluster still calls the home would strand the volume"
        );
        assert!(
            volumes.report().iter().all(|r| r.id != id.to_string()),
            "and this node says nothing about the volume at all"
        );
        assert!(
            std::path::Path::new(&file).exists(),
            "the data is untouched"
        );
        assert_eq!(
            inode(std::path::Path::new(&file)),
            before,
            "the same file, not a new one"
        );
        assert!(dir.join(format!("{id}.raw")).exists());

        // Idempotent for an id this node has never heard of: "let go of
        // something you are not holding" is already done.
        volumes
            .forget(VolumeId::new_v4())
            .await
            .expect("forgetting nothing is done");
        volumes.forget(id).await.expect("and twice is once");

        // Persisted VM ownership also blocks forgetting the volume.
        let held = VolumeId::new_v4();
        volumes
            .provision(held, spec(1024 * 1024))
            .await
            .expect("a second volume");
        let mut record = crate::types::VmRecord::blank();
        record.volumes = vec![agent_api::storage::Volume::attached(
            VolumeHandle {
                id: held,
                backend: dir.join(format!("{held}.raw")).display().to_string(),
                size_bytes: 1024 * 1024,
                params: None,
            },
            VolumeAttachment::Path(dir.join(format!("{held}.raw"))),
        )];
        store
            .put(&agent_api::VmId::new_v4(), &record)
            .expect("a vm holding it");
        let refused = volumes.forget(held).await.expect_err("a vm has it open");
        assert!(
            format!("{refused:#}").contains("held by vm"),
            "the refusal is the same one a deprovision gives, and it names the \
             vm an operator has to look at: {refused:#}"
        );
        assert!(
            volumes.get(&held).expect("a read").is_some(),
            "and the record is still there"
        );
    }

    /// Count destructive calls while delegating to the filesystem backend.
    /// A refusal must also prove that the destructive driver method was not called.
    struct Counting {
        inner: Arc<dyn agent_api::storage::VolumeDriver>,
        deprovisions: std::sync::atomic::AtomicUsize,
    }

    impl Counting {
        fn deprovisions(&self) -> usize {
            self.deprovisions.load(std::sync::atomic::Ordering::SeqCst)
        }
    }

    #[async_trait::async_trait]
    impl agent_api::storage::VolumeProvider for Counting {
        fn locality(&self) -> agent_api::storage::Locality {
            self.inner.locality()
        }
        async fn provision(
            &self,
            id: &VolumeId,
            spec: &VolumeSpec,
        ) -> agent_api::storage::Result<VolumeHandle> {
            self.inner.provision(id, spec).await
        }
        async fn deprovision(&self, handle: &VolumeHandle) -> agent_api::storage::Result<()> {
            self.deprovisions
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            self.inner.deprovision(handle).await
        }
        async fn describe(
            &self,
            handle: &VolumeHandle,
        ) -> agent_api::storage::Result<agent_api::storage::VolumeState> {
            self.inner.describe(handle).await
        }
        async fn probe(
            &self,
            id: &VolumeId,
            spec: &VolumeSpec,
        ) -> agent_api::storage::Result<Option<VolumeHandle>> {
            self.inner.probe(id, spec).await
        }
        async fn probe_snapshot(
            &self,
            volume: Option<&VolumeHandle>,
            id: &SnapshotId,
        ) -> agent_api::storage::Result<Option<VolumeHandle>> {
            self.inner.probe_snapshot(volume, id).await
        }
        async fn resize(
            &self,
            handle: &VolumeHandle,
            size_bytes: u64,
        ) -> agent_api::storage::Result<VolumeHandle> {
            self.inner.resize(handle, size_bytes).await
        }
        fn snapshot_support(&self) -> Option<agent_api::storage::SnapshotConsistency> {
            self.inner.snapshot_support()
        }
        async fn snapshot(
            &self,
            handle: &VolumeHandle,
            id: &SnapshotId,
        ) -> agent_api::storage::Result<VolumeHandle> {
            self.inner.snapshot(handle, id).await
        }
        async fn drop_snapshot(&self, handle: &VolumeHandle) -> agent_api::storage::Result<()> {
            self.inner.drop_snapshot(handle).await
        }
        async fn provision_from(
            &self,
            id: &VolumeId,
            snapshot: &VolumeHandle,
            spec: &VolumeSpec,
        ) -> agent_api::storage::Result<VolumeHandle> {
            self.inner.provision_from(id, snapshot, spec).await
        }
        async fn forget(&self, handle: &VolumeHandle) -> agent_api::storage::Result<()> {
            self.inner.forget(handle).await
        }
    }

    #[async_trait::async_trait]
    impl agent_api::storage::VolumeAttacher for Counting {
        async fn attach(
            &self,
            handle: &VolumeHandle,
            cgroup: Option<&agent_api::CgroupHandle>,
        ) -> agent_api::storage::Result<VolumeAttachment> {
            self.inner.attach(handle, cgroup).await
        }
        async fn detach(
            &self,
            handle: &VolumeHandle,
            attachment: &VolumeAttachment,
        ) -> agent_api::storage::Result<()> {
            self.inner.detach(handle, attachment).await
        }
        async fn stat(
            &self,
            handle: &VolumeHandle,
            attachment: &VolumeAttachment,
        ) -> agent_api::storage::Result<agent_api::storage::VolumeState> {
            self.inner.stat(handle, attachment).await
        }
    }

    /// Volume fixture with destructive calls instrumented by `Counting`.
    fn counted_node(
        tag: &str,
    ) -> (
        tempfile::TempDir,
        Volumes,
        Arc<Store>,
        std::path::PathBuf,
        Arc<Counting>,
    ) {
        let (temp, volumes, store, dir) = node(tag);
        let inner = volumes
            .drivers
            .storage
            .get("filesystem")
            .cloned()
            .expect("the filesystem backend");
        let counting = Arc::new(Counting {
            inner,
            deprovisions: Default::default(),
        });
        let mut drivers = volumes.drivers.clone();
        drivers
            .storage
            .insert("filesystem".to_string(), counting.clone());
        (
            temp,
            Volumes::new(
                store.clone(),
                drivers,
                Arc::new(tokio::sync::Mutex::new(())),
            ),
            store,
            dir,
            counting,
        )
    }

    /// An unreadable VM row may own any volume. Count backend calls to prove deletion was refused.
    #[tokio::test]
    async fn a_corrupt_vm_record_still_blocks_a_deprovision() {
        let (_temp, volumes, store, dir, driver) = counted_node("corrupt-holder");
        let id = VolumeId::new_v4();
        volumes.provision(id, spec(4096)).await.expect("made");
        let path = dir.join(format!("{id}.raw"));
        assert!(path.exists());

        // An unreadable VM row may hold this disk, so ownership is unknown.
        let vm = agent_api::VmId::new_v4();
        store
            .put_raw(&vm.to_string(), b"{\"spec\":")
            .expect("a raw row");

        let err = volumes
            .deprovision(id)
            .await
            .expect_err("an unreadable record is not an absent one");
        assert!(
            err.chain().any(|c| c.is::<HeldByUnreadable>()),
            "the refusal has to be recognisable and apart from HeldByVm: {err:#}"
        );
        assert!(
            !err.chain().any(|c| c.is::<HeldByVm>()),
            "and it is NOT the answer the controller heals by itself: {err:#}"
        );
        assert!(
            format!("{err:#}").contains(&vm.to_string()),
            "it names the key an operator has to look at: {err:#}"
        );
        assert_eq!(driver.deprovisions(), 0, "the backend was never asked");
        assert!(path.exists(), "the bytes are still there");
        assert_eq!(
            volumes.get(&id).unwrap().unwrap().phase,
            VolumeRecordPhase::Ready,
            "and the record did not move"
        );

        // The unreadable row also blocks forget.
        let refused = volumes
            .forget(id)
            .await
            .expect_err("forget has the same guard");
        assert!(refused.chain().any(|c| c.is::<HeldByUnreadable>()));
    }

    /// A crash can lose the handle after creation. Probe before publishing a deletion tombstone.
    #[tokio::test]
    async fn a_record_with_no_handle_is_probed_before_it_is_called_gone() {
        let (_temp, volumes, store, dir) = node("probe-before-gone");

        // One that the backend does hold: made, and then the handle taken
        // off the record, which is exactly what a crash between the write and
        // the driver's answer leaves.
        let made = VolumeId::new_v4();
        volumes.provision(made, spec(4096)).await.expect("made");
        let path = dir.join(format!("{made}.raw"));
        assert!(path.exists());
        let record = volumes.get(&made).unwrap().unwrap();
        store
            .put_volume(
                &made,
                &VolumeRecord {
                    handle: None,
                    phase: VolumeRecordPhase::Failed,
                    reason: Some(VolumeReason::DriverRefused),
                    message: Some("the answer was lost".into()),
                    ..record
                },
            )
            .expect("a record with no handle");

        volumes.deprovision(made).await.expect("deprovisioned");
        assert!(
            !path.exists(),
            "the backend was asked and the bytes it had went with the answer"
        );
        assert_eq!(
            volumes.get(&made).unwrap().unwrap().phase,
            VolumeRecordPhase::Gone
        );

        // Confirmed backend absence permits a Gone tombstone.
        let never = VolumeId::new_v4();
        store
            .put_volume(
                &never,
                &VolumeRecord {
                    spec: spec(4096),
                    handle: None,
                    phase: VolumeRecordPhase::Provisioning,
                    reason: Some(VolumeReason::Working),
                    message: None,
                    gone_at: None,
                },
            )
            .expect("an intent nothing followed");
        volumes.deprovision(never).await.expect("tombstoned");
        assert_eq!(
            volumes.get(&never).unwrap().unwrap().phase,
            VolumeRecordPhase::Gone
        );

        // Recover a backend snapshot whose pending record lacks its handle.
        let volume = VolumeId::new_v4();
        volumes.provision(volume, spec(4096)).await.expect("made");
        let snapshot = SnapshotId::new_v4();
        volumes
            .snapshot(snapshot, volume)
            .await
            .expect("a snapshot");
        let copy = dir.join(format!("{snapshot}.snap"));
        assert!(copy.exists());
        let taken = store.get_snapshot(&snapshot).unwrap().unwrap();
        store
            .put_snapshot(
                &snapshot,
                &SnapshotRecord {
                    handle: None,
                    phase: SnapshotRecordPhase::Failed,
                    reason: Some(SnapshotReason::DriverRefused),
                    message: Some("the answer was lost".into()),
                    ..taken
                },
            )
            .expect("a snapshot record with no handle");

        volumes.drop_snapshot(snapshot).await.expect("dropped");
        assert!(!copy.exists(), "the copy went with the drop");
        assert_eq!(
            store.get_snapshot(&snapshot).unwrap().unwrap().phase,
            SnapshotRecordPhase::Gone
        );
    }
}
