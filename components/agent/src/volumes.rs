// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Volumes this node owns on their own, with no VM implied.
//!
//! The other half of `provision.rs`. That file makes a disk FOR a VM and
//! unmakes it WITH the VM — an instance store, and the only kind of disk this
//! node could make until now. This one makes a disk because the control plane
//! said to, keeps a record of it that survives a restart, and unmakes it only
//! when told. The difference is entirely in who deletes it, and that is the
//! whole of what a `Volume` object is for.
//!
//! # One registry
//!
//! `Drivers::storage` is the same map both halves route through — `spec.driver`
//! picks the backend here exactly as it does inline. Two registries would be
//! two answers to "which backend owns these bytes", and the second one would
//! be wrong the first time somebody changed a configuration.
//!
//! # Why the node refuses
//!
//! [`Volumes::deprovision`] rejects a volume a VM on this node is holding. The
//! controller is not supposed to send that — it clears `attachedTo` first —
//! but the node is the last thing between a mistake and somebody's data, and
//! a defence that only exists one tier up is a defence that a bug one tier up
//! removes.

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use agent_api::storage::{SnapshotId, StorageError, VolumeId, VolumeSpec};
use anyhow::{Context, anyhow, bail};
use tracing::{debug, error, info, instrument, warn};

use crate::drivers::Drivers;
use crate::provision::timed_driver;
use crate::store::Store;
use crate::types::{SnapshotRecord, SnapshotRecordPhase, VolumeRecord, VolumeRecordPhase};

/// How long a `Gone` tombstone is kept.
///
/// Long enough that a controller which asked for the deprovision has seen the
/// answer many times over — it reads status every ten seconds — and short
/// enough that a node deleting volumes all day does not carry the list for
/// ever. Nothing depends on the exact number: a Deprovision for an id this
/// node no longer has makes a fresh tombstone, so a sweep that ran too early
/// costs one more round trip and never a stranded object.
const TOMBSTONE_TTL: Duration = Duration::from_secs(3600);

/// A refusal that is about the data rather than about this node.
///
/// Its own type so the dispatch can tell it apart from a driver that broke:
/// "a VM is holding it" is a correct answer that the tier above has to act
/// on, and logging it at ERROR beside a dead backend would be wrong.
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

/// The node's volume half: a store, the one driver registry, and four verbs.
pub struct Volumes {
    store: Arc<Store>,
    drivers: Drivers,
}

impl Volumes {
    pub fn new(store: Arc<Store>, drivers: Drivers) -> Self {
        Self { store, drivers }
    }

    /// Make the volume, or hand back the one that is already there.
    ///
    /// Idempotent twice over, and both are load-bearing. A record that
    /// already has a handle is done and the driver is not called at all; a
    /// record without one is picked up again, and the backend finds the
    /// volume it made before the crash because every backend derives its name
    /// from the id. The two together are what make it safe for the tier above
    /// to be level-triggered and simply keep asking.
    /// Make the volume from a SNAPSHOT this node holds.
    ///
    /// Beside `provision` rather than a flag on it, mirroring the trait cut:
    /// the two start from different things, and a caller that had to pass
    /// `None` for the snapshot on every ordinary provision would be a caller
    /// reading a parameter that means nothing to it.
    ///
    /// Everything else is `provision`'s: the record before the driver call,
    /// the idempotence, the `Failed` on the record AND the error to the
    /// caller. Said once by delegating the write path rather than twice.
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
        // Resolved before the record is written, because a snapshot this node
        // does not have is not something a later pass fixes: the tier above
        // sent the volume to the node the snapshot is on, so being here
        // without it means the two disagree, and making an EMPTY disk on the
        // strength of that would hand somebody a blank volume where they
        // asked for their data.
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
            // Already made. Not even a `describe`: the record is this node's
            // own statement about bytes it wrote, and asking the backend on
            // every repeat would turn a level-triggered pass into a poll of
            // the disk.
            debug!(backend = %handle.backend, "volume already provisioned");
            if existing.phase != VolumeRecordPhase::Ready {
                self.write(
                    id,
                    VolumeRecord {
                        phase: VolumeRecordPhase::Ready,
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

        // Written down BEFORE the driver runs, so that a crash in the middle
        // leaves a record without a handle rather than nothing at all. That
        // record is what the next pass picks up; without it the volume would
        // exist on the backend with nobody on this node aware of it.
        self.write(
            id,
            VolumeRecord {
                spec: spec.clone(),
                handle: None,
                phase: VolumeRecordPhase::Provisioning,
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
                        message: None,
                        gone_at: None,
                    },
                )
            }
            Err(e) => {
                let message = format!("{e:#}");
                warn!(error = %message, "volume provision failed");
                // Failed on the record AND an error to the caller: the first
                // is what the tier above reads off the status road and turns
                // into `Volume.status.message`, the second is what makes the
                // command a failed command rather than a silent one.
                self.write(
                    id,
                    VolumeRecord {
                        spec,
                        handle: None,
                        phase: VolumeRecordPhase::Failed,
                        message: Some(message),
                        gone_at: None,
                    },
                )?;
                Err(e).context("provisioning volume")
            }
        }
    }

    /// Destroy the volume and its data, or say who is holding it.
    ///
    /// Idempotent, including for an id this node has never heard of: that is
    /// the same outcome, and answering it with a tombstone rather than with
    /// silence is what keeps the tier above from waiting for ever. See
    /// [`VolumeRecordPhase::Gone`].
    #[instrument(skip_all, fields(volume_id = %id))]
    pub async fn deprovision(&self, id: VolumeId) -> anyhow::Result<()> {
        if let Some(vm) = self.holder(&id)? {
            // The last defence. The controller clears `attachedTo` before it
            // sends this, so reaching here means the controller is wrong, and
            // at the end of obeying it anyway is somebody's data.
            warn!(vm = %vm, "refusing to deprovision a volume a vm is holding");
            return Err(HeldByVm { volume: id, vm }.into());
        }

        let Some(record) = self.store.get_volume(&id)? else {
            debug!("no record; answering Gone, which is the same outcome");
            return self.tombstone(id, None, None);
        };
        if record.phase == VolumeRecordPhase::Gone {
            return Ok(());
        }

        let Some(handle) = record.handle.clone() else {
            // Told to make it, never did — so there is nothing on any backend
            // to remove, and the record was the only trace.
            debug!("no handle; nothing was ever made");
            return self.tombstone(id, Some(record.spec), None);
        };
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
        timed_driver(&driver_name, "deprovision", driver.deprovision(&handle))
            .await
            .with_context(|| format!("deprovisioning volume {id} via {driver_name}"))?;
        info!(backend = %handle.backend, "volume deprovisioned");
        self.tombstone(id, Some(record.spec), None)
    }

    /// Stop being a node that holds this volume. **The bytes stay.**
    ///
    /// The other end of a live migration's bookkeeping. When a guest moves,
    /// the destination opens the disk before the source lets go, and
    /// afterwards the object's home moves with the guest — leaving this node
    /// with a record for a disk it has no business with. It went on reporting
    /// that volume on every heartbeat, and the cluster dropped every one of
    /// those reports because this node is neither the volume's home nor a
    /// holder of it: one line per node per report, for ever (D8/D20).
    ///
    /// **No tombstone**, and that is the difference from `deprovision` that
    /// matters most. `Gone` means "the bytes are not on this node", and from
    /// a node the control plane still believes is the home — a
    /// `move_volume_home` that lost a race, a forget that arrived first —
    /// that word clears `status.node` and strands the volume. The record is
    /// simply removed, so this node says nothing about the volume at all;
    /// absence up there means "does not know", which is exactly what has
    /// become true.
    ///
    /// The backend is asked to let go of what it holds PER NODE and nothing
    /// else — `VolumeProvider::forget`, which for everything but
    /// `nvmeof-import` does nothing. Its failure is a WARN and not an error:
    /// what must happen here is that this node stops speaking for the volume,
    /// and a claim file that could not be removed is a leak on one machine,
    /// not a reason to keep reporting a disk that has moved.
    ///
    /// Idempotent for an id this node has never heard of, and refused while a
    /// VM here still holds the disk — the same last defence `deprovision`
    /// has, and reaching it means the tier above is wrong.
    #[instrument(skip_all, fields(volume_id = %id))]
    pub async fn forget(&self, id: VolumeId) -> anyhow::Result<()> {
        if let Some(vm) = self.holder(&id)? {
            warn!(vm = %vm, "refusing to forget a volume a vm on this node is holding");
            return Err(HeldByVm { volume: id, vm }.into());
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

    /// Freeze what a volume holds right now, under the snapshot's own id.
    ///
    /// Idempotent twice over, exactly as `provision` is and for the same two
    /// reasons: a record that already carries a handle is done without asking
    /// the backend, and a record without one is picked up again because every
    /// backend derives the copy's name from the id.
    ///
    /// Nothing here pauses anything. Whether the VM has to stand still is the
    /// DRIVER's answer and the CLUSTER's to act on — the VM may be on another
    /// machine under a `shared` pool, and only the tier that can see both ends
    /// can sequence a pause around a call to a second node.
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

        // The record before the driver call, for the reason `provision` gives
        // in full: a crash in the middle leaves a record without a handle
        // rather than nothing at all, and the next pass picks it up.
        let pending = SnapshotRecord {
            volume,
            handle: None,
            driver: driver_name.clone(),
            phase: SnapshotRecordPhase::Creating,
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
                        message: Some(message),
                        ..pending
                    },
                )?;
                Err(e).context("taking snapshot")
            }
        }
    }

    /// Grow the bytes of a volume this node owns.
    ///
    /// The first of the two halves of a resize, and the only one that touches
    /// data. Always the driver, even when a VM has the disk open and the VMM
    /// could grow a file itself: a block device grows here or nowhere, and a
    /// volume nothing is holding has no VMM to ask.
    ///
    /// The handle on the record takes the size the BACKEND came out at rather
    /// than the one asked for — lvm rounds up to the extent size — so the
    /// status road carries a measurement and not an echo.
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

    /// Destroy a snapshot and its data.
    ///
    /// No holder check, and the absence is the point: nothing attaches a
    /// snapshot. What holds it is an OBJECT one tier up, and that is where a
    /// `HeldBy` belongs — the node's own last-defence argument
    /// (`deprovision`) is about a live attachment, and there is none here.
    #[instrument(skip_all, fields(snapshot_id = %id))]
    pub async fn drop_snapshot(&self, id: SnapshotId) -> anyhow::Result<()> {
        let Some(record) = self.store.get_snapshot(&id)? else {
            debug!("no record; answering Gone, which is the same outcome");
            return self.snapshot_tombstone(id, None);
        };
        if record.phase == SnapshotRecordPhase::Gone {
            return Ok(());
        }
        let Some(handle) = record.handle.clone() else {
            debug!("no handle; nothing was ever made");
            return self.snapshot_tombstone(id, Some(record));
        };
        let driver = self.driver(&record.driver)?;
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

    /// A snapshot record that says the bytes are not here any more.
    ///
    /// The mirror of `tombstone` one object over, and the same rule: absence
    /// from a report is "this node does not know", so the end of a drop has
    /// to be something the node SAYS.
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

    /// Which VM on this node is holding this volume, if any.
    ///
    /// Asked of the VM records rather than of the volume record, because the
    /// attachment belongs to the consumer: a VM's record is what names the
    /// volumes it has open, and that stays true whether the volume was made
    /// inline or handed over as an object.
    fn holder(&self, id: &VolumeId) -> anyhow::Result<Option<agent_api::VmId>> {
        for (vm, record) in self.store.list()? {
            if record.volumes.iter().any(|v| v.id() == *id) {
                return Ok(Some(vm));
            }
        }
        Ok(None)
    }

    /// What this node has to say about its volumes, for the status report.
    ///
    /// Tombstones included and swept on the way past: this is the one pass
    /// that runs on every heartbeat, so it is where the sweep costs nothing
    /// extra. A record that is too old to matter is removed AND left out,
    /// which is the same statement a fresh node makes about it.
    pub fn report(&self) -> Vec<proto::VolumeStateReport> {
        let records = match self.store.list_volumes() {
            Ok(records) => records,
            Err(e) => {
                error!(error = %format!("{e:#}"), "reading volume records failed");
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
                message: record.message.clone().unwrap_or_default(),
                // What the handle says the volume IS, which after a resize is
                // not what the spec asked for: lvm rounds up to the extent
                // size. Zero while there is no handle, which reads up there
                // as "not measured".
                size_bytes: record.handle.as_ref().map(|h| h.size_bytes).unwrap_or(0),
            });
        }
        out
    }

    /// Every volume record, for `meister agent volume ls`. Tombstones and all
    /// — an operator asking what this node holds wants the one that was just
    /// deleted in the list too.
    pub fn list(&self) -> anyhow::Result<Vec<(VolumeId, VolumeRecord)>> {
        self.store.list_volumes()
    }

    pub fn get(&self, id: &VolumeId) -> anyhow::Result<Option<VolumeRecord>> {
        self.store.get_volume(id)
    }

    /// Ask every backend whether the volumes this node thinks it has are
    /// really there. Run once, at start-up, the way VMs are adopted.
    ///
    /// A volume the backend has never heard of is `Failed` and not silently
    /// re-made: the tier above owns that decision, its requeue is what kicks,
    /// and the kick is another Provision — which is idempotent, so the repair
    /// path is the ordinary path and there is no second one to get wrong.
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
                            message: Some(message),
                            ..record
                        },
                    ) {
                        warn!(volume_id = %id, error = %format!("{e:#}"),
                              "marking the volume failed did not stick");
                    }
                }
                // A backend that could not be asked is not a backend that
                // said no. The record stays Ready and the next start-up asks
                // again — an unreachable export must not turn into "the data
                // is gone".
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
                message,
                gone_at: Some(SystemTime::now()),
            },
        )
    }

    fn write(&self, id: VolumeId, record: VolumeRecord) -> anyhow::Result<()> {
        self.store.put_volume(&id, &record)
    }
}

/// Parse the spec a `ProvisionVolume` carries.
///
/// Its own function so the error names the field rather than the crate: a
/// controller that sends something this node cannot read gets a sentence
/// about the document, not a serde path.
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

    /// A real `filesystem` backend over a temp directory, and a store beside
    /// it. No hypervisor anywhere: the whole point of the volume half is that
    /// it needs no consumer, so these tests need no VM either.
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
        (temp, Volumes::new(store.clone(), drivers), store, volumes)
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

    /// The contract the whole level-triggered tier above rests on: asking
    /// twice makes one volume. The inode is the proof — a second provision
    /// that re-created the file would be a second inode, and somebody's data
    /// would be the thing that had been replaced.
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

    /// The record is what makes bytes survive the process that made them.
    /// Without it a restarted agent could not be asked to delete anything it
    /// had ever made.
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

    /// A status report carries the volume with its phase and the name its
    /// backend knows it by — the same road a VM phase takes.
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

    /// The node is the last defence. The controller clears `attachedTo`
    /// before it sends a deprovision, so this can only fire when the tier
    /// above is wrong — and at the end of obeying it anyway is somebody's
    /// data.
    #[tokio::test]
    async fn deprovisioning_a_volume_a_vm_holds_is_refused_and_keeps_the_bytes() {
        let (_temp, volumes, store, dir) = node("held");
        let id = VolumeId::new_v4();
        volumes.provision(id, spec(4096)).await.expect("made");
        let path = dir.join(format!("{id}.raw"));

        // A VM record holding it, exactly as `run_chain` would have left one.
        let vm = agent_api::VmId::new_v4();
        let mut record = crate::types::VmRecord {
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
            unhealthy: None,
            managed_by_controller: true,
            volumes: vec![],
            nics: vec![],
            devices: vec![],
            vmm_pid: None,
            overlay_bridges: Default::default(),
        };
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

    /// Deprovision removes the data and leaves a tombstone, because absence
    /// from a report means "does not know" and only an explicit `Gone` may
    /// release the object one tier up.
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

        // Idempotent: the second one is the same answer, not an error.
        volumes.deprovision(id).await.expect("again");
        assert_eq!(volumes.report()[0].phase, "Gone");
    }

    /// A deprovision for an id this node has never heard of is the same
    /// outcome and gets the same answer. Without this the tombstone sweep
    /// could strand the tier above: it would ask, hear nothing, and wait for
    /// ever on a volume that does not exist.
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

    /// A backend that has lost the volume is `Failed` and not silently
    /// re-made: the decision belongs to the tier above, and its kick is
    /// another Provision — which is idempotent, so the repair path is the
    /// ordinary path.
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

    /// A volume that is really there stays Ready, and adoption says nothing
    /// about it — the ordinary case, and the one a restart must not disturb.
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

    /// A spec naming a backend this node does not have is a refused command,
    /// and the record must not be left behind as a Failed volume nobody asked
    /// for.
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
            volumes: vec![proto::VolumeStateReport {
                size_bytes: 0,
                id: id.to_string(),
                phase: VolumeRecordPhase::Ready.as_str().to_string(),
                backend: "/var/lib/meister/volumes/x.raw".into(),
                message: String::new(),
            }],
            stopping: false,
            migrations: Vec::new(),
        };
        let back = proto::StatusReport::decode(report.encode_to_vec().as_slice()).unwrap();
        assert_eq!(back.volumes[0].phase, "Ready");
        assert_eq!(back.volumes[0].backend, "/var/lib/meister/volumes/x.raw");

        // A report from an agent that predates the field carries none, and
        // that is "knows of none" rather than "they are gone".
        let old = proto::StatusReport {
            snapshots: Vec::new(),
            node: None,
            vms: Vec::new(),
            routers: Vec::new(),
            images: Vec::new(),
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
    /// Forgetting removes the record and keeps every byte.
    ///
    /// The whole of D20, and the whole of what makes it safe to send: the
    /// source of a finished live migration has a record for a disk whose home
    /// has moved, and the only two commands that could take it away before
    /// this one were `Destroy` (which is about a VM) and `DeprovisionVolume`
    /// (which unlinks the file). So the record stayed, the node reported the
    /// volume on every heartbeat for ever, and the cluster dropped every
    /// report because that node is neither the volume's home nor a holder of
    /// it.
    ///
    /// Absence and not a tombstone, which is the difference that matters
    /// most: `Gone` says "the bytes are not on this node", and from a node the
    /// control plane still believes is the home that word clears
    /// `status.node` and strands the volume.
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

        // The last defence, the same one a deprovision has: a volume a VM
        // here is holding is not forgotten, whoever asked.
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
}
