// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! The disks: what the spec asks for, what the record holds, and the
//! difference between the two.
//!
//! Two shapes and one rule. An INLINE entry is an instance store made with
//! this VM and unmade with it; a REFERENCED one names a `Volume` object that
//! outlives the VM, so this node only ever opens and closes the connection to
//! it. Every function here that has to choose between the two asks the record
//! for the answer, because the record is what was written down when the VM
//! was made.
//!
//! Moved out of `provision.rs` unchanged.

use super::*;

/// Which backend created this volume, read back off the spec the record was
/// built from — the mirror of `device_driver_name`, and for the same reason:
/// teardown has to reach the driver that made the thing, and the record is
/// the only place that still remembers which one that was.
pub(crate) fn volume_driver_name(store: &Store, record: &VmRecord, id: &VolumeId) -> String {
    // A REFERENCED entry carries no driver of its own — the VM's spec says
    // `{"volume": "<uid>"}` and nothing else, because the disk is not this
    // VM's to describe. So the answer comes from the volume table, which is
    // the same place `reference()` reads it at attach.
    //
    // Before this it did not, and fell through to `default_volume_driver()`.
    // Nothing noticed while every backend's `detach` was a no-op for a plain
    // path; the first driver whose detach MATTERS is the one that opened a
    // connection — an nvme-of session stayed up after its VM was gone, and
    // an nfs virtiofsd would have too.
    if volume_is_referenced(record, id)
        && let Ok(Some(volume)) = store.get_volume(id)
        && let Some(driver) = volume.spec.driver.clone()
    {
        return driver;
    }
    record
        .spec
        .volumes
        .iter()
        .find(|v| &v.id == id)
        .and_then(|v| v.spec.driver.clone())
        .unwrap_or_else(default_volume_driver)
}

/// Whether this entry of the record was ATTACHED rather than made.
///
/// Read off the VM's own spec and nowhere else. The teardown path asks it to
/// choose between `detach` and `deprovision`, and the difference between the
/// two is somebody's data — so the answer has to be the one that was written
/// down when the VM was created, not one derived from a second table that may
/// since have lost its row.
///
/// A record whose spec does not name the volume at all defaults to `false`,
/// which is the safe direction only because it is also the true one: every
/// volume in a record from before this field was made by that VM.
pub(crate) fn volume_is_referenced(record: &VmRecord, id: &VolumeId) -> bool {
    record
        .spec
        .volumes
        .iter()
        .find(|v| &v.id == id)
        .map(|v| v.referenced)
        .unwrap_or(false)
}

/// What changed between the volumes a record holds and the ones a new spec
/// asks for: what to attach, and what to let go.
///
/// **Only from the second entry on, and only referenced entries.** The boot
/// entry is what the guest boots from and never moves; an inline entry is an
/// instance store that came with the VM and goes with it. Both rules are
/// enforced a tier up as a 422 — this is the same rule said again where the
/// bytes are, because a rule that lives only at the edge is a rule a second
/// client at the agent's own socket does not meet.
///
/// Compared by volume ID and not by position: a detach renumbers the list,
/// and a diff that compared positions would tear down a disk that had merely
/// moved up one.
pub(crate) fn volume_diff(
    held: &AgentVmSpec,
    wanted: &AgentVmSpec,
) -> (
    Vec<crate::types::VolumeWithId>,
    Vec<crate::types::VolumeWithId>,
) {
    let pluggable = |spec: &AgentVmSpec| -> Vec<crate::types::VolumeWithId> {
        spec.volumes
            .iter()
            .skip(1)
            .filter(|v| v.referenced)
            .cloned()
            .collect()
    };
    let (held, wanted) = (pluggable(held), pluggable(wanted));
    let attach = wanted
        .iter()
        .filter(|w| !held.iter().any(|h| h.id == w.id))
        .cloned()
        .collect();
    let detach = held
        .iter()
        .filter(|h| !wanted.iter().any(|w| w.id == h.id))
        .cloned()
        .collect();
    (attach, detach)
}

/// The extra slice headroom the volumes actually turned out to need.
///
/// `limits_for` cannot answer this and that is not an oversight: whether a
/// volume becomes a PROCESS is the driver's answer, never the spec's. A
/// `[volume.nfs]` share becomes a virtiofsd that lives in this VM's slice
/// and eats host memory there; a plain file on the very same driver becomes
/// a path and eats nothing. Only the attachment the driver handed back says
/// which of the two happened, so the slice is created with what the spec can
/// predict and widened once, here, before the VMM moves in.
///
/// Widened only, never narrowed: the backends are already inside the slice
/// by the time this runs, and lowering `memory.max` under a live process is
/// how a VM gets OOM-killed at boot.
///
/// `None` is "nothing to do" — a VM whose volumes are all plain paths, which
/// is most of them, keeps byte for byte the limits it had before this
/// existed.
pub(crate) fn widen_for_storage_backends(
    base: &ResourceLimits,
    volumes: &[Volume],
) -> Option<ResourceLimits> {
    let backends = volumes
        .iter()
        .filter(|v| v.attachment.backend_pid().is_some())
        .count() as u64;
    if backends == 0 {
        return None;
    }
    let mut widened = base.clone();
    widened.memory_max = base
        .memory_max
        .map(|bytes| bytes + backends * BACKEND_OVERHEAD_MIB * 1024 * 1024);
    Some(widened)
}

impl Provisioner {
    /// The handle of a volume this node already owns, for a VM that REFERS to
    /// it.
    ///
    /// Read out of the volume table rather than made: the record is this
    /// node's own statement about bytes it wrote, and a VM that provisioned
    /// here would be claiming to have made a disk that was there before it.
    /// A volume with no record, or a record with no handle, is a refusal
    /// rather than a fresh disk — the controller only sends a reference for a
    /// volume it has seen reported `Ready`, so reaching either means the two
    /// pictures disagree and making bytes on the strength of that would be
    /// the wrong repair.
    pub(super) fn reference(
        &self,
        id: &VolumeId,
        attach_params: Option<serde_json::Value>,
    ) -> Result<(String, agent_api::storage::VolumeHandle)> {
        let record = self
            .store
            .get_volume(id)?
            .ok_or_else(|| anyhow!("this node has no record of volume {id}"))?;
        let mut handle = record
            .handle
            .ok_or_else(|| anyhow!("volume {id} is known here but has not been provisioned"))?;
        let driver_name = record
            .spec
            .driver
            .clone()
            .unwrap_or_else(default_volume_driver);
        // Attach options travel with the VM, not with the volume: a virtiofs
        // tag is a property of the CONNECTION, and two VMs of one volume over
        // time may mount it under two names. Only when the entry named some —
        // otherwise whatever the volume was provisioned with stands.
        if attach_params.is_some() {
            handle.params = attach_params;
        }
        debug!(volume_id = %id, driver = %driver_name, backend = %handle.backend,
               "attaching a volume this node already owns");
        Ok((driver_name, handle))
    }

    /// The first link of the chain: every volume the spec names, standing and
    /// connected to this VM's slice.
    pub(super) async fn attach_volumes(
        &self,
        id: &VmId,
        record: &mut VmRecord,
        spec: &AgentVmSpec,
        cgroup: &agent_api::CgroupHandle,
    ) -> Result<()> {
        for v in &spec.volumes {
            // Two shapes, and the difference is who owns the bytes.
            //
            // An inline entry describes a disk to be MADE for this VM: two
            // driver calls, the data first with no consumer in sight and then
            // the connection into THIS VM's slice.
            //
            // A referenced entry names a volume this node already has a
            // record of, made because a `Volume` object said so. Then there
            // is exactly ONE call — the connection — and provisioning it here
            // would be this VM claiming to have made somebody else's disk.
            let (driver_name, handle) = match v.referenced {
                true => self.reference(&v.id, v.spec.params.clone())?,
                false => {
                    let driver_name = v.spec.driver.clone().unwrap_or_else(default_volume_driver);
                    debug!(volume_id = %v.id, driver = %driver_name,
                               base_image = ?v.spec.base_image, "creating volume");
                    let driver = self.storage(&driver_name)?;
                    let handle =
                        timed_driver(&driver_name, "provision", driver.provision(&v.id, &v.spec))
                            .await
                            .with_context(|| {
                                format!("provisioning volume {} via {driver_name}", v.id)
                            })?;
                    (driver_name, handle)
                }
            };
            let driver = self.storage(&driver_name)?;
            let attachment =
                timed_driver(&driver_name, "attach", driver.attach(&handle, Some(cgroup)))
                    .await
                    .with_context(|| format!("attaching volume {} via {driver_name}", v.id))?;
            record.volumes.push(Volume::attached(handle, attachment));
        }
        record.phase = Phase::VolumesDone;
        self.store.put(id, record)?;
        info!(count = record.volumes.len(), "volumes ready");
        Ok(())
    }

    /// Give the volume backends back without touching the data.
    ///
    /// The same loop `stop` runs and for the same reason — a backend process
    /// serving a guest that is not here is a process with nothing to serve —
    /// and the same mark, so the teardown that follows does not detach twice.
    /// Nothing is DEPROVISIONED: a live migration moves a guest and never its
    /// disks, and every disk it could have moved with belongs to a `Volume`
    /// object that outlives this record by definition.
    pub(super) async fn detach_volumes(&self, id: &VmId, record: &mut VmRecord) {
        let by_driver: Vec<String> = record
            .volumes
            .iter()
            .map(|v| volume_driver_name(&self.store, record, &v.id()))
            .collect();
        for (v, name) in record.volumes.iter_mut().zip(by_driver) {
            if v.detached {
                continue;
            }
            let volume = v.handle.id;
            match self.drivers.storage.get(&name) {
                Some(driver) => {
                    match timed_driver(&name, "detach", driver.detach(&v.handle, &v.attachment))
                        .await
                    {
                        Ok(()) => v.detached = true,
                        Err(e) => warn!(vm_id = %id, volume = %volume,
                                        error = %format!("{e:#}"),
                                        "detaching a volume backend failed"),
                    }
                }
                None => warn!(vm_id = %id, volume = %volume, driver = %name,
                              "volume driver not configured, skipping"),
            }
        }
    }

    /// Bring a known VM's volumes in line with a spec the controller re-sent.
    ///
    /// The entry point for both roads a re-sent spec travels: a
    /// `CreateInstance` for a VM this node already has, and the desired-state
    /// snapshot after a reconnect. One function, because a hot-plug that only
    /// worked down one of them would be a hot-plug that silently waited for a
    /// session to drop.
    ///
    /// A VM this node does not have is not an error here: it is the ordinary
    /// create, and the caller is about to make it.
    ///
    /// The `ops` lock is the CALLER's, like everywhere else on this type: it
    /// belongs to the agent, and a method that took it would take it twice
    /// for the caller that already had it.
    pub async fn sync_volumes(&self, id: &VmId, wanted: &AgentVmSpec) -> Result<()> {
        let Some(mut record) = self.store.get(id)? else {
            return Ok(());
        };
        self.apply_volume_diff(id, &mut record, wanted).await?;
        self.store.put(id, &record)
    }

    /// Bring the record's volumes in line with a spec that has changed.
    ///
    /// Hot-plug, and the whole of the agent's half of it. What may differ is
    /// narrow by construction — the API refuses everything but referenced
    /// entries from index 1 on — so this compares by volume id and does two
    /// things: attach what is new, detach what is gone.
    ///
    /// **The order within each half is the rule.** A disk is attached before
    /// the VMM is told about it, because telling a VMM about a path that is
    /// not there yet is an error the guest sees; and the VMM is told to drop
    /// a disk before the attachment goes, because pulling a backend out from
    /// under a live device is how a guest gets I/O errors instead of an
    /// unplug. Mirror images, and neither is reversible.
    ///
    /// **A VMM that is not running is not told anything.** The record takes
    /// the change and the next start builds the config from it — which is the
    /// same path a stopped VM's disks take anyway, and the reason a hypervisor
    /// with no `HotPluggable` is not an error here.
    ///
    /// What this deliberately does NOT do is ask the guest anything. A disk
    /// the guest has mounted does not go away because somebody asked, and
    /// that is the guest's business exactly as it is with EBS; the one disk
    /// nobody can pull out from under a guest is the boot disk, and that
    /// entry is immutable a tier up.
    pub(super) async fn apply_volume_diff(
        &self,
        id: &VmId,
        record: &mut VmRecord,
        wanted: &AgentVmSpec,
    ) -> Result<()> {
        let (attach, detach) = volume_diff(&record.spec, wanted);
        if attach.is_empty() && detach.is_empty() {
            return Ok(());
        }
        // Asked once and not per volume: whether the guest has to be told at
        // all is a property of this VM at this moment, and a plan that
        // half-told it would be worse than one that told it nothing.
        let hypervisor = self.drivers.hypervisor()?;
        let live = record.vmm_pid.is_some() && hypervisor.is_tracked(id);
        let hotplug = hypervisor.as_hotpluggable();
        if live && hotplug.is_none() {
            bail!(
                "this node's hypervisor cannot plug a disk into a running vm; \
                 stop the vm and start it again to pick the change up"
            );
        }
        info!(
            attach = attach.len(),
            detach = detach.len(),
            live,
            "the vm spec's volumes changed"
        );

        // Detach first. A spec that swaps one volume for another otherwise
        // holds both at once, and on a node whose slice is sized for one that
        // is a limit nobody asked to raise.
        for v in &detach {
            let Some(index) = record.volumes.iter().position(|held| held.id() == v.id) else {
                debug!(volume_id = %v.id, "not held here; nothing to detach");
                continue;
            };
            let name = v.spec.driver.clone().unwrap_or_else(default_volume_driver);
            let driver = self.storage(&name)?;
            if let Some(hotplug) = hotplug.filter(|_| live) {
                hotplug
                    .remove_disk(id, &agent_api::disk_id(&v.id))
                    .await
                    .with_context(|| format!("unplugging volume {} from the guest", v.id))?;
            }
            let held = record.volumes.remove(index);
            timed_driver(
                &name,
                "detach",
                driver.detach(&held.handle, &held.attachment),
            )
            .await
            .with_context(|| format!("detaching volume {} via {name}", v.id))?;
            // The bytes stay. A referenced volume belongs to a `Volume`
            // object that outlives this VM by definition, and this path is
            // never reached by an inline one — those are immutable.
            info!(volume_id = %v.id, "volume detached; the data stays");
        }

        for v in &attach {
            let (driver_name, handle) = self.reference(&v.id, v.spec.params.clone())?;
            let driver = self.storage(&driver_name)?;
            let cgroup = self.drivers.confiner.open_slice(&id.to_string());
            let attachment = timed_driver(
                &driver_name,
                "attach",
                driver.attach(&handle, Some(&cgroup)),
            )
            .await
            .with_context(|| format!("attaching volume {} via {driver_name}", v.id))?;
            let plugged = agent_api::AttachedVolume {
                id: handle.id,
                attachment: attachment.clone(),
            };
            if let Some(hotplug) = hotplug.filter(|_| live) {
                hotplug
                    .add_disk(id, &plugged)
                    .await
                    .with_context(|| format!("plugging volume {} into the guest", v.id))?;
            }
            record.volumes.push(Volume::attached(handle, attachment));
            info!(volume_id = %v.id, "volume attached");
        }

        // The spec's volume list, and only that. Everything else on the
        // record's spec is either identical by the tier above's rule or
        // resolved by this node when the VM was made, and taking the whole
        // document would quietly let a caller at the agent's own socket
        // rewrite the second half of it.
        record.spec.volumes = wanted.volumes.clone();
        Ok(())
    }

    /// Tell a running guest that one of its disks has grown.
    ///
    /// The second half of a resize, and the half that changes no data: the
    /// backend has already grown the bytes (`Volumes::resize`), and this is
    /// the part no storage driver can do. On the provisioner because the
    /// hypervisor lives here, and by disk id because that is the name the VMM
    /// knows the disk by (`hypervisor::disk_id`).
    ///
    /// A VMM that is not running is an error rather than a quiet success: the
    /// tier above has to be able to tell "the guest now has the room" from
    /// "the guest will have it after a restart", and a lie here is the one
    /// that would fill a filesystem the guest thinks is bigger than it is.
    #[instrument(skip_all, fields(vm_id = %id, volume_id = %volume, size_bytes))]
    pub async fn resize_attachment(
        &self,
        id: &VmId,
        volume: &VolumeId,
        size_bytes: u64,
    ) -> Result<()> {
        let record = self
            .store
            .get(id)?
            .ok_or_else(|| anyhow!("this node has no record of vm {id}"))?;
        if !record.volumes.iter().any(|v| v.id() == *volume) {
            bail!("vm {id} does not have volume {volume} attached on this node");
        }
        let hypervisor = self.drivers.hypervisor()?;
        if record.vmm_pid.is_none() || !hypervisor.is_tracked(id) {
            bail!("vm {id} is not running here; its guest will see the new size at the next start");
        }
        let hotplug = hypervisor.as_hotpluggable().ok_or_else(|| {
            anyhow!(
                "this node's hypervisor cannot tell a running guest that a disk grew; \
                 stop the vm and start it again to pick the new size up"
            )
        })?;
        hotplug
            .resize_disk(id, &agent_api::disk_id(volume), size_bytes)
            .await
            .with_context(|| format!("telling vm {id} that volume {volume} grew"))?;
        info!("the guest was told its disk grew");
        Ok(())
    }
}
