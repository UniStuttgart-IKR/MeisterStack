// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Volume acquisition and changes to a VM's attachments.
//!
//! Inline volumes are owned by the VM. Referenced volumes have independent
//! records and survive VM deletion. Ownership comes from the persisted spec.

use super::*;

/// Resolve the creating volume driver from persisted ownership records for cleanup.
pub(crate) fn volume_driver_name(store: &Store, record: &VmRecord, id: &VolumeId) -> String {
    // Referenced entries get their driver from the independent volume record.
    // Inline entries use the VM specification, with the normal driver default.
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

/// Read volume ownership from the VM specification, independent of whether
/// the standalone volume row still exists. Missing entries default to inline
/// ownership for compatibility with records predating references.
pub(crate) fn volume_is_referenced(record: &VmRecord, id: &VolumeId) -> bool {
    record
        .spec
        .volumes
        .iter()
        .find(|v| &v.id == id)
        .map(|v| v.referenced)
        .unwrap_or(false)
}

/// Compare secondary referenced volumes by ID, ignoring position changes.
/// Boot and inline disks are excluded; API validation enforces their immutability.
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

/// Increase memory allowance for storage attachments with backend processes.
/// The returned attachment, rather than the spec, reveals whether a process is
/// needed. Never lower limits beneath backends already running in the cgroup.
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
    /// Resolve a referenced volume from its existing record. Missing records or
    /// handles refuse attachment; this path never provisions replacement data.
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
        // VM-specific attach options, such as a virtiofs tag, override handle
        // params only when explicitly supplied.
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
            // Reuse referenced handles. For inline disks, persist provisioned handles
            // before attach so failures and restarts can reclaim or reuse them.
            let (driver_name, handle) = match v.referenced {
                true => self.reference(&v.id, v.spec.params.clone())?,
                false => {
                    let driver_name = v.spec.driver.clone().unwrap_or_else(default_volume_driver);
                    if let Some(handle) = record.unattached_volumes.iter().find(|h| h.id == v.id) {
                        (driver_name, handle.clone())
                    } else {
                        debug!(volume_id = %v.id, driver = %driver_name,
                               base_image = ?v.spec.base_image, "creating volume");
                        let driver = self.storage(&driver_name)?;
                        let handle = timed_driver(
                            &driver_name,
                            "provision",
                            driver.provision(&v.id, &v.spec),
                        )
                        .await
                        .with_context(|| {
                            format!("provisioning volume {} via {driver_name}", v.id)
                        })?;
                        record.unattached_volumes.push(handle.clone());
                        self.store.put(id, record)?;
                        (driver_name, handle)
                    }
                }
            };
            let driver = self.storage(&driver_name)?;
            let attachment =
                timed_driver(&driver_name, "attach", driver.attach(&handle, Some(cgroup)))
                    .await
                    .with_context(|| format!("attaching volume {} via {driver_name}", v.id))?;
            record.volumes.push(Volume::attached(handle, attachment));
            record.unattached_volumes.retain(|h| h.id != v.id);
            self.store.put(id, record)?;
        }
        record.phase = Phase::VolumesDone;
        self.store.put(id, record)?;
        info!(count = record.volumes.len(), "volumes ready");
        Ok(())
    }

    /// Reclaim inline disks for which attach never returned a durable attachment.
    /// The persisted spec is also intent: probe covers a crash after provision but
    /// before its returned handle was written. A failed probe must retain the row.
    pub(super) async fn reclaim_unattached_volumes(
        &self,
        id: &VmId,
        record: &VmRecord,
    ) -> Vec<String> {
        let mut failures = Vec::new();
        for v in record.spec.volumes.iter().filter(|v| !v.referenced) {
            if record.volumes.iter().any(|held| held.id() == v.id) {
                continue;
            }
            let name = v.spec.driver.clone().unwrap_or_else(default_volume_driver);
            let result: Result<()> = async {
                let driver = self.storage(&name)?;
                let handle = match record.unattached_volumes.iter().find(|h| h.id == v.id) {
                    Some(handle) => handle.clone(),
                    None => match timed_driver(&name, "probe", driver.probe(&v.id, &v.spec)).await?
                    {
                        Some(handle) => {
                            self.store
                                .mutate(id, |r| r.unattached_volumes.push(handle.clone()))?;
                            handle
                        }
                        None => return Ok(()),
                    },
                };
                timed_driver(&name, "deprovision", driver.deprovision(&handle)).await?;
                self.store
                    .mutate(id, |r| r.unattached_volumes.retain(|h| h.id != v.id))?;
                Ok(())
            }
            .await;
            if let Err(error) = result {
                failures.push(format!("unattached volume {}: {error:#}", v.id));
            }
        }
        failures
    }

    /// Detach volume connections without deleting data. Record successful detaches
    /// so later teardown does not repeat them; failed detaches remain retryable.
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

    /// Apply controller volume changes to an existing VM. Both create replay and
    /// reconnect synchronization use this path. The caller must hold the operations
    /// lock; an absent VM is left to the ordinary provisioning path.
    pub async fn sync_volumes(&self, id: &VmId, wanted: &AgentVmSpec) -> Result<()> {
        let Some(mut record) = self.store.get(id)? else {
            return Ok(());
        };
        self.apply_volume_diff(id, &mut record, wanted).await?;
        self.store.put(id, &record)
    }

    /// Apply secondary referenced-volume changes. Remove disks from the VMM before
    /// detaching their backends; attach new backends before adding them to the VMM.
    ///
    /// For a VMM considered live, hotplug support is required. Otherwise only the
    /// record and attachments change, and the next start uses the new configuration.
    /// Guest filesystems are not unmounted by this operation.
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
        // Use one liveness decision for the entire attachment diff.
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

        // Detach removed backends before adding replacements to avoid overlapping resource usage.
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

        // Update only the volume list, preserving the node-resolved fields and
        // other immutable parts of the existing specification.
        record.spec.volumes = wanted.volumes.clone();
        Ok(())
    }

    /// Notify the VMM after the storage backend has grown a disk. This does not
    /// resize guest partitions or filesystems. Refuse an absent or untracked VMM
    /// so the caller can distinguish immediate notification from a future reboot.
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
