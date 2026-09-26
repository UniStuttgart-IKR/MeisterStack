// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Stop releases runtime resources while retaining disks and taps; teardown also
//! removes VM-owned resources and deletes the record after collected failures clear.
//!
//! Teardown continues after driver failures. Stop returns early on a VMM destroy
//! failure and logs later device and volume cleanup failures.

use super::*;

impl Provisioner {
    #[instrument(skip(self), fields(vm_id = %id))]
    pub async fn teardown(&self, id: &VmId) -> Result<()> {
        let Some(record) = self.store.get(id)? else {
            return Ok(());
        };

        let mut failures: Vec<String> = Vec::new();
        // A failed receiver must also release imported claims for referenced volumes.
        let abandoned_reception = record.phase == Phase::Receiving;

        if let Err(e) = self.drivers.confiner.kill_slice(&id.to_string()) {
            failures.push(format!("cgroup kill: {e}"));
        }

        // Missing drivers prevent complete cleanup and retain the record for retry.
        match self.drivers.hypervisor() {
            Ok(hv) => match timed_driver(HYPERVISOR, "destroy", hv.destroy(id)).await {
                Ok(()) | Err(HypervisorError::NotFound(_)) => {}
                Err(e) => failures.push(format!("hypervisor destroy: {e}")),
            },
            Err(e) => failures.push(format!("hypervisor destroy: {e:#}")),
        }

        // Attempt every device cleanup and collect failures, including missing drivers.
        for d in &record.devices {
            let name = device_driver_name(&record, &d.id);
            let Some(driver) = self.drivers.devices.get(&name) else {
                failures.push(format!(
                    "device {}: driver {name:?} is not configured",
                    d.id
                ));
                continue;
            };
            if let Err(e) =
                timed_driver(&name, "destroy", driver.destroy(&d.id, &d.attachment)).await
            {
                failures.push(format!("device {}: {e}", d.id));
            }
        }

        // Whether every tap of this VM is off the host. The overlay below
        // hangs on it: a bridge with a port left on it is a bridge in use.
        let mut taps_gone = true;
        for n in &record.nics {
            let driver = match self.drivers.networking() {
                Ok(driver) => driver,
                // Retain the failure because the tap cannot be removed without its driver.
                Err(e) => {
                    failures.push(format!("nic {}: {e:#}", n.id));
                    taps_gone = false;
                    continue;
                }
            };
            if let Err(e) = timed_driver(NETWORKING, "destroy", driver.destroy(&n.id)).await {
                failures.push(format!("nic {}: {e}", n.id));
                taps_gone = false;
            }
        }

        // Remove an overlay only after all VM taps are gone and no other VM uses it.
        // The bridge driver also checks router ownership and remaining kernel ports.
        for vni in overlay_vnis(&record) {
            if !taps_gone {
                debug!(vni, "overlay left standing: a tap of this vm is still up");
                continue;
            }
            // A recorded bridge name prevents deleting an overlay created by another driver configuration.
            let named = record.overlay_bridges.get(&vni).map(String::as_str);
            match overlay_users(&self.store, vni, id) {
                Ok(0) => match self.drivers.bridge() {
                    Ok(bridge) => {
                        if let Err(e) = timed_driver(
                            NETWORKING,
                            "destroy_overlay",
                            bridge.destroy_overlay(vni, named),
                        )
                        .await
                        {
                            failures.push(format!("overlay {vni}: {e}"));
                        }
                    }
                    Err(e) => failures.push(format!("overlay {vni}: {e:#}")),
                },
                Ok(users) => {
                    debug!(vni, users, "overlay kept: other vms on this node use it");
                }
                // An unreadable VM inventory retains the overlay without blocking this VM teardown.
                Err(e) => warn!(vni, error = %format!("{e:#}"),
                                "cannot count the users of this overlay, leaving it up"),
            }
        }

        // Attempt detach before deleting inline volume data. Currently a failed detach
        // does not prevent deprovision; failures are collected for a later retry.
        //
        // Skip connections already recorded as detached, and persist newly completed
        // detaches below to avoid repeating process cleanup using a stale PID.
        let mut closed: Vec<VolumeId> = Vec::new();
        failures.extend(self.reclaim_unattached_volumes(id, &record).await);
        for v in &record.volumes {
            let id = v.id();
            let name = volume_driver_name(&self.store, &record, &id);
            let Some(driver) = self.drivers.storage.get(&name) else {
                failures.push(format!("volume {id}: driver {name:?} is not configured"));
                continue;
            };
            if v.detached {
                debug!(volume_id = %id, "already detached by the stop before this");
            } else {
                match timed_driver(&name, "detach", driver.detach(&v.handle, &v.attachment)).await {
                    Ok(()) => closed.push(id),
                    Err(e) => failures.push(format!("volume {id}: detach: {e}")),
                }
            }
            // Referenced volumes outlive the VM; teardown releases their attachments
            // without deleting their data or standalone volume records.
            if volume_is_referenced(&record, &id) {
                // A failed receiver also forgets its local import claim. `forget` must
                // preserve the remote data, unlike `deprovision`.
                if abandoned_reception {
                    if let Err(e) = timed_driver(&name, "forget", driver.forget(&v.handle)).await {
                        failures.push(format!("volume {id}: forget: {e}"));
                    } else {
                        debug!(volume_id = %id,
                               "the reception was given back; this node has let the disk go");
                    }
                    continue;
                }
                debug!(volume_id = %id, "detached; the volume outlives this vm");
                continue;
            }
            if let Err(e) = timed_driver(&name, "deprovision", driver.deprovision(&v.handle)).await
            {
                failures.push(format!("volume {id}: {e}"));
            }
        }

        // Persist completed detaches even if another cleanup step failed. This limits
        // repeated process cleanup and updates the volume-open report before record deletion.
        if !closed.is_empty()
            && let Err(e) = self.store.mutate(id, |r| {
                for v in r.volumes.iter_mut().filter(|v| closed.contains(&v.id())) {
                    v.detached = true;
                }
            })
        {
            // The connection is closed, but failed persistence may cause a later retry
            // to repeat detach using the old record. This error is logged only.
            warn!(error = %format!("{e:#}"),
                  "could not write down which volumes this teardown closed");
        }

        // The seed is regenerated from the spec on provision; remove it with the VM.
        let _ = std::fs::remove_file(crate::cloudinit::seed_path(&self.run_dir, id));

        let cg = self.drivers.confiner.open_slice(&id.to_string());
        if let Err(e) = self.drivers.confiner.destroy_slice(&cg) {
            failures.push(format!("cgroup slice: {e}"));
        }

        if failures.is_empty() {
            self.store.delete(id)?;
            Ok(())
        } else {
            bail!("teardown of vm {id} incomplete: {}", failures.join("; "))
        }
    }

    #[instrument(skip(self, record), fields(vm_id = %id))]
    pub(crate) async fn stop(&self, id: &VmId, mut record: VmRecord) -> Result<()> {
        let hypervisor = self.drivers.hypervisor()?;
        match timed_driver(HYPERVISOR, "destroy", hypervisor.destroy(id)).await {
            Ok(()) | Err(HypervisorError::NotFound(_)) => {}
            Err(e) => bail!("stopping vmm: {e}"),
        }

        if let Some(pid) = record.vmm_pid {
            let in_slice = self
                .drivers
                .confiner
                .pids_in_slice(&id.to_string())
                .map(|pids| pids.contains(&pid))
                .unwrap_or(false);
            // Require both cgroup membership and VMM identity before signalling a PID
            // that may have been reused since the record was written.
            if in_slice && hypervisor.owns_pid(id, pid) {
                warn!(pid, "vmm survived destroy, killing it directly");
                let _ = nix::sys::signal::kill(
                    nix::unistd::Pid::from_raw(pid as i32),
                    nix::sys::signal::Signal::SIGKILL,
                );
            } else if in_slice {
                // A missing process needs no signal; a reused PID must not be killed.
                match agent_api::process_exists(pid) {
                    true => warn!(
                        pid,
                        "the recorded vmm pid belongs to another process now; not signalling it"
                    ),
                    false => debug!(pid, "the vmm is already gone; nothing to signal"),
                }
            }
        }

        for d in &record.devices {
            let name = device_driver_name(&record, &d.id);
            match self.drivers.devices.get(&name) {
                Some(driver) => {
                    if let Err(e) =
                        timed_driver(&name, "destroy", driver.destroy(&d.id, &d.attachment)).await
                    {
                        warn!(device = %d.id, error = %format!("{e:#}"),
                              "stopping device backend failed");
                    }
                }
                None => {
                    warn!(device = %d.id, driver = %name, "device driver not configured, skipping")
                }
            }
        }
        record.devices.clear();

        // Detach volume backends without deleting data. Persist successful detaches
        // so teardown can avoid repeating cleanup after a stop or restart.
        // Resolve driver names before mutably borrowing the attachments.
        let by_driver: Vec<String> = record
            .volumes
            .iter()
            .map(|v| volume_driver_name(&self.store, &record, &v.id()))
            .collect();
        for (v, name) in record.volumes.iter_mut().zip(by_driver) {
            let id = v.handle.id;
            match self.drivers.storage.get(&name) {
                Some(driver) => {
                    match timed_driver(&name, "detach", driver.detach(&v.handle, &v.attachment))
                        .await
                    {
                        Ok(()) => v.detached = true,
                        Err(e) => warn!(volume = %id, error = %format!("{e:#}"),
                                        "detaching volume backend failed"),
                    }
                }
                None => warn!(volume = %id, driver = %name,
                              "volume driver not configured, skipping"),
            }
        }

        record.vmm_pid = None;
        record.stop_deadline = None;
        record.unhealthy = None;
        self.store.put(id, &record)?;
        info!("vm stopped, volumes and taps kept");
        Ok(())
    }
}
