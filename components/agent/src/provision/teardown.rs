// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! The two ways a VM ends on this node.
//!
//! `stop` keeps everything the record names and gives back only what a
//! stopped guest must not hold — the VMM, the device backends, the volume
//! connections. `teardown` unmakes the lot and deletes the record, and it is
//! the one path that has to decide, per volume, between a connection to close
//! and bytes to delete.
//!
//! Neither stops at the first failure: both collect what went wrong and say
//! it in one sentence, because a driver that refuses says nothing about the
//! next one and the caller drives the whole thing again anyway.
//!
//! Moved out of `provision.rs` unchanged.

use super::*;

impl Provisioner {
    #[instrument(skip(self), fields(vm_id = %id))]
    pub async fn teardown(&self, id: &VmId) -> Result<()> {
        let Some(record) = self.store.get(id)? else {
            return Ok(());
        };

        let mut failures: Vec<String> = Vec::new();
        // Whether this node was WAITING for a guest that never came, which is
        // the one teardown that has to give back more than a connection. See
        // the referenced-volume arm below.
        let abandoned_reception = record.phase == Phase::Receiving;

        if let Err(e) = self.drivers.confiner.kill_slice(&id.to_string()) {
            failures.push(format!("cgroup kill: {e}"));
        }

        // A record exists, so this node HAD a hypervisor when the VM was
        // provisioned. Not having one now means somebody removed the section
        // under a running VM, and that is a failure like any other in this
        // list: the VMM is still there and nobody can reach it.
        match self.drivers.hypervisor() {
            Ok(hv) => match timed_driver(HYPERVISOR, "destroy", hv.destroy(id)).await {
                Ok(()) | Err(HypervisorError::NotFound(_)) => {}
                Err(e) => failures.push(format!("hypervisor destroy: {e}")),
            },
            Err(e) => failures.push(format!("hypervisor destroy: {e:#}")),
        }

        // Flat on purpose: every one of these three loops is "find the driver
        // that made the thing, ask it to unmake it, and note it down if that
        // did not work". A missing driver is a failure like any other — the
        // resource is still there and nobody can reach it — so it takes the
        // same `failures.push` and the `else` that skips the rest.
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
                // Same shape as the missing volume driver below: the tap is
                // still on the host and nobody can take it down.
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

        // And the tenant's overlay, when this VM was the last thing on the
        // node that used it.
        //
        // The half `ensure_overlay` never had. A node used to gain a bridge
        // and a VXLAN device the first time a tenant put a VM on it and keep
        // both for ever — no isolation break, because the VNI allocator is a
        // monotonic counter and never hands a number out twice, but unbounded
        // growth in links on a machine that runs VMs for a living.
        //
        // Only after the taps are down, and only if they came down: an
        // overlay whose bridge still has a port is an overlay in use, and
        // taking it out from under a tap that would not go away is how a leak
        // turns into a broken VM. Everything else in `failures` is deliberately
        // NOT part of the condition — a volume that would not detach says
        // nothing about a bridge, and the teardown is driven again anyway,
        // which counts again from the same records.
        for vni in overlay_vnis(&record) {
            if !taps_gone {
                debug!(vni, "overlay left standing: a tap of this vm is still up");
                continue;
            }
            // What the record says this VM's overlay was called, where it says
            // anything. A driver whose own name for the VNI is a different one
            // did not build this overlay and refuses to take it down — which
            // is the whole reason the name is on the record.
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
                // Not a failure of this teardown. The overlay stays, which is
                // what it did before any of this existed, and the next VM to
                // leave asks the same question again.
                Err(e) => warn!(vni, error = %format!("{e:#}"),
                                "cannot count the users of this overlay, leaving it up"),
            }
        }

        // Detach before deprovision, always. Deleting the bytes out from
        // under a live backend process is the one ordering that can lose data
        // rather than merely leak it, and this is the loop that used to do
        // both in one call — the nfs driver stopped its virtiofsd inside
        // `destroy` and nothing outside said so.
        //
        // A failed detach does NOT skip the deprovision. It could not before
        // either: `stop_backend` returned nothing and its outcome never
        // reached this loop, so the data went whatever happened to the
        // process. Both failures are recorded, which is more than the old
        // shape could say.
        //
        // ONE detach per attachment. `stop` already gave these back if it ran
        // — a `stop` followed by a `destroy` is the ordinary way a VM ends —
        // and asking a driver to detach a connection nobody holds is not the
        // harmless no-op it looks like: the driver's own map lost the entry
        // with the first call, so the second falls through to the pid on the
        // record, and a pid is a number the kernel hands out again.
        // What this pass really closed. Written back below, and the reason it
        // is collected rather than acted on per volume is that `record` is
        // borrowed for the length of this loop.
        let mut closed: Vec<VolumeId> = Vec::new();
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
            // And here the two shapes part for good. An inline disk was made
            // with this VM and goes with it. A REFERENCED one belongs to a
            // `Volume` object that outlives this VM by definition — the
            // connection ends, the data stays, and the record in the volume
            // table stays with it. Deprovisioning here would make "delete the
            // vm" and "delete the disk" one act again, which is the whole
            // thing the object exists to take apart.
            if volume_is_referenced(&record, &id) {
                // ...unless this node never had the guest. A reception that
                // was torn down opened these disks for a guest that never
                // arrived, so what this node holds for them is a claim it has
                // no business with — `nvmeof-import`'s note over a namespace,
                // which is per node and which `detach` does not touch. The
                // lab found two of them on agent-1b after a run, for volumes
                // it never held (D-P20).
                //
                // `forget` and never `deprovision`: the distance between the
                // two is somebody's data, and the bytes here belong to a
                // guest that is running on another machine. For every backend
                // but that one it does nothing at all.
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

        // The detaches this pass managed, written down at once — the same
        // rule every other link of the chain follows, and here it answers two
        // things at once.
        //
        // A teardown that fails keeps its record and is driven again, and
        // until now the second attempt could not know that the first one had
        // already given a connection back. The loop above says in full why
        // that matters: a second detach is not a no-op, it falls through to a
        // pid the kernel may have handed to somebody else.
        //
        // And it is what makes `VolumeStateReport.open` true rather than
        // approximately true: the tier above derives `openOn` from that field,
        // so the moment a disk is really closed has to be the moment it stops
        // being in the set — even though this record will usually be gone
        // three lines further down, and even though a crash could land in
        // between.
        if !closed.is_empty()
            && let Err(e) = self.store.mutate(id, |r| {
                for v in r.volumes.iter_mut().filter(|v| closed.contains(&v.id())) {
                    v.detached = true;
                }
            })
        {
            // Not a failure of the teardown: the connections ARE closed, and
            // saying otherwise would keep a record that has nothing left to
            // give back. It is worth a line, because the next attempt will
            // detach again on the strength of a record that could not be
            // updated.
            warn!(error = %format!("{e:#}"),
                  "could not write down which volumes this teardown closed");
        }

        // The seed goes with the VM. Written from the spec on every
        // provision, so nothing is lost by removing it and a file per vm id
        // that ever existed is what keeping it would cost.
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
            // Both, before a SIGKILL. The slice is the older half of the
            // check and it is not enough on its own: a slice outlives a crash
            // that failed to remove it, and a pid outlives the process it
            // named. `owns_pid` is the half that asks whether the thing at
            // that number is still this VM's VMM.
            if in_slice && hypervisor.owns_pid(id, pid) {
                warn!(pid, "vmm survived destroy, killing it directly");
                let _ = nix::sys::signal::kill(
                    nix::unistd::Pid::from_raw(pid as i32),
                    nix::sys::signal::Signal::SIGKILL,
                );
            } else if in_slice {
                // The slice still names the pid and the process behind that
                // number is not this VM's VMM. Two ways to get here, and only
                // one of them is anybody's problem: the process is GONE —
                // ordinary, the driver's own destroy above got there first
                // and a real cgroup would already have dropped the entry — or
                // somebody else holds the number, which is the case this
                // guard exists for and the one worth waking an operator for.
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

        // A stopped VM keeps its volumes but must not keep a backend process
        // running for a VM that is not there. `detach` and not `destroy`: the
        // data stays, only the process serving it goes — and a driver whose
        // volumes are plain paths has nothing to do here.
        //
        // And it is written down. A detach that nobody records is a detach the
        // teardown after it repeats, and the repeat is the dangerous one: by
        // then the driver's map is empty and the only handle left is the pid
        // on the record. Marked on SUCCESS only — a detach that failed leaves
        // something holding on, and the teardown should try again.
        //
        // The mark is set on `record` before it is written back at the end of
        // this function, so it survives an agent restart between the stop and
        // the destroy the same way the rest of the record does.
        // Which driver made which volume, answered before the list is
        // borrowed mutably: `volume_driver_name` reads the record's own spec.
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
