// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! The second entrance to the chain and its second exit: a guest that
//! arrives here, and a guest that leaves.
//!
//! What a migration adds to this node is narrow on purpose. `prepare_migration`
//! runs the same chain a create runs and stops one step short of a VM, so a
//! transfer that never happens leaves an ordinary half-built record that the
//! ordinary `teardown` takes apart. `migrate_out` is the only call of the whole
//! move that touches the source, and it is the last one.
//!
//! Moved out of `provision.rs` unchanged.

use super::*;
use tracing::error;

/// Locally established terminal evidence. All other observations remain unknown.
enum Departure {
    /// The source VMM is gone. Success additionally requires destination evidence.
    Gone,
    /// The guest is still being served here, and why that is known.
    StillHere(String),
}

impl Provisioner {
    /// Make this node ready to RECEIVE `id`, and return the address the
    /// source should send to.
    ///
    /// The second entrance to the same chain `provision` runs, and the record
    /// it leaves behind is an ordinary record in every way but its phase.
    /// That matters more than it looks: if the migration fails, what is
    /// standing here is a normal half-built VM, and `teardown` — which knows
    /// nothing about migrations — takes it apart correctly.
    ///
    /// **A VM this node already has is refused.** A migration into a record
    /// that exists is either the same guest twice or a name collision, and
    /// both are worse than not moving.
    ///
    /// A ROW that exists is refused too, whether or not this build can read
    /// it: `Store::get` answers "unknown" for bytes it cannot deserialise,
    /// which is right for a reader describing the node and wrong for the
    /// admission check that stands in front of a guest's disks. Astra finding
    /// S11, 2026-09-23.
    #[instrument(skip(self, spec), fields(vm_id = %id, listen))]
    pub async fn prepare_migration(
        &self,
        id: VmId,
        spec: AgentVmSpec,
        listen: &str,
        managed_by_controller: bool,
        migration_id: &str,
    ) -> Result<()> {
        anyhow::ensure!(
            !migration_id.is_empty(),
            "migration requires an operation identity"
        );
        match self.store.row(&id)? {
            None => {}
            Some(crate::store::VmRow::Record(..)) => {
                bail!("this node already has a record of vm {id}; it cannot receive it as well");
            }
            Some(crate::store::VmRow::Unreadable(key)) => {
                bail!(
                    "this node has a record of vm {key} that it cannot read; it cannot receive \
                     the vm as well. The row has to be looked at before this node takes the \
                     guest: receiving over it would build a second vmm on top of whatever it \
                     describes."
                );
            }
        }
        // An inline disk is an instance store: it was MADE with the vm, on
        // the machine the vm was made on, and it has no `Volume` object
        // behind it that could be reached from anywhere else. So the config
        // that arrives in the stream would name a file that this node would
        // have to invent — and a guest resuming onto a blank disk is worse
        // than a migration that does not happen.
        //
        // The refusal names the disk, because "it has an inline disk" is not
        // something an operator can act on and "drop this one and give it a
        // volume" is.
        if let Some(inline) = spec.volumes.iter().find(|v| !v.referenced) {
            bail!(
                "vm {id} has an inline disk ({}): it is an instance store, made with the vm on \
                 the machine it is standing on, and no live migration takes it along. Give the \
                 vm a `Volume` on a shared or networked pool instead.",
                inline.id
            );
        }

        self.check_device_admission(&id, &spec)?;
        anyhow::ensure!(
            self.store.claim_migration(&id, migration_id, false)?,
            "migration attempt was already handled or cancelled"
        );

        let mut record = VmRecord {
            spec,
            desired: Desired::Running,
            vmm_pid: None,
            overlay_bridges: Default::default(),
            phase: Phase::Provisioning,
            // The reconciler's hands-off marker, set for the whole of the
            // approach: between the first driver call and a listening VMM
            // this record passes through every phase a broken provision
            // passes through, and a pass that ran in the middle would read
            // one of them as work to redo.
            operation: Some(Operation::MigratingIn {
                peer: listen.to_string(),
            }),
            stop_deadline: None,
            receive_deadline: None,
            send_failed: None,
            migration: Some(crate::types::MigrationAttempt {
                id: migration_id.into(),
                peer: listen.into(),
                incoming: true,
                accepted: false,
                unknown: None,
            }),
            unhealthy: None,
            managed_by_controller,
            unattached_volumes: Vec::new(),
            volumes: vec![],
            nics: vec![],
            devices: vec![],
        };
        self.store.put(&id, &record)?;

        let result = self
            .run_chain(&id, &mut record, Finish::Receive { listen })
            .await;
        // The marker comes off either way — success hands the record to the
        // migration's own phase, failure hands it to the teardown below.
        record.operation = None;
        match result {
            Ok(()) => {
                self.store.put(&id, &record)?;
                Ok(())
            }
            Err(e) => {
                let _ = self.store.put(&id, &record);
                warn!(error = %format!("{e:#}"), "preparing to receive failed, tearing down");
                if let Err(td) = self.teardown(&id).await {
                    return Err(e.context(format!(
                        "teardown after a failed migration prepare also failed: {td:#}"
                    )));
                }
                Err(e)
            }
        }
    }

    /// Start sending this VM's guest to `peer`. Answering means the stream is
    /// open, NOT that the guest has gone.
    ///
    /// **The only call in a migration that touches the source**, and it is
    /// the last one: by the time it is made, the destination has a VMM
    /// listening and every disk and tap the arriving config names. Everything
    /// before it can fail without the guest noticing.
    ///
    /// # Why this returns before the transfer is over
    ///
    /// Because the tier above was waiting for it, and a guest's memory takes
    /// as long as it takes. The cluster's reconcile pass called this through
    /// the session and awaited the ack — 300 ms of pass time on a small
    /// guest, up to 45 s on a large one, and for the whole of that no other VM
    /// in the cluster was placed or repaired. That is migration D16, and it
    /// is a shape problem rather than a slow function: an operation measured
    /// in a network's throughput has no business being a command's answer.
    ///
    /// So the answer is "accepted" and the OUTCOME travels on the status
    /// road, which is where every other fact about this node travels
    /// (`MigrationReport`, read off the record by `departure`). The tier above
    /// reads it instead of waiting for it.
    ///
    /// What this still does synchronously is everything that can be wrong
    /// with the REQUEST: no record, a guest that is not running, a hypervisor
    /// that cannot migrate, a `vm.send-migration` v53 refuses outright. All
    /// four leave the guest untouched, all four are the caller's to hear
    /// about at once, and none of them takes longer than a unix socket
    /// round trip.
    ///
    /// # Why the node's operation lock is an argument
    ///
    /// Because it must be RELEASED for the wait, and a caller that took it
    /// around the whole call could not do that. This is the whole of D-P4:
    /// after a send that cloud-hypervisor failed, agent-1a answered no
    /// command at all — every one of them ran into the controller's 60 s
    /// timeout — while its unit, its reconciler and its heartbeat all looked
    /// healthy, and a `vm create` on that node went `Failed` because of it.
    /// Nothing was wrong with the node: this function was holding the lock
    /// every other command needs, waiting ten minutes for a process that had
    /// gone back to serving its guest and was never going to exit.
    ///
    /// A transfer is not an operation on this node's devices and slices,
    /// which is what that lock is for. What keeps a second hand off THIS vm
    /// meanwhile is the `MigratingOut` marker on its record, which is the
    /// per-VM exclusion and the one the reconciler reads — and it is written
    /// here, before this returns, so the pass that runs one millisecond after
    /// the ack already sees it.
    #[instrument(skip(self, ops), fields(vm_id = %id, peer))]
    pub async fn begin_migrate_out(
        &self,
        id: &VmId,
        peer: &str,
        migration_id: &str,
        ops: &tokio::sync::Mutex<()>,
    ) -> Result<()> {
        anyhow::ensure!(
            !migration_id.is_empty(),
            "migration requires an operation identity"
        );
        let hypervisor = self.drivers.hypervisor()?;
        let migratable = hypervisor.as_migratable().ok_or_else(|| {
            anyhow!(
                "this node's hypervisor cannot send a live migration; \
                 the vm has to move by reboot instead"
            )
        })?;

        let _guard = ops.lock().await;
        let mut record = self
            .store
            .get(id)?
            .ok_or_else(|| anyhow!("this node has no record of vm {id}"))?;
        if record.phase != Phase::Provisioned || record.vmm_pid.is_none() {
            bail!(
                "vm {id} is not running here ({:?}); only a running guest migrates live",
                record.phase
            );
        }
        // A send that is already running is not started again.
        //
        // Astra finding S06, 2026-09-23: the marker below was written over
        // whatever was there, so a second `MigrateOut` for a guest that was
        // already being sent overwrote the peer of the transfer in flight and
        // started a second `migrate_out` against the same VMM. What the
        // record then named was the second destination, so the task watching
        // the first send wrote its outcome against the wrong address — and
        // the guest would have been offered to two machines at once.
        //
        // The refusal names the address the guest is already going to,
        // because that is what tells the caller which of the two migrations
        // is the real one.
        if let Some(op) = &record.operation {
            let under_way = format!("{op:?}");
            bail!(
                "vm {id} is already being sent to {under_way}; a guest is sent to one machine \
                 at a time"
            );
        }
        anyhow::ensure!(
            self.store.claim_migration(id, migration_id, false)?,
            "migration attempt was already handled"
        );
        record.migration = Some(crate::types::MigrationAttempt {
            id: migration_id.into(),
            peer: peer.into(),
            incoming: false,
            accepted: false,
            unknown: None,
        });
        // Hands off for the length of the transfer. The guest is paused
        // near the end of it, and a pass that saw a paused guest under a
        // Running record would resume it — into a copy of itself.
        record.operation = Some(Operation::MigratingOut {
            peer: peer.to_string(),
        });
        // And the last attempt's verdict goes, because this is a new one. A
        // `StillHere` left standing would be reported beside a send that is
        // running, and the tier above would read the old sentence as this
        // migration's.
        record.send_failed = None;
        self.store.put(id, &record)?;

        if let Err(e) =
            timed_driver(HYPERVISOR, "migrate_out", migratable.migrate_out(id, peer)).await
        {
            record.migration.as_mut().unwrap().unknown =
                Some(format!("send acceptance is unknown: {e}"));
            self.store.put(id, &record)?;
            bail!("sending vm {id} to {peer}: {e}");
        }
        record.migration.as_mut().unwrap().accepted = true;
        self.store.put(id, &record)?;
        info!("the stream is open; the guest is on its way");
        Ok(())
    }

    /// Watch a single durable attempt. A deadline ends this task, not ownership.
    pub async fn finish_migrate_out(
        &self,
        id: &VmId,
        peer: &str,
        migration_id: &str,
        started: std::time::Instant,
        ops: &tokio::sync::Mutex<()>,
    ) {
        loop {
            match self.observe_send(id, migration_id, ops).await {
                Ok(true) => return,
                Ok(false) => {}
                Err(e) => {
                    error!(error = %e, "cannot observe migration");
                    return;
                }
            }
            if started.elapsed() >= self.ceilings.migrate_out {
                let _guard = ops.lock().await;
                if let Ok(Some(mut record)) = self.store.get(id) {
                    if record.operation.is_some()
                        && record
                            .migration
                            .as_ref()
                            .is_some_and(|m| m.id == migration_id && m.peer == peer)
                    {
                        record.migration.as_mut().unwrap().unknown =
                            Some("send deadline elapsed; transfer outcome is unknown".into());
                        if let Err(e) = self.store.put(id, &record) {
                            error!(error = %e, "cannot record unknown outcome");
                        }
                    }
                }
                return;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    /// One bounded observation, also called by reconciliation after task loss.
    /// No repair is permitted while this returns an unresolved outcome.
    pub(crate) async fn observe_send(
        &self,
        id: &VmId,
        migration_id: &str,
        ops: &tokio::sync::Mutex<()>,
    ) -> Result<bool> {
        let Some(snapshot) = self.store.get(id)? else {
            return Ok(true);
        };
        if !matches!(snapshot.operation, Some(Operation::MigratingOut { .. })) {
            return Ok(true);
        }
        let Some(attempt) = &snapshot.migration else {
            return Ok(false);
        };
        if attempt.id != migration_id || attempt.incoming {
            return Ok(true);
        }
        let hypervisor = self.drivers.hypervisor()?;
        let Some(migratable) = hypervisor.as_migratable() else {
            return Ok(false);
        };
        let departure = if hypervisor.probe(id).await {
            if attempt.accepted {
                migratable.send_failed(id).await.map(Departure::StillHere)
            } else {
                None
            }
        } else if snapshot
            .vmm_pid
            .is_some_and(|pid| !hypervisor.owns_pid(id, pid))
        {
            Some(Departure::Gone)
        } else {
            None
        };
        let Some(departure) = departure else {
            return Ok(false);
        };
        let _guard = ops.lock().await;
        let Some(mut record) = self.store.get(id)? else {
            return Ok(true);
        };
        // A watcher from an older attempt must never clear a newer one's guard.
        if record.migration.as_ref() != Some(attempt)
            || !matches!(record.operation, Some(Operation::MigratingOut { .. }))
        {
            return Ok(true);
        }
        record.operation = None;
        record.migration.as_mut().unwrap().unknown = None;
        match departure {
            Departure::Gone => {
                record.phase = Phase::Migrated;
                record.vmm_pid = None;
                record.send_failed = None;
                // Persist the repair barrier before any detach side effect.
                self.store.put(id, &record)?;
                self.detach_volumes(id, &mut record).await;
            }
            Departure::StillHere(why) => record.send_failed = Some(why),
        }
        self.store.put(id, &record)?;
        Ok(true)
    }

    /// Attempt-scoped cleanup. Cancellation also fences a delayed prepare.
    pub(crate) async fn cleanup_migration(
        &self,
        id: &VmId,
        migration_id: &str,
        source: bool,
    ) -> Result<()> {
        anyhow::ensure!(
            !migration_id.is_empty(),
            "migration cleanup requires an operation identity"
        );
        // A corrupt VM row is not an absent VM.
        let record = match self.store.row(id)? {
            None => None,
            Some(crate::store::VmRow::Record(_, record)) => Some(record),
            Some(crate::store::VmRow::Unreadable(_)) => {
                bail!("cannot verify migration ownership of unreadable vm {id}")
            }
        };
        if let Some(record) = &record {
            let attempt = record
                .migration
                .as_ref()
                .ok_or_else(|| anyhow!("legacy migration requires recovery"))?;
            anyhow::ensure!(
                attempt.id == migration_id && attempt.incoming != source,
                "migration cleanup does not own this record"
            );
            if source {
                anyhow::ensure!(
                    record.phase == Phase::Migrated && record.operation.is_none(),
                    "source departure has not been established"
                );
            } else {
                anyhow::ensure!(
                    record.phase != Phase::Provisioned,
                    "destination already received the guest"
                );
                anyhow::ensure!(
                    !matches!(
                        self.drivers.hypervisor()?.get_state(id).await,
                        Ok(agent_api::VmState::Running | agent_api::VmState::Paused)
                    ),
                    "destination may hold the guest"
                );
            }
        }
        self.store.claim_migration(id, migration_id, true)?;
        self.teardown(id).await
    }

    /// The guest arrived: a record that was `Receiving` is an ordinary
    /// provisioned VM from here on.
    ///
    /// Driven by the reconciler off the hypervisor's own answer rather than
    /// by anything the control plane says, because the moment is the
    /// hypervisor's to know: the driver reads `migration-receive-finished`
    /// out of the event file and only then does `get_state` speak for the
    /// guest again.
    pub(crate) async fn migration_arrived(&self, id: &VmId) -> Result<()> {
        let Some(mut record) = self.store.get(id)? else {
            return Ok(());
        };
        if record.phase != Phase::Receiving {
            return Ok(());
        }
        record.phase = Phase::Provisioned;
        // Nothing is waited for any more, so nothing gives up any more.
        record.receive_deadline = None;
        self.store.put(id, &record)?;
        info!(vm_id = %id, "the guest arrived; this node is running it");
        Ok(())
    }

    /// The second exit of the chain: no VM is created here, only a VMM
    /// listening for one that is on its way.
    pub(super) async fn receive(
        &self,
        id: &VmId,
        record: &mut VmRecord,
        listen: &str,
        cgroup: &agent_api::CgroupHandle,
    ) -> Result<()> {
        // No `create` and no `start`, and neither is an omission. v53 refuses
        // `vm.receive-migration` outright when a VM has been created ("Can't
        // receive a migration when a VM is already created") and builds the
        // destination's VM from the `VmMigrationConfig` that arrives in the
        // stream — so the only thing this node contributes is a VMM with no
        // VM in it and everything that config will name, standing at the same
        // paths. That is what the chain above just built.
        let hypervisor = self.drivers.hypervisor()?;
        let migratable = hypervisor.as_migratable().ok_or_else(|| {
            anyhow!(
                "this node's hypervisor cannot receive a live migration; \
                     the vm has to move by reboot instead"
            )
        })?;
        let vmm_pid = timed_driver(HYPERVISOR, "migrate_in", migratable.migrate_in(id, listen))
            .await
            .context("hypervisor migrate_in")?;
        record.vmm_pid = Some(vmm_pid);
        // The VMM is attached to the slice here rather than by the driver,
        // for the same reason `create` does it: the process has to be inside
        // the guest's allowance before the guest's memory arrives, and the
        // whole of a migrating guest's memory arrives at once.
        //
        // And the failure is handled the way `create` handles it — kill the
        // process, answer with the error — rather than warned about. Astra
        // finding S17, 2026-09-23: this used to log and carry on, so the
        // record went to `Receiving` with a VMM outside the guest's
        // allowance, and the whole of a guest's memory then arrived into a
        // process the node's accounting does not cover. It is also the one
        // failure that leaves nothing behind to repair it: the pid is not on
        // the record yet, so a teardown that ran later would tear down every
        // part of this reception EXCEPT the VMM, and what is left is a
        // listening process nobody has a record of.
        if let Err(e) = cgroup.attach_pid(vmm_pid) {
            warn!(error = %format!("{e:#}"), pid = vmm_pid,
                  "could not put the receiving vmm in its slice; ending it");
            // Best effort and logged, not propagated: the error the caller
            // has to see is the one that made this reception impossible, and
            // the teardown the caller runs next asks for this again.
            if let Err(gone) = timed_driver(HYPERVISOR, "destroy", hypervisor.destroy(id)).await {
                error!(error = %format!("{gone:#}"), pid = vmm_pid,
                       "and the receiving vmm could not be ended either");
            }
            record.vmm_pid = None;
            return Err(anyhow::Error::new(e).context(format!(
                "putting the receiving vmm for vm {id} in its slice"
            )));
        }
        record.phase = Phase::Receiving;
        // An advisory deadline, persisted with the reception. It must never
        // authorize teardown: the VMM can still be receiving when it expires.
        // Written down beside the
        // phase rather than held in the task that started it: the task dies
        // with the agent and the record does not, and an agent that came back
        // to a `Receiving` record with nothing to end it is exactly the ghost
        // the lab found — a VMM and a live NVMe/TCP session held for a guest
        // that had been running on another machine for hours.
        record.receive_deadline = Some(std::time::SystemTime::now() + self.ceilings.receive);
        self.store.put(id, record)?;
        info!(pid = vmm_pid, listen, "listening for the guest");
        Ok(())
    }
}
