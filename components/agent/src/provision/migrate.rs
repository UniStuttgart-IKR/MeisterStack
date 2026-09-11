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

// The two ceilings this file used to hold as constants are `Ceilings` in
// `provision/mod.rs` now, set from `migrate_out_ceiling_secs` and
// `receive_ceiling_secs`. The arguments for the numbers are on that type; what
// is unchanged is that both must be longer than the cluster's own
// `migration_transfer_secs`, because the tier that ASKED for the migration is
// the one that decides it has failed.

/// What became of a guest this node was told to send.
///
/// Two words rather than a `bool` or an `Option<String>`, because the caller
/// writes a different record for each and the reader of that call should not
/// have to work out which way round `true` meant.
enum Departure {
    /// The source VMM is gone, which v53 does only when the send took.
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
    #[instrument(skip(self, spec), fields(vm_id = %id, listen))]
    pub async fn prepare_migration(
        &self,
        id: VmId,
        spec: AgentVmSpec,
        listen: &str,
        managed_by_controller: bool,
    ) -> Result<()> {
        if self.store.get(&id)?.is_some() {
            bail!("this node already has a record of vm {id}; it cannot receive it as well");
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
            unhealthy: None,
            managed_by_controller,
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
        ops: &tokio::sync::Mutex<()>,
    ) -> Result<()> {
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
            record.operation = None;
            self.store.put(id, &record)?;
            bail!("sending vm {id} to {peer}: {e}");
        }
        info!("the stream is open; the guest is on its way");
        Ok(())
    }

    /// Watch the send this node started, and write down how it ended.
    ///
    /// The half that used to be the second page of `migrate_out`, running in
    /// a task of its own now. Nothing about it changed except who awaits it:
    /// the lock is taken for the two short stretches that touch this node and
    /// dropped for the wait between them, exactly as before.
    ///
    /// It answers nothing to anybody. The record is the answer — `Migrated`,
    /// or `send_failed` with v53's own sentence — and `departure` turns it
    /// into the line the next heartbeat carries.
    ///
    /// A task dies with the agent, and the marker it leaves behind is cleared
    /// by `clear_orphaned_operation` on the next start, which is what that
    /// function has always been for. The transfer itself is the VMM's and
    /// survives both.
    #[instrument(skip(self, ops), fields(vm_id = %id, peer))]
    pub async fn finish_migrate_out(
        &self,
        id: &VmId,
        peer: &str,
        started: std::time::Instant,
        ops: &tokio::sync::Mutex<()>,
    ) {
        let Ok(hypervisor) = self.drivers.hypervisor() else {
            return;
        };
        let Some(migratable) = hypervisor.as_migratable() else {
            return;
        };
        let departure = self
            .watch_the_send(id, hypervisor, migratable, started)
            .await;

        let _guard = ops.lock().await;
        let mut record = match self.store.get(id) {
            Ok(Some(record)) => record,
            Ok(None) => {
                warn!("the record went while the vm was being sent; nothing to write");
                return;
            }
            Err(e) => {
                error!(error = %format!("{e:#}"), "cannot read the record of a vm that was sent");
                return;
            }
        };
        record.operation = None;
        match departure {
            Departure::Gone => {
                record.phase = Phase::Migrated;
                record.vmm_pid = None;
                record.send_failed = None;
                self.detach_volumes(id, &mut record).await;
                info!(
                    ms = started.elapsed().as_millis(),
                    "the guest left for the destination"
                );
            }
            // Still here, and that is the invariant this whole path is built
            // on arriving as news rather than as silence: v53 gives the guest
            // back on a failed send, so the vm is exactly where it was — and
            // the tier above is TOLD so, on the next heartbeat, instead of
            // being left to time out.
            Departure::StillHere(why) => {
                let sentence = format!(
                    "vm {id} is still running here {}s after the send to {peer} started: {why}. \
                     {}",
                    started.elapsed().as_secs(),
                    common::migration::GUEST_NOT_GIVEN_UP
                );
                warn!(reason = %why, "the send did not take; this node still has the guest");
                record.send_failed = Some(sentence);
            }
        }
        if let Err(e) = self.store.put(id, &record) {
            error!(error = %format!("{e:#}"),
                   "writing down what became of a send failed; the tier above will time out");
        }
    }

    /// Watch until the guest has left, or until it is certain it has not.
    ///
    /// Two questions per round and they answer different halves. The socket
    /// going quiet is SUCCESS — v53 exits the source VMM only when the send
    /// took — and the two cheaper answers to that half are both wrong, as the
    /// first live run measured: `is_tracked` reads the driver's own map,
    /// which nothing clears when a VMM exits of its own accord, and a pid
    /// stays in `/proc` as a zombie until somebody reaps the child, which is
    /// never, because nothing awaits it. Both said "alive" about a process
    /// that had finished.
    ///
    /// The other half is FAILURE, and until it was asked there was nothing to
    /// end this wait but the ceiling — ten minutes of a command that answers
    /// nothing while the guest it was about has been running here all along.
    async fn watch_the_send(
        &self,
        id: &VmId,
        hypervisor: &std::sync::Arc<dyn agent_api::hypervisor::Hypervisor>,
        migratable: &dyn agent_api::Migratable,
        started: std::time::Instant,
    ) -> Departure {
        let ceiling = self.ceilings.migrate_out;
        let deadline = started + ceiling;
        loop {
            if !hypervisor.probe(id).await {
                return Departure::Gone;
            }
            if let Some(why) = migratable.send_failed(id).await {
                return Departure::StillHere(why);
            }
            if std::time::Instant::now() >= deadline {
                return Departure::StillHere(format!(
                    "the transfer has not ended within {}s and this node stopped watching it",
                    ceiling.as_secs()
                ));
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
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
        if let Err(e) = cgroup.attach_pid(vmm_pid) {
            warn!(error = %format!("{e:#}"), pid = vmm_pid,
                      "could not put the receiving vmm in its slice");
        }
        record.phase = Phase::Receiving;
        // And the moment this node stops waiting. Written down beside the
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
