// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Migration endpoint resources and durable attempt ownership.
//!
//! Preparation shares the provisioning chain. A source operation blocks repair
//! until attempt-specific terminal evidence is persisted; deadlines preserve
//! unknown outcomes. Cleanup validates the attempt before releasing resources.

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
    /// Prepare a receiving VMM with a durable attempt identity. Any existing VM
    /// row, including an unreadable row, refuses reception. Inline disks are
    /// unsupported because their data is not transferred by this path.
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
        // Inline disks belong to the VM lifecycle and have no independent volume
        // object to resolve on the destination. Refuse migration and name the disk
        // that must be replaced by a referenced volume.
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
            // Block ordinary repair throughout destination resource preparation.
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

    /// Persist the attempt receipt and repair barrier before submitting the send.
    /// An acknowledgement means accepted, not transferred. Errors after submission
    /// leave acceptance unknown and retain the barrier.
    ///
    /// The operations lock covers submission and record writes, while the watcher
    /// releases it between observations. The controller learns terminal evidence
    /// through status reports.
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
        // An existing operation owns this VM. Do not replace its identity or peer
        // with a second send request.
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
        // Clear the previous attempt's verdict before reporting the new attempt.
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
                if let Ok(Some(mut record)) = self.store.get(id)
                    && record.operation.is_some()
                    && let Some(attempt) = record.migration.as_mut()
                    && attempt.id == migration_id
                    && attempt.peer == peer
                {
                    attempt.unknown =
                        Some("send deadline elapsed; transfer outcome is unknown".into());
                    if let Err(e) = self.store.put(id, &record) {
                        error!(error = %e, "cannot record unknown outcome");
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

    /// Persist arrival observed by the reconciler. Retain the incoming attempt
    /// so controller snapshots cannot reap the destination before binding moves.
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
        // The receive stream supplies VM configuration. Prepare matching paths,
        // then start a VMM without defining or booting a guest locally.
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
        // Attach the receiving VMM to the VM cgroup before completing preparation.
        // If attachment fails, attempt VMM destruction and let the caller retry cleanup.
        if let Err(e) = cgroup.attach_pid(vmm_pid) {
            warn!(error = %format!("{e:#}"), pid = vmm_pid,
                  "could not put the receiving vmm in its slice; ending it");
            // Preserve the original receive error; log cleanup failure for the caller's later teardown retry.
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
        // Persist an advisory receive deadline. Expiry cannot authorize teardown
        // while the VMM may still be receiving.
        record.receive_deadline = Some(std::time::SystemTime::now() + self.ceilings.receive);
        self.store.put(id, record)?;
        info!(pid = vmm_pid, listen, "listening for the guest");
        Ok(())
    }
}
