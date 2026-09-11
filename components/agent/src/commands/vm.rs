// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! The verbs about a VM itself — create it, stop it, pause it, destroy it
//! — and the three steps they share: claim it, write the desired state,
//! answer if there was nothing to write it on.

use super::*;

impl Agent {
    /// Create is idempotent by id: the controller sends it once for a new VM
    /// and repeats the whole set as a SyncState on every reconnect.
    pub(super) async fn handle_create(&self, c: proto::CreateInstance) -> anyhow::Result<()> {
        let id: VmId = c.id.parse().context("invalid vm id")?;
        // spec_json wins: same format and same serde as the local REST API.
        let (spec, desired) = if !c.spec_json.is_empty() {
            let new_spec: crate::types::NewVmSpec =
                serde_json::from_str(&c.spec_json).context("invalid spec_json")?;
            let (_, spec, desired) = new_spec.into_spec(&self.default_bridge)?;
            (spec, desired)
        } else {
            let spec = c.spec.ok_or_else(|| anyhow!("create without spec"))?;
            let spec: AgentVmSpec = spec.try_into().context("invalid vm spec")?;
            (spec, Desired::Running)
        };

        if self.store.get(&id)?.is_some() {
            // Known already, and since storage B a re-sent spec can differ
            // from the one on record in exactly one way: `volumes[]` from its
            // second entry on, and there only entries that name a `Volume`
            // object. Everything else is refused a tier up
            // (`Owned::structural("spec.vm", …)`), so the diff is the whole
            // of what a re-create can mean besides the intent.
            //
            // The intent still goes through the lifecycle path a command
            // takes, so a create that means "stop" gets its grace period —
            // that was always true and stays true. What is new is the line
            // above it.
            self.claim(&id).await?;
            {
                let _guard = self.ops.lock().await;
                self.provisioner.sync_volumes(&id, &spec).await?;
            }
            return self.set_desired(id, desired).await.map(|_| ());
        }

        // The four structural questions, and what makes them structural is
        // that they are all about THIS NODE rather than about this attempt: a
        // node with no hypervisor, without the driver a device names, without
        // the backend a volume names, without the overlay a NIC names will
        // never be able to serve this VM, however often it is asked.
        //
        // So the refusal carries `CannotServe`, and no record is made. The
        // tier above answers it by taking the binding back and placing the VM
        // somewhere else — which is the one thing it must NOT do for a
        // failure after the record exists, because a boot that did not work
        // may work next time in the same place.
        cannot_serve(
            self.hypervisor
                .validate()
                .context("this node cannot run a vm"),
        )?;
        cannot_serve(
            self.catalog
                .validate(&spec.devices)
                .context("invalid device spec"),
        )?;
        cannot_serve(
            self.volumes
                .validate(&spec.volumes)
                .context("invalid volume spec"),
        )?;
        cannot_serve(
            self.network
                .validate(&spec.nics)
                .context("invalid nic spec"),
        )?;
        let _guard = self.ops.lock().await;
        self.provisioner.provision(id, spec, desired, true).await
    }

    /// The controller only ever names VMs it owns, so a record it sends is
    /// the controller's by definition. This is also the migration path:
    /// records written before the marker existed default to unmanaged and
    /// would otherwise stay outside every desired-state snapshot forever.
    async fn claim(&self, id: &VmId) -> anyhow::Result<()> {
        let _guard = self.ops.lock().await;
        let Some(mut record) = self.store.get(id)? else {
            return Ok(());
        };
        if record.managed_by_controller {
            return Ok(());
        }
        info!(vm_id = %id, "claiming pre-existing record as controller-managed");
        record.managed_by_controller = true;
        self.store.put(id, &record)
    }

    /// A desired state off the wire, with the grace a stop needs; whether the
    /// deadline is actually armed is `set_desired`'s call. `Ok(false)` means
    /// the record was gone — for a destroy that is the asked-for outcome, for
    /// a lifecycle command it is not.
    pub(super) async fn set_desired(&self, id: VmId, desired: Desired) -> anyhow::Result<bool> {
        let deadline = (desired == Desired::Stopped).then(|| SystemTime::now() + self.stop_grace);
        Ok(self
            .reconciler
            .set_desired(id, desired, deadline)
            .await?
            .is_some())
    }

    /// A lifecycle command names a VM the controller believes is here. If it
    /// is not, say so rather than acking a no-op: the controller's picture of
    /// this node is wrong, and its next SyncState is what repairs it.
    pub(super) async fn lifecycle(&self, raw_id: &str, desired: Desired) -> anyhow::Result<()> {
        let id: VmId = raw_id.parse().context("invalid vm id")?;
        if !self.set_desired(id, desired).await? {
            return Err(NoSuchVm(id).into());
        }
        Ok(())
    }

    pub(super) async fn handle_stop(&self, s: proto::StopInstance) -> anyhow::Result<()> {
        let id: VmId = s.id.parse().context("invalid vm id")?;
        let grace = s
            .grace_secs
            .map(Duration::from_secs)
            .unwrap_or(self.stop_grace);
        let armed = self
            .reconciler
            .set_desired(id, Desired::Stopped, Some(SystemTime::now() + grace))
            .await?;
        if armed.is_none() {
            return Err(NoSuchVm(id).into());
        }
        Ok(())
    }

    /// Same gate as the REST path: a driver that cannot pause must say so
    /// instead of parking a desired state it can never reach.
    pub(super) async fn handle_pause(&self, p: proto::PauseInstance) -> anyhow::Result<()> {
        if !self.pause_supported {
            bail!("hypervisor driver does not support pausing");
        }
        self.lifecycle(&p.id, Desired::Paused).await
    }

    pub(super) async fn handle_destroy(&self, d: proto::DestroyInstance) -> anyhow::Result<()> {
        let id: VmId = d.id.parse().context("invalid vm id")?;
        // A record that is already gone is exactly what a destroy wants.
        self.set_desired(id, Desired::Absent).await.map(|_| ())
    }
}
