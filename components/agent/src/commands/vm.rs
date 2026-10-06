// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! VM creation and lifecycle commands, with controller ownership and desired-state updates.

use super::*;

impl Agent {
    /// Create idempotently by ID, including replay through reconnect snapshots.
    pub(super) async fn handle_create(&self, c: proto::CreateInstance) -> anyhow::Result<()> {
        let id: VmId = c.id.parse().context("invalid vm id")?;
        // spec_json wins: same format and same serde as the local REST API.
        let (spec, desired) = if !c.spec_json.is_empty() {
            let new_spec: crate::types::NewVmSpec =
                serde_json::from_str(&c.spec_json).context("invalid spec_json")?;
            new_spec.into_spec(id, &self.default_bridge)?
        } else {
            let spec = c.spec.ok_or_else(|| anyhow!("create without spec"))?;
            let spec: AgentVmSpec = spec.try_into().context("invalid vm spec")?;
            (spec, Desired::Running)
        };

        if self.store.get(&id)?.is_some() {
            // For known VMs, synchronize secondary referenced volumes and apply the
            // desired state through the lifecycle path, including stop grace handling.
            self.claim(&id).await?;
            {
                let _guard = self.ops.lock().await;
                self.provisioner.sync_volumes(&id, &spec).await?;
            }
            return self.set_desired(id, desired).await.map(|_| ());
        }

        // Refuse unsupported node capabilities before creating a record. The typed
        // CannotServe error lets the controller distinguish placement incompatibility
        // from a failed operation on resources already owned here.
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

        // Fetch missing images before acquiring the operations lock. The later
        // ensure inside provisioning reuses the cache. Controller command dispatch
        // remains sequential while this handler awaits the fetch.
        for source in &spec.images {
            self.images
                .ensure(source)
                .await
                .with_context(|| format!("base image {}", source.name))?;
        }

        let _guard = self.ops.lock().await;
        self.provisioner.provision(id, spec, desired, true).await?;
        // The recorder on the serial line, now, on this road as on the
        // socket's: a guest boots faster than the periodic pass comes round
        // (Reconciler::record_console says what that cost `vm logs`).
        self.reconciler.record_console(&id).await;
        Ok(())
    }

    /// Mark controller-named records as managed, including legacy records
    /// that defaulted to unmanaged.
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

    /// Apply a desired state with stop grace. `set_desired` decides whether to
    /// arm the deadline; `Ok(false)` means the record no longer exists.
    pub(super) async fn set_desired(&self, id: VmId, desired: Desired) -> anyhow::Result<bool> {
        let deadline = (desired == Desired::Stopped).then(|| SystemTime::now() + self.stop_grace);
        Ok(self
            .reconciler
            .set_desired(id, desired, deadline)
            .await?
            .is_some())
    }

    /// Report unknown lifecycle targets so the controller can repair its inventory.
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
