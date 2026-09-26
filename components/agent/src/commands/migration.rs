// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! The two verbs of a live migration, one for each end of it.

use super::*;

impl Agent {
    /// Validate the destination capabilities and prepare reception. The reply is
    /// a JSON object containing the listening address chosen or supplied for this attempt.
    pub(super) async fn handle_prepare_migration(
        &self,
        c: proto::PrepareMigration,
    ) -> anyhow::Result<Vec<u8>> {
        let id: VmId = c.id.parse().context("invalid vm id")?;
        // Parse the source create document so destination resources match the incoming VM config.
        let new_spec: crate::types::NewVmSpec =
            serde_json::from_str(&c.spec_json).context("invalid spec_json")?;
        let (_, spec, _desired) = new_spec.into_spec(&self.default_bridge)?;

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

        // An explicit listen URL is used verbatim; an empty value selects a local endpoint.
        let listen = match c.listen.is_empty() {
            true => cannot_serve(self.migration.listen_url())?,
            false => c.listen.clone(),
        };

        let _guard = self.ops.lock().await;
        self.provisioner
            .prepare_migration(id, spec, &listen, true, &c.migration_id)
            .await?;
        // Encode the selected peer URL as a JSON acknowledgement payload.
        Ok(serde_json::to_vec(&serde_json::json!({ "peer": listen }))?)
    }

    /// Submit a migration send and start its outcome watcher. The command reply
    /// confirms acceptance only; durable reports carry the transfer outcome.
    /// Submission errors can leave acceptance unknown. Reconciliation continues
    /// observing the same attempt after watcher loss or agent restart.
    pub(super) async fn handle_migrate_out(&self, c: proto::MigrateOut) -> anyhow::Result<()> {
        let id: VmId = c.id.parse().context("invalid vm id")?;
        if c.peer.is_empty() {
            bail!("migrate-out without a peer address; the destination has to answer first");
        }
        let started = std::time::Instant::now();
        self.provisioner
            .begin_migrate_out(&id, &c.peer, &c.migration_id, &self.ops)
            .await?;

        let provisioner = self.provisioner.clone();
        let ops = self.ops.clone();
        let peer = c.peer.clone();
        let report_now = self.report_now.clone();
        tokio::spawn(async move {
            provisioner
                .finish_migrate_out(&id, &peer, &c.migration_id, started, &ops)
                .await;
            // Report the persisted outcome immediately instead of waiting for the next heartbeat.
            report_now.notify_one();
        });
        Ok(())
    }
}
