// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! The two verbs of a live migration, one for each end of it.

use super::*;

impl Agent {
    /// Make this node ready to receive a running guest, and answer with the
    /// address the source has to dial.
    ///
    /// The one command in this file whose Ack carries something the caller
    /// could not have worked out: which of this node's addresses a peer can
    /// reach it on, and which port is free. Both are the node's to know, and
    /// the string that comes back is in the hypervisor's own spelling and is
    /// passed on unopened.
    ///
    /// The two structural refusals come first, before anything is built and
    /// with `CannotServe` on them, for the reason the create path gives at
    /// length: they are about THIS NODE and this request rather than about
    /// this attempt, so the tier above answers them by choosing another
    /// destination instead of trying again here.
    pub(super) async fn handle_prepare_migration(
        &self,
        c: proto::PrepareMigration,
    ) -> anyhow::Result<Vec<u8>> {
        let id: VmId = c.id.parse().context("invalid vm id")?;
        // The same document a `CreateInstance` carries, read the same way:
        // the destination has to build what the arriving configuration will
        // name, so it has to read the spec the source was built from.
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

        // Where to listen. An explicit `listen` is honoured verbatim — a
        // caller with one hole in a firewall is the case it exists for — and
        // the empty string, which is what the cluster always sends, means
        // "choose", which is the node's own answer to its own question.
        let listen = match c.listen.is_empty() {
            true => cannot_serve(self.migration.listen_url())?,
            false => c.listen.clone(),
        };

        let _guard = self.ops.lock().await;
        self.provisioner
            .prepare_migration(id, spec, &listen, true)
            .await?;
        // JSON and not the bare string, because `Ack.payload` is bytes with
        // no type on them and a reader a year from now should not have to
        // guess which of the two it is holding.
        Ok(serde_json::to_vec(&serde_json::json!({ "peer": listen }))?)
    }

    /// Start sending this node's guest away. Answering means the stream is
    /// open — NOT that the guest has gone.
    ///
    /// The change D16 asked for, and it is a change of shape rather than of
    /// speed. The answer used to be the outcome, so the cluster's reconcile
    /// pass awaited it for the length of a transfer: 300 ms on a small guest,
    /// up to 45 s on a large one, and for all of it no other VM in that
    /// cluster was placed or repaired. An operation measured in a network's
    /// throughput has no business being a command's answer.
    ///
    /// So the split. Everything that can be wrong with the REQUEST is still
    /// answered here and at once — no record, a guest that is not running, a
    /// hypervisor that cannot migrate, a `vm.send-migration` v53 refuses —
    /// and all four leave the guest exactly where it was. What the outcome
    /// costs afterwards is one heartbeat: `MigrationReport` carries it up the
    /// status road, derived from this node's own record, and the tier above
    /// READS it instead of holding a pass open for it.
    ///
    /// The task is spawned and nobody awaits it. It dies with the agent, and
    /// what it leaves behind — a `MigratingOut` marker on the record — is
    /// what `clear_orphaned_operation` has cleared at start-up since long
    /// before this. The transfer itself belongs to the VMM and survives both.
    ///
    /// The lock is NOT taken around any of this: it goes down into
    /// `begin_migrate_out`, which holds it for the moment that touches this
    /// node's devices, and into the task, which takes it again to write the
    /// outcome down. Holding it here is what made agent-1a answer nothing for
    /// ten minutes after a send cloud-hypervisor had already failed — unit
    /// healthy, reconciler running, heartbeat green, and a `vm create` on
    /// that node going `Failed` at the controller's 60 s timeout.
    pub(super) async fn handle_migrate_out(&self, c: proto::MigrateOut) -> anyhow::Result<()> {
        let id: VmId = c.id.parse().context("invalid vm id")?;
        if c.peer.is_empty() {
            bail!("migrate-out without a peer address; the destination has to answer first");
        }
        let started = std::time::Instant::now();
        self.provisioner
            .begin_migrate_out(&id, &c.peer, &self.ops)
            .await?;

        let provisioner = self.provisioner.clone();
        let ops = self.ops.clone();
        let peer = c.peer.clone();
        let report_now = self.report_now.clone();
        tokio::spawn(async move {
            provisioner
                .finish_migrate_out(&id, &peer, started, &ops)
                .await;
            // The outcome is written down; say so now rather than up to ten
            // seconds from now. The tier above is waiting on exactly this
            // line, and the whole point of the split was to stop making it
            // wait for things it does not have to.
            report_now.notify_one();
        });
        Ok(())
    }
}
