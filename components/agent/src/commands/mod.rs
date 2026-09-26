// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Controller command dispatch, trace propagation and error classification.

use super::*;

mod console;
mod image;
mod migration;
mod router;
mod state;
mod vm;
mod volume;

impl Agent {
    /// Dispatch under the supplied trace context, or a new root when it cannot
    /// be parsed. Driver work inherits this command span.
    pub(crate) async fn dispatch(&self, cmd: proto::Command) -> CommandResult {
        let context = telemetry::TraceParent::parse(&cmd.traceparent)
            .unwrap_or_else(telemetry::TraceParent::root);
        let span = tracing::info_span!(
            "dispatch",
            request_id = %cmd.request_id,
            trace_id = %context.trace_id_hex()
        );
        telemetry::in_trace(span, &context, self.dispatch_traced(cmd)).await
    }

    async fn dispatch_traced(&self, cmd: proto::Command) -> CommandResult {
        let request_id = cmd.request_id.clone();
        // Most mutating commands acknowledge with an empty payload; handlers that
        // return data, including migration preparation, supply their own payload.
        let done = |r: anyhow::Result<()>| r.map(|()| Vec::new());
        let op_result = match cmd.op {
            Some(command::Op::Create(c)) => done(self.handle_create(c).await),
            Some(command::Op::Destroy(d)) => done(self.handle_destroy(d).await),
            Some(command::Op::Start(s)) => done(self.lifecycle(&s.id, Desired::Running).await),
            Some(command::Op::Stop(s)) => done(self.handle_stop(s).await),
            Some(command::Op::Pause(p)) => done(self.handle_pause(p).await),
            // Resume requests Running, including for a VM that is not currently paused.
            Some(command::Op::Resume(r)) => done(self.lifecycle(&r.id, Desired::Running).await),
            Some(command::Op::Logs(l)) => self.handle_logs(l),
            Some(command::Op::ProvisionVolume(v)) => done(self.handle_provision_volume(v).await),
            Some(command::Op::DeprovisionVolume(v)) => {
                done(self.handle_deprovision_volume(v).await)
            }
            Some(command::Op::ForgetVolume(v)) => done(self.handle_forget_volume(v).await),
            Some(command::Op::SnapshotVolume(v)) => done(self.handle_snapshot_volume(v).await),
            Some(command::Op::DropSnapshot(v)) => done(self.handle_drop_snapshot(v).await),
            Some(command::Op::ResizeVolume(v)) => done(self.handle_resize_volume(v).await),
            Some(command::Op::ResizeAttachment(v)) => done(self.handle_resize_attachment(v).await),
            Some(command::Op::PrepareMigration(m)) => self.handle_prepare_migration(m).await,
            Some(command::Op::MigrateOut(m)) => done(self.handle_migrate_out(m).await),
            Some(command::Op::CleanupMigration(c)) => done(
                async {
                    let id: VmId = c.id.parse().context("invalid vm id")?;
                    let _guard = self.ops.lock().await;
                    self.provisioner
                        .cleanup_migration(&id, &c.migration_id, c.source)
                        .await
                }
                .await,
            ),
            Some(command::Op::EnsureRouter(r)) => done(self.handle_ensure_router(r).await),
            Some(command::Op::DestroyRouter(r)) => done(self.handle_destroy_router(r).await),
            Some(command::Op::DropImage(d)) => done(self.handle_drop_image(d).await),
            None => Err(anyhow!("command without op")),
        };
        let outcome = match op_result {
            Ok(payload) => {
                info!("command ok");
                command_result::Outcome::Ok(proto::Ack { payload })
            }
            Err(e) => {
                let message = format!("{e:#}");
                if heals_without_an_operator(&e) {
                    warn!(error = %message, "command failed");
                } else {
                    error!(error = %message, "command failed");
                }
                // Only structural `CannotServe` failures request rescheduling. Other
                // errors retain the empty reason used for retries on this node.
                let reason = match e.downcast_ref::<CannotServe>().is_some() {
                    true => proto::CANNOT_SERVE.to_string(),
                    false => String::new(),
                };
                command_result::Outcome::Error(proto::ErrorMsg { message, reason })
            }
        };
        CommandResult {
            request_id,
            outcome: Some(outcome),
        }
    }
}
