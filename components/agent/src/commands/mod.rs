// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Payload to handler, and nothing else.
//!
//! The one table of this node's verbs. What it adds around a handler is the
//! two things every answer needs and no handler should have to know about:
//! the trace the command came in on, and whether the failure it is answering
//! with is somebody's to act on.

use super::*;

mod console;
mod migration;
mod router;
mod state;
mod vm;
mod volume;

impl Agent {
    /// One command, under the trace of whatever asked for it. Everything the
    /// dispatch reaches — provision, the volume and device drivers, the CH
    /// API calls — is a child span of this one, so `POST /vms` at the cloud
    /// edge and the backend spawn on this node are the same trace.
    ///
    /// The span is built and given its parent before it starts; see
    /// `telemetry::in_trace`. A command without a readable context is not an
    /// error — it gets its own root, and this node's work is still traceable,
    /// just not back to whoever asked for it.
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
        // Every command that CHANGES something answers with "done" and an
        // empty payload; the one that asks a question answers with bytes.
        // `done` is what makes the six mutating arms read as they always did.
        let done = |r: anyhow::Result<()>| r.map(|()| Vec::new());
        let op_result = match cmd.op {
            Some(command::Op::Create(c)) => done(self.handle_create(c).await),
            Some(command::Op::Destroy(d)) => done(self.handle_destroy(d).await),
            Some(command::Op::Start(s)) => done(self.lifecycle(&s.id, Desired::Running).await),
            Some(command::Op::Stop(s)) => done(self.handle_stop(s).await),
            Some(command::Op::Pause(p)) => done(self.handle_pause(p).await),
            // Resume is Start under another name — the REST path does not gate
            // it on pause support either, and a vm that is not paused simply
            // converges to Running.
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
            Some(command::Op::EnsureRouter(r)) => done(self.handle_ensure_router(r).await),
            Some(command::Op::DestroyRouter(r)) => done(self.handle_destroy_router(r).await),
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
                // One word, and only for the refusal that MEANS something up
                // there: a create this node cannot serve at all. Every other
                // failure stays bare, which is the meaning the tier above has
                // always assumed for a rejection — "about this VM here", to be
                // answered with a requeue in the same place.
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
