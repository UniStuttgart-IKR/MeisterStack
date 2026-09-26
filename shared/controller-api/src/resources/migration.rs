// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Migration intent, progress and evidence for one VM attempt.

use super::*;

/// Intent and progress for one live migration within a cluster. The resource
/// retains source, target and outcome after the operation ends. It is tenant
/// scoped and requires Operator write authority; drain may also create it.
#[derive(Clone, Debug, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VmMigrationSpec {
    /// Whose it is. Server-set from the VM's own tenant, never from the
    /// request: a migration of somebody's VM belongs to whoever the VM
    /// belongs to, and letting a caller name it would let them file the
    /// record in the wrong tenant's history.
    #[serde(default)]
    pub tenant: String,
    /// The VM to move, by name, in the same tenant.
    pub vm: String,
    /// Requested destination node. None lets placement choose, as used by a drain.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_node: Option<String>,
}

reasons! {
    /// Migration reason categories for controller progress and source outcomes. Reported refers
    /// to the typed DepartureOutcome retained separately in sourceReported; nodes do not send
    /// migration reason strings.
    VmMigrationReason [5] {
        /// Nobody recorded one — see `VmReason::Unrecorded`.
        #[default]
        Unrecorded => "Unrecorded",
        /// Waiting for a target to be chosen.
        AwaitingTarget => "AwaitingTarget",
        /// The destination is being built, or the stream is in the air.
        Dispatched => "Dispatched",
        /// This tier gave up on the transfer and tore the destination down.
        /// The source is still running — that is the invariant.
        Abandoned => "Abandoned",
        /// The source's own outcome, which is `status.sourceReported` — see
        /// this list's own doc for why this one word stays.
        Reported => "Reported",
    }
}

phases! {
    /// Migration progress. Succeeded and Failed are terminal operation results; a later attempt
    /// uses another migration resource.
    VmMigrationPhase / VmMigrationPhaseKind / VmMigrationReason / VmMigrationPhaseWire / VmMigrationReported [5] {
        /// Accepted, nothing done. No target chosen yet.
        Pending { reason, message, since } => "Pending",
        /// A target has been chosen and is being made ready: the record, the
        /// taps, the volumes attached THERE, and a VMM listening for the stream.
        Preparing { reason, message, since } => "Preparing",
        /// The source has been told to send. The guest is still the source's
        /// until it is not.
        Running { reason, message, since } => "Running",
        /// The attempt is recorded as completed and the binding moved to its target.
        /// The reconciler must establish matching Gone and Arrived evidence first.
        Succeeded { message, since } => "Succeeded",
        /// The attempt ended unsuccessfully with an explanation. This phase alone
        /// is not cleanup authority; unresolved ownership must remain nonterminal
        /// and retain recovery protection.
        Failed { reason, message, since } => "Failed",
    }
}

impl VmMigrationPhaseKind {
    /// Nothing will move this one again.
    pub fn is_final(self) -> bool {
        matches!(
            self,
            VmMigrationPhaseKind::Succeeded | VmMigrationPhaseKind::Failed
        )
    }

    /// Whether stuck detection expects further progress. Failed and Succeeded both end this
    /// operation.
    pub fn is_terminal(self) -> bool {
        self.is_final()
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct VmMigrationStatus {
    /// Durable operation identity. Missing on legacy records, which require recovery.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub migration_id: Option<String>,
    /// VM incarnation captured before prepare; reports must match it as well.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vm_uid: Option<String>,
    /// An unresolved outcome is nonterminal and retains its capacity reservation.
    #[serde(default)]
    pub recovery_required: bool,
    /// Persisted before cleanup so no replica may dispatch a send afterwards.
    #[serde(default)]
    pub cancelling: bool,
    /// The phase, with the reason it is that phase and since when.
    ///
    /// Flat on the wire — `phase`, `reason`, `message`, `since` as siblings
    /// right here — so every client that reads `status.phase` as a string
    /// goes on reading it as a string. See `resources::phase`.
    #[serde(flatten)]
    pub(super) phase: VmMigrationPhase,
    /// Evidence consumed by settle_vm_migration. Controller progress records have no node
    /// identity and cannot establish Succeeded; successful completion requires a machine
    /// report. Absent before the first decision.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reported: Option<VmMigrationReported>,
    /// The same field, with the same meaning, that every other object here
    /// carries: the last `metadata.generation` the reconciler ACTED on.
    #[serde(default)]
    pub observed_generation: u64,
    /// Where the VM was when this started. Written at `Preparing` and never
    /// again — it is what a `Failed` record is read for.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_node: Option<String>,
    /// Where it is going. Written when the scheduler chose, which for a
    /// migration with `spec.targetNode` is immediately.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_node: Option<String>,
    /// Destination listener returned by PrepareMigration, such as tcp:10.0.0.5:49000. The
    /// source uses this address to send the stream. None means no answer yet or an older
    /// record; peer_of supports the older message-based encoding.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub peer: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub started_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub finished_at: Option<DateTime<Utc>>,
    /// Attempt-bound destination evidence: `Provisioning` for `Receiving`,
    /// `Running` for `Arrived`. Ordinary VM status reports do not populate it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_reported: Option<String>,
    /// Attempt-bound source evidence: `Sending`, `Unknown`, `Gone`, `StillHere`.
    /// Missing legacy evidence never establishes an abort or a successful move.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_reported: Option<String>,
    /// The sentence that came with a `StillHere`, verbatim from the node.
    /// Empty for the other two outcomes and before either.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_message: Option<String>,
}

/// Typed source report: departure, confirmed local retention, or uncertainty. Keep the report
/// as evidence rather than inferring it from transport success.
pub const SEND_SENDING: &str = "Sending";
pub const SEND_GONE: &str = "Gone";
pub const SEND_STILL_HERE: &str = "StillHere";

/// In-flight records retain ownership and cannot be deleted through the API.
pub type VmMigration = Object<VmMigrationSpec, VmMigrationStatus>;

/// Derive migration phase from its recorded observation. Succeeded requires
/// a destination node; callers must establish matching durable attempt evidence
/// before recording success. This function does not itself verify that protocol.
/// An untouched record waits with AwaitingTarget; timestamps follow kind changes.
pub fn settle_vm_migration(status: &VmMigrationStatus) -> VmMigrationPhase {
    match status
        .reported
        .as_ref()
        .and_then(VmMigrationReported::phase)
    {
        Some(phase) => phase,
        None => VmMigrationPhase::new(
            VmMigrationPhaseKind::Pending,
            VmMigrationReason::AwaitingTarget,
            Some("no target chosen yet".to_string()),
            UNSTAMPED,
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(secs: i64) -> DateTime<Utc> {
        DateTime::from_timestamp(1_800_000_000 + secs, 0).expect("an instant")
    }

    fn migration() -> VmMigration {
        VmMigration::declare(
            "web-1-x",
            VmMigrationSpec {
                tenant: "acme".to_string(),
                vm: "web-1".to_string(),
                target_node: None,
            },
        )
    }

    /// The table: the step this tier has reached, and the one word from below
    /// that ends it.
    #[test]
    fn a_move_is_the_step_it_has_reached() {
        let mut fresh = migration();
        fresh.settle(at(0));
        assert_eq!(fresh.status.phase().kind(), VmMigrationPhaseKind::Pending);
        assert_eq!(
            fresh.status.phase().reason(),
            Some(VmMigrationReason::AwaitingTarget),
            "the sentence Pending's own doc comment has carried since it was written"
        );

        let cases: &[(VmMigrationReported, VmMigrationPhaseKind, VmMigrationReason)] = &[
            (
                VmMigrationReported::here(
                    VmMigrationPhaseKind::Preparing,
                    VmMigrationReason::Dispatched,
                    Some("preparing soller".into()),
                    at(0),
                ),
                VmMigrationPhaseKind::Preparing,
                VmMigrationReason::Dispatched,
            ),
            (
                VmMigrationReported::here(
                    VmMigrationPhaseKind::Running,
                    VmMigrationReason::Dispatched,
                    Some("sending to soller at 10.0.0.2:18000".into()),
                    at(0),
                ),
                VmMigrationPhaseKind::Running,
                VmMigrationReason::Dispatched,
            ),
            (
                VmMigrationReported::here(
                    VmMigrationPhaseKind::Failed,
                    VmMigrationReason::Abandoned,
                    Some("the destination was not ready after 120s".into()),
                    at(0),
                ),
                VmMigrationPhaseKind::Failed,
                VmMigrationReason::Abandoned,
            ),
        ];
        for (word, kind, reason) in cases {
            let mut m = migration();
            m.status.reported = Some(word.clone());
            m.settle(at(0));
            assert_eq!(m.status.phase().kind(), *kind, "{word:?}");
            assert_eq!(
                m.status.phase().reason().unwrap_or_default(),
                *reason,
                "{word:?}"
            );
        }
    }

    /// `Succeeded` demands a machine, and it is the only word here that does.
    /// What it claims is that a guest is executing somewhere else, and a step
    /// this tier took cannot be the evidence for that — the destination's own
    /// `Running` is.
    #[test]
    fn nothing_has_succeeded_unless_the_destination_said_so() {
        let mut invented = migration();
        invented.status.reported = Some(VmMigrationReported::here(
            VmMigrationPhaseKind::Succeeded,
            VmMigrationReason::Unrecorded,
            Some("web-1 is on soller".into()),
            at(0),
        ));
        invented.settle(at(0));
        assert_eq!(
            invented.status.phase().kind(),
            VmMigrationPhaseKind::Pending,
            "this tier cannot declare a guest arrived"
        );

        let mut real = migration();
        real.status.reported = Some(VmMigrationReported::by(
            "soller",
            VmMigrationPhaseKind::Succeeded,
            VmMigrationReason::Unrecorded,
            Some("web-1 is on soller".into()),
            at(0),
        ));
        real.settle(at(0));
        assert_eq!(real.status.phase().kind(), VmMigrationPhaseKind::Succeeded);
        assert!(real.status.phase().kind().is_final());
    }
}
