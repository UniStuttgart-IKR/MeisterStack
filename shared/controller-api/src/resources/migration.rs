// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! The `VmMigration` kind: one live move of one VM, the
//! intent and how far it got. Moved out of `resources.rs`
//! unchanged.

use super::*;

/// One live migration of one VM.
///
/// KubeVirt's shape, and the argument for it is the one KubeVirt makes: a
/// migration is a thing with a lifetime, a source, a target and an outcome,
/// and a verb has nowhere to keep any of those. `POST` one and it says
/// "move this VM while it runs"; read it back and it says how far that got
/// and, if it did not, what stopped it. `node drain` creates them itself for
/// the VMs it can move that way.
///
/// The other reason it is a resource rather than a verb is the milestone
/// rule: inside `meister.io/v1` only new FIELDS with a default and new
/// RESOURCES are allowed, and a new verb on `Vm` would be neither.
///
/// Tenant-scoped, so a tenant can see what is happening to its own VMs — and
/// operator-written, because a migration is an OPERATION on the estate rather
/// than a thing a member does to their own VM. That pair is the fifth class
/// in the permission table (`auth::Class::TenantOperated`) and it is the only
/// resource in it.
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
    /// Where to. `None` = let the scheduler choose, which is what a drain
    /// asks for and what an operator usually wants.
    ///
    /// A HARD requirement when it is set — not a preference. Somebody who
    /// names a node is answering a question about that node ("get off this
    /// machine and onto that one"), and quietly using a different one would
    /// answer a question they did not ask.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_node: Option<String>,
}

reasons! {
    /// Why a migration is where it is.
    ///
    /// Five, all of them sentences the migration reconciler already writes:
    /// "preparing <target>", "sending to <target> at <peer>", the abandon
    /// path's `why`, and the two outcomes a source reports — `StillHere` is
    /// the good outcome of a bad transfer and has always had a field of its
    /// own (`status.sourceReported`).
    ///
    /// The one enum in this file that keeps a `Reported`, and the reason is
    /// that there is nothing for it to be replaced BY: a migration's word
    /// from below is `MigrationReport.outcome`, a typed enum
    /// (`DepartureOutcome`) that already travels in a field of its own, and
    /// `proto::reasons` has no list for migrations because no node writes a
    /// reason string about one. Here `Reported` names the field to read, and
    /// that is a different thing from naming the road it came down.
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
    /// How far a migration got.
    ///
    /// Five phases and the two ends are terminal: nothing retries a `Failed`
    /// migration by itself, because the thing that failed was an operation
    /// somebody asked for and asking again is somebody's decision. `Succeeded`
    /// and `Failed` are both worth keeping — the record of a move that did not
    /// work is the most useful object in this file on the day somebody asks why
    /// a machine is still full.
    VmMigrationPhase / VmMigrationPhaseKind / VmMigrationReason / VmMigrationPhaseWire / VmMigrationReported [5] {
        /// Accepted, nothing done. No target chosen yet.
        Pending { reason, message, since } => "Pending",
        /// A target has been chosen and is being made ready: the record, the
        /// taps, the volumes attached THERE, and a VMM listening for the stream.
        Preparing { reason, message, since } => "Preparing",
        /// The source has been told to send. The guest is still the source's
        /// until it is not.
        Running { reason, message, since } => "Running",
        /// The target reports the VM Running and the source has stopped naming
        /// it. `Vm.spec.nodeName` is the target.
        Succeeded { message, since } => "Succeeded",
        /// It did not happen, and the message says what stopped it. **The
        /// source VM is still running** — that is the invariant the whole
        /// reconciler is built around, and it is why this phase is safe to reach.
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

    /// The same question, under the name `crate::stuck` asks it by — and the
    /// only enum here where `Failed` is an end: a migration that failed was
    /// an operation somebody ASKED for, and asking again is somebody's
    /// decision rather than a curve's.
    ///
    /// Two names for one answer, and the older one stays because the
    /// migration reconciler reads it on every pass and "is this record
    /// finished" is the sentence that belongs there.
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
    /// The last word anybody established about the move — the one fact
    /// `settle_vm_migration` derives from.
    ///
    /// Nearly all of them are this tier's own, because a migration is an
    /// operation this tier RUNS: it chose the target, it made the
    /// destination ready, it told the source to send. Those words carry no
    /// node, which is what keeps any of them from being `Succeeded` —
    /// the one resting word here, and the only one that needs a machine's
    /// say-so. See `VmMigrationReported`.
    ///
    /// `None` on a record nothing has been decided about, which is every
    /// record for the moment between the request and the first pass.
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
    /// The address the DESTINATION is listening at for the stream, in the
    /// node's own spelling (`tcp:10.0.0.5:49000`). Written when the
    /// destination answered `PrepareMigration`, and the one thing the source
    /// has to be told.
    ///
    /// Astra finding S05, 2026-09-23: it used to live only inside the
    /// `Preparing` message — "{target} is listening at {peer}" — and the send
    /// step scraped it back out with `rsplit_once(" at ")`. A sentence is for
    /// a person to read; a field is what another step reads. Scraping made
    /// the address depend on the wording, and it gave a replica that saw the
    /// migration one write earlier no way to tell "no address yet" from "no
    /// address ever".
    ///
    /// `None` on a migration whose destination has not answered yet, and on
    /// every record written before this field existed — `peer_of` falls back
    /// to the sentence for those.
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

/// The three things a source says about a send, spelled as `MigrationReport`
/// spells them.
///
/// Constants and not an enum, because this tier only ever compares: the words
/// are the node's, they travel as strings, and an enum here would be a parse
/// that can fail over a spelling a newer agent invented. `settle` acts on
/// `SEND_STILL_HERE` and nothing else.
pub const SEND_SENDING: &str = "Sending";
pub const SEND_GONE: &str = "Gone";
pub const SEND_STILL_HERE: &str = "StillHere";

/// In-flight records retain ownership and cannot be deleted through the API.
pub type VmMigration = Object<VmMigrationSpec, VmMigrationStatus>;

/// How far the move got, out of the last word anybody established about it.
///
/// The thinnest of the three "last word" derivations and the one where that
/// is least surprising: a migration is not a thing whose state somebody
/// observes, it is an OPERATION this tier runs, and its phase is the step it
/// has reached. Which is why nearly every word here carries no node.
///
/// What the one place is for:
///
/// * **`Succeeded` demands a machine.** It is the one resting word, and what
///   it claims is that a guest is executing somewhere else — so it has to
///   name the destination that reported `Running`. A step this tier took
///   cannot be the evidence for that; see `VmMigrationReported`.
/// * **No phase without a reason.** A record nobody has acted on is
///   `Pending { AwaitingTarget }`, which is the sentence
///   `VmMigrationPhase::Pending` has carried in its own doc comment since it
///   was written and that nothing ever put on an object.
/// * **One `since`,** so "Running since" is when the send started.
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
