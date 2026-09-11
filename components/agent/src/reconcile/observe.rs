// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! What IS: the node as this pass can see it, and the same picture as the
//! controller is told it.
//!
//! Every field of `Observed` is measured and none is remembered. Two of them
//! are deliberately two questions about one number — see `observe` — because
//! a pid is reused and a cgroup slice outlives the crash that left it behind,
//! and either alone eventually reports a stranger as this VM's hypervisor.
//!
//! Moved out of `reconcile.rs` unchanged.

use super::*;

// Copy because it is a plain observation value and the exhaustive net in
// tests/ builds tens of thousands of them.
#[derive(Debug, Clone, Copy, Serialize)]
pub struct Observed {
    pub tracked: bool,
    pub vmm_alive: bool,
    pub socket_responsive: bool,
    /// Every backend process this VM has — device and volume alike — is
    /// still in its cgroup slice. Attachments with no process behind them
    /// (passthrough, mdev, a file, a block device) are always "alive".
    pub backends_alive: bool,
    pub guest: Option<VmState>,
    /// The guest that was on its way to this node is not coming.
    ///
    /// One field for the several ways a reception dies, because they have
    /// one answer. Cloud-hypervisor states three of them itself — the stream
    /// broke, a component refused its snapshot, the source gave up — and
    /// writes `migration-receive-failed`; the fourth is a source that never
    /// dialled at all, which nothing states and which the record's own
    /// deadline measures. Both are the same fact about the world: this node
    /// is holding a VMM, a disk connection and a set of taps for a guest
    /// that another machine is still running.
    ///
    /// Never set for a record that is not `Receiving`, and never set on the
    /// strength of a driver that cannot answer — see
    /// `Migratable::receive_failed`.
    pub receive_failed: bool,
}

/// Every backend process this VM has, device and volume alike.
///
/// Both halves of the spec, one question. A virtiofsd serving a share is as
/// much a backend as a vhost-user GPU is, and a VM that lost one is in the
/// same condition either way — so the attachments answer `backend_pid` and
/// this walks both lists rather than each being matched on at the one place
/// that asks. Attachments with no process behind them (passthrough, mdev, a
/// file, a block device) contribute nothing and are never "dead".
pub(crate) fn backend_pids(record: &VmRecord) -> impl Iterator<Item = u32> + '_ {
    record
        .devices
        .iter()
        .filter_map(|d| match &d.attachment {
            DeviceAttachment::VhostUser { pid, .. } => Some(*pid),
            _ => None,
        })
        .chain(
            record
                .volumes
                .iter()
                .filter_map(|v| v.attachment.backend_pid()),
        )
}

/// Why a VM with a dead backend is quarantined. One string for the
/// marking, the report and the operator, so a status report can never word
/// the condition differently from the record it anticipates.
pub const BACKEND_DIED_REASON: &str = "backend process died while the vmm is running, automatic restart \
     is disabled - use start/stop/destroy to repair";

/// A backend died while the VMM kept running — the condition the
/// reconciler marks unhealthy and refuses to repair automatically. Shared
/// between the marking in `reconcile` and the preview in `dry_run`, so
/// `observe` shows the same decision a real pass would make.
///
/// # `obs.vmm_alive` is a guard and not a detail
///
/// A DEAD VMM is not this condition, and the chaos run made the difference
/// worth writing down: killing a VMM was expected to quarantine and instead
/// went `Running -> Provisioning -> Running` in fifteen seconds. The code is
/// right and the expectation was wrong.
///
/// Recovering is the better answer because a dead VMM leaves nothing to
/// diagnose in place: the backends exit when their VMM hangs up — that is
/// how they are built, see `meister-backend`'s module doc — so by the next
/// pass the VM is a record and no processes, and the only two things that can
/// happen to it are "build it again" or "leave it broken until a person
/// notices". Rebuilding is idempotent by design (a re-provision finds the
/// same volumes and reattaches them), and the alternative is an outage that
/// lasts until somebody reads a dashboard.
///
/// The quarantine keeps the case it was built for and only that one: a
/// backend that died UNDER a live VMM. There the VM is still running, still
/// serving, and half its hardware is gone — a guest whose disk backend
/// vanished is a guest doing IO into nothing. Restarting it automatically
/// would be a reboot of a live machine on the strength of a condition nobody
/// has looked at, and the repair almost always has to happen on the host
/// first. So: dead VMM, no guest, rebuild; live VMM, dead backend, stop and
/// wait for a person.
///
/// The test that keeps the two apart is
/// `a_killed_vmm_recovers_and_a_backend_that_dies_under_a_live_one_does_not`.
pub fn backend_died_under_vmm(record: &VmRecord, obs: &Observed) -> bool {
    record.phase == Phase::Provisioned
        && matches!(record.desired, Desired::Running | Desired::Paused)
        && obs.vmm_alive
        && !obs.backends_alive
}

/// The phase the controller shows for a VM. Spelled exactly like the
/// controller's `VmPhase` variants — the agent must not depend on

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReportedPhase {
    Provisioning,
    Running,
    Stopped,
    Paused,
    Failed,
    Quarantined,
}

impl ReportedPhase {
    /// Every variant, in declaration order. What the status report walks to
    /// publish a zero for the phases nothing is in — a phase that stops being
    /// written looks, in a dashboard, exactly like an agent that stopped
    /// reporting.
    pub const ALL: [ReportedPhase; 6] = [
        ReportedPhase::Provisioning,
        ReportedPhase::Running,
        ReportedPhase::Stopped,
        ReportedPhase::Paused,
        ReportedPhase::Failed,
        ReportedPhase::Quarantined,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            ReportedPhase::Provisioning => "Provisioning",
            ReportedPhase::Running => "Running",
            ReportedPhase::Stopped => "Stopped",
            ReportedPhase::Paused => "Paused",
            ReportedPhase::Failed => "Failed",
            ReportedPhase::Quarantined => "Quarantined",
        }
    }
}

/// What the controller should show, from the same record and observation
/// `plan` decides on — the report is a view of the reconciler's world, not a
/// second one. `failures` is the consecutive-failure count of the backoff
/// (0 = the last pass was fine), which is what separates "the agent is
/// working on it" from "the agent keeps failing at it".
///
/// `Desired::Absent` is not a phase: those records are on their way out and
/// the caller drops them from the report instead.
/// The `Volume` objects this record currently HOLDS, by uid.
///
/// Joined across the two halves of the record on purpose: `record.volumes` is
/// what the drivers actually made or attached, and `record.spec.volumes` is
/// what says which of those belong to an object one tier up. Neither alone is
/// the answer — the spec would report a disk the attach failed on, and the
/// held list would report an inline disk under an id nobody up there knows.
pub fn attached_volumes(record: &VmRecord) -> Vec<agent_api::VolumeId> {
    record
        .volumes
        .iter()
        .map(|v| v.id())
        .filter(|id| {
            record
                .spec
                .volumes
                .iter()
                .any(|v| &v.id == id && v.referenced)
        })
        .collect()
}

/// The taps this node actually MADE for a VM, and the address on each.
///
/// Read off `record.nics` and never off `record.spec.nics`, which is the same
/// distinction `attached_volumes` above draws and it matters for the same
/// reason: the spec is what the controller asked for, the record is what the
/// driver came back with. A NIC whose tap was never made has no entry here,
/// and neither has one whose driver does not know an address — no `mac`, no
/// line, rather than a line with an empty address in it.
///
/// The name is the position, because a VM spec's NICs are an ordered list and
/// nothing gives one a name of its own. `record.nics` is filled by walking
/// `spec.nics` in order, so index `i` here is `spec.nics[i]` up there — the
/// same correspondence the hypervisor spec already rides on (see
/// `provision::seed`).
pub fn reported_nics(record: &VmRecord) -> Vec<ReportedNic> {
    record
        .nics
        .iter()
        .enumerate()
        .filter_map(|(i, nic)| {
            Some(ReportedNic {
                name: format!("nics[{i}]"),
                mac: nic.mac?.to_string(),
            })
        })
        .collect()
}

/// One tap of a VM, as the tier above should read it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReportedNic {
    /// `nics[0]`, `nics[1]` — the spec's own way of pointing at a NIC.
    pub name: String,
    /// Lower case with colons, as `MacAddr` prints it.
    pub mac: String,
}

/// What a destination says about a reception that will not finish. One
/// string for the report and the log, for the reason `BACKEND_DIED_REASON`
/// is one.
pub const RECEIVE_FAILED_REASON: &str = "the guest did not arrive; this node is giving back the vmm, the disks and the taps it \
     made for it, and the vm is still running where it was";

pub fn report_status(
    record: &VmRecord,
    obs: &Observed,
    failures: u32,
) -> (ReportedPhase, Option<String>) {
    if let Some(reason) = &record.unhealthy {
        return (ReportedPhase::Quarantined, Some(reason.clone()));
    }
    // Stop leaves the phase at Provisioned (volumes and taps stay), so the
    // desired state is what tells a stopped VM from an unprovisioned one.
    if record.desired == Desired::Stopped && !obs.vmm_alive {
        return (ReportedPhase::Stopped, None);
    }
    // The two migration phases report `Provisioning` with a sentence, and
    // both choices are deliberate.
    //
    // `Provisioning` because that is the tier above's word for "in flight,
    // nothing here to act on", and neither end of a migration is anything
    // else: the destination has no guest yet, the source has just given one
    // up. `Running` from either would be a claim that a guest is being served
    // here, and `Stopped` from the source would flip the vm's phase at the
    // cluster in the middle of a migration that is going well.
    //
    // The sentence is the half that matters: a phase that says "in flight"
    // and nothing else is the state an operator cannot act on, and these two
    // are the states where knowing WHICH machine to look at is the whole
    // question.
    match record.phase {
        Phase::Receiving => {
            // The GUEST decides, not the phase. The phase flips on the next
            // reconcile pass — thirty seconds away at worst — and the report
            // goes out every ten, so a report that waited for it would tell
            // the tier above that this node is empty while a guest is running
            // on it. That window is not academic: it is exactly the one in
            // which a migration's transfer timeout fires, and the tier above
            // decides what may be torn down by reading this line.
            return match obs.guest {
                Some(VmState::Running) => (ReportedPhase::Running, None),
                // And the third answer, which used to be the second one's
                // silence: the guest is not coming and this node is giving
                // back what it built for it. `Failed` and not `Provisioning`,
                // because a destination is never the node a VM is BOUND to —
                // its word about this VM reaches nothing but the migration's
                // own arrival check — so the only reader of this line is a
                // person asking why a move did not happen, and "in flight"
                // would be the wrong thing to tell them.
                _ if obs.receive_failed => (
                    ReportedPhase::Failed,
                    Some(RECEIVE_FAILED_REASON.to_string()),
                ),
                _ => (
                    ReportedPhase::Provisioning,
                    Some("waiting for the guest to arrive from another node".to_string()),
                ),
            };
        }
        Phase::Migrated => {
            return (
                ReportedPhase::Provisioning,
                Some("the guest has left this node; the destination has it".to_string()),
            );
        }
        _ => {}
    }
    if record.phase != Phase::Provisioned {
        return (ReportedPhase::Provisioning, None);
    }
    if !obs.vmm_alive || !obs.socket_responsive {
        // The next pass re-provisions; only a run of failed attempts turns
        // that from "in flight" into something a human has to look at.
        return if failures > 0 {
            (
                ReportedPhase::Failed,
                Some(format!(
                    "{failures} failed reconcile attempt(s), retrying with backoff"
                )),
            )
        } else {
            (ReportedPhase::Provisioning, None)
        };
    }
    match obs.guest {
        Some(VmState::Running) => (ReportedPhase::Running, None),
        Some(VmState::Paused) => (ReportedPhase::Paused, None),
        Some(VmState::Defined) | Some(VmState::Stopped) => (ReportedPhase::Stopped, None),
        // VMM alive but its state is unreadable: the pass will re-provision.
        None => (ReportedPhase::Provisioning, None),
    }
}

/// The host routes a set of records asks the world to send it.
///
/// Its own function and not a loop inside the caller, because WHICH addresses
/// end up announced is the whole of the failover semantics and is worth
/// asserting: a VM that is not running contributes nothing, so a stop, a
/// teardown and a move to another node all withdraw by the same mechanism —
/// the address stops being in this set, and the next pass says so.
///
/// Only `/32`s, ever. A routed subnet spans hosts and is nobody's to announce
/// FROM A VM RECORD — a per-node announcement of one would be every node
/// claiming the whole prefix. 6k gives the prefix a party that may announce
/// it (a router, which is the thing traffic for the subnet arrives at), and
/// that set comes out of the network driver beside this one rather than out
/// of here; see `reconcile::announce_prefixes` and
/// `linux_network_driver::router::router_prefixes`.
pub fn floating_prefixes<'a>(
    running: impl Iterator<Item = &'a VmRecord>,
) -> std::collections::BTreeSet<String> {
    running
        .flat_map(|record| record.spec.nics.iter())
        .flat_map(|nic| nic.spec.floating_ips.iter())
        .map(|address| linux_network_driver::frr::host_prefix(address))
        .collect()
}

/// One VM's line in a status report.
pub struct VmReport {
    pub id: VmId,
    pub phase: ReportedPhase,
    pub message: Option<String>,
    /// The referenced volumes this node has ATTACHED to the VM right now,
    /// read off the record rather than off the spec.
    ///
    /// The difference is the whole value of the field: the spec is what the
    /// controller asked for and the record is what happened, and a hot-plug
    /// is finished exactly when the two agree. Inline disks are left out —
    /// their ids are this node's own and name no object up there.
    pub volumes: Vec<agent_api::VolumeId>,
    /// The taps this node made for the VM, and the address on each. See
    /// `reported_nics`: an empty list is "this node knows of none", and the
    /// tier above reads nothing at all out of one.
    pub nics: Vec<ReportedNic>,
    /// What this node has to say about a guest it was told to SEND, if it was
    /// told to send this one. See [`departure`].
    pub departure: Option<Departure>,
}

/// What became of a guest this node was told to send away.
///
/// The three answers of `MigrationReport`, and they are DERIVED from the
/// record on every heartbeat rather than remembered as an event. That is what
/// makes the line survive an agent restart mid-transfer: the record is the
/// state, the report is a reading of it, and a reading taken twice says the
/// same thing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Departure {
    /// Where to, verbatim. Empty once the send is over — while it runs it is
    /// what the line is about, and afterwards the outcome is.
    pub peer: String,
    pub outcome: DepartureOutcome,
    /// Why, for `StillHere`, and `None` for the other two.
    pub message: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DepartureOutcome {
    /// The stream is open and this node is watching its own VMM.
    Sending,
    /// The VMM exited, which is how cloud-hypervisor states that a send took.
    Gone,
    /// v53 gave the guest back and is serving it here.
    StillHere,
}

impl DepartureOutcome {
    /// The spelling that goes on the wire (control.proto: MigrationReport).
    pub fn as_str(self) -> &'static str {
        match self {
            DepartureOutcome::Sending => "Sending",
            DepartureOutcome::Gone => "Gone",
            DepartureOutcome::StillHere => "StillHere",
        }
    }
}

/// What this node says about a send, read off one record.
///
/// Pure, and it is the whole of the D16 repair on this side: `MigrateOut`
/// answers "accepted" the moment the stream is open, and what says how the
/// transfer ENDED is this line on the next heartbeat. The tier above reads it
/// instead of holding its reconcile pass open for the length of a guest's
/// memory.
///
/// The order of the three questions is the order of certainty, and it
/// matters. A record that is `MigratingOut` right now is sending, whatever a
/// previous attempt left behind; only then is `send_failed` this VM's last
/// word; and `Migrated` is the record of a guest that is somewhere else.
///
/// `None` for every VM nobody asked to move, which is nearly all of them —
/// so an ordinary node sends an empty list and reads exactly like an agent
/// from before the field.
pub fn departure(record: &VmRecord) -> Option<Departure> {
    if let Some(crate::types::Operation::MigratingOut { peer }) = &record.operation {
        return Some(Departure {
            peer: peer.clone(),
            outcome: DepartureOutcome::Sending,
            message: None,
        });
    }
    if let Some(why) = &record.send_failed {
        return Some(Departure {
            peer: String::new(),
            outcome: DepartureOutcome::StillHere,
            message: Some(why.clone()),
        });
    }
    (record.phase == Phase::Migrated).then(|| Departure {
        peer: String::new(),
        outcome: DepartureOutcome::Gone,
        message: None,
    })
}

impl Reconciler {
    /// Every tracked VM as the controller should see it. Same observation
    /// and same unhealthy detection a real pass performs, nothing persisted —
    /// `dry_run` for the whole node, without the per-VM plumbing.
    #[instrument(level = "debug", skip_all)]
    pub async fn report(&self) -> Result<Vec<VmReport>> {
        let mut out = Vec::new();
        for (id, mut record) in self.store.list()? {
            if record.desired == Desired::Absent {
                continue; // being torn down; the controller drives the delete
            }
            let observed = self.observe(&id, &record).await;
            // The periodic pass may not have marked the record yet; report
            // what it is about to write, not a preview of it.
            if record.unhealthy.is_none() && backend_died_under_vmm(&record, &observed) {
                record.unhealthy = Some(BACKEND_DIED_REASON.to_string());
            }
            let (phase, message) = report_status(&record, &observed, self.failure_count(&id));
            let volumes = attached_volumes(&record);
            let nics = reported_nics(&record);
            out.push(VmReport {
                id,
                phase,
                message,
                volumes,
                nics,
                departure: departure(&record),
            });
        }
        Ok(out)
    }

    pub(super) async fn observe(&self, id: &VmId, record: &VmRecord) -> Observed {
        // A node with no hypervisor tracks nothing, answers no socket and has
        // no guest to ask — which is what these three already mean when the
        // VMM is gone, so the record converges the way it does after a crash
        // rather than through a path of its own.
        let hypervisor = self.drivers.hypervisor.as_ref();
        let tracked = hypervisor.is_some_and(|h| h.is_tracked(id));

        let slice_pids = self
            .drivers
            .confiner
            .pids_in_slice(&id.to_string())
            .unwrap_or_default();

        // Two questions about one number, and a VM is alive only if both
        // answer yes. The slice says the pid is one of THIS VM's processes;
        // `owns_pid` says the process at that pid is still the VMM the record
        // named. A pid is reused, a slice is reused after a crash that left
        // it behind, and either alone eventually reports a stranger as this
        // VM's hypervisor — which is the observation the whole plan below is
        // built on.
        let vmm_alive = match (record.vmm_pid, hypervisor) {
            (Some(pid), Some(h)) => slice_pids.contains(&pid) && h.owns_pid(id, pid),
            _ => false,
        };

        let backends_alive = backend_pids(record).all(|pid| slice_pids.contains(&pid));

        let socket_responsive = match hypervisor {
            Some(h) => h.probe(id).await,
            None => false,
        };

        let guest = match hypervisor.filter(|_| tracked && socket_responsive) {
            Some(h) => h.get_state(id).await.ok(),
            None => None,
        };

        // Asked after the state and not before it: the cloud-hypervisor
        // driver learns a reception is over by reading the event file, and
        // `get_state` is the call that reads it. Asking first would be right
        // one pass later, which for a VMM holding somebody's disk is a pass
        // too many.
        let receive_failed = self.receive_failed(id, record, hypervisor);

        Observed {
            tracked,
            vmm_alive,
            socket_responsive,
            backends_alive,
            guest,
            receive_failed,
        }
    }

    /// Whether the guest this node was waiting for is not coming.
    ///
    /// Two sources and neither is enough alone. The hypervisor knows every
    /// way a transfer that STARTED can end, and knows none of them until the
    /// source has dialled; the deadline knows the one case the hypervisor
    /// cannot see, which is nobody dialling. A record that is not
    /// `Receiving` is asked neither question — a failed reception that has
    /// been given back is not a failure to find again on the next pass.
    fn receive_failed(
        &self,
        id: &VmId,
        record: &VmRecord,
        hypervisor: Option<&std::sync::Arc<dyn agent_api::hypervisor::Hypervisor>>,
    ) -> bool {
        if record.phase != Phase::Receiving {
            return false;
        }
        if let Some(said) = hypervisor
            .and_then(|h| h.as_migratable())
            .and_then(|m| m.receive_failed(id))
        {
            warn!(vm_id = %id, reason = %said, "the guest is not coming");
            return true;
        }
        let Some(deadline) = record.receive_deadline else {
            return false;
        };
        if SystemTime::now() < deadline {
            return false;
        }
        warn!(vm_id = %id, "nothing arrived before the deadline; the guest is not coming");
        true
    }
}
