// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use anyhow::Result;
use macros::generated;
use tokio::time::Instant;
use tracing::{debug, error, info, instrument, trace, warn};

use agent_api::{DeviceAttachment, VmId, VmState};

use crate::drivers::Drivers;
use crate::provision::Provisioner;
use crate::store::Store;
use crate::types::{Desired, Phase, VmRecord};
use serde::Serialize;

#[derive(Debug, Clone, Copy)]
pub enum Trigger {
    Startup,
    Periodic,
    /// Somebody stated an intent — the unix socket or the controller session.
    Manual,
}

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
}

/// What a pass WOULD do, without doing it: the record's stated intent, where
/// its resources got to, whether it is quarantined, what the world looks
/// like, and the action those three add up to. A struct and not a tuple
/// because the REST `observe` endpoint is where an operator reads it, and
/// five positional fields is how the wrong two get swapped.
pub struct DryRun {
    pub desired: Desired,
    pub phase: Phase,
    pub unhealthy: Option<String>,
    pub observed: Observed,
    pub action: Action,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    None,
    Blocked,
    /// VM carries an unhealthy marker: the reconciler must not repair it
    /// automatically. Manual lifecycle actions (start/stop/destroy) clear the
    /// marker.
    Quarantined,
    Adopt {
        vmm_pid: u32,
    },
    Provision,
    Start,
    SignalShutdown,
    Stop,
    Pause,
    Resume,
    Teardown,
}

#[generated(model = ClaudeFable, version = "5")]
pub fn plan(record: &VmRecord, obs: &Observed, now: SystemTime) -> Action {
    if record.operation.is_some() {
        return Action::Blocked;
    }

    if record.desired == Desired::Absent {
        return Action::Teardown;
    }

    if record.desired == Desired::Stopped {
        if !obs.vmm_alive {
            // The VMM exits on its own when the guest powers off. The record
            // then still says Provisioned and the device backends are still
            // running — the Stop path tears those down and tolerates the
            // dead VMM, so it must run exactly once even posthumously.
            //
            // Exactly once, and the phase cannot say when: stop() keeps the
            // volumes and taps and therefore leaves the phase at Provisioned,
            // so the phase alone would ask for the same stop on every pass,
            // forever. `vmm_pid` is what stop() clears, and so is what tells
            // a VM that still has to be cleaned up from one that already was.
            return if record.phase == Phase::Provisioned && record.vmm_pid.is_some() {
                Action::Stop
            } else {
                Action::None
            };
        }
        return match obs.guest {
            Some(VmState::Defined) | Some(VmState::Stopped) => Action::Stop,
            // A paused guest never gets to see the power button, so waiting
            // out the grace period buys nothing but the wait.
            Some(VmState::Paused) => Action::Stop,
            _ => match record.stop_deadline {
                Some(deadline) if now < deadline => Action::SignalShutdown,
                _ => Action::Stop,
            },
        };
    }

    // Quarantine gate: teardown and stop above stay allowed (that IS the
    // manual maintenance path), but no automatic provision/start/resume.
    if record.unhealthy.is_some() {
        return Action::Quarantined;
    }

    if record.desired == Desired::Halted {
        return Action::None;
    }

    if record.phase != Phase::Provisioned {
        return Action::Provision;
    }

    if !obs.vmm_alive || !obs.socket_responsive {
        return Action::Provision;
    }

    if !obs.tracked {
        return match record.vmm_pid {
            Some(pid) => Action::Adopt { vmm_pid: pid },
            None => Action::Provision,
        };
    }

    let Some(guest) = obs.guest else {
        return Action::None;
    };
    match (record.desired, guest) {
        (Desired::Running, VmState::Defined | VmState::Stopped) => Action::Start,
        (Desired::Running, VmState::Paused) => Action::Resume,
        (Desired::Running, VmState::Running) => Action::None,
        (Desired::Paused, VmState::Running) => Action::Pause,
        (Desired::Paused, VmState::Paused) => Action::None,
        (Desired::Paused, VmState::Defined | VmState::Stopped) => Action::Start,
        _ => Action::None,
    }
}

/// The stop deadline a lifecycle transition leaves behind. Arming happens on
/// the way INTO Stopped and nowhere else: the controller derives its Stop
/// level-triggered and repeats it until the phase moves, and a repeat that
/// re-armed the grace would push the hard stop out of reach forever. Leaving
/// Stopped disarms — nothing else is waiting on that deadline.
#[generated(model = ClaudeOpus, version = "5")]
pub fn next_stop_deadline(
    from: Desired,
    armed: Option<SystemTime>,
    to: Desired,
    proposed: Option<SystemTime>,
) -> Option<SystemTime> {
    match to {
        Desired::Stopped if from != Desired::Stopped => proposed,
        Desired::Stopped => armed,
        _ => None,
    }
}

/// What a desired-state snapshot means for the records this node holds: a
/// managed record the controller does not list has been deleted while the
/// session was down, and tearing it down is the whole point of sending the
/// snapshot. Everything else survives it — above all the VMs created
/// straight on the agent's unix socket, which are never in a snapshot and
/// are not the controller's to reap. Records already on their way out are
/// left to the pass that is removing them.
#[generated(model = ClaudeOpus, version = "5")]
pub fn sync_orphans<'a>(
    snapshot: &HashSet<VmId>,
    records: impl IntoIterator<Item = (VmId, &'a VmRecord)>,
) -> Vec<VmId> {
    records
        .into_iter()
        .filter(|(id, r)| {
            r.managed_by_controller && r.desired != Desired::Absent && !snapshot.contains(id)
        })
        .map(|(id, _)| id)
        .collect()
}

/// Every backend process this VM has, device and volume alike.
///
/// Both halves of the spec, one question. A virtiofsd serving a share is as
/// much a backend as a vhost-user GPU is, and a VM that lost one is in the
/// same condition either way — so the attachments answer `backend_pid` and
/// this walks both lists rather than each being matched on at the one place
/// that asks. Attachments with no process behind them (passthrough, mdev, a
/// file, a block device) contribute nothing and are never "dead".
#[generated(model = ClaudeOpus, version = "5")]
fn backend_pids(record: &VmRecord) -> impl Iterator<Item = u32> + '_ {
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
#[generated(model = ClaudeFable, version = "5")]
pub fn backend_died_under_vmm(record: &VmRecord, obs: &Observed) -> bool {
    record.phase == Phase::Provisioned
        && matches!(record.desired, Desired::Running | Desired::Paused)
        && obs.vmm_alive
        && !obs.backends_alive
}

/// The phase the controller shows for a VM. Spelled exactly like the
/// controller's `VmPhase` variants — the agent must not depend on
/// controller-api, so the string is the contract (see control.proto).
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
#[generated(model = ClaudeOpus, version = "5")]
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
/// per node; see the module doc in `linux_network_driver::frr`.
#[generated(model = ClaudeOpus, version = "5")]
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
}

#[derive(Debug, Default)]
pub struct ReconcileSummary {
    pub total: usize,
    pub adopted: usize,
    pub provisioned: usize,
    pub lifecycle: usize,
    pub torn_down: usize,
    pub blocked: usize,
    pub quarantined: usize,
    pub failed: usize,
}

impl ReconcileSummary {
    fn had_events(&self) -> bool {
        self.adopted
            + self.provisioned
            + self.lifecycle
            + self.torn_down
            + self.blocked
            + self.quarantined
            + self.failed
            > 0
    }
}

struct FailureState {
    failures: u32,
    next_attempt: Instant,
}

const BACKOFF_BASE: Duration = Duration::from_secs(30);
const BACKOFF_MAX: Duration = Duration::from_secs(15 * 60);

const MAX_CONVERGE_STEPS: usize = 4;

pub struct Reconciler {
    store: Arc<Store>,
    drivers: Drivers,
    provisioner: Arc<Provisioner>,
    ops: Arc<tokio::sync::Mutex<()>>,
    failures: Mutex<HashMap<VmId, FailureState>>,
}

#[generated(model = ClaudeFable, version = "5")]
impl Reconciler {
    pub fn new(
        store: Arc<Store>,
        drivers: Drivers,
        provisioner: Arc<Provisioner>,
        ops: Arc<tokio::sync::Mutex<()>>,
    ) -> Self {
        Self {
            store,
            drivers,
            provisioner,
            ops,
            failures: Mutex::new(HashMap::new()),
        }
    }

    #[instrument(skip_all, fields(?trigger))]
    pub async fn reconcile_all(&self, trigger: Trigger) -> Result<ReconcileSummary> {
        let mut summary = ReconcileSummary::default();
        let vms = self.store.list()?;
        summary.total = vms.len();

        for (id, _) in vms {
            match self.reconcile(id, trigger).await {
                Ok(Action::None) => {}
                Ok(Action::Blocked) => summary.blocked += 1,
                Ok(Action::Quarantined) => summary.quarantined += 1,
                Ok(Action::Adopt { .. }) => summary.adopted += 1,
                Ok(Action::Provision) => summary.provisioned += 1,
                Ok(Action::Teardown) => summary.torn_down += 1,
                Ok(_) => summary.lifecycle += 1,
                Err(_) => summary.failed += 1,
            }
        }

        // Level-triggered, at the end of the pass: which floating addresses
        // live on this node right now. `right now` is why it observes again
        // instead of reusing what the loop above saw — see
        // `announce_floating_addresses`. See also `announcements`.
        self.announce_floating_addresses().await;

        if matches!(trigger, Trigger::Startup) || summary.had_events() {
            info!(
                total = summary.total,
                adopted = summary.adopted,
                provisioned = summary.provisioned,
                lifecycle = summary.lifecycle,
                torn_down = summary.torn_down,
                blocked = summary.blocked,
                quarantined = summary.quarantined,
                failed = summary.failed,
                "reconcile pass complete"
            );
        } else {
            trace!(
                total = summary.total,
                "reconcile pass complete, all converged"
            );
        }
        Ok(summary)
    }

    /// Tell the announcer which floating addresses are on this node.
    ///
    /// Level-triggered in the strict sense: the whole set is recomputed from
    /// the reconciler's own observation and handed over as a whole, every
    /// pass. Nothing here remembers what changed, nothing here reacts to an
    /// event, and a missed transition is not a stuck route — it is a route the
    /// next pass corrects. Which is also why the announcer swallows its own
    /// failures: the same set arrives again in thirty seconds.
    ///
    /// A node with no `[network.bgp]` section does not even observe: the whole
    /// thing is one `is_none` check, and the pass costs exactly what it cost
    /// before this milestone.
    ///
    /// On a node that DOES announce, this is a second observation of every VM
    /// on top of the one the pass just made, and that is deliberate. The
    /// pass's own observations are taken BEFORE it acts: `reconcile` observes,
    /// plans, executes — and on the paths that leave the converge loop right
    /// after executing (`Teardown`, `SignalShutdown`, the step limit, any
    /// error) nothing observes again afterwards. Reusing those would announce
    /// the node as it was before the pass, which for a VM the pass just tore
    /// down means a /32 pointing at a host that no longer runs it: a
    /// blackhole, held until the next pass. The records are stale in the same
    /// way — the pass writes phases and the unhealthy marker while it runs,
    /// and `report` re-reads them. Two probes per VM per thirty seconds is a
    /// few hundred microseconds of unix-socket traffic; a blackholed tenant
    /// address is not.
    #[instrument(level = "debug", skip_all)]
    async fn announce_floating_addresses(&self) {
        let Some(announcer) = &self.drivers.announcer else {
            return;
        };
        let reports = match self.report().await {
            Ok(r) => r,
            Err(e) => {
                warn!(error = %format!("{e:#}"),
                      "could not observe the node, leaving the announcements alone");
                return;
            }
        };
        let running: Vec<VmRecord> = reports
            .iter()
            .filter(|r| r.phase == ReportedPhase::Running)
            .filter_map(|r| self.store.get(&r.id).ok().flatten())
            .collect();
        announcer.announce(floating_prefixes(running.iter())).await;
    }

    #[instrument(skip_all, fields(vm_id = %id, ?trigger))]
    pub async fn reconcile(&self, id: VmId, trigger: Trigger) -> Result<Action> {
        if self.in_backoff(&id) {
            // Debug and not trace: the pass did not converge this vm and the
            // level contract puts the reason a thing was skipped at DEBUG.
            debug!("in backoff, skipping this pass");
            return Ok(Action::None);
        }

        let mut first_action: Option<Action> = None;

        for step in 0..MAX_CONVERGE_STEPS {
            let Some(mut record) = self.store.get(&id)? else {
                break;
            };

            if step == 0
                && matches!(trigger, Trigger::Startup)
                && let Some(op) = record.operation.take()
            {
                warn!(?op, "clearing orphaned operation after restart");
                self.store.put(&id, &record)?;
            }

            let observed = self.observe(&id, &record).await;

            // Unhealthy detection: a backend died while the VMM is still
            // running. Cloud Hypervisor cannot reconnect a vhost-user backend
            // — not a gpu, not a virtiofs share — and restarting the VM
            // automatically is not wanted here: mark the VM and quarantine it
            // until a human acts (start/stop/destroy clears the marker).
            if record.unhealthy.is_none() && backend_died_under_vmm(&record, &observed) {
                // Error and not warn: quarantine is the one state no pass
                // ever leaves on its own. The reason string says as much —
                // only start/stop/destroy clears the marker, and all three
                // need a human.
                error!(reason = BACKEND_DIED_REASON, "marking vm unhealthy");
                // Through `mutate` and NOT `put`: `observe` above awaited a
                // probe of the VMM's socket, so the record in hand is a
                // snapshot from before that wait. Writing the whole thing back
                // would drop anything that landed meanwhile — a Stop from the
                // controller most of all, whose `set_desired` writes the same
                // record from another task. Only the marker is ours to set.
                if let Some(fresh) = self
                    .store
                    .mutate(&id, |r| r.unhealthy = Some(BACKEND_DIED_REASON.to_string()))?
                {
                    record = fresh;
                }
            }

            let action = plan(&record, &observed, SystemTime::now());

            if observed.tracked && observed.socket_responsive && observed.guest.is_none() {
                warn!("vmm responsive but guest state unreadable, waiting");
            }
            if record.desired == Desired::Halted {
                // Debug and not warn: nothing is degraded, the pass simply
                // declines to act, and warning about it once every thirty
                // seconds for the life of the record teaches nobody anything.
                debug!(
                    desired = ?Desired::Halted,
                    "reserved desired state is not implemented, treating as no-op"
                );
            }

            match action {
                Action::None => trace!(?observed, "converged"),
                a => info!(
                    step,
                    action = ?a,
                    desired = ?record.desired,
                    phase = ?record.phase,
                    ?observed,
                    "reconcile decision"
                ),
            }

            if first_action.is_none() {
                first_action = Some(action);
            }

            if matches!(action, Action::None | Action::Blocked | Action::Quarantined) {
                break;
            }

            if let Err(e) = self
                .execute(&id, (record.phase, record.desired), action)
                .await
            {
                let retry_in = self.register_failure(&id);
                warn!(error = %format!("{e:#}"), ?retry_in, "reconcile failed");
                return Err(e);
            }

            if matches!(action, Action::SignalShutdown | Action::Teardown) {
                break;
            }
        }

        self.clear_failure(&id);
        Ok(first_action.unwrap_or(Action::None))
    }

    /// The one lifecycle transition the agent has: state the intent, drop the
    /// quarantine marker a deliberate action clears, converge once. The local
    /// REST API and the controller session both come through here, so a
    /// `vm stop` over the unix socket and a Stop off the session cannot end
    /// up meaning two different things.
    ///
    /// `Ok(None)` means there is no such record — what that is worth is the
    /// caller's business (404 locally, a no-op for a destroy).
    #[generated(model = ClaudeOpus, version = "5")]
    #[instrument(skip(self), fields(vm_id = %id, ?desired))]
    pub async fn set_desired(
        &self,
        id: VmId,
        desired: Desired,
        stop_deadline: Option<SystemTime>,
    ) -> Result<Option<Action>> {
        {
            let _guard = self.ops.lock().await;
            let Some(mut record) = self.store.get(&id)? else {
                return Ok(None);
            };
            info!(from = ?record.desired, to = ?desired, "setting desired");
            record.stop_deadline =
                next_stop_deadline(record.desired, record.stop_deadline, desired, stop_deadline);
            record.desired = desired;
            if record.unhealthy.take().is_some() {
                info!(
                    reason = "deliberate lifecycle action",
                    "clearing unhealthy marker"
                );
            }
            self.store.put(&id, &record)?;
        }
        // A new intent invalidates the retry schedule of the old one: without
        // this a VM deep in provisioning backoff would swallow its own stop.
        self.clear_failure(&id);
        self.reconcile(id, Trigger::Manual).await.map(Some)
    }

    #[instrument(level = "debug", skip_all, fields(vm_id = %id))]
    pub async fn dry_run(&self, id: &VmId) -> Result<Option<DryRun>> {
        let Some(mut record) = self.store.get(id)? else {
            return Ok(None);
        };
        let observed = self.observe(id, &record).await;
        // Preview only, nothing is persisted: apply the same unhealthy
        // detection a real pass would, so the shown action matches it.
        if record.unhealthy.is_none() && backend_died_under_vmm(&record, &observed) {
            record.unhealthy = Some("backend process died (would quarantine)".into());
        }
        let action = plan(&record, &observed, SystemTime::now());
        Ok(Some(DryRun {
            desired: record.desired,
            phase: record.phase,
            unhealthy: record.unhealthy.clone(),
            observed,
            action,
        }))
    }

    /// Every tracked VM as the controller should see it. Same observation
    /// and same unhealthy detection a real pass performs, nothing persisted —
    /// `dry_run` for the whole node, without the per-VM plumbing.
    #[generated(model = ClaudeOpus, version = "5")]
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
            out.push(VmReport { id, phase, message });
        }
        Ok(out)
    }

    async fn observe(&self, id: &VmId, record: &VmRecord) -> Observed {
        let tracked = self.drivers.hypervisor.is_tracked(id);

        let slice_pids = self
            .drivers
            .confiner
            .pids_in_slice(&id.to_string())
            .unwrap_or_default();

        let vmm_alive = match record.vmm_pid {
            Some(pid) => slice_pids.contains(&pid),
            None => false,
        };

        let backends_alive = backend_pids(record).all(|pid| slice_pids.contains(&pid));

        let socket_responsive = self.drivers.hypervisor.probe(id).await;

        let guest = if tracked && socket_responsive {
            self.drivers.hypervisor.get_state(id).await.ok()
        } else {
            None
        };

        Observed {
            tracked,
            vmm_alive,
            socket_responsive,
            backends_alive,
            guest,
        }
    }

    async fn execute(&self, id: &VmId, planned: (Phase, Desired), action: Action) -> Result<()> {
        if matches!(action, Action::None | Action::Blocked | Action::Quarantined) {
            return Ok(());
        }

        let _guard = self.ops.lock().await;

        let Some(current) = self.store.get(id)? else {
            debug!("record gone before execute, skipping");
            return Ok(());
        };
        if (current.phase, current.desired) != planned {
            debug!(
                phase = ?current.phase,
                desired = ?current.desired,
                "record changed before execute, skipping"
            );
            return Ok(());
        }

        match action {
            Action::None | Action::Blocked | Action::Quarantined => Ok(()),

            Action::Adopt { vmm_pid } => self
                .drivers
                .hypervisor
                .adopt(id, vmm_pid)
                .await
                .map_err(|e| anyhow::anyhow!("adopting vmm: {e}")),

            Action::Provision => {
                self.drivers
                    .confiner
                    .kill_slice(&id.to_string())
                    .map_err(|e| anyhow::anyhow!("killing cgroup slice: {e}"))?;
                self.provisioner.resume(id, current).await
            }

            Action::Start => self
                .drivers
                .hypervisor
                .start(id)
                .await
                .map_err(|e| anyhow::anyhow!("starting vm: {e}")),

            Action::SignalShutdown => self
                .drivers
                .hypervisor
                .power_button(id)
                .await
                .map_err(|e| anyhow::anyhow!("sending power button: {e}")),

            Action::Stop => self.provisioner.stop(id, current).await,

            Action::Pause => {
                let p =
                    self.drivers.hypervisor.as_pausable().ok_or_else(|| {
                        anyhow::anyhow!("hypervisor driver does not support pausing")
                    })?;
                p.pause(id)
                    .await
                    .map_err(|e| anyhow::anyhow!("pausing vm: {e}"))
            }

            Action::Resume => {
                let p =
                    self.drivers.hypervisor.as_pausable().ok_or_else(|| {
                        anyhow::anyhow!("hypervisor driver does not support pausing")
                    })?;
                p.resume(id)
                    .await
                    .map_err(|e| anyhow::anyhow!("resuming vm: {e}"))
            }

            Action::Teardown => self.provisioner.teardown(id).await,
        }
    }

    fn failure_count(&self, id: &VmId) -> u32 {
        self.failures
            .lock()
            .unwrap()
            .get(id)
            .map_or(0, |st| st.failures)
    }

    fn in_backoff(&self, id: &VmId) -> bool {
        self.failures
            .lock()
            .unwrap()
            .get(id)
            .is_some_and(|st| Instant::now() < st.next_attempt)
    }

    fn register_failure(&self, id: &VmId) -> Duration {
        let mut map = self.failures.lock().unwrap();
        let st = map.entry(*id).or_insert(FailureState {
            failures: 0,
            next_attempt: Instant::now(),
        });
        st.failures += 1;
        let delay = BACKOFF_BASE
            .saturating_mul(2u32.saturating_pow(st.failures.min(5)))
            .min(BACKOFF_MAX);
        st.next_attempt = Instant::now() + delay;
        delay
    }

    fn clear_failure(&self, id: &VmId) {
        self.failures.lock().unwrap().remove(id);
    }
}

#[cfg(test)]
#[generated(model = ClaudeFable, version = "5")]
mod tests {
    use super::*;
    use crate::types::{AgentVmSpec, BootSourceSpec, VmRecord};
    use std::time::{Duration, SystemTime};

    fn record(desired: Desired, phase: Phase) -> VmRecord {
        VmRecord {
            spec: AgentVmSpec {
                vcpus: 1,
                memory_mib: 256,
                boot: BootSourceSpec::Firmware {
                    firmware: "fw".into(),
                },
                volumes: vec![],
                nics: vec![],
                devices: vec![],
            },
            desired,
            phase,
            operation: None,
            stop_deadline: None,
            unhealthy: None,
            managed_by_controller: false,
            volumes: vec![],
            nics: vec![],
            devices: vec![],
            vmm_pid: None,
        }
    }

    fn obs(vmm: bool, sock: bool, dev: bool, guest: Option<VmState>) -> Observed {
        Observed {
            tracked: true,
            vmm_alive: vmm,
            socket_responsive: sock,
            backends_alive: dev,
            guest,
        }
    }

    fn now() -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000)
    }

    /// The one line that decides whether a dead virtiofsd quarantines a VM.
    /// A share's backend has to be counted exactly as a gpu backend is, and
    /// the things with no process behind them must not be counted at all —
    /// a passthrough device or a plain disk contributing a phantom pid would
    /// quarantine every VM that has one.
    #[test]
    fn every_backend_process_counts_and_nothing_else_does() {
        use agent_api::device::Device;
        use agent_api::storage::{Volume, VolumeAttachment};

        let mut r = record(Desired::Running, Phase::Provisioned);
        r.devices = vec![
            Device {
                id: uuid::Uuid::nil(),
                attachment: DeviceAttachment::VhostUser {
                    socket: "/run/gpu.sock".into(),
                    pid: 100,
                    device_type: 16,
                    queue_sizes: vec![256],
                },
            },
            Device {
                id: uuid::Uuid::nil(),
                attachment: DeviceAttachment::VfioPci {
                    sysfs_path: "/sys/x".into(),
                },
            },
        ];
        r.volumes = vec![
            Volume {
                id: uuid::Uuid::nil(),
                attachment: VolumeAttachment::Path("/vol/a.raw".into()),
                size_bytes: 1,
            },
            Volume {
                id: uuid::Uuid::nil(),
                attachment: VolumeAttachment::FsShare {
                    socket: "/run/fs.sock".into(),
                    tag: "share".into(),
                    pid: 200,
                },
                size_bytes: 0,
            },
        ];
        assert_eq!(backend_pids(&r).collect::<Vec<_>>(), vec![100, 200]);

        // A VM with nothing but a plain disk has no backend to lose.
        let mut plain = record(Desired::Running, Phase::Provisioned);
        plain.volumes = vec![Volume {
            id: uuid::Uuid::nil(),
            attachment: VolumeAttachment::Path("/vol/a.raw".into()),
            size_bytes: 1,
        }];
        assert_eq!(backend_pids(&plain).count(), 0);
    }

    #[test]
    fn running_and_healthy_converges() {
        let r = record(Desired::Running, Phase::Provisioned);
        assert_eq!(
            plan(&r, &obs(true, true, true, Some(VmState::Running)), now()),
            Action::None
        );
    }

    #[test]
    fn dead_vmm_reprovisions_when_running_desired() {
        let r = record(Desired::Running, Phase::Provisioned);
        assert_eq!(
            plan(&r, &obs(false, false, false, None), now()),
            Action::Provision
        );
    }

    #[test]
    fn stopping_signals_within_grace_then_forces() {
        let mut r = record(Desired::Stopped, Phase::Provisioned);
        r.stop_deadline = Some(now() + Duration::from_secs(30));
        let o = obs(true, true, true, Some(VmState::Running));
        assert_eq!(plan(&r, &o, now()), Action::SignalShutdown);
        // Deadline expired: escalate to a hard stop.
        assert_eq!(plan(&r, &o, now() + Duration::from_secs(31)), Action::Stop);
        // No deadline recorded at all: hard stop immediately.
        r.stop_deadline = None;
        assert_eq!(plan(&r, &o, now()), Action::Stop);
    }

    #[test]
    fn stopping_runs_stop_posthumously_exactly_once() {
        // The VMM exits by itself when the guest powers off; device backends
        // and record state still need the Stop path once.
        let mut r = record(Desired::Stopped, Phase::Provisioned);
        r.vmm_pid = Some(4242);
        let dead = obs(false, false, false, None);
        assert_eq!(plan(&r, &dead, now()), Action::Stop);

        // And exactly once. stop() keeps volumes and taps, so it leaves the
        // phase at Provisioned; clearing vmm_pid is what marks it done, and
        // without that this VM would be stopped again on every pass forever.
        r.vmm_pid = None;
        assert_eq!(plan(&r, &dead, now()), Action::None);

        // A VM that never got as far as a VMM has nothing to tear down.
        let r = record(Desired::Stopped, Phase::Provisioning);
        assert_eq!(plan(&r, &dead, now()), Action::None);
    }

    #[test]
    fn stopping_a_paused_guest_does_not_wait_out_the_grace() {
        // A paused guest cannot act on a power button, so the deadline would
        // only ever expire unused.
        let mut r = record(Desired::Stopped, Phase::Provisioned);
        r.stop_deadline = Some(now() + Duration::from_secs(30));
        assert_eq!(
            plan(&r, &obs(true, true, true, Some(VmState::Paused)), now()),
            Action::Stop
        );
    }

    #[test]
    fn the_stop_deadline_is_armed_on_the_way_in_and_never_re_armed() {
        let first = now() + Duration::from_secs(30);
        let later = now() + Duration::from_secs(300);
        // Running -> Stopped arms what the caller proposed.
        assert_eq!(
            next_stop_deadline(Desired::Running, None, Desired::Stopped, Some(first)),
            Some(first)
        );
        // A repeated Stop keeps the running deadline: the controller derives
        // its command level-triggered and repeats it until the phase moves,
        // and each repeat would otherwise postpone the hard stop.
        assert_eq!(
            next_stop_deadline(Desired::Stopped, Some(first), Desired::Stopped, Some(later)),
            Some(first)
        );
        // Any other intent disarms.
        for to in [Desired::Running, Desired::Paused, Desired::Absent] {
            assert_eq!(
                next_stop_deadline(Desired::Stopped, Some(first), to, None),
                None
            );
        }
    }

    #[test]
    fn dead_device_backend_quarantines_running_vm() {
        let mut r = record(Desired::Running, Phase::Provisioned);
        r.unhealthy = Some("backend died".into());
        assert_eq!(
            plan(&r, &obs(true, true, false, Some(VmState::Running)), now()),
            Action::Quarantined
        );
    }

    #[test]
    fn quarantine_still_allows_stop_and_teardown() {
        let mut r = record(Desired::Stopped, Phase::Provisioned);
        r.unhealthy = Some("backend died".into());
        assert_eq!(
            plan(&r, &obs(true, true, false, Some(VmState::Running)), now()),
            Action::Stop
        );
        r.desired = Desired::Absent;
        assert_eq!(
            plan(&r, &obs(true, true, false, Some(VmState::Running)), now()),
            Action::Teardown
        );
    }

    #[test]
    fn pending_operation_blocks_everything() {
        let mut r = record(Desired::Running, Phase::Provisioned);
        r.operation = Some(crate::types::Operation::Snapshotting { target: "t".into() });
        assert_eq!(
            plan(&r, &obs(true, true, true, Some(VmState::Running)), now()),
            Action::Blocked
        );
    }

    #[test]
    fn untracked_vmm_with_pid_is_adopted() {
        let mut r = record(Desired::Running, Phase::Provisioned);
        r.vmm_pid = Some(4242);
        let mut o = obs(true, true, true, Some(VmState::Running));
        o.tracked = false;
        assert_eq!(plan(&r, &o, now()), Action::Adopt { vmm_pid: 4242 });
    }

    fn phase_of(r: &VmRecord, o: &Observed, failures: u32) -> &'static str {
        report_status(r, o, failures).0.as_str()
    }

    #[test]
    fn reported_phase_follows_the_observed_guest() {
        let r = record(Desired::Running, Phase::Provisioned);
        assert_eq!(
            phase_of(&r, &obs(true, true, true, Some(VmState::Running)), 0),
            "Running"
        );
        assert_eq!(
            phase_of(&r, &obs(true, true, true, Some(VmState::Paused)), 0),
            "Paused"
        );
        assert_eq!(
            phase_of(&r, &obs(true, true, true, Some(VmState::Stopped)), 0),
            "Stopped"
        );
        assert_eq!(
            phase_of(&r, &obs(true, true, true, Some(VmState::Defined)), 0),
            "Stopped"
        );
    }

    #[test]
    fn reported_phase_is_provisioning_while_resources_are_built() {
        let r = record(Desired::Running, Phase::VolumesDone);
        assert_eq!(
            phase_of(&r, &obs(false, false, true, None), 0),
            "Provisioning"
        );
        // Provisioned but the vmm is gone: the next pass re-provisions, and a
        // first attempt is in flight, not failed.
        let r = record(Desired::Running, Phase::Provisioned);
        assert_eq!(
            phase_of(&r, &obs(false, false, false, None), 0),
            "Provisioning"
        );
        // A live vmm whose state cannot be read is the same situation.
        assert_eq!(
            phase_of(&r, &obs(true, false, true, None), 0),
            "Provisioning"
        );
    }

    #[test]
    fn repeated_reconcile_failures_report_failed_with_a_count() {
        let r = record(Desired::Running, Phase::Provisioned);
        let (phase, message) = report_status(&r, &obs(false, false, false, None), 3);
        assert_eq!(phase.as_str(), "Failed");
        assert!(message.unwrap().contains('3'));
    }

    #[test]
    fn unhealthy_reports_quarantined_with_its_reason() {
        let mut r = record(Desired::Running, Phase::Provisioned);
        r.unhealthy = Some("backend died".into());
        let (phase, message) =
            report_status(&r, &obs(true, true, false, Some(VmState::Running)), 0);
        assert_eq!(phase.as_str(), "Quarantined");
        assert_eq!(message.as_deref(), Some("backend died"));
    }

    #[test]
    fn stopped_stays_stopped_although_stop_leaves_the_phase_provisioned() {
        // stop() keeps volumes and taps, so phase is still Provisioned; only
        // desired tells this apart from a vm that never came up.
        let r = record(Desired::Stopped, Phase::Provisioned);
        assert_eq!(phase_of(&r, &obs(false, false, false, None), 0), "Stopped");
        // Still shutting down: the guest is what the controller should see.
        assert_eq!(
            phase_of(&r, &obs(true, true, true, Some(VmState::Running)), 0),
            "Running"
        );
    }

    fn managed(desired: Desired) -> VmRecord {
        let mut r = record(desired, Phase::Provisioned);
        r.managed_by_controller = true;
        r
    }

    /// The failover, asserted at the only place it is decided: an address is
    /// announced because its VM is running HERE. Stop it, tear it down or move
    /// it, and the same mechanism withdraws — the record stops contributing to
    /// this set.
    #[test]
    fn only_the_addresses_of_running_vms_are_announced_and_only_as_host_routes() {
        let mut holder = record(Desired::Running, Phase::Provisioned);
        holder.spec.nics.push(crate::types::NicWithId {
            id: uuid::Uuid::nil(),
            spec: agent_api::networking::NicSpec {
                bridge: "meister_br0".into(),
                mac: "52:54:00:00:00:01".parse().unwrap(),
                vxlan_id: Some(10_007),
                floating_ips: vec!["10.255.0.7".into(), "203.0.113.9".into()],
                routed_subnets: vec!["10.7.1.0/24".into()],
            },
        });
        let plain = record(Desired::Running, Phase::Provisioned);

        let announced = floating_prefixes([&holder, &plain].into_iter());
        assert_eq!(
            announced,
            ["10.255.0.7/32".to_string(), "203.0.113.9/32".to_string()].into()
        );
        // The routed subnet is NOT in there. A subnet spans hosts, so a
        // per-host announcement would be every node claiming the whole prefix.
        assert!(
            !announced.iter().any(|p| p.contains("10.7.1")),
            "{announced:?}"
        );

        // Nobody running is nothing announced, which is the withdraw.
        assert!(floating_prefixes(std::iter::empty()).is_empty());
    }

    #[test]
    fn a_snapshot_reaps_managed_records_it_does_not_list() {
        let gone = uuid::Uuid::from_u128(1);
        let kept = uuid::Uuid::from_u128(2);
        let listed = managed(Desired::Running);
        let dropped = managed(Desired::Running);
        let snapshot = HashSet::from([kept]);
        assert_eq!(
            sync_orphans(&snapshot, [(kept, &listed), (gone, &dropped)]),
            vec![gone]
        );
    }

    #[test]
    fn a_snapshot_never_touches_a_locally_created_vm() {
        // The managed boundary: a VM born on the agent's unix socket is not
        // in any snapshot and is not the controller's to reap.
        let local = uuid::Uuid::from_u128(3);
        let r = record(Desired::Running, Phase::Provisioned);
        assert!(sync_orphans(&HashSet::new(), [(local, &r)]).is_empty());
    }

    #[test]
    fn a_record_already_being_torn_down_is_left_alone() {
        // Its teardown is already in flight; naming it again would only
        // restart a pass that is running.
        let leaving = uuid::Uuid::from_u128(4);
        let r = managed(Desired::Absent);
        assert!(sync_orphans(&HashSet::new(), [(leaving, &r)]).is_empty());
    }

    #[test]
    fn lifecycle_transitions() {
        let r = record(Desired::Running, Phase::Provisioned);
        assert_eq!(
            plan(&r, &obs(true, true, true, Some(VmState::Stopped)), now()),
            Action::Start
        );
        assert_eq!(
            plan(&r, &obs(true, true, true, Some(VmState::Paused)), now()),
            Action::Resume
        );
        let r = record(Desired::Paused, Phase::Provisioned);
        assert_eq!(
            plan(&r, &obs(true, true, true, Some(VmState::Running)), now()),
            Action::Pause
        );
        assert_eq!(
            plan(&r, &obs(true, true, true, Some(VmState::Paused)), now()),
            Action::None
        );
    }
}
