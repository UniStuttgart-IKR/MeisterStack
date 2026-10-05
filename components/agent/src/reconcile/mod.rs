// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Reconcile each VM by observing host state, planning a deterministic action,
//! and revalidating it under the operations lock before execution.
//!
//! Records persist intent and ownership. Retry schedules, resume counters and
//! stray-process grace periods are held in memory and reset on agent restart.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use anyhow::{Result, bail};
use tokio::time::Instant;
use tracing::{debug, error, info, instrument, trace, warn};

use agent_api::{ConsoleStream, DeviceAttachment, VmId, VmState};

use crate::drivers::Drivers;
use crate::provision::Provisioner;
use crate::store::Store;
use crate::types::{Desired, Phase, VmRecord};
use serde::Serialize;

mod act;
mod observe;
mod plan;

pub use act::*;
pub use observe::*;
pub use plan::*;

#[derive(Debug, Clone, Copy)]
pub enum Trigger {
    Startup,
    Periodic,
    /// Somebody stated an intent — the unix socket or the controller session.
    Manual,
}

/// Record, observation and planning time passed to execution for revalidation
/// under the operations lock.
pub(super) struct Planned<'a> {
    pub(super) record: &'a VmRecord,
    pub(super) observed: &'a Observed,
    pub(super) at: SystemTime,
}

/// Dry-run view of the persisted record, current observation and planned action.
pub struct DryRun {
    pub desired: Desired,
    pub phase: Phase,
    pub unhealthy: Option<String>,
    pub observed: Observed,
    pub action: Action,
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
    /// Last failed attempt, reported with the in-memory backoff state.
    /// Both the diagnostic and retry schedule reset on restart.
    last_error: String,
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
    /// Consecutive accepted resumes without an observed Running state.
    /// Kept separate from ordinary backoff so repeated intent updates cannot
    /// reset the ineffective-resume threshold.
    resume_failures: Mutex<HashMap<VmId, u32>>,
    /// Guest serial recorders and interactive holders, ensured on each reconciliation pass.
    pub consoles: Arc<crate::attach::Consoles>,
    /// First observation of an unmanaged VMM. Kept in memory so a restart
    /// restarts the grace period rather than ending a process immediately.
    strays: Mutex<HashMap<VmId, Instant>>,
}

/// Grace period before terminating a discovered VMM without a stored VM ID.
/// Unreadable rows still protect their IDs; store-read failure skips the sweep.
/// The in-memory clock restarts after an agent restart.
const STRAY_GRACE: Duration = Duration::from_secs(600);

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
            resume_failures: Mutex::new(HashMap::new()),
            consoles: Arc::new(crate::attach::Consoles::default()),
            strays: Mutex::new(HashMap::new()),
        }
    }

    /// Read the startup driver registry, including its optional gateway capability.
    pub fn drivers(&self) -> &Drivers {
        &self.drivers
    }

    /// Read recorded console tails through paths supplied by the hypervisor.
    pub fn console(
        &self,
        id: &VmId,
        lines: usize,
        keep: &crate::console::LogFilter,
        wanted: &[ConsoleStream],
    ) -> Vec<(ConsoleStream, String)> {
        let Some(hypervisor) = &self.drivers.hypervisor else {
            return Vec::new();
        };
        // Include guest streams and explicitly requested VMM diagnostics.
        let mut paths = hypervisor.console_paths(id);
        if wanted.contains(&ConsoleStream::Vmm) {
            paths.extend(
                hypervisor
                    .diagnostic_paths(id)
                    .into_iter()
                    .map(|path| (ConsoleStream::Vmm, path)),
            );
        }
        crate::console::read_all(paths, lines, keep, wanted)
    }

    #[instrument(skip_all, fields(?trigger))]
    pub async fn reconcile_all(&self, trigger: Trigger) -> Result<ReconcileSummary> {
        let clock = telemetry::metrics::Timer::start();
        let outcome = self.reconcile_all_inner(trigger).await;
        // Use the shared wire kind without a controller-api dependency so metrics
        // from each tier appear in the same series.
        telemetry::metrics::reconcile().pass(
            telemetry::metrics::TIER_AGENT,
            "Vm",
            clock.seconds(),
            outcome.is_ok(),
        );
        outcome
    }

    async fn reconcile_all_inner(&self, trigger: Trigger) -> Result<ReconcileSummary> {
        let mut summary = ReconcileSummary::default();
        // Refresh node-wide cgroup and path-image conditions before reconciling VMs.
        self.check_the_cgroup_root();
        self.provisioner.verify_path_images().await;
        self.sweep_unmanaged_vmms().await;
        let vms = self.store.list()?;
        summary.total = vms.len();

        for (id, _) in vms {
            // Trim guest and VMM output on every pass, including for converged VMs.
            if let Some(hypervisor) = &self.drivers.hypervisor {
                // Ensure a recorder exists for the serial socket; restart it if its task ended.
                if let Some(socket) = hypervisor.console_socket(&id) {
                    self.consoles.ensure(&id, &socket).await;
                }
                crate::console::trim_all(&hypervisor.console_paths(&id));
                // Bound VMM diagnostics separately from guest logs. The driver removes
                // these files on destroy; the guest logs API does not expose them.
                for path in hypervisor.diagnostic_paths(&id) {
                    crate::console::trim(&path);
                }
            }
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

        // Reobserve running guests after actions before updating announced prefixes.
        self.announce_prefixes().await;

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

    /// Recheck the configured confiner root each pass and update the shared node
    /// condition. A confiner without a filesystem root needs no check.
    fn check_the_cgroup_root(&self) {
        if let Some(root) = self.drivers.confiner.root() {
            crate::conditions::check_cgroup_root(root, self.store.conditions());
        }
    }

    /// Report unmanaged VMMs and end them after STRAY_GRACE. Read raw row keys
    /// so corrupt records still protect their VM IDs; a failed table read skips
    /// the sweep. Remove grace entries when the driver no longer reports them.
    async fn sweep_unmanaged_vmms(&self) {
        let Some(hypervisor) = &self.drivers.hypervisor else {
            return;
        };
        let known: Vec<VmId> = match self.store.list_raw() {
            Ok(rows) => rows
                .iter()
                .filter_map(|(key, _)| key.parse().ok())
                .collect(),
            Err(e) => {
                warn!(error = %format!("{e:#}"),
                      "cannot read the records, so nothing here is provably unmanaged");
                return;
            }
        };
        let found = hypervisor.strays(&known).await;
        let now = Instant::now();
        let overdue: Vec<VmId> = {
            let mut held = self.strays.lock().expect("strays");
            held.retain(|id, _| found.contains(id));
            for id in &found {
                held.entry(*id).or_insert(now);
            }
            held.iter()
                .filter(|(_, since)| now.duration_since(**since) >= STRAY_GRACE)
                .map(|(id, _)| *id)
                .collect()
        };

        if found.is_empty() {
            self.store
                .conditions()
                .clear(crate::conditions::VMM_UNMANAGED);
            return;
        }
        let names: Vec<String> = found.iter().map(VmId::to_string).collect();
        self.store.conditions().raise(
            crate::conditions::VMM_UNMANAGED,
            format!(
                "{} vmm(s) are running here that this node has no record of ({}); they answer no \
                 command and hold their disks and taps. This node's free memory is not what it \
                 reports. Each is ended {}s after it was first seen.",
                found.len(),
                names.join(", "),
                STRAY_GRACE.as_secs()
            ),
        );
        for id in overdue {
            match hypervisor.end_stray(&id).await {
                Ok(()) => {
                    warn!(vm_id = %id, "an unmanaged vmm was ended after its grace");
                    self.strays.lock().expect("strays").remove(&id);
                }
                // Left in the map, so the next pass says it again and tries
                // again. A stray that cannot be ended is worse news than one
                // that can, not better.
                Err(e) => warn!(vm_id = %id, error = %format!("{e:#}"),
                                "an unmanaged vmm could not be ended"),
            }
        }
    }

    /// Recompute route announcements after VM actions, using fresh observations.
    /// A VM report failure leaves existing announcements unchanged; a router-list
    /// failure excludes router prefixes from the new set. The next pass retries.

    #[instrument(level = "debug", skip_all)]
    async fn announce_prefixes(&self) {
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
        let mut want = floating_prefixes(running.iter());

        // Add prefixes from the driver's observed active routers. If router
        // inventory fails, omit its prefixes so the announcer withdraws them.
        if let Some(bridge) = &self.drivers.bridge {
            match bridge.list_routers().await {
                Ok(routers) => want.extend(routers.into_iter().flat_map(|r| r.announce)),
                Err(e) => warn!(error = %format!("{e:#}"),
                                "could not list this node's routers, announcing none of them"),
            }
        }
        announcer.announce(want).await;
    }

    /// Attach an idempotent serial recorder immediately after create or start
    /// so boot output does not wait for the periodic reconcile pass.
    pub async fn record_console(&self, id: &VmId) {
        if let Some(hypervisor) = &self.drivers.hypervisor
            && let Some(socket) = hypervisor.console_socket(id)
        {
            self.consoles.ensure(id, &socket).await;
        }
    }

    #[instrument(skip_all, fields(vm_id = %id, ?trigger))]
    pub async fn reconcile(&self, id: VmId, trigger: Trigger) -> Result<Action> {
        if self.in_backoff(&id) {
            // Backoff skips are diagnostic, not converged passes.
            debug!("in backoff, skipping this pass");
            return Ok(Action::None);
        }

        let mut first_action: Option<Action> = None;

        for step in 0..MAX_CONVERGE_STEPS {
            let Some(mut record) = self.store.get(&id)? else {
                break;
            };

            if step == 0 && matches!(trigger, Trigger::Startup) {
                self.clear_orphaned_operation(&id, &mut record)?;
            }

            if matches!(
                record.operation,
                Some(crate::types::Operation::MigratingOut { .. })
            ) && let Some(attempt) = &record.migration
            {
                self.provisioner
                    .observe_send(&id, &attempt.id, &self.ops)
                    .await?;
                record = match self.store.get(&id)? {
                    Some(r) => r,
                    None => break,
                };
            }
            let observed = self.observe(&id, &record).await;
            if let Some(fresh) = self.quarantine_if_backend_died(&id, &record, &observed)? {
                record = fresh;
            }

            let at = SystemTime::now();
            let action = plan(&record, &observed, at);
            log_decision(step, &record, &observed, action);

            if first_action.is_none() {
                first_action = Some(action);
            }

            if matches!(action, Action::None | Action::Blocked | Action::Quarantined) {
                break;
            }

            let planned = Planned {
                record: &record,
                observed: &observed,
                at,
            };
            if let Err(e) = self.execute(&id, planned, action).await {
                let said = format!("{e:#}");
                let retry_in = self.register_failure(&id, &said);
                warn!(error = %said, ?retry_in, "reconcile failed");
                return Err(e);
            }

            if matches!(action, Action::SignalShutdown | Action::Teardown) {
                break;
            }
        }

        self.clear_failure(&id);
        Ok(first_action.unwrap_or(Action::None))
    }

    /// Clear task-local operations only. VMM transfers survive this process;
    /// legacy sends without an identity also remain blocked for manual recovery.
    fn clear_orphaned_operation(&self, id: &VmId, record: &mut VmRecord) -> Result<()> {
        if matches!(
            record.operation,
            Some(crate::types::Operation::MigratingOut { .. })
        ) {
            return Ok(());
        }
        if matches!(
            record.operation,
            Some(crate::types::Operation::MigratingIn { .. })
        ) && record.phase != Phase::Receiving
        {
            return Ok(());
        }
        if let Some(op) = record.operation.take() {
            warn!(?op, "clearing orphaned operation after restart");
            self.store.put(id, record)?;
        }
        Ok(())
    }

    /// Persist the new intent, clear quarantine and reconcile once.
    /// Both local API and controller lifecycle commands use this path.
    /// Ok(None) means the record does not exist.
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

    /// Refresh path-image observations before constructing a status report.
    pub async fn verify_path_images(&self) {
        self.provisioner.verify_path_images().await;
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

    fn in_backoff(&self, id: &VmId) -> bool {
        self.failures
            .lock()
            .unwrap()
            .get(id)
            .is_some_and(|st| Instant::now() < st.next_attempt)
    }

    /// The retry schedule as the status report reads it: how many passes in
    /// a row have failed, and what the last one said.
    fn backoff_state(&self, id: &VmId) -> (u32, Option<String>) {
        self.failures
            .lock()
            .unwrap()
            .get(id)
            .map_or((0, None), |st| {
                (
                    st.failures,
                    Some(st.last_error.clone()).filter(|s| !s.is_empty()),
                )
            })
    }

    fn register_failure(&self, id: &VmId, said: &str) -> Duration {
        let mut map = self.failures.lock().unwrap();
        let st = map.entry(*id).or_insert(FailureState {
            failures: 0,
            next_attempt: Instant::now(),
            last_error: String::new(),
        });
        st.failures += 1;
        st.last_error = said.to_string();
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

/// Log converged decisions at TRACE and actions at INFO. Report unreadable
/// guest state and reserved intent separately from the selected action.
fn log_decision(step: usize, record: &VmRecord, observed: &Observed, action: Action) {
    if observed.tracked && observed.socket_responsive && observed.guest.is_none() {
        warn!("vmm responsive but guest state unreadable, waiting");
    }
    if record.desired == Desired::Halted {
        // Reserved Halted intent selects no action; avoid repeated warnings.
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
}

#[cfg(test)]
mod tests;
