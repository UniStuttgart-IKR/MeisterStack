// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! The pass: look, decide, act — in that order, once per VM, over and over.
//!
//! Level-triggered and stateless between passes. Nothing here remembers what
//! the last pass did; every decision is derived again from the record and
//! from what the node can be seen to be doing, which is what lets a restart,
//! a crash or a missed message end up in the same place as a quiet minute.
//!
//! The three steps have a file each, and they are the whole of the pass:
//!
//! * `observe` — what IS: the VMM, its socket, the backend processes, the
//!   guest state, and the same picture rendered for the controller
//! * `plan` — what WOULD be done: one pure function from record plus
//!   observation to an `Action`, with no clock but the one it is handed and
//!   no way to touch the world
//! * `act` — doing it, and the marker a dead backend leaves behind
//!
//! `plan` is pure so that the whole of it can be enumerated: `tests/space`
//! walks all 89 600 cells of its input space, which is only possible because
//! the function takes values and returns one.

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
    /// What the last failed attempt said.
    ///
    /// Kept beside the count because the count alone is not a diagnosis: a VM
    /// that has been `Provisioning` for ten minutes used to report how often
    /// a pass had failed and nothing about what stopped it, and the sentence
    /// was in this node's log — the one place the person reading the API
    /// cannot see. It goes out with the phase now (`VmReason::Backoff`).
    ///
    /// In memory like the schedule it belongs to, and gone with it: a restart
    /// forgets both, and the first pass after one either works or says why
    /// again.
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
    /// How many resumes in a row this node has issued for a VM without the
    /// guest coming back. Its own counter and not `failures`, because the two
    /// are cleared by different things: `failures` is the retry schedule and a
    /// new intent wipes it, while the controller's repeated Resume IS the
    /// retry here — a counter that a repeat reset could never reach three.
    resume_failures: Mutex<HashMap<VmId, u32>>,
    /// The guest serial lines this node records, and who holds them. Level
    /// -triggered like everything else here: the pass below asks for a
    /// recorder every time and the map answers "already" almost always.
    pub consoles: Arc<crate::attach::Consoles>,
    /// When each VMM that no record names was first seen by a pass.
    ///
    /// In memory and not on disk, and that is the conservative direction: a
    /// restart forgets the clock and the grace starts again, so an agent that
    /// keeps restarting never ends anything. The alternative — a deadline on
    /// disk for a VM there is no record of — would be a record, which is
    /// precisely what this is about the absence of.
    strays: Mutex<HashMap<VmId, Instant>>,
}

/// How long a VMM nobody has a record of is left alone before it is ended.
///
/// Long, and the length is the argument. Every honest reason for a stray is
/// a race this agent lost and will not win by hurrying: a `destroy` that
/// removed the record and failed at the process, a crash between a spawn and
/// a write. Ten minutes is longer than any of them and longer than an
/// operator needs to see the condition and look, and being wrong in the other
/// direction is a guest killed on the strength of a row that could not be
/// read.
///
/// The same order as `Ceilings::receive`, and not by coincidence: a
/// destination that was killed mid-transfer is the case both numbers are
/// about, from the two sides of the same minute.
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

    /// The driver table this node came up with.
    ///
    /// On the reconciler because the reconciler is what holds it, exactly as
    /// `console` below is here because the hypervisor driver is. The one
    /// caller outside this module is the router half of the command table:
    /// the gateway slot is a driver's, and the agent only ever calls the
    /// trait.
    pub fn drivers(&self) -> &Drivers {
        &self.drivers
    }

    /// The end of this VM's one-way output, both streams of it.
    ///
    /// On the reconciler because the reconciler is what holds the drivers,
    /// and the hypervisor driver is the only party that knows where its
    /// console files are. Read-only in every sense: no attach, no input, no
    /// follow — see `crate::console`.
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
        // The guest's streams and, only when it was asked for by name, the
        // driver's own. `diagnostic_paths` is a plain list of files with no
        // stream attached, because until now nothing served it.
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
        // "Vm" spelled out rather than taken from a constant: the agent does
        // not depend on controller-api, and the kind is the wire contract
        // either way (control.proto). Same series as the two tiers above, so
        // one panel shows all three.
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
        // Before the VMs, and about none of them in particular: whether this
        // node can still tear a guest down at all, and whether the base images
        // its records name are still on its disk. Both are facts about the
        // NODE that only a pass can keep saying — see `check_the_cgroup_root`
        // and `Provisioner::verify_path_images`.
        self.check_the_cgroup_root();
        self.provisioner.verify_path_images().await;
        self.sweep_unmanaged_vmms().await;
        let vms = self.store.list()?;
        summary.total = vms.len();

        for (id, _) in vms {
            // Level-triggered, like everything else in this pass: the guest's
            // output files are bounded here because this is the one loop that
            // runs over every VM this node has, whatever else is happening to
            // them. A VM that is converged still prints, and a boot loop is
            // precisely the case where nothing else in this pass would fire.
            if let Some(hypervisor) = &self.drivers.hypervisor {
                // The serial line is a socket now, so somebody has to be
                // reading it for `<id>.serial` to exist at all. Asked for
                // here, beside the trim, for the same reason the trim is
                // here: this is the one loop that runs over every VM whatever
                // else is happening to them, so a recorder that ended is made
                // again without anything having to notice that it ended.
                if let Some(socket) = hypervisor.console_socket(&id) {
                    self.consoles.ensure(&id, &socket).await;
                }
                crate::console::trim_all(&hypervisor.console_paths(&id));
                // The VMM's own log is bounded here too and read nowhere: it is
                // the driver's diagnostics, not the guest's output, and `vm logs`
                // must not mix them. `destroy` removes it; without this nothing
                // stopped it growing while the VM lived.
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

        // Level-triggered, at the end of the pass: which addresses live on
        // this node right now. `right now` is why it observes again instead
        // of reusing what the loop above saw — see `announce_prefixes`. See
        // also `announcements`.
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

    /// Is this node's `cgroup_root` still a cgroup2 filesystem?
    ///
    /// Asked here, once per pass, and it is about the NODE rather than about
    /// any VM — which is why it sits beside the loop and not inside it. The
    /// check ran exactly once, at start-up, and that made it a statement about
    /// the second the agent came up: a `/sys/fs/cgroup` that was unmounted,
    /// remounted or shadowed afterwards went unmentioned until the first
    /// delete hung, which is the original defect with a start-up check in
    /// front of it.
    ///
    /// The path comes from the confiner and not from a copy of the config,
    /// because the confiner is the party that WRITES into that directory —
    /// see `ResourceConfiner::root`. A confiner with no directory (every fake
    /// in these tests) is asked nothing and claims nothing.
    ///
    /// The conditions are the store's, which are the node's: one `Arc` is
    /// made in `store_and_conditions` and handed to everything that raises
    /// into it, so what the heartbeat carries is one list.
    fn check_the_cgroup_root(&self) {
        if let Some(root) = self.drivers.confiner.root() {
            crate::conditions::check_cgroup_root(root, self.store.conditions());
        }
    }

    /// VMMs running here that no record of this agent names: say so, and end
    /// them once they have been saying so for long enough.
    ///
    /// D18. "The agent adopts what it has a record of" was only half a rule,
    /// and the other half went unwritten: a guest whose record went while its
    /// process did not runs on a machine nobody manages. It answers no
    /// command, appears in no report, holds its disks and its taps, and the
    /// first anybody hears of it is a second guest dying on a write lock over
    /// the same volume. The lab made one — a destination whose agent was
    /// killed mid-migration, whose VMM finished the transfer, and whose guest
    /// then ran for hours while the control plane called the migration failed.
    ///
    /// **The known set is `list_raw`, not `list`.** The question is whether a
    /// RECORD EXISTS, not whether this build can read it: a row that cannot be
    /// deserialised is a VM this agent cannot manage, and killing its guest
    /// over that would be the worst possible reading of a bad row. A row that
    /// cannot be read at all — the whole table unreadable — declines the sweep
    /// outright, the same way the overlay sweep does and for the same reason.
    ///
    /// **Said before it is done, and done only after a grace.** The condition
    /// is what the tier above acts on: a node with an unmanaged guest is a
    /// node whose free memory is a fiction. The grace is `STRAY_GRACE`, and
    /// what it buys is the difference between a race this agent lost and a
    /// mistake it is about to make.
    ///
    /// Level-triggered like the rest of the pass: the map holds only what
    /// this pass saw, so a stray that goes away — adopted, ended by somebody,
    /// or given a record — takes its deadline with it and the condition
    /// clears by itself.
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

    /// Tell the announcer which addresses this node answers for.
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
    /// before this milestone. A node with a section but neither floating
    /// addresses nor routers hands over the empty set, which is a session
    /// that stays up and says nothing.
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

        // 6k, N-A4: the second sort of address this node answers for, and it
        // is the SAME mechanism — one set, handed over whole, every pass. The
        // routers' half comes out of the driver rather than out of a spec
        // this tier kept, because whether a router is standing is the
        // driver's answer and a standby announces nothing whatever it was
        // asked to be.
        //
        // A failure here leaves the routers' prefixes out of the set and
        // therefore WITHDRAWS them, which is the safe direction: an agent
        // that cannot see its own routers must not go on telling the fabric
        // to send them traffic. The next pass is thirty seconds away.
        if let Some(bridge) = &self.drivers.bridge {
            match bridge.list_routers().await {
                Ok(routers) => want.extend(routers.into_iter().flat_map(|r| r.announce)),
                Err(e) => warn!(error = %format!("{e:#}"),
                                "could not list this node's routers, announcing none of them"),
            }
        }
        announcer.announce(want).await;
    }

    /// One VM, from what it is to what it should be, up to four times.
    ///
    /// Four steps and not one: an action moves the record one phase along,
    /// and the next observation of the same VM is a different one — a
    /// provision that finished wants a start, a start that took wants
    /// nothing. Converging here rather than waiting for the next pass is what
    /// makes a create feel like a create instead of like four ticks.
    ///
    /// The loop is the same three lines every time: observe, plan, execute.
    /// Everything else in it is the bookkeeping around those three — the
    /// backoff that keeps a broken VM from eating the pass, the marker a dead
    /// backend leaves, and the two ways the loop ends early.
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

            if step == 0 && matches!(trigger, Trigger::Startup) {
                self.clear_orphaned_operation(&id, &mut record)?;
            }

            let observed = self.observe(&id, &record).await;
            if let Some(fresh) = self.quarantine_if_backend_died(&id, &record, &observed)? {
                record = fresh;
            }

            let action = plan(&record, &observed, SystemTime::now());
            log_decision(step, &record, &observed, action);

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

    /// The operation marker a crash left behind, dropped once at startup.
    ///
    /// An operation belongs to the task that started it, and that task did
    /// not survive the restart. `plan` returns `Blocked` for as long as the
    /// marker stands, so a marker nobody is holding would block this VM for
    /// ever.
    fn clear_orphaned_operation(&self, id: &VmId, record: &mut VmRecord) -> Result<()> {
        if let Some(op) = record.operation.take() {
            warn!(?op, "clearing orphaned operation after restart");
            self.store.put(id, record)?;
        }
        Ok(())
    }

    /// The one lifecycle transition the agent has: state the intent, drop the
    /// quarantine marker a deliberate action clears, converge once. The local
    /// REST API and the controller session both come through here, so a
    /// `vm stop` over the unix socket and a Stop off the session cannot end
    /// up meaning two different things.
    ///
    /// `Ok(None)` means there is no such record — what that is worth is the
    /// caller's business (404 locally, a no-op for a destroy).
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

/// What the pass saw and what it decided, each at the level the contract
/// gives it: a converged pass is TRACE because there are thousands of them,
/// a pass that will act is INFO because there are few. The two notes before
/// the decision are about a READING and not about it — one says the guest
/// could not be asked, the other that the intent is a reserved one.
fn log_decision(step: usize, record: &VmRecord, observed: &Observed, action: Action) {
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
}

#[cfg(test)]
mod tests;
