// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Execute frozen rollout plans with fresh observations and journaled outcomes.
//!
//! Hosts execute sequentially within each wave. Failures stop subsequent waves;
//! provider handoffs stop immediately. Mutating steps revalidate affected hosts,
//! and activation intent is fsynced before invoking the target helper. Resume
//! combines local evidence with target transaction state.
//!
//! Per-host locks and control-plane anchors coordinate operators. Unreachable
//! anchors are reported but do not prevent execution, so fleet exclusion can be
//! incomplete. Receipts retain failed and untouched hosts.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Result, bail};

use crate::activate::Mode;
use crate::checks::{self, CheckResult};
use crate::effects::{Clock, Files};
use crate::manifest::ResolvedFleet;
use crate::observation::{Endpoint, HostObservation, Observations};
use crate::observe::{self, HostProbe, ProbeSpec, Prober};
use crate::plan::{
    Action, ActionKind, ApprovalClass, DeploymentPlan, HostVerdict, RollbackMode, Verdict,
    WorkloadControl, approvals_missing, validate_against_next,
};
use crate::readiness;
use crate::receipt::{
    ActionResult, DeploymentReceipt, EventKind, HostRun, HostState, Operator, Step, TxnView, fold,
    next_step, receipt,
};
use crate::release::ReleaseManifest;
use crate::run::{Cancel, Cmd, Effect, Expect, Runner};
use crate::state::{Journal, StateDir, journal_ref, read_journal, repair_journal};
use crate::transport::{Ssh, Target};

/// Drain deadline; a host still carrying work is not advanced.
pub const DRAIN_WAIT: Duration = Duration::from_secs(600);

/// How long a host may take to come back from a reboot.
pub const REBOOT_WAIT: Duration = Duration::from_secs(600);

/// Allow SSH and networking to recover before interpreting activation failure.
pub const SETTLE_WAIT: Duration = Duration::from_secs(120);

/// How often a bounded wait asks again.
pub const POLL: Duration = Duration::from_secs(5);

/// How long `nix copy` of a whole system closure may take.
pub const COPY_DEADLINE: Duration = Duration::from_secs(3600);

/// How long the small remote commands may take.
pub const REMOTE_DEADLINE: Duration = Duration::from_secs(120);

/// How long an activation may take on the target. The same as the helper's
/// own switch deadline plus room for the ssh around it.
pub const ACTIVATE_DEADLINE: Duration = Duration::from_secs(960);

/// What `apply` was asked for.
#[derive(Debug, Clone)]
pub struct ApplyOptions {
    pub run_id: String,
    /// `--approve <class>=<plan_id>`, as given.
    pub approvals: Vec<(ApprovalClass, String)>,
    /// Continue a run that was interrupted: its journal is folded and every
    /// host is asked where it got to.
    pub resume: bool,
    /// Take the per-host locks of this run. Only after a fresh observation
    /// and a re-validation, and never by a clock.
    pub takeover: Option<String>,
    /// The operator's cli, for the cordon and the drain (D7). `None` when
    /// the inventory names none — and then the plan has already blocked
    /// every interrupting step on an agent.
    pub workload: Option<WorkloadControl>,
    pub drain_wait: Duration,
    pub reboot_wait: Duration,
    /// How long a host gets to answer again after a step that restarts its
    /// network.
    pub settle_wait: Duration,
    pub poll: Duration,
    /// Operator repository containing locally issued delivery certificates.
    pub repo: PathBuf,
    /// `[operator] ca_dir`, where the files the CA keeps live. `None` when
    /// the inventory names none — and then a plan that needs one has
    /// already blocked the host with the sentence that says so.
    pub ca_dir: Option<PathBuf>,
}

impl ApplyOptions {
    pub fn new(run_id: impl Into<String>) -> ApplyOptions {
        ApplyOptions {
            run_id: run_id.into(),
            approvals: Vec::new(),
            resume: false,
            takeover: None,
            workload: None,
            drain_wait: DRAIN_WAIT,
            reboot_wait: REBOOT_WAIT,
            settle_wait: SETTLE_WAIT,
            poll: POLL,
            repo: PathBuf::from("."),
            ca_dir: None,
        }
    }
}

/// What a run came to, for the caller that has to print it and exit.
#[derive(Debug, Clone)]
pub struct Applied {
    pub receipt: DeploymentReceipt,
    pub journal_path: String,
    /// Why the run stopped early, when it did. A sentence for a person.
    pub stopped: Option<String>,
    /// Hosts whose steps the plan refused. Not a failure of the run — the
    /// plan said so before it started.
    pub blocked: Vec<String>,
    /// Provider handoff details; the CLI returns the waiting outcome with exit code 2.
    pub waiting: Option<ProviderWait>,
}


/// Provider handoff carried through the action error path without classifying
/// it as a host failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderWait {
    pub host: String,
    pub run_id: String,
    pub bundle: crate::release::DirectBoot,
}

impl ProviderWait {
    /// The sentence a person reads, with the three values and the command
    /// that comes after them.
    pub fn sentence(&self) -> String {
        format!(
            "the provider has to load kernel {} ({}) / initrd {} ({}) / cmdline {:?} for host \
             {} and reboot it; then `meister-deploy apply --resume {}`.",
            short_hash(&self.bundle.kernel.sha256),
            self.bundle.kernel.store_path,
            short_hash(&self.bundle.initrd.sha256),
            self.bundle.initrd.store_path,
            self.bundle.cmdline,
            self.host,
            self.run_id
        )
    }

    /// Structured direct-boot bundle for provider adapters.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "waiting_for": "provider-reboot",
            "host": self.host,
            "bundle": self.bundle,
            "resume": self.run_id,
        })
    }
}

impl std::fmt::Display for ProviderWait {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.sentence())
    }
}

impl std::error::Error for ProviderWait {}

/// The first twelve characters of a `sha256:…` or a bare digest, for a
/// sentence somebody compares by eye against what they uploaded.
fn short_hash(digest: &str) -> String {
    let bare = digest.strip_prefix("sha256:").unwrap_or(digest);
    bare.chars().take(12).collect()
}

/// Why [`Executor::walk_waves`] stopped, when it did.
enum Stop {
    /// A host did not come through, and the sentence says which and why.
    Failed(String),
    /// The plan reached the step this tool does not take.
    Provider(ProviderWait),
}


/// Inject fresh host observations independently of execution ordering.
pub trait Look {
    fn observe(&self, host: &crate::manifest::ResolvedHost, target: &Target) -> HostObservation;
}

/// Read-only SSH observation implementation.
pub struct SshLook<'a> {
    pub prober: &'a dyn Prober,
}

impl Look for SshLook<'_> {
    fn observe(&self, host: &crate::manifest::ResolvedHost, target: &Target) -> HostObservation {
        observe::observe_host(
            self.prober,
            &HostProbe::new(target.clone(), ProbeSpec::for_host(host)),
        )
    }
}

/// Everything one run needs, and nothing it could get wrong.
pub struct Executor<'a> {
    pub runner: &'a dyn Runner,
    pub files: &'a dyn Files,
    pub clock: &'a dyn Clock,
    pub look: &'a dyn Look,
    pub ssh: &'a Ssh,
    pub state: &'a StateDir,
    pub plan: &'a DeploymentPlan,
    pub release: &'a ReleaseManifest,
    pub operator: Operator,
    pub options: ApplyOptions,
    pub cancel: Cancel,
}

/// Lock-release scope: host action or final anchor cleanup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Release {
    /// The host's own `unlock` step: its step lock goes, the anchor stays.
    HostStep,
    /// The end of the run: everything this run still holds goes.
    RunEnd,
}

/// The running picture of one host, between the plan and the journal.
struct HostRunState {
    state: HostState,
    /// The transaction this run opened on it, if it has.
    txn: Option<String>,
    /// Whether this run holds the target's lock.
    locked: bool,
    /// Fleet anchor held until run cleanup, independently of the host Unlock action.
    anchored: bool,
    /// Whether this run already changed the system. Unlike HostState, this remains
    /// true across resumed preflight and identifies the run's own plan differences.
    moved: bool,
}

impl<'a> Executor<'a> {
    /// Execute the plan and return its receipt when persistence succeeds.
    /// Host failures are outcomes; validation or I/O failures may return Err, including
    /// after work has begun. The caller also interprets stop and waiting fields.
    pub fn run(&self) -> Result<Applied> {
        let missing = approvals_missing(self.plan, &self.options.approvals);
        if !missing.is_empty() {
            bail!(
                "this plan needs {}, and nothing was granted for it. Read the plan, then pass \
                 {}. An approval names the plan it is for, so it cannot be carried over from \
                 another one.",
                missing
                    .iter()
                    .map(|c| c.as_str())
                    .collect::<Vec<_>>()
                    .join(" and "),
                missing
                    .iter()
                    .map(|c| format!("--approve {c}={}", self.plan.plan_id))
                    .collect::<Vec<_>>()
                    .join(" ")
            );
        }

        let journal_path = self.state.journal_path(&self.options.run_id);
        let (journal, resumed) = if self.options.resume {
            // Repair a torn final journal line on disk before appending. Otherwise the
            // next event would turn the tail fragment into interior corruption. Reporting
            // remains read-only.
            if let Some(torn) = repair_journal(self.files, &journal_path)? {
                eprintln!("note: {torn}");
            }
            let read = read_journal(self.files, &journal_path)?;
            let folded = fold(&read.events)?;
            if folded.plan_id != self.plan.plan_id {
                bail!(
                    "the run {} was about the plan {} and this is {}. A resume continues the \
                     run it was, not a different rollout with the same id.",
                    self.options.run_id,
                    folded.plan_id,
                    self.plan.plan_id
                );
            }
            let last = read.last_seq();
            (
                Journal::resuming(
                    journal_path.clone(),
                    &self.options.run_id,
                    &self.plan.plan_id,
                    last,
                ),
                Some(folded),
            )
        } else {
            self.state.begin_run(self.files, &self.options.run_id)?;
            // The plan travels into the run directory, because `report`
            // folds a receipt out of the journal and the plan, and a run
            // whose plan has been edited since is a run nobody can read.
            self.files.write_atomic(
                &self.state.plan_copy_path(&self.options.run_id),
                &self.plan.to_json()?,
                0o644,
            )?;
            // Save the release beside the plan so resume retains its paths and NAR hashes
            // even if an operator overwrites the original release output.
            self.files.write_atomic(
                &self.state.release_copy_path(&self.options.run_id),
                &self.release.to_json()?,
                0o644,
            )?;
            (
                Journal::new(
                    journal_path.clone(),
                    &self.options.run_id,
                    &self.plan.plan_id,
                ),
                None,
            )
        };

        let anchor = self.anchor_hosts();
        self.write(
            &journal,
            EventKind::RunStart,
            None,
            None,
            serde_json::json!({
                "operator": self.operator,
                // Record anchor details in the run payload; lock.acquire requires a host.
                "anchor": { "control_plane": anchor, "resumed": self.options.resume },
                "plan_id": self.plan.plan_id,
                "release_id": self.plan.release_id,
            }),
        )?;

        let mut hosts: BTreeMap<String, HostRunState> = BTreeMap::new();
        for id in &self.plan.selection.targets {
            let planned = &self.plan.hosts[id];
            let state = match resumed.as_ref().and_then(|r| r.host(id)) {
                Some(run) => HostRunState {
                    state: run.state,
                    txn: run.txn_id.clone(),
                    locked: run.lock_held,
                    // The anchor is taken again below (`take_anchor`), which
                    // is where this becomes true for the hosts it holds.
                    anchored: false,
                    moved: run.txn_id.is_some(),
                },
                None if planned.verdict.blocks() => HostRunState {
                    state: HostState::Blocked,
                    txn: None,
                    locked: false,
                    anchored: false,
                    moved: false,
                },
                None => HostRunState {
                    state: HostState::Planned,
                    txn: None,
                    locked: false,
                    anchored: false,
                    moved: false,
                },
            };
            hosts.insert(id.clone(), state);
        }

        let mut stopped: Option<String> = None;
        // Attempt control-plane anchors before host actions. Unreachable anchors
        // leave exclusion incomplete but do not block recovery work.
        if let Err(e) = self.take_anchor(&journal, &anchor, &mut hosts) {
            stopped = Some(format!("{e:#}"));
        }

        let mut waiting: Option<ProviderWait> = None;
        if stopped.is_none() {
            match self.walk_waves(&journal, &mut hosts) {
                None => {}
                Some(Stop::Failed(why)) => stopped = Some(why),
                Some(Stop::Provider(wait)) => {
                    stopped = Some(wait.sentence());
                    waiting = Some(wait);
                }
            }
        }

        // Whatever happened, the locks this run took go back — otherwise the
        // next run needs `--takeover` for a rollout that simply ended.
        self.release_locks(&journal, &mut hosts);

        self.write(
            &journal,
            EventKind::RunEnd,
            None,
            None,
            serde_json::json!({ "stopped": stopped }),
        )?;

        let read = read_journal(self.files, &journal_path)?;
        let folded = fold(&read.events)?;
        let reference = journal_ref(self.files, &journal_path)?;
        let mut built = receipt(self.plan, &folded, &reference, self.clock.now());
        // Attach stop and provider-handoff details to the single receipt document.
        built.stopped = stopped.clone();
        built.waiting = waiting.as_ref().map(ProviderWait::to_json);
        self.state.write_receipt(self.files, &built)?;
        Ok(Applied {
            receipt: built,
            journal_path: journal_path.display().to_string(),
            stopped,
            blocked: self
                .plan
                .hosts
                .iter()
                .filter(|(_, h)| h.verdict.blocks())
                .map(|(id, _)| id.clone())
                .collect(),
            waiting,
        })
    }

    // -----------------------------------------------------------------
    // the walk
    // -----------------------------------------------------------------

    /// Wave by wave, host by host. A wave in which anything failed is the
    /// last wave: the next one would be a rollout that had already been told
    /// something was wrong.
    fn walk_waves(
        &self,
        journal: &Journal,
        hosts: &mut BTreeMap<String, HostRunState>,
    ) -> Option<Stop> {
        for wave in 0..=self.plan.last_wave() {
            let in_wave: Vec<String> = self
                .plan
                .selection
                .targets
                .iter()
                .filter(|id| {
                    self.plan
                        .actions_for(id)
                        .iter()
                        .any(|a| a.wave == wave && !a.is_blocked())
                })
                .cloned()
                .collect();
            let mut failed: Vec<String> = Vec::new();
            for id in &in_wave {
                if self.cancel.is_cancelled() {
                    return Some(Stop::Failed(format!(
                        "this run was interrupted before {id}; what was already started is in \
                         the journal and on the hosts."
                    )));
                }
                match self.run_host(journal, id, wave, hosts) {
                    Ok(()) => {}
                    // Stop the run at provider handoff to preserve wave order until the
                    // provider boots the requested bundle.
                    Err(e) => match e.downcast::<ProviderWait>() {
                        Ok(wait) => return Some(Stop::Provider(wait)),
                        Err(e) => failed.push(format!("{id}: {e:#}")),
                    },
                }
            }
            if !failed.is_empty() {
                return Some(Stop::Failed(format!(
                    "wave {wave} did not come through: {}. Nothing of wave {} was started.",
                    failed.join("; "),
                    wave + 1
                )));
            }
        }
        None
    }

    /// Execute this host's planned actions in order, adjusting only for resume state.
    fn run_host(
        &self,
        journal: &Journal,
        id: &str,
        wave: u32,
        hosts: &mut BTreeMap<String, HostRunState>,
    ) -> Result<()> {
        let planned = &self.plan.hosts[id];
        if planned.verdict.blocks() {
            // The plan said so, with a sentence, before this started. Saying
            // it again as a failure would turn a refusal into an incident.
            return Ok(());
        }

        // Where a resume picks up, decided by the journal and the TARGET and
        // never by this function (V17).
        let mut skip: BTreeSet<ActionKind> = BTreeSet::new();
        if self.options.resume {
            match self.resume_point(journal, id, hosts)? {
                Resume::Done => return Ok(()),
                Resume::Carry => {}
                Resume::AtTheProviderReboot => {
                    // Provider handoff follows confirmation; skip preparation and confirmation.
                    skip.extend([
                        ActionKind::Stage,
                        ActionKind::DeliverSecret,
                        ActionKind::Cordon,
                        ActionKind::Drain,
                        ActionKind::Activate,
                        ActionKind::Confirm,
                    ]);
                }
                Resume::AtKeysPhase(phase) => {
                    // Skip phases already represented by the target rotation state. Preparing
                    // a second key would invalidate the certificate bound to the first.
                    let reached = crate::receipt::keys_phase_order(phase);
                    for kind in [
                        ActionKind::KeysPrepare,
                        ActionKind::KeysOverlap,
                        ActionKind::KeysSwitch,
                        ActionKind::KeysVerify,
                        ActionKind::KeysRemove,
                    ] {
                        if crate::receipt::keys_phase_order(kind) < reached {
                            skip.insert(kind);
                        }
                    }
                }
                Resume::AfterTheActivation {
                    confirmed,
                    rebooted,
                } => {
                    // Target evidence confirms activation; do not repeat preparation or activation.
                    skip.extend([
                        ActionKind::Stage,
                        ActionKind::DeliverSecret,
                        ActionKind::Cordon,
                        ActionKind::Drain,
                        ActionKind::Activate,
                    ]);
                    if confirmed {
                        skip.insert(ActionKind::Confirm);
                    }
                    // Skip a completed reboot using journal evidence. Rebooting again before
                    // boot-mode confirmation can consume the fallback path and boot the old default.
                    if rebooted {
                        skip.insert(ActionKind::Reboot);
                    }
                }
            }
        }

        if planned.verdict == HostVerdict::Unchanged {
            // Record unchanged hosts so the receipt distinguishes them from unreached hosts.
            let actions: Vec<Action> = self
                .plan
                .actions_for(id)
                .into_iter()
                .filter(|a| a.wave == wave && !a.is_blocked())
                .cloned()
                .collect();
            let fresh = self.observe(&self.affected(id))?;
            self.guard(&fresh, id, hosts)?;
            for action in &actions {
                self.begin(journal, id, action)?;
                // Unchanged hosts still run required readiness checks; matching system
                // identity alone does not establish health.
                if action.kind == ActionKind::Verify {
                    let results = self.verify(id, &fresh);
                    let verdict = checks::acceptance(&results);
                    if verdict.is_accepted() {
                        self.end_with_checks(
                            journal,
                            id,
                            action,
                            ActionResult::Ok,
                            results,
                            Vec::new(),
                        )?;
                    } else {
                        self.end_with_checks(
                            journal,
                            id,
                            action,
                            ActionResult::Failed,
                            results,
                            Vec::new(),
                        )?;
                        let why = match verdict {
                            checks::Acceptance::Blocked { reasons } => reasons.join("; "),
                            checks::Acceptance::Accepted => unreachable!("it was not accepted"),
                        };
                        self.move_to(journal, id, hosts, HostState::Failed, fresh.host(id))?;
                        bail!(
                            "{id} already runs the release and is not right: the readiness \
                             checks did not pass: {why}"
                        );
                    }
                    continue;
                }
                self.end(
                    journal,
                    id,
                    action,
                    ActionResult::Skipped,
                    Vec::new(),
                    Vec::new(),
                )?;
            }
            self.move_to(journal, id, hosts, HostState::Unchanged, fresh.host(id))?;
            return Ok(());
        }

        let actions: Vec<Action> = self
            .plan
            .actions_for(id)
            .into_iter()
            .filter(|a| a.wave == wave)
            .cloned()
            .collect();
        for action in &actions {
            if action.is_blocked() || skip.contains(&action.kind) {
                continue;
            }
            if self.cancel.is_cancelled() {
                bail!(
                    "interrupted before the step {} ({})",
                    action.seq,
                    action.kind
                );
            }
            self.run_action(journal, id, action, hosts)?;
        }
        Ok(())
    }

    /// One step. The order inside it is always the same: look, validate,
    /// journal, do, journal.
    fn run_action(
        &self,
        journal: &Journal,
        id: &str,
        action: &Action,
        hosts: &mut BTreeMap<String, HostRunState>,
    ) -> Result<()> {
        // A fresh look, immediately before the step that changes something.
        // `preflight` and `verify` take their own below; `lock` and `unlock`
        // are the door itself and their refusal IS the check.
        let fresh = if needs_validation(action.kind) {
            let fresh = self.observe(&self.affected(id))?;
            self.guard(&fresh, id, hosts)?;
            Some(fresh)
        } else {
            None
        };

        match action.kind {
            ActionKind::Preflight => {
                let fresh = self.observe(&self.affected(id))?;
                self.guard(&fresh, id, hosts)?;
                self.begin(journal, id, action)?;
                let seen = fresh.host(id).cloned();
                let mut evidence = vec![format!(
                    "identity {}, generation {}",
                    seen.as_ref()
                        .and_then(|o| o.identity.host_key_fingerprint.clone())
                        .unwrap_or_else(|| "unknown".to_string()),
                    seen.as_ref()
                        .and_then(|o| o.generation)
                        .map(|g| g.to_string())
                        .unwrap_or_else(|| "unknown".to_string())
                )];
                // Recheck hardware constraints before staging; stale planned capacity
                // or hardware evidence must fail the step.
                if let Some(obs) = seen.as_ref() {
                    let host = &self.release.resolved_fleet.hosts[id];
                    let verdict = crate::plan::hardware_verdict(
                        id,
                        host,
                        obs,
                        Some(self.release.artifacts[id].toplevel.closure_size),
                    );
                    if !verdict.is_clear() {
                        let why = verdict.blocked.join(" ");
                        self.end(
                            journal,
                            id,
                            action,
                            ActionResult::Failed,
                            verdict.blocked.clone(),
                            Vec::new(),
                        )?;
                        bail!("the preflight of {id} found the machine changed: {why}");
                    }
                    evidence.extend(verdict.met);
                }
                self.end(journal, id, action, ActionResult::Ok, evidence, Vec::new())?;
                self.move_to(journal, id, hosts, HostState::Preflight, fresh.host(id))?;
            }
            ActionKind::Lock => {
                self.begin(journal, id, action)?;
                let cmd = self.lock_cmd(id)?;
                let line = cmd.line();
                self.runner.run(&cmd)?;
                self.entry(hosts, id).locked = true;
                self.write(
                    journal,
                    EventKind::LockAcquire,
                    Some(id),
                    None,
                    serde_json::json!({ "run_id": self.options.run_id }),
                )?;
                self.end(
                    journal,
                    id,
                    action,
                    ActionResult::Ok,
                    Vec::new(),
                    vec![line],
                )?;
            }
            ActionKind::Stage => {
                self.begin(journal, id, action)?;
                let evidence = self.stage(id, action)?;
                self.end(journal, id, action, ActionResult::Ok, evidence, Vec::new())?;
                self.move_to(journal, id, hosts, HostState::Staged, None)?;
            }
            ActionKind::Cordon | ActionKind::Drain | ActionKind::Uncordon => {
                self.begin(journal, id, action)?;
                let mut evidence = Vec::new();
                let mut refs = Vec::new();
                for verb in self.workload_verbs(id, action) {
                    let cmd = self.workload_cmd(id, verb)?;
                    refs.push(cmd.line());
                    self.runner.run(&cmd)?;
                }
                if action.kind == ActionKind::Drain {
                    let guests = self.wait_for_drain(id)?;
                    evidence.push(format!("{guests} guest(s) left on {id}"));
                }
                self.end(journal, id, action, ActionResult::Ok, evidence, refs)?;
                if action.kind == ActionKind::Drain {
                    self.move_to(journal, id, hosts, HostState::MaintenanceReady, None)?;
                }
            }
            ActionKind::Activate => {
                let txn = self.txn_id();
                self.begin(journal, id, action)?;
                // The line that a resume stands on, on the disk before the
                // command that cannot be taken back.
                self.write(
                    journal,
                    EventKind::ActionIrreversible,
                    Some(id),
                    None,
                    serde_json::json!({
                        "action": action.seq,
                        "kind": action.kind,
                        "txn": txn,
                        "desired": action.desired,
                    }),
                )?;
                self.entry(hosts, id).txn = Some(txn.clone());
                self.entry(hosts, id).moved = true;
                // Journal the Activating transition before later events refer to it.
                self.move_to(journal, id, hosts, HostState::Activating, None)?;
                let cmd = self.activate_cmd(id, action, &txn)?;
                let line = cmd.line();
                let next = if action.rollback.mode == RollbackMode::Boot {
                    HostState::AwaitingReboot
                } else {
                    HostState::Verifying
                };
                match self.runner.run(&cmd) {
                    Ok(_) => {
                        self.end(
                            journal,
                            id,
                            action,
                            ActionResult::Ok,
                            Vec::new(),
                            vec![line],
                        )?;
                        self.move_to(journal, id, hosts, next, None)?;
                    }
                    Err(e) => {
                        // Activation can restart SSH. Wait for target transaction evidence before
                        // classifying a lost connection as failure.
                        let (seen, view) = self.settled_view(id, Some(&txn));
                        if matches!(view, TxnView::Pending { .. }) {
                            self.end(
                                journal,
                                id,
                                action,
                                ActionResult::Ok,
                                vec![
                                    format!("the connection did not survive the switch: {e:#}"),
                                    format!(
                                        "{id} holds the transaction {txn} and is waiting for a \
                                         word"
                                    ),
                                ],
                                vec![line],
                            )?;
                            self.move_to(journal, id, hosts, next, seen.as_ref())?;
                        } else {
                            self.end(
                                journal,
                                id,
                                action,
                                ActionResult::Failed,
                                vec![format!("{e:#}")],
                                vec![line],
                            )?;
                            // The helper may already have reverted; inspect its recorded outcome.
                            return self
                                .after_a_failed_activation(journal, id, hosts, e, seen, view);
                        }
                    }
                }
            }
            ActionKind::Reboot => {
                // Record the pre-reboot boot ID for interrupted-command reconciliation.
                // If unavailable, resume falls back to booted-system evidence.
                let before = self.observe_one(id).ok().and_then(|o| o.boot_id);
                let evidence: Vec<String> = before.iter().map(|b| format!("boot_id {b}")).collect();
                self.begin_with_evidence(journal, id, action, evidence)?;
                let refs = self.reboot(id)?;
                let desired = action
                    .desired
                    .clone()
                    .unwrap_or_else(|| self.plan.hosts[id].desired_system.clone());
                let back = self.wait_for_boot(id, &desired)?;
                self.end(
                    journal,
                    id,
                    action,
                    ActionResult::Ok,
                    vec![format!("booted {}", back)],
                    refs,
                )?;
                let fresh = self.observe(&self.affected(id))?;
                self.guard(&fresh, id, hosts)?;
                self.move_to(journal, id, hosts, HostState::Verifying, fresh.host(id))?;
            }
            ActionKind::Verify => {
                self.begin(journal, id, action)?;
                let fresh = self.observe(&self.affected(id))?;
                let results = self.verify(id, &fresh);
                let verdict = checks::acceptance(&results);
                let payload_checks = results.clone();
                if verdict.is_accepted() {
                    self.end_with_checks(
                        journal,
                        id,
                        action,
                        ActionResult::Ok,
                        payload_checks,
                        Vec::new(),
                    )?;
                    // Commit when no later Confirm exists. This includes delivery/reboot-only
                    // plans and the second verify after a direct-boot provider handoff.
                    if !self.plan.actions_for(id).iter().any(|a| {
                        a.kind == ActionKind::Confirm && !a.is_blocked() && a.seq > action.seq
                    }) {
                        self.move_to(journal, id, hosts, HostState::Committed, fresh.host(id))?;
                    }
                } else {
                    self.end_with_checks(
                        journal,
                        id,
                        action,
                        ActionResult::Failed,
                        payload_checks,
                        Vec::new(),
                    )?;
                    let why = match verdict {
                        checks::Acceptance::Blocked { reasons } => reasons.join("; "),
                        checks::Acceptance::Accepted => unreachable!("it was not accepted"),
                    };
                    // Without an activation transaction there is no system rollback to invoke.
                    if self.entry(hosts, id).txn.is_some() {
                        self.take_back(journal, id, hosts, &why)?;
                    }
                    bail!("the readiness checks did not pass: {why}");
                }
            }
            ActionKind::Confirm => {
                self.begin(journal, id, action)?;
                let txn = self.require_txn(hosts, id)?;
                let cmd = self.helper_cmd(id, &["confirm", "--txn", &txn])?;
                let line = cmd.line();
                self.runner.run(&cmd)?;
                self.end(
                    journal,
                    id,
                    action,
                    ActionResult::Ok,
                    Vec::new(),
                    vec![line],
                )?;
                let fresh = fresh.unwrap_or_else(|| self.plan.observation.clone());
                // Keep direct-boot hosts Verifying until the provider handoff completes.
                let more_to_come = self.plan.actions_for(id).iter().any(|a| {
                    a.kind == ActionKind::ProviderReboot && !a.is_blocked() && a.seq > action.seq
                });
                let next = if more_to_come {
                    HostState::Verifying
                } else {
                    HostState::Committed
                };
                self.move_to(journal, id, hosts, next, fresh.host(id))?;
            }
            ActionKind::Unlock => {
                self.begin(journal, id, action)?;
                let mut refs = Vec::new();
                // The record goes with the run that opened it: until it is
                // retired, the next plan refuses to start over, which is
                // what makes an interrupted run visible.
                if let Some(txn) = self.entry(hosts, id).txn.clone() {
                    let cmd = self.helper_cmd(
                        id,
                        &[
                            "txn",
                            "retire",
                            "--txn",
                            &txn,
                            "--run",
                            &self.options.run_id,
                        ],
                    )?;
                    refs.push(cmd.line());
                    self.runner.run(&cmd)?;
                    self.entry(hosts, id).txn = None;
                }
                if let Some(cmd) = self.unlock_cmd(id, hosts, Release::HostStep)? {
                    refs.push(cmd.line());
                    self.runner.run(&cmd)?;
                    self.entry(hosts, id).locked = false;
                    self.write(
                        journal,
                        EventKind::LockRelease,
                        Some(id),
                        None,
                        serde_json::json!({ "run_id": self.options.run_id }),
                    )?;
                }
                self.end(journal, id, action, ActionResult::Ok, Vec::new(), refs)?;
                // Complete resumed cleanup as Committed: repeated preflight may have
                // reset the local state even though confirmation was already complete.
                if self.entry(hosts, id).state != HostState::Committed {
                    self.move_to(journal, id, hosts, HostState::Committed, None)?;
                }
            }
            ActionKind::DeliverSecret => {
                self.begin(journal, id, action)?;
                // File delivery records an action but no activation transaction intent.
                let evidence = self.deliver(id, action)?;
                self.end(journal, id, action, ActionResult::Ok, evidence, Vec::new())?;
            }
            ActionKind::KeysPrepare => {
                let rotation = self.rotation(id, action)?;
                self.begin(journal, id, action)?;
                // Reuse the prepared key without --replace; the certificate binds that key.
                let cmd = self.helper_cmd(
                    id,
                    &[
                        "keygen",
                        "--subject",
                        &rotation.subject,
                        "--kind",
                        &rotation.kind,
                        "--suffix",
                        "next",
                    ],
                )?;
                let line = cmd.line();
                let answer = self.runner.run(&cmd)?;
                let reply = crate::pki::parse_keygen(&answer.stdout, id)?;
                if reply.public_key_sha256 != rotation.public_key_sha256 {
                    bail!(
                        "{id} holds the prepared {} key {} and this plan was made for {}. \
                         Somebody rotated this key between the plan and this run; make the \
                         plan again with `keys rotate`.",
                        rotation.kind,
                        reply.public_key_sha256,
                        rotation.public_key_sha256
                    );
                }
                self.end(
                    journal,
                    id,
                    action,
                    ActionResult::Ok,
                    vec![format!(
                        "{id} holds the prepared {} key {}",
                        rotation.kind, reply.public_key_sha256
                    )],
                    vec![line],
                )?;
            }
            ActionKind::KeysOverlap => {
                let rotation = self.rotation(id, action)?;
                self.begin(journal, id, action)?;
                let evidence = self.overlap(id, &rotation)?;
                self.end(journal, id, action, ActionResult::Ok, evidence, Vec::new())?;
            }
            ActionKind::KeysSwitch => {
                let rotation = self.rotation(id, action)?;
                self.begin(journal, id, action)?;
                // Rotation recovery uses the helper's key-state record, separate from
                // activation transaction intent.
                let cmd = self.helper_cmd(
                    id,
                    &[
                        "keys",
                        "switch",
                        "--kind",
                        &rotation.kind,
                        "--run",
                        &self.options.run_id,
                    ],
                )?;
                let mut refs = vec![cmd.line()];
                self.runner.run(&cmd)?;
                self.entry(hosts, id).moved = true;
                let mut evidence = vec![format!(
                    "{} is now {}",
                    rotation.cert_path, rotation.cert_sha256
                )];
                evidence.extend(self.poke(id, &rotation.units, &mut refs)?);
                self.end(journal, id, action, ActionResult::Ok, evidence, refs)?;
            }
            ActionKind::KeysVerify => {
                let rotation = self.rotation(id, action)?;
                self.begin(journal, id, action)?;
                // What the HOST says it holds, first: a check that passed
                // while the old certificate was still in place would be a
                // check about the wrong thing.
                let target = self.target(id)?;
                let seen = self.runner.run(&self.ssh.ask(
                    &target,
                    &format!(
                        "sha256sum {} 2>/dev/null | cut -d' ' -f1",
                        crate::run::shell_quote(&rotation.cert_path)
                    ),
                    REMOTE_DEADLINE,
                ))?;
                let seen = format!("sha256:{}", seen.trimmed());
                let fresh = self.observe(&self.affected(id))?;
                let results = self.verify(id, &fresh);
                let verdict = checks::acceptance(&results);
                let holds = seen == rotation.cert_sha256;
                if holds && verdict.is_accepted() {
                    self.end_with_checks(
                        journal,
                        id,
                        action,
                        ActionResult::Ok,
                        results,
                        Vec::new(),
                    )?;
                } else {
                    let why = if holds {
                        match verdict {
                            checks::Acceptance::Blocked { reasons } => reasons.join("; "),
                            checks::Acceptance::Accepted => unreachable!("it was accepted"),
                        }
                    } else {
                        format!(
                            "{id} answered {seen} for {} and this rotation put {} there",
                            rotation.cert_path, rotation.cert_sha256
                        )
                    };
                    self.end_with_checks(
                        journal,
                        id,
                        action,
                        ActionResult::Failed,
                        results,
                        Vec::new(),
                    )?;
                    // The way back, and it is the point of the overlap: the
                    // pair that was working is still on the disk.
                    let back = self.helper_cmd(
                        id,
                        &["keys", "revert", "--kind", &rotation.kind, "--reason", &why],
                    )?;
                    let line = back.line();
                    match self.runner.run(&back) {
                        Ok(_) => {
                            let mut refs = vec![line];
                            let _ = self.poke(id, &rotation.units, &mut refs);
                            self.move_to(
                                journal,
                                id,
                                hosts,
                                HostState::RolledBack,
                                fresh.host(id),
                            )?;
                            bail!(
                                "the rotation of the {} key of {id} did not verify and was \
                                 taken back: {why}",
                                rotation.kind
                            );
                        }
                        Err(e) => {
                            self.move_to(
                                journal,
                                id,
                                hosts,
                                HostState::RecoveryRequired,
                                fresh.host(id),
                            )?;
                            bail!(
                                "the rotation of the {} key of {id} did not verify ({why}) and \
                                 the way back failed too ({e:#}). The pair that was working is \
                                 on the host as `{}.prev`; `meister-activate keys revert --kind \
                                 {}` is what puts it back.",
                                rotation.kind,
                                rotation.cert_path,
                                rotation.kind
                            );
                        }
                    }
                }
            }
            ActionKind::KeysRemove => {
                let rotation = self.rotation(id, action)?;
                self.begin(journal, id, action)?;
                // Publish the new active certificate locally before removing target backups.
                // This prevents later ordinary plans from restoring the old certificate.
                // Both local publication and target cleanup support repetition on resume.
                let mut evidence = Vec::new();
                let active = self
                    .options
                    .repo
                    .join(crate::pki::ISSUED_DIR)
                    .join(id)
                    .join(format!("{}.crt", rotation.kind));
                let source = self.options.repo.join(&rotation.source);
                if self.files.exists(&source) {
                    if self.files.exists(&active) {
                        let previous = active.with_file_name(format!("{}.prev.crt", rotation.kind));
                        self.files.rename(&active, &previous)?;
                        evidence.push(format!(
                            "{} is what {id} held before this rotation; it is still valid \
                             until somebody takes it back (`keys revoke --serial …`)",
                            previous.display()
                        ));
                    }
                    self.files.rename(&source, &active)?;
                    evidence.push(format!("{} is now what {id} holds", active.display()));
                }
                let cmd = self.helper_cmd(id, &["keys", "remove", "--kind", &rotation.kind])?;
                let line = cmd.line();
                self.runner.run(&cmd)?;
                evidence.push(format!(
                    "the {} pair {id} used before this rotation is gone",
                    rotation.kind
                ));
                self.end(journal, id, action, ActionResult::Ok, evidence, vec![line])?;
                let fresh = fresh.unwrap_or_else(|| self.plan.observation.clone());
                self.move_to(journal, id, hosts, HostState::Committed, fresh.host(id))?;
            }
            ActionKind::Install | ActionKind::Revoke | ActionKind::Gc => {
                bail!(
                    "the step {} on {id} is a {} and this tool cannot do it yet: \
                     install arrives with M3A, revoke with M5, gc with M4. \
                     Nothing was done to {id} in this step.",
                    action.seq,
                    action.kind
                );
            }
            // Check whether the provider has booted the requested system. Otherwise
            // persist a handoff and stop; provider uploads/reboots are not initiated or polled.
            ActionKind::ProviderReboot => {
                let fresh = fresh.expect("a provider-reboot is validated, so it was looked at");
                let seen = fresh.host(id);
                let desired = action
                    .desired
                    .clone()
                    .unwrap_or_else(|| self.plan.hosts[id].desired_system.clone());
                self.begin(journal, id, action)?;
                let booted = seen.and_then(|o| o.booted_system.clone());
                if booted.as_deref() == Some(desired.as_str()) {
                    // The provider has been here. The evidence is the
                    // machine's own answer and not this tool's memory of
                    // having printed something.
                    let mut evidence = vec![format!("{id} booted {desired}")];
                    if let Some(kernel) = seen.and_then(|o| o.kernel_booted.as_ref()) {
                        evidence.push(format!(
                            "it booted the kernel {} with the initrd {}",
                            kernel.kernel_store_path, kernel.initrd_store_path
                        ));
                    }
                    self.end(journal, id, action, ActionResult::Ok, evidence, Vec::new())?;
                    self.move_to(journal, id, hosts, HostState::Verifying, seen)?;
                } else {
                    let wait = self.provider_wait(id, action)?;
                    let from = self.entry(hosts, id).state;
                    // Persist the bundle so a later resume or adapter can read the handoff.
                    self.write(
                        journal,
                        EventKind::HostState,
                        Some(id),
                        Some((from, HostState::AwaitingReboot)),
                        serde_json::json!({
                            "system": seen.and_then(|o| o.current_system.clone()),
                            "generation": seen.and_then(|o| o.generation),
                            "booted": booted,
                            "waiting_for": "provider-reboot",
                            "bundle": wait.bundle,
                            "resume": self.options.run_id,
                        }),
                    )?;
                    self.set_state(hosts, id, HostState::AwaitingReboot);
                    // The step keeps no `action.end`: it did not end. That is
                    // what a resume reads to know where this run stopped.
                    return Err(anyhow::Error::new(wait));
                }
            } // --- end lane 3-integration -----------------------------------
        }
        Ok(())
    }

    // -----------------------------------------------------------------
    // the steps
    // -----------------------------------------------------------------

    /// Deliver one planned file and collect target-side evidence. Public files are
    /// verified by digest; private files record mode/owner without hashing their contents.
    /// Only running units receive reload/restart actions. SSH enrollment still applies
    /// when delivery supplies the host's first service certificate.
    fn deliver(&self, id: &str, action: &Action) -> Result<Vec<String>> {
        let target = self.target(id)?;
        let host = self.release.resolved_fleet.hosts.get(id).ok_or_else(|| {
            anyhow::anyhow!("the release describes no host {id}, so it has no secrets either")
        })?;
        let wanted = action.desired.clone().unwrap_or_default();
        // Match the action against its exact secret reference instead of parsing
        // an ID/path delimiter.
        let secret = host
            .secret_refs
            .iter()
            .find(|s| format!("{} at {}", s.id, s.target_path) == wanted)
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "the step {} on {id} is about {wanted:?} and this release names no such \
                     secret for it. The plan and the release do not describe the same fleet.",
                    action.seq
                )
            })?;

        let Some(source) = crate::pki::local_source(
            &self.options.repo,
            self.options.ca_dir.as_deref().unwrap_or(&self.options.repo),
            id,
            secret,
        ) else {
            bail!(
                "{} is made on {id} itself and never travels — `meister-activate keygen` \
                 makes it there and only the request comes back. A plan that asks for it to \
                 be delivered is a plan this tool will not carry out.",
                secret.target_path
            );
        };
        if !self.files.exists(&source) {
            bail!(
                "{} is not there, and it is what {id} needs at {}. Nothing was sent. Issue \
                 it first: `keys csr --host {id} --kind …` makes the request on the host, \
                 `keys issue --host {id} --kind …` signs it.",
                source.display(),
                secret.target_path
            );
        }
        let bytes = self.files.read(&source)?;
        // Compare local bytes with the planned digest before upload so changed
        // credentials cannot be delivered under an approval for different content.
        if let Some(expected) = &action.expected_sha256 {
            let here = format!("sha256:{}", crate::ids::sha256_hex(&bytes));
            if &here != expected {
                bail!(
                    "{} hashes to {here} and this plan was made for {expected}. The file \
                     changed after the plan was written; make it again.",
                    source.display()
                );
            }
        }

        let put = self.ssh.put(
            &target,
            &secret.target_path,
            &bytes,
            &secret.mode,
            &format!("{}:{}", secret.owner, secret.owner),
            REMOTE_DEADLINE,
        );
        self.runner.run(&put)?;

        // Collect public digests or private-file mode/owner from the target.
        let public = crate::observe::is_certificate(&secret.target_path);
        let question = if public {
            format!(
                "sha256sum {} 2>/dev/null | cut -d' ' -f1",
                crate::run::shell_quote(&secret.target_path)
            )
        } else {
            format!(
                "stat -c 'mode:%a owner:%U:%G' {}",
                crate::run::shell_quote(&secret.target_path)
            )
        };
        let answer = self
            .runner
            .run(&self.ssh.ask(&target, &question, REMOTE_DEADLINE))?;
        let seen = answer.trimmed().to_string();
        let mut evidence = vec![format!(
            "{} at {}: {}",
            secret.id,
            secret.target_path,
            if public {
                format!("sha256:{seen}")
            } else {
                seen.clone()
            }
        )];
        if public {
            let here = crate::ids::sha256_hex(&bytes);
            if seen != here {
                bail!(
                    "{id} answered with sha256:{seen} for {} and this workstation sent \
                     sha256:{here}. Something is between the two, or the file was replaced \
                     between the write and the question.",
                    secret.target_path
                );
            }
        }

        // CRL readers refresh on their own interval; delivery needs no unit restart.
        if secret.kind == crate::manifest::SecretKind::Crl {
            evidence.push(
                "no unit was restarted: a controller re-reads its revocation list within 30 s"
                    .to_string(),
            );
            return Ok(evidence);
        }

        // And the unit that reads it, if it is running.
        if let Some(reload) = &secret.reload {
            // Accept inactive/failed (3) and missing (4) units as probe answers.
            // SSH transport failure (255) remains an error.
            let active = self.runner.run(
                &self
                    .ssh
                    .ask(
                        &target,
                        &format!(
                            "systemctl is-active {}",
                            crate::run::shell_quote(&reload.unit)
                        ),
                        REMOTE_DEADLINE,
                    )
                    .expect(Expect::Codes(vec![0, 1, 3, 4])),
            )?;
            if active.trimmed() == "active" {
                let cmd = self.ssh.exec(
                    &target,
                    ["systemctl", &reload.action, &reload.unit],
                    Effect::TargetWrite,
                    REMOTE_DEADLINE,
                );
                self.runner.run(&cmd)?;
                evidence.push(format!("{} {}", reload.action, reload.unit));
            } else {
                evidence.push(format!(
                    "{} was {} and was left alone",
                    reload.unit,
                    active.trimmed()
                ));
            }
        }
        Ok(evidence)
    }


    /// Check the local active certificate against this rotation's expected digest.
    /// Missing or unreadable local evidence means publication still needs checking.
    fn rotation_published(&self, id: &str) -> bool {
        let Some(rotation) = self.plan.rotations.get(id) else {
            return false;
        };
        let active = self
            .options
            .repo
            .join(crate::pki::ISSUED_DIR)
            .join(id)
            .join(format!("{}.crt", rotation.kind));
        self.files
            .read(&active)
            .map(|bytes| {
                format!("sha256:{}", crate::ids::sha256_hex(&bytes)) == rotation.cert_sha256
            })
            .unwrap_or(false)
    }

    /// Where the rotation on this host has got to, asked of the host.
    fn keys_state(&self, id: &str) -> Result<crate::activate::KeysState> {
        let kind = self
            .plan
            .rotations
            .get(id)
            .map(|r| r.kind.clone())
            .unwrap_or_else(|| "identity".to_string());
        let cmd = self.helper_cmd(id, &["keys", "status", "--kind", &kind])?;
        let answer = self.runner.run(&cmd)?;
        let text = answer.trimmed();
        // The helper prints its usual envelope (`{ok, what, result}`) with
        // `--json`; a bare view is accepted too, so that a test can hand
        // one over without building the envelope around it.
        let view: crate::activate::KeysView = match serde_json::from_str(text) {
            Ok(view) => view,
            Err(_) => serde_json::from_str::<serde_json::Value>(text)
                .ok()
                .and_then(|v| v.get("result").cloned())
                .and_then(|v| serde_json::from_value(v).ok())
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "meister-activate keys status on {id} did not answer with the json \
                         this tool reads"
                    )
                })?,
        };
        Ok(view.state)
    }

    /// What this plan says it is rotating on this host.
    fn rotation(&self, id: &str, action: &Action) -> Result<crate::plan::KeyRotation> {
        self.plan.rotations.get(id).cloned().ok_or_else(|| {
            anyhow::anyhow!(
                "the step {} on {id} is a {} and this plan carries no rotation for {id}. A \
                 rotation plan is made by `keys rotate`, which prepares the key on the host \
                 first; a plan without that is a plan about nothing.",
                action.seq,
                action.kind
            )
        })
    }

    /// Write and verify the next certificate without replacing the active one.
    fn overlap(&self, id: &str, rotation: &crate::plan::KeyRotation) -> Result<Vec<String>> {
        let target = self.target(id)?;
        let source = self.options.repo.join(&rotation.source);
        if !self.files.exists(&source) {
            bail!(
                "{} is not there, and it is the certificate this rotation is about. Make the \
                 plan again with `keys rotate --host {id} --kind {}`.",
                source.display(),
                rotation.kind
            );
        }
        let bytes = self.files.read(&source)?;
        let here = format!("sha256:{}", crate::ids::sha256_hex(&bytes));
        if here != rotation.cert_sha256 {
            bail!(
                "{} hashes to {here} and this plan was made for {}. The file changed after \
                 the plan was written; make it again.",
                source.display(),
                rotation.cert_sha256
            );
        }
        let next = format!("{}.next", rotation.cert_path);
        let put = self.ssh.put(
            &target,
            &next,
            &bytes,
            &rotation.mode,
            &format!("{}:{}", rotation.owner, rotation.owner),
            REMOTE_DEADLINE,
        );
        self.runner.run(&put)?;
        let answer = self.runner.run(&self.ssh.ask(
            &target,
            &format!(
                "sha256sum {} 2>/dev/null | cut -d' ' -f1",
                crate::run::shell_quote(&next)
            ),
            REMOTE_DEADLINE,
        ))?;
        let seen = format!("sha256:{}", answer.trimmed());
        if seen != rotation.cert_sha256 {
            bail!(
                "{id} answered {seen} for {next} and this workstation sent {}. Something is \
                 between the two.",
                rotation.cert_sha256
            );
        }
        Ok(vec![format!("{next}: {seen}")])
    }

    /// Restart only running units that consume the rotated pair.
    fn poke(&self, id: &str, units: &[String], refs: &mut Vec<String>) -> Result<Vec<String>> {
        let target = self.target(id)?;
        let mut evidence = Vec::new();
        for unit in units {
            let active = self.runner.run(
                &self
                    .ssh
                    .ask(
                        &target,
                        &format!("systemctl is-active {}", crate::run::shell_quote(unit)),
                        REMOTE_DEADLINE,
                    )
                    .expect(Expect::Codes(vec![0, 1, 3])),
            )?;
            if active.trimmed() == "active" {
                let cmd = self.ssh.exec(
                    &target,
                    ["systemctl", "restart", unit],
                    Effect::TargetWrite,
                    REMOTE_DEADLINE,
                );
                refs.push(cmd.line());
                self.runner.run(&cmd)?;
                evidence.push(format!("restart {unit}"));
            } else {
                evidence.push(format!(
                    "{unit} was {} and was left alone",
                    active.trimmed()
                ));
            }
        }
        Ok(evidence)
    }

    /// Carry the closure, then check at the TARGET that what arrived is what
    /// the release names (V12), then let the helper say it is whole.
    fn stage(&self, id: &str, action: &Action) -> Result<Vec<String>> {
        let target = self.target(id)?;
        let artifacts = self.release.artifacts.get(id).ok_or_else(|| {
            anyhow::anyhow!("the release builds nothing for {id}, so there is nothing to stage")
        })?;
        let toplevel = action
            .desired
            .clone()
            .unwrap_or_else(|| artifacts.toplevel.store_path.clone());

        // Enable destination substitution only when the release records a cache
        // and the target declares substituters. The target chooses its configured
        // cache sources; copying and remote NAR verification still run.
        let substitute = self.release.build_env.cache_url.is_some()
            && self
                .release
                .resolved_fleet
                .hosts
                .get(id)
                .map(|host| !host.substituters.is_empty())
                .unwrap_or(false);
        let mut copy = Cmd::new(Effect::TargetWrite, "nix", COPY_DEADLINE).arg("copy");
        if substitute {
            copy = copy.arg("--substitute-on-destination");
        }
        let copy = copy
            .arg("--to")
            .arg(target.store_url())
            .arg(&toplevel)
            // Use shared SSH options; reject paths Nix cannot represent before copying.
            .env("NIX_SSHOPTS", self.ssh.nix_sshopts(target.port)?);
        self.runner.run(&copy)?;

        // Check the target toplevel NAR hash against the release before activation.
        let info =
            crate::nix::path_info_cmd(Some(&target.store_url()), std::slice::from_ref(&toplevel))
                .env("NIX_SSHOPTS", self.ssh.nix_sshopts(target.port)?);
        let out = self.runner.run(&info)?;
        let seen = crate::build::parse_path_info(&out.stdout, &format!("nix path-info on {id}"))?
            .get(&toplevel)
            .map(|info| info.nar_hash.clone())
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "{id} says nothing about {toplevel} after it was copied there, so what                      arrived cannot be compared with what was built."
                )
            })?;
        if seen != artifacts.toplevel.nar_hash {
            bail!(
                "what is at {toplevel} on {id} hashes to {seen} and the release says {}. Same \
                 name, different bytes: nothing was activated.",
                artifacts.toplevel.nar_hash
            );
        }

        let stage = self.helper_cmd(id, &["stage", &toplevel])?;
        self.runner.run(&stage)?;
        let mut evidence = vec![
            format!("{toplevel} is on {id}"),
            format!("nar hash {seen} as the release says"),
        ];
        if substitute {
            evidence.push(format!(
                "{id} was allowed to fetch from its own substituters ({})",
                self.release.resolved_fleet.hosts[id]
                    .substituters
                    .join(", ")
            ));
        }
        Ok(evidence)
    }

    /// Build workstation CLI maintenance commands. Returning a drained node requires
    /// undrain before uncordon: clearing schedulable alone leaves spec.drain set.
    fn workload_verbs(&self, id: &str, action: &Action) -> Vec<&'static str> {
        match action.kind {
            ActionKind::Cordon => vec!["cordon"],
            ActionKind::Drain => vec!["drain"],
            _ if self
                .plan
                .actions_for(id)
                .iter()
                .any(|a| a.kind == ActionKind::Drain && !a.is_blocked()) =>
            {
                vec!["undrain", "uncordon"]
            }
            _ => vec!["uncordon"],
        }
    }

    fn workload_cmd(&self, id: &str, verb: &str) -> Result<Cmd> {
        let control = self.options.workload.as_ref().ok_or_else(|| {
            anyhow::anyhow!(
                "this step needs `meister node {verb}` and the inventory names no `[operator] \
                 cli_config`. A plan made with that reference blocks the step instead; this \
                 run was given one that does not have it."
            )
        })?;
        let host = self.fleet().hosts.get(id).ok_or_else(|| {
            anyhow::anyhow!("{id} is not a host of the manifest this release carries")
        })?;
        let group = host.controller_group.clone().ok_or_else(|| {
            anyhow::anyhow!(
                "{id} names no controller_group, so there is no cluster to cordon it in."
            )
        })?;
        let mut cmd = Cmd::new(Effect::TargetWrite, "meister", REMOTE_DEADLINE)
            .arg("--config")
            .arg(&control.cli_config);
        if let Some(profile) = &control.cli_profile {
            cmd = cmd.arg("-p").arg(profile);
        }
        Ok(cmd
            .arg("node")
            .arg(verb)
            .arg(id)
            .arg("--cluster")
            .arg(group))
    }

    /// Wait for an explicit target VM count of zero. Missing evidence is unknown,
    /// not an empty node.
    fn wait_for_drain(&self, id: &str) -> Result<u32> {
        let started = self.clock.now();
        loop {
            let obs = self.observe_one(id)?;
            match obs.vms_running {
                Some(0) => return Ok(0),
                seen => {
                    if self.clock.now() - started
                        > chrono::TimeDelta::from_std(self.options.drain_wait)
                            .unwrap_or_else(|_| chrono::TimeDelta::zero())
                    {
                        bail!(
                            "{id} still carries {} after {:?}, so it was not interrupted. \
                             What is on it is what the drain was to protect: look at \
                             `meister agent vm ls` on the node.",
                            match seen {
                                Some(n) => format!("{n} guest(s)"),
                                None => "an unknown number of guests".to_string(),
                            },
                            self.options.drain_wait
                        );
                    }
                    if self.cancel.is_cancelled() {
                        bail!("interrupted while waiting for {id} to be empty");
                    }
                    self.clock.sleep(self.options.poll);
                }
            }
        }
    }

    fn activate_cmd(&self, id: &str, action: &Action, txn: &str) -> Result<Cmd> {
        let desired = action
            .desired
            .clone()
            .unwrap_or_else(|| self.plan.hosts[id].desired_system.clone());
        let mode = match action.rollback.mode {
            RollbackMode::Boot => Mode::Boot,
            // `none` is not an activation mode: a step that activates has a
            // way back, and the planner gives every one of them a mode. A
            // plan that says `none` here is a plan this tool does not act on.
            RollbackMode::Switch => Mode::Switch,
            RollbackMode::None => bail!(
                "the step {} on {id} activates a system and names no way back. A plan whose \
                 activation has no rollback mode is not one this tool runs.",
                action.seq
            ),
        };
        let within = action.rollback.confirm_within_secs.to_string();
        self.helper_cmd(
            id,
            &[
                "activate",
                "--txn",
                txn,
                "--toplevel",
                &desired,
                "--mode",
                mode.as_str(),
                "--confirm-within",
                &within,
                "--run",
                &self.options.run_id,
            ],
        )
        .map(|cmd| cmd.expect(Expect::ExitZero))
    }

    /// Read the approved provider bundle from the plan and check it against
    /// the release before handoff.
    fn provider_wait(&self, id: &str, action: &Action) -> Result<ProviderWait> {
        let from_plan = action.provider_boot.as_ref();
        let from_release = self
            .release
            .artifacts
            .get(id)
            .and_then(|a| a.direct_boot.as_ref());
        let bundle = match (from_plan, from_release) {
            (Some(planned), Some(built)) if planned != built => bail!(
                "the plan says {id} is to be booted from {} and the release now carries {}. \
                 A halt hands somebody bytes to load, so the two have to be the same bytes; \
                 make the plan again.",
                planned.bundle_store_path,
                built.bundle_store_path
            ),
            (Some(planned), _) => planned.clone(),
            (None, Some(built)) => built.clone(),
            (None, None) => bail!(
                "the step {} on {id} is a provider-reboot and neither the plan nor the release \
                 says which kernel, initrd and command line a provider would load. Nothing was \
                 done to {id}.",
                action.seq
            ),
        };
        Ok(ProviderWait {
            host: id.to_string(),
            run_id: self.options.run_id.clone(),
            bundle,
        })
    }

    /// Request a reboot, accepting connection loss as an expected possibility.
    fn reboot(&self, id: &str) -> Result<Vec<String>> {
        let target = self.target(id)?;
        let mut cmd = self
            .ssh
            .ask(&target, "systemctl reboot", REMOTE_DEADLINE)
            // 255 is ssh's own "the connection went away", which is what a
            // machine that is rebooting does to it.
            .expect(Expect::AnyExit);
        // Retag this ask-built command as TargetWrite because reboot mutates the host.
        cmd.effect = Effect::TargetWrite;
        let line = cmd.line();
        self.runner.run(&cmd)?;
        Ok(vec![line])
    }

    /// Whether this host both belongs to a Raft group and runs an etcd member.
    fn is_raft_member(&self, id: &str) -> bool {
        let fleet = &self.release.resolved_fleet;
        // A rollout group can include hosts without their own etcd member.
        let has_etcd = fleet
            .hosts
            .get(id)
            .is_some_and(|host| host.effective_settings.etcd.is_some());
        has_etcd
            && fleet.groups.values().any(|group| {
                group.kind == crate::manifest::GroupKind::Raft
                    && group.members.iter().any(|m| m == id)
            })
    }

    /// Whether any member of the host's Raft group was healthy when planned.
    /// An entirely unhealthy bootstrap group skips the rejoin wait: its first
    /// member cannot establish quorum before later waves activate peers.
    fn group_was_serving(&self, id: &str) -> bool {
        let fleet = self.fleet();
        fleet
            .groups
            .iter()
            .filter(|(_, group)| {
                group.kind == crate::manifest::GroupKind::Raft
                    && group.members.iter().any(|m| m == id)
            })
            .filter_map(|(gid, _)| self.plan.groups.get(gid))
            .any(|view| view.unhealthy_now < view.size)
    }

    fn wait_for_boot(&self, id: &str, desired: &str) -> Result<String> {
        let started = self.clock.now();
        // What the last look said, for the sentence a person reads when the
        // deadline passes.
        let mut last;
        loop {
            match self.observe_one(id) {
                Ok(obs) if obs.reachable => match obs.booted_system.as_deref() {
                    // Wait for etcd recovery after SSH returns, before quorum and topology
                    // checks interpret temporarily incomplete membership.
                    Some(booted)
                        if booted == desired
                            && self.is_raft_member(id)
                            // come back to; see `group_was_serving`.
                            && self.group_was_serving(id)
                            && !obs.etcd.as_ref().is_some_and(|e| e.healthy) =>
                    {
                        last = "it booted the release and its etcd has not answered yet".to_string()
                    }
                    Some(booted) if booted == desired => return Ok(booted.to_string()),
                    Some(other) => last = format!("it booted {other}"),
                    None => last = "it answered and could not say what it booted".to_string(),
                },
                // A host that answered and is not reachable is a host the
                // probe reached and could not read.
                Ok(obs) => {
                    last = obs
                        .unknown_reason
                        .unwrap_or_else(|| "it did not answer".to_string())
                }
                Err(e) => last = format!("{e:#}"),
            }
            if self.clock.now() - started
                > chrono::TimeDelta::from_std(self.options.reboot_wait)
                    .unwrap_or_else(|_| chrono::TimeDelta::zero())
            {
                bail!(
                    "{id} did not come back as {desired} within {:?}: {last}. The host keeps \
                     its transaction record, so `apply --resume {}` asks it what happened \
                     rather than activating anything again.",
                    self.options.reboot_wait,
                    self.options.run_id
                );
            }
            if self.cancel.is_cancelled() {
                bail!("interrupted while waiting for {id} to come back");
            }
            self.clock.sleep(self.options.poll);
        }
    }

    /// The readiness checks of 2A, against a fresh snapshot and this release.
    fn verify(&self, id: &str, fresh: &Observations) -> Vec<CheckResult> {
        let Some(host) = self.fleet().hosts.get(id) else {
            return Vec::new();
        };
        let missing = HostObservation::unreachable(format!(
            "{id} was not in the snapshot taken for its own verification."
        ));
        let obs = fresh.host(id).unwrap_or(&missing);
        readiness::readiness(id, host, obs, Some(self.release))
    }

    /// Request rollback and observe the previous current system. Boot-mode rollback
    /// also reboots and waits; an unverified result requires recovery.
    fn take_back(
        &self,
        journal: &Journal,
        id: &str,
        hosts: &mut BTreeMap<String, HostRunState>,
        why: &str,
    ) -> Result<()> {
        let txn = self.require_txn(hosts, id)?;
        let mode = self.mode_of(id);
        let revert = self.helper_cmd(id, &["revert", "--txn", &txn, "--because", why])?;
        if let Err(e) = self.runner.run(&revert) {
            self.move_to(journal, id, hosts, HostState::RecoveryRequired, None)?;
            bail!(
                "{id} was asked to go back and could not ({e:#}). Nothing else was done to \
                 it: read `meister-activate txn show --txn {txn}` on the host."
            );
        }
        if mode == Mode::Boot {
            // In boot mode the running system was never changed; what the
            // revert undid is the boot entry. The machine has to go through
            // a boot for the rollback to be a fact.
            self.reboot(id)?;
            let previous = self
                .plan
                .observation
                .host(id)
                .and_then(|o| o.booted_system.clone())
                .unwrap_or_else(|| {
                    self.plan.hosts[id]
                        .current_system
                        .clone()
                        .unwrap_or_default()
                });
            if let Err(e) = self.wait_for_boot(id, &previous) {
                self.move_to(journal, id, hosts, HostState::RecoveryRequired, None)?;
                bail!("{id} did not come back on its previous system ({e:#})");
            }
        }
        let fresh = self.observe(&[id.to_string()])?;
        let seen = fresh.host(id);
        let before = self.plan.hosts[id].current_system.clone();
        let back = seen.and_then(|o| o.current_system.clone()) == before;
        if back {
            self.move_to(journal, id, hosts, HostState::RolledBack, seen)?;
            // Retire the transaction after observing rollback to permit a fresh plan.
            let retire = self.helper_cmd(
                id,
                &[
                    "txn",
                    "retire",
                    "--txn",
                    &txn,
                    "--run",
                    &self.options.run_id,
                ],
            )?;
            let _ = self.runner.run(&retire);
            self.entry(hosts, id).txn = None;
        } else {
            self.move_to(journal, id, hosts, HostState::RecoveryRequired, seen)?;
            bail!(
                "{id} was reverted and does not run what it ran before ({:?} now, {:?} then). \
                 This needs a person.",
                seen.and_then(|o| o.current_system.as_deref()),
                before
            );
        }
        Ok(())
    }

    /// Classify target state after failed activation without repeating activation.
    #[allow(clippy::too_many_arguments)]
    fn after_a_failed_activation(
        &self,
        journal: &Journal,
        id: &str,
        hosts: &mut BTreeMap<String, HostRunState>,
        why: anyhow::Error,
        observed: Option<HostObservation>,
        view: TxnView,
    ) -> Result<()> {
        let answered = observed.as_ref().map(|o| o.reachable).unwrap_or(false);
        let state = match view {
            TxnView::Reverted => HostState::RolledBack,
            // An unexpected confirming/reverting decision after this activation error
            // requires recovery; do not advance over an unexplained target transition.
            TxnView::Pending { .. }
            | TxnView::Confirming
            | TxnView::Reverting
            | TxnView::Inconsistent => HostState::RecoveryRequired,
            TxnView::Confirmed => HostState::Committed,
            // A responsive target with no transaction is classified as failed activation.
            TxnView::None if answered => HostState::Failed,
            // It did not answer. What happened is what a resume is for, and
            // guessing here would be guessing about a machine that may be
            // half way through a switch.
            TxnView::None => HostState::Unknown,
        };
        self.move_to(journal, id, hosts, state, observed.as_ref())?;
        bail!(
            "the activation of {id} failed ({why:#}); the host says {}",
            match state {
                HostState::RolledBack => "it took itself back",
                HostState::RecoveryRequired => "it has a transaction that needs a person",
                HostState::Committed => "the transaction is confirmed, which nobody here did",
                HostState::Failed => "nothing was activated",
                _ =>
                    "nothing at all — it did not answer, so `apply --resume` is what asks \
                      it again",
            }
        );
    }

    /// Poll target transaction state within a bounded network-recovery window.
    fn settled_view(&self, id: &str, txn: Option<&str>) -> (Option<HostObservation>, TxnView) {
        let started = self.clock.now();
        let mut last: Option<HostObservation> = None;
        loop {
            if let Ok(obs) = self.observe_one(id) {
                if obs.reachable {
                    let view = TxnView::of(&obs, txn);
                    return (Some(obs), view);
                }
                last = Some(obs);
            }
            if self.clock.now() - started
                > chrono::TimeDelta::from_std(self.options.settle_wait)
                    .unwrap_or_else(|_| chrono::TimeDelta::zero())
            {
                let view = last
                    .as_ref()
                    .map(|obs| TxnView::of(obs, txn))
                    .unwrap_or(TxnView::None);
                return (last, view);
            }
            self.clock.sleep(self.options.poll);
        }
    }

    // -----------------------------------------------------------------
    // resume
    // -----------------------------------------------------------------

    /// Reconcile a reboot that may have completed before its journal end event.
    /// A changed boot ID plus the desired system completes it; a changed ID with
    /// another system requires recovery. An unchanged ID permits reboot. Without
    /// boot-ID evidence, fall back to the booted system.
    fn settle_reboot(
        &self,
        journal: &Journal,
        id: &str,
        hosts: &mut BTreeMap<String, HostRunState>,
        run: &HostRun,
        observed: &HostObservation,
    ) -> Result<bool> {
        if run.rebooted() {
            return Ok(true);
        }
        let Some(open) = run.reboot_in_flight() else {
            return Ok(false);
        };
        let desired = self.plan.hosts[id].desired_system.clone();
        let booted = observed.booted_system.clone().unwrap_or_default();
        let came_up_right = booted == desired;
        let ids = (open.boot_id_before.as_deref(), observed.boot_id.as_deref());
        let went_round = match ids {
            (Some(before), Some(now)) => Some(before != now),
            _ => None,
        };
        let done = match went_round {
            Some(false) => false,
            Some(true) if came_up_right => true,
            Some(true) => {
                self.move_to(
                    journal,
                    id,
                    hosts,
                    HostState::RecoveryRequired,
                    Some(observed),
                )?;
                bail!(
                    "{id} went round after its reboot step began (boot id {} became {}) and \
                     came up as {}, not as {desired}. Nothing here reboots it again: the \
                     one-shot boot entry is spent, so a second reboot would boot the fallback \
                     and undeploy this host. Look at it, and at `meister-activate txn list` \
                     on it.",
                    ids.0.unwrap_or("?"),
                    ids.1.unwrap_or("?"),
                    if booted.is_empty() {
                        "nothing it could name"
                    } else {
                        booted.as_str()
                    }
                )
            }
            None => came_up_right,
        };
        if done
            && let Some(action) = self
                .plan
                .actions_for(id)
                .into_iter()
                .find(|a| a.kind == ActionKind::Reboot && a.seq == open.seq)
        {
            // The end the run did not live to write: the reboot happened,
            // and from now on the journal says so.
            let how = match ids {
                (Some(before), Some(now)) => format!(", boot id {before} became {now}"),
                _ => String::new(),
            };
            self.end(
                journal,
                id,
                action,
                ActionResult::Ok,
                vec![format!("booted {booted} (found on resume{how})")],
                Vec::new(),
            )?;
        }
        Ok(done)
    }

    /// Where a resume picks this host up — the V17 table, asked of the
    /// journal and of the target and of nothing else.
    fn resume_point(
        &self,
        journal: &Journal,
        id: &str,
        hosts: &mut BTreeMap<String, HostRunState>,
    ) -> Result<Resume> {
        let read = read_journal(self.files, &self.state.journal_path(&self.options.run_id))?;
        let folded = fold(&read.events)?;
        let Some(run) = folded.host(id) else {
            return Ok(Resume::Carry);
        };
        let observed = self.observe_one(id)?;
        // Rotations resume from key-state evidence, separate from activation transactions.
        if self.plan.kind == crate::plan::PlanKind::KeysRotate {
            let state = self.keys_state(id)?;
            // Check local certificate publication as well as target confirmation.
            let published = self.rotation_published(id);
            return match crate::receipt::next_keys_step(run, state, published) {
                Step::Done => Ok(Resume::Done),
                Step::AtKeysPhase(phase) => {
                    if crate::receipt::keys_phase_order(phase)
                        > crate::receipt::keys_phase_order(ActionKind::KeysSwitch)
                    {
                        // The pair is in. Whatever else this run does, it
                        // has already moved this host.
                        self.entry(hosts, id).moved = true;
                    }
                    Ok(Resume::AtKeysPhase(phase))
                }
                Step::RolledBack => {
                    self.move_to(journal, id, hosts, HostState::RolledBack, Some(&observed))?;
                    Ok(Resume::Done)
                }
                Step::RecoveryRequired(why) => {
                    self.move_to(
                        journal,
                        id,
                        hosts,
                        HostState::RecoveryRequired,
                        Some(&observed),
                    )?;
                    bail!("{why}")
                }
                other => bail!(
                    "the resume table answered {other:?} for the rotation on {id}, which is \
                     not an answer about a rotation."
                ),
            };
        }
        let view = TxnView::of(&observed, run.txn_id.as_deref());
        match next_step(run, &view) {
            Step::Done => Ok(Resume::Done),
            Step::StartOver | Step::ResumeFromStage => Ok(Resume::Carry),
            Step::AtTheProviderReboot => {
                // The journal transaction ID may be absent for reboot-only plans.
                self.entry(hosts, id).txn = run.txn_id.clone();
                self.entry(hosts, id).moved = run.txn_id.is_some();
                self.set_state(hosts, id, HostState::AwaitingReboot);
                Ok(Resume::AtTheProviderReboot)
            }
            // Journal resumed state transitions so the next event has a valid predecessor.
            Step::VerifyOnly => {
                self.entry(hosts, id).txn = run.txn_id.clone();
                let rebooted = self.settle_reboot(journal, id, hosts, run, &observed)?;
                self.move_to(journal, id, hosts, HostState::Verifying, Some(&observed))?;
                Ok(Resume::AfterTheActivation {
                    confirmed: true,
                    rebooted,
                })
            }
            Step::VerifyAndConfirm => {
                // The activation happened and the target is still waiting
                // for a word. The transaction id comes from the journal,
                // never from a new one.
                self.entry(hosts, id).txn = run.txn_id.clone();
                let rebooted = self.settle_reboot(journal, id, hosts, run, &observed)?;
                self.move_to(journal, id, hosts, HostState::Verifying, Some(&observed))?;
                Ok(Resume::AfterTheActivation {
                    confirmed: false,
                    rebooted,
                })
            }
            Step::RolledBack => {
                self.move_to(journal, id, hosts, HostState::RolledBack, Some(&observed))?;
                Ok(Resume::Done)
            }
            Step::RecoveryRequired(why) => {
                self.move_to(
                    journal,
                    id,
                    hosts,
                    HostState::RecoveryRequired,
                    Some(&observed),
                )?;
                bail!("{why}");
            }
            // Rotation states are handled by the separate rotation resume table.
            Step::AtKeysPhase(phase) => bail!(
                "the resume table answered {phase} for {id}, which is a phase of a key \
                 rotation and this plan is a {}.",
                self.plan.kind
            ),
        }
    }

    // -----------------------------------------------------------------
    // locks
    // -----------------------------------------------------------------

    /// Choose inventory control-plane hosts as cross-checkout lock anchors,
    /// including those outside the plan selection when reachable via frozen endpoints.
    fn anchor_hosts(&self) -> Vec<String> {
        self.fleet()
            .hosts
            .iter()
            .filter(|(_, h)| {
                h.deployment == crate::manifest::Deployment::Nixos
                    && h.roles.iter().any(|r| r == "cloud" || r == "cluster")
            })
            .map(|(id, _)| id.clone())
            .collect()
    }

    fn take_anchor(
        &self,
        journal: &Journal,
        anchor: &[String],
        hosts: &mut BTreeMap<String, HostRunState>,
    ) -> Result<()> {
        let mut unreachable = Vec::new();
        for id in anchor {
            if self.plan.hosts.get(id).map(|h| h.verdict.blocks()) == Some(true) {
                unreachable.push(format!("{id} (the plan blocked it)"));
                continue;
            }
            let cmd = match self.lock_cmd(id) {
                Ok(cmd) => cmd,
                Err(e) => {
                    unreachable.push(format!("{id} ({e:#})"));
                    continue;
                }
            };
            match self.runner.run(&cmd) {
                Ok(_) => {
                    if hosts.contains_key(id) {
                        let entry = self.entry(hosts, id);
                        entry.locked = true;
                        entry.anchored = true;
                    } else {
                        hosts.insert(
                            id.clone(),
                            HostRunState {
                                state: HostState::Planned,
                                txn: None,
                                locked: true,
                                anchored: true,
                                moved: false,
                            },
                        );
                    }
                    self.write(
                        journal,
                        EventKind::LockAcquire,
                        Some(id),
                        None,
                        serde_json::json!({ "run_id": self.options.run_id, "anchor": true }),
                    )?;
                }
                Err(e) => {
                    let text = format!("{e:#}");
                    // Foreign lock ownership blocks execution; other anchor failures are
                    // reported as incomplete exclusion.
                    if text.contains("is held by the run") {
                        bail!(
                            "the fleet anchor could not be taken: {text} Nothing was done to \
                             any host."
                        );
                    }
                    unreachable.push(format!("{id} ({text})"));
                }
            }
        }
        if !unreachable.is_empty() {
            eprintln!(
                "note: the fleet anchor is incomplete: {}. The state directory's lock still \
                 holds for this workstation, and a second operator on a second checkout would \
                 not be kept out by these hosts.",
                unreachable.join(", ")
            );
        }
        Ok(())
    }

    /// Give back every lock this run took, whatever the run came to.
    fn release_locks(&self, journal: &Journal, hosts: &mut BTreeMap<String, HostRunState>) {
        let held: Vec<String> = hosts
            .iter()
            .filter(|(_, s)| s.locked)
            .map(|(id, _)| id.clone())
            .collect();
        for id in held {
            let Ok(Some(cmd)) = self.unlock_cmd(&id, hosts, Release::RunEnd) else {
                continue;
            };
            if self.runner.run(&cmd).is_ok() {
                self.entry(hosts, &id).locked = false;
                let _ = self.write(
                    journal,
                    EventKind::LockRelease,
                    Some(&id),
                    None,
                    serde_json::json!({ "run_id": self.options.run_id }),
                );
            }
        }
    }

    fn lock_cmd(&self, id: &str) -> Result<Cmd> {
        let operator = format!("{}@{}", self.operator.user, self.operator.workstation);
        let pid = std::process::id().to_string();
        match &self.options.takeover {
            Some(of_run) => self.helper_cmd(
                id,
                &[
                    "lock",
                    "take-over",
                    "--of-run",
                    of_run,
                    "--run",
                    &self.options.run_id,
                    "--operator",
                    &operator,
                    "--pid",
                    &pid,
                ],
            ),
            None => self.helper_cmd(
                id,
                &[
                    "lock",
                    "acquire",
                    "--run",
                    &self.options.run_id,
                    "--operator",
                    &operator,
                    "--pid",
                    &pid,
                ],
            ),
        }
    }

    /// Release a held host lock at its action boundary, or an anchor only
    /// during final run cleanup.
    fn unlock_cmd(
        &self,
        id: &str,
        hosts: &BTreeMap<String, HostRunState>,
        when: Release,
    ) -> Result<Option<Cmd>> {
        let Some(held) = hosts.get(id) else {
            return Ok(None);
        };
        if !held.locked || (when == Release::HostStep && held.anchored) {
            return Ok(None);
        }
        self.helper_cmd(id, &["lock", "release", "--run", &self.options.run_id])
            .map(Some)
    }

    // -----------------------------------------------------------------
    // looking
    // -----------------------------------------------------------------

    /// Refresh the target and available selected Raft peers for quorum-dependent
    /// validation. Other hosts retain the plan observation.
    fn affected(&self, id: &str) -> Vec<String> {
        let mut out = BTreeSet::new();
        out.insert(id.to_string());
        if let Some(host) = self.fleet().hosts.get(id) {
            for group in &host.groups {
                let Some(g) = self.fleet().groups.get(group) else {
                    continue;
                };
                if g.kind != crate::manifest::GroupKind::Raft {
                    continue;
                }
                for member in &g.members {
                    if self.plan.selection.targets.contains(member)
                        || self.plan.endpoints.contains_key(member)
                    {
                        out.insert(member.clone());
                    }
                }
            }
        }
        out.into_iter().collect()
    }

    /// Merge fresh affected-host observations into the original snapshot. Changes
    /// on hosts outside this set are not detected by this validation pass.
    fn observe(&self, ids: &[String]) -> Result<Observations> {
        let mut snapshot = self.plan.observation.clone();
        snapshot.taken_at = self.clock.now();
        snapshot.provisional = false;
        for id in ids {
            let obs = self.observe_one(id)?;
            snapshot.hosts.insert(id.clone(), obs);
        }
        Ok(snapshot)
    }

    /// One host, one read-only round trip.
    fn observe_one(&self, id: &str) -> Result<HostObservation> {
        let target = self.target(id)?;
        let host = self
            .fleet()
            .hosts
            .get(id)
            .ok_or_else(|| anyhow::anyhow!("{id} is not a host of this release's manifest"))?;
        Ok(self.look.observe(host, &target))
    }

    /// Remove this run's own lock, transaction and system changes before comparing
    /// against the plan. Preserve identity and quorum evidence so unrelated changes
    /// still invalidate the step.
    fn own_footprints_removed(
        &self,
        fresh: &Observations,
        hosts: &BTreeMap<String, HostRunState>,
    ) -> Observations {
        let mut out = fresh.clone();
        for (id, obs) in out.hosts.iter_mut() {
            if obs.lock.as_ref().map(|l| l.run_id.as_str()) == Some(self.options.run_id.as_str()) {
                obs.lock = self.plan.observation.host(id).and_then(|o| o.lock.clone());
            }
            obs.open_txns.retain(|t| {
                t.id != self.txn_id() && t.run_id.as_deref() != Some(self.options.run_id.as_str())
            });
            let moved = hosts.get(id).map(|s| s.moved).unwrap_or(false);
            if moved && let Some(before) = self.plan.observation.host(id) {
                obs.current_system = before.current_system.clone();
                obs.booted_system = before.booted_system.clone();
                obs.next_boot_system = before.next_boot_system.clone();
                obs.generation = before.generation;
            }
        }
        out
    }

    /// What the plan assumed, re-checked now.
    fn guard(
        &self,
        fresh: &Observations,
        id: &str,
        hosts: &BTreeMap<String, HostRunState>,
    ) -> Result<()> {
        let fresh = self.own_footprints_removed(fresh, hosts);
        // group block that says only "this one is down" must not stop the
        // run that is bringing it up.
        match validate_against_next(self.plan, self.release, &fresh, self.clock.now(), Some(id)) {
            Verdict::Proceed => Ok(()),
            Verdict::Stop { reasons } => bail!(
                "this plan is not the truth about the fleet any more, so nothing more was done \
                 ({id} was next): {}",
                reasons.join("; ")
            ),
            Verdict::Replan { reasons } => bail!(
                "the fleet moved under this plan ({id} was next); make it again with `plan` \
                 and read it before applying it: {}",
                reasons.join("; ")
            ),
        }
    }

    // -----------------------------------------------------------------
    // small things
    // -----------------------------------------------------------------

    fn fleet(&self) -> &ResolvedFleet {
        &self.release.resolved_fleet
    }

    fn endpoint(&self, id: &str) -> Result<&Endpoint> {
        self.plan.endpoints.get(id).ok_or_else(|| {
            anyhow::anyhow!(
                "this plan froze no address for {id}. A plan carries the endpoints it was made \
                 with; make it again."
            )
        })
    }

    fn target(&self, id: &str) -> Result<Target> {
        Ok(Target::from_endpoint(id, self.endpoint(id)?))
    }

    /// Build a target helper command using the configured deploy directory.
    fn helper_cmd(&self, id: &str, args: &[&str]) -> Result<Cmd> {
        let target = self.target(id)?;
        let mut argv = vec!["meister-activate".to_string(), "--json".to_string()];
        argv.extend(args.iter().map(|a| a.to_string()));
        Ok(self
            .ssh
            .exec(&target, argv, Effect::TargetWrite, ACTIVATE_DEADLINE))
    }

    /// The transaction id of this run on this host. One per host per run:
    /// the record lives on the host, so the run id is unique there, and a
    /// receipt that names it can be read against the host's own record.
    fn txn_id(&self) -> String {
        self.options.run_id.clone()
    }

    fn require_txn(&self, hosts: &BTreeMap<String, HostRunState>, id: &str) -> Result<String> {
        hosts.get(id).and_then(|s| s.txn.clone()).ok_or_else(|| {
            anyhow::anyhow!(
                "there is no transaction of this run on {id}, so there is nothing to confirm \
                 or to take back. This is a bug in the order of a plan rather than a state of \
                 the fleet."
            )
        })
    }

    fn mode_of(&self, id: &str) -> Mode {
        self.plan
            .actions_for(id)
            .iter()
            .find(|a| a.kind == ActionKind::Activate)
            .map(|a| match a.rollback.mode {
                RollbackMode::Boot => Mode::Boot,
                _ => Mode::Switch,
            })
            .unwrap_or(Mode::Switch)
    }

    fn entry<'h>(
        &self,
        hosts: &'h mut BTreeMap<String, HostRunState>,
        id: &str,
    ) -> &'h mut HostRunState {
        hosts.entry(id.to_string()).or_insert(HostRunState {
            state: HostState::Planned,
            txn: None,
            locked: false,
            anchored: false,
            moved: false,
        })
    }

    fn set_state(&self, hosts: &mut BTreeMap<String, HostRunState>, id: &str, to: HostState) {
        self.entry(hosts, id).state = to;
    }

    /// Journal the previous and next host states before updating memory.
    fn move_to(
        &self,
        journal: &Journal,
        id: &str,
        hosts: &mut BTreeMap<String, HostRunState>,
        to: HostState,
        seen: Option<&HostObservation>,
    ) -> Result<()> {
        let from = self.entry(hosts, id).state;
        let payload = match seen {
            Some(obs) => serde_json::json!({
                "system": obs.current_system,
                "generation": obs.generation,
                "booted": obs.booted_system,
            }),
            None => serde_json::json!({}),
        };
        let event = journal
            .event(EventKind::HostState, self.clock.now())
            .host(id)
            .transition(from, to)
            .payload(payload);
        journal.append(self.files, event)?;
        self.entry(hosts, id).state = to;
        Ok(())
    }

    fn begin(&self, journal: &Journal, id: &str, action: &Action) -> Result<()> {
        self.begin_with_evidence(journal, id, action, Vec::new())
    }

    /// Journal pre-command evidence for interrupted-action reconciliation.
    fn begin_with_evidence(
        &self,
        journal: &Journal,
        id: &str,
        action: &Action,
        evidence: Vec<String>,
    ) -> Result<()> {
        self.write(
            journal,
            EventKind::ActionBegin,
            Some(id),
            None,
            serde_json::json!({
                "action": action.seq,
                "kind": action.kind,
                "current": action.current,
                "desired": action.desired,
                "evidence": evidence,
            }),
        )
    }

    fn end(
        &self,
        journal: &Journal,
        id: &str,
        action: &Action,
        result: ActionResult,
        evidence: Vec<String>,
        cmd_refs: Vec<String>,
    ) -> Result<()> {
        self.end_inner(journal, id, action, result, evidence, cmd_refs, Vec::new())
    }

    fn end_with_checks(
        &self,
        journal: &Journal,
        id: &str,
        action: &Action,
        result: ActionResult,
        checks: Vec<CheckResult>,
        cmd_refs: Vec<String>,
    ) -> Result<()> {
        self.end_inner(journal, id, action, result, Vec::new(), cmd_refs, checks)
    }

    #[allow(clippy::too_many_arguments)]
    fn end_inner(
        &self,
        journal: &Journal,
        id: &str,
        action: &Action,
        result: ActionResult,
        evidence: Vec<String>,
        cmd_refs: Vec<String>,
        checks: Vec<CheckResult>,
    ) -> Result<()> {
        self.write(
            journal,
            EventKind::ActionEnd,
            Some(id),
            None,
            serde_json::json!({
                "action": action.seq,
                "kind": action.kind,
                "result": result,
                "evidence": evidence,
                "cmd_refs": cmd_refs,
                "checks": checks,
            }),
        )
    }

    fn write(
        &self,
        journal: &Journal,
        kind: EventKind,
        host: Option<&str>,
        transition: Option<(HostState, HostState)>,
        payload: serde_json::Value,
    ) -> Result<()> {
        let mut event = journal.event(kind, self.clock.now()).payload(payload);
        if let Some(host) = host {
            event = event.host(host);
        }
        if let Some((from, to)) = transition {
            event = event.transition(from, to);
        }
        journal.append(self.files, event)?;
        Ok(())
    }
}

/// Where a resume found a host.
enum Resume {
    /// Nothing more to do here.
    Done,
    /// Carry on with the plan's steps from the beginning: nothing
    /// irreversible had begun, and everything before it can be done again.
    Carry,
    /// Resume after activation, skipping confirmation or reboot when their
    /// completion is already supported by evidence.
    AfterTheActivation { confirmed: bool, rebooted: bool },
    /// The run stopped in front of the provider's reboot. Everything before
    /// it happened; the step itself asks the machine again.
    AtTheProviderReboot,
    /// Resume the remaining rotation phases without preparing another key.
    AtKeysPhase(ActionKind),
}

/// Actions requiring a fresh guard. Preflight/verify observe directly;
/// lock/unlock rely on helper ownership checks.
fn needs_validation(kind: ActionKind) -> bool {
    matches!(
        kind,
        ActionKind::Stage
            | ActionKind::KeysPrepare
            | ActionKind::KeysOverlap
            | ActionKind::KeysSwitch
            | ActionKind::KeysRemove
            | ActionKind::DeliverSecret
            | ActionKind::Cordon
            | ActionKind::Drain
            | ActionKind::Activate
            | ActionKind::Reboot
            // A provider-reboot changes nothing here and is validated all
            // the same: the fresh look is the whole step — it is what
            // decides between carrying on and stopping.
            | ActionKind::ProviderReboot
            | ActionKind::Confirm
            | ActionKind::Uncordon
            | ActionKind::Install
            | ActionKind::Revoke
            | ActionKind::Gc
    )
}

#[cfg(test)]
mod tests;
