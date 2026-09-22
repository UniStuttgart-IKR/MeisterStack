// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! The machine of §6: what `apply` actually does to a fleet.
//!
//! Everything about a rollout that is a DECISION was made before this file
//! runs. The planner said which hosts, in which order, in which wave, with
//! which approval class and with which way back ([`crate::plan`]); the
//! release said which bytes ([`crate::release`]); the observation said what
//! was there. What is left here is execution, and its whole worth is in four
//! properties:
//!
//! * **Nothing is done to a host that was not just looked at.** Before every
//!   mutating step the host is probed again and
//!   [`crate::plan::validate_against`] re-checks what the plan assumed. Not
//!   once at the start: between the plan and the third host of a wave there
//!   is a rollout's worth of time.
//! * **The journal is ahead of the world.** `action.irreversible` is written
//!   and `fsync`ed BEFORE the activation, so a workstation that dies in the
//!   middle leaves a file that says "something was started here". What
//!   happened after it is a question for the target, which keeps a
//!   transaction record — and [`crate::receipt::next_step`] is the table
//!   that puts the two answers together (V17). Nothing is ever repeated
//!   blind.
//! * **A host that fails does not take the fleet with it, and a host that
//!   succeeds does not hide one that failed.** A failure ends the run before
//!   the next wave, every host that was not reached is named in
//!   `untouched[]`, and a verified rollback is `rolled-back` and never
//!   `success`.
//! * **Two operators cannot both be here.** The state directory's lock (2A)
//!   is the workstation's door; the per-host lock `meister-activate` writes
//!   is the fleet's, and the control-plane hosts are locked before the first
//!   step as the fleet anchor (D6).
//!
//! **One deliberate departure from the lane brief.** Hosts of one wave are
//! executed one after another, not in parallel, and there is no `--parallel`
//! flag. The reason is that the only runner the tests may use is a strict
//! SEQUENCE of expected commands ([`crate::run::StrictFake`], by design of
//! lane 1C) — a parallel path could not be pinned by a test at all, and an
//! untested concurrency in the code that reboots machines is worth less than
//! a wave that takes longer. The waves are what bound the risk: a raft
//! group's wave is one host by construction, and a compute group's wave is
//! at most its `max_unavailable`. Making the hosts of a wave concurrent is
//! M4A's, together with the measurement over seventy hosts that would
//! justify it.

use std::collections::{BTreeMap, BTreeSet};
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
    WorkloadControl, approvals_missing, validate_against,
};
use crate::readiness;
use crate::receipt::{
    ActionResult, DeploymentReceipt, EventKind, HostState, Operator, Step, TxnView, fold,
    next_step, receipt,
};
use crate::release::ReleaseManifest;
use crate::run::{Cancel, Cmd, Effect, Expect, Runner};
use crate::state::{Journal, StateDir, journal_ref, read_journal};
use crate::transport::{Ssh, Target};

/// How long a guest-drain may take before the step is refused.
///
/// A drain that does not finish is a host with work on it, and the answer is
/// to leave it alone rather than to interrupt what was being protected.
pub const DRAIN_WAIT: Duration = Duration::from_secs(600);

/// How long a host may take to come back from a reboot.
pub const REBOOT_WAIT: Duration = Duration::from_secs(600);

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
    pub poll: Duration,
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
            poll: POLL,
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
}

/// How this run looks at a host.
///
/// One method, because one thing is needed: what this host is, now. The real
/// implementation is lane 2A's read-only probe over ssh; a test's is a
/// table, and that is the whole reason this is a trait — a test about an
/// ORDER must not also be a test about a shell script's parser, which
/// [`crate::observe`] has twenty of its own for.
pub trait Look {
    fn observe(&self, host: &crate::manifest::ResolvedHost, target: &Target) -> HostObservation;
}

/// The real one: one read-only round trip, the script of lane 2A.
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

/// The running picture of one host, between the plan and the journal.
struct HostRunState {
    state: HostState,
    /// The transaction this run opened on it, if it has.
    txn: Option<String>,
    /// Whether this run holds the target's lock.
    locked: bool,
    /// Whether THIS run has already moved this host's system.
    ///
    /// Separate from the state rather than derived from it: the state moves
    /// on through `verifying` and `committed` and back through `preflight`
    /// on a resume, and what this flag is for does not — once a rollout has
    /// activated something here, the plan's idea of what this host runs is
    /// this run's own doing and must not stop it
    /// ([`Executor::own_footprints_removed`]).
    moved: bool,
}

impl<'a> Executor<'a> {
    /// Walk the plan.
    ///
    /// Returns `Ok` whenever a receipt could be written, whatever the
    /// receipt says: a rollout that failed is not this function failing, and
    /// the caller reads `receipt.outcome` for the exit code. `Err` is for the
    /// things that make a run impossible before it starts — a missing
    /// approval, a plan that no longer matches the fleet.
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
            let read = read_journal(self.files, &journal_path)?;
            if let Some(torn) = &read.torn {
                eprintln!("note: {torn}");
            }
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
                // The fleet anchor of D6, in the payload rather than as a
                // `lock.acquire` event: `fold` requires a host for those,
                // and the anchor is a statement about the run.
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
                    moved: run.txn_id.is_some(),
                },
                None if planned.verdict.blocks() => HostRunState {
                    state: HostState::Blocked,
                    txn: None,
                    locked: false,
                    moved: false,
                },
                None => HostRunState {
                    state: HostState::Planned,
                    txn: None,
                    locked: false,
                    moved: false,
                },
            };
            hosts.insert(id.clone(), state);
        }

        let mut stopped: Option<String> = None;
        // The anchor, before the first step. A control-plane host that
        // cannot be reached leaves the anchor incomplete, which is a
        // sentence and not a refusal: a fleet whose cloud is down is exactly
        // a fleet somebody has to be able to roll forward.
        if let Err(e) = self.take_anchor(&journal, &anchor, &mut hosts) {
            stopped = Some(format!("{e:#}"));
        }

        if stopped.is_none() {
            stopped = self.walk_waves(&journal, &mut hosts);
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
        let built = receipt(self.plan, &folded, &reference, self.clock.now());
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
    ) -> Option<String> {
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
                    return Some(format!(
                        "this run was interrupted before {id}; what was already started is in \
                         the journal and on the hosts."
                    ));
                }
                match self.run_host(journal, id, wave, hosts) {
                    Ok(()) => {}
                    Err(e) => {
                        failed.push(format!("{id}: {e:#}"));
                    }
                }
            }
            if !failed.is_empty() {
                return Some(format!(
                    "wave {wave} did not come through: {}. Nothing of wave {} was started.",
                    failed.join("; "),
                    wave + 1
                ));
            }
        }
        None
    }

    /// One host, one wave: the actions the plan wrote for it, in its order.
    ///
    /// The plan is the sequence — a host that already runs the release has
    /// two steps and neither of them touches it (V10), and a host that only
    /// has to boot has no `activate` and no `confirm`. Nothing here decides
    /// which steps exist.
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
                Resume::AfterTheActivation { confirmed } => {
                    // Everything up to and including the activation happened
                    // on the machine, and the target is what said so. The
                    // preparation is not repeated — a second `nix copy` would
                    // be harmless and a second `activate` would not.
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
                }
            }
        }

        if planned.verdict == HostVerdict::Unchanged {
            // Journalled, not skipped: a host nobody wrote a line about is
            // `unreached` in the receipt and makes a whole run `partial`
            // (2A's finding). It already runs the release, and that is an
            // outcome.
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
                self.end(
                    journal,
                    id,
                    action,
                    ActionResult::Ok,
                    vec![format!(
                        "identity {}, generation {}",
                        seen.as_ref()
                            .and_then(|o| o.identity.host_key_fingerprint.clone())
                            .unwrap_or_else(|| "unknown".to_string()),
                        seen.as_ref()
                            .and_then(|o| o.generation)
                            .map(|g| g.to_string())
                            .unwrap_or_else(|| "unknown".to_string())
                    )],
                    Vec::new(),
                )?;
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
                let cmd = self.workload_cmd(id, action.kind)?;
                refs.push(cmd.line());
                self.runner.run(&cmd)?;
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
                self.set_state(hosts, id, HostState::Activating);
                let cmd = self.activate_cmd(id, action, &txn)?;
                let line = cmd.line();
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
                        let next = if action.rollback.mode == RollbackMode::Boot {
                            HostState::AwaitingReboot
                        } else {
                            HostState::Verifying
                        };
                        self.move_to(journal, id, hosts, next, None)?;
                    }
                    Err(e) => {
                        self.end(
                            journal,
                            id,
                            action,
                            ActionResult::Failed,
                            vec![format!("{e:#}")],
                            vec![line],
                        )?;
                        // The helper puts the host back itself when its own
                        // step fails, and it says so in the record. What is
                        // left here is to find out which of the two
                        // happened, and the target is the one that knows.
                        return self.after_a_failed_activation(journal, id, hosts, e);
                    }
                }
            }
            ActionKind::Reboot => {
                self.begin(journal, id, action)?;
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
                    // A host that was never activated has nothing to take
                    // back: the verify of an unchanged or a preflight-only
                    // host is a report, and a failing one fails the run
                    // without moving anything.
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
                self.move_to(journal, id, hosts, HostState::Committed, fresh.host(id))?;
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
                if let Some(cmd) = self.unlock_cmd(id, hosts)? {
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
            }
            ActionKind::DeliverSecret
            | ActionKind::Install
            | ActionKind::Revoke
            | ActionKind::Gc => {
                bail!(
                    "the step {} on {id} is a {} and this tool cannot do it yet: \
                     deliver-secret and install arrive with M3, revoke with M5, gc with M4. \
                     Nothing was done to {id} in this step.",
                    action.seq,
                    action.kind
                );
            }
        }
        Ok(())
    }

    // -----------------------------------------------------------------
    // the steps
    // -----------------------------------------------------------------

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

        let copy = Cmd::new(Effect::TargetWrite, "nix", COPY_DEADLINE)
            .arg("copy")
            .arg("--to")
            .arg(target.store_url())
            .arg(&toplevel)
            // The one set of ssh options, as the one string nix splits. It
            // refuses rather than lie when a path cannot be expressed that
            // way (2A), and then nothing is copied.
            .env("NIX_SSHOPTS", self.ssh.nix_sshopts(target.port)?);
        self.runner.run(&copy)?;

        // The same question `build` asks of the local store, asked of the
        // target's. This is V12 at the last possible moment: a path with the
        // right name and the wrong bytes is caught HERE, after the transfer
        // and before anything is activated.
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
        Ok(vec![
            format!("{toplevel} is on {id}"),
            format!("nar hash {seen} as the release says"),
        ])
    }

    /// `meister node cordon|drain|uncordon`, on the WORKSTATION, through the
    /// operator's own cli (D7).
    ///
    /// Not over ssh on the node: cordoning is a statement to the control
    /// plane about a node, and a node is not the authority on whether it may
    /// be drained.
    fn workload_cmd(&self, id: &str, kind: ActionKind) -> Result<Cmd> {
        let control = self.options.workload.as_ref().ok_or_else(|| {
            anyhow::anyhow!(
                "this step needs `meister node {kind}` and the inventory names no `[operator] \
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
            .arg(match kind {
                ActionKind::Cordon => "cordon",
                ActionKind::Drain => "drain",
                _ => "uncordon",
            })
            .arg(id)
            .arg("--cluster")
            .arg(group))
    }

    /// Wait until the node carries nothing, or refuse the step.
    ///
    /// The count comes from the node's own socket through the read-only
    /// probe (`vms_running`), so "empty" is what the node says rather than
    /// what a controller believes. `null` is not zero: a node that did not
    /// answer the question is a node whose guests are unknown, and that is
    /// not a host to interrupt.
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

    /// Tell the host to reboot. The connection dies with it, and that is the
    /// expected answer rather than an error.
    fn reboot(&self, id: &str) -> Result<Vec<String>> {
        let target = self.target(id)?;
        let cmd = self
            .ssh
            .ask(&target, "systemctl reboot", REMOTE_DEADLINE)
            // 255 is ssh's own "the connection went away", which is what a
            // machine that is rebooting does to it.
            .expect(Expect::AnyExit);
        let line = cmd.line();
        self.runner.run(&cmd)?;
        Ok(vec![line])
    }

    /// Wait for the host to come back, as the SAME machine, running the
    /// system it was meant to boot.
    ///
    /// The host key is not compared here by hand: every connection this tool
    /// makes carries `StrictHostKeyChecking=yes` against the repository's
    /// `known_hosts` (D10), so a machine with another key does not answer at
    /// all — and the `identity` comparison in
    /// [`crate::plan::validate_against`] catches the rest.
    fn wait_for_boot(&self, id: &str, desired: &str) -> Result<String> {
        let started = self.clock.now();
        // What the last look said, for the sentence a person reads when the
        // deadline passes.
        let mut last;
        loop {
            match self.observe_one(id) {
                Ok(obs) if obs.reachable => match obs.booted_system.as_deref() {
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

    /// Take the host back, and find out whether it went.
    ///
    /// A rollback is only a rollback when it was OBSERVED: the record says
    /// `reverted`, and the machine runs what it ran before. Anything else is
    /// `recovery-required`, because "we asked it to go back" is not a fact
    /// about a machine.
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
            // The record is finished and the host is where it was, so the
            // next plan may be made freshly rather than needing a resume.
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

    /// An activation whose own command came back with an error.
    ///
    /// The helper takes the host back itself when its switch fails and
    /// writes the reason into the record (see [`crate::activate`]), so the
    /// question here is which of the two happened — and the target is the
    /// one that knows. Nothing is activated again either way.
    fn after_a_failed_activation(
        &self,
        journal: &Journal,
        id: &str,
        hosts: &mut BTreeMap<String, HostRunState>,
        why: anyhow::Error,
    ) -> Result<()> {
        let txn = self.entry(hosts, id).txn.clone();
        let observed = self.observe_one(id).ok();
        let view = match (&observed, txn.as_deref()) {
            (Some(obs), id_of) => TxnView::of(obs, id_of),
            (None, _) => TxnView::None,
        };
        let state = match view {
            TxnView::Reverted => HostState::RolledBack,
            TxnView::Pending { .. } | TxnView::Inconsistent => HostState::RecoveryRequired,
            TxnView::Confirmed => HostState::Committed,
            TxnView::None if observed.is_some() => HostState::Failed,
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
                _ => "nothing at all",
            }
        );
    }

    // -----------------------------------------------------------------
    // resume
    // -----------------------------------------------------------------

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
        let view = TxnView::of(&observed, run.txn_id.as_deref());
        match next_step(run, &view) {
            Step::Done => Ok(Resume::Done),
            Step::StartOver | Step::ResumeFromStage => Ok(Resume::Carry),
            Step::VerifyOnly => {
                self.entry(hosts, id).txn = run.txn_id.clone();
                self.set_state(hosts, id, HostState::Verifying);
                Ok(Resume::AfterTheActivation { confirmed: true })
            }
            Step::VerifyAndConfirm => {
                // The activation happened and the target is still waiting
                // for a word. The transaction id comes from the journal,
                // never from a new one.
                self.entry(hosts, id).txn = run.txn_id.clone();
                self.set_state(hosts, id, HostState::Verifying);
                Ok(Resume::AfterTheActivation { confirmed: false })
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
        }
    }

    // -----------------------------------------------------------------
    // locks
    // -----------------------------------------------------------------

    /// Which hosts are the fleet's anchor (D6): every control-plane host of
    /// the INVENTORY, whether it is in this plan or not.
    ///
    /// The point is a second operator in a second repository: the state
    /// directory's lock keeps two runs out of one checkout, and this keeps
    /// two checkouts out of one fleet.
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
                        self.entry(hosts, id).locked = true;
                    } else {
                        hosts.insert(
                            id.clone(),
                            HostRunState {
                                state: HostState::Planned,
                                txn: None,
                                locked: true,
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
                    // A lock somebody else holds is the one thing the anchor
                    // exists to find. Anything else — a host that is off, a
                    // host that has no helper yet — leaves the anchor
                    // incomplete and says so.
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
            let Ok(Some(cmd)) = self.unlock_cmd(&id, hosts) else {
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

    fn unlock_cmd(&self, id: &str, hosts: &BTreeMap<String, HostRunState>) -> Result<Option<Cmd>> {
        if !hosts.get(id).map(|s| s.locked).unwrap_or(false) {
            return Ok(None);
        }
        self.helper_cmd(id, &["lock", "release", "--run", &self.options.run_id])
            .map(Some)
    }

    // -----------------------------------------------------------------
    // looking
    // -----------------------------------------------------------------

    /// Which hosts have to be fresh for a step on this one.
    ///
    /// The host itself, plus the members of every RAFT group it is in.
    /// Not the whole fleet, and the reason is arithmetic rather than
    /// laziness: [`crate::plan::validate_against`] compares each host
    /// against what the plan saw and re-does the quorum sum, and the quorum
    /// sum is the only part that depends on OTHER hosts. It depends on them
    /// only for raft groups — a compute group's `allowed_unavailable` is its
    /// `max_unavailable` and does not move with an observation (2B). So a
    /// fresh look at this host and at its raft peers is exactly what the
    /// check can use, and a fresh look at sixty compute nodes per step would
    /// be sixty round trips that change no verdict.
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

    /// A snapshot in which the named hosts were just asked and the rest is
    /// what the plan saw.
    ///
    /// The mixture is deliberate and is the one place this file trades
    /// completeness for round trips. What it costs is stated here so that
    /// nobody has to find it out: a host that was NOT re-asked compares
    /// equal to itself, so `validate_against` cannot notice that somebody
    /// deployed to a host of this plan that this step is not about. What it
    /// buys is that the host about to be changed, and everybody whose quorum
    /// arithmetic includes it, are facts from seconds ago rather than from
    /// the plan.
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

    /// What the plan assumed, re-checked now — minus what THIS run did on
    /// purpose.
    ///
    /// [`crate::plan::validate_against`] asks "is this plan still the truth
    /// about the fleet?", and the answer it is worth asking for is "did
    /// anything happen here that this rollout did not do". Its own footprints
    /// have to come out first, or the second step of every host would stop
    /// the run:
    ///
    /// * the lock this run holds is not a foreign lock;
    /// * the transaction this run opened is not somebody else's activation;
    /// * and a host this run has already activated is SUPPOSED to be running
    ///   something else than the plan saw — that move is in the journal,
    ///   which is where the evidence for it belongs.
    ///
    /// Everything else stays exactly as the host reported it, including the
    /// identity, the quorum and every other host's system.
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
        match validate_against(self.plan, self.release, &fresh, self.clock.now()) {
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

    /// `ssh <host> meister-activate --deploy-dir … <args>`.
    ///
    /// The helper is a word on the target's PATH (nix/managed.nix puts the
    /// package there), and the arguments are separate arguments: a store
    /// path with a space in it is one argument here and would be two in a
    /// string.
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
            moved: false,
        })
    }

    fn set_state(&self, hosts: &mut BTreeMap<String, HostRunState>, id: &str, to: HostState) {
        self.entry(hosts, id).state = to;
    }

    /// Write a `host.state` line and remember the new state.
    ///
    /// `from` is what this run believed, so a line that says a host left a
    /// state it was not in is a lost line — which is what `fold` reports as
    /// a break rather than hiding.
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
    /// The activation is behind us. What is left is the verification and,
    /// unless somebody already confirmed, the confirmation.
    AfterTheActivation { confirmed: bool },
}

/// Whether a step changes something and therefore has to be preceded by a
/// fresh look.
///
/// `preflight` and `verify` take their own snapshot — they ARE looking —
/// and `lock`/`unlock` are the door itself: a lock that somebody else holds
/// refuses, and that refusal is a better check than any comparison.
fn needs_validation(kind: ActionKind) -> bool {
    matches!(
        kind,
        ActionKind::Stage
            | ActionKind::DeliverSecret
            | ActionKind::Cordon
            | ActionKind::Drain
            | ActionKind::Activate
            | ActionKind::Reboot
            | ActionKind::Confirm
            | ActionKind::Uncordon
            | ActionKind::Install
            | ActionKind::Revoke
            | ActionKind::Gc
    )
}

#[cfg(test)]
mod tests;
