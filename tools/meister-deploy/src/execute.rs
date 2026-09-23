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

/// How long a host gets to answer again after an activation.
///
/// `switch-to-configuration` restarts sshd and the network, so the
/// connection that started it can die with it — and the first question
/// asked afterwards can go unanswered without anything being wrong.
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
    /// The operator's repository, where `keys issue` wrote the
    /// certificates this run may have to deliver (lane 3B).
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
    // --- lane 3-integration ---
    /// Set when the run stopped in front of a `provider-reboot`: which host,
    /// which bytes somebody has to load, and the run to come back to. Not a
    /// failure — the exit code is 2, the same "this is an answer and not a
    /// crash" a blocked plan gets.
    pub waiting: Option<ProviderWait>,
    // --- end lane 3-integration ---
}

// --- lane 3-integration: the halt ------------------------------------------

/// A run that stopped in front of the one step it may not take.
///
/// It is an error type because that is how it travels out of the step it
/// happened in — but it is not a failure of anything: the rollout did
/// everything it could do from here, and what is left is a hypervisor
/// somebody else drives.
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

    /// The same, for the thing that will actually do it. A launcher
    /// (`lab.py boot publish` + `lab.py reboot` in L2) reads this rather
    /// than the sentence: three store paths and a command line are what it
    /// needs, and reading them out of prose is how an adapter breaks the
    /// first time somebody improves the wording.
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

// --- end lane 3-integration ------------------------------------------------

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
            // --- lane 5C ---
            // And the release with it. A resume needs the store paths and
            // the nar hashes the plan only names by id, and the operator's
            // own `--out` file is a file the next `build` overwrites (L2
            // finding N10).
            self.files.write_atomic(
                &self.state.release_copy_path(&self.options.run_id),
                &self.release.to_json()?,
                0o644,
            )?;
            // --- end lane 5C ---
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

        // --- lane 3-integration ---
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
        // --- end lane 3-integration ---

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
                    // --- lane 3-integration ---
                    // A halt is not a failure and must not be folded into
                    // one: the run did everything it could from here, and
                    // what is left is outside this program. It ends the run
                    // rather than the host, because the fleet's own order
                    // is what a wave means — taking the next host forward
                    // while this one runs a kernel nobody arranged yet
                    // would be a rollout that overtook itself.
                    Err(e) => match e.downcast::<ProviderWait>() {
                        Ok(wait) => return Some(Stop::Provider(wait)),
                        Err(e) => failed.push(format!("{id}: {e:#}")),
                    },
                    // --- end lane 3-integration ---
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
                // --- lane 3-integration ---
                Resume::AtTheProviderReboot => {
                    // The same set as after an activation, plus the
                    // confirmation: a halt happens AFTER it, so repeating it
                    // would be confirming a transaction that is already
                    // confirmed (or none at all).
                    skip.extend([
                        ActionKind::Stage,
                        ActionKind::DeliverSecret,
                        ActionKind::Cordon,
                        ActionKind::Drain,
                        ActionKind::Activate,
                        ActionKind::Confirm,
                    ]);
                }
                // --- end lane 3-integration ---
                // --- lane 5A ---
                Resume::AtKeysPhase(phase) => {
                    // Everything before this phase is on the host's disk
                    // already. `prepare` above all: a second one would make
                    // a second key, and the certificate this plan carries
                    // is for the first.
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
                // --- end lane 5A ---
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
                // --- lane 4A: the hardware preflight ---
                //
                // The same function the plan was made with, asked again
                // against the snapshot of THIS minute and before anything
                // is copied. The plan's answer is a document; this one is
                // the one that stands between a release and a machine that
                // stopped being the machine the inventory describes —
                // a disk that filled up, a card that was pulled, a NIC that
                // was swapped, a `/dev/kvm` that is not there.
                //
                // It fails the step rather than only recording it: this is
                // the last look before `stage`, and the whole point of a
                // preflight is that what it finds does not get copied over.
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
                // --- end lane 4A ---
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
                // --- lane 5C ---
                // `move_to` and not `set_state`: the state has to reach the
                // JOURNAL here, not only this process's memory.
                //
                // Measured in every run of lab lane L2 (2026-09-23). The
                // next `move_to` writes `from: activating`, the replay had
                // the host in `staged`, and every receipt of that lane ended
                // with "entry N says box left the state activating and the
                // journal had it in staged; a line is missing." The §6 table
                // names this transition and its evidence — `action.
                // irreversible` written, transaction record on the target —
                // and both are on the disk one line above this one, so there
                // is nothing left to wait for.
                self.move_to(journal, id, hosts, HostState::Activating, None)?;
                // --- end lane 5C ---
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
                        // The connection may have died BECAUSE the activation
                        // worked: `switch-to-configuration` restarts sshd and
                        // the network under the very connection that started
                        // it, and an ssh that comes back 255 with nothing to
                        // say is not evidence about a machine. Measured in
                        // nix/tests/update.nix, where the switch had finished
                        // and the operator called the run failed. So the
                        // TARGET is asked, and it is asked after it has had
                        // time to answer again.
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
                            // The helper puts the host back itself when its
                            // own step fails, and it says so in the record.
                            // What is left is to find out which of the two
                            // happened, and the target is the one that knows.
                            return self
                                .after_a_failed_activation(journal, id, hosts, e, seen, view);
                        }
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
                    // A host whose plan has no `confirm` has nothing to
                    // confirm: nothing was activated, so the way back is
                    // not a timer on the target and this verify is where
                    // the host is done. Without this it would end the run
                    // in whatever state it last moved to, which the receipt
                    // reads as `skipped` and the run as `aborted`.
                    //
                    // Two shapes reach it: a `deliver-secret` only host
                    // (lane 3B) and a `reboot_only` one (2B) — neither of
                    // them activates anything.
                    //
                    // `a.seq > action.seq` and not "has a confirm at all":
                    // a direct-boot host verifies TWICE — once for the
                    // switch, before the confirmation, and once for what
                    // its provider booted, after the halt. The second one
                    // is the last word on that host, and a host whose last
                    // word was never written ends the run in whatever state
                    // it last moved to, which the receipt reads as
                    // `unknown` (lane 3-integration).
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
                // Committed unless something still has to happen to this
                // host. On a direct-boot host the confirmation is not the
                // end: it is what makes the switch survive the wait in
                // front of the provider's reboot (lane 3-integration).
                // Calling it committed there would make a resume read
                // `Done` and skip the reboot the plan exists for.
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
            // --- lane 3B ----------------------------------------------
            ActionKind::DeliverSecret => {
                self.begin(journal, id, action)?;
                // NOT `action.irreversible`: replacing a file can be taken
                // back by writing the old one, and the journal line that
                // means "something started that cannot be undone" is worth
                // exactly as much as the number of times it is true.
                let evidence = self.deliver(id, action)?;
                self.end(journal, id, action, ActionResult::Ok, evidence, Vec::new())?;
            }
            // --- end lane 3B ------------------------------------------
            // --- lane 5A: the five phases of a rotation ------------------
            ActionKind::KeysPrepare => {
                let rotation = self.rotation(id, action)?;
                self.begin(journal, id, action)?;
                // WITHOUT `--replace`: the key was made when the plan was
                // made, and a second one here would be a second identity —
                // the certificate in this plan is for the first. So the
                // host is asked, and what it answers with has to be the key
                // this plan was made for.
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
                // NOT `action.irreversible`: the helper can put the pair
                // that worked back (`keys revert`), and the record on the
                // target says which state it is in. What makes a switch
                // survivable is that record, not a line in this journal —
                // and the line means exactly as much as the number of times
                // it is true.
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
                let cmd = self.helper_cmd(id, &["keys", "remove", "--kind", &rotation.kind])?;
                let line = cmd.line();
                self.runner.run(&cmd)?;
                // And the repository catches up with the host.
                //
                // Until this moment `<kind>.crt` in the repository is the
                // certificate the host USED to hold, and it is what the
                // planner compares every host against. Leaving it there
                // would make the next ordinary plan deliver the old
                // certificate back over the new one — undoing the rotation,
                // quietly, in a plan nobody read as a rotation. So the
                // rotation ends where it began: on this workstation.
                let mut evidence = vec![format!(
                    "the {} pair {id} used before this rotation is gone",
                    rotation.kind
                )];
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
                self.end(journal, id, action, ActionResult::Ok, evidence, vec![line])?;
                let fresh = fresh.unwrap_or_else(|| self.plan.observation.clone());
                self.move_to(journal, id, hosts, HostState::Committed, fresh.host(id))?;
            }
            // --- end lane 5A ---------------------------------------------
            ActionKind::Install | ActionKind::Revoke | ActionKind::Gc => {
                bail!(
                    "the step {} on {id} is a {} and this tool cannot do it yet: \
                     install arrives with M3A, revoke with M5, gc with M4. \
                     Nothing was done to {id} in this step.",
                    action.seq,
                    action.kind
                );
            }
            // --- lane 3-integration: the step this tool does not take -----
            //
            // Nothing is started here and nothing is waited for. The machine
            // is asked one question — have you booted what this plan wants —
            // and the two answers are "carry on" and "the run ends here,
            // with the bytes somebody has to load".
            //
            // No polling, on purpose: what happens next is a person or an
            // adapter uploading a kernel and telling a hypervisor to restart
            // a guest, and a workstation that sat on an ssh connection for
            // that would be a workstation that has to stay awake for it.
            // The journal is what carries the run across the gap.
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
                    // The halt, with the bundle in it: a run that comes back
                    // tomorrow, or a person reading the journal, gets the
                    // three values out of the file rather than out of a
                    // terminal somebody closed.
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

    /// Put one file on a host, and ask the host what it now has (lane 3B).
    ///
    /// Three properties, and each one is a line below:
    ///
    /// * **The content travels on stdin and is redacted out of everything
    ///   this run writes down.** `transport::Ssh::put` does both; what
    ///   reaches the journal is a command line with `***` where the file
    ///   was. A `secrets.key` in a receipt somebody attaches to a ticket is
    ///   a secret that has left the building.
    /// * **The evidence is what the HOST says afterwards, not what this
    ///   workstation sent.** A public file is hashed there and the digest
    ///   is the evidence; a private one is described by its mode and owner,
    ///   which is what its loader refuses it for (M0 probe S11) and which
    ///   is all that may be said about it.
    /// * **A unit is poked only if it is running.** In a bootstrap the
    ///   units are off — they wait on the very file being delivered — and a
    ///   restart of something that is not running is a restart that starts
    ///   it before the rest of its configuration is there.
    ///
    /// This is also the one action a host without a service identity may
    /// receive. The planner refuses everything else to an `unenrolled`
    /// host, and rightly: nothing can be verified about a machine that
    /// cannot authenticate. But delivering the certificate is how it stops
    /// being one, so a bootstrap's `deliver-secret` is exactly the step
    /// that gets it there (2B's N5: the SSH host key is what a bootstrap
    /// may not invent, the service identity is what it delivers).
    fn deliver(&self, id: &str, action: &Action) -> Result<Vec<String>> {
        let target = self.target(id)?;
        let host = self.release.resolved_fleet.hosts.get(id).ok_or_else(|| {
            anyhow::anyhow!("the release describes no host {id}, so it has no secrets either")
        })?;
        let wanted = action.desired.clone().unwrap_or_default();
        // The plan wrote `<id> at <path>`, so the step is matched back
        // against the reference it was made from rather than parsed out of
        // a string: an id that contained the separator would otherwise
        // deliver the wrong file.
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
        // --- lane 3B: Astra finding F10, 2026-09-23 ---
        // The step is bound to the bytes it was planned with, exactly as a
        // rotation's overlap is (`Executor::overlap`), and with the same
        // sentence. Without this the executor re-read the operator's file
        // and then checked the host's copy against whatever that file now
        // held, so a plan made with one certificate -- or one revocation
        // list -- delivered another under its own plan_id, with the
        // approval, the journal and the receipt all naming the wrong bytes.
        // The comparison is BEFORE the put: a run that stops here has
        // changed nothing on the host.
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
        // --- end lane 3B ---

        let put = self.ssh.put(
            &target,
            &secret.target_path,
            &bytes,
            &secret.mode,
            &format!("{}:{}", secret.owner, secret.owner),
            REMOTE_DEADLINE,
        );
        self.runner.run(&put)?;

        // What the host has now, asked of the host. A public file by its
        // digest, a private one by its mode and its owner — the same
        // asymmetry the read-only probe of 2A uses, so the next snapshot
        // says the same thing about it.
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

        // --- lane 5A ---
        // A revocation list is not poked. The process that reads one looks
        // at it again on its own clock, within half a minute
        // (`controller_api::auth::Revocations`), and restarting a controller
        // to deliver a list it re-reads by itself would be the one avoidable
        // outage in this design — on every host of the fleet, for every
        // revocation.
        if secret.kind == crate::manifest::SecretKind::Crl {
            evidence.push(
                "no unit was restarted: a controller re-reads its revocation list within 30 s"
                    .to_string(),
            );
            return Ok(evidence);
        }
        // --- end lane 5A ---

        // And the unit that reads it, if it is running.
        if let Some(reload) = &secret.reload {
            // `Codes([0, 1, 3, 4])` and not the `ask` default: `systemctl
            // is-active` answers 3 for a unit that is inactive or failed
            // and 4 for one this machine does not have, and both are the
            // answer this question is asked for. 255 stays an error, which
            // is how "ssh could not connect" is told apart from "the unit
            // is not running". (Measured twice: the first run of this VM
            // test ended the whole wave on an exit 3 that said `inactive`,
            // and the first bootstrap in the lab — 2026-09-23, lane L2 —
            // ended it on an exit 4, because a fresh host was still running
            // the generic image and did not HAVE the controller unit yet.
            // That is what a bootstrap is: the unit arrives with the
            // closure, after the file it waits for.)
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

    // --- lane 5A ---------------------------------------------------------

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

    /// Put the new certificate beside the one in use.
    ///
    /// The same three steps a delivery is — write, ask, compare — against
    /// `<cert_path>.next`, which nothing reads. A run that stops here has
    /// changed nothing that is running.
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

    /// Restart the units that read a pair, the ones that are running.
    ///
    /// The same question and the same answer as a delivery's: `systemctl
    /// is-active` says 3 for a unit that is not running, and 3 is the
    /// answer this question is asked for.
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
    // --- end lane 5A -------------------------------------------------------

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

        // --- lane 4C: the cache is a shortcut INSIDE the copy -------------
        //
        // `--substitute-on-destination` lets the far store fetch what it can
        // reach itself and leaves this side to send only what it cannot. It
        // is asked for when two things are true at once: the release says
        // its closures were pushed into a cache, and this host's own
        // configuration names substituters. Without the first there is
        // nothing out there to fetch; without the second the target fetches
        // from nowhere and the flag is a round trip for nothing.
        //
        // What does NOT change is the command: there is still one `nix
        // copy`, it still ends with the whole closure on the target, and the
        // `nix path-info --store ssh-ng://` below still compares what
        // arrived against the release. A cache that is stale, empty or
        // unreachable therefore costs time and never correctness — nix falls
        // back to the bytes on this side. And a path the target pulled out
        // of a cache carries the same signature requirement as a path this
        // side pushed: `require-sigs = true` is a property of the target's
        // store, not of the road.
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
            // The one set of ssh options, as the one string nix splits. It
            // refuses rather than lie when a path cannot be expressed that
            // way (2A), and then nothing is copied.
            .env("NIX_SSHOPTS", self.ssh.nix_sshopts(target.port)?);
        self.runner.run(&copy)?;
        // --- end lane 4C ---

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
        let mut evidence = vec![
            format!("{toplevel} is on {id}"),
            format!("nar hash {seen} as the release says"),
        ];
        // --- lane 4C ---
        if substitute {
            evidence.push(format!(
                "{id} was allowed to fetch from its own substituters ({})",
                self.release.resolved_fleet.hosts[id]
                    .substituters
                    .join(", ")
            ));
        }
        // --- end lane 4C ---
        Ok(evidence)
    }

    /// `meister node cordon|drain|uncordon`, on the WORKSTATION, through the
    /// operator's own cli (D7).
    ///
    /// Not over ssh on the node: cordoning is a statement to the control
    /// plane about a node, and a node is not the authority on whether it may
    /// be drained.
    /// Which cli verbs one maintenance step is, in the order they run.
    ///
    /// Giving a host back is two things, because taking it was: `node
    /// drain` sets `spec.drain` and `node cordon` sets `spec.schedulable`,
    /// and `node uncordon` gives back only the second. A node whose
    /// `spec.drain` is still true is a node the scheduler never places on
    /// again — so a rollout that only uncordoned would hand back a machine
    /// that looks healthy in every check and takes no work. Measured in
    /// `checks.vm-bootstrap-fleet`: after a green update `meister node ls`
    /// said `n1  draining  0 moved, 0 leaving, 0 staying (done)`.
    ///
    /// The undrain comes FIRST: `node drain` implies the cordon, so undoing
    /// it and then uncordoning ends with a node that is both schedulable
    /// and not draining, whichever order the far side applies them in.
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

    // --- lane 3-integration ---
    /// What a provider has to be handed for this host, out of the plan and
    /// with the release as the second reading.
    ///
    /// The PLAN first, because the plan is what an approval was given for:
    /// a bundle read out of the release at this moment could be a bundle
    /// somebody rebuilt since. They are compared, and a disagreement is a
    /// sentence rather than a choice.
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
    // --- end lane 3-integration ---

    /// Tell the host to reboot. The connection dies with it, and that is the
    /// expected answer rather than an error.
    fn reboot(&self, id: &str) -> Result<Vec<String>> {
        let target = self.target(id)?;
        let mut cmd = self
            .ssh
            .ask(&target, "systemctl reboot", REMOTE_DEADLINE)
            // 255 is ssh's own "the connection went away", which is what a
            // machine that is rebooting does to it.
            .expect(Expect::AnyExit);
        // Astra finding F20, 2026-09-23: `ask` tags every command it builds
        // Effect::Read, correctly, for the probes it exists for — but a
        // reboot is not a question, and this is the one call to `ask` in
        // this crate for which that tag is wrong. Corrected here rather
        // than in `ask` itself, which every genuinely read-only probe still
        // depends on being Effect::Read (including `--dry-run`, which
        // admits Read but must keep refusing this).
        cmd.effect = Effect::TargetWrite;
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
    // --- lane 4A ---
    /// Whether this host is a member of a raft group of this fleet — and
    /// therefore a host whose etcd is part of what "back" means.
    fn is_raft_member(&self, id: &str) -> bool {
        let fleet = &self.release.resolved_fleet;
        // Both halves, and the second one matters: a host can sit in a raft
        // group without running a database of its own (the group is the
        // unit of ROLLOUT, and a fleet may put a host in one for that
        // reason alone). Waiting for an etcd such a host does not have
        // would be waiting until the reboot deadline for nothing.
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

    // --- lane L4 ---
    /// Whether the raft group this host belongs to was SERVING when the plan
    /// was made.
    ///
    /// The wait above exists for a window of seconds: sshd answers before
    /// etcd does, and a member that is merely still starting must not be
    /// read as one that is down. That is true of a group that HAS a quorum
    /// to rejoin. It is not true of a group that is coming into existence:
    /// the first member of a fresh three-member cluster has no majority to
    /// elect a leader with, so `etcdctl endpoint health` cannot answer until
    /// the SECOND member is activated — which is the next wave, which does
    /// not start until this one finishes. Measured in the lab on 2026-09-23
    /// (lane L4): the first bootstrap of a three-member control plane sat in
    /// this loop with "it booted the release and its etcd has not answered
    /// yet" until the reboot deadline, and the run then failed.
    ///
    /// So the question the wait really asks is "is there a database for this
    /// member to come back to", and the plan already answered it: a group
    /// whose members were ALL unhealthy when the plan was made is not
    /// serving, and there is nothing to wait for.
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
    // --- end lane L4 ---
    // --- end lane 4A ---

    fn wait_for_boot(&self, id: &str, desired: &str) -> Result<String> {
        let started = self.clock.now();
        // What the last look said, for the sentence a person reads when the
        // deadline passes.
        let mut last;
        loop {
            match self.observe_one(id) {
                Ok(obs) if obs.reachable => match obs.booted_system.as_deref() {
                    // --- lane 4A ---
                    // A controller that has rebooted is not back until its
                    // database is back. sshd answers seconds before etcd
                    // does (measured in `vm-kernel-change`: sshd at five
                    // seconds into the boot, etcd at thirteen), and in that
                    // window the host's own member list is EMPTY — which
                    // the quorum arithmetic reads as a member that is down
                    // and the topology check read as a fleet that has
                    // changed. Waiting here is cheaper and truer than
                    // teaching two later rules about a machine that is
                    // merely still starting.
                    Some(booted)
                        if booted == desired
                            && self.is_raft_member(id)
                            // --- lane L4: only where there is a database to
                            // come back to; see `group_was_serving`.
                            && self.group_was_serving(id)
                            && !obs.etcd.as_ref().is_some_and(|e| e.healthy) =>
                    {
                        last = "it booted the release and its etcd has not answered yet".to_string()
                    }
                    // --- end lane 4A ---
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
            TxnView::Pending { .. } | TxnView::Inconsistent => HostState::RecoveryRequired,
            TxnView::Confirmed => HostState::Committed,
            // It answered and holds no record: nothing was activated, and
            // that is a fact rather than a silence.
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

    /// What the target says about a transaction, once it is answering again.
    ///
    /// A bounded wait and not one question: the step that just failed is the
    /// one that restarts the network, so the first answer after it is likely
    /// to be no answer at all — and reading that as "nothing happened" is
    /// the worst of the possible wrong readings.
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
        // --- lane 5A: a rotation asks the host a different question ------
        //
        // Not the transaction record — a rotation opens none — but the key
        // files themselves, which is where the five phases leave their
        // marks. The table is `receipt::next_keys_step`.
        if self.plan.kind == crate::plan::PlanKind::KeysRotate {
            let state = self.keys_state(id)?;
            return match crate::receipt::next_keys_step(run, state) {
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
        // --- end lane 5A -------------------------------------------------
        let view = TxnView::of(&observed, run.txn_id.as_deref());
        match next_step(run, &view) {
            Step::Done => Ok(Resume::Done),
            Step::StartOver | Step::ResumeFromStage => Ok(Resume::Carry),
            // --- lane 3-integration ---
            Step::AtTheProviderReboot => {
                // The transaction comes from the JOURNAL, and may be none:
                // a host that was only waiting for its boot (switched, never
                // booted) never opened one. What is skipped is the whole
                // preparation, because it happened.
                self.entry(hosts, id).txn = run.txn_id.clone();
                self.entry(hosts, id).moved = run.txn_id.is_some();
                self.set_state(hosts, id, HostState::AwaitingReboot);
                Ok(Resume::AtTheProviderReboot)
            }
            // --- end lane 3-integration ---
            // --- lane 5C ---
            // `move_to` and not `set_state` in both arms below: a resume
            // that only remembers where it put a host writes the NEXT line
            // as a transition out of a state the journal never mentions,
            // and `fold` reports that as a lost line (L2 finding N7). The
            // move is real — the target was asked, and its answer is what
            // decided it — so it belongs in the journal like every other.
            Step::VerifyOnly => {
                self.entry(hosts, id).txn = run.txn_id.clone();
                self.move_to(journal, id, hosts, HostState::Verifying, Some(&observed))?;
                Ok(Resume::AfterTheActivation { confirmed: true })
            }
            Step::VerifyAndConfirm => {
                // The activation happened and the target is still waiting
                // for a word. The transaction id comes from the journal,
                // never from a new one.
                self.entry(hosts, id).txn = run.txn_id.clone();
                self.move_to(journal, id, hosts, HostState::Verifying, Some(&observed))?;
                Ok(Resume::AfterTheActivation { confirmed: false })
            }
            // --- end lane 5C ---
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
            // --- lane 5A ---
            // The rotation table is asked above, and only for a rotation
            // plan. Reaching this with a keys phase would mean the two
            // tables were crossed.
            Step::AtKeysPhase(phase) => bail!(
                "the resume table answered {phase} for {id}, which is a phase of a key \
                 rotation and this plan is a {}.",
                self.plan.kind
            ),
            // --- end lane 5A ---
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
        // --- lane L4: `id` is the host this wave is about to act on, and a
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
    // --- lane 3-integration ---
    /// The run stopped in front of the provider's reboot. Everything before
    /// it happened; the step itself asks the machine again.
    AtTheProviderReboot,
    // --- end lane 3-integration ---
    // --- lane 5A ---
    /// A rotation is open on this host, at this phase. Everything before it
    /// is on the disk already and is not done again — a second `prepare`
    /// would be a second key.
    AtKeysPhase(ActionKind),
    // --- end lane 5A ---
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
            // --- lane 5A: every phase that touches the host ---
            | ActionKind::KeysPrepare
            | ActionKind::KeysOverlap
            | ActionKind::KeysSwitch
            | ActionKind::KeysRemove
            // --- end lane 5A ---
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
