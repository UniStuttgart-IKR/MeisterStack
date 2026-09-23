// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Verification: make the fleet do the thing it exists for, then take it
//! back out again.
//!
//! `check` reads. It asks whether a unit is active and whether a socket is
//! there, and that is genuinely all it can say — measured in lane 2A and
//! written down there: a controller that accepts connections and refuses
//! THIS node's certificate leaves every readiness check green. The positive
//! proof that a fleet works is a guest that was created through the
//! operator's own control plane, ran, said something only a booted guest can
//! say, and was deleted again. That is this module.
//!
//! Three properties decide whether such a thing may be run against a fleet
//! somebody depends on:
//!
//! * **The ledger is ahead of the world.** Every resource is written down
//!   before it is asked for, the way the journal writes `action.irreversible`
//!   before the step. A run that is killed between the write and the create
//!   leaves a ledger entry for a guest that may or may not exist, and the
//!   cleanup then looks — which is the only order in which a crash cannot
//!   leak something nobody knows about. The other order leaks silently.
//! * **Cleanup takes only what this run made.** A resource is removed only
//!   when its ledger entry belongs to this run AND its name carries this
//!   run's tag. A guest that somebody else called `meister-verify-other-1`
//!   is not this run's, and a verification that tidies up somebody's estate
//!   is a verification nobody will run twice.
//! * **A cleanup that worked proves nothing.** Removing the guests is not a
//!   result; it is the cost of having had them. The verdict comes from the
//!   [`CheckResult`]s, and a resource that could not be removed becomes one
//!   MORE check — `unknown`, with the name in it — rather than a silent
//!   success.
//!
//! And one property decides whether the result is worth anything:
//! **`hardware` evidence is measured, never declared.** An inventory that
//! says a host has a GPU is an inventory; the snapshot that says
//! `/dev/vfio/vfio` is there is a measurement. So every piece of evidence
//! this module emits is [`EvidenceKind::Vm`] or [`EvidenceKind::Command`]
//! unless the snapshot of the machine the guest actually ran on says the
//! capability was there, and a run whose guests were answered by a
//! [`crate::run::StrictFake`] is [`EvidenceKind::Mock`] throughout. A CPU
//! mock is not evidence that a GPU works, and `report` prints the two apart.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Result, bail};
use chrono::{DateTime, Utc};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::checks::{CheckResult, Evidence, EvidenceKind, Status, Subject};
use crate::effects::{Clock, Files};
use crate::manifest::{ResolvedFleet, ResolvedHost};
use crate::observation::Observations;
use crate::plan::WorkloadControl;
use crate::receipt::Outcome;
use crate::release::ReleaseManifest;
use crate::run::{Cancel, Cmd, Effect, Expect, Runner, last_lines};
use crate::state::StateDir;

pub const LEDGER_SCHEMA: &str = "meister-deploy/verify-ledger/1";
pub const VERIFY_SCHEMA: &str = "meister-deploy/verify/1";

/// How long one call of the operator's cli may take.
///
/// A `vm create` is one POST and the answer is "it is recorded", so this is
/// generous rather than tight; what a guest then takes to boot is
/// [`Options::settle`] and is counted in polls, not in this.
pub const CLI_DEADLINE: Duration = Duration::from_secs(60);

/// How long a guest gets to reach a phase, and how often it is asked.
pub const SETTLE: Duration = Duration::from_secs(120);
pub const POLL: Duration = Duration::from_secs(2);

/// The whole run, when nobody said otherwise.
pub const DEADLINE: Duration = Duration::from_secs(1800);

/// How long ONE fabric measurement may take.
pub const FABRIC_DEADLINE: Duration = Duration::from_secs(120);

/// How many round trips `rping` is asked for. Ten, because one proves a
/// connection and ten prove it keeps working — and because a hundred would
/// make a failure take a hundred times as long to find.
pub const RPING_ROUNDS: usize = 10;

/// How long each perftest measurement runs, in seconds. Five: long enough
/// that a link settles, short enough that a fleet of pairs is minutes and
/// not an afternoon.
pub const FABRIC_SECONDS: u32 = 5;

/// How many guests may be alive at once when nobody said otherwise.
///
/// Two, so that the default run makes three guests per host: one on its own
/// first — a canary, because a suite that starts its whole budget and then
/// finds the image is wrong has made the same mistake three times — and then
/// a batch of `budget`. The count of create/delete pairs per host is
/// therefore `1 + budget`.
pub const BUDGET: usize = 2;

/// The line `nix/packages/guest-tiny.nix` writes on the serial console as
/// its first act. One string, in one place, and the package writes the same
/// one into `$out/marker`.
pub const TINY_MARKER: &str = "MS-S0-TINY-OK";

// ---------------------------------------------------------------------------
// the contract
// ---------------------------------------------------------------------------

/// Which suite. Not a free string: a typo in a suite name must be a sentence
/// and not an empty run that reports nothing and exits 0.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum Suite {
    VmLifecycle,
    Gpu,
    Rdma,
}

impl Suite {
    pub fn parse(text: &str) -> Result<Suite> {
        match text {
            "vm-lifecycle" => Ok(Suite::VmLifecycle),
            "gpu" => Ok(Suite::Gpu),
            "rdma" => Ok(Suite::Rdma),
            other => bail!(
                "there is no suite called {other:?}; this tool knows vm-lifecycle, gpu and \
                 rdma. `check --suite readiness` is the one that only reads."
            ),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Suite::VmLifecycle => "vm-lifecycle",
            Suite::Gpu => "gpu",
            Suite::Rdma => "rdma",
        }
    }
}

impl std::fmt::Display for Suite {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.pad(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ResourceKind {
    Vm,
    Volume,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ResourceState {
    /// Written down before it was asked for. A resource in this state at the
    /// end of a run is one the cleanup has not reached yet.
    Created,
    /// Gone, and that was checked rather than assumed: the delete returned
    /// and the name is no longer in the listing.
    Deleted,
    /// It could not be removed, or the listing still has it. The run says so
    /// with a check of its own, and somebody has to go and look.
    Lost,
}

impl ResourceState {
    pub fn as_str(self) -> &'static str {
        match self {
            ResourceState::Created => "created",
            ResourceState::Deleted => "deleted",
            ResourceState::Lost => "lost",
        }
    }
}

impl std::fmt::Display for ResourceState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.pad(self.as_str())
    }
}

/// One thing this run made, and what became of it.
///
/// `host` is where it RAN, not where it was asked for: the operator's cli
/// has no way to name a node (`components/cli` has `vm create <name> -f`,
/// and placement is the scheduler's), so the suite reads the binding back
/// out of the created object. That is also what decides whether the
/// evidence may be called `hardware`, because the capability that matters is
/// the one on the machine that actually ran the guest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Resource {
    pub kind: ResourceKind,
    /// The control plane's own id, once it has answered with one. `null`
    /// between the ledger write and the create, which is the window this
    /// order exists for.
    pub id: Option<String>,
    pub name: String,
    /// Empty until the guest is placed — see the type's own note.
    pub host: String,
    pub created_at: DateTime<Utc>,
    pub state: ResourceState,
}

/// `runs/<run_id>/ledger.json`: what exists because of this run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Ledger {
    pub schema: String,
    pub run_id: String,
    pub release_id: String,
    pub suite: Suite,
    /// `meister-verify-<run_id>`. Every name this run makes starts with it,
    /// and nothing without it is ever deleted.
    pub tag: String,
    pub started_at: DateTime<Utc>,
    pub resources: Vec<Resource>,
}

impl Ledger {
    pub fn new(run_id: &str, release_id: &str, suite: Suite, started_at: DateTime<Utc>) -> Ledger {
        Ledger {
            schema: LEDGER_SCHEMA.to_string(),
            run_id: run_id.to_string(),
            release_id: release_id.to_string(),
            suite,
            tag: tag_of(run_id),
            started_at,
            resources: Vec::new(),
        }
    }

    pub fn from_json(text: &str, origin: &str) -> Result<Ledger> {
        crate::manifest::parse_checked(text, origin, LEDGER_SCHEMA)
    }

    pub fn to_json(&self) -> Result<Vec<u8>> {
        let mut bytes = serde_json::to_vec_pretty(self)
            .map_err(|e| anyhow::anyhow!("writing the verify ledger as json failed: {e}"))?;
        bytes.push(b'\n');
        Ok(bytes)
    }

    /// What this run still holds, as far as the ledger knows: everything
    /// that is not known to be gone, `lost` included.
    pub fn outstanding(&self) -> Vec<&Resource> {
        self.resources
            .iter()
            .filter(|r| r.state != ResourceState::Deleted)
            .collect()
    }

    /// What nobody has tried to remove yet. `lost` is deliberately not here:
    /// it has been tried, it has its own check, and a second attempt in the
    /// same breath would only produce a second sentence about the same
    /// thing.
    pub fn untried(&self) -> Vec<&Resource> {
        self.resources
            .iter()
            .filter(|r| r.state == ResourceState::Created)
            .collect()
    }
}

/// `meister-verify-<run_id>`: the one string that says a resource is ours.
pub fn tag_of(run_id: &str) -> String {
    format!("meister-verify-{run_id}")
}

/// `runs/<run_id>/verify.json`: what the suite found.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct VerifyRun {
    pub schema: String,
    pub run_id: String,
    pub release_id: String,
    pub manifest_id: String,
    pub suite: Suite,
    pub started_at: DateTime<Utc>,
    pub ended_at: DateTime<Utc>,
    pub outcome: Outcome,
    /// The hosts the suite was asked about, frozen at the start.
    pub hosts: Vec<String>,
    pub checks: Vec<CheckResult>,
    /// The ledger as it stood when the run ended. The file beside it is the
    /// live one; this is the copy the receipt argues from.
    pub ledger: Ledger,
    pub ledger_path: String,
}

impl VerifyRun {
    pub fn from_json(text: &str, origin: &str) -> Result<VerifyRun> {
        crate::manifest::parse_checked(text, origin, VERIFY_SCHEMA)
    }

    pub fn to_json(&self) -> Result<Vec<u8>> {
        let mut bytes = serde_json::to_vec_pretty(self)
            .map_err(|e| anyhow::anyhow!("writing the verification as json failed: {e}"))?;
        bytes.push(b'\n');
        Ok(bytes)
    }

    /// The checks whose evidence came off real hardware, and the rest.
    ///
    /// The split `report` prints, kept here so that the rule lives with the
    /// contract rather than in a formatter: evidence of kind `hardware` is
    /// the only kind that says a device was there, and a reader who cannot
    /// see the boundary will read a mock as a measurement.
    pub fn hardware_evidence(&self) -> (Vec<&CheckResult>, Vec<&CheckResult>) {
        self.checks
            .iter()
            .partition(|c| c.evidence.iter().any(|e| e.kind == EvidenceKind::Hardware))
    }
}

// ---------------------------------------------------------------------------
// the run
// ---------------------------------------------------------------------------

/// What the operator decided about this verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Options {
    pub run_id: String,
    pub suite: Suite,
    /// The most guests that may be alive at once. It is a count of LIVING
    /// guests and not a count of threads: the commands themselves go out one
    /// after another, because the only runner the tests are allowed to use
    /// is a strict sequence and untestable concurrency in the code that
    /// creates virtual machines on somebody's fleet is worth less than a
    /// slower suite.
    pub budget: usize,
    /// The whole run. When it passes, whatever is running is cleaned up and
    /// the outcome is `aborted`.
    pub deadline: Duration,
    /// Leave the guests where they are and say so. For somebody who wants to
    /// look at one that misbehaved.
    pub keep: bool,
    /// `[operator] cli_config` / `cli_profile` (D7). Without it there is no
    /// control plane to ask, and every host is `blocked`.
    pub control: Option<WorkloadControl>,
    /// How long a guest gets to reach a phase.
    pub settle: Duration,
    pub poll: Duration,
    pub cli_deadline: Duration,
    /// `--pairs <a>:<b>`, for the rdma suite. Empty means every pair the
    /// inventory declares among the selected hosts.
    pub pairs: Vec<(String, String)>,
    /// How long ONE fabric measurement may take. Longer than a cli call,
    /// because `ib_write_bw -D 10` is ten seconds of work by construction
    /// and a fabric that is being set up takes longer than one that is.
    pub fabric: Duration,
}

impl Options {
    pub fn new(run_id: impl Into<String>, suite: Suite) -> Options {
        Options {
            run_id: run_id.into(),
            suite,
            budget: BUDGET,
            deadline: DEADLINE,
            keep: false,
            control: None,
            settle: SETTLE,
            poll: POLL,
            cli_deadline: CLI_DEADLINE,
            pairs: Vec::new(),
            fabric: FABRIC_DEADLINE,
        }
    }
}

/// One step of a suite, as `--dry-run` lists it and as the report names it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Step {
    pub host: String,
    pub what: String,
}

/// The driver.
///
/// It owns the ledger and writes it through [`Files`], asks the world
/// through [`Runner`], and reads the clock through [`Clock`] — so the whole
/// of it, including the deadline and the waits, is a test with a fake clock
/// rather than a test that sleeps.
pub struct Verifier<'a> {
    runner: &'a dyn Runner,
    files: &'a dyn Files,
    clock: &'a dyn Clock,
    cancel: Cancel,
    /// The runner the cleanup uses. `None` falls back to the one above,
    /// which is right for a test and wrong for an interrupted run: see
    /// [`crate::run::Real::stoppable`].
    cleanup_runner: Option<&'a dyn Runner>,
    /// Whether the cleanup is what is running. It decides which runner the
    /// next command goes through and nothing else.
    cleaning_up: bool,
    state: StateDir,
    release: &'a ReleaseManifest,
    observation: &'a Observations,
    /// How both ends of a fabric pair are reached. `None` for a run that
    /// only drives the operator's cli, which is every guest suite.
    ssh: Option<&'a crate::transport::Ssh>,
    endpoints: BTreeMap<String, crate::observation::Endpoint>,
    hosts: Vec<String>,
    options: Options,
    ledger: Ledger,
    checks: Vec<CheckResult>,
    started_at: DateTime<Utc>,
    /// Guest numbers within this run, so a name is unique across hosts.
    made: usize,
    /// Whether anything this run did was answered by a real program. A run
    /// whose runner is a fake says `mock` on every piece of evidence, and
    /// that is decided here rather than guessed by a reader.
    mock: bool,
}

impl<'a> Verifier<'a> {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        runner: &'a dyn Runner,
        files: &'a dyn Files,
        clock: &'a dyn Clock,
        state: StateDir,
        release: &'a ReleaseManifest,
        observation: &'a Observations,
        hosts: Vec<String>,
        options: Options,
    ) -> Verifier<'a> {
        let started_at = clock.now();
        let ledger = Ledger::new(
            &options.run_id,
            &release.release_id,
            options.suite,
            started_at,
        );
        Verifier {
            runner,
            files,
            clock,
            cancel: Cancel::new(),
            cleanup_runner: None,
            cleaning_up: false,
            state,
            release,
            observation,
            ssh: None,
            endpoints: BTreeMap::new(),
            hosts,
            options,
            ledger,
            checks: Vec::new(),
            started_at,
            made: 0,
            mock: false,
        }
    }

    /// The token that ends a run early. `apply` and `verify` share the
    /// process-wide SIGINT handler; this is how a test interrupts one.
    pub fn with_cancel(mut self, cancel: Cancel) -> Verifier<'a> {
        self.cancel = cancel;
        self
    }

    /// The runner the cleanup is to use, which is the one the operator's
    /// interrupt does not reach: taking the guests back is the work an
    /// interrupt ASKS for, and a runner that honoured it would kill the
    /// delete it had just started.
    pub fn with_cleanup_runner(mut self, runner: &'a dyn Runner) -> Verifier<'a> {
        self.cleanup_runner = Some(runner);
        self
    }

    /// Whichever runner this phase of the run goes through.
    fn exec(&self, cmd: &Cmd) -> Result<crate::run::Output> {
        match (self.cleaning_up, self.cleanup_runner) {
            (true, Some(runner)) => runner.run(cmd),
            _ => self.runner.run(cmd),
        }
    }

    /// Say that every answer in this run came from a fake, so no evidence may
    /// claim to be more than a mock.
    pub fn as_mock(mut self) -> Verifier<'a> {
        self.mock = true;
        self
    }

    /// How to reach both ends of a fabric pair. Only the rdma suite needs
    /// it; the guest suites talk to a control plane and never to a host.
    pub fn over_ssh(
        mut self,
        ssh: &'a crate::transport::Ssh,
        endpoints: BTreeMap<String, crate::observation::Endpoint>,
    ) -> Verifier<'a> {
        self.ssh = Some(ssh);
        self.endpoints = endpoints;
        self
    }

    fn fleet(&self) -> &ResolvedFleet {
        &self.release.resolved_fleet
    }

    pub fn ledger(&self) -> &Ledger {
        &self.ledger
    }

    pub fn tag(&self) -> &str {
        &self.ledger.tag
    }

    fn ledger_path(&self) -> PathBuf {
        self.state.run_dir(&self.options.run_id).join("ledger.json")
    }

    fn verify_path(&self) -> PathBuf {
        self.state.run_dir(&self.options.run_id).join("verify.json")
    }

    // --- the steps, for a listing that creates nothing --------------------

    /// What this run WOULD do, without doing any of it.
    pub fn steps(&self) -> Vec<Step> {
        let mut out = Vec::new();
        for id in &self.hosts {
            let Some(host) = self.fleet().hosts.get(id) else {
                continue;
            };
            match applicability(self.options.suite, self.fleet(), id, host) {
                Applicability::No(reason) => out.push(Step {
                    host: id.clone(),
                    what: format!("not_applicable: {reason}"),
                }),
                Applicability::Yes if self.unreachable(id).is_some() => out.push(Step {
                    host: id.clone(),
                    what: format!("skipped: {}", self.unreachable(id).unwrap_or_default()),
                }),
                Applicability::Yes => match self.options.suite {
                    Suite::VmLifecycle => {
                        for n in 0..self.guests_per_host() {
                            out.push(Step {
                                host: id.clone(),
                                what: format!(
                                    "create, wait for Running, read the console for \
                                     {TINY_MARKER}, delete and wait until it is gone \
                                     (guest {} of {})",
                                    n + 1,
                                    self.guests_per_host()
                                ),
                            });
                        }
                    }
                    Suite::Gpu => out.push(Step {
                        host: id.clone(),
                        what: GPU_PLAN.to_string(),
                    }),
                    Suite::Rdma => out.push(Step {
                        host: id.clone(),
                        what: RDMA_PLAN.to_string(),
                    }),
                },
            }
        }
        out
    }

    /// One on its own first, then a batch of the budget.
    fn guests_per_host(&self) -> usize {
        1 + self.options.budget.max(1)
    }

    // --- the ledger -------------------------------------------------------

    /// Write the ledger down, whole, atomically.
    ///
    /// Called before every create and after every state change. It is a
    /// small file and it is written often on purpose: the value of it is
    /// entirely that it is on the disk when this process stops existing.
    fn save_ledger(&self) -> Result<()> {
        self.files
            .write_atomic(&self.ledger_path(), &self.ledger.to_json()?, 0o644)
    }

    /// Write down that a guest is about to exist, and give it its name.
    fn intend_vm(&mut self, host: &str) -> Result<String> {
        self.made += 1;
        let name = format!("{}-{}", self.ledger.tag, self.made);
        self.ledger.resources.push(Resource {
            kind: ResourceKind::Vm,
            id: None,
            name: name.clone(),
            host: host.to_string(),
            created_at: self.clock.now(),
            state: ResourceState::Created,
        });
        self.save_ledger()?;
        Ok(name)
    }

    fn resource_mut(&mut self, name: &str) -> Option<&mut Resource> {
        self.ledger.resources.iter_mut().find(|r| r.name == name)
    }

    fn set_state(&mut self, name: &str, state: ResourceState) -> Result<()> {
        if let Some(resource) = self.resource_mut(name) {
            resource.state = state;
        }
        self.save_ledger()
    }

    fn set_placement(&mut self, name: &str, node: &str, id: Option<String>) -> Result<()> {
        if let Some(resource) = self.resource_mut(name) {
            if !node.is_empty() {
                resource.host = node.to_string();
            }
            if id.is_some() {
                resource.id = id;
            }
        }
        self.save_ledger()
    }

    // --- the operator's cli ----------------------------------------------

    /// `meister --config <cli_config> [-p <profile>] -o json …`, on the
    /// WORKSTATION.
    ///
    /// The same door D7 opens for `node cordon`: a verification asks the
    /// control plane for a guest, because that is what an operator does and
    /// because it is the only path that exercises the session between the
    /// tiers. A guest made at the node's own socket would prove the
    /// hypervisor works and say nothing about the fleet.
    fn cli(&self, effect: Effect) -> Result<Cmd> {
        let control = self.options.control.as_ref().ok_or_else(|| {
            anyhow::anyhow!(
                "this suite drives the operator's own cli and the inventory names no \
                 `[operator] cli_config`. Set it (and `cli_profile`) in fleet.toml, or pass \
                 --inventory <file> so this can be read."
            )
        })?;
        let mut cmd = Cmd::new(effect, "meister", self.options.cli_deadline)
            .arg("--config")
            .arg(&control.cli_config);
        if let Some(profile) = &control.cli_profile {
            cmd = cmd.arg("-p").arg(profile);
        }
        Ok(cmd.arg("-o").arg("json"))
    }

    /// The same, for a verb that would otherwise stop and ask.
    fn cli_yes(&self, effect: Effect) -> Result<Cmd> {
        Ok(self.cli(effect)?.arg("--yes"))
    }

    // --- the run ----------------------------------------------------------

    /// Run the suite, clean up whatever it made, and say what it found.
    ///
    /// It returns `Ok` for a suite that failed: a failing check is an answer
    /// and the exit code is the caller's to derive from
    /// [`crate::checks::acceptance`]. `Err` is for the run itself not being
    /// possible — no cli reference, a ledger that cannot be written.
    pub fn run(&mut self) -> Result<VerifyRun> {
        self.state
            .begin_run(self.files, &self.options.run_id.clone())?;
        self.save_ledger()?;

        let outcome = match self.options.suite {
            Suite::VmLifecycle => self.vm_lifecycle(),
            Suite::Gpu => self.gpu(),
            Suite::Rdma => self.rdma(),
        };

        // Whatever happened above, what this run made is this run's to take
        // back. A suite that failed halfway is exactly the run whose guests
        // would otherwise stay.
        let interrupted = match outcome {
            Ok(()) => self.cancel.is_cancelled() || self.out_of_time(),
            Err(ref e) => {
                self.record(CheckResult {
                    id: format!("{}.run", self.options.suite),
                    subject: Subject::resource(self.ledger.tag.clone()),
                    required: true,
                    status: Status::Unknown,
                    expected: format!("the {} suite runs", self.options.suite),
                    observed: "it stopped".to_string(),
                    reason: format!("{e:#}"),
                    duration_ms: 0,
                    evidence: Vec::new(),
                    release_id: Some(self.release.release_id.clone()),
                    config_id: Some(self.fleet().manifest_id.clone()),
                });
                true
            }
        };
        self.cleanup()?;

        let ended_at = self.clock.now();
        let accepted = crate::checks::acceptance(&self.checks).is_accepted();
        let outcome = if interrupted {
            Outcome::Aborted
        } else if accepted {
            Outcome::Success
        } else {
            Outcome::Failed
        };

        let run = VerifyRun {
            schema: VERIFY_SCHEMA.to_string(),
            run_id: self.options.run_id.clone(),
            release_id: self.release.release_id.clone(),
            manifest_id: self.fleet().manifest_id.clone(),
            suite: self.options.suite,
            started_at: self.started_at,
            ended_at,
            outcome,
            hosts: self.hosts.clone(),
            checks: self.checks.clone(),
            ledger: self.ledger.clone(),
            ledger_path: self.ledger_path().display().to_string(),
        };
        self.files
            .write_atomic(&self.verify_path(), &run.to_json()?, 0o644)?;
        Ok(run)
    }

    fn out_of_time(&self) -> bool {
        let spent = self.clock.now() - self.started_at;
        spent
            .to_std()
            .map(|d| d >= self.options.deadline)
            .unwrap_or(false)
    }

    /// The deadline and the interrupt, as one question with one sentence.
    fn keep_going(&self) -> Result<()> {
        if self.cancel.is_cancelled() {
            bail!(
                "this verification was interrupted. What it had made is being deleted; the \
                 ledger {} says what it held.",
                self.ledger_path().display()
            );
        }
        if self.out_of_time() {
            bail!(
                "this verification ran out of its {:?} budget. What it had made is being \
                 deleted; raise --deadline to give it longer.",
                self.options.deadline
            );
        }
        Ok(())
    }

    fn record(&mut self, check: CheckResult) {
        self.checks.push(check);
    }

    /// The evidence kind a guest on this node earns.
    ///
    /// Three conditions, and all three have to hold:
    ///
    /// * the answer came from a real program and not from a fake;
    /// * the SNAPSHOT of the machine the guest RAN ON says the capability
    ///   was there — not the inventory, which is a declaration;
    /// * the step actually happened. A `vm create` the control plane refused
    ///   produced no guest, so it is evidence about a control plane and not
    ///   about hardware, and printing it under "hardware evidence" would put
    ///   a failure nobody measured on a machine beside the ones somebody
    ///   did. Measured: the first real run of this suite refused every
    ///   create (a 422 from the cluster tier) and the report still listed
    ///   six checks as hardware evidence.
    fn evidence_kind(&self, node: &str, capability: &str, happened: bool) -> EvidenceKind {
        if self.mock {
            return EvidenceKind::Mock;
        }
        if !happened {
            return EvidenceKind::Command;
        }
        match self.observation.host(node) {
            Some(obs) if obs.has_capability(capability) => EvidenceKind::Hardware,
            _ => EvidenceKind::Vm,
        }
    }

    /// Whether this suite's verdict for this host decides the run.
    ///
    /// From `checks.functional` in the inventory, which is the field the
    /// operator already has for exactly this: "these functional checks must
    /// pass on this host". A host that does not name the suite is still
    /// verified and still reported — it simply does not block, which is what
    /// makes `verify --suite gpu` over a mixed fleet useful rather than a
    /// wall of refusals.
    fn required_for(&self, id: &str) -> bool {
        self.fleet()
            .hosts
            .get(id)
            .map(|h| {
                h.checks
                    .functional
                    .iter()
                    .any(|name| name == self.options.suite.as_str())
            })
            .unwrap_or(false)
    }

    fn check(&self, id: &str, host_id: &str, subject: Subject, status: Status) -> CheckResult {
        CheckResult {
            id: id.to_string(),
            subject,
            required: self.required_for(host_id),
            status,
            expected: String::new(),
            observed: String::new(),
            reason: String::new(),
            duration_ms: 0,
            evidence: Vec::new(),
            release_id: Some(self.release.release_id.clone()),
            config_id: Some(self.fleet().manifest_id.clone()),
        }
    }

    // --- suite: vm-lifecycle ---------------------------------------------

    /// Guests, through the operator's control plane, on every host that runs
    /// them.
    fn vm_lifecycle(&mut self) -> Result<()> {
        let hosts = self.hosts.clone();
        for id in hosts {
            self.keep_going()?;
            let Some(host) = self.fleet().hosts.get(&id).cloned() else {
                continue;
            };
            match applicability(Suite::VmLifecycle, self.fleet(), &id, &host) {
                Applicability::No(reason) => {
                    let mut check = self.check(
                        "vm-lifecycle",
                        &id,
                        Subject::host(&id),
                        Status::NotApplicable,
                    );
                    check.expected = "a host that runs guests".to_string();
                    check.observed = reason.clone();
                    check.reason = reason;
                    self.record(check);
                    continue;
                }
                Applicability::Yes => {}
            }
            if let Some(reason) = self.unreachable(&id) {
                let mut check =
                    self.check("vm-lifecycle", &id, Subject::host(&id), Status::Skipped);
                check.expected = "a host that answers, so a guest can be asked for".to_string();
                check.observed = reason.clone();
                check.reason = format!(
                    "{reason} This suite was not run there, which is not the same as it \
                     having passed."
                );
                self.record(check);
                continue;
            }

            let kernel = self.guest_tiny()?;
            let total = self.guests_per_host();
            let mut all_good = true;
            // One alone, then the rest together: the canary, and then as
            // many at once as the budget allows.
            let mut done = 0usize;
            while done < total {
                self.keep_going()?;
                let batch = if done == 0 {
                    1
                } else {
                    self.options.budget.max(1).min(total - done)
                };
                all_good &= self.lifecycle_batch(&id, &kernel, batch)?;
                done += batch;
            }

            let mut check = self.check("vm-lifecycle", &id, Subject::host(&id), Status::Pass);
            check.expected = format!("{total} guest(s) created, booted, read and deleted");
            check.observed = format!(
                "{} of {total} came through every step",
                if all_good { total } else { 0 }
            );
            if !all_good {
                check.status = Status::Fail;
                check.observed = format!("at least one of the {total} did not");
            }
            check.reason = format!(
                "a guest that reached Running and printed {TINY_MARKER} is the control \
                 plane, the session and the hypervisor of this host working together, \
                 which no readiness check can say."
            );
            self.record(check);
        }
        Ok(())
    }

    /// One round: create `n` guests, let them all be alive at once, read
    /// each one, then delete them all.
    fn lifecycle_batch(&mut self, id: &str, kernel: &GuestTiny, n: usize) -> Result<bool> {
        let mut names = Vec::new();
        let mut good = true;
        for _ in 0..n {
            self.keep_going()?;
            let name = self.intend_vm(id)?;
            good &= self.create_guest(id, &name, kernel)?;
            names.push(name);
        }
        for name in &names {
            self.keep_going()?;
            good &= self.await_running(id, name)?;
            good &= self.read_console(id, name)?;
        }
        for name in &names {
            // NOT `keep_going`: a deadline that stopped the deletes would
            // leave the guests behind, and the cleanup below is what an
            // interrupted run relies on. The deletes are the cheap half.
            good &= self.delete_guest(id, name)?;
        }
        Ok(good)
    }

    /// Where the guest kernel and its initramfs are, out of the release.
    fn guest_tiny(&self) -> Result<GuestTiny> {
        let package = self.release.packages.get("guest-tiny").ok_or_else(|| {
            anyhow::anyhow!(
                "this release has no `guest-tiny` package, so there is no guest to boot. \
                 `build` puts it there; a release made before it did has to be built again."
            )
        })?;
        Ok(GuestTiny {
            kernel: format!("{}/bzImage", package.store_path),
            initrd: format!("{}/initrd", package.store_path),
        })
    }

    fn create_guest(&mut self, id: &str, name: &str, kernel: &GuestTiny) -> Result<bool> {
        let spec_path = self
            .state
            .run_dir(&self.options.run_id)
            .join("specs")
            .join(format!("{name}.json"));
        self.files
            .create_dir_all(&self.state.run_dir(&self.options.run_id).join("specs"))?;
        self.files
            .write_atomic(&spec_path, &tiny_spec(kernel)?, 0o644)?;

        let cmd = self
            .cli(Effect::TargetWrite)?
            .arg("vm")
            .arg("create")
            .arg(name)
            .arg("-f")
            .arg(spec_path.display().to_string());
        let started = self.clock.now();
        let answer = self.exec(&cmd);
        let mut check = self.check("vm.create", id, Subject::resource(name), Status::Pass);
        check.duration_ms = self.since(started);
        check.expected = format!("the control plane records {name} for {id}");
        check.evidence.push(Evidence {
            kind: if self.mock {
                EvidenceKind::Mock
            } else {
                EvidenceKind::Command
            },
            reference: cmd.line(),
        });
        match answer {
            Ok(out) => {
                let (node, uid) = placement_of(&out.stdout);
                check.observed = match &node {
                    Some(node) => format!("created, and the scheduler put it on {node}"),
                    None => "created; the object carries no node yet".to_string(),
                };
                check.reason =
                    "the operator's own cli made it, over the same session an operator uses"
                        .to_string();
                self.record(check);
                self.set_placement(name, node.as_deref().unwrap_or(""), uid)?;
                Ok(true)
            }
            Err(e) => {
                check.status = Status::Fail;
                check.observed = "it was refused".to_string();
                check.reason = format!("{e:#}");
                self.record(check);
                // The ledger entry stays `created`: a create that returned
                // an error may still have made the object, and the cleanup
                // is what finds out.
                Ok(false)
            }
        }
    }

    /// Poll until the object says `Running`, or say what it did say.
    fn await_running(&mut self, id: &str, name: &str) -> Result<bool> {
        let started = self.clock.now();
        // The initial value is the one a run that was interrupted before it
        // could ask anything ends up reporting, which is why the interrupt
        // is looked at FIRST: a guest nobody got to look at is `unknown` and
        // not a guest that failed to start.
        let mut last = "nothing was asked: the run was interrupted".to_string();
        let mut node = None;
        let mut status = Status::Unknown;
        loop {
            if self.cancel.is_cancelled() {
                break;
            }
            let cmd = self
                .cli(Effect::Read)?
                .arg("vm")
                .arg("get")
                .arg(name)
                .expect(Expect::AnyExit);
            match self.exec(&cmd) {
                Ok(out) if out.ok() => {
                    let (placed, _) = placement_of(&out.stdout);
                    if placed.is_some() {
                        node = placed;
                    }
                    last = phase_of(&out.stdout).unwrap_or_else(|| "(no phase)".to_string());
                    if last == "Running" {
                        status = Status::Pass;
                        break;
                    }
                    // A guest that came to rest somewhere else is not going
                    // to move on its own, so there is nothing to wait for.
                    if last == "Failed" || last == "Quarantined" {
                        break;
                    }
                }
                Ok(out) => {
                    last = format!("the cli said: {}", last_lines(&out.stderr));
                }
                Err(e) => {
                    last = format!("{e:#}");
                    status = Status::Unknown;
                    break;
                }
            }
            if self.waited_out(started) {
                status = Status::Fail;
                break;
            }
            self.clock.sleep(self.options.poll);
        }

        if let Some(node) = &node {
            self.set_placement(name, node, None)?;
        }
        let ran_on = self.node_of(name).unwrap_or_else(|| id.to_string());
        let mut check = self.check("vm.running", id, Subject::resource(name), status);
        check.duration_ms = self.since(started);
        check.expected = "phase Running".to_string();
        check.observed = format!("phase {last} on {ran_on}");
        check.reason = if status == Status::Pass {
            format!(
                "the hypervisor on {ran_on} started it, so that node has a working \
                 cloud-hypervisor and a session that carried the order to it"
            )
        } else {
            format!(
                "it never reached Running within {:?}; the console of the guest and \
                 `meister vm get {name}` say more",
                self.options.settle
            )
        };
        check.evidence.push(Evidence {
            kind: self.evidence_kind(&ran_on, "kvm", status == Status::Pass),
            reference: format!("vm {name} on node {ran_on}"),
        });
        let pass = status == Status::Pass;
        self.record(check);
        Ok(pass)
    }

    /// Read what the guest printed, and look for the one line only a booted
    /// guest-tiny prints.
    ///
    /// Polled and not asked once, and the reason is a measurement: the
    /// node's serial line is a SOCKET, and the file `vm logs` reads exists
    /// only once the agent's reconcile pass has attached a recorder to it.
    /// That pass runs every thirty seconds, so a guest that booted in 0.8 s
    /// has an empty console for up to half a minute — and cloud-hypervisor
    /// holds a 1 MiB ring in the meantime and replays it, so nothing is
    /// lost, it is only late. Asking once would have called every healthy
    /// guest a guest that never booted.
    fn read_console(&mut self, id: &str, name: &str) -> Result<bool> {
        let started = self.clock.now();
        let cmd = self
            .cli(Effect::Read)?
            .arg("vm")
            .arg("logs")
            .arg(name)
            .arg("--lines")
            .arg("200");
        // The verdict a run that was interrupted before it could ask even
        // once ends up with: nobody looked, so nobody knows.
        let mut status = Status::Unknown;
        let mut observed = "nothing was recorded".to_string();
        let mut reason = String::new();
        loop {
            if self.cancel.is_cancelled() {
                break;
            }
            match self.exec(&cmd) {
                Ok(out) if console_says(&out.stdout, TINY_MARKER) => {
                    status = Status::Pass;
                    break;
                }
                Ok(out) => {
                    let text = console_text(&out.stdout);
                    match record_of(&text) {
                        Record::Empty => {
                            status = Status::Unknown;
                            observed = "nothing was recorded".to_string();
                        }
                        Record::Truncated => {
                            status = Status::Unknown;
                            observed = format!(
                                "the record ends in the middle of a line: {}",
                                last_lines(&text)
                            );
                        }
                        Record::Whole => {
                            status = Status::Fail;
                            observed =
                                format!("the console had no such line: {}", last_lines(&text));
                        }
                    }
                }
                Err(e) => {
                    status = Status::Unknown;
                    observed = "the console could not be read".to_string();
                    reason = format!("{e:#}");
                    break;
                }
            }
            if self.waited_out(started) {
                break;
            }
            self.clock.sleep(self.options.poll);
        }

        let ran_on = self.node_of(name).unwrap_or_else(|| id.to_string());
        let mut check = self.check("vm.console", id, Subject::resource(name), status);
        check.duration_ms = self.since(started);
        check.expected = format!("{TINY_MARKER} on the guest's serial console");
        check.evidence.push(Evidence {
            kind: self.evidence_kind(&ran_on, "kvm", status == Status::Pass),
            reference: cmd.line(),
        });
        match status {
            Status::Pass => {
                check.observed = TINY_MARKER.to_string();
                check.reason = format!(
                    "a kernel started, an init ran and wrote to the serial line on \
                     {ran_on}: the guest booted, and nothing short of a boot prints this"
                );
            }
            Status::Unknown => {
                check.observed = observed;
                check.reason = if reason.is_empty() {
                    format!(
                        "this cannot tell whether the guest booted, because the record of \
                         what it said is not whole. The node's serial line is a socket and \
                         the agent attaches its recorder on a reconcile pass, so a guest \
                         that says everything it has to say in its first second can be \
                         recorded from the middle. Measured against this node: the whole \
                         boot is on the wire (a client connected at 0.2 s reads 20 750 \
                         bytes ending in {TINY_MARKER}) and the recorded file holds 278 \
                         bytes. Not a pass, and not a failure of the guest."
                    )
                } else {
                    reason
                };
            }
            _ => {
                check.observed = observed;
                check.reason = format!(
                    "the object may be Running while the guest never booted; that is the \
                     difference this check exists for. The node attaches its serial \
                     recorder on a reconcile pass, so this waited {:?} for one.",
                    self.options.settle
                );
            }
        }
        let pass = status == Status::Pass;
        self.record(check);
        Ok(pass)
    }

    fn delete_guest(&mut self, id: &str, name: &str) -> Result<bool> {
        let started = self.clock.now();
        if self.options.keep {
            // `--keep` is for somebody who wants to look at a guest that
            // misbehaved, so the guest stays — and the step that was not
            // taken is `skipped` rather than absent. A required suite is
            // therefore BLOCKED by `--keep`, which is right: a lifecycle
            // that never deleted anything has not shown a lifecycle.
            let mut check = self.check("vm.delete", id, Subject::resource(name), Status::Skipped);
            check.expected = format!("{name} is gone from the control plane");
            check.observed = "--keep: it was left standing".to_string();
            check.reason = format!(
                "look at it with `meister vm get {name}`, and remove it with \
                 `meister vm rm {name}` when you are done."
            );
            self.record(check);
            return Ok(false);
        }
        let gone = match self.remove(name) {
            Ok(outcome) => outcome,
            Err(e) => {
                self.set_state(name, ResourceState::Lost)?;
                Removal::Left(format!("it could not even be asked for: {e:#}"))
            }
        };
        let mut check = self.check("vm.delete", id, Subject::resource(name), Status::Pass);
        check.duration_ms = self.since(started);
        check.expected = format!("{name} is gone from the control plane");
        match gone {
            Removal::Gone => {
                check.observed = "it is not in the listing any more".to_string();
                check.reason = "a suite that leaves its guests behind is a suite nobody runs twice"
                    .to_string();
                self.record(check);
                Ok(true)
            }
            Removal::Left(why) => {
                check.status = Status::Unknown;
                check.observed = format!("it is still there: {why}");
                check.reason = format!(
                    "this run made {name} and could not take it back. It is in the ledger \
                     as `lost`; `meister vm rm {name}` is the command, and nothing here \
                     will retry it on its own."
                );
                self.record(check);
                Ok(false)
            }
        }
    }

    // --- suite: gpu -------------------------------------------------------

    /// Passthrough, repeated, and a refusal that has to be a refusal.
    ///
    /// The guests here carry one PCI device each, out of the host's declared
    /// `hardware.gpus`. What this suite deliberately does NOT do is claim a
    /// computation: `guest-tiny` is busybox and a kernel, there is no CUDA
    /// or nvrm userland in this repository, and a suite that reported "the
    /// GPU works" on the strength of a PCI id in `/sys` would be the exact
    /// sort of green line this tool exists to refuse. That half is
    /// `not_applicable` with the sentence saying what would have to exist.
    fn gpu(&mut self) -> Result<()> {
        let hosts = self.hosts.clone();
        for id in hosts {
            self.keep_going()?;
            let Some(host) = self.fleet().hosts.get(&id).cloned() else {
                continue;
            };
            match applicability(Suite::Gpu, self.fleet(), &id, &host) {
                Applicability::No(reason) => {
                    let mut check =
                        self.check("gpu", &id, Subject::host(&id), Status::NotApplicable);
                    check.expected =
                        "a host declaring hardware.gpus and the vfio capability".to_string();
                    check.observed = reason.clone();
                    check.reason = reason;
                    self.record(check);
                    continue;
                }
                Applicability::Yes => {}
            }
            if let Some(reason) = self.unreachable(&id) {
                let mut check = self.check("gpu", &id, Subject::host(&id), Status::Skipped);
                check.expected = "a host that answers, so a guest can be given its GPU".to_string();
                check.observed = reason.clone();
                check.reason = format!("{reason} The declared hardware was not exercised.");
                self.record(check);
                continue;
            }
            // Declared AND reachable, and the machine does not have the
            // device node the driver needs: that is a measurement, and it is
            // a failure of the host rather than a reason to skip.
            if !self.measured(&id, "vfio") {
                let mut check = self.check("gpu", &id, Subject::host(&id), Status::Fail);
                check.expected = "/dev/vfio/vfio on a host that declares a GPU".to_string();
                check.observed = "the snapshot of this host has no vfio capability".to_string();
                check.reason =
                    "the inventory says this machine passes a GPU through and the machine \
                     says it cannot: one of the two is wrong, and no guest was started to \
                     paper over it."
                        .to_string();
                check.evidence.push(Evidence {
                    kind: EvidenceKind::Command,
                    reference: format!("observation of {id}: capabilities"),
                });
                self.record(check);
                continue;
            }

            let kernel = self.guest_tiny()?;
            let gpus: Vec<String> = host.hardware.gpus.iter().map(|g| g.pci.clone()).collect();
            let mut good = true;
            // Two guests with a device each, five rounds: a passthrough that
            // works once and leaks the device on teardown is the failure
            // this repeats for.
            for _ in 0..GPU_ROUNDS {
                self.keep_going()?;
                let mut names = Vec::new();
                for pci in gpus.iter().take(2) {
                    let name = self.intend_vm(&id)?;
                    good &= self.create_gpu_guest(&id, &name, &kernel, pci)?;
                    names.push(name);
                }
                for name in &names {
                    good &= self.await_running(&id, name)?;
                    good &= self.gpu_seen(&id, name)?;
                }
                for name in &names {
                    good &= self.delete_guest(&id, name)?;
                }
            }
            good &= self.gpu_refusal(&id, &kernel)?;
            self.gpu_compute_not_applicable(&id);

            let mut check = self.check(
                "gpu",
                &id,
                Subject::host(&id),
                if good { Status::Pass } else { Status::Fail },
            );
            check.expected =
                format!("{GPU_ROUNDS} rounds of two guests with a device each, and a refusal");
            check.observed = if good {
                "every round created, ran and deleted, and the bad address was refused".to_string()
            } else {
                "at least one round did not".to_string()
            };
            check.reason =
                "a device that can be handed out, handed back and handed out again is the \
                 property a single successful passthrough does not show"
                    .to_string();
            self.record(check);
        }
        Ok(())
    }

    fn create_gpu_guest(
        &mut self,
        id: &str,
        name: &str,
        kernel: &GuestTiny,
        pci: &str,
    ) -> Result<bool> {
        let dir = self.state.run_dir(&self.options.run_id).join("specs");
        self.files.create_dir_all(&dir)?;
        let spec_path = dir.join(format!("{name}.json"));
        self.files
            .write_atomic(&spec_path, &gpu_spec(kernel, pci)?, 0o644)?;
        let cmd = self
            .cli(Effect::TargetWrite)?
            .arg("vm")
            .arg("create")
            .arg(name)
            .arg("-f")
            .arg(spec_path.display().to_string());
        let started = self.clock.now();
        let answer = self.exec(&cmd);
        let mut check = self.check("gpu.create", id, Subject::resource(name), Status::Pass);
        check.duration_ms = self.since(started);
        check.expected = format!("a guest on {id} holding {pci}");
        check.evidence.push(Evidence {
            kind: if self.mock {
                EvidenceKind::Mock
            } else {
                EvidenceKind::Command
            },
            reference: cmd.line(),
        });
        match answer {
            Ok(out) => {
                let (node, uid) = placement_of(&out.stdout);
                check.observed = format!("created on {}", node.clone().unwrap_or_default());
                check.reason = "the device was accepted by the node's own catalogue".to_string();
                self.record(check);
                self.set_placement(name, node.as_deref().unwrap_or(""), uid)?;
                Ok(true)
            }
            Err(e) => {
                check.status = Status::Fail;
                check.observed = "it was refused".to_string();
                check.reason = format!("{e:#}");
                self.record(check);
                Ok(false)
            }
        }
    }

    /// Whether the guest can see the device it was given.
    ///
    /// `guest-tiny` is busybox without `lspci` and without `/usr/share/pci.ids`,
    /// so what can be read is `/sys/bus/pci/devices` — and that is only
    /// reachable through the console, which this guest does not offer a shell
    /// on. So the answer here is `unknown` with the sentence saying so, and
    /// not a pass: an image with PCI tooling is what would turn it into one.
    fn gpu_seen(&mut self, id: &str, name: &str) -> Result<bool> {
        let ran_on = self.node_of(name).unwrap_or_else(|| id.to_string());
        let mut check = self.check("gpu.in-guest", id, Subject::resource(name), Status::Unknown);
        check.expected = "the device in the guest's /sys/bus/pci/devices".to_string();
        check.observed = "guest-tiny has no PCI tooling and no shell on its console".to_string();
        check.reason =
            "the hypervisor accepted the device and the guest booted with it; whether the \
             guest SEES it needs an image that can be asked, which this repository does not \
             build. This is not a pass."
                .to_string();
        check.evidence.push(Evidence {
            kind: self.evidence_kind(&ran_on, "vfio", true),
            reference: format!("vm {name} on node {ran_on}"),
        });
        self.record(check);
        Ok(true)
    }

    /// A device that is not there has to be refused, and the refusal is the
    /// pass.
    fn gpu_refusal(&mut self, id: &str, kernel: &GuestTiny) -> Result<bool> {
        let dir = self.state.run_dir(&self.options.run_id).join("specs");
        self.files.create_dir_all(&dir)?;
        let name = format!("{}-refusal", self.ledger.tag);
        let spec_path = dir.join(format!("{name}.json"));
        self.files
            .write_atomic(&spec_path, &gpu_spec(kernel, NO_SUCH_PCI)?, 0o644)?;
        let cmd = self
            .cli(Effect::TargetWrite)?
            .arg("vm")
            .arg("create")
            .arg(&name)
            .arg("-f")
            .arg(spec_path.display().to_string())
            .expect(Expect::AnyExit);
        let started = self.clock.now();
        let answer = self.exec(&cmd);
        let mut check = self.check("gpu.refusal", id, Subject::resource(&name), Status::Fail);
        check.duration_ms = self.since(started);
        check.expected = format!("{NO_SUCH_PCI} is refused, because no such device exists");
        check.evidence.push(Evidence {
            kind: if self.mock {
                EvidenceKind::Mock
            } else {
                EvidenceKind::Command
            },
            reference: cmd.line(),
        });
        match answer {
            Ok(out) if !out.ok() => {
                check.status = Status::Pass;
                check.observed = format!("refused: {}", last_lines(&out.stderr));
                check.reason =
                    "a backend that accepts a device it does not have is a backend that \
                     fails at boot instead of at the door"
                        .to_string();
                self.record(check);
                Ok(true)
            }
            Ok(_) => {
                // It was accepted. Whatever that made is ours, so it goes in
                // the ledger and the cleanup takes it.
                self.made += 1;
                self.ledger.resources.push(Resource {
                    kind: ResourceKind::Vm,
                    id: None,
                    name: name.clone(),
                    host: id.to_string(),
                    created_at: self.clock.now(),
                    state: ResourceState::Created,
                });
                self.save_ledger()?;
                check.observed = "it was accepted".to_string();
                check.reason =
                    "a PCI address nothing on this machine answers to was taken as valid"
                        .to_string();
                self.record(check);
                Ok(false)
            }
            Err(e) => {
                check.status = Status::Unknown;
                check.observed = "the cli could not be asked".to_string();
                check.reason = format!("{e:#}");
                self.record(check);
                Ok(false)
            }
        }
    }

    /// The half of the GPU suite this repository cannot honestly run.
    fn gpu_compute_not_applicable(&mut self, id: &str) {
        let mut check = self.check("gpu.compute", id, Subject::host(id), Status::NotApplicable);
        check.expected =
            "a deterministic computation in the guest, checked against a known result".to_string();
        check.observed = "no guest image with a compute stack in this repository".to_string();
        check.reason =
            "it would need a guest carrying a CUDA or nvrm userland and a pinned kernel \
             driver, built the way nix/packages/guest-tiny.nix builds the small one. \
             Until that exists this says so rather than reporting a number nothing checked."
                .to_string();
        self.record(check);
    }

    // --- suite: rdma ------------------------------------------------------

    /// Three measurements between two hosts that DECLARE a fabric to each
    /// other, and nothing between any other two.
    ///
    /// A round trip, a latency and a bandwidth, each server-on-A and
    /// client-on-B over ssh, each its own [`CheckResult`]. The declaration
    /// is what makes a pair: two hosts with `hardware.nics[].rdma = true` on
    /// the same `networks.storage`. This suite never guesses a peer — a
    /// bandwidth test invents neither of its two ends — and it never reads a
    /// number off a machine whose snapshot has no fabric device.
    fn rdma(&mut self) -> Result<()> {
        let hosts = self.hosts.clone();
        let pairs = self.pairs()?;
        // Every host of the selection gets a verdict, even the ones that
        // are in no pair: a suite that silently covered two of seventy
        // hosts is a suite whose green line means nothing.
        for id in &hosts {
            self.keep_going()?;
            let Some(host) = self.fleet().hosts.get(id).cloned() else {
                continue;
            };
            if let Applicability::No(reason) = applicability(Suite::Rdma, self.fleet(), id, &host) {
                let mut check = self.check("rdma", id, Subject::host(id), Status::NotApplicable);
                check.expected =
                    "a host declaring hardware.nics[].rdma and a storage network".to_string();
                check.observed = reason.clone();
                check.reason = reason;
                self.record(check);
                continue;
            }
            if !pairs.iter().any(|(a, b)| a == id || b == id) {
                let mut check = self.check("rdma", id, Subject::host(id), Status::NotApplicable);
                check.expected = "a declared peer on the same storage network".to_string();
                check.observed =
                    "this host declares rdma and no other selected host shares its storage \
                     network"
                        .to_string();
                check.reason =
                    "a fabric measurement needs two ends, and this suite invents neither of \
                     them. `--pairs <a>:<b>` names one explicitly."
                        .to_string();
                self.record(check);
                continue;
            }
        }

        for (server, client) in pairs {
            self.keep_going()?;
            let subject = Subject::resource(format!("{server}<->{client}"));
            if let Some(reason) = self
                .unreachable(&server)
                .or_else(|| self.unreachable(&client))
            {
                // Declared and unreachable: `skipped`, and a required
                // `skipped` blocks (V22). Never `not_applicable`, which is
                // the one non-pass that lets a run through.
                let mut check = self.check("rdma.pair", &server, subject, Status::Skipped);
                check.expected = format!("{server} and {client} both answering");
                check.observed = reason.clone();
                check.reason = format!(
                    "{reason} The declared fabric between them was not exercised, which is \
                     not the same as it having worked."
                );
                self.record(check);
                continue;
            }
            for end in [&server, &client] {
                if !self.measured(end, "rdma") {
                    let mut check = self.check("rdma.pair", &server, subject.clone(), Status::Fail);
                    check.expected =
                        "a device under /sys/class/infiniband at both ends".to_string();
                    check.observed = format!("the snapshot of {end} has no rdma capability");
                    check.reason =
                        "the inventory declares an RDMA nic on this machine and the machine \
                         has no fabric device: one of the two is wrong, and no number was \
                         taken to paper over it."
                            .to_string();
                    check.evidence.push(Evidence {
                        kind: EvidenceKind::Command,
                        reference: format!("observation of {end}: capabilities"),
                    });
                    self.record(check);
                    return Ok(());
                }
            }
            self.rdma_ping(&server, &client)?;
            self.rdma_latency(&server, &client)?;
            self.rdma_bandwidth(&server, &client)?;
        }
        Ok(())
    }

    /// The pairs to measure: what `--pairs` named, or every declared pair of
    /// the selection, each one once.
    fn pairs(&self) -> Result<Vec<(String, String)>> {
        if !self.options.pairs.is_empty() {
            for (a, b) in &self.options.pairs {
                for id in [a, b] {
                    let host = self.fleet().hosts.get(id).ok_or_else(|| {
                        anyhow::anyhow!(
                            "--pairs names {id}, and the fleet {:?} has no such host.",
                            self.fleet().fleet.name
                        )
                    })?;
                    if let Applicability::No(reason) =
                        applicability(Suite::Rdma, self.fleet(), id, host)
                    {
                        bail!(
                            "--pairs names {a}:{b}, and {reason} A pair this tool measures is \
                             one the inventory declares."
                        );
                    }
                }
            }
            return Ok(self.options.pairs.clone());
        }
        let peers = rdma_peers(self.fleet(), &self.hosts);
        let mut out: Vec<(String, String)> = Vec::new();
        for (id, others) in &peers {
            for other in others {
                // Each unordered pair once: which end is the server is this
                // suite's decision and the lower id takes it, so two runs
                // of the same fleet measure the same direction.
                if id < other {
                    out.push((id.clone(), other.clone()));
                }
            }
        }
        Ok(out)
    }

    /// A server that does not block this run.
    ///
    /// The three tools are all server-on-one-end, client-on-the-other, and
    /// every server of them BLOCKS until a client has been and gone. The
    /// only runner these tests may use is a strict sequence, so a server in
    /// the foreground would hold the run for ever — and a second thread
    /// would be concurrency no test could fix. So the server is started in
    /// the background ON THE TARGET, its pid comes back on stdout, and it is
    /// killed afterwards whatever the client did.
    fn start_server(&self, host: &str, argv: &[String], log: &str) -> Result<(Cmd, String)> {
        let target = self.target(host)?;
        let script = format!(
            "{} > {log} 2>&1 & echo $!",
            argv.iter()
                .map(|a| crate::run::shell_quote(a))
                .collect::<Vec<_>>()
                .join(" ")
        );
        let cmd = self.ssh()?.exec(
            &target,
            ["sh", "-c", &script],
            Effect::TargetWrite,
            self.options.cli_deadline,
        );
        let out = self.exec(&cmd)?;
        Ok((cmd, out.trimmed().to_string()))
    }

    /// Take the server down, and say nothing if it had already gone: these
    /// servers exit on their own when their client disconnects, and a kill
    /// of a pid that is not there is the normal case rather than an error.
    fn stop_server(&self, host: &str, pid: &str, log: &str) -> Result<String> {
        let target = self.target(host)?;
        let script = format!("kill {pid} 2>/dev/null; cat {log} 2>/dev/null; true");
        let cmd = self.ssh()?.exec(
            &target,
            ["sh", "-c", &script],
            Effect::TargetWrite,
            self.options.cli_deadline,
        );
        Ok(self.exec(&cmd)?.stdout)
    }

    fn client(&self, host: &str, argv: &[String]) -> Result<(Cmd, Result<crate::run::Output>)> {
        let target = self.target(host)?;
        let cmd = self
            .ssh()?
            .exec(&target, argv, Effect::TargetWrite, self.options.fabric)
            .expect(Expect::AnyExit);
        let out = self.exec(&cmd);
        Ok((cmd, out))
    }

    /// `rping`: does a round trip complete at all, ten times over?
    fn rdma_ping(&mut self, server: &str, client: &str) -> Result<()> {
        let address = self.storage_address(server)?;
        let log = format!("/tmp/{}-rping.log", self.ledger.tag);
        let started = self.clock.now();
        let subject = Subject::resource(format!("{server}<->{client}"));
        let mut check = self.check("rdma.ping", server, subject, Status::Fail);
        check.expected = format!("{RPING_ROUNDS} round trips {client} -> {server} ({address})");

        let server_argv = rping_server(&address);
        let (server_cmd, pid) = self.start_server(server, &server_argv, &log)?;
        let client_argv = rping_client(&address);
        let (client_cmd, answer) = self.client(client, &client_argv)?;
        let server_said = self.stop_server(server, &pid, &log)?;

        check.duration_ms = self.since(started);
        check.evidence.push(Evidence {
            kind: self.fabric_evidence(server),
            reference: server_cmd.line(),
        });
        check.evidence.push(Evidence {
            kind: self.fabric_evidence(client),
            reference: client_cmd.line(),
        });
        match answer {
            Ok(out) if out.ok() => {
                let rounds = rping_rounds(&out.stdout);
                if rounds >= RPING_ROUNDS {
                    check.status = Status::Pass;
                    check.observed = format!("{rounds} round trips, no error");
                    check.reason = format!(
                        "a connection was made over the fabric between {client} and {server} \
                         and data went both ways; nothing short of a working fabric does that"
                    );
                } else {
                    check.observed = format!("{rounds} of {RPING_ROUNDS} round trips");
                    check.reason = format!(
                        "the client returned 0 and the fabric carried fewer rounds than it \
                         was asked for. The server said: {}",
                        last_lines(&server_said)
                    );
                }
            }
            Ok(out) => {
                check.observed = format!("rping exited {}", out.status);
                check.reason = format!(
                    "{}. The server at {server} said: {}",
                    last_lines(&out.stderr),
                    last_lines(&server_said)
                );
            }
            Err(e) => {
                check.status = Status::Unknown;
                check.observed = "the client could not be run".to_string();
                check.reason = format!("{e:#}");
            }
        }
        self.record(check);
        Ok(())
    }

    /// `ib_send_lat`: how long one message takes, typically and at worst.
    fn rdma_latency(&mut self, server: &str, client: &str) -> Result<()> {
        let address = self.storage_address(server)?;
        let log = format!("/tmp/{}-lat.log", self.ledger.tag);
        let started = self.clock.now();
        let subject = Subject::resource(format!("{server}<->{client}"));
        let mut check = self.check("rdma.latency", server, subject, Status::Fail);
        check.expected = format!("a latency for {client} -> {server} ({address}), in us");

        let (server_cmd, pid) = self.start_server(server, &ib_send_lat_server(), &log)?;
        let (client_cmd, answer) = self.client(client, &ib_send_lat_client(&address))?;
        let server_said = self.stop_server(server, &pid, &log)?;

        check.duration_ms = self.since(started);
        check.evidence.push(Evidence {
            kind: self.fabric_evidence(server),
            reference: server_cmd.line(),
        });
        check.evidence.push(Evidence {
            kind: self.fabric_evidence(client),
            reference: client_cmd.line(),
        });
        match answer {
            Ok(out) if out.ok() => match latency_of(&out.stdout) {
                Some(latency) => {
                    check.status = Status::Pass;
                    check.observed = format!(
                        "typical {:.2} us, worst {:.2} us",
                        latency.typical, latency.max
                    );
                    check.reason =
                        "measured end to end over the fabric; the worst case is the number \
                         a storage path is actually held to"
                            .to_string();
                }
                None => {
                    check.status = Status::Unknown;
                    check.observed = "the output had no row this tool could read".to_string();
                    check.reason = format!(
                        "ib_send_lat returned 0 and printed: {}",
                        last_lines(&out.stdout)
                    );
                }
            },
            Ok(out) => {
                check.observed = format!("ib_send_lat exited {}", out.status);
                check.reason = format!(
                    "{}. The server at {server} said: {}",
                    last_lines(&out.stderr),
                    last_lines(&server_said)
                );
            }
            Err(e) => {
                check.status = Status::Unknown;
                check.observed = "the client could not be run".to_string();
                check.reason = format!("{e:#}");
            }
        }
        self.record(check);
        Ok(())
    }

    /// `ib_write_bw`: how much the fabric carries.
    fn rdma_bandwidth(&mut self, server: &str, client: &str) -> Result<()> {
        let address = self.storage_address(server)?;
        let log = format!("/tmp/{}-bw.log", self.ledger.tag);
        let started = self.clock.now();
        let subject = Subject::resource(format!("{server}<->{client}"));
        let mut check = self.check("rdma.bandwidth", server, subject, Status::Fail);
        check.expected = format!("a bandwidth for {client} -> {server} ({address}), in MB/s");

        let (server_cmd, pid) = self.start_server(server, &ib_write_bw_server(), &log)?;
        let (client_cmd, answer) = self.client(client, &ib_write_bw_client(&address))?;
        let server_said = self.stop_server(server, &pid, &log)?;

        check.duration_ms = self.since(started);
        check.evidence.push(Evidence {
            kind: self.fabric_evidence(server),
            reference: server_cmd.line(),
        });
        check.evidence.push(Evidence {
            kind: self.fabric_evidence(client),
            reference: client_cmd.line(),
        });
        match answer {
            Ok(out) if out.ok() => match bandwidth_of(&out.stdout) {
                Some(bandwidth) => {
                    check.status = Status::Pass;
                    check.observed = format!(
                        "average {:.2} MB/s, peak {:.2} MB/s",
                        bandwidth.average, bandwidth.peak
                    );
                    check.reason =
                        "measured end to end over the fabric; the average is what a copy \
                         between these two machines gets"
                            .to_string();
                }
                None => {
                    check.status = Status::Unknown;
                    check.observed = "the output had no row this tool could read".to_string();
                    check.reason = format!(
                        "ib_write_bw returned 0 and printed: {}",
                        last_lines(&out.stdout)
                    );
                }
            },
            Ok(out) => {
                check.observed = format!("ib_write_bw exited {}", out.status);
                check.reason = format!(
                    "{}. The server at {server} said: {}",
                    last_lines(&out.stderr),
                    last_lines(&server_said)
                );
            }
            Err(e) => {
                check.status = Status::Unknown;
                check.observed = "the client could not be run".to_string();
                check.reason = format!("{e:#}");
            }
        }
        self.record(check);
        Ok(())
    }

    /// The address on the fabric, which is `networks.storage` and never the
    /// management address: a measurement over the wrong wire is a number
    /// that looks like an answer.
    fn storage_address(&self, id: &str) -> Result<String> {
        let host = self
            .fleet()
            .hosts
            .get(id)
            .ok_or_else(|| anyhow::anyhow!("{id} is not a host of this release"))?;
        host.networks
            .storage
            .as_ref()
            .map(|n| n.address.clone())
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "{id} declares an rdma nic and no networks.storage, so there is no \
                     address on the fabric to measure to."
                )
            })
    }

    fn ssh(&self) -> Result<&crate::transport::Ssh> {
        self.ssh.ok_or_else(|| {
            anyhow::anyhow!(
                "this suite reaches both ends over ssh and this run was given no transport."
            )
        })
    }

    fn target(&self, id: &str) -> Result<crate::transport::Target> {
        let endpoint = self.endpoints.get(id).ok_or_else(|| {
            anyhow::anyhow!("nothing in this run says where {id} answers, so it was not asked.")
        })?;
        Ok(crate::transport::Target::from_endpoint(id, endpoint))
    }

    /// `hardware` only where the SNAPSHOT of that machine found a fabric
    /// device — the same rule the guest suites follow, for the same reason.
    fn fabric_evidence(&self, id: &str) -> EvidenceKind {
        self.evidence_kind(id, "rdma", true)
    }

    // --- cleanup ----------------------------------------------------------

    /// Take back what this run made, and say what could not be taken back.
    ///
    /// Only entries of THIS ledger, and only names carrying THIS run's tag.
    /// The second condition is redundant while the ledger is written by this
    /// process and is not redundant at all when a `--resume` of somebody
    /// else's ledger is added later, so it is enforced now, with a sentence
    /// and a check when it fires.
    pub fn cleanup(&mut self) -> Result<()> {
        self.cleaning_up = true;
        if self.options.keep {
            let outstanding: Vec<String> = self
                .ledger
                .outstanding()
                .iter()
                .map(|r| r.name.clone())
                .collect();
            if !outstanding.is_empty() {
                let mut check = self.check(
                    "verify.cleanup",
                    self.hosts.first().map(String::as_str).unwrap_or(""),
                    Subject::resource(self.ledger.tag.clone()),
                    Status::Skipped,
                );
                check.required = true;
                check.expected = "every guest of this run removed".to_string();
                check.observed = format!("--keep: {} left standing", outstanding.len());
                check.reason = format!(
                    "they are {}. `meister vm rm <name>` removes them, and {} says which \
                     host each one is on.",
                    outstanding.join(", "),
                    self.ledger_path().display()
                );
                self.record(check);
            }
            return Ok(());
        }

        let untried: Vec<(String, String)> = self
            .ledger
            .untried()
            .iter()
            .map(|r| (r.name.clone(), r.host.clone()))
            .collect();
        for (name, host) in untried {
            if !name.starts_with(&self.ledger.tag) {
                let mut check = self.check(
                    "verify.cleanup",
                    &host,
                    Subject::resource(&name),
                    Status::Unknown,
                );
                check.required = true;
                check.expected = format!("every name of this run starts with {}", self.ledger.tag);
                check.observed = format!("{name} does not");
                check.reason =
                    "this run will not delete a resource it cannot prove it made. Look at \
                     it by hand."
                        .to_string();
                self.record(check);
                self.set_state(&name, ResourceState::Lost)?;
                continue;
            }
            // A removal that could not even be ASKED for — no cli reference,
            // a runner that refuses the class — is the same outcome as one
            // that was refused: the resource is still there and somebody has
            // to be told. It must not end the cleanup, because the next
            // resource may still be removable.
            let outcome = match self.remove(&name) {
                Ok(outcome) => outcome,
                Err(e) => {
                    self.set_state(&name, ResourceState::Lost)?;
                    Removal::Left(format!("it could not even be asked for: {e:#}"))
                }
            };
            match outcome {
                Removal::Gone => {}
                Removal::Left(why) => {
                    let mut check = self.check(
                        "verify.cleanup",
                        &host,
                        Subject::resource(&name),
                        Status::Unknown,
                    );
                    check.required = true;
                    check.expected = format!("{name} removed");
                    check.observed = why;
                    check.reason = format!(
                        "this run made {name} on {host} and could not take it back; the \
                         ledger has it as lost."
                    );
                    self.record(check);
                }
            }
        }
        let lost: Vec<String> = self
            .ledger
            .outstanding()
            .iter()
            .map(|r| r.name.clone())
            .collect();
        if !lost.is_empty() {
            // Said once, at the top level, so a reader does not have to
            // count the individual lines.
            let mut check = self.check(
                "verify.leftovers",
                self.hosts.first().map(String::as_str).unwrap_or(""),
                Subject::resource(self.ledger.tag.clone()),
                Status::Unknown,
            );
            check.required = true;
            check.expected = "this run leaves nothing behind".to_string();
            check.observed = format!("{} resource(s) left: {}", lost.len(), lost.join(", "));
            check.reason = format!(
                "a cleanup that did not finish is the one thing a verification must not \
                 report quietly. The ledger is {}.",
                self.ledger_path().display()
            );
            self.record(check);
        }
        Ok(())
    }

    /// Delete one guest and then LOOK, rather than believe the delete.
    ///
    /// A `vm rm` that failed because the object is already gone and a
    /// `vm rm` that failed because the control plane is down are the same
    /// exit code and different worlds, so the listing decides. The listing
    /// is also what makes a `Terminating` guest — which is what `vm rm`
    /// leaves behind for as long as the node takes — into a wait rather than
    /// a leak.
    fn remove(&mut self, name: &str) -> Result<Removal> {
        let cmd = self
            .cli_yes(Effect::TargetWrite)?
            .arg("vm")
            .arg("rm")
            .arg(name)
            .expect(Expect::AnyExit);
        let deleted = self.exec(&cmd);
        let refusal = match &deleted {
            Ok(out) if out.ok() => None,
            Ok(out) => Some(last_lines(&out.stderr).to_string()),
            Err(e) => Some(format!("{e:#}")),
        };

        let started = self.clock.now();
        loop {
            match self.exists(name) {
                Ok(false) => {
                    self.set_state(name, ResourceState::Deleted)?;
                    return Ok(Removal::Gone);
                }
                Ok(true) => {}
                Err(e) => {
                    self.set_state(name, ResourceState::Lost)?;
                    return Ok(Removal::Left(format!(
                        "the listing could not be read, so nothing here knows: {e:#}"
                    )));
                }
            }
            if self.waited_out(started) {
                self.set_state(name, ResourceState::Lost)?;
                return Ok(Removal::Left(match refusal {
                    Some(why) => format!("the delete was refused ({why}) and it is still listed"),
                    None => format!(
                        "it is still listed {:?} after the delete returned",
                        self.options.settle
                    ),
                }));
            }
            self.clock.sleep(self.options.poll);
        }
    }

    /// Whether the control plane still lists this name.
    fn exists(&self, name: &str) -> Result<bool> {
        let cmd = self
            .cli(Effect::Read)?
            .arg("vm")
            .arg("ls")
            .expect(Expect::ExitZero);
        let out = self.exec(&cmd)?;
        Ok(lists_name(&out.stdout, name))
    }

    // --- small answers ----------------------------------------------------

    fn since(&self, started: DateTime<Utc>) -> u64 {
        (self.clock.now() - started).num_milliseconds().max(0) as u64
    }

    fn waited_out(&self, started: DateTime<Utc>) -> bool {
        (self.clock.now() - started)
            .to_std()
            .map(|d| d >= self.options.settle)
            .unwrap_or(false)
    }

    /// Why this host cannot be asked anything, or `None` when it can.
    fn unreachable(&self, id: &str) -> Option<String> {
        match self.observation.host(id) {
            None => Some(format!(
                "the snapshot this run was given says nothing about {id}."
            )),
            Some(obs) if !obs.reachable => Some(format!(
                "{id} did not answer: {}",
                obs.unknown_reason
                    .clone()
                    .unwrap_or_else(|| "no reason was recorded".to_string())
            )),
            Some(_) => None,
        }
    }

    /// What the SNAPSHOT says the machine has, as opposed to what the
    /// inventory declares.
    fn measured(&self, id: &str, capability: &str) -> bool {
        self.observation
            .host(id)
            .map(|obs| obs.has_capability(capability))
            .unwrap_or(false)
    }

    fn node_of(&self, name: &str) -> Option<String> {
        self.ledger
            .resources
            .iter()
            .find(|r| r.name == name)
            .map(|r| r.host.clone())
            .filter(|h| !h.is_empty())
    }
}

/// What became of a resource this run tried to remove.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Removal {
    Gone,
    Left(String),
}

/// Where a guest kernel and its initramfs are.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuestTiny {
    pub kernel: String,
    pub initrd: String,
}

// ---------------------------------------------------------------------------
// applicability
// ---------------------------------------------------------------------------

/// Whether a suite has anything to say about a host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Applicability {
    Yes,
    /// With the sentence that goes in `reason`.
    No(String),
}

/// Pure, so that "this host has no GPU, so the GPU suite is not applicable"
/// is a test rather than a path through a run that creates things.
pub fn applicability(
    suite: Suite,
    fleet: &ResolvedFleet,
    id: &str,
    host: &ResolvedHost,
) -> Applicability {
    match suite {
        Suite::VmLifecycle => {
            if host.roles.iter().any(|r| r == "agent") {
                Applicability::Yes
            } else {
                Applicability::No(format!(
                    "{id} has no agent role ({}), so no guest of this fleet ever runs on it.",
                    if host.roles.is_empty() {
                        "no roles at all".to_string()
                    } else {
                        host.roles.join(", ")
                    }
                ))
            }
        }
        Suite::Gpu => {
            if host.hardware.gpus.is_empty() {
                return Applicability::No(format!(
                    "{id} declares no hardware.gpus, so there is no device to pass through."
                ));
            }
            if !host.hardware.capabilities.iter().any(|c| c == "vfio") {
                return Applicability::No(format!(
                    "{id} declares a GPU and not the vfio capability, so the inventory does \
                     not claim it can be passed through."
                ));
            }
            Applicability::Yes
        }
        Suite::Rdma => {
            if !host.hardware.nics.iter().any(|n| n.rdma) {
                return Applicability::No(format!("{id} declares no nic with rdma = true."));
            }
            if host.networks.storage.is_none() {
                return Applicability::No(format!(
                    "{id} declares an rdma nic and no storage network, so there is no fabric \
                     to name a peer on."
                ));
            }
            let _ = fleet;
            Applicability::Yes
        }
    }
}

/// Which hosts share a storage network with which, among those that declare
/// an RDMA nic. Pure, and the only thing that decides who this suite talks
/// to: a peer is declared or it does not exist.
pub fn rdma_peers(fleet: &ResolvedFleet, hosts: &[String]) -> BTreeMap<String, Vec<String>> {
    let declared: Vec<(&String, &str)> = hosts
        .iter()
        .filter_map(|id| {
            let host = fleet.hosts.get(id)?;
            if !host.hardware.nics.iter().any(|n| n.rdma) {
                return None;
            }
            let storage = host.networks.storage.as_ref()?;
            Some((id, storage.address.as_str()))
        })
        .collect();
    let mut out = BTreeMap::new();
    for (id, address) in &declared {
        let prefix = network_prefix(address);
        let peers: Vec<String> = declared
            .iter()
            .filter(|(other, other_address)| other != id && network_prefix(other_address) == prefix)
            .map(|(other, _)| (*other).clone())
            .collect();
        out.insert((*id).clone(), peers);
    }
    out
}

/// The first three octets of a dotted address. Crude on purpose: what makes
/// two hosts peers here is that the INVENTORY put them on one storage
/// network, and the prefix is how that is spelled.
fn network_prefix(address: &str) -> String {
    address.split('.').take(3).collect::<Vec<_>>().join(".")
}

const GPU_ROUNDS: usize = 5;

/// A PCI address in a domain nothing uses, so a node that answers to it is a
/// node that answers to anything.
const NO_SUCH_PCI: &str = "ffff:ff:1f.7";

const GPU_PLAN: &str = "two guests with one PCI device each, five times over, then a \
                        create with a device that does not exist (which has to be refused)";

const RDMA_PLAN: &str = "a round trip (rping), a latency (ib_send_lat) and a bandwidth \
                         (ib_write_bw) between each declared pair, server on one end and \
                         client on the other";

// --- the four command lines, in one place --------------------------------
//
// One function per end of each tool, so that the server line and the client
// line of a measurement cannot drift apart — and so that a test can pin all
// four without reaching into the driver.
//
// No `-d <device>`: the tools take the first fabric device, and which one a
// machine calls `mlx5_0` is a fact this tool has no business guessing. An
// estate with two cards names the address it wants in `networks.storage`,
// which is what these lines carry.

/// `rping -s`: listen on the fabric address of the server end.
pub fn rping_server(address: &str) -> Vec<String> {
    vec![
        "rping".to_string(),
        "-s".to_string(),
        "-a".to_string(),
        address.to_string(),
        "-C".to_string(),
        RPING_ROUNDS.to_string(),
        "-v".to_string(),
    ]
}

/// `rping -c`: connect to it, ten times over.
pub fn rping_client(address: &str) -> Vec<String> {
    vec![
        "rping".to_string(),
        "-c".to_string(),
        "-a".to_string(),
        address.to_string(),
        "-C".to_string(),
        RPING_ROUNDS.to_string(),
        "-v".to_string(),
    ]
}

/// `ib_send_lat`, listening. `-F` because these machines do not have their
/// cpu frequency pinned and the tool otherwise refuses to start rather than
/// report a slightly noisy number.
pub fn ib_send_lat_server() -> Vec<String> {
    vec![
        "ib_send_lat".to_string(),
        "-F".to_string(),
        "-D".to_string(),
        FABRIC_SECONDS.to_string(),
    ]
}

pub fn ib_send_lat_client(address: &str) -> Vec<String> {
    vec![
        "ib_send_lat".to_string(),
        "-F".to_string(),
        "-D".to_string(),
        FABRIC_SECONDS.to_string(),
        address.to_string(),
    ]
}

pub fn ib_write_bw_server() -> Vec<String> {
    vec![
        "ib_write_bw".to_string(),
        "-F".to_string(),
        "-D".to_string(),
        FABRIC_SECONDS.to_string(),
    ]
}

pub fn ib_write_bw_client(address: &str) -> Vec<String> {
    vec![
        "ib_write_bw".to_string(),
        "-F".to_string(),
        "-D".to_string(),
        FABRIC_SECONDS.to_string(),
        address.to_string(),
    ]
}

// --- what the three tools say --------------------------------------------
//
// All three print a table with a header and one row of numbers, and the row
// is read BY POSITION with the column count checked. Reading it by header
// name is what one would want and is not possible: perftest's headers hold
// spaces (`BW average[MB/sec]`), so a split on white space does not line up
// with the columns. So: the row is the last line whose every token is a
// number, its length says which tool's row it is, and a row of the wrong
// length is `None` — an `unknown` check with the raw output in it, never a
// number read out of the wrong column.

/// How many round trips `rping -v` reported.
pub fn rping_rounds(text: &str) -> usize {
    text.lines().filter(|l| l.contains("ping data:")).count()
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Latency {
    pub min: f64,
    pub max: f64,
    pub typical: f64,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Bandwidth {
    pub peak: f64,
    pub average: f64,
}

/// The last all-numeric row of a perftest table, as numbers.
fn numeric_row(text: &str) -> Option<Vec<f64>> {
    text.lines()
        .rev()
        .filter_map(|line| {
            let tokens: Vec<&str> = line.split_whitespace().collect();
            if tokens.len() < 4 {
                return None;
            }
            tokens
                .iter()
                .map(|t| t.parse::<f64>().ok())
                .collect::<Option<Vec<f64>>>()
        })
        .next()
}

/// `#bytes #iterations t_min t_max t_typical t_avg t_stdev 99% 99.9%`
pub fn latency_of(text: &str) -> Option<Latency> {
    let row = numeric_row(text)?;
    if row.len() < 5 {
        return None;
    }
    Some(Latency {
        min: row[2],
        max: row[3],
        typical: row[4],
    })
}

/// `#bytes #iterations BW_peak BW_average MsgRate`
pub fn bandwidth_of(text: &str) -> Option<Bandwidth> {
    let row = numeric_row(text)?;
    // Exactly five: a latency row has nine, and reading its `t_typical` as a
    // bandwidth would print a plausible number that means nothing.
    if row.len() != 5 {
        return None;
    }
    Some(Bandwidth {
        peak: row[2],
        average: row[3],
    })
}

// ---------------------------------------------------------------------------
// the guest, and what the control plane answers
// ---------------------------------------------------------------------------

/// How big the one ephemeral disk of a verification guest is.
///
/// Sixteen mebibytes: the guest never writes to it. It exists because the
/// cluster tier refuses a VM without one — "a vm needs at least one volume
/// as boot disk", measured against the throwaway control plane of
/// deploy/chaos/selftest.sh — and a disk that is made and unmade with every
/// guest of every round is a disk worth keeping small.
pub const GUEST_DISK_BYTES: u64 = 16 * 1024 * 1024;

/// The `NewVmSpec` for one guest-tiny.
///
/// Three decisions, each of them measured rather than reasoned about:
///
/// * **The serial console and nothing else.** `nix/packages/guest-tiny.nix`
///   explains why: 8250 is built into the pinned kernel and virtio_console
///   is a module, so a guest that talked over virtio would have to insmod
///   before it could say anything — and the marker line this suite reads is
///   the first thing that guest prints.
/// * **No nic.** A lifecycle suite that needed a bridge would be testing
///   the network driver, which is somebody else's suite — and it would make
///   this one unrunnable on a node without `CAP_NET_ADMIN`.
/// * **One ephemeral disk, and no `desired`.** The cluster tier refuses a
///   VM with neither: `spec.vm.desired is controller-owned; use
///   spec.runStrategy` (422) and `a vm needs at least one volume as boot
///   disk` (422). Both were found by running this against a real control
///   plane and not by reading the type, which is what this whole suite is
///   for.
pub fn tiny_spec(kernel: &GuestTiny) -> Result<Vec<u8>> {
    let spec = serde_json::json!({
        "vcpus": 1,
        "memory_mib": 256,
        "boot": {
            "kind": "direct_kernel",
            "kernel": kernel.kernel,
            "initramfs": kernel.initrd,
            "cmdline": "console=ttyS0 reboot=k panic=1",
        },
        "volumes": [ { "size_bytes": GUEST_DISK_BYTES } ],
    });
    let mut bytes = serde_json::to_vec_pretty(&spec)
        .map_err(|e| anyhow::anyhow!("writing the guest spec as json failed: {e}"))?;
    bytes.push(b'\n');
    Ok(bytes)
}

/// The same guest with one PCI device attached by `vfio`.
pub fn gpu_spec(kernel: &GuestTiny, pci: &str) -> Result<Vec<u8>> {
    let spec = serde_json::json!({
        "vcpus": 1,
        "memory_mib": 512,
        "boot": {
            "kind": "direct_kernel",
            "kernel": kernel.kernel,
            "initramfs": kernel.initrd,
            "cmdline": "console=ttyS0 reboot=k panic=1",
        },
        "volumes": [ { "size_bytes": GUEST_DISK_BYTES } ],
        "devices": [
            { "driver": "vfio", "partition": "exclusive", "params": { "pci_address": pci } }
        ],
    });
    let mut bytes = serde_json::to_vec_pretty(&spec)
        .map_err(|e| anyhow::anyhow!("writing the guest spec as json failed: {e}"))?;
    bytes.push(b'\n');
    Ok(bytes)
}

/// `status.phase` out of whatever `meister vm get -o json` printed.
///
/// Tolerant on purpose: a cli that printed a note before the document, or a
/// document this tool does not fully know, must not turn into a panic in the
/// middle of a run that is holding guests.
pub fn phase_of(text: &str) -> Option<String> {
    let value: serde_json::Value = serde_json::from_str(text.trim()).ok()?;
    value
        .get("status")?
        .get("phase")?
        .as_str()
        .map(str::to_string)
}

/// `spec.nodeName` and `metadata.uid`, out of a created or fetched object.
pub fn placement_of(text: &str) -> (Option<String>, Option<String>) {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(text.trim()) else {
        return (None, None);
    };
    let node = value
        .get("spec")
        .and_then(|s| s.get("nodeName"))
        .and_then(serde_json::Value::as_str)
        .filter(|n| !n.is_empty())
        .map(str::to_string);
    let uid = value
        .get("metadata")
        .and_then(|m| m.get("uid"))
        .and_then(serde_json::Value::as_str)
        .filter(|n| !n.is_empty())
        .map(str::to_string);
    (node, uid)
}

/// Whether `meister vm ls -o json` still has this name.
///
/// An answer that cannot be parsed is treated as "it is there": the caller
/// uses this to decide that a guest is gone, and guessing "gone" from a
/// broken answer is how a leak becomes a green line.
pub fn lists_name(text: &str, name: &str) -> bool {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(text.trim()) else {
        return !text.trim().is_empty();
    };
    let Some(items) = value.get("items").and_then(serde_json::Value::as_array) else {
        return true;
    };
    items.iter().any(|item| {
        item.get("metadata")
            .and_then(|m| m.get("name"))
            .and_then(serde_json::Value::as_str)
            == Some(name)
    })
}

/// Everything the guest printed, out of `meister vm logs -o json`.
pub fn console_text(text: &str) -> String {
    let Ok(streams) = serde_json::from_str::<Vec<serde_json::Value>>(text.trim()) else {
        return text.to_string();
    };
    streams
        .iter()
        .filter_map(|s| s.get("text").and_then(serde_json::Value::as_str))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Whether the console carries this line.
pub fn console_says(text: &str, marker: &str) -> bool {
    console_text(text).contains(marker)
}

/// What a console record looks like, when it does not hold the line that was
/// being looked for.
///
/// The distinction is the difference between `fail` and `unknown`, and it is
/// the whole reason [`crate::checks::Status`] has five values: a guest that
/// printed something else did not boot the way it was supposed to, and a
/// record that stops in the middle of a line says nothing about the guest at
/// all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Record {
    /// Nobody recorded anything.
    Empty,
    /// It ends mid-line, so what is missing is the recording and not the
    /// output: a guest writes whole lines.
    Truncated,
    /// Whole, as far as anything here can tell.
    Whole,
}

pub fn record_of(text: &str) -> Record {
    if text.trim().is_empty() {
        return Record::Empty;
    }
    if text.ends_with('\n') || text.ends_with("\r\n") {
        Record::Whole
    } else {
        Record::Truncated
    }
}

/// Every host of the fleet a suite would look at, in the fleet's own order.
pub fn targets(fleet: &ResolvedFleet, selected: &[String]) -> Vec<String> {
    let known: BTreeSet<&String> = fleet.hosts.keys().collect();
    selected
        .iter()
        .filter(|id| known.contains(id))
        .cloned()
        .collect()
}

/// What `verify` prints for a person, and what `--json` does not need.
pub fn summary(run: &VerifyRun) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "==> verify {} suite {}  release {}\n",
        run.run_id, run.suite, run.release_id
    ));
    out.push_str(&format!(
        "    outcome: {}   {} check(s) over {} host(s)\n",
        run.outcome,
        run.checks.len(),
        run.hosts.len()
    ));
    let (hardware, other) = run.hardware_evidence();
    out.push_str(&format!(
        "    hardware evidence: {} check(s); everything else: {}\n",
        hardware.len(),
        other.len()
    ));
    for check in &run.checks {
        out.push_str(&format!(
            "    {:<16} {:<14} {}\n",
            check.id,
            check.status,
            check
                .subject
                .host
                .as_deref()
                .or(check.subject.resource.as_deref())
                .unwrap_or("the fleet")
        ));
    }
    let outstanding = run.ledger.outstanding();
    if outstanding.is_empty() {
        out.push_str(&format!(
            "    ledger: {} resource(s), all deleted\n",
            run.ledger.resources.len()
        ));
    } else {
        out.push_str(&format!(
            "    ledger: {} resource(s), {} NOT deleted: {}\n",
            run.ledger.resources.len(),
            outstanding.len(),
            outstanding
                .iter()
                .map(|r| r.name.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    out
}

/// One line per step, for `--dry-run`.
pub fn listing(steps: &[Step]) -> String {
    let mut out = String::new();
    for step in steps {
        out.push_str(&format!("{}\t{}\n", step.host, step.what));
    }
    out
}

#[cfg(test)]
mod tests;

// ---------------------------------------------------------------------------
// the report
// ---------------------------------------------------------------------------

pub const REPORT_SCHEMA: &str = "meister-deploy/verify-report/1";

/// What a verification is worth, with the one line drawn that matters.
///
/// `hardware` evidence and everything else are printed apart, in the text
/// and in the json, because a reader who cannot see the boundary will read
/// a mock as a measurement — and `verify --suite gpu` against a strict fake
/// produces exactly the shape of a green GPU report without a GPU having
/// been anywhere near it.
pub fn report_text(run: &VerifyRun) -> String {
    let (hardware, other) = run.hardware_evidence();
    let mut out = String::new();
    out.push_str(&format!(
        "==> verify {}  suite {}  release {}\n",
        run.run_id, run.suite, run.release_id
    ));
    out.push_str(&format!(
        "    outcome: {}   started {}   ended {}\n",
        run.outcome,
        run.started_at.format("%Y-%m-%dT%H:%M:%SZ"),
        run.ended_at.format("%Y-%m-%dT%H:%M:%SZ"),
    ));
    out.push_str(&format!("    hosts: {}\n", run.hosts.join(", ")));

    out.push_str("--- hardware evidence ---\n");
    if hardware.is_empty() {
        out.push_str(
            "    (none. Nothing in this run ran on a machine whose snapshot had the \n\
             \x20    capability it was about, so nothing here is evidence about hardware.)\n",
        );
    } else {
        for check in &hardware {
            out.push_str(&check_line(check));
            for evidence in check
                .evidence
                .iter()
                .filter(|e| e.kind == EvidenceKind::Hardware)
            {
                out.push_str(&format!("        hardware: {}\n", evidence.reference));
            }
        }
    }

    out.push_str("--- everything else ---\n");
    if other.is_empty() {
        out.push_str("    (none)\n");
    } else {
        for check in &other {
            out.push_str(&check_line(check));
        }
    }

    let outstanding = run.ledger.outstanding();
    if outstanding.is_empty() {
        out.push_str(&format!(
            "    ledger: {} resource(s), all deleted\n",
            run.ledger.resources.len()
        ));
    } else {
        out.push_str(&format!(
            "    ledger: {} resource(s), {} NOT deleted: {}\n",
            run.ledger.resources.len(),
            outstanding.len(),
            outstanding
                .iter()
                .map(|r| r.name.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    out
}

fn check_line(check: &CheckResult) -> String {
    format!(
        "    {:<16} {:<14} {:<24} {}\n",
        check.id,
        check.status,
        check
            .subject
            .host
            .as_deref()
            .or(check.subject.resource.as_deref())
            .unwrap_or("the fleet"),
        if check.observed.is_empty() {
            check.reason.as_str()
        } else {
            check.observed.as_str()
        }
    )
}

/// The same split, for a script.
pub fn report_json(run: &VerifyRun) -> serde_json::Value {
    let (hardware, other) = run.hardware_evidence();
    serde_json::json!({
        "schema": REPORT_SCHEMA,
        "run_id": run.run_id,
        "suite": run.suite,
        "release_id": run.release_id,
        "manifest_id": run.manifest_id,
        "started_at": run.started_at,
        "ended_at": run.ended_at,
        "outcome": run.outcome,
        "hosts": run.hosts,
        "hardware_evidence": hardware,
        "other_evidence": other,
        "ledger": run.ledger,
        "blocked": blocking(run),
    })
}

/// The required checks that did not pass, each as the sentence `acceptance`
/// makes of it. Empty is a verification somebody may quote.
pub fn blocking(run: &VerifyRun) -> Vec<String> {
    match crate::checks::acceptance(&run.checks) {
        crate::checks::Acceptance::Accepted => Vec::new(),
        crate::checks::Acceptance::Blocked { reasons } => reasons,
    }
}
