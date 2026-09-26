// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Functional verification through the operator CLI and SSH.
//!
//! VM suites record normal create intent in a persistent ownership ledger,
//! check running state and console output, then verify removal by listing.
//! The GPU refusal probe is an exception: accepted creates are recorded only
//! after the response. RDMA background servers are outside the VM ledger.
//!
//! Checks determine acceptance separately from cleanup. Evidence classification
//! uses observed capabilities, reported placement and an explicit mock flag;
//! missing placement falls back to the requested host. These observations do
//! not prove GPU computation or complete coverage of selected hosts.

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

/// Deadline for one operator CLI command; guest startup has a separate settle window.
pub const CLI_DEADLINE: Duration = Duration::from_secs(60);

/// How long a guest gets to reach a phase, and how often it is asked.
pub const SETTLE: Duration = Duration::from_secs(120);
pub const POLL: Duration = Duration::from_secs(2);

/// Default run deadline.
pub const DEADLINE: Duration = Duration::from_secs(1800);

/// How long ONE fabric measurement may take.
pub const FABRIC_DEADLINE: Duration = Duration::from_secs(120);

/// Number of round trips requested from `rping`.
pub const RPING_ROUNDS: usize = 10;

/// Duration of each perftest measurement, in seconds.
pub const FABRIC_SECONDS: u32 = 5;

/// Default VM lifecycle batch size. Each selected host requests one canary
/// and then this many guests; retained or lost guests can exceed the batch size.
pub const BUDGET: usize = 2;

/// Serial marker emitted by `nix/packages/guest-tiny.nix` and stored in `$out/marker`.
pub const TINY_MARKER: &str = "MS-S0-TINY-OK";

// ---------------------------------------------------------------------------
// the contract
// ---------------------------------------------------------------------------

/// Supported functional suites.
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
    /// Create intent recorded; existence or removal has not yet been resolved.
    Created,
    /// Removal verified by absence from the control-plane listing.
    Deleted,
    /// Removal or its verification failed; the resource may still exist.
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

/// Resource owned by this verification run.
/// `host` starts as the selected host and is updated from scheduler placement
/// when available. VM specifications do not request placement on that host.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Resource {
    pub kind: ResourceKind,
    /// Control-plane UID, when returned by create or get.
    pub id: Option<String>,
    pub name: String,
    /// Selected host initially; replaced by reported placement when available.
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
    /// Run-specific name prefix required by cleanup.
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

    /// Resources not verified deleted, including failed cleanup attempts.
    pub fn outstanding(&self) -> Vec<&Resource> {
        self.resources
            .iter()
            .filter(|r| r.state != ResourceState::Deleted)
            .collect()
    }

    /// Resources not yet processed by cleanup. Lost resources are not retried in this pass.
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
    /// Ledger snapshot at completion; the adjacent ledger file remains the live record.
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

    /// Separate checks with `hardware` evidence from all other evidence kinds.
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
    /// VM lifecycle batch size, normalized to at least one.
    /// This does not cap all live resources across hosts, retained guests or the GPU suite.
    pub budget: usize,
    /// Run deadline checked between work steps; cleanup runs after expiry.
    pub deadline: Duration,
    /// Retain guests for inspection; required cleanup checks remain skipped.
    pub keep: bool,
    /// Operator CLI configuration and optional profile required for control-plane commands.
    pub control: Option<WorkloadControl>,
    /// How long a guest gets to reach a phase.
    pub settle: Duration,
    pub poll: Duration,
    pub cli_deadline: Duration,
    /// Explicit RDMA pairs. Empty selects pairs sharing the first three storage-address octets.
    pub pairs: Vec<(String, String)>,
    /// Deadline for one fabric command.
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

/// Verification coordinator with injected command, file and clock effects.
pub struct Verifier<'a> {
    runner: &'a dyn Runner,
    files: &'a dyn Files,
    clock: &'a dyn Clock,
    cancel: Cancel,
    /// Optional runner for final cleanup, typically unaffected by the run cancellation token.
    cleanup_runner: Option<&'a dyn Runner>,
    /// Selects the cleanup runner during the final cleanup phase.
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
    /// Explicit mock-evidence flag. The runner type is not detected automatically.
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

    /// Cancellation token shared with the CLI interrupt handler.
    pub fn with_cancel(mut self, cancel: Cancel) -> Verifier<'a> {
        self.cancel = cancel;
        self
    }

    /// Use a separate runner for final cleanup so cancellation does not stop its deletes.
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

    /// Mark all results as mock evidence.
    pub fn as_mock(mut self) -> Verifier<'a> {
        self.mock = true;
        self
    }

    /// SSH transport for RDMA pairs; VM suites use the operator control plane.
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

    /// Persist the whole ledger atomically. Normal creates call this before issuing commands;
    /// the GPU refusal probe records an accepted create after its response.
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

    /// Build workstation `meister --config … [-p …] -o json` commands.
    /// Using the operator control plane exercises controller sessions and scheduling.
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

    /// Run checks, attempt cleanup and persist the receipt.
    /// Failed checks are returned in the receipt; setup or persistence errors may return `Err`.
    pub fn run(&mut self) -> Result<VerifyRun> {
        self.state
            .begin_run(self.files, &self.options.run_id.clone())?;
        self.save_ledger()?;

        let outcome = match self.options.suite {
            Suite::VmLifecycle => self.vm_lifecycle(),
            Suite::Gpu => self.gpu(),
            Suite::Rdma => self.rdma(),
        };

        // Attempt cleanup even when a suite returns an error.
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

    /// Check cancellation and the run deadline.
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

    /// Classify evidence using the mock flag, a capability in the supplied node's
    /// observation and whether the step happened. Callers may supply the selected
    /// host when placement is unavailable.
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

    /// Whether `checks.functional` requires this suite on the host.
    /// Optional checks are reported without blocking acceptance.
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

    /// Request lifecycle guests for each applicable selected host.
    /// The scheduler chooses their actual placement.
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
            // Run one canary, then the configured batch.
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

    /// Create a batch, check each guest, then attempt deletion of each resource.
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
            // Attempt deletes even after the run deadline. These still use the current phase runner.
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
                // A failed response may follow a successful create; leave intent for cleanup.
                Ok(false)
            }
        }
    }

    /// Poll until the object says `Running`, or say what it did say.
    fn await_running(&mut self, id: &str, name: &str) -> Result<bool> {
        let started = self.clock.now();
        // Until observed, startup remains unknown, including cancellation before the first poll.
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
                    // Stop polling terminal failure phases.
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

    /// Poll console output for the guest marker.
    /// Recording can attach after the guest boots, so one empty read is inconclusive.
    fn read_console(&mut self, id: &str, name: &str) -> Result<bool> {
        let started = self.clock.now();
        let cmd = self
            .cli(Effect::Read)?
            .arg("vm")
            .arg("logs")
            .arg(name)
            .arg("--lines")
            .arg("200");
        // No console observation leaves an unknown verdict.
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
            // Retained guests produce skipped cleanup checks, blocking required suites.
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

    /// Repeat VFIO guest creation for up to two declared GPUs, then probe invalid-device refusal.
    /// The current guest cannot prove in-guest PCI visibility or GPU computation.
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
            // A reachable host missing the declared VFIO capability fails the check.
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
            // Five rounds exercise repeated attachment and teardown for up to two devices.
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

    /// Return unknown: guest-tiny has no console shell or PCI inspection interface.
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

    /// Request an invalid PCI address. Any nonzero CLI exit currently counts as refusal.
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
                // Only accepted responses are recorded here; failed or lost responses have no ledger entry.
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

    /// Report GPU computation as not applicable for the current guest image.
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

    /// Run ping, latency and bandwidth measurements over SSH for each selected RDMA pair.
    /// Default pairing uses storage-address text, not the configured network prefix.
    fn rdma(&mut self) -> Result<()> {
        let hosts = self.hosts.clone();
        let pairs = self.pairs()?;
        // Report hosts with no applicable RDMA pair before starting measurements.
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
                // Required skipped checks block acceptance.
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

    /// Use explicit pairs, or enumerate selected peers with matching storage-address prefixes.
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
                // Visit unordered pairs once, with the lexicographically smaller ID as server.
                if id < other {
                    out.push((id.clone(), other.clone()));
                }
            }
        }
        Ok(out)
    }

    /// Start the remote server in the background and return its PID.
    /// The caller stops it after the client command; it is not recorded in the VM ledger.
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

    /// Best-effort remote kill; an already-exited process is accepted.
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

    /// Read the server storage-network address; do not substitute its management endpoint.
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

    /// Classify fabric evidence from the observed RDMA capability and mock flag.
    fn fabric_evidence(&self, id: &str) -> EvidenceKind {
        self.evidence_kind(id, "rdma", true)
    }

    // --- cleanup ----------------------------------------------------------

    /// Clean up ledger entries whose names carry this run's tag.
    /// Lost resources are reported but not retried by this pass.
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
            // Record failed removal as lost and continue cleaning up the remaining resources.
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
            // Report the aggregate cleanup result.
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

    /// Request deletion, then poll the listing until the name disappears.
    /// The listing resolves failed deletes, asynchronous teardown and already-absent objects.
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
        lists_name(&out.stdout, name)
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

    /// Read capability presence from the observation snapshot.
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
    /// Reason for non-applicability.
    No(String),
}

/// Determine applicability from manifest roles and declared hardware.
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

/// Group selected hosts with declared RDMA NICs by the first three storage-address octets.
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

/// Textual first-three-octet key. This ignores the configured network prefix and IPv6.
fn network_prefix(address: &str) -> String {
    address.split('.').take(3).collect::<Vec<_>>().join(".")
}

const GPU_ROUNDS: usize = 5;

/// Synthetic PCI address used to test device refusal; absence is not independently probed.
const NO_SUCH_PCI: &str = "ffff:ff:1f.7";

const GPU_PLAN: &str = "two guests with one PCI device each, five times over, then a \
                        create with a device that does not exist (which has to be refused)";

const RDMA_PLAN: &str = "a round trip (rping), a latency (ib_send_lat) and a bandwidth \
                         (ib_write_bw) between each declared pair, server on one end and \
                         client on the other";

// Fabric command builders. Perftest uses its default device because no `-d`
// argument is supplied; the client receives the server storage address.

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

/// `ib_send_lat` server; `-F` allows measurements without fixed CPU frequency.
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

// Parse the last all-numeric perftest row by column position.
// Bandwidth requires five columns; latency accepts at least five.
// The parsers do not validate headers or measurement thresholds.

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
    // Require five bandwidth columns to reject the usual nine-column latency row.
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

/// Ephemeral verification disk size: 16 MiB.
/// The control plane requires a boot volume even when kernel and initrd boot directly.
pub const GUEST_DISK_BYTES: u64 = 16 * 1024 * 1024;

/// Guest-tiny specification: serial console, no NIC, one ephemeral disk.
/// The pinned kernel has built-in 8250 support. Leave controller-owned `desired`
/// unset and request running behavior through `runStrategy`.
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

/// Read `status.phase` from CLI JSON; return unknown for invalid or unsupported output.
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

/// Test name presence in a JSON object's `items` array.
/// Malformed, empty or unsupported output is an error, never proof of deletion.
pub fn lists_name(text: &str, name: &str) -> Result<bool> {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        bail!(
            "the listing answered nothing at all, and an empty answer is not a list that \
             lacks {name}."
        );
    }
    let value = serde_json::from_str::<serde_json::Value>(trimmed).map_err(|e| {
        anyhow::anyhow!(
            "the listing is not json ({e}), so it does not say whether {name} is there: {}",
            last_lines(trimmed)
        )
    })?;
    let Some(items) = value.get("items").and_then(serde_json::Value::as_array) else {
        bail!(
            "the listing carries no `items`, so it does not say whether {name} is there: {}",
            last_lines(trimmed)
        );
    };
    Ok(items.iter().any(|item| {
        item.get("metadata")
            .and_then(|m| m.get("name"))
            .and_then(serde_json::Value::as_str)
            == Some(name)
    }))
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

/// Classify console output without the marker.
/// A trailing newline is the completeness heuristic used to distinguish fail from unknown.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Record {
    /// Nobody recorded anything.
    Empty,
    /// Nonempty output without a trailing newline; treated as incomplete.
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

/// Render hardware-classified checks separately from other evidence.
/// Classification alone does not mean the check passed or covered the intended host.
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

/// Acceptance reasons for required checks that did not pass.
pub fn blocking(run: &VerifyRun) -> Vec<String> {
    match crate::checks::acceptance(&run.checks) {
        crate::checks::Acceptance::Accepted => Vec::new(),
        crate::checks::Acceptance::Blocked { reasons } => reasons,
    }
}
