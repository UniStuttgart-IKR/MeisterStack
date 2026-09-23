// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Seventy hosts through the reading half of `apply`, in the strict fake.
//!
//! `tests/plan_fleet70.rs` measures the planner, which does no i/o at all.
//! This measures the two things a rollout over seventy hosts actually
//! spends its wall clock on before it touches anything: asking every host
//! (one ssh-keygen and one ssh each, in a bounded pool) and re-deciding
//! whether the plan still matches what came back. Those two are exactly
//! what `apply --dry-run` is.
//!
//! The runner is the strict fake, so "it only reads" is not a claim: an
//! unexpected command is an error and an expectation nobody used is an
//! error, and the test says how many commands there were and what they
//! were.
//!
//! The numbers this prints are the ones in the lane report. They are CPU
//! and parsing only — the fake answers at once, and a real fleet answers
//! over a network. That is said in the report too, because it is the half
//! that decides whether seventy hosts need parallelism, and it is not this
//! test that can measure it.

mod support;

use std::collections::BTreeMap;
use std::time::Instant;

use meister_deploy::manifest::ResolvedFleet;
use meister_deploy::observation::Observations;
use meister_deploy::observe::{
    DEFAULT_CONCURRENCY, HostProbe, ProbeSpec, SshProber, observe_fleet,
};
use meister_deploy::plan::{
    DeploymentPlan, PlanKind, PlanPolicy, Verdict, WorkloadControl, plan, validate_against,
};
use meister_deploy::release::ReleaseManifest;
use meister_deploy::run::{Matcher, Output, StrictFake};
use meister_deploy::transport::{Ssh, Target, fingerprint_of};

use support::{at, fleet70, observed, probe_answer, release_of, with_new_systems};

const TAKEN: &str = "2026-09-21T11:59:00Z";
const NOW: &str = "2026-09-21T12:00:00Z";
const KNOWN_HOSTS: &str = "/repo/known_hosts";

/// One line of a `known_hosts` file, as `ssh-keygen -F` prints it. The blob
/// is not a real key and does not have to be: what is measured here is that
/// the fingerprint the fleet enrolled and the fingerprint that answers are
/// computed by the same function from the same bytes.
const KEY_LINE: &str =
    "host ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEr0hJk1vDqf9L0ZQ2cWv7c8rHcYxr0kTfQnpS3bJmQx";

/// The seventy-host fleet with every host enrolled against [`KEY_LINE`].
fn enrolled() -> ResolvedFleet {
    let mut fleet = fleet70();
    let fingerprint = fingerprint_of(KEY_LINE).expect("the line is a key line");
    for host in fleet.hosts.values_mut() {
        host.ssh.host_key_fingerprint = Some(fingerprint.clone());
    }
    fleet
}

fn policy() -> PlanPolicy {
    PlanPolicy::new(PlanKind::Upgrade).with_workload_control(Some(WorkloadControl {
        cli_config: "cli.toml".to_string(),
        cli_profile: Some("cloud-mtls".to_string()),
    }))
}

/// Every host of the fleet answering as the machine that runs `running`.
fn fleet_that_answers(base: &ResolvedFleet, running: &ReleaseManifest, ssh: &Ssh) -> StrictFake {
    let mut fake = StrictFake::new();
    for (id, host) in &base.hosts {
        let target = Target::new(id, &host.address, host.ssh.port, &host.ssh.user);
        fake = fake.expect(
            Matcher::exact(
                "ssh-keygen",
                ["-F", &target.known_hosts_name(), "-f", KNOWN_HOSTS],
            ),
            Output::stdout(KEY_LINE),
        );
        let mut argv = ssh.opts(host.ssh.port);
        argv.push(format!("{}@{}", host.ssh.user, host.address));
        fake = fake.expect(
            Matcher::prefix("ssh", argv),
            Output::stdout(probe_answer(base, running, id)),
        );
    }
    fake
}

/// How many hosts each wave carries.
fn wave_sizes(plan: &DeploymentPlan) -> Vec<usize> {
    let mut per_wave: BTreeMap<u32, std::collections::BTreeSet<&str>> = BTreeMap::new();
    for action in &plan.actions {
        if action.is_blocked() {
            continue;
        }
        if plan.hosts[&action.host].verdict != meister_deploy::plan::HostVerdict::Change {
            continue;
        }
        per_wave
            .entry(action.wave)
            .or_default()
            .insert(action.host.as_str());
    }
    per_wave.values().map(|hosts| hosts.len()).collect()
}

#[test]
fn seventy_hosts_are_asked_once_each_and_nothing_else_is_run() {
    let base = enrolled();
    let running = release_of(base.clone());
    let changed: Vec<String> = base.hosts.keys().cloned().collect();
    let release = with_new_systems(base.clone(), &changed, false);

    let ssh = Ssh::with_known_hosts(KNOWN_HOSTS);
    let fake = fleet_that_answers(&base, &running, &ssh);
    let prober = SshProber::new(&fake, &ssh);
    let probes: Vec<HostProbe> = base
        .hosts
        .iter()
        .map(|(id, host)| {
            HostProbe::new(
                Target::new(id, &host.address, host.ssh.port, &host.ssh.user),
                ProbeSpec::for_host(host),
            )
        })
        .collect();

    // A pool of ONE, and that is a property of the fake and not of the
    // tool: `StrictFake` is a SEQUENCE — the expectation at the front has
    // to be the command that comes — so eight threads asking at once would
    // make this test about thread scheduling. The tool asks
    // `DEFAULT_CONCURRENCY` ({DEFAULT_CONCURRENCY}) at a time, and what the
    // pool buys is latency, which a fake that answers instantly cannot
    // show. So this number is the PARSING cost of seventy answers.
    let started = Instant::now();
    let fresh = observe_fleet(&prober, &probes, at(TAKEN), 1).expect("seventy hosts answer");
    let observing = started.elapsed();

    assert_eq!(fresh.hosts.len(), 70);
    for (id, obs) in &fresh.hosts {
        assert!(obs.reachable, "{id} did not answer");
        assert_eq!(obs.unknown_reason, None, "{id}: {:?}", obs.unknown_reason);
    }
    // The strict half: two commands per host and not one more, and every
    // expectation was used. `verify` is what turns "it did not crash" into
    // "these were the commands".
    let calls = fake.calls();
    assert_eq!(calls.len(), 140, "two reads per host");
    assert!(
        calls
            .iter()
            .all(|c| c.starts_with("ssh ") || c.starts_with("ssh-keygen ")),
        "a read-only round ran something else"
    );
    fake.verify()
        .expect("every expectation was used exactly once");

    // And then the two decisions that `apply --dry-run` is made of.
    let started = Instant::now();
    let the_plan = plan(&release, "all", &fresh, None, &policy(), at(NOW)).expect("it plans");
    let planning = started.elapsed();

    let started = Instant::now();
    let verdict = validate_against(&the_plan, &release, &fresh, at(NOW));
    let validating = started.elapsed();
    assert_eq!(verdict, Verdict::Proceed, "{verdict:?}");

    let sizes = wave_sizes(&the_plan);
    println!(
        "seventy hosts: observe {observing:?} (140 reads, parsed serially; the tool asks \
         {DEFAULT_CONCURRENCY} at a time), plan {planning:?}, validate {validating:?}"
    );
    println!(
        "waves: {}, hosts per wave {:?}, widest {}",
        sizes.len(),
        sizes,
        sizes.iter().copied().max().unwrap_or(0)
    );
    println!(
        "actions: {} over {} host(s)",
        the_plan.actions.len(),
        the_plan.selection.targets.len()
    );
}

#[test]
fn a_fleet_that_moved_under_the_plan_is_stopped_and_not_rolled() {
    // The other half of what `--dry-run` answers, over seventy hosts: it
    // re-decides against what came back, so a fleet that moved says so
    // before a lock is taken rather than in the middle of wave nine.
    let base = enrolled();
    let running = release_of(base.clone());
    let observation: Observations = observed(&running, at(TAKEN));
    let changed: Vec<String> = base.hosts.keys().cloned().collect();
    let release = with_new_systems(base.clone(), &changed, false);
    let the_plan = plan(&release, "all", &observation, None, &policy(), at(NOW)).expect("it plans");

    // One machine was reinstalled between the plan and the run.
    let mut fresh = observation.clone();
    fresh.hosts.get_mut("agent-01").unwrap().identity.machine_id =
        Some("a-different-installation".to_string());
    let verdict = validate_against(&the_plan, &release, &fresh, at(NOW));
    match verdict {
        Verdict::Stop { reasons } => {
            let said = reasons.join(" ");
            assert!(said.contains("agent-01"), "{said}");
        }
        other => panic!("a fleet that moved is not {other:?}"),
    }
}
