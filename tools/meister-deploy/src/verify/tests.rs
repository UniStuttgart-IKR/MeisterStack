// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! What a verification does, measured with a strict fake and a fake clock.
//!
//! Two of these tests are about an ORDER rather than a result — the ledger
//! is written before the create, and the cleanup happens whatever else did —
//! so the runner here is a small one of its own that photographs the ledger
//! file at the moment each command goes out. Everything else uses the crate's
//! own [`StrictFake`], which refuses a command nobody expected and fails on
//! an expectation nobody used.

use std::cell::RefCell;

use super::*;
use crate::effects::{FakeClock, MemFiles};
use crate::fixtures::{at, observed, onebox_enrolled, release_of};
use crate::ids::{IdKind, content_id};
use crate::observation::HostObservation;
use crate::release::PackageArtifact;
use crate::run::{Matcher, Output, Policy, StrictFake};

const RUN: &str = "0192f0c0-0000-7000-8000-00000000abcd";
const STORE: &str = "/nix/store/gggggggggggggggggggggggggggggggg-guest-tiny";

fn tag() -> String {
    tag_of(RUN)
}

fn guest(n: usize) -> String {
    format!("{}-{n}", tag())
}

/// A release that carries the guest this suite boots. The fixture's own
/// `release_of` binds no packages, so this adds the one the suite reads and
/// renames the release, because a release whose content changed and whose id
/// did not is one `validate` refuses.
fn release_with_guest() -> ReleaseManifest {
    let mut release = release_of(onebox_enrolled());
    release.packages.insert(
        "guest-tiny".to_string(),
        PackageArtifact {
            store_path: STORE.to_string(),
            nar_hash: "sha256:guest".to_string(),
        },
    );
    release.release_id = content_id(IdKind::Release, &release).expect("a release hashes");
    release
}

fn options(suite: Suite) -> Options {
    let mut options = Options::new(RUN, suite);
    options.budget = 1;
    options.control = Some(WorkloadControl {
        cli_config: "cli.toml".to_string(),
        cli_profile: Some("cloud".to_string()),
    });
    options
}

/// The head of every command line this suite builds.
fn head() -> Vec<String> {
    ["--config", "cli.toml", "-p", "cloud", "-o", "json"]
        .into_iter()
        .map(str::to_string)
        .collect()
}

fn cli_args(rest: &[&str]) -> Vec<String> {
    let mut args = head();
    args.extend(rest.iter().map(|a| a.to_string()));
    args
}

fn created(name: &str, node: &str) -> Output {
    Output::stdout(format!(
        r#"{{"apiVersion":"meister.io/v1","kind":"Vm","metadata":{{"name":"{name}",
           "uid":"uid-of-{name}"}},"spec":{{"nodeName":"{node}"}},"status":{{"phase":"Pending"}}}}"#
    ))
}

fn phase(name: &str, node: &str, phase: &str) -> Output {
    Output::stdout(format!(
        r#"{{"metadata":{{"name":"{name}","uid":"uid-of-{name}"}},
           "spec":{{"nodeName":"{node}"}},"status":{{"phase":"{phase}"}}}}"#
    ))
}

fn console(text: &str) -> Output {
    Output::stdout(format!(r#"[{{"stream":"console","text":"{text}"}}]"#))
}

fn listing(names: &[&str]) -> Output {
    let items: Vec<String> = names
        .iter()
        .map(|n| format!(r#"{{"metadata":{{"name":"{n}"}}}}"#))
        .collect();
    Output::stdout(format!(r#"{{"items":[{}]}}"#, items.join(",")))
}

/// Every expectation of one whole guest that behaves: created, running,
/// says the line, deleted, gone.
fn a_good_guest(fake: StrictFake, name: &str, node: &str) -> StrictFake {
    fake.expect(
        Matcher::prefix("meister", cli_args(&["vm", "create", name, "-f"])),
        created(name, node),
    )
    .expect(
        Matcher::exact("meister", cli_args(&["vm", "get", name])),
        phase(name, node, "Running"),
    )
    .expect(
        Matcher::exact("meister", cli_args(&["vm", "logs", name, "--lines", "200"])),
        console(TINY_MARKER),
    )
    .expect(
        Matcher::exact("meister", {
            let mut args = head();
            args.extend(["--yes", "vm", "rm", name].iter().map(|a| a.to_string()));
            args
        }),
        Output::stdout(""),
    )
    .expect(
        Matcher::exact("meister", cli_args(&["vm", "ls"])),
        listing(&[]),
    )
}

/// The world this suite is pointed at: one agent host, reachable, with kvm.
struct World {
    release: ReleaseManifest,
    observation: Observations,
}

fn world() -> World {
    let release = release_with_guest();
    let observation = observed(&release, at("2026-09-22T19:00:00Z"));
    World {
        release,
        observation,
    }
}

fn state() -> StateDir {
    StateDir::at("/repo/.meister-deploy")
}

fn ledger_path() -> PathBuf {
    state().run_dir(RUN).join("ledger.json")
}

/// A runner that photographs the ledger file every time a command goes out.
///
/// The order "ledger first, then create" cannot be shown by comparing two
/// logs — they are two lists with no common clock — so this takes the one
/// measurement that decides it: what was on the disk at the moment the
/// create was spawned.
struct Watching<'a> {
    inner: &'a StrictFake,
    files: &'a MemFiles,
    seen: RefCell<Vec<(String, Option<Ledger>)>>,
}

impl<'a> Watching<'a> {
    fn new(inner: &'a StrictFake, files: &'a MemFiles) -> Watching<'a> {
        Watching {
            inner,
            files,
            seen: RefCell::new(Vec::new()),
        }
    }

    /// What the ledger said when the command matching this substring ran.
    fn ledger_at(&self, needle: &str) -> Option<Ledger> {
        self.seen
            .borrow()
            .iter()
            .find(|(line, _)| line.contains(needle))
            .and_then(|(_, ledger)| ledger.clone())
    }
}

impl Runner for Watching<'_> {
    fn run(&self, cmd: &Cmd) -> Result<crate::run::Output> {
        let ledger = self.files.content(ledger_path()).and_then(|bytes| {
            Ledger::from_json(&String::from_utf8(bytes).ok()?, "the ledger").ok()
        });
        self.seen.borrow_mut().push((cmd.line(), ledger));
        self.inner.run(cmd)
    }

    fn policy(&self) -> Policy {
        self.inner.policy()
    }
}

// ---------------------------------------------------------------------------

#[test]
fn the_ledger_is_written_before_the_guest_is_asked_for() {
    let world = world();
    let files = MemFiles::new();
    let clock = FakeClock::at(at("2026-09-22T19:00:00Z"));
    let mut fake = StrictFake::new();
    fake = a_good_guest(fake, &guest(1), "n1");
    fake = a_good_guest(fake, &guest(2), "n1");
    let watching = Watching::new(&fake, &files);

    let mut verifier = Verifier::new(
        &watching,
        &files,
        &clock,
        state(),
        &world.release,
        &world.observation,
        vec!["n1".to_string()],
        options(Suite::VmLifecycle),
    )
    .as_mock();
    let run = verifier.run().expect("the suite runs");
    fake.verify().expect("every expectation was used");

    let at_create = watching
        .ledger_at(&format!("vm create {}", guest(1)))
        .expect("the create was seen");
    assert_eq!(
        at_create.resources.len(),
        1,
        "the ledger did not know about the guest when it was asked for"
    );
    assert_eq!(at_create.resources[0].name, guest(1));
    assert_eq!(at_create.resources[0].state, ResourceState::Created);
    assert_eq!(at_create.tag, tag());
    assert_eq!(run.outcome, Outcome::Success);
}

#[test]
fn one_guest_alone_first_and_then_the_budget() {
    let world = world();
    let files = MemFiles::new();
    let clock = FakeClock::at(at("2026-09-22T19:00:00Z"));
    // budget 2: one canary, then two at once, so three guests and three
    // create/delete pairs.
    let mut options = options(Suite::VmLifecycle);
    options.budget = 2;

    let mut fake = StrictFake::new();
    fake = a_good_guest(fake, &guest(1), "n1");
    // The batch: both created, then both read, then both deleted — which is
    // what "two alive at once" means.
    fake = fake
        .expect(
            Matcher::prefix("meister", cli_args(&["vm", "create", &guest(2), "-f"])),
            created(&guest(2), "n1"),
        )
        .expect(
            Matcher::prefix("meister", cli_args(&["vm", "create", &guest(3), "-f"])),
            created(&guest(3), "n1"),
        )
        .expect(
            Matcher::exact("meister", cli_args(&["vm", "get", &guest(2)])),
            phase(&guest(2), "n1", "Running"),
        )
        .expect(
            Matcher::exact(
                "meister",
                cli_args(&["vm", "logs", &guest(2), "--lines", "200"]),
            ),
            console(TINY_MARKER),
        )
        .expect(
            Matcher::exact("meister", cli_args(&["vm", "get", &guest(3)])),
            phase(&guest(3), "n1", "Running"),
        )
        .expect(
            Matcher::exact(
                "meister",
                cli_args(&["vm", "logs", &guest(3), "--lines", "200"]),
            ),
            console(TINY_MARKER),
        );
    for n in [2, 3] {
        let mut rm = head();
        rm.extend(["--yes", "vm", "rm"].iter().map(|a| a.to_string()));
        rm.push(guest(n));
        fake = fake
            .expect(Matcher::exact("meister", rm), Output::stdout(""))
            .expect(
                Matcher::exact("meister", cli_args(&["vm", "ls"])),
                listing(&[]),
            );
    }

    let mut verifier = Verifier::new(
        &fake,
        &files,
        &clock,
        state(),
        &world.release,
        &world.observation,
        vec!["n1".to_string()],
        options,
    )
    .as_mock();
    let run = verifier.run().expect("the suite runs");
    fake.verify().expect("every expectation was used");

    assert_eq!(run.ledger.resources.len(), 3, "{:?}", run.ledger.resources);
    assert!(
        run.ledger
            .resources
            .iter()
            .all(|r| r.state == ResourceState::Deleted),
        "the run went out holding something: {:?}",
        run.ledger.resources
    );
    assert_eq!(run.outcome, Outcome::Success);
}

#[test]
fn a_delete_that_does_not_take_is_lost_and_unknown_and_never_a_pass() {
    let world = world();
    let files = MemFiles::new();
    let clock = FakeClock::at(at("2026-09-22T19:00:00Z"));
    let name = guest(1);
    let mut rm = head();
    rm.extend(["--yes", "vm", "rm"].iter().map(|a| a.to_string()));
    rm.push(name.clone());

    let mut fake = StrictFake::new()
        .expect(
            Matcher::prefix("meister", cli_args(&["vm", "create", &name, "-f"])),
            created(&name, "n1"),
        )
        .expect(
            Matcher::exact("meister", cli_args(&["vm", "get", &name])),
            phase(&name, "n1", "Running"),
        )
        .expect(
            Matcher::exact(
                "meister",
                cli_args(&["vm", "logs", &name, "--lines", "200"]),
            ),
            console(TINY_MARKER),
        )
        .expect(
            Matcher::exact("meister", rm),
            Output::failing(1, "the node refused: still terminating"),
        );
    // The delete failed, so the listing decides — and it keeps saying the
    // guest is there until the settle window runs out.
    for _ in 0..61 {
        fake = fake.expect(
            Matcher::exact("meister", cli_args(&["vm", "ls"])),
            listing(&[&name]),
        );
    }
    // The suite carries on to the second guest of the host: one refusal is
    // not a reason to stop looking at the rest.
    fake = a_good_guest(fake, &guest(2), "n1");

    let mut verifier = Verifier::new(
        &fake,
        &files,
        &clock,
        state(),
        &world.release,
        &world.observation,
        vec!["n1".to_string()],
        options(Suite::VmLifecycle),
    )
    .as_mock();
    let run = verifier.run().expect("the suite runs");

    let lost = run
        .ledger
        .resources
        .iter()
        .find(|r| r.name == name)
        .expect("the guest is in the ledger");
    assert_eq!(lost.state, ResourceState::Lost);
    let delete = run
        .checks
        .iter()
        .find(|c| c.id == "vm.delete" && c.subject.resource.as_deref() == Some(name.as_str()))
        .expect("the delete produced a check");
    assert_eq!(delete.status, Status::Unknown);
    assert!(delete.reason.contains(&name), "{}", delete.reason);
    assert!(
        run.checks.iter().any(|c| c.id == "verify.leftovers"),
        "a run that left something behind said nothing about it"
    );
    assert_ne!(run.outcome, Outcome::Success);
}

#[test]
fn keep_leaves_the_guests_and_says_which() {
    let world = world();
    let files = MemFiles::new();
    let clock = FakeClock::at(at("2026-09-22T19:00:00Z"));
    let mut options = options(Suite::VmLifecycle);
    options.keep = true;

    // Two guests that work, and nothing that removes them: `--keep` is for
    // somebody who wants to look at one, so no `vm rm` and no `vm ls` may
    // appear — a StrictFake turns an attempt into a failure.
    let mut fake = StrictFake::new();
    for n in [1, 2] {
        fake = fake
            .expect(
                Matcher::prefix("meister", cli_args(&["vm", "create", &guest(n), "-f"])),
                created(&guest(n), "n1"),
            )
            .expect(
                Matcher::exact("meister", cli_args(&["vm", "get", &guest(n)])),
                phase(&guest(n), "n1", "Running"),
            )
            .expect(
                Matcher::exact(
                    "meister",
                    cli_args(&["vm", "logs", &guest(n), "--lines", "200"]),
                ),
                console(TINY_MARKER),
            );
    }

    let mut verifier = Verifier::new(
        &fake,
        &files,
        &clock,
        state(),
        &world.release,
        &world.observation,
        vec!["n1".to_string()],
        options,
    )
    .as_mock();
    let run = verifier.run().expect("the suite runs");
    fake.verify().expect("every expectation was used");

    let deletes: Vec<&crate::checks::CheckResult> =
        run.checks.iter().filter(|c| c.id == "vm.delete").collect();
    assert_eq!(deletes.len(), 2);
    assert!(deletes.iter().all(|c| c.status == Status::Skipped));
    let cleanup = run
        .checks
        .iter()
        .find(|c| c.id == "verify.cleanup")
        .expect("--keep says what it kept");
    assert_eq!(cleanup.status, Status::Skipped);
    assert!(cleanup.required, "a leftover has to block");
    assert!(cleanup.reason.contains(&guest(1)), "{}", cleanup.reason);
    assert!(cleanup.reason.contains(&guest(2)), "{}", cleanup.reason);
    assert!(
        run.ledger
            .resources
            .iter()
            .all(|r| r.state == ResourceState::Created),
        "--keep removed something: {:?}",
        run.ledger.resources
    );
    assert_ne!(run.outcome, Outcome::Success);
}

#[test]
fn the_cleanup_will_not_delete_a_name_it_cannot_prove_it_made() {
    let world = world();
    let files = MemFiles::new();
    let clock = FakeClock::at(at("2026-09-22T19:00:00Z"));
    // Nothing is expected of the runner at all: a foreign name must not
    // reach a `vm rm`, and a StrictFake turns an attempt into a failure.
    let fake = StrictFake::new();
    let mut verifier = Verifier::new(
        &fake,
        &files,
        &clock,
        state(),
        &world.release,
        &world.observation,
        vec!["n1".to_string()],
        options(Suite::VmLifecycle),
    )
    .as_mock();
    verifier.ledger.resources.push(Resource {
        kind: ResourceKind::Vm,
        id: None,
        name: "meister-verify-other-1".to_string(),
        host: "n1".to_string(),
        created_at: at("2026-09-22T18:00:00Z"),
        state: ResourceState::Created,
    });
    verifier.cleanup().expect("the cleanup runs");
    fake.verify().expect("nothing was run");

    let refusal = verifier
        .checks
        .iter()
        .find(|c| c.id == "verify.cleanup")
        .expect("it said why");
    assert_eq!(refusal.status, Status::Unknown);
    assert!(
        refusal.observed.contains("meister-verify-other-1"),
        "{}",
        refusal.observed
    );
}

#[test]
fn a_deadline_that_passes_stops_the_run_and_still_takes_the_guests_back() {
    let world = world();
    let files = MemFiles::new();
    let clock = FakeClock::at(at("2026-09-22T19:00:00Z"));
    let mut options = options(Suite::VmLifecycle);
    // One second: the first `await_running` sleep is two, so the second
    // guest of the host is never started.
    options.deadline = Duration::from_secs(1);
    let name = guest(1);
    let mut rm = head();
    rm.extend(["--yes", "vm", "rm"].iter().map(|a| a.to_string()));
    rm.push(name.clone());

    let fake = StrictFake::new()
        .expect(
            Matcher::prefix("meister", cli_args(&["vm", "create", &name, "-f"])),
            created(&name, "n1"),
        )
        .expect(
            Matcher::exact("meister", cli_args(&["vm", "get", &name])),
            phase(&name, "n1", "Pending"),
        )
        .expect(
            Matcher::exact("meister", cli_args(&["vm", "get", &name])),
            phase(&name, "n1", "Running"),
        )
        .expect(
            Matcher::exact(
                "meister",
                cli_args(&["vm", "logs", &name, "--lines", "200"]),
            ),
            console(TINY_MARKER),
        )
        .expect(Matcher::exact("meister", rm), Output::stdout(""))
        .expect(
            Matcher::exact("meister", cli_args(&["vm", "ls"])),
            listing(&[]),
        );

    let mut verifier = Verifier::new(
        &fake,
        &files,
        &clock,
        state(),
        &world.release,
        &world.observation,
        vec!["n1".to_string()],
        options,
    )
    .as_mock();
    let run = verifier.run().expect("the suite runs");
    fake.verify().expect("every expectation was used");

    assert_eq!(run.outcome, Outcome::Aborted);
    assert!(
        run.ledger
            .resources
            .iter()
            .all(|r| r.state == ResourceState::Deleted),
        "a run that ran out of time left something: {:?}",
        run.ledger.resources
    );
    let stopped = run
        .checks
        .iter()
        .find(|c| c.id == "vm-lifecycle.run")
        .expect("it said why it stopped");
    assert!(stopped.reason.contains("budget"), "{}", stopped.reason);
}

/// A runner that pulls the interrupt out from under the run, after the
/// command whose line contains this needle.
struct Interrupting<'a> {
    inner: &'a StrictFake,
    cancel: Cancel,
    after: String,
}

impl Runner for Interrupting<'_> {
    fn run(&self, cmd: &Cmd) -> Result<crate::run::Output> {
        let out = self.inner.run(cmd);
        if cmd.line().contains(&self.after) {
            self.cancel.cancel();
        }
        out
    }

    fn policy(&self) -> Policy {
        self.inner.policy()
    }
}

#[test]
fn an_interrupted_run_deletes_what_it_made_and_is_aborted() {
    let world = world();
    let files = MemFiles::new();
    let clock = FakeClock::at(at("2026-09-22T19:00:00Z"));
    let cancel = Cancel::new();
    let name = guest(1);
    let mut rm = head();
    rm.extend(["--yes", "vm", "rm"].iter().map(|a| a.to_string()));
    rm.push(name.clone());

    // The guest exists — the create returned — and the interrupt arrives
    // with that answer. Everything after it is the way back.
    let fake = StrictFake::new()
        .expect(
            Matcher::prefix("meister", cli_args(&["vm", "create", &name, "-f"])),
            created(&name, "n1"),
        )
        .expect(Matcher::exact("meister", rm), Output::stdout(""))
        .expect(
            Matcher::exact("meister", cli_args(&["vm", "ls"])),
            listing(&[]),
        );
    let interrupting = Interrupting {
        inner: &fake,
        cancel: cancel.clone(),
        after: format!("vm create {name}"),
    };

    let mut verifier = Verifier::new(
        &interrupting,
        &files,
        &clock,
        state(),
        &world.release,
        &world.observation,
        vec!["n1".to_string()],
        options(Suite::VmLifecycle),
    )
    .as_mock()
    .with_cancel(cancel);
    let run = verifier.run().expect("the suite runs");
    fake.verify().expect("every expectation was used");

    assert_eq!(run.outcome, Outcome::Aborted);
    assert_eq!(run.ledger.resources.len(), 1);
    assert_eq!(
        run.ledger.resources[0].state,
        ResourceState::Deleted,
        "an interrupted run kept a guest"
    );
    let stopped = run
        .checks
        .iter()
        .find(|c| c.id == "vm-lifecycle.run")
        .expect("it said why it stopped");
    assert!(stopped.reason.contains("interrupted"), "{}", stopped.reason);
}

#[test]
fn evidence_is_hardware_only_where_the_snapshot_measured_the_capability() {
    let world = world();
    let files = MemFiles::new();
    let clock = FakeClock::at(at("2026-09-22T19:00:00Z"));
    let mut fake = StrictFake::new();
    fake = a_good_guest(fake, &guest(1), "n1");
    fake = a_good_guest(fake, &guest(2), "n1");

    let mut verifier = Verifier::new(
        &fake,
        &files,
        &clock,
        state(),
        &world.release,
        &world.observation,
        vec!["n1".to_string()],
        options(Suite::VmLifecycle),
    );
    let run = verifier.run().expect("the suite runs");
    fake.verify().expect("every expectation was used");

    // The fixture's snapshot measured `kvm` on n1, and the runner was not
    // declared a mock, so the guest is hardware evidence.
    let (hardware, _) = run.hardware_evidence();
    assert!(
        hardware.iter().any(|c| c.id == "vm.running"),
        "a guest that ran on a machine with /dev/kvm is hardware evidence"
    );
}

#[test]
fn a_run_answered_by_a_fake_is_a_mock_and_never_hardware() {
    let world = world();
    let files = MemFiles::new();
    let clock = FakeClock::at(at("2026-09-22T19:00:00Z"));
    let mut fake = StrictFake::new();
    fake = a_good_guest(fake, &guest(1), "n1");
    fake = a_good_guest(fake, &guest(2), "n1");

    let mut verifier = Verifier::new(
        &fake,
        &files,
        &clock,
        state(),
        &world.release,
        &world.observation,
        vec!["n1".to_string()],
        options(Suite::VmLifecycle),
    )
    .as_mock();
    let run = verifier.run().expect("the suite runs");
    fake.verify().expect("every expectation was used");

    let (hardware, _) = run.hardware_evidence();
    assert!(
        hardware.is_empty(),
        "a mock claimed to be hardware: {:?}",
        hardware.iter().map(|c| &c.id).collect::<Vec<_>>()
    );
    assert!(
        run.checks
            .iter()
            .flat_map(|c| &c.evidence)
            .all(|e| e.kind == EvidenceKind::Mock),
        "not every piece of evidence of a fake run says mock"
    );
}

#[test]
fn a_host_that_runs_no_guests_is_not_applicable_and_does_not_block() {
    let world = world();
    let files = MemFiles::new();
    let clock = FakeClock::at(at("2026-09-22T19:00:00Z"));
    let fake = StrictFake::new();
    let mut fleet = world.release.resolved_fleet.clone();
    fleet
        .hosts
        .get_mut("n1")
        .expect("n1 is in the fixture")
        .roles = vec!["addons".to_string()];
    fleet.manifest_id = content_id(IdKind::Manifest, &fleet).expect("a manifest hashes");
    let release = {
        let mut release = world.release.clone();
        release.resolved_fleet = fleet;
        release
    };

    let mut verifier = Verifier::new(
        &fake,
        &files,
        &clock,
        state(),
        &release,
        &world.observation,
        vec!["n1".to_string()],
        options(Suite::VmLifecycle),
    )
    .as_mock();
    let run = verifier.run().expect("the suite runs");
    fake.verify().expect("nothing was run");

    let check = &run.checks[0];
    assert_eq!(check.status, Status::NotApplicable);
    assert!(check.reason.contains("no agent role"), "{}", check.reason);
    assert!(crate::checks::acceptance(&run.checks).is_accepted());
}

#[test]
fn a_declared_host_that_does_not_answer_is_skipped_and_a_required_skip_blocks() {
    let world = world();
    let files = MemFiles::new();
    let clock = FakeClock::at(at("2026-09-22T19:00:00Z"));
    let fake = StrictFake::new();
    let mut observation = world.observation.clone();
    // `box` is the fixture's host whose `checks.functional` names
    // vm-lifecycle, so its verdict is a required one.
    observation.hosts.insert(
        "box".to_string(),
        HostObservation::unreachable("no route to host"),
    );

    let mut verifier = Verifier::new(
        &fake,
        &files,
        &clock,
        state(),
        &world.release,
        &observation,
        vec!["box".to_string()],
        options(Suite::VmLifecycle),
    )
    .as_mock();
    let run = verifier.run().expect("the suite runs");
    fake.verify().expect("nothing was run");

    let check = &run.checks[0];
    assert_eq!(check.status, Status::Skipped);
    assert!(check.required, "the inventory names this suite for box");
    assert!(
        check.reason.contains("not the same as it having passed"),
        "{}",
        check.reason
    );
    match crate::checks::acceptance(&run.checks) {
        crate::checks::Acceptance::Blocked { reasons } => {
            assert!(reasons[0].contains("vm-lifecycle on box"), "{reasons:?}")
        }
        crate::checks::Acceptance::Accepted => panic!("a required skip has to block (V22)"),
    }
}

#[test]
fn a_fleet_without_gpus_answers_not_applicable_with_the_reason() {
    let world = world();
    let files = MemFiles::new();
    let clock = FakeClock::at(at("2026-09-22T19:00:00Z"));
    let fake = StrictFake::new();

    let mut verifier = Verifier::new(
        &fake,
        &files,
        &clock,
        state(),
        &world.release,
        &world.observation,
        vec!["n1".to_string(), "box".to_string()],
        options(Suite::Gpu),
    )
    .as_mock();
    let run = verifier.run().expect("the suite runs");
    fake.verify().expect("nothing was run");

    assert_eq!(run.checks.len(), 2);
    for check in &run.checks {
        assert_eq!(check.status, Status::NotApplicable);
        assert!(
            check.reason.contains("no hardware.gpus"),
            "{}",
            check.reason
        );
    }
    assert!(crate::checks::acceptance(&run.checks).is_accepted());
    assert_eq!(run.outcome, Outcome::Success);
}

#[test]
fn a_gpu_host_that_declares_no_vfio_capability_is_not_applicable() {
    let mut fleet = onebox_enrolled();
    let host = fleet.hosts.get_mut("n1").expect("n1 is in the fixture");
    host.hardware.gpus = vec![crate::manifest::Gpu {
        model: "NVIDIA RTX 2070".to_string(),
        pci: "0000:01:00.0".to_string(),
        selected_for: None,
    }];
    let answer = applicability(Suite::Gpu, &fleet, "n1", &fleet.hosts["n1"]);
    match answer {
        Applicability::No(reason) => {
            assert!(reason.contains("not the vfio capability"), "{reason}")
        }
        Applicability::Yes => panic!("a GPU without the capability is not a passthrough host"),
    }
}

#[test]
fn a_gpu_host_that_declares_everything_and_measures_nothing_fails_rather_than_skips() {
    let mut fleet = onebox_enrolled();
    {
        let host = fleet.hosts.get_mut("n1").expect("n1 is in the fixture");
        host.hardware.gpus = vec![crate::manifest::Gpu {
            model: "NVIDIA RTX 2070".to_string(),
            pci: "0000:01:00.0".to_string(),
            selected_for: None,
        }];
        host.hardware.capabilities.push("vfio".to_string());
    }
    fleet.manifest_id = content_id(IdKind::Manifest, &fleet).expect("a manifest hashes");
    let mut release = release_with_guest();
    release.resolved_fleet = fleet;
    // The snapshot has kvm and NOT vfio: the fixture's `observed` copies the
    // declared capabilities, so this takes it back out to make the point.
    let mut observation = observed(&release, at("2026-09-22T19:00:00Z"));
    observation
        .hosts
        .get_mut("n1")
        .expect("n1 was observed")
        .capabilities = vec!["kvm".to_string()];

    let files = MemFiles::new();
    let clock = FakeClock::at(at("2026-09-22T19:00:00Z"));
    let fake = StrictFake::new();
    let mut verifier = Verifier::new(
        &fake,
        &files,
        &clock,
        state(),
        &release,
        &observation,
        vec!["n1".to_string()],
        options(Suite::Gpu),
    )
    .as_mock();
    let run = verifier.run().expect("the suite runs");
    fake.verify().expect("nothing was started");

    let check = &run.checks[0];
    assert_eq!(check.status, Status::Fail);
    assert!(check.observed.contains("no vfio"), "{}", check.observed);
}

#[test]
fn rdma_is_not_applicable_where_nothing_declares_it() {
    let world = world();
    let files = MemFiles::new();
    let clock = FakeClock::at(at("2026-09-22T19:00:00Z"));
    let fake = StrictFake::new();
    let mut verifier = Verifier::new(
        &fake,
        &files,
        &clock,
        state(),
        &world.release,
        &world.observation,
        vec!["n1".to_string(), "n2".to_string()],
        options(Suite::Rdma),
    )
    .as_mock();
    let run = verifier.run().expect("the suite runs");
    fake.verify().expect("nothing was run");

    for check in &run.checks {
        assert_eq!(check.status, Status::NotApplicable);
        assert!(check.reason.contains("rdma = true"), "{}", check.reason);
    }
}

#[test]
fn an_rdma_peer_is_a_declared_one_and_never_an_assumed_one() {
    let mut fleet = onebox_enrolled();
    for (id, last) in [("n1", 11u8), ("n2", 12u8)] {
        let host = fleet.hosts.get_mut(id).expect("the fixture has it");
        host.hardware.nics.push(crate::manifest::Nic {
            name: "mlx0".to_string(),
            mac: format!("b8:ce:f6:00:00:{last:02x}"),
            role: "storage".to_string(),
            rdma: true,
        });
        host.networks.storage = Some(crate::manifest::Network {
            address: format!("10.200.0.{last}"),
            prefix: 24,
            interface: Some("mlx0".to_string()),
            gateway: None,
        });
    }
    // `box` declares an rdma nic on a DIFFERENT storage network, so it is
    // nobody's peer here.
    {
        let host = fleet.hosts.get_mut("box").expect("the fixture has it");
        host.hardware.nics.push(crate::manifest::Nic {
            name: "mlx0".to_string(),
            mac: "b8:ce:f6:00:00:10".to_string(),
            role: "storage".to_string(),
            rdma: true,
        });
        host.networks.storage = Some(crate::manifest::Network {
            address: "10.201.0.10".to_string(),
            prefix: 24,
            interface: Some("mlx0".to_string()),
            gateway: None,
        });
    }
    let hosts: Vec<String> = vec!["box".to_string(), "n1".to_string(), "n2".to_string()];
    let peers = rdma_peers(&fleet, &hosts);
    assert_eq!(peers["n1"], vec!["n2".to_string()]);
    assert_eq!(peers["n2"], vec!["n1".to_string()]);
    assert!(peers["box"].is_empty(), "{:?}", peers["box"]);
}

#[test]
fn a_ledger_and_a_verification_read_back_as_themselves() {
    let ledger = Ledger {
        schema: LEDGER_SCHEMA.to_string(),
        run_id: RUN.to_string(),
        release_id: "release-abc".to_string(),
        suite: Suite::VmLifecycle,
        tag: tag(),
        started_at: at("2026-09-22T19:00:00Z"),
        resources: vec![Resource {
            kind: ResourceKind::Vm,
            id: Some("uid-1".to_string()),
            name: guest(1),
            host: "n1".to_string(),
            created_at: at("2026-09-22T19:00:01Z"),
            state: ResourceState::Deleted,
        }],
    };
    let text = String::from_utf8(ledger.to_json().unwrap()).unwrap();
    assert_eq!(Ledger::from_json(&text, "a ledger").unwrap(), ledger);
    assert!(text.contains(r#""state": "deleted""#), "{text}");
    assert!(text.contains(r#""suite": "vm-lifecycle""#), "{text}");

    let run = VerifyRun {
        schema: VERIFY_SCHEMA.to_string(),
        run_id: RUN.to_string(),
        release_id: "release-abc".to_string(),
        manifest_id: "manifest-abc".to_string(),
        suite: Suite::Gpu,
        started_at: at("2026-09-22T19:00:00Z"),
        ended_at: at("2026-09-22T19:05:00Z"),
        outcome: Outcome::Success,
        hosts: vec!["n1".to_string()],
        checks: Vec::new(),
        ledger,
        ledger_path: "/repo/.meister-deploy/runs/x/ledger.json".to_string(),
    };
    let text = String::from_utf8(run.to_json().unwrap()).unwrap();
    assert_eq!(VerifyRun::from_json(&text, "a verification").unwrap(), run);
}

#[test]
fn a_field_nobody_declared_is_refused_by_the_ledger() {
    let text = r#"{"schema":"meister-deploy/verify-ledger/1","run_id":"x","release_id":"y",
        "suite":"gpu","tag":"meister-verify-x","started_at":"2026-09-22T19:00:00Z",
        "resources":[],"leftovers":[]}"#;
    let err = Ledger::from_json(text, "a ledger").unwrap_err().to_string();
    assert!(err.contains("unknown field `leftovers`"), "{err}");
}

#[test]
fn a_ledger_of_another_schema_is_a_sentence_and_not_a_guess() {
    let text = r#"{"schema":"meister-deploy/verify-ledger/2","run_id":"x","release_id":"y",
        "suite":"gpu","tag":"meister-verify-x","started_at":"2026-09-22T19:00:00Z",
        "resources":[]}"#;
    let err = Ledger::from_json(text, "a ledger").unwrap_err().to_string();
    assert!(err.contains("verify-ledger/2"), "{err}");
    assert!(err.contains("verify-ledger/1"), "{err}");
}

#[test]
fn a_suite_nobody_has_is_a_sentence() {
    let err = Suite::parse("vm-lifecyle").unwrap_err().to_string();
    assert!(err.contains("vm-lifecycle"), "{err}");
    assert!(err.contains("readiness"), "{err}");
}

#[test]
fn the_steps_of_a_dry_run_name_every_guest_and_create_nothing() {
    let world = world();
    let files = MemFiles::new().with_policy(Policy::dry_run());
    let clock = FakeClock::at(at("2026-09-22T19:00:00Z"));
    let fake = StrictFake::new().with_policy(Policy::dry_run());
    let verifier = Verifier::new(
        &fake,
        &files,
        &clock,
        state(),
        &world.release,
        &world.observation,
        vec!["n1".to_string(), "box".to_string()],
        options(Suite::VmLifecycle),
    );
    let steps = verifier.steps();
    assert_eq!(steps.len(), 4, "{steps:?}");
    assert!(steps.iter().all(|s| s.what.contains(TINY_MARKER)));
    assert!(files.attempts().is_empty(), "{:?}", files.attempts());
    assert!(fake.calls().is_empty(), "{:?}", fake.calls());
    fake.verify().expect("nothing was expected and nothing ran");
}

#[test]
fn without_the_operator_cli_reference_nothing_is_created() {
    let world = world();
    let files = MemFiles::new();
    let clock = FakeClock::at(at("2026-09-22T19:00:00Z"));
    let fake = StrictFake::new();
    let mut options = options(Suite::VmLifecycle);
    options.control = None;

    let mut verifier = Verifier::new(
        &fake,
        &files,
        &clock,
        state(),
        &world.release,
        &world.observation,
        vec!["n1".to_string()],
        options,
    )
    .as_mock();
    let run = verifier.run().expect("the suite answers");
    fake.verify().expect("nothing was run");

    let stopped = run
        .checks
        .iter()
        .find(|c| c.id == "vm-lifecycle.run")
        .expect("it said why");
    assert_eq!(stopped.status, Status::Unknown);
    assert!(stopped.reason.contains("cli_config"), "{}", stopped.reason);
    assert_eq!(run.outcome, Outcome::Aborted);
    // The ledger is the whole point of the order: the guest was written
    // down, nothing was created, and the cleanup says it could not even ask.
    assert_eq!(run.ledger.resources.len(), 1);
    assert_eq!(run.ledger.resources[0].state, ResourceState::Lost);
    let cleanup = run
        .checks
        .iter()
        .find(|c| c.id == "verify.cleanup")
        .expect("the cleanup said what it could not do");
    assert_eq!(cleanup.status, Status::Unknown);
    assert!(
        cleanup.observed.contains("could not even be asked for"),
        "{}",
        cleanup.observed
    );
}

#[test]
fn the_guest_spec_is_the_one_the_package_builds() {
    let spec = tiny_spec(&GuestTiny {
        kernel: format!("{STORE}/bzImage"),
        initrd: format!("{STORE}/initrd"),
    })
    .unwrap();
    let value: serde_json::Value = serde_json::from_slice(&spec).unwrap();
    assert_eq!(value["boot"]["kind"], "direct_kernel");
    assert_eq!(value["boot"]["kernel"], format!("{STORE}/bzImage"));
    assert_eq!(value["boot"]["initramfs"], format!("{STORE}/initrd"));
    // The serial console, because guest-tiny's marker is written there and
    // virtio_console is a module in the pinned kernel.
    assert!(
        value["boot"]["cmdline"]
            .as_str()
            .unwrap()
            .contains("console=ttyS0")
    );
    assert!(value.get("nics").is_none(), "a lifecycle guest has no nic");

    let gpu = gpu_spec(
        &GuestTiny {
            kernel: format!("{STORE}/bzImage"),
            initrd: format!("{STORE}/initrd"),
        },
        "0000:41:00.0",
    )
    .unwrap();
    let value: serde_json::Value = serde_json::from_slice(&gpu).unwrap();
    assert_eq!(value["devices"][0]["driver"], "vfio");
    assert_eq!(value["devices"][0]["partition"], "exclusive");
    assert_eq!(value["devices"][0]["params"]["pci_address"], "0000:41:00.0");
}

#[test]
fn an_answer_that_cannot_be_read_is_never_read_as_gone() {
    assert!(lists_name(r#"{"items":[{"metadata":{"name":"a"}}]}"#, "a"));
    assert!(!lists_name(r#"{"items":[]}"#, "a"));
    // Not json, and not empty: something answered and nobody understood it.
    assert!(lists_name("Error: the cluster is not reachable", "a"));
    // Nothing at all: the listing is empty, which is an answer.
    assert!(!lists_name("", "a"));
    // A document without `items` is one this tool does not know, and
    // guessing "gone" from it is how a leak becomes a green line.
    assert!(lists_name(r#"{"kind":"Status","code":500}"#, "a"));
}

#[test]
fn the_console_is_read_out_of_every_stream() {
    let text = r#"[{"stream":"serial","text":"boot"},{"stream":"console","text":"MS-S0-TINY-OK"}]"#;
    assert!(console_says(text, TINY_MARKER));
    assert!(!console_says(
        r#"[{"stream":"serial","text":"boot"}]"#,
        TINY_MARKER
    ));
    // A cli that printed something else entirely is searched as plain text
    // rather than treated as an empty console.
    assert!(console_says("MS-S0-TINY-OK\n", TINY_MARKER));
}

#[test]
fn the_placement_is_read_back_out_of_the_object() {
    let text = r#"{"metadata":{"uid":"u1","name":"g"},"spec":{"nodeName":"n1"},
                   "status":{"phase":"Running"}}"#;
    assert_eq!(
        placement_of(text),
        (Some("n1".to_string()), Some("u1".to_string()))
    );
    assert_eq!(phase_of(text).as_deref(), Some("Running"));
    // An object the scheduler has not touched yet has no node, and that is
    // not an error.
    assert_eq!(placement_of(r#"{"spec":{}}"#), (None, None));
    assert_eq!(phase_of("not json"), None);
}
