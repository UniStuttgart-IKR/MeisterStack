// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! What a rollout does, pinned command by command.
//!
//! The runner is the strict fake: an unexpected command is an error and an
//! expectation nobody used is an error. So these tests are not "the code ran
//! and did not fall over" — they are the command lines a machine would have
//! received, in order, and the journal that was written around them.
//!
//! Two pieces of scaffolding, and both exist for the same reason: a test
//! about an ORDER must not be a test about a parser or about how many times
//! somebody looked.
//!
//! * [`World`] wraps the strict fake and moves the fleet the way the command
//!   that just ran would have moved it — an `activate` puts the host on the
//!   new system, a `revert` puts it back, a reboot takes it away for two
//!   looks. So an observation is a consequence rather than a number of
//!   entries in a queue somebody has to keep in step with the code.
//! * [`TableLook`] is the [`Look`] of that world.

use super::*;

use std::cell::RefCell;

use crate::effects::{FakeClock, MemFiles};
use crate::fixtures::{at, observed, onebox_enrolled, release_of, with_new_systems};
use crate::manifest::ResolvedHost;
use crate::observation::{BootedKernel, Txn, TxnState};
use crate::plan::{PlanKind, WorkloadControl, plan};
use crate::receipt::{HostOutcome, JournalEvent, Outcome, parse_journal};
use crate::run::{Matcher, Output, Policy, StrictFake};

const NOW: &str = "2026-09-22T12:00:00Z";

/// Where a host is in this test's world.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    /// Running what it ran when the plan was made.
    Before,
    /// Running what the release says.
    After,
    /// Away, for this many more looks, and then `After`.
    Down(u32),
    /// Away, for this many more looks, and then `Before` — a machine that
    /// rebooted into its previous generation.
    ComingBack(u32),
}

/// The fleet as this test believes it to be.
struct TableLook {
    before: BTreeMap<String, HostObservation>,
    after: BTreeMap<String, HostObservation>,
    phase: RefCell<BTreeMap<String, Phase>>,
    /// Hosts whose new system has a unit that did not come up.
    broken: RefCell<BTreeSet<String>>,
    /// The transaction each host holds, as `meister-activate status` would
    /// report it.
    txns: RefCell<BTreeMap<String, Txn>>,
    /// Hosts that never come back from their reboot.
    lost: RefCell<BTreeSet<String>>,
    asked: RefCell<Vec<String>>,
}

impl TableLook {
    fn new(fx: &Fixture) -> TableLook {
        let mut before = BTreeMap::new();
        let mut after = BTreeMap::new();
        for id in fx.plan.observation.hosts.keys() {
            before.insert(id.clone(), fx.seen(id));
            after.insert(id.clone(), fx.moved(id));
        }
        TableLook {
            before,
            after,
            phase: RefCell::new(BTreeMap::new()),
            broken: RefCell::new(BTreeSet::new()),
            txns: RefCell::new(BTreeMap::new()),
            lost: RefCell::new(BTreeSet::new()),
            asked: RefCell::new(Vec::new()),
        }
    }

    /// The new system of this host comes up with a unit that failed.
    fn breaks(self, id: &str) -> TableLook {
        self.broken.borrow_mut().insert(id.to_string());
        self
    }

    /// This host is told to reboot and never comes back.
    fn never_returns(self, id: &str) -> TableLook {
        self.lost.borrow_mut().insert(id.to_string());
        self
    }

    /// This host already carries a transaction record, whatever anybody does.
    fn carrying(self, id: &str, txn: Txn) -> TableLook {
        self.txns.borrow_mut().insert(id.to_string(), txn);
        self
    }

    fn set(&self, id: &str, phase: Phase) {
        self.phase.borrow_mut().insert(id.to_string(), phase);
    }

    fn asked(&self) -> Vec<String> {
        self.asked.borrow().clone()
    }
}

impl Look for TableLook {
    fn observe(&self, host: &ResolvedHost, target: &Target) -> HostObservation {
        let id = target.host_id.clone();
        self.asked.borrow_mut().push(id.clone());
        assert!(
            host.name.ends_with(&id),
            "the fixture's host {} is not {id}",
            host.name
        );
        let phase = self
            .phase
            .borrow()
            .get(&id)
            .copied()
            .unwrap_or(Phase::Before);
        let mut obs = match phase {
            Phase::Before => self.before[&id].clone(),
            Phase::After => self.after[&id].clone(),
            Phase::Down(0) => {
                self.set(&id, Phase::After);
                self.after[&id].clone()
            }
            Phase::Down(n) => {
                self.set(&id, Phase::Down(n - 1));
                let mut obs = HostObservation::unreachable(format!("{id} is rebooting"));
                obs.identity.host_key_fingerprint =
                    self.before[&id].identity.host_key_fingerprint.clone();
                obs
            }
            Phase::ComingBack(0) => {
                self.set(&id, Phase::Before);
                self.before[&id].clone()
            }
            Phase::ComingBack(n) => {
                self.set(&id, Phase::ComingBack(n - 1));
                HostObservation::unreachable(format!("{id} is rebooting"))
            }
        };
        if phase == Phase::After && self.broken.borrow().contains(&id) {
            obs.units
                .insert("meister-agent.service".to_string(), "failed".to_string());
        }
        if let Some(txn) = self.txns.borrow().get(&id) {
            obs.open_txns = vec![txn.clone()];
        }
        obs
    }
}

/// The strict fake, plus what the command it just answered would have done.
struct World<'a> {
    inner: StrictFake,
    look: &'a TableLook,
}

impl<'a> World<'a> {
    fn new(inner: StrictFake, look: &'a TableLook) -> World<'a> {
        World { inner, look }
    }

    fn verify(&self) -> Result<()> {
        self.inner.verify()
    }

    fn calls(&self) -> Vec<String> {
        self.inner.calls()
    }
}

impl Runner for World<'_> {
    fn run(&self, cmd: &Cmd) -> Result<Output> {
        let out = self.inner.run(cmd)?;
        // Which host this was about: the ssh destination, `root@10.0.0.11`.
        let host = cmd
            .args
            .iter()
            .find_map(|a| a.strip_prefix("root@"))
            .and_then(address_to_host);
        let says = |word: &str| cmd.args.iter().any(|a| a == word);
        if let Some(host) = host {
            if says("activate") {
                self.look.set(&host, Phase::After);
                self.look.txns.borrow_mut().remove(&host);
            } else if says("revert") {
                self.look.set(&host, Phase::Before);
                self.look.txns.borrow_mut().remove(&host);
            } else if says("systemctl reboot") {
                // Two looks away, then wherever the profile points — unless
                // this test says the machine does not come back.
                let phase = self.look.phase.borrow().get(&host).copied();
                let lost = self.look.lost.borrow().contains(&host);
                self.look.set(
                    &host,
                    match (lost, phase) {
                        (true, _) => Phase::Down(u32::MAX),
                        (false, Some(Phase::Before)) => Phase::ComingBack(2),
                        (false, _) => Phase::Down(2),
                    },
                );
            }
        }
        Ok(out)
    }

    fn policy(&self) -> Policy {
        self.inner.policy()
    }
}

fn address_to_host(address: &str) -> Option<String> {
    match address {
        "10.0.0.10" => Some("box".to_string()),
        "10.0.0.11" => Some("n1".to_string()),
        "10.0.0.12" => Some("n2".to_string()),
        _ => None,
    }
}

/// Everything a test needs to run one plan.
struct Fixture {
    release: ReleaseManifest,
    plan: DeploymentPlan,
    files: MemFiles,
    clock: FakeClock,
    state: StateDir,
    ssh: Ssh,
}

impl Fixture {
    /// A fleet in which these hosts have a new system and everybody else is
    /// where the release says.
    fn changing(hosts: &[&str], new_kernel: bool) -> Fixture {
        let release = with_new_systems(onebox_enrolled(), hosts, new_kernel);
        let before = release_of(onebox_enrolled());
        let observation = observed(&before, at(NOW));
        Fixture::of(release, observation, "all")
    }

    /// A fleet that already runs the release.
    fn unchanged() -> Fixture {
        let release = release_of(onebox_enrolled());
        let observation = observed(&release, at(NOW));
        Fixture::of(release, observation, "all")
    }

    fn of(release: ReleaseManifest, observation: Observations, select: &str) -> Fixture {
        let plan = plan(
            &release,
            select,
            &observation,
            None,
            &crate::fixtures::plan_policy(PlanKind::Upgrade),
            at(NOW),
        )
        .expect("the fixture plans");
        Fixture {
            release,
            plan,
            files: MemFiles::new(),
            clock: FakeClock::at(at(NOW)),
            state: StateDir::at("/repo/.meister-deploy"),
            ssh: Ssh::with_known_hosts("/repo/known_hosts"),
        }
    }

    /// An operator who has read the plan and granted what it asks for.
    fn options(&self) -> ApplyOptions {
        let mut options = self.ungranted();
        options.approvals = self
            .plan
            .approvals
            .iter()
            .map(|a| (a.class, self.plan.plan_id.clone()))
            .collect();
        options
    }

    /// The same, without the approvals — for the two tests that are about
    /// what happens when nobody granted them.
    fn ungranted(&self) -> ApplyOptions {
        let mut options = ApplyOptions::new("run-1");
        // The same reference the plan was made with (D7), so the cordon and
        // the drain have a cli to run.
        options.workload = Some(WorkloadControl {
            cli_config: "cli.toml".to_string(),
            cli_profile: Some("cloud-mtls".to_string()),
        });
        options
    }

    fn executor<'a>(
        &'a self,
        runner: &'a World<'a>,
        look: &'a TableLook,
        options: ApplyOptions,
    ) -> Executor<'a> {
        Executor {
            runner,
            files: &self.files,
            clock: &self.clock,
            look,
            ssh: &self.ssh,
            state: &self.state,
            plan: &self.plan,
            release: &self.release,
            operator: Operator {
                user: "silas".to_string(),
                workstation: "manacor".to_string(),
            },
            options,
            cancel: Cancel::new(),
        }
    }

    /// The snapshot the plan was made from, host by host.
    fn seen(&self, id: &str) -> HostObservation {
        self.plan
            .observation
            .host(id)
            .expect("the plan saw every host")
            .clone()
    }

    /// The same host, now running what the release says.
    fn moved(&self, id: &str) -> HostObservation {
        let mut obs = self.seen(id);
        let artifacts = &self.release.artifacts[id];
        obs.current_system = Some(artifacts.toplevel.store_path.clone());
        obs.booted_system = Some(artifacts.toplevel.store_path.clone());
        obs.next_boot_system = Some(artifacts.toplevel.store_path.clone());
        obs.generation = obs.generation.map(|g| g + 1);
        obs.kernel_booted = Some(BootedKernel {
            kernel_store_path: artifacts.boot.kernel_store_path.clone(),
            initrd_store_path: artifacts.boot.initrd_store_path.clone(),
            kernel_params_sha256: artifacts.boot.kernel_params_sha256.clone(),
        });
        obs
    }

    fn journal_lines(&self, run: &str) -> Vec<JournalEvent> {
        let path = self.state.journal_path(run);
        let text = String::from_utf8(self.files.content(&path).unwrap_or_default())
            .expect("the journal is utf-8");
        parse_journal(&text, "the journal").expect("it parses")
    }

    fn top(&self, id: &str) -> String {
        self.release.artifacts[id].toplevel.store_path.clone()
    }

    /// What `nix path-info --json` on the target would say about it.
    fn path_info(&self, id: &str) -> String {
        let a = &self.release.artifacts[id];
        format!(
            "{{\"{}\":{{\"narHash\":\"{}\",\"narSize\":1,\"closureSize\":2,\
             \"signatures\":[\"k:s\"]}}}}",
            a.toplevel.store_path, a.toplevel.nar_hash
        )
    }
}

/// The argv prefix of `ssh … meister-activate --json <args…>` for one host.
fn helper(id: &str, args: &[&str]) -> Matcher {
    let address = match id {
        "box" => "10.0.0.10",
        "n1" => "10.0.0.11",
        _ => "10.0.0.12",
    };
    let mut out = Ssh::with_known_hosts("/repo/known_hosts").opts(22);
    out.push(format!("root@{address}"));
    out.push("meister-activate".to_string());
    out.push("--json".to_string());
    out.extend(args.iter().map(|a| a.to_string()));
    Matcher::prefix("ssh", out)
}

/// `ssh … 'systemctl reboot'`, which is the one ssh that is not the helper.
fn reboot_of(id: &str) -> Matcher {
    let address = match id {
        "box" => "10.0.0.10",
        "n1" => "10.0.0.11",
        _ => "10.0.0.12",
    };
    let mut out = Ssh::with_known_hosts("/repo/known_hosts").opts(22);
    out.push(format!("root@{address}"));
    out.push("sh".to_string());
    out.push("-c".to_string());
    out.push("systemctl reboot".to_string());
    Matcher::exact("ssh", out)
}

fn cli(verb: &str, id: &str) -> Matcher {
    Matcher::exact(
        "meister",
        [
            "--config",
            "cli.toml",
            "-p",
            "cloud-mtls",
            "node",
            verb,
            id,
            "--cluster",
            "box",
        ],
    )
}

fn ok() -> Output {
    Output::stdout("{}")
}

/// The steps a host gets, as the planner wrote them.
fn kinds(plan: &DeploymentPlan, id: &str) -> Vec<ActionKind> {
    plan.actions_for(id)
        .into_iter()
        .filter(|a| !a.is_blocked())
        .map(|a| a.kind)
        .collect()
}

// ---------------------------------------------------------------------------

#[test]
fn a_host_that_already_runs_the_release_is_journalled_and_not_touched() {
    // V10 at the executor: the plan gives it two steps and neither of them
    // may start a command.
    let fx = Fixture::unchanged();
    let look = TableLook::new(&fx);
    // The fleet anchor is taken even by a run that changes nothing: it is
    // the door, not a change, and two operators must not both be here (D6).
    let runner = World::new(
        StrictFake::new()
            .expect(helper("box", &["lock", "acquire"]), ok())
            .expect(helper("box", &["lock", "release"]), ok()),
        &look,
    );
    let applied = fx
        .executor(&runner, &look, fx.options())
        .run()
        .expect("an unchanged fleet applies");
    runner.verify().expect("the anchor and nothing else");
    for call in runner.calls() {
        assert!(
            call.contains("lock acquire") || call.contains("lock release"),
            "an unchanged fleet ran {call}"
        );
    }

    assert_eq!(applied.receipt.outcome, Outcome::Success);
    for id in ["box", "n1", "n2"] {
        assert_eq!(
            applied.receipt.hosts[id].outcome,
            HostOutcome::Unchanged,
            "{id}"
        );
    }
    assert!(applied.receipt.untouched.is_empty());
    // It is in the journal, which is what makes the receipt `success`
    // rather than `partial` (2A's finding).
    let states: Vec<String> = fx
        .journal_lines("run-1")
        .into_iter()
        .filter(|e| e.event == EventKind::HostState)
        .map(|e| {
            format!(
                "{}:{}",
                e.host.unwrap_or_default(),
                e.to.unwrap_or_default()
            )
        })
        .collect();
    assert_eq!(states, ["box:unchanged", "n1:unchanged", "n2:unchanged"]);
}

#[test]
fn the_whole_of_one_changed_host_in_the_order_the_plan_wrote() {
    let fx = Fixture::changing(&["n1"], false);
    assert_eq!(
        kinds(&fx.plan, "n1"),
        [
            ActionKind::Preflight,
            ActionKind::Lock,
            ActionKind::Stage,
            ActionKind::Cordon,
            ActionKind::Drain,
            ActionKind::Activate,
            ActionKind::Verify,
            ActionKind::Confirm,
            ActionKind::Uncordon,
            ActionKind::Unlock,
        ],
        "these expectations are written for exactly this sequence"
    );
    let top = fx.top("n1");
    let look = TableLook::new(&fx);
    let runner = World::new(
        StrictFake::new()
            // The fleet anchor: the control-plane host, before anything.
            .expect(helper("box", &["lock", "acquire", "--run", "run-1"]), ok())
            .expect(helper("n1", &["lock", "acquire", "--run", "run-1"]), ok())
            .expect(
                Matcher::exact("nix", ["copy", "--to", "ssh-ng://root@10.0.0.11", &top]),
                Output::stdout(""),
            )
            .expect(
                Matcher::prefix("nix", ["path-info", "--json", "--closure-size"]),
                Output::stdout(fx.path_info("n1")),
            )
            .expect(helper("n1", &["stage", &top]), ok())
            .expect(cli("cordon", "n1"), Output::stdout(""))
            .expect(cli("drain", "n1"), Output::stdout(""))
            .expect(
                helper(
                    "n1",
                    &[
                        "activate",
                        "--txn",
                        "run-1",
                        "--toplevel",
                        &top,
                        "--mode",
                        "switch",
                        "--confirm-within",
                        "300",
                        "--run",
                        "run-1",
                    ],
                ),
                ok(),
            )
            .expect(helper("n1", &["confirm", "--txn", "run-1"]), ok())
            .expect(cli("uncordon", "n1"), Output::stdout(""))
            .expect(
                helper("n1", &["txn", "retire", "--txn", "run-1", "--run", "run-1"]),
                ok(),
            )
            .expect(helper("n1", &["lock", "release", "--run", "run-1"]), ok())
            .expect(helper("box", &["lock", "release", "--run", "run-1"]), ok()),
        &look,
    );

    let applied = fx
        .executor(&runner, &look, fx.options())
        .run()
        .expect("the rollout runs");
    assert_eq!(applied.stopped, None, "it did not get to the end");
    runner.verify().expect("every expectation was used");

    assert_eq!(applied.receipt.outcome, Outcome::Success);
    assert_eq!(applied.receipt.hosts["n1"].outcome, HostOutcome::Success);
    assert_eq!(
        applied.receipt.hosts["n1"].txn_id.as_deref(),
        Some("run-1"),
        "the receipt names the transaction the host kept"
    );
    assert_eq!(
        applied.receipt.hosts["n1"].before.system.as_deref(),
        fx.seen("n1").current_system.as_deref(),
        "the receipt says where it came from"
    );
    assert_eq!(
        applied.receipt.hosts["n1"].after.system,
        Some(top),
        "and where it went"
    );

    // The line a resume stands on is between the activation's begin and its
    // end, and it is on the disk before the command ran.
    let order: Vec<String> = fx
        .journal_lines("run-1")
        .iter()
        .filter(|e| e.host.as_deref() == Some("n1"))
        .map(|e| {
            format!(
                "{:?}:{}",
                e.event,
                e.payload
                    .get("kind")
                    .and_then(|k| k.as_str())
                    .unwrap_or_default()
            )
        })
        .collect();
    let at_of = |needle: &str| {
        order
            .iter()
            .position(|s| s == needle)
            .unwrap_or_else(|| panic!("{needle} is not in {order:?}"))
    };
    assert!(at_of("ActionBegin:activate") < at_of("ActionIrreversible:activate"));
    assert!(at_of("ActionIrreversible:activate") < at_of("ActionEnd:activate"));
}

#[test]
fn a_missing_approval_stops_before_the_first_command() {
    // The fixture's box is a raft group of one, so a plan that touches it
    // needs `singleton` (V13).
    let fx = Fixture::changing(&["box"], false);
    let look = TableLook::new(&fx);
    let runner = World::new(StrictFake::new(), &look);
    let err = fx
        .executor(&runner, &look, fx.ungranted())
        .run()
        .unwrap_err()
        .to_string();
    assert!(err.contains("--approve"), "{err}");
    assert!(err.contains("singleton"), "{err}");
    assert!(err.contains(&fx.plan.plan_id), "{err}");
    runner.verify().expect("not one command");
    assert!(look.asked().is_empty(), "nobody was even asked");
}

#[test]
fn an_approval_for_another_plan_is_not_an_approval() {
    let fx = Fixture::changing(&["box"], false);
    let look = TableLook::new(&fx);
    let runner = World::new(StrictFake::new(), &look);
    let mut options = fx.ungranted();
    options.approvals = fx
        .plan
        .approvals
        .iter()
        .map(|a| (a.class, "plan-yesterdays".to_string()))
        .collect();
    let err = fx
        .executor(&runner, &look, options)
        .run()
        .unwrap_err()
        .to_string();
    assert!(err.contains("--approve"), "{err}");
    runner.verify().expect("not one command");
}

#[test]
fn a_fleet_that_moved_under_the_plan_stops_before_anything_is_done() {
    let fx = Fixture::changing(&["n1"], false);
    let mut look = TableLook::new(&fx);
    // Somebody else deployed to n1 in the meantime.
    look.before.get_mut("n1").unwrap().current_system =
        Some("/nix/store/zzzz-somebody-elses-system".to_string());
    let runner = World::new(
        StrictFake::new()
            .expect(helper("box", &["lock", "acquire"]), ok())
            .expect(helper("box", &["lock", "release"]), ok()),
        &look,
    );
    let applied = fx
        .executor(&runner, &look, fx.options())
        .run()
        .expect("a receipt is still written");
    runner.verify().expect("the anchor and nothing else");

    let stopped = applied.stopped.expect("it stopped");
    assert!(
        stopped.contains("the fleet moved under this plan"),
        "{stopped}"
    );
    assert!(stopped.contains("somebody deployed to it"), "{stopped}");
    // box and n2 already ran the release and were journalled as unchanged
    // before n1 was reached, so the run did move forward — for two hosts
    // that needed nothing. `partial` is that, and `aborted` would claim
    // nothing at all had happened.
    assert_eq!(applied.receipt.outcome, Outcome::Partial);
    assert!(
        applied.receipt.untouched.contains(&"n1".to_string()),
        "{:?}",
        applied.receipt.untouched
    );
}

#[test]
fn what_arrived_with_the_right_name_and_the_wrong_bytes_is_not_activated() {
    // V12 at the target, after the copy and before anything moves.
    let fx = Fixture::changing(&["n1"], false);
    let look = TableLook::new(&fx);
    let runner = World::new(
        StrictFake::new()
            .expect(helper("box", &["lock", "acquire"]), ok())
            .expect(helper("n1", &["lock", "acquire"]), ok())
            .expect(Matcher::prefix("nix", ["copy"]), Output::stdout(""))
            .expect(
                Matcher::prefix("nix", ["path-info"]),
                Output::stdout(format!(
                    "{{\"{}\":{{\"narHash\":\"sha256-somethingelse\",\"narSize\":1,\
                     \"closureSize\":2,\"signatures\":[]}}}}",
                    fx.top("n1")
                )),
            )
            // The run stopped before n1's own unlock step, so the locks go
            // back in host order at the end of the run.
            .expect(helper("box", &["lock", "release"]), ok())
            .expect(helper("n1", &["lock", "release"]), ok()),
        &look,
    );
    let applied = fx
        .executor(&runner, &look, fx.options())
        .run()
        .expect("a receipt is written");
    runner.verify().expect("nothing after the hash");
    let stopped = applied.stopped.expect("it stopped");
    assert!(stopped.contains("Same name, different bytes"), "{stopped}");
    assert_eq!(applied.receipt.hosts["n1"].outcome, HostOutcome::Skipped);
    assert_eq!(applied.receipt.outcome, Outcome::Partial);
}

#[test]
fn a_readiness_failure_takes_the_host_back_and_the_run_stays_failed() {
    let fx = Fixture::changing(&["n1"], false);
    let look = TableLook::new(&fx).breaks("n1");
    let runner = World::new(
        StrictFake::new()
            .expect(helper("box", &["lock", "acquire"]), ok())
            .expect(helper("n1", &["lock", "acquire"]), ok())
            .expect(Matcher::prefix("nix", ["copy"]), Output::stdout(""))
            .expect(
                Matcher::prefix("nix", ["path-info"]),
                Output::stdout(fx.path_info("n1")),
            )
            .expect(helper("n1", &["stage"]), ok())
            .expect(cli("cordon", "n1"), Output::stdout(""))
            .expect(cli("drain", "n1"), Output::stdout(""))
            .expect(helper("n1", &["activate"]), ok())
            // The check fails, so the host is asked to go back.
            .expect(helper("n1", &["revert", "--txn", "run-1"]), ok())
            .expect(helper("n1", &["txn", "retire"]), ok())
            // The run stopped in the verify, before n1's own unlock step,
            // so the locks go back in host order at the end of the run.
            .expect(helper("box", &["lock", "release"]), ok())
            .expect(helper("n1", &["lock", "release"]), ok()),
        &look,
    );

    let applied = fx
        .executor(&runner, &look, fx.options())
        .run()
        .expect("a receipt is written");
    runner.verify().expect("every expectation was used");

    assert_eq!(applied.receipt.hosts["n1"].outcome, HostOutcome::RolledBack);
    assert_eq!(
        applied.receipt.outcome,
        Outcome::Partial,
        "a rollback that worked is still a rollout that did not"
    );
    let stopped = applied.stopped.expect("it stopped");
    assert!(
        stopped.contains("readiness checks did not pass"),
        "{stopped}"
    );
    // And the reason travels into the record on the host.
    assert!(
        runner
            .calls()
            .iter()
            .any(|c| c.contains("revert") && c.contains("units")),
        "{:?}",
        runner.calls()
    );
}

#[test]
fn a_host_that_does_not_come_back_from_a_revert_needs_a_person() {
    let fx = Fixture::changing(&["n1"], false);
    let look = TableLook::new(&fx).breaks("n1");
    let runner = World::new(
        StrictFake::new()
            .expect(helper("box", &["lock", "acquire"]), ok())
            .expect(helper("n1", &["lock", "acquire"]), ok())
            .expect(Matcher::prefix("nix", ["copy"]), Output::stdout(""))
            .expect(
                Matcher::prefix("nix", ["path-info"]),
                Output::stdout(fx.path_info("n1")),
            )
            .expect(helper("n1", &["stage"]), ok())
            .expect(cli("cordon", "n1"), Output::stdout(""))
            .expect(cli("drain", "n1"), Output::stdout(""))
            .expect(helper("n1", &["activate"]), ok())
            .expect(
                helper("n1", &["revert"]),
                Output::failing(1, "the profile could not be moved"),
            )
            // The run stopped before n1's own unlock step, so the locks go
            // back in host order at the end of the run.
            .expect(helper("box", &["lock", "release"]), ok())
            .expect(helper("n1", &["lock", "release"]), ok()),
        &look,
    );
    let applied = fx
        .executor(&runner, &look, fx.options())
        .run()
        .expect("a receipt is written");
    runner.verify().expect("every expectation was used");
    assert_eq!(
        applied.receipt.hosts["n1"].outcome,
        HostOutcome::RecoveryRequired
    );
    assert_eq!(applied.receipt.outcome, Outcome::Partial);
}

#[test]
fn a_host_somebody_else_holds_stops_this_run_and_names_the_holder() {
    // V18 at the executor: the refusal comes from the target's own lock.
    let fx = Fixture::changing(&["n1"], false);
    let look = TableLook::new(&fx);
    let runner = World::new(
        StrictFake::new().expect(
            helper("box", &["lock", "acquire"]),
            Output::failing(
                1,
                "meister-activate: this host is held by the run run-other since 2026-09-22 \
                 11:00:00 UTC (operator silas@elsewhere, pid 1234).",
            ),
        ),
        &look,
    );
    let applied = fx
        .executor(&runner, &look, fx.options())
        .run()
        .expect("a receipt is written");
    runner.verify().expect("the anchor and nothing else");
    let stopped = applied.stopped.expect("it stopped");
    assert!(
        stopped.contains("the fleet anchor could not be taken"),
        "{stopped}"
    );
    assert!(stopped.contains("run-other"), "{stopped}");
    assert_eq!(applied.receipt.outcome, Outcome::Aborted);
    assert!(look.asked().is_empty(), "nothing was even looked at");
}

#[test]
fn a_resume_after_an_irreversible_step_asks_the_target_and_does_not_repeat_it() {
    // V17: the journal says an activation began and never ended; the target
    // says it is pending. So: verify and confirm, and no second activate.
    let fx = Fixture::changing(&["n1"], false);
    write_interrupted_journal(&fx, "run-1");
    let look = TableLook::new(&fx).carrying(
        "n1",
        Txn {
            id: "run-1".to_string(),
            state: TxnState::Pending,
            target_system: Some(fx.top("n1")),
            deadline: Some(at("2026-09-22T12:05:00Z")),
            run_id: Some("run-1".to_string()),
        },
    );
    look.set("n1", Phase::After);
    let runner = World::new(
        StrictFake::new()
            .expect(helper("box", &["lock", "acquire"]), ok())
            .expect(helper("n1", &["lock", "acquire"]), ok())
            .expect(helper("n1", &["confirm", "--txn", "run-1"]), ok())
            .expect(cli("uncordon", "n1"), Output::stdout(""))
            .expect(helper("n1", &["txn", "retire", "--txn", "run-1"]), ok())
            .expect(helper("n1", &["lock", "release"]), ok())
            .expect(helper("box", &["lock", "release"]), ok()),
        &look,
    );

    let mut options = fx.options();
    options.resume = true;
    let applied = fx
        .executor(&runner, &look, options)
        .run()
        .expect("the resume runs");
    assert_eq!(applied.stopped, None, "the resume did not get to the end");
    runner.verify().expect("every expectation was used");
    assert_eq!(applied.receipt.hosts["n1"].outcome, HostOutcome::Success);
    assert!(
        !runner.calls().iter().any(|c| c.contains("activate --txn")),
        "an activation was repeated: {:?}",
        runner.calls()
    );
    assert!(
        !runner.calls().iter().any(|c| c.contains("nix copy")),
        "the closure was carried again: {:?}",
        runner.calls()
    );
}

#[test]
fn a_resume_whose_target_knows_nothing_repeats_nothing_and_asks_for_a_person() {
    let fx = Fixture::changing(&["n1"], false);
    write_interrupted_journal(&fx, "run-1");
    let look = TableLook::new(&fx);
    look.set("n1", Phase::After);
    let runner = World::new(
        StrictFake::new()
            .expect(helper("box", &["lock", "acquire"]), ok())
            .expect(helper("box", &["lock", "release"]), ok()),
        &look,
    );
    let mut options = fx.options();
    options.resume = true;
    let applied = fx
        .executor(&runner, &look, options)
        .run()
        .expect("a receipt is written");
    runner.verify().expect("nothing was done to n1");
    assert_eq!(
        applied.receipt.hosts["n1"].outcome,
        HostOutcome::RecoveryRequired
    );
    let stopped = applied.stopped.expect("it stopped");
    assert!(stopped.contains("no transaction record"), "{stopped}");
}

#[test]
fn a_resume_of_another_plan_is_refused_by_name() {
    let fx = Fixture::changing(&["n1"], false);
    fx.state
        .begin_run(&fx.files, "run-1")
        .expect("the run directory");
    let journal = Journal::new(fx.state.journal_path("run-1"), "run-1", "plan-yesterdays");
    journal
        .append(
            &fx.files,
            journal
                .event(EventKind::RunStart, at(NOW))
                .payload(serde_json::json!({})),
        )
        .expect("a line");
    let look = TableLook::new(&fx);
    let runner = World::new(StrictFake::new(), &look);
    let mut options = fx.options();
    options.resume = true;
    let err = fx
        .executor(&runner, &look, options)
        .run()
        .unwrap_err()
        .to_string();
    assert!(err.contains("plan-yesterdays"), "{err}");
    runner.verify().expect("not one command");
}

#[test]
fn a_reboot_class_host_waits_for_the_system_it_was_meant_to_boot() {
    let fx = Fixture::changing(&["n1"], true);
    assert!(
        fx.plan.hosts["n1"].reboot_required,
        "a changed kernel is a reboot class"
    );
    assert!(
        kinds(&fx.plan, "n1").contains(&ActionKind::Reboot),
        "{:?}",
        kinds(&fx.plan, "n1")
    );
    let top = fx.top("n1");
    let look = TableLook::new(&fx);
    let runner = World::new(
        StrictFake::new()
            .expect(helper("box", &["lock", "acquire"]), ok())
            .expect(helper("n1", &["lock", "acquire"]), ok())
            .expect(Matcher::prefix("nix", ["copy"]), Output::stdout(""))
            .expect(
                Matcher::prefix("nix", ["path-info"]),
                Output::stdout(fx.path_info("n1")),
            )
            .expect(helper("n1", &["stage"]), ok())
            .expect(cli("cordon", "n1"), Output::stdout(""))
            .expect(cli("drain", "n1"), Output::stdout(""))
            .expect(
                helper(
                    "n1",
                    &[
                        "activate",
                        "--txn",
                        "run-1",
                        "--toplevel",
                        &top,
                        "--mode",
                        "boot",
                        "--confirm-within",
                        "900",
                    ],
                ),
                ok(),
            )
            .expect(
                reboot_of("n1"),
                Output::failing(255, "Connection closed by remote host"),
            )
            .expect(helper("n1", &["confirm"]), ok())
            .expect(cli("uncordon", "n1"), Output::stdout(""))
            .expect(helper("n1", &["txn", "retire"]), ok())
            .expect(helper("n1", &["lock", "release"]), ok())
            .expect(helper("box", &["lock", "release"]), ok()),
        &look,
    );

    let options = fx.options();
    let applied = fx
        .executor(&runner, &look, options)
        .run()
        .expect("the rollout runs");
    runner.verify().expect("every expectation was used");
    assert_eq!(applied.receipt.hosts["n1"].outcome, HostOutcome::Success);
    assert!(
        !fx.clock.slept().is_empty(),
        "a bounded wait that never sleeps is a spin"
    );
}

#[test]
fn a_host_that_does_not_come_back_is_not_activated_again() {
    let fx = Fixture::changing(&["n1"], true);
    let look = TableLook::new(&fx).never_returns("n1");
    let runner = World::new(
        StrictFake::new()
            .expect(helper("box", &["lock", "acquire"]), ok())
            .expect(helper("n1", &["lock", "acquire"]), ok())
            .expect(Matcher::prefix("nix", ["copy"]), Output::stdout(""))
            .expect(
                Matcher::prefix("nix", ["path-info"]),
                Output::stdout(fx.path_info("n1")),
            )
            .expect(helper("n1", &["stage"]), ok())
            .expect(cli("cordon", "n1"), Output::stdout(""))
            .expect(cli("drain", "n1"), Output::stdout(""))
            .expect(helper("n1", &["activate"]), ok())
            .expect(
                reboot_of("n1"),
                Output::failing(255, "Connection closed by remote host"),
            )
            // The run stopped before n1's own unlock step, so the locks go
            // back in host order at the end of the run.
            .expect(helper("box", &["lock", "release"]), ok())
            .expect(helper("n1", &["lock", "release"]), ok()),
        &look,
    );

    let mut options = fx.options();
    options.reboot_wait = Duration::from_secs(30);
    let applied = fx
        .executor(&runner, &look, options)
        .run()
        .expect("a receipt is written");
    runner.verify().expect("every expectation was used");
    let stopped = applied.stopped.expect("it stopped");
    assert!(stopped.contains("did not come back"), "{stopped}");
    assert!(stopped.contains("apply --resume run-1"), "{stopped}");
    assert_eq!(applied.receipt.hosts["n1"].outcome, HostOutcome::Unknown);
}

#[test]
fn an_interrupted_run_stops_at_the_next_step_and_says_so() {
    let fx = Fixture::changing(&["n1"], false);
    let look = TableLook::new(&fx);
    let runner = World::new(
        StrictFake::new()
            .expect(helper("box", &["lock", "acquire"]), ok())
            .expect(helper("box", &["lock", "release"]), ok()),
        &look,
    );
    let executor = fx.executor(&runner, &look, fx.options());
    executor.cancel.cancel();
    let applied = executor.run().expect("a receipt is written");
    runner.verify().expect("the anchor and nothing else");
    let stopped = applied.stopped.expect("it stopped");
    assert!(stopped.contains("interrupted"), "{stopped}");
    assert_eq!(applied.receipt.outcome, Outcome::Aborted);
}

#[test]
fn a_drain_that_never_empties_the_host_refuses_the_step() {
    let fx = Fixture::changing(&["n1"], false);
    let mut look = TableLook::new(&fx);
    // Two guests, and they stay.
    look.before.get_mut("n1").unwrap().vms_running = Some(2);
    look.after.get_mut("n1").unwrap().vms_running = Some(2);
    let runner = World::new(
        StrictFake::new()
            .expect(helper("box", &["lock", "acquire"]), ok())
            .expect(helper("n1", &["lock", "acquire"]), ok())
            .expect(Matcher::prefix("nix", ["copy"]), Output::stdout(""))
            .expect(
                Matcher::prefix("nix", ["path-info"]),
                Output::stdout(fx.path_info("n1")),
            )
            .expect(helper("n1", &["stage"]), ok())
            .expect(cli("cordon", "n1"), Output::stdout(""))
            .expect(cli("drain", "n1"), Output::stdout(""))
            // The run stopped before n1's own unlock step, so the locks go
            // back in host order at the end of the run.
            .expect(helper("box", &["lock", "release"]), ok())
            .expect(helper("n1", &["lock", "release"]), ok()),
        &look,
    );
    let mut options = fx.options();
    options.drain_wait = Duration::from_secs(20);
    let applied = fx
        .executor(&runner, &look, options)
        .run()
        .expect("a receipt is written");
    runner.verify().expect("nothing was activated");
    let stopped = applied.stopped.expect("it stopped");
    assert!(stopped.contains("still carries 2 guest(s)"), "{stopped}");
    assert_eq!(applied.receipt.hosts["n1"].outcome, HostOutcome::Skipped);
}

#[test]
fn an_unknown_number_of_guests_is_not_an_empty_host() {
    let fx = Fixture::changing(&["n1"], false);
    let mut look = TableLook::new(&fx);
    look.before.get_mut("n1").unwrap().vms_running = None;
    look.after.get_mut("n1").unwrap().vms_running = None;
    let runner = World::new(
        StrictFake::new()
            .expect(helper("box", &["lock", "acquire"]), ok())
            .expect(helper("n1", &["lock", "acquire"]), ok())
            .expect(Matcher::prefix("nix", ["copy"]), Output::stdout(""))
            .expect(
                Matcher::prefix("nix", ["path-info"]),
                Output::stdout(fx.path_info("n1")),
            )
            .expect(helper("n1", &["stage"]), ok())
            .expect(cli("cordon", "n1"), Output::stdout(""))
            .expect(cli("drain", "n1"), Output::stdout(""))
            // The run stopped before n1's own unlock step, so the locks go
            // back in host order at the end of the run.
            .expect(helper("box", &["lock", "release"]), ok())
            .expect(helper("n1", &["lock", "release"]), ok()),
        &look,
    );
    let mut options = fx.options();
    options.drain_wait = Duration::from_secs(20);
    let applied = fx
        .executor(&runner, &look, options)
        .run()
        .expect("a receipt is written");
    runner.verify().expect("nothing was activated");
    let stopped = applied.stopped.expect("it stopped");
    assert!(stopped.contains("an unknown number of guests"), "{stopped}");
}

#[test]
fn the_anchor_says_when_it_could_not_hold_a_control_plane_host() {
    // The selection is n1 alone; the anchor still wants box, because a
    // second operator in a second checkout is what it is for (D6). box has
    // no frozen endpoint in this plan, so the anchor is incomplete and says
    // so rather than pretending.
    let release = with_new_systems(onebox_enrolled(), &["n1"], false);
    let before = release_of(onebox_enrolled());
    let observation = observed(&before, at(NOW));
    let fx = Fixture::of(release, observation, "host=n1");
    assert_eq!(fx.plan.selection.targets, ["n1"]);
    let look = TableLook::new(&fx);
    let runner = World::new(
        StrictFake::new().expect(
            helper("n1", &["lock", "acquire"]),
            Output::failing(1, "no such command"),
        ),
        &look,
    );
    let applied = fx
        .executor(&runner, &look, fx.options())
        .run()
        .expect("a receipt is written");
    runner.verify().expect("only what could be asked");
    assert_eq!(applied.receipt.outcome, Outcome::Aborted);
}

/// A journal of a run that died between `action.irreversible` and the end of
/// its activation — the one window the V17 table exists for.
fn write_interrupted_journal(fx: &Fixture, run: &str) {
    fx.state
        .begin_run(&fx.files, run)
        .expect("the run directory");
    fx.files
        .write_atomic(
            &fx.state.plan_copy_path(run),
            &fx.plan.to_json().expect("the plan"),
            0o644,
        )
        .expect("the plan copy");
    let journal = Journal::new(fx.state.journal_path(run), run, &fx.plan.plan_id);
    let put = |event: JournalEvent| {
        journal.append(&fx.files, event).expect("a line");
    };
    put(journal
        .event(EventKind::RunStart, at(NOW))
        .payload(serde_json::json!({"operator": {"user": "silas", "workstation": "manacor"}})));
    for (from, to) in [
        (HostState::Planned, HostState::Preflight),
        (HostState::Preflight, HostState::Staged),
        (HostState::Staged, HostState::MaintenanceReady),
    ] {
        put(journal
            .event(EventKind::HostState, at(NOW))
            .host("n1")
            .transition(from, to)
            .payload(serde_json::json!({})));
    }
    let activate = fx
        .plan
        .actions_for("n1")
        .into_iter()
        .find(|a| a.kind == ActionKind::Activate)
        .expect("there is one")
        .seq;
    put(journal
        .event(EventKind::ActionBegin, at(NOW))
        .host("n1")
        .payload(serde_json::json!({"action": activate, "kind": "activate"})));
    put(journal
        .event(EventKind::ActionIrreversible, at(NOW))
        .host("n1")
        .payload(serde_json::json!({"action": activate, "kind": "activate", "txn": run})));
    // And here the workstation went away: no `action.end`, no `run.end`.
}

#[test]
fn every_mutating_step_is_preceded_by_a_fresh_look() {
    // The rule of §6, read off the list rather than trusted.
    for kind in [
        ActionKind::Stage,
        ActionKind::Cordon,
        ActionKind::Drain,
        ActionKind::Activate,
        ActionKind::Reboot,
        ActionKind::Confirm,
        ActionKind::Uncordon,
        ActionKind::DeliverSecret,
        ActionKind::Install,
        ActionKind::Revoke,
        ActionKind::Gc,
    ] {
        assert!(needs_validation(kind), "{kind} changes something");
    }
    for kind in [
        ActionKind::Preflight,
        ActionKind::Verify,
        ActionKind::Lock,
        ActionKind::Unlock,
    ] {
        assert!(!needs_validation(kind), "{kind} is a look or a door");
    }
}
