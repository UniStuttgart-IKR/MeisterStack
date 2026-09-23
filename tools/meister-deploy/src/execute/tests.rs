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
    /// How many more looks this host's etcd needs before it answers, the
    /// way a real one does after a reboot (lane 4A).
    etcd_late: RefCell<BTreeMap<String, u32>>,
    /// Hosts whose activation leaves the record a real one leaves: pending,
    /// waiting for a word.
    keeps_the_record: RefCell<BTreeSet<String>>,
    /// Hosts whose kernel comes from OUTSIDE (lane 3-integration): an
    /// activation moves their userland and leaves what they booted exactly
    /// where it was, because the thing that decides that is a hypervisor.
    /// [`TableLook::provider_boots`] is the test playing that hypervisor.
    from_outside: RefCell<BTreeSet<String>>,
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
            etcd_late: RefCell::new(BTreeMap::new()),
            keeps_the_record: RefCell::new(BTreeSet::new()),
            from_outside: RefCell::new(BTreeSet::new()),
            asked: RefCell::new(Vec::new()),
        }
    }

    /// This host has no boot loader: what it RUNS follows an activation and
    /// what it BOOTED does not (lane 3-integration).
    fn boots_from_outside(self, id: &str) -> TableLook {
        self.from_outside.borrow_mut().insert(id.to_string());
        self
    }

    /// The test as the provider: the bundle was loaded and the machine was
    /// restarted, so from now on it answers with what the release says it
    /// booted.
    fn provider_boots(&self, id: &str) {
        self.from_outside.borrow_mut().remove(id);
    }

    /// The new system of this host comes up with a unit that failed.
    fn breaks(self, id: &str) -> TableLook {
        self.broken.borrow_mut().insert(id.to_string());
        self
    }

    // --- lane 4A ---
    /// Between the plan and the run, this host's store filled up. The plan
    /// was made when there was room; the preflight is the look that finds
    /// out there is none.
    fn ran_out_of_room(mut self, id: &str) -> TableLook {
        for map in [&mut self.before, &mut self.after] {
            if let Some(obs) = map.get_mut(id) {
                obs.disk_free_nix_bytes = Some(1);
            }
        }
        self
    }
    // --- end lane 4A ---

    /// This host's activation leaves a pending transaction behind, as a
    /// real one does until somebody confirms it.
    fn keeps_the_record(self, id: &str, txn: &str, top: &str) -> TableLook {
        self.keeps_the_record.borrow_mut().insert(id.to_string());
        self.txns.borrow_mut().insert(
            format!("pending:{id}"),
            Txn {
                id: txn.to_string(),
                state: TxnState::Pending,
                target_system: Some(top.to_string()),
                deadline: Some(at("2026-09-22T12:05:00Z")),
                run_id: Some(txn.to_string()),
            },
        );
        self
    }

    // --- lane 4A ---
    /// This host's etcd answers only after `looks` more looks — which is
    /// what a controller does after a reboot: sshd is up seconds before
    /// the database is.
    fn etcd_late(self, id: &str, looks: u32) -> TableLook {
        self.etcd_late.borrow_mut().insert(id.to_string(), looks);
        self
    }
    // --- end lane 4A ---

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
        // A guest whose kernel is loaded from outside: the switch moved its
        // userland, and its boot is still the one the provider last started
        // it with.
        if phase == Phase::After && self.from_outside.borrow().contains(&id) {
            obs.booted_system = self.before[&id].booted_system.clone();
            obs.kernel_booted = self.before[&id].kernel_booted.clone();
        }
        if phase == Phase::After && self.broken.borrow().contains(&id) {
            obs.units
                .insert("meister-agent.service".to_string(), "failed".to_string());
        }
        // --- lane 4A ---
        // A member that has not answered yet reports no members at all,
        // which is what `observe::etcd_view` makes of a unit that is not
        // active.
        if let Some(left) = self.etcd_late.borrow_mut().get_mut(&id)
            && *left > 0
        {
            *left -= 1;
            obs.etcd = Some(crate::observation::EtcdView {
                member_id: None,
                healthy: false,
                members: Vec::new(),
            });
        }
        // --- end lane 4A ---
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
        let out = self.inner.run(cmd);
        // A command whose CONNECTION dropped — ssh's own 255 — still
        // happened on the far side. That is the case this fake exists to be
        // able to show, and it is what an activation over ssh does to its
        // own connection.
        let happened = match &out {
            Ok(_) => true,
            Err(e) => format!("{e:#}").contains("exited 255"),
        };
        if !happened {
            return out;
        }
        // Which host this was about: the ssh destination, `root@10.0.0.11`.
        let host = cmd
            .args
            .iter()
            .find_map(|a| a.strip_prefix("root@"))
            .and_then(address_to_host);
        // The quotes come off first: an argument that crosses an ssh is
        // quoted for the shell on the other side, so the reboot arrives
        // here as `'systemctl reboot'`. Whole words all the same —
        // `meister-activate` is not an `activate`.
        let says = |word: &str| cmd.args.iter().any(|a| a.trim_matches('\'') == word);
        if let Some(host) = host {
            if says("activate") {
                self.look.set(&host, Phase::After);
                if self.look.keeps_the_record.borrow().contains(&host) {
                    let record = self
                        .look
                        .txns
                        .borrow()
                        .get(&format!("pending:{host}"))
                        .cloned();
                    if let Some(record) = record {
                        self.look.txns.borrow_mut().insert(host.clone(), record);
                    }
                } else {
                    self.look.txns.borrow_mut().remove(&host);
                }
            } else if says("confirm") {
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
        out
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

    /// The same, with `n1` turned into a guest whose hypervisor loads its
    /// kernel — and a release that changes exactly that (lane
    /// 3-integration).
    fn changing_direct(new_kernel: bool) -> Fixture {
        let base = crate::fixtures::with_direct_host(onebox_enrolled(), "n1");
        let before = crate::fixtures::direct_release_of(base.clone());
        let observation = observed(&before, at(NOW));
        let release = crate::fixtures::direct_release_of(crate::fixtures::with_new_toplevels(
            base,
            &["n1"],
            new_kernel,
        ));
        // The whole fleet, not only `n1`: the control-plane host is the
        // fleet's anchor (D6) whether it changes or not, and a selection
        // that leaves it out leaves the anchor out with it.
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
    // Quoted, because ssh joins its arguments and the remote shell splits
    // them again — see [`crate::transport::Ssh::exec`].
    out.push(crate::run::shell_quote("systemctl reboot"));
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
            // Two commands, because a rollout took two things: the drain
            // and the cordon. `node uncordon` gives back only the second.
            .expect(cli("undrain", "n1"), Output::stdout(""))
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

    // --- lane 4A ---
    // And the preflight wrote down WHAT it checked, so that a receipt read
    // a week later says which machine this release went onto and not only
    // that somebody looked.
    let preflight = applied.receipt.hosts["n1"]
        .actions
        .iter()
        .find(|a| a.kind == ActionKind::Preflight)
        .expect("n1 has a preflight");
    let evidence = preflight.evidence.join(" ");
    assert!(evidence.contains("free for a closure of"), "{evidence}");
    assert!(evidence.contains("has /dev/kvm"), "{evidence}");
    // --- end lane 4A ---

    // --- lane 5C ---
    // And the journal replays into itself. Every run of lab lane L2 ended
    // with "entry N says box left the state activating and the journal had
    // it in staged; a line is missing", because `activating` only ever
    // reached this process's memory. A journal that cannot be folded
    // without a break is a journal a resume cannot trust.
    let states: Vec<String> = fx
        .journal_lines("run-1")
        .into_iter()
        .filter(|e| e.event == EventKind::HostState && e.host.as_deref() == Some("n1"))
        .map(|e| e.to.unwrap_or_default())
        .collect();
    assert_eq!(
        states,
        [
            "preflight",
            "staged",
            "maintenance-ready",
            "activating",
            "verifying",
            "committed"
        ],
        "the machine of §6, line by line"
    );
    let folded = crate::receipt::fold(&fx.journal_lines("run-1")).expect("it folds");
    assert!(
        folded.breaks.is_empty(),
        "a finished rollout left a hole in its own journal: {:?}",
        folded.breaks
    );
    // --- end lane 5C ---
}

// --- lane 4C: the cache is a shortcut inside the copy --------------------

/// The fleet, changed on `n1`, with a release that was pushed into a cache.
///
/// `build_env` is NOT part of `release_id` (a release built on a laptop and
/// one built on a farm are the same release), so saying where the closures
/// went afterwards is a statement about this release and not a different
/// one — which is what makes this two lines instead of a second fixture.
fn changing_with_a_cache(cache: Option<&str>) -> Fixture {
    let mut fx = Fixture::changing(&["n1"], false);
    fx.release.build_env.cache_url = cache.map(str::to_string);
    fx
}

#[test]
fn a_target_that_names_substituters_is_allowed_to_fetch_what_it_can() {
    let fx = changing_with_a_cache(Some("file:///srv/cache"));
    // The fixture's `n1` names a cache and the other two do not, which is
    // what makes this a property of the HOST and not of the release.
    assert_eq!(
        fx.release.resolved_fleet.hosts["n1"].substituters,
        vec!["http://box.lab:8080/cache".to_string()]
    );
    let top = fx.top("n1");
    let look = TableLook::new(&fx);
    let runner = World::new(
        StrictFake::new()
            .expect(helper("box", &["lock", "acquire"]), ok())
            .expect(helper("n1", &["lock", "acquire"]), ok())
            .expect(
                Matcher::exact(
                    "nix",
                    [
                        "copy",
                        "--substitute-on-destination",
                        "--to",
                        "ssh-ng://root@10.0.0.11",
                        &top,
                    ],
                ),
                Output::stdout(""),
            )
            .expect(
                Matcher::prefix("nix", ["path-info"]),
                Output::stdout(fx.path_info("n1")),
            )
            .expect(helper("n1", &["stage"]), ok())
            .expect(cli("cordon", "n1"), Output::stdout(""))
            .expect(cli("drain", "n1"), Output::stdout(""))
            .expect(helper("n1", &["activate"]), ok())
            .expect(helper("n1", &["confirm", "--txn", "run-1"]), ok())
            // Giving a host back is two commands since the integration lane:
            // the drain and the cordon (see the tests above).
            .expect(cli("undrain", "n1"), Output::stdout(""))
            .expect(cli("uncordon", "n1"), Output::stdout(""))
            .expect(helper("n1", &["txn", "retire"]), ok())
            .expect(helper("n1", &["lock", "release"]), ok())
            .expect(helper("box", &["lock", "release"]), ok()),
        &look,
    );
    let applied = fx
        .executor(&runner, &look, fx.options())
        .run()
        .expect("the rollout runs");
    runner.verify().expect("every expectation was used");
    assert_eq!(applied.receipt.hosts["n1"].outcome, HostOutcome::Success);

    // What arrived is still compared against the release: the cache is a
    // road and never an exception.
    let evidence: Vec<String> = applied.receipt.hosts["n1"]
        .actions
        .iter()
        .flat_map(|a| a.evidence.clone())
        .collect();
    assert!(
        evidence.iter().any(|e| e.contains("as the release says")),
        "{evidence:?}"
    );
    // And the receipt says the target was allowed to fetch, with the store
    // its own configuration names.
    assert!(
        evidence
            .iter()
            .any(|e| e.contains("allowed to fetch") && e.contains("http://box.lab:8080/cache")),
        "{evidence:?}"
    );
}

/// One changed host, one plain `nix copy`, asserted exactly.
fn a_plain_copy_is_what_happens(fx: Fixture, id: &str, address: &str) {
    let top = fx.top(id);
    let look = TableLook::new(&fx);
    let runner = World::new(
        StrictFake::new()
            .expect(helper("box", &["lock", "acquire"]), ok())
            .expect(helper(id, &["lock", "acquire"]), ok())
            .expect(
                Matcher::exact(
                    "nix",
                    ["copy", "--to", &format!("ssh-ng://root@{address}"), &top],
                ),
                Output::stdout(""),
            )
            .expect(
                Matcher::prefix("nix", ["path-info"]),
                Output::stdout(fx.path_info(id)),
            )
            .expect(helper(id, &["stage"]), ok())
            .expect(cli("cordon", id), Output::stdout(""))
            .expect(cli("drain", id), Output::stdout(""))
            .expect(helper(id, &["activate"]), ok())
            .expect(helper(id, &["confirm", "--txn", "run-1"]), ok())
            // Giving a host back is two commands since the integration lane:
            // the drain and the cordon (see the tests above).
            .expect(cli("undrain", id), Output::stdout(""))
            .expect(cli("uncordon", id), Output::stdout(""))
            .expect(helper(id, &["txn", "retire"]), ok())
            .expect(helper(id, &["lock", "release"]), ok())
            .expect(helper("box", &["lock", "release"]), ok()),
        &look,
    );
    fx.executor(&runner, &look, fx.options())
        .run()
        .expect("the rollout runs");
    runner.verify().expect("every expectation was used");
}

#[test]
fn a_release_that_went_into_no_cache_asks_the_target_to_fetch_nothing() {
    // `n1` names a substituter and the release names no cache: there is
    // nothing out there to fetch, so asking the far store to try would be a
    // round trip for nothing.
    let fx = changing_with_a_cache(None);
    assert!(
        !fx.release.resolved_fleet.hosts["n1"]
            .substituters
            .is_empty()
    );
    a_plain_copy_is_what_happens(fx, "n1", "10.0.0.11");
}

#[test]
fn a_target_that_names_no_substituter_is_pushed_to_even_when_there_is_a_cache() {
    // The other half: a cache exists and THIS host fetches from nowhere, so
    // the whole closure comes over ssh — which is the default and the
    // smaller attack surface.
    let mut fx = Fixture::changing(&["n2"], false);
    fx.release.build_env.cache_url = Some("file:///srv/cache".to_string());
    assert!(
        fx.release.resolved_fleet.hosts["n2"]
            .substituters
            .is_empty()
    );
    a_plain_copy_is_what_happens(fx, "n2", "10.0.0.12");
}

// --- end lane 4C ---------------------------------------------------------

#[test]
fn an_activation_whose_connection_died_is_decided_by_the_host_and_not_by_ssh() {
    // The case the VM test found: `switch-to-configuration` restarts sshd
    // and the network under the very connection that started it, so the
    // activation succeeds and the ssh comes back 255 with nothing to say.
    // What decides is the transaction record on the target.
    let fx = Fixture::changing(&["n1"], false);
    let look = TableLook::new(&fx).keeps_the_record("n1", "run-1", &fx.top("n1"));
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
                helper("n1", &["activate"]),
                // ssh's own code for "the connection went away", and
                // nothing on stderr — `LogLevel=ERROR` swallows the rest.
                Output::failing(255, ""),
            )
            .expect(helper("n1", &["confirm", "--txn", "run-1"]), ok())
            // Two commands, because a rollout took two things: the drain
            // and the cordon. `node uncordon` gives back only the second.
            .expect(cli("undrain", "n1"), Output::stdout(""))
            .expect(cli("uncordon", "n1"), Output::stdout(""))
            .expect(helper("n1", &["txn", "retire"]), ok())
            .expect(helper("n1", &["lock", "release"]), ok())
            .expect(helper("box", &["lock", "release"]), ok()),
        &look,
    );
    let applied = fx
        .executor(&runner, &look, fx.options())
        .run()
        .expect("the rollout runs");
    assert_eq!(applied.stopped, None, "{:?}", applied.stopped);
    runner.verify().expect("every expectation was used");
    assert_eq!(applied.receipt.hosts["n1"].outcome, HostOutcome::Success);
    // And the receipt says what happened rather than hiding it.
    let evidence: Vec<String> = applied.receipt.hosts["n1"]
        .actions
        .iter()
        .flat_map(|a| a.evidence.clone())
        .collect();
    assert!(
        evidence
            .iter()
            .any(|e| e.contains("did not survive the switch")),
        "{evidence:?}"
    );
    assert!(
        !runner.calls().iter().any(|c| c.contains("revert")),
        "a host that had activated was taken back: {:?}",
        runner.calls()
    );
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
            // Two commands, because a rollout took two things: the drain
            // and the cordon. `node uncordon` gives back only the second.
            .expect(cli("undrain", "n1"), Output::stdout(""))
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

// --- lane 5C ---

/// A journal of a run in which `n1` went all the way through and gave its
/// lock and its transaction record back — which is what the `unlock` step
/// does, and therefore what a resume finds on the target: nothing.
fn write_finished_host_journal(fx: &Fixture, run: &str, given_back: bool) {
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
    put(journal
        .event(EventKind::LockAcquire, at(NOW))
        .host("n1")
        .payload(serde_json::json!({"run_id": run})));
    let activate = fx
        .plan
        .actions_for("n1")
        .into_iter()
        .find(|a| a.kind == ActionKind::Activate)
        .expect("there is one")
        .seq;
    for (from, to) in [
        (HostState::Planned, HostState::Preflight),
        (HostState::Preflight, HostState::Staged),
        (HostState::Staged, HostState::MaintenanceReady),
        (HostState::MaintenanceReady, HostState::Activating),
    ] {
        put(journal
            .event(EventKind::HostState, at(NOW))
            .host("n1")
            .transition(from, to)
            .payload(serde_json::json!({})));
    }
    put(journal
        .event(EventKind::ActionBegin, at(NOW))
        .host("n1")
        .payload(serde_json::json!({"action": activate, "kind": "activate"})));
    put(journal
        .event(EventKind::ActionIrreversible, at(NOW))
        .host("n1")
        .payload(serde_json::json!({"action": activate, "kind": "activate", "txn": run})));
    put(journal
        .event(EventKind::ActionEnd, at(NOW))
        .host("n1")
        .payload(serde_json::json!({"action": activate, "kind": "activate", "result": "ok"})));
    for (from, to) in [
        (HostState::Activating, HostState::Verifying),
        (HostState::Verifying, HostState::Committed),
    ] {
        put(journal
            .event(EventKind::HostState, at(NOW))
            .host("n1")
            .transition(from, to)
            .payload(serde_json::json!({})));
    }
    // The `unlock` step: the record is retired on the target and the lock
    // goes back. After this the target has NO transaction for this run.
    //
    // Astra finding F06, 2026-09-23: this used to be the `lock.release`
    // line alone, which is not what the executor writes — every step
    // carries an `action.begin` and an `action.end` around what it does.
    // The difference matters now, because "did this run give the host back"
    // is read off the `unlock` step's own end: the bare `lock.release` that
    // the safety net `release_locks` writes at the end of EVERY run cannot
    // tell a finished host from an abandoned one.
    if given_back {
        let unlock = fx
            .plan
            .actions_for("n1")
            .into_iter()
            .find(|a| a.kind == ActionKind::Unlock)
            .expect("a host that is taken forward is given back")
            .seq;
        put(journal
            .event(EventKind::ActionBegin, at(NOW))
            .host("n1")
            .payload(serde_json::json!({"action": unlock, "kind": "unlock"})));
        put(journal
            .event(EventKind::LockRelease, at(NOW))
            .host("n1")
            .payload(serde_json::json!({"run_id": run})));
        put(journal
            .event(EventKind::ActionEnd, at(NOW))
            .host("n1")
            .payload(serde_json::json!({"action": unlock, "kind": "unlock", "result": "ok"})));
    }
    // And here the run stopped, before its `run.end` — a halt in front of
    // another host's provider reboot, which is how lab lane L2 got here.
}

#[test]
fn a_resume_reads_a_host_this_run_already_finished_as_finished() {
    // L2 finding N7, second half. A run over two hosts that boot through
    // their provider halts once per host. At the second resume `n1` was
    // `committed` and its record was gone, and the table read that as "an
    // irreversible step began and the target has no transaction record for
    // it" — so the second resume refused the whole run and there was no
    // supported way to finish it.
    let fx = Fixture::changing(&["n1"], false);
    write_finished_host_journal(&fx, "run-1", true);
    let look = TableLook::new(&fx);
    // The machine is where the journal says it is.
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
        .expect("the resume runs");
    runner.verify().expect("nothing was done to n1");
    assert_eq!(applied.stopped, None, "the resume stopped: {applied:?}");
    assert_eq!(applied.receipt.hosts["n1"].outcome, HostOutcome::Success);
    assert_eq!(applied.receipt.hosts["n1"].state, HostState::Committed);
    assert!(
        !runner.calls().iter().any(|c| c.contains("activate --txn")),
        "an activation was repeated: {:?}",
        runner.calls()
    );
}

// Astra finding F06, 2026-09-23.
#[test]
fn a_resume_of_a_confirmed_but_uncleaned_host_uncordons_and_retires() {
    // The host is `committed` — the confirm put it there — and the run
    // stopped before its `uncordon` and its `unlock`. That was read as a
    // host with nothing left to do, so the resume walked past both: the
    // machine stayed cordoned, so nothing was scheduled onto it, and its
    // transaction record stayed open, which is what makes the NEXT plan
    // refuse to start.
    let fx = Fixture::changing(&["n1"], false);
    write_finished_host_journal(&fx, "run-1", false);
    let look = TableLook::new(&fx).carrying(
        "n1",
        Txn {
            id: "run-1".to_string(),
            state: TxnState::Confirmed,
            target_system: Some(fx.top("n1")),
            deadline: None,
            run_id: Some("run-1".to_string()),
        },
    );
    look.set("n1", Phase::After);
    let runner = World::new(
        StrictFake::new()
            .expect(helper("box", &["lock", "acquire"]), ok())
            .expect(helper("n1", &["lock", "acquire"]), ok())
            // What was left, and only what was left.
            .expect(cli("undrain", "n1"), Output::stdout(""))
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
    runner.verify().expect("every expectation was used");
    assert_eq!(applied.stopped, None, "the resume stopped: {applied:?}");
    assert_eq!(applied.receipt.hosts["n1"].state, HostState::Committed);
    assert_eq!(applied.receipt.hosts["n1"].outcome, HostOutcome::Success);
    // And nothing before the confirm was touched.
    for repeated in ["activate --txn", "nix copy", "confirm --txn"] {
        assert!(
            !runner.calls().iter().any(|c| c.contains(repeated)),
            "{repeated} was repeated: {:?}",
            runner.calls()
        );
    }
}

// Astra finding F19, 2026-09-23.
#[test]
fn a_resume_after_a_completed_reboot_does_not_reboot_again() {
    // The machine went round and came back as the system the plan wants,
    // and the run stopped before the confirm. `reboot` was not in the set a
    // resume skips, and `wait_for_boot` only asks whether the booted system
    // is the wanted one — which it is — so the resume sent `systemctl
    // reboot` again. In `mode boot` that boots the OLD generation, because
    // the one-shot is spent and the confirm that makes the new one the
    // default has not run: a rollout one step from done undeployed itself.
    let fx = Fixture::changing(&["n1"], true);
    assert!(
        kinds(&fx.plan, "n1").contains(&ActionKind::Reboot),
        "a changed kernel is a reboot class: {:?}",
        kinds(&fx.plan, "n1")
    );
    write_rebooted_journal(&fx, "run-1");
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
    // The machine is back on what it booted, which is what it had to boot.
    look.set("n1", Phase::After);
    let runner = World::new(
        StrictFake::new()
            .expect(helper("box", &["lock", "acquire"]), ok())
            .expect(helper("n1", &["lock", "acquire"]), ok())
            .expect(helper("n1", &["confirm", "--txn", "run-1"]), ok())
            .expect(cli("undrain", "n1"), Output::stdout(""))
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
    runner.verify().expect("every expectation was used");
    assert_eq!(applied.stopped, None, "the resume stopped: {applied:?}");
    assert_eq!(applied.receipt.hosts["n1"].outcome, HostOutcome::Success);
    assert!(
        !runner
            .calls()
            .iter()
            .any(|c| c.contains("systemctl reboot")),
        "the machine was rebooted a second time: {:?}",
        runner.calls()
    );
}

// Astra finding F19, 2026-09-23.
#[test]
fn a_resume_of_a_host_that_was_switched_and_never_booted_still_boots_it() {
    // The other side of the same condition, and the reason it is read off
    // the journal rather than set for every resume: a host whose run died
    // between the activation and the reboot still has to go round.
    let fx = Fixture::changing(&["n1"], true);
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
            .expect(reboot_of("n1"), Output::stdout(""))
            .expect(helper("n1", &["confirm", "--txn", "run-1"]), ok())
            .expect(cli("undrain", "n1"), Output::stdout(""))
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
    runner.verify().expect("the reboot was sent");
    assert_eq!(applied.stopped, None, "the resume stopped: {applied:?}");
    assert_eq!(applied.receipt.hosts["n1"].outcome, HostOutcome::Success);
}

#[test]
fn a_takeover_reaches_the_anchor_host_twice_and_that_is_the_point() {
    // The shape behind L2 finding N8, pinned where it is decided rather
    // than by walking a whole rollout: `box` is a control-plane host, so
    // it is the fleet anchor (D6) AND — when the release changes it — a
    // host with a `lock` step of its own. Both go through `lock_cmd`, so
    // under `--takeover` the SAME `lock take-over --of-run <old>` reaches
    // that host twice.
    //
    // The second call finds the host held by the run that is doing the
    // taking. In the lab that was the end of the rollout: "this host is
    // held by the run <new>, not by <old>. Nothing was taken over."
    // tools/meister-deploy/src/activate.rs answers yes to it now.
    let fx = Fixture::changing(&["box"], false);
    let look = TableLook::new(&fx);
    let runner = World::new(StrictFake::new(), &look);
    let mut options = fx.options();
    options.takeover = Some("run-0".to_string());
    let executor = fx.executor(&runner, &look, options);
    assert!(
        executor.anchor_hosts().contains(&"box".to_string()),
        "box is a cloud and a cluster, so it is the fleet anchor"
    );
    assert!(
        kinds(&fx.plan, "box").contains(&ActionKind::Lock),
        "and the release changes it, so it has a lock step of its own"
    );
    let anchor = executor.lock_cmd("box").expect("the anchor's command");
    let step = executor.lock_cmd("box").expect("the step's command");
    assert_eq!(anchor.line(), step.line(), "one command, taken twice");
    assert!(
        anchor.line().contains("lock take-over --of-run run-0"),
        "{}",
        anchor.line()
    );
}

// --- end lane 5C ---

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
            // Two commands, because a rollout took two things: the drain
            // and the cordon. `node uncordon` gives back only the second.
            .expect(cli("undrain", "n1"), Output::stdout(""))
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

/// A reboot-class host that activated, went round, came back — and then the
/// run stopped, before the verify and before the confirm.
///
/// Astra finding F19, 2026-09-23: this is the window in which a resume used
/// to send `systemctl reboot` a second time.
fn write_rebooted_journal(fx: &Fixture, run: &str) {
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
    let seq_of = |kind: ActionKind| {
        fx.plan
            .actions_for("n1")
            .into_iter()
            .find(|a| a.kind == kind)
            .unwrap_or_else(|| panic!("the plan has a {kind}"))
            .seq
    };
    put(journal
        .event(EventKind::RunStart, at(NOW))
        .payload(serde_json::json!({"operator": {"user": "silas", "workstation": "manacor"}})));
    put(journal
        .event(EventKind::LockAcquire, at(NOW))
        .host("n1")
        .payload(serde_json::json!({"run_id": run})));
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
    let activate = seq_of(ActionKind::Activate);
    put(journal
        .event(EventKind::ActionBegin, at(NOW))
        .host("n1")
        .payload(serde_json::json!({"action": activate, "kind": "activate"})));
    put(journal
        .event(EventKind::ActionIrreversible, at(NOW))
        .host("n1")
        .payload(serde_json::json!({"action": activate, "kind": "activate", "txn": run})));
    put(journal
        .event(EventKind::HostState, at(NOW))
        .host("n1")
        .transition(HostState::MaintenanceReady, HostState::Activating)
        .payload(serde_json::json!({})));
    put(journal
        .event(EventKind::ActionEnd, at(NOW))
        .host("n1")
        .payload(serde_json::json!({"action": activate, "kind": "activate", "result": "ok"})));
    put(journal
        .event(EventKind::HostState, at(NOW))
        .host("n1")
        .transition(HostState::Activating, HostState::AwaitingReboot)
        .payload(serde_json::json!({})));
    // The reboot, whole: the `action.end` is written only after
    // `wait_for_boot` has seen the machine come back as what it had to be.
    let reboot = seq_of(ActionKind::Reboot);
    put(journal
        .event(EventKind::ActionBegin, at(NOW))
        .host("n1")
        .payload(serde_json::json!({"action": reboot, "kind": "reboot"})));
    put(journal
        .event(EventKind::ActionEnd, at(NOW))
        .host("n1")
        .payload(serde_json::json!({"action": reboot, "kind": "reboot", "result": "ok"})));
    put(journal
        .event(EventKind::HostState, at(NOW))
        .host("n1")
        .transition(HostState::AwaitingReboot, HostState::Verifying)
        .payload(serde_json::json!({})));
    // And here the operator pressed ctrl-c: no verify, no confirm.
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

// ---------------------------------------------------------------------------
// lane 3B: deliver-secret
// ---------------------------------------------------------------------------

/// One host, one file to put there, and the operator's own copy of it on a
/// fake disk.
///
/// `host=n1` and not the whole fleet: what these tests are about is the
/// step, and a plan over one host is a plan whose every command is one of
/// its own. The identity key of the fixture is `target-generated` and never
/// travels, which is half of what is being shown.
fn delivering() -> (Fixture, String) {
    let release = release_of(onebox_enrolled());
    let mut observation = observed(&release, at(NOW));
    // n1 has never been handed the fleet's CA certificate.
    let n1 = observation
        .hosts
        .get_mut("n1")
        .expect("n1 is in the fixture");
    n1.credentials.insert("ca-bundle".to_string(), None);
    let expected = crate::fixtures::expected_credentials(&release.resolved_fleet);
    let plan = plan(
        &release,
        "host=n1",
        &observation,
        None,
        &crate::fixtures::plan_policy(PlanKind::Upgrade).with_expected_credentials(expected),
        at(NOW),
    )
    .expect("the fixture plans");
    let contents = "a certificate authority\n".to_string();
    let fx = Fixture {
        release,
        plan,
        // The CA's own file where `[operator] ca_dir` says it is.
        files: MemFiles::new().given("/ca/ca.crt", contents.clone()),
        clock: FakeClock::at(at(NOW)),
        state: StateDir::at("/repo/.meister-deploy"),
        ssh: Ssh::with_known_hosts("/repo/known_hosts"),
    };
    (fx, contents)
}

/// The `ssh … sh -c '<script>'` a put or a question arrives as.
fn shell_on(id: &str, script: &str) -> Matcher {
    let address = match id {
        "box" => "10.0.0.10",
        "n1" => "10.0.0.11",
        _ => "10.0.0.12",
    };
    let mut out = Ssh::with_known_hosts("/repo/known_hosts").opts(22);
    out.push(format!("root@{address}"));
    out.push("sh".to_string());
    out.push("-c".to_string());
    out.push(crate::run::shell_quote(script));
    Matcher::exact("ssh", out)
}

fn deliver_options(fx: &Fixture) -> ApplyOptions {
    let mut options = fx.options();
    options.repo = PathBuf::from("/repo");
    options.ca_dir = Some(PathBuf::from("/ca"));
    options
}

const PUT_SCRIPT: &str = "set -e; d=$(dirname /var/lib/meisterstack/pki/ca.crt); mkdir -p \"$d\"; \
                          t=$(mktemp \"$d/.meister.XXXXXX\"); cat > \"$t\"; chown root:root \"$t\"; \
                          chmod 0644 \"$t\"; mv \"$t\" /var/lib/meisterstack/pki/ca.crt";

const SHA_SCRIPT: &str = "sha256sum /var/lib/meisterstack/pki/ca.crt 2>/dev/null | cut -d' ' -f1";

/// The commands one delivery is, in order: the lock, the put, the question,
/// the lock back.
fn delivery_runner<'a>(look: &'a TableLook, answer: Output) -> World<'a> {
    World::new(
        StrictFake::new()
            .expect(helper("n1", &["lock", "acquire"]), ok())
            .expect(shell_on("n1", PUT_SCRIPT), ok())
            .expect(shell_on("n1", SHA_SCRIPT), answer)
            .expect(helper("n1", &["lock", "release"]), ok()),
        look,
    )
}

/// The whole step: the file goes over, the HOST is asked what it now has,
/// and the digest it answers with is the evidence.
#[test]
fn a_secret_is_put_there_and_the_host_says_what_it_has() {
    let (fx, contents) = delivering();
    let digest = crate::ids::sha256_hex(contents.as_bytes());
    let look = TableLook::new(&fx);
    let runner = delivery_runner(&look, Output::stdout(format!("{digest}\n")));
    let applied = fx
        .executor(&runner, &look, deliver_options(&fx))
        .run()
        .expect("a delivery applies");
    runner.verify().expect("exactly those commands");

    assert_eq!(applied.receipt.outcome, Outcome::Success);
    assert_eq!(applied.receipt.hosts["n1"].outcome, HostOutcome::Success);
    let steps: Vec<ActionKind> = applied.receipt.hosts["n1"]
        .actions
        .iter()
        .map(|a| a.kind)
        .collect();
    assert_eq!(
        steps,
        [
            ActionKind::Preflight,
            ActionKind::Lock,
            ActionKind::DeliverSecret,
            ActionKind::Verify,
            ActionKind::Unlock
        ],
        "nothing was staged and nothing was activated"
    );
    // The evidence is the digest the HOST computed.
    let evidence = applied.receipt.hosts["n1"]
        .actions
        .iter()
        .find(|a| a.kind == ActionKind::DeliverSecret)
        .expect("the step is in the receipt")
        .evidence
        .join(" ");
    assert!(evidence.contains(&format!("sha256:{digest}")), "{evidence}");
    assert!(
        evidence.contains("/var/lib/meisterstack/pki/ca.crt"),
        "{evidence}"
    );
}

/// The content travels on stdin and out of everything this run writes down.
#[test]
fn what_was_sent_is_not_in_the_journal() {
    let (fx, contents) = delivering();
    let digest = crate::ids::sha256_hex(contents.as_bytes());
    let look = TableLook::new(&fx);
    let runner = delivery_runner(&look, Output::stdout(format!("{digest}\n")));
    fx.executor(&runner, &look, deliver_options(&fx))
        .run()
        .expect("it applies");
    runner.verify().unwrap();

    // Not in the command lines this run saw…
    for call in runner.calls() {
        assert!(!call.contains("a certificate authority"), "{call}");
    }
    // …and not in the journal it wrote. The redaction is a whole-string
    // replacement (`transport::Ssh::put`), so what stands there is `***`.
    let journal = String::from_utf8(
        fx.files
            .content(fx.state.journal_path("run-1"))
            .expect("a journal was written"),
    )
    .unwrap();
    assert!(!journal.contains("a certificate authority"), "{journal}");
    assert!(journal.contains("deliver-secret"), "{journal}");
    // And no `action.irreversible`: replacing a file can be taken back by
    // writing the old one, and that line means something.
    let kinds: Vec<EventKind> = fx
        .journal_lines("run-1")
        .into_iter()
        .map(|e| e.event)
        .collect();
    assert!(!kinds.contains(&EventKind::ActionIrreversible), "{kinds:?}");
}

/// A file this workstation does not have is not a file it sends, and the
/// sentence names the verb that makes it.
#[test]
fn a_certificate_nobody_issued_stops_the_step_before_the_connection() {
    let (fx, _) = delivering();
    // The operator's disk is empty after all.
    let fx = Fixture {
        files: MemFiles::new(),
        ..fx
    };
    let look = TableLook::new(&fx);
    let runner = World::new(
        StrictFake::new()
            .expect(helper("n1", &["lock", "acquire"]), ok())
            .expect(helper("n1", &["lock", "release"]), ok()),
        &look,
    );
    let applied = fx
        .executor(&runner, &look, deliver_options(&fx))
        .run()
        .expect("the run ends with a receipt");
    runner.verify().expect("nothing was put anywhere");
    assert_ne!(applied.receipt.outcome, Outcome::Success);
    let why = applied.stopped.unwrap_or_default();
    assert!(why.contains("/ca/ca.crt"), "{why}");
    assert!(why.contains("keys issue"), "{why}");
}

/// The host answered with a different digest than what was sent. Somebody
/// is between the two, and the run says so instead of calling it done.
#[test]
fn a_digest_the_host_does_not_agree_with_fails_the_step() {
    let (fx, _) = delivering();
    let look = TableLook::new(&fx);
    let runner = delivery_runner(
        &look,
        Output::stdout("0000000000000000000000000000000000000000000000000000000000000000\n"),
    );
    let applied = fx
        .executor(&runner, &look, deliver_options(&fx))
        .run()
        .expect("the run ends with a receipt");
    runner.verify().unwrap();
    assert_ne!(applied.receipt.outcome, Outcome::Success);
    let why = applied.stopped.unwrap_or_default();
    assert!(why.contains("Something is between the two"), "{why}");
}

/// A key the target made itself is never sent, whatever a plan says. The
/// refusal is in the executor as well as in the planner, because the
/// executor is the one that would have to read the file.
#[test]
fn a_key_the_target_made_is_never_delivered_even_if_a_plan_asks() {
    let (fx, _) = delivering();
    let look = TableLook::new(&fx);
    let runner = World::new(StrictFake::new(), &look);
    let executor = fx.executor(&runner, &look, deliver_options(&fx));
    let mut action = fx
        .plan
        .actions_for("n1")
        .into_iter()
        .find(|a| a.kind == ActionKind::DeliverSecret)
        .expect("the plan has one")
        .clone();
    // A step nobody would plan: the identity key of the fixture is
    // `target-generated`.
    action.desired = Some("identity at /var/lib/meisterstack/pki/identity.key".to_string());
    let err = executor.deliver("n1", &action).unwrap_err();
    assert!(err.to_string().contains("never travels"), "{err}");
    assert!(runner.calls().is_empty(), "{:?}", runner.calls());
    runner.verify().unwrap();
}

/// A unit that is running is restarted; one that is not is left alone —
/// which is what a bootstrap is, because the unit is waiting for the very
/// file being delivered.
///
/// Three cases and not two, and the third one was paid for in the lab
/// (lane L2, 2026-09-23): a fresh host still runs the generic image, which
/// has no roles and therefore does NOT HAVE the unit. `systemctl is-active`
/// answers 4 for a unit this machine does not know, prints `inactive`, and
/// the whole wave ended there — on the one host the bootstrap was about to
/// give that unit to.
#[test]
fn a_unit_is_poked_only_when_it_is_running() {
    for (running, code) in [(true, 0), (false, 3), (false, 4)] {
        // The same fleet, except that the CA certificate has a unit hanging
        // off it. (The fixture's own `ca-bundle` has no reload, which is
        // what the tests above pin.)
        let mut fleet = onebox_enrolled();
        for secret in fleet
            .hosts
            .get_mut("n1")
            .expect("n1 is in the fixture")
            .secret_refs
            .iter_mut()
            .filter(|s| s.id == "ca-bundle")
        {
            // A unit that is NOT one of this host's role units, so that
            // whether it runs is a question for the target alone and not
            // one the readiness checks also have an opinion about.
            secret.reload = Some(crate::manifest::Reload {
                unit: "meister-trust.service".to_string(),
                action: "restart".to_string(),
            });
        }
        fleet.manifest_id =
            crate::ids::content_id(crate::ids::IdKind::Manifest, &fleet).expect("it hashes");
        let release = release_of(fleet);
        let mut observation = observed(&release, at(NOW));
        observation
            .hosts
            .get_mut("n1")
            .expect("n1 is in the fixture")
            .credentials
            .insert("ca-bundle".to_string(), None);
        let expected = crate::fixtures::expected_credentials(&release.resolved_fleet);
        let plan = plan(
            &release,
            "host=n1",
            &observation,
            None,
            &crate::fixtures::plan_policy(PlanKind::Upgrade).with_expected_credentials(expected),
            at(NOW),
        )
        .expect("it plans");
        let contents = "a certificate authority\n".to_string();
        let digest = crate::ids::sha256_hex(contents.as_bytes());
        let fx = Fixture {
            release,
            plan,
            files: MemFiles::new().given("/ca/ca.crt", contents),
            clock: FakeClock::at(at(NOW)),
            state: StateDir::at("/repo/.meister-deploy"),
            ssh: Ssh::with_known_hosts("/repo/known_hosts"),
        };
        let look = TableLook::new(&fx);
        let mut fake = StrictFake::new()
            .expect(helper("n1", &["lock", "acquire"]), ok())
            .expect(shell_on("n1", PUT_SCRIPT), ok())
            .expect(
                shell_on("n1", SHA_SCRIPT),
                Output::stdout(format!("{digest}\n")),
            )
            .expect(
                shell_on("n1", "systemctl is-active meister-trust.service"),
                // systemd prints the state on stdout whatever it exits
                // with: `inactive` and 3 for a unit that is there and
                // stopped, `inactive` and 4 for one that is not there.
                Output {
                    status: code,
                    stdout: if running { "active\n" } else { "inactive\n" }.to_string(),
                    stderr: String::new(),
                },
            );
        if running {
            fake = fake.expect(
                Matcher::prefix("ssh", {
                    let mut out = Ssh::with_known_hosts("/repo/known_hosts").opts(22);
                    out.push("root@10.0.0.11".to_string());
                    out.push("systemctl".to_string());
                    out.push("restart".to_string());
                    out.push("meister-trust.service".to_string());
                    out
                }),
                ok(),
            );
        }
        let runner = World::new(fake.expect(helper("n1", &["lock", "release"]), ok()), &look);
        let applied = fx
            .executor(&runner, &look, deliver_options(&fx))
            .run()
            .expect("it applies");
        runner.verify().expect("exactly those commands");
        assert_eq!(
            applied.receipt.outcome,
            Outcome::Success,
            "running={running} code={code}"
        );

        let evidence = applied.receipt.hosts["n1"]
            .actions
            .iter()
            .find(|a| a.kind == ActionKind::DeliverSecret)
            .expect("the step is there")
            .evidence
            .join(" ");
        if running {
            assert!(
                evidence.contains("restart meister-trust.service"),
                "{evidence}"
            );
        } else {
            assert!(
                evidence.contains("was inactive and was left alone"),
                "{evidence}"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// lane 3-integration: the step this tool does not take
// ---------------------------------------------------------------------------

/// Everything a direct-boot host's rollout runs BEFORE the halt, in order.
/// The halt itself is what each of the three tests below does differently.
fn up_to_the_halt(fx: &Fixture) -> StrictFake {
    let top = fx.top("n1");
    StrictFake::new()
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
                    // The userland half, and only it: a boot-mode activation
                    // needs a boot menu, and this machine has none.
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
}

#[test]
fn a_direct_host_stops_in_front_of_its_provider_and_writes_the_bundle_down() {
    let fx = Fixture::changing_direct(true);
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
            ActionKind::ProviderReboot,
            ActionKind::Verify,
            ActionKind::Uncordon,
            ActionKind::Unlock,
        ],
        "these expectations are written for exactly this sequence"
    );
    let look = TableLook::new(&fx).boots_from_outside("n1");
    // The locks go back when the run ends, which a halt is: holding a fleet
    // while somebody arranges a hypervisor would be holding it for hours.
    let runner = World::new(
        up_to_the_halt(&fx)
            // In host order, because that is the order the run gives the
            // doors back in when it ends rather than when a host's own
            // `unlock` step runs — and this run's last host never got that
            // far.
            .expect(helper("box", &["lock", "release", "--run", "run-1"]), ok())
            .expect(helper("n1", &["lock", "release", "--run", "run-1"]), ok()),
        &look,
    );

    let applied = fx
        .executor(&runner, &look, fx.options())
        .run()
        .expect("a halt is an answer and not an error");
    runner.verify().expect("every expectation was used");

    // Nothing rebooted anything: no `systemctl reboot` and no second
    // activation anywhere in what this run ran.
    for call in runner.calls() {
        assert!(!call.contains("systemctl reboot"), "{call}");
    }

    let wait = applied
        .waiting
        .expect("the run says what it is waiting for");
    assert_eq!(wait.host, "n1");
    assert_eq!(wait.run_id, "run-1");
    let bundle = fx.release.artifacts["n1"]
        .direct_boot
        .clone()
        .expect("a direct host has a bundle");
    assert_eq!(wait.bundle, bundle);

    // The sentence names the three values and the way back.
    let said = wait.sentence();
    assert!(said.contains(&bundle.kernel.store_path), "{said}");
    assert!(said.contains(&bundle.initrd.store_path), "{said}");
    assert!(said.contains(&bundle.cmdline), "{said}");
    assert!(said.contains("apply --resume run-1"), "{said}");

    // …and the machine-readable form carries them as data.
    let json = wait.to_json();
    assert_eq!(json["waiting_for"], "provider-reboot");
    assert_eq!(json["host"], "n1");
    assert_eq!(json["resume"], "run-1");
    assert_eq!(json["bundle"]["cmdline"], bundle.cmdline);
    assert_eq!(
        json["bundle"]["kernel"]["store_path"],
        bundle.kernel.store_path
    );

    // The journal: the step began, it never ended, and the line that says
    // where the run stopped carries the bundle.
    let events = fx.journal_lines("run-1");
    let begun = events.iter().any(|e| {
        e.event == EventKind::ActionBegin
            && e.payload.get("kind").and_then(|k| k.as_str()) == Some("provider-reboot")
    });
    assert!(begun, "the step is in the journal");
    let ended = events.iter().any(|e| {
        e.event == EventKind::ActionEnd
            && e.payload.get("kind").and_then(|k| k.as_str()) == Some("provider-reboot")
    });
    assert!(!ended, "a step that did not happen has no end");
    let halt = events
        .iter()
        .find(|e| e.to.as_deref() == Some("awaiting-reboot"))
        .expect("the host is waiting for a reboot");
    assert_eq!(halt.host.as_deref(), Some("n1"));
    assert_eq!(
        halt.payload["waiting_for"].as_str(),
        Some("provider-reboot")
    );
    assert_eq!(halt.payload["bundle"]["cmdline"], bundle.cmdline);
    assert!(
        events.iter().any(|e| e.event == EventKind::RunEnd),
        "the run ended rather than hanging"
    );

    // The receipt says where it stopped and does not call it success.
    assert_eq!(applied.receipt.hosts["n1"].state, HostState::AwaitingReboot);
    assert_ne!(applied.receipt.outcome, Outcome::Success);
}

#[test]
fn a_resume_before_the_provider_has_been_halts_again_and_changes_nothing() {
    // The counter-probe the lane brief asks for: `apply --resume` BEFORE the
    // provider did its half is the same answer again, not a reboot and not a
    // failure.
    let fx = Fixture::changing_direct(true);
    let look = TableLook::new(&fx).boots_from_outside("n1");
    let runner = World::new(
        up_to_the_halt(&fx)
            .expect(helper("box", &["lock", "release", "--run", "run-1"]), ok())
            .expect(helper("n1", &["lock", "release", "--run", "run-1"]), ok()),
        &look,
    );
    let first = fx
        .executor(&runner, &look, fx.options())
        .run()
        .expect("the first run halts");
    runner.verify().expect("every expectation was used");
    assert!(first.waiting.is_some());

    // The machine still boots what it booted. The resume takes the locks
    // again, asks, and stops at the same place — no stage, no activation,
    // no confirmation.
    let mut options = fx.options();
    options.resume = true;
    let look = TableLook::new(&fx).boots_from_outside("n1");
    look.set("n1", Phase::After);
    let runner = World::new(
        StrictFake::new()
            .expect(helper("box", &["lock", "acquire", "--run", "run-1"]), ok())
            .expect(helper("n1", &["lock", "acquire", "--run", "run-1"]), ok())
            .expect(helper("box", &["lock", "release", "--run", "run-1"]), ok())
            .expect(helper("n1", &["lock", "release", "--run", "run-1"]), ok()),
        &look,
    );
    let again = fx
        .executor(&runner, &look, options)
        .run()
        .expect("a second halt is an answer too");
    runner.verify().expect("nothing but the doors");
    let wait = again.waiting.expect("it is still waiting");
    assert_eq!(wait.host, "n1");
    for call in runner.calls() {
        // `meister-activate` is the name of the helper, so the word to look
        // for is the SUBCOMMAND.
        assert!(!call.contains("--json activate"), "{call}");
        assert!(!call.contains("--json stage"), "{call}");
        assert!(!call.contains("systemctl reboot"), "{call}");
    }
    assert_eq!(again.receipt.hosts["n1"].state, HostState::AwaitingReboot);
}

#[test]
fn a_resume_after_the_provider_has_been_asks_the_machine_and_finishes() {
    let fx = Fixture::changing_direct(true);
    let look = TableLook::new(&fx).boots_from_outside("n1");
    let runner = World::new(
        up_to_the_halt(&fx)
            .expect(helper("box", &["lock", "release", "--run", "run-1"]), ok())
            .expect(helper("n1", &["lock", "release", "--run", "run-1"]), ok()),
        &look,
    );
    fx.executor(&runner, &look, fx.options())
        .run()
        .expect("the first run halts");
    runner.verify().expect("every expectation was used");

    // The provider loaded the bundle and restarted the guest. Everything the
    // resume does after that is: look, and finish.
    let look = TableLook::new(&fx);
    look.set("n1", Phase::After);
    look.provider_boots("n1");
    let mut options = fx.options();
    options.resume = true;
    let runner = World::new(
        StrictFake::new()
            .expect(helper("box", &["lock", "acquire", "--run", "run-1"]), ok())
            .expect(helper("n1", &["lock", "acquire", "--run", "run-1"]), ok())
            // Two commands, because a rollout took two things: the drain
            // and the cordon. `node uncordon` gives back only the second.
            .expect(cli("undrain", "n1"), Output::stdout(""))
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
        .executor(&runner, &look, options)
        .run()
        .expect("the resume runs");
    runner.verify().expect("every expectation was used");

    assert!(applied.waiting.is_none(), "it is not waiting any more");
    assert_eq!(applied.stopped, None, "{:?}", applied.stopped);
    assert_eq!(applied.receipt.outcome, Outcome::Success);
    assert_eq!(applied.receipt.hosts["n1"].outcome, HostOutcome::Success);
    assert_eq!(applied.receipt.hosts["n1"].state, HostState::Committed);
    // Nothing was activated a second time and nothing was copied again.
    for call in runner.calls() {
        assert!(!call.contains("nix copy"), "{call}");
        assert!(!call.contains("meister-activate --json activate"), "{call}");
    }
    // The step that did happen says what the machine answered.
    let evidence = applied.receipt.hosts["n1"]
        .actions
        .iter()
        .filter(|a| a.kind == ActionKind::ProviderReboot)
        .flat_map(|a| a.evidence.clone())
        .collect::<Vec<_>>()
        .join(" ");
    assert!(evidence.contains(&fx.top("n1")), "{evidence}");
}

#[test]
fn a_halt_and_a_resume_are_the_v17_table_and_not_a_recovery() {
    // The table itself, which is what a resume of a host that never opened a
    // transaction stands on: a `reboot_only` direct host is switched,
    // unbooted and holds no record at all, and asking the txn view first
    // would call that `recovery-required`.
    use crate::receipt::{HostRun, Step, next_step};

    let mut run = HostRun::new("n1");
    run.state = HostState::AwaitingReboot;
    run.actions.push(crate::receipt::ActionRun {
        seq: 7,
        kind: ActionKind::ProviderReboot,
        started: at(NOW),
        ended: None,
        result: None,
        evidence: Vec::new(),
        cmd_refs: Vec::new(),
    });
    for view in [TxnView::None, TxnView::Confirmed] {
        assert_eq!(
            next_step(&run, &view),
            Step::AtTheProviderReboot,
            "{view:?}"
        );
    }

    // And once the step has ended, the table is the ordinary one again.
    run.actions[0].ended = Some(at(NOW));
    run.actions[0].result = Some(ActionResult::Ok);
    run.state = HostState::Verifying;
    assert_eq!(next_step(&run, &TxnView::Confirmed), Step::VerifyOnly);
}

// --- lane 4A: the preflight at the run ------------------------------------

#[test]
fn a_store_that_filled_up_between_the_plan_and_the_run_stops_before_the_copy() {
    // The plan was made when there was room. The preflight is the last look
    // before the first copy, and what it finds there is not a note in a
    // receipt — it is the reason nothing is copied.
    let fx = Fixture::changing(&["n1"], false);
    let look = TableLook::new(&fx).ran_out_of_room("n1");
    let runner = World::new(
        StrictFake::new()
            // The fleet anchor is taken before any host is looked at, and
            // given back when the run ends.
            .expect(helper("box", &["lock", "acquire", "--run", "run-1"]), ok())
            .expect(helper("box", &["lock", "release", "--run", "run-1"]), ok()),
        &look,
    );
    let applied = fx
        .executor(&runner, &look, fx.options())
        .run()
        .expect("a stopped wave is an answer and not a crash");
    let stopped = applied.stopped.clone().unwrap_or_default();
    assert!(
        stopped.contains("free on the filesystem that carries /nix"),
        "{stopped}"
    );

    // Nothing was copied, nothing was locked on the host itself, nothing
    // was activated: the only commands were the anchor's.
    for call in runner.calls() {
        assert!(
            call.contains("lock acquire") || call.contains("lock release"),
            "the run ran {call} after a preflight that failed"
        );
    }
    runner.verify().expect("the anchor and nothing else");

    // The receipt says the host was not reached and names the step that
    // said so, with the sentence as its evidence.
    assert_eq!(applied.receipt.hosts["n1"].outcome, HostOutcome::Unreached);
    assert_eq!(applied.receipt.untouched, ["n1"]);
    let preflight = applied.receipt.hosts["n1"]
        .actions
        .iter()
        .find(|a| a.kind == ActionKind::Preflight)
        .expect("n1 has a preflight");
    assert_eq!(preflight.result, Some(ActionResult::Failed));
    assert!(
        preflight.evidence.join(" ").contains("2000000000"),
        "{:?}",
        preflight.evidence
    );
}

#[test]
fn a_raft_member_is_not_back_until_its_database_is() {
    // What `vm-kernel-change` found on a machine that had just rebooted:
    // sshd answered at five seconds into the boot and etcd at thirteen,
    // and in that window the host's own member list is EMPTY. The quorum
    // arithmetic reads that as a member that is down and the topology
    // check read it as a fleet that had changed — so the rollout stopped
    // in the middle of the reboot it had asked for. `wait_for_boot` now
    // waits for the database of a raft member, not only for the machine.
    let fx = Fixture::changing(&["box"], true);
    let look = TableLook::new(&fx).etcd_late("box", 2);
    let runner = World::new(StrictFake::new(), &look);
    let executor = fx.executor(&runner, &look, fx.options());

    assert!(
        executor.is_raft_member("box"),
        "box is the raft group of this fixture"
    );
    assert!(
        !executor.is_raft_member("n1"),
        "n1 is compute, and its etcd is nobody's business"
    );
    // And a host that sits in a raft group without a database of its own
    // is not waited for either — there would be nothing to wait for.
    let mut without = fx.release.resolved_fleet.clone();
    without
        .hosts
        .get_mut("box")
        .unwrap()
        .effective_settings
        .etcd = None;
    let mut release = fx.release.clone();
    release.resolved_fleet = without;
    let other = Fixture {
        release,
        plan: fx.plan.clone(),
        files: MemFiles::new(),
        clock: FakeClock::at(at(NOW)),
        state: StateDir::at("/repo/.meister-deploy"),
        ssh: Ssh::with_known_hosts("/repo/known_hosts"),
    };
    assert!(
        !other
            .executor(&runner, &look, other.options())
            .is_raft_member("box"),
        "a raft member without a database has none to wait for"
    );

    // The machine has booted the release from the very first look; its
    // database has not.
    look.set("box", Phase::After);
    let back = executor
        .wait_for_boot("box", &fx.top("box"))
        .expect("it does come back");
    assert_eq!(back, fx.top("box"));
    assert_eq!(
        look.etcd_late.borrow()["box"],
        0,
        "it returned before the database had answered"
    );
    assert!(
        !fx.clock.slept().is_empty(),
        "a bounded wait that never sleeps is a spin"
    );
}

#[test]
fn a_member_of_a_group_that_was_not_serving_is_back_when_the_machine_is() {
    // --- lane L4 ---
    // The wait above is for a window of SECONDS. A group that is coming
    // into existence has no such window: the first member of a fresh
    // three-member cluster has no majority to elect a leader with, so
    // `etcdctl endpoint health` cannot answer until the SECOND member is
    // activated — which is the next wave, which does not start until this
    // one finishes. Measured in the lab on 2026-09-23: the first bootstrap
    // of a three-member control plane sat in this loop with "it booted the
    // release and its etcd has not answered yet" until the reboot deadline,
    // and the run failed.
    let fx = Fixture::changing(&["box"], true);
    // What the plan says about the group is what decides it. `box` is the
    // raft group of this fixture; make it a group that was NOT serving when
    // the plan was made.
    let mut plan = fx.plan.clone();
    for view in plan.groups.values_mut() {
        view.unhealthy_now = view.size;
    }
    let fx = Fixture {
        release: fx.release.clone(),
        plan,
        files: MemFiles::new(),
        clock: FakeClock::at(at(NOW)),
        state: StateDir::at("/repo/.meister-deploy"),
        ssh: Ssh::with_known_hosts("/repo/known_hosts"),
    };
    // etcd would answer only after two more looks — and is never asked.
    let look = TableLook::new(&fx).etcd_late("box", 2);
    let runner = World::new(StrictFake::new(), &look);
    let executor = fx.executor(&runner, &look, fx.options());
    assert!(
        executor.is_raft_member("box"),
        "box is still a member of a raft group"
    );
    assert!(
        !executor.group_was_serving("box"),
        "every member of that group was unhealthy when the plan was made"
    );

    look.set("box", Phase::After);
    let back = executor
        .wait_for_boot("box", &fx.top("box"))
        .expect("the machine is back, and that is all there is to wait for");
    assert_eq!(back, fx.top("box"));
    // One look, and it was enough: the counter went down by the one
    // observation this call made, and nothing ever slept.
    assert_eq!(look.etcd_late.borrow()["box"], 1);
    assert!(
        fx.clock.slept().is_empty(),
        "it waited for a database that had nothing to come back to"
    );
}

// ---------------------------------------------------------------------------
// lane 5A: the revocation list
// ---------------------------------------------------------------------------

const CRL_PUT: &str = "set -e; d=$(dirname /var/lib/meisterstack/pki/crl.pem); mkdir -p \"$d\"; \
                       t=$(mktemp \"$d/.meister.XXXXXX\"); cat > \"$t\"; chown root:root \"$t\"; \
                       chmod 0644 \"$t\"; mv \"$t\" /var/lib/meisterstack/pki/crl.pem";

const CRL_SHA: &str = "sha256sum /var/lib/meisterstack/pki/crl.pem 2>/dev/null | cut -d' ' -f1";

/// A revocation, ready to be carried out: one host that reads a list, a new
/// list on the operator's disk, and the old one on the host.
fn revoking() -> (Fixture, String) {
    let release = release_of(crate::fixtures::with_crl(onebox_enrolled(), &["box"]));
    let observation = observed(&release, at(NOW));
    let contents = "-----BEGIN X509 CRL-----\nthe new list\n-----END X509 CRL-----\n".to_string();
    let digest = crate::ids::sha256_hex(contents.as_bytes());
    let mut expected = crate::fixtures::expected_credentials(&release.resolved_fleet);
    for secrets in expected.values_mut() {
        for (id, value) in secrets.iter_mut() {
            if id.starts_with("crl-") {
                *value = format!("sha256:{digest}");
            }
        }
    }
    let plan = plan(
        &release,
        "host=box",
        &observation,
        None,
        &crate::fixtures::plan_policy(PlanKind::KeysRevoke).with_expected_credentials(expected),
        at(NOW),
    )
    .expect("the fixture plans");
    let fx = Fixture {
        release,
        plan,
        files: MemFiles::new().given("/repo/pki/crl.pem", contents.clone()),
        clock: FakeClock::at(at(NOW)),
        state: StateDir::at("/repo/.meister-deploy"),
        ssh: Ssh::with_known_hosts("/repo/known_hosts"),
    };
    (fx, contents)
}

/// The whole step, and the one thing that must NOT be in it: a restart.
///
/// A controller re-reads its revocation list within half a minute. Poking
/// the unit would be the single avoidable outage in this design — on every
/// host of the fleet, for every revocation — so the list is written, the
/// host is asked what it now has, and nothing else happens.
#[test]
fn a_revocation_list_is_delivered_and_no_unit_is_restarted() {
    let (fx, contents) = revoking();
    let digest = crate::ids::sha256_hex(contents.as_bytes());
    let look = TableLook::new(&fx);
    // Two references to ONE file (a cloud and a cluster on one host), which
    // is what the one derivation writes.
    let runner = World::new(
        StrictFake::new()
            // Twice: the fleet anchor holds every control-plane host of the
            // inventory (D6), and this host is one — and it is also the
            // host of this plan, so its own `lock` step takes it as well.
            .expect(helper("box", &["lock", "acquire"]), ok())
            .expect(helper("box", &["lock", "acquire"]), ok())
            .expect(shell_on("box", CRL_PUT), ok())
            .expect(
                shell_on("box", CRL_SHA),
                Output::stdout(format!("{digest}\n")),
            )
            .expect(shell_on("box", CRL_PUT), ok())
            .expect(
                shell_on("box", CRL_SHA),
                Output::stdout(format!("{digest}\n")),
            )
            .expect(helper("box", &["lock", "release"]), ok()),
        &look,
    );
    let mut options = fx.options();
    options.repo = PathBuf::from("/repo");
    options.ca_dir = Some(PathBuf::from("/ca"));
    let applied = fx
        .executor(&runner, &look, options)
        .run()
        .expect("a revocation applies");
    // `verify()` is the assertion that matters here: a `systemctl restart`
    // would have been an unexpected command and the run would have failed.
    runner.verify().expect("exactly those commands");

    assert_eq!(applied.receipt.outcome, Outcome::Success);
    let steps: Vec<ActionKind> = applied.receipt.hosts["box"]
        .actions
        .iter()
        .map(|a| a.kind)
        .collect();
    assert_eq!(
        steps,
        [
            ActionKind::Preflight,
            ActionKind::Lock,
            ActionKind::DeliverSecret,
            ActionKind::DeliverSecret,
            ActionKind::Verify,
            ActionKind::Unlock
        ]
    );
    let evidence = applied.receipt.hosts["box"]
        .actions
        .iter()
        .filter(|a| a.kind == ActionKind::DeliverSecret)
        .flat_map(|a| a.evidence.clone())
        .collect::<Vec<_>>()
        .join(" ");
    assert!(
        evidence.contains("re-reads its revocation list"),
        "{evidence}"
    );
    assert!(evidence.contains(&format!("sha256:{digest}")), "{evidence}");
}

// ---------------------------------------------------------------------------
// lane 5A: the rotation
// ---------------------------------------------------------------------------

const NEW_CERT: &str = "-----BEGIN CERTIFICATE-----\nthe new one\n-----END CERTIFICATE-----\n";

const ROT_PUT: &str = "set -e; d=$(dirname /var/lib/meisterstack/pki/identity.crt.next); \
                       mkdir -p \"$d\"; t=$(mktemp \"$d/.meister.XXXXXX\"); cat > \"$t\"; \
                       chown meister:meister \"$t\"; chmod 0644 \"$t\"; \
                       mv \"$t\" /var/lib/meisterstack/pki/identity.crt.next";

const ROT_SHA_NEXT: &str =
    "sha256sum /var/lib/meisterstack/pki/identity.crt.next 2>/dev/null | cut -d' ' -f1";
const ROT_SHA: &str =
    "sha256sum /var/lib/meisterstack/pki/identity.crt 2>/dev/null | cut -d' ' -f1";

/// The units of the fixture's four-role host, in the order the plan sorts
/// them.
const ROT_UNITS: [&str; 3] = [
    "meister-agent.service",
    "meister-cloud-controller.service",
    "meister-cluster-controller.service",
];

fn is_active(id: &str, unit: &str) -> Matcher {
    shell_on(id, &format!("systemctl is-active {unit}"))
}

fn restart(id: &str, unit: &str) -> Matcher {
    let address = match id {
        "box" => "10.0.0.10",
        "n1" => "10.0.0.11",
        _ => "10.0.0.12",
    };
    let mut out = Ssh::with_known_hosts("/repo/known_hosts").opts(22);
    out.push(format!("root@{address}"));
    out.push("systemctl".to_string());
    out.push("restart".to_string());
    out.push(unit.to_string());
    Matcher::exact("ssh", out)
}

/// A rotation of `box`'s identity key, prepared and planned.
fn rotating() -> (Fixture, String) {
    let release = release_of(crate::fixtures::with_cert(
        onebox_enrolled(),
        &["box"],
        "identity",
    ));
    let observation = observed(&release, at(NOW));
    let digest = format!("sha256:{}", crate::ids::sha256_hex(NEW_CERT.as_bytes()));
    let rotation = crate::fixtures::rotation_for(&release.resolved_fleet, "box", &digest);
    let plan = plan(
        &release,
        "host=box",
        &observation,
        None,
        &crate::fixtures::plan_policy(PlanKind::KeysRotate)
            .with_rotations([("box".to_string(), rotation)].into_iter().collect()),
        at(NOW),
    )
    .expect("the fixture plans");
    let fx = Fixture {
        release,
        plan,
        files: MemFiles::new().given("/repo/pki/issued/box/identity.next.crt", NEW_CERT),
        clock: FakeClock::at(at(NOW)),
        state: StateDir::at("/repo/.meister-deploy"),
        ssh: Ssh::with_known_hosts("/repo/known_hosts"),
    };
    (fx, digest)
}

fn keygen_answer() -> Output {
    Output::stdout(
        serde_json::json!({
            "subject": "system:node:box",
            "kind": "identity",
            "csr_pem": "-----BEGIN CERTIFICATE REQUEST-----\nAAAA\n-----END CERTIFICATE REQUEST-----\n",
            "public_key_sha256": "cd".repeat(32),
            "created": false,
        })
        .to_string(),
    )
}

fn rotate_options(fx: &Fixture) -> ApplyOptions {
    let mut options = fx.options();
    options.repo = PathBuf::from("/repo");
    options.ca_dir = Some(PathBuf::from("/ca"));
    options.approvals = vec![
        (ApprovalClass::Disruptive, fx.plan.plan_id.clone()),
        (ApprovalClass::Singleton, fx.plan.plan_id.clone()),
    ];
    options
}

/// The whole rotation, command for command.
#[test]
fn a_rotation_is_prepared_overlapped_switched_verified_and_finished() {
    let (fx, digest) = rotating();
    let bare = digest.trim_start_matches("sha256:").to_string();
    let look = TableLook::new(&fx);
    let mut fake = StrictFake::new()
        .expect(helper("box", &["lock", "acquire"]), ok())
        .expect(helper("box", &["lock", "acquire"]), ok())
        .expect(
            helper(
                "box",
                &[
                    "keygen",
                    "--subject",
                    "system:node:box",
                    "--kind",
                    "identity",
                    "--suffix",
                    "next",
                ],
            ),
            keygen_answer(),
        )
        .expect(shell_on("box", ROT_PUT), ok())
        .expect(
            shell_on("box", ROT_SHA_NEXT),
            Output::stdout(format!("{bare}\n")),
        )
        .expect(
            helper("box", &["keys", "switch", "--kind", "identity", "--run"]),
            ok(),
        );
    for unit in ROT_UNITS {
        fake = fake
            .expect(is_active("box", unit), Output::stdout("active\n"))
            .expect(restart("box", unit), ok());
    }
    let runner = World::new(
        fake.expect(
            shell_on("box", ROT_SHA),
            Output::stdout(format!("{bare}\n")),
        )
        .expect(
            helper("box", &["keys", "remove", "--kind", "identity"]),
            ok(),
        )
        .expect(helper("box", &["lock", "release"]), ok()),
        &look,
    );

    let applied = fx
        .executor(&runner, &look, rotate_options(&fx))
        .run()
        .expect("a rotation applies");
    runner.verify().expect("exactly those commands");

    assert_eq!(applied.receipt.outcome, Outcome::Success);
    assert_eq!(applied.receipt.hosts["box"].outcome, HostOutcome::Success);
    let steps: Vec<ActionKind> = applied.receipt.hosts["box"]
        .actions
        .iter()
        .map(|a| a.kind)
        .collect();
    assert_eq!(
        steps,
        [
            ActionKind::Preflight,
            ActionKind::Lock,
            ActionKind::KeysPrepare,
            ActionKind::KeysOverlap,
            ActionKind::KeysSwitch,
            ActionKind::KeysVerify,
            ActionKind::KeysRemove,
            ActionKind::Unlock,
        ]
    );
    // Nothing of the certificate is in the journal beyond its digest, and
    // nothing of the key at all.
    let journal = String::from_utf8(
        fx.files
            .content("/repo/.meister-deploy/runs/run-1/journal.jsonl")
            .expect("a journal"),
    )
    .unwrap();
    assert!(!journal.contains("BEGIN CERTIFICATE"), "{journal}");
    assert!(!journal.contains("PRIVATE KEY"), "{journal}");
    assert!(journal.contains(&digest), "the digest is the evidence");

    // And the repository caught up with the host: what the planner compares
    // every host against is now the certificate the host actually holds.
    // Without this the next ordinary plan would deliver the old one back.
    assert_eq!(
        fx.files.content("/repo/pki/issued/box/identity.crt"),
        Some(NEW_CERT.as_bytes().to_vec())
    );
    assert!(
        fx.files
            .content("/repo/pki/issued/box/identity.next.crt")
            .is_none(),
        "the rotation's file is still lying about"
    );
}

/// A key that is not the one the plan was made for stops the run before
/// anything is put anywhere.
#[test]
fn a_host_that_prepared_a_different_key_stops_the_rotation() {
    let (fx, _) = rotating();
    let look = TableLook::new(&fx);
    let runner = World::new(
        StrictFake::new()
            .expect(helper("box", &["lock", "acquire"]), ok())
            .expect(helper("box", &["lock", "acquire"]), ok())
            .expect(
                helper("box", &["keygen"]),
                Output::stdout(
                    serde_json::json!({
                        "subject": "system:node:box",
                        "kind": "identity",
                        "csr_pem": "-----BEGIN CERTIFICATE REQUEST-----\nAAAA\n-----END CERTIFICATE REQUEST-----\n",
                        "public_key_sha256": "ee".repeat(32),
                        "created": true,
                    })
                    .to_string(),
                ),
            )
            .expect(helper("box", &["lock", "release"]), ok()),
        &look,
    );
    let applied = fx
        .executor(&runner, &look, rotate_options(&fx))
        .run()
        .expect("the run ends with a receipt");
    runner.verify().expect("exactly those commands");
    // `aborted` and not `failed`: the host never reached a state of its
    // own, because the run stopped at the first step — which is the point.
    // Nothing was put anywhere.
    assert_eq!(applied.receipt.outcome, Outcome::Aborted);
    let why = applied.stopped.unwrap_or_default();
    assert!(why.contains("Somebody rotated this key"), "{why}");
}

/// A rotation that did not verify goes back, and the run says so.
#[test]
fn a_rotation_that_does_not_verify_is_taken_back() {
    let (fx, digest) = rotating();
    let bare = digest.trim_start_matches("sha256:").to_string();
    let look = TableLook::new(&fx);
    let mut fake = StrictFake::new()
        .expect(helper("box", &["lock", "acquire"]), ok())
        .expect(helper("box", &["lock", "acquire"]), ok())
        .expect(helper("box", &["keygen"]), keygen_answer())
        .expect(shell_on("box", ROT_PUT), ok())
        .expect(
            shell_on("box", ROT_SHA_NEXT),
            Output::stdout(format!("{bare}\n")),
        )
        .expect(helper("box", &["keys", "switch"]), ok());
    for unit in ROT_UNITS {
        fake = fake
            .expect(is_active("box", unit), Output::stdout("active\n"))
            .expect(restart("box", unit), ok());
    }
    // The host answers with the certificate it had BEFORE the switch: the
    // pair did not go in, whatever the helper said.
    let runner = World::new(
        fake.expect(
            shell_on("box", ROT_SHA),
            Output::stdout("0000000000000000000000000000000000000000000000000000000000000000\n"),
        )
        .expect(
            helper("box", &["keys", "revert", "--kind", "identity"]),
            ok(),
        )
        .expect(is_active("box", ROT_UNITS[0]), Output::stdout("active\n"))
        .expect(restart("box", ROT_UNITS[0]), ok())
        .expect(is_active("box", ROT_UNITS[1]), Output::stdout("active\n"))
        .expect(restart("box", ROT_UNITS[1]), ok())
        .expect(is_active("box", ROT_UNITS[2]), Output::stdout("active\n"))
        .expect(restart("box", ROT_UNITS[2]), ok())
        .expect(helper("box", &["lock", "release"]), ok()),
        &look,
    );
    let applied = fx
        .executor(&runner, &look, rotate_options(&fx))
        .run()
        .expect("the run ends with a receipt");
    runner.verify().expect("exactly those commands");
    assert_eq!(
        applied.receipt.hosts["box"].outcome,
        HostOutcome::RolledBack
    );
    assert_eq!(applied.receipt.outcome, Outcome::Failed);
    // And the removal never ran: what the switch replaced is still there.
    assert!(
        !applied.receipt.hosts["box"]
            .actions
            .iter()
            .any(|a| a.kind == ActionKind::KeysRemove)
    );
}

/// A journal of a rotation that got as far as `through` and then stopped.
fn write_rotation_journal(fx: &Fixture, run: &str, through: ActionKind) {
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
    put(journal
        .event(EventKind::HostState, at(NOW))
        .host("box")
        .transition(HostState::Planned, HostState::Preflight)
        .payload(serde_json::json!({})));
    let reached = crate::receipt::keys_phase_order(through).expect("a phase");
    for kind in [
        ActionKind::KeysPrepare,
        ActionKind::KeysOverlap,
        ActionKind::KeysSwitch,
        ActionKind::KeysVerify,
        ActionKind::KeysRemove,
    ] {
        if crate::receipt::keys_phase_order(kind) > Some(reached) {
            break;
        }
        let seq = fx
            .plan
            .actions_for("box")
            .into_iter()
            .find(|a| a.kind == kind)
            .expect("the plan has it")
            .seq;
        put(journal
            .event(EventKind::ActionBegin, at(NOW))
            .host("box")
            .payload(serde_json::json!({"action": seq, "kind": kind})));
        put(journal
            .event(EventKind::ActionEnd, at(NOW))
            .host("box")
            .payload(serde_json::json!({"action": seq, "kind": kind, "result": "ok"})));
    }
    if through == ActionKind::KeysRemove {
        put(journal
            .event(EventKind::HostState, at(NOW))
            .host("box")
            .transition(HostState::Preflight, HostState::Committed)
            .payload(serde_json::json!({})));
    }
}

/// V17 for a rotation: the run died after the certificate was put beside
/// the one in use. A resume asks the HOST where it is and carries on from
/// there — and never prepares a second key.
#[test]
fn a_resume_carries_a_rotation_on_from_the_phase_the_host_is_at() {
    let (fx, digest) = rotating();
    let bare = digest.trim_start_matches("sha256:").to_string();
    write_rotation_journal(&fx, "run-1", ActionKind::KeysOverlap);
    let look = TableLook::new(&fx);
    let mut fake = StrictFake::new()
        // The fleet anchor first, as in every run (D6), and then the
        // question this resume turns on: where is the host.
        .expect(helper("box", &["lock", "acquire"]), ok())
        .expect(
            helper("box", &["keys", "status", "--kind", "identity"]),
            // The helper's own envelope, exactly as `meister-activate
            // --json keys status` prints it.
            Output::stdout(
                serde_json::json!({
                    "ok": true,
                    "what": "keys status",
                    "result": {
                        "kind": "identity",
                        "state": "overlap",
                        "key_next": true,
                        "crt_next": true,
                        "prev": false,
                        "reason": null,
                        "record": null,
                    },
                })
                .to_string(),
            ),
        )
        .expect(helper("box", &["lock", "acquire"]), ok())
        .expect(
            helper("box", &["keys", "switch", "--kind", "identity"]),
            ok(),
        );
    for unit in ROT_UNITS {
        fake = fake
            .expect(is_active("box", unit), Output::stdout("active\n"))
            .expect(restart("box", unit), ok());
    }
    let runner = World::new(
        fake.expect(
            shell_on("box", ROT_SHA),
            Output::stdout(format!("{bare}\n")),
        )
        .expect(
            helper("box", &["keys", "remove", "--kind", "identity"]),
            ok(),
        )
        .expect(helper("box", &["lock", "release"]), ok()),
        &look,
    );

    let mut options = rotate_options(&fx);
    options.resume = true;
    let applied = fx
        .executor(&runner, &look, options)
        .run()
        .expect("the resume runs");
    runner.verify().expect("exactly those commands");
    assert_eq!(applied.stopped, None);
    assert_eq!(applied.receipt.hosts["box"].outcome, HostOutcome::Success);
    // The two things a resume must never do.
    assert!(
        !runner.calls().iter().any(|c| c.contains("keygen")),
        "a second key was prepared: {:?}",
        runner.calls()
    );
    assert!(
        !runner
            .calls()
            .iter()
            .any(|c| c.contains("identity.crt.next")),
        "the certificate was delivered twice: {:?}",
        runner.calls()
    );
}

/// And the two answers that are not a phase: the rotation is over, or the
/// host has nothing and a person has to look.
#[test]
fn a_resume_of_a_finished_rotation_does_nothing_at_all() {
    let (fx, _) = rotating();
    // Astra finding F09, 2026-09-23: the run being resumed here ran its
    // whole `keys remove` step, and the LOCAL half of that step is what
    // makes the certificate this rotation issued the repository's own. A
    // resume asks for that half now — the host cannot answer it — so the
    // fixture says what a finished run leaves behind.
    fx.files
        .write_atomic(
            &PathBuf::from("/repo/pki/issued/box/identity.crt"),
            NEW_CERT.as_bytes(),
            0o644,
        )
        .expect("the published certificate");
    fx.files
        .remove_file(&PathBuf::from("/repo/pki/issued/box/identity.next.crt"))
        .expect("and the source it was published from is gone");
    write_rotation_journal(&fx, "run-1", ActionKind::KeysRemove);
    let look = TableLook::new(&fx);
    let runner = World::new(
        StrictFake::new()
            .expect(helper("box", &["lock", "acquire"]), ok())
            .expect(
                helper("box", &["keys", "status", "--kind", "identity"]),
                Output::stdout(
                    serde_json::json!({
                        "ok": true,
                        "what": "keys status",
                        "result": {
                            "kind": "identity",
                            "state": "confirmed",
                            "key_next": false,
                            "crt_next": false,
                            "prev": false,
                            "reason": null,
                            "record": null,
                        },
                    })
                    .to_string(),
                ),
            )
            .expect(helper("box", &["lock", "release"]), ok()),
        &look,
    );
    let mut options = rotate_options(&fx);
    options.resume = true;
    let applied = fx
        .executor(&runner, &look, options)
        .run()
        .expect("the resume runs");
    runner.verify().expect("exactly those commands");
    assert!(
        !runner.calls().iter().any(|c| c.contains("keys switch")),
        "{:?}",
        runner.calls()
    );
    assert_eq!(applied.receipt.outcome, Outcome::Success);
}

// Astra finding F09, 2026-09-23.
#[test]
fn a_resume_after_the_remote_removal_still_publishes_the_new_cert() {
    // The last phase has two halves: the old pair goes on the host, and the
    // certificate this rotation issued becomes the repository's own — which
    // is what the planner compares every host against. The host answers
    // `confirmed` for the first half alone, and that was read as `done`, so
    // a run that died between the two left the OLD certificate in the
    // repository and the next ordinary plan delivered it back over the new
    // one, undoing the rotation in a plan nobody read as one.
    let (fx, digest) = rotating();
    write_rotation_journal(&fx, "run-1", ActionKind::KeysRemove);
    let look = TableLook::new(&fx);
    let runner = World::new(
        StrictFake::new()
            .expect(helper("box", &["lock", "acquire"]), ok())
            .expect(
                helper("box", &["keys", "status", "--kind", "identity"]),
                Output::stdout(
                    serde_json::json!({
                        "ok": true,
                        "what": "keys status",
                        "result": {
                            "kind": "identity",
                            "state": "confirmed",
                            "key_next": false,
                            "crt_next": false,
                            "prev": false,
                            "reason": null,
                            "record": null,
                        },
                    })
                    .to_string(),
                ),
            )
            // The plan's own `lock` step, which a resume with work left to
            // do runs: the anchor above took the same lock, and the same run
            // asking twice is asking whether it may act.
            .expect(helper("box", &["lock", "acquire"]), ok())
            // Named again, and both halves of it are idempotent.
            .expect(
                helper("box", &["keys", "remove", "--kind", "identity"]),
                ok(),
            )
            .expect(helper("box", &["lock", "release"]), ok()),
        &look,
    );
    let mut options = rotate_options(&fx);
    options.resume = true;
    let applied = fx
        .executor(&runner, &look, options)
        .run()
        .expect("the resume runs");
    runner.verify().expect("exactly those commands");
    assert_eq!(applied.receipt.outcome, Outcome::Success);
    // The repository now holds what the host holds.
    let published = fx
        .files
        .content(PathBuf::from("/repo/pki/issued/box/identity.crt"))
        .expect("the certificate is published");
    assert_eq!(
        format!("sha256:{}", crate::ids::sha256_hex(&published)),
        digest
    );
    assert!(
        !fx.files
            .exists(&PathBuf::from("/repo/pki/issued/box/identity.next.crt")),
        "the source it was published from is gone"
    );
    // And nothing before the last phase was repeated: a second `prepare`
    // would be a second key.
    for repeated in ["keys switch", "keygen", "keys revert"] {
        assert!(
            !runner.calls().iter().any(|c| c.contains(repeated)),
            "{repeated} was repeated: {:?}",
            runner.calls()
        );
    }
}

// --- lane 5B: what `scripts/check-push-pki.sh` asked ----------------------
//
// The pre-v1 road delivered certificates with `deploy/push.sh pki`: an rsync
// of a staging directory under FIXED file names, followed by `chown` and
// `chmod` at the far end. Four questions decided whether that was safe, and
// a 264-line shell script with ssh and rsync stubs on `PATH` answered them
// (28 checks). The script goes with M5B. These four tests are the same four
// questions, asked of the road that replaced it — the plan's
// `deliver-secret` steps and the executor that carries them out.
//
// They are stronger than the script was in one place and weaker in none:
// question B used to be a fixed order (agents, clusters, clouds) and is now
// the DIRECTION of the plan, which is the reverse for a bootstrap — and the
// reason it is reversed is a fact about the fleet rather than a constant in
// a script.

/// A: every host gets the files its own roles name, and nobody else's.
///
/// This is the question the script existed for: two clusters with different
/// names, and an rsync that puts one cluster's `identity.crt` on the other
/// host. Here there is no staging directory and no fixed name to get wrong —
/// a delivery step names the secret reference of ONE host, and the executor
/// looks it up in that host's own `secret_refs` (`Executor::deliver`).
#[test]
fn every_host_gets_the_files_its_roles_name_and_no_others() {
    let release = release_of(onebox_enrolled());
    let fleet = &release.resolved_fleet;
    // A bootstrap, because that is the plan in which everything is missing
    // and therefore everything is delivered — so the snapshot has to be of
    // hosts that have nothing yet.
    let mut observation = observed(&release, at(NOW));
    for host in observation.hosts.values_mut() {
        for value in host.credentials.values_mut() {
            *value = None;
        }
    }
    let expected = crate::fixtures::expected_credentials(fleet);
    let plan = plan(
        &release,
        "all",
        &observation,
        None,
        &crate::fixtures::plan_policy(PlanKind::Bootstrap).with_expected_credentials(expected),
        at(NOW),
    )
    .expect("a bootstrap plans");

    let mut delivered: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for action in plan
        .actions
        .iter()
        .filter(|a| a.kind == ActionKind::DeliverSecret)
    {
        delivered
            .entry(action.host.clone())
            .or_default()
            .push(action.desired.clone().unwrap_or_default());
    }
    assert!(!delivered.is_empty(), "a bootstrap delivers something");

    for (id, steps) in &delivered {
        let host = &fleet.hosts[id];
        for step in steps {
            // The step says `<secret id> at <target path>`, and both halves
            // have to be THIS host's.
            let own = host
                .secret_refs
                .iter()
                .any(|s| format!("{} at {}", s.id, s.target_path) == *step);
            assert!(
                own,
                "{id} is handed {step:?}, which is not one of its own secret_refs: {:?}",
                host.secret_refs
                    .iter()
                    .map(|s| format!("{} at {}", s.id, s.target_path))
                    .collect::<Vec<_>>()
            );
        }
        // And nothing of another host's is in there. A cluster identity
        // belongs to the GROUP, so two hosts may legitimately be handed the
        // same file — what may not happen is a host being handed a
        // reference it does not declare, which is what the loop above holds.
        assert_eq!(
            steps.len(),
            steps.iter().collect::<BTreeSet<_>>().len(),
            "{id} is handed the same file twice"
        );
    }
}

/// B: the order, and why it is not a constant.
///
/// `push.sh` went agents, then clusters, then clouds, always. That is right
/// for an UPGRADE — the tier below is taken forward first, so a controller
/// never issues a command the tier under it does not understand yet — and
/// it is exactly wrong for a BOOTSTRAP, where a node has nothing to dial
/// until the thing it dials exists. The planner derives the direction from
/// the kind; these two assertions are the two directions.
#[test]
fn the_order_is_the_bottom_tier_first_and_a_bootstrap_is_the_other_way_round() {
    // A release in which every host has a new system, because a plan only
    // orders hosts it has something to do to.
    let base = onebox_enrolled();
    let running = release_of(base.clone());
    let observation = observed(&running, at(NOW));
    let release = crate::fixtures::with_new_systems(base, &["box", "n1", "n2"], false);

    let first_seq = |plan: &crate::plan::DeploymentPlan, id: &str| -> u32 {
        plan.actions
            .iter()
            .filter(|a| a.host == id)
            .map(|a| a.seq)
            .min()
            .unwrap_or_else(|| panic!("{id} is in the plan"))
    };

    // Upgrade: the agents move before the box that carries the controllers.
    let upgrade = plan(
        &release,
        "all",
        &observation,
        None,
        &crate::fixtures::plan_policy(PlanKind::Upgrade),
        at(NOW),
    )
    .expect("an upgrade plans");
    assert!(
        first_seq(&upgrade, "n1") < first_seq(&upgrade, "box"),
        "an upgrade takes the bottom tier first"
    );

    // Bootstrap: the box comes up first, because n1 has nothing to talk to
    // until it has.
    let mut bare = observation.clone();
    for host in bare.hosts.values_mut() {
        for value in host.credentials.values_mut() {
            *value = None;
        }
    }
    let expected = crate::fixtures::expected_credentials(&release.resolved_fleet);
    let bootstrap = plan(
        &release,
        "all",
        &bare,
        None,
        &crate::fixtures::plan_policy(PlanKind::Bootstrap).with_expected_credentials(expected),
        at(NOW),
    )
    .expect("a bootstrap plans");
    assert!(
        first_seq(&bootstrap, "box") < first_seq(&bootstrap, "n1"),
        "a bootstrap turns it around"
    );
}

/// C: the modes, and who owns the file.
///
/// The script ran a real `chmod` in a temporary tree and read the result
/// back. Here the mode is not something a step decides at all: it is a field
/// of the secret reference the FLEET derived, and the executor passes it
/// through to the far end verbatim. So there are two things to hold: the
/// derivation gives a private file 0600 and a public one 0644, and the put
/// carries exactly what the reference says.
#[test]
fn a_private_file_is_0600_at_the_far_end_and_a_public_one_0644() {
    let release = release_of(onebox_enrolled());
    for (id, host) in &release.resolved_fleet.hosts {
        for secret in &host.secret_refs {
            let private = secret.target_path.ends_with(".key");
            let wanted = if private { "0600" } else { "0644" };
            assert_eq!(
                secret.mode,
                wanted,
                "{id}: {} is mode {}, and a {} file of this fleet is {wanted}",
                secret.target_path,
                secret.mode,
                if private { "private" } else { "public" }
            );
            // And the owner travels with it: the loaders of this stack
            // open a key only as the user that owns it (M0 probe S11), so
            // an empty owner would be a file nobody can read.
            assert!(
                !secret.owner.is_empty(),
                "{id}: {} names no owner",
                secret.target_path
            );
        }
    }

    // And the mode the reference names is the mode the command carries. The
    // whole script is asserted in `PUT_SCRIPT` above; this is the one line
    // of it that this test is about.
    assert!(
        PUT_SCRIPT.contains("chmod 0644"),
        "the put of a public file carries its mode: {PUT_SCRIPT}"
    );
}

/// D: a file that is not here stops the run, names the host AND the file,
/// and leaves nothing half-written on the target.
#[test]
fn a_secret_that_is_not_here_names_the_host_and_the_file_and_sends_nothing() {
    let (mut fx, _) = delivering();
    // The CA certificate is gone from the operator's machine.
    fx.files = MemFiles::new();
    let look = TableLook::new(&fx);
    // The lock is taken and given back; nothing is put anywhere.
    let runner = World::new(
        StrictFake::new()
            .expect(helper("n1", &["lock", "acquire"]), ok())
            .expect(helper("n1", &["lock", "release"]), ok()),
        &look,
    );
    let applied = fx
        .executor(&runner, &look, deliver_options(&fx))
        .run()
        .expect("the run ends with a receipt rather than a panic");
    runner.verify().expect("exactly those commands");

    assert_ne!(
        applied.receipt.hosts["n1"].outcome,
        HostOutcome::Success,
        "a delivery that could not happen is not a success"
    );
    assert_ne!(
        applied.receipt.hosts["n1"]
            .actions
            .iter()
            .find(|a| a.kind == ActionKind::DeliverSecret)
            .and_then(|a| a.result),
        Some(crate::receipt::ActionResult::Ok),
        "the step that could not be done is not marked ok"
    );
    // The sentence is in the journal, where a resume and a report both read
    // it. It has to name BOTH — the host, because a run covers many, and the
    // file, because a run delivers many.
    let journal = String::from_utf8(
        fx.files
            .content(fx.state.journal_path("run-1"))
            .expect("a journal was written"),
    )
    .unwrap();
    assert!(
        journal.contains("n1"),
        "the sentence names the host: {journal}"
    );
    assert!(
        journal.contains("/var/lib/meisterstack/pki/ca.crt"),
        "the sentence names the file: {journal}"
    );
    assert!(
        !runner.calls().iter().any(|c| c.contains("mktemp")),
        "something was written to the target: {:?}",
        runner.calls()
    );
}

// --- end lane 5B ---------------------------------------------------------
