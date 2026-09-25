// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! What `apply` does to the machine it runs on, measured through the real
//! binary — including the one thing a shim cannot show.
//!
//! `PATH` is a directory of shims, so every program the run starts is in a
//! log and whatever the log does not have it did not run. That pins the
//! command lines. What it cannot pin is a syscall that reaches the network
//! without one of those programs, and `apply` is the verb with something to
//! hide: it is the one that changes machines. So the last test here runs the
//! whole thing inside `unshare -rn` — a network namespace with a single
//! `lo` that is DOWN — and a run that behaves identically there is a run
//! that opened no socket of its own (V20).
//!
//! The working directory is compared byte for byte before and after, so
//! "wrote nothing" is a comparison rather than a claim.

mod support;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use meister_deploy::manifest::ResolvedFleet;
use meister_deploy::plan::{self, DeploymentPlan, PlanKind, PlanPolicy};
use meister_deploy::release::ReleaseManifest;

use support::{observed, onebox, probe_answer, release_of};

const BIN: &str = env!("CARGO_BIN_EXE_meister-deploy");

/// Every program a rollout is allowed to know about. `meister` is the
/// operator's own cli, which is what a cordon and a drain go through (D7).
const SHIMS: [&str; 6] = ["nix", "git", "rsync", "ssh", "ssh-keygen", "meister"];

const ENROLLED_KEY: &str = "AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
const ENROLLED_FINGERPRINT: &str = "SHA256:kmYcvdi2GkPeWxB6XLjrZB8JHsy2Hm8luHMFp9GMvqk";

struct Sandbox {
    cwd: tempfile::TempDir,
    shims: tempfile::TempDir,
    answers: tempfile::TempDir,
    home: tempfile::TempDir,
    log: PathBuf,
    fleet: ResolvedFleet,
    release: ReleaseManifest,
    plan: DeploymentPlan,
    /// What the `ssh` shim answers to an invocation of the helper: 97 is
    /// "this program was not supposed to run", 0 is "it worked".
    ssh_exit: i32,
    /// The same for the operator's cli, which the cordon and the drain go
    /// through (D7).
    cli_exit: i32,
}

impl Sandbox {
    fn new() -> Sandbox {
        use std::os::unix::fs::PermissionsExt;
        let shims = tempfile::tempdir().unwrap();
        let answers = tempfile::tempdir().unwrap();
        let cwd = tempfile::tempdir().unwrap();
        let home = tempfile::tempdir().unwrap();
        let log = shims.path().join("calls.log");

        for name in SHIMS {
            let body = match name {
                "ssh-keygen" => format!(
                    "#!/bin/sh\nline=\"{name}\"\n\
                     for a in \"$@\"; do line=\"$line [$a]\"; done\n\
                     printf '%s\\n' \"$line\" >> \"$MEISTER_SHIM_LOG\"\n\
                     printf '# Host found: line 1\\n10.0.0.10 ssh-ed25519 {ENROLLED_KEY}\\n'\n\
                     exit 0\n"
                ),
                // Answers a probe from the file prepared for the address in
                // its argv. An invocation of the HELPER — `meister-activate`
                // as an argument of its own, rather than a word inside the
                // probe script — answers with the exit code the test asked
                // for. No external program in the body: PATH holds only this
                // directory while the binary runs.
                "ssh" => format!(
                    "#!/bin/sh\nline=\"{name}\"\naddr=\nhelper=\n\
                     for a in \"$@\"; do line=\"$line [$a]\"; \
                     case \"$a\" in *@*) addr=${{a#*@}};; \
                     meister-activate) helper=1;; esac; done\n\
                     printf '%s\\n' \"$line\" >> \"$MEISTER_SHIM_LOG\"\n\
                     if [ -n \"$helper\" ]; then exit ${{MEISTER_SHIM_SSH_EXIT:-97}}; fi\n\
                     f=\"$MEISTER_SHIM_ANSWERS/$addr\"\n\
                     if [ -f \"$f\" ]; then \
                     while IFS= read -r l; do printf '%s\\n' \"$l\"; done < \"$f\"; exit 0; \
                     fi\n\
                     exit 255\n"
                ),
                // The operator's own cli (D7), which a cordon and a drain
                // go through. 97 is "this program was not supposed to run";
                // a test that needs a drain to work says so.
                "meister" => format!(
                    "#!/bin/sh\nline=\"{name}\"\n\
                     for a in \"$@\"; do line=\"$line [$a]\"; done\n\
                     printf '%s\\n' \"$line\" >> \"$MEISTER_SHIM_LOG\"\n\
                     exit ${{MEISTER_SHIM_CLI_EXIT:-97}}\n"
                ),
                _ => format!(
                    "#!/bin/sh\nline=\"{name}\"\n\
                     for a in \"$@\"; do line=\"$line [$a]\"; done\n\
                     printf '%s\\n' \"$line\" >> \"$MEISTER_SHIM_LOG\"\nexit 97\n"
                ),
            };
            let path = shims.path().join(name);
            std::fs::write(&path, body).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        }

        let mut fleet = onebox();
        for host in fleet.hosts.values_mut() {
            host.ssh.host_key_fingerprint = Some(ENROLLED_FINGERPRINT.to_string());
        }
        fleet.manifest_id =
            meister_deploy::ids::content_id(meister_deploy::ids::IdKind::Manifest, &fleet).unwrap();
        // The fleet runs the release: so the plan is a no-op plan, which is
        // the one an `apply` may carry out without any approval at all.
        let release = release_of(fleet.clone());
        // The clock of the MACHINE, not a literal: a plan carries an
        // `expires_at` (`created_at` plus an hour) and the binary under test
        // reads the real clock to compare against it. A fixture pinned to a
        // date is a test that passes until that hour goes by and is red for
        // ever after — measured: this file went red on the afternoon of the
        // day its literal named. What the other tests of this crate pin with
        // a fake clock is the CONTENT of a plan; what is pinned here is what
        // a program does against a fleet right now.
        let now = chrono::Utc::now();
        let observation = observed(&release, now);
        let the_plan = plan::plan(
            &release,
            "all",
            &observation,
            None,
            &PlanPolicy::new(PlanKind::Upgrade),
            now,
        )
        .expect("the fixture plans");

        std::fs::write(cwd.path().join("release.json"), release.to_json().unwrap()).unwrap();
        std::fs::write(cwd.path().join("plan.json"), the_plan.to_json().unwrap()).unwrap();
        std::fs::write(
            cwd.path().join("fleet.toml"),
            include_str!("fixtures/fleet-v2.toml"),
        )
        .unwrap();

        let sandbox = Sandbox {
            cwd,
            shims,
            answers,
            home,
            log,
            fleet,
            release,
            plan: the_plan,
            ssh_exit: 97,
            cli_exit: 97,
        };
        for id in sandbox.fleet.hosts.keys() {
            sandbox.answer(id, &probe_answer(&sandbox.fleet, &sandbox.release, id));
        }
        sandbox
    }

    fn answer(&self, id: &str, text: &str) {
        let address = &self.fleet.hosts[id].address;
        std::fs::write(self.answers.path().join(address), text).unwrap();
    }

    fn run(&self, args: &[&str]) -> Output {
        self.run_with(&[], args)
    }

    /// The same, wrapped in a program of its own — `unshare -rn`, for the
    /// one test that needs the network taken away.
    fn run_with(&self, wrapper: &[&str], args: &[&str]) -> Output {
        let mut command = match wrapper.split_first() {
            Some((program, rest)) => {
                let mut command = Command::new(program);
                command.args(rest).arg(BIN);
                command
            }
            None => Command::new(BIN),
        };
        command
            .args(args)
            .current_dir(self.cwd.path())
            .env("PATH", self.shims.path())
            .env("MEISTER_SHIM_LOG", &self.log)
            .env("MEISTER_SHIM_ANSWERS", self.answers.path())
            .env("MEISTER_SHIM_SSH_EXIT", self.ssh_exit.to_string())
            .env("MEISTER_SHIM_CLI_EXIT", self.cli_exit.to_string())
            .env("HOME", self.home.path())
            .output()
            .expect("the binary was just built")
    }

    /// One entry per invocation; a multi-line argument is joined back on.
    fn calls(&self) -> Vec<String> {
        let Ok(text) = std::fs::read_to_string(&self.log) else {
            return Vec::new();
        };
        let mut out: Vec<String> = Vec::new();
        for line in text.lines() {
            let starts = SHIMS
                .iter()
                .any(|shim| line == *shim || line.starts_with(&format!("{shim} ")));
            if starts {
                out.push(line.to_string());
            } else if let Some(last) = out.last_mut() {
                last.push(' ');
                last.push_str(line);
            }
        }
        out
    }

    fn forget_calls(&self) {
        let _ = std::fs::remove_file(&self.log);
    }

    fn state(&self) -> PathBuf {
        self.cwd.path().join(".meister-deploy")
    }
}

fn snapshot_of(dir: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    let mut out = BTreeMap::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(next) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&next) else {
            continue;
        };
        for entry in entries {
            let path = entry.unwrap().path();
            if path.is_dir() {
                stack.push(path);
            } else {
                out.insert(path.clone(), std::fs::read(&path).unwrap_or_default());
            }
        }
    }
    out
}

fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

fn code(out: &Output) -> i32 {
    out.status.code().unwrap_or(-1)
}

// ---------------------------------------------------------------------------

#[test]
fn a_dry_run_asks_the_hosts_and_writes_nothing_at_all() {
    let sandbox = Sandbox::new();
    let before = snapshot_of(sandbox.cwd.path());
    let out = sandbox.run(&[
        "apply",
        "--plan",
        "plan.json",
        "--release",
        "release.json",
        "--repo",
        ".",
        "--inventory",
        "fleet.toml",
        "--dry-run",
    ]);
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    assert!(
        stderr(&out).contains("the plan still matches the fleet"),
        "{}",
        stderr(&out)
    );
    assert!(
        stderr(&out).contains("nothing was locked"),
        "{}",
        stderr(&out)
    );
    assert_eq!(
        before,
        snapshot_of(sandbox.cwd.path()),
        "a dry run left something behind"
    );
    assert!(
        !sandbox.state().exists(),
        "a dry run made a state directory"
    );

    // It looked, and it looked only with the two read-only programs.
    let calls = sandbox.calls();
    assert!(!calls.is_empty(), "a dry run asked nobody anything");
    for call in &calls {
        assert!(
            call.starts_with("ssh-keygen") || call.starts_with("ssh "),
            "a dry run ran {call}"
        );
        // The helper as an INVOCATION — `[meister-activate] [--json]` in
        // the shim's log — rather than the word inside the probe script,
        // which asks whether the program is there at all.
        assert!(
            !call.contains("[meister-activate] [--json]"),
            "a dry run reached for the helper: {call}"
        );
    }
    // Every step of the plan is on stdout, so an operator can read what
    // would happen without it happening.
    let listed = stdout(&out);
    for action in &sandbox.plan.actions {
        assert!(
            listed.contains(&format!("{}\t{}", action.seq, action.host)),
            "the step {} on {} is not in the listing",
            action.seq,
            action.host
        );
    }
}

#[test]
fn a_run_that_changes_nothing_still_takes_the_anchor_and_writes_its_receipt() {
    // Every host already runs the release, so the whole plan is two steps
    // per host and neither touches anything (V10). What the run still does
    // is take the control plane's lock (D6) and leave a receipt.
    let mut sandbox = Sandbox::new();
    // The helper answers `ok` on every host, which is what a lock acquire
    // and a lock release get from a host that is not held.
    sandbox.ssh_exit = 0;
    let out = sandbox.run(&[
        "apply",
        "--plan",
        "plan.json",
        "--release",
        "release.json",
        "--repo",
        ".",
        "--inventory",
        "fleet.toml",
    ]);
    assert_eq!(code(&out), 0, "{}", stderr(&out));

    let run_id = stdout(&out).lines().next().unwrap_or_default().to_string();
    assert_eq!(run_id.len(), 36, "the run id goes to stdout: {run_id:?}");

    // The journal and the receipt are where `report` looks for them.
    let journal = sandbox
        .state()
        .join("runs")
        .join(&run_id)
        .join("journal.jsonl");
    let receipt = sandbox
        .state()
        .join("runs")
        .join(&run_id)
        .join("receipt.json");
    assert!(journal.exists(), "no journal at {}", journal.display());
    assert!(receipt.exists(), "no receipt at {}", receipt.display());
    let text = std::fs::read_to_string(&receipt).unwrap();
    assert!(text.contains("\"outcome\": \"success\""), "{text}");
    assert!(text.contains("\"unchanged\""), "{text}");

    // The lock is given back, whatever the run came to.
    assert!(
        !sandbox.state().join("lock").exists(),
        "the state directory is still locked"
    );

    // And the only thing it did on a host was the anchor's lock.
    let helper_calls: Vec<String> = sandbox
        .calls()
        .into_iter()
        .filter(|c| c.contains("[meister-activate] [--json]"))
        .collect();
    assert_eq!(
        helper_calls.len(),
        2,
        "an unchanged fleet ran {helper_calls:?}"
    );
    assert!(
        helper_calls[0].contains("lock] [acquire]"),
        "{helper_calls:?}"
    );
    assert!(
        helper_calls[1].contains("lock] [release]"),
        "{helper_calls:?}"
    );

    // `report` reads back what the run wrote.
    let reported = sandbox.run(&["report", "--run", &run_id, "--repo", "."]);
    assert_eq!(code(&reported), 0, "{}", stderr(&reported));
    assert!(
        stdout(&reported).contains("unchanged"),
        "{}",
        stdout(&reported)
    );
}

// --- lane 5C ---

#[test]
fn a_resume_finds_the_plan_and_the_release_in_the_run_s_own_directory() {
    // L2 finding N10. `runs/<id>/` held the plan and not the release, so a
    // resume needed the operator's own `--out` file — and the next `build`
    // over the same path took it away. In the lab there was then no
    // supported way to continue an interrupted run at all.
    let mut sandbox = Sandbox::new();
    sandbox.ssh_exit = 0;
    let out = sandbox.run(&[
        "apply",
        "--plan",
        "plan.json",
        "--release",
        "release.json",
        "--repo",
        ".",
        "--inventory",
        "fleet.toml",
    ]);
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    let run_id = stdout(&out).lines().next().unwrap_or_default().to_string();

    let run_dir = sandbox.state().join("runs").join(&run_id);
    let kept = run_dir.join("release.json");
    assert!(kept.exists(), "no release at {}", kept.display());
    let release: ReleaseManifest =
        serde_json::from_slice(&std::fs::read(&kept).unwrap()).expect("it reads back");
    assert_eq!(release.release_id, sandbox.release.release_id);

    // And now the operator builds again over the same file, which is what
    // happened in the lab. Both documents are gone from the working
    // directory.
    std::fs::remove_file(sandbox.cwd.path().join("release.json")).unwrap();
    std::fs::remove_file(sandbox.cwd.path().join("plan.json")).unwrap();
    sandbox.forget_calls();

    let again = sandbox.run(&["apply", "--resume", &run_id, "--repo", "."]);
    assert_eq!(code(&again), 0, "{}", stderr(&again));
    assert!(
        stderr(&again).contains("resuming from"),
        "{}",
        stderr(&again)
    );
    assert!(
        stderr(&again).contains("release.json"),
        "{}",
        stderr(&again)
    );
}

#[test]
fn apply_without_a_plan_and_without_a_resume_says_which_one_is_missing() {
    let sandbox = Sandbox::new();
    let out = sandbox.run(&["apply", "--release", "release.json", "--repo", "."]);
    assert_eq!(code(&out), 1, "{}", stderr(&out));
    assert!(
        stderr(&out).contains("--plan is missing"),
        "{}",
        stderr(&out)
    );
    let out = sandbox.run(&["apply", "--repo", "."]);
    assert_eq!(code(&out), 1, "{}", stderr(&out));
    assert!(
        stderr(&out).contains("Neither was named"),
        "{}",
        stderr(&out)
    );
}

// --- end lane 5C ---

#[test]
fn a_second_operator_is_refused_by_the_state_directory() {
    // V18 on the workstation: the fleet's own anchor is the per-host lock,
    // and this is the door of the repository.
    let sandbox = Sandbox::new();
    std::fs::create_dir_all(sandbox.state()).unwrap();
    std::fs::write(
        sandbox.state().join("lock"),
        serde_json::to_vec_pretty(&serde_json::json!({
            "schema": "meister-deploy/operator-lock/1",
            "run_id": "0192f0c0-0000-7000-8000-00000000abcd",
            "operator": "somebody",
            "workstation": "elsewhere",
            "pid": 4242,
            "acquired_at": "2026-09-22T11:00:00Z",
        }))
        .unwrap(),
    )
    .unwrap();
    sandbox.forget_calls();
    let out = sandbox.run(&[
        "apply",
        "--plan",
        "plan.json",
        "--release",
        "release.json",
        "--repo",
        ".",
        "--inventory",
        "fleet.toml",
    ]);
    assert_eq!(code(&out), 1, "{}", stderr(&out));
    assert!(stderr(&out).contains("somebody"), "{}", stderr(&out));
    assert!(stderr(&out).contains("--takeover"), "{}", stderr(&out));
    assert!(
        sandbox.calls().is_empty(),
        "a refused run still asked a host: {:?}",
        sandbox.calls()
    );
}

#[test]
fn a_plan_and_a_release_that_do_not_belong_together_are_refused_by_name() {
    let sandbox = Sandbox::new();
    // A release of a fleet whose systems are different: same shape, other
    // bytes, other id.
    let mut other = sandbox.fleet.clone();
    for host in other.hosts.values_mut() {
        host.build.toplevel_out = format!("{}-other", host.build.toplevel_out);
    }
    other.manifest_id =
        meister_deploy::ids::content_id(meister_deploy::ids::IdKind::Manifest, &other).unwrap();
    let other = release_of(other);
    std::fs::write(
        sandbox.cwd.path().join("other.json"),
        other.to_json().unwrap(),
    )
    .unwrap();
    let out = sandbox.run(&[
        "apply",
        "--plan",
        "plan.json",
        "--release",
        "other.json",
        "--repo",
        ".",
    ]);
    assert_eq!(code(&out), 1, "{}", stderr(&out));
    assert!(
        stderr(&out).contains("another build is another plan"),
        "{}",
        stderr(&out)
    );
    assert!(sandbox.calls().is_empty(), "{:?}", sandbox.calls());
    assert!(
        !sandbox.state().exists(),
        "a refusal made a state directory"
    );
}

#[test]
fn an_approval_is_a_class_and_a_plan_id_and_nothing_else() {
    let sandbox = Sandbox::new();
    let out = sandbox.run(&[
        "apply",
        "--plan",
        "plan.json",
        "--release",
        "release.json",
        "--repo",
        ".",
        "--inventory",
        "fleet.toml",
        "--approve",
        "reboot",
    ]);
    assert_eq!(code(&out), 1, "{}", stderr(&out));
    assert!(
        stderr(&out).contains("<class>=<plan_id>"),
        "{}",
        stderr(&out)
    );

    let out = sandbox.run(&[
        "apply",
        "--plan",
        "plan.json",
        "--release",
        "release.json",
        "--repo",
        ".",
        "--inventory",
        "fleet.toml",
        "--approve",
        "whenever-i-feel-like-it=plan-1",
    ]);
    assert_eq!(code(&out), 1, "{}", stderr(&out));
    assert!(stderr(&out).contains("singleton"), "{}", stderr(&out));
}

/// V20, and the only test in this crate that can show it.
///
/// `unshare -rn` gives the process a network namespace with one interface,
/// `lo`, and it is DOWN. Anything that opens a socket to an address fails
/// there. A run whose output is identical inside and outside it is a run
/// whose entire reach outside this process goes through the programs on
/// `PATH` — which the log then names, one by one.
#[test]
fn a_dry_run_behaves_the_same_with_the_network_taken_away() {
    // M0 probe S13 measured that this is allowed on this machine. If it
    // ever is not, the test says so instead of passing quietly.
    let unshare = ["/usr/bin/unshare", "/bin/unshare", "/usr/sbin/unshare"]
        .into_iter()
        .find(|p| Path::new(p).exists())
        .unwrap_or("/usr/bin/unshare");
    let allowed = Command::new(unshare)
        .args(["-rn", "true"])
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    assert!(
        allowed,
        "unshare -rn is not available here, so this test could not show what it is for. \
         It is not skipped: the claim V20 makes needs it."
    );

    let sandbox = Sandbox::new();
    let plain = sandbox.run(&[
        "apply",
        "--plan",
        "plan.json",
        "--release",
        "release.json",
        "--repo",
        ".",
        "--inventory",
        "fleet.toml",
        "--dry-run",
    ]);
    let outside = sandbox.calls();
    sandbox.forget_calls();
    let before = snapshot_of(sandbox.cwd.path());

    let inside = sandbox.run_with(
        &[unshare, "-rn"],
        &[
            "apply",
            "--plan",
            "plan.json",
            "--release",
            "release.json",
            "--repo",
            ".",
            "--inventory",
            "fleet.toml",
            "--dry-run",
        ],
    );
    assert_eq!(
        code(&plain),
        code(&inside),
        "the same run said {} outside the namespace and {} inside it\n--- outside ---\n{}\n\
         --- inside ---\n{}",
        code(&plain),
        code(&inside),
        stderr(&plain),
        stderr(&inside)
    );
    assert_eq!(
        stdout(&plain),
        stdout(&inside),
        "the same run printed something else with the network taken away"
    );
    assert_eq!(
        outside,
        sandbox.calls(),
        "the same run started other programs with the network taken away"
    );
    assert_eq!(
        before,
        snapshot_of(sandbox.cwd.path()),
        "the run in the namespace left something behind"
    );
}

// ---------------------------------------------------------------------------
// lane 3-integration: the halt, at the real binary
// ---------------------------------------------------------------------------

/// A sandbox whose `n1` is a guest with no boot loader, switched to the
/// release and still running the kernel its provider last handed it.
///
/// The shortest road to a `provider-reboot` that the shims can walk: nothing
/// is staged (the closure is there), nothing is activated (the profile
/// already points at it), and what is left is the boot — which is the one
/// step this tool does not take.
fn waiting_for_a_provider() -> Sandbox {
    let mut sandbox = Sandbox::new();
    let base = support::with_direct_host(sandbox.fleet.clone(), "n1");
    let before = support::direct_release_of(base.clone());
    let release = support::direct_release_of(support::with_new_toplevels(base, &["n1"], true));
    let old = before.artifacts["n1"].toplevel.store_path.clone();
    let new = release.artifacts["n1"].toplevel.store_path.clone();

    // What the machine says: it RUNS the new system and it BOOTED the old
    // one, because the thing that decides the second is a hypervisor.
    let mut observation = observed(&before, chrono::Utc::now());
    {
        let n1 = observation.hosts.get_mut("n1").unwrap();
        n1.current_system = Some(new.clone());
        n1.next_boot_system = Some(new.clone());
    }
    let the_plan = plan::plan(
        &release,
        "all",
        &observation,
        None,
        &PlanPolicy::new(PlanKind::Upgrade).with_workload_control(Some(
            meister_deploy::plan::WorkloadControl {
                cli_config: "cli.toml".to_string(),
                cli_profile: Some("cloud-mtls".to_string()),
            },
        )),
        chrono::Utc::now(),
    )
    .expect("the fixture plans");

    std::fs::write(
        sandbox.cwd.path().join("release.json"),
        release.to_json().unwrap(),
    )
    .unwrap();
    std::fs::write(
        sandbox.cwd.path().join("plan.json"),
        the_plan.to_json().unwrap(),
    )
    .unwrap();
    sandbox.fleet = release.resolved_fleet.clone();
    sandbox.release = release;
    sandbox.plan = the_plan;
    // The helper and the cli answer; the machine answers the probe with the
    // two lines that make it a host waiting for its provider.
    sandbox.ssh_exit = 0;
    sandbox.cli_exit = 0;
    for id in sandbox.fleet.hosts.keys() {
        let mut answer = probe_answer(&sandbox.fleet, &before, id);
        if id == "n1" {
            answer = answer.replace(
                &format!("current_system={old}"),
                &format!("current_system={new}"),
            );
            answer = answer.replace(
                &format!("next_boot_system={old}"),
                &format!("next_boot_system={new}"),
            );
        }
        sandbox.answer(id, &answer);
    }
    sandbox
}

#[test]
fn a_halt_in_front_of_a_provider_is_exit_two_a_sentence_and_one_line_of_json() {
    let sandbox = waiting_for_a_provider();
    let approvals: Vec<String> = sandbox
        .plan
        .approvals
        .iter()
        .map(|a| format!("--approve {}={}", a.class, a.bound_plan_id))
        .collect();
    let mut args = vec![
        "apply",
        "--plan",
        "plan.json",
        "--release",
        "release.json",
        "--repo",
        ".",
        "--inventory",
        "fleet.toml",
    ];
    let granted: Vec<&str> = approvals
        .iter()
        .flat_map(|a| a.split(' '))
        .filter(|s| !s.is_empty())
        .collect();
    args.extend(granted);
    let out = sandbox.run(&args);

    // Exit 2: this tool worked and the fleet is not where the plan wants it
    // yet. Not 1, which is "this tool broke".
    assert_eq!(code(&out), 2, "{}\n{}", stdout(&out), stderr(&out));

    let bundle = sandbox.release.artifacts["n1"]
        .direct_boot
        .clone()
        .expect("a direct host carries a bundle");

    // The sentence, for the person.
    let said = stderr(&out);
    assert!(said.contains(&bundle.kernel.store_path), "{said}");
    assert!(said.contains(&bundle.initrd.store_path), "{said}");
    assert!(said.contains(&bundle.cmdline), "{said}");
    assert!(said.contains("apply --resume"), "{said}");

    // The line, for the thing that will do it: one JSON object on stdout,
    // parsed here rather than grepped.
    let line = stdout(&out)
        .lines()
        .find(|l| l.starts_with('{') && l.contains("waiting_for"))
        .expect("a launcher gets a line it can read")
        .to_string();
    let halt: serde_json::Value = serde_json::from_str(&line).expect("it is json");
    assert_eq!(halt["waiting_for"], "provider-reboot");
    assert_eq!(halt["host"], "n1");
    assert_eq!(halt["bundle"]["cmdline"], bundle.cmdline);
    assert_eq!(
        halt["bundle"]["kernel"]["store_path"],
        bundle.kernel.store_path
    );
    assert_eq!(
        halt["bundle"]["initrd"]["store_path"],
        bundle.initrd.store_path
    );
    let run = halt["resume"]
        .as_str()
        .expect("it names the run")
        .to_string();

    // Nothing was built, nothing was copied and nobody was rebooted.
    for call in sandbox.calls() {
        assert!(!call.starts_with("nix "), "{call}");
        assert!(!call.contains("systemctl reboot"), "{call}");
        assert!(!call.contains("[activate]"), "{call}");
    }

    // The journal has the step, has no end for it, and carries the bundle
    // on the line that says where the run stopped.
    let journal = std::fs::read_to_string(
        sandbox
            .state()
            .join("runs")
            .join(&run)
            .join("journal.jsonl"),
    )
    .expect("the run wrote a journal");
    let events: Vec<serde_json::Value> = journal
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).expect("a journal line is json"))
        .collect();
    let begun = events
        .iter()
        .any(|e| e["event"] == "action.begin" && e["payload"]["kind"] == "provider-reboot");
    assert!(begun, "{journal}");
    let ended = events
        .iter()
        .any(|e| e["event"] == "action.end" && e["payload"]["kind"] == "provider-reboot");
    assert!(!ended, "a step that did not happen has no end: {journal}");
    let halt_line = events
        .iter()
        .find(|e| e["to"] == "awaiting-reboot")
        .expect("the journal says where it stopped");
    assert_eq!(halt_line["payload"]["waiting_for"], "provider-reboot");
    assert_eq!(halt_line["payload"]["bundle"]["cmdline"], bundle.cmdline);
    assert!(
        events.iter().any(|e| e["event"] == "run.end"),
        "the run ended rather than hanging: {journal}"
    );

    // And the receipt of that run says the same thing in its own words.
    let receipt: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(sandbox.state().join("runs").join(&run).join("receipt.json"))
            .expect("the run wrote a receipt"),
    )
    .expect("a receipt is json");
    assert_eq!(receipt["hosts"]["n1"]["state"], "awaiting-reboot");
    assert_ne!(receipt["outcome"], "success");
}

// Astra finding MD09, 2026-09-25: `--json` promised one json document and
// printed the run id as a bare line in front of it, and the halt for a
// provider as a second document after it. A parser fed the whole of stdout
// failed on the first byte.
#[test]
fn apply_json_is_one_document_that_carries_the_run_id_the_halt_and_the_stop() {
    let sandbox = waiting_for_a_provider();
    let approvals: Vec<String> = sandbox
        .plan
        .approvals
        .iter()
        .map(|a| format!("--approve {}={}", a.class, a.bound_plan_id))
        .collect();
    let mut args = vec![
        "apply",
        "--json",
        "--plan",
        "plan.json",
        "--release",
        "release.json",
        "--repo",
        ".",
        "--inventory",
        "fleet.toml",
    ];
    let granted: Vec<&str> = approvals
        .iter()
        .flat_map(|a| a.split(' '))
        .filter(|s| !s.is_empty())
        .collect();
    args.extend(granted);
    let out = sandbox.run(&args);
    assert_eq!(code(&out), 2, "{}\n{}", stdout(&out), stderr(&out));

    // The WHOLE of stdout, not a line picked out of it.
    let document: serde_json::Value = serde_json::from_str(&stdout(&out))
        .unwrap_or_else(|e| panic!("stdout is not one json document ({e}):\n{}", stdout(&out)));
    let run = document["run_id"]
        .as_str()
        .expect("the receipt names the run")
        .to_string();
    assert!(!run.is_empty());
    assert_eq!(document["waiting"]["waiting_for"], "provider-reboot");
    assert_eq!(document["waiting"]["host"], "n1");
    assert_eq!(document["waiting"]["resume"], run);
    assert!(
        document["stopped"]
            .as_str()
            .is_some_and(|s| s.contains("n1")),
        "{document}"
    );
    // The run id still reaches the person, on stderr.
    assert!(stderr(&out).contains(&run), "{}", stderr(&out));
    // And the receipt on the disk is the same document.
    let on_disk: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(sandbox.state().join("runs").join(&run).join("receipt.json"))
            .expect("the run wrote a receipt"),
    )
    .expect("the receipt is json");
    assert_eq!(on_disk["waiting"], document["waiting"]);
    assert_eq!(on_disk["stopped"], document["stopped"]);
}
