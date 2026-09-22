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

use support::{at, observed, onebox, probe_answer, release_of};

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
        let observation = observed(&release, at("2026-09-22T12:00:00Z"));
        let the_plan = plan::plan(
            &release,
            "all",
            &observation,
            None,
            &PlanPolicy::new(PlanKind::Upgrade),
            at("2026-09-22T12:00:00Z"),
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
