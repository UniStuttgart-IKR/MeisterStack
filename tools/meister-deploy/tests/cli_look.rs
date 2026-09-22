// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! What the reading verbs do to the machine they run on, and to the
//! machines they ask — measured through the real binary.
//!
//! The unit tests pin the parser, the probe script and the readiness rules.
//! This pins the PROGRAM: `PATH` holds nothing but a directory of shims, so
//! whatever `meister-deploy status`, `check`, `plan` or `build --dry-run`
//! runs is in a log, and whatever the log does not have they did not run.
//! Two of the shims answer rather than fail — `ssh-keygen` hands back a
//! `known_hosts` line and `ssh` hands back a probe answer read from a file
//! — so the whole path from "ask the fleet" to "a snapshot on disk and a
//! verdict on stderr" runs here, with no host and no network anywhere.
//!
//! The working directory is compared byte for byte before and after, so
//! "wrote nothing" is a comparison and not a claim.
//!
//! What this cannot show is a syscall that reaches the network without one
//! of the shimmed programs. There is no socket in this crate; the `unshare
//! -rn` proof of that belongs to lane 2C, which is the one that gets a verb
//! with something to hide.

mod support;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use meister_deploy::manifest::ResolvedFleet;
use meister_deploy::release::ReleaseManifest;

use support::{onebox, release_of};

const BIN: &str = env!("CARGO_BIN_EXE_meister-deploy");

/// Every program these verbs are allowed to know about.
const SHIMS: [&str; 5] = ["nix", "git", "rsync", "ssh", "ssh-keygen"];

/// An ed25519 public key of all zeroes, and the fingerprint `ssh-keygen -lf`
/// computes for it. The fleet in this test is enrolled with exactly this
/// key, so the identity check has something true to compare.
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
}

impl Sandbox {
    /// A directory with a release of the one-box fleet, every host enrolled
    /// with [`ENROLLED_KEY`], and shims that answer.
    fn new() -> Sandbox {
        use std::os::unix::fs::PermissionsExt;
        let shims = tempfile::tempdir().unwrap();
        let answers = tempfile::tempdir().unwrap();
        let cwd = tempfile::tempdir().unwrap();
        let home = tempfile::tempdir().unwrap();
        let log = shims.path().join("calls.log");

        for name in SHIMS {
            let body = match name {
                // Hands back the `known_hosts` line of the key the fleet is
                // enrolled with. The tool computes the fingerprint from it
                // rather than believing a host that claims one.
                "ssh-keygen" => format!(
                    "#!/bin/sh\nline=\"{name}\"\n\
                     for a in \"$@\"; do line=\"$line [$a]\"; done\n\
                     printf '%s\\n' \"$line\" >> \"$MEISTER_SHIM_LOG\"\n\
                     printf '# Host found: line 1\\n10.0.0.10 ssh-ed25519 {ENROLLED_KEY}\\n'\n\
                     exit 0\n"
                ),
                // Reads the answer prepared for the address in the argv. No
                // external program in the body: PATH holds only this
                // directory while the binary runs, so the file is read with
                // shell builtins.
                "ssh" => format!(
                    "#!/bin/sh\nline=\"{name}\"\naddr=\n\
                     for a in \"$@\"; do line=\"$line [$a]\"; \
                     case \"$a\" in *@*) addr=${{a#*@}};; esac; done\n\
                     printf '%s\\n' \"$line\" >> \"$MEISTER_SHIM_LOG\"\n\
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

        // The fleet, enrolled with the key the shim hands back, and a
        // release of it. Both go through the public API, so a change to a
        // contract breaks this at the contract.
        let mut fleet = onebox();
        for host in fleet.hosts.values_mut() {
            host.ssh.host_key_fingerprint = Some(ENROLLED_FINGERPRINT.to_string());
        }
        fleet.manifest_id =
            meister_deploy::ids::content_id(meister_deploy::ids::IdKind::Manifest, &fleet).unwrap();
        let release = release_of(fleet.clone());
        std::fs::write(cwd.path().join("release.json"), release.to_json().unwrap()).unwrap();
        std::fs::write(cwd.path().join("manifest.json"), fleet.to_json().unwrap()).unwrap();
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
        };
        sandbox.answer_healthily();
        sandbox
    }

    /// Prepare a healthy probe answer for every host.
    fn answer_healthily(&self) {
        for id in self.fleet.hosts.keys() {
            self.answer(id, &self.healthy_answer(id));
        }
    }

    /// What one host says: the shared builder, so that the two test
    /// binaries that shim `ssh` answer with the same shape.
    fn healthy_answer(&self, id: &str) -> String {
        support::probe_answer(&self.fleet, &self.release, id)
    }

    fn answer(&self, id: &str, text: &str) {
        let address = &self.fleet.hosts[id].address;
        std::fs::write(self.answers.path().join(address), text).unwrap();
    }

    /// Take a host's answer away: what an unreachable host looks like.
    fn silence(&self, id: &str) {
        let address = &self.fleet.hosts[id].address;
        let _ = std::fs::remove_file(self.answers.path().join(address));
    }

    fn run(&self, args: &[&str]) -> Output {
        Command::new(BIN)
            .args(args)
            .current_dir(self.cwd.path())
            .env("PATH", self.shims.path())
            .env("MEISTER_SHIM_LOG", &self.log)
            .env("MEISTER_SHIM_ANSWERS", self.answers.path())
            .env("HOME", self.home.path())
            .output()
            .expect("the binary was just built")
    }

    /// One entry per invocation.
    ///
    /// The probe script is a multi-line argument, so a shim's single
    /// `printf` still lands as several LINES in the log. A line that does
    /// not begin with the name of a shim is therefore a continuation of the
    /// invocation above it, and is joined back on — otherwise "one round
    /// trip per host" would be counted in lines of shell.
    fn calls(&self) -> Vec<String> {
        let Ok(text) = std::fs::read_to_string(&self.log) else {
            return Vec::new();
        };
        let mut out: Vec<String> = Vec::new();
        for line in text.lines() {
            let starts_an_invocation = SHIMS
                .iter()
                .any(|shim| line == *shim || line.starts_with(&format!("{shim} ")));
            if starts_an_invocation {
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
// build
// ---------------------------------------------------------------------------

#[test]
fn a_dry_run_of_build_prints_the_derivations_and_builds_none_of_them() {
    let sandbox = Sandbox::new();
    let before = snapshot_of(sandbox.cwd.path());
    let out = sandbox.run(&[
        "build",
        "--manifest",
        "manifest.json",
        "--out",
        "release-2.json",
        "--dry-run",
    ]);
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    // The list, one derivation per line, and every one of them is a path
    // the manifest wrote down.
    let printed = stdout(&out);
    let lines: Vec<&str> = printed.lines().collect();
    assert_eq!(lines.len(), 6, "three hosts and three packages: {lines:?}");
    for line in &lines {
        let (what, drv) = line.split_once('\t').expect("what and the derivation");
        assert!(drv.ends_with(".drv"), "{line}");
        assert!(!what.is_empty());
    }
    assert!(stdout(&out).contains(&sandbox.fleet.hosts["box"].build.toplevel_drv));
    // And nothing happened: no program, no file.
    assert!(sandbox.calls().is_empty(), "{:?}", sandbox.calls());
    assert_eq!(snapshot_of(sandbox.cwd.path()), before);
    assert!(!sandbox.cwd.path().join("release-2.json").exists());
    assert!(
        stderr(&out).contains("nothing was built"),
        "{}",
        stderr(&out)
    );
}

#[test]
fn an_offline_build_refuses_and_touches_nothing() {
    let sandbox = Sandbox::new();
    let before = snapshot_of(sandbox.cwd.path());
    let out = sandbox.run(&[
        "build",
        "--manifest",
        "manifest.json",
        "--out",
        "release-2.json",
        "--offline",
    ]);
    assert_eq!(code(&out), 1);
    assert!(stdout(&out).is_empty());
    assert!(
        stderr(&out).contains("--offline forbids it"),
        "{}",
        stderr(&out)
    );
    assert!(sandbox.calls().is_empty());
    assert_eq!(snapshot_of(sandbox.cwd.path()), before);
}

#[test]
fn a_build_with_no_key_anywhere_stops_before_it_runs_nix() {
    let sandbox = Sandbox::new();
    // An inventory without `[operator] signing_key`, and no --sign-key.
    std::fs::write(
        sandbox.cwd.path().join("empty.toml"),
        "schema = 2\n[fleet]\nname = \"x\"\n",
    )
    .unwrap();
    let out = sandbox.run(&[
        "build",
        "--manifest",
        "manifest.json",
        "--out",
        "release-2.json",
        "--inventory",
        "empty.toml",
    ]);
    assert_eq!(code(&out), 1);
    assert!(
        stderr(&out).contains("no signing key was given"),
        "{}",
        stderr(&out)
    );
    assert!(
        sandbox.calls().is_empty(),
        "not one nix ran: {:?}",
        sandbox.calls()
    );
}

// ---------------------------------------------------------------------------
// status
// ---------------------------------------------------------------------------

#[test]
fn status_asks_every_host_once_over_ssh_and_nothing_else() {
    let sandbox = Sandbox::new();
    let out = sandbox.run(&["status", "--release", "release.json", "--repo", "."]);
    assert_eq!(code(&out), 0, "{}", stderr(&out));

    let calls = sandbox.calls();
    // One local lookup and one round trip per host, and no other program.
    assert_eq!(calls.len(), 6, "{calls:?}");
    for id in ["box", "n1", "n2"] {
        let address = &sandbox.fleet.hosts[id].address;
        assert_eq!(
            calls
                .iter()
                .filter(|c| c.starts_with("ssh-keygen") && c.contains(address))
                .count(),
            1,
            "one known_hosts lookup for {id}: {calls:?}"
        );
        assert_eq!(
            calls
                .iter()
                .filter(|c| c.starts_with("ssh ") && c.contains(&format!("root@{address}")))
                .count(),
            1,
            "one probe for {id}: {calls:?}"
        );
    }
    assert!(
        calls.iter().all(|c| c.starts_with("ssh")),
        "no nix, no git, no rsync: {calls:?}"
    );
    // The options the connection was made with are the fleet's one set.
    let probe = calls
        .iter()
        .find(|c| c.starts_with("ssh "))
        .expect("a probe ran");
    for expected in [
        "[StrictHostKeyChecking=yes]",
        "[GlobalKnownHostsFile=/dev/null]",
        "[BatchMode=yes]",
        "[IdentitiesOnly=yes]",
        "[ConnectTimeout=10]",
        "[ServerAliveInterval=15]",
    ] {
        assert!(probe.contains(expected), "{expected} missing from {probe}");
    }
    assert!(
        !probe.contains("accept-new") && !probe.contains("StrictHostKeyChecking=no]"),
        "{probe}"
    );

    // Every host answered, and the table says so.
    let table = stdout(&out);
    for id in ["box", "n1", "n2"] {
        assert!(table.contains(id), "{table}");
    }
    assert!(table.contains("0 fail, 0 unknown"), "{table}");
    assert!(!table.contains("REQUIRED"), "nothing failed:\n{table}");

    // And the snapshot is on disk, twice, as the contract object.
    let latest = sandbox.state().join("observations/latest.json");
    let text = std::fs::read_to_string(&latest).expect("latest.json was written");
    let snapshot = meister_deploy::observation::Observations::from_json(&text, "latest.json")
        .expect("it is an observation/1");
    assert_eq!(snapshot.hosts.len(), 3);
    assert!(!snapshot.provisional);
    // The fingerprint is the one the fleet's key hashes to, not one a host
    // claimed.
    for host in snapshot.hosts.values() {
        assert!(host.reachable);
        assert_eq!(
            host.identity.host_key_fingerprint.as_deref(),
            Some(ENROLLED_FINGERPRINT)
        );
        assert_eq!(host.generation, Some(42));
        assert!(host.enrolled);
    }
    assert!(stderr(&out).contains("==> "), "{}", stderr(&out));
}

#[test]
fn status_offline_answers_from_the_last_snapshot_and_asks_nobody() {
    let sandbox = Sandbox::new();
    // First a run that asks, to leave a snapshot behind.
    let out = sandbox.run(&["status", "--release", "release.json", "--repo", "."]);
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    let after_first = snapshot_of(sandbox.cwd.path());
    sandbox.forget_calls();

    let out = sandbox.run(&[
        "status",
        "--release",
        "release.json",
        "--repo",
        ".",
        "--offline",
        "--json",
    ]);
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    assert!(
        sandbox.calls().is_empty(),
        "an offline status asks nobody: {:?}",
        sandbox.calls()
    );
    // It wrote nothing either: the directory is byte for byte what the
    // first run left.
    assert_eq!(snapshot_of(sandbox.cwd.path()), after_first);
    assert!(
        stderr(&out).contains("nothing was asked of any host"),
        "{}",
        stderr(&out)
    );
    // And what came out is the contract object, with the snapshot whole
    // inside it.
    let report = meister_deploy::readiness::StatusReport::from_json(&stdout(&out), "stdout")
        .expect("a status/1");
    assert_eq!(report.observation.hosts.len(), 3);
    assert_eq!(
        report.release_id.as_deref(),
        Some(sandbox.release.release_id.as_str())
    );
    assert!(
        report
            .checks
            .iter()
            .all(|c| c.status != meister_deploy::checks::Status::Fail)
    );
}

#[test]
fn status_needs_a_fleet_and_says_which_two_files_are_one() {
    let sandbox = Sandbox::new();
    let out = sandbox.run(&["status"]);
    assert_eq!(code(&out), 1);
    assert!(
        stderr(&out).contains("--release <file>"),
        "{}",
        stderr(&out)
    );
    assert!(
        stderr(&out).contains("--manifest <file>"),
        "{}",
        stderr(&out)
    );
    assert!(sandbox.calls().is_empty());
}

#[test]
fn a_host_that_says_nothing_is_unreachable_and_the_others_are_still_read() {
    let sandbox = Sandbox::new();
    sandbox.silence("n1");
    let out = sandbox.run(&["status", "--release", "release.json", "--repo", "."]);
    assert_eq!(code(&out), 0, "status reports, it does not judge");
    let text = std::fs::read_to_string(sandbox.state().join("observations/latest.json")).unwrap();
    let snapshot =
        meister_deploy::observation::Observations::from_json(&text, "latest.json").unwrap();
    assert!(!snapshot.hosts["n1"].reachable);
    assert!(
        snapshot.hosts["n1"]
            .unknown_reason
            .as_deref()
            .is_some_and(|r| r.contains("did not answer")),
        "{:?}",
        snapshot.hosts["n1"].unknown_reason
    );
    // The other two were read anyway: one host that is gone does not take
    // the snapshot with it.
    assert!(snapshot.hosts["box"].reachable);
    assert!(snapshot.hosts["n2"].reachable);
    assert!(stdout(&out).contains("REQUIRED"), "{}", stdout(&out));
}

// ---------------------------------------------------------------------------
// check
// ---------------------------------------------------------------------------

#[test]
fn check_is_exit_zero_when_every_required_check_passed() {
    let sandbox = Sandbox::new();
    let out = sandbox.run(&["check", "--release", "release.json", "--repo", "."]);
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    assert!(
        stderr(&out).contains("every required check passed"),
        "{}",
        stderr(&out)
    );
}

#[test]
fn check_is_exit_two_when_the_fleet_is_not_ready_and_says_why() {
    let sandbox = Sandbox::new();
    // A unit that is not running, on a host whose inventory requires it.
    let broken = sandbox.healthy_answer("n1").replace(
        "unit=meister-agent.service\tactive",
        "unit=meister-agent.service\tfailed",
    );
    sandbox.answer("n1", &broken);
    let out = sandbox.run(&["check", "--release", "release.json", "--repo", "."]);
    // Two and not one: the tool worked, and the answer is no.
    assert_eq!(code(&out), 2, "{}", stderr(&out));
    let why = stderr(&out);
    assert!(why.contains("blocked: units on n1"), "{why}");
    assert!(why.contains("not a failure of this tool"), "{why}");
    assert!(
        stdout(&out).contains("REQUIRED units on n1"),
        "{}",
        stdout(&out)
    );
}

#[test]
fn a_suite_that_does_work_on_the_fleet_is_not_something_check_does() {
    let sandbox = Sandbox::new();
    let out = sandbox.run(&[
        "check",
        "--release",
        "release.json",
        "--suite",
        "gpu",
        "--repo",
        ".",
    ]);
    assert_eq!(code(&out), 1);
    assert!(
        stderr(&out).contains("verify --suite gpu"),
        "{}",
        stderr(&out)
    );
    assert!(
        sandbox.calls().is_empty(),
        "nothing was asked: {:?}",
        sandbox.calls()
    );
}

// ---------------------------------------------------------------------------
// plan
// ---------------------------------------------------------------------------

#[test]
fn a_dry_run_of_plan_asks_the_fleet_and_keeps_nothing() {
    let sandbox = Sandbox::new();
    let before = snapshot_of(sandbox.cwd.path());
    let out = sandbox.run(&[
        "plan",
        "--release",
        "release.json",
        "--select",
        "all",
        "--inventory",
        "fleet.toml",
        "--repo",
        ".",
        "--out",
        "plan.json",
        "--dry-run",
    ]);
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    // It asked: one lookup and one probe per host.
    assert_eq!(sandbox.calls().len(), 6, "{:?}", sandbox.calls());
    // And kept nothing at all — not the plan, not the snapshot.
    assert_eq!(snapshot_of(sandbox.cwd.path()), before);
    assert!(!sandbox.cwd.path().join("plan.json").exists());
    assert!(!sandbox.state().exists(), "no state directory was made");
    assert!(
        stderr(&out).contains("was not written, and no snapshot was kept"),
        "{}",
        stderr(&out)
    );
    // The plan itself came out on stdout and carries the snapshot it was
    // made from.
    let plan: serde_json::Value = serde_json::from_str(&stdout(&out)).expect("a plan");
    assert_eq!(plan["observation"]["provisional"], serde_json::json!(false));
    assert_eq!(
        plan["hosts"]["box"]["verdict"],
        serde_json::json!("unchanged")
    );
}

#[test]
fn a_plan_that_asked_keeps_its_snapshot_and_names_it() {
    let sandbox = Sandbox::new();
    let out = sandbox.run(&[
        "plan",
        "--release",
        "release.json",
        "--select",
        "host=n1",
        "--inventory",
        "fleet.toml",
        "--repo",
        ".",
        "--out",
        "plan.json",
    ]);
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    // Only the selected host was asked. A plan over one host that probed
    // three would be a plan that looked at two machines nobody named.
    let calls = sandbox.calls();
    assert_eq!(calls.len(), 2, "{calls:?}");
    assert!(calls.iter().all(|c| c.contains("10.0.0.11")), "{calls:?}");

    let plan_id = stdout(&out).trim().to_string();
    assert!(plan_id.starts_with("plan-"), "{plan_id}");
    let text = std::fs::read_to_string(sandbox.cwd.path().join("plan.json")).unwrap();
    let plan = meister_deploy::plan::DeploymentPlan::from_json(&text, "plan.json")
        .expect("the plan reads back");
    assert_eq!(plan.plan_id, plan_id);
    assert_eq!(plan.selection.targets, vec!["n1".to_string()]);
    assert_eq!(plan.observation.hosts.len(), 1);
    // The snapshot is in the state directory as well, so that `status
    // --offline` and a later `plan` can read it.
    let latest = sandbox.state().join("observations/latest.json");
    assert!(latest.exists(), "latest.json");
    assert!(stderr(&out).contains("observations/"), "{}", stderr(&out));
}

// ---------------------------------------------------------------------------
// report
// ---------------------------------------------------------------------------

#[test]
fn report_reads_a_journal_and_a_plan_and_asks_nobody_anything() {
    let sandbox = Sandbox::new();
    // A run that got as far as staging n1 and then stopped, written the way
    // lane 2C will write it.
    let out = sandbox.run(&[
        "plan",
        "--release",
        "release.json",
        "--select",
        "host=n1",
        "--inventory",
        "fleet.toml",
        "--repo",
        ".",
        "--out",
        "plan.json",
    ]);
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    let text = std::fs::read_to_string(sandbox.cwd.path().join("plan.json")).unwrap();
    let plan = meister_deploy::plan::DeploymentPlan::from_json(&text, "plan.json").unwrap();
    let run = "0192f0c0-0000-7000-8000-00000000c0de";
    let dir = sandbox.state().join("runs").join(run);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::copy(sandbox.cwd.path().join("plan.json"), dir.join("plan.json")).unwrap();

    let events = [
        serde_json::json!({"seq":1,"ts":"2026-09-22T09:00:00Z","run_id":run,
            "plan_id":plan.plan_id,"event":"run.start","host":null,"from":null,"to":null,
            "payload":{"operator":{"user":"silas","workstation":"manacor"}}}),
        serde_json::json!({"seq":2,"ts":"2026-09-22T09:00:01Z","run_id":run,
            "plan_id":plan.plan_id,"event":"host.state","host":"n1","from":"planned",
            "to":"preflight","payload":{"system":"/nix/store/old-nixos-system-n1","generation":42}}),
        serde_json::json!({"seq":3,"ts":"2026-09-22T09:00:02Z","run_id":run,
            "plan_id":plan.plan_id,"event":"action.begin","host":"n1","from":null,"to":null,
            "payload":{"action":3,"kind":"stage"}}),
        serde_json::json!({"seq":4,"ts":"2026-09-22T09:00:20Z","run_id":run,
            "plan_id":plan.plan_id,"event":"action.end","host":"n1","from":null,"to":null,
            "payload":{"action":3,"kind":"stage","result":"ok"}}),
        serde_json::json!({"seq":5,"ts":"2026-09-22T09:00:21Z","run_id":run,
            "plan_id":plan.plan_id,"event":"host.state","host":"n1","from":"preflight",
            "to":"staged","payload":{}}),
    ];
    let mut journal = String::new();
    for event in &events {
        journal.push_str(&serde_json::to_string(event).unwrap());
        journal.push('\n');
    }
    // A last line the machine did not finish writing.
    journal.push_str("{\"seq\":6,\"ts\":\"2026-09-2");
    std::fs::write(dir.join("journal.jsonl"), &journal).unwrap();
    sandbox.forget_calls();

    let out = sandbox.run(&["report", "--run", run, "--repo", "."]);
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    assert!(sandbox.calls().is_empty(), "{:?}", sandbox.calls());
    let table = stdout(&out);
    assert!(table.contains(run), "{table}");
    assert!(table.contains("staged"), "{table}");
    assert!(
        table.contains("skipped"),
        "the running system never moved:\n{table}"
    );
    assert!(table.contains("journal:"), "{table}");
    let why = stderr(&out);
    assert!(why.contains("wrote no receipt of its own"), "{why}");
    assert!(
        why.contains("not a whole entry"),
        "the torn line is reported: {why}"
    );

    // The same thing as json is a receipt/1.
    let out = sandbox.run(&["report", "--run", run, "--repo", ".", "--json"]);
    let receipt = meister_deploy::receipt::DeploymentReceipt::from_json(&stdout(&out), "stdout")
        .expect("a receipt/1");
    assert_eq!(receipt.run_id, run);
    assert_eq!(receipt.plan_id, plan.plan_id);
    assert_eq!(receipt.hosts["n1"].state.as_str(), "staged");
    assert_eq!(receipt.journal_sha256.len(), 64);
}

#[test]
fn a_run_that_is_not_there_is_exit_one_and_names_what_is() {
    let sandbox = Sandbox::new();
    let out = sandbox.run(&[
        "report",
        "--run",
        "0192f0c0-0000-7000-8000-000000000000",
        "--repo",
        ".",
    ]);
    assert_eq!(code(&out), 1);
    assert!(stderr(&out).contains("holds no run"), "{}", stderr(&out));
    assert!(
        stderr(&out).contains("no runs in it at all"),
        "{}",
        stderr(&out)
    );
}

// ---------------------------------------------------------------------------
// gc
// ---------------------------------------------------------------------------

#[test]
fn gc_keeps_the_newest_and_removes_no_store_path() {
    let sandbox = Sandbox::new();
    let roots = sandbox.state().join("gcroots");
    for (release, when) in [
        ("release-aaa", "2026-09-01T00:00:00Z"),
        ("release-bbb", "2026-09-21T00:00:00Z"),
    ] {
        let dir = roots.join(release);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(".created"), format!("{when}\n")).unwrap();
        std::os::unix::fs::symlink("/nix/store/does-not-matter", dir.join("box")).unwrap();
    }

    let out = sandbox.run(&["gc", "--keep", "1", "--repo", ".", "--dry-run"]);
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    assert!(stdout(&out).contains("release-aaa"), "{}", stdout(&out));
    assert!(!stdout(&out).contains("release-bbb"), "{}", stdout(&out));
    assert!(
        roots.join("release-aaa").exists(),
        "a dry run removes nothing"
    );

    let out = sandbox.run(&["gc", "--keep", "1", "--repo", "."]);
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    assert!(!roots.join("release-aaa").exists(), "the roots are gone");
    // `symlink_metadata`, not `exists`: the link points at a store path
    // that was never there, and `exists` follows it.
    assert!(
        std::fs::symlink_metadata(roots.join("release-bbb/box")).is_ok(),
        "the newest is kept"
    );
    assert!(
        stderr(&out).contains("no store path was removed"),
        "{}",
        stderr(&out)
    );
    // And it ran no nix: dropping a root is a file operation.
    assert!(sandbox.calls().is_empty(), "{:?}", sandbox.calls());
}

// --- lane 4C: the other two things that pile up ---------------------------

#[test]
fn gc_leaves_the_snapshots_and_the_runs_alone_unless_it_is_asked() {
    let sandbox = Sandbox::new();
    let state = sandbox.state();
    let observations = state.join("observations");
    std::fs::create_dir_all(&observations).unwrap();
    for name in [
        "20260901T000000Z.json",
        "20260921T000000Z.json",
        "latest.json",
    ] {
        std::fs::write(observations.join(name), b"{}").unwrap();
    }

    // Nothing asked for: the snapshots are untouched and the note says
    // which flag would have touched them.
    let out = sandbox.run(&["gc", "--keep", "1", "--repo", "."]);
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    assert!(observations.join("20260901T000000Z.json").exists());
    assert!(
        stderr(&out).contains("--observations N"),
        "{}",
        stderr(&out)
    );
    assert!(stderr(&out).contains("--runs"), "{}", stderr(&out));

    // Asked for: the oldest goes and `latest.json` never does.
    let out = sandbox.run(&["gc", "--keep", "1", "--observations", "1", "--repo", "."]);
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    assert!(!observations.join("20260901T000000Z.json").exists());
    assert!(observations.join("20260921T000000Z.json").exists());
    assert!(
        observations.join("latest.json").exists(),
        "latest is never a candidate"
    );
}

#[test]
fn gc_never_removes_a_run_that_did_not_end_success() {
    let sandbox = Sandbox::new();
    let state = sandbox.state();
    let good = "0192f0c0-0000-7000-8000-00000000000a";
    let bad = "0192f0c0-0000-7000-8000-00000000000b";
    for (run, outcome) in [(good, "success"), (bad, "failed")] {
        let dir = state.join("runs").join(run);
        std::fs::create_dir_all(dir.join("observations")).unwrap();
        std::fs::write(dir.join("journal.jsonl"), b"{}\n").unwrap();
        std::fs::write(
            dir.join("receipt.json"),
            format!(
                r#"{{"schema":"meister-deploy/receipt/1","run_id":"{run}","plan_id":"p",
                    "release_id":"r","started_at":"2026-09-01T00:00:00Z",
                    "ended_at":"2026-09-01T00:10:00Z","operator":null,"outcome":"{outcome}",
                    "hosts":{{}},"untouched":[],"checks":[],"breaks":[],
                    "journal_path":"journal.jsonl","journal_sha256":"{}"}}"#,
                "0".repeat(64)
            ),
        )
        .unwrap();
    }

    let out = sandbox.run(&["gc", "--keep", "0", "--runs", "--repo", "."]);
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    assert!(
        !state.join("runs").join(good).exists(),
        "a finished run went"
    );
    assert!(
        state.join("runs").join(bad).exists(),
        "the one that failed is the one somebody has to read"
    );
    assert!(stderr(&out).contains("it ended failed"), "{}", stderr(&out));
    assert!(
        stderr(&out).contains("no store path was removed"),
        "{}",
        stderr(&out)
    );
    assert!(sandbox.calls().is_empty(), "{:?}", sandbox.calls());
}

#[test]
fn an_age_guard_keeps_what_the_count_would_have_taken() {
    let sandbox = Sandbox::new();
    let roots = sandbox.state().join("gcroots");
    // Both made just now: `--keep 0` alone would take both, and
    // `--older-than 14` says neither is old enough to go at all.
    for release in ["release-aaa", "release-bbb"] {
        let dir = roots.join(release);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join(".created"),
            format!("{}\n", chrono::Utc::now().to_rfc3339()),
        )
        .unwrap();
        std::os::unix::fs::symlink("/nix/store/does-not-matter", dir.join("box")).unwrap();
    }
    let out = sandbox.run(&["gc", "--keep", "0", "--older-than", "14", "--repo", "."]);
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    assert!(roots.join("release-aaa").exists(), "{}", stderr(&out));
    assert!(roots.join("release-bbb").exists(), "{}", stderr(&out));
    assert!(stderr(&out).contains("14 day(s)"), "{}", stderr(&out));
}

// --- end lane 4C ----------------------------------------------------------

// ---------------------------------------------------------------------------
// the whole way through
// ---------------------------------------------------------------------------

#[test]
fn a_fleet_that_moved_is_planned_and_the_plan_is_read_back() {
    let sandbox = Sandbox::new();
    // n1 runs something else: the shape of a host that has not had this
    // release yet.
    let moved = sandbox.healthy_answer("n1").replace(
        &sandbox.release.artifacts["n1"].toplevel.store_path,
        "/nix/store/previous-nixos-system-n1-25.11",
    );
    sandbox.answer("n1", &moved);

    let out = sandbox.run(&[
        "plan",
        "--release",
        "release.json",
        "--select",
        "all",
        "--inventory",
        "fleet.toml",
        "--repo",
        ".",
        "--out",
        "plan.json",
    ]);
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    let text = std::fs::read_to_string(sandbox.cwd.path().join("plan.json")).unwrap();
    let plan = meister_deploy::plan::DeploymentPlan::from_json(&text, "plan.json").unwrap();
    assert_eq!(plan.hosts["n1"].verdict.as_str(), "change");
    assert_eq!(plan.hosts["box"].verdict.as_str(), "unchanged");
    assert_eq!(plan.hosts["n2"].verdict.as_str(), "unchanged");
    // The snapshot in the plan is the one that was taken, and it is the one
    // on disk.
    let latest = std::fs::read_to_string(sandbox.state().join("observations/latest.json")).unwrap();
    let on_disk =
        meister_deploy::observation::Observations::from_json(&latest, "latest.json").unwrap();
    assert_eq!(plan.observation, on_disk);
    // A `status` of the same fleet says the same thing about n1, and says
    // it as a check rather than as a verdict.
    sandbox.forget_calls();
    let out = sandbox.run(&["status", "--release", "release.json", "--repo", "."]);
    assert!(
        stdout(&out).contains("REQUIRED system on n1"),
        "{}",
        stdout(&out)
    );
}
