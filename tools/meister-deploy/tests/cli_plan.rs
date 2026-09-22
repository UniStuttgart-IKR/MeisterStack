// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! What `meister-deploy plan` does to the machine it runs on — measured.
//!
//! The same instrument as `cli_effects.rs`: `PATH` holds four shims called
//! `nix`, `ssh`, `git` and `rsync`, each of which records its argv and exits
//! 97, and the working and output directories are compared byte for byte
//! before and after. The planner is supposed to be pure, so the interesting
//! assertions here are all negative: no program was started, no file
//! appeared, and the two refusals the contract names came out as sentences
//! with the right exit code.
//!
//! The release and the snapshot this test plans from are built here through
//! the public API rather than checked in, so a change to a contract breaks
//! this at the contract and not at a stale fixture.

mod support;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use meister_deploy::observation::{
    OBSERVATION_SCHEMA, Observations, Target, TargetObserved, Targets,
};

use support::{at, observed, onebox, release_of, with_new_systems};

const BIN: &str = env!("CARGO_BIN_EXE_meister-deploy");
const SHIMS: [&str; 5] = ["nix", "ssh", "git", "rsync", "ssh-keygen"];

struct Sandbox {
    cwd: tempfile::TempDir,
    out: tempfile::TempDir,
    shims: tempfile::TempDir,
    log: PathBuf,
}

impl Sandbox {
    /// A directory with a release, a snapshot of the fleet running the
    /// PREVIOUS release, and an inventory carrying `[operator] cli_config`.
    fn new() -> Sandbox {
        use std::os::unix::fs::PermissionsExt;
        let shims = tempfile::tempdir().unwrap();
        let log = shims.path().join("calls.log");
        for name in SHIMS {
            let path = shims.path().join(name);
            // The whole line in ONE append: several hosts are asked at
            // once, and three writes per call would interleave into
            // nonsense exactly when the parallelism is what is being
            // tested.
            std::fs::write(
                &path,
                format!(
                    "#!/bin/sh\nline=\"{name}\"\n\
                     for a in \"$@\"; do line=\"$line [$a]\"; done\n\
                     printf '%s\\n' \"$line\" >> \"$MEISTER_SHIM_LOG\"\nexit 97\n"
                ),
            )
            .unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        }

        let cwd = tempfile::tempdir().unwrap();
        let base = onebox();
        let running = release_of(base.clone());
        let snapshot = observed(&running, at("2026-09-21T11:59:00Z"));
        let release = with_new_systems(base, &["n1".to_string()], false);
        std::fs::write(cwd.path().join("release.json"), release.to_json().unwrap()).unwrap();
        std::fs::write(cwd.path().join("snap.json"), snapshot.to_json().unwrap()).unwrap();

        // The same fleet, except that somebody else answered for n1. What a
        // reinstalled or impersonated machine looks like from here.
        let mut moved = snapshot.clone();
        moved
            .hosts
            .get_mut("n1")
            .unwrap()
            .identity
            .host_key_fingerprint = Some("SHA256:somebody-else".to_string());
        std::fs::write(cwd.path().join("snap-moved.json"), moved.to_json().unwrap()).unwrap();
        std::fs::write(
            cwd.path().join("fleet.toml"),
            include_str!("fixtures/fleet-v2.toml"),
        )
        .unwrap();

        // So the files a test plans from can be read by hand, and the same
        // run repeated at a terminal: `MEISTER_TEST_KEEP=<dir>` copies them
        // out. Nothing in any test depends on it.
        if let Ok(keep) = std::env::var("MEISTER_TEST_KEEP") {
            let keep = Path::new(&keep);
            std::fs::create_dir_all(keep).unwrap();
            for name in ["release.json", "snap.json", "snap-moved.json", "fleet.toml"] {
                std::fs::copy(cwd.path().join(name), keep.join(name)).unwrap();
            }
        }

        Sandbox {
            cwd,
            out: tempfile::tempdir().unwrap(),
            shims,
            log,
        }
    }

    fn run(&self, args: &[&str]) -> Output {
        Command::new(BIN)
            .args(args)
            .current_dir(self.cwd.path())
            .env("PATH", self.shims.path())
            .env("MEISTER_SHIM_LOG", &self.log)
            .env("HOME", self.out.path())
            .output()
            .expect("the binary was just built")
    }

    fn calls(&self) -> Vec<String> {
        match std::fs::read_to_string(&self.log) {
            Ok(text) => text.lines().map(str::to_string).collect(),
            Err(_) => Vec::new(),
        }
    }
}

fn snapshot_of(dir: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    let mut out = BTreeMap::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(next) = stack.pop() {
        for entry in std::fs::read_dir(&next).expect("a directory of our own") {
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
    out.status.code().expect("the process exited")
}

#[test]
fn a_plan_from_a_snapshot_starts_no_program_and_goes_to_stdout() {
    let sandbox = Sandbox::new();
    let before = snapshot_of(sandbox.cwd.path());
    let out = sandbox.run(&[
        "plan",
        "--release",
        "release.json",
        "--select",
        "host=n1",
        "--observation",
        "snap.json",
        "--inventory",
        "fleet.toml",
    ]);
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    assert!(sandbox.calls().is_empty(), "{:?}", sandbox.calls());
    assert_eq!(
        snapshot_of(sandbox.cwd.path()),
        before,
        "a plan without --out writes nothing"
    );

    // The whole plan on stdout, parseable, and the prose on stderr.
    let plan: serde_json::Value = serde_json::from_str(&stdout(&out)).expect("stdout is the plan");
    assert_eq!(plan["schema"], "meister-deploy/plan/1");
    assert_eq!(plan["kind"], "upgrade");
    assert_eq!(plan["selection"]["targets"], serde_json::json!(["n1"]));
    assert!(stderr(&out).contains("==> plan-"), "{}", stderr(&out));
    assert!(stderr(&out).contains("wave"), "{}", stderr(&out));
}

#[test]
fn a_plan_with_out_writes_one_file_and_prints_its_id() {
    let sandbox = Sandbox::new();
    let out = sandbox.run(&[
        "plan",
        "--release",
        "release.json",
        "--select",
        "host=n1",
        "--observation",
        "snap.json",
        "--inventory",
        "fleet.toml",
        "--out",
        "plan.json",
    ]);
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    assert!(sandbox.calls().is_empty());
    let id = stdout(&out).trim().to_string();
    assert!(id.starts_with("plan-"), "{id}");

    let written = std::fs::read_to_string(sandbox.cwd.path().join("plan.json")).unwrap();
    let plan: serde_json::Value = serde_json::from_str(&written).unwrap();
    assert_eq!(plan["plan_id"], id);
    assert!(stderr(&out).contains("==> plan.json"), "{}", stderr(&out));
}

#[test]
fn offline_and_out_together_is_a_refusal_with_a_sentence() {
    let sandbox = Sandbox::new();
    let before = snapshot_of(sandbox.cwd.path());
    let out = sandbox.run(&[
        "plan",
        "--release",
        "release.json",
        "--select",
        "all",
        "--offline",
        "--out",
        "plan.json",
    ]);
    assert_eq!(code(&out), 1);
    assert!(stdout(&out).is_empty());
    assert!(
        stderr(&out).contains("--offline and --out are not both possible"),
        "{}",
        stderr(&out)
    );
    assert_eq!(snapshot_of(sandbox.cwd.path()), before);
    assert!(sandbox.calls().is_empty());
}

#[test]
fn without_a_snapshot_it_asks_the_hosts_and_nobody_who_is_not_enrolled() {
    // The snapshot used to arrive with lane 2A; it is here now. What this
    // pins is the ORDER: the fleet's own `known_hosts` is consulted first,
    // and a host with no key in it is never connected to. The shims answer
    // 97 to everything, so every lookup fails, so no `ssh` may appear in
    // the log at all.
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
        "--dry-run",
    ]);
    // Blocked, not failed: a plan over a fleet nobody could look at is a
    // plan that refuses to interrupt anything.
    assert_eq!(code(&out), 2, "{}", stderr(&out));
    let calls = sandbox.calls();
    assert!(
        calls.iter().all(|c| c.starts_with("ssh-keygen")),
        "only the local lookup ran: {calls:?}"
    );
    assert_eq!(calls.len(), 3, "one lookup per host: {calls:?}");
    assert!(
        calls.iter().any(|c| c.contains("[-F] [10.0.0.10]")),
        "{calls:?}"
    );
    // A dry run keeps nothing: no plan file, no snapshot.
    assert_eq!(snapshot_of(sandbox.cwd.path()), before);
    let plan: serde_json::Value = serde_json::from_str(&stdout(&out)).expect("a plan on stdout");
    assert_eq!(plan["observation"]["provisional"], serde_json::json!(false));
    for host in ["box", "n1", "n2"] {
        assert_eq!(
            plan["observation"]["hosts"][host]["reachable"],
            serde_json::json!(false),
            "{host}"
        );
        assert_eq!(
            plan["hosts"][host]["verdict"],
            serde_json::json!("unreachable")
        );
    }
}

#[test]
fn an_offline_plan_is_provisional_blocks_the_interruptions_and_writes_nothing() {
    let sandbox = Sandbox::new();
    let before = snapshot_of(sandbox.cwd.path());
    let out = sandbox.run(&[
        "plan",
        "--release",
        "release.json",
        "--select",
        "all",
        "--offline",
        "--inventory",
        "fleet.toml",
    ]);
    // Exit 2: it worked, and something in it may not run.
    assert_eq!(code(&out), 2, "{}", stderr(&out));
    assert_eq!(snapshot_of(sandbox.cwd.path()), before);
    assert!(sandbox.calls().is_empty());

    let plan: serde_json::Value = serde_json::from_str(&stdout(&out)).expect("stdout is the plan");
    assert_eq!(plan["observation"]["provisional"], true);
    assert_eq!(plan["observation"]["hosts"], serde_json::json!({}));
    let actions = plan["actions"].as_array().expect("actions");
    assert!(!actions.is_empty());
    for action in actions {
        if action["disruption"] != "none" {
            assert!(
                action["blocked"]
                    .as_str()
                    .unwrap_or_default()
                    .contains("needs an online observation"),
                "{action}"
            );
        }
    }
    let why = stderr(&out);
    assert!(why.contains("provisional observation"), "{why}");
    // The table has a header, and one sentence stops eighteen steps once
    // rather than eighteen times.
    assert!(why.contains("HOST           VERDICT"), "{why}");
    assert_eq!(
        why.matches("needs an online observation").count(),
        1,
        "the same reason was printed more than once:\n{why}"
    );
    assert!(why.contains("box: cordon, drain, activate"), "{why}");
}

#[test]
fn a_blocked_plan_is_exit_two_and_still_a_plan() {
    // A host key that is not the enrolled one. The plan is still the answer
    // — it says what it refused and why — and the shell learns "blocked"
    // rather than "this tool broke".
    let sandbox = Sandbox::new();
    let out = sandbox.run(&[
        "plan",
        "--release",
        "release.json",
        "--select",
        "host=n1",
        "--observation",
        "snap-moved.json",
        "--inventory",
        "fleet.toml",
    ]);
    assert_eq!(code(&out), 2, "{}", stderr(&out));
    let plan: serde_json::Value = serde_json::from_str(&stdout(&out)).unwrap();
    assert_eq!(plan["hosts"]["n1"]["verdict"], "blocked");
    let why = stderr(&out);
    assert!(why.contains("identity changed"), "{why}");
    assert!(why.contains("SHA256:somebody-else"), "{why}");
    // Every step but the two that only look is refused.
    for action in plan["actions"].as_array().unwrap() {
        match action["kind"].as_str().unwrap() {
            "preflight" | "verify" => assert!(action["blocked"].is_null(), "{action}"),
            _ => assert!(!action["blocked"].is_null(), "{action}"),
        }
    }
}

#[test]
fn a_plan_kind_that_does_not_exist_yet_says_which_milestone_it_arrives_in() {
    let sandbox = Sandbox::new();
    for (kind, needle) in [
        ("install", "arrives with M3"),
        ("keys-rotate", "with M5"),
        ("nonsense", "is not a plan kind"),
    ] {
        let out = sandbox.run(&[
            "plan",
            "--release",
            "release.json",
            "--select",
            "all",
            "--offline",
            "--kind",
            kind,
        ]);
        assert_eq!(code(&out), 1, "{kind}");
        assert!(stderr(&out).contains(needle), "{kind}: {}", stderr(&out));
        assert!(stdout(&out).is_empty(), "{kind}");
    }
}

#[test]
fn an_unknown_selector_lists_what_exists_and_writes_nothing() {
    let sandbox = Sandbox::new();
    let out = sandbox.run(&[
        "plan",
        "--release",
        "release.json",
        "--select",
        "rack=1",
        "--observation",
        "snap.json",
    ]);
    assert_eq!(code(&out), 1);
    assert!(
        stderr(&out).contains("host, group, role, profile, site"),
        "{}",
        stderr(&out)
    );
}

#[test]
fn a_missing_cli_reference_is_a_note_and_the_plan_says_which_steps_it_blocks() {
    // D7: no `[operator] cli_config` anywhere, which is the ordinary case
    // for a plan made away from the operator's repository.
    //
    // The inventory is NAMED here rather than left to the manifest's own
    // `source.repo_path`. That path is a real directory on the machine this
    // fixture was written on (`~/git/meisterstack-lab`), so a test that
    // relied on it being absent passed only until somebody created the lab
    // repository — measured: it went red the day lane L1's directory
    // appeared, in a worktree that had not touched this code. A test about
    // a missing reference has to name the file it means.
    let sandbox = Sandbox::new();
    let missing = sandbox.cwd.path().join("no-such-inventory.toml");
    let out = sandbox.run(&[
        "plan",
        "--release",
        "release.json",
        "--select",
        "host=n1",
        "--observation",
        "snap.json",
        "--inventory",
        missing.to_str().unwrap(),
    ]);
    assert_eq!(code(&out), 2, "{}", stderr(&out));
    let why = stderr(&out);
    assert!(why.contains("could not be read"), "{why}");
    assert!(why.contains("--inventory <file>"), "{why}");
    let plan: serde_json::Value = serde_json::from_str(&stdout(&out)).unwrap();
    let drain = plan["actions"]
        .as_array()
        .unwrap()
        .iter()
        .find(|a| a["kind"] == "drain")
        .expect("an agent is drained");
    assert!(
        drain["blocked"]
            .as_str()
            .unwrap_or_default()
            .contains("cli_config"),
        "{drain}"
    );
}

#[test]
fn a_target_file_moves_the_address_and_nothing_else() {
    let sandbox = Sandbox::new();
    let targets = Targets {
        schema: meister_deploy::observation::TARGETS_SCHEMA.to_string(),
        run_ref: "lab-run-7".to_string(),
        targets: [(
            "n1".to_string(),
            Target {
                address: "192.168.122.32".to_string(),
                port: 2222,
                ssh_user: "root".to_string(),
                host_key_fingerprint: None,
                provider_ref: "one:vm:4711".to_string(),
                observed: TargetObserved {
                    reachable_at: at("2026-09-21T11:58:00Z"),
                    capabilities: vec!["kvm".to_string()],
                },
            },
        )]
        .into_iter()
        .collect(),
    };
    std::fs::write(
        sandbox.cwd.path().join("targets.json"),
        targets.to_json().unwrap(),
    )
    .unwrap();

    let out = sandbox.run(&[
        "plan",
        "--release",
        "release.json",
        "--select",
        "host=n1",
        "--observation",
        "snap.json",
        "--inventory",
        "fleet.toml",
        "--targets",
        "targets.json",
    ]);
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    let plan: serde_json::Value = serde_json::from_str(&stdout(&out)).unwrap();
    assert_eq!(plan["endpoints"]["n1"]["address"], "192.168.122.32");
    assert_eq!(plan["endpoints"]["n1"]["port"], 2222);
    assert_eq!(plan["endpoints"]["n1"]["provider_ref"], "one:vm:4711");
    // The fleet inside the release still says what it said.
    assert_eq!(
        plan["observation"]["hosts"]["n1"]["identity"]["hostname"],
        "meister-n1"
    );
    assert!(sandbox.calls().is_empty());
}

#[test]
fn a_target_file_that_does_not_line_up_stops_the_run_with_a_sentence() {
    let sandbox = Sandbox::new();
    let targets = Targets {
        schema: meister_deploy::observation::TARGETS_SCHEMA.to_string(),
        run_ref: "lab-run-8".to_string(),
        targets: BTreeMap::new(),
    };
    std::fs::write(
        sandbox.cwd.path().join("targets.json"),
        targets.to_json().unwrap(),
    )
    .unwrap();
    let out = sandbox.run(&[
        "plan",
        "--release",
        "release.json",
        "--select",
        "host=n1",
        "--observation",
        "snap.json",
        "--targets",
        "targets.json",
    ]);
    assert_eq!(code(&out), 1);
    assert!(
        stderr(&out).contains("the run covers n1"),
        "{}",
        stderr(&out)
    );
    assert!(stdout(&out).is_empty());
}

#[test]
fn a_snapshot_of_another_schema_is_refused_by_name() {
    let sandbox = Sandbox::new();
    std::fs::write(
        sandbox.cwd.path().join("wrong.json"),
        br#"{"schema":"meister-deploy/plan/1"}"#,
    )
    .unwrap();
    let out = sandbox.run(&[
        "plan",
        "--release",
        "release.json",
        "--select",
        "all",
        "--observation",
        "wrong.json",
    ]);
    assert_eq!(code(&out), 1);
    let why = stderr(&out);
    assert!(why.contains(OBSERVATION_SCHEMA), "{why}");
    assert!(why.contains("meister-deploy/plan/1"), "{why}");
}

#[test]
fn a_plan_can_be_read_back_by_the_tool_that_wrote_it() {
    // The form lane 2C needs: a plan on disk, validated as a contract.
    let sandbox = Sandbox::new();
    let out = sandbox.run(&[
        "plan",
        "--release",
        "release.json",
        "--select",
        "host=n1",
        "--observation",
        "snap.json",
        "--inventory",
        "fleet.toml",
        "--out",
        "plan.json",
    ]);
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    let text = std::fs::read_to_string(sandbox.cwd.path().join("plan.json")).unwrap();
    let plan = meister_deploy::plan::DeploymentPlan::from_json(&text, "the written plan")
        .expect("what it wrote, it reads");
    assert_eq!(plan.selection.targets, ["n1"]);
    assert!(plan.id_matches().unwrap());

    // And the schema of every contract this lane added is printable.
    for kind in [
        "release",
        "observation",
        "targets",
        "plan",
        "receipt",
        "journal-event",
    ] {
        let out = sandbox.run(&["schema", kind]);
        assert_eq!(code(&out), 0, "{kind}: {}", stderr(&out));
        let schema: serde_json::Value = serde_json::from_str(&stdout(&out)).expect("json schema");
        assert!(schema["title"].is_string(), "{kind}");
    }
}

#[test]
fn the_snapshot_this_test_planned_from_is_the_contract_and_not_a_hand_written_file() {
    // A guard for the sandbox itself: if the snapshot stopped being a
    // `meister-deploy/observation/1`, every negative assertion above would
    // pass for the wrong reason.
    let sandbox = Sandbox::new();
    let text = std::fs::read_to_string(sandbox.cwd.path().join("snap.json")).unwrap();
    let snapshot = Observations::from_json(&text, "the sandbox snapshot").unwrap();
    assert!(!snapshot.provisional);
    assert_eq!(snapshot.hosts.len(), 3);
}
