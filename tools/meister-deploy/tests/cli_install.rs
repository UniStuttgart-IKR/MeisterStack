// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! CLI tests for preparing installation media.
//! Check plan kind, release/host binding, blocked verdicts and approval.
//! A logging Nix shim prevents real builds; target formatting belongs to meister-install.

mod support;

use std::path::PathBuf;
use std::process::{Command, Output};

use meister_deploy::plan::{self, PlanKind, PlanPolicy};
use support::{at, observed, onebox, release_of};

const BIN: &str = env!("CARGO_BIN_EXE_meister-deploy");

struct Sandbox {
    cwd: tempfile::TempDir,
    shims: tempfile::TempDir,
    log: PathBuf,
    plan_id: String,
}

impl Sandbox {
    fn new() -> Sandbox {
        use std::os::unix::fs::PermissionsExt;
        let shims = tempfile::tempdir().unwrap();
        let log = shims.path().join("calls.log");
        for name in ["nix", "nix-store"] {
            let path = shims.path().join(name);
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
        let release = release_of(enrolled());
        // Unreachable observations represent hosts awaiting first installation.
        let mut observation = observed(&release, at("2026-09-21T11:59:00Z"));
        for host in observation.hosts.values_mut() {
            host.reachable = false;
            host.current_system = None;
            host.booted_system = None;
            host.next_boot_system = None;
        }
        let the_plan = plan::plan(
            &release,
            "all",
            &observation,
            None,
            &PlanPolicy::new(PlanKind::Install),
            at("2026-09-21T12:00:00Z"),
        )
        .expect("an install plans");

        std::fs::write(cwd.path().join("release.json"), release.to_json().unwrap()).unwrap();
        std::fs::write(cwd.path().join("install.json"), the_plan.to_json().unwrap()).unwrap();

        // Build an upgrade plan to test the wrong-kind refusal.
        let running = observed(&release, at("2026-09-21T11:59:00Z"));
        let upgrade = plan::plan(
            &release,
            "all",
            &running,
            None,
            &PlanPolicy::new(PlanKind::Upgrade),
            at("2026-09-21T12:00:00Z"),
        )
        .expect("an upgrade plans");
        std::fs::write(cwd.path().join("upgrade.json"), upgrade.to_json().unwrap()).unwrap();

        Sandbox {
            cwd,
            shims,
            log,
            plan_id: the_plan.plan_id.clone(),
        }
    }

    fn run(&self, args: &[&str]) -> Output {
        Command::new(BIN)
            .args(args)
            .current_dir(self.cwd.path())
            .env("PATH", self.shims.path())
            .env("MEISTER_SHIM_LOG", &self.log)
            .env("HOME", self.cwd.path())
            .output()
            .expect("the binary was just built")
    }

    fn calls(&self) -> Vec<String> {
        std::fs::read_to_string(&self.log)
            .unwrap_or_default()
            .lines()
            .map(str::to_string)
            .collect()
    }

    /// Whatever the verb left behind in the state directory.
    fn state_files(&self) -> Vec<String> {
        let dir = self.cwd.path().join(".meister-deploy");
        let mut out = Vec::new();
        let mut stack = vec![dir];
        while let Some(next) = stack.pop() {
            let Ok(entries) = std::fs::read_dir(&next) else {
                continue;
            };
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    stack.push(path);
                } else {
                    out.push(path.display().to_string());
                }
            }
        }
        out.sort();
        out
    }
}

/// Enroll every fixture host so these tests isolate installation behavior from enrollment checks.
fn enrolled() -> meister_deploy::manifest::ResolvedFleet {
    let mut fleet = onebox();
    for (id, host) in fleet.hosts.iter_mut() {
        if host.ssh.host_key_fingerprint.is_none() {
            host.ssh.host_key_fingerprint = Some(format!("SHA256:enrolled-{id}"));
        }
    }
    fleet.manifest_id =
        meister_deploy::ids::content_id(meister_deploy::ids::IdKind::Manifest, &fleet)
            .expect("a manifest hashes");
    fleet
}

fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).to_string()
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).to_string()
}

fn code(out: &Output) -> i32 {
    out.status.code().unwrap_or(-1)
}

#[test]
fn a_dry_run_prints_the_derivation_and_writes_nothing() {
    let sandbox = Sandbox::new();
    let approve = format!("destructive={}", sandbox.plan_id);
    let out = sandbox.run(&[
        "install",
        "--plan",
        "install.json",
        "--release",
        "release.json",
        "--host",
        "box",
        "--approve",
        &approve,
        "--dry-run",
    ]);
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    assert!(
        stdout(&out).contains("nixos-installer-box.drv"),
        "{}",
        stdout(&out)
    );
    assert!(sandbox.calls().is_empty(), "{:?}", sandbox.calls());
    assert!(
        sandbox.state_files().is_empty(),
        "{:?}",
        sandbox.state_files()
    );
}

#[test]
fn without_the_approval_nothing_is_built() {
    let sandbox = Sandbox::new();
    let out = sandbox.run(&[
        "install",
        "--plan",
        "install.json",
        "--release",
        "release.json",
        "--host",
        "box",
    ]);
    assert_eq!(code(&out), 1);
    let why = stderr(&out);
    assert!(why.contains("nobody granted destructive"), "{why}");
    assert!(why.contains(&sandbox.plan_id), "{why}");
    assert!(sandbox.calls().is_empty());
    assert!(sandbox.state_files().is_empty());
}

#[test]
fn an_approval_for_another_plan_is_not_an_approval() {
    let sandbox = Sandbox::new();
    let out = sandbox.run(&[
        "install",
        "--plan",
        "install.json",
        "--release",
        "release.json",
        "--host",
        "box",
        "--approve",
        "destructive=some-other-plan",
    ]);
    assert_eq!(code(&out), 1);
    assert!(
        stderr(&out).contains("nobody granted destructive"),
        "{}",
        stderr(&out)
    );
    assert!(sandbox.calls().is_empty());
}

#[test]
fn an_upgrade_plan_is_not_an_install() {
    let sandbox = Sandbox::new();
    let out = sandbox.run(&[
        "install",
        "--plan",
        "upgrade.json",
        "--release",
        "release.json",
        "--host",
        "box",
        "--dry-run",
    ]);
    assert_eq!(code(&out), 1);
    let why = stderr(&out);
    assert!(why.contains("is a `upgrade` plan"), "{why}");
    assert!(why.contains("--kind install"), "{why}");
    assert!(sandbox.calls().is_empty());
}

#[test]
fn a_host_the_plan_does_not_cover_is_a_sentence() {
    let sandbox = Sandbox::new();
    let out = sandbox.run(&[
        "install",
        "--plan",
        "install.json",
        "--release",
        "release.json",
        "--host",
        "somebody-else",
        "--dry-run",
    ]);
    assert_eq!(code(&out), 1);
    assert!(
        stderr(&out).contains("does not cover somebody-else"),
        "{}",
        stderr(&out)
    );
}

#[test]
fn a_blocked_installation_is_exit_two_and_no_medium() {
    // A reachable installed host must block first-install media preparation.
    let sandbox = Sandbox::new();
    let release = release_of(enrolled());
    let running = observed(&release, at("2026-09-21T11:59:00Z"));
    let blocked = plan::plan(
        &release,
        "all",
        &running,
        None,
        &PlanPolicy::new(PlanKind::Install),
        at("2026-09-21T12:00:00Z"),
    )
    .expect("it plans, and it blocks");
    std::fs::write(
        sandbox.cwd.path().join("blocked.json"),
        blocked.to_json().unwrap(),
    )
    .unwrap();
    let approve = format!("destructive={}", blocked.plan_id);

    let out = sandbox.run(&[
        "install",
        "--plan",
        "blocked.json",
        "--release",
        "release.json",
        "--host",
        "box",
        "--approve",
        &approve,
    ]);
    assert_eq!(code(&out), 2, "{}", stderr(&out));
    assert!(stderr(&out).contains("already runs"), "{}", stderr(&out));
    assert!(
        stderr(&out).contains("no medium was built"),
        "{}",
        stderr(&out)
    );
    assert!(sandbox.calls().is_empty());
    assert!(sandbox.state_files().is_empty());
}

#[test]
fn offline_refuses_because_a_medium_is_a_build() {
    let sandbox = Sandbox::new();
    let out = sandbox.run(&[
        "install",
        "--plan",
        "install.json",
        "--release",
        "release.json",
        "--host",
        "box",
        "--offline",
    ]);
    assert_eq!(code(&out), 1);
    assert!(
        stderr(&out).contains("the medium IS the build"),
        "{}",
        stderr(&out)
    );
}
