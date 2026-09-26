// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Image CLI refusal and dry-run tests using a logging Nix shim.
//! Real media builds and boot behavior require the separate Nix VM tests.

mod support;

use std::path::PathBuf;
use std::process::{Command, Output};

use support::{onebox, release_of};

const BIN: &str = env!("CARGO_BIN_EXE_meister-deploy");

struct Sandbox {
    cwd: tempfile::TempDir,
    shims: tempfile::TempDir,
    log: PathBuf,
}

impl Sandbox {
    /// Temporary release directory with a logging Nix shim that refuses builds.
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
        let release = release_of(onebox());
        std::fs::write(cwd.path().join("release.json"), release.to_json().unwrap()).unwrap();
        Sandbox { cwd, shims, log }
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

    /// Logged shim invocations; empty means no subprocess was started.
    fn calls(&self) -> Vec<String> {
        std::fs::read_to_string(&self.log)
            .unwrap_or_default()
            .lines()
            .map(str::to_string)
            .collect()
    }
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
fn a_dry_run_prints_the_derivation_and_starts_nothing() {
    let sandbox = Sandbox::new();
    let out = sandbox.run(&[
        "image",
        "--release",
        "release.json",
        "--host",
        "box",
        "--kind",
        "installer",
        "--dry-run",
    ]);
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    let line = stdout(&out);
    assert!(
        line.contains("nix build --no-link --print-out-paths"),
        "{line}"
    );
    assert!(line.contains("nixos-installer-box.drv"), "{line}");
    assert!(
        sandbox.calls().is_empty(),
        "a dry run started {:?}",
        sandbox.calls()
    );
    assert!(
        stderr(&out).contains("nothing was built"),
        "{}",
        stderr(&out)
    );
}

#[test]
fn offline_refuses_because_a_medium_is_a_build() {
    let sandbox = Sandbox::new();
    let out = sandbox.run(&[
        "image",
        "--release",
        "release.json",
        "--host",
        "box",
        "--kind",
        "installer",
        "--offline",
    ]);
    assert_eq!(code(&out), 1);
    assert!(
        stderr(&out).contains("the medium IS the build"),
        "{}",
        stderr(&out)
    );
    assert!(sandbox.calls().is_empty());
}

#[test]
fn a_kind_that_is_not_one_lists_the_three_that_are() {
    let sandbox = Sandbox::new();
    let out = sandbox.run(&[
        "image",
        "--release",
        "release.json",
        "--host",
        "box",
        "--kind",
        "usb-stick",
    ]);
    assert_eq!(code(&out), 1);
    let why = stderr(&out);
    assert!(why.contains("installer"), "{why}");
    assert!(why.contains("direct-boot"), "{why}");
    assert!(sandbox.calls().is_empty());
}

#[test]
fn a_medium_a_host_does_not_have_says_which_one_it_does() {
    // Self-booting fixture hosts have no direct-boot bundle.
    let sandbox = Sandbox::new();
    let out = sandbox.run(&[
        "image",
        "--release",
        "release.json",
        "--host",
        "n1",
        "--kind",
        "direct-boot",
        "--dry-run",
    ]);
    assert_eq!(code(&out), 1);
    let why = stderr(&out);
    assert!(why.contains("it boots uefi"), "{why}");
    assert!(why.contains("--kind installer"), "{why}");
    assert!(sandbox.calls().is_empty());
}

#[test]
fn a_host_the_release_never_heard_of_is_a_sentence() {
    let sandbox = Sandbox::new();
    let out = sandbox.run(&[
        "image",
        "--release",
        "release.json",
        "--host",
        "somebody-elses-box",
        "--kind",
        "installer",
        "--dry-run",
    ]);
    assert_eq!(code(&out), 1);
    assert!(
        stderr(&out).contains("knows nothing about somebody-elses-box"),
        "{}",
        stderr(&out)
    );
}
