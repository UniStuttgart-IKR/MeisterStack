// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! CLI effect checks using isolated PATH shims and temporary directories.
//!
//! Shims log external commands and fail them; directory digests detect writes.
//! These tests cover exercised command paths, not every possible syscall.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const BIN: &str = env!("CARGO_BIN_EXE_meister-deploy");

/// External programs replaced by logging shims.
const SHIMS: [&str; 4] = ["nix", "ssh", "git", "rsync"];

struct Sandbox {
    /// The working directory the binary is started in.
    cwd: tempfile::TempDir,
    /// Where `--out` would land.
    out: tempfile::TempDir,
    shims: tempfile::TempDir,
    log: PathBuf,
}

impl Sandbox {
    fn new() -> Sandbox {
        use std::os::unix::fs::PermissionsExt;
        let shims = tempfile::tempdir().unwrap();
        let log = shims.path().join("calls.log");
        for name in SHIMS {
            let path = shims.path().join(name);
            // Use an absolute shell and builtins only. Append each logged command
            // in one operation to avoid interleaving concurrent calls.
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
        std::fs::write(
            cwd.path().join("fleet.toml"),
            include_str!("fixtures/fleet-v2.toml"),
        )
        .unwrap();
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
            // Use an empty temporary HOME to exclude operator configuration.
            .env("HOME", self.out.path())
            .output()
            .expect("the binary was just built")
    }

    /// Every program the binary started, with its arguments, in order.
    fn calls(&self) -> Vec<String> {
        match std::fs::read_to_string(&self.log) {
            Ok(text) => text.lines().map(str::to_string).collect(),
            Err(_) => Vec::new(),
        }
    }

    fn out_path(&self, name: &str) -> PathBuf {
        self.out.path().join(name)
    }
}

/// Path and content of every file under a directory, so that "unchanged"
/// means unchanged and not "the same number of files".
fn snapshot(dir: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    let mut out = BTreeMap::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(next) = stack.pop() {
        for entry in std::fs::read_dir(&next).expect("a directory of our own") {
            let path = entry.unwrap().path();
            if path.is_dir() {
                stack.push(path);
            } else {
                let bytes = std::fs::read(&path).unwrap_or_default();
                out.insert(path, bytes);
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

#[test]
fn the_offline_verbs_start_no_program_at_all() {
    let sandbox = Sandbox::new();
    for args in [
        vec!["inventory"],
        vec!["inventory", "--json"],
        vec!["validate"],
        vec!["schema", "nix-manifest"],
        vec!["schema", "resolved-fleet"],
        vec!["schema", "check-result"],
    ] {
        let out = sandbox.run(&args);
        assert!(out.status.success(), "{args:?} failed: {}", stderr(&out));
        assert!(
            sandbox.calls().is_empty(),
            "{args:?} ran {:?}",
            sandbox.calls()
        );
    }
}

#[test]
fn a_dry_run_prints_the_command_lines_and_runs_none_of_them() {
    let sandbox = Sandbox::new();
    let before_cwd = snapshot(sandbox.cwd.path());
    let before_out = snapshot(sandbox.out.path());

    let target = sandbox.out_path("manifest.json");
    let out = sandbox.run(&[
        "resolve",
        "--repo",
        ".",
        "--out",
        target.to_str().unwrap(),
        "--dry-run",
    ]);

    assert!(out.status.success(), "{}", stderr(&out));
    let printed = stdout(&out);
    assert!(printed.contains("git rev-parse HEAD"), "{printed}");
    assert!(
        printed.contains("nix eval --json --no-write-lock-file"),
        "{printed}"
    );
    assert!(printed.contains("#meisterDeployment"), "{printed}");

    assert!(
        sandbox.calls().is_empty(),
        "a dry run executed {:?}",
        sandbox.calls()
    );
    assert!(!target.exists(), "a dry run wrote its output file");
    assert_eq!(before_cwd, snapshot(sandbox.cwd.path()));
    assert_eq!(before_out, snapshot(sandbox.out.path()));
}

#[test]
fn a_dev_dry_run_creates_no_snapshot_directory() {
    let sandbox = Sandbox::new();
    let before = snapshot(sandbox.cwd.path());
    let target = sandbox.out_path("manifest.json");

    let out = sandbox.run(&[
        "resolve",
        "--repo",
        ".",
        "--out",
        target.to_str().unwrap(),
        "--dev",
        "--dry-run",
    ]);

    assert!(out.status.success(), "{}", stderr(&out));
    let printed = stdout(&out);
    // It says where the snapshot WOULD go, and the name it cannot know yet
    // is spelled out as what it is.
    assert!(
        printed.contains(".meister-deploy/snapshots/<content-hash>"),
        "{printed}"
    );
    assert!(printed.contains("path:"), "{printed}");
    assert!(!printed.contains("git+file://"), "{printed}");

    assert!(sandbox.calls().is_empty(), "{:?}", sandbox.calls());
    assert!(
        !sandbox.cwd.path().join(".meister-deploy").exists(),
        "a dry run created the state directory"
    );
    assert_eq!(before, snapshot(sandbox.cwd.path()));
}

#[test]
fn an_offline_resolve_refuses_and_touches_nothing() {
    let sandbox = Sandbox::new();
    let before_cwd = snapshot(sandbox.cwd.path());
    let target = sandbox.out_path("manifest.json");

    let out = sandbox.run(&[
        "resolve",
        "--repo",
        ".",
        "--out",
        target.to_str().unwrap(),
        "--offline",
    ]);

    assert_eq!(out.status.code(), Some(1));
    let said = stderr(&out);
    assert!(said.contains("--offline"), "{said}");
    assert!(said.contains("nix"), "{said}");
    assert!(
        stdout(&out).is_empty(),
        "nothing on stdout: {:?}",
        stdout(&out)
    );
    assert!(sandbox.calls().is_empty(), "{:?}", sandbox.calls());
    assert!(!target.exists());
    assert_eq!(before_cwd, snapshot(sandbox.cwd.path()));
}

#[test]
fn a_real_resolve_asks_git_first_and_stops_when_git_says_no() {
    let sandbox = Sandbox::new();
    let target = sandbox.out_path("manifest.json");

    let out = sandbox.run(&["resolve", "--repo", ".", "--out", target.to_str().unwrap()]);

    assert_eq!(out.status.code(), Some(1));
    // Reject dirty trees before invoking Nix evaluation.
    let calls = sandbox.calls();
    assert_eq!(calls.len(), 1, "{calls:?}");
    assert_eq!(calls[0], "git [rev-parse] [HEAD]");
    let said = stderr(&out);
    assert!(said.contains("exited 97"), "{said}");
    assert!(said.contains("git rev-parse HEAD"), "{said}");
    assert!(!target.exists(), "nothing was written on the way out");
}

#[test]
fn json_goes_to_stdout_whole_and_the_prose_goes_to_stderr() {
    let sandbox = Sandbox::new();

    let out = sandbox.run(&["inventory", "--json"]);
    assert!(out.status.success(), "{}", stderr(&out));
    let parsed: serde_json::Value = serde_json::from_str(&stdout(&out))
        .unwrap_or_else(|e| panic!("stdout was not json ({e}): {}", stdout(&out)));
    assert_eq!(parsed["fleet"]["name"], "uni-lab");
    assert!(
        stderr(&out).is_empty(),
        "a --json run said something on stderr: {}",
        stderr(&out)
    );

    for kind in ["nix-manifest", "resolved-fleet", "check-result"] {
        let out = sandbox.run(&["schema", kind]);
        assert!(out.status.success(), "{kind}: {}", stderr(&out));
        let schema: serde_json::Value = serde_json::from_str(&stdout(&out))
            .unwrap_or_else(|e| panic!("{kind} was not json: {e}"));
        assert!(schema.get("$schema").is_some(), "{kind}: {schema}");
    }

    // `validate` answers on stdout and says what it did NOT check on stderr,
    // so that a script reads the verdict and a person reads the caveat.
    let out = sandbox.run(&["validate"]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(stdout(&out).starts_with("ok: "), "{}", stdout(&out));
    assert!(stderr(&out).contains("note:"), "{}", stderr(&out));
}

#[test]
fn a_refusal_is_exit_one_and_a_sentence_on_stderr() {
    let sandbox = Sandbox::new();
    std::fs::write(sandbox.cwd.path().join("broken.toml"), "schema = 2\n").unwrap();

    let out = sandbox.run(&["validate", "-f", "broken.toml"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(stdout(&out).is_empty());
    assert!(stderr(&out).contains("broken.toml"), "{}", stderr(&out));

    // Nix validation evaluates inventory once and reports evaluation failure.
    let out = sandbox.run(&["validate", "--nix"]);
    assert_eq!(out.status.code(), Some(1));
    let calls = sandbox.calls();
    assert_eq!(calls.len(), 1, "{calls:?}");
    assert!(calls[0].starts_with("nix "), "{calls:?}");
    assert!(
        calls[0].contains("[eval] [--json] [--no-write-lock-file]"),
        "{calls:?}"
    );
    assert!(
        calls[0].contains("meisterDeployment.inventory"),
        "{calls:?}"
    );
    assert!(stderr(&out).contains("exited 97"), "{}", stderr(&out));
}

#[test]
fn the_manifest_contract_can_be_checked_from_a_pipe() {
    // Validate piped evaluation output without creating repository files.
    let sandbox = Sandbox::new();
    let manifest = sandbox.out_path("m.json");
    std::fs::write(&manifest, include_str!("fixtures/nix-manifest-onebox.json")).unwrap();

    let out = sandbox.run(&["validate", "--manifest", manifest.to_str().unwrap()]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(
        stdout(&out).contains("meister-deploy/nix-manifest/1"),
        "{}",
        stdout(&out)
    );
    assert!(sandbox.calls().is_empty(), "{:?}", sandbox.calls());
}
