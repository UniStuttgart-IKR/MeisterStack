// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! `meister-agent --check-config`: does this file parse, and nothing else.
//!
//! It exists so that a BUILD host can check a configuration for a node it is
//! not. That is the whole design constraint, and it is why the check may not
//! look anything up: a `nix flake check` on a laptop has neither the node's
//! `meister` group nor its data directory, and a check that needed either
//! would be a check that only passes where it is not needed.
//!
//! These tests run the real binary, because the claim is about the binary.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const BIN: &str = env!("CARGO_BIN_EXE_meister-agent");

fn examples() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../config/examples")
}

/// Put a line right after a section header, by the header's own line.
///
/// A plain `replace` would also hit the section names the file's prose lists,
/// and the test would be about a comment.
fn under(text: &str, section: &str, line: &str) -> String {
    let mut out = Vec::new();
    let mut placed = false;
    for existing in text.lines() {
        out.push(existing.to_string());
        if existing.trim() == section {
            out.push(line.to_string());
            placed = true;
        }
    }
    assert!(placed, "{section} is not a section of this file");
    out.join("\n")
}

fn check(config: &Path, cwd: Option<&Path>) -> Output {
    let mut cmd = Command::new(BIN);
    cmd.arg("--check-config").arg("--config").arg(config);
    if let Some(dir) = cwd {
        cmd.current_dir(dir);
    }
    cmd.output().expect("the agent binary was just built")
}

#[test]
fn every_example_config_is_accepted() {
    for name in ["agent.toml", "hardened/agent.toml"] {
        let path = examples().join(name);
        let out = check(&path, None);
        assert!(
            out.status.success(),
            "{name} was refused: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(
            String::from_utf8_lossy(&out.stdout).starts_with("ok: "),
            "{name}: {:?}",
            String::from_utf8_lossy(&out.stdout)
        );
    }
}

#[test]
fn an_unknown_key_is_refused_and_named() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("agent.toml");
    let text = std::fs::read_to_string(examples().join("agent.toml")).unwrap();
    std::fs::write(&path, format!("{text}\nnosuchkey = 1\n")).unwrap();

    let out = check(&path, None);
    assert_eq!(out.status.code(), Some(1));
    let said = String::from_utf8_lossy(&out.stderr);
    assert!(said.contains("nosuchkey"), "{said}");
    assert!(out.stdout.is_empty(), "nothing on stdout: {:?}", out.stdout);
}

#[test]
fn a_value_that_does_not_parse_is_refused_by_the_checker_that_reads_it() {
    // Not a serde error: `guarded_ranges` is checked by `nft_config`, which
    // `parse` runs for its refusals. Without that, a typo here would first
    // be noticed by a VM that never gets a network.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("agent.toml");
    let text = std::fs::read_to_string(examples().join("agent.toml")).unwrap();
    let text = under(&text, "[network]", r#"guarded_ranges = ["10.0.0.0/33"]"#);
    std::fs::write(&path, text).unwrap();

    let out = check(&path, None);
    assert_eq!(out.status.code(), Some(1));
    let said = String::from_utf8_lossy(&out.stderr);
    assert!(said.contains("guarded_ranges"), "{said}");
}

#[test]
fn checking_a_config_looks_nothing_up_and_writes_nothing() {
    let home = tempfile::tempdir().unwrap();
    let path = home.path().join("agent.toml");
    let text = std::fs::read_to_string(examples().join("agent.toml")).unwrap();
    // Two things this machine cannot answer: a group that does not exist
    // here, and a database directory that cannot be created. `load` would
    // fail on the first; opening the store would fail on the second. The
    // check passes, which is the point.
    let text = under(
        &text,
        "[paths]",
        r#"socket_group = "no-such-group-for-this-test""#,
    );
    let text = text.replace(
        "\"/var/lib/meisterstack/agent.redb\"",
        "\"/proc/this-directory-cannot-exist/agent.redb\"",
    );
    std::fs::write(&path, text).unwrap();

    let cwd = tempfile::tempdir().unwrap();
    std::fs::set_permissions(cwd.path(), std::fs::Permissions::from_mode(0o555)).unwrap();

    let out = check(&path, Some(cwd.path()));
    // Put it back before any assertion can fail, or the tempdir cannot be
    // removed and the next run of this test inherits the mess.
    std::fs::set_permissions(cwd.path(), std::fs::Permissions::from_mode(0o755)).unwrap();

    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        std::fs::read_dir(cwd.path()).unwrap().count(),
        0,
        "the check created something in its working directory"
    );
    assert!(!Path::new("/proc/this-directory-cannot-exist").exists());
}
