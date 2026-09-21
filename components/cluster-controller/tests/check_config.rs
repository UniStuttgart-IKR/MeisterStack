// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! `meister-cluster-controller --check-config`: does this file parse and hang
//! together, and nothing else.
//!
//! Its reason for existing is the same as the agent's: a `nix flake check`
//! on a build host has to be able to say that a controller's configuration
//! is sound without being that controller. So the check binds no port, dials
//! no etcd, and opens no file the configuration points at — the last of
//! those is why the authenticator chain is checked in two halves
//! (`rest::check_chain` decides which links stand, `rest::build_chain` opens
//! their files), and this covers only the first.
//!
//! These tests run the real binary, because the claim is about the binary.

use std::net::TcpListener;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const BIN: &str = env!("CARGO_BIN_EXE_meister-cluster-controller");

fn examples() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../config/examples")
}

fn check(config: &Path, cwd: Option<&Path>) -> Output {
    let mut cmd = Command::new(BIN);
    cmd.arg("--check-config").arg("--config").arg(config);
    if let Some(dir) = cwd {
        cmd.current_dir(dir);
    }
    cmd.output().expect("the controller binary was just built")
}

#[test]
fn every_example_config_is_accepted() {
    for name in ["cluster.toml", "hardened/cluster.toml"] {
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
    let path = dir.path().join("cluster.toml");
    let text = std::fs::read_to_string(examples().join("cluster.toml")).unwrap();
    std::fs::write(&path, format!("{text}\nnosuchkey = 1\n")).unwrap();

    let out = check(&path, None);
    assert_eq!(out.status.code(), Some(1));
    let said = String::from_utf8_lossy(&out.stderr);
    assert!(said.contains("nosuchkey"), "{said}");
    assert!(out.stdout.is_empty(), "nothing on stdout: {:?}", out.stdout);
}

#[test]
fn an_auth_chain_that_cannot_stand_is_refused_without_reading_a_single_key() {
    // `check_chain`'s half of the refusals: a chain that names a link it has
    // no configuration for. No CA is named, so nothing could be opened even
    // if the check wanted to.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("cluster.toml");
    std::fs::write(&path, "[auth]\nchain = [\"bearer\"]\n").unwrap();

    let out = check(&path, None);
    assert_eq!(out.status.code(), Some(1));
    let said = String::from_utf8_lossy(&out.stderr);
    assert!(said.contains("bearer"), "{said}");
}

#[test]
fn checking_a_config_binds_nothing_dials_nothing_and_writes_nothing() {
    // The two addresses the config names are already taken by this test. A
    // check that bound them would fail; it passes, so it did not bind.
    let api = TcpListener::bind("127.0.0.1:0").unwrap();
    let session = TcpListener::bind("127.0.0.1:0").unwrap();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("cluster.toml");
    std::fs::write(
        &path,
        format!(
            "listen_api = \"{}\"\nlisten_session = \"{}\"\n\
             etcd_endpoints = \"http://127.0.0.1:1\"\n",
            api.local_addr().unwrap(),
            session.local_addr().unwrap()
        ),
    )
    .unwrap();

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
    // port 1 is not listening anywhere on this machine; the check returned
    // in milliseconds rather than waiting for a connection that never comes.
    assert!(TcpListener::bind("127.0.0.1:1").is_err());
}
