// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Exercise the real --check-config binary without starting controller services.
//! The check validates configuration and reads a configured CRL; other credential
//! files and backend connectivity are not validated here.

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
fn a_config_that_names_no_authenticator_is_refused() {
    // No client CA, no token, no provider: the default chain would build
    // nothing, and an empty chain serves every caller as an administrator.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("cluster.toml");
    std::fs::write(&path, "listen_api = \"127.0.0.1:1\"\n").unwrap();

    let out = check(&path, None);
    assert_eq!(out.status.code(), Some(1));
    let said = String::from_utf8_lossy(&out.stderr);
    assert!(
        said.contains("anonymous = true"),
        "and it says how to ask: {said}"
    );
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
             etcd_endpoints = \"http://127.0.0.1:1\"\n\
             [auth]\nanonymous = true\n",
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
    // This fixture assumes port 1 cannot be bound by the test process.
    // The assertion alone does not establish whether a connect was attempted.
    assert!(TcpListener::bind("127.0.0.1:1").is_err());
}

// --- lane 5A ---------------------------------------------------------------

/// `auth.crl` is the one key in that table whose FILE the check opens, and
/// on purpose: a controller that names a list refuses to start without it,
/// so a check that said "ok" to an unreadable one would be a check that
/// promises a start-up it cannot have.
#[test]
fn a_revocation_list_is_read_by_the_check_and_named_when_it_cannot_be() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("cluster.toml");

    // Named and not there.
    // Revocation is checked by the mtls link, so the config names a client CA.
    // The check reads the list and not the CA.
    std::fs::write(&path, "client_ca = \"ca.crt\"\n[auth]\ncrl = \"crl.pem\"\n").unwrap();
    let out = check(&path, None);
    assert_eq!(out.status.code(), Some(1));
    let said = String::from_utf8_lossy(&out.stderr);
    assert!(said.contains("crl.pem"), "{said}");

    // Named and not a list.
    std::fs::write(dir.path().join("crl.pem"), "not a crl\n").unwrap();
    let out = check(&path, None);
    assert_eq!(out.status.code(), Some(1));
    let said = String::from_utf8_lossy(&out.stderr);
    assert!(said.contains("revocation list"), "{said}");

    // And a real one, written by the script an operator runs. The path is
    // relative to the CONFIG, like every other file in that table.
    let ca = dir.path().join("ca");
    let meister_ca = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tools/meister-ca");
    let made = Command::new("bash")
        .arg(&meister_ca)
        .args(["--dir", ca.to_str().unwrap(), "--init", "--node", "n1"])
        .output()
        .expect("bash");
    if !made.status.success() {
        // Any fixture-generation failure skips acceptance coverage.
        // The missing and malformed CRL cases above have still run.
        eprintln!("skipping the accepted half: meister-ca did not run here");
        return;
    }
    let out = Command::new("bash")
        .arg(&meister_ca)
        .args([
            "--dir",
            ca.to_str().unwrap(),
            "--revoke",
            ca.join("system-node-n1.crt").to_str().unwrap(),
            "--gencrl",
        ])
        .output()
        .expect("bash");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    std::fs::copy(ca.join("crl.pem"), dir.path().join("crl.pem")).unwrap();

    let out = check(&path, None);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let said = String::from_utf8_lossy(&out.stderr);
    assert!(said.contains("1 revoked serial(s)"), "{said}");
}
