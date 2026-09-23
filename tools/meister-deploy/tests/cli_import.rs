// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! `keys import` against a CA that really exists.
//!
//! The other CLI tests put shims on `PATH` so that what they measure is
//! this tool's own argv. This one does the opposite: it makes a throwaway
//! CA with `tools/meister-ca`, with real openssl, under the fixed file
//! names a lab that predates this tool has — `system-node-<id>.crt`,
//! `system-cluster-<group>.crt` — and then imports them. What it proves is
//! the one thing a shim cannot: that the subject this fleet would issue and
//! the subject an existing certificate carries are the same string, so a
//! migration does not end in a host presenting a name nobody expects.
//!
//! The CA is made in a temporary directory and thrown away with it. The
//! lab's own PKI is never read: `/mnt/vmstore/MeisterStack/labpki` is not
//! touched here or anywhere in this crate.

mod support;

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use support::onebox;

const BIN: &str = env!("CARGO_BIN_EXE_meister-deploy");

fn meister_ca() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tools/meister-ca")
        .canonicalize()
        .expect("tools/meister-ca is in this repository")
}

/// The inventory fixture with `[operator] ca_dir` pointed at the throwaway
/// CA, which is where a CA key belongs: outside the repository.
fn inventory_with_ca(dir: &str) -> String {
    include_str!("fixtures/fleet-v2.toml")
        .lines()
        .map(|line| {
            if line.starts_with("ca_dir") {
                format!("ca_dir = {dir:?}")
            } else {
                line.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

struct Scratch {
    repo: tempfile::TempDir,
    ca: tempfile::TempDir,
    /// Where the certificates lie under their old fixed names, which is not
    /// the CA directory: a lab hands somebody a folder of files.
    handover: tempfile::TempDir,
    fleet: meister_deploy::manifest::ResolvedFleet,
}

impl Scratch {
    /// A CA, two identities, and the folder somebody would hand over.
    ///
    /// `--node n1` and `--cluster-identity <group>` are the two shapes that
    /// matter: one names a host and one names a GROUP of hosts, and the
    /// second is the one a file name cannot tell you the host of.
    fn new() -> Option<Scratch> {
        if Command::new("openssl").arg("version").output().is_err() {
            eprintln!("skipped: no openssl on this machine");
            return None;
        }
        let repo = tempfile::tempdir().unwrap();
        let ca = tempfile::tempdir().unwrap();
        let handover = tempfile::tempdir().unwrap();
        let fleet = onebox();

        let cluster =
            meister_deploy::pki::tier_name(&fleet, "box", meister_deploy::pki::CaKind::Cluster)
                .expect("box carries a cluster");

        let out = Command::new("bash")
            .arg(meister_ca())
            .args([
                "--dir",
                &ca.path().display().to_string(),
                "--node",
                "n1",
                "--cluster-identity",
                &cluster,
            ])
            .output()
            .expect("bash is on this machine");
        assert!(
            out.status.success(),
            "the throwaway CA did not build: {}",
            String::from_utf8_lossy(&out.stderr)
        );

        // What a hand-over folder looks like: the two certificates under the
        // names the CA gave them, their keys beside them at 0600, and the
        // CA's own certificate.
        let mut found = 0;
        for entry in walk(ca.path()) {
            let name = entry.file_name().unwrap().to_string_lossy().into_owned();
            if name.starts_with("system-") || name == "ca.crt" {
                std::fs::copy(&entry, handover.path().join(&name)).unwrap();
                found += 1;
            }
        }
        assert!(
            found >= 3,
            "the CA wrote no files under the names this test maps: {:?}",
            walk(ca.path())
        );

        std::fs::write(repo.path().join("manifest.json"), fleet.to_json().unwrap()).unwrap();
        std::fs::write(
            repo.path().join("fleet.toml"),
            inventory_with_ca(&ca.path().display().to_string()),
        )
        .unwrap();
        Some(Scratch {
            repo,
            ca,
            handover,
            fleet,
        })
    }

    fn run(&self, args: &[&str]) -> Output {
        Command::new(BIN)
            .args(args)
            .current_dir(self.repo.path())
            .output()
            .expect("the binary was just built")
    }

    fn path(&self, rest: &str) -> PathBuf {
        self.repo.path().join(rest)
    }
}

fn walk(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return out;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            out.extend(walk(&path));
        } else {
            out.push(path);
        }
    }
    out.sort();
    out
}

fn code(out: &Output) -> i32 {
    out.status.code().unwrap_or(-1)
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).to_string()
}

fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).to_string()
}

#[test]
fn certificates_a_lab_already_has_are_taken_in_under_the_host_they_belong_to() {
    let Some(scratch) = Scratch::new() else {
        return;
    };
    let cluster =
        meister_deploy::pki::tier_name(&scratch.fleet, "box", meister_deploy::pki::CaKind::Cluster)
            .unwrap();
    let node_stem = "system-node-n1";
    let cluster_stem = format!("system-cluster-{cluster}");

    // A dry run first: it says where each file would go and writes nothing.
    let out = scratch.run(&[
        "keys",
        "import",
        "--from",
        &scratch.handover.path().display().to_string(),
        "--map",
        &format!("n1={node_stem}"),
        "--map",
        &format!("box={cluster_stem}"),
        "--manifest",
        "manifest.json",
        "--inventory",
        "fleet.toml",
        "--dry-run",
    ]);
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    assert!(stdout(&out).contains("system:node:n1"), "{}", stdout(&out));
    assert!(
        stdout(&out).contains(&format!("system:cluster:{cluster}")),
        "{}",
        stdout(&out)
    );
    assert!(
        !scratch.path("pki/issued/n1/identity.crt").exists(),
        "a dry run copied a certificate"
    );

    // And now for real.
    let out = scratch.run(&[
        "keys",
        "import",
        "--from",
        &scratch.handover.path().display().to_string(),
        "--map",
        &format!("n1={node_stem}"),
        "--map",
        &format!("box={cluster_stem}"),
        "--manifest",
        "manifest.json",
        "--inventory",
        "fleet.toml",
        "--meister-ca",
        &meister_ca().display().to_string(),
    ]);
    assert_eq!(code(&out), 0, "{}", stderr(&out));

    // Each certificate under the host it belongs to, under the name the
    // planner compares against (`pki::issued_path`).
    for (host, stem) in [("n1", node_stem), ("box", cluster_stem.as_str())] {
        let landed = scratch.path(&format!("pki/issued/{host}/identity.crt"));
        assert!(landed.exists(), "{host}: {}", stderr(&out));
        assert_eq!(
            std::fs::read(&landed).unwrap(),
            std::fs::read(scratch.handover.path().join(format!("{stem}.crt"))).unwrap(),
            "{host} got a different certificate than the one handed over"
        );
    }

    // The private halves stayed where they were. Nothing under `pki/` in
    // the repository is a key — not one file, not one byte.
    for file in walk(&scratch.path("pki")) {
        let name = file.file_name().unwrap().to_string_lossy().into_owned();
        assert!(!name.ends_with(".key"), "a private key was copied: {name}");
        let text = String::from_utf8_lossy(&std::fs::read(&file).unwrap()).to_string();
        assert!(
            !text.contains("PRIVATE KEY"),
            "{name} contains a private key"
        );
    }

    // And the index the CA revokes out of names both of them, so an
    // imported certificate is one this fleet can take back.
    let index = std::fs::read_to_string(scratch.ca.path().join("index.txt")).unwrap_or_default();
    assert!(index.contains("system:node:n1"), "{index}");
    assert!(
        index.contains(&format!("system:cluster:{cluster}")),
        "{index}"
    );
}

#[test]
fn a_certificate_mapped_to_the_wrong_host_is_refused_and_nothing_is_copied() {
    let Some(scratch) = Scratch::new() else {
        return;
    };
    // `system-node-n1` is CN=system:node:n1. Mapping it to n2 would put n1's
    // identity under n2's name, and the fleet would then have two machines
    // able to speak as one.
    let out = scratch.run(&[
        "keys",
        "import",
        "--from",
        &scratch.handover.path().display().to_string(),
        "--map",
        "n2=system-node-n1",
        "--manifest",
        "manifest.json",
        "--inventory",
        "fleet.toml",
    ]);
    assert_eq!(code(&out), 1, "{}", stderr(&out));
    assert!(
        stderr(&out).contains("system:node:n1") && stderr(&out).contains("system:node:n2"),
        "the refusal names both subjects: {}",
        stderr(&out)
    );
    assert!(
        !scratch.path("pki/issued/n2").exists(),
        "a refusal wrote something"
    );
}

#[test]
fn a_private_key_that_lies_open_stops_the_import() {
    let Some(scratch) = Scratch::new() else {
        return;
    };
    use std::os::unix::fs::PermissionsExt;
    let key = scratch.handover.path().join("system-node-n1.key");
    std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o644)).unwrap();
    let out = scratch.run(&[
        "keys",
        "import",
        "--from",
        &scratch.handover.path().display().to_string(),
        "--map",
        "n1=system-node-n1",
        "--manifest",
        "manifest.json",
        "--inventory",
        "fleet.toml",
    ]);
    assert_eq!(code(&out), 1, "{}", stderr(&out));
    assert!(stderr(&out).contains("chmod 600"), "{}", stderr(&out));
    assert!(!scratch.path("pki/issued/n1").exists());
}

#[test]
fn a_stem_that_is_not_there_says_what_is() {
    let Some(scratch) = Scratch::new() else {
        return;
    };
    let out = scratch.run(&[
        "keys",
        "import",
        "--from",
        &scratch.handover.path().display().to_string(),
        "--map",
        "n1=system-node-nowhere",
        "--manifest",
        "manifest.json",
        "--inventory",
        "fleet.toml",
    ]);
    assert_eq!(code(&out), 1, "{}", stderr(&out));
    assert!(
        stderr(&out).contains("system-node-n1.crt"),
        "{}",
        stderr(&out)
    );
}

#[test]
fn one_host_cannot_be_mapped_twice_and_a_host_outside_the_manifest_is_named() {
    let Some(scratch) = Scratch::new() else {
        return;
    };
    let out = scratch.run(&[
        "keys",
        "import",
        "--from",
        &scratch.handover.path().display().to_string(),
        "--map",
        "n1=system-node-n1",
        "--map",
        "n1=system-node-n1",
        "--manifest",
        "manifest.json",
        "--inventory",
        "fleet.toml",
    ]);
    assert_eq!(code(&out), 1, "{}", stderr(&out));
    assert!(stderr(&out).contains("mapped twice"), "{}", stderr(&out));

    let out = scratch.run(&[
        "keys",
        "import",
        "--from",
        &scratch.handover.path().display().to_string(),
        "--map",
        "nobody=system-node-n1",
        "--manifest",
        "manifest.json",
        "--inventory",
        "fleet.toml",
    ]);
    assert_eq!(code(&out), 1, "{}", stderr(&out));
    assert!(stderr(&out).contains("nobody"), "{}", stderr(&out));
}
