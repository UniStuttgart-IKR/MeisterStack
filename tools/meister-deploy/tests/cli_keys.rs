// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! `meister-deploy keys` through the real binary.
//!
//! The unit tests pin the comparison, the subjects and the command lines.
//! This pins the PROGRAM: `PATH` holds nothing but a directory of shims, so
//! whatever the verbs run is in a log and whatever the log does not have
//! they did not run. Three shims answer rather than fail —
//! `ssh-keyscan` hands back a host key, `ssh` hands back what
//! `meister-activate keygen` would have printed, and `meister-ca` writes a
//! file — because what is interesting here is the wiring: which file lands
//! where, and which refusal comes before which connection.
//!
//! No host, no network, no CA key. `scripts/check-sign-csr.sh` is where the
//! CA meets real openssl, and `nix/tests/keys.nix` is where all of it meets
//! a real machine.

mod support;

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use meister_deploy::manifest::ResolvedFleet;

use support::onebox;

const BIN: &str = env!("CARGO_BIN_EXE_meister-deploy");

const SHIMS: [&str; 5] = ["ssh", "ssh-keygen", "ssh-keyscan", "meister-ca", "openssl"];

/// A real ed25519 public key and the fingerprint `ssh-keygen -lf` prints for
/// it — the same vector the unit tests use.
const KEY: &str = "AAAAC3NzaC1lZDI1NTE5AAAAIGaYimwvsKj3dq6R/7mpM1IdGR6CKdji1qLjc488Cxol";
const FINGERPRINT: &str = "SHA256:n4iE8HiaQ8h0ur9SAR4Op6czqCfYYwHSX857a4w10Ks";
/// A second one, for "that is not the machine whose console you read".
const OTHER_KEY: &str = "AAAAC3NzaC1lZDI1NTE5AAAAIBxDX2LuYkwdC3yGwD8hW6DpgdYcrFFs7fcm0OXyb7T6";

struct Sandbox {
    cwd: tempfile::TempDir,
    shims: tempfile::TempDir,
    home: tempfile::TempDir,
    ca: tempfile::TempDir,
    log: PathBuf,
    fleet: ResolvedFleet,
}

impl Sandbox {
    fn new() -> Sandbox {
        use std::os::unix::fs::PermissionsExt;
        let shims = tempfile::tempdir().unwrap();
        let cwd = tempfile::tempdir().unwrap();
        let home = tempfile::tempdir().unwrap();
        let ca = tempfile::tempdir().unwrap();
        let log = shims.path().join("calls.log");

        for name in SHIMS {
            let body = match name {
                // What answers on the address. `MEISTER_SHIM_KEY` decides
                // which key, so a test can make the machine a different one.
                "ssh-keyscan" => format!(
                    "#!/bin/sh\nline=\"{name}\"\naddr=\n\
                     for a in \"$@\"; do line=\"$line [$a]\"; addr=\"$a\"; done\n\
                     printf '%s\\n' \"$line\" >> \"$MEISTER_SHIM_LOG\"\n\
                     printf '# %s:22 SSH-2.0-OpenSSH_10.0\\n' \"$addr\"\n\
                     printf '%s ssh-ed25519 %s\\n' \"$addr\" \"$MEISTER_SHIM_KEY\"\n\
                     exit 0\n"
                ),
                // The enrolment lookup `require_enrolled` does before the
                // first connection: answers only while the file is there.
                "ssh-keygen" => format!(
                    "#!/bin/sh\nline=\"{name}\"\n\
                     for a in \"$@\"; do line=\"$line [$a]\"; done\n\
                     printf '%s\\n' \"$line\" >> \"$MEISTER_SHIM_LOG\"\n\
                     if [ -f \"$MEISTER_SHIM_ENROLLED\" ]; then \
                     printf '# Host found: line 1\\n10.0.0.11 ssh-ed25519 {KEY}\\n'; exit 0; fi\n\
                     exit 1\n"
                ),
                // `meister-activate keygen` on the far side: the json the
                // helper prints, with a request-shaped body and no key.
                "ssh" => format!(
                    "#!/bin/sh\nline=\"{name}\"\n\
                     for a in \"$@\"; do line=\"$line [$a]\"; done\n\
                     printf '%s\\n' \"$line\" >> \"$MEISTER_SHIM_LOG\"\n\
                     while IFS= read -r l; do printf '%s\\n' \"$l\"; done \
                     < \"$MEISTER_SHIM_KEYGEN\"\nexit 0\n"
                ),
                // The CA: writes what it was told to write and nothing else.
                "meister-ca" => format!(
                    "#!/bin/sh\nline=\"{name}\"\nout=\ntake=\n\
                     for a in \"$@\"; do line=\"$line [$a]\"; \
                     if [ \"$take\" = out ]; then out=\"$a\"; take=; fi; \
                     if [ \"$a\" = --out ]; then take=out; fi; done\n\
                     printf '%s\\n' \"$line\" >> \"$MEISTER_SHIM_LOG\"\n\
                     printf 'a certificate\\n' > \"$out\"\n\
                     printf '%s\\n' \"$out\"\nexit 0\n"
                ),
                // `openssl x509` reading the certificate back.
                _ => format!(
                    "#!/bin/sh\nline=\"{name}\"\n\
                     for a in \"$@\"; do line=\"$line [$a]\"; done\n\
                     printf '%s\\n' \"$line\" >> \"$MEISTER_SHIM_LOG\"\n\
                     printf 'serial=0A0B\\nsubject=CN=x\\nnotAfter=Dec 20 16:55:20 2026 GMT\\n'\n\
                     exit 0\n"
                ),
            };
            let path = shims.path().join(name);
            std::fs::write(&path, &body).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
            // So a shim can be read by hand when one of these tests says
            // something surprising: `MEISTER_TEST_KEEP=<dir>` copies them
            // out. Nothing depends on it.
            if let Ok(keep) = std::env::var("MEISTER_TEST_KEEP") {
                std::fs::create_dir_all(&keep).unwrap();
                std::fs::write(Path::new(&keep).join(name), &body).unwrap();
            }
        }

        let fleet = onebox();
        std::fs::write(cwd.path().join("manifest.json"), fleet.to_json().unwrap()).unwrap();
        // An inventory whose `[operator] ca_dir` points OUT of the
        // repository, which is where a CA key belongs.
        std::fs::write(
            cwd.path().join("fleet.toml"),
            inventory_with_ca(&ca.path().display().to_string()),
        )
        .unwrap();

        Sandbox {
            cwd,
            shims,
            home,
            ca,
            log,
            fleet,
        }
    }

    /// What the far side answers `keygen` with.
    fn keygen_answer(&self, subject: &str) {
        let reply = serde_json::json!({
            "subject": subject,
            "kind": "identity",
            "csr_pem": "-----BEGIN CERTIFICATE REQUEST-----\nAAAA\n-----END CERTIFICATE REQUEST-----\n",
            "public_key_sha256": "ab".repeat(32),
            "created": true,
        });
        self.answer_keygen(&reply);
    }

    /// Put an answer where the `ssh` shim reads it.
    ///
    /// With a trailing newline, and that is not cosmetic: `while read`
    /// returns non-zero on a last line that has none, so the loop body
    /// never runs for it and the shim answers with nothing at all.
    fn answer_keygen(&self, reply: &serde_json::Value) {
        std::fs::write(
            self.shims.path().join("keygen.json"),
            format!("{}\n", serde_json::to_string(reply).unwrap()),
        )
        .unwrap();
    }

    fn enrolled(&self, yes: bool) {
        let marker = self.shims.path().join("enrolled");
        if yes {
            std::fs::write(&marker, "").unwrap();
        } else {
            let _ = std::fs::remove_file(&marker);
        }
    }

    fn run_with_key(&self, key: &str, args: &[&str]) -> Output {
        Command::new(BIN)
            .args(args)
            .current_dir(self.cwd.path())
            .env("PATH", self.shims.path())
            .env("MEISTER_SHIM_LOG", &self.log)
            .env("MEISTER_SHIM_KEY", key)
            .env("MEISTER_SHIM_ENROLLED", self.shims.path().join("enrolled"))
            .env("MEISTER_SHIM_KEYGEN", self.shims.path().join("keygen.json"))
            .env("HOME", self.home.path())
            .output()
            .expect("the binary was just built")
    }

    fn run(&self, args: &[&str]) -> Output {
        self.run_with_key(KEY, args)
    }

    fn calls(&self) -> Vec<String> {
        std::fs::read_to_string(&self.log)
            .map(|t| {
                t.lines()
                    .filter(|l| SHIMS.iter().any(|s| l.starts_with(*s)))
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default()
    }

    fn known_hosts(&self) -> String {
        std::fs::read_to_string(self.cwd.path().join("known_hosts")).unwrap_or_default()
    }

    fn path(&self, rest: &str) -> PathBuf {
        self.cwd.path().join(rest)
    }
}

/// The checked-in inventory with `[operator] ca_dir` pointed somewhere else.
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

/// Enrolling `n1` through the MANIFEST. The inventory fixture beside it is
/// a different fleet — which is the ordinary case for a host that has been
/// resolved once — and the other spelling has a test of its own below.
const ENROLL_N1: [&str; 7] = [
    "keys",
    "enroll",
    "n1",
    "--fingerprint",
    FINGERPRINT,
    "--manifest",
    "manifest.json",
];

fn code(out: &Output) -> i32 {
    out.status.code().unwrap_or(-1)
}

fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

/// The whole of D10 through the binary: a host is enrolled against a typed
/// fingerprint, and `known_hosts` is what comes out.
#[test]
fn enrolling_writes_known_hosts_and_prints_the_line_for_the_inventory() {
    let sandbox = Sandbox::new();
    let out = sandbox.run(&ENROLL_N1);
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    assert_eq!(
        sandbox.known_hosts(),
        format!("10.0.0.11 ssh-ed25519 {KEY}\n")
    );
    // The inventory is not touched, and the line to paste is on stderr.
    let before = include_str!("fixtures/fleet-v2.toml");
    assert!(
        std::fs::read_to_string(sandbox.path("fleet.toml"))
            .unwrap()
            .starts_with(&before[..40]),
        "the inventory was edited"
    );
    assert!(
        stderr(&out).contains(&format!("ssh.host_key = \"{FINGERPRINT}\"")),
        "{}",
        stderr(&out)
    );
    // Exactly one program was run, and it was the scan.
    assert_eq!(sandbox.calls().len(), 1, "{:?}", sandbox.calls());
    assert!(
        sandbox.calls()[0].starts_with("ssh-keyscan"),
        "{:?}",
        sandbox.calls()
    );
}

#[test]
fn a_machine_that_shows_another_key_is_not_enrolled_and_the_file_stays_empty() {
    let sandbox = Sandbox::new();
    let out = sandbox.run_with_key(OTHER_KEY, &ENROLL_N1);
    assert_eq!(code(&out), 1);
    assert!(
        stderr(&out).contains("is not the one you typed"),
        "{}",
        stderr(&out)
    );
    assert_eq!(sandbox.known_hosts(), "");
}

#[test]
fn enrolling_twice_is_not_a_change_and_enrolling_offline_is_refused() {
    let sandbox = Sandbox::new();
    sandbox.run(&ENROLL_N1);
    let first = sandbox.known_hosts();
    let out = sandbox.run(&ENROLL_N1);
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    assert!(
        stdout(&out).contains("already enrolled"),
        "{}",
        stdout(&out)
    );
    assert_eq!(sandbox.known_hosts(), first);

    let out = sandbox.run(&[
        "keys",
        "enroll",
        "n1",
        "--fingerprint",
        FINGERPRINT,
        "--manifest",
        "manifest.json",
        "--offline",
    ]);
    assert_eq!(code(&out), 1);
    assert!(
        stderr(&out).contains("--offline forbids asking"),
        "{}",
        stderr(&out)
    );
}

#[test]
fn a_dry_run_asks_and_writes_nothing() {
    let sandbox = Sandbox::new();
    let out = sandbox.run(&[
        "keys",
        "enroll",
        "n1",
        "--fingerprint",
        FINGERPRINT,
        "--manifest",
        "manifest.json",
        "--dry-run",
    ]);
    assert_eq!(code(&out), 1, "{}", stderr(&out));
    // It asked — a scan is a read — and the write is what the policy
    // stopped, at the door.
    assert!(
        sandbox.calls()[0].starts_with("ssh-keyscan"),
        "{:?}",
        sandbox.calls()
    );
    assert!(stderr(&out).contains("--dry-run"), "{}", stderr(&out));
    assert_eq!(sandbox.known_hosts(), "");
}

/// A host nobody enrolled is refused BEFORE the first connection, with the
/// verb that was never run in the sentence.
#[test]
fn a_request_from_a_host_that_is_not_enrolled_is_refused_before_it_is_asked() {
    let sandbox = Sandbox::new();
    sandbox.enrolled(false);
    sandbox.keygen_answer("system:node:n1");
    let out = sandbox.run(&["keys", "csr", "--host", "n1", "--manifest", "manifest.json"]);
    assert_eq!(code(&out), 1);
    assert!(stderr(&out).contains("keys enroll"), "{}", stderr(&out));
    // The lookup is local. No ssh happened.
    assert!(
        !sandbox.calls().iter().any(|c| c.starts_with("ssh ")),
        "{:?}",
        sandbox.calls()
    );
}

#[test]
fn a_request_lands_under_the_repository_and_names_the_subject() {
    let sandbox = Sandbox::new();
    sandbox.enrolled(true);
    sandbox.keygen_answer("system:node:n1");
    let out = sandbox.run(&["keys", "csr", "--host", "n1", "--manifest", "manifest.json"]);
    assert_eq!(code(&out), 0, "{}\n{:?}", stderr(&out), sandbox.calls());
    let csr = sandbox.path("pki/csr/n1-identity.csr");
    assert!(csr.exists(), "{}", stdout(&out));
    assert!(
        std::fs::read_to_string(&csr)
            .unwrap()
            .contains("BEGIN CERTIFICATE REQUEST")
    );
    assert!(
        stderr(&out).contains("CN=system:node:n1, O=system:nodes"),
        "{}",
        stderr(&out)
    );
    // And the ssh carried the subject this fleet decided on.
    let ssh = sandbox
        .calls()
        .into_iter()
        .find(|c| c.starts_with("ssh "))
        .expect("an ssh happened");
    assert!(ssh.contains("[meister-activate]"), "{ssh}");
    assert!(ssh.contains("[keygen]"), "{ssh}");
    assert!(ssh.contains("[system:node:n1]"), "{ssh}");
}

/// A host that carries several tiers has one `identity.key`, so the
/// operator says which identity it holds.
#[test]
fn a_host_with_two_tiers_is_asked_which_one_it_is() {
    let sandbox = Sandbox::new();
    sandbox.enrolled(true);
    sandbox.keygen_answer("system:cluster:box");
    let out = sandbox.run(&[
        "keys",
        "csr",
        "--host",
        "box",
        "--manifest",
        "manifest.json",
    ]);
    assert_eq!(code(&out), 1);
    let why = stderr(&out);
    assert!(why.contains("ONE identity.key"), "{why}");
    assert!(why.contains("--as"), "{why}");

    let out = sandbox.run(&[
        "keys",
        "csr",
        "--host",
        "box",
        "--as",
        "cluster",
        "--manifest",
        "manifest.json",
    ]);
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    assert!(
        stderr(&out).contains("CN=system:cluster:box"),
        "{}",
        stderr(&out)
    );

    // And a tier the host does not carry is a sentence with the ones it
    // does.
    let out = sandbox.run(&[
        "keys",
        "csr",
        "--host",
        "n1",
        "--as",
        "cloud",
        "--manifest",
        "manifest.json",
    ]);
    assert_eq!(code(&out), 1);
    assert!(
        stderr(&out).contains("cannot be a cloud"),
        "{}",
        stderr(&out)
    );
}

/// The CA gets the subject, the request and a place to put the answer — and
/// the certificate lands where `deliver-secret` will look for it.
#[test]
fn issuing_calls_the_ca_and_keeps_the_certificate_in_the_repository() {
    let sandbox = Sandbox::new();
    sandbox.enrolled(true);
    // A real request, made here, so that the signature check has something
    // true to check.
    let made = pki::generate_key_and_csr("system:node:n1").unwrap();
    std::fs::create_dir_all(sandbox.path("pki/csr")).unwrap();
    std::fs::write(sandbox.path("pki/csr/n1-identity.csr"), &made.csr_pem).unwrap();

    let out = sandbox.run(&[
        "keys",
        "issue",
        "--host",
        "n1",
        "--kind",
        "node",
        "--manifest",
        "manifest.json",
        "--inventory",
        "fleet.toml",
    ]);
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    let crt = sandbox.path("pki/issued/n1/identity.crt");
    assert!(crt.exists(), "{}", stdout(&out));

    let call = sandbox
        .calls()
        .into_iter()
        .find(|c| c.starts_with("meister-ca"))
        .expect("the ca was called");
    assert!(call.contains("[--kind] [node]"), "{call}");
    assert!(call.contains("[--name] [n1]"), "{call}");
    assert!(
        call.contains(&format!("[--dir] [{}]", sandbox.ca.path().display())),
        "{call}"
    );
    assert!(
        !call.contains("[--san]"),
        "a client certificate has no SANs: {call}"
    );
    // And the sentence says how it gets to the host, which is not a verb.
    assert!(stderr(&out).contains("deliver-secret"), "{}", stderr(&out));
}

/// A request for another name is not signed, even though the CA would write
/// its own subject: it means the request came from somewhere else.
#[test]
fn a_request_for_another_name_is_refused() {
    let sandbox = Sandbox::new();
    let made = pki::generate_key_and_csr("system:node:n2").unwrap();
    std::fs::create_dir_all(sandbox.path("pki/csr")).unwrap();
    std::fs::write(sandbox.path("pki/csr/n1-identity.csr"), &made.csr_pem).unwrap();
    let out = sandbox.run(&[
        "keys",
        "issue",
        "--host",
        "n1",
        "--kind",
        "node",
        "--manifest",
        "manifest.json",
        "--inventory",
        "fleet.toml",
    ]);
    assert_eq!(code(&out), 1);
    let why = stderr(&out);
    assert!(why.contains("system:node:n2"), "{why}");
    assert!(why.contains("system:node:n1"), "{why}");
    assert!(
        !sandbox.calls().iter().any(|c| c.starts_with("meister-ca")),
        "the ca was called anyway: {:?}",
        sandbox.calls()
    );
}

/// A request nobody signed is a form, and this CA does not fill in forms.
#[test]
fn a_request_that_is_not_signed_by_its_own_key_is_refused() {
    let sandbox = Sandbox::new();
    let made = pki::generate_key_and_csr("system:node:n1").unwrap();
    let mut lines: Vec<String> = made.csr_pem.lines().map(str::to_string).collect();
    let body = lines.len() / 2;
    lines[body] = lines[body]
        .chars()
        .map(|c| match c {
            'A' => 'B',
            'B' => 'A',
            other => other,
        })
        .collect();
    std::fs::create_dir_all(sandbox.path("pki/csr")).unwrap();
    std::fs::write(sandbox.path("pki/csr/n1-identity.csr"), lines.join("\n")).unwrap();
    let out = sandbox.run(&[
        "keys",
        "issue",
        "--host",
        "n1",
        "--kind",
        "node",
        "--manifest",
        "manifest.json",
        "--inventory",
        "fleet.toml",
    ]);
    assert_eq!(code(&out), 1);
    assert!(
        stderr(&out).contains("not a certificate request this CA will sign"),
        "{}",
        stderr(&out)
    );
    assert!(!sandbox.calls().iter().any(|c| c.starts_with("meister-ca")));
}

/// The CA key is the one file of this fleet that must not be committed.
#[test]
fn a_ca_directory_inside_the_repository_is_refused() {
    let sandbox = Sandbox::new();
    std::fs::write(sandbox.path("fleet.toml"), inventory_with_ca("pki/ca")).unwrap();
    let made = pki::generate_key_and_csr("system:node:n1").unwrap();
    std::fs::create_dir_all(sandbox.path("pki/csr")).unwrap();
    std::fs::write(sandbox.path("pki/csr/n1-identity.csr"), &made.csr_pem).unwrap();
    let out = sandbox.run(&[
        "keys",
        "issue",
        "--host",
        "n1",
        "--kind",
        "node",
        "--manifest",
        "manifest.json",
        "--inventory",
        "fleet.toml",
        "--repo",
        ".",
    ]);
    assert_eq!(code(&out), 1);
    assert!(stderr(&out).contains("is committed"), "{}", stderr(&out));
}

/// A dry run of either verb prints the command line and runs nothing.
#[test]
fn a_dry_run_of_the_two_verbs_runs_nothing() {
    let sandbox = Sandbox::new();
    sandbox.enrolled(true);
    let out = sandbox.run(&[
        "keys",
        "csr",
        "--host",
        "n1",
        "--manifest",
        "manifest.json",
        "--dry-run",
    ]);
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    assert!(
        stdout(&out).contains("meister-activate --json keygen"),
        "{}",
        stdout(&out)
    );
    assert!(sandbox.calls().is_empty(), "{:?}", sandbox.calls());
    assert!(!sandbox.path("pki/csr/n1-identity.csr").exists());

    let made = pki::generate_key_and_csr("system:node:n1").unwrap();
    std::fs::create_dir_all(sandbox.path("pki/csr")).unwrap();
    std::fs::write(sandbox.path("pki/csr/n1-identity.csr"), &made.csr_pem).unwrap();
    let out = sandbox.run(&[
        "keys",
        "issue",
        "--host",
        "n1",
        "--kind",
        "node",
        "--manifest",
        "manifest.json",
        "--inventory",
        "fleet.toml",
        "--dry-run",
    ]);
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    assert!(stdout(&out).contains("--sign-csr"), "{}", stdout(&out));
    assert!(sandbox.calls().is_empty(), "{:?}", sandbox.calls());
    assert!(!sandbox.path("pki/issued/n1/identity.crt").exists());
}

/// A host the manifest does not know is named, and so is what it does know.
#[test]
fn a_host_that_is_not_in_the_manifest_is_named() {
    let sandbox = Sandbox::new();
    let out = sandbox.run(&[
        "keys",
        "csr",
        "--host",
        "nobody",
        "--manifest",
        "manifest.json",
    ]);
    assert_eq!(code(&out), 1);
    let why = stderr(&out);
    assert!(why.contains("names no host \"nobody\""), "{why}");
    for id in sandbox.fleet.hosts.keys() {
        assert!(why.contains(id.as_str()), "{why}");
    }
}

/// A certificate request that travels through this tool never carries a key,
/// and the check is in the program rather than in a comment.
#[test]
fn a_helper_that_sends_a_key_is_not_the_helper_this_tool_speaks_to() {
    let sandbox = Sandbox::new();
    sandbox.enrolled(true);
    let reply = serde_json::json!({
        "subject": "system:node:n1",
        "kind": "identity",
        "csr_pem": "-----BEGIN CERTIFICATE REQUEST-----\nA\n-----END CERTIFICATE REQUEST-----\n\
                    -----BEGIN PRIVATE KEY-----\nB\n-----END PRIVATE KEY-----\n",
        "public_key_sha256": "ab".repeat(32),
        "created": true,
    });
    sandbox.answer_keygen(&reply);
    let out = sandbox.run(&["keys", "csr", "--host", "n1", "--manifest", "manifest.json"]);
    assert_eq!(code(&out), 1);
    assert!(stderr(&out).contains("PRIVATE KEY"), "{}", stderr(&out));
    assert!(!sandbox.path("pki/csr/n1-identity.csr").exists());
}

/// Whatever else it prints, no verb of this file ever puts a key on stdout.
#[test]
fn nothing_these_verbs_print_is_a_private_key() {
    let sandbox = Sandbox::new();
    sandbox.enrolled(true);
    sandbox.keygen_answer("system:node:n1");
    let made = pki::generate_key_and_csr("system:node:n1").unwrap();
    let mut printed = String::new();
    for args in [
        vec![
            "keys",
            "enroll",
            "n1",
            "--fingerprint",
            FINGERPRINT,
            "--manifest",
            "manifest.json",
            "--json",
        ],
        vec![
            "keys",
            "csr",
            "--host",
            "n1",
            "--manifest",
            "manifest.json",
            "--json",
        ],
    ] {
        let out = sandbox.run(&args);
        printed.push_str(&stdout(&out));
        printed.push_str(&stderr(&out));
    }
    std::fs::write(sandbox.path("pki/csr/n1-identity.csr"), &made.csr_pem).unwrap();
    let out = sandbox.run(&[
        "keys",
        "issue",
        "--host",
        "n1",
        "--kind",
        "node",
        "--manifest",
        "manifest.json",
        "--inventory",
        "fleet.toml",
        "--json",
    ]);
    printed.push_str(&stdout(&out));
    printed.push_str(&stderr(&out));
    assert!(!printed.contains("PRIVATE KEY"), "{printed}");
    assert!(!printed.contains(&made.key_pem), "{printed}");
}

/// The file `deliver-secret` will read is the one `keys issue` wrote, under
/// the name it has on the host.
#[test]
fn the_names_of_the_two_directories_are_the_contract_with_the_planner() {
    assert_eq!(meister_deploy::pki::CSR_DIR, "pki/csr");
    assert_eq!(meister_deploy::pki::ISSUED_DIR, "pki/issued");
    let repo = Path::new("/repo");
    assert_eq!(
        meister_deploy::pki::csr_path(repo, "n1", "identity"),
        repo.join("pki/csr/n1-identity.csr")
    );
    assert_eq!(
        meister_deploy::pki::issued_path(repo, "n1", "identity.crt"),
        repo.join("pki/issued/n1/identity.crt")
    );
}

/// The road a FRESH machine takes: there is no manifest yet, because a host
/// nobody has enrolled cannot be reached and so nothing that reaches it can
/// have run. The inventory is the file that exists at that point.
#[test]
fn a_host_that_was_never_resolved_is_read_out_of_the_inventory() {
    let sandbox = Sandbox::new();
    let out = sandbox.run(&["keys", "enroll", "cloud-a", "--fingerprint", FINGERPRINT]);
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    // The address, the port and the user came out of `fleet.toml`.
    assert_eq!(
        sandbox.known_hosts(),
        format!("10.128.1.103 ssh-ed25519 {KEY}\n")
    );
    let out = sandbox.run(&["keys", "enroll", "nobody", "--fingerprint", FINGERPRINT]);
    assert_eq!(code(&out), 1);
    assert!(
        stderr(&out).contains("no host \"nobody\" in this inventory"),
        "{}",
        stderr(&out)
    );
}

// --- lane 5A: taking one back ------------------------------------------------

/// The refusals of `keys revoke` come before the CA is touched at all, and
/// the log is what proves it: nothing ran.
#[test]
fn a_revocation_says_what_is_being_taken_back_before_it_touches_the_ca() {
    let sandbox = Sandbox::new();
    let release = support::release_of(sandbox.fleet.clone());
    std::fs::write(
        sandbox.cwd.path().join("release.json"),
        release.to_json().unwrap(),
    )
    .unwrap();

    // Nothing named.
    let out = sandbox.run(&["keys", "revoke", "--release", "release.json"]);
    assert_eq!(code(&out), 1, "{}", stderr(&out));
    assert!(stderr(&out).contains("--serial"), "{}", stderr(&out));

    // Two of the three named.
    let out = sandbox.run(&[
        "keys",
        "revoke",
        "--release",
        "release.json",
        "--serial",
        "0A0B",
        "--host",
        "box",
    ]);
    assert_eq!(code(&out), 1, "{}", stderr(&out));
    assert!(
        stderr(&out).contains("Exactly one of the three"),
        "{}",
        stderr(&out)
    );

    // A host this repository has issued nothing for: the sentence names the
    // other way in (a serial off a receipt), because the machine may be gone.
    let out = sandbox.run(&[
        "keys",
        "revoke",
        "--release",
        "release.json",
        "--host",
        "box",
    ]);
    assert_eq!(code(&out), 1, "{}", stderr(&out));
    assert!(stderr(&out).contains("report --run"), "{}", stderr(&out));

    // A host that is not in the fleet at all.
    let out = sandbox.run(&[
        "keys",
        "revoke",
        "--release",
        "release.json",
        "--host",
        "nobody",
    ]);
    assert_eq!(code(&out), 1, "{}", stderr(&out));
    assert!(stderr(&out).contains("nobody"), "{}", stderr(&out));

    assert!(
        !sandbox.calls().iter().any(|l| l.starts_with("meister-ca")),
        "the CA was called by a refusal: {:?}",
        sandbox.calls()
    );
}

/// `--dry-run` prints the two commands and runs neither.
#[test]
fn a_dry_run_shows_the_ca_the_commands_it_would_get() {
    let sandbox = Sandbox::new();
    let release = support::release_of(sandbox.fleet.clone());
    std::fs::write(
        sandbox.cwd.path().join("release.json"),
        release.to_json().unwrap(),
    )
    .unwrap();
    let out = sandbox.run(&[
        "keys",
        "revoke",
        "--release",
        "release.json",
        "--serial",
        "64:35:c9:c4",
        "--reason",
        "keyCompromise",
        "--dry-run",
    ]);
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    let said = String::from_utf8_lossy(&out.stdout).to_string();
    assert!(said.contains("--index-rebuild"), "{said}");
    assert!(said.contains("--revoke"), "{said}");
    assert!(said.contains("64:35:c9:c4"), "{said}");
    assert!(said.contains("--gencrl"), "{said}");
    assert!(
        sandbox.calls().is_empty(),
        "a dry run ran something: {:?}",
        sandbox.calls()
    );
    assert!(
        !sandbox.cwd.path().join("pki/crl.pem").exists(),
        "a dry run wrote the list"
    );
}

/// V24, the half that is an ORDER: a machine that was reinstalled asks for a
/// certificate under the name its predecessor still holds one for. The old
/// one has to be taken back first, or the fleet would accept either.
#[test]
fn a_second_certificate_for_one_name_needs_the_first_one_taken_back() {
    let sandbox = Sandbox::new();
    sandbox.enrolled(true);
    // A real request, so that the signature check has something true to
    // check.
    let made = pki::generate_key_and_csr("system:node:n1").unwrap();
    std::fs::create_dir_all(sandbox.path("pki/csr")).unwrap();
    std::fs::write(sandbox.path("pki/csr/n1-identity.csr"), &made.csr_pem).unwrap();
    let out = sandbox.run(&[
        "keys",
        "issue",
        "--host",
        "n1",
        "--kind",
        "node",
        "--manifest",
        "manifest.json",
        "--inventory",
        "fleet.toml",
    ]);
    assert_eq!(code(&out), 0, "{}", stderr(&out));

    // And now the machine was reinstalled: a new key, a new request, and a
    // certificate this repository will not sign until the old one is gone.
    let out = sandbox.run(&[
        "keys",
        "issue",
        "--host",
        "n1",
        "--kind",
        "node",
        "--manifest",
        "manifest.json",
        "--inventory",
        "fleet.toml",
    ]);
    assert_eq!(code(&out), 1, "{}", stderr(&out));
    let said = stderr(&out);
    assert!(said.contains("keys revoke --host n1"), "{said}");
    assert!(said.contains("0A0B"), "the serial of the old one: {said}");
    assert!(
        said.contains("no revocation list"),
        "it says which of the two reasons it is: {said}"
    );
}

// --- lane 5B: retiring a host ------------------------------------------------

/// A fleet of one host, so that `retire` has nobody left to hand the list to
/// and the test is about the operator's side alone.
fn one_host_release(sandbox: &Sandbox, keep: &str) -> PathBuf {
    let mut fleet = sandbox.fleet.clone();
    fleet.hosts.retain(|id, _| id == keep);
    fleet.evaluated_hosts.retain(|id| id == keep);
    fleet.groups.clear();
    // The id is over the content, so a fleet that was cut down has a new
    // one; a manifest whose id does not hash to itself is one `validate`
    // refuses, and rightly.
    fleet.manifest_id =
        meister_deploy::ids::content_id(meister_deploy::ids::IdKind::Manifest, &fleet)
            .expect("a manifest hashes");
    let release = support::release_of(fleet);
    let path = sandbox.path("release-one.json");
    std::fs::write(&path, release.to_json().unwrap()).unwrap();
    path
}

/// `--dry-run` says what would be taken back and takes nothing back.
#[test]
fn a_retirement_dry_run_touches_neither_the_ca_nor_the_repository() {
    let sandbox = Sandbox::new();
    one_host_release(&sandbox, "box");
    std::fs::create_dir_all(sandbox.path("pki/issued/box")).unwrap();
    std::fs::write(sandbox.path("pki/issued/box/identity.crt"), "x").unwrap();

    let out = sandbox.run(&[
        "retire",
        "box",
        "--release",
        "release-one.json",
        "--inventory",
        "fleet.toml",
        "--reason",
        "decommissioned",
        "--dry-run",
    ]);
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    let said = String::from_utf8_lossy(&out.stdout).to_string();
    assert!(said.contains("--revoke"), "{said}");
    assert!(said.contains("--gencrl"), "{said}");
    assert!(
        !sandbox.path(".meister-deploy/retired/box.json").exists(),
        "a dry run wrote the record"
    );
    assert!(
        !sandbox.calls().iter().any(|l| l.starts_with("meister-ca")),
        "a dry run called the CA: {:?}",
        sandbox.calls()
    );
}

/// The whole of what a retirement leaves behind, and what it leaves alone.
#[test]
fn retiring_takes_the_certificates_back_and_marks_the_line_without_removing_it() {
    let sandbox = Sandbox::new();
    one_host_release(&sandbox, "box");
    std::fs::create_dir_all(sandbox.path("pki/issued/box")).unwrap();
    std::fs::write(sandbox.path("pki/issued/box/identity.crt"), "x").unwrap();
    // What the CA writes when it is asked for a list.
    std::fs::write(
        sandbox.ca.path().join("crl.pem"),
        "-----BEGIN X509 CRL-----\n",
    )
    .unwrap();
    // And the entry a real fleet has for the machine.
    let address = &sandbox.fleet.hosts["box"].address;
    std::fs::write(
        sandbox.path("known_hosts"),
        format!("{address} ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIexample\n"),
    )
    .unwrap();

    let out = sandbox.run(&[
        "retire",
        "box",
        "--release",
        "release-one.json",
        "--inventory",
        "fleet.toml",
        "--reason",
        "decommissioned",
    ]);
    assert_eq!(code(&out), 0, "{}", stderr(&out));

    // The CA was asked for both halves, in that order.
    let ca: Vec<String> = sandbox
        .calls()
        .into_iter()
        .filter(|l| l.starts_with("meister-ca"))
        .collect();
    assert!(
        ca.iter().any(|l| l.contains("--revoke")),
        "the certificate was not taken back: {ca:?}"
    );
    assert!(
        ca.iter().any(|l| l.contains("--gencrl")),
        "no list was written: {ca:?}"
    );
    // And the list is in the repository, where the delivery reads it from.
    assert!(sandbox.path("pki/crl.pem").exists(), "{ca:?}");

    // The record says what happened, with the serial the CA's own answer
    // named.
    let record = std::fs::read_to_string(sandbox.path(".meister-deploy/retired/box.json")).unwrap();
    assert!(record.contains("\"host\": \"box\""), "{record}");
    assert!(record.contains("decommissioned"), "{record}");
    assert!(record.contains("0A0B"), "{record}");

    // The `known_hosts` line is still there, with the reason above it. A
    // deleted line would let the next machine on that address be enrolled
    // without anybody seeing that there had been one.
    let known = sandbox.known_hosts();
    assert!(known.contains(address.as_str()), "{known}");
    assert!(known.contains("# retired "), "{known}");
    assert!(known.contains("decommissioned"), "{known}");

    // And the certificate file itself is untouched: `retire` takes a
    // certificate back, it does not delete anybody's files.
    assert!(sandbox.path("pki/issued/box/identity.crt").exists());
    assert!(
        stderr(&out).contains("nothing on box was changed or deleted"),
        "{}",
        stderr(&out)
    );
}

/// Running it twice adds one marker, not two.
#[test]
fn retiring_twice_does_not_fill_known_hosts_with_comments() {
    let sandbox = Sandbox::new();
    one_host_release(&sandbox, "box");
    std::fs::write(sandbox.ca.path().join("crl.pem"), "x\n").unwrap();
    let address = &sandbox.fleet.hosts["box"].address;
    std::fs::write(
        sandbox.path("known_hosts"),
        format!("{address} ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIexample\n"),
    )
    .unwrap();
    for _ in 0..2 {
        let out = sandbox.run(&[
            "retire",
            "box",
            "--release",
            "release-one.json",
            "--inventory",
            "fleet.toml",
        ]);
        assert_eq!(code(&out), 0, "{}", stderr(&out));
    }
    let known = sandbox.known_hosts();
    assert_eq!(known.matches("# retired ").count(), 1, "{known}");
}

/// A host this release does not have is named, and nothing is written.
#[test]
fn retiring_a_host_the_release_does_not_have_is_a_sentence() {
    let sandbox = Sandbox::new();
    one_host_release(&sandbox, "box");
    let out = sandbox.run(&[
        "retire",
        "nobody",
        "--release",
        "release-one.json",
        "--inventory",
        "fleet.toml",
    ]);
    assert_eq!(code(&out), 1, "{}", stderr(&out));
    assert!(stderr(&out).contains("nobody"), "{}", stderr(&out));
    assert!(
        sandbox.calls().is_empty(),
        "a refusal ran something: {:?}",
        sandbox.calls()
    );
}

/// Astra finding F11, 2026-09-23: a directory `retire` cannot even list used
/// to look exactly like a host with no certificates -- the CA was never
/// asked, no record was written, and the run still exited 0. It has to
/// refuse instead.
#[test]
fn retiring_refuses_rather_than_pretend_an_unreadable_directory_is_empty() {
    use std::os::unix::fs::PermissionsExt;

    // Root ignores a directory's own permission bits, so this test cannot
    // say anything under it.
    if std::env::var("USER").as_deref() == Ok("root") {
        eprintln!("skipping: running as root, a chmod 000 directory stays readable");
        return;
    }

    let sandbox = Sandbox::new();
    one_host_release(&sandbox, "box");
    let dir = sandbox.path("pki/issued/box");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("identity.crt"), "x").unwrap();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o000)).unwrap();

    let out = sandbox.run(&[
        "retire",
        "box",
        "--release",
        "release-one.json",
        "--inventory",
        "fleet.toml",
        "--reason",
        "decommissioned",
    ]);

    // Restored before any assertion can early-return and leave an
    // unreadable directory behind for the sandbox's own cleanup.
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();

    assert_ne!(code(&out), 0, "{}", stderr(&out));
    assert!(
        sandbox.calls().is_empty(),
        "the CA was asked despite the listing failure: {:?}",
        sandbox.calls()
    );
    assert!(
        !sandbox.path(".meister-deploy/retired/box.json").exists(),
        "a run that could not even list the certificates wrote a retirement record"
    );
}
