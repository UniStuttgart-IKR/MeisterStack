// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! `verify`, through the real binary, with `PATH` holding nothing but shims.
//!
//! The unit tests of `src/verify.rs` pin what the driver does with a strict
//! fake. What they cannot pin is the verb: the approval, the refusals, the
//! exit codes, and the fact that a `--dry-run` writes nothing at all. Those
//! are properties of the PROGRAM, so they are measured by running it.
//!
//! The `meister` shim is the operator's own cli, and it answers from files
//! the test lays out per verb — which is also how a guest is made to look
//! like it took, like it never booted, or like it refuses to go away.

mod support;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use meister_deploy::manifest::ResolvedFleet;
use meister_deploy::release::ReleaseManifest;
use meister_deploy::verify::{Ledger, ResourceState, VerifyRun};

use support::{observed, onebox, probe_answer, release_of, with_guest_tiny};

const BIN: &str = env!("CARGO_BIN_EXE_meister-deploy");

/// Every program this verb is allowed to know about. `meister` is the
/// operator's own cli, which is how a guest is asked for (D7); `ssh` and
/// `ssh-keygen` are the read-only round trip that says what the machines
/// are.
const SHIMS: [&str; 5] = ["nix", "git", "ssh", "ssh-keygen", "meister"];

const STORE: &str = "/nix/store/gggggggggggggggggggggggggggggggg-guest-tiny";
const ENROLLED_KEY: &str = "AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
const ENROLLED_FINGERPRINT: &str = "SHA256:kmYcvdi2GkPeWxB6XLjrZB8JHsy2Hm8luHMFp9GMvqk";

struct Sandbox {
    cwd: tempfile::TempDir,
    shims: tempfile::TempDir,
    answers: tempfile::TempDir,
    /// What the `meister` shim answers, keyed by the verb pair it saw
    /// (`vm create`, `vm get`, `vm logs`, `vm rm`, `vm ls`).
    cli: tempfile::TempDir,
    home: tempfile::TempDir,
    log: PathBuf,
    fleet: ResolvedFleet,
    release: ReleaseManifest,
}

impl Sandbox {
    fn new() -> Sandbox {
        use std::os::unix::fs::PermissionsExt;
        let shims = tempfile::tempdir().unwrap();
        let answers = tempfile::tempdir().unwrap();
        let cli = tempfile::tempdir().unwrap();
        let cwd = tempfile::tempdir().unwrap();
        let home = tempfile::tempdir().unwrap();
        let log = shims.path().join("calls.log");

        for name in SHIMS {
            let body = match name {
                "ssh-keygen" => format!(
                    "#!/bin/sh\nline=\"{name}\"\n\
                     for a in \"$@\"; do line=\"$line [$a]\"; done\n\
                     printf '%s\\n' \"$line\" >> \"$MEISTER_SHIM_LOG\"\n\
                     printf '# Host found: line 1\\n10.0.0.10 ssh-ed25519 {ENROLLED_KEY}\\n'\n\
                     exit 0\n"
                ),
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
                // The operator's cli, as a very small control plane: it
                // remembers the guests it was told to create, forgets the
                // ones it was told to remove, and lists what is left. A
                // canned answer per verb could not tell "the delete took"
                // from "the delete was refused", and that difference is
                // most of what this suite is about.
                //
                // Only shell builtins in the body: `PATH` holds this
                // directory and nothing else while the binary runs, so
                // there is no `cat`, no `sed` and no `grep` to reach for.
                //
                // The noun and the verb after it — `vm create`, `vm ls` —
                // and not "the first two arguments that are not options":
                // `--config cli.toml` has a value that looks exactly like a
                // noun, which is a shim that answers the wrong file and a
                // test that is green for the wrong reason.
                "meister" => format!(
                    "#!/bin/sh\nline=\"{name}\"\n\
                     for a in \"$@\"; do line=\"$line [$a]\"; done\n\
                     printf '%s\\n' \"$line\" >> \"$MEISTER_SHIM_LOG\"\n\
                     noun=; verb=; vmname=; want=0\n\
                     for a in \"$@\"; do\n\
                       if [ \"$want\" = 1 ]; then verb=\"$a\"; want=2; continue; fi\n\
                       if [ \"$want\" = 2 ]; then\n\
                         case \"$a\" in -*) : ;; *) vmname=\"$a\"; want=3;; esac\n\
                         continue\n\
                       fi\n\
                       case \"$a\" in vm|node|agent) noun=\"$a\"; want=1;; esac\n\
                     done\n\
                     state=\"$MEISTER_SHIM_CLI/state\"\n\
                     f=\"$MEISTER_SHIM_CLI/$noun-$verb\"\n\
                     code=0\n\
                     if [ -f \"$f.exit\" ]; then read -r code < \"$f.exit\"; fi\n\
                     if [ \"$noun-$verb\" = vm-ls ]; then\n\
                       items=\n\
                       if [ -f \"$state\" ]; then\n\
                         while IFS= read -r l; do\n\
                           [ -z \"$l\" ] && continue\n\
                           items=\"$items{{\\\"metadata\\\":{{\\\"name\\\":\\\"$l\\\"}}}},\"\n\
                         done < \"$state\"\n\
                       fi\n\
                       printf '{{\"items\":[%s]}}\\n' \"${{items%,}}\"\n\
                       exit \"$code\"\n\
                     fi\n\
                     if [ \"$noun-$verb\" = vm-create ] && [ \"$code\" = 0 ]; then\n\
                       printf '%s\\n' \"$vmname\" >> \"$state\"\n\
                     fi\n\
                     if [ \"$noun-$verb\" = vm-rm ] && [ \"$code\" = 0 ]; then\n\
                       keep=\n\
                       if [ -f \"$state\" ]; then\n\
                         while IFS= read -r l; do\n\
                           [ \"$l\" = \"$vmname\" ] && continue\n\
                           keep=\"$keep$l\n\"\n\
                         done < \"$state\"\n\
                       fi\n\
                       printf '%s' \"$keep\" > \"$state\"\n\
                     fi\n\
                     if [ -f \"$f\" ]; then\n\
                       while IFS= read -r l; do\n\
                         case \"$l\" in\n\
                           *@NAME@*) printf '%s%s%s\\n' \"${{l%%@NAME@*}}\" \"$vmname\" \"${{l#*@NAME@}}\";;\n\
                           *) printf '%s\\n' \"$l\";;\n\
                         esac\n\
                       done < \"$f\"\n\
                     elif [ \"$code\" = 0 ]; then\n\
                       exit 97\n\
                     fi\n\
                     exit \"$code\"\n"
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

        let mut fleet = onebox();
        for host in fleet.hosts.values_mut() {
            host.ssh.host_key_fingerprint = Some(ENROLLED_FINGERPRINT.to_string());
        }
        fleet.manifest_id =
            meister_deploy::ids::content_id(meister_deploy::ids::IdKind::Manifest, &fleet).unwrap();
        let release = with_guest_tiny(release_of(fleet.clone()), STORE);

        std::fs::write(cwd.path().join("release.json"), release.to_json().unwrap()).unwrap();
        std::fs::write(
            cwd.path().join("fleet.toml"),
            include_str!("fixtures/fleet-v2.toml"),
        )
        .unwrap();

        let sandbox = Sandbox {
            cwd,
            shims,
            answers,
            cli,
            home,
            log,
            fleet,
            release,
        };
        for id in sandbox.fleet.hosts.keys() {
            sandbox.answer(id, &probe_answer(&sandbox.fleet, &sandbox.release, id));
        }
        sandbox
    }

    fn answer(&self, id: &str, text: &str) {
        let address = &self.fleet.hosts[id].address;
        std::fs::write(self.answers.path().join(address), text).unwrap();
    }

    /// What `meister <noun> <verb> …` prints. `@NAME@` becomes the guest's
    /// name.
    ///
    /// With a trailing newline, always: the shim reads its templates with
    /// `while read`, which drops a last line that has none — and a template
    /// that produced nothing looked exactly like a control plane that
    /// answered nothing, which is a two-minute wait per guest rather than a
    /// failure. Measured.
    fn cli_says(&self, pair: &str, text: &str) {
        std::fs::write(self.cli.path().join(pair), format!("{text}\n")).unwrap();
    }

    /// What it exits with.
    fn cli_exits(&self, pair: &str, code: i32) {
        std::fs::write(
            self.cli.path().join(format!("{pair}.exit")),
            code.to_string(),
        )
        .unwrap();
    }

    fn run(&self, args: &[&str]) -> Output {
        Command::new(BIN)
            .args(args)
            .current_dir(self.cwd.path())
            .env("PATH", self.shims.path())
            .env("MEISTER_SHIM_LOG", &self.log)
            .env("MEISTER_SHIM_ANSWERS", self.answers.path())
            .env("MEISTER_SHIM_CLI", self.cli.path())
            .env("HOME", self.home.path())
            .output()
            .expect("the binary was just built")
    }

    fn calls(&self) -> Vec<String> {
        let Ok(text) = std::fs::read_to_string(&self.log) else {
            return Vec::new();
        };
        let mut out: Vec<String> = Vec::new();
        for line in text.lines() {
            let starts = SHIMS
                .iter()
                .any(|shim| line == *shim || line.starts_with(&format!("{shim} ")));
            if starts {
                out.push(line.to_string());
            } else if let Some(last) = out.last_mut() {
                last.push(' ');
                last.push_str(line);
            }
        }
        out
    }

    fn state(&self) -> PathBuf {
        self.cwd.path().join(".meister-deploy")
    }

    fn ledger_of(&self, run: &str) -> Ledger {
        let path = self.state().join("runs").join(run).join("ledger.json");
        let text = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("{} could not be read: {e}", path.display()));
        Ledger::from_json(&text, "the ledger").expect("the ledger reads back")
    }

    fn verification_of(&self, run: &str) -> VerifyRun {
        let path = self.state().join("runs").join(run).join("verify.json");
        let text = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("{} could not be read: {e}", path.display()));
        VerifyRun::from_json(&text, "the verification").expect("it reads back")
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

/// The run id, which `verify` prints on its own line before anything else.
fn run_id(out: &Output) -> String {
    stdout(out)
        .lines()
        .next()
        .expect("verify prints its run id first")
        .trim()
        .to_string()
}

/// A control plane that behaves: a guest is created on n1, comes up
/// Running, printed the marker, and is gone once it is deleted.
fn a_working_control_plane(sandbox: &Sandbox) {
    sandbox.cli_says(
        "vm-create",
        r#"{"kind":"Vm","metadata":{"name":"@NAME@","uid":"uid-@NAME@"},"spec":{"nodeName":"n1"},"status":{"phase":"Pending"}}"#,
    );
    sandbox.cli_says(
        "vm-get",
        r#"{"metadata":{"name":"@NAME@","uid":"uid-@NAME@"},"spec":{"nodeName":"n1"},"status":{"phase":"Running"}}"#,
    );
    sandbox.cli_says(
        "vm-logs",
        r#"[{"stream":"console","text":"MS-S0-TINY-OK\nMS-S0-DONE"}]"#,
    );
    // A delete says nothing and exits 0; what it did is read back out of
    // the listing, never out of this.
    sandbox.cli_says("vm-rm", "");
}

// ---------------------------------------------------------------------------

#[test]
fn a_dry_run_lists_every_step_and_writes_nothing_at_all() {
    let sandbox = Sandbox::new();
    let before = snapshot_of(sandbox.cwd.path());
    let out = sandbox.run(&[
        "verify",
        "--release",
        "release.json",
        "--suite",
        "vm-lifecycle",
        "--repo",
        ".",
        "--inventory",
        "fleet.toml",
        "--budget",
        "2",
        "--dry-run",
    ]);
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    assert_eq!(
        before,
        snapshot_of(sandbox.cwd.path()),
        "a dry run left something behind"
    );
    assert!(
        !sandbox.state().exists(),
        "a dry run made a state directory"
    );
    // Three agent hosts, three guests each: one alone and then the budget.
    let listed = stdout(&out);
    assert_eq!(listed.lines().count(), 9, "{listed}");
    assert!(listed.contains("MS-S0-TINY-OK"), "{listed}");
    // It looked, and only with the two read-only programs.
    for call in sandbox.calls() {
        assert!(
            call.starts_with("ssh-keygen") || call.starts_with("ssh "),
            "a dry run ran {call}"
        );
    }
}

#[test]
fn without_an_approval_nothing_is_created_and_the_sentence_names_the_release() {
    let sandbox = Sandbox::new();
    let out = sandbox.run(&[
        "verify",
        "--release",
        "release.json",
        "--suite",
        "vm-lifecycle",
        "--repo",
        ".",
        "--host",
        "n1",
    ]);
    assert_eq!(code(&out), 1, "{}", stderr(&out));
    assert!(
        stderr(&out).contains(&format!("--approve verify={}", sandbox.release.release_id)),
        "{}",
        stderr(&out)
    );
    assert!(sandbox.calls().is_empty(), "{:?}", sandbox.calls());
    assert!(!sandbox.state().exists());
}

#[test]
fn an_approval_for_another_release_is_refused_by_name() {
    let sandbox = Sandbox::new();
    let out = sandbox.run(&[
        "verify",
        "--release",
        "release.json",
        "--suite",
        "vm-lifecycle",
        "--repo",
        ".",
        "--host",
        "n1",
        "--approve",
        "verify=release-somebody-elses",
    ]);
    assert_eq!(code(&out), 1, "{}", stderr(&out));
    assert!(
        stderr(&out).contains("release-somebody-elses"),
        "{}",
        stderr(&out)
    );
    assert!(
        stderr(&out).contains(&sandbox.release.release_id),
        "{}",
        stderr(&out)
    );
}

#[test]
fn an_approval_of_a_class_this_verb_does_not_have_is_a_sentence() {
    let sandbox = Sandbox::new();
    let out = sandbox.run(&[
        "verify",
        "--release",
        "release.json",
        "--suite",
        "vm-lifecycle",
        "--repo",
        ".",
        "--approve",
        "destructive=release-x",
    ]);
    assert_eq!(code(&out), 1, "{}", stderr(&out));
    assert!(stderr(&out).contains("destructive"), "{}", stderr(&out));
    assert!(
        stderr(&out).contains("--approve verify=<release_id>"),
        "{}",
        stderr(&out)
    );
}

#[test]
fn offline_is_refused_because_a_verification_is_work_on_the_fleet() {
    let sandbox = Sandbox::new();
    let out = sandbox.run(&[
        "verify",
        "--release",
        "release.json",
        "--suite",
        "vm-lifecycle",
        "--offline",
    ]);
    assert_eq!(code(&out), 1, "{}", stderr(&out));
    assert!(
        stderr(&out).contains("check --suite readiness"),
        "{}",
        stderr(&out)
    );
    assert!(sandbox.calls().is_empty(), "{:?}", sandbox.calls());
}

#[test]
fn a_suite_nobody_has_is_a_sentence_and_not_an_empty_run() {
    let sandbox = Sandbox::new();
    let out = sandbox.run(&[
        "verify",
        "--release",
        "release.json",
        "--suite",
        "vm-lifecyle",
        "--dry-run",
    ]);
    assert_eq!(code(&out), 1, "{}", stderr(&out));
    assert!(stderr(&out).contains("vm-lifecycle"), "{}", stderr(&out));
}

#[test]
fn one_host_three_guests_and_an_empty_ledger_at_the_end() {
    let sandbox = Sandbox::new();
    a_working_control_plane(&sandbox);
    let out = sandbox.run(&[
        "verify",
        "--release",
        "release.json",
        "--suite",
        "vm-lifecycle",
        "--repo",
        ".",
        "--inventory",
        "fleet.toml",
        "--host",
        "n1",
        "--budget",
        "2",
        "--approve",
        &format!("verify={}", sandbox.release.release_id),
    ]);
    assert_eq!(code(&out), 0, "{}\n{}", stdout(&out), stderr(&out));
    let run = run_id(&out);

    let ledger = sandbox.ledger_of(&run);
    assert_eq!(ledger.tag, format!("meister-verify-{run}"));
    assert_eq!(ledger.resources.len(), 3, "{:?}", ledger.resources);
    assert!(
        ledger
            .resources
            .iter()
            .all(|r| r.state == ResourceState::Deleted),
        "the run went out holding something: {:?}",
        ledger.resources
    );
    assert!(
        ledger.resources.iter().all(|r| r.host == "n1"),
        "the ledger did not read the placement back: {:?}",
        ledger.resources
    );

    let verification = sandbox.verification_of(&run);
    assert_eq!(
        verification.outcome,
        meister_deploy::receipt::Outcome::Success
    );
    // Four checks per guest and one verdict for the host.
    assert_eq!(verification.checks.len(), 3 * 4 + 1);
    let (hardware, _) = verification.hardware_evidence();
    assert!(
        !hardware.is_empty(),
        "n1 has kvm in the snapshot, so a guest that ran there is hardware evidence"
    );

    // Every guest went through the cli, and nothing else did.
    let creates = sandbox
        .calls()
        .iter()
        .filter(|c| c.contains("[vm] [create]"))
        .count();
    assert_eq!(creates, 3);
    assert!(
        sandbox
            .calls()
            .iter()
            .filter(|c| c.starts_with("meister "))
            .all(|c| c.contains("[--config] [cli.toml]") && c.contains("[-p] [cloud-mtls]")),
        "a call went out without the operator's own configuration: {:?}",
        sandbox.calls()
    );
}

#[test]
fn a_guest_that_never_printed_the_marker_fails_and_is_still_deleted() {
    let sandbox = Sandbox::new();
    a_working_control_plane(&sandbox);
    // The object is Running and the guest never booted: exactly the gap
    // `check --suite readiness` cannot see.
    sandbox.cli_says("vm-logs", r#"[{"stream":"console","text":"nothing"}]"#);

    let out = sandbox.run(&[
        "verify",
        "--release",
        "release.json",
        "--suite",
        "vm-lifecycle",
        "--repo",
        ".",
        "--inventory",
        "fleet.toml",
        "--host",
        "box",
        "--budget",
        "1",
        "--approve",
        &format!("verify={}", sandbox.release.release_id),
    ]);
    // `box` is the fixture's host whose `checks.functional` names
    // vm-lifecycle, so its verdict is a required one and exit 2 is blocked.
    assert_eq!(code(&out), 2, "{}\n{}", stdout(&out), stderr(&out));
    assert!(
        stderr(&out).contains("vm-lifecycle on box"),
        "{}",
        stderr(&out)
    );
    let run = run_id(&out);
    assert!(
        sandbox
            .ledger_of(&run)
            .resources
            .iter()
            .all(|r| r.state == ResourceState::Deleted),
        "a failing suite kept its guests"
    );
}

#[test]
fn a_guest_that_will_not_go_away_is_lost_and_named() {
    let sandbox = Sandbox::new();
    a_working_control_plane(&sandbox);
    // The delete is refused, so the shim keeps the guest in its listing —
    // which is the only way the tool can tell "it went" from "it was told
    // to go and did not".
    sandbox.cli_exits("vm-rm", 1);

    let out = sandbox.run(&[
        "verify",
        "--release",
        "release.json",
        "--suite",
        "vm-lifecycle",
        "--repo",
        ".",
        "--inventory",
        "fleet.toml",
        "--host",
        "n1",
        "--budget",
        "1",
        "--deadline",
        "6",
        "--settle",
        "2",
        "--poll",
        "1",
        "--approve",
        &format!("verify={}", sandbox.release.release_id),
    ]);
    assert_eq!(code(&out), 2, "{}\n{}", stdout(&out), stderr(&out));
    let run = run_id(&out);
    let ledger = sandbox.ledger_of(&run);
    // The `vm ls` answers with somebody else's guest and never with ours,
    // so the delete is honest about not having taken: the name has to stay
    // in the ledger as lost.
    assert!(
        ledger
            .resources
            .iter()
            .any(|r| r.state == ResourceState::Lost),
        "{:?}",
        ledger.resources
    );
    let verification = sandbox.verification_of(&run);
    assert!(
        verification
            .checks
            .iter()
            .any(|c| c.id == "verify.leftovers"),
        "a run that left something behind said nothing about it"
    );
    assert!(stdout(&out).contains("NOT deleted"), "{}", stdout(&out));
}

#[test]
fn a_host_that_does_not_answer_is_skipped_and_no_guest_is_asked_for() {
    let sandbox = Sandbox::new();
    a_working_control_plane(&sandbox);
    // No file for this address: the ssh shim exits 255, which is a host
    // that did not answer.
    std::fs::remove_file(
        sandbox
            .answers
            .path()
            .join(&sandbox.fleet.hosts["box"].address),
    )
    .unwrap();

    let out = sandbox.run(&[
        "verify",
        "--release",
        "release.json",
        "--suite",
        "vm-lifecycle",
        "--repo",
        ".",
        "--inventory",
        "fleet.toml",
        "--host",
        "box",
        "--approve",
        &format!("verify={}", sandbox.release.release_id),
    ]);
    assert_eq!(code(&out), 2, "{}\n{}", stdout(&out), stderr(&out));
    assert!(
        stderr(&out).contains("vm-lifecycle on box is skipped"),
        "{}",
        stderr(&out)
    );
    assert!(
        !sandbox.calls().iter().any(|c| c.contains("[vm] [create]")),
        "a guest was asked for on a host nobody could reach: {:?}",
        sandbox.calls()
    );
}

#[test]
fn the_gpu_suite_over_a_fleet_without_gpus_is_not_applicable_and_passes() {
    let sandbox = Sandbox::new();
    let out = sandbox.run(&[
        "verify",
        "--release",
        "release.json",
        "--suite",
        "gpu",
        "--repo",
        ".",
        "--inventory",
        "fleet.toml",
        "--approve",
        &format!("verify={}", sandbox.release.release_id),
    ]);
    assert_eq!(code(&out), 0, "{}\n{}", stdout(&out), stderr(&out));
    let verification = sandbox.verification_of(&run_id(&out));
    assert!(
        verification
            .checks
            .iter()
            .all(|c| c.status == meister_deploy::checks::Status::NotApplicable),
        "{:?}",
        verification.checks
    );
    let (hardware, _) = verification.hardware_evidence();
    assert!(
        hardware.is_empty(),
        "a suite that ran nothing produced hardware evidence"
    );
    assert!(
        !sandbox.calls().iter().any(|c| c.starts_with("meister ")),
        "a not-applicable suite asked the control plane for something: {:?}",
        sandbox.calls()
    );
}

#[test]
fn a_snapshot_from_disk_is_used_and_no_host_is_asked_anything() {
    let sandbox = Sandbox::new();
    a_working_control_plane(&sandbox);
    let snapshot = observed(&sandbox.release, chrono::Utc::now());
    std::fs::write(
        sandbox.cwd.path().join("snapshot.json"),
        snapshot.to_json().unwrap(),
    )
    .unwrap();

    let out = sandbox.run(&[
        "verify",
        "--release",
        "release.json",
        "--suite",
        "vm-lifecycle",
        "--repo",
        ".",
        "--inventory",
        "fleet.toml",
        "--observation",
        "snapshot.json",
        "--host",
        "n1",
        "--budget",
        "1",
        "--approve",
        &format!("verify={}", sandbox.release.release_id),
    ]);
    assert_eq!(code(&out), 0, "{}\n{}", stdout(&out), stderr(&out));
    assert!(stderr(&out).contains("a fleet moves"), "{}", stderr(&out));
    assert!(
        !sandbox.calls().iter().any(|c| c.starts_with("ssh ")),
        "a snapshot was given and a host was asked anyway: {:?}",
        sandbox.calls()
    );
}

#[test]
fn the_contracts_this_verb_writes_have_a_schema_anybody_can_read() {
    let sandbox = Sandbox::new();
    for kind in ["verify", "verify-ledger"] {
        let out = sandbox.run(&["schema", kind]);
        assert_eq!(code(&out), 0, "{}", stderr(&out));
        let schema: serde_json::Value = serde_json::from_str(&stdout(&out)).unwrap();
        assert!(schema.get("properties").is_some(), "{kind}: {schema}");
    }
}

// ---------------------------------------------------------------------------
// `report --run <id>` over a verification
// ---------------------------------------------------------------------------

/// A verification written by hand into the state directory, so that what
/// `report` does with one is measured against bytes a test controls rather
/// than against whatever a run happened to produce.
fn a_verification(sandbox: &Sandbox, run: &str, checks: serde_json::Value) {
    let dir = sandbox.state().join("runs").join(run);
    std::fs::create_dir_all(&dir).unwrap();
    let document = serde_json::json!({
        "schema": "meister-deploy/verify/1",
        "run_id": run,
        "release_id": sandbox.release.release_id,
        "manifest_id": sandbox.release.resolved_fleet.manifest_id,
        "suite": "gpu",
        "started_at": "2026-09-22T19:00:00Z",
        "ended_at": "2026-09-22T19:05:00Z",
        "outcome": "success",
        "hosts": ["n1"],
        "checks": checks,
        "ledger": {
            "schema": "meister-deploy/verify-ledger/1",
            "run_id": run,
            "release_id": sandbox.release.release_id,
            "suite": "gpu",
            "tag": format!("meister-verify-{run}"),
            "started_at": "2026-09-22T19:00:00Z",
            "resources": [],
        },
        "ledger_path": dir.join("ledger.json").display().to_string(),
    });
    std::fs::write(
        dir.join("verify.json"),
        serde_json::to_vec_pretty(&document).unwrap(),
    )
    .unwrap();
}

fn check(id: &str, status: &str, kind: &str, required: bool) -> serde_json::Value {
    serde_json::json!({
        "id": id,
        "subject": { "host": "n1", "resource": null },
        "required": required,
        "status": status,
        "expected": "a device in the guest",
        "observed": "what was found",
        "reason": "a sentence",
        "duration_ms": 12,
        "evidence": [{ "kind": kind, "ref": "vm g on node n1" }],
        "release_id": null,
        "config_id": null,
    })
}

#[test]
fn a_run_whose_evidence_is_a_mock_is_not_printed_as_a_hardware_proof() {
    let sandbox = Sandbox::new();
    let run = "0192f0c0-0000-7000-8000-00000000mock";
    a_verification(
        &sandbox,
        run,
        serde_json::json!([
            check("gpu.create", "pass", "mock", false),
            check("gpu.in-guest", "pass", "mock", false),
        ]),
    );

    let out = sandbox.run(&["report", "--run", run, "--repo", "."]);
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    let text = stdout(&out);
    let (before, after) = text
        .split_once("--- everything else ---")
        .expect("the two sections are printed apart");
    assert!(before.contains("--- hardware evidence ---"), "{text}");
    assert!(
        before.contains("(none."),
        "a mock was printed under hardware evidence:\n{text}"
    );
    assert!(after.contains("gpu.create"), "{text}");
    assert!(after.contains("gpu.in-guest"), "{text}");
}

#[test]
fn a_run_with_hardware_evidence_prints_it_apart_and_names_it() {
    let sandbox = Sandbox::new();
    let run = "0192f0c0-0000-7000-8000-0000000000hw";
    a_verification(
        &sandbox,
        run,
        serde_json::json!([
            check("gpu.create", "pass", "command", false),
            check("gpu.in-guest", "pass", "hardware", false),
        ]),
    );

    let out = sandbox.run(&["report", "--run", run, "--repo", "."]);
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    let text = stdout(&out);
    let (hardware, other) = text
        .split_once("--- everything else ---")
        .expect("the two sections are printed apart");
    assert!(hardware.contains("gpu.in-guest"), "{text}");
    assert!(hardware.contains("hardware: vm g on node n1"), "{text}");
    assert!(!hardware.contains("gpu.create"), "{text}");
    assert!(other.contains("gpu.create"), "{text}");
}

#[test]
fn a_required_check_that_did_not_pass_makes_the_report_exit_two_and_say_which() {
    let sandbox = Sandbox::new();
    let run = "0192f0c0-0000-7000-8000-000000blocked";
    a_verification(
        &sandbox,
        run,
        serde_json::json!([
            check("gpu.create", "pass", "hardware", true),
            check("gpu.in-guest", "unknown", "hardware", true),
        ]),
    );

    let out = sandbox.run(&["report", "--run", run, "--repo", "."]);
    assert_eq!(code(&out), 2, "{}\n{}", stdout(&out), stderr(&out));
    assert!(
        stderr(&out).contains("gpu.in-guest on n1 is unknown"),
        "{}",
        stderr(&out)
    );
    assert!(stderr(&out).contains("gpu suite"), "{}", stderr(&out));
}

#[test]
fn the_json_report_separates_the_two_kinds_as_well() {
    let sandbox = Sandbox::new();
    let run = "0192f0c0-0000-7000-8000-00000000json";
    a_verification(
        &sandbox,
        run,
        serde_json::json!([
            check("gpu.create", "pass", "mock", false),
            check("gpu.in-guest", "pass", "hardware", false),
        ]),
    );

    let out = sandbox.run(&["report", "--run", run, "--repo", ".", "--json"]);
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    let document: serde_json::Value = serde_json::from_str(&stdout(&out)).unwrap();
    assert_eq!(document["schema"], "meister-deploy/verify-report/1");
    let hardware = document["hardware_evidence"].as_array().unwrap();
    let other = document["other_evidence"].as_array().unwrap();
    assert_eq!(hardware.len(), 1);
    assert_eq!(hardware[0]["id"], "gpu.in-guest");
    assert_eq!(other.len(), 1);
    assert_eq!(other[0]["id"], "gpu.create");
    assert!(document["blocked"].as_array().unwrap().is_empty());
}

#[test]
fn a_verification_and_a_rollout_do_not_get_in_each_others_way() {
    let sandbox = Sandbox::new();
    // A run directory with neither is still the sentence it was.
    let out = sandbox.run(&[
        "report",
        "--run",
        "0192f0c0-0000-7000-8000-00000000none",
        "--repo",
        ".",
    ]);
    assert_eq!(code(&out), 1, "{}", stderr(&out));
    assert!(stderr(&out).contains("holds no run"), "{}", stderr(&out));
}
