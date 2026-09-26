// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Resolve externally provided evaluation output while recording local Git source
//! and the evaluation-file digest. These checks verify parsing and provenance
//! recording; they do not establish that the supplied evaluation came from that tree.
//! Git runs locally in temporary repositories; Nix is replaced by a failing shim.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const BIN: &str = env!("CARGO_BIN_EXE_meister-deploy");

struct Sandbox {
    repo: tempfile::TempDir,
    /// Keep generated manifests outside the repository so output does not dirty
    /// the source tree under inspection.
    out: tempfile::TempDir,
    shims: tempfile::TempDir,
    log: PathBuf,
}

impl Sandbox {
    /// A git repository with an inventory in it, and a PATH on which `nix`
    /// is a shim that refuses and `git` is the real one behind a logger.
    fn new() -> Sandbox {
        use std::os::unix::fs::PermissionsExt;
        let repo = tempfile::tempdir().unwrap();
        let out = tempfile::tempdir().unwrap();
        let shims = tempfile::tempdir().unwrap();
        let log = shims.path().join("calls.log");

        let real_git = which("git");
        for name in ["nix", "ssh", "rsync", "git"] {
            let body = if name == "git" {
                format!(
                    "#!/bin/sh\nline=\"git\"\n\
                     for a in \"$@\"; do line=\"$line [$a]\"; done\n\
                     printf '%s\\n' \"$line\" >> \"$MEISTER_SHIM_LOG\"\n\
                     exec {real_git} \"$@\"\n"
                )
            } else {
                format!(
                    "#!/bin/sh\nline=\"{name}\"\n\
                     for a in \"$@\"; do line=\"$line [$a]\"; done\n\
                     printf '%s\\n' \"$line\" >> \"$MEISTER_SHIM_LOG\"\nexit 97\n"
                )
            };
            let path = shims.path().join(name);
            std::fs::write(&path, body).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        }

        std::fs::write(
            repo.path().join("fleet.toml"),
            include_str!("fixtures/fleet-v2.toml"),
        )
        .unwrap();
        std::fs::write(
            repo.path().join("evaluation.json"),
            include_str!("fixtures/nix-manifest-onebox.json"),
        )
        .unwrap();
        // A manifest says what its inputs were locked to, on both roads: the
        // evaluation may have happened elsewhere, but WHICH nixpkgs it was
        // against is a fact about this repository.
        std::fs::write(
            repo.path().join("flake.lock"),
            "{\"nodes\":{\"root\":{}},\"root\":\"root\",\"version\":7}\n",
        )
        .unwrap();

        let sandbox = Sandbox {
            repo,
            out,
            shims,
            log,
        };
        sandbox.git(&["init", "-q"]);
        sandbox.git(&["add", "-A"]);
        sandbox.git(&[
            "-c",
            "user.name=test",
            "-c",
            "user.email=test@example",
            "commit",
            "-qm",
            "the fleet",
        ]);
        sandbox.forget_calls();
        sandbox
    }

    /// The real git, straight — not through the shim, because the shim's log
    /// is about what the TOOL ran.
    fn git(&self, args: &[&str]) {
        let out = Command::new("git")
            .arg("-C")
            .arg(self.repo.path())
            .args(args)
            .env("HOME", self.repo.path())
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_SYSTEM", "/dev/null")
            .output()
            .expect("git is on the PATH of the test runner");
        assert!(
            out.status.success(),
            "git {args:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    fn run(&self, args: &[&str]) -> Output {
        Command::new(BIN)
            .args(args)
            .current_dir(self.repo.path())
            .env("PATH", self.shims.path())
            .env("MEISTER_SHIM_LOG", &self.log)
            .env("HOME", self.repo.path())
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_SYSTEM", "/dev/null")
            .output()
            .expect("the binary was just built")
    }

    fn calls(&self) -> Vec<String> {
        std::fs::read_to_string(&self.log)
            .map(|text| text.lines().map(str::to_string).collect())
            .unwrap_or_default()
    }

    fn forget_calls(&self) {
        let _ = std::fs::remove_file(&self.log);
    }

    fn path(&self, name: &str) -> PathBuf {
        self.repo.path().join(name)
    }

    /// A path beside the repository, as a string for the command line.
    fn out(&self, name: &str) -> String {
        self.out.path().join(name).display().to_string()
    }

    fn manifest(&self) -> serde_json::Value {
        serde_json::from_str(&std::fs::read_to_string(self.out("m.json")).unwrap()).unwrap()
    }
}

fn which(program: &str) -> String {
    for dir in std::env::var("PATH").unwrap_or_default().split(':') {
        let candidate = Path::new(dir).join(program);
        if candidate.exists() {
            return candidate.display().to_string();
        }
    }
    panic!("{program} is not on the PATH of the test runner");
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

#[test]
fn an_evaluation_that_was_handed_over_is_read_and_nothing_is_evaluated() {
    let sandbox = Sandbox::new();
    let out = sandbox.run(&[
        "resolve",
        "--from",
        "evaluation.json",
        "--repo",
        ".",
        "--out",
        &sandbox.out("m.json"),
    ]);
    assert!(out.status.success(), "{}", stderr(&out));

    // Not one `nix`. The log holds git and nothing else.
    let calls = sandbox.calls();
    assert!(!calls.is_empty(), "the source was not read at all");
    for call in &calls {
        assert!(call.starts_with("git "), "resolve --from ran {call}");
    }

    let manifest = sandbox.manifest();
    let source = &manifest["source"];
    // The fingerprint is this tree's, read here with git.
    assert!(
        source["fingerprint"].as_str().unwrap().starts_with("git:"),
        "{source}"
    );
    assert_eq!(source["dirty"], false);
    // And the manifest says the evaluation was handed over, with the digest
    // of what was handed.
    let provided = &source["provided_evaluation"];
    assert_eq!(provided["origin"], "evaluation.json", "{source}");
    let digest = sha256_of(&std::fs::read(sandbox.path("evaluation.json")).unwrap());
    assert_eq!(provided["sha256"], digest, "{source}");
    // The note says it out loud as well.
    assert!(
        stderr(&out).contains("nothing was evaluated here"),
        "{}",
        stderr(&out)
    );

    // What came out is a manifest this tool reads back.
    sandbox.forget_calls();
    let out = sandbox.run(&["validate", "--manifest", &sandbox.out("m.json")]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(
        stdout(&out).contains("meister-deploy/resolved-fleet/1"),
        "{}",
        stdout(&out)
    );
    assert!(sandbox.calls().is_empty(), "{:?}", sandbox.calls());
}

/// Warn when supplied evaluation and local inventory digests differ.
#[test]
fn an_evaluation_of_another_inventory_is_said_out_loud() {
    let sandbox = Sandbox::new();
    // The fixture's digest is all zeros, which is not the sandbox's fleet.toml.
    let out = sandbox.run(&[
        "resolve",
        "--from",
        "evaluation.json",
        "--repo",
        ".",
        "--out",
        &sandbox.out("m.json"),
    ]);
    assert!(out.status.success(), "{}", stderr(&out));
    let err = stderr(&out);
    assert!(err.contains("not the same file"), "{err}");
    assert!(err.contains("only a warning"), "{err}");
    assert!(err.contains("fleet.toml"), "{err}");
}

#[test]
fn a_manifest_that_was_already_resolved_is_not_an_evaluation() {
    let sandbox = Sandbox::new();
    let out = sandbox.run(&[
        "resolve",
        "--from",
        "evaluation.json",
        "--repo",
        ".",
        "--out",
        &sandbox.out("m.json"),
    ]);
    assert!(out.status.success(), "{}", stderr(&out));

    // The output of one resolve, handed to the next one.
    let out = sandbox.run(&[
        "resolve",
        "--from",
        &sandbox.out("m.json"),
        "--repo",
        ".",
        "--out",
        &sandbox.out("again.json"),
    ]);
    assert_eq!(out.status.code(), Some(1));
    let said = stderr(&out);
    assert!(said.contains("resolved-fleet/1"), "{said}");
    assert!(said.contains("reads an EVALUATION"), "{said}");
    assert!(!Path::new(&sandbox.out("again.json")).exists());
}

#[test]
fn a_file_that_is_not_a_contract_is_refused_by_the_parser_that_reads_contracts() {
    let sandbox = Sandbox::new();
    std::fs::write(sandbox.out("rubbish.json"), "{\"schema\": \"something/1\"}").unwrap();
    let out = sandbox.run(&[
        "resolve",
        "--from",
        &sandbox.out("rubbish.json"),
        "--repo",
        ".",
        "--out",
        &sandbox.out("m.json"),
    ]);
    assert_eq!(out.status.code(), Some(1));
    let said = stderr(&out);
    assert!(said.contains("something/1"), "{said}");
    assert!(!Path::new(&sandbox.out("m.json")).exists());
}

#[test]
fn a_dirty_tree_is_refused_whoever_did_the_evaluating() {
    // The source is read HERE, so the rule that a manifest names a tree
    // somebody can check out again holds on this road too.
    let sandbox = Sandbox::new();
    std::fs::write(sandbox.path("fleet.toml"), "schema = 2\n# changed\n").unwrap();
    let out = sandbox.run(&[
        "resolve",
        "--from",
        "evaluation.json",
        "--repo",
        ".",
        "--out",
        &sandbox.out("m.json"),
    ]);
    assert_eq!(out.status.code(), Some(1));
    assert!(stderr(&out).contains("--dev"), "{}", stderr(&out));
    assert!(!Path::new(&sandbox.out("m.json")).exists());
}

fn sha256_of(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let digest = <sha2::Sha256 as sha2::Digest>::digest(bytes);
    digest.iter().fold(String::new(), |mut out, byte| {
        let _ = write!(out, "{byte:02x}");
        out
    })
}
