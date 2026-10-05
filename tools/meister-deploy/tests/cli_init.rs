// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Run init with empty PATH and temporary HOME. Verify template creation, refusal to
//! overwrite existing directories, dry-run behavior, and the missing-Nix diagnostic.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

fn binary() -> PathBuf {
    // target/debug/meister-deploy, from the test binary beside it.
    let mut path = std::env::current_exe().expect("the test binary has a path");
    path.pop();
    if path.ends_with("deps") {
        path.pop();
    }
    path.join("meister-deploy")
}

fn run(args: &[&str], empty_path: &Path) -> (bool, String, String) {
    let out = Command::new(binary())
        .args(args)
        .env("PATH", empty_path)
        .env("HOME", empty_path)
        .output()
        .expect("running meister-deploy");
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

fn snapshot(dir: &Path) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    fn walk(dir: &Path, prefix: &str, into: &mut BTreeMap<String, String>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            let rel = if prefix.is_empty() {
                name.clone()
            } else {
                format!("{prefix}/{name}")
            };
            if entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                into.insert(format!("{rel}/"), String::new());
                walk(&entry.path(), &rel, into);
            } else {
                into.insert(
                    rel,
                    std::fs::read_to_string(entry.path()).unwrap_or_default(),
                );
            }
        }
    }
    walk(dir, "", &mut out);
    out
}

#[test]
fn a_fresh_directory_becomes_a_deployment_repository() {
    let tmp = tempfile::tempdir().unwrap();
    let empty = tmp.path().join("no-programs-here");
    std::fs::create_dir(&empty).unwrap();
    let repo = tmp.path().join("fleet");

    let (ok, stdout, stderr) = run(&["init", repo.to_str().unwrap()], &empty);
    assert!(ok, "init failed: {stderr}");

    for needed in [
        "flake.nix",
        "fleet.toml",
        "profiles.nix",
        "profiles/base.nix",
        "profiles/single-node.nix",
        "disko/single-nvme.nix",
        "known_hosts",
        ".gitignore",
        ".meister-deploy",
    ] {
        assert!(
            repo.join(needed).exists(),
            "init wrote no {needed}\nstdout:\n{stdout}"
        );
        assert!(stdout.contains(needed), "{needed} is not in the output");
    }

    // No nix on this PATH, so no lock file — and the sentence says so
    // instead of the tool inventing one.
    assert!(!repo.join("flake.lock").exists());
    assert!(
        stderr.contains("nix flake lock") && stderr.contains("does not write a lock file"),
        "stderr does not say why there is no lock file:\n{stderr}"
    );
    // And the next steps, which are the ones a fleet cannot skip.
    assert!(stderr.contains("generate-binary-cache-key"), "{stderr}");

    // The default input, unchanged.
    let flake = std::fs::read_to_string(repo.join("flake.nix")).unwrap();
    assert!(
        flake.contains("meisterstack.url = \"github:UniStuttgart-IKR/MeisterStack\";"),
        "{flake}"
    );
}

#[test]
fn the_first_command_of_the_sentence_has_a_directory_to_write_into() {
    let tmp = tempfile::tempdir().unwrap();
    let empty = tmp.path().join("no-programs-here");
    std::fs::create_dir(&empty).unwrap();
    let repo = tmp.path().join("fleet");

    let (ok, stdout, stderr) = run(&["init", repo.to_str().unwrap()], &empty);
    assert!(ok, "{stderr}");

    // The generated cache-key command needs keys/ to exist before the operator runs it.
    let keys = repo.join("keys");
    assert!(
        keys.is_dir(),
        "init left no keys/ to write the key into\n{stdout}"
    );
    assert!(stdout.contains("keys"), "{stdout}");

    // It is empty and it stays out of git: the SECRET half lives there and
    // the public half (`signing.pub`) belongs beside it, in the repository.
    assert_eq!(std::fs::read_dir(&keys).unwrap().count(), 0);
    let ignored = std::fs::read_to_string(repo.join(".gitignore")).unwrap();
    assert!(ignored.lines().any(|l| l.trim() == "keys/"), "{ignored}");

    // And the key really can be written there, which is the whole point.
    std::fs::write(keys.join("signing.sec"), "my-fleet:c2VjcmV0\n").unwrap();
    assert!(keys.join("signing.sec").exists());
}

#[test]
fn the_meisterstack_input_can_be_pointed_at_a_checkout() {
    let tmp = tempfile::tempdir().unwrap();
    let empty = tmp.path().join("no-programs-here");
    std::fs::create_dir(&empty).unwrap();
    let repo = tmp.path().join("fleet");

    let reference = "git+file:///home/x/MeisterStack?ref=main";
    let (ok, _, stderr) = run(
        &["init", repo.to_str().unwrap(), "--meisterstack", reference],
        &empty,
    );
    assert!(ok, "{stderr}");
    let flake = std::fs::read_to_string(repo.join("flake.nix")).unwrap();
    assert!(
        flake.contains(&format!("meisterstack.url = \"{reference}\";")),
        "{flake}"
    );
    assert!(
        !flake.contains("github:UniStuttgart-IKR/MeisterStack\";"),
        "{flake}"
    );
}

#[test]
fn a_directory_that_is_not_empty_is_refused_and_nothing_in_it_changes() {
    let tmp = tempfile::tempdir().unwrap();
    let empty = tmp.path().join("no-programs-here");
    std::fs::create_dir(&empty).unwrap();
    let repo = tmp.path().join("mine");
    std::fs::create_dir(&repo).unwrap();
    std::fs::write(repo.join("fleet.toml"), "schema = 2\n").unwrap();
    let before = snapshot(&repo);

    let (ok, stdout, stderr) = run(&["init", repo.to_str().unwrap()], &empty);
    assert!(!ok, "init overwrote a repository somebody already had");
    assert!(stdout.is_empty(), "it printed a file list anyway: {stdout}");
    assert!(
        stderr.contains("is not empty") && stderr.contains("merges with nothing"),
        "{stderr}"
    );
    assert_eq!(
        before,
        snapshot(&repo),
        "it changed something on the way out"
    );
}

#[test]
fn a_dry_run_lists_the_files_and_writes_none_of_them() {
    let tmp = tempfile::tempdir().unwrap();
    let empty = tmp.path().join("no-programs-here");
    std::fs::create_dir(&empty).unwrap();
    let repo = tmp.path().join("fleet");

    let (ok, stdout, stderr) = run(&["init", repo.to_str().unwrap(), "--dry-run"], &empty);
    assert!(ok, "{stderr}");
    assert!(
        stdout.contains("flake.nix") && stdout.contains("fleet.toml"),
        "{stdout}"
    );
    assert!(stderr.contains("--dry-run wrote nothing"), "{stderr}");
    // Including the two directories, so that the list is the list.
    assert!(stdout.contains(".meister-deploy"), "{stdout}");
    assert!(stdout.trim_end().ends_with("keys"), "{stdout}");
    assert!(!repo.exists(), "a dry run created the directory");
}
