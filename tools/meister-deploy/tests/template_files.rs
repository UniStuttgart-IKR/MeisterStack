// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! The template in the binary and the template in the repository are one set.
//!
//! `templates/operator/` is both `templates.operator` of the flake (for
//! `nix flake new -t`) and the source of what `meister-deploy init` embeds
//! (`src/template.rs`, `include_str!`). Two roads to one directory is fine;
//! two DIFFERENT sets of files would mean a repository that is complete when
//! it is created one way and missing a file the other way — and the missing
//! file would only be noticed by whoever ran `nix flake check` in it.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use meister_deploy::template;

/// `templates/operator/` of this repository, from the crate's own directory:
/// `tools/meister-deploy/` is two levels down.
fn template_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../templates/operator")
        .canonicalize()
        .expect("templates/operator is where this crate expects it")
}

fn walk(dir: &Path, prefix: &str, into: &mut BTreeSet<String>) {
    for entry in std::fs::read_dir(dir).expect("reading the template directory") {
        let entry = entry.expect("a directory entry");
        let name = entry.file_name().to_string_lossy().into_owned();
        let rel = if prefix.is_empty() {
            name.clone()
        } else {
            format!("{prefix}/{name}")
        };
        if entry.file_type().expect("a file type").is_dir() {
            walk(&entry.path(), &rel, into);
        } else {
            into.insert(rel);
        }
    }
}

#[test]
fn every_file_of_the_template_is_in_the_binary_and_the_other_way_round() {
    let mut on_disk = BTreeSet::new();
    walk(&template_dir(), "", &mut on_disk);
    // A lock file is never part of the template: `init` has nix make one, and
    // a lock somebody committed here would pin revisions for every fleet.
    on_disk.remove("flake.lock");

    let embedded: BTreeSet<String> = template::FILES
        .iter()
        .map(|f| f.path.to_string())
        .collect();

    let missing: Vec<&String> = on_disk.difference(&embedded).collect();
    let extra: Vec<&String> = embedded.difference(&on_disk).collect();
    assert!(
        missing.is_empty() && extra.is_empty(),
        "templates/operator and src/template.rs disagree: \
         only on disk {missing:?}, only in the binary {extra:?}"
    );
}

#[test]
fn what_the_binary_carries_is_what_the_directory_holds() {
    for file in template::FILES {
        let path = template_dir().join(file.path);
        let on_disk = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("reading {} failed: {e}", path.display()));
        assert_eq!(
            on_disk,
            file.body,
            "{} differs between the directory and the binary",
            file.path
        );
    }
}

#[test]
fn the_template_has_no_lock_file_and_ignores_the_two_directories_that_must_not_be_committed() {
    let gitignore = template::FILES
        .iter()
        .find(|f| f.path == ".gitignore")
        .expect("the template has a .gitignore");
    for needed in [".meister-deploy/", "keys/"] {
        assert!(
            gitignore.body.contains(needed),
            "the template's .gitignore does not ignore {needed}"
        );
    }
    assert!(
        !template::FILES.iter().any(|f| f.path == "flake.lock"),
        "the template must not carry a lock file"
    );
}
