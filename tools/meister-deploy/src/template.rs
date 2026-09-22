// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! The repository a deployment starts from, embedded in this binary.
//!
//! `meister-deploy init <dir>` writes these files and nothing else. They are
//! `include_str!`d rather than fetched, for three reasons: the verb works
//! offline, the files are the ones THIS binary was built with (so a manifest
//! and a template cannot be two versions apart), and `templates/operator/` in
//! the repository stays a real flake that `nix flake new -t` can also use.
//!
//! The list below and that directory have to stay the same set, and
//! `tests/template_files.rs` compares them — a file added to the directory
//! and forgotten here would be a template that is missing a file only when
//! somebody uses the tool rather than the flake.
//!
//! **No secrets, and no example keys.** A template that ships a certificate,
//! a private key or a plausible-looking public one is a template somebody
//! deploys by accident. `keys/` and `.meister-deploy/` are in its
//! `.gitignore`, `known_hosts` is empty, and the one key a fleet needs — the
//! public half of its signing key — is named by a sentence in
//! `profiles/base.nix` and created by the operator.

/// A file of the template: where it goes, what is in it, and how it is
/// written. Modes are explicit because a file this tool writes is a file
/// somebody else reads.
pub struct File {
    pub path: &'static str,
    pub body: &'static str,
    pub mode: u32,
}

/// Where the `meisterstack` input points unless `--meisterstack` says
/// otherwise. The line in the template names a branch; a deployment that is
/// made twice pins a revision, which the template says in the comment above
/// it and `init --meisterstack` writes for you.
pub const DEFAULT_FLAKE_REF: &str = "github:UniStuttgart-IKR/MeisterStack";

macro_rules! file {
    ($path:literal) => {
        File {
            path: $path,
            body: include_str!(concat!("../../../templates/operator/", $path)),
            mode: 0o644,
        }
    };
}

pub const FILES: &[File] = &[
    file!("flake.nix"),
    file!("fleet.toml"),
    file!("profiles.nix"),
    file!("profiles/base.nix"),
    file!("profiles/controller.nix"),
    file!("profiles/compute-cpu.nix"),
    file!("profiles/compute-gpu-pro6000.nix"),
    file!("profiles/observability-local.nix"),
    file!("hosts/cp-1.nix"),
    file!("hosts/a1.nix"),
    file!("disko/single-nvme.nix"),
    file!("tests/default.nix"),
    file!("known_hosts"),
    file!(".gitignore"),
];

/// The `meisterstack` input, pointed somewhere else.
///
/// A whole-line replacement and not a `{{placeholder}}`: the template has to
/// stay a flake that evaluates on its own (it is also `templates.operator`),
/// so what is in the file is a real flake reference and this function swaps
/// the value while leaving the comment above it — which is where the reason
/// for pinning a revision is written — untouched.
pub fn with_flake_ref(body: &str, flake_ref: &str) -> String {
    let needle = format!("meisterstack.url = \"{DEFAULT_FLAKE_REF}\";");
    let replacement = format!("meisterstack.url = \"{flake_ref}\";");
    body.replace(&needle, &replacement)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_template_carries_the_files_a_fleet_needs() {
        let paths: Vec<&str> = FILES.iter().map(|f| f.path).collect();
        for needed in [
            "flake.nix",
            "fleet.toml",
            "profiles.nix",
            "profiles/base.nix",
            "disko/single-nvme.nix",
            "known_hosts",
            ".gitignore",
        ] {
            assert!(paths.contains(&needed), "the template has no {needed}");
        }
    }

    #[test]
    fn no_file_of_the_template_is_empty_and_none_carries_a_key() {
        for file in FILES {
            assert!(!file.body.is_empty(), "{} is empty", file.path);
            // A template that ships key material is a template somebody
            // deploys by accident. `known_hosts` is public by definition and
            // is empty of keys; nothing else may look like one either.
            for marker in ["PRIVATE KEY", "BEGIN CERTIFICATE", "ssh-ed25519 AAAA"] {
                assert!(
                    !file.body.contains(marker),
                    "{} contains {marker:?}",
                    file.path
                );
            }
        }
    }

    #[test]
    fn the_flake_reference_is_the_one_line_that_changes() {
        let flake = FILES.iter().find(|f| f.path == "flake.nix").unwrap();
        assert!(flake.body.contains(DEFAULT_FLAKE_REF));
        let mine = with_flake_ref(flake.body, "git+file:///home/x/MeisterStack?ref=main");
        assert!(
            mine.contains("meisterstack.url = \"git+file:///home/x/MeisterStack?ref=main\";"),
            "{mine}"
        );
        // The comment above it survives, and so does the rest of the file.
        assert!(mine.contains("nixpkgs.url"));
        assert_eq!(mine.lines().count(), flake.body.lines().count());
        // And it is the only DEFINITION: the line above it is the comment
        // that says to pin a revision, and a comment is not an input. What
        // must never be two is the assignment.
        let definitions = mine
            .lines()
            .filter(|l| l.trim_start().starts_with("meisterstack.url = \""))
            .count();
        assert_eq!(
            definitions, 1,
            "more than one meisterstack.url in the template"
        );
        // The comment survives untouched, which is where the reason for
        // pinning is written.
        assert!(mine.contains("MeisterStack/<rev>"), "{mine}");
    }
}
