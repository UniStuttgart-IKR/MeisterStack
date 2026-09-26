// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Local files embedded from templates/operator. After writing them, init separately attempts
//! `nix flake lock`. Template tests compare the embedded and on-disk file sets and contents.
//! The operator supplies credentials; the embedded files contain no keys.

/// Embedded file contents, relative destination, and creation mode.
pub struct File {
    pub path: &'static str,
    pub body: &'static str,
    pub mode: u32,
}

/// Default MeisterStack flake input, replaceable through `init --meisterstack`. Pin the
/// deployment through its flake lock.
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
    file!("disko/single-direct.nix"),
    file!("tests/default.nix"),
    file!("known_hosts"),
    file!(".gitignore"),
];

/// Replace the default input declaration while retaining the surrounding template comments.
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
            // Reject private material, certificates, and populated SSH-key examples.
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
