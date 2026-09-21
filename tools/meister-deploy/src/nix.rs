// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Talking to `nix`, and only ever by running it.
//!
//! There is no Nix evaluator here and there will not be one. What is here is
//! the small set of command lines this tool depends on, each built in one
//! place so that a test can read the argv rather than a lab.
//!
//! Two of those command lines carry a decision worth spelling out.
//!
//! **`--no-write-lock-file`.** An evaluation that resolves an unlocked input
//! writes `flake.lock` as a side effect. A tool whose read-only verb changes
//! a committed file is a tool nobody can run twice and compare. `resolve`
//! therefore refuses a repository without a lock file (see [`crate::source`])
//! and forbids nix to write one.
//!
//! **The flake reference is never a bare path.** `getFlake` on a bare path
//! copies the entire directory into the store — `target/`, `result` symlinks,
//! whatever else is lying around — and a full disk during a rollout is a bad
//! day. A clean tree is addressed as `git+file://`, which copies what git
//! tracks and nothing else. A `--dev` tree has to be addressed as `path:`,
//! because seeing the untracked files is the entire point of `--dev`; that
//! copy is the price, and it is why `--dev` is not the default.

use std::path::Path;
use std::time::Duration;

use anyhow::Result;

use crate::run::{Cmd, Effect, Runner};

/// The attribute an operator's flake exports, built by `lib.mkFleet`.
pub const MANIFEST_ATTR: &str = "meisterDeployment";

/// Ten minutes. A seventy-host evaluation on a cold eval cache is minutes,
/// not seconds; an evaluation that has not answered in ten is one that never
/// will, and it is holding a lock while it does not.
pub const EVAL_DEADLINE: Duration = Duration::from_secs(600);

/// How to address the operator's repository. See the module note.
pub fn flake_ref(repo: &Path, dev: bool) -> String {
    let path = repo.display();
    if dev {
        format!("path:{path}")
    } else {
        format!("git+file://{path}")
    }
}

/// `nix eval --json --no-write-lock-file <ref>#meisterDeployment`.
///
/// Built separately from being run so that `--dry-run` can print exactly the
/// line a real run would execute, rather than a description of it.
pub fn eval_manifest_cmd(flake_ref: &str, hosts: Option<&[String]>) -> Cmd {
    let cmd = Cmd::new(Effect::NixEval, "nix", EVAL_DEADLINE).args([
        "eval".to_string(),
        "--json".to_string(),
        "--no-write-lock-file".to_string(),
        format!("{flake_ref}#{MANIFEST_ATTR}"),
    ]);
    match hosts {
        None => cmd,
        Some(hosts) => cmd.args(["--apply".to_string(), restrict_to(hosts)]),
    }
}

pub fn eval_manifest(
    runner: &dyn Runner,
    flake_ref: &str,
    hosts: Option<&[String]>,
) -> Result<String> {
    let out = runner.run(&eval_manifest_cmd(flake_ref, hosts))?;
    Ok(out.stdout)
}

/// Restrict the manifest to a subset of its hosts, lazily.
///
/// Nix only forces what the result mentions, so leaving out a host leaves out
/// its whole evaluation — which is the point: on seventy hosts the expensive
/// half is `hosts.<id>.build`, and a change to one host should not cost the
/// other sixty-nine.
///
/// Both halves are restricted, and so are the group memberships and the
/// services, because `manifest::resolve` requires them to agree. What comes
/// out is an honest manifest of a SUB-FLEET: it is for inspecting and for
/// iterating, and a plan over it is a plan over those hosts only.
fn restrict_to(hosts: &[String]) -> String {
    let keep = hosts
        .iter()
        .map(|h| format!("{h:?}"))
        .collect::<Vec<_>>()
        .join(" ");
    format!(
        "m: let keep = [ {keep} ]; has = n: builtins.elem n keep; \
         pick = attrs: builtins.listToAttrs (map (n: {{ name = n; value = attrs.${{n}}; }}) keep); \
         in m // {{ \
         hosts = pick m.hosts; \
         inventory = m.inventory // {{ \
         hosts = pick m.inventory.hosts; \
         groups = builtins.mapAttrs (_: g: g // {{ members = builtins.filter has g.members; }}) \
         m.inventory.groups; \
         services = builtins.listToAttrs (builtins.filter \
         (kv: kv.value.host == null || has kv.value.host) \
         (map (n: {{ name = n; value = m.inventory.services.${{n}}; }}) \
         (builtins.attrNames m.inventory.services))); \
         }}; }}"
    )
}

/// `nix path-info --json`, optionally against another store. Reading only:
/// it says what a path's nar hash and closure size are, and M2's `build` and
/// `stage` both compare that answer against the release.
pub fn path_info_cmd(store: Option<&str>, paths: &[String]) -> Cmd {
    let mut cmd = Cmd::new(Effect::Read, "nix", Duration::from_secs(300)).args([
        "path-info",
        "--json",
        "--closure-size",
    ]);
    if let Some(store) = store {
        cmd = cmd.args(["--store".to_string(), store.to_string()]);
    }
    cmd.args(paths.iter().cloned())
}

pub fn path_info_json(
    runner: &dyn Runner,
    store: Option<&str>,
    paths: &[String],
) -> Result<String> {
    let out = runner.run(&path_info_cmd(store, paths))?;
    Ok(out.stdout)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::run::{Matcher, Output, Policy, StrictFake};

    #[test]
    fn a_clean_tree_is_a_git_flake_and_a_dev_tree_is_a_path_flake() {
        let repo = Path::new("/home/silas/git/meisterstack-lab");
        assert_eq!(
            flake_ref(repo, false),
            "git+file:///home/silas/git/meisterstack-lab"
        );
        assert_eq!(
            flake_ref(repo, true),
            "path:/home/silas/git/meisterstack-lab"
        );
        // Never the bare path, whichever it is.
        assert!(!flake_ref(repo, false).starts_with('/'));
        assert!(!flake_ref(repo, true).starts_with('/'));
    }

    #[test]
    fn the_whole_fleet_is_four_arguments_and_one_of_them_is_the_lock_file() {
        let cmd = eval_manifest_cmd("git+file:///r", None);
        assert_eq!(
            cmd.args,
            vec![
                "eval",
                "--json",
                "--no-write-lock-file",
                "git+file:///r#meisterDeployment"
            ]
        );
        assert_eq!(cmd.effect, Effect::NixEval);
        assert_eq!(cmd.deadline, EVAL_DEADLINE);
    }

    #[test]
    fn a_subset_is_the_same_line_plus_one_apply() {
        let hosts = vec!["box".to_string(), "n1".to_string()];
        let cmd = eval_manifest_cmd("git+file:///r", Some(&hosts));
        assert_eq!(cmd.args.len(), 6);
        assert_eq!(cmd.args[4], "--apply");
        let apply = &cmd.args[5];
        assert!(apply.contains(r#"keep = [ "box" "n1" ]"#), "{apply}");
        assert!(apply.contains("hosts = pick m.hosts"), "{apply}");
        assert!(apply.contains("hosts = pick m.inventory.hosts"), "{apply}");
        assert!(apply.contains("builtins.filter has g.members"), "{apply}");
    }

    #[test]
    fn a_host_name_is_quoted_into_the_expression_and_cannot_end_it() {
        // Host ids are checked by `inventory`, so this can never happen from
        // a valid inventory; it is here because the day it can, it must not
        // become nix code.
        let hosts = vec!["\" ]; abort \"".to_string()];
        let cmd = eval_manifest_cmd("git+file:///r", Some(&hosts));
        assert!(
            cmd.args[5].contains(r#"[ "\" ]; abort \"" ]"#),
            "{}",
            cmd.args[5]
        );
    }

    #[test]
    fn an_offline_run_refuses_the_evaluation_rather_than_faking_it() {
        let runner = StrictFake::new().with_policy(Policy::offline());
        let err = eval_manifest(&runner, "git+file:///r", None)
            .unwrap_err()
            .to_string();
        assert!(err.contains("--offline"), "{err}");
        assert!(err.contains("nix-eval"), "{err}");
    }

    #[test]
    fn the_evaluation_hands_its_stdout_back_whole() {
        let runner = StrictFake::new().expect(
            Matcher::prefix("nix", ["eval", "--json", "--no-write-lock-file"]),
            Output::stdout(r#"{"schema":"meister-deploy/nix-manifest/1"}"#),
        );
        let text = eval_manifest(&runner, "git+file:///r", None).unwrap();
        runner.verify().unwrap();
        assert!(text.contains("nix-manifest/1"));
    }

    #[test]
    fn path_info_asks_the_store_that_was_named() {
        let paths = vec!["/nix/store/aaa-system".to_string()];
        let local = path_info_cmd(None, &paths);
        assert_eq!(
            local.args,
            vec![
                "path-info",
                "--json",
                "--closure-size",
                "/nix/store/aaa-system"
            ]
        );
        let remote = path_info_cmd(Some("ssh-ng://root@box"), &paths);
        assert_eq!(remote.args[3], "--store");
        assert_eq!(remote.args[4], "ssh-ng://root@box");
        assert_eq!(remote.effect, Effect::Read);
    }
}
