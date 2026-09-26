// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Nix command construction and execution through Runner. Evaluation uses
//! --no-write-lock-file; callers require an existing lock. Clean trees use git+file
//! references, optionally pinned to the captured revision. Development evaluations use path
//! references to the scanned, materialized source snapshot, never the working directory
//! containing ignored files or keys.

use std::path::Path;
use std::time::Duration;

use anyhow::Result;

use crate::run::{Cmd, Effect, Runner};

/// The attribute an operator's flake exports, built by `lib.mkFleet`.
pub const MANIFEST_ATTR: &str = "meisterDeployment";

/// Maximum evaluation duration: ten minutes.
pub const EVAL_DEADLINE: Duration = Duration::from_secs(600);

/// Build the evaluation reference. Clean trees use the captured revision when supplied.
/// Development trees use the immutable snapshot selected by source::Tree::eval_dir; rev is
/// ignored.
pub fn flake_ref(dir: &Path, dev: bool, rev: Option<&str>) -> String {
    let path = dir.display();
    if dev {
        format!("path:{path}")
    } else {
        match rev {
            Some(rev) => format!("git+file://{path}?rev={rev}"),
            None => format!("git+file://{path}"),
        }
    }
}

/// Construct manifest evaluation separately so callers can describe it without executing it.
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

/// Lazily restrict both host maps, group memberships, and host-bound services. Excluded
/// systems are not evaluated; the result describes only the selected subfleet.
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

/// Evaluate the inventory attribute without evaluating host system modules.
pub fn eval_inventory_cmd(flake_ref: &str) -> Cmd {
    Cmd::new(Effect::NixEval, "nix", EVAL_DEADLINE).args([
        "eval".to_string(),
        "--json".to_string(),
        "--no-write-lock-file".to_string(),
        format!("{flake_ref}#{MANIFEST_ATTR}.inventory"),
    ])
}

pub fn eval_inventory(runner: &dyn Runner, flake_ref: &str) -> Result<String> {
    let out = runner.run(&eval_inventory_cmd(flake_ref))?;
    Ok(out.stdout)
}

/// Construct the explicit flake-lock operation used by init after writing the template.
pub fn flake_lock_cmd(dir: &Path) -> Cmd {
    Cmd::new(Effect::NixEval, "nix", Duration::from_secs(300))
        .args(["flake", "lock"])
        .cwd(dir)
}

/// Read NAR hashes and closure sizes, optionally from a remote store, for release validation.
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
            flake_ref(repo, false, None),
            "git+file:///home/silas/git/meisterstack-lab"
        );
        // A dev run is never handed the repository — `describe` hands it the
        // snapshot — but the spelling is `path:` either way.
        let snapshot = repo.join(".meister-deploy/snapshots/9f2c");
        assert_eq!(
            flake_ref(&snapshot, true, None),
            "path:/home/silas/git/meisterstack-lab/.meister-deploy/snapshots/9f2c"
        );
        // Never the bare path, whichever it is.
        assert!(!flake_ref(repo, false, None).starts_with('/'));
        assert!(!flake_ref(&snapshot, true, None).starts_with('/'));
    }

    /// A clean reference pins the captured commit; a development reference names its
    /// materialized snapshot.
    #[test]
    fn a_clean_tree_is_pinned_to_the_rev_it_was_read_at() {
        let repo = Path::new("/home/silas/git/meisterstack-lab");
        assert_eq!(
            flake_ref(repo, false, Some("f83cd70")),
            "git+file:///home/silas/git/meisterstack-lab?rev=f83cd70"
        );
        let snapshot = repo.join(".meister-deploy/snapshots/9f2c");
        assert_eq!(
            flake_ref(&snapshot, true, Some("f83cd70")),
            "path:/home/silas/git/meisterstack-lab/.meister-deploy/snapshots/9f2c",
            "a rev has nothing to pin on a path: reference, and is ignored"
        );
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
