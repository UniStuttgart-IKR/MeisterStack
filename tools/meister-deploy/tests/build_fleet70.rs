// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Seventy-host build test with strict command-count expectations.
//! Verify one artifact build, one signing command and one measurement batch,
//! with output association by derivation rather than response order.

mod support;

use std::collections::BTreeMap;
use std::path::PathBuf;

use meister_deploy::build::{BuildOptions, Builder, derivations};
use meister_deploy::effects::{FakeClock, MemFiles};
use meister_deploy::manifest::ResolvedFleet;
use meister_deploy::run::{Matcher, Output, StrictFake};

use support::fleet70;

/// The files every host's units read, so that `build` can measure them.
fn files_with_config(fleet: &ResolvedFleet) -> MemFiles {
    let mut files = MemFiles::new();
    for host in fleet.hosts.values() {
        for path in host.config_artifacts.values() {
            files = files.given(path.clone(), b"[node]\n".to_vec());
        }
    }
    files.given("/keys/fleet.sec", b"seventy:c2VjcmV0\n".to_vec())
}

/// What nix answers for a build of the whole fleet: one json array, one
/// entry per derivation, each naming its own `drvPath`.
fn answer(pairs: &[(String, String)]) -> String {
    let results: Vec<serde_json::Value> = pairs
        .iter()
        .map(|(drv, out)| serde_json::json!({ "drvPath": drv, "outputs": { "out": out } }))
        .collect();
    serde_json::to_string(&results).unwrap()
}

#[test]
fn seventy_hosts_are_one_nix_build_one_signature_and_one_measurement() {
    let fleet = fleet70();
    assert_eq!(fleet.hosts.len(), 70, "the fixture is the seventy");

    let drvs = derivations(&fleet, &fleet.evaluated_hosts);
    // Seventy systems plus three packages; this fixture has no derivation-based checks.
    assert_eq!(drvs.len(), 73, "{:?}", drvs.len());

    let mut pairs: Vec<(String, String)> = drvs
        .iter()
        .map(|d| {
            let out = d
                .drv
                .strip_suffix(".drv")
                .expect("the fixture's derivations end in .drv")
                .to_string();
            (d.drv.clone(), out)
        })
        .collect();
    pairs.sort_by(|a, b| a.0.cmp(&b.0));

    let info: BTreeMap<String, serde_json::Value> = pairs
        .iter()
        .map(|(_, out)| {
            (
                out.clone(),
                serde_json::json!({
                    "narHash": "sha256-AAAA",
                    "narSize": 1024,
                    "closureSize": 2048,
                    "signatures": ["seventy:abc"],
                }),
            )
        })
        .collect();

    let runner = StrictFake::new()
        .expect(
            Matcher::prefix("nix", ["path-info", "--json"]),
            Output::stdout("{}"),
        )
        .expect(
            Matcher::exact(
                "nix",
                [
                    "build".to_string(),
                    "--no-link".to_string(),
                    "--json".to_string(),
                ]
                .into_iter()
                .chain(pairs.iter().map(|(drv, _)| format!("{drv}^*")))
                .collect::<Vec<_>>(),
            ),
            Output::stdout(answer(&pairs)),
        )
        .expect(
            Matcher::prefix("nix", ["store", "sign", "--recursive", "--key-file"]),
            Output::stdout(""),
        )
        .expect(
            Matcher::prefix("nix", ["path-info", "--json", "--closure-size"]),
            Output::stdout(serde_json::to_string(&info).unwrap()),
        )
        .expect(
            Matcher::exact("nix", ["--version"]),
            Output::stdout("nix (Nix) 2.35.2\n"),
        )
        .expect(
            Matcher::exact("nix", ["config", "show", "system"]),
            Output::stdout("x86_64-linux\n"),
        )
        .expect(
            Matcher::exact("nix", ["config", "show", "sandbox"]),
            Output::stdout("true\n"),
        );

    let files = files_with_config(&fleet);
    let clock = FakeClock::fixed();
    let builder = Builder {
        runner: &runner,
        files: &files,
        clock: &clock,
        options: BuildOptions {
            sign_key: Some(PathBuf::from("/keys/fleet.sec")),
            ..BuildOptions::default()
        },
        state: None,
    };
    let built = builder.realise(fleet).expect("seventy hosts build");
    runner.verify().expect("nothing was left unasked");

    let calls = runner.calls();
    let builds = calls.iter().filter(|c| c.starts_with("nix build")).count();
    let signs = calls.iter().filter(|c| c.contains("store sign")).count();
    let measures = calls
        .iter()
        .filter(|c| c.contains("path-info --json --closure-size"))
        .count();
    assert_eq!(builds, 1, "seventy hosts, one build: {calls:?}");
    assert_eq!(signs, 1, "one closure walk, not seventy: {calls:?}");
    assert_eq!(measures, 1, "one measurement: {calls:?}");

    // Associate outputs by Nix `drvPath`, independent of response order.
    assert_eq!(built.release.artifacts.len(), 70);
    for (id, artifacts) in &built.release.artifacts {
        let promised = &built.release.resolved_fleet.hosts[id].build.toplevel_out;
        assert_eq!(&artifacts.toplevel.store_path, promised, "{id}");
    }
}

#[test]
fn what_the_operator_hands_nix_is_on_the_command_line_and_in_the_release() {
    let options = BuildOptions {
        builders: vec!["ssh://big".to_string(), "ssh://bigger".to_string()],
        substituters: vec!["https://cache.example".to_string()],
        max_jobs: Some("8".to_string()),
        options: BTreeMap::from([("cores".to_string(), "4".to_string())]),
        ..BuildOptions::default()
    };
    let line =
        meister_deploy::build::build_many_cmd(&["/nix/store/x.drv".to_string()], &options).line();
    assert!(
        line.contains("--builders 'ssh://big ; ssh://bigger'"),
        "{line}"
    );
    assert!(
        line.contains("--substituters https://cache.example"),
        "{line}"
    );
    assert!(line.contains("--max-jobs 8"), "{line}");
    assert!(line.contains("--option cores 4"), "{line}");
    assert!(line.contains("'/nix/store/x.drv^*'"), "{line}");
}
