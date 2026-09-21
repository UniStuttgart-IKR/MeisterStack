// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! The fleet the unit tests of this crate argue about.
//!
//! One fixture, built from the file lane 1B has to produce —
//! `tests/fixtures/nix-manifest-onebox.json`, read through the real
//! [`crate::manifest::NixManifest`] parser and the real
//! [`crate::manifest::resolve`]. So a test about a plan is a test about a
//! manifest that would actually validate, and a change to the contract
//! breaks these tests where it should: at the contract.
//!
//! Three hosts: `box` (cloud, cluster, agent, addons — a raft group of ONE,
//! which is the singleton case), `n1` and `n2` (agents in the `compute`
//! group). Compiled only for tests.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};

use crate::manifest::{NixManifest, ResolvedFleet, Source, Tool};
use crate::release::{
    BootArtifacts, BuildEnv, ConfigArtifact, HostArtifacts, ReleaseManifest, Reproducibility,
    StoreArtifact, bind,
};

/// The one-box fixture, resolved. Three hosts: `box` (four roles, a raft
/// group of one), `n1` and `n2` (compute).
pub fn onebox() -> ResolvedFleet {
    let text = include_str!("../tests/fixtures/nix-manifest-onebox.json");
    let nix = NixManifest::from_json(text, "the one-box fixture").expect("the fixture parses");
    crate::manifest::resolve(nix, source(), tool(), at("2026-09-21T10:00:00Z"), None)
        .expect("the fixture resolves")
}

pub fn at(ts: &str) -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(ts)
        .expect("a literal this file controls")
        .with_timezone(&Utc)
}

fn source() -> Source {
    Source {
        repo_path: "/home/silas/git/meisterstack-lab".to_string(),
        git_rev: Some("f83cd70".to_string()),
        tree_hash: Some("8a1c".to_string()),
        dirty: false,
        fingerprint: "git:f83cd70:8a1c".to_string(),
        dev_mode: None,
        flake_lock: BTreeMap::new(),
        inventory_path: "fleet.toml".to_string(),
        inventory_sha256: "0".repeat(64),
    }
}

fn tool() -> Tool {
    Tool {
        name: "meister-deploy".to_string(),
        version: "0.1.0".to_string(),
        git_rev: None,
    }
}

pub fn build_env() -> BuildEnv {
    BuildEnv {
        nix_version: "2.35.2".to_string(),
        system: "x86_64-linux".to_string(),
        builders: Vec::new(),
        substituters: vec!["https://cache.nixos.org".to_string()],
        signing_key_name: Some("fleet-1".to_string()),
        sandbox: true,
    }
}

/// Artifacts that say exactly what the manifest promised.
pub fn artifacts_for(resolved: &ResolvedFleet) -> BTreeMap<String, HostArtifacts> {
    resolved
        .hosts
        .iter()
        .map(|(id, host)| {
            (
                id.clone(),
                HostArtifacts {
                    toplevel: StoreArtifact {
                        store_path: host.build.toplevel_out.clone(),
                        nar_hash: format!("sha256:{id}-toplevel"),
                        nar_size: 1_000_000,
                        closure_size: 2_000_000_000,
                        signatures: vec![format!("fleet-1:{id}")],
                    },
                    installer_iso: None,
                    disk_image: None,
                    boot: BootArtifacts {
                        kernel_store_path: host.build.boot.kernel_out.clone(),
                        initrd_store_path: host.build.boot.initrd_out.clone(),
                        kernel_params_sha256: host.build.boot.kernel_params_sha256.clone(),
                    },
                    config_files: host
                        .config_artifacts
                        .iter()
                        .map(|(name, path)| {
                            (
                                name.clone(),
                                ConfigArtifact {
                                    store_path: path.clone(),
                                    sha256: "0".repeat(64),
                                },
                            )
                        })
                        .collect(),
                },
            )
        })
        .collect()
}

pub fn reproducibility() -> Reproducibility {
    Reproducibility {
        inputs_pinned: true,
        bit_identical_verified: false,
        method: None,
    }
}

pub fn release_of(resolved: ResolvedFleet) -> ReleaseManifest {
    let artifacts = artifacts_for(&resolved);
    bind(
        resolved,
        artifacts,
        BTreeMap::new(),
        Vec::new(),
        build_env(),
        Vec::new(),
        reproducibility(),
        at("2026-09-21T11:00:00Z"),
    )
    .expect("the fixture binds")
}
