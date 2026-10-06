// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Built artifacts bound to an unchanged resolved manifest.
//!
//! `bind` requires exactly the evaluated hosts and matching declared output
//! paths. Releases record NAR hashes, sizes, signatures and boot artifacts;
//! embedded manifest and release IDs provide content-integrity checks.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Result, bail};
use chrono::{DateTime, Utc};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::checks::CheckResult;
use crate::ids::{IdKind, content_id};
use crate::manifest::ResolvedFleet;

pub const RELEASE_SCHEMA: &str = "meister-deploy/release/1";

/// Build provenance excluded from release identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BuildEnv {
    pub nix_version: String,
    /// `x86_64-linux`.
    pub system: String,
    /// Remote builders that were offered, in the order nix got them.
    pub builders: Vec<String>,
    pub substituters: Vec<String>,
    /// `--max-jobs`, as nix was given it (a number or `auto`). Null when it
    /// was not given: then nix used its own setting, and naming a number
    /// here would be this tool inventing one.
    pub max_jobs: Option<String>,
    /// `--option <name> <value>`, whatever the operator passed on.
    pub options: BTreeMap<String, String>,
    /// The name of the key `nix store sign` used, never the key. A managed
    /// host runs with `require-sigs = true`, so an unsigned closure is one
    /// `nix copy` will refuse at the far end (M0 S12).
    pub signing_key_name: Option<String>,
    /// Cache receiving the signed build outputs, if any. This is provenance;
    /// targets use substituters configured on the target itself.
    pub cache_url: Option<String>,
    pub sandbox: bool,
}

/// A store path that exists, with what makes it that store path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct StoreArtifact {
    pub store_path: String,
    /// `sha256:…` as `nix path-info --json` reports it. Two paths with the
    /// same name and different nar hashes are two different systems, and
    /// this is the field a stage compares against the far store.
    pub nar_hash: String,
    pub nar_size: u64,
    pub closure_size: u64,
    /// `<key-name>:<base64>` per signature, as the store carries them.
    pub signatures: Vec<String>,
}

/// Boot or installer file identified by its byte SHA256 rather than a NAR hash.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ImageArtifact {
    pub store_path: String,
    pub sha256: String,
    pub size: u64,
}

/// Kernel, initrd and command line for provider-managed direct boot.
/// The paths must match the manifest. Uploading and booting this bundle remain
/// provider responsibilities.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DirectBoot {
    pub kernel: ImageArtifact,
    pub initrd: ImageArtifact,
    /// `<kernel params> init=<toplevel>/init`, byte for byte as the file
    /// `cmdline` in the bundle holds it.
    pub cmdline: String,
    /// The directory that holds the three above as `kernel`, `initrd` and
    /// `cmdline` — what `meister-deploy image --kind direct-boot` prints and
    /// what a garbage-collector root of this release protects.
    pub bundle_store_path: String,
}

/// Boot artifact identities used by the planner to classify required reboots.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BootArtifacts {
    pub kernel_store_path: String,
    pub initrd_store_path: String,
    /// sha256 over the kernel command line. A command line changes without
    /// any store path changing, and it still needs a reboot to take effect.
    pub kernel_params_sha256: String,
}

/// A rendered configuration file, by the name the manifest's
/// `config_artifacts` gave it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ConfigArtifact {
    pub store_path: String,
    pub sha256: String,
}

/// Everything this release built for one host.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HostArtifacts {
    pub toplevel: StoreArtifact,
    /// Optional installer image, permitted only when declared by the manifest.
    pub installer_iso: Option<ImageArtifact>,
    pub disk_image: Option<ImageArtifact>,
    /// Required exactly when the manifest specifies direct boot.
    pub direct_boot: Option<DirectBoot>,
    pub boot: BootArtifacts,
    /// Keyed as `config_artifacts` in the manifest: `agent_toml_out`, …
    pub config_files: BTreeMap<String, ConfigArtifact>,
}

/// A package the fleet's units point at, as it exists.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PackageArtifact {
    pub store_path: String,
    pub nar_hash: String,
}

/// Guest boot artifact used by verification suites, separate from host closures.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GuestArtifact {
    pub name: String,
    pub store_path: String,
    pub sha256: String,
}

/// Separate pinned inputs from a measured bit-identical rebuild result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Reproducibility {
    pub inputs_pinned: bool,
    pub bit_identical_verified: bool,
    /// How it was verified, when it was. Null otherwise.
    pub method: Option<String>,
    /// Per-system rebuild mismatches; an empty list alone does not prove verification.
    pub differences: Vec<String>,
}

/// `release.json`: one manifest, one set of built artifacts, one id.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ReleaseManifest {
    pub schema: String,
    /// sha256 over the content below, minus this field, `created_at` and
    /// `build_env`. Not part of its own input.
    pub release_id: String,
    /// Repeated from the embedded manifest so that a reader — and a plan —
    /// can name the manifest without unpacking the fleet.
    pub manifest_id: String,
    pub created_at: DateTime<Utc>,
    /// The manifest, verbatim. Not re-derived, not re-ordered, not trimmed.
    pub resolved_fleet: ResolvedFleet,
    pub build_env: BuildEnv,
    /// Keyed by host id — exactly the hosts the manifest evaluated.
    pub artifacts: BTreeMap<String, HostArtifacts>,
    pub packages: BTreeMap<String, PackageArtifact>,
    pub guest_artifacts: Vec<GuestArtifact>,
    /// The checks that had to pass for this release to exist at all — the
    /// flake checks, `--check-config` per host. Carried so that a receipt
    /// can say what was green before anything was copied anywhere.
    pub required_checks: Vec<CheckResult>,
    pub reproducibility: Reproducibility,
    /// Inherited from the manifest: built from a tree nobody can check out
    /// again.
    pub dev_mode: bool,
    /// Inherited from the manifest: this covers part of a fleet, and a plan
    /// over it is a plan over those hosts.
    pub partial: bool,
}

impl ReleaseManifest {
    pub fn from_json(text: &str, origin: &str) -> Result<ReleaseManifest> {
        let release: ReleaseManifest =
            crate::manifest::parse_checked(text, origin, RELEASE_SCHEMA)?;
        if !release.id_matches()? {
            bail!(
                "{origin} carries the id {} and its content hashes to {}; \
                 it was edited after it was built.",
                release.release_id,
                content_id(IdKind::Release, &release)?
            );
        }
        if !release.manifest_is_intact()? {
            bail!(
                "{origin} embeds a manifest that says it is {} and hashes to something \
                 else; the fleet was edited after it was resolved.",
                release.resolved_fleet.manifest_id
            );
        }
        Ok(release)
    }

    /// Pretty, with a trailing newline: this file is committed and diffed.
    pub fn to_json(&self) -> Result<Vec<u8>> {
        let mut bytes = serde_json::to_vec_pretty(self)
            .map_err(|e| anyhow::anyhow!("writing the release as json failed: {e}"))?;
        bytes.push(b'\n');
        Ok(bytes)
    }

    pub fn id_matches(&self) -> Result<bool> {
        Ok(content_id(IdKind::Release, self)? == self.release_id)
    }

    /// Check the embedded manifest content against its own ID.
    pub fn manifest_is_intact(&self) -> Result<bool> {
        self.resolved_fleet.id_matches()
    }

    /// The hosts this release built for, in id order.
    pub fn hosts(&self) -> Vec<&String> {
        self.artifacts.keys().collect()
    }
}

/// Bind build artifacts to declared manifest outputs, using the supplied timestamp.
#[allow(clippy::too_many_arguments)]
pub fn bind(
    resolved: ResolvedFleet,
    artifacts: BTreeMap<String, HostArtifacts>,
    packages: BTreeMap<String, PackageArtifact>,
    guest_artifacts: Vec<GuestArtifact>,
    build_env: BuildEnv,
    required_checks: Vec<CheckResult>,
    reproducibility: Reproducibility,
    now: DateTime<Utc>,
) -> Result<ReleaseManifest> {
    if resolved.schema != crate::manifest::RESOLVED_FLEET_SCHEMA {
        bail!(
            "this manifest says its schema is {:?}, and a release binds \
             {:?}.",
            resolved.schema,
            crate::manifest::RESOLVED_FLEET_SCHEMA
        );
    }

    // Require exactly the evaluated host set.
    let wanted: BTreeSet<&String> = resolved.evaluated_hosts.iter().collect();
    let built: BTreeSet<&String> = artifacts.keys().collect();
    let missing: Vec<&str> = wanted.difference(&built).map(|s| s.as_str()).collect();
    if !missing.is_empty() {
        bail!(
            "the manifest {} evaluated {} and nothing was built for {}; \
             a release covers every host of the manifest it binds.",
            resolved.manifest_id,
            resolved.evaluated_hosts.join(", "),
            missing.join(", ")
        );
    }
    let extra: Vec<&str> = built.difference(&wanted).map(|s| s.as_str()).collect();
    if !extra.is_empty() {
        bail!(
            "{} was built and is not a host of the manifest {}; \
             a release binds what its manifest asked for and nothing else.",
            extra.join(", "),
            resolved.manifest_id
        );
    }

    for (id, built) in &artifacts {
        let host = resolved
            .hosts
            .get(id)
            .expect("the host sets were just compared");

        // The one rule: a release binds, it does not replace. Every path
        // below was promised by the evaluation, and a build that produced a
        // different one built a different system.
        expect_same(
            id,
            "the toplevel",
            &host.build.toplevel_out,
            &built.toplevel.store_path,
        )?;
        expect_same(
            id,
            "the kernel",
            &host.build.boot.kernel_out,
            &built.boot.kernel_store_path,
        )?;
        expect_same(
            id,
            "the initrd",
            &host.build.boot.initrd_out,
            &built.boot.initrd_store_path,
        )?;
        expect_same(
            id,
            "the kernel command line digest",
            &host.build.boot.kernel_params_sha256,
            &built.boot.kernel_params_sha256,
        )?;

        // Require a direct-boot bundle exactly for direct-boot hosts.
        match (&built.direct_boot, host.build.boot.mode) {
            (Some(bundle), crate::manifest::BootMode::Direct) => {
                expect_same(
                    id,
                    "the direct-boot kernel",
                    &host.build.boot.kernel_out,
                    &bundle.kernel.store_path,
                )?;
                expect_same(
                    id,
                    "the direct-boot initrd",
                    &host.build.boot.initrd_out,
                    &bundle.initrd.store_path,
                )?;
                let promised = host.build.boot.cmdline.as_deref().unwrap_or_default();
                expect_same(
                    id,
                    "the direct-boot command line",
                    promised,
                    &bundle.cmdline,
                )?;
            }
            (None, crate::manifest::BootMode::Direct) => bail!(
                "{id} boots direct and this release carries no direct-boot bundle for it. A \
                 direct-boot host is started by its provider out of a kernel, an initrd and a \
                 command line, and a release that names none of them is a release nobody can \
                 boot that host from."
            ),
            // GRUB also uses a menu from the host disk.
            (Some(_), mode) => bail!(
                "a direct-boot bundle was built for {id} and its manifest says it boots \
                 {mode}. Such a host reads a boot menu of its own; the bundle would be a \
                 directory nothing ever loads."
            ),
            (None, _) => {} // --- end lane 5C ---
        }

        // An image only exists where the evaluation said there would be one.
        // The other direction is fine: `build` may leave an ISO unbuilt.
        if built.installer_iso.is_some() && host.build.installer_drv.is_none() {
            bail!(
                "an installer image was built for {id} and its manifest declares none; \
                 a host gets an installer by having `install` in the inventory."
            );
        }
        if built.disk_image.is_some() && host.build.disk_image_drv.is_none() {
            bail!(
                "a disk image was built for {id} and its manifest declares none; \
                 a host gets one by asking for it in the inventory."
            );
        }

        // Compare rendered configuration as a set of store paths; keys are labels.
        let promised: BTreeSet<&String> = host.config_artifacts.values().collect();
        let delivered: BTreeSet<&String> =
            built.config_files.values().map(|c| &c.store_path).collect();
        if promised != delivered {
            let missing: Vec<&str> = promised
                .difference(&delivered)
                .map(|s| s.as_str())
                .collect();
            let extra: Vec<&str> = delivered
                .difference(&promised)
                .map(|s| s.as_str())
                .collect();
            bail!(
                "the configuration files built for {id} are not the ones its manifest \
                 named{}{}.",
                if missing.is_empty() {
                    String::new()
                } else {
                    format!("; nothing was built for {}", missing.join(", "))
                },
                if extra.is_empty() {
                    String::new()
                } else {
                    format!("; nobody asked for {}", extra.join(", "))
                }
            );
        }
    }

    let mut release = ReleaseManifest {
        schema: RELEASE_SCHEMA.to_string(),
        // Filled in below; it is over everything else and is removed from
        // its own input in any case.
        release_id: String::new(),
        manifest_id: resolved.manifest_id.clone(),
        created_at: now,
        dev_mode: resolved.source.dev_mode.is_some(),
        partial: resolved.partial,
        resolved_fleet: resolved,
        build_env,
        artifacts,
        packages,
        guest_artifacts,
        required_checks,
        reproducibility,
    };
    release.release_id = content_id(IdKind::Release, &release)?;
    Ok(release)
}

fn expect_same(host: &str, what: &str, promised: &str, delivered: &str) -> Result<()> {
    if promised != delivered {
        bail!(
            "{what} built for {host} is {delivered} and its manifest says {promised}; \
             a release binds what the manifest evaluated, it does not replace it. \
             Resolve again if the fleet changed."
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixtures::{artifacts_for, at, build_env, onebox, release_of, reproducibility};

    #[test]
    fn a_release_embeds_the_manifest_byte_for_byte() {
        let resolved = onebox();
        let before =
            crate::canonical::to_vec(&serde_json::to_value(&resolved).expect("a manifest is json"));
        let release = release_of(resolved);
        let after = crate::canonical::to_vec(
            &serde_json::to_value(&release.resolved_fleet).expect("a manifest is json"),
        );
        assert_eq!(before, after, "the manifest travelled unchanged");
        assert!(release.manifest_is_intact().unwrap());
        assert_eq!(release.manifest_id, release.resolved_fleet.manifest_id);
    }

    #[test]
    fn a_different_nar_is_a_different_release_under_the_same_manifest() {
        let resolved = onebox();
        let manifest_id = resolved.manifest_id.clone();
        let first = release_of(resolved.clone());

        let mut artifacts = artifacts_for(&resolved);
        artifacts
            .get_mut("n1")
            .expect("n1 is in the fixture")
            .toplevel
            .nar_hash = "sha256:something-else".to_string();
        let second = bind(
            resolved,
            artifacts,
            BTreeMap::new(),
            Vec::new(),
            build_env(),
            Vec::new(),
            reproducibility(),
            at("2026-09-21T11:00:00Z"),
        )
        .expect("it still binds: the path is the promised one");

        assert_eq!(first.manifest_id, manifest_id);
        assert_eq!(second.manifest_id, manifest_id);
        assert_ne!(
            first.release_id, second.release_id,
            "the same fleet built to different bytes is a different release"
        );
    }

    /// One required check, as `build` writes it: a derivation that built.
    fn a_check(duration_ms: u64) -> CheckResult {
        CheckResult {
            id: "config-n1".to_string(),
            subject: crate::checks::Subject::host("n1"),
            required: true,
            status: crate::checks::Status::Pass,
            expected: "the derivation builds".to_string(),
            observed: "/nix/store/cccc-config-n1".to_string(),
            reason: "/nix/store/dddd-config-n1.drv built".to_string(),
            duration_ms,
            evidence: Vec::new(),
            release_id: None,
            config_id: None,
        }
    }

    fn release_with(checks: Vec<CheckResult>, now: &str) -> ReleaseManifest {
        let resolved = onebox();
        let artifacts = artifacts_for(&resolved);
        bind(
            resolved,
            artifacts,
            BTreeMap::new(),
            Vec::new(),
            build_env(),
            checks,
            reproducibility(),
            at(now),
        )
        .expect("the fixture binds")
    }

    #[test]
    fn two_builds_of_one_manifest_are_one_release() {
        // Check durations are execution metadata and must not change release identity.
        let first = release_with(vec![a_check(1_204)], "2026-09-21T11:00:00Z");
        let second = release_with(vec![a_check(973)], "2026-09-23T06:31:00Z");
        assert_eq!(
            first.release_id, second.release_id,
            "how long a check took is not what a release IS"
        );
        // And both still read back as themselves: the id is over the
        // content that is left, and the file is not edited afterwards.
        let text = String::from_utf8(second.to_json().expect("json")).expect("utf-8");
        ReleaseManifest::from_json(&text, "the second build").expect("it reads back");
    }

    #[test]
    fn which_checks_ran_and_what_they_said_is_still_part_of_the_release() {
        // The other half of the same decision: only the duration left the
        // id. A check that FAILED, or a check that is not there at all, is
        // a different release.
        let green = release_with(vec![a_check(500)], "2026-09-21T11:00:00Z");
        let mut failed = a_check(500);
        failed.status = crate::checks::Status::Fail;
        assert_ne!(
            green.release_id,
            release_with(vec![failed], "2026-09-21T11:00:00Z").release_id
        );
        let mut renamed = a_check(500);
        renamed.id = "config-n2".to_string();
        assert_ne!(
            green.release_id,
            release_with(vec![renamed], "2026-09-21T11:00:00Z").release_id
        );
        assert_ne!(
            green.release_id,
            release_with(Vec::new(), "2026-09-21T11:00:00Z").release_id
        );
    }

    // ---------------------------------------------------------------
    // The bundle of a direct-boot host (M3A position 3)
    // ---------------------------------------------------------------

    fn direct_release(
        mutate: impl FnOnce(&mut BTreeMap<String, HostArtifacts>, &ResolvedFleet),
    ) -> Result<ReleaseManifest> {
        let resolved = crate::fixtures::with_direct_host(onebox(), "n1");
        let mut artifacts = artifacts_for(&resolved);
        mutate(&mut artifacts, &resolved);
        bind(
            resolved,
            artifacts,
            BTreeMap::new(),
            Vec::new(),
            build_env(),
            Vec::new(),
            reproducibility(),
            at("2026-09-22T11:00:00Z"),
        )
    }

    #[test]
    fn a_direct_host_carries_the_bundle_its_manifest_promised() {
        let release = direct_release(|artifacts, fleet| {
            artifacts.get_mut("n1").unwrap().direct_boot =
                Some(crate::fixtures::bundle_for(fleet, "n1"));
        })
        .expect("it binds");
        let bundle = release.artifacts["n1"]
            .direct_boot
            .as_ref()
            .expect("n1 boots direct");
        assert_eq!(
            bundle.kernel.store_path,
            release.resolved_fleet.hosts["n1"].build.boot.kernel_out
        );
        assert!(bundle.cmdline.contains("init=/nix/store/"), "{bundle:?}");
        // And nobody else got one.
        assert!(release.artifacts["box"].direct_boot.is_none());
        assert!(release.artifacts["n2"].direct_boot.is_none());
    }

    #[test]
    fn a_direct_host_without_a_bundle_is_a_release_nobody_can_boot_it_from() {
        let err = direct_release(|_, _| {}).unwrap_err().to_string();
        assert!(err.contains("no direct-boot bundle"), "{err}");
        assert!(err.contains("started by its provider"), "{err}");
    }

    #[test]
    fn a_uefi_host_with_a_bundle_is_refused_too() {
        let resolved = crate::fixtures::with_direct_host(onebox(), "n1");
        let mut artifacts = artifacts_for(&resolved);
        artifacts.get_mut("n1").unwrap().direct_boot =
            Some(crate::fixtures::bundle_for(&resolved, "n1"));
        // …and one for a host that reads its own boot menu.
        let mut stray = crate::fixtures::bundle_for(&resolved, "n1");
        stray.bundle_store_path = "/nix/store/bbbbbox-box-direct-boot".to_string();
        artifacts.get_mut("box").unwrap().direct_boot = Some(stray);
        let err = bind(
            resolved,
            artifacts,
            BTreeMap::new(),
            Vec::new(),
            build_env(),
            Vec::new(),
            reproducibility(),
            at("2026-09-22T11:00:00Z"),
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("boots uefi"), "{err}");
        assert!(err.contains("nothing ever loads"), "{err}");
    }

    #[test]
    fn a_bundle_that_names_another_kernel_or_another_command_line_is_refused() {
        let err = direct_release(|artifacts, fleet| {
            let mut bundle = crate::fixtures::bundle_for(fleet, "n1");
            bundle.kernel.store_path = "/nix/store/somebody-elses-linux/bzImage".to_string();
            artifacts.get_mut("n1").unwrap().direct_boot = Some(bundle);
        })
        .unwrap_err()
        .to_string();
        assert!(err.contains("direct-boot kernel"), "{err}");

        let err = direct_release(|artifacts, fleet| {
            let mut bundle = crate::fixtures::bundle_for(fleet, "n1");
            bundle.cmdline = "loglevel=4".to_string();
            artifacts.get_mut("n1").unwrap().direct_boot = Some(bundle);
        })
        .unwrap_err()
        .to_string();
        assert!(err.contains("direct-boot command line"), "{err}");
    }

    #[test]
    fn a_changed_bundle_is_a_different_release() {
        let first = direct_release(|artifacts, fleet| {
            artifacts.get_mut("n1").unwrap().direct_boot =
                Some(crate::fixtures::bundle_for(fleet, "n1"));
        })
        .expect("binds");
        let second = direct_release(|artifacts, fleet| {
            let mut bundle = crate::fixtures::bundle_for(fleet, "n1");
            // The same paths, different bytes: a rebuilt initrd.
            bundle.initrd.sha256 = "3".repeat(64);
            artifacts.get_mut("n1").unwrap().direct_boot = Some(bundle);
        })
        .expect("binds");
        assert_eq!(first.manifest_id, second.manifest_id);
        assert_ne!(
            first.release_id, second.release_id,
            "the bytes a provider loads are part of what a release IS"
        );
    }

    #[test]
    fn another_builder_is_the_same_release() {
        let resolved = onebox();
        let first = release_of(resolved.clone());
        let mut elsewhere = build_env();
        elsewhere.nix_version = "2.24.9".to_string();
        elsewhere.builders = vec!["ssh://builder-2".to_string()];
        elsewhere.sandbox = false;
        let second = bind(
            resolved.clone(),
            artifacts_for(&resolved),
            BTreeMap::new(),
            Vec::new(),
            elsewhere,
            Vec::new(),
            reproducibility(),
            at("2026-09-22T23:00:00Z"),
        )
        .expect("binds");
        assert_eq!(
            first.release_id, second.release_id,
            "where it was built is recorded, and it is not what the release IS"
        );
        assert_ne!(first.build_env, second.build_env, "it is still recorded");
    }

    #[test]
    fn a_signature_is_part_of_what_a_release_is() {
        // Signing-key provenance is excluded from identity; artifact signatures remain.
        let resolved = onebox();
        let first = release_of(resolved.clone());
        let mut artifacts = artifacts_for(&resolved);
        artifacts.get_mut("box").unwrap().toplevel.signatures = Vec::new();
        let second = bind(
            resolved,
            artifacts,
            BTreeMap::new(),
            Vec::new(),
            build_env(),
            Vec::new(),
            reproducibility(),
            at("2026-09-21T11:00:00Z"),
        )
        .expect("binds");
        assert_ne!(first.release_id, second.release_id);
    }

    #[test]
    fn the_release_id_is_not_part_of_itself() {
        let mut release = release_of(onebox());
        let computed = content_id(IdKind::Release, &release).unwrap();
        assert_eq!(computed, release.release_id);
        release.release_id = "release-something-else".to_string();
        assert_eq!(
            computed,
            content_id(IdKind::Release, &release).unwrap(),
            "otherwise the id would have to contain itself"
        );
    }

    #[test]
    fn a_missing_artifact_is_a_refusal_that_names_the_host() {
        let resolved = onebox();
        let mut artifacts = artifacts_for(&resolved);
        artifacts.remove("n2");
        let err = bind(
            resolved,
            artifacts,
            BTreeMap::new(),
            Vec::new(),
            build_env(),
            Vec::new(),
            reproducibility(),
            at("2026-09-21T11:00:00Z"),
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("nothing was built for n2"), "{err}");
    }

    #[test]
    fn an_artifact_for_a_stranger_is_a_refusal() {
        let resolved = onebox();
        let mut artifacts = artifacts_for(&resolved);
        let stray = artifacts.get("n1").unwrap().clone();
        artifacts.insert("n9".to_string(), stray);
        let err = bind(
            resolved,
            artifacts,
            BTreeMap::new(),
            Vec::new(),
            build_env(),
            Vec::new(),
            reproducibility(),
            at("2026-09-21T11:00:00Z"),
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("n9 was built"), "{err}");
    }

    #[test]
    fn a_toplevel_that_is_not_the_promised_one_is_a_refusal() {
        let resolved = onebox();
        let mut artifacts = artifacts_for(&resolved);
        artifacts.get_mut("box").unwrap().toplevel.store_path =
            "/nix/store/zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz-nixos-system-box-25.11".to_string();
        let err = bind(
            resolved,
            artifacts,
            BTreeMap::new(),
            Vec::new(),
            build_env(),
            Vec::new(),
            reproducibility(),
            at("2026-09-21T11:00:00Z"),
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("the toplevel built for box"), "{err}");
        assert!(err.contains("it does not replace it"), "{err}");
    }

    #[test]
    fn a_boot_artifact_that_drifted_is_a_refusal_too() {
        for mutate in [
            |a: &mut HostArtifacts| a.boot.kernel_store_path = "/nix/store/x-linux".to_string(),
            |a: &mut HostArtifacts| a.boot.initrd_store_path = "/nix/store/x-initrd".to_string(),
            |a: &mut HostArtifacts| a.boot.kernel_params_sha256 = "deadbeef".to_string(),
        ] {
            let resolved = onebox();
            let mut artifacts = artifacts_for(&resolved);
            mutate(artifacts.get_mut("n1").unwrap());
            let err = bind(
                resolved,
                artifacts,
                BTreeMap::new(),
                Vec::new(),
                build_env(),
                Vec::new(),
                reproducibility(),
                at("2026-09-21T11:00:00Z"),
            )
            .unwrap_err()
            .to_string();
            assert!(err.contains("built for n1"), "{err}");
        }
    }

    #[test]
    fn an_image_nobody_asked_for_is_a_refusal() {
        let resolved = onebox();
        let mut artifacts = artifacts_for(&resolved);
        // n1 has no `disk_image_drv` in the fixture.
        artifacts.get_mut("n1").unwrap().disk_image = Some(ImageArtifact {
            store_path: "/nix/store/x-disk.img".to_string(),
            sha256: "0".repeat(64),
            size: 4,
        });
        let err = bind(
            resolved,
            artifacts,
            BTreeMap::new(),
            Vec::new(),
            build_env(),
            Vec::new(),
            reproducibility(),
            at("2026-09-21T11:00:00Z"),
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("a disk image was built for n1"), "{err}");
    }

    #[test]
    fn a_configuration_file_nobody_evaluated_is_a_refusal() {
        let resolved = onebox();
        let mut artifacts = artifacts_for(&resolved);
        artifacts.get_mut("box").unwrap().config_files.insert(
            "etcd_env_out".to_string(),
            ConfigArtifact {
                store_path: "/nix/store/x-etcd.env".to_string(),
                sha256: "0".repeat(64),
            },
        );
        let err = bind(
            resolved,
            artifacts,
            BTreeMap::new(),
            Vec::new(),
            build_env(),
            Vec::new(),
            reproducibility(),
            at("2026-09-21T11:00:00Z"),
        )
        .unwrap_err()
        .to_string();
        assert!(
            err.contains("nobody asked for /nix/store/x-etcd.env"),
            "{err}"
        );
    }

    #[test]
    fn dev_mode_and_partial_come_from_the_manifest_and_are_not_a_second_opinion() {
        let mut resolved = onebox();
        resolved.source.dirty = true;
        resolved.source.fingerprint = "dev:abc".to_string();
        resolved.source.dev_mode = Some(crate::manifest::DevMode {
            content_hash: "abc".to_string(),
            untracked_files: vec!["local.nix".to_string()],
            secret_scan: crate::manifest::SecretScan {
                ok: true,
                hits: Vec::new(),
            },
        });
        resolved.partial = true;
        resolved.evaluated_hosts = vec!["box".to_string(), "n1".to_string(), "n2".to_string()];
        resolved.manifest_id = content_id(IdKind::Manifest, &resolved).unwrap();
        let release = release_of(resolved);
        assert!(release.dev_mode);
        assert!(release.partial);
    }

    #[test]
    fn a_release_reads_back_from_its_own_json() {
        let release = release_of(onebox());
        let text = String::from_utf8(release.to_json().unwrap()).unwrap();
        let back = ReleaseManifest::from_json(&text, "the round trip").unwrap();
        assert_eq!(release, back);
    }

    #[test]
    fn a_release_that_was_edited_afterwards_is_refused() {
        let release = release_of(onebox());
        let mut value: serde_json::Value =
            serde_json::from_slice(&release.to_json().unwrap()).unwrap();
        value["artifacts"]["n1"]["toplevel"]["closure_size"] = serde_json::json!(7);
        let text = serde_json::to_string(&value).unwrap();
        let err = ReleaseManifest::from_json(&text, "the edited file")
            .unwrap_err()
            .to_string();
        assert!(err.contains("edited after it was built"), "{err}");
    }

    #[test]
    fn a_release_whose_fleet_was_edited_afterwards_is_refused() {
        // The embedded manifest carries its own id, so editing the fleet
        // inside a release is caught even when the release id was recomputed
        // around the change.
        let mut release = release_of(onebox());
        release.resolved_fleet.hosts.get_mut("n1").unwrap().address = "10.0.0.99".to_string();
        release.release_id = content_id(IdKind::Release, &release).unwrap();
        let text = String::from_utf8(release.to_json().unwrap()).unwrap();
        let err = ReleaseManifest::from_json(&text, "the edited file")
            .unwrap_err()
            .to_string();
        assert!(err.contains("edited after it was resolved"), "{err}");
    }

    #[test]
    fn a_file_of_another_schema_says_which_one_it_is() {
        let err = ReleaseManifest::from_json(r#"{"schema":"meister-deploy/plan/1"}"#, "a plan")
            .unwrap_err()
            .to_string();
        assert!(err.contains("meister-deploy/plan/1"), "{err}");
        assert!(err.contains(RELEASE_SCHEMA), "{err}");
    }
}
