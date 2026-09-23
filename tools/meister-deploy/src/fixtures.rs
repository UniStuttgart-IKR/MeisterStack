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
use crate::observation::{
    BootedKernel, EtcdMember, EtcdView, HostObservation, Identity, Mount, Observations,
};
use crate::plan::{PlanKind, PlanPolicy, WorkloadControl};
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
        provided_evaluation: None,
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
        max_jobs: None,
        options: BTreeMap::new(),
        signing_key_name: Some("fleet-1".to_string()),
        cache_url: None,
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
                    direct_boot: None,
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
        differences: Vec::new(),
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

/// The same fleet with every host enrolled.
///
/// `n2` has no host key in the file on purpose — it is the fixture's
/// unenrolled host — and most tests about a rollout are not about that, so
/// they start from here. The manifest id is recomputed, because a fleet
/// whose content was edited and whose id was not is a fleet
/// `validate` refuses.
pub fn onebox_enrolled() -> ResolvedFleet {
    let mut fleet = onebox();
    for (id, host) in fleet.hosts.iter_mut() {
        if host.ssh.host_key_fingerprint.is_none() {
            host.ssh.host_key_fingerprint = Some(format!("SHA256:enrolled-{id}"));
        }
    }
    fleet.manifest_id =
        crate::ids::content_id(crate::ids::IdKind::Manifest, &fleet).expect("a manifest hashes");
    fleet
}

/// The same fleet with one host turned into a direct-boot guest.
///
/// The fixture's three hosts all boot themselves, which is the common case
/// and the one most tests are about. A test about the OTHER boot mode needs
/// a host whose kernel comes from outside, and building a second fixture
/// file for one field would be two fixtures to keep in step. The manifest id
/// is recomputed, because a fleet whose content was edited and whose id was
/// not is a fleet `validate` refuses.
pub fn with_direct_host(mut fleet: ResolvedFleet, id: &str) -> ResolvedFleet {
    {
        let host = fleet
            .hosts
            .get_mut(id)
            .unwrap_or_else(|| panic!("{id} is in the fixture"));
        host.build.boot.mode = crate::manifest::BootMode::Direct;
        host.build.boot.cmdline = Some(format!("loglevel=4 init={}/init", host.build.toplevel_out));
        host.build.direct_boot_drv = Some(format!("/nix/store/bbbb{id}-{id}-direct-boot.drv"));
        // A machine with no boot loader has no EFI disk image either, and
        // the manifest says so: `lib.mkFleet` builds none for such a host.
        host.build.disk_image_drv = None;
    }
    fleet.manifest_id =
        crate::ids::content_id(crate::ids::IdKind::Manifest, &fleet).expect("a manifest hashes");
    fleet
}

/// The bundle that belongs to such a host: the paths its own manifest
/// promised, plus the directory that holds them.
pub fn bundle_for(fleet: &ResolvedFleet, id: &str) -> crate::release::DirectBoot {
    let host = &fleet.hosts[id];
    crate::release::DirectBoot {
        kernel: crate::release::ImageArtifact {
            store_path: host.build.boot.kernel_out.clone(),
            sha256: "1".repeat(64),
            size: 12_000_000,
        },
        initrd: crate::release::ImageArtifact {
            store_path: host.build.boot.initrd_out.clone(),
            sha256: "2".repeat(64),
            size: 48_000_000,
        },
        cmdline: host
            .build
            .boot
            .cmdline
            .clone()
            .expect("a direct host carries a command line"),
        bundle_store_path: format!("/nix/store/bbbb{id}-{id}-direct-boot"),
    }
}

/// The same fleet after a new evaluation: the named hosts got a new system —
/// which is what a changed profile or a changed input actually looks like: a
/// new evaluation, a new manifest, a new set of store paths.
///
/// Separate from [`with_new_systems`] because a fleet with a direct-boot host
/// cannot become a release without its bundles ([`direct_release_of`]), and a
/// test about the second boot mode needs the fleet in between.
pub fn with_new_toplevels(
    mut fleet: ResolvedFleet,
    hosts: &[&str],
    new_kernel: bool,
) -> ResolvedFleet {
    for id in hosts {
        let host = fleet
            .hosts
            .get_mut(*id)
            .unwrap_or_else(|| panic!("{id} is in the fixture"));
        host.build.toplevel_drv = format!("/nix/store/next{id}-nixos-system-{id}-25.11.drv");
        host.build.toplevel_out = format!("/nix/store/next{id}-nixos-system-{id}-25.11");
        if new_kernel {
            host.build.boot.kernel_out = "/nix/store/next-linux-6.12.48/bzImage".to_string();
            host.build.boot.initrd_out = "/nix/store/next-initrd-linux-6.12.48/initrd".to_string();
            host.build.boot.kernel_params_sha256 = "3b8fnnnnnnnn".to_string();
            host.build.boot.kernel_version = "6.12.48".to_string();
        }
        // The command line of a direct-boot host names the system its kernel
        // is to start, so a new toplevel is a new command line. A fixture
        // that kept the old one would describe a guest booting the system
        // before the one this release builds.
        if host.build.boot.mode == crate::manifest::BootMode::Direct {
            host.build.boot.cmdline =
                Some(format!("loglevel=4 init={}/init", host.build.toplevel_out));
            host.build.direct_boot_drv = Some(format!("/nix/store/next{id}-{id}-direct-boot.drv"));
        }
    }
    fleet.manifest_id =
        crate::ids::content_id(crate::ids::IdKind::Manifest, &fleet).expect("a manifest hashes");
    fleet
}

/// A release in which the named hosts got a new system.
pub fn with_new_systems(fleet: ResolvedFleet, hosts: &[&str], new_kernel: bool) -> ReleaseManifest {
    release_of(with_new_toplevels(fleet, hosts, new_kernel))
}

/// [`release_of`] for a fleet that has direct-boot hosts: each of them
/// carries the bundle its provider is handed, because `release::bind` refuses
/// a release in which one does not.
pub fn direct_release_of(resolved: ResolvedFleet) -> ReleaseManifest {
    let mut artifacts = artifacts_for(&resolved);
    for (id, host) in &resolved.hosts {
        if host.build.boot.mode == crate::manifest::BootMode::Direct {
            artifacts
                .get_mut(id)
                .expect("every host of the fleet has artifacts")
                .direct_boot = Some(bundle_for(&resolved, id));
        }
    }
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

/// Every host of this release, running exactly what it says, with nothing in
/// the way. The starting point every test about a rollout departs from.
pub fn observed(release: &ReleaseManifest, taken_at: DateTime<Utc>) -> Observations {
    let fleet = &release.resolved_fleet;
    let mut hosts = BTreeMap::new();
    for (id, host) in &fleet.hosts {
        let artifacts = &release.artifacts[id];
        let system = artifacts.toplevel.store_path.clone();
        // Every unit the probe of this host asks about, so that a fixture
        // is what a real snapshot of a healthy host looks like: a unit the
        // probe asked about and nobody answered is `unknown` to the
        // readiness checks, and a fixture that left half of them out would
        // make a healthy host look half-read.
        let units: BTreeMap<String, String> = crate::observe::ProbeSpec::for_host(host)
            .units
            .into_iter()
            .map(|unit| (unit, "active".to_string()))
            .collect();
        hosts.insert(
            id.clone(),
            HostObservation {
                reachable: true,
                identity: Identity {
                    hostname: Some(host.name.clone()),
                    machine_id: Some(format!("machine-id-of-{id}")),
                    host_key_fingerprint: host
                        .ssh
                        .host_key_fingerprint
                        .clone()
                        .or_else(|| Some(format!("SHA256:seen-{id}"))),
                },
                current_system: Some(system.clone()),
                booted_system: Some(system.clone()),
                next_boot_system: Some(system),
                generation: Some(42),
                kernel_running: Some(host.build.boot.kernel_version.clone()),
                kernel_booted: Some(BootedKernel {
                    kernel_store_path: artifacts.boot.kernel_store_path.clone(),
                    initrd_store_path: artifacts.boot.initrd_store_path.clone(),
                    kernel_params_sha256: artifacts.boot.kernel_params_sha256.clone(),
                }),
                units,
                mounts: host
                    .persistence
                    .iter()
                    .map(|p| Mount {
                        path: p.path.clone(),
                        device: p.device_ref.replace("label:", "/dev/disk/by-label/"),
                        fstype: "ext4".to_string(),
                    })
                    .collect(),
                credentials: host
                    .secret_refs
                    .iter()
                    .map(|s| (s.id.clone(), Some(format!("fingerprint-of-{}", s.id))))
                    .collect(),
                etcd: etcd_view(fleet, id),
                vms_running: host.roles.iter().any(|r| r == "agent").then_some(0),
                open_txns: Vec::new(),
                lock: None,
                capabilities: host.hardware.capabilities.clone(),
                enrolled: true,
                unknown_reason: None,
            },
        );
    }
    Observations {
        schema: crate::observation::OBSERVATION_SCHEMA.to_string(),
        taken_at,
        provisional: false,
        hosts,
    }
}

/// What etcd would report on a host that is a member of a raft group: the
/// membership the fleet itself declares in `initial_cluster`.
fn etcd_view(fleet: &ResolvedFleet, id: &str) -> Option<EtcdView> {
    let host = fleet.hosts.get(id)?;
    let in_raft = host.groups.iter().any(|g| {
        fleet
            .groups
            .get(g)
            .map(|group| group.kind == crate::manifest::GroupKind::Raft)
            .unwrap_or(false)
    });
    if !in_raft {
        return None;
    }
    let declared = host
        .effective_settings
        .etcd
        .as_ref()?
        .get("initial_cluster")?
        .as_str()?
        .to_string();
    let members = declared
        .split(',')
        .filter_map(|entry| entry.trim().split_once('='))
        .map(|(name, url)| EtcdMember {
            id: format!("{name}-member-id"),
            name: name.to_string(),
            peer_urls: vec![url.to_string()],
            healthy: true,
        })
        .collect::<Vec<_>>();
    Some(EtcdView {
        member_id: Some(format!("{id}-member-id")),
        healthy: true,
        members,
    })
}

/// What the operator's own disk holds when every certificate of this fleet
/// has been issued — and it matches, secret for secret, what
/// [`observed`] puts on the hosts.
///
/// The public files by content (the same string the snapshot carries), the
/// private ones by existence. A key the target made itself has no local
/// half at all and is not in here, which is the whole point of it.
pub fn expected_credentials(
    fleet: &ResolvedFleet,
) -> BTreeMap<String, crate::pki::ExpectedCredentials> {
    let mut out = BTreeMap::new();
    for (id, host) in &fleet.hosts {
        let mut secrets = crate::pki::ExpectedCredentials::new();
        for secret in &host.secret_refs {
            if secret.source.kind == crate::manifest::SecretSourceKind::TargetGenerated {
                continue;
            }
            let value = if crate::observe::is_certificate(&secret.target_path) {
                format!("fingerprint-of-{}", secret.id)
            } else {
                crate::pki::PRESENT.to_string()
            };
            secrets.insert(secret.id.clone(), value);
        }
        if !secrets.is_empty() {
            out.insert(id.clone(), secrets);
        }
    }
    out
}

/// An operator who has the cli the drain needs.
pub fn plan_policy(kind: PlanKind) -> PlanPolicy {
    PlanPolicy::new(kind).with_workload_control(Some(WorkloadControl {
        cli_config: "cli.toml".to_string(),
        cli_profile: Some("cloud-mtls".to_string()),
    }))
}

/// The same operator, with every certificate of `fleet` issued.
pub fn plan_policy_with_certificates(kind: PlanKind, fleet: &ResolvedFleet) -> PlanPolicy {
    plan_policy(kind).with_expected_credentials(expected_credentials(fleet))
}

// --- lane 5A ---------------------------------------------------------------

/// The same fleet, with the hosts that carry a controller reading a
/// revocation list.
///
/// A separate helper rather than a line in the fixture file, for the reason
/// `with_direct_host` is one: `auth.crl` is not rendered by the one
/// derivation today (a controller refuses to start without a file it names,
/// and no fleet has been delivered one yet), so a fixture that carried it
/// everywhere would describe a fleet that does not exist. The manifest id is
/// recomputed, because a fleet whose content was edited and whose id was not
/// is a fleet `validate` refuses.
pub fn with_crl(mut fleet: ResolvedFleet, hosts: &[&str]) -> ResolvedFleet {
    for id in hosts {
        let host = fleet
            .hosts
            .get_mut(*id)
            .unwrap_or_else(|| panic!("{id} is in the fixture"));
        let dir = host
            .secret_refs
            .iter()
            .find(|s| s.target_path.ends_with("/ca.crt"))
            .map(|s| s.target_path.trim_end_matches("/ca.crt").to_string())
            .unwrap_or_else(|| "/var/lib/meisterstack/pki".to_string());
        // One per role that reads one, exactly as `nix/lib/manifest.nix`
        // writes a reference per file AND unit.
        for role in ["cloud", "cluster"] {
            if !host.roles.iter().any(|r| r == role) {
                continue;
            }
            host.secret_refs.push(crate::manifest::SecretRef {
                id: format!("crl-pem-{role}"),
                kind: crate::manifest::SecretKind::Crl,
                source: crate::manifest::SecretSource {
                    kind: crate::manifest::SecretSourceKind::MeisterCa,
                    reference: "crl".to_string(),
                },
                target_path: format!("{dir}/crl.pem"),
                owner: "root".to_string(),
                mode: "0644".to_string(),
                delivery: crate::manifest::Delivery::File,
                // What the one derivation renders: a unit per file. The
                // planner and the executor are what decide that a list is
                // not poked, and a test that left this out would be a test
                // of a manifest nobody writes.
                reload: Some(crate::manifest::Reload {
                    unit: format!("meister-{role}-controller.service"),
                    action: "restart".to_string(),
                }),
            });
        }
    }
    fleet.manifest_id =
        crate::ids::content_id(crate::ids::IdKind::Manifest, &fleet).expect("a manifest hashes");
    fleet
}

/// The same fleet, with a certificate beside the key a host makes itself.
///
/// The checked-in manifest is older than the shape `nix/lib/manifest.nix`
/// renders today: it carries `identity.key` but no `identity.crt`, and a
/// rotation is about the pair. Rather than rewrite a fixture every other
/// test's ids are computed from, this adds the reference the way the one
/// derivation writes it — one per file AND unit.
pub fn with_cert(mut fleet: ResolvedFleet, hosts: &[&str], kind: &str) -> ResolvedFleet {
    for id in hosts {
        let host = fleet
            .hosts
            .get_mut(*id)
            .unwrap_or_else(|| panic!("{id} is in the fixture"));
        let dir = host
            .secret_refs
            .iter()
            .find(|s| s.target_path.ends_with("/ca.crt"))
            .map(|s| s.target_path.trim_end_matches("/ca.crt").to_string())
            .unwrap_or_else(|| "/var/lib/meisterstack/pki".to_string());
        let roles: Vec<String> = ["cloud", "cluster", "agent"]
            .iter()
            .filter(|role| host.roles.iter().any(|r| r == *role))
            .map(|r| r.to_string())
            .collect();
        for role in roles {
            let unit = if role == "agent" {
                "meister-agent.service".to_string()
            } else {
                format!("meister-{role}-controller.service")
            };
            host.secret_refs.push(crate::manifest::SecretRef {
                id: format!("{kind}-crt-{role}"),
                kind: if kind == "serving" {
                    crate::manifest::SecretKind::ServingKey
                } else {
                    crate::manifest::SecretKind::IdentityKey
                },
                source: crate::manifest::SecretSource {
                    kind: crate::manifest::SecretSourceKind::MeisterCa,
                    reference: format!("system:node:{id}"),
                },
                target_path: format!("{dir}/{kind}.crt"),
                owner: "meister".to_string(),
                mode: "0644".to_string(),
                delivery: crate::manifest::Delivery::File,
                reload: Some(crate::manifest::Reload {
                    unit,
                    action: "restart".to_string(),
                }),
            });
        }
    }
    fleet.manifest_id =
        crate::ids::content_id(crate::ids::IdKind::Manifest, &fleet).expect("a manifest hashes");
    fleet
}

/// A rotation of the identity key of `id`, as `keys rotate` would have
/// prepared it.
pub fn rotation_for(
    fleet: &ResolvedFleet,
    id: &str,
    cert_sha256: &str,
) -> crate::plan::KeyRotation {
    crate::pki::rotation_of(
        &fleet.hosts[id],
        crate::pki::Prepared {
            host_id: id,
            kind: "identity",
            subject: &format!("system:node:{id}"),
            public_key_sha256: "cd".repeat(32).as_str(),
            cert_sha256,
            serial: Some("0A0B0C".to_string()),
            source: &std::path::PathBuf::from(format!("pki/issued/{id}/identity.next.crt")),
        },
    )
    .expect("the fixture renders a certificate for that host")
}
