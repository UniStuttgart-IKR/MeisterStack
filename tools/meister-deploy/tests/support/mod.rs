// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Fleet fixtures built through public manifest resolution and release binding.
//! The 70-host fixture derives from the checked-in one-box evaluation.

// Shared by two test binaries; each uses part of it.
#![allow(dead_code)]

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde_json::{Value, json};

use meister_deploy::manifest::{self, NixManifest, ResolvedFleet, Source, Tool};
use meister_deploy::observation::{
    BootedKernel, EtcdMember, EtcdView, HostObservation, Identity, Mount, NetworkInterface,
    OBSERVATION_SCHEMA, Observations, PciDevice,
};
use meister_deploy::release::{
    BootArtifacts, BuildEnv, ConfigArtifact, HostArtifacts, ReleaseManifest, Reproducibility,
    StoreArtifact, bind,
};

pub fn at(ts: &str) -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(ts)
        .expect("a literal these tests control")
        .with_timezone(&Utc)
}

pub fn source() -> Source {
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

pub fn tool() -> Tool {
    Tool {
        name: "meister-deploy".to_string(),
        version: "0.1.0".to_string(),
        git_rev: None,
    }
}

pub fn onebox_json() -> Value {
    serde_json::from_str(include_str!("../fixtures/nix-manifest-onebox.json"))
        .expect("the fixture is json")
}

/// The one-box fleet, resolved, with every host enrolled.
pub fn onebox() -> ResolvedFleet {
    resolve_value(onebox_json())
}

pub fn resolve_value(value: Value) -> ResolvedFleet {
    let text = serde_json::to_string(&value).expect("a manifest is json");
    let nix = NixManifest::from_json(&text, "the generated manifest").expect("it parses");
    let mut fleet = manifest::resolve(nix, source(), tool(), at("2026-09-21T10:00:00Z"), None)
        .expect("it resolves");
    for (id, host) in fleet.hosts.iter_mut() {
        if host.ssh.host_key_fingerprint.is_none() {
            host.ssh.host_key_fingerprint = Some(format!("SHA256:enrolled-{id}"));
        }
    }
    fleet.manifest_id =
        meister_deploy::ids::content_id(meister_deploy::ids::IdKind::Manifest, &fleet)
            .expect("a manifest hashes");
    fleet
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
                        nar_hash: format!("sha256:{}", host.build.toplevel_out),
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

pub fn release_of(resolved: ResolvedFleet) -> ReleaseManifest {
    let artifacts = artifacts_for(&resolved);
    bind(
        resolved,
        artifacts,
        BTreeMap::new(),
        Vec::new(),
        build_env(),
        Vec::new(),
        Reproducibility {
            inputs_pinned: true,
            bit_identical_verified: false,
            method: None,
            differences: Vec::new(),
        },
        at("2026-09-21T11:00:00Z"),
    )
    .expect("the fixture binds")
}

/// Add guest-tiny artifacts required by VM verification and recompute the release ID.
pub fn with_guest_tiny(mut release: ReleaseManifest, store_path: &str) -> ReleaseManifest {
    release.packages.insert(
        "guest-tiny".to_string(),
        meister_deploy::release::PackageArtifact {
            store_path: store_path.to_string(),
            nar_hash: "sha256:guest-tiny".to_string(),
        },
    );
    release.release_id =
        meister_deploy::ids::content_id(meister_deploy::ids::IdKind::Release, &release)
            .expect("a release hashes");
    release
}

/// A release in which the named hosts got a new system.
pub fn with_new_systems(
    mut fleet: ResolvedFleet,
    hosts: &[String],
    new_kernel: bool,
) -> ReleaseManifest {
    for id in hosts {
        let host = fleet
            .hosts
            .get_mut(id)
            .unwrap_or_else(|| panic!("{id} is in the fleet"));
        host.build.toplevel_drv = format!("/nix/store/next{id}-nixos-system-{id}.drv");
        host.build.toplevel_out = format!("/nix/store/next{id}-nixos-system-{id}");
        if new_kernel {
            host.build.boot.kernel_out = "/nix/store/next-linux-6.12.48/bzImage".to_string();
            host.build.boot.initrd_out = "/nix/store/next-initrd-6.12.48/initrd".to_string();
            host.build.boot.kernel_params_sha256 = "3b8fnnnnnnnn".to_string();
            host.build.boot.kernel_version = "6.12.48".to_string();
        }
    }
    fleet.manifest_id =
        meister_deploy::ids::content_id(meister_deploy::ids::IdKind::Manifest, &fleet)
            .expect("a manifest hashes");
    release_of(fleet)
}

/// Give one host provider-loaded boot artifacts without a bootloader.
pub fn with_direct_host(mut fleet: ResolvedFleet, id: &str) -> ResolvedFleet {
    {
        let host = fleet
            .hosts
            .get_mut(id)
            .unwrap_or_else(|| panic!("{id} is in the fleet"));
        host.build.boot.mode = meister_deploy::manifest::BootMode::Direct;
        host.build.boot.cmdline = Some(format!("loglevel=4 init={}/init", host.build.toplevel_out));
        host.build.direct_boot_drv = Some(format!("/nix/store/bbbb{id}-{id}-direct-boot.drv"));
        host.build.disk_image_drv = None;
    }
    fleet.manifest_id =
        meister_deploy::ids::content_id(meister_deploy::ids::IdKind::Manifest, &fleet)
            .expect("a manifest hashes");
    fleet
}

/// Update evaluated outputs; direct-boot hosts require direct_release_of.
pub fn with_new_toplevels(
    mut fleet: ResolvedFleet,
    hosts: &[&str],
    new_kernel: bool,
) -> ResolvedFleet {
    for id in hosts {
        let host = fleet
            .hosts
            .get_mut(*id)
            .unwrap_or_else(|| panic!("{id} is in the fleet"));
        host.build.toplevel_drv = format!("/nix/store/next{id}-nixos-system-{id}.drv");
        host.build.toplevel_out = format!("/nix/store/next{id}-nixos-system-{id}");
        if new_kernel {
            host.build.boot.kernel_out = "/nix/store/next-linux-6.12.48/bzImage".to_string();
            host.build.boot.initrd_out = "/nix/store/next-initrd-6.12.48/initrd".to_string();
            host.build.boot.kernel_params_sha256 = "3b8fnnnnnnnn".to_string();
            host.build.boot.kernel_version = "6.12.48".to_string();
        }
        if host.build.boot.mode == meister_deploy::manifest::BootMode::Direct {
            host.build.boot.cmdline =
                Some(format!("loglevel=4 init={}/init", host.build.toplevel_out));
            host.build.direct_boot_drv = Some(format!("/nix/store/next{id}-{id}-direct-boot.drv"));
        }
    }
    fleet.manifest_id =
        meister_deploy::ids::content_id(meister_deploy::ids::IdKind::Manifest, &fleet)
            .expect("a manifest hashes");
    fleet
}

/// Bind a release with the required provider boot bundles.
pub fn direct_release_of(resolved: ResolvedFleet) -> ReleaseManifest {
    let mut artifacts = artifacts_for(&resolved);
    for (id, host) in &resolved.hosts {
        if host.build.boot.mode != meister_deploy::manifest::BootMode::Direct {
            continue;
        }
        artifacts
            .get_mut(id)
            .expect("every host has artifacts")
            .direct_boot = Some(meister_deploy::release::DirectBoot {
            kernel: meister_deploy::release::ImageArtifact {
                store_path: host.build.boot.kernel_out.clone(),
                sha256: "1".repeat(64),
                size: 12_000_000,
            },
            initrd: meister_deploy::release::ImageArtifact {
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
        });
    }
    bind(
        resolved,
        artifacts,
        BTreeMap::new(),
        Vec::new(),
        build_env(),
        Vec::new(),
        Reproducibility {
            inputs_pinned: true,
            bit_identical_verified: false,
            method: None,
            differences: Vec::new(),
        },
        at("2026-09-21T11:00:00Z"),
    )
    .expect("the fixture binds")
}

/// Build healthy observations matching the release.
pub fn observed(release: &ReleaseManifest, taken_at: DateTime<Utc>) -> Observations {
    let fleet = &release.resolved_fleet;
    let mut hosts = BTreeMap::new();
    for (id, host) in &fleet.hosts {
        let artifacts = &release.artifacts[id];
        let system = artifacts.toplevel.store_path.clone();
        // Include every probed unit as active.
        let units: BTreeMap<String, String> = meister_deploy::observe::ProbeSpec::for_host(host)
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
                boot_id: None,
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
                disk_free_nix_bytes: Some(40_000_000_000),
                pci: host
                    .hardware
                    .gpus
                    .iter()
                    .map(|gpu| PciDevice {
                        address: gpu.pci.clone(),
                        vendor_device: "10de:2684".to_string(),
                    })
                    .collect(),
                nics: host
                    .hardware
                    .nics
                    .iter()
                    .map(|nic| NetworkInterface {
                        name: nic.name.clone(),
                        mac: nic.mac.clone(),
                    })
                    .collect(),
                generation_units: host.units.clone(),
                unknown_reason: None,
            },
        );
    }
    Observations {
        schema: OBSERVATION_SCHEMA.to_string(),
        taken_at,
        provisional: false,
        hosts,
    }
}

fn etcd_view(fleet: &ResolvedFleet, id: &str) -> Option<EtcdView> {
    let host = fleet.hosts.get(id)?;
    let in_raft = host.groups.iter().any(|g| {
        fleet
            .groups
            .get(g)
            .map(|group| group.kind == meister_deploy::manifest::GroupKind::Raft)
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

// ---------------------------------------------------------------------------
// Seventy hosts
// ---------------------------------------------------------------------------

/// The four hardware classes the agents come in.
pub const CLASSES: [&str; 4] = ["compute-cpu", "compute-gpu", "compute-rdma", "compute-big"];

/// The three hosts that carry two roles at once.
pub const MULTI_ROLE: [&str; 3] = ["cluster-1-c", "cluster-2-b", "cluster-2-c"];

/// Generate 3 cloud controllers, 6 cluster controllers and 61 agents.
/// Three cluster controllers also carry the agent role. This models placement
/// and scheduling; it does not validate multi-role credential deployment.
pub fn fleet70_json() -> Value {
    let template = onebox_json();
    let controller = template["inventory"]["hosts"]["box"].clone();
    let controller_built = template["hosts"]["box"].clone();
    let agent = template["inventory"]["hosts"]["n1"].clone();
    let agent_built = template["hosts"]["n1"].clone();

    let mut inventory_hosts = serde_json::Map::new();
    let mut built_hosts = serde_json::Map::new();
    let mut groups = serde_json::Map::new();

    let add = |id: &str,
               inv: Value,
               built: Value,
               inventory_hosts: &mut serde_json::Map<String, Value>,
               built_hosts: &mut serde_json::Map<String, Value>| {
        inventory_hosts.insert(id.to_string(), inv);
        built_hosts.insert(id.to_string(), built);
    };

    // --- the three raft groups ---------------------------------------
    let raft: [(&str, Vec<String>, u8); 3] = [
        (
            "cloud",
            vec!["cloud-a".into(), "cloud-b".into(), "cloud-c".into()],
            1,
        ),
        (
            "cluster-1",
            vec![
                "cluster-1-a".into(),
                "cluster-1-b".into(),
                "cluster-1-c".into(),
            ],
            2,
        ),
        (
            "cluster-2",
            vec![
                "cluster-2-a".into(),
                "cluster-2-b".into(),
                "cluster-2-c".into(),
            ],
            3,
        ),
    ];
    for (group, members, subnet) in &raft {
        let peers: Vec<String> = members
            .iter()
            .enumerate()
            .map(|(i, m)| format!("{m}=https://10.0.{subnet}.{}:2380", 10 + i))
            .collect();
        for (i, id) in members.iter().enumerate() {
            let mut inv = controller.clone();
            let mut built = controller_built.clone();
            let address = format!("10.0.{subnet}.{}", 10 + i);
            inv["name"] = json!(id);
            inv["address"] = json!(address);
            inv["networks"]["management"]["address"] = json!(address);
            inv["groups"] = json!([group]);
            inv["controller_group"] = Value::Null;
            inv["modules"] = json!([]);
            inv["ssh"]["host_key_fingerprint"] = json!(format!("SHA256:enrolled-{id}"));
            inv["roles"] = if *group == "cloud" {
                json!(["cloud"])
            } else if MULTI_ROLE.contains(&id.as_str()) {
                // One machine, two tiers, one interruption.
                json!(["cluster", "agent"])
            } else {
                json!(["cluster"])
            };
            built["rollout"]["canary_class"] = json!("controller");
            built["effective_settings"]["etcd"] = json!({
                "name": id,
                "initial_cluster": peers.join(","),
            });
            built["build"]["toplevel_drv"] = json!(format!("/nix/store/base{id}-system-{id}.drv"));
            built["build"]["toplevel_out"] = json!(format!("/nix/store/base{id}-system-{id}"));
            add(id, inv, built, &mut inventory_hosts, &mut built_hosts);
        }
        groups.insert(
            (*group).to_string(),
            json!({
                "kind": "raft",
                "members": members,
                "quorum": {"size": members.len()},
                "profiles": ["base", "controller"],
                "rollout": {
                    "canary_class": "controller",
                    "max_unavailable": 1,
                    "reboot": "approve"
                }
            }),
        );
    }

    // --- sixty-one agents in four classes ------------------------------
    let mut by_class: BTreeMap<&str, Vec<String>> = BTreeMap::new();
    for index in 1..=61u32 {
        let id = format!("agent-{index:02}");
        let class = CLASSES[(index as usize - 1) % CLASSES.len()];
        let controller_group = if index % 2 == 0 {
            "cluster-1"
        } else {
            "cluster-2"
        };
        let mut inv = agent.clone();
        let mut built = agent_built.clone();
        let address = format!("10.0.9.{index}");
        inv["name"] = json!(id);
        inv["address"] = json!(address);
        inv["networks"]["management"]["address"] = json!(address);
        inv["groups"] = json!([class]);
        inv["controller_group"] = json!(controller_group);
        inv["ssh"]["host_key_fingerprint"] = json!(format!("SHA256:enrolled-{id}"));
        inv["profiles"] = json!(["base", class]);
        if class == "compute-gpu" {
            inv["hardware"]["gpus"] = json!([{
                "model": "NVIDIA RTX PRO 6000",
                "pci": "0000:41:00.0",
                "selected_for": "vfio"
            }]);
            inv["hardware"]["capabilities"] = json!(["kvm", "vfio"]);
        }
        if class == "compute-rdma" {
            inv["hardware"]["nics"] = json!([{
                "name": "mlx0", "mac": format!("b8:ce:f6:00:00:{index:02x}"),
                "role": "storage", "rdma": true
            }]);
            inv["hardware"]["capabilities"] = json!(["kvm", "rdma"]);
        }
        built["rollout"]["canary_class"] = json!(class);
        built["build"]["toplevel_drv"] = json!(format!("/nix/store/base{id}-system-{id}.drv"));
        built["build"]["toplevel_out"] = json!(format!("/nix/store/base{id}-system-{id}"));
        by_class.entry(class).or_default().push(id.clone());
        add(&id, inv, built, &mut inventory_hosts, &mut built_hosts);
    }
    for (class, members) in &by_class {
        groups.insert(
            (*class).to_string(),
            json!({
                "kind": "compute",
                "members": members,
                "quorum": Value::Null,
                "profiles": ["base", class],
                "rollout": {
                    "canary_class": class,
                    "max_unavailable": 2,
                    "reboot": "approve"
                }
            }),
        );
    }

    let mut manifest = template;
    manifest["inventory"]["fleet"]["name"] = json!("seventy");
    manifest["inventory"]["hosts"] = Value::Object(inventory_hosts);
    manifest["inventory"]["groups"] = Value::Object(groups);
    manifest["inventory"]["services"] = json!({});
    manifest["hosts"] = Value::Object(built_hosts);
    manifest
}

pub fn fleet70() -> ResolvedFleet {
    resolve_value(fleet70_json())
}

/// Render a healthy probe response for CLI tests using a fake SSH executable.
pub fn probe_answer(fleet: &ResolvedFleet, release: &ReleaseManifest, id: &str) -> String {
    use meister_deploy::observe::ProbeSpec;
    let host = &fleet.hosts[id];
    let artifacts = &release.artifacts[id];
    let spec = ProbeSpec::for_host(host);
    let system = &artifacts.toplevel.store_path;
    let mut s = String::from("probe=start\n");
    s.push_str(&format!("hostname={}\n", host.name));
    s.push_str(&format!("machine_id=machine-id-of-{id}\n"));
    s.push_str(&format!("current_system={system}\n"));
    s.push_str(&format!("booted_system={system}\n"));
    s.push_str(&format!("next_boot_system={system}\n"));
    s.push_str("generation=42\n");
    s.push_str(&format!(
        "kernel_running={}\n",
        host.build.boot.kernel_version
    ));
    s.push_str(&format!(
        "kernel_booted={}\n",
        artifacts.boot.kernel_store_path
    ));
    s.push_str(&format!(
        "initrd_booted={}\n",
        artifacts.boot.initrd_store_path
    ));
    s.push_str(&format!(
        "kernel_params_sha256={}\n",
        artifacts.boot.kernel_params_sha256
    ));
    for unit in &spec.units {
        s.push_str(&format!("unit={unit}\tactive\n"));
    }
    for path in &spec.mounts {
        s.push_str(&format!("mount={path}\t/dev/disk/by-label/data ext4\n"));
    }
    for cred in &spec.credentials {
        if cred.public {
            s.push_str(&format!("cred={}\tsha256:{}\n", cred.id, "ab".repeat(32)));
        } else {
            s.push_str(&format!(
                "cred={}\tmode:600 owner:meister:meister\n",
                cred.id
            ));
        }
    }
    for cert in &spec.identity_certs {
        s.push_str(&format!("identity_cert={cert}\tpresent\n"));
    }
    for cap in &host.hardware.capabilities {
        s.push_str(&format!("cap={cap}\n"));
    }
    // Provide sufficient disk space and the hardware/units declared by the release.
    s.push_str(&format!(
        "disk_free_nix={}\n",
        artifacts.toplevel.closure_size * 20
    ));
    for gpu in &host.hardware.gpus {
        s.push_str(&format!("pci={}\t10de:2684\n", gpu.pci));
    }
    // Include an unrelated device so an empty inventory cannot mean probe failure.
    s.push_str("pci=0000:00:01.0\t8086:1237\n");
    for nic in &host.hardware.nics {
        s.push_str(&format!("nic={}\t{}\n", nic.name, nic.mac));
    }
    s.push_str("nic=lo\t00:00:00:00:00:00\n");
    s.push_str(&format!("gen_units={}\n", host.units.join(" ")));
    if let Some(etcd) = &spec.etcd {
        let name = etcd.member_name.clone().unwrap_or_else(|| id.to_string());
        s.push_str(&format!(
            "etcd_members={{\"members\":[{{\"ID\":1,\"name\":\"{name}\",\
             \"peerURLs\":[\"https://{}:2380\"]}}]}}\n",
            host.address
        ));
        s.push_str("etcd_health=[{\"endpoint\":\"http://127.0.0.1:2379\",\"health\":true}]\n");
    }
    if spec.agent_socket.is_some() {
        s.push_str("vms=[]\n");
    }
    s.push_str("probe=end\n");
    s
}
