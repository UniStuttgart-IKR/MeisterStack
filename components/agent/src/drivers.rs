// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use crate::config::{
    AgentConfig, CloudHypervisorConfig, CrosvmGpuConfig, FilesystemVolumeConfig,
    LvmThinVolumeConfig, ManagedDevice, NfsVolumeConfig, NvrmConfig, Sections, section,
};
use crate::types::{DeviceWithId, VolumeWithId};
use agent_api::{
    Hypervisor, ResourceConfiner,
    device::DeviceDriver,
    networking::{BridgeDriver, NetworkDriver, NicDriver, RouteAnnouncer},
    storage::{Locality, SnapshotConsistency, VolumeDriver},
};
use anyhow::bail;
use crosvm_gpu_driver::CrosvmGpuDriver;
use filesystem_driver::FilesystemBlockDriver;
use linux_network_driver::LinuxNetworkDriver;
use lvm_thin_driver::LvmThinDriver;
use nfs_driver::NfsDriver;
use nvrm_driver::NvrmDriver;
use vfio_driver::VfioPciDriver;

pub const DRIVER_CROSVM_GPU: &str = "crosvm-gpu";
pub const DRIVER_NVRM: &str = "nvrm";
pub const DRIVER_VFIO: &str = "vfio";
pub const DRIVER_LVM_THIN: &str = "lvm-thin";
pub const DRIVER_NFS: &str = "nfs";
/// The attacher for namespaces that live somewhere else, and the first
/// consumer of `Locality::Networked`.
pub const DRIVER_NVMEOF: &str = "nvmeof";
/// Its provider half: namespaces that already exist, handed out.
pub const DRIVER_NVMEOF_IMPORT: &str = "nvmeof-import";
pub const DRIVER_CLOUD_HYPERVISOR: &str = "cloud-hypervisor";
/// The one networking driver there is — and the one driver name in this file
/// that is not also a config key. See `NETWORK_DRIVERS`.
pub const DRIVER_LINUX_NETWORK: &str = "linux";
/// The same string `agent_api::default_volume_driver()` returns — taken from
/// `common` so the name a spec omits and the name this table registers
/// cannot drift apart.
pub const DRIVER_FILESYSTEM: &str = common::capability::DEFAULT_VOLUME_DRIVER;
/// The one table key that is not a driver name: see `DriverEntry::keys`.
const KEY_MANAGED: &str = "managed";

/// One driver this agent can register: what a spec calls it, which sections
/// of `[volume]`/`[device]` it owns, and how to build it from them.
///
/// The two tables below are the ONLY place a new driver is added. Before
/// this there were two — a field on a config struct and an if-let in
/// `from_config` — and a driver wired into one but not the other was a
/// config key that parsed and then did nothing at all.
pub struct DriverEntry<T: ?Sized + 'static> {
    /// The name a spec uses.
    pub name: &'static str,
    /// The keys of the `[volume]`/`[device]` table this driver owns.
    /// Normally just its own name; vfio owns "managed", because its
    /// configuration is an inventory of host devices and not a setting of
    /// itself.
    pub keys: &'static [&'static str],
    /// Ok(None) = not configured on this node.
    pub build: fn(&Sections, &AgentConfig) -> anyhow::Result<Option<Arc<T>>>,
}

/// The storage backends this agent has. `filesystem` is the default driver
/// and the one row that registers with or without a section.
static VOLUME_DRIVERS: &[DriverEntry<dyn VolumeDriver>] = &[
    DriverEntry {
        name: DRIVER_FILESYSTEM,
        keys: &[DRIVER_FILESYSTEM],
        build: build_filesystem,
    },
    DriverEntry {
        name: DRIVER_LVM_THIN,
        keys: &[DRIVER_LVM_THIN],
        build: build_lvm_thin,
    },
    DriverEntry {
        name: DRIVER_NFS,
        keys: &[DRIVER_NFS],
        build: build_nfs,
    },
    DriverEntry {
        name: DRIVER_NVMEOF,
        keys: &[DRIVER_NVMEOF],
        build: build_nvmeof,
    },
    DriverEntry {
        name: DRIVER_NVMEOF_IMPORT,
        keys: &[DRIVER_NVMEOF_IMPORT],
        build: build_nvmeof_import,
    },
];

/// The device backends this agent has.
static DEVICE_DRIVERS: &[DriverEntry<dyn DeviceDriver>] = &[
    DriverEntry {
        name: DRIVER_CROSVM_GPU,
        keys: &[DRIVER_CROSVM_GPU],
        build: build_crosvm_gpu,
    },
    DriverEntry {
        name: DRIVER_NVRM,
        keys: &[DRIVER_NVRM],
        build: build_nvrm,
    },
    DriverEntry {
        name: DRIVER_VFIO,
        keys: &[KEY_MANAGED],
        build: build_vfio,
    },
];

/// The hypervisors this agent has.
///
/// One row, and a table anyway. Before this the choice was a `match` on a
/// config enum inside `from_config`, which is exactly the two-places shape
/// the volume and device tables were built to kill: a second hypervisor meant
/// an enum variant, a match arm, and a builder — three edits, of which the
/// forgotten one silently did nothing. Here it is a row, and the row is the
/// seam a container runtime (podman, LXC) docks onto without an
/// architectural change, because from this side "start this instance, under
/// this cgroup, with these attachments" is the same sentence either way.
static HYPERVISOR_DRIVERS: &[DriverEntry<dyn Hypervisor>] = &[DriverEntry {
    name: DRIVER_CLOUD_HYPERVISOR,
    keys: &[DRIVER_CLOUD_HYPERVISOR],
    build: build_cloud_hypervisor,
}];

/// The networking drivers this agent has.
///
/// `keys` is EMPTY, and this is the one row in the file where that is right:
/// `[network]` is a single section with a `default_bridge` in it, not a table
/// of one section per driver, and pretending otherwise would rename a key in
/// every config that exists. So this row owns no key, `register` finds no
/// unknown section to complain about, and what decides whether the driver is
/// built is the presence of `[network]` itself.
///
/// The row still earns its place. What varies between nodes today is the
/// uplink and the overlay, not which kernel does the bridging — but the next
/// driver (an OVN integration, a DPU offload) becomes a row here plus the
/// `[network.ovn]` section it owns, rather than a second `match` in
/// `from_config`.
static NETWORK_DRIVERS: &[DriverEntry<dyn NetworkDriver>] = &[DriverEntry {
    name: DRIVER_LINUX_NETWORK,
    keys: &[],
    build: build_linux_network,
}];

/// Build every driver in `entries` that this node's config asks for, keyed
/// by the name a spec routes on.
///
/// Both halves of the seam come through here — `T` is `dyn VolumeDriver` for
/// `[volume]` and `dyn DeviceDriver` for `[device]`, and the table is the
/// only difference between them.
fn register<T: ?Sized>(
    entries: &[DriverEntry<T>],
    sections: &Sections,
    cfg: &AgentConfig,
    what: &str,
) -> anyhow::Result<HashMap<String, Arc<T>>> {
    // A section no driver owns is a typo, and a typo that is ignored is a
    // node that comes up without the backend somebody configured — the
    // failure only shows up later, on the first VM that needed it. This is
    // what `deny_unknown_fields` did on the old config struct, except that
    // it can now say what this agent actually has. Sorted, so a config with
    // two bad sections reports the same one every time.
    let mut unknown: Vec<&str> = sections
        .keys()
        .map(String::as_str)
        .filter(|key| !entries.iter().any(|e| e.keys.contains(key)))
        .collect();
    unknown.sort_unstable();
    if let Some(key) = unknown.first() {
        let mut known: Vec<&str> = entries
            .iter()
            .flat_map(|e| e.keys.iter().copied())
            .collect();
        known.sort_unstable();
        bail!(
            "[{what}.{key}]: this agent has no {what} driver {key:?}; built in: {}",
            known.join(", ")
        );
    }

    let mut built: HashMap<String, Arc<T>> = HashMap::new();
    for entry in entries {
        if let Some(driver) = (entry.build)(sections, cfg)? {
            built.insert(entry.name.to_string(), driver);
        }
    }
    Ok(built)
}

/// The single-slot half of `register`: a node has at most ONE hypervisor and
/// at most one network driver.
///
/// Two configured rows is a refusal and not a coin toss — `register` returns
/// a map, and which of two entries a `HashMap` hands back first is not
/// something a node's behaviour may depend on. `None` is a node that
/// configured neither, which is now a legal thing for a node to be.
///
/// The row's NAME comes back with the driver. It is what the node claims in
/// its Hello (`hypervisor/cloud-hypervisor`), and taking it from the table
/// rather than asking the driver keeps one authority for the name: the same
/// string routes the config section and lands in the catalogue.
fn register_one<T: ?Sized>(
    entries: &[DriverEntry<T>],
    sections: &Sections,
    cfg: &AgentConfig,
    what: &str,
) -> anyhow::Result<Option<(String, Arc<T>)>> {
    let built = register(entries, sections, cfg, what)?;
    if built.len() > 1 {
        let mut names: Vec<&str> = built.keys().map(String::as_str).collect();
        names.sort_unstable();
        bail!(
            "this node configures {} {what} drivers ({}); exactly one may be configured",
            names.len(),
            names.join(", ")
        );
    }
    Ok(built.into_iter().next())
}

/// The default backend, and the one builder that never returns `None`: a
/// spec that names no driver has to keep meaning what it means on every
/// node, so this registers whether or not `[volume.filesystem]` is there.
/// The section only overrides where its files live.
fn build_filesystem(
    sections: &Sections,
    cfg: &AgentConfig,
) -> anyhow::Result<Option<Arc<dyn VolumeDriver>>> {
    let fs: Option<FilesystemVolumeConfig> = section(sections, "volume", DRIVER_FILESYSTEM)?;
    let driver = FilesystemBlockDriver::new(filesystem_driver::FilesystemDriverConfig {
        image_dir: fs
            .as_ref()
            .and_then(|f| f.image_dir.clone())
            .unwrap_or_else(|| cfg.paths.image_dir.clone()),
        volume_dir: fs
            .as_ref()
            .and_then(|f| f.volume_dir.clone())
            .unwrap_or_else(|| cfg.paths.volume_dir.clone()),
        qemu_img: fs
            .as_ref()
            .map(|f| f.qemu_img.clone())
            .unwrap_or_else(|| std::path::PathBuf::from("qemu-img")),
    })?;
    Ok(Some(Arc::new(driver)))
}

fn build_lvm_thin(
    sections: &Sections,
    cfg: &AgentConfig,
) -> anyhow::Result<Option<Arc<dyn VolumeDriver>>> {
    let Some(l): Option<LvmThinVolumeConfig> = section(sections, "volume", DRIVER_LVM_THIN)? else {
        return Ok(None);
    };
    let driver = LvmThinDriver::new(lvm_thin_driver::LvmThinDriverConfig {
        vg: l.vg.clone(),
        thin_pool: l.thin_pool.clone(),
        max_data_percent: l.max_data_percent,
        image_dir: l
            .image_dir
            .clone()
            .unwrap_or_else(|| cfg.paths.image_dir.clone()),
        bin_dir: l.bin_dir.clone(),
        qemu_img: l.qemu_img.clone(),
    })?;
    Ok(Some(Arc::new(driver)))
}

fn build_nvmeof(
    sections: &Sections,
    _cfg: &AgentConfig,
) -> anyhow::Result<Option<Arc<dyn VolumeDriver>>> {
    let Some(n): Option<crate::config::NvmeofVolumeConfig> =
        section(sections, "volume", DRIVER_NVMEOF)?
    else {
        return Ok(None);
    };
    Ok(Some(Arc::new(nvmeof_driver::NvmeofAttacher::new(
        nvmeof_driver::NvmeofAttacherConfig {
            bin_dir: n.bin_dir.clone(),
        },
    ))))
}

fn build_nvmeof_import(
    sections: &Sections,
    cfg: &AgentConfig,
) -> anyhow::Result<Option<Arc<dyn VolumeDriver>>> {
    let Some(n): Option<crate::config::NvmeofImportVolumeConfig> =
        section(sections, "volume", DRIVER_NVMEOF_IMPORT)?
    else {
        return Ok(None);
    };
    // Beside the agent's own database, because the assignment is state of
    // exactly that kind: small, this node's, and worthless to anybody else.
    let state_dir = n.state_dir.clone().unwrap_or_else(|| {
        cfg.paths
            .db_path
            .parent()
            .unwrap_or(std::path::Path::new("."))
            .join("nvmeof-import")
    });
    Ok(Some(Arc::new(
        nvmeof_import_driver::NvmeofImportDriver::new(nvmeof_import_driver::NvmeofImportConfig {
            state_dir,
            bin_dir: n.bin_dir.clone(),
        }),
    )))
}

fn build_nfs(
    sections: &Sections,
    cfg: &AgentConfig,
) -> anyhow::Result<Option<Arc<dyn VolumeDriver>>> {
    let Some(n): Option<NfsVolumeConfig> = section(sections, "volume", DRIVER_NFS)? else {
        return Ok(None);
    };
    let driver = NfsDriver::new(nfs_driver::NfsDriverConfig {
        share_root: n.share_root.clone(),
        image_dir: n
            .image_dir
            .clone()
            .unwrap_or_else(|| cfg.paths.image_dir.clone()),
        virtiofsd: n.virtiofsd.clone(),
        run_dir: cfg.paths.run_dir.join("virtiofs"),
        socket_timeout: Duration::from_millis(n.socket_timeout_ms),
        virtiofsd_args: n.virtiofsd_args.clone(),
        manage_mount: n.manage_mount,
        mount: n.mount_spec()?,
    })?;
    Ok(Some(Arc::new(driver)))
}

fn build_crosvm_gpu(
    sections: &Sections,
    cfg: &AgentConfig,
) -> anyhow::Result<Option<Arc<dyn DeviceDriver>>> {
    let Some(g): Option<CrosvmGpuConfig> = section(sections, "device", DRIVER_CROSVM_GPU)? else {
        return Ok(None);
    };
    let driver = CrosvmGpuDriver::new(crosvm_gpu_driver::CrosvmGpuDriverConfig {
        crosvm_bin: g.binary.clone(),
        run_dir: cfg.paths.run_dir.join("gpu"),
        defaults: g.defaults.clone(),
        profiles: g.profiles.clone(),
        socket_timeout: Duration::from_millis(g.socket_timeout_ms),
    })?;
    Ok(Some(Arc::new(driver)))
}

fn build_nvrm(
    sections: &Sections,
    cfg: &AgentConfig,
) -> anyhow::Result<Option<Arc<dyn DeviceDriver>>> {
    let Some(n): Option<NvrmConfig> = section(sections, "device", DRIVER_NVRM)? else {
        return Ok(None);
    };
    let driver = NvrmDriver::new(nvrm_driver::NvrmDriverConfig {
        binary: n.binary.clone(),
        vgpuprofile_bin: n.vgpuprofile.clone(),
        run_dir: cfg.paths.run_dir.join("nvrm"),
        socket_timeout: Duration::from_millis(n.socket_timeout_ms),
        vram_budget_mib: n.vram_budget_mib,
        defaults: n.defaults.clone(),
        profiles: n.profiles.clone(),
    })?;
    Ok(Some(Arc::new(driver)))
}

/// The odd row: vfio's section is an inventory of host devices rather than a
/// setting of its own, so it owns the key `managed`. No inventory, or an
/// empty one, means nothing on this node is passthrough-able — which is not
/// the same as a driver that failed to configure, so it is `Ok(None)`.
fn build_vfio(
    sections: &Sections,
    _cfg: &AgentConfig,
) -> anyhow::Result<Option<Arc<dyn DeviceDriver>>> {
    let managed: Vec<ManagedDevice> = section(sections, "device", KEY_MANAGED)?.unwrap_or_default();
    let inventory: Vec<_> = managed.iter().map(|m| m.pci_address()).collect();
    if inventory.is_empty() {
        return Ok(None);
    }
    Ok(Some(Arc::new(VfioPciDriver::new(inventory)?)))
}

fn build_cloud_hypervisor(
    sections: &Sections,
    cfg: &AgentConfig,
) -> anyhow::Result<Option<Arc<dyn Hypervisor>>> {
    let Some(h): Option<CloudHypervisorConfig> =
        section(sections, "hypervisor", DRIVER_CLOUD_HYPERVISOR)?
    else {
        return Ok(None);
    };
    // Asked here and not at the first migration: a typo in the range would
    // otherwise be found by an operator draining a node, at the moment they
    // can least afford to read a parse error.
    h.ports()
        .map_err(|why| anyhow::anyhow!("[hypervisor.cloud-hypervisor]: {why}"))?;
    let driver = cloud_hypervisor_driver::CloudHypervisorDriver::new(
        h.binary.clone(),
        cfg.paths.run_dir.join("vms"),
        Duration::from_millis(h.timeout_ms),
        h.unplug_timeout(),
    )?;
    Ok(Some(Arc::new(driver)))
}

/// The one builder whose `Ok(None)` is decided by a section its table does
/// not own: `[network]`. See `NETWORK_DRIVERS`.
fn build_linux_network(
    _sections: &Sections,
    cfg: &AgentConfig,
) -> anyhow::Result<Option<Arc<dyn NetworkDriver>>> {
    let Some(network) = &cfg.network else {
        return Ok(None);
    };
    let vxlan = network
        .vxlan
        .as_ref()
        .map(|v| linux_network_driver::VxlanConfig {
            uplink: v.uplink.clone(),
            mtu: v.mtu,
            evpn: v.evpn,
        });
    Ok(Some(Arc::new(LinuxNetworkDriver::build(
        vxlan,
        cfg.nft_config()?,
        cfg.provider_config(),
    )?)))
}

/// Which network capabilities this node has, for the same two reasons the
/// volume catalogue exists: an unservable spec should be a rejected spec at
/// the edge rather than a VM torn down halfway through, and the scheduler one
/// tier up has to be able to keep such a VM away from this node entirely.
///
/// One entry so far. It is a list and not a bool because the next one —
/// Geneve, an OVN integration, whatever the DPU track wants — is a profile
/// beside it and not a second mechanism.
#[derive(Clone, Debug, Default)]
pub struct NetworkCatalog {
    profiles: Vec<String>,
    /// Whether this node built a NIC driver at all — the plainer half of the
    /// same question the profiles answer, and the one `validate` needs.
    ///
    /// From the registered slot rather than from the config, for the reason
    /// `HypervisorCatalog::new` gives about its own: what a node claims has
    /// to be what it actually built. `Drivers::networking` and
    /// `Drivers::bridge` are `Some` together or `None` together, so one bool
    /// answers for both.
    ///
    /// `false` on a `Default` catalogue, which is what a test that never
    /// mentions networking means by one.
    makes_taps: bool,
}

impl NetworkCatalog {
    /// `None` — a node with no `[network]` section — claims nothing, which
    /// is the same answer a node with a section and no overlay gives. The two
    /// are different configurations and the same capability: neither can
    /// carry a tenant overlay, and the catalogue is about what a node can
    /// serve rather than about how it is written down.
    pub fn new(
        cfg: Option<&crate::config::NetworkConfig>,
        makes_taps: bool,
        physnets: &[String],
    ) -> Self {
        let mut profiles = Vec::new();
        if let Some(vxlan) = cfg.and_then(|c| c.vxlan.as_ref()) {
            profiles.push(common::capability::VXLAN.to_string());
            // A second entry beside `vxlan` and never instead of it: a VM asks
            // for an overlay, and a node that dropped `network/vxlan` when it
            // turned evpn on would stop being a candidate for the very VMs it
            // serves best. This one is for the operator reading
            // `meister node ls` — evpn is a cluster-wide decision (see
            // `VxlanConfig::evpn`), and the only thing that can enforce it is
            // somebody being able to see who is on which side.
            if vxlan.evpn {
                profiles.push(common::capability::EVPN.to_string());
            }
        }
        // Floating addresses and routed subnets get NO entry, and that is a
        // decision rather than an omission: a catalogue entry exists so the
        // scheduler can keep a VM away from a node that cannot serve it, and
        // every node serves these. The rules are built from the spec on
        // whatever node the VM lands on, `guarded_ranges` is the same list
        // everywhere, and a VM that asked for `network/floating` would be a VM
        // constrained by nothing. `[network.bgp]` gets none either, for a
        // sharper version of the same reason: a floating address whose node
        // does not announce it is still reserved and still enforced — it is
        // reached by a static route instead — so announcing is a property of
        // the environment and not a requirement of the VM.
        // Festlegung 2: the gateway is a capability out of the config, not an
        // agent of its own. One entry per provider network this node gave an
        // interface away to, named after the network and not after the
        // interface — two nodes saying `ext` mean the same wire, and which
        // interface each of them uses to reach it is nobody else's business.
        //
        // Off the DRIVER's list and not off the config file, for the reason
        // `makes_taps` is a bool from the registered slot: what a node claims
        // has to be what it actually built. A physnet whose bridge name the
        // driver refused never reaches this list, because the driver refused
        // to come up at all.
        profiles.extend(
            physnets
                .iter()
                .map(|physnet| common::capability::gateway_claim(physnet)),
        );
        Self {
            profiles,
            makes_taps,
        }
    }

    /// The provider networks this node claims, by name. What a router's
    /// physnet is checked against before an `EnsureRouter` reaches the driver.
    pub fn physnets(&self) -> Vec<&str> {
        self.profiles
            .iter()
            .filter_map(|p| common::capability::parse_gateway_claim(p))
            .collect()
    }

    /// Whether a router on `physnet` could be built here at all.
    pub fn serves_physnet(&self, physnet: &str) -> bool {
        self.physnets().contains(&physnet)
    }

    /// What this node claims about its networking, for the Hello. Empty is a
    /// node with no overlay, and an empty profile list is what makes the
    /// `network` pseudo-driver contribute no catalogue entry at all — the
    /// same shape a device driver with no profiles would have.
    pub fn inventory(&self) -> Vec<String> {
        self.profiles.clone()
    }

    pub fn serves_overlays(&self) -> bool {
        self.profiles.iter().any(|p| p == common::capability::VXLAN)
    }

    /// Whether a router on `physnet` could be built here at all.
    ///
    /// Structural in the same sense the four catalogues are: "this node gave
    /// no interface away to `ext`" will not be different on the next attempt,
    /// so the refusal carries `CannotServe` and the tier above stops counting
    /// this node as a candidate. Everything the DRIVER refuses afterwards is
    /// about the attempt.
    pub fn validate_router(&self, physnet: &str) -> anyhow::Result<()> {
        if self.serves_physnet(physnet) {
            return Ok(());
        }
        let mut have = self.physnets();
        have.sort_unstable();
        bail!(
            "this node has no gateway slot on the provider network {physnet:?}; it gave away \
             [{}]",
            have.join(", ")
        )
    }

    /// A spec that asks for an overlay this node cannot join is a 422 on the
    /// REST path and a refused Create on the session — never a VM quietly
    /// placed on the default bridge, where it would reach every other tenant
    /// on this host.
    ///
    /// And, since this position, the cruder question first: a NIC at all on a
    /// node that makes no taps. That refusal existed already — it came out of
    /// `Drivers::networking()` deep inside `run_chain` — but it came out
    /// THERE, which is after the point where a refusal can still be called
    /// structural. Everything the four catalogues refuse carries
    /// `CannotServe` and gives the binding back; everything `run_chain`
    /// refuses is a `Failed` VM that stays bound to the node that cannot run
    /// it. The fact is the same either way — this node has no `[network]`
    /// section and will not grow one on the next attempt — so it belongs on
    /// the side that says so.
    pub fn validate(&self, nics: &[crate::types::NicWithId]) -> anyhow::Result<()> {
        if !nics.is_empty() && !self.makes_taps {
            bail!(
                "this node has no [network] section and so makes no taps; a vm with {} nic(s) \
                 cannot run here",
                nics.len()
            );
        }
        for n in nics {
            // Festlegung 3: a NIC names one wire. The driver refuses the pair
            // too, at the tap -- but a refusal there is a Failed VM bound to
            // this node, and this one is structural and gives the binding
            // back.
            if let (Some(physnet), Some(vni)) = (&n.spec.physnet, n.spec.vxlan_id) {
                bail!(
                    "nic names the provider network {physnet:?} and the overlay {vni}; a tap \
                     hangs on one wire, so name one of the two"
                );
            }
            if let Some(physnet) = &n.spec.physnet
                && !self.serves_physnet(physnet)
            {
                let mut have = self.physnets();
                have.sort_unstable();
                bail!(
                    "nic asks for the provider network {physnet:?}, and this node gave away \
                     [{}]",
                    have.join(", ")
                );
            }
            let Some(vni) = n.spec.vxlan_id else { continue };
            if !self.serves_overlays() {
                bail!(
                    "nic asks for vxlan {vni}, but this node has no [network.vxlan] section \
                     and so serves no overlays"
                );
            }
        }
        Ok(())
    }
}

#[derive(Clone)]
pub struct Drivers {
    /// The one slot that stays mandatory. A storage node wants its NVMe-oF
    /// target process inside a cgroup exactly as a compute node wants its
    /// VMMs there, so there is no configuration in which confinement is
    /// optional.
    pub confiner: Arc<dyn ResourceConfiner>,
    /// `None` = this node runs no VMs. See `Drivers::hypervisor`.
    pub hypervisor: Option<Arc<dyn Hypervisor>>,
    /// Which row of `HYPERVISOR_DRIVERS` built it — `Some` exactly when
    /// `hypervisor` is, both set from one `register_one` call. The catalogue
    /// claims it as `hypervisor/<name>`.
    pub hypervisor_name: Option<String>,
    /// Keyed by driver name, exactly as `devices` is: `spec.driver` routes,
    /// `None` means `default_volume_driver()`, and that entry always exists.
    pub storage: HashMap<String, Arc<dyn VolumeDriver>>,
    /// `None` = this node makes no taps. Both of these are upcasts of one
    /// `Arc<dyn NetworkDriver>` and are therefore Some together or None
    /// together; see `agent_api::networking::NetworkDriver`.
    pub networking: Option<Arc<dyn NicDriver>>,
    pub bridge: Option<Arc<dyn BridgeDriver>>,
    /// Who to tell which addresses live on this node. `None` = no
    /// `[network.bgp]` section, which is every node before M5.1: the floating
    /// addresses are still reserved and still enforced at the tap, and how
    /// they are reached is the environment's static route or a tenant
    /// appliance rather than a session with a router.
    pub announcer: Option<Arc<dyn RouteAnnouncer>>,
    pub devices: HashMap<String, Arc<dyn DeviceDriver>>,
}

impl Drivers {
    pub async fn from_config(cfg: &AgentConfig) -> anyhow::Result<Self> {
        // What a node is FOR: it runs VMs, or it serves volumes, or both.
        //
        // Asked of the CONFIG and before anything is built, because it is a
        // question about the config: a node that serves nothing should not
        // spend a start-up finding drivers for it.
        //
        // The storage half is `[volume.*]` and not the built `storage` map,
        // which would always be non-empty — `filesystem` registers on every
        // node whether or not it is configured, so that `driver: None` in a
        // VM spec keeps meaning something everywhere. That default exists for
        // VMs; a node with no hypervisor has none, and an unconfigured
        // fallback backend is not a declaration that this machine serves
        // storage to anybody.
        //
        // Fail fast, the same sort as the missing `nft`: a node that comes up
        // serving nothing is one an operator finds out about from a VM that
        // never gets placed, days later, on a cluster where it looks like a
        // scheduling problem.
        //
        // Devices and networking alone are deliberately NOT a node. That
        // changes the day PCIe-over-fabric arrives, and it changes by adding
        // one disjunct here.
        if cfg.hypervisor.is_empty() && cfg.volume.is_empty() {
            bail!(
                "this agent serves nothing: it has no [hypervisor.*] section, so it runs no \
                 vms, and no [volume.*] section, so it offers no storage. Configure one or \
                 the other"
            );
        }

        let confiner = Arc::new(cgroup_driver::CgroupV2::new(cfg.paths.cgroup_root.clone()));

        // All four slots come out of tables now, and the two that used to be
        // hard-wired are the reason: a node used to be assumed to run VMs and
        // to make taps, and that assumption is what kept a volume tied to the
        // VM it was made for. A storage node has neither.
        let (hypervisor_name, hypervisor) =
            register_one(HYPERVISOR_DRIVERS, &cfg.hypervisor, cfg, "hypervisor")?.unzip();
        let storage = register(VOLUME_DRIVERS, &cfg.volume, cfg, "volume")?;
        let devices = register(DEVICE_DRIVERS, &cfg.device, cfg, "device")?;
        // `[network]` is not a table of sections, so there is none to check
        // against; the row's own builder reads `cfg.network`. See
        // `NETWORK_DRIVERS`.
        let net: Option<Arc<dyn NetworkDriver>> =
            register_one(NETWORK_DRIVERS, &Sections::new(), cfg, "network")?.map(|(_, n)| n);
        // One pointer, two views of it. Upcasts rather than two registrations:
        // a tap and the bridge it joins are made by the same driver on the
        // same node, and two independently configured halves would be a state
        // this node can be in and cannot recover from.
        let networking: Option<Arc<dyn NicDriver>> = net.clone().map(|n| n as Arc<dyn NicDriver>);
        let bridge: Option<Arc<dyn BridgeDriver>> = net.map(|n| n as Arc<dyn BridgeDriver>);

        // Built here and not lazily, so a node whose config claims it
        // announces routes finds out at start-up that FRR is not answering —
        // the same fail-fast the lvm-thin driver applies to its pool.
        let announcer: Option<Arc<dyn RouteAnnouncer>> = match cfg.bgp_config()? {
            Some(bgp) => Some(Arc::new(linux_network_driver::frr::Frr::new(bgp).await?)),
            None => None,
        };

        Ok(Self {
            confiner,
            hypervisor,
            hypervisor_name,
            storage,
            networking,
            bridge,
            announcer,
            devices,
        })
    }

    /// The hypervisor, or the sentence this node owes whoever asked it to run
    /// a VM.
    ///
    /// Every VM path goes through here rather than through an `expect`: a
    /// node without one is a legal configuration now, so the absence is an
    /// answer to give and not an invariant to assert. The message names the
    /// section, because the fix is one.
    pub fn hypervisor(&self) -> anyhow::Result<&Arc<dyn Hypervisor>> {
        self.hypervisor.as_ref().ok_or_else(|| {
            anyhow::anyhow!(
                "this node has no [hypervisor.*] section and so runs no vms; it was asked to \
                 run one anyway"
            )
        })
    }

    /// The tap half of the networking driver, or the same kind of sentence.
    pub fn networking(&self) -> anyhow::Result<&Arc<dyn NicDriver>> {
        self.networking.as_ref().ok_or_else(|| {
            anyhow::anyhow!(
                "this node has no [network] section and so makes no taps; a vm with a nic \
                 cannot run here"
            )
        })
    }

    /// The bridge half. Some exactly when `networking` is — see the field.
    pub fn bridge(&self) -> anyhow::Result<&Arc<dyn BridgeDriver>> {
        self.bridge.as_ref().ok_or_else(|| {
            anyhow::anyhow!(
                "this node has no [network] section and so makes no bridges; a vm with a nic \
                 cannot run here"
            )
        })
    }
}

/// Whether this node runs VMs at all, and with what.
///
/// The thinnest of the four catalogues, and the one whose ABSENCE carries the
/// information. Before the driver slots became optional, every node ran VMs,
/// so there was nothing to claim and nothing that could be missing. Now a
/// storage node exists, and without an entry it would look to a scheduler
/// exactly like a compute node with room: the first VM asking for nothing in
/// particular would be placed there and fail at the first `create`.
#[derive(Clone, Debug, Default)]
pub struct HypervisorCatalog {
    /// The configured driver's name, or `None` on a node that runs no VMs.
    driver: Option<String>,
}

impl HypervisorCatalog {
    /// From the registered slot rather than from the config, so that what a
    /// node CLAIMS is what it actually built. A section that failed to
    /// produce a driver never reaches here at all — `from_config` refuses to
    /// start — and the name is the table row's, which is also the config key
    /// that selected it.
    pub fn new(name: Option<&str>) -> Self {
        Self {
            driver: name.map(str::to_string),
        }
    }

    /// What this node claims about its hypervisor, for the Hello: one profile
    /// or none at all. Shaped like the volume catalogue's, so the flattening
    /// one tier up needs no new rule — `hypervisor/cloud-hypervisor` goes
    /// through exactly the path `volume/lvm-thin` goes through.
    pub fn inventory(&self) -> Vec<String> {
        self.driver.iter().cloned().collect()
    }

    /// A VM on a node that runs none is a refused spec at the edge rather
    /// than a VM whose volumes and taps are built and then torn down again.
    /// Same trade the other three catalogues make.
    ///
    /// Takes no spec because there is nothing in a spec to check: a VM needs
    /// a hypervisor, all of them do, and which one is the node's business.
    pub fn validate(&self) -> anyhow::Result<()> {
        if self.driver.is_none() {
            bail!(
                "this node has no [hypervisor.*] section and so runs no vms; it offers \
                 storage only"
            );
        }
        Ok(())
    }
}

/// Which storage backends this node has, for the same reason `DeviceCatalog`
/// exists: an unknown driver name should be a rejected spec at the edge, not
/// a VM that gets half-provisioned and then torn down again.
#[derive(Clone, Debug)]
pub struct VolumeCatalog {
    /// Backend name and what that backend says about where its bytes are,
    /// sorted by name so the Hello is byte-identical across restarts.
    ///
    /// The locality is asked ONCE, here, and never again: it is a property of
    /// the driver, so a value read per Hello would be the same value read
    /// again. Keeping it beside the name is also what makes the two travel
    /// together — a catalogue entry without its locality is exactly the
    /// half-statement the pool status would then have to guess at.
    drivers: Vec<(String, Locality)>,
    /// The backends that can take a point-in-time copy, and what each needs
    /// to make one worth having. Asked once for the same reason the locality
    /// is: it is a property of the driver.
    snapshots: Vec<(String, SnapshotConsistency)>,
}

impl VolumeCatalog {
    pub fn new(storage: &HashMap<String, Arc<dyn VolumeDriver>>) -> Self {
        let mut drivers: Vec<(String, Locality)> = storage
            .iter()
            .map(|(name, driver)| (name.clone(), driver.locality()))
            .collect();
        drivers.sort_unstable_by(|a, b| a.0.cmp(&b.0));
        let mut snapshots: Vec<(String, SnapshotConsistency)> = storage
            .iter()
            .filter_map(|(name, driver)| Some((name.clone(), driver.snapshot_support()?)))
            .collect();
        snapshots.sort_unstable_by(|a, b| a.0.cmp(&b.0));
        Self { drivers, snapshots }
    }

    /// Backend name and locality, in the order the Hello sends them.
    pub fn localities(&self) -> &[(String, Locality)] {
        &self.drivers
    }

    /// The snapshot half of the claim: `<backend>/snapshot` for every backend
    /// that answered `snapshot_support`, flattening one tier up into
    /// `volume/<backend>/snapshot`.
    ///
    /// The same spelling a GPU profile claims, and that is the whole point:
    /// the tier above already knows how to ask a catalogue whether a node
    /// offers `<driver>/<profile>`, so a pool whose driver cannot snapshot is
    /// refused where a person can still read the refusal rather than becoming
    /// a `Failed` object twenty seconds later.
    ///
    /// The CONSISTENCY travels beside it, as a second profile:
    /// `<backend>/snapshot:atomic` or `<backend>/snapshot:needs-quiesce`.
    ///
    /// It did not, and the reason it has to now is that a backend's answer
    /// stopped being a property of its NAME. `filesystem` reflinks on XFS and
    /// btrfs and copies on ext4 — the same driver, two answers, decided by
    /// the pool's own mount — so the tier that pauses a guest cannot get it
    /// from `pool.spec.driver` any more. The node is the only party that
    /// knows, and the claim is how a node says what it knows.
    ///
    /// BESIDE and never instead of: the bare `<backend>/snapshot` is what
    /// every reader built so far matches on, and a node that stopped emitting
    /// it would have its pools refused by a cluster one release older. Same
    /// mixed-version trap `capability::HYPERVISOR` describes, same answer —
    /// claiming is additive and safe, replacing is not.
    pub fn snapshot_claims(&self) -> Vec<String> {
        self.snapshots
            .iter()
            .flat_map(|(name, consistency)| {
                [
                    format!("{name}/{}", common::capability::SNAPSHOT),
                    common::capability::snapshot_claim(name, *consistency),
                ]
            })
            .collect()
    }

    /// What this backend needs to make a snapshot worth having, or `None`
    /// where it cannot make one at all. What the agent asks before it decides
    /// whether to pause a VM.
    pub fn snapshot_support(&self, backend: &str) -> Option<SnapshotConsistency> {
        self.snapshots
            .iter()
            .find(|(name, _)| name == backend)
            .map(|(_, c)| *c)
    }

    /// What this node claims about its storage, for the Hello.
    ///
    /// One capability driver with one profile per backend — `volume/lvm-thin`
    /// and not `lvm-thin` — because the catalogue is a flat list of
    /// `<driver>/<profile>` strings shared with the device half, and a bare
    /// `lvm-thin` in it would collide with a device driver of that name and
    /// answer a device request nobody could serve. The `filesystem` entry is
    /// in there too: every node has it, so it never decides a placement, but
    /// leaving it out would make `meister node ls` lie about what a
    /// node can do.
    pub fn inventory(&self) -> Vec<String> {
        self.drivers.iter().map(|(name, _)| name.clone()).collect()
    }

    pub fn validate(&self, volumes: &[VolumeWithId]) -> anyhow::Result<()> {
        for v in volumes {
            self.validate_driver(v.spec.driver.as_deref())?;
        }
        Ok(())
    }

    /// One backend name, or none. The half of `validate` a standalone volume
    /// needs: it has one spec rather than a list, and refusing it at the edge
    /// is worth exactly as much — a Provision that names a backend this node
    /// does not have should be a refused command, not a Failed volume.
    pub fn validate_driver(&self, driver: Option<&str>) -> anyhow::Result<()> {
        // None is the default driver, which is always registered.
        let Some(driver) = driver else {
            return Ok(());
        };
        if !self.drivers.iter().any(|(d, _)| d == driver) {
            bail!(
                "volume driver {driver:?} is not configured on this node; available: [{}]",
                self.inventory().join(", ")
            );
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct DeviceCatalog {
    profiles: HashMap<String, Vec<String>>,
}

impl DeviceCatalog {
    pub fn new(devices: &HashMap<String, Arc<dyn DeviceDriver>>) -> Self {
        Self {
            profiles: devices
                .iter()
                .map(|(name, driver)| (name.clone(), driver.profiles()))
                .collect(),
        }
    }

    /// The node's device capability, sorted for a stable Hello: every
    /// configured driver with the profiles it can resolve.
    pub fn inventory(&self) -> Vec<(String, Vec<String>)> {
        let mut out: Vec<(String, Vec<String>)> = self
            .profiles
            .iter()
            .map(|(name, profiles)| {
                let mut profiles = profiles.clone();
                profiles.sort_unstable();
                (name.clone(), profiles)
            })
            .collect();
        out.sort_unstable_by(|a, b| a.0.cmp(&b.0));
        out
    }

    fn driver_names(&self) -> String {
        let mut names: Vec<&str> = self.profiles.keys().map(String::as_str).collect();
        names.sort_unstable();
        if names.is_empty() {
            "<none>".to_string()
        } else {
            names.join(", ")
        }
    }

    pub fn validate(&self, devices: &[DeviceWithId]) -> anyhow::Result<()> {
        for d in devices {
            let Some(profiles) = self.profiles.get(&d.spec.driver) else {
                bail!(
                    "device driver {:?} is not configured on this node; available: [{}]",
                    d.spec.driver,
                    self.driver_names()
                );
            };
            if let Some(profile) = &d.spec.profile
                && !profiles.iter().any(|p| p == profile)
            {
                bail!(
                    "device driver {:?} has no profile {:?}; configured profiles: [{}]",
                    d.spec.driver,
                    profile,
                    profiles.join(", ")
                );
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::VolumeWithId;
    use agent_api::storage::SnapshotConsistency;
    use agent_api::storage::{
        VolumeAttacher, VolumeHandle, VolumeProvider, VolumeSpec, VolumeState,
    };

    struct Stub(Locality, Option<SnapshotConsistency>);

    #[async_trait::async_trait]
    impl VolumeProvider for Stub {
        fn locality(&self) -> Locality {
            self.0
        }

        fn snapshot_support(&self) -> Option<SnapshotConsistency> {
            self.1
        }

        async fn provision(
            &self,
            _: &agent_api::VolumeId,
            _: &VolumeSpec,
        ) -> agent_api::storage::Result<VolumeHandle> {
            unreachable!("the catalogue never provisions anything")
        }
        async fn deprovision(&self, _: &VolumeHandle) -> agent_api::storage::Result<()> {
            unreachable!()
        }
        async fn describe(&self, _: &VolumeHandle) -> agent_api::storage::Result<VolumeState> {
            unreachable!()
        }
    }

    #[async_trait::async_trait]
    impl VolumeAttacher for Stub {
        async fn attach(
            &self,
            _: &VolumeHandle,
            _: Option<&agent_api::CgroupHandle>,
        ) -> agent_api::storage::Result<agent_api::VolumeAttachment> {
            unreachable!()
        }
        async fn stat(
            &self,
            _: &VolumeHandle,
            _: &agent_api::VolumeAttachment,
        ) -> agent_api::storage::Result<VolumeState> {
            unreachable!()
        }
    }

    fn catalogue(names: &[&str]) -> VolumeCatalog {
        localities(
            &names
                .iter()
                .map(|n| (*n, Locality::NodeLocal))
                .collect::<Vec<_>>(),
        )
    }

    fn localities(named: &[(&str, Locality)]) -> VolumeCatalog {
        let mut map: HashMap<String, Arc<dyn VolumeDriver>> = HashMap::new();
        for (n, l) in named {
            map.insert(n.to_string(), Arc::new(Stub(*l, None)));
        }
        VolumeCatalog::new(&map)
    }

    fn volume(driver: Option<&str>) -> VolumeWithId {
        VolumeWithId {
            referenced: false,
            id: uuid::Uuid::nil(),
            spec: VolumeSpec {
                base_image: None,
                size_bytes: 1,
                driver: driver.map(str::to_string),
                params: None,
            },
        }
    }

    /// Locality is asked of the DRIVER once and travels beside the name, so
    /// that a Hello can say `volume/nfs` and `shared` in one entry. The
    /// inventory itself is unchanged by carrying it.
    #[test]
    fn the_catalogue_carries_each_backends_locality_beside_its_name() {
        let cat = localities(&[
            ("nfs", Locality::Shared),
            ("filesystem", Locality::NodeLocal),
            ("lvm-thin", Locality::NodeLocal),
        ]);
        assert_eq!(cat.inventory(), vec!["filesystem", "lvm-thin", "nfs"]);
        assert_eq!(
            cat.localities(),
            &[
                ("filesystem".to_string(), Locality::NodeLocal),
                ("lvm-thin".to_string(), Locality::NodeLocal),
                ("nfs".to_string(), Locality::Shared),
            ],
            "sorted by name, so a Hello is byte-identical across restarts"
        );
    }

    /// An unknown backend is a rejected spec at the edge — a 422 on the REST
    /// path and a refused Create on the session — rather than a VM that gets
    /// half-provisioned and torn down again. Same trade the device catalogue
    /// makes, for the same reason.
    #[test]
    fn an_unconfigured_volume_driver_is_refused_by_name() {
        let cat = catalogue(&["filesystem"]);
        let err = cat
            .validate(&[volume(Some("lvm-thin"))])
            .unwrap_err()
            .to_string();
        assert!(err.contains("lvm-thin"), "{err}");
        assert!(
            err.contains("filesystem"),
            "the message must say what IS available: {err}"
        );
    }

    /// What the node claims is sorted and complete, and the scheduler one
    /// tier up finds exactly the drivers this node registered — the same
    /// round trip the device catalogue's test makes, through the same
    /// `common::capability` spelling.
    #[test]
    fn the_inventory_is_what_a_scheduler_matches_against() {
        let cat = catalogue(&["nfs", "filesystem", "lvm-thin"]);
        assert_eq!(cat.inventory(), vec!["filesystem", "lvm-thin", "nfs"]);

        let catalogue: Vec<String> = cat
            .inventory()
            .iter()
            .map(|d| common::capability::entry(common::capability::VOLUME, Some(d)))
            .collect();
        let volume = common::capability::VOLUME;
        assert!(common::capability::offers(
            &catalogue,
            volume,
            Some("lvm-thin")
        ));
        assert!(!common::capability::offers(
            &catalogue,
            volume,
            Some("ceph")
        ));
        // and the bare driver name is NOT in the catalogue: `lvm-thin` alone
        // would answer a DEVICE request for a driver of that name.
        assert!(!catalogue.contains(&"lvm-thin".to_string()));
    }

    fn network(vxlan: bool) -> NetworkCatalog {
        let raw = if vxlan {
            r#"default_bridge = "br0"
               [vxlan]
               uplink = "eno1""#
        } else {
            r#"default_bridge = "br0""#
        };
        // A `[network]` section is what builds the NIC driver, so a catalogue
        // made from one makes taps.
        NetworkCatalog::new(
            Some(&toml::from_str(raw).expect("the network section parses")),
            true,
            &[],
        )
    }

    fn tenant_nic(vxlan_id: Option<u32>) -> crate::types::NicWithId {
        crate::types::NicWithId {
            id: uuid::Uuid::nil(),
            spec: agent_api::networking::NicSpec {
                bridge: "br0".into(),
                mac: "52:54:00:00:00:01".parse().unwrap(),
                vxlan_id,
                physnet: None,
                floating_ips: Vec::new(),
                routed_subnets: Vec::new(),
            },
        }
    }

    fn provider_nic(physnet: &str) -> crate::types::NicWithId {
        let mut nic = tenant_nic(None);
        nic.spec.physnet = Some(physnet.to_string());
        nic
    }

    /// A VM that asks for an overlay this node cannot join must be refused in
    /// words. Putting it on the default bridge instead would be the one
    /// failure mode tenancy exists to prevent — it would reach every other
    /// tenant on this host — and it would look like success.
    #[test]
    fn an_overlay_nic_on_a_node_without_one_is_refused_by_name() {
        let cat = network(false);
        assert!(!cat.serves_overlays());
        assert!(cat.inventory().is_empty());
        cat.validate(&[tenant_nic(None)])
            .expect("a plain nic is unaffected");

        let err = cat
            .validate(&[tenant_nic(Some(10_000))])
            .unwrap_err()
            .to_string();
        assert!(err.contains("10000"), "{err}");
        assert!(
            err.contains("network.vxlan"),
            "the message names the section: {err}"
        );
    }

    /// And what a configured node claims is what the scheduler one tier up
    /// looks for — the same round trip the device and volume catalogues make,
    /// through the same `common::capability` spelling.
    #[test]
    fn a_configured_node_claims_the_entry_the_scheduler_matches() {
        let cat = network(true);
        assert!(cat.serves_overlays());
        cat.validate(&[tenant_nic(Some(10_000))])
            .expect("configured, so servable");

        let catalogue: Vec<String> = cat
            .inventory()
            .iter()
            .map(|p| common::capability::entry(common::capability::NETWORK, Some(p)))
            .collect();
        assert_eq!(catalogue, vec!["network/vxlan".to_string()]);
        assert!(common::capability::offers(
            &catalogue,
            common::capability::NETWORK,
            Some(common::capability::VXLAN)
        ));
    }

    #[test]
    fn a_configured_one_and_the_default_both_pass() {
        let cat = catalogue(&["filesystem", "lvm-thin"]);
        cat.validate(&[volume(Some("lvm-thin")), volume(Some("filesystem"))])
            .unwrap();
        // None means the default, which `from_config` always registers, so it
        // is not the catalogue's business to second-guess it.
        cat.validate(&[volume(None)]).unwrap();
        catalogue(&[]).validate(&[volume(None)]).unwrap();
    }

    /// Enough of a config to register drivers from; `sections` is what is
    /// under test. `image_dir` has to be a directory that exists — the
    /// filesystem backend checks at start-up, which is the point of it — so
    /// everything in [paths] lives under one temp directory.
    fn config(sections: &str) -> (tempfile::TempDir, AgentConfig) {
        raw_config(&format!(
            r#"[hypervisor.cloud-hypervisor]
               binary = "/usr/bin/cloud-hypervisor"
               timeout_ms = 5000
               [network]
               default_bridge = "br0"
               {sections}"#
        ))
    }

    /// The same thing without the hypervisor and network sections baked in:
    /// what a node IS is now a question the config answers, so a test about
    /// that question has to be able to leave them out.
    fn raw_config(sections: &str) -> (tempfile::TempDir, AgentConfig) {
        let temp = tempfile::Builder::new()
            .prefix("meister-agent-drivers-")
            .tempdir()
            .expect("a temp dir");
        let dir = temp.path().display();
        let cfg: AgentConfig = toml::from_str(&format!(
            r#"node_id = "n1"
               [paths]
               db_path     = "{dir}/a.redb"
               run_dir     = "{dir}/run"
               image_dir   = "{dir}"
               volume_dir  = "{dir}/vol"
               cgroup_root = "/sys/fs/cgroup/x"
               {sections}"#
        ))
        .expect("the test config parses");
        (temp, cfg)
    }

    /// `driver: None` in a spec has to keep meaning something on every node,
    /// so the default backend registers with no section of its own — and the
    /// other two rows of the table stay unregistered until a section asks
    /// for them. Between them those are the two halves of what the table is
    /// for.
    #[test]
    fn the_default_volume_driver_is_registered_without_a_section() {
        let (_temp, cfg) = config("");
        assert!(cfg.volume.is_empty(), "no [volume] section at all");

        let storage = register(VOLUME_DRIVERS, &cfg.volume, &cfg, "volume")
            .expect("a config with no [volume] section still has storage");
        assert_eq!(
            storage.keys().collect::<Vec<_>>(),
            vec![&agent_api::default_volume_driver()],
            "the default backend, and only it"
        );
    }

    /// vfio configures itself out of an inventory of host devices, so an
    /// absent or empty `managed` is a node with nothing to pass through —
    /// not a driver that failed to configure. The distinction is what keeps
    /// a GPU-less lab VM running the same binary as manacor.
    #[test]
    fn vfio_without_a_managed_inventory_is_not_registered() {
        for sections in ["", "[device]\nmanaged = []"] {
            let (_temp, cfg) = config(sections);
            let devices = register(DEVICE_DRIVERS, &cfg.device, &cfg, "device")
                .expect("nothing configured is not an error");
            assert!(
                devices.is_empty(),
                "{sections:?} registers no device driver, got {:?}",
                devices.keys().collect::<Vec<_>>()
            );
        }
    }

    /// The hypervisor came out of a `match` on a config enum and is now a
    /// row, and this is the round trip that says the file on disk did not
    /// move: the same two keys under the same section name build the same
    /// driver, and the section is now optional.
    #[test]
    fn the_hypervisor_section_still_names_the_driver_it_always_named() {
        let (_temp, cfg) = config("");
        let built = register_one(HYPERVISOR_DRIVERS, &cfg.hypervisor, &cfg, "hypervisor")
            .expect("the example's hypervisor section builds");
        assert!(built.is_some(), "[hypervisor.cloud-hypervisor] builds one");

        let (_temp, none) = raw_config(r#"[volume.filesystem]"#);
        assert!(
            register_one(HYPERVISOR_DRIVERS, &none.hypervisor, &none, "hypervisor")
                .expect("no section is not an error")
                .is_none(),
            "a node with no [hypervisor.*] section runs no vms"
        );
    }

    /// A section no row owns goes through the same message `[volume.ceph]`
    /// gets — which is the whole reason the hypervisor is a table now: the
    /// enum could say the variant was unknown, but not what this agent has.
    #[test]
    fn an_unknown_hypervisor_section_is_refused_by_name() {
        let (_temp, cfg) = raw_config(
            r#"[hypervisor.qemu]
                                binary = "/usr/bin/qemu-system-x86_64""#,
        );
        let Err(err) = register_one(HYPERVISOR_DRIVERS, &cfg.hypervisor, &cfg, "hypervisor") else {
            panic!("qemu is a typo, not a hypervisor this agent has");
        };
        let err = err.to_string();
        assert!(err.contains("[hypervisor.qemu]"), "{err}");
        assert!(
            err.contains("cloud-hypervisor"),
            "the message says what IS built in: {err}"
        );
    }

    /// Two configured rows in a single-slot table is a refusal. `register`
    /// returns a `HashMap`, and which of two entries it hands back first is
    /// not something a node's behaviour may depend on.
    #[test]
    fn two_drivers_in_a_single_slot_are_refused_rather_than_picked_between() {
        static TWO: &[DriverEntry<dyn VolumeDriver>] = &[
            DriverEntry {
                name: "a",
                keys: &["a"],
                build: |_, _| Ok(Some(Arc::new(Stub(Locality::NodeLocal, None)))),
            },
            DriverEntry {
                name: "b",
                keys: &["b"],
                build: |_, _| Ok(Some(Arc::new(Stub(Locality::NodeLocal, None)))),
            },
        ];
        let (_temp, cfg) = config("");
        let Err(err) = register_one(TWO, &Sections::new(), &cfg, "hypervisor") else {
            panic!("two configured rows in a single slot is not a choice to make");
        };
        let err = err.to_string();
        assert!(err.contains("2 hypervisor drivers"), "{err}");
        assert!(err.contains("a, b"), "the message names both: {err}");
    }

    /// The validity rule, and the reason it is asked of the CONFIG: a node
    /// with neither section serves nothing, and refusing at start-up is the
    /// difference between an operator reading one sentence now and reading a
    /// scheduler's Pending reason in three days.
    #[tokio::test]
    async fn an_agent_that_serves_neither_vms_nor_volumes_refuses_to_start() {
        let (_temp, nothing) = raw_config("");
        assert!(nothing.hypervisor.is_empty() && nothing.volume.is_empty());

        let Err(err) = Drivers::from_config(&nothing).await else {
            panic!("a node with neither section serves nothing");
        };
        let err = err.to_string();
        assert!(err.contains("serves nothing"), "{err}");
        assert!(
            err.contains("[hypervisor.*]") && err.contains("[volume.*]"),
            "{err}"
        );
    }

    /// And the shape this whole position exists for: a node with storage and
    /// no hypervisor comes up. No VMM, no taps, and a confiner all the same —
    /// a storage node wants its backend process in a cgroup exactly as a
    /// compute node wants its VMMs there.
    #[tokio::test]
    async fn a_storage_node_comes_up_without_a_hypervisor_or_a_network() {
        let (_temp, cfg) = raw_config("[volume.filesystem]");
        let drivers = Drivers::from_config(&cfg)
            .await
            .expect("storage alone is a node");

        assert!(drivers.hypervisor.is_none(), "no [hypervisor.*] section");
        assert!(drivers.networking.is_none() && drivers.bridge.is_none());
        assert!(drivers.storage.contains_key(DRIVER_FILESYSTEM));

        // And the absence is an answer rather than a panic, in words that
        // name the section an operator would have to add.
        fn said<T: ?Sized>(r: anyhow::Result<&Arc<T>>) -> String {
            match r {
                Ok(_) => panic!("this node has neither a hypervisor nor a network"),
                Err(e) => format!("{e:#}"),
            }
        }
        let err = said(drivers.hypervisor());
        assert!(
            err.contains("[hypervisor.*]") && err.contains("runs no vms"),
            "{err}"
        );
        assert!(said(drivers.networking()).contains("[network]"));
        assert!(said(drivers.bridge()).contains("[network]"));
    }

    /// The claim a compute node makes, through the same `common::capability`
    /// round trip the volume and device catalogues make — which is the whole
    /// reason there is no separate hypervisor catalogue on the wire: the
    /// entry flattens one tier up exactly as `volume/lvm-thin` does.
    #[tokio::test]
    async fn a_compute_node_claims_the_hypervisor_a_scheduler_would_match() {
        // No `[network]`: a node that runs VMs without making taps is a legal
        // shape too, and the one this test can build without nftables.
        let (_temp, cfg) = raw_config(
            r#"[hypervisor.cloud-hypervisor]
               binary = "/usr/bin/cloud-hypervisor"
               timeout_ms = 5000"#,
        );
        let drivers = Drivers::from_config(&cfg)
            .await
            .expect("a hypervisor and the default backend");
        let cat = HypervisorCatalog::new(drivers.hypervisor_name.as_deref());
        cat.validate().expect("this node runs vms");
        assert_eq!(cat.inventory(), vec![DRIVER_CLOUD_HYPERVISOR.to_string()]);

        let catalogue: Vec<String> = cat
            .inventory()
            .iter()
            .map(|d| common::capability::entry(common::capability::HYPERVISOR, Some(d)))
            .collect();
        assert_eq!(catalogue, vec!["hypervisor/cloud-hypervisor".to_string()]);
        assert!(common::capability::offers(
            &catalogue,
            common::capability::HYPERVISOR,
            None
        ));
    }

    /// And the claim a storage node does NOT make. The empty inventory is the
    /// whole point: an entry with no profiles would flatten to the bare
    /// driver name `hypervisor`, which answers a bare request for one — so
    /// the Hello leaves the entry out entirely rather than sending an empty
    /// one, the same rule the network half follows.
    #[tokio::test]
    async fn a_storage_node_claims_no_hypervisor_and_refuses_a_vm_in_words() {
        let (_temp, cfg) = raw_config("[volume.filesystem]");
        let drivers = Drivers::from_config(&cfg)
            .await
            .expect("storage alone is a node");
        let cat = HypervisorCatalog::new(drivers.hypervisor_name.as_deref());
        assert!(cat.inventory().is_empty());

        let err = match cat.validate() {
            Ok(()) => panic!("a node with no hypervisor cannot run a vm"),
            Err(e) => format!("{e:#}"),
        };
        assert!(err.contains("[hypervisor.*]"), "{err}");
        assert!(err.contains("storage only"), "{err}");

        // Nothing an empty inventory produces answers a request, bare or not.
        assert!(!common::capability::offers(
            &[],
            common::capability::HYPERVISOR,
            None
        ));
    }

    /// A node with no `[network]` section claims exactly what a node with one
    /// and no overlay claims: nothing. Two configurations, one capability.
    ///
    /// The CLAIM is the same and what they can serve is not, which is why the
    /// catalogue carries `makes_taps` beside the profiles: an empty claim is
    /// what a scheduler reads, and "can this spec run here at all" is what
    /// this node reads.
    #[test]
    fn a_node_without_a_network_section_claims_no_overlay() {
        let cat = NetworkCatalog::new(None, false, &[]);
        assert!(cat.inventory().is_empty());
        assert!(!cat.serves_overlays());
        assert_eq!(cat.inventory(), network(false).inventory());
        // A VM with no NIC at all is still perfectly welcome here.
        cat.validate(&[]).expect("no nic, no taps needed");
    }

    /// Festlegung 2: the gateway is a capability out of the config. A node
    /// that gave an interface away claims one entry per provider network, and
    /// a node that gave none claims nothing and is a candidate for no router.
    #[test]
    fn a_node_that_gave_an_interface_away_claims_it_by_the_networks_name() {
        let cat = NetworkCatalog::new(
            Some(&toml::from_str(r#"default_bridge = "br0""#).unwrap()),
            true,
            &["ext".to_string(), "dmz".to_string()],
        );
        assert_eq!(cat.inventory(), ["gateway:ext", "gateway:dmz"]);
        assert_eq!(cat.physnets(), ["ext", "dmz"]);
        assert!(cat.serves_physnet("ext"));
        assert!(!cat.serves_physnet("wan"));
        // The overlay claim is a different question and this node answers it
        // no: a gateway node with no [network.vxlan] can hold no router, and
        // the router's own build says so at `ensure_overlay`.
        assert!(!cat.serves_overlays());

        // The ordinary node, which is every node before 6k.
        assert!(network(true).physnets().is_empty());
        assert!(!network(true).serves_physnet("ext"));
    }

    /// A NIC on a provider network this node did not give an interface away
    /// to is structural: the node will not grow the interface on the next
    /// attempt, so the refusal carries `CannotServe` and the VM is placed
    /// somewhere else rather than going Failed here.
    #[test]
    fn a_nic_on_a_provider_network_this_node_does_not_have_is_refused() {
        let gateway = NetworkCatalog::new(
            Some(&toml::from_str(r#"default_bridge = "br0""#).unwrap()),
            true,
            &["ext".to_string()],
        );
        gateway
            .validate(&[provider_nic("ext")])
            .expect("this node gave eth1 away to ext");

        let err = gateway
            .validate(&[provider_nic("dmz")])
            .expect_err("and to nothing else")
            .to_string();
        assert!(err.contains("\"dmz\"") && err.contains("[ext]"), "{err}");

        // A node with no slot at all says the same thing with an empty list.
        let err = network(true)
            .validate(&[provider_nic("ext")])
            .expect_err("no slot here")
            .to_string();
        assert!(err.contains("[]"), "{err}");
    }

    /// Both wires named at once, refused where the refusal is still
    /// structural. The driver refuses it too, at the tap -- but that is a
    /// Failed VM bound to this node, and this is a VM that moves.
    #[test]
    fn a_nic_that_names_both_wires_is_refused_before_a_tap_exists() {
        let mut nic = provider_nic("ext");
        nic.spec.vxlan_id = Some(10_000);
        let err = NetworkCatalog::new(
            Some(&toml::from_str(r#"default_bridge = "br0""#).unwrap()),
            true,
            &["ext".to_string()],
        )
        .validate(&[nic])
        .expect_err("one wire")
        .to_string();
        assert!(err.contains("name one of the two"), "{err}");
    }

    /// The refusal this position moved, and the one behaviour change it
    /// makes: a plain NIC on a node that makes no taps.
    ///
    /// It was always refused. It was refused in `run_chain`, three layers
    /// down and after the point where `handle_create` marks a refusal
    /// structural — so the VM stayed bound to a node that will never be able
    /// to run it and went `Failed` instead of moving. Here it carries
    /// `CannotServe`, and the tier above takes the binding back.
    #[test]
    fn a_nic_on_a_node_that_makes_no_taps_is_refused_where_it_is_structural() {
        let none = NetworkCatalog::new(None, false, &[]);
        let err = none
            .validate(&[tenant_nic(None)])
            .expect_err("this node makes no taps");
        let err = err.to_string();
        assert!(err.contains("[network]"), "it names the section: {err}");
        assert!(err.contains("makes no taps"), "{err}");

        // And a node that HAS the section takes the same nic, overlay or not
        // — the second question is the one that was always asked here.
        network(false)
            .validate(&[tenant_nic(None)])
            .expect("a plain nic on a node with taps");
        network(true)
            .validate(&[tenant_nic(Some(4242))])
            .expect("an overlay nic on a node with one");
        assert!(
            network(false).validate(&[tenant_nic(Some(4242))]).is_err(),
            "taps yes, overlay no"
        );
    }

    /// A section no driver owns used to be `deny_unknown_fields` on a config
    /// struct, which could say the key was wrong but not what this agent
    /// has. Silently ignoring it would be worse than either: a node that
    /// comes up without the backend its operator configured, and finds out
    /// on the first VM that needed it.
    #[test]
    fn a_section_no_driver_owns_is_refused_by_name() {
        let (_temp, cfg) = config("[volume.ceph]\npool = \"rbd\"");
        let Err(err) = register(VOLUME_DRIVERS, &cfg.volume, &cfg, "volume") else {
            panic!("ceph is not a storage backend this agent has");
        };
        let err = err.to_string();
        assert!(err.contains("[volume.ceph]"), "{err}");
        assert!(
            err.contains("filesystem, lvm-thin, nfs"),
            "the message says what IS built in: {err}"
        );

        // The device half goes through the same function, and its list is
        // the table KEYS rather than the driver names — `managed` is what
        // you would have to write, and `vfio` is not.
        let (_temp, cfg) = config("[device.crosvm-gp]\nbinary = \"/usr/bin/crosvm\"");
        let Err(err) = register(DEVICE_DRIVERS, &cfg.device, &cfg, "device") else {
            panic!("crosvm-gp is a typo, not a device backend");
        };
        let err = err.to_string();
        assert!(err.contains("[device.crosvm-gp]"), "{err}");
        assert!(err.contains("crosvm-gpu, managed, nvrm"), "{err}");
    }

    /// The catalogue claim follows `snapshot_support` and nothing else.
    ///
    /// The claim is what makes "this pool cannot snapshot" a 422 at the API
    /// edge rather than a `Failed` object twenty seconds later — the same
    /// spelling a GPU profile uses, so the tier above asks with the function
    /// it already has. A backend that answers `None` claims nothing, and one
    /// that answers anything at all claims `<backend>/snapshot` — plus, since
    /// a backend's consistency stopped being a property of its name, the
    /// same entry with the answer on it.
    #[test]
    fn a_backend_claims_a_snapshot_entry_exactly_when_it_says_it_can() {
        let mut map: HashMap<String, Arc<dyn VolumeDriver>> = HashMap::new();
        map.insert(
            "filesystem".into(),
            Arc::new(Stub(
                Locality::NodeLocal,
                Some(SnapshotConsistency::NeedsQuiesce),
            )),
        );
        map.insert(
            "lvm-thin".into(),
            Arc::new(Stub(Locality::NodeLocal, Some(SnapshotConsistency::Atomic))),
        );
        // A backend that cannot. The default of the trait, and the honest
        // answer of most: unlike `locality`, a default here is a real answer
        // rather than a value nobody thought about.
        map.insert("blackhole".into(), Arc::new(Stub(Locality::Shared, None)));
        let catalogue = VolumeCatalog::new(&map);

        assert_eq!(
            catalogue.snapshot_claims(),
            vec![
                "filesystem/snapshot".to_string(),
                "filesystem/snapshot:needs-quiesce".into(),
                "lvm-thin/snapshot".into(),
                "lvm-thin/snapshot:atomic".into(),
            ],
            "sorted, so a Hello is byte-identical across restarts"
        );
        // Flattened one tier up, this is what a scheduler and an API edge see.
        let flat: Vec<String> = catalogue
            .snapshot_claims()
            .iter()
            .map(|p| common::capability::entry(common::capability::VOLUME, Some(p)))
            .collect();
        assert!(flat.contains(&"volume/lvm-thin/snapshot".to_string()));
        assert!(flat.contains(&"volume/lvm-thin/snapshot:atomic".to_string()));
        assert!(!flat.contains(&"volume/blackhole/snapshot".to_string()));

        // The bare entry is still there and still bare, which is what a
        // cluster one release older matches on: adding the consistency must
        // not take a pool away from a controller that has not learned to read
        // it yet.
        assert!(
            common::capability::offers(
                &flat,
                common::capability::VOLUME,
                Some("lvm-thin/snapshot")
            ),
            "the old question still gets the old answer"
        );

        // And the consistency now travels, because it stopped being a
        // property of the driver's NAME: `filesystem` reflinks on one mount
        // and copies on the next.
        for (profile, want) in [
            ("lvm-thin/snapshot:atomic", SnapshotConsistency::Atomic),
            (
                "filesystem/snapshot:needs-quiesce",
                SnapshotConsistency::NeedsQuiesce,
            ),
        ] {
            let (backend, consistency) =
                common::capability::parse_snapshot_claim(profile).expect("a claim reads back");
            assert_eq!(consistency, want);
            assert!(profile.starts_with(backend));
        }
        // The bare entry carries no answer, and a reader that gets none has
        // to quiesce rather than guess.
        assert_eq!(
            common::capability::parse_snapshot_claim("lvm-thin/snapshot"),
            None
        );

        assert_eq!(
            catalogue.snapshot_support("lvm-thin"),
            Some(SnapshotConsistency::Atomic)
        );
        assert_eq!(catalogue.snapshot_support("blackhole"), None);
        assert_eq!(catalogue.snapshot_support("nothing-here"), None);

        // The locality half is untouched by any of it: the snapshot entry
        // carries no locality, so it cannot be read as one.
        assert_eq!(catalogue.localities().len(), 3);
    }
}
