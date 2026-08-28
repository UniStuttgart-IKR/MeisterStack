// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use crate::config::{
    AgentConfig, CrosvmGpuConfig, FilesystemVolumeConfig, HypervisorConfig, LvmThinVolumeConfig,
    ManagedDevice, NfsVolumeConfig, NvrmConfig, Sections, section,
};
use crate::types::{DeviceWithId, VolumeWithId};
use agent_api::{
    Hypervisor, ResourceConfiner,
    device::DeviceDriver,
    networking::{BridgeDriver, NicDriver, RouteAnnouncer},
    storage::BlockDriver,
};
use anyhow::bail;
use crosvm_gpu_driver::CrosvmGpuDriver;
use filesystem_driver::FilesystemBlockDriver;
use linux_network_driver::LinuxNetworkDriver;
use lvm_thin_driver::LvmThinDriver;
use macros::generated;
use nfs_driver::NfsDriver;
use nvrm_driver::NvrmDriver;
use vfio_driver::VfioPciDriver;

pub const DRIVER_CROSVM_GPU: &str = "crosvm-gpu";
pub const DRIVER_NVRM: &str = "nvrm";
pub const DRIVER_VFIO: &str = "vfio";
pub const DRIVER_LVM_THIN: &str = "lvm-thin";
pub const DRIVER_NFS: &str = "nfs";
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
#[generated(model = ClaudeOpus, version = "5")]
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
#[generated(model = ClaudeOpus, version = "5")]
static VOLUME_DRIVERS: &[DriverEntry<dyn BlockDriver>] = &[
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
];

/// The device backends this agent has.
#[generated(model = ClaudeOpus, version = "5")]
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

/// Build every driver in `entries` that this node's config asks for, keyed
/// by the name a spec routes on.
///
/// Both halves of the seam come through here — `T` is `dyn BlockDriver` for
/// `[volume]` and `dyn DeviceDriver` for `[device]`, and the table is the
/// only difference between them.
#[generated(model = ClaudeOpus, version = "5")]
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

/// The default backend, and the one builder that never returns `None`: a
/// spec that names no driver has to keep meaning what it means on every
/// node, so this registers whether or not `[volume.filesystem]` is there.
/// The section only overrides where its files live.
#[generated(model = ClaudeOpus, version = "5")]
fn build_filesystem(
    sections: &Sections,
    cfg: &AgentConfig,
) -> anyhow::Result<Option<Arc<dyn BlockDriver>>> {
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
    })?;
    Ok(Some(Arc::new(driver)))
}

#[generated(model = ClaudeOpus, version = "5")]
fn build_lvm_thin(
    sections: &Sections,
    cfg: &AgentConfig,
) -> anyhow::Result<Option<Arc<dyn BlockDriver>>> {
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

#[generated(model = ClaudeOpus, version = "5")]
fn build_nfs(
    sections: &Sections,
    cfg: &AgentConfig,
) -> anyhow::Result<Option<Arc<dyn BlockDriver>>> {
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

#[generated(model = ClaudeOpus, version = "5")]
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

#[generated(model = ClaudeOpus, version = "5")]
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
#[generated(model = ClaudeOpus, version = "5")]
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

/// Which network capabilities this node has, for the same two reasons the
/// volume catalogue exists: an unservable spec should be a rejected spec at
/// the edge rather than a VM torn down halfway through, and the scheduler one
/// tier up has to be able to keep such a VM away from this node entirely.
///
/// One entry so far. It is a list and not a bool because the next one —
/// Geneve, an OVN integration, whatever the DPU track wants — is a profile
/// beside it and not a second mechanism.
#[generated(model = ClaudeOpus, version = "5")]
#[derive(Clone, Debug, Default)]
pub struct NetworkCatalog {
    profiles: Vec<String>,
}

#[generated(model = ClaudeOpus, version = "5")]
impl NetworkCatalog {
    pub fn new(cfg: &crate::config::NetworkConfig) -> Self {
        let mut profiles = Vec::new();
        if let Some(vxlan) = &cfg.vxlan {
            profiles.push(common::capability::VXLAN.to_string());
            // A second entry beside `vxlan` and never instead of it: a VM asks
            // for an overlay, and a node that dropped `network/vxlan` when it
            // turned evpn on would stop being a candidate for the very VMs it
            // serves best. This one is for the operator reading
            // `meister cluster nodes` — evpn is a cluster-wide decision (see
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
        Self { profiles }
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

    /// A spec that asks for an overlay this node cannot join is a 422 on the
    /// REST path and a refused Create on the session — never a VM quietly
    /// placed on the default bridge, where it would reach every other tenant
    /// on this host.
    pub fn validate(&self, nics: &[crate::types::NicWithId]) -> anyhow::Result<()> {
        for n in nics {
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
    pub confiner: Arc<dyn ResourceConfiner>,
    pub hypervisor: Arc<dyn Hypervisor>,
    /// Keyed by driver name, exactly as `devices` is: `spec.driver` routes,
    /// `None` means `default_volume_driver()`, and that entry always exists.
    pub storage: HashMap<String, Arc<dyn BlockDriver>>,
    pub networking: Arc<dyn NicDriver>,
    pub bridge: Arc<dyn BridgeDriver>,
    /// Who to tell which addresses live on this node. `None` = no
    /// `[network.bgp]` section, which is every node before M5.1: the floating
    /// addresses are still reserved and still enforced at the tap, and how
    /// they are reached is the environment's static route or a tenant
    /// appliance rather than a session with a router.
    pub announcer: Option<Arc<dyn RouteAnnouncer>>,
    pub devices: HashMap<String, Arc<dyn DeviceDriver>>,
}

#[generated(model = ClaudeFable, version = "5")]
impl Drivers {
    pub async fn from_config(cfg: &AgentConfig) -> anyhow::Result<Self> {
        let confiner = Arc::new(cgroup_driver::CgroupV2::new(cfg.paths.cgroup_root.clone()));

        let hypervisor: Arc<dyn Hypervisor> = match &cfg.hypervisor {
            HypervisorConfig::CloudHypervisor { binary, timeout_ms } => {
                Arc::new(cloud_hypervisor_driver::CloudHypervisorDriver::new(
                    binary.clone(),
                    cfg.paths.run_dir.join("vms"),
                    Duration::from_millis(*timeout_ms),
                )?)
            }
        };

        let storage = register(VOLUME_DRIVERS, &cfg.volume, cfg, "volume")?;

        // The hypervisor above and the networking below deliberately stay out
        // of the tables: neither has the many-of-them shape the tables exist
        // for. There is one hypervisor, picked by which `[hypervisor.*]`
        // variant the config names, and one network driver that every node
        // runs unconditionally. A row for either would register nothing that
        // is not already here and would cost a `dyn` hop to read.
        let vxlan = cfg
            .network
            .vxlan
            .as_ref()
            .map(|v| linux_network_driver::VxlanConfig {
                uplink: v.uplink.clone(),
                mtu: v.mtu,
                evpn: v.evpn,
            });
        let net = Arc::new(LinuxNetworkDriver::build(vxlan, cfg.nft_config()?)?);
        let networking: Arc<dyn NicDriver> = net.clone();
        let bridge: Arc<dyn BridgeDriver> = net;

        let devices = register(DEVICE_DRIVERS, &cfg.device, cfg, "device")?;

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
            storage,
            networking,
            bridge,
            announcer,
            devices,
        })
    }
}

/// Which storage backends this node has, for the same reason `DeviceCatalog`
/// exists: an unknown driver name should be a rejected spec at the edge, not
/// a VM that gets half-provisioned and then torn down again.
#[generated(model = ClaudeOpus, version = "5")]
#[derive(Clone, Debug)]
pub struct VolumeCatalog {
    drivers: Vec<String>,
}

#[generated(model = ClaudeOpus, version = "5")]
impl VolumeCatalog {
    pub fn new(storage: &HashMap<String, Arc<dyn BlockDriver>>) -> Self {
        let mut drivers: Vec<String> = storage.keys().cloned().collect();
        drivers.sort_unstable();
        Self { drivers }
    }

    /// What this node claims about its storage, for the Hello.
    ///
    /// One capability driver with one profile per backend — `volume/lvm-thin`
    /// and not `lvm-thin` — because the catalogue is a flat list of
    /// `<driver>/<profile>` strings shared with the device half, and a bare
    /// `lvm-thin` in it would collide with a device driver of that name and
    /// answer a device request nobody could serve. The `filesystem` entry is
    /// in there too: every node has it, so it never decides a placement, but
    /// leaving it out would make `meister cluster nodes` lie about what a
    /// node can do.
    #[generated(model = ClaudeOpus, version = "5")]
    pub fn inventory(&self) -> Vec<String> {
        self.drivers.clone()
    }

    pub fn validate(&self, volumes: &[VolumeWithId]) -> anyhow::Result<()> {
        for v in volumes {
            // None is the default driver, which is always registered.
            let Some(driver) = &v.spec.driver else {
                continue;
            };
            if !self.drivers.iter().any(|d| d == driver) {
                bail!(
                    "volume driver {driver:?} is not configured on this node; available: [{}]",
                    self.drivers.join(", ")
                );
            }
        }
        Ok(())
    }
}

#[generated(model = ClaudeFable, version = "5")]
#[derive(Clone, Debug)]
pub struct DeviceCatalog {
    profiles: HashMap<String, Vec<String>>,
}

#[generated(model = ClaudeFable, version = "5")]
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
    #[generated(model = ClaudeOpus, version = "5")]
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
#[generated(model = ClaudeOpus, version = "5")]
mod tests {
    use super::*;
    use crate::types::VolumeWithId;
    use agent_api::storage::{Volume, VolumeSpec};

    struct Stub;

    #[async_trait::async_trait]
    impl BlockDriver for Stub {
        async fn create(
            &self,
            _: &agent_api::VolumeId,
            _: &VolumeSpec,
            _: Option<&agent_api::CgroupHandle>,
        ) -> agent_api::storage::Result<Volume> {
            unreachable!("the catalogue never creates anything")
        }
        async fn destroy(
            &self,
            _: &agent_api::VolumeId,
            _: &agent_api::VolumeAttachment,
        ) -> agent_api::storage::Result<()> {
            unreachable!()
        }
        async fn get(
            &self,
            _: &agent_api::VolumeId,
            _: &agent_api::VolumeAttachment,
        ) -> agent_api::storage::Result<Volume> {
            unreachable!()
        }
    }

    fn catalogue(names: &[&str]) -> VolumeCatalog {
        let mut map: HashMap<String, Arc<dyn BlockDriver>> = HashMap::new();
        for n in names {
            map.insert(n.to_string(), Arc::new(Stub));
        }
        VolumeCatalog::new(&map)
    }

    fn volume(driver: Option<&str>) -> VolumeWithId {
        VolumeWithId {
            id: uuid::Uuid::nil(),
            spec: VolumeSpec {
                base_image: None,
                size_bytes: 1,
                driver: driver.map(str::to_string),
                params: None,
            },
        }
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
        NetworkCatalog::new(&toml::from_str(raw).expect("the network section parses"))
    }

    fn tenant_nic(vxlan_id: Option<u32>) -> crate::types::NicWithId {
        crate::types::NicWithId {
            id: uuid::Uuid::nil(),
            spec: agent_api::networking::NicSpec {
                bridge: "br0".into(),
                mac: "52:54:00:00:00:01".parse().unwrap(),
                vxlan_id,
                floating_ips: Vec::new(),
                routed_subnets: Vec::new(),
            },
        }
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
    fn config(sections: &str) -> AgentConfig {
        let dir = std::env::temp_dir().join("meister-agent-drivers-test");
        std::fs::create_dir_all(&dir).expect("a temp directory");
        let dir = dir.display();
        toml::from_str(&format!(
            r#"node_id = "n1"
               [paths]
               db_path     = "{dir}/a.redb"
               run_dir     = "{dir}/run"
               image_dir   = "{dir}"
               volume_dir  = "{dir}/vol"
               cgroup_root = "/sys/fs/cgroup/x"
               [hypervisor.cloud-hypervisor]
               binary = "/usr/bin/cloud-hypervisor"
               timeout_ms = 5000
               [network]
               default_bridge = "br0"
               {sections}"#
        ))
        .expect("the test config parses")
    }

    /// `driver: None` in a spec has to keep meaning something on every node,
    /// so the default backend registers with no section of its own — and the
    /// other two rows of the table stay unregistered until a section asks
    /// for them. Between them those are the two halves of what the table is
    /// for.
    #[test]
    fn the_default_volume_driver_is_registered_without_a_section() {
        let cfg = config("");
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
            let cfg = config(sections);
            let devices = register(DEVICE_DRIVERS, &cfg.device, &cfg, "device")
                .expect("nothing configured is not an error");
            assert!(
                devices.is_empty(),
                "{sections:?} registers no device driver, got {:?}",
                devices.keys().collect::<Vec<_>>()
            );
        }
    }

    /// A section no driver owns used to be `deny_unknown_fields` on a config
    /// struct, which could say the key was wrong but not what this agent
    /// has. Silently ignoring it would be worse than either: a node that
    /// comes up without the backend its operator configured, and finds out
    /// on the first VM that needed it.
    #[test]
    fn a_section_no_driver_owns_is_refused_by_name() {
        let cfg = config("[volume.ceph]\npool = \"rbd\"");
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
        let cfg = config("[device.crosvm-gp]\nbinary = \"/usr/bin/crosvm\"");
        let Err(err) = register(DEVICE_DRIVERS, &cfg.device, &cfg, "device") else {
            panic!("crosvm-gp is a typo, not a device backend");
        };
        let err = err.to_string();
        assert!(err.contains("[device.crosvm-gp]"), "{err}");
        assert!(err.contains("crosvm-gpu, managed, nvrm"), "{err}");
    }
}
