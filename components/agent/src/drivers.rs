// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use crate::config::{
    AgentConfig, CloudHypervisorConfig, CrosvmGpuConfig, FilesystemVolumeConfig, InputConfig,
    LvmThinVolumeConfig, ManagedDevice, NfsVolumeConfig, NvrmConfig, Sections, section,
};
use crate::privileges;
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
use input_driver::InputDriver;
use linux_network_driver::LinuxNetworkDriver;
use lvm_thin_driver::LvmThinDriver;
use nfs_driver::NfsDriver;
use nvrm_driver::NvrmDriver;
use vfio_driver::VfioPciDriver;

pub const DRIVER_CROSVM_GPU: &str = "crosvm-gpu";
pub const DRIVER_NVRM: &str = "nvrm";
/// The second vhost-user backend of the display rig: virtio-input, which
/// cloud-hypervisor does not have of its own.
pub const DRIVER_INPUT: &str = "input";
pub const DRIVER_VFIO: &str = "vfio";
pub const DRIVER_LVM_THIN: &str = "lvm-thin";
pub const DRIVER_NFS: &str = "nfs";
/// The attacher for namespaces that live somewhere else, and the first
/// consumer of `Locality::Networked`.
pub const DRIVER_NVMEOF: &str = "nvmeof";
/// Its provider half: namespaces that already exist, handed out.
pub const DRIVER_NVMEOF_IMPORT: &str = "nvmeof-import";
pub const DRIVER_CLOUD_HYPERVISOR: &str = "cloud-hypervisor";
/// Networking driver name, separate from its configuration section; see `NETWORK_DRIVERS`.
pub const DRIVER_LINUX_NETWORK: &str = "linux";
/// Share the default driver name with specification parsing.
pub const DRIVER_FILESYSTEM: &str = common::capability::DEFAULT_VOLUME_DRIVER;
/// The one table key that is not a driver name: see `DriverEntry::keys`.
const KEY_MANAGED: &str = "managed";

/// Registry entry connecting a runtime driver name, owned config sections,
/// prerequisites, and constructor.
pub struct DriverEntry<T: ?Sized + 'static> {
    /// The name a spec uses.
    pub name: &'static str,
    /// Owned configuration keys. Usually the driver name; VFIO owns `managed`,
    /// which contains the host device inventory.
    pub keys: &'static [&'static str],
    /// Prerequisites checked before constructing this driver.
    pub needs: &'static crate::privileges::Needs,
    /// Ok(None) = not configured on this node.
    pub build: fn(&Sections, &AgentConfig) -> anyhow::Result<Option<Arc<T>>>,
}

/// Storage registry; filesystem is registered even without an explicit section.
static VOLUME_DRIVERS: &[DriverEntry<dyn VolumeDriver>] = &[
    DriverEntry {
        name: DRIVER_FILESYSTEM,
        keys: &[DRIVER_FILESYSTEM],
        needs: &privileges::NOTHING,
        build: build_filesystem,
    },
    DriverEntry {
        name: DRIVER_LVM_THIN,
        keys: &[DRIVER_LVM_THIN],
        needs: &privileges::DEVICE_MAPPER,
        build: build_lvm_thin,
    },
    DriverEntry {
        name: DRIVER_NFS,
        keys: &[DRIVER_NFS],
        needs: &privileges::MOUNT,
        build: build_nfs,
    },
    DriverEntry {
        name: DRIVER_NVMEOF,
        keys: &[DRIVER_NVMEOF],
        needs: &privileges::NVME_FABRICS,
        build: build_nvmeof,
    },
    DriverEntry {
        name: DRIVER_NVMEOF_IMPORT,
        keys: &[DRIVER_NVMEOF_IMPORT],
        needs: &privileges::NOTHING,
        build: build_nvmeof_import,
    },
];

/// The device backends this agent has.
static DEVICE_DRIVERS: &[DriverEntry<dyn DeviceDriver>] = &[
    DriverEntry {
        name: DRIVER_CROSVM_GPU,
        keys: &[DRIVER_CROSVM_GPU],
        needs: &privileges::RENDER_NODE,
        build: build_crosvm_gpu,
    },
    DriverEntry {
        name: DRIVER_NVRM,
        keys: &[DRIVER_NVRM],
        needs: &privileges::NVIDIA,
        build: build_nvrm,
    },
    DriverEntry {
        name: DRIVER_INPUT,
        keys: &[DRIVER_INPUT],
        needs: &privileges::NOTHING,
        build: build_input,
    },
    DriverEntry {
        name: DRIVER_VFIO,
        keys: &[KEY_MANAGED],
        needs: &privileges::VFIO_BIND,
        build: build_vfio,
    },
];

/// Hypervisor registrations; at most one may be built per node.
static HYPERVISOR_DRIVERS: &[DriverEntry<dyn Hypervisor>] = &[DriverEntry {
    name: DRIVER_CLOUD_HYPERVISOR,
    keys: &[DRIVER_CLOUD_HYPERVISOR],
    needs: &privileges::KVM,
    build: build_cloud_hypervisor,
}];

/// Network registrations. Linux uses the single `[network]` section, so it
/// owns no key in a driver-section map; its builder checks `cfg.network`.
static NETWORK_DRIVERS: &[DriverEntry<dyn NetworkDriver>] = &[DriverEntry {
    name: DRIVER_LINUX_NETWORK,
    keys: &[],
    needs: &privileges::TAPS,
    build: build_linux_network,
}];

/// Constructed drivers by registry name.
type Registry<T> = HashMap<String, Arc<T>>;

/// Build configured, permitted drivers and reject unknown section names.
fn register<T: ?Sized>(
    entries: &[DriverEntry<T>],
    sections: &Sections,
    cfg: &AgentConfig,
    what: &str,
    skip: &HashSet<&'static str>,
) -> anyhow::Result<HashMap<String, Arc<T>>> {
    refuse_unknown_sections(entries, sections, what)?;
    build_each(entries, sections, cfg, skip, |_, e| Err(e))
}

/// Like [`register`], except that a driver whose constructor fails is left
/// out and named, with its reason, in the second list. Unknown sections still
/// fail: they are a configuration this agent cannot read at all.
fn register_or_report<T: ?Sized>(
    entries: &[DriverEntry<T>],
    sections: &Sections,
    cfg: &AgentConfig,
    what: &str,
    skip: &HashSet<&'static str>,
) -> anyhow::Result<(Registry<T>, Vec<String>)> {
    refuse_unknown_sections(entries, sections, what)?;
    let mut unavailable = Vec::new();
    let built = build_each(entries, sections, cfg, skip, |name, e| {
        unavailable.push(format!("{what} driver {name:?} could not be built: {e:#}"));
        Ok(())
    })?;
    Ok((built, unavailable))
}

fn refuse_unknown_sections<T: ?Sized>(
    entries: &[DriverEntry<T>],
    sections: &Sections,
    what: &str,
) -> anyhow::Result<()> {
    // Sort unknown sections so configuration errors are deterministic.
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
    Ok(())
}

/// Construct every configured, permitted driver. `failed` decides what a
/// constructor error means: returning it ends registration.
fn build_each<T: ?Sized>(
    entries: &[DriverEntry<T>],
    sections: &Sections,
    cfg: &AgentConfig,
    skip: &HashSet<&'static str>,
    mut failed: impl FnMut(&'static str, anyhow::Error) -> anyhow::Result<()>,
) -> anyhow::Result<Registry<T>> {
    let mut built: Registry<T> = HashMap::new();
    for entry in entries {
        // Skip drivers with unmet host prerequisites; unknown sections still fail.
        if skip.contains(entry.name) {
            continue;
        }
        match (entry.build)(sections, cfg) {
            Ok(Some(driver)) => {
                built.insert(entry.name.to_string(), driver);
            }
            Ok(None) => {}
            Err(e) => failed(entry.name, e)?,
        }
    }
    Ok(built)
}

/// Build at most one driver and return its registry name. Refuse multiple
/// results rather than choosing an arbitrary map entry.
fn register_one<T: ?Sized>(
    entries: &[DriverEntry<T>],
    sections: &Sections,
    cfg: &AgentConfig,
    what: &str,
    skip: &HashSet<&'static str>,
) -> anyhow::Result<Option<(String, Arc<T>)>> {
    let built = register(entries, sections, cfg, what, skip)?;
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

/// Startup prerequisite decisions and watches for configured drivers.
#[derive(Default)]
pub struct Screen {
    /// Driver names `register` leaves out.
    pub skip: HashSet<&'static str>,
    /// Unavailable configured drivers and router capabilities, for node reporting.
    pub gaps: Vec<String>,
    /// Missing prerequisites for a configured hypervisor are fatal to startup.
    pub fatal: Option<String>,
    /// Configured prerequisites to recheck during heartbeat reporting.
    pub watch: Vec<crate::privileges::Watched>,
}

impl Screen {
    fn look<T: ?Sized>(
        &mut self,
        entries: &[DriverEntry<T>],
        sections: &Sections,
        rights: &dyn privileges::Probe,
        fatal: bool,
    ) {
        for entry in entries {
            // Check prerequisites only for explicitly configured drivers.
            if !entry.keys.iter().any(|key| sections.contains_key(*key)) {
                continue;
            }
            self.watch.push(privileges::Watched {
                driver: entry.name,
                needs: entry.needs,
            });
            let Some(gap) = entry.needs.missing(entry.name, rights) else {
                continue;
            };
            if fatal {
                self.fatal = Some(gap);
            } else {
                self.skip.insert(entry.name);
                self.gaps.push(gap);
            }
        }
    }
}

/// Evaluate configured-driver prerequisites using the supplied probe.
/// Host probes may change between calls; test probes can provide fixed inputs.
pub fn screen(cfg: &AgentConfig, rights: &dyn privileges::Probe) -> Screen {
    let mut screen = Screen::default();
    screen.look(VOLUME_DRIVERS, &cfg.volume, rights, false);
    screen.look(DEVICE_DRIVERS, &cfg.device, rights, false);
    screen.look(HYPERVISOR_DRIVERS, &cfg.hypervisor, rights, true);

    // The singleton `[network]` section needs a separate prerequisite check.
    if cfg.network.is_some() {
        let row = &NETWORK_DRIVERS[0];
        screen.watch.push(privileges::Watched {
            driver: row.name,
            needs: row.needs,
        });
        match row.needs.missing(row.name, rights) {
            Some(gap) => {
                screen.skip.insert(row.name);
                screen.gaps.push(gap);
            }
            // Router namespace setup additionally needs CAP_SYS_ADMIN. Report the gap
            // without excluding the network driver or its configured gateway claims.
            None => {
                let claims_gateway = cfg
                    .network
                    .as_ref()
                    .and_then(|network| network.provider.as_ref())
                    .is_some_and(|provider| !provider.physnets.is_empty());
                if claims_gateway {
                    screen.watch.push(privileges::Watched {
                        driver: "router",
                        needs: &privileges::ROUTER,
                    });
                    if let Some(gap) = privileges::ROUTER.missing("router", rights) {
                        screen.gaps.push(gap);
                    }
                }
            }
        }
    }
    screen
}

/// Always register the default filesystem backend. Its optional section
/// overrides paths and tooling without controlling registration.
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
        // Probe and convert untrusted base images in the default transient-unit sandbox.
        convert: agent_api::base_image::Sandbox::default(),
        // Staging files carry the writing node's id so a shared pool directory cannot have
        // one node's start-up sweep remove another's copy (R3-F09).
        host_id: cfg.node_id.clone(),
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
        // Where LVM's symlinks are. Not a key: a node whose device nodes are
        // not under /dev is not a node LVM runs on.
        dev_dir: std::path::PathBuf::from("/dev"),
        // Run base-image conversion in the default transient-unit sandbox.
        convert: agent_api::base_image::Sandbox::default(),
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
    // Default node-local claims beside the agent database.
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
        // The share is every node's pool, so staging files stay per-node (R3-F09).
        host_id: cfg.node_id.clone(),
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
        log_dir: backend_log_dir(cfg, DRIVER_CROSVM_GPU),
        defaults: g.defaults.clone(),
        profiles: g.profiles.clone(),
        socket_timeout: Duration::from_millis(g.socket_timeout_ms),
        vmm_user: vmm_user(cfg)?,
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
        log_dir: backend_log_dir(cfg, DRIVER_NVRM),
        socket_timeout: Duration::from_millis(n.socket_timeout_ms),
        vram_budget_mib: n.vram_budget_mib,
        vgpu_host_reserve_mib: n.vgpu_host_reserve_mib,
        defaults: n.defaults.clone(),
        profiles: n.profiles.clone(),
        // A vhost-user backend maps the guest's memory, so it drops with the
        // vmm and not after it. See `agent_api::VmmUser`.
        vmm_user: vmm_user(cfg)?,
    })?;
    Ok(Some(Arc::new(driver)))
}

/// Build the input backend; its evdev profile is defined by the driver.
fn build_input(
    sections: &Sections,
    cfg: &AgentConfig,
) -> anyhow::Result<Option<Arc<dyn DeviceDriver>>> {
    let Some(i): Option<InputConfig> = section(sections, "device", DRIVER_INPUT)? else {
        return Ok(None);
    };
    let driver = InputDriver::new(input_driver::InputDriverConfig {
        binary: i.binary.clone(),
        run_dir: cfg.paths.run_dir.join(DRIVER_INPUT),
        log_dir: backend_log_dir(cfg, DRIVER_INPUT),
        socket_timeout: Duration::from_millis(i.socket_timeout_ms),
        vmm_user: vmm_user(cfg)?,
        evdev: i.evdev.clone(),
    })?;
    Ok(Some(Arc::new(driver)))
}

/// Build VFIO from `[device].managed`; an empty inventory registers nothing.
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

/// Where a device driver's backends log: beside the run directories and not
/// in one, because a run directory goes to the vmm user and this one stays
/// the agent's (the drivers make it 0700 and refuse a link in its place).
fn backend_log_dir(cfg: &AgentConfig, driver: &str) -> std::path::PathBuf {
    cfg.paths.run_dir.join("backend-logs").join(driver)
}

/// Resolve the configured backend user during driver construction.
fn vmm_user(cfg: &AgentConfig) -> anyhow::Result<Option<agent_api::VmmUser>> {
    cfg.vmm_user
        .as_deref()
        .map(agent_api::VmmUser::resolve)
        .transpose()
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
    // A separate VMM user requires tap descriptors. Cloud Hypervisor cannot
    // live-migrate NICs configured this way.
    let vmm_user = vmm_user(cfg)?;
    let driver = cloud_hypervisor_driver::CloudHypervisorDriver::new(
        h.binary.clone(),
        cfg.paths.run_dir.join("vms"),
        Duration::from_millis(h.timeout_ms),
        h.unplug_timeout(),
    )?
    .with_tap_fds(vmm_user.is_some())
    .with_vmm_user(vmm_user)
    // Permit later hotplug access under the default image and volume directories.
    // Driver-specific storage paths are not added here.
    .with_landlock_paths(vec![
        cfg.paths.image_dir.clone(),
        cfg.paths.volume_dir.clone(),
    ]);
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

/// Network capabilities used for admission and controller advertisements.
#[derive(Clone, Debug, Default)]
pub struct NetworkCatalog {
    profiles: Vec<String>,
    /// Whether a NIC driver was registered, independently of optional profiles.
    makes_taps: bool,
}

impl NetworkCatalog {
    /// Build profiles from enabled network config and registered provider networks.
    pub fn new(
        cfg: Option<&crate::config::NetworkConfig>,
        makes_taps: bool,
        physnets: &[String],
    ) -> Self {
        let mut profiles = Vec::new();
        if let Some(vxlan) = cfg.and_then(|c| c.vxlan.as_ref()) {
            profiles.push(common::capability::VXLAN.to_string());
            // Advertise EVPN in addition to VXLAN so overlay matching remains compatible.
            if vxlan.evpn {
                profiles.push(common::capability::EVPN.to_string());
            }
        }
        // No separate floating-address or BGP profile is advertised. Provider
        // networks contribute gateway claims from the registered bridge driver.
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

    /// Advertised optional network profiles. Empty profiles add no network entry.
    pub fn inventory(&self) -> Vec<String> {
        self.profiles.clone()
    }

    pub fn serves_overlays(&self) -> bool {
        self.profiles.iter().any(|p| p == common::capability::VXLAN)
    }

    /// Reject unavailable provider networks with `CannotServe` so scheduling
    /// can choose another node. Later driver errors concern the individual attempt.
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

    /// Reject NIC requirements unavailable on this node before provisioning.
    /// A NIC may select a provider network or VXLAN overlay, never both.
    pub fn validate(&self, nics: &[crate::types::NicWithId]) -> anyhow::Result<()> {
        if !nics.is_empty() && !self.makes_taps {
            bail!(
                "this node has no [network] section and so makes no taps; a vm with {} nic(s) \
                 cannot run here",
                nics.len()
            );
        }
        for n in nics {
            // Reject mutually exclusive provider and overlay wiring before provisioning
            // so the structural failure can release the node binding.
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
    /// Resource confinement is always constructed, including for storage-only nodes.
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
    /// Optional route announcer. Without one, reachability depends on external routes.
    pub announcer: Option<Arc<dyn RouteAnnouncer>>,
    pub devices: HashMap<String, Arc<dyn DeviceDriver>>,
}

/// What startup made of the configured drivers.
pub struct Startup {
    pub drivers: Drivers,
    /// Configured device drivers whose constructor failed, with the reason.
    /// They stay unregistered until a restart builds them; see [`report_unavailable`].
    pub unavailable: Vec<String>,
}

/// Raise [`crate::conditions::DRIVER_UNAVAILABLE`] for device drivers that
/// could not be built. Only a restart retries them, so nothing clears it.
pub fn report_unavailable(unavailable: &[String], conditions: &crate::conditions::Conditions) {
    if !unavailable.is_empty() {
        conditions.raise(
            crate::conditions::DRIVER_UNAVAILABLE,
            unavailable.join(" | "),
        );
    }
}

impl Drivers {
    /// Build the drivers, leaving out device drivers that could not be built.
    pub async fn from_config(cfg: &AgentConfig) -> anyhow::Result<Self> {
        Ok(Self::start(cfg).await?.drivers)
    }

    /// Build the drivers. A device driver whose constructor fails is left out
    /// and reported, not fatal: a wrong backend setting must not keep the agent
    /// from managing the guests it already runs. Its capability is then simply
    /// not advertised.
    pub async fn start(cfg: &AgentConfig) -> anyhow::Result<Startup> {
        // Require explicit compute or storage configuration. The implicit filesystem
        // fallback alone is not a declaration of a storage-only node.
        if cfg.hypervisor.is_empty() && cfg.volume.is_empty() {
            bail!(
                "this agent serves nothing: it has no [hypervisor.*] section, so it runs no \
                 vms, and no [volume.*] section, so it offers no storage. Configure one or \
                 the other"
            );
        }

        // Move the agent below a delegated root so child cgroups can enable resource
        // controllers. Failure is logged; the filesystem-type condition does not
        // verify delegation or controller availability.
        let mut cgroups = cgroup_driver::CgroupV2::new(cfg.paths.cgroup_root.clone());
        match cgroups.join_supervisor_subgroup() {
            Ok(Some(supervisor)) => tracing::info!(
                supervisor = %supervisor.display(),
                "this agent hung itself below its delegated cgroup root, so the root can hand \
                 cpu and memory to vm slices"
            ),
            Ok(None) => {}
            Err(e) => tracing::warn!(
                cgroup_root = %cfg.paths.cgroup_root.display(),
                error = %format!("{e:#}"),
                "could not move this process into <cgroup_root>/supervisor; vm slices under a \
                 root that still holds this process cannot be given limits"
            ),
        }
        let confiner = Arc::new(cgroups);

        // Screen host prerequisites before constructors perform privileged work.
        let rights = privileges::Host;
        let screen = screen(cfg, &rights);
        // Log measured primitives alongside prerequisite diagnostics.
        tracing::info!(
            rights = %privileges::Probe::primitives(&rights, &cfg.paths.cgroup_root),
            "the rights this agent came up with"
        );
        for gap in &screen.gaps {
            // Report each configured driver whose requirements are unmet.
            tracing::warn!(detail = %gap, "a configured driver is not registered on this node");
        }
        // A configured hypervisor must pass its prerequisite checks.
        if let Some(fatal) = screen.fatal {
            bail!("{fatal}");
        }

        // Construct drivers from the registry after screening.
        let skip = &screen.skip;
        let (hypervisor_name, hypervisor) =
            register_one(HYPERVISOR_DRIVERS, &cfg.hypervisor, cfg, "hypervisor", skip)?.unzip();
        let storage = register(VOLUME_DRIVERS, &cfg.volume, cfg, "volume", skip)?;
        let (devices, unavailable) =
            register_or_report(DEVICE_DRIVERS, &cfg.device, cfg, "device", skip)?;
        for detail in &unavailable {
            tracing::error!(%detail, "a configured device driver is not registered on this node");
        }
        // `[network]` is not a table of sections, so there is none to check
        // against; the row's own builder reads `cfg.network`. See
        // `NETWORK_DRIVERS`.
        let net: Option<Arc<dyn NetworkDriver>> =
            register_one(NETWORK_DRIVERS, &Sections::new(), cfg, "network", skip)?.map(|(_, n)| n);
        // Share one configured instance between NIC and bridge interfaces.
        let networking: Option<Arc<dyn NicDriver>> = net.clone().map(|n| n as Arc<dyn NicDriver>);
        let bridge: Option<Arc<dyn BridgeDriver>> = net.map(|n| n as Arc<dyn BridgeDriver>);

        // Validate FRR connectivity during startup rather than the first announcement.
        let announcer: Option<Arc<dyn RouteAnnouncer>> = match cfg.bgp_config()? {
            Some(bgp) => Some(Arc::new(linux_network_driver::frr::Frr::new(bgp).await?)),
            None => None,
        };

        Ok(Startup {
            drivers: Self {
                confiner,
                hypervisor,
                hypervisor_name,
                storage,
                networking,
                bridge,
                announcer,
                devices,
            },
            unavailable,
        })
    }

    /// Return the hypervisor or a configuration error for a storage-only node.
    pub fn hypervisor(&self) -> anyhow::Result<&Arc<dyn Hypervisor>> {
        self.hypervisor.as_ref().ok_or_else(|| {
            anyhow::anyhow!(
                "this node has no [hypervisor.*] section and so runs no vms; it was asked to \
                 run one anyway"
            )
        })
    }

    /// Return the networking driver or explain why this node cannot create taps.
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

/// Advertise the registered hypervisor and reject VM requests when absent.
#[derive(Clone, Debug, Default)]
pub struct HypervisorCatalog {
    /// The configured driver's name, or `None` on a node that runs no VMs.
    driver: Option<String>,
}

impl HypervisorCatalog {
    /// Use the constructed driver's registry name.
    pub fn new(name: Option<&str>) -> Self {
        Self {
            driver: name.map(str::to_string),
        }
    }

    /// Hypervisor profile for Hello, or an empty inventory.
    pub fn inventory(&self) -> Vec<String> {
        self.driver.iter().cloned().collect()
    }

    /// Reject VM requests before allocating resources when no hypervisor exists.
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

/// Registered storage backends used to reject unsupported specs before provisioning.
#[derive(Clone, Debug)]
pub struct VolumeCatalog {
    /// Driver name and locality, measured at catalogue construction and sorted.
    drivers: Vec<(String, Locality)>,
    /// Driver-advertised snapshot support and consistency requirements, sampled at startup.
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

    /// Advertise both `<backend>/snapshot` and a consistency profile. Keeping the
    /// bare claim preserves compatibility with controllers that do not parse
    /// consistency. The value comes from the driver, not its name.
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

    /// Cached snapshot support for controller advertisement and admission checks.
    pub fn snapshot_support(&self, backend: &str) -> Option<SnapshotConsistency> {
        self.snapshots
            .iter()
            .find(|(name, _)| name == backend)
            .map(|(_, c)| *c)
    }

    /// Storage profiles, flattened by Hello under the `volume` capability namespace.
    pub fn inventory(&self) -> Vec<String> {
        self.drivers.iter().map(|(name, _)| name.clone()).collect()
    }

    pub fn validate(&self, volumes: &[VolumeWithId]) -> anyhow::Result<()> {
        for v in volumes {
            self.validate_driver(v.spec.driver.as_deref())?;
        }
        Ok(())
    }

    /// Validate a standalone volume's driver before provisioning begins.
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
        async fn probe(
            &self,
            _: &agent_api::VolumeId,
            _: &VolumeSpec,
        ) -> agent_api::storage::Result<Option<VolumeHandle>> {
            unreachable!("the catalogue never looks at any bytes")
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

    /// Preserve each driver's locality beside its advertised name.
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

    /// Reject unregistered volume drivers before provisioning resources.
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

    /// Advertised driver inventory is sorted and matches scheduler capability checks.
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

    /// Reject unsupported overlays without falling back to the default bridge.
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

    /// Network advertisements match the scheduler capability format.
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
        // An omitted driver selects the default registered by from_config.
        cat.validate(&[volume(None)]).unwrap();
        catalogue(&[]).validate(&[volume(None)]).unwrap();
    }

    /// Build registry-test configuration with paths in one temporary directory.
    /// The default filesystem driver requires an existing image directory.
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

    /// Include all registry entries independently of host prerequisite checks.
    fn nothing_skipped() -> HashSet<&'static str> {
        HashSet::new()
    }

    /// Build configuration with optional hypervisor and network sections.
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

    /// Register the default volume driver without a section; optional drivers require one.
    #[test]
    fn the_default_volume_driver_is_registered_without_a_section() {
        let (_temp, cfg) = config("");
        assert!(cfg.volume.is_empty(), "no [volume] section at all");

        let storage = register(
            VOLUME_DRIVERS,
            &cfg.volume,
            &cfg,
            "volume",
            &nothing_skipped(),
        )
        .expect("a config with no [volume] section still has storage");
        assert_eq!(
            storage.keys().collect::<Vec<_>>(),
            vec![&agent_api::default_volume_driver()],
            "the default backend, and only it"
        );
    }

    /// An absent or empty managed-device inventory leaves VFIO unregistered.
    #[test]
    fn vfio_without_a_managed_inventory_is_not_registered() {
        for sections in ["", "[device]\nmanaged = []"] {
            let (_temp, cfg) = config(sections);
            let devices = register(
                DEVICE_DRIVERS,
                &cfg.device,
                &cfg,
                "device",
                &nothing_skipped(),
            )
            .expect("nothing configured is not an error");
            assert!(
                devices.is_empty(),
                "{sections:?} registers no device driver, got {:?}",
                devices.keys().collect::<Vec<_>>()
            );
        }
    }

    #[test]
    fn a_node_with_the_input_section_claims_evdev() {
        let binary = std::env::current_exe().expect("this test binary");
        let (_temp, cfg) = config(&format!("[device.input]\nbinary = {binary:?}"));

        let devices = register(
            DEVICE_DRIVERS,
            &cfg.device,
            &cfg,
            "device",
            &nothing_skipped(),
        )
        .expect("[device.input] builds the driver");
        let cat = DeviceCatalog::new(&devices);
        assert_eq!(
            cat.inventory(),
            vec![(DRIVER_INPUT.to_string(), vec!["evdev".to_string()])],
            "one evdev profile"
        );

        let catalogue: Vec<String> = cat
            .inventory()
            .into_iter()
            .flat_map(|(name, profiles)| {
                profiles
                    .into_iter()
                    .map(move |p| common::capability::entry(&name, Some(&p)))
                    .collect::<Vec<_>>()
            })
            .collect();
        assert_eq!(catalogue, vec!["input/evdev"]);
        assert!(
            common::capability::offers(&catalogue, DRIVER_INPUT, Some("evdev")),
            "a vm asking for input/evdev fits this node"
        );
        assert!(common::capability::offers(&catalogue, DRIVER_INPUT, None));
        assert!(!common::capability::offers(
            &catalogue,
            DRIVER_INPUT,
            Some("touchscreen")
        ));

        let device = |profile: &str| DeviceWithId {
            id: agent_api::device::DeviceId::new_v4(),
            spec: agent_api::device::DeviceSpec {
                driver: DRIVER_INPUT.to_string(),
                partition: agent_api::device::PartitionSpec::Mediated,
                profile: Some(profile.to_string()),
                params: None,
            },
        };
        cat.validate(&[device("evdev")])
            .expect("evdev is available");
        assert!(cat.validate(&[device("fifo")]).is_err());
        let err = cat
            .validate(&[device("touchscreen")])
            .expect_err("and nothing else is")
            .to_string();
        assert!(err.contains("evdev"), "{err}");
    }

    /// The Cloud Hypervisor section builds one driver; absence builds none.
    #[test]
    fn the_hypervisor_section_still_names_the_driver_it_always_named() {
        let (_temp, cfg) = config("");
        let built = register_one(
            HYPERVISOR_DRIVERS,
            &cfg.hypervisor,
            &cfg,
            "hypervisor",
            &nothing_skipped(),
        )
        .expect("the example's hypervisor section builds");
        assert!(built.is_some(), "[hypervisor.cloud-hypervisor] builds one");

        let (_temp, none) = raw_config(r#"[volume.filesystem]"#);
        assert!(
            register_one(
                HYPERVISOR_DRIVERS,
                &none.hypervisor,
                &none,
                "hypervisor",
                &nothing_skipped()
            )
            .expect("no section is not an error")
            .is_none(),
            "a node with no [hypervisor.*] section runs no vms"
        );
    }

    /// Reject unknown hypervisor sections and list registered choices.
    #[test]
    fn an_unknown_hypervisor_section_is_refused_by_name() {
        let (_temp, cfg) = raw_config(
            r#"[hypervisor.qemu]
                                binary = "/usr/bin/qemu-system-x86_64""#,
        );
        let Err(err) = register_one(
            HYPERVISOR_DRIVERS,
            &cfg.hypervisor,
            &cfg,
            "hypervisor",
            &nothing_skipped(),
        ) else {
            panic!("qemu is a typo, not a hypervisor this agent has");
        };
        let err = err.to_string();
        assert!(err.contains("[hypervisor.qemu]"), "{err}");
        assert!(
            err.contains("cloud-hypervisor"),
            "the message says what IS built in: {err}"
        );
    }

    /// Reject multiple drivers for a single slot rather than depending on map iteration order.
    #[test]
    fn two_drivers_in_a_single_slot_are_refused_rather_than_picked_between() {
        static TWO: &[DriverEntry<dyn VolumeDriver>] = &[
            DriverEntry {
                name: "a",
                keys: &["a"],
                needs: &privileges::NOTHING,
                build: |_, _| Ok(Some(Arc::new(Stub(Locality::NodeLocal, None)))),
            },
            DriverEntry {
                name: "b",
                keys: &["b"],
                needs: &privileges::NOTHING,
                build: |_, _| Ok(Some(Arc::new(Stub(Locality::NodeLocal, None)))),
            },
        ];
        let (_temp, cfg) = config("");
        let Err(err) = register_one(
            TWO,
            &Sections::new(),
            &cfg,
            "hypervisor",
            &nothing_skipped(),
        ) else {
            panic!("two configured rows in a single slot is not a choice to make");
        };
        let err = err.to_string();
        assert!(err.contains("2 hypervisor drivers"), "{err}");
        assert!(err.contains("a, b"), "the message names both: {err}");
    }

    /// Reject configurations that serve neither VMs nor explicitly configured storage.
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

    /// Storage-only nodes need no hypervisor or network, but retain backend cgroup confinement.
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

    /// Compute-node hypervisor advertisements match the scheduler capability format.
    #[tokio::test]
    async fn a_compute_node_claims_the_hypervisor_a_scheduler_would_match() {
        // A compute node may omit networking; this fixture then needs no nftables access.
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

    /// Storage-only nodes omit the hypervisor inventory entry. An empty profile
    /// list would still advertise the bare `hypervisor` capability.
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

    /// No network section and bridge-only networking both advertise no overlay.
    /// The local `makes_taps` flag distinguishes their NIC support.
    #[test]
    fn a_node_without_a_network_section_claims_no_overlay() {
        let cat = NetworkCatalog::new(None, false, &[]);
        assert!(cat.inventory().is_empty());
        assert!(!cat.serves_overlays());
        assert_eq!(cat.inventory(), network(false).inventory());
        // A VM with no NIC at all is still perfectly welcome here.
        cat.validate(&[]).expect("no nic, no taps needed");
    }

    /// Advertise one gateway capability per configured provider network.
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

    /// Unavailable provider networks produce structural `CannotServe` failures.
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

    /// Reject simultaneous provider and overlay wiring before provisioning.
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

    /// NIC requests require a registered tap driver before provisioning starts.
    #[test]
    fn a_nic_on_a_node_that_makes_no_taps_is_refused_where_it_is_structural() {
        let none = NetworkCatalog::new(None, false, &[]);
        let err = none
            .validate(&[tenant_nic(None)])
            .expect_err("this node makes no taps");
        let err = err.to_string();
        assert!(err.contains("[network]"), "it names the section: {err}");
        assert!(err.contains("makes no taps"), "{err}");

        // Configured networking accepts a plain NIC; overlay support is checked separately.
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

    /// Reject configuration sections not owned by any driver and identify their names.
    #[test]
    fn a_section_no_driver_owns_is_refused_by_name() {
        let (_temp, cfg) = config("[volume.ceph]\npool = \"rbd\"");
        let Err(err) = register(
            VOLUME_DRIVERS,
            &cfg.volume,
            &cfg,
            "volume",
            &nothing_skipped(),
        ) else {
            panic!("ceph is not a storage backend this agent has");
        };
        let err = err.to_string();
        assert!(err.contains("[volume.ceph]"), "{err}");
        assert!(
            err.contains("filesystem, lvm-thin, nfs"),
            "the message says what IS built in: {err}"
        );

        // Device errors list accepted configuration keys, including managed rather than vfio.
        let (_temp, cfg) = config("[device.crosvm-gp]\nbinary = \"/usr/bin/crosvm\"");
        let Err(err) = register(
            DEVICE_DRIVERS,
            &cfg.device,
            &cfg,
            "device",
            &nothing_skipped(),
        ) else {
            panic!("crosvm-gp is a typo, not a device backend");
        };
        let err = err.to_string();
        assert!(err.contains("[device.crosvm-gp]"), "{err}");
        assert!(err.contains("crosvm-gpu, input, managed, nvrm"), "{err}");
    }

    /// Snapshot claims include support and consistency, preserving the bare claim.
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
        // Include a driver with no snapshot support.
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
        // Flatten capabilities as the scheduler and API edge see them.
        let flat: Vec<String> = catalogue
            .snapshot_claims()
            .iter()
            .map(|p| common::capability::entry(common::capability::VOLUME, Some(p)))
            .collect();
        assert!(flat.contains(&"volume/lvm-thin/snapshot".to_string()));
        assert!(flat.contains(&"volume/lvm-thin/snapshot:atomic".to_string()));
        assert!(!flat.contains(&"volume/blackhole/snapshot".to_string()));

        // Retain the bare capability for controllers that do not inspect consistency profiles.
        assert!(
            common::capability::offers(
                &flat,
                common::capability::VOLUME,
                Some("lvm-thin/snapshot")
            ),
            "the old question still gets the old answer"
        );

        // Carry runtime-advertised consistency independently of the driver name.
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

    // Prerequisite screening with synthetic host rights.

    use crate::privileges::{Capability, Denial, fake::Fake};

    /// Skip unavailable configured backends and report each missing prerequisite.
    #[test]
    fn an_unprivileged_node_leaves_out_what_it_may_not_build() {
        let (_temp, cfg) = config(
            r#"[volume.lvm-thin]
               vg = "vg0"
               thin_pool = "pool"
               [volume.nfs]
               share_root = "/srv/nfs"
               [volume.filesystem]"#,
        );
        let screen = screen(&cfg, &Fake::unprivileged());

        assert!(screen.skip.contains(DRIVER_LVM_THIN));
        assert!(screen.skip.contains(DRIVER_NFS));
        assert!(screen.skip.contains(DRIVER_LINUX_NETWORK));
        assert!(
            !screen.skip.contains(DRIVER_FILESYSTEM),
            "the default backend needs nothing and stays"
        );
        assert!(
            screen.fatal.is_none(),
            "a node that can do less is not a node that must not start: {:?}",
            screen.fatal
        );
        assert_eq!(screen.gaps.len(), 3, "{:?}", screen.gaps);
        let said = screen.gaps.join(" | ");
        assert!(
            said.contains("CAP_SYS_ADMIN and CAP_DAC_OVERRIDE"),
            "{said}"
        );
        assert!(
            said.contains("tap guard off: guests on this node are not filtered"),
            "the security statement is said out loud: {said}"
        );

        // Skipped drivers must also be absent from the registered catalogue.
        let storage = register(VOLUME_DRIVERS, &cfg.volume, &cfg, "volume", &screen.skip)
            .expect("a node with no rights still comes up");
        assert!(storage.contains_key(DRIVER_FILESYSTEM));
        assert!(!storage.contains_key(DRIVER_LVM_THIN));
        assert!(!storage.contains_key(DRIVER_NFS));
    }

    /// CAP_NET_ADMIN permits tap networking while privileged storage remains unavailable.
    #[test]
    fn with_cap_net_admin_the_taps_stay_and_the_storage_does_not() {
        let (_temp, cfg) = config(
            r#"[volume.lvm-thin]
               vg = "vg0"
               thin_pool = "pool""#,
        );
        let screen = screen(&cfg, &Fake::unprivileged().with(Capability::NetAdmin));

        assert!(
            !screen.skip.contains(DRIVER_LINUX_NETWORK),
            "CAP_NET_ADMIN is the whole of what a tap, a bridge and the guard need"
        );
        assert!(screen.skip.contains(DRIVER_LVM_THIN));
    }

    /// Gateway prerequisites can fail while the network driver retains tap support.
    #[test]
    fn a_node_that_claims_a_gateway_without_cap_sys_admin_says_so() {
        let (_temp, cfg) = config(
            r#"[network.provider]
               physnets = { ext = "eth1" }"#,
        );
        let screen = screen(&cfg, &Fake::unprivileged().with(Capability::NetAdmin));

        assert!(!screen.skip.contains(DRIVER_LINUX_NETWORK));
        let said = screen.gaps.join(" | ");
        assert!(said.contains("router: needs CAP_SYS_ADMIN"), "{said}");
        assert!(said.contains("network/gateway"), "{said}");

        // With it, nothing is said at all.
        let screen = super::screen(
            &cfg,
            &Fake::unprivileged()
                .with(Capability::NetAdmin)
                .with(Capability::SysAdmin),
        );
        assert!(screen.gaps.is_empty(), "{:?}", screen.gaps);
    }

    /// A configured hypervisor cannot start without access to KVM.
    #[test]
    fn a_node_that_cannot_open_dev_kvm_does_not_start() {
        let (_temp, cfg) = config("");
        let screen = screen(
            &cfg,
            &Fake::root().without_device("/dev/kvm", Denial::Refused("Permission denied".into())),
        );
        let fatal = screen
            .fatal
            .expect("a node that runs no vm must not come up");
        assert!(fatal.contains("cloud-hypervisor"), "{fatal}");
        assert!(fatal.contains("/dev/kvm"), "{fatal}");
    }

    /// Root prerequisites permit every configured driver.
    #[test]
    fn as_root_the_start_check_changes_nothing() {
        let (_temp, cfg) = config(
            r#"[volume.lvm-thin]
               vg = "vg0"
               thin_pool = "pool"
               [volume.nfs]
               share_root = "/srv/nfs"
               [device.nvrm]
               binary = "/opt/meisterstack/bin/vhost-user-nvrm"
               vgpuprofile = "/opt/meisterstack/bin/vgpuprofile""#,
        );
        let screen = screen(&cfg, &Fake::root());
        assert!(screen.skip.is_empty(), "{:?}", screen.skip);
        assert!(screen.gaps.is_empty(), "{:?}", screen.gaps);
        assert!(screen.fatal.is_none());
        // Watch satisfied prerequisites too so later failures and recovery update the condition.
        assert!(screen.watch.len() >= 5, "{}", screen.watch.len());
    }

    /// Do not report prerequisites for unconfigured drivers.
    #[test]
    fn a_driver_nobody_configured_says_nothing() {
        let (_temp, cfg) = config("");
        let screen = screen(&cfg, &Fake::unprivileged());
        let said = screen.gaps.join(" | ");
        assert!(!said.contains(DRIVER_LVM_THIN), "{said}");
        assert!(!said.contains(DRIVER_NVMEOF), "{said}");
        assert!(!said.contains(DRIVER_VFIO), "{said}");
    }

    /// IKR-B15: a device driver whose configuration cannot be built is left
    /// out and named, and the agent still registers every other driver. The
    /// nvrm section fails on its missing host reserve before it asks the card
    /// anything.
    #[test]
    fn a_device_driver_that_cannot_be_built_is_reported_and_the_rest_registers() {
        let binary = std::env::current_exe().expect("this test binary");
        let (_temp, cfg) = config(&format!(
            r#"[device.input]
               binary = {binary:?}
               [device.nvrm]
               binary = {binary:?}
               vgpuprofile = "/nonexistent/vgpuprofile"
               [device.nvrm.profiles.4q]
               vgpu_type = "4Q""#
        ));
        let (devices, unavailable) = register_or_report(
            DEVICE_DRIVERS,
            &cfg.device,
            &cfg,
            "device",
            &nothing_skipped(),
        )
        .expect("a driver that cannot be built does not stop the agent");
        assert!(devices.contains_key(DRIVER_INPUT));
        assert!(!devices.contains_key(DRIVER_NVRM));
        let said = unavailable.join(" | ");
        assert!(said.contains("\"nvrm\""), "{said}");
        assert!(said.contains("vgpu_host_reserve_mib"), "{said}");
    }

    /// The reason a driver is missing is part of the node's status.
    #[test]
    fn an_unavailable_driver_is_reported_as_a_node_condition() {
        let conditions = crate::conditions::Conditions::default();
        report_unavailable(&[], &conditions);
        assert!(
            conditions.report().is_empty(),
            "nothing failed, nothing said"
        );

        report_unavailable(&["device driver \"nvrm\": why".to_string()], &conditions);
        let said = conditions
            .message(crate::conditions::DRIVER_UNAVAILABLE)
            .expect("raised");
        assert!(said.contains("nvrm"), "{said}");
    }
}
