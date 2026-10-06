// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

use anyhow::{Context, bail};
use crosvm_gpu_driver::GpuParams;
use nvrm_driver::NvrmParams;
use serde::Deserialize;
use std::collections::{BTreeMap, HashMap};
use std::fs::read_to_string;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;
use toml::from_str;

fn default_nvrm_socket_timeout_ms() -> u64 {
    nvrm_driver::DEFAULT_SOCKET_TIMEOUT_MS
}
fn default_input_socket_timeout_ms() -> u64 {
    input_driver::DEFAULT_SOCKET_TIMEOUT_MS
}
fn default_nfs_socket_timeout_ms() -> u64 {
    nfs_driver::DEFAULT_SOCKET_TIMEOUT_MS
}
fn default_max_data_percent() -> f64 {
    lvm_thin_driver::DEFAULT_MAX_DATA_PERCENT
}
fn default_qemu_img() -> PathBuf {
    PathBuf::from("qemu-img")
}
fn default_fs_type() -> String {
    "nfs".to_string()
}
use agent_api::types::pci::PciAddress;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentConfig {
    pub node_id: String,
    /// Single-controller fallback; a nonempty `controller_addrs` takes precedence.
    pub controller_addr: Option<String>,
    /// Controller replicas. Rendezvous hashing derives a node-specific preference
    /// order independent of list order; see `hrw`.
    #[serde(default)]
    pub controller_addrs: Vec<String>,
    #[serde(default = "default_stop_grace_secs")]
    pub stop_grace_secs: u64,
    /// Maximum wait for the source send API. Timeout records an unresolved
    /// outcome; it does not establish that the guest is safe to restart. Default: 600 s.
    #[serde(default = "default_migration_ceiling_secs")]
    pub migrate_out_ceiling_secs: u64,
    /// Advisory destination receive interval persisted with the attempt. Expiry
    /// alone does not authorize cleanup. Default: 600 s.
    #[serde(default = "default_migration_ceiling_secs")]
    pub receive_ceiling_secs: u64,
    /// Optional OTLP collector for span export, for example `http://127.0.0.1:4317`.
    #[serde(default)]
    pub otlp_endpoint: Option<String>,
    /// Log output format: `human` by default, or `json`. Filtering uses RUST_LOG.
    #[serde(default)]
    pub log_format: telemetry::LogFormat,
    /// Optional Prometheus listener, separate from the local admin socket.
    #[serde(default)]
    pub metrics_listen: Option<String>,
    /// Migration address reachable by peer nodes. When absent, derive an IPv4
    /// source address from a route to a configured controller endpoint. Set this
    /// explicitly when controller and peer traffic use different interfaces.
    #[serde(default)]
    pub advertise_addr: Option<String>,
    /// Operator-supplied physical host identity for nested nodes. Migration
    /// compatibility uses it to restrict nested transfers to a known shared host.
    #[serde(default)]
    pub physical_host: Option<String>,
    /// Optional user for the VMM and supported vhost-user backends. The agent
    /// prepares privileged resources before dropping backend identity. The user
    /// must exist and must not belong to the agent socket group.
    #[serde(default)]
    pub vmm_user: Option<String>,

    // Optional controller TLS credentials. Relative PEM paths resolve against
    // the config directory; no credentials selects plaintext gRPC.
    #[serde(default)]
    pub controller_ca: Option<PathBuf>,
    /// Client certificate identity `CN=system:node:<node_id>`, checked against Hello.
    #[serde(default)]
    pub controller_cert: Option<PathBuf>,
    #[serde(default)]
    pub controller_key: Option<PathBuf>,

    // Optional ceilings on measured host capacity, useful for multiple agents
    // on one host. These affect advertisements, not guest CPU affinity.
    #[serde(default)]
    pub capacity_vcpus: Option<u32>,
    #[serde(default)]
    pub capacity_mem_mib: Option<u64>,
    /// `cpuset.cpus` for the agent VM slice, for example `0-15,32-47`.
    /// Capacity ceilings limit advertised resources; this setting restricts CPU placement.
    #[serde(default)]
    pub cgroup_cpuset: Option<String>,

    // Guarded IPv4 ranges shared with the cloud floating pools. Tap rules permit
    // only the addresses assigned to that NIC within these ranges. Empty ranges
    // leave MAC pinning active. This duplicated configuration must be kept in sync.
    #[serde(default)]
    pub guarded_ranges: Vec<String>,
    /// Path to `nft`; defaults to PATH.
    #[serde(default)]
    pub nft: Option<String>,

    pub paths: PathsConfig,
    /// Optional hypervisor sections; at most one registered driver is allowed.
    #[serde(default)]
    pub hypervisor: Sections,
    /// Optional tap and bridge configuration. Without it, NIC requests are refused.
    #[serde(default)]
    pub network: Option<NetworkConfig>,
    /// Optional `[device.*]` sections, one per device backend.
    #[serde(default)]
    pub device: Sections,
    /// Storage driver sections. Filesystem is registered by default from `[paths]`.
    #[serde(default)]
    pub volume: Sections,
}

fn default_stop_grace_secs() -> u64 {
    30
}

/// Default migration observation interval in seconds.
fn default_migration_ceiling_secs() -> u64 {
    600
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PathsConfig {
    pub db_path: PathBuf,
    pub run_dir: PathBuf,
    pub image_dir: PathBuf,
    pub volume_dir: PathBuf,
    pub cgroup_root: PathBuf,
    /// Optional Unix group granted local admin access: directory/socket modes
    /// 0750/0660 instead of owner-only 0700/0600. Filesystem permissions are the
    /// socket's access control; there is no separate API authenticator.
    #[serde(default)]
    pub socket_group: Option<String>,
}

/// Cloud Hypervisor executable and operation settings.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CloudHypervisorConfig {
    pub binary: PathBuf,
    pub timeout_ms: u64,
    /// Inclusive receiver port range, for example `49000-49099`. Absence disables
    /// receiving; sending does not require a local receiver port.
    #[serde(default)]
    pub migration_ports: Option<String>,
    /// Wait for guest-cooperative hot unplug before returning an error. Default:
    /// 30 s; zero also selects the default. Timeout leaves ownership unresolved.
    #[serde(default = "default_unplug_timeout_secs")]
    pub unplug_timeout_secs: u64,
}

/// Use the driver default to keep config and runtime timeout values aligned.
fn default_unplug_timeout_secs() -> u64 {
    cloud_hypervisor_driver::DEFAULT_UNPLUG_TIMEOUT.as_secs()
}

impl CloudHypervisorConfig {
    /// `unplug_timeout_secs` as a duration, with zero read as the default.
    pub fn unplug_timeout(&self) -> Duration {
        match self.unplug_timeout_secs {
            0 => cloud_hypervisor_driver::DEFAULT_UNPLUG_TIMEOUT,
            secs => Duration::from_secs(secs),
        }
    }

    /// Parse the inclusive migration port range. Reject zero and reversed ranges.
    pub fn ports(&self) -> Result<Option<(u16, u16)>, String> {
        let Some(raw) = self.migration_ports.as_deref() else {
            return Ok(None);
        };
        let raw = raw.trim();
        let (from, to) = raw.split_once('-').ok_or_else(|| {
            format!("migration_ports = {raw:?} is not a range; write it as \"49000-49099\"")
        })?;
        let parse = |s: &str, which: &str| -> Result<u16, String> {
            s.trim()
                .parse::<u16>()
                .map_err(|e| format!("the {which} of migration_ports = {raw:?} is not a port: {e}"))
        };
        let (from, to) = (parse(from, "start")?, parse(to, "end")?);
        if from == 0 {
            return Err(format!(
                "migration_ports = {raw:?} starts at 0, which is not a port"
            ));
        }
        if to < from {
            return Err(format!("migration_ports = {raw:?} ends before it starts"));
        }
        Ok(Some((from, to)))
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkConfig {
    pub default_bridge: String,
    #[serde(default)]
    pub bridge_addr: Option<String>,
    /// Optional tenant VXLAN support; overlay NICs require it.
    #[serde(default)]
    pub vxlan: Option<VxlanNetworkConfig>,
    /// Optional FRR route announcements. Without this, reachability requires
    /// external routing; tap address guards still apply.
    #[serde(default)]
    pub bgp: Option<BgpNetworkConfig>,
    /// Optional provider interfaces for tenant routers and direct provider NICs.
    #[serde(default)]
    pub provider: Option<ProviderNetworkConfig>,
    /// Sweep unreferenced overlays once at startup when all VM rows are readable.
    /// Disable when overlay links are administered outside this agent.
    #[serde(default = "default_sweep_orphans")]
    pub sweep_orphans: bool,
}

fn default_sweep_orphans() -> bool {
    true
}

/// Provider interface mappings used to construct gateway capability claims.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderNetworkConfig {
    /// Provider-network name to host-interface mapping, sorted for stable claims.
    /// The interface must have no addresses when assigned to the provider bridge.
    pub physnets: BTreeMap<String, String>,
    /// Path to iproute2 `ip`; defaults to PATH. Router namespaces use named netns.
    #[serde(default)]
    pub ip: Option<String>,
    /// Path to `arping` for gratuitous ARP on router activation; defaults to PATH.
    #[serde(default)]
    pub arping: Option<String>,
}

/// FRR session configuration. Startup requires a responsive vtysh connection.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BgpNetworkConfig {
    /// This node's autonomous system number.
    pub asn: u32,
    /// Explicit dotted BGP router ID, independent of changing interface addresses.
    pub router_id: String,
    /// Addressed BGP peers and their ASNs. Unnumbered peers are not supported.
    #[serde(default)]
    pub neighbors: Vec<BgpNeighborConfig>,
    /// Path to `vtysh`; defaults to PATH.
    #[serde(default)]
    pub vtysh: Option<PathBuf>,
    /// Override FRR's default vty socket directory (`/var/run/frr`).
    #[serde(default)]
    pub vty_socket: Option<PathBuf>,
    /// Rendered configuration fragment; defaults to `<run_dir>/meister-bgp.conf`.
    #[serde(default)]
    pub fragment: Option<PathBuf>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BgpNeighborConfig {
    pub address: String,
    pub remote_asn: u32,
}

/// Tenant VXLAN support, enabled by the presence of `[network.vxlan]`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VxlanNetworkConfig {
    /// Host interface used to transmit encapsulated frames.
    pub uplink: String,
    /// MTU for the tenant bridge, VXLAN device and taps. Defaults to
    /// `linux_network_driver::DEFAULT_VXLAN_MTU`.
    #[serde(default = "default_vxlan_mtu")]
    pub mtu: u32,
    /// Distribute overlay MACs through BGP EVPN. Requires `[network.bgp]`
    /// and a consistent cluster setting; see `linux_network_driver::VxlanConfig::evpn`.
    #[serde(default)]
    pub evpn: bool,
}

fn default_vxlan_mtu() -> u32 {
    linux_network_driver::DEFAULT_VXLAN_MTU
}

impl NetworkConfig {
    pub fn parsed_bridge_addr(&self) -> anyhow::Result<Option<(IpAddr, u8)>> {
        let Some(raw) = &self.bridge_addr else {
            return Ok(None);
        };
        let (ip, prefix) = raw.split_once('/').ok_or_else(|| {
            anyhow::anyhow!("bridge_addr {raw:?} must be CIDR notation, e.g. 10.42.0.1/24")
        })?;
        let ip: IpAddr = ip
            .parse()
            .with_context(|| format!("bridge_addr {raw:?}: invalid ip address"))?;
        let prefix: u8 = prefix
            .parse()
            .with_context(|| format!("bridge_addr {raw:?}: invalid prefix length"))?;
        let max = if ip.is_ipv4() { 32 } else { 128 };
        if prefix > max {
            bail!("bridge_addr {raw:?}: prefix length {prefix} out of range (max {max})");
        }
        Ok(Some((ip, prefix)))
    }
}

/// Driver sections kept as TOML until the owning registry builder deserializes
/// them. Builders reject unknown fields; registration rejects unknown sections.
pub type Sections = HashMap<String, toml::Value>;

/// Deserialize one named driver section, adding its section name to errors.
pub fn section<T: serde::de::DeserializeOwned>(
    sections: &Sections,
    what: &str,
    key: &str,
) -> anyhow::Result<Option<T>> {
    let Some(raw) = sections.get(key) else {
        return Ok(None);
    };
    let parsed = raw
        .clone()
        .try_into()
        .with_context(|| format!("[{what}.{key}]"))?;
    Ok(Some(parsed))
}

/// LVM thin pool configuration. Startup validates that the pool exists.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LvmThinVolumeConfig {
    pub vg: String,
    pub thin_pool: String,
    /// Maximum pool data usage for creation. Defaults to
    /// `lvm_thin_driver::DEFAULT_MAX_DATA_PERCENT`.
    #[serde(default = "default_max_data_percent")]
    pub max_data_percent: f64,
    /// Base image directory; defaults to `[paths].image_dir`.
    #[serde(default)]
    pub image_dir: Option<PathBuf>,
    /// Directory containing `lvs`, `lvcreate` and `lvremove`; defaults to PATH.
    #[serde(default)]
    pub bin_dir: Option<PathBuf>,
    #[serde(default = "default_qemu_img")]
    pub qemu_img: PathBuf,
}

/// NVMe-oF attachment configuration. Targets come from each volume
/// handle; this driver does not provision namespaces.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NvmeofVolumeConfig {
    /// Directory containing `nvme`; defaults to PATH.
    #[serde(default)]
    pub bin_dir: Option<PathBuf>,
}

/// NVMe-oF provider configuration for assigning existing namespaces to volumes.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NvmeofImportVolumeConfig {
    /// Directory for per-namespace claim files; defaults beside the agent database.
    #[serde(default)]
    pub state_dir: Option<PathBuf>,
    /// Directory containing `nvme`; defaults to PATH.
    #[serde(default)]
    pub bin_dir: Option<PathBuf>,
}

/// NFS-backed volumes under `share_root`. `manage_mount` controls mounting.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NfsVolumeConfig {
    pub share_root: PathBuf,
    pub virtiofsd: PathBuf,
    /// Node-local base image directory; defaults to `[paths].image_dir`.
    #[serde(default)]
    pub image_dir: Option<PathBuf>,
    /// Backend socket timeout; defaults to `nfs_driver::DEFAULT_SOCKET_TIMEOUT_MS`.
    #[serde(default = "default_nfs_socket_timeout_ms")]
    pub socket_timeout_ms: u64,
    /// Extra `virtiofsd` arguments, appended verbatim.
    #[serde(default)]
    pub virtiofsd_args: Vec<String>,
    /// Mount the share at startup when true; requires `server` and `export`.
    /// When false (the default), validate an existing mount.
    #[serde(default)]
    pub manage_mount: bool,
    #[serde(default)]
    pub server: Option<String>,
    #[serde(default)]
    pub export: Option<String>,
    #[serde(default)]
    pub mount_opts: Option<String>,
    /// mount(8) filesystem type. The source is still rendered as `server:export`.
    #[serde(default = "default_fs_type")]
    pub fs_type: String,
}

impl NfsVolumeConfig {
    /// Resolve the requested mount. Managed mounts require both server and export.
    pub fn mount_spec(&self) -> anyhow::Result<Option<nfs_driver::MountSpec>> {
        if !self.manage_mount {
            return Ok(None);
        }
        let (Some(server), Some(export)) = (&self.server, &self.export) else {
            bail!("[volume.nfs] manage_mount = true needs both server and export");
        };
        Ok(Some(nfs_driver::MountSpec {
            server: server.clone(),
            export: export.clone(),
            options: self.mount_opts.clone(),
            fs_type: self.fs_type.clone(),
        }))
    }
}

/// Optional overrides for the always-registered filesystem driver.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FilesystemVolumeConfig {
    #[serde(default)]
    pub image_dir: Option<PathBuf>,
    #[serde(default)]
    pub volume_dir: Option<PathBuf>,
    /// `qemu-img` executable for non-raw base images; defaults to PATH.
    #[serde(default = "default_qemu_img")]
    pub qemu_img: PathBuf,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NvrmConfig {
    pub binary: PathBuf,
    pub vgpuprofile: PathBuf,
    /// Backend socket timeout; defaults to `nvrm_driver::DEFAULT_SOCKET_TIMEOUT_MS`.
    #[serde(default = "default_nvrm_socket_timeout_ms")]
    pub socket_timeout_ms: u64,
    pub vram_budget_mib: Option<u64>,
    /// The host's share of the card in MiB that `vgpuprofile` subtracts before
    /// deriving vGPU types. Required once a vGPU type is configured or requested.
    pub vgpu_host_reserve_mib: Option<u64>,
    #[serde(default)]
    pub defaults: NvrmParams,
    #[serde(default)]
    pub profiles: HashMap<String, NvrmParams>,
}

/// Upstream vhost-device-input executable and startup timeout.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InputConfig {
    pub binary: PathBuf,
    /// Backend socket timeout; defaults to `input_driver::DEFAULT_SOCKET_TIMEOUT_MS`.
    #[serde(default = "default_input_socket_timeout_ms")]
    pub socket_timeout_ms: u64,
    /// The host input nodes vms may take, as a spec must name them; see
    /// `input_driver::InputDriverConfig::evdev`. Unset offers none.
    #[serde(default)]
    pub evdev: Vec<PathBuf>,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum ManagedDevice {
    NicSriov { pci_address: PciAddress },
    Passthrough { pci_address: PciAddress },
}

impl ManagedDevice {
    pub fn pci_address(&self) -> PciAddress {
        match self {
            ManagedDevice::NicSriov { pci_address } => *pci_address,
            ManagedDevice::Passthrough { pci_address } => *pci_address,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CrosvmGpuConfig {
    pub binary: PathBuf,
    pub socket_timeout_ms: u64,
    pub defaults: GpuParams,
    #[serde(default)]
    pub profiles: HashMap<String, serde_json::Value>,
}

impl AgentConfig {
    /// Resolve migration intervals; zero selects the default.
    pub fn migration_ceilings(&self) -> crate::provision::Ceilings {
        let default = crate::provision::Ceilings::default();
        crate::provision::Ceilings {
            migrate_out: match self.migrate_out_ceiling_secs {
                0 => default.migrate_out,
                secs => Duration::from_secs(secs),
            },
            receive: match self.receive_ceiling_secs {
                0 => default.receive,
                secs => Duration::from_secs(secs),
            },
        }
    }

    /// Parse config, resolve `[paths]` and TLS paths, and check network value
    /// syntax. Driver section validation and host checks occur separately; this
    /// method does not open configured resource paths.
    pub fn parse(path: &Path) -> anyhow::Result<Self> {
        let raw = read_to_string(path)
            .with_context(|| format!("reading config file {}", path.display()))?;
        let mut config: AgentConfig =
            from_str(&raw).with_context(|| format!("parsing config file {}", path.display()))?;

        let dir = path.parent().unwrap_or(Path::new("."));
        let base = std::path::absolute(dir)
            .with_context(|| format!("resolving config directory {}", dir.display()))?;
        config.paths.resolve_against(&base);
        for pem in [
            &mut config.controller_ca,
            &mut config.controller_cert,
            &mut config.controller_key,
        ] {
            if let Some(p) = pem
                && !p.is_absolute()
            {
                *p = base.join(&*p);
            }
        }

        // Validate network values before startup without opening host resources.
        config.nft_config().context("[network] guarded_ranges")?;
        config.bgp_config().context("[network.bgp]")?;
        config
            .parsed_bridge_addr()
            .context("[network] bridge_addr")?;

        Ok(config)
    }

    /// Parse configuration and validate the local admin socket group.
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let config = AgentConfig::parse(path)?;

        // Fail startup for an unknown group before the spawned socket task can
        // reduce the error to a log entry. Binding resolves the gid again.
        config.paths.socket_gid()?;

        Ok(config)
    }

    /// Parse guarded address ranges and resolve `nft`. Called during config
    /// parsing so malformed CIDRs fail before VM provisioning.
    pub fn nft_config(&self) -> anyhow::Result<linux_network_driver::nftables::NftConfig> {
        let guarded =
            common::net::Ipv4Ranges::parse(&self.guarded_ranges).context("guarded_ranges")?;
        Ok(linux_network_driver::nftables::NftConfig {
            binary: self
                .nft
                .clone()
                .unwrap_or_else(|| linux_network_driver::DEFAULT_NFT.to_string()),
            guarded,
        })
    }

    /// Resolve provider tools and put router state under `<run_dir>/routers`.
    /// The deployment is responsible for the lifetime of `run_dir`.
    pub fn provider_config(&self) -> Option<linux_network_driver::router::GatewayConfig> {
        let provider = self.network.as_ref()?.provider.as_ref()?;
        Some(linux_network_driver::router::GatewayConfig {
            physnets: provider.physnets.clone(),
            ip: provider
                .ip
                .clone()
                .unwrap_or_else(|| linux_network_driver::router::DEFAULT_IP.to_string()),
            arping: provider
                .arping
                .clone()
                .unwrap_or_else(|| linux_network_driver::router::DEFAULT_ARPING.to_string()),
            state_dir: self.paths.run_dir.join("routers"),
        })
    }

    /// Resolve FRR settings and carry the VXLAN EVPN flag. EVPN requires a BGP
    /// section; this check does not require a nonempty neighbor list.
    pub fn bgp_config(&self) -> anyhow::Result<Option<linux_network_driver::frr::BgpConfig>> {
        let Some(network) = &self.network else {
            return Ok(None);
        };
        let evpn = network.vxlan.as_ref().is_some_and(|v| v.evpn);
        let Some(bgp) = &network.bgp else {
            if evpn {
                bail!(
                    "[network.vxlan] evpn = true needs a [network.bgp] section: evpn is BGP \
                     carrying the overlay's mac addresses, and without a peer to carry \
                     them to, the overlay would flood into a multicast group it is no \
                     longer in"
                );
            }
            return Ok(None);
        };
        Ok(Some(linux_network_driver::frr::BgpConfig {
            asn: bgp.asn,
            router_id: bgp.router_id.clone(),
            neighbors: bgp
                .neighbors
                .iter()
                .map(|n| linux_network_driver::frr::Neighbor {
                    address: n.address.clone(),
                    remote_asn: n.remote_asn,
                })
                .collect(),
            vtysh: bgp.vtysh.clone().unwrap_or_else(|| PathBuf::from("vtysh")),
            vty_socket: bgp.vty_socket.clone(),
            fragment: bgp
                .fragment
                .clone()
                .unwrap_or_else(|| self.paths.run_dir.join("meister-bgp.conf")),
            evpn,
        }))
    }

    /// Default bridge name, or an empty string without network configuration.
    pub fn default_bridge(&self) -> String {
        self.network
            .as_ref()
            .map(|n| n.default_bridge.clone())
            .unwrap_or_default()
    }

    /// Parse the optional bridge address; no network section yields `None`.
    pub fn parsed_bridge_addr(&self) -> anyhow::Result<Option<(IpAddr, u8)>> {
        match &self.network {
            Some(n) => n.parsed_bridge_addr(),
            None => Ok(None),
        }
    }

    /// Build optional controller TLS configuration. Certificate and key must be
    /// paired, and client identity requires a configured CA.
    pub fn session_tls(&self) -> anyhow::Result<Option<tonic::transport::ClientTlsConfig>> {
        let identity = match (&self.controller_cert, &self.controller_key) {
            (None, None) => None,
            (Some(cert), Some(key)) => Some((cert.as_path(), key.as_path())),
            _ => bail!("controller_cert and controller_key go together; set both or neither"),
        };
        let Some(ca) = &self.controller_ca else {
            if identity.is_some() {
                bail!(
                    "controller_cert was set without a controller_ca to verify the controller \
                     with; this node would present its key to whoever answered"
                );
            }
            return Ok(None);
        };
        Ok(Some(proto::client_tls(ca, identity)?))
    }

    /// Apply optional ceilings to measured capacity; preserve node conditions.
    pub fn capped(&self, measured: proto::NodeStatus) -> proto::NodeStatus {
        proto::NodeStatus {
            vcpus: self
                .capacity_vcpus
                .map_or(measured.vcpus, |c| measured.vcpus.min(c)),
            mem_mib: self
                .capacity_mem_mib
                .map_or(measured.mem_mib, |c| measured.mem_mib.min(c)),
            // Capacity ceilings do not clear measured node faults.
            conditions: measured.conditions,
        }
    }

    /// Configured controller endpoints; a nonempty replica list takes precedence.
    pub fn controller_endpoints(&self) -> Vec<String> {
        if !self.controller_addrs.is_empty() {
            return self.controller_addrs.clone();
        }
        self.controller_addr.iter().cloned().collect()
    }
}

impl PathsConfig {
    /// Resolve the configured Unix group, failing when its name is unknown.
    pub fn socket_gid(&self) -> anyhow::Result<Option<u32>> {
        let Some(name) = &self.socket_group else {
            return Ok(None);
        };
        let group = nix::unistd::Group::from_name(name)
            .with_context(|| format!("looking up the group {name:?}"))?
            .with_context(|| {
                format!("[paths] socket_group names the group {name:?}, which does not exist here")
            })?;
        Ok(Some(group.gid.as_raw()))
    }

    fn resolve_against(&mut self, base: &Path) {
        for p in [
            &mut self.db_path,
            &mut self.run_dir,
            &mut self.image_dir,
            &mut self.volume_dir,
            &mut self.cgroup_root,
        ] {
            if !p.is_absolute() {
                *p = base.join(&*p);
            }
        }
    }
}

#[cfg(test)]
mod tests {

    /// Validate inclusive migration port ranges and report malformed values.
    #[test]
    fn the_migration_port_range_is_read_at_startup_or_refused_there() {
        let cfg = |ports: Option<&str>| CloudHypervisorConfig {
            binary: "/usr/bin/cloud-hypervisor".into(),
            timeout_ms: 2000,
            migration_ports: ports.map(str::to_string),
            unplug_timeout_secs: default_unplug_timeout_secs(),
        };

        // An absent range disables receiving.
        assert_eq!(cfg(None).ports(), Ok(None));
        assert_eq!(cfg(Some("49000-49099")).ports(), Ok(Some((49000, 49099))));
        // A single port is a valid range.
        assert_eq!(cfg(Some("49000-49000")).ports(), Ok(Some((49000, 49000))));
        assert_eq!(
            cfg(Some(" 49000 - 49099 ")).ports(),
            Ok(Some((49000, 49099)))
        );

        for (written, expected) in [
            ("49000", "is not a range"),
            ("49000-", "is not a port"),
            ("abc-49099", "is not a port"),
            ("49000-70000", "is not a port"),
            ("0-49099", "starts at 0"),
            ("49099-49000", "ends before it starts"),
        ] {
            let why = cfg(Some(written)).ports().expect_err(written);
            assert!(why.contains(expected), "{written}: {why}");
        }
    }
    use super::*;

    /// `section`, for a section the test knows is there.
    fn one<T: serde::de::DeserializeOwned>(sections: &Sections, what: &str, key: &str) -> T {
        section(sections, what, key)
            .unwrap_or_else(|e| panic!("[{what}.{key}] parses: {e:#}"))
            .unwrap_or_else(|| panic!("[{what}.{key}] is a real section"))
    }

    /// Typed driver sections reject unknown keys and include the key in the error.
    #[test]
    fn a_typo_inside_a_section_is_still_refused_by_name() {
        let cfg = config_with(
            r#"[volume.nfs]
               share_root = "/srv/share"
               virtiofsd  = "/usr/bin/virtiofsd"
               socket_timeout_mss = 100"#,
        );
        let err = section::<NfsVolumeConfig>(&cfg.volume, "volume", "nfs").unwrap_err();
        let err = format!("{err:#}");
        assert!(err.contains("socket_timeout_mss"), "{err}");
        assert!(err.contains("[volume.nfs]"), "the section is named: {err}");
    }

    /// Without a socket group, access remains owner-only.
    #[test]
    fn no_socket_group_is_no_group() {
        let cfg = config_with("");
        assert!(cfg.paths.socket_group.is_none());
        assert_eq!(cfg.paths.socket_gid().unwrap(), None);
    }

    /// Unknown socket groups fail with the requested name in the error.
    #[test]
    fn an_unknown_socket_group_is_an_error_that_names_it() {
        let mut cfg = config_with("");
        cfg.paths.socket_group = Some("meister-no-such-group".to_string());
        let err = format!("{:#}", cfg.paths.socket_gid().unwrap_err());
        assert!(err.contains("meister-no-such-group"), "{err}");
        assert!(err.contains("socket_group"), "{err}");
    }

    /// Resolve an existing group using the test process's gid.
    #[test]
    fn a_known_socket_group_resolves_to_its_gid() {
        let gid = nix::unistd::getgid();
        let Some(group) = nix::unistd::Group::from_gid(gid).expect("reading the group database")
        else {
            // Skip name lookup when this environment has no group entry for its gid.
            eprintln!("gid {gid} has no name here; nothing to look up");
            return;
        };
        let mut cfg = config_with("");
        cfg.paths.socket_group = Some(group.name.clone());
        assert_eq!(cfg.paths.socket_gid().unwrap(), Some(gid.as_raw()));
    }

    /// Enough of a config to parse; the endpoint keys are what is under test.
    fn config_with(endpoints: &str) -> AgentConfig {
        from_str(&format!(
            r#"
            node_id = "n1"
            {endpoints}
            [paths]
            db_path = "/tmp/a.redb"
            run_dir = "/tmp/run"
            image_dir = "/tmp/img"
            volume_dir = "/tmp/vol"
            cgroup_root = "/sys/fs/cgroup/x"
            [hypervisor.cloud-hypervisor]
            binary = "/usr/bin/cloud-hypervisor"
            timeout_ms = 5000
            [network]
            default_bridge = "br0"
            "#
        ))
        .expect("config parses")
    }

    /// Map provider-network names to local host interfaces.
    #[test]
    fn a_node_names_its_provider_networks_and_the_interface_for_each() {
        let cfg: AgentConfig = from_str(
            r#"
            node_id = "n1"
            [paths]
            db_path = "/tmp/a.redb"
            run_dir = "/run/ms"
            image_dir = "/tmp/img"
            volume_dir = "/tmp/vol"
            cgroup_root = "/sys/fs/cgroup/x"
            [hypervisor.cloud-hypervisor]
            binary = "/usr/bin/cloud-hypervisor"
            timeout_ms = 5000
            [network]
            default_bridge = "br0"
            [network.provider]
            physnets = { ext = "eth1", dmz = "eth2" }
            "#,
        )
        .expect("the provider section parses");

        let gateway = cfg.provider_config().expect("this node holds a slot");
        assert_eq!(
            gateway.physnets.keys().collect::<Vec<_>>(),
            ["dmz", "ext"],
            "a BTreeMap, so the Hello does not depend on hash order"
        );
        assert_eq!(gateway.physnets["ext"], "eth1");
        assert_eq!(gateway.ip, "ip", "unset = PATH, the same default nft takes");
        // Router state uses the configured runtime directory.
        assert_eq!(gateway.state_dir, PathBuf::from("/run/ms/routers"));

        // An absent provider section advertises no gateway slot.
        assert!(config_with("").provider_config().is_none());
    }

    /// Migration and unplug settings retain their defaults; zero intervals use defaults.
    #[test]
    fn the_three_waits_are_keys_and_their_defaults_are_the_old_constants() {
        let none = config_with("");
        assert_eq!(none.migrate_out_ceiling_secs, 600);
        assert_eq!(none.receive_ceiling_secs, 600);
        let ceilings = none.migration_ceilings();
        assert_eq!(ceilings.migrate_out, Duration::from_secs(600));
        assert_eq!(ceilings.receive, Duration::from_secs(600));

        let ch: CloudHypervisorConfig = section(&none.hypervisor, "hypervisor", "cloud-hypervisor")
            .expect("the section reads")
            .expect("it is there");
        assert_eq!(ch.unplug_timeout_secs, 30);
        assert_eq!(
            ch.unplug_timeout(),
            cloud_hypervisor_driver::DEFAULT_UNPLUG_TIMEOUT,
            "the config's default IS the driver's, not a second copy of 30"
        );

        // Explicit settings override defaults.
        let set = config_with(
            r#"migrate_out_ceiling_secs = 1800
               receive_ceiling_secs = 1200"#,
        );
        assert_eq!(
            set.migration_ceilings().migrate_out,
            Duration::from_secs(1800)
        );
        assert_eq!(set.migration_ceilings().receive, Duration::from_secs(1200));

        // Zero migration intervals select the default.
        let zero = config_with(
            r#"migrate_out_ceiling_secs = 0
               receive_ceiling_secs = 0"#,
        );
        assert_eq!(
            zero.migration_ceilings().migrate_out,
            Duration::from_secs(600)
        );
        assert_eq!(zero.migration_ceilings().receive, Duration::from_secs(600));
    }

    #[test]
    fn a_single_controller_addr_is_still_a_valid_endpoint_list() {
        assert_eq!(
            config_with(r#"controller_addr = "http://a:1""#).controller_endpoints(),
            vec!["http://a:1".to_string()]
        );
        assert!(config_with("").controller_endpoints().is_empty());
    }

    /// Parse the shipped example, including unknown-key validation.
    #[test]
    fn the_example_config_parses() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../config/examples/agent.toml");
        let cfg = AgentConfig::load(&path).expect("config/examples/agent.toml parses");
        assert_eq!(cfg.node_id, "manacor");
        assert_eq!(
            cfg.controller_endpoints().len(),
            2,
            "the list wins over the single addr"
        );
    }

    /// Commented example settings must remain valid configuration keys.
    #[test]
    fn every_commented_key_in_the_example_is_a_real_key() {
        let raw = std::fs::read_to_string(
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../config/examples/agent.toml"),
        )
        .unwrap();
        // Example prose starts with `# `; disabled settings start with `#key`.
        // Uncomment only settings, then validate their keys.
        let uncommented: String = raw
            .lines()
            .map(|l| match l.strip_prefix('#') {
                Some(rest) if !rest.starts_with(' ') && !rest.is_empty() => rest,
                _ if l.starts_with('#') => "",
                _ => l,
            })
            .collect::<Vec<_>>()
            .join("\n");
        let cfg: AgentConfig = from_str(&uncommented)
            .expect("every commented key and section in the example is a real one");
        // Verify the enabled log format setting.
        assert_eq!(cfg.log_format, telemetry::LogFormat::Json);
        // Deserialize each driver section to exercise its `deny_unknown_fields`.
        let gpu: CrosvmGpuConfig = one(&cfg.device, "device", "crosvm-gpu");
        assert!(gpu.profiles.contains_key("venus"));
        let _: NvrmConfig = one(&cfg.device, "device", "nvrm");
        let input: InputConfig = one(&cfg.device, "device", "input");
        assert_eq!(input.socket_timeout_ms, 5000);
        let _: FilesystemVolumeConfig = one(&cfg.volume, "volume", "filesystem");
        let lvm: LvmThinVolumeConfig = one(&cfg.volume, "volume", "lvm-thin");
        assert_eq!(lvm.vg, "meister");
        let nfs: NfsVolumeConfig = one(&cfg.volume, "volume", "nfs");
        // The example enables mounting and must supply a complete mount source.
        assert!(nfs.mount_spec().unwrap().is_some());
        let managed: Vec<ManagedDevice> = one(&cfg.device, "device", "managed");
        assert_eq!(managed.len(), 1);

        // Validate enabled overlay and capacity settings.
        let network = cfg
            .network
            .as_ref()
            .expect("[network] is a real section in the example");
        let vxlan = network
            .vxlan
            .as_ref()
            .expect("[network.vxlan] is a real section");
        assert_eq!(vxlan.uplink, "eno1");
        assert_eq!(vxlan.mtu, linux_network_driver::DEFAULT_VXLAN_MTU);
        assert!(cfg.controller_ca.is_some() && cfg.controller_cert.is_some());
        assert!(
            cfg.session_tls().is_err(),
            "the example's pki/ paths do not exist here"
        );
        assert_eq!(cfg.capacity_vcpus, Some(32));
        assert_eq!(cfg.cgroup_cpuset.as_deref(), Some("0-15,32-47"));

        // Validate guard, EVPN and BGP settings, including top-level `guarded_ranges`.
        let guarded = cfg.nft_config().expect("the example's ranges parse");
        assert_eq!(
            guarded.guarded.ranges().len(),
            3,
            "a cidr, an address and a range"
        );
        assert!(guarded.guarded.contains("10.255.0.7".parse().unwrap()));
        assert!(guarded.binary.ends_with("nft"));

        assert!(
            network.vxlan.as_ref().unwrap().evpn.eq(&false),
            "off is M5's behaviour"
        );
        let bgp = cfg
            .bgp_config()
            .expect("the example's bgp section resolves")
            .expect("present");
        assert_eq!(bgp.asn, 65_001);
        assert_eq!(bgp.neighbors.len(), 1);
        assert_eq!(bgp.neighbors[0].remote_asn, 65_000);
        assert!(
            !bgp.evpn,
            "evpn is off in the example, so the fragment has no l2vpn family"
        );
        assert!(bgp.fragment.ends_with("meister-bgp.conf"));
    }

    /// EVPN configuration requires a BGP section.
    #[test]
    fn evpn_without_a_bgp_section_is_refused_at_start_up() {
        let orphan = config_with("").network.is_none_or(|n| n.vxlan.is_none());
        assert!(orphan, "the bare test config has no overlay at all");

        let cfg: AgentConfig = from_str(
            r#"
            node_id = "n1"
            [paths]
            db_path = "/tmp/a.redb"
            run_dir = "/tmp/run"
            image_dir = "/tmp/img"
            volume_dir = "/tmp/vol"
            cgroup_root = "/sys/fs/cgroup/x"
            [hypervisor.cloud-hypervisor]
            binary = "/usr/bin/cloud-hypervisor"
            timeout_ms = 5000
            [network]
            default_bridge = "br0"
            [network.vxlan]
            uplink = "dummy0"
            evpn = true
            "#,
        )
        .expect("config parses");
        let err = cfg.bgp_config().unwrap_err().to_string();
        assert!(err.contains("[network.bgp]"), "{err}");
    }

    /// The development config does not require an explicit volume section.
    #[test]
    fn the_dev_config_in_the_repo_still_loads() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../config/agent.dev.toml");
        let cfg = AgentConfig::load(&path).expect("config/agent.dev.toml still loads");
        assert!(
            cfg.volume.is_empty(),
            "no [volume] section, and none needed"
        );
        let _: CrosvmGpuConfig = one(&cfg.device, "device", "crosvm-gpu");
    }

    /// Storage sections use the driver defaults when settings are omitted.
    #[test]
    fn the_storage_defaults_come_from_the_drivers() {
        let cfg = config_with(
            r#"[volume.lvm-thin]
               vg = "vg0"
               thin_pool = "thin"
               [volume.nfs]
               share_root = "/srv/share"
               virtiofsd = "/usr/bin/virtiofsd""#,
        );
        let lvm: LvmThinVolumeConfig = one(&cfg.volume, "volume", "lvm-thin");
        assert_eq!(
            lvm.max_data_percent,
            lvm_thin_driver::DEFAULT_MAX_DATA_PERCENT
        );
        assert_eq!(lvm.qemu_img, PathBuf::from("qemu-img"));
        assert_eq!(lvm.image_dir, None, "unnamed falls back to paths.image_dir");

        let nfs: NfsVolumeConfig = one(&cfg.volume, "volume", "nfs");
        assert_eq!(nfs.socket_timeout_ms, nfs_driver::DEFAULT_SOCKET_TIMEOUT_MS);
        assert_eq!(nfs.fs_type, "nfs");
        assert!(
            !nfs.manage_mount,
            "checking is the safe default, mounting is not"
        );
        assert!(nfs.mount_spec().unwrap().is_none());
    }

    /// Managed mounts require a complete source before the driver starts.
    #[test]
    fn managing_a_mount_without_a_source_is_refused() {
        let cfg = config_with(
            r#"[volume.nfs]
               share_root = "/srv/share"
               virtiofsd = "/usr/bin/virtiofsd"
               manage_mount = true"#,
        );
        let nfs: NfsVolumeConfig = one(&cfg.volume, "volume", "nfs");
        let err = nfs.mount_spec().unwrap_err().to_string();
        assert!(err.contains("server and export"), "{err}");
    }

    #[test]
    fn a_volume_section_overrides_only_the_directories_it_names() {
        let cfg = config_with(
            r#"[volume.filesystem]
               volume_dir = "/srv/thin""#,
        );
        let fs: FilesystemVolumeConfig = one(&cfg.volume, "volume", "filesystem");
        assert_eq!(fs.volume_dir, Some(PathBuf::from("/srv/thin")));
        assert_eq!(fs.image_dir, None, "unnamed falls back to paths.image_dir");
    }

    /// Without TLS credentials, controller sessions use plaintext.
    #[test]
    fn a_config_with_no_certificate_keys_dials_plain() {
        assert!(config_with("").session_tls().unwrap().is_none());
    }

    /// Refuse incomplete client identity or identity without a controller CA.
    #[test]
    fn half_a_session_credential_is_refused() {
        let only_cert = config_with(
            r#"controller_cert = "/tmp/n.crt"
               controller_key  = "/tmp/n.key""#,
        );
        let err = only_cert.session_tls().unwrap_err().to_string();
        assert!(err.contains("controller_ca"), "{err}");

        let half = config_with(r#"controller_cert = "/tmp/n.crt""#);
        let err = half.session_tls().unwrap_err().to_string();
        assert!(err.contains("go together"), "{err}");
    }

    /// Capacity ceilings can reduce measured capacity but cannot increase it.
    #[test]
    fn the_capacity_ceiling_only_ever_lowers_what_was_measured() {
        let measured = proto::NodeStatus {
            vcpus: 32,
            mem_mib: 64_000,
            conditions: Vec::new(),
        };
        assert_eq!(config_with("").capped(measured.clone()).vcpus, 32);

        let pinned = config_with(
            r#"capacity_vcpus   = 16
               capacity_mem_mib = 32000"#,
        );
        let capped = pinned.capped(measured.clone());
        assert_eq!((capped.vcpus, capped.mem_mib), (16, 32_000));

        let greedy = config_with(
            r#"capacity_vcpus   = 128
               capacity_mem_mib = 999999"#,
        );
        let capped = greedy.capped(measured);
        assert_eq!(
            (capped.vcpus, capped.mem_mib),
            (32, 64_000),
            "the machine wins"
        );
    }

    /// Malformed guarded CIDRs fail during config parsing.
    #[test]
    fn the_guarded_ranges_are_parsed_when_the_config_is_read() {
        let cfg = config_with(
            r#"guarded_ranges = ["10.255.0.0/16", "203.0.113.7", "198.51.100.16-198.51.100.17"]"#,
        );
        let nft = cfg.nft_config().expect("three shapes, all of them real");
        assert_eq!(nft.binary, linux_network_driver::DEFAULT_NFT);
        assert_eq!(nft.guarded.ranges().len(), 3);
        assert_eq!(nft.guarded.len(), 65_536 + 1 + 2);

        let typo = config_with(r#"guarded_ranges = ["10.255.0.0/16", "10.255.0"]"#);
        let err = typo.nft_config().unwrap_err().to_string();
        assert!(err.contains("guarded_ranges"), "{err}");
    }

    /// Omitted guarded ranges produce no address rules; MAC pinning is independent.
    #[test]
    fn a_config_with_no_guarded_ranges_guards_nothing() {
        let nft = config_with("").nft_config().unwrap();
        assert!(nft.guarded.is_empty());
        assert_eq!(nft.binary, "nft", "PATH, like lvs");

        let elsewhere = config_with(r#"nft = "/run/current-system/sw/bin/nft""#);
        assert_eq!(
            elsewhere.nft_config().unwrap().binary,
            "/run/current-system/sw/bin/nft"
        );
    }

    /// A nonempty controller replica list overrides the single-address fallback.
    #[test]
    fn the_replica_list_wins_over_the_single_address() {
        let cfg = config_with(
            r#"controller_addr = "http://old:1"
               controller_addrs = ["http://a:1", "http://b:1"]"#,
        );
        assert_eq!(
            cfg.controller_endpoints(),
            vec!["http://a:1".to_string(), "http://b:1".to_string()]
        );
    }
}
