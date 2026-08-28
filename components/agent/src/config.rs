// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

use anyhow::{Context, bail};
use crosvm_gpu_driver::GpuParams;
use macros::generated;
use nvrm_driver::NvrmParams;
use serde::Deserialize;
use std::collections::HashMap;
use std::fs::read_to_string;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use toml::from_str;

fn default_nvrm_socket_timeout_ms() -> u64 {
    nvrm_driver::DEFAULT_SOCKET_TIMEOUT_MS
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
    /// One controller. Kept for the single-controller lab and for the config
    /// the OpenNebula context still writes; `controller_addrs` supersedes it.
    pub controller_addr: Option<String>,
    /// The controller replicas to choose between (HA, leaderless). Order here
    /// is irrelevant — each agent derives its own preference order over the
    /// list by rendezvous hashing (see `hrw`).
    #[serde(default)]
    pub controller_addrs: Vec<String>,
    #[serde(default = "default_stop_grace_secs")]
    pub stop_grace_secs: u64,
    /// OTLP collector for span export, e.g. "http://127.0.0.1:4317". Absent =
    /// the fmt subscriber and nothing else, which is how this has always run.
    #[serde(default)]
    pub otlp_endpoint: Option<String>,

    // --- the session credential. PEM paths, never PEM. -----------------------
    //
    // All three unset — the default — is the plain gRPC session this agent has
    // opened since M1, and the lab still runs that way. Relative paths resolve
    // against THIS file, so a config and its pki/ directory travel as one unit,
    // exactly as [paths] does and exactly as the controllers' configs do.
    /// The CA the controller's serving certificate must chain to. Set on its
    /// own it is one-way TLS: encrypted, and the controller learns nothing
    /// about who this is.
    #[serde(default)]
    pub controller_ca: Option<PathBuf>,
    /// This node's own identity, `CN=system:node:<node_id>`. The controller
    /// matches that name against the node_id in the Hello, so one node's key
    /// cannot report as another node — which is the whole reason for putting
    /// a certificate on a session that is already encrypted.
    #[serde(default)]
    pub controller_cert: Option<PathBuf>,
    #[serde(default)]
    pub controller_key: Option<PathBuf>,

    // --- what this node says it has, when the truth needs a ceiling ---------
    //
    // Two agents pinned to two NUMA nodes of one host are two nodes to the
    // controller and one machine to the kernel: each of them reads the WHOLE
    // host's CPUs and memory out of /proc, and the cluster would then schedule
    // against twice the hardware that exists. These are the ceiling. Unset =
    // report what was measured, which is what every config written so far says.
    #[serde(default)]
    pub capacity_vcpus: Option<u32>,
    #[serde(default)]
    pub capacity_mem_mib: Option<u64>,
    /// `cpuset.cpus` for the slice every VM of this agent lands under, e.g.
    /// "0-15,32-47". The other half of the same recipe: the ceiling is what
    /// this agent CLAIMS, and this is what its VMs actually get.
    #[serde(default)]
    pub cgroup_cpuset: Option<String>,

    // --- the addresses no tap may source from --------------------------------
    //
    // The union of every floating pool's ranges, in the same spelling the cloud
    // writes them: a cidr, a single address, or `a-b`. The driver turns them
    // into one nftables set and drops any frame or ARP claiming a source
    // address inside it — on EVERY tap, with an exception only for the
    // addresses the tap's own VM holds a reservation for.
    //
    // Empty, which is every config written before M5.1, means the guard has
    // nothing to guard: taps still get their mac pinned (that needs no
    // configuration and never did) and no address rule is written at all.
    //
    // Deliberate duplication of what the cloud holds in FloatingPool objects,
    // documented as such in the example. TOP-LEVEL and not under `[network]`
    // on purpose: the lab's context rendering prepends top-level keys in front
    // of the config template, and a prepended `[network]` table would be a
    // duplicate of the template's own.
    //
    // REFACTOR, not built here: push the pools down the session the way the
    // vni is pushed down, and this becomes a fallback. See the field doc on
    // `nftables::NftConfig::guarded`.
    #[serde(default)]
    pub guarded_ranges: Vec<String>,
    /// Where `nft` is. Unset = PATH, which is right on a NixOS node — the same
    /// default the lvm-thin driver takes for `lvs`.
    #[serde(default)]
    pub nft: Option<String>,

    pub paths: PathsConfig,
    pub hypervisor: HypervisorConfig,
    pub network: NetworkConfig,
    /// `[device.*]` — one section per device backend. Optional: a GPU-less
    /// agent (lab VM) has no device section at all.
    #[serde(default)]
    pub device: Sections,
    /// `[volume.*]` — storage backends, keyed by driver name exactly as
    /// `[device.*]` is. Optional in full: a node that names none still gets
    /// `filesystem` from `[paths]`, which is what every config written so
    /// far says.
    #[serde(default)]
    pub volume: Sections,
}

fn default_stop_grace_secs() -> u64 {
    30
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PathsConfig {
    pub db_path: PathBuf,
    pub run_dir: PathBuf,
    pub image_dir: PathBuf,
    pub volume_dir: PathBuf,
    pub cgroup_root: PathBuf,
}

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum HypervisorConfig {
    #[serde(rename_all = "snake_case")]
    CloudHypervisor { binary: PathBuf, timeout_ms: u64 },
}

#[generated(model = ClaudeFable, version = "5")]
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkConfig {
    pub default_bridge: String,
    #[serde(default)]
    pub bridge_addr: Option<String>,
    /// `[network.vxlan]` — this node can carry tenant overlays. Absent, which
    /// is every config written before M5, means it cannot: a VM whose spec
    /// names a `vxlan_id` is refused here rather than quietly put on the
    /// default bridge, and the scheduler keeps such VMs away in the first
    /// place because the node claims no `network/vxlan` entry.
    #[serde(default)]
    pub vxlan: Option<VxlanNetworkConfig>,
    /// `[network.bgp]` — this node speaks BGP to somebody, and announces the
    /// floating addresses of the VMs running on it. Absent, which is every
    /// config written before M5.1, means it does not: the addresses are still
    /// reserved, still enforced at the tap, and reachable by whatever static
    /// route or appliance the environment provides.
    #[serde(default)]
    pub bgp: Option<BgpNetworkConfig>,
}

/// `[network.bgp]`. Config-keyed like every other capability in this file:
/// the section is what turns it on.
///
/// What it turns on is a renderer and a `vtysh` call — FRR does the protocol,
/// out of nixpkgs, exactly as virtiofsd does the filesystem on the storage
/// side. A section here without a running FRR is a hard start-up error, for
/// the same reason a `[volume.lvm-thin]` without its pool is: the node would
/// claim to announce its addresses and announce nothing.
#[generated(model = ClaudeOpus, version = "5")]
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BgpNetworkConfig {
    /// This node's autonomous system number. A private ASN (64512-65534, or
    /// the 32-bit block) unless somebody has given the lab a real one.
    pub asn: u32,
    /// The BGP identifier, dotted. Set explicitly: FRR would otherwise take
    /// the highest address on the box, which on a node full of bridges and
    /// taps is whatever the last VM created.
    pub router_id: String,
    /// The peers. Address plus their ASN — the rack switch, or a route
    /// reflector, or in the lab an FRR in a namespace.
    ///
    /// Unnumbered eBGP (`neighbor <interface> interface remote-as external`,
    /// which needs no addresses at all and is what a modern fabric uses) is
    /// the obvious next shape and is NOT built: it needs IPv6 link-local
    /// next-hops to carry IPv4 routes (RFC 5549), which is a second code path
    /// through everything below and buys nothing in a lab whose switch has a
    /// management address anyway.
    #[serde(default)]
    pub neighbors: Vec<BgpNeighborConfig>,
    /// Where `vtysh` is. Unset = PATH.
    #[serde(default)]
    pub vtysh: Option<PathBuf>,
    /// FRR's vty socket directory, for an FRR that is not at the default
    /// `/var/run/frr` — a second agent on one host, or an FRR in a namespace.
    #[serde(default)]
    pub vty_socket: Option<PathBuf>,
    /// Where the rendered fragment is written before vtysh reads it. Unset =
    /// `<run_dir>/meister-bgp.conf`, kept flat in run_dir like everything
    /// else there.
    #[serde(default)]
    pub fragment: Option<PathBuf>,
}

#[generated(model = ClaudeOpus, version = "5")]
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BgpNeighborConfig {
    pub address: String,
    pub remote_asn: u32,
}

/// `[network.vxlan]`. Config-keyed exactly as `[volume.*]` and `[device.*]`
/// are: the section is what turns the capability on.
#[generated(model = ClaudeOpus, version = "5")]
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VxlanNetworkConfig {
    /// The interface encapsulated frames leave by.
    pub uplink: String,
    /// MTU for the tenant bridge, its VXLAN device and the taps on it. The
    /// driver's own number, not this file's: see
    /// linux_network_driver::DEFAULT_VXLAN_MTU.
    #[serde(default = "default_vxlan_mtu")]
    pub mtu: u32,
    /// Distribute the overlay's MACs over BGP instead of flooding for them.
    /// Needs `[network.bgp]`; see `linux_network_driver::VxlanConfig::evpn`
    /// for what it changes and why it is a CLUSTER-wide decision.
    #[serde(default)]
    pub evpn: bool,
}

fn default_vxlan_mtu() -> u32 {
    linux_network_driver::DEFAULT_VXLAN_MTU
}

#[generated(model = ClaudeFable, version = "5")]
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

/// The raw `[volume]` / `[device]` table: one entry per section, still in
/// TOML, deserialized by whichever driver owns the key. `[volume.lvm-thin]`
/// is the entry "lvm-thin", `[[device.managed]]` the entry "managed" with an
/// array under it — the file on disk is unchanged either way.
///
/// Raw rather than a struct with one `Option<…>` field per driver, because
/// that struct was the second place every new driver had to be edited, and
/// the easier of the two to forget: forgetting the if-let in `drivers.rs`
/// only cost you a driver, while forgetting the field cost you a config key
/// that parsed and then did nothing. The typed structs below are unchanged
/// and keep their `deny_unknown_fields`, so a typo INSIDE a section still
/// fails; a typo in a SECTION NAME is caught by `drivers::register`, which
/// unlike serde can say which drivers this agent actually has.
#[generated(model = ClaudeOpus, version = "5")]
pub type Sections = HashMap<String, toml::Value>;

/// One section of `[volume]`/`[device]`, as the type its driver wants, or
/// `None` when this node did not configure it.
///
/// `what` and `key` are only there to name the section in the error: the
/// section is parsed out of a `toml::Value` rather than straight out of the
/// file, so serde's "unknown field" still comes through but its line number
/// does not.
#[generated(model = ClaudeOpus, version = "5")]
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

/// `[volume.lvm-thin]`. The pool has to exist on this node — the driver
/// checks at start-up rather than at the first VM boot.
#[generated(model = ClaudeOpus, version = "5")]
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LvmThinVolumeConfig {
    pub vg: String,
    pub thin_pool: String,
    /// Refuse a create while the pool is fuller than this. The driver's own
    /// number, not the config's: see lvm_thin_driver::DEFAULT_MAX_DATA_PERCENT.
    #[serde(default = "default_max_data_percent")]
    pub max_data_percent: f64,
    /// Falls back to [paths].image_dir, where base images have always lived.
    #[serde(default)]
    pub image_dir: Option<PathBuf>,
    /// Where lvs/lvcreate/lvremove are. Unset = PATH.
    #[serde(default)]
    pub bin_dir: Option<PathBuf>,
    #[serde(default = "default_qemu_img")]
    pub qemu_img: PathBuf,
}

/// `[volume.nfs]`. `share_root` is the mounted share everything lives under;
/// whether the driver is the one mounting it is `manage_mount`.
#[generated(model = ClaudeOpus, version = "5")]
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NfsVolumeConfig {
    pub share_root: PathBuf,
    pub virtiofsd: PathBuf,
    /// Falls back to [paths].image_dir. Images are the node's; copying them
    /// onto the share to copy them back off it would be work for nothing.
    #[serde(default)]
    pub image_dir: Option<PathBuf>,
    /// The driver's own number: see nfs_driver::DEFAULT_SOCKET_TIMEOUT_MS.
    #[serde(default = "default_nfs_socket_timeout_ms")]
    pub socket_timeout_ms: u64,
    /// Extra virtiofsd flags, verbatim and last.
    #[serde(default)]
    pub virtiofsd_args: Vec<String>,
    /// false (the default): share_root is already mounted by fstab or a
    /// systemd unit and the driver only checks. true: the driver mounts it
    /// at start-up, and then it needs server and export.
    #[serde(default)]
    pub manage_mount: bool,
    #[serde(default)]
    pub server: Option<String>,
    #[serde(default)]
    pub export: Option<String>,
    #[serde(default)]
    pub mount_opts: Option<String>,
    /// mount(8)'s `-t`. Anything the host can mount can be a share.
    #[serde(default = "default_fs_type")]
    pub fs_type: String,
}

#[generated(model = ClaudeOpus, version = "5")]
impl NfsVolumeConfig {
    /// What to mount, or nothing to mount. `manage_mount = true` without a
    /// server and an export is a config that cannot be carried out, and the
    /// driver says so rather than starting half-configured.
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

/// `[volume.filesystem]`. Both directories fall back to `[paths]`, which is
/// where they have always been configured — the section exists so a second
/// backend has a place to be configured next to, not to move anything.
///
/// The default driver is registered with or without this section, because
/// `driver: None` in a spec has to keep meaning something on every node; see
/// `drivers::build_filesystem`.
#[generated(model = ClaudeOpus, version = "5")]
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FilesystemVolumeConfig {
    #[serde(default)]
    pub image_dir: Option<PathBuf>,
    #[serde(default)]
    pub volume_dir: Option<PathBuf>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NvrmConfig {
    pub binary: PathBuf,
    pub vgpuprofile: PathBuf,
    /// The driver's own number, not the config's: see nvrm_driver::DEFAULT_SOCKET_TIMEOUT_MS.
    #[serde(default = "default_nvrm_socket_timeout_ms")]
    pub socket_timeout_ms: u64,
    pub vram_budget_mib: Option<u64>,
    #[serde(default)]
    pub defaults: NvrmParams,
    #[serde(default)]
    pub profiles: HashMap<String, NvrmParams>,
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
    pub fn load(path: &Path) -> anyhow::Result<Self> {
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

        Ok(config)
    }

    /// The tap guard's configuration: where `nft` is, and which addresses no
    /// tap may source from.
    ///
    /// The ranges are parsed HERE and not at the first VM boot, for the same
    /// reason the lvm-thin driver looks for its pool at start-up: a typo in a
    /// cidr is a config error, and finding it out when somebody's VM will not
    /// come up helps nobody.
    #[generated(model = ClaudeOpus, version = "5")]
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

    /// `[network.bgp]`, resolved against this node's paths — or nothing,
    /// which is a node that announces no routes.
    ///
    /// `evpn` comes from the VXLAN section and lands here, because that is
    /// where it is carried out: the overlay decides whether its MACs travel
    /// over BGP, and this section is only the session they travel on. A node
    /// that asks for evpn without a BGP peer to send it to is refused here
    /// rather than at the first tenant VM.
    #[generated(model = ClaudeOpus, version = "5")]
    pub fn bgp_config(&self) -> anyhow::Result<Option<linux_network_driver::frr::BgpConfig>> {
        let evpn = self.network.vxlan.as_ref().is_some_and(|v| v.evpn);
        let Some(bgp) = &self.network.bgp else {
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

    /// The credential for the controller session, if this node has one.
    ///
    /// `None` is the plain dial and the default. A certificate without a CA
    /// is refused rather than quietly ignored: it would authenticate this
    /// node to whoever answered on that address, which is the one mistake in
    /// this file worth failing at start-up over.
    #[generated(model = ClaudeOpus, version = "5")]
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

    /// What this node reports as its capacity: what was measured, under the
    /// ceiling the config names.
    ///
    /// A ceiling rather than an override, and the difference matters on the
    /// day somebody copies a config onto a smaller machine: claiming 64 vCPUs
    /// on a 16-core box is a scheduler placing VMs that will never fit, and
    /// the config is the less trustworthy of the two numbers.
    pub fn capped(&self, measured: proto::NodeStatus) -> proto::NodeStatus {
        proto::NodeStatus {
            vcpus: self
                .capacity_vcpus
                .map_or(measured.vcpus, |c| measured.vcpus.min(c)),
            mem_mib: self
                .capacity_mem_mib
                .map_or(measured.mem_mib, |c| measured.mem_mib.min(c)),
        }
    }

    /// Every controller this agent may dial. The list wins when both are set:
    /// a single `controller_addr` left over from before HA is one replica, and
    /// a list that names replicas is the newer, more complete statement.
    pub fn controller_endpoints(&self) -> Vec<String> {
        if !self.controller_addrs.is_empty() {
            return self.controller_addrs.clone();
        }
        self.controller_addr.iter().cloned().collect()
    }
}

impl PathsConfig {
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
#[generated(model = ClaudeOpus, version = "5")]
mod tests {
    use super::*;

    /// `section`, for a section the test knows is there.
    fn one<T: serde::de::DeserializeOwned>(sections: &Sections, what: &str, key: &str) -> T {
        section(sections, what, key)
            .unwrap_or_else(|e| panic!("[{what}.{key}] parses: {e:#}"))
            .unwrap_or_else(|| panic!("[{what}.{key}] is a real section"))
    }

    /// A misspelled key INSIDE a section still fails, and still says which
    /// key it was. Moving `[volume]` to a raw table moved this check from
    /// the whole-file parse to the driver that owns the section, so it is
    /// worth an assertion of its own: the section keeps its
    /// `deny_unknown_fields`, and a silently ignored setting here would be a
    /// node running on a timeout its operator thought they had changed.
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

    #[test]
    fn a_single_controller_addr_is_still_a_valid_endpoint_list() {
        assert_eq!(
            config_with(r#"controller_addr = "http://a:1""#).controller_endpoints(),
            vec!["http://a:1".to_string()]
        );
        assert!(config_with("").controller_endpoints().is_empty());
    }

    /// The curated example, parsed as it is on disk. An example that does not
    /// parse is worse than no example: it is a file that looks like an answer.
    /// `deny_unknown_fields` means this also catches a key renamed in the code
    /// and left behind here.
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

    /// Every commented-out key in the example has to be a key that exists.
    /// Uncommenting a line in an example is the first thing anyone does with
    /// one, and a stale key there fails at the worst possible moment — on a
    /// node, at start-up, with `deny_unknown_fields` and no hint which line.
    #[test]
    fn every_commented_key_in_the_example_is_a_real_key() {
        let raw = std::fs::read_to_string(
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../config/examples/agent.toml"),
        )
        .unwrap();
        // The example's convention, and the reason it is worth having: prose
        // is `# text`, a commented-out setting is `#key = …` with no space.
        // So uncommenting the settings and leaving the prose alone is one
        // rule, and this is what enforces it in both directions — a stale key
        // fails here, and so does a prose line that forgot its space.
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
        // Every section is deserialized into its typed struct HERE, and that
        // is the whole point of this block rather than a `contains_key`:
        // `[volume]` and `[device]` are raw TOML in the config now, so
        // `deny_unknown_fields` inside a section only fires when somebody
        // parses the section — which on a node is `Drivers::from_config`,
        // and in this test is these six lines.
        let gpu: CrosvmGpuConfig = one(&cfg.device, "device", "crosvm-gpu");
        assert!(gpu.profiles.contains_key("venus"));
        let _: NvrmConfig = one(&cfg.device, "device", "nvrm");
        let _: FilesystemVolumeConfig = one(&cfg.volume, "volume", "filesystem");
        let lvm: LvmThinVolumeConfig = one(&cfg.volume, "volume", "lvm-thin");
        assert_eq!(lvm.vg, "meister");
        let nfs: NfsVolumeConfig = one(&cfg.volume, "volume", "nfs");
        // manage_mount = true in the example, so the mount it describes has
        // to be one the driver could actually carry out.
        assert!(nfs.mount_spec().unwrap().is_some());
        let managed: Vec<ManagedDevice> = one(&cfg.device, "device", "managed");
        assert_eq!(managed.len(), 1);

        // The M5 half of the example: the overlay section and the two-agents
        // recipe are commented-out KEYS, so uncommenting them has to give a
        // config that means what the prose above them says.
        let vxlan = cfg
            .network
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

        // The M5.1 half: the guard, the overlay's evpn switch and the bgp
        // session. Uncommenting them has to give a config that means what the
        // prose above them says — including that `guarded_ranges` is a
        // TOP-LEVEL key and not a `[network]` one, which is what keeps the
        // lab's context rendering from producing a duplicate table.
        let guarded = cfg.nft_config().expect("the example's ranges parse");
        assert_eq!(
            guarded.guarded.ranges().len(),
            3,
            "a cidr, an address and a range"
        );
        assert!(guarded.guarded.contains("10.255.0.7".parse().unwrap()));
        assert!(guarded.binary.ends_with("nft"));

        assert!(
            cfg.network.vxlan.as_ref().unwrap().evpn.eq(&false),
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

    /// Two keys that only mean something together: evpn is BGP carrying the
    /// overlay's MAC addresses, so a node asking for it without a peer to
    /// carry them to would flood into a multicast group it is no longer in —
    /// silently, which is the worst way for an overlay to be broken.
    #[test]
    fn evpn_without_a_bgp_section_is_refused_at_start_up() {
        let orphan = config_with("").network.vxlan.is_none();
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

    /// The repo's own dev config, parsed as it is on disk — a `[volume]`
    /// section it does not have must stay a section it does not need.
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

    /// And when there is one, it overrides only what it names — the rest
    /// stays where it has always been configured, in `[paths]`.
    /// The two knobs whose default lives in the driver rather than here, so
    /// that the number is next to the process it is about. A config that says
    /// nothing about them has to come out the same as one that repeats them.
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

    /// A node that says it will mount the share and does not say what has a
    /// config that cannot be carried out. Better to say so at start-up than
    /// to run with a storage backend rooted in an empty local directory.
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

    /// The default, and the whole compatibility claim of this milestone in
    /// one assertion: a config that says nothing about certificates dials
    /// plain, exactly as it has since M1.
    #[test]
    fn a_config_with_no_certificate_keys_dials_plain() {
        assert!(config_with("").session_tls().unwrap().is_none());
    }

    /// A certificate with no CA to check the SERVER against would present
    /// this node's key to whoever answered on that address. Half a config is
    /// refused rather than silently downgraded — the same rule the two
    /// controllers already apply to their own TLS keys.
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

    /// A ceiling, not an override. Two agents pinned to two NUMA nodes each
    /// read the whole host out of /proc, and the controller would otherwise
    /// schedule against twice the hardware that exists — but a config copied
    /// onto a smaller machine must not be able to claim more than is there.
    #[test]
    fn the_capacity_ceiling_only_ever_lowers_what_was_measured() {
        let measured = proto::NodeStatus {
            vcpus: 32,
            mem_mib: 64_000,
        };
        assert_eq!(config_with("").capped(measured).vcpus, 32);

        let pinned = config_with(
            r#"capacity_vcpus   = 16
               capacity_mem_mib = 32000"#,
        );
        let capped = pinned.capped(measured);
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

    /// The guard's config, parsed at start-up rather than at the first VM
    /// boot — the same fail-fast the lvm-thin driver applies to its pool, and
    /// for the same reason: a typo in a cidr is a config error, and finding it
    /// out when somebody's VM will not come up helps nobody.
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

    /// The compatibility invariant in one assertion: a config that says
    /// nothing about addresses guards nothing. Taps still get their mac
    /// pinned — that needs no configuration and never did — and no address
    /// rule is written at all.
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

    /// The lab's context still writes `controller_addr` into every agent
    /// config; a list that names the replicas is the newer and more complete
    /// statement, so it wins rather than being merged into an ambiguity.
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
