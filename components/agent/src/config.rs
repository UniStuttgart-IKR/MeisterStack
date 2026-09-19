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
    /// How long this node watches a live migration it is SENDING before it
    /// stops watching. Default 600.
    ///
    /// Deliberately longer than the cluster's own transfer timeout (120 s by
    /// default), and that relation is the whole reason the number exists: the
    /// tier that ASKED for the migration is the one that decides it has
    /// failed, and an agent that gave up first would report a failure for a
    /// transfer still running. This is only the ceiling that keeps a wait from
    /// being unbounded.
    ///
    /// A key rather than a constant because what it has to be longer than is
    /// configuration one tier up: an estate that raised
    /// `migration_transfer_secs` for 32 GiB guests over a congested link has
    /// to raise this with it, and until now that was a recompile.
    #[serde(default = "default_migration_ceiling_secs")]
    pub migrate_out_ceiling_secs: u64,
    /// How long this node holds a VMM, a set of disks and a set of taps for a
    /// guest that has not turned up. Default 600.
    ///
    /// The same number as `migrate_out_ceiling_secs` and the same argument
    /// from the other end. It is only ever reached by the one failure nobody
    /// reports — a source that never dialled — because every transfer that
    /// STARTED ends with an event in the file, and the pass acts on that the
    /// moment it appears.
    ///
    /// Being wrong downwards is a guest that dies mid-move; being wrong
    /// upwards is a leak that lasts this long. A fleet that has measured its
    /// own transfers sets both keys together.
    #[serde(default = "default_migration_ceiling_secs")]
    pub receive_ceiling_secs: u64,
    /// OTLP collector for span export, e.g. "http://127.0.0.1:4317". Absent =
    /// the fmt subscriber and nothing else, which is how this has always run.
    #[serde(default)]
    pub otlp_endpoint: Option<String>,
    /// How a log line is written: `"human"` (the default) or `"json"`.
    ///
    /// File-only and deliberately: which format a node logs in is a property
    /// of the deployment that collects those logs, not of a run. `RUST_LOG`
    /// is the per-run knob and it is untouched by this.
    #[serde(default)]
    pub log_format: telemetry::LogFormat,
    /// Where to serve the Prometheus exposition, e.g. "127.0.0.1:9100".
    /// Absent = nothing listens, which is how every node has run so far.
    ///
    /// Its own listener and not the `http-api` one: that socket is the node's
    /// local admin API, this port is a scrape target, and a node that serves
    /// metrics should not have to serve mutations to do it. On a box that
    /// also runs a controller the two need different ports — which is the
    /// reason there is no single hard default for the whole stack.
    #[serde(default)]
    pub metrics_listen: Option<String>,
    /// The address other NODES should reach this one at, for a live
    /// migration stream.
    ///
    /// A new key rather than a reuse of anything above, because nothing above
    /// answers the question: `controller_addrs` is where this agent DIALS,
    /// `metrics_listen` is where a scraper comes from, and neither is "the
    /// address a peer on the cluster network can open a TCP connection to me
    /// on".
    ///
    /// Absent = derived, and the derivation is the honest one: the local
    /// address of the socket this agent used to reach the controller it
    /// chose. That is by construction an address that carries traffic on the
    /// cluster network, which is what a migration needs; it is wrong only on
    /// a node whose route to the controller and whose route to its peers go
    /// out of different interfaces, and such a node sets this key.
    #[serde(default)]
    pub advertise_addr: Option<String>,
    /// The physical machine this node is on, when somebody outside can see
    /// what the machine itself cannot.
    ///
    /// A nested node — an agent in a VM, which is what a lab is — cannot ask
    /// its host who it is. The platform's own DMI says `QEMU` and a serial
    /// that belongs to the guest, and that is the whole of what a guest may
    /// know. So this is written from outside, by whoever placed the VM.
    ///
    /// It exists for exactly one decision, and D-X1 is why: nested KVM state
    /// does not restore on a different physical host, measured twice on this
    /// lab's own hardware. Two nested nodes that both name the same host may
    /// migrate live between each other; two that cannot both name one are
    /// refused, because "we cannot tell" is not "it is fine" and the lab's
    /// answer to "we cannot tell" was two nights.
    ///
    /// Absent on bare metal, where it is not needed at all: an unnested node
    /// is never subject to that rule.
    #[serde(default)]
    pub physical_host: Option<String>,
    /// The system user the hypervisor and its vhost-user backends run as.
    ///
    /// Absent — the default, and the whole fleet today — means they run as the
    /// agent, exactly as they always have. Set, it is Stufe 3 of
    /// `design/privilege-separation.md`: the agent stays the privileged side
    /// and prepares what needs rights (taps, cgroups, device nodes, file
    /// ownership), and the processes that run guest code get descriptors
    /// instead. `nvrm`, `input` and `crosvm-gpu` change with the VMM and not
    /// after it, because vhost-user is not a boundary between them.
    ///
    /// The user has to exist before the agent starts; the deployment makes
    /// it, and it must NOT be in the agent's `socket_group`.
    ///
    /// no-root-Lane: Start-Check prueft CAP_SETUID/SETGID dafuer.
    #[serde(default)]
    pub vmm_user: Option<String>,

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
    /// `[hypervisor.*]` — at most one, keyed by driver name exactly as
    /// `[volume.*]` and `[device.*]` are. Optional in full: a node that names
    /// none runs no VMs, which is half of what a storage node is. Every
    /// config written so far names `cloud-hypervisor` and parses byte for
    /// byte the same — the section was an enum variant and is now a table
    /// key, and both spell `[hypervisor.cloud-hypervisor]`.
    #[serde(default)]
    pub hypervisor: Sections,
    /// `[network]` — this node makes taps and bridges. Absent means it does
    /// not, which is the other half: no VMs, so no NICs. Present is every
    /// config written so far.
    #[serde(default)]
    pub network: Option<NetworkConfig>,
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

/// 600 s — what `MIGRATE_OUT_CEILING` and `RECEIVE_CEILING` were as
/// constants. One function for both, because the two numbers are one
/// argument seen from the two ends of a transfer, and a fleet that changes
/// one without the other has an asymmetry nobody meant.
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
    /// Who else may talk to the agent's unix socket.
    ///
    /// Absent — every config written so far — is `run_dir` 0700 and the socket
    /// 0600, so the answer is "root and nobody else" and every `meister agent`
    /// command on the node needs sudo. Named, the socket becomes 0660 and the
    /// directory 0750, both owned by that group: its members get the node's
    /// local admin API without becoming root for it.
    ///
    /// The group is a *unix* group and not an authorization decision this
    /// stack makes. There is no authenticator on this socket — it is the
    /// node's own admin surface, reachable only by somebody already on the
    /// node — so the group IS the whole access rule, and it should be one
    /// somebody was deliberately put into.
    #[serde(default)]
    pub socket_group: Option<String>,
}

/// `[hypervisor.cloud-hypervisor]`. Was an enum variant; the two keys under
/// it are unchanged, and `deny_unknown_fields` still catches a typo INSIDE
/// the section while `drivers::register` catches one in the section NAME —
/// and, unlike the enum, can say which hypervisors this agent actually has.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CloudHypervisorConfig {
    pub binary: PathBuf,
    pub timeout_ms: u64,
    /// `migration_ports = "49000-49099"` — the range a receiving VMM may
    /// listen on, inclusive at both ends.
    ///
    /// A RANGE and not one port, because a node can be receiving more than
    /// one guest at a time and each stream is its own listener; a range and
    /// not "any free port", because the ports have to be open between the
    /// nodes and an operator has to be able to write that firewall rule down.
    ///
    /// Absent = this node does not receive live migrations. It can still SEND
    /// one, which is not asymmetry for its own sake: sending needs no port of
    /// one's own, and a node being emptied is exactly the node whose operator
    /// may not have got round to this key.
    #[serde(default)]
    pub migration_ports: Option<String>,
    /// How long a hot-unplug may take before this driver stops believing in
    /// it. Default 30.
    ///
    /// A key rather than a constant because it is a number about GUESTS and
    /// not about this stack: virtio unplug is cooperative, and how long a
    /// kernel takes to let go of a device is a property of the images a fleet
    /// runs. The deadline is not the guest's response time — it is the point
    /// at which "the guest is thinking about it" becomes "the guest is never
    /// going to do it", and being wrong in the fast direction is what D3 was:
    /// the control plane reported a volume free while the VMM still held the
    /// fd, and the next VM to use it died on cloud-hypervisor's write lock.
    ///
    /// So a fleet whose guests need forty seconds turns this up rather than
    /// living with a detach that reports a failure over a device that did in
    /// fact go. Zero is read as the default, the same way `ports()` reads a
    /// zero: a zero in a config file is almost always a key somebody meant to
    /// fill in.
    #[serde(default = "default_unplug_timeout_secs")]
    pub unplug_timeout_secs: u64,
}

/// The driver's own default, read from the driver rather than written out a
/// second time: two literals for one number is how an option table and the
/// code it describes start disagreeing.
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

    /// The migration port range as two numbers, or a sentence saying what is
    /// wrong with what was written.
    ///
    /// Parsed at start-up rather than at the first migration, and that is the
    /// whole reason it is a function: a typo here would otherwise be found by
    /// an operator who is draining a node at the moment they can least afford
    /// to read a parse error. `None` = the key was not set, which is a node
    /// that does not receive migrations and not a mistake.
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
    /// `[network.provider]` — this node gives one or more interfaces away to
    /// provider networks, and is therefore a candidate for a tenant router.
    /// Absent, which is every config before 6k, means it is not: the node
    /// still runs VMs and still carries overlays, it just holds no gateway
    /// slot and claims no `network/gateway:*`.
    #[serde(default)]
    pub provider: Option<ProviderNetworkConfig>,
    /// Take down overlay links no record on this node names, once, at
    /// start-up.
    ///
    /// On by default, and the default answers a leak that was measured: the
    /// chaos run left VNI 10003 and 10004 standing on three nodes for good.
    /// The reference count that removes an overlay hangs on records, and a VM
    /// whose record went while its agent was not running takes its wire's
    /// last counter with it — after which nobody counts again.
    ///
    /// It runs ONCE, before the first reconcile, and only when the whole
    /// record table could be read. That is what makes it something other than
    /// the timer this driver's own doc argues against: at that moment no VM
    /// is being provisioned here, so "is another VM for this tenant arriving
    /// in the next second?" has an answer.
    ///
    /// Off is for a node whose overlay links somebody else administers. Then
    /// they leak, and that is the operator's trade to make.
    #[serde(default = "default_sweep_orphans")]
    pub sweep_orphans: bool,
}

fn default_sweep_orphans() -> bool {
    true
}

/// `[network.provider]`. Config-keyed exactly as `[network.vxlan]` is: the
/// section is what turns the capability on.
///
/// What it turns on is Festlegung 2 — the gateway is a capability out of the
/// config, not an agent of its own and not a compile feature. A node that
/// names a physnet builds the provider bridge for it at start-up, claims
/// `network/gateway:<physnet>` in its Hello, and may be given routers; a node
/// that names none is no candidate for any.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderNetworkConfig {
    /// The interfaces this node gives away, by the name of the provider
    /// network each of them reaches: `physnets = { ext = "eth1" }`.
    ///
    /// A map and not a list, because the NAME is the thing the tier above
    /// schedules on — two nodes saying `ext` mean the same network, and which
    /// interface each of them uses to reach it is nobody else's business.
    /// Sorted, because it is a `BTreeMap`: the Hello a node sends must not
    /// depend on hash order.
    ///
    /// The interface must carry NO address. See `ensure_physnet`: an address
    /// there is somebody still using the interface, and a router placed on it
    /// would answer for a network the host is also on.
    pub physnets: BTreeMap<String, String>,
    /// Where `ip` is. Unset = PATH, the same default `nft` takes.
    ///
    /// `iproute2` and not netlink for the namespace half, for the reason this
    /// stack shells out to `nft`, `vtysh` and `nvme`: `ip netns` pins a
    /// namespace under `/var/run/netns`, which is what makes
    /// `ip netns exec meister-rt-<id> ip a` work for an operator standing at
    /// the node. A netlink implementation would build the same namespace and
    /// leave nobody a way to look into it.
    #[serde(default)]
    pub ip: Option<String>,
    /// Where `arping` is. Unset = PATH, as `ip` above.
    ///
    /// One use: the gratuitous ARP a router sends the moment it becomes the
    /// active one. A node without it keeps every other property of a failover
    /// and pays the neighbour's ARP cache — measured at 5,2 s in the lab.
    #[serde(default)]
    pub arping: Option<String>,
}

/// `[network.bgp]`. Config-keyed like every other capability in this file:
/// the section is what turns it on.
///
/// What it turns on is a renderer and a `vtysh` call — FRR does the protocol,
/// out of nixpkgs, exactly as virtiofsd does the filesystem on the storage
/// side. A section here without a running FRR is a hard start-up error, for
/// the same reason a `[volume.lvm-thin]` without its pool is: the node would
/// claim to announce its addresses and announce nothing.
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

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BgpNeighborConfig {
    pub address: String,
    pub remote_asn: u32,
}

/// `[network.vxlan]`. Config-keyed exactly as `[volume.*]` and `[device.*]`
/// are: the section is what turns the capability on.
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
pub type Sections = HashMap<String, toml::Value>;

/// One section of `[volume]`/`[device]`, as the type its driver wants, or
/// `None` when this node did not configure it.
///
/// `what` and `key` are only there to name the section in the error: the
/// section is parsed out of a `toml::Value` rather than straight out of the
/// file, so serde's "unknown field" still comes through but its line number
/// does not.
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

/// `[volume.nvmeof]`. The attacher alone: this node can connect to a target
/// and can provision nothing. Nothing to configure but where `nvme` is —
/// where the target IS comes from the pool, per volume, because one node
/// attaches namespaces from several.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NvmeofVolumeConfig {
    /// Where `nvme` is. Unset = PATH.
    #[serde(default)]
    pub bin_dir: Option<PathBuf>,
}

/// `[volume.nvmeof-import]`. The provider half: namespaces that already
/// exist, handed out one per volume.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NvmeofImportVolumeConfig {
    /// Where the assignment lives: one claim file per namespace that is
    /// spoken for. Falls back to a directory beside the agent's own database,
    /// because it is state of exactly that kind — small, this node's, and
    /// worthless to anybody else.
    #[serde(default)]
    pub state_dir: Option<PathBuf>,
    /// Where `nvme` is. Unset = PATH.
    #[serde(default)]
    pub bin_dir: Option<PathBuf>,
}

/// `[volume.nfs]`. `share_root` is the mounted share everything lives under;
/// whether the driver is the one mounting it is `manage_mount`.
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
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FilesystemVolumeConfig {
    #[serde(default)]
    pub image_dir: Option<PathBuf>,
    #[serde(default)]
    pub volume_dir: Option<PathBuf>,
    /// Where `qemu-img` is, for the one case that needs it: a base image that
    /// is not raw. Unset = PATH, which is right on a NixOS node — the same
    /// default `[volume.lvm-thin]` takes for the same tool.
    #[serde(default = "default_qemu_img")]
    pub qemu_img: PathBuf,
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

/// Upstream vhost-device-input executable and startup timeout.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InputConfig {
    pub binary: PathBuf,
    /// The driver's own number, not the config's: see input_driver::DEFAULT_SOCKET_TIMEOUT_MS.
    #[serde(default = "default_input_socket_timeout_ms")]
    pub socket_timeout_ms: u64,
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
    /// The two migration ceilings this node was configured with, zero read as
    /// the default in both — a zero in a config file is almost always a key
    /// somebody meant to fill in, and a ceiling of zero would end every
    /// transfer before it began.
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

        // Resolved here and not where the socket is bound, because that
        // happens in a spawned task whose error only reaches the log: a group
        // that does not exist has to stop the agent, and this is the last
        // place that still can. The gid itself is looked up again at bind
        // time; what this call buys is the failure.
        config.paths.socket_gid()?;

        Ok(config)
    }

    /// The tap guard's configuration: where `nft` is, and which addresses no
    /// tap may source from.
    ///
    /// The ranges are parsed HERE and not at the first VM boot, for the same
    /// reason the lvm-thin driver looks for its pool at start-up: a typo in a
    /// cidr is a config error, and finding it out when somebody's VM will not
    /// come up helps nobody.
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

    /// `[network.provider]`, resolved against this node's paths — or nothing,
    /// which is a node that gave no interface away and holds no gateway slot.
    ///
    /// The records go under `run_dir`, and that is a decision rather than a
    /// convenience: a router is a network namespace, a namespace dies with the
    /// machine, and a record of it that survived a reboot would be a record of
    /// something that is gone. The two are lost together, which is what makes
    /// the start-up sweep able to tell a half-built router from a live one.
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

    /// `[network.bgp]`, resolved against this node's paths — or nothing,
    /// which is a node that announces no routes.
    ///
    /// `evpn` comes from the VXLAN section and lands here, because that is
    /// where it is carried out: the overlay decides whether its MACs travel
    /// over BGP, and this section is only the session they travel on. A node
    /// that asks for evpn without a BGP peer to send it to is refused here
    /// rather than at the first tenant VM.
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

    /// The bridge a NIC lands on when its spec names none.
    ///
    /// Empty on a node with no `[network]` section — a node that makes no
    /// taps, and whose VMs (if it runs any at all) therefore have no NICs to
    /// give a bridge to. The one caller that would notice, `into_spec`, reads
    /// it per NIC, and a NIC on such a node is refused one layer down by
    /// `Drivers::networking` in words rather than landing on `""`.
    pub fn default_bridge(&self) -> String {
        self.network
            .as_ref()
            .map(|n| n.default_bridge.clone())
            .unwrap_or_default()
    }

    /// `[network].bridge_addr`, parsed — or nothing, which is both "no
    /// address configured" and "no `[network]` section at all".
    pub fn parsed_bridge_addr(&self) -> anyhow::Result<Option<(IpAddr, u8)>> {
        match &self.network {
            Some(n) => n.parsed_bridge_addr(),
            None => Ok(None),
        }
    }

    /// The credential for the controller session, if this node has one.
    ///
    /// `None` is the plain dial and the default. A certificate without a CA
    /// is refused rather than quietly ignored: it would authenticate this
    /// node to whoever answered on that address, which is the one mistake in
    /// this file worth failing at start-up over.
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
            // Untouched: a ceiling is about capacity, and no number in a
            // config makes a fault on this machine go away.
            conditions: measured.conditions,
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
    /// `socket_group` as a gid, or `None` when the key is absent.
    ///
    /// A name no group answers to is an error rather than a fall back to the
    /// private mode: the key exists to open the socket, and quietly not
    /// opening it would be found out by somebody who cannot use the CLI and
    /// has no reason to suspect the config. Resolved at start-up for the same
    /// reason a cidr is parsed there.
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

    /// A range an operator has to be able to open in a firewall, and a
    /// refusal that says what is wrong with what they wrote.
    #[test]
    fn the_migration_port_range_is_read_at_startup_or_refused_there() {
        let cfg = |ports: Option<&str>| CloudHypervisorConfig {
            binary: "/usr/bin/cloud-hypervisor".into(),
            timeout_ms: 2000,
            migration_ports: ports.map(str::to_string),
            unplug_timeout_secs: default_unplug_timeout_secs(),
        };

        // Not set is a node that does not receive live migrations, which is
        // an answer and not a mistake.
        assert_eq!(cfg(None).ports(), Ok(None));
        assert_eq!(cfg(Some("49000-49099")).ports(), Ok(Some((49000, 49099))));
        // One port is a range of one, which is a real thing to want.
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

    /// The default and every config written before this key existed: root
    /// talks to the socket, and nobody else.
    #[test]
    fn no_socket_group_is_no_group() {
        let cfg = config_with("");
        assert!(cfg.paths.socket_group.is_none());
        assert_eq!(cfg.paths.socket_gid().unwrap(), None);
    }

    /// A name nothing answers to is refused WITH the name. The alternative is
    /// a node whose socket is quietly still 0600 while its operator believes
    /// they opened it, and the person who finds that out is somebody whose
    /// CLI says "permission denied" for no visible reason.
    #[test]
    fn an_unknown_socket_group_is_an_error_that_names_it() {
        let mut cfg = config_with("");
        cfg.paths.socket_group = Some("meister-no-such-group".to_string());
        let err = format!("{:#}", cfg.paths.socket_gid().unwrap_err());
        assert!(err.contains("meister-no-such-group"), "{err}");
        assert!(err.contains("socket_group"), "{err}");
    }

    /// A group that does exist resolves to its gid. The one group every test
    /// process is certain to be in is its own.
    #[test]
    fn a_known_socket_group_resolves_to_its_gid() {
        let gid = nix::unistd::getgid();
        let Some(group) = nix::unistd::Group::from_gid(gid).expect("reading the group database")
        else {
            // A build environment whose own gid has no /etc/group entry can
            // say nothing about name lookup. Say so rather than pass quietly.
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

    /// The gateway slot, in the form a node writes it down: the NAME of the
    /// provider network on the left and this node's interface for it on the
    /// right. Two nodes reaching one wire by different NICs is the ordinary
    /// case and the whole reason it is a map.
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
        // The records go under run_dir and nowhere else: a namespace dies with
        // the machine, and a record of it that outlived a reboot would be a
        // record of something that is gone.
        assert_eq!(gateway.state_dir, PathBuf::from("/run/ms/routers"));

        // And the ordinary node, which is every node before 6k: no section,
        // no slot, no claim.
        assert!(config_with("").provider_config().is_none());
    }

    /// The three numbers that were constants have keys, and the keys default
    /// to exactly what the constants were.
    ///
    /// That last half is the point of the test. A config key whose default
    /// differs from the constant it replaced is a silent change of behaviour
    /// on every fleet that never sets it, and the two migration ceilings are
    /// the pair where that would be worst: both have to stay longer than the
    /// cluster's own `migration_transfer_secs`, or a node starts calling a
    /// transfer failed that the tier above still believes in.
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

        // Set, they are what was written.
        let set = config_with(
            r#"migrate_out_ceiling_secs = 1800
               receive_ceiling_secs = 1200"#,
        );
        assert_eq!(
            set.migration_ceilings().migrate_out,
            Duration::from_secs(1800)
        );
        assert_eq!(set.migration_ceilings().receive, Duration::from_secs(1200));

        // And zero is the default rather than "give up at once", the same
        // rule `ports()` applies to a zero: a zero in a config file is almost
        // always a key somebody meant to fill in, and a ceiling of zero would
        // end every transfer before it started.
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
        // The envelope key. It is the one line in the example a fleet really
        // does uncomment, so a rename here has to fail in this test rather
        // than on twelve nodes at start-up.
        assert_eq!(cfg.log_format, telemetry::LogFormat::Json);
        // Every section is deserialized into its typed struct HERE, and that
        // is the whole point of this block rather than a `contains_key`:
        // `[volume]` and `[device]` are raw TOML in the config now, so
        // `deny_unknown_fields` inside a section only fires when somebody
        // parses the section — which on a node is `Drivers::from_config`,
        // and in this test is these six lines.
        let gpu: CrosvmGpuConfig = one(&cfg.device, "device", "crosvm-gpu");
        assert!(gpu.profiles.contains_key("venus"));
        let _: NvrmConfig = one(&cfg.device, "device", "nvrm");
        let input: InputConfig = one(&cfg.device, "device", "input");
        assert_eq!(input.socket_timeout_ms, 5000);
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

    /// Two keys that only mean something together: evpn is BGP carrying the
    /// overlay's MAC addresses, so a node asking for it without a peer to
    /// carry them to would flood into a multicast group it is no longer in —
    /// silently, which is the worst way for an overlay to be broken.
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
