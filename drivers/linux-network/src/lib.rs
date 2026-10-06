// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Linux bridges, taps, VXLAN overlays and tenant gateways.
//! Each VNI uses a bridge and VXLAN device. Multicast discovery is the default;
//! EVPN mode delegates peer learning to FRR. Configure the same mode across peers.
//! The driver sets UDP port 4789 and the configured overlay MTU; hardware offload
//! and underlay reachability remain host properties. See docs/NETWORKING.md.

pub mod frr;
pub mod nftables;
/// 6k Mini-Neutron: the gateway slot. See the module.
pub mod router;

use futures::TryStreamExt;
use std::net::Ipv4Addr;
use std::path::Path;

use agent_api::networking::{
    self, BridgeDriver, NetworkError, Nic, NicDriver, NicId, NicSpec, RouterId, RouterSpec,
    RouterState,
};
use rtnetlink::packet_route::link::LinkAttribute;
use rtnetlink::{LinkBridge, LinkUnspec, LinkVxlan};
use tracing::{debug, info, instrument, warn};

/// A port other than this overlay's own tunnel is still a bridge consumer.
fn is_overlay_consumer(attributes: &[LinkAttribute], bridge: u32, tunnel: &str) -> bool {
    attributes
        .iter()
        .any(|a| matches!(a, LinkAttribute::Controller(index) if *index == bridge))
        && !attributes
            .iter()
            .any(|a| matches!(a, LinkAttribute::IfName(name) if name == tunnel))
}

/// UDP destination port used by this driver's VXLAN devices.
pub const VXLAN_PORT: u16 = 4789;

/// What an overlay costs a frame: 14 bytes of inner Ethernet, 8 of VXLAN, 8
/// of UDP and 20 of outer IPv4. On a 1500-byte uplink that leaves 1450, which
/// is the driver's default MTU for the tenant bridge and its VXLAN device.
pub const VXLAN_OVERHEAD: u32 = 50;
pub const DEFAULT_VXLAN_MTU: u32 = 1500 - VXLAN_OVERHEAD;

/// Where `nft` is when nobody says. PATH, which is right on a NixOS node and
/// wrong nowhere in particular — the same default the lvm-thin driver takes
/// for `lvs`.
pub const DEFAULT_NFT: &str = "nft";

/// How long an external command (`ip`, `nft`, `arping`) may run before it is killed (R3-F08).
///
/// Generous for commands that take milliseconds, but short enough that a wedged one costs one
/// retried command instead of stalling the agent's serial command pump.
pub(crate) const COMMAND_DEADLINE: std::time::Duration = std::time::Duration::from_secs(5);

/// How this node reaches other VXLAN endpoints.
#[derive(Clone, Debug)]
pub struct VxlanConfig {
    /// Underlay interface used by the VXLAN tunnel.
    pub uplink: String,
    /// MTU assigned to new overlay bridges, VXLAN devices and taps.
    pub mtu: u32,
    /// Use FRR EVPN with an explicit VTEP address and kernel learning disabled.
    /// All peers of an overlay must use compatible discovery settings.
    pub evpn: bool,
}

/// Bridge name derived from the VNI.
pub fn overlay_bridge(vni: u32) -> String {
    format!("meister-vx{vni}")
}

/// Parse this driver's overlay bridge naming convention.
pub fn overlay_vni(name: &str) -> Option<u32> {
    name.strip_prefix("meister-vx")?.parse().ok()
}

/// The VXLAN device itself, enslaved to that bridge. Shorter than the bridge
/// name because both have to fit `IFNAMSIZ` and only one of them can be the
/// readable one.
pub fn overlay_device(vni: u32) -> String {
    format!("mvx{vni}")
}

/// Parse this driver's VXLAN device naming convention.
fn overlay_device_vni(name: &str) -> Option<u32> {
    name.strip_prefix("mvx")?.parse().ok()
}

/// Whether `key` is the short form of an id that tap and router veth names carry: the first
/// eight hex digits of its simple form.
pub(crate) fn is_short_key(key: &str) -> bool {
    key.len() == 8
        && key
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Whether this driver names a link `name` for guests' or tenants' frames: a tap, an overlay's
/// bridge or VXLAN device, a provider bridge or the host end of a router's leg.
fn is_tenant_link(name: &str) -> bool {
    LinuxNetworkDriver::is_tap_name(name)
        || overlay_vni(name).is_some()
        || overlay_device_vni(name).is_some()
        || name.starts_with(router::PROVIDER_PREFIX)
        || router::is_router_veth(name)
}

/// Refuse cleanup when the recorded bridge belongs to another naming scheme.
/// Legacy records without a bridge name use this driver's conventional name.
fn not_this_drivers_overlay(vni: u32, recorded: Option<&str>) -> Option<String> {
    let mine = overlay_bridge(vni);
    let said = recorded.filter(|name| *name != mine)?;
    Some(format!(
        "vxlan {vni} was carried by bridge {said:?} on this node, and this driver names its own \
         {mine:?}; another network driver built it and it is not this one's to remove"
    ))
}

/// Require the generated bridge name to fit Linux's interface-name limit.
/// The meister-vx prefix leaves five decimal digits for the VNI.
fn check_overlay_name(vni: u32) -> networking::Result<()> {
    let name = overlay_bridge(vni);
    if name.len() >= libc::IFNAMSIZ {
        return Err(NetworkError::InvalidSpec(format!(
            "vxlan {vni} would need the interface {name:?}, which is {} characters and the \
             kernel allows {}; keep vni_base and the tenant count under six digits",
            name.len(),
            libc::IFNAMSIZ - 1
        )));
    }
    Ok(())
}

/// Where the kernel keeps IPv6's settings, per link. Absent when the kernel runs without IPv6.
const IPV6_CONF: &str = "/proc/sys/net/ipv6/conf";

/// Whether this kernel runs IPv6 at all; booted with `ipv6.disable=1` it does not.
pub(crate) fn kernel_has_ipv6() -> bool {
    Path::new(IPV6_CONF).is_dir()
}

/// Turn the host's IPv6 off on a link this driver made for guests' or tenants' frames
/// (IKR-B77).
///
/// With IPv6 on, the host gives the link a link-local address and sends router solicitations
/// and MLD reports through it: into every tenant overlay, which VXLAN carries on to other
/// hosts, showing tenants the host's interfaces and MACs. The guests' own IPv6 is bridged and
/// stays as it is. Called before the link first goes up, so that it never has an address, and
/// again whenever the link is ensured: a tap on every start of its guest, an overlay with every
/// NIC or router on it, a provider bridge at every agent start. Links made before that are
/// mended at agent start by [`host_ipv6_off_where_still_on`].
pub(crate) async fn host_ipv6_off(link: &str) -> networking::Result<()> {
    if !kernel_has_ipv6() {
        return Ok(());
    }
    let switch = Path::new(IPV6_CONF).join(link).join("disable_ipv6");
    tokio::fs::write(&switch, b"1").await.map_err(|e| {
        NetworkError::Backend(
            anyhow::Error::new(e).context(format!("turning the host's IPv6 off on {link}")),
        )
    })
}

/// Turn the host's IPv6 off on every link of this driver's naming where it is still on, and
/// name those links (IKR-B77).
///
/// A guest that kept running across the agent's restart keeps its tap, and the overlay it hangs
/// on, as an agent before IKR-B77 made them: with the host's IPv6 on until the guest's next
/// start. Every link is tried; the error names those that refused.
async fn host_ipv6_off_where_still_on() -> networking::Result<Vec<String>> {
    if !kernel_has_ipv6() {
        return Ok(Vec::new());
    }
    let mut mended = Vec::new();
    let mut refused = Vec::new();
    for link in tenant_links_with_host_ipv6().await? {
        match host_ipv6_off(&link).await {
            Ok(()) => mended.push(link),
            Err(e) => {
                warn!(link = %link, error = %format!("{e:#}"),
                      "the host's IPv6 could not be turned off on this link");
                refused.push(link);
            }
        }
    }
    match refused.is_empty() {
        true => Ok(mended),
        false => Err(NetworkError::Backend(anyhow::anyhow!(
            "the host's IPv6 stays on on {}",
            refused.join(", ")
        ))),
    }
}

/// The links of this driver's naming whose IPv6 switch is not off, as the kernel's per-link
/// settings show them. A switch that cannot be read counts as on: unknown is not off.
async fn tenant_links_with_host_ipv6() -> networking::Result<Vec<String>> {
    let unlisted = |e: std::io::Error| {
        NetworkError::Backend(anyhow::Error::new(e).context(format!("listing {IPV6_CONF}")))
    };
    let mut entries = tokio::fs::read_dir(IPV6_CONF).await.map_err(unlisted)?;
    let mut links = Vec::new();
    while let Some(entry) = entries.next_entry().await.map_err(unlisted)? {
        let Ok(name) = entry.file_name().into_string() else {
            continue;
        };
        if !is_tenant_link(&name) {
            continue;
        }
        let switch = entry.path().join("disable_ipv6");
        let off = tokio::fs::read_to_string(&switch)
            .await
            .is_ok_and(|value| value.trim() == "1");
        if !off {
            links.push(name);
        }
    }
    links.sort_unstable();
    Ok(links)
}

/// Map the lower 24 VNI bits to an administratively scoped IPv4 multicast group.
pub fn multicast_group(vni: u32) -> Ipv4Addr {
    let [_, b1, b2, b3] = vni.to_be_bytes();
    Ipv4Addr::new(239, b1, b2, b3)
}

mod tun {
    use std::os::fd::AsRawFd;
    nix::ioctl_write_ptr_bad!(
        tunsetiff,
        nix::request_code_write!(b'T', 202, std::mem::size_of::<libc::c_int>()),
        libc::ifreq
    );
    nix::ioctl_write_int!(tunsetpersist, b'T', 203);

    pub fn create_persistent_tap(name: &str) -> std::io::Result<()> {
        if name.len() >= libc::IFNAMSIZ {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("tap name too long: {name}"),
            ));
        }

        let tunfd = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/net/tun")?;

        let mut ifr: libc::ifreq = unsafe { std::mem::zeroed() };
        for (dst, src) in ifr.ifr_name.iter_mut().zip(name.as_bytes()) {
            *dst = *src as libc::c_char;
        }
        ifr.ifr_ifru.ifru_flags = (libc::IFF_TAP | libc::IFF_NO_PI) as libc::c_short;

        unsafe { tunsetiff(tunfd.as_raw_fd(), &ifr) }.map_err(std::io::Error::from)?;
        unsafe { tunsetpersist(tunfd.as_raw_fd(), 1) }.map_err(std::io::Error::from)?;

        Ok(())
    }
}

/// Whether this is an address the kernel gives an interface rather than one
/// somebody put there.
fn is_link_local(ip: &std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => v4.is_link_local(),
        std::net::IpAddr::V6(v6) => v6.is_unicast_link_local(),
    }
}

pub struct LinuxNetworkDriver {
    handle: rtnetlink::Handle,
    /// `None` = this node serves no overlays, which is every node before M5
    /// and every node without a `[network.vxlan]` section.
    vxlan: Option<VxlanConfig>,
    /// Every created tap gets MAC pinning; address checks depend on its network spec.
    nft: nftables::Nft,
    guarded: common::net::Ipv4Ranges,
    /// Optional provider-network mapping and router state directory.
    gateway: Option<router::GatewayConfig>,
}

impl LinuxNetworkDriver {
    pub fn new() -> networking::Result<Self> {
        Self::build(
            None,
            nftables::NftConfig {
                binary: DEFAULT_NFT.to_string(),
                guarded: common::net::Ipv4Ranges::default(),
            },
            None,
        )
    }

    pub fn build(
        vxlan: Option<VxlanConfig>,
        nft: nftables::NftConfig,
        gateway: Option<router::GatewayConfig>,
    ) -> networking::Result<Self> {
        let (connection, handle, _) =
            rtnetlink::new_connection().map_err(|e| NetworkError::Backend(e.into()))?;
        tokio::spawn(connection);
        let guarded = nft.guarded;
        if !guarded.is_empty() {
            info!(ranges = %guarded.to_nft(), addresses = guarded.len(),
                  "guarding the floating pool on every tap");
        }
        // Fails the start-up if this node cannot program nftables. See
        // `nftables::Nft::new` for why that is an error and not a warning.
        let nft = nftables::Nft::new(nft.binary)?;
        // Validate provider names and log the configured interface mappings.
        if let Some(g) = &gateway {
            for (physnet, interface) in &g.physnets {
                router::check_physnet_name(physnet)?;
                info!(physnet = %physnet, interface = %interface,
                      bridge = %router::provider_bridge(physnet),
                      "this node gives an interface away and can hold routers");
            }
        }
        Ok(Self {
            handle,
            vxlan,
            nft,
            guarded,
            gateway,
        })
    }

    fn tap_name(id: &NicId) -> String {
        format!("msk{}", &id.simple().to_string()[..8])
    }

    /// Whether `name` is one [`Self::tap_name`] gives.
    fn is_tap_name(name: &str) -> bool {
        name.strip_prefix("msk").is_some_and(is_short_key)
    }

    async fn link_index(&self, name: &str) -> networking::Result<Option<u32>> {
        let mut links = self
            .handle
            .link()
            .get()
            .match_name(name.to_string())
            .execute();
        match links.try_next().await {
            Ok(Some(link)) => Ok(Some(link.header.index)),
            Ok(None) => Ok(None),
            Err(rtnetlink::Error::NetlinkError(err)) if err.raw_code() == -libc::ENODEV => Ok(None),
            Err(e) => Err(NetworkError::Backend(e.into())),
        }
    }

    /// Read the existing link MTU, used to size router provider-side veths.
    pub(crate) async fn link_mtu(&self, name: &str) -> networking::Result<Option<u32>> {
        let mut links = self
            .handle
            .link()
            .get()
            .match_name(name.to_string())
            .execute();
        match links.try_next().await {
            Ok(Some(link)) => Ok(link.attributes.iter().find_map(|attr| match attr {
                rtnetlink::packet_route::link::LinkAttribute::Mtu(mtu) => Some(*mtu),
                _ => None,
            })),
            Ok(None) => Ok(None),
            Err(rtnetlink::Error::NetlinkError(err)) if err.raw_code() == -libc::ENODEV => Ok(None),
            Err(e) => Err(NetworkError::Backend(e.into())),
        }
    }

    /// Enumerate overlay bridges by naming convention, including partially removed pairs.
    async fn overlays_present(&self) -> networking::Result<Vec<u32>> {
        let mut links = self.handle.link().get().execute();
        let mut found = Vec::new();
        while let Some(link) = links
            .try_next()
            .await
            .map_err(|e| NetworkError::Backend(e.into()))?
        {
            for attribute in &link.attributes {
                if let LinkAttribute::IfName(name) = attribute
                    && let Some(vni) = overlay_vni(name)
                {
                    found.push(vni);
                }
            }
        }
        found.sort_unstable();
        found.dedup();
        Ok(found)
    }

    /// Shared by last-VM teardown and startup sweeping. Router records and live
    /// ports both count; a failed inventory read authorizes no link deletion.
    async fn remove_unused_overlay(&self, vni: u32) -> networking::Result<bool> {
        if let Some(gateway) = &self.gateway
            && router::overlay_vnis(&gateway.state_dir)
                .await?
                .contains(&vni)
        {
            return Ok(false);
        }
        let bridge = overlay_bridge(vni);
        let device = overlay_device(vni);
        if let Some(index) = self.link_index(&bridge).await? {
            let mut links = self.handle.link().get().execute();
            while let Some(link) = links
                .try_next()
                .await
                .map_err(|e| NetworkError::Backend(e.into()))?
            {
                if is_overlay_consumer(&link.attributes, index, &device) {
                    return Ok(false);
                }
            }
        }
        BridgeDriver::destroy(self, &device).await?;
        BridgeDriver::destroy(self, &bridge).await?;
        Ok(true)
    }

    /// The first IPv4 address on a link, which for the uplink is this node's
    /// VTEP identity under EVPN.
    async fn link_address(&self, index: u32) -> networking::Result<Option<Ipv4Addr>> {
        use rtnetlink::packet_route::address::AddressAttribute;
        let mut addrs = self
            .handle
            .address()
            .get()
            .set_link_index_filter(index)
            .execute();
        while let Some(msg) = addrs
            .try_next()
            .await
            .map_err(|e| NetworkError::Backend(e.into()))?
        {
            for attr in &msg.attributes {
                if let AddressAttribute::Address(std::net::IpAddr::V4(v4)) = attr {
                    return Ok(Some(*v4));
                }
            }
        }
        Ok(None)
    }

    /// Enslave and raise a link in one netlink message.
    pub(crate) async fn enslave(&self, index: u32, controller: u32) -> networking::Result<()> {
        self.handle
            .link()
            .set(
                LinkUnspec::new_with_index(index)
                    .controller(controller)
                    .up()
                    .build(),
            )
            .execute()
            .await
            .map_err(|e| NetworkError::Backend(e.into()))
    }

    /// Read non-link-local addresses before assigning a provider interface to a bridge.
    pub(crate) async fn global_addresses(&self, index: u32) -> networking::Result<Vec<String>> {
        use rtnetlink::packet_route::address::AddressAttribute;
        let mut addrs = self
            .handle
            .address()
            .get()
            .set_link_index_filter(index)
            .execute();
        let mut out = Vec::new();
        while let Some(msg) = addrs
            .try_next()
            .await
            .map_err(|e| NetworkError::Backend(e.into()))?
        {
            for attr in &msg.attributes {
                if let AddressAttribute::Address(ip) = attr
                    && !is_link_local(ip)
                {
                    out.push(format!("{ip}/{}", msg.header.prefix_len));
                }
            }
        }
        Ok(out)
    }

    /// The MTU this node's overlays run at, when it has any.
    pub(crate) fn vxlan_mtu(&self) -> Option<u32> {
        self.vxlan.as_ref().map(|v| v.mtu)
    }

    /// Make sure a bridge for guests' or tenants' frames exists and is up, with the host's IPv6
    /// off before it first comes up (IKR-B77). Returns its index.
    pub(crate) async fn ensure_wire_bridge(
        &self,
        name: &str,
        mtu: Option<u32>,
    ) -> networking::Result<u32> {
        if self.link_index(name).await?.is_none() {
            info!(bridge = %name, mtu, "creating bridge");
            let mut bridge = LinkBridge::new(name);
            if let Some(mtu) = mtu {
                bridge = bridge.mtu(mtu);
            }
            self.handle
                .link()
                .add(bridge.build())
                .execute()
                .await
                .map_err(|e| NetworkError::Backend(e.into()))?;
        }
        let index = self.link_index(name).await?.ok_or_else(|| {
            NetworkError::Backend(anyhow::anyhow!("bridge {name} vanished after create"))
        })?;
        host_ipv6_off(name).await?;
        self.set_up(index).await?;
        Ok(index)
    }

    async fn set_up(&self, index: u32) -> networking::Result<()> {
        self.handle
            .link()
            .set(LinkUnspec::new_with_index(index).up().build())
            .execute()
            .await
            .map_err(|e| NetworkError::Backend(e.into()))
    }

    /// Select the provider, overlay or explicitly configured bridge.
    fn target_bridge(spec: &NicSpec) -> networking::Result<String> {
        match (&spec.physnet, spec.vxlan_id) {
            // Provider and overlay selection are mutually exclusive.
            (Some(physnet), Some(vni)) => Err(NetworkError::InvalidSpec(format!(
                "this nic names the provider network {physnet:?} and the overlay {vni}; a tap \
                 hangs on one wire, so name one of the two"
            ))),
            (Some(physnet), None) => {
                router::check_physnet_name(physnet)?;
                Ok(router::provider_bridge(physnet))
            }
            (None, Some(vni)) => Ok(overlay_bridge(vni)),
            (None, None) => Ok(spec.bridge.clone()),
        }
    }

    /// Return the configured overlay MTU; other NICs keep their interface default.
    fn overlay_mtu(&self, spec: &NicSpec) -> Option<u32> {
        spec.vxlan_id.and(self.vxlan.as_ref()).map(|v| v.mtu)
    }
}

#[async_trait::async_trait]
impl BridgeDriver for LinuxNetworkDriver {
    #[instrument(skip_all, fields(bridge = %name))]
    async fn ensure(&self, name: &str) -> networking::Result<()> {
        if let Some(index) = self.link_index(name).await? {
            return self.set_up(index).await;
        }
        info!("creating bridge");
        self.handle
            .link()
            .add(LinkBridge::new(name).build())
            .execute()
            .await
            .map_err(|e| NetworkError::Backend(e.into()))?;
        let index = self.link_index(name).await?.ok_or_else(|| {
            NetworkError::Backend(anyhow::anyhow!("bridge {name} vanished after create"))
        })?;
        self.set_up(index).await
    }

    #[instrument(skip_all, fields(bridge = %name, addr = %addr, prefix = prefix_len))]
    async fn ensure_address(
        &self,
        name: &str,
        addr: std::net::IpAddr,
        prefix_len: u8,
    ) -> networking::Result<()> {
        let index = self
            .link_index(name)
            .await?
            .ok_or_else(|| NetworkError::BridgeNotFound(name.to_string()))?;

        match self
            .handle
            .address()
            .add(index, addr, prefix_len)
            .execute()
            .await
        {
            Ok(()) => {
                info!("assigned address to bridge");
                Ok(())
            }
            Err(rtnetlink::Error::NetlinkError(err)) if err.raw_code() == -libc::EEXIST => {
                debug!("address already present on bridge");
                Ok(())
            }
            Err(e) => Err(NetworkError::Backend(e.into())),
        }
    }

    #[instrument(skip_all, fields(bridge = %name))]
    async fn destroy(&self, name: &str) -> networking::Result<()> {
        match self.link_index(name).await? {
            Some(index) => self
                .handle
                .link()
                .del(index)
                .execute()
                .await
                .map_err(|e| NetworkError::Backend(e.into())),
            None => Ok(()),
        }
    }

    /// Ensure overlay links exist and are up. Existing link attributes are not fully
    /// reconciled against changed configuration.
    #[instrument(skip_all, fields(vni, uplink = tracing::field::Empty))]
    async fn ensure_overlay(&self, vni: u32) -> networking::Result<String> {
        let Some(cfg) = &self.vxlan else {
            return Err(NetworkError::InvalidSpec(format!(
                "this vm asks for vxlan {vni}, but this node has no [network.vxlan] section \
                 and so cannot join an overlay"
            )));
        };
        tracing::Span::current().record("uplink", cfg.uplink.as_str());
        check_overlay_name(vni)?;

        let bridge = overlay_bridge(vni);
        let bridge_index = self.ensure_wire_bridge(&bridge, Some(cfg.mtu)).await?;

        let device = overlay_device(vni);
        if self.link_index(&device).await?.is_none() {
            // The uplink has to exist first: `dev` is an interface INDEX on
            // the wire, so a missing one would otherwise become a VXLAN
            // device bound to nothing that silently carries no traffic.
            let uplink = self.link_index(&cfg.uplink).await?.ok_or_else(|| {
                NetworkError::InvalidSpec(format!(
                    "[network.vxlan] uplink {:?} does not exist on this node",
                    cfg.uplink
                ))
            })?;
            // Made down: it comes up below, once the host's IPv6 is off on it.
            let mut builder = LinkVxlan::new(&device, vni)
                .dev(uplink)
                .port(VXLAN_PORT)
                // Leave source-port selection and checksum policy at their kernel defaults.
                .mtu(cfg.mtu);
            if cfg.evpn {
                // EVPN uses the uplink address as VTEP identity and does not join a multicast group.
                let local = self.link_address(uplink).await?.ok_or_else(|| {
                    NetworkError::InvalidSpec(format!(
                        "[network.vxlan] evpn = true needs an ipv4 address on the uplink {:?}: it is \
                         this node's vtep identity and the next hop of every evpn route it \
                         originates",
                        cfg.uplink
                    ))
                })?;
                info!(device = %device, %local, port = VXLAN_PORT, mtu = cfg.mtu,
                      evpn = true, flooding = false, "creating vxlan device");
                builder = builder.local(local).learning(false);
            } else {
                let group = multicast_group(vni);
                info!(device = %device, %group, port = VXLAN_PORT, mtu = cfg.mtu,
                      evpn = false, flooding = true, "creating vxlan device");
                // The kernel fills the FDB from the frames that arrive, which
                // is what makes multicast discovery need no configuration per
                // peer.
                builder = builder.group(group).learning(true);
            }
            self.handle
                .link()
                .add(builder.build())
                .execute()
                .await
                .map_err(|e| NetworkError::Backend(e.into()))?;
        }
        let device_index = self.link_index(&device).await?.ok_or_else(|| {
            NetworkError::Backend(anyhow::anyhow!(
                "vxlan device {device} vanished after create"
            ))
        })?;
        host_ipv6_off(&device).await?;
        self.handle
            .link()
            .set(
                LinkUnspec::new_with_index(device_index)
                    .controller(bridge_index)
                    .up()
                    .build(),
            )
            .execute()
            .await
            .map_err(|e| NetworkError::Backend(e.into()))?;
        debug!(bridge = %bridge, device = %device, "overlay ready");
        Ok(bridge)
    }

    /// Remove an unused VXLAN device before its bridge, preserving a discoverable
    /// bridge if the second deletion fails. Router records and live ports also protect it.
    #[instrument(skip_all, fields(vni))]
    async fn destroy_overlay(&self, vni: u32, recorded: Option<&str>) -> networking::Result<()> {
        if self.vxlan.is_none() {
            return Ok(());
        }
        if let Some(said) = not_this_drivers_overlay(vni, recorded) {
            return Err(NetworkError::InvalidSpec(said));
        }
        if self.remove_unused_overlay(vni).await? {
            info!(vni, "overlay removed, no VM, router or live port owns it");
        }
        Ok(())
    }

    /// Sweep unreferenced overlay bridges after router and live-port ownership checks.
    /// Log individual failures and continue with the remaining overlays.
    #[instrument(skip_all)]
    async fn sweep_overlays(&self, keep: &[u32]) -> networking::Result<Vec<String>> {
        if self.vxlan.is_none() {
            return Ok(Vec::new());
        }
        let mut swept = Vec::new();
        for vni in self.overlays_present().await? {
            if keep.contains(&vni) {
                continue;
            }
            let bridge = overlay_bridge(vni);
            match self.remove_unused_overlay(vni).await {
                Ok(true) => {
                    info!(vni, bridge = %bridge,
                          "orphaned overlay removed: no record on this node names it");
                    swept.push(bridge);
                }
                Ok(false) => {}
                Err(e) => warn!(vni, bridge = %bridge, error = %format!("{e:#}"),
                                "an orphaned overlay bridge would not come down"),
            }
        }
        Ok(swept)
    }

    // Gateway operations are implemented in router.rs.

    async fn ensure_physnet(&self, name: &str, interface: &str) -> networking::Result<String> {
        self.ensure_physnet_impl(name, interface).await
    }

    fn physnets(&self) -> Vec<String> {
        // Off the driver and not off the config file, which is the same
        // pointer here — but it is the driver that would have refused a name
        // it cannot build a bridge for, so this is the list that is true.
        self.gateway
            .as_ref()
            .map(|g| g.physnets.keys().cloned().collect())
            .unwrap_or_default()
    }

    async fn ensure_router(&self, spec: &RouterSpec) -> networking::Result<RouterState> {
        self.ensure_router_impl(spec).await
    }

    async fn destroy_router(&self, id: &RouterId) -> networking::Result<()> {
        // A node with no gateway slot never built one, so it has none to
        // remove and says so by doing nothing — the same answer
        // `destroy_overlay` gives, and for the same reason.
        match self.gateway.is_some() {
            true => self.destroy_router_impl(id).await,
            false => Ok(()),
        }
    }

    async fn router_status(&self, id: &RouterId) -> networking::Result<RouterState> {
        self.router_status_impl(id).await
    }

    async fn list_routers(&self) -> networking::Result<Vec<RouterState>> {
        match self.gateway.is_some() {
            true => self.list_routers_impl().await,
            false => Ok(Vec::new()),
        }
    }

    async fn sweep_routers(&self) -> networking::Result<Vec<String>> {
        match self.gateway.is_some() {
            true => self.sweep_routers_impl().await,
            false => Ok(Vec::new()),
        }
    }

    async fn silence_router(&self, id: &RouterId) -> networking::Result<()> {
        // A node with no gateway slot never built a router, so none of them answers here.
        match self.gateway.is_some() {
            true => self.silence_router_impl(id).await,
            false => Ok(()),
        }
    }

    async fn fall_silent(&self) -> networking::Result<networking::Silencing> {
        // A node with no gateway slot holds no router and has nothing to stop
        // saying — the same answer `sweep_routers` gives.
        match self.gateway.is_some() {
            true => self.fall_silent_impl().await,
            false => Ok(networking::Silencing::default()),
        }
    }
}

#[async_trait::async_trait]
impl NicDriver for LinuxNetworkDriver {
    #[instrument(skip_all, fields(nic_id = %id, bridge = tracing::field::Empty,
                                  vxlan_id = spec.vxlan_id,
                                  physnet = spec.physnet.as_deref()))]
    async fn create(&self, id: &NicId, spec: &NicSpec) -> networking::Result<Nic> {
        let tap = Self::tap_name(id);
        let bridge = LinuxNetworkDriver::target_bridge(spec)?;
        tracing::Span::current().record("bridge", bridge.as_str());

        let bridge_index = self
            .link_index(&bridge)
            .await?
            .ok_or_else(|| NetworkError::BridgeNotFound(bridge.clone()))?;

        if self.link_index(&tap).await?.is_none() {
            let name = tap.clone();
            tokio::task::spawn_blocking(move || tun::create_persistent_tap(&name))
                .await
                .map_err(|e| NetworkError::Backend(anyhow::anyhow!("blocking task failed: {e}")))?
                .map_err(|e| NetworkError::Backend(e.into()))?;
        }

        let tap_index = self.link_index(&tap).await?.ok_or_else(|| {
            NetworkError::Backend(anyhow::anyhow!("tap {tap} vanished after create"))
        })?;
        debug!(tap = %tap, "tap created");
        host_ipv6_off(&tap).await?;

        let mtu = self.overlay_mtu(spec);
        let mut set = LinkUnspec::new_with_index(tap_index)
            .controller(bridge_index)
            .up();
        if let Some(mtu) = mtu {
            set = set.mtu(mtu);
        }
        self.handle
            .link()
            .set(set.build())
            .execute()
            .await
            .map_err(|e| NetworkError::Backend(e.into()))?;

        // Install the guard before returning the tap to VM provisioning.
        // This ordering assumes no existing guest already uses the selected link name.
        self.nft.guard(&tap, spec, &self.guarded).await?;

        // Return the configured MTU and pinned guest MAC to the VMM.
        Ok(Nic {
            id: *id,
            tap_name: tap,
            mtu,
            mac: Some(spec.mac),
        })
    }

    #[tracing::instrument(skip_all, fields(nic_id = %id))]
    async fn destroy(&self, id: &NicId) -> networking::Result<()> {
        let tap = Self::tap_name(id);
        // Remove rules before the tap; unguard failure is logged but does not stop deletion.
        self.nft.unguard(&tap).await;
        match self.link_index(&tap).await? {
            Some(index) => self
                .handle
                .link()
                .del(index)
                .execute()
                .await
                .map_err(|e| NetworkError::Backend(e.into())),
            None => Ok(()),
        }
    }

    /// The tap chains this node has, minus the taps it still holds. See the
    /// trait's own doc: it is the half of a teardown a `kill -9` can leave
    /// behind, and `nft list ruleset` is something an operator reads.
    async fn reap(&self, live_taps: &[String]) {
        self.nft.reap(live_taps).await;
    }

    /// The host's IPv6 off on the taps and wires an agent before IKR-B77 left it on, for the
    /// guests still running on them.
    async fn mend_existing_links(&self) -> networking::Result<Vec<String>> {
        host_ipv6_off_where_still_on().await
    }

    #[instrument(level = "trace", skip_all, fields(nic_id = %id))]
    async fn get(&self, id: &NicId) -> networking::Result<Nic> {
        let tap = Self::tap_name(id);
        match self.link_index(&tap).await? {
            // Check link existence only; this does not verify its type, MAC, MTU or guard.
            Some(_) => Ok(Nic {
                id: *id,
                tap_name: tap,
                mtu: None,
                mac: None,
            }),
            None => Err(NetworkError::NicNotFound(*id)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use agent_api::types::mac_addr::MacAddr;

    fn nic(bridge: &str, vxlan_id: Option<u32>) -> NicSpec {
        NicSpec {
            physnet: None,
            bridge: bridge.to_string(),
            mac: "52:54:00:11:22:33".parse::<MacAddr>().unwrap(),
            vxlan_id,
            floating_ips: Vec::new(),
            routed_subnets: Vec::new(),
        }
    }

    /// Recognize overlay bridge names without matching unrelated interfaces.
    #[test]
    fn only_this_drivers_own_overlay_names_yield_a_vni() {
        for vni in [1, 10_000, 10_003, 99_999] {
            assert_eq!(overlay_vni(&overlay_bridge(vni)), Some(vni), "vni {vni}");
        }
        for other in [
            "meister_br0",
            "docker0",
            "eth0",
            "mvx10003",
            "meister-vx",
            "meister-vxten",
            "meister-vx10003x",
            "tap-4f2c",
        ] {
            assert_eq!(overlay_vni(other), None, "{other}");
        }
    }

    /// IKR-B77: the startup mend touches the links this driver names for guests' and tenants'
    /// frames, and no link an operator named.
    #[test]
    fn only_this_drivers_tenant_links_are_mended() {
        let router = RouterId::from_u128(0x1a2b_3c4d_5e6f_0000_0000_0000_0000_0000);
        for ours in [
            LinuxNetworkDriver::tap_name(&NicId::from_u128(0x77)),
            overlay_bridge(10_003),
            overlay_device(10_003),
            router::provider_bridge("ext"),
            router::veth_external(&router),
            router::veth_internal(&router),
        ] {
            assert!(is_tenant_link(&ours), "{ours}");
        }
        for other in [
            "eth0",
            "lo",
            "all",
            "default",
            "meister_br0",
            "msk",
            "msk1234567",
            "msk1234567g",
            "mskABCDEF01",
            "mvx",
            "rtx-uplink",
            "rti1a2b3c4d5",
        ] {
            assert!(!is_tenant_link(other), "{other}");
        }
    }

    /// Respect recorded driver ownership while retaining compatibility with unnamed records.
    #[test]
    fn an_overlay_another_driver_named_is_not_this_ones_to_remove() {
        assert!(not_this_drivers_overlay(10_000, Some("meister-vx10000")).is_none());
        assert!(not_this_drivers_overlay(10_000, None).is_none());

        let said = not_this_drivers_overlay(10_000, Some("tenant-br-10000"))
            .expect("a refusal, not a removal");
        assert!(said.contains("tenant-br-10000"), "{said}");
        assert!(said.contains("meister-vx10000"), "{said}");
        assert!(said.contains("10000"), "{said}");
    }

    /// One VNI, one group, and no two VNIs sharing one: the three bytes of a
    /// 24-bit identifier are the three low octets of the address, so the map
    /// is one-to-one by construction rather than by hoping.
    #[test]
    fn the_multicast_group_is_the_vni_in_the_admin_scoped_block() {
        assert_eq!(multicast_group(10_000), Ipv4Addr::new(239, 0, 39, 16));
        assert_eq!(multicast_group(1), Ipv4Addr::new(239, 0, 0, 1));
        assert_eq!(
            multicast_group(0x00FF_FFFF),
            Ipv4Addr::new(239, 255, 255, 255)
        );
        // every address is inside 239.0.0.0/8 — the block RFC 2365 reserves
        for vni in [1, 10_000, 65_535, 0x00FF_FFFF] {
            assert_eq!(multicast_group(vni).octets()[0], 239, "vni {vni}");
        }
        // and distinct VNIs never meet
        assert_ne!(multicast_group(10_000), multicast_group(10_001));
    }

    /// The whole compatibility claim of this driver in one assertion: a NIC
    /// that names no overlay goes exactly where it went yesterday.
    #[test]
    fn a_nic_without_a_vxlan_id_lands_on_the_bridge_it_named() {
        assert_eq!(
            LinuxNetworkDriver::target_bridge(&nic("meister_br0", None)).unwrap(),
            "meister_br0"
        );
    }

    /// Festlegung 3: a NIC that names a provider network hangs on that
    /// network's bridge and on no overlay. The lab and single-tenant mode,
    /// which is what exists today and stays.
    #[test]
    fn a_nic_with_a_physnet_lands_on_the_provider_bridge() {
        let mut spec = nic("meister_br0", None);
        spec.physnet = Some("ext".into());
        assert_eq!(
            LinuxNetworkDriver::target_bridge(&spec).unwrap(),
            "meister-px-ext"
        );
        assert_eq!(
            spec.bridge, "meister_br0",
            "the spec still says which default it would otherwise have taken"
        );

        // A name whose bridge would not fit is refused here too, and not only
        // at start-up: a spec may name a physnet this node never configured.
        spec.physnet = Some("public".into());
        let err = LinuxNetworkDriver::target_bridge(&spec)
            .unwrap_err()
            .to_string();
        assert!(err.contains("meister-px-public"), "{err}");
    }

    /// Both at once is a refusal and not a precedence rule. Guessing which
    /// one an operator meant would put a tenant's guest on a wire the tenant
    /// does not own, or the other way round, with nothing said.
    #[test]
    fn a_nic_that_names_a_physnet_and_an_overlay_is_refused_in_words() {
        let mut spec = nic("meister_br0", Some(10_000));
        spec.physnet = Some("ext".into());
        let err = LinuxNetworkDriver::target_bridge(&spec)
            .unwrap_err()
            .to_string();
        assert!(err.contains("\"ext\"") && err.contains("10000"), "{err}");
        assert!(err.contains("name one of the two"), "{err}");
    }

    /// And one that does goes to the tenant's bridge — while the record goes
    /// on saying which default it would otherwise have taken.
    #[test]
    fn a_nic_with_a_vxlan_id_lands_on_the_tenant_bridge() {
        let spec = nic("meister_br0", Some(10_000));
        assert_eq!(
            LinuxNetworkDriver::target_bridge(&spec).unwrap(),
            "meister-vx10000"
        );
        assert_eq!(
            spec.bridge, "meister_br0",
            "the spec still says what was asked for"
        );
        assert_eq!(overlay_device(10_000), "mvx10000");
    }

    /// Both names have to survive the kernel, and the readable one is the one
    /// that runs out first. Five digits fit; six do not, and the refusal says
    /// so before a netlink call turns it into ENAMETOOLONG.
    #[test]
    fn a_vni_whose_interface_name_would_not_fit_is_refused_in_words() {
        assert!(check_overlay_name(10_000).is_ok());
        assert_eq!(
            overlay_bridge(99_999).len(),
            libc::IFNAMSIZ - 1,
            "exactly at the limit"
        );
        assert!(check_overlay_name(99_999).is_ok());

        let err = check_overlay_name(100_000).unwrap_err().to_string();
        assert!(err.contains("meister-vx100000"), "{err}");
        assert!(
            err.contains("15"),
            "the message names the kernel's limit: {err}"
        );
    }

    /// 1450 on a 1500-byte uplink, and the number is arithmetic rather than
    /// folklore: 14 inner Ethernet + 8 VXLAN + 8 UDP + 20 outer IPv4.
    #[test]
    fn the_default_mtu_is_the_uplink_minus_the_encapsulation() {
        assert_eq!(VXLAN_OVERHEAD, 14 + 8 + 8 + 20);
        assert_eq!(DEFAULT_VXLAN_MTU, 1450);
    }
}
