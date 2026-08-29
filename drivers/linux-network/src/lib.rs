// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Bridges, taps, and — since M5 — one VXLAN overlay per tenant.
//!
//! The overlay is deliberately the smallest thing that isolates. Per VNI the
//! node gets a bridge (`meister-vx<vni>`) and a VXLAN device (`mvx<vni>`)
//! enslaved to it, and a tenant's taps join that bridge instead of the
//! default one. Two tenants on one host are then two bridges with no path
//! between them, and two tenants across hosts are two VNIs in the encap
//! header, which the receiving kernel demultiplexes before the frame reaches
//! any bridge at all.
//!
//! **Peer discovery is multicast**, and the group is DERIVED from the VNI
//! (`239.<b1>.<b2>.<b3>` out of its three bytes, in the admin-scoped block).
//! Nothing has to be configured per peer and nothing has to be told when a
//! node joins: the kernel's own MAC learning fills the FDB from the frames
//! that arrive. The cost is that the uplink's network has to pass multicast,
//! which a lab switch does and some clouds do not.
//!
//! The documented alternative for a network that does not, NOT built here:
//! static FDB entries, one per peer —
//!
//! ```text
//! bridge fdb append 00:00:00:00:00:00 dev mvx10000 dst <peer-ip>
//! ```
//!
//! — appended for every other node, which turns broadcast into head-end
//! replication to a known list. It needs no multicast at all and it needs
//! somebody to maintain the list, which is a control-plane job: the cluster
//! knows every node's address, so the natural home for it is a peer list
//! pushed down the session rather than a config file per node. That is a
//! milestone of its own and this comment is where it starts.
//!
//! ## Hardware offload is why several of these choices are not free
//!
//! VXLAN is the overlay nearly every server NIC of the last decade can
//! encapsulate and segment in hardware, and that is most of the reason to
//! pick it over a cleverer encapsulation. In software, encapsulation costs a
//! per-packet trip through the stack and gives up TSO/GRO on the inner
//! frames — the difference between line rate and one core pegged at a few
//! Gbit/s. On the NIC it costs almost nothing. So the settings below are
//! chosen to stay ON the offload path, and the ones that would leave it are
//! deliberately not set:
//!
//! - **The destination port is 4789 and is not configurable.** A NIC learns
//!   which UDP ports are tunnels through `ndo_udp_tunnel_add`, the table it
//!   keeps is small, and some parts only ever offload the IANA port. A custom
//!   port is the easiest way to fall off hardware encapsulation with no error
//!   to show for it.
//! - **No `srcport` range is set.** The kernel derives the outer UDP source
//!   port from a hash of the inner headers, which is what gives the receiving
//!   NIC's RSS something to spread flows across queues with. Pinning it would
//!   collapse every tenant flow between two nodes onto one receive queue.
//! - **No UDP checksum is forced.** IPv4 VXLAN leaves it zero by default; a
//!   NIC that offloads fills it in, and demanding it in software is a
//!   per-packet cost for a check the outer IP header already covers.
//! - **The MTU is a config key.** 1450 keeps an overlay frame inside a
//!   1500-byte uplink; a jumbo uplink (9000, overlay 8950) removes most of
//!   the segmentation work altogether, which is the shape to aim for on a
//!   cluster fabric.
//!
//! What this driver cannot do is make a NIC offload — that is the uplink's
//! own capability, checked with `ethtool -k <uplink> | grep udp_tnl`
//! (`tx-udp_tnl-segmentation` and `tx-udp_tnl-csum-segmentation` on). A node
//! whose NIC reports them off pays for its overlay in CPU. Nothing here turns
//! them off, and nothing here should.

pub mod frr;
pub mod nftables;

use futures::TryStreamExt;
use std::net::Ipv4Addr;

use agent_api::networking::{self, BridgeDriver, NetworkError, Nic, NicDriver, NicId, NicSpec};
use rtnetlink::{LinkBridge, LinkUnspec, LinkVxlan};
use tracing::{debug, info, instrument};

/// The IANA-assigned VXLAN port (RFC 7348 §5).
///
/// Not configurable, and the reason is hardware rather than convention: a NIC
/// offloads encapsulation only for ports it has been told are tunnels, its
/// table of them is small, and some parts only ever handle this one. A custom
/// port drops the overlay onto the software path silently — no error, just a
/// core at 100%. It is also what every `tcpdump` filter assumes, and a lab
/// wanting a second overlay wants a second VNI, which is free.
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

/// How this node reaches other VXLAN endpoints.
#[derive(Clone, Debug)]
pub struct VxlanConfig {
    /// The interface encapsulated frames leave by. Its address is what peers
    /// see as the tunnel endpoint, so it has to be the one on the network the
    /// other nodes are on — on a single host with no peers, a `dummy0` is
    /// enough to prove the encapsulation happens.
    pub uplink: String,
    /// MTU for the tenant bridge, its VXLAN device and the taps on it.
    ///
    /// 1450 fits an overlay frame inside a 1500-byte uplink. A jumbo uplink
    /// is the shape to aim for on a cluster fabric — 9000 there means 8950
    /// here, and most of the segmentation work disappears along with six
    /// sevenths of the per-packet overhead.
    pub mtu: u32,
    /// Learn the overlay's MACs over BGP instead of flooding for them.
    ///
    /// With it on, the VXLAN device gets no multicast group and no kernel
    /// learning at all: it gets a `local` address (its VTEP identity) and FRR
    /// — told `advertise-all-vni` — reads the device, advertises the MACs
    /// behind it as EVPN type-2 routes and the VTEP itself as type-3, and
    /// programs the FDB from what its peers send back. What was a multicast
    /// group is a BGP session, which is the answer for every network that does
    /// not carry multicast: most clouds, and some switches.
    ///
    /// Off by default, and that default is M5's behaviour byte for byte: a
    /// derived group, kernel learning, and no daemon anywhere.
    ///
    /// Cluster-wide, not per node. Two nodes of one overlay disagreeing about
    /// this are two nodes that never learn each other's MACs — one floods to a
    /// group nobody is in, the other waits for routes nobody sends. The
    /// example config says so; there is no scheduling constraint that could
    /// enforce it, because a VM does not ask for evpn, it asks for an overlay.
    pub evpn: bool,
}

/// The bridge a tenant's taps join on this node.
///
/// Named after the VNI and not after the tenant: the agent never learns what
/// a tenant is called — that is the control plane's business — and the number
/// is what both ends of the tunnel agree on anyway. An operator reading
/// `ip link` sees the same number `tenant ls` prints and the same number in
/// the encap header, which is the whole reason not to invent a third name.
pub fn overlay_bridge(vni: u32) -> String {
    format!("meister-vx{vni}")
}

/// The VXLAN device itself, enslaved to that bridge. Shorter than the bridge
/// name because both have to fit `IFNAMSIZ` and only one of them can be the
/// readable one.
pub fn overlay_device(vni: u32) -> String {
    format!("mvx{vni}")
}

/// Whether this VNI's interfaces can be named at all.
///
/// A Linux interface name is 15 characters plus a NUL, so `meister-vx` plus
/// the number fits up to five digits — VNI 99999, and with the default floor
/// of 10000 that is ninety thousand tenants per deployment. The limit is the
/// kernel's and not this driver's, and a node meeting it should say so at the
/// first VM rather than fail inside a netlink call with `ENAMETOOLONG` and no
/// hint which name was too long.
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

/// The multicast group a VNI's endpoints meet in.
///
/// Derived rather than configured, and that is the point: two nodes given the
/// same VNI by the control plane land in the same group without anybody
/// distributing a second number. 239.0.0.0/8 is the administratively scoped
/// block (RFC 2365) — the private-address equivalent for multicast — and the
/// three bytes of a 24-bit VNI fit its lower three octets exactly, so the
/// mapping is one-to-one and no two tenants can collide.
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

pub struct LinuxNetworkDriver {
    handle: rtnetlink::Handle,
    /// `None` = this node serves no overlays, which is every node before M5
    /// and every node without a `[network.vxlan]` section.
    vxlan: Option<VxlanConfig>,
    /// The tap guard. Not an Option, and that is the point: MAC pinning
    /// applies to every VM this stack boots, whether or not anybody has
    /// configured a floating pool. What IS optional is the pool inside it —
    /// `guarded` is empty on a node with no `guarded_ranges`, and an empty set
    /// produces no address rule at all.
    nft: nftables::Nft,
    guarded: common::net::Ipv4Ranges,
}

impl LinuxNetworkDriver {
    pub fn new() -> networking::Result<Self> {
        Self::build(
            None,
            nftables::NftConfig {
                binary: DEFAULT_NFT.to_string(),
                guarded: common::net::Ipv4Ranges::default(),
            },
        )
    }

    pub fn build(vxlan: Option<VxlanConfig>, nft: nftables::NftConfig) -> networking::Result<Self> {
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
        Ok(Self {
            handle,
            vxlan,
            nft,
            guarded,
        })
    }

    fn tap_name(id: &NicId) -> String {
        format!("msk{}", &id.simple().to_string()[..8])
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

    async fn set_up(&self, index: u32) -> networking::Result<()> {
        self.handle
            .link()
            .set(LinkUnspec::new_with_index(index).up().build())
            .execute()
            .await
            .map_err(|e| NetworkError::Backend(e.into()))
    }

    /// Where this NIC's tap belongs: the tenant's overlay bridge, or the one
    /// the spec named.
    ///
    /// Derived here rather than carried in `NicSpec.bridge` so that the
    /// record keeps saying what was ASKED for. A tap whose spec says
    /// `bridge = "meister_br0", vxlan_id = 10000` is on the overlay, and an
    /// operator reading the record can still see which default it would have
    /// taken without the tenant.
    fn target_bridge(spec: &NicSpec) -> String {
        match spec.vxlan_id {
            Some(vni) => overlay_bridge(vni),
            None => spec.bridge.clone(),
        }
    }

    /// The MTU a tap gets: the overlay's where there is one, and the
    /// interface default otherwise.
    ///
    /// Set on the tap and not only on the bridge because a Linux bridge takes
    /// the MTU of its smallest port: a 1500-byte tap joining a 1450-byte
    /// bridge drags the bridge back up to 1500, and the first full-size frame
    /// a guest sends is then dropped by the VXLAN device with nothing in any
    /// log to say why.
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

    /// The tenant's overlay on this node: a bridge, a VXLAN device in it, and
    /// both up at the configured MTU.
    ///
    /// Idempotent by existence, exactly as `ensure` is — the second VM of a
    /// tenant finds both links there and only makes sure they are up. What it
    /// does NOT do is tear anything down: the bridge and the VXLAN device
    /// outlive the last VM of a tenant on this node, on purpose. Reaping them
    /// would mean knowing that no other VM is arriving in the next second,
    /// which is a question a level-triggered agent cannot answer, and the cost
    /// of being wrong is a VM that boots into a bridge somebody just deleted.
    /// Two idle links per tenant per node is the price; a GC pass driven by
    /// the reconciler is the documented way to stop paying it.
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
        match self.link_index(&bridge).await? {
            Some(index) => self.set_up(index).await?,
            None => {
                info!(bridge = %bridge, mtu = cfg.mtu, "creating tenant bridge");
                self.handle
                    .link()
                    .add(LinkBridge::new(&bridge).mtu(cfg.mtu).build())
                    .execute()
                    .await
                    .map_err(|e| NetworkError::Backend(e.into()))?;
            }
        }
        let bridge_index = self.link_index(&bridge).await?.ok_or_else(|| {
            NetworkError::Backend(anyhow::anyhow!("bridge {bridge} vanished after create"))
        })?;
        self.set_up(bridge_index).await?;

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
            let mut builder = LinkVxlan::new(&device, vni)
                .dev(uplink)
                .port(VXLAN_PORT)
                // Deliberately NOT set here, and the module doc says why: no
                // `port_range` (the inner-header hash in the outer source
                // port is what the receiver's RSS spreads on) and no forced
                // UDP checksum. Both are the difference between a NIC that
                // encapsulates and a core that does.
                .mtu(cfg.mtu)
                .up();
            if cfg.evpn {
                // EVPN's shape: no group to flood into and no learning of our
                // own, because both are FRR's job now. `local` is this node's
                // VTEP identity — the address peers see as the tunnel end and
                // the next hop FRR puts on every type-2 route it originates —
                // so it has to be the uplink's own address and not the
                // interface index the `dev` above carries.
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
}

#[async_trait::async_trait]
impl NicDriver for LinuxNetworkDriver {
    #[instrument(skip_all, fields(nic_id = %id, bridge = tracing::field::Empty,
                                  vxlan_id = spec.vxlan_id))]
    async fn create(&self, id: &NicId, spec: &NicSpec) -> networking::Result<Nic> {
        let tap = Self::tap_name(id);
        let bridge = Self::target_bridge(spec);
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

        // The guard goes on AFTER the tap is up and before the VMM is told
        // about it: provisioning builds the tap, this builds its chain, and
        // the hypervisor is spawned afterwards. A guest never sees an
        // unguarded moment on its own tap — which is also why the rules follow
        // the TAP's lifetime and not the VMM's, and why a stop/start keeps the
        // rules it had while a recreate reads the spec again.
        self.nft.guard(&tap, spec, &self.guarded).await?;

        // Handed back so the hypervisor can pass it to the guest: the tap and
        // the bridge bound what the HOST forwards, and a guest that still
        // believes in 1500 would go on emitting frames the overlay drops.
        Ok(Nic {
            id: *id,
            tap_name: tap,
            mtu,
        })
    }

    #[tracing::instrument(skip_all, fields(nic_id = %id))]
    async fn destroy(&self, id: &NicId) -> networking::Result<()> {
        let tap = Self::tap_name(id);
        // Chain first, tap second. The other order would leave a window in
        // which a chain names a device that no longer exists, and the kernel
        // reaps those on its own — which is fine, and is exactly why the
        // failure here is a debug line rather than a failed teardown.
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

    #[instrument(level = "trace", skip_all, fields(nic_id = %id))]
    async fn get(&self, id: &NicId) -> networking::Result<Nic> {
        let tap = Self::tap_name(id);
        match self.link_index(&tap).await? {
            // Liveness only — `mtu` is what a create SET, and this call is
            // the reconciler asking whether the tap is still there.
            Some(_) => Ok(Nic {
                id: *id,
                tap_name: tap,
                mtu: None,
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
            bridge: bridge.to_string(),
            mac: "52:54:00:11:22:33".parse::<MacAddr>().unwrap(),
            vxlan_id,
            floating_ips: Vec::new(),
            routed_subnets: Vec::new(),
        }
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
            LinuxNetworkDriver::target_bridge(&nic("meister_br0", None)),
            "meister_br0"
        );
    }

    /// And one that does goes to the tenant's bridge — while the record goes
    /// on saying which default it would otherwise have taken.
    #[test]
    fn a_nic_with_a_vxlan_id_lands_on_the_tenant_bridge() {
        let spec = nic("meister_br0", Some(10_000));
        assert_eq!(LinuxNetworkDriver::target_bridge(&spec), "meister-vx10000");
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
