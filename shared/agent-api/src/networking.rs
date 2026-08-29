// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

use crate::types::mac_addr::MacAddr;
use uuid::Uuid;

pub type NicId = Uuid;

#[derive(Debug, thiserror::Error)]
pub enum NetworkError {
    #[error("nic not found: {0}")]
    NicNotFound(NicId),
    #[error("bridge not found: {0}")]
    BridgeNotFound(String),
    #[error("invalid nic spec: {0}")]
    InvalidSpec(String),
    #[error("network backend failure: {0}")]
    Backend(anyhow::Error),
}

pub type Result<T> = std::result::Result<T, NetworkError>;

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct NicSpec {
    pub bridge: String,
    pub mac: MacAddr,
    /// The tenant overlay this NIC belongs on, if any. `None` — the default
    /// and every spec written before M5 — is the node's default bridge,
    /// exactly as it always was.
    ///
    /// A number and not a tenant name on purpose: by the time a spec reaches
    /// a node the controller has already resolved which wire this is (see
    /// `controller_api::vni`), and an agent that had to look tenants up would
    /// be an agent that needs the directory. Typed rather than shovelled
    /// through `params` for the same reason the driver name is: it decides
    /// where the tap lands, and the scheduler reads it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vxlan_id: Option<u32>,
    /// The floating addresses this NIC's VM holds the reservation for.
    ///
    /// The one exception to the guard the driver puts on every tap: source
    /// addresses inside the node's `guarded_ranges` are dropped everywhere,
    /// except here. Travels the same road `vxlan_id` does and is injected in
    /// the same place — the cloud owns the FloatingIp objects, the cluster
    /// writes them into the NIC entries, and the agent only checks types.
    ///
    /// Defaults to empty, so every spec ever written is still exactly the spec
    /// it was: no entries, no exception, and a node with no guarded ranges has
    /// nothing to make an exception to in the first place.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub floating_ips: Vec<String>,
    /// The routed subnets of this NIC's tenant.
    ///
    /// What turns the tap rule from a DENY into an ALLOWLIST. A tenant whose
    /// address space nobody wrote down can only be told "not out of the
    /// floating pool"; a tenant whose subnets are here can be told "these,
    /// your floating addresses, and nothing else". Empty is the first case and
    /// the default.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub routed_subnets: Vec<String>,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct Nic {
    pub id: NicId,
    pub tap_name: String,
    /// What the driver set on the tap, when it set anything. Defaults, so a
    /// record written before overlays existed loads unchanged and means what
    /// it always meant: nobody named an MTU, so nobody tells the guest one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mtu: Option<u32>,
}

#[async_trait::async_trait]
pub trait NicDriver: Send + Sync {
    async fn create(&self, id: &NicId, spec: &NicSpec) -> Result<Nic>;
    async fn destroy(&self, id: &NicId) -> Result<()>;
    async fn get(&self, id: &NicId) -> Result<Nic>;

    /// Throw away whatever per-tap state this driver holds outside its own
    /// records for taps that are not in `live_taps`.
    ///
    /// Called once at start-up, with the taps the agent's own store still
    /// names. A `kill -9` between "remove the tap's filter chain" and "delete
    /// the tap" leaves the first half behind, and while that is harmless — the
    /// device is gone — it is a rule waiting for a name nobody will reuse, and
    /// `nft list ruleset` is something an operator reads.
    ///
    /// Default: nothing to reap. A driver with no host state beyond the links
    /// it creates has nothing to do here, which is what this was before
    /// filtering existed.
    async fn reap(&self, _live_taps: &[String]) {}
}

#[async_trait::async_trait]
pub trait BridgeDriver: Send + Sync {
    async fn ensure(&self, name: &str) -> Result<()>;
    async fn ensure_address(
        &self,
        name: &str,
        addr: std::net::IpAddr,
        prefix_len: u8,
    ) -> Result<()>;
    async fn destroy(&self, name: &str) -> Result<()>;

    /// Make sure this node can carry the overlay `vni`, and say which bridge
    /// taps for it join.
    ///
    /// Its own method rather than a flag on `ensure` because it is a
    /// different thing to ensure: a plain bridge is one link, an overlay is a
    /// bridge plus an encapsulation device pointed at an uplink, and only
    /// this one can be unavailable on a node. The default is that refusal —
    /// a driver that knows nothing about overlays says so in words instead of
    /// quietly putting the VM on the default bridge, where it would reach
    /// every other tenant on the node.
    async fn ensure_overlay(&self, vni: u32) -> Result<String> {
        Err(NetworkError::InvalidSpec(format!(
            "this node has no overlay networking configured, so it cannot serve vxlan {vni}"
        )))
    }
}

/// Both halves of the networking seam in one driver.
///
/// A blanket supertrait and nothing else: every implementation of the two
/// above is automatically one of these, and no driver has to say so. It
/// exists because the agent's driver TABLE registers one row per driver and
/// hands back one `Arc` — and taps and bridges are two faces of one kernel
/// object, made by one implementation, on one node. The two fields on
/// `Drivers` are upcasts of the same pointer, which is what they always held;
/// before this they were two `Arc::clone`s of a concrete type, at the one
/// call site that still knew which type it was.
pub trait NetworkDriver: NicDriver + BridgeDriver {}

impl<T: NicDriver + BridgeDriver + ?Sized> NetworkDriver for T {}

/// Something that tells the outside world which addresses live on this node.
///
/// One implementation and one caller: the reconciler hands over the whole set
/// of floating addresses whose VMs are running here, on every pass, and the
/// implementation makes that true. Level-triggered by contract — the set is
/// the truth, not a stream of changes — which is why the method takes a set
/// and returns nothing to react to.
///
/// It swallows its own failures for the same reason: the next pass hands over
/// the same set, so a failed apply is a degradation that heals itself and not
/// something a caller could do anything about. A driver that could not
/// announce says so in its own log line.
#[async_trait::async_trait]
pub trait RouteAnnouncer: Send + Sync {
    async fn announce(&self, prefixes: std::collections::BTreeSet<String>);
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct NicAttachment {
    pub tap_name: String,
    pub mac: MacAddr,
    /// The MTU to TELL THE GUEST, over virtio-net's own feature bit.
    ///
    /// Setting it on the tap and the bridge is not enough on its own: those
    /// bound what the host will forward, and a guest that still believes in
    /// 1500 goes on emitting frames the overlay then drops — silently, which
    /// is the worst way for a network to be broken. The hypervisor is the one
    /// party that can tell the guest, so the number travels with the
    /// attachment. `None` = say nothing, which is every VM before overlays
    /// and every VM on the default bridge.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mtu: Option<u32>,
}
