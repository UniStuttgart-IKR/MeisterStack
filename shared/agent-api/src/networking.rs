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
    #[error("this node holds no router {0}")]
    RouterNotFound(RouterId),
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
    /// The provider network this NIC hangs on instead of an overlay.
    ///
    /// Festlegung 3, and the one path through the gateway slot that needs no
    /// router at all: a tap on `meister-px-<physnet>` is a guest ON the
    /// provider network, with whatever addressing that network hands out.
    /// It is the lab and single-tenant mode, it is what exists today, and it
    /// stays — the cluster writes no VNI into a NIC that names a physnet.
    ///
    /// A NIC with BOTH is a refusal and not a precedence rule: the two say
    /// different things about where the tap belongs, and guessing which one
    /// the operator meant would put a tenant's guest on a wire the tenant
    /// does not own, or the other way round.
    ///
    /// `None` — every spec ever written — is the overlay-or-default-bridge
    /// behaviour, unchanged.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub physnet: Option<String>,
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
    /// The hardware address this driver PUT on this tap, when it knows one.
    ///
    /// Not read back off the link, and that is the point: a tap device has a
    /// random address of its own that no guest ever uses, so asking the
    /// kernel would answer a different question with a plausible-looking
    /// number. What a guest sends is what the driver pinned — the address in
    /// the tap's filter chain, and the one the hypervisor hands the virtio
    /// device — so the driver that pinned it is the one party that can say.
    ///
    /// `None` is "this driver does not know one", which is a real answer and
    /// the one a liveness check gives: `get` asks whether the tap is still
    /// there and sets nothing, exactly as it leaves `mtu` alone. A record
    /// written before this field loads as `None` as well, and the status
    /// report leaves such an entry out rather than inventing an address.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mac: Option<MacAddr>,
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

    /// Take the overlay `vni` off this node again: its bridge, its
    /// encapsulation device, and nothing else.
    ///
    /// The counterpart `ensure_overlay` never had. What makes it safe to have
    /// now is that somebody counts: the linux driver's own doc argued that
    /// reaping is a question a level-triggered agent cannot answer — "is
    /// another VM for this tenant arriving in the next second?" — and that is
    /// still true, which is why this is NOT a timer or a sweep. It is driven
    /// by the agent's store, which knows every VM this node was told to run,
    /// and the caller asks it only when no record names the VNI any more.
    ///
    /// Two links and not one, which is why `destroy` cannot stand in for it:
    /// deleting a bridge unenslaves its ports, it does not delete them, so
    /// `mvx<vni>` would outlive `meister-vx<vni>` and the leak would be half
    /// as big rather than gone.
    ///
    /// Idempotent by contract, exactly as `destroy` is: an overlay that is
    /// not there is `Ok(())`. The default is a no-op for the same reason
    /// `ensure_overlay`'s default is a refusal — a driver that never built one
    /// has nothing to take down.
    ///
    /// `bridge` is what the VM's record says this overlay was CALLED — the
    /// answer this driver gave at `ensure_overlay` — and `None` means nobody
    /// wrote it down, which is every record from before it was kept. An
    /// implementation whose own name for the VNI is a different one must
    /// refuse rather than remove: the number alone does not say whose the
    /// overlay is, and on a node with two network drivers this call used to
    /// reach whichever one the agent held and take down its link, or none.
    async fn destroy_overlay(&self, _vni: u32, _bridge: Option<&str>) -> Result<()> {
        Ok(())
    }

    /// Take down every overlay this driver built that is not in `keep`, and
    /// say which ones went.
    ///
    /// The one sweep in this trait, and the reason it is allowed where the
    /// per-VM reference count is not: it runs ONCE, at start-up, against the
    /// whole record table at a moment when nothing is being provisioned, so
    /// "is another VM for this tenant arriving in the next second?" — the
    /// question a level-triggered reaper cannot answer — has an answer here.
    /// It is not a timer.
    ///
    /// `keep` is every VNI any record on this node names. The caller must not
    /// call this at all unless it could read the whole table: a record it
    /// could not read might name any VNI, and a sweep on an incomplete list
    /// is a sweep that takes a live tenant's wire down.
    ///
    /// Only this driver's own overlays. Whatever marks them — a name, a
    /// label, a directory — is the implementation's business, and a driver
    /// that cannot tell its own from the rest of the node's links must sweep
    /// nothing, which is what the default does.
    async fn sweep_overlays(&self, _keep: &[u32]) -> Result<Vec<String>> {
        Ok(Vec::new())
    }

    /// Take the interface this node gave away into a provider bridge, and say
    /// what that bridge is called.
    ///
    /// Festlegung 1: the interface belongs to the bridge and the HOST has no
    /// address on it. A driver that finds one must refuse rather than build,
    /// because an address there is somebody still using the interface — the
    /// node did not give it away, and a router put on it would answer for a
    /// network the host is also on.
    ///
    /// Called once per configured physnet at start-up and never again: it is
    /// the node's side of the bargain, and a node whose side of it is broken
    /// must not come up claiming `gateway:<physnet>`.
    ///
    /// The default is the refusal every method of this section defaults to. A
    /// driver with no gateway slot has no provider bridge to make, and saying
    /// so beats returning a name nothing stands behind.
    async fn ensure_physnet(&self, name: &str, _interface: &str) -> Result<String> {
        Err(NetworkError::InvalidSpec(format!(
            "this node's network driver has no gateway slot, so it cannot serve the provider \
             network {name:?}"
        )))
    }

    /// The provider networks this driver actually serves, by name.
    ///
    /// What the Hello turns into one `gateway:<physnet>` profile each, and
    /// what the agent checks an `EnsureRouter` against before it reaches the
    /// driver at all. Off the DRIVER and not off the config for the reason
    /// `HypervisorCatalog` gives about its own name: what a node claims has
    /// to be what it built.
    ///
    /// Empty is a node that is no candidate for any router, which is every
    /// node before 6k and every node with no `[network.provider]` section.
    fn physnets(&self) -> Vec<String> {
        Vec::new()
    }

    /// Make this router exist here, exactly as `spec` says, and answer with
    /// what it now is.
    ///
    /// Level-triggered like everything else: the same spec twice is one
    /// router, and a spec that differs in one field — most often `active` —
    /// converges the router that is already there rather than building a
    /// second one. That is what makes the failover of Festlegung 7 a single
    /// command to the standby.
    async fn ensure_router(&self, spec: &RouterSpec) -> Result<RouterState> {
        Err(NetworkError::InvalidSpec(format!(
            "this node's network driver has no gateway slot, so it cannot build router {}",
            spec.id
        )))
    }

    /// Let this router go, with everything this driver made for it.
    ///
    /// Idempotent by contract, and `Ok(())` by default for the reason
    /// `destroy_overlay` is: a driver that never built one has nothing to take
    /// down, and answering a teardown with a refusal would leave the tier
    /// above retrying a removal that already happened.
    async fn destroy_router(&self, _id: &RouterId) -> Result<()> {
        Ok(())
    }

    /// One router as it IS. `RouterNotFound` for one this node does not hold,
    /// which is a real answer and the one a teardown checks.
    async fn router_status(&self, id: &RouterId) -> Result<RouterState> {
        Err(NetworkError::RouterNotFound(*id))
    }

    /// Every router this driver holds — the half of the status report that is
    /// about routers, and the set the announcement pass reads.
    async fn list_routers(&self) -> Result<Vec<RouterState>> {
        Ok(Vec::new())
    }

    /// Take down whatever this driver built for routers nothing names any
    /// more, and say which ones went.
    ///
    /// The router twin of `sweep_overlays`, and it runs at the same moment
    /// and under the same rule: ONCE, at start-up, before anything can be
    /// asked for. A `kill -9` between "make the namespace" and "write the
    /// record" leaves a namespace with two legs in two bridges and nobody who
    /// knows what it is for; nothing else would ever remove it.
    ///
    /// No `keep` list, unlike the overlay sweep: a router is not reference
    /// -counted from VM records — it is its own object, and this driver's own
    /// record is the only thing that names one.
    async fn sweep_routers(&self) -> Result<Vec<String>> {
        Ok(Vec::new())
    }

    /// Make every router this node holds STOP SPEAKING, and take none of them
    /// down. Says which ones fell silent.
    ///
    /// The router half of saying goodbye, and the reason it exists is a
    /// measurement: a gateway node stopped with `systemctl stop` told its
    /// cluster it was going, the cluster made the standby active eight
    /// seconds later — and the leaving node went on answering ARP for the
    /// router's external address, its floating addresses and the tenant's
    /// gateway, because a namespace outlives the agent that built it. Two
    /// machines answered one `arping` on manacor on 2026-09-10, with two
    /// different MACs, and nothing ever ended it: the `DestroyRouter` the
    /// cluster sent went to a node that was already down, and the start-up
    /// sweep keeps every namespace whose record is still there.
    ///
    /// Silent and not destroyed, deliberately. `systemctl restart` must not
    /// be an outage — the same rule that keeps a stopping agent's guests
    /// running — and a router that is still built is a router the next
    /// `EnsureRouter` makes active again in one pass. What a standby is, is
    /// exactly what this leaves behind.
    ///
    /// Best effort: a node on its way out reports what it managed and goes.
    async fn fall_silent(&self) -> Result<Vec<RouterId>> {
        Ok(Vec::new())
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

// --- the gateway slot -------------------------------------------------------
//
// 6k Mini-Neutron. A tenant router is a second thing a network driver can be
// asked for, beside taps and bridges: a box with one leg on the provider
// network this node gave away and one on a tenant's overlay, translating
// between them. It lives HERE, on the driver seam, and not in the linux
// driver alone — the whole point of the OVN-shaped model is that an OVN
// backend or a DPU offload answers the same four verbs with a logical router
// instead of a namespace, and the agent must not be able to tell.
//
// Every method below has a default, exactly as `ensure_overlay` does, and the
// default is a refusal in words: a driver that has no gateway slot says so
// rather than quietly building nothing and reporting success.

/// A tenant router, by the uid the tier above minted for it.
pub type RouterId = Uuid;

/// OVN's two NAT kinds, and no third one.
///
/// Typed here rather than carried as the wire string, for the reason
/// `Locality` is typed: the driver has to BRANCH on it — one kind is a
/// source rewrite for a whole subnet and the other a 1:1 pair — and a match
/// on prose is a match that silently does nothing the day somebody writes
/// `dnat-and-snat`. Whatever a driver cannot recognise is refused at the
/// translation, where the sentence can still name the rule.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NatKind {
    /// The whole internal subnet leaves behind one external address. `snat`
    /// in OVN, masquerade in nftables.
    Snat,
    /// One address maps to one address, both ways. A floating IP.
    DnatAndSnat,
}

impl NatKind {
    pub const ALL: [NatKind; 2] = [NatKind::Snat, NatKind::DnatAndSnat];

    /// The wire spelling, and the only one: it is what `NatRule.kind` carries
    /// on the session and what OVN's own northbound calls it.
    pub fn as_str(self) -> &'static str {
        match self {
            NatKind::Snat => "snat",
            NatKind::DnatAndSnat => "dnat_and_snat",
        }
    }

    /// The inverse, total. `None` is a kind this build does not know, which
    /// the caller has to turn into a refusal naming the string — a rule
    /// nobody can render must never be a rule silently dropped.
    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|k| k.as_str() == s)
    }
}

/// One translation the router performs.
///
/// Addresses are bare, never CIDRs — a NAT rule is about addresses and not
/// about wires. `logical_ip` is the inside, `external_ip` the outside; for
/// [`NatKind::Snat`] an empty `logical_ip` means "the whole subnet the
/// router's internal leg is on", which is what OVN's own empty field means.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct NatRule {
    pub kind: NatKind,
    pub external_ip: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub logical_ip: String,
}

/// What a router should be, as the tier above states it.
///
/// The driver-facing twin of the session's `EnsureRouter`, translated in the
/// agent exactly as `NicSpec` is: a driver never sees a protobuf, and the
/// second backend does not have to learn one.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct RouterSpec {
    pub id: RouterId,
    /// Which of this node's provider networks the outside leg joins. A node
    /// that does not serve it is not a candidate — see [`BridgeDriver::physnets`].
    pub physnet: String,
    /// The router's own address on the provider network, as a CIDR: the
    /// address `snat` hides a subnet behind, and the one the fabric is asked
    /// to send this router's traffic to while it is active.
    pub external_addr: String,
    /// Where the outside leg's default route points.
    pub external_gateway: String,
    /// The tenant's wire on the inside.
    pub vxlan_id: u32,
    /// The router's address on the tenant's wire, as a CIDR. Its prefix is
    /// the subnet an `snat` rule with an empty `logical_ip` means.
    pub internal_addr: String,
    #[serde(default)]
    pub nats: Vec<NatRule>,
    /// The tenant prefixes this router ANNOUNCES rather than translates.
    ///
    /// Festlegung 5: a routed subnet gets no NAT at all — the router simply
    /// answers for it, and the fabric learns where to send it from the
    /// announcement. Stateless, so every active router of the subnet may
    /// announce it and ECMP is the fabric's business.
    #[serde(default)]
    pub routed_subnets: Vec<String>,
    /// Whether this node is the one that answers for the router right now.
    ///
    /// `false` is fully built and silent: the namespace, both legs, the
    /// addresses and every rule are there, and the router answers no ARP and
    /// is announced nowhere. That is what makes a failover a `true` on the
    /// standby and nothing else — Festlegung 7.
    pub active: bool,
}

/// What a router IS, as the driver finds it.
///
/// The same rule `VmStatusReport` follows: what is, not what was asked. It is
/// what the status report carries upwards and what the announcement pass
/// reads, which is why `announce` is on it — WHICH prefixes a router asks the
/// world for is the driver's answer, not something the agent recomputes from
/// a spec it would have to keep.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RouterState {
    pub id: RouterId,
    /// Where this driver put it, in whatever a driver's own terms are — a
    /// network namespace here, a logical router elsewhere. For the operator
    /// and for the log line; nothing branches on it.
    pub location: String,
    pub phase: RouterPhase,
    pub message: String,
    pub active: bool,
    /// The prefixes to announce while this router is active, already in
    /// `a.b.c.d/len` form. Empty on a standby, which IS the withdraw.
    pub announce: Vec<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RouterPhase {
    /// Built, and everything the spec asked for is there.
    Ready,
    /// Something the spec asked for is not there. `message` says what.
    Failed,
}

impl RouterPhase {
    pub const ALL: [RouterPhase; 2] = [RouterPhase::Ready, RouterPhase::Failed];

    /// The wire spelling of `RouterReport.phase`.
    pub fn as_str(self) -> &'static str {
        match self {
            RouterPhase::Ready => "Ready",
            RouterPhase::Failed => "Failed",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|p| p.as_str() == s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A driver that implements nothing but the two mandatory halves. It is
    /// the compatibility case in one type: everything the gateway slot adds
    /// has a default, so a driver written before 6k — or a second backend
    /// that only does taps — still compiles and still says what it cannot do.
    struct NoGatewaySlot;

    #[async_trait::async_trait]
    impl NicDriver for NoGatewaySlot {
        async fn create(&self, _id: &NicId, _spec: &NicSpec) -> Result<Nic> {
            unreachable!("this fixture is about the bridge half")
        }
        async fn destroy(&self, _id: &NicId) -> Result<()> {
            unreachable!("this fixture is about the bridge half")
        }
        async fn get(&self, _id: &NicId) -> Result<Nic> {
            unreachable!("this fixture is about the bridge half")
        }
    }

    #[async_trait::async_trait]
    impl BridgeDriver for NoGatewaySlot {
        async fn ensure(&self, _name: &str) -> Result<()> {
            Ok(())
        }
        async fn ensure_address(
            &self,
            _name: &str,
            _addr: std::net::IpAddr,
            _prefix_len: u8,
        ) -> Result<()> {
            Ok(())
        }
        async fn destroy(&self, _name: &str) -> Result<()> {
            Ok(())
        }
    }

    fn spec(id: RouterId) -> RouterSpec {
        RouterSpec {
            id,
            physnet: "ext".into(),
            external_addr: "203.0.113.10/24".into(),
            external_gateway: "203.0.113.1".into(),
            vxlan_id: 10_000,
            internal_addr: "10.7.1.1/24".into(),
            nats: Vec::new(),
            routed_subnets: Vec::new(),
            active: true,
        }
    }

    /// The default is a refusal IN WORDS and never a success that built
    /// nothing. A driver that answered `Ok` here would give the tier above a
    /// router it can schedule on to and a node that has none.
    #[tokio::test]
    async fn a_driver_without_a_gateway_slot_says_so_instead_of_pretending() {
        let d = NoGatewaySlot;
        let id = RouterId::from_u128(1);
        assert!(d.physnets().is_empty());

        let err = d
            .ensure_physnet("ext", "eth1")
            .await
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("no gateway slot") && err.contains("ext"),
            "{err}"
        );

        let err = d.ensure_router(&spec(id)).await.unwrap_err().to_string();
        assert!(
            err.contains("no gateway slot") && err.contains(&id.to_string()),
            "{err}"
        );

        let err = d.router_status(&id).await.unwrap_err().to_string();
        assert!(err.contains(&id.to_string()), "{err}");

        assert!(d.list_routers().await.unwrap().is_empty());
        assert!(d.sweep_routers().await.unwrap().is_empty());
    }

    /// The one default that is NOT a refusal, and the reason is
    /// `destroy_overlay`'s: a teardown of something that was never built has
    /// already happened, and refusing it would leave the tier above retrying
    /// a removal for ever.
    #[tokio::test]
    async fn letting_go_of_a_router_that_was_never_built_is_done_and_not_refused() {
        assert!(
            NoGatewaySlot
                .destroy_router(&RouterId::from_u128(1))
                .await
                .is_ok()
        );
    }

    /// Both NAT kinds round-trip through the one spelling the session, OVN's
    /// northbound and this driver seam share — and nothing else parses, so a
    /// rule this build cannot render is a refusal rather than a rule quietly
    /// left out of the ruleset.
    #[test]
    fn a_nat_kind_round_trips_through_ovns_own_spelling() {
        for kind in NatKind::ALL {
            assert_eq!(NatKind::parse(kind.as_str()), Some(kind));
        }
        assert_eq!(NatKind::Snat.as_str(), "snat");
        assert_eq!(NatKind::DnatAndSnat.as_str(), "dnat_and_snat");
        assert_eq!(NatKind::parse("dnat-and-snat"), None);
        assert_eq!(NatKind::parse("masquerade"), None);
        assert_eq!(NatKind::parse(""), None);
        // serde spells it the way the wire does, so a rule can stand in a
        // record and in a proto string without two conversions to disagree.
        assert_eq!(
            serde_json::to_string(&NatKind::DnatAndSnat).unwrap(),
            "\"dnat_and_snat\""
        );
    }

    /// The phase a `RouterReport` carries, in the spelling `VmStatusReport`
    /// uses for its own.
    #[test]
    fn a_router_phase_round_trips_through_its_wire_spelling() {
        for phase in RouterPhase::ALL {
            assert_eq!(RouterPhase::parse(phase.as_str()), Some(phase));
        }
        assert_eq!(RouterPhase::Ready.as_str(), "Ready");
        assert_eq!(RouterPhase::parse("ready"), None);
    }
}
