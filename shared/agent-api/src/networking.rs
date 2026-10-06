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

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct NicSpec {
    pub bridge: String,
    pub mac: MacAddr,
    /// Controller-resolved tenant VNI. None selects the default bridge.
    /// The agent does not resolve tenant names.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vxlan_id: Option<u32>,
    /// Controller-resolved floating addresses permitted by the tap guard.
    /// Defaults to no exceptions within configured guarded ranges.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub floating_ips: Vec<String>,
    /// The prefixes the guest may send from, as the controller sends them: its
    /// tenant's routed subnets and the prefixes of its tenant's network. The
    /// name is the one the field had before the network's prefixes went into
    /// it. Nonempty puts the tap's IPv4 sources on an allowlist of these, the
    /// floating addresses and the unspecified address. Empty says the
    /// controller knows no address space for the NIC (a tenant that declares
    /// no network prefix and has no router and no routed subnet, a VM of no
    /// tenant, a standalone spec that names none): the tap is then kept off
    /// the node's guarded ranges, the cloud's floating and routed pools, where
    /// the node has them, and otherwise pinned by MAC only; a known limit
    /// until the stack hands out overlay addresses itself (IPAM).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub routed_subnets: Vec<String>,
    /// Provider physnet for a direct guest connection. Mutually exclusive
    /// with a tenant VNI; specifying both is rejected. None retains the
    /// overlay-or-default-bridge path.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub physnet: Option<String>,
}

impl NicSpec {
    /// Whether the tap guard holds this NIC's IPv4 sources to an allowlist of
    /// its routed subnets, its floating addresses and the unspecified address,
    /// rather than only banning the floating pool. A provider NIC is pinned by
    /// its MAC alone and never is.
    ///
    /// Read off this document and nothing else, so every node that builds the
    /// tap from the same document guards it the same: no node keeps a word of
    /// its own about a NIC's address space (NL5-2).
    pub fn sources_allowlisted(&self) -> bool {
        self.physnet.is_none() && !self.routed_subnets.is_empty()
    }
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct Nic {
    pub id: NicId,
    pub tap_name: String,
    /// MTU configured by the driver, absent when unspecified in current or legacy records.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mtu: Option<u32>,
    /// Guest MAC assigned by this driver, not the tap interface's own MAC.
    /// A liveness-only lookup or legacy record may return None; reports must
    /// not invent an address when it is unknown.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mac: Option<MacAddr>,
}

#[async_trait::async_trait]
pub trait NicDriver: Send + Sync {
    async fn create(&self, id: &NicId, spec: &NicSpec) -> Result<Nic>;
    async fn destroy(&self, id: &NicId) -> Result<()>;
    async fn get(&self, id: &NicId) -> Result<Nic>;

    /// Bring the source-address guard of the existing NIC `id` to `spec`: its wiring and MAC
    /// as created, its address lists as a re-sent create names them. The old rules give way
    /// to the new ones in one step, so no frame passes the tap between the two (NL4-1). Only
    /// the guard changes. `NicNotFound` when the tap is not there. No default: a driver that
    /// guards taps and kept the old lists would leave a guest sending from addresses taken
    /// away from it.
    async fn update_guard(&self, id: &NicId, spec: &NicSpec) -> Result<()>;

    /// Remove stale per-tap host state, such as nftables chains, using the
    /// agent's persisted live-tap inventory at startup. Default: no extra state.
    async fn reap(&self, _live_taps: &[String]) {}

    /// Bring the host side of links this driver made before, which guests still running
    /// across an agent restart keep using, to what it makes today; name the links changed.
    /// Called once at startup, before reconciliation. Default: nothing to bring up to date.
    async fn mend_existing_links(&self) -> Result<Vec<String>> {
        Ok(Vec::new())
    }
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

    /// Ensure the overlay bridge and encapsulation device for `vni`.
    /// Unsupported drivers must refuse rather than put a tenant NIC on the
    /// default bridge.
    async fn ensure_overlay(&self, vni: u32) -> Result<String> {
        Err(NetworkError::InvalidSpec(format!(
            "this node has no overlay networking configured, so it cannot serve vxlan {vni}"
        )))
    }

    /// Remove this driver's overlay bridge and encapsulation device.
    ///
    /// Call only after checking every VM and router reference under the agent
    /// lifecycle guard. Unreadable records cannot authorize removal. `bridge`
    /// is the recorded name returned by `ensure_overlay`; implementations must
    /// refuse a mismatched name rather than remove another driver's overlay.
    /// Missing overlays succeed. The default has nothing to remove.
    async fn destroy_overlay(&self, _vni: u32, _bridge: Option<&str>) -> Result<()> {
        Ok(())
    }

    /// Remove this driver's overlays absent from `keep` and return their VNIs.
    ///
    /// The caller must have a complete VM and router inventory and exclude
    /// concurrent provisioning. Unreadable records prevent the sweep. A driver
    /// that cannot identify its own overlays must remove nothing; the default
    /// does nothing.
    async fn sweep_overlays(&self, _keep: &[u32]) -> Result<Vec<String>> {
        Ok(Vec::new())
    }

    /// Ensure a provider bridge over a dedicated host interface. Refuse an
    /// interface with a host address. Called for configured physnets at startup;
    /// only successfully prepared physnets may be advertised as gateway capacity.
    async fn ensure_physnet(&self, name: &str, _interface: &str) -> Result<String> {
        Err(NetworkError::InvalidSpec(format!(
            "this node's network driver has no gateway slot, so it cannot serve the provider \
             network {name:?}"
        )))
    }

    /// Prepared provider physnets. These drive gateway capability reports
    /// and router-command admission; configuration alone is insufficient.
    fn physnets(&self) -> Vec<String> {
        Vec::new()
    }

    /// Create or reconcile a router to the supplied specification. Repeated
    /// requests are idempotent; changed fields update the existing router.
    async fn ensure_router(&self, spec: &RouterSpec) -> Result<RouterState> {
        Err(NetworkError::InvalidSpec(format!(
            "this node's network driver has no gateway slot, so it cannot build router {}",
            spec.id
        )))
    }

    /// Destroy router-owned resources idempotently. The default removes nothing.
    async fn destroy_router(&self, _id: &RouterId) -> Result<()> {
        Ok(())
    }

    /// Read observed router state; absent local routers return RouterNotFound.
    async fn router_status(&self, id: &RouterId) -> Result<RouterState> {
        Err(NetworkError::RouterNotFound(*id))
    }

    /// Every router this driver holds — the half of the status report that is
    /// about routers, and the set the announcement pass reads.
    async fn list_routers(&self) -> Result<Vec<RouterState>> {
        Ok(Vec::new())
    }

    /// Sweep unrecorded router resources once at startup, before commands.
    /// Router ownership comes from driver records, independently of VM
    /// references used for overlay cleanup.
    async fn sweep_routers(&self) -> Result<Vec<String>> {
        Ok(Vec::new())
    }

    /// Silence one router without destroying its namespace: it stops answering ARP and stops
    /// claiming to be active, so it announces nothing. Used ahead of a demotion, before the rest
    /// of the command is read, so a command this node refuses cannot leave the old router
    /// answering (NL2-2). An absent router is silent already; the default builds no router and
    /// has none to silence.
    async fn silence_router(&self, _id: &RouterId) -> Result<()> {
        Ok(())
    }

    /// Withdraw one router's sole-gateway claim (`RouterSpec::sole_gateway`) from what this node
    /// holds of it, without touching the router. Used ahead of a command that no longer makes
    /// the claim, before the rest of it is read, so a command this node refuses cannot leave the
    /// dead man keeping the router answering while another node claims its provider network
    /// (NL-A2). A router this node holds no record of makes no claim; the default builds no
    /// router and has no claim to withdraw.
    async fn withdraw_sole_gateway(&self, _id: &RouterId) -> Result<()> {
        Ok(())
    }

    /// Silence all local routers without destroying their namespaces. Used on
    /// shutdown and by the dead man to stop stale ARP and routing activity
    /// before another gateway takes over. A later `EnsureRouter` can reactivate
    /// the retained router. Best effort; the outcome names failed routers (R3-F06).
    /// An active router no other node can take over (`RouterSpec::sole_gateway`)
    /// keeps answering, and the outcome names it kept (IKR-B76).
    async fn fall_silent(&self) -> Result<Silencing> {
        Ok(Silencing::default())
    }
}

/// Per-router outcome of one silencing pass; lists, so a log names the router still answering.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Silencing {
    pub silenced: Vec<RouterId>,
    pub failed: Vec<RouterId>,
    /// Active routers left answering because no other node can be made active for them.
    pub kept: Vec<RouterId>,
}

impl Silencing {
    /// Every router this pass looked at is now silent, or was kept answering on purpose;
    /// vacuously true when there was none.
    pub fn complete(&self) -> bool {
        self.failed.is_empty()
    }
}

/// Combined NIC/bridge contract for one registered driver instance.
/// The agent upcasts the same shared instance for each capability.
pub trait NetworkDriver: NicDriver + BridgeDriver {}

impl<T: NicDriver + BridgeDriver + ?Sized> NetworkDriver for T {}

/// Publish the desired prefix set for this node. Callers submit a complete
/// set on each pass; implementations log failures and own reconciliation.
/// Repeated calls are required to converge, but do not establish success.
#[async_trait::async_trait]
pub trait RouteAnnouncer: Send + Sync {
    async fn announce(&self, prefixes: std::collections::BTreeSet<String>);
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct NicAttachment {
    pub tap_name: String,
    pub mac: MacAddr,
    /// Guest MTU advertised through virtio-net. Host link MTUs alone do not
    /// configure the guest. None leaves the guest setting unspecified.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mtu: Option<u32>,
}

// Router contracts connect a provider network to a tenant overlay.
// Implementations may use namespaces or another dataplane; unsupported
// operations must fail explicitly.

/// Tenant-router UID assigned by the control plane.
pub type RouterId = Uuid;

/// Supported NAT operations. Translation rejects unknown wire spellings
/// before the driver can omit an unsupported rule.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NatKind {
    /// Rewrite subnet source addresses through one external address.
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

    /// Parse a supported kind. Callers must reject unknown values instead of omitting the rule.
    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|k| k.as_str() == s)
    }
}

/// Router address translation using bare logical and external IPs. For SNAT,
/// an empty logical IP selects the router's internal subnet.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct NatRule {
    pub kind: NatKind,
    pub external_ip: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub logical_ip: String,
}

/// Driver-facing desired router state, translated from the controller command.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct RouterSpec {
    pub id: RouterId,
    /// Which of this node's provider networks the outside leg joins. A node
    /// that does not serve it is not a candidate — see [`BridgeDriver::physnets`].
    pub physnet: String,
    /// Provider-side router address as CIDR, used for SNAT and active-router reachability.
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
    /// Tenant prefixes routed and announced without NAT. Multiple active
    /// routers may advertise them when the fabric supports ECMP.
    #[serde(default)]
    pub routed_subnets: Vec<String>,
    /// Whether this router answers ARP and advertises routes. Inactive routers
    /// retain prepared namespaces, links, addresses and rules for activation.
    pub active: bool,
    /// No other node of the cluster claims this router's provider network, whether alive or
    /// not: none can be made active while this one is cut off from its controller, so the dead
    /// man keeps an active router answering instead of silencing it for nothing (IKR-B76).
    /// Absent in records and commands from before, which keeps the dead man silencing it.
    #[serde(default)]
    pub sole_gateway: bool,
}

/// Driver-observed router state used for reports and route announcements.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RouterState {
    pub id: RouterId,
    /// Where this driver put it, in whatever a driver's own terms are — a
    /// network namespace here, a logical router elsewhere. For the operator
    /// and for the log line; nothing branches on it.
    pub location: String,
    pub phase: RouterPhase,
    /// Machine-readable observed reason, separate from the operator message; None for Ready.
    pub reason: Option<RouterReason>,
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

/// Driver-reported router failure reason. In particular, distinguish an
/// absent namespace from an unsuccessful host probe.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RouterReason {
    /// The network namespace this node built for the router is not there.
    NetnsGone,
    /// Namespace exists but a required link is absent; message identifies it.
    LegGone,
    /// Host probing failed or a record will not parse (R3-F07); state unknown, not proven absent.
    DriverUnreachable,
}

impl RouterReason {
    /// Every variant, in declaration order — see `RouterPhase::ALL`.
    pub const ALL: [RouterReason; 3] = [
        RouterReason::NetnsGone,
        RouterReason::LegGone,
        RouterReason::DriverUnreachable,
    ];

    /// The wire spelling of `RouterReport.reason`.
    pub fn as_str(self) -> &'static str {
        match self {
            RouterReason::NetnsGone => "NetnsGone",
            RouterReason::LegGone => "LegGone",
            RouterReason::DriverUnreachable => "DriverUnreachable",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|r| r.as_str() == s)
    }
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

    /// Minimal network fixture exercising defaults for unsupported gateway operations.
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
        async fn update_guard(&self, _id: &NicId, _spec: &NicSpec) -> Result<()> {
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
            sole_gateway: false,
        }
    }

    /// Unsupported router creation must return an explanatory error.
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

    /// Default router destruction succeeds when the driver owns no router.
    #[tokio::test]
    async fn letting_go_of_a_router_that_was_never_built_is_done_and_not_refused() {
        assert!(
            NoGatewaySlot
                .destroy_router(&RouterId::from_u128(1))
                .await
                .is_ok()
        );
    }

    /// A driver that builds no router has none answering, so silencing one is done (NL2-2).
    #[tokio::test]
    async fn silencing_a_router_that_was_never_built_is_done_and_not_refused() {
        assert!(
            NoGatewaySlot
                .silence_router(&RouterId::from_u128(1))
                .await
                .is_ok()
        );
    }

    /// A driver that builds no router holds no sole-gateway claim, so withdrawing one is done
    /// (NL-A2).
    #[tokio::test]
    async fn withdrawing_the_claim_of_a_router_that_was_never_built_is_done() {
        assert!(
            NoGatewaySlot
                .withdraw_sole_gateway(&RouterId::from_u128(1))
                .await
                .is_ok()
        );
    }

    /// NAT kinds round-trip through their wire spellings; unknown kinds are rejected.
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
