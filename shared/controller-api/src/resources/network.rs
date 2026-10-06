// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Provider networks and tenant routers. A provider maps a physical network
//! name to node uplinks; a router connects that network to a tenant overlay.
//! Gateway candidates have explicit priority, and NAT rules are explicit.

use super::*;

/// Provider network identified by a physnet name. Each node maps that name to a dedicated
/// interface without host IP addresses; management uses another interface or network. The
/// resource does not impose identical interface names across nodes.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProviderNetworkSpec {
    /// The name a gateway node claims this network under —  the `ext` of
    /// `gateway:ext` in its Hello. The join between an object here and an
    /// interface out there, and the only string the two sides have to agree
    /// on.
    pub physnet: String,
    /// The subnet on the wire, CIDR. What a router's external leg is a member
    /// of, and what says whether the gateway below is reachable from it at
    /// all.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub cidr: String,
    /// The next hop out there — the default route a router on this network
    /// takes. Empty is legal and means "no default route": a routed-subnet
    /// deployment where the fabric knows where the prefixes are and nothing
    /// needs a default at all.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub gateway: String,
    /// Router external-address allocation ranges, expressed as CIDRs, individual IPv4
    /// addresses, or a-b ranges. They restrict the allocatable subset independently of the
    /// provider network's reachability CIDR.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allocation: Vec<String>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub description: String,
}

/// Empty, and honestly so — the same answer `FloatingPoolStatus` gives. How
/// many addresses are left is a question about the routers, which are their
/// own objects and are counted when asked; a number cached here would be
/// wrong after every create.
#[derive(Clone, Debug, Default, Serialize, Deserialize, JsonSchema)]
pub struct ProviderNetworkStatus {}

/// No finalizer: a provider network owns nothing. What keeps it from
/// vanishing under a router is the delete handler's refusal, exactly as a
/// floating pool with reservations in it cannot be deleted.
pub type ProviderNetwork = Object<ProviderNetworkSpec, ProviderNetworkStatus>;

/// Explicit router rule kinds, shared with the wire contract. `snat` and
/// `dnat_and_snat` describe translations. `routed` carries an announced prefix
/// in logicalIp with no externalIp and produces no translation rule.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum NatKind {
    /// A whole subnet behind the router's own external address. `logicalIp`
    /// is the tenant's inside prefix; the reply is matched by conntrack.
    Snat,
    /// One address, one guest, both ways — a floating IP as OVN spells it.
    /// `externalIp` is the public address and `logicalIp` the guest's inside
    /// address.
    DnatAndSnat,
    /// Announced, not translated: `logicalIp` is a routed subnet's prefix and
    /// `externalIp` is empty. The active router says where the prefix is and
    /// touches no packet of it.
    ///
    /// The second half of decision 5, and the half it is easiest to get wrong
    /// by being helpful: a routed subnet's addresses are the addresses,
    /// inside and out, and a masquerade in the middle would hide the tenant
    /// from the fabric that was told to route to it.
    Routed,
}

impl NatKind {
    pub const ALL: [NatKind; 3] = [NatKind::Snat, NatKind::DnatAndSnat, NatKind::Routed];

    /// The spelling on the wire and in the object — `proto::NatRule.kind`.
    pub fn as_str(self) -> &'static str {
        match self {
            NatKind::Snat => "snat",
            NatKind::DnatAndSnat => "dnat_and_snat",
            NatKind::Routed => "routed",
        }
    }

    /// The inverse, total. `None` for a word this tier does not have, which
    /// is a refusal and not a default: a rule whose kind nobody understood
    /// must not quietly become a masquerade.
    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|k| k.as_str() == s)
    }
}

/// One translation the router performs, as an operator reads it and as the
/// node is told it.
///
/// The same three fields `proto::NatRule` has, and deliberately so: this is
/// the object form of that message and the conversion is field-for-field.
/// A shape of its own here rather than the protobuf type because a stored
/// object needs serde and a schema, and because the controller tiers do not
/// depend on the wire types for anything they persist.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NatRule {
    pub kind: NatKind,
    /// The address on the provider side. The router's own external address
    /// for a `snat` rule, the floating address for a `dnat_and_snat` one.
    pub external_ip: String,
    /// The address on the tenant side: a prefix for `snat`, one guest
    /// address for `dnat_and_snat`.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub logical_ip: String,
}

/// The scheduler class a router asks for when its spec names none.
///
/// Decision 6 in one word: a node may say it takes only certain classes
/// (`NodeSpec.accepts`), and a workload says which class it is. This is the
/// default for a router and [`CLASS_VM`] is the default for a VM, so an
/// operator who wants a machine to carry routers and nothing else writes
/// `accepts = ["router"]` and has said the whole thing.
pub const CLASS_ROUTER: &str = "router";

/// The scheduler class a VM asks for when its spec names none. See
/// [`CLASS_ROUTER`].
pub const CLASS_VM: &str = "vm";

/// An empty accepts list allows every workload class. A nonempty list is an explicit allowlist,
/// preserving compatibility for older unrestricted nodes.
pub fn accepts_class(accepts: &[String], class: &str) -> bool {
    accepts.is_empty() || accepts.iter().any(|a| a == class)
}

/// Classes accepted by usable nodes in a cluster. Any usable node with an
/// empty list makes the cluster unrestricted. Unready, drained or unhealthy
/// nodes do not broaden acceptance. An empty fleet returns an empty list;
/// node-level placement remains the final eligibility check.
pub fn cluster_accepts(nodes: &[crate::NodeSummary]) -> Vec<String> {
    let usable: Vec<&crate::NodeSummary> = nodes.iter().filter(|n| n.usable()).collect();
    if usable.is_empty() || usable.iter().any(|n| n.accepts.is_empty()) {
        return Vec::new();
    }
    let mut classes: Vec<String> = usable
        .iter()
        .flat_map(|n| n.accepts.iter().cloned())
        .collect();
    classes.sort();
    classes.dedup();
    classes
}

/// A tenant's way out: one leg on a provider network, one on its overlay,
/// and the translations between them.
///
/// A cloud object per decision 4 — **routers are cloud objects, placement is
/// the cluster's business**. What a tenant asks for is "a way out over this
/// provider network"; which cluster serves it and which of that cluster's
/// gateway-capable machines holds it are answers, not requests, and they are
/// therefore in the status and not here.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RouterSpec {
    /// Whose way out this is. Never empty on a STORED object, but defaulted
    /// on the way in for the reason `FloatingIpSpec.tenant` is: the server
    /// fills in the caller's own, and a required field here would make a
    /// self-service request a deserialization error rather than a refusal
    /// with a sentence.
    #[serde(default)]
    pub tenant: String,
    /// Which provider network it goes out over, by name.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub provider_network: String,
    /// The scheduler class this router asks for.
    ///
    /// Empty is the ordinary case and it means [`CLASS_ROUTER`] — read
    /// through [`RouterSpec::class`], never off the field. The same
    /// empty-is-the-default shape `VmSpec.class` has, and it is what keeps
    /// the two readable as one rule: a workload that said nothing about its
    /// class is of its kind's own class, and a workload that said something
    /// is of that.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub class: String,
    /// Masquerade the tenant overlay behind the router's external address. Defaults to true in
    /// both serde and Rust Default. Disable for routed subnets whose original source addresses
    /// must remain visible.
    #[serde(default = "snat_default")]
    pub snat: bool,
    /// Tenant VNI resolved by the cloud or supplied to a standalone cluster. The node needs the
    /// numeric overlay identity; a missing overlay leg is refused.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vni: Option<u32>,
    /// Router gateway address on the tenant overlay, as a CIDR. The operator supplies it
    /// because this stack has no tenant-overlay IPAM or DHCP. Its prefix also defines
    /// whole-subnet SNAT; an empty value is refused by the node.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub internal_addr: String,
    /// RoutedSubnet resources this router announces without NAT. Explicit selection allows
    /// different provider networks to advertise different tenant prefixes. Multiple active
    /// routers may advertise them; ECMP behavior belongs to the fabric.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub routed_subnets: Vec<String>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub description: String,
}

fn snat_default() -> bool {
    true
}

impl Default for RouterSpec {
    fn default() -> Self {
        Self {
            tenant: String::new(),
            provider_network: String::new(),
            class: String::new(),
            snat: snat_default(),
            vni: None,
            internal_addr: String::new(),
            routed_subnets: Vec::new(),
            description: String::new(),
        }
    }
}

impl RouterSpec {
    /// The class this router really asks for: what it says, or
    /// [`CLASS_ROUTER`] if it says nothing. The one place the default is
    /// applied, so that a stored object goes on recording what was asked for
    /// and every reader gets the same answer.
    pub fn class(&self) -> &str {
        if self.class.is_empty() {
            CLASS_ROUTER
        } else {
            &self.class
        }
    }
}

reasons! {
    /// Router reasons combine placement, dispatch, refusal, and holder-silence decisions with
    /// network-driver reasons from proto::reasons::ROUTER.
    RouterReason [9] {
        /// Nobody recorded one — see `VmReason::Unrecorded`.
        #[default]
        Unrecorded => "Unrecorded",
        /// No pass has looked at it yet — the moment between the create and
        /// the first reconcile, and the reason a fresh router no longer reads
        /// `Pending` with nothing beside it. Written by
        /// [`settle_router`] and by nobody else, which is where the state
        /// exists.
        ///
        /// Spelled as the image's, the pool's and the copy's are, so that
        /// "nobody has said anything yet" is one word across this crate.
        AwaitingNode => "AwaitingNode",
        /// Nowhere to put it: no gateway-capable node for this provider
        /// network, or every candidate is down, drained or refuses the class.
        /// The sentence says which.
        Unplaced => "Unplaced",
        /// A cluster or a node has been told; nobody has reported it yet.
        Dispatched => "Dispatched",
        /// A node refused it — no gateway slot, which is a structural answer
        /// about the MACHINE and is remembered in `status.refused`.
        Refused => "Refused",
        /// Nobody has heard from the node holding it for longer than the
        /// heartbeat allows. Spelled as `VmReason::Silent` is, because it is
        /// the same silence about the same machine.
        Silent => "Silent",

        // ------------------------------------------------------------------
        // The node's own words: `proto::reasons::ROUTER`, off
        // `RouterReport.reason`.
        // ------------------------------------------------------------------

        /// The network namespace this router lives in is gone from the node.
        NetnsGone => "NetnsGone",
        /// The namespace is there and a leg of it is not — the uplink, the
        /// tenant side, or both. The sentence says which.
        LegGone => "LegGone",
        /// The node could not FIND OUT: its `ip` call failed. Its own word
        /// because a tier that read it as "the namespace is gone" would swing
        /// a router away from a machine whose kernel merely did not answer in
        /// time — which is a working gateway taken out of service by a
        /// timeout.
        DriverUnreachable => "DriverUnreachable",
    }
}

phases! {
    /// How far along a router is — the same vocabulary a VM's phase has, one
    /// object over, and with the same rule: what IS, not what was asked.
    RouterPhase / RouterPhaseKind / RouterReason / RouterPhaseWire / RouterReported [6] {
        /// Nowhere to put it yet: no cluster has a gateway-capable node for this
        /// provider network, or every candidate is down, drained or refuses the
        /// class. The message says which of those it is.
        Pending { reason, message, since } => "Pending",
        /// Placed, and the nodes have been told. Nobody has reported it active
        /// yet.
        Provisioning { reason, message, since } => "Provisioning",
        /// A node reports it built and active. Packets go.
        Active { message, since } => "Active",
        /// Built but deliberately inactive router, including standby nodes awaiting safe
        /// activation. This is a resting phase without a reason category; activeNode identifies
        /// the forwarding node.
        Standby { message, since } => "Standby",
        /// A node refused it, or reports it broken. The sentence is the node's.
        Failed { reason, message, since } => "Failed",
        /// Nobody has heard from the node holding it for longer than the
        /// heartbeat allows. Exactly `VmPhaseKind::Unknown` and for exactly its
        /// reason: nothing went wrong that anybody can point at, and what is true
        /// is only that the control plane has stopped knowing.
        Unknown { reason, message, since } => "Unknown",
    }
}

impl RouterPhaseKind {
    /// Active and Standby are resting states. Failed and Unknown can still recover and remain
    /// eligible for stalled-progress diagnostics.
    pub fn is_terminal(self) -> bool {
        matches!(self, RouterPhaseKind::Active | RouterPhaseKind::Standby)
    }
}

/// Where the router ended up and what it is doing — all of it evidence, none
/// of it a request.
#[derive(Clone, Debug, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct RouterStatus {
    /// The phase, with the reason it is that phase and since when.
    ///
    /// Flat on the wire — `phase`, `reason`, `message`, `since` as siblings
    /// right here — so every client that reads `status.phase` as a string
    /// goes on reading it as a string. See `resources::phase`.
    #[serde(flatten)]
    pub(super) phase: RouterPhase,
    /// Router evidence from cluster realization or mirrored cluster reports. Controller-only
    /// conclusions have an empty node and cannot establish Active or Standby. None precedes the
    /// first pass.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reported: Option<RouterReported>,
    /// The address this router answers for on the provider network, CIDR.
    /// Cut from `ProviderNetwork.spec.allocation` when the router is first
    /// placed and kept for its life: it is what the SNAT rules translate to
    /// and what the fabric learns, so a router that changed it under its own
    /// conntrack would drop every established flow.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub external_addr: String,
    /// The cluster serving it, empty until one does.
    ///
    /// In the status and not the spec, which is where a VM's binding lives —
    /// and the difference is the point. A VM's `spec.clusterName` is a
    /// binding a client may take back to force a reschedule; a router is
    /// placed where the gateway hardware is, and there is nothing for a
    /// client to decide.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub cluster: String,
    /// The gateway-capable nodes this router is built on, best first —
    /// OVN's `gateway_chassis` list, priority given by position.
    ///
    /// Every node in it holds the whole router: the netns, both legs, the
    /// rules. What the standby does not do is answer for the addresses (no
    /// announcement, no ARP), which is decision 7: **HA over BGP withdraw**.
    /// A failover is therefore not a build — it is one node starting to speak
    /// and the other having stopped.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub nodes: Vec<String>,
    /// The one of `nodes` that is active: the first live one. Empty while
    /// none is.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub active_node: String,
    /// The rules this router really carries, derived from the tenant's
    /// floating addresses and this router's own `snat`.
    ///
    /// On the object because they are what an operator has to be able to read
    /// when an address does not work — the intent (`snat`, a `FloatingIp`
    /// pointing here) and the ruleset at the node are otherwise separated by
    /// a derivation nobody can see. Server-written, every pass, from the
    /// objects as they stand.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub nats: Vec<NatRule>,
    /// Nodes that structurally refused EnsureRouter despite their capability
    /// claim. The planner skips them until the router spec changes or a new
    /// node session supplies fresh capability evidence. Transient silence is
    /// not cached as a structural refusal.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub refused: Vec<String>,
    /// Former holders still owed router cleanup. Preserve unreachable nodes
    /// here after removing them from placement, so reconnection can trigger
    /// DestroyRouter. Remove the entry after acknowledgement, or when the node
    /// becomes a planned holder again.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub releasing: Vec<String>,
    /// The prefixes this router announces, resolved from
    /// `spec.routedSubnets` — the CIDRs themselves and not the object names.
    ///
    /// Derived rather than asked for, so an operator can see what a name
    /// really meant, and readable in one place rather than only as the
    /// `routed` entries of `nats` it also becomes. `proto::EnsureRouter` has
    /// no field of its own for the announcement, so the prefixes travel as
    /// [`NatKind::Routed`] rules — see that variant for why.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub announced: Vec<String>,
    /// The last `metadata.generation` this router was carried down on — the
    /// same pair every other spec-driven object here carries. `0` on one
    /// nothing has been dispatched for yet.
    #[serde(default)]
    pub observed_generation: u64,
}

pub type Router = Object<RouterSpec, RouterStatus>;

/// Derive router phase from recorded evidence at either tier. Active and Standby require an
/// identified machine; missing evidence becomes Pending/AwaitingNode. Preserve since while the
/// reported state is unchanged.
pub fn settle_router(status: &RouterStatus) -> RouterPhase {
    match status.reported.as_ref().and_then(RouterReported::phase) {
        Some(phase) => phase,
        None => RouterPhase::new(
            RouterPhaseKind::Pending,
            RouterReason::AwaitingNode,
            Some("no pass has placed it yet".to_string()),
            UNSTAMPED,
        ),
    }
}

#[cfg(test)]
mod router_tests {
    use super::*;

    fn at(secs: i64) -> DateTime<Utc> {
        DateTime::from_timestamp(1_800_000_000 + secs, 0).expect("an instant")
    }

    fn router() -> Router {
        Router::declare("acme-out", RouterSpec::default())
    }

    /// The table: what the pass that looked last found, and what the router
    /// therefore IS.
    #[test]
    fn a_router_is_the_last_word_anybody_established_about_it() {
        let mut fresh = router();
        fresh.settle(at(0));
        assert_eq!(fresh.status.phase().kind(), RouterPhaseKind::Pending);
        assert_eq!(
            fresh.status.phase().reason(),
            Some(RouterReason::AwaitingNode),
            "a router nobody has planned says so instead of nothing"
        );

        let cases: &[(RouterReported, RouterPhaseKind, RouterReason)] = &[
            (
                RouterReported::here(
                    RouterPhaseKind::Pending,
                    RouterReason::Unplaced,
                    Some("no gateway-capable node for physnet0".into()),
                    at(0),
                ),
                RouterPhaseKind::Pending,
                RouterReason::Unplaced,
            ),
            (
                RouterReported::here(
                    RouterPhaseKind::Provisioning,
                    RouterReason::Dispatched,
                    Some("cluster-1 was told".into()),
                    at(0),
                ),
                RouterPhaseKind::Provisioning,
                RouterReason::Dispatched,
            ),
            (
                // The node's own driver word, the one `DriverUnreachable`
                // earns its place for: this says the machine could not find
                // out, not that the namespace is gone.
                RouterReported::by(
                    "agent-1b",
                    RouterPhaseKind::Failed,
                    RouterReason::DriverUnreachable,
                    Some("ip did not answer".into()),
                    at(0),
                ),
                RouterPhaseKind::Failed,
                RouterReason::DriverUnreachable,
            ),
            (
                RouterReported::here(
                    RouterPhaseKind::Unknown,
                    RouterReason::Silent,
                    Some("agent-1b last reported 2026-09-15T16:42:25Z".into()),
                    at(0),
                ),
                RouterPhaseKind::Unknown,
                RouterReason::Silent,
            ),
        ];
        for (word, kind, reason) in cases {
            let mut r = router();
            r.status.reported = Some(word.clone());
            r.settle(at(0));
            assert_eq!(r.status.phase().kind(), *kind, "{word:?}");
            assert_eq!(
                r.status.phase().reason().unwrap_or_default(),
                *reason,
                "{word:?}"
            );
        }
    }

    /// `Active` and `Standby` demand a machine. Both claim that a namespace
    /// exists somewhere and is either forwarding or deliberately silent, and
    /// no tier may claim that on its own behalf — so a word with no speaker
    /// is not one, and the router falls back to the wait.
    #[test]
    fn nothing_is_active_unless_a_machine_is_named() {
        for resting in [RouterPhaseKind::Active, RouterPhaseKind::Standby] {
            let mut invented = router();
            invented.status.reported = Some(RouterReported::here(
                resting,
                RouterReason::Unrecorded,
                None,
                at(0),
            ));
            invented.settle(at(0));
            assert_eq!(
                invented.status.phase().kind(),
                RouterPhaseKind::Pending,
                "{resting:?} with nobody behind it"
            );

            let mut real = router();
            real.status.reported = Some(RouterReported::by(
                "agent-1a",
                resting,
                RouterReason::Unrecorded,
                None,
                at(0),
            ));
            real.settle(at(0));
            assert_eq!(real.status.phase().kind(), resting);
        }
    }
}
