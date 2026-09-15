// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! The north-south kinds: `ProviderNetwork` — the wire a cluster gave away —
//! and `Router`, a tenant's way out over it.
//!
//! Everything else in this tree describes the inside of a tenant: an overlay
//! it is alone on, addresses it may source from, disks it owns. None of it
//! says how a packet leaves. Until 6k it did not have to be said, because
//! nothing carried one: a floating address lived IN the guest, the node
//! announced a /32 for it, and a tenant with private space behind no
//! appliance had no egress at all.
//!
//! The shape is OVN's, deliberately and from the first line, because the
//! alternative is a model that has to be replaced rather than translated the
//! day a real SDN is under it. `ProviderNetwork` is OVN's localnet — a
//! physical network named by a `physnet` that a chassis maps to an interface.
//! `Router` is a logical router with one leg on that localnet and one on the
//! tenant's logical switch, and its placement is `gateway_chassis`: a list of
//! candidates with a priority, of which the first live one is active. The NAT
//! is OVN's two kinds, spelled OVN's way and neither implied nor derived.
//! What is not here yet — ACLs on port groups, a `Port` object of its own —
//! is absent rather than approximated.

use super::*;

/// A physical network the operator handed over, by the name a node knows it
/// under.
///
/// The first of Silas' seven decisions is what this object records: **every
/// cluster gives at least one interface away, without an address on it**. The
/// interface belongs to the provider bridge on the node; the host holds no
/// address there, no tap hangs off it directly, and management runs wherever
/// the operator wants it to. So this object never names an interface — it
/// names a `physnet`, and which interface that is on a given machine is that
/// machine's own configuration (`[network.provider] physnets = { ext =
/// "eth1" }`). Two nodes may reach the same wire through differently named
/// NICs and be the same provider network, which is exactly what a physnet is
/// for and exactly what a field called `interface` here would have destroyed.
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
    /// Where a router's own external address is cut from, in the spelling
    /// `FloatingPoolSpec.cidrs` uses: a CIDR, a single address or an `a-b`
    /// range per entry, parsed by `common::net::Ipv4Ranges`.
    ///
    /// Its own range rather than "anything inside `cidr`", because the two
    /// are different facts. `cidr` is what the wire IS — it decides
    /// reachability and it is usually somebody else's to declare — and this
    /// is the slice of it this control plane may hand out. An operator who
    /// gave us `198.51.100.0/24` and kept `.1` to `.99` for their own
    /// hardware says so here and nowhere else.
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

/// What one entry of a router's rule list says.
///
/// The whole of decision 5: **NAT as explicit rules**. A router does not
/// "have NAT on"; it carries a list, every entry of which says what is
/// translated to what, and the list is readable on the object. The
/// alternative — deriving the rules at the node from a bool and a subnet —
/// is what makes a floating address that does not work unanswerable, because
/// there is nothing to look at between the intent and the nftables ruleset.
///
/// Two of the three are OVN's, spelled OVN's way, underscore and all, and it
/// is the wire spelling too (`proto::NatRule.kind`): one string reaches from
/// `meister router get` through the session into the driver, so nothing on
/// the way has to translate and nothing on the way can translate wrongly.
///
/// The third is not a translation at all and rides in this list because the
/// contract has nowhere else for it. `proto::EnsureRouter` carries the
/// physnet, both addresses, the VNI, this list and the active bit — and no
/// field that says what to ANNOUNCE. So the routed subnets travel as
/// [`NatKind::Routed`] entries, which is what the agent side of 6k settled
/// on: a prefix in `logicalIp`, no `externalIp`, and no rule rendered for it.
/// A `NatRule` list that is really "what this router does with a prefix" is a
/// slightly wider noun than its name, and the alternative was a proto change
/// in a locked file.
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

/// Does a node that `accepts` these classes take a workload of this one?
///
/// **Empty accepts everything**, and that is what keeps this additive: every
/// node ever written carries no list, and a rule that read an empty list as
/// "nothing" would empty a fleet on upgrade. A node that names classes is
/// exclusive — Kubernetes' taint and toleration in one word, from the side
/// where an operator actually thinks about it ("this machine is for routers")
/// rather than from the side where the workload has to apologise for
/// existing.
pub fn accepts_class(accepts: &[String], class: &str) -> bool {
    accepts.is_empty() || accepts.iter().any(|a| a == class)
}

/// The same question about a whole FLEET: which classes a cluster takes, out
/// of what its machines take.
///
/// A cluster is not a machine, so its `accepts` is not a field somebody
/// writes — it is derived, and the derivation is the only one that keeps the
/// answer the same at both tiers: a cluster takes a class if one machine of
/// it that could actually run something takes that class. One machine with an
/// empty list makes the whole fleet open, because that machine takes anything
/// sent to it.
///
/// "Could actually run something" is the gate `NodeDemand::met_by_a_node`
/// uses, for its reason: a fleet whose only general-purpose machine is down,
/// drained or wedged is a fleet an ordinary VM should not be bound to, and
/// finding that out after the binding is what leaves a tenant reading Pending
/// at a tier that has nothing more to say.
///
/// Empty out of an empty fleet, which reads as "said nothing" — the same
/// thing an old cluster's report says, and the conservative answer: the
/// refusal is then made one tier down, exactly as it was before this field.
pub fn cluster_accepts(nodes: &[crate::NodeSummary]) -> Vec<String> {
    let usable: Vec<&crate::NodeSummary> = nodes
        .iter()
        .filter(|n| n.ready && n.schedulable && n.conditions.is_empty())
        .collect();
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
    /// Translate the tenant's whole overlay behind this router's external
    /// address.
    ///
    /// True by default, because it is what a tenant with private space wants
    /// and because the object would otherwise do nothing at all on the road
    /// everybody takes. False is the routed-subnet deployment: the prefixes
    /// are real, the fabric routes them, and a masquerade in the middle would
    /// be an active harm — it would hide the tenant's own addresses from the
    /// network that was told to route to them.
    ///
    /// The one field in this tree that defaults to TRUE, which is why
    /// `RouterSpec` writes its `Default` by hand rather than deriving it:
    /// a derived one would say `false` and disagree with serde about what a
    /// router with no opinion does.
    #[serde(default = "snat_default")]
    pub snat: bool,
    /// The tenant's overlay — the wire the router's inside leg lands on.
    ///
    /// Exactly the road `NewNic.vxlan_id` travels and for exactly its reason:
    /// the cloud resolves it out of the `Tenant` object at create, because
    /// that is where tenants live, and it is set by hand on a standalone
    /// cluster which has no `Tenant` to resolve. A number and not a tenant
    /// name, so that by the time this reaches a node it says plainly which
    /// wire it wants and no agent has to know what a tenant is.
    ///
    /// `None` is a router with no overlay leg, which the node refuses.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vni: Option<u32>,
    /// The address this router holds on the tenant's overlay, CIDR — the
    /// default gateway its guests point at.
    ///
    /// **Asked for and not derived, because there is no IPAM for a tenant
    /// overlay in this stack.** A tenant's logical switch is `Tenant.vni` and
    /// nothing else: there is no `Subnet` object, no DHCP served by the
    /// control plane and no agent inside a guest, so what addressing a tenant
    /// runs on its own wire is known to that tenant and to nobody here. The
    /// honest shape is therefore a field somebody fills in — `10.42.0.1/24`
    /// beside guests on `10.42.0.0/24` — rather than a number this tier
    /// invents and half the guests then cannot reach.
    ///
    /// It is also what the SNAT rule is about: `NatRule` with an empty
    /// `logicalIp` means "the whole internal subnet", and the subnet is the
    /// prefix of this address. Empty here is a router with no overlay leg,
    /// which the node refuses — see `proto::EnsureRouter.internal_addr`.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub internal_addr: String,
    /// The `RoutedSubnet` objects this router announces, by name.
    ///
    /// Announced and NOT translated: decision 5's second half. A routed
    /// subnet's addresses are the addresses, inside and out, so the router's
    /// job for one is to say where it is — every active router of that subnet
    /// says it, and whether the fabric turns that into ECMP is the fabric's
    /// business, which is why nothing here is stateful and nothing here has
    /// to be a single active hop.
    ///
    /// Named rather than derived from the tenant's subnets, because the two
    /// are different questions: a tenant may hold a subnet that it does not
    /// want announced from this provider network, and a tenant with two
    /// routers on two provider networks has to be able to say which announces
    /// what.
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
    /// Why a router is where it is.
    ///
    /// Six, all of them out of the two router reconcilers: the four
    /// `Pending` sentences the cluster planner returns (no provider network,
    /// no gateway node, every candidate down or drained, the class refused),
    /// the dispatch the cloud writes when it has told a cluster, the node's
    /// own word on the status road, and the silence `verdict` turns into
    /// `Unknown` when the node holding an active router stops answering.
    RouterReason [6] {
        /// Nobody recorded one — see `VmReason::Unrecorded`.
        #[default]
        Unrecorded => "Unrecorded",
        /// Nowhere to put it: no gateway-capable node for this provider
        /// network, or every candidate is down, drained or refuses the class.
        /// The sentence says which.
        Unplaced => "Unplaced",
        /// A cluster or a node has been told; nobody has reported it yet.
        Dispatched => "Dispatched",
        /// A node refused it — no gateway slot, which is a structural answer
        /// about the MACHINE and is remembered in `status.refused`.
        Refused => "Refused",
        /// A node's own word about the namespace, verbatim in the message.
        Reported => "Reported",
        /// Nobody has heard from the node holding it for longer than the
        /// heartbeat allows. Spelled as `VmReason::Silent` is, because it is
        /// the same silence about the same machine.
        Silent => "Silent",
    }
}

phases! {
    /// How far along a router is — the same vocabulary a VM's phase has, one
    /// object over, and with the same rule: what IS, not what was asked.
    RouterPhase / RouterPhaseKind / RouterReason / RouterPhaseWire [6] {
        /// Nowhere to put it yet: no cluster has a gateway-capable node for this
        /// provider network, or every candidate is down, drained or refuses the
        /// class. The message says which of those it is.
        Pending { reason, message, since } => "Pending",
        /// Placed, and the nodes have been told. Nobody has reported it active
        /// yet.
        Provisioning { reason, message, since } => "Provisioning",
        /// A node reports it built and active. Packets go.
        Active { message, since } => "Active",
        /// A node reports it built and NOT active — every standby says this, and
        /// so does a router whose whole priority list is standby because the
        /// active node has gone quiet without letting go.
        ///
        /// Its own phase rather than `Provisioning`, because the two send an
        /// operator to different places: `Provisioning` is "wait", this is "the
        /// thing exists on a machine and is deliberately silent".
        ///
        /// No reason slot, and that is the judgement rather than an omission:
        /// a standby is a RESTING state — the router is built and doing
        /// exactly what it was asked to do — so there is no category behind
        /// it. Which node speaks is `status.activeNode`.
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
    /// The nodes that answered `EnsureRouter` with "no gateway slot" — a
    /// structural refusal about the MACHINE and not about the router.
    ///
    /// Remembered rather than re-asked, because a node whose claim and whose
    /// answer disagree will disagree again on the next pass, and a planner
    /// that put it back every five seconds would be a loop that fills a log
    /// and never converges. The planner skips whatever is named here.
    ///
    /// Cleared in two moments, and both are somebody saying something new:
    /// the router's `spec` changes, or the node opens a NEW SESSION.
    ///
    /// The second was missing and it was the expensive half. A Hello is not
    /// a heartbeat and not a report — it is the agent stating its whole
    /// catalogue at the start of a session, `gateway:<physnet>` among it — so
    /// a refusal recorded against the process that has just been replaced is
    /// evidence about something that no longer exists. Without it a machine
    /// whose provider bridge had been repaired stayed off every priority list
    /// until an operator noticed and patched an unrelated object. The cost of
    /// being wrong is one `EnsureRouter` that is refused again and written
    /// down again.
    ///
    /// A node-level `Condition` would be the other place for it and is the
    /// wrong one: `NodeStatus.conditions` is what the NODE says about itself
    /// and is replaced wholesale by every status report, so a word written
    /// there by a controller lives ten seconds.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub refused: Vec<String>,
    /// The nodes that still have to be told to let this router go, and could
    /// not be told yet.
    ///
    /// A machine that drops off `nodes` while it is DOWN cannot be told
    /// anything, and it also stops being on `nodes` — so the next pass derives
    /// the release list out of the list it has just shortened and the machine
    /// is never told at all. It comes back holding a whole namespace that
    /// answers for an address another node is now carrying. Seen on manacor on
    /// 2026-09-10: a `DestroyRouter` went to a node that was already down, and
    /// its start-up sweep kept every namespace whose record was still beside
    /// it — `run_dir` is a tmpfs, so a REBOOT would have taken it, but a
    /// restart of the agent does not.
    ///
    /// So it is remembered instead, and the debt is paid the first pass the
    /// machine is reachable again. Level-triggered in both directions: a node
    /// that is planned onto this router again leaves the list without a
    /// command, and a destroy that is acknowledged leaves it because it is
    /// done.
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
