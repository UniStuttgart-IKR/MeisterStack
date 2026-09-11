// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Planning a router and making it so: which machines may carry it, in what
//! order, what it translates — and the seam a second backend goes behind.
//!
//! The split here is the one `scheduler` makes and it is worth naming,
//! because the whole point of 6k's object model is that an OVN backend should
//! be a translator rather than a rewrite. Everything above [`NetworkBackend`]
//! is a DECISION and is backend-independent: which nodes claim the physnet,
//! which of them accepts the class, which is active, which address the router
//! holds, what the NAT rules are. Everything behind the trait is how that
//! decision is CARRIED OUT — for `meister`, an `EnsureRouter` down each
//! node's session; for an `ovn` backend that does not exist yet, a write into
//! the northbound database and no commands at all.
//!
//! A plugin trait with one implementation wired in by hand is not a seam, it
//! is a comment about one. So this resolves through the controller config
//! (`network = "meister"`) exactly as `scheduler = "first-fit"` does, and a
//! second backend is a new arm and a new line in a TOML file.

use std::collections::{BTreeMap, BTreeSet};
use std::net::Ipv4Addr;

use common::net::Ipv4Ranges;

use crate::resources::{
    FloatingIp, NatKind, NatRule, ProviderNetwork, Router, RouterPhase, accepts_class,
};
use crate::scheduler::{Candidate, is_alive};

/// How many machines one router is built on: the active one and one standby.
///
/// OVN allows up to five `gateway_chassis` per logical router port and two is
/// what deployments actually run, for the reason decision 7 gives: the
/// standby costs a netns, a veth pair and a ruleset on a second machine and
/// buys exactly one failure. A third buys the case where two gateway nodes
/// are down at once, which is a case where the cluster has other problems.
///
/// A router on a cluster with ONE gateway node is built on that one and says
/// so — a standby that does not exist is not a reason to refuse the router.
pub const GATEWAY_CHASSIS: usize = 2;

/// Every node that could carry this router, best first.
///
/// The three cuts are the ones decision 4 names and nothing else: the node
/// claims an interface for the router's provider network (`gateway:<physnet>`
/// in its catalogue), it is up and willing and says nothing is wrong with
/// itself, and it accepts the router's class. A node that answered "no
/// gateway slot" is skipped as well — see `RouterStatus::refused`.
///
/// The ORDER is least-loaded first, ties broken by name so that every replica
/// of a leaderless control plane computes the same list out of the same
/// store. Load is routers already planned onto that node, which is what the
/// caller counts out of the same listing it is walking.
pub fn gateway_candidates<'a>(
    physnet: &str,
    class: &str,
    refused: &[String],
    load: &BTreeMap<String, usize>,
    candidates: &'a [Candidate],
) -> Vec<&'a Candidate> {
    let mut fit: Vec<&Candidate> = candidates
        .iter()
        // `is_alive` and not `is_usable`: the list has to come out the same
        // at every replica, and whose session a gateway node hangs off is not
        // a fact about the fleet. See `Candidate::alive`.
        .filter(|c| is_alive(c))
        .filter(|c| accepts_class(&c.accepts, class))
        .filter(|c| !refused.iter().any(|r| r == &c.name))
        .filter(|c| common::capability::gateway_physnets(&c.catalogue).contains(&physnet))
        .collect();
    fit.sort_by_key(|c| (load.get(&c.name).copied().unwrap_or(0), c.name.clone()));
    fit
}

/// The priority list this router should be on, best first — OVN's
/// `gateway_chassis`.
///
/// Stability first and load second, and the order of those two is the whole
/// of the function. A router that is already built somewhere STAYS there as
/// long as that machine is still a candidate: rebuilding a gateway because
/// another node grew a little emptier would tear down a netns, drop every
/// conntrack entry behind it and cost every established flow, to gain a
/// number in a dashboard. So the nodes it is on keep their places, in the
/// order they had, and the rest of the list is filled from the least loaded
/// of what is left.
///
/// Anti-affinity against the active node falls out of this rather than being
/// a rule of its own: the entries are distinct machines, so the standby is
/// never the active one. That is the whole of what "anti-affinity against the
/// active" can mean for an object that is deliberately built on several
/// machines at once.
pub fn plan_nodes(current: &[String], candidates: &[&Candidate]) -> Vec<String> {
    let eligible: BTreeSet<&str> = candidates.iter().map(|c| c.name.as_str()).collect();
    let mut planned: Vec<String> = current
        .iter()
        .filter(|n| eligible.contains(n.as_str()))
        .cloned()
        .collect();
    for candidate in candidates {
        if planned.len() >= GATEWAY_CHASSIS {
            break;
        }
        if !planned.iter().any(|n| n == &candidate.name) {
            planned.push(candidate.name.clone());
        }
    }
    planned.truncate(GATEWAY_CHASSIS);
    planned
}

/// Which of the planned nodes is ACTIVE: the first one that is live.
///
/// Decision 7 in one line — HA over BGP withdraw. Every node on the list
/// holds the whole router; the active one announces its external address and
/// answers ARP on the overlay, and the others are silent. So a failover is
/// not a build: the first entry stops being live, the second becomes the
/// active one, and the only thing that changes on either machine is whether
/// it speaks.
///
/// `None` when no node of the list is reachable, which is a router in
/// `Unknown` rather than one in `Failed`: the netns on those machines is
/// almost certainly still forwarding, and nothing here knows otherwise.
pub fn active_node<'a>(planned: &'a [String], candidates: &[&Candidate]) -> Option<&'a str> {
    planned
        .iter()
        // `alive` and not `connected`, for the reason `gateway_candidates`
        // gives: two replicas that answered this out of their own session
        // maps would disagree about which machine is the active one, and
        // then take it in turns to tell the other one to stand down.
        .find(|n| candidates.iter().any(|c| &c.name == *n && c.alive))
        .map(String::as_str)
}

/// How many routers each node already carries, out of one listing.
///
/// Every router counts, whatever its phase, and the standby entries count
/// too: a machine holding two standbys holds two netns, two veth pairs and
/// two rulesets, and the fact that neither is speaking today does not make
/// the third one free.
pub fn router_load(routers: &[Router]) -> BTreeMap<String, usize> {
    let mut load = BTreeMap::new();
    for router in routers {
        for node in &router.status.nodes {
            *load.entry(node.clone()).or_insert(0) += 1;
        }
    }
    load
}

/// The first address of `network`'s allocation that no other router holds.
///
/// A router keeps whatever address it already has for its whole life, so this
/// is asked exactly once per router — see `RouterStatus::external_addr`. The
/// answer is a pure function of the store as it stands, which is what lets
/// several leaderless replicas reach it without agreeing on anything: two
/// replicas placing the SAME router pick the same address and write the same
/// thing, and two replicas placing two different routers in the same instant
/// can pick the same address, which the caller resolves by looking again —
/// the pattern `create_routed_subnet` uses, and for the same reason.
///
/// The prefix comes from `spec.cidr`, because an address on a wire has to
/// carry the wire's mask or the router has no on-link route to its own
/// gateway. A network with no `cidr` gets `/32`, which is the honest answer
/// for a wire nobody described: the address is the router's and it reaches
/// its gateway through the explicit route the driver adds.
pub fn cut_external_addr(network: &ProviderNetwork, routers: &[Router]) -> Option<String> {
    let ranges = Ipv4Ranges::parse(&network.spec.allocation).ok()?;
    let taken: BTreeSet<Ipv4Addr> = routers
        .iter()
        .filter_map(|r| r.status.external_addr.split('/').next()?.parse().ok())
        .collect();
    let address = ranges.first_free(&taken)?;
    let prefix = network
        .spec
        .cidr
        .rsplit_once('/')
        .and_then(|(_, len)| len.parse::<u8>().ok())
        .unwrap_or(32);
    Some(format!("{address}/{prefix}"))
}

/// The rules this router really carries, derived from what is stored.
///
/// Decision 5, and the derivation is the whole of it: an operator writes
/// `snat: true` and points a floating address at a router, and what comes out
/// is a list somebody can read next to the ruleset on the machine. Two kinds
/// and no third:
///
///   * `snat` — one rule, present exactly when `spec.snat` is true. Its
///     `logicalIp` is deliberately EMPTY, which is what
///     `proto::NatRule` spells as "the whole internal subnet": the subnet is
///     the prefix of the router's own overlay address, the node has that
///     address anyway, and a prefix written twice is a prefix that can
///     disagree with itself.
///   * `dnat_and_snat` — one per floating address that names this router AND
///     says what it translates to. A reservation that names the router and no
///     inside address yields nothing, on purpose: half a 1:1 rule is not a
///     rule, and its absence from this list is the visible form of the
///     question. See `FloatingIpSpec::internal_address`.
///
///   * `routed` — one per announced prefix, and it is not a translation at
///     all. `proto::EnsureRouter` carries no field for the announcement, so
///     this is the road it takes: the prefix in `logicalIp`, no `externalIp`,
///     and the driver renders no rule for it and announces it instead. The
///     agent side of 6k settled the spelling; see [`NatKind::Routed`].
///
/// Sorted within each kind, because this list is compared against the stored
/// one to decide whether a write is worth making, and two passes that agreed
/// on the content and disagreed on the order would rewrite the object every
/// five seconds. The kinds keep their order — the masquerade, then the
/// floating addresses, then the announcements — because that is the order
/// somebody reads them in.
pub fn nat_rules(router: &Router, floating: &[FloatingIp], announced: &[String]) -> Vec<NatRule> {
    let external = router.status.external_addr.split('/').next().unwrap_or("");
    let mut rules = Vec::new();
    if router.spec.snat && !external.is_empty() {
        rules.push(NatRule {
            kind: NatKind::Snat,
            external_ip: external.to_string(),
            logical_ip: String::new(),
        });
    }
    let mut ours: Vec<&FloatingIp> = floating
        .iter()
        .filter(|f| f.spec.router == router.metadata.name)
        .filter(|f| !f.spec.internal_address.is_empty() && !f.spec.address.is_empty())
        .collect();
    ours.sort_by(|a, b| a.spec.address.cmp(&b.spec.address));
    rules.extend(ours.into_iter().map(|f| NatRule {
        kind: NatKind::DnatAndSnat,
        external_ip: f.spec.address.clone(),
        logical_ip: f.spec.internal_address.clone(),
    }));
    let mut prefixes: Vec<&String> = announced.iter().filter(|p| !p.is_empty()).collect();
    prefixes.sort();
    prefixes.dedup();
    rules.extend(prefixes.into_iter().map(|prefix| NatRule {
        kind: NatKind::Routed,
        external_ip: String::new(),
        logical_ip: prefix.clone(),
    }));
    rules
}

/// One router, decided — everything a backend needs to make it so, and
/// nothing about how.
///
/// It is the output of the planning above and the input of the trait below,
/// and that is why it holds resolved values rather than object names: a
/// backend that had to look a `ProviderNetwork` up would be a backend with a
/// store in it, and two backends resolving the same names separately is how
/// they start disagreeing about which wire a router is on.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RouterPlan {
    /// The router's `metadata.uid` — what a node keys the thing by, exactly
    /// as it keys a VM by its uid. A name is what people call a router and
    /// people reuse names.
    pub id: String,
    /// For the log line and the event; the uid is the identity.
    pub name: String,
    pub physnet: String,
    /// CIDR, out of the provider network's allocation.
    pub external_addr: String,
    /// The next hop out there. Empty = no default route, which is legal.
    pub external_gateway: String,
    /// The tenant's overlay.
    pub vni: u32,
    /// CIDR, the router's address on that overlay.
    pub internal_addr: String,
    pub nats: Vec<NatRule>,
    /// The nodes this router belongs on, best first.
    pub nodes: Vec<String>,
    /// The one of `nodes` that should be announcing. `None` = none of them is
    /// reachable, and every node keeps whatever it was told last.
    pub active: Option<String>,
    /// Nodes that hold this router and should let go of it: they fell off the
    /// list, or the router is on its way out and the list is empty.
    pub release: Vec<String>,
}

/// What a backend says is true after it tried.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RouterOutcome {
    /// The nodes that took the router — what goes on `status.nodes`, so that
    /// a node which refused never appears there.
    pub built: Vec<String>,
    pub active_node: String,
    /// The nodes that acknowledged letting the router go. What comes OFF
    /// `status.releasing`, and the only thing that takes a node off it: a
    /// destroy nobody could deliver is a debt that is still owed.
    pub released: Vec<String>,
    /// Nodes that refused STRUCTURALLY: they claim the physnet and have no
    /// gateway slot for it. They go on `status.refused` and the planner never
    /// offers them this router again. See `Refused::cannot_serve`, whose
    /// distinction this is — a node that could not be reached is not one that
    /// said no.
    pub refused: Vec<String>,
    pub phase: RouterPhase,
    pub message: Option<String>,
}

/// The one road a backend has to the machines: one command, to one node,
/// awaited.
///
/// A trait and not the session registry itself, because the registry is the
/// cluster controller's and this crate is under it — the same reason
/// `Scheduler` takes `Candidate`s rather than reading etcd. The cluster's
/// `Dispatch` is the implementation that matters; a recorder is what the
/// tests use, and a backend that talks to a database rather than to machines
/// ignores it entirely.
#[async_trait::async_trait]
pub trait RouterSink: Send + Sync {
    /// Build or re-state one router on one node. Level-triggered: the same
    /// call twice is one router.
    ///
    /// `Ok(())` is "the node has it". An `Err` whose cause is a
    /// [`crate::Refused`] with `CANNOT_SERVE` is the structural refusal —
    /// this machine has no gateway slot for that physnet — and everything
    /// else is a fact about the session.
    async fn ensure(&self, node: &str, router: proto::EnsureRouter) -> anyhow::Result<()>;
    /// Let go of one router on one node, by uid.
    async fn destroy(&self, node: &str, id: &str) -> anyhow::Result<()>;
}

/// How a decided router becomes a router that exists.
///
/// The seam an OVN backend goes behind, and the reason the objects of 6k are
/// shaped the way they are. Everything this takes is already decided —
/// [`RouterPlan`] — so a second implementation writes the same facts into a
/// northbound database instead of sending commands, and nothing above it
/// changes: not the objects, not the scheduler, not the reconciler, not the
/// CLI.
#[async_trait::async_trait]
pub trait NetworkBackend: Send + Sync {
    /// The word in the config that chose this backend. For the log line at
    /// start-up and for `router get`, so that an operator can see which
    /// backend a router was built by.
    fn name(&self) -> &'static str;

    /// Make one router so, and say what is true afterwards.
    async fn realise(&self, sink: &dyn RouterSink, plan: &RouterPlan) -> RouterOutcome;
}

/// MeisterStack's own network backend: the routers are built by the agents
/// with the `linux-network` driver.
///
/// One `EnsureRouter` per node of the priority list, `active` true on the
/// first live one and false on the rest, and a `DestroyRouter` to everything
/// that should let go. Level-triggered like everything else this control
/// plane sends: the same plan twice is one router, so a pass that reaches a
/// node which already has it costs one message and changes nothing.
///
/// The order is deliberate and it is the failover's whole correctness
/// argument: **the standbys are told first, the active last**. Two nodes
/// announcing one address at once is a fabric that has to choose, and it may
/// choose the one whose conntrack does not have the flow; a moment where
/// NOBODY announces is a moment of loss and no confusion. So a node that is
/// giving up `active` hears about it before the node that is taking it up.
pub struct MeisterNetwork;

#[async_trait::async_trait]
impl NetworkBackend for MeisterNetwork {
    fn name(&self) -> &'static str {
        "meister"
    }

    async fn realise(&self, sink: &dyn RouterSink, plan: &RouterPlan) -> RouterOutcome {
        let mut out = RouterOutcome::default();
        let mut unreachable = Vec::new();

        for node in &plan.release {
            match sink.destroy(node, &plan.id).await {
                Ok(()) => out.released.push(node.clone()),
                Err(e) => tracing::warn!(router = %plan.name, node = %node,
                                         error = format!("{e:#}"), "letting a router go failed"),
            }
        }

        // Standbys first, the active one last. See the type's doc.
        let ordered = plan
            .nodes
            .iter()
            .filter(|n| Some(n.as_str()) != plan.active.as_deref())
            .chain(
                plan.nodes
                    .iter()
                    .filter(|n| Some(n.as_str()) == plan.active.as_deref()),
            );
        for node in ordered {
            let active = Some(node.as_str()) == plan.active.as_deref();
            match sink.ensure(node, plan.ensure_for(active)).await {
                Ok(()) => {
                    out.built.push(node.clone());
                    if active {
                        out.active_node = node.clone();
                    }
                }
                Err(e) if crate::Refused::reason_of(&e) == crate::CANNOT_SERVE => {
                    tracing::warn!(router = %plan.name, node = %node,
                                   error = format!("{e:#}"), "node has no gateway slot");
                    out.refused.push(node.clone());
                    out.message = Some(format!("{node}: {e}"));
                }
                Err(e) => {
                    tracing::debug!(router = %plan.name, node = %node,
                                    error = format!("{e:#}"), "router not carried down");
                    unreachable.push(node.clone());
                    out.message = Some(format!("{node}: {e}"));
                }
            }
        }

        out.phase = verdict(plan, &out, &unreachable);
        out
    }
}

/// What the phase IS after a pass, out of what happened rather than out of
/// what was asked.
///
/// The order of the questions is the answer: a router nobody would carry is
/// Pending, one every candidate refused is Failed, one that is built and
/// speaking is Active, one that is built and deliberately silent is Standby,
/// and one whose machines could not be reached is Unknown — never Failed,
/// for the reason `VmPhase::Unknown` gives.
fn verdict(plan: &RouterPlan, out: &RouterOutcome, unreachable: &[String]) -> RouterPhase {
    if plan.nodes.is_empty() {
        return RouterPhase::Pending;
    }
    if out.built.is_empty() {
        return if unreachable.is_empty() {
            RouterPhase::Failed
        } else {
            RouterPhase::Unknown
        };
    }
    if out.active_node.is_empty() {
        RouterPhase::Standby
    } else {
        RouterPhase::Active
    }
}

impl RouterPlan {
    /// The wire form, for one node, with the active bit that node should
    /// have. Built here rather than in the backend so that a second backend
    /// speaking the same protocol cannot spell it differently.
    pub fn ensure_for(&self, active: bool) -> proto::EnsureRouter {
        proto::EnsureRouter {
            id: self.id.clone(),
            physnet: self.physnet.clone(),
            external_addr: self.external_addr.clone(),
            external_gateway: self.external_gateway.clone(),
            vni: self.vni,
            internal_addr: self.internal_addr.clone(),
            nats: self
                .nats
                .iter()
                .map(|r| proto::NatRule {
                    kind: r.kind.as_str().to_string(),
                    external_ip: r.external_ip.clone(),
                    logical_ip: r.logical_ip.clone(),
                })
                .collect(),
            active,
        }
    }
}

/// The TOML spelling: `network = "meister"`.
///
/// The same shape `SchedulerConfig` has, for the same reason. Both
/// controllers resolve their backend through here, so a second one is a new
/// arm and a new line in a config file rather than an edit in two `main`s.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct NetworkConfig(pub String);

impl NetworkConfig {
    /// Default when the config says nothing: `meister` — the routers are
    /// built by the agents with the `linux-network` driver, which is the only
    /// backend there is and the one every cluster was implicitly running.
    pub fn into_backend(this: Option<Self>) -> anyhow::Result<std::sync::Arc<dyn NetworkBackend>> {
        Ok(match this.as_ref().map(|n| n.0.as_str()) {
            None | Some("meister") => std::sync::Arc::new(MeisterNetwork),
            Some(other) => {
                anyhow::bail!("network = {other:?}, expected \"meister\"")
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::resources::{FloatingIpSpec, RouterSpec};
    use crate::scheduler::CandidateKind;
    use std::sync::Mutex;

    fn gateway(name: &str, physnets: &[&str], connected: bool) -> Candidate {
        Candidate {
            name: name.into(),
            connected,
            alive: connected,
            schedulable: true,
            unhealthy: Vec::new(),
            free: Default::default(),
            catalogue: physnets
                .iter()
                .map(|p| format!("network/{}", common::capability::gateway_claim(p)))
                .collect(),
            kind: CandidateKind::Node,
            labels: Default::default(),
            hosted: Vec::new(),
            accepts: Vec::new(),
            machine: None,
        }
    }

    fn router(name: &str) -> Router {
        let mut r = Router::declare(
            name,
            RouterSpec {
                tenant: "acme".into(),
                provider_network: "ext".into(),
                internal_addr: "10.42.0.1/24".into(),
                ..Default::default()
            },
        );
        r.metadata.uid = format!("uid-{name}");
        r
    }

    fn all(candidates: &[Candidate]) -> Vec<&Candidate> {
        candidates.iter().collect()
    }

    /// The three cuts, each on its own: the wire, the class and the machine's
    /// health. A router placed on a node that holds no interface for its
    /// physnet is a tenant with no way out and a netns nobody can reach.
    #[test]
    fn only_a_live_node_holding_that_wire_and_taking_that_class_is_a_candidate() {
        let mut wrong_class = gateway("gw-strict", &["ext"], true);
        wrong_class.accepts = vec!["gpu".into()];
        let mut wedged = gateway("gw-wedged", &["ext"], true);
        wedged.unhealthy = vec!["DiskPressure".into()];
        let field = [
            gateway("gw-1", &["ext"], true),
            gateway("gw-dmz", &["dmz"], true),
            wrong_class,
            wedged,
            gateway("gw-down", &["ext"], false),
        ];
        let names: Vec<&str> = gateway_candidates("ext", "router", &[], &BTreeMap::new(), &field)
            .iter()
            .map(|c| c.name.as_str())
            .collect();
        assert_eq!(names, ["gw-1"], "a down node is not usable either");

        // And a node that already said it has no gateway slot is skipped
        // however healthy it looks.
        assert!(
            gateway_candidates(
                "ext",
                "router",
                &["gw-1".to_string()],
                &BTreeMap::new(),
                &field
            )
            .is_empty()
        );
    }

    /// Least loaded first, ties by name — so three leaderless replicas
    /// reading one store plan the same list, and nobody has to agree with
    /// anybody.
    #[test]
    fn the_list_is_least_loaded_first_and_deterministic() {
        let field = [
            gateway("gw-c", &["ext"], true),
            gateway("gw-a", &["ext"], true),
            gateway("gw-b", &["ext"], true),
        ];
        let load = BTreeMap::from([("gw-a".to_string(), 3), ("gw-b".to_string(), 1)]);
        let ranked: Vec<&str> = gateway_candidates("ext", "router", &[], &load, &field)
            .iter()
            .map(|c| c.name.as_str())
            .collect();
        assert_eq!(ranked, ["gw-c", "gw-b", "gw-a"], "0, 1, 3");
    }

    /// A router that is built somewhere stays there. Rebuilding a gateway
    /// because another machine grew a little emptier would drop every
    /// conntrack entry behind it to gain a number in a dashboard.
    #[test]
    fn a_router_keeps_the_machines_it_is_already_on() {
        let field = [
            gateway("gw-empty", &["ext"], true),
            gateway("gw-busy", &["ext"], true),
        ];
        let ranked = all(&field);
        assert_eq!(
            plan_nodes(&["gw-busy".to_string()], &ranked),
            ["gw-busy", "gw-empty"],
            "the one it is on keeps its place and the standby is filled in"
        );
        // ... and a machine that stopped being a candidate falls off.
        assert_eq!(
            plan_nodes(&["gone".to_string(), "gw-busy".to_string()], &ranked),
            ["gw-busy", "gw-empty"]
        );
        // Never more than the fleet has.
        let one = [gateway("gw-1", &["ext"], true)];
        assert_eq!(plan_nodes(&[], &all(&one)), ["gw-1"]);
    }

    /// Decision 7: the active one is the first LIVE entry, so a failover is
    /// the list staying exactly as it is and the second machine starting to
    /// speak.
    #[test]
    fn the_active_node_is_the_first_live_one_and_a_failover_moves_nothing_else() {
        let planned = ["gw-1".to_string(), "gw-2".to_string()];
        let up = [
            gateway("gw-1", &["ext"], true),
            gateway("gw-2", &["ext"], true),
        ];
        assert_eq!(active_node(&planned, &all(&up)), Some("gw-1"));

        let first_gone = [
            gateway("gw-1", &["ext"], false),
            gateway("gw-2", &["ext"], true),
        ];
        assert_eq!(active_node(&planned, &all(&first_gone)), Some("gw-2"));
        // The list itself does not move, which is what makes the failover
        // free: both machines already hold the whole router.
        assert_eq!(
            plan_nodes(
                &planned,
                &gateway_candidates("ext", "router", &[], &BTreeMap::new(), &first_gone)
            ),
            ["gw-2"],
            "a node that is down is no longer a candidate, and the list shrinks to what is"
        );

        let all_gone = [
            gateway("gw-1", &["ext"], false),
            gateway("gw-2", &["ext"], false),
        ];
        assert_eq!(active_node(&planned, &all(&all_gone)), None);
    }

    /// Decision 5: two kinds, explicit, derived from what is stored — and a
    /// routed subnet produces none of them.
    #[test]
    fn the_rules_are_ovns_two_kinds_and_nothing_is_implied() {
        let mut r = router("acme-out");
        r.status.external_addr = "198.51.100.10/24".into();
        r.spec.routed_subnets = vec!["acme-net".into()];

        let floating = |addr: &str, router: &str, inside: &str| {
            let mut f = FloatingIp::declare(
                addr,
                FloatingIpSpec {
                    tenant: "acme".into(),
                    address: addr.into(),
                    router: router.into(),
                    internal_address: inside.into(),
                    ..Default::default()
                },
            );
            f.metadata.uid = addr.into();
            f
        };
        let addresses = [
            floating("198.51.100.9", "acme-out", "10.42.0.9"),
            floating("198.51.100.8", "acme-out", "10.42.0.8"),
            // Somebody else's router: not ours to translate.
            floating("198.51.100.7", "other", "10.42.0.7"),
            // Ours, and half a rule: no inside address, so no rule at all.
            floating("198.51.100.6", "acme-out", ""),
        ];

        let rules = nat_rules(&r, &addresses, &["10.7.1.0/24".to_string()]);
        assert_eq!(
            rules,
            vec![
                NatRule {
                    kind: NatKind::Snat,
                    external_ip: "198.51.100.10".into(),
                    // Empty: the whole internal subnet. Written twice it
                    // could disagree with itself.
                    logical_ip: String::new(),
                },
                NatRule {
                    kind: NatKind::DnatAndSnat,
                    external_ip: "198.51.100.8".into(),
                    logical_ip: "10.42.0.8".into(),
                },
                NatRule {
                    kind: NatKind::DnatAndSnat,
                    external_ip: "198.51.100.9".into(),
                    logical_ip: "10.42.0.9".into(),
                },
                // Announced and never translated: no external address, and
                // the driver renders no rule for it. The contract has no
                // field of its own for the announcement, so this is the road
                // it takes — see `NatKind::Routed`.
                NatRule {
                    kind: NatKind::Routed,
                    external_ip: String::new(),
                    logical_ip: "10.7.1.0/24".into(),
                },
            ],
            "sorted, so that two passes do not rewrite the object every tick"
        );

        // A router that was told not to masquerade carries no snat rule,
        // which is the routed-subnet deployment: the prefixes are real and a
        // masquerade in the middle would hide them from the fabric that was
        // told to route to them.
        r.spec.snat = false;
        assert!(
            nat_rules(&r, &addresses, &["10.7.1.0/24".to_string()])
                .iter()
                .all(|r| r.kind != NatKind::Snat)
        );
    }

    /// A router keeps its address for life, so the cut is asked once — and
    /// what it may not do is hand out an address another router holds.
    #[test]
    fn an_external_address_is_cut_once_and_never_handed_out_twice() {
        let network = ProviderNetwork::declare(
            "ext",
            crate::resources::ProviderNetworkSpec {
                physnet: "ext".into(),
                cidr: "198.51.100.0/24".into(),
                gateway: "198.51.100.1".into(),
                allocation: vec!["198.51.100.10-198.51.100.11".into()],
                description: String::new(),
            },
        );
        assert_eq!(
            cut_external_addr(&network, &[]).as_deref(),
            Some("198.51.100.10/24"),
            "the wire's own mask, or the router has no on-link route to its gateway"
        );

        let mut held = router("first");
        held.status.external_addr = "198.51.100.10/24".into();
        assert_eq!(
            cut_external_addr(&network, std::slice::from_ref(&held)).as_deref(),
            Some("198.51.100.11/24")
        );

        let mut second = router("second");
        second.status.external_addr = "198.51.100.11/24".into();
        assert_eq!(
            cut_external_addr(&network, &[held, second]),
            None,
            "an exhausted allocation is a Pending router with a sentence, not a collision"
        );
    }

    /// What a node is told, field for field. The one place the wire form is
    /// built, so a second backend speaking this protocol cannot spell it
    /// differently.
    #[test]
    fn the_wire_form_carries_the_plan_and_the_active_bit() {
        let plan = RouterPlan {
            id: "uid-1".into(),
            name: "acme-out".into(),
            physnet: "ext".into(),
            external_addr: "198.51.100.10/24".into(),
            external_gateway: "198.51.100.1".into(),
            vni: 10_007,
            internal_addr: "10.42.0.1/24".into(),
            nats: vec![NatRule {
                kind: NatKind::DnatAndSnat,
                external_ip: "198.51.100.9".into(),
                logical_ip: "10.42.0.9".into(),
            }],
            nodes: vec!["gw-1".into()],
            active: Some("gw-1".into()),
            release: Vec::new(),
        };
        let wire = plan.ensure_for(true);
        assert_eq!(wire.id, "uid-1", "a node keys a router by uid, not by name");
        assert_eq!(wire.vni, 10_007);
        assert_eq!(wire.internal_addr, "10.42.0.1/24");
        assert!(wire.active);
        assert_eq!(
            wire.nats[0].kind, "dnat_and_snat",
            "OVN's spelling, unchanged"
        );
        assert!(!plan.ensure_for(false).active);
    }

    /// A sink that remembers what it was told, and can be made to refuse.
    #[derive(Default)]
    struct Recorder {
        sent: Mutex<Vec<(String, bool)>>,
        destroyed: Mutex<Vec<String>>,
        /// node -> how it answers.
        refuse: BTreeMap<String, &'static str>,
    }

    #[async_trait::async_trait]
    impl RouterSink for Recorder {
        async fn ensure(&self, node: &str, router: proto::EnsureRouter) -> anyhow::Result<()> {
            match self.refuse.get(node) {
                Some(&crate::CANNOT_SERVE) => {
                    Err(crate::Refused::cannot_serve("no gateway slot for physnet ext").into())
                }
                Some(_) => anyhow::bail!("node {node} has no active session"),
                None => {
                    self.sent
                        .lock()
                        .unwrap()
                        .push((node.to_string(), router.active));
                    Ok(())
                }
            }
        }

        async fn destroy(&self, node: &str, _id: &str) -> anyhow::Result<()> {
            self.destroyed.lock().unwrap().push(node.to_string());
            Ok(())
        }
    }

    fn plan_on(nodes: &[&str], active: Option<&str>, release: &[&str]) -> RouterPlan {
        RouterPlan {
            id: "uid-1".into(),
            name: "acme-out".into(),
            physnet: "ext".into(),
            external_addr: "198.51.100.10/24".into(),
            external_gateway: "198.51.100.1".into(),
            vni: 10_007,
            internal_addr: "10.42.0.1/24".into(),
            nats: Vec::new(),
            nodes: nodes.iter().map(|n| n.to_string()).collect(),
            active: active.map(str::to_string),
            release: release.iter().map(|n| n.to_string()).collect(),
        }
    }

    /// Every node of the list is told, exactly one of them with `active` —
    /// and the standby hears first. Two machines announcing one address at
    /// once is a fabric that has to choose; a moment where nobody announces
    /// is a moment of loss and no confusion.
    #[tokio::test]
    async fn the_standby_is_told_before_the_active_one() {
        let sink = Recorder::default();
        let plan = plan_on(&["gw-1", "gw-2"], Some("gw-1"), &["gw-old"]);
        let out = MeisterNetwork.realise(&sink, &plan).await;

        assert_eq!(
            *sink.sent.lock().unwrap(),
            vec![("gw-2".to_string(), false), ("gw-1".to_string(), true)]
        );
        assert_eq!(*sink.destroyed.lock().unwrap(), vec!["gw-old".to_string()]);
        assert_eq!(out.phase, RouterPhase::Active);
        assert_eq!(out.active_node, "gw-1");
        assert_eq!(out.built, ["gw-2", "gw-1"]);
    }

    /// The distinction the whole refusal machinery exists for, one object
    /// over: a node that says it has no gateway slot is never offered this
    /// router again, and a node that could not be reached is not a node that
    /// said no — the router is Unknown, and its netns is very probably still
    /// forwarding.
    #[tokio::test]
    async fn a_structural_refusal_is_remembered_and_a_silent_node_is_not() {
        let sink = Recorder {
            refuse: BTreeMap::from([("gw-1".to_string(), crate::CANNOT_SERVE)]),
            ..Default::default()
        };
        let out = MeisterNetwork
            .realise(&sink, &plan_on(&["gw-1", "gw-2"], Some("gw-1"), &[]))
            .await;
        assert_eq!(out.refused, ["gw-1"]);
        assert_eq!(out.built, ["gw-2"]);
        assert_eq!(
            out.phase,
            RouterPhase::Standby,
            "built, and nobody speaking"
        );

        let quiet = Recorder {
            refuse: BTreeMap::from([("gw-1".to_string(), "Unavailable")]),
            ..Default::default()
        };
        let out = MeisterNetwork
            .realise(&quiet, &plan_on(&["gw-1"], Some("gw-1"), &[]))
            .await;
        assert!(out.refused.is_empty(), "silence is not a refusal");
        assert_eq!(out.phase, RouterPhase::Unknown);

        // Everything refused, nothing unreachable: that IS a failure.
        let all_refuse = Recorder {
            refuse: BTreeMap::from([("gw-1".to_string(), crate::CANNOT_SERVE)]),
            ..Default::default()
        };
        let out = MeisterNetwork
            .realise(&all_refuse, &plan_on(&["gw-1"], Some("gw-1"), &[]))
            .await;
        assert_eq!(out.phase, RouterPhase::Failed);

        // And a router nobody would carry is Pending, whatever the sink says.
        let out = MeisterNetwork
            .realise(&Recorder::default(), &plan_on(&[], None, &[]))
            .await;
        assert_eq!(out.phase, RouterPhase::Pending);
    }

    /// The config seam, the same shape `SchedulerConfig` has: a word chooses
    /// a backend, and a word nobody implements is a start-up error naming
    /// what there is.
    #[test]
    fn the_backend_is_chosen_by_a_word_in_the_config() {
        assert_eq!(NetworkConfig::into_backend(None).unwrap().name(), "meister");
        assert_eq!(
            NetworkConfig::into_backend(Some(NetworkConfig("meister".into())))
                .unwrap()
                .name(),
            "meister"
        );
        let unknown = NetworkConfig::into_backend(Some(NetworkConfig("ovn".into())))
            .err()
            .expect("there is no ovn backend yet");
        assert!(unknown.to_string().contains("\"meister\""), "{unknown}");
    }
}
