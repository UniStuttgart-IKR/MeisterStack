// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Router placement policy and the network backend interface.
//!
//! Planning selects eligible gateway nodes, active placement, addresses and NAT
//! rules. [`NetworkBackend`] applies that plan. The configured `meister` backend
//! sends commands through agent sessions; other backends can implement the same
//! interface.

use std::collections::{BTreeMap, BTreeSet};
use std::net::Ipv4Addr;

use common::net::Ipv4Ranges;

use crate::resources::{
    FloatingIp, NatKind, NatRule, ProviderNetwork, Router, RouterPhaseKind, RouterReason,
    accepts_class,
};
use crate::scheduler::{Candidate, is_alive};

/// Desired gateway count: one active and one standby. A cluster with
/// only one eligible gateway can still host the router.
pub const GATEWAY_CHASSIS: usize = 2;

/// Eligible gateways ordered by planned router load, then name. Require
/// the physnet capability, health, schedulability and accepted class;
/// exclude nodes with a recorded gateway refusal.
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

/// Whether at most one node of the cluster claims `physnet`, counting every node the
/// inventory holds: alive or not, cordoned or not, refused or not (IKR-B76).
///
/// Then no node but the one carrying a router can be made active for it, and that node's dead
/// man, which silences a router so that another node may take its addresses over, would cut
/// the tenants off and protect nothing. The planned nodes are not the measure: a gateway that
/// was down, cordoned or refused when the plan was made can be the active one of the next plan,
/// made while the old node is cut off and still answering. What is left is a node that comes
/// to claim the physnet while the active one is cut off, which takes an operator.
pub fn sole_gateway(physnet: &str, candidates: &[Candidate]) -> bool {
    candidates
        .iter()
        .filter(|c| common::capability::gateway_physnets(&c.catalogue).contains(&physnet))
        .count()
        <= 1
}

/// Retain eligible existing placements in order, then fill remaining
/// slots from candidates. Avoid rebalancing a working gateway merely to
/// reduce load; rebuilding loses connection state. Each node appears once.
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

/// Select the first live planned gateway. None means no reachable
/// placement; it does not prove that old namespaces stopped forwarding.
pub fn active_node<'a>(planned: &'a [String], candidates: &[&Candidate]) -> Option<&'a str> {
    planned
        .iter()
        // Use fleet-wide liveness so replicas with different session ownership
        // select the same active gateway.
        .find(|n| candidates.iter().any(|c| &c.name == *n && c.alive))
        .map(String::as_str)
}

/// Count every listed router placement, including standbys: inactive instances
/// still consume namespaces, interfaces and rulesets.
pub fn router_load(routers: &[Router]) -> BTreeMap<String, usize> {
    let mut load = BTreeMap::new();
    for router in routers {
        for node in &router.status.nodes {
            *load.entry(node.clone()).or_insert(0) += 1;
        }
    }
    load
}

/// Choose the first unclaimed provider address. Concurrent routers can
/// choose the same address, so callers must recheck after writing. Use
/// the provider CIDR prefix, or /32 when unspecified; the driver adds
/// an explicit gateway route when needed.
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

/// The bare host part of a stored external address: `203.0.113.10/24` is the
/// same claim on the wire as `203.0.113.10/32`, and the mask is a fact about
/// the provider network rather than about who holds the address.
fn bare_addr(stored: &str) -> &str {
    stored.split('/').next().unwrap_or("")
}

/// What a pass has to do about the external address of ONE router.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AddressClaim {
    /// Leave `status.external_addr` exactly as it is.
    Keep,
    /// Write this address: the router holds none and this one is free.
    Take(String),
    /// Clear the address this router is holding. Somebody with a lower name
    /// holds it too, and only one of them may.
    Yield,
}

/// Find other holders of the same host address, ignoring CIDR prefix differences.
pub fn other_holders<'a>(name: &str, address: &str, routers: &'a [Router]) -> Vec<&'a str> {
    let wanted = bare_addr(address);
    if wanted.is_empty() {
        return Vec::new();
    }
    let mut holders: Vec<&str> = routers
        .iter()
        .filter(|r| r.metadata.name != name)
        .filter(|r| bare_addr(&r.status.external_addr) == wanted)
        .map(|r| r.metadata.name.as_str())
        .collect();
    holders.sort_unstable();
    holders
}

/// Choose whether a router keeps, acquires or yields its external address.
///
/// Recheck on every pass, including after allocation. Among duplicate holders,
/// only the lowest name keeps the address; the others yield and retry later.
/// This deterministic rule repairs concurrent allocations from stale listings.
pub fn claim_external_addr(
    router: &Router,
    network: &ProviderNetwork,
    routers: &[Router],
) -> AddressClaim {
    let name = router.metadata.name.as_str();
    let held = router.status.external_addr.as_str();
    if bare_addr(held).is_empty() {
        return match cut_external_addr(network, routers) {
            Some(address) => AddressClaim::Take(address),
            // Nothing held and nothing free: there is nothing to write, and
            // the caller says so in its own words.
            None => AddressClaim::Keep,
        };
    }
    match other_holders(name, held, routers)
        .into_iter()
        .any(|other| other < name)
    {
        true => AddressClaim::Yield,
        false => AddressClaim::Keep,
    }
}

/// Apply the shared claim rule in at most two rounds. After assigning a
/// new address, reread to detect competing writes. Existing claims are
/// also checked for keep/yield conflicts.
pub async fn settle_external_addr(
    store: &crate::store::EtcdStore,
    router: Router,
    network: &ProviderNetwork,
) -> crate::store::Result<Router> {
    let name = router.metadata.name.clone();
    let mut router = router;
    for _ in 0..2 {
        let routers = store.list::<Router>().await?;
        match claim_external_addr(&router, network, &routers) {
            AddressClaim::Keep => break,
            AddressClaim::Take(address) => {
                let taken = address.clone();
                router = store
                    .mutate::<Router, _>(&name, |r| r.status.external_addr = taken.clone())
                    .await?;
                tracing::info!(router = %name, address = %address, "external address cut");
            }
            AddressClaim::Yield => {
                let lost = router.status.external_addr.clone();
                let to = other_holders(&name, &lost, &routers).join(", ");
                tracing::warn!(router = %name, address = %lost, lost_to = %to,
                               "lost the claim on this external address, taking it back");
                router = store
                    .mutate::<Router, _>(&name, |r| r.status.external_addr.clear())
                    .await?;
                break;
            }
        }
    }
    Ok(router)
}

/// Derive ordered router rules from stored intent and allocations:
///
/// * `snat` when enabled, with empty logicalIp meaning the whole internal subnet.
/// * `dnat_and_snat` for floating addresses with a router and internal address.
/// * `routed` for announced prefixes, carried in logicalIp without translation.
///
/// Sort within each kind to keep repeated reconciliation from changing order.
/// The kind order is SNAT, floating translations, then announcements.
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

/// Resolved router configuration for a backend to apply without store lookups.
/// Central resolution keeps placement and network interpretation consistent.
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
    /// No node of the cluster but one claims this router's physnet. See `sole_gateway`.
    pub sole_gateway: bool,
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
    /// Nodes with structural gateway refusal, retained in status.refused until
    /// that evidence is cleared. Unreachable nodes are not structural refusals.
    pub refused: Vec<String>,
    pub phase: RouterPhaseKind,
    /// Reason derived alongside phase; phase alone cannot distinguish missing
    /// candidates from candidates that explicitly refused.
    pub reason: RouterReason,
    pub message: Option<String>,
}

/// Await one command to one node. The cluster supplies session dispatch;
/// tests can supply a recorder without depending on controller internals.
#[async_trait::async_trait]
pub trait RouterSink: Send + Sync {
    /// Idempotently ensure a router on one node. `Refused` with `CANNOT_SERVE`
    /// denotes structural incompatibility; other errors do not establish that refusal.
    async fn ensure(&self, node: &str, router: proto::EnsureRouter) -> anyhow::Result<()>;
    /// Let go of one router on one node, by uid.
    async fn destroy(&self, node: &str, id: &str) -> anyhow::Result<()>;
}

/// Apply a resolved RouterPlan through a network implementation.
/// Backends receive placement and configuration rather than resolving objects.
#[async_trait::async_trait]
pub trait NetworkBackend: Send + Sync {
    /// The word in the config that chose this backend. For the log line at
    /// start-up and for `router get`, so that an operator can see which
    /// backend a router was built by.
    fn name(&self) -> &'static str;

    /// Make one router so, and say what is true afterwards.
    async fn realise(&self, sink: &dyn RouterSink, plan: &RouterPlan) -> RouterOutcome;
}

/// Apply the gateway plan through agent EnsureRouter/DestroyRouter
/// commands. Send standby updates before activation to reduce overlap.
/// This order does not fence an unreachable previous active gateway.
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
                    out.message = Some(status_line(node, &e));
                }
                Err(e) => {
                    tracing::debug!(router = %plan.name, node = %node,
                                    error = format!("{e:#}"), "router not carried down");
                    unreachable.push(node.clone());
                    out.message = Some(status_line(node, &e));
                }
            }
        }

        (out.phase, out.reason) = verdict(plan, &out, &unreachable);
        out
    }
}

/// The router status line for a node that did not carry it: the whole error
/// chain, because the node's own sentence sits under a line that only says who
/// answered ("agent … rejected command", "the replica at … answered 409").
fn status_line(node: &str, e: &anyhow::Error) -> String {
    format!("{node}: {e:#}")
}

/// Derive router phase and reason from the plan, acknowledgements and failures.
/// Unreachable nodes yield Unknown rather than proving the router Failed.
fn verdict(
    plan: &RouterPlan,
    out: &RouterOutcome,
    unreachable: &[String],
) -> (RouterPhaseKind, RouterReason) {
    if plan.nodes.is_empty() {
        return (RouterPhaseKind::Pending, RouterReason::Unplaced);
    }
    if out.built.is_empty() {
        return if unreachable.is_empty() {
            (RouterPhaseKind::Failed, RouterReason::Refused)
        } else {
            (RouterPhaseKind::Unknown, RouterReason::Silent)
        };
    }
    if out.active_node.is_empty() {
        // A standby carries no reason at all: it is built and doing what it
        // was asked to do. See `RouterPhase::Standby`.
        (RouterPhaseKind::Standby, RouterReason::Unrecorded)
    } else {
        (RouterPhaseKind::Active, RouterReason::Unrecorded)
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
            sole_gateway: self.sole_gateway,
        }
    }
}

/// Shared backend configuration, such as `network = "meister"`, resolved by
/// both controller tiers.
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

    /// IKR-B76: a router is its node's alone when no other node of the cluster claims the
    /// physnet, however unusable that other node is right now.
    #[test]
    fn a_gateway_is_sole_only_when_no_other_node_claims_the_wire_at_all() {
        let mut cordoned = gateway("gw-cordoned", &["ext"], true);
        cordoned.schedulable = false;
        let alone = [
            gateway("gw-1", &["ext"], true),
            gateway("gw-dmz", &["dmz"], true),
        ];
        assert!(sole_gateway("ext", &alone));
        for other in [gateway("gw-down", &["ext"], false), cordoned] {
            let field = [gateway("gw-1", &["ext"], true), other];
            assert!(
                !sole_gateway("ext", &field),
                "{} can be made active while gw-1 is cut off",
                field[1].name
            );
        }
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
                // Routed entries carry announcements without address translation; logical_ip
                // holds the prefix and external_ip remains empty.
                NatRule {
                    kind: NatKind::Routed,
                    external_ip: String::new(),
                    logical_ip: "10.7.1.0/24".into(),
                },
            ],
            "sorted, so that two passes do not rewrite the object every tick"
        );

        // Disabling SNAT preserves routed source addresses visible to the fabric.
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
            sole_gateway: true,
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
        assert!(
            wire.sole_gateway,
            "the node's dead man reads it off the record"
        );
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

    /// A sink whose nodes refuse the way a session hands an agent's refusal
    /// back: the agent's sentence under the line that says who refused.
    struct Rejecting;

    #[async_trait::async_trait]
    impl RouterSink for Rejecting {
        async fn ensure(&self, node: &str, _router: proto::EnsureRouter) -> anyhow::Result<()> {
            Err(
                anyhow::Error::new(crate::Refusal::plain("no uplink carries vni 10007"))
                    .context(format!("agent {node} rejected command")),
            )
        }

        async fn destroy(&self, _node: &str, _id: &str) -> anyhow::Result<()> {
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
            sole_gateway: false,
        }
    }

    /// Configure standbys before the selected active node to avoid overlap during
    /// ordered role changes.
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
        assert_eq!(out.phase, RouterPhaseKind::Active);
        assert_eq!(out.active_node, "gw-1");
        assert_eq!(out.built, ["gw-2", "gw-1"]);
    }

    /// Structural refusal is remembered; transport silence remains uncertainty
    /// about a router that may still be forwarding.
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
            RouterPhaseKind::Standby,
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
        assert_eq!(out.phase, RouterPhaseKind::Unknown);

        // Everything refused, nothing unreachable: that IS a failure.
        let all_refuse = Recorder {
            refuse: BTreeMap::from([("gw-1".to_string(), crate::CANNOT_SERVE)]),
            ..Default::default()
        };
        let out = MeisterNetwork
            .realise(&all_refuse, &plan_on(&["gw-1"], Some("gw-1"), &[]))
            .await;
        assert_eq!(out.phase, RouterPhaseKind::Failed);

        // And a router nobody would carry is Pending, whatever the sink says.
        let out = MeisterNetwork
            .realise(&Recorder::default(), &plan_on(&[], None, &[]))
            .await;
        assert_eq!(out.phase, RouterPhaseKind::Pending);
    }

    /// The status says what the node said, not only that it said no: a plain
    /// Display of the error would keep just the line naming who answered.
    #[tokio::test]
    async fn a_router_status_keeps_the_node_s_own_sentence() {
        let out = MeisterNetwork
            .realise(&Rejecting, &plan_on(&["gw-1"], Some("gw-1"), &[]))
            .await;

        assert_eq!(
            out.message.as_deref(),
            Some("gw-1: agent gw-1 rejected command: no uplink carries vni 10007")
        );
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
