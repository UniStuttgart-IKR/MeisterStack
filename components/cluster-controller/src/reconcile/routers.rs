// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! The router half of the pass: plan, carry down, write back.
//!
//! Level-triggered like every other loop here — the plan is derived from the
//! stored objects every time and the same plan twice is one router — and
//! leaderless like every other loop here, which is the interesting half. A VM
//! is about ONE machine, so the replica holding that machine's session owns
//! it and the others leave it alone (`may_reconcile`). A router is
//! deliberately about SEVERAL: it is built on its whole priority list, and
//! the failover that decision 7 asks for has to survive the loss of exactly
//! the machine an ownership rule would have hung it on. So the rule is looser
//! here and the store arbitrates — see `may_reconcile_router`.

use super::*;

use controller_api::network::{self, NetworkBackend, RouterOutcome, RouterPlan, RouterSink};
use controller_api::{ProviderNetwork, Router, RouterPhase};

/// Who, of several leaderless replicas, may act on this router: anybody who
/// can reach ONE of the machines it is on, and everybody while it is on none.
///
/// Deliberately looser than `may_reconcile`, and the looseness is the point.
/// A VM's owner is the replica holding its node's session, which works because
/// a VM has one node and because a VM whose node is gone is a VM nobody can do
/// anything for anyway. A router with two gateway nodes has two sessions,
/// possibly on two replicas, and the very case the object exists for — the
/// active machine dies and the standby takes over — is the case where the
/// obvious owner is the one that just went away.
///
/// What that costs is two replicas planning the same router in the same pass.
/// It costs nothing: the plan is a pure function of the store (see
/// `network::plan_nodes`), so they compute the same list, send the same
/// level-triggered commands and write the same status — and one of them loses
/// the compare-and-swap and drops it, exactly as two replicas expiring one
/// heartbeat do.
pub fn may_reconcile_router(router: &Router, sessions: &HashSet<String>) -> bool {
    router.status.nodes.is_empty() || router.status.nodes.iter().any(|n| sessions.contains(n))
}

/// One pass over the routers of this cluster.
pub(super) async fn reconcile_routers(
    pass: &Pass<'_>,
    dispatch: &crate::dispatch::Dispatch,
    backend: &dyn NetworkBackend,
) -> anyhow::Result<()> {
    let routers = pass.store.list::<Router>().await?;
    telemetry::metrics::objects().set_count(Router::KIND, routers.len() as i64);
    if routers.is_empty() {
        return Ok(());
    }
    let networks = pass.store.list::<ProviderNetwork>().await?;
    // One picture of the fleet's router load for the whole pass, out of the
    // listing above: two readings could disagree about which machine is
    // busiest, and then two routers of one pass would both go to it.
    let load = network::router_load(&routers);

    for router in routers {
        if !may_reconcile_router(&router, pass.sessions) {
            continue;
        }
        let name = router.metadata.name.clone();
        if let Err(e) = reconcile_router(pass, dispatch, backend, router, &networks, &load).await {
            warn!(router = %name, error = format!("{e:#}"), "router reconcile failed");
        }
    }
    Ok(())
}

/// What one router's pass decides, before anything is sent.
///
/// Split out of the acting half because it is the half worth testing: it
/// takes objects and candidates and answers with a plan or with the sentence
/// that says why there is none, and it touches neither the store nor a
/// session.
pub(crate) fn plan_router(
    router: &Router,
    networks: &[ProviderNetwork],
    load: &std::collections::BTreeMap<String, usize>,
    candidates: &[Candidate],
) -> Result<RouterPlan, (RouterPhase, String)> {
    let Some(network) = networks
        .iter()
        .find(|n| n.metadata.name == router.spec.provider_network)
    else {
        return Err((
            RouterPhase::Pending,
            format!(
                "no provider network called {} at this cluster",
                router.spec.provider_network
            ),
        ));
    };
    let Some(vni) = router.spec.vni else {
        return Err((
            RouterPhase::Pending,
            "spec.vni is unset, so this router has no overlay to put its inside leg on; \
             the cloud fills it in from the tenant, and a standalone cluster names it"
                .to_string(),
        ));
    };
    if router.spec.internal_addr.is_empty() {
        return Err((
            RouterPhase::Pending,
            "spec.internalAddr is unset, so the guests have no gateway address to point at; \
             this stack allocates no tenant addresses, so somebody has to say which one it is"
                .to_string(),
        ));
    }
    if router.status.external_addr.is_empty() {
        return Err((
            RouterPhase::Pending,
            format!(
                "no free address left in the allocation of provider network {} ({})",
                network.metadata.name,
                network.spec.allocation.join(", ")
            ),
        ));
    }

    let fit = network::gateway_candidates(
        &network.spec.physnet,
        router.spec.class(),
        &router.status.refused,
        load,
        candidates,
    );
    let nodes = network::plan_nodes(&router.status.nodes, &fit);
    if nodes.is_empty() {
        return Err((
            RouterPhase::Pending,
            gateway_sentence(&network.spec.physnet, router, candidates),
        ));
    }
    let active = network::active_node(&nodes, &fit).map(str::to_string);
    // Whatever held it, is not on the list any more, and can be told so.
    //
    // The reachability half is the important one and it is not an
    // optimisation. A node that fell off the list because it is DOWN still
    // has the netns and is very probably still forwarding; tearing it down is
    // neither possible (there is nobody to tell) nor right (it may be the
    // machine that comes back and takes the router again). A node that is up
    // and dropped out — cordoned, unhealthy, or simply beaten by a better
    // candidate — is one this cluster can and should tidy up.
    //
    // `alive` and not `connected`, for the reason the whole router path uses
    // it: whose session a machine hangs off is not a fact about the fleet,
    // and the commands go through `Dispatch`, which forwards to the replica
    // holding it. With `connected` the release was silently skipped whenever
    // the machine belonged to a sibling — which on a three-replica cluster is
    // most of the time — and then nothing ever told it, because the very same
    // pass takes the machine off `status.nodes` and the next pass computes
    // this list out of the list it just shortened.
    //
    // `alive` on its own and not `is_alive`: the question here is whether
    // anybody can be TOLD, not whether the machine is a candidate. A cordoned
    // or wedged machine is exactly one that dropped off the list, and it is
    // the one that most needs to hear about it.
    //
    // `status.releasing` beside `status.nodes` is the half that was missing,
    // and it is the one the lab found. A machine that fell off the list while
    // it was DOWN is not in this list — there is nobody to tell — and the very
    // same pass takes it off `status.nodes`, so the next pass derives this out
    // of the list it just shortened and the machine is never told AT ALL. It
    // comes back with the whole namespace, answering for an address another
    // node now carries. `status.releasing` remembers the debt; this is where
    // it is paid, the first pass the machine is reachable again.
    let release: Vec<String> = owed(router)
        .filter(|n| !nodes.contains(n))
        .filter(|n| candidates.iter().any(|c| c.name == **n && c.alive))
        .cloned()
        .collect();

    Ok(RouterPlan {
        id: router.metadata.uid.clone(),
        name: router.metadata.name.clone(),
        physnet: network.spec.physnet.clone(),
        external_addr: router.status.external_addr.clone(),
        external_gateway: network.spec.gateway.clone(),
        vni,
        internal_addr: router.spec.internal_addr.clone(),
        nats: router.status.nats.clone(),
        nodes,
        active,
        release,
    })
}

/// Every machine that holds this router and should not: the ones on the
/// priority list plus the ones still owed a `DestroyRouter`, each named once.
///
/// Sorted and deduplicated by the `BTreeSet` the caller of the second use
/// builds; here it is only "both lists, in this order".
fn owed(router: &Router) -> impl Iterator<Item = &String> {
    router
        .status
        .nodes
        .iter()
        .chain(router.status.releasing.iter())
}

/// Why no machine will carry this router, in the words that send somebody to
/// the right place.
///
/// Three different operator problems and three different sentences: nobody
/// gave an interface away for this wire, everybody who did is down or
/// drained, or everybody who did takes only other classes. Saying "no gateway
/// node" to somebody whose two gateway nodes are cordoned is the same kind of
/// wrong answer `PendingReason` exists to prevent.
fn gateway_sentence(physnet: &str, router: &Router, candidates: &[Candidate]) -> String {
    let claiming: Vec<&Candidate> = candidates
        .iter()
        .filter(|c| common::capability::gateway_physnets(&c.catalogue).contains(&physnet))
        .collect();
    if claiming.is_empty() {
        return format!(
            "no node of this cluster gives an interface away for physnet {physnet}; \
             a gateway node says so with `[network.provider] physnets = {{ {physnet} = \"…\" }}`"
        );
    }
    if !router.status.refused.is_empty() {
        return format!(
            "every node claiming physnet {physnet} has refused this router: {}",
            router.status.refused.join(", ")
        );
    }
    let taking: Vec<&&Candidate> = claiming
        .iter()
        .filter(|c| controller_api::accepts_class(&c.accepts, router.spec.class()))
        .collect();
    if taking.is_empty() {
        return format!(
            "no node claiming physnet {physnet} accepts the class {:?}: {}",
            router.spec.class(),
            claiming
                .iter()
                .map(|c| format!("{} ({})", c.name, c.accepts.join(", ")))
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
    format!(
        "every node claiming physnet {physnet} is down, drained or unhealthy: {}",
        taking
            .iter()
            .map(|c| c.name.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    )
}

async fn reconcile_router(
    pass: &Pass<'_>,
    dispatch: &crate::dispatch::Dispatch,
    backend: &dyn NetworkBackend,
    router: Router,
    networks: &[ProviderNetwork],
    load: &std::collections::BTreeMap<String, usize>,
) -> anyhow::Result<()> {
    let name = router.metadata.name.clone();
    // The address first and once: a router keeps it for life, so this is the
    // only pass that writes it. See `network::cut_external_addr`.
    let router = ensure_external_addr(pass, router, networks).await?;
    // Then the rules, which are derived every pass out of what is stored —
    // an operator pointing a floating address at this router is a NAT rule
    // one tick later and nothing else.
    let router = ensure_nats(pass, router).await?;

    let candidates = pass.nodes.lock().unwrap().clone();
    let plan = match plan_router(&router, networks, load, &candidates) {
        Ok(plan) => plan,
        Err((phase, message)) => {
            // Nothing is sent and nothing is torn down: a router that cannot
            // be planned right now is a router whose machines should go on
            // forwarding. The sentence is what changes.
            return note(pass, &router, phase, Some(message), None).await;
        }
    };
    let outcome = backend.realise(dispatch, &plan).await;
    settle(pass, &router, &plan, outcome).await?;
    debug!(router = %name, backend = backend.name(), nodes = ?plan.nodes,
           active = ?plan.active, "router pass");
    Ok(())
}

/// Cut the router's external address, once, and look again.
///
/// The second look is what makes this safe without a lock: two replicas
/// placing two different routers in the same instant both read the same free
/// address and both write it, so after writing we ask whether anybody else
/// now holds it and the higher name gives it up. Deterministic, so the two
/// replicas agree about which of them lost, and level-triggered, so the loser
/// simply has no address again on the next pass and takes the next one. The
/// same shape `create_routed_subnet` uses for the same reason.
async fn ensure_external_addr(
    pass: &Pass<'_>,
    router: Router,
    networks: &[ProviderNetwork],
) -> anyhow::Result<Router> {
    if !router.status.external_addr.is_empty() {
        return Ok(router);
    }
    let Some(network) = networks
        .iter()
        .find(|n| n.metadata.name == router.spec.provider_network)
    else {
        return Ok(router);
    };
    let held = pass.store.list::<Router>().await?;
    let Some(address) = network::cut_external_addr(network, &held) else {
        return Ok(router);
    };
    let name = router.metadata.name.clone();
    let taken = address.clone();
    let router = pass
        .store
        .mutate::<Router, _>(&name, |r| r.status.external_addr = taken.clone())
        .await?;

    let others: Vec<String> = pass
        .store
        .list::<Router>()
        .await?
        .into_iter()
        .filter(|r| r.metadata.name != name && r.status.external_addr == address)
        .map(|r| r.metadata.name)
        .collect();
    // The higher name gives it up, which is a rule both replicas reach out of
    // the same two names and no clock.
    if others.iter().any(|other| other < &name) {
        warn!(router = %name, address = %address, lost_to = ?others,
              "lost the claim on this external address, taking it back");
        let cleared = pass
            .store
            .mutate::<Router, _>(&name, |r| r.status.external_addr.clear())
            .await?;
        return Ok(cleared);
    }
    info!(router = %name, address = %address, "external address cut");
    Ok(router)
}

/// Derive the NAT rules and the announced prefixes, and write them if they
/// moved.
///
/// A write per pass would churn an etcd revision every five seconds for a
/// router nothing happened to, so the comparison is the point: these are
/// derived, sorted and compared whole, and an unchanged derivation is not
/// news. Exactly the rule `mirror::observe` follows one object over.
async fn ensure_nats(pass: &Pass<'_>, router: Router) -> anyhow::Result<Router> {
    // A cloud router's rules are the CLOUD's derivation and arrive stamped on
    // the object by `handle_create_router`. Re-deriving them here would mean
    // deriving them out of objects this tier does not serve — `FloatingIp`
    // and `RoutedSubnet` live one tier up — and the answer would be an empty
    // list: the tenant's DNAT rules deleted one pass after they arrived. So
    // the derivation runs for the routers this tier owns and for no others.
    if router.metadata.managed_by_cloud() {
        return Ok(router);
    }
    let floating = pass.store.list::<controller_api::FloatingIp>().await?;
    // The announcement, resolved as far as this tier can. A `RoutedSubnet` is
    // a cloud object and this tier serves none — so at a cluster under a
    // cloud the prefixes arrive already resolved on the object, and at a
    // standalone cluster `spec.routedSubnets` holds what somebody wrote,
    // which is the prefix itself. Either way the entries reach the node as
    // `routed` rules; see `NatKind::Routed`.
    let announced = router.spec.routed_subnets.clone();
    let nats = network::nat_rules(&router, &floating, &announced);
    if router.status.nats == nats && router.status.announced == announced {
        return Ok(router);
    }
    let name = router.metadata.name.clone();
    Ok(pass
        .store
        .mutate::<Router, _>(&name, |r| {
            r.status.nats = nats.clone();
            r.status.announced = announced.clone();
        })
        .await?)
}

/// Write what a pass decided, if it is different from what is stored.
async fn note(
    pass: &Pass<'_>,
    router: &Router,
    phase: RouterPhase,
    message: Option<String>,
    placement: Option<Placement<'_>>,
) -> anyhow::Result<()> {
    let generation = router.metadata.generation;
    let unchanged = router.status.phase == phase
        && router.status.message == message
        && placement.as_ref().is_none_or(|p| {
            router.status.nodes == p.nodes
                && router.status.active_node == p.active
                && router.status.refused == p.refused
                && router.status.releasing == p.releasing
        })
        && router.status.observed_generation == generation;
    if unchanged {
        return Ok(());
    }
    let was = router.status.phase;
    let was_active = router.status.active_node.clone();
    let name = router.metadata.name.clone();
    let placement = placement.map(|p| {
        (
            p.nodes.to_vec(),
            p.active.to_string(),
            p.refused.to_vec(),
            p.releasing.to_vec(),
        )
    });
    pass.store
        .mutate::<Router, _>(&name, |r| {
            r.status.phase = phase;
            r.status.message = message.clone();
            r.status.observed_generation = generation;
            if let Some((nodes, active, refused, releasing)) = &placement {
                r.status.nodes = nodes.clone();
                r.status.active_node = active.clone();
                r.status.refused = refused.clone();
                r.status.releasing = releasing.clone();
            }
        })
        .await?;
    if was != phase {
        info!(router = %name, from = was.as_str(), to = phase.as_str(), "router phase");
        events::record(
            pass.store,
            Happening {
                kind: Router::KIND,
                name: &name,
                uid: &router.metadata.uid,
                reason: events::reason::PHASE_CHANGED,
                message: message.unwrap_or_else(|| phase.as_str().to_string()),
                event_type: if phase == RouterPhase::Failed {
                    EventType::Warning
                } else {
                    EventType::Normal
                },
                tenant: Some(&router.spec.tenant),
            },
        )
        .await;
    }
    // And the fact the phase cannot state: WHICH machine is forwarding now.
    //
    // A failover is Active on one machine and then Active on another — no
    // phase change at all, and it is the one moment a tenant's traffic
    // actually moved. Before this it was a line in one replica's log and
    // nowhere an operator reads. Not written when the router had no active
    // machine and has none now, and not written for the first one it ever
    // gets: `Scheduled`-shaped news belongs to the phase event above.
    if let Some((_, active, _, _)) = &placement
        && active != &was_active
        && !active.is_empty()
        && !was_active.is_empty()
    {
        info!(router = %name, from = %was_active, to = %active, "the active machine changed");
        events::record(
            pass.store,
            Happening {
                kind: Router::KIND,
                name: &name,
                uid: &router.metadata.uid,
                reason: events::reason::ACTIVE_CHANGED,
                message: format!("now forwarding on {active}, was {was_active}"),
                // Warning and not Normal: nothing automatic put the tenant
                // back where they were, and somebody should look at why the
                // machine that was active stopped being it.
                event_type: EventType::Warning,
                tenant: Some(&router.spec.tenant),
            },
        )
        .await;
    }
    Ok(())
}

/// What the backend answered, onto the object.
///
/// `status.nodes` is the plan minus what REFUSED it, and the distinction
/// between refusing and not answering is the whole of this function. A
/// machine that said "no gateway slot" is not a candidate any more and never
/// appears there — that is what makes `status.refused` a fact rather than a
/// note. A machine this REPLICA could not reach said nothing at all, and it
/// stays on the list: its session hangs off a sibling, that sibling's pass
/// derives the same plan out of the same store and sends it the same command,
/// and dropping it here would be this process reporting its own reach as the
/// fleet's shape. That was the lab's finding — a router on two gateway nodes
/// lost one of them the moment its session moved to another replica, and the
/// list never grew back.
async fn settle(
    pass: &Pass<'_>,
    router: &Router,
    plan: &RouterPlan,
    outcome: RouterOutcome,
) -> anyhow::Result<()> {
    let mut refused = router.status.refused.clone();
    for node in outcome.refused {
        if !refused.contains(&node) {
            refused.push(node);
        }
    }
    refused.sort();
    // Ordered as the plan is and not as the answers came back: the priority
    // list is what says which machine is next, and the standby answered
    // first.
    let built: Vec<String> = plan
        .nodes
        .iter()
        .filter(|n| !refused.contains(n))
        .cloned()
        .collect();
    let releasing = still_owed(router, &plan.nodes, &outcome.released);
    note(
        pass,
        router,
        outcome.phase,
        outcome.message,
        Some(Placement {
            nodes: &built,
            active: &outcome.active_node,
            refused: &refused,
            releasing: &releasing,
        }),
    )
    .await
}

/// What is still owed a `DestroyRouter` after a pass.
///
/// Everything that held the router and is not on the new list, minus whatever
/// acknowledged letting go. A machine nobody could reach stays on it, and that
/// is the whole point of the field — see `RouterStatus::releasing`.
///
/// Sorted and named once, so that the comparison in `note` is a comparison of
/// two lists and not of two orderings.
pub(crate) fn still_owed(router: &Router, planned: &[String], released: &[String]) -> Vec<String> {
    let owed: std::collections::BTreeSet<String> = owed(router)
        .filter(|n| !planned.contains(n))
        .filter(|n| !released.contains(n))
        .cloned()
        .collect();
    owed.into_iter().collect()
}

/// Where a router stands on the machines, as one pass leaves it.
///
/// A struct and not four positional lists, because three of them are
/// `Vec<String>` and the compiler would not notice two of them swapped.
struct Placement<'a> {
    nodes: &'a [String],
    active: &'a str,
    refused: &'a [String],
    releasing: &'a [String],
}

/// The cluster's own sink: one `EnsureRouter` or `DestroyRouter` to one node,
/// wherever in this cluster the session happens to be.
///
/// Through `Dispatch` and not through the local session registry, and that is
/// the same defect one object over that rollout 59 found in the migration
/// reconciler (D-P2): a router is built on TWO machines whose sessions may
/// hang off two different replicas, so a reconciler asking its own registry
/// would build the half it can reach and call the other half unreachable —
/// on a three-replica cluster, most of the time.
#[async_trait::async_trait]
impl RouterSink for crate::dispatch::Dispatch {
    async fn ensure(&self, node: &str, router: proto::EnsureRouter) -> anyhow::Result<()> {
        let nats = router
            .nats
            .into_iter()
            .filter_map(|r| {
                Some(controller_api::NatRule {
                    kind: controller_api::NatKind::parse(&r.kind)?,
                    external_ip: r.external_ip,
                    logical_ip: r.logical_ip,
                })
            })
            .collect();
        self.send(
            node,
            crate::dispatch::NodeCommand::EnsureRouter {
                id: router.id,
                physnet: router.physnet,
                external_addr: router.external_addr,
                external_gateway: router.external_gateway,
                vni: router.vni,
                internal_addr: router.internal_addr,
                nats,
                active: router.active,
            },
        )
        .await
        .map(|_| ())
    }

    async fn destroy(&self, node: &str, id: &str) -> anyhow::Result<()> {
        self.send(
            node,
            crate::dispatch::NodeCommand::DestroyRouter { id: id.to_string() },
        )
        .await
        .map(|_| ())
    }
}
