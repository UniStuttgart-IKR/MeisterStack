// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Derive router plans from stored intent and dispatch them across gateway nodes.
//! Routers span several node sessions, so VM-style single-node ownership cannot
//! cover failover. `may_reconcile_router` and store arbitration coordinate replicas.

use super::*;

use controller_api::network::{self, NetworkBackend, RouterOutcome, RouterPlan, RouterSink};
use controller_api::{ProviderNetwork, Router, RouterPhaseKind};

/// Any replica reaching a planned gateway may reconcile the router.
/// Unassigned routers are eligible everywhere. Plans use shared fleet state;
/// commands are idempotent and status updates use CAS.
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

/// Derive a router plan from stored resources and fleet candidates without I/O.
pub(crate) fn plan_router(
    router: &Router,
    networks: &[ProviderNetwork],
    load: &std::collections::BTreeMap<String, usize>,
    candidates: &[Candidate],
) -> Result<RouterPlan, (RouterPhaseKind, String)> {
    let Some(network) = networks
        .iter()
        .find(|n| n.metadata.name == router.spec.provider_network)
    else {
        return Err((
            RouterPhaseKind::Pending,
            format!(
                "no provider network called {} at this cluster",
                router.spec.provider_network
            ),
        ));
    };
    let Some(vni) = router.spec.vni else {
        return Err((
            RouterPhaseKind::Pending,
            "spec.vni is unset, so this router has no overlay to put its inside leg on; \
             the cloud fills it in from the tenant, and a standalone cluster names it"
                .to_string(),
        ));
    };
    if router.spec.internal_addr.is_empty() {
        return Err((
            RouterPhaseKind::Pending,
            "spec.internalAddr is unset, so the guests have no gateway address to point at; \
             this stack allocates no tenant addresses, so somebody has to say which one it is"
                .to_string(),
        ));
    }
    if router.status.external_addr.is_empty() {
        return Err((
            RouterPhaseKind::Pending,
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
            RouterPhaseKind::Pending,
            gateway_sentence(&network.spec.physnet, router, candidates),
        ));
    }
    let active = network::active_node(&nodes, &fit).map(str::to_string);
    let sole_gateway = network::sole_gateway(&network.spec.physnet, candidates);
    // Release nodes excluded from the new plan when they are reachable anywhere
    // in the cluster. Dispatch forwards through sibling-held sessions.
    // Use `alive`, not scheduling eligibility: cordoned or unhealthy nodes still
    // need teardown commands. Persist unreachable cleanup in `status.releasing`
    // so it is retried after the node returns, even after `status.nodes` changes.
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
        sole_gateway,
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

pub(super) async fn reconcile_router(
    pass: &Pass<'_>,
    dispatch: &dyn RouterSink,
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
            // The planner said no: nowhere to put it, and the sentence says
            // which of the four walls it is.
            return note(
                pass,
                &router,
                phase,
                controller_api::RouterReason::Unplaced,
                Some(message),
                None,
            )
            .await;
        }
    };
    // Carried down already and resting since: the same plan again is the same
    // EnsureRouter to every gateway again, once per pass, and a pass runs on
    // every write to any VM. A router that is not resting (a node said its
    // namespace or a leg is gone, or it never came up) is told again at once.
    // (IKR-B74)
    if router.status.phase().kind().is_terminal() && pass.told.router_lately(&plan) {
        debug!(router = %name, "plan unchanged and carried down lately");
        return Ok(());
    }
    let outcome = backend.realise(dispatch, &plan).await;
    if outcome.phase.is_terminal() {
        pass.told.note_router(&plan);
    } else {
        pass.told.forget_router(&plan.id);
    }
    settle(pass, &router, &plan, outcome).await?;
    debug!(router = %name, backend = backend.name(), nodes = ?plan.nodes,
           active = ?plan.active, "router pass");
    Ok(())
}

/// Allocate and recheck the external address on every pass.
/// Concurrent claims are resolved deterministically by the shared allocator,
/// including conflicts that appeared after an earlier successful check.
async fn ensure_external_addr(
    pass: &Pass<'_>,
    router: Router,
    networks: &[ProviderNetwork],
) -> anyhow::Result<Router> {
    let Some(network) = networks
        .iter()
        .find(|n| n.metadata.name == router.spec.provider_network)
    else {
        return Ok(router);
    };
    Ok(network::settle_external_addr(pass.store, router, network).await?)
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
        .mutate_if::<Router, _>(&name, &router.metadata.uid, |r| {
            r.status.nats = nats.clone();
            r.status.announced = announced.clone();
        })
        .await?)
}

/// Write what a pass decided, if it is different from what is stored.
async fn note(
    pass: &Pass<'_>,
    router: &Router,
    phase: RouterPhaseKind,
    reason: controller_api::RouterReason,
    message: Option<String>,
    placement: Option<Placement<'_>>,
) -> anyhow::Result<()> {
    let generation = router.metadata.generation;
    // Who the word is ABOUT. A resting word — `Active`, `Standby` — claims
    // that a namespace exists on a machine and is forwarding or deliberately
    // silent, and no tier may claim that on its own behalf: the word has to
    // name the node. The active one, or the first that built it. Everything
    // else is this pass's own conclusion and names nobody, which is exactly
    // what keeps a planner from writing `Active`.
    let speaker = placement
        .as_ref()
        .map(|p| {
            if p.active.is_empty() {
                p.nodes.first().map(String::as_str).unwrap_or_default()
            } else {
                p.active
            }
        })
        .unwrap_or_default();
    let said =
        controller_api::RouterReported::by(speaker, phase, reason, message.clone(), Utc::now());
    let unchanged = router
        .status
        .reported
        .as_ref()
        .is_some_and(|held| held.same_word(&said))
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
    let was = router.status.phase().kind();
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
        .mutate_if::<Router, _>(&name, &router.metadata.uid, |r| {
            r.status.reported = Some(said.clone());
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
                event_type: if phase == RouterPhaseKind::Failed {
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

/// Persist the backend outcome, preserving unreachable planned nodes.
/// Only explicit refusals remove a node from the plan; release debt remains
/// until DestroyRouter is acknowledged.
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
        outcome.reason,
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

/// Previous and outstanding gateway placements absent from the new plan,
/// excluding nodes that acknowledged destruction. Return a sorted unique list.
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

/// Dispatch router ensure and destroy commands through the session-owning replica.
/// A router's gateway nodes can be split across several replica registries.
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
                sole_gateway: router.sole_gateway,
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
