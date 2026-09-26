// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Resolve router placement, external address, prefixes and rules at cloud scope.
//! `CreateRouter` carries those facts and the provider network to the cluster,
//! which selects nodes and the active instance. Cluster reports alone supply
//! the cloud router's phase, nodes and activeNode; dispatch is not readiness.

use super::*;

use controller_api::network;
use controller_api::{ProviderNetwork, Router, RouterPhaseKind, RouterReason, Tenant};

/// One pass over the routers of this cloud.
pub(super) async fn reconcile_routers(
    store: &EtcdStore,
    registry: &SessionRegistry,
    sessions: &HashSet<String>,
) -> anyhow::Result<()> {
    let routers = store.list::<Router>().await?;
    telemetry::metrics::objects().set_count(Router::KIND, routers.len() as i64);
    if routers.is_empty() {
        return Ok(());
    }
    let networks = store.list::<ProviderNetwork>().await?;
    let clusters = store.list::<Cluster>().await?;
    let tenants = store.list::<Tenant>().await?;
    let subnets = controller_api::floating::all_subnets(store).await?;
    let floating = controller_api::floating::all_reservations(store).await?;

    for router in routers {
        let name = router.metadata.name.clone();
        let held = store.list::<Router>().await?;
        let outcome = if router.is_deleting() {
            teardown(store, registry, &router).await
        } else {
            reconcile_router(
                store,
                registry,
                router,
                &Estate {
                    networks: &networks,
                    clusters: &clusters,
                    tenants: &tenants,
                    subnets: &subnets,
                    floating: &floating,
                    held: &held,
                    sessions,
                },
            )
            .await
        };
        if let Err(e) = outcome {
            warn!(router = %name, error = format!("{e:#}"), "router reconcile failed");
        }
    }
    Ok(())
}

/// Request cluster teardown while a complete router inventory still names the UID.
/// The current check accepts absence without comparing report age to dispatch
/// or deletion time; it therefore does not establish the VM path's freshness guarantee.
async fn teardown(
    store: &EtcdStore,
    registry: &SessionRegistry,
    router: &Router,
) -> anyhow::Result<()> {
    let name = router.metadata.name.clone();
    let uid = router.metadata.uid.clone();
    let cluster = router.status.cluster.clone();
    if cluster.is_empty() {
        // Never handed to anybody: there is nothing out there to tear down.
        store.delete::<Router>(&name).await?;
        info!(router = %name, "router deleted (never placed)");
        return Ok(());
    }

    let report = registry.report(&cluster);
    // While the cluster still names the router — and while it has told us
    // nothing current, which for this decision is the same thing — the
    // teardown is what there is to do.
    let still_there = report
        .as_ref()
        .and_then(|r| r.routers.as_ref())
        .is_none_or(|routers| routers.contains(&uid));
    if still_there {
        let op = cloud_command::Op::DeleteRouter(proto::DeleteRouter {
            name: name.clone(),
            uid,
        });
        match registry.send_command(&cluster, "", op).await {
            Ok(Ack::Acked(_)) => info!(router = %name, cluster = %cluster, "delete dispatched"),
            Ok(Ack::Rejected(refusal)) => {
                warn!(router = %name, cluster = %cluster, error = %refusal.message,
                      "cluster refused the delete")
            }
            Err(e) => warn!(router = %name, cluster = %cluster, error = format!("{e:#}"),
                            "delete could not be delivered"),
        }
        return Ok(());
    }
    store.delete::<Router>(&name).await?;
    info!(router = %name, cluster = %cluster, "router deleted");
    Ok(())
}

/// Everything one router's pass reads, listed once for the whole pass.
struct Estate<'a> {
    networks: &'a [ProviderNetwork],
    clusters: &'a [Cluster],
    tenants: &'a [Tenant],
    subnets: &'a [controller_api::RoutedSubnet],
    floating: &'a [controller_api::FloatingIp],
    /// The routers as they stand, for the address cut. Re-read per router
    /// rather than reused, because the previous router in this very loop may
    /// have taken an address.
    held: &'a [Router],
    /// The clusters with a session on THIS replica. A router is only handed
    /// to a cluster this process can actually reach; the others are somebody
    /// else's pass, and the same one every five seconds.
    sessions: &'a HashSet<String>,
}

/// Choose a cluster whose capability catalogue includes the required physnet.
/// Prefer the fewest existing routers, then the cluster name for deterministic
/// ties. The selected cluster chooses its own router nodes and active instance.
pub(crate) fn cluster_for<'a>(
    physnet: &str,
    clusters: &'a [Cluster],
    held: &[Router],
) -> Option<&'a Cluster> {
    let mut load: BTreeMap<&str, usize> = BTreeMap::new();
    for router in held {
        if !router.status.cluster.is_empty() {
            *load.entry(router.status.cluster.as_str()).or_insert(0) += 1;
        }
    }
    clusters
        .iter()
        .filter(|c| c.spec.schedulable && !c.spec.drain)
        .filter(|c| {
            common::capability::gateway_physnets(&c.status.capacity.capabilities).contains(&physnet)
        })
        .min_by_key(|c| {
            (
                load.get(c.metadata.name.as_str()).copied().unwrap_or(0),
                c.metadata.name.clone(),
            )
        })
}

/// Why no cluster will serve this router, in the words that send somebody to
/// the right fleet.
fn cluster_sentence(physnet: &str, clusters: &[Cluster]) -> String {
    let holding: Vec<&str> = clusters
        .iter()
        .filter(|c| {
            common::capability::gateway_physnets(&c.status.capacity.capabilities).contains(&physnet)
        })
        .map(|c| c.metadata.name.as_str())
        .collect();
    if holding.is_empty() {
        return format!(
            "no cluster has a node giving an interface away for physnet {physnet}; \
             a gateway node says so with `[network.provider] physnets = {{ {physnet} = \"…\" }}`"
        );
    }
    format!(
        "every cluster holding physnet {physnet} is cordoned or draining: {}",
        holding.join(", ")
    )
}

async fn reconcile_router(
    store: &EtcdStore,
    registry: &SessionRegistry,
    router: Router,
    estate: &Estate<'_>,
) -> anyhow::Result<()> {
    let name = router.metadata.name.clone();
    let generation = router.metadata.generation;
    // A spec that moved withdraws the refusals: they are evidence about a
    // router nobody has changed, and somebody has now. See
    // `RouterStatus::refused`.
    let cleared_refusals = router.status.observed_generation != generation;

    let Some(network) = estate
        .networks
        .iter()
        .find(|n| n.metadata.name == router.spec.provider_network)
    else {
        // Cannot happen through the API — `create_router` refuses a name that
        // is not there — so this is the network having been deleted under a
        // router, which its own delete handler refuses. Said rather than
        // assumed away.
        return note(
            store,
            &router,
            RouterPhaseKind::Pending,
            RouterReason::Unplaced,
            format!(
                "provider network {} does not exist",
                router.spec.provider_network
            ),
            None,
        )
        .await;
    };

    // The tenant's overlay, resolved where tenants live. The same road
    // `CreateVm.vni` travels and the same reason: no tier below this one has
    // to know what a tenant is.
    let vni = estate
        .tenants
        .iter()
        .find(|t| t.metadata.name == router.spec.tenant)
        .and_then(|t| t.spec.vni);
    if router.spec.vni != vni && vni.is_some() {
        store
            .mutate::<Router, _>(&name, |r| r.spec.vni = vni)
            .await?;
    }

    // Recheck the external address on every pass to resolve concurrent allocation.
    // The lowest-named holder keeps a duplicate address; other holders release it.
    // Both tiers use `network::settle_external_addr` for the same rule.
    let mut router = network::settle_external_addr(store, router, network).await?;

    // The derived halves: the prefixes this router announces, and the rules
    // — which carry those prefixes as `routed` entries, because the contract
    // has no other field for them.
    let announced: Vec<String> = router
        .spec
        .routed_subnets
        .iter()
        .filter_map(|named| {
            estate
                .subnets
                .iter()
                .find(|s| &s.metadata.name == named)
                .map(|s| s.spec.cidr.clone())
        })
        .filter(|cidr| !cidr.is_empty())
        .collect();
    let nats = network::nat_rules(&router, estate.floating, &announced);

    let decision = if router.status.external_addr.is_empty() {
        Err(format!(
            "no free address left in the allocation of provider network {} ({})",
            network.metadata.name,
            network.spec.allocation.join(", ")
        ))
    } else if vni.is_none() {
        Err(format!(
            "tenant {} has no overlay, so there is no inside wire to put a router on",
            router.spec.tenant
        ))
    } else {
        match bound_cluster(&router, &network.spec.physnet, estate) {
            Some(cluster) => Ok(cluster),
            None => Err(cluster_sentence(&network.spec.physnet, estate.clusters)),
        }
    };

    let cluster = match &decision {
        Ok(cluster) => cluster.clone(),
        Err(_) => String::new(),
    };
    // The derived halves and the binding, and NOT the phase: from here on the
    // phase is the cluster's answer and this pass has no business writing one
    // — see `ingest_routers`. The one exception is the arm below that has no
    // cluster at all, where there is nobody to answer and Pending is the
    // whole truth.
    let moved = router.status.cluster != cluster
        || router.status.nats != nats
        || router.status.announced != announced
        || router.status.observed_generation != generation
        || cleared_refusals;
    if moved {
        router = store
            .mutate::<Router, _>(&name, |r| {
                r.status.cluster = cluster.clone();
                r.status.nats = nats.clone();
                r.status.announced = announced.clone();
                r.status.observed_generation = generation;
                if cleared_refusals {
                    r.status.refused.clear();
                }
            })
            .await?;
    }

    let cluster = match decision {
        Ok(cluster) => cluster,
        Err(message) => {
            // The planner's refusal: nowhere to put it, and the sentence
            // says which of the four walls it is.
            return note(
                store,
                &router,
                RouterPhaseKind::Pending,
                RouterReason::Unplaced,
                message,
                None,
            )
            .await;
        }
    };
    if !estate.sessions.contains(&cluster) {
        // Somebody else's replica holds that session. Nothing is written: the
        // decision is in the store, and the pass that can reach the cluster
        // makes the same one out of it five seconds from now.
        debug!(router = %name, cluster = %cluster, "no session here for this router's cluster");
        return Ok(());
    }
    dispatch(
        store, registry, &cluster, &router, network, &nats, &announced,
    )
    .await?;
    // This records the rendered plan. Dispatch also returns Ok after logging
    // a rejected or undeliverable command, so this is not delivery evidence.
    stamp_floating(store, &router, estate.floating, &nats).await;
    Ok(())
}

/// Whether a rendered NAT rule matches this tenant's floating address and router
/// and its generation has not yet been stamped. This predicate checks the plan;
/// it does not establish command acknowledgement.
pub(crate) fn carried_down(
    ip: &controller_api::FloatingIp,
    router: &Router,
    nats: &[controller_api::NatRule],
) -> bool {
    ip.spec.router == router.metadata.name
        && ip.spec.tenant == router.spec.tenant
        && ip.status.observed_generation < ip.metadata.generation
        && nats.iter().any(|n| {
            n.kind == controller_api::NatKind::DnatAndSnat && n.external_ip == ip.spec.address
        })
}

async fn stamp_floating(
    store: &EtcdStore,
    router: &Router,
    floating: &[controller_api::FloatingIp],
    nats: &[controller_api::NatRule],
) {
    for ip in floating.iter().filter(|ip| carried_down(ip, router, nats)) {
        let generation = ip.metadata.generation;
        let name = ip.metadata.name.clone();
        if let Err(e) = store
            .mutate::<controller_api::FloatingIp, _>(&name, |f| {
                f.status.observed_generation = f.status.observed_generation.max(generation);
            })
            .await
        {
            // Debug for the reason `stamp_addresses` gives: the command went
            // out, which is the fact that matters, and a bookkeeping write
            // that lost is made again by the next pass.
            debug!(floating_ip = %name, error = format!("{e:#}"),
                   "could not record that this address was carried down");
        }
    }
}

/// Keep the current cluster while it remains eligible.
/// Least-load ranking selects only a new binding; changing an eligible binding
/// would tear down a working router whenever unrelated load changed.
fn bound_cluster(router: &Router, physnet: &str, estate: &Estate<'_>) -> Option<String> {
    let held = &router.status.cluster;
    if !held.is_empty()
        && let Some(cluster) = estate.clusters.iter().find(|c| &c.metadata.name == held)
        && cluster.spec.schedulable
        && !cluster.spec.drain
        && common::capability::gateway_physnets(&cluster.status.capacity.capabilities)
            .contains(&physnet)
    {
        return Some(held.clone());
    }
    cluster_for(physnet, estate.clusters, estate.held).map(|c| c.metadata.name.clone())
}

/// Hand the router to its cluster. Idempotent by uid down there, so this is
/// equally the first handover, the repair after a cluster lost the object, and
/// the way a floating address somebody pointed at this router reaches the tier
/// that can render a rule for it.
async fn dispatch(
    store: &EtcdStore,
    registry: &SessionRegistry,
    cluster: &str,
    router: &Router,
    network: &ProviderNetwork,
    nats: &[controller_api::NatRule],
    announced: &[String],
) -> anyhow::Result<()> {
    let name = router.metadata.name.clone();
    let op = cloud_command::Op::CreateRouter(proto::CreateRouter {
        name: name.clone(),
        uid: router.metadata.uid.clone(),
        spec_json: serde_json::to_string(&router.spec)?,
        network_name: network.metadata.name.clone(),
        network_json: serde_json::to_string(&network.spec)?,
        external_addr: router.status.external_addr.clone(),
        nats: nats
            .iter()
            .map(|r| proto::NatRule {
                kind: r.kind.as_str().to_string(),
                external_ip: r.external_ip.clone(),
                logical_ip: r.logical_ip.clone(),
            })
            .collect(),
        announced: announced.to_vec(),
    });
    match registry.send_command(cluster, "", op).await {
        Ok(Ack::Acked(_)) => {
            // Anticipation never overwrites observation: only a router nobody
            // has reported on yet is moved by a dispatch, and the sentence
            // that named the missing message goes with it.
            if router.status.phase().kind() == RouterPhaseKind::Pending
                && router.status.nodes.is_empty()
            {
                store
                    .mutate::<Router, _>(&name, |r| {
                        // This tier's own anticipation, so it names nobody —
                        // which is also what stops it ever being read as a
                        // router that is up.
                        r.status.reported = Some(controller_api::RouterReported::here(
                            RouterPhaseKind::Provisioning,
                            RouterReason::Dispatched,
                            Some(format!("{cluster} was told")),
                            Utc::now(),
                        ));
                    })
                    .await?;
            }
            debug!(router = %name, cluster, nats = nats.len(), "router dispatched");
        }
        Ok(Ack::Rejected(refusal)) => {
            let message = refusal.message;
            warn!(router = %name, cluster, error = %message, "cluster refused the router");
            note(
                store,
                router,
                RouterPhaseKind::Failed,
                RouterReason::Refused,
                message,
                None,
            )
            .await?;
        }
        // A broken session is a fact about the session. Nothing is written,
        // and the next pass derives the same decision from the same state.
        Err(e) => warn!(router = %name, cluster, error = format!("{e:#}"),
                        "router could not be delivered"),
    }
    Ok(())
}

/// The short form of the write above, for the arms that decide nothing else.
async fn note(
    store: &EtcdStore,
    router: &Router,
    phase: RouterPhaseKind,
    reason: RouterReason,
    message: String,
    cluster: Option<&str>,
) -> anyhow::Result<()> {
    if router.status.phase().kind() == phase
        && router.status.phase().message() == Some(message.as_str())
    {
        return Ok(());
    }
    let name = router.metadata.name.clone();
    let cluster = cluster.map(str::to_string);
    let now = Utc::now();
    store
        .mutate::<Router, _>(&name, |r| {
            r.status.reported = Some(controller_api::RouterReported::here(
                phase,
                reason,
                Some(message.clone()),
                now,
            ));
            if let Some(cluster) = &cluster {
                r.status.cluster = cluster.clone();
            }
        })
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cluster(name: &str, physnets: &[&str], schedulable: bool) -> Cluster {
        let mut c = Cluster::declare(
            name,
            controller_api::ClusterSpec {
                schedulable,
                ..Default::default()
            },
        );
        c.status.capacity.capabilities = physnets
            .iter()
            .map(|p| format!("network/{}", common::capability::gateway_claim(p)))
            .collect();
        c
    }

    fn on(cluster: &str) -> Router {
        let mut r = Router::declare("r", controller_api::RouterSpec::default());
        r.status.cluster = cluster.into();
        r
    }

    /// D-B2: an address a ROUTER translates gets the same stamp an address a
    /// `CreateVm` carries down does.
    ///
    /// Without it `floatingip ls` said `pending` in the `APPLIED` column for
    /// an address that was answering pings from outside, with the DNAT rule in
    /// place and the counters running. Cosmetic, and in front of an audience
    /// it reads as "broken".
    #[test]
    fn a_floating_address_a_router_carried_down_is_applied() {
        let mut router = Router::declare(
            "lab-out",
            controller_api::RouterSpec {
                tenant: "lab".into(),
                ..Default::default()
            },
        );
        router.metadata.name = "lab-out".into();
        let mut ip = controller_api::FloatingIp::declare(
            "10.128.1.217",
            controller_api::FloatingIpSpec {
                tenant: "lab".into(),
                address: "10.128.1.217".into(),
                router: "lab-out".into(),
                internal_address: "10.30.0.2".into(),
                ..Default::default()
            },
        );
        ip.metadata.generation = 1;
        let nats = network::nat_rules(&router, std::slice::from_ref(&ip), &[]);
        assert!(
            carried_down(&ip, &router, &nats),
            "the rule for it went down with this very EnsureRouter"
        );

        // Once stamped, nothing more to say. This runs every five seconds per
        // router.
        let mut stamped = ip.clone();
        stamped.status.observed_generation = 1;
        assert!(!carried_down(&stamped, &router, &nats));

        // An address with no inside address renders no rule, so it is not
        // applied — which is the truth and not a gap.
        let mut half = ip.clone();
        half.spec.internal_address.clear();
        let nats = network::nat_rules(&router, std::slice::from_ref(&half), &[]);
        assert!(!carried_down(&half, &router, &nats));

        // And an address of another tenant, or one pointed at another router,
        // is never this router's to stamp.
        let mut elsewhere = ip.clone();
        elsewhere.spec.router = "acme-out".into();
        let nats = network::nat_rules(&router, std::slice::from_ref(&ip), &[]);
        assert!(!carried_down(&elsewhere, &router, &nats));
        let mut other_tenant = ip.clone();
        other_tenant.spec.tenant = "acme".into();
        assert!(!carried_down(&other_tenant, &router, &nats));
    }

    /// Concurrent duplicate external-address claims converge on the lowest-named
    /// holder, using the same arbitration rule as the cluster tier.
    #[test]
    fn two_routers_that_both_wrote_the_same_external_address_do_not_both_keep_it() {
        use controller_api::network::{AddressClaim, claim_external_addr};

        let net = ProviderNetwork::declare(
            "ext",
            controller_api::ProviderNetworkSpec {
                physnet: "ext".into(),
                cidr: "198.51.100.0/24".into(),
                gateway: "198.51.100.1".into(),
                allocation: vec!["198.51.100.10-198.51.100.20".into()],
                description: String::new(),
            },
        );
        let holding = |name: &str, address: &str| {
            let mut r = Router::declare(
                name,
                controller_api::RouterSpec {
                    provider_network: "ext".into(),
                    ..Default::default()
                },
            );
            r.status.external_addr = address.into();
            r
        };

        // The stale snapshot both replicas cut out of: nobody holds anything.
        let stale: Vec<Router> = vec![holding("acme-out", ""), holding("beta-out", "")];
        assert_eq!(
            claim_external_addr(&stale[0], &net, &stale),
            AddressClaim::Take("198.51.100.10/24".to_string())
        );
        assert_eq!(
            claim_external_addr(&stale[1], &net, &stale),
            AddressClaim::Take("198.51.100.10/24".to_string()),
            "out of the same snapshot, the same address -- which is the race"
        );

        // Both wrote it. The listing as it now stands is what decides.
        let mut held = vec![
            holding("acme-out", "198.51.100.10/24"),
            holding("beta-out", "198.51.100.10/24"),
        ];
        assert_eq!(
            claim_external_addr(&held[0], &net, &held),
            AddressClaim::Keep
        );
        assert_eq!(
            claim_external_addr(&held[1], &net, &held),
            AddressClaim::Yield,
            "the higher name gives the address back, on this tier too"
        );
        held[1].status.external_addr.clear();
        assert_eq!(
            held.iter()
                .filter(|r| r.status.external_addr == "198.51.100.10/24")
                .count(),
            1,
            "exactly one router answers for the address"
        );

        // And the loser is not left without one: the next pass takes the next
        // free address and both are settled from then on.
        assert_eq!(
            claim_external_addr(&held[1], &net, &held),
            AddressClaim::Take("198.51.100.11/24".to_string())
        );
        held[1].status.external_addr = "198.51.100.11/24".into();
        assert_eq!(
            claim_external_addr(&held[0], &net, &held),
            AddressClaim::Keep
        );
        assert_eq!(
            claim_external_addr(&held[1], &net, &held),
            AddressClaim::Keep
        );
    }

    /// Decision 4's first half: the cluster is the one whose nodes gave an
    /// interface away for this wire, and among those the least loaded — by
    /// name where they tie, so that three leaderless replicas reading one
    /// store reach one answer.
    #[test]
    fn a_router_goes_to_a_cluster_that_really_holds_that_wire() {
        let fleet = [
            cluster("cluster-b", &["ext"], true),
            cluster("cluster-a", &["ext"], true),
            cluster("cluster-dmz", &["dmz"], true),
            cluster("cluster-cordoned", &["ext"], false),
        ];
        assert_eq!(
            cluster_for("ext", &fleet, &[]).map(|c| c.metadata.name.as_str()),
            Some("cluster-a"),
            "the tie goes to the name"
        );
        assert_eq!(
            cluster_for("ext", &fleet, &[on("cluster-a")]).map(|c| c.metadata.name.as_str()),
            Some("cluster-b"),
            "and the load moves it"
        );
        assert!(
            cluster_for("public", &fleet, &[]).is_none(),
            "a wire nobody holds is nobody's"
        );
    }

    /// Where a router goes the first time is a question about load; where it
    /// STAYS is not. A binding that followed the load would tear a tenant's
    /// netns down on one fleet and build it on another because somebody else
    /// created a router.
    #[test]
    fn a_router_stays_on_the_fleet_it_is_on_while_that_fleet_can_serve_it() {
        let sessions = HashSet::new();
        let bound = |router: &Router, clusters: &[Cluster]| {
            bound_cluster(
                router,
                "ext",
                &Estate {
                    networks: &[],
                    clusters,
                    tenants: &[],
                    subnets: &[],
                    floating: &[],
                    held: &[],
                    sessions: &sessions,
                },
            )
        };

        let both = [
            cluster("cluster-a", &["ext"], true),
            cluster("cluster-b", &["ext"], true),
        ];
        let mut router = Router::declare("r", controller_api::RouterSpec::default());
        assert_eq!(
            bound(&router, &both).as_deref(),
            Some("cluster-a"),
            "the first time, the least loaded — by name where they tie"
        );

        // On b now: it does not move because a is emptier.
        router.status.cluster = "cluster-b".into();
        assert_eq!(bound(&router, &both).as_deref(), Some("cluster-b"));

        // It moves when the fleet it is on stops being able to serve it, and
        // only then — cordoned, or having given the wire back.
        let cordoned = [
            cluster("cluster-a", &["ext"], true),
            cluster("cluster-b", &["ext"], false),
        ];
        assert_eq!(bound(&router, &cordoned).as_deref(), Some("cluster-a"));
        let no_wire = [
            cluster("cluster-a", &["ext"], true),
            cluster("cluster-b", &["dmz"], true),
        ];
        assert_eq!(bound(&router, &no_wire).as_deref(), Some("cluster-a"));
        // And a fleet that has gone away entirely.
        let alone = [cluster("cluster-a", &["ext"], true)];
        assert_eq!(bound(&router, &alone).as_deref(), Some("cluster-a"));
    }

    /// Two different operator problems, two different sentences: nobody gave
    /// this wire away anywhere, or the fleet that did is being emptied.
    #[test]
    fn a_router_with_nowhere_to_go_says_which_of_the_two_it_is() {
        let nowhere = cluster_sentence("ext", &[cluster("cluster-a", &["dmz"], true)]);
        assert!(nowhere.contains("network.provider"), "{nowhere}");

        let cordoned = cluster_sentence("ext", &[cluster("cluster-a", &["ext"], false)]);
        assert!(cordoned.contains("cordoned or draining"), "{cordoned}");
        assert!(cordoned.contains("cluster-a"), "{cordoned}");
    }
}
