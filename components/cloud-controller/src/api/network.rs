// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! The `providernetworks` and `routers` resources — the two halves of
//! north-south, at the tier where both are declared.
//!
//! They are one file because they are one decision read from two sides. A
//! provider network is what an operator gave away and is an administrator's
//! to declare; a router is a tenant's way out over one, readable by that
//! tenant and written by an operator (see `auth::Class::TenantOperated`).
//! Splitting them would put the refusal that keeps a network from vanishing
//! under a router in a file that cannot see the router.

use super::*;

// --- provider networks ------------------------------------------------------

/// Everyone with a role may look — a provider network is the estate, like a
/// cluster or a floating pool, and a member has to be able to see which one
/// their router could go out over.
pub(super) async fn list_provider_networks(
    State(st): State<ApiState>,
    axum::extract::Query(q): axum::extract::Query<controller_api::ListQuery>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let selector = controller_api::Selector::parse(q.label_selector.as_deref())?;
    let mut items = st.store.list::<ProviderNetwork>().await?;
    items.retain(|n| selector.selects(&n.metadata.labels));
    Ok(Json(
        json!({ "apiVersion": API_VERSION, "kind": "ProviderNetworkList", "items": items }),
    ))
}

pub(super) async fn get_provider_network(
    State(st): State<ApiState>,
    Path(name): Path<String>,
) -> Result<Json<ProviderNetwork>, ApiError> {
    Ok(Json(st.store.get(&name).await?))
}

/// Declare a wire this fleet was given.
///
/// The three checks are all about the addresses, because that is the whole of
/// what can be wrong here that a person would not see: a physnet is a name
/// two sides agree on and this tier cannot verify it (a node claims it, or no
/// node does, and the router stays Pending with a sentence saying which).
pub(super) async fn create_provider_network(
    State(st): State<ApiState>,
    dry: controller_api::DryRun,
    Json(body): Json<ProviderNetwork>,
) -> Result<(StatusCode, Json<ProviderNetwork>), ApiError> {
    check_envelope(&body)?;
    if body.metadata.name.is_empty() {
        return Err(invalid("metadata.name must be set"));
    }
    check_provider_addresses(&body.spec)?;
    if body.spec.physnet.is_empty() {
        return Err(invalid(
            "spec.physnet must be set; it is the name a gateway node claims this network \
             under (`gateway:<physnet>` in its Hello), and a network nobody can claim \
             carries no router",
        ));
    }
    let mut network = ProviderNetwork::declare(&body.metadata.name, body.spec.clone());
    network.metadata.labels = body.metadata.labels.clone();
    let created = match dry.preview(&network) {
        Some(preview) => preview,
        None => st.store.create(&network).await?,
    };
    info!(network = %created.metadata.name, physnet = %created.spec.physnet,
          "provider network declared");
    Ok((StatusCode::CREATED, Json(created)))
}

/// The addresses, checked as a set rather than one at a time.
///
/// `allocation` may not reach outside `cidr`, and the reason is not tidiness:
/// a router's external address is what its SNAT translates to and what the
/// fabric has to route back, so an address the wire does not contain is a
/// tenant with no return path and nothing anywhere saying why. Empty `cidr`
/// switches the check off, which is the lab road — a wire whose subnet nobody
/// wrote down cannot contradict anything.
pub(super) fn check_provider_addresses(
    spec: &controller_api::ProviderNetworkSpec,
) -> Result<(), ApiError> {
    let allocation = common::net::Ipv4Ranges::parse(&spec.allocation)
        .map_err(|e| invalid_field("spec.allocation", e.to_string()))?;
    if spec.cidr.is_empty() {
        return Ok(());
    }
    let wire: common::net::Ipv4Range = spec
        .cidr
        .parse()
        .map_err(|e: common::net::RangeError| invalid_field("spec.cidr", e.to_string()))?;
    for range in allocation.ranges() {
        if !wire.contains(range.first()) || !wire.contains(range.last()) {
            return Err(invalid(format!(
                "spec.allocation entry {range} is not inside spec.cidr {}; a router's external \
                 address has to be on the wire it answers for",
                spec.cidr
            )));
        }
    }
    if !spec.gateway.is_empty() {
        let gateway: std::net::Ipv4Addr = spec
            .gateway
            .parse()
            .map_err(|_| invalid_field("spec.gateway", "is not an IPv4 address"))?;
        if !wire.contains(gateway) {
            return Err(invalid(format!(
                "spec.gateway {gateway} is not inside spec.cidr {}; a default route has to be \
                 reachable from the address the router holds",
                spec.cidr
            )));
        }
    }
    Ok(())
}

/// What an update of a provider network may not change.
///
/// The physnet is what joins this object to an interface out there, and every
/// router already built on it took its address from this allocation. Moving
/// either would move the ground under a running gateway — so the two roads
/// are: edit the description and the labels, or delete the network (which its
/// routers refuse) and declare another.
///
/// `allocation` is deliberately NOT here. Adding a range is how an operator
/// makes room for the next router, and a router that already holds an address
/// keeps it: `status.externalAddr` is written once and read from then on. A
/// range REMOVED under a router that holds an address out of it is the case
/// this leaves open, and it is the honest one — the address goes on working
/// and the operator can see it in `router ls`.
pub(super) const PROVIDER_NETWORK_OWNED: &[Owned] = &[Owned::immutable(
    "spec.physnet",
    "is immutable; it is the name the nodes claim this network under, and changing it \
     would silently move every router on it to a wire nobody claimed",
)];

pub(super) async fn update_provider_network(
    State(st): State<ApiState>,
    Path(name): Path<String>,
    dry: controller_api::DryRun,
    Json(mut body): Json<ProviderNetwork>,
) -> Result<Json<ProviderNetwork>, ApiError> {
    if body.metadata.name != name {
        return Err(invalid("metadata.name does not match the path"));
    }
    let current: ProviderNetwork = st.store.get(&name).await?;
    keep_server_owned(&mut body.metadata, &current.metadata);
    check_owned(&current, &body, PROVIDER_NETWORK_OWNED)?;
    check_provider_addresses(&body.spec)?;
    body.status = current.status.clone();
    controller_api::carry_generation(&current, &mut body)?;
    match dry.preview(&body) {
        Some(preview) => Ok(Json(preview)),
        None => Ok(Json(st.store.update(&body).await?)),
    }
}

/// Refused while a router is on it — the same refusal a floating pool with
/// reservations in it gets, and for a sharper reason: the routers on this
/// network hold addresses out of its allocation, and an allocation that
/// stopped existing would leave them holding addresses out of nothing.
pub(super) async fn delete_provider_network(
    State(st): State<ApiState>,
    Path(name): Path<String>,
) -> Result<controller_api::Removed, ApiError> {
    let _: ProviderNetwork = st.store.get(&name).await?;
    let on_it: Vec<String> = st
        .store
        .list::<controller_api::Router>()
        .await?
        .into_iter()
        .filter(|r| r.spec.provider_network == name)
        .map(|r| r.metadata.name)
        .collect();
    if !on_it.is_empty() {
        return Err(conflict(format!(
            "provider network {name} still carries {} router(s): {}; delete them first",
            on_it.len(),
            on_it.join(", ")
        )));
    }
    st.store.delete::<ProviderNetwork>(&name).await?;
    info!(network = %name, "provider network deleted");
    Ok(controller_api::removed(
        ProviderNetwork::KIND,
        &name,
        controller_api::Removal::Gone,
    ))
}

// --- routers ----------------------------------------------------------------

/// A member sees its own tenant's routers and nobody else's — the read half
/// of `Class::TenantOperated`.
pub(super) async fn list_routers(
    State(st): State<ApiState>,
    caller: Caller,
    role: CallerRole,
    tenant: CallerTenant,
    axum::extract::Query(q): axum::extract::Query<controller_api::ListQuery>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let selector = controller_api::Selector::parse(q.label_selector.as_deref())?;
    let who = Grant::new(caller, role, tenant).listing(q.tenant.as_deref());
    let mut items = st.store.list::<controller_api::Router>().await?;
    items.retain(|r| {
        who.keeps(Some(r.spec.tenant.as_str())) && selector.selects(&r.metadata.labels)
    });
    Ok(Json(
        json!({ "apiVersion": API_VERSION, "kind": "RouterList", "items": items }),
    ))
}

pub(super) async fn get_router(
    State(st): State<ApiState>,
    Path(name): Path<String>,
    caller: Caller,
    role: CallerRole,
    tenant: CallerTenant,
) -> Result<Json<controller_api::Router>, ApiError> {
    let router: controller_api::Router = st.store.get(&name).await?;
    Grant::new(caller, role, tenant)
        .allows(Scope::of(Some(router.spec.tenant.as_str())), Verb::Read)?;
    Ok(Json(router))
}

/// Give a tenant a way out.
///
/// Everything a router needs that is not a placement is checked here, because
/// the alternative is a Pending object with a sentence about a name the client
/// mistyped: the tenant exists, the provider network exists, the routed
/// subnets named are that tenant's, and no other router of this tenant is
/// already on this network.
///
/// The last one is a real constraint and not tidiness. Two routers of one
/// tenant on one provider network would both hold a SNAT rule for the same
/// overlay, both announce, and the tenant's return traffic would land on
/// whichever the fabric preferred — with conntrack on the other. One way out
/// per tenant per wire; a tenant that wants two ways out has two provider
/// networks.
pub(super) async fn create_router(
    State(st): State<ApiState>,
    caller: Caller,
    role: CallerRole,
    tenant: CallerTenant,
    dry: controller_api::DryRun,
    Json(body): Json<controller_api::Router>,
) -> Result<(StatusCode, Json<controller_api::Router>), ApiError> {
    check_envelope(&body)?;
    if body.metadata.name.is_empty() {
        return Err(invalid("metadata.name must be set"));
    }
    let grant = Grant::new(caller, role, tenant);
    let owner = grant
        .tenant_for_create(Some(body.spec.tenant.clone()))
        .ok_or_else(|| invalid("spec.tenant must name a tenant"))?;
    grant.allows(Scope::of(Some(owner.as_str())), Verb::Write)?;
    check_tenant(&st, &owner).await?;
    if body.spec.provider_network.is_empty() {
        return Err(invalid(
            "spec.providerNetwork must name the network this router goes out over; \
             `meister providernetwork ls` says which there are",
        ));
    }
    let network: ProviderNetwork =
        st.store
            .get(&body.spec.provider_network)
            .await
            .map_err(|_| {
                invalid(format!(
                    "no provider network called {}",
                    body.spec.provider_network
                ))
            })?;

    let subnets = floating::all_subnets(&st.store).await?;
    for named in &body.spec.routed_subnets {
        let Some(subnet) = subnets.iter().find(|s| &s.metadata.name == named) else {
            return Err(invalid(format!("no routed subnet called {named}")));
        };
        if subnet.spec.tenant != owner {
            return Err(forbidden(format!(
                "routed subnet {named} belongs to {}, not to {owner}",
                subnet.spec.tenant
            )));
        }
    }

    let existing = st.store.list::<controller_api::Router>().await?;
    if let Some(other) = other_router_on(
        &existing,
        &body.metadata.name,
        &owner,
        &network.metadata.name,
    ) {
        return Err(conflict(format!(
            "{owner} already has a router on {}: {}",
            network.metadata.name, other.metadata.name
        )));
    }

    let mut router = controller_api::Router::declare(
        &body.metadata.name,
        controller_api::RouterSpec {
            tenant: owner.clone(),
            ..body.spec.clone()
        },
    );
    router.metadata.labels = body.metadata.labels.clone();
    let created = match dry.preview(&router) {
        Some(preview) => preview,
        None => st.store.create(&router).await?,
    };
    info!(router = %created.metadata.name, tenant = %owner,
          network = %created.spec.provider_network, snat = created.spec.snat,
          "router created");
    Ok((StatusCode::CREATED, Json(created)))
}

/// Is there ALREADY another way out for this tenant on this wire?
///
/// "Another" is the word that matters, and it is the whole of the function.
/// A router of this very name is not a second way out — it is this one — so a
/// POST that names it falls through to the store, the store answers
/// AlreadyExists, and `meister apply` reads that as "replace instead of
/// create". Without the name cut a router could never be applied twice, and
/// changing what it announces meant deleting it and losing its address. Found
/// in the lab, on the first `apply` of an edited router.
///
/// The rule itself stands: one way out per tenant per wire (see
/// `create_router`), because two would be two addresses on one L2 for one
/// overlay and a fabric that has to choose between them.
fn other_router_on<'a>(
    existing: &'a [controller_api::Router],
    name: &str,
    tenant: &str,
    network: &str,
) -> Option<&'a controller_api::Router> {
    existing.iter().find(|r| {
        r.metadata.name != name && r.spec.tenant == tenant && r.spec.provider_network == network
    })
}

/// What an update of a router may not change.
///
/// The tenant and the provider network are what the router IS — its overlay
/// leg and its external leg — and an address is already cut out of that
/// network's allocation for it. The two that stay editable are the two an
/// operator changes their mind about: `snat` and `routedSubnets`, which are
/// what it DOES, and both take effect on the next pass.
pub(super) const ROUTER_OWNED: &[Owned] = &[
    Owned::immutable(
        "spec.tenant",
        "is immutable; a router is the way out of the overlay it was made for",
    ),
    Owned::immutable(
        "spec.providerNetwork",
        "is immutable; the router holds an address out of that network's allocation. \
         Delete it and make another",
    ),
];

pub(super) async fn update_router(
    State(st): State<ApiState>,
    Path(name): Path<String>,
    caller: Caller,
    role: CallerRole,
    tenant: CallerTenant,
    dry: controller_api::DryRun,
    Json(mut body): Json<controller_api::Router>,
) -> Result<Json<controller_api::Router>, ApiError> {
    if body.metadata.name != name {
        return Err(invalid("metadata.name does not match the path"));
    }
    let current: controller_api::Router = st.store.get(&name).await?;
    Grant::new(caller, role, tenant)
        .allows(Scope::of(Some(current.spec.tenant.as_str())), Verb::Write)?;
    keep_server_owned(&mut body.metadata, &current.metadata);
    check_owned(&current, &body, ROUTER_OWNED)?;
    body.status = current.status.clone();
    controller_api::carry_generation(&current, &mut body)?;
    match dry.preview(&body) {
        Some(preview) => Ok(Json(preview)),
        None => Ok(Json(st.store.update(&body).await?)),
    }
}

/// Marked, not removed — and the floating addresses pointed at it are not a
/// refusal.
///
/// The addresses are deliberate, and it is the same argument
/// `delete_routed_subnet` makes: taking the router away NARROWS what a tenant
/// can reach — the DNAT rules that were derived from those reservations
/// simply stop being derived, the addresses stay reserved, and pointing them
/// at another router is one patch. A refusal here would make deleting a
/// router a two-step dance through somebody else's objects for no safety at
/// all.
///
/// The marking is what changed when the router started travelling down a
/// session. A cloud object dropped here and now would leave the cluster's
/// copy standing with nobody left to tell it to go, and the netns forwarding
/// for a tenant who has deleted their router. So this sets the timestamp and
/// `reconcile::teardown` finishes it once the cluster has stopped naming the
/// router — the same promise `vm rm` makes.
pub(super) async fn delete_router(
    State(st): State<ApiState>,
    Path(name): Path<String>,
    caller: Caller,
    role: CallerRole,
    tenant: CallerTenant,
) -> Result<controller_api::Removed, ApiError> {
    let current: controller_api::Router = st.store.get(&name).await?;
    Grant::new(caller, role, tenant)
        .allows(Scope::of(Some(current.spec.tenant.as_str())), Verb::Write)?;
    // Never handed to a cluster: nothing out there is holding a netns for it,
    // so there is nothing to wait for and the object goes now. It is also the
    // answer that keeps a router whose cluster never existed from becoming
    // undeletable.
    if current.status.cluster.is_empty() {
        st.store.delete::<controller_api::Router>(&name).await?;
        info!(router = %name, tenant = %current.spec.tenant, "router deleted (never placed)");
        return Ok(controller_api::removed(
            controller_api::Router::KIND,
            &name,
            controller_api::Removal::Gone,
        ));
    }
    st.store
        .mutate::<controller_api::Router, _>(&name, |r| {
            if r.metadata.deletion_timestamp.is_none() {
                r.metadata.deletion_timestamp = Some(chrono::Utc::now());
            }
        })
        .await?;
    info!(router = %name, tenant = %current.spec.tenant, cluster = %current.status.cluster,
          node = %current.status.active_node, "router marked for teardown");
    Ok(controller_api::removed(
        controller_api::Router::KIND,
        &name,
        controller_api::Removal::Going,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(cidr: &str, gateway: &str, allocation: &[&str]) -> controller_api::ProviderNetworkSpec {
        controller_api::ProviderNetworkSpec {
            physnet: "ext".into(),
            cidr: cidr.into(),
            gateway: gateway.into(),
            allocation: allocation.iter().map(|s| s.to_string()).collect(),
            description: String::new(),
        }
    }

    /// The check that decides whether a router has a return path at all: an
    /// external address outside the wire is a tenant whose replies come back
    /// to nobody, and nothing downstream can notice — the node builds the
    /// netns, the rules render, and the packets go into the dark.
    #[test]
    fn an_allocation_outside_the_wire_is_refused_with_the_range_named() {
        check_provider_addresses(&spec(
            "198.51.100.0/24",
            "198.51.100.1",
            &["198.51.100.100-198.51.100.200"],
        ))
        .expect("inside");
        let out = check_provider_addresses(&spec(
            "198.51.100.0/24",
            "198.51.100.1",
            &["198.51.100.200-198.51.101.10"],
        ))
        .expect_err("half of it is on the next wire");
        assert!(
            out.message().contains("198.51.100.0/24"),
            "{}",
            out.message()
        );

        // And the gateway, which is the other half of the same sentence.
        let away = check_provider_addresses(&spec("198.51.100.0/24", "10.0.0.1", &[]))
            .expect_err("not reachable from the address the router holds");
        assert!(away.message().contains("10.0.0.1"), "{}", away.message());
    }

    /// A wire whose subnet nobody wrote down cannot contradict anything, and
    /// that is the lab road: an operator who has an interface and a range and
    /// no opinion about the prefix gets a network rather than a refusal.
    #[test]
    fn a_network_with_no_cidr_checks_only_that_the_ranges_parse() {
        check_provider_addresses(&spec("", "", &["192.0.2.10-192.0.2.20"])).expect("parses");
        let bad = check_provider_addresses(&spec("", "", &["192.0.2.10-nonsense"]))
            .expect_err("does not parse");
        // The field is named on the error rather than in the sentence — a
        // form highlights `spec.allocation`, a person reads the sentence,
        // and the sentence is the range parser's own.
        assert!(
            bad.message().contains("is not an address range"),
            "{}",
            bad.message()
        );
    }

    /// One way out per tenant per wire — and a router is not its own
    /// competitor.
    ///
    /// The second half is what the lab found: `meister apply` POSTs first and
    /// falls back to a PUT when the server says AlreadyExists, so a guard
    /// that fired on the object's own name turned every re-apply into a
    /// conflict. Changing what a router announces then meant deleting it,
    /// which means losing the address it holds.
    #[test]
    fn a_router_is_not_its_own_second_way_out() {
        let router = |name: &str, tenant: &str, network: &str| {
            controller_api::Router::declare(
                name,
                controller_api::RouterSpec {
                    tenant: tenant.into(),
                    provider_network: network.into(),
                    ..Default::default()
                },
            )
        };
        let held = [
            router("lab-out", "lab", "ext"),
            router("ops-out", "ops", "ext"),
        ];

        assert!(
            other_router_on(&held, "lab-out", "lab", "ext").is_none(),
            "applying the same router again is not a second way out"
        );
        assert_eq!(
            other_router_on(&held, "lab-second", "lab", "ext").map(|r| r.metadata.name.as_str()),
            Some("lab-out"),
            "but a second NAME on the same wire is exactly what the rule refuses"
        );
        // Another tenant on the same wire, and the same tenant on another
        // wire, are both fine.
        assert!(other_router_on(&held, "acme-out", "acme", "ext").is_none());
        assert!(other_router_on(&held, "lab-dmz", "lab", "dmz").is_none());
    }
}
