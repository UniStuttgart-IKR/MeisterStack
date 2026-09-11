// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! The `providernetworks` and `routers` resources, one tier down.
//!
//! Both are served here and not only at the cloud, and the reason is the same
//! one `vms` and `volumes` are: this is the tier that BUILDS the thing. The
//! reconciler here picks the gateway nodes, cuts the external address and
//! sends `EnsureRouter`; a router that could not be read or written at this
//! tier would be a router nobody could look at from the machine it is on, and
//! the standalone road — a cluster with no cloud above it, which is how this
//! controller ran before M4 and how it goes on running when the cloud is away
//! — would have no way to make one at all.
//!
//! What is NOT here is the tenant directory: `spec.tenant` is a label at this
//! tier, as it is on a `Vm`, and it is not checked against anything. The
//! cloud is where a tenant exists.

use super::*;

// --- provider networks ------------------------------------------------------

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

pub(super) async fn create_provider_network(
    State(st): State<ApiState>,
    dry: controller_api::DryRun,
    Json(body): Json<ProviderNetwork>,
) -> Result<(StatusCode, Json<ProviderNetwork>), ApiError> {
    check_envelope(&body)?;
    if body.metadata.name.is_empty() {
        return Err(invalid("metadata.name must be set"));
    }
    if body.spec.physnet.is_empty() {
        return Err(invalid(
            "spec.physnet must be set; it is the name a gateway node claims this network \
             under (`gateway:<physnet>` in its Hello), and a network nobody can claim \
             carries no router",
        ));
    }
    common::net::Ipv4Ranges::parse(&body.spec.allocation)
        .map_err(|e| invalid_field("spec.allocation", e.to_string()))?;
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

/// See the cloud tier's table of the same name; the rule is the same one and
/// it is stated twice because each tier enforces its own.
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
    check_owned(&current, &body, PROVIDER_NETWORK_OWNED)?;
    common::net::Ipv4Ranges::parse(&body.spec.allocation)
        .map_err(|e| invalid_field("spec.allocation", e.to_string()))?;
    body.status = current.status.clone();
    controller_api::carry_generation(&current, &mut body)?;
    match dry.preview(&body) {
        Some(preview) => Ok(Json(preview)),
        None => Ok(Json(st.store.update(&body).await?)),
    }
}

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

pub(super) async fn list_routers(
    State(st): State<ApiState>,
    axum::extract::Query(q): axum::extract::Query<controller_api::ListQuery>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let selector = controller_api::Selector::parse(q.label_selector.as_deref())?;
    let mut items = st.store.list::<controller_api::Router>().await?;
    items.retain(|r| selector.selects(&r.metadata.labels));
    Ok(Json(
        json!({ "apiVersion": API_VERSION, "kind": "RouterList", "items": items }),
    ))
}

pub(super) async fn get_router(
    State(st): State<ApiState>,
    Path(name): Path<String>,
) -> Result<Json<controller_api::Router>, ApiError> {
    Ok(Json(st.store.get(&name).await?))
}

/// The one check this tier can make that the cloud cannot: the router names a
/// provider network that EXISTS HERE, with an allocation to cut an address
/// out of. Everything else about a router is a fact about tenants, and there
/// are none at this tier.
pub(super) async fn create_router(
    State(st): State<ApiState>,
    dry: controller_api::DryRun,
    Json(body): Json<controller_api::Router>,
) -> Result<(StatusCode, Json<controller_api::Router>), ApiError> {
    check_envelope(&body)?;
    if body.metadata.name.is_empty() {
        return Err(invalid("metadata.name must be set"));
    }
    if body.spec.provider_network.is_empty() {
        return Err(invalid(
            "spec.providerNetwork must name the network this router goes out over",
        ));
    }
    let _: ProviderNetwork = st
        .store
        .get(&body.spec.provider_network)
        .await
        .map_err(|_| {
            invalid(format!(
                "no provider network called {}",
                body.spec.provider_network
            ))
        })?;
    let mut router = controller_api::Router::declare(&body.metadata.name, body.spec.clone());
    router.metadata.labels = body.metadata.labels.clone();
    let created = match dry.preview(&router) {
        Some(preview) => preview,
        None => st.store.create(&router).await?,
    };
    info!(router = %created.metadata.name, tenant = %created.spec.tenant,
          network = %created.spec.provider_network, "router created");
    Ok((StatusCode::CREATED, Json(created)))
}

/// See the cloud tier's table of the same name.
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
    dry: controller_api::DryRun,
    Json(mut body): Json<controller_api::Router>,
) -> Result<Json<controller_api::Router>, ApiError> {
    if body.metadata.name != name {
        return Err(invalid("metadata.name does not match the path"));
    }
    let current: controller_api::Router = st.store.get(&name).await?;
    check_owner_labels(&current.metadata, &body.metadata)?;
    check_owned(&current, &body, ROUTER_OWNED)?;
    body.status = current.status.clone();
    controller_api::carry_generation(&current, &mut body)?;
    match dry.preview(&body) {
        Some(preview) => Ok(Json(preview)),
        None => Ok(Json(st.store.update(&body).await?)),
    }
}

/// No finalizer, and the teardown is the reconciler's: the object goes, and
/// the next pass finds nodes holding a router nothing names and sends
/// `DestroyRouter`. The same shape an overlay's sweep has one tier down, and
/// it is what makes a router deleted while its node was away get cleaned up
/// when the node comes back rather than never.
pub(super) async fn delete_router(
    State(st): State<ApiState>,
    Path(name): Path<String>,
) -> Result<controller_api::Removed, ApiError> {
    let current: controller_api::Router = st.store.get(&name).await?;
    st.store.delete::<controller_api::Router>(&name).await?;
    info!(router = %name, node = %current.status.active_node, "router deleted");
    Ok(controller_api::removed(
        controller_api::Router::KIND,
        &name,
        controller_api::Removal::Gone,
    ))
}
