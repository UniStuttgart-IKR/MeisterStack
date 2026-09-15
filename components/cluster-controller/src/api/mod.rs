// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! The cluster's REST API — same K8s-style shape as the cloud tier's end
//! API, addressable directly (the way the agent's unix socket is).

use std::sync::Arc;

use axum::Router;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::routing::get;
// This API's `Json`, not axum's: it extracts and renders exactly as axum's
// does, and its rejection is a `kind: Status` like every other refusal here.
use chrono::Utc;
use controller_api::rest::Json;
use controller_api::{
    API_VERSION, ApiError, ApiResource, EtcdStore, Event, Node, NodeSpec, Owned, ProviderNetwork,
    Resource, SpecUpdate, StoragePool, StoreError, Vm, VmSpec, Volume, VolumeSnapshot,
    apply_spec_update, check_envelope, check_owned, conflict, invalid, invalid_field,
    resources::{new_vm, new_volume},
};
use serde_json::json;
use tracing::info;

mod consoles;
mod migrations;
mod network;
mod nodes;
mod vms;
mod volumes;

use consoles::*;
pub(crate) use migrations::*;
use network::*;
pub(crate) use nodes::*;
use vms::*;
use volumes::*;

#[derive(Clone)]
pub struct ApiState {
    store: Arc<EtcdStore>,
    /// The agent sessions, for the one route whose answer lives on a node
    /// rather than in the store.
    registry: Arc<crate::session::SessionRegistry>,
    /// What this replica needs to ask a SIBLING replica, for the one route
    /// whose answer may live on neither this process nor the store: a
    /// console. See `crate::logs`.
    forward: Arc<crate::logs::Forward>,
    /// The admission factors the reconciler places under. Read by exactly one
    /// route — the `?dryRun=All` preview of `POST /vms`, which has to measure
    /// a node the same way the pass would or it is showing a different
    /// cluster than the one that will answer.
    overcommit: controller_api::Overcommit,
    /// The same strategy object the reconciler places with, for the same one
    /// route. Two schedulers would be two answers to "where would this go".
    scheduler: Arc<dyn controller_api::Scheduler>,
}

/// What this endpoint serves, as `GET /apis/meister.io/v1` reports it. See
/// the cloud tier's table for why it stands beside the routes rather than
/// under them.
/// What this endpoint does that is not a resource and not a verb. See the
/// cloud's list and `controller_api::rest::features`.
///
/// No `console.websocket`: this tier serves the raw upgrade a CLI asks for
/// and mints no tickets, and a browser has no business at a cluster endpoint
/// — there is no directory here to say who it is. Naming the feature anyway
/// would be the one thing this document must never do.
pub const FEATURES: &[&str] = &[
    controller_api::rest::features::DRY_RUN,
    controller_api::rest::features::LABEL_SELECTOR,
    controller_api::rest::features::TENANT_FILTER,
    controller_api::rest::features::WHOAMI,
];

pub const RESOURCES: &[ApiResource] = &[
    ApiResource::new(
        Vm::RESOURCE,
        Vm::KIND,
        &["get", "list", "create", "update", "patch", "delete"],
        // `console` was served here and announced only at the cloud, which is
        // the same defect one tier down that fremdsicht 1 found one tier up:
        // a client that reads the document, as the reference tells it to,
        // never finds the route. No `console/ticket` beside it, and that is
        // not an oversight — this tier mints none. See `FEATURES`.
        &["logs", "events", "console"],
    )
    .owning(VM_OWNED)
    .shaped(controller_api::schema_of::<Vm>),
    ApiResource::new(
        Node::RESOURCE,
        Node::KIND,
        &["get", "list", "update", "patch"],
        &[],
    )
    .owning(NODE_OWNED)
    .shaped(controller_api::schema_of::<Node>),
    // Served here as well as at the cloud, and for the reason `vms` is: this
    // is the tier that BUILDS a router. See `api::network`.
    ApiResource::new(
        ProviderNetwork::RESOURCE,
        ProviderNetwork::KIND,
        &["get", "list", "create", "update", "patch", "delete"],
        &[],
    )
    .owning(PROVIDER_NETWORK_OWNED)
    .shaped(controller_api::schema_of::<ProviderNetwork>),
    ApiResource::new(
        controller_api::Router::RESOURCE,
        controller_api::Router::KIND,
        &["get", "list", "create", "update", "patch", "delete"],
        &[],
    )
    .owning(ROUTER_OWNED)
    .shaped(controller_api::schema_of::<controller_api::Router>),
    ApiResource::new(
        StoragePool::RESOURCE,
        StoragePool::KIND,
        &["get", "list", "create", "delete"],
        &[],
    )
    .shaped(controller_api::schema_of::<StoragePool>),
    ApiResource::new(
        Volume::RESOURCE,
        Volume::KIND,
        &["get", "list", "create", "update", "patch", "delete"],
        &[],
    )
    .owning(VOLUME_OWNED)
    .shaped(controller_api::schema_of::<Volume>),
    ApiResource::new(
        VolumeSnapshot::RESOURCE,
        VolumeSnapshot::KIND,
        &["get", "list", "create", "delete"],
        &[],
    )
    .shaped(controller_api::schema_of::<VolumeSnapshot>),
    // Read-only, and that is the shape rather than a gap. A secret is SEALED
    // by the tier that holds the tenant directory and the key, and mirrored
    // down here so that a dispatch can open it; what this tier can usefully
    // answer is WHICH secrets have arrived — which is exactly the question a
    // VM sitting on "secret X has not arrived here yet" raises. Making one
    // here would be making a tenant's object at a tier with no tenants.
    ApiResource::new(
        controller_api::Secret::RESOURCE,
        controller_api::Secret::KIND,
        &["get", "list"],
        &[],
    )
    .shaped(controller_api::schema_of::<controller_api::Secret>),
    // No `update` and no `patch`, and that is the shape of the thing: a
    // migration is an INTENT that was stated once. Changing where it is going
    // halfway through would be a second intent wearing the first one's
    // record, and the honest way to ask for that is a second migration.
    ApiResource::new(
        controller_api::VmMigration::RESOURCE,
        controller_api::VmMigration::KIND,
        &["get", "list", "create", "delete"],
        &[],
    )
    .shaped(controller_api::schema_of::<controller_api::VmMigration>),
    ApiResource::new(Event::RESOURCE, Event::KIND, &["list"], &[])
        .shaped(controller_api::schema_of::<Event>),
];

/// The rows of `resources!` this tier deliberately does not serve, and the
/// one sentence behind almost all of them: there is one user directory in
/// this stack and it is the cloud's, and so are the catalogue and the address
/// space that are written against it.
#[cfg(test)]
const NOT_SERVED: &[&str] = &[
    // Server-owned bookkeeping, as one tier up.
    controller_api::Counter::RESOURCE,
    // A cluster is what this process IS. It has no object of its own here;
    // the one that stands for it lives at the cloud.
    controller_api::Cluster::RESOURCE,
    // The directory, and the certificates written against it.
    controller_api::Tenant::RESOURCE,
    controller_api::User::RESOURCE,
    controller_api::CertificateSigningRequest::RESOURCE,
    // The catalogue: one name for an image across the whole stack, decided
    // where the tenants are.
    controller_api::Image::RESOURCE,
    // The address space an operator was actually given, and what was cut out
    // of it. Both are the cloud's to hand down.
    controller_api::FloatingPool::RESOURCE,
    controller_api::FloatingIp::RESOURCE,
    controller_api::RoutedSubnet::RESOURCE,
    // A console ticket is a stored SECRET, not a document: a client that
    // could list these would read every other client's outstanding
    // credential. It is a resource only because it lives in the store, and
    // its one road in and out is `controller_api::tickets`.
    controller_api::Ticket::RESOURCE,
];

pub fn router(
    store: Arc<EtcdStore>,
    registry: Arc<crate::session::SessionRegistry>,
    forward: Arc<crate::logs::Forward>,
    overcommit: controller_api::Overcommit,
    scheduler: Arc<dyn controller_api::Scheduler>,
    // The chain rather than a string it was asked for once: whether a link
    // can authenticate anybody is the one thing in the discovery document
    // that changes while the process runs (D11). See `rest::discovery`.
    chain: std::sync::Arc<controller_api::AuthChain>,
) -> Router {
    let state = ApiState {
        store,
        registry,
        forward,
        overcommit,
        scheduler,
    };
    let router = Router::new()
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
        .route("/apis/meister.io/v1/vms", get(list_vms).post(create_vm))
        .route(
            "/apis/meister.io/v1/vms/{name}",
            get(get_vm).put(update_vm).patch(patch_vm).delete(delete_vm),
        )
        .route("/apis/meister.io/v1/vms/{name}/logs", get(vm_logs))
        .route("/apis/meister.io/v1/vms/{name}/console", get(vm_console))
        .route("/apis/meister.io/v1/vms/{name}/events", get(vm_events))
        .route("/apis/meister.io/v1/events", get(list_events))
        .route(
            "/apis/meister.io/v1/storagepools",
            get(list_storage_pools).post(create_storage_pool),
        )
        .route(
            "/apis/meister.io/v1/storagepools/{name}",
            get(get_storage_pool).delete(delete_storage_pool),
        )
        .route(
            "/apis/meister.io/v1/volumes",
            get(list_volumes).post(create_volume),
        )
        .route(
            "/apis/meister.io/v1/volumes/{name}",
            get(get_volume)
                .put(update_volume)
                .patch(patch_volume)
                .delete(delete_volume),
        )
        .route(
            "/apis/meister.io/v1/volumesnapshots",
            get(list_volume_snapshots).post(create_volume_snapshot),
        )
        .route(
            "/apis/meister.io/v1/volumesnapshots/{name}",
            get(get_volume_snapshot).delete(delete_volume_snapshot),
        )
        .route(
            "/apis/meister.io/v1/vmmigrations",
            get(list_vm_migrations).post(create_vm_migration),
        )
        .route(
            "/apis/meister.io/v1/vmmigrations/{name}",
            get(get_vm_migration).delete(delete_vm_migration),
        )
        .route(
            "/apis/meister.io/v1/providernetworks",
            get(list_provider_networks).post(create_provider_network),
        )
        .route(
            "/apis/meister.io/v1/providernetworks/{name}",
            get(get_provider_network)
                .put(update_provider_network)
                .patch(patch_provider_network)
                .delete(delete_provider_network),
        )
        .route(
            "/apis/meister.io/v1/routers",
            get(list_routers).post(create_router),
        )
        .route(
            "/apis/meister.io/v1/routers/{name}",
            get(get_router)
                .put(update_router)
                .patch(patch_router)
                .delete(delete_router),
        )
        .route("/apis/meister.io/v1/secrets", get(list_secrets))
        .route("/apis/meister.io/v1/secrets/{name}", get(get_secret))
        .route("/apis/meister.io/v1/nodes", get(list_nodes))
        .route(
            "/apis/meister.io/v1/nodes/{name}",
            get(get_node).put(update_node).patch(patch_node),
        )
        // Not in `RESOURCES`, and deliberately: the discovery document is
        // what a CLIENT may ask this endpoint for, and this is the tier
        // talking to itself. See `crate::dispatch`.
        .route(
            crate::dispatch::COMMAND_PATH,
            axum::routing::post(node_command),
        )
        .with_state(state)
        .merge(controller_api::discovery(
            controller_api::rest::Tier::Cluster,
            chain,
            RESOURCES,
            FEATURES,
        ))
        // Gated, unlike the discovery it sits beside: the answer is what the
        // directory says about one person. See `rest::whoami`.
        .merge(controller_api::rest::whoami(
            controller_api::rest::Tier::Cluster,
        ));
    // Last, so that it sees the whole table above it: the two refusals axum
    // would otherwise answer in plain text get this API's `kind: Status`.
    controller_api::statuses(router)
}

/// A router with no etcd behind it, for the tests of this crate that need a
/// REST edge rather than a store.
///
/// `EtcdStore::connect` is lazy — it builds a channel and dials nothing — so
/// a test that never reaches a handler which asks the store a question never
/// notices. The registry is a parameter because the one test that DOES reach
/// a handler is the migration forward, which needs the node dialled into this
/// router's replica and not into its own.
#[cfg(test)]
pub(crate) async fn test_router(registry: Arc<crate::session::SessionRegistry>) -> Router {
    let store = Arc::new(
        EtcdStore::connect(&["http://127.0.0.1:1".to_string()], "/discovery-test")
            .await
            .expect("the etcd client is built lazily"),
    );
    router(
        store,
        registry,
        Arc::new(crate::logs::Forward {
            cluster: "cluster-1".into(),
            sibling: controller_api::forward::Sibling {
                serves_tls: false,
                tls: None,
            },
        }),
        controller_api::Overcommit::default(),
        Arc::new(controller_api::FirstFit),
        // Two links that are ready by construction, named the way a real
        // chain names its own: what the document says under `auth` is asked
        // of the CHAIN now, not handed in as a string (D11).
        Arc::new(controller_api::AuthChain::named(
            vec![Box::new(token("a")), Box::new(token("b"))],
            vec!["mtls", "bearer"],
        )),
    )
}

/// A link that is ready the moment it is built, which is every link but the
/// oidc one.
#[cfg(test)]
fn token(secret: &str) -> controller_api::BearerAuthenticator {
    controller_api::BearerAuthenticator::new(
        secret,
        controller_api::Identity::new("root", vec![controller_api::GROUP_MASTERS.into()]),
    )
}

/// Cluster-local objects the cloud owns are the cloud's to change. It is the
/// only party that knows what the object one tier up says, and an edit made
/// down here would either be quietly undone by the next thing the cloud hands
/// over, or — worse — not undone at all, leaving the two tiers describing
/// different machines. Local operation stays entirely free: this applies only
/// to objects that carry the mark.
fn refuse_if_cloud_owned(vm: &Vm) -> Result<(), ApiError> {
    if !vm.metadata.managed_by_cloud() {
        return Ok(());
    }
    Err(conflict(format!(
        "vm {} is managed by the cloud; change it there (meister vm ...)",
        vm.metadata.name
    )))
}

async fn healthz() -> &'static str {
    "ok"
}

/// Whether this replica can serve, which is not the same question `/healthz`
/// answers. See `controller_api::readiness`.
async fn readyz(State(st): State<ApiState>) -> axum::response::Response {
    controller_api::readiness(&st.store).await
}

/// PATCH on an object route: read what is stored, merge the patch into it,
/// and hand the result to the handler a PUT would have reached.
///
/// The same macro the cloud tier has, and the same sentence behind it: PATCH
/// is a PUT with a server-filled body and not a second write path, so
/// `refuse_if_cloud_owned` and every other check the update makes is made for
/// a patch too. The object is read twice, here and inside the update; the
/// compare-and-swap the update does is what makes the gap safe.
macro_rules! patch_object {
    ($name:ident -> $put:ident, $object:ty, $body:ty) => {
        async fn $name(
            State(st): State<ApiState>,
            Path(name): Path<String>,
            dry: controller_api::DryRun,
            Json(patch): Json<serde_json::Value>,
        ) -> Result<Json<$object>, ApiError> {
            let patched = &patch;
            controller_api::patch_with_retry(&patch, move || {
                let st = st.clone();
                let name = name.clone();
                async move {
                    let current: $object = st.store.get(&name).await?;
                    let body: $body = controller_api::apply_merge_patch(&current, patched)?;
                    $put(State(st), Path(name), dry, Json(body)).await
                }
            })
            .await
        }
    };
}

patch_object!(patch_vm -> update_vm, Vm, Vm);

patch_object!(patch_volume -> update_volume, Volume, Volume);
patch_object!(
    patch_provider_network -> update_provider_network,
    ProviderNetwork,
    ProviderNetwork
);
patch_object!(patch_router -> update_router, controller_api::Router, controller_api::Router);

/// The node's JSON, handed on as the bytes it is.
///
/// Deserialising it here to serialise it again would be two chances to change
/// what a console said, in the two tiers between the node and the person
/// reading it, for no gain at all.
pub(crate) fn json_passthrough(payload: Vec<u8>) -> axum::response::Response {
    use axum::response::IntoResponse;
    (
        [(axum::http::header::CONTENT_TYPE, "application/json")],
        payload,
    )
        .into_response()
}

/// The whole log of this cluster: its VMs' transitions and its nodes' coming
/// and going.
async fn list_events(
    State(st): State<ApiState>,
    axum::extract::Query(q): axum::extract::Query<controller_api::ListQuery>,
    axum::extract::Query(narrow): axum::extract::Query<controller_api::events::EventQuery>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let selector = controller_api::Selector::parse(q.label_selector.as_deref())?;
    let since = narrow.since()?;
    let mut items = controller_api::events::all(&st.store).await;
    items.retain(|e| {
        q.tenant
            .as_deref()
            .is_none_or(|t| e.spec.tenant.as_deref() == Some(t))
            && selector.selects(&e.metadata.labels)
            && narrow.selects(e, since)
    });
    Ok(Json(json!({
        "apiVersion": API_VERSION,
        "kind": "EventList",
        "items": items,
    })))
}

/// The inventory is the Node objects, not the live session map: a node that
/// is down has to stay listed as NotReady, with the capacity it last had.
/// Which secrets have arrived here, by name and by KEY name.
///
/// `Secret::redacted` is the same door the cloud's read goes through, and it
/// is what makes this route safe to serve at a tier where the only human is
/// holding break glass: the values never leave this process, and the answer
/// is what the dispatch would find.
async fn list_secrets(
    State(st): State<ApiState>,
    axum::extract::Query(q): axum::extract::Query<controller_api::ListQuery>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let selector = controller_api::Selector::parse(q.label_selector.as_deref())?;
    let mut items: Vec<controller_api::Secret> = st.store.list().await?;
    items.retain(|s| {
        q.tenant.as_deref().is_none_or(|t| s.spec.tenant == t)
            && selector.selects(&s.metadata.labels)
    });
    let items: Vec<controller_api::Secret> = items
        .into_iter()
        .map(controller_api::Secret::redacted)
        .collect();
    Ok(Json(json!({
        "apiVersion": controller_api::API_VERSION,
        "kind": "SecretList",
        "items": items,
    })))
}

async fn get_secret(
    State(st): State<ApiState>,
    Path(name): Path<String>,
) -> Result<Json<controller_api::Secret>, ApiError> {
    let secret: controller_api::Secret = st.store.get(&name).await?;
    Ok(Json(secret.redacted()))
}

#[cfg(test)]
mod tests;
