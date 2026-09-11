// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! The cloud's REST API — the end API of the stack, in the same K8s-style
//! shape the cluster serves one tier down. One CLI, two endpoints; what
//! differs is only the resources (cloud: clusters, vms, images).

use std::collections::BTreeSet;
use std::sync::Arc;

use axum::Router;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::routing::{get, put};
// This API's `Json`, not axum's: it extracts and renders exactly as axum's
// does, and its rejection is a `kind: Status` like every other refusal here.
use chrono::{Duration, Utc};
use controller_api::events;
use controller_api::rest::Json;
use controller_api::{
    API_VERSION, ApiError, ApiResource, Caller, CallerRole, CallerTenant, Capacity,
    CertificateSigningRequest, Cluster, ClusterSpec, EtcdStore, Event, FloatingIp, FloatingPool,
    Image, ImageSpec, Owned, ProviderNetwork, Resource, Role, RoutedSubnet, Scope, SpecUpdate,
    StoragePool, StoreError, Tenant, User, Verb, Vm, VmSpec, Volume, VolumePhase, VolumeSnapshot,
    apply_spec_update, check_envelope, check_owned, conflict, floating, forbidden, invalid,
    invalid_field, permits_object, quota,
    resources::{
        CsrCondition, CsrConditionType, CsrSpec, IssuedCertificate, SIGNER_USER_CLIENT, new_vm,
        new_volume,
    },
    vni,
};
use proto::cloud_command;
use serde_json::json;
use tracing::{error, info, warn};

/// The CA this API server signs with, and the two decisions that go with it.
///
/// `None` means no CA is configured: the certificatesigningrequests resource
/// still exists and still records requests, and approving one answers 501.
/// A control plane that accepted requests it could never fulfil would be
/// worse than one that says so.
pub struct Signing {
    pub ca: pki::Ca,
    /// Approve every request the moment it arrives. The lab switch, and it is
    /// exactly as dangerous as it sounds: with it on, the only thing between
    /// a caller and a certificate is the authenticator chain in front of the
    /// API. That is why a non-admin can only ever ask for its own name.
    pub auto_approve: bool,
    pub ttl_days: i64,
}

#[derive(Clone)]
pub struct ApiState {
    store: Arc<EtcdStore>,
    /// The cluster sessions, for the one route whose answer lives on a node
    /// two tiers down rather than in this store.
    sessions: Arc<crate::session::SessionRegistry>,
    signing: Option<Arc<Signing>>,
    /// Where tenant VNI allocation starts. See `controller_api::vni`.
    vni_base: u32,
    /// The address space routed subnets are cut out of, from the cloud config
    /// (`routed_pools`). Empty = an admin has to name every subnet's CIDR
    /// outright, which is the right default: the stack does not know which
    /// prefixes an operator was actually given, and inventing one would put
    /// somebody else's addresses inside a tenant's allowlist.
    routed_pools: Arc<Vec<String>>,
    /// This replica's own REST address, where it has one. Read by exactly one
    /// route: a console forward, to be sure it is not about to connect to
    /// itself. See `CONSOLE_FORWARDED`.
    advertise: Option<String>,
    /// The admission factors and the placement strategy the reconciler uses,
    /// read by exactly one route: the `?dryRun=All` preview of `POST /vms`,
    /// which has to measure a cluster the same way the pass would or it is
    /// showing a different cloud than the one that will answer.
    overcommit: controller_api::Overcommit,
    scheduler: Arc<dyn controller_api::Scheduler>,
    /// The key a `Secret`'s values are sealed with. `None` = no
    /// `secrets_key` in the config, and `POST /secrets` answers 501 rather
    /// than storing what it could not seal. See `api::secrets::sealer`.
    kek: Option<Arc<controller_api::secrets::Kek>>,
    /// The console tickets this TIER has outstanding. The same value the
    /// guard spends, and it lives in etcd rather than in this process — see
    /// `controller_api::tickets`.
    tickets: Arc<controller_api::tickets::Tickets>,
    /// How to reach a SIBLING replica of this cloud, and with what.
    ///
    /// Read by the two routes whose answer may live on neither this process
    /// nor the store: a log read and a console. See
    /// `controller_api::forward`.
    sibling: controller_api::forward::Sibling,
}

/// What this endpoint serves, as `GET /apis/meister.io/v1` reports it.
///
/// Beside the routes and deliberately not derived from them. The router below
/// stays written out route by route; this is a second, independent statement
/// about it, and the test at the bottom of this file holds the two together.
/// A table the routes were built from would be true by construction and would
/// therefore tell a client nothing.
///
/// `verbs` is what the router really offers — `clusters` has no POST and no
/// DELETE because a cluster joins and leaves by session, not by request.
pub const RESOURCES: &[ApiResource] = &[
    ApiResource::new(
        Vm::RESOURCE,
        Vm::KIND,
        &["get", "list", "create", "update", "patch", "delete"],
        // `console` was served and not announced, which is the one thing a
        // discovery document must never be: a client that reads it, as the
        // reference tells it to, never found the route at all. `console/
        // ticket` is the door a browser goes through, and it is a path
        // rather than a word for the same reason — it is where it is.
        &["logs", "events", "console", "console/ticket"],
    )
    .owning(VM_OWNED)
    .shaped(vms::cloud_vm_schema),
    ApiResource::new(
        Cluster::RESOURCE,
        Cluster::KIND,
        &["get", "list", "update", "patch"],
        &["nodes"],
    )
    .owning(CLUSTER_OWNED)
    .shaped(controller_api::schema_of::<Cluster>),
    ApiResource::new(
        Image::RESOURCE,
        Image::KIND,
        &["get", "list", "create", "delete"],
        &[],
    )
    .shaped(controller_api::schema_of::<Image>),
    ApiResource::new(
        Tenant::RESOURCE,
        Tenant::KIND,
        &["get", "list", "create", "update", "patch", "delete"],
        &[],
    )
    .owning(TENANT_OWNED)
    .shaped(controller_api::schema_of::<Tenant>),
    ApiResource::new(
        User::RESOURCE,
        User::KIND,
        &["get", "list", "create", "update", "patch", "delete"],
        &[],
    )
    .owning(USER_OWNED)
    .shaped(controller_api::schema_of::<User>),
    ApiResource::new(
        CertificateSigningRequest::RESOURCE,
        CertificateSigningRequest::KIND,
        &["get", "list", "create", "delete"],
        &["approval"],
    )
    .shaped(controller_api::schema_of::<CertificateSigningRequest>),
    ApiResource::new(
        FloatingPool::RESOURCE,
        FloatingPool::KIND,
        &["get", "list", "create", "update", "patch", "delete"],
        &[],
    )
    .owning(FLOATING_POOL_OWNED)
    .shaped(controller_api::schema_of::<FloatingPool>),
    ApiResource::new(
        FloatingIp::RESOURCE,
        FloatingIp::KIND,
        &["get", "list", "create", "update", "patch", "delete"],
        &[],
    )
    .owning(FLOATING_IP_OWNED)
    .shaped(controller_api::schema_of::<FloatingIp>),
    ApiResource::new(
        RoutedSubnet::RESOURCE,
        RoutedSubnet::KIND,
        &["get", "list", "create", "update", "patch", "delete"],
        &[],
    )
    .owning(ROUTED_SUBNET_OWNED)
    .shaped(controller_api::schema_of::<RoutedSubnet>),
    // The wire an operator gave away, and a tenant's way out over it. The
    // same split the floating pair has one noun over: what EXISTS is an
    // administrator's decision, and a router is filed in a tenant.
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
        &["get", "list", "create", "update", "patch", "delete"],
        &[],
    )
    .owning(STORAGE_POOL_OWNED)
    .shaped(controller_api::schema_of::<StoragePool>),
    ApiResource::new(
        Volume::RESOURCE,
        Volume::KIND,
        &["get", "list", "create", "update", "patch", "delete"],
        &[],
    )
    .owning(VOLUME_OWNED)
    .shaped(controller_api::schema_of::<Volume>),
    // Snapshots. No update verb at either tier: what a snapshot IS was
    // decided when it was taken, and the two fields a client could write are
    // the two that would make it a copy of something else.
    ApiResource::new(
        VolumeSnapshot::RESOURCE,
        VolumeSnapshot::KIND,
        &["get", "list", "create", "delete"],
        &[],
    )
    .owning(VOLUME_SNAPSHOT_OWNED)
    .shaped(controller_api::schema_of::<VolumeSnapshot>),
    // No `owned` table, and `Some(&[])` says somebody looked: there is
    // nothing on a Secret's spec a client may keep, because a client can
    // never READ one. See `update_secret`.
    ApiResource::new(
        controller_api::Secret::RESOURCE,
        controller_api::Secret::KIND,
        &["get", "list", "create", "update", "delete"],
        &[],
    )
    .owning(&[])
    .shaped(controller_api::schema_of::<controller_api::Secret>),
    ApiResource::new(Event::RESOURCE, Event::KIND, &["list"], &[])
        .shaped(controller_api::schema_of::<Event>),
    // One verb, and the row is the honest half of D-P9: this tier serves the
    // ASK and keeps no object, so `create` is the whole truth and a client
    // that reads this document will not try to list here. The records
    // themselves are at the cluster, which is where the machines are.
    ApiResource::new(
        controller_api::VmMigration::RESOURCE,
        controller_api::VmMigration::KIND,
        &["create"],
        &[],
    )
    // The KIND's shape and not this route's: what a client renders is a
    // `VmMigration`, wherever it reads one, and the phases in `status` are
    // exactly what it will go to the cluster for. A schema cut down to the
    // four fields that travel would describe a document nobody ever holds.
    .shaped(controller_api::schema_of::<controller_api::VmMigration>),
];

/// What this endpoint does that is not a resource and not a verb.
///
/// A second statement beside the routes, exactly as the resource table is,
/// and held to them by the test at the bottom of this file: a name here is a
/// promise, and a promise nothing keeps is worse than silence. See
/// `controller_api::rest::features`.
pub const FEATURES: &[&str] = &[
    controller_api::rest::features::DRY_RUN,
    controller_api::rest::features::LABEL_SELECTOR,
    controller_api::rest::features::TENANT_FILTER,
    controller_api::rest::features::WHOAMI,
    // Cloud only: the ticket endpoint is here and the browser talks to this
    // tier. The cluster serves the raw console and says nothing about a
    // websocket, which is exactly true of it.
    controller_api::rest::features::CONSOLE_WEBSOCKET,
];

/// The rows of `resources!` this tier deliberately does not serve.
///
/// Its own list rather than an omission, so that a new resource in
/// `controller_api::resources` is a decision somebody makes here rather than
/// a hole nobody notices: the test below fails on a row that is in neither
/// list.
#[cfg(test)]
const NOT_SERVED: &[&str] = &[
    // Server-owned bookkeeping (the VNI allocator's). Nothing an operator
    // lists, names or creates.
    controller_api::Counter::RESOURCE,
    // A node belongs to the cluster that has it. This tier keeps no Node
    // object at all — it reads them out of the cluster's status.
    controller_api::Node::RESOURCE,
    // A console ticket is a stored SECRET, not a document: a client that
    // could list these would read every other client's outstanding
    // credential. It is a resource only because it lives in the store, and
    // its one road in and out is `controller_api::tickets`.
    controller_api::Ticket::RESOURCE,
];

/// Everything this API server needs from the config, in one place.
///
/// A struct rather than eight parameters, and it earned that when the
/// placement preview added the seventh and eighth: a call site with eight
/// positional values of which three are `Option` is a call site where two
/// arguments get swapped and nothing complains. Each field is read by one or
/// two routes; see `ApiState`, which is what they become.
pub struct Settings {
    pub signing: Option<Arc<Signing>>,
    /// See `ApiState::kek`.
    pub kek: Option<Arc<controller_api::secrets::Kek>>,
    /// See `ApiState::sibling`.
    pub sibling: controller_api::forward::Sibling,
    pub vni_base: u32,
    pub routed_pools: Vec<String>,
    pub advertise: Option<String>,
    pub overcommit: controller_api::Overcommit,
    pub scheduler: Arc<dyn controller_api::Scheduler>,
    /// See `ApiState::tickets`.
    pub tickets: Arc<controller_api::tickets::Tickets>,
}

pub fn router(
    store: Arc<EtcdStore>,
    sessions: Arc<crate::session::SessionRegistry>,
    settings: Settings,
    // The chain rather than a string it was asked for once: whether a link
    // can authenticate anybody is the one thing in the discovery document
    // that changes while the process runs (D11). See `rest::discovery`.
    chain: std::sync::Arc<controller_api::AuthChain>,
) -> Router {
    let state = ApiState {
        store,
        sessions,
        signing: settings.signing,
        vni_base: settings.vni_base,
        routed_pools: Arc::new(settings.routed_pools),
        advertise: settings.advertise,
        overcommit: settings.overcommit,
        scheduler: settings.scheduler,
        sibling: settings.sibling,
        kek: settings.kek,
        tickets: settings.tickets,
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
        .route(
            "/apis/meister.io/v1/vms/{name}/console/ticket",
            axum::routing::post(vm_console_ticket),
        )
        .route("/apis/meister.io/v1/vms/{name}/events", get(vm_events))
        .route(
            "/apis/meister.io/v1/secrets",
            get(list_secrets).post(create_secret),
        )
        .route(
            "/apis/meister.io/v1/secrets/{name}",
            get(get_secret).put(update_secret).delete(delete_secret),
        )
        .route("/apis/meister.io/v1/events", get(list_events))
        .route(
            "/apis/meister.io/v1/vmmigrations",
            axum::routing::post(create_vm_migration),
        )
        .route("/apis/meister.io/v1/clusters", get(list_clusters))
        .route(
            "/apis/meister.io/v1/clusters/{name}",
            get(get_cluster).put(update_cluster).patch(patch_cluster),
        )
        .route(
            "/apis/meister.io/v1/clusters/{cluster}/nodes",
            get(list_cluster_nodes),
        )
        .route(
            "/apis/meister.io/v1/clusters/{cluster}/nodes/{node}",
            get(get_cluster_node).patch(patch_cluster_node),
        )
        .route(
            "/apis/meister.io/v1/images",
            get(list_images).post(create_image),
        )
        .route(
            "/apis/meister.io/v1/images/{name}",
            get(get_image).delete(delete_image),
        )
        .route(
            "/apis/meister.io/v1/tenants",
            get(list_tenants).post(create_tenant),
        )
        .route(
            "/apis/meister.io/v1/tenants/{name}",
            get(get_tenant)
                .put(update_tenant)
                .patch(patch_tenant)
                .delete(delete_tenant),
        )
        .route(
            "/apis/meister.io/v1/floatingpools",
            get(list_floating_pools).post(create_floating_pool),
        )
        .route(
            "/apis/meister.io/v1/floatingpools/{name}",
            get(get_floating_pool)
                .put(update_floating_pool)
                .patch(patch_floating_pool)
                .delete(delete_floating_pool),
        )
        .route(
            "/apis/meister.io/v1/floatingips",
            get(list_floating_ips).post(create_floating_ip),
        )
        .route(
            "/apis/meister.io/v1/floatingips/{name}",
            get(get_floating_ip)
                .put(update_floating_ip)
                .patch(patch_floating_ip)
                .delete(delete_floating_ip),
        )
        .route(
            "/apis/meister.io/v1/storagepools",
            get(list_storage_pools).post(create_storage_pool),
        )
        .route(
            "/apis/meister.io/v1/storagepools/{name}",
            get(get_storage_pool)
                .put(update_storage_pool)
                .patch(patch_storage_pool)
                .delete(delete_storage_pool),
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
        .route(
            "/apis/meister.io/v1/routedsubnets",
            get(list_routed_subnets).post(create_routed_subnet),
        )
        .route(
            "/apis/meister.io/v1/routedsubnets/{name}",
            get(get_routed_subnet)
                .put(update_routed_subnet)
                .patch(patch_routed_subnet)
                .delete(delete_routed_subnet),
        )
        .route(
            "/apis/meister.io/v1/users",
            get(list_users).post(create_user),
        )
        .route(
            "/apis/meister.io/v1/users/{name}",
            get(get_user)
                .put(update_user)
                .patch(patch_user)
                .delete(delete_user),
        )
        .route(
            "/apis/meister.io/v1/certificatesigningrequests",
            get(list_csrs).post(create_csr),
        )
        .route(
            "/apis/meister.io/v1/certificatesigningrequests/{name}",
            get(get_csr).delete(delete_csr),
        )
        .route(
            "/apis/meister.io/v1/certificatesigningrequests/{name}/approval",
            put(approve_csr),
        )
        .with_state(state)
        .merge(controller_api::discovery(
            controller_api::rest::Tier::Cloud,
            chain,
            RESOURCES,
            FEATURES,
        ))
        // Gated, unlike the discovery it sits beside: the answer is what the
        // directory says about one person. See `rest::whoami`.
        .merge(controller_api::rest::whoami(
            controller_api::rest::Tier::Cloud,
        ));
    // Last, so that it sees the whole table above it: the two refusals axum
    // would otherwise answer in plain text get this API's `kind: Status`.
    controller_api::statuses(router)
}

/// A Cluster has nothing the server keeps from a client, and that is a
/// finding rather than an omission: its whole spec is `schedulable` and
/// `labels`, and both are exactly what an operator edits. Everything a
/// controller writes about a cluster lives in `status`, which
/// `apply_spec_update` refuses outright — a different mechanism, one layer up
/// from this table.
///
/// Declared empty rather than left out, so that
/// `every_writable_resource_publishes_its_mutability` can tell "nothing is
/// owned here" from "nobody has looked".
const CLUSTER_OWNED: &[Owned] = &[];

/// Nothing in a `User` is the server's. Role, tenant and description are all
/// an administrator's to change, and changing the first two IS the point of
/// the resource — a demotion and a move between tenants are the two things
/// the directory exists to make possible. `status` holds the issued
/// certificates and is refused separately.
///
/// Declared empty on purpose; see `CLUSTER_OWNED`.
const USER_OWNED: &[Owned] = &[];

/// Nothing in a `FloatingPool` is the server's either. Its ranges, its
/// scope, its default flag and its per-tenant quotas are all an
/// administrator's — what the API does instead is REFUSE a pool whose ranges
/// do not parse or overlap another's, which is a validity rule and not an
/// ownership one.
///
/// Declared empty on purpose; see `CLUSTER_OWNED`.
const FLOATING_POOL_OWNED: &[Owned] = &[];

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
/// A macro rather than one copy per resource, because what is worth reading
/// is that every one of them is the SAME four lines. PATCH here is a PUT with
/// a server-filled body and not a second write path: every check the update
/// handler makes — whose the object is, which fields it keeps, the sentence
/// it refuses with — is made for a patch too, because it IS that handler.
///
/// The object is read twice, once here and once inside the update. That is
/// what a patch costs: it has to be applied to something. The
/// compare-and-swap the update does is what makes the gap between the two
/// reads safe — a writer that slips in wins, and this one is told, or, when
/// the client named no version to be told against, the whole of it happens
/// again. See `controller_api::patch_with_retry`.
///
/// Two arms, for the two extractor sets the update handlers have: the
/// tenant-scoped ones take the caller's grant and check it against the
/// object, the rest leave the whole question to the middleware.
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
    (scoped $name:ident -> $put:ident, $object:ty, $body:ty) => {
        async fn $name(
            State(st): State<ApiState>,
            Path(name): Path<String>,
            caller: Caller,
            role: CallerRole,
            tenant: CallerTenant,
            dry: controller_api::DryRun,
            Json(patch): Json<serde_json::Value>,
        ) -> Result<Json<$object>, ApiError> {
            let patched = &patch;
            controller_api::patch_with_retry(&patch, move || {
                let st = st.clone();
                let name = name.clone();
                let caller = caller.clone();
                let tenant = tenant.clone();
                async move {
                    let current: $object = st.store.get(&name).await?;
                    let body: $body = controller_api::apply_merge_patch(&current, patched)?;
                    $put(State(st), Path(name), caller, role, tenant, dry, Json(body)).await
                }
            })
            .await
        }
    };
}

// --- one file per resource --------------------------------------------------
//
// Mechanical, and the glob re-imports are what make it mechanical: a child
// says `use super::*` and sees this file's imports, helpers, state and macro;
// this file says `use <child>::*` and sees the handlers the router names. So
// a handler that moves between two of them needs no import changed at either
// end, and the router below stays one line per route.
mod clusters;
mod csrs;
#[path = "events.rs"]
mod events_route;
#[path = "floating.rs"]
mod floating_route;
mod guards;
mod images;
mod migrations;
mod network;
mod nodes;
mod routed_subnets;
mod secrets;
mod storage;
mod tenants;
#[cfg(test)]
mod tests;
mod users;
mod vms;

use clusters::*;
use csrs::*;
use events_route::*;
use floating_route::*;
use guards::*;
use images::*;
use migrations::*;
use network::*;
use nodes::*;
use routed_subnets::*;
use secrets::*;
use storage::*;
use tenants::*;
use users::*;
use vms::*;

// --- patch, one line per object route that has a put ------------------------

patch_object!(scoped patch_vm -> update_vm, Vm, Vm);
patch_object!(patch_cluster -> update_cluster, Cluster, SpecUpdate<ClusterSpec>);
patch_object!(patch_tenant -> update_tenant, Tenant, Tenant);
patch_object!(patch_user -> update_user, User, User);
patch_object!(patch_floating_pool -> update_floating_pool, FloatingPool, FloatingPool);
patch_object!(scoped patch_floating_ip -> update_floating_ip, FloatingIp, FloatingIp);
patch_object!(patch_routed_subnet -> update_routed_subnet, RoutedSubnet, RoutedSubnet);
patch_object!(
    patch_provider_network -> update_provider_network,
    ProviderNetwork,
    ProviderNetwork
);
patch_object!(scoped patch_router -> update_router, controller_api::Router, controller_api::Router);
patch_object!(patch_storage_pool -> update_storage_pool, StoragePool, StoragePool);
patch_object!(scoped patch_volume -> update_volume, Volume, Volume);
