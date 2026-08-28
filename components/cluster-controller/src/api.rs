// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! The cluster's REST API — same K8s-style shape as the cloud tier's end
//! API, addressable directly (the way the agent's unix socket is).

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::routing::get;
use axum::{Json, Router};
use chrono::Utc;
use controller_api::{
    API_VERSION, ApiError, EtcdStore, Node, NodeSpec, SpecUpdate, Vm, VmSpec, apply_spec_update,
    check_envelope, conflict, invalid, resources::new_vm,
};
use macros::generated;
use serde_json::json;
use tracing::info;

#[derive(Clone)]
pub struct ApiState {
    store: Arc<EtcdStore>,
    /// The agent sessions, for the one route whose answer lives on a node
    /// rather than in the store.
    registry: Arc<crate::session::SessionRegistry>,
}

pub fn router(store: Arc<EtcdStore>, registry: Arc<crate::session::SessionRegistry>) -> Router {
    let state = ApiState { store, registry };
    Router::new()
        .route("/healthz", get(healthz))
        .route("/readyz", get(healthz))
        .route("/apis/meister.io/v1/vms", get(list_vms).post(create_vm))
        .route(
            "/apis/meister.io/v1/vms/{name}",
            get(get_vm).put(update_vm).delete(delete_vm),
        )
        .route("/apis/meister.io/v1/vms/{name}/logs", get(vm_logs))
        .route("/apis/meister.io/v1/nodes", get(list_nodes))
        .route(
            "/apis/meister.io/v1/nodes/{name}",
            get(get_node).put(update_node),
        )
        .with_state(state)
}

/// Cluster-local objects the cloud owns are the cloud's to change. It is the
/// only party that knows what the object one tier up says, and an edit made
/// down here would either be quietly undone by the next thing the cloud hands
/// over, or — worse — not undone at all, leaving the two tiers describing
/// different machines. Local operation stays entirely free: this applies only
/// to objects that carry the mark.
#[generated(model = ClaudeOpus, version = "5")]
fn refuse_if_cloud_owned(vm: &Vm) -> Result<(), ApiError> {
    if !vm.metadata.managed_by_cloud() {
        return Ok(());
    }
    Err(conflict(format!(
        "vm {} is managed by the cloud; change it there (meister cloud vm ...)",
        vm.metadata.name
    )))
}

async fn healthz() -> &'static str {
    "ok"
}

/// Everything this tier can decide about a VM spec on its own — run from POST
/// and from PUT both. A document that is only checked on the way in is a
/// document that gets edited afterwards, and it is the edited one that
/// travels down to the agent: a spec.vm that is not an object gets no further
/// than build_spec_json, where it fails every pass, silently, forever.
#[generated(model = ClaudeOpus, version = "5")]
fn validate_vm_spec(spec: &VmSpec) -> Result<(), ApiError> {
    if !spec.vm.is_object() {
        return Err(invalid("spec.vm must be the agent's NewVmSpec object"));
    }
    if spec.vm.get("desired").is_some() {
        return Err(invalid(
            "spec.vm.desired is controller-owned; use spec.runStrategy",
        ));
    }
    Ok(())
}

#[generated(model = ClaudeFable, version = "5")]
async fn list_vms(State(st): State<ApiState>) -> Result<Json<serde_json::Value>, ApiError> {
    let items = st.store.list::<Vm>().await?;
    Ok(Json(json!({
        "apiVersion": API_VERSION,
        "kind": "VmList",
        "items": items,
    })))
}

#[generated(model = ClaudeFable, version = "5")]
/// The edge is where the trace is decided: continue the caller's if it sent a
/// readable one, start a new one if it did not. The span is built and given
/// its parent before it starts — see `telemetry::in_trace` — because a parent
/// attached from inside the body arrives after the trace id has been minted.
async fn create_vm(
    State(st): State<ApiState>,
    headers: axum::http::HeaderMap,
    Json(body): Json<Vm>,
) -> Result<(StatusCode, Json<Vm>), ApiError> {
    let context = telemetry::TraceParent::parse_or_root(
        headers.get("traceparent").and_then(|v| v.to_str().ok()),
    );
    let span = tracing::info_span!(
        "create_vm",
        vm = %body.metadata.name,
        vm_id = tracing::field::Empty,
        trace_id = %context.trace_id_hex()
    );
    telemetry::in_trace(span, &context, create_vm_traced(st, body, context)).await
}

async fn create_vm_traced(
    st: ApiState,
    body: Vm,
    traceparent: telemetry::TraceParent,
) -> Result<(StatusCode, Json<Vm>), ApiError> {
    if body.metadata.name.is_empty() {
        return Err(invalid("metadata.name must be set"));
    }
    check_envelope(&body)?;
    validate_vm_spec(&body.spec)?;
    if body.metadata.managed_by_cloud() || body.metadata.cloud_uid().is_some() {
        // Letting a client wear the mark would let it create a VM that neither
        // tier can then remove: unremovable here because of the guard, unknown
        // up there because no cloud ever created it.
        return Err(invalid(
            "the meister.io/managed-by and meister.io/cloud-uid labels are set by the cloud \
             session, not by clients",
        ));
    }
    // Server-owned metadata; client keeps name + labels.
    let mut vm = new_vm(
        &body.metadata.name,
        VmSpec {
            node_name: None, // scheduling is the controller's job
            // Nothing at this tier has a cluster binding: the field exists because
            // both tiers share one Vm type, and here it is simply not ours.
            cluster_name: None,
            ..body.spec
        },
    );
    vm.metadata.labels = body.metadata.labels;
    // On the object: a VM created straight at the cluster (no cloud in the
    // picture) gets its trace here, and `meister cluster vm create` is that
    // request. See ANNOTATION_TRACEPARENT.
    vm.metadata
        .set_traceparent(&telemetry::outgoing(&traceparent).to_string());
    tracing::Span::current().record("vm_id", &vm.metadata.uid);
    let created = st.store.create(&vm).await?;
    info!(vm = %created.metadata.name, vm_id = %created.metadata.uid,
          trace_id = %traceparent.trace_id_hex(), "vm created");
    Ok((StatusCode::CREATED, Json(created)))
}

async fn get_vm(
    State(st): State<ApiState>,
    Path(name): Path<String>,
) -> Result<Json<Vm>, ApiError> {
    Ok(Json(st.store.get(&name).await?))
}

/// How many lines the caller wants, from the end. Absent = the node's own
/// default; the ring is bounded either way, so this only shortens.
#[derive(serde::Deserialize)]
struct LogQuery {
    #[serde(default)]
    lines: Option<u32>,
}

/// What the guest printed, from the node that has it.
///
/// One way and only that: no attach, no input channel, no follow. The
/// interactive console is a separate feature with separate questions — one
/// attach at a time, a controller that pipes without storing, an audit line
/// per session — and none of them are answered by reading a ring buffer.
///
/// The node's document is served through unopened. A VM that has printed
/// nothing, and one that is not placed yet, both answer with an empty list
/// and a 200: "nothing to show" is an answer. A node that cannot be reached
/// is a 503, because that is a different sentence.
#[generated(model = ClaudeOpus, version = "5")]
async fn vm_logs(
    State(st): State<ApiState>,
    Path(name): Path<String>,
    axum::extract::Query(q): axum::extract::Query<LogQuery>,
) -> Result<axum::response::Response, ApiError> {
    let vm: Vm = st.store.get(&name).await?;
    let payload = match crate::logs::fetch(&st.registry, &vm, q.lines.unwrap_or(0), "").await {
        Ok(crate::logs::Logs::From(payload)) => payload,
        Ok(crate::logs::Logs::NotYet(why)) => {
            info!(vm = %name, reason = %why, "no console yet");
            crate::logs::NO_STREAMS.to_vec()
        }
        // Reaching the node failed. Not 500 and not 404: the store answered,
        // the object is there, and the one party that holds the console is
        // out of reach right now. A caller that retries is right.
        Err(e) => {
            return Err(ApiError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "Unavailable",
                format!("{e:#}"),
            ));
        }
    };
    Ok(json_passthrough(payload))
}

/// The node's JSON, handed on as the bytes it is.
///
/// Deserialising it here to serialise it again would be two chances to change
/// what a console said, in the two tiers between the node and the person
/// reading it, for no gain at all.
#[generated(model = ClaudeOpus, version = "5")]
pub(crate) fn json_passthrough(payload: Vec<u8>) -> axum::response::Response {
    use axum::response::IntoResponse;
    (
        [(axum::http::header::CONTENT_TYPE, "application/json")],
        payload,
    )
        .into_response()
}

#[generated(model = ClaudeFable, version = "5")]
async fn update_vm(
    State(st): State<ApiState>,
    Path(name): Path<String>,
    Json(mut body): Json<Vm>,
) -> Result<Json<Vm>, ApiError> {
    if body.metadata.name != name {
        return Err(invalid("metadata.name does not match the path"));
    }
    // Server-owned fields survive the round-trip untouched — the scheduler's
    // binding and the cloud's ownership marks among them.
    let current: Vm = st.store.get(&name).await?;
    // Ownership first, so a cloud-owned object answers 409 rather than 422.
    refuse_if_cloud_owned(&current)?;
    validate_vm_spec(&body.spec)?;
    body.metadata.take_ownership_labels_from(&current.metadata);
    body.spec.node_name = current.spec.node_name.clone();
    body.spec.cluster_name = None;
    body.metadata.uid = current.metadata.uid;
    body.metadata.creation_timestamp = current.metadata.creation_timestamp;
    body.metadata.deletion_timestamp = current.metadata.deletion_timestamp;
    body.metadata.finalizers = current.metadata.finalizers;
    body.status = current.status;
    Ok(Json(st.store.update(&body).await?))
}

#[generated(model = ClaudeFable, version = "5")]
async fn delete_vm(
    State(st): State<ApiState>,
    Path(name): Path<String>,
) -> Result<Json<Vm>, ApiError> {
    refuse_if_cloud_owned(&st.store.get::<Vm>(&name).await?)?;
    let vm = st
        .store
        .mutate::<Vm, _>(&name, |v| {
            if v.metadata.deletion_timestamp.is_none() {
                v.metadata.deletion_timestamp = Some(Utc::now());
            }
        })
        .await?;
    Ok(Json(vm))
}

/// The inventory is the Node objects, not the live session map: a node that
/// is down has to stay listed as NotReady, with the capacity it last had.
#[generated(model = ClaudeOpus, version = "5")]
async fn list_nodes(State(st): State<ApiState>) -> Result<Json<serde_json::Value>, ApiError> {
    let items = st.store.list::<Node>().await?;
    Ok(Json(json!({
        "apiVersion": API_VERSION,
        "kind": "NodeList",
        "items": items,
    })))
}

async fn get_node(
    State(st): State<ApiState>,
    Path(name): Path<String>,
) -> Result<Json<Node>, ApiError> {
    Ok(Json(st.store.get(&name).await?))
}

/// The only write on a Node, and the reason this route exists: `spec` is what
/// an operator decides and `status` is what the agent reported.
///
/// `spec.schedulable` has been read by the scheduler at both tiers since it
/// was added, and `pending_reason` has been able to say "none of the known
/// candidates is both connected and schedulable" for as long — but nothing
/// could ever set it to false. Draining a node meant writing into etcd by
/// hand. This is the door.
///
/// Draining blocks NEW placements and nothing else. The VMs already on the
/// node go on running and go on being reconciled, the session stays up, and
/// no eviction and no migration happens: those are separate things with
/// separate questions, and quietly starting to move somebody's VM because a
/// flag was flipped would be the worst possible answer to both.
#[generated(model = ClaudeOpus, version = "5")]
async fn update_node(
    State(st): State<ApiState>,
    Path(name): Path<String>,
    Json(body): Json<SpecUpdate<NodeSpec>>,
) -> Result<Json<Node>, ApiError> {
    let current: Node = st.store.get(&name).await?;
    let was = current.spec.schedulable;
    // The same compare-and-swap every other update at this tier goes through:
    // the client's resourceVersion is what the store compares, and a loser is
    // told rather than overwritten. See `apply_spec_update`.
    let next = apply_spec_update(body, &name, current)?;
    let now = next.spec.schedulable;
    let updated = st.store.update(&next).await?;
    if was != now {
        // A state change, so INFO — and one worth having in the log of the
        // replica that made it: a drained node stops taking work silently
        // everywhere else.
        info!(node = %name, schedulable = now, "node schedulability changed");
    }
    Ok(Json(updated))
}
