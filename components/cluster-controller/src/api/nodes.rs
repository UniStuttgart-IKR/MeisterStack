// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Node spec updates, heartbeat joins, and authenticated command forwarding.

use super::*;

/// All Node spec fields are operator-managed. Status is updated separately
/// from agent reports; merge patch validation restricts the writable envelope.
pub(super) const NODE_OWNED: &[Owned] = &[];

/// Join heartbeat keys into the API objects with one batched read.
/// Missing heartbeat keys leave the optional field unset.
async fn join_heartbeats(store: &EtcdStore, nodes: &mut [Node]) -> Result<(), ApiError> {
    let beats = store.beats::<Node>().await?;
    for node in nodes.iter_mut() {
        node.status.last_heartbeat = beats.get(&node.metadata.name).copied();
    }
    Ok(())
}

/// Join the current heartbeat into a single-object response.
async fn join_one(store: &EtcdStore, node: &mut Node) -> Result<(), ApiError> {
    node.status.last_heartbeat = store.last_beat::<Node>(&node.metadata.name).await?;
    Ok(())
}

pub(super) async fn list_nodes(
    State(st): State<ApiState>,
    axum::extract::Query(q): axum::extract::Query<controller_api::ListQuery>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let selector = controller_api::Selector::parse(q.label_selector.as_deref())?;
    // Against `spec.labels`: a node's labels are what an operator wrote and
    // what a vm's nodeSelector selects against, and `metadata.labels` on a
    // Node is a field nothing here has ever filled in.
    let mut items = st.store.list::<Node>().await?;
    items.retain(|n| selector.selects(&n.spec.labels));
    join_heartbeats(&st.store, &mut items).await?;
    Ok(Json(json!({
        "apiVersion": API_VERSION,
        "kind": "NodeList",
        "items": items,
    })))
}

pub(super) async fn get_node(
    State(st): State<ApiState>,
    Path(name): Path<String>,
) -> Result<Json<Node>, ApiError> {
    let mut node: Node = st.store.get(&name).await?;
    join_one(&st.store, &mut node).await?;
    Ok(Json(node))
}

/// Update the operator-managed Node spec.
/// `schedulable = false` cordons the node; `drain = true` also asks the reconciler
/// to evacuate existing VMs according to each VM's evacuation policy.
pub(super) async fn update_node(
    State(st): State<ApiState>,
    Path(name): Path<String>,
    dry: controller_api::DryRun,
    Json(body): Json<SpecUpdate<NodeSpec>>,
) -> Result<Json<Node>, ApiError> {
    let current: Node = st.store.get(&name).await?;
    let mut node = write_node_spec(&st.store, &name, body, current, dry).await?;
    join_one(&st.store, &mut node).await?;
    Ok(Json(node))
}

pub(super) async fn patch_node(
    State(st): State<ApiState>,
    Path(name): Path<String>,
    dry: controller_api::DryRun,
    Json(patch): Json<serde_json::Value>,
) -> Result<Json<Node>, ApiError> {
    let mut node = patch_node_spec(&st.store, &name, &patch, dry).await?;
    join_one(&st.store, &mut node).await?;
    Ok(Json(node))
}

/// Apply the same node spec validation for local PATCH and cloud UpdateNode commands.
pub(crate) async fn patch_node_spec(
    store: &EtcdStore,
    name: &str,
    patch: &serde_json::Value,
    dry: controller_api::DryRun,
) -> Result<Node, ApiError> {
    let current: Node = store.get(name).await?;
    let body: SpecUpdate<NodeSpec> = controller_api::apply_merge_patch(&current, patch)?;
    write_node_spec(store, name, body, current, dry).await
}

/// Write with the client's resourceVersion, preserving concurrent updates.
/// Dry-run returns the validated object without writing or logging a state change.
pub(super) async fn write_node_spec(
    store: &EtcdStore,
    name: &str,
    body: SpecUpdate<NodeSpec>,
    current: Node,
    dry: controller_api::DryRun,
) -> Result<Node, ApiError> {
    let was = current.spec.schedulable;
    let next = apply_spec_update(body, name, current)?;
    let now = next.spec.schedulable;
    // The drain that would have happened, and the log line that would have
    // been written, both do not.
    if let Some(preview) = dry.preview(&next) {
        return Ok(preview);
    }
    let updated = store.update(&next).await?;
    if was != now {
        // A state change, so INFO — and one worth having in the log of the
        // replica that made it: a drained node stops taking work silently
        // everywhere else.
        info!(node = %name, schedulable = now, "node schedulability changed");
    }
    Ok(updated)
}

/// The one route at this tier that is not a client's: a sibling replica
/// asking this one to say something to a node it holds the session for.
///
/// A live migration is about two machines, and their sessions can hang off
/// two replicas — see `crate::dispatch` for why that is the one object no
/// ownership rule can carry. Everything that makes this narrow is beside the
/// rule it applies: the body is a closed enum, the caller has to hold this
/// cluster's own `system:cluster:<name>` certificate (the permission table),
/// and the request has to BE a forward.
pub(super) async fn node_command(
    State(st): State<ApiState>,
    Path(name): Path<String>,
    headers: axum::http::HeaderMap,
    Json(cmd): Json<crate::dispatch::NodeCommand>,
) -> Result<axum::response::Response, ApiError> {
    let forwarded = headers.contains_key(controller_api::forward::FORWARDED);
    let payload = crate::dispatch::serve_forwarded(&st.registry, &name, forwarded, cmd).await?;
    // The agent's ack, unopened: one command answers with the address the
    // destination is listening at and the other three answer with nothing,
    // and an empty document is not json.
    let response = if payload.is_empty() {
        axum::response::Response::builder()
            .status(StatusCode::NO_CONTENT)
            .body(axum::body::Body::empty())
    } else {
        axum::response::Response::builder()
            .status(StatusCode::OK)
            .header(axum::http::header::CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(payload))
    };
    Ok(response.expect("a status and a body make a response"))
}
