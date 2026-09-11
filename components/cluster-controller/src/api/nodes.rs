// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! The node edge: what an operator may say about a machine, which is its
//! spec and nothing else. Moved out of `api.rs` unchanged.

use super::*;

/// A Node has nothing the server keeps from a client — its spec is
/// `schedulable` and `labels` and nothing else, and both are an operator's.
/// What the agent reports lives in `status`, and the PATCH route refuses a
/// body that names anything else outright. See the cloud tier's
/// `CLUSTER_OWNED` for why this is declared rather than left out.
pub(super) const NODE_OWNED: &[Owned] = &[];

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
pub(super) async fn update_node(
    State(st): State<ApiState>,
    Path(name): Path<String>,
    dry: controller_api::DryRun,
    Json(body): Json<SpecUpdate<NodeSpec>>,
) -> Result<Json<Node>, ApiError> {
    let current: Node = st.store.get(&name).await?;
    Ok(Json(
        write_node_spec(&st.store, &name, body, current, dry).await?,
    ))
}

pub(super) async fn patch_node(
    State(st): State<ApiState>,
    Path(name): Path<String>,
    dry: controller_api::DryRun,
    Json(patch): Json<serde_json::Value>,
) -> Result<Json<Node>, ApiError> {
    Ok(Json(patch_node_spec(&st.store, &name, &patch, dry).await?))
}

/// A merge patch onto one node's spec, from wherever it came: this tier's own
/// PATCH route, or an `UpdateNode` the cloud sent down its session.
///
/// `pub(crate)` for that second caller, and that IS the point. Draining a node
/// from the cloud and draining it from here are the same act on the same
/// object, and a second write path for one of them is how the two ends of a
/// drain start disagreeing about whether it happened.
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

/// The compare-and-swap itself, and the one line of log a drain is worth.
///
/// The client's resourceVersion is what the store compares, and a loser is
/// told rather than overwritten. See `apply_spec_update`.
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
