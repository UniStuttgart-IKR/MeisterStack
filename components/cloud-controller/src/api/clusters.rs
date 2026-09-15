// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! The `clusters` resource. A cluster joins and leaves by session, so there is no POST and no DELETE.

use super::*;

// --- clusters --------------------------------------------------------------

/// The inventory is the Cluster objects, not the live session map: a cluster
/// that is down has to stay listed as disconnected, with the capacity it last
/// had.
pub(super) async fn list_clusters(
    State(st): State<ApiState>,
    axum::extract::Query(q): axum::extract::Query<controller_api::ListQuery>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let selector = controller_api::Selector::parse(q.label_selector.as_deref())?;
    let mut items = st.store.list::<Cluster>().await?;
    items.retain(|c| selector.selects(&c.metadata.labels));
    // `status.lastHeartbeat`, joined back on: the field lives in a key of its
    // own since D-C7 (`EtcdStore::beat`), and this is what keeps the API's
    // answer the answer it always was — `meister cluster ls` shows the column
    // it always showed. One batched read per LIST.
    let beats = st.store.beats::<Cluster>().await?;
    for cluster in items.iter_mut() {
        cluster.status.last_heartbeat = beats.get(&cluster.metadata.name).copied();
    }
    Ok(Json(
        json!({ "apiVersion": API_VERSION, "kind": "ClusterList", "items": items }),
    ))
}

pub(super) async fn get_cluster(
    State(st): State<ApiState>,
    Path(name): Path<String>,
) -> Result<Json<Cluster>, ApiError> {
    let mut cluster: Cluster = st.store.get(&name).await?;
    cluster.status.last_heartbeat = st.store.last_beat::<Cluster>(&name).await?;
    Ok(Json(cluster))
}

/// The Node route one tier up, over the object one tier up, with the same
/// rule and the same narrow meaning: `spec.schedulable = false` stops NEW
/// placements onto this cluster and touches nothing that is already on it.
///
/// Not tenant-scoped and not a member's: a cluster is a piece of the
/// operator's estate, and the middleware already says so (`clusters` is
/// outside `TENANT_SCOPED`, so a member reads and an admin writes).
pub(super) async fn update_cluster(
    State(st): State<ApiState>,
    Path(name): Path<String>,
    dry: controller_api::DryRun,
    Json(body): Json<SpecUpdate<ClusterSpec>>,
) -> Result<Json<Cluster>, ApiError> {
    let current: Cluster = st.store.get(&name).await?;
    let was = current.spec.schedulable;
    let next = apply_spec_update(body, &name, current)?;
    let now = next.spec.schedulable;
    let mut updated = match dry.preview(&next) {
        Some(preview) => preview,
        None => st.store.update(&next).await?,
    };
    // The same join GET and LIST make: a response that showed the instant
    // left in etcd before the field moved would be the only lie this route
    // could still tell.
    updated.status.last_heartbeat = st.store.last_beat::<Cluster>(&name).await?;
    if was != now {
        info!(cluster = %name, schedulable = now, "cluster schedulability changed");
    }
    Ok(Json(updated))
}
