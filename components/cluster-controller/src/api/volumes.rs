// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! The storage edge: pools, volumes and their snapshots. Moved out of
//! `api.rs` unchanged.

use super::*;

pub(super) async fn list_storage_pools(
    State(st): State<ApiState>,
    axum::extract::Query(q): axum::extract::Query<controller_api::ListQuery>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let selector = controller_api::Selector::parse(q.label_selector.as_deref())?;
    let mut items = st.store.list::<StoragePool>().await?;
    items.retain(|p| selector.selects(&p.metadata.labels));
    // The ceiling this pool applies to everybody nobody named, stated rather
    // than left to a constant nobody can read. No redaction here: this tier
    // keeps no directory and confines nobody. See `StoragePoolSpec`.
    for pool in &mut items {
        pool.spec.state_default_quota();
    }
    Ok(Json(
        json!({ "apiVersion": API_VERSION, "kind": "StoragePoolList", "items": items }),
    ))
}

pub(super) async fn get_storage_pool(
    State(st): State<ApiState>,
    Path(name): Path<String>,
) -> Result<Json<StoragePool>, ApiError> {
    let mut pool: StoragePool = st.store.get(&name).await?;
    pool.spec.state_default_quota();
    Ok(Json(pool))
}

pub(super) async fn create_storage_pool(
    State(st): State<ApiState>,
    dry: controller_api::DryRun,
    Json(body): Json<StoragePool>,
) -> Result<(StatusCode, Json<StoragePool>), ApiError> {
    check_envelope(&body)?;
    if body.metadata.name.is_empty() {
        return Err(invalid("metadata.name must be set"));
    }
    if body.spec.driver.is_empty() {
        return Err(invalid(
            "spec.driver must name a storage backend, e.g. \"lvm-thin\"",
        ));
    }
    let mut pool = StoragePool::declare(&body.metadata.name, body.spec);
    pool.metadata.labels = body.metadata.labels;
    // Two pool objects over one block is two names for one disk, and the
    // assignment table cannot see it: `status.claims` is atomic across the
    // NODES of a pool and there is one table per pool. Round 4's e2e got two
    // `Ready` volumes on the same namespace that way, on two nodes, which is
    // the rollout-59 finding again by a different road. Refused HERE because
    // this is where the second name is invented; every later tier is looking
    // at one pool at a time and correctly so.
    if let Some((other, nqn)) =
        crate::reconcile::namespaces::already_listed(&pool, &st.store.list::<StoragePool>().await?)
    {
        return Err(conflict(format!(
            "namespace {nqn} is already listed by storage pool {other}; an nqn names one block, \
             and two pools over one block hand the same disk to two guests"
        )));
    }
    let created = match dry.preview(&pool) {
        Some(preview) => preview,
        None => st.store.create(&pool).await?,
    };
    info!(pool = %created.metadata.name, driver = %created.spec.driver,
          nodes = created.spec.nodes.len(), "storage pool created");
    Ok((StatusCode::CREATED, Json(created)))
}

/// A pool with volumes in it stays — the invariant "every volume came out of
/// a pool that exists" is worth what the refusal that keeps it true is worth.
/// `place_volume` reads it back on every pass and would have nowhere to put a
/// volume whose pool had vanished.
pub(super) async fn delete_storage_pool(
    State(st): State<ApiState>,
    Path(name): Path<String>,
) -> Result<controller_api::Removed, ApiError> {
    let _: StoragePool = st.store.get(&name).await?;
    let held: Vec<String> = st
        .store
        .list::<Volume>()
        .await?
        .into_iter()
        .filter(|v| v.spec.pool == name)
        .map(|v| v.metadata.name)
        .collect();
    if !held.is_empty() {
        return Err(conflict(format!(
            "storage pool {name} still has volumes: {}",
            held.join(", ")
        )));
    }
    st.store.delete::<StoragePool>(&name).await?;
    Ok(controller_api::removed(
        StoragePool::KIND,
        &name,
        controller_api::Removal::Gone,
    ))
}

pub(super) async fn list_volumes(
    State(st): State<ApiState>,
    axum::extract::Query(q): axum::extract::Query<controller_api::ListQuery>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let selector = controller_api::Selector::parse(q.label_selector.as_deref())?;
    let mut items = st.store.list::<Volume>().await?;
    items.retain(|v| {
        q.tenant.as_deref().is_none_or(|t| v.spec.tenant == t)
            && selector.selects(&v.metadata.labels)
    });
    Ok(Json(
        json!({ "apiVersion": API_VERSION, "kind": "VolumeList", "items": items }),
    ))
}

pub(super) async fn get_volume(
    State(st): State<ApiState>,
    Path(name): Path<String>,
) -> Result<Json<Volume>, ApiError> {
    Ok(Json(st.store.get(&name).await?))
}

/// Reserve storage here. Nothing is provisioned: the reconcile pass picks a
/// node that can reach the pool, and the volume is `Pending` and says why
/// until one is found.
/// A volume starts from exactly one thing.
///
/// Empty, a catalogue image, or somebody's own point in time — and never two
/// of them. A spec that names both is a spec whose author believes one, and a
/// silent winner would hand somebody a disk they did not ask for. Refused
/// here, where a person is still holding the request, and again at the node,
/// which is the refusal nobody can go around.
pub(super) fn check_one_seed(volume: &Volume) -> Result<(), ApiError> {
    let image = volume
        .spec
        .base_image
        .as_deref()
        .is_some_and(|i| !i.is_empty());
    let snapshot = volume
        .spec
        .from_snapshot
        .as_deref()
        .is_some_and(|s| !s.is_empty());
    if image && snapshot {
        return Err(invalid_field(
            "spec.fromSnapshot",
            "a volume starts from a base image or from a snapshot, not both; drop one",
        ));
    }
    Ok(())
}

pub(super) async fn create_volume(
    State(st): State<ApiState>,
    dry: controller_api::DryRun,
    Json(body): Json<Volume>,
) -> Result<(StatusCode, Json<Volume>), ApiError> {
    check_envelope(&body)?;
    if body.metadata.name.is_empty() {
        return Err(invalid("metadata.name must be set"));
    }
    if body.spec.size_gib == 0 {
        return Err(invalid("spec.sizeGib must be greater than zero"));
    }
    if body.status.node.is_some() || !body.status.backend.is_empty() {
        return Err(invalid(
            "status is controller-owned; it says where the volume actually is",
        ));
    }
    check_one_seed(&body)?;
    if let Some(named) = body.spec.from_snapshot.as_deref().filter(|s| !s.is_empty()) {
        check_snapshot_ready(&st, named).await?;
    }
    let pools = st.store.list::<StoragePool>().await?;
    let pool = match body.spec.pool.as_str() {
        "" => pools
            .iter()
            .find(|p| p.spec.default)
            .ok_or_else(|| invalid("no storage pool is marked default; name one with spec.pool"))?,
        named => pools
            .iter()
            .find(|p| p.metadata.name == named)
            .ok_or_else(|| invalid(format!("no storage pool {named:?} in this cluster")))?,
    };

    let mut spec = body.spec;
    spec.pool = pool.metadata.name.clone();
    // `status.backend` stays EMPTY. It is what the node calls the volume, and
    // no node has been asked yet — see `VolumeStatus::backend`, where a
    // derived guess used to live and named a path that existed nowhere.
    let volume = new_volume(&body.metadata.name, spec);
    let created = match dry.preview(&volume) {
        Some(preview) => preview,
        None => st.store.create(&volume).await?,
    };
    info!(volume = %created.metadata.name, pool = %created.spec.pool,
          size_gib = created.spec.size_gib, "volume reserved");
    Ok((StatusCode::CREATED, Json(created)))
}

/// What an update of a volume may not change, and why.
///
/// The cloud tier's table, at the tier that HAS the nodes — a cluster with no
/// cloud above it holds its own volumes and has to be able to grow one. Kept
/// as its own constant rather than shared across the crate boundary for the
/// reason every other table here is: what a tier enforces is what a tier
/// publishes, and one table imported into two routers is one edit away from
/// promising something a tier does not check.
pub(super) const VOLUME_OWNED: &[Owned] = &[
    // Upwards only. See the cloud's copy for the argument in full: a
    // filesystem does not know which bytes past the new end were free, so
    // taking them is taking data and no later pass gets it back.
    Owned::structural(
        "spec.sizeGib",
        "may only grow: shrinking a volume is not supported, because the bytes past the new end \
         are not this control plane's to decide about",
        controller_api::grows_only,
    )
    .noting(
        "a resize is two steps and they are not symmetric: the backend grows first, then the \
         guest is told. status.sizeGib is what actually happened",
    ),
    Owned::immutable(
        "spec.pool",
        "is immutable; the disk was provisioned out of it",
    ),
    Owned::immutable(
        "spec.tenant",
        "is immutable; whose a disk is, is decided once",
    ),
    Owned::immutable("spec.mode", "is immutable; it is how the disk was made"),
    Owned::immutable(
        "spec.accessMode",
        "is immutable; it is how the disk was made",
    ),
    Owned::immutable(
        "spec.baseImage",
        "is immutable; it is what the disk was seeded from",
    ),
    Owned::immutable(
        "spec.fromSnapshot",
        "is immutable; it is what the disk was seeded from",
    ),
];

/// The one edit a volume takes: a bigger `sizeGib`, and the description.
///
/// `status` is put back rather than refused, the same way `update_vm` does it
/// and for the same reason: a PUT is a document the client read and re-sends
/// whole, so quietly keeping the server's half is the only way a client can
/// round-trip one at all.
pub(super) async fn update_volume(
    State(st): State<ApiState>,
    Path(name): Path<String>,
    dry: controller_api::DryRun,
    Json(mut body): Json<Volume>,
) -> Result<Json<Volume>, ApiError> {
    if body.metadata.name != name {
        return Err(invalid("metadata.name does not match the path"));
    }
    let current: Volume = st.store.get(&name).await?;
    check_owned(&current, &body, VOLUME_OWNED)?;
    body.metadata.uid = current.metadata.uid.clone();
    body.metadata.creation_timestamp = current.metadata.creation_timestamp;
    body.metadata.deletion_timestamp = current.metadata.deletion_timestamp;
    body.metadata.finalizers = current.metadata.finalizers.clone();
    body.status = current.status.clone();
    controller_api::carry_generation(&current, &mut body)?;
    match dry.preview(&body) {
        Some(preview) => Ok(Json(preview)),
        None => Ok(Json(st.store.update(&body).await?)),
    }
}

/// Mark it for release. Never a hard delete: the finalizer comes off in the
/// reconcile pass, and only once nothing holds the volume. See `release`.
pub(super) async fn delete_volume(
    State(st): State<ApiState>,
    Path(name): Path<String>,
) -> Result<controller_api::Removed, ApiError> {
    let volume = st
        .store
        .mutate::<Volume, _>(&name, |v| {
            if v.metadata.deletion_timestamp.is_none() {
                v.metadata.deletion_timestamp = Some(Utc::now());
            }
            v.status.phase = VolumePhase::Releasing;
        })
        .await?;
    // The sentence as well as the detail, and the same one the tier above
    // writes: a client that does not know this resource's own `details` key
    // still gets told the disk is not gone (D4).
    let said = match &volume.status.attached_to {
        Some(vm) => {
            format!("volume {name} is attached to vm {vm}; its data stays until that vm lets go")
        }
        None => format!("volume {name} will be deprovisioned by the node holding it"),
    };
    Ok(
        controller_api::removed(Volume::KIND, &name, controller_api::Removal::Going)
            .saying(said)
            .detail("attachedTo", json!(volume.status.attached_to)),
    )
}

/// The snapshot a volume says it starts from has to be one this tenant has.
///
/// **404 and not 403** for a snapshot in another tenant, by the same argument
/// `check_volume_refs` gives: a 403 would confirm that a snapshot of that
/// name exists somewhere, which is what a caller probing names is after.
///
/// A snapshot that is merely not `Ready` yet is NOT refused — the copy is
/// being made and the volume waits as Pending, the same way a VM waits for
/// its disk. One that FAILED is refused: nothing about waiting fixes it.
pub(super) async fn check_snapshot_ready(st: &ApiState, named: &str) -> Result<(), ApiError> {
    let snapshot: VolumeSnapshot = match st.store.get::<VolumeSnapshot>(named).await {
        Ok(s) => s,
        Err(StoreError::NotFound(_)) => {
            return Err(ApiError::new(
                StatusCode::NOT_FOUND,
                "NotFound",
                format!("no volume snapshot {named:?} in this tenant"),
            ));
        }
        Err(e) => return Err(e.into()),
    };
    if snapshot.metadata.deletion_timestamp.is_some() {
        return Err(conflict(format!(
            "snapshot {named} is being deleted; it cannot seed a new volume"
        )));
    }
    if snapshot.status.phase == controller_api::VolumeSnapshotPhase::Failed {
        return Err(invalid_field(
            "spec.fromSnapshot",
            format!(
                "snapshot {named} failed: {}",
                snapshot
                    .status
                    .message
                    .as_deref()
                    .unwrap_or("no copy was made")
            ),
        ));
    }
    Ok(())
}

pub(super) async fn list_volume_snapshots(
    State(st): State<ApiState>,
    axum::extract::Query(q): axum::extract::Query<controller_api::ListQuery>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let selector = controller_api::Selector::parse(q.label_selector.as_deref())?;
    let mut items = st.store.list::<VolumeSnapshot>().await?;
    items.retain(|s| {
        q.tenant.as_deref().is_none_or(|t| s.spec.tenant == t)
            && selector.selects(&s.metadata.labels)
    });
    Ok(Json(
        json!({ "apiVersion": API_VERSION, "kind": "VolumeSnapshotList", "items": items }),
    ))
}

pub(super) async fn get_volume_snapshot(
    State(st): State<ApiState>,
    Path(name): Path<String>,
) -> Result<Json<VolumeSnapshot>, ApiError> {
    Ok(Json(st.store.get(&name).await?))
}

/// Ask for a point in time of a volume.
///
/// Nothing is copied here. What this writes down is that somebody wants one;
/// the reconcile pass sends the command to the node that HAS the bytes, and
/// the snapshot is `Pending` until it does.
///
/// Two refusals at the edge, and both are things no waiting will fix:
///
///   * a volume that is not there, or is another tenant's — **404**, never
///     403, by the argument `check_volume_refs` gives: a 403 would confirm
///     that a volume of that name exists somewhere.
///   * a pool whose backend cannot snapshot at all — **422**, naming the
///     driver and the node that said so. The catalogue answers this
///     (`volume/<driver>/snapshot`), which is the same claim a GPU profile
///     makes and is why the answer is available here rather than twenty
///     seconds later as a `Failed` object.
///
/// A volume that is merely not `Ready` yet is neither: the copy waits, the
/// same way a VM waits for its disk.
pub(super) async fn create_volume_snapshot(
    State(st): State<ApiState>,
    dry: controller_api::DryRun,
    Json(body): Json<VolumeSnapshot>,
) -> Result<(StatusCode, Json<VolumeSnapshot>), ApiError> {
    check_envelope(&body)?;
    if body.metadata.name.is_empty() {
        return Err(invalid("metadata.name must be set"));
    }
    if body.spec.volume.is_empty() {
        return Err(invalid("spec.volume must name the volume to snapshot"));
    }
    if body.status.node.is_some() || !body.status.backend.is_empty() {
        return Err(invalid(
            "status is controller-owned; it says where the copy actually is",
        ));
    }
    let volume: Volume = match st.store.get::<Volume>(&body.spec.volume).await {
        Ok(v) => v,
        Err(StoreError::NotFound(_)) => {
            return Err(ApiError::new(
                StatusCode::NOT_FOUND,
                "NotFound",
                format!("no volume {:?} in this tenant", body.spec.volume),
            ));
        }
        Err(e) => return Err(e.into()),
    };
    if volume.metadata.deletion_timestamp.is_some() {
        return Err(conflict(format!(
            "volume {} is being deleted; it cannot be snapshotted",
            body.spec.volume
        )));
    }
    check_pool_can_snapshot(&st, &volume).await?;

    let mut spec = body.spec;
    // The tenant follows the VOLUME and is not the client's to state: a copy
    // of somebody's data belongs to whoever the data belongs to.
    spec.tenant = volume.spec.tenant.clone();
    let snapshot = controller_api::new_volume_snapshot(&body.metadata.name, spec);
    let created = match dry.preview(&snapshot) {
        Some(preview) => preview,
        None => st.store.create(&snapshot).await?,
    };
    info!(snapshot = %created.metadata.name, volume = %created.spec.volume,
          "volume snapshot requested");
    Ok((StatusCode::CREATED, Json(created)))
}

/// Refuse a snapshot of a volume whose pool cannot take one.
///
/// Asked of the CATALOGUE of the nodes the pool names, because that is where
/// the answer is: a driver states `snapshot_support` and the agent claims
/// `volume/<driver>/snapshot` for it, exactly as it claims a GPU profile. The
/// sentence names the driver and one node that said no, because "the pool
/// cannot" is not something an operator can act on and "the filesystem driver
/// on agent-1 reports no snapshot support" is.
///
/// A pool whose nodes are not connected has no catalogue to ask and is
/// refused too, with the same sentence a pool with no candidate gets
/// elsewhere: silence here is not a yes.
pub(super) async fn check_pool_can_snapshot(
    st: &ApiState,
    volume: &Volume,
) -> Result<(), ApiError> {
    let pool: StoragePool = match st.store.get::<StoragePool>(&volume.spec.pool).await {
        Ok(p) => p,
        // A pool that has gone missing under a volume is not this request's
        // to diagnose, and refusing on it would be refusing on a guess.
        Err(StoreError::NotFound(_)) => return Ok(()),
        Err(e) => return Err(e.into()),
    };
    let wanted = common::capability::entry(
        common::capability::VOLUME,
        Some(&format!(
            "{}/{}",
            pool.spec.driver,
            common::capability::SNAPSHOT
        )),
    );
    let nodes = st.store.list::<Node>().await?;
    // Only the nodes this pool is served by, the same narrowing the pool's
    // own status derives its locality from.
    let serving: Vec<&Node> = nodes
        .iter()
        .filter(|n| pool.spec.nodes.is_empty() || pool.spec.nodes.contains(&n.metadata.name))
        .collect();
    if serving
        .iter()
        .any(|n| n.status.capacity.capabilities.contains(&wanted))
    {
        return Ok(());
    }
    let who = serving
        .first()
        .map(|n| format!("driver {} on node {}", pool.spec.driver, n.metadata.name))
        .unwrap_or_else(|| format!("driver {}", pool.spec.driver));
    Err(invalid(format!(
        "pool {} cannot snapshot ({who} reports no snapshot support)",
        pool.metadata.name
    )))
}

/// Mark it for release. Never a hard delete: the finalizer comes off once the
/// node says the copy is gone, exactly as it does for a volume — otherwise a
/// `volumesnapshot rm` would take the row and leave an LV nobody can name.
pub(super) async fn delete_volume_snapshot(
    State(st): State<ApiState>,
    Path(name): Path<String>,
) -> Result<controller_api::Removed, ApiError> {
    st.store
        .mutate::<VolumeSnapshot, _>(&name, |s| {
            if s.metadata.deletion_timestamp.is_none() {
                s.metadata.deletion_timestamp = Some(Utc::now());
            }
        })
        .await?;
    // The same sentence the cloud tier gives, because it is the same fact: a
    // snapshot object goes when the node that holds the copy says the bytes
    // are gone, and a node that is not answering leaves the object standing.
    Ok(
        controller_api::removed(VolumeSnapshot::KIND, &name, controller_api::Removal::Going)
            .saying(format!(
                "snapshot {name} will be dropped by the node holding it"
            )),
    )
}
