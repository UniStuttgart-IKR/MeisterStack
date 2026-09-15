// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! The `storagepools` and `volumes` resources.

use super::*;

// --- the storage a tenant may claim ------------------------------------------
//
// The same section the floating pools have, one noun over, and the rule runs
// through both: what EXISTS is an administrator's decision and taking room out
// of it is self-service inside a quota. Reading the block above is reading this
// one with different words.
//
// What is different is what a mistake costs. At the end of a confused address
// is a tenant that cannot be reached; at the end of a confused volume is data
// that is gone. Two rules carry the difference and both live here:
//
//   * the backend name is DERIVED from the object's uid, never allocated, so a
//     provision whose handle is lost finds its volume instead of making a
//     second one nobody knows about;
//   * a volume somebody is holding is not deleted. DELETE marks it Releasing
//     and the finalizer keeps the object until the consumer lets go.
//
// Nothing here provisions anything. What comes out is a RESERVATION — who owns
// how much room in which pool — and choosing the node that makes it real is
// the reconciler's, through the same `feasible()` a VM goes through.

/// The pools, with one thing hidden: a member sees its own quota and not
/// everybody else's. The mirror of `redact_quota` next door, and the same
/// argument — a member has to be able to see which pool is the default and
/// how much they may take out of it, and what another tenant was granted is
/// none of their business.
pub(super) fn redact_storage_quota(pool: &mut StoragePool, mine: &str) {
    // The `*` row survives, and it has to: it is this member's own ceiling
    // whenever nobody wrote a row with their name on it, and hiding it would
    // leave them looking at `QUOTA -` while a create is refused against a
    // number they cannot see. It says nothing about any other tenant.
    pool.spec.quota.retain(|tenant, _| {
        tenant == mine || tenant == controller_api::StoragePoolSpec::QUOTA_EVERYONE
    });
}

pub(super) async fn list_storage_pools(
    State(st): State<ApiState>,
    caller: Caller,
    role: CallerRole,
    tenant: CallerTenant,
    axum::extract::Query(q): axum::extract::Query<controller_api::ListQuery>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let selector = controller_api::Selector::parse(q.label_selector.as_deref())?;
    // Not a tenant's object either; see `list_floating_pools`.
    let who = Grant::new(caller, role, tenant);
    let mut items = st.store.list::<StoragePool>().await?;
    items.retain(|p| selector.selects(&p.metadata.labels));
    for pool in &mut items {
        // Before the redaction, so that a member sees the row that applies to
        // them rather than the absence the store happens to hold.
        pool.spec.state_default_quota();
        if let Some(mine) = who.confined_to() {
            redact_storage_quota(pool, mine);
        }
    }
    Ok(Json(
        json!({ "apiVersion": API_VERSION, "kind": "StoragePoolList", "items": items }),
    ))
}

pub(super) async fn get_storage_pool(
    State(st): State<ApiState>,
    Path(name): Path<String>,
    caller: Caller,
    role: CallerRole,
    tenant: CallerTenant,
) -> Result<Json<StoragePool>, ApiError> {
    let mut pool: StoragePool = st.store.get(&name).await?;
    pool.spec.state_default_quota();
    if let Some(mine) = Grant::new(caller, role, tenant).confined_to() {
        redact_storage_quota(&mut pool, mine);
    }
    Ok(Json(pool))
}

/// Everything about a pool that has to be true before it is stored.
///
/// `driver` is checked for being SET and not for being a driver this cloud
/// has heard of, which is deliberate: the catalogue lives on the nodes, an
/// admin may declare a pool before the node that serves it has ever dialled
/// in, and a cloud with an allowlist of backend names would be a second place
/// to add a driver.
pub(super) async fn check_storage_pool(
    st: &ApiState,
    pool: &StoragePool,
    updating: Option<&str>,
) -> Result<(), ApiError> {
    if pool.spec.driver.is_empty() {
        return Err(invalid(
            "spec.driver must name a storage backend, e.g. \"lvm-thin\"",
        ));
    }
    // A cloud pool is a cluster pool seen from above, so it has to say which
    // cluster. Without one there is nothing to dispatch a volume to, and a
    // volume reserved out of it would be an object nothing could ever make
    // bytes for.
    //
    // The cluster does not have to EXIST yet: a pool written before the
    // cluster dials in for the first time is an ordinary order of operations,
    // and the volumes in it stay Pending until it does — which is a sentence
    // an operator can read, unlike a 422 at three in the morning.
    if pool.spec.served_by().is_empty() {
        return Err(invalid(
            "spec.cluster must name the cluster that serves this pool (or spec.clusters, if more \
             than one really does)",
        ));
    }
    if !pool.spec.default {
        return Ok(());
    }
    // At most one default, checked here and again from inside the store after
    // the create. Two defaults would make "which pool did my disk come out
    // of" a question about ordering.
    let others: Vec<String> = st
        .store
        .list::<StoragePool>()
        .await?
        .into_iter()
        .filter(|p| p.spec.default)
        .map(|p| p.metadata.name)
        .filter(|n| Some(n.as_str()) != updating)
        .collect();
    if !others.is_empty() {
        return Err(conflict(format!(
            "storage pool {} is already marked default; exactly one may be",
            others.join(", ")
        )));
    }
    Ok(())
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
    let mut pool = StoragePool::declare(&body.metadata.name, body.spec);
    pool.metadata.labels = body.metadata.labels;
    check_storage_pool(&st, &pool, None).await?;
    let created = match dry.preview(&pool) {
        Some(preview) => preview,
        None => st.store.create(&pool).await?,
    };

    // And the same question again, from inside the store — the create is what
    // makes a race visible. No retry: an admin marked this pool default
    // outright, so there is nothing for the server to pick differently.
    if created.spec.default
        && let Err(why) = check_storage_pool(&st, &created, Some(&created.metadata.name)).await
    {
        take_back::<StoragePool>(&st, &created.metadata.name, "storage pool").await;
        return Err(why);
    }

    info!(pool = %created.metadata.name, driver = %created.spec.driver,
          nodes = created.spec.nodes.len(), default = created.spec.default,
          "storage pool created");
    Ok((StatusCode::CREATED, Json(created)))
}

/// Quotas, the node list, the default mark and the description all move. The
/// DRIVER does not: a pool that changed backend would be a pool whose live
/// volumes are on a backend its object does not name, and no reconciler could
/// ever explain where the data went.
/// What an update of this resource may not change, and why. See `VM_OWNED`
/// for the rule the tables share.
///
/// The driver was a 409 before this and is a 422 now, which is the right
/// word: nobody else took the pool, the request simply cannot be carried
/// out. What hangs off the driver is every volume already provisioned from
/// the pool — a changed driver would look them up in a backend that has
/// never heard of them.
pub(super) const STORAGE_POOL_OWNED: &[Owned] = &[
    Owned::immutable(
        "spec.driver",
        "is immutable; the volumes in this pool were provisioned by it",
    ),
    // For the same reason the driver is, one tier further: the volumes in
    // this pool have their bytes on that cluster's nodes, and a pool
    // re-pointed at another cluster would name a place they are not.
    Owned::immutable(
        "spec.cluster",
        "is immutable; the volumes in this pool have their bytes on it",
    ),
    // `spec.clusters` is deliberately NOT in this table, and the difference
    // from `spec.cluster` above is which direction the edit goes. Re-pointing
    // a pool at a different cluster moves nothing and leaves the volumes
    // behind; ADDING a cluster to the list is an operator writing down a fact
    // about the wiring — this target is dialled from over there too, this
    // export is mounted on both sides — and it is the only way a stopped VM's
    // disks can follow it across a cluster boundary. Nothing about the bytes
    // changes either way, so it is an ordinary mutable field.
    //
    // Taking one back OFF is refused where the narrowing of `spec.nodes` is,
    // and for the same reason: a volume whose record is on a cluster the pool
    // no longer names is a volume nothing can dispatch.
];

pub(super) async fn update_storage_pool(
    State(st): State<ApiState>,
    Path(name): Path<String>,
    dry: controller_api::DryRun,
    Json(mut body): Json<StoragePool>,
) -> Result<Json<StoragePool>, ApiError> {
    if body.metadata.name != name {
        return Err(invalid("metadata.name does not match the path"));
    }
    let current: StoragePool = st.store.get(&name).await?;
    keep_server_owned(&mut body.metadata, &current.metadata);
    body.status = current.status.clone();
    check_owned(&current, &body, STORAGE_POOL_OWNED)?;
    check_storage_pool(&st, &body, Some(&name)).await?;

    // A node list cannot be narrowed out from under a volume that lives on a
    // node it would drop: the volume's data is there, and an object saying
    // otherwise is worse than no object.
    let stranded: Vec<String> = st
        .store
        .list::<Volume>()
        .await?
        .into_iter()
        .filter(|v| v.spec.pool == name)
        .filter(|v| {
            v.status
                .node
                .as_deref()
                .is_some_and(|n| !body.spec.reaches(n))
        })
        .map(|v| v.metadata.name)
        .collect();
    if !stranded.is_empty() {
        return Err(conflict(format!(
            "these volumes live on nodes the new list drops: {}",
            stranded.join(", ")
        )));
    }
    // The same rule one scope up, and it arrived with `spec.clusters`: a pool
    // may be widened freely, but a cluster that is holding a record of one of
    // its volumes cannot be taken off — nothing would be able to dispatch to
    // that volume afterwards, and the object would name a cluster the pool
    // says does not serve it.
    let orphaned: Vec<String> = st
        .store
        .list::<Volume>()
        .await?
        .into_iter()
        .filter(|v| v.spec.pool == name)
        .filter(|v| {
            v.status
                .cluster
                .as_deref()
                .is_some_and(|c| !body.spec.serves(c))
        })
        .map(|v| v.metadata.name)
        .collect();
    if !orphaned.is_empty() {
        return Err(conflict(format!(
            "these volumes have their record on a cluster the new list drops: {}",
            orphaned.join(", ")
        )));
    }
    controller_api::carry_generation(&current, &mut body)?;
    match dry.preview(&body) {
        Some(preview) => Ok(Json(preview)),
        None => Ok(Json(st.store.update(&body).await?)),
    }
}

/// A pool with volumes in it stays. The same rule and the same reason as a
/// floating pool with reservations: the invariant "every volume came out of a
/// pool that exists" is worth exactly what the refusal that keeps it true is
/// worth.
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

/// The pool a volume belongs to: the one it named, or the one marked default.
///
/// The mirror of `floating::pick_pool`, refusal wording included. "No pool" is
/// the state a cloud is in before an administrator has declared any storage at
/// all, and the useful answer to a member asking for a disk on such a cloud is
/// what the administrator has to do, not `404`.
pub(super) fn pick_storage_pool<'a>(
    pools: &'a [StoragePool],
    named: Option<&str>,
) -> Result<&'a StoragePool, ApiError> {
    if let Some(name) = named.filter(|n| !n.is_empty()) {
        return pools
            .iter()
            .find(|p| p.metadata.name == name)
            .ok_or_else(|| invalid(format!("no storage pool {name:?} in this cloud")));
    }
    let defaults: Vec<&StoragePool> = pools.iter().filter(|p| p.spec.default).collect();
    match defaults.as_slice() {
        [one] => Ok(one),
        [] if pools.is_empty() => Err(invalid(
            "this cloud has no storage pool; an administrator creates one with \
             `meister storagepool create`",
        )),
        [] => Err(invalid(format!(
            "no storage pool is marked default; name one with --pool (have: {})",
            pools
                .iter()
                .map(|p| p.metadata.name.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        ))),
        // Refused at write time, so reaching this means somebody edited etcd
        // by hand. Saying so beats picking one and being unable to explain
        // which pool the data ended up on.
        many => Err(conflict(format!(
            "{} storage pools are marked default ({}); exactly one may be",
            many.len(),
            many.iter()
                .map(|p| p.metadata.name.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        ))),
    }
}

/// Every volume, refusing to answer from a partial list.
///
/// `list` drops what it cannot decode, and a dropped volume is room this
/// tenant is holding that nobody counted. The same guard
/// `floating::all_reservations` applies and for a sharper reason: there the
/// cost of undercounting is two tenants on one address, here it is a pool
/// quietly overcommitted past the disk that is actually in the machine.
pub(super) async fn all_volumes(st: &ApiState) -> Result<Vec<Volume>, ApiError> {
    let volumes = st.store.list::<Volume>().await?;
    if volumes.len() != st.store.count::<Volume>().await? {
        return Err(conflict(
            "some volume objects did not decode, so how much storage is held cannot be \
             established; refusing rather than handing out room twice",
        ));
    }
    Ok(volumes)
}

pub(super) async fn list_volumes(
    State(st): State<ApiState>,
    caller: Caller,
    role: CallerRole,
    tenant: CallerTenant,
    axum::extract::Query(q): axum::extract::Query<controller_api::ListQuery>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let selector = controller_api::Selector::parse(q.label_selector.as_deref())?;
    let who = Grant::new(caller, role, tenant).listing(q.tenant.as_deref());
    let mut items = st.store.list::<Volume>().await?;
    items.retain(|v| {
        who.keeps(Some(v.spec.tenant.as_str())) && selector.selects(&v.metadata.labels)
    });
    Ok(Json(
        json!({ "apiVersion": API_VERSION, "kind": "VolumeList", "items": items }),
    ))
}

pub(super) async fn get_volume(
    State(st): State<ApiState>,
    Path(name): Path<String>,
    caller: Caller,
    role: CallerRole,
    tenant: CallerTenant,
) -> Result<Json<Volume>, ApiError> {
    let volume: Volume = st.store.get(&name).await?;
    Grant::new(caller, role, tenant)
        .allows(Scope::of(Some(volume.spec.tenant.as_str())), Verb::Read)?;
    Ok(Json(volume))
}

/// Reserve storage.
///
/// The tenant is the caller's own unless an admin says otherwise, the pool is
/// resolved here and frozen, and `status` is entirely the server's — a client
/// that could write `status.backend` could point its object at another
/// tenant's data, which is the whole of what `check_owned_volume_status`
/// refuses.
///
/// Nothing is provisioned. What this writes down is a RESERVATION against a
/// pool's quota; a node that can reach the pool makes it real, and until then
/// the volume is `Pending` and says so.
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
        return Err(controller_api::invalid_field(
            "spec.fromSnapshot",
            "a volume starts from a base image or from a snapshot, not both; drop one",
        ));
    }
    Ok(())
}

pub(super) async fn create_volume(
    State(st): State<ApiState>,
    caller: Caller,
    role: CallerRole,
    tenant: CallerTenant,
    dry: controller_api::DryRun,
    Json(body): Json<Volume>,
) -> Result<(StatusCode, Json<Volume>), ApiError> {
    check_envelope(&body)?;
    check_owned_volume_status(&body)?;
    if body.metadata.name.is_empty() {
        return Err(invalid("metadata.name must be set"));
    }
    let who = Grant::new(caller, role, tenant);
    let owner = who
        .tenant_for_create(Some(body.spec.tenant.clone()))
        .ok_or_else(|| invalid("spec.tenant must name a tenant"))?;
    who.allows(Scope::of(Some(owner.as_str())), Verb::Write)?;
    check_tenant(&st, &owner).await?;

    if body.spec.size_gib == 0 {
        return Err(invalid("spec.sizeGib must be greater than zero"));
    }
    check_one_seed(&body)?;
    if let Some(image) = body.spec.base_image.as_deref().filter(|i| !i.is_empty()) {
        check_base_image(&st.store, image).await?;
    }
    if let Some(named) = body.spec.from_snapshot.as_deref().filter(|s| !s.is_empty()) {
        check_snapshot_seeds(&st, &who, named).await?;
    }

    let pools = st.store.list::<StoragePool>().await?;
    let pool = pick_storage_pool(&pools, Some(body.spec.pool.as_str()))?;

    // One rejection path, and it is the one in `controller_api::quota`. A
    // second sum computed here would be a second answer to "is this tenant
    // over its limit", and the wrong one is whichever an operator is not
    // looking at.
    let held = quota::StorageUsage::of(&owner, &pool.metadata.name, &all_volumes(&st).await?, None);
    if let Err(why) = quota::check_storage(pool, &owner, held.plus(body.spec.size_gib)) {
        return Err(conflict(why));
    }

    let mut spec = body.spec;
    spec.tenant = owner.clone();
    spec.pool = pool.metadata.name.clone();
    // `status.backend` stays EMPTY, like every other piece of evidence about
    // bytes that do not exist yet. See `VolumeStatus::backend`: it used to be
    // filled in here with a derived `vol-<uid>` that no backend in this tree
    // ever uses, and until the first report the object then named a path that
    // was nowhere.
    let volume = new_volume(&body.metadata.name, spec);
    let created = match dry.preview(&volume) {
        Some(preview) => preview,
        None => st.store.create(&volume).await?,
    };

    info!(volume = %created.metadata.name, tenant = %owner, pool = %created.spec.pool,
          size_gib = created.spec.size_gib, "volume reserved");
    Ok((StatusCode::CREATED, Json(created)))
}

/// What a client may never write on a volume.
///
/// `check_owned_nic_fields` one object over, and the same argument: every one
/// of these is the control plane's answer about where the DATA is, and a
/// client that could set them could point its own object at somebody else's
/// bytes — `status.backend` most directly of all, since that string is what a
/// node hands its driver.
pub(super) fn check_owned_volume_status(volume: &Volume) -> Result<(), ApiError> {
    let owned = [
        ("status.backend", !volume.status.backend.is_empty()),
        ("status.node", volume.status.node.is_some()),
        ("status.attachedTo", volume.status.attached_to.is_some()),
        (
            "status.phase",
            volume.status.phase != VolumePhaseKind::default(),
        ),
    ];
    if let Some((field, _)) = owned.into_iter().find(|(_, set)| *set) {
        return Err(invalid(format!(
            "{field} is control-plane-owned; the cloud fills it in from where the volume \
             actually is"
        )));
    }
    Ok(())
}

/// The description moves and nothing else does.
///
/// Size, pool, mode, access mode and base image are what the volume IS. A
/// resize is a real operation on a live filesystem and is explicitly out of
/// scope until the object stands; letting the field move without it would be
/// an object that lies about how big its data is.
/// What an update of this resource may not change, and why. See `VM_OWNED`
/// for the rule the tables share.
///
/// Everything about a volume except its description is decided when the disk
/// is made, and at the end of a confused volume is data that is gone rather
/// than an address that cannot be reached. The size was a 409 before this and
/// is a 422 now: growing a disk is a real operation and this is not it.
pub(super) const VOLUME_OWNED: &[Owned] = &[
    // The row storage B changed, and the `note` storage A left the space for.
    //
    // Upwards only, and the projection says it exactly: a resize compares the
    // two numbers, so growing passes and shrinking is refused with the
    // sentence. It cannot be an ordinary immutable row any more (that refused
    // both directions) and it must not be a free field (that would accept
    // both), which is what `Mutability::Structural` is for.
    //
    // Shrinking is not "not built yet": a filesystem does not know which
    // bytes past the new end were free, so taking them is taking data, and no
    // later pass gets it back. The way to a smaller disk is a new one and a
    // copy, which is a thing a tenant does and not a thing a control plane
    // does behind one.
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

pub(super) async fn update_volume(
    State(st): State<ApiState>,
    Path(name): Path<String>,
    caller: Caller,
    role: CallerRole,
    tenant: CallerTenant,
    dry: controller_api::DryRun,
    Json(mut body): Json<Volume>,
) -> Result<Json<Volume>, ApiError> {
    if body.metadata.name != name {
        return Err(invalid("metadata.name does not match the path"));
    }
    let current: Volume = st.store.get(&name).await?;
    let who = Grant::new(caller, role, tenant);
    who.allows(Scope::of(Some(current.spec.tenant.as_str())), Verb::Write)?;

    keep_server_owned(&mut body.metadata, &current.metadata);
    check_owned(&current, &body, VOLUME_OWNED)?;
    body.status = current.status.clone();
    controller_api::carry_generation(&current, &mut body)?;
    match dry.preview(&body) {
        Some(preview) => Ok(Json(preview)),
        None => Ok(Json(st.store.update(&body).await?)),
    }
}

/// Give the storage back — or say so, and wait.
///
/// The one delete in this API that does not delete. A volume somebody is
/// holding keeps its data: the object is marked `Releasing`, the finalizer
/// keeps it in the store, and the deprovision happens when the consumer lets
/// go. That is not politeness about ordering, it is the difference between a
/// tenant losing a VM and a tenant losing the contents of a disk.
///
/// A volume nobody holds goes the ordinary way: `Releasing` and the finalizer
/// all the same, because the bytes are still on a node and it is the node
/// saying they are gone that removes the object — not this handler saying they
/// should be.
pub(super) async fn delete_volume(
    State(st): State<ApiState>,
    Path(name): Path<String>,
    caller: Caller,
    role: CallerRole,
    tenant: CallerTenant,
) -> Result<controller_api::Removed, ApiError> {
    let current: Volume = st.store.get(&name).await?;
    Grant::new(caller, role, tenant)
        .allows(Scope::of(Some(current.spec.tenant.as_str())), Verb::Write)?;

    let held_by = current.status.attached_to.clone();
    let released = st
        .store
        .mutate::<Volume, _>(&name, |v| {
            if v.metadata.deletion_timestamp.is_none() {
                v.metadata.deletion_timestamp = Some(chrono::Utc::now());
            }
            v.status.phase = VolumePhaseKind::Releasing;
        })
        .await?;

    match &held_by {
        Some(vm) => info!(volume = %name, tenant = %released.spec.tenant, vm = %vm,
                          "volume marked for release; it is still attached and keeps its data"),
        None => info!(volume = %name, tenant = %released.spec.tenant,
                      "volume marked for release"),
    }
    let said = match &held_by {
        Some(vm) => {
            format!("volume {name} is attached to vm {vm}; its data stays until that vm lets go")
        }
        None => format!("volume {name} will be deprovisioned by the node holding it"),
    };
    Ok(
        controller_api::removed(Volume::KIND, &name, controller_api::Removal::Going)
            .saying(said)
            // The one fact a caller cannot derive: a volume somebody else is
            // holding open is not going anywhere yet, and `volume rm` says so.
            .detail("attachedTo", serde_json::json!(held_by)),
    )
}

/// A snapshot has no update verb, so every field of it is decided once. The
/// table is here all the same, because `/schemas` publishes it and a form
/// that can see WHY a field is grey needs the sentence — and because the
/// assertion that every named path is a real field of the schema is what
/// keeps this honest.
pub(super) const VOLUME_SNAPSHOT_OWNED: &[Owned] = &[
    Owned::immutable(
        "spec.volume",
        "is immutable; it is the disk this is a copy of",
    ),
    Owned::immutable(
        "spec.tenant",
        "is immutable; a copy of somebody's data belongs to whoever the data belongs to",
    ),
];

// --- the point in time a tenant keeps ---------------------------------------
//
// Storage B built snapshots at the cluster, where the nodes that hold the
// bytes are. This is the cloud half, and it is the same road `Volume` took in
// nightshift 0a: routes here, a `CloudCommand` pair down, evidence back up in
// `ClusterStatus.snapshots`, and a mirror that finishes the delete when the
// cluster stops naming it.
//
// There is nothing to schedule and that is not a shortcut: a snapshot is
// taken where its volume's bytes are, so the cluster is the volume's cluster
// and the node is the volume's node. What the cloud adds is the DIRECTORY —
// whose snapshot it is, and whether the volume it names is one of theirs.

pub(super) async fn list_volume_snapshots(
    State(st): State<ApiState>,
    caller: Caller,
    role: CallerRole,
    tenant: CallerTenant,
    axum::extract::Query(q): axum::extract::Query<controller_api::ListQuery>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let selector = controller_api::Selector::parse(q.label_selector.as_deref())?;
    let who = Grant::new(caller, role, tenant).listing(q.tenant.as_deref());
    let mut items = st.store.list::<VolumeSnapshot>().await?;
    items.retain(|s| {
        who.keeps(Some(s.spec.tenant.as_str())) && selector.selects(&s.metadata.labels)
    });
    Ok(Json(
        json!({ "apiVersion": API_VERSION, "kind": "VolumeSnapshotList", "items": items }),
    ))
}

pub(super) async fn get_volume_snapshot(
    State(st): State<ApiState>,
    Path(name): Path<String>,
    caller: Caller,
    role: CallerRole,
    tenant: CallerTenant,
) -> Result<Json<VolumeSnapshot>, ApiError> {
    let snapshot: VolumeSnapshot = st.store.get(&name).await?;
    Grant::new(caller, role, tenant)
        .allows(Scope::of(Some(snapshot.spec.tenant.as_str())), Verb::Read)?;
    Ok(Json(snapshot))
}

/// Ask for a copy of a disk.
///
/// Nothing is copied here and nothing is decided here. The volume has to be
/// one this caller may see — **404 and never 403** for one that is not, the
/// same argument `get_volume` makes: a 403 would confirm that a volume of
/// that name exists in somebody else's tenant.
///
/// Whether the POOL can snapshot at all is the cluster's refusal and stays
/// there: the answer is in a node's capability catalogue, which this tier does
/// not keep. So the cloud can say "not your volume" synchronously and "that
/// backend cannot" arrives as a Failed phase with the cluster's own sentence
/// — which is the tier line this whole road is drawn along.
pub(super) async fn create_volume_snapshot(
    State(st): State<ApiState>,
    caller: Caller,
    role: CallerRole,
    tenant: CallerTenant,
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
    let who = Grant::new(caller, role, tenant);
    let volume = readable_volume(&st, &who, &body.spec.volume).await?;
    if volume.metadata.deletion_timestamp.is_some() {
        return Err(conflict(format!(
            "volume {} is being deleted; it cannot be snapshotted",
            body.spec.volume
        )));
    }
    who.allows(Scope::of(Some(volume.spec.tenant.as_str())), Verb::Write)?;

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
          tenant = %created.spec.tenant, "volume snapshot requested");
    Ok((StatusCode::CREATED, Json(created)))
}

/// The snapshot a volume says it starts from has to be one this caller has.
///
/// **404 and not 403** for a snapshot in another tenant, the same argument
/// `readable_volume` makes: a 403 would confirm that a snapshot of that name
/// exists somewhere.
///
/// A snapshot that is merely not `Ready` yet is NOT refused — the copy is on
/// its way and the volume waits for it, exactly as a VM waits for its disk.
/// One being DELETED is, because that is a wait that never ends.
async fn check_snapshot_seeds(st: &ApiState, who: &Grant, named: &str) -> Result<(), ApiError> {
    let missing = || {
        ApiError::new(
            StatusCode::NOT_FOUND,
            "NotFound",
            format!("no volume snapshot {named:?} in this tenant"),
        )
    };
    let snapshot: VolumeSnapshot = match st.store.get(named).await {
        Ok(s) => s,
        Err(StoreError::NotFound(_)) => return Err(missing()),
        Err(e) => return Err(e.into()),
    };
    if who
        .allows(Scope::of(Some(snapshot.spec.tenant.as_str())), Verb::Read)
        .is_err()
    {
        return Err(missing());
    }
    if snapshot.metadata.deletion_timestamp.is_some() {
        return Err(conflict(format!(
            "snapshot {named} is being deleted; it cannot seed a new volume"
        )));
    }
    if snapshot.status.phase == controller_api::VolumeSnapshotPhaseKind::Failed {
        return Err(controller_api::invalid_field(
            "spec.fromSnapshot",
            format!(
                "snapshot {named} failed: {}",
                snapshot
                    .status
                    .message
                    .as_deref()
                    .unwrap_or("no reason recorded")
            ),
        ));
    }
    Ok(())
}

/// The volume this caller may see, or a 404 that says nothing about whose it
/// is.
async fn readable_volume(st: &ApiState, who: &Grant, name: &str) -> Result<Volume, ApiError> {
    let missing = || {
        ApiError::new(
            StatusCode::NOT_FOUND,
            "NotFound",
            format!("no volume {name:?} in this tenant"),
        )
    };
    let volume: Volume = match st.store.get(name).await {
        Ok(v) => v,
        Err(StoreError::NotFound(_)) => return Err(missing()),
        Err(e) => return Err(e.into()),
    };
    if who
        .allows(Scope::of(Some(volume.spec.tenant.as_str())), Verb::Read)
        .is_err()
    {
        return Err(missing());
    }
    Ok(volume)
}

/// Mark it for release. Never a hard delete, exactly as at the cluster: the
/// object goes when the cluster stops naming it in its status, which happens
/// when the node says the copy is gone.
pub(super) async fn delete_volume_snapshot(
    State(st): State<ApiState>,
    Path(name): Path<String>,
    caller: Caller,
    role: CallerRole,
    tenant: CallerTenant,
) -> Result<controller_api::Removed, ApiError> {
    let current: VolumeSnapshot = st.store.get(&name).await?;
    Grant::new(caller, role, tenant)
        .allows(Scope::of(Some(current.spec.tenant.as_str())), Verb::Write)?;
    st.store
        .mutate::<VolumeSnapshot, _>(&name, |s| {
            if s.metadata.deletion_timestamp.is_none() {
                s.metadata.deletion_timestamp = Some(chrono::Utc::now());
            }
        })
        .await?;
    info!(snapshot = %name, tenant = %current.spec.tenant, "snapshot marked for release");
    Ok(
        controller_api::removed(VolumeSnapshot::KIND, &name, controller_api::Removal::Going)
            .saying(format!(
                "snapshot {name} will be dropped by the node holding it"
            )),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The row storage B opened, in the one direction it opened.
    ///
    /// A disk may grow and may not shrink, and the asymmetry is not "not
    /// built yet": a filesystem does not know which bytes past the new end
    /// were free, so taking them is taking data and no later pass gets it
    /// back. The way to a smaller disk is a new one and a copy — a thing a
    /// tenant does, not a thing a control plane does behind one.
    #[test]
    fn a_volume_may_grow_and_may_not_shrink() {
        let size = |n: u64| json!({"spec": {"sizeGib": n}});
        controller_api::check_owned(&size(10), &size(10), VOLUME_OWNED).expect("a round trip");
        controller_api::check_owned(&size(10), &size(20), VOLUME_OWNED).expect("growing");
        let refused =
            controller_api::check_owned(&size(20), &size(10), VOLUME_OWNED).expect_err("shrinking");
        assert!(
            refused.message().contains("may only grow"),
            "{}",
            refused.message()
        );
        assert!(
            refused
                .message()
                .contains("shrinking a volume is not supported"),
            "the sentence a person reads: {}",
            refused.message()
        );

        // And the published row says `structural`, with the note storage A
        // left the space for — a form that greyed the field out entirely on
        // the strength of "immutable" would be greying out a resize.
        let row = VOLUME_OWNED
            .iter()
            .find(|o| o.path == "spec.sizeGib")
            .expect("the row");
        assert_eq!(row.kind, controller_api::Mutability::Structural);
        assert!(
            row.note.is_some_and(|n| n.contains("two steps")),
            "{:?}",
            row.note
        );

        // Everything that is not a number falls back to equality, which is
        // what an absent field and a client's typo both are.
        let odd = json!({"spec": {"sizeGib": "ten"}});
        controller_api::check_owned(&odd, &odd, VOLUME_OWNED).expect("a round trip");
        controller_api::check_owned(&odd, &size(20), VOLUME_OWNED).expect_err("not a number");
    }

    /// `status` is the cloud's answer about where the DATA is, and a client
    /// that could write it could point its own object at somebody else's
    /// bytes. `status.backend` most directly of all: that string is what a
    /// node hands to its driver.
    #[test]
    fn a_client_may_not_write_a_volumes_status() {
        type Setter = fn(&mut Volume);
        let owned: [(&str, Setter); 4] = [
            ("status.backend", |v| {
                v.status.backend = "vol-someone-else".into()
            }),
            ("status.node", |v| v.status.node = Some("manacor".into())),
            ("status.attachedTo", |v| {
                v.status.attached_to = Some("web".into())
            }),
            ("status.phase", |v| v.status.phase = VolumePhaseKind::Ready),
        ];
        for (field, set) in owned {
            let mut volume = Volume::declare("data", controller_api::VolumeSpec::default());
            set(&mut volume);
            let msg = format!("{:?}", check_owned_volume_status(&volume).unwrap_err());
            assert!(msg.contains(field), "the message names the field: {msg}");
        }
        // The shape a client actually sends: a size, a pool, nothing else.
        let mut plain = Volume::declare("data", controller_api::VolumeSpec::default());
        plain.spec.size_gib = 10;
        check_owned_volume_status(&plain).expect("nothing status-owned here");
    }

    fn pool(name: &str, default: bool) -> StoragePool {
        StoragePool::declare(
            name,
            controller_api::StoragePoolSpec {
                driver: "lvm-thin".into(),
                default,
                ..Default::default()
            },
        )
    }

    /// The refusals a member reads when a cloud has no storage, or has
    /// several pools and no default. Wordy on purpose and for the reason
    /// `floating::pick_pool` is wordy: "no pool" is the state a cloud is in
    /// before an administrator has declared any storage at all, and the
    /// useful answer is what the administrator has to do.
    #[test]
    fn picking_a_pool_says_what_an_administrator_would_have_to_do() {
        let msg = format!("{:?}", pick_storage_pool(&[], None).unwrap_err());
        assert!(msg.contains("no storage pool"), "{msg}");
        assert!(msg.contains("storagepool create"), "{msg}");

        let pools = vec![pool("fast", false), pool("bulk", false)];
        let msg = format!("{:?}", pick_storage_pool(&pools, None).unwrap_err());
        assert!(msg.contains("no storage pool is marked default"), "{msg}");
        assert!(msg.contains("fast, bulk"), "it lists them: {msg}");

        // A named pool is taken as named, and an unknown name is refused
        // rather than quietly replaced — a caller who asked for `fast` asked
        // for the disk they meant.
        assert_eq!(
            pick_storage_pool(&pools, Some("bulk"))
                .unwrap()
                .metadata
                .name,
            "bulk"
        );
        let msg = format!("{:?}", pick_storage_pool(&pools, Some("nvme")).unwrap_err());
        assert!(
            msg.contains("nvme") && msg.contains("no storage pool"),
            "{msg}"
        );

        // With exactly one default, saying nothing takes it.
        let pools = vec![pool("fast", true), pool("bulk", false)];
        assert_eq!(
            pick_storage_pool(&pools, None).unwrap().metadata.name,
            "fast"
        );

        // Two defaults is a store somebody edited by hand, and saying so
        // beats picking one and being unable to explain where the data went.
        let pools = vec![pool("fast", true), pool("bulk", true)];
        let msg = format!("{:?}", pick_storage_pool(&pools, None).unwrap_err());
        assert!(msg.contains("2 storage pools are marked default"), "{msg}");
    }

    /// A member sees its own ceiling and not everybody else's — the quota map
    /// is the only field on a pool that names other tenants at all.
    #[test]
    fn a_member_sees_its_own_storage_quota_and_no_one_elses() {
        let mut p = pool("fast", true);
        p.spec.quota = [("acme".to_string(), 500), ("globex".to_string(), 20)]
            .into_iter()
            .collect();
        redact_storage_quota(&mut p, "acme");
        assert_eq!(p.spec.quota.len(), 1);
        assert_eq!(p.spec.quota.get("acme"), Some(&500));

        // D-P11: the row that is about EVERYBODY stays, because for a member
        // nobody named it is their own ceiling -- and a member looking at
        // `QUOTA -` while a create is refused against a number they cannot
        // see is exactly the state this row exists to end. It still says
        // nothing about any other tenant.
        let mut p = pool("mixed", true);
        p.spec.quota = [
            (
                controller_api::StoragePoolSpec::QUOTA_EVERYONE.to_string(),
                100,
            ),
            ("globex".to_string(), 20),
        ]
        .into_iter()
        .collect();
        redact_storage_quota(&mut p, "acme");
        assert_eq!(
            p.spec
                .quota
                .get(controller_api::StoragePoolSpec::QUOTA_EVERYONE),
            Some(&100)
        );
        assert_eq!(p.spec.quota.get("globex"), None);
        // and everything else about the pool is still readable: a member has
        // to be able to see which pool is the default and what backs it.
        assert!(p.spec.default);
        assert_eq!(p.spec.driver, "lvm-thin");
    }

    /// Storage A's first defect, as a test.
    ///
    /// `status.backend` used to be filled in right here at create with a
    /// derived `vol-<uid>` — a name no backend in this tree ever gives a
    /// volume — and replaced by the real one on the node's first report. In
    /// between, the object named a path that existed nowhere, and an operator
    /// who looked in that window looked for the wrong file. So: a created
    /// volume says nothing about a backend, because nothing has made one.
    ///
    /// What the deletion did NOT cost is the rule the derived name was there
    /// to serve: a provision whose handle is lost must find its volume rather
    /// than make a second one. That rule lives on `metadata.uid`, which every
    /// backend derives its own name from, and it never needed a second copy
    /// of the answer up here.
    #[test]
    fn a_created_volume_says_nothing_about_a_backend_until_a_node_does() {
        let fresh = new_volume("data", controller_api::VolumeSpec::default());
        assert!(
            fresh.status.backend.is_empty(),
            "no node has been asked yet: {:?}",
            fresh.status.backend
        );
        assert!(fresh.status.node.is_none());
        assert_eq!(fresh.status.phase, VolumePhaseKind::Pending);

        // And the same string, arriving as evidence, is a client's 422 — the
        // field is the control plane's answer about where the data is.
        let mut claimed = fresh.clone();
        claimed.status.backend = "/tmp/vols/deadbeef.raw".into();
        check_owned_volume_status(&claimed).expect_err("still not a client's to write");
    }

    /// A volume carries the finalizer that makes "detach before delete" the
    /// one path out. The mirror of what `new_vm` does, for a reason with more
    /// at stake: at the end of getting this wrong is data that is gone.
    #[test]
    fn a_volume_is_born_with_the_release_finalizer_on_it() {
        let v = new_volume("data", controller_api::VolumeSpec::default());
        assert!(
            v.metadata
                .finalizers
                .contains(&controller_api::VOLUME_RELEASE_FINALIZER.to_string()),
            "{:?}",
            v.metadata.finalizers
        );
        assert_eq!(v.status.phase, VolumePhaseKind::Pending);
        assert!(v.status.attached_to.is_none());
    }
}
