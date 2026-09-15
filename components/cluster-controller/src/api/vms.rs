// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! The VM edge: list, create, read, log, patch, delete — and the checks a
//! write has to pass before it reaches the store. Moved out of `api.rs`
//! unchanged.

use super::*;

/// Everything this tier can decide about a VM spec on its own — run from POST
/// and from PUT both. A document that is only checked on the way in is a
/// document that gets edited afterwards, and it is the edited one that
/// travels down to the agent: a spec.vm that is not an object gets no further
/// than build_spec_json, where it fails every pass, silently, forever.
pub(super) fn validate_vm_spec(spec: &VmSpec) -> Result<(), ApiError> {
    if !spec.vm.is_object() {
        return Err(invalid("spec.vm must be the agent's NewVmSpec object"));
    }
    if spec.vm.get("desired").is_some() {
        return Err(invalid(
            "spec.vm.desired is controller-owned; use spec.runStrategy",
        ));
    }
    // The same refusal the cloud's edge makes, made again here because this
    // edge is reachable on its own: a break-glass operator, and a cluster
    // with no cloud above it. That is the whole reason `vm_spec::check` is in
    // the shared crate rather than at the cloud: a spec.vm this tier takes
    // and the tier above refuses would be two APIs.
    controller_api::vm_spec::check(&spec.vm)?;
    if spec.user_data_said_twice() {
        return Err(controller_api::invalid_field(
            "spec.vm.cloud_init",
            "user_data and user_data_from are two starting points; name one",
        ));
    }
    Ok(())
}

pub(super) async fn list_vms(
    State(st): State<ApiState>,
    axum::extract::Query(q): axum::extract::Query<controller_api::ListQuery>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let selector = controller_api::Selector::parse(q.label_selector.as_deref())?;
    // `?tenant=` narrows here as it does one tier up, and it is a filter and
    // nothing more: this tier keeps no user directory, so nobody is confined
    // to a tenant here and nobody is being let past anything by it.
    let mut items = st.store.list::<Vm>().await?;
    items.retain(|v| {
        q.tenant
            .as_deref()
            .is_none_or(|t| v.spec.tenant.as_deref() == Some(t))
            && selector.selects(&v.metadata.labels)
    });
    Ok(Json(json!({
        "apiVersion": API_VERSION,
        "kind": "VmList",
        "items": items,
    })))
}

/// The edge is where the trace is decided: continue the caller's if it sent a
/// readable one, start a new one if it did not. The span is built and given
/// its parent before it starts — see `telemetry::in_trace` — because a parent
/// attached from inside the body arrives after the trace id has been minted.
pub(super) async fn create_vm(
    State(st): State<ApiState>,
    headers: axum::http::HeaderMap,
    dry: controller_api::DryRun,
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
    telemetry::in_trace(span, &context, create_vm_traced(st, body, dry, context)).await
}

pub(super) async fn create_vm_traced(
    st: ApiState,
    body: Vm,
    dry: controller_api::DryRun,
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
    check_volume_refs(&st, &vm).await?;
    // On the object: a VM created straight at the cluster (no cloud in the
    // picture) gets its trace here, and `meister vm create` is that
    // request. See ANNOTATION_TRACEPARENT.
    vm.metadata
        .set_traceparent(&telemetry::outgoing(&traceparent).to_string());
    tracing::Span::current().record("vm_id", &vm.metadata.uid);
    // The half that makes a preview of a VM worth more than a preview of any
    // other object: what the SCHEDULER would say. Everything above answers
    // "is this a legal VM"; this answers "and where would it go", which is
    // the question somebody looking at a suggestion actually has.
    if dry.requested() {
        let said =
            crate::reconcile::would_place(&st.store, st.scheduler.as_ref(), st.overcommit, &vm)
                .await
                .map_err(|e| {
                    ApiError::new(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "Internal",
                        format!("{e:#}"),
                    )
                })?;
        // On the phase the VM already has: a preview is a sentence about a VM
        // that has not been created, not a phase change.
        let phase = vm.status.phase().kind();
        #[allow(deprecated)]
        vm.status.assign(controller_api::VmPhase::said(
            phase,
            Some(said),
            chrono::Utc::now(),
        ));
    }
    let created = match dry.preview(&vm) {
        Some(preview) => preview,
        None => st.store.create(&vm).await?,
    };
    info!(vm = %created.metadata.name, vm_id = %created.metadata.uid,
          trace_id = %traceparent.trace_id_hex(), "vm created");
    Ok((StatusCode::CREATED, Json(created)))
}

/// Every `Volume` this VM refers to has to exist, be this tenant's, and be
/// free — checked at the edge, where a person is still holding the request.
///
/// Three refusals and each one is a different word on purpose:
///
///   * **404** for a volume in another tenant, and NOT 403. A 403 would
///     confirm that a volume of that name exists somewhere, which is exactly
///     what a caller poking at names is trying to find out. To this tenant
///     the volume does not exist, and that is what it is told.
///   * **409** for one somebody is already holding. `AccessMode` has one
///     variant and it means one consumer, so a second is a conflict rather
///     than something to queue behind.
///   * nothing at all for a volume that merely is not `Ready` yet. That is
///     not a refusal — the disk is being made — and the VM waits as Pending
///     with `VolumeNotReady` on it, the same way it waits for a node.
pub(super) async fn check_volume_refs(st: &ApiState, vm: &Vm) -> Result<(), ApiError> {
    // The shape first, and it needs no store: an entry that both names a
    // volume and describes one is refused here so that a PERSON sees it while
    // they are still holding the request. The node refuses it too — that is
    // the one that cannot be bypassed — but by then it is a Failed VM.
    if let Some(field) = vm.spec.malformed_volume_reference() {
        return Err(invalid_field(
            "spec.vm.volumes",
            format!("a referenced volume has its size and image already; drop {field:?}"),
        ));
    }
    for name in vm.spec.referenced_volumes() {
        let unknown = || {
            ApiError::new(
                StatusCode::NOT_FOUND,
                "NotFound",
                format!("no volume {name:?} in this tenant"),
            )
        };
        let volume: Volume = match st.store.get::<Volume>(&name).await {
            Ok(v) => v,
            Err(StoreError::NotFound(_)) => return Err(unknown()),
            Err(e) => return Err(e.into()),
        };
        if !controller_api::same_tenancy(&volume.spec.tenant, vm.spec.tenant.as_deref()) {
            return Err(unknown());
        }
        if volume.metadata.deletion_timestamp.is_some() {
            return Err(conflict(format!(
                "volume {name} is being deleted; it cannot be attached to a new vm"
            )));
        }
        if let Some(holder) = &volume.status.attached_to
            && holder != &vm.metadata.name
        {
            return Err(conflict(format!("volume {name} is held by {holder}")));
        }
        // And the fourth, which only a hot-plug can meet: a node-local disk
        // on a machine this VM is not running on.
        //
        // At create there is no binding yet — `spec.nodeName` is the
        // scheduler's and the locality axis is what it schedules BY, so the
        // VM lands where its disks are. On an update the VM is already
        // somewhere, and an attach is not a move: telling the node to open a
        // path that is on another machine would be a Failed VM, and moving
        // the VM to the disk would be a reschedule nobody asked for.
        //
        // 422 and not a wait, because nothing about waiting changes it.
        if let Some(node) = &vm.spec.node_name
            && let Some(elsewhere) = locality_conflict(st, &volume, node).await?
        {
            return Err(invalid_field(
                "spec.vm.volumes",
                format!("volume {name} lives on node {elsewhere}; this vm runs on node {node}"),
            ));
        }
    }
    Ok(())
}

/// The node a volume is pinned to, when that is not the one given.
///
/// The pool carries the locality and the volume carries the node, so both are
/// read — and `VolumeBinding::pins_elsewhere` is what decides, so the API
/// edge and the reconciler answer with the same function rather than with two
/// that can drift. A pool that has gone missing pins nothing, which is the
/// same direction every other unknown takes here.
pub(super) async fn locality_conflict(
    st: &ApiState,
    volume: &Volume,
    node: &str,
) -> Result<Option<String>, ApiError> {
    let pool: Option<StoragePool> = match st.store.get(&volume.spec.pool).await {
        Ok(pool) => Some(pool),
        Err(StoreError::NotFound(_)) => None,
        Err(e) => return Err(e.into()),
    };
    let binding = controller_api::VolumeBinding {
        volume: volume.metadata.name.clone(),
        node: volume.status.node.clone(),
        locality: pool.as_ref().and_then(|p| p.status.locality),
        driver: pool.as_ref().map(|p| p.spec.driver.clone()),
        pool_nodes: pool.map(|p| p.spec.nodes).unwrap_or_default(),
    };
    Ok(binding
        .pins_elsewhere(node)
        .then(|| volume.status.node.clone().unwrap_or_default()))
}

pub(super) async fn get_vm(
    State(st): State<ApiState>,
    Path(name): Path<String>,
) -> Result<Json<Vm>, ApiError> {
    Ok(Json(st.store.get(&name).await?))
}

/// What the caller wants of a console: how much, and which lines.
///
/// Read as raw pairs and not as a struct, because `hide` and `only` repeat
/// and the form encoding behind a typed `Query` cannot spell a repeated key.
/// `lines` absent = the node's own default; the ring is bounded either way,
/// so it only shortens.
pub(super) fn log_request(pairs: &[(String, String)]) -> (u32, crate::logs::Keep) {
    let lines = pairs
        .iter()
        .find(|(k, _)| k == "lines")
        .and_then(|(_, v)| v.parse().ok())
        .unwrap_or(0);
    (lines, crate::logs::Keep::from_pairs(pairs))
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
pub(super) async fn vm_logs(
    State(st): State<ApiState>,
    Path(name): Path<String>,
    headers: axum::http::HeaderMap,
    axum::extract::Query(q): axum::extract::Query<Vec<(String, String)>>,
) -> Result<axum::response::Response, ApiError> {
    let vm: Vm = st.store.get(&name).await?;
    let (lines, keep) = log_request(&q);
    // A sibling replica sent this here because IT does not hold the node's
    // session. If this one does not either, the answer is a refusal and never
    // a third hop. See `logs::FORWARDED`.
    let forwarded = headers.contains_key(crate::logs::FORWARDED);
    let payload = match crate::logs::fetch(
        &st.registry,
        &st.store,
        &st.forward,
        &vm,
        lines,
        &keep,
        "",
        forwarded,
    )
    .await
    {
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

/// What an update of a VM may not change here, and why.
///
/// The rule, whole: a field the controller acts on ONCE — when it creates the
/// instance — is immutable, and a field a controller writes belongs to the
/// server. `spec.vm` is the hard one: a node takes a spec when it creates the
/// instance and never again, so a PUT that changed it answered 200 and did
/// nothing at all. What stays free is `spec.runStrategy`, which is exactly the
/// field a level-triggered lifecycle reads every pass.
pub(super) const VM_OWNED: &[Owned] = &[
    // The row storage B rewrote, and the whole of what it says about
    // volumes: `spec.vm` is immutable in everything EXCEPT `volumes[]` from
    // its second entry on, and there only the entries that refer to a
    // `Volume` object. The projection that says it precisely is
    // `resources::frozen_vm_shape`, and `check_owned` compares through it —
    // one row, one enforcement point, so no update handler can forget it.
    //
    // It cannot be its own row, and the reason is a tier boundary rather than
    // an oversight: `spec.vm` is another crate's document (see `VmSpec.vm`),
    // its schema is not published, and `assert_tables_match_schemas` holds
    // every path in this table to a field that really exists. So the sentence
    // rides on the row that already covers it, and the `note` — which storage
    // A used to announce this change — is gone, because it has happened.
    //
    // Adding a referenced entry is the attach and leaving one out is the
    // detach; hot-plug is the reconcile consequence of that edit rather than
    // a verb of its own (KubeVirt deprecated `addvolume` in 1.6 for the same
    // reason). `Volume.status.attachedTo` stays derived either way — a Volume
    // never grows a `spec.vm`.
    Owned::structural(
        "spec.vm",
        "is immutable except for spec.vm.volumes[] from the second entry on, and there only for \
         entries that name a volume: the boot entry and every inline disk are fixed for the life \
         of the vm",
        controller_api::vm_shape_unchanged,
    ),
    Owned::immutable(
        "spec.nodeSelector",
        "is immutable; it decided where the vm was placed, and it was placed",
    ),
    // Server-owned with ONE exception, and the note names it: a client may
    // set this to `null`. That is the reschedule — the binding falls and the
    // scheduler decides again — and it is the third verb of catalogue 16, the
    // one that covers the 95 % of moves nobody needs live migration for.
    //
    // What the predicate cannot say is WHEN: it sees one field and the rule
    // is about the VM's phase. `update_vm` asks the rest.
    Owned::structural(
        "spec.nodeName",
        "is the scheduler's to set; a client may only clear it, and only on a stopped vm",
        controller_api::unbind_only,
    )
    .noting(
        "clearing it is a reschedule: the binding falls, the old node is told to destroy the \
         instance, and the scheduler places the vm again. Allowed only while runStrategy is \
         Stopped and the reported phase is Stopped",
    ),
    Owned::server_owned("spec.clusterName", "is the cloud's to set, not this tier's"),
];

/// The two labels that say which cloud owns a cluster-local object.
///
/// Not in a `*_OWNED` table because they are not spec fields and their keys
/// have dots in them, so they cannot be named as a dotted path. Same rule,
/// said once in the one place it applies: a client that could write these
/// could adopt an object into a cloud, or orphan one out of it.
///
/// Over the METADATA and not over a `Vm`, because a VM is no longer the only
/// cloud-owned object at this tier — a `Router` wears the same pair, and the
/// rule about them is a rule about the envelope rather than about VMs.
pub(super) fn check_owner_labels(
    current: &controller_api::Metadata,
    body: &controller_api::Metadata,
) -> Result<(), ApiError> {
    for key in [
        controller_api::LABEL_MANAGED_BY,
        controller_api::LABEL_CLOUD_UID,
    ] {
        if body.labels.get(key) != current.labels.get(key) {
            return Err(invalid(format!(
                "metadata.labels[\"{key}\"] says which cloud owns this object and is written \
                 by the cloud"
            )));
        }
    }
    Ok(())
}

pub(super) async fn update_vm(
    State(st): State<ApiState>,
    Path(name): Path<String>,
    dry: controller_api::DryRun,
    Json(mut body): Json<Vm>,
) -> Result<Json<Vm>, ApiError> {
    if body.metadata.name != name {
        return Err(invalid("metadata.name does not match the path"));
    }
    // Server-owned fields are refused rather than put back — the scheduler's
    // binding and the cloud's ownership marks among them. See `VM_OWNED`.
    let current: Vm = st.store.get(&name).await?;
    // Ownership first, so a cloud-owned object answers 409 rather than 422.
    refuse_if_cloud_owned(&current)?;
    validate_vm_spec(&body.spec)?;
    check_owner_labels(&current.metadata, &body.metadata)?;
    check_owned(&current, &body, VM_OWNED)?;
    // The volumes an update may have added: the same four refusals a create
    // meets, asked again because `check_owned` now lets `volumes[]` move from
    // its second entry on. A body that changed nothing about them passes
    // every one of them — the holder check already admits this VM's own name.
    check_volume_refs(&st, &body).await?;
    check_reschedule(&current, &body)?;
    check_holder_is_talking(&st, &current, &body).await?;
    body.metadata.uid = current.metadata.uid.clone();
    body.metadata.creation_timestamp = current.metadata.creation_timestamp;
    body.metadata.deletion_timestamp = current.metadata.deletion_timestamp;
    body.metadata.finalizers = current.metadata.finalizers.clone();
    body.status = current.status.clone();
    controller_api::carry_generation(&current, &mut body)?;
    match dry.preview(&body) {
        Some(preview) => Ok(Json(preview)),
        None => {
            let stored = st.store.update(&body).await?;
            note_unknown_release(&st, &current, &body).await;
            Ok(Json(stored))
        }
    }
}

/// The node this update is letting go of, if it is letting go of one.
pub(super) fn releasing<'a>(current: &'a Vm, next: &Vm) -> Option<&'a str> {
    match (current.spec.node_name.as_deref(), &next.spec.node_name) {
        (Some(node), None) => Some(node),
        _ => None,
    }
}

/// The evidence half of a reschedule: is the machine that holds this VM
/// talking?
///
/// The rule is in `controller_api` so the two tiers cannot answer it
/// differently; the read is here, because the fact lives in the store. A
/// current heartbeat IS the session — it is written by the replica holding it,
/// every beat — and it is the same fact the watchdog read to call the phase
/// `Unknown`.
async fn check_holder_is_talking(st: &ApiState, current: &Vm, next: &Vm) -> Result<(), ApiError> {
    let Some(node) = releasing(current, next) else {
        return Ok(());
    };
    // The lease and not the object: the heartbeat moved into a key of its own
    // (D-C7), and an absent lease is the same answer an absent object gave —
    // this machine has not reported.
    let heard = st.store.last_beat::<Node>(node).await?;
    holder_refusal(current, node, heard, Utc::now())
}

/// The rule this tier applies once the heartbeat has been read, as a pure
/// function: the reads are next door, so the rule can be exercised without an
/// etcd.
///
/// 409 and not 422: nothing about the request is malformed. The state of the
/// world is what refuses it, and it is a state that ends by itself.
pub(super) fn holder_refusal(
    current: &Vm,
    node: &str,
    heard: Option<chrono::DateTime<Utc>>,
    now: chrono::DateTime<Utc>,
) -> Result<(), ApiError> {
    match controller_api::unknown_needs_its_holder(
        current.status.phase().kind(),
        controller_api::Holder::Node,
        node,
        heard,
        now,
    ) {
        Some(why) => Err(conflict(why)),
        None => Ok(()),
    }
}

/// Record that a binding was let go while nobody knew what the guest was
/// doing.
///
/// Only for `Unknown`, and only after the write landed. Every other phase is
/// evidence — the node said so — and needs no note beside the `Unbound` the
/// reconciler already writes.
async fn note_unknown_release(st: &ApiState, current: &Vm, next: &Vm) {
    let Some(message) = release_event(current, next) else {
        return;
    };
    controller_api::events::record(
        &st.store,
        controller_api::events::Happening {
            kind: Vm::KIND,
            name: &current.metadata.name,
            uid: &current.metadata.uid,
            reason: controller_api::events::reason::UNBOUND,
            message,
            event_type: controller_api::EventType::Warning,
            tenant: current.spec.tenant.as_deref(),
        },
    )
    .await;
}

/// The sentence a released binding leaves on the object, where it leaves one.
pub(super) fn release_event(current: &Vm, next: &Vm) -> Option<String> {
    if current.status.phase().kind() != controller_api::VmPhaseKind::Unknown {
        return None;
    }
    let node = releasing(current, next)?;
    Some(controller_api::released_while_unknown(
        controller_api::Holder::Node,
        node,
    ))
}

/// A client may let a binding go, and only on a VM that is standing still.
///
/// The one exception to `spec.nodeName` being the scheduler's, and the whole
/// of what "reschedule" is here: no live migration, no restart of anything
/// running, no `spec.evacuation`. The binding falls, the old node is told to
/// destroy the instance, and the scheduler decides again.
///
/// **Two conditions and not one.** `runStrategy` is the INTENT and the phase
/// is the OBSERVATION, and a VM that has been told to stop and has not
/// finished stopping satisfies the first and not the second. Moving that one
/// would be moving something that is still running, which is exactly what
/// this position is not.
///
/// The sentence names the phase, because that is the half a person can act
/// on: they asked for a stop a second ago and it has not landed yet.
pub(super) fn check_reschedule(current: &Vm, next: &Vm) -> Result<(), ApiError> {
    let letting_go = current.spec.node_name.is_some() && next.spec.node_name.is_none();
    if !letting_go {
        return Ok(());
    }
    // The same rule and the same sentence as one tier up, from the one place
    // that holds both. Two copies of this drifted once already — the cloud
    // grew disk conditions the cluster does not have — and the phase half is
    // exactly the half that must not.
    if controller_api::stopped_enough(current.spec.run_strategy, current.status.phase().kind()) {
        return Ok(());
    }
    Err(invalid_field(
        "spec.nodeName",
        controller_api::not_stopped_enough(
            current.spec.run_strategy,
            current.status.phase().kind(),
        ),
    ))
}

pub(super) async fn delete_vm(
    State(st): State<ApiState>,
    Path(name): Path<String>,
) -> Result<controller_api::Removed, ApiError> {
    refuse_if_cloud_owned(&st.store.get::<Vm>(&name).await?)?;
    st.store
        .mutate::<Vm, _>(&name, |v| {
            if v.metadata.deletion_timestamp.is_none() {
                v.metadata.deletion_timestamp = Some(Utc::now());
            }
        })
        .await?;
    Ok(controller_api::removed(
        Vm::KIND,
        &name,
        controller_api::Removal::Going,
    ))
}

// --- storage, cluster-local -------------------------------------------------
//
// The same two objects the cloud tier keeps, at the tier that has NODES —
// which is the tier that can answer "who provisions this". A cluster with no
// cloud above it declares its own pools and holds its own volumes, exactly as
// it creates its own VMs; a cluster under a cloud will be handed them down the
// session, and that hop is the step after this one.
//
// No tenancy here, and that is the design rule rather than an omission: this
// tier keeps no user directory (one directory, and it is the cloud's), so
// `spec.tenant` is carried and never enforced — the same thing a
// cluster-local VM does with the field.

/// Everything that happened to one VM, recently.
///
/// No tenant filter here, and that is not an omission: this tier keeps no
/// user directory (one directory, and it is the cloud's), so a member reading
/// it is read-only over everything exactly as they are over the VM objects
/// themselves.
pub(super) async fn vm_events(
    State(st): State<ApiState>,
    Path(name): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let vm: Vm = st.store.get(&name).await?;
    let items = controller_api::events::about(&st.store, Vm::KIND, &vm.metadata.uid, &name).await;
    Ok(Json(json!({
        "apiVersion": API_VERSION,
        "kind": "EventList",
        "items": items,
    })))
}
