// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! The `vms` resource: create, read, update, delete, plus logs and console.

use super::*;

// --- vms -------------------------------------------------------------------

/// Every base_image a VM spec names. A volume without one is a blank disk and
/// references nothing. The boot source resolves against the same node-local
/// directory but is deliberately not catalogued in v1 — the check covers disk
/// base images, which is what the design put in the catalogue.
pub(super) fn base_images(vm: &serde_json::Value) -> BTreeSet<String> {
    vm.get("volumes")
        .and_then(|v| v.as_array())
        .map(|vols| {
            vols.iter()
                .filter_map(|v| v.get("base_image")?.as_str())
                .filter(|s| !s.is_empty())
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

/// A VM has at least one CPU and at least one megabyte, and that is the whole
/// of what this checks.
///
/// Deliberately structural and not a sizing rule. The cloud does NOT work out
/// how big a VM is or whether it fits — that is the scheduler's, against real
/// capacity, and a second place that answers "how big" is exactly the drift
/// this control plane is careful about elsewhere. So `vcpus: 100000` passes
/// here and comes to rest as `Pending` with a reason, which is the honest
/// answer: nothing has room for it today, and something might tomorrow.
///
/// But `vcpus: 0` and `memory_mib: -1` are not sizing questions. They are not
/// a VM. Before this they answered 201, bound, burned a scheduling slot and
/// came back `Failed` when the agent could not build them — a refusal three
/// tiers and a round trip away from the request that caused it.
///
/// The fields are read out of the JSON rather than off `InstanceSpec` because
/// at this tier `spec.vm` IS json: the cloud carries the agent's document
/// without deserialising it, on purpose, so that a spec field added below can
/// travel without a change here. `-1` never reaches the `u32` that would have
/// refused it.
pub(super) fn check_vm_shape(vm: &serde_json::Value) -> Result<(), ApiError> {
    // A referenced volume has its size and image already, refused where a
    // person can still read it. Built through `VmSpec` so the rule is the one
    // function both tiers call rather than two that could drift.
    let as_spec: controller_api::VmSpec = serde_json::from_value(serde_json::json!({ "vm": vm }))
        .unwrap_or_else(|_| {
            // Unreachable in practice: `vm` is already a Value and every
            // other field of VmSpec defaults. A malformed one falls through
            // to the checks below, which is where "is this a VM at all" is
            // answered anyway.
            serde_json::from_value(serde_json::json!({ "vm": {} })).expect("an empty spec")
        });
    if let Some(field) = as_spec.malformed_volume_reference() {
        return Err(controller_api::invalid_field(
            "spec.vm.volumes",
            format!("a referenced volume has its size and image already; drop {field:?}"),
        ));
    }
    // `vcpus >= 1` and `memory_mib >= 1` moved into `vm_spec::check` with the
    // rest of the document's own rules: this edge is no longer the only one
    // that makes them.
    Ok(())
}

/// Fields on a NIC that the control plane owns, refused when a client sends
/// them.
///
/// A tenancy boundary rather than tidiness. `vxlan_id` comes from the VM's
/// tenant, `floating_ips` and `routed_subnets` from what that tenant was
/// allocated — and all three injectors deliberately leave a NIC alone that
/// already carries the field, because a cluster with no cloud above it has to
/// be able to say these things in the spec itself. At THIS edge the spec is a
/// member's POST body, so that same skip would let one write another tenant's
/// VNI into its own NIC and land on their overlay, or name an allowlist wide
/// enough to source from anywhere (the tap rules are built from these lists).
/// Nobody needs to set them here: the cloud resolves all three from the
/// tenant, and refusing is the difference between a rule and a suggestion.
pub(super) fn check_owned_nic_fields(vm: &serde_json::Value) -> Result<(), ApiError> {
    let nics = vm
        .get("nics")
        .and_then(|n| n.as_array())
        .map(Vec::as_slice)
        .unwrap_or(&[]);
    for (i, nic) in nics.iter().enumerate() {
        for field in [
            "vxlan_id",
            controller_api::floating::NIC_FLOATING_IPS,
            controller_api::floating::NIC_ROUTED_SUBNETS,
        ] {
            if nic.get(field).is_some_and(|v| !v.is_null()) {
                return Err(invalid(format!(
                    "spec.vm.nics[{i}].{field} is control-plane-owned; the cloud fills it in \
                     from the vm's tenant"
                )));
            }
        }
    }
    Ok(())
}

/// Every `Volume` this VM refers to has to exist, be this tenant's, and be
/// free — asked at the cloud's edge, where a person is still holding the
/// request.
///
/// The same three words `check_volume_refs` says one tier down, and
/// deliberately the same function name: a member who names a volume at the
/// cloud and a member who names one at the cluster are asking the same
/// question, and two different answers to it would be two different products.
///
///   * **404** for a volume in another tenant, and NOT 403. A 403 would
///     confirm that a volume of that name exists somewhere, which is exactly
///     what a caller poking at names is trying to find out.
///   * **409** for one somebody else is already holding, and for one that is
///     being deleted. `AccessMode` has one variant and it means one consumer.
///   * nothing at all for a volume that is merely not `Ready` yet. That is
///     not a refusal — the disk is being made — and the VM waits as Pending
///     with `VolumeNotReady` on it, put there by `servable_clusters` in the
///     reconciler. The cloud does not hold a request open for bytes.
///
/// The fourth refusal the cluster makes — a node-local disk on a machine this
/// VM is not running on — has no counterpart here on purpose: this tier never
/// names a node. Which CLUSTER can serve the volumes is the same question one
/// scope wider, and `servable_clusters` answers it as placement rather than
/// as a refusal, because at the cloud a volume on another cluster is a
/// placement that does not exist yet rather than a request that is wrong.
pub(super) async fn check_volume_refs(
    st: &ApiState,
    tenant: Option<&str>,
    vm_name: &str,
    spec: &VmSpec,
) -> Result<(), ApiError> {
    if let Some((secret, key)) = spec.user_data_from() {
        let unknown = || {
            ApiError::new(
                StatusCode::NOT_FOUND,
                "NotFound",
                format!("no secret {secret:?} in this tenant"),
            )
        };
        let object: controller_api::Secret = match st.store.get(&secret).await {
            Ok(s) => s,
            Err(StoreError::NotFound(_)) => return Err(unknown()),
            Err(e) => return Err(e.into()),
        };
        // 404 and not 403, by the argument this file makes about volumes: a
        // 403 would confirm that a secret of that name exists somewhere.
        if !controller_api::same_tenancy(&object.spec.tenant, tenant) {
            return Err(unknown());
        }
        // The KEY is checked here too, where a person is still holding the
        // request. It is not a security boundary — the cluster checks it
        // again at dispatch, and that is the one that cannot be bypassed —
        // it is the difference between a 422 now and a VM that sits Pending
        // until somebody reads its message.
        if !object.spec.data.contains_key(&key) {
            return Err(controller_api::invalid_field(
                "spec.vm.cloud_init.user_data_from.key",
                format!(
                    "secret {secret} has no key {key:?}; it has [{}]",
                    object
                        .spec
                        .data
                        .keys()
                        .cloned()
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
            ));
        }
    }
    for name in spec.referenced_volumes() {
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
        if !controller_api::same_tenancy(&volume.spec.tenant, tenant) {
            return Err(unknown());
        }
        if volume.metadata.deletion_timestamp.is_some() {
            return Err(conflict(format!(
                "volume {name} is being deleted; it cannot be attached to a new vm"
            )));
        }
        if let Some(holder) = &volume.status.attached_to
            && holder != vm_name
        {
            return Err(conflict(format!("volume {name} is held by {holder}")));
        }
    }
    Ok(())
}

/// Everything the cloud can decide about a VM spec on its own — run from POST
/// and from PUT both. A document that is only checked on the way in is a
/// document that gets edited afterwards, and it is the edited one that
/// travels down to the agent.
pub(super) async fn validate_vm_spec(store: &EtcdStore, spec: &VmSpec) -> Result<(), ApiError> {
    check_no_node_name(spec)?;
    if !spec.vm.is_object() {
        return Err(invalid("spec.vm must be the agent's NewVmSpec object"));
    }
    if spec.vm.get("desired").is_some() {
        return Err(invalid(
            "spec.vm.desired is controller-owned; use spec.runStrategy",
        ));
    }
    // The node's own create document, deserialised HERE — synchronously,
    // where the caller is still listening. Before this the cloud answered 201
    // to any shape and the node said `missing field "boot"` into a status
    // field some seconds later. First, because a document that is not one
    // makes every check below it meaningless.
    controller_api::vm_spec::check(&spec.vm)?;
    check_vm_shape(&spec.vm)?;
    check_owned_nic_fields(&spec.vm)?;
    check_owned_volume_fields(&spec.vm, &catalogue_sources(store, &spec.vm).await)?;
    if spec.user_data_said_twice() {
        return Err(controller_api::invalid_field(
            "spec.vm.cloud_init",
            "user_data and user_data_from are two starting points; name one",
        ));
    }
    // The seed's hostname is the control plane's: it comes from the object's
    // own name one tier down, and a client that could set it would be a
    // client whose VM calls itself something the API never agreed to.
    // Everything else in the block — user_data above all — is the client's,
    // untouched and unread: what is valid cloud-init is cloud-init's
    // question, and a control plane that validated it would be one that
    // rejects next year's syntax.
    if spec
        .vm
        .get("cloud_init")
        .and_then(|c| c.get("local_hostname"))
        .is_some_and(|v| !v.is_null())
    {
        return Err(invalid(
            "spec.vm.cloud_init.local_hostname is control-plane-owned; it comes from the vm's \
             own name. Write a meta_data of your own to say something else",
        ));
    }
    for image in base_images(&spec.vm) {
        check_base_image(store, &image).await?;
    }
    Ok(())
}

/// That base image is registered here and is usable.
///
/// One function because there are two callers now — a VM's embedded volumes
/// and a `Volume` object — and two copies of "is this image usable" would be
/// two answers to give a tenant about the same image.
///
/// A Failed image is one a node has already tried and could not use: a
/// checksum that did not match, a url that did not answer. Refusing here is
/// the whole point of the phase — the alternative is an object that is
/// accepted, placed, and then fails at provision on every node it is offered
/// to.
pub(super) async fn check_base_image(store: &EtcdStore, name: &str) -> Result<(), ApiError> {
    match store.get::<Image>(name).await {
        Ok(image) if image.status.phase().kind() == controller_api::ImagePhaseKind::Failed => {
            Err(invalid(format!(
                "base_image {:?} is not usable: {}",
                image.metadata.name,
                image.status.phase().message().unwrap_or("unknown reason")
            )))
        }
        Ok(_) => Ok(()),
        Err(StoreError::NotFound(_)) => Err(invalid(format!(
            "unknown base_image {name:?}; register it first (meister image create)"
        ))),
        Err(e) => Err(e.into()),
    }
}

/// Fields on a volume that the control plane owns, refused when a client
/// sends a value of its OWN.
///
/// The same boundary `check_owned_nic_fields` guards, one field-list over.
/// Where a base image is fetched from and what it must hash to come out of
/// the Image OBJECT, resolved by the cloud — a client that could write them
/// into its own spec could point a `base_image` name at bytes of its own
/// choosing while the catalogue entry everybody else reads says something
/// different.
///
/// **Presence is not the offence; disagreement is.** Refusing the field
/// outright broke read-modify-write on every VM that has a base image, and a
/// control plane that will not take back the document it just handed out is
/// one nobody can edit: a PATCH here is a merge onto the STORED object (see
/// the `patch!` macro), so `vm stop` on a VM with an Ubuntu image arrived
/// carrying the very url this cloud wrote into it, and was answered with
/// "spec.vm.volumes[0].base_image_url is control-plane-owned". Found in the
/// lab, on the first `vm stop` anybody had run against a cloud VM built from
/// the catalogue.
///
/// So `resolved` is what the catalogue says right now, and a value equal to
/// it is the client giving the object back unchanged. Anything else is
/// refused with the sentence it always had.
pub(super) fn check_owned_volume_fields(
    vm: &serde_json::Value,
    resolved: &std::collections::BTreeMap<String, (String, String)>,
) -> Result<(), ApiError> {
    let volumes = vm
        .get("volumes")
        .and_then(|v| v.as_array())
        .map(Vec::as_slice)
        .unwrap_or(&[]);
    for (i, volume) in volumes.iter().enumerate() {
        let ours = volume
            .get("base_image")
            .and_then(|b| b.as_str())
            .and_then(|name| resolved.get(name));
        for (field, catalogue) in [
            ("base_image_url", ours.map(|(url, _)| url)),
            ("base_image_sha256", ours.map(|(_, sha)| sha)),
        ] {
            let Some(said) = volume.get(field).filter(|v| !v.is_null()) else {
                continue;
            };
            if said.as_str() == catalogue.map(String::as_str) {
                continue;
            }
            return Err(invalid(format!(
                "spec.vm.volumes[{i}].{field} is control-plane-owned; the cloud fills it in \
                 from the image catalogue"
            )));
        }
        // `volume` itself is NOT on this list, and that is the difference
        // between this function and the tenancy check below it.
        //
        // It named a door that was shut: until resolution landed, a spec
        // naming a `Volume` object would have booted the VM on a fresh blank
        // disk instead of the tenant's data, so the field was refused
        // outright. Both tiers under this one resolve the name now
        // (`check_volume_refs` at the cluster, `servable_clusters` here), and
        // what the refusal's own comment promised has taken its place: the
        // volume named has to be one this VM's tenant owns, asked in
        // `check_volume_refs` where the tenant is known. A client MAY write
        // this field — it is the whole point of the object.
    }
    Ok(())
}

/// What the catalogue says about every base image this spec names: the url
/// and the checksum, by image name.
///
/// Read twice per request and deliberately: once to hold the client's own
/// copy of these fields against (`check_owned_volume_fields`) and once to
/// write them in (`resolve_base_images`). An image nobody registered is
/// simply absent — `validate_vm_spec` has already refused it by name — and a
/// path-based image has neither field, so its volume keeps the spec it has
/// always had.
pub(super) async fn catalogue_sources(
    store: &EtcdStore,
    vm: &serde_json::Value,
) -> std::collections::BTreeMap<String, (String, String)> {
    let mut sources: std::collections::BTreeMap<String, (String, String)> = Default::default();
    for name in base_images(vm) {
        let Ok(image) = store.get::<Image>(&name).await else {
            continue;
        };
        if let (Some(url), Some(sha256)) = (image.spec.url, image.spec.sha256) {
            sources.insert(name, (url, sha256));
        }
    }
    sources
}

/// Write the catalogue's answer into the spec: where each base image comes
/// from, and what it must hash to.
///
/// At the create edge and once, so the VM keeps the image it was created
/// against even if somebody re-registers the name later — which is the same
/// promise the tenant and the VNI make on this object.
///
/// Only for images that HAVE a url. A path-based image gets nothing written
/// into its volume at all, so its spec is byte for byte the spec it has
/// always been and the node looks the name up locally exactly as before.
pub(super) async fn resolve_base_images(
    store: &EtcdStore,
    vm: &mut serde_json::Value,
) -> Result<(), ApiError> {
    let sources = catalogue_sources(store, vm).await;
    if sources.is_empty() {
        return Ok(());
    }
    let Some(volumes) = vm.get_mut("volumes").and_then(|v| v.as_array_mut()) else {
        return Ok(());
    };
    for volume in volumes.iter_mut() {
        let Some(name) = volume.get("base_image").and_then(|b| b.as_str()) else {
            continue;
        };
        let Some((url, sha256)) = sources.get(name).cloned() else {
            continue;
        };
        let Some(volume) = volume.as_object_mut() else {
            continue;
        };
        volume.insert("base_image_url".into(), json!(url));
        volume.insert("base_image_sha256".into(), json!(sha256));
    }
    Ok(())
}

/// Would this tenant still be inside its quota afterwards?
///
/// Run from POST and from PUT both, and that is the half that gets forgotten:
/// a PUT that raises an existing VM's vCPUs is the same act as creating one
/// that size, and a control plane that only guards the create is a control
/// plane whose quota is a suggestion.
///
/// A tenant with no quota costs nothing at all — no listing, no arithmetic —
/// which is what keeps every create in a fleet that has never set one exactly
/// as cheap as it was. An unscoped VM (an admin's, belonging to nobody) has
/// no tenant and therefore no ceiling; that is the shape every VM had before
/// M5 and the one an admin still gets by naming none.
///
/// `except` is the VM being changed, taken out of the sum so the caller can
/// put it back at its new size. `None` on a create.
///
/// The listing is guarded the way `delete_image`'s is: `list` drops what it
/// cannot decode, and a VM not seen is usage not counted — which would let a
/// tenant past its ceiling by exactly the size of whatever failed to parse.
/// Refusing to answer beats answering from a list that is not all of them.
pub(super) async fn check_quota(
    st: &ApiState,
    tenant: Option<&str>,
    adding: Capacity,
    except: Option<&str>,
) -> Result<(), ApiError> {
    let Some(tenant) = tenant else { return Ok(()) };
    let object: Tenant = st.store.get(tenant).await?;
    if object.spec.quota.is_unset() {
        return Ok(());
    }
    let vms = st.store.list::<Vm>().await?;
    if vms.len() != st.store.count::<Vm>().await? {
        return Err(conflict(
            "cannot tell how much this tenant is holding (some vm objects did not decode); \
             refusing to let it grow",
        ));
    }
    let after = quota::Usage::of(tenant, &vms, except).plus(adding);
    let Err(why) = quota::check(&object.spec.quota, tenant, after) else {
        return Ok(());
    };
    // On the TENANT and not on a VM: the VM this was about is being refused
    // and will not exist, so an event pointing at it would point at nothing.
    // What an operator wants to see is that this tenant has been hitting its
    // ceiling — which is exactly what the aggregation on (tenant, reason)
    // gives, one object with a count rather than one per attempt.
    events::record(
        &st.store,
        events::Happening {
            kind: Tenant::KIND,
            name: tenant,
            uid: &object.metadata.uid,
            reason: events::reason::QUOTA_EXCEEDED,
            message: why.clone(),
            event_type: controller_api::EventType::Warning,
            tenant: Some(tenant),
        },
    )
    .await;
    Err(invalid(why))
}

/// A member sees its own tenant's VMs and nothing else. Filtering the list
/// rather than only guarding the individual GET is the point: a name is an
/// inventory, and handing over the whole one is the leak that matters.
pub(super) async fn list_vms(
    State(st): State<ApiState>,
    caller: Caller,
    role: CallerRole,
    tenant: CallerTenant,
    axum::extract::Query(q): axum::extract::Query<controller_api::ListQuery>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let selector = controller_api::Selector::parse(q.label_selector.as_deref())?;
    let who = Grant::new(caller, role, tenant).listing(q.tenant.as_deref());
    let mut items = st.store.list::<Vm>().await?;
    items
        .retain(|vm| who.keeps(vm.spec.tenant.as_deref()) && selector.selects(&vm.metadata.labels));
    Ok(Json(
        json!({ "apiVersion": API_VERSION, "kind": "VmList", "items": items }),
    ))
}

/// The edge is where the trace is decided: continue the caller's if it sent a
/// readable one, start a new one if it did not. The span is built and given
/// its parent before it starts — see `telemetry::in_trace` — because a parent
/// attached from inside the body arrives after the trace id has been minted.
pub(super) async fn create_vm(
    State(st): State<ApiState>,
    caller: Caller,
    role: CallerRole,
    tenant: CallerTenant,
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
    let who = Grant::new(caller, role, tenant);
    telemetry::in_trace(
        span,
        &context,
        create_vm_traced(st, who, body, dry, context),
    )
    .await
}

pub(super) async fn create_vm_traced(
    st: ApiState,
    who: Grant,
    body: Vm,
    dry: controller_api::DryRun,
    traceparent: telemetry::TraceParent,
) -> Result<(StatusCode, Json<Vm>), ApiError> {
    if body.metadata.name.is_empty() {
        return Err(invalid("metadata.name must be set"));
    }
    check_envelope(&body)?;
    validate_vm_spec(&st.store, &body.spec).await?;

    // Whose it is, decided before anything is written: named by the client,
    // or the member's own. A tenant that does not exist is refused here and
    // not at the cluster, because a VM bound to a tenant nobody created would
    // be a VM with a network identifier nobody allocated.
    //
    // **Required, and that is D-P10's answer to "one rule or two".** A volume,
    // a floating address and a secret have each refused a create without a
    // tenant since they existed; a VM did not, so `vm ls` showed `TENANT -`
    // beside disks that could not have been made that way. The three are the
    // rule and the VM was the exception, so the VM moves: whose a thing is,
    // is decided when it is made, and an object nobody owns is one no member
    // can ever see and no quota ever counts. A member never meets this — the
    // server fills their own tenant in — and an admin says `-t`.
    let owner = who
        .tenant_for_create(body.spec.tenant.clone())
        .ok_or_else(|| invalid("spec.tenant must name a tenant"))?;
    who.allows(Scope::of(Some(owner.as_str())), Verb::Write)?;
    check_tenant(&st, &owner).await?;
    // After the owner is known and not in `validate_vm_spec`, because whose
    // volume it has to be is exactly the question the owner answers.
    check_volume_refs(&st, Some(owner.as_str()), &body.metadata.name, &body.spec).await?;
    // Before the create and not after: a VM that was written and then found
    // to be over the ceiling is a VM somebody has to go and delete.
    check_quota(
        &st,
        Some(owner.as_str()),
        Capacity::wanted_by_spec(&body.spec.vm),
        None,
    )
    .await?;

    // Server-owned metadata; client keeps name + labels.
    let mut spec = body.spec;
    resolve_base_images(&st.store, &mut spec.vm).await?;
    let mut vm = new_vm(
        &body.metadata.name,
        VmSpec {
            // Placement is the controller's job at this tier too, and the node is
            // never the cloud's business at all.
            cluster_name: None,
            node_name: None,
            tenant: Some(owner),
            ..spec
        },
    );
    vm.metadata.labels = body.metadata.labels;
    // On the object, because the reconciler that picks this VM up has no
    // other way back to the request it came from. See ANNOTATION_TRACEPARENT.
    vm.metadata
        .set_traceparent(&telemetry::outgoing(&traceparent).to_string());
    tracing::Span::current().record("vm_id", &vm.metadata.uid);
    // What the scheduler would say, one scope wider than at the cluster: a
    // cluster rather than a node. The same reason it is worth having — a
    // suggestion is only worth showing if it says where the thing would land.
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
        // On the phase the VM already has, because a preview is not a phase
        // change: it is a sentence about a VM that has not been created.
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

pub(super) async fn get_vm(
    State(st): State<ApiState>,
    Path(name): Path<String>,
    caller: Caller,
    role: CallerRole,
    tenant: CallerTenant,
) -> Result<Json<Vm>, ApiError> {
    let vm: Vm = st.store.get(&name).await?;
    Grant::new(caller, role, tenant).allows(Scope::of(vm.spec.tenant.as_deref()), Verb::Read)?;
    Ok(Json(vm))
}

/// What an update of this resource may not change, and why.
///
/// One table per resource, next to the handler that enforces it, and the rule
/// they all say: a field the controller acts on ONCE — when it creates the
/// thing — is immutable, and a field a controller writes belongs to the
/// server. Everything not named here is free, and the free half is the half
/// that matters: `spec.runStrategy`, `spec.schedulable`, the quotas, the
/// labels and the annotations all stay editable, because they are the fields
/// an operator edits.
///
/// `spec.vm` is the hard one and the reason this whole table exists: a node
/// takes a spec when it CREATES the instance and never again, so a PUT that
/// changed it answered 200 and did nothing. The honest answer names the only
/// way to get a different VM — and says it out loud, because with volumes
/// that do not outlive a VM today that way costs data.
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
        "spec.clusterSelector",
        "is immutable; it decides where the vm was placed, and it was placed",
    ),
    Owned::server_owned(
        "spec.tenant",
        "is set by the server; whose a vm is, is decided once",
    ),
    // Server-owned with ONE exception, the same one the cluster tier's
    // `spec.nodeName` has and for the same reason: a client may set it to
    // `null`. That is the reschedule, one tier up — the binding falls, the
    // old cluster is told to destroy the VM, and the cloud scheduler decides
    // again over `servable_clusters`.
    //
    // The predicate opens only the SHAPE of the edit; whether it is allowed
    // right now depends on the phase and on what disks hang off the VM, and
    // neither of those is a property of this field. `check_reschedule` asks
    // the rest.
    Owned::structural(
        "spec.clusterName",
        "is the scheduler's to set; a client may only clear it, and only on a stopped vm",
        controller_api::unbind_only,
    )
    .noting(
        "clearing it moves the vm to another cluster: the old one is told to destroy it, the \
         disks on a pool both clusters serve follow without being copied, and the scheduler \
         places it again. Allowed only while runStrategy is Stopped and the reported phase is \
         Stopped, and never for a vm with a node-local disk",
    ),
];

/// The `Vm` shape this tier publishes: `spec.nodeName` taken out of it.
///
/// One `Vm` type serves both tiers, deliberately — the API form is the same on
/// both, each writes its own binding and ignores the other's. What that left
/// behind at THIS tier is a field with no meaning: the cloud places on
/// CLUSTERS, nothing here ever writes `spec.nodeName`, and `/schemas`
/// published it anyway. A client read it, believed it, set it, and was
/// ignored (fremdsicht 2). A shape that does not name a field cannot be
/// believed in, so this tier does not name it — and `check_no_node_name`
/// below refuses a body that names it anyway, at both write edges, so the two
/// statements agree.
pub(super) fn cloud_vm_schema() -> serde_json::Value {
    let mut schema = controller_api::schema_of::<Vm>();
    if let Some(properties) = schema
        .get_mut("$defs")
        .and_then(|defs| defs.get_mut("VmSpec"))
        .and_then(|spec| spec.get_mut("properties"))
        .and_then(|properties| properties.as_object_mut())
    {
        properties.remove("nodeName");
    }
    schema
}

/// A field this tier does not have is a field a body may not carry.
///
/// A 422 and not a silent drop: the client wrote it down because it meant
/// something by it, and "the cloud placed your vm somewhere else than you
/// asked" is the one answer it must never get without hearing about it.
pub(super) fn check_no_node_name(spec: &VmSpec) -> Result<(), ApiError> {
    match spec.node_name.is_some() {
        true => Err(controller_api::invalid_field(
            "spec.nodeName",
            "spec.nodeName is not a field of a vm at this tier: the cloud places on clusters, \
             and which machine inside one runs the vm is the cluster's decision. Use \
             spec.clusterName, or spec.nodeSelector to say what kind of machine it needs",
        )),
        false => Ok(()),
    }
}

/// A client may let the CLUSTER binding go, and only on a VM that is standing
/// still and whose disks can follow it.
///
/// The cloud half of catalogue 16's third verb. The two phase conditions are
/// the cluster tier's, word for word — `runStrategy` is the intent, the phase
/// is the observation, and a VM that has been told to stop and has not
/// finished stopping satisfies the first and not the second.
///
/// What is new one tier up is the DISKS. A node-local volume is bytes on one
/// machine of one cluster and no amount of scheduling moves them, so the VM
/// is pinned and the sentence says by what and where — an operator who reads
/// "pinned by volume data-1 on node agent-1 in cluster-1" knows both what to
/// delete and where to look. A pool that names only one cluster pins the same
/// way for a smaller reason: nobody has said the bytes are reachable from
/// anywhere else.
///
/// A pool whose clusters disagree about what it is made of is refused too,
/// and that one is worth the extra read: `spec.clusters` is an operator's
/// claim, and the only evidence against it is what each cluster says about
/// its own pool of that name.
/// One referenced disk of a VM, reduced to the four facts that decide
/// whether it can follow the VM to another cluster.
///
/// A value rather than four lookups inside the rule, because the rule is the
/// part worth testing and the lookups need an etcd. Everything here is read
/// off objects this tier already owns.
#[derive(Clone, Debug)]
pub(super) struct DiskFacts {
    pub volume: String,
    pub pool: String,
    /// Where the pool's driver says the bytes are, as its nodes agree.
    /// `None` = nobody has said, which never pins anything.
    pub locality: Option<controller_api::Locality>,
    /// The node holding it, for the sentence.
    pub node: Option<String>,
    /// The cluster whose record holds it, for the sentence.
    pub cluster: String,
    /// How many clusters the pool claims to serve.
    pub serving: usize,
    /// The first two serving clusters that describe the pool differently, if
    /// any do.
    pub disagreement: Option<(String, String)>,
}

/// Why this VM may not let its cluster binding go — or `None`, meaning it may.
///
/// The cloud half of catalogue 16's third verb, as a pure rule. The two phase
/// conditions are the cluster tier's, word for word: `runStrategy` is the
/// intent, the phase is the observation, and a VM that has been told to stop
/// and has not finished stopping satisfies the first and not the second.
///
/// What is new one tier up is the DISKS, and there are three ways one holds a
/// VM back:
///
///   * `node-local` — the bytes are on one machine of one cluster and no
///     amount of scheduling moves them. The sentence names the volume, the
///     node and the cluster, because an operator who reads it needs to know
///     both what to delete and where to look.
///   * a pool naming ONE cluster — the same pin for a smaller reason: nobody
///     has said the bytes are reachable from anywhere else, and this tier
///     does not guess that they are.
///   * a pool naming two clusters that describe it differently — the claim
///     `spec.clusters` makes, contradicted by what those clusters actually
///     report about their own pool of that name.
///
/// Ephemeral disks are not here at all, and that is the rule rather than an
/// omission: an inline entry has no `Volume` object, so it is not a
/// referenced volume, and it is made fresh at the destination. Instance-store
/// semantics, the same as one tier down.
pub(super) fn reschedule_refusal(current: &Vm, disks: &[DiskFacts]) -> Option<String> {
    // The rule, and the sentence, from the one place both tiers read them —
    // see `controller_api::stopped_enough`. `Failed` and `Unknown` are
    // stopped enough, which is the whole of D12: the phases a wedged VM is
    // actually in were the phases the call that would rescue it refused.
    if !controller_api::stopped_enough(current.spec.run_strategy, current.status.phase().kind()) {
        return Some(controller_api::not_stopped_enough(
            current.spec.run_strategy,
            current.status.phase().kind(),
        ));
    }
    for disk in disks {
        let DiskFacts {
            volume,
            pool,
            cluster,
            ..
        } = disk;
        if disk.locality == Some(controller_api::Locality::NodeLocal) {
            let node = disk.node.as_deref().unwrap_or("an unknown node");
            return Some(format!(
                "pinned by volume {volume} on node {node} in {cluster}: pool {pool} is \
                 node-local, so its bytes are on that one machine and cannot follow the vm"
            ));
        }
        if disk.serving < 2 {
            return Some(format!(
                "pinned by volume {volume} in {cluster}: storage pool {pool} serves only that \
                 cluster; set spec.clusters on the pool if the same bytes really are reachable \
                 from another one"
            ));
        }
        if let Some((a, b)) = &disk.disagreement {
            return Some(format!(
                "storage pool {pool} is served by {a} and {b}, but they do not describe the same \
                 backend; volume {volume} cannot follow the vm across them"
            ));
        }
    }
    None
}

/// Gather what [`reschedule_refusal`] decides on, and apply it.
///
/// The reads are here and the rule is next door, so that the rule can be
/// exercised without an etcd — which matters, because it is the one function
/// standing between a client and a VM whose disks are somewhere it is not.
async fn check_reschedule(st: &ApiState, current: &Vm, next: &Vm) -> Result<(), ApiError> {
    let Some(here) = releasing(current, next) else {
        return Ok(());
    };
    // Before the disks, because it is the cheaper question and the one about
    // the same evidence the phase is: a cluster that is not talking cannot be
    // asked to stop the guest first, and no amount of storage makes that
    // safe.
    check_holder_is_talking(st, current, here).await?;
    let here = here.to_string();
    let mut disks = Vec::new();
    for volume in current.spec.referenced_volumes() {
        let object: controller_api::Volume = match st.store.get(&volume).await {
            Ok(v) => v,
            // A disk that is not there any more holds nothing back. The VM
            // stays Pending with a sentence about it either way.
            Err(StoreError::NotFound(_)) => continue,
            Err(e) => return Err(e.into()),
        };
        let pool: controller_api::StoragePool = match st.store.get(&object.spec.pool).await {
            Ok(p) => p,
            Err(StoreError::NotFound(_)) => continue,
            Err(e) => return Err(e.into()),
        };
        disks.push(DiskFacts {
            volume,
            locality: pool.status.locality,
            node: object.status.node.clone(),
            cluster: object
                .status
                .cluster
                .clone()
                .unwrap_or_else(|| here.clone()),
            serving: pool.spec.served_by().len(),
            disagreement: controller_api::StoragePoolSpec::disagreeing(&pool.status)
                .map(|(a, b)| (a.to_string(), b.to_string())),
            pool: pool.metadata.name,
        });
    }
    match reschedule_refusal(current, &disks) {
        Some(why) => Err(controller_api::invalid_field("spec.clusterName", why)),
        None => Ok(()),
    }
}

/// The cluster this update is letting go of, if it is letting go of one.
pub(super) fn releasing<'a>(current: &'a Vm, next: &Vm) -> Option<&'a str> {
    match (
        current.spec.cluster_name.as_deref(),
        &next.spec.cluster_name,
    ) {
        (Some(cluster), None) => Some(cluster),
        _ => None,
    }
}

/// The evidence half of a reschedule: is the cluster that holds this VM
/// talking?
///
/// The rule is in `controller_api` so the two tiers cannot answer it
/// differently; the read is here, because the fact lives in the store. A
/// current heartbeat IS the session — it is written by the replica holding it,
/// every beat — and it is the same fact the pass reads to expire a cluster.
async fn check_holder_is_talking(
    st: &ApiState,
    current: &Vm,
    cluster: &str,
) -> Result<(), ApiError> {
    let heard = match st.store.get::<controller_api::Cluster>(cluster).await {
        Ok(c) => c.status.last_heartbeat,
        // A cluster object that is not there any more has certainly not
        // reported; the refusal is the same one and says so.
        Err(StoreError::NotFound(_)) => None,
        Err(e) => return Err(e.into()),
    };
    holder_refusal(current, cluster, heard, Utc::now())
}

/// The rule this tier applies once the heartbeat has been read, as a pure
/// function: the reads are next door, so the rule can be exercised without an
/// etcd.
///
/// 409 and not 422: nothing about the request is malformed. The state of the
/// world is what refuses it, and it is a state that ends by itself.
pub(super) fn holder_refusal(
    current: &Vm,
    cluster: &str,
    heard: Option<chrono::DateTime<Utc>>,
    now: chrono::DateTime<Utc>,
) -> Result<(), ApiError> {
    match controller_api::unknown_needs_its_holder(
        current.status.phase().kind(),
        controller_api::Holder::Cluster,
        cluster,
        heard,
        now,
    ) {
        Some(why) => Err(controller_api::conflict(why)),
        None => Ok(()),
    }
}

/// Record that a binding was let go while nobody knew what the guest was
/// doing.
///
/// Only for `Unknown`, and only after the write landed. Every other phase is
/// evidence — the cluster said so — and needs no note beside the `Unbound`
/// the reconciler already writes.
async fn note_unknown_release(st: &ApiState, current: &Vm, next: &Vm) {
    let Some(message) = release_event(current, next) else {
        return;
    };
    events::record(
        &st.store,
        events::Happening {
            kind: Vm::KIND,
            name: &current.metadata.name,
            uid: &current.metadata.uid,
            reason: events::reason::UNBOUND,
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
    let cluster = releasing(current, next)?;
    Some(controller_api::released_while_unknown(
        controller_api::Holder::Cluster,
        cluster,
    ))
}

pub(super) async fn update_vm(
    State(st): State<ApiState>,
    Path(name): Path<String>,
    caller: Caller,
    role: CallerRole,
    tenant: CallerTenant,
    dry: controller_api::DryRun,
    Json(mut body): Json<Vm>,
) -> Result<Json<Vm>, ApiError> {
    if body.metadata.name != name {
        return Err(invalid("metadata.name does not match the path"));
    }
    validate_vm_spec(&st.store, &body.spec).await?;
    // Resolved again, for the same reason it is validated again: the spec on
    // a PUT is a document the client wrote, so whatever the cloud filled in
    // last time is not in it.
    resolve_base_images(&st.store, &mut body.spec.vm).await?;

    // Server-owned fields survive the round-trip untouched — the binding
    // among them. A VM that could be re-pointed at another cluster by editing
    // a field would leave the running one behind on the old one, with the
    // teardown going to a cluster that never had it.
    let current: Vm = st.store.get(&name).await?;
    Grant::new(caller, role, tenant)
        .allows(Scope::of(current.spec.tenant.as_deref()), Verb::Write)?;
    body.metadata.uid = current.metadata.uid.clone();
    body.metadata.creation_timestamp = current.metadata.creation_timestamp;
    body.metadata.deletion_timestamp = current.metadata.deletion_timestamp;
    body.metadata.finalizers = current.metadata.finalizers.clone();
    // The binding, the tenant and the spec itself: refused rather than put
    // back. The tenant is where the VM's network comes from, and a VM that
    // changed tenants while running would be one whose NICs were built for a
    // VNI it no longer belongs to.
    check_owned(&current, &body, VM_OWNED)?;
    // After `check_owned`, which is what makes `current.spec.tenant` the
    // right tenant to ask about: a PUT that moved the VM to another tenant
    // was already refused, so the two are the same value here.
    //
    // This is the hot-plug edge. `vm_shape_unchanged` lets `spec.vm.volumes`
    // grow from the second entry on for entries that name a volume, so a PUT
    // is how a second disk arrives — and a PUT is therefore also where a
    // member could first name somebody else's.
    check_volume_refs(&st, current.spec.tenant.as_deref(), &name, &body.spec).await?;
    check_reschedule(&st, &current, &body).await?;
    body.status = current.status.clone();
    // The half that gets forgotten. A PUT that raises this VM's vcpus is the
    // same act as creating one that size, and it goes through the same
    // arithmetic: the object as it stands comes out of the sum (`except`),
    // and its new size goes back in.
    check_quota(
        &st,
        body.spec.tenant.as_deref(),
        Capacity::wanted_by_spec(&body.spec.vm),
        Some(&name),
    )
    .await?;
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

pub(super) async fn delete_vm(
    State(st): State<ApiState>,
    Path(name): Path<String>,
    caller: Caller,
    role: CallerRole,
    tenant: CallerTenant,
) -> Result<controller_api::Removed, ApiError> {
    let current: Vm = st.store.get(&name).await?;
    Grant::new(caller, role, tenant)
        .allows(Scope::of(current.spec.tenant.as_deref()), Verb::Write)?;
    st.store
        .mutate::<Vm, _>(&name, |v| {
            if v.metadata.deletion_timestamp.is_none() {
                v.metadata.deletion_timestamp = Some(Utc::now());
            }
        })
        .await?;
    // `Going` and not `Gone`: the object is marked and the tier below tears
    // the machine down, which is the same promise `vm ls` makes with
    // Terminating. It still answers a GET until the teardown is done.
    Ok(controller_api::removed(
        Vm::KIND,
        &name,
        controller_api::Removal::Going,
    ))
}

/// What the caller wants of a console: how much, and which lines.
///
/// Raw pairs and not a struct: `hide` and `only` repeat, and the form
/// encoding behind a typed `Query` cannot spell a repeated key. Nothing here
/// reads the needles — they travel to the node, which is the only party that
/// can apply them before `lines` shortens anything.
pub(super) type LogRequest = (u32, Vec<String>, Vec<String>, Vec<String>);

pub(super) fn log_request(pairs: &[(String, String)]) -> LogRequest {
    let mut lines = 0;
    let (mut hide, mut only, mut streams) = (Vec::new(), Vec::new(), Vec::new());
    for (key, value) in pairs {
        match key.as_str() {
            "lines" => lines = value.parse().unwrap_or(lines),
            "hide" if !value.is_empty() => hide.push(value.clone()),
            "only" if !value.is_empty() => only.push(value.clone()),
            "streams" if !value.is_empty() => streams.extend(
                value
                    .split(',')
                    .filter(|s| !s.is_empty())
                    .map(str::to_string),
            ),
            _ => {}
        }
    }
    (lines, hide, only, streams)
}

/// The empty console document, in the shape a node would have sent it.
pub(super) const NO_STREAMS: &[u8] = b"[]";

/// What the guest printed, fetched through the cluster from the node.
///
/// Tenant-scoped exactly as the VM is, and through the same `Grant::allows`
/// every other object route uses: a console is the most revealing thing a VM
/// has, and reading somebody else's would be worse than reading their object.
///
/// One way and only that — no attach, no input, no follow. See the cluster
/// tier's twin.
/// What `forward::holder` says this tier is talking about.
pub(super) const ABOUT: controller_api::forward::About = controller_api::forward::About {
    peer: "cluster",
    tier: "cloud",
};

/// Where the replica holding this cluster's session says it can be reached,
/// or `None`.
///
/// Off the `Cluster` object, which is where the holder wrote it at Hello. A
/// cluster that has gone away between the VM read and here is not an error:
/// it is the same "nobody holds it" the field being empty means.
pub(super) async fn session_endpoint(
    st: &ApiState,
    cluster: &str,
) -> Result<Option<String>, ApiError> {
    match st.store.get::<Cluster>(cluster).await {
        Ok(c) => Ok(c.status.session_endpoint),
        Err(StoreError::NotFound(_)) => Ok(None),
        Err(e) => Err(e.into()),
    }
}

/// The filter, back on the wire for the one hop that is HTTP.
///
/// A sibling that answered the unfiltered console would make the answer
/// depend on which replica a client happened to reach.
fn forwarded_query(hide: &[String], only: &[String], streams: &[String]) -> String {
    let mut out = String::new();
    for (key, values) in [("hide", hide), ("only", only), ("streams", streams)] {
        for value in values {
            out.push_str(&format!(
                "&{key}={}",
                controller_api::forward::urlencode(value)
            ));
        }
    }
    out
}

pub(super) async fn vm_logs(
    State(st): State<ApiState>,
    Path(name): Path<String>,
    caller: Caller,
    role: CallerRole,
    tenant: CallerTenant,
    headers: axum::http::HeaderMap,
    axum::extract::Query(q): axum::extract::Query<Vec<(String, String)>>,
) -> Result<axum::response::Response, ApiError> {
    let vm: Vm = st.store.get(&name).await?;
    let (lines, hide, only, streams) = log_request(&q);
    Grant::new(caller, role, tenant).allows(Scope::of(vm.spec.tenant.as_deref()), Verb::Read)?;

    let Some(cluster) = vm.spec.cluster_name.as_deref() else {
        // Not placed on a cluster: nothing has started, so nothing has
        // printed. An answer, not a failure.
        return Ok(json_passthrough(NO_STREAMS.to_vec()));
    };
    // Which replica can answer. A cluster dials ONE cloud replica, so two of
    // every three requests land somewhere that cannot ask it anything — the
    // same fact one tier down, and now the same answer: forward once to the
    // replica that published `Cluster.status.sessionEndpoint`, with this
    // cloud's own `system:cloud:<name>` identity. Until this position that
    // identity did not exist and this route simply refused; see the image
    // report.
    match controller_api::forward::holder(
        ABOUT,
        st.sessions.holds(cluster),
        session_endpoint(&st, cluster).await?.as_deref(),
        headers.contains_key(controller_api::forward::FORWARDED),
    ) {
        controller_api::forward::Holder::Here => {}
        controller_api::forward::Holder::Sibling(endpoint) => {
            info!(vm = %name, cluster, %endpoint,
                  "forwarding a log read to the replica that holds the cluster session");
            let path = format!(
                "/apis/meister.io/v1/vms/{name}/logs?lines={lines}{}",
                forwarded_query(&hide, &only, &streams)
            );
            return match controller_api::forward::ask(&st.sibling, &endpoint, &path).await {
                Ok(payload) => Ok(json_passthrough(payload.to_vec())),
                Err(e) => Err(ApiError::new(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Unavailable",
                    format!("{e:#}"),
                )),
            };
        }
        controller_api::forward::Holder::Nowhere(why) => {
            return Err(ApiError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "Unavailable",
                why,
            ));
        }
    }

    let op = cloud_command::Op::Logs(proto::FetchVmLogs {
        name: name.clone(),
        // The uid, for the reason CreateVm and DestroyVm carry one: a name is
        // a label people reuse, and a cluster-local VM sharing it is not this
        // VM.
        uid: vm.metadata.uid.clone(),
        lines,
        hide,
        only,
        streams,
    });
    match st.sessions.send_command(cluster, "", op).await {
        Ok(controller_api::Ack::Acked(payload)) => Ok(json_passthrough(payload)),
        // The cluster's own refusal, in its own words AND with its own word
        // for what kind of refusal it is. See `refused`.
        Ok(controller_api::Ack::Rejected(refusal)) => Err(refused(refusal)),
        // Reaching the cluster failed. The store answered and the object is
        // there; the party that holds the console is out of reach right now,
        // and a caller that retries is right.
        Err(e) => Err(ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "Unavailable",
            format!("{e:#}"),
        )),
    }
}

/// Take this VM's serial line, through both tiers, and speak to it.
///
/// Mint a ticket for this VM's console.
///
/// It exists because a browser opening a `WebSocket` cannot set an
/// `Authorization` header — the API is `new WebSocket(url)` and that is all
/// of it. So a page holding a perfectly good token has no way to present it,
/// and the only thing left that reaches the server is the query string.
///
/// What comes back is not a new permission. It is the permission this caller
/// already has, frozen: `Verb::Write` on this VM, checked here with the
/// caller's own credential, valid for thirty seconds, for this one path,
/// once. A ticket can never open a door its holder could not have walked
/// through themselves.
pub(super) async fn vm_console_ticket(
    State(st): State<ApiState>,
    Path(name): Path<String>,
    identity: Option<axum::Extension<controller_api::Identity>>,
    caller: Caller,
    role: CallerRole,
    tenant: CallerTenant,
) -> Result<Json<serde_json::Value>, ApiError> {
    let vm: Vm = st.store.get(&name).await?;
    // The same door the console itself is behind, asked with the caller's own
    // credential — Write, because the route it opens can type into the guest.
    Grant::new(caller, role, tenant.clone())
        .allows(Scope::of(vm.spec.tenant.as_deref()), Verb::Write)?;
    // Anonymous mode has no identity to freeze, and a ticket that carried
    // nobody would be a ticket that means nothing. There is also nothing to
    // gain: a server with no chain lets the plain WebSocket through.
    let Some(axum::Extension(identity)) = identity else {
        return Err(invalid(
            "this endpoint authenticates nobody, so a console needs no ticket; open it directly",
        ));
    };
    let path = format!("/apis/meister.io/v1/vms/{name}/console");
    // Into the tier's own etcd, so that the replica the browser's WebSocket
    // lands on can spend it — see `controller_api::tickets`.
    let token = st
        .tickets
        .mint(
            controller_api::tickets::Bearer {
                identity,
                role: role.0,
                tenant: tenant.0,
            },
            &path,
        )
        .await?;
    let expires = chrono::Utc::now()
        + chrono::Duration::from_std(controller_api::tickets::TICKET_TTL)
            .expect("thirty seconds fits");
    info!(vm = %name, "console ticket minted");
    Ok(Json(json!({
        "apiVersion": API_VERSION,
        "kind": "ConsoleTicket",
        "ticket": token,
        // The path to open, so a client does not build it out of string
        // pieces and get the tier's own prefix wrong.
        "path": format!("{path}?ticket={token}"),
        "expiresAt": expires,
    })))
}

/// The same raw upgrade the agent serves, relayed — and, for a browser, the
/// same bytes in WebSocket frames.
///
/// One route and two framings, told apart by the request's own `Upgrade`
/// header. Before this the token was never looked at: a WebSocket handshake
/// got a 101 carrying `Upgrade: meister-console` and no `Sec-WebSocket-Accept`,
/// and the browser — correctly — threw the connection away. So the console
/// worked through both tiers to the node and was reachable from nothing that
/// has a screen.
///
/// The framing is an ADAPTER and stops at this function: `websocket::adapt`
/// hands back an ordinary duplex stream, so the pump below and the socket
/// splice that forwards to a sibling replica both go on speaking raw bytes
/// and neither knows which kind of client it has.
///
/// Tenant-scoped exactly as `vm logs` is, and through the same `Grant`: a
/// console is the most revealing thing a VM has, and typing into somebody
/// else's is worse than reading it.
///
/// **Which replica.** A console is a live stream through the session this
/// process holds, so only the replica holding the cluster's session can serve
/// one. The others answer 503 and say so rather than pretending — the same
/// honest gap `vm logs` has one tier down, and the same reason: forwarding a
/// stream is a proxy, not a redirect, and that is its own piece of work.
pub(super) async fn vm_console(
    State(st): State<ApiState>,
    Path(name): Path<String>,
    caller: Caller,
    role: CallerRole,
    tenant: CallerTenant,
    req: axum::extract::Request,
) -> Result<axum::response::Response, ApiError> {
    let vm: Vm = st.store.get(&name).await?;
    // Write and not Read: this route can type into the guest.
    Grant::new(caller, role, tenant).allows(Scope::of(vm.spec.tenant.as_deref()), Verb::Write)?;

    let Some(cluster) = vm.spec.cluster_name.clone() else {
        return Err(invalid(format!(
            "vm {name} is not placed on a cluster yet, so there is no console to hold"
        )));
    };

    let (mut parts, body) = req.into_parts();
    drop(body);
    let Some(on_upgrade) = parts.extensions.remove::<hyper::upgrade::OnUpgrade>() else {
        return Err(invalid(
            "a console is an upgraded connection; send Connection: upgrade",
        ));
    };
    // Which framing this client speaks. `None` is the raw console the CLI
    // asks for, which is what this route has always answered.
    let websocket = controller_api::websocket::handshake(&parts.headers);

    let session_id = uuid::Uuid::new_v4().to_string();
    let mut events = st.sessions.consoles.expect(&session_id);
    // To the cluster's speaker, exactly like a command. WHICH replica of that
    // cluster holds this VM's node is not the cloud's to know — it is a fact
    // about a gRPC stream, and the tier that owns those streams forwards
    // among itself. See the cluster's console_open.
    let reached = usize::from(
        st.sessions
            .send_to(
                &cluster,
                proto::CloudMessage {
                    kind: Some(proto::cloud_message::Kind::ConsoleOpen(
                        proto::ConsoleOpen {
                            session_id: session_id.clone(),
                            // The NAME here and the uid one tier down: this cluster
                            // keeps its own object, and the tier below resolves it.
                            vm_id: name.clone(),
                        },
                    )),
                },
            )
            .await,
    );
    if reached == 0 {
        st.sessions.consoles.forget(&session_id);
        // This replica has no session to that cluster — the cluster dialled
        // one of our siblings. Forward there rather than refusing: the same
        // hop the tier below makes for a node, and the address comes from the
        // same kind of field, written by whichever replica took the session.
        let endpoint = st
            .store
            .get::<Cluster>(&cluster)
            .await
            .ok()
            .and_then(|c| c.status.session_endpoint)
            .filter(|e| !e.is_empty());
        // Never to ourselves, and never twice. `session_endpoint` is written
        // at Hello and not cleared, so it can still name THIS replica after
        // its own session has gone stale — and forwarding there would be a
        // process connecting to itself, once per hop, for ever. The header is
        // the second guard: every replica reads the same field, so a second
        // hop could only ever be a mistake.
        let forwarded = parts.headers.contains_key(CONSOLE_FORWARDED);
        let mine = st.advertise.as_deref();
        let endpoint = endpoint.filter(|e| Some(e.as_str()) != mine && !forwarded);
        let Some(endpoint) = endpoint else {
            return Err(ApiError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "Unavailable",
                format!(
                    "no replica of this cloud is holding cluster {cluster}'s session right \
                     now, or the one that is could not name its own address (set \
                     advertise_api in its config)"
                ),
            ));
        };
        return forward_console(&st.sibling, &endpoint, &name, on_upgrade, websocket).await;
    }

    // Waited for BEFORE the upgrade is answered, because a refusal needs a
    // status code to travel on and there is none left after 101.
    //
    // One yes wins; it takes `reached` noes to lose. The replicas that do not
    // hold this VM's node all refuse, and their refusals are the normal case
    // rather than the answer — the last one is what a client is told, because
    // by then nobody had the line.
    await_console_open(&mut events, reached, &session_id, &st.sessions).await?;

    info!(vm = %name, cluster = %cluster, session = %session_id,
          websocket = websocket.is_some(), "console opened");
    let sessions = st.sessions.clone();
    let framed = websocket.is_some();
    tokio::spawn(async move {
        match on_upgrade.await {
            Ok(upgraded) => {
                let client = hyper_util::rt::TokioIo::new(upgraded);
                // One line, and it is where the two framings become one: a
                // framed client is adapted into a raw one and the pump below
                // never learns the difference.
                match framed {
                    true => {
                        console_pump(
                            controller_api::websocket::adapt(client),
                            events,
                            &sessions,
                            &cluster,
                            &session_id,
                        )
                        .await;
                    }
                    false => {
                        console_pump(client, events, &sessions, &cluster, &session_id).await;
                    }
                }
            }
            Err(e) => warn!(error = format!("{e:#}"), "console upgrade failed"),
        }
        sessions.consoles.forget(&session_id);
        // Whatever ended it, the tier below is told: a line held for a client
        // that has gone is a line nobody else can have.
        let _ = sessions
            .send_to(
                &cluster,
                proto::CloudMessage {
                    kind: Some(proto::cloud_message::Kind::ConsoleClose(
                        proto::ConsoleClose {
                            session_id: session_id.clone(),
                            reason: "the client's console ended".to_string(),
                        },
                    )),
                },
            )
            .await;
        info!(session = %session_id, "console closed");
    });

    Ok(switching(websocket))
}

/// The 101, in whichever protocol the client asked for.
///
/// `Sec-WebSocket-Accept` is the whole of the handshake's proof, and its
/// absence was the defect: a 101 that names another protocol is a 101 a
/// browser is right to hang up on.
pub(super) fn switching(websocket: Option<String>) -> axum::response::Response {
    let response = axum::response::Response::builder()
        .status(StatusCode::SWITCHING_PROTOCOLS)
        .header(axum::http::header::CONNECTION, "upgrade");
    match websocket {
        Some(accept) => response
            .header(axum::http::header::UPGRADE, "websocket")
            .header("sec-websocket-accept", accept),
        None => response.header(axum::http::header::UPGRADE, CONSOLE_PROTOCOL),
    }
    .body(axum::body::Body::empty())
    .expect("a fixed response")
}

/// Hand a whole console to the sibling replica that holds the cluster.
///
/// A pure socket proxy, and simpler than the tier below's forward for one
/// reason: nothing here has to be translated. The sibling answers the very
/// route this one serves, so what travels between the two connections is the
/// same byte stream in both directions — no session frames, no ids.
///
/// One hop, and it needs no header to say so: a forward asks a SIBLING, and a
/// sibling that has no session either refuses rather than forwarding again —
/// they all read the same `session_endpoint`, so a second hop could only be a
/// mistake that bounces a live stream between two processes.
/// A forwarded console, whichever way this cloud is spoken to.
///
/// A boxed trait object rather than a generic, and the reason is what happens
/// at the end of this function: the stream is spliced to the client's with
/// `copy_bidirectional` inside a spawned task, so it has to be one type by
/// then. Two monomorphisations of the whole splice for one boolean would be
/// two copies of the hardest code in this file.
trait Console: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send {}
impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send> Console for T {}

pub(super) async fn forward_console(
    sibling_tls: &controller_api::forward::Sibling,
    endpoint: &str,
    vm_name: &str,
    on_upgrade: hyper::upgrade::OnUpgrade,
    websocket: Option<String>,
) -> Result<axum::response::Response, ApiError> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    // The same rule the log forward follows, and now the same function: an
    // endpoint that names a scheme decides for itself, and one that does not
    // is read as whatever this replica serves.
    let (authority, tls) = controller_api::forward::dial(endpoint, sibling_tls.serves_tls);
    let authority = authority.to_string();
    let unreachable = |why: String| {
        ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "Unavailable",
            format!("the replica at {authority}: {why}"),
        )
    };

    let stream = match tokio::time::timeout(
        CONSOLE_FORWARD_TIMEOUT,
        tokio::net::TcpStream::connect(&authority),
    )
    .await
    {
        Ok(Ok(stream)) => stream,
        Ok(Err(e)) => return Err(unreachable(e.to_string())),
        Err(_) => {
            return Err(unreachable(format!(
                "did not answer within {}s",
                CONSOLE_FORWARD_TIMEOUT.as_secs()
            )));
        }
    };
    let _ = stream.set_nodelay(true);

    // The half the image report left open: which identity a cloud replica
    // shows its sibling. It shows `system:cloud:<name>`, the same certificate
    // the log forward uses, and until it existed this hop could only ever go
    // in plain text — against a sibling that stopped answering plain text
    // when auth went on.
    let mut sibling: Box<dyn Console> = if tls {
        let config = sibling_tls
            .tls
            .clone()
            .ok_or_else(|| unreachable("is https and this replica has no identity_cert".into()))?;
        let host = authority
            .rsplit_once(':')
            .map_or(&authority[..], |(h, _)| h);
        let name = tokio_rustls::rustls::pki_types::ServerName::try_from(host.to_string())
            .map_err(|_| unreachable(format!("{host} is not a usable server name")))?;
        match tokio_rustls::TlsConnector::from(config)
            .connect(name, stream)
            .await
        {
            Ok(tls) => Box::new(tls),
            Err(e) => return Err(unreachable(format!("tls handshake failed: {e}"))),
        }
    } else {
        Box::new(stream)
    };

    let request = format!(
        "GET /apis/meister.io/v1/vms/{vm_name}/console HTTP/1.1\r\nHost: {authority}\r\n\
         Connection: upgrade\r\nUpgrade: {CONSOLE_PROTOCOL}\r\n\
         {CONSOLE_FORWARDED}: 1\r\n\r\n"
    );
    if let Err(e) = sibling.write_all(request.as_bytes()).await {
        return Err(unreachable(e.to_string()));
    }
    // The head, byte at a time, so the socket survives to carry the console.
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        match sibling.read(&mut byte).await {
            Ok(0) => return Err(unreachable("closed without answering".to_string())),
            Err(e) => return Err(unreachable(e.to_string())),
            Ok(_) => head.push(byte[0]),
        }
        if head.len() > 16 * 1024 {
            return Err(unreachable("sent an oversized response head".to_string()));
        }
    }
    let text = String::from_utf8_lossy(&head);
    let status = text
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .unwrap_or("?")
        .to_string();
    if status != "101" {
        // The sibling's own SENTENCE, not just its number. It is the replica
        // that actually knows why — "somebody else is holding this console"
        // is an answer a person can act on, and "a replica answered 409" is
        // not. Read by the content-length the head promised, which is the
        // only length there is on a connection that was about to become a
        // console.
        let said = read_refusal(&mut sibling, &text).await;
        return Err(conflict(said.unwrap_or_else(|| {
            format!("the replica at {authority} answered {status} to a console open")
        })));
    }

    let framed = websocket.is_some();
    tokio::spawn(async move {
        if let Ok(upgraded) = on_upgrade.await {
            let client = hyper_util::rt::TokioIo::new(upgraded);
            // The hop to the sibling is ALWAYS raw — a replica asking its
            // sibling is the cloud asking itself, and it should not have to
            // learn what a browser is. So the frames come off here, and from
            // there on nothing is translated in either direction.
            let mut client: Box<dyn Console> = match framed {
                true => Box::new(controller_api::websocket::adapt(client)),
                false => Box::new(client),
            };
            let _ = tokio::io::copy_bidirectional(&mut client, &mut sibling).await;
        }
    });

    Ok(switching(websocket))
}

/// The sentence behind a sibling's refusal, out of the `Status` body it sent.
///
/// `None` when there is nothing to read or nothing to understand — the caller
/// then falls back to naming the status, which is worse but still true.
pub(super) async fn read_refusal<S>(stream: &mut S, head: &str) -> Option<String>
where
    S: tokio::io::AsyncRead + Unpin,
{
    use tokio::io::AsyncReadExt;
    let length: usize = head.lines().find_map(|line| {
        let (name, value) = line.split_once(':')?;
        name.eq_ignore_ascii_case("content-length")
            .then(|| value.trim().parse().ok())?
    })?;
    let mut body = vec![0u8; length.min(64 * 1024)];
    stream.read_exact(&mut body).await.ok()?;
    #[derive(serde::Deserialize)]
    struct Status {
        message: String,
    }
    serde_json::from_slice::<Status>(&body)
        .ok()
        .map(|s| s.message)
        .filter(|m| !m.is_empty())
}

/// The header a forwarded console carries, and the whole of the loop
/// prevention beside the self-check. One hop is the design.
pub const CONSOLE_FORWARDED: &str = "x-meister-console-forwarded";

/// How long a console forward waits on a sibling — the budget `vm logs` uses.
pub(super) const CONSOLE_FORWARD_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// Wait until one replica opens the line, or until all of them have refused.
pub(super) async fn await_console_open(
    events: &mut tokio::sync::mpsc::Receiver<crate::session::ConsoleEvent>,
    reached: usize,
    session_id: &str,
    sessions: &crate::session::SessionRegistry,
) -> Result<(), ApiError> {
    let mut refusals = 0usize;
    let mut last = String::from("no replica of this cluster answered");
    let deadline = tokio::time::Instant::now() + CONSOLE_OPEN_TIMEOUT;
    loop {
        // Every arm but this one is an answer that ends the wait; what falls
        // through is one replica saying no, and the wait goes on until they
        // all have.
        let why = match tokio::time::timeout_at(deadline, events.recv()).await {
            Ok(Some(crate::session::ConsoleEvent::Opened(Ok(())))) => return Ok(()),
            Ok(Some(crate::session::ConsoleEvent::Opened(Err(why))))
            | Ok(Some(crate::session::ConsoleEvent::Closed(why))) => why,
            // Output before the open was answered is a peer out of order;
            // ignored rather than treated as an answer.
            Ok(Some(crate::session::ConsoleEvent::Data(_))) => continue,
            Ok(None) => {
                return Err(gone(
                    sessions,
                    session_id,
                    ApiError::new(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "Unavailable",
                        "the console session ended before it began",
                    ),
                ));
            }
            Err(_) => {
                return Err(gone(
                    sessions,
                    session_id,
                    ApiError::new(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "Unavailable",
                        format!(
                            "no replica answered about this console within {}s; the last said: {last}",
                            CONSOLE_OPEN_TIMEOUT.as_secs()
                        ),
                    ),
                ));
            }
        };
        refusals += 1;
        last = why;
        // Every replica that was reached has now said no, so there is nobody
        // left to hear a yes from.
        if refusals >= reached {
            return Err(gone(sessions, session_id, conflict(last)));
        }
    }
}

/// Give up on this console: forget the route, and answer with the reason.
///
/// Every way out of the wait but the good one comes through here, and each of
/// them has to forget the session — a route nobody will ever open is a route
/// the next ticket must not find.
fn gone(sessions: &crate::session::SessionRegistry, session_id: &str, error: ApiError) -> ApiError {
    sessions.consoles.forget(session_id);
    error
}

/// What this upgrade is called on the wire, at every tier that serves one.
pub const CONSOLE_PROTOCOL: &str = "meister-console";

/// How long to wait for the tiers below to say whether the line was given.
///
/// Two hops and a node, so generous — but bounded, because the alternative is
/// a client hanging on a `curl` for ever when a node has stopped answering.
pub(super) const CONSOLE_OPEN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Both directions of one console session, until either end stops.
pub(super) async fn console_pump<S>(
    stream: S,
    mut events: tokio::sync::mpsc::Receiver<crate::session::ConsoleEvent>,
    sessions: &crate::session::SessionRegistry,
    cluster: &str,
    session_id: &str,
) where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let (mut from_client, mut to_client) = tokio::io::split(stream);
    // The same bound the node applies to one write, so that a client cannot
    // send a frame the tier below will refuse.
    let mut buf = vec![0u8; 4096];
    loop {
        tokio::select! {
            event = events.recv() => match event {
                Some(crate::session::ConsoleEvent::Data(bytes)) => {
                    if to_client.write_all(&bytes).await.is_err() {
                        break;
                    }
                }
                Some(crate::session::ConsoleEvent::Closed(_)) | None => break,
                // An `Opened` after the open was answered is a peer repeating
                // itself; nothing to do and nothing to complain about.
                Some(crate::session::ConsoleEvent::Opened(_)) => {}
            },
            read = from_client.read(&mut buf) => match read {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    let sent = sessions
                        .send_to(
                            cluster,
                            proto::CloudMessage {
                                kind: Some(proto::cloud_message::Kind::ConsoleInput(
                                    proto::ConsoleData {
                                        session_id: session_id.to_string(),
                                        data: buf[..n].to_vec(),
                                    },
                                )),
                            },
                        )
                        .await;
                    if !sent {
                        break;
                    }
                }
            },
        }
    }
}

/// What a cluster's "no" becomes at this edge.
///
/// A refusal that crossed the session used to be a 409 whatever it said, and
/// the comment here called that "an answer about this VM, with nothing to
/// retry against it". That was true for the refusals anybody had in mind —
/// no such node, a lost compare-and-swap — and false for the one that turned
/// out to matter most: with three cloud replicas and three cluster replicas,
/// "no replica of this cluster is holding this node's session" is what two
/// out of three console reads got, and it is not a disagreement. It is a
/// party being out of reach, which is `Unavailable`, and a caller that
/// retries is right.
///
/// The word comes from the cluster now (see `Refusal`). Empty means a peer
/// that names no reason — every agent today, and every cluster before this —
/// and empty keeps the old meaning exactly.
pub(super) fn refused(refusal: controller_api::Refusal) -> ApiError {
    match refusal.reason.as_str() {
        "" | "Conflict" => conflict(refusal.message),
        reason => ApiError::new(
            match reason {
                "Unavailable" | "Timeout" => StatusCode::SERVICE_UNAVAILABLE,
                "NotFound" => StatusCode::NOT_FOUND,
                "Invalid" => StatusCode::UNPROCESSABLE_ENTITY,
                "Forbidden" => StatusCode::FORBIDDEN,
                // A word this tier does not know is still a refusal, and
                // guessing a status for it would be worse than the one the
                // path already had.
                _ => StatusCode::CONFLICT,
            },
            // Leaked deliberately: the reason a client switches on is the
            // one the tier that MET the failure chose, not one invented here.
            match reason {
                "Unavailable" => "Unavailable",
                "Timeout" => "Timeout",
                "NotFound" => "NotFound",
                "Invalid" => "Invalid",
                "Forbidden" => "Forbidden",
                _ => "Conflict",
            },
            refusal.message,
        ),
    }
}

/// The node's JSON, handed on as the bytes it is — see the cluster tier's
/// twin. Two tiers of deserialise-and-reserialise would be two chances to
/// change what a console said, for no gain.
pub(super) fn json_passthrough(payload: Vec<u8>) -> axum::response::Response {
    use axum::response::IntoResponse;
    (
        [(axum::http::header::CONTENT_TYPE, "application/json")],
        payload,
    )
        .into_response()
}

#[cfg(test)]
mod tests {

    /// `spec.nodeName` is not a field of a vm at THIS tier, and the two ways
    /// of saying so have to agree.
    ///
    /// One `Vm` type serves both tiers on purpose, and what that left behind
    /// up here was a field with no meaning: this tier places on clusters and
    /// never writes it. `/schemas` published it anyway, a client read it,
    /// believed it, set it and was ignored (fremdsicht 2). The shape does not
    /// name it any more, and a body that names it is refused rather than
    /// quietly dropped — otherwise the silence would be back, one layer down.
    #[test]
    fn the_cloud_publishes_no_node_name_and_refuses_one() {
        let schema = cloud_vm_schema();
        assert!(
            !controller_api::schema_has_field(&schema, "spec.nodeName"),
            "this tier still publishes a field it never writes"
        );
        // The neighbours are untouched: this takes ONE field out, it does not
        // replace the shape with a smaller one.
        for kept in ["spec.clusterName", "spec.tenant", "spec.runStrategy"] {
            assert!(
                controller_api::schema_has_field(&schema, kept),
                "{kept} went missing with it"
            );
        }

        let mut spec: VmSpec = serde_json::from_value(serde_json::json!({
            "vm": {},
            "nodeName": "agent-1",
        }))
        .expect("the type still has the field; one Vm serves both tiers");
        let refusal = check_no_node_name(&spec).expect_err("a body that names it is refused");
        assert_eq!(refusal.field(), Some("spec.nodeName"));
        assert_eq!(
            refusal.status(),
            axum::http::StatusCode::UNPROCESSABLE_ENTITY
        );

        spec.node_name = None;
        assert!(check_no_node_name(&spec).is_ok(), "and nothing else is");
    }
    use super::*;

    /// The 101 a browser is willing to keep. Before this, a WebSocket
    /// handshake got the raw console's answer — `Upgrade: meister-console`
    /// and no accept header — and the browser hung up, correctly. The route
    /// worked through both tiers to the node and was reachable from nothing
    /// with a screen.
    #[test]
    fn the_upgrade_answer_names_the_protocol_that_was_asked_for() {
        let raw = switching(None);
        assert_eq!(raw.status(), StatusCode::SWITCHING_PROTOCOLS);
        assert_eq!(raw.headers()["upgrade"], CONSOLE_PROTOCOL);
        assert!(
            !raw.headers().contains_key("sec-websocket-accept"),
            "the CLI's console is not a websocket"
        );

        let framed = switching(Some("s3pPLMBiTxaQ9kYGzzhZRbK+xOo=".into()));
        assert_eq!(framed.headers()["upgrade"], "websocket");
        assert_eq!(
            framed.headers()["sec-websocket-accept"],
            "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=",
            "the whole of the handshake's proof"
        );
        assert_eq!(framed.headers()["connection"], "upgrade");
    }

    /// The row itself, and only the shape it opens: clearing, yes; pointing
    /// at a different cluster, no. What the shape does not say is WHEN, and
    /// that is deliberate — `reschedule_refusal` asks the phase and the
    /// disks, because neither is a property of this field.
    #[test]
    fn a_client_may_only_clear_the_cluster_binding_never_move_it() {
        let bound = |c: serde_json::Value| json!({"spec": {"clusterName": c}});
        let one = bound(json!("cluster-1"));

        controller_api::check_owned(&one, &one, VM_OWNED).expect("a round trip");
        controller_api::check_owned(&one, &bound(serde_json::Value::Null), VM_OWNED)
            .expect("letting the binding go is the reschedule");

        let moved = controller_api::check_owned(&one, &bound(json!("cluster-2")), VM_OWNED)
            .expect_err("a client does not choose the cluster");
        assert!(
            moved.message().contains("a client may only clear it"),
            "{}",
            moved.message()
        );

        // The published row: structural, so a form does not grey out the one
        // edit a client may make; and the note says what clearing means.
        let row = VM_OWNED
            .iter()
            .find(|o| o.path == "spec.clusterName")
            .expect("the row");
        assert_eq!(row.kind, controller_api::Mutability::Structural);
        assert!(
            row.note.is_some_and(|n| n.contains("node-local")),
            "the note names the disk that stops it: {:?}",
            row.note
        );
    }

    fn stopped_vm() -> Vm {
        let mut vm = controller_api::resources::new_vm(
            "web-1",
            controller_api::VmSpec {
                class: Default::default(),
                cluster_selector: Default::default(),
                node_selector: Default::default(),
                anti_affinity: Vec::new(),
                node_name: None,
                cluster_name: Some("cluster-1".into()),
                run_strategy: controller_api::RunStrategy::Stopped,
                evacuation: Default::default(),
                tenant: None,
                vm: json!({ "vcpus": 1 }),
            },
        );
        #[allow(deprecated)]
        vm.status.assign(controller_api::VmPhase::of(
            controller_api::VmPhaseKind::Stopped,
            chrono::Utc::now(),
        ));
        vm
    }

    fn disk(locality: Option<controller_api::Locality>, serving: usize) -> DiskFacts {
        DiskFacts {
            volume: "data-1".into(),
            pool: "shared-1".into(),
            locality,
            node: Some("agent-1".into()),
            cluster: "cluster-1".into(),
            serving,
            disagreement: None,
        }
    }

    /// Silas' rule at this tier: an `Unknown` binding is let go only while
    /// the cluster holding it is reporting, and 409 says so when it is not.
    ///
    /// The same rule the tier below applies about a node, asked here about a
    /// cluster and answered out of `controller_api` so the two cannot drift.
    #[test]
    fn an_unknown_binding_is_only_let_go_while_its_cluster_reports() {
        let at = |secs: i64| chrono::DateTime::from_timestamp(1_800_000_000 + secs, 0).unwrap();
        let now = at(1_000);
        let mut vm = stopped_vm();
        #[allow(deprecated)]
        vm.status.assign(controller_api::VmPhase::of(
            controller_api::VmPhaseKind::Unknown,
            now,
        ));

        // Silent: 409, because nothing about the request is malformed — the
        // state of the world refuses it, and that state ends by itself.
        let refused =
            holder_refusal(&vm, "cluster-1", Some(at(0)), now).expect_err("a silent cluster");
        assert_eq!(refused.status(), axum::http::StatusCode::CONFLICT);
        assert!(
            refused.message().contains("cluster cluster-1"),
            "{}",
            refused.message()
        );
        assert!(
            refused.message().contains("drain the cluster"),
            "{}",
            refused.message()
        );

        // Reporting: it goes through, and then the disks get their say.
        holder_refusal(&vm, "cluster-1", Some(at(1_000)), now).expect("a cluster that is talking");

        // `Failed` is the cluster's own word that the guest is not running.
        let mut failed = vm.clone();
        #[allow(deprecated)]
        failed.status.assign(controller_api::VmPhase::of(
            controller_api::VmPhaseKind::Failed,
            now,
        ));
        holder_refusal(&failed, "cluster-1", None, now).expect("Failed is evidence");

        // And what the object is left carrying when the release does land.
        let unbound = |from: &Vm| {
            let mut v = from.clone();
            v.spec.cluster_name = None;
            v
        };
        let said = release_event(&vm, &unbound(&vm)).expect("an Unknown release is noted");
        assert!(said.contains("while the phase was Unknown"), "{said}");
        assert!(said.contains("cluster-1"), "{said}");
        assert_eq!(release_event(&vm, &vm), None);
        assert_eq!(release_event(&failed, &unbound(&failed)), None);
    }

    /// The two conditions and not one. An operator who asked for a stop a
    /// second ago has satisfied the intent and not the observation, and the
    /// sentence names the PHASE because that is the half they can act on.
    #[test]
    fn a_vm_that_is_still_running_does_not_change_cluster() {
        let stopped = stopped_vm();
        assert_eq!(reschedule_refusal(&stopped, &[]), None, "nothing holds it");

        for (strategy, phase) in [
            (
                controller_api::RunStrategy::Running,
                controller_api::VmPhaseKind::Running,
            ),
            // Told to stop, not stopped yet: the one the second condition is
            // for.
            (
                controller_api::RunStrategy::Stopped,
                controller_api::VmPhaseKind::Running,
            ),
            (
                controller_api::RunStrategy::Stopped,
                controller_api::VmPhaseKind::Provisioning,
            ),
            (
                controller_api::RunStrategy::Paused,
                controller_api::VmPhaseKind::Paused,
            ),
        ] {
            let mut vm = stopped_vm();
            vm.spec.run_strategy = strategy;
            #[allow(deprecated)]
            vm.status
                .assign(controller_api::VmPhase::of(phase, chrono::Utc::now()));
            let why = reschedule_refusal(&vm, &[]).expect("a moving vm does not move");
            assert!(why.contains(phase.as_str()), "and names the phase: {why}");
        }
    }

    /// D12 at this tier: the phases a VM on an unresponsive node is actually
    /// in are the ones this call used to refuse.
    ///
    /// `mc-r1` in the mini-chaos run sat at `runStrategy Stopped, phase
    /// Failed` on a machine that executed nothing, and the one API call that
    /// would have moved it answered "stop it first" — advice to do what had
    /// already been done, and the only exit was through Silas' hands.
    #[test]
    fn a_failed_or_unknown_vm_may_let_its_cluster_binding_go() {
        for phase in [
            controller_api::VmPhaseKind::Failed,
            controller_api::VmPhaseKind::Unknown,
        ] {
            let mut vm = stopped_vm();
            #[allow(deprecated)]
            vm.status
                .assign(controller_api::VmPhase::of(phase, chrono::Utc::now()));
            assert_eq!(
                reschedule_refusal(&vm, &[]),
                None,
                "{phase:?} is stopped enough"
            );
            // And the disk rules still apply to it: being unreachable is not
            // a reason for bytes to follow a VM across clusters.
            let why =
                reschedule_refusal(&vm, &[disk(Some(controller_api::Locality::NodeLocal), 2)])
                    .expect("node-local still does not travel");
            assert!(why.contains("pinned by volume data-1"), "{why}");
        }
    }

    /// The hard wall, and the sentence the brief asks for by name: a
    /// node-local disk is bytes on one machine of one cluster, and it says
    /// which machine and which cluster.
    #[test]
    fn a_node_local_disk_pins_a_vm_to_its_cluster() {
        let vm = stopped_vm();
        let why = reschedule_refusal(&vm, &[disk(Some(controller_api::Locality::NodeLocal), 2)])
            .expect("node-local does not travel");
        assert!(why.contains("pinned by volume data-1"), "{why}");
        assert!(why.contains("on node agent-1"), "and where: {why}");
        assert!(why.contains("in cluster-1"), "and whose: {why}");
        assert!(why.contains("node-local"), "and why: {why}");
    }

    /// `shared` and `networked` travel — but only as far as somebody wrote
    /// down. A pool naming one cluster is not a claim that its bytes are
    /// reachable from a second, and this tier does not invent one.
    #[test]
    fn a_pool_that_names_one_cluster_pins_the_same_way() {
        let vm = stopped_vm();
        let why = reschedule_refusal(&vm, &[disk(Some(controller_api::Locality::Shared), 1)])
            .expect("one cluster is one cluster");
        assert!(why.contains("serves only that cluster"), "{why}");
        assert!(why.contains("spec.clusters"), "and the way out: {why}");

        // Two, and the same disk moves.
        assert_eq!(
            reschedule_refusal(&vm, &[disk(Some(controller_api::Locality::Shared), 2)]),
            None
        );
        // As does an import provider's, which is the other locality that can
        // be reached from two places at once.
        assert_eq!(
            reschedule_refusal(&vm, &[disk(Some(controller_api::Locality::Networked), 2)]),
            None
        );
        // And a pool nobody has reported on yet constrains nothing — silence
        // is not `node-local`.
        assert_eq!(reschedule_refusal(&vm, &[disk(None, 2)]), None);
    }

    /// A pool may CLAIM two clusters; whether the two describe the same
    /// export is the clusters' own answer, and when they differ the claim
    /// loses.
    #[test]
    fn two_clusters_that_describe_a_pool_differently_do_not_share_it() {
        let vm = stopped_vm();
        let mut d = disk(Some(controller_api::Locality::Shared), 2);
        d.disagreement = Some(("cluster-1".into(), "cluster-2".into()));
        let why = reschedule_refusal(&vm, &[d]).expect("two exports are not one export");
        assert!(why.contains("do not describe the same backend"), "{why}");
        assert!(why.contains("cluster-1"), "and which two: {why}");
        assert!(why.contains("cluster-2"), "and which two: {why}");
    }

    /// Where a base image comes from is the catalogue's answer — and a
    /// reference to a `Volume` object is NOT one of the fields this door
    /// guards, which is the half that changed.
    ///
    /// The refusal that used to stand here said "attaching one to a vm is not
    /// built yet". It is built, on both tiers, and the sentence had outlived
    /// its truth: the promise its own comment made — that the door becomes
    /// the TENANCY check rather than disappearing — is kept by
    /// `check_volume_refs`, which needs a store and a tenant and therefore
    /// cannot live in this function. So the assertion here is the negative
    /// one: naming a volume gets past this door.
    #[test]
    fn a_client_may_not_name_the_volume_fields_the_cloud_owns() {
        let catalogue = || {
            std::collections::BTreeMap::from([(
                "noble".to_string(),
                ("https://images/noble.img".to_string(), "abc123".to_string()),
            )])
        };
        for field in ["base_image_url", "base_image_sha256"] {
            let spec = json!({ "volumes": [{}, { "base_image": "noble", field: "x" }] });
            let msg = format!(
                "{:?}",
                check_owned_volume_fields(&spec, &catalogue()).unwrap_err()
            );
            assert!(msg.contains(field), "{msg}");
            assert!(msg.contains("volumes[1]"), "and which volume: {msg}");
        }
        // And naming one for an image the catalogue says nothing about is the
        // same offence: there is no answer to agree with.
        let invented = json!({ "volumes": [{ "base_image_url": "https://mine/x.img" }] });
        assert!(check_owned_volume_fields(&invented, &catalogue()).is_err());

        // The tenant's own reference, which is the point of the object.
        check_owned_volume_fields(
            &json!({ "volumes": [{ "volume": "acme-data" }] }),
            &catalogue(),
        )
        .expect("naming a volume object is the tenant's business, not the cloud's");

        // And an ordinary declared disk is untouched.
        check_owned_volume_fields(
            &json!({ "volumes": [{ "size_bytes": 1, "base_image": "debian.raw" }] }),
            &catalogue(),
        )
        .expect("nothing control-plane-owned here");
    }

    /// The document this cloud handed out, handed back — which is what every
    /// PATCH on this API is, because a patch is merged onto the STORED object
    /// before it reaches the PUT that validates it.
    ///
    /// Refusing the fields on presence alone made `vm stop` impossible on any
    /// VM built from the catalogue: the merged document carried the very url
    /// this cloud had written into it, and was told the field was
    /// control-plane-owned. Found in the lab on the first `vm stop` anybody
    /// ran against such a VM.
    #[test]
    fn the_document_the_cloud_wrote_may_be_handed_back_unchanged() {
        let catalogue = std::collections::BTreeMap::from([(
            "noble".to_string(),
            ("https://images/noble.img".to_string(), "abc123".to_string()),
        )]);
        let stored = json!({
            "volumes": [{
                "base_image": "noble",
                "base_image_url": "https://images/noble.img",
                "base_image_sha256": "abc123",
                "size_bytes": 4294967296u64,
            }]
        });
        check_owned_volume_fields(&stored, &catalogue)
            .expect("the cloud's own answer, given back to it");

        // One character different is a client choosing the bytes, and that is
        // the whole reason the door is here.
        let tampered = json!({
            "volumes": [{
                "base_image": "noble",
                "base_image_url": "https://elsewhere/noble.img",
                "base_image_sha256": "abc123",
            }]
        });
        let msg = format!(
            "{:?}",
            check_owned_volume_fields(&tampered, &catalogue).unwrap_err()
        );
        assert!(msg.contains("base_image_url"), "{msg}");
    }

    /// A member's POST body is not allowed to name its own overlay, its own
    /// floating addresses or its own allowlist. All three injectors skip a NIC
    /// that already carries the field — that skip is the standalone road one
    /// tier down, and at this edge it would be a tenant writing another
    /// tenant's VNI into its own NIC and landing on their bridge.
    #[test]
    fn a_client_may_not_name_the_fields_the_cloud_owns() {
        for (field, value) in [
            ("vxlan_id", json!(10042)),
            ("floating_ips", json!(["203.0.113.7"])),
            ("routed_subnets", json!(["0.0.0.0/0"])),
        ] {
            let spec = json!({ "nics": [{}, { field: value }] });
            let err = check_owned_nic_fields(&spec).unwrap_err();
            let msg = format!("{err:?}");
            assert!(msg.contains(field), "the message names the field: {msg}");
            assert!(msg.contains("nics[1]"), "and which nic: {msg}");
        }
    }

    /// What a spec MAY say is untouched: a plain nic, no nics at all, and an
    /// explicit null (which is "named nothing", not "named something").
    #[test]
    fn a_spec_that_leaves_those_fields_alone_passes() {
        for spec in [
            json!({ "nics": [{ "mac": "52:54:00:11:22:33" }] }),
            json!({ "nics": [] }),
            json!({ "vcpus": 2 }),
            json!({ "nics": [{ "vxlan_id": null, "floating_ips": null }] }),
        ] {
            check_owned_nic_fields(&spec).expect("nothing control-plane-owned here");
        }
    }

    #[test]
    fn base_images_are_the_volumes_that_name_one() {
        let spec = json!({
            "volumes": [
                { "base_image": "nixos.raw", "size_bytes": 1 },
                { "size_bytes": 2 },
                { "base_image": "", "size_bytes": 3 },
                { "base_image": "nixos.raw", "size_bytes": 4 }
            ]
        });
        let found = base_images(&spec);
        assert_eq!(found.len(), 1);
        assert!(found.contains("nixos.raw"));
        // A spec with no volumes at all references nothing rather than failing.
        assert!(base_images(&json!({ "vcpus": 1 })).is_empty());
    }
}
