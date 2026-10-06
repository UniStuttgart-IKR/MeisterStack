// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! The `vms` resource: create, read, update, delete, plus logs and console.

use super::*;

// --- vms -------------------------------------------------------------------

/// Collect nonempty disk base-image names. Boot sources are resolved separately
/// and are not image-catalogue references.
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

/// Reject referenced-volume entries that also supply inline disk fields.
/// General VM JSON validation, including CPU and memory bounds, is performed by
/// vm_spec::check before this helper.
pub(super) fn check_vm_shape(vm: &serde_json::Value) -> Result<(), ApiError> {
    // A referenced volume has its size and image already, refused where a
    // person can still read it. Built through `VmSpec` so the rule is the one
    // function both tiers call rather than two that could drift.
    let as_spec: controller_api::VmSpec = serde_json::from_value(serde_json::json!({ "vm": vm }))
        .unwrap_or_else(|_| {
            // The VM value and defaulted envelope fields normally deserialize directly.
            // The empty fallback leaves reference validation with no entries.
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

/// Reject client-supplied VNI and address allowlists at the cloud boundary.
/// Lower tiers preserve explicit values for standalone operation; accepting them
/// here would let tenants select another overlay or expand their source allowlist.
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

/// Validate referenced secrets and volumes within the VM's tenant.
/// Missing or cross-tenant references return 404 to conceal other tenants' names.
/// Deleting volumes and volumes held by another VM return 409. A missing secret
/// key returns 422; a volume that is not Ready yet is accepted.
///
/// Volume readiness and cluster reachability constrain placement in
/// `reconcile::placement::wanted`; this tier does not select a node.
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
        // Reject missing keys at admission for immediate feedback. Dispatch resolves
        // the secret again before sending it to a node.
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

/// Validate VM shape and cloud-owned fields on both create and update.
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
    // Validate the agent document before checking its cloud-specific constraints.
    controller_api::vm_spec::check(&spec.vm)?;
    check_vm_shape(&spec.vm)?;
    check_owned_nic_fields(&spec.vm)?;
    // Unconditionally: every vm at this tier is a tenant's, `create_vm_traced`
    // insists on one.
    controller_api::vni::check_tenant_nics(&spec.vm)?;
    check_owned_volume_fields(&spec.vm, &catalogue_sources(store, &spec.vm).await)?;
    if spec.user_data_said_twice() {
        return Err(controller_api::invalid_field(
            "spec.vm.cloud_init",
            "user_data and user_data_from are two starting points; name one",
        ));
    }
    // The cluster derives local_hostname from the VM name. Other cloud-init
    // content remains client-supplied and is interpreted by cloud-init.
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

/// Require a registered image whose phase is not Failed.
/// Shared by inline VM disks and Volume objects; readiness is resolved later.
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
        Err(StoreError::NotFound(_)) => Err(unknown_base_image(name)),
        Err(e) => Err(e.into()),
    }
}

/// Require image read permission before exposing its existence or failure state.
/// Using an image copies its bytes into a tenant-readable disk, so it needs the
/// same permission as GET. Missing and inaccessible images receive the same error.
///
/// Called at VM and volume creation. Updates cannot change the base image and
/// must remain possible for an owner whose VM was created by an administrator.
pub(super) async fn check_image_readable(
    store: &EtcdStore,
    who: &Grant,
    name: &str,
) -> Result<(), ApiError> {
    let image = match store.get::<Image>(name).await {
        Ok(image) => image,
        Err(StoreError::NotFound(_)) => return Err(unknown_base_image(name)),
        Err(e) => return Err(e.into()),
    };
    who.allows(
        Scope::image(image.spec.tenant.as_deref(), image.spec.public),
        Verb::Read,
    )
    .map_err(|_| unknown_base_image(name))
}

fn unknown_base_image(name: &str) -> ApiError {
    invalid(format!(
        "unknown base_image {name:?}; register it first (meister image create)"
    ))
}

/// Reject non-null image source fields that disagree with the current catalogue.
/// The URL, digest and image UID determine which bytes a node uses and caches.
/// Matching values are accepted so PUT and merged PATCH requests can round-trip
/// the fields the cloud injected; clients cannot substitute their own source.
pub(super) fn check_owned_volume_fields(
    vm: &serde_json::Value,
    resolved: &std::collections::BTreeMap<String, CatalogueSource>,
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
            ("base_image_url", ours.map(|s| &s.url)),
            ("base_image_sha256", ours.map(|s| &s.sha256)),
            ("base_image_uid", ours.map(|s| &s.uid)),
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
        // Clients may name a `volume` reference. `check_volume_refs` checks its
        // tenant ownership separately, once the VM's tenant is known.
    }
    Ok(())
}

/// Read URL, digest and UID for each named catalogue image.
/// Missing or unreadable images and entries without both URL and digest are
/// omitted. Validation and injection read independently; these reads are not
/// an atomic catalogue snapshot.
pub(super) async fn catalogue_sources(
    store: &EtcdStore,
    vm: &serde_json::Value,
) -> std::collections::BTreeMap<String, CatalogueSource> {
    let mut sources: std::collections::BTreeMap<String, CatalogueSource> = Default::default();
    for name in base_images(vm) {
        let Ok(image) = store.get::<Image>(&name).await else {
            continue;
        };
        let uid = image.metadata.uid.clone();
        if let (Some(url), Some(sha256)) = (image.spec.url, image.spec.sha256) {
            sources.insert(name, CatalogueSource { url, sha256, uid });
        }
    }
    sources
}

/// Resolved source and registration identity for one catalogue image.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct CatalogueSource {
    pub(super) url: String,
    pub(super) sha256: String,
    /// The image OBJECT's uid, which is the only thing about an image that is
    /// not shared with everybody who registers the same name. The node keys
    /// its cache on it. Astra finding S02, 2026-09-23.
    pub(super) uid: String,
}

/// Inject the current catalogue URL, digest and UID for URL-backed images.
/// Called during create and update; immutable-shape checks constrain updates.
/// Path images retain local name resolution without injected source fields.
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
        let Some(source) = sources.get(name).cloned() else {
            continue;
        };
        let Some(volume) = volume.as_object_mut() else {
            continue;
        };
        volume.insert("base_image_url".into(), json!(source.url));
        volume.insert("base_image_sha256".into(), json!(source.sha256));
        // And WHOSE registration it was. The node's cache entry is keyed on
        // this and the digest, so a name re-registered by somebody else never
        // reaches these bytes. Astra finding S02, 2026-09-23.
        volume.insert("base_image_uid".into(), json!(source.uid));
    }
    Ok(())
}

/// Check VM quota and return the tenant fence required by the admission write.
/// `except` excludes an existing VM so updates count its replacement capacity.
/// Read the fence before usage to detect concurrent admissions or quota changes.
/// Even tenants without limits return a fence; unscoped VMs return none.
/// Reject incomplete VM listings rather than undercounting usage.
pub(super) async fn check_quota(
    st: &ApiState,
    tenant: Option<&str>,
    adding: Capacity,
    except: Option<&str>,
) -> Result<Option<Fence>, ApiError> {
    let Some(tenant) = tenant else {
        return Ok(None);
    };
    let fence = st.store.fence(&quota::fence(tenant)).await?;
    let object: Tenant = st.store.get(tenant).await?;
    if object.spec.quota.is_unset() {
        return Ok(Some(fence));
    }
    let (vms, keys) = st.store.list_counted::<Vm>().await?;
    if vms.len() != keys {
        return Err(conflict(
            "cannot tell how much this tenant is holding (some vm objects did not decode); \
             refusing to let it grow",
        ));
    }
    let after = quota::Usage::of(tenant, &vms, except).plus(adding);
    let Err(why) = quota::check(&object.spec.quota, tenant, after) else {
        return Ok(Some(fence));
    };
    // Attach quota events to the tenant so rejected creates have a persistent
    // subject and repeated failures aggregate by tenant and reason.
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

/// Continue a valid caller trace or create a root. Attach the parent before
/// entering the span so it determines the trace ID.
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
    // Before `validate_vm_spec`, which describes an image it finds unusable:
    // see `check_image_readable`.
    for image in base_images(&body.spec.vm) {
        check_image_readable(&st.store, &who, &image).await?;
    }
    validate_vm_spec(&st.store, &body.spec).await?;

    // Require an existing owner before writing. Confined callers default to their
    // own tenant; administrators must name one. The tenant supplies the VM's VNI
    // and quota scope.
    let owner = who
        .tenant_for_create(body.spec.tenant.clone())
        .ok_or_else(|| invalid("spec.tenant must name a tenant"))?;
    who.allows(Scope::of(Some(owner.as_str())), Verb::Write)?;
    check_tenant(&st, &owner).await?;
    // After the owner is known and not in `validate_vm_spec`, because whose
    // volume it has to be is exactly the question the owner answers.
    check_volume_refs(&st, Some(owner.as_str()), &body.metadata.name, &body.spec).await?;

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
            tenant: Some(owner.clone()),
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
        // As the scheduler's own fact, exactly as one tier down: a preview is
        // a sentence about a VM that has not been created, and this object is
        // never stored.
        vm.status.placement = Some(controller_api::VmPlacement {
            reason: controller_api::VmReason::Unplaced,
            message: said,
            at: chrono::Utc::now(),
        });
        vm.settle(chrono::Utc::now());
    }
    // The quota, and the write, as one decision: see `admission`. Before the
    // create and not after — a VM that was written and then found to be over
    // the ceiling is a VM somebody has to go and delete.
    let wanted = Capacity::wanted_by_spec(&vm.spec.vm);
    let (st_, vm_, owner_) = (&st, &vm, owner.as_str());
    let created = admit(owner_, move || async move {
        let fence = check_quota(st_, Some(owner_), wanted, None).await?;
        #[cfg(test)]
        super::admission_tests::admission_gate(owner_).await;
        match dry.preview(vm_) {
            Some(preview) => Ok(Some(preview)),
            None => create_under(st_, vm_, fence.as_ref()).await,
        }
    })
    .await?;
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

/// Field ownership and mutability for VM updates.
/// Boot shape and inline disks are immutable; later referenced disks may change
/// for hot-plug. A binding may only be cleared through the reschedule guards.
pub(super) const VM_OWNED: &[Owned] = &[
    // `vm_shape_unchanged` freezes boot and inline disks while permitting edits
    // to referenced disks after the boot entry. Adding or removing a reference
    // drives hot-plug; `Volume.status.attachedTo` remains derived.
    // The rule covers `spec.vm` because its nested schema belongs to the agent.
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
    // Clients may clear the cluster binding but cannot choose a replacement.
    // This predicate checks edit shape; `check_reschedule` separately checks phase,
    // holder evidence and whether referenced disks can follow the VM.
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

/// Publish the shared VM schema without `spec.nodeName`.
/// Cloud placement chooses clusters; write validation rejects explicit node names.
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

/// Reject explicit node placement with 422; this tier places on clusters.
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

/// Store-derived facts about one referenced disk used by `reschedule_refusal`.
/// Keeping reads outside the rule allows phase and storage checks without etcd.
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

/// Return the reason a VM cannot release its cluster binding.
/// The shared phase rule requires stopped intent and an allowed reported phase.
/// Referenced disks must not be node-local, must serve at least two clusters,
/// and must have no reported backend disagreement between those clusters.
/// Inline ephemeral disks are recreated at the destination and are not checked.
pub(super) fn reschedule_refusal(current: &Vm, disks: &[DiskFacts]) -> Option<String> {
    // The shared rule permits Stopped intent with Failed or Unknown reports;
    // separate holder checks constrain an Unknown release.
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

/// Read storage facts and apply the pure reschedule rule.
async fn check_reschedule(st: &ApiState, current: &Vm, next: &Vm) -> Result<(), ApiError> {
    let Some(here) = releasing(current, next) else {
        return Ok(());
    };
    // Check required holder evidence before reading storage constraints.
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

/// Read the cluster heartbeat lease and apply the shared holder rule.
/// Unknown guests require a recently reporting holder before binding release.
async fn check_holder_is_talking(
    st: &ApiState,
    current: &Vm,
    cluster: &str,
) -> Result<(), ApiError> {
    // The lease and not the object: the heartbeat moved into a key of its own
    // (D-C7), and an absent lease is the same answer an absent object gave —
    // this cluster has not reported.
    let heard = st
        .store
        .last_beat::<controller_api::Cluster>(cluster)
        .await?;
    holder_refusal(current, cluster, heard, Utc::now())
}

/// Apply the shared heartbeat rule without store access. A stale holder returns
/// 409 because cluster state, not request shape, prevents release.
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

/// Record a warning after successfully releasing an Unknown VM binding.
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

    // Restore server metadata before ownership checks. Binding changes are
    // validated separately so teardown cannot be redirected to another cluster.
    let current: Vm = st.store.get(&name).await?;
    Grant::new(caller, role, tenant)
        .allows(Scope::of(current.spec.tenant.as_deref()), Verb::Write)?;
    body.metadata.uid = current.metadata.uid.clone();
    body.metadata.creation_timestamp = current.metadata.creation_timestamp;
    body.metadata.deletion_timestamp = current.metadata.deletion_timestamp;
    body.metadata.finalizers = current.metadata.finalizers.clone();
    // Reject forbidden ownership edits. Changing tenant would change the VM
    // network identity while its existing NICs still use the old VNI.
    check_owned(&current, &body, VM_OWNED)?;
    // Check references after immutable tenancy is established. Hot-plug updates
    // can introduce new volume names and require the same ownership checks as create.
    check_volume_refs(&st, current.spec.tenant.as_deref(), &name, &body.spec).await?;
    check_reschedule(&st, &current, &body).await?;
    body.status = current.status.clone();
    // Recalculate replacement usage under the tenant fence for updates as well
    // as creates, excluding the current VM from the existing total.
    controller_api::carry_generation(&current, &mut body)?;
    let wanted = Capacity::wanted_by_spec(&body.spec.vm);
    let (st_, body_, name_) = (&st, &body, name.as_str());
    let tenant = body.spec.tenant.as_deref();
    let stored = admit(tenant.unwrap_or("-"), move || async move {
        let fence = check_quota(st_, tenant, wanted, Some(name_)).await?;
        match dry.preview(body_) {
            Some(preview) => Ok(Some(preview)),
            None => update_under(st_, body_, fence.as_ref()).await,
        }
    })
    .await?;
    if !dry.requested() {
        note_unknown_release(&st, &current, &body).await;
    }
    Ok(Json(stored))
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
    // On the object whose tenant was checked: one deleted and made again
    // under the name since is somebody else's. (IKR-B81)
    st.store
        .mutate_if::<Vm, _>(&name, &current.metadata.uid, |v| {
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

/// Requested line count and repeated log filters. Keep raw query pairs to
/// preserve repeated hide/only values. Nodes filter before applying the line limit.
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

/// Peer and tier labels for forwarding cloud requests to a cluster-session holder.
pub(super) const ABOUT: controller_api::forward::About = controller_api::forward::About {
    peer: "cluster",
    tier: "cloud",
};

/// Read the endpoint advertised by the cluster-session holder. A missing
/// cluster or unset endpoint yields None.
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

/// Encode log filters for the HTTP sibling hop so routing preserves the query.
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
    // Forward once to the advertised cluster-session holder using this cloud
    // identity when the session is held by a sibling.
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

/// Mint a single-use console ticket after checking write permission on the VM.
/// Browser WebSockets cannot set an Authorization header, so the ticket carries
/// the authenticated grant in a path-bound query credential for thirty seconds.
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

/// Open a raw or WebSocket guest console after tenant-scoped write authorization.
/// Use the local cluster session or one authenticated sibling hop; wait for
/// ConsoleReady before upgrading so a refusal can retain an HTTP status.
/// ConsoleOpen currently carries a VM name without the cloud UID.
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
    // Send to the cluster speaker. The cluster resolves and forwards to its
    // node-session holder; that routing is outside cloud ownership.
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
        // Use the endpoint advertised by the sibling holding the cluster session.
        let endpoint = st
            .store
            .get::<Cluster>(&cluster)
            .await
            .ok()
            .and_then(|c| c.status.session_endpoint)
            .filter(|e| !e.is_empty());
        // Reject self-forwarding and a second hop. The advertised endpoint can be
        // stale after session loss, so it cannot itself establish reachability.
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

    // Wait before HTTP 101 so a refusal can retain an HTTP error status.
    // One acceptance succeeds; otherwise wait for every reached recipient to refuse.
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

/// Build the raw-console or WebSocket upgrade response, including the
/// Sec-WebSocket-Accept value required by the latter.
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

/// A common byte stream for plain and TLS sibling connections.
trait Console: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send {}
impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send> Console for T {}

/// Proxy a console to one sibling, carrying the loop-prevention header.
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

    // TLS sibling requests use the cloud system identity, matching log forwarding.
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
        // Read the sibling status message when a Content-Length body is available,
        // so the caller receives the cause rather than only the HTTP number.
        let said = read_refusal(&mut sibling, &text).await;
        return Err(conflict(said.unwrap_or_else(|| {
            format!("the replica at {authority} answered {status} to a console open")
        })));
    }

    let framed = websocket.is_some();
    tokio::spawn(async move {
        if let Ok(upgraded) = on_upgrade.await {
            let client = hyper_util::rt::TokioIo::new(upgraded);
            // Sibling transport is raw; unwrap browser WebSocket frames at this edge.
            let mut client: Box<dyn Console> = match framed {
                true => Box::new(controller_api::websocket::adapt(client)),
                false => Box::new(client),
            };
            let _ = tokio::io::copy_bidirectional(&mut client, &mut sibling).await;
        }
    });

    Ok(switching(websocket))
}

/// Read a nonempty message from a length-delimited sibling Status body.
/// Return None on absent, malformed or unreadable content for the status fallback.
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

/// Remove a failed console route before returning its error.
fn gone(sessions: &crate::session::SessionRegistry, session_id: &str, error: ApiError) -> ApiError {
    sessions.consoles.forget(session_id);
    error
}

/// What this upgrade is called on the wire, at every tier that serves one.
pub const CONSOLE_PROTOCOL: &str = "meister-console";

/// Deadline for opening a console through the controller tiers and node.
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

/// Translate cluster refusals into HTTP errors while preserving their messages.
/// Unavailable and Timeout are retryable 503 responses. Empty and unknown reason
/// codes retain the legacy 409 response.
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

    /// The cloud schema omits node placement and validation rejects it explicitly.
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

    /// Raw and WebSocket clients receive their respective upgrade headers.
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

    /// Field ownership allows clearing a cluster binding but not replacing it.
    /// Separate reschedule checks decide when clearing is allowed.
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
        said_to_be(&mut vm, controller_api::VmPhaseKind::Stopped);
        vm
    }

    /// A VM whose cluster has said it is in this phase, through the
    /// derivation — the only way in since struktur 4, and a resting word is
    /// refused unless a holder is named (see `VmReported`).
    fn said_to_be(vm: &mut Vm, phase: controller_api::VmPhaseKind) {
        let holder = vm
            .status
            .cluster_name
            .clone()
            .or_else(|| vm.spec.cluster_name.clone())
            .unwrap_or_else(|| "a-cluster".to_string());
        vm.status.reported = Some(controller_api::VmReported::by(
            &holder,
            phase,
            controller_api::VmReason::Unrecorded,
            None,
            chrono::Utc::now(),
        ));
        vm.settle(chrono::Utc::now());
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

    /// Unknown bindings require a reporting cluster; a silent holder returns 409.
    #[test]
    fn an_unknown_binding_is_only_let_go_while_its_cluster_reports() {
        let at = |secs: i64| chrono::DateTime::from_timestamp(1_800_000_000 + secs, 0).unwrap();
        let now = at(1_000);
        let mut vm = stopped_vm();
        said_to_be(&mut vm, controller_api::VmPhaseKind::Unknown);

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
        said_to_be(&mut failed, controller_api::VmPhaseKind::Failed);
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
            said_to_be(&mut vm, phase);
            let why = reschedule_refusal(&vm, &[]).expect("a moving vm does not move");
            assert!(why.contains(phase.as_str()), "and names the phase: {why}");
        }
    }

    /// Failed and Unknown phases allow binding release under stopped intent,
    /// while referenced-disk restrictions still apply.
    #[test]
    fn a_failed_or_unknown_vm_may_let_its_cluster_binding_go() {
        for phase in [
            controller_api::VmPhaseKind::Failed,
            controller_api::VmPhaseKind::Unknown,
        ] {
            let mut vm = stopped_vm();
            said_to_be(&mut vm, phase);
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

    /// Catalogue source fields reject substitutions. Volume references remain
    /// allowed here because their tenant ownership is checked separately.
    #[test]
    fn a_client_may_not_name_the_volume_fields_the_cloud_owns() {
        let catalogue = || {
            std::collections::BTreeMap::from([(
                "noble".to_string(),
                CatalogueSource {
                    url: "https://images/noble.img".to_string(),
                    sha256: "abc123".to_string(),
                    uid: "4f3c0000-0000-0000-0000-00000000000a".to_string(),
                },
            )])
        };
        // Image registration identity is cloud-owned, just like URL and digest,
        // because it selects the node cache entry.
        for field in ["base_image_url", "base_image_sha256", "base_image_uid"] {
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

    /// Accept catalogue fields round-tripped by PUT or merged PATCH, while rejecting
    /// any substituted source value.
    #[test]
    fn the_document_the_cloud_wrote_may_be_handed_back_unchanged() {
        let catalogue = std::collections::BTreeMap::from([(
            "noble".to_string(),
            CatalogueSource {
                url: "https://images/noble.img".to_string(),
                sha256: "abc123".to_string(),
                uid: "4f3c0000-0000-0000-0000-00000000000a".to_string(),
            },
        )]);
        let stored = json!({
            "volumes": [{
                "base_image": "noble",
                "base_image_url": "https://images/noble.img",
                "base_image_sha256": "abc123",
                "base_image_uid": "4f3c0000-0000-0000-0000-00000000000a",
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

    /// Clients cannot supply overlay or source-allowlist fields that lower-tier
    /// injectors preserve for standalone use.
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

    /// IKR-B67: `physnet: ext` from a tenant member was taken while
    /// `vxlan_id` was refused. Every vm at this tier is a tenant's.
    #[tokio::test]
    async fn a_vm_whose_nic_picks_its_own_wire_is_refused_at_the_cloud() {
        // No base image, so nothing below reads the store.
        let store = EtcdStore::connect(&["http://127.0.0.1:1".to_string()], "/b67-test")
            .await
            .expect("the etcd client is built lazily");
        for field in ["physnet", "bridge"] {
            let spec: VmSpec = serde_json::from_value(json!({ "vm": {
                "vcpus": 1, "memory_mib": 512,
                "boot": { "kind": "firmware", "firmware": "fw" },
                "volumes": [{ "size_bytes": 1 }],
                "nics": [{ field: "ext" }],
            }}))
            .expect("a vm spec");
            let err = validate_vm_spec(&store, &spec)
                .await
                .expect_err("a tenant's tap on a wire it chose");
            assert_eq!(
                err.field(),
                Some(format!("spec.vm.nics[0].{field}").as_str())
            );
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
