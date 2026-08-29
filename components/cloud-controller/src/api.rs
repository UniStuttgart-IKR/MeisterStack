// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! The cloud's REST API — the end API of the stack, in the same K8s-style
//! shape the cluster serves one tier down. One CLI, two endpoints; what
//! differs is only the resources (cloud: clusters, vms, images).

use std::collections::BTreeSet;
use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::routing::{get, put};
use axum::{Json, Router};
use chrono::{Duration, Utc};
use controller_api::events;
use controller_api::{
    API_VERSION, ApiError, Caller, CallerRole, CallerTenant, Capacity, CertificateSigningRequest,
    Cluster, ClusterSpec, EtcdStore, FloatingIp, FloatingPool, Image, ImageSpec, Resource, Role,
    RoutedSubnet, Scope, SpecUpdate, StoragePool, StoreError, Tenant, User, Verb, Vm, VmSpec,
    Volume, VolumePhase, apply_spec_update, check_envelope, conflict, floating, forbidden, invalid,
    permits_object, quota,
    resources::{
        CsrCondition, CsrConditionType, CsrSpec, IssuedCertificate, SIGNER_USER_CLIENT,
        backend_name, new_vm, new_volume,
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
}

pub fn router(
    store: Arc<EtcdStore>,
    sessions: Arc<crate::session::SessionRegistry>,
    signing: Option<Arc<Signing>>,
    vni_base: u32,
    routed_pools: Vec<String>,
) -> Router {
    let state = ApiState {
        store,
        sessions,
        signing,
        vni_base,
        routed_pools: Arc::new(routed_pools),
    };
    Router::new()
        .route("/healthz", get(healthz))
        .route("/readyz", get(healthz))
        .route("/apis/meister.io/v1/vms", get(list_vms).post(create_vm))
        .route(
            "/apis/meister.io/v1/vms/{name}",
            get(get_vm).put(update_vm).delete(delete_vm),
        )
        .route("/apis/meister.io/v1/vms/{name}/logs", get(vm_logs))
        .route("/apis/meister.io/v1/vms/{name}/events", get(vm_events))
        .route("/apis/meister.io/v1/events", get(list_events))
        .route("/apis/meister.io/v1/clusters", get(list_clusters))
        .route(
            "/apis/meister.io/v1/clusters/{name}",
            get(get_cluster).put(update_cluster),
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
            get(get_tenant).put(update_tenant).delete(delete_tenant),
        )
        .route(
            "/apis/meister.io/v1/floatingpools",
            get(list_floating_pools).post(create_floating_pool),
        )
        .route(
            "/apis/meister.io/v1/floatingpools/{name}",
            get(get_floating_pool)
                .put(update_floating_pool)
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
                .delete(delete_storage_pool),
        )
        .route(
            "/apis/meister.io/v1/volumes",
            get(list_volumes).post(create_volume),
        )
        .route(
            "/apis/meister.io/v1/volumes/{name}",
            get(get_volume).put(update_volume).delete(delete_volume),
        )
        .route(
            "/apis/meister.io/v1/routedsubnets",
            get(list_routed_subnets).post(create_routed_subnet),
        )
        .route(
            "/apis/meister.io/v1/routedsubnets/{name}",
            get(get_routed_subnet)
                .put(update_routed_subnet)
                .delete(delete_routed_subnet),
        )
        .route(
            "/apis/meister.io/v1/users",
            get(list_users).post(create_user),
        )
        .route(
            "/apis/meister.io/v1/users/{name}",
            get(get_user).put(update_user).delete(delete_user),
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
}

/// Who the guard says is calling, in the shape the tenant-scoped handlers
/// want it: an identity (or anonymous), the role the DIRECTORY gave it, and
/// the tenant from the same object.
///
/// Bundled rather than threaded as three parameters because they are one
/// fact and are never useful apart — and because a handler that took only two
/// of them would be a handler that had quietly stopped scoping.
#[derive(Clone, Debug)]
struct Grant {
    caller: Caller,
    role: Option<Role>,
    tenant: Option<String>,
}

impl Grant {
    fn new(
        caller: Caller,
        CallerRole(role): CallerRole,
        CallerTenant(tenant): CallerTenant,
    ) -> Self {
        Self {
            caller,
            role,
            tenant,
        }
    }

    /// May this caller do `verb` to an object in `scope`?
    ///
    /// The middleware has already said yes to the KIND of request; this is
    /// the half that needs the object, and it runs in every handler that
    /// touches one. Anonymous mode says yes to everything, here as it does
    /// everywhere else — that is the mode the lab has run in since M1.
    ///
    /// A refusal is 403 and not 404 in both directions, which is K8s' own
    /// answer and its own trade: a name's existence is inferable from the
    /// difference, and a 404 on a write would send an admin debugging the
    /// wrong thing. Listings still filter, so an inventory is never handed
    /// out wholesale — but a guessed name gets an honest "not yours".
    fn allows(&self, scope: Scope<'_>, verb: Verb) -> Result<(), ApiError> {
        let Some(identity) = &self.caller.0 else {
            return Ok(());
        };
        if permits_object(identity, self.role, self.tenant.as_deref(), scope, verb) {
            return Ok(());
        }
        Err(forbidden(format!(
            "{} may not {verb:?} an object of tenant {}",
            identity.name,
            scope.tenant.unwrap_or("<none>")
        )))
    }

    /// Is this caller confined to one tenant? An admin, a system identity and
    /// anonymous are not, and get their objects exactly as they always did.
    fn confined_to(&self) -> Option<&str> {
        let identity = self.caller.0.as_ref()?;
        if identity.is_system() || self.role != Some(Role::Member) {
            return None;
        }
        self.tenant.as_deref()
    }

    /// What a create means when the client named no tenant: a member's object
    /// is its own tenant's, and nobody else's create is changed at all.
    ///
    /// The injection is here rather than in the client because the client is
    /// where a value can be left out, and an object created without an owner
    /// is an object no member can ever see again.
    fn tenant_for_create(&self, named: Option<String>) -> Option<String> {
        named
            .filter(|t| !t.is_empty())
            .or_else(|| self.confined_to().map(str::to_string))
    }
}

async fn healthz() -> &'static str {
    "ok"
}

// --- vms -------------------------------------------------------------------

/// Every base_image a VM spec names. A volume without one is a blank disk and
/// references nothing. The boot source resolves against the same node-local
/// directory but is deliberately not catalogued in v1 — the check covers disk
/// base images, which is what the design put in the catalogue.
fn base_images(vm: &serde_json::Value) -> BTreeSet<String> {
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
fn check_owned_nic_fields(vm: &serde_json::Value) -> Result<(), ApiError> {
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

/// Everything the cloud can decide about a VM spec on its own — run from POST
/// and from PUT both. A document that is only checked on the way in is a
/// document that gets edited afterwards, and it is the edited one that
/// travels down to the agent.
async fn validate_vm_spec(store: &EtcdStore, spec: &VmSpec) -> Result<(), ApiError> {
    if !spec.vm.is_object() {
        return Err(invalid("spec.vm must be the agent's NewVmSpec object"));
    }
    if spec.vm.get("desired").is_some() {
        return Err(invalid(
            "spec.vm.desired is controller-owned; use spec.runStrategy",
        ));
    }
    check_owned_nic_fields(&spec.vm)?;
    check_owned_volume_fields(&spec.vm)?;
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
async fn check_base_image(store: &EtcdStore, name: &str) -> Result<(), ApiError> {
    match store.get::<Image>(name).await {
        Ok(image) if image.status.phase == controller_api::ImagePhase::Failed => {
            Err(invalid(format!(
                "base_image {:?} is not usable: {}",
                image.metadata.name,
                image.status.message.as_deref().unwrap_or("unknown reason")
            )))
        }
        Ok(_) => Ok(()),
        Err(StoreError::NotFound(_)) => Err(invalid(format!(
            "unknown base_image {name:?}; register it first (cloud image create)"
        ))),
        Err(e) => Err(e.into()),
    }
}

/// Fields on a volume that the control plane owns, refused when a client
/// sends them.
///
/// The same boundary `check_owned_nic_fields` guards, one field-list over.
/// Where a base image is fetched from and what it must hash to come out of
/// the Image OBJECT, resolved by the cloud — a client that could write them
/// into its own spec could point a `base_image` name at bytes of its own
/// choosing while the catalogue entry everybody else reads says something
/// different.
fn check_owned_volume_fields(vm: &serde_json::Value) -> Result<(), ApiError> {
    let volumes = vm
        .get("volumes")
        .and_then(|v| v.as_array())
        .map(Vec::as_slice)
        .unwrap_or(&[]);
    for (i, volume) in volumes.iter().enumerate() {
        for field in ["base_image_url", "base_image_sha256"] {
            if volume.get(field).is_some_and(|v| !v.is_null()) {
                return Err(invalid(format!(
                    "spec.vm.volumes[{i}].{field} is control-plane-owned; the cloud fills it in \
                     from the image catalogue"
                )));
            }
        }
        // A reference to a `Volume` OBJECT, refused outright rather than
        // ignored.
        //
        // The object exists now and the attach path does not: nothing between
        // here and the agent resolves the name, and the agent's `VolumeSpec`
        // takes unknown fields without complaint. So a spec naming one would
        // be accepted and would boot the VM on a fresh blank disk instead of
        // the tenant's data — which is the one failure mode in this file
        // worth a hard refusal.
        //
        // When resolution lands, this door becomes the tenancy check rather
        // than disappearing: the volume named has to be one this VM's tenant
        // owns, checked HERE for the reason `check_owned_nic_fields` gives —
        // at this edge the spec is a member's POST body, and a member naming
        // somebody else's volume would be reading somebody else's disk.
        if volume.get("volume").is_some_and(|v| !v.is_null()) {
            return Err(invalid(format!(
                "spec.vm.volumes[{i}].volume names a volume object; attaching one to a vm is \
                 not built yet, and a spec that named one would silently get a blank disk \
                 instead. Declare the disk in the spec, or wait for volume attachment"
            )));
        }
    }
    Ok(())
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
async fn resolve_base_images(
    store: &EtcdStore,
    vm: &mut serde_json::Value,
) -> Result<(), ApiError> {
    let mut sources: std::collections::BTreeMap<String, (String, String)> = Default::default();
    for name in base_images(vm) {
        let image: Image = match store.get(&name).await {
            Ok(image) => image,
            // Already refused by `validate_vm_spec`; nothing to resolve.
            Err(_) => continue,
        };
        if let (Some(url), Some(sha256)) = (image.spec.url, image.spec.sha256) {
            sources.insert(name, (url, sha256));
        }
    }
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
async fn check_quota(
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
async fn list_vms(
    State(st): State<ApiState>,
    caller: Caller,
    role: CallerRole,
    tenant: CallerTenant,
) -> Result<Json<serde_json::Value>, ApiError> {
    let who = Grant::new(caller, role, tenant);
    let mut items = st.store.list::<Vm>().await?;
    if let Some(mine) = who.confined_to() {
        items.retain(|vm| vm.spec.tenant.as_deref() == Some(mine));
    }
    Ok(Json(
        json!({ "apiVersion": API_VERSION, "kind": "VmList", "items": items }),
    ))
}

/// The edge is where the trace is decided: continue the caller's if it sent a
/// readable one, start a new one if it did not. The span is built and given
/// its parent before it starts — see `telemetry::in_trace` — because a parent
/// attached from inside the body arrives after the trace id has been minted.
async fn create_vm(
    State(st): State<ApiState>,
    caller: Caller,
    role: CallerRole,
    tenant: CallerTenant,
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
    let who = Grant::new(caller, role, tenant);
    telemetry::in_trace(span, &context, create_vm_traced(st, who, body, context)).await
}

async fn create_vm_traced(
    st: ApiState,
    who: Grant,
    body: Vm,
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
    let owner = who.tenant_for_create(body.spec.tenant.clone());
    who.allows(Scope::of(owner.as_deref()), Verb::Write)?;
    if let Some(t) = &owner {
        check_tenant(&st, t).await?;
    }
    // Before the create and not after: a VM that was written and then found
    // to be over the ceiling is a VM somebody has to go and delete.
    check_quota(
        &st,
        owner.as_deref(),
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
            tenant: owner,
            ..spec
        },
    );
    vm.metadata.labels = body.metadata.labels;
    // On the object, because the reconciler that picks this VM up has no
    // other way back to the request it came from. See ANNOTATION_TRACEPARENT.
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
    caller: Caller,
    role: CallerRole,
    tenant: CallerTenant,
) -> Result<Json<Vm>, ApiError> {
    let vm: Vm = st.store.get(&name).await?;
    Grant::new(caller, role, tenant).allows(Scope::of(vm.spec.tenant.as_deref()), Verb::Read)?;
    Ok(Json(vm))
}

async fn update_vm(
    State(st): State<ApiState>,
    Path(name): Path<String>,
    caller: Caller,
    role: CallerRole,
    tenant: CallerTenant,
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
    body.metadata.uid = current.metadata.uid;
    body.metadata.creation_timestamp = current.metadata.creation_timestamp;
    body.metadata.deletion_timestamp = current.metadata.deletion_timestamp;
    body.metadata.finalizers = current.metadata.finalizers;
    body.spec.cluster_name = current.spec.cluster_name;
    body.spec.node_name = None;
    // Ownership is server-owned for the same reason the binding is, and one
    // reason more: the tenant is where the VM's network comes from, and a VM
    // that changed tenants while running would be a VM whose NICs were built
    // for a VNI it no longer belongs to. Whose it is, is decided once.
    body.spec.tenant = current.spec.tenant;
    body.status = current.status;
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
    Ok(Json(st.store.update(&body).await?))
}

async fn delete_vm(
    State(st): State<ApiState>,
    Path(name): Path<String>,
    caller: Caller,
    role: CallerRole,
    tenant: CallerTenant,
) -> Result<Json<Vm>, ApiError> {
    let current: Vm = st.store.get(&name).await?;
    Grant::new(caller, role, tenant)
        .allows(Scope::of(current.spec.tenant.as_deref()), Verb::Write)?;
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

/// How many lines the caller wants, from the end.
#[derive(serde::Deserialize)]
struct LogQuery {
    #[serde(default)]
    lines: Option<u32>,
}

/// The empty console document, in the shape a node would have sent it.
const NO_STREAMS: &[u8] = b"[]";

/// What the guest printed, fetched through the cluster from the node.
///
/// Tenant-scoped exactly as the VM is, and through the same `Grant::allows`
/// every other object route uses: a console is the most revealing thing a VM
/// has, and reading somebody else's would be worse than reading their object.
///
/// One way and only that — no attach, no input, no follow. See the cluster
/// tier's twin.
async fn vm_logs(
    State(st): State<ApiState>,
    Path(name): Path<String>,
    caller: Caller,
    role: CallerRole,
    tenant: CallerTenant,
    axum::extract::Query(q): axum::extract::Query<LogQuery>,
) -> Result<axum::response::Response, ApiError> {
    let vm: Vm = st.store.get(&name).await?;
    Grant::new(caller, role, tenant).allows(Scope::of(vm.spec.tenant.as_deref()), Verb::Read)?;

    let Some(cluster) = vm.spec.cluster_name.as_deref() else {
        // Not placed on a cluster: nothing has started, so nothing has
        // printed. An answer, not a failure.
        return Ok(json_passthrough(NO_STREAMS.to_vec()));
    };
    let op = cloud_command::Op::Logs(proto::FetchVmLogs {
        name: name.clone(),
        // The uid, for the reason CreateVm and DestroyVm carry one: a name is
        // a label people reuse, and a cluster-local VM sharing it is not this
        // VM.
        uid: vm.metadata.uid.clone(),
        lines: q.lines.unwrap_or(0),
    });
    match st.sessions.send_command(cluster, "", op).await {
        Ok(controller_api::Ack::Acked(payload)) => Ok(json_passthrough(payload)),
        // The cluster's own refusal is an answer about this VM, and there is
        // nothing here to retry against it.
        Ok(controller_api::Ack::Rejected(msg)) => Err(conflict(msg)),
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

/// The node's JSON, handed on as the bytes it is — see the cluster tier's
/// twin. Two tiers of deserialise-and-reserialise would be two chances to
/// change what a console said, for no gain.
fn json_passthrough(payload: Vec<u8>) -> axum::response::Response {
    use axum::response::IntoResponse;
    (
        [(axum::http::header::CONTENT_TYPE, "application/json")],
        payload,
    )
        .into_response()
}

// --- events ----------------------------------------------------------------

/// Everything that happened to one VM, recently.
///
/// Scoped through the VM, not through the events: the caller has to be
/// allowed to read the OBJECT, and then it gets the object's history. Doing
/// it the other way round — filtering the event list by the caller's tenant —
/// would answer 200 with an empty list for somebody else's VM, and "there is
/// nothing" is a different and less honest sentence than "that is not yours".
async fn vm_events(
    State(st): State<ApiState>,
    Path(name): Path<String>,
    caller: Caller,
    role: CallerRole,
    tenant: CallerTenant,
) -> Result<Json<serde_json::Value>, ApiError> {
    let vm: Vm = st.store.get(&name).await?;
    Grant::new(caller, role, tenant).allows(Scope::of(vm.spec.tenant.as_deref()), Verb::Read)?;
    let items = events::about(&st.store, Vm::KIND, &vm.metadata.uid, &name).await;
    Ok(Json(
        json!({ "apiVersion": API_VERSION, "kind": "EventList", "items": items }),
    ))
}

/// The whole log, filtered to what the caller may see.
///
/// A member gets its own tenant's and nothing else — the same rule the VM
/// list follows, and for the same reason: a listing is an inventory, and an
/// event names the object it is about. Events with no tenant are the
/// operator's estate (a node's heartbeat, a cluster reconnecting) and only an
/// admin sees them, which is the conservative direction and the one an
/// unscoped VM already takes.
async fn list_events(
    State(st): State<ApiState>,
    caller: Caller,
    role: CallerRole,
    tenant: CallerTenant,
) -> Result<Json<serde_json::Value>, ApiError> {
    let who = Grant::new(caller, role, tenant);
    let mut items = events::all(&st.store).await;
    if let Some(mine) = who.confined_to() {
        items.retain(|e| e.spec.tenant.as_deref() == Some(mine));
    }
    Ok(Json(
        json!({ "apiVersion": API_VERSION, "kind": "EventList", "items": items }),
    ))
}

// --- clusters --------------------------------------------------------------

/// The inventory is the Cluster objects, not the live session map: a cluster
/// that is down has to stay listed as disconnected, with the capacity it last
/// had.
async fn list_clusters(State(st): State<ApiState>) -> Result<Json<serde_json::Value>, ApiError> {
    let items = st.store.list::<Cluster>().await?;
    Ok(Json(
        json!({ "apiVersion": API_VERSION, "kind": "ClusterList", "items": items }),
    ))
}

async fn get_cluster(
    State(st): State<ApiState>,
    Path(name): Path<String>,
) -> Result<Json<Cluster>, ApiError> {
    Ok(Json(st.store.get(&name).await?))
}

/// The Node route one tier up, over the object one tier up, with the same
/// rule and the same narrow meaning: `spec.schedulable = false` stops NEW
/// placements onto this cluster and touches nothing that is already on it.
///
/// Not tenant-scoped and not a member's: a cluster is a piece of the
/// operator's estate, and the middleware already says so (`clusters` is
/// outside `TENANT_SCOPED`, so a member reads and an admin writes).
async fn update_cluster(
    State(st): State<ApiState>,
    Path(name): Path<String>,
    Json(body): Json<SpecUpdate<ClusterSpec>>,
) -> Result<Json<Cluster>, ApiError> {
    let current: Cluster = st.store.get(&name).await?;
    let was = current.spec.schedulable;
    let next = apply_spec_update(body, &name, current)?;
    let now = next.spec.schedulable;
    let updated = st.store.update(&next).await?;
    if was != now {
        info!(cluster = %name, schedulable = now, "cluster schedulability changed");
    }
    Ok(Json(updated))
}

// --- images ----------------------------------------------------------------

/// The catalogue name IS the reference: it is what a VM's `base_image` says,
/// and what the node's block driver then looks up under its own image_dir. v1
/// distributes nothing, so the only way those two namespaces can line up is
/// for the name to be the file name — and a catalogue entry that cannot line
/// up would be worse than no entry at all, because the 422 it buys is a
/// promise the agent goes on to break.
fn check_image_name(name: &str, source: &str) -> Result<(), ApiError> {
    if name.is_empty() || name.contains('/') || name == "." || name == ".." {
        return Err(invalid(
            "metadata.name must be the image's bare file name (no path separators)",
        ));
    }
    let base = source.rsplit('/').next().unwrap_or(source);
    if !base.is_empty() && base != name {
        return Err(invalid(format!(
            "metadata.name must match the file spec.source points at ({base:?}); v1 hands the \
             name to the node verbatim and distributes nothing"
        )));
    }
    Ok(())
}

/// The two rules a fetchable image has to obey, and both are about the
/// checksum rather than about the URL.
///
/// A URL without one is refused because an image fetched over a network and
/// not checked is an image whose contents somebody else chooses — every VM in
/// the fleet booting whatever answered. And a checksum without a URL is
/// refused because it would be a promise nobody checks: nothing fetches a
/// path image, so nothing would ever compare it, and an operator reading the
/// object would believe otherwise.
///
/// The shape is validated here rather than at the node for the reason every
/// other spec rule is: the node is the last place to find out, and by then
/// somebody is waiting for a VM.
fn check_fetchable(spec: &ImageSpec) -> Result<(), ApiError> {
    match (&spec.url, &spec.sha256) {
        (None, None) => Ok(()),
        (Some(_), None) => Err(invalid(
            "spec.sha256 is required with spec.url; an image fetched over a network and not \
             checked is an image somebody else chooses the contents of",
        )),
        (None, Some(_)) => Err(invalid(
            "spec.sha256 without spec.url is a promise nobody checks; nothing fetches a \
             path-based image",
        )),
        (Some(url), Some(sha256)) => {
            if sha256.len() != 64 || !sha256.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err(invalid(format!(
                    "spec.sha256 {sha256:?} must be 64 hex characters"
                )));
            }
            if sha256.bytes().any(|b| b.is_ascii_uppercase()) {
                return Err(invalid("spec.sha256 must be lowercase"));
            }
            // The node runs `curl`, which speaks more than http. A scheme
            // this control plane has not thought about is refused here rather
            // than discovered on a node — `file://` in particular would make
            // an image mean something different on every machine.
            if !(url.starts_with("http://") || url.starts_with("https://")) {
                return Err(invalid(
                    "spec.url must be http:// or https://; a node fetches this, and a scheme \
                     that means something different on every machine is not an image",
                ));
            }
            Ok(())
        }
    }
}

/// A member's catalogue is its own images plus the public ones — which is
/// what a shared base image is for, and why the list is not simply filtered
/// to one tenant the way the VM list is.
async fn list_images(
    State(st): State<ApiState>,
    caller: Caller,
    role: CallerRole,
    tenant: CallerTenant,
) -> Result<Json<serde_json::Value>, ApiError> {
    let who = Grant::new(caller, role, tenant);
    let mut items = st.store.list::<Image>().await?;
    if let Some(mine) = who.confined_to() {
        items.retain(|i| i.spec.public || i.spec.tenant.as_deref() == Some(mine));
    }
    Ok(Json(
        json!({ "apiVersion": API_VERSION, "kind": "ImageList", "items": items }),
    ))
}

async fn create_image(
    State(st): State<ApiState>,
    caller: Caller,
    role: CallerRole,
    tenant: CallerTenant,
    Json(body): Json<Image>,
) -> Result<(StatusCode, Json<Image>), ApiError> {
    check_envelope(&body)?;
    if body.spec.source.is_empty() {
        return Err(invalid("spec.source must say where the image already is"));
    }
    check_image_name(&body.metadata.name, &body.spec.source)?;
    check_fetchable(&body.spec)?;

    let who = Grant::new(caller, role, tenant);
    let owner = who.tenant_for_create(body.spec.tenant.clone());
    // `public` is deliberately not gated beyond this: publishing an image
    // grants a read of a file every node can already open by path, and a
    // member that may create the catalogue entry may say who else sees it.
    who.allows(
        Scope::image(owner.as_deref(), body.spec.public),
        Verb::Write,
    )?;
    if let Some(t) = &owner {
        check_tenant(&st, t).await?;
    }

    let url = body.spec.url.clone();
    let mut image = Image::declare(
        &body.metadata.name,
        ImageSpec {
            tenant: owner,
            ..body.spec
        },
    );
    image.metadata.labels = body.metadata.labels;
    // A path image is Ready the moment it is registered: it is a catalogue
    // entry over storage somebody else already filled, and this control plane
    // has never claimed to check it — saying anything else would be inventing
    // a promise where there was none. A URL image is Pending until a node
    // that has fetched it says otherwise, because the node is what fetches.
    image.status.phase = if url.is_some() {
        controller_api::ImagePhase::Pending
    } else {
        controller_api::ImagePhase::Ready
    };
    image.status.message = url
        .is_some()
        .then(|| "not fetched by any node yet".to_string());
    let created = st.store.create(&image).await?;
    info!(image = %created.metadata.name, tenant = ?created.spec.tenant,
          public = created.spec.public, "image registered");
    Ok((StatusCode::CREATED, Json(created)))
}

async fn get_image(
    State(st): State<ApiState>,
    Path(name): Path<String>,
    caller: Caller,
    role: CallerRole,
    tenant: CallerTenant,
) -> Result<Json<Image>, ApiError> {
    let image: Image = st.store.get(&name).await?;
    Grant::new(caller, role, tenant).allows(
        Scope::image(image.spec.tenant.as_deref(), image.spec.public),
        Verb::Read,
    )?;
    Ok(Json(image))
}

/// A hard delete, because an image object owns no resource anywhere and there
/// is nothing for a teardown to do — but only once nothing names it. The
/// catalogue's whole job is that "every base_image names an Image" holds, and
/// deleting out from under a VM would break it silently, at the exact moment
/// nobody is looking.
async fn delete_image(
    State(st): State<ApiState>,
    Path(name): Path<String>,
    caller: Caller,
    role: CallerRole,
    tenant: CallerTenant,
) -> Result<Json<serde_json::Value>, ApiError> {
    let image: Image = st.store.get(&name).await?;
    let who = Grant::new(caller, role, tenant);
    who.allows(
        Scope::image(image.spec.tenant.as_deref(), image.spec.public),
        Verb::Write,
    )?;

    let vms = st.store.list::<Vm>().await?;
    // `list` drops what it cannot decode, and a dropped VM is a reference not
    // seen. Refusing to answer beats answering "nothing references it" from a
    // list that is not all of them.
    if vms.len() != st.store.count::<Vm>().await? {
        return Err(conflict(
            "cannot tell whether anything still references this image (some vm objects did not \
             decode); refusing to delete",
        ));
    }
    // Every VM counts, whoever's it is: the invariant this refusal keeps is
    // the catalogue's, not one tenant's. Which of them get NAMED is another
    // question — a public image somebody else booted from must not turn its
    // owner's delete into a listing of another tenant's VMs.
    let holders: Vec<&Vm> = vms
        .iter()
        .filter(|v| base_images(&v.spec.vm).contains(&name))
        .collect();
    if !holders.is_empty() {
        let visible: Vec<String> = holders
            .iter()
            .filter(|v| {
                who.allows(Scope::of(v.spec.tenant.as_deref()), Verb::Read)
                    .is_ok()
            })
            .map(|v| v.metadata.name.clone())
            .collect();
        let detail = match visible.len() {
            0 => format!("{} vm(s), none of them yours", holders.len()),
            n if n == holders.len() => visible.join(", "),
            n => format!(
                "{} (and {} more, not yours)",
                visible.join(", "),
                holders.len() - n
            ),
        };
        return Err(conflict(format!("image {name} is still used by: {detail}")));
    }

    st.store.delete::<Image>(&name).await?;
    Ok(Json(json!({ "deleted": name })))
}

// --- tenants ---------------------------------------------------------------

/// The tenants, each with what it is holding right now.
///
/// The usage is computed here and never stored, for the reason a candidate's
/// free capacity is: both halves are objects this server already has, and a
/// stored copy would be a number that can be wrong — here in the direction
/// that lets a tenant past its own ceiling.
///
/// Computed at the SERVER and not in the CLI, and that is a scoping decision
/// rather than a convenience: `list_vms` filters to a member's own tenant, so
/// a client-side aggregation would show that member every other tenant using
/// nothing.
async fn list_tenants(State(st): State<ApiState>) -> Result<Json<serde_json::Value>, ApiError> {
    let mut items = st.store.list::<Tenant>().await?;
    let vms = st.store.list::<Vm>().await?;
    for tenant in &mut items {
        tenant.status.used = quota::Usage::of(&tenant.metadata.name, &vms, None).reported();
    }
    Ok(Json(
        json!({ "apiVersion": API_VERSION, "kind": "TenantList", "items": items }),
    ))
}

/// Creating a tenant allocates its network.
///
/// The VNI is server-set and a client's is ignored, exactly as `uid` is —
/// and for a stronger reason than uid has. A uid a client could choose would
/// collide with somebody's object; a VNI a client could choose would put two
/// tenants on one broadcast domain, which is not a collision anybody would
/// see from an object at all. The allocation is a compare-and-swap on a
/// counter in the store (`controller_api::vni`), so two API servers creating
/// a tenant in the same moment hand out two numbers.
///
/// Allocated BEFORE the create and not rolled back if the create then fails:
/// the cost of a leaked VNI is one number out of sixteen million, and the
/// cost of the other order — a tenant object that exists with no network —
/// is a tenant whose VMs quietly land on the default bridge.
async fn create_tenant(
    State(st): State<ApiState>,
    Json(body): Json<Tenant>,
) -> Result<(StatusCode, Json<Tenant>), ApiError> {
    check_envelope(&body)?;
    if body.metadata.name.is_empty() {
        return Err(invalid("metadata.name must be set"));
    }
    if body.spec.vni.is_some() {
        return Err(invalid(
            "spec.vni is server-owned; the cloud allocates one per tenant and never twice",
        ));
    }
    let vni = vni::allocate(&st.store, st.vni_base).await?;
    let mut tenant = Tenant::declare(&body.metadata.name, body.spec);
    tenant.spec.vni = Some(vni);
    tenant.metadata.labels = body.metadata.labels;
    let created = st.store.create(&tenant).await?;
    info!(tenant = %created.metadata.name, vni, "tenant created");
    Ok((StatusCode::CREATED, Json(created)))
}

async fn get_tenant(
    State(st): State<ApiState>,
    Path(name): Path<String>,
) -> Result<Json<Tenant>, ApiError> {
    let mut tenant: Tenant = st.store.get(&name).await?;
    let vms = st.store.list::<Vm>().await?;
    tenant.status.used = quota::Usage::of(&name, &vms, None).reported();
    Ok(Json(tenant))
}

async fn update_tenant(
    State(st): State<ApiState>,
    Path(name): Path<String>,
    Json(mut body): Json<Tenant>,
) -> Result<Json<Tenant>, ApiError> {
    if body.metadata.name != name {
        return Err(invalid("metadata.name does not match the path"));
    }
    let current: Tenant = st.store.get(&name).await?;
    keep_server_owned(&mut body.metadata, &current.metadata);
    // `spec.quota` is the operator's and travels through untouched. Who may
    // write it is not decided here and does not have to be: `tenants` is not
    // among the resources a member may write (auth::TENANT_SCOPED), so a
    // member raising its own ceiling never reaches this handler.
    // Immutable, and not merely server-owned: every node that has ever built
    // a bridge for this tenant built it for THIS number, and a tenant that
    // changed VNI would leave its running VMs on the old overlay while new
    // ones went to a different one. Silently kept rather than refused, the
    // same way the cluster binding is — a client that round-trips the object
    // must not have to strip fields it did not write.
    body.spec.vni = current.spec.vni;
    body.status = current.status;
    Ok(Json(st.store.update(&body).await?))
}

/// Everything that would be left ownerless by deleting `tenant`, said in one
/// sentence — or nothing, and then the tenant may go.
///
/// Four kinds of thing name a tenant, not two, and all four have to be gone.
/// Users and VMs are the obvious pair. The other two are the network:
/// a FloatingIp or a RoutedSubnet left behind names an owner that no longer
/// exists AND goes on holding its address space against everybody else, because
/// `floating::occupied` and the gap scan count objects and not tenants. Nothing
/// releases such a reservation afterwards — the API deletes it by name, and
/// nobody is left who knows the name.
///
/// Pure, and taking the four lists rather than the store, so the rule is one
/// readable thing instead of four repetitions inside a handler.
fn tenant_still_holds(
    tenant: &str,
    users: &[User],
    vms: &[Vm],
    ips: &[FloatingIp],
    subnets: &[RoutedSubnet],
) -> Option<String> {
    let sentence = |what: &str, names: Vec<String>| -> Option<String> {
        (!names.is_empty())
            .then(|| format!("tenant {tenant} still has {what}: {}", names.join(", ")))
    };
    sentence(
        "users",
        users
            .iter()
            .filter(|u| u.spec.tenant == tenant)
            .map(|u| u.metadata.name.clone())
            .collect(),
    )
    .or_else(|| {
        sentence(
            "vms",
            vms.iter()
                .filter(|v| v.spec.tenant.as_deref() == Some(tenant))
                .map(|v| v.metadata.name.clone())
                .collect(),
        )
    })
    .or_else(|| {
        sentence(
            "floating addresses",
            ips.iter()
                .filter(|ip| ip.spec.tenant == tenant)
                .map(|ip| ip.spec.address.clone())
                .collect(),
        )
    })
    .or_else(|| {
        sentence(
            "routed subnets",
            subnets
                .iter()
                .filter(|s| s.spec.tenant == tenant)
                .map(|s| s.spec.cidr.clone())
                .collect(),
        )
    })
}

/// A hard delete — a tenant owns nothing yet — but only once nobody is in it
/// and nothing of it is left. The same rule and the same reason as an image
/// with a VM on it: the invariant "everything that names a tenant names one
/// that exists" is worth exactly as much as the refusal that keeps it true.
async fn delete_tenant(
    State(st): State<ApiState>,
    Path(name): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let _: Tenant = st.store.get(&name).await?;

    let users = st.store.list::<User>().await?;
    // `list` drops what it cannot decode, and a dropped user is a membership
    // not seen. Refusing to answer beats answering "nobody is in it" from a
    // list that is not all of them.
    if users.len() != st.store.count::<User>().await? {
        return Err(conflict(
            "cannot tell whether anybody is still in this tenant (some user objects did not \
             decode); refusing to delete",
        ));
    }

    // And nothing of the tenant's is still running. The same rule and the
    // same reason one more time: deleting the tenant would take its VNI out
    // of the directory while the overlay it names is still carrying frames,
    // and the next tenant to be given that number would join them.
    let vms = st.store.list::<Vm>().await?;
    if vms.len() != st.store.count::<Vm>().await? {
        return Err(conflict(
            "cannot tell whether this tenant still has vms (some vm objects did not decode); \
             refusing to delete",
        ));
    }

    // The network half, through the readers that carry the same guard of their
    // own: a partial list here would authorise a delete that strands somebody
    // else's address space.
    let ips = floating::all_reservations(&st.store).await?;
    let subnets = floating::all_subnets(&st.store).await?;

    if let Some(why) = tenant_still_holds(&name, &users, &vms, &ips, &subnets) {
        return Err(conflict(why));
    }
    st.store.delete::<Tenant>(&name).await?;
    Ok(Json(json!({ "deleted": name })))
}

// --- floating pools, reservations, routed subnets ---------------------------
//
// Three resources and one rule that runs through all of them: what EXISTS is
// an administrator's decision, and taking one address out of what exists is
// self-service inside a quota. The middleware already enforces the verb half
// of that (`floatingips` is tenant-scoped and writable by a member, the other
// two are not), so what is left here is the object half and the arithmetic.
//
// Nothing in this section routes a packet. A reservation is a statement about
// ownership; the node turns it into an nftables rule and, with `[network.bgp]`,
// into a /32 announcement. How the address gets from the outside world to a
// host is the environment's business — a static route towards the nodes, or
// the BGP session Part C opens.

/// A member sees its own tenant's reservations. Same filter and same reason as
/// `list_vms`: the addresses somebody holds are an inventory.
async fn list_floating_ips(
    State(st): State<ApiState>,
    caller: Caller,
    role: CallerRole,
    tenant: CallerTenant,
) -> Result<Json<serde_json::Value>, ApiError> {
    let who = Grant::new(caller, role, tenant);
    let mut items = st.store.list::<FloatingIp>().await?;
    if let Some(mine) = who.confined_to() {
        items.retain(|ip| ip.spec.tenant == mine);
    }
    Ok(Json(
        json!({ "apiVersion": API_VERSION, "kind": "FloatingIpList", "items": items }),
    ))
}

/// Reserve an address.
///
/// The object's name is the address and the server sets it, which is why the
/// request body carries no useful `metadata.name`: an address a client could
/// name into existence is an address two clients could name into existence.
/// The explicit wish travels in `spec.address` instead, and is either granted
/// or refused with the reason — never quietly replaced by another address,
/// because a caller who asked for `203.0.113.7` asked for the one their DNS
/// already points at.
async fn create_floating_ip(
    State(st): State<ApiState>,
    caller: Caller,
    role: CallerRole,
    tenant: CallerTenant,
    Json(body): Json<FloatingIp>,
) -> Result<(StatusCode, Json<FloatingIp>), ApiError> {
    check_envelope(&body)?;
    let who = Grant::new(caller, role, tenant);

    let owner = who
        .tenant_for_create(Some(body.spec.tenant.clone()))
        .ok_or_else(|| invalid("spec.tenant must name a tenant"))?;
    who.allows(Scope::of(Some(owner.as_str())), Verb::Write)?;
    check_tenant(&st, &owner).await?;

    // An address may be asked for by either name, because both are the same
    // string on the object that comes back.
    let wanted = match first_non_empty([body.spec.address.as_str(), body.metadata.name.as_str()]) {
        Some(raw) => Some(
            raw.parse::<std::net::Ipv4Addr>()
                .map_err(|_| invalid(format!("{raw:?} is not an ipv4 address")))?,
        ),
        None => None,
    };

    // A VM named here has to be one this tenant has. The check is at the edge
    // for the same reason `base_image` is: an assignment to a VM that is not
    // theirs would be an address whose frames no node ever lets through, and
    // finding that out from a tcpdump is nobody's idea of an error message.
    if let Some(vm) = body.spec.vm.as_deref().filter(|v| !v.is_empty()) {
        check_vm_of_tenant(&st, vm, &owner).await?;
    }

    let pools = floating::all_pools(&st.store).await?;
    let pool = floating::pick_pool(&pools, Some(body.spec.pool.as_str()))?;
    let created = floating::allocate(
        &st.store,
        pool,
        &owner,
        wanted,
        body.spec.vm.filter(|v| !v.is_empty()),
    )
    .await?;
    info!(address = %created.spec.address, tenant = %owner, pool = %pool.metadata.name,
          vm = ?created.spec.vm, "floating address reserved");
    Ok((StatusCode::CREATED, Json(created)))
}

async fn get_floating_ip(
    State(st): State<ApiState>,
    Path(name): Path<String>,
    caller: Caller,
    role: CallerRole,
    tenant: CallerTenant,
) -> Result<Json<FloatingIp>, ApiError> {
    let ip: FloatingIp = st.store.get(&name).await?;
    Grant::new(caller, role, tenant)
        .allows(Scope::of(Some(ip.spec.tenant.as_str())), Verb::Read)?;
    Ok(Json(ip))
}

/// Point the address at a VM, or take it off one. That is the whole of what
/// an update may do.
///
/// The tenant, the pool and the address are what the reservation IS, and every
/// one of them is server-owned for the same reason the VM's tenant is: an
/// address that changed tenants would be an address whose old owner's node is
/// still letting frames through for it, and one that changed pool would be an
/// address outside the range it was cut from.
///
/// The assignment reaches a node when the VM is CREATED there — the addresses
/// are written into the spec, and a node's spec is immutable once it has it.
/// So this changes the object now and the tap when the VM is next recreated;
/// stopping and starting it keeps the same tap and the same rules. Making a
/// re-home live is a documented nice-to-have and not this milestone's job; see
/// `floating::inject_nic_list`.
async fn update_floating_ip(
    State(st): State<ApiState>,
    Path(name): Path<String>,
    caller: Caller,
    role: CallerRole,
    tenant: CallerTenant,
    Json(mut body): Json<FloatingIp>,
) -> Result<Json<FloatingIp>, ApiError> {
    if body.metadata.name != name {
        return Err(invalid("metadata.name does not match the path"));
    }
    let current: FloatingIp = st.store.get(&name).await?;
    let who = Grant::new(caller, role, tenant);
    who.allows(Scope::of(Some(current.spec.tenant.as_str())), Verb::Write)?;

    if let Some(vm) = body.spec.vm.as_deref().filter(|v| !v.is_empty()) {
        check_vm_of_tenant(&st, vm, &current.spec.tenant).await?;
    }
    keep_server_owned(&mut body.metadata, &current.metadata);
    body.spec.tenant = current.spec.tenant.clone();
    body.spec.pool = current.spec.pool.clone();
    body.spec.address = current.spec.address.clone();
    body.spec.vm = body.spec.vm.filter(|v| !v.is_empty());
    body.status = current.status;
    let updated = st.store.update(&body).await?;
    info!(address = %updated.spec.address, tenant = %updated.spec.tenant,
          vm = ?updated.spec.vm, "floating assignment changed");
    Ok(Json(updated))
}

/// Give the address back. A hard delete — a reservation owns nothing — and the
/// address is free for the next allocation immediately.
///
/// The VM that had it keeps sending from it until it is recreated, and that is
/// not a hole: the tap rules of a RUNNING vm were built from the assignment
/// that was true when it was created, and the next VM to be given this address
/// gets its own rules at its own create. Two VMs briefly permitted the same
/// address is the same window a DHCP lease has, and the way to close it is the
/// runtime re-home above.
async fn delete_floating_ip(
    State(st): State<ApiState>,
    Path(name): Path<String>,
    caller: Caller,
    role: CallerRole,
    tenant: CallerTenant,
) -> Result<Json<serde_json::Value>, ApiError> {
    let current: FloatingIp = st.store.get(&name).await?;
    Grant::new(caller, role, tenant)
        .allows(Scope::of(Some(current.spec.tenant.as_str())), Verb::Write)?;
    st.store.delete::<FloatingIp>(&name).await?;
    info!(address = %name, tenant = %current.spec.tenant, "floating address released");
    Ok(Json(json!({ "deleted": name })))
}

/// The pools, with one thing hidden: a member sees its own quota and not
/// everybody else's.
///
/// Redaction rather than refusal, because a member has to be able to see what
/// they may take — which pool is the default, how big it is, and how many
/// addresses they are allowed out of it. What another tenant was granted is
/// none of their business, and the map is the only field on the object that
/// names other tenants at all.
fn redact_quota(pool: &mut FloatingPool, mine: &str) {
    pool.spec.quota.retain(|tenant, _| tenant == mine);
}

async fn list_floating_pools(
    State(st): State<ApiState>,
    caller: Caller,
    role: CallerRole,
    tenant: CallerTenant,
) -> Result<Json<serde_json::Value>, ApiError> {
    let who = Grant::new(caller, role, tenant);
    let mut items = st.store.list::<FloatingPool>().await?;
    if let Some(mine) = who.confined_to() {
        let mine = mine.to_string();
        for pool in &mut items {
            redact_quota(pool, &mine);
        }
    }
    Ok(Json(
        json!({ "apiVersion": API_VERSION, "kind": "FloatingPoolList", "items": items }),
    ))
}

async fn get_floating_pool(
    State(st): State<ApiState>,
    Path(name): Path<String>,
    caller: Caller,
    role: CallerRole,
    tenant: CallerTenant,
) -> Result<Json<FloatingPool>, ApiError> {
    let mut pool: FloatingPool = st.store.get(&name).await?;
    if let Some(mine) = Grant::new(caller, role, tenant).confined_to() {
        redact_quota(&mut pool, mine);
    }
    Ok(Json(pool))
}

/// Everything a pool has to be true about before it is written: its ranges
/// parse, at most one pool is default, and it collides with nothing.
///
/// `except` is the pool being updated, which must not be found to overlap
/// itself.
async fn check_pool(
    st: &ApiState,
    pool: &FloatingPool,
    except: Option<&str>,
) -> Result<(), ApiError> {
    if pool.spec.cidrs.is_empty() {
        return Err(invalid("spec.cidrs must name at least one range"));
    }
    let ranges =
        common::net::Ipv4Ranges::parse(&pool.spec.cidrs).map_err(|e| invalid(e.to_string()))?;

    let others: Vec<FloatingPool> = floating::all_pools(&st.store)
        .await?
        .into_iter()
        .filter(|p| Some(p.metadata.name.as_str()) != except)
        .collect();
    if pool.spec.default
        && let Some(other) = others.iter().find(|p| p.spec.default)
    {
        return Err(conflict(format!(
            "floating pool {} is already the default; exactly one may be",
            other.metadata.name
        )));
    }

    // A pool that overlapped another one would make "which pool is this
    // address from" a question about ordering, and a pool that overlapped a
    // routed subnet would put its addresses inside somebody's allowlist.
    let subnets = floating::all_subnets(&st.store).await?;
    let taken = floating::occupied(&others, &subnets, None);
    for range in ranges.ranges() {
        floating::check_free(range, &taken)?;
    }
    Ok(())
}

// --- claiming address space, and the race the store cannot arbitrate --------
//
// `check_pool` and `create_routed_subnet` both read the store, decide, and
// then write — and between the read and the write a second request can do the
// whole of the same thing. One resource over, `floating::allocate` has no such
// window, and the reason is worth naming: there the object's NAME is the
// address, so two allocators racing for one gap write the same key and etcd's
// own create is the compare-and-swap. Here the name is whatever an admin
// called the pool or the subnet, so two claims on one range are two writes to
// two different keys and both of them succeed. The store cannot arbitrate what
// it cannot see as a collision.
//
// The cleanest fix would be to give the range a key of its own — a reservation
// object whose name IS the canonical CIDR, exactly the trick the floating side
// plays — so that etcd arbitrates this the way it arbitrates an address. That
// needs a new resource in `controller-api` and is not built here.
//
// What is built here instead: repeat the check once the object IS in the
// store, where a concurrent claim is finally visible, and have the loser take
// itself back. The tie is broken on the one total order both sides agree about
// without talking to each other — etcd's revision.

/// One thing already in the store that a claim collides with: what to call it
/// in the refusal, and the revision of the write that put it there.
struct Collision {
    what: String,
    revision: String,
}

/// Whose post-write scan this is, so that it does not find itself. A pool and
/// a subnet may carry the same name, so which resource it is has to travel
/// with the name.
#[derive(Clone, Copy)]
enum Claimant<'a> {
    Pool(&'a str),
    Subnet(&'a str),
}

/// Did the write that produced `mine` land after the one that produced
/// `theirs`?
///
/// `resourceVersion` is the etcd mod_revision, and on an object that was just
/// created it is the revision of the create itself — a strict total order over
/// the writes of one etcd, agreed on by every replica without any of them
/// asking the others.
///
/// A revision that will not parse is not an order, and then the answer is
/// "yes". Two claimants that both take themselves back cost a retry and an
/// honest refusal; two that both keep theirs cost an overlap that nothing
/// afterwards can explain or repair.
fn arrived_after(mine: &str, theirs: &str) -> bool {
    match (mine.parse::<i64>(), theirs.parse::<i64>()) {
        (Ok(mine), Ok(theirs)) => mine > theirs,
        _ => true,
    }
}

/// The collision this claim has to yield to, if there is one.
///
/// Both sides of a race run this same comparison against each other, so
/// exactly one of them yields and the survivor is the claim that reached etcd
/// first. A collision with something that arrived AFTER us is not ours to act
/// on: that writer is running this same function right now and will take
/// itself back.
fn lost_to<'a>(mine: &str, hits: &'a [Collision]) -> Option<&'a Collision> {
    hits.iter().find(|c| arrived_after(mine, &c.revision))
}

/// Everything in the store these ranges overlap, skipping the claimant's own
/// object, each with the revision of the write that put it there.
///
/// `floating::occupied` answers the same question and throws the revision
/// away, and the revision is precisely what the arbitration needs.
async fn collisions(
    st: &ApiState,
    ranges: &[common::net::Ipv4Range],
    mine: Claimant<'_>,
) -> Result<Vec<Collision>, ApiError> {
    let hits = |r: &common::net::Ipv4Range| ranges.iter().any(|c| r.overlaps(c));
    let mut out = Vec::new();
    for pool in floating::all_pools(&st.store).await? {
        if matches!(mine, Claimant::Pool(n) if n == pool.metadata.name) {
            continue;
        }
        if pool
            .spec
            .cidrs
            .iter()
            .filter_map(|entry| entry.parse::<common::net::Ipv4Range>().ok())
            .any(|r| hits(&r))
        {
            out.push(Collision {
                what: format!("floating pool {}", pool.metadata.name),
                revision: pool.metadata.resource_version.clone(),
            });
        }
    }
    for subnet in floating::all_subnets(&st.store).await? {
        if matches!(mine, Claimant::Subnet(n) if n == subnet.metadata.name) {
            continue;
        }
        if subnet
            .spec
            .cidr
            .parse::<common::net::Ipv4Range>()
            .is_ok_and(|r| hits(&r))
        {
            out.push(Collision {
                what: format!(
                    "routed subnet {} (tenant {})",
                    subnet.metadata.name, subnet.spec.tenant
                ),
                revision: subnet.metadata.resource_version.clone(),
            });
        }
    }
    Ok(out)
}

/// Undo a create that turned out to have lost its race. The object is the only
/// thing that was written, so deleting it is the whole rollback.
///
/// A failure here is an ERROR: what stays behind is a pool or a subnet lying
/// on top of another one, and no pass, retry or reconnect ever clears it —
/// only a person does.
async fn take_back<T: Resource>(st: &ApiState, name: &str, kind: &str) {
    if let Err(e) = st.store.delete::<T>(name).await {
        error!(name, kind, error = %format!("{e:#}"),
               "could not take back an object that lost its claim; it now overlaps another \
                one and has to be deleted by hand");
    }
}

/// How many lost races a subnet cut accepts before it says so. A liveness
/// bound and not a correctness one, the same one `floating::allocate` sets for
/// the same reason: every round is a block somebody else took first.
const MAX_CLAIM_ROUNDS: usize = 8;

/// The claims a pool that is already in the store turns out to have lost.
///
/// The same three questions `check_pool` asked before the write, asked once
/// more now that a concurrent create is visible: the default mark, and the
/// ranges. Two pools posted at the same moment both read a store with no
/// default in it and both wrote one — which is not a hand-edited etcd, it is
/// two administrators and one second, and `floating::pick_pool` then refuses
/// every allocation on this cloud until somebody deletes one by hand.
async fn pool_lost_claim(st: &ApiState, pool: &FloatingPool) -> Result<Option<String>, ApiError> {
    let mine = pool.metadata.resource_version.as_str();

    if pool.spec.default {
        let rivals: Vec<Collision> = floating::all_pools(&st.store)
            .await?
            .into_iter()
            .filter(|p| p.spec.default && p.metadata.name != pool.metadata.name)
            .map(|p| Collision {
                what: format!("floating pool {}", p.metadata.name),
                revision: p.metadata.resource_version,
            })
            .collect();
        if let Some(won) = lost_to(mine, &rivals) {
            return Ok(Some(format!(
                "{} was marked default at the same moment; exactly one may be",
                won.what
            )));
        }
    }

    let ranges = common::net::Ipv4Ranges::parse(&pool.spec.cidrs)
        .map_err(|e| invalid(e.to_string()))?
        .ranges()
        .to_vec();
    let hits = collisions(st, &ranges, Claimant::Pool(&pool.metadata.name)).await?;
    Ok(lost_to(mine, &hits).map(|won| {
        format!(
            "{} was claimed at the same moment and overlaps this pool ({})",
            won.what,
            pool.spec.cidrs.join(", ")
        )
    }))
}

async fn create_floating_pool(
    State(st): State<ApiState>,
    Json(body): Json<FloatingPool>,
) -> Result<(StatusCode, Json<FloatingPool>), ApiError> {
    check_envelope(&body)?;
    if body.metadata.name.is_empty() {
        return Err(invalid("metadata.name must be set"));
    }
    let mut pool = FloatingPool::declare(&body.metadata.name, body.spec);
    pool.metadata.labels = body.metadata.labels;
    check_pool(&st, &pool, None).await?;
    let created = st.store.create(&pool).await?;

    // And now the same questions again, from inside the store. No retry: an
    // administrator named these ranges and this default mark outright, so
    // there is nothing for the server to pick differently on a second round.
    if let Some(why) = pool_lost_claim(&st, &created).await? {
        take_back::<FloatingPool>(&st, &created.metadata.name, "floating pool").await;
        return Err(conflict(why));
    }

    info!(pool = %created.metadata.name, cidrs = %created.spec.cidrs.join(","),
          public = created.spec.public, default = created.spec.default, "floating pool created");
    Ok((StatusCode::CREATED, Json(created)))
}

/// Ranges, quotas, the default mark and the description all move. What does
/// not move is any address somebody already holds: a pool cannot be narrowed
/// out from under a live reservation, because the reservation would then name
/// an address the pool no longer contains and no allocator could ever explain
/// where it came from.
async fn update_floating_pool(
    State(st): State<ApiState>,
    Path(name): Path<String>,
    Json(mut body): Json<FloatingPool>,
) -> Result<Json<FloatingPool>, ApiError> {
    if body.metadata.name != name {
        return Err(invalid("metadata.name does not match the path"));
    }
    let current: FloatingPool = st.store.get(&name).await?;
    keep_server_owned(&mut body.metadata, &current.metadata);
    body.status = current.status;
    check_pool(&st, &body, Some(&name)).await?;

    let ranges =
        common::net::Ipv4Ranges::parse(&body.spec.cidrs).map_err(|e| invalid(e.to_string()))?;
    let held: Vec<String> = floating::all_reservations(&st.store)
        .await?
        .into_iter()
        .filter(|ip| ip.spec.pool == name)
        .filter(|ip| !ip.spec.address.parse().is_ok_and(|a| ranges.contains(a)))
        .map(|ip| ip.spec.address)
        .collect();
    if !held.is_empty() {
        return Err(conflict(format!(
            "these addresses are reserved out of pool {name} and would fall outside it: {}",
            held.join(", ")
        )));
    }
    Ok(Json(st.store.update(&body).await?))
}

/// A pool with reservations in it stays. The same rule and the same reason as
/// a tenant with users: the invariant "every reservation came out of a pool
/// that exists" is worth exactly what the refusal that keeps it true is worth.
async fn delete_floating_pool(
    State(st): State<ApiState>,
    Path(name): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let _: FloatingPool = st.store.get(&name).await?;
    let held: Vec<String> = floating::all_reservations(&st.store)
        .await?
        .into_iter()
        .filter(|ip| ip.spec.pool == name)
        .map(|ip| ip.spec.address)
        .collect();
    if !held.is_empty() {
        return Err(conflict(format!(
            "floating pool {name} still has reservations: {}",
            held.join(", ")
        )));
    }
    st.store.delete::<FloatingPool>(&name).await?;
    Ok(Json(json!({ "deleted": name })))
}

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
fn redact_storage_quota(pool: &mut StoragePool, mine: &str) {
    pool.spec.quota.retain(|tenant, _| tenant == mine);
}

async fn list_storage_pools(
    State(st): State<ApiState>,
    caller: Caller,
    role: CallerRole,
    tenant: CallerTenant,
) -> Result<Json<serde_json::Value>, ApiError> {
    let who = Grant::new(caller, role, tenant);
    let mut items = st.store.list::<StoragePool>().await?;
    if let Some(mine) = who.confined_to() {
        for pool in &mut items {
            redact_storage_quota(pool, mine);
        }
    }
    Ok(Json(
        json!({ "apiVersion": API_VERSION, "kind": "StoragePoolList", "items": items }),
    ))
}

async fn get_storage_pool(
    State(st): State<ApiState>,
    Path(name): Path<String>,
    caller: Caller,
    role: CallerRole,
    tenant: CallerTenant,
) -> Result<Json<StoragePool>, ApiError> {
    let mut pool: StoragePool = st.store.get(&name).await?;
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
async fn check_storage_pool(
    st: &ApiState,
    pool: &StoragePool,
    updating: Option<&str>,
) -> Result<(), ApiError> {
    if pool.spec.driver.is_empty() {
        return Err(invalid(
            "spec.driver must name a storage backend, e.g. \"lvm-thin\"",
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

async fn create_storage_pool(
    State(st): State<ApiState>,
    Json(body): Json<StoragePool>,
) -> Result<(StatusCode, Json<StoragePool>), ApiError> {
    check_envelope(&body)?;
    if body.metadata.name.is_empty() {
        return Err(invalid("metadata.name must be set"));
    }
    let mut pool = StoragePool::declare(&body.metadata.name, body.spec);
    pool.metadata.labels = body.metadata.labels;
    check_storage_pool(&st, &pool, None).await?;
    let created = st.store.create(&pool).await?;

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
async fn update_storage_pool(
    State(st): State<ApiState>,
    Path(name): Path<String>,
    Json(mut body): Json<StoragePool>,
) -> Result<Json<StoragePool>, ApiError> {
    if body.metadata.name != name {
        return Err(invalid("metadata.name does not match the path"));
    }
    let current: StoragePool = st.store.get(&name).await?;
    keep_server_owned(&mut body.metadata, &current.metadata);
    body.status = current.status.clone();
    if body.spec.driver != current.spec.driver {
        return Err(conflict(format!(
            "storage pool {name} is a {:?} pool and cannot become a {:?} one; its volumes are \
             on the backend it names",
            current.spec.driver, body.spec.driver
        )));
    }
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
    Ok(Json(st.store.update(&body).await?))
}

/// A pool with volumes in it stays. The same rule and the same reason as a
/// floating pool with reservations: the invariant "every volume came out of a
/// pool that exists" is worth exactly what the refusal that keeps it true is
/// worth.
async fn delete_storage_pool(
    State(st): State<ApiState>,
    Path(name): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
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
    Ok(Json(json!({ "deleted": name })))
}

/// The pool a volume belongs to: the one it named, or the one marked default.
///
/// The mirror of `floating::pick_pool`, refusal wording included. "No pool" is
/// the state a cloud is in before an administrator has declared any storage at
/// all, and the useful answer to a member asking for a disk on such a cloud is
/// what the administrator has to do, not `404`.
fn pick_storage_pool<'a>(
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
             `meister cloud storagepool create`",
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
async fn all_volumes(st: &ApiState) -> Result<Vec<Volume>, ApiError> {
    let volumes = st.store.list::<Volume>().await?;
    if volumes.len() != st.store.count::<Volume>().await? {
        return Err(conflict(
            "some volume objects did not decode, so how much storage is held cannot be \
             established; refusing rather than handing out room twice",
        ));
    }
    Ok(volumes)
}

async fn list_volumes(
    State(st): State<ApiState>,
    caller: Caller,
    role: CallerRole,
    tenant: CallerTenant,
) -> Result<Json<serde_json::Value>, ApiError> {
    let who = Grant::new(caller, role, tenant);
    let mut items = st.store.list::<Volume>().await?;
    if let Some(mine) = who.confined_to() {
        items.retain(|v| v.spec.tenant == mine);
    }
    Ok(Json(
        json!({ "apiVersion": API_VERSION, "kind": "VolumeList", "items": items }),
    ))
}

async fn get_volume(
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
async fn create_volume(
    State(st): State<ApiState>,
    caller: Caller,
    role: CallerRole,
    tenant: CallerTenant,
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
    if let Some(image) = body.spec.base_image.as_deref().filter(|i| !i.is_empty()) {
        check_base_image(&st.store, image).await?;
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
    let created = st
        .store
        .create(&new_volume(&body.metadata.name, spec))
        .await?;

    // The backend name is derived from the uid, which only exists once the
    // object does — so it is written on the way back out rather than on the
    // way in. Derived and not allocated: a provision whose handle is lost has
    // to find its volume rather than make a second one.
    let named = st
        .store
        .mutate::<Volume, _>(&created.metadata.name, |v| {
            v.status.backend = backend_name(&v.metadata.uid);
        })
        .await?;

    info!(volume = %named.metadata.name, tenant = %owner, pool = %named.spec.pool,
          size_gib = named.spec.size_gib, backend = %named.status.backend,
          "volume reserved");
    Ok((StatusCode::CREATED, Json(named)))
}

/// What a client may never write on a volume.
///
/// `check_owned_nic_fields` one object over, and the same argument: every one
/// of these is the control plane's answer about where the DATA is, and a
/// client that could set them could point its own object at somebody else's
/// bytes — `status.backend` most directly of all, since that string is what a
/// node hands its driver.
fn check_owned_volume_status(volume: &Volume) -> Result<(), ApiError> {
    let owned = [
        ("status.backend", !volume.status.backend.is_empty()),
        ("status.node", volume.status.node.is_some()),
        ("status.attachedTo", volume.status.attached_to.is_some()),
        (
            "status.phase",
            volume.status.phase != VolumePhase::default(),
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
async fn update_volume(
    State(st): State<ApiState>,
    Path(name): Path<String>,
    caller: Caller,
    role: CallerRole,
    tenant: CallerTenant,
    Json(mut body): Json<Volume>,
) -> Result<Json<Volume>, ApiError> {
    if body.metadata.name != name {
        return Err(invalid("metadata.name does not match the path"));
    }
    let current: Volume = st.store.get(&name).await?;
    let who = Grant::new(caller, role, tenant);
    who.allows(Scope::of(Some(current.spec.tenant.as_str())), Verb::Write)?;

    if body.spec.size_gib != current.spec.size_gib {
        return Err(conflict(format!(
            "volume {name} is {} GiB; growing a volume is a live filesystem operation and is \
             not supported yet",
            current.spec.size_gib
        )));
    }
    keep_server_owned(&mut body.metadata, &current.metadata);
    body.spec.tenant = current.spec.tenant.clone();
    body.spec.pool = current.spec.pool.clone();
    body.spec.mode = current.spec.mode;
    body.spec.access_mode = current.spec.access_mode;
    body.spec.base_image = current.spec.base_image.clone();
    body.status = current.status.clone();
    Ok(Json(st.store.update(&body).await?))
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
async fn delete_volume(
    State(st): State<ApiState>,
    Path(name): Path<String>,
    caller: Caller,
    role: CallerRole,
    tenant: CallerTenant,
) -> Result<Json<serde_json::Value>, ApiError> {
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
            v.status.phase = VolumePhase::Releasing;
        })
        .await?;

    match &held_by {
        Some(vm) => info!(volume = %name, tenant = %released.spec.tenant, vm = %vm,
                          "volume marked for release; it is still attached and keeps its data"),
        None => info!(volume = %name, tenant = %released.spec.tenant,
                      "volume marked for release"),
    }
    Ok(Json(json!({
        "releasing": name,
        "attachedTo": held_by,
        "message": match held_by {
            Some(vm) => format!(
                "volume {name} is attached to vm {vm}; its data stays until that vm lets go"
            ),
            None => format!("volume {name} will be deprovisioned by the node holding it"),
        }
    })))
}

/// A member sees its own tenant's subnets. Read-only for them by the verb
/// rule; whether a tenant gets a routed subnet at all is an admin's decision,
/// because it is a piece of the operator's own address space.
async fn list_routed_subnets(
    State(st): State<ApiState>,
    caller: Caller,
    role: CallerRole,
    tenant: CallerTenant,
) -> Result<Json<serde_json::Value>, ApiError> {
    let who = Grant::new(caller, role, tenant);
    let mut items = st.store.list::<RoutedSubnet>().await?;
    if let Some(mine) = who.confined_to() {
        items.retain(|s| s.spec.tenant == mine);
    }
    Ok(Json(
        json!({ "apiVersion": API_VERSION, "kind": "RoutedSubnetList", "items": items }),
    ))
}

async fn get_routed_subnet(
    State(st): State<ApiState>,
    Path(name): Path<String>,
    caller: Caller,
    role: CallerRole,
    tenant: CallerTenant,
) -> Result<Json<RoutedSubnet>, ApiError> {
    let subnet: RoutedSubnet = st.store.get(&name).await?;
    Grant::new(caller, role, tenant)
        .allows(Scope::of(Some(subnet.spec.tenant.as_str())), Verb::Read)?;
    Ok(Json(subnet))
}

/// Which block this subnet gets, decided against the store as it reads right
/// now.
///
/// Two roads in, and both end at the same check. An admin names the CIDR —
/// which is what a lab with an address plan does — or leaves it empty and gets
/// the first free aligned block out of the cloud's `routed_pools`. Either way
/// it may overlap nothing: not another tenant's subnet, and not a floating
/// pool, because a subnet containing a pool address would put that address on
/// its tenant's allowlist and punch a hole in the pool guard the size of the
/// subnet.
async fn choose_subnet_cidr(
    st: &ApiState,
    spec: &controller_api::RoutedSubnetSpec,
) -> Result<common::net::Ipv4Range, ApiError> {
    let pools = floating::all_pools(&st.store).await?;
    let subnets = floating::all_subnets(&st.store).await?;
    let taken = floating::occupied(&pools, &subnets, None);

    if spec.cidr.is_empty() {
        let supers = common::net::Ipv4Ranges::parse(&st.routed_pools)
            .map_err(|e| invalid(format!("routed_pools in the cloud config: {e}")))?;
        if supers.is_empty() {
            return Err(invalid(
                "this cloud has no routed_pools configured, so a subnet cannot be cut; \
                 name one with --cidr, or configure routed_pools",
            ));
        }
        let prefix = spec
            .prefix_len
            .unwrap_or(controller_api::DEFAULT_ROUTED_PREFIX_LEN);
        floating::cut_subnet(&supers, prefix, &taken).ok_or_else(|| {
            conflict(format!(
                "no free /{prefix} left in routed_pools ({})",
                st.routed_pools.join(", ")
            ))
        })
    } else {
        let wanted: common::net::Ipv4Range = spec
            .cidr
            .parse()
            .map_err(|e: common::net::RangeError| invalid(e.to_string()))?;
        floating::check_free(&wanted, &taken)?;
        Ok(wanted)
    }
}

/// Give a tenant a real subnet.
///
/// The block is chosen against the store, written, and then checked AGAINST
/// THE STORE AGAIN — see the section head above `arrived_after`. The object's
/// name is an admin's word and not the CIDR, so etcd's create arbitrates
/// nothing here, and without the second look two POSTs a millisecond apart
/// would both be handed the same free block and two tenants would be routed
/// the same addresses.
///
/// What the loser does depends on which road it came in by. A cut block has
/// somewhere else to go, so it takes its object back and scans again — the
/// same retry `floating::allocate` runs for the same reason. A named CIDR has
/// nowhere else to go and is refused, which is what an admin who wrote an
/// address plan wants to hear.
async fn create_routed_subnet(
    State(st): State<ApiState>,
    Json(body): Json<RoutedSubnet>,
) -> Result<(StatusCode, Json<RoutedSubnet>), ApiError> {
    check_envelope(&body)?;
    if body.metadata.name.is_empty() {
        return Err(invalid("metadata.name must be set"));
    }
    check_tenant(&st, &body.spec.tenant).await?;
    let named = !body.spec.cidr.is_empty();

    for _ in 0..MAX_CLAIM_ROUNDS {
        let cidr = choose_subnet_cidr(&st, &body.spec).await?;
        let mut subnet = RoutedSubnet::declare(
            &body.metadata.name,
            controller_api::RoutedSubnetSpec {
                // The stored form is the canonical one, so two admins who wrote
                // `10.7.1.0/24` and `10.7.1.7/24` end up with the same object.
                cidr: cidr.to_cidr().unwrap_or_else(|| cidr.to_string()),
                ..body.spec.clone()
            },
        );
        subnet.metadata.labels = body.metadata.labels.clone();
        let created = st.store.create(&subnet).await?;

        let name = created.metadata.name.clone();
        let hits = collisions(&st, &[cidr], Claimant::Subnet(&name)).await?;
        let Some(won) = lost_to(&created.metadata.resource_version, &hits) else {
            info!(subnet = %name, tenant = %created.spec.tenant,
                  cidr = %created.spec.cidr, "routed subnet created");
            return Ok((StatusCode::CREATED, Json(created)));
        };

        // Degraded and self-healing on the cut road, so WARN: the object is
        // gone again and the next round takes the next free block.
        warn!(subnet = %name, cidr = %created.spec.cidr, lost_to = %won.what,
              "lost the claim on this block, taking the subnet back");
        let overlap = format!("{} overlaps {}", created.spec.cidr, won.what);
        take_back::<RoutedSubnet>(&st, &name, "routed subnet").await;
        if named {
            return Err(conflict(overlap));
        }
    }
    Err(conflict(format!(
        "lost {MAX_CLAIM_ROUNDS} races for a free block in routed_pools ({}); retries exhausted",
        st.routed_pools.join(", ")
    )))
}

/// The description moves. The tenant and the CIDR do not: both are what the
/// subnet IS, and both are already inside the allowlist of every tap of that
/// tenant's running VMs. Silently kept rather than refused, the same way a
/// tenant's VNI is — a client that round-trips the object must not have to
/// strip fields it did not write.
async fn update_routed_subnet(
    State(st): State<ApiState>,
    Path(name): Path<String>,
    Json(mut body): Json<RoutedSubnet>,
) -> Result<Json<RoutedSubnet>, ApiError> {
    if body.metadata.name != name {
        return Err(invalid("metadata.name does not match the path"));
    }
    let current: RoutedSubnet = st.store.get(&name).await?;
    keep_server_owned(&mut body.metadata, &current.metadata);
    body.spec.tenant = current.spec.tenant;
    body.spec.cidr = current.spec.cidr;
    body.spec.prefix_len = current.spec.prefix_len;
    body.status = current.status;
    Ok(Json(st.store.update(&body).await?))
}

/// A hard delete, and no refusal for running VMs — deliberately. Taking a
/// subnet away NARROWS what its tenant's taps may send from, and it takes
/// effect when each of its VMs is next recreated. Nothing is left dangling and
/// nothing keeps working that should not.
async fn delete_routed_subnet(
    State(st): State<ApiState>,
    Path(name): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let current: RoutedSubnet = st.store.get(&name).await?;
    st.store.delete::<RoutedSubnet>(&name).await?;
    info!(subnet = %name, tenant = %current.spec.tenant, cidr = %current.spec.cidr,
          "routed subnet deleted");
    Ok(Json(json!({ "deleted": name })))
}

/// The first of these strings that is not empty.
fn first_non_empty<const N: usize>(candidates: [&str; N]) -> Option<&str> {
    candidates.into_iter().find(|s| !s.is_empty())
}

/// That VM exists and belongs to this tenant.
async fn check_vm_of_tenant(st: &ApiState, vm: &str, tenant: &str) -> Result<(), ApiError> {
    match st.store.get::<Vm>(vm).await {
        Ok(found) if found.spec.tenant.as_deref() == Some(tenant) => Ok(()),
        Ok(_) => Err(invalid(format!(
            "vm {vm:?} does not belong to tenant {tenant}"
        ))),
        Err(StoreError::NotFound(_)) => Err(invalid(format!("no vm {vm:?} in this cloud"))),
        Err(e) => Err(e.into()),
    }
}

// --- users -----------------------------------------------------------------

async fn list_users(State(st): State<ApiState>) -> Result<Json<serde_json::Value>, ApiError> {
    let items = st.store.list::<User>().await?;
    Ok(Json(
        json!({ "apiVersion": API_VERSION, "kind": "UserList", "items": items }),
    ))
}

async fn create_user(
    State(st): State<ApiState>,
    Json(body): Json<User>,
) -> Result<(StatusCode, Json<User>), ApiError> {
    check_envelope(&body)?;
    if body.metadata.name.is_empty() {
        return Err(invalid("metadata.name must be set"));
    }
    check_user_name(&body.metadata.name)?;
    check_tenant(&st, &body.spec.tenant).await?;

    let mut user = User::declare(&body.metadata.name, body.spec);
    user.metadata.labels = body.metadata.labels;
    // status is the record of certificates this server issued; a client that
    // could write it could invent a credential history.
    let created = st.store.create(&user).await?;
    info!(user = %created.metadata.name, tenant = %created.spec.tenant,
          role = created.spec.role.as_str(), "user created");
    Ok((StatusCode::CREATED, Json(created)))
}

async fn get_user(
    State(st): State<ApiState>,
    Path(name): Path<String>,
) -> Result<Json<User>, ApiError> {
    Ok(Json(st.store.get(&name).await?))
}

async fn update_user(
    State(st): State<ApiState>,
    Path(name): Path<String>,
    Json(mut body): Json<User>,
) -> Result<Json<User>, ApiError> {
    if body.metadata.name != name {
        return Err(invalid("metadata.name does not match the path"));
    }
    check_user_name(&name)?;
    check_tenant(&st, &body.spec.tenant).await?;
    let current: User = st.store.get(&name).await?;
    keep_server_owned(&mut body.metadata, &current.metadata);
    // The issued-certificate record is this server's, not the client's.
    body.status = current.status;
    let updated = st.store.update(&body).await?;
    info!(user = %name, role = updated.spec.role.as_str(), "user updated");
    Ok(Json(updated))
}

/// Deleting a user does NOT revoke the certificates they hold — nothing here
/// has a revocation list. What it does is take the name out of the directory,
/// and the directory is what the guard consults on every request: from the
/// next call onwards that certificate authenticates to somebody the cloud
/// does not know, and somebody the cloud does not know may do nothing.
///
/// That is the whole revocation story of this milestone, and it is worth
/// saying out loud rather than implying: it works at the cloud, and the
/// cluster tier keeps honouring the certificate until it expires.
async fn delete_user(
    State(st): State<ApiState>,
    Path(name): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let user: User = st.store.get(&name).await?;
    let live = user.status.live(Utc::now()).count();
    st.store.delete::<User>(&name).await?;
    info!(user = %name, live_certificates = live, "user deleted");
    Ok(Json(json!({ "deleted": name, "liveCertificates": live })))
}

// --- certificate signing requests ------------------------------------------

/// What a PUT to `.../approval` says. Deliberately not the whole object: the
/// only thing an approver decides is yes or no and why, and a handler that
/// took a full object would have to work out which of its fields it was
/// allowed to believe.
#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct Approval {
    approved: bool,
    #[serde(default)]
    reason: Option<String>,
    #[serde(default)]
    message: Option<String>,
}

async fn list_csrs(State(st): State<ApiState>) -> Result<Json<serde_json::Value>, ApiError> {
    let items = st.store.list::<CertificateSigningRequest>().await?;
    Ok(Json(json!({
        "apiVersion": API_VERSION,
        "kind": "CertificateSigningRequestList",
        "items": items,
    })))
}

/// Accept a request for a certificate.
///
/// `metadata.name` may be empty, and normally is: certificate requests happen
/// to the same person repeatedly, so a name the client picked would collide
/// with its own last one. The server derives `<username>-<8 of the uid>`,
/// which is unique because the uid is.
///
/// Three checks, and each of them exists because of something a client could
/// otherwise get away with:
///
///   - the request has to parse and its signature has to check out, or the
///     store would fill with documents the signer will choke on later;
///   - the name in the request has to be the name being asked for, so that
///     what the client signed is what it asked for;
///   - a caller who is not an admin may only ask for its own name. This is
///     the one that matters: without it, `auto_approve` plus any member's
///     certificate is a path to the administrator's.
async fn create_csr(
    State(st): State<ApiState>,
    caller: Caller,
    CallerRole(role): CallerRole,
    Json(body): Json<CertificateSigningRequest>,
) -> Result<(StatusCode, Json<CertificateSigningRequest>), ApiError> {
    check_envelope(&body)?;
    if body.spec.username.is_empty() {
        return Err(invalid("spec.username must say who the certificate is for"));
    }
    if body.spec.signer_name != SIGNER_USER_CLIENT {
        return Err(invalid(format!(
            "unknown signer {:?}; this control plane runs {SIGNER_USER_CLIENT}",
            body.spec.signer_name
        )));
    }
    if !caller.may_act_for(role, &body.spec.username) {
        return Err(forbidden(format!(
            "{} may only request a certificate for itself, not for {:?}",
            caller.name(),
            body.spec.username
        )));
    }

    // Parses, and the key inside it signed it — otherwise anybody could
    // submit somebody else's public key and have the CA vouch for a key they
    // do not hold. A request made out to one name and submitted under another
    // is either a mistake or an attempt; the answer is the same either way.
    let made_out_to = pki::requested_name(&body.spec.request)
        .map_err(|e| invalid(format!("spec.request: {e:#}")))?;
    if made_out_to != body.spec.username {
        return Err(invalid(format!(
            "the request is made out to {made_out_to:?} but asks for {:?}; sign the request with \
             the name you are asking for",
            body.spec.username
        )));
    }

    // The name in the directory is the name the certificate will carry.
    let user: User = match st.store.get(&body.spec.username).await {
        Ok(u) => u,
        Err(StoreError::NotFound(_)) => {
            return Err(invalid(format!(
                "no user {:?}; create it first (meister cloud user create)",
                body.spec.username
            )));
        }
        Err(e) => return Err(e.into()),
    };

    let mut csr = CertificateSigningRequest::declare(
        &body.metadata.name,
        CsrSpec {
            request: body.spec.request,
            username: body.spec.username,
            signer_name: body.spec.signer_name,
        },
    );
    if csr.metadata.name.is_empty() {
        // Requests are things that happen repeatedly to the same person, so
        // the default name carries who and which — the uid is already unique
        // and already on the object.
        csr.metadata.name = format!("{}-{}", csr.spec.username, &csr.metadata.uid[..8]);
    }
    csr.metadata.labels = body.metadata.labels;

    if st.signing.as_ref().is_some_and(|s| s.auto_approve) {
        let by = format!("{} (auto_approve)", caller.name());
        approve_and_sign(&st, &mut csr, &user, &by).await?;
    }

    let created = st.store.create(&csr).await?;
    info!(csr = %created.metadata.name, user = %created.spec.username,
          phase = created.status.phase(), "certificate request accepted");
    Ok((StatusCode::CREATED, Json(created)))
}

async fn get_csr(
    State(st): State<ApiState>,
    Path(name): Path<String>,
) -> Result<Json<CertificateSigningRequest>, ApiError> {
    Ok(Json(st.store.get(&name).await?))
}

async fn delete_csr(
    State(st): State<ApiState>,
    Path(name): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let _: CertificateSigningRequest = st.store.get(&name).await?;
    st.store.delete::<CertificateSigningRequest>(&name).await?;
    Ok(Json(json!({ "deleted": name })))
}

/// Approve or deny, and — on approval — sign, because this process is both
/// the approver and the signer.
///
/// Kubernetes splits those two roles across two components and that split is
/// worth something there: the approver decides policy and the signer holds
/// the key, and they can be operated by different people. Here one process
/// holds the key and serves the API, so splitting them would be ceremony
/// around a boundary that does not exist. The condition still records who
/// approved, which is the part of the split that carries the meaning.
async fn approve_csr(
    State(st): State<ApiState>,
    Path(name): Path<String>,
    caller: Caller,
    Json(decision): Json<Approval>,
) -> Result<Json<CertificateSigningRequest>, ApiError> {
    let mut csr: CertificateSigningRequest = st.store.get(&name).await?;
    if csr.status.denied() {
        return Err(conflict(format!("{name} was denied; a denial is final")));
    }
    if csr.status.certificate.is_some() {
        // Idempotent: the certificate is already there and re-signing would
        // hand out a second credential for one request.
        return Ok(Json(csr));
    }

    if !decision.approved {
        csr.status.set(CsrCondition {
            kind: CsrConditionType::Denied,
            reason: decision.reason.unwrap_or_else(|| "Denied".into()),
            message: decision.message.unwrap_or_default(),
            last_update_time: Utc::now(),
            by: caller.name().to_string(),
        });
        info!(csr = %name, by = caller.name(), "certificate request denied");
        return Ok(Json(st.store.update(&csr).await?));
    }

    let user: User = match st.store.get(&csr.spec.username).await {
        Ok(u) => u,
        Err(StoreError::NotFound(_)) => {
            return Err(invalid(format!(
                "the user {:?} this request was made for no longer exists",
                csr.spec.username
            )));
        }
        Err(e) => return Err(e.into()),
    };
    approve_and_sign(&st, &mut csr, &user, caller.name()).await?;
    Ok(Json(st.store.update(&csr).await?))
}

/// Stamp the approval, sign, and record the fingerprint on the user.
///
/// The subject comes from the directory and nowhere else: the common name is
/// the user object's name and the one group is the role it carries. Nothing a
/// client wrote reaches the certificate.
async fn approve_and_sign(
    st: &ApiState,
    csr: &mut CertificateSigningRequest,
    user: &User,
    by: &str,
) -> Result<(), ApiError> {
    let Some(signing) = &st.signing else {
        return Err(ApiError::new(
            StatusCode::NOT_IMPLEMENTED,
            "NoSigner",
            "this cloud-controller has no CA configured (ca_cert/ca_key); it can record \
             certificate requests but not sign them",
        ));
    };

    let now = Utc::now();
    let subject = pki::ca::Subject {
        common_name: user.metadata.name.clone(),
        organization: Some(user.spec.role.group().to_string()),
    };
    let issued = signing
        .ca
        .sign_csr(
            &csr.spec.request,
            &subject,
            Duration::days(signing.ttl_days),
            now,
        )
        .map_err(|e| {
            ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Internal",
                format!("signing failed: {e:#}"),
            )
        })?;

    csr.status.set(CsrCondition {
        kind: CsrConditionType::Approved,
        reason: "Approved".into(),
        message: String::new(),
        last_update_time: now,
        by: by.to_string(),
    });
    csr.status.certificate = Some(issued.pem);

    let record = IssuedCertificate {
        fingerprint: issued.info.fingerprint.clone(),
        issued_at: now,
        not_after: issued.info.not_after,
        serial: issued.info.serial.clone(),
        request: csr.metadata.name.clone(),
    };
    // Expired entries go at the same moment: the list is there to say what
    // credentials exist, and one that has died is history rather than a
    // credential. Without this the object grows for ever.
    st.store
        .mutate::<User, _>(&user.metadata.name, |u| {
            u.status.certificates.retain(|c| c.not_after > now);
            u.status.certificates.push(record.clone());
        })
        .await?;

    info!(csr = %csr.metadata.name, user = %user.metadata.name, by,
          role = user.spec.role.as_str(), fingerprint = %issued.info.fingerprint,
          not_after = %issued.info.not_after.to_rfc3339(), "certificate issued");
    Ok(())
}

// --- shared checks ---------------------------------------------------------

/// `system:` is the stack's own namespace and is not for people.
///
/// Not cosmetic. `Identity::is_system` reads the prefix off the certificate's
/// common name, and the signer writes the user object's name into that common
/// name — so a user called `system:anything` would be issued a certificate
/// that skips the directory lookup and every authorization check with it.
/// Creating one takes an admin, which makes this a way to keep access rather
/// than to gain it; that is exactly the kind of door worth not leaving open.
/// Kubernetes reserves the same prefix for the same reason.
fn check_user_name(name: &str) -> Result<(), ApiError> {
    if name.starts_with(controller_api::auth::SYSTEM_PREFIX) {
        return Err(invalid(format!(
            "{:?} is reserved: names beginning {:?} are the stack's own identities (nodes, \
             controllers) and are not issued to people",
            name,
            controller_api::auth::SYSTEM_PREFIX
        )));
    }
    Ok(())
}

/// The fields a client does not get to write, whatever its body said.
fn keep_server_owned(body: &mut controller_api::Metadata, current: &controller_api::Metadata) {
    body.uid = current.uid.clone();
    body.creation_timestamp = current.creation_timestamp;
    body.deletion_timestamp = current.deletion_timestamp;
    body.finalizers = current.finalizers.clone();
}

async fn check_tenant(st: &ApiState, tenant: &str) -> Result<(), ApiError> {
    if tenant.is_empty() {
        return Err(invalid("spec.tenant must name a tenant"));
    }
    match st.store.get::<Tenant>(tenant).await {
        Ok(_) => Ok(()),
        Err(StoreError::NotFound(_)) => Err(invalid(format!(
            "no tenant {tenant:?}; create it first (meister cloud tenant create)"
        ))),
        Err(e) => Err(e.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Where a base image comes from is the catalogue's answer, and a
    /// reference to a `Volume` object is refused outright — not ignored.
    ///
    /// The second half is the one worth a test. The object exists, the attach
    /// path does not, and the agent's volume spec takes unknown fields
    /// quietly: a VM naming a volume would be accepted and would boot on a
    /// blank disk instead of the tenant's data. When resolution lands, this
    /// refusal becomes the tenancy check and the test changes with it.
    #[test]
    fn a_client_may_not_name_the_volume_fields_the_cloud_owns() {
        for field in ["base_image_url", "base_image_sha256"] {
            let spec = json!({ "volumes": [{}, { field: "x" }] });
            let msg = format!("{:?}", check_owned_volume_fields(&spec).unwrap_err());
            assert!(msg.contains(field), "{msg}");
            assert!(msg.contains("volumes[1]"), "and which volume: {msg}");
        }

        let spec = json!({ "volumes": [{ "volume": "acme-data" }] });
        let msg = format!("{:?}", check_owned_volume_fields(&spec).unwrap_err());
        assert!(msg.contains("volumes[0].volume"), "{msg}");
        assert!(msg.contains("not built yet"), "{msg}");
        assert!(
            msg.contains("blank disk"),
            "it says what would go wrong: {msg}"
        );

        // And an ordinary declared disk is untouched.
        check_owned_volume_fields(&json!({
            "volumes": [{ "size_bytes": 1, "base_image": "debian.raw" }]
        }))
        .expect("nothing control-plane-owned here");
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
            ("status.phase", |v| v.status.phase = VolumePhase::Ready),
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
        // and everything else about the pool is still readable: a member has
        // to be able to see which pool is the default and what backs it.
        assert!(p.spec.default);
        assert_eq!(p.spec.driver, "lvm-thin");
    }

    /// The most important detail in the storage brief, as a test.
    ///
    /// Derived from the uid and never allocated: a provision that succeeds
    /// and whose handle is then lost has to FIND its volume on the next try,
    /// not make a second one nobody will ever know about. And derived from
    /// the uid rather than the name, because people reuse names — two volumes
    /// called `data` in one tenant, a year apart, must not be one volume on
    /// the backend.
    #[test]
    fn a_backend_name_is_derived_from_the_uid_and_is_stable() {
        let uid = "3f2504e0-4f89-11d3-9a0c-0305e82c3301";
        assert_eq!(backend_name(uid), backend_name(uid), "a pure function");
        assert!(backend_name(uid).contains(uid), "and it carries the uid");

        let recreated = "9c5b94b1-35ad-49bb-b118-8e8fc24abf80";
        assert_ne!(
            backend_name(uid),
            backend_name(recreated),
            "the same name a year later is a different volume"
        );
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
        assert_eq!(v.status.phase, VolumePhase::Pending);
        assert!(v.status.attached_to.is_none());
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

    /// The prefix a certificate is read for. A user wearing it would be
    /// issued one that skips the directory and every check behind it.
    #[test]
    fn the_system_prefix_is_not_for_people() {
        assert!(check_user_name("alice").is_ok());
        assert!(
            check_user_name("system-admin").is_ok(),
            "the hyphen is not the prefix"
        );
        assert!(check_user_name("system:masters").is_err());
        assert!(check_user_name("system:node:manacor").is_err());
    }

    /// The catalogue is only worth a 422 if its names are the names the node
    /// will look up. A path that disagrees with the object name is a
    /// reference that would resolve here and fail down there.
    #[test]
    fn an_image_name_has_to_be_the_file_the_node_will_look_for() {
        assert!(check_image_name("nixos.raw", "/mnt/nfs/images/nixos.raw").is_ok());
        assert!(check_image_name("nixos.raw", "nixos.raw").is_ok());
        assert!(check_image_name("ubuntu", "/mnt/nfs/images/ubuntu-24.04.raw").is_err());
        assert!(check_image_name("a/b", "/mnt/a/b").is_err());
        assert!(check_image_name("", "x").is_err());
        assert!(check_image_name("..", "/mnt/..").is_err());
    }

    // --- claiming address space ---------------------------------------------

    fn collided(what: &str, revision: &str) -> Collision {
        Collision {
            what: what.to_string(),
            revision: revision.to_string(),
        }
    }

    /// The race the store cannot arbitrate, settled after both writes landed.
    ///
    /// Two POSTs a millisecond apart both read a store without the other in it
    /// and both created their object, because the key is a name an admin chose
    /// and not the range. So the verdict is reached afterwards, and it has to
    /// come out the same on both sides without them talking: the later etcd
    /// revision is the one that takes itself back. Two keepers would be two
    /// tenants routed the same addresses; two yielders only cost a retry,
    /// which is why an unreadable revision yields.
    #[test]
    fn of_two_claims_on_one_range_exactly_one_takes_itself_back() {
        let first = collided("routed subnet a (tenant one)", "100");
        let second = collided("routed subnet b (tenant two)", "101");

        // Each side sees only the other, and only the later write yields.
        let keeps = lost_to(&first.revision, std::slice::from_ref(&second)).is_none();
        let yields = lost_to(&second.revision, std::slice::from_ref(&first)).is_some();
        assert!(keeps && yields, "exactly one of the two may survive");

        // The refusal names what was lost to, because "conflict" alone tells
        // an admin nothing about whose range it is now.
        let won = lost_to("101", std::slice::from_ref(&first)).expect("101 arrived second");
        assert_eq!(won.what, "routed subnet a (tenant one)");

        // Nothing in the way is not a loss.
        assert!(lost_to("101", &[]).is_none());

        // A revision that is not a number is not an order, and then the safe
        // half of the answer is to yield.
        assert!(arrived_after("", "100"));
        assert!(arrived_after("101", ""));
        assert!(!arrived_after("100", "101"));
    }

    /// The default mark is the same race with a different collision: two pools
    /// both marked default and neither of them able to see the other yet.
    /// `floating::pick_pool` reads that state as a hand-edited etcd and refuses
    /// every allocation on the cloud, so the second one must take itself back
    /// rather than be created.
    #[test]
    fn the_second_pool_to_claim_default_is_the_one_that_yields() {
        let standing = collided("floating pool lab", "40");
        assert!(lost_to("41", std::slice::from_ref(&standing)).is_some());
        assert!(lost_to("39", std::slice::from_ref(&standing)).is_none());
    }

    // --- deleting a tenant ---------------------------------------------------

    fn ip_of(tenant: &str, address: &str) -> FloatingIp {
        FloatingIp::declare(
            address,
            controller_api::resources::FloatingIpSpec {
                tenant: tenant.into(),
                pool: "lab".into(),
                address: address.into(),
                vm: None,
            },
        )
    }

    fn subnet_of(tenant: &str, cidr: &str) -> RoutedSubnet {
        RoutedSubnet::declare(
            "net",
            controller_api::RoutedSubnetSpec {
                tenant: tenant.into(),
                cidr: cidr.into(),
                ..controller_api::RoutedSubnetSpec::default()
            },
        )
    }

    /// A tenant may only go once it owns nothing, and it owns four kinds of
    /// thing. The two that used to be missed are the ones that hold address
    /// space: a reservation or a subnet left behind names an owner that does
    /// not exist any more AND goes on occupying its range for everybody else,
    /// with nobody left who could hand it back.
    #[test]
    fn a_tenant_still_holding_addresses_may_not_be_deleted() {
        let ips = vec![ip_of("acme", "10.255.0.7")];
        let subnets = vec![subnet_of("acme", "10.7.1.0/24")];

        let why = tenant_still_holds("acme", &[], &[], &ips, &[]).expect("the address is theirs");
        assert!(why.contains("floating addresses"), "{why}");
        assert!(why.contains("10.255.0.7"), "{why}");

        let why =
            tenant_still_holds("acme", &[], &[], &[], &subnets).expect("the subnet is theirs");
        assert!(why.contains("routed subnets"), "{why}");
        assert!(why.contains("10.7.1.0/24"), "{why}");

        // Somebody else's holdings are not this tenant's business, and a
        // tenant that holds nothing at all may go.
        assert!(tenant_still_holds("other", &[], &[], &ips, &subnets).is_none());
        assert!(tenant_still_holds("acme", &[], &[], &[], &[]).is_none());
    }

    /// The two checks that were already there keep their exact sentence, and
    /// they still come first: "still has users" is the more useful thing to
    /// read than "still has floating addresses" when both are true.
    #[test]
    fn users_and_vms_are_still_refused_in_the_same_words() {
        let user = User::declare(
            "ann",
            controller_api::resources::UserSpec {
                tenant: "acme".into(),
                role: Role::default(),
                description: String::new(),
            },
        );
        let vm = new_vm(
            "web",
            VmSpec {
                cluster_selector: Default::default(),
                node_selector: Default::default(),
                anti_affinity: Vec::new(),
                cluster_name: None,
                node_name: None,
                tenant: Some("acme".into()),
                run_strategy: controller_api::RunStrategy::Running,
                vm: json!({}),
            },
        );
        let ips = vec![ip_of("acme", "10.255.0.7")];

        let vms = std::slice::from_ref(&vm);
        let why = tenant_still_holds("acme", &[user], vms, &ips, &[]).unwrap();
        assert_eq!(why, "tenant acme still has users: ann");
        let why = tenant_still_holds("acme", &[], vms, &ips, &[]).unwrap();
        assert_eq!(why, "tenant acme still has vms: web");
    }
}
