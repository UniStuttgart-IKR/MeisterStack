// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! The `tenants` resource, and the VNI that comes with one.

use super::*;

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
pub(super) async fn list_tenants(
    State(st): State<ApiState>,
    axum::extract::Query(q): axum::extract::Query<controller_api::ListQuery>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let selector = controller_api::Selector::parse(q.label_selector.as_deref())?;
    let mut items = st.store.list::<Tenant>().await?;
    items.retain(|t| selector.selects(&t.metadata.labels));
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
pub(super) async fn create_tenant(
    State(st): State<ApiState>,
    dry: controller_api::DryRun,
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
    // A preview READS the counter instead of turning it: see `vni::peek`.
    // Showing somebody a tenant must not spend a number.
    let vni = match dry.requested() {
        true => vni::peek(&st.store, st.vni_base).await?,
        false => vni::allocate(&st.store, st.vni_base).await?,
    };
    let mut tenant = Tenant::declare(&body.metadata.name, body.spec);
    tenant.spec.vni = Some(vni);
    tenant.metadata.labels = body.metadata.labels;
    let created = match dry.preview(&tenant) {
        Some(preview) => preview,
        None => st.store.create(&tenant).await?,
    };
    info!(tenant = %created.metadata.name, vni, "tenant created");
    Ok((StatusCode::CREATED, Json(created)))
}

pub(super) async fn get_tenant(
    State(st): State<ApiState>,
    Path(name): Path<String>,
) -> Result<Json<Tenant>, ApiError> {
    let mut tenant: Tenant = st.store.get(&name).await?;
    let vms = st.store.list::<Vm>().await?;
    tenant.status.used = quota::Usage::of(&name, &vms, None).reported();
    Ok(Json(tenant))
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
/// The VNI is allocated once, at create, out of `vni_base` — an overlay
/// identifier a tenant could edit is two tenants on one segment.
pub(super) const TENANT_OWNED: &[Owned] = &[Owned::server_owned(
    "spec.vni",
    "is allocated by the server when the tenant is created",
)];

pub(super) async fn update_tenant(
    State(st): State<ApiState>,
    Path(name): Path<String>,
    dry: controller_api::DryRun,
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
    check_owned(&current, &body, TENANT_OWNED)?;
    body.status = current.status.clone();
    controller_api::carry_generation(&current, &mut body)?;
    match dry.preview(&body) {
        Some(preview) => Ok(Json(preview)),
        None => Ok(Json(st.store.update(&body).await?)),
    }
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
pub(super) fn tenant_still_holds(
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
pub(super) async fn delete_tenant(
    State(st): State<ApiState>,
    Path(name): Path<String>,
) -> Result<controller_api::Removed, ApiError> {
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
    Ok(controller_api::removed(
        Tenant::KIND,
        &name,
        controller_api::Removal::Gone,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- deleting a tenant ---------------------------------------------------

    fn ip_of(tenant: &str, address: &str) -> FloatingIp {
        FloatingIp::declare(
            address,
            controller_api::resources::FloatingIpSpec {
                internal_address: String::new(),
                router: String::new(),
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
                class: Default::default(),
                cluster_selector: Default::default(),
                node_selector: Default::default(),
                anti_affinity: Vec::new(),
                cluster_name: None,
                node_name: None,
                tenant: Some("acme".into()),
                run_strategy: controller_api::RunStrategy::Running,
                evacuation: Default::default(),
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
