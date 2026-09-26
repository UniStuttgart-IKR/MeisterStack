// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! The `tenants` resource, and the VNI that comes with one.

use super::*;

// --- tenants ---------------------------------------------------------------

/// List tenants with VM usage computed from server inventory. Server aggregation
/// avoids deriving totals from a caller’s tenant-filtered VM listing.
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

/// Allocate a server-owned VNI before storing the tenant. The counter CAS gives
/// concurrent creates distinct networks; failed creates may consume a VNI.
/// Dry-run reads the next candidate without advancing the counter.
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

/// The VNI is allocated once and cannot change while guests use its overlay.
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
    // Middleware restricts tenant quota edits to privileged callers.
    // The VNI is immutable: changing it would split existing and new guests across
    // different overlays. `check_owned` rejects such changes.
    check_owned(&current, &body, TENANT_OWNED)?;
    body.status = current.status.clone();
    controller_api::carry_generation(&current, &mut body)?;
    match dry.preview(&body) {
        Some(preview) => Ok(Json(preview)),
        None => Ok(Json(st.store.update(&body).await?)),
    }
}

/// Describe the first remaining user, VM, floating-address or routed-subnet owner.
/// This check does not cover volumes, snapshots, secrets or routers.
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

/// Delete after checking users, VMs and address reservations. These checks do not
/// cover every tenant-scoped resource or serialize concurrent child creation.
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
