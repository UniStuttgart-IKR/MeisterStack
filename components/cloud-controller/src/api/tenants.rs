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
/// concurrent creates distinct networks; a create that fails after it, at the
/// store or because its network lost a claim written at the same moment, may
/// consume a VNI, while one refused for its own input does not.
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
    // The client's input is judged before the counter turns, so a create refused
    // for its prefixes spends no VNI. (RR5-7)
    let prefixes =
        checked_network_prefixes(&st, &body.metadata.name, &body.spec.network_prefixes, &[])
            .await?;
    // A preview READS the counter instead of turning it: see `vni::peek`.
    // Showing somebody a tenant must not spend a number.
    let vni = match dry.requested() {
        true => vni::peek(&st.store, st.vni_base).await?,
        false => vni::allocate(&st.store, st.vni_base).await?,
    };
    let mut tenant = Tenant::declare(&body.metadata.name, body.spec);
    tenant.spec.vni = Some(vni);
    tenant.spec.network_prefixes = prefixes;
    tenant.metadata.labels = body.metadata.labels;
    if let Some(preview) = dry.preview(&tenant) {
        return Ok((StatusCode::CREATED, Json(preview)));
    }
    #[cfg(test)]
    super::admission_tests::admission_gate(&tenant.metadata.name).await;
    let created = st.store.create(&tenant).await?;
    settle_network_claim(&st, &created, &[], take_back(&st, &created)).await?;
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
    body.spec.network_prefixes = checked_network_prefixes(
        &st,
        &name,
        &body.spec.network_prefixes,
        &current.spec.network_prefixes,
    )
    .await?;
    body.status = current.status.clone();
    controller_api::carry_generation(&current, &mut body)?;
    if let Some(preview) = dry.preview(&body) {
        return Ok(Json(preview));
    }
    #[cfg(test)]
    super::admission_tests::admission_gate(&name).await;
    let updated = st.store.update(&body).await?;
    // This handler asks once; a PATCH without a resourceVersion runs it again on
    // a 409 (`patch_with_retry`), and that round judges the tenant as it was put
    // back. A put back that failed answers `claim_not_taken_back`, which is not
    // run again. (NL6-3)
    settle_network_claim(
        &st,
        &updated,
        &current.spec.network_prefixes,
        put_back(&st, &current, &updated),
    )
    .await?;
    Ok(Json(updated))
}

/// The field a tenant's network prefixes are named by in a refusal.
const NETWORK_PREFIXES: &str = "spec.networkPrefixes";

/// Whether a write of `declared` over the `current` network prefixes is judged on them: when
/// it names some and they differ from what stands. An unchanged list is not judged again, so
/// an edit of the quota is not refused for a pool created since.
fn network_prefixes_judged(declared: &[String], current: &[String]) -> bool {
    !declared.is_empty() && declared != current
}

/// The network prefixes a write of `tenant` stores: `declared` in canonical form, checked
/// against what it may not overlap whenever it is judged (`network_prefixes_judged`).
async fn checked_network_prefixes(
    st: &ApiState,
    tenant: &str,
    declared: &[String],
    current: &[String],
) -> Result<Vec<String>, ApiError> {
    if !network_prefixes_judged(declared, current) {
        return Ok(declared.to_vec());
    }
    let taken = off_limits_to_network_prefixes(st, tenant).await?;
    canonical_network_prefixes(declared, &taken)
}

/// A tenant's network asked about again from inside the store after its write, as a pool or a
/// routed subnet asks after its own: one written at the same moment was not in the listing the
/// check before the write read. `undo` takes the write back when it lost (RR5-6). The create
/// and the update of a tenant take this one road, and only a write judged on its prefixes over
/// the `before` ones (`network_prefixes_judged`) is asked again. (NL6-2)
async fn settle_network_claim(
    st: &ApiState,
    written: &Tenant,
    before: &[String],
    undo: impl std::future::Future<Output = Result<(), ApiError>>,
) -> Result<(), ApiError> {
    if !network_prefixes_judged(&written.spec.network_prefixes, before) {
        return Ok(());
    }
    let lost = network_lost_claim(st, written).await;
    settle_claim(&written.metadata.name, "tenant", lost, undo).await
}

/// The claim a tenant's network that is already in the store turns out to have lost: what
/// `checked_network_prefixes` asked before the write, asked once more now that a pool or a
/// routed subnet written at the same moment is visible. The routed pools are configuration
/// and cannot race. A pool or a subnet that finds this network after its own write yields to
/// it whatever the revisions say (`Collision::tenant_network`); this side yields to one that
/// was written first. (RR5-6)
pub(super) async fn network_lost_claim(
    st: &ApiState,
    tenant: &Tenant,
) -> Result<Option<String>, ApiError> {
    let ranges = common::net::Ipv4Ranges::parse(&tenant.spec.network_prefixes)
        .map_err(|e| invalid_field(NETWORK_PREFIXES, e.to_string()))?
        .ranges()
        .to_vec();
    let hits = collisions(st, &ranges, Claimant::Network(&tenant.metadata.name)).await?;
    Ok(
        lost_to(&tenant.metadata.resource_version, &hits).map(|won| {
            format!(
                "{} was claimed at the same moment and overlaps this tenant's network ({})",
                won.what,
                tenant.spec.network_prefixes.join(", ")
            )
        }),
    )
}

/// What a tenant's network prefixes may not overlap, each with its name for the refusal:
/// every floating pool, every other tenant's routed subnet, and the routed pools subnets are
/// cut from. A network prefix goes onto the source allowlist of every tap of the tenant's VMs,
/// so an overlap would let its guests send from addresses that are somebody else's or may
/// become so. The tenant's own routed subnets are on that allowlist already.
async fn off_limits_to_network_prefixes(
    st: &ApiState,
    tenant: &str,
) -> Result<Vec<(String, common::net::Ipv4Range)>, ApiError> {
    let pools = floating::all_pools(&st.store).await?;
    let subnets = floating::all_subnets(&st.store).await?;
    Ok(controller_api::address_space::off_limits_to_tenant(
        tenant,
        &pools,
        &subnets,
        &routed_pools(st)?,
    ))
}

/// The routed pools from the cloud config, which subnets are cut from.
pub(super) fn routed_pools(st: &ApiState) -> Result<common::net::Ipv4Ranges, ApiError> {
    common::net::Ipv4Ranges::parse(&st.routed_pools)
        .map_err(|e| invalid(format!("routed_pools in the cloud config: {e}")))
}

/// Every tenant's network prefixes but those of `except`, each with its name for a refusal:
/// what a floating pool or a routed subnet may not overlap, for the reason the prefixes may
/// not overlap them. Read from a list that is all of them, since a tenant that did not decode
/// could hide the prefix a pool would land on; list and count come from one response, so a
/// tenant created or deleted in between neither refuses a pool for nothing nor hides one that
/// did not decode. (RR5-3)
pub(super) async fn network_prefixes_taken(
    st: &ApiState,
    except: Option<&str>,
) -> Result<Vec<(String, common::net::Ipv4Range)>, ApiError> {
    let (tenants, keys) = st.store.list_counted::<Tenant>().await?;
    if tenants.len() != keys {
        return Err(conflict(
            "cannot tell which prefixes the tenants' networks hold (some tenant objects did not \
             decode); refusing rather than overlapping one",
        ));
    }
    Ok(controller_api::address_space::tenant_networks(
        &tenants, except,
    ))
}

/// `declared` as CIDRs of their network address, sorted and each once, or why not: an entry
/// that is no IPv4 prefix, or one that overlaps something in `taken`.
fn canonical_network_prefixes(
    declared: &[String],
    taken: &[(String, common::net::Ipv4Range)],
) -> Result<Vec<String>, ApiError> {
    let mut prefixes = Vec::with_capacity(declared.len());
    for entry in declared {
        let range: common::net::Ipv4Range = entry
            .parse()
            .map_err(|e: common::net::RangeError| invalid_field(NETWORK_PREFIXES, e.to_string()))?;
        let cidr = range.to_cidr().ok_or_else(|| {
            invalid_field(
                NETWORK_PREFIXES,
                format!("{entry} is a run of addresses, not a prefix; name it as a CIDR"),
            )
        })?;
        floating::check_free(&range, taken)?;
        prefixes.push(cidr);
    }
    prefixes.sort();
    prefixes.dedup();
    Ok(prefixes)
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
    let current: Tenant = st.store.get(&name).await?;

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
    // The revision that was judged, not whatever the name names by now. (IKR-B81)
    st.store
        .delete_if::<Tenant>(&name, &current.metadata.resource_version)
        .await?;
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

    // --- a tenant's network prefixes (NL5-1) ---------------------------------

    fn taken(entries: &[(&str, &str)]) -> Vec<(String, common::net::Ipv4Range)> {
        entries
            .iter()
            .map(|(what, range)| (what.to_string(), range.parse().expect("a range")))
            .collect()
    }

    /// A prefix is stored as the CIDR of its network address, once, in order, whatever host
    /// address or order the administrator wrote it with.
    #[test]
    fn network_prefixes_are_stored_as_the_cidrs_of_their_networks() {
        let declared = ["10.30.0.1/24", "10.20.0.0/16", "10.30.0.0/24"].map(String::from);
        let stored = canonical_network_prefixes(&declared, &[]).expect("prefixes");
        assert_eq!(stored, ["10.20.0.0/16", "10.30.0.0/24"]);
    }

    /// A run of addresses that is no prefix, and what is no address at all, are refused by the
    /// field's name.
    #[test]
    fn a_network_prefix_must_be_a_prefix() {
        for entry in ["10.30.0.1-10.30.0.3", "10.30.0"] {
            let refused =
                canonical_network_prefixes(&[entry.to_string()], &[]).expect_err("not a prefix");
            assert_eq!(
                refused.field(),
                Some(NETWORK_PREFIXES),
                "{entry}: {}",
                refused.message()
            );
        }
    }

    /// A prefix that overlaps a floating pool, another tenant's routed subnet or the routed
    /// pools would let the tenant's guests send as somebody else, and is refused naming what it
    /// overlaps.
    #[test]
    fn a_network_prefix_may_not_overlap_what_is_somebody_elses() {
        let others = taken(&[
            ("floating pool lab", "10.255.0.0/16"),
            ("routed subnet theirs (tenant other)", "10.7.2.0/24"),
            ("the routed pools", "10.7.0.0/16"),
        ]);
        for (prefix, what) in [
            ("10.255.3.0/24", "floating pool lab"),
            ("10.7.2.128/25", "routed subnet theirs"),
            ("10.7.9.0/24", "the routed pools"),
            ("0.0.0.0/0", "floating pool lab"),
        ] {
            let refused =
                canonical_network_prefixes(&[prefix.to_string()], &others).expect_err("an overlap");
            assert_eq!(refused.status(), StatusCode::CONFLICT, "{prefix}");
            assert!(
                refused.message().contains(what),
                "{prefix}: {}",
                refused.message()
            );
        }
        assert_eq!(
            canonical_network_prefixes(&["10.30.0.0/24".to_string()], &others).expect("free"),
            ["10.30.0.0/24"]
        );
    }
}
