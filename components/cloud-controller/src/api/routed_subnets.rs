// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! The `routedsubnets` resource.

use super::*;

/// A member sees its own tenant's subnets. Read-only for them by the verb
/// rule; whether a tenant gets a routed subnet at all is an admin's decision,
/// because it is a piece of the operator's own address space.
pub(super) async fn list_routed_subnets(
    State(st): State<ApiState>,
    caller: Caller,
    role: CallerRole,
    tenant: CallerTenant,
    axum::extract::Query(q): axum::extract::Query<controller_api::ListQuery>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let selector = controller_api::Selector::parse(q.label_selector.as_deref())?;
    let who = Grant::new(caller, role, tenant).listing(q.tenant.as_deref());
    let mut items = st.store.list::<RoutedSubnet>().await?;
    items.retain(|s| {
        who.keeps(Some(s.spec.tenant.as_str())) && selector.selects(&s.metadata.labels)
    });
    Ok(Json(
        json!({ "apiVersion": API_VERSION, "kind": "RoutedSubnetList", "items": items }),
    ))
}

pub(super) async fn get_routed_subnet(
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

/// Choose an explicit CIDR or the first free aligned block in `routed_pools`.
/// Reject overlap with routed subnets, floating pools and other tenants' networks.
/// Otherwise a tenant's source allowlist could include addresses it does not own.
pub(super) async fn choose_subnet_cidr(
    st: &ApiState,
    spec: &controller_api::RoutedSubnetSpec,
) -> Result<common::net::Ipv4Range, ApiError> {
    let pools = floating::all_pools(&st.store).await?;
    let subnets = floating::all_subnets(&st.store).await?;
    let mut taken = floating::occupied(&pools, &subnets, None);
    taken.extend(network_prefixes_taken(st, Some(&spec.tenant)).await?);

    if spec.cidr.is_empty() {
        let supers = routed_pools(st)?;
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

/// Return the prefix length only when the range is an aligned CIDR block.
fn prefix_of(range: &common::net::Ipv4Range) -> Option<u32> {
    range.to_cidr()?.rsplit_once('/')?.1.parse().ok()
}

/// Create a subnet and ask the overlap question again after the write, since
/// different object names do not arbitrate competing CIDR claims. The subnet is
/// taken back when it lost: to a pool or a subnet of an earlier revision, to
/// another tenant's network whatever the revisions say, or because the question
/// could not be answered. A block lost on the cut road is cut again elsewhere;
/// a named CIDR that lost, and a question without an answer, are refused.
pub(super) async fn create_routed_subnet(
    State(st): State<ApiState>,
    dry: controller_api::DryRun,
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
                // What the block was really cut with, and not what the client
                // asked for: on the named road a client asks for nothing at
                // all, and the field came back absent for ever (tofu). It is
                // documented as "kept beside the cidr so an admin can see
                // whether a /24 was a request or a coincidence" — which only
                // works if it is there.
                prefix_len: prefix_of(&cidr).or(body.spec.prefix_len),
                ..body.spec.clone()
            },
        );
        subnet.metadata.labels = body.metadata.labels.clone();
        #[cfg(test)]
        super::admission_tests::admission_gate(&subnet.metadata.name).await;
        let created = match dry.preview(&subnet) {
            Some(preview) => preview,
            None => st.store.create(&subnet).await?,
        };

        let lost = subnet_lost_claim(&st, &created, cidr).await;
        let cut_again = !named && matches!(lost, Ok(Some(_)));
        let name = created.metadata.name.as_str();
        match settle_claim(name, "routed subnet", lost, take_back(&st, &created)).await {
            Ok(()) => {
                info!(subnet = %name, tenant = %created.spec.tenant,
                      cidr = %created.spec.cidr, "routed subnet created");
                return Ok((StatusCode::CREATED, Json(created)));
            }
            // Degraded and self-healing on the cut road, so WARN: the block was
            // lost and the subnet is gone again (a take-back that failed answers
            // 500, not 409), and the next round takes the next free block.
            Err(lost) if cut_again && lost.status() == StatusCode::CONFLICT => {
                warn!(subnet = %name, cidr = %created.spec.cidr, why = %lost.message(),
                      "lost the claim on this block, took the subnet back");
            }
            Err(refused) => return Err(refused),
        }
    }
    Err(conflict(format!(
        "lost {MAX_CLAIM_ROUNDS} races for a free block in routed_pools ({}); retries exhausted",
        st.routed_pools.join(", ")
    )))
}

/// The claim a routed subnet that is already in the store on `cidr` turns out to have lost:
/// the overlap question asked again now that a concurrent write is visible, naming what won.
async fn subnet_lost_claim(
    st: &ApiState,
    subnet: &RoutedSubnet,
    cidr: common::net::Ipv4Range,
) -> Result<Option<String>, ApiError> {
    let claimant = Claimant::Subnet {
        name: &subnet.metadata.name,
        tenant: &subnet.spec.tenant,
    };
    let hits = collisions(st, &[cidr], claimant).await?;
    Ok(lost_to(&subnet.metadata.resource_version, &hits)
        .map(|won| format!("{} overlaps {}", subnet.spec.cidr, won.what)))
}

/// Tenant and CIDR cannot change after allocation; prefixLen records the chosen block.
pub(super) const ROUTED_SUBNET_OWNED: &[Owned] = &[
    Owned::immutable(
        "spec.cidr",
        "is immutable; delete the subnet and cut another",
    ),
    Owned::immutable(
        "spec.tenant",
        "is immutable; a subnet belongs to the tenant it was cut for",
    ),
    Owned::server_owned(
        "spec.prefixLen",
        "is what the cidr was cut with and is kept beside it",
    ),
];

pub(super) async fn update_routed_subnet(
    State(st): State<ApiState>,
    Path(name): Path<String>,
    dry: controller_api::DryRun,
    Json(mut body): Json<RoutedSubnet>,
) -> Result<Json<RoutedSubnet>, ApiError> {
    if body.metadata.name != name {
        return Err(invalid("metadata.name does not match the path"));
    }
    let current: RoutedSubnet = st.store.get(&name).await?;
    keep_server_owned(&mut body.metadata, &current.metadata);
    check_owned(&current, &body, ROUTED_SUBNET_OWNED)?;
    body.status = current.status.clone();
    controller_api::carry_generation(&current, &mut body)?;
    match dry.preview(&body) {
        Some(preview) => Ok(Json(preview)),
        None => Ok(Json(st.store.update(&body).await?)),
    }
}

/// Release the subnet immediately. Existing VM tap permissions persist until the
/// VM is recreated; this operation does not revoke them before the range is reused.
pub(super) async fn delete_routed_subnet(
    State(st): State<ApiState>,
    Path(name): Path<String>,
) -> Result<controller_api::Removed, ApiError> {
    let current: RoutedSubnet = st.store.get(&name).await?;
    // The revision that was judged, not whatever the name names by now. (IKR-B81)
    st.store
        .delete_if::<RoutedSubnet>(&name, &current.metadata.resource_version)
        .await?;
    info!(subnet = %name, tenant = %current.spec.tenant, cidr = %current.spec.cidr,
          "routed subnet deleted");
    Ok(controller_api::removed(
        RoutedSubnet::KIND,
        &name,
        controller_api::Removal::Gone,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `spec.prefixLen` is kept beside the cidr so an admin can see whether a
    /// /24 was a request or a coincidence — which only works if it is there.
    ///
    /// On the named road a client asks for no prefix at all, so the field
    /// came back absent for every subnet an address plan produced (tofu). It
    /// is filled from the block that was really cut, on both roads.
    #[test]
    fn a_cut_block_says_what_it_was_cut_with() {
        let block = |cidr: &str| -> common::net::Ipv4Range { cidr.parse().expect("a range") };
        assert_eq!(prefix_of(&block("10.7.1.0/24")), Some(24));
        assert_eq!(prefix_of(&block("10.7.0.0/16")), Some(16));
        assert_eq!(prefix_of(&block("192.0.2.7/32")), Some(32));
        // A range that is not an aligned block is a range no prefix length
        // describes, and inventing one would be worse than the absent field
        // this replaces.
        assert_eq!(prefix_of(&block("10.7.1.5-10.7.1.9")), None);
    }
}
