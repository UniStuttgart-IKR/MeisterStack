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
pub(super) async fn choose_subnet_cidr(
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

/// The prefix length of a block, read off its own canonical spelling.
///
/// `Ipv4Range` is a first/last pair and says nothing about prefixes; the one
/// place it does is `to_cidr`, which answers `None` for a range that is not an
/// aligned block. So does this, and the caller then keeps whatever the client
/// asked for — an unaligned range is a range no prefix length describes, and
/// inventing one would be worse than the absent field this replaces.
fn prefix_of(range: &common::net::Ipv4Range) -> Option<u32> {
    range.to_cidr()?.rsplit_once('/')?.1.parse().ok()
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
        let created = match dry.preview(&subnet) {
            Some(preview) => preview,
            None => st.store.create(&subnet).await?,
        };

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
/// A subnet is an address range somebody was really given and the tap rules
/// are built from it. Editing one in place would move a tenant's allowlist
/// under the VMs already running behind it.
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

/// A hard delete, and no refusal for running VMs — deliberately. Taking a
/// subnet away NARROWS what its tenant's taps may send from, and it takes
/// effect when each of its VMs is next recreated. Nothing is left dangling and
/// nothing keeps working that should not.
pub(super) async fn delete_routed_subnet(
    State(st): State<ApiState>,
    Path(name): Path<String>,
) -> Result<controller_api::Removed, ApiError> {
    let current: RoutedSubnet = st.store.get(&name).await?;
    st.store.delete::<RoutedSubnet>(&name).await?;
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
