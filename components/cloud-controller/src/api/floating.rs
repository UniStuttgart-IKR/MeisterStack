// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Floating-address reservations and pool admission. Range claims use a post-write
//! collision check; this is separate from allocation of individual address keys.

use super::*;

// Administrators define address pools and routed subnets; tenants reserve
// floating addresses within their quotas. Middleware checks resource verbs;
// these handlers check ownership and allocation.
//
// These objects do not route packets themselves. Nodes install the rules and,
// when BGP is configured, announce addresses. The fabric must route traffic to
// those nodes.

/// A member sees its own tenant's reservations. Same filter and same reason as
/// `list_vms`: the addresses somebody holds are an inventory.
pub(super) async fn list_floating_ips(
    State(st): State<ApiState>,
    caller: Caller,
    role: CallerRole,
    tenant: CallerTenant,
    axum::extract::Query(q): axum::extract::Query<controller_api::ListQuery>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let selector = controller_api::Selector::parse(q.label_selector.as_deref())?;
    let who = Grant::new(caller, role, tenant).listing(q.tenant.as_deref());
    let mut items = st.store.list::<FloatingIp>().await?;
    items.retain(|ip| {
        who.keeps(Some(ip.spec.tenant.as_str())) && selector.selects(&ip.metadata.labels)
    });
    Ok(Json(
        json!({ "apiVersion": API_VERSION, "kind": "FloatingIpList", "items": items }),
    ))
}

/// Reserve the requested address, or allocate one when `spec.address` is empty.
/// The server names the object after its address so competing reservations
/// collide on the same store key. An explicit address is never substituted.
pub(super) async fn create_floating_ip(
    State(st): State<ApiState>,
    caller: Caller,
    role: CallerRole,
    tenant: CallerTenant,
    dry: controller_api::DryRun,
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
    check_router_binding(&st, &body.spec, &owner).await?;

    let pools = floating::all_pools(&st.store).await?;
    let pool = floating::pick_pool(&pools, Some(body.spec.pool.as_str()))?;
    let created = floating::allocate(
        &st.store,
        pool,
        &owner,
        wanted,
        floating::Pointing {
            vm: body.spec.vm.filter(|v| !v.is_empty()),
            router: body.spec.router.clone(),
            internal_address: body.spec.internal_address.clone(),
        },
        dry,
    )
    .await?;
    info!(address = %created.spec.address, tenant = %owner, pool = %pool.metadata.name,
          vm = ?created.spec.vm, "floating address reserved");
    Ok((StatusCode::CREATED, Json(created)))
}

/// Refuse a router binding that is not the tenant's own way out.
///
/// The router has to exist and be this tenant's, or the address would be
/// translated in somebody else's namespace; a missing and a foreign router
/// get the same answer, so the refusal names nobody else's router. The
/// inside end has to be a guest on that router's overlay
/// (`network::inside_address_refusal`). `nat_rules` checks both again when
/// it renders, for what was stored before this edge did.
async fn check_router_binding(
    st: &ApiState,
    spec: &controller_api::FloatingIpSpec,
    tenant: &str,
) -> Result<(), ApiError> {
    if spec.router.is_empty() {
        return Ok(());
    }
    let unknown = || {
        invalid_field(
            "spec.router",
            format!("no router {:?} in this tenant", spec.router),
        )
    };
    let router: controller_api::Router = match st.store.get(&spec.router).await {
        Ok(router) => router,
        Err(StoreError::NotFound(_)) => return Err(unknown()),
        Err(e) => return Err(e.into()),
    };
    if router.spec.tenant != tenant {
        return Err(unknown());
    }
    if spec.internal_address.is_empty() {
        return Ok(());
    }
    match controller_api::network::inside_address_refusal(&router, &spec.internal_address) {
        Some(why) => Err(invalid_field("spec.internalAddress", why)),
        None => Ok(()),
    }
}

pub(super) async fn get_floating_ip(
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

/// Address, pool and tenant identify the reservation and cannot change. VM/router
/// assignment is editable; existing VM tap permissions are refreshed on recreation,
/// not by this update or by a stop/start of the existing instance.
pub(super) const FLOATING_IP_OWNED: &[Owned] = &[
    Owned::immutable(
        "spec.address",
        "is the name of this reservation; release it and reserve another",
    ),
    Owned::immutable(
        "spec.pool",
        "is immutable; it is the quota this address was taken out of",
    ),
    Owned::immutable(
        "spec.tenant",
        "is immutable; release the address and reserve it as the other tenant",
    ),
];

pub(super) async fn update_floating_ip(
    State(st): State<ApiState>,
    Path(name): Path<String>,
    caller: Caller,
    role: CallerRole,
    tenant: CallerTenant,
    dry: controller_api::DryRun,
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
    check_router_binding(&st, &body.spec, &current.spec.tenant).await?;
    keep_server_owned(&mut body.metadata, &current.metadata);
    check_owned(&current, &body, FLOATING_IP_OWNED)?;
    body.spec.vm = body.spec.vm.filter(|v| !v.is_empty());
    body.status = current.status.clone();
    controller_api::carry_generation(&current, &mut body)?;
    let updated = match dry.preview(&body) {
        Some(preview) => preview,
        None => st.store.update(&body).await?,
    };
    info!(address = %updated.spec.address, tenant = %updated.spec.tenant,
          vm = ?updated.spec.vm, "floating assignment changed");
    Ok(Json(updated))
}

/// Release the reservation immediately. An existing VM retains its tap permissions
/// until recreation, so reuse can temporarily authorize the same address on two VMs.
pub(super) async fn delete_floating_ip(
    State(st): State<ApiState>,
    Path(name): Path<String>,
    caller: Caller,
    role: CallerRole,
    tenant: CallerTenant,
) -> Result<controller_api::Removed, ApiError> {
    let current: FloatingIp = st.store.get(&name).await?;
    Grant::new(caller, role, tenant)
        .allows(Scope::of(Some(current.spec.tenant.as_str())), Verb::Write)?;
    // The reservation that was judged, not whatever the address names by now:
    // released and reserved again by another tenant in between, it is theirs.
    // (IKR-B81)
    st.store
        .delete_if::<FloatingIp>(&name, &current.metadata.resource_version)
        .await?;
    info!(address = %name, tenant = %current.spec.tenant, "floating address released");
    Ok(controller_api::removed(
        FloatingIp::KIND,
        &name,
        controller_api::Removal::Gone,
    ))
}

/// The pools, with one thing hidden: a member sees its own quota and not
/// everybody else's.
///
/// Redaction rather than refusal, because a member has to be able to see what
/// they may take — which pool is the default, how big it is, and how many
/// addresses they are allowed out of it. What another tenant was granted is
/// none of their business, and the map is the only field on the object that
/// names other tenants at all.
pub(super) fn redact_quota(pool: &mut FloatingPool, mine: &str) {
    pool.spec.quota.retain(|tenant, _| tenant == mine);
}

pub(super) async fn list_floating_pools(
    State(st): State<ApiState>,
    caller: Caller,
    role: CallerRole,
    tenant: CallerTenant,
    axum::extract::Query(q): axum::extract::Query<controller_api::ListQuery>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let selector = controller_api::Selector::parse(q.label_selector.as_deref())?;
    // A pool is not a tenant's object, so there is nothing here for
    // `?tenant=` to narrow: what a confined caller gets is the same LIST with
    // somebody else's quota taken out of it. The label selector applies as it
    // does everywhere.
    let who = Grant::new(caller, role, tenant);
    let mut items = st.store.list::<FloatingPool>().await?;
    items.retain(|p| selector.selects(&p.metadata.labels));
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

pub(super) async fn get_floating_pool(
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
pub(super) async fn check_pool(
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
    // routed subnet or a tenant's network would put its addresses inside
    // somebody's allowlist.
    let subnets = floating::all_subnets(&st.store).await?;
    let mut taken = floating::occupied(&others, &subnets, None);
    taken.extend(network_prefixes_taken(st, None).await?);
    for range in ranges.ranges() {
        floating::check_free(range, &taken)?;
    }
    Ok(())
}

// Range claims use administrator-chosen names, so overlapping ranges can be
// created under different keys after concurrent checks. Every claim asks its
// question again after the write and takes itself back when it lost: among
// pools and routed subnets to the earlier etcd revision, and a pool or a
// subnet always to a tenant's network, whose revision dates its latest edit
// rather than its claim (`Collision::tenant_network`). A question that cannot
// be answered is a claim not known to have won, taken back the same way.
// Floating addresses instead use the address as their key, making store
// creation arbitrate the race.

/// One thing already in the store that a claim collides with: what to call it
/// in the refusal, and the revision of the write that put it there.
pub(super) struct Collision {
    /// `pub(super)` because the routed-subnet half of this race reads it to
    /// build its own sentence, and since the split that is a sibling module.
    pub(super) what: String,
    pub(super) revision: String,
}

impl Collision {
    /// A tenant's network, which a pool or a routed subnet that finds it after its own write
    /// always yields to. The tenant object's revision is that of its latest edit of any kind,
    /// later than the claim on its network whenever the quota or a label moved since, so it
    /// cannot say which came first; it is left unread, and an unreadable revision is the one
    /// `arrived_after` yields to. The tenant's own update knows its revision and asks the same
    /// question from its side (`network_lost_claim`), so of two claims at the same moment at
    /// most one stays. (RR5-6)
    fn tenant_network(what: String) -> Self {
        Self {
            what,
            revision: String::new(),
        }
    }
}

/// Whose post-write scan this is, so that it does not find itself or what its
/// claim may lie on. A pool and a subnet may carry the same name, so which
/// resource it is has to travel with the name.
#[derive(Clone, Copy)]
pub(super) enum Claimant<'a> {
    Pool(&'a str),
    /// A routed subnet, and the tenant it was cut for, whose network it may lie in.
    Subnet {
        name: &'a str,
        tenant: &'a str,
    },
    /// A tenant's network, which may hold the tenant's own routed subnets and may
    /// overlap other tenants' networks, which are other overlays.
    Network(&'a str),
}

impl Claimant<'_> {
    /// Whether `pool` is the claimant's own object.
    fn is_pool(&self, pool: &FloatingPool) -> bool {
        matches!(self, Self::Pool(name) if *name == pool.metadata.name)
    }

    /// Whether the claim may lie on `subnet`: its own object, or a subnet of the
    /// tenant whose network it is.
    fn may_hold(&self, subnet: &RoutedSubnet) -> bool {
        match self {
            Self::Pool(_) => false,
            Self::Subnet { name, .. } => *name == subnet.metadata.name,
            Self::Network(tenant) => *tenant == subnet.spec.tenant,
        }
    }
}

/// Compare etcd modification revisions. An unreadable revision yields the claim,
/// favoring a retry over retaining an unresolved overlap.
pub(super) fn arrived_after(mine: &str, theirs: &str) -> bool {
    match (mine.parse::<i64>(), theirs.parse::<i64>()) {
        (Ok(mine), Ok(theirs)) => mine > theirs,
        _ => true,
    }
}

/// Find an earlier conflicting write. Later claimants are expected to withdraw
/// their own objects; interruption or rollback failure can leave overlaps.
pub(super) fn lost_to<'a>(mine: &str, hits: &'a [Collision]) -> Option<&'a Collision> {
    hits.iter().find(|c| arrived_after(mine, &c.revision))
}

/// Everything in the store these ranges overlap, skipping the claimant's own
/// object and what it may lie on, each with the revision of the write that put
/// it there: floating pools, routed subnets and tenants' networks.
///
/// `floating::occupied` answers the same question and throws the revision
/// away, and the revision is precisely what the arbitration needs.
pub(super) async fn collisions(
    st: &ApiState,
    ranges: &[common::net::Ipv4Range],
    mine: Claimant<'_>,
) -> Result<Vec<Collision>, ApiError> {
    let hits = |r: &common::net::Ipv4Range| ranges.iter().any(|c| r.overlaps(c));
    let mut out = Vec::new();
    for pool in floating::all_pools(&st.store).await? {
        if mine.is_pool(&pool) {
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
        if mine.may_hold(&subnet) {
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
    let networks = match mine {
        Claimant::Pool(_) => network_prefixes_taken(st, None).await?,
        Claimant::Subnet { tenant, .. } => network_prefixes_taken(st, Some(tenant)).await?,
        Claimant::Network(_) => Vec::new(),
    };
    out.extend(
        networks
            .into_iter()
            .filter(|(_, range)| hits(range))
            .map(|(what, _)| Collision::tenant_network(what)),
    );
    Ok(out)
}

/// How many lost races a subnet cut accepts before it says so. A liveness
/// bound and not a correctness one, the same one `floating::allocate` sets for
/// the same reason: every round is a block somebody else took first.
pub(super) const MAX_CLAIM_ROUNDS: usize = 8;

/// The claims a pool that is already in the store turns out to have lost.
///
/// The questions `check_pool` asked before the write (a create's or an
/// update's), asked once more now that a concurrent write is visible: the
/// default mark, and the ranges against the other pools, the routed subnets
/// and the tenants' networks. Two pools posted at the same moment both read a
/// store with no
/// default in it and both wrote one — which is not a hand-edited etcd, it is
/// two administrators and one second, and `floating::pick_pool` then refuses
/// every allocation on this cloud until somebody deletes one by hand.
pub(super) async fn pool_lost_claim(
    st: &ApiState,
    pool: &FloatingPool,
) -> Result<Option<String>, ApiError> {
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

pub(super) async fn create_floating_pool(
    State(st): State<ApiState>,
    dry: controller_api::DryRun,
    Json(body): Json<FloatingPool>,
) -> Result<(StatusCode, Json<FloatingPool>), ApiError> {
    check_envelope(&body)?;
    if body.metadata.name.is_empty() {
        return Err(invalid("metadata.name must be set"));
    }
    let mut pool = FloatingPool::declare(&body.metadata.name, body.spec);
    pool.metadata.labels = body.metadata.labels;
    check_pool(&st, &pool, None).await?;
    // Before the write: a preview is not in the store, so there is nothing to ask about after
    // it and nothing to take back. (RR6-2)
    if let Some(preview) = dry.preview(&pool) {
        return Ok((StatusCode::CREATED, Json(preview)));
    }
    #[cfg(test)]
    super::admission_tests::admission_gate(&pool.metadata.name).await;
    let created = st.store.create(&pool).await?;

    // And now the same questions again, from inside the store. No second
    // round: an administrator named these ranges and this default mark
    // outright, so there is nothing for the server to pick differently.
    settle_claim(
        &created.metadata.name,
        "floating pool",
        pool_lost_claim(&st, &created).await,
        take_back(&st, &created),
    )
    .await?;

    info!(pool = %created.metadata.name, cidrs = %created.spec.cidrs.join(","),
          public = created.spec.public, default = created.spec.default, "floating pool created");
    Ok((StatusCode::CREATED, Json(created)))
}

/// Ranges, quotas, the default mark and the description all move. What does
/// not move is any address somebody already holds: a pool cannot be narrowed
/// out from under a live reservation, because the reservation would then name
/// an address the pool no longer contains and no allocator could ever explain
/// where it came from.
pub(super) async fn update_floating_pool(
    State(st): State<ApiState>,
    Path(name): Path<String>,
    dry: controller_api::DryRun,
    Json(mut body): Json<FloatingPool>,
) -> Result<Json<FloatingPool>, ApiError> {
    if body.metadata.name != name {
        return Err(invalid("metadata.name does not match the path"));
    }
    let current: FloatingPool = st.store.get(&name).await?;
    keep_server_owned(&mut body.metadata, &current.metadata);
    body.status = current.status.clone();
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
    controller_api::carry_generation(&current, &mut body)?;
    if let Some(preview) = dry.preview(&body) {
        return Ok(Json(preview));
    }
    #[cfg(test)]
    super::admission_tests::admission_gate(&name).await;
    let updated = st.store.update(&body).await?;

    // The questions the create asks after its write, for the same reason: a
    // pool, a routed subnet or a tenant's network written at the same moment
    // was not in the listings `check_pool` read. Lost, the whole update is put
    // back. (NL6-6)
    settle_claim(
        &name,
        "floating pool",
        pool_lost_claim(&st, &updated).await,
        put_back(&st, &current, &updated),
    )
    .await?;
    Ok(Json(updated))
}

/// A pool with reservations in it stays. The same rule and the same reason as
/// a tenant with users: the invariant "every reservation came out of a pool
/// that exists" is worth exactly what the refusal that keeps it true is worth.
pub(super) async fn delete_floating_pool(
    State(st): State<ApiState>,
    Path(name): Path<String>,
) -> Result<controller_api::Removed, ApiError> {
    let current: FloatingPool = st.store.get(&name).await?;
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
    // The revision that was judged, not whatever the name names by now. (IKR-B81)
    st.store
        .delete_if::<FloatingPool>(&name, &current.metadata.resource_version)
        .await?;
    Ok(controller_api::removed(
        FloatingPool::KIND,
        &name,
        controller_api::Removal::Gone,
    ))
}

/// The first of these strings that is not empty.
fn first_non_empty<const N: usize>(candidates: [&str; N]) -> Option<&str> {
    candidates.into_iter().find(|s| !s.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- claiming address space ---------------------------------------------

    fn collided(what: &str, revision: &str) -> Collision {
        Collision {
            what: what.to_string(),
            revision: revision.to_string(),
        }
    }

    /// Concurrent overlapping claims keep the earlier etcd revision.
    /// An unreadable revision yields conservatively: an extra retry is preferable
    /// to retaining conflicting allocations.
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
}
