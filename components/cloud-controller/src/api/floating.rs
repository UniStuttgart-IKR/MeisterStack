// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! The `floatingips` and `floatingpools` resources, and the claim race neither the store nor a lock can arbitrate. See `events` for why the module and the file are named differently.

use super::*;

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

/// Reserve an address.
///
/// The object's name is the address and the server sets it, which is why the
/// request body carries no useful `metadata.name`: an address a client could
/// name into existence is an address two clients could name into existence.
/// The explicit wish travels in `spec.address` instead, and is either granted
/// or refused with the reason — never quietly replaced by another address,
/// because a caller who asked for `203.0.113.7` asked for the one their DNS
/// already points at.
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
/// `spec.vm` is deliberately NOT here: the assign is the one thing an update
/// of a reservation is for. What cannot move is which address this is — the
/// name IS the address — and which pool it was taken out of, because that is
/// the quota it was counted against.
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

/// Give the address back. A hard delete — a reservation owns nothing — and the
/// address is free for the next allocation immediately.
///
/// The VM that had it keeps sending from it until it is recreated, and that is
/// not a hole: the tap rules of a RUNNING vm were built from the assignment
/// that was true when it was created, and the next VM to be given this address
/// gets its own rules at its own create. Two VMs briefly permitted the same
/// address is the same window a DHCP lease has, and the way to close it is the
/// runtime re-home above.
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
    st.store.delete::<FloatingIp>(&name).await?;
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
pub(super) struct Collision {
    /// `pub(super)` because the routed-subnet half of this race reads it to
    /// build its own sentence, and since the split that is a sibling module.
    pub(super) what: String,
    pub(super) revision: String,
}

/// Whose post-write scan this is, so that it does not find itself. A pool and
/// a subnet may carry the same name, so which resource it is has to travel
/// with the name.
#[derive(Clone, Copy)]
pub(super) enum Claimant<'a> {
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
pub(super) fn arrived_after(mine: &str, theirs: &str) -> bool {
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
pub(super) fn lost_to<'a>(mine: &str, hits: &'a [Collision]) -> Option<&'a Collision> {
    hits.iter().find(|c| arrived_after(mine, &c.revision))
}

/// Everything in the store these ranges overlap, skipping the claimant's own
/// object, each with the revision of the write that put it there.
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
pub(super) async fn take_back<T: Resource>(st: &ApiState, name: &str, kind: &str) {
    if let Err(e) = st.store.delete::<T>(name).await {
        error!(name, kind, error = %format!("{e:#}"),
               "could not take back an object that lost its claim; it now overlaps another \
                one and has to be deleted by hand");
    }
}

/// How many lost races a subnet cut accepts before it says so. A liveness
/// bound and not a correctness one, the same one `floating::allocate` sets for
/// the same reason: every round is a block somebody else took first.
pub(super) const MAX_CLAIM_ROUNDS: usize = 8;

/// The claims a pool that is already in the store turns out to have lost.
///
/// The same three questions `check_pool` asked before the write, asked once
/// more now that a concurrent create is visible: the default mark, and the
/// ranges. Two pools posted at the same moment both read a store with no
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
    let created = match dry.preview(&pool) {
        Some(preview) => preview,
        None => st.store.create(&pool).await?,
    };

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
    match dry.preview(&body) {
        Some(preview) => Ok(Json(preview)),
        None => Ok(Json(st.store.update(&body).await?)),
    }
}

/// A pool with reservations in it stays. The same rule and the same reason as
/// a tenant with users: the invariant "every reservation came out of a pool
/// that exists" is worth exactly what the refusal that keeps it true is worth.
pub(super) async fn delete_floating_pool(
    State(st): State<ApiState>,
    Path(name): Path<String>,
) -> Result<controller_api::Removed, ApiError> {
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
}
