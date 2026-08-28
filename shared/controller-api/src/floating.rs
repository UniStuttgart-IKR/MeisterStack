// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Handing out a floating address, and cutting a routed subnet: the two
//! allocations Part A and Part B need, and the one compare-and-swap that makes
//! both of them safe.
//!
//! A floating address is not a label either — it is what a node's nftables
//! rules will let exactly one tap send from, so two tenants issued the same
//! one are two tenants whose frames the same rule permits, which is the
//! precise thing the reservation exists to prevent. So this is the same
//! argument `vni` makes, with a better answer available: the object's NAME is
//! the address, so two allocators racing for the same gap both try to create
//! `10.255.0.7`, and etcd's own create lets exactly one of them win. The loser
//! reads the store again and takes the next gap. Nothing new was built for it;
//! the allocator is a scan and a retry.
//!
//! The scan is a GAP scan and not a high-water mark, which is the other
//! difference from `vni`. A VNI released by a deleted tenant is one number out
//! of sixteen million and nobody misses it; a public address released by a
//! tenant is one of the four an operator was given, and a counter that only
//! moved forward would exhaust that pool on the fourth release.
//!
//! Neither allocation ROUTES anything. What comes out of here is ownership —
//! who may use which address — and everything downstream (the tap rules, the
//! BGP announcement) is a consequence of it.

use std::collections::BTreeSet;
use std::net::Ipv4Addr;

use common::net::{Ipv4Range, Ipv4Ranges};
use macros::generated;
use tracing::{debug, error};

use crate::object::Resource;
use crate::resources::{FloatingIp, FloatingIpSpec, FloatingPool, RoutedSubnet};
use crate::store::{EtcdStore, Result, StoreError};

/// How many lost races to accept before saying so. A liveness bound, not a
/// correctness one — every round is one address somebody else took first, or
/// one this caller gave back rather than go over a quota (see `within_quota`),
/// and a caller that has lost sixteen in a row is on a cloud with bigger
/// problems than this reservation.
const MAX_ROUNDS: usize = 16;

/// The pool a reservation belongs to: the one it named, or the one marked
/// default.
///
/// A refusal here is deliberately wordy. "No pool" is the state a cloud is in
/// before an operator has configured any addresses at all, and the useful
/// answer to a member who asks for a floating address on such a cloud is what
/// the administrator has to do, not `404`.
#[generated(model = ClaudeOpus, version = "5")]
pub fn pick_pool<'a>(pools: &'a [FloatingPool], named: Option<&str>) -> Result<&'a FloatingPool> {
    if let Some(name) = named.filter(|n| !n.is_empty()) {
        return pools
            .iter()
            .find(|p| p.metadata.name == name)
            .ok_or_else(|| StoreError::NotFound(format!("{}/{name}", FloatingPool::RESOURCE)));
    }
    let defaults: Vec<&FloatingPool> = pools.iter().filter(|p| p.spec.default).collect();
    match defaults.as_slice() {
        [one] => Ok(one),
        [] if pools.is_empty() => Err(StoreError::Invalid(
            "this cloud has no floating pool; an administrator creates one with \
             `meister cloud floatingpool create`"
                .into(),
        )),
        [] => Err(StoreError::Invalid(format!(
            "no floating pool is marked default; name one with --pool (have: {})",
            pools
                .iter()
                .map(|p| p.metadata.name.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        ))),
        // Refused at write time, so reaching this means somebody edited etcd
        // by hand. Saying so beats picking one and being unable to explain
        // which address came from where.
        many => Err(StoreError::Invalid(format!(
            "{} pools are marked default ({}); exactly one may be",
            many.len(),
            many.iter()
                .map(|p| p.metadata.name.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        ))),
    }
}

/// The addresses of a set of reservations, for the gap scan and the quota.
fn addresses(ips: &[FloatingIp]) -> BTreeSet<Ipv4Addr> {
    ips.iter()
        .filter_map(|ip| ip.spec.address.parse().ok())
        .collect()
}

/// Every reservation, refusing to answer from a partial list.
///
/// `list` drops what it cannot decode, and a dropped reservation is an address
/// this function would hand out to somebody else. The same guard `delete_tenant`
/// applies to its membership check, for the same reason and with more at stake:
/// there the cost is a tenant deleted too eagerly, here it is two tenants
/// holding one address.
#[generated(model = ClaudeOpus, version = "5")]
pub async fn all_reservations(store: &EtcdStore) -> Result<Vec<FloatingIp>> {
    let ips = store.list::<FloatingIp>().await?;
    if ips.len() != store.count::<FloatingIp>().await? {
        return Err(StoreError::Invalid(
            "some floatingip objects did not decode, so which addresses are taken cannot be \
             established; refusing rather than handing out one twice"
                .into(),
        ));
    }
    Ok(ips)
}

/// How many addresses `tenant` holds in `pool`.
///
/// Per tenant AND per pool, which is what makes a public pool safe to have
/// next to a private one: a tenant's four private addresses say nothing about
/// how many routable ones it may hold.
#[generated(model = ClaudeOpus, version = "5")]
fn held_by(ips: &[FloatingIp], tenant: &str, pool: &str) -> u32 {
    ips.iter()
        .filter(|ip| ip.spec.tenant == tenant && ip.spec.pool == pool)
        .count() as u32
}

/// Which address this round will try to take: the one that was asked for, or
/// the first gap.
///
/// Both answers come out of the same allocatable set, and that symmetry is the
/// whole reason this is one function. `first_free` steps over a CIDR's network
/// and broadcast address because a guest given either of them is a guest whose
/// neighbours answer for it — and an address a caller NAMES is exactly as
/// unusable, for exactly that reason. The named path used to check only
/// `contains`, which is the GUARD's set and two addresses larger per range, so
/// `--address 10.255.0.0` out of a `/16` was handed over down a path the scan
/// would never have taken.
///
/// The three refusals are kept apart on purpose: "not in this pool", "not an
/// address that can be handed out" and "somebody already has it" are three
/// different things to the person reading them, and only the last of the three
/// is worth trying again later.
#[generated(model = ClaudeOpus, version = "5")]
fn pick_address(
    ranges: &Ipv4Ranges,
    pool: &FloatingPool,
    wanted: Option<Ipv4Addr>,
    taken: &BTreeSet<Ipv4Addr>,
) -> Result<Ipv4Addr> {
    let name = &pool.metadata.name;
    let Some(addr) = wanted else {
        return ranges.first_free(taken).ok_or_else(|| {
            StoreError::Conflict(format!(
                "floating pool {name} has no free address left ({} of {} in use)",
                taken.len(),
                ranges.len()
            ))
        });
    };
    if !ranges.contains(addr) {
        return Err(StoreError::Conflict(format!(
            "{addr} is not in floating pool {name} ({})",
            pool.spec.cidrs.join(", ")
        )));
    }
    if !ranges.is_allocatable(addr) {
        return Err(StoreError::Conflict(format!(
            "{addr} is the network or the broadcast address of a range in floating pool \
             {name} ({}) and is not handed out",
            pool.spec.cidrs.join(", ")
        )));
    }
    if taken.contains(&addr) {
        return Err(StoreError::Conflict(format!("{addr} is already reserved")));
    }
    Ok(addr)
}

/// Whether the reservation that has just been written is one the quota still
/// allows, counted from a list that INCLUDES it.
///
/// The quota check before the create is a check-then-act and cannot be
/// anything else: two requests for the same tenant read the same list, both
/// see room, and both write. etcd arbitrates the ADDRESS — the object's name
/// IS the address, so two scans racing for the same gap collide and one of
/// them loses — but two requests that NAME two different addresses collide on
/// nothing at all, and the tenant ends up one over its ceiling with no pass
/// that will ever notice.
///
/// So the count is taken again afterwards, and whoever sees a list that is
/// over the line gives its own address back. What makes that an answer rather
/// than a second race is that etcd's reads are linearizable: each racer reads
/// after its own write, so of any two of them at least one sees the other's
/// object — for both to miss each other, each read would have to come before
/// the other's write, and one of the two writes came first. Whoever sees both
/// counts both, and gives its address back.
///
/// The honest price, twice over. Two racers can BOTH see the full list and
/// both give their address back, so a tenant that had room for one ends up
/// with none and an error saying its quota is used up; the round then starts
/// over, the re-read shows the truth, and `MAX_ROUNDS` bounds how long that
/// can go on. And there is a window, between the create and the rollback, in
/// which a concurrent reader sees an over-quota reservation. Both are the cost
/// of not holding a lock per tenant, and both are recoverable by asking again
/// — which the thing they replace, an over-grant no pass takes back, is not.
#[generated(model = ClaudeOpus, version = "5")]
fn within_quota(after: &[FloatingIp], tenant: &str, pool: &str, quota: u32) -> bool {
    held_by(after, tenant, pool) <= quota
}

/// Take an address out of `pool` for `tenant`.
///
/// `wanted` is the explicit request: an address a caller names is either given
/// to them or refused with the reason, never quietly replaced by another one.
/// Without it the first gap in the pool's ranges is taken, in the order the
/// operator wrote them.
///
/// The quota is checked inside the retry loop and not before it, because a
/// round that lost its race is a round whose count may have changed — the
/// tenant that beat us to the address may also have been our own. And it is
/// checked a second time AFTER the write, because the check before it is a
/// check-then-act that two requests naming two different addresses walk
/// straight through: `within_quota` has that argument in full.
#[generated(model = ClaudeOpus, version = "5")]
pub async fn allocate(
    store: &EtcdStore,
    pool: &FloatingPool,
    tenant: &str,
    wanted: Option<Ipv4Addr>,
    vm: Option<String>,
) -> Result<FloatingIp> {
    let ranges = Ipv4Ranges::parse(&pool.spec.cidrs).map_err(|e| {
        StoreError::Invalid(format!(
            "floating pool {} has an unusable range: {e}",
            pool.metadata.name
        ))
    })?;
    let quota = pool.spec.quota_for(tenant);

    for _ in 0..MAX_ROUNDS {
        let existing = all_reservations(store).await?;

        let held = held_by(&existing, tenant, &pool.metadata.name);
        if held >= quota {
            // Zero reads differently from "used up", and the difference is
            // the whole assignment rule: a public pool defaults to zero, so
            // the answer for most tenants asking for a routable address is
            // "nobody has given you any", not "you have spent yours".
            let name = &pool.metadata.name;
            return Err(StoreError::Invalid(if quota == 0 {
                format!(
                    "tenant {tenant} has no quota in floating pool {name}; an administrator \
                     grants one with `meister cloud floatingpool quota {name} {tenant} <n>`"
                )
            } else {
                format!(
                    "tenant {tenant} already holds all {quota} of its addresses in floating \
                     pool {name}; an administrator raises it with \
                     `meister cloud floatingpool quota {name} {tenant} <n>`"
                )
            }));
        }

        let taken = addresses(&existing);
        let address = pick_address(&ranges, pool, wanted, &taken)?;

        let object = FloatingIp::declare(
            &address.to_string(),
            FloatingIpSpec {
                tenant: tenant.to_string(),
                pool: pool.metadata.name.clone(),
                address: address.to_string(),
                vm: vm.clone(),
            },
        );
        match store.create(&object).await {
            // The address is ours. Whether the QUOTA is, is a question the
            // list we read before the write could not answer — see
            // `within_quota` for why it is asked here instead, and for what
            // this costs.
            Ok(created) => {
                let after = all_reservations(store).await?;
                if within_quota(&after, tenant, &pool.metadata.name, quota) {
                    return Ok(created);
                }
                if let Err(e) = store.delete::<FloatingIp>(&address.to_string()).await {
                    // Error, not warn: the reservation is over the tenant's
                    // quota and the rollback did not land, so the pool holds
                    // an address that is nobody's business to take back. No
                    // pass repairs it — only a person running
                    // `meister cloud floatingip release` does.
                    error!(
                        address = %address,
                        tenant,
                        pool = %pool.metadata.name,
                        error = %format!("{e:#}"),
                        "could not give back an over-quota address"
                    );
                    return Err(e);
                }
                // Debug, not warn: losing a quota race is a decision that did
                // not fall, and the round that follows says out loud whichever
                // of the two things is actually true — the quota is used up,
                // or there was room after all.
                debug!(
                    address = %address,
                    tenant,
                    pool = %pool.metadata.name,
                    quota,
                    "gave back an address that would have gone over the quota"
                );
                continue;
            }
            // Somebody took this address between the scan and the write. The
            // NAME is the address, so the store's own create is the
            // compare-and-swap — and an explicit request has nowhere else to
            // go, while a scan simply reads what the winner left and tries
            // the next gap.
            Err(StoreError::AlreadyExists(_)) => {
                if wanted.is_some() {
                    return Err(StoreError::Conflict(format!(
                        "{address} is already reserved"
                    )));
                }
                continue;
            }
            Err(e) => return Err(e),
        }
    }
    Err(StoreError::Conflict(format!(
        "lost {MAX_ROUNDS} races for an address in floating pool {} (retries exhausted)",
        pool.metadata.name
    )))
}

// --- routed subnets ---------------------------------------------------------

/// Everything a new subnet may not touch: the other routed subnets and every
/// floating pool.
///
/// Floating pools are in the list for a reason worth stating: a tenant whose
/// routed subnet contained a floating address would have that address on its
/// allowlist by virtue of the subnet, and the pool guard — the rule that says
/// nobody sources from a pool address without holding it — would have a hole
/// exactly the size of that subnet.
#[generated(model = ClaudeOpus, version = "5")]
pub fn occupied(
    pools: &[FloatingPool],
    subnets: &[RoutedSubnet],
    except: Option<&str>,
) -> Vec<(String, Ipv4Range)> {
    let mut out = Vec::new();
    for p in pools {
        for entry in &p.spec.cidrs {
            if let Ok(range) = entry.parse::<Ipv4Range>() {
                out.push((format!("floating pool {}", p.metadata.name), range));
            }
        }
    }
    for s in subnets {
        if except == Some(s.metadata.name.as_str()) {
            continue;
        }
        if let Ok(range) = s.spec.cidr.parse::<Ipv4Range>() {
            out.push((
                format!(
                    "routed subnet {} (tenant {})",
                    s.metadata.name, s.spec.tenant
                ),
                range,
            ));
        }
    }
    out
}

/// Refuse a range that overlaps something that already exists, naming what it
/// collided with.
#[generated(model = ClaudeOpus, version = "5")]
pub fn check_free(candidate: &Ipv4Range, occupied: &[(String, Ipv4Range)]) -> Result<()> {
    if let Some((what, range)) = occupied.iter().find(|(_, r)| r.overlaps(candidate)) {
        return Err(StoreError::Conflict(format!(
            "{candidate} overlaps {what} ({range})"
        )));
    }
    Ok(())
}

/// The first aligned block of `prefix_len` bits inside the super-pools that
/// collides with nothing.
///
/// Aligned, because a subnet that is not on its own boundary is a subnet no
/// router will accept as a prefix — and walking blocks rather than addresses
/// is also what keeps this a handful of comparisons on a /16.
#[generated(model = ClaudeOpus, version = "5")]
pub fn cut_subnet(
    supers: &Ipv4Ranges,
    prefix_len: u32,
    occupied: &[(String, Ipv4Range)],
) -> Option<Ipv4Range> {
    if prefix_len > 32 {
        return None;
    }
    let size = 1u64 << (32 - prefix_len);
    for range in supers.ranges() {
        let first = u32::from(range.first()) as u64;
        let last = u32::from(range.last()) as u64;
        // Start at the first aligned block at or after the range's start.
        let mut base = first.div_ceil(size) * size;
        while base + size - 1 <= last {
            let candidate: Ipv4Range = format!("{}/{prefix_len}", Ipv4Addr::from(base as u32))
                .parse()
                .ok()?;
            if !occupied.iter().any(|(_, r)| r.overlaps(&candidate)) {
                return Some(candidate);
            }
            base += size;
        }
    }
    None
}

/// Every routed subnet, refusing to answer from a partial list — same guard
/// and same reason as `all_reservations`, with the overlap check at stake
/// instead of the address.
#[generated(model = ClaudeOpus, version = "5")]
pub async fn all_subnets(store: &EtcdStore) -> Result<Vec<RoutedSubnet>> {
    let subnets = store.list::<RoutedSubnet>().await?;
    if subnets.len() != store.count::<RoutedSubnet>().await? {
        return Err(StoreError::Invalid(
            "some routedsubnet objects did not decode, so an overlap check cannot be made; \
             refusing rather than cutting a subnet on top of another one"
                .into(),
        ));
    }
    Ok(subnets)
}

/// Every floating pool, with the same guard.
#[generated(model = ClaudeOpus, version = "5")]
pub async fn all_pools(store: &EtcdStore) -> Result<Vec<FloatingPool>> {
    let pools = store.list::<FloatingPool>().await?;
    if pools.len() != store.count::<FloatingPool>().await? {
        return Err(StoreError::Invalid(
            "some floatingpool objects did not decode; refusing rather than allocating out of \
             a list that is not all of them"
                .into(),
        ));
    }
    Ok(pools)
}

// --- injection --------------------------------------------------------------

/// Write a list of strings into every NIC of an agent NewVmSpec, and say how
/// many NICs that was.
///
/// The same injection `vni::inject_vxlan_id` does and in the same place, for
/// the same reason: whose address this is, is a control-plane fact, and by the
/// time a spec reaches a node it should say plainly which addresses this VM
/// may source from. The agent then only checks types.
///
/// Every NIC gets the whole list, and that is the honest v1: which of a VM's
/// two NICs a floating address belongs on is a question this control plane
/// cannot answer — it knows the VM holds the address, not which wire it means
/// to answer for it on. The rules the node builds are a permission and not a
/// route, so a permission on both taps of a two-NIC VM costs nothing and
/// forbids nothing that was allowed before.
///
/// A NIC that already carries entries under `field` is left alone: that is the
/// standalone road, exactly as it is for `vxlan_id` — a cluster with no cloud
/// above it has no FloatingIp objects to resolve, and putting the addresses
/// straight in the spec has to keep working.
///
/// WHEN a change takes effect, exactly: the addresses are read at CREATE and
/// written into the spec the node stores, and a node's spec is immutable once
/// it has it. So a VM created after the assignment has it, and an existing one
/// picks it up when it is RECREATED — not when it is merely stopped and
/// started, which keeps the same tap and the same record.
///
/// NICE-TO-HAVE, not built, and this is the gap it closes: a session message
/// that re-applies one tap's chain from a new list. The chain is already
/// computed from a list and rebuilt whole on every apply, so the work is the
/// plumbing and not the rules.
#[generated(model = ClaudeOpus, version = "5")]
pub fn inject_nic_list(spec: &mut serde_json::Value, field: &str, values: &[String]) -> usize {
    if values.is_empty() {
        return 0;
    }
    let Some(nics) = spec.get_mut("nics").and_then(|n| n.as_array_mut()) else {
        return 0;
    };
    let mut touched = 0;
    for nic in nics {
        let Some(nic) = nic.as_object_mut() else {
            continue;
        };
        let already = nic
            .get(field)
            .and_then(|v| v.as_array())
            .is_some_and(|a| !a.is_empty());
        if already {
            continue;
        }
        nic.insert(field.to_string(), serde_json::Value::from(values.to_vec()));
        touched += 1;
    }
    touched
}

/// The NIC field the addresses a VM may claim travel in.
pub const NIC_FLOATING_IPS: &str = "floating_ips";
/// And the one its tenant's own subnets travel in.
pub const NIC_ROUTED_SUBNETS: &str = "routed_subnets";

#[cfg(test)]
#[generated(model = ClaudeOpus, version = "5")]
mod tests {
    use super::*;
    use crate::resources::{
        DEFAULT_QUOTA_PRIVATE, DEFAULT_QUOTA_PUBLIC, FloatingPoolSpec, RoutedSubnetSpec,
    };

    fn pool(name: &str, cidrs: &[&str], default: bool) -> FloatingPool {
        FloatingPool::declare(
            name,
            FloatingPoolSpec {
                cidrs: cidrs.iter().map(|s| s.to_string()).collect(),
                default,
                ..FloatingPoolSpec::default()
            },
        )
    }

    fn subnet(name: &str, tenant: &str, cidr: &str) -> RoutedSubnet {
        RoutedSubnet::declare(
            name,
            RoutedSubnetSpec {
                tenant: tenant.into(),
                cidr: cidr.into(),
                ..RoutedSubnetSpec::default()
            },
        )
    }

    /// The pool a reservation lands in, and every way that question can have
    /// no answer. Each refusal says what to do about it — a member asking for
    /// an address on a cloud with no pools should read the sentence that
    /// names the command their administrator has to run.
    #[test]
    fn a_reservation_lands_in_the_named_pool_or_the_default_one() {
        let pools = vec![
            pool("lab", &["10.255.0.0/24"], true),
            pool("public", &["203.0.113.0/29"], false),
        ];
        assert_eq!(pick_pool(&pools, None).unwrap().metadata.name, "lab");
        assert_eq!(
            pick_pool(&pools, Some("public")).unwrap().metadata.name,
            "public"
        );
        assert!(matches!(
            pick_pool(&pools, Some("nope")),
            Err(StoreError::NotFound(_))
        ));

        let none: Vec<FloatingPool> = Vec::new();
        let err = pick_pool(&none, None).unwrap_err().to_string();
        assert!(err.contains("floatingpool create"), "{err}");

        let undecided = vec![
            pool("a", &["10.0.0.0/24"], false),
            pool("b", &["10.0.1.0/24"], false),
        ];
        let err = pick_pool(&undecided, None).unwrap_err().to_string();
        assert!(err.contains("--pool"), "{err}");

        let both = vec![
            pool("a", &["10.0.0.0/24"], true),
            pool("b", &["10.0.1.0/24"], true),
        ];
        let err = pick_pool(&both, None).unwrap_err().to_string();
        assert!(err.contains("exactly one"), "{err}");
    }

    /// Zero for a public pool is the design rule in one assertion: a routable
    /// address is something an operator was given by somebody else, and this
    /// control plane does not give it away by default.
    #[test]
    fn the_default_quota_says_no_to_public_addresses() {
        let mut private = pool("lab", &["10.255.0.0/24"], true);
        assert_eq!(private.spec.quota_for("acme"), DEFAULT_QUOTA_PRIVATE);
        private.spec.quota.insert("acme".into(), 9);
        assert_eq!(private.spec.quota_for("acme"), 9);
        assert_eq!(private.spec.quota_for("other"), DEFAULT_QUOTA_PRIVATE);

        let mut public = pool("public", &["203.0.113.0/29"], false);
        public.spec.public = true;
        assert_eq!(public.spec.quota_for("acme"), DEFAULT_QUOTA_PUBLIC);
        assert_eq!(DEFAULT_QUOTA_PUBLIC, 0);
        public.spec.quota.insert("acme".into(), 2);
        assert_eq!(
            public.spec.quota_for("acme"),
            2,
            "an admin hands them out one tenant at a time"
        );
    }

    fn reservation(address: &str, tenant: &str, pool: &str) -> FloatingIp {
        FloatingIp::declare(
            address,
            FloatingIpSpec {
                tenant: tenant.into(),
                pool: pool.into(),
                address: address.into(),
                vm: None,
            },
        )
    }

    fn ranges(cidrs: &[&str]) -> Ipv4Ranges {
        Ipv4Ranges::parse(&cidrs.iter().map(|s| s.to_string()).collect::<Vec<_>>()).unwrap()
    }

    /// The asymmetry that was there: the scan steps over a subnet's network
    /// and broadcast address, so a caller who NAMES one has to be refused it
    /// too. A guest holding the broadcast address of its own subnet is a
    /// guest whose neighbours answer for it, and the pool cannot tell the two
    /// requests apart once the object exists.
    #[test]
    fn a_named_address_is_measured_against_the_same_set_the_scan_walks() {
        let lab = pool("lab", &["10.255.0.0/24"], true);
        let space = ranges(&["10.255.0.0/24"]);
        let none = BTreeSet::new();

        // The scan never offers the edges...
        assert_eq!(
            pick_address(&space, &lab, None, &none).unwrap(),
            "10.255.0.1".parse::<Ipv4Addr>().unwrap()
        );
        // ...and naming one is now the same answer, with the reason in it.
        for edge in ["10.255.0.0", "10.255.0.255"] {
            let err = pick_address(&space, &lab, Some(edge.parse().unwrap()), &none)
                .unwrap_err()
                .to_string();
            assert!(err.contains("broadcast"), "{err}");
            assert!(err.contains("lab"), "{err}");
        }

        // The three refusals stay three different sentences.
        let outside = pick_address(&space, &lab, Some("10.0.0.5".parse().unwrap()), &none)
            .unwrap_err()
            .to_string();
        assert!(outside.contains("is not in floating pool lab"), "{outside}");

        let taken: BTreeSet<Ipv4Addr> = ["10.255.0.7".parse().unwrap()].into_iter().collect();
        let held = pick_address(&space, &lab, Some("10.255.0.7".parse().unwrap()), &taken)
            .unwrap_err()
            .to_string();
        assert!(held.contains("already reserved"), "{held}");

        // A written-out range and a single address have no edges to reserve:
        // somebody who wrote those addresses down meant them.
        let four = pool(
            "public",
            &["203.0.113.8-203.0.113.11", "203.0.113.7"],
            false,
        );
        let space = ranges(&["203.0.113.8-203.0.113.11", "203.0.113.7"]);
        assert!(pick_address(&space, &four, Some("203.0.113.8".parse().unwrap()), &none).is_ok());
        assert!(pick_address(&space, &four, Some("203.0.113.7".parse().unwrap()), &none).is_ok());
    }

    /// The count after the write, which is the only one that can be believed.
    ///
    /// Two requests for the same tenant read the same list and both see room.
    /// etcd arbitrates the address — the name IS the address — so two scans
    /// for the same gap collide, but two requests NAMING two addresses do
    /// not, and the tenant ends up over its ceiling. Recounting afterwards is
    /// what closes that, and the closing rests on one fact: reads are
    /// linearizable and each racer reads after its own write, so the pair of
    /// views where each misses the other cannot happen. Every pair that CAN
    /// happen is below, and in none of them do two racers keep an address.
    #[test]
    fn a_second_writer_that_saw_the_first_one_gives_its_address_back() {
        let a = reservation("10.255.0.1", "acme", "lab");
        let b = reservation("10.255.0.2", "acme", "lab");

        let alone = std::slice::from_ref(&a);
        let both = [a.clone(), b.clone()];

        // Alone, and inside the quota: kept.
        assert!(within_quota(alone, "acme", "lab", 1));

        // A's view (it wrote first and read before B landed) keeps A; B's
        // view has both and gives B's address back. Exactly one survivor.
        assert!(within_quota(alone, "acme", "lab", 1));
        assert!(!within_quota(&both, "acme", "lab", 1));

        // Both reads after both writes: both give theirs back and the tenant
        // is told its quota is used up although it had room. A spurious
        // refusal the next round undoes — the over-grant it replaces, no pass
        // ever does.
        assert!(!within_quota(&both, "acme", "lab", 1));

        // Room for two is room for two: neither gives anything back.
        assert!(within_quota(&both, "acme", "lab", 2));

        // And the count is per tenant AND per pool, so a neighbour's address
        // and the same tenant's address in another pool count for nothing.
        let other_tenant = reservation("10.255.0.3", "globex", "lab");
        let other_pool = reservation("203.0.113.7", "acme", "public");
        assert_eq!(held_by(&[a, b, other_tenant, other_pool], "acme", "lab"), 2);
    }

    /// A floating pool is in the occupied list, and that is not tidiness: a
    /// routed subnet containing a pool address would put that address on its
    /// tenant's allowlist, and the pool guard would have a hole the size of
    /// the subnet.
    #[test]
    fn a_subnet_may_not_overlap_a_pool_or_another_subnet() {
        let pools = vec![pool("lab", &["10.255.0.0/16"], true)];
        let subnets = vec![subnet("acme-net", "acme", "10.7.1.0/24")];
        let taken = occupied(&pools, &subnets, None);

        check_free(&"10.7.2.0/24".parse().unwrap(), &taken).expect("free space is free");

        let err = check_free(&"10.7.1.128/25".parse().unwrap(), &taken)
            .unwrap_err()
            .to_string();
        assert!(err.contains("routed subnet acme-net"), "{err}");
        assert!(err.contains("tenant acme"), "{err}");

        let err = check_free(&"10.255.9.0/24".parse().unwrap(), &taken)
            .unwrap_err()
            .to_string();
        assert!(err.contains("floating pool lab"), "{err}");

        // An update of a subnet must not collide with ITSELF.
        let mine = occupied(&pools, &subnets, Some("acme-net"));
        check_free(&"10.7.1.0/24".parse().unwrap(), &mine)
            .expect("its own range is not a conflict");
    }

    /// Cutting from a super-pool: aligned blocks, first free one wins, and
    /// the floating pool inside the same space is stepped over.
    #[test]
    fn a_subnet_is_cut_from_the_first_free_aligned_block() {
        let supers = Ipv4Ranges::parse(&["10.7.0.0/16".into()]).unwrap();
        let none: Vec<(String, Ipv4Range)> = Vec::new();
        assert_eq!(
            cut_subnet(&supers, 24, &none).unwrap().to_string(),
            "10.7.0.0-10.7.0.255"
        );

        let taken = occupied(
            &[pool("lab", &["10.7.1.0/24"], true)],
            &[subnet("a", "acme", "10.7.0.0/24")],
            None,
        );
        assert_eq!(
            cut_subnet(&supers, 24, &taken).unwrap().to_string(),
            "10.7.2.0-10.7.2.255"
        );

        // A super-pool with nothing left says so rather than returning a
        // block that does not fit in it.
        let tiny = Ipv4Ranges::parse(&["10.9.0.0/24".into()]).unwrap();
        assert!(
            cut_subnet(&tiny, 23, &none).is_none(),
            "a /23 does not fit in a /24"
        );
        let full = occupied(&[], &[subnet("s", "t", "10.9.0.0/24")], None);
        assert!(cut_subnet(&tiny, 24, &full).is_none());
    }

    /// Alignment is the point of walking blocks rather than addresses: a
    /// prefix that is not on its own boundary is a prefix no router accepts.
    #[test]
    fn a_cut_block_always_starts_on_its_own_boundary() {
        let supers = Ipv4Ranges::parse(&["10.7.0.13-10.7.9.200".into()]).unwrap();
        let cut = cut_subnet(&supers, 24, &[]).unwrap();
        assert_eq!(
            cut.to_string(),
            "10.7.1.0-10.7.1.255",
            "10.7.0.x is only partly ours"
        );
    }

    // --- injection ----------------------------------------------------------

    #[test]
    fn every_nic_without_a_list_of_its_own_gets_the_vms_addresses() {
        let mut spec =
            serde_json::json!({ "vcpus": 1, "nics": [{}, { "mac": "52:54:00:aa:bb:cc" }] });
        let addrs = vec!["10.255.0.7".to_string()];
        assert_eq!(inject_nic_list(&mut spec, NIC_FLOATING_IPS, &addrs), 2);
        for nic in spec["nics"].as_array().unwrap() {
            assert_eq!(nic[NIC_FLOATING_IPS][0], "10.255.0.7");
        }
        assert_eq!(spec["vcpus"], 1, "the rest of the document is untouched");
        assert_eq!(spec["nics"][1]["mac"], "52:54:00:aa:bb:cc");
    }

    /// The standalone road and the override, exactly as `inject_vxlan_id` has
    /// them: a spec that already says which addresses a NIC may use has said
    /// something more specific than the cloud did.
    #[test]
    fn a_nic_that_already_names_addresses_is_never_overwritten() {
        let mut spec = serde_json::json!({
            "nics": [{ "floating_ips": ["192.0.2.9"] }, {}, { "floating_ips": [] }]
        });
        let addrs = vec!["10.255.0.7".to_string()];
        assert_eq!(inject_nic_list(&mut spec, NIC_FLOATING_IPS, &addrs), 2);
        assert_eq!(spec["nics"][0]["floating_ips"][0], "192.0.2.9");
        assert_eq!(spec["nics"][1]["floating_ips"][0], "10.255.0.7");
        assert_eq!(
            spec["nics"][2]["floating_ips"][0], "10.255.0.7",
            "an empty list is no claim"
        );
    }

    /// Nothing to inject writes nothing — in particular not an empty key the
    /// agent's serde would then have to explain, and not a `nics` array on a
    /// VM that has none.
    #[test]
    fn a_vm_with_no_addresses_or_no_nics_is_left_exactly_as_it_was() {
        let mut spec = serde_json::json!({ "vcpus": 2, "nics": [{}] });
        assert_eq!(inject_nic_list(&mut spec, NIC_FLOATING_IPS, &[]), 0);
        assert_eq!(spec, serde_json::json!({ "vcpus": 2, "nics": [{}] }));

        let mut none = serde_json::json!({ "vcpus": 2 });
        assert_eq!(
            inject_nic_list(&mut none, NIC_ROUTED_SUBNETS, &["10.7.0.0/24".into()]),
            0
        );
        assert_eq!(none, serde_json::json!({ "vcpus": 2 }));
    }
}
