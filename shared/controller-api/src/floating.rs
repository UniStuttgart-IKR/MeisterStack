// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Floating address allocation and routed subnet selection.
//!
//! Floating allocation names identify addresses. Concurrent allocators may choose
//! the same gap, but only one create succeeds; losers rescan. Subnet selection
//! returns a candidate that its caller must commit with a concurrency guard.
//! Downstream reconcilers configure packet filtering and routing.

use std::collections::BTreeSet;
use std::net::Ipv4Addr;

use common::net::{Ipv4Range, Ipv4Ranges};
use tracing::{debug, error};

use crate::object::Resource;
use crate::resources::{FloatingIp, FloatingIpSpec, FloatingPool, RoutedSubnet};
use crate::store::{EtcdStore, Result, StoreError};

/// Bound allocation retries after address races or quota rollback.
/// This limits liveness work; each attempt still enforces its allocation checks.
const MAX_ROUNDS: usize = 16;

/// Select the named pool or the default, with actionable configuration errors.
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
             `meister floatingpool create`"
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

/// Read reservations and reject a list/count mismatch rather than allocate
/// from known partial inventory. List and count come from one response, so a
/// write landing between two reads cannot pass for an object that did not
/// decode: a range claim's question after its write runs exactly while the
/// other claim writes or takes itself back.
pub async fn all_reservations(store: &EtcdStore) -> Result<Vec<FloatingIp>> {
    store
        .list_complete(
            "which addresses are taken cannot be established; refusing rather than handing out \
             one twice",
        )
        .await
}

/// Count reservations within both tenant and pool, keeping public and private
/// pool quotas independent.
fn held_by(ips: &[FloatingIp], tenant: &str, pool: &str) -> u32 {
    ips.iter()
        .filter(|ip| ip.spec.tenant == tenant && ip.spec.pool == pool)
        .count() as u32
}

/// Choose the requested address or first free allocatable address. Both
/// paths exclude unusable network/broadcast addresses. Distinguish an
/// out-of-pool request, an unallocatable address and an occupied address.
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

/// Check quota from a linearizable list containing the new reservation.
///
/// Per-address create CAS prevents duplicate addresses, but different addresses
/// can race past the same tenant quota. A post-create read detects excess and
/// rolls back this caller's allocation. Both racers may roll back, and readers
/// may briefly see excess; bounded retries recover without a tenant lock.
fn within_quota(after: &[FloatingIp], tenant: &str, pool: &str, quota: u32) -> bool {
    held_by(after, tenant, pool) <= quota
}

/// References stored with a floating allocation. Carry them in the initial
/// create so the address does not temporarily exist without its target.
#[derive(Clone, Debug, Default)]
pub struct Pointing {
    /// The VM this address is for, by name. `None` = reserved and unassigned.
    pub vm: Option<String>,
    /// The router that carries the 1:1 rule, where the address does not live
    /// in the guest. See `FloatingIpSpec::router`.
    pub router: String,
    /// The guest's own address on the overlay — the inside half of that pair.
    pub internal_address: String,
}

pub async fn allocate(
    store: &EtcdStore,
    pool: &FloatingPool,
    tenant: &str,
    wanted: Option<Ipv4Addr>,
    pointing: Pointing,
    dry: crate::rest::DryRun,
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
            // Distinguish an unassigned zero quota from a quota the tenant has exhausted.
            let name = &pool.metadata.name;
            return Err(StoreError::Invalid(if quota == 0 {
                format!(
                    "tenant {tenant} has no quota in floating pool {name}; an administrator \
                     grants one with `meister floatingpool quota {name} {tenant} <n>`"
                )
            } else {
                format!(
                    "tenant {tenant} already holds all {quota} of its addresses in floating \
                     pool {name}; an administrator raises it with \
                     `meister floatingpool quota {name} {tenant} <n>`"
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
                vm: pointing.vm.clone(),
                router: pointing.router.clone(),
                internal_address: pointing.internal_address.clone(),
            },
        );
        // Preview validates quota and shows this candidate without reserving it.
        // Another caller may claim the address before a later real request.
        if let Some(preview) = dry.preview(&object) {
            return Ok(preview);
        }
        match store.create(&object).await {
            // After creating the address, recheck quota to detect competing allocations
            // under different address keys.
            Ok(created) => {
                let after = all_reservations(store).await?;
                if within_quota(&after, tenant, &pool.metadata.name, quota) {
                    return Ok(created);
                }
                // The reservation this call made, by its uid and revision: one
                // released and reserved again by somebody else in between is
                // theirs. (IKR-B81)
                if let Err(e) = crate::deletion::take_back_created(store, &created).await {
                    // Failed rollback leaves an over-quota reservation requiring operator release;
                    // no reconciler repairs it automatically.
                    error!(
                        address = %address,
                        tenant,
                        pool = %pool.metadata.name,
                        error = %format!("{e:#}"),
                        "could not give back an over-quota address"
                    );
                    return Err(e);
                }
                // Retry after quota rollback; the next scan determines whether room remains.
                debug!(
                    address = %address,
                    tenant,
                    pool = %pool.metadata.name,
                    quota,
                    "gave back an address that would have gone over the quota"
                );
                continue;
            }
            // Creation by address key arbitrates a lost race. An explicit address fails;
            // automatic allocation rescans for the next gap.
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

/// Collect ranges a subnet must avoid, including all floating pools.
/// Overlap would authorize a tenant to source unreserved floating addresses
/// through its routed-subnet allowlist.
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
pub fn check_free(candidate: &Ipv4Range, occupied: &[(String, Ipv4Range)]) -> Result<()> {
    if let Some((what, range)) = occupied.iter().find(|(_, r)| r.overlaps(candidate)) {
        return Err(StoreError::Conflict(format!(
            "{candidate} overlaps {what} ({range})"
        )));
    }
    Ok(())
}

/// Find the first free, prefix-aligned block inside the super-pools.
/// Advance by whole blocks rather than individual addresses.
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
pub async fn all_subnets(store: &EtcdStore) -> Result<Vec<RoutedSubnet>> {
    store
        .list_complete(
            "an overlap check cannot be made; refusing rather than cutting a subnet on top of \
             another one",
        )
        .await
}

/// Every floating pool, with the same guard.
pub async fn all_pools(store: &EtcdStore) -> Result<Vec<FloatingPool>> {
    store
        .list_complete(
            "the pools are not all known; refusing rather than allocating out of a list that is \
             not all of them",
        )
        .await
}

// --- injection --------------------------------------------------------------

/// Fill empty NIC address lists and return the number changed. Every eligible
/// NIC receives the VM's full list because the controller does not select a
/// particular interface for an address. Explicit NIC lists remain unchanged.
///
/// Injection happens in the create payload. Existing agent records pick up
/// new lists only when recreated, not by a stop/start of the same record.
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
        // Provider NICs use operator-defined layer-2 networks, not the tenant overlay.
        // Do not inject tenant floating or routed source lists that their taps ignore.
        if nic.get("physnet").is_some_and(|p| !p.is_null()) {
            continue;
        }
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

/// `spec` without the address lists of its NICs: what of a VM's NICs holds
/// still while the addresses it may use come and go. A tenant's floating
/// addresses and routed subnets change while its VMs exist, and the cloud
/// sends the lists as they are now with every hand-down.
pub fn without_nic_lists(spec: &serde_json::Value) -> serde_json::Value {
    let mut out = spec.clone();
    if let Some(nics) = out.get_mut("nics").and_then(|n| n.as_array_mut()) {
        for nic in nics.iter_mut().filter_map(|n| n.as_object_mut()) {
            nic.remove(NIC_FLOATING_IPS);
            nic.remove(NIC_ROUTED_SUBNETS);
        }
    }
    out
}

/// The NIC field the addresses a VM may claim travel in.
pub const NIC_FLOATING_IPS: &str = "floating_ips";
/// And the one the prefixes it may send from travel in: its tenant's routed
/// subnets and the prefixes of its tenant's network, under the name the field
/// had before the network's prefixes went into it.
pub const NIC_ROUTED_SUBNETS: &str = "routed_subnets";

#[cfg(test)]
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

    /// Select named/default pools and explain missing or ambiguous configuration.
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
                internal_address: String::new(),
                router: String::new(),
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

    /// Explicit addresses obey the scan's exclusions, including subnet network
    /// and broadcast addresses.
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

    /// Model post-write quota checks for concurrent address requests. Each
    /// linearizable reread follows its own write; both writers cannot miss
    /// each other. Address-name uniqueness alone does not enforce tenant quota.
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

        // Both racing allocations may roll back after observing excess quota.
        // A later attempt can retry once that transient excess is removed.
        assert!(!within_quota(&both, "acme", "lab", 1));

        // Room for two is room for two: neither gives anything back.
        assert!(within_quota(&both, "acme", "lab", 2));

        // And the count is per tenant AND per pool, so a neighbour's address
        // and the same tenant's address in another pool count for nothing.
        let other_tenant = reservation("10.255.0.3", "globex", "lab");
        let other_pool = reservation("203.0.113.7", "acme", "public");
        assert_eq!(held_by(&[a, b, other_tenant, other_pool], "acme", "lab"), 2);
    }

    /// Subnet ranges cannot overlap floating pools, which would bypass address
    /// reservation through the subnet source allowlist.
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

        // Provider NICs receive neither tenant-overlay address list.
        let mut mixed = serde_json::json!({
            "nics": [ {}, { "physnet": "ext" } ]
        });
        assert_eq!(
            inject_nic_list(&mut mixed, NIC_ROUTED_SUBNETS, &["10.31.0.0/24".into()]),
            1,
            "the overlay nic, and only it"
        );
        assert_eq!(mixed["nics"][0][NIC_ROUTED_SUBNETS][0], "10.31.0.0/24");
        assert!(mixed["nics"][1].get(NIC_ROUTED_SUBNETS).is_none());
        assert_eq!(spec, serde_json::json!({ "vcpus": 2, "nics": [{}] }));

        let mut none = serde_json::json!({ "vcpus": 2 });
        assert_eq!(
            inject_nic_list(&mut none, NIC_ROUTED_SUBNETS, &["10.7.0.0/24".into()]),
            0
        );
        assert_eq!(none, serde_json::json!({ "vcpus": 2 }));
    }

    /// The address lists come off every NIC, and nothing else does: not the
    /// wire a NIC is on, and not a VM without NICs.
    #[test]
    fn without_nic_lists_takes_the_addresses_and_leaves_the_wires() {
        let spec = serde_json::json!({
            "vcpus": 2,
            "nics": [
                { "vxlan_id": 10_007, "floating_ips": ["10.255.0.7"], "routed_subnets": ["10.7.1.0/24"] },
                { "physnet": "ext" }
            ]
        });
        assert_eq!(
            without_nic_lists(&spec),
            serde_json::json!({
                "vcpus": 2,
                "nics": [ { "vxlan_id": 10_007 }, { "physnet": "ext" } ]
            })
        );
        let bare = serde_json::json!({ "vcpus": 2 });
        assert_eq!(without_nic_lists(&bare), bare);
    }
}
