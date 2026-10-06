// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Who claims which IPv4 address space in a cloud, and which prefixes a tenant's guests may
//! therefore be let send from.
//!
//! A tenant's network prefixes and the prefix behind each of its routers go onto the source
//! allowlist of every tap of its VMs. What they may lie on is decided here, once, for the
//! admission that judges a write and for the pass that hands the list down.

use std::net::Ipv4Addr;

use common::net::{Ipv4Range, Ipv4Ranges};

use crate::floating::{all_pools, all_subnets, occupied};
use crate::resources::{FloatingPool, ProviderNetwork, RoutedSubnet, Router, Tenant};
use crate::store::{EtcdStore, Result};

/// What a prefix a tenant's guests send from may not overlap, each named for a refusal: every
/// floating pool, every other tenant's routed subnet, and the routed pools subnets are cut
/// from. Those addresses are somebody else's or may become so; the tenant's own routed subnets
/// are on its allowlist already. (NL5-1)
pub fn off_limits_to_tenant(
    tenant: &str,
    pools: &[FloatingPool],
    subnets: &[RoutedSubnet],
    routed_pools: &Ipv4Ranges,
) -> Vec<(String, Ipv4Range)> {
    let others: Vec<RoutedSubnet> = subnets
        .iter()
        .filter(|s| s.spec.tenant != tenant)
        .cloned()
        .collect();
    let mut taken = occupied(pools, &others, None);
    taken.extend(
        routed_pools
            .ranges()
            .iter()
            .map(|range| ("the routed pools".to_string(), *range)),
    );
    taken
}

/// Every tenant's network prefixes but those of `except`, each named for a refusal. (NL5-1)
pub fn tenant_networks(tenants: &[Tenant], except: Option<&str>) -> Vec<(String, Ipv4Range)> {
    tenants
        .iter()
        .filter(|t| Some(t.metadata.name.as_str()) != except)
        .flat_map(|t| {
            t.spec.network_prefixes.iter().filter_map(|prefix| {
                let range = prefix.parse::<Ipv4Range>().ok()?;
                Some((format!("tenant {}'s network", t.metadata.name), range))
            })
        })
        .collect()
}

/// The wire of each provider network, each named for a refusal: its CIDR, or where it names
/// none, its allocation and its gateway, which are then all of it that is known.
pub fn provider_wires(networks: &[ProviderNetwork]) -> Vec<(String, Ipv4Range)> {
    networks
        .iter()
        .flat_map(|n| {
            let what = format!("provider network {}", n.metadata.name);
            let entries: Vec<&String> = if n.spec.cidr.is_empty() {
                n.spec
                    .allocation
                    .iter()
                    .chain(std::iter::once(&n.spec.gateway))
                    .collect()
            } else {
                vec![&n.spec.cidr]
            };
            entries
                .into_iter()
                .filter_map(|entry| entry.parse::<Ipv4Range>().ok())
                .map(move |range| (what.clone(), range))
        })
        .collect()
}

/// The address `router` holds on its inside and the prefix it is on (`10.30.0.1/24` is
/// 10.30.0.1 on 10.30.0.0/24): `None` for a router that names no inside address, and why not
/// when `spec.internalAddr` is not an address with its prefix length. The one reader of
/// `spec.internalAddr`, for what may be sent from behind the router and for what may be
/// translated into it. (NL6-1, RR6-6)
pub fn inside_address(
    router: &Router,
) -> std::result::Result<Option<(Ipv4Addr, Ipv4Range)>, String> {
    let inside = router.spec.internal_addr.as_str();
    if inside.is_empty() {
        return Ok(None);
    }
    let host = inside
        .split_once('/')
        .and_then(|(host, _)| host.trim().parse::<Ipv4Addr>().ok());
    let Some(host) = host else {
        return Err(format!(
            "{inside:?} is not an address with its prefix length, like 10.30.0.1/24"
        ));
    };
    let prefix = inside.parse::<Ipv4Range>().map_err(|e| e.to_string())?;
    Ok(Some((host, prefix)))
}

/// The prefix `router`'s inside address is on: `inside_address` without the address.
pub fn inside_prefix(router: &Router) -> std::result::Result<Option<Ipv4Range>, String> {
    Ok(inside_address(router)?.map(|(_, prefix)| prefix))
}

/// `range` as the CIDR it is, or as a run of addresses where it is none.
pub fn cidr_of(range: &Ipv4Range) -> String {
    range.to_cidr().unwrap_or_else(|| range.to_string())
}

/// The prefix behind `router` where it reaches beyond what its tenant holds already, which only
/// the address space claimed by everybody else can judge (`ClaimedSpace::refusal_of`). (NL6-1)
///
/// It opens nothing new (`Ok(None)`) when the router names no inside address, or when the
/// prefix lies inside one of the tenant's own routed subnets (out of `subnets`) or, with a
/// network `declared` (the tenant's `networkPrefixes`, which an administrator writes and which
/// were judged against everybody else's addresses), inside one of its prefixes. With a network
/// declared, any other prefix is refused, and so is an inside address that cannot be read,
/// since what it would open is unknown. What is left is the prefix of a tenant that declares
/// no network (`Ok(Some(prefix))`).
pub fn prefix_beyond_own(
    router: &Router,
    subnets: &[RoutedSubnet],
    declared: &[String],
) -> std::result::Result<Option<Ipv4Range>, String> {
    let Some(prefix) = inside_prefix(router)? else {
        return Ok(None);
    };
    let tenant = router.spec.tenant.as_str();
    let own_subnets = subnets
        .iter()
        .filter(|s| s.spec.tenant == tenant)
        .map(|s| &s.spec.cidr);
    if covered_by_any(own_subnets, &prefix) || covered_by_any(declared, &prefix) {
        return Ok(None);
    }
    if !declared.is_empty() {
        return Err(format!(
            "{} is not inside tenant {tenant}'s network ({})",
            cidr_of(&prefix),
            declared.join(", ")
        ));
    }
    Ok(Some(prefix))
}

/// What a claim that did not decode costs: the address space it holds cannot be told.
const UNTOLD: &str =
    "the address space they claim cannot be told; refusing rather than letting a prefix onto it";

/// The address space claimed in a cloud, read together so that one judgement is made from one
/// picture of it: the floating pools, the routed subnets, the tenants' networks, the provider
/// networks' wires, and the routed pools from the cloud config.
pub struct ClaimedSpace {
    pub pools: Vec<FloatingPool>,
    pub subnets: Vec<RoutedSubnet>,
    pub tenants: Vec<Tenant>,
    pub provider_networks: Vec<ProviderNetwork>,
    pub routed_pools: Ipv4Ranges,
}

impl ClaimedSpace {
    /// Read through readers that refuse to answer from a partial list: a claim that did not
    /// decode is a claim a prefix would not be kept off.
    pub async fn read(store: &EtcdStore, routed_pools: Ipv4Ranges) -> Result<Self> {
        Ok(Self {
            pools: all_pools(store).await?,
            subnets: all_subnets(store).await?,
            tenants: store.list_complete(UNTOLD).await?,
            provider_networks: store.list_complete(UNTOLD).await?,
            routed_pools,
        })
    }

    /// The network prefixes `tenant` declares, empty for a tenant that declares none or is
    /// not there.
    pub fn network_of(&self, tenant: &str) -> &[String] {
        self.tenants
            .iter()
            .find(|t| t.metadata.name == tenant)
            .map_or(&[], |t| t.spec.network_prefixes.as_slice())
    }

    /// What the prefix behind `router` opens on the source allowlist of its tenant's taps
    /// beyond what is open there already, or why it may not open anything. (NL6-1)
    ///
    /// `spec.internalAddr` is the tenant's own to write, and the prefix it is on would let
    /// every guest of the tenant send from it. What the tenant holds already decides first
    /// (`prefix_beyond_own`); a prefix of a tenant that declares no network that lies beyond
    /// that is opened (`Ok(Some(prefix))`) unless it lies on somebody else's claim
    /// (`refusal_of`).
    pub fn opened_by_router(
        &self,
        router: &Router,
        declared: &[String],
    ) -> std::result::Result<Option<Ipv4Range>, String> {
        let Some(prefix) = prefix_beyond_own(router, &self.subnets, declared)? else {
            return Ok(None);
        };
        match self.refusal_of(&router.spec.tenant, &prefix) {
            Some(why) => Err(why),
            None => Ok(Some(prefix)),
        }
    }

    /// Why `prefix`, behind a router of `tenant`, which declares no network, may not be opened:
    /// it overlaps a floating pool, another tenant's routed subnet or network, the routed pools
    /// or a provider network's wire. `None` where it lies on none of them.
    pub fn refusal_of(&self, tenant: &str, prefix: &Ipv4Range) -> Option<String> {
        self.off_limits_to_inside_prefix(tenant)
            .into_iter()
            .find(|(_, range)| range.overlaps(prefix))
            .map(|(what, _)| {
                format!(
                    "{} overlaps {what}; tenant {tenant} declares no network its routers' \
                     prefixes could lie in",
                    cidr_of(prefix)
                )
            })
    }

    /// What the prefix behind a router of `tenant`, which declares no network, may not
    /// overlap: what a declared network may not either (the floating pools, the other
    /// tenants' routed subnets, the routed pools; `off_limits_to_tenant`), and besides the
    /// other tenants' networks and the provider networks' wires. The prefix is the tenant's
    /// own word; theirs are an administrator's.
    ///
    /// A member reads the refusal, and the pass's event on its router: another tenant's
    /// routed subnet or network is named by its kind, never by its name, owner or range.
    fn off_limits_to_inside_prefix(&self, tenant: &str) -> Vec<(String, Ipv4Range)> {
        let others_subnets = self
            .subnets
            .iter()
            .filter(|s| s.spec.tenant != tenant)
            .filter_map(|s| s.spec.cidr.parse::<Ipv4Range>().ok())
            .map(|range| ("another tenant's routed subnet".to_string(), range));
        let routed_pools = self
            .routed_pools
            .ranges()
            .iter()
            .map(|range| ("the routed pools".to_string(), *range));
        let others_networks = tenant_networks(&self.tenants, Some(tenant))
            .into_iter()
            .map(|(_, range)| ("another tenant's network".to_string(), range));

        let mut taken = occupied(&self.pools, &[], None);
        taken.extend(others_subnets);
        taken.extend(routed_pools);
        taken.extend(others_networks);
        taken.extend(provider_wires(&self.provider_networks));
        taken
    }
}

/// Whether one of `entries` holds all of `prefix`.
fn covered_by_any<'a>(entries: impl IntoIterator<Item = &'a String>, prefix: &Ipv4Range) -> bool {
    entries
        .into_iter()
        .filter_map(|entry| entry.parse::<Ipv4Range>().ok())
        .any(|range| range.covers(prefix))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::resources::{
        FloatingPoolSpec, ProviderNetworkSpec, RoutedSubnetSpec, RouterSpec, TenantSpec,
    };

    fn router(tenant: &str, inside: &str) -> Router {
        Router::declare(
            &format!("{tenant}-out"),
            RouterSpec {
                tenant: tenant.into(),
                provider_network: "ext".into(),
                internal_addr: inside.into(),
                ..Default::default()
            },
        )
    }

    fn tenant(name: &str, prefixes: &[&str]) -> Tenant {
        Tenant::declare(
            name,
            TenantSpec {
                network_prefixes: prefixes.iter().map(|p| p.to_string()).collect(),
                ..Default::default()
            },
        )
    }

    /// A cloud with a floating pool, a routed subnet of `rival`, `rival`'s declared network,
    /// a provider network and routed pools.
    fn claimed() -> ClaimedSpace {
        ClaimedSpace {
            pools: vec![FloatingPool::declare(
                "lab",
                FloatingPoolSpec {
                    cidrs: vec!["198.51.100.0/24".into()],
                    ..Default::default()
                },
            )],
            subnets: vec![RoutedSubnet::declare(
                "theirs",
                RoutedSubnetSpec {
                    tenant: "rival".into(),
                    cidr: "10.7.2.0/24".into(),
                    ..Default::default()
                },
            )],
            tenants: vec![tenant("acme", &[]), tenant("rival", &["10.50.0.0/16"])],
            provider_networks: vec![ProviderNetwork::declare(
                "ext",
                ProviderNetworkSpec {
                    physnet: "ext".into(),
                    cidr: "10.172.0.0/24".into(),
                    ..Default::default()
                },
            )],
            routed_pools: Ipv4Ranges::parse(&["10.7.0.0/16".to_string()]).expect("ranges"),
        }
    }

    /// Why `router`'s prefix may not open, or nothing when it may.
    fn refusal(space: &ClaimedSpace, router: &Router, declared: &[String]) -> Option<String> {
        space.opened_by_router(router, declared).err()
    }

    /// A tenant that declares its network keeps its routers' prefixes inside it: one that
    /// lies wholly in a declared prefix opens nothing new, one that only overlaps it is
    /// refused.
    #[test]
    fn a_declared_network_holds_its_routers_prefixes() {
        let space = claimed();
        let declared = ["10.30.0.0/16".to_string()];
        assert_eq!(
            space.opened_by_router(&router("acme", "10.30.4.1/24"), &declared),
            Ok(None)
        );
        let why = refusal(&space, &router("acme", "10.30.0.1/15"), &declared)
            .expect("sticks out of the network");
        assert!(why.contains("not inside tenant acme's network"), "{why}");
    }

    /// Without a declared network a router's prefix may lie on nothing somebody else claims,
    /// and the refusal names what it lies on, another tenant's claim by its kind alone.
    #[test]
    fn an_undeclared_tenants_router_prefix_stays_off_every_other_claim() {
        let space = claimed();
        for (inside, what) in [
            ("198.51.100.1/25", "floating pool lab"),
            ("10.7.2.1/24", "another tenant's routed subnet"),
            ("10.50.3.1/24", "another tenant's network"),
            ("10.7.9.1/24", "the routed pools"),
            ("10.172.0.1/24", "provider network ext"),
            ("128.0.0.1/1", "floating pool lab"),
        ] {
            let why = refusal(&space, &router("acme", inside), &[])
                .unwrap_or_else(|| panic!("{inside} lies on {what}"));
            assert!(why.contains(what), "{inside}: {why}");
            assert!(!why.contains("rival") && !why.contains("theirs"), "{why}");
        }
    }

    /// Without a declared network a router's prefix on nobody's claim is opened.
    #[test]
    fn an_undeclared_tenants_free_router_prefix_is_opened() {
        let opened = claimed()
            .opened_by_router(&router("acme", "10.42.0.1/24"), &[])
            .expect("free")
            .map(|prefix| cidr_of(&prefix));
        assert_eq!(opened.as_deref(), Some("10.42.0.0/24"));
    }

    /// A prefix inside the tenant's own routed subnet opens nothing the subnet does not, even
    /// where the subnet was cut from the routed pools.
    #[test]
    fn a_router_prefix_inside_its_tenants_own_routed_subnet_opens_nothing_new() {
        assert_eq!(
            claimed().opened_by_router(&router("rival", "10.7.2.1/25"), &[]),
            Ok(None)
        );
    }

    /// An inside address that is no address with a prefix length is refused, since what it
    /// would open cannot be told.
    #[test]
    fn an_unreadable_inside_address_is_refused() {
        let space = claimed();
        for inside in [
            "10.42.0.1",
            "10.42.0.0-10.42.0.9/24",
            "nonsense/24",
            "10.42.0.1/33",
        ] {
            assert!(
                refusal(&space, &router("acme", inside), &[]).is_some(),
                "{inside}"
            );
        }
    }

    /// A router without an inside address opens nothing.
    #[test]
    fn a_router_without_an_inside_address_opens_nothing() {
        assert_eq!(
            claimed().opened_by_router(&router("acme", ""), &[]),
            Ok(None)
        );
    }

    /// A provider network that names no CIDR is known by its allocation and its gateway.
    #[test]
    fn a_provider_network_without_a_cidr_is_its_allocation_and_gateway() {
        let wires = provider_wires(&[ProviderNetwork::declare(
            "dmz",
            ProviderNetworkSpec {
                physnet: "dmz".into(),
                gateway: "192.0.2.1".into(),
                allocation: vec!["192.0.2.10-192.0.2.20".into()],
                ..Default::default()
            },
        )]);
        let ranges: Vec<String> = wires.iter().map(|(_, r)| r.to_string()).collect();
        assert_eq!(ranges, ["192.0.2.10-192.0.2.20", "192.0.2.1"]);
    }
}
