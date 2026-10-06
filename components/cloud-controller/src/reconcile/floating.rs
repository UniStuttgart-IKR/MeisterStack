// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! The address half of the pass: what this tier knows about a VM's addresses
//! and how it gets stamped onto the object. Moved out of `reconcile.rs`
//! unchanged.

use super::*;

use anyhow::Context as _;
use common::net::Ipv4Ranges;
use controller_api::address_space::{self, ClaimedSpace};

/// What a VM may source from, resolved where the objects are.
///
/// The same split `tenant_network` makes and for the same reason: the FloatingIp
/// and RoutedSubnet objects live at the cloud, the injection into the NIC
/// entries happens at the cluster, and no tier below this one has to know what
/// a tenant is. A VM with no tenant holds nothing — a reservation belongs to a
/// tenant by definition, so an unscoped VM has no way to be given one.
#[derive(Default)]
pub(super) struct Addresses {
    pub(super) floating_ips: Vec<String>,
    /// The prefixes the VM's guest may send from: those of its tenant's network and its
    /// tenant's routed subnets, sorted and each once. They travel in `CreateVm.routed_subnets`,
    /// the name the wire had before the network's own prefixes went into it; a field of their
    /// own would be dropped by a cluster or refused by an agent of the release before.
    pub(super) source_prefixes: Vec<String>,
    /// The FloatingIp and RoutedSubnet objects the two lists above were read
    /// out of, each with the generation it carried at that moment. The
    /// prefixes declared on the tenant and those behind its routers are in
    /// `source_prefixes` too, but neither the Tenant nor a Router is carried
    /// or stamped: whether a change of theirs reached a node is not recorded.
    ///
    /// The generation is captured HERE and not read again at stamping time,
    /// and that is the whole honesty of the field: an assign that lands
    /// between building this command and writing the status has not
    /// travelled, and claiming it had would make `APPLIED` a lie in exactly
    /// the window the column exists to show.
    pub(super) carried: Vec<Carried>,
    /// The routers of the VM's tenant whose inside prefix is kept off `source_prefixes`, and
    /// why: said on the router by `note_refused_prefixes`. (NL6-1)
    pub(super) refused: Vec<RefusedPrefix>,
}

/// A router whose inside prefix is kept off its tenant's taps, and why. (NL6-1)
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct RefusedPrefix {
    pub(super) router: String,
    pub(super) uid: String,
    pub(super) tenant: String,
    pub(super) why: String,
}

impl RefusedPrefix {
    fn of(router: &controller_api::Router, why: String) -> Self {
        Self {
            router: router.metadata.name.clone(),
            uid: router.metadata.uid.clone(),
            tenant: router.spec.tenant.clone(),
            why,
        }
    }
}

/// One object a `CreateVm` was built out of, as it was when it was read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Carried {
    pub(super) resource: &'static str,
    pub(super) name: String,
    /// Which object of that name: the stamp lands on this one or on none.
    pub(super) uid: String,
    pub(super) generation: u64,
}

impl Carried {
    fn of<S, St>(object: &controller_api::Object<S, St>, resource: &'static str) -> Self {
        Self {
            resource,
            name: object.metadata.name.clone(),
            uid: object.metadata.uid.clone(),
            generation: object.metadata.generation,
        }
    }
}

/// Address and router inventory cached for one reconcile pass.
/// Load lazily on the first dispatch to avoid repeated store listings for each
/// VM after a cluster restart. Discard at the end of the pass; subsequent passes
/// must observe allocation changes.
pub(super) struct AddressBook {
    pub(super) reservations: Vec<controller_api::FloatingIp>,
    /// The routed subnets: a tenant's guests send from its own, and the prefix behind its
    /// router opens nothing new inside them.
    pub(super) subnets: Vec<controller_api::RoutedSubnet>,
    /// The tenants' routers, for the prefix their inside leg is on.
    pub(super) routers: Vec<controller_api::Router>,
}

/// The pass's `AddressBook`, read by the first dispatch that asks for it: most passes
/// dispatch nothing, and those must go on costing nothing. The address space claimed in the
/// cloud is read apart from it, by the first dispatch whose router prefix has to be judged
/// against it: an object there that does not decode stops those dispatches and no others.
/// (RR6-3)
pub(super) struct LazyBook<'a> {
    book: OnceCell<AddressBook>,
    claimed: OnceCell<ClaimedSpace>,
    /// The routed pools from the cloud config, which a router's prefix may not lie on.
    routed_pools: &'a Ipv4Ranges,
}

impl<'a> LazyBook<'a> {
    pub(super) fn new(routed_pools: &'a Ipv4Ranges) -> Self {
        Self {
            book: OnceCell::new(),
            claimed: OnceCell::new(),
            routed_pools,
        }
    }

    /// What `vm` may send from (`AddressBook::for_vm`), with the address space claimed in the
    /// cloud read only where a router prefix of its tenant reaches beyond what the tenant holds.
    /// Where that cannot be read, this dispatch fails, as one whose tenant or routers cannot be
    /// read does: a list handed down without the prefix would cut a running guest off it on a
    /// read that failed, not on a claim that was found.
    pub(super) async fn addresses(
        &self,
        store: &EtcdStore,
        vm: &Vm,
        declared: &[String],
    ) -> anyhow::Result<Addresses> {
        let book = self
            .book
            .get_or_try_init(|| AddressBook::read(store))
            .await?;
        let claimed = match book.tenant_reaching_beyond_own(vm, declared) {
            Some(tenant) => Some(self.claimed(store).await.with_context(|| {
                format!("judging the prefix behind a router of tenant {tenant}")
            })?),
            None => None,
        };
        Ok(book.for_vm(vm, declared, claimed))
    }

    /// The address space claimed in the cloud, read on the first call of the pass.
    async fn claimed(&self, store: &EtcdStore) -> anyhow::Result<&ClaimedSpace> {
        Ok(self
            .claimed
            .get_or_try_init(|| ClaimedSpace::read(store, self.routed_pools.clone()))
            .await?)
    }
}

/// Every router, refusing to answer from a partial list: a router that did not decode would
/// take the prefix behind it off its tenant's taps, and with nothing else named a re-send would
/// open them from the allowlist to the pool ban. One listing, so a router created or deleted
/// between two reads cannot pass for one that did not decode. (RR5-2)
async fn all_routers(store: &EtcdStore) -> anyhow::Result<Vec<controller_api::Router>> {
    Ok(store
        .list_complete(
            "the prefixes behind them cannot be named; refusing rather than guarding their \
             tenants' taps on a list without them",
        )
        .await?)
}

impl AddressBook {
    /// Through the three readers that refuse to answer from a partial list —
    /// an undecodable object here is an address handed to the wrong VM, or a
    /// prefix taken off a tap that sends from it.
    pub(super) async fn read(store: &EtcdStore) -> anyhow::Result<Self> {
        Ok(Self {
            reservations: controller_api::floating::all_reservations(store).await?,
            subnets: controller_api::floating::all_subnets(store).await?,
            routers: all_routers(store).await?,
        })
    }

    /// The tenant of `vm`, where a router of it has a prefix beyond what the tenant holds
    /// (`address_space::prefix_beyond_own`): only the address space claimed in the cloud can
    /// judge that one. `declared` as for `for_vm`.
    pub(super) fn tenant_reaching_beyond_own<'v>(
        &self,
        vm: &'v Vm,
        declared: &[String],
    ) -> Option<&'v str> {
        let tenant = vm.spec.tenant.as_deref().filter(|t| !t.is_empty())?;
        self.routers_of(tenant)
            .any(|r| matches!(self.beyond_own(r, declared), Ok(Some(_))))
            .then_some(tenant)
    }

    /// What `vm` may send from. `declared` are the network prefixes of its tenant
    /// (`TenantSpec::network_prefixes`), which the caller read with the tenant. `claimed` judges
    /// a router prefix beyond what the tenant holds; without it, such a prefix is kept off.
    pub(super) fn for_vm(
        &self,
        vm: &Vm,
        declared: &[String],
        claimed: Option<&ClaimedSpace>,
    ) -> Addresses {
        let Some(tenant) = vm.spec.tenant.as_deref().filter(|t| !t.is_empty()) else {
            return Addresses::default();
        };
        let name = vm.metadata.name.as_str();

        // Both filters name the tenant as well as the VM. A VM name is unique
        // in this store so the tenant is redundant today — and it is the check
        // that keeps it redundant: an assignment that somehow named another
        // tenant's VM must not become that VM's permission to use the address.
        let mine = |ip: &&controller_api::FloatingIp| {
            ip.spec.tenant == tenant && ip.spec.vm.as_deref() == Some(name)
        };
        let mut floating_ips: Vec<String> = self
            .reservations
            .iter()
            .filter(mine)
            .map(|ip| ip.spec.address.clone())
            .collect();
        floating_ips.sort();

        let (network, refused) = self.network_prefixes(tenant, declared, claimed);
        let mut source_prefixes: Vec<String> = self
            .subnets
            .iter()
            .filter(|s| s.spec.tenant == tenant)
            .map(|s| s.spec.cidr.clone())
            .chain(network)
            .collect();
        source_prefixes.sort();
        source_prefixes.dedup();

        let carried: Vec<Carried> = self
            .reservations
            .iter()
            .filter(mine)
            .map(|ip| Carried::of(ip, controller_api::FloatingIp::RESOURCE))
            .chain(
                self.subnets
                    .iter()
                    .filter(|s| s.spec.tenant == tenant)
                    .map(|s| Carried::of(s, controller_api::RoutedSubnet::RESOURCE)),
            )
            .collect();

        if !floating_ips.is_empty() || !source_prefixes.is_empty() {
            debug!(vm = %name, tenant, floating = ?floating_ips, prefixes = ?source_prefixes,
                   "resolved the addresses this vm may source from");
        }
        Addresses {
            floating_ips,
            source_prefixes,
            carried,
            refused,
        }
    }

    /// The prefixes of `tenant`'s overlay network, and the routers whose prefix is kept off
    /// them. A guest addresses itself out of them, and SNAT behind a router needs them too, so
    /// they are on the allowlist whatever routed subnets the tenant has. (NL5-1)
    ///
    /// The network `declared` on the tenant holds whether a router is there or not. The prefix
    /// behind each of its routers is added where it opens something (`opened_by`), and goes
    /// with the router; with a network declared, a router's prefix lies inside it and adds
    /// nothing, or is refused. A prefix that lies on somebody else's claim is never opened,
    /// whatever was admitted when the router was written. (NL6-1)
    fn network_prefixes(
        &self,
        tenant: &str,
        declared: &[String],
        claimed: Option<&ClaimedSpace>,
    ) -> (Vec<String>, Vec<RefusedPrefix>) {
        let mut prefixes = declared.to_vec();
        let mut refused = Vec::new();
        for router in self.routers_of(tenant) {
            match self.opened_by(router, declared, claimed) {
                Ok(opened) => prefixes.extend(opened.map(|p| address_space::cidr_of(&p))),
                Err(why) => refused.push(RefusedPrefix::of(router, why)),
            }
        }
        (prefixes, refused)
    }

    /// What the prefix behind `router` opens on its tenant's taps, as
    /// `ClaimedSpace::opened_by_router` judges it, with the tenant's own subnets out of this
    /// book. A prefix beyond what the tenant holds is judged by `claimed`, and kept off
    /// without it: what it would lie on is unknown.
    fn opened_by(
        &self,
        router: &controller_api::Router,
        declared: &[String],
        claimed: Option<&ClaimedSpace>,
    ) -> Result<Option<common::net::Ipv4Range>, String> {
        let Some(prefix) = self.beyond_own(router, declared)? else {
            return Ok(None);
        };
        let claimed = claimed.ok_or_else(|| {
            format!(
                "{} could not be judged against the address space claimed in the cloud",
                address_space::cidr_of(&prefix)
            )
        })?;
        match claimed.refusal_of(&router.spec.tenant, &prefix) {
            Some(why) => Err(why),
            None => Ok(Some(prefix)),
        }
    }

    /// `address_space::prefix_beyond_own` with the routed subnets of this book.
    fn beyond_own(
        &self,
        router: &controller_api::Router,
        declared: &[String],
    ) -> Result<Option<common::net::Ipv4Range>, String> {
        address_space::prefix_beyond_own(router, &self.subnets, declared)
    }

    /// The routers of `tenant`.
    fn routers_of<'a>(
        &'a self,
        tenant: &'a str,
    ) -> impl Iterator<Item = &'a controller_api::Router> + 'a {
        self.routers.iter().filter(move |r| r.spec.tenant == tenant)
    }
}

/// Say that a router's inside prefix is kept off its tenant's taps: in the log, and as an event
/// on the router, which its tenant sees. Every dispatch that leaves it off says so again, and
/// the event counts them. (NL6-1)
pub(super) async fn note_refused_prefixes(store: &EtcdStore, refused: &[RefusedPrefix]) {
    for r in refused {
        warn!(router = %r.router, tenant = %r.tenant, why = %r.why,
              "a router's inside prefix is kept off its tenant's taps");
        events::record(
            store,
            Happening {
                kind: controller_api::Router::KIND,
                name: &r.router,
                uid: &r.uid,
                reason: events::reason::INSIDE_PREFIX_REFUSED,
                message: format!("its inside prefix is kept off the tenant's taps: {}", r.why),
                event_type: EventType::Warning,
                tenant: Some(&r.tenant),
            },
        )
        .await;
    }
}

/// Write back what a `CreateVm` really carried.
///
/// Only on the acked branch, and only upwards (`max`): a dispatch that was
/// refused carried nothing, and a late write from an older pass must not undo
/// a newer one's. On the uid that was read: an address released and reserved
/// again under the same name did not travel. (IKR-B81)
pub(super) async fn stamp_addresses(store: &EtcdStore, carried: &[Carried]) {
    for Carried {
        resource,
        name,
        uid,
        generation,
    } in carried
    {
        let generation = *generation;
        let outcome = if *resource == controller_api::FloatingIp::RESOURCE {
            store
                .mutate_if::<controller_api::FloatingIp, _>(name, uid, |ip| {
                    ip.status.observed_generation = ip.status.observed_generation.max(generation);
                })
                .await
                .map(|_| ())
        } else {
            store
                .mutate_if::<controller_api::RoutedSubnet, _>(name, uid, |s| {
                    s.status.observed_generation = s.status.observed_generation.max(generation);
                })
                .await
                .map(|_| ())
        };
        // Debug, not warn: the command went out, which is the fact that
        // matters. A bookkeeping write that lost is re-made by the next pass,
        // and an address whose object is gone was released while we dispatched
        // — neither is a reason to shout at the operator.
        if let Err(e) = outcome {
            debug!(%resource, %name, error = format!("{e:#}"), "could not record what was dispatched");
        }
    }
}

/// Stamp cloud-owned floating addresses while preserving node-reported MACs.
/// `session::ingest_placements` owns the MAC entries. Both writers use
/// `mirror::addresses_with` ordering to avoid rewriting each other's output.
pub(super) async fn stamp_vm_addresses(store: &EtcdStore, vms: &[Vm]) -> anyhow::Result<()> {
    let reservations = controller_api::floating::all_reservations(store).await?;
    for vm in vms {
        let want = addresses_of(&reservations, vm);
        if vm.status.addresses == want {
            continue;
        }
        let name = vm.metadata.name.clone();
        if let Err(e) = store
            .mutate_if::<Vm, _>(&name, &vm.metadata.uid, |v| {
                v.status.addresses = want.clone()
            })
            .await
        {
            // Debug: bookkeeping nothing decides on, and the next pass writes
            // it again.
            debug!(vm = %name, error = format!("{e:#}"), "recording the addresses failed");
        }
    }
    Ok(())
}

/// The lines this VM's status should carry: whatever is already there that
/// this tier does not own, plus the floating addresses pointed at it.
///
/// The tenant is named as well as the VM, exactly as `AddressBook::for_vm`
/// does and for the same reason: an assignment that somehow named another
/// tenant's VM must not become that VM's address.
pub(super) fn addresses_of(
    reservations: &[controller_api::FloatingIp],
    vm: &Vm,
) -> Vec<controller_api::VmAddress> {
    let mut lines: Vec<controller_api::VmAddress> = vm
        .status
        .addresses
        .iter()
        .filter(|a| a.kind != controller_api::VmAddressKind::FloatingIp)
        .cloned()
        .collect();
    let Some(tenant) = vm.spec.tenant.as_deref().filter(|t| !t.is_empty()) else {
        return lines;
    };
    let name = vm.metadata.name.as_str();
    let mut floating: Vec<controller_api::VmAddress> = reservations
        .iter()
        .filter(|ip| ip.spec.tenant == tenant && ip.spec.vm.as_deref() == Some(name))
        .map(|ip| controller_api::VmAddress {
            kind: controller_api::VmAddressKind::FloatingIp,
            address: Some(ip.spec.address.clone()),
            ..controller_api::VmAddress::default()
        })
        .collect();
    // Sorted, so two passes over the same facts write the same document and
    // the second one writes nothing at all.
    floating.sort_by(|a, b| a.address.cmp(&b.address));
    lines.extend(floating);
    lines
}
