// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! The address half of the pass: what this tier knows about a VM's addresses
//! and how it gets stamped onto the object. Moved out of `reconcile.rs`
//! unchanged.

use super::*;

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
    /// The objects the two lists above were read out of, each with the
    /// generation it carried at that moment.
    ///
    /// The generation is captured HERE and not read again at stamping time,
    /// and that is the whole honesty of the field: an assign that lands
    /// between building this command and writing the status has not
    /// travelled, and claiming it had would make `APPLIED` a lie in exactly
    /// the window the column exists to show.
    pub(super) carried: Vec<Carried>,
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
    pub(super) subnets: Vec<controller_api::RoutedSubnet>,
    /// The tenants' routers, for the prefix their inside leg is on.
    pub(super) routers: Vec<controller_api::Router>,
}

/// The PREFIX a router's inside address is on: `10.30.0.1/24` → `10.30.0.0/24`.
///
/// The address is the router's own and the prefix is the tenant's, and it is
/// the prefix the guests source from. Written out rather than passed through,
/// because a tap allow-list holding `10.30.0.1/24` would read as the single
/// host in some renderings and as the whole subnet in others — and this list
/// is what decides whether a tenant's packets live or die.
fn inside_prefix(addr: &str) -> Option<String> {
    let (host, bits) = addr.split_once('/')?;
    let bits: u32 = bits.parse().ok()?;
    let host: std::net::Ipv4Addr = host.parse().ok()?;
    let mask = if bits == 0 {
        0
    } else {
        u32::MAX << (32 - bits.min(32))
    };
    let network = std::net::Ipv4Addr::from(u32::from(host) & mask);
    Some(format!("{network}/{bits}"))
}

impl AddressBook {
    /// Through the two readers that refuse to answer from a partial list —
    /// an undecodable object here is an address handed to the wrong VM.
    pub(super) async fn read(store: &EtcdStore) -> anyhow::Result<Self> {
        Ok(Self {
            reservations: controller_api::floating::all_reservations(store).await?,
            subnets: controller_api::floating::all_subnets(store).await?,
            routers: store.list::<controller_api::Router>().await?,
        })
    }

    /// What `vm` may send from. `declared` are the network prefixes of its tenant
    /// (`TenantSpec::network_prefixes`), which the caller read with the tenant.
    pub(super) fn for_vm(&self, vm: &Vm, declared: &[String]) -> Addresses {
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

        let mut source_prefixes: Vec<String> = self
            .subnets
            .iter()
            .filter(|s| s.spec.tenant == tenant)
            .map(|s| s.spec.cidr.clone())
            .collect();
        source_prefixes.extend(self.network_prefixes(tenant, declared));
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
        }
    }

    /// The prefixes of `tenant`'s overlay network: those `declared` on the tenant, which hold
    /// whether a router is there or not, and the one behind each of its routers, which goes
    /// with the router. A guest addresses itself out of them, and SNAT behind a router needs
    /// them too, so they are on the allowlist whatever routed subnets the tenant has. (NL5-1)
    fn network_prefixes<'a>(
        &'a self,
        tenant: &'a str,
        declared: &'a [String],
    ) -> impl Iterator<Item = String> + 'a {
        let behind_routers = self
            .routers
            .iter()
            .filter(move |r| r.spec.tenant == tenant)
            .map(|r| r.spec.internal_addr.as_str())
            .filter(|addr| !addr.is_empty())
            .filter_map(inside_prefix);
        declared.iter().cloned().chain(behind_routers)
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
