// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! The address half of the pass: what this tier knows about a VM's addresses
//! and how it gets stamped onto the object. Moved out of `reconcile.rs`
//! unchanged.

use super::*;

/// What a VM may source from, resolved where the objects are.
///
/// The same split `tenant_vni` makes and for the same reason: the FloatingIp
/// and RoutedSubnet objects live at the cloud, the injection into the NIC
/// entries happens at the cluster, and no tier below this one has to know what
/// a tenant is. A VM with no tenant holds nothing — a reservation belongs to a
/// tenant by definition, so an unscoped VM has no way to be given one.
#[derive(Default)]
pub(super) struct Addresses {
    pub(super) floating_ips: Vec<String>,
    pub(super) routed_subnets: Vec<String>,
    /// The objects the two lists above were read out of, each with the
    /// generation it carried at that moment — `(resource, name, generation)`.
    ///
    /// The generation is captured HERE and not read again at stamping time,
    /// and that is the whole honesty of the field: an assign that lands
    /// between building this command and writing the status has not
    /// travelled, and claiming it had would make `APPLIED` a lie in exactly
    /// the window the column exists to show.
    pub(super) carried: Vec<(&'static str, String, u64)>,
}

/// Both registries, read once and then asked about per VM.
///
/// A dispatch used to list them for itself, and the note that stood here said
/// so on purpose: a cached answer would be a VM booting with the addresses
/// somebody held an hour ago. That reason is kept and its scope is made exact
/// — the book lives for ONE reconcile pass and is thrown away with it, so the
/// oldest answer it can give is milliseconds old.
///
/// What that buys is the amplification, which the old note underestimated:
/// `missing` and `drifted` are level conditions, so a pass after a cluster
/// restart dispatches EVERY VM it holds, and each of those did two listings
/// and two counts of its own — four etcd round trips per VM, all of them
/// serialized behind the one store client, for two answers that are identical
/// across the whole pass.
///
/// Filled lazily (see `pass`), which is what keeps the common case free: a
/// pass that dispatches nothing still reads nothing.
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

    pub(super) fn for_vm(&self, vm: &Vm) -> Addresses {
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

        let mut routed_subnets: Vec<String> = self
            .subnets
            .iter()
            .filter(|s| s.spec.tenant == tenant)
            .map(|s| s.spec.cidr.clone())
            .collect();
        // And the private prefix behind this tenant's router.
        //
        // The node turns this list into "these addresses and nothing else"
        // for the tap, so a list that names only the ROUTED subnets fences a
        // tenant out of its own overlay: the guests on the router's inside
        // wire — the ordinary ones, the whole point of `snat` — source from a
        // prefix nobody wrote down, and every packet they send is dropped by
        // `src-ip`. Seen in the lab the moment a tenant had both: the guest
        // with a routed address got through and the guest behind SNAT beside
        // it had 57 packets dropped on its own tap.
        //
        // It is the same statement the routed subnets make — where this
        // tenant's addresses are — and it comes from the same place the rest
        // of the router's facts do.
        routed_subnets.extend(
            self.routers
                .iter()
                .filter(|r| r.spec.tenant == tenant)
                .map(|r| r.spec.internal_addr.as_str())
                .filter(|addr| !addr.is_empty())
                .filter_map(inside_prefix),
        );
        routed_subnets.sort();
        routed_subnets.dedup();

        let carried: Vec<(&'static str, String, u64)> = self
            .reservations
            .iter()
            .filter(mine)
            .map(|ip| {
                (
                    controller_api::FloatingIp::RESOURCE,
                    ip.metadata.name.clone(),
                    ip.metadata.generation,
                )
            })
            .chain(
                self.subnets
                    .iter()
                    .filter(|s| s.spec.tenant == tenant)
                    .map(|s| {
                        (
                            controller_api::RoutedSubnet::RESOURCE,
                            s.metadata.name.clone(),
                            s.metadata.generation,
                        )
                    }),
            )
            .collect();

        if !floating_ips.is_empty() || !routed_subnets.is_empty() {
            debug!(vm = %name, tenant, floating = ?floating_ips, subnets = ?routed_subnets,
                   "resolved the addresses this vm may source from");
        }
        Addresses {
            floating_ips,
            routed_subnets,
            carried,
        }
    }
}

/// Write back what a `CreateVm` really carried.
///
/// Only on the acked branch, and only upwards (`max`): a dispatch that was
/// refused carried nothing, and a late write from an older pass must not undo
/// a newer one's.
pub(super) async fn stamp_addresses(store: &EtcdStore, carried: &[(&'static str, String, u64)]) {
    for (resource, name, generation) in carried {
        let generation = *generation;
        let outcome = if *resource == controller_api::FloatingIp::RESOURCE {
            store
                .mutate::<controller_api::FloatingIp, _>(name, |ip| {
                    ip.status.observed_generation = ip.status.observed_generation.max(generation);
                })
                .await
                .map(|_| ())
        } else {
            store
                .mutate::<controller_api::RoutedSubnet, _>(name, |s| {
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

/// Write down what this cloud knows about reaching each VM.
///
/// Its own small pass rather than a field the status ingest watches, and for
/// the same reason the node pass above it is one: the facts come from
/// somewhere else than a cluster's report, and a matcher that compared them
/// against one would call every report a change.
///
/// The floating half is complete — an assignment is this cloud's own object
/// and needs nobody's word for it. The MAC half belongs to the other writer
/// of this same list: it starts at a node's tap and arrives through
/// `session::ingest_placements`. So `Mac` lines are never written here and
/// never removed here, and the two passes agree on the ORDER as well as the
/// content — this one keeps what it does not own and appends its own after
/// it, and the MAC writer does the mirror image (`mirror::addresses_with`).
/// Two passes that disagreed would rewrite each other's document for ever.
pub(super) async fn stamp_vm_addresses(store: &EtcdStore, vms: &[Vm]) -> anyhow::Result<()> {
    let reservations = controller_api::floating::all_reservations(store).await?;
    for vm in vms {
        let want = addresses_of(&reservations, vm);
        if vm.status.addresses == want {
            continue;
        }
        let name = vm.metadata.name.clone();
        if let Err(e) = store
            .mutate::<Vm, _>(&name, |v| v.status.addresses = want.clone())
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
