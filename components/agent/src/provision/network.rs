// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Create VM taps and tenant overlays, and keep the taps' address guards on the
//! lists a re-sent spec names. Overlay VM ownership is derived from persisted
//! records; the bridge driver also protects router and kernel users.

use super::*;
use crate::types::NicWithId;
use agent_api::networking::{NetworkError, NicId, NicSpec};

/// Sorted, distinct VNIs requested by the persisted specification. Runtime NIC
/// attachments contain tap details but do not retain the VNI.
pub(crate) fn overlay_vnis(record: &VmRecord) -> Vec<u32> {
    let mut out: Vec<u32> = record
        .spec
        .nics
        .iter()
        .filter_map(|n| n.spec.vxlan_id)
        .collect();
    out.sort_unstable();
    out.dedup();
    out
}

/// Count other VM records that name this VNI. Exclude the VM being removed,
/// whose row remains until teardown completes. Count every undecodable row as
/// a possible user so incomplete inventory cannot authorize overlay deletion.
pub(crate) fn overlay_users(store: &Store, vni: u32, except: &VmId) -> Result<usize> {
    let mut users = 0;
    for (key, bytes) in store.list_raw()? {
        // The VM being torn down is not a user of its own overlay, whatever
        // state its record is in.
        if key.parse::<VmId>().is_ok_and(|id| &id == except) {
            continue;
        }
        match serde_json::from_slice::<VmRecord>(&bytes) {
            Ok(record) if overlay_vnis(&record).contains(&vni) => users += 1,
            Ok(_) => {}
            Err(e) => {
                warn!(
                    key = %key, vni, error = %format!("{e:#}"),
                    "a record here cannot be read; counting it as a user of this overlay"
                );
                users += 1;
            }
        }
    }
    Ok(users)
}

/// Whether a guest behind `wanted` may send from exactly the addresses `held` allows.
fn same_addresses(held: &NicSpec, wanted: &NicSpec) -> bool {
    held.floating_ips == wanted.floating_ips && held.routed_subnets == wanted.routed_subnets
}

/// Whether `wanted` hangs the NIC on the same wire with the same MAC as `held`.
fn same_wiring(held: &NicSpec, wanted: &NicSpec) -> bool {
    held.bridge == wanted.bridge
        && held.mac == wanted.mac
        && held.vxlan_id == wanted.vxlan_id
        && held.physnet == wanted.physnet
}

/// `held` as it was created, with the address lists of `wanted`.
fn readdressed(held: &NicSpec, wanted: &NicSpec) -> NicSpec {
    NicSpec {
        floating_ips: wanted.floating_ips.clone(),
        routed_subnets: wanted.routed_subnets.clone(),
        ..held.clone()
    }
}

/// The positions at which a re-sent spec changes a held NIC's address lists. NICs pair up by
/// position, the way `types::nic_id` derives their ids, so a record whose ids were rolled at
/// random still pairs with its re-sent spec.
fn readdressed_positions(held: &[NicWithId], wanted: &[NicWithId]) -> Vec<usize> {
    held.iter()
        .zip(wanted)
        .enumerate()
        .filter(|(_, (h, w))| !same_addresses(&h.spec, &w.spec))
        .map(|(position, _)| position)
        .collect()
}

/// Whether a re-sent spec adds, drops or rewires a NIC, which no existing VM takes in place.
fn nics_rewired(held: &[NicWithId], wanted: &[NicWithId]) -> bool {
    held.len() != wanted.len()
        || held
            .iter()
            .zip(wanted)
            .any(|(h, w)| !same_wiring(&h.spec, &w.spec))
}

impl Provisioner {
    /// Bring the address guards of an existing VM's NICs to a re-sent spec (NL4-1).
    ///
    /// A subnet or floating address taken from the VM must stop being a source its guest may
    /// send from now, not at the next provisioning. Per changed NIC the driver swaps the guard
    /// in one step, then the record names the new lists, so a later start guards the same. A
    /// guard the driver refuses leaves the record on the old lists and the error with the
    /// caller, and the next re-send tries again. Only the address lists follow the spec; a
    /// NIC's wiring stays as it was created.
    pub(crate) async fn sync_nic_addresses(&self, id: &VmId, wanted: &AgentVmSpec) -> Result<()> {
        let Some(mut record) = self.store.get(id)? else {
            return Ok(());
        };
        if nics_rewired(&record.spec.nics, &wanted.nics) {
            warn!(
                held = record.spec.nics.len(),
                wanted = wanted.nics.len(),
                "the re-sent spec adds, drops or rewires nics; that waits for the vm to be \
                 created again, only the addresses of the nics it keeps follow now"
            );
        }
        for position in readdressed_positions(&record.spec.nics, &wanted.nics) {
            let nic = record.spec.nics[position].id;
            let spec = readdressed(
                &record.spec.nics[position].spec,
                &wanted.nics[position].spec,
            );
            self.update_guard(&nic, &spec).await?;
            info!(
                nic_id = %nic,
                floating = spec.floating_ips.len(),
                subnets = spec.routed_subnets.len(),
                "nic addresses follow the re-sent spec"
            );
            record.spec.nics[position].spec = spec;
            self.store.put(id, &record)?;
        }
        Ok(())
    }

    /// Swap the guard of NIC `nic`'s tap for one built from `spec`. A NIC without a tap has no
    /// guard to swap; the record's lists are what its next start guards it with.
    async fn update_guard(&self, nic: &NicId, spec: &NicSpec) -> Result<()> {
        let driver = self.drivers.networking()?;
        match timed_driver(NETWORKING, "update_guard", driver.update_guard(nic, spec)).await {
            Ok(()) => Ok(()),
            Err(NetworkError::NicNotFound(_)) => {
                debug!(nic_id = %nic, "no tap on this host; the record alone takes the addresses");
                Ok(())
            }
            Err(e) => Err(anyhow!(e))
                .with_context(|| format!("guarding nic {nic} with the re-sent addresses")),
        }
    }

    /// The second link of the chain: a tap per NIC, on the bridge that NIC
    /// belongs on, and the tenant overlay under it where the spec names one.
    pub(super) async fn attach_nics(
        &self,
        id: &VmId,
        record: &mut VmRecord,
        spec: &AgentVmSpec,
    ) -> Result<()> {
        // Resolve required network drivers before creating any taps. A VM without
        // NICs does not need a network driver.
        let (nic_driver, bridge) = match spec.nics.is_empty() {
            true => (None, None),
            false => (
                Some(self.drivers.networking()?),
                Some(self.drivers.bridge()?),
            ),
        };
        for n in &spec.nics {
            // Overlay NICs use the tenant bridge while the spec retains its default
            // bridge name. Do not assign the host an address on the tenant network.
            if let Some(vni) = n.spec.vxlan_id {
                let joined = bridge
                    .expect("the nic list is not empty, so the bridge driver was asked for")
                    .ensure_overlay(vni)
                    .await
                    .with_context(|| format!("ensuring the overlay for vxlan {vni}"))?;
                debug!(nic_id = %n.id, vni, bridge = %joined, "nic joins a tenant overlay");
                // Persist the actual overlay bridge name for teardown validation.
                record.overlay_bridges.insert(vni, joined);
            } else if let Some(physnet) = &n.spec.physnet {
                // Provider bridges are prepared at startup. Do not create an empty bridge
                // here if the configured provider interface is unavailable.
                debug!(nic_id = %n.id, physnet = %physnet,
                       "nic hangs on a provider network");
            } else {
                bridge
                    .expect("the nic list is not empty, so the bridge driver was asked for")
                    .ensure(&n.spec.bridge)
                    .await
                    .with_context(|| format!("ensuring bridge {}", n.spec.bridge))?;
                if n.spec.bridge == self.default_bridge
                    && let Some((ip, prefix)) = self.bridge_addr
                {
                    bridge
                        .expect("the nic list is not empty, so the bridge driver was asked for")
                        .ensure_address(&n.spec.bridge, ip, prefix)
                        .await
                        .with_context(|| {
                            format!("assigning {ip}/{prefix} to bridge {}", n.spec.bridge)
                        })?;
                }
            }
            let nic = timed_driver(
                NETWORKING,
                "create",
                nic_driver
                    .expect("the nic list is not empty, so the nic driver was asked for")
                    .create(&n.id, &n.spec),
            )
            .await
            .with_context(|| format!("creating nic {}", n.id))?;
            record.nics.push(nic);
        }
        record.phase = Phase::NetworkDone;
        self.store.put(id, record)?;
        info!(count = record.nics.len(), "nics ready");
        Ok(())
    }
}
