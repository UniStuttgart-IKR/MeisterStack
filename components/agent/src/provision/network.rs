// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Create VM taps and tenant overlays. Overlay VM ownership is derived from
//! persisted records; the bridge driver also protects router and kernel users.

use super::*;

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

impl Provisioner {
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
