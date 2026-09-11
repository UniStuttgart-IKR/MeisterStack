// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! The taps and the wire under them.
//!
//! A NIC of a tenant VM lands on that tenant's own overlay bridge and never
//! on the node's default one; the overlay is built on demand and taken down
//! when the last VM that named it goes. The count that decides "last" is
//! counted from the records rather than kept, which is what makes it survive
//! a restart with nothing to reconstruct — see `overlay_users`.
//!
//! Moved out of `provision.rs` unchanged.

use super::*;

/// Which tenant overlays this record's VM asked this node to carry.
///
/// Off the SPEC and not off `record.nics`, for the same reason
/// `volume_is_referenced` reads the spec: a `Nic` is what the driver handed
/// back — a tap name and an MTU — and the VNI was never on it. The spec is
/// where the number was written down and it is what `run_chain` reads when it
/// calls `ensure_overlay`, so it is the only source that cannot name an
/// overlay this VM never joined.
///
/// Sorted and deduplicated: two NICs of one VM on one tenant wire are one
/// overlay, and asking twice would log a removal that did not happen.
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

/// How many VM records OTHER than `except` still name this overlay.
///
/// The reference count, and it is COUNTED rather than kept. A stored counter
/// would be a second truth about the same thing: it has to be raised before
/// the overlay is built and lowered after it is taken down, every crash in
/// between leaves it off by one, and a count that is off by one either leaks
/// for ever or deletes a bridge out from under a running VM. Counting the
/// records has neither failure mode, and it is what makes the answer survive
/// a restart with nothing to reconstruct: the records ARE the state, and
/// after an adoption they are the records that were there before.
///
/// `except` is the VM being torn down. Its own record is still in the table
/// while this is asked — `teardown` removes it last, and only when everything
/// before it succeeded — so counting it would mean never reaching zero.
///
/// **A record this build cannot read counts as a user.** It is read off
/// `list_raw` for exactly that reason: `Store::list` logs a record it cannot
/// deserialise and passes over it, which is right for every other reader —
/// silence there means "I do not know of one" — and wrong for this one. A
/// count that passed over a damaged record would reach zero while a VM was
/// still on the wire, and the bridge would go out from under a running guest.
/// So the unknown is counted, the overlay stays up, and the node leaks a
/// bridge instead of breaking a guest. That is the direction to be wrong in.
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
        // Asked once for the whole loop rather than per call: a node with no
        // `[network]` section cannot serve any of these NICs, and finding
        // that out on the second one would leave a tap behind from the first.
        // A VM with no NICs never asks, which is what lets one run on a node
        // that makes no taps at all.
        let (nic_driver, bridge) = match spec.nics.is_empty() {
            true => (None, None),
            false => (
                Some(self.drivers.networking()?),
                Some(self.drivers.bridge()?),
            ),
        };
        for n in &spec.nics {
            // A tenant NIC lands on the tenant's own bridge; the one the spec
            // names is the default it WOULD have taken, and stays on record
            // as exactly that. No address is ever assigned to an overlay
            // bridge: the host is not on the tenant's network, and giving it
            // an address there would be the one hole the isolation is for.
            if let Some(vni) = n.spec.vxlan_id {
                let joined = bridge
                    .expect("the nic list is not empty, so the bridge driver was asked for")
                    .ensure_overlay(vni)
                    .await
                    .with_context(|| format!("ensuring the overlay for vxlan {vni}"))?;
                debug!(nic_id = %n.id, vni, bridge = %joined, "nic joins a tenant overlay");
                // Written down and not only logged: this is the only moment
                // anybody knows which bridge this VM's overlay actually got,
                // and the teardown is the caller that has to be sure it is
                // taking down the same one. See `VmRecord::overlay_bridges`.
                record.overlay_bridges.insert(vni, joined);
            } else if let Some(physnet) = &n.spec.physnet {
                // Festlegung 3: the tap hangs on the provider bridge, which
                // this node made at start-up out of the interface it gave
                // away. NOTHING is ensured here and that is deliberate -- an
                // `ensure` would happily make an empty bridge with no
                // interface in it, and a guest on that bridge would be a
                // guest on a wire that reaches nowhere. If the bridge is not
                // there, the tap's create says so by name.
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
