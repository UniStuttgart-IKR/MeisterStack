// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! VXLAN network identifiers: handing one out per tenant, exactly once, and
//! writing it into the specs that have to carry it.
//!
//! A VNI is not a label. It is the number on the wire that decides which
//! frames a node's overlay bridge accepts, so two tenants issued the same one
//! are not a naming conflict somebody notices in `tenant ls` — they are two
//! tenants on one broadcast domain, which is the precise thing tenancy is for
//! preventing. That is why this is a compare-and-swap against the store and
//! not a `max(existing) + 1` over a list: the list read and the write are two
//! moments, and two API servers creating a tenant in the same moment would
//! both read the same maximum.
//!
//! The mechanism is the store's own. A counter object carries an ordinary
//! `resourceVersion`, an update compares it, and the loser of a race is told
//! `Conflict` and tries again with what the winner left behind. Nothing new
//! was built for this; the allocator is one object and a retry.

use crate::object::Resource;
use crate::resources::{Counter, CounterSpec};
use crate::store::{EtcdStore, Result, StoreError};

/// The counter object's name. `<prefix>/registry/counters/vni`.
pub const COUNTER_VNI: &str = "vni";

/// Where allocation starts when a config names no floor.
///
/// Ten thousand rather than one: a lab that also runs somebody else's VXLAN
/// deployment collides less if the two do not both start at the bottom, and a
/// VNI an operator sees in a `tcpdump` is easier to recognise as ours when it
/// is not `1`.
pub const DEFAULT_VNI_BASE: u32 = 10_000;

/// A VNI is 24 bits (RFC 7348 §5). Zero is excluded here rather than in the
/// kernel: `id 0` is a legal VXLAN device and a terrible tenant, because
/// "unset" and "tenant zero" would be the same number in every JSON document
/// this stack writes.
pub const VNI_MAX: u32 = 0x00FF_FFFF;

/// The arithmetic half, with no store in it: what a counter standing at
/// `current` hands out under floor `base`, and what it is left standing at.
///
/// The floor is applied on every allocation and not only on the first, so
/// raising `vni_base` in a config moves the allocator forward instead of
/// being a setting that quietly did nothing after the first tenant. Lowering
/// it does nothing at all, which is the honest behaviour: the numbers below
/// have already been handed out.
pub fn next_vni(current: Option<u32>, base: u32) -> Result<(u32, u32)> {
    let base = base.max(1);
    let issued = current.unwrap_or(base).max(base);
    if issued > VNI_MAX {
        return Err(StoreError::Invalid(format!(
            "cannot allocate a vni: {issued} is past the 24-bit range a vxlan identifier has ({VNI_MAX}); \
             the tenant counter is exhausted"
        )));
    }
    Ok((issued, issued + 1))
}

/// Take the next VNI. Retries its own losses; every other error is the
/// caller's to turn into a status code.
///
/// The bound on retries is a liveness one, not a correctness one: each round
/// is one lost race, and a caller that has lost sixteen in a row is on an API
/// server that has bigger problems than this tenant.
pub async fn allocate(store: &EtcdStore, base: u32) -> Result<u32> {
    for _ in 0..16 {
        match store.get::<Counter>(COUNTER_VNI).await {
            Ok(mut counter) => {
                let (issued, next) = next_vni(Some(counter.spec.next), base)?;
                counter.spec.next = next;
                match store.update(&counter).await {
                    Ok(_) => return Ok(issued),
                    // Somebody else took this number. Read what they left.
                    Err(StoreError::Conflict(_)) => continue,
                    Err(e) => return Err(e),
                }
            }
            Err(StoreError::NotFound(_)) => {
                let (issued, next) = next_vni(None, base)?;
                match store
                    .create(&Counter::declare(COUNTER_VNI, CounterSpec { next }))
                    .await
                {
                    Ok(_) => return Ok(issued),
                    // Two first tenants at once: exactly one created the
                    // counter, and the other one reads it on the next round.
                    Err(StoreError::AlreadyExists(_)) => continue,
                    Err(e) => return Err(e),
                }
            }
            Err(e) => return Err(e),
        }
    }
    Err(StoreError::Conflict(format!(
        "resource version conflict on {}/{COUNTER_VNI} (retries exhausted)",
        Counter::RESOURCE
    )))
}

/// Write `vni` into every NIC of an agent NewVmSpec that names none, and say
/// how many that was.
///
/// This is the injection the design puts at the controller and not at the
/// agent: the tenant is a control-plane fact, the VNI is a control-plane
/// allocation, and by the time a spec reaches a node it should say plainly
/// which wire it wants. The agent then only checks types, exactly as it does
/// for `base_image` — one place where the truth is made, one place where it
/// is validated, and no node that has to know what a tenant is.
///
/// A NIC that already names a `vxlan_id` is left alone. That is the
/// standalone road of the design: a cluster with no cloud above it has no
/// Tenant object to resolve, and putting the number straight in the spec has
/// to keep working. It is also the override — an admin who has said exactly
/// which overlay a NIC belongs on has said something more specific than the
/// tenant did.
pub fn inject_vxlan_id(spec: &mut serde_json::Value, vni: u32) -> usize {
    let Some(nics) = spec.get_mut("nics").and_then(|n| n.as_array_mut()) else {
        return 0;
    };
    let mut touched = 0;
    for nic in nics {
        let Some(nic) = nic.as_object_mut() else {
            continue;
        };
        if nic.get("vxlan_id").is_some_and(|v| !v.is_null()) {
            continue;
        }
        nic.insert("vxlan_id".to_string(), serde_json::Value::from(vni));
        touched += 1;
    }
    touched
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The counter is where the next one comes from, and it moves by one.
    #[test]
    fn allocation_walks_the_counter_forward() {
        let (issued, next) = next_vni(None, DEFAULT_VNI_BASE).unwrap();
        assert_eq!((issued, next), (10_000, 10_001));
        let (issued, next) = next_vni(Some(next), DEFAULT_VNI_BASE).unwrap();
        assert_eq!((issued, next), (10_001, 10_002));
    }

    /// A floor raised after the fact moves the allocator; one lowered does
    /// not move it back, because the numbers below are already out there.
    #[test]
    fn the_floor_applies_to_every_allocation_and_only_upwards() {
        assert_eq!(next_vni(Some(10_005), 20_000).unwrap(), (20_000, 20_001));
        assert_eq!(next_vni(Some(10_005), 100).unwrap(), (10_005, 10_006));
    }

    /// Zero is not a tenant: "unset" and "tenant zero" would be the same
    /// number in every document this stack writes.
    #[test]
    fn zero_is_never_handed_out() {
        assert_eq!(next_vni(None, 0).unwrap().0, 1);
        assert_eq!(next_vni(Some(0), 0).unwrap().0, 1);
    }

    /// Past 24 bits there is no VXLAN identifier left to give, and saying so
    /// beats handing out a number the kernel will refuse.
    #[test]
    fn an_exhausted_counter_is_an_error_rather_than_a_wrap() {
        assert_eq!(next_vni(Some(VNI_MAX), 1).unwrap(), (VNI_MAX, VNI_MAX + 1));
        let err = next_vni(Some(VNI_MAX + 1), 1).unwrap_err().to_string();
        assert!(err.contains("24-bit"), "{err}");
    }

    // --- injection ---------------------------------------------------------

    #[test]
    fn every_nic_without_one_gets_the_tenants_vni() {
        let mut spec = serde_json::json!({
            "vcpus": 1,
            "nics": [{}, { "mac": "52:54:00:aa:bb:cc" }],
        });
        assert_eq!(inject_vxlan_id(&mut spec, 10_007), 2);
        for nic in spec["nics"].as_array().unwrap() {
            assert_eq!(nic["vxlan_id"], 10_007);
        }
        // and the rest of the document is untouched
        assert_eq!(spec["vcpus"], 1);
        assert_eq!(spec["nics"][1]["mac"], "52:54:00:aa:bb:cc");
    }

    /// The standalone road, and the override: a spec that already says which
    /// overlay a NIC belongs on has said something more specific.
    #[test]
    fn an_explicit_vxlan_id_is_never_overwritten() {
        let mut spec = serde_json::json!({ "nics": [{ "vxlan_id": 4242 }, {}] });
        assert_eq!(inject_vxlan_id(&mut spec, 10_007), 1);
        assert_eq!(spec["nics"][0]["vxlan_id"], 4242);
        assert_eq!(spec["nics"][1]["vxlan_id"], 10_007);
    }

    /// A VM with no NICs is a VM with no NICs. Nothing to write, nothing to
    /// invent — in particular not a `nics` key the agent's serde would then
    /// have to explain.
    #[test]
    fn a_spec_with_no_nics_is_left_exactly_as_it_was() {
        let mut spec = serde_json::json!({ "vcpus": 2 });
        assert_eq!(inject_vxlan_id(&mut spec, 10_007), 0);
        assert_eq!(spec, serde_json::json!({ "vcpus": 2 }));

        let mut empty = serde_json::json!({ "nics": [] });
        assert_eq!(inject_vxlan_id(&mut empty, 10_007), 0);
        assert_eq!(empty, serde_json::json!({ "nics": [] }));
    }
}
