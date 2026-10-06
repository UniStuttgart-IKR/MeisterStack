// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Allocate tenant VXLAN identifiers through an etcd CAS counter.
//!
//! Concurrent tenant creation must not assign the same broadcast domain twice.
//! The losing writer retries against the updated counter; allocated IDs are then
//! injected into the relevant VM specifications.

use crate::object::Resource;
use crate::resources::{Counter, CounterSpec};
use crate::rest::{ApiError, invalid_field};
use crate::store::{EtcdStore, Result, StoreError};

/// The counter object's name. `<prefix>/registry/counters/vni`.
pub const COUNTER_VNI: &str = "vni";

/// Default configurable VNI allocation floor. It does not coordinate with
/// independent VXLAN deployments.
pub const DEFAULT_VNI_BASE: u32 = 10_000;

/// Maximum 24-bit VNI. The allocator excludes zero so it cannot be confused
/// with an unset network identifier.
pub const VNI_MAX: u32 = 0x00FF_FFFF;

/// Choose the next VNI at or above both the counter and configured floor.
/// Raising the floor advances allocation; lowering it cannot reuse earlier IDs.
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

/// Preview the next VNI without advancing the counter. Concurrent previews can
/// return the same value; no allocation is reserved until the actual create.
pub async fn peek(store: &EtcdStore, base: u32) -> Result<u32> {
    let current = match store.get::<Counter>(COUNTER_VNI).await {
        Ok(counter) => Some(counter.spec.next),
        Err(StoreError::NotFound(_)) => None,
        Err(e) => return Err(e),
    };
    let (issued, _) = next_vni(current, base)?;
    Ok(issued)
}

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

/// Fill the tenant VNI into NICs that name neither a VNI nor a physnet, returning
/// the count changed. Explicit overlays and provider-network NICs are preserved.
/// The agent receives concrete network parameters and does not resolve tenants.
pub fn inject_vxlan_id(spec: &mut serde_json::Value, vni: u32) -> usize {
    let Some(nics) = spec.get_mut("nics").and_then(|n| n.as_array_mut()) else {
        return 0;
    };
    let mut touched = 0;
    for nic in nics {
        let Some(nic) = nic.as_object_mut() else {
            continue;
        };
        if nic.get("vxlan_id").is_some_and(|v| !v.is_null()) || on_a_provider_network(nic) {
            continue;
        }
        nic.insert("vxlan_id".to_string(), serde_json::Value::from(vni));
        touched += 1;
    }
    touched
}

/// Whether the NIC selects a nonempty provider physnet. Empty or null
/// means no provider selection for both VNI injection and scheduling.
pub fn on_a_provider_network(nic: &serde_json::Map<String, serde_json::Value>) -> bool {
    physnet_of(nic).is_some()
}

/// The provider network this NIC asks for, if it asks for one.
pub fn physnet_of(nic: &serde_json::Map<String, serde_json::Value>) -> Option<&str> {
    nic.get("physnet")
        .and_then(|p| p.as_str())
        .filter(|p| !p.is_empty())
}

/// The NIC fields that pick a wire themselves instead of the tenant's overlay.
const WIRE_FIELDS: [&str; 2] = ["physnet", "bridge"];

/// Refuse a tenant's VM whose NIC picks its own wire.
///
/// A tenant's NICs belong on its overlay, which the cluster binds from the
/// tenant's VNI. A provider network belongs to no tenant: a tap on it shares
/// layer 2 with every router's external leg and every floating IP, and the
/// agent fences it by its MAC alone, because the address space out there is
/// the operator's. A host bridge is any wire on the machine, and it is the
/// one the tap lands on whenever the tenant has no VNI. Neither is a tenant's
/// to choose. Empty and null say nothing, as for `physnet_of`. A VM without
/// a tenant is the operator's own, and the caller does not ask then.
pub fn check_tenant_nics(vm: &serde_json::Value) -> std::result::Result<(), ApiError> {
    let nics = vm
        .get("nics")
        .and_then(|n| n.as_array())
        .map(Vec::as_slice)
        .unwrap_or(&[]);
    for (i, nic) in nics.iter().enumerate() {
        for field in WIRE_FIELDS {
            let named = nic
                .get(field)
                .and_then(|v| v.as_str())
                .is_some_and(|v| !v.is_empty());
            if named {
                return Err(invalid_field(
                    &format!("spec.vm.nics[{i}].{field}"),
                    format!(
                        "spec.vm.nics[{i}].{field} is not a tenant's to set: a tenant's vm \
                         hangs on its own overlay, and a provider network or a host bridge is \
                         shared with everybody on it"
                    ),
                ));
            }
        }
    }
    Ok(())
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

    /// Provider NICs must not receive the tenant overlay VNI.
    #[test]
    fn a_nic_on_a_provider_network_never_gets_the_tenants_vni() {
        let mut spec = serde_json::json!({
            "nics": [{ "physnet": "ext" }, {}],
        });
        assert_eq!(inject_vxlan_id(&mut spec, 10_007), 1);
        assert!(
            spec["nics"][0].get("vxlan_id").is_none(),
            "a nic on the provider bridge is on no overlay: {spec}"
        );
        assert_eq!(spec["nics"][1]["vxlan_id"], 10_007);

        // Empty and null are "said nothing", not "a network called
        // nothing": a client that cleared the field gets the overlay back
        // rather than a tap on no network at all.
        let mut cleared = serde_json::json!({ "nics": [{ "physnet": "" }, { "physnet": null }] });
        assert_eq!(inject_vxlan_id(&mut cleared, 10_007), 2);
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

    // --- a tenant's wires ---------------------------------------------------

    /// IKR-B67: a tenant member wrote `physnet: ext` and got a tap on the
    /// provider segment beside every router's external leg.
    #[test]
    fn a_tenant_nic_may_not_name_a_provider_network_or_a_host_bridge() {
        for (field, value) in [("physnet", "ext"), ("bridge", "br0")] {
            let vm = serde_json::json!({ "nics": [{}, { field: value }] });
            let err = check_tenant_nics(&vm).unwrap_err();
            assert_eq!(
                err.field(),
                Some(format!("spec.vm.nics[1].{field}").as_str()),
                "{}",
                err.message()
            );
        }
    }

    /// Empty and null are "said nothing", exactly as VNI injection reads them.
    #[test]
    fn a_tenant_nic_that_names_no_wire_passes() {
        for vm in [
            serde_json::json!({ "nics": [{}, { "mac": "52:54:00:11:22:33" }] }),
            serde_json::json!({ "nics": [{ "physnet": "", "bridge": null }] }),
            serde_json::json!({ "vcpus": 1 }),
        ] {
            check_tenant_nics(&vm).expect("no wire picked");
        }
    }
}
