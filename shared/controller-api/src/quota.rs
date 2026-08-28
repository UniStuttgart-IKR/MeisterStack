// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! How much one tenant may hold.
//!
//! `floatingpool quota` was the only quota in this system: no limit on VM
//! count, vCPU, memory or disk per tenant. The tenancy BOUNDARY was sharp
//! from M5 — a member sees its own objects and writes its own objects — and
//! only the quantity behind it was missing. Together with capacity admission
//! that is the class of trouble somebody causes who does not mean any harm:
//! admission stops one machine being asked for more than it has, and this
//! stops one tenant asking for all of them.
//!
//! ## The same seam admission laid
//!
//! What a VM costs is [`Capacity::wanted_by`] — the same function the
//! scheduler measures a candidate with, over the same two numbers. There is
//! deliberately no second reading of a VM's size here: two rejection paths
//! that each derive "how big is this VM" separately are two paths that start
//! disagreeing, and the one that is wrong is whichever an operator is not
//! looking at.
//!
//! ## Every phase counts, Pending included
//!
//! A VM that is waiting for a placement is a VM this tenant asked for, and
//! leaving it out is how a tenant puts a thousand of them in the queue and
//! walks past the ceiling. A VM on its way out counts too, until its object
//! is gone: it still holds a disk and a slice on some node, and the quota is
//! released by the teardown finishing rather than by the DELETE being
//! accepted.

use macros::generated;

use crate::resources::{TenantQuota, TenantUsage, Vm};
use crate::scheduler::Capacity;

/// What a tenant holds, and what it would hold.
///
/// One type for both, because the check is the same question either way:
/// take the usage, put the change into it, and ask whether the result is
/// inside the ceiling. A create is "plus this VM", an update is "minus the
/// old size, plus the new one", and neither needs a rule of its own.
#[generated(model = ClaudeOpus, version = "5")]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Usage {
    pub vms: u32,
    pub size: Capacity,
}

#[generated(model = ClaudeOpus, version = "5")]
impl Usage {
    /// What this tenant holds, out of the whole VM listing.
    ///
    /// `except` is the VM being changed, by name, and it is what makes an
    /// update one rule rather than two: the object as it stands is taken out
    /// of the sum and put back at its new size by the caller. `None` for a
    /// create, which is taking nothing out.
    pub fn of(tenant: &str, vms: &[Vm], except: Option<&str>) -> Self {
        vms.iter()
            .filter(|v| v.spec.tenant.as_deref() == Some(tenant))
            .filter(|v| Some(v.metadata.name.as_str()) != except)
            .fold(Self::default(), |acc, vm| acc.plus(Capacity::wanted_by(vm)))
    }

    /// This usage with one more VM of the given size in it.
    pub fn plus(self, size: Capacity) -> Self {
        Self {
            vms: self.vms.saturating_add(1),
            size: self.size.plus(size),
        }
    }

    /// The shape the API hands out on a Tenant's status.
    pub fn reported(self) -> TenantUsage {
        TenantUsage {
            vms: self.vms,
            vcpus: self.size.vcpus,
            mem_mib: self.size.mem_mib,
        }
    }
}

/// Would this usage be inside the ceiling? The sentence names WHICH limit.
///
/// An unset limit is unlimited, checked field by field, so a tenant with a VM
/// count and no memory ceiling is a perfectly ordinary thing to configure.
///
/// The message says the number that was hit and the number that stands, both,
/// because "quota exceeded" sends an operator to look up what their quota
/// actually is and a sentence that says it does not.
#[generated(model = ClaudeOpus, version = "5")]
pub fn check(quota: &TenantQuota, tenant: &str, after: Usage) -> Result<(), String> {
    let over = |what: &str, want: u64, limit: u64| {
        format!("tenant {tenant} would hold {want} {what}, and its quota is {limit}")
    };
    if let Some(max) = quota.max_vms
        && after.vms > max
    {
        return Err(over("vms", after.vms as u64, max as u64));
    }
    if let Some(max) = quota.max_vcpus
        && after.size.vcpus > max
    {
        return Err(over("vcpus", after.size.vcpus as u64, max as u64));
    }
    if let Some(max) = quota.max_mem_mib
        && after.size.mem_mib > max
    {
        return Err(over("MiB of memory", after.size.mem_mib, max));
    }
    Ok(())
}

#[cfg(test)]
#[generated(model = ClaudeOpus, version = "5")]
mod tests {
    use super::*;
    use crate::resources::{VmSpec, new_vm};

    fn vm(name: &str, tenant: Option<&str>, vcpus: u32, mem_mib: u64) -> Vm {
        new_vm(
            name,
            VmSpec {
                cluster_selector: Default::default(),
                node_selector: Default::default(),
                anti_affinity: Vec::new(),
                node_name: None,
                cluster_name: None,
                run_strategy: Default::default(),
                tenant: tenant.map(str::to_string),
                vm: serde_json::json!({"vcpus": vcpus, "memory_mib": mem_mib}),
            },
        )
    }

    fn quota(vms: Option<u32>, vcpus: Option<u32>, mem: Option<u64>) -> TenantQuota {
        TenantQuota {
            max_vms: vms,
            max_vcpus: vcpus,
            max_mem_mib: mem,
        }
    }

    fn fleet() -> Vec<Vm> {
        vec![
            vm("a", Some("acme"), 2, 1024),
            vm("b", Some("acme"), 4, 2048),
            vm("theirs", Some("globex"), 8, 8192),
            // Unscoped: an admin's VM that belongs to nobody. It is nobody's
            // usage either, and counting it against a tenant would be
            // counting it against the wrong one.
            vm("nobodys", None, 16, 16384),
        ]
    }

    /// Only this tenant's, and all of this tenant's.
    #[test]
    fn a_tenants_usage_is_its_own_vms_and_nothing_else() {
        let used = Usage::of("acme", &fleet(), None);
        assert_eq!(used.vms, 2);
        assert_eq!(used.size.vcpus, 6);
        assert_eq!(used.size.mem_mib, 3072);

        assert_eq!(Usage::of("globex", &fleet(), None).vms, 1);
        assert_eq!(Usage::of("nobody-here", &fleet(), None), Usage::default());
    }

    /// Nothing set is nothing enforced, which is what every tenant written
    /// before this milestone says. The compatibility promise, held rather
    /// than written in a comment.
    #[test]
    fn an_unset_quota_admits_anything() {
        let huge = Usage::default().plus(Capacity {
            vcpus: u32::MAX,
            mem_mib: u64::MAX,
        });
        assert!(check(&TenantQuota::default(), "acme", huge).is_ok());
        assert!(TenantQuota::default().is_unset());
        assert!(!quota(Some(1), None, None).is_unset());
    }

    /// At the ceiling is inside it; one past is not. Each limit refuses on
    /// its own, and the sentence names which one and what it is.
    #[test]
    fn each_limit_refuses_by_itself_and_says_which() {
        let vms = fleet();
        let used = Usage::of("acme", &vms, None);

        // Exactly at the limit: allowed. This is the boundary that decides
        // whether a quota of 2 means two vms or one.
        assert!(check(&quota(Some(2), Some(6), Some(3072)), "acme", used).is_ok());

        let after = used.plus(Capacity {
            vcpus: 1,
            mem_mib: 1,
        });
        let err = check(&quota(Some(2), None, None), "acme", after).unwrap_err();
        assert!(err.contains("3 vms") && err.contains("quota is 2"), "{err}");

        let err = check(&quota(None, Some(6), None), "acme", after).unwrap_err();
        assert!(
            err.contains("7 vcpus") && err.contains("quota is 6"),
            "{err}"
        );

        let err = check(&quota(None, None, Some(3072)), "acme", after).unwrap_err();
        assert!(
            err.contains("3073 MiB of memory") && err.contains("quota is 3072"),
            "{err}"
        );

        // A limit that is set on a dimension nobody is near does not refuse.
        assert!(check(&quota(None, None, Some(1_000_000)), "acme", after).is_ok());
    }

    /// The update rule, which is the one that gets forgotten: raising an
    /// existing VM's vCPUs is the same act as creating one that size, and it
    /// goes through the same arithmetic — the object as it stands comes out
    /// of the sum, and its new size goes back in.
    #[test]
    fn growing_a_vm_is_measured_the_same_way_as_creating_one() {
        let vms = fleet();
        let ceiling = quota(Some(10), None, Some(4096));

        // acme holds 3072 MiB over two vms. Growing "a" from 1024 to 2048
        // lands at 4096 exactly: allowed.
        let after = Usage::of("acme", &vms, Some("a")).plus(Capacity {
            vcpus: 2,
            mem_mib: 2048,
        });
        assert_eq!(after.vms, 2, "the vm being changed is not counted twice");
        assert_eq!(after.size.mem_mib, 4096);
        assert!(check(&ceiling, "acme", after).is_ok());

        // One MiB more is one MiB too many.
        let over = Usage::of("acme", &vms, Some("a")).plus(Capacity {
            vcpus: 2,
            mem_mib: 2049,
        });
        assert!(check(&ceiling, "acme", over).is_err());

        // And shrinking is always allowed, whatever the ceiling says.
        let smaller = Usage::of("acme", &vms, Some("b")).plus(Capacity {
            vcpus: 1,
            mem_mib: 128,
        });
        assert!(check(&quota(Some(10), None, Some(4096)), "acme", smaller).is_ok());
    }

    /// A VM on its way out still counts. It holds a disk and a slice on some
    /// node until the teardown finishes, and the quota is released by the
    /// object going away rather than by the DELETE being accepted.
    #[test]
    fn a_vm_that_is_terminating_still_counts_until_its_object_is_gone() {
        let mut vms = fleet();
        vms[0].metadata.deletion_timestamp = Some(chrono::Utc::now());
        assert_eq!(Usage::of("acme", &vms, None).vms, 2);
        vms.remove(0);
        assert_eq!(Usage::of("acme", &vms, None).vms, 1);
    }
}
