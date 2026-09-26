// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Tenant VM, CPU, memory and per-pool storage accounting.
//!
//! VM sizing uses the scheduler's [`Capacity::wanted_by`]. All existing VM objects
//! count, including Pending and deleting objects. Releasing volumes also count
//! until deprovisioning removes the object. Admission callers must serialize
//! quota checks and writes with the store's admission fence.

use crate::resources::{StoragePool, TenantQuota, TenantUsage, Vm, Volume, VolumePhaseKind};
use crate::scheduler::Capacity;

/// Per-tenant admission fence shared by VM and storage writes.
/// Callers read it before usage and compare it during writes to detect races.
pub fn fence(tenant: &str) -> String {
    format!("quota/{tenant}")
}

/// Existing or prospective VM usage. Updates subtract the old VM and add its
/// replacement; creates only add the new demand.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Usage {
    pub vms: u32,
    pub size: Capacity,
}

impl Usage {
    /// Sum tenant VM usage, excluding the named current VM during an update.
    /// The caller adds the replacement size; creates pass no exclusion.
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

/// Check each configured limit and name the requested total and exceeded ceiling.
/// Unset limits are independent and unlimited.
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

/// Tenant storage usage within one pool, matching per-pool quota configuration.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct StorageUsage {
    pub volumes: u32,
    pub gib: u64,
}

impl StorageUsage {
    /// Count this tenant's volumes in the pool, excluding the named volume
    /// being replaced or resized. All phases count, including Releasing,
    /// until deprovisioning removes the resource.
    pub fn of(tenant: &str, pool: &str, volumes: &[Volume], except: Option<&str>) -> Self {
        volumes
            .iter()
            .filter(|v| v.spec.tenant == tenant && v.spec.pool == pool)
            .filter(|v| Some(v.metadata.name.as_str()) != except)
            .fold(Self::default(), |acc, v| acc.plus(v.spec.size_gib))
    }

    /// This usage with one more volume of the given size in it.
    pub fn plus(self, gib: u64) -> Self {
        Self {
            volumes: self.volumes.saturating_add(1),
            gib: self.gib.saturating_add(gib),
        }
    }
}

/// Check the pool's per-tenant ceiling and report limit plus requested
/// usage. Pool ceilings are numeric, including zero; tenant-wide optional
/// quotas use the separate `check` path.
pub fn check_storage(pool: &StoragePool, tenant: &str, after: StorageUsage) -> Result<(), String> {
    let limit = pool.spec.quota_for(tenant);
    if after.gib > limit {
        return Err(format!(
            "tenant {tenant} would hold {} GiB in storage pool {}, and its quota there is \
             {limit} GiB",
            after.gib, pool.metadata.name
        ));
    }
    Ok(())
}

/// All volume phases reserve quota, including Pending, Failed and Releasing.
/// Only object removal releases that accounting.
pub fn holds_room(phase: VolumePhaseKind) -> bool {
    match phase {
        VolumePhaseKind::Pending
        | VolumePhaseKind::Provisioning
        | VolumePhaseKind::Ready
        | VolumePhaseKind::Releasing
        | VolumePhaseKind::Failed => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::object::Resource;
    use crate::resources::{VmSpec, new_vm};
    use chrono::Utc;

    fn vm(name: &str, tenant: Option<&str>, vcpus: u32, mem_mib: u64) -> Vm {
        new_vm(
            name,
            VmSpec {
                class: Default::default(),
                cluster_selector: Default::default(),
                node_selector: Default::default(),
                anti_affinity: Vec::new(),
                node_name: None,
                cluster_name: None,
                run_strategy: Default::default(),
                evacuation: Default::default(),
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

    /// Updates count replacement VM capacity through the same arithmetic as creates.
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

    fn pool(name: &str, quota: &[(&str, u64)]) -> StoragePool {
        StoragePool::declare(
            name,
            crate::resources::StoragePoolSpec {
                driver: "lvm-thin".into(),
                quota: quota.iter().map(|(t, g)| ((*t).to_string(), *g)).collect(),
                ..Default::default()
            },
        )
    }

    fn volume(name: &str, tenant: &str, pool: &str, gib: u64) -> Volume {
        crate::resources::new_volume(
            name,
            crate::resources::VolumeSpec {
                tenant: tenant.into(),
                pool: pool.into(),
                size_gib: gib,
                ..Default::default()
            },
        )
    }

    fn disks() -> Vec<Volume> {
        vec![
            volume("root", "acme", "fast", 20),
            volume("data", "acme", "fast", 100),
            // A different pool: the same tenant, a separate ceiling.
            volume("cold", "acme", "bulk", 500),
            volume("theirs", "globex", "fast", 40),
        ]
    }

    /// Per pool and per tenant, and neither half leaks into the other. The
    /// mirror of `a_tenants_usage_is_its_own_vms_and_nothing_else`, which is
    /// the point: one seam, two nouns.
    #[test]
    fn storage_usage_is_one_tenants_volumes_in_one_pool() {
        let used = StorageUsage::of("acme", "fast", &disks(), None);
        assert_eq!(used.volumes, 2);
        assert_eq!(used.gib, 120);

        assert_eq!(StorageUsage::of("acme", "bulk", &disks(), None).gib, 500);
        assert_eq!(StorageUsage::of("globex", "fast", &disks(), None).gib, 40);
        assert_eq!(
            StorageUsage::of("nobody", "fast", &disks(), None),
            StorageUsage::default()
        );
    }

    /// At the ceiling is inside it, one GiB past is not, and the sentence
    /// names both numbers and the pool.
    #[test]
    fn a_pool_refuses_by_name_and_says_what_the_ceiling_is() {
        let fast = pool("fast", &[("acme", 200)]);
        let used = StorageUsage::of("acme", "fast", &disks(), None);

        assert!(
            check_storage(&fast, "acme", used.plus(80)).is_ok(),
            "200 exactly"
        );
        let err = check_storage(&fast, "acme", used.plus(81)).unwrap_err();
        assert!(err.contains("201 GiB"), "{err}");
        assert!(err.contains("quota there is 200 GiB"), "{err}");
        assert!(err.contains("storage pool fast"), "{err}");
    }

    /// Tenants without an explicit pool entry receive its default quota;
    /// an explicit zero denies allocation.
    #[test]
    fn an_unnamed_tenant_gets_the_default_and_a_zero_closes_the_door() {
        let open = pool("fast", &[]);
        assert_eq!(
            open.spec.quota_for("newcomer"),
            crate::resources::DEFAULT_QUOTA_STORAGE_GIB
        );
        assert!(check_storage(&open, "newcomer", StorageUsage::default().plus(100)).is_ok());
        assert!(check_storage(&open, "newcomer", StorageUsage::default().plus(101)).is_err());

        let shut = pool("fast", &[("newcomer", 0)]);
        let err = check_storage(&shut, "newcomer", StorageUsage::default().plus(1)).unwrap_err();
        assert!(err.contains("quota there is 0 GiB"), "{err}");
    }

    /// The wildcard quota row exposes and configures the pool default.
    #[test]
    fn the_ceiling_for_everybody_nobody_named_is_a_row_like_any_other() {
        use crate::resources::StoragePoolSpec;

        // Nothing written: the built-in default, exactly as before.
        let mut open = pool("fast", &[]);
        assert_eq!(
            open.spec.quota_for("newcomer"),
            crate::resources::DEFAULT_QUOTA_STORAGE_GIB
        );

        // And this is how a read of the object says so.
        open.spec.state_default_quota();
        assert_eq!(
            open.spec.quota.get(StoragePoolSpec::QUOTA_EVERYONE),
            Some(&crate::resources::DEFAULT_QUOTA_STORAGE_GIB)
        );

        // An operator's own number for everybody, and the built-in default
        // stops applying to anybody.
        let generous = pool("fast", &[(StoragePoolSpec::QUOTA_EVERYONE, 500)]);
        assert_eq!(generous.spec.quota_for("newcomer"), 500);
        assert!(check_storage(&generous, "newcomer", StorageUsage::default().plus(500)).is_ok());
        let err =
            check_storage(&generous, "newcomer", StorageUsage::default().plus(501)).unwrap_err();
        assert!(err.contains("quota there is 500 GiB"), "{err}");

        // A named tenant outranks it, in both directions.
        let mixed = pool(
            "fast",
            &[
                (StoragePoolSpec::QUOTA_EVERYONE, 500),
                ("acme", 10),
                ("globex", 900),
            ],
        );
        assert_eq!(mixed.spec.quota_for("acme"), 10);
        assert_eq!(mixed.spec.quota_for("globex"), 900);
        assert_eq!(mixed.spec.quota_for("newcomer"), 500);

        // And filling a gap never overwrites what somebody wrote, including
        // a deliberate zero -- which is the whole point of the door being
        // shuttable.
        let mut shut = pool("fast", &[(StoragePoolSpec::QUOTA_EVERYONE, 0)]);
        shut.spec.state_default_quota();
        assert_eq!(shut.spec.quota_for("newcomer"), 0);
    }

    /// Volume growth replaces old size in usage rather than counting both copies.
    #[test]
    fn growing_a_volume_is_measured_the_same_way_as_creating_one() {
        let fast = pool("fast", &[("acme", 200)]);
        let after = StorageUsage::of("acme", "fast", &disks(), Some("data")).plus(180);
        assert_eq!(
            after.volumes, 2,
            "the volume being changed is not counted twice"
        );
        assert_eq!(after.gib, 200);
        assert!(check_storage(&fast, "acme", after).is_ok());

        let over = StorageUsage::of("acme", "fast", &disks(), Some("data")).plus(181);
        assert!(check_storage(&fast, "acme", over).is_err());
    }

    /// Deleting volumes continue consuming quota until their objects are removed.
    #[test]
    fn a_volume_on_its_way_out_still_holds_its_room() {
        for phase in VolumePhaseKind::ALL {
            assert!(holds_room(phase), "{phase:?}");
        }
        let mut vols = disks();
        vols[1].metadata.deletion_timestamp = Some(chrono::Utc::now());
        // The timestamp is the decision and `Releasing` is derived from it —
        // see `settle_volume`. This test used to say both, which was the
        // shape of the defect: four writers of one word.
        vols[1].settle(Utc::now());
        assert_eq!(
            vols[1].status.phase().kind(),
            VolumePhaseKind::Releasing,
            "a volume being released says so without anybody stamping it"
        );
        assert_eq!(StorageUsage::of("acme", "fast", &vols, None).gib, 120);

        // ... and it is the object going away that gives the room back.
        vols.remove(1);
        assert_eq!(StorageUsage::of("acme", "fast", &vols, None).gib, 20);
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
