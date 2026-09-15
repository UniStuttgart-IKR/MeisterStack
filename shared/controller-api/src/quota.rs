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
//!
//! ## Storage is the same argument, one noun over
//!
//! [`StorageUsage`] is the per-pool half: how many GiB one tenant holds in
//! one pool, measured over the `Volume` objects the store already has. It is
//! HERE and not in a handler for the reason the module's first paragraph
//! gives — a second place that decides "is this tenant over its limit" is a
//! second place that can say a different thing, and the one that is wrong is
//! whichever an operator is not looking at.
//!
//! A `Releasing` volume still counts. The bytes are still on a disk somewhere
//! and go when the last consumer lets go, so the quota is released by the
//! deprovision finishing rather than by the DELETE being accepted — the same
//! sentence the VM half makes, with more at stake.

use crate::resources::{StoragePool, TenantQuota, TenantUsage, Vm, Volume, VolumePhaseKind};
use crate::scheduler::Capacity;

/// What a tenant holds, and what it would hold.
///
/// One type for both, because the check is the same question either way:
/// take the usage, put the change into it, and ask whether the result is
/// inside the ceiling. A create is "plus this VM", an update is "minus the
/// old size, plus the new one", and neither needs a rule of its own.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Usage {
    pub vms: u32,
    pub size: Capacity,
}

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

/// How much storage a tenant holds in ONE pool, and what it would hold.
///
/// Per pool and not per tenant, because that is where the number an
/// administrator wrote lives: a tenant with a hundred GiB on the fast NVMe
/// pool and a terabyte on the spinning one is an ordinary thing to configure,
/// and one tenant-wide ceiling could not say it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct StorageUsage {
    pub volumes: u32,
    pub gib: u64,
}

impl StorageUsage {
    /// What this tenant holds in this pool, out of the whole volume listing.
    ///
    /// `except` is the volume being changed, by name — the same seam
    /// [`Usage::of`] has, so that resizing one is measured exactly like
    /// creating one that size.
    ///
    /// Every phase counts, `Releasing` included: the bytes are on a disk
    /// until the deprovision finishes, and a tenant that could delete a
    /// volume and immediately create its replacement would hold twice its
    /// quota for as long as the release took.
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

/// Would this usage be inside the pool's ceiling for this tenant?
///
/// The ceiling comes from [`StoragePool::quota_for`] and is never optional:
/// unlike a tenant quota, a storage pool always has a number, because it is a
/// finite disk and "unlimited" would be a claim about hardware. Zero is a
/// perfectly ordinary value and means "an admin hands these out one at a
/// time" — the same door `DEFAULT_QUOTA_PUBLIC` closes on the address side.
///
/// The message says the number that was hit and the number that stands, both,
/// exactly as [`check`] does: "quota exceeded" sends an operator to look up
/// what their quota is, and a sentence that says it does not.
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

/// Whether this volume still holds room on a backend.
///
/// Every phase does, and the function exists to say so in one place rather
/// than to filter: a `Failed` volume may have got half-way, a `Releasing` one
/// is definitely still there, and a `Pending` one is what the tenant asked
/// for. If a phase ever stops counting, it stops counting here.
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
    use crate::resources::{VmSpec, new_vm};

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

    /// A tenant nobody named gets the default, and it is not zero: disk is
    /// something the machine has, unlike a routable address, which somebody
    /// gave the operator. An admin who wants a ticket per volume writes a
    /// zero, and then nothing gets through.
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

    /// D-P11: the hundred GiB stops being a number only the source knows.
    ///
    /// `storagepool ls` showed `QUOTA -` while a create was refused with "its
    /// quota there is 100 GiB", and there was nowhere to look the number up
    /// or change it for a tenant nobody had named yet. The `*` row is both:
    /// what the pool applies, written down, and the thing to patch.
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

    /// Growing an existing volume is measured exactly like creating one that
    /// size — the object as it stands comes out of the sum, and its new size
    /// goes back in. The same rule the VM half has, and the one that gets
    /// forgotten.
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

    /// Every phase holds room, `Releasing` included. Without that a tenant
    /// deletes a volume, creates its replacement in the same second, and
    /// holds twice its quota for as long as the release takes — which is
    /// exactly as long as somebody's VM keeps running.
    #[test]
    fn a_volume_on_its_way_out_still_holds_its_room() {
        for phase in VolumePhaseKind::ALL {
            assert!(holds_room(phase), "{phase:?}");
        }
        let mut vols = disks();
        vols[1].status.phase = VolumePhaseKind::Releasing;
        vols[1].metadata.deletion_timestamp = Some(chrono::Utc::now());
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
