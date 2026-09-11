// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! The `Tenant` kind: who an object belongs to, and how much of
//! the estate they may take. Moved out of `resources.rs`
//! unchanged.

use super::*;

/// A tenant is the unit a user belongs to and, from M5, the unit a VM and an
/// image belong to. It is also the unit a NETWORK belongs to: every tenant
/// carries a VXLAN network identifier, and that number is what makes the
/// isolation real rather than a label on an object.
#[derive(Clone, Debug, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TenantSpec {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub description: String,
    /// How much this tenant may hold. Every field absent = unlimited, which
    /// is what every tenant written before this milestone says and therefore
    /// exactly what every one of them keeps doing.
    #[serde(default, skip_serializing_if = "TenantQuota::is_unset")]
    pub quota: TenantQuota,
    /// The tenant's overlay network, allocated by the cloud at create time
    /// and never afterwards. Server-owned and immutable, for the reason every
    /// identifier that names a wire is: two tenants sharing a VNI is not a
    /// conflict anybody would notice from an object, it is two tenants on one
    /// broadcast domain. `None` is a tenant created before this milestone, or
    /// one on a cloud that allocates none — it gets no overlay and its VMs
    /// land on the default bridge, exactly as they did yesterday.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vni: Option<u32>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub labels: BTreeMap<String, String>,
}

/// The ceiling on what a tenant may hold, one number per thing that runs out.
///
/// Every field optional, and absent means unlimited rather than zero. That is
/// the whole compatibility story: `floatingpool quota` was the only quota in
/// this system, so nothing else here was ever bounded, and a default of
/// anything but "unlimited" would stop a running fleet the moment this
/// milestone rolled out.
///
/// Set by an admin and by nobody else. Not a rule written here — the
/// middleware already says it, because `tenants` is not among the resources a
/// member may write (`auth::TENANT_SCOPED`), so a member raising their own
/// ceiling never reaches a handler at all.
#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TenantQuota {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_vms: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_vcpus: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_mem_mib: Option<u64>,
}

impl TenantQuota {
    /// No ceiling of any kind — the shape every tenant had before this
    /// existed, and the one that is not serialised at all.
    pub fn is_unset(&self) -> bool {
        self.max_vms.is_none() && self.max_vcpus.is_none() && self.max_mem_mib.is_none()
    }
}

/// What a tenant is holding right now.
///
/// Computed where it is read and never stored, for the reason a candidate's
/// free capacity is: both halves are objects the server already has, and a
/// second copy in etcd would be a number that can be wrong — here in the
/// direction that lets a tenant past its own ceiling.
#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct TenantUsage {
    #[serde(default)]
    pub vms: u32,
    #[serde(default)]
    pub vcpus: u32,
    #[serde(default)]
    pub mem_mib: u64,
}

/// What the tenant is using, filled in by the read that hands the object out.
///
/// The design gave a tenant `clusters` and `vmCount` and neither was
/// computable while VMs were not tenant-bound; they are now. Nothing writes
/// this to the store — a `Tenant` read back out of etcd carries zeros, and
/// the API is what puts the truth in it.
#[derive(Clone, Debug, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct TenantStatus {
    #[serde(default)]
    pub used: TenantUsage,
}

/// No finalizer: a tenant owns no resource anywhere yet, so DELETE can mean
/// delete — the same reason an Image has none.
pub type Tenant = Object<TenantSpec, TenantStatus>;

// --- the addresses a tenant may claim ---------------------------------------
//
// Two objects and a rule. The pool says which addresses exist and who may take
// how many of them; the reservation says who holds one and which VM it is for.
// Nothing here routes a packet or answers an ARP — that is the tenant's own
// appliance, or the environment's static route, or Part C's announcement. What
// this pair produces is OWNERSHIP, and ownership is what the node's nftables
// rules turn into an answer to "may this tap send from this address".

/// How many addresses a tenant may hold out of a PRIVATE pool without anybody
/// being asked. Four is a lab's worth: a gateway, a load balancer and two
/// spare — enough to build the appliance pattern without a ticket.
pub const DEFAULT_QUOTA_PRIVATE: u32 = 4;

/// And out of a PUBLIC one: none. A routable address is the scarce thing an
/// operator was actually given by somebody else, and the design rule is that
/// an admin hands those out one tenant at a time by raising this pool's quota
/// for them. A default of anything but zero would be this control plane
/// giving away addresses it does not own.
pub const DEFAULT_QUOTA_PUBLIC: u32 = 0;
