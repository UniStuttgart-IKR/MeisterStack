// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! The address kinds: `FloatingPool`, `FloatingIp` and
//! `RoutedSubnet` — what a tenant is reachable at. Moved out
//! of `resources.rs` unchanged.

use super::*;

/// A range of addresses an operator has, and who may take from it.
///
/// `cidrs` is a list of strings and not one CIDR because that is the shape a
/// real allocation has: four scattered public addresses are four entries, and
/// a lab's private range is one. Each entry is a CIDR, a single address or an
/// `a-b` range — `common::net::Ipv4Ranges` is the parser, shared with the node
/// that has to guard the same addresses.
#[derive(Clone, Debug, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FloatingPoolSpec {
    pub cidrs: Vec<String>,
    /// These addresses are reachable from outside. It changes exactly one
    /// thing in this control plane — the default quota, which is zero — and
    /// that is the whole point: the stack cannot tell a routable address from
    /// a private one by looking at it, so an operator says so, and saying so
    /// closes the door rather than opening it.
    #[serde(default, skip_serializing_if = "is_false")]
    pub public: bool,
    /// The pool a reservation lands in when it names none. At most one pool
    /// may say true, checked at write time: two defaults would make "which
    /// pool did I just take an address from" a question about ordering.
    #[serde(default, skip_serializing_if = "is_false")]
    pub default: bool,
    /// Per-tenant ceiling on reservations out of THIS pool. A tenant that is
    /// not named here gets `DEFAULT_QUOTA_PRIVATE` or `DEFAULT_QUOTA_PUBLIC`
    /// depending on `public` — so raising a tenant's public quota is the one
    /// explicit act that hands out a routable address.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub quota: BTreeMap<String, u32>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub description: String,
}

impl FloatingPoolSpec {
    /// What this tenant may hold here: the named ceiling, or the default the
    /// pool's kind implies.
    pub fn quota_for(&self, tenant: &str) -> u32 {
        self.quota.get(tenant).copied().unwrap_or(if self.public {
            DEFAULT_QUOTA_PUBLIC
        } else {
            DEFAULT_QUOTA_PRIVATE
        })
    }
}

/// Empty, and honestly so: how many addresses are left is a question about
/// the reservations, which are their own objects and are counted when asked.
/// A number cached here would be a number that is wrong after every create.
#[derive(Clone, Debug, Default, Serialize, Deserialize, JsonSchema)]
pub struct FloatingPoolStatus {}

/// No finalizer: a pool owns nothing. What keeps it from vanishing under a
/// reservation is the delete handler's refusal, exactly as a tenant with users
/// in it cannot be deleted.
pub type FloatingPool = Object<FloatingPoolSpec, FloatingPoolStatus>;

/// One address, held by one tenant, optionally pointed at one VM.
///
/// The object's `metadata.name` IS the address, and that is deliberate: the
/// address is the identity here, it is what an operator types (`floatingip
/// assign 10.255.0.7 --vm web`), and it is the only name under which two
/// racing allocators can collide — which turns the store's own create into
/// the compare-and-swap the allocation needs. See `floating::allocate`.
#[derive(Clone, Debug, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FloatingIpSpec {
    /// Whose reservation this is. Never empty on a STORED object — a floating
    /// address belongs to somebody or it is not reserved — but defaulted on
    /// the way in, because the request a member sends names no tenant at all:
    /// the server fills in their own, exactly as it does for a VM. A required
    /// field here would make the self-service path a deserialization error.
    #[serde(default)]
    pub tenant: String,
    /// Which pool it came out of. Server-set at create (the named pool, or
    /// the default one) and immutable afterwards — the pool is where the
    /// address came from, and an object that could be re-pointed at another
    /// pool would move an address into a range that does not contain it.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub pool: String,
    /// The address itself, server-set and equal to `metadata.name`. Written
    /// twice on purpose: the name is how the store finds it, and the spec is
    /// what everything downstream reads, so a caller reading the object never
    /// has to know that the two are the same string.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub address: String,
    /// The VM this address is for, by name, inside the same tenant. `None` =
    /// reserved and unassigned, which is a perfectly good state: the address
    /// is the tenant's from the moment they take it, and pointing it at a VM
    /// is a second, reversible decision.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vm: Option<String>,
    /// Which `Router` carries the 1:1 translation for this address.
    ///
    /// Empty — the default and every reservation written before 6k — is the
    /// road this stack has always taken: the address lives IN the guest, the
    /// node lets that one source address past its pool guard, and FRR
    /// announces a /32 from the compute node. Distributed, no gateway in the
    /// path, and it works exactly as long as the address is routable to the
    /// node.
    ///
    /// Naming a router is the other road, and it is the one a tenant behind
    /// SNAT needs: the address never reaches the guest at all, and the router
    /// translates it to [`FloatingIpSpec::internal_address`] and back —
    /// OVN's `dnat_and_snat`. See `Router.status.nats`.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub router: String,
    /// The address the guest holds on its own overlay — the inside half of
    /// the 1:1 pair.
    ///
    /// The half this control plane cannot learn, and the field exists because
    /// of that rather than in spite of it. There is no IPAM for a tenant
    /// overlay here (see `RouterSpec.internal_addr`), no DHCP served by this
    /// tier and no agent in the guest; `Vm.status.addresses` carries the MACs
    /// a node reported and deliberately no addresses, because "the address a
    /// guest gave itself is known to the guest and to nobody here".
    ///
    /// Empty with a `router` named is a reservation nothing can be derived
    /// from: no `dnat_and_snat` rule is written, and `router get` shows the
    /// address missing from `status.nats`, which is the visible form of the
    /// question "what is it supposed to translate to".
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub internal_address: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct FloatingIpStatus {
    /// The last `metadata.generation` this reservation was carried down on.
    ///
    /// Kubernetes' half of the pair, and the whole of what it says is:
    /// `observedGeneration < generation` means the spec was changed after the
    /// controller last did something about it. For an address that is what
    /// `meister floatingip ls` prints as `APPLIED`: an assign takes effect
    /// when the VM is next created, and until then the cloud has not yet put
    /// this address into a `CreateVm`.
    ///
    /// `0` on an object nothing has been dispatched for yet, and on every
    /// object written before this field existed.
    #[serde(default)]
    pub observed_generation: u64,
}

pub type FloatingIp = Object<FloatingIpSpec, FloatingIpStatus>;

/// A real subnet a tenant owns, routed rather than translated.
///
/// The other half of the network story and the one the lab wants: a tenant
/// with a routed subnet needs no NAT and no gateway appliance to be reachable
/// — the addresses inside its overlay ARE the addresses outside it. The
/// hoster's mode is the same stack without this object: a tenant with no
/// routed subnet gets whatever private space it likes behind its own NAT
/// appliance, and this control plane never learns those addresses.
///
/// It also completes the anti-spoofing. A tenant whose address space is
/// UNKNOWN can only be told "not out of the floating pool"; a tenant whose
/// address space is written down here can be told "these and nothing else".
#[derive(Clone, Debug, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RoutedSubnetSpec {
    pub tenant: String,
    /// The subnet, CIDR. Either cut from the cloud's `routed_pools` at create
    /// time or named outright by the admin; either way it may not overlap any
    /// other routed subnet or any floating pool.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub cidr: String,
    /// How big a block to cut when `cidr` was left empty. Kept on the object
    /// afterwards although `cidr` makes it redundant, for the reason
    /// `NicSpec.bridge` is kept next to `vxlan_id`: the record goes on saying
    /// what was ASKED for, and an admin reading it can see whether a /24 was
    /// a request or a coincidence.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prefix_len: Option<u32>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub description: String,
}

/// The block size a routed subnet gets when nobody names one. A /24 is what
/// an operator draws on a whiteboard, and it is small enough that a /16 super
/// pool holds 256 tenants' worth of them.
pub const DEFAULT_ROUTED_PREFIX_LEN: u32 = 24;

#[derive(Clone, Debug, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct RoutedSubnetStatus {
    /// The last `metadata.generation` this subnet was carried down on.
    ///
    /// Kubernetes' half of the pair, and the whole of what it says is:
    /// `observedGeneration < generation` means the spec was changed after the
    /// controller last did something about it. Same meaning as on a floating address: the subnet reaches a node inside a
    /// `CreateVm`, so it lands when the tenant's VMs are next created.
    ///
    /// `0` on an object nothing has been dispatched for yet, and on every
    /// object written before this field existed.
    #[serde(default)]
    pub observed_generation: u64,
}

pub type RoutedSubnet = Object<RoutedSubnetSpec, RoutedSubnetStatus>;

// --- the storage a tenant may claim -----------------------------------------
//
// The same two-object shape the addresses have, and deliberately so: a pool an
// administrator declares, and a reservation a member takes out of it inside a
// quota. Reading `FloatingPoolSpec` and `FloatingIpSpec` above is reading this
// pair with different nouns.
//
// One difference is worth naming before the code, because it changes what the
// refusals are worth. At the end of a confused floating address is a tenant
// that cannot be reached. At the end of a confused volume is data that is
// gone. That is why `Volume` carries a finalizer and `FloatingIp` does not,
// and why the backend name is derived rather than allocated.
