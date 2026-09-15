// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! The typed resources. The embedded VM definition stays the agent's
//! NewVmSpec JSON verbatim — one spec format everywhere, the agent is the
//! validating authority.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
pub use common::capability::Locality;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::object::{Metadata, Object, Resource};

pub const API_VERSION: &str = "meister.io/v1";

#[macro_use]
// The phase machinery every resource below uses, so it has to be textually
// first: `macro_rules!` is in scope from its definition on, and `#[macro_use]`
// on a module is what carries it to the sibling modules.
mod phase;

mod cluster;
mod counter;
mod csr;
mod event;
mod floating;
mod image;
mod migration;
mod network;
mod node;
mod pool;
mod secret;
mod tenant;
mod ticket;
mod user;
mod vm;
mod volume;

pub use cluster::*;
pub use counter::*;
pub use csr::*;
pub use event::*;
pub use floating::*;
pub use image::*;
pub use migration::*;
pub use network::*;
pub use node::*;
pub use phase::*;
pub use pool::*;
pub use secret::*;
pub use tenant::*;
pub use ticket::*;
pub use user::*;
pub use vm::*;
pub use volume::*;

/// The resource table: every kind this control plane stores, with the
/// directory it lives in and the `kind` its envelope wears. One place, so that
/// adding a resource is adding a row rather than remembering to add a pair of
/// constants, a constructor and an entry in whatever else went by the name.
///
/// The store reads both off the type (`crate::object::Resource`), which is why
/// nothing outside this table ever spells a resource name again.
/// A row may also carry a `{ ... }` block of extra associated items, which is
/// where `Resource::settle` lives: the derivation is a statement about ONE
/// resource, so it is written beside that resource's row and reads as part of
/// it. A row without a block keeps the trait's no-op — the resources with no
/// phase at all (`Node`, `Secret`, `Ticket`, …) have nothing to derive.
macro_rules! resources {
    ($(
        $(#[$about:meta])*
        $ty:ty => $resource:literal, $kind:literal $(, $shape:path)?
        $({ $($item:item)* })? ;
    )*) => {
        $(
            $(#[$about])*
            impl Resource for $ty {
                const RESOURCE: &'static str = $resource;
                const KIND: &'static str = $kind;
                // A row that names a shape gets it; every other row keeps the
                // trait's default, which is the DNS label.
                $( const NAME_SHAPE: crate::object::NameShape = $shape; )?
                $( $($item)* )?
            }
        )*

        /// The table itself, for the checks that have to walk every row of
        /// it. Public since the discovery tables: each tier's router has to
        /// account for every row of this — served, or named as not served —
        /// and those two checks live in the crates the routers live in.
        pub const ALL_RESOURCES: &[(&str, &str)] = &[
            $( (<$ty as Resource>::RESOURCE, <$ty as Resource>::KIND) ),*
        ];
    };
}

resources! {
    Vm => "vms", "Vm";
    Node => "nodes", "Node";
    Cluster => "clusters", "Cluster";
    /// Named after the FILE a node looks it up as, extension and all — so a
    /// dotted name, not a label. `debian-13.raw` is what an image is called;
    /// insisting on a label here meant no image with an extension could be
    /// catalogued at all. See `NameShape`.
    Image => "images", "Image", crate::object::NameShape::Dotted {
        /// What the fleet's words add up to. See [`settle_image`].
        fn settle(&mut self, now: DateTime<Utc>) {
            let phase = settle_image(&self.spec, &self.status);
            self.status.stamp(phase, now);
        }
    };
    Tenant => "tenants", "Tenant";
    User => "users", "User";
    CertificateSigningRequest => "certificatesigningrequests", "CertificateSigningRequest";
    /// Server-owned counters — the one object kind here that is not something
    /// an operator creates, lists or names. See `vni`.
    Counter => "counters", "Counter";
    /// The address side of the network, MetalLB's shape: a pool is an OBJECT
    /// and not a config key, so an operator adds public addresses with the
    /// same verb they add anything else with, and a second cloud replica reads
    /// the same pools out of the same store.
    FloatingPool => "floatingpools", "FloatingPool";
    /// Named after its ADDRESS — the name and `spec.address` are the same
    /// string on purpose — so a dotted name. A DNS label cannot hold an
    /// address, and while it was required here every reservation was a 422.
    /// See `NameShape`.
    FloatingIp => "floatingips", "FloatingIp", crate::object::NameShape::Dotted;
    /// A real subnet a tenant owns — the NAT-free half of the story. See
    /// `RoutedSubnetSpec`.
    RoutedSubnet => "routedsubnets", "RoutedSubnet";
    /// The wire a cluster gave away, by the name a node claims it under: the
    /// operator's half of north-south, and an administrator's to declare. See
    /// `ProviderNetworkSpec`.
    ProviderNetwork => "providernetworks", "ProviderNetwork";
    /// A tenant's way out over one of those — the tenant's half. See
    /// `RouterSpec`.
    Router => "routers", "Router" {
        /// The last word anybody established about it. See [`settle_router`].
        fn settle(&mut self, now: DateTime<Utc>) {
            let phase = settle_router(&self.status);
            self.status.stamp(phase, now);
        }
    };
    /// The storage side of the same shape the network side has: what EXISTS
    /// is an administrator's decision, and taking room out of it is
    /// self-service inside a quota. See `StoragePoolSpec`.
    StoragePool => "storagepools", "StoragePool" {
        /// What the nodes — or the cluster this pointer names — have said.
        /// See [`settle_storage_pool`].
        fn settle(&mut self, now: DateTime<Utc>) {
            let phase = settle_storage_pool(&self.metadata.name, &self.spec, &self.status);
            self.status.stamp(phase, now);
        }
    };
    /// A volume with a life of its own — the object that lets a disk outlive
    /// the VM that was using it. See `VolumeSpec`.
    Volume => "volumes", "Volume";
    /// A point in time of a volume, which outlives the volume. See
    /// `VolumeSnapshotSpec`.
    VolumeSnapshot => "volumesnapshots", "VolumeSnapshot" {
        /// The last word anybody said about the copy. See
        /// [`settle_volume_snapshot`].
        fn settle(&mut self, now: DateTime<Utc>) {
            let phase = settle_volume_snapshot(&self.status);
            self.status.stamp(phase, now);
        }
    };
    /// A tenant's own bytes, sealed before they reach etcd. See
    /// `SecretSpec`.
    Secret => "secrets", "Secret";
    /// One live migration of one VM: the intent, and how far it got. See
    /// `VmMigrationSpec`.
    VmMigration => "vmmigrations", "VmMigration" {
        /// How far the move got. See [`settle_vm_migration`].
        fn settle(&mut self, now: DateTime<Utc>) {
            let phase = settle_vm_migration(&self.status);
            self.status.stamp(phase, now);
        }
    };
    /// One credential, for one URL, for thirty seconds — and the second
    /// resource that expires by itself. Served by nobody: a client that could
    /// list these could read every other client's outstanding credential. See
    /// `TicketSpec`.
    Ticket => "tickets", "Ticket";
    /// The other resource that expires by itself, and the older of the two.
    /// See `EventSpec`.
    Event => "events", "Event";
}

/// The cloud's ownership marker on a cluster-local object (the ownerRef
/// analogon of the design). Only the cloud session may change or delete an
/// object that carries it; a VM created straight at the cluster does not, and
/// local operation stays as free as it was.
pub const LABEL_MANAGED_BY: &str = "meister.io/managed-by";
pub const MANAGED_BY_CLOUD: &str = "cloud";
/// The uid of the cloud object this cluster-local object stands for. Names are
/// what people call VMs and people reuse names; this is which VM it is.
pub const LABEL_CLOUD_UID: &str = "meister.io/cloud-uid";

/// May something owned by `mine` name a tenant-scoped object whose
/// `spec.tenant` is `theirs`?
///
/// A tenant is what a name is scoped BY: two tenants may both have a volume
/// called `data-1`, and each of them has exactly one. So this is not a
/// permission question — `permits_object` answers that — but a NAMING one,
/// and the two are asked at different moments. By the time a VM spec names a
/// volume, the caller has already been allowed to write in this tenant; what
/// is left is whether the name they wrote means anything here.
///
/// One function because two tiers ask it about the same pair of objects, and
/// the empty-vs-absent seam is where a second copy would drift: a `Volume`
/// spells "nobody's" as `""` and a `Vm` spells it as `None`, and the admin's
/// own unscoped estate — both sides nobody's — has to match. An
/// implementation that compared `Some("")` against `None` would refuse an
/// admin their own disks, and one that let an empty tenant match a named one
/// would hand every tenant the admin's.
pub fn same_tenancy(theirs: &str, mine: Option<&str>) -> bool {
    match mine.filter(|t| !t.is_empty()) {
        Some(mine) => theirs == mine,
        None => theirs.is_empty(),
    }
}

/// The cloud's ownership marks on a cluster-local object. They are server-owned
/// the way uid and status are: a client that could write them could make its
/// own VM unremovable, or take the mark off one that really does belong to the
/// cloud.
impl Metadata {
    pub fn managed_by_cloud(&self) -> bool {
        self.labels.get(LABEL_MANAGED_BY).map(String::as_str) == Some(MANAGED_BY_CLOUD)
    }

    /// Which cloud object this one stands for. A name is what people call a VM
    /// and people reuse names; this is which VM it is.
    pub fn cloud_uid(&self) -> Option<&str> {
        self.labels.get(LABEL_CLOUD_UID).map(String::as_str)
    }

    pub fn mark_managed_by_cloud(&mut self, uid: &str) {
        self.labels
            .insert(LABEL_MANAGED_BY.to_string(), MANAGED_BY_CLOUD.to_string());
        self.labels
            .insert(LABEL_CLOUD_UID.to_string(), uid.to_string());
    }
}

/// A new object of this resource, wearing the envelope its own type carries.
///
/// This replaced nine `new_*` helpers that were the same line each, and every
/// one of them was a place where a resource could be created wearing another
/// resource's kind. A VM keeps a constructor of its own because it is more
/// than an envelope — see `new_vm`.
impl<S, St: Default> Object<S, St>
where
    Self: Resource,
{
    pub fn declare(name: &str, spec: S) -> Self {
        Self::new(API_VERSION, Self::KIND, name, spec)
    }
}

fn schedulable_default() -> bool {
    true
}

impl Default for NodeSpec {
    fn default() -> Self {
        Self {
            schedulable: true,
            drain: false,
            labels: BTreeMap::new(),
            accepts: Vec::new(),
        }
    }
}

fn is_false(b: &bool) -> bool {
    !*b
}

fn is_zero(n: &u32) -> bool {
    *n == 0
}

#[cfg(test)]
mod tests;
