// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Capacity reserved for a VM not yet at its destination: live migration or placement.

use super::*;

/// How long a placement claim may stand before the reaper reads it as abandoned.
/// Reaping early is safe: the binding is refused once its claim is gone
/// (`EtcdStore::update_if_standing`); the bound only delays a crashed placement's room.
pub const STALE_PLACEMENT_AFTER_SECS: i64 = 60;

/// Prefix of a placement claim's name, followed by the guest's uid. The `.` is what no DNS
/// label, and so no migration name, can hold: placement and migration claims share one
/// directory and can never share a key, whatever a user names a migration (R2-3).
const PLACEMENT_CLAIM_PREFIX: &str = "place.";

/// Which road to a node holds this room; the reaper releases each on a different fact.
/// `Migration` is the default so objects stored before this field existed stay migrations.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub enum Claimant {
    /// A live migration's destination, held from `prepare` until the binding moves there.
    #[default]
    Migration,
    /// An ordinary placement, held from the scheduler's decision until the binding.
    Placement,
}

/// Capacity claimed on one node for a guest not bound there yet: a migration destination
/// (the guest stays bound to the source until settlement) or a placement before binding.
/// Both roads take the same commit, so neither can overfill a node (R3-F05; S07):
///
///   1. CLAIM: create-only write (key: migration name or `place.<vm uid>`), unique across
///      replicas.
///   2. CONFIRM: [`crate::capacity::claim_holds`] reads node, VMs and reservations at one
///      revision; the allowance must cover bound guests, earlier claims (etcd
///      `mod_revision` order) and this one. A failed read is a failed verdict (R3-F04).
///   3. BIND: CAS on `spec.nodeName`; a placement also requires the claim to stand.
///   4. RELEASE: guarded delete after the binding, so the guest is always counted.
///
/// An object, not a node field: replicas share only etcd. Orphans: [`orphaned_reservations`].
#[derive(Clone, Debug, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CapacityReservationSpec {
    /// The machine the room is promised on.
    #[serde(default)]
    pub node: String,
    /// The guest it is promised to, by name — for the sentence a person
    /// reads, and for nothing a decision is made on.
    #[serde(default)]
    pub vm: String,
    /// Which guest it is. A name is what people call a VM and people reuse
    /// names; this is the identity, and it is what a destination's `Destroy`
    /// is addressed by, and what a placement's claim is named after.
    #[serde(default)]
    pub vm_uid: String,
    /// Which road the guest is on, and therefore which fact releases this.
    #[serde(default)]
    pub claimant: Claimant,
    /// The migration this promise belongs to, by name; empty for a placement's claim.
    #[serde(default)]
    pub migration: String,
    /// Migration UID, preventing a later resource with the same name from inheriting the claim.
    #[serde(default)]
    pub migration_uid: String,
    /// Serialized VM requirements read by Capacity::wanted_by using the same accounting as
    /// ordinary placement.
    #[serde(default)]
    pub vcpus: u32,
    #[serde(default)]
    pub mem_mib: u64,
}

impl CapacityReservationSpec {
    /// The promise, in the units a candidate's room is measured in.
    pub fn size(&self) -> crate::scheduler::Capacity {
        crate::scheduler::Capacity {
            vcpus: self.vcpus,
            mem_mib: self.mem_mib,
        }
    }
}

pub type CapacityReservation = Object<CapacityReservationSpec, ()>;

impl CapacityReservation {
    /// Construct the destination reservation for one migration and VM identity.
    pub fn of(migration: &VmMigration, vm: &Vm, node: &str) -> Self {
        let size = crate::scheduler::Capacity::wanted_by(vm);
        Self::declare(
            &migration.metadata.name,
            CapacityReservationSpec {
                node: node.to_string(),
                vm: vm.metadata.name.clone(),
                vm_uid: vm.metadata.uid.clone(),
                claimant: Claimant::Migration,
                migration: migration.metadata.name.clone(),
                migration_uid: migration.metadata.uid.clone(),
                vcpus: size.vcpus,
                mem_mib: size.mem_mib,
            },
        )
    }

    /// The claim one placement would make at `node` for `vm`.
    ///
    /// Named by the guest's UID, not its name (as `migration_uid`): names are reused, and a
    /// claim for a deleted VM must not be taken for its namesake's. `place.<uuid>` is not a
    /// DNS label, and a migration's name always is, so the two roads cannot collide on a key.
    pub fn for_placement(vm: &Vm, node: &str) -> Self {
        let size = crate::scheduler::Capacity::wanted_by(vm);
        Self::declare(
            &format!("{PLACEMENT_CLAIM_PREFIX}{}", vm.metadata.uid),
            CapacityReservationSpec {
                node: node.to_string(),
                vm: vm.metadata.name.clone(),
                vm_uid: vm.metadata.uid.clone(),
                claimant: Claimant::Placement,
                migration: String::new(),
                migration_uid: String::new(),
                vcpus: size.vcpus,
                mem_mib: size.mem_mib,
            },
        )
    }

    /// Match both migration name and UID so recreated operations cannot adopt old reservations.
    pub fn belongs_to(&self, migration: &VmMigration) -> bool {
        self.spec.claimant == Claimant::Migration
            && self.spec.migration == migration.metadata.name
            && self.spec.migration_uid == migration.metadata.uid
    }

    /// Whether this is the claim a placement of `vm` made (matched by uid).
    pub fn is_placement_of(&self, vm: &Vm) -> bool {
        self.spec.claimant == Claimant::Placement && self.spec.vm_uid == vm.metadata.uid
    }

    /// Whether somebody is still coming for this room, as far as `migrations` and `vms`
    /// can say at `now`.
    ///
    /// A migration's claim is live while its migration (name and uid) is still being carried;
    /// a placement's while its guest exists, is not deleting, is unbound, and the claim is
    /// younger than `STALE_PLACEMENT_AFTER_SECS`. A claim without a creation time is read as
    /// ancient: the store stamps every object it writes, so an unstamped one is nobody's.
    pub fn is_live(&self, migrations: &[VmMigration], vms: &[Vm], now: DateTime<Utc>) -> bool {
        match self.spec.claimant {
            Claimant::Migration => migrations.iter().any(|m| {
                self.belongs_to(m)
                    && m.metadata.deletion_timestamp.is_none()
                    && !m.status.phase().kind().is_final()
            }),
            Claimant::Placement => {
                let young = self.metadata.creation_timestamp.is_some_and(|made| {
                    now.signed_duration_since(made).num_seconds() <= STALE_PLACEMENT_AFTER_SECS
                });
                young
                    && vms.iter().any(|v| {
                        v.metadata.uid == self.spec.vm_uid
                            && v.metadata.deletion_timestamp.is_none()
                            && v.spec.node_name.is_none()
                    })
            }
        }
    }
}

/// Reservations nobody is coming for, decided without a store; liveness per road is
/// [`CapacityReservation::is_live`]. `now` is a parameter so the age rule is testable.
pub fn orphaned_reservations<'a>(
    held: &'a [CapacityReservation],
    migrations: &[VmMigration],
    vms: &[Vm],
    now: DateTime<Utc>,
) -> Vec<&'a CapacityReservation> {
    held.iter()
        .filter(|r| !r.is_live(migrations, vms, now))
        .collect()
}
