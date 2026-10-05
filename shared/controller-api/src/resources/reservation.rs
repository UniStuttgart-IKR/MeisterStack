// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Capacity reserved for a VM that has not yet reached its destination, by
//! either road: live migration or ordinary placement.

use super::*;

/// How long a placement claim may stand before the reaper reads it as abandoned.
/// A placement holds it for one confirmation and one binding. Reaping early is
/// safe because the binding is refused once its claim is gone
/// (`EtcdStore::update_if_standing`), so the bound only delays a crashed
/// placement's room by a minute.
pub const STALE_PLACEMENT_AFTER_SECS: i64 = 60;

/// The prefix a placement's claim is named under, ahead of the guest's uid.
const PLACEMENT_CLAIM_PREFIX: &str = "place-";

/// Which road to a node holds this room; the reaper releases each on a different
/// fact. `Migration` is the default so promises written before this field read
/// as what they were.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub enum Claimant {
    /// A live migration's destination, held from `prepare` until the guest's
    /// binding moves there.
    #[default]
    Migration,
    /// An ordinary placement, held from the scheduler's decision until the
    /// binding is written.
    Placement,
}

/// Capacity claimed on one node for a guest that is not bound there yet: a live
/// migration's destination (the guest stays bound to the source until settlement)
/// or a placement between decision and binding. Both roads take the same commit:
///
///   1. CLAIM: create-only write; the key (migration name, or `place-<vm uid>`)
///      makes "one claim per move" a store fact across replicas.
///   2. CONFIRM: [`crate::capacity::claim_holds`] reads node, VMs and reservations
///      at one revision and checks the allowance covers bound guests, every claim
///      written before this one (etcd `mod_revision` order) and this claim. A failed
///      read is a failed verdict (R3-F04).
///   3. BIND: CAS on `spec.nodeName`; a placement also requires the claim to stand
///      unchanged in the same transaction (`EtcdStore::update_if_standing`).
///   4. RELEASE: guarded delete after the binding, never before, so the guest is
///      counted at least once at every revision (twice for one round trip).
///
/// Given two claims on one node, the later one confirms after the earlier one's
/// write, when the earlier is still a reservation or already bound, so neither
/// road can overfill a node (R3-F05; S07 for the migration half). Orphans are
/// reaped by [`orphaned_reservations`]. An object rather than a node field because
/// replicas share only etcd, and a create-only key is what makes the claim unique.
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
    /// The migration this promise belongs to, by name. Empty for a
    /// placement's claim.
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
    /// Named after the guest's UID and not its name, for the reason
    /// `migration_uid` exists: names are reused, and a claim standing for a
    /// VM that was deleted and made again under the same name must not be
    /// mistaken for the new one's. The uid is a lowercase UUID, which is a
    /// DNS label with a prefix on it, and no migration is named this way —
    /// so the two roads' claims cannot collide on a key.
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

    /// Is this the claim a placement of `vm` made — this very VM, by uid?
    pub fn is_placement_of(&self, vm: &Vm) -> bool {
        self.spec.claimant == Claimant::Placement && self.spec.vm_uid == vm.metadata.uid
    }

    /// Is somebody still coming for this room, as far as `migrations` and
    /// `vms` can say at `now`?
    ///
    /// The two roads are released by two different facts, and this is where
    /// the field that tells them apart is read. A migration's promise is live
    /// while a migration of its own name and uid is still being carried; a
    /// placement's while its guest exists, is not on its way out, is bound
    /// nowhere, and the claim is younger than a placement can take. A claim
    /// with no creation time at all is read as ancient — the store stamps
    /// every object it makes, so one without a stamp is nothing this control
    /// plane wrote, and the safe reading of it is "nobody's".
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

/// Reservations nobody is coming for, decided without a store. Liveness per road
/// is [`CapacityReservation::is_live`]: a migration's while its matching name and
/// UID is nonterminal and not deleting; a placement's while its guest exists, is
/// unbound and not deleting, and the claim is younger than
/// [`STALE_PLACEMENT_AFTER_SECS`]. `now` is a parameter so the age rule is testable.
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
