// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Capacity reserved for a VM that has not yet reached its destination.

use super::*;

/// Capacity held before a migration destination is prepared, while ordinary
/// VM bindings do not yet account for the arriving guest. The migration name
/// is the create-only key; VM and migration UIDs identify the incarnations.
///
/// Release must follow the migration ownership protocol. An unresolved attempt
/// retains its reservation; elapsed time or a lost reply does not free capacity.
/// The stored resource amounts keep accounting independent of later VM edits.
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
    /// is addressed by.
    #[serde(default)]
    pub vm_uid: String,
    /// The migration this promise belongs to, by name.
    #[serde(default)]
    pub migration: String,
    /// And WHICH migration of that name. A migration is named for a vm and a
    /// moment, and a record can be removed and one made again under the same
    /// name; without this, releasing a reservation would be a delete by name
    /// alone — the ABA hole S19 closed for secrets, in a place where the cost
    /// of getting it wrong is a node carrying twice its memory.
    #[serde(default)]
    pub migration_uid: String,
    /// What the guest asks for, read by `Capacity::wanted_by` off the very
    /// spec the agent will be handed. Stored rather than looked up, because
    /// the whole point of this object is to be readable by a replica that
    /// cannot see the VM's future: a reservation whose size had to be derived
    /// from the VM would stop meaning anything the moment the VM was resized
    /// or removed mid-flight.
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
    /// The reservation one migration would make at `node` for `vm`.
    ///
    /// One constructor, called by the one place that reserves, so the name
    /// and the uid pair can never be filled in two different ways — the whole
    /// of the release and the whole of the reaper are a comparison against
    /// what this wrote.
    pub fn of(migration: &VmMigration, vm: &Vm, node: &str) -> Self {
        Self::declare(
            &migration.metadata.name,
            CapacityReservationSpec {
                node: node.to_string(),
                vm: vm.metadata.name.clone(),
                vm_uid: vm.metadata.uid.clone(),
                migration: migration.metadata.name.clone(),
                migration_uid: migration.metadata.uid.clone(),
                vcpus: crate::scheduler::Capacity::wanted_by(vm).vcpus,
                mem_mib: crate::scheduler::Capacity::wanted_by(vm).mem_mib,
            },
        )
    }

    /// Is this reservation the one `migration` made?
    ///
    /// Name AND uid, which is the whole point of carrying the uid: a record
    /// removed and made again under the same name is a different move, and a
    /// reservation held for the first of them is capacity nobody is coming
    /// for.
    pub fn belongs_to(&self, migration: &VmMigration) -> bool {
        self.spec.migration == migration.metadata.name
            && self.spec.migration_uid == migration.metadata.uid
    }
}

/// The reservations nobody is coming for: the reaper's whole decision, as a
/// function that needs no store.
///
/// A reservation is live exactly while a migration of its own name and uid is
/// still being carried — not final, and not on its way out. Everything else
/// is an orphan, and the four ways to become one are the four ways this
/// comparison fails: the migration finished, it failed, it was deleted, or
/// its name was taken by a later record.
///
/// This is the invariant on the [`CapacityReservation`] type with a store
/// behind it: a reservation outlives nothing. A controller that died between
/// the reservation and the migration's last phase would otherwise hold a
/// machine's room for ever, and nothing in the fleet could say why the node
/// was full.
pub fn orphaned_reservations<'a>(
    held: &'a [CapacityReservation],
    migrations: &[VmMigration],
) -> Vec<&'a CapacityReservation> {
    held.iter()
        .filter(|r| {
            !migrations.iter().any(|m| {
                r.belongs_to(m)
                    && m.metadata.deletion_timestamp.is_none()
                    && !m.status.phase().kind().is_final()
            })
        })
        .collect()
}
