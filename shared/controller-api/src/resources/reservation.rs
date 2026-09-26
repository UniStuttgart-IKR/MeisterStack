// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Capacity reserved for a VM that has not yet reached its destination.

use super::*;

/// Capacity claim held while preparing a migration destination. It competes with ordinary VM
/// placement and belongs to one migration name/UID pair.
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

    /// Match both migration name and UID so recreated operations cannot adopt old reservations.
    pub fn belongs_to(&self, migration: &VmMigration) -> bool {
        self.spec.migration == migration.metadata.name
            && self.spec.migration_uid == migration.metadata.uid
    }
}

/// A reservation is live only while its matching migration name and UID exists, is nonterminal,
/// and is not deleting. Finished, failed, deleted, or recreated migrations leave orphan
/// reservations for the reaper.
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
