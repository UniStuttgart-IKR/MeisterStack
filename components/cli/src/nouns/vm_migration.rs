// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! `VmMigration`: the object and its row. The verbs are in
//! [`crate::vm`], with the other things one does to a machine.

use super::*;

#[derive(Deserialize)]
pub(super) struct VmMigration {
    metadata: BareMeta,
    #[serde(default)]
    spec: VmMigrationSpec,
    #[serde(default)]
    status: VmMigrationStatus,
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub(super) struct VmMigrationSpec {
    #[serde(default)]
    tenant: String,
    #[serde(default)]
    vm: String,
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub(super) struct VmMigrationStatus {
    #[serde(default)]
    phase: Option<String>,
    #[serde(default)]
    source_node: Option<String>,
    #[serde(default)]
    target_node: Option<String>,
    #[serde(default)]
    message: Option<String>,
}

pub(super) fn vm_migration_row(m: VmMigration, now: DateTime<Utc>) -> Vec<String> {
    vec![
        m.metadata.name,
        or_dash(Some(m.spec.tenant).filter(|t| !t.is_empty())),
        m.spec.vm,
        or_dash(m.status.phase),
        or_dash(m.status.source_node),
        or_dash(m.status.target_node),
        age(m.metadata.creation_timestamp, now),
        m.status.message.unwrap_or_default(),
    ]
}
