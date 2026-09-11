// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! `VolumeSnapshot`: the object, its row and its verbs.

use super::*;

pub(super) fn volume_snapshot_row(s: VolumeSnapshot) -> Vec<String> {
    let now = Utc::now();
    vec![
        s.metadata.name,
        s.spec.tenant,
        s.spec.volume,
        or_dash(s.status.phase),
        match s.status.size_gib {
            0 => "-".to_string(),
            gib => format!("{gib}Gi"),
        },
        or_dash(s.status.node),
        age(s.metadata.creation_timestamp, now),
        s.spec.description,
    ]
}

#[derive(Deserialize)]
pub(super) struct VolumeSnapshot {
    pub(super) metadata: VolumeMeta,
    pub(super) spec: VolumeSnapshotSpec,
    #[serde(default)]
    pub(super) status: VolumeSnapshotStatus,
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub(super) struct VolumeSnapshotSpec {
    #[serde(default)]
    pub(super) tenant: String,
    #[serde(default)]
    pub(super) volume: String,
    #[serde(default)]
    pub(super) description: String,
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub(super) struct VolumeSnapshotStatus {
    #[serde(default)]
    phase: Option<String>,
    #[serde(default)]
    node: Option<String>,
    #[serde(default)]
    size_gib: u64,
}

pub async fn volume_snapshot(ctx: &Ctx<'_>, cmd: &VolumeSnapshotCmd) -> Result<()> {
    let VolumeSnapshotCmd::Create {
        name,
        volume,
        description,
    } = cmd
    else {
        unreachable!("dispatched generically")
    };
    let mut object = json!({
        "apiVersion": "meister.io/v1",
        "kind": "VolumeSnapshot",
        "metadata": { "name": name },
        "spec": {
            "volume": volume,
            "description": description.clone().unwrap_or_default(),
        },
    });
    // The tenant follows the VOLUME at the server, so this is only what a
    // member's `-t` would have said; sending it as null would be a different
    // request from not sending it at all.
    if let Some(tenant) = &ctx.global.tenant {
        object["spec"]["tenant"] = json!(tenant);
    }
    let body = ctx.post("volumesnapshots", object).await?;
    output::emit_line(ctx.global, &body, name)
}
