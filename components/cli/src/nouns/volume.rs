// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Volume rows, snapshot counts and volume commands.

use super::*;

#[derive(Deserialize)]
pub(super) struct Volume {
    metadata: VolumeMeta,
    #[serde(default)]
    spec: VolumeSpec,
    #[serde(default)]
    status: VolumeStatus,
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub(super) struct VolumeSpec {
    #[serde(default)]
    tenant: String,
    #[serde(default)]
    pool: String,
    #[serde(default)]
    size_gib: u64,
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub(super) struct VolumeStatus {
    #[serde(default)]
    phase: Option<String>,
    #[serde(default)]
    node: Option<String>,
    #[serde(default)]
    attached_to: Option<String>,
    /// Reported openers; live migration can temporarily report more than one.
    #[serde(default)]
    open_on: Vec<String>,
    /// Measured size; zero means no measurement is available.
    #[serde(default)]
    size_gib: u64,
}

/// Show measured-to-requested size while resize is pending.
/// Omit the snapshot column when discovery does not expose snapshots.
pub(super) fn volume_row(v: Volume, snapshots: Option<usize>, now: DateTime<Utc>) -> Vec<String> {
    let size = match v.status.size_gib {
        0 => format!("{}Gi", v.spec.size_gib),
        have if have == v.spec.size_gib => format!("{have}Gi"),
        have => format!("{have}Gi->{}Gi", v.spec.size_gib),
    };
    // Show all reported openers during overlap, otherwise the home node.
    let node = match v.status.open_on.len() {
        0 | 1 => or_dash(v.status.node),
        _ => v.status.open_on.join(","),
    };
    let mut row = vec![
        v.metadata.name,
        v.spec.tenant,
        or_dash(Some(v.spec.pool).filter(|p| !p.is_empty())),
        size,
        or_dash(v.status.phase),
        node,
        or_dash(v.status.attached_to),
    ];
    // Summarize dependent snapshots without expanding the row.
    if let Some(n) = snapshots {
        row.push(match n {
            0 => "-".to_string(),
            n => n.to_string(),
        });
    }
    row.push(age(v.metadata.creation_timestamp, now));
    row
}

/// List volumes and count snapshots with one additional request.
pub async fn list_volumes(ctx: &Ctx<'_>, selector: Option<&str>) -> Result<()> {
    let body = ctx
        .client
        .get(&format!(
            "{}{}",
            ctx.path("volumes", None)?,
            crate::generic::query(ctx.global, selector)
        ))
        .await?;
    // Use discovery to omit unsupported snapshot counts.
    let counts: Option<std::collections::HashMap<String, usize>> =
        match ctx.path("volumesnapshots", None) {
            Err(e) => {
                tracing::debug!(error = %format!("{e:#}"), "this endpoint serves no snapshots");
                None
            }
            // Keep the volume listing available if the optional snapshot request fails.
            // The current fallback renders the same count as an empty snapshot list.
            Ok(path) => {
                let snapshots: Vec<VolumeSnapshot> = match ctx.client.get(&path).await {
                    Ok(body) => output::items::<VolumeSnapshot>(&body, "parsing snapshot list")
                        .unwrap_or_default(),
                    Err(e) => {
                        tracing::debug!(
                            error = %format!("{e:#}"),
                            "listing snapshots for the count failed"
                        );
                        Vec::new()
                    }
                };
                Some(snapshots.iter().fold(Default::default(), |mut acc, s| {
                    *acc.entry(s.spec.volume.clone()).or_default() += 1;
                    acc
                }))
            }
        };
    let has_snapshots = counts.is_some();
    output::emit(ctx.global, &body, move |body| {
        let now = Utc::now();
        let rows = output::items::<Volume>(body, "parsing volume list")?
            .into_iter()
            .map(|v| {
                let n = counts
                    .as_ref()
                    .map(|c| c.get(&v.metadata.name).copied().unwrap_or(0));
                volume_row(v, n, now)
            })
            .collect();
        // Keep headers aligned with the optional snapshot-count column.
        const WITH: &[&str] = &[
            "volume",
            "tenant",
            "pool",
            "size",
            "phase",
            "node",
            "attached-to",
            "snapshots",
            "age",
        ];
        const WITHOUT: &[&str] = &[
            "volume",
            "tenant",
            "pool",
            "size",
            "phase",
            "node",
            "attached-to",
            "age",
        ];
        Ok(View::table(
            if has_snapshots { WITH } else { WITHOUT },
            rows,
            "no volumes",
        ))
    })
}

/// Request deletion and display any reported attachment blocking completion.
pub async fn remove_volume(ctx: &Ctx<'_>, name: &str) -> Result<()> {
    ctx.confirm("delete", "volume", name)?;
    let body = ctx.client.delete(&ctx.path("volumes", Some(name))?).await?;
    match attached_to(&body) {
        Some(vm) => output::emit(ctx.global, &body, |_| {
            Ok(View::note_owned(
                name.to_string(),
                format!("held by {vm}; delete the vm first, or wait"),
            ))
        }),
        // Display the server's remaining asynchronous cleanup status.
        None => output::emit_removal(ctx.global, &body, name),
    }
}

pub async fn volume(ctx: &Ctx<'_>, cmd: &VolumeCmd) -> Result<()> {
    if let VolumeCmd::Resize { name, size_gib } = cmd {
        return resize_volume(ctx, name, *size_gib).await;
    }
    let VolumeCmd::Create {
        name,
        size_gib,
        pool,
        base_image,
        from_snapshot,
        mode,
        access_mode,
        description,
    } = cmd
    else {
        unreachable!("dispatched generically")
    };
    let mut object = json!({
        "apiVersion": "meister.io/v1",
        "kind": "Volume",
        "metadata": { "name": name },
        "spec": {
            "sizeGib": size_gib,
            "description": description.clone().unwrap_or_default(),
        },
    });
    for (key, value) in [
        ("tenant", ctx.global.tenant.clone()),
        ("pool", pool.clone()),
        ("baseImage", base_image.clone()),
        ("fromSnapshot", from_snapshot.clone()),
        ("mode", mode.clone()),
        ("accessMode", access_mode.clone()),
    ] {
        if let Some(value) = value {
            object["spec"][key] = json!(value);
        }
    }
    let body = ctx.post("volumes", object).await?;
    output::emit_line(ctx.global, &body, name)
}

/// Request a larger disk. Guest filesystem expansion remains the tenant's responsibility.
pub async fn resize_volume(ctx: &Ctx<'_>, name: &str, size_gib: u64) -> Result<()> {
    let body = ctx
        .patch("volumes", name, json!({ "spec": { "sizeGib": size_gib } }))
        .await?;
    output::emit_line(ctx.global, &body, &format!("{size_gib}Gi"))
}

/// Read the optional attachment blocker from the DELETE Status envelope.
pub(super) fn attached_to(body: &[u8]) -> Option<String> {
    serde_json::from_slice::<serde_json::Value>(body)
        .ok()?
        .get("details")?
        .get("attachedTo")?
        .as_str()
        .map(str::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Keep headers aligned whether or not snapshot discovery is available.
    #[test]
    fn a_volume_row_is_the_same_width_as_its_header() {
        let volume = || -> Volume {
            serde_json::from_str(
                r#"{"metadata":{"name":"data-1"},"spec":{"tenant":"acme","sizeGib":10},
                    "status":{}}"#,
            )
            .unwrap()
        };
        let now = Utc::now();

        let counted = volume_row(volume(), Some(2), now);
        assert_eq!(counted.len(), 9);
        assert_eq!(counted[7], "2");

        let uncounted = volume_row(volume(), None, now);
        assert_eq!(uncounted.len(), 8);
        // The last column is still the age and not a count that slid over.
        assert_eq!(uncounted[7], counted[8]);
    }
}
