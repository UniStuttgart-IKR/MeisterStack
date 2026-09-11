// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! `Volume`: the object, its row, the listing that counts snapshots per
//! disk, and its verbs.

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
    /// Every node that has the disk OPEN. One in the ordinary case, where it
    /// says nothing `node` does not already say; two while a live migration
    /// is under way, and then it is the only column that says so.
    #[serde(default)]
    open_on: Vec<String>,
    /// What the NODE measured, which is not what the spec asked for while a
    /// resize is in flight. Zero = nobody has measured it, and then the
    /// column shows the spec's number alone.
    #[serde(default)]
    size_gib: u64,
}

/// One volume's row, with the snapshots standing on it counted.
///
/// `size` is the SPEC's, and it grows a second half while a resize is in
/// flight: `1Gi->2Gi` says the intent and the measurement disagree, which is
/// exactly the state an operator needs to see and the reason `status.sizeGib`
/// exists at all. Once the node has reported the new size the arrow goes
/// away by itself.
/// `snapshots` is `None` where the endpoint serves no snapshots at all — the
/// column is then not in the table either, which is a different statement
/// from a count of zero.
pub(super) fn volume_row(v: Volume, snapshots: Option<usize>, now: DateTime<Utc>) -> Vec<String> {
    let size = match v.status.size_gib {
        0 => format!("{}Gi", v.spec.size_gib),
        have if have == v.spec.size_gib => format!("{have}Gi"),
        have => format!("{have}Gi->{}Gi", v.spec.size_gib),
    };
    // `node` is where the bytes live and answers for the volume nearly all of
    // the time. The exception is a live migration, and then one machine is
    // the wrong answer: both ends have the disk open. So the column says the
    // whole set when there is more than one machine in it, and stays the home
    // when there is not — a table that grew a second name on every row would
    // charge every volume for a case that lasts a few hundred milliseconds
    // once in a machine's life.
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
    // A count and not a list: what an operator needs from this column is
    // "will a delete of this disk go through", and one number answers it
    // where a list of names would wrap the table.
    if let Some(n) = snapshots {
        row.push(match n {
            0 => "-".to_string(),
            n => n.to_string(),
        });
    }
    row.push(age(v.metadata.creation_timestamp, now));
    row
}

/// `volume ls`, which is the one listing in this CLI that asks twice.
///
/// The second question is "what stands on this disk", and it cannot be
/// answered from the volume: a snapshot is its own object and names the
/// volume, not the other way round — which is what lets it outlive one. So
/// the snapshots are listed too and counted per volume.
///
/// One extra request per `volume ls` and none per volume: the alternative,
/// a `status.snapshots` counter on the volume, would be a number two
/// controllers write and one of them can leave stale.
pub async fn list_volumes(ctx: &Ctx<'_>, selector: Option<&str>) -> Result<()> {
    let body = ctx
        .client
        .get(&format!(
            "{}{}",
            ctx.path("volumes", None)?,
            crate::generic::query(ctx.global, selector)
        ))
        .await?;
    // Does this endpoint serve snapshots at all? Ask the discovery, not the
    // server: a cloud does not serve them yet, and `ctx.path` answers a
    // resource it has never heard of with a sentence — which used to end
    // `volume ls` entirely. A tenant could not list their own disks against a
    // cloud, because of a courtesy column. Not served means the column is not
    // in the table; served and unanswerable means the column is empty.
    let counts: Option<std::collections::HashMap<String, usize>> =
        match ctx.path("volumesnapshots", None) {
            Err(e) => {
                tracing::debug!(error = %format!("{e:#}"), "this endpoint serves no snapshots");
                None
            }
            // A failure here is not a failure of `volume ls`: an operator asking
            // what disks exist gets them, with the column that could not be
            // filled saying nothing. The listing is the answer; the count is a
            // courtesy.
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
        // `node` and `attached-to` are where the bytes are and who has them
        // open — the two columns the object exists for. `snapshots` is what
        // stands on it, the other reason a delete does not finish, and it is
        // in the table only where the endpoint has snapshots to count.
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

/// `volume rm`, which is the one delete in this CLI that routinely does not
/// finish.
///
/// A volume a VM is holding goes to `Releasing` and STAYS there — that is the
/// finalizer doing its job, and it is the one rule in this stack with
/// somebody's data on the other side of it. Printing the name and nothing
/// else, the way every other delete does, would leave an operator watching a
/// volume that never goes and no idea why. So the answer is read: the server
/// has already told us who holds it.
///
/// The note goes to stderr, so `meister volume rm x --yes | ...` still pipes
/// the name and nothing else.
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
        // Nobody is holding it, and the delete STILL did not finish: the
        // bytes are on a node and it is the node saying they are gone that
        // removes the object. The server's own sentence says so, and until
        // D4 this printed the name and let it read as "deleted".
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

/// Grow a disk: one merge patch of `spec.sizeGib`.
///
/// The server refuses a smaller number — the bytes past the new end are not
/// its to decide about — and answers a bigger one by growing the backend and
/// then telling the guest, in that order. The filesystem INSIDE the guest is
/// the tenant's to grow afterwards, exactly as it is with EBS.
pub async fn resize_volume(ctx: &Ctx<'_>, name: &str, size_gib: u64) -> Result<()> {
    let body = ctx
        .patch("volumes", name, json!({ "spec": { "sizeGib": size_gib } }))
        .await?;
    output::emit_line(ctx.global, &body, &format!("{size_gib}Gi"))
}

/// Who is still holding this disk, out of the `Status` a DELETE answers with.
///
/// `details.attachedTo`, which is where a resource's own answer goes now that
/// every DELETE in this API wears the same envelope. Absent, null, or a body
/// of another shape all mean the same thing here — nobody said, so nothing is
/// claimed.
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

    /// A courtesy column must not be able to end a listing. `volume ls` asks
    /// the endpoint for snapshots to count them per disk; a cloud serves no
    /// `volumesnapshots`, and asking for a path the discovery has never heard
    /// of is an error — which used to propagate and leave a tenant unable to
    /// list their own volumes at all.
    ///
    /// The row is the shorter one then, and it has to be short in the same
    /// place the header is: an off-by-one here is a table whose `age` column
    /// holds a snapshot count.
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
