// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Dispatch volumes and snapshots to clusters and move shared-volume records.

use super::*;

/// Dispatch to the volume's recorded cluster, falling back to its pool home.
/// The cluster chooses the provisioning node; the cloud does not schedule storage bytes.
pub(super) async fn dispatch_volumes(
    store: &EtcdStore,
    registry: &SessionRegistry,
    sessions: &HashSet<String>,
) -> anyhow::Result<()> {
    let volumes = store.list::<controller_api::Volume>().await?;
    if volumes.is_empty() {
        return Ok(());
    }
    // The pool's HOME, which is where a volume goes when nothing has said
    // otherwise. A volume that has been dispatched carries the answer itself
    // (`status.cluster`), and that is the one that moves when a VM does.
    let pools: std::collections::HashMap<String, String> = store
        .list::<controller_api::StoragePool>()
        .await?
        .into_iter()
        .filter_map(|p| Some((p.metadata.name.clone(), p.spec.home()?.to_string())))
        .collect();
    for volume in volumes {
        let name = volume.metadata.name.clone();
        if let Err(e) = dispatch_volume(store, registry, sessions, &pools, volume).await {
            warn!(volume = %name, error = format!("{e:#}"), "volume dispatch failed");
        }
    }
    Ok(())
}

/// Dispatch an unobserved volume or a spec generation not yet sent to its cluster.
pub(super) fn needs_dispatch(volume: &controller_api::Volume) -> bool {
    volume.status.observed_at.is_none()
        || volume.metadata.generation > volume.status.observed_generation
}

pub(super) async fn dispatch_volume(
    store: &EtcdStore,
    registry: &SessionRegistry,
    sessions: &HashSet<String>,
    pools: &std::collections::HashMap<String, String>,
    volume: controller_api::Volume,
) -> anyhow::Result<()> {
    let name = volume.metadata.name.clone();
    let dispatched_to = volume.status.cluster.clone();
    let Some(cluster) = dispatched_to
        .as_ref()
        .or_else(|| pools.get(&volume.spec.pool))
        .filter(|c| !c.is_empty())
    else {
        // The pool is gone or names no cluster. Refused at the create edge,
        // so reaching here means it was edited afterwards; the sentence says
        // so and the volume waits rather than being sent nowhere.
        return note_volume_pending(
            store,
            &volume,
            format!(
                "storage pool {} names no cluster here; the volume cannot be dispatched",
                volume.spec.pool
            ),
        )
        .await;
    };
    // Only the replica the cluster talks to may send it anything — the same
    // ownership token the VM half uses, and for the same reason: it is a fact
    // this replica can observe by itself and it is already exclusive.
    if !sessions.contains(cluster.as_str()) {
        return Ok(());
    }

    if volume.metadata.deletion_timestamp.is_some() {
        // The object goes when the cluster stops naming it — which the mirror
        // decides, not this. Here we only keep asking, because a Destroy that
        // was lost has to be sent again.
        registry
            .send_command(
                cluster,
                "",
                cloud_command::Op::DestroyVolume(proto::DestroyVolume {
                    name: name.clone(),
                    uid: volume.metadata.uid.clone(),
                }),
            )
            .await?;
        debug!(volume = %name, cluster = %cluster, "destroy dispatched");
        return Ok(());
    }

    if !needs_dispatch(&volume) {
        return Ok(());
    }
    let spec_json = serde_json::to_string(&volume.spec)?;
    let dispatched = volume.metadata.generation;
    registry
        .send_command(
            cluster,
            "",
            cloud_command::Op::CreateVolume(proto::CreateVolume {
                name: name.clone(),
                spec_json,
                uid: volume.metadata.uid.clone(),
                tenant: volume.spec.tenant.clone(),
            }),
        )
        .await?;
    // The generation this command carried down — the one thing we KNOW,
    // because we sent it. Same statement the VM half makes on the same road.
    store
        .mutate::<controller_api::Volume, _>(&name, |v| {
            v.status.observed_generation = v.status.observed_generation.max(dispatched);
            // Which cluster's record holds this volume — the same statement
            // `Vm.status.clusterName` makes at dispatch, and the only one
            // this tier knows rather than guesses, because it is what it
            // sent. A pool naming one cluster writes the value it already
            // had; a pool naming two writes the one that was chosen.
            v.status.cluster = Some(cluster.clone());
        })
        .await?;
    info!(volume = %name, cluster = %cluster, "create dispatched");
    Ok(())
}

/// Route snapshots through their source volume's pool.
/// This path currently reads `pool.spec.cluster`, not `volume.status.cluster`
/// or the pool's multi-cluster home, so it cannot follow a relocated volume.
pub(super) async fn dispatch_snapshots(
    store: &EtcdStore,
    registry: &SessionRegistry,
    sessions: &HashSet<String>,
) -> anyhow::Result<()> {
    let snapshots = store.list::<controller_api::VolumeSnapshot>().await?;
    if snapshots.is_empty() {
        return Ok(());
    }
    let pools: std::collections::HashMap<String, String> = store
        .list::<controller_api::StoragePool>()
        .await?
        .into_iter()
        .map(|p| (p.metadata.name, p.spec.cluster))
        .collect();
    let volumes: std::collections::HashMap<String, String> = store
        .list::<controller_api::Volume>()
        .await?
        .into_iter()
        .map(|v| (v.metadata.name, v.spec.pool))
        .collect();
    for snapshot in snapshots {
        let name = snapshot.metadata.name.clone();
        if let Err(e) =
            dispatch_snapshot(store, registry, sessions, &pools, &volumes, snapshot).await
        {
            warn!(snapshot = %name, error = format!("{e:#}"), "snapshot dispatch failed");
        }
    }
    Ok(())
}

pub(super) async fn dispatch_snapshot(
    store: &EtcdStore,
    registry: &SessionRegistry,
    sessions: &HashSet<String>,
    pools: &std::collections::HashMap<String, String>,
    volumes: &std::collections::HashMap<String, String>,
    snapshot: controller_api::VolumeSnapshot,
) -> anyhow::Result<()> {
    let name = snapshot.metadata.name.clone();
    let cluster = volumes
        .get(&snapshot.spec.volume)
        .and_then(|pool| pools.get(pool))
        .filter(|c| !c.is_empty());
    let Some(cluster) = cluster else {
        // The volume is gone, or its pool names no cluster. A snapshot whose
        // volume has been deleted still has bytes down there and still gets
        // its Destroy — but there is nowhere to send it, so it waits and says
        // so rather than being sent nowhere.
        return note_snapshot_pending(
            store,
            &snapshot,
            format!(
                "volume {} names no cluster here; the snapshot cannot be dispatched",
                snapshot.spec.volume
            ),
        )
        .await;
    };
    if !sessions.contains(cluster.as_str()) {
        return Ok(());
    }

    if snapshot.metadata.deletion_timestamp.is_some() {
        registry
            .send_command(
                cluster,
                "",
                cloud_command::Op::DestroySnapshot(proto::DestroySnapshot {
                    name: name.clone(),
                    uid: snapshot.metadata.uid.clone(),
                }),
            )
            .await?;
        debug!(snapshot = %name, cluster = %cluster, "destroy dispatched");
        return Ok(());
    }

    // Dedup by evidence, exactly as the volume half does.
    if snapshot.status.observed_at.is_some() {
        return Ok(());
    }
    let spec_json = serde_json::to_string(&snapshot.spec)?;
    registry
        .send_command(
            cluster,
            "",
            cloud_command::Op::CreateSnapshot(proto::CreateSnapshot {
                name: name.clone(),
                spec_json,
                uid: snapshot.metadata.uid.clone(),
                tenant: snapshot.spec.tenant.clone(),
            }),
        )
        .await?;
    info!(snapshot = %name, cluster = %cluster, "create dispatched");
    Ok(())
}

/// Record a changed routing wait only if no node observation already exists.
pub(super) async fn note_snapshot_pending(
    store: &EtcdStore,
    snapshot: &controller_api::VolumeSnapshot,
    reason: String,
) -> anyhow::Result<()> {
    if snapshot
        .status
        .reported
        .as_ref()
        .is_some_and(|r| !r.node.is_empty())
    {
        return Ok(());
    }
    if snapshot.status.phase().message() == Some(reason.as_str()) {
        return Ok(());
    }
    store
        .mutate::<controller_api::VolumeSnapshot, _>(&snapshot.metadata.name, |s| {
            s.status.reported = Some(controller_api::VolumeSnapshotReported::here(
                controller_api::VolumeSnapshotPhaseKind::Pending,
                controller_api::VolumeSnapshotReason::SourceGone,
                Some(reason.clone()),
                chrono::Utc::now(),
            ));
        })
        .await?;
    Ok(())
}

/// Record a changed routing wait without replacing a node's volume observation.
pub(super) async fn note_volume_pending(
    store: &EtcdStore,
    volume: &controller_api::Volume,
    reason: String,
) -> anyhow::Result<()> {
    if volume
        .status
        .reported
        .as_ref()
        .is_some_and(|r| !r.node.is_empty())
    {
        return Ok(());
    }
    if volume.status.phase().message() == Some(reason.as_str()) {
        return Ok(());
    }
    store
        .mutate::<controller_api::Volume, _>(&volume.metadata.name, |v| {
            v.status.reported = Some(controller_api::VolumeReported::here(
                controller_api::VolumePhaseKind::Pending,
                controller_api::VolumeReason::Unplaced,
                Some(reason.clone()),
                chrono::Utc::now(),
            ));
        })
        .await?;
    Ok(())
}

/// Move referenced volume records before handing the VM to its new cluster.
/// Release the old record first, preserving shared backend bytes, then reset
/// dispatch evidence so the destination reconstructs its record from the UID.
/// This record handoff does not itself copy data or provide distributed fencing.
pub(super) async fn move_volumes(
    store: &EtcdStore,
    registry: &SessionRegistry,
    vm: &Vm,
    cluster: &str,
) -> anyhow::Result<bool> {
    let mut all_there = true;
    for name in vm.spec.referenced_volumes() {
        let volume: controller_api::Volume = match store.get(&name).await {
            Ok(v) => v,
            // Not this pass's problem: the placement already refused to
            // consider a VM whose volume is missing, and it says so there.
            Err(StoreError::NotFound(_)) => continue,
            Err(e) => return Err(e.into()),
        };
        let pool: controller_api::StoragePool = store.get(&volume.spec.pool).await?;
        let at = volume
            .status
            .cluster
            .clone()
            .or_else(|| pool.spec.home().map(str::to_string));
        match at.as_deref() {
            Some(here) if here == cluster => continue,
            // A volume that has never been dispatched anywhere has nothing to
            // release; pointing it at the new cluster is enough, and the
            // dispatcher makes it there.
            None => {}
            Some(old) => {
                registry
                    .send_command(
                        old,
                        "",
                        cloud_command::Op::ReleaseVolume(proto::ReleaseVolume {
                            name: name.clone(),
                            uid: volume.metadata.uid.clone(),
                        }),
                    )
                    .await?;
                info!(volume = %name, from = old, to = cluster, "record released; the bytes stay");
            }
        }
        // `observedAt` and `observedGeneration` are what the dispatcher reads
        // to decide the cluster already has this volume, and the new one does
        // not. They are cleared here and nowhere else — this is the one
        // moment a volume stops having been spoken about.
        store
            .mutate::<controller_api::Volume, _>(&name, |v| {
                v.status.cluster = Some(cluster.to_string());
                v.status.observed_at = None;
                v.status.observed_generation = 0;
                v.status.node = None;
                v.status.reported = Some(controller_api::VolumeReported::here(
                    controller_api::VolumePhaseKind::Pending,
                    controller_api::VolumeReason::Following,
                    Some(format!("moving to {cluster} with its vm")),
                    chrono::Utc::now(),
                ));
            })
            .await?;
        all_there = false;
    }
    Ok(all_there)
}
