// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! The volume half of the pass: hand a volume or a snapshot to the cluster
//! that should carry it, and move a VM's volumes along when it is evacuated.
//! Moved out of `reconcile.rs` unchanged.

use super::*;

/// Every volume this cloud holds, once per pass: hand it down to the cluster
/// its pool names, or ask for it back.
///
/// No scheduling, and that is the design rather than a shortcut: a cloud pool
/// NAMES its cluster, so which cluster a volume goes to is written down by an
/// operator who knows the wiring. The cloud has no way to compare two pools
/// on two clusters — how full a thin pool is and which nodes mount an export
/// are facts down there — and an answer invented up here would go stale
/// between the decision and the dispatch.
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

    // Dedup by evidence, exactly as the VM half does: a volume the cluster
    // already names in its status is a volume the cluster already has, and
    // re-sending the create every five seconds would be a write per pass down
    // there for nothing. `observed_at` is set by the mirror and by nothing
    // else, so it is precisely "the cluster has spoken about this".
    if volume.status.observed_at.is_some() {
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

/// Every snapshot this cloud holds, once per pass. Same road as the volumes,
/// one object over — and one hop longer to the cluster, because a snapshot
/// names a volume and the VOLUME names the pool that names the cluster.
///
/// Nothing is scheduled here either, and for a shorter reason than the
/// volume's: a copy is taken where the bytes are.
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

/// Say what a snapshot is waiting for, and only when it changed.
///
/// It used to keep whatever kind the object had and replace the sentence
/// beside it. That worked while the two were separate fields and cannot
/// survive the derivation — a word carries its own sentence now — so the
/// guard below is what takes over the job the kept kind was doing: a copy
/// some cluster has already described is not waiting for anything. Its bytes
/// exist down there, and this is only this tier having lost sight of the road
/// to them. Writing `Pending` over it would be this tier un-observing an
/// observation, which is D-B2's shape.
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

/// Say what a volume is waiting for, and only when it changed.
pub(super) async fn note_volume_pending(
    store: &EtcdStore,
    volume: &controller_api::Volume,
    reason: String,
) -> anyhow::Result<()> {
    if volume.status.phase().message() == Some(reason.as_str()) {
        return Ok(());
    }
    store
        .mutate::<controller_api::Volume, _>(&volume.metadata.name, |v| {
            let kind = v.status.phase().kind();
            #[allow(deprecated)]
            v.status.assign(controller_api::VolumePhase::said(
                kind,
                Some(reason.clone()),
                chrono::Utc::now(),
            ));
        })
        .await?;
    Ok(())
}

/// Move this VM's referenced disks to the cluster it is now bound to, and say
/// whether they are all there yet.
///
/// The step between the binding and the create, and it exists because a
/// `Volume` at this tier is a REFERENCE to an object on one cluster: the
/// bytes are on an export or a target that both clusters reach, but the
/// record naming them belongs to exactly one of them at a time. Handing the
/// VM down before the record has moved would be a create the target cluster
/// cannot resolve.
///
/// Two commands and their order is the rule: **release at the old cluster
/// first**, create at the new one after. The release destroys nothing (see
/// `ReleaseVolume`), so the window between them is a window in which the
/// bytes have no record anywhere — which is recoverable, because the handle
/// is derived from the uid and the create finds them again. The other order
/// is not recoverable: two clusters with a record of one export is two
/// consumers of a disk whose `AccessMode` says one.
///
/// The release is synchronous and its ack IS the proof: nothing below the
/// cluster was asked anything, so there is no absence to wait for.
///
/// `Ok(false)` means "not yet, come back next pass" and never an error — a
/// cluster that is not dialled in right now is a fact about the session.
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
                #[allow(deprecated)]
                v.status.assign(controller_api::VolumePhase::new(
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
