// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Snapshot dispatch, guest pause/resume sequencing, retries, and deletion.

use super::*;

/// Reconcile snapshots separately from volume placement.
/// Each snapshot targets the node recorded on its source volume.
pub(super) async fn take_snapshots(p: &Pass<'_>) -> anyhow::Result<()> {
    let snapshots = p.store.list::<VolumeSnapshot>().await?;
    if snapshots.is_empty() {
        return Ok(());
    }
    telemetry::metrics::objects().set_count(VolumeSnapshot::KIND, snapshots.len() as i64);
    for snapshot in snapshots {
        // Whose snapshot this is, before anything is decided about it — the
        // volume rule one object further; see `may_reconcile_snapshot`.
        if !may_reconcile_snapshot(&snapshot, p.sessions) {
            continue;
        }
        let name = snapshot.metadata.name.clone();
        if let Err(e) = reconcile_snapshot(p, snapshot).await {
            warn!(snapshot = %name, error = format!("{e:#}"), "snapshot reconcile failed");
        }
    }
    Ok(())
}

/// The node's word for "this copy does not exist any more". The mirror of
/// [`VOLUME_GONE`], and the same rule: not a phase, read in exactly two
/// places, and the only thing that lets a `VolumeSnapshot` object go.
pub(crate) const SNAPSHOT_GONE: &str = "Gone";

/// One snapshot: drop -> dispatch -> requeue.
///
/// Drop first, for the reason release comes first on a volume: a snapshot on
/// its way out is not one to take.
pub(super) async fn reconcile_snapshot(
    p: &Pass<'_>,
    snapshot: VolumeSnapshot,
) -> anyhow::Result<()> {
    if snapshot.metadata.deletion_timestamp.is_some() {
        return drop_snapshot(p, &snapshot).await;
    }
    match snapshot.status.phase().kind() {
        VolumeSnapshotPhaseKind::Pending => dispatch_snapshot(p, &snapshot).await,
        VolumeSnapshotPhaseKind::Failed => requeue_snapshot(p, &snapshot).await,
        VolumeSnapshotPhaseKind::Creating | VolumeSnapshotPhaseKind::Ready => Ok(()),
    }
}

/// Claim the snapshot by CAS, then dispatch to the volume node.
/// For non-atomic backends, request a pause on the holder's node before dispatch
/// and a resume after the command reply. That reply acknowledges dispatch, not
/// completion of the asynchronous backend copy; see `docs/STORAGE.md`.
pub(super) async fn dispatch_snapshot(
    p: &Pass<'_>,
    snapshot: &VolumeSnapshot,
) -> anyhow::Result<()> {
    let name = snapshot.metadata.name.clone();
    let volume: Volume = match p.store.get(&snapshot.spec.volume).await {
        Ok(v) => v,
        // The volume was deleted between the request and this pass. Failed
        // with the sentence rather than stuck Pending: no later pass can make
        // a copy of something that is not there.
        Err(StoreError::NotFound(_)) => {
            return note_snapshot_failed(
                p,
                snapshot,
                controller_api::VolumeSnapshotReason::SourceGone,
                format!(
                    "volume {} does not exist here any more",
                    snapshot.spec.volume
                ),
            )
            .await;
        }
        Err(e) => return Err(e.into()),
    };
    // Not ready yet is a WAIT and not a refusal, exactly as it is for a VM
    // that names a disk still being made.
    let (Some(node), VolumePhaseKind::Ready) =
        (volume.status.node.clone(), volume.status.phase().kind())
    else {
        debug!(snapshot = %name, volume = %volume.metadata.name,
               "the volume is not ready yet; the snapshot waits");
        return Ok(());
    };

    // The claim before the command, like every other dispatch in this file:
    // a CAS that loses means another replica is already sending. The node
    // goes on the object HERE, so that a later drop finds the machine even if
    // the volume has since gone.
    let mut sent = snapshot.clone();
    sent.status.node = Some(node.clone());
    // The FACT: this tier told a machine. It carries no node in the word
    // itself — `here` rather than `by` — because nobody has looked at the
    // copy yet, and that is what keeps the anticipation from ever being
    // `Ready` (see `VolumeSnapshotReported`).
    sent.status.reported = Some(controller_api::VolumeSnapshotReported::here(
        VolumeSnapshotPhaseKind::Creating,
        controller_api::VolumeSnapshotReason::Dispatched,
        Some(format!("{node} was told")),
        Utc::now(),
    ));
    match p.store.update(&sent).await {
        Ok(_) => {}
        Err(StoreError::Conflict(_)) => {
            debug!(snapshot = %name, "lost the snapshot race");
            return Ok(());
        }
        Err(e) => return Err(e.into()),
    }

    // Pause only the holder returned by snapshot_needs_quiesce. A missing
    // holder includes non-Running phases; it does not prove there are no writers.
    let quiesce = snapshot_needs_quiesce(p, &volume).await?;
    let guest = quiesce.clone();
    let outcome = quiesced(
        guest.as_ref(),
        |node, vm, halt| tell_guest(p.registry, node, vm, halt),
        async {
            p.registry
                .send_command(
                    &node,
                    "",
                    command::Op::SnapshotVolume(proto::SnapshotVolume {
                        id: volume.metadata.uid.clone(),
                        snapshot_id: snapshot.metadata.uid.clone(),
                    }),
                )
                .await
                .map(|_| ())
        },
    )
    .await;

    if let Err(e) = outcome {
        // Failed on the object so the requeue curve picks it up — the same
        // rule a provision that could not be delivered follows, and for the
        // same reason: a node that never accepted the command sends no report
        // about it, so Creating would be forever.
        return note_snapshot_failed(
            p,
            &sent,
            controller_api::VolumeSnapshotReason::Undeliverable,
            format!("{e:#}"),
        )
        .await;
    }
    info!(snapshot = %name, node = %node, "snapshot dispatched");
    Ok(())
}

/// Guest command used by the pause/resume sequence.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Halt {
    Pause,
    Resume,
}

/// Tell the node the VM runs on to stop or start it. The real `tell` for
/// `quiesced`; the tests pass one that records instead.
pub(super) async fn tell_guest(
    registry: &SessionRegistry,
    node: String,
    vm: String,
    halt: Halt,
) -> anyhow::Result<()> {
    let op = match halt {
        Halt::Pause => command::Op::Pause(proto::PauseInstance { id: vm }),
        Halt::Resume => command::Op::Resume(proto::ResumeInstance { id: vm }),
    };
    registry.send_command(&node, "", op).await.map(|_| ())
}

/// Request a pause, run `work`, then attempt a resume.
/// A pause error returns immediately. After a successful pause, resume is attempted
/// on either work result; a resume failure is logged without replacing that result.
/// Cancellation or process failure can interrupt this sequence. `guest = None`
/// runs the work directly. The caller must define when `work` is complete.
pub(super) async fn quiesced<T, Fut>(
    guest: Option<&(String, String)>,
    tell: impl Fn(String, String, Halt) -> Fut,
    work: impl std::future::Future<Output = anyhow::Result<T>>,
) -> anyhow::Result<T>
where
    Fut: std::future::Future<Output = anyhow::Result<()>>,
{
    let Some((vm, node)) = guest else {
        return work.await;
    };
    debug!(vm = %vm, node = %node, "pausing the guest across the copy");
    tell(node.clone(), vm.clone(), Halt::Pause)
        .await
        .map_err(|e| anyhow::anyhow!("pausing the vm for a consistent copy failed: {e:#}"))?;
    let outcome = work.await;
    if let Err(e) = tell(node.clone(), vm.clone(), Halt::Resume).await {
        error!(vm = %vm, node = %node, error = %format!("{e:#}"),
               "the guest was paused for a snapshot and could not be resumed");
    } else {
        debug!(vm = %vm, node = %node, "guest resumed");
    }
    outcome
}

/// Find a running holder unless the volume node advertises atomic snapshots.
/// Missing consistency information conservatively requests a pause.
pub(super) async fn snapshot_needs_quiesce(
    p: &Pass<'_>,
    volume: &Volume,
) -> anyhow::Result<Option<(String, String)>> {
    let pool: StoragePool = match p.store.get(&volume.spec.pool).await {
        Ok(pool) => pool,
        // A pool that has gone missing under a Ready volume says nothing
        // about consistency, and guessing "atomic" would be guessing in the
        // direction that loses data. Pause.
        Err(StoreError::NotFound(_)) => {
            warn!(volume = %volume.metadata.name, pool = %volume.spec.pool,
                  "the pool is gone; assuming the copy needs a standstill");
            return holder_of(p, volume).await;
        }
        Err(e) => return Err(e.into()),
    };
    // Choose whether to request a writer pause from node-reported consistency.
    // Driver names alone cannot describe per-pool behavior. Only an explicit Atomic
    // claim skips the pause; absent or legacy claims take the pause path.
    if snapshot_consistency(p, volume, &pool.spec.driver).await?
        == Some(common::capability::SnapshotConsistency::Atomic)
    {
        return Ok(None);
    }
    holder_of(p, volume).await
}

/// Read consistency from the node that will execute the snapshot.
/// Other nodes serving a shared pool may have different backend capabilities.
pub(super) async fn snapshot_consistency(
    p: &Pass<'_>,
    volume: &Volume,
    driver: &str,
) -> anyhow::Result<Option<common::capability::SnapshotConsistency>> {
    let Some(name) = volume.status.node.as_deref() else {
        // Not provisioned anywhere yet. There is nothing to snapshot either,
        // so this is a state the caller resolves; saying "learned nothing"
        // is the honest answer.
        return Ok(None);
    };
    let node: Node = match p.store.get(name).await {
        Ok(node) => node,
        Err(StoreError::NotFound(_)) => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    Ok(consistency_in(&node.status.capacity.capabilities, driver))
}

/// Parse the backend's `volume/<backend>/snapshot:<consistency>` claim.
/// A bare legacy snapshot claim supplies no consistency information.
pub(super) fn consistency_in(
    catalogue: &[String],
    driver: &str,
) -> Option<common::capability::SnapshotConsistency> {
    let prefix = format!("{}/", common::capability::VOLUME);
    catalogue
        .iter()
        .filter_map(|entry| entry.strip_prefix(&prefix))
        .filter_map(common::capability::parse_snapshot_claim)
        .find(|(backend, _)| *backend == driver)
        .map(|(_, consistency)| consistency)
}

/// The VM holding this volume and the node it runs on, if it is running.
pub(super) async fn holder_of(
    p: &Pass<'_>,
    volume: &Volume,
) -> anyhow::Result<Option<(String, String)>> {
    let Some(holder) = volume.status.attached_to.as_deref() else {
        return Ok(None);
    };
    let vm: Vm = match p.store.get(holder).await {
        Ok(vm) => vm,
        Err(StoreError::NotFound(_)) => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    // The uid, because that is what a node was handed on CreateInstance, and
    // the node from the BINDING rather than from the status, for the reason
    // the status ingest gives.
    match (vm.status.phase().kind(), vm.spec.node_name.clone()) {
        (VmPhaseKind::Running, Some(node)) => Ok(Some((vm.metadata.uid, node))),
        _ => Ok(None),
    }
}

/// Record the caller's failure reason for snapshot retry and diagnostics.
pub(super) async fn note_snapshot_failed(
    p: &Pass<'_>,
    snapshot: &VolumeSnapshot,
    reason: controller_api::VolumeSnapshotReason,
    message: String,
) -> anyhow::Result<()> {
    warn!(snapshot = %snapshot.metadata.name, error = %message, "snapshot failed");
    p.store
        .mutate::<VolumeSnapshot, _>(&snapshot.metadata.name, |s| {
            s.status.reported = Some(controller_api::VolumeSnapshotReported::here(
                VolumeSnapshotPhaseKind::Failed,
                reason,
                Some(message.clone()),
                Utc::now(),
            ));
        })
        .await?;
    Ok(())
}

/// Return a failed snapshot to Pending when its retry delay expires.
pub(super) async fn requeue_snapshot(
    p: &Pass<'_>,
    snapshot: &VolumeSnapshot,
) -> anyhow::Result<()> {
    let now = Utc::now();
    let due = match snapshot.status.last_requeue {
        None => true,
        Some(since) => match p.requeue.next_delay(snapshot.status.requeue_attempts) {
            None => return Ok(()),
            Some(delay) => now
                .signed_duration_since(since)
                .to_std()
                .is_ok_and(|elapsed| elapsed >= delay),
        },
    };
    if !due {
        return Ok(());
    }
    let name = snapshot.metadata.name.clone();
    let kicked = p
        .store
        .mutate::<VolumeSnapshot, _>(&name, |s| {
            // Back to Pending, which is what makes the next pass dispatch
            // again — `reconcile_snapshot` branches on the phase, and the
            // phase is this word.
            s.status.reported = Some(controller_api::VolumeSnapshotReported::here(
                VolumeSnapshotPhaseKind::Pending,
                controller_api::VolumeSnapshotReason::Requeued,
                Some(format!(
                    "attempt {} after a failure",
                    s.status.requeue_attempts.saturating_add(1)
                )),
                now,
            ));
            s.status.requeue_attempts = s.status.requeue_attempts.saturating_add(1);
            s.status.last_requeue = Some(now);
        })
        .await?;
    info!(snapshot = %name, attempts = kicked.status.requeue_attempts, "snapshot requeued");
    Ok(())
}

/// Request deletion and retain the object until a node reports `Gone`.
/// A snapshot with no recorded node can be deleted immediately.
pub(super) async fn drop_snapshot(p: &Pass<'_>, snapshot: &VolumeSnapshot) -> anyhow::Result<()> {
    let name = snapshot.metadata.name.clone();
    let Some(node) = snapshot.status.node.clone() else {
        p.store.delete::<VolumeSnapshot>(&name).await?;
        info!(snapshot = %name, "snapshot deleted; no node ever had it");
        return Ok(());
    };
    let reachable = {
        let nodes = p.nodes.lock().unwrap();
        nodes.iter().any(|c| c.name == node && c.connected)
    };
    if !reachable {
        debug!(snapshot = %name, node, "the node holding this snapshot is not reachable");
        return Ok(());
    }
    p.registry
        .send_command(
            &node,
            "",
            command::Op::DropSnapshot(proto::DropSnapshot {
                snapshot_id: snapshot.metadata.uid.clone(),
            }),
        )
        .await?;
    Ok(())
}

/// Names of undeleted snapshots referencing a volume.
/// These references block volume deprovisioning across backends. Snapshots already
/// marked for deletion are excluded from this guard.
pub(super) fn snapshots_holding(snapshots: &[VolumeSnapshot], volume: &str) -> Vec<String> {
    snapshots
        .iter()
        .filter(|s| s.spec.volume == volume && s.metadata.deletion_timestamp.is_none())
        .map(|s| s.metadata.name.clone())
        .collect()
}
