// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Volume snapshots: dispatch, the standstill a non-atomic backend needs,
//! requeue and teardown. Moved out of `reconcile.rs` unchanged.

use super::*;

/// Every snapshot this cluster holds, once per pass.
///
/// Its own pass beside `place_volumes` and not folded into it: a snapshot is
/// dispatched to the node the VOLUME is on, so it makes no placement decision
/// of its own, and a loop that had to do both would be a loop with two
/// meanings for "unplaced".
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
    match snapshot.status.phase {
        VolumeSnapshotPhase::Pending => dispatch_snapshot(p, &snapshot).await,
        VolumeSnapshotPhase::Failed => requeue_snapshot(p, &snapshot).await,
        VolumeSnapshotPhase::Creating | VolumeSnapshotPhase::Ready => Ok(()),
    }
}

/// Send the snapshot to the node that has the bytes, pausing the guest across
/// the call if the backend needs it.
///
/// # The quiesce sequence, in miniature
///
/// A backend that COPIES cannot promise that its copy is of one instant while
/// the guest is writing, so the vCPUs stop for the length of the call:
///
/// ```text
///   PauseInstance  -> the node the VM runs on
///   SnapshotVolume -> the node the VOLUME is on   (a different one, under a
///   ResumeInstance -> the node the VM runs on      shared storage)
/// ```
///
/// Three things about it are load-bearing:
///
///   * **The resume happens whatever the snapshot did.** A failure in the
///     middle leaves a paused guest, and a paused guest that nobody resumes is
///     an outage caused by a backup. So the resume is unconditional and its
///     own failure is logged beside the first one rather than replacing it.
///   * **Two nodes, and the tier that can see both is this one.** The node
///     holding the volume cannot pause a VM on another machine, and the node
///     running the VM does not have the bytes. That is why the pause is
///     sequenced here and not inside `SnapshotVolume`.
///   * **`Atomic` pauses nothing.** A thin LV's snapshot is one instant by
///     construction, and so is a reflink clone; stopping a guest for either
///     would be a cost with nothing bought. WHICH backends are atomic is the
///     NODE's answer and not a list here — `filesystem` copies on ext4 and
///     reflinks on XFS, and it learns which by probing its own pool. See
///     `snapshot_consistency`.
///
/// This is the same shape the floppy brief needs for its barrier across N
/// replicas — pause the writers, do the thing, resume them whatever happened
/// — one node smaller. What it does not have is the part that makes a barrier
/// a barrier: an ordering across several nodes that all have to be quiet at
/// once. Here there is exactly one writer, so "pause it" IS the barrier.
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
    let (Some(node), VolumePhase::Ready) = (volume.status.node.clone(), volume.status.phase) else {
        debug!(snapshot = %name, volume = %volume.metadata.name,
               "the volume is not ready yet; the snapshot waits");
        return Ok(());
    };

    // The claim before the command, like every other dispatch in this file:
    // a CAS that loses means another replica is already sending. The node
    // goes on the object HERE, so that a later drop finds the machine even if
    // the volume has since gone.
    let mut sent = snapshot.clone();
    sent.status.phase = VolumeSnapshotPhase::Creating;
    sent.status.node = Some(node.clone());
    sent.status.message = None;
    match p.store.update(&sent).await {
        Ok(_) => {}
        Err(StoreError::Conflict(_)) => {
            debug!(snapshot = %name, "lost the snapshot race");
            return Ok(());
        }
        Err(e) => return Err(e.into()),
    }

    // Who has to stand still, if anybody. `None` where the backend is atomic,
    // where nobody is holding the volume, or where the holder is not running:
    // a guest that is not executing is already as quiesced as a pause makes
    // it.
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
        return note_snapshot_failed(p, &sent, format!("{e:#}")).await;
    }
    info!(snapshot = %name, node = %node, "snapshot dispatched");
    Ok(())
}

/// Which way a guest is being told to go, for the one closure the sequence
/// below takes.
///
/// One closure and an enum rather than two closures, because what has to be
/// exercised is the ORDER of the two calls — and a test that could pass one
/// of them and not the other could not see an ordering at all.
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

/// Run `work` with the guest stopped, and start it again whatever happened.
///
/// Three rules, and each of them is a thing that goes wrong otherwise:
///
///   * **A pause that failed cancels the work.** The pause is what makes the
///     copy worth having; taking it anyway would produce a copy nobody was
///     told is torn, which is worse than no copy at all.
///   * **The resume is unconditional.** It runs whether the work succeeded,
///     failed, or was never reached — a guest left paused by a backup is an
///     outage this stack caused, and no error is worth one.
///   * **A resume that failed does not replace the work's answer.** It is
///     logged at ERROR beside it: the operator has two problems, and hiding
///     the first behind the second helps with neither.
///
/// `guest` is `None` where nothing has to stand still — an atomic backend, a
/// volume nobody holds, a guest that is not running — and then this is `work`
/// and nothing else.
///
/// This is the shape the floppy brief needs for its barrier across N
/// replicas, one node smaller. What it does not have is what makes a barrier
/// one: an ordering over several writers that all have to be quiet at the
/// same instant. Here there is exactly one writer, so "pause it" IS the
/// barrier.
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

/// The VM that has to stand still for this copy, and the node it runs on.
///
/// `None` — nothing is paused — in three cases, and each is a different
/// sentence: the backend takes its copy at one instant anyway (`Atomic`),
/// nobody is holding the volume, or the holder is not running. The third
/// matters more than it looks: a stopped guest is not writing, and pausing
/// something that is not executing would buy nothing and could fail.
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
    // The catalogue carries the consistency now, so it is asked instead of
    // the driver's NAME being compared with a constant. The name was never
    // the question: `filesystem` copies on ext4 and REFLINKS on XFS and
    // btrfs, and it finds that out by probing its own pool rather than by
    // being told — so a node is the only thing that knows, and a table here
    // would be a second answer that drifts.
    //
    // `None` means nothing was learned — a node from before the claim, a
    // pool no node has reported on, a backend that says only that it can.
    // Nothing learned is NOT "atomic": it falls through to the pause, which
    // is the direction where being wrong costs milliseconds instead of a
    // torn copy.
    if snapshot_consistency(p, volume, &pool.spec.driver).await?
        == Some(common::capability::SnapshotConsistency::Atomic)
    {
        return Ok(None);
    }
    holder_of(p, volume).await
}

/// What the node holding these bytes says its backend needs.
///
/// The node that HOLDS the volume and not any node serving the pool: under a
/// `shared` pool two machines can serve the same bytes with different
/// filesystems underneath, and the one that will take the copy is the one
/// whose answer counts.
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

/// The consistency this catalogue claims for one backend, if it claims one.
///
/// The flat `volume/<backend>/snapshot:<consistency>` entries, read back. Its
/// own function so that the rule can be stated without a store: `None` is
/// "this catalogue said nothing about it", which includes a node that claims
/// only the bare `volume/<backend>/snapshot` — every node from before the
/// claim existed.
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
    match (vm.status.phase, vm.spec.node_name.clone()) {
        (VmPhase::Running, Some(node)) => Ok(Some((vm.metadata.uid, node))),
        _ => Ok(None),
    }
}

/// Say a snapshot failed, and start the requeue clock. Only on a change, like
/// every other status write in this file.
pub(super) async fn note_snapshot_failed(
    p: &Pass<'_>,
    snapshot: &VolumeSnapshot,
    message: String,
) -> anyhow::Result<()> {
    warn!(snapshot = %snapshot.metadata.name, error = %message, "snapshot failed");
    p.store
        .mutate::<VolumeSnapshot, _>(&snapshot.metadata.name, |s| {
            s.status.phase = VolumeSnapshotPhase::Failed;
            s.status.message = Some(message.clone());
        })
        .await?;
    Ok(())
}

/// A Failed snapshot, kicked on the same curve everything else here rides.
///
/// The kick is another dispatch, which is idempotent at the node — so the
/// repair path is the ordinary path and there is no second one to get wrong.
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
            s.status.phase = VolumeSnapshotPhase::Pending;
            s.status.requeue_attempts = s.status.requeue_attempts.saturating_add(1);
            s.status.last_requeue = Some(now);
        })
        .await?;
    info!(snapshot = %name, attempts = kicked.status.requeue_attempts, "snapshot requeued");
    Ok(())
}

/// Tell the node to destroy the copy, and finish the delete once it says it
/// is gone.
///
/// The same order and the same argument as `deprovision_volume`: the object
/// goes only AFTER the node has said `Gone`, because absence from a report is
/// "this node does not know" and a restart before the first report would
/// otherwise take an object whose bytes are on a disk.
///
/// A snapshot with no node never had one told about it, so there is nothing
/// to destroy and the finalizer comes off at once.
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

/// The snapshots that still stand on a volume's bytes, by name.
///
/// What turns a `volume rm` into `Releasing` rather than a deprovision — the
/// same `HeldBy` shape a VM produces, and the reason is the same one word
/// long: a snapshot standing on a file that has been deleted is a snapshot of
/// nothing.
///
/// (`lvm-thin` would hold its origin LV itself, because a thin snapshot
/// shares the origin's blocks. This rule is what makes `filesystem` behave
/// the way `lvm-thin` behaves anyway, so an operator sees one storage system
/// rather than one per backend.)
///
/// A snapshot that is itself being deleted does not hold: it is on its way
/// out, and holding the volume for it would make two deletes wait for each
/// other.
pub(super) fn snapshots_holding(snapshots: &[VolumeSnapshot], volume: &str) -> Vec<String> {
    snapshots
        .iter()
        .filter(|s| s.spec.volume == volume && s.metadata.deletion_timestamp.is_none())
        .map(|s| s.metadata.name.clone())
        .collect()
}
