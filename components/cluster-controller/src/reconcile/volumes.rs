// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Volume placement, provisioning, resize, release, and derived pool locality.

use super::*;

/// The uid of every `Volume` a VM's spec names, by the name it used.
///
/// Built once per dispatch and handed to `build_spec_json`, so that the
/// function stays pure and testable while the reads stay where the store is.
pub(crate) type VolumeUids = BTreeMap<String, String>;

/// Read the uid of every volume this VM refers to.
///
/// Fails rather than skipping a name it cannot resolve: a spec that reached a
/// node still carrying a name is a spec the node cannot act on, and finding
/// that out here is better than finding it out as a refused create.
pub(crate) async fn volume_uids(store: &EtcdStore, vm: &Vm) -> anyhow::Result<VolumeUids> {
    let mut out = VolumeUids::new();
    for name in vm.spec.referenced_volumes() {
        let volume: Volume = store.get(&name).await?;
        out.insert(name, volume.metadata.uid);
    }
    Ok(out)
}

/// Derive pool locality from the nodes reporting its driver.
/// Locality is reported by drivers; it is not an operator-selected pool property.
pub(super) async fn reconcile_pools(
    store: &EtcdStore,
    localities: &NodeLocalities,
) -> anyhow::Result<()> {
    let pools = store.list::<StoragePool>().await?;
    for pool in pools {
        let name = pool.metadata.name.clone();
        let verdict = pool_locality(&pool, localities);
        if let Err(e) = write_pool_status(store, &pool, verdict).await {
            warn!(pool = %name, error = format!("{e:#}"), "storage pool status write failed");
        }
    }
    Ok(())
}

/// Agreement, missing evidence, or a disagreement among the pool's reporting nodes.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum PoolLocality<'a> {
    /// Every node that serves this pool says the same thing.
    Agreed(Locality),
    /// Nobody said anything: no node the pool names runs the driver, or every
    /// one of them predates the field. NOT a disagreement, and above all not
    /// `NodeLocal` — "unknown" may not pin a VM to a machine.
    Unheard,
    /// Two nodes said different things about one backend. It cannot be a
    /// configuration — locality is compiled into the driver — so it is two
    /// binaries of different ages on one pool, and both are named because
    /// which two is the whole of what an operator needs.
    Split {
        node: &'a str,
        says: Locality,
        other: &'a str,
        other_says: Locality,
    },
}

/// What the nodes that can reach this pool say its driver is.
///
/// Only the nodes the pool NAMES are asked (all of them when the list is
/// empty — see `StoragePoolSpec.nodes`), and only about the pool's own
/// driver. A node that runs lvm-thin has nothing to say about an NFS pool
/// even if the pool names it, and a node the pool does not name has nothing
/// to say about it at all.
pub(super) fn pool_locality<'a>(
    pool: &StoragePool,
    localities: &'a NodeLocalities,
) -> PoolLocality<'a> {
    let mut heard: Option<(&str, Locality)> = None;
    for (node, by_driver) in localities {
        if !pool.spec.reaches(node) {
            continue;
        }
        let Some(&says) = by_driver.get(&pool.spec.driver) else {
            // Either the node does not run this backend, or its agent
            // predates the field. Both are silence, and silence is not a
            // disagreement — see `NodeCapacity.volume_localities`.
            continue;
        };
        match heard {
            None => heard = Some((node.as_str(), says)),
            Some((_, first)) if first == says => {}
            Some((other, other_says)) => {
                return PoolLocality::Split {
                    node,
                    says,
                    other,
                    other_says,
                };
            }
        }
    }
    match heard {
        Some((_, l)) => PoolLocality::Agreed(l),
        None => PoolLocality::Unheard,
    }
}

/// Convert locality evidence into shared status facts.
/// On disagreement, retain the previous locality and record both conflicting reports.
pub(super) fn pool_facts(
    verdict: PoolLocality<'_>,
    previous: Option<Locality>,
) -> (Option<Locality>, Option<controller_api::PoolDisagreement>) {
    match verdict {
        PoolLocality::Agreed(l) => (Some(l), None),
        // Nobody said anything, and that is not a disagreement: a pool whose
        // nodes are all down, or all older than the field, is a pool nothing
        // is known about, and placement falls back to the soft preference it
        // always had.
        PoolLocality::Unheard => (None, None),
        // The locality is deliberately KEPT on a disagreement: what was
        // learned before the version mix is still the better guess of the
        // two, and the phase derived beside it is what says not to trust it.
        // Dropping it would turn one bad agent into "this pool's shape is
        // unknown", which is a worse statement than the one it replaces.
        PoolLocality::Split {
            node,
            says,
            other,
            other_says,
        } => (
            previous,
            Some(controller_api::PoolDisagreement {
                node: node.to_string(),
                says,
                other: other.to_string(),
                other_says,
            }),
        ),
    }
}

/// Write the verdict, and only when it changed.
///
/// The same rule `note_pending` follows: a level-triggered pass reaches this
/// same conclusion every five seconds, and rewriting it would wake every
/// watch on the pool for nothing.
pub(super) async fn write_pool_status(
    store: &EtcdStore,
    pool: &StoragePool,
    verdict: PoolLocality<'_>,
) -> anyhow::Result<()> {
    let (locality, disagreement) = pool_facts(verdict, pool.status.locality);
    if pool.status.locality == locality && pool.status.disagreement == disagreement {
        return Ok(());
    }
    match &disagreement {
        Some(split) => warn!(pool = %pool.metadata.name, node = %split.node,
                             says = split.says.as_str(), other = %split.other,
                             other_says = split.other_says.as_str(),
                             "storage pool is inconsistent"),
        None => info!(pool = %pool.metadata.name,
                      locality = locality.map(|l| l.as_str()).unwrap_or("unknown"),
                      "storage pool locality"),
    }
    store
        .mutate_if::<StoragePool, _>(&pool.metadata.name, &pool.metadata.uid, |p| {
            p.status.locality = locality;
            p.status.disagreement = disagreement.clone();
        })
        .await?;
    Ok(())
}

/// Every volume this cluster holds, once per pass: bind the unbound, and let
/// go of the released.
///
/// The pools are read once and shared, for the reason the VM half reads its
/// nodes once: a pool that is edited halfway through a listing would place
/// two volumes of the same pass against two different statements about the
/// same wiring.
pub(super) async fn place_volumes(p: &Pass<'_>) -> anyhow::Result<()> {
    let volumes = p.store.list::<Volume>().await?;
    if volumes.is_empty() {
        return Ok(());
    }
    let pools = p.store.list::<StoragePool>().await?;
    // D4: whether the claim on each volume still has an object behind it.
    // One listing per pass, shared, for the reason the pools are — and the
    // VMs have to be read here at all because `attachedTo` is a NAME and the
    // derivation may not look up another object.
    let claimants = p.store.list::<Vm>().await?;
    telemetry::metrics::objects().set_count(Volume::KIND, volumes.len() as i64);
    for volume in volumes {
        // Before the ownership gate, and deliberately: this is a fact about
        // `Vm` OBJECTS, which every replica reads out of the same store, and
        // it is idempotent under CAS. Gating it would leave unanswered
        // exactly the case it exists for — a holder that went away with its
        // machine, whose volume no replica holds a session for. The same
        // argument `expire_vm_reports` makes one object over.
        if let Err(e) = note_claimant(p, &volume, &claimants).await {
            warn!(volume = %volume.metadata.name, error = format!("{e:#}"),
                  "recording the claimant failed");
        }
        // Whose volume this is, before anything else is decided about it.
        // Without this the two replicas that do not hold the node's session
        // used to reconcile it too, fail to deliver, and publish `Failed`
        // with a sentence that was false — see `may_reconcile_volume`.
        if !may_reconcile_volume(&volume, p.sessions) {
            continue;
        }
        let name = volume.metadata.name.clone();
        if let Err(e) = reconcile_volume(p, &pools, volume).await {
            warn!(volume = %name, error = format!("{e:#}"), "volume reconcile failed");
        }
    }
    Ok(())
}

/// Record whether the VM object that claims this volume still does.
/// Deleting VMs no longer count as claimants, but node open-handle reports must
/// also clear before the derived attachment claim is released.
async fn note_claimant(p: &Pass<'_>, volume: &Volume, vms: &[Vm]) -> anyhow::Result<()> {
    let Some(holder) = volume.status.attached_to.as_deref() else {
        return Ok(());
    };
    let verdict = claimant_verdict(volume, vms);
    if volume.status.claimant_gone == verdict.gone && verdict.bind.is_none() {
        return Ok(());
    }
    let claim = (
        volume.status.attached_to.clone(),
        volume.status.attached_uid.clone(),
    );
    p.store
        .mutate_if::<Volume, _>(&volume.metadata.name, &volume.metadata.uid, |v| {
            // The claim this verdict was made about, or nothing: a claim taken
            // or bound since is the next pass's to judge.
            if (v.status.attached_to.clone(), v.status.attached_uid.clone()) != claim {
                return;
            }
            v.status.claimant_gone = verdict.gone;
            if let Some(uid) = &verdict.bind {
                v.status.attached_uid = Some(uid.clone());
            }
        })
        .await?;
    if verdict.gone {
        info!(volume = %volume.metadata.name, holder,
              "the claimant is gone; the claim falls when no node reports the bytes open");
    }
    Ok(())
}

/// What the claimant pass concludes about one volume's claim.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct ClaimantVerdict {
    /// No live VM object holds the claim any more.
    pub(super) gone: bool,
    /// A claim from before claims carried a uid, bound to the one VM object
    /// that carries the name and still refers to the volume. (IKR-B81)
    pub(super) bind: Option<String>,
}

/// Judge a claim by the uid it carries. A claim without one is bound to the
/// live VM of its name that refers to the volume — names are unique at any
/// one moment — unless it has already been found gone: a gone claim is never
/// handed to a VM made under the name since, it falls and is taken afresh.
pub(super) fn claimant_verdict(volume: &Volume, vms: &[Vm]) -> ClaimantVerdict {
    let claims = |vm: &&Vm| {
        vm.metadata.deletion_timestamp.is_none()
            && vm
                .spec
                .referenced_volumes()
                .iter()
                .any(|named| named == &volume.metadata.name)
    };
    match volume.status.attached_uid.as_deref() {
        Some(uid) => ClaimantVerdict {
            gone: !vms.iter().filter(claims).any(|vm| vm.metadata.uid == uid),
            bind: None,
        },
        None if volume.status.claimant_gone => ClaimantVerdict {
            gone: true,
            bind: None,
        },
        None => {
            let holder = volume.status.attached_to.as_deref();
            let named = vms
                .iter()
                .filter(claims)
                .find(|vm| Some(vm.metadata.name.as_str()) == holder);
            ClaimantVerdict {
                gone: named.is_none(),
                bind: named.map(|vm| vm.metadata.uid.clone()),
            }
        }
    }
}

/// The node's word for "these bytes do not exist any more".
///
/// Not a `VolumePhaseKind`, and it must not become one: an object that reaches it
/// is deleted rather than parked. It travels as a string on the status road
/// and is read in exactly two places — the ingest, which maps it onto the
/// `Releasing` an outgoing volume already carries, and `release`, which reads
/// the node's report to decide the finalizer may come off.
pub(crate) const VOLUME_GONE: &str = "Gone";

/// One volume, as the ordered sequence of concerns it is:
///
/// release -> placement -> provision -> requeue.
///
/// Release first, and for the same reason teardown comes before placement on
/// a VM: a volume on its way out is not a volume to place. Everything after
/// it needs a volume that is staying.
pub(super) async fn reconcile_volume(
    p: &Pass<'_>,
    pools: &[StoragePool],
    volume: Volume,
) -> anyhow::Result<()> {
    if volume.metadata.deletion_timestamp.is_some() {
        return release(p, &volume).await;
    }
    match next_for(&volume) {
        Next::Place => place_volume(p, pools, volume).await,
        Next::Provision(node) => {
            let node = node.to_string();
            provision_volume(p, &volume, &node).await
        }
        Next::Requeue(node) => {
            let node = node.to_string();
            requeue_volume(p, &volume, &node).await
        }
        Next::Resize(node) => {
            let node = node.to_string();
            resize_volume(p, &volume, &node).await
        }
        Next::Settled => Ok(()),
    }
}

/// The next operation required by a retained volume and its provisioning node.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Next<'a> {
    /// No node yet: choose one out of the pool.
    Place,
    /// Bound and not yet made — the command that OPEN-ITEMS §1 was about.
    /// Everything before it existed; nothing sent it.
    Provision(&'a str),
    /// Failed, and the policy says try again. The kick is another Provision,
    /// which is idempotent — so the repair path is the ordinary path and
    /// there is no second one to get wrong.
    Requeue(&'a str),
    /// Ready, and the spec asks for more room than the node has measured —
    /// or the room is there and the guest holding it has not been told.
    Resize(&'a str),
    /// Nothing to do this pass.
    Settled,
}

pub(super) fn next_for(volume: &Volume) -> Next<'_> {
    let Some(node) = volume.status.node.as_deref() else {
        return Next::Place;
    };
    match volume.status.phase().kind() {
        VolumePhaseKind::Pending => Next::Provision(node),
        VolumePhaseKind::Failed => Next::Requeue(node),
        VolumePhaseKind::Ready if grew(volume) || volume.status.untold_gib > 0 => {
            Next::Resize(node)
        }
        _ => Next::Settled,
    }
}

/// What an object says when the bytes grew and the guest did not hear.
///
/// Its own function because it is the whole of what a half-done resize looks
/// like from a chair, and it has to say three things in one line: what
/// happened (the backend grew), what did not (the guest was not told), and
/// what a retry would do (only the second half — there is no shrinking back,
/// so nothing is rolled back and nothing is repeated).
pub(super) fn guest_not_told(size_gib: u64, error: &str) -> String {
    format!(
        "backend grew to {size_gib} GiB; the guest was not told: {error}; \
         retry resizes only the notification"
    )
}

/// Whether a positive backend size measurement is smaller than the requested size.
/// Zero means unmeasured and does not trigger growth by itself.
pub(super) fn grew(volume: &Volume) -> bool {
    volume.status.size_gib > 0 && volume.spec.size_gib > volume.status.size_gib
}

/// Persist the notification intent, grow the backend, then notify a running holder.
/// The volume and VM may be on different nodes. `untold_gib` keeps notification
/// due after a restart or failure even when the backend already reports the new
/// size. Growth is not rolled back if notification fails.
pub(super) async fn resize_volume(p: &Pass<'_>, volume: &Volume, node: &str) -> anyhow::Result<()> {
    let name = volume.metadata.name.clone();
    let size_bytes = volume.spec.size_gib.saturating_mul(1024 * 1024 * 1024);

    // The intent, before anything is asked of anybody: whoever holds this
    // volume has to hear about this size. First, so that losing this
    // controller between the two halves loses nothing.
    if volume.status.untold_gib < volume.spec.size_gib {
        p.store
            .mutate_if::<Volume, _>(&name, &volume.metadata.uid, |v| {
                v.status.untold_gib = v.status.untold_gib.max(v.spec.size_gib);
            })
            .await?;
    }

    // First half: the bytes, on the provisioning node — unless the node has
    // measured them at this size already, which makes this pass the retry of
    // the second half and of nothing else.
    if grew(volume) {
        info!(volume = %name, node, from = volume.status.size_gib, to = volume.spec.size_gib,
              "growing a volume");
        if let Err(e) = p
            .registry
            .send_command(
                node,
                "",
                command::Op::ResizeVolume(proto::ResizeVolume {
                    id: volume.metadata.uid.clone(),
                    size_bytes,
                }),
            )
            .await
        {
            let message = format!("{e:#}");
            warn!(volume = %name, node, error = %message, "the backend did not grow");
            p.store
                .mutate_if::<Volume, _>(&name, &volume.metadata.uid, |v| {
                    // Not the node's word: the node never got the command.
                    // Two of the old assignments said "Reported" about a
                    // session failure, and this was one of them — the
                    // sentence is this tier's, about a wire, and the fix is
                    // on the network. Which is also why it names nobody.
                    v.status.reported = Some(controller_api::VolumeReported::here(
                        VolumePhaseKind::Failed,
                        controller_api::VolumeReason::Undeliverable,
                        Some(message.clone()),
                        Utc::now(),
                    ));
                })
                .await?;
            return Ok(());
        }
    }

    // Second half: the guest, on the node the VM runs on — a different
    // machine whenever the pool is shared.
    let Some((vm, vm_node)) = holder_of(p, volume).await? else {
        // Nothing is running it, so nothing has a size to be wrong about: a
        // guest that starts later opens the disk as big as it is.
        debug!(volume = %name, "nobody is holding it; there is no guest to tell");
        return told(p, volume).await;
    };
    if let Err(e) = p
        .registry
        .send_command(
            &vm_node,
            "",
            command::Op::ResizeAttachment(proto::ResizeAttachment {
                vm,
                volume_id: volume.metadata.uid.clone(),
                size_bytes,
            }),
        )
        .await
    {
        // NOT Failed. The bytes are there and the object is not broken; what
        // is missing is one notification, and a phase that said Failed would
        // send the requeue curve at a provision that has nothing to do.
        let message = guest_not_told(volume.spec.size_gib, &format!("{e:#}"));
        warn!(volume = %name, node = %vm_node, "{message}");
        p.store
            .mutate_if::<Volume, _>(&name, &volume.metadata.uid, |v| {
                // The sentence, onto the word that is already there. The
                // bytes ARE what the node last said they are — the resize
                // grew them — and what is missing is one notification, so the
                // word must not move. Only the sentence does; `untoldGib`,
                // written above, is what makes the next pass try again.
                note_on_volume(v, Some(message.clone()));
            })
            .await?;
        return Ok(());
    }
    told(p, volume).await?;
    info!(volume = %name, "the guest was told");
    Ok(())
}

/// The second half is done: the guest has heard about this size, or there is
/// no running guest to hear it.
///
/// The size on the object is the NODE's word and arrives with its next
/// report; nothing about it is written here. What goes is the intent this
/// pass answered — only up to the size it told, so a spec that grew again in
/// between keeps its own — and the sentence a previous half-resize may have
/// left, because it is answered now.
async fn told(p: &Pass<'_>, volume: &Volume) -> anyhow::Result<()> {
    let size = volume.spec.size_gib;
    p.store
        .mutate_if::<Volume, _>(&volume.metadata.name, &volume.metadata.uid, |v| {
            if v.status.untold_gib <= size {
                v.status.untold_gib = 0;
            }
            note_on_volume(v, None);
        })
        .await?;
    Ok(())
}

/// Resolve namespace and seed, claim Provisioning by CAS, and dispatch.
/// The backend handle remains empty until the node reports the resource it made.
pub(super) async fn provision_volume(
    p: &Pass<'_>,
    volume: &Volume,
    node: &str,
) -> anyhow::Result<()> {
    let name = volume.metadata.name.clone();
    // Before the spec, because the spec carries the answer. A pool that hands
    // out nothing countable answers `None` and costs the pool read this
    // function was going to make anyway.
    if let Err(why) = super::namespaces::assign(p.store, volume).await? {
        // No later pass can make a namespace appear, so this is Failed and
        // not a wait — the same shape as a snapshot that is gone.
        warn!(volume = %name, %why, "provision cannot start");
        p.store
            .mutate_if::<Volume, _>(&name, &volume.metadata.uid, |v| {
                v.status.reported = Some(controller_api::VolumeReported::here(
                    VolumePhaseKind::Failed,
                    controller_api::VolumeReason::SourceMissing,
                    Some(why.clone()),
                    Utc::now(),
                ));
            })
            .await?;
        return Ok(());
    }
    let spec_json = volume_spec_json(p.store, volume).await?;
    // The third thing a volume can start from, after "empty" and "a
    // catalogue image": somebody's own point in time. Resolved to a uid here,
    // because a name is what people call a snapshot and the node was handed a
    // uid when it took one.
    let from_snapshot = match &volume.spec.from_snapshot {
        None => String::new(),
        Some(named) => match p.store.get::<VolumeSnapshot>(named).await {
            Ok(s) if s.status.phase().kind() == VolumeSnapshotPhaseKind::Ready => s.metadata.uid,
            // Not ready is a WAIT, not a refusal — the copy is being made,
            // and the volume waits as Pending the same way a VM waits for its
            // disk. Gone is a refusal: no later pass can make a volume from a
            // snapshot that does not exist.
            Ok(s) => {
                debug!(volume = %name, snapshot = %named, phase = s.status.phase().kind().as_str(),
                       "the snapshot is not ready yet; the volume waits");
                return Ok(());
            }
            Err(StoreError::NotFound(_)) => {
                let message = format!("snapshot {named} does not exist here any more");
                warn!(volume = %name, %message, "provision cannot start");
                p.store
                    .mutate_if::<Volume, _>(&name, &volume.metadata.uid, |v| {
                        v.status.reported = Some(controller_api::VolumeReported::here(
                            VolumePhaseKind::Failed,
                            controller_api::VolumeReason::SourceMissing,
                            Some(message.clone()),
                            Utc::now(),
                        ));
                    })
                    .await?;
                return Ok(());
            }
            Err(e) => return Err(e.into()),
        },
    };
    let mut sent = volume.clone();
    sent.status.reported = Some(controller_api::VolumeReported::here(
        VolumePhaseKind::Provisioning,
        controller_api::VolumeReason::Dispatched,
        Some(format!("{node} was told to make the bytes")),
        Utc::now(),
    ));
    // The claim before the command, like everywhere else in this file: a CAS
    // that loses means another replica is already sending, and sending twice
    // is a second `provision` on a backend that may not enjoy it — idempotent
    // by contract, but there is no reason to lean on that when a CAS is free.
    match p.store.update(&sent).await {
        Ok(_) => {}
        Err(StoreError::Conflict(_)) => {
            debug!(volume = %name, "lost the provision race");
            return Ok(());
        }
        Err(e) => return Err(e.into()),
    }
    let outcome = p
        .registry
        .send_command(
            node,
            "",
            command::Op::ProvisionVolume(proto::ProvisionVolume {
                id: volume.metadata.uid.clone(),
                spec_json,
                from_snapshot,
            }),
        )
        .await;
    if let Err(e) = outcome {
        // Failed on the object, so the requeue curve picks it up. Not left
        // Provisioning: a volume waiting for a node that refused it would
        // wait for ever, because the node sends no report about a volume it
        // never accepted.
        let message = format!("{e:#}");
        warn!(volume = %name, node, error = %message, "provision could not be delivered");
        p.store
            .mutate_if::<Volume, _>(&name, &volume.metadata.uid, |v| {
                if v.status.phase().kind() == VolumePhaseKind::Provisioning {
                    v.status.reported = Some(controller_api::VolumeReported::here(
                        VolumePhaseKind::Failed,
                        controller_api::VolumeReason::Undeliverable,
                        Some(message.clone()),
                        Utc::now(),
                    ));
                }
            })
            .await?;
        return Ok(());
    }
    // The generation this command carried down. Same statement the cloud half
    // makes one tier up, and the reason both make it: a client could not tell
    // "this tier does not report it" from "this tier is behind", and every
    // volume in the estate read `generation 1, observed 0` for ever.
    let dispatched = volume.metadata.generation;
    p.store
        .mutate_if::<Volume, _>(&name, &volume.metadata.uid, |v| {
            v.status.observed_generation = v.status.observed_generation.max(dispatched);
        })
        .await?;
    info!(volume = %name, node, "provision dispatched");
    Ok(())
}

/// A Failed volume, on the same backoff curve a Failed VM is on.
///
/// The kick is another `ProvisionVolume`, and that is the whole reason this
/// is three lines rather than a second mechanism: provision is idempotent by
/// contract, so "try again" and "do it the first time" are one command.
pub(super) async fn requeue_volume(
    p: &Pass<'_>,
    volume: &Volume,
    node: &str,
) -> anyhow::Result<()> {
    let now = Utc::now();
    let due = match volume.status.last_requeue {
        None => true,
        Some(since) => match p.requeue.next_delay(volume.status.requeue_attempts) {
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
    let name = volume.metadata.name.clone();
    let kicked = p
        .store
        .mutate_if::<Volume, _>(&name, &volume.metadata.uid, |v| {
            v.status.requeue_attempts = v.status.requeue_attempts.saturating_add(1);
            v.status.last_requeue = Some(now);
            // Back to a wait, and the failure that got it here is forgotten:
            // a requeue IS "try again as if nothing had been said". Without
            // clearing the word the derivation would go on reading the old
            // `Failed` and the volume would never be asked for again.
            v.status.reported = Some(controller_api::VolumeReported::here(
                VolumePhaseKind::Pending,
                controller_api::VolumeReason::AwaitingNode,
                Some(format!(
                    "attempt {} after a failure",
                    v.status.requeue_attempts
                )),
                now,
            ));
        })
        .await?;
    info!(volume = %name, attempt = kicked.status.requeue_attempts, "requeueing a failed volume");
    // Straight back through the dispatch rather than waiting a tick: the
    // object now says Pending, which is what `reconcile_volume` would read
    // next pass anyway.
    provision_volume(p, &kicked, node).await
}

/// Build the agent spec from the pool driver, size, seed, and backend parameters.
/// The controller-assigned namespace overrides the pool's top-level default.
/// The agent receives the resolved spec and does not need a pool resource.
pub(crate) async fn volume_spec_json(store: &EtcdStore, volume: &Volume) -> anyhow::Result<String> {
    let pool: StoragePool = store.get(&volume.spec.pool).await?;
    // The one thing this tier writes INTO a driver's params rather than
    // passing through: which namespace of a cluster-wide pool this volume
    // holds. Read here and assigned in `provision_volume`, because building
    // a spec is a read and assigning is a write — and because a migration
    // builds this same spec for a volume that has held its namespace since
    // it was made. See `super::namespaces`.
    let namespace = super::namespaces::held_by(&pool, volume);
    Ok(serde_json::to_string(&serde_json::json!({
        "base_image": volume.spec.base_image,
        "size_bytes": volume.spec.size_gib.saturating_mul(1024 * 1024 * 1024),
        "driver": pool.spec.driver,
        "params": merge_params(pool.spec.params.as_ref(), volume_params(namespace).as_ref()),
    }))?)
}

/// What THIS volume says about its own backend options, over the pool's.
///
/// A volume carries no params FIELD — the object has none, deliberately,
/// because everything a tenant may choose about a disk is already a named
/// field. What it does carry is one answer this tier worked out for it: which
/// namespace of a cluster-wide pool is its own (`super::namespaces`). That is
/// a per-volume statement about a pool-wide document, which is exactly what
/// the merge below is for.
pub(super) fn volume_params(namespace: Option<String>) -> Option<serde_json::Value> {
    Some(serde_json::json!({ "namespace": namespace? }))
}

/// Pool params, with the volume's own written over them.
///
/// A shallow merge over the top-level keys and no deeper, because that is the
/// depth at which the two documents mean anything to each other: a pool says
/// `{"vg": "vg0"}` and a volume would say `{"tag": "data"}`, and merging into
/// nested objects would be this tier claiming to understand a backend's
/// options.
pub(super) fn merge_params(
    pool: Option<&serde_json::Value>,
    volume: Option<&serde_json::Value>,
) -> Option<serde_json::Value> {
    match (pool, volume) {
        (None, None) => None,
        (Some(one), None) | (None, Some(one)) => Some(one.clone()),
        (Some(pool), Some(volume)) => {
            let mut merged = pool.clone();
            if let (Some(into), Some(from)) = (merged.as_object_mut(), volume.as_object()) {
                for (k, v) in from {
                    into.insert(k.clone(), v.clone());
                }
                return Some(merged);
            }
            // Either side is not an object: the volume's word is the later
            // one and stands whole, rather than being merged into something
            // that has no keys.
            Some(volume.clone())
        }
    }
}

/// Retain the finalizer while a VM or undeleted snapshot holds the volume.
/// Otherwise request deprovisioning and wait for the node to report Gone.
/// An unplaced volume can be removed immediately.
pub(super) async fn release(p: &Pass<'_>, volume: &Volume) -> anyhow::Result<()> {
    let name = &volume.metadata.name;
    // Read once per volume rather than once per pass, because the answer is
    // only needed for a volume that is on its way out — which is nearly none
    // of them.
    let snapshots = snapshots_holding(&p.store.list::<VolumeSnapshot>().await?, name);
    match release_action(volume, &snapshots) {
        Release::HeldBy(holder) => {
            // And here the sentence becomes true. It has been in this file
            // since the storage split and could never fire, because nothing
            // wrote `attachedTo` — which is what made "detach before delete",
            // the one rule guarding against data loss, dead code. Storage A
            // wrote it; this reads it, and storage B gave it a second reason.
            debug!(volume = %name, ?holder, "still held, keeping the data");
            note_volume_releasing(p, volume, holder.sentence()).await
        }
        Release::WaitingForNode(node) => deprovision_volume(p, volume, node).await,
        Release::Drop => drop_volume(p, volume, &snapshots).await,
    }
}

/// Carry out `Release::Drop` on the revision it was decided for (R2-2, R3-F02).
///
/// The finalizer comes off the listed uid only while the fresh revision still drops, and the
/// delete names the revision that write produced: a volume recreated under the same name, or
/// one a holder took in between, is left for the next pass. The namespace claim goes back
/// between the two, once the object is committed to going and before it is deleted, because
/// the table is keyed by its uid. The DATA on the namespace is untouched — an import provider
/// made none of it and destroys none of it.
async fn drop_volume(p: &Pass<'_>, volume: &Volume, snapshots: &[String]) -> anyhow::Result<()> {
    let name = &volume.metadata.name;
    let finalizer = controller_api::VOLUME_RELEASE_FINALIZER;
    let drops = |v: &Volume| {
        v.metadata.deletion_timestamp.is_some() && release_action(v, snapshots) == Release::Drop
    };
    let Some(written) = deletion::take_finalizer(p.store, volume, finalizer, &drops).await? else {
        debug!(volume = %name, "the volume moved on since it was listed; the next pass decides");
        return Ok(());
    };
    namespaces::give_back(p.store, volume).await;
    if deletion::finish_release(p.store, &written, finalizer, drops).await? {
        info!(volume = %name, "volume released; nothing holds its bytes any more");
    }
    Ok(())
}

/// Deletion decision derived from recorded holders and node placement.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Release<'a> {
    /// Somebody is using it. Everything stays — the object, the data, the
    /// finalizer — and the pass comes back: the holder letting go happens
    /// elsewhere, and no amount of deciding here makes it sooner.
    HeldBy(HeldBy<'a>),
    /// Nobody holds it, but a node has the bytes. Sending that node the
    /// deprovision is the step that follows this one; until then the object
    /// stays, because an object removed while its LV is still in the volume
    /// group is a volume nobody will ever find again.
    WaitingForNode(&'a str),
    /// Drop an unclaimed volume with no node: it was either never placed or its
    /// node reported Gone and cleared the binding. No backend command remains.
    Drop,
}

/// Request backend deletion and retain the object until explicit Gone evidence.
/// Missing reports or an unreachable node do not establish that the bytes are gone.
pub(super) async fn deprovision_volume(
    p: &Pass<'_>,
    volume: &Volume,
    node: &str,
) -> anyhow::Result<()> {
    let name = volume.metadata.name.clone();
    // A node nobody can reach keeps the volume. NOT a silent delete: the
    // bytes are on a machine that is down, and an object removed while they
    // are there is a volume nobody will ever find again. The sentence says so
    // rather than leaving an operator with an object that simply does not go.
    let reachable = {
        let nodes = p.nodes.lock().unwrap();
        nodes.iter().any(|c| c.name == node && c.connected)
    };
    if !reachable {
        debug!(volume = %name, node, "the node holding this volume is not reachable");
        return note_volume_releasing(
            p,
            volume,
            format!("node {node} unreachable; the data is there until it returns"),
        )
        .await;
    }
    let outcome = p
        .registry
        .send_command(
            node,
            "",
            command::Op::DeprovisionVolume(proto::DeprovisionVolume {
                id: volume.metadata.uid.clone(),
            }),
        )
        .await;
    if let Err(e) = outcome {
        // A refusal is an answer, and the one that matters is the node's own
        // last defence: it will not destroy a volume a VM there still has
        // open. Recorded on the object and retried next pass — the VM is on
        // its way out, and the sentence tells an operator what is being
        // waited for.
        let message = format!("{e:#}");
        debug!(volume = %name, node, error = %message, "deprovision refused");
        return note_volume_releasing(p, volume, message).await;
    }
    debug!(volume = %name, node, "deprovision dispatched, waiting for Gone");
    Ok(())
}

/// Say what the release is waiting for, and only when it changed.
///
/// The phase moves to `Releasing` here too: a volume with a deletionTimestamp
/// that still said `Ready` would be an object whose own status contradicts
/// its metadata.
pub(super) async fn note_volume_releasing(
    p: &Pass<'_>,
    volume: &Volume,
    reason: String,
) -> anyhow::Result<()> {
    if volume.status.holder.as_deref() == Some(reason.as_str()) {
        return Ok(());
    }
    p.store
        .mutate_if::<Volume, _>(&volume.metadata.name, &volume.metadata.uid, |v| {
            // The one place that knows WHO is holding it — the sentence names
            // the vm or the snapshot, and the snapshot is an object the
            // derivation may not read — so the one place that writes the
            // fact. `Releasing { HeldBy }` follows from it.
            v.status.holder = Some(reason.clone());
        })
        .await?;
    Ok(())
}

pub(super) fn release_action<'a>(volume: &'a Volume, snapshots: &'a [String]) -> Release<'a> {
    // Consumer before node, and the order is the rule: a volume that is BOTH
    // attached and provisioned must report the attachment, because that is
    // what has to end first.
    if let Some(vm) = volume.status.attached_to.as_deref() {
        return Release::HeldBy(HeldBy::Vm(vm));
    }
    // The second holder, and it is a different sentence with the same shape:
    // a snapshot standing on a file that has been deleted is a snapshot of
    // nothing, so the bytes stay until the last copy of them goes. The VM
    // comes first because a VM is what a person will look for.
    if let Some(snapshot) = snapshots.first() {
        return Release::HeldBy(HeldBy::Snapshot(snapshot));
    }
    match volume.status.node.as_deref() {
        Some(node) => Release::WaitingForNode(node),
        None => Release::Drop,
    }
}

/// Who is holding a volume's bytes. Two answers, one shape, two sentences.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum HeldBy<'a> {
    /// A VM has the disk open. Ends when the VM lets go.
    Vm(&'a str),
    /// A snapshot stands on the data. Ends when the snapshot is deleted —
    /// and, unlike a VM, deleting the volume does not make that happen.
    Snapshot(&'a str),
}

impl HeldBy<'_> {
    /// What an operator is told, and what to do about it. Different for the
    /// two because the way out is different: a VM lets go when it is deleted
    /// or stopped, a snapshot has to be deleted itself.
    pub(super) fn sentence(&self) -> String {
        match self {
            HeldBy::Vm(vm) => format!("held by {vm}; delete the vm first, or wait"),
            HeldBy::Snapshot(s) => {
                format!("held by snapshot {s}; delete the snapshot first, or wait")
            }
        }
    }
}

/// Choose a reachable pool node with the required backend capability.
/// Storage placement does not spend VM CPU or memory capacity. Claim placement
/// by one CAS; a losing writer must not overwrite the winning node.
pub(super) async fn place_volume(
    p: &Pass<'_>,
    pools: &[StoragePool],
    volume: Volume,
) -> anyhow::Result<()> {
    let name = volume.metadata.name.clone();
    let Some(pool) = pools.iter().find(|p| p.metadata.name == volume.spec.pool) else {
        // The pool a volume names is checked at the API edge, so reaching
        // this means it was deleted afterwards — which the delete handler
        // refuses while volumes point at it. Say so and wait rather than
        // placing the volume somewhere arbitrary.
        return note_pending(
            p,
            &volume,
            format!(
                "storage pool {:?} does not exist here; the volume cannot be placed",
                volume.spec.pool
            ),
        )
        .await;
    };

    let policy = StoragePolicy::of(pool);
    let decision = {
        let nodes = p.nodes.lock().unwrap();
        match feasible_for_storage(&policy, &nodes).first() {
            Some(node) => Ok(node.name.clone()),
            None => Err(storage_pending_reason(&policy, &pool.metadata.name, &nodes)),
        }
    };
    let node = match decision {
        Ok(node) => node,
        Err((category, reason)) => {
            p.pending.note(category);
            return note_pending(p, &volume, reason).await;
        }
    };

    let mut bound = volume;
    bound.status.node = Some(node.clone());
    // Placement alone is not provisioning evidence. Clear prior runtime reports
    // and retain Pending/AwaitingNode until dispatch and node reports advance it.
    bound.status.reported = None;
    match p.store.update(&bound).await {
        Ok(_) => info!(volume = %name, node = %node, pool = %bound.spec.pool,
                       "volume placed"),
        Err(StoreError::Conflict(_)) => {
            debug!(volume = %name, node = %node, "lost the placement race")
        }
        Err(e) => return Err(e.into()),
    }
    Ok(())
}

/// Change only the diagnostic on an existing report, preserving its observation.
/// Do nothing if no report exists; notification failure is not a new byte-state observation.
fn note_on_volume(v: &mut Volume, message: Option<String>) {
    if let Some(said) = &mut v.status.reported {
        said.message = message;
    }
}

/// Say WHY on the object, and only when it changed.
///
/// The same rule the VM half follows: a level-triggered pass reaches this
/// conclusion every five seconds for as long as the volume is unplaceable,
/// and writing the same sentence again would wake the watch for nothing.
pub(super) async fn note_pending(
    p: &Pass<'_>,
    volume: &Volume,
    reason: String,
) -> anyhow::Result<()> {
    debug!(volume = %volume.metadata.name, reason = %reason, "volume stays pending");
    if volume.status.phase().message() == Some(reason.as_str()) {
        return Ok(());
    }
    p.store
        .mutate_if::<Volume, _>(&volume.metadata.name, &volume.metadata.uid, |v| {
            v.status.reported = Some(controller_api::VolumeReported::here(
                VolumePhaseKind::Pending,
                controller_api::VolumeReason::Unplaced,
                Some(reason.clone()),
                Utc::now(),
            ));
        })
        .await?;
    Ok(())
}
