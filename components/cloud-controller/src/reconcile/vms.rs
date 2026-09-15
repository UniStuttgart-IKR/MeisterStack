// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! The VM half of the pass: reconcile one VM, hand it to its cluster,
//! evacuate it, drain a cluster of them, tear it down. Moved out of
//! `reconcile.rs` unchanged.

use super::*;

/// Same shape as one tier down: the trace is on the object, and the span gets
/// its parent before it starts (`telemetry::in_trace`).
///
/// `vm` is what a person calls it, `vm_id` is the uid that travels down — the
/// cluster keeps it as the cloud-uid and reports phases under it.
#[allow(clippy::too_many_arguments)]
pub(super) async fn reconcile_vm(
    store: &EtcdStore,
    registry: &SessionRegistry,
    scheduler: &dyn Scheduler,
    sessions: &HashSet<String>,
    clusters: &std::sync::Mutex<Vec<Candidate>>,
    book: &OnceCell<AddressBook>,
    pending: &PendingTally,
    vm: Vm,
) -> anyhow::Result<()> {
    let context = birth_trace(&vm).unwrap_or_else(telemetry::TraceParent::root);
    let span = tracing::info_span!(
        "reconcile_vm",
        vm = %vm.metadata.name,
        vm_id = %vm.metadata.uid,
        trace_id = %context.trace_id_hex()
    );
    telemetry::in_trace(
        span,
        &context,
        reconcile_vm_traced(
            store, registry, scheduler, sessions, clusters, book, pending, vm, context,
        ),
    )
    .await
}

/// The trace a pass belongs to.
///
/// The object's context covers the VM's BIRTH and stops there: while it is
/// still Pending or Provisioning, this pass is part of the request that asked
/// for it. Once the phase is stable — or Failed, or Quarantined — the pass
/// gets a root of its own.
///
/// Without that cut the trace never ends. Level-triggered means a pass runs
/// every tick forever, and a first version of this attached all of them: one
/// VM, thirty seconds, twelve spans hanging off a `POST /vms` that had long
/// since returned. The annotation stays on the object either way — it is the
/// record of where the VM came from, which is worth keeping whether or not
/// anything is still tracing against it.
pub(super) fn birth_trace(vm: &Vm) -> Option<telemetry::TraceParent> {
    if !matches!(
        vm.status.phase().kind(),
        VmPhaseKind::Pending | VmPhaseKind::Provisioning
    ) {
        return None;
    }
    telemetry::TraceParent::parse(vm.metadata.traceparent().unwrap_or_default())
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn reconcile_vm_traced(
    store: &EtcdStore,
    registry: &SessionRegistry,
    scheduler: &dyn Scheduler,
    sessions: &HashSet<String>,
    clusters: &std::sync::Mutex<Vec<Candidate>>,
    book: &OnceCell<AddressBook>,
    pending: &PendingTally,
    vm: Vm,
    context: telemetry::TraceParent,
) -> anyhow::Result<()> {
    // Everything this pass hands to the cluster rides on it, and the cluster
    // hands it to the agent, so `POST /vms` and the backend spawn are one
    // trace.
    let outgoing = telemetry::outgoing(&context).to_string();

    // Ownership before anything else, teardown included: a bound VM is the
    // business of the replica its cluster talks to, and of no other. Not an
    // error and not a warning — the right replica is doing this right now.
    if !may_reconcile(&vm, sessions) {
        debug!(cluster = ?vm.spec.cluster_name, "vm belongs to another replica's session, skipping");
        return Ok(());
    }

    if vm.is_deleting() {
        return teardown(store, registry, &vm, &outgoing).await;
    }

    let Some(cluster) = vm.spec.cluster_name.clone() else {
        return place(store, registry, scheduler, clusters, pending, vm, &outgoing).await;
    };

    let Some(report) = current_report(registry, &vm, &cluster) else {
        return Ok(());
    };

    if vm.status.phase().kind() == VmPhaseKind::Failed {
        // A cluster that answered "no" answered about this VM. Asking again
        // every five seconds would not change the answer, and renaming the VM
        // to dodge it is the kind of cleverness that loses somebody's disk.
        return Ok(());
    }

    // Before the drift table, for the same reason as one tier down: a VM
    // being moved by restart is meant to be Running and is deliberately not
    // running right now, and the drift table has no arm for "stopped on
    // purpose by somebody else".
    if vm.status.evacuating.is_some() {
        return evacuate(store, registry, &vm, &cluster, book, &outgoing).await;
    }

    hand_down(store, registry, book, &vm, &cluster, &report, &outgoing).await
}

/// What the bound cluster last said, where it is an answer about this VM at
/// all.
///
/// Everything the steps below decide is decided against this, and silence is
/// not an answer: a cluster that has reported nothing, or nothing newer than
/// our own last command, gets nothing decided about its VMs.
fn current_report(
    registry: &SessionRegistry,
    vm: &Vm,
    cluster: &str,
) -> Option<crate::session::Report> {
    let Some(report) = registry.report(cluster) else {
        debug!(cluster = %cluster, "no current status from the bound cluster, waiting");
        return None;
    };
    if !status_is_current(vm, report.at) {
        debug!(cluster = %cluster, "the last status predates our last command, waiting");
        return None;
    }
    Some(report)
}

/// The VM is not bound to a cluster: get it onto one, or say why it is not.
///
/// Three outcomes, in this order because the first two are about a cluster
/// that already has something of ours: an old binding that has to be given up
/// first, a storage answer that no cluster satisfies, and otherwise the
/// scheduler's pick.
async fn place(
    store: &EtcdStore,
    registry: &SessionRegistry,
    scheduler: &dyn Scheduler,
    clusters: &std::sync::Mutex<Vec<Candidate>>,
    pending: &PendingTally,
    vm: Vm,
    outgoing: &str,
) -> anyhow::Result<()> {
    // The binding is gone and a cluster still has this VM. That cluster
    // has to be told first: placing it again while the old one still
    // holds it would be two clusters for one VM, and on a pool both of
    // them serve, two VMMs on one file. The same order the tier below
    // keeps for the same move one scope down.
    if let Some(old) = vm.status.cluster_name.clone() {
        return unbind(registry, &vm, &old, outgoing).await;
    }
    // Which clusters have a NODE that could actually run this VM. Asked
    // before the binding, which is the whole fix: a cluster's capacity is
    // a sum and its catalogue a union, so a cluster can look able to
    // serve a VM that no single node of it can — and until this the
    // answer was found one tier down, after the VM had been sent there.
    let node_level = match servable_clusters(store, &vm).await? {
        Servable::Clusters(names) => names,
        Sentence(reason) => {
            pending.note(controller_api::PendingReason::VolumeNotReady);
            return note_pending(
                store,
                &vm,
                controller_api::PendingReason::VolumeNotReady,
                reason,
            )
            .await;
        }
    };
    match pick_cluster(scheduler, clusters, &vm, &node_level) {
        Ok(pick) => bind(store, vm, pick).await,
        Err((known, (category, reason))) => {
            // Say WHY on the object and not only in this replica's debug
            // log — see the cluster tier's `place`. One floor up the
            // sentence is worth even more: a cluster catalogue is the
            // UNION of its nodes', so "each part is served somewhere" is
            // a real and otherwise invisible outcome here.
            // The sentence goes on the object, the CATEGORY into the
            // tally: the sentence names capabilities and counts
            // candidates, and is the string that must never be a label.
            pending.note(category);
            debug!(known, "no schedulable cluster, staying pending");
            note_pending(store, &vm, category, reason).await
        }
    }
}

/// Decide and SPEND under one lock, and let go before anything awaits — see
/// the cluster tier's `place` for why the binding and not the API edge is the
/// authority.
///
/// `Err` carries how many candidates the sentence was measured against,
/// beside the category and the sentence itself.
fn pick_cluster(
    scheduler: &dyn Scheduler,
    clusters: &std::sync::Mutex<Vec<Candidate>>,
    vm: &Vm,
    node_level: &[String],
) -> Result<String, (usize, (controller_api::PendingReason, String))> {
    let mut clusters = clusters.lock().unwrap();
    let allowed: Vec<Candidate> = clusters
        .iter()
        .filter(|c| node_level.iter().any(|n| n == &c.name))
        .cloned()
        .collect();
    match scheduler.assign(vm, &allowed) {
        Some(pick) => {
            controller_api::spend(&mut clusters, &pick, vm);
            Ok(pick)
        }
        // The sentence is measured against what was actually
        // offered. A cluster cut away for having no suitable node is
        // not a cluster that "had no room", and saying so would send
        // an operator to look at the wrong thing.
        None if allowed.is_empty() && !clusters.is_empty() => Err((
            clusters.len(),
            (
                controller_api::PendingReason::NoNodeForVolume,
                node_level_reason(vm, clusters.len()),
            ),
        )),
        None => Err((
            allowed.len(),
            controller_api::pending_reason_of(vm, &allowed),
        )),
    }
}

/// Write the binding the scheduler picked, and record it where a person can
/// see it.
///
/// A plain CAS on the object this pass read, not a read-modify-write: with
/// several replicas scheduling at once the binding is exactly what must NOT be
/// retried onto a newer object — a retry would re-apply this replica's choice
/// over the winner's and move a VM that is already placed. One write, one
/// winner, and the loser is told.
async fn bind(store: &EtcdStore, vm: Vm, pick: String) -> anyhow::Result<()> {
    let mut bound = vm;
    bound.spec.cluster_name = Some(pick.clone());
    // The binding answers whatever a previous pass wrote about why there was
    // none.
    // Both of them lived inside the phase since struktur 4, so one write
    // answers what a previous pass said and why it said it.
    let kind = bound.status.phase().kind();
    #[allow(deprecated)]
    bound.status.assign(VmPhase::of(kind, Utc::now()));
    match store.update(&bound).await {
        Ok(_) => {
            telemetry::metrics::scheduling().placed(telemetry::metrics::TIER_CLOUD);
            // In the arm where the compare-and-swap SUCCEEDED — the replica
            // that lost the race records nothing.
            events::record(
                store,
                about(
                    &bound,
                    events::reason::SCHEDULED,
                    format!("bound to cluster {pick}"),
                    EventType::Normal,
                ),
            )
            .await;
            info!(cluster = %pick, "scheduled");
            Ok(())
        }
        Err(StoreError::Conflict(_)) => {
            telemetry::metrics::scheduling().conflict(telemetry::metrics::TIER_CLOUD);
            debug!(cluster = %pick, "lost the scheduling race, another writer bound it");
            Ok(())
        }
        Err(e) => Err(e.into()),
    }
}

/// Hand the spec down to the bound cluster, if anything down there is behind
/// what is written here.
///
/// Three reasons to hand the spec down, and all three are level conditions
/// rather than events: the cluster does not have this VM, it has it under
/// an intent that no longer matches, or it has an older SPEC than the one
/// written here. None of them needs a memory of what was sent — when the
/// condition is gone, so is the command.
///
/// The third arrived with the volume reference, and it is the reason a
/// hot-plug at this tier now happens at all. Until the edge accepted
/// `spec.vm.volumes[].volume`, the spec of a bound VM could not change
/// here: everything on `VM_OWNED` is immutable or server-owned, so a
/// create was the only spec that ever travelled. `vm_shape_unchanged`
/// opened exactly one door — volume entries appended from the second on —
/// and without this line an attach at the cloud was accepted, bumped
/// `metadata.generation`, and stopped: the object said two disks and the
/// cluster had one, for ever.
///
/// `status.observedGeneration` is what this tier has SENT (it is written
/// by `dispatch_create` and by nothing else, deliberately), so the
/// comparison is "there is a generation here the cluster has never been
/// told about" and not a guess about what the cluster did with it.
async fn hand_down(
    store: &EtcdStore,
    registry: &SessionRegistry,
    book: &OnceCell<AddressBook>,
    vm: &Vm,
    cluster: &str,
    report: &crate::session::Report,
    outgoing: &str,
) -> anyhow::Result<()> {
    let missing = !report.uids.contains(&vm.metadata.uid);
    let drifted = lifecycle_command(vm.spec.run_strategy, vm.status.phase().kind()).is_some();
    let stale = vm.metadata.generation > vm.status.observed_generation;
    if !(missing || drifted || stale) {
        return Ok(());
    }
    // Asked only when something is about to go down, because it costs a
    // read per referenced disk and the answer cannot have changed while
    // nothing was being sent. A VM whose disks are all where it is — every
    // VM that never moved — pays one comparison and goes on.
    if !move_volumes(store, registry, vm, cluster).await? {
        debug!(cluster = %cluster, "waiting for this vm's disks to arrive at its cluster");
        return note_pending(
            store,
            vm,
            controller_api::PendingReason::VolumeNotReady,
            format!("moving this vm's disks to cluster {cluster}"),
        )
        .await;
    }
    dispatch_create(store, registry, cluster, vm, missing, book, outgoing).await
}

/// Empty every cluster an operator has asked to empty, and say what is left.
///
/// The same table one scope up, over clusters instead of machines, with one
/// row permanently dark: **there is no live migration across clusters**, so
/// `live_possible` is false here for ever rather than until something is
/// built. A running VM leaves a cluster only if its owner allowed a reboot.
pub(super) async fn drain_clusters(
    store: &EtcdStore,
    sessions: &HashSet<String>,
    vms: &[Vm],
) -> anyhow::Result<()> {
    for cluster in store.list::<Cluster>().await? {
        let name = cluster.metadata.name.clone();
        if !cluster.spec.drain {
            if cluster.status.draining.is_some() {
                store
                    .mutate::<Cluster, _>(&name, |c| c.status.draining = None)
                    .await?;
            }
            continue;
        }
        // Only the replica that talks to this cluster: everything the drain
        // decides ends in a command to it, and the ownership token is the
        // session, exactly as it is for a VM.
        if !sessions.contains(&name) {
            continue;
        }
        if let Err(e) = drain_cluster(store, &name, vms).await {
            warn!(cluster = %name, error = format!("{e:#}"), "draining this cluster failed");
        }
    }
    Ok(())
}

/// How many VMs left this CLUSTER between the last pass and this one.
///
/// The cluster-shaped twin of the node tier's `departed`, and the same rule:
/// a name that was leaving last pass, is on neither list now, still exists,
/// and is neither bound to nor reported by this cluster has arrived
/// somewhere else. What differs is only what "here" means one scope up.
pub(super) fn cluster_departed(
    previous: Option<&controller_api::Draining>,
    leaving: &[String],
    staying: &[controller_api::StayingVm],
    vms: &[Vm],
    cluster: &str,
) -> u32 {
    let Some(previous) = previous else {
        return 0;
    };
    previous
        .leaving_vms
        .iter()
        .filter(|name| {
            !leaving.contains(name)
                && !staying.iter().any(|s| &&s.vm == name)
                && vms.iter().any(|v| {
                    &&v.metadata.name == name
                        && !v.is_deleting()
                        && v.spec.cluster_name.as_deref() != Some(cluster)
                        && v.status.cluster_name.as_deref() != Some(cluster)
                })
        })
        .count() as u32
}

pub(super) async fn drain_cluster(
    store: &EtcdStore,
    cluster: &str,
    vms: &[Vm],
) -> anyhow::Result<()> {
    let mut leaving: Vec<String> = Vec::new();
    let mut staying: Vec<controller_api::StayingVm> = Vec::new();
    let mut settled = true;

    for vm in vms {
        let name = vm.metadata.name.clone();
        if vm.is_deleting() {
            continue;
        }
        if vm.spec.cluster_name.as_deref() != Some(cluster) {
            // Unbound and still reported here: on its way out, and the drain
            // is not finished while it is.
            if vm.status.cluster_name.as_deref() == Some(cluster) {
                leaving.push(name);
                settled = false;
            }
            continue;
        }
        // What holds a disk back at THIS tier is not only `node-local`: a
        // pool that names one cluster pins just as hard, because nobody has
        // said its bytes are reachable from anywhere else. Both come out of
        // the same reads the reschedule edge makes, so the two answers cannot
        // drift apart.
        let pinned = pinning_disk(store, vm, cluster).await?;
        let facts = controller_api::drain::DrainFacts {
            has_device: vm
                .spec
                .vm
                .get("devices")
                .and_then(serde_json::Value::as_array)
                .is_some_and(|d| !d.is_empty()),
            node_local_disk: pinned.as_ref().map(|(volume, _)| volume.clone()),
            // Never, at this tier. See the doc comment.
            live_possible: false,
            // And therefore no sentence about a machine: nothing here was
            // ever going to be compared.
            live_refusal: None,
        };
        match controller_api::drain::verdict(vm, &facts) {
            controller_api::drain::Verdict::Moving | controller_api::drain::Verdict::Live => {
                leaving.push(name);
                settled = false;
            }
            controller_api::drain::Verdict::Reschedule => {
                store
                    .mutate::<Vm, _>(&name, |v| v.spec.cluster_name = None)
                    .await?;
                events::record(
                    store,
                    about(
                        vm,
                        events::reason::UNBOUND,
                        format!(
                            "cluster {cluster} is being drained; placing this stopped vm again"
                        ),
                        EventType::Normal,
                    ),
                )
                .await;
                info!(vm = %name, cluster, "drained: the binding fell");
                leaving.push(name);
                settled = false;
            }
            controller_api::drain::Verdict::Restart => {
                store
                    .mutate::<Vm, _>(&name, |v| {
                        v.status.evacuating = Some(controller_api::Evacuating {
                            from: cluster.to_string(),
                            step: controller_api::EvacuationStep::Stopping
                                .as_str()
                                .to_string(),
                            since: Utc::now(),
                        });
                    })
                    .await?;
                events::record(
                    store,
                    about(
                        vm,
                        events::reason::UNBOUND,
                        format!("cluster {cluster} is being drained; moving this vm by restart"),
                        EventType::Normal,
                    ),
                )
                .await;
                info!(vm = %name, cluster, "drained: moving by restart");
                leaving.push(name);
                settled = false;
            }
            controller_api::drain::Verdict::Stays(reason) => {
                // The sentence is built here rather than by `drain::sentence`
                // for the one case the shared helper cannot word: a pool that
                // serves one cluster is not a node-local disk, even though it
                // pins the VM in exactly the same way.
                let message = match &pinned {
                    Some((volume, why)) => format!("{name} stays: {why} ({volume})"),
                    None => controller_api::drain::sentence(reason, &name, &facts),
                };
                staying.push(controller_api::StayingVm {
                    vm: name,
                    reason: reason.as_str().to_string(),
                    message,
                });
                settled &= reason.settles_a_drain();
            }
        }
    }

    // Sorted, so two passes over the same facts write the same document and
    // the second one writes nothing.
    leaving.sort();
    let current: Cluster = store.get(cluster).await?;
    let previous = current.status.draining.as_ref();
    let draining = controller_api::Draining {
        leaving: leaving.len() as u32,
        complete: settled && leaving.is_empty(),
        // The cumulative half, by the same difference the node's drain makes
        // one tier down — see `reconcile::drain::departed`. Here the machine
        // being emptied is a CLUSTER and "left" means bound to another one.
        moved_total: previous.map_or(0, |d| d.moved_total)
            + cluster_departed(previous, &leaving, &staying, vms, cluster),
        leaving_vms: leaving,
        staying: staying.len() as u32,
        reasons: staying,
    };
    if current.status.draining.as_ref() == Some(&draining) {
        return Ok(());
    }
    let complete = draining.complete;
    let leaving = draining.leaving;
    store
        .mutate::<Cluster, _>(cluster, |c| c.status.draining = Some(draining.clone()))
        .await?;
    debug!(cluster, leaving, complete, "drain observed");
    Ok(())
}

/// The first disk of this VM that cannot follow it off `cluster`, and why in
/// words.
///
/// Two things pin at this tier and they are told apart because an operator
/// has to do different things about them: a `node-local` pool means the bytes
/// are on one machine and only a copy would move them; a pool naming one
/// cluster means nobody has said the bytes are reachable from elsewhere, and
/// `spec.clusters` is how they would say so.
pub(super) async fn pinning_disk(
    store: &EtcdStore,
    vm: &Vm,
    cluster: &str,
) -> anyhow::Result<Option<(String, String)>> {
    for name in vm.spec.referenced_volumes() {
        let volume: controller_api::Volume = match store.get(&name).await {
            Ok(v) => v,
            Err(StoreError::NotFound(_)) => continue,
            Err(e) => return Err(e.into()),
        };
        let pool: controller_api::StoragePool = match store.get(&volume.spec.pool).await {
            Ok(p) => p,
            Err(StoreError::NotFound(_)) => continue,
            Err(e) => return Err(e.into()),
        };
        if pool.status.locality == Some(controller_api::Locality::NodeLocal) {
            let node = volume.status.node.as_deref().unwrap_or("one machine");
            return Ok(Some((
                name,
                format!(
                    "pool {} is node-local and the bytes are on node {node} in {cluster}",
                    pool.metadata.name
                ),
            )));
        }
        if pool.spec.served_by().len() < 2 {
            return Ok(Some((
                name,
                format!(
                    "storage pool {} serves only {cluster}; set spec.clusters on it if the same \
                     bytes really are reachable from another cluster",
                    pool.metadata.name
                ),
            )));
        }
        if controller_api::StoragePoolSpec::disagreeing(&pool.status).is_some() {
            return Ok(Some((
                name,
                format!(
                    "the clusters serving storage pool {} do not describe the same backend",
                    pool.metadata.name
                ),
            )));
        }
    }
    Ok(None)
}

/// The binding fell: tell the old cluster to destroy the VM, and wait.
///
/// The first half of a cross-cluster reschedule, and the half with something
/// at stake. What follows is NOT a placement — `status.clusterName` still
/// names the old cluster, so this pass runs again every tick until that
/// cluster's complete VM list stops naming the uid, and `session` is what
/// clears it. Placing before then would be two clusters for one VM.
///
/// `DestroyVm` is the same command a delete sends, and the cluster's own
/// finalizer flow does the rest: the node is told to destroy the instance,
/// which detaches referenced volumes and deprovisions inline ones. So an
/// instance store does not survive a cross-cluster move either — it was made
/// with the VM on that machine — while the disks that have objects of their
/// own stay exactly where their bytes are and change owner afterwards
/// (`move_volumes`).
///
/// Idempotent: the destroy is idempotent at the cluster, and a cluster that
/// has already let go simply keeps not naming the VM.
pub(super) async fn unbind(
    registry: &SessionRegistry,
    vm: &Vm,
    old: &str,
    traceparent: &str,
) -> anyhow::Result<()> {
    debug!(vm = %vm.metadata.name, cluster = old, "the binding fell; telling the old cluster");
    registry
        .send_command(
            old,
            traceparent,
            cloud_command::Op::Destroy(proto::DestroyVm {
                name: vm.metadata.name.clone(),
                uid: vm.metadata.uid.clone(),
            }),
        )
        .await?;
    Ok(())
}

/// Carry a move-by-restart one step further, or finish it — the cloud's half
/// of the same two-step machine the cluster runs one scope down.
///
/// The one thing that differs is HOW the guest is stopped. This tier sends no
/// lifecycle commands; it sends a spec, and the cluster derives the lifecycle
/// from it. So the stop is `build_spec_json` putting `Stopped` in the
/// dispatch while the mark is in its Stopping step — the cloud's instruction
/// to that cluster really is "stop it", and the owner's `runStrategy` up here
/// never changes, which is what makes the guest come back Running on the new
/// cluster with nobody having to restore anything.
pub(super) async fn evacuate(
    store: &EtcdStore,
    registry: &SessionRegistry,
    vm: &Vm,
    cluster: &str,
    book: &OnceCell<AddressBook>,
    traceparent: &str,
) -> anyhow::Result<()> {
    let Some(mark) = vm.status.evacuating.clone() else {
        return Ok(());
    };
    let name = vm.metadata.name.clone();
    if cluster != mark.from {
        store
            .mutate::<Vm, _>(&name, |v| v.status.evacuating = None)
            .await?;
        events::record(
            store,
            about(
                vm,
                events::reason::SCHEDULED,
                format!("moved off {} by restart; now on {cluster}", mark.from),
                EventType::Normal,
            ),
        )
        .await;
        info!(vm = %name, from = %mark.from, to = cluster, "evacuation finished");
        return Ok(());
    }
    match controller_api::EvacuationStep::parse(&mark.step) {
        Some(controller_api::EvacuationStep::Stopping) => {
            if vm.status.phase().kind() == VmPhaseKind::Running
                || vm.status.phase().kind() == VmPhaseKind::Paused
            {
                // Level-triggered: the same dispatch every pass until the
                // phase moves, and idempotent at the cluster because what
                // changes down there is one object's desired state.
                return dispatch_create(store, registry, cluster, vm, false, book, traceparent)
                    .await;
            }
            if vm.status.phase().kind() != VmPhaseKind::Stopped {
                debug!(vm = %name, phase = vm.status.phase().kind().as_str(),
                       "not stopped yet; the evacuation waits");
                return Ok(());
            }
            store
                .mutate::<Vm, _>(&name, |v| {
                    v.spec.cluster_name = None;
                    v.status.evacuating = Some(controller_api::Evacuating {
                        from: mark.from.clone(),
                        step: controller_api::EvacuationStep::Moving.as_str().to_string(),
                        since: mark.since,
                    });
                })
                .await?;
            info!(vm = %name, cluster, "stopped for evacuation; letting the binding go");
            Ok(())
        }
        // Bound to the cluster it was leaving while the mark says the binding
        // had fallen: the scheduler chose the same cluster again, which it
        // only can if nothing else could take the VM. Giving the move up is
        // honest; looping is not.
        Some(controller_api::EvacuationStep::Moving) => {
            store
                .mutate::<Vm, _>(&name, |v| v.status.evacuating = None)
                .await?;
            warn!(vm = %name, cluster, "evacuation came back to the same cluster; giving it up");
            Ok(())
        }
        None => {
            warn!(vm = %name, step = %mark.step, "unknown evacuation step; leaving the vm alone");
            Ok(())
        }
    }
}

/// Hand the VM to its cluster. Create is idempotent by uid down there, so this
/// is equally the first handover, the repair after a cluster lost the object,
/// and the way a changed runStrategy reaches the tier that can act on it.
#[allow(clippy::too_many_arguments)]
pub(super) async fn dispatch_create(
    store: &EtcdStore,
    registry: &SessionRegistry,
    cluster: &str,
    vm: &Vm,
    missing: bool,
    book: &OnceCell<AddressBook>,
    traceparent: &str,
) -> anyhow::Result<()> {
    let name = vm.metadata.name.clone();
    // The first dispatch of the pass pays for the two listings; every other
    // one reads the same book. See `AddressBook`.
    let addresses = book
        .get_or_try_init(|| AddressBook::read(store))
        .await?
        .for_vm(vm);
    let op = cloud_command::Op::Create(proto::CreateVm {
        name: name.clone(),
        uid: vm.metadata.uid.clone(),
        spec_json: build_spec_json(vm)?,
        vni: tenant_vni(store, vm.spec.tenant.as_deref()).await?,
        floating_ips: addresses.floating_ips,
        routed_subnets: addresses.routed_subnets,
    });

    let dispatched = vm.metadata.generation;
    match registry.send_command(cluster, traceparent, op).await {
        Ok(Ack::Acked(_)) => {
            store
                .mutate::<Vm, _>(&name, |v| {
                    // The generation this command carried down. Everything
                    // below is a guess about what the cluster will do with
                    // it; this is the one thing we KNOW, because we sent it.
                    v.status.observed_generation = v.status.observed_generation.max(dispatched);
                    // Stamped whatever the phase does: this is the last moment
                    // we know something happened to this VM downstairs, and
                    // the teardown gate below uses it as its floor. Without
                    // it, a status built before the create landed could pass
                    // for proof that the VM was never there.
                    v.status.observed_at = Some(Utc::now());
                    v.status.cluster_name = v.spec.cluster_name.clone();
                    // Anticipation never overwrites observation. Dispatching
                    // is a guess about the future; only a VM nobody has
                    // reported on yet may be moved by one.
                    if v.status.phase().kind() == VmPhaseKind::Pending {
                        #[allow(deprecated)]
                        v.status.assign(VmPhase::new(
                            VmPhaseKind::Provisioning,
                            controller_api::VmReason::Dispatched,
                            None,
                            Utc::now(),
                        ));
                    }
                })
                .await?;
            stamp_addresses(store, &addresses.carried).await;
            info!(cluster, missing, "create dispatched");
        }
        Ok(Ack::Rejected(refusal)) => {
            let msg = refusal.message;
            warn!(cluster, error = %msg, "cluster refused the create");
            store
                .mutate::<Vm, _>(&name, |v| {
                    #[allow(deprecated)]
                    v.status.assign(VmPhase::new(
                        VmPhaseKind::Failed,
                        controller_api::VmReason::Refused,
                        Some(msg.clone()),
                        Utc::now(),
                    ));
                    v.status.cluster_name = v.spec.cluster_name.clone();
                    v.status.observed_at = Some(Utc::now());
                })
                .await?;
        }
        // A broken session is a fact about the session. Nothing is written,
        // and the next pass derives the same decision from the same state.
        Err(e) => warn!(
            cluster,
            error = format!("{e:#}"),
            "create could not be delivered"
        ),
    }
    Ok(())
}

/// Finalizer flow, one tier up. The cluster is told to tear the VM down and
/// acks that it recorded the order — which is not the same as having carried
/// it out. The proof is the VM leaving the cluster's status, and only then may
/// the cloud object go: an object deleted early is a VM nobody is left to
/// delete.
pub(super) async fn teardown(
    store: &EtcdStore,
    registry: &SessionRegistry,
    vm: &Vm,
    traceparent: &str,
) -> anyhow::Result<()> {
    let name = vm.metadata.name.clone();
    let uid = vm.metadata.uid.clone();

    let Some(cluster) = vm.spec.cluster_name.clone() else {
        // Never placed anywhere: there is nothing to tear down.
        store.delete::<Vm>(&name).await?;
        info!("vm deleted (never placed)");
        return Ok(());
    };

    let report = registry.report(&cluster);
    // While the cluster still names the VM — and while it has told us nothing
    // current, which for this decision is the same thing — the teardown is
    // what there is to do.
    if report.as_ref().is_none_or(|r| r.uids.contains(&uid)) {
        match registry
            .send_command(
                &cluster,
                traceparent,
                cloud_command::Op::Destroy(proto::DestroyVm {
                    name: name.clone(),
                    uid,
                }),
            )
            .await
        {
            Ok(Ack::Acked(_)) => {
                store
                    .mutate::<Vm, _>(&name, |v| {
                        v.status.observed_at = Some(Utc::now());
                    })
                    .await?;
                info!(cluster = %cluster, "destroy dispatched");
            }
            Ok(Ack::Rejected(refusal)) => {
                let msg = refusal.message;
                warn!(cluster = %cluster, error = %msg, "cluster refused the destroy")
            }
            Err(e) => {
                warn!(cluster = %cluster, error = format!("{e:#}"),
                      "destroy could not be delivered")
            }
        }
        return Ok(());
    }

    let report = report.expect("a missing report keeps us in the branch above");
    if !status_is_current(vm, report.at) {
        debug!(cluster = %cluster, "waiting for a status younger than what we already know");
        return Ok(());
    }
    store.delete::<Vm>(&name).await?;
    info!(cluster = %cluster, "vm deleted");
    Ok(())
}

/// The tenant's network, looked up where the Tenant object lives.
///
/// The cloud resolves it and the CLUSTER writes it into the NIC entries —
/// that split is the design's, and it is what keeps the cluster from needing
/// a copy of the tenant directory to schedule a VM. A tenant that has no VNI
/// (one created before overlays existed) resolves to nothing and its VMs go
/// on landing on the default bridge, which is what they did yesterday.
///
/// A tenant that has been DELETED out from under a running VM is a warning
/// and not a failed dispatch: refusing to hand the VM down would leave it
/// stuck at the cloud with no way back, and the honest degradation is the
/// same one an old tenant gets.
pub(super) async fn tenant_vni(
    store: &EtcdStore,
    tenant: Option<&str>,
) -> anyhow::Result<Option<u32>> {
    let Some(tenant) = tenant.filter(|t| !t.is_empty()) else {
        return Ok(None);
    };
    match store.get::<controller_api::Tenant>(tenant).await {
        Ok(t) => Ok(t.spec.vni),
        Err(StoreError::NotFound(_)) => {
            warn!(
                tenant,
                "the tenant this vm belongs to is gone; dispatching without an overlay"
            );
            Ok(None)
        }
        Err(e) => Err(e.into()),
    }
}

/// What travels down: the cluster tier's VmSpec and nothing else. The cloud's
/// own binding stays out of it — which cluster a VM sits on is a fact about
/// this store, and shipping a copy downstairs only invites the two to
/// disagree about it.
///
/// The tenant DOES travel, and is not a binding: it is what the VM is, the
/// tier below records it so `meister vm ls` can say whose a VM is, and the
/// VNI that comes with it on the same message is what the cluster injects.
pub(crate) fn build_spec_json(vm: &Vm) -> anyhow::Result<String> {
    if !vm.spec.vm.is_object() {
        bail!("spec.vm must be a JSON object");
    }
    let strategy = match vm.spec.run_strategy {
        RunStrategy::Running => "Running",
        RunStrategy::Stopped => "Stopped",
        RunStrategy::Paused => "Paused",
    };
    // The one moment this tier sends down something other than what the spec
    // says, and it is not a lie about the spec: what travels here is the
    // cloud's DISPATCH, and while a cluster drain has this VM in its Stopping
    // step the cloud's instruction to that cluster really is "stop it". The
    // owner's `runStrategy` up here never changes — which is what makes the
    // guest come back Running by itself, on the new cluster, without anybody
    // having to remember to restore anything.
    //
    // If this controller dies in the middle, the mark is on the object and
    // the next pass sends the same thing again; if the MARK is lost the next
    // dispatch carries the real strategy and the VM starts where it stands,
    // which is the safe direction to fail in.
    let strategy = match &vm.status.evacuating {
        Some(mark)
            if controller_api::EvacuationStep::parse(&mark.step)
                == Some(controller_api::EvacuationStep::Stopping) =>
        {
            "Stopped"
        }
        _ => strategy,
    };
    Ok(serde_json::to_string(&serde_json::json!({
        "runStrategy": strategy,
        // What a DRAIN one tier down may do to this vm, which is the owner's
        // answer and travels because the tier that acts on it is the one
        // below. Without it the cluster's drain table read `never` for every
        // cloud-managed vm — the safe direction, and still wrong: a `node
        // drain` would have listed a vm whose owner had explicitly agreed to
        // a reboot as one that will not move. Found in the position-2 e2e.
        //
        // The cluster's own copy is not editable by hand (a cloud-owned
        // object answers 409 there), so this is the only road it has.
        "evacuation": vm.spec.evacuation.as_str(),
        "tenant": vm.spec.tenant,
        "vm": vm.spec.vm,
    }))?)
}
