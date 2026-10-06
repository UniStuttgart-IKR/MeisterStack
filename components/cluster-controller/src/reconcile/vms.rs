// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! The VM half of the pass: reconcile one VM, dispatch it to a node, hot-plug
//! its drift, evacuate it, tear it down. Moved out of `reconcile.rs`
//! unchanged.

use super::*;

/// Detect expired node evidence for phases that claim a live guest, or legacy
/// Unknown status without a silence fact. Silence means Unknown, not Failed:
/// an agent can disappear while its VMMs continue running, and failure recovery
/// must not restart a guest whose state is unobserved. The caller supplies time.
pub(crate) fn silent(vm: &Vm, last_heartbeat: Option<DateTime<Utc>>, now: DateTime<Utc>) -> bool {
    vm.spec.node_name.is_some()
        && (claims_a_guest(vm.status.phase().kind()) || unexplained_unknown(&vm.status))
        && heartbeat_expired(last_heartbeat, now)
}

/// Recognize legacy Unknown status without a silence fact so the watchdog can
/// populate derivation evidence once, without rewriting it on every pass.
fn unexplained_unknown(status: &controller_api::VmStatus) -> bool {
    status.phase().kind() == VmPhaseKind::Unknown && status.silence.is_none()
}

/// The phases that are a statement about a guest that is supposed to exist
/// right now, and therefore the only ones a silence can make untrue.
fn claims_a_guest(phase: VmPhaseKind) -> bool {
    matches!(
        phase,
        VmPhaseKind::Running | VmPhaseKind::Paused | VmPhaseKind::Provisioning
    )
}

/// Mark affected VMs Unknown whenever their node evidence expires.
/// Any replica may apply this idempotently through CAS: gating on session
/// ownership would exclude precisely the disconnected nodes that need it.
pub(super) async fn expire_vm_reports(
    store: &EtcdStore,
    vms: &[Vm],
    node: &str,
    last_heartbeat: Option<DateTime<Utc>>,
    now: DateTime<Utc>,
) {
    for vm in vms
        .iter()
        .filter(|v| v.spec.node_name.as_deref() == Some(node))
    {
        if !silent(vm, last_heartbeat, now) {
            continue;
        }
        let name = vm.metadata.name.clone();
        let was = vm.status.phase().kind();
        let message = format!("{node} stopped answering");
        match store
            .mutate_if::<Vm, _>(&name, &vm.metadata.uid, |v| {
                // Re-read inside the mutate: a report may have landed between
                // the listing and here, and taking a phase away from a node
                // that has just spoken is the one way this can do harm.
                //
                // The FACT, and `settle` makes `Unknown { Silent }` out of it
                // — including the sentence, so that both tiers word a silence
                // the same way. See `VmSilence`.
                if claims_a_guest(v.status.phase().kind()) || unexplained_unknown(&v.status) {
                    v.status.silence = Some(controller_api::VmSilence {
                        holder: format!("node {node}"),
                        last_heard: last_heartbeat,
                        since: v.status.silence.as_ref().map(|s| s.since).unwrap_or(now),
                    });
                }
            })
            .await
        {
            Ok(_) => {
                warn!(vm = %name, node, was = was.as_str(), %message,
                      "the node has gone silent; the phase is no longer known");
                events::record(
                    store,
                    warning(vm, events::reason::PHASE_CHANGED, message.clone()),
                )
                .await;
            }
            Err(e) => warn!(vm = %name, node, error = format!("{e:#}"),
                            "writing the unknown phase failed"),
        }
    }
}

/// The shared drift table says what has to happen; this is the only part that
/// is the agent protocol's business, and so the only part that stays here.
pub(super) fn lifecycle_op(action: Lifecycle, uid: &str) -> command::Op {
    let id = uid.to_string();
    match action {
        Lifecycle::Start => command::Op::Start(proto::StartInstance { id }),
        // No grace override: how long a guest gets to power off is the node's
        // policy (stop_grace_secs), not the controller's.
        Lifecycle::Stop => command::Op::Stop(proto::StopInstance {
            id,
            grace_secs: None,
        }),
        Lifecycle::Pause => command::Op::Pause(proto::PauseInstance { id }),
        Lifecycle::Resume => command::Op::Resume(proto::ResumeInstance { id }),
    }
}

/// The user-data a VM's `cloud_init.user_data_from` reference resolves to.
///
/// Three answers and not two, because a missing secret is a WAIT and not a
/// failure: it is the same shape a volume that is not `Ready` yet has, and
/// for the same reason — at the cloud the reference travels down in the
/// CreateVm and the object itself is mirrored separately, so the two arrive
/// in whatever order the session delivers them.
pub(crate) enum Seed {
    /// The spec names no secret. Every VM written before this existed.
    None,
    /// The plaintext, opened here and handed to the node over the mTLS
    /// session — exactly as `user_data` has always travelled.
    Ready(String),
    /// Why not yet. Goes on the object as a Pending reason.
    NotReady(String),
}

/// Open the secret a VM's cloud-init names, here and nowhere else.
///
/// HERE is the point of it. The value is decrypted at the last tier that has
/// a store, handed to the node over the session that is already mutually
/// authenticated, and written by the node into a seed image the guest reads.
/// It is never in the cloud's `CreateVm`, never in this tier's `Vm` object,
/// and never in a log: the only two places the plaintext exists are this
/// function's stack and the seed on the node that runs the VM.
pub(crate) async fn seed_for(
    store: &EtcdStore,
    kek: Option<&controller_api::secrets::Kek>,
    vm: &Vm,
) -> anyhow::Result<Seed> {
    let Some((name, key)) = vm.spec.user_data_from() else {
        return Ok(Seed::None);
    };
    let Some(kek) = kek else {
        // Configured with no key and asked to open something. Not a wait —
        // no pass will fix it — but it is not a refusal either: the object
        // was accepted by an edge that had a key, or mirrored from a tier
        // that has one. The sentence names the file.
        return Ok(Seed::NotReady(
            "this cluster-controller has no secrets_key configured and cannot open a secret"
                .to_string(),
        ));
    };
    let secret: controller_api::Secret = match store.get(&name).await {
        Ok(secret) => secret,
        Err(StoreError::NotFound(_)) => {
            return Ok(Seed::NotReady(format!(
                "secret {name} has not arrived here yet"
            )));
        }
        Err(e) => return Err(e.into()),
    };
    // A secret whose tenant is not the VM's is not this VM's to read. The
    // cloud's edge checks it too; this is the half that cannot be bypassed,
    // because a mirrored object arrives without a request behind it.
    if !controller_api::same_tenancy(&secret.spec.tenant, vm.spec.tenant.as_deref()) {
        return Ok(Seed::NotReady(format!(
            "secret {name} belongs to another tenant"
        )));
    }
    let Some(sealed) = secret.spec.data.get(&key) else {
        return Ok(Seed::NotReady(format!(
            "secret {name} has no key {key:?}; it has [{}]",
            secret
                .spec
                .data
                .keys()
                .cloned()
                .collect::<Vec<_>>()
                .join(", ")
        )));
    };
    let aad = controller_api::secrets::Aad::of(controller_api::Secret::RESOURCE, &name, &key);
    // An error here is tampering or the wrong key, and both are structural.
    // It goes on the object as a wait anyway: a Failed VM would be a VM
    // somebody has to delete and recreate after fixing a key file.
    match kek.open(&aad, sealed) {
        Ok(plaintext) => Ok(Seed::Ready(plaintext)),
        Err(e) => Ok(Seed::NotReady(format!("secret {name}/{key}: {e:#}"))),
    }
}

/// The trace of the request this VM came from is on the object, because there
/// is no call stack from that request to here. The span is built and given
/// its parent BEFORE it starts — see `telemetry::in_trace`; attaching from
/// inside the body is too late and silently loses the trace.
///
/// `vm` is what a person calls it, `vm_id` is what the agent knows it as —
/// the uid is the only identity that survives the hop down.
pub(super) async fn reconcile_vm(p: &Pass<'_>, vm: Vm) -> anyhow::Result<()> {
    let context = birth_trace(&vm).unwrap_or_else(telemetry::TraceParent::root);
    let span = tracing::info_span!(
        "reconcile_vm",
        vm = %vm.metadata.name,
        vm_id = %vm.metadata.uid,
        trace_id = %context.trace_id_hex()
    );
    telemetry::in_trace(span, &context, reconcile_vm_traced(p, vm, context)).await
}

/// Continue the creation trace only while Pending or Provisioning.
/// Later passes start independent traces; the origin annotation remains stored.
pub(super) fn birth_trace(vm: &Vm) -> Option<telemetry::TraceParent> {
    if !matches!(
        vm.status.phase().kind(),
        VmPhaseKind::Pending | VmPhaseKind::Provisioning
    ) {
        return None;
    }
    telemetry::TraceParent::parse(vm.metadata.traceparent().unwrap_or_default())
}

/// Reconcile in dependency order: ownership, teardown, placement, create,
/// lifecycle drift, then requeue. No mutation precedes the ownership gate.
/// Teardown excludes new placement, and a newly written binding ends this pass
/// so subsequent work reads the committed node on the next one.
pub(super) async fn reconcile_vm_traced(
    p: &Pass<'_>,
    vm: Vm,
    context: telemetry::TraceParent,
) -> anyhow::Result<()> {
    // Every command this pass sends rides on it, so `POST /vms` and the
    // driver spawn three hops down land in one trace.
    let outgoing = telemetry::outgoing(&context).to_string();

    // Ownership before anything else, teardown included: a bound VM is the
    // business of the replica its node talks to, and of no other. Not an
    // error and not a warning — the right replica is doing this right now.
    if !may_reconcile(&vm, p.sessions) {
        debug!(node = ?vm.spec.node_name, "vm belongs to another replica's session, skipping");
        return Ok(());
    }
    if vm.is_deleting() {
        return tear_down(p, &vm, &outgoing).await;
    }
    let Some(node) = vm.spec.node_name.clone() else {
        // The binding is gone. If a node still has this VM, that node has to
        // be told first — placing it again while the old one still holds it
        // would be two nodes for one VM, and under a shared pool two VMMs on
        // one file.
        if let Some(old) = vm.status.node_name.clone() {
            return unbind(p, &vm, &old, &outgoing).await;
        }
        return place(p, vm).await;
    };
    if vm.status.phase().kind() == VmPhaseKind::Pending {
        // The claim before the telling, never after. A node that has the disk
        // open while the object says nobody holds it is exactly the window
        // `Release::HeldBy` reads, and it is the window in which a delete
        // takes somebody's data.
        hold_volumes(p, &vm, &node).await?;
        dispatch_create(p, &vm, &node, &outgoing).await?;
    } else if let Some(drift) = volume_drift(&vm) {
        return hot_plug(p, &vm, &node, drift, &outgoing).await;
    }
    // The one place anything is allowed to contradict `runStrategy`, and it
    // has to come BEFORE the lifecycle: a VM being moved by restart is meant
    // to be Running and is deliberately not running right now, and the drift
    // table would read that as "start it" and put it back on the machine
    // somebody is emptying.
    if vm.status.evacuating.is_some() {
        return evacuate(p, &vm, &node, &outgoing).await;
    }
    if let Some(action) = lifecycle_command(vm.spec.run_strategy, vm.status.phase().kind()) {
        send_lifecycle(p, &vm, &node, action, &outgoing).await?;
    }
    heal_if_failed(p, &vm, &node, &outgoing).await
}

/// Advance durable move-by-restart evacuation without changing owner intent.
/// Stopping requests shutdown, then clears the binding once the phase permits it.
/// Ordinary unbind and placement handle the move. Moving clears the mark after
/// the VM binds to another node, allowing its original runStrategy to resume.
/// Persisting the step prevents restart from treating the intentional stop as drift.
pub(super) async fn evacuate(
    p: &Pass<'_>,
    vm: &Vm,
    node: &str,
    outgoing: &str,
) -> anyhow::Result<()> {
    let Some(mark) = vm.status.evacuating.clone() else {
        return Ok(());
    };
    let name = vm.metadata.name.clone();
    // Bound to a machine that is not the one it was leaving: the move
    // landed. This is also the arm a `Stopping` mark lands in if an operator
    // moved the VM by hand in the middle, which is the right answer to that
    // too — the VM is where the mark wanted it.
    if node != mark.from {
        p.store
            .mutate_if::<Vm, _>(&name, &vm.metadata.uid, |v| v.status.evacuating = None)
            .await?;
        events::record(
            p.store,
            normal(
                vm,
                events::reason::SCHEDULED,
                format!("moved off {} by restart; now on {node}", mark.from),
            ),
        )
        .await;
        info!(vm = %name, from = %mark.from, to = node, "evacuation finished");
        return Ok(());
    }
    match controller_api::EvacuationStep::parse(&mark.step) {
        Some(controller_api::EvacuationStep::Stopping) => {
            if vm.status.phase().kind() == VmPhaseKind::Running
                || vm.status.phase().kind() == VmPhaseKind::Paused
            {
                // Level-triggered: the same Stop until the phase moves,
                // idempotent at the node because the record's desired state
                // is what changes. Once per `told::RETELL_AFTER`, not once
                // per pass. (IKR-B74)
                return send_lifecycle(p, vm, node, Lifecycle::Stop, outgoing).await;
            }
            if vm.status.phase().kind() != VmPhaseKind::Stopped {
                // Provisioning, Pending, Failed, Quarantined: not something
                // to stop and not something to move. Waited on rather than
                // forced — a Failed VM has its own requeue curve and a
                // Quarantined one is deliberately nobody's.
                debug!(vm = %name, phase = vm.status.phase().kind().as_str(),
                       "not stopped yet; the evacuation waits");
                return Ok(());
            }
            // Off. One write does the rest: the binding falls, and everything
            // that follows is the reschedule that already exists.
            p.store
                .mutate_if::<Vm, _>(&name, &vm.metadata.uid, |v| {
                    v.spec.node_name = None;
                    v.status.evacuating = Some(controller_api::Evacuating {
                        from: mark.from.clone(),
                        step: controller_api::EvacuationStep::Moving.as_str().to_string(),
                        since: mark.since,
                    });
                })
                .await?;
            info!(vm = %name, node, "stopped for evacuation; letting the binding go");
            Ok(())
        }
        // Still bound to the machine it is leaving while the mark says the
        // binding has already fallen — which happens for exactly one pass,
        // between `place` writing a binding and this pass reading it, and
        // means the scheduler chose the same node again. That is a legitimate
        // outcome (the node is cordoned, so it only happens if nothing else
        // could take the VM), and the honest answer is to give up the move
        // rather than loop: the drain will list it as having nowhere to go.
        Some(controller_api::EvacuationStep::Moving) => {
            p.store
                .mutate_if::<Vm, _>(&name, &vm.metadata.uid, |v| v.status.evacuating = None)
                .await?;
            warn!(vm = %name, node, "evacuation came back to the same node; giving it up");
            Ok(())
        }
        // A step this binary does not know. Refusing to guess is the only
        // safe answer — the alternative is a VM stopped by one version and
        // started by another.
        None => {
            warn!(vm = %name, step = %mark.step, "unknown evacuation step; leaving the vm alone");
            Ok(())
        }
    }
}

/// Destroy the old instance after binding release and await reported absence.
/// `status.nodeName` blocks replacement placement until `forget_unbound` clears it.
/// The node detaches referenced storage and deprovisions inline disks, so inline
/// data does not survive rescheduling. Volume claims await separate close evidence.
pub(super) async fn unbind(p: &Pass<'_>, vm: &Vm, old: &str, outgoing: &str) -> anyhow::Result<()> {
    let name = vm.metadata.name.clone();
    debug!(vm = %name, node = old, "the binding fell; telling the old node");
    p.registry
        .send_command(
            old,
            outgoing,
            command::Op::Destroy(proto::DestroyInstance {
                id: vm.metadata.uid.clone(),
            }),
        )
        .await?;
    // The claims go with the instance. The new placement takes them again
    // through `hold_volumes`, which is the same path a first create takes —
    // and a node-local volume is what will pull the VM back to this very
    // machine, hard, because that is where its bytes are.
    release_volumes(p, vm).await;
    Ok(())
}

/// Clear a binding after structural CannotServe refusal and temporarily exclude
/// that node. Ordinary boot failures retain their binding for requeue.
/// Expiring exclusions avoid repeatedly selecting the same unsuitable node while
/// allowing a repaired node to become eligible again.
pub(super) async fn unbind_refused(
    p: &Pass<'_>,
    vm: &Vm,
    node: &str,
    said: String,
) -> anyhow::Result<()> {
    let name = vm.metadata.name.clone();
    warn!(vm = %name, node, error = %said, "the node cannot serve this vm; placing it again");
    let until = Utc::now() + chrono::Duration::from_std(REFUSAL_TTL).expect("a valid duration");
    let refusal = controller_api::VmRefusal {
        node: node.to_string(),
        message: said.clone(),
        until,
    };
    p.store
        .mutate_if::<Vm, _>(&name, &vm.metadata.uid, |v| {
            v.spec.node_name = None;
            // The node refused to serve it at all, which is a statement about
            // the MACHINE — it is remembered in `refusedBy` for exactly that
            // reason, and the word says the same thing. This tier's own
            // conclusion out of a refusal, so it names nobody: what the node
            // said is that it cannot, not what the guest is doing.
            v.status.reported = Some(controller_api::VmReported::here(
                VmPhaseKind::Pending,
                controller_api::VmReason::Refused,
                Some(said.clone()),
                Utc::now(),
            ));
            // The binding is gone, so what the scheduler said about the last
            // one is answered.
            v.status.placement = None;
            v.status.refused_by.retain(|r| r.node != node);
            v.status.refused_by.push(refusal.clone());
        })
        .await?;
    events::record(
        p.store,
        warning(vm, events::reason::UNBOUND, format!("node {node}: {said}")),
    )
    .await;
    Ok(())
}

/// Lifetime of a per-VM CannotServe exclusion. Expiry permits retry after repair;
/// an unchanged incompatibility produces another refusal and renews the exclusion.
pub(super) const REFUSAL_TTL: std::time::Duration = std::time::Duration::from_secs(600);

/// Finalizer flow: tear down on the bound node (idempotent at the agent),
/// then the object really goes away.
pub(super) async fn tear_down(p: &Pass<'_>, vm: &Vm, outgoing: &str) -> anyhow::Result<()> {
    if let Some(node) = destroy_target(vm) {
        p.registry
            .send_command(
                node,
                outgoing,
                command::Op::Destroy(proto::DestroyInstance {
                    id: vm.metadata.uid.clone(),
                }),
            )
            .await?;
    }
    // The VM that was judged, under the judgement it was given: still deleting, and the Destroy
    // above went where the revision being deleted would send it. One recreated under the same
    // name since the listing is a new VM and is left alone (NL2-6); one rebound, or no longer
    // Pending or newly so, is judged again by the next pass (NL3-2).
    let judged = |v: &Vm| v.is_deleting() && destroy_target(v) == destroy_target(vm);
    if !deletion::finish_delete(p.store, vm, judged).await? {
        return Ok(());
    }
    info!("vm deleted");
    // Let go of what this VM was holding once this call has removed it, and not before: a
    // claim names the VM, not its uid, so a teardown that lost the name to a newer VM would
    // release the newer one's claims (NL3-1). A crash between the two is answered by
    // `note_claimant`, which finds no VM of this name holding the volume.
    //
    // The node has been told to tear down and has acked being told; whether
    // it has finished detaching is its own business and this tier cannot
    // wait for it, because the object is what would have carried the wait and
    // the object is gone. The gap that leaves is covered where it has to be:
    // the node refuses to deprovision a volume it still has open, so a delete
    // arriving in the window is answered and retried rather than obeyed.
    release_volumes(p, vm).await;
    Ok(())
}

/// The node a teardown tells to destroy the instance: the bound one, unless the VM is still
/// Pending, which the teardown takes as nothing started there to destroy.
fn destroy_target(vm: &Vm) -> Option<&str> {
    vm.spec
        .node_name
        .as_deref()
        .filter(|_| vm.status.phase().kind() != VmPhaseKind::Pending)
}

/// Compare desired referenced disks with node-reported attachments.
/// `observedGeneration` alone cannot prove that disks remain open after restart
/// or failed attachment. Legacy agents reporting no attachments cause repeated
/// idempotent create dispatches for VMs with references until upgraded.
pub(crate) fn volume_drift(vm: &Vm) -> Option<Drift> {
    // Only where a node has a record to diff against. A Pending VM is handled
    // by the create path above; a Failed one is on the requeue curve, which
    // re-sends the current spec anyway and does it with a backoff — plugging
    // a disk into a VM that will not boot would be a command per pass with
    // nothing to receive it.
    if !matches!(
        vm.status.phase().kind(),
        VmPhaseKind::Running | VmPhaseKind::Stopped
    ) {
        return None;
    }
    let wanted = vm.spec.referenced_volumes();
    if wanted.is_empty() && vm.status.volumes.is_empty() {
        return None;
    }
    let held: Vec<&str> = vm
        .status
        .volumes
        .iter()
        .filter(|v| v.attached)
        .map(|v| v.name.as_str())
        .collect();
    let attach: Vec<String> = wanted
        .iter()
        .filter(|name| !held.contains(&name.as_str()))
        .cloned()
        .collect();
    let release: Vec<String> = held
        .iter()
        .filter(|name| !wanted.iter().any(|w| w == *name))
        .map(|name| (*name).to_string())
        .collect();
    (!attach.is_empty() || !release.is_empty()).then_some(Drift { attach, release })
}

/// The difference between a VM's spec and the disks its node has open.
///
/// `pub(crate)`, alongside `volume_drift` — see that function's note.
pub(crate) struct Drift {
    /// Referenced volumes the spec names that the node does not report.
    pub(crate) attach: Vec<String>,
    /// Volumes the node reports that the spec no longer names.
    pub(crate) release: Vec<String>,
}

/// Claim newly referenced volumes before resending CreateInstance for hot-plug.
/// Claims must precede opening disks so deletion cannot see an unowned open disk.
/// Release follows separate close evidence. Attachment reports, not this ACK,
/// advance `observedGeneration` for disk changes.
pub(super) async fn hot_plug(
    p: &Pass<'_>,
    vm: &Vm,
    node: &str,
    drift: Drift,
    outgoing: &str,
) -> anyhow::Result<()> {
    // The disks that are arriving have to be Ready and this VM's to take,
    // exactly as they do at create. Not ready is a WAIT and not a refusal —
    // the same sentence a Pending VM gets, said about a VM that is already
    // running with its other disks.
    match volume_bindings(p.store, vm).await? {
        Bindings::Ready(bindings) => {
            if let Some(elsewhere) = bindings
                .iter()
                .find(|b| b.pins_elsewhere(node))
                .and_then(|b| b.node.as_ref().map(|n| (b.volume.clone(), n.clone())))
            {
                // A node-local volume on another machine. Refused at the API
                // edge, so reaching it means the volume moved between the
                // request and this pass; said again here because a wrong
                // answer would be a VM told to open a path that is not on it.
                let (volume, on) = elsewhere;
                let reason =
                    format!("volume {volume} lives on node {on}; this vm runs on node {node}");
                p.pending.note(PendingReason::VolumeNotReady);
                return note_vm_pending(p, vm, PendingReason::VolumeNotReady, reason).await;
            }
        }
        Bindings::NotReady(reason) => {
            p.pending.note(PendingReason::VolumeNotReady);
            return note_vm_pending(p, vm, PendingReason::VolumeNotReady, reason).await;
        }
    }

    info!(attach = ?drift.attach, release = ?drift.release, "the vm's volumes drifted");
    hold_volumes(p, vm, node).await?;
    dispatch_create(p, vm, node, outgoing).await?;
    // Only the ones the spec dropped, and only after the node has been told.
    // `release_volumes` clears every claim this VM holds, which is right at
    // teardown and wrong here — the disks it keeps are still its.
    release_named_volumes(p, vm, &drift.release).await;
    Ok(())
}

/// Point a volume record at the VM's chosen node and mark it awaiting reopen.
/// Keep that explicit destination: clearing it would let independent volume
/// placement choose another node and repeatedly undo the VM's placement.
pub(super) fn follow_vm(v: &mut Volume, vm: &str, node: &str) {
    v.status.node = Some(node.to_string());
    v.status.reported = Some(controller_api::VolumeReported::here(
        VolumePhaseKind::Pending,
        controller_api::VolumeReason::Following,
        Some(format!("following {vm} to {node}")),
        Utc::now(),
    ));
}

/// A volume somebody else took in the meantime stops the dispatch: the create
/// edge already refused that shape, so reaching it means the race was lost
/// between the two, and losing it quietly would give two VMs one disk.
pub(super) async fn hold_volumes(p: &Pass<'_>, vm: &Vm, node: &str) -> anyhow::Result<()> {
    // Asked once for the whole VM rather than once per disk: the answer is a
    // property of the VM, and a listing per volume would ask etcd the same
    // question three times for a three-disk guest.
    let migrating = crate::migration::migration_in_flight(p.store, vm).await?;
    for name in vm.spec.referenced_volumes() {
        let mut volume: Volume = p.store.get(&name).await?;
        // Whose disk it is before anything moves it: both re-points below
        // write the record's home, and another VM's record is not this VM's
        // to move, whatever their names. (IKR-B81)
        if !may_carry(&volume.status, vm) {
            let holder = volume.status.attached_to.clone().unwrap_or_default();
            return wait_for_holder(p, vm, &name, &holder).await;
        }
        // The node this vm is on already HAS the disk open — which today
        // happens exactly one way: a live migration put it there, the record
        // still calls the source home, and the source is on its way out.
        // Re-point the home and skip the release-and-remake below; the bytes
        // are already open under the guest, and taking the volume through
        // `Pending` to say so would be a red phase describing nothing.
        if volume.status.node.as_deref().is_some_and(|n| n != node)
            && volume.status.open_on.iter().any(|n| n == node)
        {
            let from = volume.status.node.clone().unwrap_or_default();
            volume =
                carry_record(p, vm, &volume, |v| v.status.node = Some(node.to_string())).await?;
            info!(volume = %name, from = %from, to = node,
                  "the vm's node already has the volume open; the record moves with it");
        }
        // For reachable shared storage, move the record to the VM's destination so
        // the agent reopens the existing UID-derived backend. Preserve that explicit
        // node to prevent volume placement from selecting elsewhere. Node-local bytes
        // cannot follow the VM through this path.
        if volume.status.node.as_deref().is_some_and(|n| n != node) {
            let pool: Option<StoragePool> = match p.store.get(&volume.spec.pool).await {
                Ok(pool) => Some(pool),
                Err(StoreError::NotFound(_)) => None,
                Err(e) => return Err(e.into()),
            };
            let travels = matches!(
                pool.and_then(|p| p.status.locality),
                Some(Locality::Shared) | Some(Locality::Networked)
            );
            if travels {
                let from = volume.status.node.clone().unwrap_or_default();
                carry_record(p, vm, &volume, |v| follow_vm(v, &vm.metadata.name, node)).await?;
                info!(volume = %name, from = %from, to = node,
                      "the record follows the vm; the bytes stay where they are");
                anyhow::bail!("volume {name} is being re-opened on {node}");
            }
        }
        // Wait for volume readiness at the bound node before VM dispatch.
        // A rebound VM bypasses initial placement checks and may arrive before its
        // volume record has been opened there.
        if volume.status.phase().kind() != VolumePhaseKind::Ready {
            anyhow::bail!(
                "volume {name} is {} on {node}; the vm waits for it",
                volume.status.phase().kind().as_str()
            );
        }
        match volume.status.attached_to.as_deref() {
            // This object's claim, by uid: a VM made again under the name of
            // the one that holds the disk is not that VM, and a claim from
            // before claims carried a uid is not adopted by a name either —
            // the claimant pass binds it or lets it fall. (IKR-B81)
            Some(_) if volume.status.claimed_by(&vm.metadata.uid) => {
                // Held by us already, and nothing to write: `openOn` is the
                // node's own answer since D4 and arrives with its next report
                // (`VolumeStateReport.open`). This pass used to put the node
                // in as the create went out, which was a second writer of the
                // set and an anticipation besides — the disk is open when the
                // machine has opened it.
                continue;
            }
            Some(holder) => return wait_for_holder(p, vm, &name, holder).await,
            None => {}
        }
        // The one exception to `AccessMode`, enforced where the second entry
        // would be made rather than described in a doc comment somewhere.
        // Another machine having this disk open is a conflict — one consumer
        // means one machine — UNLESS this vm is in the middle of a live
        // migration, which is the one operation that needs both ends holding
        // the same bytes at the same time. Stale entries do not wedge a vm
        // here: `openOn` is re-stated from every node's own report, so a node
        // that no longer has the disk drops out of the list by itself.
        if let Some(other) = volume.status.open_elsewhere(node)
            && !migrating
        {
            anyhow::bail!(
                "volume {name} is still open on node {other}; only a live migration \
                 may have it open on two"
            );
        }
        let mut held = volume;
        held.status.attached_to = Some(vm.metadata.name.clone());
        held.status.attached_uid = Some(vm.metadata.uid.clone());
        // A fresh claim: whatever a previous holder's absence established is
        // about that holder and not this one.
        held.status.claimant_gone = false;
        match p.store.update(&held).await {
            Ok(_) => info!(volume = %name, "volume attached"),
            // Somebody wrote the volume between the read and the write. Not
            // this pass's to force: the next one reads it again, and if the
            // other writer took it the dispatch stops there.
            Err(StoreError::Conflict(_)) => {
                anyhow::bail!("volume {name} changed while it was being attached")
            }
            Err(e) => return Err(e.into()),
        }
    }
    Ok(())
}

/// Move `volume`'s record as `re_point` says, on the record this pass read and
/// only while `vm` may still carry it: a claim taken between the read and the
/// write stops the move. (IKR-B81)
async fn carry_record(
    p: &Pass<'_>,
    vm: &Vm,
    volume: &Volume,
    re_point: impl Fn(&mut Volume),
) -> anyhow::Result<Volume> {
    let name = &volume.metadata.name;
    let mut carried = false;
    let moved = p
        .store
        .mutate_if::<Volume, _>(name, &volume.metadata.uid, |v| {
            carried = may_carry(&v.status, vm);
            if carried {
                re_point(v);
            }
        })
        .await?;
    if !carried {
        anyhow::bail!("volume {name} was claimed while its record was being moved");
    }
    Ok(moved)
}

/// Whether `vm` may move this volume's record to its node: nobody holds the
/// volume, or the claim is this VM object's by uid (`claimed_by`). A claim
/// from before claims carried a uid is nobody's to carry: by its name alone a
/// VM made again under it would carry the record of a claimant already found
/// gone. The claimant pass binds such a claim to its VM or lets it fall, and
/// the wait lasts until then. (IKR-B81)
fn may_carry(status: &controller_api::VolumeStatus, vm: &Vm) -> bool {
    status.attached_to.is_none() || status.claimed_by(&vm.metadata.uid)
}

/// The claim is somebody else's, and since D4 it may still be standing after
/// that somebody has gone: it falls when no Vm object carries it AND no
/// machine reports the bytes open (`volume_claim_holds`). So the wait gets a
/// word of its own — nothing here will ever take a disk off its holder, and an
/// operator has to be able to see who has it. Always an error: the dispatch
/// stops here.
async fn wait_for_holder(p: &Pass<'_>, vm: &Vm, volume: &str, holder: &str) -> anyhow::Result<()> {
    note_vm_held(p, vm, volume, holder).await?;
    anyhow::bail!("volume {volume} is held by {holder}")
}

/// Record VolumeHeld separately from VolumeNotReady: another VM's claim must
/// be released, not displaced by this request. Close evidence can lag teardown.
async fn note_vm_held(p: &Pass<'_>, vm: &Vm, volume: &str, holder: &str) -> anyhow::Result<()> {
    let said = format!("volume {volume} is still held by {holder}");
    if vm
        .status
        .placement
        .as_ref()
        .is_some_and(|pl| pl.message == said)
    {
        return Ok(());
    }
    p.store
        .mutate_if::<Vm, _>(&vm.metadata.name, &vm.metadata.uid, |v| {
            v.status.placement = Some(controller_api::VmPlacement {
                reason: controller_api::VmReason::VolumeHeld,
                message: said.clone(),
                at: Utc::now(),
            });
        })
        .await?;
    Ok(())
}

/// Let go of every volume this VM was holding.
///
/// Called when the VM is gone — which is the absence of its uid from the
/// node's status report, the same rule the object itself goes by. Only ever
/// clears a claim that names THIS VM: a volume some other VM has since taken
/// is not this teardown's to release.
pub(super) async fn release_volumes(p: &Pass<'_>, vm: &Vm) {
    release_named_volumes(p, vm, &vm.spec.referenced_volumes()).await
}

/// Let go of exactly these, and only where the claim is THIS VM object's
/// (`VolumeStatus::held_by`): a VM of the same name made since holds its own
/// claim, by its own uid. (IKR-B81)
///
/// The half `release_volumes` is now written in terms of. A teardown lets go
/// of everything the VM refers to; a detach lets go of the difference, and
/// handing it the same loop is what keeps the two from growing two answers to
/// "may I clear this claim".
pub(super) async fn release_named_volumes(p: &Pass<'_>, vm: &Vm, names: &[String]) {
    for name in names {
        let held = p
            .store
            .mutate::<Volume, _>(name, |v| {
                if v.status.held_by(&vm.metadata.name, &vm.metadata.uid) {
                    // Record claimant departure without releasing the claim yet. `settle`
                    // requires both this fact and empty `openOn` before freeing it. Destroy ACKs
                    // alone cannot prove handles closed. Rescheduling the same VM retains its claim.
                    v.status.claimant_gone = true;
                }
            })
            .await;
        match held {
            Ok(_) => debug!(volume = %name, "the claimant is going; the claim falls when the \
                                             bytes are nobody's"),
            // A volume that is already gone needs no release, and a store
            // that could not be written is retried by the next pass. Neither
            // is worth failing a teardown over — the object is the record and
            // the pass is level-triggered.
            Err(e) => debug!(volume = %name, error = %format!("{e:#}"),
                             "releasing the volume did nothing"),
        }
    }
}

/// A Pending VM on a node that has not been told about it yet: send the spec
/// and record what came back.
pub(super) async fn dispatch_create(
    p: &Pass<'_>,
    vm: &Vm,
    node: &str,
    outgoing: &str,
) -> anyhow::Result<()> {
    // The secret, opened one line before the spec is built and nowhere else.
    // A VM waiting for one is not dispatched at all — the same wait a volume
    // that is not Ready produces, said with its own reason.
    let seed = match seed_for(p.store, p.kek, vm).await? {
        Seed::None => None,
        Seed::Ready(plaintext) => Some(plaintext),
        Seed::NotReady(reason) => {
            p.pending.note(PendingReason::SecretNotReady);
            return note_vm_pending(p, vm, PendingReason::SecretNotReady, reason).await;
        }
    };
    let spec_json = build_spec_json(vm, &volume_uids(p.store, vm).await?, seed.as_deref())?;
    let outcome = p
        .registry
        .send_command(
            node,
            outgoing,
            command::Op::Create(proto::CreateInstance {
                id: vm.metadata.uid.clone(),
                spec: None,
                spec_json,
            }),
        )
        .await;
    // The node's own word for "I cannot serve this VM at all", which is a
    // different thing from a create that went wrong: no record was made, and
    // asking again here would fail in exactly the same way. So the binding
    // falls and the scheduler decides again — see `unbind_refused`.
    if let Err(e) = &outcome
        && e.downcast_ref::<controller_api::Refusal>()
            .is_some_and(|r| r.reason == controller_api::CANNOT_SERVE)
    {
        let said = e
            .downcast_ref::<controller_api::Refusal>()
            .map(|r| r.message.clone())
            .unwrap_or_else(|| format!("{e:#}"));
        return unbind_refused(p, vm, node, said).await;
    }
    // The payload of an ack is empty for every command that only changes
    // something, which is all of these; only the console fetch answers with
    // anything, and no reconcile pass sends one.
    let said = outcome.as_ref().err().map(|e| format!("{e:#}"));
    let dispatched = vm.metadata.generation;
    let settles_here = volume_drift(vm).is_none();
    p.store
        .mutate_if::<Vm, _>(&vm.metadata.name, &vm.metadata.uid, |v| {
            // Advance the acknowledged generation only when this dispatch settles it.
            // For changed attachments, `ingest_attachments` instead waits for the reported
            // disk set; command acknowledgement alone is insufficient evidence.
            if outcome.is_ok() && settles_here {
                v.status.observed_generation = v.status.observed_generation.max(dispatched);
            }
            // The agent acks the create and reports the booted VM over
            // the same session, so its first StatusReport can land before
            // this write. Dispatching is a guess about the future; a
            // status report is an observation of the present, and the
            // guess must not overwrite it.
            //
            // A REFUSAL is the other kind of thing — see `create_answer`.
            if let Some((phase, message)) = create_answer(said.clone(), v.status.phase().kind()) {
                // A refusal is the node's own word; a dispatch is this tier's
                // guess. `create_answer` has already decided which of the two
                // this is, and the reason follows from the phase it chose.
                // Either way it is written HERE — as this tier's conclusion —
                // because neither is a machine saying what a guest is doing,
                // and that is what keeps a dispatch from ever being `Running`.
                let reason = match phase {
                    VmPhaseKind::Failed => controller_api::VmReason::Refused,
                    _ => controller_api::VmReason::Dispatched,
                };
                v.status.reported = Some(controller_api::VmReported::here(
                    phase,
                    reason,
                    message,
                    Utc::now(),
                ));
                v.status.node_name = v.spec.node_name.clone();
                v.status.observed_at = Some(Utc::now());
            }
        })
        .await?;
    outcome?;
    info!("create dispatched");
    Ok(())
}

/// Apply a create ACK only before runtime evidence has advanced the phase.
/// A later status report must not be overwritten by an earlier acknowledgement.
/// Refusals can update other phases so recovery sees them, but never override
/// operator quarantine.
pub(crate) fn create_answer(
    refusal: Option<String>,
    current: VmPhaseKind,
) -> Option<(VmPhaseKind, Option<String>)> {
    match refusal {
        None if current == VmPhaseKind::Pending => Some((VmPhaseKind::Provisioning, None)),
        None => None,
        Some(_) if current == VmPhaseKind::Quarantined => None,
        Some(said) => Some((VmPhaseKind::Failed, Some(said))),
    }
}

/// Level-triggered lifecycle: spec.runStrategy is the intent, status.phase
/// the observation, and the difference between them is the command. The
/// ack writes nothing back — dispatching is a guess about the future, a
/// status report is the present, and anticipation never overwrites
/// observation. The next pass re-derives from what the node reported.
pub(super) async fn send_lifecycle(
    p: &Pass<'_>,
    vm: &Vm,
    node: &str,
    action: Lifecycle,
    outgoing: &str,
) -> anyhow::Result<()> {
    let uid = &vm.metadata.uid;
    let said = told::LifecycleSaid {
        node: node.to_string(),
        action,
        generation: vm.metadata.generation,
    };
    // The phase lags the command by a stop grace or a boot, and every write
    // to any VM runs a pass: said once per `told::RETELL_AFTER`, not once per
    // pass. (IKR-B74)
    if p.told.lifecycle_lately(uid, &said) {
        debug!(?action, "said lately; waiting for the phase to follow");
        // This generation's intent went to this node, so it is acted on;
        // closing it here also mends a close that failed after the send.
        return close_generation(p.store, vm).await;
    }
    info!(
        ?action,
        strategy = ?vm.spec.run_strategy,
        phase = ?vm.status.phase().kind(),
        "run strategy drifted, sending command"
    );
    p.registry
        .send_command(node, outgoing, lifecycle_op(action, uid))
        .await?;
    p.told.note_lifecycle(uid, said);
    close_generation(p.store, vm).await
}

/// The other half of "acted on this generation". A runStrategy change travels
/// as a lifecycle command and never as a new spec, so without this a stopped
/// VM would read `pending` forever — the one drift Position 2 deliberately
/// leaves possible on a VM.
///
/// Written only when it moves: a write that changes nothing is still a watch
/// event, and every watch event is another pass. On the uid the pass judged,
/// so a VM recreated under the name keeps its own generation.
async fn close_generation(store: &EtcdStore, vm: &Vm) -> anyhow::Result<()> {
    let dispatched = vm.metadata.generation;
    if vm.status.observed_generation >= dispatched {
        return Ok(());
    }
    store
        .mutate_if::<Vm, _>(&vm.metadata.name, &vm.metadata.uid, |v| {
            v.status.observed_generation = v.status.observed_generation.max(dispatched);
        })
        .await?;
    Ok(())
}

/// Failed is no longer anybody's last word (config `retry`, default
/// CrashLoopBackoff). The kick is a re-sent intent: the agent's
/// set_desired clears its own failure backoff and provisions afresh —
/// which also heals the backoff state an agent restart forgets. The
/// bookkeeping lives in status so a controller three seconds old kicks
/// exactly when one up for a week would. Quarantined stays untouched.
pub(super) async fn heal_if_failed(
    p: &Pass<'_>,
    vm: &Vm,
    node: &str,
    outgoing: &str,
) -> anyhow::Result<()> {
    let name = &vm.metadata.name;
    match requeue_decision(vm, p.requeue, Utc::now()) {
        Requeue::Not => {}
        Requeue::Reset => {
            p.store
                .mutate_if::<Vm, _>(name, &vm.metadata.uid, |v| {
                    v.status.requeue_attempts = 0;
                    v.status.last_requeue = None;
                })
                .await?;
        }
        // Arm, don't kick: the first delay is measured from first seeing
        // Failed, so the agent's own retry gets its window before ours.
        Requeue::Arm => {
            p.store
                .mutate_if::<Vm, _>(name, &vm.metadata.uid, |v| {
                    if v.status.last_requeue.is_none() {
                        v.status.last_requeue = Some(Utc::now());
                    }
                })
                .await?;
        }
        Requeue::Kick => kick(p, vm, node, outgoing).await?,
    }
    Ok(())
}

/// The kick itself: count the attempt, re-send the intent, and let the
/// agent's own report say the rest.
pub(super) async fn kick(p: &Pass<'_>, vm: &Vm, node: &str, outgoing: &str) -> anyhow::Result<()> {
    let name = &vm.metadata.name;
    let attempt = vm.status.requeue_attempts + 1;
    info!(attempt, node = %node, "requeueing failed vm");
    p.store
        .mutate_if::<Vm, _>(name, &vm.metadata.uid, |v| {
            v.status.requeue_attempts = attempt;
            v.status.last_requeue = Some(Utc::now());
        })
        .await?;
    // Create, not Start: a create the agent REJECTED left no record
    // behind, and a lifecycle command on a record-less VM is an
    // error. provision() is idempotent — an existing record only has
    // its desired re-asserted — so Create is the kick that reaches
    // both failure classes.
    let seed = match seed_for(p.store, p.kek, vm).await? {
        Seed::None => None,
        Seed::Ready(plaintext) => Some(plaintext),
        Seed::NotReady(reason) => {
            p.pending.note(PendingReason::SecretNotReady);
            return note_vm_pending(p, vm, PendingReason::SecretNotReady, reason).await;
        }
    };
    let spec_json = build_spec_json(vm, &volume_uids(p.store, vm).await?, seed.as_deref())?;
    let outcome = p
        .registry
        .send_command(
            node,
            outgoing,
            command::Op::Create(proto::CreateInstance {
                id: vm.metadata.uid.clone(),
                spec: None,
                spec_json,
            }),
        )
        .await;
    let dispatched = vm.metadata.generation;
    match outcome {
        Ok(_) => {
            // The agent took it this time; let its report say the rest.
            p.store
                .mutate_if::<Vm, _>(name, &vm.metadata.uid, |v| {
                    // A kick re-sends the spec, so it is a dispatch like any
                    // other and says so.
                    v.status.observed_generation = v.status.observed_generation.max(dispatched);
                    if v.status.phase().kind() == VmPhaseKind::Failed {
                        v.status.reported = Some(controller_api::VmReported::here(
                            VmPhaseKind::Provisioning,
                            controller_api::VmReason::Dispatched,
                            Some(format!("{node} was told again")),
                            Utc::now(),
                        ));
                    }
                })
                .await?;
        }
        // Warn, not debug: the kick is an action that failed, and
        // the backoff is what heals it. Bounded noise by construction
        // - the curve caps at one attempt every five minutes.
        Err(e) => {
            warn!(
                attempt,
                error = format!("{e:#}"),
                "requeue kick rejected again"
            )
        }
    }
    Ok(())
}

/// The agent's NewVmSpec JSON, with `desired` derived from runStrategy —
/// the same document the agent's own REST API accepts.
pub(crate) fn build_spec_json(
    vm: &Vm,
    refs: &VolumeUids,
    seed: Option<&str>,
) -> anyhow::Result<String> {
    let mut doc = vm.spec.vm.clone();
    let obj = doc
        .as_object_mut()
        .ok_or_else(|| anyhow::anyhow!("spec.vm must be a JSON object"))?;
    // A name is what people call a volume; a uid is which volume it is. The
    // node holds no directory and cannot resolve one, so the swap happens
    // here — the same rule `CreateInstance.id` follows for the VM itself.
    if let Some(volumes) = obj.get_mut("volumes").and_then(|v| v.as_array_mut()) {
        for entry in volumes.iter_mut() {
            let Some(entry) = entry.as_object_mut() else {
                continue;
            };
            let Some(name) = entry.get("volume").and_then(|v| v.as_str()) else {
                continue;
            };
            let uid = refs.get(name).ok_or_else(|| {
                // Every caller resolves the references before building the
                // document, so a name with no uid means the volume vanished
                // between the two reads. Refusing is right: a spec that
                // reached a node still naming a name would be a spec the node
                // has no way to act on.
                anyhow::anyhow!("volume {name} could not be resolved to a uid")
            })?;
            entry.insert("volume".to_string(), serde_json::Value::String(uid.clone()));
        }
    }
    // What the guest should call itself, from the object's own name. This
    // tier is where that is filled in because it is the last one that knows
    // it: a node holds a uid and nothing else, so a seed built down there
    // could only ever derive a uuid for a hostname. Only when the VM asked
    // for cloud-init at all, and only when nobody named one — a meta_data
    // written by hand outranks this and is left alone.
    if let Some(config) = obj
        .get_mut("cloud_init")
        .and_then(serde_json::Value::as_object_mut)
    {
        if !config.contains_key("local_hostname") {
            config.insert(
                "local_hostname".to_string(),
                serde_json::Value::String(vm.metadata.name.clone()),
            );
        }
        // The reference becomes the value, here and only here. The field
        // itself always goes, resolved or not: the agent's `CloudInit` is
        // `deny_unknown_fields`, so a `user_data_from` that reached a node
        // would be a REFUSED create — which is exactly the failure mode to
        // want. A dispatch that forgot to resolve is loud, never a guest
        // that boots without its configuration.
        if config.remove("user_data_from").is_some()
            && let Some(plaintext) = seed
        {
            config.insert(
                "user_data".to_string(),
                serde_json::Value::String(plaintext.to_string()),
            );
        }
    }
    let desired = match vm.spec.run_strategy {
        RunStrategy::Running => "Running",
        RunStrategy::Stopped => "Stopped",
        RunStrategy::Paused => "Paused",
    };
    obj.insert(
        "desired".to_string(),
        serde_json::Value::String(desired.to_string()),
    );
    Ok(serde_json::to_string(&doc)?)
}
