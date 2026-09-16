// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! The VM half of the pass: reconcile one VM, dispatch it to a node, hot-plug
//! its drift, evacuate it, tear it down. Moved out of `reconcile.rs`
//! unchanged.

use super::*;

/// What the watchdog has to say about one VM on one node, as a value.
///
/// D10: a VM on a node that stopped talking kept `phase: Running` for ever,
/// at both tiers. Three minutes measured in the mini-chaos run, and the lab's
/// standing inventory showed it over days — eleven guests on manacor reported
/// `Running` while the agent that would know had been dead for twenty hours.
/// The guests really were running, which is precisely the point: the control
/// plane had no evidence either way and was asserting one of them.
///
/// `Unknown` and not `Failed`. Nothing is proven broken — an agent that is
/// killed leaves its VMMs standing, deliberately — and `Failed` is the phase
/// the requeue curve acts on, so claiming it would have this tier repairing
/// something it cannot see.
///
/// Only for the phases that CLAIM something about a guest. `Pending` claims
/// nothing has been dispatched, `Stopped` and `Failed` are already the phases
/// where nothing is expected to be running, and `Quarantined` is deliberately
/// nobody's to touch. Overwriting any of those would replace a fact this tier
/// established with an absence of one.
///
/// Pure, and the clock comes in as an argument: this is the rule, and a rule
/// that reads `Utc::now()` is a rule that can only be exercised by waiting.
pub(crate) fn silent(vm: &Vm, last_heartbeat: Option<DateTime<Utc>>, now: DateTime<Utc>) -> bool {
    vm.spec.node_name.is_some()
        && claims_a_guest(vm.status.phase().kind())
        && heartbeat_expired(last_heartbeat, now)
}

/// The phases that are a statement about a guest that is supposed to exist
/// right now, and therefore the only ones a silence can make untrue.
fn claims_a_guest(phase: VmPhaseKind) -> bool {
    matches!(
        phase,
        VmPhaseKind::Running | VmPhaseKind::Paused | VmPhaseKind::Provisioning
    )
}

/// Write that verdict on every VM of one silent node.
///
/// Level-triggered and not edge-triggered, which is what the manacor case
/// forces: the node had been down for twenty hours before this code existed,
/// so `ready` was already false and there was no transition left to fire on.
/// Every pass asks the same question of every node, and the write only
/// happens where the phase is not already `Unknown` — so the event fires once
/// and the store sees nothing after that.
///
/// Every replica's business, exactly as the heartbeat expiry beside it is:
/// the verdict is idempotent under CAS, and a VM whose node talks to nobody
/// is a VM `may_reconcile` gives to nobody — so gating this on ownership
/// would leave the one case it exists for unanswered.
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
            .mutate::<Vm, _>(&name, |v| {
                // Re-read inside the mutate: a report may have landed between
                // the listing and here, and taking a phase away from a node
                // that has just spoken is the one way this can do harm.
                //
                // The FACT, and `settle` makes `Unknown { Silent }` out of it
                // — including the sentence, so that both tiers word a silence
                // the same way. See `VmSilence`.
                if claims_a_guest(v.status.phase().kind()) {
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

/// One VM, as the ordered sequence of concerns it actually is. Each step
/// below is one of them and does nothing else; the order they stand in here
/// is the whole of the control flow, and it is not free to change:
///
/// ownership gate -> teardown -> placement -> create dispatch -> lifecycle
/// drift -> requeue.
///
/// Ownership comes first because every step after it writes or sends.
/// Teardown comes before placement because a deleting VM is not a VM to
/// place. Placement ends the pass because there is nothing to send to a node
/// that was picked a microsecond ago and has not seen the object yet — the
/// next pass reads the binding back out of the store and goes on from there.
/// Everything after it needs a bound VM, which is why the node is resolved
/// once, right here, instead of being unwrapped in three places.
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

/// Carry a move-by-restart one step further, or finish it.
///
/// The whole of what the mark does, and it is deliberately small: two steps,
/// and the second one is somebody else's work.
///
///   * **Stopping** — the guest is asked to power off with the node's grace
///     period, every pass until the phase says it is off. Then the binding is
///     let go, and that single write hands the VM to the reschedule that has
///     existed since storage B: `unbind` tells the old node, `forget_unbound`
///     waits for its report to stop naming the VM, `place` decides again.
///   * **Moving** — nothing to do but watch. The mark's only remaining job is
///     to be cleared, and the condition for that is the one thing that means
///     the move landed: the VM is bound somewhere ELSE. Once it is cleared,
///     `runStrategy` still says Running and the ordinary lifecycle starts the
///     guest on the new machine without this function being involved at all.
///
/// A restart of this controller in the middle is survivable because the mark
/// is on the object: the replica that comes back reads which step it was in
/// and carries on. Without it, the middle of the operation — a VM that is
/// deliberately off — would be read as drift and started where it stood.
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
            .mutate::<Vm, _>(&name, |v| v.status.evacuating = None)
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
                // Level-triggered like every other command here: sent again
                // every pass until the phase moves, and idempotent at the
                // node because the record's desired state is what changes.
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
                .mutate::<Vm, _>(&name, |v| {
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
                .mutate::<Vm, _>(&name, |v| v.status.evacuating = None)
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

/// The binding fell: tell the old node to destroy the instance, and let go of
/// what this VM was holding.
///
/// The first half of a reschedule, and the half with something at stake.
/// What follows is NOT a placement — `status.nodeName` still names the old
/// node, so this pass runs again every tick until that node's report stops
/// naming the VM, and `session::forget_unbound` is what clears it. Placing
/// before then would be two nodes for one VM.
///
/// **A referenced volume is detached and an inline one is deprovisioned**,
/// and neither of those is decided here: `DestroyInstance` is the same
/// command a delete sends, and the node has read that fork off the VM's own
/// spec since storage A. So an instance store does not survive a reschedule
/// — it was made with the VM on that machine and goes with it — which is
/// exactly what an instance store is, and the guide says so.
///
/// Idempotent: the destroy is idempotent at the node, and the release only
/// ever clears a claim naming THIS VM.
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

/// Take the binding back because the node said it cannot serve this VM at
/// all, and remember that it said so.
///
/// The second half of `OPEN-ITEMS` §2, and the distinction it rests on is the
/// node's: a create that failed AFTER a record exists is a boot that may work
/// next time, and it stays where it is on the requeue curve. A create the
/// node refused STRUCTURALLY leaves no record and will never work there,
/// however often it is asked — so the binding falls and the scheduler decides
/// again.
///
/// The node is remembered as a non-candidate with an EXPIRY. Without the
/// memory the scheduler would very likely choose it again — nothing else
/// about it changed — and the VM would walk a loop of one create per pass.
/// With a permanent memory an operator who fixes the node would have to clear
/// a field nobody told them about.
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
        .mutate::<Vm, _>(&name, |v| {
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

/// How long a node that said `CannotServe` stays off this VM's candidate
/// list.
///
/// One curve, in the sense the requeue policy uses the word: long enough that
/// a VM does not walk a loop while the scheduler keeps choosing the same
/// node, short enough that an operator who installs the missing driver does
/// not have to wait out a shift. Nothing depends on the exact number — a
/// refusal that expires early is answered by the node refusing again, which
/// writes a fresh one.
pub(super) const REFUSAL_TTL: std::time::Duration = std::time::Duration::from_secs(600);

/// Finalizer flow: tear down on the bound node (idempotent at the agent),
/// then the object really goes away.
pub(super) async fn tear_down(p: &Pass<'_>, vm: &Vm, outgoing: &str) -> anyhow::Result<()> {
    if let Some(node) = vm.spec.node_name.as_deref()
        && vm.status.phase().kind() != VmPhaseKind::Pending
    {
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
    // Let go of what this VM was holding, in the same breath the object goes.
    //
    // The node has been told to tear down and has acked being told; whether
    // it has finished detaching is its own business and this tier cannot
    // wait for it, because the object is what would have carried the wait and
    // the object is going. The gap that leaves is covered where it has to be:
    // the node refuses to deprovision a volume it still has open, so a delete
    // arriving in the window is answered and retried rather than obeyed.
    release_volumes(p, vm).await;
    p.store.delete::<Vm>(&vm.metadata.name).await?;
    info!("vm deleted");
    Ok(())
}

/// What the spec asks for against what the node says it has: the disks to
/// plug in, and the ones to let go.
///
/// `None` when the two agree, which is the ordinary state of every VM and the
/// only state a VM with no referenced disks can be in.
///
/// Read off `status.volumes` and NOT off `observedGeneration`, and that is
/// the whole reason this is level-triggered rather than edge-triggered: a
/// generation says a spec was written, and what has to be answered here is
/// whether the bytes are open. An agent restart, a node that lost a record, a
/// command that was acked and then failed inside the node — all three leave
/// the generation satisfied and the disk missing, and all three are the same
/// drift as a fresh attach.
///
/// A VM whose node runs an agent from before `attached_volumes` existed
/// reports an empty list, so every referenced disk reads as not attached and
/// this asks for a re-create every pass. Idempotent at the node and visible
/// in the log, which is the honest failure mode for a version skew that has
/// to end with a rollout anyway.
pub(super) fn volume_drift(vm: &Vm) -> Option<Drift> {
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
pub(super) struct Drift {
    /// Referenced volumes the spec names that the node does not report.
    pub(super) attach: Vec<String>,
    /// Volumes the node reports that the spec no longer names.
    pub(super) release: Vec<String>,
}

/// Make the node's disks match the spec: hold the new ones, re-send the spec,
/// let the gone ones go.
///
/// One idempotent `CreateInstance` and no new verb, which is the whole shape
/// of declarative hot-plug: the node already takes a re-sent create for a VM
/// it knows and now diffs its volume list against it. A second command would
/// be a second way to say the same thing, and the two would drift.
///
/// **The order is the rule, and it is the same one storage A wrote down for
/// the create path.** A volume is HELD before the node is told to open it —
/// the reverse leaves a window in which a node has the disk open while the
/// object says nobody holds it, and `Release::HeldBy` reads that object. It
/// is let go only AFTER the node has been told to drop it, for the mirror
/// reason: a volume released while a guest still has it open is a volume a
/// delete would take the bytes of.
///
/// `observedGeneration` is deliberately NOT written here. See
/// `session::ingest_attachments`: for a spec that changed `volumes[]` it
/// closes when the node reports the set, because an attach can fail inside
/// the node long after the command was acked.
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

/// Take hold of every volume this VM refers to, by name, before the node is
/// told anything.
///
/// A compare-and-swap per volume, and the order is the point: the claim is
/// written BEFORE the create is dispatched, so a volume that is held is held
/// from the first moment anybody could be using it. The reverse order has a
/// window in which the node has the disk open and the object says nobody
/// does — and `Release::HeldBy` reads that object.
///
/// Point a volume's record at the node its vm is on, to be re-opened there.
///
/// Pure and named for one reason: the node has to be WRITTEN and not cleared,
/// and a `None` here reads so much like "let somebody decide" that it was
/// written that way and shipped. `place_volume` is that somebody — it takes
/// the first feasible node of the pool and knows nothing about a vm waiting
/// on another one — so a cleared node came back as the node the volume had
/// just left, and the two passes took turns every five seconds: "the record
/// follows the vm", "volume ns-b is being re-opened on agent-1b", with the vm
/// `Pending` for as long as anybody watched. `next_for` is the other half of
/// this rule and says the same thing from the volume's side.
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
            volume = p
                .store
                .mutate::<Volume, _>(&name, |v| v.status.node = Some(node.to_string()))
                .await?;
            info!(volume = %name, from = %from, to = node,
                  "the vm's node already has the volume open; the record moves with it");
        }
        // The RECORD follows the vm, and only ever within a pool that says
        // the bytes are reachable from where it is going.
        //
        // A volume's `status.node` is the machine that has it OPEN, and until
        // a vm could move it was also the machine that made it, so the two
        // were the same fact and nothing distinguished them. A drain
        // separates them: the vm is placed on another node of the same
        // `shared` pool — legitimately, `volume_bindings` allowed exactly
        // that — and the node it lands on has never been told about the
        // volume. The create then dies with the agent's own sentence, "this
        // node has no record of volume <uid>", and the vm sits Failed with
        // its disk one machine away.
        //
        // Re-pointing it is enough because the bytes do not move: every
        // backend derives its name from the volume's uid, `provision` adopts
        // an existing file rather than making a second one, and the pool has
        // already said both machines can reach it. The record is pointed AT
        // the vm's node, not cleared: `place_volume` takes the first feasible
        // node of the pool and has no idea a vm is waiting on the other one,
        // so a cleared `node` came straight back as the node the volume had
        // just left. Round 4's e2e watched the two passes take turns every
        // five seconds — "the record follows the vm" and then "volume ns-b is
        // being re-opened on agent-1b", for as long as anybody looked, with
        // the vm `Pending` throughout. A destination this pass already knows
        // must not be re-derived by a pass that does not.
        //
        // NOT done for a `node-local` pool, and the guard is the same one the
        // scheduler used to get here: such a vm was never placed anywhere but
        // on the machine holding its bytes.
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
                p.store
                    .mutate::<Volume, _>(&name, |v| follow_vm(v, &vm.metadata.name, node))
                    .await?;
                info!(volume = %name, from = %from, to = node,
                      "the record follows the vm; the bytes stay where they are");
                anyhow::bail!("volume {name} is being re-opened on {node}");
            }
        }
        // Not ready HERE, yet. The gate exists because a bound VM's create is
        // no longer preceded by `place`, which is where "is this disk ready"
        // used to be asked: a vm that is REBOUND — by a reschedule, by a
        // drain, by the record above following it — is dispatched straight
        // from `reconcile_vm_traced`, and the node it lands on may not have
        // been told about the volume yet.
        //
        // Seen in the position-2 e2e as a `Failed` vm carrying the agent's
        // own sentence, "this node has no record of volume <uid>", one pass
        // before the provision reached that node. It healed itself on the
        // requeue, which is the worst kind of bug: correct in the end, and a
        // red phase in between that nothing explains.
        if volume.status.phase().kind() != VolumePhaseKind::Ready {
            anyhow::bail!(
                "volume {name} is {} on {node}; the vm waits for it",
                volume.status.phase().kind().as_str()
            );
        }
        match volume.status.attached_to.as_deref() {
            Some(holder) if holder == vm.metadata.name => {
                // Held by us already, but the node may still be missing from
                // `openOn` — a volume attached before the field existed, or a
                // vm that has just been rebound. One idempotent write, and
                // `open_here` returns false on every pass after the first.
                let mut here = volume;
                if here.status.open_here(node) {
                    let _ = p.store.update(&here).await;
                }
                continue;
            }
            Some(holder) => {
                anyhow::bail!("volume {name} is held by {holder}");
            }
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
        held.status.open_here(node);
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

/// Let go of every volume this VM was holding.
///
/// Called when the VM is gone — which is the absence of its uid from the
/// node's status report, the same rule the object itself goes by. Only ever
/// clears a claim that names THIS VM: a volume some other VM has since taken
/// is not this teardown's to release.
pub(super) async fn release_volumes(p: &Pass<'_>, vm: &Vm) {
    release_named_volumes(p, vm, &vm.spec.referenced_volumes()).await
}

/// Let go of exactly these, and only where the claim names THIS VM.
///
/// The half `release_volumes` is now written in terms of. A teardown lets go
/// of everything the VM refers to; a detach lets go of the difference, and
/// handing it the same loop is what keeps the two from growing two answers to
/// "may I clear this claim".
pub(super) async fn release_named_volumes(p: &Pass<'_>, vm: &Vm, names: &[String]) {
    // WHERE it was open, so that letting go clears both halves of the claim.
    // `status.nodeName` is the evidence half and `spec.nodeName` the intent,
    // and a vm being torn down may have lost either — whichever is left names
    // the machine that had the disk open.
    let node = vm
        .status
        .node_name
        .clone()
        .or_else(|| vm.spec.node_name.clone());
    for name in names {
        let held = p
            .store
            .mutate::<Volume, _>(name, |v| {
                if v.status.attached_to.as_deref() == Some(vm.metadata.name.as_str()) {
                    v.status.attached_to = None;
                    // Only THIS vm's node comes off. A migration in flight has
                    // the other end in the list too, and that end is not this
                    // release's to clear.
                    if let Some(node) = &node {
                        v.status.closed_here(node);
                    }
                }
            })
            .await;
        match held {
            Ok(_) => debug!(volume = %name, "volume released"),
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
        .mutate::<Vm, _>(&vm.metadata.name, |v| {
            // The generation the node was actually told about, and only
            // when the telling worked: a create that never left the process
            // is not a spec anybody has acted on.
            //
            // AND only when this dispatch settles the spec on its own. A
            // create that changes `volumes[]` on a VM that already has a
            // record does not: the command is acked the moment the node has
            // it, and the attach can still fail inside the node. That one
            // closes when the report names the disks — see
            // `session::ingest_attachments`, which is the only other writer
            // of this field and the reason it is guarded here rather than
            // simply not written.
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

/// What a create's answer says about the object, and whether it may be
/// written over what is already there.
///
/// Two answers and two different kinds of thing, which is the whole of this
/// function. An ACK is a guess about the future: the node has the spec and
/// will try. The agent acks a create and reports the booted VM over the same
/// session, so its first status report can land before this write — and
/// anticipation must never overwrite observation, so an ack moves only a VM
/// nobody has reported on yet.
///
/// A REFUSAL is an observation. The node ANSWERED, the answer is that this
/// create did not happen, and a node that refuses a create keeps no record of
/// the VM — so no further report is ever coming to correct whatever phase an
/// earlier report left behind. Gating the refusal on Pending as well is what
/// made a VM vanish into Provisioning for ever: seen in the lab, a guest
/// whose kernel was on the node and whose initramfs was not reported
/// Provisioning, failed inside cloud-hypervisor a heartbeat later, lost its
/// record, and then sat there with no message and nothing retrying. Written
/// whatever the object says now, so that `heal_if_failed` — right at the end
/// of the same pass, and it re-sends the whole create — can see it.
///
/// `Quarantined` is the one phase a refusal may not overwrite: it is an
/// operator's word about a VM and it outranks a machine's.
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
    info!(
        ?action,
        strategy = ?vm.spec.run_strategy,
        phase = ?vm.status.phase().kind(),
        "run strategy drifted, sending command"
    );
    p.registry
        .send_command(node, outgoing, lifecycle_op(action, &vm.metadata.uid))
        .await?;
    // The other half of "acted on this generation". A runStrategy change
    // travels as a lifecycle command and never as a new spec, so without this
    // a stopped VM would read `pending` forever — the one drift Position 2
    // deliberately leaves possible on a VM.
    let dispatched = vm.metadata.generation;
    p.store
        .mutate::<Vm, _>(&vm.metadata.name, |v| {
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
                .mutate::<Vm, _>(name, |v| {
                    v.status.requeue_attempts = 0;
                    v.status.last_requeue = None;
                })
                .await?;
        }
        // Arm, don't kick: the first delay is measured from first seeing
        // Failed, so the agent's own retry gets its window before ours.
        Requeue::Arm => {
            p.store
                .mutate::<Vm, _>(name, |v| {
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
        .mutate::<Vm, _>(name, |v| {
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
                .mutate::<Vm, _>(name, |v| {
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
