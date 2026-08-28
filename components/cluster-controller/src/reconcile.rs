// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! The Vm reconciler: level-triggered like the agent's — a periodic pass
//! plus etcd-watch wakeups, every decision derived from the stored object.
//! Phase is the dedup: Pending → schedule + create, Provisioning+ → the
//! agent owns it and its status reports carry the phase from there.
//!
//! The same pass expires node heartbeats: a session that tears down reports
//! its node down immediately, but an agent that is killed outright — or one
//! that died while this controller was restarting — leaves nothing behind
//! except a heartbeat that stops moving.
//!
//! Several replicas run this same pass against the same etcd, with no leader
//! between them, and the session map is what divides the work (see
//! `may_reconcile`). Everything they still do share — binding an unbound VM,
//! expiring a heartbeat — goes through a compare-and-swap, and the store is
//! the arbiter: one writer wins, the loser sees a Conflict and drops it.

use std::collections::{BTreeMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use controller_api::{
    Candidate, CandidateKind, Capacity, EtcdStore, Lifecycle, Node, Overcommit, PassTrigger,
    PendingTally, RequeuePolicy, Resource, RunStrategy, Scheduler, StoreError, Vm, VmPhase,
    heartbeat_expired, lifecycle_command,
};
use macros::generated;
use proto::command;
use tracing::{debug, info, warn};

use controller_api::EventType;
use controller_api::events::{self, Happening};

use crate::session::SessionRegistry;

const TICK: Duration = Duration::from_secs(5);

/// Who, of several leaderless replicas, may act on this VM: the one its node
/// is dialled into. The session is the ownership token — it is a fact the
/// replica can observe by itself, it is already exclusive (an agent holds one
/// session at a time), and it is the only replica that can reach the node
/// anyway, so nothing is lost by declaring it the owner.
///
/// An unbound VM belongs to everybody: any replica may schedule it, but only
/// onto nodes of its own session map (`Candidate::connected`), so whoever wins
/// the binding CAS binds the VM to a node it already owns and ownership
/// follows the binding for free. No hand-off, no forwarding, no leader.
///
/// The edge this leaves open, deliberately: a VM whose node is dialled into
/// no replica at all is reconciled by nobody. It waits — including a deleting
/// one, which stays Terminating until its node comes back, because tearing a
/// VM down is something only its agent can do.
#[generated(model = ClaudeOpus, version = "5")]
pub fn may_reconcile(vm: &Vm, sessions: &HashSet<String>) -> bool {
    match vm.spec.node_name.as_deref() {
        Some(node) => sessions.contains(node),
        None => true,
    }
}

/// The shared drift table says what has to happen; this is the only part that
/// is the agent protocol's business, and so the only part that stays here.
#[generated(model = ClaudeOpus, version = "5")]
fn lifecycle_op(action: Lifecycle, uid: &str) -> command::Op {
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

#[generated(model = ClaudeFable, version = "5")]
pub async fn run(
    store: Arc<EtcdStore>,
    registry: Arc<SessionRegistry>,
    scheduler: Arc<dyn Scheduler>,
    requeue: Arc<dyn RequeuePolicy>,
    overcommit: Overcommit,
) {
    let mut trigger = PassTrigger::<Vm>::new(&store, TICK).await;
    loop {
        trigger.wait(&store).await;
        let clock = telemetry::metrics::Timer::start();
        let outcome = pass(
            &store,
            &registry,
            scheduler.as_ref(),
            requeue.as_ref(),
            overcommit,
        )
        .await;
        // Measured around the whole pass and not around its parts: what an
        // operator is asking when a cluster feels slow is how long one lap of
        // the loop takes, and a pass that FAILED still took the time it took.
        telemetry::metrics::reconcile().pass(
            telemetry::metrics::TIER_CLUSTER,
            Vm::KIND,
            clock.seconds(),
            outcome.is_ok(),
        );
        if let Err(e) = outcome {
            warn!(error = format!("{e:#}"), "reconcile pass failed");
        }
    }
}

#[generated(model = ClaudeFable, version = "5")]
async fn pass(
    store: &EtcdStore,
    registry: &SessionRegistry,
    scheduler: &dyn Scheduler,
    requeue: &dyn RequeuePolicy,
    overcommit: Overcommit,
) -> anyhow::Result<()> {
    // One reading of the session map for the whole pass: what this replica
    // owns must not change halfway through the list it is deciding about.
    let sessions = registry.connected();
    telemetry::metrics::sessions()
        .set_connected(telemetry::metrics::PEER_NODE, sessions.len() as i64);
    // The VMs first: what is already bound to a node is half of what "free"
    // means, and the candidates cannot be built without it.
    let vms = store.list::<Vm>().await?;
    publish_vm_gauges(&vms);
    let nodes = expire_and_collect_nodes(store, &sessions, &vms, overcommit).await?;
    telemetry::metrics::objects().set_count(Node::KIND, nodes.len() as i64);
    let pass = Pass {
        store,
        registry,
        scheduler,
        requeue,
        sessions: &sessions,
        nodes: std::sync::Mutex::new(nodes),
        pending: PendingTally::new(),
    };
    for vm in vms {
        let name = vm.metadata.name.clone();
        if let Err(e) = reconcile_vm(&pass, vm).await {
            warn!(vm = %name, error = format!("{e:#}"), "vm reconcile failed");
        }
    }
    // After the loop, because until it has run nobody knows how many VMs are
    // pending for which reason. See `PendingTally`.
    pass.pending.publish(telemetry::metrics::TIER_CLUSTER);
    Ok(())
}

/// One event about a VM, in the two shapes this tier makes.
///
/// The tenant travels with it because the cloud handed it down on the object;
/// a VM created straight at this tier has none, and its events are unscoped
/// exactly as it is.
#[generated(model = ClaudeOpus, version = "5")]
fn about<'a>(vm: &'a Vm, reason: &'a str, message: String, kind: EventType) -> Happening<'a> {
    Happening {
        kind: Vm::KIND,
        name: &vm.metadata.name,
        uid: &vm.metadata.uid,
        reason,
        message,
        event_type: kind,
        tenant: vm.spec.tenant.as_deref(),
    }
}

fn normal<'a>(vm: &'a Vm, reason: &'a str, message: String) -> Happening<'a> {
    about(vm, reason, message, EventType::Normal)
}

fn warning<'a>(vm: &'a Vm, reason: &'a str, message: String) -> Happening<'a> {
    about(vm, reason, message, EventType::Warning)
}

/// What is still free on one node: the allowance its reported capacity gives
/// under the configured overcommit, minus everything already bound to it.
///
/// Both halves are things the controller already has in hand — the Node
/// object and the VM listing this pass made anyway — which is why nothing is
/// stored. A second copy of this number in etcd would be a number that can be
/// wrong, and it would be wrong in the direction that fills a node.
///
/// Every phase counts, a Pending one included. A VM that has been bound and
/// not yet started is a claim on this node, and leaving it out is how a node
/// takes on twice its memory in one burst of creates.
#[generated(model = ClaudeOpus, version = "5")]
fn free_on(
    node: &str,
    capacity: &controller_api::NodeCapacity,
    vms: &[Vm],
    overcommit: Overcommit,
) -> Capacity {
    let bound = vms
        .iter()
        .filter(|v| v.spec.node_name.as_deref() == Some(node))
        .fold(Capacity::default(), |sum, vm| {
            sum.plus(Capacity::wanted_by(vm))
        });
    overcommit
        .allowance(Capacity {
            vcpus: capacity.vcpus,
            mem_mib: capacity.mem_mib,
        })
        .minus(bound)
}

/// The label sets of the VMs already bound to `on` — what anti-affinity is
/// measured against.
///
/// Every phase counts, exactly as `free_on` counts them: a VM that has been
/// bound and not yet started is already there as far as "do not put these two
/// together" is concerned, and skipping it is how two replicas land on one
/// machine in a single burst of creates.
#[generated(model = ClaudeOpus, version = "5")]
fn hosted_on(
    on: &str,
    vms: &[Vm],
    bound: fn(&Vm) -> Option<&str>,
) -> Vec<BTreeMap<String, String>> {
    vms.iter()
        .filter(|v| bound(v) == Some(on))
        .map(|v| v.metadata.labels.clone())
        .collect()
}

/// How many VMs there are, and how they are spread over the phases.
///
/// Every phase every time, zero included: a phase that stops being written
/// while nothing is in it looks, in a dashboard, exactly like a controller
/// that stopped reporting. Derived from the listing the pass already made —
/// this costs no etcd round trip of its own.
#[generated(model = ClaudeOpus, version = "5")]
fn publish_vm_gauges(vms: &[Vm]) {
    telemetry::metrics::objects().set_count(Vm::KIND, vms.len() as i64);
    for phase in VmPhase::ALL {
        let n = vms.iter().filter(|v| v.status.phase == phase).count();
        telemetry::metrics::objects().set_vms(phase.as_str(), n as i64);
    }
}

/// Everything one pass carries from VM to VM, in one place: the store it
/// writes through, the session map that says which VMs are this replica's,
/// the nodes it may place on and the two policies that decide placement and
/// healing.
///
/// A struct rather than a parameter list because none of it is per-VM — the
/// six were the same six at every step of every VM, and the only thing that
/// actually changes between the steps below is the VM itself. What the steps
/// take is what they are about.
#[generated(model = ClaudeOpus, version = "5")]
struct Pass<'a> {
    store: &'a EtcdStore,
    registry: &'a SessionRegistry,
    scheduler: &'a dyn Scheduler,
    requeue: &'a dyn RequeuePolicy,
    /// Read once for the whole pass; see `pass`.
    sessions: &'a HashSet<String>,
    /// What is left after the heartbeat expiry, as the scheduler wants it.
    ///
    /// Behind a mutex because a pass SPENDS it: every binding takes room off
    /// the candidate it went to, so the next VM of the same pass is measured
    /// against what is actually left. Never held across an await — see
    /// `place`, which locks, decides, deducts and lets go.
    nodes: std::sync::Mutex<Vec<Candidate>>,
    /// Filled in by `place`, published once at the end of the pass.
    pending: PendingTally,
}

/// Expire stale heartbeats and hand the scheduler what is left. Both halves
/// read the same Node objects, so a node that just expired cannot still be
/// scheduled onto in the same pass.
///
/// Expiry is every replica's business, not just the owner's: the heartbeat it
/// judges was written to the shared store by whichever replica holds the
/// session, and the verdict — `ready = false` — is idempotent under CAS, so
/// two replicas reaching it at once cost one redundant write and nothing else.
/// `connected` stays strictly local, though: a node with a live session
/// *somewhere* is still not a node this replica can send anything to.
#[generated(model = ClaudeOpus, version = "5")]
async fn expire_and_collect_nodes(
    store: &EtcdStore,
    sessions: &HashSet<String>,
    vms: &[Vm],
    overcommit: Overcommit,
) -> anyhow::Result<Vec<Candidate>> {
    let now = Utc::now();
    let mut out = Vec::new();
    // The whole per-node series set is rebuilt from this listing. A node that
    // has been removed from the inventory has to LOSE its age rather than
    // keep the last one for ever — frozen, and indistinguishable from a node
    // whose heartbeat merely stopped.
    telemetry::metrics::sessions().reset_heartbeats();
    for node in store.list::<Node>().await? {
        let name = node.metadata.name;
        if let Some(last) = node.status.last_heartbeat {
            telemetry::metrics::sessions().set_heartbeat_age(
                telemetry::metrics::PEER_NODE,
                &name,
                (now - last).num_milliseconds() as f64 / 1000.0,
            );
        }
        let mut ready = node.status.ready;
        if ready && heartbeat_expired(node.status.last_heartbeat, now) {
            // ISO-8601 UTC rather than the Debug of an Option: the instant
            // is what an operator lines up against everything else in the log.
            let last = node
                .status
                .last_heartbeat
                .map(|t| t.to_rfc3339())
                .unwrap_or_else(|| "never".to_string());
            warn!(node = %name, last_heartbeat = %last, "heartbeat expired, node not ready");
            match store
                .mutate::<Node, _>(&name, |n| n.status.ready = false)
                .await
            {
                Ok(_) => {
                    // Inside the branch that already established the node WAS
                    // ready and is not any more, so this fires on the
                    // transition rather than on every pass that finds it
                    // still gone. A Node has no uid of its own here; its name
                    // is its identity, and `name_of` knows that.
                    events::record(
                        store,
                        Happening {
                            kind: Node::KIND,
                            name: &name,
                            uid: "",
                            reason: events::reason::PEER_LOST,
                            message: format!("heartbeat expired, last seen {last}"),
                            event_type: EventType::Warning,
                            // A node is the operator's estate and belongs to
                            // no tenant; only an admin sees this.
                            tenant: None,
                        },
                    )
                    .await;
                    ready = false
                }
                Err(e) => warn!(node = %name, error = format!("{e:#}"),
                                "marking the node not ready failed"),
            }
        }
        out.push(Candidate {
            connected: ready && sessions.contains(&name),
            schedulable: node.spec.schedulable,
            free: free_on(&name, &node.status.capacity, vms, overcommit),
            catalogue: node.status.capacity.capabilities,
            kind: CandidateKind::Node,
            hosted: hosted_on(&name, vms, |v| v.spec.node_name.as_deref()),
            labels: node.spec.labels,
            name,
        });
    }
    Ok(out)
}

#[generated(model = ClaudeFable, version = "5")]
/// The trace of the request this VM came from is on the object, because there
/// is no call stack from that request to here. The span is built and given
/// its parent BEFORE it starts — see `telemetry::in_trace`; attaching from
/// inside the body is too late and silently loses the trace.
///
/// `vm` is what a person calls it, `vm_id` is what the agent knows it as —
/// the uid is the only identity that survives the hop down.
async fn reconcile_vm(p: &Pass<'_>, vm: Vm) -> anyhow::Result<()> {
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
fn birth_trace(vm: &Vm) -> Option<telemetry::TraceParent> {
    if !matches!(vm.status.phase, VmPhase::Pending | VmPhase::Provisioning) {
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
#[generated(model = ClaudeOpus, version = "5")]
async fn reconcile_vm_traced(
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
        return place(p, vm).await;
    };
    if vm.status.phase == VmPhase::Pending {
        dispatch_create(p, &vm, &node, &outgoing).await?;
    }
    if let Some(action) = lifecycle_command(vm.spec.run_strategy, vm.status.phase) {
        send_lifecycle(p, &vm, &node, action, &outgoing).await?;
    }
    heal_if_failed(p, &vm, &node, &outgoing).await
}

/// Finalizer flow: tear down on the bound node (idempotent at the agent),
/// then the object really goes away.
#[generated(model = ClaudeOpus, version = "5")]
async fn tear_down(p: &Pass<'_>, vm: &Vm, outgoing: &str) -> anyhow::Result<()> {
    if let Some(node) = vm.spec.node_name.as_deref()
        && vm.status.phase != VmPhase::Pending
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
    p.store.delete::<Vm>(&vm.metadata.name).await?;
    info!("vm deleted");
    Ok(())
}

/// Bind an unbound VM to a node, or leave it Pending for the next pass.
#[generated(model = ClaudeOpus, version = "5")]
async fn place(p: &Pass<'_>, vm: Vm) -> anyhow::Result<()> {
    // Decide and SPEND under one lock, and let go before anything awaits: the
    // room this VM takes has to be gone before the next VM of the same pass
    // is measured against the node, or two creates in one breath would both
    // be told there is space for them. See `controller_api::deduct`.
    //
    // An API-edge check cannot do this and that is why it is not the
    // authority: the objects it would have to count do not exist yet when it
    // runs. The edge may still refuse early — it just never decides.
    let decision = {
        let mut nodes = p.nodes.lock().unwrap();
        match p.scheduler.assign(&vm, &nodes) {
            Some(node) => {
                controller_api::deduct(&mut nodes, &node, Capacity::wanted_by(&vm));
                Ok(node)
            }
            // Sentence and category together, from the same candidate list
            // this decision was made against.
            None => Err((nodes.len(), controller_api::pending_reason_of(&vm, &nodes))),
        }
    };
    let node = match decision {
        Ok(node) => node,
        Err((known, (category, reason))) => {
            // Say WHY on the object, not only in this process's debug log. A
            // Pending VM was a dead end for anybody holding the API: `vm ls` and
            // `vm inspect` both showed the phase and nothing else, while the one
            // explanation lived in a `debug!` line inside whichever replica
            // happened to run the pass.
            //
            // The sentence goes on the object and the CATEGORY goes in the
            // tally: the sentence counts candidates and names capabilities, and
            // is exactly the string that must never become a metric label.
            p.pending.note(category);
            debug!(
                known,
                reason = %reason,
                "no schedulable node here, staying pending"
            );
            // Only when it CHANGED: peers report every few seconds and a pass runs
            // on every tick, so writing the same sentence again would wake the vm
            // watch for nothing.
            //
            // The event rides in the same branch, and for a sharper version
            // of the same reason: a level-triggered pass reaches this
            // conclusion every five seconds for as long as the VM is
            // unplaceable, and an event per pass would be a store filling at
            // one write per VM per tick. What is worth recording is the
            // moment the answer CHANGED.
            if vm.status.message.as_deref() != Some(reason.as_str()) {
                p.store
                    .mutate::<Vm, _>(&vm.metadata.name, |v| {
                        v.status.message = Some(reason.clone());
                    })
                    .await?;
                events::record(
                    p.store,
                    warning(&vm, events::reason::FAILED_SCHEDULING, reason),
                )
                .await;
            }
            return Ok(());
        }
    };
    // A plain CAS on the object this pass read, not a read-modify-write:
    // with several replicas scheduling at once the binding is exactly what
    // must NOT be retried onto a newer object — a retry would re-apply this
    // replica's choice over the winner's and move a VM that is already
    // placed. One write, one winner, and the loser is told.
    let mut bound = vm;
    bound.spec.node_name = Some(node.clone());
    // The reason a previous pass may have written is answered by the binding
    // itself; leaving it would make a placed VM carry the sentence that said
    // it could not be placed.
    bound.status.message = None;
    match p.store.update(&bound).await {
        Ok(_) => {
            telemetry::metrics::scheduling().placed(telemetry::metrics::TIER_CLUSTER);
            // Inside the arm where the compare-and-swap SUCCEEDED, which is
            // what makes this an event rather than a pass: the replica that
            // lost the race takes the other arm and records nothing.
            events::record(
                p.store,
                normal(
                    &bound,
                    events::reason::SCHEDULED,
                    format!("bound to node {node}"),
                ),
            )
            .await;
            info!(node = %node, "scheduled")
        }
        Err(StoreError::Conflict(_)) => {
            telemetry::metrics::scheduling().conflict(telemetry::metrics::TIER_CLUSTER);
            debug!(node = %node, "lost the scheduling race, another writer bound it")
        }
        Err(e) => return Err(e.into()),
    }
    Ok(())
}

/// A Pending VM on a node that has not been told about it yet: send the spec
/// and record what came back.
#[generated(model = ClaudeOpus, version = "5")]
async fn dispatch_create(p: &Pass<'_>, vm: &Vm, node: &str, outgoing: &str) -> anyhow::Result<()> {
    let spec_json = build_spec_json(vm)?;
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
    let (phase, message) = match &outcome {
        // The payload of an ack is empty for every command that only changes
        // something, which is all of these; only the console fetch answers
        // with anything, and no reconcile pass sends one.
        Ok(_) => (VmPhase::Provisioning, None),
        Err(e) => (VmPhase::Failed, Some(format!("{e:#}"))),
    };
    p.store
        .mutate::<Vm, _>(&vm.metadata.name, |v| {
            // The agent acks the create and reports the booted VM over
            // the same session, so its first StatusReport can land before
            // this write. Dispatching is a guess about the future; a
            // status report is an observation of the present, and the
            // guess must not overwrite it.
            if v.status.phase == VmPhase::Pending {
                v.status.phase = phase;
                v.status.node_name = v.spec.node_name.clone();
                v.status.message = message.clone();
                v.status.observed_at = Some(Utc::now());
            }
        })
        .await?;
    outcome?;
    info!("create dispatched");
    Ok(())
}

/// Level-triggered lifecycle: spec.runStrategy is the intent, status.phase
/// the observation, and the difference between them is the command. The
/// ack writes nothing back — dispatching is a guess about the future, a
/// status report is the present, and anticipation never overwrites
/// observation. The next pass re-derives from what the node reported.
#[generated(model = ClaudeOpus, version = "5")]
async fn send_lifecycle(
    p: &Pass<'_>,
    vm: &Vm,
    node: &str,
    action: Lifecycle,
    outgoing: &str,
) -> anyhow::Result<()> {
    info!(
        ?action,
        strategy = ?vm.spec.run_strategy,
        phase = ?vm.status.phase,
        "run strategy drifted, sending command"
    );
    p.registry
        .send_command(node, outgoing, lifecycle_op(action, &vm.metadata.uid))
        .await
        .map(|_| ())
}

/// Failed is no longer anybody's last word (config `retry`, default
/// CrashLoopBackoff). The kick is a re-sent intent: the agent's
/// set_desired clears its own failure backoff and provisions afresh —
/// which also heals the backoff state an agent restart forgets. The
/// bookkeeping lives in status so a controller three seconds old kicks
/// exactly when one up for a week would. Quarantined stays untouched.
#[generated(model = ClaudeOpus, version = "5")]
async fn heal_if_failed(p: &Pass<'_>, vm: &Vm, node: &str, outgoing: &str) -> anyhow::Result<()> {
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
#[generated(model = ClaudeOpus, version = "5")]
async fn kick(p: &Pass<'_>, vm: &Vm, node: &str, outgoing: &str) -> anyhow::Result<()> {
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
    let spec_json = build_spec_json(vm)?;
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
    match outcome {
        Ok(_) => {
            // The agent took it this time; let its report say the rest.
            p.store
                .mutate::<Vm, _>(name, |v| {
                    if v.status.phase == VmPhase::Failed {
                        v.status.phase = VmPhase::Provisioning;
                        v.status.message = None;
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

/// What the requeue policy wants done about this VM right now. Pure — the
/// whole retry timeline is testable as a table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Requeue {
    Not,
    /// Failed, first sighting: start the clock, send nothing yet.
    Arm,
    /// The delay for this attempt has passed: re-send the intent.
    Kick,
    /// The phase left Failed with bookkeeping still on the object.
    Reset,
}

#[generated(model = ClaudeFable, version = "5")]
pub fn requeue_decision(vm: &Vm, policy: &dyn RequeuePolicy, now: DateTime<Utc>) -> Requeue {
    if vm.status.phase != VmPhase::Failed {
        return if vm.status.requeue_attempts > 0 || vm.status.last_requeue.is_some() {
            Requeue::Reset
        } else {
            Requeue::Not
        };
    }
    // A Failed VM that is wanted Stopped needs no healing; unbound Failed
    // (create dispatch failed before any node ack) restarts through the
    // Pending path once a kick cannot reach it anyway.
    if vm.spec.run_strategy == RunStrategy::Stopped || vm.spec.node_name.is_none() {
        return Requeue::Not;
    }
    let Some(since) = vm.status.last_requeue else {
        return Requeue::Arm;
    };
    match policy.next_delay(vm.status.requeue_attempts) {
        None => Requeue::Not,
        Some(delay) => match now.signed_duration_since(since).to_std() {
            Ok(elapsed) if elapsed >= delay => Requeue::Kick,
            _ => Requeue::Not,
        },
    }
}

/// The agent's NewVmSpec JSON, with `desired` derived from runStrategy —
/// the same document the agent's own REST API accepts.
#[generated(model = ClaudeFable, version = "5")]
pub(crate) fn build_spec_json(vm: &Vm) -> anyhow::Result<String> {
    let mut doc = vm.spec.vm.clone();
    let obj = doc
        .as_object_mut()
        .ok_or_else(|| anyhow::anyhow!("spec.vm must be a JSON object"))?;
    // What the guest should call itself, from the object's own name. This
    // tier is where that is filled in because it is the last one that knows
    // it: a node holds a uid and nothing else, so a seed built down there
    // could only ever derive a uuid for a hostname. Only when the VM asked
    // for cloud-init at all, and only when nobody named one — a meta_data
    // written by hand outranks this and is left alone.
    if let Some(config) = obj
        .get_mut("cloud_init")
        .and_then(serde_json::Value::as_object_mut)
        && !config.contains_key("local_hostname")
    {
        config.insert(
            "local_hostname".to_string(),
            serde_json::Value::String(vm.metadata.name.clone()),
        );
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

#[cfg(test)]
#[generated(model = ClaudeOpus, version = "5")]
mod tests {
    use super::*;

    fn at(secs: i64) -> DateTime<Utc> {
        DateTime::from_timestamp(1_800_000_000 + secs, 0).unwrap()
    }

    fn bound_to(node: Option<&str>) -> Vm {
        controller_api::resources::new_vm(
            "t",
            controller_api::VmSpec {
                cluster_selector: Default::default(),
                node_selector: Default::default(),
                anti_affinity: Vec::new(),
                node_name: node.map(str::to_string),
                cluster_name: None,
                run_strategy: RunStrategy::Running,
                tenant: None,
                vm: serde_json::json!({}),
            },
        )
    }

    fn sessions(names: &[&str]) -> HashSet<String> {
        names.iter().map(|s| s.to_string()).collect()
    }

    /// The whole of leaderless ownership: my sessions, my VMs.
    #[test]
    fn a_bound_vm_is_only_reconciled_by_the_replica_its_node_talks_to() {
        let mine = sessions(&["node-a"]);
        assert!(may_reconcile(&bound_to(Some("node-a")), &mine));
        assert!(!may_reconcile(&bound_to(Some("node-b")), &mine));
        // and a replica holding no session at all owns no bound VM
        assert!(!may_reconcile(&bound_to(Some("node-a")), &sessions(&[])));
    }

    /// Unbound is everybody's: the scheduler only offers nodes of the local
    /// session map, so binding and ownership land on the same replica anyway.
    #[test]
    fn an_unbound_vm_may_be_scheduled_by_any_replica() {
        assert!(may_reconcile(&bound_to(None), &sessions(&[])));
        assert!(may_reconcile(&bound_to(None), &sessions(&["node-a"])));
    }

    /// Draining is one bit and it belongs to the scheduler alone.
    ///
    /// The session is what decides who reconciles a VM and what makes a
    /// candidate `connected`; `spec.schedulable` is a separate field that
    /// only ever narrows the set FirstFit may pick from. So a cordoned node
    /// goes on owning, running and reconciling everything already bound to
    /// it, and the only thing that changes is that nothing new lands there —
    /// which is why cordon cannot evict, migrate or stop anything, and why
    /// there is nothing in this file that would have to be careful not to.
    #[test]
    fn draining_a_node_changes_only_what_the_scheduler_may_pick() {
        let mine = sessions(&["manacor"]);
        let running = bound_to(Some("manacor"));
        // Bound: still this replica's, drained or not — `may_reconcile` does
        // not look at the node object at all, only at the session map, and
        // cordoning writes neither.
        assert!(may_reconcile(&running, &mine));

        let drained = Candidate {
            kind: controller_api::CandidateKind::Node,
            labels: Default::default(),
            hosted: Vec::new(),
            name: "manacor".into(),
            connected: true,
            schedulable: false,
            // Room to spare: this test is about the drain and nothing else.
            free: controller_api::Capacity {
                vcpus: 64,
                mem_mib: 65536,
            },
            catalogue: Vec::new(),
        };
        // Nothing NEW goes there, and the sentence on the object says which
        // of the reasons it is.
        let waiting = bound_to(None);
        assert_eq!(
            controller_api::FirstFit.assign(&waiting, std::slice::from_ref(&drained)),
            None
        );
        let (why, sentence) =
            controller_api::pending_reason_of(&waiting, std::slice::from_ref(&drained));
        assert_eq!(why, controller_api::PendingReason::NoneUsable);
        assert!(sentence.contains("connected and schedulable"), "{sentence}");

        // Uncordon: the same candidate, the same VM, placed.
        let back = Candidate {
            schedulable: true,
            ..drained
        };
        assert_eq!(
            controller_api::FirstFit
                .assign(&waiting, std::slice::from_ref(&back))
                .as_deref(),
            Some("manacor")
        );
    }

    /// Deleting changes nothing about who acts: only the node's own replica
    /// can order the teardown, so a deleting VM on a foreign node waits.
    #[test]
    fn deleting_does_not_widen_ownership() {
        let mut vm = bound_to(Some("node-b"));
        vm.metadata.deletion_timestamp = Some(at(0));
        assert!(!may_reconcile(&vm, &sessions(&["node-a"])));
        assert!(may_reconcile(&vm, &sessions(&["node-b"])));
    }

    /// The whole retry timeline as a table: arm on first sighting, kick when
    /// the policy's delay has passed, reset the moment the phase recovers —
    /// and never touch a VM that is wanted Stopped, unbound, or whose policy
    /// says Failed is final.
    #[test]
    fn the_requeue_timeline() {
        use controller_api::requeue::{CrashLoopBackoff, NoRequeue};
        let failed = |last: Option<chrono::DateTime<Utc>>, attempts: u32| {
            let mut vm = bound_to(Some("node-a"));
            vm.status.phase = VmPhase::Failed;
            vm.status.last_requeue = last;
            vm.status.requeue_attempts = attempts;
            vm
        };
        // healthy VM without bookkeeping: nothing; with leftovers: reset
        assert_eq!(
            requeue_decision(&bound_to(Some("node-a")), &CrashLoopBackoff, at(0)),
            Requeue::Not
        );
        let mut recovered = bound_to(Some("node-a"));
        recovered.status.requeue_attempts = 3;
        assert_eq!(
            requeue_decision(&recovered, &CrashLoopBackoff, at(0)),
            Requeue::Reset
        );
        // first sighting arms the clock, sends nothing
        assert_eq!(
            requeue_decision(&failed(None, 0), &CrashLoopBackoff, at(0)),
            Requeue::Arm
        );
        // attempt 0 is due after 10s, not after 9
        assert_eq!(
            requeue_decision(&failed(Some(at(0)), 0), &CrashLoopBackoff, at(9)),
            Requeue::Not
        );
        assert_eq!(
            requeue_decision(&failed(Some(at(0)), 0), &CrashLoopBackoff, at(10)),
            Requeue::Kick
        );
        // attempt 3 waits its 80s
        assert_eq!(
            requeue_decision(&failed(Some(at(0)), 3), &CrashLoopBackoff, at(79)),
            Requeue::Not
        );
        assert_eq!(
            requeue_decision(&failed(Some(at(0)), 3), &CrashLoopBackoff, at(80)),
            Requeue::Kick
        );
        // "none" restores the old world: Failed stays Failed
        assert_eq!(
            requeue_decision(&failed(Some(at(0)), 0), &NoRequeue, at(3600)),
            Requeue::Not
        );
        // wanted Stopped or never bound: not this mechanism's business
        let mut stopped = failed(Some(at(0)), 0);
        stopped.spec.run_strategy = RunStrategy::Stopped;
        assert_eq!(
            requeue_decision(&stopped, &CrashLoopBackoff, at(3600)),
            Requeue::Not
        );
        let mut unbound = failed(Some(at(0)), 0);
        unbound.spec.node_name = None;
        assert_eq!(
            requeue_decision(&unbound, &CrashLoopBackoff, at(3600)),
            Requeue::Not
        );
    }

    // ---- the joint cross product ------------------------------------------
    //
    // `lifecycle_command` and `requeue_decision` are the two pure decisions
    // `reconcile_vm` takes about a VM, and it takes them both in the same
    // pass, about the same object. Each has its own table above; what neither
    // can say alone is what the pair does together — and that is the thing
    // that can go wrong, because both of them can end in a message to the
    // node. The cross product below is every combination of their inputs,
    // with the joint answer.

    /// The requeue side's whole input, spread over every dimension it reads.
    /// `elapsed` is seconds since `last_requeue`; -5 is a clock that went
    /// backwards, 9/10 and 79/80 straddle the CrashLoopBackoff delays for
    /// attempt 0 and attempt 3.
    fn requeue_inputs() -> Vec<(Option<i64>, u32)> {
        let mut out = Vec::new();
        for elapsed in [
            None,
            Some(-5),
            Some(0),
            Some(9),
            Some(10),
            Some(79),
            Some(80),
            Some(3600),
        ] {
            for attempts in [0u32, 3] {
                out.push((elapsed, attempts));
            }
        }
        out
    }

    fn policies() -> Vec<(&'static str, Box<dyn RequeuePolicy>)> {
        use controller_api::requeue::{CrashLoopBackoff, NoRequeue, RetryCount};
        vec![
            ("none", Box::new(NoRequeue)),
            ("count(2)", Box::new(RetryCount(2))),
            ("crash-loop-backoff", Box::new(CrashLoopBackoff)),
        ]
    }

    /// One cell of the joint space, built from the two functions' dimensions.
    #[allow(clippy::type_complexity)]
    fn joint_cells() -> Vec<(String, Vm, DateTime<Utc>, usize)> {
        let mut out = Vec::new();
        for (policy_index, (policy_name, _)) in policies().into_iter().enumerate() {
            for phase in VmPhase::ALL {
                for strategy in RunStrategy::ALL {
                    for node in [None, Some("node-a")] {
                        for (elapsed, attempts) in requeue_inputs() {
                            let mut vm = bound_to(node);
                            vm.spec.run_strategy = strategy;
                            vm.status.phase = phase;
                            vm.status.requeue_attempts = attempts;
                            vm.status.last_requeue = elapsed.map(|e| at(-e));
                            let label = format!(
                                "policy={policy_name} phase={phase:?} strategy={strategy:?} \
                                 node={node:?} elapsed={elapsed:?} attempts={attempts}"
                            );
                            out.push((label, vm, at(0), policy_index));
                        }
                    }
                }
            }
        }
        out
    }

    /// What the requeue side must answer, as an ordered list of guards rather
    /// than as a copy of `requeue_decision`'s control flow.
    fn expected_requeue(vm: &Vm, policy: &dyn RequeuePolicy, now: DateTime<Utc>) -> Requeue {
        if vm.status.phase != VmPhase::Failed {
            // Not Failed: nothing to retry, but bookkeeping left over from an
            // earlier Failed has to be cleared or the next failure would
            // inherit somebody else's attempt count.
            return if vm.status.requeue_attempts > 0 || vm.status.last_requeue.is_some() {
                Requeue::Reset
            } else {
                Requeue::Not
            };
        }
        if vm.spec.run_strategy == RunStrategy::Stopped {
            return Requeue::Not; // a VM nobody wants running needs no healing
        }
        if vm.spec.node_name.is_none() {
            return Requeue::Not; // no node to kick; the Pending path owns it
        }
        let Some(since) = vm.status.last_requeue else {
            return Requeue::Arm; // first sighting: start the clock, send nothing
        };
        let Some(delay) = policy.next_delay(vm.status.requeue_attempts) else {
            return Requeue::Not; // the policy says Failed is final
        };
        match now.signed_duration_since(since).to_std() {
            Ok(elapsed) if elapsed >= delay => Requeue::Kick,
            // Includes a clock that went backwards: to_std() refuses a
            // negative span, and waiting is the safe reading of it.
            _ => Requeue::Not,
        }
    }

    /// Every cell of both decisions at once — 2016 of them — against the
    /// guards above. What this buys over the two tables separately is the
    /// next test; this one is what makes it trustworthy.
    #[test]
    fn the_joint_cross_product_decides_what_the_guards_say() {
        let policies = policies();
        let mut cells = 0usize;
        for (label, vm, now, policy_index) in joint_cells() {
            let policy = policies[policy_index].1.as_ref();
            assert_eq!(
                requeue_decision(&vm, policy, now),
                expected_requeue(&vm, policy, now),
                "{label}"
            );
            cells += 1;
        }
        assert_eq!(
            cells,
            3 * 7 * 3 * 2 * 16,
            "the joint space is not the size it was"
        );
    }

    /// The invariant the pair exists to keep and neither half can state: the
    /// two never both send. A Kick re-sends the whole spec as a Create; a
    /// lifecycle command names a transition on a record the agent already
    /// has. Both in one pass would be the controller arguing with itself
    /// about the same VM in the same tick — and the node would see the two in
    /// whichever order they happened to leave.
    ///
    /// It holds structurally, and it is worth pinning because it holds for a
    /// reason that is easy to lose: Kick fires only at Failed, and Failed is
    /// exactly one of the phases `lifecycle_command` refuses to argue with.
    /// Moving Failed to the stable side of that line — which has been done
    /// once already, see 6315d84 — would break this silently.
    #[test]
    fn a_requeue_kick_and_a_lifecycle_command_never_fire_in_the_same_pass() {
        let policies = policies();
        let mut kicks = 0usize;
        let mut commands = 0usize;
        for (label, vm, now, policy_index) in joint_cells() {
            let requeue = requeue_decision(&vm, policies[policy_index].1.as_ref(), now);
            let command = lifecycle_command(vm.spec.run_strategy, vm.status.phase);
            if requeue == Requeue::Kick {
                kicks += 1;
                assert!(
                    command.is_none(),
                    "kick and {command:?} in one pass: {label}"
                );
                assert_eq!(
                    vm.status.phase,
                    VmPhase::Failed,
                    "a kick outside Failed: {label}"
                );
            }
            if command.is_some() {
                commands += 1;
                assert!(
                    matches!(requeue, Requeue::Not | Requeue::Reset),
                    "{command:?} alongside {requeue:?}: {label}"
                );
            }
        }
        // Both actually occur; an invariant nothing reaches proves nothing.
        assert!(
            kicks > 0 && commands > 0,
            "kicks={kicks} commands={commands}"
        );
    }

    /// The one overlap that IS allowed, and why it is harmless: Reset writes
    /// nothing but the VM's own retry bookkeeping, so it can share a pass
    /// with a command without the two meaning anything to each other. It is
    /// also the only requeue answer that can: Arm and Kick both need Failed,
    /// and Failed gets no command.
    #[test]
    fn only_reset_may_share_a_pass_with_a_command() {
        let policies = policies();
        let mut shared = 0usize;
        for (label, vm, now, policy_index) in joint_cells() {
            let requeue = requeue_decision(&vm, policies[policy_index].1.as_ref(), now);
            if lifecycle_command(vm.spec.run_strategy, vm.status.phase).is_none() {
                continue;
            }
            assert_ne!(requeue, Requeue::Arm, "{label}");
            assert_ne!(requeue, Requeue::Kick, "{label}");
            if requeue == Requeue::Reset {
                shared += 1;
            }
        }
        assert!(
            shared > 0,
            "the permitted overlap never occurs, so it is not being tested"
        );
    }

    /// Quarantined is the phase that exists so nothing automatic touches the
    /// VM, and both halves have to honour it — `lifecycle_command` by not
    /// arguing with it, `requeue_decision` by not treating it as a failure to
    /// heal. Stated over the whole space because it is the one guarantee an
    /// operator is given by name (see BACKEND_DIED_REASON in the agent).
    #[test]
    fn nothing_automatic_touches_a_quarantined_vm() {
        let policies = policies();
        for (label, vm, now, policy_index) in joint_cells() {
            if vm.status.phase != VmPhase::Quarantined {
                continue;
            }
            assert_eq!(
                lifecycle_command(vm.spec.run_strategy, vm.status.phase),
                None,
                "{label}"
            );
            let requeue = requeue_decision(&vm, policies[policy_index].1.as_ref(), now);
            assert!(
                matches!(requeue, Requeue::Not | Requeue::Reset),
                "{requeue:?} on a quarantined vm: {label}"
            );
        }
    }

    /// The retry bookkeeping only ever survives a phase that is still Failed:
    /// the moment the VM leaves it, the counters are cleared. Without this a
    /// VM that failed once, recovered, and failed again a week later would
    /// start its second life on the far end of the backoff curve.
    #[test]
    fn leaving_failed_always_clears_the_bookkeeping() {
        let policies = policies();
        for (label, vm, now, policy_index) in joint_cells() {
            if vm.status.phase == VmPhase::Failed {
                continue;
            }
            let has_bookkeeping =
                vm.status.requeue_attempts > 0 || vm.status.last_requeue.is_some();
            let requeue = requeue_decision(&vm, policies[policy_index].1.as_ref(), now);
            assert_eq!(
                requeue == Requeue::Reset,
                has_bookkeeping,
                "{requeue:?} with bookkeeping={has_bookkeeping}: {label}"
            );
        }
    }

    fn vm_with(run_strategy: RunStrategy) -> Vm {
        controller_api::resources::new_vm(
            "t",
            controller_api::VmSpec {
                cluster_selector: Default::default(),
                node_selector: Default::default(),
                anti_affinity: Vec::new(),
                node_name: None,
                cluster_name: None,
                run_strategy,
                tenant: None,
                vm: serde_json::json!({ "vcpus": 1 }),
            },
        )
    }

    /// The agent has no RunStrategy type: the variant name travels in
    /// spec_json and its own serde is what has to accept it. The other half
    /// of the contract is guarded in the agent's types.rs.
    #[test]
    fn the_run_strategy_travels_as_the_agents_desired_state() {
        for (strategy, spelling) in [
            (RunStrategy::Running, "Running"),
            (RunStrategy::Stopped, "Stopped"),
            (RunStrategy::Paused, "Paused"),
        ] {
            let doc: serde_json::Value =
                serde_json::from_str(&build_spec_json(&vm_with(strategy)).unwrap()).unwrap();
            assert_eq!(doc["desired"], spelling);
            // and nothing else about the spec is touched on the way through
            assert_eq!(doc["vcpus"], 1);
        }
    }

    /// The guest's hostname comes from the object's own name, and this tier
    /// is where it is filled in because it is the last one that knows it: a
    /// node holds a uid and nothing else, so a seed built down there could
    /// only ever derive a uuid for a hostname.
    ///
    /// And it is filled in only where it was left out. A VM with no
    /// cloud-init block gets nothing added to its spec at all, which is the
    /// property the whole feature is judged on.
    #[test]
    fn the_seeds_hostname_comes_from_the_vm_object_and_only_when_it_was_left_out() {
        let seeded = |cloud_init: serde_json::Value| {
            let mut vm = bound_to(None);
            vm.metadata.name = "web-1".into();
            vm.spec.vm = serde_json::json!({"vcpus": 1, "cloud_init": cloud_init});
            let doc: serde_json::Value =
                serde_json::from_str(&build_spec_json(&vm).unwrap()).unwrap();
            doc
        };

        let filled = seeded(serde_json::json!({"user_data": "x"}));
        assert_eq!(filled["cloud_init"]["local_hostname"], "web-1");
        assert_eq!(filled["cloud_init"]["user_data"], "x", "untouched");

        // Somebody who said one keeps it.
        let theirs = seeded(serde_json::json!({"user_data": "x", "local_hostname": "chosen"}));
        assert_eq!(theirs["cloud_init"]["local_hostname"], "chosen");

        // No block, nothing added: the spec that goes down is the spec that
        // came in, plus the `desired` this function has always written.
        let mut plain = bound_to(None);
        plain.spec.vm = serde_json::json!({"vcpus": 1});
        let doc: serde_json::Value =
            serde_json::from_str(&build_spec_json(&plain).unwrap()).unwrap();
        assert!(doc.get("cloud_init").is_none());
        assert_eq!(
            doc.as_object().map(|o| o.len()),
            Some(2),
            "vcpus and desired, and nothing invented"
        );
    }
}
