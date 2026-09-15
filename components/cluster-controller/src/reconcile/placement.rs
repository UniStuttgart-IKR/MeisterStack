// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Placement: what the candidate list is, what a preview would decide, and
//! the binding itself. Moved out of `reconcile.rs` unchanged.

use super::*;

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
pub(super) fn free_on(
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
pub(super) fn hosted_on(
    on: &str,
    vms: &[Vm],
    bound: fn(&Vm) -> Option<&str>,
) -> Vec<BTreeMap<String, String>> {
    vms.iter()
        .filter(|v| bound(v) == Some(on))
        .map(|v| v.metadata.labels.clone())
        .collect()
}

/// The condition TYPES of a node, in the order it reported them.
///
/// Types and not sentences: `Candidate::unhealthy` is read as a set and
/// printed as a column, and the sentence belongs on the object where an
/// operator reads it with `node get`.
pub(crate) fn condition_types(conditions: &[controller_api::NodeCondition]) -> Vec<String> {
    conditions.iter().map(|c| c.type_.clone()).collect()
}

/// The candidate list as a PREVIEW sees it: read-only, and from the shared
/// facts rather than from this replica's own.
///
/// `expire_and_collect_nodes` below cannot serve `?dryRun=All`, and the
/// reason is in its name: it WRITES — a node whose heartbeat has run out is
/// marked not-ready as a side effect of being counted. A request that asked
/// to be shown something must not change the fleet's opinion of a machine.
///
/// Two differences from the pass's list, and both are deliberate:
///
///   * `connected` comes from `status.ready`, which is in etcd and is
///     therefore the CLUSTER's word, rather than from this process's session
///     set. A preview answers "what would this cluster do", and which replica
///     happens to hold a node's session is not part of that question — asking
///     it would make the same preview come out differently depending on which
///     replica a client's request landed on.
///   * an expired heartbeat is read as not-ready here without the object
///     being changed, so the preview and the next pass agree about the node
///     even though only one of them writes it down.
pub(crate) async fn candidates_for_preview(
    store: &EtcdStore,
    overcommit: Overcommit,
) -> anyhow::Result<Vec<Candidate>> {
    let now = Utc::now();
    let vms = store.list::<Vm>().await?;
    let mut out = Vec::new();
    for node in store.list::<Node>().await? {
        let name = node.metadata.name;
        let ready = node.status.ready && !heartbeat_expired(node.status.last_heartbeat, now);
        out.push(Candidate {
            connected: ready,
            // No session map in this listing at all, so the two questions
            // have one answer here: whoever reads it wants to know which
            // machines are up.
            alive: ready,
            schedulable: node.spec.schedulable,
            unhealthy: condition_types(&node.status.conditions),
            free: free_on(&name, &node.status.capacity, &vms, overcommit),
            catalogue: node.status.capacity.capabilities,
            kind: CandidateKind::Node,
            hosted: hosted_on(&name, &vms, |v| v.spec.node_name.as_deref()),
            labels: node.spec.labels,
            accepts: node.spec.accepts,
            // Not a scheduling input; see `Candidate::machine`. It is here
            // because the choice of a live migration's DESTINATION is made
            // from this very list.
            machine: node.status.machine,
            name,
        });
    }
    Ok(out)
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
pub(super) async fn expire_and_collect_nodes(
    store: &EtcdStore,
    sessions: &HashSet<String>,
    vms: &[Vm],
    overcommit: Overcommit,
) -> anyhow::Result<(Vec<Candidate>, NodeLocalities)> {
    let now = Utc::now();
    let mut out = Vec::new();
    let mut localities = NodeLocalities::new();
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
        // What the silence means for the VMs on this machine. Beside the
        // heartbeat verdict because it is the same verdict, one object down:
        // a node nobody has heard from is a node whose VMs nobody can vouch
        // for. Level-triggered — see `expire_vm_reports` — so a node that was
        // already down before this existed is answered too, which is the case
        // the lab was actually in.
        if !ready {
            expire_vm_reports(store, vms, &name, node.status.last_heartbeat, now).await;
        }
        // Read off the object rather than off the Candidate, because a
        // Candidate is what a SCHEDULER sees and a locality is not a
        // scheduling input at this tier: it is a fact about the node that the
        // pool's status is derived from. A drained or unreachable node still
        // contributes it — what a backend is does not depend on whether the
        // machine is up today, and dropping it would make a pool's locality
        // flicker with the fleet's health.
        localities.insert(name.clone(), node.status.capacity.volume_localities.clone());
        out.push(Candidate {
            connected: ready && sessions.contains(&name),
            // The fleet's answer beside this replica's: the machine is up as
            // the STORE says, whichever replica happens to hold its session.
            // What a router's priority list is derived from — see
            // `Candidate::alive`.
            alive: ready,
            // A drain implies the cordon and does not SET it. The two are the
            // operator's two separate statements — "nothing new here" and
            // "what is here should leave" — and a controller that wrote
            // `schedulable = false` on their behalf would leave them, after
            // an undrain, with a node they never cordoned and cannot tell
            // from one they did.
            schedulable: node.spec.schedulable && !node.spec.drain,
            // What the machine said about ITSELF, which is the third half of
            // usable and the one neither of the two above can carry: the node
            // that wedged in the mini-chaos run was connected and
            // schedulable for three hours and could not execute a command.
            unhealthy: condition_types(&node.status.conditions),
            free: free_on(&name, &node.status.capacity, vms, overcommit),
            catalogue: node.status.capacity.capabilities,
            kind: CandidateKind::Node,
            hosted: hosted_on(&name, vms, |v| v.spec.node_name.as_deref()),
            labels: node.spec.labels,
            // What this MACHINE takes — the mirror image of a selector, and
            // the tier that has it: `NodeSpec.accepts` is an operator's word
            // about one machine and never leaves the cluster it is in.
            accepts: node.spec.accepts,
            machine: node.status.machine,
            name,
        });
    }
    Ok((out, localities))
}

/// What every node in this cluster said about every volume backend it runs,
/// by node name and then by backend name.
///
/// Built once per pass out of the same listing the candidates come from, so
/// that deriving a pool's locality costs no second read of the inventory.
pub(super) type NodeLocalities = BTreeMap<String, BTreeMap<String, Locality>>;

/// Bind an unbound VM to a node, or leave it Pending for the next pass.
/// What the scheduler would say about a VM that does not exist yet — the
/// `?dryRun=All` half of `POST /vms`.
///
/// The same three steps `place` takes, in the same order and through the same
/// functions: resolve the volumes, narrow by them, ask `decide`. What it does
/// NOT do is the fourth — spend, and write. So the sentence is true of the
/// cluster as it stands and is not a reservation: two previews in the same
/// second both say "would place on agent-1", and only a create takes it.
///
/// `status.message` is where it goes, because that is where the reason a real
/// VM is Pending already goes. A UI showing a model's suggestion reads one
/// field either way.
pub(crate) async fn would_place(
    store: &EtcdStore,
    scheduler: &dyn controller_api::Scheduler,
    overcommit: Overcommit,
    vm: &Vm,
) -> anyhow::Result<String> {
    let bindings = match volume_bindings(store, vm).await? {
        Bindings::Ready(bindings) => bindings,
        Bindings::NotReady(reason) => return Ok(reason),
    };
    let nodes = candidates_for_preview(store, overcommit).await?;
    // A VM that does not exist has been refused by nobody, so there is no
    // `refusing_now` here and nothing to filter — the one input `place` has
    // that a preview cannot have, and it can only ever make the real
    // placement narrower than the preview said. The report says so.
    let allowed: Vec<Candidate> =
        controller_api::feasible_for_volumes(&bindings, nodes.iter().collect())
            .into_iter()
            .cloned()
            .collect();
    let local: Vec<Candidate> =
        controller_api::preferred_for_volumes(&bindings, allowed.iter().collect())
            .into_iter()
            .cloned()
            .collect();
    Ok(
        match decide(scheduler, vm, &bindings, &allowed, &local, &nodes) {
            Ok(node) => format!("would place on {node}"),
            Err((_, (_, reason))) => reason,
        },
    )
}

/// Which node, or why none — over a candidate list somebody else owns.
///
/// Pulled out of `place` when `?dryRun=All` arrived, and pulled out rather
/// than copied for the obvious reason: a preview that answered this question
/// its own way would be a preview of a different scheduler. The pass calls it
/// under the lock and spends what it returns; the preview calls it over a
/// list nobody is spending from, and neither has an opinion of its own.
///
/// `allowed` is the volume-narrowed list and `local` is the preference inside
/// it — both computed by the caller, because the pass computes them from a
/// borrowed lock guard.
///
/// `Err` carries how many candidates were known and the sentence-with-category
/// for the object.
pub(super) fn decide(
    scheduler: &dyn controller_api::Scheduler,
    vm: &Vm,
    bindings: &[controller_api::VolumeBinding],
    allowed: &[Candidate],
    local: &[Candidate],
    nodes: &[Candidate],
) -> Result<String, (usize, (PendingReason, String))> {
    // Soft second, and with the fallback that makes it a preference: try the
    // nodes that already hold the data, and if the strategy can place nothing
    // there, try them all.
    match scheduler
        .assign(vm, local)
        .or_else(|| scheduler.assign(vm, allowed))
    {
        Some(node) => Ok(node),
        // Sentence and category together, from the same candidate list this
        // decision was made against. A volume that cut every candidate away
        // answers first: "no node can reach your disk" is a sharper sentence
        // than "nothing had room", and it is the true one whenever the
        // narrowing is what emptied the list.
        None if !bindings.is_empty() && allowed.is_empty() && !nodes.is_empty() => Err((
            nodes.len(),
            controller_api::volume_pending_reason(bindings, &nodes.iter().collect::<Vec<_>>()),
        )),
        // And the case that used to fall through that arm into a sentence
        // about the wrong machines: the narrowing left nodes standing and
        // `assign` threw all of them out anyway. The explanation is chosen
        // AFTER the assignment and measured against the list the assignment
        // actually saw — a node the volumes cut away is not a node this VM
        // "had no room on".
        None => Err((
            nodes.len(),
            controller_api::volume_nodes_unusable(bindings, &allowed.iter().collect::<Vec<_>>())
                .unwrap_or_else(|| {
                    let against = if bindings.is_empty() { nodes } else { allowed };
                    controller_api::pending_reason_of(vm, against)
                }),
        )),
    }
}

/// Whose machines these are, widened from "mine" to "the fleet's".
///
/// `Candidate::connected` is this replica's own reach — a session in THIS
/// process — because that is what decides who may command a machine. Whether
/// a machine EXISTS and is being held at all is a different question, and the
/// Node object answers it: `status.ready` and a `sessionEndpoint` mean some
/// replica has it. The same evidence `migration.rs::reaches` reads, and it is
/// only ever widening — a machine this replica can reach stays reachable
/// whatever the object says, so a stale endpoint cannot take a session away
/// from the replica that holds it.
pub(crate) fn widen_to_fleet(fleet: &mut [Candidate], nodes: &[Node]) {
    for candidate in fleet.iter_mut() {
        candidate.connected = candidate.connected
            || nodes.iter().any(|n| {
                n.metadata.name == candidate.name
                    && n.status.ready
                    && n.status.session_endpoint.is_some()
            });
    }
}

/// The same decision, asked of the whole FLEET instead of this replica.
///
/// `None` means somebody else can take this VM, so this replica must say
/// nothing: the machine is real, its session hangs off a sibling, and that
/// sibling's next pass will place it. `Some(sentence)` means nobody anywhere
/// can, and then every replica derives the same sentence out of the same
/// store — which is what makes it worth writing on the object at all.
///
/// The widening is `Node.status.sessionEndpoint`, exactly the evidence
/// `migration.rs::reaches` reads and for the same reason: a node object that
/// names a session endpoint is a node SOME replica is holding. Nothing is
/// spent here and nothing is bound — this only decides whether to speak.
async fn fleet_verdict(
    p: &Pass<'_>,
    vm: &Vm,
    bindings: &[controller_api::VolumeBinding],
    refused: &[String],
    here: (PendingReason, String),
) -> anyhow::Result<Option<(PendingReason, String)>> {
    let mut fleet: Vec<Candidate> = p.nodes.lock().unwrap().clone();
    if fleet.iter().all(|c| c.connected) {
        // This replica already sees the whole fleet, so its own verdict is
        // the fleet's and there is nothing to ask.
        return Ok(Some(here));
    }
    widen_to_fleet(&mut fleet, &p.store.list::<Node>().await?);
    let candidates: Vec<&Candidate> = fleet
        .iter()
        .filter(|c| !refused.contains(&c.name))
        .collect();
    let allowed: Vec<Candidate> = controller_api::feasible_for_volumes(bindings, candidates)
        .into_iter()
        .cloned()
        .collect();
    let local: Vec<Candidate> =
        controller_api::preferred_for_volumes(bindings, allowed.iter().collect())
            .into_iter()
            .cloned()
            .collect();
    match decide(p.scheduler, vm, bindings, &allowed, &local, &fleet) {
        Ok(_) => Ok(None),
        Err((_, sentence)) => Ok(Some(sentence)),
    }
}

pub(super) async fn place(p: &Pass<'_>, vm: Vm) -> anyhow::Result<()> {
    // Decide and SPEND under one lock, and let go before anything awaits: the
    // room this VM takes has to be gone before the next VM of the same pass
    // is measured against the node, or two creates in one breath would both
    // be told there is space for them, and no VM that must stay away from
    // them would be told they are empty. See `controller_api::spend`.
    //
    // An API-edge check cannot do this and that is why it is not the
    // authority: the objects it would have to count do not exist yet when it
    // runs. The edge may still refuse early — it just never decides.
    // What this VM's referenced volumes demand of the node it runs on, read
    // before the lock because it reads etcd. A VM with only inline disks asks
    // nothing and this is empty, which is every VM before this milestone.
    let bindings = match volume_bindings(p.store, &vm).await? {
        Bindings::Ready(bindings) => bindings,
        // A disk that is still being made is not a refusal, it is a wait —
        // the same wait a VM does for a node, said with its own reason.
        Bindings::NotReady(reason) => {
            p.pending.note(PendingReason::VolumeNotReady);
            return note_vm_pending(p, &vm, PendingReason::VolumeNotReady, reason).await;
        }
    };

    // Nodes that have already said they cannot serve this VM, and have not
    // said it long enough ago to be worth asking again. Cut before anything
    // else looks at the list, for the same reason the volume narrowing is:
    // it is not a matter of strategy, and a strategy that chose one of these
    // would produce one refused create per pass for ever.
    let refused = refusing_now(&vm, Utc::now());
    let decision = {
        let mut nodes = p.nodes.lock().unwrap();
        // A COPY of the list, filtered — never `retain` on the shared one.
        // `p.nodes` is the whole pass's candidate list and every VM after
        // this one is measured against it; removing a node here because THIS
        // vm was refused there would hide it from all of them.
        let candidates: Vec<&Candidate> = nodes
            .iter()
            .filter(|c| !refused.contains(&c.name))
            .collect();
        // Hard first: where a `node-local` volume IS, is where the VM runs.
        // Applied to the candidate list before any strategy sees it, because
        // it is not a matter of strategy — the same argument `feasible` makes.
        let allowed: Vec<Candidate> = controller_api::feasible_for_volumes(&bindings, candidates)
            .into_iter()
            .cloned()
            .collect();
        // Soft second, and with the fallback that makes it a preference: try
        // the nodes that already hold the data, and if the strategy can place
        // nothing there, try them all. After capacity rather than before it,
        // or a full node holding the data would strand the VM.
        let local: Vec<Candidate> =
            controller_api::preferred_for_volumes(&bindings, allowed.iter().collect())
                .into_iter()
                .cloned()
                .collect();
        let decision = decide(p.scheduler, &vm, &bindings, &allowed, &local, &nodes);
        // SPENT under the same lock the decision was made under, which is the
        // whole reason this block exists. A preview does not spend, and that
        // is the whole difference between it and this.
        if let Ok(node) = &decision {
            controller_api::spend(&mut nodes, node, &vm);
        }
        decision
    };
    let node = match decision {
        Ok(node) => node,
        Err((known, here)) => {
            // Nothing THIS replica can reach — which is not the same as
            // nothing at all, and the difference is what a tenant reads.
            //
            // Every replica runs this pass for an unbound VM, and each sees
            // only the machines whose sessions it holds (`Candidate::
            // connected`). So on a three-replica cluster the three took turns
            // writing their own view onto one object: "no connected candidate
            // offers [network/vxlan]" from the replica that holds no machine
            // with an overlay, then the real reason, then the first one
            // again. Seen in the lab while proving the class refusal.
            //
            // So the second opinion is fleet-wide, out of the Node objects
            // (`status.sessionEndpoint`, the same evidence `migration.rs::
            // reaches` reads): if ANY replica holds a machine that would take
            // this VM, this one says nothing at all and leaves the object
            // alone — the replica with the session will place it, and it is
            // the only one that may. The placement and the `free` it spends
            // stay exactly where they were.
            //
            // Only when nobody anywhere can take it does the sentence get
            // written — and then it is the same sentence on every replica,
            // because it is derived from the same store.
            let Some((category, reason)) = fleet_verdict(p, &vm, &bindings, &refused, here).await?
            else {
                debug!(
                    known,
                    "no machine here, but somebody else holds one; leaving it"
                );
                return Ok(());
            };
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
            debug!(known, "no schedulable node anywhere, staying pending");
            return note_vm_pending(p, &vm, category, reason).await;
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
    // it could not be placed — and the category with it.
    // Both of them live inside the phase since struktur 4, so one write
    // answers the sentence and the category together.
    let kind = bound.status.phase().kind();
    #[allow(deprecated)]
    bound.status.assign(VmPhase::of(kind, Utc::now()));
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

/// The nodes whose refusal of this VM is still standing at `now`.
///
/// Expiry rather than for ever, and the reason is the shape of the fact: a
/// node says `CannotServe` because of how it is CONFIGURED, and a
/// configuration changes. An operator who installs the driver or rolls out
/// the agent should get their node back as a candidate without having to
/// clear a field nobody told them about.
///
/// A refusal that has expired is simply not counted; it is not swept, because
/// the next create either succeeds — and nothing looks at the list again — or
/// is refused, which overwrites the entry.
pub(super) fn refusing_now(vm: &Vm, now: DateTime<Utc>) -> Vec<String> {
    vm.status
        .refused_by
        .iter()
        .filter(|r| r.until > now)
        .map(|r| r.node.clone())
        .collect()
}

/// What a VM's referenced volumes say, once they have all been read.
pub(super) enum Bindings {
    /// Every volume is `Ready`; here is what each demands of the node.
    Ready(Vec<VolumeBinding>),
    /// One of them is not there yet, and this sentence says which and why.
    /// Not a refusal — the disk is being made, and the VM waits.
    NotReady(String),
}

/// Resolve the `Volume` objects a VM refers to into what the scheduler needs.
///
/// Two objects per volume: the volume for `status.node`, and its pool for the
/// locality and the wiring. Both are read here rather than passed in because
/// this is the only place that knows which volumes a given VM names, and a
/// VM with no references — every VM before this milestone — reads nothing at
/// all.
pub(super) async fn volume_bindings(store: &EtcdStore, vm: &Vm) -> anyhow::Result<Bindings> {
    let names = vm.spec.referenced_volumes();
    if names.is_empty() {
        return Ok(Bindings::Ready(Vec::new()));
    }
    let mut bindings = Vec::new();
    for name in names {
        let volume: Volume = match store.get(&name).await {
            Ok(v) => v,
            // Refused at the create edge, so reaching here means the volume
            // was deleted afterwards. The VM waits rather than being placed
            // somewhere arbitrary — and says which volume it is waiting for.
            Err(StoreError::NotFound(_)) => {
                return Ok(Bindings::NotReady(format!(
                    "volume {name} does not exist here any more"
                )));
            }
            Err(e) => return Err(e.into()),
        };
        if volume.status.phase().kind() != VolumePhaseKind::Ready {
            return Ok(Bindings::NotReady(format!(
                "volume {name} is {}: {}",
                volume.status.phase().kind().as_str(),
                volume
                    .status
                    .phase()
                    .message()
                    .unwrap_or("waiting for it to be made")
            )));
        }
        // The pool carries the locality. A pool that has gone missing under a
        // Ready volume leaves the binding with no hard rule, which degrades
        // to the soft preference rather than to a wrong placement.
        let pool: Option<StoragePool> = match store.get(&volume.spec.pool).await {
            Ok(pool) => Some(pool),
            Err(StoreError::NotFound(_)) => None,
            Err(e) => return Err(e.into()),
        };
        bindings.push(VolumeBinding {
            volume: name,
            node: volume.status.node.clone(),
            locality: pool.as_ref().and_then(|p| p.status.locality),
            driver: pool.as_ref().map(|p| p.spec.driver.clone()),
            pool_nodes: pool.map(|p| p.spec.nodes).unwrap_or_default(),
        });
    }
    Ok(Bindings::Ready(bindings))
}

/// Say WHY on the VM, and only when it changed.
///
/// Lifted out of `place` because there are two callers now: the scheduler
/// finding no node, and a volume that is not ready yet. Both write the same
/// two fields and record the same event, and both must do it only on a
/// CHANGE — a level-triggered pass reaches the same conclusion every five
/// seconds, and an event per pass is a store filling at one write per VM per
/// tick.
pub(super) async fn note_vm_pending(
    p: &Pass<'_>,
    vm: &Vm,
    category: PendingReason,
    reason: String,
) -> anyhow::Result<()> {
    debug!(reason = %reason, "vm stays pending");
    if vm.status.phase().message() == Some(reason.as_str()) {
        return Ok(());
    }
    p.store
        .mutate::<Vm, _>(&vm.metadata.name, |v| {
            // The sentence and the category, both inside the phase, and the
            // phase itself left alone: this pass says why a VM is not placed,
            // it does not decide what the VM is doing.
            let kind = v.status.phase().kind();
            #[allow(deprecated)]
            v.status.assign(VmPhase::new(
                kind,
                category.category(),
                Some(reason.clone()),
                Utc::now(),
            ));
        })
        .await?;
    events::record(
        p.store,
        warning(vm, events::reason::FAILED_SCHEDULING, reason),
    )
    .await;
    Ok(())
}
