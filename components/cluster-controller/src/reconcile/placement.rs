// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Placement: what the candidate list is, what a preview would decide, and
//! the binding itself. Moved out of `reconcile.rs` unchanged.

use super::*;

// What is still free on one node, `free_on`, lives in `controller_api::
// scheduler` since Astra finding R3-F05, 2026-09-24: the candidate list here
// and the confirmation a claim makes against the store both need exactly
// that number, and the confirmation is shared with the migration road.

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
    // What is promised to a guest a live migration is moving, which a sum
    // over the VM objects cannot see: the guest is still bound to the machine
    // it is LEAVING. A preview that left it out would answer "would place on
    // agent-2" about a machine whose last slot a migration is already flying
    // into. See Astra finding S07, 2026-09-23.
    let held = store.list::<CapacityReservation>().await?;
    // One read for the whole fleet's liveness: the heartbeat lives in its own
    // key since D-C7, and a LIST of ten nodes must not become eleven round
    // trips.
    let beats = store.beats::<Node>().await?;
    let mut out = Vec::new();
    for node in store.list::<Node>().await? {
        let name = node.metadata.name;
        let ready = node.status.ready && !heartbeat_expired(beats.get(&name).copied(), now);
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
    controller_api::hold(&mut out, &held);
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
///
/// `held` is what the fleet has promised to guests that are on their way but
/// not yet bound — a live migration's destination, and nothing else. It is
/// read by the caller rather than here, because the same listing is what the
/// reaper walks one step later in the same pass, and two readings of it could
/// disagree about which promises are standing.
pub(super) async fn expire_and_collect_nodes(
    store: &EtcdStore,
    sessions: &HashSet<String>,
    vms: &[Vm],
    held: &[CapacityReservation],
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
    // The fleet's heartbeats in one read — see `candidates_for_preview`.
    let beats = store.beats::<Node>().await?;
    for node in store.list::<Node>().await? {
        let name = node.metadata.name;
        let heard = beats.get(&name).copied();
        if let Some(last) = heard {
            telemetry::metrics::sessions().set_heartbeat_age(
                telemetry::metrics::PEER_NODE,
                &name,
                (now - last).num_milliseconds() as f64 / 1000.0,
            );
        }
        let mut ready = node.status.ready;
        if ready && heartbeat_expired(heard, now) {
            // ISO-8601 UTC rather than the Debug of an Option: the instant
            // is what an operator lines up against everything else in the log.
            let last = heard
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
            expire_vm_reports(store, vms, &name, heard, now).await;
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
    // The second subtraction, and the one `free_on` cannot make: room already
    // promised to a guest in flight. Applied here, where the list is built,
    // so that every reader of it — the VM loop, the migrations, a preview —
    // is measured against one number. See Astra finding S07, 2026-09-23.
    controller_api::hold(&mut out, held);
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
    // A claim this guest already holds, from an attempt that did not reach
    // the binding — a process killed between the claim and the write, a
    // confirmation that could not be read. Astra finding R3-F05, 2026-09-24.
    // `hold` took its room off the candidate list where the list was built,
    // as it takes every promise off; but this promise is this very guest's,
    // and measured against a node exactly itself too full the guest would be
    // refused by its own bookkeeping, every pass, for ever. So its own claim
    // is given back on the COPY the decision is made from — the copy and
    // never the shared list, because every other VM of this pass is measured
    // against the shared list and the room is spoken for until the claim is
    // used or reaped. The same `give_back` a migration makes for its own
    // promise.
    let standing = p.held.iter().find(|r| r.is_placement_of(&vm)).cloned();
    let decision = {
        let mut nodes = p.nodes.lock().unwrap();
        // A COPY of the list, filtered — never `retain` on the shared one.
        // `p.nodes` is the whole pass's candidate list and every VM after
        // this one is measured against it; removing a node here because THIS
        // vm was refused there would hide it from all of them.
        let mut candidates: Vec<Candidate> = nodes
            .iter()
            .filter(|c| !refused.contains(&c.name))
            .cloned()
            .collect();
        if let Some(ours) = &standing
            && let Some(c) = candidates.iter_mut().find(|c| c.name == ours.spec.node)
        {
            c.free = c.free.plus(ours.spec.size());
        }
        // Hard first: where a `node-local` volume IS, is where the VM runs.
        // Applied to the candidate list before any strategy sees it, because
        // it is not a matter of strategy — the same argument `feasible` makes.
        let allowed: Vec<Candidate> =
            controller_api::feasible_for_volumes(&bindings, candidates.iter().collect())
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
    // Everything above this line is this replica's OPINION: formed from a
    // snapshot, booked in a process-local mutex, and every sibling replica
    // has one just like it. Astra finding R3-F05, 2026-09-24: two opinions
    // about one node's last slot were both written down as bindings — B read
    // 8 GiB free, A reserved and confirmed 6 for a migration, B bound 6 from
    // its old snapshot, and the machine carried 12 of 8. From here on the
    // store is the authority, in the four steps `CapacityReservationSpec`
    // sets out and the migration road takes in `prepare` and `settle`:
    // claim, confirm, bind under the claim, release.
    let mine = match claim(p.store, &vm, &node).await? {
        Claimed::Fresh(mine) => mine,
        Claimed::Standing(mine) if mine.spec.node == node => mine,
        // An earlier attempt, or a sibling in this very step, claimed this
        // guest onto a different machine. That claim is the one that stands
        // — one guest, one claim — and this pass does not second-guess it:
        // the sibling binds within the tick, or the reaper takes the claim
        // once it has stood for `STALE_PLACEMENT_AFTER_SECS` with the guest
        // unbound, and the pass after that decides afresh. The room spent on
        // `node` above stays spent for the rest of this pass, which costs
        // one VM one tick, as a lost binding always has.
        Claimed::Standing(mine) => {
            debug!(node = %node, claimed = %mine.spec.node,
                   "this guest is already claimed onto another machine; leaving it");
            return Ok(());
        }
        // Given back between the two round trips. Nothing is held, and the
        // next pass claims again.
        Claimed::Gone => return Ok(()),
    };
    match controller_api::capacity::claim_holds(p.store, &mine, p.overcommit).await {
        Ok(true) => {}
        // Somebody wrote a claim on this node's last room before this one
        // was written — a sibling's placement, a migration's `prepare` — and
        // in the store's own order theirs stands. Given back at once, and
        // measured again next pass against a list that has the winner on it.
        Ok(false) => {
            controller_api::capacity::release(p.store, &mine).await;
            telemetry::metrics::scheduling().conflict(telemetry::metrics::TIER_CLUSTER);
            p.pending.note(PendingReason::NoCapacity);
            return note_vm_pending(
                p,
                &vm,
                PendingReason::NoCapacity,
                format!(
                    "node {node} had room when this pass began and another claim took it \
                     first; measured again next pass"
                ),
            )
            .await;
        }
        // A reading that failed is not a passed check (Astra finding R3-F04).
        // The claim stands, so the room stays spoken for; the next pass finds
        // it in `held`, gives it back on its own copy of the list, and if the
        // scheduler names this node again adopts it and asks again.
        Err(e) => {
            return Err(e.context(format!(
                "vm {}: the room on {node} could not be confirmed; nothing was bound",
                vm.metadata.name
            )));
        }
    }
    // A plain CAS on the object this pass read, not a read-modify-write:
    // with several replicas scheduling at once the binding is exactly what
    // must NOT be retried onto a newer object — a retry would re-apply this
    // replica's choice over the winner's and move a VM that is already
    // placed. One write, one winner, and the loser is told. And under the
    // claim: the same transaction compares the claim's revision, so a claim
    // the reaper took or a sibling released cannot become a binding.
    let mut bound = vm;
    bound.spec.node_name = Some(node.clone());
    // What the scheduler said about the last pass is answered by the binding
    // itself; leaving it would make a placed VM carry the sentence that said
    // it could not be placed — and the category with it. Clearing the FACT is
    // all there is to do: `settle_vm` reads it only while the VM is waiting.
    bound.status.placement = None;
    match p.store.update_if_standing(&bound, &mine).await {
        Ok(_) => {
            // The room is given back HERE, in the arm where the binding took,
            // and not a line earlier. From this write on the guest is counted
            // on the node by `free_on` like any other VM bound there, and the
            // claim beside it is the same guest twice — the safe direction,
            // for the length of one round trip. Before the write, the claim
            // is the only thing holding the room at all.
            controller_api::capacity::release(p.store, &mine).await;
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
        // Either the VM moved under this pass — a client editing it, a
        // sibling that adopted this very claim and bound first — or the claim
        // did: reaped as stale, or released by a sibling whose confirmation
        // came out the other way. In both the binding did not happen, which
        // is what the guard is for. The claim, if it still stands, is given
        // back so that the next pass starts clean; a sibling that bound with
        // it releases it itself, and a release that finds nothing costs one
        // read.
        Err(StoreError::Conflict(why)) => {
            telemetry::metrics::scheduling().conflict(telemetry::metrics::TIER_CLUSTER);
            debug!(node = %node, %why, "lost the scheduling race; nothing was bound");
            controller_api::capacity::release(p.store, &mine).await;
        }
        Err(e) => return Err(e.into()),
    }
    Ok(())
}

/// What `claim` found at the key this guest's placement writes to.
enum Claimed {
    /// This pass wrote it. Unique as a KEY, which is not yet the same as
    /// fitting — see `controller_api::capacity::claim_holds`.
    Fresh(CapacityReservation),
    /// A claim for this very guest was already standing: an earlier attempt
    /// wrote it and the process died before the binding, or a sibling
    /// replica is in this step for the same guest right now. Its node is
    /// where the choice was written down.
    Standing(CapacityReservation),
    /// The key was taken and then given back between the two round trips.
    Gone,
}

/// Step one of the commit: write down, create-only, that this guest is going
/// to `node` — so that one guest's placement has exactly one claim, on every
/// replica, and a second replica reaching this step finds the room already
/// spoken for by this very guest rather than booking it twice.
///
/// The key is `place-<vm uid>`, so whatever stands under it and is not this
/// guest's claim is nothing this control plane wrote; it is refused rather
/// than adopted, and the reaper — which finds no guest for it — takes it.
async fn claim(store: &EtcdStore, vm: &Vm, node: &str) -> anyhow::Result<Claimed> {
    let want = CapacityReservation::for_placement(vm, node);
    match store.create(&want).await {
        Ok(mine) => Ok(Claimed::Fresh(mine)),
        Err(StoreError::AlreadyExists(_)) | Err(StoreError::Terminating(_)) => {
            match store.get::<CapacityReservation>(&want.metadata.name).await {
                Ok(standing) if standing.is_placement_of(vm) => Ok(Claimed::Standing(standing)),
                Ok(other) => anyhow::bail!(
                    "the claim key {} is held by something that is not this guest's claim \
                     (vm uid {}); leaving it to the reaper",
                    want.metadata.name,
                    other.spec.vm_uid
                ),
                Err(StoreError::NotFound(_)) => Ok(Claimed::Gone),
                Err(e) => Err(e.into()),
            }
        }
        Err(e) => Err(e.into()),
    }
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
            // Its own fact, and that is what keeps the old sentence true:
            // this pass says why a VM is WAITING, it does not decide what the
            // VM is doing. `settle_vm` reads it only where a wait is what the
            // VM is in — a running guest whose newly added disk is not ready
            // is still running.
            v.status.placement = Some(controller_api::VmPlacement {
                reason: category.category(),
                message: reason.clone(),
                at: Utc::now(),
            });
        })
        .await?;
    events::record(
        p.store,
        warning(vm, events::reason::FAILED_SCHEDULING, reason),
    )
    .await;
    Ok(())
}
