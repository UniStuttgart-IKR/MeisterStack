// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Node candidates, placement previews, and compare-and-swap VM binding.

use super::*;

/// Labels of all VMs bound to this candidate, including VMs that have not started.
/// Anti-affinity must account for reservations made earlier in the same pass.
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

/// Condition types used by candidate health checks and diagnostics.
pub(crate) fn condition_types(conditions: &[controller_api::NodeCondition]) -> Vec<String> {
    conditions.iter().map(|c| c.type_.clone()).collect()
}

/// Build candidates without changing readiness or reserving capacity.
/// Readiness comes from shared status and heartbeat age, independent of which
/// replica owns a session. Unlike live placement, this path uses `schedulable`
/// without applying the node drain flag.
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

/// Expire shared heartbeats and build candidates from the same node listing.
/// `alive` reflects shared readiness; `connected` also requires a local session.
/// Subtract the caller's reservation snapshot, which is also used by the reaper.
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

/// Backend localities indexed by node and driver, from this pass's node listing.
pub(super) type NodeLocalities = BTreeMap<String, BTreeMap<String, Locality>>;

/// Preview volume resolution and scheduling without spending capacity or binding.
/// A preview is advisory: concurrent creates and per-VM refusal history may change
/// the eventual placement.
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

/// Select a node from volume-compatible candidates, preferring nodes with the data.
/// The preview and live placement share this decision. On failure, return the
/// candidate count and a reason derived from the candidates actually considered.
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

/// Include ready nodes whose sessions belong to another controller replica.
/// A local session remains reachable even if its stored endpoint is stale.
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

/// Suppress a local scheduling failure when another replica could place the VM.
/// Only a fleet-wide failure is published on the VM; this check reserves nothing.
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
    // Read volume constraints before locking candidates, since these reads await
    // etcd. Placement later chooses and spends capacity under one lock so other
    // VMs in this pass see the updated capacity and anti-affinity occupancy.
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
    // A claim this guest holds from an attempt that did not bind (R3-F05). `hold` already
    // subtracted it; give it back on the decision's copy only, or the guest is refused by
    // its own claim. The shared list keeps it spent for other VMs until used or reaped.
    let standing = p.held.iter().find(|r| r.is_placement_of(&vm)).cloned();
    let decision = {
        let mut nodes = p.nodes.lock().unwrap();
        // Filter a copy: later VMs in this pass are measured against the shared list.
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
            // A replica with no local candidate must not overwrite a valid sibling's view.
            // Check fleet-wide node evidence before publishing a refusal. If another replica
            // can place the VM, leave it alone; only the session owner allocates and spends
            // capacity. Otherwise publish the shared fleet-wide reason.
            let Some((category, reason)) = fleet_verdict(p, &vm, &bindings, &refused, here).await?
            else {
                debug!(
                    known,
                    "no machine here, but somebody else holds one; leaving it"
                );
                return Ok(());
            };
            // Store the detailed Pending explanation for API readers, but use only its
            // bounded category as a metric label.
            p.pending.note(category);
            debug!(known, "no schedulable node anywhere, staying pending");
            return note_vm_pending(p, &vm, category, reason).await;
        }
    };
    // The decision above is a snapshot opinion; siblings and migrations can spend the same
    // room (R3-F05). From here the store decides: claim, confirm, bind under it, release.
    let mine = match claim(p.store, &vm, &node).await? {
        Claimed::Fresh(mine) => mine,
        Claimed::Standing(mine) if mine.spec.node == node => mine,
        // One guest, one claim: the standing claim elsewhere wins. Its owner binds
        // within the tick, or the reaper takes it after `STALE_PLACEMENT_AFTER_SECS`.
        Claimed::Standing(mine) => {
            debug!(node = %node, claimed = %mine.spec.node,
                   "this guest is already claimed onto another machine; leaving it");
            return Ok(());
        }
        Claimed::Gone => return Ok(()),
    };
    match controller_api::capacity::claim_holds(p.store, &mine, p.overcommit).await {
        Ok(true) => {}
        // An earlier claim in etcd order took the room; release ours and retry next pass.
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
        // A failed read is not a passed check (R3-F04). The claim stands and keeps
        // the room spoken for; the next pass adopts it and asks again.
        Err(e) => {
            return Err(e.context(format!(
                "vm {}: the room on {node} could not be confirmed; nothing was bound",
                vm.metadata.name
            )));
        }
    }
    // CAS on the object this pass read (a retry onto a newer one could move a placed VM);
    // it also compares the claim's revision, so a reaped claim cannot become a binding.
    let mut bound = vm;
    bound.spec.node_name = Some(node.clone());
    // What the scheduler said about the last pass is answered by the binding
    // itself; leaving it would make a placed VM carry the sentence that said
    // it could not be placed — and the category with it. Clearing the FACT is
    // all there is to do: `settle_vm` reads it only while the VM is waiting.
    bound.status.placement = None;
    match p.store.update_if_standing(&bound, &mine).await {
        Ok(_) => {
            // Release only after the binding: until then the claim alone holds the room.
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
        // The VM or the claim changed under this pass; nothing was bound. Release
        // the claim if it still stands so the next pass starts clean.
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
    /// This pass wrote it; unique as a key, not yet proven to fit (`claim_holds`).
    Fresh(CapacityReservation),
    /// This guest's claim already stood (crashed attempt or sibling replica); its node is
    /// where the choice was recorded.
    Standing(CapacityReservation),
    /// The key was taken and then given back between the two round trips.
    Gone,
}

/// Write a create-only claim that this guest goes to `node`: one claim per placement across
/// replicas (R3-F05). The key is `place.<vm uid>`; anything else under it is refused, not
/// adopted, and left to the reaper.
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

/// Nodes whose configuration refusal has not expired.
/// Expired entries remain recorded but no longer exclude a node from placement.
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

/// Resolve referenced volume placement and pool locality.
/// Missing or unready volumes delay placement. A missing pool leaves locality
/// unknown, so the scheduler can only apply a preference.
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

/// Record a changed placement reason and emit one scheduling failure event.
/// The placement fact does not overwrite an existing observation of a running VM.
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
