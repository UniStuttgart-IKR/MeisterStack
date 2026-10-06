// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Node evacuation and persisted drain progress.

use super::*;

/// Re-evaluate the standing drain request each pass.
/// Progress is derived from stored objects, so a controller restart needs no
/// in-memory continuation. Clear drain status when the request is removed.
pub(super) async fn drain_nodes(p: &Pass<'_>, vms: &[Vm]) -> anyhow::Result<()> {
    for node in p.store.list::<Node>().await? {
        let name = node.metadata.name.clone();
        if !node.spec.drain {
            // The evidence goes when the drain does. An operator who
            // undrained a node must not be left reading last week's list of
            // what would not move — it is not true any more, and a status
            // that outlives its question is worse than none.
            if node.status.draining.is_some() {
                p.store
                    .mutate::<Node, _>(&name, |n| n.status.draining = None)
                    .await?;
            }
            continue;
        }
        if let Err(e) = drain_node(p, &name, vms).await {
            warn!(node = %name, error = format!("{e:#}"), "draining this node failed");
        }
    }
    Ok(())
}

/// Apply evacuation policy to VMs bound to or still reported on this node.
/// A removed binding alone does not prove that the old guest has been torn down.
pub(super) async fn drain_node(p: &Pass<'_>, node: &str, vms: &[Vm]) -> anyhow::Result<()> {
    let mut leaving: Vec<String> = Vec::new();
    let mut staying: Vec<controller_api::StayingVm> = Vec::new();
    // A drain is FINISHED when nothing is on its way and everything left is
    // left for a reason waiting does not change. Both halves are tracked
    // here, because `complete` is written once and read by scripts.
    let mut settled = true;

    for vm in vms {
        let name = vm.metadata.name.clone();
        // On its way out under its own steam. Nothing to decide, and nothing
        // to say about it — it is leaving either way.
        if vm.is_deleting() {
            continue;
        }
        if vm.spec.node_name.as_deref() != Some(node) {
            // Not bound here. Still HERE if the node's last report named it,
            // which is exactly the window between the binding falling and the
            // old node letting go.
            if vm.status.node_name.as_deref() == Some(node) {
                leaving.push(name);
                settled = false;
            }
            continue;
        }
        let facts = match drain_facts(p, vm, node).await? {
            Some(facts) => facts,
            // A disk this tier cannot see the state of yet. Conservative on
            // purpose: an unknown disk is not a disk that may be left behind,
            // and the drain says so rather than moving the VM on a guess.
            None => {
                staying.push(controller_api::StayingVm {
                    vm: name,
                    reason: controller_api::StayReason::NoTarget.as_str().to_string(),
                    message: format!(
                        "{} waits: one of its volumes is not ready, so where its bytes are is not \
                         yet knowable",
                        vm.metadata.name
                    ),
                });
                settled = false;
                continue;
            }
        };
        match controller_api::drain::verdict(vm, &facts) {
            // Already going, by a mark from an earlier pass.
            controller_api::drain::Verdict::Moving => {
                leaving.push(name);
                settled = false;
            }
            // Standing still, so the binding can simply fall — the same one
            // write a client makes with `vm reschedule`, made here on the
            // operator's behalf because that is what a drain IS.
            controller_api::drain::Verdict::Reschedule => {
                p.store
                    .mutate_if::<Vm, _>(&name, &vm.metadata.uid, |v| v.spec.node_name = None)
                    .await?;
                events::record(
                    p.store,
                    normal(
                        vm,
                        events::reason::UNBOUND,
                        format!("node {node} is being drained; placing this stopped vm again"),
                    ),
                )
                .await;
                info!(vm = %name, node, "drained: the binding fell");
                leaving.push(name);
                settled = false;
            }
            // The owner allowed a reboot. The mark is the whole of what
            // happens here; `evacuate` carries it from there.
            controller_api::drain::Verdict::Restart => {
                p.store
                    .mutate_if::<Vm, _>(&name, &vm.metadata.uid, |v| {
                        v.status.evacuating = Some(controller_api::Evacuating {
                            from: node.to_string(),
                            step: controller_api::EvacuationStep::Stopping
                                .as_str()
                                .to_string(),
                            since: Utc::now(),
                        });
                    })
                    .await?;
                events::record(
                    p.store,
                    normal(
                        vm,
                        events::reason::UNBOUND,
                        format!("node {node} is being drained; moving this vm by restart"),
                    ),
                )
                .await;
                info!(vm = %name, node, "drained: moving by restart");
                leaving.push(name);
                settled = false;
            }
            // Create live-migration intent for the migration reconciler to execute.
            // Reuse an in-flight migration for the VM instead of creating competing moves.
            controller_api::drain::Verdict::Live => {
                if let Err(e) = crate::migration::start_for_drain(p.store, vm, node).await {
                    warn!(vm = %name, node, error = %format!("{e:#}"),
                          "could not ask for a live migration");
                }
                leaving.push(name);
                settled = false;
            }
            controller_api::drain::Verdict::Stays(reason) => {
                staying.push(controller_api::StayingVm {
                    vm: name.clone(),
                    reason: reason.as_str().to_string(),
                    message: controller_api::drain::sentence(reason, &name, &facts),
                });
                settled &= reason.settles_a_drain();
            }
        }
    }

    // Sorted, so two passes over the same facts write the same document and
    // the second one writes nothing.
    leaving.sort();
    // Read before the document is finished, because the cumulative half is
    // derived from the difference between the two.
    let current: Node = p.store.get(node).await?;
    let previous = current.status.draining.as_ref();
    let moved_total =
        previous.map_or(0, |d| d.moved_total) + departed(previous, &leaving, &staying, vms, node);
    let draining = controller_api::Draining {
        leaving: leaving.len() as u32,
        complete: settled && leaving.is_empty(),
        leaving_vms: leaving,
        staying: staying.len() as u32,
        reasons: staying,
        moved_total,
    };
    // Only on a change: a drain that has come to rest is a level condition
    // this pass reaches every five seconds, and a write per pass would churn
    // etcd revisions while nothing about the node happened.
    if current.status.draining.as_ref() == Some(&draining) {
        return Ok(());
    }
    let complete = draining.complete;
    let leaving_now = draining.leaving;
    p.store
        .mutate::<Node, _>(node, |n| n.status.draining = Some(draining.clone()))
        .await?;
    debug!(node, leaving = leaving_now, complete, "drain observed");
    Ok(())
}

/// Count previously leaving VMs that no longer appear on either drain list
/// and are neither bound to nor reported on this node. Deleted VMs do not count.
pub(super) fn departed(
    previous: Option<&controller_api::Draining>,
    leaving: &[String],
    staying: &[controller_api::StayingVm],
    vms: &[Vm],
    node: &str,
) -> u32 {
    let Some(previous) = previous else {
        // No previous list to compare against: the first pass of a drain has
        // moved nothing yet by definition, and reading it as "everything that
        // is not here left" would count the whole fleet.
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
                        && v.spec.node_name.as_deref() != Some(node)
                        && v.status.node_name.as_deref() != Some(node)
                })
        })
        .count() as u32
}

/// The two facts the drain table needs about one VM that its object does not
/// carry.
///
/// `None` means a disk whose state this tier cannot read yet — which is not
/// the same as a VM with no disks, and must not be treated as one.
pub(super) async fn drain_facts(
    p: &Pass<'_>,
    vm: &Vm,
    node: &str,
) -> anyhow::Result<Option<controller_api::drain::DrainFacts>> {
    // Read off the spec the same way the scheduler reads the device requests
    // out of it: this control plane carries `spec.vm` unopened except for the
    // few fields it genuinely has to answer about, and "does this VM have a
    // passthrough device" is one of them, because it is what decides that no
    // live migration will ever move it.
    let has_device = vm
        .spec
        .vm
        .get("devices")
        .and_then(serde_json::Value::as_array)
        .is_some_and(|d| !d.is_empty());
    let node_local_disk = match volume_bindings(p.store, vm).await? {
        Bindings::Ready(bindings) => bindings
            .into_iter()
            .find(|b| b.locality == Some(Locality::NodeLocal) && b.node.as_deref() == Some(node))
            .map(|b| b.volume),
        Bindings::NotReady(_) => return Ok(None),
    };
    // Somewhere to go, and whether anything there could take this guest's
    // saved state. Asked once, because the second answer is the sentence the
    // node's own line will carry when there is nowhere.
    let (live_target, live_refusal) = live_target_exists(p, vm, node);
    Ok(Some(controller_api::drain::DrainFacts {
        has_device,
        node_local_disk,
        // There IS live migration at this tier now, and the drain may use
        // it: a running guest whose owner never agreed to a reboot can still
        // be moved without one. Still gated on the vm actually running — a
        // stopped one has a cheaper verb and takes it two arms higher — and
        // on somewhere to go, which is the same question `migration_refusal`
        // asks at the api edge, answered here against the same fleet the
        // placement is measured against.
        live_possible: vm.status.phase().kind() == VmPhaseKind::Running && live_target,
        live_refusal,
    }))
}

/// Check the pass's remaining candidate capacity and migration machine profiles.
/// A refusal is reported as a drain blocker before creating a migration.
fn live_target_exists(p: &Pass<'_>, vm: &Vm, node: &str) -> (bool, Option<String>) {
    let nodes = p.nodes.lock().unwrap();
    // The source is cut away first, because "it could stay where it is" is
    // not an answer to "can it move". `feasible` is the same narrowing every
    // placement in this tree goes through — room, selectors, devices,
    // anti-affinity — so a drain and a migration cannot disagree about
    // whether a machine could take this guest.
    let elsewhere: Vec<Candidate> = nodes.iter().filter(|c| c.name != node).cloned().collect();
    let room = controller_api::feasible(vm, &elsewhere);
    if room.is_empty() {
        return (false, None);
    }
    // And the second narrowing, which is not about room at all: whether any
    // of those machines could hold this guest's saved STATE. It is
    // deliberately after `feasible` and not inside it — where to put a new
    // guest is a question about room, devices and selectors, and a machine
    // profile answers none of them.
    let source = nodes.iter().find(|c| c.name == node);
    let room: Vec<Candidate> = room.into_iter().cloned().collect();
    let (fits, refusals) = crate::migration::machines_that_fit(source, &room);
    if !fits.is_empty() {
        return (true, None);
    }
    // Nowhere, and the reason is worth carrying: without it the node's line
    // says the ordinary "evacuation is never" and an operator reads "the
    // owner said no" about a fleet that is the wrong shape. One sentence,
    // because they will all say the same thing.
    (false, refusals.into_iter().next())
}
