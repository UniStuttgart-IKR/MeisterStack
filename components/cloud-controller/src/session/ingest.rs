// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! What a cluster says about itself and the vms it holds for this cloud.
//!
//! `ingest_status` is the order the steps below are read in; each one owns
//! one kind of line out of the report and nothing else. The four kinds the
//! cluster mirrors upward beside its vms live next door in `inventory.rs`.
//! Verbatim out of `session.rs`.

use super::*;

/// A cluster status is the cluster's heartbeat and everything it has to say
/// about the objects this cloud handed it.
///
/// A sequence of named steps, in this order because each one is read by the
/// next: the heartbeat and the cluster's own facts, the inventory it mirrors
/// (images, pools, snapshots, volumes), the VM listing that every VM step
/// below is measured against, then the placements and finally the phases.
pub(super) async fn ingest_status(
    store: &EtcdStore,
    cluster: &str,
    status: &ClusterStatus,
    at: DateTime<Utc>,
    speaker: bool,
) -> anyhow::Result<()> {
    if !speaker {
        return beat(store, cluster, at).await;
    }
    ingest_cluster_facts(store, cluster, status, at).await?;
    ingest_inventory(store, cluster, status, at).await;

    // The cluster speaks the uids this cloud handed out on CreateVm, while the
    // store is keyed by name, so the list doubles as the index — the same
    // trade the cluster tier makes with the agent's reports, and the reason
    // both read their reports through `controller_api::mirror`.
    //
    // Listed BEFORE the empty-list shortcut below, because the one decision
    // that reads an empty list is the one that matters: a cluster that has
    // just let go of the last VM it had names none, and that is precisely the
    // proof `forget_unbound` waits for.
    let known = store.list::<Vm>().await?;
    forget_unbound(store, &known, cluster, status, at).await?;
    ingest_routers(store, cluster, status).await;

    if status.vms.is_empty() {
        return Ok(());
    }

    // Bound to THIS cluster, strictly: an unplaced VM has no cluster whose
    // word about it counts.
    let ours = |vm: &Vm| vm.spec.cluster_name.as_deref() == Some(cluster);

    ingest_placements(store, cluster, status, &known, ours).await;
    ingest_phases(store, cluster, status, &known, ours, at).await;
    Ok(())
}

/// What the cluster says about the routers it carries for this cloud, onto
/// the objects up here.
///
/// The one place that writes a router's `phase`, `nodes` and `activeNode` —
/// the cloud's own pass decides the cluster, the address and the rules and
/// stops there, because where a router actually IS is a fact only the fleet
/// holding it has. Which makes this the road a failover travels: the active
/// machine dies, the cluster makes the next one active, and ten seconds later
/// `router get` at the cloud names the new one.
///
/// Listed OUTSIDE the vms shortcut in `ingest_status` for the reason
/// `forget_unbound` is: a cluster holding routers and no VMs at all is an
/// ordinary state, and its routers still have to be read.
pub(super) async fn ingest_routers(store: &EtcdStore, cluster: &str, status: &ClusterStatus) {
    if status.routers.is_empty() {
        return;
    }
    let known = match store.list::<controller_api::Router>().await {
        Ok(routers) => routers,
        Err(e) => {
            warn!(cluster, error = format!("{e:#}"), "listing routers failed");
            return;
        }
    };
    for reported in &status.routers {
        let Some(router) = known.iter().find(|r| r.metadata.uid == reported.id) else {
            warn!(cluster, router_id = %reported.id,
                  "cluster reports a router this cloud does not know");
            continue;
        };
        // Only the cluster this router was handed to is heard about it. Two
        // fleets that both hold a copy — a cluster that kept one after the
        // binding moved — must not take turns writing the phase.
        if router.status.cluster != cluster {
            warn!(router = %router.metadata.name, cluster,
                  "router status from a cluster it is not bound to");
            continue;
        }
        let Some(phase) = controller_api::RouterPhase::parse(&reported.phase) else {
            warn!(router = %router.metadata.name, phase = %reported.phase,
                  "unknown router phase from cluster");
            continue;
        };
        let message = (!reported.message.is_empty()).then(|| reported.message.clone());
        if router.status.phase == phase
            && router.status.message == message
            && router.status.active_node == reported.node
            && router.status.nodes == reported.nodes
        {
            continue;
        }
        let name = router.metadata.name.clone();
        let was = router.status.phase;
        let active_was = router.status.active_node.clone();
        let tenant = router.spec.tenant.clone();
        let uid = router.metadata.uid.clone();
        let result = store
            .mutate::<controller_api::Router, _>(&name, |r| {
                r.status.phase = phase;
                r.status.message = message.clone();
                r.status.active_node = reported.node.clone();
                r.status.nodes = reported.nodes.clone();
            })
            .await;
        match result {
            Ok(_) => {
                if was != phase || active_was != reported.node {
                    info!(router = %name, cluster, ?phase, node = %reported.node,
                          "router observed");
                    events::record(
                        store,
                        Happening {
                            kind: controller_api::Router::KIND,
                            name: &name,
                            uid: &uid,
                            reason: events::reason::PHASE_CHANGED,
                            message: match &message {
                                Some(said) => format!("{} ({said})", phase.as_str()),
                                None if reported.node.is_empty() => phase.as_str().to_string(),
                                None => format!("{} on {}", phase.as_str(), reported.node),
                            },
                            event_type: if phase == controller_api::RouterPhase::Failed {
                                EventType::Warning
                            } else {
                                EventType::Normal
                            },
                            tenant: Some(&tenant),
                        },
                    )
                    .await;
                }
            }
            Err(e) => {
                warn!(router = %name, error = format!("{e:#}"), "writing router status failed")
            }
        }
    }
}

/// The heartbeat on its own: this session is up, and that is all a
/// non-speaking replica's copy of the report is allowed to say.
pub(super) async fn beat(
    store: &EtcdStore,
    cluster: &str,
    at: DateTime<Utc>,
) -> anyhow::Result<()> {
    store
        .mutate::<Cluster, _>(cluster, |c| {
            c.status.connected = true;
            c.status.last_heartbeat = Some(at);
        })
        .await?;
    Ok(())
}

/// What the cluster says about ITSELF: how many nodes it has, how many are
/// ready, how much room they add up to, and who they are.
pub(super) async fn ingest_cluster_facts(
    store: &EtcdStore,
    cluster: &str,
    status: &ClusterStatus,
    at: DateTime<Utc>,
) -> anyhow::Result<()> {
    let capacity = status.capacity.clone();
    let (ready, total, vms) = (
        status.nodes_ready,
        status.nodes_total,
        status.vms.len() as u32,
    );
    // Evidence, mirrored whole: the cluster's list of nodes replaces this
    // cloud's copy of it rather than being merged into it. A node that has
    // gone is a node that is gone, and a merge would keep it on the object
    // for ever — the same rule the VM phases below follow and the same rule
    // the tier below follows about what an agent reported.
    let nodes: Vec<controller_api::NodeSummary> = status.nodes.iter().map(node_summary).collect();
    store
        .mutate::<Cluster, _>(cluster, |c| {
            c.status.connected = true;
            c.status.last_heartbeat = Some(at);
            c.status.nodes_ready = ready;
            c.status.nodes_total = total;
            c.status.vms = vms;
            c.status.nodes = nodes.clone();
            if let Some(cap) = &capacity {
                c.status.capacity.vcpus = cap.vcpus;
                c.status.capacity.mem_mib = cap.mem_mib;
                c.status.capacity.capabilities = cap.capabilities.clone();
            }
        })
        .await?;
    Ok(())
}

/// One reported node, as the cloud keeps it. A straight copy: the cluster is
/// the only party that knows any of this, and a cloud that reworded it would
/// be a tier that could get it wrong.
pub(super) fn node_summary(n: &proto::NodeReport) -> controller_api::NodeSummary {
    controller_api::NodeSummary {
        name: n.name.clone(),
        ready: n.ready,
        schedulable: n.schedulable,
        drain: n.drain,
        labels: n.labels.clone().into_iter().collect(),
        vcpus: n.vcpus,
        mem_mib: n.mem_mib,
        capabilities: n.capabilities.clone(),
        vms: n.vms,
        conditions: n
            .conditions
            .iter()
            .map(|c| controller_api::NodeCondition {
                type_: c.r#type.clone(),
                message: c.message.clone(),
            })
            .collect(),
        // Absent from a cluster that is emptying nothing, and from a cluster
        // that predates the field — which reads the same way here, and has
        // to: the cloud shows a drain column for a machine it has evidence
        // about, and shows none for one it has not heard from.
        draining: n.draining.as_ref().map(|d| controller_api::Draining {
            leaving: d.leaving,
            leaving_vms: d.leaving_vms.clone(),
            moved_total: d.moved_total,
            staying: d.staying,
            complete: d.complete,
            reasons: d
                .reasons
                .iter()
                .map(|r| controller_api::StayingVm {
                    vm: r.vm.clone(),
                    reason: r.reason.clone(),
                    message: r.message.clone(),
                })
                .collect(),
        }),
        // Empty from a cluster that predates the field, which reads as "said
        // nothing" — and the derivation one level up (`cluster_accepts`)
        // keeps that meaning: nothing said is nothing refused, and the
        // refusal is made one tier down exactly as it was before.
        accepts: n.accepts.clone(),
    }
}

/// The objects the cluster mirrors upward beside its VMs. Each half says so
/// itself when it fails and none of them stops the others: a pool mirror that
/// cannot write is not a reason to drop the phases of every VM in the report.
pub(super) async fn ingest_inventory(
    store: &EtcdStore,
    cluster: &str,
    status: &ClusterStatus,
    at: DateTime<Utc>,
) {
    ingest_images(store, cluster, &status.images).await;
    if let Err(e) = ingest_pools(store, cluster, status).await {
        warn!(cluster, error = %format!("{e:#}"), "storage pool mirror failed");
    }
    if let Err(e) = ingest_snapshots(store, cluster, status, at).await {
        warn!(
            cluster,
            error = format!("{e:#}"),
            "mirroring snapshots failed"
        );
    }
    if let Err(e) = ingest_volumes(store, cluster, status, at).await {
        warn!(cluster, error = %format!("{e:#}"), "volume mirror failed");
    }
}

/// A VM whose cluster binding fell, and whose old cluster has stopped naming
/// it: the reschedule may go on.
///
/// The cloud tier's half of the same wait the tier below keeps for a node,
/// and the same reading of absence. The question is not "does this VM exist"
/// — absence never answers that — but *"does this cluster still name this
/// VM"*, and a list the cluster itself calls COMPLETE answers exactly that.
///
/// It is stricter than the node-level version in one way, and it can afford
/// to be: the reporter here is a control plane that owns its objects and says
/// whether it read all of them, so `vms_complete` is a real gate rather than
/// a hope. An incomplete list concludes nothing.
///
/// Narrow on purpose. A VM with a `spec.clusterName` is untouched however
/// silent its cluster is, and one that never had a `status.clusterName` was
/// never anywhere to leave.
/// Which of these VMs this report proves have left `cluster`.
///
/// The decision, as a value: an unbound VM whose `status.clusterName` still
/// names this cluster, and which a list the cluster itself calls COMPLETE
/// does not mention. An incomplete list proves nothing and yields nobody —
/// which is the whole of the difference from the tier below, where the
/// reporter is a node and absence never proves anything at all.
pub(super) fn leaving_cluster<'a>(
    vms: &'a [Vm],
    cluster: &str,
    status: &ClusterStatus,
) -> Vec<&'a Vm> {
    if !status.vms_complete {
        return Vec::new();
    }
    vms.iter()
        .filter(|vm| {
            vm.spec.cluster_name.is_none() && vm.status.cluster_name.as_deref() == Some(cluster)
        })
        .filter(|vm| !status.vms.iter().any(|r| r.id == vm.metadata.uid))
        .collect()
}

pub(super) async fn forget_unbound(
    store: &EtcdStore,
    vms: &[Vm],
    cluster: &str,
    status: &ClusterStatus,
    at: DateTime<Utc>,
) -> anyhow::Result<()> {
    for vm in leaving_cluster(vms, cluster, status) {
        let name = vm.metadata.name.clone();
        store
            .mutate::<Vm, _>(&name, |v| {
                v.status.cluster_name = None;
                // The node went with the cluster: this cloud only ever knew
                // it because that cluster reported it, and there is nothing
                // left to report it.
                v.status.node_name = None;
                // Pending and not Stopped, exactly as one tier down: the VM
                // is nowhere, and the phase an operator reads has to say that
                // rather than describing a guest that no longer exists.
                v.status.phase = VmPhase::Pending;
                v.status.message = Some(format!("cluster {cluster} let go; waiting to be placed"));
                v.status.volumes.clear();
                v.status.reschedules = v.status.reschedules.saturating_add(1);
                v.status.observed_at = Some(at);
            })
            .await?;
        info!(vm = %name, cluster, "the old cluster let go; the vm can be placed again");
    }
    Ok(())
}

/// The machine a VM ended up on, which is the one thing this tier cannot
/// derive: the cloud binds to a CLUSTER, and which node inside it runs the
/// VM is decided down there. Without it the fleet view — cluster, node, vm —
/// stops one level short, and the NODE column of every listing is a dash.
///
/// Its own small pass rather than a field `observe` watches, because the
/// same `VmStatusReport` is what an AGENT sends one tier down: there the
/// field is empty by construction, so a matcher that compared it would
/// call every agent report a change and write per report for ever.
///
/// Empty from a cluster means "not placed", which is a real state and the
/// one an unbound VM is in — so it CLEARS. That is different from the
/// backend-name rule next door, and deliberately: a name only ever
/// arrives, a placement can be given up.
///
/// Two more facts ride this same pass, and for the same reason (D5): the
/// cluster knows them, the cloud cannot derive them, and `observe` would
/// never carry them because it only fires when the PHASE or the message
/// changed. A disk arriving in a running guest changes neither.
///
///   * `status.volumes` — the evidence half of hot-plug. The cluster had
///     it and the cloud did not, so a tenant, who reads their VM at the
///     cloud and nowhere else, could see the intent in `spec.vm.volumes[]`
///     and never the observation.
///   * `status.pendingReason` — the closed word for why a VM is not
///     placed. It stopped one tier down, and a Pending VM at the cloud was
///     a dead end for everybody without a cluster credential.
///   * `status.addresses[]` — the MAC lines, which begin at a node's tap and
///     stopped at the cluster. This is where a tenant reads their VM, so it
///     is the one tier the address has to reach.
///
/// The addresses are the exception to the rule above about clearing, and the
/// reason is that they have TWO writers: the floating half is this cloud's
/// own object and `reconcile::floating` writes it. So this pass replaces the
/// MAC lines and leaves everything else standing, and the floating pass does
/// the mirror image of that. A cluster that names no MAC at all is a cluster
/// from before the field, and it changes nothing here — which is also what an
/// old AGENT looks like one tier further down, deliberately: neither of them
/// is saying "this VM has no addresses".
pub(super) async fn ingest_placements(
    store: &EtcdStore,
    cluster: &str,
    status: &ClusterStatus,
    known: &[Vm],
    ours: impl Fn(&Vm) -> bool,
) {
    for reported in &status.vms {
        let node = (!reported.node.is_empty()).then(|| reported.node.clone());
        let volumes: Vec<controller_api::VolumeAttachmentStatus> = reported
            .volumes
            .iter()
            .map(|v| controller_api::VolumeAttachmentStatus {
                name: v.name.clone(),
                attached: v.attached,
            })
            .collect();
        let pending_reason =
            (!reported.pending_reason.is_empty()).then(|| reported.pending_reason.clone());
        let Some(vm) = known.iter().find(|v| v.metadata.uid == reported.id) else {
            continue;
        };
        let addresses = controller_api::addresses_with(&vm.status.addresses, &reported.nics);
        // All three clear, and that is deliberate for each: a placement can
        // be given up, a disk can be detached, and a VM that has been placed
        // has no pending reason any more. What an EMPTY list may not do is
        // clear a list that a cluster too old to send one never filled — and
        // it cannot, because such a cluster's VMs never had one either.
        let unchanged = vm.status.node_name == node
            && vm.status.volumes == volumes
            && vm.status.pending_reason == pending_reason
            && vm.status.addresses == addresses;
        if !ours(vm) || unchanged {
            continue;
        }
        let name = vm.metadata.name.clone();
        if let Err(e) = store
            .mutate::<Vm, _>(&name, |v| {
                v.status.node_name = node.clone();
                v.status.volumes = volumes.clone();
                v.status.pending_reason = pending_reason.clone();
                v.status.addresses = addresses.clone();
            })
            .await
        {
            warn!(vm = %name, cluster, error = format!("{e:#}"), "recording the node failed");
            continue;
        }
        debug!(vm = %name, cluster, node = ?node, "placement observed");
    }
}

/// The phase half: what the cluster says each of its VMs is doing, written
/// onto the VM this cloud holds.
pub(super) async fn ingest_phases(
    store: &EtcdStore,
    cluster: &str,
    status: &ClusterStatus,
    known: &[Vm],
    ours: impl Fn(&Vm) -> bool,
    at: DateTime<Utc>,
) {
    for (reported, seen) in controller_api::observe(known, &status.vms, ours) {
        let Some((vm, phase, message)) = changed(cluster, reported, seen) else {
            continue;
        };
        let name = vm.metadata.name.clone();
        // Read off the object before the mutate borrows it: the tenant is on
        // the spec and travels with the event, so a member sees its own VMs'
        // history and nobody else's.
        let vm_tenant = vm.spec.tenant.clone();
        let result = store
            .mutate::<Vm, _>(&name, |v| {
                v.status.phase = phase;
                v.status.message = message.clone();
                // From the binding, never from the reporter: the only cluster
                // whose word counts for a VM is the one it was placed on.
                v.status.cluster_name = v.spec.cluster_name.clone();
                // The instant of the status this came out of, not the instant
                // of the write. The reconciler measures a status against what
                // it already knows about the VM, and stamping "now" here would
                // put every mirrored change just past the report that carried
                // it — postponing the decision it should have unblocked.
                v.status.observed_at = Some(at);
            })
            .await;
        match result {
            Ok(_) => {
                note_phase(store, &name, &reported.id, phase, &message, &vm_tenant).await;
                info!(vm = %name, vm_id = %reported.id, ?phase, "phase observed")
            }
            Err(e) => warn!(vm = %name, error = format!("{e:#}"), "writing vm status failed"),
        }
    }
}

/// What one reported line says about one VM, where it says something this
/// tier acts on. `None` is a line that was already answered by saying so.
pub(super) fn changed<'a>(
    cluster: &str,
    reported: &proto::VmStatusReport,
    seen: Observation<'a>,
) -> Option<(&'a Vm, VmPhase, Option<String>)> {
    match seen {
        Observation::Unknown => {
            // Not a phase we can file anywhere. It is also not nothing:
            // some cluster is running a VM in this cloud's name that this
            // cloud has no record of, and that deserves to be said out
            // loud rather than dropped at debug level.
            warn!(cluster, vm_id = %reported.id,
                  "cluster reports a cloud-managed vm this cloud does not know");
            None
        }
        Observation::NotBound(vm) => {
            warn!(vm = %vm.metadata.name, cluster,
                  "status from a cluster the vm is not bound to");
            None
        }
        Observation::BadPhase(vm) => {
            warn!(vm = %vm.metadata.name, phase = %reported.phase,
                  "unknown phase from cluster");
            None
        }
        Observation::Changed(vm, phase, message) => Some((vm, phase, message)),
    }
}

/// The event a landed phase leaves behind.
///
/// In the arm where the write LANDED, and only for a report that `observe`
/// already called a change — a peer reports every ten seconds and says the
/// same thing nearly every time, and the one that matters is the one that is
/// different. Warning for the two phases nothing automatic leaves on its own;
/// Normal for every ordinary transition.
pub(super) async fn note_phase(
    store: &EtcdStore,
    name: &str,
    uid: &str,
    phase: VmPhase,
    message: &Option<String>,
    tenant: &Option<String>,
) {
    let kind = match phase {
        VmPhase::Failed | VmPhase::Quarantined => EventType::Warning,
        _ => EventType::Normal,
    };
    events::record(
        store,
        Happening {
            kind: Vm::KIND,
            name,
            uid,
            reason: events::reason::PHASE_CHANGED,
            message: match message {
                Some(said) => format!("{} ({said})", phase.as_str()),
                None => phase.as_str().to_string(),
            },
            event_type: kind,
            tenant: tenant.as_deref(),
        },
    )
    .await;
}

impl Connection {
    /// A status: this session's heartbeat always, and its cluster's account of
    /// itself if this session holds the voice.
    pub(super) async fn status(&self, live: &Live, status: ClusterStatus) {
        let (Some(name), Some(id)) = (live.cluster.as_deref(), live.id) else {
            warn!("cluster status before hello, ignoring");
            return;
        };
        // One instant for the report and for everything it writes, so the two
        // can be compared at all.
        let at = Utc::now();
        let speaker = self.registry.record_report(id, &status, at);
        // What this cluster is holding for us, remembered whatever the rest
        // of the ingest does: it is read by the mirror pass in another task,
        // and it is the only thing that lets that pass tell "already there"
        // from "not sent yet". Every replica remembers what ITS session was
        // told, which is exactly the set it can act on.
        self.registry.secrets.observe(name, &status.secrets);
        if let Err(e) = ingest_status(&self.store, name, &status, at, speaker).await {
            warn!(
                cluster = name,
                error = format!("{e:#}"),
                "status ingest failed"
            );
        }
    }
}
