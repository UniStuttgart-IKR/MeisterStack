// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Ingest cluster heartbeat, inventory, placement and phase evidence. Only the
//! selected session speaker updates resource evidence; other sessions renew heartbeat.

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

    // Index cloud VMs by the UIDs used in cluster reports. Read before handling
    // an empty inventory: absence of the final VM can complete an unbind.
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

/// Mirror reported router phase, nodes and activeNode into cloud objects.
/// The cloud reconciler owns placement and rules; cluster reports own runtime
/// evidence. Process router reports even when the cluster has no VMs.
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
        let Some(phase) = controller_api::RouterPhaseKind::parse(&reported.phase) else {
            warn!(router = %router.metadata.name, phase = %reported.phase,
                  "unknown router phase from cluster");
            continue;
        };
        let message = (!reported.message.is_empty()).then(|| reported.message.clone());
        // The cluster's word, which is a node's driver's word where one came
        // up that road. Relayed, not re-derived — decision 1. The CLUSTER is
        // the speaker at this tier, which is what lets `Active` stand: it is
        // the party that looked.
        let (reason, message) = controller_api::RouterReason::read(&reported.reason, message);
        let said = controller_api::RouterReported::by(
            cluster,
            phase,
            reason,
            message.clone(),
            chrono::Utc::now(),
        );
        if router
            .status
            .reported
            .as_ref()
            .is_some_and(|held| held.same_word(&said))
            && router.status.active_node == reported.node
            && router.status.nodes == reported.nodes
        {
            continue;
        }
        let name = router.metadata.name.clone();
        let was = router.status.phase().kind();
        let active_was = router.status.active_node.clone();
        let tenant = router.spec.tenant.clone();
        let uid = router.metadata.uid.clone();
        // Pin the uid and re-check the binding on the live object; the listing's check may be
        // stale. (R3-F03)
        let mut applied = false;
        let result = store
            .mutate_if::<controller_api::Router, _>(&name, &uid, |r| {
                applied = r.status.cluster == cluster;
                if !applied {
                    return;
                }
                r.status.reported = Some(said.clone());
                r.status.active_node = reported.node.clone();
                r.status.nodes = reported.nodes.clone();
            })
            .await;
        match result {
            Ok(_) if !applied => {
                debug!(router = %name, cluster,
                       "the router was rebound between the listing and the write; the word is dropped");
            }
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
                            event_type: if phase == controller_api::RouterPhaseKind::Failed {
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
///
/// Two writes and not one since D-C7: the beat goes into a key of its own and
/// the OBJECT is touched only when `connected` really changes — which for a
/// cluster that is up is never, and was one full `Cluster` rewrite every ten
/// seconds before this.
pub(super) async fn beat(
    store: &EtcdStore,
    cluster: &str,
    at: DateTime<Utc>,
) -> anyhow::Result<()> {
    store.beat::<Cluster>(cluster, at).await?;
    // The read `mutate` used to make, made here so the write can be skipped.
    // A cluster with no object errors exactly as it did before.
    if store.get::<Cluster>(cluster).await?.status.connected {
        // Already up, and there is nothing else on this road to say: the beat
        // is recorded and the object stays exactly as it is.
        return Ok(());
    }
    store
        .mutate::<Cluster, _>(cluster, |c| c.status.connected = true)
        .await?;
    Ok(())
}

/// What one status says about the cluster ITSELF: how many nodes it has, how
/// many are ready, how much room they add up to, who they are, and what waits
/// on them for a node — in this cloud's words.
#[derive(Clone, Debug, Default)]
pub(super) struct ClusterFacts {
    pub(super) ready: u32,
    pub(super) total: u32,
    pub(super) vms: u32,
    pub(super) nodes: Vec<controller_api::NodeSummary>,
    pub(super) unplaced: Vec<controller_api::Capacity>,
    pub(super) unplaced_omitted: u32,
    /// None: the status said nothing about capacity, and nothing is written.
    pub(super) capacity: Option<proto::ClusterCapacity>,
}

impl ClusterFacts {
    pub(super) fn of(status: &ClusterStatus) -> Self {
        let (unplaced, unplaced_omitted) = unplaced_kept(status);
        Self {
            ready: status.nodes_ready,
            total: status.nodes_total,
            vms: status.vms.len() as u32,
            // Evidence, mirrored whole: the cluster's list of nodes replaces
            // this cloud's copy of it rather than being merged into it. A node
            // that has gone is a node that is gone, and a merge would keep it
            // on the object for ever — the same rule the VM phases below
            // follow and the same rule the tier below follows about what an
            // agent reported.
            nodes: status.nodes.iter().map(node_summary).collect(),
            unplaced,
            unplaced_omitted,
            capacity: status.capacity.clone(),
        }
    }

    /// Does this say anything the Cluster object does not already say?
    ///
    /// The same four questions the node half asks, one tier up, and the same
    /// omission: NOT the heartbeat. Pulled out so the decision can be made in
    /// a test without an etcd.
    pub(super) fn are_news_to(&self, status: &controller_api::ClusterStatus) -> bool {
        if !status.connected
            || status.nodes_ready != self.ready
            || status.nodes_total != self.total
            || status.vms != self.vms
            || status.nodes != self.nodes
            || status.unplaced != self.unplaced
            || status.unplaced_omitted != self.unplaced_omitted
        {
            return true;
        }
        self.capacity.as_ref().is_some_and(|cap| {
            status.capacity.vcpus != cap.vcpus
                || status.capacity.mem_mib != cap.mem_mib
                || status.capacity.capabilities != cap.capabilities
        })
    }

    /// Write these facts onto the status of a cluster a session speaks for.
    pub(super) fn write_onto(&self, status: &mut controller_api::ClusterStatus) {
        status.connected = true;
        status.nodes_ready = self.ready;
        status.nodes_total = self.total;
        status.vms = self.vms;
        status.nodes = self.nodes.clone();
        status.unplaced = self.unplaced.clone();
        status.unplaced_omitted = self.unplaced_omitted;
        if let Some(cap) = &self.capacity {
            status.capacity.vcpus = cap.vcpus;
            status.capacity.mem_mib = cap.mem_mib;
            status.capacity.capabilities = cap.capabilities.clone();
        }
    }
}

/// What waits at the cluster for a node, as this cloud keeps it: at most
/// [`controller_api::UNPLACED_CARRIED_MAX`] demands, and every one past them
/// counted with those the cluster already left out. A cluster that sends more
/// does not get them onto the Cluster object, every write of which is all of
/// it. (IKR-B78)
fn unplaced_kept(status: &ClusterStatus) -> (Vec<controller_api::Capacity>, u32) {
    let kept: Vec<controller_api::Capacity> = status
        .unplaced
        .iter()
        .take(controller_api::UNPLACED_CARRIED_MAX)
        .map(|d| controller_api::Capacity {
            vcpus: d.vcpus,
            mem_mib: d.mem_mib,
        })
        .collect();
    let cut = u32::try_from(status.unplaced.len() - kept.len()).unwrap_or(u32::MAX);
    (kept, status.unplaced_omitted.saturating_add(cut))
}

/// What the cluster says about ITSELF, written when it is news.
pub(super) async fn ingest_cluster_facts(
    store: &EtcdStore,
    cluster: &str,
    status: &ClusterStatus,
    at: DateTime<Utc>,
) -> anyhow::Result<()> {
    let facts = ClusterFacts::of(status);
    // The beat in its own key (D-C7), and the object only when the cluster's
    // own facts moved.
    store.beat::<Cluster>(cluster, at).await?;
    let current = store.get::<Cluster>(cluster).await?;
    if !facts.are_news_to(&current.status) {
        return Ok(());
    }
    if facts.unplaced_omitted > 0 && current.status.unplaced_omitted == 0 {
        warn!(
            cluster,
            omitted = facts.unplaced_omitted,
            "more vms wait there for a node than its status carries; its nodes offer no room \
               until fewer do"
        );
    }
    store
        .mutate::<Cluster, _>(cluster, |c| facts.write_onto(&mut c.status))
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
        bound_vcpus: n.bound_vcpus,
        bound_mem_mib: n.bound_mem_mib,
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
    ingest_images(store, cluster, &status.images, &status.nodes).await;
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

/// Select unbound VMs whose old cluster omits their UID from a complete inventory.
/// Incomplete reports cannot release the old cluster binding.
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
        let uid = vm.metadata.uid.clone();
        // The listing may be stale: pin the uid and re-read both facts on the live object.
        // (R3-F03)
        let mut applied = false;
        let result = store
            .mutate_if::<Vm, _>(&name, &uid, |v| {
                applied = v.spec.cluster_name.is_none()
                    && v.status.cluster_name.as_deref() == Some(cluster);
                if !applied {
                    return;
                }
                v.status.cluster_name = None;
                // The node went with the cluster: this cloud only ever knew
                // it because that cluster reported it, and there is nothing
                // left to report it.
                v.status.node_name = None;
                // Pending and not Stopped, exactly as one tier down: the VM
                // is nowhere, and the phase an operator reads has to say that
                // rather than describing a guest that no longer exists.
                // `settle_vm` makes it out of the two facts together — no
                // binding, no holder — and this word is the sentence.
                v.status.reported = Some(controller_api::VmReported::here(
                    VmPhaseKind::Pending,
                    controller_api::VmReason::Unbound,
                    Some(format!("cluster {cluster} let go; waiting to be placed")),
                    at,
                ));
                v.status.silence = None;
                v.status.volumes.clear();
                v.status.reschedules = v.status.reschedules.saturating_add(1);
                v.status.observed_at = Some(at);
            })
            .await;
        if let Err(e) = result {
            warn!(vm = %name, cluster, error = format!("{e:#}"), "clearing the old cluster failed");
            continue;
        }
        if !applied {
            debug!(vm = %name, cluster,
                   "bound again between the listing and the write; the let-go is dropped");
            continue;
        }
        info!(vm = %name, cluster, "the old cluster let go; the vm can be placed again");
    }
    Ok(())
}

/// Mirror node placement, attachment evidence and MAC addresses for bound VMs.
/// Node and volume fields can clear; address merging preserves cloud-owned floating
/// entries and treats an absent NIC list as compatibility with older reporters.
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
        let Some(vm) = known.iter().find(|v| v.metadata.uid == reported.id) else {
            continue;
        };
        let addresses = controller_api::addresses_with(&vm.status.addresses, &reported.nics);
        // Allow reports to clear placement and attached-volume lists.
        // Phase and reason are written separately by `ingest_phases`.
        let unchanged = vm.status.node_name == node
            && vm.status.volumes == volumes
            && vm.status.addresses == addresses;
        if !ours(vm) || unchanged {
            continue;
        }
        let name = vm.metadata.name.clone();
        // Pin the uid, re-check the binding on the live object and merge the MAC lines into its
        // current addresses: the floating pass writes the other half of that list. (R3-F03)
        let mut applied = false;
        if let Err(e) = store
            .mutate_if::<Vm, _>(&name, &reported.id, |v| {
                applied = ours(v);
                if !applied {
                    return;
                }
                v.status.node_name = node.clone();
                v.status.volumes = volumes.clone();
                v.status.addresses =
                    controller_api::addresses_with(&v.status.addresses, &reported.nics);
            })
            .await
        {
            warn!(vm = %name, cluster, error = format!("{e:#}"), "recording the node failed");
            continue;
        }
        if !applied {
            debug!(vm = %name, cluster,
                   "the vm was rebound between the listing and the write; the placement is dropped");
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
    for (reported, seen) in controller_api::observe(known, &status.vms, &ours) {
        let Some((vm, phase, reason, message)) = changed(cluster, reported, seen) else {
            continue;
        };
        let name = vm.metadata.name.clone();
        // Read off the object before the mutate borrows it: the tenant is on
        // the spec and travels with the event, so a member sees its own VMs'
        // history and nobody else's.
        let vm_tenant = vm.spec.tenant.clone();
        // The listing may be stale (name recreated, vm rebound): `mutate_if` pins the uid and
        // re-checks the binding on the live object; `applied` is reset on every retry. (R3-F03)
        let mut applied = false;
        let result = store
            .mutate_if::<Vm, _>(&name, &reported.id, |v| {
                applied = ours(v);
                if !applied {
                    return;
                }
                v.status.reported = Some(controller_api::VmReported::by(
                    cluster,
                    phase,
                    reason,
                    message.clone(),
                    at,
                ));
                // The cluster has spoken, so a silence concluded from its
                // absence is answered.
                v.status.silence = None;
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
            Ok(_) if applied => {
                note_phase(store, &name, &reported.id, phase, &message, &vm_tenant).await;
                info!(vm = %name, vm_id = %reported.id, ?phase, "phase observed")
            }
            Ok(_) => debug!(vm = %name, cluster,
                            "the vm was rebound between the listing and the write; the phase is dropped"),
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
) -> Option<(
    &'a Vm,
    VmPhaseKind,
    controller_api::VmReason,
    Option<String>,
)> {
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
        Observation::Changed(vm, phase, reason, message) => Some((vm, phase, reason, message)),
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
    phase: VmPhaseKind,
    message: &Option<String>,
    tenant: &Option<String>,
) {
    let kind = match phase {
        VmPhaseKind::Failed | VmPhaseKind::Quarantined => EventType::Warning,
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
