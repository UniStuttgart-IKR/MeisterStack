// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Which cluster a VM can go to, and the sentence that says why none can.
//! Moved out of `reconcile.rs` unchanged.

use super::*;

/// Subtract bound VM demand from aggregate Ready-node capacity, with overcommit.
/// This bounds cluster-wide demand; the cluster's node scheduler performs the
/// more precise per-node feasibility check.
pub(super) fn free_on(
    cluster: &str,
    capacity: &controller_api::ClusterCapacity,
    vms: &[Vm],
    overcommit: Overcommit,
) -> Capacity {
    let bound = vms
        .iter()
        .filter(|v| v.spec.cluster_name.as_deref() == Some(cluster))
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

/// Preview cluster placement using the same volume and selector constraints
/// as reconciliation, without mutating objects or reserving capacity.
/// Read shared connection and heartbeat state so the answer does not depend on
/// which replica handles the request; expired heartbeats are ignored, not written.
pub(crate) async fn would_place(
    store: &EtcdStore,
    scheduler: &dyn controller_api::Scheduler,
    overcommit: Overcommit,
    vm: &Vm,
) -> anyhow::Result<String> {
    let wanted = match wanted(store, vm).await? {
        Ok(wanted) => wanted,
        Err(reason) => return Ok(reason),
    };
    let now = Utc::now();
    let vms = store.list::<Vm>().await?;
    // One read for every cluster's liveness — the heartbeat has its own key
    // since D-C7.
    let beats = store.beats::<Cluster>().await?;
    let mut clusters = Vec::new();
    let mut names = Vec::new();
    for cluster in store.list::<Cluster>().await? {
        if wanted.served_by(
            &cluster.metadata.name,
            &rooms_of(&cluster, &vms, overcommit),
        ) {
            names.push(cluster.metadata.name.clone());
        }
        let name = cluster.metadata.name;
        let connected = cluster.status.connected
            && !controller_api::heartbeat_expired(beats.get(&name).copied(), now);
        clusters.push(Candidate {
            connected,
            // One view at this tier: a cloud has one session per cluster
            // group and no second opinion to reconcile against.
            alive: connected,
            schedulable: cluster.spec.schedulable,
            // A cluster is not a machine: it has no disk to fill and no
            // store to wedge, and the conditions its NODES raise are read one
            // tier down, where the placement they veto is made. What reaches
            // this tier of them is `NodeDemand::met_by_a_node`, which refuses
            // a cluster whose only matching machine has said something is
            // wrong with it.
            unhealthy: Vec::new(),
            // Derived and not read off a field: a cluster has no `accepts`
            // of its own, and what it takes is what its usable machines take.
            // See `controller_api::cluster_accepts`.
            accepts: controller_api::cluster_accepts(&cluster.status.nodes),
            free: free_on(&name, &cluster.status.capacity, &vms, overcommit),
            catalogue: cluster.status.capacity.capabilities,
            kind: CandidateKind::Cluster,
            hosted: controller_api::hosted_on(&name, &vms, |v| v.spec.cluster_name.as_deref()),
            labels: cluster.spec.labels,
            name,
            // A candidate here is a CLUSTER and not a machine, so there is no
            // machine state to compare and never will be: there is no live
            // migration across clusters.
            machine: None,
        });
    }
    let allowed: Vec<Candidate> = clusters
        .iter()
        .filter(|c| names.iter().any(|n| n == &c.name))
        .cloned()
        .collect();
    Ok(match scheduler.assign(vm, &allowed) {
        Some(pick) => format!("would place on cluster {pick}"),
        // The same two sentences the pass gives, and in the same order: a
        // cluster cut away for having no suitable node is not a cluster that
        // "had no room".
        None if allowed.is_empty() && !clusters.is_empty() => {
            node_level_reason(vm, clusters.len()).1
        }
        None => controller_api::pending_reason_of(vm, &allowed).1,
    })
}

/// Say WHY on the object, and only when it changed.
///
/// Lifted out because there are two callers now: the scheduler finding no
/// cluster, and a volume that is not ready yet. Both write the same two
/// fields and record the same event, and both must do it only on a CHANGE —
/// a level-triggered pass reaches this conclusion every five seconds, and an
/// event per pass is a store filling at one write per VM per tick.
pub(super) async fn note_pending(
    store: &EtcdStore,
    vm: &Vm,
    category: controller_api::PendingReason,
    reason: String,
) -> anyhow::Result<()> {
    if vm.status.phase().message() == Some(reason.as_str()) {
        return Ok(());
    }
    store
        .mutate_if::<Vm, _>(&vm.metadata.name, &vm.metadata.uid, |v| {
            // Its own fact, exactly as one tier down: this pass says why a VM
            // is WAITING and does not decide what the VM is doing. See
            // `settle_vm`, which reads it only where a wait is what the VM is
            // in.
            v.status.placement = Some(controller_api::VmPlacement {
                reason: category.category(),
                message: reason.clone(),
                at: chrono::Utc::now(),
            });
        })
        .await?;
    events::record(
        store,
        about(
            vm,
            events::reason::FAILED_SCHEDULING,
            reason,
            EventType::Warning,
        ),
    )
    .await;
    Ok(())
}

/// What one pass may still hand out, spent under one lock so that the VMs it
/// binds see each other: each cluster's aggregate, and the room on each of
/// its nodes. With the aggregate alone a burst of creates bound more to one
/// cluster than any of its nodes holds. (IKR-B78)
#[derive(Default)]
pub(super) struct Ledger {
    pub(super) clusters: Vec<Candidate>,
    /// Keyed by cluster name, the same names `clusters` carries.
    pub(super) nodes: BTreeMap<String, Vec<NodeRoom>>,
}

impl Ledger {
    /// The rooms of `cluster`'s nodes this pass; none for a cluster this
    /// pass did not list.
    fn rooms(&self, cluster: &str) -> &[NodeRoom] {
        self.nodes.get(cluster).map_or(&[], Vec::as_slice)
    }
}

/// The rooms of `cluster`'s nodes as this cloud measures them: what it
/// reported, less what it holds without a node and what this cloud bound to
/// it that it has not reported yet. Neither is in any node's bound sum yet.
pub(super) fn rooms_of(cluster: &Cluster, vms: &[Vm], overcommit: Overcommit) -> Vec<NodeRoom> {
    let name = cluster.metadata.name.as_str();
    let unreported = vms
        .iter()
        .filter(|v| v.spec.cluster_name.as_deref() == Some(name) && !reported_by(v, name))
        .map(Capacity::wanted_by);
    let unplaced: Vec<Capacity> = cluster
        .status
        .unplaced
        .iter()
        .copied()
        .chain(unreported)
        .collect();
    controller_api::node_rooms(&cluster.status.nodes, overcommit, &unplaced)
}

/// Whether `cluster` has said anything about this VM: from then on it counts
/// the VM itself, on a node or among what it holds unplaced.
fn reported_by(vm: &Vm, cluster: &str) -> bool {
    vm.status
        .reported
        .as_ref()
        .is_some_and(|r| r.node == cluster)
}

/// What a VM asks before a cluster is chosen: the clusters its volumes allow
/// (`None`: any), and what ONE node of the chosen one has to give it — its
/// selector, the locality of its volumes, its class and its size. A cluster
/// of two half-full nodes has room in total for a VM neither node can take,
/// and binding it there leaves it Pending a tier down (IKR-B78).
pub(super) struct Wanted<'a> {
    clusters: Option<Vec<String>>,
    node: controller_api::NodeDemand<'a>,
}

impl<'a> Wanted<'a> {
    /// `vm`'s own asks, within the clusters and nodes its volumes allow
    /// (`None`: any).
    pub(super) fn of(
        vm: &'a Vm,
        clusters: Option<Vec<String>>,
        allowed: Option<Vec<String>>,
    ) -> Self {
        Self {
            clusters,
            node: controller_api::NodeDemand {
                selector: &vm.spec.node_selector,
                allowed,
                size: Capacity::wanted_by(vm),
                class: vm.spec.class(),
            },
        }
    }

    /// Whether `cluster`, whose nodes have `rooms`, can take the VM.
    pub(super) fn served_by(&self, cluster: &str, rooms: &[NodeRoom]) -> bool {
        self.clusters
            .as_ref()
            .is_none_or(|w| w.iter().any(|n| n == cluster))
            && self.node.met_by_a_node(rooms)
    }
}

/// What `vm` wants of a cluster — or a sentence saying why the question
/// cannot be answered yet: a volume this VM names is not ready, or not there.
/// The VM waits; it is not a refusal, and it must not be turned into "no
/// cluster has room".
pub(super) async fn wanted<'a>(
    store: &EtcdStore,
    vm: &'a Vm,
) -> anyhow::Result<OrSentence<Wanted<'a>>> {
    let names = vm.spec.referenced_volumes();

    // Intersect the clusters serving every referenced volume, then apply node
    // locality. Multiple pools must share at least one reachable placement.
    let mut wanted: Option<Vec<String>> = None;
    let mut allowed: Option<Vec<String>> = None;
    for name in &names {
        let (volume, pool) = match volume_and_pool(store, name).await? {
            Ok(pair) => pair,
            Err(sentence) => return Ok(Err(sentence)),
        };
        let serving = match pool_serving(&pool, name) {
            Ok(serving) => serving,
            Err(sentence) => return Ok(Err(sentence)),
        };
        wanted = Some(match narrow_clusters(wanted, serving, name) {
            Ok(both) => both,
            Err(sentence) => return Ok(Err(sentence)),
        });
        if volume.status.phase().kind() != controller_api::VolumePhaseKind::Ready {
            return Ok(Err(format!(
                "volume {name} is {}",
                volume.status.phase().kind().as_str()
            )));
        }
        allowed = controller_api::narrow_allowed(allowed, reachable_nodes(&volume, &pool));
    }

    Ok(Ok(Wanted::of(vm, wanted, allowed)))
}

/// Decide and SPEND under one lock, and let go before anything awaits — see
/// the cluster tier's `place` for why the binding and not the API edge is the
/// authority. The VM's size comes off the chosen cluster's aggregate and off
/// the node it is assumed to land on, so the next VM of the pass measures
/// what is left. (IKR-B78)
///
/// `Err` carries how many candidates the sentence was measured against,
/// beside the category and the sentence itself.
pub(super) fn pick_cluster(
    scheduler: &dyn Scheduler,
    ledger: &std::sync::Mutex<Ledger>,
    vm: &Vm,
    wanted: &Wanted,
) -> Result<String, (usize, (controller_api::PendingReason, String))> {
    let mut ledger = ledger.lock().unwrap();
    let allowed: Vec<Candidate> = ledger
        .clusters
        .iter()
        .filter(|c| wanted.served_by(&c.name, ledger.rooms(&c.name)))
        .cloned()
        .collect();
    let listed = ledger.clusters.len();
    match scheduler.assign(vm, &allowed) {
        Some(pick) => {
            controller_api::spend(&mut ledger.clusters, &pick, vm);
            if let Some(rooms) = ledger.nodes.get_mut(&pick) {
                wanted.node.debit(rooms);
            }
            Ok(pick)
        }
        // The sentence is measured against what was actually
        // offered. A cluster cut away for having no suitable node is
        // not a cluster that "had no room", and saying so would send
        // an operator to look at the wrong thing.
        None if allowed.is_empty() && listed > 0 => Err((listed, node_level_reason(vm, listed))),
        None => Err((
            allowed.len(),
            controller_api::pending_reason_of(vm, &allowed),
        )),
    }
}

/// An answer, or the sentence that says why there is none yet. The outer
/// `anyhow::Result` around these stays what it always was: the store itself
/// failing, which is not something to tell a VM about.
pub(super) type OrSentence<T> = Result<T, String>;

/// The volume a VM names and the pool its bytes live in — or which of the two
/// this cloud has never heard of.
pub(super) async fn volume_and_pool(
    store: &EtcdStore,
    name: &str,
) -> anyhow::Result<OrSentence<(controller_api::Volume, controller_api::StoragePool)>> {
    let volume: controller_api::Volume = match store.get(name).await {
        Ok(v) => v,
        Err(StoreError::NotFound(_)) => {
            return Ok(Err(format!("volume {name} does not exist here any more")));
        }
        Err(e) => return Err(e.into()),
    };
    let pool: controller_api::StoragePool = match store.get(&volume.spec.pool).await {
        Ok(p) => p,
        Err(StoreError::NotFound(_)) => {
            return Ok(Err(format!(
                "storage pool {} of volume {name} does not exist here",
                volume.spec.pool
            )));
        }
        Err(e) => return Err(e.into()),
    };
    Ok(Ok((volume, pool)))
}

/// The clusters that serve this pool, if the pool is telling a story that
/// holds together.
///
/// A pool that claims two clusters is only telling the truth if both describe
/// the same backend. Read here as well as at the reschedule edge, because a
/// pool can be widened after a VM was placed and this is where the
/// consequence lands: the VM stays where it is with a sentence, rather than
/// being scheduled onto a cluster whose export is somebody else's.
pub(super) fn pool_serving(
    pool: &controller_api::StoragePool,
    volume: &str,
) -> OrSentence<Vec<String>> {
    let serving: Vec<String> = pool
        .spec
        .served_by()
        .into_iter()
        .map(str::to_string)
        .collect();
    if serving.is_empty() {
        return Err(format!(
            "storage pool {} names no cluster, so volume {volume} cannot be reached",
            pool.metadata.name
        ));
    }
    if let Some((a, b)) = controller_api::StoragePoolSpec::disagreeing(&pool.status) {
        return Err(format!(
            "storage pool {} is served by {a} and {b}, but they do not describe the same \
             backend; volume {volume} is reachable from one of them at most",
            pool.metadata.name
        ));
    }
    Ok(serving)
}

/// The clusters that can serve everything asked of them so far, this volume
/// included. The first volume sets the list; every one after it narrows it.
pub(super) fn narrow_clusters(
    wanted: Option<Vec<String>>,
    serving: Vec<String>,
    volume: &str,
) -> OrSentence<Vec<String>> {
    let Some(already) = wanted else {
        return Ok(serving);
    };
    let both: Vec<String> = already
        .iter()
        .filter(|c| serving.iter().any(|s| s == *c))
        .cloned()
        .collect();
    if both.is_empty() {
        // Two volumes on clusters with nothing in common. No cluster can
        // serve both and no placement will ever fix it — but this tier does
        // not refuse a VM it already accepted, so it says so and waits.
        return Err(format!(
            "volume {volume} is on [{}] and another of this vm's volumes is on [{}]",
            serving.join(", "),
            already.join(", ")
        ));
    }
    Ok(both)
}

/// The nodes that can reach this volume's bytes, where the pool's locality
/// says which. Spent one tier higher than in position 3 and to the same
/// effect: node-local pins the VM to the machine that holds the bytes, shared
/// opens the pool, unknown constrains nothing.
pub(super) fn reachable_nodes(
    volume: &controller_api::Volume,
    pool: &controller_api::StoragePool,
) -> Option<Vec<String>> {
    match pool.status.locality {
        Some(controller_api::Locality::NodeLocal) => volume.status.node.clone().map(|n| vec![n]),
        Some(controller_api::Locality::Shared) => {
            // The UNION over the clusters that serve the pool, not the home
            // cluster's list: a shared pool crossing clusters is one export
            // mounted on both sides, and the nodes that can reach it are the
            // nodes on both sides. `status.nodes` is the home cluster's
            // answer and is still what a single-cluster pool has, so this
            // reads the same for every pool that never crossed anything.
            let mut nodes = pool.status.nodes.clone();
            for at in &pool.status.clusters {
                for node in &at.nodes {
                    if !nodes.contains(node) {
                        nodes.push(node.clone());
                    }
                }
            }
            (!nodes.is_empty()).then_some(nodes)
        }
        Some(controller_api::Locality::Networked) | None => None,
    }
}

/// Why no cluster has a node for this VM, and under which category. Names
/// every node-level ask the VM makes, because which of them cut the clusters
/// away is what an operator has to change; the category is the most specific
/// one the VM asked for.
pub(super) fn node_level_reason(vm: &Vm, known: usize) -> (controller_api::PendingReason, String) {
    let selector: Vec<String> = vm
        .spec
        .node_selector
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect();
    let volumes = vm.spec.referenced_volumes();
    let size = Capacity::wanted_by(vm);
    let mut asks = Vec::new();
    if !selector.is_empty() {
        asks.push(format!("is labelled [{}]", selector.join(", ")));
    }
    if !volumes.is_empty() {
        asks.push(format!("can reach [{}]", volumes.join(", ")));
    }
    asks.push(format!(
        "takes class {} with room for {} vcpu and {} MiB",
        vm.spec.class(),
        size.vcpus,
        size.mem_mib
    ));
    let category = if !volumes.is_empty() {
        controller_api::PendingReason::NoNodeForVolume
    } else if !selector.is_empty() {
        controller_api::PendingReason::SelectorUnmatched
    } else {
        controller_api::PendingReason::NoCapacity
    };
    (
        category,
        format!(
            "none of the {known} known clusters has a schedulable node that {}",
            asks.join(" and ")
        ),
    )
}
