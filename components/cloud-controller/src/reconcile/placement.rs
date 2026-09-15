// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Which cluster a VM can go to, and the sentence that says why none can.
//! Moved out of `reconcile.rs` unchanged.

use super::*;

/// What is still free on one cluster: the allowance its reported capacity
/// gives under the configured overcommit, minus everything already bound to
/// it.
///
/// The aggregate the cluster reports is the sum over its READY nodes and is
/// deliberately coarse — which node inside it ends up carrying a VM is the
/// cluster's own decision, and the check one tier down is the exact one. What
/// this prevents is the coarse mistake: handing a cluster more than it has at
/// all, and then watching every one of those VMs sit Pending down there with
/// nobody up here able to see why.
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

/// The label sets of the VMs already bound to `on` — what anti-affinity is
/// measured against. Every phase counts, exactly as `free_on` counts them.
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

/// The cloud's half of `?dryRun=All` on `POST /vms`: which CLUSTER, or why
/// none.
///
/// The same shape the cluster tier's `would_place` has one scope down, and
/// through the same two functions the pass uses — `servable_clusters` for the
/// volume-and-selector narrowing, then `assign` over what is left. Nothing is
/// spent and nothing is written.
///
/// Read-only where the pass is not: `collect_clusters` marks a cluster whose
/// heartbeat ran out as disconnected as a side effect of counting it, and a
/// request that asked to be SHOWN something must not change the cloud's
/// opinion of a cluster. So an expired heartbeat is read as not-connected
/// here without the object being touched, and `connected` comes from
/// `status.connected` — the shared fact — rather than from this replica's own
/// session set, which would make the same preview differ by which replica
/// answered it.
pub(crate) async fn would_place(
    store: &EtcdStore,
    scheduler: &dyn controller_api::Scheduler,
    overcommit: Overcommit,
    vm: &Vm,
) -> anyhow::Result<String> {
    let names = match servable_clusters(store, vm).await? {
        Servable::Clusters(names) => names,
        Sentence(reason) => return Ok(reason),
    };
    let now = Utc::now();
    let vms = store.list::<Vm>().await?;
    let mut clusters = Vec::new();
    for cluster in store.list::<Cluster>().await? {
        let name = cluster.metadata.name;
        let connected = cluster.status.connected
            && !controller_api::heartbeat_expired(cluster.status.last_heartbeat, now);
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
            hosted: hosted_on(&name, &vms, |v| v.spec.cluster_name.as_deref()),
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
        None if allowed.is_empty() && !clusters.is_empty() => node_level_reason(vm, clusters.len()),
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
    if vm.status.message.as_deref() == Some(reason.as_str()) {
        return Ok(());
    }
    store
        .mutate::<Vm, _>(&vm.metadata.name, |v| {
            v.status.message = Some(reason.clone());
            v.status.pending_reason = Some(category.as_str().to_string());
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

/// The clusters that have at least one node able to run this VM — or a
/// sentence saying why the question cannot be answered yet.
pub(super) enum Servable {
    Clusters(Vec<String>),
    /// A volume this VM names is not ready, or not there. The VM waits; it is
    /// not a refusal, and it must not be turned into "no cluster has room".
    Sentence(String),
}

pub(super) use Servable::Sentence;

/// Which clusters could actually run this VM, asked of their NODES.
///
/// Two facts are read here that a `Candidate` cannot carry, because a
/// candidate is a cluster summed up and both of these are about individual
/// machines:
///
///   * the `nodeSelector`, which until now was checked one tier down and
///     therefore AFTER the binding — a VM no node matched went Pending on a
///     cluster it should never have been sent to (image report, open finding);
///   * where a referenced volume's bytes are, which for a `node-local` pool
///     is one machine of one cluster.
///
/// They are one question and this asks it once. A VM that refers to no volume
/// and selects no labels demands nothing, and every connected cluster is
/// servable — which is every VM before this milestone.
pub(super) async fn servable_clusters(store: &EtcdStore, vm: &Vm) -> anyhow::Result<Servable> {
    let names = vm.spec.referenced_volumes();
    if names.is_empty() && vm.spec.node_selector.is_empty() {
        return Ok(Servable::Clusters(
            store
                .list::<Cluster>()
                .await?
                .into_iter()
                .map(|c| c.metadata.name)
                .collect(),
        ));
    }

    // The volumes decide WHICH clusters (through their pool) and which nodes
    // in them (through the pool's locality).
    //
    // A SET and no longer a single name, because a pool may name more than
    // one cluster: an import provider pointing at a target both dial, or one
    // export both mount. Narrowed by intersection across the VM's volumes,
    // which is the same rule `narrow_allowed` applies to nodes one level
    // down — two disks on two pools may be reachable from the intersection of
    // their clusters and from nowhere else.
    let mut wanted: Option<Vec<String>> = None;
    let mut allowed: Option<Vec<String>> = None;
    for name in &names {
        let (volume, pool) = match volume_and_pool(store, name).await? {
            Ok(pair) => pair,
            Err(sentence) => return Ok(Sentence(sentence)),
        };
        let serving = match pool_serving(&pool, name) {
            Ok(serving) => serving,
            Err(sentence) => return Ok(Sentence(sentence)),
        };
        wanted = Some(match narrow_clusters(wanted, serving, name) {
            Ok(both) => both,
            Err(sentence) => return Ok(Sentence(sentence)),
        });
        if volume.status.phase != controller_api::VolumePhaseKind::Ready {
            return Ok(Sentence(format!(
                "volume {name} is {}",
                volume.status.phase.as_str()
            )));
        }
        allowed = controller_api::narrow_allowed(allowed, reachable_nodes(&volume, &pool));
    }

    let demand = controller_api::NodeDemand {
        selector: &vm.spec.node_selector,
        allowed,
    };
    let servable = store
        .list::<Cluster>()
        .await?
        .into_iter()
        .filter(|c| {
            wanted
                .as_ref()
                .is_none_or(|w| w.iter().any(|n| n == &c.metadata.name))
        })
        .filter(|c| demand.met_by_a_node(&c.status.nodes))
        .map(|c| c.metadata.name)
        .collect();
    Ok(Servable::Clusters(servable))
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

/// Why no cluster has a node for this VM. Names the two things that can cut
/// one away, because which of them it was is what an operator has to change.
pub(super) fn node_level_reason(vm: &Vm, known: usize) -> String {
    let selector: Vec<String> = vm
        .spec
        .node_selector
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect();
    let volumes = vm.spec.referenced_volumes();
    match (selector.is_empty(), volumes.is_empty()) {
        (true, false) => format!(
            "none of the {known} known clusters has a node that can reach [{}]",
            volumes.join(", ")
        ),
        (false, true) => format!(
            "none of the {known} known clusters has a schedulable node labelled [{}]",
            selector.join(", ")
        ),
        _ => format!(
            "none of the {known} known clusters has a schedulable node that is labelled [{}] \
             and can reach [{}]",
            selector.join(", "),
            volumes.join(", ")
        ),
    }
}
