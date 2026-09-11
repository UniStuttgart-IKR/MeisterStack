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
    Candidate, CandidateKind, Capacity, EtcdStore, Lifecycle, Locality, Node, Overcommit,
    PassTrigger, PendingReason, PendingTally, RequeuePolicy, Resource, RunStrategy, Scheduler,
    StoragePool, StoragePoolPhase, StoreError, Vm, VmPhase, Volume, VolumeBinding, VolumePhase,
    VolumeSnapshot, VolumeSnapshotPhase, heartbeat_expired, lifecycle_command,
    scheduler::{StoragePolicy, feasible_for_storage, storage_pending_reason},
};
use proto::command;
use tracing::{debug, error, info, warn};

use controller_api::EventType;
use controller_api::events::{self, Happening};

use crate::session::SessionRegistry;
use controller_api::NetworkBackend;

const TICK: Duration = Duration::from_secs(5);

mod drain;
pub(crate) mod namespaces;
mod placement;
mod requeue;
mod routers;
mod snapshots;
mod vms;
mod volumes;

use drain::*;
pub(crate) use placement::*;
pub(crate) use requeue::*;
pub(crate) use routers::*;
pub(crate) use snapshots::*;
pub(crate) use vms::*;
pub(crate) use volumes::*;

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
pub fn may_reconcile(vm: &Vm, sessions: &HashSet<String>) -> bool {
    match vm.spec.node_name.as_deref() {
        Some(node) => sessions.contains(node),
        // Unbound, and the second arm is what storage B added to it: a VM
        // whose binding fell is the business of the replica that can still
        // reach the node it is LEAVING, until that node has let go. Any
        // replica may place one that has no old node — that is the ordinary
        // scheduling case, and it is what this arm always meant.
        None => match vm.status.node_name.as_deref() {
            Some(old) => sessions.contains(old),
            None => true,
        },
    }
}

/// The same question for a volume, and the answer it never got.
///
/// A VM has had `may_reconcile` since the leaderless design was written: the
/// replica holding the node's session owns the object on it, and the others
/// leave it alone. Volumes were reconciled by every replica, and the two that
/// could not reach the node found out by SENDING — their local registry
/// answered "node X has no active session", and they wrote that on the object
/// as `phase = Failed` with a sentence that is, from a client's chair, simply
/// false: the node was up, healthy, and provisioning the volume for the
/// replica that did hold it.
///
/// Measured (mini-chaos D1): on a three-replica cluster EVERY volume
/// provision went through `Failed` at least once, p50 29.2 s against 13.1 s
/// on a one-replica cluster. On a single replica the defect cannot appear at
/// all, which is why it survived every local run.
///
/// The other repair would have been a forward, the way the REST path
/// forwards a console to the replica holding the session. It is the wrong one
/// here: a reconcile is a level-triggered pass and not a request, so there is
/// no caller waiting for an answer, and the replica that DOES hold the
/// session reaches the same volume on its own next tick. Ownership follows
/// the session, as it does everywhere else in this file.
///
/// Same deliberate edge as the VM rule: a volume whose node is dialled into
/// no replica at all is reconciled by nobody and waits — including a deleting
/// one, because destroying bytes is something only that node can do.
pub fn may_reconcile_volume(volume: &Volume, sessions: &HashSet<String>) -> bool {
    match volume.status.node.as_deref() {
        Some(node) => sessions.contains(node),
        // Not placed yet: any replica may place it, and only onto nodes of
        // its own session map (`Candidate::connected`) — so whoever wins the
        // placement CAS placed it on a node it already owns, and ownership
        // follows the placement for free. Exactly the VM rule.
        None => true,
    }
}

/// Who, of several leaderless replicas, may act on this snapshot: the one
/// whose session reaches the node that holds the copy.
///
/// D1 one object further (chaos B-C1). `take_snapshots` walked every snapshot
/// on every replica; the two that cannot reach the node asked their own
/// registry, were told the node has no session, and `note_snapshot_failed`
/// wrote that sentence onto an object a third replica was in the middle of
/// taking. `Failed` is a phase a client is entitled to read as final.
pub fn may_reconcile_snapshot(snapshot: &VolumeSnapshot, sessions: &HashSet<String>) -> bool {
    match snapshot.status.node.as_deref() {
        Some(node) => sessions.contains(node),
        // Not dispatched yet, so it belongs to everybody — the volume rule,
        // and it holds for the same reason: the node a snapshot goes to is
        // the node its VOLUME sits on, the volume is only ever placed onto a
        // node of the placing replica's own session map, and the dispatch
        // stamps `status.node` as it sends. Ownership follows the dispatch.
        None => true,
    }
}

#[allow(clippy::too_many_arguments)]
pub async fn run(
    store: Arc<EtcdStore>,
    registry: Arc<SessionRegistry>,
    dispatch: Arc<crate::dispatch::Dispatch>,
    scheduler: Arc<dyn Scheduler>,
    requeue: Arc<dyn RequeuePolicy>,
    overcommit: Overcommit,
    kek: Option<Arc<controller_api::secrets::Kek>>,
    migration: crate::migration::Timeouts,
    network: Arc<dyn NetworkBackend>,
) {
    let mut trigger = PassTrigger::<Vm>::new(&store, TICK).await;
    loop {
        trigger.wait(&store).await;
        let clock = telemetry::metrics::Timer::start();
        let outcome = pass(
            &store,
            &registry,
            &dispatch,
            scheduler.as_ref(),
            requeue.as_ref(),
            overcommit,
            kek.as_deref(),
            migration,
            network.as_ref(),
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

#[allow(clippy::too_many_arguments)]
async fn pass(
    store: &EtcdStore,
    registry: &SessionRegistry,
    dispatch: &crate::dispatch::Dispatch,
    scheduler: &dyn Scheduler,
    requeue: &dyn RequeuePolicy,
    overcommit: Overcommit,
    kek: Option<&controller_api::secrets::Kek>,
    migration: crate::migration::Timeouts,
    network: &dyn NetworkBackend,
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
    // The drain reads the same listing the VM loop consumes, so it is kept
    // rather than read a second time: one picture of the fleet per pass, and
    // two readings could disagree about which node a VM is on.
    let vms_for_drain = vms.clone();
    let (nodes, localities) = expire_and_collect_nodes(store, &sessions, &vms, overcommit).await?;
    telemetry::metrics::objects().set_count(Node::KIND, nodes.len() as i64);
    let pass = Pass {
        store,
        registry,
        scheduler,
        requeue,
        sessions: &sessions,
        nodes: std::sync::Mutex::new(nodes),
        pending: PendingTally::new(),
        kek,
    };
    for vm in vms {
        let name = vm.metadata.name.clone();
        if let Err(e) = reconcile_vm(&pass, vm).await {
            warn!(vm = %name, error = format!("{e:#}"), "vm reconcile failed");
        }
    }

    // After the VMs and out of the same candidate list. A volume takes no
    // room off a node — see `feasible_for_storage` — so the order between the
    // two loops decides nothing, and it is this way round because a VM
    // waiting for a placement is the more urgent of the two.
    // Before the volumes, because a pool's locality is what a placement is
    // allowed to read: writing it after would mean every first pass places
    // against last pass's answer.
    if let Err(e) = reconcile_pools(store, &localities).await {
        warn!(
            error = format!("{e:#}"),
            "storage pool reconcile pass failed"
        );
    }
    if let Err(e) = place_volumes(&pass).await {
        warn!(error = format!("{e:#}"), "volume reconcile pass failed");
    }
    // After the volumes, because a snapshot is dispatched to the node its
    // volume is on and a volume placed this pass has one for the first time.
    if let Err(e) = take_snapshots(&pass).await {
        warn!(error = format!("{e:#}"), "snapshot reconcile pass failed");
    }
    // After the VM loop, because the drain reads VM state and writes marks
    // that the NEXT pass acts on. One tick of latency, which is what
    // level-triggered means: nothing here is a request that has to return.
    // The live migrations, after the VMs and before the drain. After, because
    // a migration reads the same candidate list the VM loop has been spending
    // from and must be measured against what is actually left; before,
    // because a drain that finds a live-capable VM CREATES a migration, and
    // the one it made should be picked up by the next pass rather than by
    // this one, half-decided.
    if let Err(e) =
        crate::migration::reconcile_migrations(store, dispatch, scheduler, &pass.nodes, migration)
            .await
    {
        warn!(error = format!("{e:#}"), "vm migration pass failed");
    }
    if let Err(e) = drain_nodes(&pass, &vms_for_drain).await {
        warn!(error = format!("{e:#}"), "node drain pass failed");
    }
    // The routers, last and out of the same candidate list. Last because a
    // router takes no room off a node — it is a netns and a veth pair, not a
    // guest — so nothing above it is measured against what it spends, and
    // because a VM waiting for a machine is the more urgent of the two. Out
    // of the same list, so that a node this pass already found unhealthy is
    // not a gateway candidate a moment later.
    if let Err(e) = reconcile_routers(&pass, dispatch, network).await {
        warn!(error = format!("{e:#}"), "router reconcile pass failed");
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

/// How many VMs there are, and how they are spread over the phases.
///
/// Every phase every time, zero included: a phase that stops being written
/// while nothing is in it looks, in a dashboard, exactly like a controller
/// that stopped reporting. Derived from the listing the pass already made —
/// this costs no etcd round trip of its own.
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
    /// `place`, which locks, decides, spends and lets go.
    pub(crate) nodes: std::sync::Mutex<Vec<Candidate>>,
    /// Filled in by `place`, published once at the end of the pass.
    pending: PendingTally,
    /// The key a secret's values are opened with, where this tier has one.
    /// `None` = no `secrets_key` in the config, and a VM naming a secret
    /// stays Pending with a sentence saying so. See `seed_for`.
    kek: Option<&'a controller_api::secrets::Kek>,
}

#[cfg(test)]
mod tests;
