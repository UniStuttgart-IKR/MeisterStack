// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Level-triggered VM reconciliation driven by periodic passes and store watches.
//! Stored intent selects actions; agent reports supply runtime evidence. The pass
//! also expires stale heartbeats after agents or controllers disappear.
//!
//! Replicas share etcd without a leader. Node sessions divide bound-object work;
//! compare-and-swap arbitrates bindings and shared status changes.

use std::collections::{BTreeMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use controller_api::{
    Candidate, CandidateKind, Capacity, CapacityReservation, EtcdStore, Lifecycle, Locality, Node,
    Overcommit, PassTrigger, PendingReason, PendingTally, RequeuePolicy, Resource, RunStrategy,
    Scheduler, StoragePool, StoreError, Vm, VmPhaseKind, Volume, VolumeBinding, VolumePhaseKind,
    VolumeSnapshot, VolumeSnapshotPhaseKind, heartbeat_expired, lifecycle_command,
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

/// Reconcile through the session that owns the bound node.
/// After unbinding, the old reported node retains ownership until teardown is
/// observed. An entirely unbound VM may be placed by any replica through CAS.
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

/// Only the replica holding the volume node's session reconciles it.
/// An unplaced volume is eligible on every replica; placement is claimed by CAS.
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

/// Reconcile an assigned snapshot through its node's session owner.
/// An unassigned snapshot is eligible on every replica. Initial dispatch does
/// not yet restrict eligibility to the source volume's session owner.
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
    // How many ticks between two deadline passes. A five-minute budget does
    // not need a five-second resolution, and six listings per tick would be a
    // monitoring feature that changes the thing it monitors — the same
    // argument `telemetry::metrics::Objects` makes about its own gauges. One
    // minute leaves the overshoot a deadline reports accurate to a minute,
    // which is what a four-and-a-half-day silence needed (D-C1).
    const DEADLINE_EVERY: u32 = 12;
    let mut ticks: u32 = 0;
    loop {
        trigger.wait(&store).await;
        ticks = ticks.wrapping_add(1);
        if ticks % DEADLINE_EVERY == 0
            && let Err(e) = deadlines(&store, TICK * DEADLINE_EVERY).await
        {
            warn!(error = format!("{e:#}"), "deadline pass failed");
        }
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

/// Report overdue phases through metrics and events without changing resource state.
/// Unknown observations remain Unknown; elapsed time does not authorize recovery.
/// Run across all objects, including those without a live session owner.
async fn deadlines(store: &EtcdStore, tick: Duration) -> anyhow::Result<()> {
    let now = Utc::now();
    use controller_api::stuck::{About, Late};
    let mut late = Late::default();
    for vm in store.list::<Vm>().await? {
        late.look(
            About::of::<Vm>(&vm.metadata, vm.spec.tenant.as_deref()),
            vm.status.standing(),
            now,
            tick,
        );
    }
    for volume in store.list::<Volume>().await? {
        late.look(
            About::of::<Volume>(&volume.metadata, Some(volume.spec.tenant.as_str())),
            volume.status.standing(),
            now,
            tick,
        );
    }
    for snapshot in store.list::<controller_api::VolumeSnapshot>().await? {
        late.look(
            About::of::<controller_api::VolumeSnapshot>(
                &snapshot.metadata,
                Some(snapshot.spec.tenant.as_str()),
            ),
            snapshot.status.standing(),
            now,
            tick,
        );
    }
    for pool in store.list::<StoragePool>().await? {
        late.look(
            About::of::<StoragePool>(&pool.metadata, None),
            pool.status.standing(),
            now,
            tick,
        );
    }
    for router in store.list::<controller_api::Router>().await? {
        late.look(
            About::of::<controller_api::Router>(
                &router.metadata,
                Some(router.spec.tenant.as_str()),
            ),
            router.status.standing(),
            now,
            tick,
        );
    }
    for migration in store.list::<controller_api::VmMigration>().await? {
        late.look(
            About::of::<controller_api::VmMigration>(
                &migration.metadata,
                Some(migration.spec.tenant.as_str()),
            ),
            migration.status.standing(),
            now,
            tick,
        );
    }
    late.publish();
    late.report(store).await;
    for crossed in late.crossed() {
        warn!(kind = crossed.kind, name = %crossed.name, phase = crossed.word,
              reason = crossed.reason, over_secs = crossed.over.as_secs(),
              "a phase has stood past its budget");
    }
    Ok(())
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
    // What the fleet has promised to guests that are on their way and are not
    // bound anywhere yet — a live migration's destination. One reading for
    // the whole pass: the candidate list is built with it taken off, and the
    // reaper below walks the same list, so the two cannot disagree about
    // which promises were standing when this pass began. Astra finding S07,
    // 2026-09-23.
    let held: Vec<CapacityReservation> = match store.list().await {
        Ok(held) => held,
        // Nothing has ever reserved in this cluster, which is the ordinary
        // state of a fleet that is not migrating anything.
        Err(StoreError::NotFound(_)) => Vec::new(),
        Err(e) => return Err(e.into()),
    };
    let (nodes, localities) =
        expire_and_collect_nodes(store, &sessions, &vms, &held, overcommit).await?;
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
    // Run migrations after VM placement so they see remaining candidate capacity.
    // Run drains afterward: their new evacuation marks and migration objects are
    // processed on the next pass.
    if let Err(e) = crate::migration::reconcile_migrations(
        store,
        dispatch,
        scheduler,
        &pass.nodes,
        migration,
        &held,
        overcommit,
    )
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
    for phase in VmPhaseKind::ALL {
        let n = vms
            .iter()
            .filter(|v| v.status.phase().kind() == phase)
            .count();
        telemetry::metrics::objects().set_vms(phase.as_str(), n as i64);
    }
}

/// Shared inputs, capacity accounting, and diagnostics for one reconcile pass.
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
