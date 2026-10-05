// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Live migration coordinates two durable endpoint records and one attempt.
//!
//! A timeout is not an abort. Unknown outcomes retain their migration record,
//! placement and reservation; only matching terminal evidence permits cleanup.
//! See docs/MIGRATION.md for the protocol, restart and upgrade contracts.

use std::sync::Mutex;
use std::time::Duration;

use chrono::Utc;
use controller_api::{
    Candidate, CapacityReservation, EtcdStore, Node, Overcommit, Resource, Scheduler, StoreError,
    Vm, VmMigration, VmMigrationPhaseKind, VmMigrationStatus, VmPhaseKind, Volume,
};
use proto::StatusReport;
use tracing::{debug, info, warn};

use crate::dispatch::{Dispatch, NodeCommand};

/// Deadlines for destination preparation and transfer observation.
/// Preparation may be cancelled before dispatch; an uncertain transfer outcome
/// retains ownership and requires recovery. Only the transfer budget is configurable.
#[derive(Debug, Clone, Copy)]
pub struct Timeouts {
    pub prepare: Duration,
    pub transfer: Duration,
}

impl Default for Timeouts {
    fn default() -> Self {
        Self {
            prepare: Duration::from_secs(30),
            transfer: Duration::from_secs(120),
        }
    }
}

impl Timeouts {
    /// `migration_transfer_secs` from the controller's config, or the
    /// default. Zero is read as "the default" rather than as "give up at
    /// once", because a zero in a config file is almost always a key somebody
    /// meant to fill in.
    pub fn with_transfer_secs(secs: Option<u64>) -> Self {
        match secs.filter(|s| *s > 0) {
            Some(secs) => Self {
                transfer: Duration::from_secs(secs),
                ..Default::default()
            },
            None => Self::default(),
        }
    }
}

/// Check whether a Preparing or Running attempt permits a second volume open.
/// Store errors propagate to the caller; they do not grant permission.
pub async fn migration_in_flight(store: &EtcdStore, vm: &Vm) -> anyhow::Result<bool> {
    let migrations: Vec<VmMigration> = match store.list().await {
        Ok(m) => m,
        Err(StoreError::NotFound(_)) => Vec::new(),
        Err(e) => return Err(e.into()),
    };
    Ok(phase_for(&migrations, vm).is_some())
}

/// Find the nonterminal migration phase matching this VM and tenant.
pub fn phase_for(migrations: &[VmMigration], vm: &Vm) -> Option<VmMigrationPhaseKind> {
    migrations
        .iter()
        .filter(|m| {
            m.spec.vm == vm.metadata.name
                && controller_api::same_tenancy(&m.spec.tenant, vm.spec.tenant.as_deref())
        })
        .map(|m| m.status.phase().kind())
        .find(|p| controller_api::second_open_is_a_migration(Some(*p)))
}

/// Detect another nonterminal attempt for this VM, including Pending records.
/// This check precedes destination preparation; concurrent contenders may both
/// be refused, but must not prepare or clean up each other's attempt.
fn another_attempt_in_flight(all: &[VmMigration], mine: &VmMigration) -> bool {
    all.iter().any(|m| {
        m.metadata.name != mine.metadata.name
            && m.spec.vm == mine.spec.vm
            && !m.status.phase().kind().is_final()
    })
}

/// Apply only evidence belonging to this VM incarnation and this attempt.
/// Terminal evidence cannot be replaced by an older in-flight heartbeat.
fn apply_report(m: &mut VmMigration, vm: &Vm, node: &str, line: &proto::MigrationReport) {
    let phase = m.status.phase().kind();
    if m.status.cancelling
        || !matches!(
            phase,
            VmMigrationPhaseKind::Preparing | VmMigrationPhaseKind::Running
        )
        || line.migration_id.is_empty()
        || m.status.migration_id.as_deref() != Some(line.migration_id.as_str())
        || m.status.vm_uid.as_deref() != Some(vm.metadata.uid.as_str())
        || line.vm_id != vm.metadata.uid
        || m.spec.vm != vm.metadata.name
        || !controller_api::same_tenancy(&m.spec.tenant, vm.spec.tenant.as_deref())
    {
        return;
    }
    if m.status.source_node.as_deref() == Some(node)
        && phase == VmMigrationPhaseKind::Running
        && m.status.peer.as_deref() == Some(line.peer.as_str())
        && matches!(
            line.outcome.as_str(),
            "Sending" | "Unknown" | "Gone" | "StillHere"
        )
        && !matches!(
            m.status.source_reported.as_deref(),
            Some("Gone" | "StillHere")
        )
    {
        m.status.source_reported = Some(line.outcome.clone());
        m.status.source_message = (!line.message.is_empty()).then(|| line.message.clone());
    }
    if m.status.target_node.as_deref() == Some(node)
        && matches!(line.outcome.as_str(), "Receiving" | "Arrived")
        && m.status.target_reported.as_deref() != Some("Running")
    {
        m.status.target_reported = Some(
            if line.outcome == "Arrived" {
                "Running"
            } else {
                "Provisioning"
            }
            .into(),
        );
    }
}

/// Both endpoints use the same attempt-bound report and compare again inside
/// the CAS retry. Ordinary VM phases and legacy reports are not migration evidence.
pub async fn ingest_reports(
    store: &EtcdStore,
    vms: &[Vm],
    node_id: &str,
    report: &StatusReport,
) -> anyhow::Result<()> {
    if report.migrations.is_empty() {
        return Ok(());
    }
    let migrations: Vec<VmMigration> = match store.list().await {
        Ok(m) => m,
        Err(StoreError::NotFound(_)) => return Ok(()),
        Err(e) => return Err(e.into()),
    };
    for migration in migrations {
        let Some(vm) = vms.iter().find(|v| v.metadata.name == migration.spec.vm) else {
            continue;
        };
        for line in &report.migrations {
            let mut changed = migration.clone();
            apply_report(&mut changed, vm, node_id, line);
            if serde_json::to_value(&changed.status)? == serde_json::to_value(&migration.status)? {
                continue;
            }
            store
                .mutate_if::<VmMigration, _>(
                    &migration.metadata.name,
                    &migration.metadata.uid,
                    |m| {
                        apply_report(m, vm, node_id, line);
                    },
                )
                .await?;
        }
    }
    Ok(())
}

/// Create a durable migration request for a drain.
/// An existing nonterminal request prevents one new attempt per reconciliation pass.
pub async fn start_for_drain(store: &EtcdStore, vm: &Vm, node: &str) -> anyhow::Result<()> {
    let existing: Vec<VmMigration> = match store.list().await {
        Ok(m) => m,
        Err(StoreError::NotFound(_)) => Vec::new(),
        Err(e) => return Err(e.into()),
    };
    if existing
        .iter()
        .any(|m| m.spec.vm == vm.metadata.name && !m.status.phase().kind().is_final())
    {
        return Ok(());
    }
    let name = format!(
        "{}-{}",
        vm.metadata.name,
        Utc::now().format("%Y%m%dt%H%M%S")
    );
    let migration = VmMigration::declare(
        &name,
        controller_api::VmMigrationSpec {
            tenant: vm.spec.tenant.clone().unwrap_or_default(),
            vm: vm.metadata.name.clone(),
            // Deliberately not pinned. A drain asks for the guest to go
            // SOMEWHERE ELSE and has no opinion about where; naming a node
            // here would turn an operator's "empty this machine" into
            // "empty this machine onto that one".
            target_node: None,
        },
    );
    match store.create(&migration).await {
        Ok(_) => {
            info!(migration = %name, vm = %vm.metadata.name, from = node,
                  "the drain asked for a live migration");
            Ok(())
        }
        // Another replica got there first, which is the same outcome.
        Err(StoreError::Conflict(_)) => Ok(()),
        Err(e) => Err(e.into()),
    }
}

/// Create the cloud-named migration request, preserving an optional target node.
/// Destination preparation checks for competing attempts before acting.
pub async fn start_from_the_cloud(
    store: &EtcdStore,
    name: &str,
    vm: &str,
    target_node: Option<&str>,
    tenant: &str,
) -> anyhow::Result<()> {
    // The vm has to be one of ours, and saying so here is what makes the
    // cloud's answer a sentence instead of a migration that fails a pass
    // later with "vm ... does not exist here any more".
    let _: Vm = store
        .get(vm)
        .await
        .map_err(|e| anyhow::anyhow!("vm {vm} is not on this cluster: {e}"))?;
    let migration = VmMigration::declare(
        name,
        controller_api::VmMigrationSpec {
            tenant: tenant.to_string(),
            vm: vm.to_string(),
            target_node: target_node.map(str::to_string),
        },
    );
    match store.create(&migration).await {
        Ok(_) => {
            info!(migration = %name, vm, to = target_node.unwrap_or("anywhere"),
                  "the cloud asked for a live migration");
            Ok(())
        }
        // The same command twice — a retry, a sibling that forwarded and did
        // not hear the answer. One migration either way.
        Err(StoreError::Conflict(_)) => {
            debug!(migration = %name, "this migration was already asked for");
            Ok(())
        }
        Err(e) => Err(e.into()),
    }
}

/// Advance each nonterminal migration by at most one phase step per pass.
/// Persisted attempt state carries progress across controller restarts.
#[allow(clippy::too_many_arguments)]
pub async fn reconcile_migrations(
    store: &EtcdStore,
    dispatch: &Dispatch,
    scheduler: &dyn Scheduler,
    nodes: &Mutex<Vec<Candidate>>,
    timeouts: Timeouts,
    held: &[CapacityReservation],
    vms: &[Vm],
    overcommit: Overcommit,
) -> anyhow::Result<()> {
    let migrations: Vec<VmMigration> = match store.list().await {
        Ok(m) => m,
        Err(StoreError::NotFound(_)) => Vec::new(),
        Err(e) => return Err(e.into()),
    };
    // BEFORE the early return below, and that is the whole point of it: an
    // orphaned promise is exactly the one whose migration is gone, so a
    // reaper that only ran when there were migrations could never reap the
    // last one.
    reap_reservations(store, held, &migrations, vms).await;
    if migrations.is_empty() {
        return Ok(());
    }
    telemetry::metrics::objects().set_count(VmMigration::KIND, migrations.len() as i64);
    for migration in migrations {
        let name = migration.metadata.name.clone();
        if migration.status.phase().kind().is_final() {
            continue;
        }
        // A record somebody deleted mid-flight is not this pass's to carry
        // on with — the object is the progress, and there is none.
        if migration.metadata.deletion_timestamp.is_some() {
            continue;
        }
        if let Err(e) = step(
            store, dispatch, scheduler, nodes, timeouts, held, overcommit, migration,
        )
        .await
        {
            warn!(migration = %name, error = %format!("{e:#}"), "migration step failed");
        }
    }
    Ok(())
}

/// Remove reservations whose move is over: a migration's once it is terminal,
/// deleted or absent; a placement's once its guest is bound, gone or deleting,
/// or its claim has outlived any placement (R3-F05). Compare the reservation
/// revision when deleting so a reused name cannot lose a newer claim. `held`
/// and `vms` are the pass's snapshot and migrations are read again after it,
/// so claims created during this pass are not reaped from stale data. Reaping
/// early costs a placement one retry, never room: its binding is written only
/// while its claim stands.
async fn reap_reservations(
    store: &EtcdStore,
    held: &[CapacityReservation],
    migrations: &[VmMigration],
    vms: &[Vm],
) {
    for orphan in controller_api::orphaned_reservations(held, migrations, vms, Utc::now()) {
        let name = &orphan.metadata.name;
        match store
            .delete_if::<CapacityReservation>(name, &orphan.metadata.resource_version)
            .await
        {
            Ok(()) => info!(reservation = %name, node = %orphan.spec.node, vm = %orphan.spec.vm,
                            claimant = ?orphan.spec.claimant,
                            "a reservation whose move is over was given back"),
            Err(StoreError::NotFound(_)) => {}
            Err(e) => debug!(reservation = %name, error = %format!("{e:#}"),
                             "the reservation was not given back this pass"),
        }
    }
}

/// Every promise this cluster is holding, with an empty directory read as
/// none — which is the ordinary state of a fleet that is not migrating.
async fn reservations(store: &EtcdStore) -> anyhow::Result<Vec<CapacityReservation>> {
    match store.list().await {
        Ok(held) => Ok(held),
        Err(StoreError::NotFound(_)) => Ok(Vec::new()),
        Err(e) => Err(e.into()),
    }
}

/// What `reserve` found at the key this migration writes its promise to.
enum Reserved {
    /// This pass wrote it. Unique as a KEY, which is not yet the same as
    /// fitting — see `controller_api::capacity::claim_holds`.
    Fresh(CapacityReservation),
    /// A promise for this very migration was already standing: an earlier
    /// attempt of this record wrote it and the process died before the phase
    /// moved, or a sibling replica is in `prepare` for it right now. Its node
    /// IS the destination — the promise is where the choice is written down,
    /// and a second answer to "where is this guest going" is how a guest gets
    /// two destinations.
    Standing(CapacityReservation),
    /// The key is held by a promise belonging to a DIFFERENT record of the
    /// same name. Nothing to do: the reaper takes it, and the next pass
    /// reserves.
    Foreign,
}

/// Write down, before anything is built at the destination, that this guest
/// is coming — with a create-only write, so the room is promised once.
async fn reserve(
    store: &EtcdStore,
    migration: &VmMigration,
    vm: &Vm,
    target: &str,
) -> anyhow::Result<Reserved> {
    let want = CapacityReservation::of(migration, vm, target);
    match store.create(&want).await {
        Ok(held) => Ok(Reserved::Fresh(held)),
        Err(StoreError::AlreadyExists(_)) | Err(StoreError::Terminating(_)) => {
            let standing: CapacityReservation = match store.get(&want.metadata.name).await {
                Ok(standing) => standing,
                // Given back between the two round trips. Nothing is held,
                // and the next pass writes it again.
                Err(StoreError::NotFound(_)) => return Ok(Reserved::Foreign),
                Err(e) => return Err(e.into()),
            };
            Ok(match standing.belongs_to(migration) {
                true => Reserved::Standing(standing),
                false => Reserved::Foreign,
            })
        }
        Err(e) => Err(e.into()),
    }
}

/// Restore this attempt's own reservation in the pass's candidate accounting.
/// Only restore a reservation included in the earlier subtraction; otherwise
/// this would invent capacity.
fn give_back(all: &mut [Candidate], held: &[CapacityReservation], mine: &CapacityReservation) {
    if !held.iter().any(|h| h.metadata.name == mine.metadata.name) {
        return;
    }
    if let Some(c) = all.iter_mut().find(|c| c.name == mine.spec.node) {
        c.free = c.free.plus(mine.spec.size());
    }
}

/// Release this migration's reservation, checking owner and revision.
/// A failed deletion is retried by the reservation reaper.
async fn release(store: &EtcdStore, migration: &VmMigration) {
    let name = migration.metadata.name.clone();
    let held: CapacityReservation = match store.get(&name).await {
        Ok(held) => held,
        Err(StoreError::NotFound(_)) => return,
        Err(e) => {
            warn!(migration = %name, error = %format!("{e:#}"),
                  "the reservation could not be read back to give it away");
            return;
        }
    };
    if !held.belongs_to(migration) {
        debug!(migration = %name, "that reservation belongs to a later record of this name");
        return;
    }
    match store
        .delete_if::<CapacityReservation>(&name, &held.metadata.resource_version)
        .await
    {
        Ok(()) => debug!(migration = %name, node = %held.spec.node, "the room was given back"),
        Err(e) => warn!(migration = %name, error = %format!("{e:#}"),
                        "the reservation was not given back; the reaper will take it"),
    }
}

// The post-reservation confirmation lives in `controller_api::capacity::claim_holds`,
// shared with ordinary placement so both roads answer "does this claim still fit"
// the same way (R3-F05). A failed read there is an error, never a pass (R3-F04).

/// One migration, one step.
#[allow(clippy::too_many_arguments)]
async fn step(
    store: &EtcdStore,
    dispatch: &Dispatch,
    scheduler: &dyn Scheduler,
    nodes: &Mutex<Vec<Candidate>>,
    timeouts: Timeouts,
    held: &[CapacityReservation],
    overcommit: Overcommit,
    migration: VmMigration,
) -> anyhow::Result<()> {
    let vm: Vm = match store.get(&migration.spec.vm).await {
        Ok(vm) => vm,
        // The object it was about is gone. Failed and not deleted: the record
        // of a move that did not happen is worth keeping, and it is the only
        // place the reason will ever be written down.
        Err(StoreError::NotFound(_)) => {
            let why = format!(
                "vm {} no longer exists; migration ownership requires recovery",
                migration.spec.vm
            );
            return if migration.status.phase().kind() == VmMigrationPhaseKind::Pending {
                fail(store, &migration, why).await
            } else {
                unresolved(store, &migration, why).await
            };
        }
        Err(e) => return Err(e.into()),
    };

    if !migration.status.phase().kind().is_final()
        && migration.status.phase().kind() != VmMigrationPhaseKind::Pending
        && (migration.status.migration_id.is_none()
            || migration.status.vm_uid.as_deref() != Some(vm.metadata.uid.as_str()))
    {
        return unresolved(
            store,
            &migration,
            "legacy or replaced VM: migration ownership requires recovery".into(),
        )
        .await;
    }
    if migration.status.cancelling
        && !migration.status.phase().kind().is_final()
        && let Some(target) = &migration.status.target_node
    {
        return abandon(
            store,
            dispatch,
            &migration,
            &vm,
            target,
            "migration cancelled".into(),
        )
        .await;
    }
    match migration.status.phase().kind() {
        VmMigrationPhaseKind::Pending => {
            prepare(
                store, dispatch, scheduler, nodes, held, overcommit, &migration, &vm,
            )
            .await
        }
        VmMigrationPhaseKind::Preparing => send(store, dispatch, timeouts, &migration, &vm).await,
        VmMigrationPhaseKind::Running => settle(store, dispatch, timeouts, &migration, &vm).await,
        VmMigrationPhaseKind::Succeeded | VmMigrationPhaseKind::Failed => Ok(()),
    }
}

/// `Pending` -> `Preparing`: choose a destination, open the disks there, and
/// get a VMM listening.
///
/// Everything this does is on the DESTINATION. The source is not addressed
/// once, and at the end of it the source is still serving the guest — which
/// is what makes every failure below a matter of tidying up one machine.
#[allow(clippy::too_many_arguments)]
async fn prepare(
    store: &EtcdStore,
    dispatch: &Dispatch,
    scheduler: &dyn Scheduler,
    nodes: &Mutex<Vec<Candidate>>,
    held: &[CapacityReservation],
    overcommit: Overcommit,
    migration: &VmMigration,
    vm: &Vm,
) -> anyhow::Result<()> {
    let name = migration.metadata.name.clone();
    let Some(source) = vm
        .spec
        .node_name
        .clone()
        .or_else(|| vm.status.node_name.clone())
    else {
        return fail(
            store,
            migration,
            format!(
                "vm {} is not on a node; there is nothing to move",
                vm.metadata.name
            ),
        )
        .await;
    };
    if vm.status.phase().kind() != VmPhaseKind::Running {
        return fail(
            store,
            migration,
            format!(
                "vm {} is {} and only a running vm can migrate live",
                vm.metadata.name,
                vm.status.phase().kind().as_str()
            ),
        )
        .await;
    }

    // Where to. A named node is a HARD requirement and is checked against the
    // same list the scheduler would have chosen from — somebody who names a
    // node asked about that node, and quietly using another would answer a
    // question they did not ask.
    let mut all = nodes.lock().unwrap().clone();
    reachable_anywhere(store, &mut all).await?;
    // What the fleet has promised to guests that are on their way and are
    // bound nowhere yet. Astra finding S07, 2026-09-23: the migrations of one
    // pass are stepped one after the other out of ONE snapshot, so without a
    // fresh reading the second migration to a node with room for one guest
    // would be measured against the room the first has already taken — and
    // both would pass.
    let standing = reservations(store).await?;
    // This record's own promise, if an earlier attempt wrote one and the
    // process died before the phase moved, or if a sibling replica wrote one
    // a moment ago.
    let ours = standing.iter().find(|r| r.belongs_to(migration)).cloned();
    // Everybody ELSE's, and only the ones the pass did not already know
    // about: `free` has the pass's own promises taken off it, the
    // subtraction saturates, and a number taken off twice cannot be added
    // back. A promise given back since the snapshot stays subtracted for this
    // pass — a node that looks fuller than it is for five seconds, which is
    // the safe direction.
    let theirs: Vec<CapacityReservation> = standing
        .iter()
        .filter(|r| !r.belongs_to(migration))
        .filter(|r| !held.iter().any(|h| h.metadata.name == r.metadata.name))
        .cloned()
        .collect();
    controller_api::hold(&mut all, &theirs);
    if let Some(ours) = &ours {
        give_back(&mut all, held, ours);
    }

    // Where to. A promise that already stands IS the destination — it is
    // where the choice was written down, and deciding again would give one
    // guest two of them — and it is checked again all the same, because a
    // machine that was feasible when it was promised may have been drained,
    // filled or wedged since.
    let named = ours
        .as_ref()
        .map(|r| r.spec.node.clone())
        .or_else(|| migration.spec.target_node.clone());
    let mut target = match choose_target(scheduler, vm, &source, named.as_deref(), &all) {
        Ok(target) => target,
        Err(why) => return fail(store, migration, why).await,
    };

    // Check for another active migration of this VM before claiming a target.
    // Otherwise a competing attempt's cleanup could destroy the first attempt's
    // receiving VMM, since teardown addresses the VM UID. Record a refusal rather
    // than silently leaving the duplicate request Pending.
    let siblings: Vec<VmMigration> = match store.list().await {
        Ok(m) => m,
        Err(StoreError::NotFound(_)) => Vec::new(),
        Err(e) => return Err(e.into()),
    };
    if another_attempt_in_flight(&siblings, migration) {
        return fail(
            store,
            migration,
            format!(
                "another migration record for vm {} has not finished; one guest moves once, so \
                 this record ends here and the other one carries the move",
                migration.spec.vm
            ),
        )
        .await;
    }

    // Reserve destination capacity before preparation and before claiming the move.
    // The VM remains bound to its source until settlement, so bound-VM usage alone
    // does not account for destination demand. A crash before the claim leaves a
    // recoverable reservation for a Pending migration rather than unaccounted work.
    // Named and scheduler-selected targets use the same reservation path.
    for endpoint in [&source, &target] {
        if !all.iter().any(|n| {
            &n.name == endpoint
                && n.catalogue
                    .iter()
                    .any(|c| c == common::migration::ATTEMPT_PROTOCOL)
        }) {
            return fail(store, migration, format!("node {endpoint} does not support migration/attempt-v2; upgrade both endpoints before migrating")).await;
        }
    }

    let mine = match reserve(store, migration, vm, &target).await? {
        Reserved::Fresh(mine) => mine,
        Reserved::Standing(mine) if mine.spec.node == target => mine,
        // A sibling replica wrote the promise between the reading above and
        // the write, and named another machine. Its choice is the one that
        // stands — one promise, one destination — and it is checked on a list
        // this guest's own promise is not counted against.
        Reserved::Standing(mine) => {
            let elsewhere = mine.spec.node.clone();
            debug!(migration = %name, reserved = %elsewhere, chose = %target,
                   "another replica promised this guest a different machine");
            give_back(&mut all, held, &mine);
            match choose_target(scheduler, vm, &source, Some(&elsewhere), &all) {
                Ok(chosen) => {
                    target = chosen;
                    mine
                }
                // It was promised and it no longer holds. `fail` gives the
                // room back — it is the one funnel every ending goes through.
                Err(why) => return fail(store, migration, why).await,
            }
        }
        Reserved::Foreign => {
            debug!(migration = %name,
                   "the reservation key is held by another record of this name; waiting");
            return Ok(());
        }
    };

    // A unique key is not a sum: concurrent creates on one node both succeed, so
    // confirm the claim's place in etcd's revision order. The queue includes
    // ordinary placement claims (R3-F05).
    match controller_api::capacity::claim_holds(store, &mine, overcommit).await {
        Ok(true) => {}
        Ok(false) => {
            return fail(
                store,
                migration,
                format!(
                    "another claim took the last of {target}'s room first; this record \
                     ends here and the move can be asked for again"
                ),
            )
            .await;
        }
        // A failed read is not a passed check (R3-F04): end the step before the
        // claim and any dispatch. The reservation stands, so the node looks fuller
        // until the next pass adopts it and asks again.
        Err(e) => {
            return Err(e.context(format!(
                "migration {name}: the room at {target} could not be confirmed; \
                 nothing was prepared and the next pass asks again"
            )));
        }
    }

    // The claim before the command, exactly as every other dispatch in this
    // tree: a CAS that loses means another replica is already preparing this
    // migration, and two replicas preparing one migration would build two
    // destinations for one guest.
    let mut claimed = migration.clone();
    claimed.status.migration_id = Some(migration.metadata.uid.clone());
    claimed.status.vm_uid = Some(vm.metadata.uid.clone());
    claimed.status.source_node = Some(source.clone());
    claimed.status.target_node = Some(target.clone());
    claimed.status.started_at = Some(Utc::now());
    claimed.status.observed_generation = migration.metadata.generation;
    // This tier's own step, so it names nobody — see `VmMigrationReported`.
    claimed.status.reported = Some(controller_api::VmMigrationReported::here(
        VmMigrationPhaseKind::Preparing,
        controller_api::VmMigrationReason::Dispatched,
        Some(format!("preparing {target}")),
        Utc::now(),
    ));
    match store.update(&claimed).await {
        Ok(fresh) => {
            claimed = fresh;
        }
        Err(StoreError::Conflict(_)) => {
            debug!(migration = %name, "lost the prepare race");
            return Ok(());
        }
        Err(e) => return Err(e.into()),
    }

    // Open referenced volumes at the destination before preparing its VMM; the
    // incoming configuration contains their paths. UID-derived provisioning reopens
    // existing bytes. `openOn` records the temporary overlap between both nodes.
    if let Err(e) = open_volumes_at(store, dispatch, vm, &target).await {
        let why = format!("the destination could not open the disks: {e:#}");
        return abandon(store, dispatch, &claimed, vm, &target, why).await;
    }

    let spec_json = match spec_for(store, vm).await {
        Ok(spec) => spec,
        Err(e) => {
            let why = format!("this vm's spec could not be built for the destination: {e:#}");
            return abandon(store, dispatch, &claimed, vm, &target, why).await;
        }
    };
    // The node picks the address it listens at — it is the only party that
    // knows which of its addresses a peer can reach and which port is free —
    // and the string it answers with travels to the source unopened.
    let peer = dispatch
        .send(
            &target,
            NodeCommand::PrepareMigration {
                migration_id: migration.metadata.uid.clone(),
                id: vm.metadata.uid.clone(),
                spec_json,
            },
        )
        .await;
    let peer = match peer.and_then(|payload| peer_from(&payload)) {
        Ok(peer) => peer,
        Err(e) => {
            let why = format!("node {target} could not make itself ready: {e:#}");
            return abandon(store, dispatch, &claimed, vm, &target, why).await;
        }
    };

    store
        .mutate_if::<VmMigration, _>(&name, &migration.metadata.uid, |m| {
            let phase = m.status.phase().kind();
            if m.status.cancelling || m.status.phase().kind() != VmMigrationPhaseKind::Preparing {
                return;
            }
            // The field and the sentence in one write, so that no pass can
            // ever see one without the other. The sentence is what a person
            // reads; the field is what `send` reads — see `peer_of`, and
            // Astra finding S05 on `status.peer`.
            m.status.peer = Some(peer.clone());
            m.status.reported = Some(controller_api::VmMigrationReported::here(
                phase,
                controller_api::VmMigrationReason::Dispatched,
                Some(format!("{target} is listening at {peer}")),
                Utc::now(),
            ));
        })
        .await?;
    info!(migration = %name, vm = %vm.metadata.name, from = %source, to = %target, %peer,
          "the destination is ready");
    Ok(())
}

/// Include nodes whose sessions are held by another replica.
/// Migration commands use Dispatch forwarding. A stale object cannot remove
/// a session this replica already holds.
async fn reachable_anywhere(store: &EtcdStore, all: &mut [Candidate]) -> anyhow::Result<()> {
    if all.iter().all(|c| c.connected) {
        return Ok(());
    }
    let nodes = store.list::<Node>().await?;
    for candidate in all.iter_mut() {
        candidate.connected = reaches(candidate, &nodes);
    }
    Ok(())
}

/// The rule of the above, as a value: this replica's own session, or any
/// replica's, which is what a `sessionEndpoint` on the object means.
fn reaches(candidate: &Candidate, nodes: &[Node]) -> bool {
    candidate.connected
        || nodes.iter().any(|n| {
            n.metadata.name == candidate.name
                && n.status.ready
                && n.status.session_endpoint.is_some()
        })
}

/// Filter destination machine profiles against the source and retain refusals.
/// Missing profiles impose no compatibility restriction for older agents; this
/// preflight check does not prove that the VMM can complete a transfer.
pub(crate) fn machines_that_fit<'a>(
    source: Option<&Candidate>,
    all: &'a [Candidate],
) -> (Vec<&'a Candidate>, Vec<String>) {
    let Some(source) = source else {
        // The source is not in the candidate list at all — a node that went
        // away between two passes. Nothing is compared and nothing is
        // refused: what stops that migration is the source having no session,
        // which is a better sentence than any of these.
        return (all.iter().collect(), Vec::new());
    };
    let Some(here) = &source.machine else {
        return (all.iter().collect(), Vec::new());
    };
    let mut fits = Vec::new();
    let mut refusals = Vec::new();
    for candidate in all {
        match candidate.machine.as_ref().and_then(|there| {
            controller_api::live_migration_refusal(&source.name, here, &candidate.name, there)
        }) {
            Some(why) => refusals.push(why),
            None => fits.push(candidate),
        }
    }
    (fits, refusals)
}

/// Exclude the source and choose a feasible destination.
/// A named target is a requirement: apply the same feasibility rules without
/// substituting another node.
fn choose_target(
    scheduler: &dyn Scheduler,
    vm: &Vm,
    source: &str,
    named: Option<&str>,
    all: &[Candidate],
) -> Result<String, String> {
    let here = all.iter().find(|c| c.name == source);
    let elsewhere: Vec<Candidate> = all.iter().filter(|c| c.name != source).cloned().collect();
    match named {
        Some(named) => {
            // Apply the scheduler's full feasibility predicate to named targets too,
            // including capacity, selectors, affinity, health and hypervisor capability.
            let Some(candidate) = controller_api::feasible(vm, &elsewhere)
                .into_iter()
                .find(|c| c.name == named)
            else {
                return Err(format!(
                    "node {named} cannot take this vm: it must be connected, schedulable, \
                     healthy, running a hypervisor, with room for this vm and the labels it \
                     selects, and not the node the vm is already on"
                ));
            };
            // And the question no amount of capacity answers: can this
            // machine hold that machine's saved state? Asked here, before a
            // disk is opened on it, because v53 only finds out two
            // milliseconds after the vCPUs are made. See `machines_that_fit`.
            let (fits, refusals) = machines_that_fit(here, std::slice::from_ref(candidate));
            match fits.is_empty() {
                // Its own sentence and not the generic one: somebody named
                // this node, so the answer is about this node.
                true => Err(refusals
                    .into_iter()
                    .next()
                    .unwrap_or_else(|| format!("node {named} cannot take this vm"))),
                false => Ok(named.to_string()),
            }
        }
        None => {
            // The machine-state narrowing comes FIRST, and the order is what
            // makes the sentence right: a scheduler asked over machines that
            // cannot hold this guest would answer "no room" about a fleet
            // that has plenty.
            let (fits, refusals) = machines_that_fit(here, &elsewhere);
            if fits.is_empty() && !refusals.is_empty() {
                return Err(refusals.into_iter().next().unwrap_or_default());
            }
            let fits: Vec<Candidate> = fits.into_iter().cloned().collect();
            scheduler.assign(vm, &fits).ok_or_else(|| {
                format!(
                    "no other node can take {}: {}",
                    vm.metadata.name,
                    controller_api::pending_reason_of(vm, &fits).1
                )
            })
        }
    }
}

/// Persist Running before sending the source's attempt-bound MigrateOut command.
/// An uncertain reply must retain the attempt for later endpoint evidence.
async fn send(
    store: &EtcdStore,
    dispatch: &Dispatch,
    timeouts: Timeouts,
    migration: &VmMigration,
    vm: &Vm,
) -> anyhow::Result<()> {
    if migration.status.cancelling
        || migration.status.phase().kind() != VmMigrationPhaseKind::Preparing
    {
        return Ok(());
    }
    let name = migration.metadata.name.clone();
    let (Some(source), Some(target)) = (
        migration.status.source_node.clone(),
        migration.status.target_node.clone(),
    ) else {
        return unresolved(
            store,
            migration,
            "migration endpoints are missing; ownership requires recovery".to_string(),
        )
        .await;
    };
    let peer = peer_of(&migration.status);

    // Wait for the preparation budget before treating a missing address as failure.
    // Another replica can observe Preparing while the owner is still opening disks
    // or awaiting PrepareMigration; absence during that interval is expected.
    if let Some(over) = overdue(migration, timeouts.prepare) {
        let why = match &peer {
            Some(_) => format!("the destination was not ready after {over}s"),
            // Past the budget and still no address: now the old sentence is
            // the true one. Nothing has been done to the source, so tearing
            // the destination down is safe.
            None => format!(
                "the destination's address never reached this record, and {target} was not \
                 ready after {over}s"
            ),
        };
        return abandon(store, dispatch, migration, vm, &target, why).await;
    }
    let Some(peer) = peer else {
        debug!(migration = %name, node = %target,
               "the destination has not said where to send yet; it still has time");
        return Ok(());
    };

    let mut claimed = migration.clone();
    claimed.status.reported = Some(controller_api::VmMigrationReported::here(
        VmMigrationPhaseKind::Running,
        controller_api::VmMigrationReason::Dispatched,
        Some(format!("sending to {target} at {peer}")),
        Utc::now(),
    ));
    match store.update(&claimed).await {
        Ok(_) => {}
        Err(StoreError::Conflict(_)) => {
            debug!(migration = %name, "lost the send race");
            return Ok(());
        }
        Err(e) => return Err(e.into()),
    }

    info!(migration = %name, vm = %vm.metadata.name, from = %source, to = %target,
          "telling the source to send");
    if let Err(e) = dispatch
        .send(
            &source,
            NodeCommand::MigrateOut {
                migration_id: migration.status.migration_id.clone().unwrap_or_default(),
                id: vm.metadata.uid.clone(),
                peer: peer.clone(),
            },
        )
        .await
    {
        // An error string cannot prove that an accepted transfer was aborted.
        // Keep ownership and wait for attempt-bound reports from both endpoints.
        let e = format!("{e:#}");
        let why = format!("the source's answer did not come back: {e}");
        warn!(migration = %name, node = %source, reason = %why,
              "the send is unaccounted for; waiting for the destination to say");
        unresolved(store, migration, why).await?;
    }
    Ok(())
}

/// Interpret matching source-abort evidence together with destination evidence.
/// Contradictory or possibly running destination state requires recovery.
fn still_here(source: &str, target: &str, status: &VmMigrationStatus) -> Option<Verdict> {
    if status.source_reported.as_deref() != Some(controller_api::resources::SEND_STILL_HERE) {
        return None;
    }
    let said = status
        .source_message
        .clone()
        .unwrap_or_else(|| format!("{source} says it still has the guest"));
    let seen = status.target_reported.as_deref();
    if matches!(seen, None | Some("Provisioning")) {
        return Some(Verdict::TearDownTheDestination(format!(
            "the transfer did not take and {source} is still running the vm: {said}. \
             {target} holds no guest and has been torn down"
        )));
    }
    Some(Verdict::TouchNothing(format!(
        "{source} says it still has the guest ({said}) while {target} last said {} — two \
         machines claim one vm, so nothing here has been torn down; look at both before \
         deleting anything",
        seen.unwrap_or("nothing at all")
    )))
}

/// A confirmed abort permits cleanup; contradictory evidence requires recovery.
#[derive(Debug, PartialEq, Eq)]
enum Verdict {
    TearDownTheDestination(String),
    TouchNothing(String),
}

/// Silence and stale progress reports cannot prove an empty destination.
/// The deadline therefore requests recovery without authorizing destruction.
fn verdict_on_timeout(
    source: &str,
    target: &str,
    over: i64,
    source_reported: Option<&str>,
    target_reported: Option<&str>,
) -> Verdict {
    let said = target_reported.unwrap_or("nothing at all");
    if source_reported == Some(controller_api::resources::SEND_GONE) {
        return Verdict::TouchNothing(format!(
            "the guest had not arrived on {target} after {over}s, and {source} says it let the \
             guest go; the destination last said {said}. {source} is not serving this vm any \
             more, so {target} may hold the only copy and nothing here has been torn down — \
             look at both before deleting anything"
        ));
    }
    Verdict::TouchNothing(format!(
        "the guest had not arrived on {target} after {over}s; the destination last said {said}, \
         so it may hold the guest and nothing here has been torn down — look at {source} and \
         {target} before deleting anything"
    ))
}

/// Commit a completed handoff from matching endpoint evidence.
/// Move the VM binding before releasing the source record. Volume-home updates
/// and source volume-record cleanup afterward are best effort.
async fn settle(
    store: &EtcdStore,
    dispatch: &Dispatch,
    timeouts: Timeouts,
    migration: &VmMigration,
    vm: &Vm,
) -> anyhow::Result<()> {
    let name = migration.metadata.name.clone();
    let (Some(source), Some(target)) = (
        migration.status.source_node.clone(),
        migration.status.target_node.clone(),
    ) else {
        return unresolved(
            store,
            migration,
            "migration endpoints are missing; ownership requires recovery".to_string(),
        )
        .await;
    };

    let arrived = migration.status.target_reported.as_deref()
        == Some(VmPhaseKind::Running.as_str())
        && migration.status.source_reported.as_deref() == Some("Gone");
    if !arrived {
        // The one answer that ends a migration before its timeout does, and
        // the one D16 made available: the SOURCE's own word about the send.
        // See `still_here`, where the decision is argued and can be checked
        // without a store.
        match still_here(&source, &target, &migration.status) {
            Some(Verdict::TearDownTheDestination(why)) => {
                return abandon(store, dispatch, migration, vm, &target, why).await;
            }
            Some(Verdict::TouchNothing(why)) => return unresolved(store, migration, why).await,
            None => {}
        }
        let Some(over) = overdue(migration, timeouts.prepare + timeouts.transfer) else {
            return Ok(());
        };
        // Out of time, and now the one question that decides what may be
        // done about it: **can the destination possibly have this guest?**
        // The answer is `verdict_on_timeout`, where it can be checked
        // without a store.
        return match verdict_on_timeout(
            &source,
            &target,
            over,
            migration.status.source_reported.as_deref(),
            migration.status.target_reported.as_deref(),
        ) {
            Verdict::TearDownTheDestination(why) => {
                abandon(store, dispatch, migration, vm, &target, why).await
            }
            Verdict::TouchNothing(why) => unresolved(store, migration, why).await,
        };
    }

    // The binding, by CAS onto the object this pass read. A conflict is
    // another writer — a client editing the VM, another replica finishing the
    // same migration — and the next pass reads it again.
    let mut bound = vm.clone();
    bound.spec.node_name = Some(target.clone());
    match store.update(&bound).await {
        Ok(_) => {}
        Err(StoreError::Conflict(_)) => {
            debug!(migration = %name, "the vm changed while the binding was being moved");
            return Ok(());
        }
        Err(e) => return Err(e.into()),
    }

    // The room is given back HERE, in the arm where the binding took, and not
    // a line earlier. From this write on the guest is counted on the
    // destination by `free_on` like any other VM bound there, and a promise
    // beside it would be the same guest counted twice; before it, the promise
    // is the only thing holding the room at all. Astra finding S07,
    // 2026-09-23: whichever of the two comes first, the machine's room is
    // claimed by exactly one of them at every instant.
    release(store, migration).await;

    // And now, and only now, the source. A failure here is not a failed
    // migration: the guest is at the destination and the object says so. What
    // is left behind is a record on a machine that no longer serves it, and
    // the ordinary drift — `SyncState` on the next reconnect — reaps it.
    if let Err(e) = dispatch
        .send(
            &source,
            NodeCommand::CleanupMigration {
                migration_id: migration.status.migration_id.clone().unwrap_or_default(),
                source: true,
                id: vm.metadata.uid.clone(),
            },
        )
        .await
    {
        warn!(migration = %name, node = %source, error = %format!("{e:#}"),
              "the source could not be told to let go; the guest is at the destination either way");
    }
    close_volumes_at(vm, &source);
    move_volume_home(store, vm, &source, &target).await;
    forget_volumes_at(store, dispatch, vm, &source).await;

    let finished = Utc::now();
    store
        .mutate_if::<VmMigration, _>(&name, &migration.metadata.uid, |m| {
            m.status.recovery_required = false;
            m.status.finished_at = Some(finished);
            // The one resting word here, and the only one that names a
            // machine: what it claims is that a guest is executing on the
            // destination, and the evidence for that is the destination's own
            // `Running` — see `VmMigrationReported` and `settle_vm_migration`.
            m.status.reported = Some(controller_api::VmMigrationReported::by(
                &target,
                VmMigrationPhaseKind::Succeeded,
                controller_api::VmMigrationReason::Unrecorded,
                Some(format!("{} is on {target}", vm.metadata.name)),
                finished,
            ));
        })
        .await?;
    let took = migration
        .status
        .started_at
        .map(|s| (finished - s).num_milliseconds())
        .unwrap_or_default();
    info!(migration = %name, vm = %vm.metadata.name, from = %source, to = %target, ms = took,
          "the guest moved");
    Ok(())
}

/// Cancel before dispatch, or after a matching authoritative source abort.
/// A CAS excludes concurrent dispatch; the agent checks durable attempt ownership.
/// Capacity is retained until cleanup acknowledges success.
async fn abandon(
    store: &EtcdStore,
    dispatch: &Dispatch,
    migration: &VmMigration,
    vm: &Vm,
    target: &str,
    why: String,
) -> anyhow::Result<()> {
    let Some(_) = migration.status.migration_id.as_ref() else {
        return unresolved(
            store,
            migration,
            "legacy migration requires recovery before cleanup".into(),
        )
        .await;
    };
    let mut claimed = migration.clone();
    if !claimed.status.cancelling {
        claimed.status.cancelling = true;
        claimed = match store.update(&claimed).await {
            Ok(m) => m,
            Err(StoreError::Conflict(_)) => return Ok(()),
            Err(e) => return Err(e.into()),
        };
    }
    let migration = &claimed;
    // No acknowledgement means unresolved cleanup, not a released reservation.
    if let Err(e) = dispatch
        .send(
            target,
            NodeCommand::CleanupMigration {
                migration_id: migration.status.migration_id.clone().unwrap_or_default(),
                source: false,
                id: vm.metadata.uid.clone(),
            },
        )
        .await
    {
        warn!(migration = %migration.metadata.name, node = target,
              error = %format!("{e:#}"), "the destination could not be torn down");
        return unresolved(
            store,
            migration,
            format!("cleanup has not been confirmed: {e:#}"),
        )
        .await;
    }
    close_volumes_at(vm, target);
    fail(store, migration, why).await
}

/// Unknown is nonterminal: keep placement, operation ownership and reservation.
async fn unresolved(store: &EtcdStore, migration: &VmMigration, why: String) -> anyhow::Result<()> {
    store
        .mutate_if::<VmMigration, _>(&migration.metadata.name, &migration.metadata.uid, |m| {
            if m.status.phase().kind().is_final() {
                return;
            }
            m.status.recovery_required = true;
            m.status.reported = Some(controller_api::VmMigrationReported::here(
                m.status.phase().kind(),
                controller_api::VmMigrationReason::Reported,
                Some(why.clone()),
                Utc::now(),
            ));
        })
        .await?;
    Ok(())
}

/// Commit a terminal failure only if the deciding snapshot still owns the revision.
async fn fail(store: &EtcdStore, migration: &VmMigration, why: String) -> anyhow::Result<()> {
    let name = migration.metadata.name.clone();
    warn!(migration = %name, vm = %migration.spec.vm, reason = %why, "migration failed");
    let mut ended = migration.clone();
    let now = Utc::now();
    ended.status.recovery_required = false;
    ended.status.finished_at = Some(now);
    ended.status.reported = Some(controller_api::VmMigrationReported::here(
        VmMigrationPhaseKind::Failed,
        controller_api::VmMigrationReason::Abandoned,
        Some(why),
        now,
    ));
    match store.update(&ended).await {
        Ok(_) => {}
        Err(StoreError::Conflict(_)) => return Ok(()),
        Err(e) => return Err(e.into()),
    }
    // After the ending and not before it, and the order is the invariant's:
    // a process killed between the two leaves a promise whose migration is
    // FINAL, which is exactly what the reaper takes. The other order would
    // leave a non-final migration with no room held, and the gap this whole
    // object exists to close would be open again for the length of one
    // destination's teardown.
    release(store, migration).await;
    Ok(())
}

/// Return elapsed seconds since startedAt once the budget is exceeded.
/// Return None before the deadline or when preparation has not started.
fn overdue(migration: &VmMigration, budget: Duration) -> Option<i64> {
    let started = migration.status.started_at?;
    let elapsed = Utc::now().signed_duration_since(started).num_seconds();
    (elapsed > budget.as_secs() as i64).then_some(elapsed)
}

/// Provision referenced volume records on the destination without changing their
/// existing phase. Node reports, not command acceptance, update openOn.
async fn open_volumes_at(
    store: &EtcdStore,
    dispatch: &Dispatch,
    vm: &Vm,
    node: &str,
) -> anyhow::Result<()> {
    for name in vm.spec.referenced_volumes() {
        let volume: Volume = store.get(&name).await?;
        let spec_json = crate::reconcile::volume_spec_json(store, &volume).await?;
        dispatch
            .send(
                node,
                NodeCommand::ProvisionVolume {
                    id: volume.metadata.uid.clone(),
                    spec_json,
                },
            )
            .await
            .map_err(|e| anyhow::anyhow!("volume {name} on {node}: {e:#}"))?;
        // The node reports open handles after attachment; acceptance is not evidence.
        debug!(volume = %name, node, "the destination was told to open the disk");
    }
    Ok(())
}

/// Ask the former source to forget referenced volume records without deleting bytes.
/// Called after attempting the volume-home updates. Failures are logged; this
/// terminal migration does not persist a retry obligation for the cleanup.
async fn forget_volumes_at(store: &EtcdStore, dispatch: &Dispatch, vm: &Vm, node: &str) {
    for name in vm.spec.referenced_volumes() {
        let uid = match store.get::<Volume>(&name).await {
            Ok(volume) => volume.metadata.uid,
            Err(e) => {
                debug!(volume = %name, node, error = %format!("{e:#}"),
                       "cannot say which disk to forget; leaving the source's record");
                continue;
            }
        };
        match dispatch
            .send(node, NodeCommand::ForgetVolume { id: uid })
            .await
        {
            Ok(_) => debug!(volume = %name, node, "the source has let the disk go"),
            Err(e) => warn!(volume = %name, node, error = %format!("{e:#}"),
                            "the source could not be told to forget the disk; it will go on \
                             reporting a volume this cluster ignores"),
        }
    }
}

/// Log the expected close; only node reports remove entries from openOn.
fn close_volumes_at(vm: &Vm, node: &str) {
    // A source teardown may still hold the disk until detach completes.
    for name in vm.spec.referenced_volumes() {
        debug!(volume = %name, node, "the source will report the disk closed");
    }
}

/// Move referenced volume homes that still name the source to the destination.
/// Failures are logged after the migration succeeds; there is no retry here.
async fn move_volume_home(store: &EtcdStore, vm: &Vm, from: &str, to: &str) {
    for name in vm.spec.referenced_volumes() {
        let moved = store
            .mutate::<Volume, _>(&name, |v| {
                if v.status.node.as_deref() == Some(from) {
                    v.status.node = Some(to.to_string());
                }
            })
            .await;
        match moved {
            Ok(_) => debug!(volume = %name, from, to, "the volume's home moved with the guest"),
            // The guest has moved; report the metadata failure without undoing it.
            Err(e) => warn!(volume = %name, from, to, error = %format!("{e:#}"),
                            "the volume's home could not be moved"),
        }
    }
}

/// The same document a `CreateInstance` carries, because the destination has
/// to build what the arriving configuration will name — and that
/// configuration was built from this spec on the source.
///
/// No seed: a migrating guest is past its first boot by definition, the seed
/// is written from the spec on every provision anyway, and a cloud-init image
/// that is not in the arriving config is one the destination need not have.
async fn spec_for(store: &EtcdStore, vm: &Vm) -> anyhow::Result<String> {
    let refs = crate::reconcile::volume_uids(store, vm).await?;
    crate::reconcile::build_spec_json(vm, &refs, None)
}

/// The address out of the destination's Ack.
///
/// JSON and not the bare bytes, because `Ack.payload` has no type on it and a
/// reader should not have to guess which of the two shapes it is holding.
fn peer_from(payload: &[u8]) -> anyhow::Result<String> {
    let answer: serde_json::Value =
        serde_json::from_slice(payload).map_err(|e| anyhow::anyhow!("unreadable answer: {e}"))?;
    answer
        .get("peer")
        .and_then(serde_json::Value::as_str)
        .filter(|p| !p.is_empty())
        .map(str::to_string)
        .ok_or_else(|| anyhow::anyhow!("the destination named no address to send to"))
}

/// Read the destination address from `status.peer`, falling back to the legacy
/// Preparing message only for older records without that field.
fn peer_of(status: &VmMigrationStatus) -> Option<String> {
    if let Some(peer) = status.peer.as_deref().filter(|p| !p.is_empty()) {
        return Some(peer.to_string());
    }
    status
        .phase()
        .message()
        .and_then(|m| m.rsplit_once(" is listening at "))
        .map(|(_, peer)| peer.to_string())
        .filter(|p| !p.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn delayed_completion_reports_never_authorize_timeout_cleanup() {
        for source in [None, Some("Sending"), Some("Gone"), Some("Unknown")] {
            for target in [None, Some("Provisioning"), Some("Running")] {
                assert!(
                    matches!(
                        verdict_on_timeout("source", "target", 150, source, target),
                        Verdict::TouchNothing(_)
                    ),
                    "source={source:?}, target={target:?}"
                );
            }
        }
    }

    #[test]
    fn old_reports_cannot_change_a_new_attempt_before_or_after_dispatch() {
        let mut guest = vm("web");
        guest.metadata.uid = "vm-incarnation".into();
        for phase in [
            VmMigrationPhaseKind::Preparing,
            VmMigrationPhaseKind::Running,
        ] {
            let mut m = migration("web", phase);
            m.status.migration_id = Some("M2".into());
            m.status.vm_uid = Some(guest.metadata.uid.clone());
            m.status.source_node = Some("source".into());
            m.status.target_node = Some("target".into());
            m.status.peer = Some("tcp:target:49000".into());
            for outcome in ["StillHere", "Gone", "Sending", "Arrived"] {
                let line = proto::MigrationReport {
                    vm_id: guest.metadata.uid.clone(),
                    migration_id: "M1".into(),
                    peer: "tcp:target:49000".into(),
                    outcome: outcome.into(),
                    message: "old".into(),
                };
                for reporter in ["source", "target"] {
                    apply_report(&mut m, &guest, reporter, &line);
                }
            }
            assert!(m.status.source_reported.is_none());
            assert!(m.status.target_reported.is_none());
            assert!(still_here("source", "target", &m.status).is_none());
        }
    }

    #[test]
    fn reports_check_reporter_peer_phase_and_incarnation_and_survive_roundtrip() {
        let mut guest = vm("web");
        guest.metadata.uid = "vm-incarnation".into();
        let mut m = migration("web", VmMigrationPhaseKind::Running);
        m.status.migration_id = Some("M2".into());
        m.status.vm_uid = Some(guest.metadata.uid.clone());
        m.status.source_node = Some("source".into());
        m.status.target_node = Some("target".into());
        m.status.peer = Some("tcp:target:49000".into());
        let mut line = proto::MigrationReport {
            vm_id: guest.metadata.uid.clone(),
            migration_id: "M2".into(),
            peer: "tcp:target:49000".into(),
            outcome: "Gone".into(),
            message: String::new(),
        };
        apply_report(&mut m, &guest, "target", &line);
        assert!(m.status.source_reported.is_none());
        for field in ["migration_id", "vm_id", "peer"] {
            let mut invalid = line.clone();
            match field {
                "migration_id" => invalid.migration_id.clear(),
                "vm_id" => invalid.vm_id = "recreated".into(),
                _ => invalid.peer = "wrong".into(),
            }
            apply_report(&mut m, &guest, "source", &invalid);
            assert!(m.status.source_reported.is_none());
        }
        m.status.recovery_required = true;
        let mut restarted: VmMigration =
            serde_json::from_slice(&serde_json::to_vec(&m).unwrap()).unwrap();
        apply_report(&mut restarted, &guest, "source", &line);
        line.outcome = "Sending".into();
        apply_report(&mut restarted, &guest, "source", &line);
        assert_eq!(restarted.status.source_reported.as_deref(), Some("Gone"));
        line.outcome = "Arrived".into();
        apply_report(&mut restarted, &guest, "target", &line);
        line.outcome = "Receiving".into();
        apply_report(&mut restarted, &guest, "target", &line);
        assert_eq!(restarted.status.target_reported.as_deref(), Some("Running"));
        assert!(!restarted.status.phase().kind().is_final());
    }
    use controller_api::{FirstFit, RunStrategy, VmMigrationSpec, VmSpec};

    fn vm(name: &str) -> Vm {
        controller_api::resources::new_vm(
            name,
            VmSpec {
                class: Default::default(),
                evacuation: Default::default(),
                cluster_selector: Default::default(),
                node_selector: Default::default(),
                anti_affinity: Vec::new(),
                node_name: Some("agent-1".into()),
                cluster_name: None,
                run_strategy: RunStrategy::Running,
                tenant: Some("acme".into()),
                vm: serde_json::json!({}),
            },
        )
    }

    fn migration(vm: &str, phase: VmMigrationPhaseKind) -> VmMigration {
        let mut m = VmMigration::declare(
            &format!("{vm}-x"),
            VmMigrationSpec {
                tenant: "acme".into(),
                vm: vm.to_string(),
                target_node: None,
            },
        );
        m.status.reported = Some(controller_api::VmMigrationReported::by(
            "target",
            phase,
            controller_api::VmMigrationReason::Dispatched,
            None,
            Utc::now(),
        ));
        m.settle(Utc::now());
        m
    }

    /// The window, and both its edges. `Pending` has made nothing ready, so a
    /// second open at that point is a second open; the two terminal phases
    /// have one side already let go, so a list that still named two would be
    /// a leak rather than a migration.
    #[test]
    fn only_a_migration_that_is_under_way_permits_a_second_open() {
        for (phase, allowed) in [
            (VmMigrationPhaseKind::Pending, false),
            (VmMigrationPhaseKind::Preparing, true),
            (VmMigrationPhaseKind::Running, true),
            (VmMigrationPhaseKind::Succeeded, false),
            (VmMigrationPhaseKind::Failed, false),
        ] {
            let all = vec![migration("web-1", phase)];
            assert_eq!(
                phase_for(&all, &vm("web-1")).is_some(),
                allowed,
                "{}",
                phase.as_str()
            );
        }
    }

    /// Refuse a second active migration of the same VM before preparing a target;
    /// its cleanup must not destroy the first migration's receiving VMM.
    #[test]
    fn a_second_record_for_one_guest_never_reaches_a_destination() {
        let mine = migration("web-1", VmMigrationPhaseKind::Pending);
        let sibling = |vm: &str, phase| {
            let mut m = migration(vm, phase);
            m.metadata.name = format!("{vm}-y");
            m
        };

        // Nothing else on file, and the record's own entry in the list: this
        // migration is the one carrying the move.
        assert!(!another_attempt_in_flight(&[], &mine));
        assert!(
            !another_attempt_in_flight(std::slice::from_ref(&mine), &mine),
            "a record is not another attempt at itself"
        );

        // Every phase that is not an ending, `Pending` included: a record
        // nothing has acted on yet is one that will be acted on inside the
        // tick, and this is asked one line before a claim.
        for phase in [
            VmMigrationPhaseKind::Pending,
            VmMigrationPhaseKind::Preparing,
            VmMigrationPhaseKind::Running,
        ] {
            assert!(
                another_attempt_in_flight(&[sibling("web-1", phase)], &mine),
                "{}",
                phase.as_str()
            );
        }

        // And the two endings, which have let go of both machines.
        for phase in [
            VmMigrationPhaseKind::Succeeded,
            VmMigrationPhaseKind::Failed,
        ] {
            assert!(
                !another_attempt_in_flight(&[sibling("web-1", phase)], &mine),
                "{}",
                phase.as_str()
            );
        }

        // Another guest's move is not this guest's business.
        assert!(!another_attempt_in_flight(
            &[sibling("web-2", VmMigrationPhaseKind::Running)],
            &mine
        ));
    }

    /// Somebody else's migration is not this vm's permission — neither
    /// another vm's nor the same name in another tenant.
    #[test]
    fn a_migration_of_another_vm_permits_nothing() {
        let all = vec![migration("web-2", VmMigrationPhaseKind::Running)];
        assert!(phase_for(&all, &vm("web-1")).is_none());

        let mut theirs = migration("web-1", VmMigrationPhaseKind::Running);
        theirs.spec.tenant = "other".into();
        assert!(phase_for(&[theirs], &vm("web-1")).is_none());
    }

    fn node(name: &str) -> Candidate {
        Candidate {
            accepts: Vec::new(),
            name: name.to_string(),
            connected: true,
            alive: true,
            schedulable: true,
            unhealthy: Vec::new(),
            free: controller_api::Capacity {
                vcpus: 8,
                mem_mib: 8192,
            },
            machine: None,
            catalogue: vec!["hypervisor/cloud-hypervisor".to_string()],
            kind: controller_api::CandidateKind::Node,
            hosted: Vec::new(),
            labels: Default::default(),
        }
    }

    fn node_object(name: &str, endpoint: Option<&str>) -> Node {
        let mut n = Node::declare(name, controller_api::NodeSpec::default());
        n.status.ready = true;
        n.status.session_endpoint = endpoint.map(str::to_string);
        n
    }

    /// A destination held by a sibling replica remains eligible through Dispatch;
    /// local session absence alone must not reject it.
    #[test]
    fn a_node_another_replica_holds_the_session_with_can_take_a_guest() {
        let mut elsewhere = node("agent-1b");
        elsewhere.connected = false; // not OUR session
        let nodes = vec![node_object("agent-1b", Some("10.128.1.104:3001"))];
        assert!(reaches(&elsewhere, &nodes));

        // ...and a node NO replica holds is still out of reach.
        let nodes = vec![node_object("agent-1b", None)];
        assert!(!reaches(&elsewhere, &nodes));

        // A node this replica holds itself needs no object to say so — the
        // widening only ever adds, so a stale endpoint cannot take a live
        // session away.
        assert!(reaches(&node("agent-1b"), &[]));
    }

    /// The source is never a candidate for its own migration, and the
    /// sentence when nothing is left names the vm.
    #[test]
    fn the_machine_the_guest_is_on_is_not_somewhere_for_it_to_go() {
        let fleet = vec![node("agent-1"), node("agent-2")];
        assert_eq!(
            choose_target(&FirstFit, &vm("web-1"), "agent-1", None, &fleet),
            Ok("agent-2".to_string())
        );
        // The only other machine IS the source: there is nowhere to go, and
        // the refusal is not "no room" but "no node".
        let alone = vec![node("agent-1")];
        let why = choose_target(&FirstFit, &vm("web-1"), "agent-1", None, &alone)
            .expect_err("nowhere to go");
        assert!(why.contains("web-1"), "{why}");
    }

    /// `--to` is a requirement and not a preference: a node that cannot take
    /// the guest is refused BY NAME, and the scheduler is never asked for a
    /// second opinion.
    #[test]
    fn a_named_node_is_answered_about_and_never_replaced() {
        let mut fleet = vec![node("agent-1"), node("agent-2"), node("agent-3")];
        assert_eq!(
            choose_target(&FirstFit, &vm("web-1"), "agent-1", Some("agent-3"), &fleet),
            Ok("agent-3".to_string())
        );

        // Cordoned: refused by name, and agent-2 — which would have done — is
        // not quietly used instead.
        fleet[2].schedulable = false;
        let why = choose_target(&FirstFit, &vm("web-1"), "agent-1", Some("agent-3"), &fleet)
            .expect_err("cordoned");
        assert!(why.contains("agent-3"), "{why}");
        assert!(
            !why.contains("agent-2"),
            "and nothing else was chosen: {why}"
        );

        // And the source, named: the same refusal, because it is cut away
        // before the name is looked for.
        let why = choose_target(&FirstFit, &vm("web-1"), "agent-1", Some("agent-1"), &fleet)
            .expect_err("the source");
        assert!(why.contains("agent-1"), "{why}");
    }

    /// Named targets must satisfy the same full feasibility checks as scheduled ones.
    #[test]
    fn a_named_node_must_also_be_feasible() {
        let mut big = vm("web-1");
        big.spec.vm = serde_json::json!({"vcpus": 4, "memory_mib": 4096});
        let refused = |fleet: &[Candidate], vm: &Vm| {
            choose_target(&FirstFit, vm, "agent-1", Some("agent-3"), fleet)
                .expect_err("agent-3 cannot take this guest")
        };

        // Feasible, and the named node is answered with.
        let fleet = vec![node("agent-1"), node("agent-2"), node("agent-3")];
        assert_eq!(
            choose_target(&FirstFit, &big, "agent-1", Some("agent-3"), &fleet),
            Ok("agent-3".to_string())
        );

        // Too little room. agent-2 has plenty and is not quietly used.
        let mut full = fleet.clone();
        full[2].free = controller_api::Capacity {
            vcpus: 1,
            mem_mib: 512,
        };
        let why = refused(&full, &big);
        assert!(why.contains("agent-3") && !why.contains("agent-2"), "{why}");

        // The machine said itself something is wrong with it. A guest sent
        // into that is a guest sent into a node that is about to be drained.
        let mut wedged = fleet.clone();
        wedged[2].unhealthy = vec!["StoreUnhealthy".to_string()];
        let why = refused(&wedged, &big);
        assert!(why.contains("agent-3") && !why.contains("agent-2"), "{why}");

        // And the labels this vm selects, which agent-3 does not carry.
        let mut picky = big.clone();
        picky
            .spec
            .node_selector
            .insert("rack".to_string(), "b".to_string());
        let why = refused(&fleet, &picky);
        assert!(why.contains("agent-3") && !why.contains("agent-2"), "{why}");
    }

    /// A node with no hypervisor is storage and nothing else, and a guest
    /// cannot be sent to it however much room it has.
    #[test]
    fn a_node_that_runs_no_vms_is_not_a_destination() {
        let mut storage_only = node("agent-2");
        storage_only.catalogue = Default::default();
        let fleet = vec![node("agent-1"), storage_only];
        let why = choose_target(&FirstFit, &vm("web-1"), "agent-1", Some("agent-2"), &fleet)
            .expect_err("no hypervisor");
        assert!(why.contains("running a hypervisor"), "{why}");
    }

    /// The destination's answer, and the two ways it can be useless.
    #[test]
    fn the_address_to_send_to_comes_out_of_the_acks_payload() {
        assert_eq!(
            peer_from(br#"{"peer":"tcp:10.0.0.5:49000"}"#).expect("an address"),
            "tcp:10.0.0.5:49000"
        );
        // An empty string is not an address, and neither is a missing key or
        // bytes that are not JSON at all. All three say so rather than
        // sending a guest to "".
        for bad in [&br#"{"peer":""}"#[..], &br#"{}"#[..], &b"not json"[..]] {
            assert!(
                peer_from(bad).is_err(),
                "{:?}",
                String::from_utf8_lossy(bad)
            );
        }
    }

    /// The budget is measured from `startedAt`, and a migration that has not
    /// started has not run out of time.
    #[test]
    fn a_migration_runs_out_of_time_only_after_it_started() {
        let mut m = migration("web-1", VmMigrationPhaseKind::Preparing);
        assert!(
            overdue(&m, Duration::from_secs(30)).is_none(),
            "not started"
        );

        m.status.started_at = Some(Utc::now() - chrono::Duration::seconds(5));
        assert!(overdue(&m, Duration::from_secs(30)).is_none(), "time left");
        assert_eq!(overdue(&m, Duration::from_secs(1)), Some(5));
    }

    /// The transfer budget is configuration; the prepare budget is not. Zero
    /// reads as "the default", because a zero in a config file is a key
    /// somebody meant to fill in.
    #[test]
    fn only_the_transfer_half_is_configurable() {
        let default = Timeouts::default();
        assert_eq!(default.prepare, Duration::from_secs(30));
        assert_eq!(default.transfer, Duration::from_secs(120));

        let set = Timeouts::with_transfer_secs(Some(600));
        assert_eq!(set.transfer, Duration::from_secs(600));
        assert_eq!(set.prepare, default.prepare, "the local half is a constant");

        assert_eq!(
            Timeouts::with_transfer_secs(Some(0)).transfer,
            default.transfer
        );
        assert_eq!(
            Timeouts::with_transfer_secs(None).transfer,
            default.transfer
        );
    }
    /// Source failure evidence can end a transfer before its timeout when the source
    /// still owns the guest. Cleanup must preserve a destination that might hold the
    /// only remaining copy.
    #[test]
    fn a_source_that_still_has_the_guest_ends_the_migration_without_a_timeout() {
        // Field by field and not a struct literal: `status.phase` is private
        // since struktur 4, and a literal that leaves a private field out is
        // refused even with `..Default::default()`.
        let status = |reported: Option<&str>, target_said: Option<&str>| {
            let mut status = VmMigrationStatus::default();
            status.source_reported = reported.map(str::to_string);
            status.source_message = Some("cloud-hypervisor is serving the guest here again".into());
            status.target_reported = target_said.map(str::to_string);
            status
        };

        // Absent, Sending and Gone reports do not prove the source kept the guest.
        // Gone is handled separately by the timeout verdict to protect the destination.
        for said in [None, Some("Sending"), Some("Gone")] {
            assert_eq!(still_here("agent-1", "agent-2", &status(said, None)), None);
        }

        // The destination holds no guest — silence, or its own word off the
        // GUEST rather than off its bookkeeping. Tear it down and say why.
        for seen in [None, Some("Provisioning")] {
            let Some(Verdict::TearDownTheDestination(why)) =
                still_here("agent-1", "agent-2", &status(Some("StillHere"), seen))
            else {
                panic!("a destination with no guest is tidied up");
            };
            assert!(why.contains("agent-1") && why.contains("agent-2"), "{why}");
            assert!(
                why.contains("cloud-hypervisor is serving the guest here again"),
                "and it is the node's own sentence, not a summary: {why}"
            );
            assert!(why.contains("torn down"), "{why}");
        }

        // Both ends claim it. Nothing is touched: a VMM left standing is a
        // leak, and a guest destroyed is not something you get back.
        let Some(Verdict::TouchNothing(why)) = still_here(
            "agent-1",
            "agent-2",
            &status(Some("StillHere"), Some("Running")),
        ) else {
            panic!("two machines claiming one vm is not a tidy-up");
        };
        assert!(why.contains("two machines claim one vm"), "{why}");
        assert!(why.contains("nothing here has been torn down"), "{why}");
        assert!(why.contains("Running"), "and what each of them said: {why}");
    }

    /// Source Gone evidence prevents destination cleanup on transfer timeout, even
    /// before the destination has reported: it may hold the only remaining guest.
    #[test]
    fn a_source_that_let_the_guest_go_leaves_the_destination_alone() {
        let verdict = |source_said: Option<&str>, target_said: Option<&str>| {
            verdict_on_timeout("agent-1", "agent-2", 150, source_said, target_said)
        };

        // The source is gone. Neither silence nor `Provisioning` from the
        // destination makes it safe to destroy anything.
        for target_said in [None, Some("Provisioning")] {
            let Verdict::TouchNothing(why) = verdict(Some("Gone"), target_said) else {
                panic!("a destination is not torn down when the source let the guest go");
            };
            assert!(why.contains("agent-1") && why.contains("agent-2"), "{why}");
            assert!(why.contains("let the guest go"), "{why}");
            assert!(
                !why.contains("running the vm as before"),
                "and it does not claim the source still serves it: {why}"
            );
        }

        for source_said in [None, Some("Sending"), Some("Unknown")] {
            assert!(matches!(
                verdict(source_said, None),
                Verdict::TouchNothing(_)
            ));
        }

        // And the third reading, unchanged: the destination said something
        // that is not `Provisioning`, so both ends may claim the vm.
        let Verdict::TouchNothing(why) = verdict(None, Some("Running")) else {
            panic!("a destination that may hold the guest is not torn down");
        };
        assert!(why.contains("may hold the guest"), "{why}");
    }

    /// Astra finding S05, 2026-09-23: the address to send to is a FIELD, and
    /// the sentence is only what records written before the field have.
    ///
    /// The sentence `prepare` writes at its claim — "preparing agent-2" —
    /// names no address at all, and reading one out of it is what made a
    /// replica that saw a prepare in progress believe the address had been
    /// lost.
    #[test]
    fn the_address_to_send_to_is_a_field_and_the_sentence_is_only_a_fallback() {
        // Through `settle`, because `status.phase` is derived and private
        // since struktur 4: a `reported` written by hand is not a phase until
        // the object has been settled, which is what a read off the store
        // does.
        let said = |message: &str| {
            let mut m = migration("web-1", VmMigrationPhaseKind::Preparing);
            m.status.reported = Some(controller_api::VmMigrationReported::here(
                VmMigrationPhaseKind::Preparing,
                controller_api::VmMigrationReason::Dispatched,
                Some(message.to_string()),
                Utc::now(),
            ));
            m.settle(Utc::now());
            m.status
        };

        // The claim's own sentence, which is every prepare's first word: no
        // address has been named yet, and none is invented.
        assert_eq!(peer_of(&said("preparing agent-2")), None);
        assert_eq!(peer_of(&VmMigrationStatus::default()), None);

        // An old record, from before the field: the sentence is all there is.
        assert_eq!(
            peer_of(&said("agent-2 is listening at tcp:10.0.0.5:49000")),
            Some("tcp:10.0.0.5:49000".to_string())
        );

        // And with both, the field wins — it is what the destination
        // answered, rather than what was written about it.
        let mut both = said("agent-2 is listening at tcp:10.0.0.5:49000");
        both.peer = Some("tcp:10.0.0.9:49000".to_string());
        assert_eq!(peer_of(&both), Some("tcp:10.0.0.9:49000".to_string()));
    }

    /// A Preparing migration without an address retains its full preparation budget,
    /// including when another replica observes the in-progress command.
    #[tokio::test]
    async fn a_prepare_that_has_not_named_its_address_yet_is_given_its_budget() {
        // The source is dialled into this replica, so a command for it would
        // land in `rx` rather than going anywhere. The store is never asked
        // anything if this pass does what it should — which is the other half
        // of what is asserted, since every write below would fail against it.
        let registry = std::sync::Arc::new(crate::session::SessionRegistry::new());
        let (tx, mut rx) = tokio::sync::mpsc::channel(4);
        registry.attach("agent-1", &tx);
        let store = EtcdStore::connect(&["http://127.0.0.1:1".to_string()], "/migration-test")
            .await
            .expect("the etcd client is built lazily");
        let dispatch = Dispatch::new(
            registry,
            std::sync::Arc::new(
                EtcdStore::connect(&["http://127.0.0.1:1".to_string()], "/migration-test")
                    .await
                    .expect("the etcd client is built lazily"),
            ),
            std::sync::Arc::new(crate::logs::Forward {
                cluster: "cluster-1".into(),
                sibling: controller_api::forward::Sibling {
                    serves_tls: false,
                    tls: None,
                },
            }),
        );

        let mut m = migration("web-1", VmMigrationPhaseKind::Preparing);
        m.status.source_node = Some("agent-1".to_string());
        m.status.target_node = Some("agent-2".to_string());
        m.status.started_at = Some(Utc::now() - chrono::Duration::seconds(2));
        m.status.reported = Some(controller_api::VmMigrationReported::here(
            VmMigrationPhaseKind::Preparing,
            controller_api::VmMigrationReason::Dispatched,
            Some("preparing agent-2".to_string()),
            Utc::now(),
        ));
        m.settle(Utc::now());

        send(&store, &dispatch, Timeouts::default(), &m, &vm("web-1"))
            .await
            .expect("a prepare with time left is not this pass's to end");

        // Nothing went to the source, and nothing went to the destination
        // either — no `MigrateOut`, and above all no `Destroy`.
        assert!(
            rx.try_recv().is_err(),
            "a prepare inside its budget is left alone"
        );
    }

    /// A guest of exactly `node()`'s size, so that one of them fills a
    /// machine and the second has to be told no.
    fn whole_machine(name: &str) -> Vm {
        let mut guest = vm(name);
        guest.spec.vm = serde_json::json!({"vcpus": 8, "memory_mib": 8192});
        guest
    }

    /// Destination reservations prevent two migrations from consuming the same free
    /// capacity, for both named and scheduler-selected targets.
    #[test]
    fn two_migrations_to_a_node_with_room_for_one_do_not_both_pass() {
        let first = whole_machine("web-1");
        let second = whole_machine("web-2");
        // agent-2 is the only machine that is not the source.
        let fleet = vec![node("agent-1"), node("agent-2")];
        assert_eq!(
            choose_target(&FirstFit, &first, "agent-1", None, &fleet),
            Ok("agent-2".to_string()),
            "there is room for the first"
        );
        assert_eq!(
            choose_target(&FirstFit, &second, "agent-1", Some("agent-2"), &fleet),
            Ok("agent-2".to_string()),
            "and, measured alone, for the second"
        );

        // The first move writes its promise down. Nothing is bound yet — the
        // guest is still on agent-1, and will be until the transfer finishes
        // — so this object is the only thing in the cluster that knows.
        let promise = CapacityReservation::of(
            &migration("web-1", VmMigrationPhaseKind::Pending),
            &first,
            "agent-2",
        );
        let mut after = fleet.clone();
        controller_api::hold(&mut after, std::slice::from_ref(&promise));

        let why = choose_target(&FirstFit, &second, "agent-1", None, &after)
            .expect_err("the second move has nowhere to go");
        assert!(why.contains("web-2"), "it is about the guest: {why}");
        let why = choose_target(&FirstFit, &second, "agent-1", Some("agent-2"), &after)
            .expect_err("and naming the node does not buy the room back");
        assert!(why.contains("agent-2"), "it is about the machine: {why}");

        // Given back, the machine is a candidate again — the promise is a
        // size and a moment, not a veto.
        assert_eq!(
            choose_target(&FirstFit, &second, "agent-1", None, &fleet),
            Ok("agent-2".to_string())
        );
    }

    /// Exclude a migration's own reservation when reconsidering its target after
    /// a crash between reservation and claim, avoiding double-counted demand.
    #[test]
    fn a_records_own_reservation_does_not_refuse_its_own_move() {
        let guest = whole_machine("web-1");
        let moving = migration("web-1", VmMigrationPhaseKind::Pending);
        let promise = CapacityReservation::of(&moving, &guest, "agent-2");
        let taken = std::slice::from_ref(&promise);

        let mut fleet = vec![node("agent-1"), node("agent-2")];
        controller_api::hold(&mut fleet, taken);
        assert!(
            choose_target(&FirstFit, &guest, "agent-1", Some("agent-2"), &fleet).is_err(),
            "taken off, the machine is exactly this guest too full"
        );

        give_back(&mut fleet, taken, &promise);
        assert_eq!(
            choose_target(&FirstFit, &guest, "agent-1", Some("agent-2"), &fleet),
            Ok("agent-2".to_string()),
            "and put back, it is the machine this very record promised"
        );

        // Somebody else's promise is not given back, and the guard is the
        // name: adding back a number nobody subtracted would invent room.
        let theirs = CapacityReservation::of(
            &migration("web-2", VmMigrationPhaseKind::Pending),
            &whole_machine("web-2"),
            "agent-2",
        );
        let mut other = vec![node("agent-1"), node("agent-2")];
        controller_api::hold(&mut other, std::slice::from_ref(&theirs));
        give_back(&mut other, std::slice::from_ref(&theirs), &promise);
        assert!(
            choose_target(&FirstFit, &guest, "agent-1", Some("agent-2"), &other).is_err(),
            "another move's promise stays where it is"
        );
    }

    /// **A reservation outlives nothing**, as the sweep sees it: a promise is
    /// live exactly while a migration of its own name AND uid is still being
    /// carried.
    ///
    /// The four ways to become an orphan are the four ways that comparison
    /// fails, and the fourth is why the uid is on the object at all: a
    /// migration is named for a vm and a moment, and a record can be removed
    /// and one made again under the same name.
    #[test]
    fn a_reservation_whose_migration_is_over_is_an_orphan() {
        let guest = whole_machine("web-1");
        let live = migration("web-1", VmMigrationPhaseKind::Preparing);
        let held = CapacityReservation::of(&live, &guest, "agent-2");
        let name_of = |rs: Vec<&CapacityReservation>| -> Vec<String> {
            rs.into_iter().map(|r| r.metadata.name.clone()).collect()
        };

        let now = Utc::now();
        assert!(
            controller_api::orphaned_reservations(
                std::slice::from_ref(&held),
                std::slice::from_ref(&live),
                &[],
                now
            )
            .is_empty(),
            "a move that is still being carried keeps its room"
        );

        // Finished, failed, deleted, and gone.
        for phase in [
            VmMigrationPhaseKind::Succeeded,
            VmMigrationPhaseKind::Failed,
        ] {
            let mut over = live.clone();
            over.status.reported = Some(controller_api::VmMigrationReported::by(
                "target",
                phase,
                controller_api::VmMigrationReason::Abandoned,
                Some("over".to_string()),
                Utc::now(),
            ));
            over.settle(Utc::now());
            assert_eq!(over.status.phase().kind(), phase);
            assert_eq!(
                name_of(controller_api::orphaned_reservations(
                    std::slice::from_ref(&held),
                    std::slice::from_ref(&over),
                    &[],
                    now
                )),
                vec![held.metadata.name.clone()],
                "{phase:?}"
            );
        }
        let mut removed = live.clone();
        removed.metadata.deletion_timestamp = Some(Utc::now());
        assert_eq!(
            name_of(controller_api::orphaned_reservations(
                std::slice::from_ref(&held),
                std::slice::from_ref(&removed),
                &[],
                now
            )),
            vec![held.metadata.name.clone()],
            "a record on its way out carries nothing"
        );
        assert_eq!(
            name_of(controller_api::orphaned_reservations(
                std::slice::from_ref(&held),
                &[],
                &[],
                now
            )),
            vec![held.metadata.name.clone()],
            "and a record that is gone carries nothing either"
        );

        // The one a name alone would get wrong: same name, later record.
        let mut again = live.clone();
        again.metadata.uid = uuid::Uuid::new_v4().to_string();
        assert_eq!(
            name_of(controller_api::orphaned_reservations(
                std::slice::from_ref(&held),
                std::slice::from_ref(&again),
                &[],
                now
            )),
            vec![held.metadata.name.clone()],
            "a later record of the same name is not this promise's migration"
        );
    }

    /// An etcd of one's own, the way `reconcile::tests` takes one.
    ///
    /// `#[ignore]`: it needs an etcd. Start one and name it:
    ///
    /// ```text
    /// MEISTER_TEST_ETCD=http://127.0.0.1:23700 \
    ///   cargo test -p meister-cluster-controller -- --ignored reservation
    /// ```
    async fn test_store() -> EtcdStore {
        let endpoint = std::env::var("MEISTER_TEST_ETCD")
            .unwrap_or_else(|_| "http://127.0.0.1:23700".to_string());
        let prefix = format!("/migration-reservation-test/{}", uuid::Uuid::new_v4());
        EtcdStore::connect(&[endpoint], &prefix)
            .await
            .expect("an etcd to talk to; see the function's note")
    }

    #[tokio::test]
    #[ignore = "needs an existing etcd; see test_store"]
    async fn timeout_retains_reservation_and_accepts_late_completion_reports() {
        let store = std::sync::Arc::new(test_store().await);
        let guest = store.create(&vm("late-guest")).await.unwrap();
        let mut moving = migration("late-guest", VmMigrationPhaseKind::Running);
        moving.status.migration_id = Some(moving.metadata.uid.clone());
        moving.status.vm_uid = Some(guest.metadata.uid.clone());
        moving.status.source_node = Some("source".into());
        moving.status.target_node = Some("target".into());
        moving.status.peer = Some("tcp:target:49000".into());
        moving.status.started_at = Some(Utc::now() - chrono::Duration::seconds(300));
        moving.status.target_reported = Some("Provisioning".into());
        let moving = store.create(&moving).await.unwrap();
        let promise = store
            .create(&CapacityReservation::of(&moving, &guest, "target"))
            .await
            .unwrap();
        let registry = std::sync::Arc::new(crate::session::SessionRegistry::new());
        let (tx, mut rx) = tokio::sync::mpsc::channel(4);
        registry.attach("source", &tx);
        registry.attach("target", &tx);
        let dispatch = Dispatch::new(
            registry,
            store.clone(),
            std::sync::Arc::new(crate::logs::Forward {
                cluster: "cluster".into(),
                sibling: controller_api::forward::Sibling {
                    serves_tls: false,
                    tls: None,
                },
            }),
        );
        tokio::select! {
            result = settle(&store, &dispatch, Timeouts::default(), &moving, &guest) => result.unwrap(),
            command = rx.recv() => panic!("timeout dispatched an unauthorized command: {command:?}"),
        }
        let unknown: VmMigration = store.get(&moving.metadata.name).await.unwrap();
        assert!(unknown.status.recovery_required);
        assert!(!unknown.status.phase().kind().is_final());
        assert!(unknown.status.finished_at.is_none());
        let _: CapacityReservation = store.get(&promise.metadata.name).await.unwrap();
        assert!(
            controller_api::orphaned_reservations(
                &[promise],
                &[unknown],
                std::slice::from_ref(&guest),
                Utc::now()
            )
            .is_empty()
        );
        for (node, outcome) in [("source", "Gone"), ("target", "Arrived")] {
            ingest_reports(
                &store,
                std::slice::from_ref(&guest),
                node,
                &proto::StatusReport {
                    migrations: vec![proto::MigrationReport {
                        vm_id: guest.metadata.uid.clone(),
                        migration_id: moving.metadata.uid.clone(),
                        peer: "tcp:target:49000".into(),
                        outcome: outcome.into(),
                        message: String::new(),
                    }],
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        }
        let recovered: VmMigration = store.get(&moving.metadata.name).await.unwrap();
        assert_eq!(recovered.status.source_reported.as_deref(), Some("Gone"));
        assert_eq!(recovered.status.target_reported.as_deref(), Some("Running"));
        assert!(rx.try_recv().is_err());
    }

    /// The room goes back when the move ends — through `fail`, which is the
    /// one funnel every failure in this file reaches, `abandon` included.
    #[tokio::test]
    #[ignore = "needs an etcd; see test_store"]
    async fn a_failed_migration_gives_its_room_back() {
        let store = test_store().await;
        let guest = store
            .create(&whole_machine("web-1"))
            .await
            .expect("the guest");
        let moving = store
            .create(&migration("web-1", VmMigrationPhaseKind::Pending))
            .await
            .expect("the record");
        let promise = store
            .create(&CapacityReservation::of(&moving, &guest, "agent-2"))
            .await
            .expect("the promise");
        assert_eq!(promise.spec.mem_mib, 8192, "the guest's size travelled");

        fail(&store, &moving, "the destination said no".to_string())
            .await
            .expect("the ending is written");

        let ended: VmMigration = store.get(&moving.metadata.name).await.expect("the record");
        assert_eq!(ended.status.phase().kind(), VmMigrationPhaseKind::Failed);
        let left: Vec<CapacityReservation> = store.list().await.expect("the listing");
        assert!(
            left.is_empty(),
            "a failed move holds no room: {:?}",
            left.iter().map(|r| &r.metadata.name).collect::<Vec<_>>()
        );

        // And failing again — a second replica, a re-read — is not an error
        // and takes nothing that is not there.
        fail(&store, &moving, "and again".to_string())
            .await
            .expect("releasing what was already released is a no-op");
    }

    /// The backstop for the process that was killed between the promise and
    /// the migration's last phase: one sweep per pass, and a promise nobody
    /// is coming for is given back.
    #[tokio::test]
    #[ignore = "needs an etcd; see test_store"]
    async fn the_reaper_takes_a_reservation_whose_migration_is_over() {
        let store = test_store().await;
        let guest = store
            .create(&whole_machine("web-1"))
            .await
            .expect("the guest");

        // One move that is still being carried, and one whose record is gone
        // — the crashed controller's leftover.
        let live = store
            .create(&migration("web-1", VmMigrationPhaseKind::Preparing))
            .await
            .expect("the live record");
        store
            .create(&CapacityReservation::of(&live, &guest, "agent-2"))
            .await
            .expect("its promise");
        let mut gone = migration("web-2", VmMigrationPhaseKind::Pending);
        gone.metadata.name = "web-2-20260923t193811".to_string();
        store
            .create(&CapacityReservation::of(&gone, &guest, "agent-2"))
            .await
            .expect("the orphan");

        // And a placement's claim beside them, for a guest that is BOUND —
        // the binding is the count now, and the claim is the same guest
        // twice. The crashed-between-binding-and-release leftover, Astra
        // finding R3-F05.
        store
            .create(&CapacityReservation::for_placement(&guest, "agent-2"))
            .await
            .expect("the bound guest's leftover claim");

        let held: Vec<CapacityReservation> = store.list().await.expect("the listing");
        assert_eq!(held.len(), 3);
        let migrations: Vec<VmMigration> = store.list().await.expect("the records");
        let vms: Vec<Vm> = store.list().await.expect("the guests");
        reap_reservations(&store, &held, &migrations, &vms).await;

        let left: Vec<CapacityReservation> = store.list().await.expect("the listing");
        assert_eq!(
            left.iter().map(|r| &r.spec.migration).collect::<Vec<_>>(),
            vec![&live.metadata.name],
            "the orphans went and the live one stayed"
        );

        // And it is idempotent: a second pass finds nothing to take.
        reap_reservations(&store, &left, &migrations, &vms).await;
        let after: Vec<CapacityReservation> = store.list().await.expect("the listing");
        assert_eq!(after.len(), 1);
    }
}
