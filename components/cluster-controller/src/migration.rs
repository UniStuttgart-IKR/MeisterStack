// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Live migration: the cluster's half.
//!
//! `VmMigration` is the object; this is what makes one happen. It lives in a
//! file of its own because a migration is the one operation in this tier that
//! holds both ends of a move at once — two nodes, two records, one guest —
//! and reading it interleaved with the ordinary lifecycle would bury the one
//! rule the whole thing is built around:
//!
//! > **Nothing is done to the source until the destination has the guest.**
//!
//! Everything here follows from that. The destination is built first and
//! completely; the source is told to send only once there is something to
//! send to; and every failure path tears down the DESTINATION and leaves the
//! source exactly as it was. A migration that does not work costs a record
//! and nothing else.
//!
//! # The phases, and what each one has already made true
//!
//! | Phase | What is standing | What breaks it |
//! |---|---|---|
//! | `Pending` | nothing | nothing to undo |
//! | `Preparing` | the destination has the disks open and a VMM listening | tear the destination down |
//! | `Running` | the source has been told to send | the same, and the source resumes its own guest |
//! | `Succeeded` | `spec.nodeName` names the destination, the source's record is gone | — |
//! | `Failed` | the source is running, as it was throughout | — |

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

/// How long each half of a migration may take before it is called failed.
///
/// Two numbers and not one, because the two halves fail for different reasons
/// and on different scales. Preparing is a node doing local work — a cgroup,
/// a few attaches, a VMM that has to come up — and thirty seconds is already
/// generous for it. The transfer is a guest's memory over a network, and how
/// long that may take is a property of the estate rather than of the code:
/// 512 MiB over a loopback is 300 ms, 32 GiB over a congested 10G link is
/// minutes. So the first is a constant and the second is configuration.
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

/// Is a live migration of this VM in flight?
///
/// The question `openOn` asks before it grows a second entry, and the reason
/// it is here rather than in `reconcile.rs`: the rule belongs to migration,
/// and the storage path only consults it.
///
/// `Preparing` and `Running` and nothing else — `second_open_is_a_migration`
/// says why, and this function is only the lookup in front of it. A store
/// that cannot be read answers "no", which is the safe direction: it refuses
/// a second open rather than allowing one on a guess.
pub async fn migration_in_flight(store: &EtcdStore, vm: &Vm) -> anyhow::Result<bool> {
    let migrations: Vec<VmMigration> = match store.list().await {
        Ok(m) => m,
        Err(StoreError::NotFound(_)) => Vec::new(),
        Err(e) => return Err(e.into()),
    };
    Ok(phase_for(&migrations, vm).is_some())
}

/// The phase of the live migration this VM is in, if any — the argument
/// `second_open_is_a_migration` takes, read off the store.
///
/// Separate from `migration_in_flight` because a caller that wants to SAY
/// which phase allowed a second open needs the phase and not a bool.
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

/// Does another record already name this VM and not be finished with it?
///
/// The rule `start_for_drain` has always kept for the road it owns — "at most
/// one in flight per VM" — as a value, so that the other road can keep it
/// too and so that it can be checked without a store.
///
/// Astra finding S06, 2026-09-23: `create_vm_migration` is idempotent by
/// NAME and refuses nothing else, so two operators, or one operator and a
/// retry under a fresh name, file two records for one guest. Both reach
/// `prepare`, both choose a destination, and the second one's destination
/// refuses the VM it already has a record of — a refusal this tier reads as
/// "the destination could not open the disks" and answers with `abandon`,
/// which destroys by the VM's uid on the node that is holding the FIRST
/// migration's receiving VMM.
///
/// Every non-final record counts, `Pending` included, which is deliberate: a
/// record that has not been acted on yet is one that will be acted on within
/// the tick, and this is a question asked one line before a claim. So two
/// records filed for one guest end with at most one of them building a
/// destination, and in the worst case — two replicas asking in the same
/// instant — with both failed and saying why. That is a pair of records an
/// operator can act on, which the alternative was not.
fn another_attempt_in_flight(all: &[VmMigration], mine: &VmMigration) -> bool {
    all.iter().any(|m| {
        m.metadata.name != mine.metadata.name
            && m.spec.vm == mine.spec.vm
            && !m.status.phase().kind().is_final()
    })
}

/// What the DESTINATION says about a guest that is moving to it.
///
/// Its own ingest, in its own file, and it exists because `ingest_status`'s
/// `ours` deliberately refuses a report from a node the VM is not bound to —
/// which, for the whole length of a migration, is exactly what the
/// destination is. Without this the cluster would have no way at all to learn
/// that the guest arrived: the one node that knows is the one node whose word
/// about that VM is thrown away.
///
/// It WRITES ONLY on the migration object and never on the VM. The VM's
/// status stays the binding's, which is the rule `ingest_status` states at
/// length and the reason it drops these reports in the first place — a node
/// that is not the binding must not be able to write itself into a VM's
/// status.
pub async fn ingest_arrivals(
    store: &EtcdStore,
    vms: &[Vm],
    node_id: &str,
    report: &StatusReport,
) -> anyhow::Result<()> {
    if report.vms.is_empty() {
        return Ok(());
    }
    let migrations: Vec<VmMigration> = match store.list().await {
        Ok(m) => m,
        Err(StoreError::NotFound(_)) => return Ok(()),
        Err(e) => return Err(e.into()),
    };
    for migration in migrations {
        if migration.status.phase().kind().is_final() {
            continue;
        }
        if migration.status.target_node.as_deref() != Some(node_id) {
            continue;
        }
        let Some(vm) = vms.iter().find(|v| v.metadata.name == migration.spec.vm) else {
            continue;
        };
        let Some(line) = report.vms.iter().find(|r| r.id == vm.metadata.uid) else {
            continue;
        };
        if migration.status.target_reported.as_deref() == Some(line.phase.as_str()) {
            continue;
        }
        let phase = line.phase.clone();
        store
            .mutate::<VmMigration, _>(&migration.metadata.name, |m| {
                m.status.target_reported = Some(phase.clone());
            })
            .await?;
        debug!(migration = %migration.metadata.name, node = node_id, phase = %phase,
               "the destination said something about the guest");
    }
    Ok(())
}

/// What the SOURCE says about a guest it was told to send.
///
/// The other half of `ingest_arrivals`, and it exists for a different reason:
/// the source IS the node the VM is bound to, so its report about the VM's
/// phase is taken the ordinary way. What that road cannot carry is the
/// transfer's own outcome — the VM is `Running` on the source right up to the
/// moment it is not — and that is exactly what a migration has to know.
///
/// It used to be the answer to `MigrateOut`, which is why the reconcile pass
/// awaited that answer for the length of a guest's memory (D16). Now the
/// command is accepted at once and this is the reading.
///
/// **Writes only on the migration**, like `ingest_arrivals` and for the same
/// rule: a node's word about a VM is the binding's business, and a transfer's
/// outcome is not a VM phase.
pub async fn ingest_departures(
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
        if migration.status.phase().kind().is_final() {
            continue;
        }
        if migration.status.source_node.as_deref() != Some(node_id) {
            continue;
        }
        let Some(vm) = vms.iter().find(|v| v.metadata.name == migration.spec.vm) else {
            continue;
        };
        let Some(line) = report
            .migrations
            .iter()
            .find(|m| m.vm_id == vm.metadata.uid)
        else {
            continue;
        };
        let message = (!line.message.is_empty()).then(|| line.message.clone());
        // Only on a change: a source says the same true thing every ten
        // seconds for the whole of a transfer, and a write per report would
        // churn etcd revisions and wake the migration watch while nothing
        // about the migration happened.
        if migration.status.source_reported.as_deref() == Some(line.outcome.as_str())
            && migration.status.source_message == message
        {
            continue;
        }
        let outcome = line.outcome.clone();
        store
            .mutate::<VmMigration, _>(&migration.metadata.name, |m| {
                m.status.source_reported = Some(outcome.clone());
                m.status.source_message = message.clone();
            })
            .await?;
        debug!(migration = %migration.metadata.name, node = node_id, outcome = %outcome,
               "the source said something about the send");
    }
    Ok(())
}

/// A drain asks for a live migration by making the same object an operator
/// makes by hand.
///
/// One reconciler for both roads, which is the argument for `VmMigration`
/// being a resource rather than a verb: a drain has no state of its own to
/// keep about a move it started, and the object is the state.
///
/// **At most one in flight per VM.** A drain reaches this conclusion every
/// five seconds for as long as the guest is still on the machine, and without
/// the check it would file a migration per pass — a dozen destinations for
/// one guest.
///
/// The name is the VM's and the moment's, in the same shape the CLI prints:
/// a migration is a thing that happened at a time, and two of them for one VM
/// are two rows in a history rather than one object overwritten.
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

/// A cloud asks for a live migration by making the same object.
///
/// The sibling of `start_for_drain`, and everything below it is the same
/// reconciler — which is the argument for `VmMigration` being a resource
/// rather than a verb, seen from a third road. A cloud that had to keep state
/// about a move it started would be a second lifecycle in a second place; the
/// object is the state, and it lives where the machines are.
///
/// Two things differ from the drain's. The NAME comes from up there: a
/// migration is a record somebody reads once rather than a thing they refer to
/// by name later, so the CLI mints it from the vm and the moment, and a name
/// minted down here could not be answered with. And a `target_node` may be
/// pinned, because somebody typed `--to`.
///
/// **Idempotent by name**, like every other create that arrives on this
/// session: a second command with the same name finds the first and says so
/// by doing nothing. The "at most one in flight per VM" rule of the drain is
/// deliberately NOT repeated — an operator who asks twice for one guest is
/// asking about one guest, and the reconciler's own `phase_for` is what stops
/// two from running.
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

/// Every migration this cluster holds, once per pass.
///
/// One phase step per pass and no more, which is the house rule and here it
/// is also a safety one: each phase leaves something standing on another
/// machine, and a loop that ran two of them would have no place to record
/// what it had already done if the process died between them. The object IS
/// the progress.
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

/// **A reservation outlives nothing.** Every promise whose move is over is
/// given back, once per pass — a migration's once the migration is final,
/// deleted or gone, a placement's once its guest is bound, gone, on its way
/// out, or the claim has stood longer than a placement can take.
///
/// Astra finding S07, 2026-09-23: this is what makes the reservation safe to
/// have at all. `fail` and `settle` give a promise back on the two roads a
/// migration can leave by, `place` gives a claim back after its binding, and
/// none of them runs in the process that was killed in between — so without
/// a sweep, a controller that died mid-move would hold a machine's room for
/// ever, and nothing in the fleet could say why the node was full. The
/// decision is `controller_api::orphaned_reservations`, where it can be
/// checked without a store.
///
/// `held` and `vms` are the pass's own readings and `migrations` is a fresh
/// one, which is the conservative pairing: a promise written after the pass
/// began is not in `held` and is therefore not touched, and a migration that
/// ended after the pass began IS seen. Wrong in the direction of reaping a
/// tick later rather than a tick too early — and since Astra finding R3-F05,
/// 2026-09-24, a tick too early would be safe as well: a placement's binding
/// is written only while its claim still stands, so a claim taken from under
/// a live placement costs that placement one retry and nobody any room.
///
/// The delete is guarded by the promise's own resourceVersion, for the reason
/// S19 gave the secrets: the name is the move's, moves are named for a vm and
/// a moment, and a record can be made again under a name that was used
/// before. A conflict here means somebody wrote that key between the listing
/// and now; the next pass looks again.
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

/// Put back, in this pass's own picture of the fleet, the room THIS record
/// has already promised.
///
/// A promise is somebody ELSE's claim on a machine; a record's own promise is
/// not a reason to refuse that record's own move. An earlier attempt that
/// wrote one and then died would otherwise make the destination look exactly
/// this guest too full, and the move would be failed by its own bookkeeping —
/// for ever, since every pass would write the same promise down again.
///
/// Only where the promise really was taken off, which is where the pass knew
/// about it: `held` is what `free` was built with, and adding back a number
/// nobody subtracted would invent room.
fn give_back(all: &mut [Candidate], held: &[CapacityReservation], mine: &CapacityReservation) {
    if !held.iter().any(|h| h.metadata.name == mine.metadata.name) {
        return;
    }
    if let Some(c) = all.iter_mut().find(|c| c.name == mine.spec.node) {
        c.free = c.free.plus(mine.spec.size());
    }
}

/// Give back the room this migration was holding.
///
/// Guarded by the promise's own resourceVersion and by whose it is, because
/// the key is named after the migration and a record can be made again under
/// a name that was used before: a late release that deleted by name alone
/// would take a LATER move's promise, and the node would then be offered to
/// an ordinary create while a guest was still flying into it. The same ABA
/// S19 closed for secrets.
///
/// Best effort on purpose, and it may be: it is called on the two roads a
/// migration leaves by, where the thing that must be recorded is the ENDING.
/// A release that did not go through is a promise the reaper takes on the
/// next pass, which is what the reaper is for.
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

// The confirmation after the promise — "does this claim still fit, counting
// every claim written before it" — is `controller_api::capacity::claim_holds`
// since Astra finding R3-F05, 2026-09-24: the ordinary placement makes the
// same claim and asks the same question, and the two roads have to answer it
// one way.

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
            return fail(
                store,
                &migration,
                format!("vm {} does not exist here any more", migration.spec.vm),
            )
            .await;
        }
        Err(e) => return Err(e.into()),
    };

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

    // One guest is moved once. Astra finding S06, 2026-09-23: the claim CAS
    // below is per MIGRATION, and two migration OBJECTS for one VM each win
    // their own — `create_vm_migration` mints a record per name and refuses
    // nothing, and the "at most one in flight" rule existed only inside
    // `start_for_drain`. What the second attempt then did was not a second
    // wasted preparation: the destination's agent refuses a VM it already has
    // a record of (`prepare_migration`), this tier reads that refusal as "the
    // destination could not open the disks", and `abandon` sends `Destroy`
    // BY THE VM's UID — to the node that is holding the first migration's
    // receiving VMM. The first move loses its destination to the second
    // attempt's tidy-up.
    //
    // Read immediately before the claim, so that the window between the
    // question and the answer is as short as this tier can make it, and
    // `fail` rather than a quiet return: an operator who asked twice is owed
    // a record saying which record is carrying the move.
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

    // The room at the destination, written down before ANYTHING is built
    // there — before the disks are opened, before the VMM, before the claim
    // that says this replica is carrying the move.
    //
    // Astra finding S07, 2026-09-23: a guest in flight is bound to the
    // machine it is LEAVING until `settle` moves the binding, so for the
    // whole length of a migration the destination is carrying a guest that no
    // sum over the VM objects can see. N migrations aimed at one node all
    // measured themselves against the same numbers and all passed, and so did
    // an ordinary create in the same window. This is that guest, written
    // where every replica can read it.
    //
    // Before the claim and not after, because the claim is what the next pass
    // reads as "this move is being carried": a crash in between would
    // otherwise leave a `Preparing` migration whose room nobody is holding,
    // which is the very gap this closes. In the other order the crash leaves
    // a promise for a migration that is still Pending — and the next pass
    // finds it, adopts it, and carries on.
    //
    // Both roads through the same write: a node somebody NAMED and a node the
    // scheduler picked are one `target` by the time this runs, so there is
    // one place where a destination is promised and one place where it is
    // given back.
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

    // A unique KEY is not a sum. Two replicas writing two promises onto one
    // node in the same millisecond both succeed, so the writer looks again
    // and asks where in the queue it stands — see `capacity::claim_holds`,
    // and `reservation_holds` for the order, which is etcd's own and
    // therefore the same on every replica. The queue holds the ordinary
    // placements' claims as well (Astra finding R3-F05), so a create that
    // claimed this node's last room a moment ago is counted here exactly as
    // another migration would be.
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
        // Astra finding R3-F04, 2026-09-24: a reading that failed is not a
        // passed check. The step ends here — before the claim, before the
        // disks are opened, before anything is sent to the destination — and
        // the migration stays Pending with its promise standing. The next
        // pass finds the promise, adopts it, and asks again.
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
        Ok(_) => {}
        Err(StoreError::Conflict(_)) => {
            debug!(migration = %name, "lost the prepare race");
            return Ok(());
        }
        Err(e) => return Err(e.into()),
    }

    // The disks, at the destination, BEFORE the VMM: the configuration that
    // will arrive in the stream names them by path, so a path that is not
    // open here is a guest arriving into nothing. `ProvisionVolume` is
    // idempotent by contract — every backend derives its name from the uid
    // and adopts what is already there — so this makes no second copy of
    // anything; what it makes is a record on this node.
    //
    // `openOn` grows by one here and shrinks again on every path out, which
    // is the whole reason that field exists: for the length of this migration
    // two machines legitimately have the same disk open.
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
        .mutate::<VmMigration, _>(&name, |m| {
            let phase = m.status.phase().kind();
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

/// `connected`, as a MIGRATION has to read it.
///
/// The shared candidate list marks `connected` strictly locally, and the
/// comment on it says exactly why: "a node with a live session *somewhere* is
/// still not a node this replica can send anything to."
///
/// That stopped being true in round 4. `Dispatch` forwards each of the four
/// commands a migration sends to whichever replica holds the node's session
/// (`d1e7c46`), so for THIS pass reachable means "some replica has it", which
/// is the thing `Node.status.sessionEndpoint` records for the forward to aim
/// at. Leaving the local reading in place fixed the sending of the command
/// and left the CHOOSING of the node a coin toss — which is the same defect
/// D-P2 was, one step earlier in the same function.
///
/// The e2e measured it after the fix: all three agents' sessions hung on
/// 10.128.1.104, and `vm migrate fabric-probe --to agent-1b` failed with
/// "node agent-1b cannot take this vm: it must be connected, schedulable,
/// running a hypervisor, and not the node the vm is already on" whenever
/// another replica won the object — about a node `node ls` showed ready,
/// schedulable, and offering a hypervisor.
///
/// Only ever widening: a candidate this replica can reach itself stays
/// reachable whatever the object says, so a node whose `sessionEndpoint` is
/// stale cannot take a session away from the replica that holds it.
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

/// The machines out of `all` that could hold a guest's saved state from
/// `source`, and the sentences for the ones that could not.
///
/// **The pre-flight check.** cloud-hypervisor v53 compares the CPUID before a
/// transfer and nothing else, so a machine-state mismatch is discovered two
/// milliseconds after the destination's vCPUs are made — in a log line the
/// control plane never reads, after the stream is open and after the guest
/// has been paused. This asks the same question before anything is built,
/// out of what both nodes said about themselves at Hello.
///
/// The rules and their arguments are `controller_api::live_migration_refusal`;
/// this is the loop in front of them, and the two things it adds are the two
/// this tier owns. A source that said nothing about itself — an agent from
/// before the field — refuses nothing, because a comparison needs two sides
/// and a rolling upgrade must not stop a fleet migrating. And the refusals
/// come back rather than being dropped, because the one sentence an operator
/// needs is which machine could not take the guest and why.
///
/// Pure, so that the whole table of it can be checked without a fleet.
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

/// Which node this guest is going to — or the sentence saying why none.
///
/// Without a store, so that the one decision worth arguing about in this file
/// can be checked rather than believed. The same shape `migration_refusal`
/// and `reschedule_refusal` have, and for the same reason.
///
/// Two rules, in this order:
///
///   * **the source is not a candidate.** "Move it to where it already is" is
///     not a migration, and this is the one exclusion that is not a matter of
///     strategy — it is cut away before any scheduler sees the list.
///   * **a named node is a hard requirement.** Somebody who writes
///     `--to agent-3` is asking about agent-3; quietly using agent-4 would
///     answer a question they did not ask. So a named node is checked and
///     never chosen from — and CHECKED means the same word it means for a
///     node the scheduler would have picked, which is `feasible`.
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
            // `feasible` and not a list of its own. Astra finding S07,
            // 2026-09-23: this branch used to ask four questions —
            // connected, schedulable, offers a hypervisor, not the source —
            // where the scheduler's own admission asks ten. So a node that
            // was up and willing took a guest it had no room for, or that
            // its labels did not select, or that a required anti-affinity
            // term forbade, or that had said itself it was wedged. What the
            // guest met on arrival was the agent refusing it, after the
            // disks had been opened there and a VMM built. One predicate for
            // both roads is what keeps "can this node take this vm" from
            // meaning two things depending on who asked.
            //
            // The hypervisor is still in it: every VM's `DevicePolicy` asks
            // for one, so `feasible` answers that question too, and a
            // storage-only node is refused by name exactly as before.
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

/// `Preparing` -> `Running`: tell the source to send.
///
/// **The only command in a migration that touches the source.** The phase is
/// written BEFORE it goes out, which is not bookkeeping tidiness: the send
/// blocks until the source's VMM exits, and a migration still reading
/// `Preparing` while its transfer was in the air would be killed by the
/// prepare timeout for taking too long over a thing it had finished.
async fn send(
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
        return fail(store, migration, "this migration has no ends".to_string()).await;
    };
    let peer = peer_of(&migration.status);

    // The budget first, and the missing address only after it. Astra finding
    // S05, 2026-09-23: this was the other way round, and there is no leader
    // here — `prepare` writes `Preparing` by CAS BEFORE it opens the disks at
    // the destination and blocks on `PrepareMigration`, and the address
    // reaches the record seconds later. Every other replica passes through
    // this function once per TICK (5 s) meanwhile, read "no address" as "the
    // controller died between the command and the write", and tore down a
    // destination that was being built correctly. A prepare that still has
    // time is a prepare in progress, whatever it has managed to write down.
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
                id: vm.metadata.uid.clone(),
                peer: peer.clone(),
            },
        )
        .await
    {
        // **Recorded, and nothing is torn down.** This is the line the first
        // live run was written to find, and it cost a guest to find it: from
        // the moment this command has GONE OUT, the destination may be the
        // only machine that has the guest, and an error here does not say
        // which side of that moment we are on. A command that timed out is
        // the sharpest case — the source stopped answering because its VMM
        // exited, which is what SUCCESS looks like — and the tidy-up that
        // followed destroyed a guest that had arrived.
        //
        // So the phase stays `Running`, the reason goes on the object, and
        // `settle` decides: if the destination reports the vm Running the
        // migration finishes, and if nothing ever arrives the transfer
        // timeout ends it — by then with evidence about which machine holds
        // what.
        // ...with ONE exception, and it is the one the source was taught to
        // say in round 4: cloud-hypervisor gives the guest back on a failed
        // send, so the source is serving it again and knows it. That answer
        // is not ambiguous about which machine holds the guest — it names the
        // machine, and the machine is this one. Ending on it is what the
        // sentence was added for; without this the answer arrived in seconds
        // and then sat in `Running` for the whole transfer timeout anyway,
        // which is what the lab measured.
        // `abandon` and not `fail`, for the same reason this branch exists at
        // all: the source names the machine holding the guest and it is the
        // source, so the destination CANNOT have it, and the tidy-up the
        // timeout path does only when it is sure is safe here immediately —
        // the destination is torn down and comes off the volumes' open set.
        let e = format!("{e:#}");
        if common::migration::guest_stayed(&e) {
            warn!(migration = %name, node = %source, reason = %e,
                  "the source kept the guest; the transfer is over");
            return abandon(store, dispatch, migration, vm, &target, e).await;
        }
        let why = format!("the source's answer did not come back: {e}");
        warn!(migration = %name, node = %source, reason = %why,
              "the send is unaccounted for; waiting for the destination to say");
        store
            .mutate::<VmMigration, _>(&name, |m| {
                let phase = m.status.phase().kind();
                m.status.reported = Some(controller_api::VmMigrationReported::here(
                    phase,
                    controller_api::VmMigrationReason::Reported,
                    Some(why.clone()),
                    Utc::now(),
                ));
            })
            .await?;
    }
    Ok(())
}

/// What is to be done when a source says the guest never left, and `None`
/// while it has said nothing of the kind.
///
/// Pure, and separate for the reason `choose_target` and `migration_refusal`
/// are: this is the one decision on the settle path worth arguing about, and
/// it decides whether a VMM on another machine is torn down. A decision that
/// can only be reached through a store is a decision nobody checks.
///
/// It exists at all because of D16. `MigrateOut` used to answer with the
/// outcome, so a failed send reached this tier as a command that never came
/// back — and the pass then had to wait out the whole transfer timeout to
/// work out which machine held the guest. v53 RESUMES a guest whose send
/// failed and goes on serving it, so the source knew all along; now it says
/// so on the next heartbeat and this reads it.
///
/// Two answers, and the line between them is the same one `abandon` draws:
///
///   * the destination has reported NOTHING, or `Provisioning` — it holds no
///     guest, so it is torn down and the source goes on as it was. That word
///     can be trusted because the agent reports it off the GUEST rather than
///     off its own bookkeeping.
///   * anything else — both ends claim the vm. Nothing is touched and a
///     person looks. A guest destroyed is not something you get back.
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

/// The two ways a migration can end on the source's word. Both are failures;
/// what differs is whether the destination may be tidied up.
#[derive(Debug, PartialEq, Eq)]
enum Verdict {
    TearDownTheDestination(String),
    TouchNothing(String),
}

/// What is to be done when the transfer budget is spent and the destination
/// has still not reported the guest.
///
/// The sibling of `still_here` and pure for the same reason: it decides
/// whether a VMM on another machine is torn down, and a decision that can
/// only be reached through a store is a decision nobody checks.
///
/// Two answers, and the line between them is the one `abandon` draws — a
/// destination that CANNOT hold the guest may be tidied up, and one that
/// might hold the only copy may not. Three readings go into it:
///
///   * **the source said `Gone`.** It dropped the vmm pid and detached the
///     volumes when its send finished; no guest is being served there. So
///     whatever the destination has or has not said yet, the destination is
///     the only machine that can hold this guest, and nothing here is
///     touched.
///   * **the destination has said nothing, or `Provisioning`.** It holds no
///     guest. That word can be trusted because the agent reports it off the
///     GUEST rather than off its own bookkeeping: a destination whose VMM
///     says Running reports Running, whatever its record still says. Tear it
///     down; the source is serving the guest as it was throughout.
///   * **anything else.** Both ends may claim the vm. A VMM left standing on
///     the destination is a leak; a guest destroyed is not something you get
///     back.
///
/// Astra finding S04, 2026-09-23: only the second and third readings were
/// here, so `SEND_GONE` — written by the source and carried to
/// `status.sourceReported` by `ingest_departures` — was read nowhere in this
/// tier. A send that completed while the destination's first report was
/// still in flight therefore ended in `abandon`: the destination was
/// destroyed by the VM's uid, and the record said "{source} is running the vm
/// as before" about a machine that had just let the guest go. That sentence
/// was true of no machine at all.
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
    if matches!(target_reported, None | Some("Provisioning")) {
        return Verdict::TearDownTheDestination(format!(
            "the guest had not arrived on {target} after {over}s; it said {said} and holds no \
             guest, so it has been torn down and {source} is running the vm as before"
        ));
    }
    Verdict::TouchNothing(format!(
        "the guest had not arrived on {target} after {over}s; the destination last said {said}, \
         so it may hold the guest and nothing here has been torn down — look at {source} and \
         {target} before deleting anything"
    ))
}

/// `Running` -> `Succeeded`: the destination says it has the guest, so the
/// binding moves and the source's record goes.
///
/// The order is the last safety property of the sequence. `spec.nodeName`
/// moves FIRST, because from the moment the destination has the guest the
/// object should name the machine that is actually running it — and only then
/// is the source told to destroy its record, which is a teardown that
/// detaches referenced volumes and deprovisions nothing.
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
        return fail(store, migration, "this migration has no ends".to_string()).await;
    };

    let arrived =
        migration.status.target_reported.as_deref() == Some(VmPhaseKind::Running.as_str());
    if !arrived {
        // The one answer that ends a migration before its timeout does, and
        // the one D16 made available: the SOURCE's own word about the send.
        // See `still_here`, where the decision is argued and can be checked
        // without a store.
        match still_here(&source, &target, &migration.status) {
            Some(Verdict::TearDownTheDestination(why)) => {
                return abandon(store, dispatch, migration, vm, &target, why).await;
            }
            Some(Verdict::TouchNothing(why)) => return fail(store, migration, why).await,
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
            Verdict::TouchNothing(why) => fail(store, migration, why).await,
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
            NodeCommand::Destroy {
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
        .mutate::<VmMigration, _>(&name, |m| {
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

/// Tear the DESTINATION down and record why, leaving the source untouched.
///
/// One function rather than five copies, because forgetting half of it is how
/// a failed migration turns into a leak: a VMM listening on a port for ever,
/// and a disk that two machines think they have open.
///
/// **Only callable while the source still has the guest**, which means: at
/// any point up to and including the dispatch of `MigrateOut`, and afterwards
/// only when the destination has never reported the vm. Past that line the
/// destination may hold the only copy of a running guest, and a tidy-up would
/// be a deletion. Both callers past the line check first, and the check is
/// argued where it is made.
async fn abandon(
    store: &EtcdStore,
    dispatch: &Dispatch,
    migration: &VmMigration,
    vm: &Vm,
    target: &str,
    why: String,
) -> anyhow::Result<()> {
    // Best effort, and it has to be: a destination that cannot be reached is
    // often exactly why this migration is failing. What must not happen is
    // that the failure goes unrecorded because the tidying did not work.
    if let Err(e) = dispatch
        .send(
            target,
            NodeCommand::Destroy {
                id: vm.metadata.uid.clone(),
            },
        )
        .await
    {
        warn!(migration = %migration.metadata.name, node = target,
              error = %format!("{e:#}"), "the destination could not be torn down");
    }
    close_volumes_at(vm, target);
    fail(store, migration, why).await
}

/// Write the ending. `Failed` always carries a sentence — it is the only
/// thing the object exists to say on the day somebody asks why a machine is
/// still full.
///
/// And the one funnel every failure goes through, which is why the room is
/// given back here: `abandon` ends in this, every refusal in `prepare` ends
/// in this, and a release written into each of them separately is a release
/// somebody forgets. Astra finding S07, 2026-09-23 — a reservation outlives
/// nothing, and a failed move is the commonest nothing.
///
/// Unconditional, including on the paths that ran before anything was ever
/// promised: giving back a promise that was never made is a read that finds
/// no key, which costs one round trip and cannot be wrong.
async fn fail(store: &EtcdStore, migration: &VmMigration, why: String) -> anyhow::Result<()> {
    let name = migration.metadata.name.clone();
    warn!(migration = %name, vm = %migration.spec.vm, reason = %why, "migration failed");
    store
        .mutate::<VmMigration, _>(&name, |m| {
            let now = Utc::now();
            m.status.finished_at = Some(now);
            m.status.reported = Some(controller_api::VmMigrationReported::here(
                VmMigrationPhaseKind::Failed,
                controller_api::VmMigrationReason::Abandoned,
                Some(why.clone()),
                now,
            ));
        })
        .await?;
    // After the ending and not before it, and the order is the invariant's:
    // a process killed between the two leaves a promise whose migration is
    // FINAL, which is exactly what the reaper takes. The other order would
    // leave a non-final migration with no room held, and the gap this whole
    // object exists to close would be open again for the length of one
    // destination's teardown.
    release(store, migration).await;
    Ok(())
}

/// How many seconds past its budget this migration is, or `None` while it
/// still has time. Measured from `startedAt`, which is written once when the
/// destination was chosen.
fn overdue(migration: &VmMigration, budget: Duration) -> Option<i64> {
    let started = migration.status.started_at?;
    let elapsed = Utc::now().signed_duration_since(started).num_seconds();
    (elapsed > budget.as_secs() as i64).then_some(elapsed)
}

/// Tell `node` to open every disk this VM refers to, and record that it has
/// them.
///
/// The command is the ordinary `ProvisionVolume` and the volume object's
/// PHASE is deliberately not touched: the disk is `Ready` where it is, and
/// writing `Provisioning` onto it because a second machine is opening it
/// would be this tier saying the bytes are being made again.
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
        // `openOn` is not written here since D4. The destination says it
        // itself on its next report, out of the record this command has just
        // given it (`VolumeStateReport.open`) — and that is the honest half
        // second: this pass knows the command was ACCEPTED, not that the disk
        // is open. One writer of that set, and it is the machine.
        debug!(volume = %name, node, "the destination was told to open the disk");
    }
    Ok(())
}

/// Tell `node` to stop being a machine that holds these disks at all.
///
/// The last thing the source of a finished migration is told, and it is
/// bookkeeping in both tiers at once: `close_volumes_at` above takes the node
/// off the OBJECT, and this takes the object off the NODE. Without it the
/// source keeps a volume record for a disk whose home has moved and goes on
/// reporting it on every heartbeat — reports the cluster then drops, one line
/// per node per report, for ever. That is migration D8, and D20 is this.
///
/// **After `move_volume_home`, never before.** The forget is answered by a
/// node that then says nothing about the volume, and silence is only the right
/// answer once the object names the destination. Between the two orders lies a
/// window in which the volume has no home and nobody speaking for it.
///
/// Best effort and never fatal, like every other tidy-up on this path: the
/// guest is at the destination and the migration has succeeded. A source that
/// could not be reached keeps a stale record, which is exactly the state this
/// removes and no worse than it was — and the next successful migration of
/// that volume sends it again.
///
/// Only `referenced` volumes, because only those are objects — the same list
/// `open_volumes_at` opened at the destination, addressed the same way, by
/// the uid the node knows the disk under. An inline disk is an instance store
/// and never travelled in the first place.
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

/// The mirror: `node` has let go of this VM's disks.
///
/// It writes nothing any more — see the body. It stays as a named step
/// because the ORDER of a migration's ending is what this file is about, and
/// a step that has become "the machine will say so" is worth reading in
/// place rather than inferring from an absence.
fn close_volumes_at(vm: &Vm, node: &str) {
    // Nothing to write since D4: the source says it itself, and it says it
    // when the `detach` has really run rather than when this tier decided the
    // migration was over. That is the difference A5 measured — a record on
    // its way out still has the disk open — and it is the whole reason this
    // tier stopped keeping its own copy of the answer.
    for name in vm.spec.referenced_volumes() {
        debug!(volume = %name, node, "the source will report the disk closed");
    }
}

/// The volume's HOME moves with the guest.
///
/// `status.node` is where the bytes were made and where every command about
/// the disk is sent — a snapshot, a resize, a deprovision — and after a
/// migration the machine it named has no record of the volume any more. The
/// ordinary lifecycle does not fix this: `hold_volumes` moves a home only
/// when a vm's volume list has DRIFTED, and a migration changes nothing about
/// the list.
///
/// Seen in the first successful live run: the guest was on `agent-2`,
/// `volume ls` said `agent-1`, and a snapshot of that disk would have been
/// sent to a node that had let it go.
///
/// Only ever from the source to the destination, and only for a volume whose
/// home really was the source: a disk that lives somewhere else entirely is
/// not this migration's to re-point.
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
            // The next pass reads it again, and the volume's own node keeps
            // reporting it either way. Not worth failing a migration that has
            // already succeeded.
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

/// The address to send to, off the migration's own status — or `None` while
/// the destination has not named one.
///
/// Pure, because it is what `send` decides on and `send` needs a store.
///
/// Two readings, and the field wins. Astra finding S05, 2026-09-23: the
/// address used to exist only inside the `Preparing` sentence, scraped back
/// out with `rsplit_once(" at ")` — so a reader depended on the wording of a
/// message written for a person, and "preparing agent-2" (the sentence
/// `prepare` writes at its CAS, before the destination has been asked
/// anything) read as an address of "agent-2" for any target whose name
/// happened to contain " at ". `status.peer` is the field; the sentence stays
/// as the fallback for records written before it existed, and for nothing
/// else.
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

    /// Astra finding S06, 2026-09-23: a second record for one guest is
    /// refused before it claims a destination.
    ///
    /// `create_vm_migration` mints a record per NAME and says nothing about
    /// how many name one vm, so two of them reach `prepare`. The second one's
    /// destination refuses the vm it already has a record of, this tier reads
    /// that as "the destination could not open the disks", and `abandon`
    /// destroys BY THE VM's UID — on the node that is holding the first
    /// migration's receiving VMM.
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

    /// A destination another replica holds the session with is reachable.
    ///
    /// D-P2 moved the SENDING of a migration's commands onto `Dispatch`,
    /// which forwards to the replica that holds the node's session — and left
    /// the CHOOSING of the node reading a `connected` that is still strictly
    /// this replica's. So the coin toss the fix removed came back one step
    /// earlier: the e2e had all three agents' sessions on 10.128.1.104, and
    /// `vm migrate fabric-probe --to agent-1b` failed with "node agent-1b
    /// cannot take this vm: it must be connected, schedulable, running a
    /// hypervisor..." every time another replica won the object.
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

    /// Astra finding S07, 2026-09-23: "checked" means the same thing for a
    /// node somebody named as for a node the scheduler would have picked.
    ///
    /// The branch above used to ask four questions where `feasible` asks ten,
    /// so `--to agent-3` sent a guest to a machine with no room for it, or
    /// one whose labels the vm does not select, or one that had said itself
    /// it was wedged. Each of those was found out on ARRIVAL — after the
    /// disks were opened at the destination and a VMM was built there — and
    /// each is now a sentence about agent-3 before anything is built.
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
    /// The source's own word about the send, and what it lets this tier do.
    ///
    /// D16's payoff. `MigrateOut` answered with the OUTCOME, so a failed
    /// transfer reached the cluster as a command that never came back, and the
    /// pass then waited out its whole transfer timeout — 120 s by default — to
    /// work out which machine held the guest. v53 resumes a guest whose send
    /// failed and goes on serving it, so the source knew within milliseconds;
    /// now it says so on the next heartbeat.
    ///
    /// The line between the two verdicts is the one `abandon` draws, and it is
    /// the only line here worth arguing about: a destination that holds no
    /// guest may be torn down, and one that might hold the only copy may not.
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

        // Nothing said, and the two words that are not a failure: this
        // function has no opinion and the timeout below it is still the rule.
        //
        // `Gone` stays in this list after Astra finding S04, 2026-09-23, and
        // for the reason it was always here: `still_here` answers ONE
        // question — did the source keep the guest — and a source that let it
        // go did not. What changed is that "the timeout below it" no longer
        // ignores the word: `verdict_on_timeout` reads it, and the test below
        // is where `Gone` is now argued.
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

    /// Astra finding S04, 2026-09-23: a source that said `Gone` has let the
    /// guest go, so the destination is the only machine that can still hold
    /// it — whatever it has managed to report by the time the budget runs
    /// out.
    ///
    /// The word travelled this far already: the agent writes it after
    /// `finish_migrate_out` has dropped the vmm pid and detached the volumes,
    /// and `ingest_departures` puts it on `status.sourceReported`. Nothing
    /// read it. So a send that completed while the destination's first report
    /// was still in flight was tidied up by uid — and the record said
    /// "agent-1 is running the vm as before" about a machine that was not
    /// running it.
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

        // The source never said it was gone: silence, or a send still under
        // way. Then the destination holding no guest is the old reading and
        // the old tidy-up.
        for source_said in [None, Some("Sending")] {
            let Verdict::TearDownTheDestination(why) = verdict(source_said, None) else {
                panic!("a destination with no guest is tidied up");
            };
            assert!(why.contains("nothing at all"), "{why}");
            assert!(why.contains("agent-1 is running the vm as before"), "{why}");
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

    /// Astra finding S05, 2026-09-23: a prepare that is still inside its
    /// budget is left alone, whatever it has managed to write down.
    ///
    /// There is no leader in this tier (`dispatch.rs`) and TICK is 5 s, so
    /// every replica reaches `send` for this migration while the prepare it
    /// did not start is still opening disks at the destination and blocking
    /// on `PrepareMigration`. Reading "no address" as "the address was lost"
    /// made each of those passes tear down a destination that was being
    /// built correctly — and the vm here is two seconds old against a thirty
    /// second budget.
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

    /// Astra finding S07, second half, 2026-09-23: two migrations aimed at
    /// one node with room for one used to BOTH pass.
    ///
    /// Nothing held the room between `prepare` and the guest's arrival:
    /// `Candidate::free` is a sum over the VMs BOUND to a node, and a guest
    /// in flight stays bound to the machine it is leaving until `settle`
    /// moves it. So the second migration of a pass measured itself against a
    /// node the first had already filled, found it empty, opened the disks
    /// there and built a second VMM — and what the guest met on arrival was
    /// the machine carrying twice its memory.
    ///
    /// Both roads, because both go through the same promise: the node the
    /// scheduler picks and the node somebody NAMED with `--to`.
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

    // Astra finding R3-F04 — a reading that fails is not a passed check — is
    // tested where the confirmation lives now: `controller_api::capacity`.

    /// A record's own promise is not a reason to refuse that record's own
    /// move — and it would be, without `give_back`.
    ///
    /// The case is a real one: `prepare` writes the promise BEFORE the claim
    /// that says this replica is carrying the move, so a process killed
    /// between the two leaves a promise for a migration that is still
    /// Pending. The next pass builds its candidate list with that promise
    /// taken off, finds the destination exactly this guest too full, and
    /// would fail the move by its own bookkeeping — every pass, for ever,
    /// since every pass writes the same promise down again.
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
