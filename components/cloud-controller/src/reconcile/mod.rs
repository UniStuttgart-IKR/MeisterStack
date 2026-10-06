// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Level-triggered VM reconciliation from stored intent and cluster reports.
//! Periodic passes and store watches drive dispatch, teardown and heartbeat expiry.
//! Absence is usable evidence only from a complete, sufficiently recent report.
//!
//! Replicas share etcd without a leader. Local cluster sessions select who acts;
//! compare-and-swap arbitrates bindings and shared status changes.

use std::collections::{BTreeMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use anyhow::bail;
use chrono::{DateTime, Utc};
use controller_api::{
    Ack, Candidate, CandidateKind, Capacity, Cluster, EtcdStore, NodeRoom, Overcommit, PassTrigger,
    PendingTally, Resource, RunStrategy, Scheduler, StoreError, Vm, VmPhaseKind, heartbeat_expired,
    lifecycle_command,
};
use proto::cloud_command;
use tokio::sync::OnceCell;
use tracing::{debug, info, warn};

use controller_api::EventType;
use controller_api::events::{self, Happening};

use crate::session::SessionRegistry;

const TICK: Duration = Duration::from_secs(5);

mod floating;
mod placement;
mod routers;
mod vms;
mod volumes;

use floating::*;
pub(crate) use placement::*;
use routers::*;
pub(crate) use vms::*;
use volumes::*;

/// Reconcile a bound VM only where its cluster session is held locally.
/// Unbound VMs are eligible everywhere, but placement considers locally connected
/// clusters and the binding CAS selects the winner. A disconnected holder leaves
/// its VMs waiting, including deletions.
///
/// Cluster replicas converge on the same cloud endpoint through HRW and periodic
/// re-homing. During convergence, two cloud replicas can hold sessions and act on
/// the same objects; separate streams do not provide a common teardown ordering.
pub fn may_reconcile(vm: &Vm, sessions: &HashSet<String>) -> bool {
    match vm.spec.cluster_name.as_deref() {
        Some(cluster) => sessions.contains(cluster),
        // Unbound, and the second arm is the cross-cluster reschedule: a VM
        // whose binding fell is the business of the replica that can still
        // reach the cluster it is LEAVING, until that cluster has let go.
        // Only one replica can tell a cluster anything, and telling the old
        // one is the whole of what this state is for. The same second arm the
        // tier below grew for the same move one scope down.
        None => match vm.status.cluster_name.as_deref() {
            Some(old) => sessions.contains(old),
            None => true,
        },
    }
}

pub async fn run(
    store: Arc<EtcdStore>,
    registry: Arc<SessionRegistry>,
    scheduler: Arc<dyn Scheduler>,
    overcommit: Overcommit,
) {
    let mut trigger = PassTrigger::<Vm>::new(&store, TICK).await;
    // The same cadence as one tier down and for the same reason: a
    // five-minute budget does not need a five-second resolution, and six
    // listings per tick would be a monitoring feature that changes the thing
    // it monitors.
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
        let outcome = pass(&store, &registry, scheduler.as_ref(), overcommit).await;
        // Around the whole pass, and a failed pass still took the time it
        // took — the same measurement as one tier down, so a slow lap can be
        // compared between the two.
        telemetry::metrics::reconcile().pass(
            telemetry::metrics::TIER_CLOUD,
            Vm::KIND,
            clock.seconds(),
            outcome.is_ok(),
        );
        if let Err(e) = outcome {
            warn!(error = format!("{e:#}"), "reconcile pass failed");
        }
    }
}

/// No non-terminal state without a deadline — the cloud's half of D7.
///
/// The same pass one tier down runs, over the kinds this tier holds: an
/// `Image` instead of a `VmMigration`, because a migration is a cluster's
/// operation and a catalogue is only ever the cloud's. It writes nothing onto
/// the objects; see the cluster's own `deadlines` for why that is the whole
/// design.
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
    for volume in store.list::<controller_api::Volume>().await? {
        late.look(
            About::of::<controller_api::Volume>(
                &volume.metadata,
                Some(volume.spec.tenant.as_str()),
            ),
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
    for pool in store.list::<controller_api::StoragePool>().await? {
        late.look(
            About::of::<controller_api::StoragePool>(&pool.metadata, None),
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
    // The catalogue, which is F16's other end: a path image that no node can
    // see now says `Failed { NotFound }` at once, and one that nobody has
    // looked at yet sits at `Pending { AwaitingNode }` — and if it sits there
    // for five minutes, something is not fetching it.
    for image in store.list::<controller_api::Image>().await? {
        late.look(
            About::of::<controller_api::Image>(&image.metadata, image.spec.tenant.as_deref()),
            image.status.standing(),
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

async fn pass(
    store: &EtcdStore,
    registry: &SessionRegistry,
    scheduler: &dyn Scheduler,
    overcommit: Overcommit,
) -> anyhow::Result<()> {
    // One reading of the session map for the whole pass: what this replica
    // owns must not change halfway through the list it is deciding about.
    let sessions = registry.connected();
    telemetry::metrics::sessions()
        .set_connected(telemetry::metrics::PEER_CLUSTER, sessions.len() as i64);
    // The VMs first: what is already bound to a cluster is half of what
    // "free" means, and the candidates cannot be built without it.
    let vms = store.list::<Vm>().await?;
    publish_vm_gauges(&vms);
    // The drain reads the same listing the VM loop consumes; one picture of
    // the estate per pass, because two readings could disagree about which
    // cluster a VM is on.
    let vms_for_drain = vms.clone();
    let ledger = expire_and_collect_clusters(store, &sessions, &vms, overcommit).await?;
    telemetry::metrics::objects().set_count(Cluster::KIND, ledger.clusters.len() as i64);
    // Behind a mutex because a pass SPENDS it — see the cluster tier's twin.
    let ledger = std::sync::Mutex::new(ledger);
    // And one reading of the address book, but only if somebody asks for it:
    // most passes dispatch nothing, and those must go on costing nothing.
    let book = OnceCell::new();
    let pending = PendingTally::new();
    for vm in vms {
        let name = vm.metadata.name.clone();
        if let Err(e) = reconcile_vm(
            store, registry, scheduler, &sessions, &ledger, &book, &pending, vm,
        )
        .await
        {
            warn!(vm = %name, error = format!("{e:#}"), "vm reconcile failed");
        }
    }
    // After the VMs, out of the same session map. A volume needs no candidate
    // list — its pool names the cluster — so the order between the two loops
    // decides nothing, and it is this way round because a VM waiting for a
    // placement is the more urgent of the two.
    if let Err(e) = dispatch_volumes(store, registry, &sessions).await {
        warn!(error = format!("{e:#}"), "volume dispatch pass failed");
    }
    // After the volumes, because a snapshot's road runs through one.
    if let Err(e) = dispatch_snapshots(store, registry, &sessions).await {
        warn!(error = format!("{e:#}"), "snapshot dispatch pass failed");
    }
    if let Err(e) = mirror_secrets(store, registry, &sessions).await {
        warn!(error = format!("{e:#}"), "secret mirror pass failed");
    }
    // After the VM loop, because it writes marks the NEXT pass acts on. One
    // tick of latency, which is what level-triggered means.
    if let Err(e) = drain_clusters(store, &sessions, &vms_for_drain).await {
        warn!(error = format!("{e:#}"), "cluster drain pass failed");
    }
    // What the control plane knows about reaching each VM. After the loop and
    // out of the same listing, because it is bookkeeping and not a decision:
    // nothing in this pass reads it.
    if let Err(e) = stamp_vm_addresses(store, &vms_for_drain).await {
        warn!(error = format!("{e:#}"), "vm address pass failed");
    }
    // The routers, last and out of their own listings. Last because nothing
    // above them reads what they decide — a router takes no room off a
    // cluster — and their own listings because a router is about the
    // tenant's address objects rather than about the VMs this pass has been
    // walking.
    if let Err(e) = reconcile_routers(store, registry, &sessions).await {
        warn!(error = format!("{e:#}"), "router reconcile pass failed");
    }
    // After the loop: until it has run nobody knows how many VMs are pending
    // for which reason. See `PendingTally`.
    pending.publish(telemetry::metrics::TIER_CLOUD);
    Ok(())
}

/// Mirror sealed secrets to every locally connected cluster before placement.
/// Both tiers share the sealing key; this pass forwards ciphertext without using it.
/// Reports acknowledge cloud generations, suppressing unchanged retransmissions.
///
/// Reported cloud-managed secrets absent from the cloud are deleted, including
/// copies whose cluster missed the original deletion command. Cluster-local
/// secrets are excluded from this cleanup.
async fn mirror_secrets(
    store: &EtcdStore,
    registry: &SessionRegistry,
    sessions: &HashSet<String>,
) -> anyhow::Result<()> {
    if sessions.is_empty() {
        return Ok(());
    }
    let secrets = store.list::<controller_api::Secret>().await?;
    for cluster in sessions {
        let held = registry.secrets.of(cluster);
        for secret in &secrets {
            // Dedup by evidence, exactly as the volume half does. The uid
            // as well as the name, because a name is a label people reuse and
            // a copy of the OLD secret of that name is not this one.
            if already_there(&held, secret) {
                continue;
            }
            seal_to(registry, cluster, secret).await?;
        }
        collect_leftovers(registry, cluster, &held, &secrets).await;
    }
    Ok(())
}

/// One sealed secret, on its way to one cluster.
async fn seal_to(
    registry: &SessionRegistry,
    cluster: &str,
    secret: &controller_api::Secret,
) -> anyhow::Result<()> {
    let name = secret.metadata.name.clone();
    let op = cloud_command::Op::CreateSecret(proto::CreateSecret {
        name: name.clone(),
        spec_json: serde_json::to_string(&secret.spec)?,
        uid: secret.metadata.uid.clone(),
        tenant: secret.spec.tenant.clone(),
        generation: secret.metadata.generation,
    });
    if let Err(e) = registry.send_command(cluster, "", op).await {
        // Debug and not warn: a cluster that is not answering right now is
        // the ordinary state of a fleet, the next pass sends the same thing
        // again, and one line per secret per cluster per pass would be the
        // log.
        debug!(secret = %name, cluster = %cluster,
               error = format!("{e:#}"), "secret mirror could not be delivered");
    }
    Ok(())
}

/// What the cluster says it holds for this cloud that this cloud has no
/// object for. A `secret rm` while the cluster was offline is exactly this,
/// and until the report existed there was no way to notice it at all.
async fn collect_leftovers(
    registry: &SessionRegistry,
    cluster: &str,
    held: &[proto::SecretStateReport],
    secrets: &[controller_api::Secret],
) {
    for stale in leftovers(held, secrets) {
        let op = cloud_command::Op::DeleteSecret(proto::DeleteSecret {
            name: stale.name.clone(),
            uid: stale.uid.clone(),
        });
        match registry.send_command(cluster, "", op).await {
            Ok(_) => info!(secret = %stale.name, cluster = %cluster,
                           "a sealed copy of a deleted secret was collected"),
            Err(e) => debug!(secret = %stale.name, cluster = %cluster,
                             error = format!("{e:#}"), "collecting the copy failed"),
        }
    }
}

/// Does that cluster already hold this exact secret?
///
/// The uid as well as the name, because a name is a label people reuse and a
/// copy of the OLD secret of that name is not this one — and the generation,
/// because a rotation is a new version of the same secret and has to travel.
fn already_there(held: &[proto::SecretStateReport], secret: &controller_api::Secret) -> bool {
    held.iter().any(|s| {
        s.name == secret.metadata.name
            && s.uid == secret.metadata.uid
            && s.generation == secret.metadata.generation
    })
}

/// What that cluster is holding for this cloud that this cloud has no object
/// for — a `secret rm` it was offline for, and nothing else: a secret made at
/// the cluster's own edge is never in this list, because the report only
/// carries the cloud-managed ones.
fn leftovers<'a>(
    held: &'a [proto::SecretStateReport],
    secrets: &'a [controller_api::Secret],
) -> impl Iterator<Item = &'a proto::SecretStateReport> {
    held.iter().filter(|s| {
        !secrets
            .iter()
            .any(|secret| secret.metadata.name == s.name && secret.metadata.uid == s.uid)
    })
}

/// One event about a VM. The tenant travels with it, so a member sees its
/// own VMs' history and nobody else's.
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

/// How many VMs there are, and how they are spread over the phases. Every
/// phase every time, zero included — see the cluster tier's twin: a phase
/// that stops being written looks exactly like a controller that stopped
/// reporting.
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

/// Expire stale heartbeats before constructing candidates from the same objects.
/// Any replica may perform expiry through CAS. Candidate connectivity remains
/// local: a session held by another cloud replica cannot dispatch here.
async fn expire_and_collect_clusters(
    store: &EtcdStore,
    sessions: &HashSet<String>,
    vms: &[Vm],
    overcommit: Overcommit,
) -> anyhow::Result<Ledger> {
    let now = Utc::now();
    let mut out = Ledger::default();
    // Rebuilt from this listing every pass: a cluster taken out of the
    // inventory must LOSE its age rather than keep the last one for ever.
    telemetry::metrics::sessions().reset_heartbeats();
    // One read for every cluster's liveness: the heartbeat lives in its own
    // key since D-C7.
    let beats = store.beats::<Cluster>().await?;
    for cluster in store.list::<Cluster>().await? {
        let name = cluster.metadata.name.clone();
        let rooms = rooms_of(
            &cluster,
            &unreported_on(store, &name, vms).await,
            overcommit,
        );
        let heard = beats.get(&name).copied();
        publish_heartbeat_age(&name, heard, now);
        let connected = still_connected(store, &name, &cluster.status, heard, now).await
            && sessions.contains(&name);
        out.offer(
            cluster_candidate(cluster, vms, overcommit, connected),
            rooms,
        );
    }
    Ok(out)
}

/// How old this cluster's last heartbeat is, for whoever is watching the
/// gauge. A cluster that has never spoken has no age rather than a zero.
fn publish_heartbeat_age(name: &str, last: Option<DateTime<Utc>>, now: DateTime<Utc>) {
    let Some(last) = last else { return };
    telemetry::metrics::sessions().set_heartbeat_age(
        telemetry::metrics::PEER_CLUSTER,
        name,
        (now - last).num_milliseconds() as f64 / 1000.0,
    );
}

/// Is this cluster still connected, as of now — and if its heartbeat has run
/// out, write that down. Answers with what the object says after the write,
/// so a write that failed leaves the pass believing what it believed before:
/// the next pass tries again rather than this one acting on a state nobody
/// recorded.
async fn still_connected(
    store: &EtcdStore,
    name: &str,
    status: &controller_api::ClusterStatus,
    heard: Option<DateTime<Utc>>,
    now: DateTime<Utc>,
) -> bool {
    if !status.connected || !heartbeat_expired(heard, now) {
        return status.connected;
    }
    // ISO-8601 UTC rather than the Debug of an Option: the instant is what an
    // operator lines up against everything else in the log.
    let last = heard
        .map(|t| t.to_rfc3339())
        .unwrap_or_else(|| "never".to_string());
    warn!(cluster = %name, last_heartbeat = %last,
          "heartbeat expired, cluster not connected");
    if let Err(e) = store
        .mutate::<Cluster, _>(name, |c| c.status.connected = false)
        .await
    {
        warn!(cluster = %name, error = format!("{e:#}"),
              "marking the cluster down failed");
        return true;
    }
    // The transition, not the state: getting here has already established
    // that the cluster WAS connected and is not any more.
    events::record(
        store,
        Happening {
            kind: Cluster::KIND,
            name,
            uid: "",
            reason: events::reason::PEER_LOST,
            message: format!("heartbeat expired, last seen {last}"),
            event_type: EventType::Warning,
            tenant: None,
        },
    )
    .await;
    false
}

/// Require status to postdate both deletion intent and the latest command ACK.
/// An older absence could otherwise repeat a completed create or erase a VM whose
/// teardown has not completed.
pub fn status_is_current(vm: &Vm, reported_at: DateTime<Utc>) -> bool {
    controller_api::mirror::is_current(
        vm.metadata.deletion_timestamp,
        vm.status.observed_at,
        reported_at,
    )
}

#[cfg(test)]
mod tests;
