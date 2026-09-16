// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! The cloud's Vm reconciler: level-triggered like the cluster's — a periodic
//! pass plus etcd-watch wakeups, every decision derived from the stored object
//! and from what the bound cluster last said about it.
//!
//! What is dedup one tier down (the phase) is dedup plus evidence here: a VM
//! is handed to its cluster when that cluster's own status does not name it,
//! and the cloud object goes away when the status stops naming it. The cluster
//! tier can ask an agent about one VM; the cloud only ever hears the whole
//! list, so the list is what it reasons with.
//!
//! The same pass expires cluster heartbeats: a session that tears down reports
//! its cluster down immediately, but one that is killed outright — or one that
//! died while this controller was restarting — leaves nothing behind except a
//! heartbeat that stops moving.
//!
//! Several cloud replicas run this same pass against one cloud etcd with no
//! leader between them, exactly as the cluster tier does one floor down: the
//! session map divides the work (see `may_reconcile`) and everything they
//! still share — binding an unbound VM, expiring a heartbeat — goes through a
//! compare-and-swap with the store as the arbiter.

use std::collections::{BTreeMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use anyhow::bail;
use chrono::{DateTime, Utc};
use controller_api::{
    Ack, Candidate, CandidateKind, Capacity, Cluster, EtcdStore, Overcommit, PassTrigger,
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

/// Who, of several leaderless cloud replicas, may act on this VM: the one its
/// cluster is dialled into. The same token as one tier down, one tier up — a
/// fact the replica observes by itself, and the only replica that could reach
/// the cluster anyway.
///
/// Exclusive because a cluster's replicas all hash the same `cluster_name` and
/// so share one preference order, and because each of them keeps re-homing to
/// the best endpoint that answers (cluster-controller's `REHOME_INTERVAL`) —
/// order alone would only make them agree on the ranking, not on the entry.
/// While one of them is still on its way back the cluster has two owners for
/// up to that interval; both dispatch, which the cluster tier deduplicates by
/// cloud uid, and both mirror, which is CAS-idempotent. What that window does
/// cost is the ordering the teardown proof leans on, because the two accounts
/// arrive on two unrelated streams — so the hard delete may then race rather
/// than being decided. It is bounded, not absent, and that is the honest
/// statement of it.
///
/// An unbound VM belongs to everybody: any replica may schedule it, but only
/// onto clusters of its own session map (`Candidate::connected`), so whoever
/// wins the binding CAS binds the VM to a cluster it already owns and
/// ownership follows the binding for free.
///
/// The edge this leaves open, deliberately and as one floor down: a VM whose
/// cluster is dialled into no replica at all is reconciled by nobody, a
/// deleting one included, which waits until the cluster comes back — tearing a
/// VM down is something only its cluster can do.
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
    let clusters = expire_and_collect_clusters(store, &sessions, &vms, overcommit).await?;
    telemetry::metrics::objects().set_count(Cluster::KIND, clusters.len() as i64);
    // Behind a mutex because a pass SPENDS it — see the cluster tier's twin.
    let clusters = std::sync::Mutex::new(clusters);
    // And one reading of the address book, but only if somebody asks for it:
    // most passes dispatch nothing, and those must go on costing nothing.
    let book = OnceCell::new();
    let pending = PendingTally::new();
    for vm in vms {
        let name = vm.metadata.name.clone();
        if let Err(e) = reconcile_vm(
            store, registry, scheduler, &sessions, &clusters, &book, &pending, vm,
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

/// Every secret this cloud holds, mirrored to every cluster this replica is
/// talking to.
///
/// EVERY cluster, and that is the difference from a volume. A volume's pool
/// names one cluster, so a volume has a home; a secret has none — a VM
/// referring to it can be placed anywhere, and the cluster has to hold it
/// BEFORE the placement, not after. So the set of clusters is the answer, and
/// the cost of that is the honest one: a tenant's secret exists on every
/// cluster of this cloud, sealed, whether a VM there uses it or not.
///
/// The values travel as they are stored — sealed — because both tiers hold
/// the same KEK. No plaintext crosses this session and this pass needs no key
/// at all.
///
/// Level-triggered like everything else here: the pass re-sends what it
/// cannot confirm, and `handle_create_secret` down there is idempotent for an
/// unchanged spec. Since `ClusterStatus.secrets` there IS something to
/// confirm against: a cluster says what it is holding and at which of the
/// cloud's generations, so a secret it already has at the current one is not
/// sent again. A cluster that has not spoken to THIS replica yet is remembered
/// as nothing, and nothing means "send" — which is what every replica did on
/// every pass before this existed.
///
/// The same evidence closes the other half. A deletion cannot be
/// level-triggered off a list the object has already left, so `delete_secret`
/// at the edge tells the clusters this replica is talking to and then removes
/// the object — and a cluster that was OFFLINE for that used to keep its
/// sealed copy for ever, because nothing afterwards ever mentioned it again.
/// Now it mentions it itself, every ten seconds: a cloud-managed secret in a
/// cluster's report that this cloud does not have is a leftover, and it is
/// told to go. `managed_by_cloud` is what makes that safe — a secret somebody
/// made at the cluster edge is nobody's business here and is never in the
/// list.
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

/// Expire stale heartbeats and hand the scheduler what is left. Both halves
/// read the same Cluster objects, so a cluster that just expired cannot still
/// be placed onto in the same pass.
///
/// Expiry is every replica's business, not just the owner's: the heartbeat it
/// judges was written to the shared store by whichever replica holds the
/// session, and `connected = false` is idempotent under CAS, so two replicas
/// reaching it at once cost one redundant write. `connected` in the candidate
/// stays strictly local, though: a cluster dialled in *somewhere* is still not
/// one this replica can send anything to.
async fn expire_and_collect_clusters(
    store: &EtcdStore,
    sessions: &HashSet<String>,
    vms: &[Vm],
    overcommit: Overcommit,
) -> anyhow::Result<Vec<Candidate>> {
    let now = Utc::now();
    let mut out = Vec::new();
    // Rebuilt from this listing every pass: a cluster taken out of the
    // inventory must LOSE its age rather than keep the last one for ever.
    telemetry::metrics::sessions().reset_heartbeats();
    // One read for every cluster's liveness: the heartbeat lives in its own
    // key since D-C7.
    let beats = store.beats::<Cluster>().await?;
    for cluster in store.list::<Cluster>().await? {
        let name = cluster.metadata.name;
        let heard = beats.get(&name).copied();
        publish_heartbeat_age(&name, heard, now);
        let connected = still_connected(store, &name, &cluster.status, heard, now).await;
        out.push(Candidate {
            connected: connected && sessions.contains(&name),
            // One view at this tier: a cloud has one session per cluster
            // group and no second opinion to reconcile against.
            alive: connected && sessions.contains(&name),
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
            free: free_on(&name, &cluster.status.capacity, vms, overcommit),
            catalogue: cluster.status.capacity.capabilities,
            kind: CandidateKind::Cluster,
            hosted: hosted_on(&name, vms, |v| v.spec.cluster_name.as_deref()),
            labels: cluster.spec.labels,
            name,
            // A candidate here is a CLUSTER and not a machine, so there is no
            // machine state to compare and never will be: there is no live
            // migration across clusters.
            machine: None,
        });
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

/// Is this status younger than everything we have already done to this VM?
/// Only then does it describe the VM as it is now.
///
/// Both of the decisions below turn on a name being absent from the list, and
/// a status built before our last command landed is absent of it too — it
/// describes the VM from before. Read as current, it would have us repeat a
/// create that already took (and each repeat writes, and each write wakes the
/// watch, and the pass comes round again) or delete the record of a machine
/// that is very much alive. The floor is the delete request and the last ack,
/// whichever is later, because those are the two things we did.
pub fn status_is_current(vm: &Vm, reported_at: DateTime<Utc>) -> bool {
    controller_api::mirror::is_current(
        vm.metadata.deletion_timestamp,
        vm.status.observed_at,
        reported_at,
    )
}

#[cfg(test)]
mod tests;
