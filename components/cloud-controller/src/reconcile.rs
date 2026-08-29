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
    PendingTally, Resource, RunStrategy, Scheduler, StoreError, Vm, VmPhase, heartbeat_expired,
    lifecycle_command,
};
use proto::cloud_command;
use tokio::sync::OnceCell;
use tracing::{debug, info, warn};

use controller_api::EventType;
use controller_api::events::{self, Happening};

use crate::session::SessionRegistry;

const TICK: Duration = Duration::from_secs(5);

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
        None => true,
    }
}

pub async fn run(
    store: Arc<EtcdStore>,
    registry: Arc<SessionRegistry>,
    scheduler: Arc<dyn Scheduler>,
    overcommit: Overcommit,
) {
    let mut trigger = PassTrigger::<Vm>::new(&store, TICK).await;
    loop {
        trigger.wait(&store).await;
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
    // After the loop: until it has run nobody knows how many VMs are pending
    // for which reason. See `PendingTally`.
    pending.publish(telemetry::metrics::TIER_CLOUD);
    Ok(())
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
fn free_on(
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
fn hosted_on(
    on: &str,
    vms: &[Vm],
    bound: fn(&Vm) -> Option<&str>,
) -> Vec<BTreeMap<String, String>> {
    vms.iter()
        .filter(|v| bound(v) == Some(on))
        .map(|v| v.metadata.labels.clone())
        .collect()
}

/// How many VMs there are, and how they are spread over the phases. Every
/// phase every time, zero included — see the cluster tier's twin: a phase
/// that stops being written looks exactly like a controller that stopped
/// reporting.
fn publish_vm_gauges(vms: &[Vm]) {
    telemetry::metrics::objects().set_count(Vm::KIND, vms.len() as i64);
    for phase in VmPhase::ALL {
        let n = vms.iter().filter(|v| v.status.phase == phase).count();
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
    for cluster in store.list::<Cluster>().await? {
        let name = cluster.metadata.name;
        if let Some(last) = cluster.status.last_heartbeat {
            telemetry::metrics::sessions().set_heartbeat_age(
                telemetry::metrics::PEER_CLUSTER,
                &name,
                (now - last).num_milliseconds() as f64 / 1000.0,
            );
        }
        let mut connected = cluster.status.connected;
        if connected && heartbeat_expired(cluster.status.last_heartbeat, now) {
            // ISO-8601 UTC rather than the Debug of an Option: the instant
            // is what an operator lines up against everything else in the log.
            let last = cluster
                .status
                .last_heartbeat
                .map(|t| t.to_rfc3339())
                .unwrap_or_else(|| "never".to_string());
            warn!(cluster = %name, last_heartbeat = %last,
                  "heartbeat expired, cluster not connected");
            match store
                .mutate::<Cluster, _>(&name, |c| c.status.connected = false)
                .await
            {
                Ok(_) => {
                    // The transition, not the state: this branch has already
                    // established that the cluster WAS connected and is not
                    // any more.
                    events::record(
                        store,
                        Happening {
                            kind: Cluster::KIND,
                            name: &name,
                            uid: "",
                            reason: events::reason::PEER_LOST,
                            message: format!("heartbeat expired, last seen {last}"),
                            event_type: EventType::Warning,
                            tenant: None,
                        },
                    )
                    .await;
                    connected = false
                }
                Err(e) => warn!(cluster = %name, error = format!("{e:#}"),
                                "marking the cluster down failed"),
            }
        }
        out.push(Candidate {
            connected: connected && sessions.contains(&name),
            schedulable: cluster.spec.schedulable,
            free: free_on(&name, &cluster.status.capacity, vms, overcommit),
            catalogue: cluster.status.capacity.capabilities,
            kind: CandidateKind::Cluster,
            hosted: hosted_on(&name, vms, |v| v.spec.cluster_name.as_deref()),
            labels: cluster.spec.labels,
            name,
        });
    }
    Ok(out)
}

/// Same shape as one tier down: the trace is on the object, and the span gets
/// its parent before it starts (`telemetry::in_trace`).
///
/// `vm` is what a person calls it, `vm_id` is the uid that travels down — the
/// cluster keeps it as the cloud-uid and reports phases under it.
#[allow(clippy::too_many_arguments)]
async fn reconcile_vm(
    store: &EtcdStore,
    registry: &SessionRegistry,
    scheduler: &dyn Scheduler,
    sessions: &HashSet<String>,
    clusters: &std::sync::Mutex<Vec<Candidate>>,
    book: &OnceCell<AddressBook>,
    pending: &PendingTally,
    vm: Vm,
) -> anyhow::Result<()> {
    let context = birth_trace(&vm).unwrap_or_else(telemetry::TraceParent::root);
    let span = tracing::info_span!(
        "reconcile_vm",
        vm = %vm.metadata.name,
        vm_id = %vm.metadata.uid,
        trace_id = %context.trace_id_hex()
    );
    telemetry::in_trace(
        span,
        &context,
        reconcile_vm_traced(
            store, registry, scheduler, sessions, clusters, book, pending, vm, context,
        ),
    )
    .await
}

/// The trace a pass belongs to.
///
/// The object's context covers the VM's BIRTH and stops there: while it is
/// still Pending or Provisioning, this pass is part of the request that asked
/// for it. Once the phase is stable — or Failed, or Quarantined — the pass
/// gets a root of its own.
///
/// Without that cut the trace never ends. Level-triggered means a pass runs
/// every tick forever, and a first version of this attached all of them: one
/// VM, thirty seconds, twelve spans hanging off a `POST /vms` that had long
/// since returned. The annotation stays on the object either way — it is the
/// record of where the VM came from, which is worth keeping whether or not
/// anything is still tracing against it.
fn birth_trace(vm: &Vm) -> Option<telemetry::TraceParent> {
    if !matches!(vm.status.phase, VmPhase::Pending | VmPhase::Provisioning) {
        return None;
    }
    telemetry::TraceParent::parse(vm.metadata.traceparent().unwrap_or_default())
}

#[allow(clippy::too_many_arguments)]
async fn reconcile_vm_traced(
    store: &EtcdStore,
    registry: &SessionRegistry,
    scheduler: &dyn Scheduler,
    sessions: &HashSet<String>,
    clusters: &std::sync::Mutex<Vec<Candidate>>,
    book: &OnceCell<AddressBook>,
    pending: &PendingTally,
    vm: Vm,
    context: telemetry::TraceParent,
) -> anyhow::Result<()> {
    // Everything this pass hands to the cluster rides on it, and the cluster
    // hands it to the agent, so `POST /vms` and the backend spawn are one
    // trace.
    let outgoing = telemetry::outgoing(&context).to_string();

    // Ownership before anything else, teardown included: a bound VM is the
    // business of the replica its cluster talks to, and of no other. Not an
    // error and not a warning — the right replica is doing this right now.
    if !may_reconcile(&vm, sessions) {
        debug!(cluster = ?vm.spec.cluster_name, "vm belongs to another replica's session, skipping");
        return Ok(());
    }

    if vm.is_deleting() {
        return teardown(store, registry, &vm, &outgoing).await;
    }

    let Some(cluster) = vm.spec.cluster_name.clone() else {
        // Decide and SPEND under one lock, and let go before anything awaits
        // — see the cluster tier's `place` for why the binding and not the
        // API edge is the authority.
        let decision = {
            let mut clusters = clusters.lock().unwrap();
            match scheduler.assign(&vm, &clusters) {
                Some(pick) => {
                    controller_api::deduct(&mut clusters, &pick, Capacity::wanted_by(&vm));
                    Ok(pick)
                }
                None => Err((
                    clusters.len(),
                    controller_api::pending_reason_of(&vm, &clusters),
                )),
            }
        };
        match decision {
            Ok(pick) => {
                // A plain CAS on the object this pass read, not a
                // read-modify-write: with several replicas scheduling at once
                // the binding is exactly what must NOT be retried onto a newer
                // object — a retry would re-apply this replica's choice over
                // the winner's and move a VM that is already placed. One
                // write, one winner, and the loser is told.
                let mut bound = vm;
                bound.spec.cluster_name = Some(pick.clone());
                // The binding answers whatever a previous pass wrote about
                // why there was none.
                bound.status.message = None;
                match store.update(&bound).await {
                    Ok(_) => {
                        telemetry::metrics::scheduling().placed(telemetry::metrics::TIER_CLOUD);
                        // In the arm where the compare-and-swap SUCCEEDED —
                        // the replica that lost the race records nothing.
                        events::record(
                            store,
                            about(
                                &bound,
                                events::reason::SCHEDULED,
                                format!("bound to cluster {pick}"),
                                EventType::Normal,
                            ),
                        )
                        .await;
                        info!(cluster = %pick, "scheduled")
                    }
                    Err(StoreError::Conflict(_)) => {
                        telemetry::metrics::scheduling().conflict(telemetry::metrics::TIER_CLOUD);
                        debug!(cluster = %pick, "lost the scheduling race, another writer bound it")
                    }
                    Err(e) => return Err(e.into()),
                }
            }
            Err((known, (category, reason))) => {
                // Say WHY on the object and not only in this replica's debug
                // log — see the cluster tier's `place`. One floor up the
                // sentence is worth even more: a cluster catalogue is the
                // UNION of its nodes', so "each part is served somewhere" is
                // a real and otherwise invisible outcome here.
                // The sentence goes on the object, the CATEGORY into the
                // tally: the sentence names capabilities and counts
                // candidates, and is the string that must never be a label.
                pending.note(category);
                debug!(
                    known,
                    reason = %reason,
                    "no schedulable cluster, staying pending"
                );
                // Only when the answer CHANGED, and the event with it: a
                // level-triggered pass reaches this conclusion every five
                // seconds for as long as the VM is unplaceable, and an event
                // per pass would be a store filling at one write per VM per
                // tick.
                if vm.status.message.as_deref() != Some(reason.as_str()) {
                    store
                        .mutate::<Vm, _>(&vm.metadata.name, |v| {
                            v.status.message = Some(reason.clone());
                        })
                        .await?;
                    events::record(
                        store,
                        about(
                            &vm,
                            events::reason::FAILED_SCHEDULING,
                            reason,
                            EventType::Warning,
                        ),
                    )
                    .await;
                }
            }
        }
        return Ok(());
    };

    // Everything below is decided against what the cluster last told us, and
    // silence is not an answer: a cluster that has reported nothing, or
    // nothing newer than our own last command, gets nothing decided about its
    // VMs.
    let Some(report) = registry.report(&cluster) else {
        debug!(cluster = %cluster, "no current status from the bound cluster, waiting");
        return Ok(());
    };
    if !status_is_current(&vm, report.at) {
        debug!(cluster = %cluster, "the last status predates our last command, waiting");
        return Ok(());
    }

    if vm.status.phase == VmPhase::Failed {
        // A cluster that answered "no" answered about this VM. Asking again
        // every five seconds would not change the answer, and renaming the VM
        // to dodge it is the kind of cleverness that loses somebody's disk.
        return Ok(());
    }

    // Two reasons to hand the spec down, and both are level conditions rather
    // than events: the cluster does not have this VM, or it has it under an
    // intent that no longer matches. Neither needs a memory of what was sent —
    // when the condition is gone, so is the command.
    let missing = !report.uids.contains(&vm.metadata.uid);
    let drifted = lifecycle_command(vm.spec.run_strategy, vm.status.phase).is_some();
    if missing || drifted {
        dispatch_create(store, registry, &cluster, &vm, missing, book, &outgoing).await?;
    }
    Ok(())
}

/// Hand the VM to its cluster. Create is idempotent by uid down there, so this
/// is equally the first handover, the repair after a cluster lost the object,
/// and the way a changed runStrategy reaches the tier that can act on it.
#[allow(clippy::too_many_arguments)]
async fn dispatch_create(
    store: &EtcdStore,
    registry: &SessionRegistry,
    cluster: &str,
    vm: &Vm,
    missing: bool,
    book: &OnceCell<AddressBook>,
    traceparent: &str,
) -> anyhow::Result<()> {
    let name = vm.metadata.name.clone();
    // The first dispatch of the pass pays for the two listings; every other
    // one reads the same book. See `AddressBook`.
    let addresses = book
        .get_or_try_init(|| AddressBook::read(store))
        .await?
        .for_vm(vm);
    let op = cloud_command::Op::Create(proto::CreateVm {
        name: name.clone(),
        uid: vm.metadata.uid.clone(),
        spec_json: build_spec_json(vm)?,
        vni: tenant_vni(store, vm.spec.tenant.as_deref()).await?,
        floating_ips: addresses.floating_ips,
        routed_subnets: addresses.routed_subnets,
    });

    match registry.send_command(cluster, traceparent, op).await {
        Ok(Ack::Acked(_)) => {
            store
                .mutate::<Vm, _>(&name, |v| {
                    // Stamped whatever the phase does: this is the last moment
                    // we know something happened to this VM downstairs, and
                    // the teardown gate below uses it as its floor. Without
                    // it, a status built before the create landed could pass
                    // for proof that the VM was never there.
                    v.status.observed_at = Some(Utc::now());
                    v.status.cluster_name = v.spec.cluster_name.clone();
                    // Anticipation never overwrites observation. Dispatching
                    // is a guess about the future; only a VM nobody has
                    // reported on yet may be moved by one.
                    if v.status.phase == VmPhase::Pending {
                        v.status.phase = VmPhase::Provisioning;
                        v.status.message = None;
                    }
                })
                .await?;
            info!(cluster, missing, "create dispatched");
        }
        Ok(Ack::Rejected(msg)) => {
            warn!(cluster, error = %msg, "cluster refused the create");
            store
                .mutate::<Vm, _>(&name, |v| {
                    v.status.phase = VmPhase::Failed;
                    v.status.message = Some(msg.clone());
                    v.status.cluster_name = v.spec.cluster_name.clone();
                    v.status.observed_at = Some(Utc::now());
                })
                .await?;
        }
        // A broken session is a fact about the session. Nothing is written,
        // and the next pass derives the same decision from the same state.
        Err(e) => warn!(
            cluster,
            error = format!("{e:#}"),
            "create could not be delivered"
        ),
    }
    Ok(())
}

/// Finalizer flow, one tier up. The cluster is told to tear the VM down and
/// acks that it recorded the order — which is not the same as having carried
/// it out. The proof is the VM leaving the cluster's status, and only then may
/// the cloud object go: an object deleted early is a VM nobody is left to
/// delete.
async fn teardown(
    store: &EtcdStore,
    registry: &SessionRegistry,
    vm: &Vm,
    traceparent: &str,
) -> anyhow::Result<()> {
    let name = vm.metadata.name.clone();
    let uid = vm.metadata.uid.clone();

    let Some(cluster) = vm.spec.cluster_name.clone() else {
        // Never placed anywhere: there is nothing to tear down.
        store.delete::<Vm>(&name).await?;
        info!("vm deleted (never placed)");
        return Ok(());
    };

    let report = registry.report(&cluster);
    // While the cluster still names the VM — and while it has told us nothing
    // current, which for this decision is the same thing — the teardown is
    // what there is to do.
    if report.as_ref().is_none_or(|r| r.uids.contains(&uid)) {
        match registry
            .send_command(
                &cluster,
                traceparent,
                cloud_command::Op::Destroy(proto::DestroyVm {
                    name: name.clone(),
                    uid,
                }),
            )
            .await
        {
            Ok(Ack::Acked(_)) => {
                store
                    .mutate::<Vm, _>(&name, |v| {
                        v.status.observed_at = Some(Utc::now());
                    })
                    .await?;
                info!(cluster = %cluster, "destroy dispatched");
            }
            Ok(Ack::Rejected(msg)) => {
                warn!(cluster = %cluster, error = %msg, "cluster refused the destroy")
            }
            Err(e) => {
                warn!(cluster = %cluster, error = format!("{e:#}"),
                      "destroy could not be delivered")
            }
        }
        return Ok(());
    }

    let report = report.expect("a missing report keeps us in the branch above");
    if !status_is_current(vm, report.at) {
        debug!(cluster = %cluster, "waiting for a status younger than what we already know");
        return Ok(());
    }
    store.delete::<Vm>(&name).await?;
    info!(cluster = %cluster, "vm deleted");
    Ok(())
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
    match vm.metadata.deletion_timestamp.max(vm.status.observed_at) {
        // Not-older rather than strictly-younger: a status the mirror already
        // wrote from carries exactly that instant, and it is evidence about
        // itself. Two different instants never compare equal here in practice
        // — this only readmits the status that set the floor.
        Some(floor) => reported_at >= floor,
        None => true,
    }
}

/// The tenant's network, looked up where the Tenant object lives.
///
/// The cloud resolves it and the CLUSTER writes it into the NIC entries —
/// that split is the design's, and it is what keeps the cluster from needing
/// a copy of the tenant directory to schedule a VM. A tenant that has no VNI
/// (one created before overlays existed) resolves to nothing and its VMs go
/// on landing on the default bridge, which is what they did yesterday.
///
/// A tenant that has been DELETED out from under a running VM is a warning
/// and not a failed dispatch: refusing to hand the VM down would leave it
/// stuck at the cloud with no way back, and the honest degradation is the
/// same one an old tenant gets.
async fn tenant_vni(store: &EtcdStore, tenant: Option<&str>) -> anyhow::Result<Option<u32>> {
    let Some(tenant) = tenant.filter(|t| !t.is_empty()) else {
        return Ok(None);
    };
    match store.get::<controller_api::Tenant>(tenant).await {
        Ok(t) => Ok(t.spec.vni),
        Err(StoreError::NotFound(_)) => {
            warn!(
                tenant,
                "the tenant this vm belongs to is gone; dispatching without an overlay"
            );
            Ok(None)
        }
        Err(e) => Err(e.into()),
    }
}

/// What a VM may source from, resolved where the objects are.
///
/// The same split `tenant_vni` makes and for the same reason: the FloatingIp
/// and RoutedSubnet objects live at the cloud, the injection into the NIC
/// entries happens at the cluster, and no tier below this one has to know what
/// a tenant is. A VM with no tenant holds nothing — a reservation belongs to a
/// tenant by definition, so an unscoped VM has no way to be given one.
#[derive(Default)]
struct Addresses {
    floating_ips: Vec<String>,
    routed_subnets: Vec<String>,
}

/// Both registries, read once and then asked about per VM.
///
/// A dispatch used to list them for itself, and the note that stood here said
/// so on purpose: a cached answer would be a VM booting with the addresses
/// somebody held an hour ago. That reason is kept and its scope is made exact
/// — the book lives for ONE reconcile pass and is thrown away with it, so the
/// oldest answer it can give is milliseconds old.
///
/// What that buys is the amplification, which the old note underestimated:
/// `missing` and `drifted` are level conditions, so a pass after a cluster
/// restart dispatches EVERY VM it holds, and each of those did two listings
/// and two counts of its own — four etcd round trips per VM, all of them
/// serialized behind the one store client, for two answers that are identical
/// across the whole pass.
///
/// Filled lazily (see `pass`), which is what keeps the common case free: a
/// pass that dispatches nothing still reads nothing.
struct AddressBook {
    reservations: Vec<controller_api::FloatingIp>,
    subnets: Vec<controller_api::RoutedSubnet>,
}

impl AddressBook {
    /// Through the two readers that refuse to answer from a partial list —
    /// an undecodable object here is an address handed to the wrong VM.
    async fn read(store: &EtcdStore) -> anyhow::Result<Self> {
        Ok(Self {
            reservations: controller_api::floating::all_reservations(store).await?,
            subnets: controller_api::floating::all_subnets(store).await?,
        })
    }

    fn for_vm(&self, vm: &Vm) -> Addresses {
        let Some(tenant) = vm.spec.tenant.as_deref().filter(|t| !t.is_empty()) else {
            return Addresses::default();
        };
        let name = vm.metadata.name.as_str();

        // Both filters name the tenant as well as the VM. A VM name is unique
        // in this store so the tenant is redundant today — and it is the check
        // that keeps it redundant: an assignment that somehow named another
        // tenant's VM must not become that VM's permission to use the address.
        let mut floating_ips: Vec<String> = self
            .reservations
            .iter()
            .filter(|ip| ip.spec.tenant == tenant && ip.spec.vm.as_deref() == Some(name))
            .map(|ip| ip.spec.address.clone())
            .collect();
        floating_ips.sort();

        let mut routed_subnets: Vec<String> = self
            .subnets
            .iter()
            .filter(|s| s.spec.tenant == tenant)
            .map(|s| s.spec.cidr.clone())
            .collect();
        routed_subnets.sort();

        if !floating_ips.is_empty() || !routed_subnets.is_empty() {
            debug!(vm = %name, tenant, floating = ?floating_ips, subnets = ?routed_subnets,
                   "resolved the addresses this vm may source from");
        }
        Addresses {
            floating_ips,
            routed_subnets,
        }
    }
}

/// What travels down: the cluster tier's VmSpec and nothing else. The cloud's
/// own binding stays out of it — which cluster a VM sits on is a fact about
/// this store, and shipping a copy downstairs only invites the two to
/// disagree about it.
///
/// The tenant DOES travel, and is not a binding: it is what the VM is, the
/// tier below records it so `cluster vm ls` can say whose a VM is, and the
/// VNI that comes with it on the same message is what the cluster injects.
pub(crate) fn build_spec_json(vm: &Vm) -> anyhow::Result<String> {
    if !vm.spec.vm.is_object() {
        bail!("spec.vm must be a JSON object");
    }
    let strategy = match vm.spec.run_strategy {
        RunStrategy::Running => "Running",
        RunStrategy::Stopped => "Stopped",
        RunStrategy::Paused => "Paused",
    };
    Ok(serde_json::to_string(&serde_json::json!({
        "runStrategy": strategy,
        "tenant": vm.spec.tenant,
        "vm": vm.spec.vm,
    }))?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use controller_api::{VmSpec, resources::new_vm};

    fn at(secs: i64) -> DateTime<Utc> {
        DateTime::from_timestamp(1_800_000_000 + secs, 0).unwrap()
    }

    fn vm() -> Vm {
        new_vm(
            "t",
            VmSpec {
                cluster_selector: Default::default(),
                node_selector: Default::default(),
                anti_affinity: Vec::new(),
                node_name: None,
                cluster_name: Some("cluster-1".into()),
                run_strategy: RunStrategy::Running,
                tenant: None,
                vm: serde_json::json!({ "vcpus": 1 }),
            },
        )
    }

    fn bound_to(cluster: Option<&str>) -> Vm {
        new_vm(
            "t",
            VmSpec {
                cluster_selector: Default::default(),
                node_selector: Default::default(),
                anti_affinity: Vec::new(),
                node_name: None,
                cluster_name: cluster.map(str::to_string),
                run_strategy: RunStrategy::Running,
                tenant: None,
                vm: serde_json::json!({}),
            },
        )
    }

    fn sessions(names: &[&str]) -> HashSet<String> {
        names.iter().map(|s| s.to_string()).collect()
    }

    /// Leaderless ownership, one floor up: my sessions, my VMs.
    #[test]
    fn a_bound_vm_is_only_reconciled_by_the_replica_its_cluster_talks_to() {
        let mine = sessions(&["cluster-1"]);
        assert!(may_reconcile(&bound_to(Some("cluster-1")), &mine));
        assert!(!may_reconcile(&bound_to(Some("cluster-2")), &mine));
        // a replica holding no session at all owns no bound VM
        assert!(!may_reconcile(&bound_to(Some("cluster-1")), &sessions(&[])));
    }

    /// Unbound is everybody's: the scheduler is only offered clusters of the
    /// local session map, so the binding and the ownership land together.
    #[test]
    fn an_unbound_vm_may_be_scheduled_by_any_replica() {
        assert!(may_reconcile(&bound_to(None), &sessions(&[])));
        assert!(may_reconcile(&bound_to(None), &sessions(&["cluster-1"])));
    }

    /// Deleting widens nothing: only the cluster's own replica can order the
    /// teardown, so a deleting VM on a foreign cluster waits.
    #[test]
    fn deleting_does_not_widen_ownership() {
        let mut vm = bound_to(Some("cluster-2"));
        vm.metadata.deletion_timestamp = Some(at(0));
        assert!(!may_reconcile(&vm, &sessions(&["cluster-1"])));
        assert!(may_reconcile(&vm, &sessions(&["cluster-2"])));
    }

    /// The race this gate exists for, in both directions: a status built
    /// before the create landed names no such VM either — as proof of
    /// teardown it would delete a live VM, and as proof of absence it would
    /// have the create dispatched all over again.
    #[test]
    fn a_status_older_than_what_we_know_proves_nothing() {
        let mut v = vm();
        v.metadata.deletion_timestamp = Some(at(100));
        v.status.observed_at = Some(at(120)); // the create ack
        assert!(
            !status_is_current(&v, at(110)),
            "a status from before the ack says nothing"
        );
        assert!(status_is_current(&v, at(121)));
        // The status the mirror wrote from is evidence about itself: it set
        // the floor, and it must not be shut out by it.
        v.status.observed_at = Some(at(130));
        assert!(status_is_current(&v, at(130)));
        assert!(!status_is_current(&v, at(129)));
    }

    /// A VM the cloud never got as far as handing over has no floor to clear.
    #[test]
    fn a_vm_nothing_ever_happened_to_needs_no_proof() {
        let v = vm();
        assert!(status_is_current(&v, at(0)));
    }

    #[test]
    fn the_run_strategy_travels_as_the_cluster_tiers_spec() {
        let mut v = vm();
        v.spec.run_strategy = RunStrategy::Stopped;
        let doc: serde_json::Value = serde_json::from_str(&build_spec_json(&v).unwrap()).unwrap();
        assert_eq!(doc["runStrategy"], "Stopped");
        assert_eq!(doc["vm"]["vcpus"], 1);
        // The binding is ours and stays ours.
        assert!(doc.get("clusterName").is_none());
        assert!(doc["vm"].get("desired").is_none());
    }

    /// The document the cluster receives has to be the document the cluster's
    /// own VmSpec accepts — one spec format the whole way down.
    #[test]
    fn the_cluster_tier_parses_what_the_cloud_sends() {
        let json = build_spec_json(&vm()).unwrap();
        let spec: VmSpec = serde_json::from_str(&json).unwrap();
        assert_eq!(spec.run_strategy, RunStrategy::Running);
        assert!(spec.node_name.is_none() && spec.cluster_name.is_none());
    }

    // --- the address book ----------------------------------------------------

    fn owned(name: &str, tenant: Option<&str>) -> Vm {
        new_vm(
            name,
            VmSpec {
                cluster_selector: Default::default(),
                node_selector: Default::default(),
                anti_affinity: Vec::new(),
                node_name: None,
                cluster_name: Some("cluster-1".into()),
                run_strategy: RunStrategy::Running,
                tenant: tenant.map(str::to_string),
                vm: serde_json::json!({}),
            },
        )
    }

    fn book() -> AddressBook {
        let ip = |address: &str, tenant: &str, vm: Option<&str>| {
            controller_api::FloatingIp::declare(
                address,
                controller_api::resources::FloatingIpSpec {
                    tenant: tenant.into(),
                    pool: "lab".into(),
                    address: address.into(),
                    vm: vm.map(str::to_string),
                },
            )
        };
        let net = |name: &str, tenant: &str, cidr: &str| {
            controller_api::RoutedSubnet::declare(
                name,
                controller_api::RoutedSubnetSpec {
                    tenant: tenant.into(),
                    cidr: cidr.into(),
                    ..controller_api::RoutedSubnetSpec::default()
                },
            )
        };
        AddressBook {
            reservations: vec![
                ip("10.255.0.9", "acme", Some("web")),
                ip("10.255.0.7", "acme", Some("web")),
                ip("10.255.0.8", "acme", Some("db")),
                ip("10.255.0.5", "acme", None),
                // The same VM NAME under another tenant. A VM name is unique
                // in this store, so this cannot happen today — and the filter
                // that keeps it unable to matter is the one under test.
                ip("203.0.113.4", "other", Some("web")),
            ],
            subnets: vec![
                net("acme-net", "acme", "10.7.1.0/24"),
                net("other-net", "other", "10.7.2.0/24"),
            ],
        }
    }

    /// The two listings that used to happen per dispatch happen once per pass,
    /// and every VM of that pass is answered out of the one book. What each of
    /// them gets back is exactly what its own listing would have given it:
    /// its tenant's subnets, and the addresses assigned to it BY NAME AND BY
    /// TENANT — an assignment naming another tenant's VM is not that VM's
    /// permission to source from the address.
    #[test]
    fn one_address_book_answers_for_every_vm_of_the_pass() {
        let book = book();

        let web = book.for_vm(&owned("web", Some("acme")));
        assert_eq!(web.floating_ips, ["10.255.0.7", "10.255.0.9"], "sorted");
        assert_eq!(web.routed_subnets, ["10.7.1.0/24"]);

        // The same book, a second VM, no second listing.
        let db = book.for_vm(&owned("db", Some("acme")));
        assert_eq!(db.floating_ips, ["10.255.0.8"]);
        assert_eq!(db.routed_subnets, ["10.7.1.0/24"]);

        // A VM of the tenant that holds nothing assigned to it still gets the
        // tenant's subnets, and none of anybody's addresses.
        let idle = book.for_vm(&owned("idle", Some("acme")));
        assert!(idle.floating_ips.is_empty());
        assert_eq!(idle.routed_subnets, ["10.7.1.0/24"]);
    }

    /// A reservation belongs to a tenant by definition, so a VM without one
    /// has no way to be given anything — and an empty tenant string is not a
    /// tenant either.
    #[test]
    fn a_vm_without_a_tenant_holds_nothing() {
        let book = book();
        for vm in [owned("web", None), owned("web", Some(""))] {
            let none = book.for_vm(&vm);
            assert!(none.floating_ips.is_empty() && none.routed_subnets.is_empty());
        }
    }
}
