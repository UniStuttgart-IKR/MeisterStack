// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Cluster sessions: cluster-controllers dial in (gRPC bidi
//! `ClusterPlane.Session`), say Hello with their name and then execute
//! commands. The registry holds one entry per connection and correlates
//! CommandResults by request_id, so the reconciler can await an ack without
//! owning the stream. One tier down the agents do exactly this; the shape is
//! the same on purpose.
//!
//! The session is also the only way status travels upwards: Hello creates or
//! refreshes the cluster's Cluster object, every ClusterStatus is its heartbeat
//! and carries the phase of each VM the cluster holds for the cloud.
//!
//! A cluster is several controller replicas now, and they all dial here — the
//! same name gives them the same HRW favourite, so a group arrives together.
//! The entry is therefore per connection and the cluster name only groups
//! them, because keying by the name let the second replica evict the first.

use std::collections::{HashMap, HashSet};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use anyhow::anyhow;
use chrono::{DateTime, Utc};
use macros::generated;
use proto::cluster_plane_server::{ClusterPlane, ClusterPlaneServer};
use proto::{
    CloudCommand, CloudMessage, ClusterHello, ClusterMessage, ClusterStatus, cloud_command,
    cluster_message, command_result,
};
use tokio::sync::mpsc;
use tokio_stream::StreamExt;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status, Streaming};
use tracing::{debug, error, info, warn};

use controller_api::{
    Ack, Cluster, ClusterSpec, EtcdStore, Observation, Peer, Pending, StoreError, Vm,
};

/// Shorter than the agent tier's, and deliberately: a cluster answers a command
/// with a single store write, so a minute of patience would only mean a minute
/// in which a wedged cluster holds up everybody else's reconcile pass.
const ACK_TIMEOUT: Duration = Duration::from_secs(15);

/// How long a session may stay silent before it stops being able to speak for
/// its cluster. A cluster reports every 10s on every one of its sessions, so
/// this tolerates two missed reports — the same tolerance the heartbeat gets.
const MUTE_AFTER_SECS: i64 = 30;

type CommandTx = mpsc::Sender<Result<CloudMessage, Status>>;

/// The cloud uids one cluster named in its last complete status, and when.
/// Absence from such a report is the only proof of teardown the cloud accepts,
/// which is exactly why an incomplete report is not stored at all: a short
/// list would read as "these VMs are gone".
#[derive(Clone, Debug)]
pub struct Report {
    pub at: DateTime<Utc>,
    pub uids: HashSet<String>,
}

/// One dialled-in cluster-controller process, for as long as its stream lives.
struct Session {
    cluster: String,
    tx: CommandTx,
    /// When this session said Hello — the newest of a group speaks for it.
    hello: DateTime<Utc>,
    /// When it last put a status on the wire, whether or not anybody was
    /// listening to it as evidence. A session that has fallen silent cannot
    /// speak for its cluster (see `speaker`).
    last_status: Option<DateTime<Utc>>,
    /// What this session last told us, and only ever set while it was the
    /// speaker (see `speaker`).
    report: Option<Report>,
}

pub struct SessionRegistry {
    sessions: Mutex<HashMap<u64, Session>>,
    /// Names connections, nothing else. A cluster restarting into a new
    /// session must not be confused with the old one, and a counter is the
    /// cheapest thing that cannot repeat within a process.
    next_id: AtomicU64,
    pending: Pending,
}

#[generated(model = ClaudeOpus, version = "5")]
impl Default for SessionRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[generated(model = ClaudeOpus, version = "5")]
impl SessionRegistry {
    pub fn new() -> Self {
        Self {
            sessions: Mutex::default(),
            next_id: AtomicU64::new(0),
            pending: Pending::new(ACK_TIMEOUT),
        }
    }

    /// Clusters with at least one live session. Readiness lives on the Cluster
    /// object; this is only the "can I reach it right now" half — and one live
    /// session of the group is enough to be able to reach it.
    pub fn connected(&self) -> HashSet<String> {
        self.sessions
            .lock()
            .unwrap()
            .values()
            .map(|s| s.cluster.clone())
            .collect()
    }

    /// The one session of a group the cloud talks to and listens to: the
    /// newest Hello that is still talking, ties broken by id so the choice is
    /// total.
    ///
    /// Picking one rather than any is not tidiness, it is the M4 teardown
    /// proof. What that proof needs is that a status which *arrived* after a
    /// command's ack was also *built* after it, and the only thing that
    /// guarantees it is the cluster building both on one task and this side
    /// reading one stream in order. Two replicas of a cluster share no such
    /// order: the other one's status can be built before our command landed
    /// and arrive after the ack, and absence from that list is precisely what
    /// this tier reads as "torn down".
    ///
    /// Silence disqualifies, and that half is what keeps one wedged replica
    /// from taking its cluster down with it. A cluster-controller that cannot
    /// read its own store — the minority side of an etcd partition, precisely
    /// the case this design promises to survive — keeps its session open and
    /// sends nothing (`send_status` refuses to ship a hollow status). Without
    /// this, that replica would hold the voice for as long as it lived while
    /// its healthy siblings kept the heartbeat fresh, and every VM of the
    /// cluster would wait on evidence that was never coming. A session that
    /// has not spoken within `MUTE_AFTER_SECS` therefore yields to one that
    /// has; if none has, the newest Hello holds it and the wait is honest.
    fn speaker(sessions: &HashMap<u64, Session>, cluster: &str, now: DateTime<Utc>) -> Option<u64> {
        let mine = || sessions.iter().filter(|(_, s)| s.cluster == cluster);
        let talking = |s: &Session| {
            s.last_status
                .is_some_and(|t| now.signed_duration_since(t).num_seconds() <= MUTE_AFTER_SECS)
        };
        let newest = |it: &mut dyn Iterator<Item = (&u64, &Session)>| {
            it.max_by(|a, b| a.1.hello.cmp(&b.1.hello).then_with(|| a.0.cmp(b.0)))
                .map(|(id, _)| *id)
        };
        newest(&mut mine().filter(|(_, s)| talking(s))).or_else(|| newest(&mut mine()))
    }

    /// What this cluster last told us, or None while it has told us nothing
    /// current — a fresh session, a speaker that just took over, or one whose
    /// status said it could not read its own store. None means "unknown",
    /// never "empty".
    pub fn report(&self, cluster: &str) -> Option<Report> {
        self.report_at(cluster, Utc::now())
    }

    fn report_at(&self, cluster: &str, now: DateTime<Utc>) -> Option<Report> {
        let sessions = self.sessions.lock().unwrap();
        let id = Self::speaker(&sessions, cluster, now)?;
        sessions.get(&id)?.report.clone()
    }

    /// Register a connection under its cluster and hand back the id it keeps
    /// for the rest of its life. A second Hello on the same connection
    /// replaces its own entry and nobody else's.
    fn open(&self, previous: Option<u64>, cluster: &str, tx: &CommandTx, at: DateTime<Utc>) -> u64 {
        let mut sessions = self.sessions.lock().unwrap();
        if let Some(id) = previous {
            sessions.remove(&id);
        }
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        sessions.insert(
            id,
            Session {
                cluster: cluster.to_string(),
                tx: tx.clone(),
                hello: at,
                last_status: None,
                // A new session knows nothing yet, and the last one's list must
                // not be mistaken for this one's.
                report: None,
            },
        );
        id
    }

    /// File a status against its session. True means this session speaks for
    /// its cluster, and so that its VM list is evidence and its aggregate is
    /// worth mirroring; false means the status counts as a heartbeat only.
    fn record_report(&self, id: u64, status: &ClusterStatus, at: DateTime<Utc>) -> bool {
        let mut sessions = self.sessions.lock().unwrap();
        let Some(cluster) = sessions.get(&id).map(|s| s.cluster.clone()) else {
            return false;
        };
        // Stamped before the voice is chosen and for every session, speaker or
        // not: this is the proof of talking that the choice is made on, so a
        // standby has to be able to earn the voice without holding it first.
        sessions
            .get_mut(&id)
            .expect("just read under this lock")
            .last_status = Some(at);
        let speaks = Self::speaker(&sessions, &cluster, at) == Some(id);
        let entry = sessions.get_mut(&id).expect("just read under this lock");
        if !speaks {
            // Evidence lives with the voice and nowhere else, so that a
            // session taking it over starts from "unknown" rather than from
            // whatever it happened to hear last time it was listened to.
            entry.report = None;
            return false;
        }
        if !status.vms_complete {
            // The cluster said so itself. Forgetting is the honest answer:
            // every decision that reads this asks a question absence would
            // answer wrongly.
            warn!(
                cluster,
                "cluster reported an incomplete vm list; treating it as unknown"
            );
            entry.report = None;
        } else {
            entry.report = Some(Report {
                at,
                uids: status.vms.iter().map(|v| v.id.clone()).collect(),
            });
        }
        true
    }

    /// Drop this session's entry, and nobody else's — that is what the old
    /// same_channel guard was really for, and per-connection ids generalise
    /// it. Some(cluster) only when the group is now empty: a cluster is down
    /// when its last replica has gone, not when one of three has.
    fn close(&self, id: u64) -> Option<String> {
        let mut sessions = self.sessions.lock().unwrap();
        let gone = sessions.remove(&id)?;
        if sessions.values().any(|s| s.cluster == gone.cluster) {
            return None;
        }
        Some(gone.cluster)
    }

    /// Send one command to a cluster's session and wait for its CommandResult.
    ///
    /// The speaker's session, and only its: a command answered on a stream
    /// other than the one the cloud reads its evidence from would break the
    /// ordering the teardown proof rests on (see `speaker`).
    pub async fn send_command(
        &self,
        cluster: &str,
        traceparent: &str,
        op: cloud_command::Op,
    ) -> anyhow::Result<Ack> {
        // Found before anything is registered to wait on it, so the "no
        // session" path has nothing to clean up — see `Pending::send`.
        let tx = {
            let sessions = self.sessions.lock().unwrap();
            Self::speaker(&sessions, cluster, Utc::now())
                .and_then(|id| sessions.get(&id).map(|s| s.tx.clone()))
        };
        let tx = tx.ok_or_else(|| anyhow!("cluster {cluster} has no active session"))?;

        let peer = Peer {
            kind: "cluster",
            name: cluster,
        };
        self.pending
            .send(peer, &tx, |request_id| CloudMessage {
                kind: Some(proto::cloud_message::Kind::Command(CloudCommand {
                    request_id,
                    traceparent: traceparent.to_string(),
                    op: Some(op),
                })),
            })
            .await
    }
}

/// Hello: the cluster exists from now on. Creating on first sight is what makes
/// the inventory survive the cluster — one that is down is disconnected, not
/// absent — and it is also what keeps the first status from writing into
/// nothing, because `mutate` does not create.
#[generated(model = ClaudeOpus, version = "5")]
async fn ingest_hello(store: &EtcdStore, hello: &ClusterHello) -> anyhow::Result<()> {
    let name = hello.cluster_name.as_str();
    if matches!(
        store.get::<Cluster>(name).await,
        Err(StoreError::NotFound(_))
    ) {
        match store
            .create(&Cluster::declare(name, ClusterSpec::default()))
            .await
        {
            // Two sessions for one cluster can race here; either object will do.
            Ok(_) | Err(StoreError::AlreadyExists(_)) => {}
            Err(e) => return Err(e.into()),
        }
    }
    let version = hello.version.clone();
    store
        .mutate::<Cluster, _>(name, |c| {
            c.status.connected = true;
            c.status.last_heartbeat = Some(Utc::now());
            c.status.version = Some(version.clone());
        })
        .await?;
    Ok(())
}

/// A cluster status is the cluster's heartbeat, the aggregate the cloud places
/// against, and the phase of every VM it holds for us.
///
/// Every session's status is a heartbeat; only the speaker's is a description
/// (see `SessionRegistry::speaker`). A standby replica reads the same cluster
/// etcd, so its aggregate is not wrong — it is merely a second, slightly older
/// account of the same thing, and letting two accounts write the same fields
/// buys nothing but a phase that walks backwards for one interval.
#[generated(model = ClaudeOpus, version = "5")]
async fn ingest_status(
    store: &EtcdStore,
    cluster: &str,
    status: &ClusterStatus,
    at: DateTime<Utc>,
    speaker: bool,
) -> anyhow::Result<()> {
    if !speaker {
        store
            .mutate::<Cluster, _>(cluster, |c| {
                c.status.connected = true;
                c.status.last_heartbeat = Some(at);
            })
            .await?;
        return Ok(());
    }
    let capacity = status.capacity.clone();
    let (ready, total, vms) = (
        status.nodes_ready,
        status.nodes_total,
        status.vms.len() as u32,
    );
    store
        .mutate::<Cluster, _>(cluster, |c| {
            c.status.connected = true;
            c.status.last_heartbeat = Some(at);
            c.status.nodes_ready = ready;
            c.status.nodes_total = total;
            c.status.vms = vms;
            if let Some(cap) = &capacity {
                c.status.capacity.vcpus = cap.vcpus;
                c.status.capacity.mem_mib = cap.mem_mib;
                c.status.capacity.capabilities = cap.capabilities.clone();
            }
        })
        .await?;

    if status.vms.is_empty() {
        return Ok(());
    }

    // The cluster speaks the uids this cloud handed out on CreateVm, while the
    // store is keyed by name, so the list doubles as the index — the same
    // trade the cluster tier makes with the agent's reports, and the reason
    // both read their reports through `controller_api::mirror`.
    let known = store.list::<Vm>().await?;
    // Bound to THIS cluster, strictly: an unplaced VM has no cluster whose
    // word about it counts.
    let ours = |vm: &Vm| vm.spec.cluster_name.as_deref() == Some(cluster);

    for (reported, seen) in controller_api::observe(&known, &status.vms, ours) {
        let (vm, phase, message) = match seen {
            Observation::Unknown => {
                // Not a phase we can file anywhere. It is also not nothing:
                // some cluster is running a VM in this cloud's name that this
                // cloud has no record of, and that deserves to be said out
                // loud rather than dropped at debug level.
                warn!(cluster, vm_id = %reported.id,
                      "cluster reports a cloud-managed vm this cloud does not know");
                continue;
            }
            Observation::NotBound(vm) => {
                warn!(vm = %vm.metadata.name, cluster,
                      "status from a cluster the vm is not bound to");
                continue;
            }
            Observation::BadPhase(vm) => {
                warn!(vm = %vm.metadata.name, phase = %reported.phase,
                      "unknown phase from cluster");
                continue;
            }
            Observation::Changed(vm, phase, message) => (vm, phase, message),
        };
        let name = vm.metadata.name.clone();
        let result = store
            .mutate::<Vm, _>(&name, |v| {
                v.status.phase = phase;
                v.status.message = message.clone();
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
            Ok(_) => info!(vm = %name, vm_id = %reported.id, ?phase, "phase observed"),
            Err(e) => warn!(vm = %name, error = format!("{e:#}"), "writing vm status failed"),
        }
    }
    Ok(())
}

pub fn service(
    registry: std::sync::Arc<SessionRegistry>,
    store: std::sync::Arc<EtcdStore>,
    chain: controller_api::grpc::SessionAuth,
) -> ClusterPlaneServer<ClusterPlaneService> {
    ClusterPlaneServer::new(ClusterPlaneService {
        registry,
        store,
        chain,
    })
}

pub struct ClusterPlaneService {
    registry: std::sync::Arc<SessionRegistry>,
    store: std::sync::Arc<EtcdStore>,
    /// The same chain the REST API runs. Empty = anonymous, which is how
    /// every session in M1 through M4 was opened and still is by default.
    chain: controller_api::grpc::SessionAuth,
}

/// What one live stream knows about itself: which cluster it claims to be,
/// and the id the registry knows it by. Both None until Hello, and that is
/// the whole reason they are a pair — a status before Hello has nothing to be
/// filed against and nobody to be filed as.
#[generated(model = ClaudeOpus, version = "5")]
#[derive(Default)]
struct Live {
    cluster: Option<String>,
    id: Option<u64>,
}

/// Whether the stream goes on. A refused Hello is the only thing that ends a
/// session from this side; everything else it can be told is either handled or
/// logged and survived.
#[generated(model = ClaudeOpus, version = "5")]
enum Step {
    Continue,
    Stop,
}

/// One dialled-in cluster-controller, for as long as its stream lives: what it
/// may write to, what it may be sent down, and who its certificate said it is.
///
/// The handler used to hold all of this in the locals of one spawned block,
/// with the three message kinds inlined into the match arms — one function
/// that was the connection state machine, the identity check, the hello, the
/// status ingest and the teardown at once. Split into named steps, each of
/// them is a paragraph that can be read on its own, and the loop below says
/// only what the loop actually decides: read, dispatch, stop or go on.
#[generated(model = ClaudeOpus, version = "5")]
struct Connection {
    registry: std::sync::Arc<SessionRegistry>,
    store: std::sync::Arc<EtcdStore>,
    tx: CommandTx,
    /// Who the certificate said dialled in — checked against every Hello.
    who: controller_api::Authenticated,
}

#[generated(model = ClaudeOpus, version = "5")]
impl Connection {
    /// One session, message by message, until the stream ends or a Hello is
    /// refused. Whatever ends it, the close runs.
    async fn pump(self, mut inbound: Streaming<ClusterMessage>) {
        let mut live = Live::default();
        while let Some(msg) = inbound.next().await {
            let msg = match msg {
                Ok(m) => m,
                Err(e) => {
                    warn!(
                        error = format!("{e:#}"),
                        cluster = live.cluster.as_deref().unwrap_or("?"),
                        "session stream error"
                    );
                    break;
                }
            };
            let step = match msg.kind {
                Some(cluster_message::Kind::Hello(hello)) => self.hello(&mut live, hello).await,
                Some(cluster_message::Kind::Status(status)) => {
                    self.status(&live, status).await;
                    Step::Continue
                }
                Some(cluster_message::Kind::Result(result)) => {
                    self.result(result);
                    Step::Continue
                }
                None => Step::Continue,
            };
            if matches!(step, Step::Stop) {
                break;
            }
        }
        self.closed(&live).await;
    }

    /// The cluster exists from now on, under the name its certificate allows
    /// it to claim.
    async fn hello(&self, live: &mut Live, hello: ClusterHello) -> Step {
        // The certificate said who dialled; the hello says which cluster it
        // claims to be. One cluster's key must not let it speak for another's
        // VMs.
        if let Err(e) =
            controller_api::grpc::check_session_identity(&self.who, "cluster", &hello.cluster_name)
        {
            // Error, not warn: a cluster whose certificate does not match the
            // name it claims will redial with the same certificate for ever.
            // No reconnect repairs that; only a person re-issuing it does.
            error!(cluster = %hello.cluster_name, error = format!("{e:#}"),
                   "refusing the session");
            let _ = self.tx.send(Err(e)).await;
            return Step::Stop;
        }
        info!(cluster = %hello.cluster_name, version = %hello.version, "cluster connected");
        if let Err(e) = ingest_hello(&self.store, &hello).await {
            warn!(cluster = %hello.cluster_name, error = format!("{e:#}"),
                  "recording the cluster failed");
        }
        live.id = Some(
            self.registry
                .open(live.id, &hello.cluster_name, &self.tx, Utc::now()),
        );
        live.cluster = Some(hello.cluster_name);
        Step::Continue
    }

    /// A status: this session's heartbeat always, and its cluster's account of
    /// itself if this session holds the voice.
    async fn status(&self, live: &Live, status: ClusterStatus) {
        let (Some(name), Some(id)) = (live.cluster.as_deref(), live.id) else {
            warn!("cluster status before hello, ignoring");
            return;
        };
        // One instant for the report and for everything it writes, so the two
        // can be compared at all.
        let at = Utc::now();
        let speaker = self.registry.record_report(id, &status, at);
        if let Err(e) = ingest_status(&self.store, name, &status, at, speaker).await {
            warn!(
                cluster = name,
                error = format!("{e:#}"),
                "status ingest failed"
            );
        }
    }

    /// The answer to a command somebody is awaiting. Correlated by request_id,
    /// so it needs nothing from the session state at all.
    fn result(&self, result: proto::CommandResult) {
        let outcome = match result.outcome {
            Some(command_result::Outcome::Ok(_)) => Ok(()),
            Some(command_result::Outcome::Error(e)) => Err(e.message),
            None => Err("result without outcome".to_string()),
        };
        self.registry.pending.resolve(&result.request_id, outcome);
    }

    /// The stream is over. Only the last replica of a cluster leaving means
    /// the cluster is gone; a reconnect that already replaced us, or a sibling
    /// still dialled in, keeps its own session and its readiness.
    async fn closed(&self, live: &Live) {
        let Some(id) = live.id else { return };
        match self.registry.close(id) {
            Some(name) => {
                info!(cluster = %name, "cluster disconnected");
                let result = self
                    .store
                    .mutate::<Cluster, _>(&name, |c| c.status.connected = false)
                    .await;
                if let Err(e) = result {
                    warn!(cluster = %name, error = format!("{e:#}"),
                          "marking the cluster down failed");
                }
            }
            None => debug!(
                cluster = live.cluster.as_deref().unwrap_or("?"),
                "session closed, another of this cluster is live"
            ),
        }
    }
}

#[generated(model = ClaudeOpus, version = "5")]
#[tonic::async_trait]
impl ClusterPlane for ClusterPlaneService {
    type SessionStream = ReceiverStream<Result<CloudMessage, Status>>;

    async fn session(
        &self,
        request: Request<Streaming<ClusterMessage>>,
    ) -> Result<Response<Self::SessionStream>, Status> {
        // Before the stream is touched: whoever this is, they are that for
        // the whole session. A certificate cannot change halfway through.
        let who = controller_api::grpc::authenticate_session(&self.chain, &request)?;
        if let controller_api::Authenticated::As(identity) = &who {
            info!(identity = %identity, "cluster session authenticated");
        }
        let inbound = request.into_inner();
        let (tx, rx) = mpsc::channel(16);
        tokio::spawn(
            Connection {
                registry: self.registry.clone(),
                store: self.store.clone(),
                tx,
                who,
            }
            .pump(inbound),
        );
        Ok(Response::new(ReceiverStream::new(rx)))
    }
}

#[cfg(test)]
#[generated(model = ClaudeOpus, version = "5")]
mod tests {
    use super::*;
    use proto::{ClusterCapacity, VmStatusReport};

    fn status(complete: bool, uids: &[&str]) -> ClusterStatus {
        ClusterStatus {
            nodes_ready: 1,
            nodes_total: 1,
            capacity: Some(ClusterCapacity::default()),
            vms: uids
                .iter()
                .map(|u| VmStatusReport {
                    id: (*u).to_string(),
                    phase: "Running".into(),
                    message: String::new(),
                })
                .collect(),
            vms_complete: complete,
        }
    }

    fn at(secs: i64) -> DateTime<Utc> {
        DateTime::from_timestamp(1_800_000_000 + secs, 0).unwrap()
    }

    /// The voice as the registry would pick it at a given instant. The tests
    /// run on a fixed clock so that a silence is a silence and not a race.
    fn voice(reg: &SessionRegistry, cluster: &str, now: DateTime<Utc>) -> Option<u64> {
        SessionRegistry::speaker(&reg.sessions.lock().unwrap(), cluster, now)
    }

    fn uids(reg: &SessionRegistry, cluster: &str, now: DateTime<Utc>) -> Option<HashSet<String>> {
        reg.report_at(cluster, now).map(|r| r.uids)
    }

    /// A session, as far as the registry is concerned: a channel nobody reads.
    fn dial(reg: &SessionRegistry, cluster: &str, at: DateTime<Utc>) -> u64 {
        let (tx, rx) = mpsc::channel(1);
        // The receiver has to outlive the test or the sender reports closed;
        // leaking it is cheaper than threading it through every assertion.
        Box::leak(Box::new(rx));
        reg.open(None, cluster, &tx, at)
    }

    /// The blocker this whole re-keying exists for: three replicas of one
    /// cluster used to overwrite each other, so the second Hello silently
    /// unplugged the first.
    #[test]
    fn three_replicas_of_a_cluster_are_three_sessions_of_one_group() {
        let reg = SessionRegistry::new();
        let ids: Vec<u64> = (0..3).map(|i| dial(&reg, "c1", at(i))).collect();
        assert_eq!(reg.sessions.lock().unwrap().len(), 3);
        assert_eq!(reg.connected(), ["c1".to_string()].into_iter().collect());

        // Losing one leaves the others standing, and the cluster stays up
        // until the last of them has gone.
        assert_eq!(reg.close(ids[2]), None);
        assert_eq!(reg.close(ids[0]), None);
        assert_eq!(reg.connected(), ["c1".to_string()].into_iter().collect());
        assert_eq!(reg.close(ids[1]).as_deref(), Some("c1"));
        assert!(reg.connected().is_empty());
        // and a session that already left cannot report its cluster down twice
        assert_eq!(reg.close(ids[1]), None);
    }

    /// One voice per cluster, and it is the newest session that has actually
    /// spoken: within one stream the cluster's answers are ordered against our
    /// commands, between two streams they are not (see `speaker`). A newcomer
    /// takes the voice with its first status rather than on its Hello, so the
    /// handover lands on a list that was just built.
    #[test]
    fn the_voice_is_the_newest_session_that_has_spoken() {
        let reg = SessionRegistry::new();
        let old = dial(&reg, "c1", at(0));
        let new = dial(&reg, "c1", at(1));

        // Nobody has spoken yet, so the first to speak is listened to.
        assert!(reg.record_report(old, &status(true, &["uid-a"]), at(2)));
        assert_eq!(
            uids(&reg, "c1", at(2)),
            Some(["uid-a".to_string()].into_iter().collect())
        );

        // The newer session speaks up: it takes the voice, and its own list is
        // what the cloud reasons with from here.
        assert!(reg.record_report(new, &status(true, &["uid-b"]), at(3)));
        assert_eq!(
            uids(&reg, "c1", at(3)),
            Some(["uid-b".to_string()].into_iter().collect())
        );

        // The demoted one is a heartbeat now, and stops holding evidence — so
        // that taking the voice back can only ever start from "unknown".
        assert!(!reg.record_report(old, &status(true, &["uid-a"]), at(4)));
        assert_eq!(
            uids(&reg, "c1", at(4)),
            Some(["uid-b".to_string()].into_iter().collect())
        );
        assert_eq!(reg.close(new), None);
        assert_eq!(
            uids(&reg, "c1", at(5)),
            None,
            "the voice changed hands; nothing is known yet"
        );
    }

    /// The half of the voice rule that keeps a wedged replica from taking its
    /// cluster with it: a cluster-controller on the minority side of an etcd
    /// partition holds its session open and says nothing, while its healthy
    /// siblings keep the heartbeat fresh — so silence, not liveness, has to be
    /// what moves the voice on.
    #[test]
    fn a_session_that_falls_silent_yields_the_voice_to_one_that_has_not() {
        let reg = SessionRegistry::new();
        let healthy = dial(&reg, "c1", at(0));
        let wedged = dial(&reg, "c1", at(1)); // newer Hello

        // Both talk once, so the newer one holds the voice.
        assert!(reg.record_report(wedged, &status(true, &["uid-a"]), at(2)));
        assert!(!reg.record_report(healthy, &status(true, &["uid-a"]), at(3)));
        assert_eq!(voice(&reg, "c1", at(3)), Some(wedged));

        // Now the wedged one goes quiet — session open, store unreadable, so
        // nothing on the wire — while the healthy one keeps reporting.
        assert_eq!(
            voice(&reg, "c1", at(2 + MUTE_AFTER_SECS)),
            Some(wedged),
            "a gap inside the tolerance must not move the voice"
        );
        assert!(reg.record_report(healthy, &status(true, &["uid-b"]), at(3 + MUTE_AFTER_SECS)));
        assert_eq!(voice(&reg, "c1", at(3 + MUTE_AFTER_SECS)), Some(healthy));
        // and the cloud now reasons about the cluster from the replica that
        // can actually read it
        assert_eq!(
            uids(&reg, "c1", at(3 + MUTE_AFTER_SECS)),
            Some(["uid-b".to_string()].into_iter().collect())
        );

        // A group where nobody has spoken at all still has a voice: the newest
        // Hello holds it, and the wait for its first status is the honest one.
        let quiet = SessionRegistry::new();
        let first = dial(&quiet, "c2", at(0));
        let second = dial(&quiet, "c2", at(1));
        assert_eq!(voice(&quiet, "c2", at(9999)), Some(second));
        assert_ne!(voice(&quiet, "c2", at(9999)), Some(first));
    }

    /// Grouping is by name and the entries are per connection: two clusters
    /// never see each other's sessions, and one cluster's speaker is not the
    /// other's.
    #[test]
    fn groups_do_not_reach_into_each_other() {
        let reg = SessionRegistry::new();
        let c1 = dial(&reg, "c1", at(0));
        let c2 = dial(&reg, "c2", at(1));
        assert!(reg.record_report(c1, &status(true, &["uid-a"]), at(2)));
        assert!(reg.record_report(c2, &status(true, &[]), at(2)));
        assert_eq!(reg.report("c1").unwrap().uids.len(), 1);
        assert!(reg.report("c2").unwrap().uids.is_empty());
        assert_eq!(reg.close(c1).as_deref(), Some("c1"));
        assert!(
            reg.report("c2").is_some(),
            "c1 leaving says nothing about c2"
        );
    }

    /// The whole teardown proof rests on this: a list the cluster could not
    /// build completely must leave the cloud knowing nothing, not knowing an
    /// empty set. "Unknown" blocks a delete; "empty" would authorise it.
    #[test]
    fn an_incomplete_report_is_forgotten_rather_than_believed() {
        let reg = SessionRegistry::new();
        let id = dial(&reg, "c1", at(0));
        reg.record_report(id, &status(true, &["uid-a", "uid-b"]), at(1));
        assert_eq!(reg.report("c1").unwrap().uids.len(), 2);

        reg.record_report(id, &status(false, &[]), at(2));
        assert!(
            reg.report("c1").is_none(),
            "an incomplete list must not stand as a fact"
        );
    }

    #[test]
    fn a_cluster_nobody_reported_on_is_unknown_not_empty() {
        let reg = SessionRegistry::new();
        assert!(reg.report("c1").is_none());
        dial(&reg, "c1", at(0));
        assert!(
            reg.report("c1").is_none(),
            "a fresh session has told us nothing yet"
        );
    }
}
