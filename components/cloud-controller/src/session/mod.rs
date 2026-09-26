// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Bidirectional cluster sessions carrying commands, results and status.
//! Hello registers the cluster; subsequent status messages refresh its heartbeat
//! and report cloud-managed resources. Results correlate by request ID.
//!
//! Each cluster replica has a separate connection entry. Cluster names group
//! connections for speaker selection without evicting sibling replicas.

use std::collections::{HashMap, HashSet};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use anyhow::anyhow;
use chrono::{DateTime, Utc};
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

use controller_api::events::{self, Happening};
use controller_api::{
    Ack, Cluster, ClusterSpec, EtcdStore, Observation, Peer, Pending, StoreError, Vm, Volume,
    VolumePhaseKind,
};
use controller_api::{EventType, Image, ImagePhaseKind, Resource, VmPhaseKind};

/// Shorter than the agent tier's, and deliberately: a cluster answers a command
/// with a single store write, so a minute of patience would only mean a minute
/// in which a wedged cluster holds up everybody else's reconcile pass.
const ACK_TIMEOUT: Duration = Duration::from_secs(15);

/// How long a session may stay silent before it stops being able to speak for
/// its cluster. A cluster reports every 10s on every one of its sessions, so
/// this tolerates two missed reports — the same tolerance the heartbeat gets.
const MUTE_AFTER_SECS: i64 = 30;

type CommandTx = mpsc::Sender<Result<CloudMessage, Status>>;

mod hello;
mod ingest;
mod inventory;
#[cfg(test)]
mod tests;

use inventory::*;

/// The cloud uids one cluster named in its last complete status, and when.
/// Absence from such a report is the only proof of teardown the cloud accepts,
/// which is exactly why an incomplete report is not stored at all: a short
/// list would read as "these VMs are gone".
#[derive(Clone, Debug)]
pub struct Report {
    pub at: DateTime<Utc>,
    pub uids: HashSet<String>,
    /// The routers named in the same status, under the same rule and with one
    /// difference: `None` says the cluster's router list was short, and a
    /// teardown reads that as "still there" rather than as proof. Separate
    /// from the VM list because the two completeness statements are separate,
    /// and a cluster that could read all its routers and not all its VMs
    /// should not have its routers forgotten as well.
    pub routers: Option<HashSet<String>>,
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
    // --- lane 5A ---
    /// The serial of the certificate this session opened with, or `None`
    /// when nothing authenticated it (anonymous mode, a bearer token).
    ///
    /// The only handle there is on a session that is already running: a
    /// certificate that is revoked while it talks has to be findable, and
    /// the name it claims is not enough — a rotation gives one cluster two
    /// certificates, and only one of them is the one that was taken back.
    serial: Option<String>,
    // --- end lane 5A ---
}

/// What each cluster last said it is holding for this cloud, by cluster.
///
/// In memory beside the session map and not in the store, for the reason the
/// cluster's `ImageView` gives: it is a summary of what peers are saying
/// right now, it is rebuilt from their reports, and a second copy in etcd
/// would be a number nobody recomputed. A replica that has just started knows
/// nothing and therefore sends everything once — which is what every replica
/// did on every pass before this existed.
#[derive(Default)]
pub struct SecretView(Mutex<HashMap<String, Vec<proto::SecretStateReport>>>);

impl SecretView {
    pub fn observe(&self, cluster: &str, reports: &[proto::SecretStateReport]) {
        self.0
            .lock()
            .expect("secret view")
            .insert(cluster.to_string(), reports.to_vec());
    }

    /// What that cluster said. Empty for one that has not spoken yet, and
    /// empty means "nothing known", which is safe: the mirror then sends.
    pub fn of(&self, cluster: &str) -> Vec<proto::SecretStateReport> {
        self.0
            .lock()
            .expect("secret view")
            .get(cluster)
            .cloned()
            .unwrap_or_default()
    }

    /// A cluster that has gone stops being remembered, so that a replica does
    /// not skip a send on the strength of something a departed session said.
    pub fn forget(&self, cluster: &str) {
        self.0.lock().expect("secret view").remove(cluster);
    }
}

pub struct SessionRegistry {
    sessions: Mutex<HashMap<u64, Session>>,
    /// What each cluster is holding for this cloud, sealed. See `SecretView`.
    pub secrets: SecretView,
    /// Console sessions this replica is serving, by the id it chose.
    ///
    /// On the registry because a console crosses two tasks here as well: a
    /// REST handler starts one and the SESSION task receives its frames, and
    /// the session task has no idea a REST edge exists.
    pub consoles: CloudConsoles,
    /// Names connections, nothing else. A cluster restarting into a new
    /// session must not be confused with the old one, and a counter is the
    /// cheapest thing that cannot repeat within a process.
    next_id: AtomicU64,
    pending: Pending,
}

/// What a console session's REST handler is waiting to hear.
#[derive(Debug)]
pub enum ConsoleEvent {
    /// The line was given, or refused with this sentence.
    Opened(Result<(), String>),
    /// The guest said something.
    Data(Vec<u8>),
    /// It is over, and why.
    Closed(String),
}

/// The console sessions this replica has open, by id.
///
/// Deliberately per-REPLICA and not in the store: a console is a connection,
/// and a connection belongs to the process holding it. A client that reaches
/// a different replica gets a different session, which is the honest answer —
/// see the note on `open` about which replica can serve one at all.
#[derive(Default)]
pub struct CloudConsoles {
    waiting: Mutex<HashMap<String, mpsc::Sender<ConsoleEvent>>>,
}

impl CloudConsoles {
    /// Start listening for one session's frames. The receiver is the REST
    /// handler's; dropping it is what makes `deliver` give up.
    pub fn expect(&self, session_id: &str) -> mpsc::Receiver<ConsoleEvent> {
        let (tx, rx) = mpsc::channel(64);
        self.waiting
            .lock()
            .unwrap()
            .insert(session_id.to_string(), tx);
        rx
    }

    pub fn forget(&self, session_id: &str) {
        self.waiting.lock().unwrap().remove(session_id);
    }

    /// Hand one event to the handler waiting for it. `false` when nobody is
    /// — a session whose client has gone, which the caller turns into a close
    /// travelling back down.
    pub async fn deliver(&self, session_id: &str, event: ConsoleEvent) -> bool {
        let tx = self.waiting.lock().unwrap().get(session_id).cloned();
        match tx {
            Some(tx) => tx.send(event).await.is_ok(),
            None => false,
        }
    }
}

impl Default for SessionRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl SessionRegistry {
    pub fn new() -> Self {
        Self {
            sessions: Mutex::default(),
            next_id: AtomicU64::new(0),
            pending: Pending::new(ACK_TIMEOUT),
            consoles: CloudConsoles::default(),
            secrets: SecretView::default(),
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

    /// Select the newest recently reporting session, breaking Hello ties by ID.
    /// Commands and accepted status use this one stream so arrival order can support
    /// the ACK/status freshness check; independent streams cannot provide that order.
    /// A session silent beyond `MUTE_AFTER_SECS` yields to a reporting sibling.
    /// If all are silent, retain the newest Hello and await evidence.
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

    /// Does THIS replica hold a session to that cluster?
    ///
    /// The one question a forward has to answer before it decides anything
    /// else, and `speaker` already answers it — a cluster with a speaker here
    /// is a cluster this process can send a command to. Separate from
    /// `report` because a session that has said nothing yet still IS a
    /// session: it can take a command, which is what a console read needs,
    /// even though there is no status to read.
    pub fn holds(&self, cluster: &str) -> bool {
        let sessions = self.sessions.lock().unwrap();
        Self::speaker(&sessions, cluster, Utc::now()).is_some()
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
    fn open(
        &self,
        previous: Option<u64>,
        cluster: &str,
        tx: &CommandTx,
        at: DateTime<Utc>,
        serial: Option<String>,
    ) -> u64 {
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
                // --- lane 5A ---
                serial,
                // --- end lane 5A ---
            },
        );
        id
    }

    /// End revoked sessions by sending a stream error. Let stream teardown run
    /// `closed` and update cluster connectivity; removing the map entry here would
    /// bypass that lifecycle. Return affected identities for logging.
    pub async fn drop_revoked(
        &self,
        list: &controller_api::auth::RevocationList,
    ) -> Vec<(String, String)> {
        let doomed: Vec<(u64, String, String, CommandTx)> = {
            let sessions = self.sessions.lock().unwrap();
            sessions
                .iter()
                .filter_map(|(id, session)| {
                    let serial = session.serial.as_ref()?;
                    list.is_revoked(serial).then(|| {
                        (
                            *id,
                            session.cluster.clone(),
                            serial.clone(),
                            session.tx.clone(),
                        )
                    })
                })
                .collect()
        };
        let mut ended = Vec::new();
        for (id, cluster, serial, tx) in doomed {
            warn!(
                cluster = %cluster,
                serial = %serial,
                session = id,
                "the certificate of a live session is revoked; ending it"
            );
            let _ = tx
                .send(Err(Status::permission_denied(format!(
                    "the certificate {serial} this session opened with is revoked"
                ))))
                .await;
            ended.push((cluster, serial));
        }
        ended
    }
    // --- end lane 5A ------------------------------------------------------

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
                routers: status
                    .routers_complete
                    .then(|| status.routers.iter().map(|r| r.id.clone()).collect()),
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

    /// Send an unacknowledged message to the cluster's selected speaker.
    /// Console frames have no request ID and do not produce CommandResults.
    pub async fn send_to(&self, cluster: &str, msg: proto::CloudMessage) -> bool {
        let tx = {
            let sessions = self.sessions.lock().unwrap();
            Self::speaker(&sessions, cluster, Utc::now())
                .and_then(|id| sessions.get(&id).map(|s| s.tx.clone()))
        };
        match tx {
            Some(tx) => tx.send(Ok(msg)).await.is_ok(),
            None => false,
        }
    }

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

pub fn service(
    registry: std::sync::Arc<SessionRegistry>,
    store: std::sync::Arc<EtcdStore>,
    chain: controller_api::grpc::SessionAuth,
    advertise: Option<String>,
) -> ClusterPlaneServer<ClusterPlaneService> {
    ClusterPlaneServer::new(ClusterPlaneService {
        registry,
        store,
        chain,
        advertise,
    })
}

pub struct ClusterPlaneService {
    registry: std::sync::Arc<SessionRegistry>,
    store: std::sync::Arc<EtcdStore>,
    /// The same chain the REST API runs. Empty = anonymous, which is how
    /// every session in M1 through M4 was opened and still is by default.
    chain: controller_api::grpc::SessionAuth,
    /// Where this replica's REST API can be reached by its siblings, if it
    /// can name an address at all. Written into the cluster's status at
    /// Hello, so that a console read landing on another replica knows where
    /// to forward. `None` behind a wildcard bind — see `advertised`.
    advertise: Option<String>,
}

/// What one live stream knows about itself: which cluster it claims to be,
/// and the id the registry knows it by. Both None until Hello, and that is
/// the whole reason they are a pair — a status before Hello has nothing to be
/// filed against and nobody to be filed as.
#[derive(Default)]
struct Live {
    cluster: Option<String>,
    id: Option<u64>,
}

/// Whether the stream goes on. A refused Hello is the only thing that ends a
/// session from this side; everything else it can be told is either handled or
/// logged and survived.
enum Step {
    Continue,
    Stop,
}

/// State and handlers for one cluster-controller connection, including identity,
/// message dispatch and teardown.
struct Connection {
    registry: std::sync::Arc<SessionRegistry>,
    store: std::sync::Arc<EtcdStore>,
    tx: CommandTx,
    /// Who the certificate said dialled in — checked against every Hello.
    who: controller_api::Authenticated,
    /// This replica's own REST address, for the cluster status it writes.
    advertise: Option<String>,
}

impl Connection {
    // --- lane 5A ---
    /// The serial of the certificate this connection authenticated with, or
    /// `None` when nothing did. Read once, at the Hello, because `who` is
    /// settled before the first message and never re-read.
    fn serial(&self) -> Option<String> {
        match &self.who {
            controller_api::Authenticated::As(identity) => identity.serial.clone(),
            controller_api::Authenticated::Anonymous => None,
        }
    }
    // --- end lane 5A ---

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
                Some(cluster_message::Kind::ConsoleOpened(opened)) => {
                    self.console_opened(opened).await;
                    Step::Continue
                }
                Some(cluster_message::Kind::ConsoleOutput(data)) => {
                    self.console_output(&live, data).await;
                    Step::Continue
                }
                Some(cluster_message::Kind::ConsoleClose(close)) => {
                    self.console_close(close).await;
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

    /// The console, arriving from below. Handed to the REST handler that is
    /// waiting for this session_id and read by nothing here — the same rule
    /// the whole console path follows.
    async fn console_opened(&self, opened: proto::ConsoleOpened) {
        let outcome = match opened.error.is_empty() {
            true => Ok(()),
            false => Err(opened.error.clone()),
        };
        self.registry
            .consoles
            .deliver(&opened.session_id, ConsoleEvent::Opened(outcome))
            .await;
    }

    /// Console bytes, upward to whoever holds this session_id.
    async fn console_output(&self, live: &Live, data: proto::ConsoleData) {
        if !self
            .registry
            .consoles
            .deliver(&data.session_id, ConsoleEvent::Data(data.data))
            .await
            && let Some(cluster) = live.cluster.as_deref()
        {
            // Nobody is listening any more. Tell the tier below to give the
            // line back rather than holding it for a client that has gone.
            self.registry
                .send_to(
                    cluster,
                    proto::CloudMessage {
                        kind: Some(proto::cloud_message::Kind::ConsoleClose(
                            proto::ConsoleClose {
                                session_id: data.session_id,
                                reason: "the client went away".to_string(),
                            },
                        )),
                    },
                )
                .await;
        }
    }

    /// The line ended below. Whoever is waiting hears the reason, once, and
    /// the route goes with it.
    async fn console_close(&self, close: proto::ConsoleClose) {
        self.registry
            .consoles
            .deliver(&close.session_id, ConsoleEvent::Closed(close.reason))
            .await;
        self.registry.consoles.forget(&close.session_id);
    }

    /// The answer to a command somebody is awaiting. Correlated by request_id,
    /// so it needs nothing from the session state at all.
    fn result(&self, result: proto::CommandResult) {
        let outcome = match result.outcome {
            // The peer's payload travels back with the ack. Empty for every
            // command that only changed something.
            Some(command_result::Outcome::Ok(ack)) => Ok(ack.payload),
            Some(command_result::Outcome::Error(e)) => {
                Err(controller_api::Refusal::new(e.message, e.reason))
            }
            None => Err(controller_api::Refusal::plain("result without outcome")),
        };
        self.registry.pending.resolve(&result.request_id, outcome);
    }
}

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
                advertise: self.advertise.clone(),
            }
            .pump(inbound),
        );
        Ok(Response::new(ReceiverStream::new(rx)))
    }
}
