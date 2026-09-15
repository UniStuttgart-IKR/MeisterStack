// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Agent sessions: agents dial in (gRPC bidi `ControlPlane.Session`), say
//! Hello with their node_id and then execute commands. The registry maps
//! node_id -> command channel and correlates CommandResults by request_id,
//! so the reconciler can await an ack without owning the stream.
//!
//! The session is also the only way status travels upwards: Hello creates or
//! refreshes the node's Node object, every StatusReport is its heartbeat and
//! carries the phase of each VM the node runs.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, anyhow, bail};
use chrono::{DateTime, Utc};
use proto::ClusterMessage;
use proto::control_plane_server::{ControlPlane, ControlPlaneServer};
use proto::{
    AgentMessage, Command, ControllerMessage, DriverInfo, Hello, StatusReport, agent_message,
    command, command_result,
};
use tokio::sync::mpsc;
use tokio::time::Instant;
use tokio_stream::StreamExt;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status, Streaming};
use tracing::{debug, error, info, warn};

use common::capability::{self, Locality};
use controller_api::events::{self, Happening};
use controller_api::{
    Ack, Authenticated, EtcdStore, Node, NodeSpec, Observation, Peer, Pending, StoreError, Vm,
    Volume, VolumePhaseKind, VolumeSnapshot, VolumeSnapshotPhaseKind,
};
use controller_api::{EventType, Resource, VmPhaseKind};

use crate::reconcile::build_spec_json;

const ACK_TIMEOUT: Duration = Duration::from_secs(60);

/// How long one reading of the VM list may serve the status reports that
/// arrive while it is warm. See `VmIndex`.
const VM_INDEX_TTL: Duration = Duration::from_secs(1);

type CommandTx = mpsc::Sender<Result<ControllerMessage, Status>>;

mod console;
mod hello;
mod ingest;
#[cfg(test)]
mod tests;

use console::*;
pub use console::{ConsoleRelay, LocalConsoleEvent};
use hello::*;
use ingest::*;

/// What the cluster's nodes have said about base images, by image AND by
/// node.
///
/// In memory beside the session map and not in the store, and that is the
/// same shape the VM index has: it is a summary of what peers are saying
/// right now, it is rebuilt from their reports, and a second copy in etcd
/// would be a number nobody recomputed.
///
/// By node since the cloud grew `Image.status.nodes[]`. It used to merge here
/// — one line per image, Failed winning over Ready — and the merge is right
/// but it was made one tier too early: from up there a rollout still running
/// and a checksum that will never match were the same word. The merge moved
/// to the cloud, which is where both halves are wanted; here each node's line
/// stands on its own, and the newest line from a node replaces that node's
/// older one, because a node that re-fetched an image is telling the truth
/// about it now.
#[derive(Default)]
pub struct ImageView(std::sync::Mutex<HashMap<(String, String), (String, String)>>);

impl ImageView {
    /// Take in one node's opinions.
    pub fn observe(&self, node: &str, reports: &[proto::ImageStateReport]) {
        let mut held = self.0.lock().unwrap();
        for report in reports {
            held.insert(
                (report.name.clone(), node.to_string()),
                (report.phase.clone(), report.message.clone()),
            );
        }
    }

    /// What to tell the cloud: one line per image per node.
    pub fn report(&self) -> Vec<proto::ImageStateReport> {
        let held = self.0.lock().unwrap();
        let mut out: Vec<proto::ImageStateReport> = held
            .iter()
            .map(|((name, node), (phase, message))| proto::ImageStateReport {
                name: name.clone(),
                phase: phase.clone(),
                // struktur 4: the nodes send a word now; relaying it is the
                // derivation lane's, which is where this map grows a third
                // value.
                reason: String::new(),
                message: message.clone(),
                node: node.clone(),
            })
            .collect();
        // Sorted, so two consecutive reports of the same facts are the same
        // message.
        out.sort_by(|a, b| (&a.name, &a.node).cmp(&(&b.name, &b.node)));
        out
    }
}

pub struct SessionRegistry {
    nodes: Mutex<HashMap<String, CommandTx>>,
    pending: Pending,
    /// Console frames on their way between the cloud and a node.
    ///
    /// On the registry because this is where the two session tasks already
    /// meet: one holds the agents, the other holds the cloud, and a console
    /// is the one thing that has to cross from either into the other. See
    /// `ConsoleRelay`.
    pub consoles: Arc<ConsoleRelay>,
    /// What the nodes have said about base images. On the registry because
    /// that is where the other summary of what peers are saying lives, and
    /// because the cloud session reads it from a different task than the one
    /// that fills it.
    pub images: ImageView,
}

impl Default for SessionRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl SessionRegistry {
    pub fn new() -> Self {
        Self {
            nodes: Mutex::default(),
            pending: Pending::new(ACK_TIMEOUT),
            consoles: Arc::new(ConsoleRelay::default()),
            images: ImageView::default(),
        }
    }

    /// Node ids with a live session. Readiness lives on the Node object; this
    /// is only the "can I reach it right now" half.
    pub fn connected(&self) -> HashSet<String> {
        self.nodes.lock().unwrap().keys().cloned().collect()
    }

    /// This session is the node's session from now on. A second Hello for a
    /// node that already has one REPLACES it: an agent that reconnected is
    /// speaking through the new stream, and commands sent down the old one
    /// would go to a channel nobody reads. The old session's own unwinding
    /// cannot undo this — see `disconnect`.
    fn register(&self, node_id: &str, tx: &CommandTx) {
        self.nodes
            .lock()
            .unwrap()
            .insert(node_id.to_string(), tx.clone());
    }

    /// Drop this session's entry — but only if it is still the current one. A
    /// quickly restarting agent registers its new session before the old
    /// stream finishes unwinding, and that newer session must survive.
    fn disconnect(&self, node_id: &str, tx: &CommandTx) -> bool {
        let mut nodes = self.nodes.lock().unwrap();
        match nodes.get(node_id) {
            Some(current) if current.same_channel(tx) => {
                nodes.remove(node_id);
                true
            }
            _ => false,
        }
    }

    /// A session for a node without a stream behind it.
    ///
    /// Test-only, and it is the door the migration forward is proved through:
    /// `dispatch`'s test needs TWO registries in one process, one of which
    /// holds the node — and `register` is this module's, because a session is
    /// made by a Hello and by nothing else.
    #[cfg(test)]
    pub(crate) fn attach(&self, node_id: &str, tx: &CommandTx) {
        self.register(node_id, tx);
    }

    /// The answer a real agent's `CommandResult` would carry, for the same
    /// test: `on_result` is the only other caller and it needs a stream.
    #[cfg(test)]
    pub(crate) fn answer(&self, request_id: &str, payload: Vec<u8>) {
        self.pending.resolve(request_id, Ok(payload));
    }

    /// Send one command to a node's session and wait for its CommandResult.
    /// `traceparent` rides on the envelope so the node's work lands in the
    /// trace of the request that asked for it; empty means "no context", and
    /// the node then starts its own rather than guessing.
    /// The payload the agent sent back with its ack — empty for every
    /// command that only changes something, and the console document for the
    /// one that asks a question.
    /// Send one message down a node's session without waiting for anything.
    ///
    /// Its own method beside `send_command` because a console frame is not a
    /// command: there is no request_id, nothing acks it, and a keystroke that
    /// waited for an answer would be a keystroke that arrives after the next
    /// one. `false` means the node has no session, which the caller turns
    /// into the end of that console session.
    pub async fn send_to(&self, node_id: &str, msg: ControllerMessage) -> bool {
        let tx = self.nodes.lock().unwrap().get(node_id).cloned();
        match tx {
            Some(tx) => tx.send(Ok(msg)).await.is_ok(),
            None => false,
        }
    }

    pub async fn send_command(
        &self,
        node_id: &str,
        traceparent: &str,
        op: command::Op,
    ) -> anyhow::Result<Vec<u8>> {
        // Found before anything is registered to wait on it, so the "no
        // session" path has nothing to clean up — see `Pending::send`.
        let tx = self
            .nodes
            .lock()
            .unwrap()
            .get(node_id)
            .cloned()
            .ok_or_else(|| anyhow!("node {node_id} has no active session"))?;

        let peer = Peer {
            kind: "agent",
            name: node_id,
        };
        let answer = self
            .pending
            .send(peer, &tx, |request_id| ControllerMessage {
                kind: Some(proto::controller_message::Kind::Command(Command {
                    request_id,
                    traceparent: traceparent.to_string(),
                    op: Some(op),
                })),
            })
            .await?;
        match answer {
            Ack::Acked(payload) => Ok(payload),
            // A refusal is the agent's own answer about this VM, and it
            // travels as a CAUSE rather than as a string: since storage B one
            // caller branches on the word — a create the node cannot serve at
            // all is answered by taking the binding back, and a caller
            // reduced to matching on prose would change behaviour the day
            // somebody rewords a message.
            Ack::Rejected(refusal) => {
                Err(anyhow::Error::new(refusal)
                    .context(format!("agent {node_id} rejected command")))
            }
        }
    }
}

/// The VM list a status report needs to turn the uids an agent speaks into
/// the names the store is keyed by, read once for all the reports that arrive
/// at the same moment.
///
/// Every agent reports every ten seconds, so at fifty nodes this list was
/// being read five times a second, and every one of those reads returned the
/// same list. The window is deliberately far shorter than the report interval:
/// what it coalesces is reports that overlap, never a node's next report.
///
/// What a reused list can get wrong is what it does not yet contain, and that
/// case is the one this tier acts on hardest — an uid no stored VM carries is
/// dropped as somebody else's VM. So an unknown uid is treated as evidence
/// that the list is behind: it is re-read once and the report looked at again
/// (`ingest_status`), which makes the outcome the same as an uncached read
/// and costs a node that really does run VMs of its own exactly what it cost
/// before. Everything else a slightly old entry says is corrected by the
/// write, which is a read-modify-write against the live object.
#[derive(Default)]
pub struct VmIndex {
    /// When it was read, and what was read. `None` = never.
    cached: Mutex<Option<(Instant, Arc<Vec<Vm>>)>>,
}

impl VmIndex {
    /// The list, and whether it was read just now. `false` means it came from
    /// the last read and may be behind by up to `VM_INDEX_TTL`.
    ///
    /// The store is behind a closure so the cache can be exercised without
    /// one — and so this stays the only place that decides when to read.
    async fn list<F, Fut>(&self, fetch: F) -> anyhow::Result<(Arc<Vec<Vm>>, bool)>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = anyhow::Result<Vec<Vm>>>,
    {
        {
            // Scoped: the guard must be gone before the fetch is awaited.
            let cached = self.cached.lock().unwrap();
            if let Some((at, vms)) = cached.as_ref()
                && at.elapsed() < VM_INDEX_TTL
            {
                return Ok((vms.clone(), false));
            }
        }
        Ok((self.refresh(fetch).await?, true))
    }

    /// Read the list and keep it. Two reports racing here cost two reads and
    /// nothing else: both are answers to the same question.
    async fn refresh<F, Fut>(&self, fetch: F) -> anyhow::Result<Arc<Vec<Vm>>>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = anyhow::Result<Vec<Vm>>>,
    {
        let vms = Arc::new(fetch().await?);
        *self.cached.lock().unwrap() = Some((Instant::now(), vms.clone()));
        Ok(vms)
    }
}

pub fn service(
    registry: Arc<SessionRegistry>,
    store: Arc<EtcdStore>,
    chain: controller_api::grpc::SessionAuth,
    advertise: Option<String>,
    kek: Option<Arc<controller_api::secrets::Kek>>,
) -> ControlPlaneServer<ControlPlaneService> {
    ControlPlaneServer::new(ControlPlaneService {
        registry,
        store,
        chain,
        advertise,
        kek,
        // One index for the whole server: what it saves is the reads of
        // agents reporting at the same moment, so it has to be shared by
        // all of their sessions.
        vms: Arc::new(VmIndex::default()),
    })
}

pub struct ControlPlaneService {
    registry: Arc<SessionRegistry>,
    store: Arc<EtcdStore>,
    /// The same chain the REST API runs. Empty = anonymous, which is how
    /// every agent session up to M4 was opened and still is by default.
    chain: controller_api::grpc::SessionAuth,
    vms: Arc<VmIndex>,
    /// This replica's own REST address, where it has one to give.
    advertise: Option<String>,
    /// See `Session::kek`.
    kek: Option<Arc<controller_api::secrets::Kek>>,
}

#[tonic::async_trait]
impl ControlPlane for ControlPlaneService {
    type SessionStream = ReceiverStream<Result<ControllerMessage, Status>>;

    async fn session(
        &self,
        request: Request<Streaming<AgentMessage>>,
    ) -> Result<Response<Self::SessionStream>, Status> {
        // Before the stream is touched: whoever this is, they are that for
        // the whole session. A certificate cannot change halfway through.
        let who = controller_api::grpc::authenticate_session(&self.chain, &request)?;
        if let Authenticated::As(identity) = &who {
            info!(identity = %identity, "agent session authenticated");
        }
        let inbound = request.into_inner();
        let (tx, rx) = mpsc::channel(16);
        tokio::spawn(pump(
            Session {
                registry: self.registry.clone(),
                store: self.store.clone(),
                vms: self.vms.clone(),
                who,
                tx,
                advertise: self.advertise.clone(),
                kek: self.kek.clone(),
            },
            inbound,
        ));

        Ok(Response::new(ReceiverStream::new(rx)))
    }
}

/// Everything one agent's session holds for as long as it lasts. `who` is
/// settled before the first message and never re-read.
struct Session {
    registry: Arc<SessionRegistry>,
    store: Arc<EtcdStore>,
    vms: Arc<VmIndex>,
    who: Authenticated,
    tx: CommandTx,
    /// Where a sibling replica can reach THIS one, if it can say. Written
    /// onto the node at Hello; see `ingest_hello`.
    advertise: Option<String>,
    /// The key a secret's values are opened with, for the one thing a session
    /// does that needs it: the reconnect snapshot, which carries the same
    /// resolved cloud-init a dispatch does. See `reconcile::seed_for`.
    kek: Option<Arc<controller_api::secrets::Kek>>,
}

/// One session, from the first message to the end of the stream: read, decide
/// what kind of message it is, hand it to the step that answers it. The steps
/// are below; what stays here is the loop and the one piece of state a
/// session has — which node it turned out to be.
///
/// One handler per `AgentMessage` variant, and each of them takes exactly what
/// it reads: the loop owns `node_id`, so a handler that needs it is handed it
/// and a handler that does not cannot reach it.
async fn pump(session: Session, mut inbound: Streaming<AgentMessage>) {
    let mut node_id: Option<String> = None;
    while let Some(msg) = inbound.next().await {
        let msg = match msg {
            Ok(m) => m,
            Err(e) => {
                warn!(
                    error = format!("{e:#}"),
                    node = node_id.as_deref().unwrap_or("?"),
                    "session stream error"
                );
                break;
            }
        };
        match msg.kind {
            Some(agent_message::Kind::Hello(hello)) => match on_hello(&session, hello).await {
                Some(id) => node_id = Some(id),
                // Refused, or the stream went away while the desired state
                // was going out. Either way there is no session to keep.
                None => break,
            },
            Some(agent_message::Kind::Status(report)) => {
                on_status(&session, node_id.as_deref(), &report).await;
            }
            Some(agent_message::Kind::ConsoleOpened(opened)) => {
                on_console_opened(&session, opened).await;
            }
            Some(agent_message::Kind::ConsoleOutput(data)) => {
                on_console_output(&session, node_id.as_deref(), data).await;
            }
            Some(agent_message::Kind::ConsoleClose(close)) => {
                on_console_close(&session, close).await;
            }
            Some(agent_message::Kind::Result(result)) => on_result(&session, result),
            None => {}
        }
    }
    if let Some(id) = node_id {
        on_disconnect(&session, &id).await;
    }
}

/// The answer to a command this replica sent, back to whoever is waiting on
/// the request id.
fn on_result(session: &Session, result: proto::CommandResult) {
    let outcome = match result.outcome {
        // The peer's payload travels back with the ack. Empty for every
        // command that only changed something.
        Some(command_result::Outcome::Ok(ack)) => Ok(ack.payload),
        Some(command_result::Outcome::Error(e)) => {
            Err(controller_api::Refusal::new(e.message, e.reason))
        }
        None => Err(controller_api::Refusal::plain("result without outcome")),
    };
    session
        .registry
        .pending
        .resolve(&result.request_id, outcome);
}
