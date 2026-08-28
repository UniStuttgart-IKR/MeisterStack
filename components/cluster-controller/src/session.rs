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

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, anyhow, bail};
use chrono::Utc;
use macros::generated;
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

use common::capability;
use controller_api::{
    Ack, Authenticated, EtcdStore, Node, NodeSpec, Observation, Peer, Pending, StoreError, Vm,
};

use crate::reconcile::build_spec_json;

const ACK_TIMEOUT: Duration = Duration::from_secs(60);

/// How long one reading of the VM list may serve the status reports that
/// arrive while it is warm. See `VmIndex`.
const VM_INDEX_TTL: Duration = Duration::from_secs(1);

type CommandTx = mpsc::Sender<Result<ControllerMessage, Status>>;

pub struct SessionRegistry {
    nodes: Mutex<HashMap<String, CommandTx>>,
    pending: Pending,
}

#[generated(model = ClaudeOpus, version = "5")]
impl Default for SessionRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[generated(model = ClaudeFable, version = "5")]
impl SessionRegistry {
    pub fn new() -> Self {
        Self {
            nodes: Mutex::default(),
            pending: Pending::new(ACK_TIMEOUT),
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
    #[generated(model = ClaudeOpus, version = "5")]
    fn register(&self, node_id: &str, tx: &CommandTx) {
        self.nodes
            .lock()
            .unwrap()
            .insert(node_id.to_string(), tx.clone());
    }

    /// Drop this session's entry — but only if it is still the current one. A
    /// quickly restarting agent registers its new session before the old
    /// stream finishes unwinding, and that newer session must survive.
    #[generated(model = ClaudeOpus, version = "5")]
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

    /// Send one command to a node's session and wait for its CommandResult.
    /// `traceparent` rides on the envelope so the node's work lands in the
    /// trace of the request that asked for it; empty means "no context", and
    /// the node then starts its own rather than guessing.
    pub async fn send_command(
        &self,
        node_id: &str,
        traceparent: &str,
        op: command::Op,
    ) -> anyhow::Result<()> {
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
            Ack::Acked => Ok(()),
            // A refusal is the agent's own answer about this VM, and at this
            // tier there is nothing else to do with one: the caller is a
            // reconcile pass that will derive the same command again next
            // tick, so what it needs is the sentence, not a variant.
            Ack::Rejected(msg) => bail!("agent {node_id} rejected command: {msg}"),
        }
    }
}

/// The agent's driver catalogue as the flat capacity list NodeCapacity keeps.
/// The spelling itself is `common::capability::entry` — the same function
/// FirstFit matches against one tier up, so what a node claims and what a
/// scheduler looks for cannot be worded differently.
#[generated(model = ClaudeOpus, version = "5")]
fn capacity_profiles(drivers: &[DriverInfo]) -> Vec<String> {
    drivers
        .iter()
        .flat_map(|d| {
            if d.profiles.is_empty() {
                // No profiles to choose between: the driver name IS the entry.
                vec![capability::entry(&d.name, None)]
            } else {
                d.profiles
                    .iter()
                    .map(|p| capability::entry(&d.name, Some(p)))
                    .collect()
            }
        })
        .collect()
}

/// Hello: the node exists from now on, with what it just told us about
/// itself. Creating on first sight is what makes the inventory survive the
/// agent — a node that is down is NotReady, not absent.
#[generated(model = ClaudeOpus, version = "5")]
async fn ingest_hello(store: &EtcdStore, hello: &Hello) -> anyhow::Result<()> {
    let name = hello.node_id.as_str();
    let profiles = capacity_profiles(&hello.drivers);
    let apply = |n: &mut Node| {
        n.status.ready = true;
        n.status.last_heartbeat = Some(Utc::now());
        n.status.agent_version = Some(hello.agent_version.clone());
        n.status.capacity.capabilities = profiles.clone();
    };

    if matches!(store.get::<Node>(name).await, Err(StoreError::NotFound(_))) {
        match store
            .create(&Node::declare(name, NodeSpec::default()))
            .await
        {
            // Two sessions for one node can race here; either object will do.
            Ok(_) | Err(StoreError::AlreadyExists(_)) => {}
            Err(e) => return Err(e.into()),
        }
    }
    store.mutate::<Node, _>(name, apply).await?;
    Ok(())
}

/// Everything this node is supposed to be running, as the CreateInstance
/// list the agent already knows how to apply — one message instead of a
/// replay of the history it missed.
///
/// VMs on their way out are deliberately absent: they keep going through
/// Destroy so the finalizer stays the single teardown path, and their
/// absence from the snapshot is precisely what tells an agent that was
/// offline to tear them down anyway.
///
/// All or nothing, and that is the important part. The agent reads a missing
/// VM as a deleted one, so a snapshot built from a list with one unreadable
/// object in it would order the teardown of a VM that is merely unreadable
/// here. Failing to build one costs the reconnect sweep and nothing else;
/// sending half of one costs somebody's VM.
#[generated(model = ClaudeOpus, version = "5")]
async fn desired_snapshot(
    store: &EtcdStore,
    node_id: &str,
) -> anyhow::Result<Vec<proto::CreateInstance>> {
    let vms = store.list::<Vm>().await?;
    // `list` drops what it cannot decode, and an object dropped here reads
    // at the agent as an object deleted. Count first, and say nothing at all
    // rather than something that means "the rest is gone".
    let stored = store.count::<Vm>().await?;
    if vms.len() != stored {
        bail!(
            "{} of {stored} vm objects did not decode; a snapshot missing them \
             would read as their deletion",
            stored - vms.len()
        );
    }

    let mut out = Vec::new();
    for vm in vms {
        if vm.is_deleting() || vm.spec.node_name.as_deref() != Some(node_id) {
            continue;
        }
        let spec_json = build_spec_json(&vm).with_context(|| format!("vm {}", vm.metadata.name))?;
        out.push(proto::CreateInstance {
            id: vm.metadata.uid.clone(),
            spec: None,
            spec_json,
        });
    }
    Ok(out)
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
#[generated(model = ClaudeOpus, version = "5")]
#[derive(Default)]
pub struct VmIndex {
    /// When it was read, and what was read. `None` = never.
    cached: Mutex<Option<(Instant, Arc<Vec<Vm>>)>>,
}

#[generated(model = ClaudeOpus, version = "5")]
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

/// Whether every uid in the report is one this list can name. False is the
/// only thing that makes a reused list worse than a fresh one, so it is the
/// only thing worth re-reading for.
#[generated(model = ClaudeOpus, version = "5")]
fn all_known(vms: &[Vm], reported: &[proto::VmStatusReport]) -> bool {
    let uids: HashSet<&str> = vms.iter().map(|v| v.metadata.uid.as_str()).collect();
    reported.iter().all(|line| uids.contains(line.id.as_str()))
}

/// A status report is the node's heartbeat and the phase of every VM on it.
#[generated(model = ClaudeOpus, version = "5")]
async fn ingest_status(
    store: &EtcdStore,
    index: &VmIndex,
    node_id: &str,
    report: &StatusReport,
) -> anyhow::Result<()> {
    let facts = report.node;
    let count = report.vms.len() as u32;
    store
        .mutate::<Node, _>(node_id, |n| {
            n.status.ready = true;
            n.status.last_heartbeat = Some(Utc::now());
            n.status.vms = count;
            if let Some(f) = facts {
                n.status.capacity.vcpus = f.vcpus;
                n.status.capacity.mem_mib = f.mem_mib;
            }
        })
        .await?;

    if report.vms.is_empty() {
        return Ok(());
    }

    // The agent speaks uids — that is the id it was handed on CreateInstance —
    // while the store is keyed by name, so the list doubles as the index. The
    // cloud tier reads its clusters' reports the same way, through
    // `controller_api::mirror`.
    let fetch = || async { store.list::<Vm>().await.map_err(anyhow::Error::from) };
    let (vms, fresh) = index.list(fetch).await?;
    // An uid the index cannot name is the one answer a reused list gets
    // wrong, and it is also the answer this tier throws a report away for.
    // Re-read once before believing it.
    let vms = if fresh || all_known(&vms, &report.vms) {
        vms
    } else {
        index.refresh(fetch).await?
    };
    // Bound elsewhere disqualifies the reporter; not bound at all does not.
    // Deliberately looser than the cloud tier's, which takes an unplaced VM's
    // report from nobody.
    let ours = |vm: &Vm| {
        vm.spec
            .node_name
            .as_deref()
            .is_none_or(|bound| bound == node_id)
    };
    // One instant for the whole report, as one floor up: what is being
    // recorded is when this status was seen, not when each write of it landed.
    let at = Utc::now();

    for (reported, seen) in controller_api::observe(&vms, &report.vms, ours) {
        let (vm, phase, message) = match seen {
            Observation::Unknown => {
                // A VM created straight on the agent's own API: not ours.
                debug!(node = node_id, vm_id = %reported.id, "status for an unknown vm, ignoring");
                continue;
            }
            Observation::NotBound(vm) => {
                warn!(vm = %vm.metadata.name, node = node_id, "status from a node the vm is not bound to");
                continue;
            }
            Observation::BadPhase(vm) => {
                warn!(vm = %vm.metadata.name, phase = %reported.phase, "unknown phase from agent");
                continue;
            }
            Observation::Changed(vm, phase, message) => (vm, phase, message),
        };
        let name = vm.metadata.name.clone();
        let result = store
            .mutate::<Vm, _>(&name, |v| {
                v.status.phase = phase;
                v.status.message = message.clone();
                // From the binding, never from the reporter — the rule the
                // cloud tier states one floor up, and it matters more here
                // because `ours` deliberately accepts a report about a VM
                // that is not bound at all (an agent still running one should
                // still be able to say what phase it is in). Stamping the
                // reporter's name would let such an agent write itself into
                // the status of a VM nobody placed there, and `vm ls` would
                // then show a node the spec does not name.
                v.status.node_name = v.spec.node_name.clone();
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
    registry: Arc<SessionRegistry>,
    store: Arc<EtcdStore>,
    chain: controller_api::grpc::SessionAuth,
) -> ControlPlaneServer<ControlPlaneService> {
    ControlPlaneServer::new(ControlPlaneService {
        registry,
        store,
        chain,
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
}

#[generated(model = ClaudeFable, version = "5")]
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
            },
            inbound,
        ));

        Ok(Response::new(ReceiverStream::new(rx)))
    }
}

/// Everything one agent's session holds for as long as it lasts. `who` is
/// settled before the first message and never re-read.
#[generated(model = ClaudeOpus, version = "5")]
struct Session {
    registry: Arc<SessionRegistry>,
    store: Arc<EtcdStore>,
    vms: Arc<VmIndex>,
    who: Authenticated,
    tx: CommandTx,
}

/// One session, from the first message to the end of the stream: read, decide
/// what kind of message it is, hand it to the step that answers it. The steps
/// are below; what stays here is the loop and the one piece of state a
/// session has — which node it turned out to be.
#[generated(model = ClaudeOpus, version = "5")]
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
                let Some(id) = node_id.as_deref() else {
                    warn!("status report before hello, ignoring");
                    continue;
                };
                if let Err(e) = ingest_status(&session.store, &session.vms, id, &report).await {
                    warn!(node = id, error = format!("{e:#}"), "status ingest failed");
                }
            }
            Some(agent_message::Kind::Result(result)) => {
                let outcome = match result.outcome {
                    Some(command_result::Outcome::Ok(_)) => Ok(()),
                    Some(command_result::Outcome::Error(e)) => Err(e.message),
                    None => Err("result without outcome".to_string()),
                };
                session
                    .registry
                    .pending
                    .resolve(&result.request_id, outcome);
            }
            None => {}
        }
    }
    if let Some(id) = node_id {
        on_disconnect(&session, &id).await;
    }
}

/// The node exists, it is who it says it is, it has been told what it is
/// supposed to be running, and from now on commands reach it. Returns the
/// node id the rest of the session speaks for, or None to end the session.
#[generated(model = ClaudeOpus, version = "5")]
async fn on_hello(session: &Session, hello: Hello) -> Option<String> {
    // The certificate said who dialled; the hello says which node it claims
    // to be. One node's key must not let it be told about another node's VMs.
    if let Err(e) =
        controller_api::grpc::check_session_identity(&session.who, "node", &hello.node_id)
    {
        // Error, not warn: an agent whose certificate does not match the
        // node it claims to be will redial with the same certificate for
        // ever. No pass and no reconnect repairs that; only a person
        // re-issuing it does.
        error!(node = %hello.node_id, error = format!("{e:#}"), "refusing the session");
        let _ = session.tx.send(Err(e)).await;
        return None;
    }
    info!(
        node = %hello.node_id,
        version = %hello.agent_version,
        drivers = hello.drivers.len(),
        "agent connected"
    );
    if let Err(e) = ingest_hello(&session.store, &hello).await {
        warn!(node = %hello.node_id, error = format!("{e:#}"), "recording the node failed");
    }
    // Snapshot first, registry second. The reconciler dispatches through the
    // registry, so a node that is not in it yet cannot be sent a command —
    // which is what keeps a Create issued right now from arriving ahead of a
    // snapshot taken a moment ago and being reaped by it as a VM the
    // controller never named.
    if !send_desired_state(&session.store, &session.tx, &hello.node_id).await {
        return None;
    }
    session.registry.register(&hello.node_id, &session.tx);
    Some(hello.node_id)
}

/// The reconnect sweep: one message that says everything this node should be
/// running. False means the stream is gone.
#[generated(model = ClaudeOpus, version = "5")]
async fn send_desired_state(store: &EtcdStore, tx: &CommandTx, node_id: &str) -> bool {
    let desired = match desired_snapshot(store, node_id).await {
        Ok(desired) => desired,
        // Skipped, never truncated: see desired_snapshot. The session goes
        // on — the periodic reconcile pass is what heals a missed sweep.
        Err(e) => {
            warn!(node = %node_id, error = format!("{e:#}"),
                  "could not build the desired state, none sent");
            return true;
        }
    };
    info!(node = %node_id, vms = desired.len(), "sending desired state");
    let msg = ControllerMessage {
        kind: Some(proto::controller_message::Kind::Sync(proto::SyncState {
            desired,
        })),
    };
    if tx.send(Ok(msg)).await.is_err() {
        warn!(node = %node_id, "session closed before the desired state went out");
        return false;
    }
    true
}

/// The stream is over. Whether that means the node is down is a question
/// about the registry, not about this stream.
#[generated(model = ClaudeOpus, version = "5")]
async fn on_disconnect(session: &Session, node_id: &str) {
    // A reconnect that already replaced us keeps its own session and its own
    // readiness; only a real disconnect reports down. `same_channel` is what
    // decides that, so this session's own handle is the right one to ask
    // with — it is a clone of the one a Hello registered.
    if !session.registry.disconnect(node_id, &session.tx) {
        // A decision not taken: the node stays ready because a newer session
        // speaks for it. The cloud tier's twin says the same thing at the
        // same level.
        debug!(node = %node_id, "stale session closed, a newer one is live");
        return;
    }
    info!(node = %node_id, "agent disconnected");
    let result = session
        .store
        .mutate::<Node, _>(node_id, |n| n.status.ready = false)
        .await;
    if let Err(e) = result {
        warn!(node = %node_id, error = format!("{e:#}"), "marking the node not ready failed");
    }
}

#[cfg(test)]
#[generated(model = ClaudeOpus, version = "5")]
mod tests {
    use super::*;

    use std::sync::atomic::{AtomicUsize, Ordering};

    fn vm(uid: &str) -> Vm {
        let mut vm = controller_api::resources::new_vm(
            uid,
            controller_api::VmSpec {
                node_name: None,
                cluster_name: None,
                run_strategy: Default::default(),
                tenant: None,
                vm: serde_json::json!({}),
            },
        );
        vm.metadata.uid = uid.to_string();
        vm
    }

    fn line(uid: &str) -> proto::VmStatusReport {
        proto::VmStatusReport {
            id: uid.into(),
            phase: "Running".into(),
            message: String::new(),
        }
    }

    /// The N+1 this exists to stop: every agent reports every ten seconds and
    /// every report needs the same list, so the reports that overlap share
    /// one read of it — and a read older than the window is not reused.
    #[tokio::test(start_paused = true)]
    async fn the_vm_list_is_read_once_for_the_reports_that_overlap() {
        let index = VmIndex::default();
        let reads = AtomicUsize::new(0);
        let fetch = || async {
            reads.fetch_add(1, Ordering::SeqCst);
            Ok(vec![vm("uid-a")])
        };

        let (first, fresh) = index.list(fetch).await.unwrap();
        assert!(fresh, "nothing to reuse yet");
        assert_eq!(reads.load(Ordering::SeqCst), 1);

        let (second, fresh) = index.list(fetch).await.unwrap();
        assert!(!fresh, "and the caller is told it is a reused list");
        assert_eq!(reads.load(Ordering::SeqCst), 1, "fifty agents, one read");
        assert_eq!(first[0].metadata.uid, second[0].metadata.uid);

        // ... and the window is far shorter than the ten seconds between two
        // reports of the same agent, so nobody's next report reads a stale one
        tokio::time::advance(VM_INDEX_TTL).await;
        assert!(index.list(fetch).await.unwrap().1);
        assert_eq!(reads.load(Ordering::SeqCst), 2);

        // an unknown uid forces a read whatever the clock says
        index.refresh(fetch).await.unwrap();
        assert_eq!(reads.load(Ordering::SeqCst), 3);
    }

    /// The one thing a reused list can get wrong is what it does not contain,
    /// and dropping such a report is exactly what this tier does with an
    /// unknown uid — so an unknown uid, and only that, buys a re-read.
    #[test]
    fn an_uid_the_list_cannot_name_is_what_makes_it_worth_re_reading() {
        let known = [vm("uid-a"), vm("uid-b")];
        assert!(all_known(&known, &[line("uid-a"), line("uid-b")]));
        assert!(all_known(&known, &[]));
        // the VM created since the list was read
        assert!(!all_known(&known, &[line("uid-a"), line("uid-new")]));
        assert!(!all_known(&[], &[line("uid-a")]));
    }

    /// Fund 5, checked and refuted: a second Hello for a node that already
    /// has a session replaces its registry entry rather than being dropped,
    /// and the older stream unwinding afterwards does not take the newer
    /// entry with it. Both halves are the reconnect the agent actually does.
    #[test]
    fn a_second_hello_replaces_the_entry_and_the_older_session_cannot_undo_it() {
        let registry = SessionRegistry::new();
        let (first, _first_rx) = mpsc::channel(1);
        let (second, _second_rx) = mpsc::channel(1);

        registry.register("node-a", &first);
        registry.register("node-a", &second);
        assert_eq!(registry.connected().len(), 1, "one node, not two entries");
        assert!(
            registry.nodes.lock().unwrap()["node-a"].same_channel(&second),
            "the newer session is the one commands go to"
        );

        // the old stream unwinds afterwards: it must not disconnect the node
        assert!(!registry.disconnect("node-a", &first));
        assert!(registry.connected().contains("node-a"));
        // and the session that IS current still reports the node down
        assert!(registry.disconnect("node-a", &second));
        assert!(registry.connected().is_empty());
    }

    #[test]
    fn catalogue_flattens_to_driver_slash_profile() {
        let drivers = vec![
            DriverInfo {
                name: "nvrm".into(),
                profiles: vec!["2q".into(), "8q".into()],
            },
            DriverInfo {
                name: "vfio".into(),
                profiles: vec![],
            },
        ];
        assert_eq!(
            capacity_profiles(&drivers),
            vec!["nvrm/2q".to_string(), "nvrm/8q".into(), "vfio".into()]
        );
        assert!(capacity_profiles(&[]).is_empty());
    }

    /// The two halves of the sentence, in one test: what this node writes
    /// into its capacity is what a scheduler asking for the same driver and
    /// profile finds. Both sides call `common::capability` now, and this is
    /// the seam where that stops being a claim about the code and starts
    /// being a claim about the system.
    #[test]
    fn what_a_node_claims_is_what_the_scheduler_finds() {
        let drivers = vec![
            DriverInfo {
                name: "nvrm".into(),
                profiles: vec!["2q".into(), "4q".into()],
            },
            DriverInfo {
                name: "crosvm-gpu".into(),
                profiles: vec!["venus".into()],
            },
            DriverInfo {
                name: "vfio".into(),
                profiles: vec![],
            },
        ];
        let catalogue = capacity_profiles(&drivers);
        for d in &drivers {
            // a bare request finds the driver, profiles or not
            assert!(
                capability::offers(&catalogue, &d.name, None),
                "bare {}",
                d.name
            );
            for p in &d.profiles {
                assert!(
                    capability::offers(&catalogue, &d.name, Some(p)),
                    "{}/{p}",
                    d.name
                );
            }
        }
        // and nothing this node did not claim
        assert!(!capability::offers(&catalogue, "nvrm", Some("8q")));
        assert!(!capability::offers(&catalogue, "lvm-thin", None));
    }
}
