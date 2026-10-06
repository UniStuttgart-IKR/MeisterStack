// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Outbound cloud session carrying cluster status and assigned resource intent.
//! HRW over the cluster name ranks configured cloud endpoints; failover follows
//! that order and periodic probes restore a preferred endpoint. Commands receive
//! results, with status sent periodically and after command batches.
//! Without cloud endpoints the cluster operates standalone.

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, anyhow, bail};
use chrono::Utc;
use controller_api::{
    EtcdStore, Node, ProviderNetwork, Router, StoreError, Vm, VmSpec, Volume, deletion, events,
    resources::{new_vm, new_volume},
};
use proto::cluster_plane_client::ClusterPlaneClient;
use proto::{
    ClusterCapacity, ClusterHello, ClusterMessage, ClusterStatus, CommandResult, ControllerMessage,
    VmStatusReport, cloud_command, cloud_message, cluster_message,
};
use tokio::sync::mpsc;
use tokio_stream::{Stream, StreamExt, wrappers::ReceiverStream};
use tracing::{debug, error, info, instrument, warn};

use crate::dispatch::{Dispatch, NodeCommand};
use crate::logs::{self, Logs};
use crate::session::SessionRegistry;

/// How often the cluster reports even when nothing happened. Doubles as the
/// heartbeat: the cloud expires a cluster after 30s without one, so this has
/// to stay comfortably below that.
const STATUS_INTERVAL: Duration = Duration::from_secs(10);

/// Probe for a better-ranked cloud endpoint while connected elsewhere.
/// Cluster replicas hash the same name and must converge on one cloud replica;
/// otherwise several cloud replicas can reconcile the cluster concurrently.
/// Leave a healthy session only after a better endpoint answers.
const REHOME_INTERVAL: Duration = Duration::from_secs(30);

/// How many commands one wake-up of the inbound branch may execute before the
/// status goes out. The cap is not about the store — it is about the other two
/// branches of the select: a cloud that never stops sending would otherwise
/// keep the inbound branch ready for ever, and the heartbeat and the re-home
/// probe would never be reached. Generous enough that an ordinary burst is one
/// batch, small enough that a saturated stream still yields.
const MAX_BATCH: usize = 32;

/// A probe is one connect and nothing else — the session it would open is
/// opened by the loop. Bounded because a fenced host does not refuse, it says
/// nothing at all, and this runs on the task that also has to keep the
/// heartbeat going.
const PROBE_TIMEOUT: Duration = Duration::from_secs(1);

/// How a session ended, which is what decides where the next one is dialled.
enum Ended {
    /// The stream is gone. Down the order, like the agent.
    Stream,
    /// A better-ranked replica answered: back to the top of the order, which
    /// is where the rest of this cluster's replicas are.
    Rehome,
}

/// The best-ranked endpoint ahead of us that answers, if any. In order, so a
/// cluster that drifted two positions comes back to the first one that is
/// there rather than to the first one it happens to try.
async fn better_endpoint(
    ahead: &[String],
    tls: &Option<tonic::transport::ClientTlsConfig>,
) -> Option<String> {
    for addr in ahead {
        if let Ok(Ok(_)) =
            tokio::time::timeout(PROBE_TIMEOUT, proto::dial_tls(addr, tls.as_ref())).await
        {
            return Some(addr.clone());
        }
    }
    None
}

/// `registry` is this cluster's own agent sessions. The cloud can ask for a
/// VM's console and the only party that has one is the node, so the answer to
/// a command arriving on THIS session is fetched over one of those.
///
/// `fanout` is the same `Dispatch` the migration and router reconcilers use,
/// threaded in here for one command: `DropImage` reaches every node in the
/// cluster, which on a multi-replica cluster-controller can mean nodes whose
/// session this replica does not hold. See `dispatch::NodeCommand::DropImage`.
#[allow(clippy::too_many_arguments)]
pub async fn run(
    store: Arc<EtcdStore>,
    registry: Arc<SessionRegistry>,
    forward: Arc<logs::Forward>,
    fanout: Arc<Dispatch>,
    cloud_addrs: Vec<String>,
    cluster_name: String,
    tls: Option<tonic::transport::ClientTlsConfig>,
) {
    // Hashed from this cluster's own name, so three clusters spread over three
    // cloud replicas without anybody agreeing on anything, and this cluster
    // comes back to the same favourite after every restart. The schedule is
    // `common::redial`, the same one the agents run one tier down.
    let mut redial = common::redial::Redial::new(&cluster_name, &cloud_addrs);

    loop {
        let addr = redial.endpoint().to_string();
        let (position, of) = redial.position();
        // Debug: an attempt is not a transition, and during an outage this
        // fires on every rotation. The transitions below are the INFO lines.
        debug!(endpoint = %addr, position, endpoints = of, "dialling the cloud");
        let mut established = false;
        let outcome = session(
            &store,
            &registry,
            &forward,
            &fanout,
            &addr,
            &cluster_name,
            redial.ahead(),
            &tls,
            &mut established,
        )
        .await;
        match outcome {
            // A rehome is not a failure: the session is being given up FOR a
            // better-ranked replica, so it neither advances nor waits.
            Ok(Ended::Rehome) => {
                redial.rehome();
                continue;
            }
            Ok(Ended::Stream) => info!(endpoint = %addr, "cloud session ended"),
            Err(e) => warn!(endpoint = %addr, error = format!("{e:#}"), "cloud session failed"),
        }
        // Whatever ended it, every console that was travelling through it is
        // over: the client at the far end went with the session. Told to the
        // nodes rather than left to time out, so a line is not held for
        // somebody who can no longer be reached.
        for (session_id, node) in registry.consoles.cloud_gone() {
            let _ = registry
                .send_to(
                    &node,
                    ControllerMessage {
                        kind: Some(proto::controller_message::Kind::ConsoleClose(
                            proto::ConsoleClose {
                                session_id,
                                reason: "the cloud session ended".to_string(),
                            },
                        )),
                    },
                )
                .await;
        }
        if let Some(wait) = redial.ended(established) {
            warn!(?wait, endpoints = of, "no cloud replica answered, waiting");
            tokio::time::sleep(wait).await;
        }
    }
}

#[instrument(skip_all, fields(endpoint = %cloud_addr, cluster = %cluster_name))]
#[allow(clippy::too_many_arguments)]
async fn session(
    store: &Arc<EtcdStore>,
    registry: &SessionRegistry,
    forward: &logs::Forward,
    fanout: &Dispatch,
    cloud_addr: &str,
    cluster_name: &str,
    ahead: &[String],
    tls: &Option<tonic::transport::ClientTlsConfig>,
    established: &mut bool,
) -> anyhow::Result<Ended> {
    let channel = proto::dial_tls(cloud_addr, tls.as_ref())
        .await
        .context("connecting to the cloud")?;
    let mut client = ClusterPlaneClient::new(channel);
    let (tx, rx) = mpsc::channel::<ClusterMessage>(64);
    // Where "up" is, for the console frames that arrive in the OTHER session
    // task. Registered before Hello, so a node that somehow answers early
    // still finds somewhere to send it.
    registry.consoles.cloud_connected(tx.clone());
    tx.send(ClusterMessage {
        kind: Some(cluster_message::Kind::Hello(ClusterHello {
            cluster_name: cluster_name.to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
        })),
    })
    .await
    .map_err(|_| anyhow!("session closed before hello"))?;

    let mut inbound = client.session(ReceiverStream::new(rx)).await?.into_inner();
    // This endpoint has answered; whatever ends the session, it is not
    // "nobody is there".
    *established = true;
    info!("cloud session established");

    // Build status and execute commands in one task. A status sent after a command
    // must be built after it, since the cloud uses ACK/status arrival order when
    // interpreting absence. A blocked command also delays heartbeats.
    let mut tick = tokio::time::interval(STATUS_INTERVAL);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    // Not from now: a session that has just been opened has just failed to
    // reach everything ahead of it, so the first probe worth making is one
    // interval away.
    let mut rehome = tokio::time::interval_at(
        tokio::time::Instant::now() + REHOME_INTERVAL,
        REHOME_INTERVAL,
    );
    loop {
        tokio::select! {
            incoming = inbound.next() => {
                let Some(msg) = incoming else { return Ok(Ended::Stream) };
                let msg = match msg {
                    Ok(m) => m,
                    Err(e) => {
                        warn!(error = format!("{e:#}"), "session stream error");
                        return Ok(Ended::Stream);
                    }
                };
                // Everything the cloud has ALREADY put on the wire is taken
                // in one go. A burst of n commands then costs n acks and ONE
                // status build instead of n of them, and the guarantee that
                // buys the status its meaning is untouched: it is still built
                // after the LAST command of the batch, and therefore after
                // every command in it.
                let mut batch = vec![msg];
                let ended = drain_ready(&mut inbound, &mut batch, MAX_BATCH).await;
                // Console frames leave the batch first and are answered by a
                // node rather than by this tier: they carry no request_id,
                // nothing acks them, and a keystroke that queued behind a
                // CreateVm would arrive after the next keystroke.
                let batch = relay_consoles(batch, store, registry).await;
                let mut acted = false;
                for cmd in commands(batch) {
                    let result = dispatch(store, registry, forward, fanout, cmd).await;
                    if tx
                        .send(ClusterMessage { kind: Some(cluster_message::Kind::Result(result)) })
                        .await
                        .is_err()
                    {
                        return Ok(Ended::Stream);
                    }
                    acted = true;
                }
                // The commands just changed what this cluster looks like; say
                // so instead of letting the cloud wait out the tick.
                if acted && !send_status(store, registry, &tx).await {
                    return Ok(Ended::Stream);
                }
                if ended {
                    return Ok(Ended::Stream);
                }
            }
            _ = tick.tick() => {
                if !send_status(store, registry, &tx).await {
                    return Ok(Ended::Stream);
                }
            }
            // Only when there is something ahead of us to go back to, so a
            // cluster sitting on its favourite never probes at all.
            _ = rehome.tick(), if !ahead.is_empty() => {
                if let Some(better) = better_endpoint(ahead, tls).await {
                    info!(preferred = %better, "a preferred cloud replica answered, re-homing");
                    return Ok(Ended::Rehome);
                }
            }
        }
    }
}

/// Everything the cloud has already put on the wire, without waiting for one
/// byte more: the stream is polled until it says Pending, the batch is full,
/// or it ends. Returns whether the stream is over.
///
/// This is the whole of the coalescing. It never waits, so it cannot delay a
/// command that has not arrived yet, and it cannot reorder one — what comes
/// out is arrival order.
async fn drain_ready<S>(stream: &mut S, out: &mut Vec<proto::CloudMessage>, cap: usize) -> bool
where
    S: Stream<Item = Result<proto::CloudMessage, tonic::Status>> + Unpin,
{
    while out.len() < cap {
        // Ready(…) unconditionally: this polls the stream once and hands the
        // answer back rather than suspending on it.
        let polled = std::future::poll_fn(|cx| {
            std::task::Poll::Ready(std::pin::Pin::new(&mut *stream).poll_next(cx))
        })
        .await;
        match polled {
            std::task::Poll::Pending => return false,
            std::task::Poll::Ready(None) => return true,
            std::task::Poll::Ready(Some(Ok(msg))) => out.push(msg),
            std::task::Poll::Ready(Some(Err(e))) => {
                warn!(error = format!("{e:#}"), "session stream error");
                return true;
            }
        }
    }
    false
}

/// Relay console frames and return non-console messages for command handling.
/// Open resolves a VM into a node route; input and close follow that session ID.
/// Console bytes remain opaque to this tier.
async fn relay_consoles(
    batch: Vec<proto::CloudMessage>,
    store: &EtcdStore,
    registry: &SessionRegistry,
) -> Vec<proto::CloudMessage> {
    let mut rest = Vec::with_capacity(batch.len());
    for msg in batch {
        match msg.kind {
            Some(cloud_message::Kind::ConsoleOpen(open)) => {
                console_open(store, registry, open).await;
            }
            Some(cloud_message::Kind::ConsoleInput(data)) => {
                console_input(registry, data).await;
            }
            Some(cloud_message::Kind::ConsoleClose(close)) => {
                console_close(registry, close).await;
            }
            other => rest.push(proto::CloudMessage { kind: other }),
        }
    }
    rest
}

/// One frame of a client's typing, carried to wherever its session lives.
///
/// A session this replica is forwarding goes out through that socket; one it
/// serves itself goes down to the node. Exactly one of the two is true,
/// decided when the session opened — so the first answer ends this frame.
async fn console_input(registry: &SessionRegistry, data: proto::ConsoleData) {
    if let Some(ok) = registry
        .consoles
        .write_forward(&data.session_id, &data.data)
        .await
    {
        if !ok {
            end_console(registry, &data.session_id, "the forwarded console ended").await;
        }
        return;
    }
    let Some(node) = registry.consoles.node_for(&data.session_id) else {
        return;
    };
    let sent = registry
        .send_to(
            &node,
            ControllerMessage {
                kind: Some(proto::controller_message::Kind::ConsoleInput(data.clone())),
            },
        )
        .await;
    if !sent {
        end_console(registry, &data.session_id, "the node's session ended").await;
    }
}

/// The client hung up: forget the route and tell the node that served it.
///
/// A session with no route is one nothing was ever opened for, or one already
/// ended — either way there is nobody left to tell.
async fn console_close(registry: &SessionRegistry, close: proto::ConsoleClose) {
    let Some(node) = registry.consoles.forget(&close.session_id) else {
        return;
    };
    let _ = registry
        .send_to(
            &node,
            ControllerMessage {
                kind: Some(proto::controller_message::Kind::ConsoleClose(close)),
            },
        )
        .await;
}

/// Find the node this VM is on and ask it for the line.
///
/// A VM this cluster does not have, or one not placed yet, is refused HERE
/// rather than forwarded to nobody — the client is waiting for exactly one
/// answer, and "no such vm" is a better one than silence.
async fn console_open(store: &EtcdStore, registry: &SessionRegistry, open: proto::ConsoleOpen) {
    let session_id = open.session_id.clone();
    let refuse = |error: String| {
        let session_id = session_id.clone();
        async move {
            let _ = registry
                .consoles
                .upward(ClusterMessage {
                    kind: Some(cluster_message::Kind::ConsoleOpened(proto::ConsoleOpened {
                        session_id,
                        error,
                    })),
                })
                .await;
        }
    };

    let vm: Vm = match store.get(&open.vm_id).await {
        Ok(vm) => vm,
        Err(e) => return refuse(format!("{e}")).await,
    };
    let Some(node) = vm.spec.node_name.clone() else {
        return refuse(format!(
            "vm {} is not placed on a node yet, so there is no console to hold",
            open.vm_id
        ))
        .await;
    };

    // This replica may not be the one holding that node — a node dials ONE
    // replica and only that one can ask it anything, which is the same fact
    // `vm logs` meets and forwards around. The difference is that a console
    // is a stream, so what travels is not one request but every frame of the
    // session, both ways.
    if !registry.connected().contains(&node) {
        let endpoint = match store.get::<Node>(&node).await {
            Ok(n) => n.status.session_endpoint,
            Err(e) => return refuse(format!("{e}")).await,
        };
        let Some(endpoint) = endpoint.filter(|e| !e.is_empty()) else {
            return refuse(format!(
                "no replica of this cluster is holding node {node}'s session, or the one \
                 that is could not name its own address (set advertise_api in its config)"
            ))
            .await;
        };
        return forward_console(registry, &endpoint, &vm.metadata.name, open).await;
    }

    // The route BEFORE the ask, so that a node answering faster than this
    // function returns still finds somewhere to send its answer.
    registry.consoles.route(&open.session_id, &node);
    let asked = registry
        .send_to(
            &node,
            ControllerMessage {
                kind: Some(proto::controller_message::Kind::ConsoleOpen(
                    proto::ConsoleOpen {
                        session_id: open.session_id.clone(),
                        // The uid: the node has never heard of the name.
                        vm_id: vm.metadata.uid.clone(),
                    },
                )),
            },
        )
        .await;
    if !asked {
        registry.consoles.forget(&open.session_id);
        refuse(format!("node {node} has no active session")).await;
    }
}

/// Proxy a console through the sibling holding the node session.
/// The sibling REST route refuses nodes it does not hold, bounding this path to
/// one hop. This helper currently uses plaintext HTTP without sibling credentials.
async fn forward_console(
    registry: &SessionRegistry,
    endpoint: &str,
    vm_name: &str,
    open: proto::ConsoleOpen,
) {
    let session_id = open.session_id.clone();
    let refuse = |error: String| {
        let session_id = session_id.clone();
        async move {
            let _ = registry
                .consoles
                .upward(ClusterMessage {
                    kind: Some(cluster_message::Kind::ConsoleOpened(proto::ConsoleOpened {
                        session_id,
                        error,
                    })),
                })
                .await;
        }
    };

    let authority = endpoint
        .strip_prefix("http://")
        .or_else(|| endpoint.strip_prefix("https://"))
        .unwrap_or(endpoint)
        .trim_end_matches('/')
        .to_string();
    let stream =
        match tokio::time::timeout(FORWARD_TIMEOUT, tokio::net::TcpStream::connect(&authority))
            .await
        {
            Ok(Ok(stream)) => stream,
            Ok(Err(e)) => return refuse(format!("the replica at {authority}: {e}")).await,
            Err(_) => {
                return refuse(format!(
                    "the replica at {authority} did not answer within {}s",
                    FORWARD_TIMEOUT.as_secs()
                ))
                .await;
            }
        };
    let _ = stream.set_nodelay(true);

    match console_upgrade(stream, &authority, vm_name).await {
        Ok(stream) => {
            let _ = registry
                .consoles
                .upward(ClusterMessage {
                    kind: Some(cluster_message::Kind::ConsoleOpened(proto::ConsoleOpened {
                        session_id: session_id.clone(),
                        error: String::new(),
                    })),
                })
                .await;
            registry.consoles.forwarded(&session_id, stream).await;
        }
        Err(e) => refuse(format!("{e:#}")).await,
    }
}

/// How long a forward waits on a sibling — the same budget `vm logs` uses,
/// and for the same reason: a blackholed replica costs the SYN retry budget.
const FORWARD_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// Ask a sibling's console route and keep the socket.
async fn console_upgrade(
    mut stream: tokio::net::TcpStream,
    authority: &str,
    vm_name: &str,
) -> anyhow::Result<tokio::net::TcpStream> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let request = format!(
        "GET /apis/meister.io/v1/vms/{vm_name}/console HTTP/1.1\r\nHost: {authority}\r\n\
         Connection: upgrade\r\nUpgrade: meister-console\r\n\r\n"
    );
    stream.write_all(request.as_bytes()).await?;
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        if stream.read(&mut byte).await? == 0 {
            anyhow::bail!("the replica closed the connection without answering");
        }
        head.push(byte[0]);
        anyhow::ensure!(head.len() < 16 * 1024, "the replica sent an oversized head");
    }
    let text = String::from_utf8_lossy(&head);
    let status = text
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .unwrap_or("?");
    if status != "101" {
        // The sibling's own sentence, for the same reason the tier above
        // reads one: "somebody else is holding this console" is an answer,
        // and "a replica answered 409" is not.
        let said = read_refusal(&mut stream, &text).await;
        anyhow::bail!(
            "{}",
            said.unwrap_or_else(|| format!(
                "the replica at {authority} answered {status} to a console open"
            ))
        );
    }
    Ok(stream)
}

/// The sentence behind a sibling's refusal, out of its `Status` body.
async fn read_refusal(stream: &mut tokio::net::TcpStream, head: &str) -> Option<String> {
    use tokio::io::AsyncReadExt;
    let length: usize = head.lines().find_map(|line| {
        let (name, value) = line.split_once(':')?;
        name.eq_ignore_ascii_case("content-length")
            .then(|| value.trim().parse().ok())?
    })?;
    let mut body = vec![0u8; length.min(64 * 1024)];
    stream.read_exact(&mut body).await.ok()?;
    #[derive(serde::Deserialize)]
    struct Status {
        message: String,
    }
    serde_json::from_slice::<Status>(&body)
        .ok()
        .map(|s| s.message)
        .filter(|m| !m.is_empty())
}

/// Say upwards that a console session is over, and forget it here.
async fn end_console(registry: &SessionRegistry, session_id: &str, reason: &str) {
    registry.consoles.forget(session_id);
    let _ = registry
        .consoles
        .upward(ClusterMessage {
            kind: Some(cluster_message::Kind::ConsoleClose(proto::ConsoleClose {
                session_id: session_id.to_string(),
                reason: reason.to_string(),
            })),
        })
        .await;
}

fn commands(batch: Vec<proto::CloudMessage>) -> Vec<proto::CloudCommand> {
    batch
        .into_iter()
        .filter_map(|msg| match msg.kind {
            Some(cloud_message::Kind::Command(cmd)) => Some(cmd),
            _ => None,
        })
        .collect()
}

/// The cloud's context, if it sent one; its own root if not. Recorded on the
/// span so the fmt log carries it either way, and attached as the real parent
/// before the span starts (`telemetry::in_trace`).
async fn dispatch(
    store: &EtcdStore,
    registry: &SessionRegistry,
    forward: &logs::Forward,
    fanout: &Dispatch,
    cmd: proto::CloudCommand,
) -> CommandResult {
    let context = telemetry::TraceParent::parse(&cmd.traceparent)
        .unwrap_or_else(telemetry::TraceParent::root);
    let span = tracing::info_span!(
        "dispatch",
        request_id = %cmd.request_id,
        trace_id = %context.trace_id_hex()
    );
    telemetry::in_trace(
        span,
        &context,
        dispatch_traced(store, registry, forward, fanout, cmd, context),
    )
    .await
}

async fn dispatch_traced(
    store: &EtcdStore,
    registry: &SessionRegistry,
    forward: &logs::Forward,
    fanout: &Dispatch,
    cmd: proto::CloudCommand,
    context: telemetry::TraceParent,
) -> CommandResult {
    let request_id = cmd.request_id.clone();
    // What this tier stamps onto its own object, so the cluster's reconciler
    // finds its way back to the same trace.
    let traceparent = telemetry::outgoing(&context).to_string();
    // Same shape as one tier down: the arms that CHANGE something answer
    // "done" with an empty payload, and the one that asks a question answers
    // with the node's own document, passed through unopened.
    let done = |r: anyhow::Result<()>| r.map(|()| Vec::new());
    let outcome = match cmd.op {
        Some(cloud_command::Op::Create(c)) => done(handle_create(store, c, &traceparent).await),
        Some(cloud_command::Op::Destroy(d)) => done(handle_destroy(store, d).await),
        Some(cloud_command::Op::Logs(l)) => {
            handle_logs(store, registry, forward, l, &traceparent).await
        }
        Some(cloud_command::Op::UpdateNode(u)) => done(handle_update_node(store, u).await),
        Some(cloud_command::Op::CreateVmMigration(m)) => {
            done(handle_create_vm_migration(store, m).await)
        }
        Some(cloud_command::Op::CreateVolume(v)) => done(handle_create_volume(store, v).await),
        Some(cloud_command::Op::DestroyVolume(v)) => done(handle_destroy_volume(store, v).await),
        Some(cloud_command::Op::ReleaseVolume(v)) => done(handle_release_volume(store, v).await),
        Some(cloud_command::Op::CreateSnapshot(s)) => done(handle_create_snapshot(store, s).await),
        Some(cloud_command::Op::DestroySnapshot(s)) => {
            done(handle_destroy_snapshot(store, s).await)
        }
        Some(cloud_command::Op::CreateSecret(c)) => done(handle_create_secret(store, c).await),
        Some(cloud_command::Op::DeleteSecret(d)) => done(handle_delete_secret(store, d).await),
        Some(cloud_command::Op::CreateRouter(r)) => done(handle_create_router(store, r).await),
        Some(cloud_command::Op::DeleteRouter(r)) => done(handle_delete_router(store, r).await),
        Some(cloud_command::Op::DropImage(d)) => done(handle_drop_image(store, fanout, d).await),
        None => Err(anyhow!("command without op")),
    };
    let outcome = match outcome {
        Ok(payload) => {
            info!("command ok");
            proto::command_result::Outcome::Ok(proto::Ack { payload })
        }
        Err(e) => {
            // Warn, not error: the failure travels back to the cloud in the
            // CommandResult below, and the cloud owns the retry. Nothing here
            // is an operator's to fix.
            warn!(error = format!("{e:#}"), "command failed");
            proto::command_result::Outcome::Error(proto::ErrorMsg {
                message: format!("{e:#}"),
                // The handler's own word, where it had one. Without this the
                // cloud calls every failure a conflict — including "I could
                // not reach the node", which is the one a caller should
                // simply try again.
                reason: controller_api::Refused::reason_of(&e).to_string(),
            })
        }
    };
    CommandResult {
        request_id,
        outcome: Some(outcome),
    }
}

/// Inject cloud-resolved VNI and source-address allowlists before storing the VM.
/// VNI affects overlay placement; address lists configure tap enforcement.
/// Injectors preserve explicit NIC fields for standalone use, so the cloud API
/// must reject client-owned values at its tenant boundary.
fn bind_nics(c: &proto::CreateVm, vm_spec: &mut serde_json::Value) {
    if let Some(vni) = c.vni {
        let touched = controller_api::vni::inject_vxlan_id(vm_spec, vni);
        if touched > 0 {
            info!(vm = %c.name, vni, nics = touched, "bound nics to the tenant overlay");
        }
    }
    for (field, values) in [
        (controller_api::floating::NIC_FLOATING_IPS, &c.floating_ips),
        (
            controller_api::floating::NIC_ROUTED_SUBNETS,
            &c.routed_subnets,
        ),
    ] {
        let touched = controller_api::floating::inject_nic_list(vm_spec, field, values);
        if touched > 0 {
            info!(vm = %c.name, field, values = ?values, nics = touched,
                  "bound nics to the addresses this vm may use");
        }
    }
}

/// Fetch guest logs only when the cloud UID owns the named cluster VM.
/// Names alone are reusable and could expose a cluster-local guest's logs.
/// A missing or unplaced VM returns an empty log document.
async fn handle_logs(
    store: &EtcdStore,
    registry: &SessionRegistry,
    forward: &logs::Forward,
    cmd: proto::FetchVmLogs,
    traceparent: &str,
) -> anyhow::Result<Vec<u8>> {
    let vm: Vm = match store.get(&cmd.name).await {
        Ok(vm) => vm,
        Err(StoreError::NotFound(_)) => return Ok(logs::NO_STREAMS.to_vec()),
        Err(e) => return Err(e.into()),
    };
    if vm.metadata.cloud_uid() != Some(cmd.uid.as_str()) {
        debug!(vm = %cmd.name, "the local vm of that name is not the cloud's, no console");
        return Ok(logs::NO_STREAMS.to_vec());
    }
    // From the cloud, so never a forward: this is the first hop, and the
    // replica the cloud is talking to may not be the one holding the node.
    // Every error `fetch` gives is about REACHING the console and never about
    // the VM — its own contract says so in as many words. Crossing the session
    // it has to keep that, or the cloud turns "nobody could be reached" into
    // "two truths disagree" and answers 409 to something a caller should
    // simply ask again.
    let keep = logs::Keep {
        hide: cmd.hide.clone(),
        only: cmd.only.clone(),
        streams: cmd.streams.clone(),
    };
    match logs::fetch(
        registry,
        store,
        forward,
        &vm,
        cmd.lines,
        &keep,
        traceparent,
        false,
    )
    .await
    .map_err(|e| controller_api::Refused::unavailable(format!("{e:#}")))?
    {
        Logs::From(payload) => Ok(payload),
        Logs::NotYet(_) => Ok(logs::NO_STREAMS.to_vec()),
    }
}

async fn handle_create(
    store: &EtcdStore,
    c: proto::CreateVm,
    traceparent: &str,
) -> anyhow::Result<()> {
    if c.uid.is_empty() {
        bail!("create without a cloud uid");
    }
    let mut spec: VmSpec = serde_json::from_str(&c.spec_json).context("invalid spec_json")?;
    if !spec.vm.is_object() {
        bail!("spec.vm must be the agent's NewVmSpec object");
    }
    // Every vm the cloud sends is a tenant's. The cloud refuses these fields
    // at its own edge; a cloud from before that rule must not get a tenant's
    // tap onto a provider network or a host bridge through this one.
    let own_wire = controller_api::vni::check_tenant_nics(&spec.vm)
        .err()
        .map(|e| e.message().to_string());

    // The truth is made at the edge. The cloud resolved the tenant's VNI and
    // sent it alongside; this is where it becomes part of the spec, before
    // the object is written and therefore before the scheduler reads it —
    // which matters, because `nics[].vxlan_id` is what says the VM needs a
    // node with an overlay. From here down nothing knows what a tenant is.
    bind_nics(&c, &mut spec.vm);

    if own_wire.is_none() {
        match store
            .create(&declared_for_cloud(&c, &spec, traceparent))
            .await
        {
            Ok(_) => {
                info!(vm = %c.name, "created for the cloud");
                return Ok(());
            }
            Err(StoreError::AlreadyExists(_)) => {}
            Err(e) => return Err(e.into()),
        }
    }

    let current: Vm = match (store.get(&c.name).await, own_wire.as_deref()) {
        (Ok(current), _) => current,
        // Nothing of the cloud's here yet: a new VM, and the rule holds.
        (Err(StoreError::NotFound(_)), Some(why)) => bail!("{why}"),
        (Err(e), _) => return Err(e.into()),
    };
    refuse_unless_ours(&current, &c)?;
    // Kept only by a VM that already hangs on exactly these wires: any other
    // is a new one, and refused like a new VM — whatever the shape rule says.
    if let Some(why) = &own_wire
        && controller_api::vni::own_wires(&current.spec.vm)
            != controller_api::vni::own_wires(&spec.vm)
    {
        bail!("{why}");
    }
    let shape_moved = shape_moved(&current, &spec, &c.name)?;
    // Said only of a re-send this tier takes: a refused one kept nothing.
    if let Some(why) = own_wire {
        note_own_wire_kept(store, &current, &why).await;
    }
    // `evacuation` drifts like `runStrategy` does and for the same reason:
    // both are the owner's INTENT, both are mutable at the cloud's edge, and
    // this session is the only way either reaches the tier that acts on it.
    let evacuation_moved = current.spec.evacuation != spec.evacuation;
    let placement_moved = placement_moved(&current, &spec, &c);
    if !shape_moved
        && !evacuation_moved
        && !placement_moved
        && current.spec.run_strategy == spec.run_strategy
    {
        return Ok(());
    }
    write_drift(store, &current, &c, &spec).await?;
    note_drift(
        &c.name,
        &spec,
        shape_moved,
        evacuation_moved,
        placement_moved,
    );
    Ok(())
}

/// A cloud VM stored before the tenant-NIC rule keeps its own wire: a re-send
/// manages it on (stop, start, drift), since the NIC set of a VM that exists
/// cannot change through this road (`shape_moved`), and refusing it would
/// leave a running VM nobody can stop from the cloud and a phase that flaps
/// between the refusal and the cluster's report. It is said, on the VM and in
/// the log, so an operator can recreate it. (IKR-B67)
async fn note_own_wire_kept(store: &EtcdStore, vm: &Vm, why: &str) {
    warn!(vm = %vm.metadata.name, why, "a tenant vm from before the nic rule keeps its own wire");
    events::record(
        store,
        crate::reconcile::warning(
            vm,
            events::reason::TENANT_WIRE_KEPT,
            format!(
                "stored before the rule and kept as it is; recreate it to drop the wire: {why}"
            ),
        ),
    )
    .await;
}

/// The cloud VM's own labels under this tier's ownership marks: what the
/// cluster's copy carries, so another cloud VM's `antiAffinity` term finds it
/// on its node. The marks are written last, over anything the cloud sent
/// under their keys. (IKR-B71)
fn label_for_cloud(metadata: &mut controller_api::Metadata, c: &proto::CreateVm) {
    metadata.labels = c
        .labels
        .iter()
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    metadata.mark_managed_by_cloud(&c.uid);
}

/// Whether the owner's words about where on this cluster the VM may run moved:
/// class, node selector, anti-affinity, or the labels other VMs' terms match.
/// They decide the next placement here, and the cloud is their owner.
fn placement_moved(current: &Vm, spec: &VmSpec, c: &proto::CreateVm) -> bool {
    let mut labelled = current.metadata.clone();
    label_for_cloud(&mut labelled, c);
    current.spec.class != spec.class
        || current.spec.node_selector != spec.node_selector
        || current.spec.anti_affinity != spec.anti_affinity
        || current.metadata.labels != labelled.labels
}

/// The cloud's create, as this tier's own object.
///
/// Both bindings are this tier's to make, and the cloud's is not ours to keep
/// a copy of. The cloud's trace comes down onto the object, so the cluster's
/// own reconciler — which will pick this VM up from its store later, out of
/// any call stack — lands in the same trace as the POST that started it.
fn declared_for_cloud(c: &proto::CreateVm, spec: &VmSpec, traceparent: &str) -> Vm {
    let mut vm = new_vm(
        &c.name,
        VmSpec {
            node_name: None,
            cluster_name: None,
            ..spec.clone()
        },
    );
    label_for_cloud(&mut vm.metadata, c);
    if !traceparent.is_empty() {
        vm.metadata.set_traceparent(traceparent);
    }
    vm
}

/// The name is taken, and whose it is decides everything.
///
/// A create is idempotent for the object it created itself — a lost ack, a
/// reconnect, a repeat after the cloud lost sight of it — and refused for
/// anything else: adopting on the name alone would hand this VM somebody
/// else's disk and report it as healthy.
fn refuse_unless_ours(current: &Vm, c: &proto::CreateVm) -> anyhow::Result<()> {
    if current.metadata.cloud_uid() != Some(c.uid.as_str()) {
        bail!(
            "the name {} is taken by {}",
            c.name,
            if current.metadata.managed_by_cloud() {
                "another cloud vm"
            } else {
                "a cluster-local vm"
            }
        );
    }
    if current.is_deleting() {
        bail!("vm {} is still being torn down", c.name);
    }
    Ok(())
}

/// Detect spec changes and allow only referenced-disk hot-plug after the boot
/// entry, using the same shape rule as both REST APIs. Reject other changes
/// rather than acknowledging a spec this tier did not store.
fn shape_moved(current: &Vm, spec: &VmSpec, name: &str) -> anyhow::Result<bool> {
    let moved = current.spec.vm != spec.vm;
    if moved && !controller_api::vm_shape_unchanged(&current.spec.vm, &spec.vm) {
        bail!(
            "vm {name} arrived with a spec.vm that is not the stored one plus appended volume \
             references; the shape of a vm is fixed once it exists"
        );
    }
    Ok(moved)
}

/// The fields that may drift, onto the object `refuse_unless_ours` judged and
/// no other: one recreated under the name since is not this command's.
/// (IKR-B81)
async fn write_drift(
    store: &EtcdStore,
    current: &Vm,
    c: &proto::CreateVm,
    spec: &VmSpec,
) -> anyhow::Result<()> {
    store
        .mutate_if::<Vm, _>(&c.name, &current.metadata.uid, |v| {
            v.spec.run_strategy = spec.run_strategy;
            v.spec.evacuation = spec.evacuation;
            v.spec.class = spec.class.clone();
            v.spec.node_selector = spec.node_selector.clone();
            v.spec.anti_affinity = spec.anti_affinity.clone();
            label_for_cloud(&mut v.metadata, c);
            if v.spec.vm != spec.vm {
                v.spec.vm = spec.vm.clone();
                // What `carry_generation` does at a REST edge, done by hand
                // because this path has no request to carry it from: a
                // different spec is a new generation, and
                // `status.observedGeneration` is how the plug is watched.
                v.metadata.generation += 1;
            }
        })
        .await?;
    Ok(())
}

/// Which of them it was, for the log. The order is the order the caller
/// decided in.
fn note_drift(
    name: &str,
    spec: &VmSpec,
    shape_moved: bool,
    evacuation_moved: bool,
    placement_moved: bool,
) {
    if shape_moved {
        info!(vm = %name, "spec.vm volumes updated from the cloud");
    } else if evacuation_moved {
        info!(vm = %name, evacuation = spec.evacuation.as_str(),
              "evacuation policy updated from the cloud");
    } else if placement_moved {
        info!(vm = %name, "placement constraints updated from the cloud");
    } else {
        info!(vm = %name, strategy = ?spec.run_strategy, "run strategy updated from the cloud");
    }
}

/// Mirror a cloud-owned secret, preserving its sealed values.
/// Both tiers share the KEK, so this handler needs no decryption key; dispatch
/// needs it when resolving cloud-init. Repeated creates update mutable secret
/// data while retaining cloud ownership checks.
async fn handle_create_secret(store: &EtcdStore, c: proto::CreateSecret) -> anyhow::Result<()> {
    if c.uid.is_empty() {
        bail!("create without a cloud uid");
    }
    let mut spec: controller_api::SecretSpec =
        serde_json::from_str(&c.spec_json).context("invalid spec_json")?;
    spec.tenant = c.tenant.clone();
    let mut secret = controller_api::Secret::declare(&c.name, spec);
    secret.metadata.mark_managed_by_cloud(&c.uid);
    // Which version of the cloud's object this copy is. Reported back in the
    // status, and that is what lets the cloud stop re-sending it every pass.
    secret.metadata.annotations.insert(
        controller_api::ANNOTATION_CLOUD_GENERATION.to_string(),
        c.generation.to_string(),
    );
    match store.create(&secret).await {
        Ok(_) => {
            info!(secret = %c.name, "created for the cloud");
            return Ok(());
        }
        Err(StoreError::AlreadyExists(_)) => {}
        Err(e) => return Err(e.into()),
    }
    let current: controller_api::Secret = store.get(&c.name).await?;
    if current.metadata.cloud_uid() != Some(c.uid.as_str()) {
        bail!(
            "the name {} is taken by {}",
            c.name,
            match current.metadata.cloud_uid() {
                Some(other) => format!("a cloud secret with uid {other}"),
                None => "a cluster-local secret".to_string(),
            }
        );
    }
    let stamped = current
        .metadata
        .annotations
        .get(controller_api::ANNOTATION_CLOUD_GENERATION)
        .map(String::as_str);
    if current.spec.data == secret.spec.data
        && current.spec.tenant == secret.spec.tenant
        && stamped == Some(c.generation.to_string().as_str())
    {
        // A repeat of what is already here: a lost ack, a reconnect. The
        // comparison is over CIPHERTEXT, so a re-seal of the same plaintext
        // reads as a change — which is right and costs one write: a fresh
        // nonce per value means the cloud's own object changed bytes, and
        // this tier cannot tell "rotated" from "re-sealed" without the key.
        return Ok(());
    }
    // On the copy whose owner was just checked. (IKR-B81)
    store
        .mutate_if::<controller_api::Secret, _>(&c.name, &current.metadata.uid, |v| {
            v.spec.data = secret.spec.data.clone();
            v.spec.tenant = secret.spec.tenant.clone();
            v.spec.description = secret.spec.description.clone();
            // A new generation is what tells a VM's next pass that what it
            // read is stale. See `SecretSpec`.
            v.metadata.generation += 1;
            v.metadata.annotations.insert(
                controller_api::ANNOTATION_CLOUD_GENERATION.to_string(),
                c.generation.to_string(),
            );
        })
        .await?;
    info!(secret = %c.name, "updated from the cloud");
    Ok(())
}

/// Take the mirrored copy away. No finalizer and deliberately none: nothing
/// here owns bytes on behalf of a secret the way a volume owns a disk, so
/// there is nothing to tear down and nothing to wait for.
async fn handle_delete_secret(store: &EtcdStore, d: proto::DeleteSecret) -> anyhow::Result<()> {
    let current: controller_api::Secret = match store.get(&d.name).await {
        Ok(secret) => secret,
        // Already gone. A delete is idempotent for the same reason a create
        // is: the cloud repeats what it could not confirm.
        Err(StoreError::NotFound(_)) => return Ok(()),
        Err(e) => return Err(e.into()),
    };
    if current.metadata.cloud_uid() != Some(d.uid.as_str()) {
        // Somebody else's object under the same name. Acked untouched, the
        // same rule DestroyVolume follows.
        return Ok(());
    }
    delete_cloud_record(store, &current, &d.uid).await?;
    info!(secret = %d.name, "deleted for the cloud");
    Ok(())
}

/// Delete the record a cloud delete was judged against, on the revision it was judged at, never
/// whatever its name names by the time of the delete (NL2-6, R3-F02).
///
/// A record that went, or became another object's, in between is the cloud's delete done. One
/// that is still the cloud's is an error the cloud retries, never an ack for an object that is
/// still here.
async fn delete_cloud_record<T: controller_api::Resource>(
    store: &EtcdStore,
    checked: &T,
    cloud_uid: &str,
) -> anyhow::Result<()> {
    let the_clouds = |obj: &T| obj.metadata().cloud_uid() == Some(cloud_uid);
    if deletion::finish_delete(store, checked, the_clouds).await? {
        return Ok(());
    }
    // Gone, or another object's: done.
    let deleted = |now: Option<&T>| now.is_none_or(|obj| !the_clouds(obj)).then_some(());
    answer_unwritten(store, &checked.metadata().name, deleted, "deleted").await
}

/// The answer to a cloud command whose guarded write did not land, read off what the name holds
/// now (`None`: nothing): `settled` says what the command came to, or `None` while the cloud's
/// object still waits on it — an error the cloud retries, never an ack for it.
async fn answer_unwritten<T: controller_api::Resource, A>(
    store: &EtcdStore,
    name: &str,
    settled: impl Fn(Option<&T>) -> Option<A>,
    doing: &str,
) -> anyhow::Result<A> {
    let now = match store.get::<T>(name).await {
        Ok(current) => Some(current),
        Err(StoreError::NotFound(_)) => None,
        Err(e) => return Err(e.into()),
    };
    match settled(now.as_ref()) {
        Some(answer) => Ok(answer),
        None => bail!(
            "{}/{name} changed while it was {doing}; not {doing} yet",
            T::RESOURCE
        ),
    }
}

/// Mirror the provider network before creating or updating its router.
/// Cloud UID checks prevent adoption by name alone. Each command refreshes the
/// resolved external address, rules and prefixes, which can change independently
/// of router placement.
async fn handle_create_router(store: &EtcdStore, c: proto::CreateRouter) -> anyhow::Result<()> {
    if c.uid.is_empty() {
        bail!("create without a cloud uid");
    }
    let spec: controller_api::RouterSpec =
        serde_json::from_str(&c.spec_json).context("invalid spec_json")?;
    mirror_network(store, &c).await?;

    let mut router = Router::declare(&c.name, spec.clone());
    let nats = cloud_nats(&c, &router)?;
    router.metadata.mark_managed_by_cloud(&c.uid);
    stamp_resolved(&mut router, &c, &nats);
    match store.create(&router).await {
        Ok(_) => {
            info!(router = %c.name, "created for the cloud");
            return Ok(());
        }
        Err(StoreError::AlreadyExists(_)) => {}
        Err(e) => return Err(e.into()),
    }

    let current: Router = store.get(&c.name).await?;
    if current.metadata.cloud_uid() != Some(c.uid.as_str()) {
        bail!(
            "the name {} is taken by {}",
            c.name,
            match current.metadata.cloud_uid() {
                Some(other) => format!("a cloud router with uid {other}"),
                None => "a cluster-local router".to_string(),
            }
        );
    }
    if current.is_deleting() {
        bail!("router {} is still being torn down", c.name);
    }
    let settled = current.spec == spec
        && current.status.external_addr == c.external_addr
        && current.status.nats == nats
        && current.status.announced == c.announced;
    if settled {
        return Ok(());
    }
    // On the router whose owner was just checked. (IKR-B81)
    store
        .mutate_if::<Router, _>(&c.name, &current.metadata.uid, |r| {
            r.spec = spec.clone();
            stamp_resolved(r, &c, &nats);
        })
        .await?;
    debug!(router = %c.name, nats = nats.len(), "the cloud's router moved");
    Ok(())
}

/// The three halves only the tier above could resolve, onto the object.
fn stamp_resolved(router: &mut Router, c: &proto::CreateRouter, nats: &[controller_api::NatRule]) {
    router.status.external_addr = c.external_addr.clone();
    router.status.nats = nats.to_vec();
    router.status.announced = c.announced.clone();
}

/// `CreateRouter.nats` in this tier's own words, and a refusal for a kind
/// nobody here knows.
///
/// The same rule the `RouterReport.phase` road follows: an unknown word is
/// refused rather than defaulted, because a NAT rule this tier cannot spell
/// would reach a node as a rule it cannot render, and the honest place to
/// find that out is the hop where the word arrives.
///
/// A floating address is refused, too, unless its inside end is a guest on
/// `router`'s own inside prefix. The cloud renders only such rules; a cloud
/// from before that rule must not get a public address DNATed into another
/// tenant's prefix through this hop. (IKR-B68)
fn cloud_nats(
    c: &proto::CreateRouter,
    router: &Router,
) -> anyhow::Result<Vec<controller_api::NatRule>> {
    c.nats
        .iter()
        .map(|r| {
            let kind = controller_api::NatKind::parse(&r.kind)
                .with_context(|| format!("router {}: unknown nat kind {:?}", c.name, r.kind))?;
            if kind == controller_api::NatKind::DnatAndSnat
                && let Some(why) =
                    controller_api::network::inside_address_refusal(router, &r.logical_ip)
            {
                bail!(
                    "router {}: floating address {} refused: {why}",
                    c.name,
                    r.external_ip
                );
            }
            Ok(controller_api::NatRule {
                kind,
                external_ip: r.external_ip.clone(),
                logical_ip: r.logical_ip.clone(),
            })
        })
        .collect()
}

/// Mirror cloud network intent without overwriting a cluster-local network
/// of the same name. Router planning uses the retained local definition, so a
/// physnet mismatch can leave the router Pending.
async fn mirror_network(store: &EtcdStore, c: &proto::CreateRouter) -> anyhow::Result<()> {
    if c.network_name.is_empty() {
        return Ok(());
    }
    let spec: controller_api::ProviderNetworkSpec =
        serde_json::from_str(&c.network_json).context("invalid network_json")?;
    let mut network = ProviderNetwork::declare(&c.network_name, spec.clone());
    network.metadata.mark_managed_by_cloud(&c.uid);
    match store.create(&network).await {
        Ok(_) => {
            info!(network = %c.network_name, "provider network mirrored for the cloud");
            return Ok(());
        }
        Err(StoreError::AlreadyExists(_)) => {}
        Err(e) => return Err(e.into()),
    }
    let current: ProviderNetwork = store.get(&c.network_name).await?;
    if !current.metadata.managed_by_cloud() {
        debug!(network = %c.network_name, "a cluster-local provider network of this name; left alone");
        return Ok(());
    }
    if current.spec == spec {
        return Ok(());
    }
    // On the mirror that was just found to be the cloud's. (IKR-B81)
    store
        .mutate_if::<ProviderNetwork, _>(&c.network_name, &current.metadata.uid, |n| {
            n.spec = spec.clone()
        })
        .await?;
    info!(network = %c.network_name, "the cloud's provider network moved");
    Ok(())
}

/// Delete the router record without a finalizer.
/// Nodes report remaining namespaces and `sweep_routers` removes those without
/// an owner. Record absence also removes the router from cloud-facing inventory;
/// it does not itself prove node teardown completed.
async fn handle_delete_router(store: &EtcdStore, d: proto::DeleteRouter) -> anyhow::Result<()> {
    let current: Router = match store.get(&d.name).await {
        Ok(r) => r,
        // A record that is already gone is exactly what a delete wants.
        Err(StoreError::NotFound(_)) => return Ok(()),
        Err(e) => return Err(e.into()),
    };
    if current.metadata.cloud_uid() != Some(d.uid.as_str()) {
        warn!(router = %d.name, "delete for a name held by another router, nothing done");
        return Ok(());
    }
    delete_cloud_record(store, &current, &d.uid).await?;
    info!(router = %d.name, node = %current.status.active_node, "router deleted for the cloud");
    Ok(())
}

/// Fan out an image deletion to known nodes, using sibling forwarding where needed.
/// Each node failure is logged without failing the cloud command. No durable retry
/// or deletion tombstone is kept here, so unreachable nodes may retain stale caches.
async fn handle_drop_image(
    store: &EtcdStore,
    fanout: &Dispatch,
    d: proto::DropImage,
) -> anyhow::Result<()> {
    let nodes = store.list::<Node>().await?;
    for node in nodes {
        let name = node.metadata.name.clone();
        if let Err(e) = fanout
            .send(
                &name,
                NodeCommand::DropImage {
                    name: d.name.clone(),
                    uid: d.uid.clone(),
                },
            )
            .await
        {
            debug!(image = %d.name, node = %name, error = format!("{e:#}"),
                   "could not tell this node to drop the image; it keeps whatever it cached");
        }
    }
    Ok(())
}

async fn handle_create_volume(store: &EtcdStore, c: proto::CreateVolume) -> anyhow::Result<()> {
    if c.uid.is_empty() {
        bail!("create without a cloud uid");
    }
    let mut spec: controller_api::VolumeSpec =
        serde_json::from_str(&c.spec_json).context("invalid spec_json")?;
    // Whose it is comes from the cloud, because the Tenant object lives
    // there; a spec that named a different tenant would be the cloud
    // disagreeing with itself.
    spec.tenant = c.tenant.clone();
    let mut volume = new_volume(&c.name, spec);
    volume.metadata.mark_managed_by_cloud(&c.uid);
    // Use the cloud UID for a newly mirrored volume: backend names derive from it.
    // Moving a shared volume record between clusters must reopen the same bytes,
    // not provision a new disk under a fresh UID. Existing and cluster-local
    // volumes retain their own identities.
    if !c.uid.is_empty() {
        volume.metadata.uid = c.uid.clone();
    }
    match store.create(&volume).await {
        Ok(_) => {
            info!(volume = %c.name, "created for the cloud");
            return Ok(());
        }
        Err(StoreError::AlreadyExists(_)) => {}
        Err(e) => return Err(e.into()),
    }
    let current: Volume = store.get(&c.name).await?;
    if current.metadata.cloud_uid() != Some(c.uid.as_str()) {
        bail!(
            "the name {} is taken by {}",
            c.name,
            match current.metadata.cloud_uid() {
                Some(other) => format!("a cloud volume with uid {other}"),
                None => "a cluster-local volume".to_string(),
            }
        );
    }
    // Ours, and already here: a lost ack, a reconnect, a repeat after the
    // cloud lost sight of it — or the cloud's spec moved on. The one field of
    // a volume's spec that moves is its size, and only upwards (storage B);
    // the cloud sends the create again when its generation passes the one it
    // last sent, and this is where that lands. Everything else about the spec
    // was decided once, at both tiers, and is left as it is.
    let cloud = &volume.spec;
    if cloud.size_gib > current.spec.size_gib {
        // On the volume whose owner was just checked. (IKR-B81)
        store
            .mutate_if::<Volume, _>(&c.name, &current.metadata.uid, |v| {
                grow_to_cloud_size(v, cloud);
            })
            .await?;
        info!(volume = %c.name, from = current.spec.size_gib, to = cloud.size_gib,
              "the cloud grew the volume");
    }
    Ok(())
}

/// Apply only a larger cloud volume size and advance the local generation.
/// Taking the maximum makes repeated or reordered commands unable to shrink
/// storage after a newer growth request.
pub(crate) fn grow_to_cloud_size(volume: &mut Volume, cloud: &controller_api::VolumeSpec) -> bool {
    if cloud.size_gib <= volume.spec.size_gib {
        return false;
    }
    volume.spec.size_gib = cloud.size_gib;
    volume.metadata.generation += 1;
    true
}

/// Create a snapshot with cloud UID ownership checks to prevent adopting another
/// snapshot's bytes by name. This path does not check backend capability upfront;
/// unsupported snapshots fail asynchronously through node evidence.
async fn handle_create_snapshot(store: &EtcdStore, c: proto::CreateSnapshot) -> anyhow::Result<()> {
    if c.uid.is_empty() {
        bail!("create without a cloud uid");
    }
    let mut spec: controller_api::VolumeSnapshotSpec =
        serde_json::from_str(&c.spec_json).context("invalid spec_json")?;
    spec.tenant = c.tenant.clone();
    let mut snapshot = controller_api::new_volume_snapshot(&c.name, spec);
    snapshot.metadata.mark_managed_by_cloud(&c.uid);
    match store.create(&snapshot).await {
        Ok(_) => {
            info!(snapshot = %c.name, "created for the cloud");
            return Ok(());
        }
        Err(StoreError::AlreadyExists(_)) => {}
        Err(e) => return Err(e.into()),
    }
    let current: controller_api::VolumeSnapshot = store.get(&c.name).await?;
    if current.metadata.cloud_uid() != Some(c.uid.as_str()) {
        bail!(
            "the name {} is taken by {}",
            c.name,
            match current.metadata.cloud_uid() {
                Some(other) => format!("a cloud snapshot with uid {other}"),
                None => "a cluster-local snapshot".to_string(),
            }
        );
    }
    // Ours, and already here. A snapshot's spec is immutable, so there is no
    // drift to reconcile — only the ack to repeat.
    Ok(())
}

/// Stamp a cloud-owned snapshot for teardown. The finalizer flow at this tier
/// is unchanged: the object goes when the node says the copy is gone, and the
/// cloud's own object goes when this cluster stops naming it.
async fn handle_destroy_snapshot(
    store: &EtcdStore,
    d: proto::DestroySnapshot,
) -> anyhow::Result<()> {
    let current: controller_api::VolumeSnapshot = match store.get(&d.name).await {
        Ok(s) => s,
        Err(StoreError::NotFound(_)) => return Ok(()),
        Err(e) => return Err(e.into()),
    };
    if current.metadata.cloud_uid() != Some(d.uid.as_str()) {
        warn!(snapshot = %d.name, "destroy for a name held by another snapshot, nothing done");
        return Ok(());
    }
    if current.is_deleting() {
        return Ok(());
    }
    note_teardown(
        "snapshot",
        &d.name,
        mark_for_teardown(store, &current, &d.uid).await?,
    );
    Ok(())
}

/// Stamp a cloud-owned volume for teardown. The finalizer flow at this tier
/// is unchanged, which is the whole point: `HeldBy` still holds, the node
/// still refuses while a VM has it open, and the cloud's own object goes only
/// once this cluster stops naming the volume in its status.
async fn handle_destroy_volume(store: &EtcdStore, d: proto::DestroyVolume) -> anyhow::Result<()> {
    let current: Volume = match store.get(&d.name).await {
        Ok(v) => v,
        Err(StoreError::NotFound(_)) => return Ok(()),
        Err(e) => return Err(e.into()),
    };
    if current.metadata.cloud_uid() != Some(d.uid.as_str()) {
        warn!(volume = %d.name, "destroy for a name held by another volume, nothing done");
        return Ok(());
    }
    if current.is_deleting() {
        return Ok(());
    }
    note_teardown(
        "volume",
        &d.name,
        mark_for_teardown(store, &current, &d.uid).await?,
    );
    Ok(())
}

/// Forget a volume record during cross-cluster rescheduling without deleting data.
/// Remove its finalizer explicitly and bypass deprovisioning so the destination
/// can reopen the same backend identity. Missing or differently owned records
/// are acknowledged without mutation.
async fn handle_release_volume(store: &EtcdStore, r: proto::ReleaseVolume) -> anyhow::Result<()> {
    let current: Volume = match store.get(&r.name).await {
        Ok(v) => v,
        Err(StoreError::NotFound(_)) => return Ok(()),
        Err(e) => return Err(e.into()),
    };
    if current.metadata.cloud_uid() != Some(r.uid.as_str()) {
        warn!(volume = %r.name, "release for a name held by another volume, nothing done");
        return Ok(());
    }
    // A volume a VM here still has open does not go. The claim is this
    // cluster's own bookkeeping and the cloud cannot see it, so the refusal
    // has to be made here — and it is a refusal rather than a wait, because
    // the cloud is holding a reschedule open on the answer.
    if let Some(holder) = &current.status.attached_to {
        bail!("volume {} is still attached to vm {holder} here", r.name);
    }
    release_record(store, &current, &r).await
}

/// Release the record that was checked, on the revision it was judged at (R2-2, R3-F02).
///
/// The finalizer comes off `checked`'s uid only while the fresh revision is still the cloud's
/// and unattached, and the delete names the revision that write produced. A record that went
/// or became another volume's in between is a release done; one still here is a refusal the
/// cloud retries, never an ack for bytes another cluster would then reopen.
async fn release_record(
    store: &EtcdStore,
    checked: &Volume,
    r: &proto::ReleaseVolume,
) -> anyhow::Result<()> {
    let releasable = |v: &Volume| {
        v.metadata.cloud_uid() == Some(r.uid.as_str()) && v.status.attached_to.is_none()
    };
    let finalizer = controller_api::VOLUME_RELEASE_FINALIZER;
    if deletion::release_and_delete(store, checked, finalizer, releasable).await? {
        info!(volume = %r.name, "record released for the cloud; the bytes are untouched");
        return Ok(());
    }
    match store.get::<Volume>(&r.name).await {
        Err(StoreError::NotFound(_)) => Ok(()),
        Ok(v) if v.metadata.cloud_uid() != Some(r.uid.as_str()) => Ok(()),
        Ok(v) => match v.status.attached_to {
            Some(holder) => bail!("volume {} is still attached to vm {holder} here", r.name),
            None => bail!(
                "volume {} changed while it was released; not released yet",
                r.name
            ),
        },
        Err(e) => Err(e.into()),
    }
}

async fn handle_destroy(store: &EtcdStore, d: proto::DestroyVm) -> anyhow::Result<()> {
    let current: Vm = match store.get(&d.name).await {
        Ok(v) => v,
        // A record that is already gone is exactly what a destroy wants.
        Err(StoreError::NotFound(_)) => return Ok(()),
        Err(e) => return Err(e.into()),
    };
    if current.metadata.cloud_uid() != Some(d.uid.as_str()) {
        // Another VM wearing the same name. Acked and untouched: the honest
        // answer is "there is nothing of yours here", not the destruction of
        // whatever happens to answer to the name.
        warn!(vm = %d.name, "destroy for a name held by another vm, nothing done");
        return Ok(());
    }
    if current.is_deleting() {
        return Ok(());
    }
    note_teardown(
        "vm",
        &d.name,
        mark_for_teardown(store, &current, &d.uid).await?,
    );
    Ok(())
}

/// What a cloud destroy found to mark.
#[derive(Debug, PartialEq, Eq)]
enum Teardown {
    /// The judged object is marked for teardown, by this destroy or one before it.
    Marked,
    /// The judged object went or became another's in between: nothing of this cloud object is
    /// left here to mark.
    NothingLeft,
}

/// Mark the object a cloud destroy was judged against for teardown — a VM, a volume, a
/// snapshot — under the uid it was judged at, never whatever its name names by the time of the
/// write (NL3-3, IKR-B81).
///
/// An object that went or became another cloud object's in between leaves the destroy nothing
/// to do. One that is still the cloud's and unmarked is an error the cloud retries.
async fn mark_for_teardown<T: controller_api::Resource>(
    store: &EtcdStore,
    checked: &T,
    cloud_uid: &str,
) -> anyhow::Result<Teardown> {
    let the_clouds = |v: &T| v.metadata().cloud_uid() == Some(cloud_uid);
    let meta = checked.metadata();
    let mut marked = false;
    let written = store
        .mutate_if::<T, _>(&meta.name, &meta.uid, |v| {
            marked = the_clouds(v);
            if marked && v.metadata().deletion_timestamp.is_none() {
                v.metadata_mut().deletion_timestamp = Some(Utc::now());
            }
        })
        .await;
    // A mark that did not land: gone or another cloud object's is nothing left; this cloud
    // object, marked by somebody else, is marked; unmarked it is not done yet.
    let settled = |now: Option<&T>| match now {
        Some(obj) if the_clouds(obj) => obj
            .metadata()
            .deletion_timestamp
            .is_some()
            .then_some(Teardown::Marked),
        _ => Some(Teardown::NothingLeft),
    };
    match written {
        Ok(_) if marked => Ok(Teardown::Marked),
        Ok(_) | Err(StoreError::Conflict(_)) | Err(StoreError::NotFound(_)) => {
            answer_unwritten(store, &meta.name, settled, "marked for teardown").await
        }
        Err(e) => Err(e.into()),
    }
}

/// Say what a destroy did: `marked` on a mark, and quietly that nothing of the cloud object was
/// left otherwise.
fn note_teardown(kind: &str, name: &str, outcome: Teardown) {
    match outcome {
        Teardown::Marked => info!(kind, name, "marked for teardown by the cloud"),
        Teardown::NothingLeft => debug!(kind, name, "nothing of this cloud object left to mark"),
    }
}

/// Build one status and put it on the stream. False means the session is gone.
///
/// A status that cannot be built is not sent at all rather than sent hollow:
/// everything the cloud does with this message it does on the assumption that
/// the cluster could read its own store. Missing beats wrong, and a heartbeat
/// that stops is exactly the signal a cluster in that state should be giving.
async fn send_status(
    store: &EtcdStore,
    registry: &SessionRegistry,
    tx: &mpsc::Sender<ClusterMessage>,
) -> bool {
    match build_status(store, registry).await {
        Ok(status) => tx
            .send(ClusterMessage {
                kind: Some(cluster_message::Kind::Status(status)),
            })
            .await
            .is_ok(),
        Err(e) => {
            warn!(error = format!("{e:#}"), "could not build a cluster status");
            true
        }
    }
}

/// What the cloud places against, plus the phase of every VM this cluster
/// holds for it. VMs on their way out are in the list: they exist until they
/// do not, and it is precisely their disappearance from here that tells the
/// cloud the teardown finished.
async fn build_status(
    store: &EtcdStore,
    registry: &SessionRegistry,
) -> anyhow::Result<ClusterStatus> {
    let nodes = store.list::<Node>().await?;
    let mut nodes_ready = 0u32;
    let mut vcpus = 0u32;
    let mut mem_mib = 0u64;
    let mut profiles: BTreeSet<String> = BTreeSet::new();
    for node in &nodes {
        if !node.status.ready {
            continue;
        }
        nodes_ready += 1;
        vcpus = vcpus.saturating_add(node.status.capacity.vcpus);
        mem_mib = mem_mib.saturating_add(node.status.capacity.mem_mib);
        profiles.extend(node.status.capacity.capabilities.iter().cloned());
    }
    let vms = store.list::<Vm>().await?;
    // Every node, ready or not: a node that is down is exactly the one an
    // operator is looking for one tier up, and leaving it out of the report
    // would be the cloud saying it does not exist.
    let reported_nodes: Vec<proto::NodeReport> = nodes
        .iter()
        .map(|node| {
            let name = &node.metadata.name;
            node_report(
                node,
                registry.images.is_complete(name),
                controller_api::bound_on(name, &vms),
            )
        })
        .collect();

    // Absence from this list is what the cloud accepts as proof that a VM was
    // torn down, and `list` drops what it cannot decode. A short list would
    // read up there as a deletion, so the completeness travels with it and the
    // cloud concludes nothing from a list that is not all of them.
    let mut complete = vms.len() == store.count::<Vm>().await?;
    let reported = report_cloud_vms(&vms, &mut complete);

    // The same two statements about volumes. Absence from a COMPLETE list is
    // the cloud's proof of teardown, so the completeness travels with it.
    let volumes = store.list::<Volume>().await?;
    let mut volumes_complete = volumes_complete_here(store, &volumes).await?;
    let reported_volumes = report_cloud_volumes(&volumes, &mut volumes_complete);

    // What this cluster holds for the cloud, sealed. No completeness flag
    // beside it, and that is a difference worth stating: absence from this
    // list is never proof of anything — the cloud reads it only to skip a
    // send and to spot a leftover, and both of those are safe to be wrong
    // about in the direction of doing the work again.
    let reported_secrets: Vec<proto::SecretStateReport> = store
        .list::<controller_api::Secret>()
        .await?
        .into_iter()
        .filter(|s| s.metadata.managed_by_cloud())
        .filter_map(|s| {
            Some(proto::SecretStateReport {
                name: s.metadata.name.clone(),
                uid: s.metadata.cloud_uid()?.to_string(),
                generation: s
                    .metadata
                    .annotations
                    .get(controller_api::ANNOTATION_CLOUD_GENERATION)
                    .and_then(|g| g.parse().ok())
                    .unwrap_or(0),
            })
        })
        .collect();

    // And the same two statements about the copies of those volumes.
    let snapshots = store.list::<controller_api::VolumeSnapshot>().await?;
    let mut snapshots_complete =
        snapshots.len() == store.count::<controller_api::VolumeSnapshot>().await?;
    let reported_snapshots = report_cloud_snapshots(&snapshots, &mut snapshots_complete);

    // Every pool, cloud-owned or not: the cloud points at pools an admin made
    // down here, so a pool with no cloud marking on it is exactly the one the
    // cloud is waiting to hear about.
    let reported_pools: Vec<proto::StoragePoolStatusReport> = store
        .list::<controller_api::StoragePool>()
        .await?
        .into_iter()
        .map(|pool| proto::StoragePoolStatusReport {
            name: pool.metadata.name,
            phase: pool.status.phase().kind().as_str().to_string(),
            // D-C11's field. A pool has ONE vocabulary — no node says a word
            // about one — so the cloud parses back exactly the word this
            // tier derived: `AwaitingNode` when nobody serving it has spoken,
            // `Disagreement` when two binaries of different ages are on it.
            reason: pool.status.phase().reason_word().to_string(),
            // Empty when nobody has said, which is not the same as
            // `node-local` and must not become it on the way up.
            locality: pool
                .status
                .locality
                .map(|l| l.as_str().to_string())
                .unwrap_or_default(),
            // What THIS cluster's pool is made of, so that a cloud pool
            // naming two clusters can be held to its claim that both mount
            // the same export. Empty for a pool carrying none, and empty is
            // "did not say" rather than "the same as yours".
            params_json: pool
                .spec
                .params
                .as_ref()
                .map(|p| p.to_string())
                .unwrap_or_default(),
            nodes: pool.spec.nodes,
            message: pool
                .status
                .phase()
                .message()
                .unwrap_or_default()
                .to_string(),
        })
        .collect();

    // And the routers, the same two statements as the volumes above. Absence
    // from a COMPLETE list is the cloud's proof that a router was torn down.
    let routers = store.list::<Router>().await?;
    let mut routers_complete = routers.len() == store.count::<Router>().await?;
    let reported_routers = report_cloud_routers(&routers, &mut routers_complete);
    let (unplaced, unplaced_omitted) = report_unplaced(&vms);

    Ok(ClusterStatus {
        nodes_ready,
        nodes_total: nodes.len() as u32,
        capacity: Some(ClusterCapacity {
            vcpus,
            mem_mib,
            capabilities: profiles.into_iter().collect(),
        }),
        vms: reported,
        vms_complete: complete,
        volumes: reported_volumes,
        volumes_complete,
        snapshots: reported_snapshots,
        snapshots_complete,
        secrets: reported_secrets,
        pools: reported_pools,
        nodes: reported_nodes,
        // What waits here for a node, so the cloud does not count its room
        // as free. (IKR-B78)
        unplaced,
        unplaced_omitted,
        routers: reported_routers,
        routers_complete,
        // Passed through unchanged: this tier keeps no Image objects, and a
        // cluster that reworded what its nodes said would be a tier that
        // could get it wrong.
        images: registry.images.report(),
    })
}

/// Apply cloud node updates through the same merge-patch path as the local API.
/// Label removals become null values after label additions, so removal wins if
/// a key occurs in both sets.
async fn handle_update_node(store: &EtcdStore, u: proto::UpdateNode) -> anyhow::Result<()> {
    // Nothing to do is not success: a command that says nothing is a bug one
    // tier up, and the cloud shows the sentence.
    let Some(patch) = update_node_patch(&u) else {
        bail!("update_node for node {} asks for nothing", u.name);
    };
    // A command down the session is never a preview: the cloud's own edge
    // answered the dry run and sent nothing.
    let node = crate::api::patch_node_spec(store, &u.name, &patch, Default::default())
        .await
        // The sentence and not the status: it travels back as a
        // CommandResult and comes out of the cloud's REST edge as the
        // cluster's own words.
        .map_err(|e| anyhow!("{}", e.message()))?;
    info!(node = %node.metadata.name, schedulable = node.spec.schedulable,
          labels = node.spec.labels.len(), "node updated from the cloud");
    Ok(())
}

/// Move one of this cluster's guests between two of its machines, because a
/// cloud was asked to.
///
/// The whole of D-P9's second half, and it is four lines because everything
/// else already existed: `VmMigration` is a resource, the reconciler drives
/// it, and this only has to make the object an operator would have made by
/// hand at this endpoint. See `migration::start_from_the_cloud`.
async fn handle_create_vm_migration(
    store: &EtcdStore,
    m: proto::CreateVmMigration,
) -> anyhow::Result<()> {
    if m.name.is_empty() {
        bail!("create_vm_migration without a name for the record");
    }
    if m.vm.is_empty() {
        bail!("create_vm_migration without a vm to move");
    }
    if m.vm_uid.is_empty() {
        bail!(
            "create_vm_migration without the vm's uid; a cloud that does not say which vm it \
             means does not get one moved by its name"
        );
    }
    // `m.tenant` is the cloud's say and not this tier's to record: whose a
    // migration is follows the guest (`start_from_the_cloud`).
    crate::migration::start_from_the_cloud(store, &m.name, &m.vm, &m.vm_uid, migration_target(&m))
        .await
}

/// Where the cloud asked the guest to go, or `None` for "the cluster
/// chooses".
///
/// The empty string and not an absent field, because that is what proto3 has:
/// a `string` is always there and empty is how it says nothing. The rule is
/// one line and it is the difference between an operator's `--to agent-3` and
/// their `vm migrate web-1`, so it is written down once and tested rather
/// than inlined at the one call site.
fn migration_target(m: &proto::CreateVmMigration) -> Option<&str> {
    (!m.target_node.is_empty()).then_some(m.target_node.as_str())
}

/// The command as a merge patch. `None` = it asks for nothing.
///
/// The labels key is left out entirely when the command names none, and that
/// matters: an empty object would be a merge patch that changes nothing, but
/// writing one is a habit that ends in sending `{}` where `null` was meant.
fn update_node_patch(u: &proto::UpdateNode) -> Option<serde_json::Value> {
    let mut spec = serde_json::Map::new();
    if let Some(schedulable) = u.schedulable {
        spec.insert("schedulable".into(), serde_json::json!(schedulable));
    }
    if let Some(drain) = u.drain {
        spec.insert("drain".into(), serde_json::json!(drain));
    }
    if !u.labels.is_empty() || !u.remove_labels.is_empty() {
        let mut labels = serde_json::Map::new();
        for (key, value) in &u.labels {
            labels.insert(key.clone(), serde_json::json!(value));
        }
        // After the sets, so naming a key in both means it goes.
        for key in &u.remove_labels {
            labels.insert(key.clone(), serde_json::Value::Null);
        }
        spec.insert("labels".into(), serde_json::Value::Object(labels));
    }
    // A list replaces, and the empty list is a real instruction: it takes the
    // machine's restriction off. Absent is the one that says nothing, which
    // is why the wire carries a submessage here and not a bare list.
    if let Some(accepts) = &u.accepts {
        spec.insert("accepts".into(), serde_json::json!(accepts.classes));
    }
    if spec.is_empty() {
        return None;
    }
    Some(serde_json::json!({ "spec": serde_json::Value::Object(spec) }))
}

/// One node, flattened for the tier above: what an operator decided
/// (`spec`) and what the agent reported (`status`), in one message. The cloud
/// keeps no Node object to merge two halves into, and there is nothing up
/// there that would ever hold only one of them.
///
/// `images_complete` is the one field that comes from neither half: it is off
/// the session's own `ImageView`, because the claim is about the last REPORT
/// and not about the object. See `NodeReport.images_complete`.
fn node_report(
    node: &Node,
    images_complete: bool,
    bound: controller_api::Capacity,
) -> proto::NodeReport {
    proto::NodeReport {
        name: node.metadata.name.clone(),
        ready: node.status.ready,
        schedulable: node.spec.schedulable,
        drain: node.spec.drain,
        labels: node.spec.labels.clone().into_iter().collect(),
        vcpus: node.status.capacity.vcpus,
        mem_mib: node.status.capacity.mem_mib,
        // What its VMs ask for, so the cloud binds only where one node has
        // room and not where the sum of them does. (IKR-B78)
        bound_vcpus: bound.vcpus,
        bound_mem_mib: bound.mem_mib,
        capabilities: node.status.capacity.capabilities.clone(),
        vms: node.status.vms,
        images_complete,
        // Relayed and not summarised: what makes a machine unusable is the
        // machine's own sentence, and a tier that reworded it would be a tier
        // that could get it wrong.
        conditions: node
            .status
            .conditions
            .iter()
            .map(|c| proto::NodeCondition {
                r#type: c.type_.clone(),
                message: c.message.clone(),
            })
            .collect(),
        // The evidence of a drain, relayed the same way and for the same
        // reason as the two above: an operator who asked for the drain from
        // the cloud has to be able to see from there whether it is moving.
        // Absent means nobody is emptying this machine.
        draining: node.status.draining.as_ref().map(draining_report),
        // What this machine takes, so that the cloud can refuse a class no
        // machine of this fleet takes instead of binding a VM here and
        // letting it sit Pending. Empty is "takes everything" at both ends.
        accepts: node.spec.accepts.clone(),
    }
}

/// `controller_api::Draining` in the proto's own words. Field for field and
/// nothing added: the cluster owns the object, and this message exists so the
/// tier above can read it rather than hold a second opinion about it.
fn draining_report(d: &controller_api::Draining) -> proto::DrainingReport {
    proto::DrainingReport {
        leaving: d.leaving,
        leaving_vms: d.leaving_vms.clone(),
        moved_total: d.moved_total,
        staying: d.staying,
        complete: d.complete,
        reasons: d
            .reasons
            .iter()
            .map(|r| proto::StayingVm {
                vm: r.vm.clone(),
                reason: r.reason.clone(),
                message: r.message.clone(),
            })
            .collect(),
    }
}

/// The cloud-managed VMs, spoken in the uids the cloud handed out. A VM that
/// wears the cloud's mark but no uid cannot be named in a language the cloud
/// understands — and silently leaving it out is exactly the short list this
/// whole mechanism exists to prevent, so it costs the list its completeness.
fn report_cloud_vms(vms: &[Vm], complete: &mut bool) -> Vec<VmStatusReport> {
    let mut out = Vec::new();
    for vm in vms.iter().filter(|v| v.metadata.managed_by_cloud()) {
        match vm.metadata.cloud_uid() {
            Some(uid) => out.push(VmStatusReport {
                id: uid.to_string(),
                phase: vm.status.phase().kind().as_str().to_string(),
                message: vm.status.phase().message().unwrap_or_default().to_string(),
                // Empty on this road, and not for want of the fact. The
                // cloud already learns who holds a volume from the VOLUME
                // half of this report (`VolumeStatusReport.attached_to`),
                // which is the tier-appropriate answer: names the cloud
                // handed out, resolved by the tier that owns both objects.
                // Filling this in would mean translating cluster-local volume
                // names into cloud uids on a road where the volume half
                // already did it.
                attached_volumes: Vec::new(),
                // The one fact the cloud cannot derive: it binds to a
                // CLUSTER, and which machine inside this one runs the VM is
                // decided here. From the BINDING and not from any report —
                // `spec.nodeName` is what this tier decided, and an unplaced
                // VM honestly has no node.
                node: vm.spec.node_name.clone().unwrap_or_default(),
                // The evidence half of hot-plug, by name. This tier owns both
                // objects and has already resolved uid to name; the cloud
                // owns neither and cannot. Without it a tenant — who reads
                // their VM at the cloud and nowhere else — saw only the
                // intent in `spec.vm.volumes[]` and never the observation.
                volumes: vm
                    .status
                    .volumes
                    .iter()
                    .map(|v| proto::VolumeAttachment {
                        name: v.name.clone(),
                        attached: v.attached,
                    })
                    .collect(),
                // Relay the stored phase reason unchanged, including node-originated reasons.
                // `Unrecorded` is encoded as an empty field.
                reason: vm.status.phase().reason_word().to_string(),
                // Relay only node-derived MAC addresses. Floating addresses belong to cloud
                // objects and must not be overwritten by this tier's older copy.
                nics: vm
                    .status
                    .addresses
                    .iter()
                    .filter(|a| a.kind == controller_api::VmAddressKind::Mac)
                    .filter_map(|a| {
                        Some(proto::NicReport {
                            name: a.nic.clone(),
                            mac: a.mac.clone()?,
                        })
                    })
                    .collect(),
            }),
            None => {
                // Error: this object can never be named in the language the
                // cloud speaks, so it costs every status report its
                // completeness for as long as it exists. Only a person
                // editing or removing it ends that.
                error!(vm = %vm.metadata.name, "cloud-managed vm without a cloud uid");
                *complete = false;
            }
        }
    }
    out
}

/// How many unplaced demands one status carries. The cloud copies the list
/// whole onto its Cluster object, every write of which is all of it; a
/// cluster with more cloud VMs than this waiting for a node has no room to
/// offer anyway.
const UNPLACED_CARRIED_MAX: usize = 128;

/// What each cloud VM held here without a node asks for, at most
/// [`UNPLACED_CARRIED_MAX`] of them, and how many more there are. A
/// cluster-local VM is this cluster's own: the cloud neither places it nor
/// can wait for it. (IKR-B78)
fn report_unplaced(vms: &[Vm]) -> (Vec<proto::VmDemand>, u32) {
    let demand =
        controller_api::unplaced_demand(vms.iter().filter(|v| v.metadata.managed_by_cloud()));
    let omitted = demand.len().saturating_sub(UNPLACED_CARRIED_MAX);
    let carried = demand
        .into_iter()
        .take(UNPLACED_CARRIED_MAX)
        .map(|c| proto::VmDemand {
            vcpus: c.vcpus,
            mem_mib: c.mem_mib,
        })
        .collect();
    (carried, u32::try_from(omitted).unwrap_or(u32::MAX))
}

/// Whether the volume listing is all of them. Its own function only because
/// the count and the list have to be compared in one place — a short list
/// reads up there as a deletion.
async fn volumes_complete_here(store: &EtcdStore, volumes: &[Volume]) -> anyhow::Result<bool> {
    Ok(volumes.len() == store.count::<Volume>().await?)
}

/// The volume half of the same report, by the same rule: the cloud's uid is
/// the name, and an object that cannot be named in the cloud's language costs
/// the report its completeness rather than being quietly left out.
fn report_cloud_volumes(volumes: &[Volume], complete: &mut bool) -> Vec<proto::VolumeStatusReport> {
    let mut out = Vec::new();
    for volume in volumes.iter().filter(|v| v.metadata.managed_by_cloud()) {
        match volume.metadata.cloud_uid() {
            Some(uid) => out.push(proto::VolumeStatusReport {
                uid: uid.to_string(),
                phase: volume.status.phase().kind().as_str().to_string(),
                // The object's word, which is the node's where the node had
                // one (`DriverRefused`, `NotOnBackend`) and this tier's where
                // it did not (`Following`, `Undeliverable`, `HeldBy`). One
                // list, relayed unchanged — decision 1.
                reason: volume.status.phase().reason_word().to_string(),
                node: volume.status.node.clone().unwrap_or_default(),
                attached_to: volume.status.attached_to.clone().unwrap_or_default(),
                message: volume
                    .status
                    .phase()
                    .message()
                    .unwrap_or_default()
                    .to_string(),
                // Empty until this cluster's node has said it, and passed on
                // as empty: the cloud applies the same "only ever arrives"
                // rule the cluster does, so an empty field is silence rather
                // than a claim that the name is gone.
                backend: volume.status.backend.clone(),
                // What the node measured, beside what the spec asked for.
                // Zero until it has, which reads as "not measured".
                size_gib: volume.status.size_gib,
                // Who has it OPEN, which is two machines while a live
                // migration is under way and one the rest of the time.
                open_on: volume.status.open_on.clone(),
            }),
            None => {
                error!(volume = %volume.metadata.name, "cloud-managed volume without a cloud uid");
                *complete = false;
            }
        }
    }
    out
}

/// The snapshot half of the same report, by the same rule the volume half
/// follows: the cloud's uid is the name, and an object that cannot be named in
/// the cloud's language costs the report its completeness rather than being
/// quietly left out.
fn report_cloud_snapshots(
    snapshots: &[controller_api::VolumeSnapshot],
    complete: &mut bool,
) -> Vec<proto::VolumeSnapshotStatusReport> {
    let mut out = Vec::new();
    for snapshot in snapshots.iter().filter(|s| s.metadata.managed_by_cloud()) {
        match snapshot.metadata.cloud_uid() {
            Some(uid) => out.push(proto::VolumeSnapshotStatusReport {
                uid: uid.to_string(),
                phase: snapshot.status.phase().kind().as_str().to_string(),
                // The last of the six roads to carry one. Decision 1.
                reason: snapshot.status.phase().reason_word().to_string(),
                node: snapshot.status.node.clone().unwrap_or_default(),
                backend: snapshot.status.backend.clone(),
                size_gib: snapshot.status.size_gib,
                message: snapshot
                    .status
                    .phase()
                    .message()
                    .unwrap_or_default()
                    .to_string(),
            }),
            None => {
                error!(snapshot = %snapshot.metadata.name,
                       "cloud-managed snapshot without a cloud uid");
                *complete = false;
            }
        }
    }
    out
}

/// The routers this cluster holds for the cloud, in the uids the cloud handed
/// out — and with the two fields the road one tier down leaves empty.
///
/// `active` is not `phase == Active`: the phase is what the ROUTER is and the
/// flag is whether THIS cluster currently has a machine forwarding for it, so
/// a router whose whole priority list is down reports its phase and no active
/// node, which is the state a reader is looking for.
fn report_cloud_routers(routers: &[Router], complete: &mut bool) -> Vec<proto::RouterReport> {
    let mut out = Vec::new();
    for router in routers.iter().filter(|r| r.metadata.managed_by_cloud()) {
        match router.metadata.cloud_uid() {
            Some(uid) => out.push(proto::RouterReport {
                id: uid.to_string(),
                phase: router.status.phase().kind().as_str().to_string(),
                // The object's word, relayed: `NetnsGone` and its two
                // siblings came off a node's driver, the rest are this tier's
                // own. Decision 1.
                reason: router.status.phase().reason_word().to_string(),
                message: router
                    .status
                    .phase()
                    .message()
                    .unwrap_or_default()
                    .to_string(),
                active: !router.status.active_node.is_empty(),
                node: router.status.active_node.clone(),
                nodes: router.status.nodes.clone(),
            }),
            None => {
                error!(router = %router.metadata.name, "cloud-managed router without a cloud uid");
                *complete = false;
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {

    /// A mirrored volume keeps the cloud UID so another cluster reopens the same
    /// backend bytes instead of provisioning a disk under a new identity.
    #[tokio::test]
    async fn a_cloud_volume_is_named_after_the_uid_the_cloud_handed_down() {
        let create = |uid: &str| proto::CreateVolume {
            name: "boot-1".into(),
            spec_json: serde_json::to_string(&controller_api::VolumeSpec {
                tenant: String::new(),
                pool: "shared".into(),
                size_gib: 1,
                ..Default::default()
            })
            .unwrap(),
            uid: uid.to_string(),
            tenant: "acme".into(),
        };

        // The object the handler builds, without a store: the two lines under
        // test are the uid and the ownership label, and both are pure.
        let mut spec: controller_api::VolumeSpec =
            serde_json::from_str(&create("u-1").spec_json).unwrap();
        spec.tenant = "acme".into();
        let mut volume = new_volume("boot-1", spec);
        volume.metadata.mark_managed_by_cloud("u-1");
        let minted = volume.metadata.uid.clone();
        volume.metadata.uid = "u-1".to_string();

        assert_eq!(volume.metadata.uid, "u-1", "the bytes are named after this");
        assert_eq!(volume.metadata.cloud_uid(), Some("u-1"));
        assert_ne!(
            minted, "u-1",
            "and it is NOT what declare() would have minted, which is the whole point"
        );
    }
    use super::*;
    use controller_api::object::Resource as _;
    use controller_api::{VmPhaseKind, VmSpec, VolumePhaseKind};

    /// What the cloud decided, into this tier's objects — and the two fields
    /// the road one tier down leaves empty, filled on the way back up.
    #[test]
    fn a_cloud_router_arrives_resolved_and_goes_back_up_with_its_machine() {
        let command = proto::CreateRouter {
            name: "lab-out".into(),
            uid: "u-7".into(),
            spec_json: serde_json::to_string(&controller_api::RouterSpec {
                tenant: "lab".into(),
                provider_network: "ext".into(),
                vni: Some(4711),
                internal_addr: "10.42.0.1/24".into(),
                ..Default::default()
            })
            .unwrap(),
            network_name: "ext".into(),
            network_json: String::new(),
            external_addr: "10.128.1.200/24".into(),
            nats: vec![proto::NatRule {
                kind: "dnat_and_snat".into(),
                external_ip: "10.128.1.201".into(),
                logical_ip: "10.42.0.5".into(),
            }],
            announced: vec!["10.43.0.0/24".into()],
        };

        let spec: controller_api::RouterSpec = serde_json::from_str(&command.spec_json).unwrap();
        let mut router = Router::declare("lab-out", spec);
        let nats = cloud_nats(&command, &router).expect("a kind this tier knows");
        assert_eq!(nats[0].kind, controller_api::NatKind::DnatAndSnat);
        router.metadata.mark_managed_by_cloud("u-7");
        stamp_resolved(&mut router, &command, &nats);
        assert_eq!(router.status.external_addr, "10.128.1.200/24");
        assert_eq!(router.status.announced, vec!["10.43.0.0/24".to_string()]);
        assert_eq!(router.status.nats, nats, "the cloud's derivation, not ours");

        // A word this tier cannot spell is refused rather than defaulted: a
        // rule nobody can render must not reach a node looking valid.
        let nonsense = proto::CreateRouter {
            nats: vec![proto::NatRule {
                kind: "masquerade".into(),
                ..Default::default()
            }],
            ..command.clone()
        };
        let e = cloud_nats(&nonsense, &router).expect_err("an unknown kind");
        assert!(format!("{e:#}").contains("masquerade"), "{e:#}");

        // And back up: `active` is whether a machine is really forwarding,
        // which is not the same question as the phase.
        router.status.reported = Some(controller_api::RouterReported::by(
            "agent-1b",
            controller_api::RouterPhaseKind::Active,
            controller_api::RouterReason::Unrecorded,
            None,
            Utc::now(),
        ));
        router.settle(Utc::now());
        router.status.nodes = vec!["agent-1b".into(), "agent-1c".into()];
        router.status.active_node = "agent-1b".into();
        let mut complete = true;
        let reported = report_cloud_routers(&[router.clone()], &mut complete);
        assert!(complete);
        assert_eq!(reported.len(), 1);
        assert_eq!(reported[0].id, "u-7", "the uid the cloud handed out");
        assert_eq!(reported[0].node, "agent-1b");
        assert_eq!(reported[0].nodes, vec!["agent-1b", "agent-1c"]);
        assert!(reported[0].active);

        // A router planned onto machines that are all down: the phase still
        // travels and nobody is active.
        router.status.active_node.clear();
        let quiet = report_cloud_routers(&[router.clone()], &mut complete);
        assert!(!quiet[0].active && quiet[0].node.is_empty());
        assert_eq!(quiet[0].nodes.len(), 2, "the promise is still on the list");

        // A router this cluster made itself is nobody's business up there.
        let mine = Router::declare("local", controller_api::RouterSpec::default());
        assert!(report_cloud_routers(&[mine], &mut complete).is_empty());
    }

    fn vm(name: &str, uid: Option<&str>, phase: VmPhaseKind) -> Vm {
        let mut vm = new_vm(
            name,
            VmSpec {
                class: Default::default(),
                cluster_selector: Default::default(),
                node_selector: Default::default(),
                anti_affinity: Vec::new(),
                node_name: None,
                cluster_name: None,
                run_strategy: Default::default(),
                evacuation: Default::default(),
                tenant: None,
                vm: serde_json::json!({}),
            },
        );
        if let Some(uid) = uid {
            vm.metadata.mark_managed_by_cloud(uid);
        }
        // Through the derivation, which is the only way in. The holder has
        // to be named for a resting word to stand at all (see `VmReported`),
        // and a VM this cluster reports upward is on one of its machines.
        vm.status.node_name = Some("manacor".into());
        vm.status.reported = Some(controller_api::VmReported::by(
            "manacor",
            phase,
            controller_api::VmReason::Unrecorded,
            None,
            Utc::now(),
        ));
        vm.settle(Utc::now());
        vm
    }

    fn node(name: &str, ready: bool, schedulable: bool) -> Node {
        let mut node = Node::declare(
            name,
            controller_api::NodeSpec {
                accepts: Vec::new(),
                drain: false,
                schedulable,
                labels: [("zone".to_string(), "a".to_string())]
                    .into_iter()
                    .collect(),
            },
        );
        node.status.ready = ready;
        node.status.vms = 2;
        node.status.capacity = controller_api::NodeCapacity {
            vcpus: 32,
            mem_mib: 65_536,
            capabilities: vec!["nvrm/4q".into()],
            volume_localities: Default::default(),
        };
        node
    }

    /// What the tier above reads. Spec and status flattened into one report,
    /// because up there it is a report and not an object — and a node that is
    /// NOT ready is in the list too: it is exactly the one an operator is
    /// looking for, and leaving it out would be this cluster saying it does
    /// not exist.
    #[test]
    fn a_node_report_carries_what_an_operator_decided_and_what_the_agent_said() {
        let up = node_report(&node("manacor", true, false), false, Default::default());
        assert_eq!(up.name, "manacor");
        assert!(up.ready, "the agent is talking");
        assert!(!up.schedulable, "and an operator drained it");
        assert_eq!(up.labels["zone"], "a");
        assert_eq!((up.vcpus, up.mem_mib, up.vms), (32, 65_536, 2));
        assert_eq!(up.capabilities, vec!["nvrm/4q".to_string()]);

        let down = node_report(&node("felanitx", false, true), false, Default::default());
        assert!(!down.ready);
        assert!(down.schedulable);
        // A healthy machine says nothing, and that is what travels: an empty
        // list is also what an agent from before the field reports, so it can
        // only ever mean "said nothing".
        assert!(up.conditions.is_empty());
    }

    /// IKR-B78: what a node's VMs ask for travels up beside its capacity, so
    /// the cloud can tell one node's room from the cluster's sum.
    #[test]
    fn what_a_nodes_vms_ask_for_travels_up_beside_its_capacity() {
        let bound = controller_api::Capacity {
            vcpus: 3,
            mem_mib: 3072,
        };
        let up = node_report(&node("manacor", true, true), false, bound);
        assert_eq!((up.bound_vcpus, up.bound_mem_mib), (3, 3072));
    }

    /// The evidence of a drain, on the road that carries the ask.
    ///
    /// `spec.drain` says somebody asked; this says what came of it, and it is
    /// what an operator watching a drain is actually waiting for. Absent on a
    /// machine nobody is emptying, and that absence is the whole reason it is
    /// a submessage: a block of zeroes would give every node in the fleet a
    /// drain column reading `0 moved, 0 leaving, 0 staying`.
    #[test]
    fn the_numbers_of_a_drain_travel_up_beside_the_ask() {
        let quiet = node_report(&node("manacor", true, false), false, Default::default());
        assert!(
            quiet.draining.is_none(),
            "nobody is emptying this one, so there is nothing to say"
        );

        let mut emptying = node("felanitx", true, false);
        emptying.spec.drain = true;
        emptying.status.draining = Some(controller_api::Draining {
            leaving: 1,
            leaving_vms: vec!["web-2".into()],
            moved_total: 4,
            staying: 1,
            complete: false,
            reasons: vec![controller_api::StayingVm {
                vm: "db-1".into(),
                reason: "evacuation-never".into(),
                message: "its owner said evacuation: never".into(),
            }],
        });
        let up = node_report(&emptying, false, Default::default());
        assert!(up.drain, "the ask");
        let evidence = up.draining.expect("and the evidence beside it");
        assert_eq!(
            (
                evidence.moved_total,
                evidence.leaving,
                evidence.staying,
                evidence.complete
            ),
            (4, 1, 1, false)
        );
        assert_eq!(evidence.leaving_vms, ["web-2"]);
        assert_eq!(evidence.reasons[0].vm, "db-1");
        assert_eq!(
            evidence.reasons[0].reason, "evacuation-never",
            "the closed word a client branches on"
        );
        assert_eq!(
            evidence.reasons[0].message, "its owner said evacuation: never",
            "and the sentence an operator reads, because prose is not a branch"
        );
    }

    /// D8, the relay: what the NODE said is wrong with itself reaches the
    /// tier that places on clusters, word for word.
    ///
    /// The mini-chaos run's wedged machine was invisible from the cloud —
    /// `ready`, a session, capacity, and nothing anywhere that said it could
    /// not act. Reworded here it would be a second answer to "is this machine
    /// usable", and the whole reason this list exists is that there was no
    /// first one.
    #[test]
    fn what_a_node_says_is_wrong_with_it_reaches_the_cloud_unchanged() {
        let mut wedged = node("agent-1a", true, true);
        wedged.status.conditions = vec![
            controller_api::NodeCondition {
                type_: controller_api::NodeConditionType::StoreUnhealthy
                    .as_str()
                    .into(),
                message: "the store took an I/O error and must be re-opened".into(),
            },
            controller_api::NodeCondition {
                type_: controller_api::NodeConditionType::DiskPressure
                    .as_str()
                    .into(),
                message: "/var/lib/meisterstack has 0 bytes free".into(),
            },
        ];
        let up = node_report(&wedged, false, Default::default());
        assert_eq!(
            up.conditions
                .iter()
                .map(|c| c.r#type.as_str())
                .collect::<Vec<_>>(),
            ["StoreUnhealthy", "DiskPressure"],
            "the order the node reported them in is the node's, not ours"
        );
        assert_eq!(
            up.conditions[0].message,
            "the store took an I/O error and must be re-opened"
        );
    }

    /// The command from one tier up, translated into the merge patch this
    /// tier's own PATCH route takes. `null` is how a merge patch removes, and
    /// the removals go in after the sets so that naming a key in both means
    /// it goes.
    #[test]
    fn an_update_from_the_cloud_becomes_the_patch_this_tier_already_had() {
        let patch = update_node_patch(&proto::UpdateNode {
            drain: None,
            name: "manacor".into(),
            schedulable: Some(false),
            labels: [("gpu".to_string(), "a100".to_string())]
                .into_iter()
                .collect(),
            remove_labels: vec!["zone".into()],
            accepts: None,
        })
        .expect("it says something");
        assert_eq!(patch["spec"]["schedulable"], false);
        assert_eq!(patch["spec"]["labels"]["gpu"], "a100");
        assert!(patch["spec"]["labels"]["zone"].is_null(), "null removes");

        // A drain on its own touches no labels at all — an empty label map
        // would replace the ones that are there with nothing.
        let drain = update_node_patch(&proto::UpdateNode {
            drain: None,
            name: "manacor".into(),
            schedulable: Some(true),
            labels: Default::default(),
            remove_labels: Vec::new(),
            accepts: None,
        })
        .unwrap();
        assert_eq!(drain["spec"]["schedulable"], true);
        assert!(drain["spec"].get("labels").is_none());

        // The classes, and the difference the submessage exists for: a list
        // replaces, the EMPTY list takes the restriction off, and absent
        // leaves the machine's classes exactly as they were.
        let only_routers = update_node_patch(&proto::UpdateNode {
            drain: None,
            name: "gw-1".into(),
            schedulable: None,
            labels: Default::default(),
            remove_labels: Vec::new(),
            accepts: Some(proto::AcceptsUpdate {
                classes: vec!["router".into()],
            }),
        })
        .expect("it says something");
        assert_eq!(
            only_routers["spec"]["accepts"],
            serde_json::json!(["router"])
        );

        let open_again = update_node_patch(&proto::UpdateNode {
            drain: None,
            name: "gw-1".into(),
            schedulable: None,
            labels: Default::default(),
            remove_labels: Vec::new(),
            accepts: Some(proto::AcceptsUpdate::default()),
        })
        .expect("an empty list is an instruction, not silence");
        assert_eq!(open_again["spec"]["accepts"], serde_json::json!([]));

        // And a command that asks for nothing is a bug one tier up, not a
        // no-op to swallow.
        assert!(
            update_node_patch(&proto::UpdateNode {
                drain: None,
                name: "manacor".into(),
                schedulable: None,
                labels: Default::default(),
                remove_labels: Vec::new(),
                accepts: None,
            })
            .is_none()
        );
    }

    fn create(vni: Option<u32>, floating: &[&str], subnets: &[&str]) -> proto::CreateVm {
        proto::CreateVm {
            name: "web-1".into(),
            spec_json: String::new(),
            uid: "uid-1".into(),
            vni,
            floating_ips: floating.iter().map(|s| s.to_string()).collect(),
            routed_subnets: subnets.iter().map(|s| s.to_string()).collect(),
            labels: Default::default(),
        }
    }

    /// The whole edge in one assertion: what the cloud resolved lands on every
    /// NIC, and the agent below is handed a spec that says plainly which wire
    /// it is on and which addresses it may source from.
    #[test]
    fn what_the_cloud_resolved_is_written_into_the_nics() {
        let mut spec = serde_json::json!({ "vcpus": 1, "nics": [{}, {}] });
        bind_nics(
            &create(Some(10_007), &["10.255.0.7"], &["10.7.1.0/24"]),
            &mut spec,
        );
        for nic in spec["nics"].as_array().unwrap() {
            assert_eq!(nic["vxlan_id"], 10_007);
            assert_eq!(nic["floating_ips"][0], "10.255.0.7");
            assert_eq!(nic["routed_subnets"][0], "10.7.1.0/24");
        }
    }

    /// The compatibility invariant of this milestone, at the tier that writes
    /// it: a VM whose tenant holds no address and has no routed subnet comes
    /// out of here byte-identical to what went in.
    #[test]
    fn a_vm_with_nothing_to_bind_is_left_exactly_as_it_was() {
        let before = serde_json::json!({ "vcpus": 1, "nics": [{ "bridge": "meister_br0" }] });
        let mut spec = before.clone();
        bind_nics(&create(None, &[], &[]), &mut spec);
        assert_eq!(spec, before);
    }

    /// The standalone road: a spec that already names its own addresses has
    /// said something more specific than the cloud did, and keeps it.
    #[test]
    fn a_spec_that_names_its_own_addresses_keeps_them() {
        let mut spec = serde_json::json!({
            "nics": [{ "vxlan_id": 4242, "floating_ips": ["192.0.2.9"] }]
        });
        bind_nics(
            &create(Some(10_007), &["10.255.0.7"], &["10.7.1.0/24"]),
            &mut spec,
        );
        assert_eq!(spec["nics"][0]["vxlan_id"], 4242);
        assert_eq!(spec["nics"][0]["floating_ips"][0], "192.0.2.9");
        // ... and the field it said nothing about is still filled in.
        assert_eq!(spec["nics"][0]["routed_subnets"][0], "10.7.1.0/24");
    }

    /// A cloud create whose first NIC picks the provider network `ext`.
    fn on_its_own_wire(run_strategy: &str) -> proto::CreateVm {
        proto::CreateVm {
            spec_json: serde_json::json!({
                "tenant": "acme",
                "runStrategy": run_strategy,
                "vm": { "vcpus": 1, "nics": [{ "physnet": "ext" }] },
            })
            .to_string(),
            ..create(Some(10_007), &[], &[])
        }
    }

    /// IKR-B67 one tier down: a cloud from before the rule does not get a
    /// tenant's tap onto the provider segment through this session.
    #[tokio::test]
    #[ignore = "needs an etcd; see crate::test_etcd"]
    async fn a_cloud_vm_whose_nic_picks_its_own_wire_is_refused_before_it_is_stored() {
        let store = crate::test_etcd::fresh_store("b67-test").await;
        let why = format!(
            "{:#}",
            handle_create(&store, on_its_own_wire("Running"), "")
                .await
                .expect_err("a tap on ext")
        );
        assert!(why.contains("nics[0].physnet"), "{why}");
        assert!(matches!(
            store.get::<Vm>("web-1").await,
            Err(StoreError::NotFound(_))
        ));
    }

    /// A VM stored without a wire of its own does not get one by a re-send:
    /// that is a new wire, refused like a new VM. (IKR-B67)
    #[tokio::test]
    #[ignore = "needs an etcd; see crate::test_etcd"]
    async fn a_resend_does_not_give_a_stored_vm_a_wire_of_its_own() {
        let store = crate::test_etcd::fresh_store("b67-test").await;
        let plain = proto::CreateVm {
            spec_json: serde_json::json!({
                "tenant": "acme",
                "vm": { "vcpus": 1, "nics": [{}] },
            })
            .to_string(),
            ..create(Some(10_007), &[], &[])
        };
        handle_create(&store, plain, "").await.expect("created");

        let why = format!(
            "{:#}",
            handle_create(&store, on_its_own_wire("Running"), "")
                .await
                .expect_err("a tap on ext")
        );

        assert!(why.contains("nics[0].physnet"), "{why}");
        let after: Vm = store.get("web-1").await.expect("still there");
        assert!(after.spec.vm["nics"][0].get("physnet").is_none());
    }

    /// One stored before the rule is managed on, not stranded: a stop reaches
    /// it, and the wire it kept is said on the VM. (IKR-B67)
    #[tokio::test]
    #[ignore = "needs an etcd; see crate::test_etcd"]
    async fn a_cloud_vm_stored_before_the_nic_rule_is_managed_on_and_said() {
        let store = crate::test_etcd::fresh_store("b67-test").await;
        let c = on_its_own_wire("Running");
        let spec: VmSpec = serde_json::from_str(&c.spec_json).unwrap();
        let stored = store
            .create(&declared_for_cloud(&c, &spec, ""))
            .await
            .expect("a vm from before the rule");

        handle_create(&store, on_its_own_wire("Stopped"), "")
            .await
            .expect("managed on");

        let after: Vm = store.get("web-1").await.expect("still there");
        assert_eq!(
            after.spec.run_strategy,
            controller_api::RunStrategy::Stopped
        );
        let said: controller_api::Event = store
            .get(&events::name_of(
                Vm::KIND,
                &stored.metadata.uid,
                "web-1",
                events::reason::TENANT_WIRE_KEPT,
            ))
            .await
            .expect("the kept wire is said");
        assert!(
            said.spec.message.contains("nics[0].physnet"),
            "{}",
            said.spec.message
        );
    }

    /// A VM stored before the rule with its own wire does not take another by a re-send, and is
    /// not said to have kept one: the refusal kept nothing. (IKR-B67)
    #[tokio::test]
    #[ignore = "needs an etcd; see crate::test_etcd"]
    async fn a_stored_wire_resent_as_another_is_refused_and_not_said_kept() {
        let store = crate::test_etcd::fresh_store("b67-test").await;
        let c = on_its_own_wire("Running");
        let spec: VmSpec = serde_json::from_str(&c.spec_json).unwrap();
        let stored = store
            .create(&declared_for_cloud(&c, &spec, ""))
            .await
            .expect("a vm from before the rule");
        let elsewhere = proto::CreateVm {
            spec_json: serde_json::json!({
                "tenant": "acme",
                "runStrategy": "Stopped",
                "vm": { "vcpus": 1, "nics": [{ "physnet": "other" }] },
            })
            .to_string(),
            ..create(Some(10_007), &[], &[])
        };

        let why = format!(
            "{:#}",
            handle_create(&store, elsewhere, "")
                .await
                .expect_err("a tap on another wire")
        );

        assert!(why.contains("nics[0].physnet"), "{why}");
        let after: Vm = store.get("web-1").await.expect("still there");
        assert_eq!(after.spec.vm["nics"][0]["physnet"], "ext");
        assert_eq!(
            after.spec.run_strategy,
            controller_api::RunStrategy::Running
        );
        assert!(matches!(
            store
                .get::<controller_api::Event>(&events::name_of(
                    Vm::KIND,
                    &stored.metadata.uid,
                    "web-1",
                    events::reason::TENANT_WIRE_KEPT,
                ))
                .await,
            Err(StoreError::NotFound(_))
        ));
    }

    /// Only the cloud's VMs waiting for a node travel up, and no more of them than one status
    /// carries; the rest is counted. (IKR-B78)
    #[test]
    fn only_the_clouds_unplaced_vms_travel_up_and_at_most_so_many() {
        let mut vms = vec![vm("local", None, VmPhaseKind::Pending)];
        vms.extend((0..UNPLACED_CARRIED_MAX + 2).map(|i| {
            vm(
                &format!("cloud-{i}"),
                Some(&format!("uid-{i}")),
                VmPhaseKind::Pending,
            )
        }));

        let (carried, omitted) = report_unplaced(&vms);

        assert_eq!(carried.len(), UNPLACED_CARRIED_MAX);
        assert_eq!(omitted, 2, "the cluster-local vm is not counted");
    }

    #[test]
    fn only_the_clouds_vms_are_reported_and_only_by_uid() {
        let vms = [
            vm("local", None, VmPhaseKind::Running),
            vm("theirs", Some("uid-1"), VmPhaseKind::Provisioning),
        ];
        let mut complete = true;
        let out = report_cloud_vms(&vms, &mut complete);
        assert!(complete);
        assert_eq!(
            out.len(),
            1,
            "a cluster-local vm is nobody's business up there"
        );
        assert_eq!(out[0].id, "uid-1");
        assert_eq!(out[0].phase, "Provisioning");
    }

    fn command(id: &str) -> proto::CloudMessage {
        proto::CloudMessage {
            kind: Some(cloud_message::Kind::Command(proto::CloudCommand {
                request_id: id.into(),
                traceparent: String::new(),
                op: None,
            })),
        }
    }

    fn ready(
        msgs: Vec<proto::CloudMessage>,
    ) -> impl Stream<Item = Result<proto::CloudMessage, tonic::Status>> + Unpin {
        tokio_stream::iter(msgs.into_iter().map(Ok))
    }

    /// The coalescing itself: what the cloud has already put on the wire is
    /// taken in one batch, in arrival order, and the drain never waits for a
    /// message that has not arrived — a stream with nothing ready yields the
    /// batch it has.
    #[tokio::test]
    async fn a_burst_is_taken_in_one_batch_and_a_quiet_stream_ends_it() {
        let mut stream = ready(vec![command("a"), command("b")]).chain(tokio_stream::pending());
        let mut batch = Vec::new();
        assert!(!drain_ready(&mut stream, &mut batch, MAX_BATCH).await);
        assert_eq!(
            commands(batch)
                .into_iter()
                .map(|c| c.request_id)
                .collect::<Vec<_>>(),
            vec!["a".to_string(), "b".into()],
            "arrival order, and nothing invented"
        );
        // and a stream that has nothing ready hands back an empty batch
        // rather than blocking the heartbeat behind a command that is not
        // there yet
        let mut quiet = tokio_stream::pending::<Result<proto::CloudMessage, tonic::Status>>();
        let mut batch = Vec::new();
        assert!(!drain_ready(&mut quiet, &mut batch, MAX_BATCH).await);
        assert!(batch.is_empty());
    }

    /// The cap is what keeps the other two branches of the select reachable:
    /// a cloud that never stops sending gets MAX_BATCH commands per wake-up
    /// and then has to let the heartbeat and the re-home probe run.
    #[tokio::test]
    async fn a_saturated_stream_still_yields_after_the_cap() {
        let flood: Vec<_> = (0..MAX_BATCH * 3)
            .map(|i| command(&i.to_string()))
            .collect();
        let mut stream = ready(flood);
        let mut batch = Vec::new();
        assert!(!drain_ready(&mut stream, &mut batch, MAX_BATCH).await);
        assert_eq!(batch.len(), MAX_BATCH);
    }

    /// A stream that is over says so, so the session ends instead of looping
    /// on an exhausted stream.
    #[tokio::test]
    async fn an_exhausted_stream_is_reported_as_ended() {
        let mut stream = ready(vec![command("a")]);
        let mut batch = Vec::new();
        assert!(drain_ready(&mut stream, &mut batch, MAX_BATCH).await);
        assert_eq!(batch.len(), 1, "and what was on it is still handled");
    }

    /// Only a command changes what this cluster looks like, so only a batch
    /// with one in it owes the cloud a status — a message this cluster does
    /// not understand must not cost a full status build.
    #[test]
    fn a_batch_without_a_command_asks_for_no_status() {
        assert!(commands(vec![proto::CloudMessage { kind: None }]).is_empty());
        assert!(commands(Vec::new()).is_empty());
    }

    /// Dropping it would be a short list, and a short list reads as a
    /// deletion. Losing the list's completeness is the cheap half of that
    /// trade; losing somebody's VM is the expensive one.
    #[test]
    fn a_cloud_vm_that_cannot_be_named_costs_the_list_its_completeness() {
        let mut vm = vm("orphan", None, VmPhaseKind::Running);
        vm.metadata
            .labels
            .insert("meister.io/managed-by".into(), "cloud".into());
        let mut complete = true;
        let out = report_cloud_vms(&[vm], &mut complete);
        assert!(out.is_empty());
        assert!(!complete);
    }

    fn cloud_volume(name: &str, uid: Option<&str>, phase: VolumePhaseKind) -> Volume {
        let mut v = new_volume(
            name,
            controller_api::VolumeSpec {
                pool: "fast".into(),
                size_gib: 10,
                tenant: "acme".into(),
                ..Default::default()
            },
        );
        if let Some(uid) = uid {
            v.metadata.mark_managed_by_cloud(uid);
        }
        v.status.node = Some("manacor".into());
        v.status.reported = Some(controller_api::VolumeReported::by(
            "manacor",
            phase,
            controller_api::VolumeReason::Unrecorded,
            None,
            Utc::now(),
        ));
        v.settle(Utc::now());
        v
    }

    /// What travels up: the cloud's own uid, the phase, where the bytes are
    /// and who holds them. Absence from a COMPLETE list is the cloud's proof
    /// of teardown, so a volume that cannot be named in the cloud's language
    /// costs the report its completeness rather than being left out quietly.
    #[test]
    fn the_volume_report_speaks_the_uids_the_cloud_handed_out() {
        let mut held = cloud_volume("data-1", Some("cloud-uid-1"), VolumePhaseKind::Ready);
        held.status.attached_to = Some("web-1".into());
        let volumes = vec![
            held,
            cloud_volume("data-2", Some("cloud-uid-2"), VolumePhaseKind::Provisioning),
            // Cluster-local: not the cloud's, and not in its report.
            cloud_volume("local-1", None, VolumePhaseKind::Ready),
        ];
        let mut complete = true;
        let report = report_cloud_volumes(&volumes, &mut complete);
        assert_eq!(
            report.len(),
            2,
            "the cluster-local one is nobody's business up there"
        );
        assert!(complete, "a cluster-local volume does not spoil the list");
        assert_eq!(report[0].uid, "cloud-uid-1");
        assert_eq!(report[0].phase, "Ready");
        assert_eq!(report[0].node, "manacor");
        assert_eq!(report[0].attached_to, "web-1");
        assert_eq!(report[1].phase, "Provisioning");
        assert!(report[1].attached_to.is_empty(), "nobody holds it");

        // A cloud-managed object with no cloud uid can never be named up
        // there, so it costs the list its completeness for as long as it
        // exists — the same rule the VM half follows.
        let mut broken = cloud_volume("data-3", None, VolumePhaseKind::Ready);
        broken.metadata.labels.insert(
            controller_api::LABEL_MANAGED_BY.to_string(),
            controller_api::MANAGED_BY_CLOUD.to_string(),
        );
        let mut complete = true;
        let report = report_cloud_volumes(&[broken], &mut complete);
        assert!(report.is_empty());
        assert!(!complete, "absence must not be read as teardown here");
    }

    /// The other half of storage A's first defect: `status.backend` is
    /// evidence, so it is empty until a node has said it — and once a node
    /// HAS said it, it has to reach the cloud, or the field would be a
    /// permanently empty one at the tier most operators read.
    ///
    /// The cloud cannot derive the string: `filesystem` says `<uid>.raw`,
    /// `lvm-thin` says `/dev/<vg>/vm-<uid>`, and the next backend will name
    /// its volumes without a path at all. So it travels, exactly like `node`.
    #[test]
    fn the_backend_name_travels_up_once_a_node_has_said_it() {
        let fresh = cloud_volume("data-1", Some("cloud-uid-1"), VolumePhaseKind::Pending);
        let mut complete = true;
        let report = report_cloud_volumes(std::slice::from_ref(&fresh), &mut complete);
        assert!(
            report[0].backend.is_empty(),
            "no node has made the bytes yet"
        );

        let mut made = fresh;
        made.status.backend = "/tmp/ms-e2e/vols/f8c1592d.raw".into();
        made.status.reported = Some(controller_api::VolumeReported::by(
            "manacor",
            VolumePhaseKind::Ready,
            controller_api::VolumeReason::Unrecorded,
            None,
            Utc::now(),
        ));
        made.settle(Utc::now());
        let report = report_cloud_volumes(&[made], &mut complete);
        assert_eq!(report[0].backend, "/tmp/ms-e2e/vols/f8c1592d.raw");
    }

    /// The last edge of the fleet topology. The cloud binds a VM to a
    /// CLUSTER; which machine inside it runs the VM was decided here and
    /// travelled nowhere, so the NODE column of every cloud-tier listing was
    /// a dash and the only topology view of the product stopped one level
    /// short.
    ///
    /// From the BINDING and not from a report: `spec.nodeName` is what this
    /// tier decided, and a VM nothing has placed yet honestly has no node.
    #[test]
    fn the_node_a_vm_landed_on_travels_up_with_its_phase() {
        let mut placed = vm("web-1", Some("cloud-uid-1"), VmPhaseKind::Running);
        placed.spec.node_name = Some("manacor".into());
        let unplaced = vm("web-2", Some("cloud-uid-2"), VmPhaseKind::Pending);

        let mut complete = true;
        let report = report_cloud_vms(&[placed, unplaced], &mut complete);
        assert_eq!(report[0].node, "manacor");
        assert!(
            report[1].node.is_empty(),
            "not placed is a state, not a machine"
        );
    }

    /// Report observed disk attachments and Pending reasons to the cloud.
    #[test]
    fn the_disks_a_node_really_has_open_travel_up_with_the_phase() {
        let mut hot_plugged = vm("mc-vm-c", Some("cloud-uid-1"), VmPhaseKind::Running);
        hot_plugged.status.volumes = vec![
            controller_api::VolumeAttachmentStatus {
                name: "mc-vol-b".into(),
                attached: true,
            },
            // Asked for and not there yet — the state the whole field exists
            // to make visible, and the one a boolean could not express.
            controller_api::VolumeAttachmentStatus {
                name: "mc-vol-hp".into(),
                attached: false,
            },
        ];
        let mut waiting = vm("mc-vm-d", Some("cloud-uid-2"), VmPhaseKind::Pending);
        // Through the mapping rather than past it: the scheduler's own
        // category is what a pass writes, and what travels up is the word the
        // object stores it under. As the FACT the pass writes, which is
        // `status.placement` — the phase follows from it.
        waiting.status.reported = None;
        waiting.status.placement = Some(controller_api::VmPlacement {
            reason: controller_api::PendingReason::NodeUnhealthy.category(),
            message: "every candidate has said something is wrong with itself".into(),
            at: Utc::now(),
        });
        waiting.settle(Utc::now());

        let mut complete = true;
        let report = report_cloud_vms(&[hot_plugged, waiting], &mut complete);
        assert_eq!(
            report[0]
                .volumes
                .iter()
                .map(|v| (v.name.as_str(), v.attached))
                .collect::<Vec<_>>(),
            [("mc-vol-b", true), ("mc-vol-hp", false)],
            "names and not uids: the cloud owns neither object and cannot resolve one"
        );
        assert!(
            report[0].reason.is_empty(),
            "a placed vm has no pending reason"
        );
        // `Unplaced` and no longer `node-unhealthy`: struktur 4 folded
        // `pendingReason` into the phase, and the closed set the object
        // stores is `VmReason`. The twelve scheduler words are unchanged and
        // still in the sentence and the metric label.
        assert_eq!(report[1].reason, "Unplaced");
        assert!(report[1].volumes.is_empty());
    }

    /// The MAC half of `Vm.status.addresses[]`, relayed to the cloud — which
    /// is where a tenant reads their VM, and until this field the only tier
    /// that never saw the address.
    ///
    /// Off the object and not out of a node's report, so it says exactly what
    /// this tier already wrote down. And only the MAC lines: the floating
    /// half is the cloud's own object, and sending it back up would be this
    /// tier answering with an older copy of the asker's own answer.
    #[test]
    fn the_macs_of_a_vms_taps_travel_up_and_the_floating_addresses_do_not() {
        let mut addressed = vm("mc-vm-e", Some("cloud-uid-3"), VmPhaseKind::Running);
        addressed.status.addresses = vec![
            controller_api::VmAddress {
                kind: controller_api::VmAddressKind::Mac,
                nic: "nics[0]".into(),
                mac: Some("52:54:00:11:22:33".into()),
                address: None,
            },
            controller_api::VmAddress {
                kind: controller_api::VmAddressKind::FloatingIp,
                nic: String::new(),
                mac: None,
                address: Some("192.0.2.7".into()),
            },
        ];
        let quiet = vm("mc-vm-f", Some("cloud-uid-4"), VmPhaseKind::Running);

        let mut complete = true;
        let report = report_cloud_vms(&[addressed, quiet], &mut complete);
        assert_eq!(
            report[0]
                .nics
                .iter()
                .map(|n| (n.name.as_str(), n.mac.as_str()))
                .collect::<Vec<_>>(),
            [("nics[0]", "52:54:00:11:22:33")],
            "the floating line is the cloud's own and does not travel back to it"
        );
        assert!(
            report[1].nics.is_empty(),
            "a vm no node has reported a tap for says nothing about addresses"
        );
    }

    /// The evidence half of `spec.sizeGib`. A resize is two steps on possibly
    /// two machines and can half-happen; without this the cloud answers a
    /// resize with the number that was asked for rather than the one that
    /// happened.
    #[test]
    fn the_measured_size_travels_up_beside_the_asked_for_one() {
        let mut grown = cloud_volume("data-1", Some("cloud-uid-1"), VolumePhaseKind::Ready);
        grown.status.size_gib = 6;
        let mut complete = true;
        let report = report_cloud_volumes(std::slice::from_ref(&grown), &mut complete);
        assert_eq!(report[0].size_gib, 6, "what the node measured");

        let fresh = cloud_volume("data-2", Some("cloud-uid-2"), VolumePhaseKind::Pending);
        let report = report_cloud_volumes(&[fresh], &mut complete);
        assert_eq!(report[0].size_gib, 0, "nobody has measured it yet");
    }

    /// The snapshot half of the same report, and the same two rules — because
    /// absence from a COMPLETE list is what lets the cloud remove its own
    /// object, and a short list would read up there as "the copy is gone"
    /// about bytes that are still on a disk.
    #[test]
    fn the_snapshots_a_cluster_holds_for_the_cloud_are_named_in_its_uids() {
        let snapshot = |name: &str, uid: Option<&str>| {
            let mut s = controller_api::new_volume_snapshot(
                name,
                controller_api::VolumeSnapshotSpec {
                    tenant: "acme".into(),
                    volume: "data-1".into(),
                    description: String::new(),
                },
            );
            if let Some(uid) = uid {
                s.metadata.mark_managed_by_cloud(uid);
            }
            s
        };

        let mut ours = snapshot("nightly-1", Some("cloud-uid-1"));
        ours.status.reported = Some(controller_api::VolumeSnapshotReported::by(
            "manacor",
            controller_api::VolumeSnapshotPhaseKind::Ready,
            controller_api::VolumeSnapshotReason::Unrecorded,
            None,
            Utc::now(),
        ));
        ours.settle(Utc::now());
        ours.status.node = Some("manacor".into());
        ours.status.backend = "/dev/vg0/snap-nightly-1".into();
        ours.status.size_gib = 4;
        let local = snapshot("local-1", None);

        let mut complete = true;
        let report = report_cloud_snapshots(&[ours, local], &mut complete);
        assert_eq!(report.len(), 1, "a cluster-local copy is nobody's up there");
        assert!(complete);
        assert_eq!(report[0].uid, "cloud-uid-1");
        assert_eq!(report[0].phase, "Ready");
        assert_eq!(report[0].node, "manacor");
        assert_eq!(report[0].backend, "/dev/vg0/snap-nightly-1");
        assert_eq!(report[0].size_gib, 4);

        // Marked as the cloud's, unnameable in the cloud's language: the list
        // loses its completeness rather than the object being left out.
        let mut broken = snapshot("nightly-2", None);
        broken.metadata.labels.insert(
            controller_api::LABEL_MANAGED_BY.to_string(),
            controller_api::MANAGED_BY_CLOUD.to_string(),
        );
        let mut complete = true;
        let report = report_cloud_snapshots(&[broken], &mut complete);
        assert!(report.is_empty());
        assert!(!complete, "absence must not be read as teardown here");
    }
    /// A cloud migration request creates local migration intent; this cluster's
    /// reconciler selects the target and drives the same transfer workflow.
    #[tokio::test]
    async fn a_migration_asked_for_at_the_cloud_arrives_as_the_object_it_would_have_been() {
        let ask = |target: &str| proto::CreateVmMigration {
            name: "web-1-20260910t120000".into(),
            vm: "web-1".into(),
            target_node: target.into(),
            tenant: "acme".into(),
            vm_uid: "uid-web-1".into(),
        };
        // proto3 has no absent string, so empty IS "did not say" — and the
        // difference between `--to agent-3` and no `--to` at all is this line.
        assert_eq!(migration_target(&ask("")), None);
        assert_eq!(migration_target(&ask("agent-3")), Some("agent-3"));

        // The two refusals, which are answered before anything is read: a
        // command that names no record or no guest is a bug one tier up, and
        // the cloud shows the sentence.
        let store = EtcdStore::connect(&["http://127.0.0.1:1".to_string()], "/migration-test")
            .await
            .expect("the etcd client is built lazily");
        let nameless = proto::CreateVmMigration {
            name: String::new(),
            ..ask("")
        };
        let why = format!(
            "{:#}",
            handle_create_vm_migration(&store, nameless)
                .await
                .expect_err("a record with no name")
        );
        assert!(why.contains("name for the record"), "{why}");

        let vmless = proto::CreateVmMigration {
            vm: String::new(),
            ..ask("")
        };
        let why = format!(
            "{:#}",
            handle_create_vm_migration(&store, vmless)
                .await
                .expect_err("nothing to move")
        );
        assert!(why.contains("vm to move"), "{why}");

        // IKR-B81: a cloud that does not say which vm it means gets none moved
        // by its name.
        let uidless = proto::CreateVmMigration {
            vm_uid: String::new(),
            ..ask("")
        };
        let why = format!(
            "{:#}",
            handle_create_vm_migration(&store, uidless)
                .await
                .expect_err("which vm?")
        );
        assert!(why.contains("uid"), "{why}");
    }

    /// IKR-B72: a migrate asked for at the cloud meets the REST edge's whole refusal, with its
    /// word (`Invalid`), and no record is written. An instance-store disk and a node-local
    /// volume were refused only at the REST edge before.
    #[tokio::test]
    #[ignore = "needs an etcd; see crate::test_etcd"]
    async fn a_migration_asked_for_at_the_cloud_meets_the_rest_edges_refusal() {
        let store = crate::test_etcd::fresh_store("cloud-migration-test").await;
        let mut pool = controller_api::StoragePool::declare("fast", Default::default());
        pool.status.locality = Some(controller_api::Locality::NodeLocal);
        store.create(&pool).await.expect("the pool");
        store
            .create(&cloud_volume("data", None, VolumePhaseKind::Ready))
            .await
            .expect("the volume");

        for (name, disks, why) in [
            (
                "inline",
                serde_json::json!([{ "size_bytes": 1 }]),
                "instance-store",
            ),
            (
                "pinned",
                serde_json::json!([{ "volume": "data" }]),
                "node-local",
            ),
        ] {
            let mut guest = vm(name, Some(name), VmPhaseKind::Running);
            guest.spec.node_name = Some("manacor".into());
            guest.spec.vm = serde_json::json!({ "volumes": disks });
            store.create(&guest).await.expect("the guest");
            let record = format!("{name}-move");
            let ask = proto::CreateVmMigration {
                name: record.clone(),
                vm: name.into(),
                target_node: String::new(),
                tenant: "acme".into(),
                vm_uid: name.into(),
            };
            let err = handle_create_vm_migration(&store, ask)
                .await
                .expect_err("the REST edge would refuse it");
            assert_eq!(controller_api::Refused::reason_of(&err), "Invalid");
            assert!(format!("{err:#}").contains(why), "{err:#}");
            assert!(
                store
                    .get::<controller_api::VmMigration>(&record)
                    .await
                    .is_err(),
                "and nothing was started"
            );
        }
    }

    /// Repeated cloud creation updates an existing volume to the larger size.
    #[tokio::test]
    #[ignore = "needs an etcd; see crate::test_etcd"]
    async fn a_create_for_a_volume_this_tier_holds_carries_the_grown_size() {
        let store = crate::test_etcd::fresh_store("cloud-volume-test").await;

        handle_create_volume(&store, create_volume("u-1", 10))
            .await
            .expect("made");
        handle_create_volume(&store, create_volume("u-1", 20))
            .await
            .expect("the cloud grew it");
        let held: Volume = store.get("data").await.expect("the volume");
        assert_eq!(held.spec.size_gib, 20, "the cloud's intent is this tier's");
        assert_eq!(held.metadata.generation, 2);
        assert_eq!(held.metadata.uid, "u-1", "and it is still the same bytes");

        // A late, older create does not shrink anything.
        handle_create_volume(&store, create_volume("u-1", 10))
            .await
            .expect("a repeat is acked");
        let held: Volume = store.get("data").await.expect("the volume");
        assert_eq!(held.spec.size_gib, 20);
        assert_eq!(held.metadata.generation, 2);
    }

    /// The cloud's create for the volume `data` of `size_gib` in the pool `fast`, as `uid`.
    fn create_volume(uid: &str, size_gib: u64) -> proto::CreateVolume {
        proto::CreateVolume {
            name: "data".into(),
            spec_json: serde_json::to_string(&controller_api::VolumeSpec {
                pool: "fast".into(),
                size_gib,
                ..Default::default()
            })
            .unwrap(),
            uid: uid.into(),
            tenant: "acme".into(),
        }
    }

    /// A release judged on a record that was replaced under the same name before the write
    /// takes nothing from the new record: its finalizer stays and it is not deleted. (R2-2)
    #[tokio::test]
    #[ignore = "needs an etcd; see crate::test_etcd"]
    async fn a_release_judged_on_an_old_record_leaves_the_recreated_one_alone() {
        let store = crate::test_etcd::fresh_store("cloud-release-test").await;
        handle_create_volume(&store, create_volume("u-1", 1))
            .await
            .expect("the cloud's volume");
        let checked: Volume = store
            .get("data")
            .await
            .expect("the record the release read");
        store.delete::<Volume>("data").await.expect("it goes");
        handle_create_volume(&store, create_volume("u-2", 1))
            .await
            .expect("another cloud volume under the same name");
        let release = proto::ReleaseVolume {
            name: "data".into(),
            uid: "u-1".into(),
        };

        release_record(&store, &checked, &release)
            .await
            .expect("nothing of u-1 is left here, which is a release done");

        let still: Volume = store.get("data").await.expect("the new record");
        assert_eq!(still.metadata.uid, "u-2");
        assert!(
            still
                .metadata
                .finalizers
                .contains(&controller_api::VOLUME_RELEASE_FINALIZER.to_string())
        );
    }

    /// The record the release names goes, finalizer and all: the guard is not a wall. (R2-2)
    #[tokio::test]
    #[ignore = "needs an etcd; see crate::test_etcd"]
    async fn a_release_of_the_current_record_removes_it() {
        let store = crate::test_etcd::fresh_store("cloud-release-test").await;
        handle_create_volume(&store, create_volume("u-1", 1))
            .await
            .expect("the cloud's volume");
        let release = proto::ReleaseVolume {
            name: "data".into(),
            uid: "u-1".into(),
        };

        handle_release_volume(&store, release)
            .await
            .expect("released");

        assert!(matches!(
            store.get::<Volume>("data").await,
            Err(StoreError::NotFound(_))
        ));
    }

    /// `obj` stored as the cloud's object `cloud_uid`.
    async fn stored_for_the_cloud<T: controller_api::Resource>(
        store: &EtcdStore,
        mut obj: T,
        cloud_uid: &str,
    ) -> T {
        obj.metadata_mut().mark_managed_by_cloud(cloud_uid);
        store.create(&obj).await.expect("the cloud's record")
    }

    fn secret() -> controller_api::Secret {
        controller_api::Secret::declare("db", Default::default())
    }

    fn router() -> Router {
        Router::declare("out", Default::default())
    }

    /// A secret delete judged on a record that was replaced under the same name before the
    /// delete leaves the new record alone. (NL2-6)
    #[tokio::test]
    #[ignore = "needs an etcd; see crate::test_etcd"]
    async fn a_secret_delete_judged_on_an_old_record_leaves_the_recreated_one_alone() {
        let store = crate::test_etcd::fresh_store("cloud-delete-test").await;
        let checked = stored_for_the_cloud(&store, secret(), "u-1").await;
        store
            .delete::<controller_api::Secret>("db")
            .await
            .expect("it goes");
        stored_for_the_cloud(&store, secret(), "u-2").await;

        delete_cloud_record(&store, &checked, "u-1")
            .await
            .expect("nothing of u-1 is left here, which is a delete done");

        let still: controller_api::Secret = store.get("db").await.expect("the new record");
        assert_eq!(still.metadata.cloud_uid(), Some("u-2"));
    }

    /// A router delete judged on a record that was replaced under the same name before the
    /// delete leaves the new record alone. (NL2-6)
    #[tokio::test]
    #[ignore = "needs an etcd; see crate::test_etcd"]
    async fn a_router_delete_judged_on_an_old_record_leaves_the_recreated_one_alone() {
        let store = crate::test_etcd::fresh_store("cloud-delete-test").await;
        let checked = stored_for_the_cloud(&store, router(), "u-1").await;
        store.delete::<Router>("out").await.expect("it goes");
        stored_for_the_cloud(&store, router(), "u-2").await;

        delete_cloud_record(&store, &checked, "u-1")
            .await
            .expect("nothing of u-1 is left here, which is a delete done");

        let still: Router = store.get("out").await.expect("the new record");
        assert_eq!(still.metadata.cloud_uid(), Some("u-2"));
    }

    /// A delete whose record was recreated for the same cloud object is not acked: that object
    /// is still here, and the cloud retries. (NL2-6)
    #[tokio::test]
    #[ignore = "needs an etcd; see crate::test_etcd"]
    async fn a_delete_is_not_acked_while_the_clouds_object_is_still_here() {
        let store = crate::test_etcd::fresh_store("cloud-delete-test").await;
        let checked = stored_for_the_cloud(&store, secret(), "u-1").await;
        store
            .delete::<controller_api::Secret>("db")
            .await
            .expect("it goes");
        let fresh = stored_for_the_cloud(&store, secret(), "u-1").await;

        delete_cloud_record(&store, &checked, "u-1")
            .await
            .expect_err("the record judged is gone, the cloud's object is not");

        let still: controller_api::Secret = store.get("db").await.expect("the new record");
        assert_eq!(still.metadata.uid, fresh.metadata.uid);
    }

    /// The secret the delete names goes: the guard is not a wall. (NL2-6)
    #[tokio::test]
    #[ignore = "needs an etcd; see crate::test_etcd"]
    async fn a_delete_of_the_current_secret_removes_it() {
        let store = crate::test_etcd::fresh_store("cloud-delete-test").await;
        stored_for_the_cloud(&store, secret(), "u-1").await;
        let delete = proto::DeleteSecret {
            name: "db".into(),
            uid: "u-1".into(),
        };

        handle_delete_secret(&store, delete).await.expect("deleted");

        assert!(matches!(
            store.get::<controller_api::Secret>("db").await,
            Err(StoreError::NotFound(_))
        ));
    }

    /// IKR-B68 at this hop: a floating address whose inside end is not a
    /// guest on the router's own inside prefix is refused, whatever the cloud
    /// sent; one inside it passes, and a routed prefix is no such address.
    #[test]
    fn a_floating_address_outside_the_routers_prefix_is_refused_here() {
        let router = Router::declare(
            "lab-out",
            controller_api::RouterSpec {
                internal_addr: "10.42.0.1/24".into(),
                ..Default::default()
            },
        );
        let carrying = |kind: &str, logical_ip: &str| proto::CreateRouter {
            name: "lab-out".into(),
            nats: vec![proto::NatRule {
                kind: kind.into(),
                external_ip: "10.128.1.201".into(),
                logical_ip: logical_ip.into(),
            }],
            ..Default::default()
        };
        let e = cloud_nats(&carrying("dnat_and_snat", "10.43.0.5"), &router)
            .expect_err("another prefix");
        assert!(format!("{e:#}").contains("10.128.1.201"), "{e:#}");
        assert!(cloud_nats(&carrying("dnat_and_snat", "10.42.0.1"), &router).is_err());
        assert!(cloud_nats(&carrying("dnat_and_snat", "10.42.0.9"), &router).is_ok());
        assert!(cloud_nats(&carrying("routed", "10.43.0.0/24"), &router).is_ok());
    }

    /// The router the delete names goes: the guard is not a wall. (NL2-6)
    #[tokio::test]
    #[ignore = "needs an etcd; see crate::test_etcd"]
    async fn a_delete_of_the_current_router_removes_it() {
        let store = crate::test_etcd::fresh_store("cloud-delete-test").await;
        stored_for_the_cloud(&store, router(), "u-1").await;
        let delete = proto::DeleteRouter {
            name: "out".into(),
            uid: "u-1".into(),
        };

        handle_delete_router(&store, delete).await.expect("deleted");

        assert!(matches!(
            store.get::<Router>("out").await,
            Err(StoreError::NotFound(_))
        ));
    }

    /// IKR-B71 at this tier: the node selector, anti-affinity, class and labels the cloud was
    /// given arrive on the stored object, move with a later create, and are what this tier's
    /// scheduler places by.
    #[tokio::test]
    #[ignore = "needs an etcd; see crate::test_etcd"]
    async fn a_cloud_vm_is_placed_here_by_the_constraints_the_cloud_was_given() {
        let store = crate::test_etcd::fresh_store("cloud-placement-test").await;
        let asking = |zone: &str| proto::CreateVm {
            spec_json: serde_json::json!({
                "tenant": "acme",
                "class": "gpu",
                "nodeSelector": { "network-node": zone },
                "antiAffinity": [{ "selector": { "app": "web" } }],
                "vm": { "vcpus": 1, "memory_mib": 512 },
            })
            .to_string(),
            labels: [("app".to_string(), "web".to_string())].into(),
            ..create(None, &[], &[])
        };
        handle_create(&store, asking("cobra3"), "")
            .await
            .expect("created");
        let stored: Vm = store.get("web-1").await.expect("the cloud's vm");
        assert_eq!(stored.metadata.labels["app"], "web");
        assert_eq!(stored.metadata.cloud_uid(), Some("uid-1"));

        // What each node holds: (tenant, app) of every VM on it.
        let node = |name: &str, zone: &str, hosted: &[(&str, &str)]| controller_api::Candidate {
            name: name.into(),
            connected: true,
            alive: true,
            schedulable: true,
            unhealthy: Vec::new(),
            free: controller_api::Capacity {
                vcpus: 8,
                mem_mib: 8192,
            },
            catalogue: vec!["hypervisor/cloud-hypervisor".to_string()],
            kind: controller_api::CandidateKind::Node,
            labels: [("network-node".to_string(), zone.to_string())].into(),
            accepts: vec!["gpu".to_string()],
            hosted: hosted
                .iter()
                .map(|(tenant, app)| controller_api::Hosted {
                    tenant: Some(tenant.to_string()),
                    labels: [("app".to_string(), app.to_string())].into(),
                })
                .collect(),
            machine: None,
        };
        let fleet = [
            node("cobra2", "cobra2", &[]),
            node("cobra3b", "cobra3", &[("acme", "web")]),
            node("cobra3", "cobra3", &[("umbrella", "web")]),
        ];
        assert_eq!(
            controller_api::Scheduler::assign(&controller_api::FirstFit, &stored, &fleet),
            Some("cobra3".to_string()),
            "the labelled node, and not the one already holding a web of its own tenant; \
             another tenant's web is not one it can mean"
        );

        handle_create(&store, asking("cobra2"), "")
            .await
            .expect("the cloud moved the selector");
        let moved: Vm = store.get("web-1").await.expect("the cloud's vm");
        assert_eq!(moved.spec.node_selector["network-node"], "cobra2");
        assert_eq!(moved.metadata.cloud_uid(), Some("uid-1"), "the marks stay");
    }

    /// IKR-B71: a create that differs only in its labels is drift, and the
    /// cluster's copy takes the new labels under its own marks.
    #[tokio::test]
    #[ignore = "needs an etcd; see crate::test_etcd"]
    async fn a_label_only_resend_relabels_the_cloud_vm_here() {
        let store = crate::test_etcd::fresh_store("cloud-placement-test").await;
        let labelled = |app: &str| proto::CreateVm {
            spec_json: serde_json::json!({ "vm": { "vcpus": 1, "memory_mib": 512 } }).to_string(),
            labels: [("app".to_string(), app.to_string())].into(),
            ..create(None, &[], &[])
        };
        handle_create(&store, labelled("web"), "")
            .await
            .expect("created");
        let before: Vm = store.get("web-1").await.expect("the cloud's vm");

        handle_create(&store, labelled("db"), "")
            .await
            .expect("relabelled");

        let after: Vm = store.get("web-1").await.expect("the cloud's vm");
        assert_eq!(after.metadata.labels["app"], "db");
        assert_eq!(after.metadata.cloud_uid(), Some("uid-1"), "the marks stay");
        assert_eq!(
            after.metadata.generation, before.metadata.generation,
            "labels are no new spec"
        );
    }

    /// IKR-B81: a volume destroy judged on a record that was replaced under the same name
    /// leaves the new record unmarked, as a VM destroy does (NL3-3).
    #[tokio::test]
    #[ignore = "needs an etcd; see crate::test_etcd"]
    async fn a_volume_destroy_judged_on_an_old_record_leaves_the_recreated_one_unmarked() {
        let store = crate::test_etcd::fresh_store("cloud-destroy-test").await;
        let checked = store
            .create(&cloud_volume("data", Some("u-1"), VolumePhaseKind::Ready))
            .await
            .expect("the cloud's volume");
        store.delete::<Volume>("data").await.expect("it goes");
        store
            .create(&cloud_volume("data", Some("u-2"), VolumePhaseKind::Ready))
            .await
            .expect("another cloud volume of that name");

        let outcome = mark_for_teardown(&store, &checked, "u-1")
            .await
            .expect("nothing of u-1 is left here, which is a destroy done");

        assert_eq!(
            outcome,
            Teardown::NothingLeft,
            "and it is not said to be marked"
        );
        let still: Volume = store.get("data").await.expect("the new volume");
        assert_eq!(still.metadata.cloud_uid(), Some("u-2"));
        assert!(!still.is_deleting());
    }

    /// IKR-B81: a migrate from the cloud moves the cloud's vm and not a
    /// cluster-local one that carries its name.
    #[tokio::test]
    #[ignore = "needs an etcd; see crate::test_etcd"]
    async fn a_cloud_migration_does_not_move_a_cluster_local_vm_of_the_same_name() {
        let store = crate::test_etcd::fresh_store("cloud-migration-test").await;
        let mut local = vm("web-1", None, VmPhaseKind::Running);
        local.spec.node_name = Some("manacor".into());
        store.create(&local).await.expect("the cluster's own vm");
        let ask = proto::CreateVmMigration {
            name: "web-1-move".into(),
            vm: "web-1".into(),
            target_node: String::new(),
            tenant: "acme".into(),
            vm_uid: "uid-cloud-web-1".into(),
        };

        let why = handle_create_vm_migration(&store, ask)
            .await
            .expect_err("not the cloud's to move");
        assert!(format!("{why:#}").contains("not the cloud's"), "{why:#}");
        assert!(
            store
                .get::<controller_api::VmMigration>("web-1-move")
                .await
                .is_err()
        );
    }

    /// The running VM `t`, stored as the cloud's object `cloud_uid`.
    async fn stored_vm(store: &EtcdStore, cloud_uid: &str) -> Vm {
        store
            .create(&vm("t", Some(cloud_uid), VmPhaseKind::Running))
            .await
            .expect("the cloud's vm")
    }

    /// A destroy judged on a VM that was replaced under the same name before the write leaves
    /// the new VM unmarked. (NL3-3)
    #[tokio::test]
    #[ignore = "needs an etcd; see crate::test_etcd"]
    async fn a_destroy_judged_on_an_old_vm_leaves_the_recreated_one_unmarked() {
        let store = crate::test_etcd::fresh_store("cloud-destroy-test").await;
        let checked = stored_vm(&store, "u-1").await;
        store.delete::<Vm>("t").await.expect("it goes");
        stored_vm(&store, "u-2").await;

        let outcome = mark_for_teardown(&store, &checked, "u-1")
            .await
            .expect("nothing of u-1 is left here, which is a destroy done");

        assert_eq!(
            outcome,
            Teardown::NothingLeft,
            "and it is not said to be marked"
        );
        let still: Vm = store.get("t").await.expect("the new vm");
        assert_eq!(still.metadata.cloud_uid(), Some("u-2"));
        assert!(!still.is_deleting());
    }

    /// A destroy whose VM was recreated for the same cloud object is not acked while that VM is
    /// unmarked: the cloud retries and marks it. (NL3-3)
    #[tokio::test]
    #[ignore = "needs an etcd; see crate::test_etcd"]
    async fn a_destroy_is_not_acked_while_the_clouds_vm_is_unmarked() {
        let store = crate::test_etcd::fresh_store("cloud-destroy-test").await;
        let checked = stored_vm(&store, "u-1").await;
        store.delete::<Vm>("t").await.expect("it goes");
        let fresh = stored_vm(&store, "u-1").await;

        mark_for_teardown(&store, &checked, "u-1")
            .await
            .expect_err("the vm judged is gone, the cloud's vm is not");

        let still: Vm = store.get("t").await.expect("the new vm");
        assert_eq!(still.metadata.uid, fresh.metadata.uid);
        assert!(!still.is_deleting());
    }

    /// The judged VM is marked, and says so. (IKR-B81)
    #[tokio::test]
    #[ignore = "needs an etcd; see crate::test_etcd"]
    async fn a_mark_on_the_judged_vm_is_said_to_be_marked() {
        let store = crate::test_etcd::fresh_store("cloud-destroy-test").await;
        let checked = stored_vm(&store, "u-1").await;

        let outcome = mark_for_teardown(&store, &checked, "u-1")
            .await
            .expect("marked");

        assert_eq!(outcome, Teardown::Marked);
        let marked: Vm = store.get("t").await.expect("the vm, until its teardown");
        assert!(marked.is_deleting());
    }

    /// The VM the destroy names is marked for teardown: the guard is not a wall. (NL3-3)
    #[tokio::test]
    #[ignore = "needs an etcd; see crate::test_etcd"]
    async fn a_destroy_of_the_current_vm_marks_it_for_teardown() {
        let store = crate::test_etcd::fresh_store("cloud-destroy-test").await;
        stored_vm(&store, "u-1").await;
        let destroy = proto::DestroyVm {
            name: "t".into(),
            uid: "u-1".into(),
        };

        handle_destroy(&store, destroy).await.expect("marked");

        let marked: Vm = store.get("t").await.expect("the vm, until its teardown");
        assert!(marked.is_deleting());
    }
}
