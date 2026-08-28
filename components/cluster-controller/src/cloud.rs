// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! The cloud session: this cluster dials out to the cloud-controller and from
//! then on the stream carries its status upwards and the cloud's VM
//! assignments downwards. Exactly the shape the agent uses towards this
//! controller — dial-out, Hello, a status every ten seconds and after every
//! batch of commands, commands answered with a CommandResult — one tier up.
//!
//! The cloud may be several replicas behind one etcd, and which of them this
//! cluster dials is nobody's decision but its own: `hash(cluster_name ++
//! endpoint)` gives a preference order over the configured list, failover
//! walks down it, and the cloud replicas keep no registry of who serves whom.
//! Same mechanism as the agent one tier down, same shared `hrw`.
//!
//! A cloud address is optional. Without one the cluster is standalone, which
//! is how it ran before M4 and how it goes on running when the cloud is away.

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, anyhow, bail};
use chrono::Utc;
use controller_api::{EtcdStore, Node, StoreError, Vm, VmSpec, resources::new_vm};
use macros::generated;
use proto::cluster_plane_client::ClusterPlaneClient;
use proto::{
    ClusterCapacity, ClusterHello, ClusterMessage, ClusterStatus, CommandResult, VmStatusReport,
    cloud_command, cloud_message, cluster_message,
};
use tokio::sync::mpsc;
use tokio_stream::{Stream, StreamExt, wrappers::ReceiverStream};
use tracing::{debug, error, info, instrument, warn};

use crate::logs::{self, Logs};
use crate::session::SessionRegistry;

/// How often the cluster reports even when nothing happened. Doubles as the
/// heartbeat: the cloud expires a cluster after 30s without one, so this has
/// to stay comfortably below that.
const STATUS_INTERVAL: Duration = Duration::from_secs(10);

/// How often a cluster that is NOT on its favourite looks whether a better
/// endpoint has come back.
///
/// This is the one place where copying the agent's loop is not enough, and the
/// reason is that the id being hashed is shared here. One tier down the id is a
/// node id and exactly one process owns it, so an agent drifting a position
/// down its order only moves load. Up here every replica of a cluster hashes
/// the same `cluster_name`, and the cloud's ownership guard is exclusive only
/// while they all land on the SAME entry of that shared order — a replica whose
/// stream broke alone would otherwise sit one position down for as long as that
/// session stayed healthy, and its cluster would have two owners in the cloud,
/// each dispatching to it and each mirroring status onto the same objects.
///
/// Probed rather than assumed: a healthy session is given up only when there is
/// something better to give it up for.
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
#[generated(model = ClaudeOpus, version = "5")]
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

#[generated(model = ClaudeOpus, version = "5")]
/// `registry` is this cluster's own agent sessions. The cloud can ask for a
/// VM's console and the only party that has one is the node, so the answer to
/// a command arriving on THIS session is fetched over one of those.
pub async fn run(
    store: Arc<EtcdStore>,
    registry: Arc<SessionRegistry>,
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
        if let Some(wait) = redial.ended(established) {
            warn!(?wait, endpoints = of, "no cloud replica answered, waiting");
            tokio::time::sleep(wait).await;
        }
    }
}

#[generated(model = ClaudeOpus, version = "5")]
#[instrument(skip_all, fields(endpoint = %cloud_addr, cluster = %cluster_name))]
#[allow(clippy::too_many_arguments)]
async fn session(
    store: &Arc<EtcdStore>,
    registry: &SessionRegistry,
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

    // Status and commands share one task on purpose, and this is the reason:
    // the cloud stamps a status when it arrives and then treats a status
    // younger than its own last command as evidence about the VMs named in
    // it. That only holds if a status *sent* after a command was also *built*
    // after it. A separate status task would read the store, lose the race to
    // a command landing, and ship a snapshot from before it — and a snapshot
    // that does not name a VM is how this protocol says "torn down".
    //
    // The price is that a command which cannot complete also stops the
    // heartbeat. That is the right price: a cluster that cannot do work is
    // not a cluster that is merely busy.
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
                let mut acted = false;
                for cmd in commands(batch) {
                    let result = dispatch(store, registry, cmd).await;
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
#[generated(model = ClaudeOpus, version = "5")]
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

/// The commands of a batch, in arrival order. Anything else the cloud says
/// changes nothing about this cluster and therefore owes it no status — which
/// is why the caller reads "did we act" off this list and not off the batch.
#[generated(model = ClaudeOpus, version = "5")]
fn commands(batch: Vec<proto::CloudMessage>) -> Vec<proto::CloudCommand> {
    batch
        .into_iter()
        .filter_map(|msg| match msg.kind {
            Some(cloud_message::Kind::Command(cmd)) => Some(cmd),
            _ => None,
        })
        .collect()
}

#[generated(model = ClaudeOpus, version = "5")]
/// The cloud's context, if it sent one; its own root if not. Recorded on the
/// span so the fmt log carries it either way, and attached as the real parent
/// before the span starts (`telemetry::in_trace`).
async fn dispatch(
    store: &EtcdStore,
    registry: &SessionRegistry,
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
        dispatch_traced(store, registry, cmd, context),
    )
    .await
}

#[generated(model = ClaudeOpus, version = "5")]
async fn dispatch_traced(
    store: &EtcdStore,
    registry: &SessionRegistry,
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
        Some(cloud_command::Op::Logs(l)) => handle_logs(store, registry, l, &traceparent).await,
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
            })
        }
    };
    CommandResult {
        request_id,
        outcome: Some(outcome),
    }
}

/// Everything the cloud resolved, written into the NIC entries of the spec
/// before the object is stored.
///
/// One place, three facts, and the same argument for all three: the tenant,
/// its addresses and its subnets are control-plane truths, the objects that
/// hold them live one tier up, and by the time a spec reaches a node it should
/// say plainly which wire this VM is on and which addresses it may source
/// from. From here down nothing knows what a tenant is.
///
/// Before the object is written and therefore before the scheduler reads it,
/// which matters for `vxlan_id`: it is what says the VM needs a node with an
/// overlay. The two address lists constrain no placement — every node enforces
/// them, so there is nothing to schedule around — and they are here because
/// this is where the spec is made whole.
///
/// All three are read at create time and become part of the spec the node
/// stores, which is immutable once it has it: a VM created after an assignment
/// has it, and an existing one picks it up when it is RECREATED. A live
/// re-home is a documented nice-to-have and not this milestone's job; see
/// `controller_api::floating::inject_nic_list`.
#[generated(model = ClaudeOpus, version = "5")]
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

/// A cloud VM becomes an ordinary cluster VM carrying the cloud's marks: from
/// here on the cluster's own reconciler schedules it, dispatches it and tears
/// it down like any other, and the marks are only there to say whose it is.
///
/// Acked after the store write, never after the boot — the phase makes its own
/// way back up through ClusterStatus, exactly as the agent's phase makes its
/// way up to here.
/// The cloud asked what a VM printed; the node is what has it.
///
/// The uid guard is the same one `handle_create` and `handle_destroy` carry
/// and for the same reason: a name is a label people reuse, and answering
/// about a cluster-local VM that happens to share one would hand the cloud
/// somebody else's console. A VM that is not placed yet, or one this cluster
/// does not have at all, answers with an empty document rather than an error
/// — there is genuinely nothing to show, and that is not a failure.
#[generated(model = ClaudeOpus, version = "5")]
async fn handle_logs(
    store: &EtcdStore,
    registry: &SessionRegistry,
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
    match logs::fetch(registry, &vm, cmd.lines, traceparent).await? {
        Logs::From(payload) => Ok(payload),
        Logs::NotYet(_) => Ok(logs::NO_STREAMS.to_vec()),
    }
}

#[generated(model = ClaudeOpus, version = "5")]
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

    // The truth is made at the edge. The cloud resolved the tenant's VNI and
    // sent it alongside; this is where it becomes part of the spec, before
    // the object is written and therefore before the scheduler reads it —
    // which matters, because `nics[].vxlan_id` is what says the VM needs a
    // node with an overlay. From here down nothing knows what a tenant is.
    bind_nics(&c, &mut spec.vm);

    let mut vm = new_vm(
        &c.name,
        VmSpec {
            // Both bindings are this tier's to make, and the cloud's is not ours
            // to keep a copy of.
            node_name: None,
            cluster_name: None,
            ..spec.clone()
        },
    );
    vm.metadata.mark_managed_by_cloud(&c.uid);
    // The cloud's trace comes down onto this tier's object, so the cluster's
    // own reconciler — which will pick this VM up from its store later, out
    // of any call stack — lands in the same trace as the POST that started it.
    if !traceparent.is_empty() {
        vm.metadata.set_traceparent(traceparent);
    }
    match store.create(&vm).await {
        Ok(_) => {
            info!(vm = %c.name, "created for the cloud");
            return Ok(());
        }
        Err(StoreError::AlreadyExists(_)) => {}
        Err(e) => return Err(e.into()),
    }

    // The name is taken, and whose it is decides everything. A create is
    // idempotent for the object it created itself — a lost ack, a reconnect,
    // a repeat after the cloud lost sight of it — and refused for anything
    // else: adopting on the name alone would hand this VM somebody else's
    // disk and report it as healthy.
    let current: Vm = store.get(&c.name).await?;
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
    // The spec itself is immutable once a node has it — that is the agent's
    // rule and it does not get softer up here. Only the intent can move.
    if current.spec.run_strategy == spec.run_strategy {
        return Ok(());
    }
    store
        .mutate::<Vm, _>(&c.name, |v| v.spec.run_strategy = spec.run_strategy)
        .await?;
    info!(vm = %c.name, strategy = ?spec.run_strategy, "run strategy updated from the cloud");
    Ok(())
}

/// The cloud's delete becomes this tier's delete: a deletionTimestamp, and the
/// existing finalizer flow does the rest. Nothing new tears anything down.
#[generated(model = ClaudeOpus, version = "5")]
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
    store
        .mutate::<Vm, _>(&d.name, |v| {
            if v.metadata.deletion_timestamp.is_none() {
                v.metadata.deletion_timestamp = Some(Utc::now());
            }
        })
        .await?;
    info!(vm = %d.name, "marked for teardown by the cloud");
    Ok(())
}

/// Build one status and put it on the stream. False means the session is gone.
///
/// A status that cannot be built is not sent at all rather than sent hollow:
/// everything the cloud does with this message it does on the assumption that
/// the cluster could read its own store. Missing beats wrong, and a heartbeat
/// that stops is exactly the signal a cluster in that state should be giving.
#[generated(model = ClaudeOpus, version = "5")]
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
#[generated(model = ClaudeOpus, version = "5")]
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
    // Absence from this list is what the cloud accepts as proof that a VM was
    // torn down, and `list` drops what it cannot decode. A short list would
    // read up there as a deletion, so the completeness travels with it and the
    // cloud concludes nothing from a list that is not all of them.
    let mut complete = vms.len() == store.count::<Vm>().await?;
    let reported = report_cloud_vms(&vms, &mut complete);

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
        // Passed through unchanged: this tier keeps no Image objects, and a
        // cluster that reworded what its nodes said would be a tier that
        // could get it wrong.
        images: registry.images.report(),
    })
}

/// The cloud-managed VMs, spoken in the uids the cloud handed out. A VM that
/// wears the cloud's mark but no uid cannot be named in a language the cloud
/// understands — and silently leaving it out is exactly the short list this
/// whole mechanism exists to prevent, so it costs the list its completeness.
#[generated(model = ClaudeOpus, version = "5")]
fn report_cloud_vms(vms: &[Vm], complete: &mut bool) -> Vec<VmStatusReport> {
    let mut out = Vec::new();
    for vm in vms.iter().filter(|v| v.metadata.managed_by_cloud()) {
        match vm.metadata.cloud_uid() {
            Some(uid) => out.push(VmStatusReport {
                id: uid.to_string(),
                phase: vm.status.phase.as_str().to_string(),
                message: vm.status.message.clone().unwrap_or_default(),
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

#[cfg(test)]
#[generated(model = ClaudeOpus, version = "5")]
mod tests {
    use super::*;
    use controller_api::{VmPhase, VmSpec};

    fn vm(name: &str, uid: Option<&str>, phase: VmPhase) -> Vm {
        let mut vm = new_vm(
            name,
            VmSpec {
                cluster_selector: Default::default(),
                node_selector: Default::default(),
                anti_affinity: Vec::new(),
                node_name: None,
                cluster_name: None,
                run_strategy: Default::default(),
                tenant: None,
                vm: serde_json::json!({}),
            },
        );
        if let Some(uid) = uid {
            vm.metadata.mark_managed_by_cloud(uid);
        }
        vm.status.phase = phase;
        vm
    }

    fn create(vni: Option<u32>, floating: &[&str], subnets: &[&str]) -> proto::CreateVm {
        proto::CreateVm {
            name: "web-1".into(),
            spec_json: String::new(),
            uid: "uid-1".into(),
            vni,
            floating_ips: floating.iter().map(|s| s.to_string()).collect(),
            routed_subnets: subnets.iter().map(|s| s.to_string()).collect(),
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

    #[test]
    fn only_the_clouds_vms_are_reported_and_only_by_uid() {
        let vms = [
            vm("local", None, VmPhase::Running),
            vm("theirs", Some("uid-1"), VmPhase::Provisioning),
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
        let mut vm = vm("orphan", None, VmPhase::Running);
        vm.metadata
            .labels
            .insert("meister.io/managed-by".into(), "cloud".into());
        let mut complete = true;
        let out = report_cloud_vms(&[vm], &mut complete);
        assert!(out.is_empty());
        assert!(!complete);
    }
}
