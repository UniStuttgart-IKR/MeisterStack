// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

#[cfg(feature = "http-api")]
pub mod api;
pub mod config;
pub mod console;
pub mod drivers;
pub mod images;
pub mod provision;
pub mod reconcile;
pub mod store;
pub mod types;

use anyhow::{Context, anyhow, bail};
use std::collections::HashSet;
use std::time::{Duration, SystemTime};
use tokio::sync::mpsc;
use tokio_stream::{StreamExt, wrappers::ReceiverStream};
use tracing::{error, info, instrument, warn};

use agent_api::VmId;
use macros::generated;
use proto::{
    AgentMessage, CommandResult, DriverInfo, Hello, NodeStatus, StatusReport, VmStatusReport,
    agent_message, command, command_result, control_plane_client::ControlPlaneClient,
    controller_message,
};

use config::AgentConfig;
use drivers::{DeviceCatalog, Drivers, NetworkCatalog, VolumeCatalog};
use provision::Provisioner;
use reconcile::{Reconciler, Trigger, sync_orphans};
use std::sync::Arc;
use store::Store;
use tracing::{Instrument, info_span};
use types::{AgentVmSpec, Desired};

/// How often the node reports even when nothing happened. Doubles as the
/// heartbeat: the controller expires a node after 30s without one, so this
/// has to stay comfortably below that.
const STATUS_INTERVAL: Duration = Duration::from_secs(10);

/// The command named a vm this node has no record of.
///
/// A type of its own and not a `bail!`, because the level the dispatch logs
/// a failed command at depends on which failure it was, and a string is a
/// poor thing to decide that on. What it renders is the text the `bail!`
/// produced before it, so the message that goes back over the wire as the
/// command's error is unchanged.
#[derive(Debug)]
struct NoSuchVm(VmId);

impl std::fmt::Display for NoSuchVm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "no record for vm {} on this node", self.0)
    }
}

impl std::error::Error for NoSuchVm {}

/// Whether a failed command is somebody else's to repair.
///
/// The level contract keeps ERROR for what an operator has to act on, and a
/// dispatch that logged every failed command at ERROR broke that twice over.
/// A vm the controller names but this node never had is repaired by the
/// controller's next SyncState, and an id this node cannot parse is bad
/// input from the tier above that no work on this node fixes. Both are
/// degradations that heal without a human, which is WARN. Everything else —
/// a driver, the store, the hypervisor — is this node's problem and stays
/// ERROR.
fn heals_without_an_operator(e: &anyhow::Error) -> bool {
    e.chain()
        .any(|cause| cause.is::<NoSuchVm>() || cause.is::<uuid::Error>())
}

pub struct Agent {
    provisioner: Arc<Provisioner>,
    /// The base image cache, for the half of the status report that is about
    /// this node's disk rather than about its VMs.
    images: Arc<crate::images::Cache>,
    store: Arc<Store>,
    reconciler: Arc<Reconciler>,
    ops: Arc<tokio::sync::Mutex<()>>,
    catalog: DeviceCatalog,
    volumes: VolumeCatalog,
    network: NetworkCatalog,
    default_bridge: String,
    /// The grace a Stop gives the guest when the controller names none.
    stop_grace: Duration,
    pause_supported: bool,
    /// vCPUs and RAM of this host; neither changes while the agent runs.
    node: NodeStatus,
}

#[generated(model = ClaudeFable, version = "5")]
impl Agent {
    /// Create is idempotent by id: the controller sends it once for a new VM
    /// and repeats the whole set as a SyncState on every reconnect.
    async fn handle_create(&self, c: proto::CreateInstance) -> anyhow::Result<()> {
        let id: VmId = c.id.parse().context("invalid vm id")?;
        // spec_json wins: same format and same serde as the local REST API.
        let (spec, desired) = if !c.spec_json.is_empty() {
            let new_spec: crate::types::NewVmSpec =
                serde_json::from_str(&c.spec_json).context("invalid spec_json")?;
            let (_, spec, desired) = new_spec.into_spec(&self.default_bridge)?;
            (spec, desired)
        } else {
            let spec = c.spec.ok_or_else(|| anyhow!("create without spec"))?;
            let spec: AgentVmSpec = spec.try_into().context("invalid vm spec")?;
            (spec, Desired::Running)
        };

        if self.store.get(&id)?.is_some() {
            // Known already — the spec is immutable, only the intent can have
            // moved. It goes through the same lifecycle path a command takes,
            // so a create that means "stop" still gets its grace period.
            self.claim(&id).await?;
            return self.set_desired(id, desired).await.map(|_| ());
        }

        self.catalog
            .validate(&spec.devices)
            .context("invalid device spec")?;
        self.volumes
            .validate(&spec.volumes)
            .context("invalid volume spec")?;
        self.network
            .validate(&spec.nics)
            .context("invalid nic spec")?;
        let _guard = self.ops.lock().await;
        self.provisioner.provision(id, spec, desired, true).await
    }

    /// The controller only ever names VMs it owns, so a record it sends is
    /// the controller's by definition. This is also the migration path:
    /// records written before the marker existed default to unmanaged and
    /// would otherwise stay outside every desired-state snapshot forever.
    async fn claim(&self, id: &VmId) -> anyhow::Result<()> {
        let _guard = self.ops.lock().await;
        let Some(mut record) = self.store.get(id)? else {
            return Ok(());
        };
        if record.managed_by_controller {
            return Ok(());
        }
        info!(vm_id = %id, "claiming pre-existing record as controller-managed");
        record.managed_by_controller = true;
        self.store.put(id, &record)
    }

    /// A desired state off the wire, with the grace a stop needs; whether the
    /// deadline is actually armed is `set_desired`'s call. `Ok(false)` means
    /// the record was gone — for a destroy that is the asked-for outcome, for
    /// a lifecycle command it is not.
    async fn set_desired(&self, id: VmId, desired: Desired) -> anyhow::Result<bool> {
        let deadline = (desired == Desired::Stopped).then(|| SystemTime::now() + self.stop_grace);
        Ok(self
            .reconciler
            .set_desired(id, desired, deadline)
            .await?
            .is_some())
    }

    /// A lifecycle command names a VM the controller believes is here. If it
    /// is not, say so rather than acking a no-op: the controller's picture of
    /// this node is wrong, and its next SyncState is what repairs it.
    async fn lifecycle(&self, raw_id: &str, desired: Desired) -> anyhow::Result<()> {
        let id: VmId = raw_id.parse().context("invalid vm id")?;
        if !self.set_desired(id, desired).await? {
            return Err(NoSuchVm(id).into());
        }
        Ok(())
    }

    async fn handle_stop(&self, s: proto::StopInstance) -> anyhow::Result<()> {
        let id: VmId = s.id.parse().context("invalid vm id")?;
        let grace = s
            .grace_secs
            .map(Duration::from_secs)
            .unwrap_or(self.stop_grace);
        let armed = self
            .reconciler
            .set_desired(id, Desired::Stopped, Some(SystemTime::now() + grace))
            .await?;
        if armed.is_none() {
            return Err(NoSuchVm(id).into());
        }
        Ok(())
    }

    /// Same gate as the REST path: a driver that cannot pause must say so
    /// instead of parking a desired state it can never reach.
    async fn handle_pause(&self, p: proto::PauseInstance) -> anyhow::Result<()> {
        if !self.pause_supported {
            bail!("hypervisor driver does not support pausing");
        }
        self.lifecycle(&p.id, Desired::Paused).await
    }

    async fn handle_destroy(&self, d: proto::DestroyInstance) -> anyhow::Result<()> {
        let id: VmId = d.id.parse().context("invalid vm id")?;
        // A record that is already gone is exactly what a destroy wants.
        self.set_desired(id, Desired::Absent).await.map(|_| ())
    }

    /// The whole desired state of this node in one message. Every entry is an
    /// idempotent create; what is *missing* is the other half of the message —
    /// a managed record the controller no longer lists was deleted while this
    /// agent was away, and the reconciler tears it down.
    #[instrument(skip_all, fields(vms = sync.desired.len()))]
    async fn handle_sync_state(&self, sync: proto::SyncState) -> anyhow::Result<()> {
        let mut snapshot: HashSet<VmId> = HashSet::new();
        let mut failures: Vec<String> = Vec::new();

        // An unparsable id is noted and skipped rather than nested around
        // the work: it cannot go into the snapshot, so letting it fall
        // through would put an id nobody can name into the orphan sweep.
        for create in sync.desired {
            let raw = create.id.clone();
            let id = match raw.parse::<VmId>() {
                Ok(id) => id,
                Err(e) => {
                    failures.push(format!("invalid vm id {raw:?}: {e}"));
                    continue;
                }
            };
            snapshot.insert(id);
            if let Err(e) = self.handle_create(create).await {
                failures.push(format!("vm {id}: {e:#}"));
            }
        }

        // The sweep runs even when an entry failed: a VM this node could not
        // apply says nothing about the ones the controller dropped.
        let records = self.store.list()?;
        for id in sync_orphans(&snapshot, records.iter().map(|(id, r)| (*id, r))) {
            info!(vm_id = %id, "not in the controller's desired state, tearing down");
            if let Err(e) = self.set_desired(id, Desired::Absent).await {
                failures.push(format!("vm {id}: teardown: {e:#}"));
            }
        }

        if failures.is_empty() {
            Ok(())
        } else {
            bail!(
                "{} of the desired state did not apply: {}",
                failures.len(),
                failures.join("; ")
            )
        }
    }

    /// What this node can serve, in the one list the controller flattens
    /// into a Node's capacity.
    ///
    /// Storage rides in as a single pseudo-driver whose profiles are the
    /// backend names (`volume` → `[filesystem, lvm-thin, nfs]`, flattened one
    /// tier up into `volume/lvm-thin` and friends). It is not a separate
    /// field on the Hello because it does not need one: the catalogue is
    /// already `<driver>/<profile>` strings on both sides of the sentence,
    /// and a scheduler that can ask "does this node offer nvrm/4q" can ask
    /// "does this node offer volume/lvm-thin" without learning anything new.
    fn hello(&self, node_id: &str) -> Hello {
        let mut drivers: Vec<DriverInfo> = self
            .catalog
            .inventory()
            .into_iter()
            .map(|(name, profiles)| DriverInfo { name, profiles })
            .collect();
        drivers.push(DriverInfo {
            name: common::capability::VOLUME.to_string(),
            profiles: self.volumes.inventory(),
        });
        // Networking rides in the same way and for the same reason, with one
        // difference: a node with no overlay claims NOTHING here rather than
        // an empty `network` entry. An entry with no profiles is the bare
        // driver name in the flattened catalogue (`vfio` is one), and a bare
        // `network` would answer a bare request for it — there is no such
        // request today, and leaving the door shut costs one `if`.
        let overlays = self.network.inventory();
        if !overlays.is_empty() {
            drivers.push(DriverInfo {
                name: common::capability::NETWORK.to_string(),
                profiles: overlays,
            });
        }
        Hello {
            node_id: node_id.to_string(),
            agent_version: env!("CARGO_PKG_VERSION").to_string(),
            drivers,
        }
    }

    /// Node facts plus one phase per VM, all derived from the reconciler's own
    /// observation — see `reconcile::report_status`.
    async fn status_report(&self) -> anyhow::Result<StatusReport> {
        let reported = self.reconciler.report().await?;
        // The same view the controller gets, published as a gauge. Every
        // phase every time, zero included, so that a phase nothing is in
        // stays a flat line rather than a series that vanishes from a panel.
        for phase in crate::reconcile::ReportedPhase::ALL {
            let n = reported.iter().filter(|r| r.phase == phase).count();
            telemetry::metrics::agent().set_vms(phase.as_str(), n as i64);
        }
        let vms = reported
            .into_iter()
            .map(|r| VmStatusReport {
                id: r.id.to_string(),
                phase: r.phase.as_str().to_string(),
                message: r.message.unwrap_or_default(),
            })
            .collect();
        Ok(StatusReport {
            node: Some(self.node),
            vms,
            // What this node has learned about the base images it was asked
            // to fetch. Empty on a node that has only ever seen path-based
            // images, which is every node before this milestone.
            images: self
                .images
                .report()
                .into_iter()
                .map(|(name, state)| proto::ImageStateReport {
                    name,
                    phase: state.phase().to_string(),
                    message: state.message().to_string(),
                })
                .collect(),
        })
    }

    /// The end of a VM's one-way output, as the JSON the whole way up.
    ///
    /// The same document the node's own REST API serves, passed through the
    /// cluster and the cloud without either of them opening it: what a
    /// console printed is the node's answer, and a tier that reformatted it
    /// would be a tier that could get it wrong.
    ///
    /// A vm this node has no record of is `NoSuchVm` — the same error every
    /// other command gives for the same thing, so it is logged at the same
    /// level and repaired by the same SyncState. A vm that has simply printed
    /// nothing answers with an empty list.
    #[generated(model = ClaudeOpus, version = "5")]
    fn handle_logs(&self, cmd: proto::FetchLogs) -> anyhow::Result<Vec<u8>> {
        let id: VmId = cmd.id.parse().context("invalid vm id")?;
        if self.store.get(&id)?.is_none() {
            return Err(NoSuchVm(id).into());
        }
        let lines = match cmd.lines {
            0 => crate::console::DEFAULT_LINES,
            n => n as usize,
        };
        let streams: Vec<serde_json::Value> = self
            .reconciler
            .console(&id, lines)
            .into_iter()
            .map(|(stream, text)| serde_json::json!({"stream": stream.as_str(), "text": text}))
            .collect();
        Ok(serde_json::to_vec(&streams)?)
    }

    /// One command, under the trace of whatever asked for it. Everything the
    /// dispatch reaches — provision, the volume and device drivers, the CH
    /// API calls — is a child span of this one, so `POST /vms` at the cloud
    /// edge and the backend spawn on this node are the same trace.
    ///
    /// The span is built and given its parent before it starts; see
    /// `telemetry::in_trace`. A command without a readable context is not an
    /// error — it gets its own root, and this node's work is still traceable,
    /// just not back to whoever asked for it.
    async fn dispatch(&self, cmd: proto::Command) -> CommandResult {
        let context = telemetry::TraceParent::parse(&cmd.traceparent)
            .unwrap_or_else(telemetry::TraceParent::root);
        let span = tracing::info_span!(
            "dispatch",
            request_id = %cmd.request_id,
            trace_id = %context.trace_id_hex()
        );
        telemetry::in_trace(span, &context, self.dispatch_traced(cmd)).await
    }

    async fn dispatch_traced(&self, cmd: proto::Command) -> CommandResult {
        let request_id = cmd.request_id.clone();
        // Every command that CHANGES something answers with "done" and an
        // empty payload; the one that asks a question answers with bytes.
        // `done` is what makes the six mutating arms read as they always did.
        let done = |r: anyhow::Result<()>| r.map(|()| Vec::new());
        let op_result = match cmd.op {
            Some(command::Op::Create(c)) => done(self.handle_create(c).await),
            Some(command::Op::Destroy(d)) => done(self.handle_destroy(d).await),
            Some(command::Op::Start(s)) => done(self.lifecycle(&s.id, Desired::Running).await),
            Some(command::Op::Stop(s)) => done(self.handle_stop(s).await),
            Some(command::Op::Pause(p)) => done(self.handle_pause(p).await),
            // Resume is Start under another name — the REST path does not gate
            // it on pause support either, and a vm that is not paused simply
            // converges to Running.
            Some(command::Op::Resume(r)) => done(self.lifecycle(&r.id, Desired::Running).await),
            Some(command::Op::Logs(l)) => self.handle_logs(l),
            None => Err(anyhow!("command without op")),
        };
        let outcome = match op_result {
            Ok(payload) => {
                info!("command ok");
                command_result::Outcome::Ok(proto::Ack { payload })
            }
            Err(e) => {
                let message = format!("{e:#}");
                if heals_without_an_operator(&e) {
                    warn!(error = %message, "command failed");
                } else {
                    error!(error = %message, "command failed");
                }
                command_result::Outcome::Error(proto::ErrorMsg { message })
            }
        };
        CommandResult {
            request_id,
            outcome: Some(outcome),
        }
    }
}

#[generated(model = ClaudeFable, version = "5")]
pub async fn run_agent(cfg: AgentConfig) -> anyhow::Result<()> {
    let store = Arc::new(Store::open(&cfg.paths.db_path)?);
    let drivers = Drivers::from_config(&cfg).await?;
    let networking_driver = drivers.networking.clone();
    let pause_supported = drivers.hypervisor.as_pausable().is_some();
    let ops = Arc::new(tokio::sync::Mutex::new(()));

    let bridge_addr = cfg.network.parsed_bridge_addr()?;
    let catalog = DeviceCatalog::new(&drivers.devices);
    let volumes = VolumeCatalog::new(&drivers.storage);
    let network = NetworkCatalog::new(&cfg.network);
    if network.serves_overlays() {
        info!(
            capability = "network/vxlan",
            "this node serves tenant overlays"
        );
    }

    // One cache per agent, over the configured image directory: what it puts
    // there is exactly what the volume drivers look up.
    let images = Arc::new(crate::images::Cache::new(cfg.paths.image_dir.clone()));
    let provisioner = Arc::new(Provisioner::new(
        store.clone(),
        drivers.clone(),
        images.clone(),
        cfg.paths.image_dir.clone(),
        cfg.network.default_bridge.clone(),
        bridge_addr,
        cfg.cgroup_cpuset.clone(),
    ));
    let reconciler = Arc::new(Reconciler::new(
        store.clone(),
        drivers,
        provisioner.clone(),
        ops.clone(),
    ));

    // Before the first reconcile: the taps this node still holds, so the
    // network driver can throw away filter chains for taps it does not. The
    // records are the truth about what exists — a chain for anything else is
    // the far half of a teardown a `kill -9` interrupted.
    let live_taps: Vec<String> = store
        .list()?
        .iter()
        .flat_map(|(_, record)| record.nics.iter().map(|n| n.tap_name.clone()))
        .collect();
    networking_driver.reap(&live_taps).await;

    if let Err(e) = reconciler.reconcile_all(Trigger::Startup).await {
        // Warn and not error: the periodic pass hands the same records to the
        // same code thirty seconds later. A start-up that failed once is a
        // degradation that heals itself, and the level contract says WARN.
        warn!(
            error = %format!("{e:#}"),
            "startup reconcile failed, continuing degraded"
        );
    }

    #[cfg(feature = "http-api")]
    {
        let state = api::ApiState {
            store: store.clone(),
            reconciler: reconciler.clone(),
            provisioner: provisioner.clone(),
            ops: ops.clone(),
            pause_supported,
            stop_grace: Duration::from_secs(cfg.stop_grace_secs),
            catalog: catalog.clone(),
            volumes: volumes.clone(),
            network: network.clone(),
            default_bridge: cfg.network.default_bridge.clone(),
        };
        let sock = cfg.paths.run_dir.join("agent.sock");
        tokio::spawn(async move {
            if let Err(e) = api::serve(sock, state).await {
                error!(error = %format!("{e:#}"), "http api stopped");
            }
        });
    }

    {
        let reconciler = reconciler.clone();
        tokio::spawn(
            async move {
                let mut tick = tokio::time::interval(Duration::from_secs(30));
                tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
                tick.tick().await;
                loop {
                    tick.tick().await;
                    if let Err(e) = reconciler.reconcile_all(Trigger::Periodic).await {
                        warn!(error = %format!("{e:#}"), "periodic reconcile pass failed");
                    }
                }
            }
            .instrument(info_span!("periodic_reconcile")),
        );
    }

    let endpoints = cfg.controller_endpoints();
    if endpoints.is_empty() {
        info!("no controller configured, running standalone");
        std::future::pending::<()>().await;
        unreachable!("pending() never resolves");
    }

    let agent = Arc::new(Agent {
        provisioner,
        images,
        store,
        reconciler,
        ops,
        catalog,
        volumes,
        network,
        default_bridge: cfg.network.default_bridge.clone(),
        stop_grace: Duration::from_secs(cfg.stop_grace_secs),
        pause_supported,
        node: cfg.capped(node_facts()),
    });

    // Which replica this agent belongs to is nobody's decision but its own:
    // the order is hashed from the node id, so the controllers need no
    // registry of agents and no agreement with each other about who serves
    // whom. The schedule around the session — walk the order, wait only once
    // all of it has refused — is `common::redial`, shared with the tier above
    // because it is the same schedule there.
    let mut redial = common::redial::Redial::new(&cfg.node_id, &endpoints);

    // Built once, at start-up, so a missing CA or a world-readable key is a
    // refusal to start rather than a session that never connects. `None` is
    // the plain dial this agent has used since M1, and the default.
    let tls = cfg.session_tls()?;
    if tls.is_some() {
        // Two different states, and an operator debugging a refused session
        // needs to know which one they are in: a CA alone is an encrypted
        // session the controller cannot attribute, and a certificate is what
        // makes `system:node:<node_id>` mean anything.
        info!(
            node = %cfg.node_id,
            identity = cfg.controller_cert.is_some(),
            "controller sessions are tls"
        );
    }

    loop {
        let addr = redial.endpoint().to_string();
        let (position, of) = redial.position();
        info!(endpoint = %addr, position, of, "dialling controller");
        let mut established = false;
        let outcome = run_session(&agent, &addr, &cfg, tls.as_ref(), &mut established).await;
        match outcome {
            Ok(()) => info!(endpoint = %addr, "controller session ended"),
            Err(e) => warn!(endpoint = %addr, error = %format!("{e:#}"),
                            "controller session failed"),
        }
        if let Some(wait) = redial.ended(established) {
            warn!(?wait, endpoints = of, "no controller answered, waiting");
            tokio::time::sleep(wait).await;
        }
    }
}

#[generated(model = ClaudeOpus, version = "4.8")]
#[instrument(skip_all, fields(endpoint = %controller_addr))]
async fn run_session(
    agent: &Arc<Agent>,
    controller_addr: &str,
    cfg: &AgentConfig,
    tls: Option<&tonic::transport::ClientTlsConfig>,
    established: &mut bool,
) -> anyhow::Result<()> {
    let channel = proto::dial_tls(controller_addr, tls)
        .await
        .context("connecting to controller")?;
    let mut client = ControlPlaneClient::new(channel);
    let (tx, rx) = mpsc::channel::<AgentMessage>(64);
    tx.send(AgentMessage {
        kind: Some(agent_message::Kind::Hello(agent.hello(&cfg.node_id))),
    })
    .await
    .map_err(|_| anyhow!("session closed before hello"))?;

    let mut inbound = client.session(ReceiverStream::new(rx)).await?.into_inner();
    // From here on this endpoint has answered: whatever ends the session, it
    // is not "nobody is there", and the caller's backoff should say so.
    *established = true;

    // Status goes out on its own task, not from this loop: provisioning a
    // single VM can take longer than the controller's liveness window, and a
    // node that is busy is not a node that is gone.
    let report_now = Arc::new(tokio::sync::Notify::new());
    let _status = AbortOnDrop(tokio::spawn(
        status_loop(agent.clone(), tx.clone(), report_now.clone())
            .instrument(info_span!("status_report")),
    ));

    while let Some(msg) = inbound.next().await {
        let msg = match msg {
            Ok(m) => m,
            Err(e) => {
                warn!(error = %format!("{e:#}"), "controller stream error");
                return Ok(());
            }
        };
        match msg.kind {
            Some(controller_message::Kind::Command(cmd)) => {
                let result = agent.dispatch(cmd).await;
                if tx
                    .send(AgentMessage {
                        kind: Some(agent_message::Kind::Result(result)),
                    })
                    .await
                    .is_err()
                {
                    return Ok(());
                }
                // The command just changed what this node looks like; say so
                // instead of letting the controller wait out the interval.
                report_now.notify_one();
            }
            // Applied inline, not spawned: the snapshot is the ground the
            // commands behind it stand on, and a Destroy that overtook it
            // would be deciding about a record the sync has not seen yet.
            // There is no result to send — a snapshot carries no request_id,
            // and the status report right after it is the answer.
            Some(controller_message::Kind::Sync(sync)) => {
                let vms = sync.desired.len();
                match agent.handle_sync_state(sync).await {
                    Ok(()) => info!(vms, "desired state synchronised"),
                    Err(e) => warn!(
                        vms,
                        error = %format!("{e:#}"),
                        "desired state sync incomplete"
                    ),
                }
                report_now.notify_one();
            }
            None => {}
        }
    }
    Ok(())
}

/// Heartbeat and phases on the session stream: right after Hello, then every
/// `STATUS_INTERVAL` and whenever a command was processed.
#[generated(model = ClaudeOpus, version = "5")]
async fn status_loop(
    agent: Arc<Agent>,
    tx: mpsc::Sender<AgentMessage>,
    wake: Arc<tokio::sync::Notify>,
) {
    let mut tick = tokio::time::interval(STATUS_INTERVAL);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    tick.tick().await; // interval fires at once; report below instead

    loop {
        let report = match agent.status_report().await {
            Ok(r) => r,
            Err(e) => {
                // Never skip the beat over a read error: an unreportable vm
                // must not make a live node look dead.
                warn!(
                    error = %format!("{e:#}"),
                    "status report failed, sending node facts only"
                );
                StatusReport {
                    node: Some(agent.node),
                    vms: Vec::new(),
                    // Empty for the same reason `vms` is: this is the
                    // heartbeat only, and a short list must not be read as a
                    // statement.
                    images: Vec::new(),
                }
            }
        };
        if tx
            .send(AgentMessage {
                kind: Some(agent_message::Kind::Status(report)),
            })
            .await
            .is_err()
        {
            return; // session gone
        }
        tokio::select! {
            _ = tick.tick() => {}
            _ = wake.notified() => {}
        }
    }
}

/// What the controller schedules against. Read once at start-up.
#[generated(model = ClaudeOpus, version = "5")]
fn node_facts() -> NodeStatus {
    let vcpus = std::thread::available_parallelism()
        .map(|n| n.get() as u32)
        .unwrap_or(0);
    let mem_mib = std::fs::read_to_string("/proc/meminfo")
        .ok()
        .and_then(|meminfo| {
            meminfo.lines().find_map(|l| {
                l.strip_prefix("MemTotal:")?
                    .trim()
                    .strip_suffix(" kB")?
                    .trim()
                    .parse::<u64>()
                    .ok()
            })
        })
        .map(|kb| kb / 1024)
        .unwrap_or(0);
    if vcpus == 0 || mem_mib == 0 {
        // Error and not warn: this is read once at start-up and never again,
        // so nothing repairs it while the agent runs, and a node reporting
        // zero capacity is a node the scheduler will never place on.
        error!(
            vcpus,
            mem_mib, "could not read node capacity, reporting what was found"
        );
    }
    info!(vcpus, mem_mib, "node capacity measured");
    NodeStatus { vcpus, mem_mib }
}

/// The status task belongs to one session; when the session ends by any of
/// the loop's exits, so does the task.
struct AbortOnDrop(tokio::task::JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}
