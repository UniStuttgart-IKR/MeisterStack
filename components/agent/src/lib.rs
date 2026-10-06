// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

#[cfg(feature = "http-api")]
pub mod api;
pub mod attach;
pub mod cloudinit;
mod commands;
pub mod conditions;
pub mod config;
pub mod console;
pub mod drivers;
pub mod images;
pub mod machine;
pub mod migration;
pub mod privileges;
pub mod provision;
pub mod reconcile;
pub mod store;
pub mod types;
pub mod volumes;

use anyhow::{Context, anyhow, bail};
use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant, SystemTime};
use tokio::sync::mpsc;
use tokio_stream::{StreamExt, wrappers::ReceiverStream};
use tracing::{debug, error, info, instrument, warn};

use agent_api::VmId;
use agent_api::storage::VolumeId;
use proto::{
    AgentMessage, CommandResult, DriverInfo, Hello, NodeStatus, StatusReport, VmStatusReport,
    agent_message, command, command_result, control_plane_client::ControlPlaneClient,
    controller_message,
};

use agent_api::hypervisor::ConsoleStream;
use config::AgentConfig;
use drivers::{DeviceCatalog, Drivers, HypervisorCatalog, NetworkCatalog, VolumeCatalog};
use provision::Provisioner;
use reconcile::{Reconciler, Trigger, sync_orphans};
use std::sync::{Arc, Mutex};
use store::Store;
use tracing::{Instrument, info_span};
use types::{AgentVmSpec, Desired, NewVmSpecExt};

/// How often the node reports even when nothing happened. Doubles as the
/// heartbeat: the controller expires a node after 30s without one, so this
/// has to stay comfortably below that.
const STATUS_INTERVAL: Duration = Duration::from_secs(10);

/// Typed command error for an unknown VM, used to choose logging severity.
#[derive(Debug)]
struct NoSuchVm(VmId);

impl std::fmt::Display for NoSuchVm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "no record for vm {} on this node", self.0)
    }
}

impl std::error::Error for NoSuchVm {}

/// Structural refusal marker carried as CANNOT_SERVE on the command result.
/// The controller may release the binding and choose another node.
#[derive(Debug)]
struct CannotServe(String);

impl std::fmt::Display for CannotServe {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for CannotServe {}

/// Wrap a structural refusal while preserving its rendered message once.
/// Underlying typed causes are replaced by the marker; added context retains it.
fn cannot_serve<T>(r: anyhow::Result<T>) -> anyhow::Result<T> {
    r.map_err(|e| anyhow::Error::new(CannotServe(format!("{e:#}"))))
}

fn heals_without_an_operator(e: &anyhow::Error) -> bool {
    e.chain().any(|cause| {
        cause.is::<NoSuchVm>()
            || cause.is::<uuid::Error>()
            // An ownership refusal is an expected volume condition, not a backend fault.
            || cause.is::<crate::volumes::HeldByVm>()
    })
}

/// Maximum wait for the status task to enqueue its stopping report.
const LAST_WORD: Duration = Duration::from_secs(2);

/// Delay after controller-session loss before attempting to silence routers.
/// The 10 s delay leaves margin under the configured heartbeat/keepalive
/// assumptions, but scheduling, blocked commands and failed driver calls mean
/// this is not a fencing guarantee.
const ROUTER_DEAD_MAN: Duration = Duration::from_secs(10);

/// One-way shutdown state and notification that the stopping report was enqueued.
#[derive(Default)]
pub struct Shutdown {
    asked: std::sync::atomic::AtomicBool,
    /// Notified after enqueueing a stopping report. `notify_one` retains a permit
    /// when shutdown begins waiting later; this is not a controller acknowledgement.
    said: tokio::sync::Notify,
}

impl Shutdown {
    /// A stop was asked for. Idempotent — two signals are one shutdown.
    pub fn begin(&self) {
        self.asked.store(true, std::sync::atomic::Ordering::Release);
    }

    /// What the next report has to carry.
    pub fn stopping(&self) -> bool {
        self.asked.load(std::sync::atomic::Ordering::Acquire)
    }

    /// The farewell has gone out.
    pub fn said_goodbye(&self) {
        self.said.notify_one();
    }

    /// Wait for it to have gone out. Bounded by the caller.
    pub async fn goodbye_said(&self) {
        self.said.notified().await;
    }
}

pub struct Agent {
    provisioner: Arc<Provisioner>,
    /// The base image cache, for the half of the status report that is about
    /// this node's disk rather than about its VMs.
    images: Arc<crate::images::Cache>,
    /// The volumes this node owns on their own — the half of storage that is
    /// not about any VM. See `crate::volumes`.
    volumes_owned: Arc<crate::volumes::Volumes>,
    store: Arc<Store>,
    reconciler: Arc<Reconciler>,
    ops: Arc<tokio::sync::Mutex<()>>,
    catalog: DeviceCatalog,
    volumes: VolumeCatalog,
    hypervisor: HypervisorCatalog,
    network: NetworkCatalog,
    default_bridge: String,
    /// The grace a Stop gives the guest when the controller names none.
    stop_grace: Duration,
    pause_supported: bool,
    /// vCPUs and RAM of this host; neither changes while the agent runs.
    node: NodeStatus,
    /// Startup machine profile used for migration compatibility. See
    /// `crate::machine` and `controller_api::live_migration_refusal`.
    machine: proto::MachineProfile,
    /// What is wrong with this node right now — the half of the heartbeat
    /// that does change. See `crate::conditions`.
    conditions: Arc<crate::conditions::Conditions>,
    /// The rights this node holds against the drivers it configured, asked
    /// again on every report. See `crate::privileges::Watch` for why it is
    /// level-triggered and not read once.
    unprivileged: Arc<crate::privileges::Watch>,
    /// Whether this agent is going away on purpose. See `Shutdown`.
    shutdown: Arc<Shutdown>,
    /// Wake the current status loop, including from shutdown handlers outside the session.
    report_now: Arc<tokio::sync::Notify>,
    /// Where a migration stream lands on this node, decided once at start-up.
    /// See `crate::migration`.
    migration: crate::migration::Endpoint,
    /// Active console sessions keyed by the controller-selected session ID.
    /// A competing open for the same VM must be refused under its own ID.
    console_sessions: Mutex<HashMap<String, ConsoleSession>>,
}

/// One console session as the agent holds it: a way to type into the guest,
/// and the task that is pumping its output upwards.
struct ConsoleSession {
    /// Guest input writer; session ownership remains with the output task.
    writer: crate::attach::ConsoleWriter,
    /// Owns the `Held`, so aborting it releases the line.
    pump: tokio::task::JoinHandle<()>,
}

impl Agent {
    /// Construct Hello capabilities from registered-driver catalogues.
    fn hello(&self, node_id: &str) -> Hello {
        let mut drivers: Vec<DriverInfo> = self
            .catalog
            .inventory()
            .into_iter()
            .map(|(name, profiles)| DriverInfo {
                name,
                profiles,
                // Localities are a storage fact; a device driver has none and
                // says so by leaving the field empty.
                locality: String::new(),
            })
            .collect();
        // Use one volume entry per backend because locality differs between backends.
        drivers.extend(
            self.volumes
                .localities()
                .iter()
                .map(|(name, locality)| DriverInfo {
                    name: common::capability::VOLUME.to_string(),
                    profiles: vec![name.clone()],
                    locality: locality.as_str().to_string(),
                }),
        );
        // Snapshot capabilities have no locality; locality belongs to backend entries.
        let snapshots = self.volumes.snapshot_claims();
        if !snapshots.is_empty() {
            drivers.push(DriverInfo {
                name: common::capability::VOLUME.to_string(),
                profiles: snapshots,
                locality: String::new(),
            });
        }
        // Omit absent hypervisors: an empty-profile entry would still advertise
        // the bare hypervisor capability.
        let hypervisors = self.hypervisor.inventory();
        if !hypervisors.is_empty() {
            drivers.push(DriverInfo {
                name: common::capability::HYPERVISOR.to_string(),
                profiles: hypervisors,
                locality: String::new(),
            });
        }
        // Omit an empty network profile list instead of advertising a bare capability.
        let overlays = self.network.inventory();
        if !overlays.is_empty() {
            drivers.push(DriverInfo {
                name: common::capability::NETWORK.to_string(),
                profiles: overlays,
                locality: String::new(),
            });
        }
        drivers.push(DriverInfo {
            name: common::migration::ATTEMPT_PROTOCOL.into(),
            profiles: Vec::new(),
            locality: String::new(),
        });
        Hello {
            node_id: node_id.to_string(),
            agent_version: env!("CARGO_PKG_VERSION").to_string(),
            drivers,
            // Send the startup machine profile for migration compatibility checks.
            machine: Some(self.machine.clone()),
        }
    }

    /// Translate driver router observations into session reports.
    async fn routers(&self) -> Vec<proto::RouterReport> {
        let Some(bridge) = self.reconciler.drivers().bridge.as_ref() else {
            return Vec::new();
        };
        match bridge.list_routers().await {
            Ok(routers) => routers
                .into_iter()
                .map(|r| proto::RouterReport {
                    id: r.id.to_string(),
                    phase: r.phase.as_str().to_string(),
                    // Preserve the driver's observed reason alongside its lifecycle phase.
                    reason: r
                        .reason
                        .map(|reason| reason.as_str().to_string())
                        .unwrap_or_default(),
                    message: r.message,
                    active: r.active,
                    // The controller fills placement fields when forwarding this node-local report.
                    node: String::new(),
                    nodes: Vec::new(),
                })
                .collect(),
            Err(e) => {
                warn!(error = %format!("{e:#}"), "could not list this node's routers");
                Vec::new()
            }
        }
    }

    /// Combine startup capacity measurements with refreshed current conditions.
    fn node_status(&self) -> NodeStatus {
        // Refresh prerequisite conditions before reporting current node status.
        self.unprivileged.refresh(&self.conditions);
        node_status(&self.node, &self.conditions)
    }

    /// Node facts plus one phase per VM, all derived from the reconciler's own
    /// observation — see `reconcile::report_status`.
    async fn status_report(&self) -> anyhow::Result<StatusReport> {
        let reported = self.reconciler.report().await?;
        // Publish every phase gauge, including zeros, to keep metric series present.
        for phase in crate::reconcile::ReportedPhase::ALL {
            let n = reported.iter().filter(|r| r.phase == phase).count();
            telemetry::metrics::agent().set_vms(phase.as_str(), n as i64);
        }
        // Build migration reports from the same observations as VM reports.
        // They carry transfer outcomes independently of command acknowledgements.
        let migrations: Vec<proto::MigrationReport> = reported
            .iter()
            .filter_map(|r| {
                r.departure.as_ref().map(|d| proto::MigrationReport {
                    migration_id: d.migration_id.clone(),
                    vm_id: r.id.to_string(),
                    peer: d.peer.clone(),
                    outcome: d.outcome.as_str().to_string(),
                    message: d.message.clone().unwrap_or_default(),
                })
            })
            .collect();
        let vms = reported
            .into_iter()
            .map(|r| VmStatusReport {
                id: r.id.to_string(),
                phase: r.phase.as_str().to_string(),
                message: r.message.unwrap_or_default(),
                // Report committed attachment IDs separately from requested hotplug operations.
                attached_volumes: r.volumes.iter().map(uuid::Uuid::to_string).collect(),
                // The controller supplies placement when forwarding this report.
                node: String::new(),
                // The controller fills placement-specific volume data.
                volumes: Vec::new(),
                // Serialize the observed reason independently of human-readable messages.
                reason: r
                    .reason
                    .map(|reason| reason.as_str().to_string())
                    .unwrap_or_default(),
                // Report NIC addresses observed by the driver; omit NICs without an address.
                nics: r
                    .nics
                    .into_iter()
                    .map(|n| proto::NicReport {
                        name: n.name,
                        mac: n.mac,
                    })
                    .collect(),
            })
            .collect();
        // Refresh named path images and the directory inventory before reporting.
        self.reconciler.verify_path_images().await;
        let images_complete = self.images.take_inventory().await;
        Ok(StatusReport {
            node: Some(self.node_status()),
            vms,
            // Router-list failure is logged and produces an empty router list.
            routers: self.routers().await,
            // Include explicit image checks and inventory entries. Path checks are
            // deduplicated by image name; missing digests may require hashing.
            images: self
                .images
                .report()
                .into_iter()
                .map(|(name, state, digest)| proto::ImageStateReport {
                    name,
                    phase: state.phase().to_string(),
                    // Carry the machine-readable image failure reason; Ready has none.
                    reason: state
                        .reason()
                        .map(|reason| reason.as_str().to_string())
                        .unwrap_or_default(),
                    message: state.message().to_string(),
                    // The controller fills the reporting node identity.
                    node: String::new(),
                    digest: digest.unwrap_or_default(),
                })
                .collect(),
            // Only a successful directory inventory marks image reporting complete.
            images_complete,
            // Report independent volumes, including deletion tombstones.
            volumes: self.volumes_owned.report(),
            // Report snapshots independently because they can outlive their source volumes.
            snapshots: self.volumes_owned.report_snapshots(),
            // False on every report but the last one. See `Shutdown`.
            stopping: self.shutdown.stopping(),
            migrations,
            // The reporting pass succeeded, so this list is marked complete.
            // Store::list still omits unreadable rows; completeness does not prove that
            // every persisted VM could be decoded.
            vms_complete: true,
        })
    }
}

/// Open the store with the shared node-condition set and check cgroupfs.
fn store_and_conditions(
    cfg: &AgentConfig,
) -> anyhow::Result<(Arc<crate::conditions::Conditions>, Arc<Store>)> {
    let conditions = Arc::new(crate::conditions::Conditions::default());
    let store = Arc::new(Store::open_reporting_to(
        &cfg.paths.db_path,
        conditions.clone(),
    )?);
    // Report cgroup filesystem problems at startup and refresh them during reconciliation.
    if crate::conditions::check_cgroup_root(&cfg.paths.cgroup_root, &conditions) {
        info!(cgroup_root = %cfg.paths.cgroup_root.display(),
              "cgroup2 confirmed at the configured root");
    }
    Ok((conditions, store))
}

/// Admission and advertisement catalogues derived from the constructed drivers.
struct Catalogues {
    catalog: DeviceCatalog,
    volumes: VolumeCatalog,
    hypervisor: HypervisorCatalog,
    network: NetworkCatalog,
}

/// Construct catalogues and log unavailable node roles at startup.
fn catalogues(cfg: &AgentConfig, drivers: &Drivers) -> Catalogues {
    let catalog = DeviceCatalog::new(&drivers.devices);
    let volumes = VolumeCatalog::new(&drivers.storage);
    let hypervisor = HypervisorCatalog::new(drivers.hypervisor_name.as_deref());
    if hypervisor.validate().is_err() {
        info!("this node runs no vms and offers storage only; it claims no hypervisor capability");
    }
    // Advertise provider networks actually constructed by the driver.
    let physnets = drivers
        .bridge
        .as_ref()
        .map(|b| b.physnets())
        .unwrap_or_default();
    let network = NetworkCatalog::new(
        cfg.network.as_ref(),
        drivers.networking.is_some(),
        &physnets,
    );
    if drivers.networking.is_none() {
        info!("this node makes no taps; a vm with a nic cannot run here");
    }
    if network.serves_overlays() {
        info!(
            capability = "network/vxlan",
            "this node serves tenant overlays"
        );
    }
    for physnet in network.physnets() {
        info!(
            capability = %common::capability::entry(
                common::capability::NETWORK,
                Some(&common::capability::gateway_claim(physnet)),
            ),
            "this node gave an interface away and can hold routers for this provider network"
        );
    }
    Catalogues {
        catalog,
        volumes,
        hypervisor,
        network,
    }
}

/// Sweep stale tap filters, overlays and router resources before reconciliation.
/// Each sweep uses its own persisted ownership evidence.
async fn sweep_what_no_record_names(
    cfg: &AgentConfig,
    store: &Store,
    networking: Option<&Arc<dyn agent_api::networking::NicDriver>>,
    bridge: Option<&Arc<dyn agent_api::networking::BridgeDriver>>,
) -> anyhow::Result<()> {
    // Sweep taps only when a networking driver exists.
    if let Some(driver) = networking
        && let Some(live_taps) = live_taps_for_sweep(store)?
    {
        driver.reap(&live_taps).await;
    }

    // Optionally sweep overlays using persisted ownership evidence.
    if cfg
        .network
        .as_ref()
        .is_some_and(|network| network.sweep_orphans)
        && let Some(driver) = bridge
    {
        sweep_orphan_overlays(store, driver.as_ref()).await;
    }

    // Router ownership comes from driver records, not VM reference counts.
    // The driver determines which namespaces can be swept.
    if let Some(driver) = bridge {
        match driver.sweep_routers().await {
            Ok(swept) if swept.is_empty() => {}
            Ok(swept) => info!(?swept, "orphaned routers removed"),
            Err(e) => warn!(error = %format!("{e:#}"), "sweeping orphaned routers failed"),
        }
    }
    Ok(())
}

/// None means the inventory cannot authorize removal of any guest's filters.
fn live_taps_for_sweep(store: &Store) -> anyhow::Result<Option<Vec<String>>> {
    let mut taps = Vec::new();
    for (key, bytes) in store.list_raw()? {
        let record: types::VmRecord = match serde_json::from_slice(&bytes) {
            Ok(record) => record,
            Err(e) => {
                warn!(vm = %key, error = %e, "VM inventory is incomplete; preserving all anti-spoofing filters");
                return Ok(None);
            }
        };
        taps.extend(record.nics.into_iter().map(|nic| nic.tap_name));
    }
    Ok(Some(taps))
}

/// Build provider bridges before accepting controller work. Fail startup if
/// an interface is missing or still has host addresses.
async fn give_the_interfaces_away(
    cfg: &AgentConfig,
    bridge: Option<&Arc<dyn agent_api::networking::BridgeDriver>>,
) -> anyhow::Result<()> {
    let Some(provider) = cfg.network.as_ref().and_then(|n| n.provider.as_ref()) else {
        return Ok(());
    };
    let driver = bridge.ok_or_else(|| {
        anyhow::anyhow!(
            "[network.provider] names {} provider network(s), but this node built no \
             network driver to make their bridges with",
            provider.physnets.len()
        )
    })?;
    for (physnet, interface) in &provider.physnets {
        driver
            .ensure_physnet(physnet, interface)
            .await
            .with_context(|| format!("[network.provider] physnets.{physnet}"))?;
    }
    Ok(())
}

pub async fn run_agent(cfg: AgentConfig) -> anyhow::Result<()> {
    let (conditions, store) = store_and_conditions(&cfg)?;
    let crate::drivers::Startup {
        drivers,
        unavailable,
    } = Drivers::start(&cfg).await?;
    crate::drivers::report_unavailable(&unavailable, &conditions);
    // Build recurring prerequisite watches separately from driver registration.
    let unprivileged = Arc::new(crate::privileges::Watch::new(
        Arc::new(crate::privileges::Host),
        crate::drivers::screen(&cfg, &crate::privileges::Host).watch,
    ));
    // Log startup privilege failures even when no controller is configured.
    unprivileged.refresh(&conditions);
    let networking_driver = drivers.networking.clone();
    let bridge_driver = drivers.bridge.clone();
    // Retain the hypervisor for the startup machine-profile probe.
    let hypervisor_driver = drivers.hypervisor.clone();
    let pause_supported = drivers
        .hypervisor
        .as_ref()
        .is_some_and(|h| h.as_pausable().is_some());
    let ops = Arc::new(tokio::sync::Mutex::new(()));

    let bridge_addr = cfg.parsed_bridge_addr()?;
    let Catalogues {
        catalog,
        volumes,
        hypervisor,
        network,
    } = catalogues(&cfg, &drivers);

    // One cache per agent, over the configured image directory: what it puts
    // there is exactly what the volume drivers look up.
    // The operator's egress policy applies; empty `[images] allowed_sources` fetches nowhere.
    let images = Arc::new(
        crate::images::Cache::new(cfg.paths.image_dir.clone()).with_egress(cfg.egress_policy()?),
    );
    let provisioner = Arc::new(
        Provisioner::new(
            store.clone(),
            drivers.clone(),
            images.clone(),
            cfg.paths.image_dir.clone(),
            cfg.paths.run_dir.clone(),
            cfg.default_bridge(),
            bridge_addr,
            cfg.cgroup_cpuset.clone(),
        )
        .with_ceilings(cfg.migration_ceilings()),
    );
    // Independent volumes use the same storage registry as VM provisioning.
    let volumes_owned = Arc::new(crate::volumes::Volumes::new(
        store.clone(),
        drivers.clone(),
        ops.clone(),
    ));
    let reconciler = Arc::new(Reconciler::new(
        store.clone(),
        drivers,
        provisioner.clone(),
        ops.clone(),
    ));

    // Probe persisted volumes against their backends at startup.
    volumes_owned.adopt().await;

    // Provider interfaces must be assigned before reconciliation begins.
    give_the_interfaces_away(&cfg, bridge_driver.as_ref()).await?;

    sweep_what_no_record_names(
        &cfg,
        &store,
        networking_driver.as_ref(),
        bridge_driver.as_ref(),
    )
    .await?;

    if let Err(e) = reconciler.reconcile_all(Trigger::Startup).await {
        // Periodic reconciliation retries this startup failure.
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
            hypervisor: hypervisor.clone(),
            network: network.clone(),
            default_bridge: cfg.default_bridge(),
            volumes_owned: volumes_owned.clone(),
        };
        let sock = cfg.paths.run_dir.join("agent.sock");
        // Already validated in AgentConfig::load, so this cannot be the first
        // time an unknown group name is noticed — down here the error would
        // only reach the log.
        let socket_group = cfg.paths.socket_gid()?;
        tokio::spawn(async move {
            if let Err(e) = api::serve(sock, socket_group, state).await {
                error!(error = %format!("{e:#}"), "http api stopped");
            }
        });
    }

    spawn_periodic_reconcile(reconciler.clone());

    let endpoints = cfg.controller_endpoints();
    if endpoints.is_empty() {
        info!("no controller configured, running standalone");
        // Honor shutdown signals even without a controller session.
        a_stop_was_asked_for().await;
        info!("agent stopped");
        return Ok(());
    }

    let migration_endpoint = migration_endpoint(&cfg, &endpoints);

    let agent = Arc::new(Agent {
        console_sessions: Mutex::new(HashMap::new()),
        provisioner,
        images,
        volumes_owned,
        store,
        reconciler,
        ops,
        catalog,
        volumes,
        hypervisor,
        network,
        default_bridge: cfg.default_bridge(),
        stop_grace: Duration::from_secs(cfg.stop_grace_secs),
        pause_supported,
        node: cfg.capped(node_facts()),
        machine: machine_profile(&cfg, hypervisor_driver.as_ref()).await,
        conditions,
        unprivileged,
        shutdown: Arc::new(Shutdown::default()),
        report_now: Arc::new(tokio::sync::Notify::new()),
        migration: migration_endpoint,
    });

    // Derive controller preference from the node ID. `common::redial` tries
    // each endpoint before waiting, without controller-side assignment state.
    let mut redial = common::redial::Redial::new(&cfg.node_id, &endpoints);

    // Validate TLS material at startup. No credentials selects plaintext.
    let tls = cfg.session_tls()?;
    if tls.is_some() {
        // Distinguish encryption with a CA from client-certificate node authentication.
        info!(
            node = %cfg.node_id,
            identity = cfg.controller_cert.is_some(),
            "controller sessions are tls"
        );
    }

    tokio::select! {
        _ = dial_forever(&agent, &cfg, tls.as_ref(), &mut redial) => Ok(()),
        _ = say_goodbye(&agent) => {
            info!("agent stopped");
            Ok(())
        }
    }
}

/// Assemble the startup migration profile from host facts, VMM configuration
/// and the operator-supplied physical-host identity. Send it in Hello.
async fn machine_profile(
    cfg: &AgentConfig,
    hypervisor: Option<&Arc<dyn agent_api::hypervisor::Hypervisor>>,
) -> proto::MachineProfile {
    let version = match hypervisor {
        Some(driver) => driver.version().await.unwrap_or_default(),
        None => String::new(),
    };
    let cpu_profile = hypervisor.map(|d| d.cpu_profile()).unwrap_or_default();
    let profile = crate::machine::profile(cfg.physical_host.as_deref(), cpu_profile, &version);
    info!(
        cpu = %profile.cpu_model,
        nested = profile.nested,
        host = %profile.host,
        hypervisor = %profile.hypervisor_version,
        "this node's machine profile, for the live migrations that end here"
    );
    profile
}

/// Sweep overlays not named by any persisted VM specification. An unreadable
/// row cancels the sweep because it may own any candidate overlay.
async fn sweep_orphan_overlays(store: &Store, bridge: &dyn agent_api::networking::BridgeDriver) {
    let rows = match store.list_raw() {
        Ok(rows) => rows,
        Err(e) => {
            warn!(error = %format!("{e:#}"), "cannot read the records, not sweeping overlays");
            return;
        }
    };
    let mut keep: Vec<u32> = Vec::new();
    for (key, bytes) in rows {
        match serde_json::from_slice::<types::VmRecord>(&bytes) {
            Ok(record) => keep.extend(provision::overlay_vnis(&record)),
            Err(e) => {
                warn!(
                    key = %key, error = %format!("{e:#}"),
                    "a record here cannot be read, so no overlay on this node is provably orphaned"
                );
                return;
            }
        }
    }
    keep.sort_unstable();
    keep.dedup();
    match bridge.sweep_overlays(&keep).await {
        Ok(swept) if swept.is_empty() => debug!(kept = keep.len(), "no orphaned overlays"),
        Ok(swept) => info!(?swept, kept = keep.len(), "orphaned overlays removed"),
        Err(e) => warn!(error = %format!("{e:#}"), "sweeping orphaned overlays failed"),
    }
}

/// Reconcile every thirty seconds independently of controller connectivity.
fn spawn_periodic_reconcile(reconciler: Arc<Reconciler>) {
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

/// Resolve the receiver address and port range at startup and log availability.
fn migration_endpoint(cfg: &AgentConfig, endpoints: &[String]) -> crate::migration::Endpoint {
    let advertise = cfg
        .advertise_addr
        .clone()
        .or_else(|| crate::migration::derive_advertise(endpoints));
    let ports: Option<(u16, u16)> = config::section::<config::CloudHypervisorConfig>(
        &cfg.hypervisor,
        "hypervisor",
        "cloud-hypervisor",
    )
    .ok()
    .flatten()
    .and_then(|h| h.ports().ok())
    .flatten();
    let endpoint = crate::migration::Endpoint::new(advertise.clone(), ports);
    match endpoint.can_receive() {
        true => info!(
            advertise = advertise.as_deref().unwrap_or(""),
            "this node can receive live migrations"
        ),
        false => info!("this node does not receive live migrations; it can still send one"),
    }
    endpoint
}

/// Walk the endpoint order, hold whatever session answers, and start again
/// when it ends. Never returns: what ends this agent is the other half of the
/// `select!` in `run_agent`.
async fn dial_forever(
    agent: &Arc<Agent>,
    cfg: &AgentConfig,
    tls: Option<&tonic::transport::ClientTlsConfig>,
    redial: &mut common::redial::Redial,
) {
    // Start the disconnect clock at startup, including before the first
    // controller session. See `ROUTER_DEAD_MAN`.
    let mut last_up = Instant::now();
    let mut silenced = false;
    loop {
        let addr = redial.endpoint().to_string();
        let (position, of) = redial.position();
        info!(endpoint = %addr, position, of, "dialling controller");
        let mut established = false;
        let outcome = run_session(agent, &addr, cfg, tls, &mut established).await;
        match outcome {
            Ok(()) => info!(endpoint = %addr, "controller session ended"),
            Err(e) => warn!(endpoint = %addr, error = %format!("{e:#}"),
                            "controller session failed"),
        }
        if established {
            // Reset the outage clock when an established session ends. Only subsequent
            // controller EnsureRouter commands reactivate silenced routers.
            last_up = Instant::now();
            silenced = false;
        }
        let wait = redial.ended(established);
        if let Some(wait) = wait {
            warn!(?wait, endpoints = of, "no controller answered, waiting");
        }
        wait_out_the_backoff(
            agent.reconciler.drivers().bridge.as_deref(),
            last_up,
            &mut silenced,
            wait.unwrap_or_default(),
        )
        .await;
    }
}

/// Test whether the router-silencing delay has elapsed, tolerating reversed instants.
fn should_fall_silent(last_seen: Instant, now: Instant, threshold: Duration) -> bool {
    now.saturating_duration_since(last_seen) >= threshold
}

/// Wake at the earlier of redial backoff expiry or router-silencing deadline.
/// Set `silenced` only after a complete pass (a new session resets it); a partial pass is
/// retried once per backoff round, never in a busy loop (R3-F06).
async fn wait_out_the_backoff(
    bridge: Option<&dyn agent_api::networking::BridgeDriver>,
    last_up: Instant,
    silenced: &mut bool,
    wait: Duration,
) {
    let until = Instant::now() + wait;
    let mut tried_this_round = false;
    loop {
        let now = Instant::now();
        if !*silenced && !tried_this_round && should_fall_silent(last_up, now, ROUTER_DEAD_MAN) {
            warn!(deadline = ?ROUTER_DEAD_MAN,
                  "no controller has answered for longer than the dead man's deadline; this \
                   node stops answering for its routers' addresses before the cluster can give \
                   them to a standby, except where no other node can be made active");
            tried_this_round = true;
            *silenced = silence_routers_another_node_can_take_over(bridge).await;
        }
        if now >= until {
            return;
        }
        let next = match *silenced || tried_this_round {
            true => until,
            false => until.min(last_up + ROUTER_DEAD_MAN),
        };
        tokio::time::sleep_until(tokio::time::Instant::from_std(next)).await;
    }
}

/// On SIGINT/SIGTERM, request a stopping report, wait briefly for enqueueing,
/// and attempt router silencing. Guest VMMs are left running.
async fn say_goodbye(agent: &Arc<Agent>) {
    a_stop_was_asked_for().await;
    info!("a stop was asked for; telling the controller before going");
    agent.shutdown.begin();
    agent.report_now.notify_one();
    // Bound the final report wait when the controller is unavailable.
    if tokio::time::timeout(LAST_WORD, agent.shutdown.goodbye_said())
        .await
        .is_err()
    {
        warn!(
            ?LAST_WORD,
            "the last report did not get out in time; going anyway"
        );
    }
    // VMM transfers survive agent shutdown; shutdown does not authorize cleanup.
    // One-shot farewell: there is no next round to retry on, so the result is only logged.
    let bridge = agent.reconciler.drivers().bridge.as_deref();
    let _ = silence_routers_another_node_can_take_over(bridge).await;
}

/// Attempt to silence routers without destroying their namespaces. Called
/// after the stopping report wait and after controller-session loss. Takes the
/// bridge, not the agent, so a fake driver can test it.
/// True only when every router namespace on this node is verifiably silent, whatever its record
/// says, or deliberately kept answering as the only possible gateway of its provider network
/// (IKR-B76); no bridge counts as silent. A driver error or partial `Silencing` is false so the
/// caller retries (R3-F06, R2-1).
async fn silence_routers_another_node_can_take_over(
    bridge: Option<&dyn agent_api::networking::BridgeDriver>,
) -> bool {
    let Some(bridge) = bridge else {
        return true;
    };
    match bridge.fall_silent().await {
        Ok(outcome) if outcome.complete() => {
            if !outcome.silenced.is_empty() || !outcome.kept.is_empty() {
                info!(silenced = ?outcome.silenced, kept = ?outcome.kept,
                      "this node's routers fell silent on the way out, except those no other \
                       node can be made active for");
            }
            true
        }
        Ok(outcome) => {
            warn!(silenced = ?outcome.silenced, failed = ?outcome.failed, kept = ?outcome.kept,
                  "this node's routers could only be PARTIALLY silenced; the ones that failed \
                   may still answer for addresses its cluster has moved, and are retried on the \
                   next backoff round");
            false
        }
        Err(e) => {
            warn!(error = %format!("{e:#}"),
                  "this node's routers could not be silenced; it may still answer for \
                   addresses its cluster has moved, and are retried on the next backoff round");
            false
        }
    }
}

/// Dial, send Hello, run status reporting independently, and process inbound messages.
#[instrument(skip_all, fields(endpoint = %controller_addr))]
async fn run_session(
    agent: &Arc<Agent>,
    controller_addr: &str,
    cfg: &AgentConfig,
    tls: Option<&tonic::transport::ClientTlsConfig>,
    established: &mut bool,
) -> anyhow::Result<()> {
    let (mut inbound, tx) = dial_and_say_hello(agent, controller_addr, cfg, tls).await?;
    // Record successful connection establishment for redial backoff.
    *established = true;

    // Run status reporting independently so slow provisioning does not delay heartbeats.
    let report_now = agent.report_now.clone();
    let _status = AbortOnDrop(tokio::spawn(
        status_loop(agent.clone(), tx.clone(), report_now.clone())
            .instrument(info_span!("status_report")),
    ));

    pump(agent, &mut inbound, &tx, &report_now).await;
    Ok(())
}

/// Queue Hello before opening the controller session stream.
async fn dial_and_say_hello(
    agent: &Arc<Agent>,
    controller_addr: &str,
    cfg: &AgentConfig,
    tls: Option<&tonic::transport::ClientTlsConfig>,
) -> anyhow::Result<(
    tonic::Streaming<proto::ControllerMessage>,
    mpsc::Sender<AgentMessage>,
)> {
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

    let inbound = client.session(ReceiverStream::new(rx)).await?.into_inner();
    Ok((inbound, tx))
}

/// Process controller messages serially until the stream or reply channel ends.
async fn pump(
    agent: &Arc<Agent>,
    inbound: &mut tonic::Streaming<proto::ControllerMessage>,
    tx: &mpsc::Sender<AgentMessage>,
    report_now: &tokio::sync::Notify,
) {
    while let Some(msg) = inbound.next().await {
        let msg = match msg {
            Ok(m) => m,
            Err(e) => {
                warn!(error = %format!("{e:#}"), "controller stream error");
                return;
            }
        };
        if handle(agent, msg, tx, report_now).await.is_break() {
            return;
        }
    }
}

/// Dispatch one inbound message; a closed reply channel ends the session.
async fn handle(
    agent: &Arc<Agent>,
    msg: proto::ControllerMessage,
    tx: &mpsc::Sender<AgentMessage>,
    report_now: &tokio::sync::Notify,
) -> std::ops::ControlFlow<()> {
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
                return std::ops::ControlFlow::Break(());
            }
            // The command just changed what this node looks like; say so
            // instead of letting the controller wait out the interval.
            report_now.notify_one();
        }
        // Apply snapshots inline so later lifecycle commands cannot overtake them.
        // Snapshots have no request ID; the following status report reflects the result.
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
        // Opening starts a background output task. Input and close messages reach
        // it through the session map; guest output must not block this stream.
        Some(controller_message::Kind::ConsoleOpen(open)) => {
            agent.console_open(open, tx.clone()).await;
        }
        Some(controller_message::Kind::ConsoleInput(data)) => {
            agent.console_input(data).await;
        }
        Some(controller_message::Kind::ConsoleClose(close)) => {
            agent.console_close(&close.session_id);
        }
        None => {}
    }
    std::ops::ControlFlow::Continue(())
}

/// Wait for SIGINT or SIGTERM. Failure to install a handler leaves the task pending.
async fn a_stop_was_asked_for() {
    let mut term = match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
        Ok(term) => term,
        Err(e) => {
            warn!(error = %format!("{e:#}"),
                  "cannot listen for SIGTERM; this node will not say goodbye");
            std::future::pending::<()>().await;
            unreachable!("pending() never resolves");
        }
    };
    tokio::select! {
        _ = term.recv() => {}
        _ = tokio::signal::ctrl_c() => {}
    }
}

/// Fallback heartbeat after a report failure. Mark image and VM lists
/// incomplete; preserve node conditions and the stopping flag.
fn heartbeat_only(node: NodeStatus, stopping: bool) -> StatusReport {
    StatusReport {
        node: Some(node),
        vms: Vec::new(),
        routers: Vec::new(),
        images: Vec::new(),
        // Shutdown does not inspect images; its empty inventory is incomplete.
        images_complete: false,
        volumes: Vec::new(),
        snapshots: Vec::new(),
        stopping,
        migrations: Vec::new(),
        // Shutdown does not inspect or stop guests. Mark the farewell inventory
        // incomplete so absence cannot be interpreted as released ownership.
        vms_complete: false,
    }
}

/// Heartbeat and phases on the session stream: right after Hello, then every
/// `STATUS_INTERVAL` and whenever a command was processed.
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
                heartbeat_only(agent.node_status(), agent.shutdown.stopping())
            }
        };
        let farewell = report.stopping;
        if tx
            .send(AgentMessage {
                kind: Some(agent_message::Kind::Status(report)),
            })
            .await
            .is_err()
        {
            return; // session gone
        }
        if farewell {
            // The last one. Said once and then this task is done: another
            // beat after the farewell would be a node saying it is going and
            // then going on talking.
            info!("the controller has been told this node is stopping");
            agent.shutdown.said_goodbye();
            return;
        }
        tokio::select! {
            _ = tick.tick() => {}
            _ = wake.notified() => {}
        }
    }
}

/// Combine startup capacity measurements with current node conditions.
fn node_status(node: &NodeStatus, conditions: &crate::conditions::Conditions) -> NodeStatus {
    NodeStatus {
        conditions: conditions.report(),
        ..node.clone()
    }
}

/// What the controller schedules against. Read once at start-up.
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
        // Capacity is measured only at startup; invalid values need operator attention.
        error!(
            vcpus,
            mem_mib, "could not read node capacity, reporting what was found"
        );
    }
    info!(vcpus, mem_mib, "node capacity measured");
    NodeStatus {
        vcpus,
        mem_mib,
        // Node conditions are refreshed separately on each heartbeat.
        conditions: Vec::new(),
    }
}

/// The status task belongs to one session; when the session ends by any of
/// the loop's exits, so does the task.
struct AbortOnDrop(tokio::task::JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Check the nominal router dead-man arithmetic against heartbeat and
    /// keepalive intervals. This does not exercise real transport or driver timing.
    #[test]
    fn a_node_that_lost_the_controller_falls_silent_before_a_standby_can_be_promoted() {
        let lost = Instant::now();

        assert!(
            !should_fall_silent(lost, lost, ROUTER_DEAD_MAN),
            "the moment the session ends is not yet an outage"
        );
        assert!(!should_fall_silent(
            lost,
            lost + ROUTER_DEAD_MAN - Duration::from_millis(1),
            ROUTER_DEAD_MAN
        ));
        assert!(
            should_fall_silent(lost, lost + ROUTER_DEAD_MAN, ROUTER_DEAD_MAN),
            "a deadline is a deadline"
        );
        assert!(should_fall_silent(
            lost,
            lost + Duration::from_secs(600),
            ROUTER_DEAD_MAN
        ));
        // A clock that appears to have gone backwards must not take a
        // gateway down, which is what an unsaturated subtraction would do.
        assert!(!should_fall_silent(
            lost + Duration::from_secs(30),
            lost,
            ROUTER_DEAD_MAN
        ));

        // Mirror the controller's heartbeat timeout without an agent-to-controller
        // crate dependency; see `proto::KEEPALIVE_TIMEOUT`.
        const CONTROLLER_CALLS_A_NODE_DEAD: Duration = Duration::from_secs(30);
        assert!(
            ROUTER_DEAD_MAN + STATUS_INTERVAL < CONTROLLER_CALLS_A_NODE_DEAD,
            "a session that ended cleanly: the last heartbeat the controller \
             stamped is at most one report old, so the promotion is at \
             `end + 30 - 10` and this node has to be silent before it"
        );
        assert!(
            ROUTER_DEAD_MAN + proto::KEEPALIVE_INTERVAL + proto::KEEPALIVE_TIMEOUT
                < CONTROLLER_CALLS_A_NODE_DEAD,
            "and a wire that went black without saying so: finding out costs \
             this end one keepalive interval plus its timeout, and the \
             controller's own clock started when the wire did"
        );
    }

    /// Bridge whose `fall_silent` answers a scripted sequence and counts calls (R3-F06).
    #[derive(Default)]
    struct ScriptedBridge {
        answers: Mutex<
            std::collections::VecDeque<
                agent_api::networking::Result<agent_api::networking::Silencing>,
            >,
        >,
        calls: Mutex<u32>,
    }

    impl ScriptedBridge {
        fn new(
            answers: Vec<agent_api::networking::Result<agent_api::networking::Silencing>>,
        ) -> Self {
            Self {
                answers: Mutex::new(answers.into()),
                calls: Mutex::new(0),
            }
        }
    }

    #[async_trait::async_trait]
    impl agent_api::networking::BridgeDriver for ScriptedBridge {
        async fn ensure(&self, _name: &str) -> agent_api::networking::Result<()> {
            Ok(())
        }
        async fn ensure_address(
            &self,
            _name: &str,
            _addr: std::net::IpAddr,
            _prefix_len: u8,
        ) -> agent_api::networking::Result<()> {
            Ok(())
        }
        async fn destroy(&self, _name: &str) -> agent_api::networking::Result<()> {
            Ok(())
        }
        async fn fall_silent(
            &self,
        ) -> agent_api::networking::Result<agent_api::networking::Silencing> {
            *self.calls.lock().unwrap() += 1;
            self.answers
                .lock()
                .unwrap()
                .pop_front()
                .expect("the test scripted one answer per expected call")
        }
    }

    fn router(n: u128) -> agent_api::networking::RouterId {
        agent_api::networking::RouterId::from_u128(n)
    }

    /// A partial silencing pass must not be reported as complete (R3-F06).
    #[tokio::test]
    async fn a_router_that_failed_to_fall_silent_is_reported_as_partial_not_complete() {
        let a = router(1);
        let b = router(2);
        let bridge = ScriptedBridge::new(vec![
            Ok(agent_api::networking::Silencing {
                silenced: vec![a],
                failed: vec![b],
                kept: Vec::new(),
            }),
            Ok(agent_api::networking::Silencing {
                silenced: vec![a, b],
                failed: Vec::new(),
                kept: Vec::new(),
            }),
        ]);

        let complete = silence_routers_another_node_can_take_over(Some(&bridge)).await;
        assert!(
            !complete,
            "one router still answering is not a completed farewell"
        );

        let complete = silence_routers_another_node_can_take_over(Some(&bridge)).await;
        assert!(complete, "the retry reached every router");
        assert_eq!(*bridge.calls.lock().unwrap(), 2);
    }

    /// A driver error is as incomplete as a partial `Silencing` (R3-F06).
    #[tokio::test]
    async fn a_total_driver_failure_falling_silent_is_reported_as_incomplete() {
        let bridge = ScriptedBridge::new(vec![Err(agent_api::networking::NetworkError::Backend(
            anyhow!("the netns directory could not be read"),
        ))]);
        assert!(!silence_routers_another_node_can_take_over(Some(&bridge)).await);
    }

    /// A router kept answering as the only gateway of its provider network is no failure: the
    /// pass is complete, and the dead man does not retry it every round (IKR-B76).
    #[tokio::test]
    async fn a_router_kept_answering_as_the_only_gateway_completes_the_pass() {
        let bridge = ScriptedBridge::new(vec![Ok(agent_api::networking::Silencing {
            silenced: Vec::new(),
            failed: Vec::new(),
            kept: vec![router(1)],
        })]);
        assert!(silence_routers_another_node_can_take_over(Some(&bridge)).await);
    }

    /// A node without a bridge driver has nothing to silence (R3-F06).
    #[tokio::test]
    async fn a_node_with_no_bridge_driver_has_nothing_to_silence() {
        assert!(silence_routers_another_node_can_take_over(None).await);
    }

    /// One silencing attempt per backoff round; a failed round is retried on the next (R3-F06).
    #[tokio::test]
    async fn a_failed_round_is_retried_on_the_next_backoff_round_and_not_inside_one() {
        let a = router(1);
        let b = router(2);
        let bridge = ScriptedBridge::new(vec![
            Ok(agent_api::networking::Silencing {
                silenced: vec![a],
                failed: vec![b],
                kept: Vec::new(),
            }),
            Ok(agent_api::networking::Silencing {
                silenced: vec![a, b],
                failed: Vec::new(),
                kept: Vec::new(),
            }),
        ]);
        // Start past the dead-man deadline so the first iteration falls silent.
        let last_up = Instant::now() - ROUTER_DEAD_MAN - Duration::from_millis(1);
        let mut silenced = false;

        wait_out_the_backoff(
            Some(&bridge),
            last_up,
            &mut silenced,
            Duration::from_millis(20),
        )
        .await;
        assert!(
            !silenced,
            "a partial silencing must not be reported as complete"
        );
        assert_eq!(
            *bridge.calls.lock().unwrap(),
            1,
            "one attempt per backoff round, not a busy retry for the rest of it"
        );

        wait_out_the_backoff(
            Some(&bridge),
            last_up,
            &mut silenced,
            Duration::from_millis(20),
        )
        .await;
        assert!(silenced, "the retry on the next round reached every router");
        assert_eq!(*bridge.calls.lock().unwrap(), 2);
    }

    /// Router phase spellings must match the wire constants.
    #[test]
    fn the_two_words_a_node_says_about_a_router_are_the_ones_the_wire_names() {
        use agent_api::networking::RouterPhase;
        assert_eq!(RouterPhase::Ready.as_str(), proto::ROUTER_READY);
        assert_eq!(RouterPhase::Failed.as_str(), proto::ROUTER_FAILED);
        assert_eq!(
            RouterPhase::ALL.len(),
            2,
            "a third phase on this road needs a third arm in the cluster's observed_phase"
        );
    }

    /// A stopping report carries the flag and cannot lose an early notification.
    #[tokio::test]
    async fn a_clean_stop_is_announced_and_an_ordinary_beat_is_not() {
        let node = NodeStatus {
            vcpus: 8,
            mem_mib: 16_000,
            conditions: Vec::new(),
        };
        let shutdown = Shutdown::default();

        let beat = heartbeat_only(node.clone(), shutdown.stopping());
        assert!(!beat.stopping, "an ordinary beat says nothing of the kind");
        // The empty lists are "not saying", not "none of them" — this is the
        // report that goes out when the per-VM half could not be read.
        assert!(beat.vms.is_empty() && beat.volumes.is_empty());

        shutdown.begin();
        shutdown.begin(); // two signals are one shutdown
        let farewell = heartbeat_only(node.clone(), shutdown.stopping());
        assert!(farewell.stopping, "the last one does");
        assert_eq!(
            farewell.node.expect("node facts").vcpus,
            8,
            "and it is still a report, not a special message"
        );

        // The wait for it cannot be lost by being early: the status loop may
        // say goodbye before the signal handler starts waiting, and a permit
        // is what makes that harmless.
        shutdown.said_goodbye();
        tokio::time::timeout(Duration::from_secs(1), shutdown.goodbye_said())
            .await
            .expect("the farewell was not missed");
    }

    /// Heartbeat conditions change without replacing measured capacity.
    #[test]
    fn the_heartbeat_carries_what_is_wrong_with_this_node() {
        use crate::conditions::{Conditions, DISK_PRESSURE, STORE_UNHEALTHY};

        let measured = NodeStatus {
            vcpus: 32,
            mem_mib: 64_000,
            conditions: Vec::new(),
        };
        let conditions = Conditions::default();

        let healthy = node_status(&measured, &conditions);
        assert!(healthy.conditions.is_empty(), "a healthy node says nothing");
        assert_eq!((healthy.vcpus, healthy.mem_mib), (32, 64_000));

        conditions.raise(STORE_UNHEALTHY, "the agent database is not writable");
        conditions.raise(DISK_PRESSURE, "no room left on /var/lib/meisterstack");
        let sick = node_status(&measured, &conditions);
        let said: Vec<&str> = sick.conditions.iter().map(|c| c.r#type.as_str()).collect();
        assert_eq!(said, vec!["DiskPressure", "StoreUnhealthy"]);
        assert!(sick.conditions[1].message.contains("not writable"));
        // Capacity is untouched by it, and that is the point of the pair: the
        // node still HAS 32 vCPUs and can do nothing with them.
        assert_eq!((sick.vcpus, sick.mem_mib), (32, 64_000));

        // Cleared conditions disappear from the next report.
        conditions.clear(STORE_UNHEALTHY);
        conditions.clear(DISK_PRESSURE);
        assert!(node_status(&measured, &conditions).conditions.is_empty());
    }

    /// Only structural refusals carry `CannotServe` in `ErrorMsg.reason`,
    /// allowing rescheduling without matching human-readable error text.
    #[test]
    fn only_a_structural_refusal_carries_the_word_that_moves_a_vm() {
        let structural =
            cannot_serve::<()>(Err(anyhow!("no volume driver \"lvm-thin\""))).expect_err("refused");
        assert!(
            structural.downcast_ref::<CannotServe>().is_some(),
            "the marker survives the chain"
        );
        assert!(
            format!("{structural:#}").contains("lvm-thin"),
            "and the node's own words survive it too: {structural:#}"
        );

        // A transient boot failure is not a structural rescheduling refusal.
        let ordinary = anyhow!("the vmm exited with status 1");
        assert!(ordinary.downcast_ref::<CannotServe>().is_none());

        // And it survives another layer of context on top, which is what
        // `?` through two call sites produces.
        let deeper = cannot_serve::<()>(Err(anyhow!("no hypervisor")))
            .map_err(|e| e.context("creating the instance"))
            .expect_err("still refused");
        assert!(deeper.downcast_ref::<CannotServe>().is_some());

        // Ok passes through untouched, which is the case that runs a million
        // times a day.
        assert_eq!(cannot_serve(Ok(7)).unwrap(), 7);
    }

    /// Structural marking preserves each catalogue's complete rendered message once.
    #[test]
    fn a_structural_refusal_says_its_sentence_once_in_all_four_catalogues() {
        use crate::drivers::{DeviceCatalog, HypervisorCatalog, NetworkCatalog, VolumeCatalog};
        use std::collections::HashMap;

        // Rebuild catalogue errors with their context and `CannotServe` marker.
        // Factories allow repeated assertions because `anyhow::Error` is not Clone.
        type Refusal = Box<dyn Fn() -> anyhow::Error>;

        let cases: Vec<(&str, Refusal)> = vec![
            (
                "hypervisor",
                Box::new(|| {
                    HypervisorCatalog::new(None)
                        .validate()
                        .context("this node cannot run a vm")
                        .expect_err("a node that runs no vms")
                }),
            ),
            (
                "device",
                Box::new(|| {
                    DeviceCatalog::new(&HashMap::new())
                        .validate(&[crate::types::DeviceWithId {
                            id: uuid::Uuid::new_v4(),
                            spec: agent_api::device::DeviceSpec {
                                driver: "vfio".into(),
                                profile: None,
                                partition: agent_api::device::PartitionSpec::Exclusive,
                                params: None,
                            },
                        }])
                        .context("invalid device spec")
                        .expect_err("a node with no device drivers")
                }),
            ),
            (
                "volume",
                Box::new(|| {
                    VolumeCatalog::new(&HashMap::new())
                        .validate(&[crate::types::VolumeWithId {
                            id: uuid::Uuid::new_v4(),
                            spec: agent_api::storage::VolumeSpec {
                                base_image: None,
                                size_bytes: 4096,
                                driver: Some("lvm-thin".into()),
                                params: None,
                            },
                            referenced: false,
                        }])
                        .context("invalid volume spec")
                        .expect_err("a node without that backend")
                }),
            ),
            (
                "network",
                Box::new(|| {
                    NetworkCatalog::new(None, false, &[])
                        .validate(&[crate::types::NicWithId {
                            id: uuid::Uuid::new_v4(),
                            spec: agent_api::networking::NicSpec {
                                bridge: "br0".into(),
                                mac: "52:54:00:00:00:01".parse().expect("a mac"),
                                vxlan_id: None,
                                physnet: None,
                                floating_ips: Vec::new(),
                                routed_subnets: Vec::new(),
                            },
                        }])
                        .context("invalid nic spec")
                        .expect_err("a node that makes no taps")
                }),
            ),
        ];

        for (which, build) in cases {
            let plain = format!("{:#}", build());
            let marked = cannot_serve::<()>(Err(build())).expect_err("refused");
            assert_eq!(
                format!("{marked:#}"),
                plain,
                "{which}: the marker must not change the sentence"
            );
            assert!(
                marked.downcast_ref::<CannotServe>().is_some(),
                "{which}: and the word still travels"
            );
            // The shape of the old defect, said the way an operator would see
            // it: the second half of the sentence must not come round again.
            let (head, _) = plain.split_once(": ").unwrap_or((plain.as_str(), ""));
            assert_eq!(
                format!("{marked:#}").matches(head).count(),
                1,
                "{which}: said twice: {marked:#}"
            );
        }
    }
}

#[cfg(test)]
mod sweep_tests {
    use super::*;

    #[test]
    fn a_corrupt_vm_record_cannot_remove_its_anti_spoofing_rules() {
        let (_temp, store) = a_store("corrupt-filter-owner");
        store
            .put_raw(&VmId::new_v4().to_string(), b"not a vm record")
            .unwrap();
        assert!(live_taps_for_sweep(&store).unwrap().is_none());
    }

    /// A bridge driver that builds nothing and remembers what it was asked to
    /// keep.
    #[derive(Default)]
    struct SweepingBridge {
        asked: Mutex<Vec<Vec<u32>>>,
    }

    #[async_trait::async_trait]
    impl agent_api::networking::BridgeDriver for SweepingBridge {
        async fn ensure(&self, _: &str) -> agent_api::networking::Result<()> {
            Ok(())
        }
        async fn ensure_address(
            &self,
            _: &str,
            _: std::net::IpAddr,
            _: u8,
        ) -> agent_api::networking::Result<()> {
            Ok(())
        }
        async fn destroy(&self, _: &str) -> agent_api::networking::Result<()> {
            Ok(())
        }
        async fn sweep_overlays(&self, keep: &[u32]) -> agent_api::networking::Result<Vec<String>> {
            self.asked.lock().unwrap().push(keep.to_vec());
            Ok(vec!["meister-vx10003".to_string()])
        }
    }

    /// A record with one NIC on one tenant wire.
    fn on_the_wire(vni: u32) -> types::VmRecord {
        let mut record = types::VmRecord::blank();
        record.spec.nics = vec![types::NicWithId {
            id: agent_api::networking::NicId::new_v4(),
            spec: agent_api::networking::NicSpec {
                bridge: "br0".into(),
                mac: "52:54:00:00:00:01".parse().expect("a mac"),
                vxlan_id: Some(vni),
                physnet: None,
                floating_ips: Vec::new(),
                routed_subnets: Vec::new(),
            },
        }];
        record
    }

    /// A store in a directory of its own, and the guard that removes it.
    fn a_store(tag: &str) -> (tempfile::TempDir, Store) {
        let temp = tempfile::Builder::new()
            .prefix(&format!("meister-sweep-{tag}-"))
            .tempdir()
            .expect("a temp dir");
        let store = Store::open(&temp.path().join("agent.redb")).expect("a store");
        (temp, store)
    }

    /// The keep-list is every wire any record here names, and nothing else.
    #[tokio::test]
    async fn the_sweep_keeps_every_wire_a_record_names() {
        let (_temp, store) = a_store("keeps");
        for vni in [10_001, 10_002, 10_001] {
            store
                .put(&VmId::new_v4(), &on_the_wire(vni))
                .expect("a record");
        }
        // And one VM with no overlay at all, which contributes nothing.
        store
            .put(&VmId::new_v4(), &types::VmRecord::blank())
            .expect("a record");

        let bridge = SweepingBridge::default();
        sweep_orphan_overlays(&store, &bridge).await;

        assert_eq!(
            *bridge.asked.lock().unwrap(),
            vec![vec![10_001, 10_002]],
            "asked once, sorted, without the wire named twice"
        );
    }

    /// Unreadable VM rows cancel overlay sweeping because they may reference any VNI.
    #[tokio::test]
    async fn a_record_this_build_cannot_read_cancels_the_sweep() {
        let (_temp, store) = a_store("cancels");
        store
            .put(&VmId::new_v4(), &on_the_wire(10_001))
            .expect("a record");
        store
            .put_raw(
                &VmId::new_v4().to_string(),
                br#"{"spec":"from a later build"}"#,
            )
            .expect("a raw row");

        let bridge = SweepingBridge::default();
        sweep_orphan_overlays(&store, &bridge).await;

        assert!(
            bridge.asked.lock().unwrap().is_empty(),
            "nothing may be swept while a record cannot be read"
        );
    }
}

/// Source-text checks for malformed message spacing and fixed test resources.
#[cfg(test)]
mod source_rules {
    /// Source directories scanned by these checks.
    const SITE: [&str; 4] = [
        "components/agent/src",
        "drivers",
        "shared/agent-api/src",
        "shared/common/src",
    ];

    /// Flag runs of four spaces between sentence-like bytes in a quoted line.
    /// This is a source-text heuristic, not a Rust string parser.
    #[test]
    fn no_sentence_of_this_construction_site_is_broken_by_a_missing_backslash() {
        let mut checked = 0usize;
        let mut holes: Vec<String> = Vec::new();
        for file in sources() {
            let source = std::fs::read_to_string(&file).expect("a source file");
            checked += 1;
            for (i, line) in source.lines().enumerate() {
                if line.trim_start().starts_with("//") {
                    continue;
                }
                if let Some(said) = broken_sentence(line) {
                    holes.push(format!("{}:{}: {said}", file.display(), i + 1));
                }
            }
        }
        assert!(checked > 40, "the walk found almost nothing: {checked}");
        assert!(holes.is_empty(), "{}", holes.join("\n"));
    }

    /// Recursively collect Rust files from the configured workspace directories.
    fn sources() -> Vec<std::path::PathBuf> {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(|p| p.parent())
            .expect("the workspace root is two above this crate")
            .to_path_buf();
        let mut out = Vec::new();
        let mut stack: Vec<std::path::PathBuf> = SITE.iter().map(|d| root.join(d)).collect();
        for dir in &stack {
            assert!(
                dir.is_dir(),
                "{} is not where this test looks",
                dir.display()
            );
        }
        while let Some(here) = stack.pop() {
            for entry in std::fs::read_dir(&here).expect("a readable directory") {
                let path = entry.expect("a directory entry").path();
                match path.is_dir() {
                    true => stack.push(path),
                    false if path.extension().is_some_and(|e| e == "rs") => out.push(path),
                    false => {}
                }
            }
        }
        out
    }

    /// Reject direct temp_dir calls and literal nonzero bind ports.
    /// Variable ports and Unix socket paths are outside this source-text check.
    #[test]
    fn no_source_of_this_construction_site_names_a_fixed_temp_path_or_port() {
        // Split so that this test's own source does not match itself.
        let temp_dir = concat!("env::", "temp_dir(");
        let mut checked = 0usize;
        let mut sins: Vec<String> = Vec::new();
        for file in sources() {
            let source = std::fs::read_to_string(&file).expect("a source file");
            checked += 1;
            for (i, line) in source.lines().enumerate() {
                if line.trim_start().starts_with("//") {
                    continue;
                }
                let at = format!("{}:{}", file.display(), i + 1);
                if line.contains(temp_dir) {
                    sins.push(format!("{at}: a temp path of its own instead of tempfile"));
                }
                if let Some(addr) = bound_address(line) {
                    sins.push(format!("{at}: binds {addr:?} instead of port 0"));
                }
            }
        }
        assert!(checked > 40, "the walk found almost nothing: {checked}");
        assert!(sins.is_empty(), "{}", sins.join("\n"));
    }

    /// Extract nonzero literal bind addresses from string or tuple syntax.
    /// Variable addresses are outside this source check.
    fn bound_address(line: &str) -> Option<&str> {
        let call = concat!("bind", "(");
        let after = line.split_once(call)?.1;
        if let Some(rest) = after.strip_prefix('"') {
            let addr = rest.split_once('"')?.0;
            // A path is a unix socket and another question; this is ports.
            return (addr.contains(':') && !addr.ends_with(":0")).then_some(addr);
        }
        let inner = after.strip_prefix('(')?.split_once("))")?.0;
        let port = inner.rsplit_once(',')?.1.trim();
        match port.parse::<u16>() {
            Ok(0) | Err(_) => None,
            Ok(_) => Some(inner),
        }
    }

    /// The literal on this line, if a sentence runs through a run of spaces
    /// in it.
    fn broken_sentence(line: &str) -> Option<&str> {
        let start = line.find('"')? + 1;
        let end = line.rfind('"')?;
        let inner = line.get(start..end).filter(|s| !s.is_empty())?;
        let bytes = inner.as_bytes();
        let mut i = 0;
        while i < bytes.len() {
            if bytes[i] != b' ' {
                i += 1;
                continue;
            }
            let run = bytes[i..].iter().take_while(|b| **b == b' ').count();
            let (before, after) = (bytes.get(i.wrapping_sub(1)), bytes.get(i + run));
            let word_before = before.is_some_and(|b| b.is_ascii_lowercase() || b";,.".contains(b));
            let word_after = after.is_some_and(u8::is_ascii_lowercase);
            if run >= 4 && i > 0 && word_before && word_after {
                return Some(inner);
            }
            i += run;
        }
        None
    }
}
