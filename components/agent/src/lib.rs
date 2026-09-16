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
use std::time::{Duration, SystemTime};
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
/// A refusal that is about this NODE and not about this attempt.
///
/// A marker in the error chain, read back out by the dispatcher one function
/// down and written into `ErrorMsg.reason` as `proto::CANNOT_SERVE`. It
/// carries the sentence too so that `{e:#}` still reads as it did — the
/// node's own words are what an operator sees.
#[derive(Debug)]
struct CannotServe(String);

impl std::fmt::Display for CannotServe {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for CannotServe {}

/// Mark a refusal as being about this NODE rather than about this attempt.
///
/// The error keeps its own sentence — the node's word is what an operator
/// reads — and gains the word the tier above branches on. See
/// `Refused::cannot_serve`.
///
/// **One link, and that is the whole of the change.** This used to hang the
/// already formatted sentence on the chain as CONTEXT, which left two links
/// saying the same thing — and `{e:#}` joins a chain with ": ", so every
/// structural refusal reached the API doubled:
///
/// ```text
/// invalid nic spec: this node has no [network] section …: invalid nic spec: this node has no [network] section …
/// ```
///
/// on `refusedBy[].message`, and in all four catalogues rather than only the
/// network one. Rendering the chain INTO the marker and making the marker the
/// error keeps the sentence byte for byte what it was and says it once.
///
/// What is given up is the typed causes underneath, and nothing reads them:
/// `heals_without_an_operator` looks for `NoSuchVm`, a uuid parse error and
/// the held-volume answer, and none of the three can appear under one of the
/// four structural checks — those refuse over configuration this node does
/// not have. Context added ON TOP still finds the marker, which is what `?`
/// through two call sites produces.
fn cannot_serve<T>(r: anyhow::Result<T>) -> anyhow::Result<T> {
    r.map_err(|e| anyhow::Error::new(CannotServe(format!("{e:#}"))))
}

fn heals_without_an_operator(e: &anyhow::Error) -> bool {
    e.chain().any(|cause| {
        cause.is::<NoSuchVm>()
            || cause.is::<uuid::Error>()
            // "a vm is holding it" is a CORRECT answer about a volume, not a
            // fault on this node: the controller clears `attachedTo` and asks
            // again, and nothing here needs an operator.
            || cause.is::<crate::volumes::HeldByVm>()
    })
}

/// How long the agent waits for its farewell to reach the controller before
/// it goes anyway.
///
/// A stop must stop. This is the one report that is worth a short wait and
/// nothing is worth a long one: an agent that hung on its own shutdown would
/// be a unit systemd eventually kills, which is the very ambiguity the
/// farewell exists to remove.
const LAST_WORD: Duration = Duration::from_secs(2);

/// Whether this agent is on its way out, and whether it has said so.
///
/// The state behind `StatusReport.stopping`. It is set once and never
/// cleared: an agent that has been asked to stop does not change its mind,
/// and a flag that could go back would let a stopping node claim to be
/// staying.
#[derive(Default)]
pub struct Shutdown {
    asked: std::sync::atomic::AtomicBool,
    /// Notified by the status loop once a report carrying `stopping` has gone
    /// into the session. `Notify` and not a channel because the waiter may
    /// arrive after the sender: `notify_one` leaves a permit, so the farewell
    /// cannot be missed by being early.
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
    /// What a guest's machine state would be restored INTO here — read once,
    /// for the same reason: none of it changes under a running agent. See
    /// `crate::machine`, and `controller_api::live_migration_refusal` for
    /// what the tier above does with two of them.
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
    /// Wakes the status loop of whichever session is current. On the agent
    /// rather than inside `run_session`, because the signal handler is
    /// outside every session and still has to get one last report out.
    report_now: Arc<tokio::sync::Notify>,
    /// Where a migration stream lands on this node, decided once at start-up.
    /// See `crate::migration`.
    migration: crate::migration::Endpoint,
    /// The console sessions this node is serving over the controller stream,
    /// by the session_id the tier above chose. Keyed by that and not by VM,
    /// because two attempts on the same VM are two sessions — the second is
    /// refused, and it has to be refused under its OWN id or the refusal
    /// reaches the wrong client.
    console_sessions: Mutex<HashMap<String, ConsoleSession>>,
}

/// One console session as the agent holds it: a way to type into the guest,
/// and the task that is pumping its output upwards.
struct ConsoleSession {
    /// Types into the guest. Holds nothing — the holding is the pump's,
    /// because when the reader stops the line is free.
    writer: crate::attach::ConsoleWriter,
    /// Owns the `Held`, so aborting it releases the line.
    pump: tokio::task::JoinHandle<()>,
}

impl Agent {
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
            .map(|(name, profiles)| DriverInfo {
                name,
                profiles,
                // Localities are a storage fact; a device driver has none and
                // says so by leaving the field empty.
                locality: String::new(),
            })
            .collect();
        // ONE entry per backend rather than one entry listing them all,
        // because the entry now carries a second fact and the two backends do
        // not agree about it: lvm-thin is node-local and nfs is shared. The
        // flattened catalogue one tier up is byte-identical either way — it
        // is built per (name, profile) pair — so this costs nothing anybody
        // downstream has to know about.
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
        // The snapshot half of the storage claim, in its own entry and with
        // no locality on it. `volume/<backend>/snapshot` — the same
        // `<driver>/<profile>` spelling a GPU profile takes, so the tier above
        // can ask "does this node offer it" with the function it already has,
        // and a pool whose driver cannot snapshot is a 422 rather than a
        // Failed object. The empty locality is what keeps the entry out of
        // `capacity_localities`, which parses the field and skips what it
        // cannot read.
        let snapshots = self.volumes.snapshot_claims();
        if !snapshots.is_empty() {
            drivers.push(DriverInfo {
                name: common::capability::VOLUME.to_string(),
                profiles: snapshots,
                locality: String::new(),
            });
        }
        // Whether this node runs VMs at all, claimed the same way and for a
        // sharper reason than the rest: a storage node has room, is connected
        // and is schedulable, so without this entry it is indistinguishable
        // from a compute node and the first ordinary VM lands on it.
        //
        // The `if` is the same one the network half has, and matters more
        // here: an entry with no profiles flattens to the bare driver name,
        // and a bare `hypervisor` in the catalogue would answer a bare
        // request for it — which is exactly the request the FOLLOW-UP step
        // will introduce. A storage node answering it would undo the whole
        // point of the entry.
        let hypervisors = self.hypervisor.inventory();
        if !hypervisors.is_empty() {
            drivers.push(DriverInfo {
                name: common::capability::HYPERVISOR.to_string(),
                profiles: hypervisors,
                locality: String::new(),
            });
        }
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
                locality: String::new(),
            });
        }
        Hello {
            node_id: node_id.to_string(),
            agent_version: env!("CARGO_PKG_VERSION").to_string(),
            drivers,
            // Said here and only here: it is a fact about the machine, it does
            // not change while this agent runs, and the one party that needs
            // it is the one choosing a live migration's destination.
            machine: Some(self.machine.clone()),
        }
    }

    /// Every router this node holds, in the form the session carries.
    ///
    /// Straight out of the driver's trait and derived from nothing here: WHAT
    /// a router is — built, half-gone, active, silent — is the answer of
    /// whoever built it, and an agent that recomputed it from a spec it kept
    /// would be a second truth about the same namespace.
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
                    // Straight out of the driver, like the phase beside it:
                    // whether a router is gone, half gone or unaskable is the
                    // answer of whoever looked, and this agent does not
                    // recompute it.
                    reason: r
                        .reason
                        .map(|reason| reason.as_str().to_string())
                        .unwrap_or_default(),
                    message: r.message,
                    active: r.active,
                    // Empty on this road, by construction: a node naming
                    // itself back to the controller that addressed it says
                    // nothing. The cluster fills both in when it passes the
                    // report on. See `proto::RouterReport.node`.
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

    /// What this node is, and what is wrong with it.
    ///
    /// Built per report and not once at start-up, unlike the capacity it
    /// carries: the conditions are the half that changes, and they are the
    /// half a controller can act on — a node that cannot write its records is
    /// one the scheduler has to stop placing on, and until this field existed
    /// there was nothing on the heartbeat that said so.
    fn node_status(&self) -> NodeStatus {
        // Measured again, here, because this is the sentence that carries it:
        // a group that was added to the unit, a module that loaded, a udev
        // rule that arrived late all change what this node can do without
        // changing anything about the process.
        self.unprivileged.refresh(&self.conditions);
        node_status(&self.node, &self.conditions)
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
        // What this node has to say about the guests it was told to SEND,
        // lifted out before the VMs so it can be read off the same
        // observation. Empty on every node with no migration in flight, which
        // is nearly all of them; see `MigrationReport` in control.proto for
        // why it travels here and not in the answer to `MigrateOut`.
        let migrations: Vec<proto::MigrationReport> = reported
            .iter()
            .filter_map(|r| {
                r.departure.as_ref().map(|d| proto::MigrationReport {
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
                // What this node HAS open, so the tier above can tell a
                // dispatched hot-plug from a finished one.
                attached_volumes: r.volumes.iter().map(uuid::Uuid::to_string).collect(),
                // Empty on this road by construction: a node reporting its
                // own name back to the controller that addressed it says
                // nothing. The field is the CLUSTER's, one tier up, where it
                // is the one placement fact the cloud cannot derive.
                node: String::new(),
                // Both empty on this road: `attached_volumes` above is this
                // tier's answer, by uid, and a node knows nothing about a
                // placement decision one tier up.
                volumes: Vec::new(),
                // The word that says why the phase is what it is, empty for
                // the three phases that need none. A string because this side
                // does not know the control plane's enum; see
                // `reconcile::observe::reason_table`.
                reason: r
                    .reason
                    .map(|reason| reason.as_str().to_string())
                    .unwrap_or_default(),
                // The taps this node made, with the address the network
                // driver pinned on each. The one half of
                // `Vm.status.addresses[]` that has to come from down here —
                // the other is a floating address, which is the cloud's own
                // object and needs nobody's report. A tap whose driver knows
                // no address is left out, and a VM with no taps reports
                // nothing at all, which reads exactly like an agent from
                // before the field and is meant to: neither of them is
                // saying "this VM has no addresses".
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
        // Before the report is built and not inside it: what the image half
        // says is a statement about this node's disk right now. Two looks,
        // and they answer two different questions — `verify_path_images`
        // looks at the images the records here NAME (and can therefore say
        // why one is unusable), `take_inventory` reads the directory (and can
        // therefore say that a name is not in it at all). See F16.
        self.reconciler.verify_path_images().await;
        let images_complete = self.images.take_inventory().await;
        Ok(StatusReport {
            node: Some(self.node_status()),
            vms,
            // What this node HOLDS, router by router — the same rule the VM
            // half follows: what is, not what was asked. Empty on every node
            // with no gateway slot, and on a node whose driver could not be
            // asked: a report that failed to list routers is a report about
            // this node's VMs that still has to go out, and the next one is
            // three seconds away.
            routers: self.routers().await,
            // What this node has learned about the base images its records
            // name — the ones it fetched, and the ones that are somebody
            // else's file on shared storage.
            //
            // F16: a path image was looked at once per reconcile pass and
            // reported on every beat in between out of that one look, so an
            // image that had gone missing kept being reported `Ready` for as
            // long as three reports. The look happens here now, once per
            // image per report, and `Cache::report` below is a read of what
            // it found. `verify_path_images` is what bounds the cost: the
            // names are a set, so forty VMs off three images is three
            // `stat`s, and nothing is fetched or hashed on this path.
            images: self
                .images
                .report()
                .into_iter()
                .map(|(name, state)| proto::ImageStateReport {
                    name,
                    phase: state.phase().to_string(),
                    // Which of the four ways an image is unusable this is —
                    // the bytes are not there, the name is a directory, the
                    // checksum did not match, the fetch did not work. Empty
                    // for `Ready`.
                    reason: state
                        .reason()
                        .map(|reason| reason.as_str().to_string())
                        .unwrap_or_default(),
                    message: state.message().to_string(),
                    // Empty on this road: the controller addressed this node
                    // and knows which one it is. It fills the field in on the
                    // way up, where the cloud does not.
                    node: String::new(),
                })
                .collect(),
            // Whether the list above is EVERY image under this node's image
            // directory or only the ones it has an opinion about. See
            // `Cache::take_inventory`: only a `true` lets the tier above read
            // a missing name as a missing file, which is what closes F16 for
            // an image no record here names.
            images_complete,
            // The volumes this node owns on their own. Empty on a node that
            // was never told to make one, which is every node before this
            // milestone — and empty is "knows of none", never "they are gone".
            volumes: self.volumes_owned.report(),
            // And the copies of them. A list of its own rather than a phase
            // on the volume, because a snapshot outlives its volume — putting
            // it on the volume would lose it exactly when it is the only one
            // of the two still there.
            snapshots: self.volumes_owned.report_snapshots(),
            // False on every report but the last one. See `Shutdown`.
            stopping: self.shutdown.stopping(),
            migrations,
        })
    }
}

/// Somewhere to write the records, and the list of what is wrong with this
/// node.
///
/// The two that have to exist before anything else can. The condition set is
/// made here and handed to the store, because the store is the first thing
/// that can find something wrong with this node; everything else that raises
/// into it gets the same `Arc`, so what the heartbeat carries is one list and
/// not three.
fn store_and_conditions(
    cfg: &AgentConfig,
) -> anyhow::Result<(Arc<crate::conditions::Conditions>, Arc<Store>)> {
    let conditions = Arc::new(crate::conditions::Conditions::default());
    let store = Arc::new(Store::open_reporting_to(
        &cfg.paths.db_path,
        conditions.clone(),
    )?);
    // Before any VM is provisioned, because it is a fact about this node and
    // not about a VM: an agent whose `cgroup_root` is an ordinary directory
    // can start a guest and can never tear one down. It still starts — see
    // `check_cgroup_root` — and the cluster is told instead.
    //
    // The FIRST of many. Every reconcile pass asks the same question, because
    // a mount can go away while an agent runs; this one is here so that the
    // answer is in the log of the boot rather than thirty seconds into it,
    // which is the same argument `catalogues` makes for its three sentences.
    if crate::conditions::check_cgroup_root(&cfg.paths.cgroup_root, &conditions) {
        info!(cgroup_root = %cfg.paths.cgroup_root.display(),
              "cgroup2 confirmed at the configured root");
    }
    Ok((conditions, store))
}

/// What this node may be asked for, in the four lists the controller reads.
///
/// One value and not four returns, because they are one answer: which
/// drivers this agent came up with decides all of them, and a node that
/// claims three of the four is a node that has been half configured.
struct Catalogues {
    catalog: DeviceCatalog,
    volumes: VolumeCatalog,
    hypervisor: HypervisorCatalog,
    network: NetworkCatalog,
}

/// The four catalogues, and the three sentences a node says about itself
/// when it is missing something.
///
/// Said at start-up rather than at the first refusal: "this node runs no
/// vms" is a fact an operator wants in the log of the boot that made it
/// true, not in the error of the create that fell over it.
fn catalogues(cfg: &AgentConfig, drivers: &Drivers) -> Catalogues {
    let catalog = DeviceCatalog::new(&drivers.devices);
    let volumes = VolumeCatalog::new(&drivers.storage);
    let hypervisor = HypervisorCatalog::new(drivers.hypervisor_name.as_deref());
    if hypervisor.validate().is_err() {
        info!("this node runs no vms and offers storage only; it claims no hypervisor capability");
    }
    // What the DRIVER built, not what the file says: a physnet the driver
    // refused a name for never gets here, because such a node does not start.
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

/// What a `kill -9` left behind on this node, taken away before the first
/// reconcile.
///
/// Both halves read the same evidence — the records are the truth about what
/// exists — and both are about the far end of a teardown that was
/// interrupted: filter chains for taps this node does not hold, and overlay
/// links no record names.
async fn sweep_what_no_record_names(
    cfg: &AgentConfig,
    store: &Store,
    networking: Option<&Arc<dyn agent_api::networking::NicDriver>>,
    bridge: Option<&Arc<dyn agent_api::networking::BridgeDriver>>,
) -> anyhow::Result<()> {
    let live_taps: Vec<String> = store
        .list()?
        .iter()
        .flat_map(|(_, record)| record.nics.iter().map(|n| n.tap_name.clone()))
        .collect();
    // Nothing to reap on a node that makes no taps, and nobody to ask.
    if let Some(driver) = networking {
        driver.reap(&live_taps).await;
    }

    // And the overlays beside them, on the same evidence and at the same
    // moment. Configurable and on by default; see `sweep_orphans`.
    if cfg
        .network
        .as_ref()
        .is_some_and(|network| network.sweep_orphans)
        && let Some(driver) = bridge
    {
        sweep_orphan_overlays(store, driver.as_ref()).await;
    }

    // The router half of the same sentence, and the one place it differs: a
    // router is not reference-counted from VM records, so there is no keep
    // -list to hand over. This driver's own record beside a namespace is the
    // whole of what says the namespace belongs to a live router.
    if let Some(driver) = bridge {
        match driver.sweep_routers().await {
            Ok(swept) if swept.is_empty() => {}
            Ok(swept) => info!(?swept, "orphaned routers removed"),
            Err(e) => warn!(error = %format!("{e:#}"), "sweeping orphaned routers failed"),
        }
    }
    Ok(())
}

/// Festlegung 1: every provider network this node names gets its bridge, with
/// the interface in it and no address on the host.
///
/// At start-up and once, before the first reconcile and before the session:
/// a node that claims `network/gateway:<physnet>` in its Hello has to have
/// made the bridge it would put a router's leg into, or the first router
/// placed here would be the moment anybody found out.
///
/// A failure here fails the START, which is the whole point. The two ways it
/// fails are an interface that is not there and an interface that still
/// carries an address, and neither is something the node can fix by trying
/// again.
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
    let drivers = Drivers::from_config(&cfg).await?;
    // The start-check again, for the half of it that is not a build decision:
    // what the heartbeat has to keep saying. `screen` is pure — same config,
    // same rights, same answer — so asking it twice is a second measurement
    // and not a second authority, and `from_config` keeps owning which
    // drivers get built. It has already said each sentence once, at WARN.
    let unprivileged = Arc::new(crate::privileges::Watch::new(
        Arc::new(crate::privileges::Host),
        crate::drivers::screen(&cfg, &crate::privileges::Host).watch,
    ));
    // Raised here and not only on the first heartbeat, for the reason
    // `store_and_conditions` gives about the cgroup root: the answer belongs
    // in the log of the boot that made it true, and a node with no
    // controller configured never sends a heartbeat at all.
    unprivileged.refresh(&conditions);
    let networking_driver = drivers.networking.clone();
    let bridge_driver = drivers.bridge.clone();
    // Cloned before the reconciler takes ownership of `drivers`, and for one
    // question: what this node would restore a guest's machine state INTO.
    // See `machine_profile`.
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
    let images = Arc::new(crate::images::Cache::new(cfg.paths.image_dir.clone()));
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
    // The volume half, over the SAME driver registry the inline path uses.
    // Built before the reconciler takes ownership of `drivers`, because both
    // halves route on the same map and a second one would be a second answer
    // to "which backend owns these bytes".
    let volumes_owned = Arc::new(crate::volumes::Volumes::new(store.clone(), drivers.clone()));
    let reconciler = Arc::new(Reconciler::new(
        store.clone(),
        drivers,
        provisioner.clone(),
        ops.clone(),
    ));

    // Ask every backend whether the volumes this node thinks it has are
    // really there — the same adoption VMs get, one table over.
    volumes_owned.adopt().await;

    // Festlegung 1, and it is a start-up question: the interface has been
    // given away or it has not. A node whose provider interface still carries
    // an address does not come up — see `ensure_physnet` for why that is a
    // refusal and not a repair.
    give_the_interfaces_away(&cfg, bridge_driver.as_ref()).await?;

    sweep_what_no_record_names(
        &cfg,
        &store,
        networking_driver.as_ref(),
        bridge_driver.as_ref(),
    )
    .await?;

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
        // Still stoppable. There is nobody to say goodbye to, but a unit that
        // ignored SIGTERM would be killed rather than stopped, and having no
        // controller does not make that better.
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

    tokio::select! {
        _ = dial_forever(&agent, &cfg, tls.as_ref(), &mut redial) => Ok(()),
        _ = say_goodbye(&agent) => {
            info!("agent stopped");
            Ok(())
        }
    }
}

/// What a guest's machine state would be restored INTO on this node.
///
/// Assembled once, at start-up, out of three sources that each know a
/// different part: `/proc` and `/sys` know the silicon and the kernel, the
/// hypervisor driver knows its own version and the cpuid profile it hands a
/// guest, and the CONFIG knows the one thing the machine cannot see about
/// itself — which physical host it is on when it is a guest.
///
/// It travels in the Hello and nowhere else, because none of it changes while
/// this agent runs; what the tier above does with two of them is
/// `controller_api::live_migration_refusal`, which is where the rules are
/// argued.
///
/// A node with no hypervisor still sends one. The silicon and the kernel are
/// true of it either way, and a node that runs no VMs is never the end of a
/// migration in the first place.
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

/// The overlay links on this node that no record names, taken down once.
///
/// Nachlese 5. The chaos run left VNI 10003 and 10004 standing on three lab
/// nodes, and nothing was ever going to remove them: the count that takes an
/// overlay down is over records, and both wires had lost their last record
/// while their agent was not running. A leak with no failure mode except
/// itself — a machine that runs VMs for a living gaining links for ever.
///
/// **A row this build cannot read stops the sweep.** The keep-list is every
/// VNI named by any record here, and a row nobody can read might name any of
/// them; sweeping on an incomplete list would take a live tenant's wire down.
/// Two readers of the same table, two directions to be careful in: the
/// reference count counts the unreadable row as a user, and this declines
/// altogether. Both keep the overlay up.
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

/// The pass that runs whether anybody asks or not, every thirty seconds, for
/// as long as this agent does.
///
/// Its own task and not part of the session loop: it is the half of the
/// agent that answers for this node's VMs when no controller is connected at
/// all, which is the state a node spends every restart of the tier above in.
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

/// Where a migration stream lands here, decided once and never again: an
/// address a peer can reach and a range of ports somebody opened. Derived
/// from the route to the controller when the config does not say, which is
/// by construction an address on the cluster network — and said out loud
/// either way, because "this node does not receive live migrations" is a
/// fact an operator should read at start-up rather than in the middle of a
/// drain.
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
        if let Some(wait) = redial.ended(established) {
            warn!(?wait, endpoints = of, "no controller answered, waiting");
            tokio::time::sleep(wait).await;
        }
    }
}

/// A stop that says so.
///
/// Without this the controller cannot tell an agent that was stopped from a
/// machine that died: both are simply a heartbeat that does not arrive, and
/// the tier above has to wait out the whole watchdog before it may believe
/// anything. The chaos run found the fleet in exactly that state — an agent
/// twenty hours dead, eleven VMs still reported Running — and the
/// controller's half of it (`observed_at` against the clock) is C2. This is
/// the node's half: say goodbye.
///
/// SIGINT alongside SIGTERM because a person stopping an agent by hand in a
/// terminal is the same event as systemd stopping one.
async fn say_goodbye(agent: &Arc<Agent>) {
    a_stop_was_asked_for().await;
    info!("a stop was asked for; telling the controller before going");
    agent.shutdown.begin();
    agent.report_now.notify_one();
    // Bounded, and short. A controller that is not there to hear it is
    // the case the watchdog was always for.
    if tokio::time::timeout(LAST_WORD, agent.shutdown.goodbye_said())
        .await
        .is_err()
    {
        warn!(
            ?LAST_WORD,
            "the last report did not get out in time; going anyway"
        );
    }
    give_back_what_is_half_built(agent).await;
    stop_speaking_for_every_router(agent).await;
}

/// The router half of the farewell: this node stops answering for addresses
/// its cluster is about to hand to somebody else.
///
/// It runs AFTER the goodbye and not before, because the order is the whole
/// of it: the cluster hears "I am going", makes the standby active, and this
/// node has already stopped speaking by the time it does. The other order
/// would be a gap in which nobody answers.
///
/// It takes nothing down. A stopping agent's routers stay built for the same
/// reason its guests stay running — `systemctl restart` is not an outage —
/// and what is left behind is exactly a standby.
async fn stop_speaking_for_every_router(agent: &Agent) {
    let Some(bridge) = agent.reconciler.drivers().bridge.as_ref() else {
        return;
    };
    match bridge.fall_silent().await {
        Ok(silenced) if silenced.is_empty() => {}
        Ok(silenced) => info!(?silenced, "this node's routers fell silent on the way out"),
        Err(e) => warn!(error = %format!("{e:#}"),
                        "this node's routers could not be silenced; it may still answer for \
                         addresses its cluster has moved"),
    }
}

/// The one kind of VMM a stopping agent takes with it.
///
/// **Running guests survive an agent restart, and that is not negotiable.**
/// The whole design rests on it: a record on disk, a pid in it, an adoption
/// on the way back up. An agent that killed its guests on SIGTERM would make
/// `systemctl restart meister-agent` an outage, and this function is
/// deliberately not that.
///
/// A RECEIVING VMM is the exception, and it is the other half of D18. It has
/// no guest — it is a process listening on a port for one — and it holds a
/// cgroup, a set of taps and, on a fabric, a live NVMe/TCP session to
/// somebody's disk. If this agent goes away, nothing will ever finish that
/// reception: the task that was watching it dies here, the cluster's
/// migration will time out, and what is left is the ghost the lab found — a
/// VMM and an open disk held for a guest that has been running on another
/// machine for hours. The record's own `receive_deadline` catches it on the
/// way back up, which is minutes; this catches it now, which is right.
///
/// Best effort and bounded by nothing but the teardown itself: a stop that
/// hangs here is worse than a leak, and the process is going either way.
/// Every failure is a WARN, because the next start reads the same records and
/// the same deadline.
async fn give_back_what_is_half_built(agent: &Agent) {
    let records = match agent.store.list() {
        Ok(records) => records,
        Err(e) => {
            warn!(error = %format!("{e:#}"), "cannot read the records on the way out");
            return;
        }
    };
    for id in half_built(&records) {
        info!(vm_id = %id,
              "a guest was on its way here and this agent is going; giving the vmm back");
        if let Err(e) = agent.provisioner.teardown(&id).await {
            warn!(vm_id = %id, error = %format!("{e:#}"),
                  "the listening vmm could not be torn down; its receive deadline ends it");
        }
    }
}

/// Which of this node's VMs a stopping agent takes with it: the ones that are
/// waiting for a guest, and nothing else.
///
/// Pure, and separate for the reason every rule in this tree that decides
/// somebody's guest is: the whole of the decision is the one line below, and
/// a decision that can only be reached by stopping an agent is a decision
/// nobody checks. See `give_back_what_is_half_built` for the argument.
fn half_built(records: &[(agent_api::VmId, types::VmRecord)]) -> Vec<agent_api::VmId> {
    records
        .iter()
        .filter(|(_, record)| record.phase == types::Phase::Receiving)
        .map(|(id, _)| *id)
        .collect()
}

/// One session with one controller endpoint, from the dial to the end of the
/// stream: say hello, put the status report on its own task, then pump.
///
/// Three steps and no fourth. The farewell is NOT one of them — it is sent by
/// `run_agent`, out of the shutdown path, because a session that has already
/// ended is exactly the case in which somebody still has to say goodbye.
#[instrument(skip_all, fields(endpoint = %controller_addr))]
async fn run_session(
    agent: &Arc<Agent>,
    controller_addr: &str,
    cfg: &AgentConfig,
    tls: Option<&tonic::transport::ClientTlsConfig>,
    established: &mut bool,
) -> anyhow::Result<()> {
    let (mut inbound, tx) = dial_and_say_hello(agent, controller_addr, cfg, tls).await?;
    // From here on this endpoint has answered: whatever ends the session, it
    // is not "nobody is there", and the caller's backoff should say so.
    *established = true;

    // Status goes out on its own task, not from this loop: provisioning a
    // single VM can take longer than the controller's liveness window, and a
    // node that is busy is not a node that is gone.
    let report_now = agent.report_now.clone();
    let _status = AbortOnDrop(tokio::spawn(
        status_loop(agent.clone(), tx.clone(), report_now.clone())
            .instrument(info_span!("status_report")),
    ));

    pump(agent, &mut inbound, &tx, &report_now).await;
    Ok(())
}

/// Dial the endpoint and put this node's Hello on the wire, first message of
/// the stream.
///
/// The hello goes into the channel BEFORE the call that opens the stream:
/// `session` takes the receiving half, so a hello queued here is the first
/// thing the controller reads and the session cannot be established without
/// this node having introduced itself.
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

/// Every message the controller sends, in the order it sent them, until the
/// stream ends or the answering end is gone.
///
/// Errors on the stream end the session and are not passed up: a controller
/// that dropped the connection is the ordinary case, and the caller's job is
/// to dial again rather than to decide anything about it.
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

/// One message from the controller, done.
///
/// `Break` means the sending half is gone — nobody is listening for an answer
/// any more, so the session is over. Nothing else in here ends it: a command
/// that fails is a result with a failure in it, and a sync that fails is a
/// warning and the next report.
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
        // The console: `open` takes the line and starts a task that pumps
        // the guest's output up this same stream; `input` and `close`
        // reach that task through the map. Spawned and not inline,
        // because a console session outlives the message that began it —
        // and because nothing else on this stream may wait for a guest.
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

/// Wait until somebody asks this agent to stop.
///
/// SIGINT alongside SIGTERM, because a person stopping an agent by hand in a
/// terminal is the same event as systemd stopping one. A process that cannot
/// register the handler waits forever instead: an agent that cannot listen
/// for SIGTERM still runs VMs, and refusing to start over it would trade a
/// lost farewell for an outage.
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

/// The beat with nothing on it: this node is here, this is what it is, and
/// this is what is wrong with it.
///
/// Sent when the per-VM half could not be read, and the empty lists are the
/// point — a short list must not be read as a statement, so `vms`, `images`,
/// `volumes`, `snapshots` and `migrations` all mean "not saying" here rather
/// than "none".
/// `stopping` is the exception and travels either way, because a farewell
/// that only a healthy node could send would be missing on exactly the node
/// whose farewell matters.
fn heartbeat_only(node: NodeStatus, stopping: bool) -> StatusReport {
    StatusReport {
        node: Some(node),
        vms: Vec::new(),
        routers: Vec::new(),
        images: Vec::new(),
        // "Not saying", like the empty list beside it: this beat did not look
        // at the disk, so the tier above may not read a missing name as a
        // missing file.
        images_complete: false,
        volumes: Vec::new(),
        snapshots: Vec::new(),
        stopping,
        migrations: Vec::new(),
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

/// The capacity this node measured once, plus what is wrong with it now.
///
/// A free function so the join is testable without an `Agent`: the whole
/// point of the field is that a fault raised anywhere in this process reaches
/// the controller on the very next heartbeat, and that is the sentence worth
/// pinning down.
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
        // Error and not warn: this is read once at start-up and never again,
        // so nothing repairs it while the agent runs, and a node reporting
        // zero capacity is a node the scheduler will never place on.
        error!(
            vcpus,
            mem_mib, "could not read node capacity, reporting what was found"
        );
    }
    info!(vcpus, mem_mib, "node capacity measured");
    NodeStatus {
        vcpus,
        mem_mib,
        // Measured, not observed: what is wrong with this node is asked of
        // `Agent::node_status` on every heartbeat, because it changes and
        // these two numbers do not.
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

    /// The two words a node puts in `RouterReport.phase`, held against the
    /// constants the tier above matches on.
    ///
    /// Here because this is the only crate that has both: the agent's own
    /// vocabulary (`agent_api::networking::RouterPhase`) and the wire
    /// constants in `proto`. The cluster reads the wire words and cannot
    /// depend on the enum, so nothing else in the tree would notice a rename
    /// — and the failure it would cause is silent: every report from every
    /// healthy gateway node dropped as "unknown router phase", ten seconds
    /// apart, with the routers still working.
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

    /// A node that is going says so, once, on its way out.
    ///
    /// D9's node half. The chaos run found manacor's agent twenty hours dead
    /// with eleven VMs still reported `Running`, and the reason the control
    /// plane could not know better is that an absent heartbeat means three
    /// different things — stopped, crashed, unreachable — and looks the same
    /// for all of them. A clean stop is the one case the node itself can
    /// resolve, and the whole of the fix is that it says so before it goes.
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

    /// The heartbeat carries what is wrong with this node, for as long as it
    /// is wrong, and nothing when nothing is.
    ///
    /// The defect: a node whose store had taken an I/O error went on saying
    /// READY with a fresh heartbeat for twenty hours while every command on it
    /// failed, and the scheduler kept placing VMs there — because capacity and
    /// liveness were the only two things a node could say about itself. This
    /// is the third thing.
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

        // While it holds, and no longer. The next heartbeat after the repair
        // is the one that says the node is usable again.
        conditions.clear(STORE_UNHEALTHY);
        conditions.clear(DISK_PRESSURE);
        assert!(node_status(&measured, &conditions).conditions.is_empty());
    }

    /// The `CannotServe` word, from the node's mouth to the tier that acts on
    /// it.
    ///
    /// It travels as `ErrorMsg.reason` rather than in the sentence, because a
    /// tier that had to match on prose would change behaviour the day
    /// somebody rewords a message. And it means one narrow thing: the node
    /// made no record and never will for this VM, so the binding falls. Every
    /// other failure stays bare and is answered where it happened.
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

        // A boot that did not work is NOT this: it may work next time in the
        // same place, and moving the VM for it would walk it around the
        // cluster.
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

    /// The refusal says its sentence ONCE, and it says it in all four
    /// catalogues.
    ///
    /// The old shape hung the already formatted sentence on the chain as
    /// context, and `{e:#}` prints every link joined with ": " — so
    /// `refusedBy[].message` read `"invalid nic spec: this node has no
    /// [network] section …: invalid nic spec: this node has no [network]
    /// section …"`. It was found in the network case and it was never a
    /// network defect: `cannot_serve` is one function and all four structural
    /// checks go through it.
    ///
    /// Asserted as an EQUALITY and not as a substring count, because that is
    /// the actual contract: marking a refusal structural changes what the
    /// tier above does with it and changes nothing at all about what it says.
    #[test]
    fn a_structural_refusal_says_its_sentence_once_in_all_four_catalogues() {
        use crate::drivers::{DeviceCatalog, HypervisorCatalog, NetworkCatalog, VolumeCatalog};
        use std::collections::HashMap;

        // Each one built exactly as `handle_create` builds it: the
        // catalogue's own refusal, the context line that names which of the
        // four it was, and then the marker.
        /// One catalogue's refusal, rebuilt on demand: `anyhow::Error` is
        /// not `Clone`, and the assertion needs the same refusal twice.
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

    /// A row this build cannot read cancels the sweep outright.
    ///
    /// The other direction from the reference count, and the same reason: an
    /// unreadable row may name any VNI, so no overlay on this node is
    /// PROVABLY orphaned while one is there. The count keeps the wire by
    /// counting the unknown as a user; the sweep keeps it by not running.
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

/// What this construction site's own sources may not contain.
///
/// Two rules, both kept by reading the sources rather than by everybody
/// remembering, and both about mistakes that no test on a behaviour path
/// could catch: the messages they are about are on paths that need a
/// hypervisor that cannot do the thing, or a node whose cgroup root is not
/// one.
#[cfg(test)]
mod source_rules {
    /// The five source directories this construction site owns.
    const SITE: [&str; 4] = [
        "components/agent/src",
        "drivers",
        "shared/agent-api/src",
        "shared/common/src",
    ];

    /// No sentence printed from here has a hole in the middle of it.
    ///
    /// A message that runs over two source lines needs a backslash at the
    /// break; without it, the indentation of the second line lands inside the
    /// sentence and the operator reads "…cannot plug a disk into a running
    /// vm;                  stop the vm and start it again". Four of these
    /// were found one at a time, by reading, over three briefs — and the
    /// fourth was found in a file the third had already been fixed in.
    ///
    /// The shape is exact: a run of four or more spaces inside a string
    /// literal, with the end of a word or a punctuation mark before it and
    /// the start of a lowercase word after it. That is a broken continuation
    /// and it is not anything else — a padded FAT label and a captured
    /// `nvme list` line both have runs of spaces in them, and neither has a
    /// sentence running through it.
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

    /// Every `.rs` file of this construction site, recursively.
    ///
    /// Rooted at the workspace and not at this crate: `drivers/` and
    /// `shared/` are as much this site's as `components/agent` is, and a rule
    /// that only held for one of the three would be a rule the next brief
    /// breaks in the other two.
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

    /// Nothing here writes where somebody else writes, or binds a port
    /// somebody else could be holding.
    ///
    /// The agent half of the rule the controller half already keeps
    /// (`no_source_of_this_construction_site_names_a_fixed_temp_path_or_port`
    /// in `controller-api`), and the numbers that made it worth having were
    /// always this half's: the flaky run of round 1 was this test binary, at
    /// 129 tests, with one failure nobody could reproduce.
    ///
    /// Two rules. A directory a test writes in comes from `tempfile`, which
    /// is unique and, unlike a name built from the pid, survives a panic
    /// without leaving anything behind for the next run to trip over — a pid
    /// comes back, and thirty-three places here derived a name from one. A
    /// listener asks for port `0` and reads back what it was given.
    ///
    /// An address in a string that nothing binds is not a bind: the migration
    /// tests hand `tcp:127.0.0.1:49000` to a hypervisor that records it and
    /// opens nothing, which is the same case as the controller's
    /// `127.0.0.1:1`.
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

    /// The address a `bind(` on this line asks for, if it asks for a literal
    /// one that is not port 0.
    ///
    /// Both shapes this construction site uses: a string with the port in it,
    /// and the tuple form the migration probe takes. A variable in either
    /// position is not a literal and is not this rule's business — that is
    /// what the probe itself does, with a port out of the configured range.
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
