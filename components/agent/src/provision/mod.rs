// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Making a VM stand up on this node, and taking it down again.
//!
//! `run_chain` is the chain and this file is where it lives; every link of
//! it has a file of its own, in the order the chain runs them:
//!
//! * `volumes` — what the spec's disks are, made or attached, and the
//!   hot-plug that changes them later
//! * `network` — the taps, the tenant overlay and the reference count that
//!   decides when it goes
//! * `devices` — admission and creation of the passed-through hardware
//! * `seed` — the cloud-init seed and the instance spec the VMM is handed
//! * `teardown` — `stop` and `teardown`, the two ways a VM ends
//! * `migrate` — the second entrance and the second exit of the same chain
//!
//! Nothing here is reachable from outside the crate except `Provisioner` and
//! `timed_driver`, which is what it was before the split.

use agent_api::device::{DeviceId, DeviceSpec, PartitionSpec, default_device_driver};
use agent_api::hypervisor::{AttachedVolume, BootSource, InstanceSpec};
use agent_api::networking::NicAttachment;
use agent_api::{HypervisorError, ResourceLimits, VmId};
use anyhow::{Context, Result, anyhow, bail};
use std::collections::HashMap;
use std::net::IpAddr;
use std::path::PathBuf;
use std::time::Duration;
use tracing::{debug, info, instrument, warn};

use crate::drivers::Drivers;
use crate::store::Store;
use crate::types::{AgentVmSpec, BootSourceSpec, Desired, Operation, Phase, VmRecord};
use agent_api::storage::{Volume, VolumeId, default_volume_driver};
use std::sync::Arc;

mod devices;
mod migrate;
mod network;
mod seed;
mod teardown;
mod volumes;

pub(crate) use devices::*;
pub(crate) use network::*;
pub(crate) use volumes::*;

/// Slice headroom for one backend process, MiB. Devices and storage both
/// spend it; see `limits_for` for why it is one number and not a per-driver
/// hook.
const BACKEND_OVERHEAD_MIB: u64 = 512;

/// One driver call, timed into `meister_agent_driver_operation_duration_seconds`.
///
/// Wrapped here rather than inside each driver because this is the layer that
/// knows which driver it is talking to: below it a `BlockDriver` is a trait
/// object with no name of its own, and above it nobody sees the individual
/// calls. Both labels are bounded — a configured backend name and one of a
/// handful of verbs — so the rule in `telemetry::metrics` holds.
///
/// The duration is recorded whether the call succeeded or not: a driver that
/// fails after thirty seconds is exactly the case this is for.
pub(crate) async fn timed_driver<F: std::future::Future>(
    driver: &str,
    operation: &str,
    work: F,
) -> F::Output {
    let clock = telemetry::metrics::Timer::start();
    let out = work.await;
    telemetry::metrics::agent().driver_op(driver, operation, clock.seconds());
    out
}

/// What the hypervisor and the networking drivers are called in those labels.
/// Neither is looked up by name in a configured map the way storage and
/// devices are, so the name has to come from somewhere — here, once.
const HYPERVISOR: &str = "hypervisor";
const NETWORKING: &str = "network";

pub struct Provisioner {
    store: Arc<Store>,
    drivers: Drivers,
    /// The node-local base image cache. Its directory is `image_dir`, so what
    /// it puts there is exactly what the volume drivers look up.
    images: Arc<crate::images::Cache>,
    image_dir: PathBuf,
    /// Where a VM's cloud-init seed is written. The run directory and not the
    /// volume one, because that is what a seed IS: state derived from the
    /// spec, rebuilt on every provision, and gone with the VM.
    run_dir: PathBuf,
    default_bridge: String,
    bridge_addr: Option<(IpAddr, u8)>,
    /// `cgroup_cpuset` from the config, carried into every `create_slice`
    /// call so the parent slice keeps its pinning. See `ResourceLimits`.
    cpuset: Option<String>,
    /// How long this node waits on a transfer it cannot see the end of, at
    /// either end of one. See [`Ceilings`].
    ceilings: Ceilings,
}

/// The base images in this spec that nobody fetches: named by a volume, and
/// not among the `Source` entries that carry a url and a checksum.
///
/// The complement of `spec.images` rather than a second derivation of it, so
/// the two lists cannot overlap and an image cannot be both stated by a fetch
/// and re-stated by a `stat`. Deduplicated, because two disks off one base
/// image are one image.
pub(crate) fn path_images(spec: &crate::types::AgentVmSpec) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for volume in &spec.volumes {
        let Some(name) = volume.spec.base_image.as_deref() else {
            continue;
        };
        if spec.images.iter().any(|s| s.name == name) {
            continue;
        }
        if !out.iter().any(|seen| seen == name) {
            out.push(name.to_string());
        }
    }
    out
}

/// The two numbers that keep a live migration from waiting for ever.
///
/// One struct and not two arguments, because they are one decision seen from
/// the two ends of a transfer: both have to be longer than the cluster's own
/// `migration_transfer_secs`, for the same reason — the tier that ASKED for
/// the migration is the one that decides it has failed — and a fleet that
/// moved one without the other would have an asymmetry nobody meant.
///
/// They were constants (600 s each) until an estate with 32 GiB guests over a
/// congested link had to raise the cluster's patience and found that raising
/// the node's meant a recompile.
#[derive(Debug, Clone, Copy)]
pub struct Ceilings {
    /// `migrate_out_ceiling_secs`: how long the source watches its own VMM
    /// before it declares the guest still here.
    pub migrate_out: Duration,
    /// `receive_ceiling_secs`: how long the destination holds a VMM, disks
    /// and taps for a guest that has not turned up.
    pub receive: Duration,
}

impl Default for Ceilings {
    fn default() -> Self {
        Self {
            migrate_out: Duration::from_secs(600),
            receive: Duration::from_secs(600),
        }
    }
}

impl Provisioner {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        store: Arc<Store>,
        drivers: Drivers,
        images: Arc<crate::images::Cache>,
        image_dir: PathBuf,
        run_dir: PathBuf,
        default_bridge: String,
        bridge_addr: Option<(IpAddr, u8)>,
        cpuset: Option<String>,
    ) -> Self {
        Self {
            store,
            drivers,
            images,
            image_dir,
            run_dir,
            default_bridge,
            bridge_addr,
            cpuset,
            ceilings: Ceilings::default(),
        }
    }

    /// Say again, about every path image any record here names, whether the
    /// bytes are where this node would look for them.
    ///
    /// The level half of `verify_path`. A provision states it once, and once
    /// is not a statement a control plane can rely on: an image that vanished
    /// from shared storage after the VM was made would still be reported
    /// `Ready` for ever, and an image RESTORED after somebody fixed it would
    /// still be reported `Failed` until the next create. This is the pass
    /// that keeps both honest, on the same schedule and with the same
    /// argument as everything else in the reconciler.
    ///
    /// Records and not objects: a node knows the images its own VMs name and
    /// nothing else. An `Image` no VM on this node uses is one this node has
    /// no evidence about, which is exactly what an empty entry in
    /// `Image.status.nodes[]` means.
    ///
    /// A record this build cannot read contributes nothing and stops nothing
    /// — unlike the overlay sweep, which declines altogether over one. The
    /// difference is what is at stake: there it is somebody's live wire, here
    /// it is one line of evidence about one image.
    pub(crate) async fn verify_path_images(&self) {
        let Ok(records) = self.store.list() else {
            return;
        };
        let mut seen: Vec<String> = Vec::new();
        for (_, record) in &records {
            for name in path_images(&record.spec) {
                if !seen.contains(&name) {
                    seen.push(name);
                }
            }
        }
        for name in seen {
            self.images.verify_path(&name).await;
        }
    }

    /// The two migration ceilings this node was configured with.
    ///
    /// A builder call and not a ninth argument to `new`, and the reason is
    /// what the default IS: `Ceilings::default()` is exactly the pair of
    /// constants this file held before they were configurable, so a caller
    /// that says nothing gets the behaviour it always had. Only `run_agent`
    /// has a config to say anything from.
    pub fn with_ceilings(mut self, ceilings: Ceilings) -> Self {
        self.ceilings = ceilings;
        self
    }

    /// One backend out of the one registry, or a sentence naming it.
    fn storage(&self, name: &str) -> Result<Arc<dyn agent_api::storage::VolumeDriver>> {
        self.drivers.storage.get(name).cloned().ok_or_else(|| {
            anyhow!("vm spec requests volume driver {name:?} which is not configured on this node")
        })
    }

    /// `managed_by_controller` marks the record as the controller's, which is
    /// what a desired-state snapshot is later allowed to reap. Only the
    /// session path passes true.
    #[instrument(skip(self, spec), fields(vm_id = %id))]
    pub async fn provision(
        &self,
        id: VmId,
        spec: AgentVmSpec,
        desired: Desired,
        managed_by_controller: bool,
    ) -> Result<()> {
        if let Some(mut existing) = self.store.get(&id)? {
            info!(desired = ?desired, "vm record exists, applying the volume diff");
            existing.desired = desired;
            self.store.put(&id, &existing)?;
            return self.sync_volumes(&id, &spec).await;
        }

        self.check_device_admission(&id, &spec)?;

        let mut record = VmRecord {
            spec,
            desired,
            vmm_pid: None,
            overlay_bridges: Default::default(),
            phase: Phase::Provisioning,
            operation: None,
            stop_deadline: None,
            receive_deadline: None,
            send_failed: None,
            unhealthy: None,
            managed_by_controller,
            volumes: vec![],
            nics: vec![],
            devices: vec![],
        };
        self.store.put(&id, &record)?;

        match self.run_chain(&id, &mut record, Finish::Boot).await {
            Ok(()) => Ok(()),
            Err(e) => {
                let _ = self.store.put(&id, &record);
                warn!(
                    error = %format!("{e:#}"),
                    "provisioning failed, tearing down"
                );
                if let Err(td) = self.teardown(&id).await {
                    return Err(e.context(format!(
                        "teardown after failed provision also failed: {td:#}"
                    )));
                }
                Err(e)
            }
        }
    }

    /// The resource chain, and the one span every driver span hangs under:
    /// volumes, then nics, then devices, then the VMM. Instrumented in its
    /// own right because `resume` reaches it too — a re-provision after a
    /// dead VMM is this same chain without a `provision` span above it.
    ///
    /// `finish` is the only thing that differs between a VM that boots here
    /// and a VM that ARRIVES here. Everything up to `DevicesDone` is the
    /// same work in the same order, and it has to be: the configuration of a
    /// migrating guest travels inside the stream and names this node's disks,
    /// taps and files, so all of them have to exist before the stream opens.
    /// What differs is the last two lines.
    ///
    /// One line per link, and the order of those lines is the whole of what
    /// this function says. Each link keeps its own file and writes its own
    /// phase down as it finishes, so a chain that breaks halfway leaves a
    /// record that says how far it got.
    #[instrument(skip_all, fields(vm_id = %id, volumes = record.spec.volumes.len(),
                                  nics = record.spec.nics.len(),
                                  devices = record.spec.devices.len()))]
    async fn run_chain(&self, id: &VmId, record: &mut VmRecord, finish: Finish<'_>) -> Result<()> {
        let spec = record.spec.clone();

        // Before the cgroup and before the volumes: a base image this node
        // does not have yet has to be here before any driver goes looking for
        // it, and a fetch that fails must fail the provision rather than
        // producing a VM that boots off a blank disk.
        for source in &spec.images {
            self.images
                .ensure(source)
                .await
                .with_context(|| format!("base image {}", source.name))?;
        }
        // And the ones nobody fetches, in the same registry: a path image is
        // somebody else's file on shared storage, so this node had never said
        // a word about one — which is why an `Image` whose source does not
        // exist sat at `Ready` for ever. See `images::Cache::verify_path`.
        //
        // It does NOT fail the provision. The storage driver is the party that
        // opens the file and its `ImageNotFound` is the sentence about THIS
        // vm; what this adds is the sentence about the image, on the road
        // that reaches the catalogue. Failing here would replace a good error
        // with a duplicate one.
        for name in path_images(&spec) {
            self.images.verify_path(&name).await;
        }

        let mut limits = Self::limits_for(&spec);
        limits.cpuset = self.cpuset.clone();
        debug!(?limits, "creating cgroup slice");
        let cgroup = self
            .drivers
            .confiner
            .create_slice(&id.to_string(), None, &limits)
            .map_err(|e| anyhow!("creating cgroup slice: {e}"))?;

        self.attach_volumes(id, record, &spec, &cgroup).await?;
        self.attach_nics(id, record, &spec).await?;
        self.create_devices(id, record, &spec, &cgroup).await?;

        // Now, and not at create time: only the volume drivers know which of
        // their volumes became a backend process, and by here they have all
        // said so. Before the VMM is created, so the allowance is already in
        // the slice when the VMM moves into it.
        if let Some(widened) = widen_for_storage_backends(&limits, &record.volumes) {
            debug!(?widened, "widening the slice for storage backends");
            self.drivers
                .confiner
                .create_slice(&id.to_string(), None, &widened)
                .map_err(|e| anyhow!("widening cgroup slice for storage backends: {e}"))?;
        }

        self.write_seed(id, &spec)?;

        // And here the two exits part. Everything above is identical.
        match finish {
            Finish::Boot => self.boot(id, record, &spec, &cgroup).await,
            Finish::Receive { listen } => self.receive(id, record, listen, &cgroup).await,
        }
    }

    /// The first exit of the chain: the guest is made here.
    ///
    /// Everything the instance spec names is standing by the time this runs,
    /// which is why it is three driver calls and two phases and nothing else.
    async fn boot(
        &self,
        id: &VmId,
        record: &mut VmRecord,
        spec: &AgentVmSpec,
        cgroup: &agent_api::CgroupHandle,
    ) -> Result<()> {
        let ispec = self.build_instance_spec(id, spec, record)?;
        debug!(?ispec, "creating hypervisor");
        let vmm_pid = timed_driver(
            HYPERVISOR,
            "create",
            self.drivers.hypervisor()?.create(id, &ispec, Some(cgroup)),
        )
        .await
        .context("hypervisor create")?;
        record.vmm_pid = Some(vmm_pid);
        self.store.put(id, record)?;

        debug!(?ispec, "starting hypervisor");
        timed_driver(HYPERVISOR, "start", self.drivers.hypervisor()?.start(id))
            .await
            .context("hypervisor start")?;

        record.phase = Phase::Provisioned;
        self.store.put(id, record)?;
        info!("vm provisioned and running");
        Ok(())
    }

    /// The limits the slice is CREATED with — everything the spec alone can
    /// predict. A backend the spec cannot predict is added later by
    /// `widen_for_storage_backends`; the two together are the whole
    /// allowance, and neither is complete on its own.
    fn limits_for(spec: &AgentVmSpec) -> ResourceLimits {
        let vmm_overhead_mib = 64 + (8 * spec.vcpus as u64) + 32;
        // A device backend and whatever it spawns run in the same slice as
        // the VMM; their buffers are host memory on top of guest RAM. One
        // number for every backend: no driver has yet disagreed with it, and
        // a per-driver hook where every driver returned the same constant
        // would be an abstraction over nothing (see the endstufe report).
        //
        // Devices are counted from the spec because a device spec IS one
        // backend. A volume spec is not: see `widen_for_storage_backends`.
        let device_overhead_mib = BACKEND_OVERHEAD_MIB * spec.devices.len() as u64;
        // VFIO pins all guest RAM for DMA, so the whole allowance is resident
        // at once (measured 98.6% of memory.max) — the VMM's own spikes then
        // need real headroom instead of the leftover slack.
        let vfio_overhead_mib = if spec
            .devices
            .iter()
            .any(|d| d.spec.partition == PartitionSpec::Exclusive)
        {
            256
        } else {
            0
        };
        let overhead = vmm_overhead_mib + device_overhead_mib + vfio_overhead_mib;
        ResourceLimits {
            memory_max: Some((spec.memory_mib + overhead) * 1024 * 1024),
            cpu_quota: Some(spec.vcpus * 100 + 50),
            // Not this function's business: the pinning belongs to the agent
            // and is stamped on by `run_chain`, which is the caller that has
            // the config.
            cpuset: None,
        }
    }

    #[instrument(skip(self, record), fields(vm_id = %id))]
    pub(crate) async fn resume(&self, id: &VmId, mut record: VmRecord) -> Result<()> {
        record.phase = Phase::Provisioning;
        record.volumes.clear();
        record.nics.clear();
        record.devices.clear();
        record.vmm_pid = None;
        record.unhealthy = None;
        self.store.put(id, &record)?;

        let result = self.run_chain(id, &mut record, Finish::Boot).await;
        if result.is_err() {
            let _ = self.store.put(id, &record);
        }
        result
    }
}

/// How `run_chain` ends: with a guest that boots here, or with a VMM
/// listening for one that is on its way.
///
/// An enum and not a `bool` or an `Option<&str>` because the two ends are two
/// different operations that happen to share their first ninety per cent, and
/// a caller reading `run_chain(id, rec, true)` would have to know which of
/// them `true` meant.
#[derive(Debug, Clone, Copy)]
enum Finish<'a> {
    /// `create` and `start`: the guest is made here.
    Boot,
    /// `migrate_in`: the guest is made somewhere else and arrives over
    /// `listen`, which is an address in the hypervisor's own spelling
    /// (`agent_api::migration_url`) and is passed through unopened.
    Receive { listen: &'a str },
}

#[cfg(test)]
mod tests;
