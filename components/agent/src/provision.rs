// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

use agent_api::device::{DeviceId, DeviceSpec, PartitionSpec, default_device_driver};
use agent_api::hypervisor::{BootSource, InstanceSpec};
use agent_api::networking::NicAttachment;
use agent_api::{HypervisorError, ResourceLimits, VmId};
use anyhow::{Context, Result, anyhow, bail};
use std::collections::HashMap;
use std::net::IpAddr;
use std::path::PathBuf;
use tracing::{debug, info, instrument, warn};

use crate::drivers::Drivers;
use crate::store::Store;
use crate::types::{AgentVmSpec, BootSourceSpec, Desired, Phase, VmRecord};
use agent_api::storage::{Volume, VolumeAttachment, VolumeId, default_volume_driver};
use std::sync::Arc;

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
async fn timed_driver<F: std::future::Future>(driver: &str, operation: &str, work: F) -> F::Output {
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
}

/// Which driver created this device, read back off the spec the record was
/// built from. The fallback is the spec default rather than a literal: a
/// record whose device is not in its own spec should not be routed to
/// whichever driver happened to be default the day this line was written.
fn device_driver_name(record: &VmRecord, id: &DeviceId) -> String {
    record
        .spec
        .devices
        .iter()
        .find(|d| &d.id == id)
        .map(|d| d.spec.driver.clone())
        .unwrap_or_else(default_device_driver)
}

/// Which backend created this volume, read back off the spec the record was
/// built from — the mirror of `device_driver_name`, and for the same reason:
/// teardown has to reach the driver that made the thing, and the record is
/// the only place that still remembers which one that was.
fn volume_driver_name(record: &VmRecord, id: &VolumeId) -> String {
    record
        .spec
        .volumes
        .iter()
        .find(|v| &v.id == id)
        .and_then(|v| v.spec.driver.clone())
        .unwrap_or_else(default_volume_driver)
}

/// The extra slice headroom the volumes actually turned out to need.
///
/// `limits_for` cannot answer this and that is not an oversight: whether a
/// volume becomes a PROCESS is the driver's answer, never the spec's. A
/// `[volume.nfs]` share becomes a virtiofsd that lives in this VM's slice
/// and eats host memory there; a plain file on the very same driver becomes
/// a path and eats nothing. Only the attachment the driver handed back says
/// which of the two happened, so the slice is created with what the spec can
/// predict and widened once, here, before the VMM moves in.
///
/// Widened only, never narrowed: the backends are already inside the slice
/// by the time this runs, and lowering `memory.max` under a live process is
/// how a VM gets OOM-killed at boot.
///
/// `None` is "nothing to do" — a VM whose volumes are all plain paths, which
/// is most of them, keeps byte for byte the limits it had before this
/// existed.
fn widen_for_storage_backends(base: &ResourceLimits, volumes: &[Volume]) -> Option<ResourceLimits> {
    let backends = volumes
        .iter()
        .filter(|v| v.attachment.backend_pid().is_some())
        .count() as u64;
    if backends == 0 {
        return None;
    }
    let mut widened = base.clone();
    widened.memory_max = base
        .memory_max
        .map(|bytes| bytes + backends * BACKEND_OVERHEAD_MIB * 1024 * 1024);
    Some(widened)
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
        }
    }

    /// Ask every driver this spec names whether it can serve the request
    /// alongside what the other VMs on this node already claim from it.
    ///
    /// The agent supplies the facts and the driver supplies the judgement:
    /// only this side can read the store, and only the driver knows what a
    /// conflict is — which param names the resource, whether two VMs may
    /// share it, what to say when they may not. Before this, the agent
    /// carried a second parser for vfio's `params.pci_address` next to the
    /// one the vfio driver already had.
    ///
    /// A driver the spec names but the node does not have is passed over
    /// here; `run_chain` is where that becomes an error, with the message
    /// that names the configured drivers.
    fn check_device_admission(&self, id: &VmId, spec: &AgentVmSpec) -> Result<()> {
        if spec.devices.is_empty() {
            return Ok(());
        }
        let mut requested: HashMap<&str, Vec<(DeviceId, DeviceSpec)>> = HashMap::new();
        for d in &spec.devices {
            requested
                .entry(d.spec.driver.as_str())
                .or_default()
                .push((d.id, d.spec.clone()));
        }

        let mut claimed: HashMap<String, Vec<(VmId, DeviceSpec)>> = HashMap::new();
        for (other_id, record) in self.store.list()? {
            if &other_id == id {
                continue;
            }
            for d in &record.spec.devices {
                claimed
                    .entry(d.spec.driver.clone())
                    .or_default()
                    .push((other_id, d.spec.clone()));
            }
        }

        for (name, requested) in requested {
            let Some(driver) = self.drivers.devices.get(name) else {
                continue;
            };
            let held = claimed.get(name).map(Vec::as_slice).unwrap_or(&[]);
            driver
                .admit(&requested, held)
                .with_context(|| format!("device admission refused by driver {name:?}"))?;
        }
        Ok(())
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
            info!(desired = ?desired, "vm record exists, updating desired only");
            existing.desired = desired;
            self.store.put(&id, &existing)?;
            return Ok(());
        }

        self.check_device_admission(&id, &spec)?;

        let mut record = VmRecord {
            spec,
            desired,
            vmm_pid: None,
            phase: Phase::Provisioning,
            operation: None,
            stop_deadline: None,
            unhealthy: None,
            managed_by_controller,
            volumes: vec![],
            nics: vec![],
            devices: vec![],
        };
        self.store.put(&id, &record)?;

        match self.run_chain(&id, &mut record).await {
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
    #[instrument(skip_all, fields(vm_id = %id, volumes = record.spec.volumes.len(),
                                  nics = record.spec.nics.len(),
                                  devices = record.spec.devices.len()))]
    async fn run_chain(&self, id: &VmId, record: &mut VmRecord) -> Result<()> {
        let spec = record.spec.clone();

        // Before the cgroup and before the volumes: a base image this node
        // does not have yet has to be here before any driver goes looking for
        // it, and a fetch that fails must fail the provision rather than
        // producing a VM that boots off a blank disk. Nothing at all happens
        // for a path-based image — the list is empty and this loop does not
        // run — so the node's behaviour is byte for byte what it was.
        for source in &spec.images {
            self.images
                .ensure(source)
                .await
                .with_context(|| format!("base image {}", source.name))?;
        }

        let mut limits = Self::limits_for(&spec);
        limits.cpuset = self.cpuset.clone();
        debug!(?limits, "creating cgroup slice");
        let cgroup = self
            .drivers
            .confiner
            .create_slice(&id.to_string(), None, &limits)
            .map_err(|e| anyhow!("creating cgroup slice: {e}"))?;

        for v in &spec.volumes {
            let driver_name = v.spec.driver.clone().unwrap_or_else(default_volume_driver);
            debug!(volume_id = %v.id, driver = %driver_name,
                   base_image = ?v.spec.base_image, "creating volume");
            let driver = self.drivers.storage.get(&driver_name).ok_or_else(|| {
                anyhow!(
                    "vm spec requests volume driver {driver_name:?} which is not configured \
                     on this node"
                )
            })?;
            // Two calls where there was one, and the order is the whole
            // point: the data first, with no consumer in sight, then the
            // connection into THIS VM's slice. Nothing between them belongs
            // to the volume, and nothing in the first call knows a VM exists.
            let handle = timed_driver(&driver_name, "provision", driver.provision(&v.id, &v.spec))
                .await
                .with_context(|| format!("provisioning volume {} via {driver_name}", v.id))?;
            let attachment = timed_driver(
                &driver_name,
                "attach",
                driver.attach(&handle, Some(&cgroup)),
            )
            .await
            .with_context(|| format!("attaching volume {} via {driver_name}", v.id))?;
            record.volumes.push(Volume { handle, attachment });
        }
        record.phase = Phase::VolumesDone;
        self.store.put(id, record)?;
        info!(count = record.volumes.len(), "volumes ready");

        // Asked once for the whole loop rather than per call: a node with no
        // `[network]` section cannot serve any of these NICs, and finding
        // that out on the second one would leave a tap behind from the first.
        // A VM with no NICs never asks, which is what lets one run on a node
        // that makes no taps at all.
        let (nic_driver, bridge) = match spec.nics.is_empty() {
            true => (None, None),
            false => (
                Some(self.drivers.networking()?),
                Some(self.drivers.bridge()?),
            ),
        };
        for n in &spec.nics {
            // A tenant NIC lands on the tenant's own bridge; the one the spec
            // names is the default it WOULD have taken, and stays on record
            // as exactly that. No address is ever assigned to an overlay
            // bridge: the host is not on the tenant's network, and giving it
            // an address there would be the one hole the isolation is for.
            if let Some(vni) = n.spec.vxlan_id {
                let bridge = bridge
                    .expect("the nic list is not empty, so the bridge driver was asked for")
                    .ensure_overlay(vni)
                    .await
                    .with_context(|| format!("ensuring the overlay for vxlan {vni}"))?;
                debug!(nic_id = %n.id, vni, bridge = %bridge, "nic joins a tenant overlay");
            } else {
                bridge
                    .expect("the nic list is not empty, so the bridge driver was asked for")
                    .ensure(&n.spec.bridge)
                    .await
                    .with_context(|| format!("ensuring bridge {}", n.spec.bridge))?;
                if n.spec.bridge == self.default_bridge
                    && let Some((ip, prefix)) = self.bridge_addr
                {
                    bridge
                        .expect("the nic list is not empty, so the bridge driver was asked for")
                        .ensure_address(&n.spec.bridge, ip, prefix)
                        .await
                        .with_context(|| {
                            format!("assigning {ip}/{prefix} to bridge {}", n.spec.bridge)
                        })?;
                }
            }
            let nic = timed_driver(
                NETWORKING,
                "create",
                nic_driver
                    .expect("the nic list is not empty, so the nic driver was asked for")
                    .create(&n.id, &n.spec),
            )
            .await
            .with_context(|| format!("creating nic {}", n.id))?;
            record.nics.push(nic);
        }
        record.phase = Phase::NetworkDone;
        self.store.put(id, record)?;
        info!(count = record.nics.len(), "nics ready");

        for d in &spec.devices {
            let driver = self.drivers.devices.get(&d.spec.driver).ok_or_else(|| {
                anyhow!(
                    "vm spec requests device driver {:?} which is not configured on this node",
                    d.spec.driver
                )
            })?;
            let dev = timed_driver(
                &d.spec.driver,
                "create",
                driver.create(&d.id, &d.spec, Some(&cgroup)),
            )
            .await
            .with_context(|| format!("creating device {} via {}", d.id, d.spec.driver))?;
            record.devices.push(dev);
        }
        record.phase = Phase::DevicesDone;
        self.store.put(id, record)?;
        info!(count = record.devices.len(), "devices ready");

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

        // The seed, written before the VMM is created and rebuilt every time
        // this chain runs: it is derived from the spec, so a re-provision
        // after a dead VMM produces the same bytes and nothing has to be
        // remembered about it.
        if let Some(config) = &spec.cloud_init {
            let seed = crate::cloudinit::seed_path(&self.run_dir, id);
            crate::cloudinit::write_seed(&seed, id, config)
                .context("building the cloud-init seed")?;
            info!(path = %seed.display(), "cloud-init seed ready");
        }

        let ispec = self.build_instance_spec(id, &spec, record)?;
        debug!(?ispec, "creating hypervisor");
        let vmm_pid = timed_driver(
            HYPERVISOR,
            "create",
            self.drivers.hypervisor()?.create(id, &ispec, Some(&cgroup)),
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

    /// Where this VM's seed lives, and `None` for a VM that has no
    /// cloud-init block — which is what keeps such a VM's hypervisor config
    /// byte for byte what it was.
    fn seed_path(&self, id: &VmId, spec: &AgentVmSpec) -> Option<PathBuf> {
        spec.cloud_init
            .as_ref()
            .map(|_| crate::cloudinit::seed_path(&self.run_dir, id))
    }

    fn build_instance_spec(
        &self,
        id: &VmId,
        spec: &AgentVmSpec,
        record: &VmRecord,
    ) -> Result<InstanceSpec> {
        let volumes: Vec<VolumeAttachment> = record
            .volumes
            .iter()
            .map(|v| v.attachment.clone())
            .collect();
        // A share is not something a guest can boot from, so the requirement
        // is a block volume and not merely a volume.
        if !volumes.iter().any(VolumeAttachment::is_block) {
            bail!("vm spec contains no block volume; a boot disk is required");
        }

        let nics = record
            .nics
            .iter()
            .zip(spec.nics.iter())
            .map(|(created, requested)| NicAttachment {
                tap_name: created.tap_name.clone(),
                mac: requested.spec.mac,
                mtu: created.mtu,
            })
            .collect();

        let devices = record
            .devices
            .iter()
            .map(|d| d.attachment.clone())
            .collect();

        let boot = match &spec.boot {
            BootSourceSpec::DirectKernel {
                kernel,
                cmdline,
                initramfs,
            } => BootSource::DirectKernel {
                kernel: self.image_dir.join(kernel),
                cmdline: cmdline.clone(),
                initramfs: initramfs.as_ref().map(|n| self.image_dir.join(n)),
            },
            BootSourceSpec::Firmware { firmware } => BootSource::Firmware {
                firmware: self.image_dir.join(firmware),
            },
        };

        Ok(InstanceSpec {
            boot,
            volumes,
            vcpus: spec.vcpus,
            memory_mib: spec.memory_mib,
            nics,
            devices,
            cloud_init_seed: self.seed_path(id, spec),
        })
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

    #[instrument(skip(self), fields(vm_id = %id))]
    pub async fn teardown(&self, id: &VmId) -> Result<()> {
        let Some(record) = self.store.get(id)? else {
            return Ok(());
        };

        let mut failures: Vec<String> = Vec::new();

        if let Err(e) = self.drivers.confiner.kill_slice(&id.to_string()) {
            failures.push(format!("cgroup kill: {e}"));
        }

        // A record exists, so this node HAD a hypervisor when the VM was
        // provisioned. Not having one now means somebody removed the section
        // under a running VM, and that is a failure like any other in this
        // list: the VMM is still there and nobody can reach it.
        match self.drivers.hypervisor() {
            Ok(hv) => match timed_driver(HYPERVISOR, "destroy", hv.destroy(id)).await {
                Ok(()) | Err(HypervisorError::NotFound(_)) => {}
                Err(e) => failures.push(format!("hypervisor destroy: {e}")),
            },
            Err(e) => failures.push(format!("hypervisor destroy: {e:#}")),
        }

        // Flat on purpose: every one of these three loops is "find the driver
        // that made the thing, ask it to unmake it, and note it down if that
        // did not work". A missing driver is a failure like any other — the
        // resource is still there and nobody can reach it — so it takes the
        // same `failures.push` and the `else` that skips the rest.
        for d in &record.devices {
            let name = device_driver_name(&record, &d.id);
            let Some(driver) = self.drivers.devices.get(&name) else {
                failures.push(format!(
                    "device {}: driver {name:?} is not configured",
                    d.id
                ));
                continue;
            };
            if let Err(e) =
                timed_driver(&name, "destroy", driver.destroy(&d.id, &d.attachment)).await
            {
                failures.push(format!("device {}: {e}", d.id));
            }
        }

        for n in &record.nics {
            let driver = match self.drivers.networking() {
                Ok(driver) => driver,
                // Same shape as the missing volume driver below: the tap is
                // still on the host and nobody can take it down.
                Err(e) => {
                    failures.push(format!("nic {}: {e:#}", n.id));
                    continue;
                }
            };
            if let Err(e) = timed_driver(NETWORKING, "destroy", driver.destroy(&n.id)).await {
                failures.push(format!("nic {}: {e}", n.id));
            }
        }

        // Detach before deprovision, always. Deleting the bytes out from
        // under a live backend process is the one ordering that can lose data
        // rather than merely leak it, and this is the loop that used to do
        // both in one call — the nfs driver stopped its virtiofsd inside
        // `destroy` and nothing outside said so.
        //
        // A failed detach does NOT skip the deprovision. It could not before
        // either: `stop_backend` returned nothing and its outcome never
        // reached this loop, so the data went whatever happened to the
        // process. Both failures are recorded, which is more than the old
        // shape could say.
        for v in &record.volumes {
            let id = v.id();
            let name = volume_driver_name(&record, &id);
            let Some(driver) = self.drivers.storage.get(&name) else {
                failures.push(format!("volume {id}: driver {name:?} is not configured"));
                continue;
            };
            if let Err(e) =
                timed_driver(&name, "detach", driver.detach(&v.handle, &v.attachment)).await
            {
                failures.push(format!("volume {id}: detach: {e}"));
            }
            if let Err(e) = timed_driver(&name, "deprovision", driver.deprovision(&v.handle)).await
            {
                failures.push(format!("volume {id}: {e}"));
            }
        }

        // The seed goes with the VM. Written from the spec on every
        // provision, so nothing is lost by removing it and a file per vm id
        // that ever existed is what keeping it would cost.
        let _ = std::fs::remove_file(crate::cloudinit::seed_path(&self.run_dir, id));

        let cg = self.drivers.confiner.open_slice(&id.to_string());
        if let Err(e) = self.drivers.confiner.destroy_slice(&cg) {
            failures.push(format!("cgroup slice: {e}"));
        }

        if failures.is_empty() {
            self.store.delete(id)?;
            Ok(())
        } else {
            bail!("teardown of vm {id} incomplete: {}", failures.join("; "))
        }
    }

    #[instrument(skip(self, record), fields(vm_id = %id))]
    pub(crate) async fn stop(&self, id: &VmId, mut record: VmRecord) -> Result<()> {
        let hypervisor = self.drivers.hypervisor()?;
        match timed_driver(HYPERVISOR, "destroy", hypervisor.destroy(id)).await {
            Ok(()) | Err(HypervisorError::NotFound(_)) => {}
            Err(e) => bail!("stopping vmm: {e}"),
        }

        if let Some(pid) = record.vmm_pid {
            let in_slice = self
                .drivers
                .confiner
                .pids_in_slice(&id.to_string())
                .map(|pids| pids.contains(&pid))
                .unwrap_or(false);
            if in_slice {
                warn!(pid, "vmm survived destroy, killing it directly");
                let _ = nix::sys::signal::kill(
                    nix::unistd::Pid::from_raw(pid as i32),
                    nix::sys::signal::Signal::SIGKILL,
                );
            }
        }

        for d in &record.devices {
            let name = device_driver_name(&record, &d.id);
            match self.drivers.devices.get(&name) {
                Some(driver) => {
                    if let Err(e) =
                        timed_driver(&name, "destroy", driver.destroy(&d.id, &d.attachment)).await
                    {
                        warn!(device = %d.id, error = %format!("{e:#}"),
                              "stopping device backend failed");
                    }
                }
                None => {
                    warn!(device = %d.id, driver = %name, "device driver not configured, skipping")
                }
            }
        }
        record.devices.clear();

        // A stopped VM keeps its volumes but must not keep a backend process
        // running for a VM that is not there. `detach` and not `destroy`: the
        // data stays, only the process serving it goes — and a driver whose
        // volumes are plain paths has nothing to do here.
        for v in &record.volumes {
            let id = v.id();
            let name = volume_driver_name(&record, &id);
            match self.drivers.storage.get(&name) {
                Some(driver) => {
                    if let Err(e) =
                        timed_driver(&name, "detach", driver.detach(&v.handle, &v.attachment)).await
                    {
                        warn!(volume = %id, error = %format!("{e:#}"),
                              "detaching volume backend failed");
                    }
                }
                None => warn!(volume = %id, driver = %name,
                              "volume driver not configured, skipping"),
            }
        }

        record.vmm_pid = None;
        record.stop_deadline = None;
        record.unhealthy = None;
        self.store.put(id, &record)?;
        info!("vm stopped, volumes and taps kept");
        Ok(())
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

        let result = self.run_chain(id, &mut record).await;
        if result.is_err() {
            let _ = self.store.put(id, &record);
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{AgentVmSpec, BootSourceSpec, DeviceWithId};
    use agent_api::device::DeviceSpec;

    fn spec(vcpus: u32, memory_mib: u64, devices: Vec<DeviceWithId>) -> AgentVmSpec {
        AgentVmSpec {
            vcpus,
            memory_mib,
            boot: BootSourceSpec::Firmware {
                firmware: "fw".into(),
            },
            volumes: vec![],
            nics: vec![],
            devices,
            images: Vec::new(),
            cloud_init: None,
        }
    }

    fn device(driver: &str, partition: PartitionSpec) -> DeviceWithId {
        DeviceWithId {
            id: uuid::Uuid::nil(),
            spec: DeviceSpec {
                driver: driver.into(),
                partition,
                profile: None,
                params: None,
            },
        }
    }

    #[test]
    fn plain_vm_gets_vmm_overhead_only() {
        let l = Provisioner::limits_for(&spec(2, 2048, vec![]));
        // 64 + 8*2 + 32 = 112 MiB on top of guest RAM
        assert_eq!(l.memory_max, Some((2048 + 112) * 1024 * 1024));
        assert_eq!(l.cpu_quota, Some(250));
    }

    #[test]
    fn each_device_backend_adds_headroom() {
        let one = Provisioner::limits_for(&spec(
            2,
            2048,
            vec![device("nvrm", PartitionSpec::Mediated)],
        ));
        let two = Provisioner::limits_for(&spec(
            2,
            2048,
            vec![
                device("nvrm", PartitionSpec::Mediated),
                device("crosvm-gpu", PartitionSpec::Mediated),
            ],
        ));
        assert_eq!(one.memory_max, Some((2048 + 112 + 512) * 1024 * 1024));
        assert_eq!(two.memory_max, Some((2048 + 112 + 1024) * 1024 * 1024));
    }

    fn volume(attachment: VolumeAttachment) -> Volume {
        Volume {
            handle: agent_api::VolumeHandle {
                id: uuid::Uuid::nil(),
                backend: "/vol/a.raw".into(),
                size_bytes: 0,
                params: None,
            },
            attachment,
        }
    }

    /// The claim this whole refactor is judged on: a VM gets the same
    /// configuration it got before.
    ///
    /// It goes through the real thing rather than a stub. A real filesystem
    /// backend provisions a real file and attaches it, the attachment goes
    /// into a real `VmRecord`, and `build_instance_spec` — the one function
    /// that turns a record into what the hypervisor is told — produces the
    /// list. What it must produce is exactly one `Path` volume, which is what
    /// a single `create` produced before there were two calls.
    ///
    /// The chain closes below this: `VolumeAttachment` did not change, and
    /// the cloud-hypervisor driver's own tests pin the VMM config it builds
    /// from a `Path`. So an unchanged attachment here IS an unchanged config
    /// there, and the two halves together are the "byte for byte" claim.
    #[tokio::test]
    async fn a_vm_is_built_from_the_same_attachments_two_calls_now_produce() {
        let dir = std::env::temp_dir().join(format!("meister-split-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("images")).expect("a temp image dir");
        let d = dir.display();
        let cfg: crate::config::AgentConfig = toml::from_str(&format!(
            r#"node_id = "n1"
               [paths]
               db_path     = "{d}/a.redb"
               run_dir     = "{d}/run"
               image_dir   = "{d}/images"
               volume_dir  = "{d}/volumes"
               cgroup_root = "{d}/cgroup"
               [volume.filesystem]"#
        ))
        .expect("the test config parses");

        // A storage node's driver set: no hypervisor and no network, which is
        // exactly what `build_instance_spec` needs none of.
        let drivers = Drivers::from_config(&cfg).await.expect("drivers build");
        let provisioner = Provisioner::new(
            Arc::new(Store::open(&cfg.paths.db_path).expect("a store")),
            drivers.clone(),
            Arc::new(crate::images::Cache::new(cfg.paths.image_dir.clone())),
            cfg.paths.image_dir.clone(),
            cfg.paths.run_dir.clone(),
            String::new(),
            None,
            None,
        );

        let vol_id = uuid::Uuid::new_v4();
        let vspec = agent_api::storage::VolumeSpec {
            base_image: None,
            size_bytes: 4096,
            driver: None,
            params: None,
        };
        let backend = drivers
            .storage
            .get(&default_volume_driver())
            .expect("the default backend is always registered");

        // The two calls, in the order `run_chain` makes them.
        let handle = backend
            .provision(&vol_id, &vspec)
            .await
            .expect("provisioned");
        let attachment = backend.attach(&handle, None).await.expect("attached");

        let mut vm_spec = spec(2, 2048, vec![]);
        vm_spec.volumes = vec![crate::types::VolumeWithId {
            id: vol_id,
            spec: vspec,
        }];
        let mut record = crate::types::VmRecord {
            spec: vm_spec.clone(),
            desired: Desired::Running,
            phase: Phase::VolumesDone,
            operation: None,
            stop_deadline: None,
            unhealthy: None,
            managed_by_controller: false,
            volumes: vec![Volume {
                handle: handle.clone(),
                attachment: attachment.clone(),
            }],
            nics: vec![],
            devices: vec![],
            vmm_pid: None,
        };
        record.phase = Phase::VolumesDone;

        let ispec = provisioner
            .build_instance_spec(&uuid::Uuid::new_v4(), &vm_spec, &record)
            .expect("a vm with one block volume builds");

        assert_eq!(ispec.volumes.len(), 1);
        match &ispec.volumes[0] {
            VolumeAttachment::Path(p) => {
                assert_eq!(p, &cfg.paths.volume_dir.join(format!("{vol_id}.raw")))
            }
            other => panic!("a plain disk is a path, not {other:?}"),
        }
        // Nothing about the VM grew a backend process, so the slice is not
        // widened and the guest memory does not have to be shareable —
        // exactly the three answers a one-call `create` produced.
        assert!(
            widen_for_storage_backends(&Provisioner::limits_for(&vm_spec), &record.volumes)
                .is_none()
        );
        assert!(!ispec.volumes[0].needs_shared_memory());
        assert!(ispec.volumes[0].is_block());

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The gap this closes: an `[volume.nfs]` share is a virtiofsd in the
    /// VM's own slice, and before the widening it had no allowance at all —
    /// the slice was sized for the VMM and the devices only.
    #[test]
    fn a_volume_backend_widens_the_slice_and_a_plain_path_does_not() {
        let base = Provisioner::limits_for(&spec(2, 2048, vec![]));
        assert_eq!(base.memory_max, Some((2048 + 112) * 1024 * 1024));

        // Plain paths are not processes: byte for byte the old limits.
        assert!(
            widen_for_storage_backends(&base, &[volume(VolumeAttachment::Path("/a.raw".into()))])
                .is_none()
        );
        assert!(widen_for_storage_backends(&base, &[]).is_none());

        // A virtiofsd share is, and so is a vhost-user-blk backend.
        let widened = widen_for_storage_backends(
            &base,
            &[
                volume(VolumeAttachment::Path("/a.raw".into())),
                volume(VolumeAttachment::FsShare {
                    socket: "/s".into(),
                    tag: "share".into(),
                    pid: 7,
                }),
            ],
        )
        .expect("a share is a backend process");
        assert_eq!(widened.memory_max, Some((2048 + 112 + 512) * 1024 * 1024));

        let two = widen_for_storage_backends(
            &base,
            &[
                volume(VolumeAttachment::FsShare {
                    socket: "/s".into(),
                    tag: "share".into(),
                    pid: 7,
                }),
                volume(VolumeAttachment::VhostUserBlk {
                    socket: "/b".into(),
                    pid: 8,
                }),
            ],
        )
        .expect("two backends");
        assert_eq!(two.memory_max, Some((2048 + 112 + 1024) * 1024 * 1024));
    }

    /// The pinning is the agent's, not the VM's, and the widening must not
    /// quietly drop it: it goes back through `create_slice`, which writes the
    /// parent's cpuset from exactly this field.
    #[test]
    fn widening_keeps_every_limit_it_is_not_about() {
        let mut base = Provisioner::limits_for(&spec(4, 1024, vec![]));
        base.cpuset = Some("0-7".into());
        let widened = widen_for_storage_backends(
            &base,
            &[volume(VolumeAttachment::VhostUserBlk {
                socket: "/b".into(),
                pid: 3,
            })],
        )
        .expect("one backend");
        assert_eq!(widened.cpuset.as_deref(), Some("0-7"));
        assert_eq!(widened.cpu_quota, base.cpu_quota);
    }

    #[test]
    fn vfio_pinning_gets_extra_headroom() {
        let l = Provisioner::limits_for(&spec(
            2,
            2048,
            vec![device("vfio", PartitionSpec::Exclusive)],
        ));
        assert_eq!(l.memory_max, Some((2048 + 112 + 512 + 256) * 1024 * 1024));
    }
}
