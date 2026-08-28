// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

use agent_api::device::{DeviceId, DeviceSpec, PartitionSpec, default_device_driver};
use agent_api::hypervisor::{BootSource, InstanceSpec};
use agent_api::networking::NicAttachment;
use agent_api::{HypervisorError, ResourceLimits, VmId};
use anyhow::{Context, Result, anyhow, bail};
use macros::generated;
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

pub struct Provisioner {
    store: Arc<Store>,
    drivers: Drivers,
    image_dir: PathBuf,
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
#[generated(model = ClaudeFable, version = "5")]
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
#[generated(model = ClaudeOpus, version = "5")]
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
#[generated(model = ClaudeOpus, version = "5")]
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

#[generated(model = ClaudeFable, version = "5")]
impl Provisioner {
    pub fn new(
        store: Arc<Store>,
        drivers: Drivers,
        image_dir: PathBuf,
        default_bridge: String,
        bridge_addr: Option<(IpAddr, u8)>,
        cpuset: Option<String>,
    ) -> Self {
        Self {
            store,
            drivers,
            image_dir,
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
    #[generated(model = ClaudeOpus, version = "5")]
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
    #[generated(model = ClaudeFable, version = "5")]
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
    #[generated(model = ClaudeFable, version = "5")]
    #[instrument(skip_all, fields(vm_id = %id, volumes = record.spec.volumes.len(),
                                  nics = record.spec.nics.len(),
                                  devices = record.spec.devices.len()))]
    async fn run_chain(&self, id: &VmId, record: &mut VmRecord) -> Result<()> {
        let spec = record.spec.clone();

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
            let vol = driver
                .create(&v.id, &v.spec, Some(&cgroup))
                .await
                .with_context(|| format!("creating volume {} via {driver_name}", v.id))?;
            record.volumes.push(vol);
        }
        record.phase = Phase::VolumesDone;
        self.store.put(id, record)?;
        info!(count = record.volumes.len(), "volumes ready");

        for n in &spec.nics {
            // A tenant NIC lands on the tenant's own bridge; the one the spec
            // names is the default it WOULD have taken, and stays on record
            // as exactly that. No address is ever assigned to an overlay
            // bridge: the host is not on the tenant's network, and giving it
            // an address there would be the one hole the isolation is for.
            if let Some(vni) = n.spec.vxlan_id {
                let bridge = self
                    .drivers
                    .bridge
                    .ensure_overlay(vni)
                    .await
                    .with_context(|| format!("ensuring the overlay for vxlan {vni}"))?;
                debug!(nic_id = %n.id, vni, bridge = %bridge, "nic joins a tenant overlay");
            } else {
                self.drivers
                    .bridge
                    .ensure(&n.spec.bridge)
                    .await
                    .with_context(|| format!("ensuring bridge {}", n.spec.bridge))?;
                if n.spec.bridge == self.default_bridge
                    && let Some((ip, prefix)) = self.bridge_addr
                {
                    self.drivers
                        .bridge
                        .ensure_address(&n.spec.bridge, ip, prefix)
                        .await
                        .with_context(|| {
                            format!("assigning {ip}/{prefix} to bridge {}", n.spec.bridge)
                        })?;
                }
            }
            let nic = self
                .drivers
                .networking
                .create(&n.id, &n.spec)
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
            let dev = driver
                .create(&d.id, &d.spec, Some(&cgroup))
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

        let ispec = self.build_instance_spec(&spec, record)?;
        debug!(?ispec, "creating hypervisor");
        let vmm_pid = self
            .drivers
            .hypervisor
            .create(id, &ispec, Some(&cgroup))
            .await
            .context("hypervisor create")?;
        record.vmm_pid = Some(vmm_pid);
        self.store.put(id, record)?;

        debug!(?ispec, "starting hypervisor");
        self.drivers
            .hypervisor
            .start(id)
            .await
            .context("hypervisor start")?;

        record.phase = Phase::Provisioned;
        self.store.put(id, record)?;
        info!("vm provisioned and running");
        Ok(())
    }

    fn build_instance_spec(&self, spec: &AgentVmSpec, record: &VmRecord) -> Result<InstanceSpec> {
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

    #[generated(model = ClaudeFable, version = "5")]
    #[instrument(skip(self), fields(vm_id = %id))]
    pub async fn teardown(&self, id: &VmId) -> Result<()> {
        let Some(record) = self.store.get(id)? else {
            return Ok(());
        };

        let mut failures: Vec<String> = Vec::new();

        if let Err(e) = self.drivers.confiner.kill_slice(&id.to_string()) {
            failures.push(format!("cgroup kill: {e}"));
        }

        match self.drivers.hypervisor.destroy(id).await {
            Ok(()) | Err(HypervisorError::NotFound(_)) => {}
            Err(e) => failures.push(format!("hypervisor destroy: {e}")),
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
            if let Err(e) = driver.destroy(&d.id, &d.attachment).await {
                failures.push(format!("device {}: {e}", d.id));
            }
        }

        for n in &record.nics {
            if let Err(e) = self.drivers.networking.destroy(&n.id).await {
                failures.push(format!("nic {}: {e}", n.id));
            }
        }

        for v in &record.volumes {
            let name = volume_driver_name(&record, &v.id);
            let Some(driver) = self.drivers.storage.get(&name) else {
                failures.push(format!(
                    "volume {}: driver {name:?} is not configured",
                    v.id
                ));
                continue;
            };
            if let Err(e) = driver.destroy(&v.id, &v.attachment).await {
                failures.push(format!("volume {}: {e}", v.id));
            }
        }

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

    #[generated(model = ClaudeFable, version = "5")]
    #[instrument(skip(self, record), fields(vm_id = %id))]
    pub(crate) async fn stop(&self, id: &VmId, mut record: VmRecord) -> Result<()> {
        match self.drivers.hypervisor.destroy(id).await {
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
                    if let Err(e) = driver.destroy(&d.id, &d.attachment).await {
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
            let name = volume_driver_name(&record, &v.id);
            match self.drivers.storage.get(&name) {
                Some(driver) => {
                    if let Err(e) = driver.detach(&v.id, &v.attachment).await {
                        warn!(volume = %v.id, error = %format!("{e:#}"),
                              "detaching volume backend failed");
                    }
                }
                None => warn!(volume = %v.id, driver = %name,
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

    #[generated(model = ClaudeFable, version = "5")]
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
#[generated(model = ClaudeFable, version = "5")]
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
            id: uuid::Uuid::nil(),
            attachment,
            size_bytes: 0,
        }
    }

    /// The gap this closes: an `[volume.nfs]` share is a virtiofsd in the
    /// VM's own slice, and before the widening it had no allowance at all —
    /// the slice was sized for the VMM and the devices only.
    #[test]
    #[generated(model = ClaudeOpus, version = "5")]
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
    #[generated(model = ClaudeOpus, version = "5")]
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
