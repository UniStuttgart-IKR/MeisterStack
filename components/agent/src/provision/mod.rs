// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! VM resource acquisition, recovery and teardown.
//!
//! The provisioning chain prepares images, a cgroup, volumes, NICs, devices and
//! a cloud-init seed before booting a VMM or starting a migration receiver.
//! Each resource family has a submodule; completed stages are persisted.

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

/// Cgroup memory headroom per device or storage backend process, in MiB.
const BACKEND_OVERHEAD_MIB: u64 = 512;

/// Measure a driver call, including failed calls. Labels use configured driver
/// names and operation names to keep metric cardinality bounded.
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
    /// Runtime directory for cloud-init seeds derived from VM specifications.
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

/// Deduplicated base-image names without a URL-backed source in this spec.
/// These files are checked locally rather than downloaded.
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

/// Migration observation budgets. Expiry does not establish ownership or
/// authorize receiver cleanup; see `docs/MIGRATION.md`.
#[derive(Debug, Clone, Copy)]
pub struct Ceilings {
    /// How long the source watcher runs before retaining the attempt as unresolved.
    pub migrate_out: Duration,
    /// Advisory receive deadline persisted for compatibility; not a cleanup trigger.
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

    /// Refresh path-image status for readable VM and non-Gone volume records.
    ///
    /// The reconcile and status loops call this so a file appearing or disappearing
    /// changes the report. Names are deduplicated. Unreadable records are skipped;
    /// images unused by local records cannot be verified through this path.
    pub(crate) async fn verify_path_images(&self) {
        let mut seen: Vec<String> = Vec::new();
        let mut note = |name: String| {
            if !seen.contains(&name) {
                seen.push(name);
            }
        };
        if let Ok(records) = self.store.list() {
            for (_, record) in &records {
                for name in path_images(&record.spec) {
                    note(name);
                }
            }
        }
        if let Ok(volumes) = self.store.list_volumes() {
            for (_, record) in &volumes {
                // A tombstone names bytes that are gone on purpose; nothing
                // about its base image is evidence about anything any more.
                if record.phase == crate::types::VolumeRecordPhase::Gone {
                    continue;
                }
                if let Some(name) = record.spec.base_image.clone() {
                    note(name);
                }
            }
        }
        for name in seen {
            self.images.verify_path(&name).await;
        }
    }

    /// Override the default migration observation budgets.
    pub fn with_ceilings(mut self, ceilings: Ceilings) -> Self {
        self.ceilings = ceilings;
        self
    }

    /// Resolve a storage driver by name or return an identifying error.
    fn storage(&self, name: &str) -> Result<Arc<dyn agent_api::storage::VolumeDriver>> {
        self.drivers.storage.get(name).cloned().ok_or_else(|| {
            anyhow!("vm spec requests volume driver {name:?} which is not configured on this node")
        })
    }

    /// Apply what a re-sent create may change on an existing VM: the NICs' address guards
    /// first, so that narrowing one never waits on a volume, then the referenced volumes.
    pub async fn sync_in_place(&self, id: &VmId, wanted: &AgentVmSpec) -> Result<()> {
        self.sync_nic_addresses(id, wanted).await?;
        self.sync_volumes(id, wanted).await
    }

    /// Provision a VM, or apply a re-sent spec in place to an existing record.
    ///
    /// Only controller-managed records are eligible for desired-state orphan
    /// cleanup. An unreadable existing row refuses creation to preserve ownership
    /// of any resources it may describe.
    #[instrument(skip(self, spec), fields(vm_id = %id))]
    pub async fn provision(
        &self,
        id: VmId,
        spec: AgentVmSpec,
        desired: Desired,
        managed_by_controller: bool,
    ) -> Result<()> {
        if let Some(crate::store::VmRow::Unreadable(key)) = self.store.row(&id)? {
            bail!(
                "this node has a record of vm {key} that it cannot read; it will not create a vm \
                 over it. The row has to be looked at first: building here would leave whatever \
                 it describes running with nothing naming it."
            );
        }
        if let Some(mut existing) = self.store.get(&id)? {
            info!(desired = ?desired, "vm record exists, applying the re-sent spec in place");
            existing.desired = desired;
            self.store.put(&id, &existing)?;
            return self.sync_in_place(&id, &spec).await;
        }

        self.check_device_admission(&id, &spec).await?;

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
            migration: None,
            unhealthy: None,
            managed_by_controller,
            unattached_volumes: Vec::new(),
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

    /// Acquire resources in dependency order and persist each completed stage.
    /// Boot and receive share the same resources because the migration stream
    /// contains paths that must already exist on the destination.
    #[instrument(skip_all, fields(vm_id = %id, volumes = record.spec.volumes.len(),
                                  nics = record.spec.nics.len(),
                                  devices = record.spec.devices.len()))]
    async fn run_chain(&self, id: &VmId, record: &mut VmRecord, finish: Finish<'_>) -> Result<()> {
        let spec = record.spec.clone();

        // Fetch required images before creating resources or opening them through a volume driver.
        for source in &spec.images {
            self.images
                .ensure(source)
                .await
                .with_context(|| format!("base image {}", source.name))?;
        }
        // Report path-image availability without replacing the storage driver
        // error that an unavailable file will produce during provision.
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

        // Account for storage backend processes after attachment identifies them,
        // but before placing the VMM in its slice.
        if let Some(widened) = widen_for_storage_backends(&limits, &record.volumes) {
            debug!(?widened, "widening the slice for storage backends");
            self.drivers
                .confiner
                .create_slice(&id.to_string(), None, &widened)
                .map_err(|e| anyhow!("widening cgroup slice for storage backends: {e}"))?;
        }

        self.write_seed(id, &spec)?;

        // Choose boot or receive after shared resource preparation.
        match finish {
            Finish::Boot => self.boot(id, record, &spec, &cgroup).await,
            Finish::Receive { listen } => self.receive(id, record, listen, &cgroup).await,
        }
    }

    /// Create and boot the VMM after the resource chain completes.
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

    /// Initial cgroup limits derived from the VM spec. Storage backend allowances
    /// are added after attachment by `widen_for_storage_backends`.
    fn limits_for(spec: &AgentVmSpec) -> ResourceLimits {
        let vmm_overhead_mib = 64 + (8 * spec.vcpus as u64) + 32;
        // Reserve host-memory headroom for each device and its backend. Storage
        // backend processes are counted from returned attachments after provision.
        let device_overhead_mib = BACKEND_OVERHEAD_MIB * spec.devices.len() as u64;
        // VFIO pins guest RAM for DMA, so VMM overhead needs additional resident-memory headroom.
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
        // Admitted again on every start: a node whose configuration changed
        // since this vm was first admitted (a smaller budget, a larger
        // profile) must not start it past what it can hold now.
        self.check_device_admission(id, &record.spec).await?;
        // Read off the disks of the last run, which the next line forgets.
        self.restore_drifted_inline_ids(id, &mut record)?;
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

/// Select normal boot or migration reception after the common resource chain.
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
