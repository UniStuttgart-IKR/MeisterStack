// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Cloud Hypervisor integration: one VMM process and API socket per VM.
//!
//! `config` builds the VM document, `process` owns process and file lifecycle,
//! `api` handles requests and observations, and `fd` transfers tap descriptors.

use agent_api::hypervisor;
use agent_api::{
    AttachedVolume, BootSource, CgroupHandle, ConsoleStream, DeviceAttachment, HotPluggable,
    Hypervisor, HypervisorError, InstanceSpec, Pausable, VmId, VmState, VolumeAttachment,
};
use anyhow::{Context, bail};
use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper::{Method, Request};
use hyper_util::rt::TokioIo;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Mutex;
use std::time::Duration;
use tokio::net::UnixStream;
use tokio::process::{Child, Command};
use tracing::{debug, info, instrument, warn};

mod api;
mod config;
mod fd;
mod process;

pub(crate) use api::*;
pub(crate) use config::*;
pub(crate) use process::*;

/// Default hot-unplug observation timeout. The agent configuration reuses
/// this value and can override it for guests that acknowledge unplug slowly.
/// Expiry reports incomplete removal; it does not prove the device is gone.
pub const DEFAULT_UNPLUG_TIMEOUT: Duration = Duration::from_secs(30);

pub struct CloudHypervisorDriver {
    binary: PathBuf,
    socket_dir: PathBuf,
    vms: Mutex<HashMap<VmId, RunningVm>>,
    ch_timeout: Duration,
    /// Guest hot-unplug deadline; defaults to `DEFAULT_UNPLUG_TIMEOUT`.
    unplug_timeout: Duration,
    /// Pending unplug paths keyed by VM and disk ID. Cache them before
    /// vm.remove-device removes config entries so retries can still inspect open fds.
    unplugging: Mutex<HashMap<(VmId, String), PathBuf>>,
    /// Use descriptor handoff for taps. Cloud Hypervisor v53 cannot migrate
    /// NICs configured this way; see `NetForm`.
    tap_fds: bool,
    /// Optional VMM identity; None retains the agent's identity.
    vmm_user: Option<agent_api::VmmUser>,
    /// Directories for later file-backed hotplug, added to Landlock
    /// beyond paths already named by the initial VM configuration.
    landlock_paths: Vec<PathBuf>,
}

impl CloudHypervisorDriver {
    pub fn new(
        binary: PathBuf,
        socket_dir: PathBuf,
        ch_timeout: Duration,
        unplug_timeout: Duration,
    ) -> hypervisor::Result<Self> {
        std::fs::create_dir_all(&socket_dir).map_err(|e| {
            HypervisorError::Backend(anyhow::anyhow!(
                "creating socket dir {}: {e}",
                socket_dir.display()
            ))
        })?;
        Ok(Self {
            binary,
            socket_dir,
            vms: Mutex::new(HashMap::new()),
            ch_timeout,
            unplug_timeout,
            unplugging: Mutex::new(HashMap::new()),
            tap_fds: false,
            vmm_user: None,
            landlock_paths: Vec::new(),
        })
    }

    /// Enable descriptor handoff so VMMs can use taps without CAP_NET_ADMIN.
    pub fn with_tap_fds(mut self, tap_fds: bool) -> Self {
        self.tap_fds = tap_fds;
        self
    }

    /// Run VMMs under the supplied identity. Config enables this alongside tap
    /// handoff, but they remain separate options with distinct permission failures.
    pub fn with_vmm_user(mut self, user: Option<agent_api::VmmUser>) -> Self {
        self.vmm_user = user;
        self
    }

    /// Allow later file-backed hotplug from these directories under Landlock.
    pub fn with_landlock_paths(mut self, paths: Vec<PathBuf>) -> Self {
        self.landlock_paths = paths;
        self
    }

    /// Select persistent-name or descriptor NIC handoff.
    pub(crate) fn net_form(&self) -> NetForm {
        match self.tap_fds {
            true => NetForm::TapFd,
            false => NetForm::TapName,
        }
    }

    /// Build the NIC handoff and Landlock policy. Landlock is enabled only
    /// when a separate VMM user is configured.
    pub(crate) fn vm_form(&self, spec: &InstanceSpec) -> VmForm {
        VmForm {
            net: self.net_form(),
            landlock: self.vmm_user.as_ref().map(|_| self.landlock_rules(spec)),
        }
    }

    /// Allow the run directory, configured image/volume directories and parent
    /// directories of existing path-backed volumes. A first hotplug from another
    /// directory can fail because Landlock rules cannot be widened after restriction.
    fn landlock_rules(&self, spec: &InstanceSpec) -> Vec<LandlockRule> {
        let mut rules: Vec<LandlockRule> = Vec::new();
        let mut add = |path: PathBuf, access: &'static str| {
            if !rules.iter().any(|r| r.path == path) {
                rules.push(LandlockRule { path, access });
            }
        };
        // The run directory and not only this driver's own corner of it: the
        // backends' sockets are siblings, one level up.
        add(
            self.socket_dir
                .parent()
                .unwrap_or(&self.socket_dir)
                .to_path_buf(),
            "rw",
        );
        for path in &self.landlock_paths {
            add(path.clone(), "rw");
        }
        for volume in &spec.volumes {
            if let VolumeAttachment::Path(path) = &volume.attachment
                && let Some(dir) = path.parent()
            {
                add(dir.to_path_buf(), "rw");
            }
        }
        rules
    }
}

#[async_trait::async_trait]
impl Hypervisor for CloudHypervisorDriver {
    #[instrument(skip_all, fields(vm_id = %id))]
    async fn create(
        &self,
        id: &VmId,
        spec: &InstanceSpec,
        cgroup: Option<&CgroupHandle>,
    ) -> hypervisor::Result<u32> {
        self.create_vm(id, spec, cgroup).await
    }

    #[instrument(skip_all, fields(vm_id = %id))]
    async fn start(&self, id: &VmId) -> hypervisor::Result<()> {
        self.vm_known(id)?;
        self.api(id, Method::PUT, "vm.boot", None).await.map(|_| ())
    }

    #[instrument(skip_all, fields(vm_id = %id))]
    async fn shutdown(&self, id: &VmId) -> hypervisor::Result<()> {
        self.vm_known(id)?;
        self.api(id, Method::PUT, "vm.shutdown", None)
            .await
            .map(|_| ())
    }
    #[instrument(skip_all, fields(vm_id = %id))]
    async fn power_button(&self, id: &VmId) -> hypervisor::Result<()> {
        self.vm_known(id)?;
        self.api(id, Method::PUT, "vm.power-button", None)
            .await
            .map(|_| ())
    }
    // telemetry with RUST_LOG=...=trace
    #[instrument(level = "trace", skip_all, fields(vm_id = %id))]
    async fn get_state(&self, id: &VmId) -> hypervisor::Result<VmState> {
        self.state(id).await
    }

    #[instrument(skip_all, fields(vm_id = %id))]
    async fn destroy(&self, id: &VmId) -> hypervisor::Result<()> {
        self.destroy_vm(id).await
    }

    fn console_paths(&self, id: &VmId) -> Vec<(ConsoleStream, PathBuf)> {
        ConsoleStream::ALL
            .into_iter()
            .map(|s| (s, self.console_path(id, s)))
            .collect()
    }

    /// Return retained VMM logs followed by the current log. These are driver
    /// diagnostics, exposed only when the caller explicitly requests the VMM stream.
    fn diagnostic_paths(&self, id: &VmId) -> Vec<PathBuf> {
        let mut paths = self.kept_logs(id);
        paths.push(self.vmm_log_path(id));
        paths
    }

    fn console_socket(&self, id: &VmId) -> Option<PathBuf> {
        Some(self.serial_socket_path(id))
    }

    #[instrument(skip_all, fields(vm_id = %id, pid))]
    async fn adopt(&self, id: &VmId, pid: u32) -> hypervisor::Result<()> {
        self.adopt_vm(id, pid).await
    }

    #[instrument(level = "trace", skip_all, fields(vm_id = %id))]
    async fn probe(&self, id: &VmId) -> bool {
        self.api(id, Method::GET, "vmm.ping", None).await.is_ok()
    }

    fn is_tracked(&self, id: &VmId) -> bool {
        self.vms.lock().unwrap().contains_key(id)
    }

    async fn strays(&self, known: &[VmId]) -> Vec<VmId> {
        self.stray_vms(known).await
    }

    #[instrument(skip_all, fields(vm_id = %id))]
    async fn end_stray(&self, id: &VmId) -> hypervisor::Result<()> {
        self.end_stray_vm(id).await
    }

    /// Read the executable version once at startup for migration compatibility.
    /// Probe failures return None and do not independently prevent agent startup.
    async fn version(&self) -> Option<String> {
        let out = Command::new(&self.binary)
            .arg("--version")
            .stdin(Stdio::null())
            .output()
            .await
            .ok()?;
        let said = String::from_utf8_lossy(&out.stdout);
        let line = said.lines().next().unwrap_or_default().trim();
        (!line.is_empty()).then(|| line.to_string())
    }

    /// v53's `CpuProfile` has one variant. See the trait.
    fn cpu_profile(&self) -> &'static str {
        "Host"
    }

    fn as_pausable(&self) -> Option<&dyn Pausable> {
        Some(self)
    }

    fn as_migratable(&self) -> Option<&dyn agent_api::Migratable> {
        Some(self)
    }

    fn as_hotpluggable(&self) -> Option<&dyn HotPluggable> {
        Some(self)
    }
}

#[async_trait::async_trait]
impl HotPluggable for CloudHypervisorDriver {
    /// Add a disk with its stable volume-derived ID. Filesystem shares are
    /// rejected because they require the separate vm.add-fs operation.
    #[instrument(skip_all, fields(vm_id = %id, disk = %volume.disk_id()))]
    async fn add_disk(&self, id: &VmId, volume: &AttachedVolume) -> hypervisor::Result<()> {
        self.vm_known(id)?;
        let config = disk_config(volume).ok_or_else(|| {
            HypervisorError::InvalidSpec(format!(
                "volume {} is a filesystem share, not a disk; it cannot be hot-plugged",
                volume.id
            ))
        })?;
        // Transfer file ownership before the VMM opens the hotplugged disk.
        if let Some(user) = &self.vmm_user
            && let VolumeAttachment::Path(path) = &volume.attachment
        {
            user.take(path).map_err(|e| {
                HypervisorError::Backend(anyhow::anyhow!(
                    "giving {} to {user} so the vmm can open it: {e}",
                    path.display()
                ))
            })?;
        }
        self.api(id, Method::PUT, "vm.add-disk", Some(config))
            .await
            .map(|_| ())
    }

    /// Notify the VMM after backend growth, using the stable disk ID and actual
    /// size. For block devices, Cloud Hypervisor checks that the sizes agree.
    #[instrument(skip_all, fields(vm_id = %id, disk = %disk_id, size_bytes))]
    async fn resize_disk(
        &self,
        id: &VmId,
        disk_id: &str,
        size_bytes: u64,
    ) -> hypervisor::Result<()> {
        self.vm_known(id)?;
        self.api(
            id,
            Method::PUT,
            "vm.resize-disk",
            Some(serde_json::json!({ "id": disk_id, "desired_size": size_bytes })),
        )
        .await
        .map(|_| ())
    }

    /// Request disk removal, then wait for configuration removal and, where a
    /// path and PID are available, closure of the VMM's file descriptor.
    ///
    /// An accepted request alone does not establish guest cooperation. Cache the
    /// path before the request because Cloud Hypervisor removes it from config
    /// immediately. Retry a 404 only when that path remains available. Socket-backed
    /// disks have no file witness and use the weaker configuration-only check.
    #[instrument(skip_all, fields(vm_id = %id, disk = %disk_id))]
    async fn remove_disk(&self, id: &VmId, disk_id: &str) -> hypervisor::Result<()> {
        self.vm_known(id)?;
        // The path first, while the config still names it (see `unplugging`).
        let key = (*id, disk_id.to_string());
        let path = match self.disk_path(id, disk_id).await? {
            Some(path) => {
                self.unplugging
                    .lock()
                    .unwrap()
                    .insert(key.clone(), path.clone());
                Some(path)
            }
            None => self.unplugging.lock().unwrap().get(&key).cloned(),
        };
        match self
            .api(
                id,
                Method::PUT,
                "vm.remove-device",
                Some(serde_json::json!({ "id": disk_id })),
            )
            .await
        {
            Ok(_) => {}
            // After an earlier accepted removal, 404 can still mean the guest holds
            // the fd. Continue only when the cached path permits that check.
            Err(e) if path.is_some() && is_not_found(&e) => {
                debug!("the vmm has already been asked; waiting on the fd");
            }
            Err(e) => return Err(e),
        }
        let pid = self.pid_of(id);
        let witness = path.as_deref().zip(pid);
        if witness.is_none() {
            warn!(
                path = path.is_some(),
                pid = pid.is_some(),
                "no fd witness for this disk; trusting the vmm's config, which is weaker"
            );
        }
        until_the_disk_is_gone(
            disk_id,
            || async {
                let bytes = self.api(id, Method::GET, "vm.info", None).await?;
                serde_json::from_slice(&bytes).map_err(|e| HypervisorError::Backend(e.into()))
            },
            || match witness {
                Some((path, pid)) => vmm_holds(pid, path).map(Some),
                None => Ok(None),
            },
            self.unplug_timeout,
            UNPLUG_POLL,
        )
        .await?;
        // Restore ownership only after removal checks complete, preserving access
        // while the guest can still use the disk.
        if self.vmm_user.is_some()
            && let Some(path) = &path
            && let Err(e) = agent_api::VmmUser::give_back(path)
        {
            debug!(path = %path.display(), error = %e, "the volume could not be handed back");
        }
        self.unplugging.lock().unwrap().remove(&key);
        Ok(())
    }

    /// Add a NIC through the same descriptor handoff used before boot. This
    /// method refuses the tap-name form; NIC hotplug is supported only with tap fds.
    #[instrument(skip_all, fields(vm_id = %id, tap = %nic.tap_name))]
    async fn add_nic(&self, id: &VmId, nic: &agent_api::NicAttachment) -> hypervisor::Result<()> {
        self.vm_known(id)?;
        if self.net_form() != NetForm::TapFd {
            return Err(HypervisorError::Backend(anyhow::anyhow!(
                "adding a nic to a running vm needs the descriptor form, which this node has not \
                 asked for: set `vmm_user` or recreate the vm with the nic in its spec"
            )));
        }
        self.add_net_with_fd(id, nic).await
    }
}

#[async_trait::async_trait]
impl Pausable for CloudHypervisorDriver {
    #[instrument(skip_all, fields(vm_id = %id))]
    async fn pause(&self, id: &VmId) -> hypervisor::Result<()> {
        self.vm_known(id)?;
        self.api(id, Method::PUT, "vm.pause", None)
            .await
            .map(|_| ())
    }

    #[instrument(skip_all, fields(vm_id = %id))]
    async fn resume(&self, id: &VmId) -> hypervisor::Result<()> {
        self.vm_known(id)?;
        self.api(id, Method::PUT, "vm.resume", None)
            .await
            .map(|_| ())
    }
}

#[async_trait::async_trait]
impl agent_api::Migratable for CloudHypervisorDriver {
    /// Start a receiving VMM without calling `vm.create`. The stream supplies
    /// the VM configuration, including paths that must exist on the destination.
    /// Both nodes therefore need compatible disk, tap and run-directory paths.
    ///
    /// The receive request runs in a task because it blocks the VMM API; readiness
    /// comes from the event file. Remove stale serial sockets before reception.
    /// Source console logs remain on the source rather than travelling with the guest.
    #[instrument(skip_all, fields(vm_id = %id, peer = %peer))]
    async fn migrate_in(&self, id: &VmId, peer: &str) -> hypervisor::Result<u32> {
        self.receive_migration(id, peer).await
    }

    /// Read receive failure evidence from the stored API result or event file.
    /// The event distinguishes failed reception from an idle Created VMM;
    /// stored transport errors remain subject to the uncertainty described in `api`.
    fn receive_failed(&self, id: &VmId) -> Option<String> {
        self.receive_failure(id)
    }

    /// Probe guest ownership with `vm.counters`, which the supported VMM refuses
    /// while migration owns the guest. A successful response can establish that an
    /// acknowledged send returned the guest; `vm.info` cannot because it may serve
    /// a pre-migration snapshot. Errors remain inconclusive.
    async fn send_failed(&self, id: &VmId) -> Option<String> {
        match self.api(id, Method::GET, "vm.counters", None).await {
            Ok(_) => Some(
                "cloud-hypervisor is serving the guest here again, so the transfer ended \
                 without it leaving"
                    .to_string(),
            ),
            Err(_) => None,
        }
    }

    /// Submit a send to the destination URL. The API acknowledges submission;
    /// the agent must establish the outcome independently. No TLS directory is
    /// supplied for this migration stream.
    ///
    /// With tap-fd mode enabled, refuse a VM whose current config contains fd-backed
    /// NICs: Cloud Hypervisor v53 cannot replace their descriptors on reception.
    #[instrument(skip_all, fields(vm_id = %id, peer = %peer))]
    async fn migrate_out(&self, id: &VmId, peer: &str) -> hypervisor::Result<()> {
        self.vm_known(id)?;
        if self.tap_fds && self.has_fd_nic(id).await? {
            return Err(HypervisorError::Backend(anyhow::anyhow!(
                "this vm's nics were handed to the vmm as file descriptors, and cloud hypervisor \
                 v53 cannot carry those across a live migration: the arriving config's fds are \
                 deserialised as -1 and vm.receive-migration has no way to be given new ones. A \
                 node that must migrate vms with nics runs its vmm as the agent, which means \
                 leaving `vmm_user` unset"
            )));
        }
        self.api(
            id,
            Method::PUT,
            "vm.send-migration",
            Some(serde_json::json!({ "destination_url": peer })),
        )
        .await
        .map(|_| ())
    }
}

/// Whether a `ch_api` error was cloud hypervisor answering 404 — the shape
/// `api()` gives it is "ch <endpoint> -> 404 Not Found: ...".
fn is_not_found(e: &HypervisorError) -> bool {
    format!("{e}").contains("-> 404")
}

#[cfg(test)]
mod tests;
