// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! VMM process ownership, startup, adoption and teardown, including API,
//! console and event-file paths. Requests use the sibling `api` module.

use super::*;

/// Suffix for retained guest logs after teardown; files remain beside active logs.
pub(crate) const KEPT_LOG: &str = ".log.gone-";

/// Retention age for VMM logs. Expired files are swept during later teardown;
/// this is not a timer that removes them exactly at the deadline.
const KEPT_LOG_TTL: std::time::Duration = std::time::Duration::from_secs(3600);

pub(crate) enum VmProcess {
    Owned(Child),
    Adopted { pid: u32 },
}

pub(crate) struct RunningVm {
    pub(crate) process: VmProcess,
    /// Event path while receiving blocks the VMM API. Observation uses these
    /// events instead of treating API timeouts as process failure; terminal
    /// events clear this receiving marker.
    pub(crate) receiving: Option<PathBuf>,
    /// Event path retained after reception for later outcome queries, including
    /// failed-receive cleanup. Locally booted VMMs have no event monitor.
    pub(crate) events: Option<PathBuf>,
    /// Stored error from the asynchronous receive request. This currently includes
    /// transport and timeout errors as well as explicit VMM failures; callers
    /// cannot distinguish those outcomes through this field.
    pub(crate) receive_answer: std::sync::Arc<Mutex<Option<String>>>,
}

impl CloudHypervisorDriver {
    pub(crate) fn vm_socket_path(&self, id: &VmId) -> PathBuf {
        self.socket_dir.join(format!("{id}.sock"))
    }

    /// Shared guest-log path construction for VM configuration and log reporting.
    pub(crate) fn console_path(&self, id: &VmId, stream: ConsoleStream) -> PathBuf {
        self.socket_dir.join(format!("{id}.{}", stream.as_str()))
    }

    /// VMM stdout/stderr diagnostics, separate from guest console paths.
    pub(crate) fn vmm_log_path(&self, id: &VmId) -> PathBuf {
        self.socket_dir.join(format!("{id}.log"))
    }

    /// Retained-log filename with a Unix-seconds suffix. Teardowns within the
    /// same second share a destination name.
    pub(crate) fn kept_log_path(&self, id: &VmId, at: std::time::SystemTime) -> PathBuf {
        let secs = at
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or_default();
        self.socket_dir.join(format!("{id}{KEPT_LOG}{secs}"))
    }

    /// Every kept log of one VM, oldest first.
    pub(crate) fn kept_logs(&self, id: &VmId) -> Vec<PathBuf> {
        let prefix = format!("{id}{KEPT_LOG}");
        let Ok(entries) = std::fs::read_dir(&self.socket_dir) else {
            return Vec::new();
        };
        let mut out: Vec<PathBuf> = entries
            .flatten()
            .map(|e| e.path())
            .filter(|p| {
                p.file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| n.starts_with(&prefix))
            })
            .collect();
        out.sort();
        out
    }

    /// Retain a nonempty diagnostic log and sweep expired retained logs.
    /// Empty logs are removed; all cleanup errors are handled locally.
    fn keep_the_log(&self, id: &VmId) {
        let live = self.vmm_log_path(id);
        match std::fs::metadata(&live) {
            Ok(meta) if meta.len() > 0 => {
                let kept = self.kept_log_path(id, std::time::SystemTime::now());
                match std::fs::rename(&live, &kept) {
                    Ok(()) => debug!(path = %kept.display(),
                                     "kept what the vmm said; `vm logs --streams vmm` finds it"),
                    Err(e) => {
                        warn!(error = %e, "the vmm's log could not be kept");
                        let _ = std::fs::remove_file(&live);
                    }
                }
            }
            // Empty or unavailable logs need no retained copy.
            _ => {
                let _ = std::fs::remove_file(&live);
            }
        }
        self.sweep_kept_logs();
    }

    /// Remove retained logs older than KEPT_LOG_TTL when cleanup runs.
    fn sweep_kept_logs(&self) {
        let Ok(entries) = std::fs::read_dir(&self.socket_dir) else {
            return;
        };
        let now = std::time::SystemTime::now();
        for entry in entries.flatten() {
            let path = entry.path();
            let is_kept = path
                .file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.contains(KEPT_LOG));
            if !is_kept {
                continue;
            }
            let old = entry
                .metadata()
                .and_then(|m| m.modified())
                .ok()
                .and_then(|at| now.duration_since(at).ok())
                .is_some_and(|age| age > KEPT_LOG_TTL);
            if old && let Err(e) = std::fs::remove_file(&path) {
                debug!(path = %path.display(), error = %e, "a kept vmm log could not be swept");
            }
        }
    }

    /// Grant the VMM group access to its API socket, serial socket and console
    /// file. Cloud Hypervisor's umask removes these group permissions. A nonroot
    /// agent must belong to the VMM group to use them; changing another user's
    /// file mode requires CAP_FOWNER. Failures are logged and may prevent later access.
    fn relax_to_the_group(&self, id: &VmId) {
        let Some(user) = &self.vmm_user else {
            return;
        };
        for (path, mode) in [
            (self.vm_socket_path(id), 0o770),
            (self.serial_socket_path(id), 0o770),
            (self.console_path(id, ConsoleStream::Console), 0o660),
        ] {
            use std::os::unix::fs::PermissionsExt;
            if let Err(e) = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)) {
                warn!(
                    path = %path.display(), user = %user.name, error = %e,
                    "the vmm's own file could not be opened to its group; an agent that is not \
                     root will not be able to read it"
                );
            }
        }
    }

    /// Transfer the shared run directory to the configured VMM user with mode
    /// 0770. A nonroot agent needs membership in that user's group. All VMMs use
    /// one node identity; directory layout does not isolate them from each other.
    fn hand_over_run_dir(&self) -> hypervisor::Result<()> {
        let Some(user) = &self.vmm_user else {
            return Ok(());
        };
        user.take(&self.socket_dir).map_err(|e| {
            HypervisorError::Backend(anyhow::anyhow!(
                "giving {} to {user}: {e}",
                self.socket_dir.display()
            ))
        })
    }

    /// Interactive serial socket path, derived beside its recorder log.
    pub(crate) fn serial_socket_path(&self, id: &VmId) -> PathBuf {
        self.socket_dir
            .join(format!("{id}.{}.sock", ConsoleStream::Serial.as_str()))
    }

    /// The VMM's pid, whichever way this driver came to know it.
    pub(crate) fn pid_of(&self, id: &VmId) -> Option<u32> {
        match &self.vms.lock().unwrap().get(id)?.process {
            VmProcess::Owned(child) => child.id(),
            VmProcess::Adopted { pid } => Some(*pid),
        }
    }

    pub(crate) fn vm_known(&self, id: &VmId) -> hypervisor::Result<()> {
        if self.vms.lock().unwrap().contains_key(id) {
            Ok(())
        } else {
            Err(HypervisorError::NotFound(*id))
        }
    }

    /// The event file of a VM that is still receiving, if it is.
    pub(crate) fn receiving_events(&self, id: &VmId) -> Option<PathBuf> {
        self.vms.lock().unwrap().get(id)?.receiving.clone()
    }

    /// The guest is here (or is not coming): stop treating this VMM as one
    /// that will not answer.
    pub(crate) fn arrived(&self, id: &VmId) {
        if let Some(vm) = self.vms.lock().unwrap().get_mut(id) {
            vm.receiving = None;
        }
    }

    /// Return a stored receive API error or an explicit failure event for a
    /// tracked VMM. The current API-error path also includes timeout and transport
    /// uncertainty. An untracked VMM has no failure observation here.
    pub(crate) fn receive_failure(&self, id: &VmId) -> Option<String> {
        let (answered, events) = {
            let vms = self.vms.lock().unwrap();
            let vm = vms.get(id)?;
            (vm.receive_answer.lock().unwrap().clone(), vm.events.clone())
        };
        // Prefer the receive call's error, including errors without a failure
        // event. Adopted VMMs have no task result and depend on their event file.
        if let Some(said) = answered {
            return Some(said);
        }
        match receive_outcome(&events?) {
            Some(Err(said)) => Some(said),
            _ => None,
        }
    }

    /// Receiver event path for readiness and outcome observations while the
    /// receive API request remains blocked.
    pub(crate) fn event_path(&self, id: &VmId) -> PathBuf {
        self.socket_dir.join(format!("{id}.events"))
    }

    /// Spawn a VMM without defining a guest and wait for its API. Receiving VMMs
    /// use an event monitor and verbose logs because restore failures may require
    /// component-level diagnostics. Ordinary boot failures return through API calls.
    pub(crate) async fn spawn_vmm(
        &self,
        id: &VmId,
        events: Option<&Path>,
    ) -> hypervisor::Result<Child> {
        // Transfer the run directory and diagnostic log before spawning under
        // the VMM identity. Later operations reopen these paths.
        self.hand_over_run_dir()?;
        let log = std::fs::File::create(self.vmm_log_path(id))
            .map_err(|e| HypervisorError::Backend(e.into()))?;
        if let Some(user) = &self.vmm_user {
            user.take(&self.vmm_log_path(id))
                .map_err(|e| HypervisorError::Backend(anyhow::anyhow!("the vmm's log: {e}")))?;
        }
        let log2 = log
            .try_clone()
            .map_err(|e| HypervisorError::Backend(e.into()))?;
        let socket = self.vm_socket_path(id);
        let _ = std::fs::remove_file(&socket);

        if let Some(path) = events {
            let _ = std::fs::remove_file(path);
        }
        let mut command = Command::new(&self.binary);
        command.args(vmm_args(&socket, events));
        if let Some(user) = &self.vmm_user {
            // Change credentials in pre_exec after preparing privileged resources.
            // Use `VmmUser::switch_to` to retain configured supplementary groups,
            // including KVM access, which Command::uid would discard.
            let user = user.clone();
            // SAFETY: `switch_to` is three syscalls on values it already
            // holds; it allocates nothing and opens nothing.
            unsafe {
                command.pre_exec(move || user.switch_to());
            }
        }
        let mut process = command
            .stdin(Stdio::null())
            .stdout(Stdio::from(log))
            .stderr(Stdio::from(log2))
            .spawn()
            .map_err(|e| match &self.vmm_user {
                Some(user) => HypervisorError::Backend(anyhow::anyhow!(
                    "the hypervisor could not be started: {}",
                    user.cannot_switch(&e)
                )),
                None => HypervisorError::Backend(e.into()),
            })?;
        let pid = process.id().ok_or_else(|| {
            HypervisorError::Backend(anyhow::anyhow!(
                "cloud-hypervisor exited before pid could be read"
            ))
        })?;
        debug!(pid, "cloud-hypervisor spawned");

        for attempt in 0..100 {
            if self.api(id, Method::GET, "vmm.ping", None).await.is_ok() {
                debug!(attempt, "vmm api ready");
                return Ok(process);
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        warn!("vmm api not reachable, killing process");
        let _ = process.kill().await;
        Err(HypervisorError::Backend(anyhow::anyhow!(
            "Cloud-Hypervisor API not reachable for socket: {socket:?}"
        )))
    }

    /// Create an unbooted VM in its slice and return its PID for durable ownership records.
    pub(crate) async fn create_vm(
        &self,
        id: &VmId,
        spec: &InstanceSpec,
        cgroup: Option<&CgroupHandle>,
    ) -> hypervisor::Result<u32> {
        let console_path = self.console_path(id, ConsoleStream::Console);
        let serial_socket = self.serial_socket_path(id);
        // A socket left behind by a previous instance of this id would be
        // bound already and the boot would fail; the file beside it is the
        // agent's and is cleaned up with the rest in `destroy`.
        let _ = std::fs::remove_file(&serial_socket);

        let config = build_vm_config(spec, &console_path, &serial_socket, &self.vm_form(spec))?;
        // Transfer writable files before VM creation opens them.
        self.hand_over_files(spec)?;
        // No event monitor: this VM answers every question over its API
        // socket. See `event_path`.
        let mut process = self.spawn_vmm(id, None).await?;
        let pid = process
            .id()
            .ok_or_else(|| HypervisorError::Backend(anyhow::anyhow!("the vmm has no pid")))?;

        // put process into cgroup before VM boot
        if let Some(cg) = cgroup
            && let Err(e) = cg.attach_pid(pid)
        {
            let _ = process.kill().await;
            return Err(HypervisorError::Backend(e.into()));
        }

        // create VM itself
        if let Err(e) = self.api(id, Method::PUT, "vm.create", Some(config)).await {
            let _ = process.kill().await;
            return Err(e);
        }

        // Cloud Hypervisor v53 accepts descriptors on vm.add-net, not vm.create.
        // Add and validate each descriptor-backed NIC before boot. Name-based NICs
        // are already present in the initial configuration.
        if self.net_form() == NetForm::TapFd {
            for nic in &spec.nics {
                if let Err(e) = self.add_net_with_fd(id, nic).await {
                    let _ = process.kill().await;
                    return Err(e);
                }
            }
        }

        // Relax permissions after vm.create creates the console file and serial socket.
        self.relax_to_the_group(id);

        self.vms.lock().unwrap().insert(
            *id,
            RunningVm {
                process: VmProcess::Owned(process),
                receiving: None,
                events: None,
                receive_answer: Default::default(),
            },
        );
        debug!("vm created, not booted");
        Ok(pid)
    }

    /// The VMM, the VM in it, and every file this driver made for it.
    pub(crate) async fn destroy_vm(&self, id: &VmId) -> hypervisor::Result<()> {
        let vm = self.vms.lock().unwrap().remove(id);
        let vm = vm.ok_or(HypervisorError::NotFound(*id))?;

        // While it can still be asked what it holds. See `take_files_back`.
        self.take_files_back(id).await;

        if let Err(e) = self.api(id, Method::PUT, "vmm.shutdown", None).await {
            debug!(error = %format!("{e:#}"), "vmm.shutdown failed, killing process anyway");
        }

        match vm.process {
            VmProcess::Owned(mut child) => {
                let _ = child.kill().await;
            }
            // Validate adopted process identity before signalling: a persisted PID
            // can have been reused since the original VMM exited.
            VmProcess::Adopted { pid } => {
                if self.owns_pid(id, pid) {
                    let _ = nix::sys::signal::kill(
                        nix::unistd::Pid::from_raw(pid as i32),
                        nix::sys::signal::Signal::SIGKILL,
                    );
                } else {
                    debug!(
                        pid,
                        "the adopted vmm's pid belongs to something else now; not signalling it"
                    );
                }
            }
        }

        self.remove_files(id);
        Ok(())
    }

    /// Best-effort removal of API, console, serial and event files. Retain a
    /// nonempty VMM diagnostic log temporarily through `keep_the_log`.
    pub(crate) fn remove_files(&self, id: &VmId) {
        let _ = std::fs::remove_file(self.vm_socket_path(id));
        // The lock beside it. Cloud Hypervisor makes it, not this driver, but
        // it lands in this driver's run directory under this driver's name —
        // so it is this driver's to take away.
        let _ = std::fs::remove_file(self.socket_dir.join(format!("{id}.sock.lock")));
        for stream in ConsoleStream::ALL {
            let _ = std::fs::remove_file(self.console_path(id, stream));
        }
        // And the serial line's socket, which is the driver's too.
        let _ = std::fs::remove_file(self.serial_socket_path(id));
        self.keep_the_log(id);
        let _ = std::fs::remove_file(self.event_path(id));
    }

    /// Find responsive VMM sockets absent from `known`. Scan disk because the
    /// in-memory map is empty after restart; a socket file alone is insufficient.
    /// Sort results for stable condition reporting.
    pub(crate) async fn stray_vms(&self, known: &[VmId]) -> Vec<VmId> {
        let entries = match std::fs::read_dir(&self.socket_dir) {
            Ok(entries) => entries,
            Err(e) => {
                debug!(dir = %self.socket_dir.display(), error = %e,
                       "cannot look through the run directory for unmanaged vmms");
                return Vec::new();
            }
        };
        let mut candidates: Vec<VmId> = Vec::new();
        for entry in entries.flatten() {
            let name = entry.file_name();
            let Some(stem) = name.to_str().and_then(|n| n.strip_suffix(".sock")) else {
                continue;
            };
            let Ok(id) = stem.parse::<VmId>() else {
                continue;
            };
            if !known.contains(&id) {
                candidates.push(id);
            }
        }
        candidates.sort();
        let mut out = Vec::new();
        for id in candidates {
            if self.probe(&id).await {
                out.push(id);
            }
        }
        out
    }

    /// Request stray shutdown through its API socket, then remove its files.
    /// No persisted PID identity is available, so this path sends no process signal.
    pub(crate) async fn end_stray_vm(&self, id: &VmId) -> hypervisor::Result<()> {
        // Remove files only after shutdown is acknowledged; retain the socket on
        // failure so a surviving VMM remains reachable.
        self.api(id, Method::PUT, "vmm.shutdown", None).await?;
        self.remove_files(id);
        Ok(())
    }

    /// Take a VMM this driver did not start back into the map, after an agent
    /// restart that outlived it.
    pub(crate) async fn adopt_vm(&self, id: &VmId, pid: u32) -> hypervisor::Result<()> {
        if self.vms.lock().unwrap().contains_key(id) {
            return Ok(()); // idempotent, and an Owned entry is never overwritten
        }
        // Require both socket responsiveness and matching process identity before
        // adoption; later destroy operations may signal the adopted PID.
        if !self.owns_pid(id, pid) {
            return Err(HypervisorError::Backend(anyhow::anyhow!(
                "pid {pid} is not this vm's vmm any more, cannot adopt it"
            )));
        }
        if !self.probe(id).await {
            return Err(HypervisorError::Backend(anyhow::anyhow!(
                "vmm api not responsive, cannot adopt"
            )));
        }
        self.vms.lock().unwrap().insert(
            *id,
            RunningVm {
                process: VmProcess::Adopted { pid },
                // Adoption requires a responsive API and does not reconstruct the
                // receiving marker. An in-flight transfer may outlive the agent.
                receiving: None,
                // Retain the event path so outcomes recorded while the agent was absent
                // remain available to observation.
                events: Some(self.event_path(id)),
                receive_answer: Default::default(),
            },
        );
        info!("adopted running vmm");
        Ok(())
    }
}

/// Build VMM arguments separately so receiver event-monitor configuration can be tested.
pub(crate) fn vmm_args(socket: &Path, events: Option<&Path>) -> Vec<String> {
    let mut args = vec![
        "--api-socket".to_string(),
        socket.display().to_string(),
        // Enable seccomp explicitly instead of relying on an upstream default.
        "--seccomp".to_string(),
        "true".to_string(),
    ];
    if let Some(path) = events {
        args.push("-v".to_string());
        args.push("--event-monitor".to_string());
        args.push(format!("path={}", path.display()));
    }
    args
}
