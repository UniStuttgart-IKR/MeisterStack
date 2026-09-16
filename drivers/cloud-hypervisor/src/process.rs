// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Fuehren des VMM-Prozesses: starten, uebernehmen, umbringen.
//!
//! Everything in this file is about the process and the files beside it —
//! where its socket, its logs and its event file live, how it is started, and
//! the two ways the driver comes to hold one (spawned here, or found again
//! after a restart). What it does NOT do is talk to it: that is `api`.
//!
//! Moved out of `lib.rs` unchanged.

use super::*;

/// What separates a torn-down VMM's log from the id it belonged to.
///
/// A suffix and not a directory, so that one `socket_dir` is still the whole
/// of what this driver owns and `vm logs` finds these beside the live one.
pub(crate) const KEPT_LOG: &str = ".log.gone-";

/// How long a torn-down VMM's log is kept.
///
/// An hour: longer than anybody debugging a migration that did not happen
/// takes to look, and short enough that a node churning VMs all day carries
/// nothing. See `sweep_kept_logs`.
const KEPT_LOG_TTL: std::time::Duration = std::time::Duration::from_secs(3600);

pub(crate) enum VmProcess {
    Owned(Child),
    Adopted { pid: u32 },
}

pub(crate) struct RunningVm {
    pub(crate) process: VmProcess,
    /// This VMM is receiving a migration, and the API socket is not going to
    /// answer until it has finished.
    ///
    /// `vm.receive-migration` runs the whole protocol INSIDE the request
    /// handler (v53 `vmm/src/lib.rs`, `vm_receive_migration`), so the
    /// destination's API is unresponsive for the duration — a `vm.info` on it
    /// blocks and then times out. Without this flag the agent's reconciler
    /// would read that timeout as a broken VMM and kill the very process the
    /// guest is arriving into.
    ///
    /// What clears it is the event file, which is why it holds one: cloud
    /// hypervisor writes `migration-receive-finished` (or `-failed`) to
    /// `--event-monitor path=...`, and that is the only place either outcome
    /// is stated. See `receive_outcome`.
    pub(crate) receiving: Option<PathBuf>,
    /// This VMM's event file, for as long as this VMM lives.
    ///
    /// Beside `receiving` and not the same field, because the two are
    /// cleared by different things and one of them must not be cleared at
    /// all. `receiving` says "the api will not answer, read the file
    /// instead" and comes off the moment the file has said anything;
    /// `events` says where that file IS, and it has to outlive the answer —
    /// a receive that FAILED is a fact the reconciler asks about on every
    /// pass afterwards, until it has given the VMM back.
    ///
    /// `None` for a VMM that was started without `--event-monitor`, which is
    /// every VM that boots here.
    pub(crate) events: Option<PathBuf>,
    /// What the blocking `vm.receive-migration` call answered, once it has
    /// answered at all.
    ///
    /// The event file cannot carry this one, and it took a live v53 to find
    /// out why. `vm_receive_migration` writes `migration-receive-failed` only
    /// where a COMMAND handler failed; a request it could not read at all —
    /// which is what a source that dies mid-stream leaves — takes the `?` out
    /// of the whole function and past the `match state` that writes the
    /// event. Measured: connect to the port, send something that is not a
    /// request, hang up, and the file stops at `migration-receive-started`
    /// for ever while the api call answers
    /// `["Error receiving migration", …, "received request with unknown
    /// command"]`.
    ///
    /// So the answer to that call is kept, which is the one place every
    /// failed reception is stated. Shared with the task that makes the call
    /// rather than written back into this map, because the task outlives the
    /// borrow that spawned it.
    pub(crate) receive_answer: std::sync::Arc<Mutex<Option<String>>>,
}

impl CloudHypervisorDriver {
    pub(crate) fn vm_socket_path(&self, id: &VmId) -> PathBuf {
        self.socket_dir.join(format!("{id}.sock"))
    }

    /// The guest's own two output files, named once. `create` builds the VM
    /// config from these and `console_paths` hands them to the agent, so
    /// there is one spelling of where they are rather than two that can drift.
    pub(crate) fn console_path(&self, id: &VmId, stream: ConsoleStream) -> PathBuf {
        self.socket_dir.join(format!("{id}.{}", stream.as_str()))
    }

    /// Where cloud-hypervisor's OWN stdout and stderr go — the VMM's
    /// diagnostics, not the guest's. Not part of `console_paths`: it is not
    /// the guest's output and `vm logs` must not mix the two.
    pub(crate) fn vmm_log_path(&self, id: &VmId) -> PathBuf {
        self.socket_dir.join(format!("{id}.log"))
    }

    /// What a torn-down VMM's log is renamed to, so that it survives long
    /// enough to be read.
    ///
    /// D-P19, and it is two fixes of one round cancelling each other out:
    /// `-v` was turned on for the receiving VMM to get one line out of it,
    /// and the tidy-up that removes a VM's files takes that log away the
    /// moment the reception is given back. So `vm logs --streams vmm` could
    /// never show a receiving VMM at all — the one case the flag was turned
    /// on for. The lab had to catch it with a 0.2-second watcher on the file.
    ///
    /// The seconds are in the name because a VM id can be torn down twice — a
    /// reception that failed, then one that worked — and the second must not
    /// silently replace the evidence of the first.
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

    /// Keep what this VMM said, instead of throwing it away with everything
    /// else the driver made for it.
    ///
    /// An empty log is removed rather than kept: a VMM that printed nothing
    /// leaves nothing worth a filename, and keeping one per VM id that ever
    /// existed is the leak the tidy-up was written to end.
    ///
    /// The sweep runs here and nowhere else, which is the cheapest honest
    /// place: one `read_dir` per teardown, and a node that never tears a VM
    /// down has nothing to sweep.
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
            // Nothing said, or nothing there. Either way there is no evidence
            // to keep and the file goes as it always did.
            _ => {
                let _ = std::fs::remove_file(&live);
            }
        }
        self.sweep_kept_logs();
    }

    /// Kept logs older than [`KEPT_LOG_TTL`], of any VM.
    ///
    /// Bounded by time and not by count, because what it is protecting
    /// against is the same thing every other sweep in this tree is: a
    /// directory that gains one file per VM id that ever existed. An hour is
    /// longer than anybody debugging a failed migration takes to look and
    /// short enough that a node churning VMs all day carries nothing.
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

    /// Where the serial line listens for the one client that may type into
    /// it. Beside the file it is recorded into, one suffix apart, so the two
    /// names cannot drift — the agent derives one from the other.
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

    /// Why a guest that was on its way here is not coming, if this VMM's
    /// event file says so.
    ///
    /// Read off the file every time rather than remembered, for the reason
    /// everything else in the reconcile path is: the file is the only party
    /// that knows, it survives the answer being read, and it survives the
    /// agent that read it. `destroy_vm` takes it away with the rest.
    pub(crate) fn receive_failure(&self, id: &VmId) -> Option<String> {
        let (answered, events) = {
            let vms = self.vms.lock().unwrap();
            let vm = vms.get(id)?;
            (vm.receive_answer.lock().unwrap().clone(), vm.events.clone())
        };
        // The call's own answer first: it covers every failure, including the
        // ones the event file is silent about. The file is asked as well,
        // because it is the half that survives the agent — an adopted VMM has
        // no task and no answer, and a `migration-receive-failed` in its file
        // is the ghost of the lab.
        if let Some(said) = answered {
            return Some(said);
        }
        match receive_outcome(&events?) {
            Some(Err(said)) => Some(said),
            _ => None,
        }
    }

    /// Where cloud hypervisor writes its structured events for this VM.
    ///
    /// Only a receiving VMM is started with `--event-monitor`, and only
    /// because of what `vm.receive-migration` is: a blocking call whose
    /// SUCCESS is not the HTTP answer (that comes at the end) but the moment
    /// it started listening — and whose outcome nothing else on this machine
    /// states. Every other VM here answers questions over its API socket and
    /// needs no second channel.
    pub(crate) fn event_path(&self, id: &VmId) -> PathBuf {
        self.socket_dir.join(format!("{id}.events"))
    }

    /// Start a VMM process for `id` and wait for its API to answer.
    ///
    /// Lifted out of `create` when `migrate_in` needed the same eleven lines
    /// with one argument different — and the difference matters, because a
    /// receiving VMM must be started with **no VM at all**: v53 refuses
    /// `vm.receive-migration` outright when one has been created
    /// ("Can't receive a migration when a VM is already created"), and builds
    /// the destination's VM from the config that arrives in the stream.
    ///
    /// # Why a receiving VMM runs at INFO and a booting one does not
    ///
    /// Because a reception is the one thing v53 refuses to explain when it
    /// fails, and the lab paid for that twice. Its abort line is
    ///
    /// ```text
    /// Migration aborted as migration command State failed: Failed to
    /// receive migratable component snapshot
    /// ```
    ///
    /// and that sentence is the whole of a `thiserror` variant's own
    /// `Display` — the `#[source]` beneath it, which is the anyhow chain
    /// naming the component that refused, is not printed
    /// (`vmm/src/lib.rs`, the `warn!` in `vm_receive_migration`; the SEND
    /// side of the same file does flatten its chain). The error handed back
    /// to the api caller is worse still: `"Migration was aborted"`.
    ///
    /// What DOES name it is the restore itself, at INFO, one line per
    /// component in the order they are rebuilt — measured on this v53:
    ///
    /// ```text
    /// Creating virtio-block device: DiskConfig { … image_type: Raw … }
    /// Opening RAW disk file with io_uring backend
    /// Restoring virtio-block disk0
    /// Restoring virtio-rng __rng
    /// Restoring virtio-pci _virtio-pci-disk0 resources
    /// Acquired Write lock for disk image id=disk0,path=…
    /// ```
    ///
    /// so the last of those before the abort is the answer. One flag on the
    /// one process that needs it, into the file `vm logs --stream vmm`
    /// already reads and the reconcile pass already trims. A booting VMM
    /// stays quiet: its failures come back on the api call that caused them.
    pub(crate) async fn spawn_vmm(
        &self,
        id: &VmId,
        events: Option<&Path>,
    ) -> hypervisor::Result<Child> {
        let log = std::fs::File::create(self.vmm_log_path(id))
            .map_err(|e| HypervisorError::Backend(e.into()))?;
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
        let mut process = command
            .stdin(Stdio::null())
            .stdout(Stdio::from(log))
            .stderr(Stdio::from(log2))
            .spawn()
            .map_err(|e| HypervisorError::Backend(e.into()))?;
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

    /// A VMM with this VM defined in it, in its slice, not yet booted.
    ///
    /// The pid comes back rather than being kept alone, because the record one
    /// tier up is what survives this process — see `adopt_vm`.
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

        let config = build_vm_config(spec, &console_path, &serial_socket)?;
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

        if let Err(e) = self.api(id, Method::PUT, "vmm.shutdown", None).await {
            debug!(error = %format!("{e:#}"), "vmm.shutdown failed, killing process anyway");
        }

        match vm.process {
            VmProcess::Owned(mut child) => {
                let _ = child.kill().await;
            }
            // Not our child: the agent restarted since `create`, and the
            // recorded pid is the only handle left. It is checked before it
            // is signalled, and this is the sharpest case in the tree for
            // why: the record survives the process, the kernel hands the
            // number out again, and what happens here is a SIGKILL. A VM
            // whose VMM died and whose pid was reused would take a stranger
            // with it on the next teardown.
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

    /// Everything this driver put in the run directory for one VM.
    ///
    /// One function and two callers — `destroy_vm` and `end_stray_vm` — so
    /// that "what a VM leaves behind" is written once. Until the tidy-up
    /// existed at all, the two console files, the api socket, its lock and
    /// the VMM's own log stayed behind for ever, one set per vm id that had
    /// ever run on the node: nothing in the tree read them, nothing rotated
    /// them and nothing removed them.
    ///
    /// The VMM's own log is the exception and is KEPT — see `keep_the_log`,
    /// and D-P19 for what removing it cost.
    ///
    /// Every removal is best effort. A file that is already gone is the
    /// ordinary case — a VM that never started has none of these — and a
    /// teardown must not fail over one.
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

    /// Every VMM answering in this driver's run directory that `known` does
    /// not name.
    ///
    /// The socket file is the candidate and the ANSWER is the evidence. A
    /// `<uuid>.sock` on its own proves nothing — a killed VMM leaves one
    /// behind, and `destroy_vm` removing them is the only reason the
    /// directory is not full of them — so each one is pinged, and a stray is
    /// a socket that talks back.
    ///
    /// Read off the filesystem and not off `self.vms`, which is the whole
    /// point: the map is empty after a restart, and a restart is when this
    /// question matters.
    ///
    /// Sorted, so two consecutive passes over the same machine produce the
    /// same list and the sentence on the node's condition does not shuffle.
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

    /// Ask a VMM nobody has a record of to go, and take its files with it.
    ///
    /// `vmm.shutdown` and no signal, deliberately. This driver has no pid for
    /// a stray and must not go looking for one: a pid is not an identity, the
    /// kernel hands numbers out again, and the act at the end of a wrong
    /// answer here would be a SIGKILL at a stranger. The socket is the safe
    /// handle — it reaches, by construction, exactly the process that answers
    /// for this id in this agent's run directory.
    ///
    /// The files go afterwards, the same set `destroy_vm` removes and for the
    /// same reason: they are this driver's, in this driver's directory, and
    /// nothing else will ever collect them.
    pub(crate) async fn end_stray_vm(&self, id: &VmId) -> hypervisor::Result<()> {
        // The files go only AFTER the process has agreed to. A VMM that did
        // not answer is a VMM that is still there, and removing its socket
        // would leave a live process nothing can ever reach again.
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
        // Both questions, and they are different questions. The socket says
        // "something is serving this VM's api"; the pid says "and it is the
        // process the record names". Adopting on the socket alone would
        // write a stranger's pid into the driver's map, and `destroy` signals
        // what is in that map.
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
                // A VMM found again after an agent restart is not receiving
                // anything: a migration that was in flight died with the
                // agent, and the guest is either fully arrived or not there.
                receiving: None,
                // The file, though, is where it always was, and it is the
                // only description left of a transfer that ran while nobody
                // was watching. An adopted VMM that has `migration-receive-
                // failed` in it is exactly the ghost of the lab: a process
                // holding a disk for a guest that is running elsewhere.
                events: Some(self.event_path(id)),
                receive_answer: Default::default(),
            },
        );
        info!("adopted running vmm");
        Ok(())
    }
}

/// The command line a VMM is started with.
///
/// Its own function so that the one argument nobody would guess — see
/// `spawn_vmm` on why a receiving VMM speaks and a booting one does not —
/// can be asserted without a process to spawn.
pub(crate) fn vmm_args(socket: &Path, events: Option<&Path>) -> Vec<String> {
    let mut args = vec!["--api-socket".to_string(), socket.display().to_string()];
    if let Some(path) = events {
        args.push("-v".to_string());
        args.push("--event-monitor".to_string());
        args.push(format!("path={}", path.display()));
    }
    args
}
