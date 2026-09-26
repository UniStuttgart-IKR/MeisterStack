// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! HTTP requests over each VMM's Unix socket, plus migration and unplug
//! observations. API acknowledgement is distinct from completed device removal
//! or transfer; those operations require additional evidence.

use super::*;

impl CloudHypervisorDriver {
    pub(crate) async fn api(
        &self,
        id: &VmId,
        method: Method,
        endpoint: &str,
        body: Option<serde_json::Value>,
    ) -> hypervisor::Result<Bytes> {
        let socket = self.vm_socket_path(id);
        ch_api(&socket, method, endpoint, body, self.ch_timeout)
            .await
            .map_err(HypervisorError::Backend)
    }

    /// What state the guest is in, as this VMM answers it.
    pub(crate) async fn state(&self, id: &VmId) -> hypervisor::Result<VmState> {
        self.vm_known(id)?;
        // The receive operation blocks the API socket. Use events until it ends;
        // without completion evidence, report Defined rather than a running guest.
        if let Some(events) = self.receiving_events(id) {
            match receive_outcome(&events) {
                None => return Ok(VmState::Defined),
                Some(Ok(())) => {
                    self.arrived(id);
                    info!("migration received; the guest is ours");
                }
                Some(Err(said)) => {
                    // The event reports receive failure. It does not independently establish
                    // whether the source still owns a running guest.
                    self.arrived(id);
                    return Err(HypervisorError::Backend(anyhow::anyhow!(
                        "receiving the migration failed: {said}"
                    )));
                }
            }
        }
        let bytes = self.api(id, Method::GET, "vm.info", None).await?;
        let info: serde_json::Value =
            serde_json::from_slice(&bytes).map_err(|e| HypervisorError::Backend(e.into()))?;

        match info.get("state").and_then(|s| s.as_str()).unwrap_or("") {
            "Created" => Ok(VmState::Defined),
            "Running" => Ok(VmState::Running),
            "Paused" => Ok(VmState::Paused),
            "Shutdown" => Ok(VmState::Stopped),
            other => Err(HypervisorError::Backend(anyhow::anyhow!(
                "unknown Cloud-Hypervisor state: {other}"
            ))),
        }
    }

    /// Start a receiver and return its PID after the readiness event.
    pub(crate) async fn receive_migration(&self, id: &VmId, peer: &str) -> hypervisor::Result<u32> {
        // Remove the serial socket path expected by the incoming config.
        // Source and destination must use compatible run-directory paths.
        let _ = std::fs::remove_file(self.serial_socket_path(id));
        let events = self.event_path(id);
        let process = self.spawn_vmm(id, Some(&events)).await?;
        let pid = process
            .id()
            .ok_or_else(|| HypervisorError::Backend(anyhow::anyhow!("the vmm has no pid")))?;
        let answer: std::sync::Arc<std::sync::Mutex<Option<String>>> = Default::default();
        self.vms.lock().unwrap().insert(
            *id,
            RunningVm {
                process: VmProcess::Owned(process),
                receiving: Some(events.clone()),
                events: Some(events.clone()),
                receive_answer: answer.clone(),
            },
        );

        // The receive HTTP call completes after the transfer, while this method
        // returns when listening is reported. Retain API errors for later observation.
        // Currently transport failures and timeouts are stored like explicit
        // receive errors; they do not independently prove the receiver has stopped.
        let socket = self.vm_socket_path(id);
        let body = serde_json::json!({ "receiver_url": peer });
        let timeout = self.ch_timeout;
        tokio::spawn(async move {
            // A generous ceiling of its own: the driver's ordinary API
            // timeout is sized for a question, and this is a file transfer.
            if let Err(e) = ch_api(
                &socket,
                Method::PUT,
                "vm.receive-migration",
                Some(body),
                timeout.max(Duration::from_secs(600)),
            )
            .await
            {
                let said = format!("{e:#}");
                warn!(error = %said, "vm.receive-migration returned an error");
                *answer.lock().unwrap() = Some(said);
            }
        });

        for _ in 0..200 {
            if listening(&events) {
                debug!(pid, "listening for the migration stream");
                return Ok(pid);
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        // The caller tears down a receiver that never reports readiness.
        Err(HypervisorError::Backend(anyhow::anyhow!(
            "cloud-hypervisor never reported migration-receive-ready on {peer}"
        )))
    }
}

/// Interval between hot-unplug completion probes.
pub(crate) const UNPLUG_POLL: Duration = Duration::from_millis(200);

/// Read disk presence from `vm.info`. Missing config yields None, which
/// cannot establish removal; config without a disks list means no disks.
pub(crate) fn disk_gone(info: &serde_json::Value, disk_id: &str) -> Option<bool> {
    let config = info.get("config")?;
    match config.get("disks") {
        None | Some(serde_json::Value::Null) => Some(true),
        Some(serde_json::Value::Array(disks)) => Some(
            !disks
                .iter()
                .any(|d| d.get("id").and_then(serde_json::Value::as_str) == Some(disk_id)),
        ),
        Some(_) => None,
    }
}

/// Poll until the disk is absent from config and no available fd witness
/// reports it open. Expiry returns an error; it does not establish future failure.
pub(crate) async fn until_the_disk_is_gone<F, Fut, H>(
    disk_id: &str,
    mut info: F,
    mut held: H,
    timeout: Duration,
    poll: Duration,
) -> hypervisor::Result<()>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = hypervisor::Result<serde_json::Value>>,
    H: FnMut() -> hypervisor::Result<Option<bool>>,
{
    let deadline = tokio::time::Instant::now() + timeout;
    let mut asked = 0u32;
    loop {
        asked += 1;
        let seen = info().await?;
        match disk_gone(&seen, disk_id) {
            // Configuration removal can precede guest release. Use the fd witness
            // when available; otherwise only the configuration check is possible.
            Some(true) => match held()? {
                Some(true) => {}
                _ => {
                    debug!(asked, "the vmm has let the disk go");
                    return Ok(());
                }
            },
            Some(false) => {}
            None => {
                return Err(HypervisorError::Backend(anyhow::anyhow!(
                    "cloud hypervisor's vm.info does not say which disks this vm has, so \
                     whether {disk_id} was unplugged cannot be established"
                )));
            }
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(HypervisorError::Backend(anyhow::anyhow!(
                "the guest has not let go of {disk_id} after {timeout:?}: the vmm still has it \
                 open. A virtio unplug needs the guest to cooperate, and this one has not; the \
                 volume stays attached"
            )));
        }
        tokio::time::sleep(poll).await;
    }
}

/// Check `/proc/<pid>/fd` for the disk's canonical path, resolving symlinks.
/// A missing process holds no descriptors and returns false.
pub(crate) fn vmm_holds(pid: u32, path: &Path) -> hypervisor::Result<bool> {
    let real = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    let table = PathBuf::from(format!("/proc/{pid}/fd"));
    let entries = match std::fs::read_dir(&table) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(e) => {
            return Err(HypervisorError::Backend(anyhow::anyhow!(
                "reading {}: {e}",
                table.display()
            )));
        }
    };
    for entry in entries.flatten() {
        let Ok(target) = std::fs::read_link(entry.path()) else {
            continue;
        };
        let target = target.to_string_lossy();
        let target = target.strip_suffix(" (deleted)").unwrap_or(&target);
        if Path::new(target) == real {
            return Ok(true);
        }
    }
    Ok(false)
}

impl CloudHypervisorDriver {
    /// Current file-backed disk path from `vm.info`. Missing disks and
    /// socket-backed attachments return None.
    pub(crate) async fn disk_path(
        &self,
        id: &VmId,
        disk_id: &str,
    ) -> hypervisor::Result<Option<PathBuf>> {
        let bytes = self.api(id, Method::GET, "vm.info", None).await?;
        let info: serde_json::Value =
            serde_json::from_slice(&bytes).map_err(|e| HypervisorError::Backend(e.into()))?;
        Ok(info
            .get("config")
            .and_then(|c| c.get("disks"))
            .and_then(serde_json::Value::as_array)
            .and_then(|disks| {
                disks
                    .iter()
                    .find(|d| d.get("id").and_then(serde_json::Value::as_str) == Some(disk_id))
            })
            .and_then(|d| d.get("path"))
            .and_then(serde_json::Value::as_str)
            .map(PathBuf::from))
    }
}

/// Read receive completion or failure markers from the append-only event file.
/// No recognized marker yields None. Substring matching tolerates a partially
/// written trailing JSON event.
pub(crate) fn receive_outcome(events: &Path) -> Option<Result<(), String>> {
    let text = std::fs::read_to_string(events).unwrap_or_default();
    if text.contains("migration-receive-finished") {
        return Some(Ok(()));
    }
    if text.contains("migration-receive-failed") {
        return Some(Err(
            "cloud-hypervisor reported migration-receive-failed".into()
        ));
    }
    None
}

/// Read the readiness event emitted before accept. Connecting to probe the
/// port would consume the single connection intended for the migration source.
pub(crate) fn listening(events: &Path) -> bool {
    std::fs::read_to_string(events)
        .unwrap_or_default()
        .contains("migration-receive-ready")
}

/// Use a fresh connection for each request so probes do not reuse a socket
/// connection to an earlier VMM instance at the same path.
#[instrument(level = "trace", skip(socket, body, ch_timeout), fields(%endpoint))]
async fn ch_api(
    socket: &Path,
    method: Method,
    endpoint: &str,
    body: Option<serde_json::Value>,
    ch_timeout: Duration,
) -> anyhow::Result<Bytes> {
    tokio::time::timeout(ch_timeout, async move {
        // times out after ch_timeout
        let stream = UnixStream::connect(socket)
            .await
            .with_context(|| format!("connect {}", socket.display()))?;
        let (mut sender, conn) =
            hyper::client::conn::http1::handshake(TokioIo::new(stream)).await?;
        tokio::spawn(async move {
            let _ = conn.await;
        });

        let payload = match &body {
            Some(v) => Bytes::from(serde_json::to_vec(v)?),
            None => Bytes::new(),
        };
        let req = Request::builder()
            .method(method)
            .uri(format!("/api/v1/{endpoint}"))
            .header("Host", "localhost")
            .header("Content-Type", "application/json")
            .body(Full::new(payload))?;

        let res = sender.send_request(req).await?;
        let status = res.status();
        let bytes = res.into_body().collect().await?.to_bytes();
        if !status.is_success() {
            bail!(
                "ch {endpoint} -> {status}: {}",
                String::from_utf8_lossy(&bytes)
            );
        }
        Ok(bytes)
    })
    .await
    .with_context(|| format!("ch {endpoint} timeout"))?
}

impl CloudHypervisorDriver {
    /// Inspect current VMM config for descriptor-backed NICs, including adopted
    /// VMs started under an earlier agent configuration. Absent NICs or unreadable
    /// JSON return false; API request errors propagate.
    pub(crate) async fn has_fd_nic(&self, id: &VmId) -> hypervisor::Result<bool> {
        let bytes = self.api(id, Method::GET, "vm.info", None).await?;
        let info: serde_json::Value = match serde_json::from_slice(&bytes) {
            Ok(info) => info,
            Err(e) => {
                warn!(error = %e, "vm.info is not a document this driver can read");
                return Ok(false);
            }
        };
        Ok(info
            .get("config")
            .and_then(|c| c.get("net"))
            .and_then(serde_json::Value::as_array)
            .is_some_and(|nets| {
                nets.iter()
                    .any(|n| n.get("fds").is_some_and(|f| !f.is_null()))
            }))
    }
}
