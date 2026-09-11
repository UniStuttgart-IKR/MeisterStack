// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Sprechen mit dem VMM: der HTTP-Client auf dem Unix-Socket, und die zwei
//! Stellen, an denen die Antwort nicht die Wahrheit ist.
//!
//! Two of the calls here do not mean what their status code says, and both
//! cost a lab run to find out. A hot-unplug answers 200 when the guest has
//! merely been ASKED (`until_the_disk_is_gone`), and a receive-migration
//! blocks inside the request handler and states its outcome in the event file
//! instead (`receive_outcome`). Everything else is one request, one answer.
//!
//! Moved out of `lib.rs` unchanged.

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
        // A VMM in the middle of receiving a migration will not answer, and
        // asking it anyway is how the agent would decide its VMM is broken
        // and kill the process the guest is arriving into. So the event file
        // is asked instead, and the honest answer until it says otherwise is
        // `Defined`: the VM exists here and is not running here yet.
        if let Some(events) = self.receiving_events(id) {
            match receive_outcome(&events) {
                None => return Ok(VmState::Defined),
                Some(Ok(())) => {
                    self.arrived(id);
                    info!("migration received; the guest is ours");
                }
                Some(Err(said)) => {
                    // The stream failed. The source is still running — that
                    // is v53's own behaviour on a failed send — so this VMM
                    // holds nothing and saying so is what lets the tier above
                    // tear it down.
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

    /// Stand up a VMM that is listening for a guest on its way, and return
    /// its pid once it says it is listening. The trait method is where this
    /// is argued.
    pub(crate) async fn receive_migration(&self, id: &VmId, peer: &str) -> hypervisor::Result<u32> {
        // The path the arriving config will name, derived the same way the
        // source derived it — which is only the same string if both nodes
        // have the same run_dir, and that is the requirement above.
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

        // Into a task, because the answer does not come back until the whole
        // migration has run. Nothing WAITS on the handle — this call returns
        // as soon as the listener is up — but the answer is kept, because it
        // is the only statement of a reception that ended badly that always
        // exists. See `RunningVm::receive_answer`: the event file has one
        // hole in it and this is what covers it.
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
        // Never became ready. The VMM is torn down by the caller's error
        // path; leaving a process listening on a port nobody will dial is
        // worse than the failure itself.
        Err(HypervisorError::Backend(anyhow::anyhow!(
            "cloud-hypervisor never reported migration-receive-ready on {peer}"
        )))
    }
}

/// How often `vm.info` is asked in the meantime. The whole answer arrives in
/// one small JSON document over a unix socket, so this is cheap enough to be
/// frequent and slow enough not to be a spin.
pub(crate) const UNPLUG_POLL: Duration = Duration::from_millis(200);

/// Whether this `vm.info` document still lists `disk_id`.
///
/// `None` = the document does not say, which is not the same as "gone" and is
/// the one answer that must not be read as success. A `vm.info` without a
/// `config` object is a cloud hypervisor this driver does not understand, and
/// treating silence as evidence is precisely the mistake being repaired here.
/// A `config` with no `disks` at all IS evidence: the VMM lists what it has.
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

/// Ask until the disk is gone, or until the deadline says it is not going to
/// be.
///
/// Takes the question rather than the socket so that the waiting is testable
/// without a VMM: what is worth pinning down is that a disk which disappears
/// late still counts as removed, and that one which never disappears is an
/// error with a sentence instead of a success.
pub(crate) async fn until_the_disk_is_gone<F, Fut>(
    disk_id: &str,
    mut info: F,
    timeout: Duration,
    poll: Duration,
) -> hypervisor::Result<()>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = hypervisor::Result<serde_json::Value>>,
{
    let deadline = tokio::time::Instant::now() + timeout;
    let mut asked = 0u32;
    loop {
        asked += 1;
        let seen = info().await?;
        match disk_gone(&seen, disk_id) {
            Some(true) => {
                debug!(asked, "the vmm has let the disk go");
                return Ok(());
            }
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

/// What the event file says about a receive, if it has said anything.
///
/// `None` = still going. The three states are exactly the three events v53
/// writes around `vm_receive_migration`, and the file is append-only with
/// `\n\n` between JSON blobs, so a substring search is the whole parser this
/// needs — and is robust against a partially written last blob, which a
/// `serde_json` pass over the file would not be.
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

/// Whether the listener is up yet, asked the only way that does not consume
/// the connection the source is about to make.
///
/// `migration-receive-ready` is emitted immediately BEFORE `listener.accept()`
/// (v53 `vmm/src/lib.rs`), so it is precisely "the port is bound and nobody
/// has been accepted". Probing the port instead would work exactly once and
/// then eat the source's connection.
pub(crate) fn listening(events: &Path) -> bool {
    std::fs::read_to_string(events)
        .unwrap_or_default()
        .contains("migration-receive-ready")
}

/// One request, one connection: connect, handshake, send, read, drop.
///
/// Deliberately not pooled. A pooled connection would outlive the VMM it
/// points at — `destroy` unlinks the socket and a re-provisioned VM binds a
/// new one at the same path — and `probe` would then answer "alive" out of a
/// half-open connection to a process that is gone, which is the one question
/// it exists to answer. Statelessness is what makes it a liveness check.
///
/// The price was measured rather than guessed: 60 us per call in a release
/// build over a unix socket (the HTTP/1 handshake does no round trip, it only
/// allocates). A converged VM costs about 20 calls a minute — two probes and
/// two state reads per 30 s reconcile pass, two more per 10 s status report —
/// so a node with a hundred VMs spends roughly 0.2 % of one core here.
/// Pooling could take back half of that. It is not worth the stale socket.
// tracing here via ENV: RUST_LOG=cloud_hypervisor_driver=trace
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
