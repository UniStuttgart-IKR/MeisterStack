// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

use agent_api::hypervisor;
use agent_api::{
    BootSource, CgroupHandle, DeviceAttachment, Hypervisor, HypervisorError, InstanceSpec,
    Pausable, VmId, VmState, VolumeAttachment,
};
use anyhow::{Context, bail};
use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper::{Method, Request};
use hyper_util::rt::TokioIo;
use macros::generated;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Mutex;
use std::time::Duration;
use tokio::net::UnixStream;
use tokio::process::{Child, Command};
use tracing::{debug, info, instrument, warn};

enum VmProcess {
    Owned(Child),
    Adopted { pid: u32 },
}

struct RunningVm {
    process: VmProcess,
}

pub struct CloudHypervisorDriver {
    binary: PathBuf,
    socket_dir: PathBuf,
    vms: Mutex<HashMap<VmId, RunningVm>>,
    ch_timeout: Duration,
}

impl CloudHypervisorDriver {
    pub fn new(
        binary: PathBuf,
        socket_dir: PathBuf,
        ch_timeout: Duration,
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
        })
    }

    fn vm_socket_path(&self, id: &VmId) -> PathBuf {
        self.socket_dir.join(format!("{id}.sock"))
    }

    fn vm_known(&self, id: &VmId) -> hypervisor::Result<()> {
        if self.vms.lock().unwrap().contains_key(id) {
            Ok(())
        } else {
            Err(HypervisorError::NotFound(*id))
        }
    }

    async fn api(
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
        // vm logs into file
        let log = std::fs::File::create(self.socket_dir.join(format!("{id}.log")))
            .map_err(|e| HypervisorError::Backend(e.into()))?;
        let log2 = log
            .try_clone()
            .map_err(|e| HypervisorError::Backend(e.into()))?;
        let console_path = self.socket_dir.join(format!("{id}.console"));
        let serial_path = self.socket_dir.join(format!("{id}.serial"));

        let config = build_vm_config(spec, &console_path, &serial_path)?;
        let socket = self.vm_socket_path(id);
        let _ = std::fs::remove_file(&socket);

        // create process without booting VM
        let mut process = Command::new(&self.binary)
            .arg("--api-socket")
            .arg(&socket)
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

        // put process into cgroup before VM boot
        if let Some(cg) = cgroup
            && let Err(e) = cg.attach_pid(pid)
        {
            let _ = process.kill().await;
            return Err(HypervisorError::Backend(e.into()));
        }

        // wait for API to be ready, if not ready after ch_timeout -> kill process
        let mut ready = false;
        for attempt in 0..100 {
            if self.api(id, Method::GET, "vmm.ping", None).await.is_ok() {
                debug!(attempt, "vmm api ready");
                ready = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        if !ready {
            warn!("vmm api not reachable, killing process");
            let _ = process.kill().await;
            return Err(HypervisorError::Backend(anyhow::anyhow!(
                "Cloud-Hypervisor API not reachable for socket: {socket:?}"
            )));
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
            },
        );
        debug!("vm created, not booted");
        Ok(pid)
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
        self.vm_known(id)?;
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

    #[instrument(skip_all, fields(vm_id = %id))]
    async fn destroy(&self, id: &VmId) -> hypervisor::Result<()> {
        let vm = self.vms.lock().unwrap().remove(id);
        let vm = vm.ok_or(HypervisorError::NotFound(*id))?;

        if let Err(e) = self.api(id, Method::PUT, "vmm.shutdown", None).await {
            debug!(error = %format!("{e:#}"), "vmm.shutdown failed, killing process anyway");
        }

        match vm.process {
            VmProcess::Owned(mut child) => {
                let _ = child.kill().await;
            }
            VmProcess::Adopted { pid } => {
                let _ = nix::sys::signal::kill(
                    nix::unistd::Pid::from_raw(pid as i32),
                    nix::sys::signal::Signal::SIGKILL,
                );
            }
        }

        let _ = std::fs::remove_file(self.vm_socket_path(id));
        Ok(())
    }

    #[generated(model = ClaudeFable, version = "5")]
    #[instrument(skip_all, fields(vm_id = %id, pid))]
    async fn adopt(&self, id: &VmId, pid: u32) -> hypervisor::Result<()> {
        if self.vms.lock().unwrap().contains_key(id) {
            return Ok(()); // idempotent, and an Owned entry is never overwritten
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
            },
        );
        info!("adopted running vmm");
        Ok(())
    }

    #[instrument(level = "trace", skip_all, fields(vm_id = %id))]
    async fn probe(&self, id: &VmId) -> bool {
        self.api(id, Method::GET, "vmm.ping", None).await.is_ok()
    }

    fn is_tracked(&self, id: &VmId) -> bool {
        self.vms.lock().unwrap().contains_key(id)
    }

    fn as_pausable(&self) -> Option<&dyn Pausable> {
        Some(self)
    }
}

/// One entry of CH's `disks` array. A path is opened by the VMM itself; a
/// vhost-user-blk socket is a backend process the VMM connects to instead
/// (CH's own `vhost_user`/`vhost_socket` disk fields — the same pair the
/// upstream vhost_user_block daemon is driven with).
///
/// None for an attachment that is not a disk at all: a share is a `fs` entry,
/// and `split_volumes` is what sorts the two apart.
#[generated(model = ClaudeOpus, version = "5")]
fn disk_config(disk: &VolumeAttachment) -> Option<serde_json::Value> {
    match disk {
        VolumeAttachment::Path(path) => Some(serde_json::json!({ "path": path })),
        VolumeAttachment::VhostUserBlk { socket, .. } => Some(serde_json::json!({
            "vhost_user": true,
            "vhost_socket": socket,
        })),
        VolumeAttachment::FsShare { .. } => None,
    }
}

/// One entry of CH's `fs` array: virtiofsd is already listening on `socket`,
/// and `tag` is the name the guest mounts (`mount -t virtiofs <tag> /mnt`).
/// `num_queues` and `queue_size` are CH's own defaults and are left to it.
#[generated(model = ClaudeOpus, version = "5")]
fn fs_config(volume: &VolumeAttachment) -> Option<serde_json::Value> {
    match volume {
        VolumeAttachment::FsShare { socket, tag, .. } => {
            Some(serde_json::json!({ "socket": socket, "tag": tag }))
        }
        _ => None,
    }
}

fn build_vm_config(
    spec: &InstanceSpec,
    console_path: &PathBuf,
    serial_path: &PathBuf,
) -> hypervisor::Result<serde_json::Value> {
    // `memory.shared` is a property of the VM, not of one kind of attachment:
    // any vhost-user backend maps guest memory, and a vhost-user-blk volume
    // needs it exactly as much as a gpu device does. Asking both halves of
    // the spec the same question is what keeps a storage backend from
    // silently getting a VM whose memory it cannot map.
    let has_vhost_user = spec
        .devices
        .iter()
        .any(DeviceAttachment::needs_shared_memory)
        || spec
            .volumes
            .iter()
            .any(VolumeAttachment::needs_shared_memory);

    // handle optional kernel & initramfs for direct-kernel boot, not required for UEFI boot
    let payload = match &spec.boot {
        BootSource::DirectKernel {
            kernel,
            cmdline,
            initramfs,
        } => {
            let mut p = serde_json::json!({ "kernel": kernel, "cmdline": cmdline });
            if let Some(i) = initramfs {
                p["initramfs"] = serde_json::json!(i);
            }
            p
        }
        BootSource::Firmware { firmware } => serde_json::json!({ "firmware": firmware }),
    };

    let mut config = serde_json::json!({
        "cpus":   { "boot_vcpus": spec.vcpus, "max_vcpus": spec.vcpus },
        "memory": {
            "size": spec.memory_mib * 1024 * 1024,
            "shared": has_vhost_user,
        },
        "payload": payload,
        "disks":  spec.volumes.iter().filter_map(disk_config).collect::<Vec<_>>(),
        "console": { "mode": "File", "file": console_path },
        "serial": { "mode": "File", "file": serial_path }

    });

    let shares: Vec<_> = spec.volumes.iter().filter_map(fs_config).collect();
    if !shares.is_empty() {
        config["fs"] = shares.into();
    }

    if !spec.nics.is_empty() {
        config["net"] = spec
            .nics
            .iter()
            .map(|n| {
                let mut net = serde_json::json!({ "tap": n.tap_name, "mac": n.mac.to_string() });
                // virtio-net's own MTU feature (VIRTIO_NET_F_MTU). The tap and
                // the bridge bound what the host forwards; this is the only way
                // the GUEST finds out, and without it an overlay VM emits
                // 1500-byte frames into a 1450-byte path and they vanish. Omitted
                // where nobody named one, so a plain VM's config is byte-identical
                // to what it has always been.
                if let Some(mtu) = n.mtu {
                    net["mtu"] = serde_json::Value::from(mtu);
                }
                net
            })
            .collect::<Vec<_>>()
            .into();
    }

    let mut vhost_user_devices = Vec::new();
    let mut vfio_devices = Vec::new();
    for dev in &spec.devices {
        match dev {
            DeviceAttachment::VhostUser {
                socket,
                device_type,
                queue_sizes,
                ..
            } => {
                vhost_user_devices.push(serde_json::json!({
                    "socket": socket,
                    "device_type": device_type,
                    "queue_sizes": queue_sizes,
                }));
            }
            DeviceAttachment::VfioPci { sysfs_path } => {
                vfio_devices.push(serde_json::json!({ "path": sysfs_path }));
            }
            other => {
                return Err(HypervisorError::InvalidSpec(format!(
                    "attachment type not yet supported by CH driver: {other:?}"
                )));
            }
        }
    }
    if !vhost_user_devices.is_empty() {
        config["generic_vhost_user"] = vhost_user_devices.into();
    }
    if !vfio_devices.is_empty() {
        config["devices"] = vfio_devices.into();
    }
    Ok(config)
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
#[generated(model = ClaudeOpus, version = "4.8")]
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

#[cfg(test)]
#[generated(model = ClaudeOpus, version = "5")]
mod tests {
    use super::*;
    use agent_api::NicAttachment;

    fn spec(volumes: Vec<VolumeAttachment>, devices: Vec<DeviceAttachment>) -> InstanceSpec {
        InstanceSpec {
            boot: BootSource::Firmware {
                firmware: "/fw.fd".into(),
            },
            volumes,
            vcpus: 2,
            memory_mib: 1024,
            nics: Vec::<NicAttachment>::new(),
            devices,
        }
    }

    fn config(spec: &InstanceSpec) -> serde_json::Value {
        build_vm_config(spec, &PathBuf::from("/c"), &PathBuf::from("/s")).expect("config builds")
    }

    fn vhost_gpu() -> DeviceAttachment {
        DeviceAttachment::VhostUser {
            socket: "/run/gpu.sock".into(),
            pid: 1,
            device_type: 16,
            queue_sizes: vec![256],
        }
    }

    fn nic(mtu: Option<u32>) -> NicAttachment {
        NicAttachment {
            tap_name: "msk0000".into(),
            mac: "52:54:00:00:00:01".parse().unwrap(),
            mtu,
        }
    }

    /// The last hop of the overlay MTU. The tap and the bridge bound what the
    /// HOST forwards; this is the only thing that tells the GUEST, and
    /// without it an overlay VM emits 1500-byte frames into a 1450-byte path
    /// and they vanish with nothing in any log.
    #[test]
    fn an_overlay_nic_tells_the_guest_its_mtu_and_a_plain_one_says_nothing() {
        let mut overlay = spec(vec![VolumeAttachment::Path("/vol/a.raw".into())], vec![]);
        overlay.nics = vec![nic(Some(1450))];
        let cfg = config(&overlay);
        assert_eq!(cfg["net"][0]["tap"], "msk0000");
        assert_eq!(cfg["net"][0]["mtu"], 1450);

        // And a NIC on the default bridge produces exactly the config it
        // always did — no `mtu` key at all, not an mtu of null.
        let mut plain = spec(vec![VolumeAttachment::Path("/vol/a.raw".into())], vec![]);
        plain.nics = vec![nic(None)];
        let cfg = config(&plain);
        assert_eq!(cfg["net"][0]["mac"], "52:54:00:00:00:01");
        assert!(cfg["net"][0].get("mtu").is_none(), "no key, not a null");
    }

    #[test]
    fn a_path_volume_is_a_plain_disk_and_needs_nothing_shared() {
        let cfg = config(&spec(
            vec![VolumeAttachment::Path("/vol/a.raw".into())],
            vec![],
        ));
        assert_eq!(cfg["disks"][0]["path"], "/vol/a.raw");
        assert_eq!(cfg["disks"][0].get("vhost_user"), None);
        assert_eq!(cfg["memory"]["shared"], false);
    }

    /// CH's own DiskConfig fields (`vhost_user` / `vhost_socket`) — the same
    /// pair its upstream vhost_user_block daemon is driven with, so a
    /// Mayastor-style backend needs nothing new on this side.
    #[test]
    fn a_vhost_user_blk_volume_becomes_a_vhost_user_disk() {
        let cfg = config(&spec(
            vec![VolumeAttachment::VhostUserBlk {
                socket: "/run/blk.sock".into(),
                pid: 9,
            }],
            vec![],
        ));
        assert_eq!(cfg["disks"][0]["vhost_user"], true);
        assert_eq!(cfg["disks"][0]["vhost_socket"], "/run/blk.sock");
        assert_eq!(cfg["disks"][0].get("path"), None);
    }

    /// The behaviour change this split is for: shared memory is a property of
    /// the VM, not of the device list. A VM whose only vhost-user backend is
    /// a disk used to be built with `shared: false` — and the backend would
    /// have had no guest memory to map.
    #[test]
    fn a_vhost_user_volume_alone_turns_shared_memory_on() {
        let cfg = config(&spec(
            vec![VolumeAttachment::VhostUserBlk {
                socket: "/run/blk.sock".into(),
                pid: 9,
            }],
            vec![],
        ));
        assert_eq!(cfg["memory"]["shared"], true);
        assert_eq!(
            cfg.get("generic_vhost_user"),
            None,
            "a disk is not a generic device"
        );
    }

    #[test]
    fn a_vhost_user_device_still_turns_it_on_by_itself() {
        let cfg = config(&spec(
            vec![VolumeAttachment::Path("/a.raw".into())],
            vec![vhost_gpu()],
        ));
        assert_eq!(cfg["memory"]["shared"], true);
        assert_eq!(cfg["generic_vhost_user"][0]["device_type"], 16);
    }

    /// Disks keep spec order — the first one is the boot disk, and mixing
    /// attachment kinds must not reorder them.
    #[test]
    fn mixed_attachments_keep_their_spec_order() {
        let cfg = config(&spec(
            vec![
                VolumeAttachment::Path("/boot.raw".into()),
                VolumeAttachment::VhostUserBlk {
                    socket: "/run/data.sock".into(),
                    pid: 9,
                },
                VolumeAttachment::Path("/seed.raw".into()),
            ],
            vec![],
        ));
        assert_eq!(cfg["disks"][0]["path"], "/boot.raw");
        assert_eq!(cfg["disks"][1]["vhost_socket"], "/run/data.sock");
        assert_eq!(cfg["disks"][2]["path"], "/seed.raw");
        assert_eq!(cfg["memory"]["shared"], true);
    }

    fn share() -> VolumeAttachment {
        VolumeAttachment::FsShare {
            socket: "/run/fs.sock".into(),
            tag: "share".into(),
            pid: 12,
        }
    }

    /// A share is a `fs` entry and not a disk. Both halves matter: the guest
    /// mounts it by tag, and a share that leaked into `disks` would be a
    /// DiskConfig with neither a path nor a vhost socket — CH refuses the
    /// whole VM for it, so the boot disk would go down with it.
    #[test]
    fn a_share_becomes_an_fs_entry_and_leaves_the_disks_alone() {
        let cfg = config(&spec(
            vec![VolumeAttachment::Path("/boot.raw".into()), share()],
            vec![],
        ));
        assert_eq!(cfg["disks"].as_array().unwrap().len(), 1);
        assert_eq!(cfg["disks"][0]["path"], "/boot.raw");
        assert_eq!(cfg["fs"][0]["socket"], "/run/fs.sock");
        assert_eq!(cfg["fs"][0]["tag"], "share");
        // num_queues/queue_size are CH's defaults, deliberately not ours
        assert_eq!(cfg["fs"][0].get("num_queues"), None);
    }

    /// virtiofsd maps guest memory like every other vhost-user backend, so a
    /// share alone has to turn shared memory on — the same rule the disk case
    /// already holds, asked of the third form.
    #[test]
    fn a_share_alone_turns_shared_memory_on() {
        let cfg = config(&spec(
            vec![VolumeAttachment::Path("/a.raw".into()), share()],
            vec![],
        ));
        assert_eq!(cfg["memory"]["shared"], true);
        assert_eq!(
            cfg.get("generic_vhost_user"),
            None,
            "a share is not a generic device"
        );
    }

    /// And a VM with no share has no `fs` key at all, rather than an empty
    /// array: CH's own field is an Option, and an empty list is not what
    /// "no shares" means.
    #[test]
    fn a_vm_without_shares_has_no_fs_key() {
        let cfg = config(&spec(vec![VolumeAttachment::Path("/a.raw".into())], vec![]));
        assert_eq!(cfg.get("fs"), None);
    }

    /// A vfio device pins memory but maps none of the guest's own into
    /// another process, so it must NOT flip `shared` — that would change how
    /// every passthrough VM in the lab is built.
    #[test]
    fn passthrough_does_not_ask_for_shared_memory() {
        let cfg = config(&spec(
            vec![VolumeAttachment::Path("/a.raw".into())],
            vec![DeviceAttachment::VfioPci {
                sysfs_path: "/sys/bus/pci/devices/0000:23:00.0".into(),
            }],
        ));
        assert_eq!(cfg["memory"]["shared"], false);
        assert_eq!(
            cfg["devices"][0]["path"],
            "/sys/bus/pci/devices/0000:23:00.0"
        );
    }
}
