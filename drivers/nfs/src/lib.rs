// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Volumes under a mounted share, exposed as raw disks or virtiofs.
//!
//! `params.kind = "file"` delegates to the filesystem driver under
//! `<share_root>/volumes`. `kind = "share"` creates a directory under
//! `<share_root>/shares` and serves it with a virtiofsd backend at attachment.
//! Detach preserves data. The driver advertises shared locality; operators
//! must ensure the configured path reaches the same storage on participating
//! nodes. Managed mounts render their source as `server:export`.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use agent_api::CgroupHandle;
use agent_api::storage::{
    self, Locality, SnapshotConsistency, SnapshotId, StorageError, VolumeAttacher,
    VolumeAttachment, VolumeHandle, VolumeId, VolumeProvider, VolumeSpec, VolumeState,
};
use backend::{Backend, BackendIo, BackendKind};
use filesystem_driver::{FilesystemBlockDriver, FilesystemDriverConfig};
use tokio::sync::Mutex;
use tracing::{info, instrument, warn};

/// Descriptor headroom for virtiofsd serving many guest files.
const NOFILE_LIMIT: u64 = 65536;

/// Default time allowed for a new virtiofsd socket to become ready.
pub const DEFAULT_SOCKET_TIMEOUT_MS: u64 = 5000;

/// The tag a share is mounted by when the spec does not name one. A guest
/// that does `mount -t virtiofs share /mnt` needs to know the tag before it
/// boots, so there has to be a default worth writing into an image.
pub const DEFAULT_TAG: &str = "share";

/// Default mount executable; `with_mount_bin` overrides it.
pub const DEFAULT_MOUNT_BIN: &str = "mount";

/// What a volume on this backend is.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum VolumeKind {
    /// A raw file in the share, which the guest sees as a block device.
    #[default]
    File,
    /// A directory in the share, which the guest mounts over virtiofs.
    Share,
}

#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NfsParams {
    #[serde(default)]
    pub kind: VolumeKind,
    /// virtiofs tag, `share` mode only. The guest mounts by this name.
    pub tag: Option<String>,
}

/// `[volume.nfs]`, as far as the driver is concerned.
pub struct NfsDriverConfig {
    /// The mounted share everything lives under.
    pub share_root: PathBuf,
    /// Where `base_image` names a file. Not under the share by default:
    /// images are the node's, and copying them onto a share to copy them back
    /// off it would be work for nothing.
    pub image_dir: PathBuf,
    pub virtiofsd: PathBuf,
    pub run_dir: PathBuf,
    pub socket_timeout: Duration,
    /// Additional operator-supplied virtiofsd flags, appended verbatim.
    pub virtiofsd_args: Vec<String>,
    /// Mount share_root at startup when true. Otherwise require an existing
    /// mount managed by the deployment.
    pub manage_mount: bool,
    pub mount: Option<MountSpec>,
    /// This node's id; staging files carry it so one node's start-up sweep never removes
    /// another node's running copy on the shared directory (R3-F09).
    pub host_id: String,
}

/// Source and options for a driver-managed mount.
#[derive(Clone, Debug)]
pub struct MountSpec {
    pub server: String,
    pub export: String,
    /// `-o` options, verbatim. Empty = the kernel's defaults.
    pub options: Option<String>,
    /// mount(8) filesystem type; the source still uses `server:export` syntax.
    pub fs_type: String,
}

struct ActiveBackend {
    child: Backend,
    tag: String,
}

pub struct NfsDriver {
    config: NfsDriverConfig,
    /// One virtiofsd per attachment, in a session of its own and signalled as
    /// a process GROUP. See `BackendKind::detached`.
    process: BackendKind,
    /// Delegate file-mode volumes to the filesystem driver rooted under the share.
    files: FilesystemBlockDriver,
    active: Mutex<HashMap<VolumeId, ActiveBackend>>,
}

/// Match the mount-point field from the kernel mount list.
fn is_mount_point(mounts: &str, path: &Path) -> bool {
    let want = path.to_string_lossy();
    mounts.lines().any(|line| {
        // fstab-style escaping: the kernel writes spaces as \040.
        line.split_whitespace()
            .nth(1)
            .map(|m| m.replace("\\040", " ") == want)
            .unwrap_or(false)
    })
}

/// Build mount(8) arguments independently of running the command.
fn mount_args(spec: &MountSpec, share_root: &Path) -> Vec<String> {
    let mut args = vec!["-t".to_string(), spec.fs_type.clone()];
    if let Some(opts) = &spec.options
        && !opts.is_empty()
    {
        args.push("-o".to_string());
        args.push(opts.clone());
    }
    args.push(format!("{}:{}", spec.server, spec.export));
    args.push(share_root.to_string_lossy().into_owned());
    args
}

impl NfsDriver {
    /// mount(8) off PATH, which is what every config written so far expects.
    pub fn new(config: NfsDriverConfig) -> storage::Result<Self> {
        Self::with_mount_bin(config, PathBuf::from(DEFAULT_MOUNT_BIN))
    }

    /// Construct with a mount executable override used only during startup.
    pub fn with_mount_bin(config: NfsDriverConfig, mount_bin: PathBuf) -> storage::Result<Self> {
        if !config.virtiofsd.exists() {
            return Err(StorageError::Backend(anyhow::anyhow!(
                "virtiofsd binary not found at {}",
                config.virtiofsd.display()
            )));
        }
        std::fs::create_dir_all(&config.run_dir).map_err(|e| StorageError::Backend(e.into()))?;

        Self::ensure_share_root(&config, &mount_bin)?;

        std::fs::create_dir_all(config.share_root.join("volumes"))
            .map_err(|e| StorageError::Backend(e.into()))?;
        std::fs::create_dir_all(config.share_root.join("shares"))
            .map_err(|e| StorageError::Backend(e.into()))?;

        let files = FilesystemBlockDriver::new(FilesystemDriverConfig {
            image_dir: config.image_dir.clone(),
            volume_dir: config.share_root.join("volumes"),
            // File-mode qcow2 conversion resolves qemu-img through PATH.
            qemu_img: PathBuf::from("qemu-img"),
            // Use the same base-image conversion sandbox as the local filesystem driver.
            convert: agent_api::base_image::Sandbox::default(),
            host_id: config.host_id.clone(),
        })?;

        Ok(Self {
            config,
            process: BackendKind::detached("virtiofsd", "virtiofsd", NOFILE_LIMIT),
            files,
            active: Mutex::new(HashMap::new()),
        })
    }

    /// Create a managed mount or verify the externally managed directory exists.
    /// An unmanaged path that is not a mount point only warns; mount source identity
    /// and cross-node reachability are not verified.
    fn ensure_share_root(config: &NfsDriverConfig, mount_bin: &Path) -> storage::Result<()> {
        let mounts = std::fs::read_to_string("/proc/self/mounts").unwrap_or_default();
        let mounted = is_mount_point(&mounts, &config.share_root);

        if !config.manage_mount {
            if !config.share_root.is_dir() {
                return Err(StorageError::Backend(anyhow::anyhow!(
                    "share_root {} does not exist and manage_mount is false; \
                     nothing on this node is going to create it",
                    config.share_root.display()
                )));
            }
            if !mounted {
                warn!(
                    share_root = %config.share_root.display(),
                    "share_root is not a mount point, volumes on it are local to this node"
                );
            }
            return Ok(());
        }

        let Some(spec) = &config.mount else {
            return Err(StorageError::InvalidSpec(
                "[volume.nfs] manage_mount = true needs server and export".into(),
            ));
        };
        if mounted {
            info!(share_root = %config.share_root.display(), "share already mounted");
            return Ok(());
        }
        std::fs::create_dir_all(&config.share_root).map_err(|e| StorageError::Backend(e.into()))?;

        // Use mount(8) so its NFS helper handles negotiation and RPC setup.
        let args = mount_args(spec, &config.share_root);
        let out = std::process::Command::new(mount_bin)
            .args(&args)
            .output()
            .map_err(|e| {
                StorageError::Backend(anyhow::anyhow!("running {}: {e}", mount_bin.display()))
            })?;
        if !out.status.success() {
            return Err(StorageError::Backend(anyhow::anyhow!(
                "mount {} failed: {}",
                args.join(" "),
                String::from_utf8_lossy(&out.stderr).trim()
            )));
        }
        info!(share_root = %config.share_root.display(),
              source = %format!("{}:{}", spec.server, spec.export), "share mounted");
        Ok(())
    }

    fn params(spec: &VolumeSpec) -> storage::Result<NfsParams> {
        match &spec.params {
            Some(v) => serde_json::from_value(v.clone())
                .map_err(|e| StorageError::InvalidSpec(format!("invalid nfs params: {e}"))),
            None => Ok(NfsParams::default()),
        }
    }

    fn share_dir(&self, id: &VolumeId) -> PathBuf {
        self.config.share_root.join("shares").join(id.to_string())
    }

    /// Reject file-only operations when an on-disk share directory exists.
    /// Inspect storage because legacy handles may omit mode parameters.
    async fn refuse_a_share(&self, handle: &VolumeHandle, verb: &str) -> storage::Result<()> {
        if tokio::fs::metadata(self.share_dir(&handle.id))
            .await
            .is_ok()
        {
            return Err(StorageError::Unsupported(format!(
                "{verb}: volume {} is an nfs share (a directory served over virtiofs), and a \
                 directory has no point-in-time copy this backend can make",
                handle.id
            )));
        }
        Ok(())
    }

    fn socket_path(&self, id: &VolumeId) -> PathBuf {
        self.config.run_dir.join(format!("{id}.sock"))
    }

    fn log_path(&self, id: &VolumeId) -> PathBuf {
        self.config.run_dir.join(format!("{id}.log"))
    }

    /// Virtiofsd lock-file path, removed with the attachment socket.
    fn socket_lock_path(&self, id: &VolumeId) -> PathBuf {
        self.config.run_dir.join(format!("{id}.sock.pid"))
    }

    /// Spawn virtiofsd and wait for socket-file readiness before returning the attachment.
    async fn spawn_virtiofsd(
        &self,
        id: &VolumeId,
        dir: &Path,
        tag: &str,
        cgroup: Option<&CgroupHandle>,
    ) -> storage::Result<(u32, Backend)> {
        let socket = self.socket_path(id);

        let mut cmd = tokio::process::Command::new(&self.config.virtiofsd);
        cmd.arg("--socket-path")
            .arg(&socket)
            .arg("--shared-dir")
            .arg(dir)
            .arg("--tag")
            .arg(tag)
            .args(&self.config.virtiofsd_args);

        Ok(self
            .process
            .spawn(
                cmd,
                BackendIo {
                    socket: &socket,
                    log: &self.log_path(id),
                    timeout: self.config.socket_timeout,
                    cgroup,
                    span: tracing::info_span!("backend_spawn", driver = "nfs", volume_id = %id),
                },
            )
            .await?)
    }

    /// Stop a tracked child or signal an identity-checked adopted backend, then
    /// remove socket paths. Adopted-process exit is not awaited. Preserve share data.
    async fn stop_backend(&self, id: &VolumeId, attachment: &VolumeAttachment) {
        let entry = self.active.lock().await.remove(id);

        match entry {
            Some(entry) => self.process.stop(entry.child).await,
            // For adopted backends, verify both process name and socket argument
            // before stopping the recorded PID; sibling shares run the same executable.
            None => {
                if let VolumeAttachment::FsShare { socket, pid, .. } = attachment {
                    self.process.stop_adopted(*pid, socket);
                }
            }
        }

        let _ = backend::remove_if_present(&self.socket_path(id)).await;
        let _ = backend::remove_if_present(&self.socket_lock_path(id)).await;
    }

    /// Parse attachment mode and virtiofs tag from the handle, which lets an
    /// attacher operate without the original provisioning spec.
    fn handle_params(handle: &VolumeHandle) -> storage::Result<NfsParams> {
        match &handle.params {
            Some(v) => serde_json::from_value(v.clone())
                .map_err(|e| StorageError::InvalidSpec(format!("invalid nfs params: {e}"))),
            None => Ok(NfsParams::default()),
        }
    }

    /// Start a virtiofsd backend in the consumer's cgroup for an existing share directory.
    async fn attach_share(
        &self,
        handle: &VolumeHandle,
        cgroup: Option<&CgroupHandle>,
    ) -> storage::Result<VolumeAttachment> {
        let id = &handle.id;
        let tag = Self::handle_params(handle)?
            .tag
            .unwrap_or_else(|| DEFAULT_TAG.to_string());
        let dir = handle.path();

        // Reuse only a live backend with its socket present.
        {
            let mut active = self.active.lock().await;
            if let Some(running) = active.get_mut(id) {
                let socket = self.socket_path(id);
                if running.child.is_reusable(&socket) {
                    return Ok(VolumeAttachment::FsShare {
                        socket,
                        tag: running.tag.clone(),
                        pid: running.child.pid().unwrap_or(0),
                    });
                }
                active.remove(id);
            }
        }

        let (pid, child) = self.spawn_virtiofsd(id, &dir, &tag, cgroup).await?;
        self.active.lock().await.insert(
            *id,
            ActiveBackend {
                child,
                tag: tag.clone(),
            },
        );

        info!(pid, tag = %tag, dir = %dir.display(), "virtiofs share ready");
        Ok(VolumeAttachment::FsShare {
            socket: self.socket_path(id),
            tag,
            pid,
        })
    }
}

#[async_trait::async_trait]
impl VolumeProvider for NfsDriver {
    #[instrument(skip_all, fields(volume_id = %id, size_bytes = spec.size_bytes))]
    async fn provision(&self, id: &VolumeId, spec: &VolumeSpec) -> storage::Result<VolumeHandle> {
        let params = Self::params(spec)?;
        match params.kind {
            VolumeKind::File => self.files.provision(id, spec).await,
            VolumeKind::Share => {
                let dir = self.share_dir(id);
                tokio::fs::create_dir_all(&dir)
                    .await
                    .map_err(|e| StorageError::Backend(e.into()))?;
                Ok(VolumeHandle {
                    id: *id,
                    backend: dir.to_string_lossy().into_owned(),
                    // A share has no size the guest can be told about — it is
                    // a filesystem, and how much room is in it is the share's
                    // business.
                    size_bytes: 0,
                    params: spec.params.clone(),
                })
            }
        }
    }

    /// Remove both file and directory candidates by ID, including legacy handles
    /// without mode params. This does not stop virtiofsd; callers must establish
    /// that all consumers have closed before deleting data.
    #[instrument(skip_all, fields(volume_id = %handle.id))]
    async fn deprovision(&self, handle: &VolumeHandle) -> storage::Result<()> {
        let id = &handle.id;
        let _ = tokio::fs::remove_file(self.log_path(id)).await;
        match tokio::fs::remove_dir_all(self.share_dir(id)).await {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(StorageError::Backend(e.into())),
        }
        self.files.deprovision(handle).await
    }

    /// Advertise Shared. Correctness depends on each eligible node mounting the
    /// same export; this method does not verify that configuration.
    fn locality(&self) -> Locality {
        Locality::Shared
    }

    /// Resize file-mode data through the filesystem driver; shares have no byte size.
    #[instrument(skip_all, fields(volume_id = %handle.id, size_bytes))]
    async fn resize(
        &self,
        handle: &VolumeHandle,
        size_bytes: u64,
    ) -> storage::Result<VolumeHandle> {
        self.refuse_a_share(handle, "resize").await?;
        self.files.resize(handle, size_bytes).await
    }

    /// Advertise file-mode snapshot support from the inner filesystem driver.
    /// Share-mode snapshot requests are refused at operation time.
    fn snapshot_support(&self) -> Option<SnapshotConsistency> {
        self.files.snapshot_support()
    }

    #[instrument(skip_all, fields(volume_id = %handle.id, snapshot_id = %id))]
    async fn snapshot(
        &self,
        handle: &VolumeHandle,
        id: &SnapshotId,
    ) -> storage::Result<VolumeHandle> {
        self.refuse_a_share(handle, "snapshot").await?;
        self.files.snapshot(handle, id).await
    }

    #[instrument(skip_all, fields(snapshot_id = %handle.id))]
    async fn drop_snapshot(&self, handle: &VolumeHandle) -> storage::Result<()> {
        self.files.drop_snapshot(handle).await
    }

    #[instrument(skip_all, fields(volume_id = %id))]
    async fn provision_from(
        &self,
        id: &VolumeId,
        snapshot: &VolumeHandle,
        spec: &VolumeSpec,
    ) -> storage::Result<VolumeHandle> {
        // Snapshot creation produces file volumes; reject specs requesting a share.
        if Self::params(spec)?.kind == VolumeKind::Share {
            return Err(StorageError::Unsupported(
                "an nfs share is a directory and cannot be made from a snapshot; \
                 drop params.kind or use a file volume"
                    .into(),
            ));
        }
        self.files.provision_from(id, snapshot, spec).await
    }

    #[instrument(level = "trace", skip_all, fields(volume_id = %handle.id))]
    async fn describe(&self, handle: &VolumeHandle) -> storage::Result<VolumeState> {
        // Determine share mode from its directory, including handles without params.
        if tokio::fs::metadata(self.share_dir(&handle.id))
            .await
            .is_ok()
        {
            return Ok(VolumeState { size_bytes: 0 });
        }
        self.files.describe(handle).await
    }

    /// Probe share and file locations in deletion order, independently of handle parameters.
    #[instrument(level = "trace", skip_all, fields(volume_id = %id))]
    async fn probe(
        &self,
        id: &VolumeId,
        spec: &VolumeSpec,
    ) -> storage::Result<Option<VolumeHandle>> {
        let dir = self.share_dir(id);
        if tokio::fs::metadata(&dir).await.is_ok() {
            return Ok(Some(VolumeHandle {
                id: *id,
                backend: dir.to_string_lossy().into_owned(),
                size_bytes: 0,
                params: spec.params.clone(),
            }));
        }
        self.files.probe(id, spec).await
    }

    /// Delegate snapshot probing to the filesystem backend; shares do not support snapshots.
    #[instrument(level = "trace", skip_all, fields(snapshot_id = %id))]
    async fn probe_snapshot(
        &self,
        volume: Option<&VolumeHandle>,
        id: &SnapshotId,
    ) -> storage::Result<Option<VolumeHandle>> {
        self.files.probe_snapshot(volume, id).await
    }
}

#[async_trait::async_trait]
impl VolumeAttacher for NfsDriver {
    #[instrument(skip_all, fields(volume_id = %handle.id))]
    async fn attach(
        &self,
        handle: &VolumeHandle,
        cgroup: Option<&CgroupHandle>,
    ) -> storage::Result<VolumeAttachment> {
        match Self::handle_params(handle)?.kind {
            VolumeKind::File => self.files.attach(handle, cgroup).await,
            VolumeKind::Share => self.attach_share(handle, cgroup).await,
        }
    }

    /// Stop the attachment's virtiofsd while preserving its share data. A later
    /// attachment starts a new backend.
    #[instrument(skip_all, fields(volume_id = %handle.id))]
    async fn detach(
        &self,
        handle: &VolumeHandle,
        attachment: &VolumeAttachment,
    ) -> storage::Result<()> {
        // Decided from the ATTACHMENT and not from the handle: what has to go
        // is a process, and whether there is one is what the attachment says.
        if matches!(attachment, VolumeAttachment::FsShare { .. }) {
            self.stop_backend(&handle.id, attachment).await;
        }
        Ok(())
    }

    #[instrument(level = "trace", skip_all, fields(volume_id = %handle.id))]
    async fn stat(
        &self,
        handle: &VolumeHandle,
        attachment: &VolumeAttachment,
    ) -> storage::Result<VolumeState> {
        let id = &handle.id;
        let VolumeAttachment::FsShare { socket, pid, .. } = attachment else {
            return self.files.stat(handle, attachment).await;
        };

        // Our own child first — `try_wait` is the only answer that cannot be
        // confused by pid reuse. Falling back to the record is what makes this
        // work for a backend adopted after an agent restart.
        if let Some(running) = self.active.lock().await.get_mut(id)
            && !running.child.is_running()
        {
            return Err(StorageError::NotFound(*id));
        }
        // Verify the stored PID still belongs to this share's virtiofsd.
        if !self.process.is_ours(*pid, socket) {
            return Err(StorageError::NotFound(*id));
        }
        Ok(VolumeState { size_bytes: 0 })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Temporary driver fixture with an existing virtiofsd path. These storage
    /// tests do not spawn it. Retain the returned directory guard.
    fn driver(tag: &str) -> (tempfile::TempDir, NfsDriver, PathBuf) {
        let temp = tempfile::Builder::new()
            .prefix(&format!("meister-nfs-{tag}-"))
            .tempdir()
            .expect("a temp dir");
        let root = temp.path().to_path_buf();
        let share = root.join("share");
        let images = root.join("images");
        std::fs::create_dir_all(&share).expect("a temp share root");
        std::fs::create_dir_all(&images).expect("a temp image dir");
        let d = NfsDriver::new(NfsDriverConfig {
            share_root: share.clone(),
            image_dir: images,
            // Exists, so the driver builds; never spawned by these tests.
            virtiofsd: PathBuf::from("/bin/sh"),
            run_dir: root.join("run"),
            socket_timeout: Duration::from_millis(10),
            virtiofsd_args: Vec::new(),
            manage_mount: false,
            mount: None,
            host_id: "test-node".into(),
        })
        .expect("the driver builds over a plain directory");
        (temp, d, share)
    }

    fn spec(kind: &str) -> VolumeSpec {
        VolumeSpec {
            base_image: None,
            size_bytes: 4096,
            driver: Some("nfs".into()),
            params: Some(serde_json::json!({ "kind": kind })),
        }
    }

    /// NFS file mode attaches the raw file directly, without a loop device or backend process.
    #[tokio::test]
    async fn a_file_volume_is_a_path_on_the_share_and_nothing_else() {
        let (_temp, d, share) = driver("file");
        let id = uuid::Uuid::new_v4();

        let handle = d.provision(&id, &spec("file")).await.expect("provisioned");
        let expected = share.join("volumes").join(format!("{id}.raw"));
        assert_eq!(handle.path(), expected);
        assert_eq!(
            std::fs::metadata(&expected)
                .expect("the file is there")
                .len(),
            4096
        );

        let attachment = d.attach(&handle, None).await.expect("no cgroup needed");
        match &attachment {
            VolumeAttachment::Path(p) => assert_eq!(p, &expected),
            other => panic!("no loop device, no backend: {other:?}"),
        }
        assert!(attachment.is_block());
        assert!(!attachment.needs_shared_memory());
        assert_eq!(attachment.backend_pid(), None);

        // And detaching a path is nothing at all, so the file survives it.
        d.detach(&handle, &attachment).await.expect("nothing to do");
        assert!(expected.exists());
    }

    /// Share provisioning creates data only; attach is responsible for starting virtiofsd.
    #[tokio::test]
    async fn provisioning_a_share_makes_a_directory_and_starts_nothing() {
        let (_temp, d, share) = driver("share");
        let id = uuid::Uuid::new_v4();

        let handle = d.provision(&id, &spec("share")).await.expect("provisioned");
        let dir = share.join("shares").join(id.to_string());
        assert_eq!(handle.path(), dir);
        assert!(dir.is_dir(), "the directory IS the volume");
        assert_eq!(handle.size_bytes, 0, "a filesystem has no size to promise");

        // No socket, no pid file, no child: nothing here spawned anything.
        assert!(d.active.lock().await.is_empty());
        assert!(!d.socket_path(&id).exists());

        // Preserve attach options on the handle for independent attachers.
        assert_eq!(
            NfsDriver::handle_params(&handle).unwrap().kind,
            VolumeKind::Share
        );

        // Describe volume data without requiring a consumer.
        assert_eq!(
            d.describe(&handle).await.expect("it is there"),
            VolumeState { size_bytes: 0 }
        );
    }

    /// Deprovision removes either file or directory data according to what exists.
    #[tokio::test]
    async fn deprovision_clears_either_shape_without_being_told_which() {
        let (_temp, d, share) = driver("deprovision");

        for kind in ["file", "share"] {
            let id = uuid::Uuid::new_v4();
            let handle = d.provision(&id, &spec(kind)).await.expect("provisioned");
            assert!(handle.path().exists(), "{kind}");

            // The params stripped, exactly as a migrated record has them.
            let blind = VolumeHandle {
                params: None,
                ..handle.clone()
            };
            d.deprovision(&blind).await.expect("removed");
            assert!(!handle.path().exists(), "{kind} was not removed");
            assert!(matches!(
                d.describe(&blind).await,
                Err(StorageError::NotFound(gone)) if gone == id
            ));
            // Twice is Ok: a teardown runs again after a crash between its
            // two halves.
            d.deprovision(&blind).await.expect("idempotent");
        }

        // Neither directory was taken with it — only what belonged to the
        // volume went.
        assert!(share.join("volumes").is_dir());
        assert!(share.join("shares").is_dir());
    }

    /// Detach stops the backend without changing share contents.
    #[tokio::test]
    async fn detaching_a_share_leaves_every_byte_where_it_was() {
        let (_temp, d, _) = driver("detach");
        let id = uuid::Uuid::new_v4();
        let handle = d.provision(&id, &spec("share")).await.unwrap();
        std::fs::write(handle.path().join("payload"), b"tenant data").expect("a file in the share");

        // A `Path` attachment on a share handle: no process, so nothing to
        // stop, and detach must not reach for the directory anyway.
        d.detach(&handle, &VolumeAttachment::Path(handle.path()))
            .await
            .expect("nothing to detach");
        assert_eq!(
            std::fs::read(handle.path().join("payload")).unwrap(),
            b"tenant data"
        );
    }

    /// File mode is the default; shares require an explicit kind.
    #[test]
    fn the_mode_defaults_to_file_and_is_named_to_change_it() {
        let p: NfsParams = serde_json::from_value(serde_json::json!({})).unwrap();
        assert_eq!(p.kind, VolumeKind::File);
        assert_eq!(p.tag, None);

        let p: NfsParams =
            serde_json::from_value(serde_json::json!({"kind": "share", "tag": "data"})).unwrap();
        assert_eq!(p.kind, VolumeKind::Share);
        assert_eq!(p.tag.as_deref(), Some("data"));

        // Reject unknown modes rather than defaulting them to file.
        assert!(
            serde_json::from_value::<NfsParams>(serde_json::json!({"kind": "shares"})).is_err()
        );
        assert!(serde_json::from_value::<NfsParams>(serde_json::json!({"tagg": "x"})).is_err());
    }

    #[test]
    fn params_are_read_off_the_spec_or_defaulted() {
        let spec = |params| VolumeSpec {
            base_image: None,
            size_bytes: 1,
            driver: Some("nfs".into()),
            params,
        };
        assert_eq!(
            NfsDriver::params(&spec(None)).unwrap().kind,
            VolumeKind::File
        );
        assert_eq!(
            NfsDriver::params(&spec(Some(serde_json::json!({"kind": "share"}))))
                .unwrap()
                .kind,
            VolumeKind::Share
        );
        let err = NfsDriver::params(&spec(Some(serde_json::json!({"kind": 7}))))
            .unwrap_err()
            .to_string();
        assert!(err.contains("invalid nfs params"), "{err}");
    }

    /// The mount line, without an NFS server in the room. The order matters
    /// to mount(8): options before the source, source before the target.
    #[test]
    fn the_mount_line_is_type_options_source_target() {
        let spec = MountSpec {
            server: "10.0.8.21".into(),
            export: "/exports/meister".into(),
            options: Some("vers=4.2,hard,noatime".into()),
            fs_type: "nfs".into(),
        };
        assert_eq!(
            mount_args(&spec, Path::new("/srv/share")),
            vec![
                "-t",
                "nfs",
                "-o",
                "vers=4.2,hard,noatime",
                "10.0.8.21:/exports/meister",
                "/srv/share",
            ]
        );
    }

    /// Omit -o when no mount options exist and preserve the configured filesystem type.
    #[test]
    fn no_options_means_no_o_flag_and_the_type_is_not_nfs_by_law() {
        let spec = MountSpec {
            server: "ceph-a".into(),
            export: "/vol".into(),
            options: None,
            fs_type: "ceph".into(),
        };
        assert_eq!(
            mount_args(&spec, Path::new("/srv/share")),
            vec!["-t", "ceph", "ceph-a:/vol", "/srv/share"]
        );
        let empty = MountSpec {
            options: Some(String::new()),
            ..spec
        };
        assert_eq!(mount_args(&empty, Path::new("/srv/share")).len(), 4);
    }

    /// Match only the mount-point column, not a device or another field.
    #[test]
    fn a_mount_point_is_the_second_column_and_nothing_else() {
        let mounts = "\
/dev/sda1 / ext4 rw,relatime 0 0
10.0.8.21:/exports/meister /srv/share nfs4 rw,vers=4.2 0 0
tmpfs /run tmpfs rw 0 0
";
        assert!(is_mount_point(mounts, Path::new("/srv/share")));
        assert!(is_mount_point(mounts, Path::new("/run")));
        assert!(!is_mount_point(mounts, Path::new("/srv")));
        assert!(
            !is_mount_point(mounts, Path::new("/exports/meister")),
            "that is the device"
        );
        assert!(!is_mount_point(mounts, Path::new("/srv/share/volumes")));
        assert!(!is_mount_point("", Path::new("/srv/share")));
    }

    /// The kernel escapes a space in a mount point as \040, and a share root
    /// under a path with a space would otherwise never look mounted.
    #[test]
    fn an_escaped_space_in_a_mount_point_still_matches() {
        let mounts = "srv:/e /srv/my\\040share nfs4 rw 0 0\n";
        assert!(is_mount_point(mounts, Path::new("/srv/my share")));
    }

    /// Both file and share modes advertise shared locality.
    #[test]
    fn an_export_is_shared_whichever_mode_it_serves() {
        let (_temp, d, _) = driver("locality");
        assert_eq!(d.locality(), Locality::Shared);
    }

    /// Opening the pool sweeps abandoned temporary snapshots; concurrent copies are not covered.
    #[test]
    fn an_unfinished_snapshot_on_the_share_goes_when_the_pool_is_opened() {
        let temp = tempfile::tempdir().expect("a temp dir");
        let root = temp.path().to_path_buf();
        let share = root.join("share");
        let images = root.join("images");
        std::fs::create_dir_all(share.join("volumes")).expect("a temp share root");
        std::fs::create_dir_all(&images).expect("a temp image dir");

        // This node's orphan and another node's still-running copy (R3-F09).
        let nonce = "0123456789abcdef0123456789abcdef";
        let orphan = share
            .join("volumes")
            .join(format!("aaaa.snap.tmp.test-node.{nonce}"));
        let running = share
            .join("volumes")
            .join(format!("cccc.snap.tmp.other-node.{nonce}"));
        let volume = share.join("volumes").join("bbbb.raw");
        for p in [&orphan, &running, &volume] {
            std::fs::write(p, b"x").expect("a file");
        }

        NfsDriver::new(NfsDriverConfig {
            share_root: share.clone(),
            image_dir: images,
            virtiofsd: PathBuf::from("/bin/sh"),
            run_dir: root.join("run"),
            socket_timeout: Duration::from_millis(10),
            virtiofsd_args: Vec::new(),
            manage_mount: false,
            mount: None,
            host_id: "test-node".into(),
        })
        .expect("the driver builds over a plain directory");

        assert!(!orphan.exists(), "this node's unfinished copy is gone");
        assert!(running.exists(), "another node's running copy is not");
        assert!(volume.exists(), "and the volumes on the share are not");
    }

    /// File-mode snapshot capability follows the filesystem probe; directory shares cannot snapshot.
    #[test]
    fn what_this_driver_claims_about_snapshots_is_what_the_export_can_do() {
        let (_temp, d, _) = driver("snapshot-claim");
        assert_eq!(
            d.snapshot_support(),
            d.files.snapshot_support(),
            "the claim is the file half's, not a second opinion"
        );
        assert!(
            matches!(
                d.snapshot_support(),
                Some(SnapshotConsistency::Atomic | SnapshotConsistency::NeedsQuiesce)
            ),
            "one of the two, never a refusal: the file half can always copy"
        );
    }
}
