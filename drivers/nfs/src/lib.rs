// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! The share-backed block driver: files on a mounted share, or a directory
//! handed to the guest whole over virtiofs.
//!
//! Named `nfs` because NFS is what it is for in the lab, but nothing below
//! this line knows what NFS is. The rule it implements is broader: anything
//! the HOST can mount can be a share. The driver owns the mount (or is told
//! it is already there), and what the guest sees is either a raw file it
//! boots from or a virtiofs export it mounts by tag. CephFS, an SMB share,
//! a second local disk — all of them are `share_root` to this file.
//!
//! Two modes, chosen by `params.kind`:
//!
//! * `file` (the default) — `<share_root>/volumes/<id>.raw`, created exactly
//!   as the filesystem driver creates its volumes, because it IS the
//!   filesystem driver: this one only roots it in the share. Attachment:
//!   `Path`.
//! * `share` — `<share_root>/shares/<id>/`, served by one virtiofsd per VM
//!   attachment. Attachment: `FsShare`.
//!
//! The virtiofsd half follows the device-backend pattern to the letter (see
//! `nvrm_driver`): one process per attachment, its own session so it cannot
//! die with a parent shell, room for a file descriptor per open guest file,
//! in the VM's cgroup slice so teardown reaps it, and never, ever reused —
//! a backend that exited when its VMM hung up is replaced by
//! Teardown→Provision, not handed back to the next boot.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use agent_api::CgroupHandle;
use agent_api::storage::{
    self, BlockDriver, StorageError, Volume, VolumeAttachment, VolumeId, VolumeSpec,
};
use backend::{Backend, BackendIo, BackendKind};
use filesystem_driver::{FilesystemBlockDriver, FilesystemDriverConfig};
use macros::generated;
use tokio::sync::Mutex;
use tracing::{info, instrument, warn};

/// A desktop guest can hold hundreds of files open at once and virtiofsd
/// needs one host descriptor for each. The same headroom the nvrm backend
/// gets, for the same kind of reason.
const NOFILE_LIMIT: u64 = 65536;

/// How long to wait for a freshly spawned virtiofsd to put its socket down.
/// It is a local process opening a local unix socket; anything slower than
/// this is a virtiofsd that is not going to come up.
pub const DEFAULT_SOCKET_TIMEOUT_MS: u64 = 5000;

/// The tag a share is mounted by when the spec does not name one. A guest
/// that does `mount -t virtiofs share /mnt` needs to know the tag before it
/// boots, so there has to be a default worth writing into an image.
pub const DEFAULT_TAG: &str = "share";

/// mount(8), looked up on PATH. Every other binary this driver runs is named
/// by config (`virtiofsd`, and lvm-thin's `bin_dir`/`qemu_img` next door);
/// mount was the one bare name left, and a node with mount somewhere PATH does
/// not reach had no way to say so. `NfsDriver::with_mount_bin` is that way,
/// and `new` keeps the behaviour every existing config already has.
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
    /// Extra virtiofsd flags, verbatim and last, so a knob this driver has
    /// never heard of needs no driver change. `--sandbox=none` is the one
    /// most nodes end up wanting.
    pub virtiofsd_args: Vec<String>,
    /// true: mount `share_root` at agent start if it is not mounted already.
    /// false: `share_root` is somebody else's business (fstab, a systemd
    /// mount unit, the NixOS module) and the driver only checks it is there.
    pub manage_mount: bool,
    pub mount: Option<MountSpec>,
}

/// What to mount, when the driver is the one mounting.
#[derive(Clone, Debug)]
pub struct MountSpec {
    pub server: String,
    pub export: String,
    /// `-o` options, verbatim. Empty = the kernel's defaults.
    pub options: Option<String>,
    /// `-t`. NFS is the default and the reason for the crate's name; anything
    /// mount(8) understands works.
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
    /// File-mode volumes are the filesystem driver's, rooted in the share.
    /// Delegating rather than copying: "a raw file with a base image cloned
    /// into it" is one behaviour and it should have one implementation,
    /// copy_file_range fallback and all.
    files: FilesystemBlockDriver,
    active: Mutex<HashMap<VolumeId, ActiveBackend>>,
}

/// Whether `path` is a mount point, read from the kernel rather than guessed.
/// `/proc/self/mounts` and not `/etc/mtab`: what is actually mounted is the
/// question, not what somebody meant to mount.
#[generated(model = ClaudeOpus, version = "5")]
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

/// The mount(8) argument list. A function of its own because it is the one
/// thing here worth testing without a real NFS server in the room.
#[generated(model = ClaudeOpus, version = "5")]
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

#[generated(model = ClaudeOpus, version = "5")]
impl NfsDriver {
    /// mount(8) off PATH, which is what every config written so far expects.
    pub fn new(config: NfsDriverConfig) -> storage::Result<Self> {
        Self::with_mount_bin(config, PathBuf::from(DEFAULT_MOUNT_BIN))
    }

    /// The same driver, told where mount(8) is. Only start-up runs it — the
    /// share is mounted once and never again — so the path is a parameter
    /// here rather than a field the driver carries around.
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
        })?;

        Ok(Self {
            config,
            process: BackendKind::detached("virtiofsd", "virtiofsd", NOFILE_LIMIT),
            files,
            active: Mutex::new(HashMap::new()),
        })
    }

    /// Either mount the share or satisfy ourselves that somebody else did.
    ///
    /// The asymmetry is deliberate. `manage_mount = true` is a node that has
    /// nothing else arranging the mount, and the driver failing to mount is a
    /// hard start-up error — half a storage backend is worse than none.
    /// `manage_mount = false` is a node where fstab or a systemd unit owns
    /// it, and then the only honest check is that the directory is there;
    /// a warning when it is not a mount point at all, because a share_root
    /// that is quietly a local directory means every "shared" volume is
    /// private to this node and nothing would say so.
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

        // mount(8) and not mount(2): NFS needs the mount.nfs helper to do the
        // RPC handshake and pick a protocol version, and reimplementing that
        // to avoid one fork would be a poor trade.
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

    fn socket_path(&self, id: &VolumeId) -> PathBuf {
        self.config.run_dir.join(format!("{id}.sock"))
    }

    fn log_path(&self, id: &VolumeId) -> PathBuf {
        self.config.run_dir.join(format!("{id}.log"))
    }

    /// virtiofsd puts a lock file beside its socket, named for it, and does
    /// not take it away again. Ours to clean up, or run_dir collects one
    /// orphan per share volume that ever existed.
    fn socket_lock_path(&self, id: &VolumeId) -> PathBuf {
        self.config.run_dir.join(format!("{id}.sock.pid"))
    }

    /// Spawn one virtiofsd for one attachment, and do not come back until it
    /// is listening — cloud-hypervisor connects to this socket during
    /// `vm.create` and a socket that is not there yet is a failed VM.
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

    /// Stop the backend for one volume, whether it is our child or one we
    /// adopted from a previous agent. Leaves the shared directory alone.
    async fn stop_backend(&self, id: &VolumeId, attachment: &VolumeAttachment) {
        let entry = self.active.lock().await.remove(id);

        match entry {
            Some(entry) => self.process.stop(entry.child).await,
            None => {
                if let Some(pid) = attachment.backend_pid() {
                    self.process.stop_adopted(pid);
                }
            }
        }

        let _ = backend::remove_if_present(&self.socket_path(id)).await;
        let _ = backend::remove_if_present(&self.socket_lock_path(id)).await;
    }

    async fn create_share(
        &self,
        id: &VolumeId,
        params: &NfsParams,
        cgroup: Option<&CgroupHandle>,
    ) -> storage::Result<Volume> {
        let tag = params
            .tag
            .clone()
            .unwrap_or_else(|| DEFAULT_TAG.to_string());
        let dir = self.share_dir(id);

        // A live backend for this volume is reusable; a dead one is not, ever.
        {
            let mut active = self.active.lock().await;
            if let Some(running) = active.get_mut(id) {
                let socket = self.socket_path(id);
                if running.child.is_reusable(&socket) {
                    return Ok(Volume {
                        id: *id,
                        attachment: VolumeAttachment::FsShare {
                            socket,
                            tag: running.tag.clone(),
                            pid: running.child.pid().unwrap_or(0),
                        },
                        size_bytes: 0,
                    });
                }
                active.remove(id);
            }
        }

        tokio::fs::create_dir_all(&dir)
            .await
            .map_err(|e| StorageError::Backend(e.into()))?;

        let (pid, child) = self.spawn_virtiofsd(id, &dir, &tag, cgroup).await?;
        self.active.lock().await.insert(
            *id,
            ActiveBackend {
                child,
                tag: tag.clone(),
            },
        );

        info!(pid, tag = %tag, dir = %dir.display(), "virtiofs share ready");
        Ok(Volume {
            id: *id,
            // A share has no size the guest can be told about — it is a
            // filesystem, and how much room is in it is the share's business.
            size_bytes: 0,
            attachment: VolumeAttachment::FsShare {
                socket: self.socket_path(id),
                tag,
                pid,
            },
        })
    }
}

#[generated(model = ClaudeOpus, version = "5")]
#[async_trait::async_trait]
impl BlockDriver for NfsDriver {
    #[instrument(skip_all, fields(volume_id = %id, size_bytes = spec.size_bytes))]
    async fn create(
        &self,
        id: &VolumeId,
        spec: &VolumeSpec,
        cgroup: Option<&CgroupHandle>,
    ) -> storage::Result<Volume> {
        let params = Self::params(spec)?;
        match params.kind {
            VolumeKind::File => self.files.create(id, spec, cgroup).await,
            VolumeKind::Share => self.create_share(id, &params, cgroup).await,
        }
    }

    #[instrument(skip_all, fields(volume_id = %id))]
    async fn destroy(&self, id: &VolumeId, attachment: &VolumeAttachment) -> storage::Result<()> {
        match attachment {
            VolumeAttachment::FsShare { .. } => {
                self.stop_backend(id, attachment).await;
                let _ = tokio::fs::remove_file(self.log_path(id)).await;
                // The share's contents go with the VM: this directory was
                // made for it and nothing else can reach it.
                match tokio::fs::remove_dir_all(self.share_dir(id)).await {
                    Ok(()) => {}
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                    Err(e) => return Err(StorageError::Backend(e.into())),
                }
                Ok(())
            }
            _ => self.files.destroy(id, attachment).await,
        }
    }

    #[instrument(level = "trace", skip_all, fields(volume_id = %id))]
    async fn get(&self, id: &VolumeId, attachment: &VolumeAttachment) -> storage::Result<Volume> {
        let VolumeAttachment::FsShare { socket, tag, pid } = attachment else {
            return self.files.get(id, attachment).await;
        };

        // Our own child first — `try_wait` is the only answer that cannot be
        // confused by pid reuse. Falling back to a signal probe is what makes
        // this work for a backend adopted after an agent restart.
        if let Some(running) = self.active.lock().await.get_mut(id)
            && !running.child.is_running()
        {
            return Err(StorageError::NotFound(*id));
        }
        if !backend::pid_is_alive(*pid) {
            return Err(StorageError::NotFound(*id));
        }
        Ok(Volume {
            id: *id,
            attachment: VolumeAttachment::FsShare {
                socket: socket.clone(),
                tag: tag.clone(),
                pid: *pid,
            },
            size_bytes: 0,
        })
    }

    /// A stopped VM keeps its share directory and everything in it; what it
    /// must not keep is a virtiofsd serving a VM that is not running. The
    /// next start spawns a fresh one, which is the same rule the device
    /// backends follow.
    #[instrument(skip_all, fields(volume_id = %id))]
    async fn detach(&self, id: &VolumeId, attachment: &VolumeAttachment) -> storage::Result<()> {
        if matches!(attachment, VolumeAttachment::FsShare { .. }) {
            self.stop_backend(id, attachment).await;
        }
        Ok(())
    }
}

#[cfg(test)]
#[generated(model = ClaudeOpus, version = "5")]
mod tests {
    use super::*;

    /// `file` is the default so that a spec that says nothing gets a boot
    /// disk, which is what a volume has always been. `share` has to be asked
    /// for by name.
    #[test]
    fn the_mode_defaults_to_file_and_is_named_to_change_it() {
        let p: NfsParams = serde_json::from_value(serde_json::json!({})).unwrap();
        assert_eq!(p.kind, VolumeKind::File);
        assert_eq!(p.tag, None);

        let p: NfsParams =
            serde_json::from_value(serde_json::json!({"kind": "share", "tag": "data"})).unwrap();
        assert_eq!(p.kind, VolumeKind::Share);
        assert_eq!(p.tag.as_deref(), Some("data"));

        // A misspelled mode is a rejected spec, not a silent fall back to
        // file: "kind": "shares" asking for a boot disk would be a surprise
        // nobody could debug from the outside.
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

    /// No options is no `-o` at all rather than an empty one, which mount(8)
    /// takes as a syntax error. And the type is not hardcoded: the rule is
    /// "anything the host can mount", so a CephFS share_root is a config
    /// change and not a driver change.
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

    /// The mount check reads the kernel's own list, and it has to match the
    /// mount POINT and not any other column — `/srv/share` appearing as some
    /// other mount's device would otherwise read as mounted.
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
}
