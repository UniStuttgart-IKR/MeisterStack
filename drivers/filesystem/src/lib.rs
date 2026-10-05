// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

mod layout;
mod staging;

use agent_api::CgroupHandle;
use agent_api::storage;
use agent_api::storage::{
    Locality, SnapshotConsistency, SnapshotId, StorageError, VolumeAttacher, VolumeAttachment,
    VolumeHandle, VolumeId, VolumeProvider, VolumeSpec, VolumeState,
};
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use tracing::{Span, debug, info, instrument, warn};

pub struct FilesystemDriverConfig {
    /// Path where images are stored. Read-only.
    pub image_dir: PathBuf, // should be something like /var/lib/meister-agent/<uuid>/images
    /// Directory where .raw files as images are saved.
    pub volume_dir: PathBuf, // should be something like /var/lib/meister-agent/<uuid>/volumes
    /// Image probe/conversion executable used by the sandboxed base-image helpers.
    pub qemu_img: PathBuf,
    /// Sandbox for image probing and conversion; failure does not fall back to
    /// running the parser in the agent process.
    pub convert: agent_api::base_image::Sandbox,
    /// This node's id, written into the name of every staging file this
    /// driver makes. Astra finding R3-F09, 2026-09-25: on a pool several
    /// nodes share (the nfs driver roots this one in a share), a staging
    /// file has to say whose it is, or one node's start-up sweep removes
    /// another node's running copy. See `staging`.
    pub host_id: String,
}

/// QCOW2 magic used by local format detection helpers.
const QCOW2_MAGIC: [u8; 4] = [b'Q', b'F', b'I', 0xfb];

/// Whether this file is a qcow2. A file too short to hold the magic is not
/// one, and neither is a missing one — the caller has already stat'ed it.
fn is_qcow2(path: &Path) -> std::io::Result<bool> {
    use std::io::Read;
    let mut head = [0u8; 4];
    let mut file = std::fs::File::open(path)?;
    match file.read_exact(&mut head) {
        Ok(()) => Ok(head == QCOW2_MAGIC),
        Err(e) if e.kind() == ErrorKind::UnexpectedEof => Ok(false),
        Err(e) => Err(e),
    }
}

nix::ioctl_write_int!(ficlone, 0x94, 9);

/// Nonempty payload used by the reflink probe.
const PROBE_BYTES: usize = 4096;

/// Probe FICLONE support in the pool directory. Any failure selects
/// NeedsQuiesce. This probe does not guarantee the separate copy path is atomic.
fn probe_reflink(dir: &Path, host: &staging::HostTag) -> SnapshotConsistency {
    use std::io::Write;
    use std::os::fd::AsRawFd;

    // Host- and nonce-qualified names: a pid can collide between hosts sharing a pool (R3-F09).
    let (src_path, dst_path) = staging::probe_pair(dir, host);
    // Whatever this probe leaves behind goes, on every path out of it.
    let cleanup = || {
        let _ = std::fs::remove_file(&src_path);
        let _ = std::fs::remove_file(&dst_path);
    };
    cleanup();

    let answer = (|| -> std::io::Result<bool> {
        // FICLONE requires a readable source; write-only would incorrectly report EBADF.
        let mut src = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&src_path)?;
        src.write_all(&[0u8; PROBE_BYTES])?;
        src.sync_all()?;
        let dst = std::fs::File::create(&dst_path)?;
        // SAFETY: descriptors remain open; FICLONE takes the source fd value, not a pointer.
        let cloned = unsafe { ficlone(dst.as_raw_fd(), src.as_raw_fd() as u64) }.is_ok();
        if !cloned {
            return Ok(false);
        }
        // Verify the clone length as well as the ioctl result.
        Ok(dst.metadata()?.len() == PROBE_BYTES as u64)
    })();

    cleanup();
    match answer {
        Ok(true) => {
            info!(dir = %dir.display(),
                  "this pool's filesystem reflinks; snapshots here are atomic");
            SnapshotConsistency::Atomic
        }
        Ok(false) => {
            info!(dir = %dir.display(),
                  "this pool's filesystem does not reflink; snapshots here copy and need a quiesce");
            SnapshotConsistency::NeedsQuiesce
        }
        // Probe errors reduce advertised snapshot consistency without failing startup.
        Err(e) => {
            debug!(dir = %dir.display(), error = %e,
                   "the reflink probe could not run; assuming this backend copies");
            SnapshotConsistency::NeedsQuiesce
        }
    }
}

/// See `FilesystemBlockDriver::hold`.
#[cfg(test)]
type Hold = (
    std::sync::mpsc::Sender<PathBuf>,
    std::sync::mpsc::Receiver<()>,
);

/// Manage raw block-volume files in one configured pool directory.
pub struct FilesystemBlockDriver {
    config: FilesystemDriverConfig,
    /// Snapshot consistency selected by the startup FICLONE probe.
    snapshot_consistency: SnapshotConsistency,
    /// This node as it appears in every staging file name (R3-F09).
    host: staging::HostTag,
    /// Test hook holding a snapshot between its copy and its rename, so a second
    /// driver can start while the copy is open.
    #[cfg(test)]
    hold: std::sync::Mutex<Option<Hold>>,
    /// Per-instance reservations for copies that have not finished.
    room: layout::Room,
}

impl FilesystemBlockDriver {
    pub fn new(config: FilesystemDriverConfig) -> storage::Result<Self> {
        if !config.image_dir.is_dir() {
            return Err(StorageError::Backend(anyhow::anyhow!(
                "image_dir does not exist: {}",
                config.image_dir.display()
            )));
        }
        std::fs::create_dir_all(&config.volume_dir).map_err(|e| StorageError::Backend(e.into()))?;
        // Sweep interrupted staging files before creating this startup's probe files.
        // Only this host's files are provably dead: the nfs driver shares the pool
        // across nodes, so `staging::sweep` waits out a foreign host's heartbeat (R3-F09).
        let host = staging::HostTag::new(&config.host_id).map_err(StorageError::InvalidSpec)?;
        staging::sweep(&config.volume_dir, &host);
        let snapshot_consistency = probe_reflink(&config.volume_dir, &host);
        Ok(Self {
            config,
            snapshot_consistency,
            host,
            #[cfg(test)]
            hold: Default::default(),
            room: layout::Room::default(),
        })
    }

    /// Reserve space while this instance copies on a NeedsQuiesce pool.
    /// Pools classified Atomic skip the reservation. Keep the guard alive until
    /// completion; this is not cross-process capacity coordination.
    #[must_use = "the reservation is released when this is dropped; hold it for the copy"]
    fn room_for_a_copy(&self, needed: u64) -> storage::Result<Option<layout::Reserved<'_>>> {
        if self.snapshot_consistency == SnapshotConsistency::Atomic {
            return Ok(None);
        }
        self.room.reserve(&self.config.volume_dir, needed).map(Some)
    }

    /// Where this pool keeps the snapshot with that id. See
    /// `layout::snapshot_path`.
    fn snapshot_path(&self, id: &SnapshotId) -> PathBuf {
        layout::snapshot_path(&self.config.volume_dir, id)
    }

    /// Probe a base image and reject virtual sizes larger than the requested disk.
    /// Non-raw images must be converted before being exposed as raw block volumes.
    async fn base_image_for(
        &self,
        spec: &VolumeSpec,
    ) -> storage::Result<Option<(PathBuf, Option<agent_api::base_image::BaseImage>)>> {
        match &spec.base_image {
            Some(name) => {
                let src = self.config.image_dir.join(name);
                let meta = tokio::fs::metadata(&src)
                    .await
                    .map_err(|_| StorageError::ImageNotFound(name.clone()))?;
                let qcow2 = is_qcow2(&src).map_err(|e| StorageError::Backend(e.into()))?;
                // Validate qcow2 metadata before conversion so backing or external data
                // files cannot cause additional agent-privileged reads. Pass the validated
                // format to qemu-img and compare virtual disk size, not qcow2 file length.
                // Non-qcow2 images use the direct copy path without invoking qemu-img.
                let judged = if qcow2 {
                    Some(
                        agent_api::base_image::probe(
                            &self.config.convert,
                            &self.config.qemu_img,
                            &src,
                            name,
                        )
                        .await?,
                    )
                } else {
                    None
                };
                let needed = match &judged {
                    Some(image) => image.virtual_size,
                    None => meta.len(),
                };
                if needed > spec.size_bytes {
                    return Err(StorageError::InvalidSpec(format!(
                        "size_bytes {} smaller than base image {} ({} bytes{})",
                        spec.size_bytes,
                        name,
                        needed,
                        if qcow2 { " once written out raw" } else { "" }
                    )));
                }
                Ok(Some((src, judged)))
            }
            None => Ok(None),
        }
    }

    /// Return existing file length for idempotent provisioning.
    async fn size_if_already_there(path: &Path) -> storage::Result<Option<u64>> {
        match tokio::fs::metadata(path).await {
            Ok(meta) => Ok(Some(meta.len())),
            Err(e) if e.kind() == ErrorKind::NotFound => Ok(None),
            Err(e) => Err(StorageError::Backend(e.into())),
        }
    }

    /// Read file size for both describe and stat; missing files return NotFound.
    async fn measure(&self, id: &VolumeId) -> storage::Result<VolumeState> {
        match tokio::fs::metadata(layout::volume_path(&self.config.volume_dir, id)).await {
            Ok(meta) => Ok(VolumeState {
                size_bytes: meta.len(),
            }),
            Err(e) if e.kind() == ErrorKind::NotFound => Err(StorageError::NotFound(*id)),
            Err(e) => Err(StorageError::Backend(e.into())),
        }
    }
}

/// Filesystem provider operations; this backend accepts no driver parameters.
#[async_trait::async_trait]
impl VolumeProvider for FilesystemBlockDriver {
    #[instrument(skip_all, fields(volume_id = %id, size_bytes = spec.size_bytes))]
    #[instrument(skip_all, fields(volume_id = %id, size_bytes = spec.size_bytes))]
    async fn provision(&self, id: &VolumeId, spec: &VolumeSpec) -> storage::Result<VolumeHandle> {
        let path = layout::volume_path(&self.config.volume_dir, id);
        let handle = |size_bytes| VolumeHandle {
            id: *id,
            backend: path.to_string_lossy().into_owned(),
            size_bytes,
            params: spec.params.clone(),
        };

        if let Some(size_bytes) = Self::size_if_already_there(&path).await? {
            debug!(size_bytes, "volume already exists");
            return Ok(handle(size_bytes));
        }

        let src = self.base_image_for(spec).await?;
        // A name of this host's and this attempt's own (R3-F09): two
        // attempts at one volume, a retry or two hosts after a failover,
        // never truncate each other's half-written file, and the sweep can
        // tell this one from a leftover. Moved into the blocking task so it
        // lives, and beats, exactly as long as the copy does.
        let tmp = staging::Staged::begin(staging::volume_build(
            &self.config.volume_dir,
            id,
            &self.host,
        ));
        let final_path = path.clone();
        let size = spec.size_bytes;
        let qemu_img = self.config.qemu_img.clone();
        let sandbox = self.config.convert.clone();

        let span = Span::current();
        tokio::task::spawn_blocking(move || {
            span.in_scope(|| {
                layout::write_volume_file(src, &sandbox, &qemu_img, tmp.path(), &final_path, size)
            })
        })
        .await
        .map_err(|e| StorageError::Backend(anyhow::anyhow!("blocking task failed: {e}")))?
        .map_err(|e| StorageError::Backend(e.into()))?;

        info!("volume ready");
        Ok(handle(size))
    }

    #[instrument(skip_all, fields(volume_id = %handle.id))]
    async fn deprovision(&self, handle: &VolumeHandle) -> storage::Result<()> {
        let id = &handle.id;
        let dir = &self.config.volume_dir;
        // Every staging file of this volume, whoever wrote it: the volume is
        // their owner, and it is going.
        let mut doomed =
            staging::staged_for(dir, id, false).map_err(|e| StorageError::Backend(e.into()))?;
        doomed.push(staging::legacy_volume_build(dir, id));
        doomed.push(layout::volume_path(dir, id));
        for p in doomed {
            match tokio::fs::remove_file(&p).await {
                Ok(()) => debug!(path = %p.display(), "volume file removed"),
                Err(e) if e.kind() == ErrorKind::NotFound => {}
                Err(e) => return Err(StorageError::Backend(e.into())),
            }
        }
        Ok(())
    }

    /// Grow the raw file without shrinking. New extents remain sparse until written.
    #[instrument(skip_all, fields(volume_id = %handle.id, size_bytes))]
    async fn resize(
        &self,
        handle: &VolumeHandle,
        size_bytes: u64,
    ) -> storage::Result<VolumeHandle> {
        let path = handle.path();
        let have = tokio::fs::metadata(&path)
            .await
            .map_err(|_| StorageError::NotFound(handle.id))?
            .len();
        // Matching size makes repeated resize a no-op.
        if have == size_bytes {
            debug!(size_bytes, "already this size");
            return Ok(VolumeHandle {
                size_bytes,
                ..handle.clone()
            });
        }
        // Reject shrink requests before set_len could discard data.
        if size_bytes < have {
            return Err(StorageError::InvalidSpec(format!(
                "shrinking a volume is not supported ({have} bytes now, {size_bytes} asked for)"
            )));
        }
        let file = tokio::fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .await
            .map_err(|e| StorageError::Backend(e.into()))?;
        file.set_len(size_bytes)
            .await
            .map_err(|e| StorageError::Backend(e.into()))?;
        file.sync_all()
            .await
            .map_err(|e| StorageError::Backend(e.into()))?;
        info!(from = have, to = size_bytes, "volume grown");
        Ok(VolumeHandle {
            size_bytes,
            ..handle.clone()
        })
    }

    /// Return the cached FICLONE probe result. Snapshot copying uses
    /// copy_file_range and may fall back to a byte copy; it does not enforce
    /// a single atomic clone when this capability is Atomic.
    fn snapshot_support(&self) -> Option<SnapshotConsistency> {
        Some(self.snapshot_consistency)
    }

    #[instrument(skip_all, fields(volume_id = %handle.id, snapshot_id = %id))]
    async fn snapshot(
        &self,
        handle: &VolumeHandle,
        id: &SnapshotId,
    ) -> storage::Result<VolumeHandle> {
        let src = handle.path();
        let dst = self.snapshot_path(id);
        let taken = |size_bytes| VolumeHandle {
            // Use the snapshot ID so drop_snapshot cannot address its source volume.
            id: *id,
            backend: dst.to_string_lossy().into_owned(),
            size_bytes,
            params: None,
        };
        // A completed file under the snapshot ID makes creation idempotent.
        if let Ok(meta) = tokio::fs::metadata(&dst).await {
            debug!(size_bytes = meta.len(), "snapshot already exists");
            return Ok(taken(meta.len()));
        }
        let Ok(source) = tokio::fs::metadata(&src).await else {
            return Err(StorageError::NotFound(handle.id));
        };
        // Reserve capacity before creating staging files and retain the guard
        // through the copy so concurrent snapshots account for these bytes.
        let _room = self.room_for_a_copy(source.len())?;
        // This host's and this attempt's own name, registered and beating
        // for as long as the copy runs (R3-F09): another host's start-up
        // sweep can then tell it from a leftover. Moved into the blocking
        // task, so an abandoned caller does not stop the heartbeat of a copy
        // that is still running.
        let staged = staging::Staged::begin(staging::snapshot_copy(
            &self.config.volume_dir,
            id,
            &self.host,
        ));
        let (from, target) = (src.clone(), dst.clone());
        #[cfg(test)]
        let hold = self.hold.lock().expect("the test hold").take();
        let span = Span::current();
        let size = tokio::task::spawn_blocking(move || -> std::io::Result<u64> {
            span.in_scope(|| {
                let to = staged.path();
                // Copy through a staging name so interrupted work cannot appear as a completed snapshot.
                let copied = (|| -> std::io::Result<u64> {
                    let size = layout::clone_or_copy(&from, to)?;
                    #[cfg(test)]
                    if let Some((staged_at, go)) = hold {
                        let _ = staged_at.send(to.to_path_buf());
                        let _ = go.recv();
                    }
                    std::fs::rename(to, &target)?;
                    Ok(size)
                })();
                // Remove the staging file after a returned copy or rename failure.
                if copied.is_err() {
                    match std::fs::remove_file(to) {
                        Ok(()) => warn!(path = %to.display(),
                                        "removed the half-written copy of a failed snapshot"),
                        Err(e) if e.kind() == ErrorKind::NotFound => {}
                        Err(e) => warn!(path = %to.display(), error = %e,
                                        "the half-written copy of a failed snapshot could not be \
                                         removed; it is holding disk space nothing points at"),
                    }
                }
                copied
            })
        })
        .await
        .map_err(|e| StorageError::Backend(anyhow::anyhow!("blocking task failed: {e}")))?
        .map_err(|e| StorageError::Backend(e.into()))?;
        info!(size_bytes = size, "snapshot taken");
        Ok(taken(size))
    }

    #[instrument(skip_all, fields(snapshot_id = %handle.id))]
    async fn drop_snapshot(&self, handle: &VolumeHandle) -> storage::Result<()> {
        let dir = &self.config.volume_dir;
        // Every staging copy of this snapshot, whoever made it: the object
        // is their owner, and it is going (R3-F09).
        let mut doomed = staging::staged_for(dir, &handle.id, true)
            .map_err(|e| StorageError::Backend(e.into()))?;
        doomed.push(staging::legacy_snapshot_copy(dir, &handle.id));
        doomed.push(self.snapshot_path(&handle.id));
        for p in doomed {
            match tokio::fs::remove_file(&p).await {
                Ok(()) => debug!(path = %p.display(), "snapshot removed"),
                Err(e) if e.kind() == ErrorKind::NotFound => {}
                Err(e) => return Err(StorageError::Backend(e.into())),
            }
        }
        Ok(())
    }

    #[instrument(skip_all, fields(volume_id = %id, from = %snapshot.backend))]
    async fn provision_from(
        &self,
        id: &VolumeId,
        snapshot: &VolumeHandle,
        spec: &VolumeSpec,
    ) -> storage::Result<VolumeHandle> {
        let path = layout::volume_path(&self.config.volume_dir, id);
        let handle = |size_bytes| VolumeHandle {
            id: *id,
            backend: path.to_string_lossy().into_owned(),
            size_bytes,
            params: spec.params.clone(),
        };
        // Reuse a completed volume on repeated provisioning.
        if let Ok(meta) = tokio::fs::metadata(&path).await {
            debug!(size_bytes = meta.len(), "volume already exists");
            return Ok(handle(meta.len()));
        }
        let src = snapshot.path();
        let taken = tokio::fs::metadata(&src)
            .await
            .map_err(|_| StorageError::NotFound(snapshot.id))?
            .len();
        // Reject targets smaller than the snapshot; larger targets receive zero padding.
        if spec.size_bytes < taken {
            return Err(StorageError::InvalidSpec(format!(
                "size_bytes {} smaller than the snapshot ({taken} bytes)",
                spec.size_bytes
            )));
        }
        // The same staging name `provision` uses, for the same reason.
        let staged = staging::Staged::begin(staging::volume_build(
            &self.config.volume_dir,
            id,
            &self.host,
        ));
        let (from, target, size) = (src, path.clone(), spec.size_bytes);
        let span = Span::current();
        tokio::task::spawn_blocking(move || -> std::io::Result<()> {
            span.in_scope(|| {
                let to = staged.path();
                let done = (|| {
                    layout::clone_or_copy(&from, to)?;
                    let f = std::fs::OpenOptions::new().write(true).open(to)?;
                    f.set_len(size)?;
                    f.sync_all()?;
                    std::fs::rename(to, &target)
                })();
                // Under a nonce name a failed attempt's file is never reused
                // by the next one, so it goes with the failure here rather
                // than lingering until the next agent start.
                if done.is_err() {
                    let _ = std::fs::remove_file(to);
                }
                done
            })
        })
        .await
        .map_err(|e| StorageError::Backend(anyhow::anyhow!("blocking task failed: {e}")))?
        .map_err(|e| StorageError::Backend(e.into()))?;
        info!("volume ready from snapshot");
        Ok(handle(spec.size_bytes))
    }

    fn locality(&self) -> Locality {
        Locality::NodeLocal
    }

    #[instrument(level = "trace", skip_all, fields(volume_id = %handle.id))]
    async fn describe(&self, handle: &VolumeHandle) -> storage::Result<VolumeState> {
        self.measure(&handle.id).await
    }

    /// Probe the final or unfinished volume path for cleanup. A temporary file
    /// yields a handle naming the final path, with size zero.
    #[instrument(level = "trace", skip_all, fields(volume_id = %id))]
    async fn probe(
        &self,
        id: &VolumeId,
        spec: &VolumeSpec,
    ) -> storage::Result<Option<VolumeHandle>> {
        let path = layout::volume_path(&self.config.volume_dir, id);
        let dir = &self.config.volume_dir;
        let size = match Self::size_if_already_there(&path).await? {
            Some(size) => Some(size),
            // A staging file of any host counts, and the legacy name too.
            None => {
                let staged = staging::staged_for(dir, id, false)
                    .map_err(|e| StorageError::Backend(e.into()))?;
                let legacy = Self::size_if_already_there(&staging::legacy_volume_build(dir, id))
                    .await?
                    .is_some();
                (legacy || !staged.is_empty()).then_some(0)
            }
        };
        Ok(size.map(|size_bytes| VolumeHandle {
            id: *id,
            backend: path.to_string_lossy().into_owned(),
            size_bytes,
            params: spec.params.clone(),
        }))
    }

    /// And the snapshot beside it, named after the snapshot's own id. See
    /// `layout::snapshot_path`.
    #[instrument(level = "trace", skip_all, fields(snapshot_id = %id))]
    async fn probe_snapshot(
        &self,
        _volume: Option<&VolumeHandle>,
        id: &SnapshotId,
    ) -> storage::Result<Option<VolumeHandle>> {
        let path = self.snapshot_path(id);
        Ok(Self::size_if_already_there(&path)
            .await?
            .map(|size_bytes| VolumeHandle {
                id: *id,
                backend: path.to_string_lossy().into_owned(),
                size_bytes,
                params: None,
            }))
    }
}

/// Attach by returning the raw file path. Detach has no backend process to
/// stop; the caller must ensure the VMM has closed its own file descriptor.
#[async_trait::async_trait]
impl VolumeAttacher for FilesystemBlockDriver {
    #[instrument(level = "trace", skip_all, fields(volume_id = %handle.id))]
    async fn attach(
        &self,
        handle: &VolumeHandle,
        _cgroup: Option<&CgroupHandle>,
    ) -> storage::Result<VolumeAttachment> {
        Ok(VolumeAttachment::Path(handle.path()))
    }

    #[instrument(level = "trace", skip_all, fields(volume_id = %handle.id))]
    async fn stat(
        &self,
        handle: &VolumeHandle,
        _attachment: &VolumeAttachment,
    ) -> storage::Result<VolumeState> {
        self.measure(&handle.id).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use agent_api::storage::VolumeSpec;
    use staging::{PROBE_PREFIX, SNAP_TMP};
    use uuid::Uuid;

    /// Every destination this test's sandbox was asked to hand over or take
    /// back, in order.
    type HandedOver = std::sync::Arc<std::sync::Mutex<Vec<(PathBuf, u32, u32)>>>;

    /// Fixture sandbox with a scripted systemd-run, synthetic UID resolution
    /// and recorded chowns. When `runs` is true, the script executes the command
    /// after `--`; no privileged account setup is required.
    fn sandboxed(root: &Path, runs: bool) -> (agent_api::base_image::Sandbox, HandedOver) {
        use std::os::unix::fs::PermissionsExt;
        let bin = root.join("bin");
        std::fs::create_dir_all(&bin).expect("a bin dir");
        let log = root.join("systemd-run.log").display().to_string();
        let body = if runs {
            format!(
                "echo \"$@\" >> \"{log}\"\n\
                 while [ $# -gt 0 ] && [ \"$1\" != \"--\" ]; do shift; done\n\
                 shift\n\
                 exec \"$@\"\n"
            )
        } else {
            format!(
                "echo \"$@\" >> \"{log}\"\n\
                 echo 'Failed to start transient service unit' >&2\n\
                 exit 1\n"
            )
        };
        let script = bin.join("systemd-run");
        std::fs::write(&script, format!("#!/bin/sh\n{body}")).expect("the script");
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755))
            .expect("runnable");

        let handed_over: HandedOver = Default::default();
        let recorder = handed_over.clone();
        let sandbox = agent_api::base_image::Sandbox::new(script).resolved_as(
            4242,
            4343,
            std::sync::Arc::new(move |path: &Path, uid, gid| {
                recorder.lock().expect("the recorded hand-overs").push((
                    path.to_path_buf(),
                    uid,
                    gid,
                ));
                Ok(())
            }),
        );
        (sandbox, handed_over)
    }

    /// Temporary filesystem driver and resource paths. Retain the first tuple
    /// item to keep the directory alive throughout the test.
    fn driver(tag: &str) -> (tempfile::TempDir, FilesystemBlockDriver, PathBuf, PathBuf) {
        let (temp, driver, volumes, images, _) = sandboxed_driver(tag, "qemu-img", true);
        (temp, driver, volumes, images)
    }

    /// Driver fixture with selectable conversion executable, startup outcome and ownership log.
    fn sandboxed_driver(
        tag: &str,
        qemu_img: &str,
        runs: bool,
    ) -> (
        tempfile::TempDir,
        FilesystemBlockDriver,
        PathBuf,
        PathBuf,
        HandedOver,
    ) {
        let temp = tempfile::Builder::new()
            .prefix(&format!("meister-fs-{tag}-"))
            .tempdir()
            .expect("a temp dir");
        let root = temp.path().to_path_buf();
        let images = root.join("images");
        let volumes = root.join("volumes");
        std::fs::create_dir_all(&images).expect("a temp image dir");
        let _ = std::fs::remove_dir_all(&volumes);
        let (sandbox, handed_over) = sandboxed(&root, runs);
        let qemu_img = match qemu_img.contains('/') {
            true => root.join(qemu_img),
            false => PathBuf::from(qemu_img),
        };
        let driver = FilesystemBlockDriver::new(FilesystemDriverConfig {
            image_dir: images.clone(),
            volume_dir: volumes.clone(),
            qemu_img,
            convert: sandbox,
            host_id: "test-node".into(),
        })
        .expect("the driver builds");
        (temp, driver, volumes, images, handed_over)
    }

    /// Every staging copy of this snapshot in the pool, of any host, under
    /// either name.
    fn staged_copies(volumes: &Path, snap: &SnapshotId) -> Vec<String> {
        std::fs::read_dir(volumes)
            .expect("the pool")
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.starts_with(&format!("{snap}{SNAP_TMP}")))
            .collect()
    }

    fn spec(size_bytes: u64) -> VolumeSpec {
        VolumeSpec {
            base_image: None,
            size_bytes,
            driver: None,
            params: None,
        }
    }

    /// Detect qcow2 by its header without invoking qemu-img for raw images.
    #[test]
    fn only_a_qcow2_looks_like_a_qcow2() {
        let temp = tempfile::tempdir().expect("a temp dir");
        let dir = temp.path().to_path_buf();

        let qcow = dir.join("q.img");
        std::fs::write(&qcow, b"QFI\xfb\x00\x00\x00\x03rest").expect("write");
        assert!(is_qcow2(&qcow).expect("readable"));

        let raw = dir.join("r.img");
        std::fs::write(&raw, vec![0u8; 4096]).expect("write");
        assert!(!is_qcow2(&raw).expect("readable"));

        // Shorter than the magic. Not a qcow2, and not an error either: the
        // caller has already stat'ed the file and this is a content question.
        let stub = dir.join("s.img");
        std::fs::write(&stub, b"QF").expect("write");
        assert!(!is_qcow2(&stub).expect("readable"));
    }

    /// Use qemu-img when available to verify qcow2 conversion produces a raw file
    /// of the requested virtual size. The test returns early if qemu-img is absent.
    #[tokio::test]
    async fn a_qcow2_base_image_is_written_out_raw() {
        let Ok(out) = std::process::Command::new("qemu-img")
            .arg("--version")
            .output()
        else {
            eprintln!("qemu-img is not here; nothing to convert with");
            return;
        };
        assert!(out.status.success(), "qemu-img --version failed");

        let (_temp, driver, volumes, images) = driver("qcow2");
        let base = images.join("base.qcow2");
        let _ = std::fs::remove_file(&base);
        let made = std::process::Command::new("qemu-img")
            .args(["create", "-f", "qcow2"])
            .arg(&base)
            .arg("16M")
            .output()
            .expect("qemu-img create");
        assert!(made.status.success(), "qemu-img create failed");
        assert!(
            is_qcow2(&base).expect("readable"),
            "the base really is qcow2"
        );

        let id = Uuid::new_v4();
        let mut want = spec(32 * 1024 * 1024);
        want.base_image = Some("base.qcow2".to_string());
        driver.provision(&id, &want).await.expect("provisioned");

        let path = volumes.join(format!("{id}.raw"));
        assert!(
            !is_qcow2(&path).expect("readable"),
            "the volume the VMM is handed must be raw, whatever the base was"
        );
        assert_eq!(
            std::fs::metadata(&path).expect("stat").len(),
            32 * 1024 * 1024,
            "and it must be the size that was asked for"
        );
    }

    /// Validate qcow2 virtual size rather than its smaller on-disk file length.
    #[tokio::test]
    async fn a_qcow2_is_measured_by_what_it_unpacks_to() {
        let Ok(out) = std::process::Command::new("qemu-img")
            .arg("--version")
            .output()
        else {
            eprintln!("qemu-img is not here; nothing to measure with");
            return;
        };
        assert!(out.status.success(), "qemu-img --version failed");

        let (_temp, driver, _volumes, images) = driver("qcow2-size");
        let base = images.join("big.qcow2");
        let _ = std::fs::remove_file(&base);
        assert!(
            std::process::Command::new("qemu-img")
                .args(["create", "-f", "qcow2"])
                .arg(&base)
                .arg("64M")
                .output()
                .expect("qemu-img create")
                .status
                .success()
        );
        assert!(
            std::fs::metadata(&base).expect("stat").len() < 8 * 1024 * 1024,
            "the point of the test: the FILE is much smaller than the disk"
        );

        let mut want = spec(8 * 1024 * 1024);
        want.base_image = Some("big.qcow2".to_string());
        let err = driver
            .provision(&Uuid::new_v4(), &want)
            .await
            .expect_err("8M cannot hold a 64M disk");
        let text = format!("{err}");
        assert!(
            text.contains("64"),
            "the number is the unpacked one: {text}"
        );
        assert!(
            text.contains("once written out raw"),
            "and it says so: {text}"
        );
    }

    /// Scripted qemu-img reporting a 4 MiB virtual disk and recording conversion calls.
    fn fake_qemu_img(root: &Path) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let bin = root.join("bin");
        std::fs::create_dir_all(&bin).expect("a bin dir");
        let ran = root.join("qemu-ran").display().to_string();
        let script = bin.join("qemu-img");
        std::fs::write(
            &script,
            format!(
                "#!/bin/sh\n\
                 echo \"$@\" >> \"{ran}\"\n\
                 if [ \"$1\" = info ]; then\n\
                 echo '{{\"virtual-size\": 4194304, \"format\": \"qcow2\"}}'\n\
                 fi\n"
            ),
        )
        .expect("the script");
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755))
            .expect("runnable");
        root.join("qemu-ran")
    }

    /// A qcow2 by its first four bytes, which is all this driver looks at
    /// before it asks the probe.
    fn a_qcow2(at: &Path) {
        std::fs::write(at, b"QFI\xfb\x00\x00\x00\x03and the rest").expect("the bytes");
    }

    /// Inspect sandbox command arguments and ownership handoffs; the fake does not
    /// exercise kernel isolation or the converter itself.
    #[tokio::test]
    async fn the_image_is_read_and_written_inside_the_unit_and_nowhere_else() {
        let (temp, driver, volumes, images, handed_over) =
            sandboxed_driver("sandbox", "bin/qemu-img", true);
        let root = temp.path().to_path_buf();
        let ran = fake_qemu_img(&root);
        let base = images.join("base.qcow2");
        a_qcow2(&base);

        let id = Uuid::new_v4();
        let mut want = spec(8 * 1024 * 1024);
        want.base_image = Some("base.qcow2".to_string());
        driver.provision(&id, &want).await.expect("provisioned");

        let log = std::fs::read_to_string(root.join("systemd-run.log")).expect("the two runs");
        let lines: Vec<&str> = log.lines().collect();
        // The staging name carries this host and a nonce since R3-F09, so it
        // is read off the conversion's own command line and then checked.
        let tmp = PathBuf::from(
            lines[1]
                .split_whitespace()
                .find_map(|w| w.strip_prefix("BindPaths="))
                .expect("a writable bind"),
        );
        assert_eq!(tmp.parent(), Some(volumes.as_path()));
        assert!(
            tmp.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with(&format!("{id}.tmp.test-node."))),
            "{}",
            tmp.display()
        );
        assert!(!tmp.exists(), "and it was renamed into place");
        assert_eq!(lines.len(), 2, "the probe and the conversion: {log}");
        for line in &lines {
            for property in [
                "User=meister-convert",
                "NoNewPrivileges=yes",
                "CapabilityBoundingSet=",
                "PrivateNetwork=yes",
                // Empty, not `none`: `systemd-run` refuses the word a
                // unit file would use. The trailing space is what makes
                // this an assertion about the empty value.
                "RestrictAddressFamilies= ",
                "ProtectSystem=strict",
                "ProtectHome=yes",
                "PrivateTmp=yes",
                "SystemCallFilter=@system-service",
                "MemoryMax=",
                "CPUQuota=",
                "RuntimeMaxSec=",
                "--wait",
                "--pipe",
                "--collect",
                "--quiet",
            ] {
                assert!(line.contains(property), "{property} is missing from {line}");
            }
            assert!(
                line.contains(&format!("BindReadOnlyPaths={}", base.display())),
                "the image is read-only: {line}"
            );
        }
        assert!(
            !lines[0].contains("BindPaths="),
            "the probe writes nothing: {}",
            lines[0]
        );
        // Allow writes only to the staging file, not other volumes in its parent directory.
        let writable: Vec<&str> = lines[1]
            .split_whitespace()
            .filter(|word| word.starts_with("BindPaths="))
            .collect();
        assert_eq!(
            writable,
            vec![format!("BindPaths={}", tmp.display())],
            "the conversion writes the tmp file and nothing else: {}",
            lines[1]
        );

        // Transfer and restore the staging file ownership around conversion.
        let handed_over = handed_over.lock().expect("the hand-overs").clone();
        assert_eq!(handed_over.len(), 2, "{handed_over:?}");
        assert!(
            handed_over.iter().all(|(path, _, _)| *path == tmp),
            "{handed_over:?}"
        );
        assert_eq!(handed_over[0].1, 4242, "to the converter first");
        assert_ne!(handed_over[1].1, 4242, "and back to the agent after");

        assert!(ran.exists(), "qemu-img did run — inside the unit");
        assert!(
            volumes.join(format!("{id}.raw")).exists(),
            "and the volume is there"
        );
    }

    /// Sandbox startup failure must not fall back to conversion in the agent process.
    #[tokio::test]
    async fn a_unit_that_does_not_start_refuses_rather_than_converting_here() {
        let (temp, driver, volumes, images, _) = sandboxed_driver("no-unit", "bin/qemu-img", false);
        let root = temp.path().to_path_buf();
        let ran = fake_qemu_img(&root);
        a_qcow2(&images.join("base.qcow2"));

        let id = Uuid::new_v4();
        let mut want = spec(8 * 1024 * 1024);
        want.base_image = Some("base.qcow2".to_string());
        let err = driver
            .provision(&id, &want)
            .await
            .expect_err("nothing is converted outside the unit");

        let said = format!("{err:#}");
        assert!(
            said.contains("Failed to start transient service unit"),
            "the refusal carries what systemd said: {said}"
        );
        assert!(!ran.exists(), "qemu-img was never started: {said}");
        assert!(
            !volumes.join(format!("{id}.raw")).exists(),
            "and no volume was made"
        );
    }

    /// A filesystem volume attaches directly as its raw-file path.
    #[tokio::test]
    async fn provision_then_attach_is_what_one_create_used_to_return() {
        let (_temp, driver, volumes, _images) = driver("degenerate");
        let id = Uuid::new_v4();

        let handle = driver
            .provision(&id, &spec(4096))
            .await
            .expect("provisioned");
        assert_eq!(handle.id, id);
        assert_eq!(handle.size_bytes, 4096);
        assert_eq!(handle.path(), volumes.join(format!("{id}.raw")));

        // The bytes are there before anything is attached to them: that is
        // the sentence the split exists to make true.
        let meta = std::fs::metadata(handle.path()).expect("the file exists after provision alone");
        assert_eq!(meta.len(), 4096);

        let attachment = driver.attach(&handle, None).await.expect("attached");
        match &attachment {
            VolumeAttachment::Path(p) => assert_eq!(p, &volumes.join(format!("{id}.raw"))),
            other => panic!("a file is a path, not {other:?}"),
        }
        // File attachments need neither shared memory nor a backend process.
        assert!(attachment.is_block());
        assert!(!attachment.needs_shared_memory());
        assert_eq!(attachment.backend_pid(), None);
    }

    /// File attachment needs no backend process; detach leaves volume data unchanged.
    #[tokio::test]
    async fn a_file_survives_a_detach_untouched() {
        let (_temp, driver, _, _) = driver("detach");
        let id = Uuid::new_v4();
        let handle = driver.provision(&id, &spec(2048)).await.unwrap();
        let attachment = driver.attach(&handle, None).await.unwrap();

        driver
            .detach(&handle, &attachment)
            .await
            .expect("nothing to do");
        assert_eq!(
            driver.describe(&handle).await.expect("still there"),
            VolumeState { size_bytes: 2048 },
            "detaching a file must not touch the file"
        );
        // Stat and describe return the same file measurement.
        assert_eq!(
            driver.stat(&handle, &attachment).await.unwrap(),
            VolumeState { size_bytes: 2048 }
        );
    }

    /// Deprovision data idempotently without requiring a live attachment.
    #[tokio::test]
    async fn deprovision_needs_no_attachment_and_is_idempotent() {
        let (_temp, driver, _, _) = driver("deprovision");
        let id = Uuid::new_v4();
        let handle = driver.provision(&id, &spec(1024)).await.unwrap();

        driver.deprovision(&handle).await.expect("removed");
        assert!(matches!(
            driver.describe(&handle).await,
            Err(StorageError::NotFound(gone)) if gone == id
        ));
        // Twice is Ok: teardown runs again after a crash between the two
        // halves of it.
        driver.deprovision(&handle).await.expect("idempotent");
    }

    /// ID-derived paths let probe recover the original inode after a lost handle.
    #[tokio::test]
    async fn a_lost_handle_finds_the_same_volume_rather_than_making_a_second() {
        let (_temp, driver, _, _) = driver("idempotent");
        let id = Uuid::new_v4();

        let first = driver.provision(&id, &spec(4096)).await.unwrap();
        // The size the second call asks for is deliberately different: what
        // comes back has to be the volume that EXISTS, not a new one.
        let again = driver.provision(&id, &spec(8192)).await.unwrap();
        assert_eq!(first.backend, again.backend);
        assert_eq!(
            again.size_bytes, 4096,
            "the volume that is there is the answer"
        );
    }

    /// Filesystem volumes advertise node-local placement.
    #[test]
    fn a_file_in_a_directory_is_node_local() {
        let (_temp, d, _, _) = driver("locality");
        assert_eq!(d.locality(), Locality::NodeLocal);
    }

    /// A completed snapshot has the source content and a distinct inode.
    #[tokio::test]
    async fn a_snapshot_is_a_copy_with_the_same_content_and_its_own_inode() {
        use std::os::unix::fs::MetadataExt;
        let (_temp, driver, volumes, _) = driver("snapshot");
        assert_eq!(
            driver.snapshot_support(),
            Some(SnapshotConsistency::NeedsQuiesce),
            "this backend copies, so the writes have to stop while it does"
        );

        let id = Uuid::new_v4();
        let handle = driver.provision(&id, &spec(4096)).await.expect("a volume");
        std::fs::write(handle.path(), b"the data as it was").expect("written");

        let snap_id = Uuid::new_v4();
        let taken = driver
            .snapshot(&handle, &snap_id)
            .await
            .expect("a snapshot");
        assert_eq!(taken.id, snap_id, "the handle names the copy, not the disk");
        assert_eq!(std::fs::read(taken.path()).unwrap(), b"the data as it was");
        assert_ne!(
            std::fs::metadata(handle.path()).unwrap().ino(),
            std::fs::metadata(taken.path()).unwrap().ino(),
            "a second name for one inode would follow the volume into its next write"
        );

        // Independent from here on: the volume moves, the copy does not.
        std::fs::write(handle.path(), b"and as it is now!!").expect("written");
        assert_eq!(
            std::fs::read(taken.path()).unwrap(),
            b"the data as it was",
            "the whole point of a point in time"
        );

        // Idempotent, like every other create in this tree: asked twice, the
        // second call finds the first one's copy rather than making a second.
        let again = driver
            .snapshot(&handle, &snap_id)
            .await
            .expect("idempotent");
        assert_eq!(again.backend, taken.backend);
        assert_eq!(
            std::fs::read(again.path()).unwrap(),
            b"the data as it was",
            "and it did not re-copy the volume's newer bytes"
        );

        // A new volume out of the copy: the snapshot's content, its own file,
        // and padded up to the size asked for.
        let clone_id = Uuid::new_v4();
        let cloned = driver
            .provision_from(&clone_id, &taken, &spec(8192))
            .await
            .expect("a volume from a snapshot");
        assert_eq!(cloned.size_bytes, 8192);
        let bytes = std::fs::read(cloned.path()).unwrap();
        assert_eq!(&bytes[..18], b"the data as it was");
        assert_eq!(bytes.len(), 8192, "grown, and the rest is zeros");
        assert_ne!(
            std::fs::metadata(taken.path()).unwrap().ino(),
            std::fs::metadata(cloned.path()).unwrap().ino()
        );

        // Reject restoration into a smaller target without truncating data.
        let small = driver
            .provision_from(&Uuid::new_v4(), &taken, &spec(8))
            .await
            .expect_err("a volume smaller than the data in it");
        assert!(matches!(small, StorageError::InvalidSpec(_)), "{small:?}");

        // And dropping it is idempotent, again like everything else.
        driver.drop_snapshot(&taken).await.expect("dropped");
        driver.drop_snapshot(&taken).await.expect("still dropped");
        assert!(!taken.path().exists());
        // The volume it came from is untouched by any of that.
        assert_eq!(std::fs::read(handle.path()).unwrap(), b"and as it is now!!");

        let _ = std::fs::remove_dir_all(volumes.parent().unwrap());
    }

    /// Growth retains the inode; repeated or smaller requests preserve existing size and content.
    #[tokio::test]
    async fn a_volume_grows_in_place_and_never_shrinks() {
        let (_temp, driver, volumes, _) = driver("resize");
        let id = Uuid::new_v4();
        let handle = driver.provision(&id, &spec(4096)).await.expect("a volume");
        std::fs::write(handle.path(), vec![7u8; 4096]).expect("written");

        let grown = driver.resize(&handle, 8192).await.expect("grown");
        assert_eq!(grown.size_bytes, 8192);
        assert_eq!(
            std::fs::metadata(grown.path()).unwrap().len(),
            8192,
            "the file is what the handle says it is"
        );
        let bytes = std::fs::read(grown.path()).unwrap();
        assert_eq!(&bytes[..4096], &[7u8; 4096], "the data is untouched");
        assert_eq!(&bytes[4096..], &[0u8; 4096], "and the rest is a hole");
        // The handle keeps everything else it carried; only the size moved.
        assert_eq!(grown.backend, handle.backend);
        assert_eq!(grown.id, handle.id);

        // Repeating the same resize is a no-op.
        let again = driver.resize(&grown, 8192).await.expect("idempotent");
        assert_eq!(again.size_bytes, 8192);

        // And a GiB is a multiple of the sector size by construction, which
        // is what `vm.resize-disk` requires of the second half.
        assert_eq!((1u64 << 30) % 512, 0);

        let refused = driver
            .resize(&grown, 4096)
            .await
            .expect_err("shrinking takes data");
        match &refused {
            StorageError::InvalidSpec(said) => {
                assert!(
                    said.contains("shrinking a volume is not supported"),
                    "{said}"
                )
            }
            other => panic!("{other:?}"),
        }
        assert_eq!(
            std::fs::metadata(grown.path()).unwrap().len(),
            8192,
            "and it did not half-happen"
        );

        // A volume that is not there is `NotFound`, not a fresh file.
        let ghost = VolumeHandle {
            id: Uuid::new_v4(),
            backend: volumes.join("nothing.raw").to_string_lossy().into_owned(),
            size_bytes: 1,
            params: None,
        };
        assert!(matches!(
            driver.resize(&ghost, 4096).await,
            Err(StorageError::NotFound(_))
        ));

        let _ = std::fs::remove_dir_all(volumes.parent().unwrap());
    }

    /// Probe reflink support on the pool filesystem and remove probe files afterwards.
    #[test]
    fn the_probe_answers_for_the_pool_directory_and_leaves_nothing_in_it() {
        let (_temp, driver, volumes, _images) = driver("reflink");

        let probed = probe_reflink(&volumes, &driver.host);
        assert_eq!(
            driver.snapshot_support(),
            Some(probed),
            "what the driver claims is what the probe found"
        );
        assert!(
            matches!(
                probed,
                SnapshotConsistency::Atomic | SnapshotConsistency::NeedsQuiesce
            ),
            "one of the two, never a refusal: this backend can always copy"
        );

        // Probe files must be removed after startup.
        let leftovers: Vec<String> = std::fs::read_dir(&volumes)
            .expect("the pool directory")
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.contains("reflink-probe"))
            .collect();
        assert!(leftovers.is_empty(), "the probe cleaned up: {leftovers:?}");

        // Repeated probes and driver instances agree on the mount's reflink support.
        assert_eq!(probe_reflink(&volumes, &driver.host), probed);

        // Cross-check reflink support with `cp --reflink=always` so a broken probe
        // cannot pass merely by returning the same false value on every filesystem.
        let a = volumes.join("oracle-src");
        let b = volumes.join("oracle-dst");
        std::fs::write(&a, [0u8; PROBE_BYTES]).expect("a file to clone");
        let _ = std::fs::remove_file(&b);
        if let Ok(out) = std::process::Command::new("cp")
            .arg("--reflink=always")
            .arg(&a)
            .arg(&b)
            .output()
        {
            let coreutils = match out.status.success() {
                true => SnapshotConsistency::Atomic,
                false => SnapshotConsistency::NeedsQuiesce,
            };
            assert_eq!(
                probed,
                coreutils,
                "the probe and `cp --reflink=always` disagree about {}: {}",
                volumes.display(),
                String::from_utf8_lossy(&out.stderr).trim()
            );
        }
        let _ = std::fs::remove_file(&a);
        let _ = std::fs::remove_file(&b);

        // A directory that does not exist cannot be probed, and that is
        // `NeedsQuiesce` and not a panic: the safe direction costs a pause.
        assert_eq!(
            probe_reflink(&volumes.join("no-such-pool"), &driver.host),
            SnapshotConsistency::NeedsQuiesce
        );

        let _ = std::fs::remove_dir_all(volumes.parent().unwrap());
    }

    /// A copy failure must leave neither a final snapshot nor its temporary file.
    #[tokio::test]
    async fn a_failed_snapshot_leaves_nothing_behind() {
        let (_temp, driver, volumes, _) = driver("snap-tmp");
        let id = VolumeId::new_v4();
        let snap = SnapshotId::new_v4();

        // A "volume" that is a directory: `File::open` succeeds on it and the
        // copy then fails, which is the shape of every mid-copy failure.
        let backend = volumes.join(format!("{id}.raw"));
        std::fs::create_dir_all(&backend).expect("a source that cannot be copied");
        let handle = VolumeHandle {
            id,
            backend: backend.to_string_lossy().into_owned(),
            size_bytes: 4096,
            params: None,
        };

        driver
            .snapshot(&handle, &snap)
            .await
            .expect_err("the copy cannot work");

        assert!(
            staged_copies(&volumes, &snap).is_empty(),
            "the half-written copy is gone"
        );
        assert!(
            !driver.snapshot_path(&snap).exists(),
            "and nothing was renamed into place either"
        );

        let _ = std::fs::remove_dir_all(volumes.parent().unwrap());
    }

    /// Compare the logical copy size with available space before starting a snapshot.
    #[tokio::test]
    async fn a_snapshot_that_does_not_fit_is_refused_before_a_byte_is_written() {
        let temp = tempfile::tempdir().expect("a temp dir");
        let root = temp.path().to_path_buf();
        let images = root.join("images");
        let volumes = root.join("volumes");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&images).expect("a temp image dir");
        std::fs::create_dir_all(&volumes).expect("a temp volume dir");
        let config = |volume_dir: &PathBuf| FilesystemDriverConfig {
            image_dir: images.clone(),
            volume_dir: volume_dir.clone(),
            qemu_img: PathBuf::from("qemu-img"),
            convert: agent_api::base_image::Sandbox::default(),
            host_id: "test-node".into(),
        };

        let copying = FilesystemBlockDriver {
            config: config(&volumes),
            snapshot_consistency: SnapshotConsistency::NeedsQuiesce,
            host: staging::HostTag::new("test-node").unwrap(),
            hold: Default::default(),
            room: layout::Room::default(),
        };

        let id = VolumeId::new_v4();
        let snap = SnapshotId::new_v4();
        let backend = volumes.join(format!("{id}.raw"));
        // Sparse, and bigger than any filesystem this test could be running
        // on: the copy is what needs the room, not what is written today.
        let volume = std::fs::File::create(&backend).expect("a volume");
        let needed = u64::MAX / 2;
        volume.set_len(needed).expect("a sparse claim");
        drop(volume);

        let handle = VolumeHandle {
            id,
            backend: backend.to_string_lossy().into_owned(),
            size_bytes: needed,
            params: None,
        };
        let refused = copying
            .snapshot(&handle, &snap)
            .await
            .expect_err("it does not fit");
        let said = format!("{refused}");
        assert!(
            said.contains("not enough room") && said.contains("nothing has been written"),
            "the refusal says what an operator has to do: {said}"
        );
        assert!(staged_copies(&volumes, &snap).is_empty(), "and it means it");

        // A pool that reflinks is not asked the question at all: a clone of a
        // 4 TiB volume occupies no new extents, and refusing it over free
        // space would be refusing the operation this backend is best at.
        let cloning = FilesystemBlockDriver {
            config: config(&volumes),
            snapshot_consistency: SnapshotConsistency::Atomic,
            host: staging::HostTag::new("test-node").unwrap(),
            hold: Default::default(),
            room: layout::Room::default(),
        };
        let nothing = cloning
            .room_for_a_copy(needed)
            .expect("a reflink needs no room");
        assert!(
            nothing.is_none(),
            "and it holds nothing back from anybody else either"
        );
    }

    /// Recheck available space for each copy rather than relying on cached capacity.
    #[test]
    fn a_second_copy_measures_the_room_the_first_one_is_using() {
        let temp = tempfile::tempdir().expect("a temp dir");
        let dir = temp.path();
        let room = layout::Room::default();

        // Reserve almost all free space so a second equal reservation cannot fit.
        let stat = nix::sys::statvfs::statvfs(dir).expect("a filesystem");
        let free = stat.blocks_available() as u64 * stat.fragment_size() as u64;
        assert!(free > 8192, "this test needs a temp dir with some room");
        let half = free / 2;

        let first = room.reserve(dir, half).expect("the first copy fits");
        let refused = room
            .reserve(dir, free)
            .expect_err("and the whole pool no longer does");
        let said = format!("{refused}");
        assert!(
            said.contains("already promised"),
            "the refusal says why df disagrees with it: {said}"
        );

        // Dropping the guard releases the in-memory capacity reservation.
        drop(first);
        let _second = room
            .reserve(dir, half)
            .expect("the room the first copy held is free again");
    }

    /// Opening a pool removes this host's abandoned staging and probe files and
    /// nothing else; foreign and legacy names are `staging`'s own tests (R3-F09).
    #[test]
    fn opening_a_pool_throws_away_what_a_killed_process_left() {
        let temp = tempfile::tempdir().expect("a temp dir");
        let root = temp.path().to_path_buf();
        let images = root.join("images");
        let volumes = root.join("volumes");
        std::fs::create_dir_all(&images).expect("a temp image dir");
        std::fs::create_dir_all(&volumes).expect("a temp volume dir");

        let me = staging::HostTag::new("test-node").unwrap();
        let orphan = staging::snapshot_copy(&volumes, &SnapshotId::new_v4(), &me);
        let half_volume = staging::volume_build(&volumes, &VolumeId::new_v4(), &me);
        let (probe_src, probe_dst) = staging::probe_pair(&volumes, &me);
        let finished = volumes.join("bbbb.snap");
        let volume = volumes.join("cccc.raw");
        for p in [
            &orphan,
            &half_volume,
            &finished,
            &volume,
            &probe_src,
            &probe_dst,
        ] {
            std::fs::write(p, b"x").expect("a file");
        }

        FilesystemBlockDriver::new(FilesystemDriverConfig {
            image_dir: images,
            volume_dir: volumes.clone(),
            qemu_img: PathBuf::from("qemu-img"),
            convert: agent_api::base_image::Sandbox::default(),
            host_id: "test-node".into(),
        })
        .expect("the driver builds");

        assert!(!orphan.exists(), "the unfinished copy is gone");
        assert!(!half_volume.exists(), "and the unfinished volume");
        assert!(!probe_src.exists(), "and so is a probe that never returned");
        assert!(!probe_dst.exists(), "both halves of it");
        assert!(finished.exists(), "the snapshot itself certainly is not");
        assert!(volume.exists(), "nor is anything else in the pool");

        // The driver that has just been built ran its own probe on the way
        // through, and cleaned up after itself: a pool this agent opened
        // holds no probe files at all afterwards.
        let left: Vec<String> = std::fs::read_dir(&volumes)
            .expect("the pool")
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.starts_with(PROBE_PREFIX))
            .collect();
        assert!(
            left.is_empty(),
            "the probe cleans up after itself: {left:?}"
        );
    }

    /// Astra finding R3-F09, 2026-09-25: two hosts share one pool (the nfs
    /// driver roots this driver in a share). Host A is in the middle of a
    /// snapshot copy when host B's agent starts. B's start-up sweep must
    /// leave A's copy alone, A's snapshot must publish, and an orphan of
    /// B's own host must still be removed.
    #[tokio::test]
    async fn another_hosts_running_snapshot_survives_this_hosts_start() {
        let temp = tempfile::tempdir().expect("a temp dir");
        let root = temp.path().to_path_buf();
        let images = root.join("images");
        let volumes = root.join("volumes");
        std::fs::create_dir_all(&images).expect("a temp image dir");
        let config = |host: &str| FilesystemDriverConfig {
            image_dir: images.clone(),
            volume_dir: volumes.clone(),
            qemu_img: PathBuf::from("qemu-img"),
            convert: agent_api::base_image::Sandbox::default(),
            host_id: host.into(),
        };
        let a = std::sync::Arc::new(FilesystemBlockDriver::new(config("node-a")).expect("A"));

        let id = VolumeId::new_v4();
        let backend = volumes.join(format!("{id}.raw"));
        std::fs::write(&backend, b"the volume's bytes").expect("a volume");
        let handle = VolumeHandle {
            id,
            backend: backend.to_string_lossy().into_owned(),
            size_bytes: 18,
            params: None,
        };
        let snap = SnapshotId::new_v4();

        let (staged_tx, staged_rx) = std::sync::mpsc::channel();
        let (go_tx, go_rx) = std::sync::mpsc::channel();
        *a.hold.lock().unwrap() = Some((staged_tx, go_rx));
        let copying = tokio::spawn({
            let a = a.clone();
            let handle = handle.clone();
            async move { a.snapshot(&handle, &snap).await }
        });
        let staged = tokio::task::spawn_blocking(move || staged_rx.recv().expect("A staged"))
            .await
            .unwrap();
        assert!(
            staged.exists(),
            "A's copy is on the pool: {}",
            staged.display()
        );

        // An orphan of B's own host, from B's previous agent.
        let b_tag = staging::HostTag::new("node-b").unwrap();
        let b_orphan = staging::snapshot_copy(&volumes, &SnapshotId::new_v4(), &b_tag);
        std::fs::write(&b_orphan, b"dead").expect("B's orphan");

        let _b = FilesystemBlockDriver::new(config("node-b")).expect("B starts");

        assert!(staged.exists(), "B's start left A's running copy alone");
        assert!(!b_orphan.exists(), "and removed its own host's orphan");

        go_tx.send(()).expect("A goes on");
        let taken = copying.await.unwrap().expect("A's snapshot publishes");
        assert_eq!(
            std::fs::read(taken.path()).expect("the snapshot"),
            b"the volume's bytes"
        );
        assert!(!staged.exists(), "renamed into place");
    }
}
