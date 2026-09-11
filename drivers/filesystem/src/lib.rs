// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

mod layout;

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
    /// Where `qemu-img` is, for the ONE case that needs it: a base image that
    /// is not raw. Unset = PATH, the same default `lvm-thin` takes for it and
    /// `nft` takes one module over. A node whose base images are all raw
    /// never runs it.
    pub qemu_img: PathBuf,
}

/// The qcow2 magic, and the whole of the format detection this driver does.
///
/// Four bytes rather than `qemu-img info` on every provision, deliberately:
/// the common case is a raw base image, that path has never needed a
/// subprocess, and a node without qemu-img has to keep working exactly as it
/// did. Anything that is not qcow2 is treated as raw and copied, which is
/// what this driver has always done.
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

/// How many bytes the reflink probe writes before trying to clone them.
///
/// One page. A clone of nothing is not a clone: a zero-length file gives the
/// kernel no extent to share, and while `FICLONE` on an empty file still
/// fails on a filesystem that cannot reflink, an answer arrived at from a
/// file with no data in it is one nobody would believe.
const PROBE_BYTES: usize = 4096;

/// What every file the reflink probe writes is called before the pid.
///
/// A constant and not two literals, because `probe_reflink` writes these
/// names and `sweep_leftovers` removes them: two spellings of one prefix in
/// two functions is how a sweep quietly stops finding anything.
const PROBE_PREFIX: &str = ".meister-reflink-probe-";

/// Whether the filesystem under `dir` can share extents between two files —
/// asked by doing it.
///
/// This is the probe the old `snapshot_support` comment rejected, and the
/// reason it is here now is that the objection was about a WEAKER probe. The
/// objection was that a probe "would have to be right about every mount
/// `volume_dir` might be on". It does not have to be right about every mount:
/// it has to be right about ONE, the pool's own directory, which is the only
/// place this backend ever writes a volume or a snapshot. A pool is a
/// directory, `snapshot_path` puts the copy beside the volume in that same
/// directory, and there is no second mount in the picture.
///
/// `FICLONE` and not a `copy_file_range` plus a look at `st_blocks`: the
/// ioctl is the exact question — "share these extents" — and it either
/// succeeds or fails with `EOPNOTSUPP`/`EXDEV`/`EINVAL`. Block accounting is
/// the inexact one: delayed allocation, compression and preallocation all
/// move `st_blocks` for reasons that have nothing to do with sharing, and a
/// probe that guessed from it would eventually guess `Atomic` on a filesystem
/// that copies. `cp --reflink` asks this way for the same reason.
///
/// Every failure — the ioctl, the two files, the write, a read-only mount —
/// is `NeedsQuiesce`. That is the direction where being wrong costs a pause
/// of a few milliseconds; the other direction costs a snapshot of a file
/// half-written, which nothing afterwards can detect.
fn probe_reflink(dir: &Path) -> SnapshotConsistency {
    use std::io::Write;
    use std::os::fd::AsRawFd;

    // Named after the process, so two agents over one directory — which
    // should not happen and does during a restart — do not probe into each
    // other's files.
    let src_path = dir.join(format!("{PROBE_PREFIX}{}.src", std::process::id()));
    let dst_path = dir.join(format!("{PROBE_PREFIX}{}.dst", std::process::id()));
    // Whatever this probe leaves behind goes, on every path out of it.
    let cleanup = || {
        let _ = std::fs::remove_file(&src_path);
        let _ = std::fs::remove_file(&dst_path);
    };
    cleanup();

    let answer = (|| -> std::io::Result<bool> {
        // READ and write. FICLONE reads the source, and a source opened
        // write-only is `EBADF` — which this probe would have reported as
        // "cannot reflink", quietly, on every filesystem including the ones
        // that can. The failure would have looked exactly like the answer.
        let mut src = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&src_path)?;
        src.write_all(&[0u8; PROBE_BYTES])?;
        src.sync_all()?;
        let dst = std::fs::File::create(&dst_path)?;
        // SAFETY: both descriptors are open for the duration of the call, and
        // FICLONE's argument IS the source descriptor as an integer rather
        // than a pointer into this process.
        let cloned = unsafe { ficlone(dst.as_raw_fd(), src.as_raw_fd() as u64) }.is_ok();
        if !cloned {
            return Ok(false);
        }
        // The cross-check the ioctl's return code does not give: a clone that
        // reported success and produced a file of a different length would
        // mean this kernel does not mean by FICLONE what this driver means.
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
        // Not a start-up failure. A pool whose directory would not take a
        // probe file has bigger problems and will report them at the first
        // provision, in a sentence about the volume somebody asked for.
        Err(e) => {
            debug!(dir = %dir.display(), error = %e,
                   "the reflink probe could not run; assuming this backend copies");
            SnapshotConsistency::NeedsQuiesce
        }
    }
}

/// FileSystemBlockDriver manages <vm_id>.raw files in a specified directory to support block
/// devices for MeisterStack it is the basic implementation and should be used as fallback.
pub struct FilesystemBlockDriver {
    config: FilesystemDriverConfig,
    /// Answered once, at construction, by [`probe_reflink`] over
    /// `volume_dir`. Once and not per call, for the reason the catalogue
    /// asks `locality` once: a filesystem does not learn to reflink while the
    /// agent runs, and a value read per Hello would be the same value read
    /// again — at the cost of two files in the pool directory every ten
    /// seconds.
    snapshot_consistency: SnapshotConsistency,
    /// What this pool has already promised to copies that are still running.
    /// See [`layout::Room`]: the space check used to be a `statvfs` and
    /// nothing else, which is a statement about a moment that has passed by
    /// the time the copy it approved is halfway through.
    room: layout::Room,
}

/// The suffix a snapshot copies into before it is renamed into place.
const SNAP_TMP: &str = ".snap.tmp";

/// Throw away what a killed process left in this pool: an unfinished
/// snapshot copy, and the reflink probe's own two files.
///
/// Run once, when the driver is built, which is once per pool per agent
/// start. Two shapes, one walk of the directory, because they are the same
/// fact from two sides — a file in a pool that no object names and no code
/// reads — and two walks would be two places to forget one.
///
/// **`<id>.snap.tmp`** is by construction unfinished work: the copy renames
/// it into `<id>.snap` as its last act, so a file still under the tmp name
/// belongs to an attempt that was killed, ran out of space, or lost its
/// process. Nothing reads it, no object names it, and `volumesnapshot rm`
/// does not reach it — it is pure occupied space, and in the chaos run it was
/// the 1,02 GiB that kept the node's root filesystem at 100 %.
///
/// A tmp file that DOES have its `<id>.snap` beside it is left alone. That
/// pair is the remains of a rename that lost a race with a second attempt,
/// the finished snapshot is the one that matters, and `drop_snapshot` already
/// removes both names when the object goes. Sweeping it here would be this
/// function reaching past what it can be sure of.
///
/// **`.meister-reflink-probe-<pid>.src`/`.dst`** are the probe's, and they
/// were the one file in a pool with no owner at all: `probe_reflink` cleans
/// up on every path out of itself, so what is left is a process that died
/// mid-probe, and up to 4 KiB then stayed under a pid name for ever. Small,
/// and the only leak in this directory nothing collected.
///
/// A probe belonging to a LIVE agent is swept too, and that is safe rather
/// than overlooked: `FICLONE` works on open descriptors, so unlinking the
/// path under a running probe changes neither its question nor its answer,
/// and that probe's own `cleanup` already tolerates a file that has gone.
/// Asking `/proc` whether the pid is alive would buy nothing — a pid comes
/// back, so the answer would be wrong in the other direction instead.
///
/// Every failure is a WARN and nothing more. A pool this cannot read is a
/// pool `probe_reflink` and the first provision will have their own opinion
/// about, and refusing to start over a leftover file would turn a wasted
/// gigabyte into an outage.
fn sweep_leftovers(dir: &Path) {
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) => {
            warn!(dir = %dir.display(), error = %e,
                  "could not look through the pool for leftovers");
            return;
        }
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        let what = if let Some(id) = name.strip_suffix(SNAP_TMP) {
            if dir.join(format!("{id}.snap")).exists() {
                continue;
            }
            "an unfinished snapshot was holding disk space nothing points at; removed"
        } else if name.starts_with(PROBE_PREFIX) {
            "a reflink probe died before it could clean up after itself; removed"
        } else {
            continue;
        };
        let size = entry.metadata().map(|m| m.len()).unwrap_or(0);
        match std::fs::remove_file(&path) {
            Ok(()) => warn!(path = %path.display(), size_bytes = size, "{what}"),
            Err(e) => warn!(path = %path.display(), error = %e,
                            "a leftover in this pool could not be removed"),
        }
    }
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
        // Before the probe, and before this pool serves anything: whatever a
        // killed snapshot or a killed probe left behind is occupying the room
        // the next one needs. See `sweep_leftovers`. Before the probe and not
        // after, so that the probe's own two files — written a line later and
        // removed on every path out of it — are never what this sweeps.
        sweep_leftovers(&config.volume_dir);
        let snapshot_consistency = probe_reflink(&config.volume_dir);
        Ok(Self {
            config,
            snapshot_consistency,
            room: layout::Room::default(),
        })
    }

    /// Refuse a copy this pool has no room for, before a byte of it is
    /// written, and hold that room until the caller drops what comes back.
    /// The measurement and the reservation are `layout::Room`; what is here
    /// is the one question only the driver can answer.
    ///
    /// Only asked when the copy really is a copy. A pool whose filesystem
    /// reflinks shares extents with the source and needs no room worth
    /// checking for, and `snapshot_consistency` is precisely the answer to
    /// "does this pool copy or does it clone" — it was probed by doing it.
    /// `None` is that pool: nothing was measured and nothing is held.
    ///
    /// `#[must_use]` because the value IS the reservation. `self.room_for_a_
    /// copy(n)?;` on its own line compiles, drops the guard on the spot, and
    /// silently restores the exact defect this exists to fix.
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

    /// What this volume starts from, and whether it has to be converted on
    /// the way in.
    ///
    /// A qcow2 base image cannot simply be copied here. This backend hands
    /// the VMM a RAW file — the name says `.raw` and the hypervisor driver
    /// declares it raw — so a copied qcow2 is a file whose contents and
    /// whose declared format disagree. Cloud-hypervisor says so outright
    /// ("specified = raw, detected = qcow2"), and if the file was also
    /// padded to `size_bytes` it says something much worse first ("Failed
    /// to get refcount"), because the trailing zeros move the end of the
    /// image away from where its own metadata says it is. Both seen on the
    /// fleet, 2026-09-08, on the first `image create --from-url` that ever
    /// reached a node.
    ///
    /// `qemu-img convert -O raw` is the same answer the lvm-thin driver
    /// already gives for the same reason, in the same words.
    ///
    /// The refusal in the middle is the space check of a create: a disk
    /// asked for smaller than the image it is made from is a disk nobody can
    /// write, and it is said before a byte is copied.
    async fn base_image_for(&self, spec: &VolumeSpec) -> storage::Result<Option<(PathBuf, bool)>> {
        match &spec.base_image {
            Some(name) => {
                let src = self.config.image_dir.join(name);
                let meta = tokio::fs::metadata(&src)
                    .await
                    .map_err(|_| StorageError::ImageNotFound(name.clone()))?;
                let qcow2 = is_qcow2(&src).map_err(|e| StorageError::Backend(e.into()))?;
                // For a qcow2 the FILE is smaller than the disk it describes,
                // so its length is the wrong number to compare against.
                let needed = if qcow2 {
                    layout::image_virtual_size(&self.config.qemu_img, &src, name).await?
                } else {
                    meta.len()
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
                Ok(Some((src, qcow2)))
            }
            None => Ok(None),
        }
    }

    /// How big the volume already in this pool is, or `None` if there is
    /// none.
    ///
    /// The idempotence the provider contract asks for, and the one this
    /// backend has always had: the file IS the volume, and it is named
    /// after the id.
    async fn size_if_already_there(path: &Path) -> storage::Result<Option<u64>> {
        match tokio::fs::metadata(path).await {
            Ok(meta) => Ok(Some(meta.len())),
            Err(e) if e.kind() == ErrorKind::NotFound => Ok(None),
            Err(e) => Err(StorageError::Backend(e.into())),
        }
    }

    /// How big the file is, or `NotFound`. One implementation behind both
    /// `describe` and `stat`, because for this backend they are one question:
    /// there is no connection to be down while the data is up.
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

/// The volume half. `spec.driver` has already routed the call here and
/// `spec.params` is a backend's business — this one has no options, so it
/// takes none.
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
        let tmp = layout::tmp_path(&self.config.volume_dir, id);
        let final_path = path.clone();
        let size = spec.size_bytes;
        let qemu_img = self.config.qemu_img.clone();

        let span = Span::current();
        tokio::task::spawn_blocking(move || {
            span.in_scope(|| layout::write_volume_file(src, &qemu_img, &tmp, &final_path, size))
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
        for p in [
            layout::tmp_path(&self.config.volume_dir, id),
            layout::volume_path(&self.config.volume_dir, id),
        ] {
            match tokio::fs::remove_file(&p).await {
                Ok(()) => debug!(path = %p.display(), "volume file removed"),
                Err(e) if e.kind() == ErrorKind::NotFound => {}
                Err(e) => return Err(StorageError::Backend(e.into())),
            }
        }
        Ok(())
    }

    /// A file in a directory on THIS machine. Nothing about the backend makes
    /// the bytes visible anywhere else — a second node running this driver
    /// with the same `dir` is a second directory, not the same one — so a VM
    /// that wants this volume has to run here.
    /// `set_len` on the file, and never downwards.
    ///
    /// Sparse: the tail is a hole until the guest writes into it, which is
    /// the same thing `provision` does when it pads a base image out to
    /// `size_bytes`. So growing a volume costs nothing on the pool until the
    /// data does.
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
        // Idempotent, which is what lets the tier above simply keep asking:
        // a file that is already that size is not an error, it is done.
        if have == size_bytes {
            debug!(size_bytes, "already this size");
            return Ok(VolumeHandle {
                size_bytes,
                ..handle.clone()
            });
        }
        // Refused rather than obeyed. A `set_len` downwards discards whatever
        // was past the new end, and no later pass gets it back — the tier
        // above refuses this too, and this is the refusal nobody can go
        // around.
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

    /// What this POOL's filesystem can do, found out at start-up.
    ///
    /// One line of code reflinks or copies: `copy_file_range` shares extents
    /// where the filesystem can (XFS with `reflink=1`, btrfs) and then a
    /// "copy" is a metadata operation measured in milliseconds, and it falls
    /// back to a byte copy where it cannot, where the same call takes as long
    /// as the disk is big. The old answer had to be true of both, so it was
    /// the conservative one and every pool paid for it: a VM on a
    /// reflink-capable pool was paused for an operation that does not need a
    /// standstill.
    ///
    /// The probe answers the narrow question instead — see [`probe_reflink`],
    /// which is also where the objection this used to carry is answered. It
    /// is asked once, of `volume_dir`, which is the only directory this
    /// backend writes into.
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
            // The SNAPSHOT's id. The handle names what it points at, and a
            // snapshot that carried the volume's id would be one that
            // `drop_snapshot` deleted the volume for.
            id: *id,
            backend: dst.to_string_lossy().into_owned(),
            size_bytes,
            params: None,
        };
        // Idempotent, the same way `provision` is: the file IS the snapshot
        // and it is named after the id, so a second call finds the first.
        if let Ok(meta) = tokio::fs::metadata(&dst).await {
            debug!(size_bytes = meta.len(), "snapshot already exists");
            return Ok(taken(meta.len()));
        }
        let Ok(source) = tokio::fs::metadata(&src).await else {
            return Err(StorageError::NotFound(handle.id));
        };
        // Asked before anything is opened, so a pool that is too full fails
        // with a sentence and no file at all — and HELD until this function
        // returns, so that a second snapshot asked for while this one copies
        // measures a pool with these bytes already gone. Binding it is not a
        // style choice: `_` would drop it here and leave the check the
        // snapshot of a moment it used to be.
        let _room = self.room_for_a_copy(source.len())?;
        let tmp = self.config.volume_dir.join(format!("{id}{SNAP_TMP}"));
        let (from, to, target) = (src.clone(), tmp.clone(), dst.clone());
        let span = Span::current();
        let size = tokio::task::spawn_blocking(move || -> std::io::Result<u64> {
            span.in_scope(|| {
                // Through the tmp name and renamed into place, so a crash
                // halfway leaves a `.snap.tmp` nobody reads rather than a
                // short `.snap` that looks finished.
                let copied = (|| -> std::io::Result<u64> {
                    let size = layout::clone_or_copy(&from, &to)?;
                    std::fs::rename(&to, &target)?;
                    Ok(size)
                })();
                // And the half-written copy goes with the failure. Leaving it
                // was the whole of D6: 1,02 GiB of a snapshot that ran out of
                // space, holding exactly the room the next attempt needed, on
                // a file no object pointed at and no `volumesnapshot rm`
                // could reach. Every requeue then failed identically.
                if copied.is_err() {
                    match std::fs::remove_file(&to) {
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
        for p in [
            self.config
                .volume_dir
                .join(format!("{}{SNAP_TMP}", handle.id)),
            self.snapshot_path(&handle.id),
        ] {
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
        // Idempotent for the same reason and in the same words as `provision`.
        if let Ok(meta) = tokio::fs::metadata(&path).await {
            debug!(size_bytes = meta.len(), "volume already exists");
            return Ok(handle(meta.len()));
        }
        let src = snapshot.path();
        let taken = tokio::fs::metadata(&src)
            .await
            .map_err(|_| StorageError::NotFound(snapshot.id))?
            .len();
        // Bigger is fine and is padded with zeros, exactly as a base image
        // is; smaller would truncate somebody's data, so it is refused rather
        // than obeyed.
        if spec.size_bytes < taken {
            return Err(StorageError::InvalidSpec(format!(
                "size_bytes {} smaller than the snapshot ({taken} bytes)",
                spec.size_bytes
            )));
        }
        let tmp = layout::tmp_path(&self.config.volume_dir, id);
        let (from, to, target, size) = (src, tmp, path.clone(), spec.size_bytes);
        let span = Span::current();
        tokio::task::spawn_blocking(move || -> std::io::Result<()> {
            span.in_scope(|| {
                layout::clone_or_copy(&from, &to)?;
                let f = std::fs::OpenOptions::new().write(true).open(&to)?;
                f.set_len(size)?;
                f.sync_all()?;
                std::fs::rename(&to, &target)?;
                Ok(())
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
}

/// The connection half, and the degenerate case the whole split has to keep
/// cheap: a file is not a process, so attaching one is naming it and
/// detaching one is nothing at all. No cgroup is taken because there is
/// nothing to confine, and `stat` and `describe` give the same answer because
/// for this backend the volume and the connection are the same object.
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
    use uuid::Uuid;

    /// A driver over a directory of its own, and the directory's guard.
    ///
    /// The guard is FIRST in the tuple and is what every caller binds: it owns
    /// the directory and removes it when the test ends, however it ends. A
    /// caller that dropped it would be running against a pool that is already
    /// gone.
    fn driver(tag: &str) -> (tempfile::TempDir, FilesystemBlockDriver, PathBuf, PathBuf) {
        let temp = tempfile::Builder::new()
            .prefix(&format!("meister-fs-{tag}-"))
            .tempdir()
            .expect("a temp dir");
        let root = temp.path().to_path_buf();
        let images = root.join("images");
        let volumes = root.join("volumes");
        std::fs::create_dir_all(&images).expect("a temp image dir");
        let _ = std::fs::remove_dir_all(&volumes);
        let driver = FilesystemBlockDriver::new(FilesystemDriverConfig {
            image_dir: images.clone(),
            volume_dir: volumes.clone(),
            qemu_img: PathBuf::from("qemu-img"),
        })
        .expect("the driver builds");
        (temp, driver, volumes, images)
    }

    fn spec(size_bytes: u64) -> VolumeSpec {
        VolumeSpec {
            base_image: None,
            size_bytes,
            driver: None,
            params: None,
        }
    }

    /// Four bytes, and no subprocess for the common case. A raw base image
    /// must not start reaching for qemu-img just because a qcow2 one exists.
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

    /// A qcow2 base image comes out RAW, at `size_bytes`, and bootable.
    ///
    /// The bug this pins down: the base image used to be copied byte for byte
    /// and then padded to `size_bytes`, which leaves a file that says qcow2
    /// in its first four bytes, is declared raw to the VMM, and whose own
    /// metadata no longer matches its length. Cloud-hypervisor refused it
    /// twice over, and the first refusal ("Failed to get refcount") named
    /// nothing an operator could act on.
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

    /// The size check has to use the disk the qcow2 DESCRIBES, not the file
    /// it is: a 16M qcow2 is a few hundred kilobytes on disk, so comparing
    /// the file length would let a volume through that the image does not
    /// fit into once written out.
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

    /// The degeneration probe, and the reason it is in the plainest backend:
    /// splitting one verb into two must not change what a VM gets.
    ///
    /// `create` used to return `Path(<volume_dir>/<id>.raw)` and a size, in
    /// one call. Provision and attach now produce exactly that — the same
    /// path, the same file, the same length — and `VolumeAttachment` did not
    /// change, so an `InstanceSpec` built from it is the same list of the
    /// same variants and the VMM config below it is byte for byte the config
    /// it was.
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
        // And what the VMM is told is the same shape it was told before: a
        // block volume, no shared memory, no backend process to keep alive.
        assert!(attachment.is_block());
        assert!(!attachment.needs_shared_memory());
        assert_eq!(attachment.backend_pid(), None);
    }

    /// Attaching takes no cgroup because a file is not a process, and
    /// detaching is nothing at all. The two halves of "this backend
    /// degenerates cleanly": a volume that outlives its VM loses nothing when
    /// the VM goes, because the attachment held nothing.
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
        // stat asks the same question one layer out, and for this backend
        // gets the same answer: there is no connection to be down.
        assert_eq!(
            driver.stat(&handle, &attachment).await.unwrap(),
            VolumeState { size_bytes: 2048 }
        );
    }

    /// Deleting the data needs a handle and nothing else — no attachment
    /// anywhere in the call. This is the signature the old trait could not
    /// write, and the one a volume outliving its VM needs.
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

    /// Provisioning twice is one volume. The rule the whole idempotence
    /// contract rests on: a provision whose handle is lost — a controller
    /// that died before writing it down — must be FOUND again rather than
    /// answered with a second volume, and the name derived from the id is
    /// what makes that true.
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

    /// A file in a directory is on the machine that holds the directory and
    /// nowhere else. Stated as a test because this value is what pins a VM to
    /// a node: a driver answering `Shared` here would have VMs placed where
    /// their disks are not.
    #[test]
    fn a_file_in_a_directory_is_node_local() {
        let (_temp, d, _, _) = driver("locality");
        assert_eq!(d.locality(), Locality::NodeLocal);
    }

    /// A snapshot is a COPY with the same content and a life of its own.
    ///
    /// Both halves are asserted, and the second is the one that matters: the
    /// content has to match, and the file has to be a different file. A
    /// backend that handed back a second name for the same inode would look
    /// right in every read and would follow the volume into the next write.
    ///
    /// (`copy_file_range` reflinks where the filesystem can, and a reflinked
    /// copy is a different inode sharing extents — which is exactly what is
    /// wanted, and why the inode is the thing checked rather than the disk
    /// usage.)
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

        // Smaller than the snapshot is a refusal and not a truncation: at the
        // end of obeying it is somebody's data.
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

    /// Growing a file, and refusing to shrink one.
    ///
    /// `set_len` upwards is a hole until the guest writes into it, which is
    /// what `provision` already does when it pads a base image out — so a
    /// resize costs nothing on the pool until the data does. Downwards is
    /// refused rather than obeyed: the bytes past the new end are not this
    /// backend's to decide about, and `set_len` would take them with no way
    /// back.
    ///
    /// Idempotence is the third assertion and the one the tier above rests
    /// on: it is level-triggered and simply keeps asking.
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

        // Idempotent: the same request again is done, not an error.
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

    /// The probe answers about THIS directory, it leaves nothing behind, and
    /// its answer is what the driver claims.
    ///
    /// It cannot assert WHICH answer: the machine running the test decides
    /// that, and both are correct — `/tmp` is tmpfs here and ext4 there and
    /// btrfs on a third. What it can assert is the three things that are true
    /// on every filesystem, and those are what the position turns on: the
    /// probe agrees with the driver, it cleans up after itself, and a
    /// filesystem that reflinks is reported as `Atomic` rather than as the
    /// flat `NeedsQuiesce` this backend used to answer everywhere.
    #[test]
    fn the_probe_answers_for_the_pool_directory_and_leaves_nothing_in_it() {
        let (_temp, driver, volumes, _images) = driver("reflink");

        let probed = probe_reflink(&volumes);
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

        // Nothing of the probe's is left in the pool. A file per start-up in
        // the directory the volumes live in would be the kind of leak this
        // whole round is about.
        let leftovers: Vec<String> = std::fs::read_dir(&volumes)
            .expect("the pool directory")
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.contains("reflink-probe"))
            .collect();
        assert!(leftovers.is_empty(), "the probe cleaned up: {leftovers:?}");

        // Asked twice it says the same thing — it is a fact about a mount,
        // not a measurement — and a second driver over the same directory
        // agrees with the first.
        assert_eq!(probe_reflink(&volumes), probed);

        // An independent oracle for whichever answer this machine gives:
        // `cp --reflink=always` asks the kernel the same question through the
        // same ioctl, and the two must not disagree. This is what catches the
        // probe being accidentally right — a source opened write-only says
        // "cannot reflink" on a filesystem that can, and every assertion
        // above still passes.
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
            probe_reflink(&volumes.join("no-such-pool")),
            SnapshotConsistency::NeedsQuiesce
        );

        let _ = std::fs::remove_dir_all(volumes.parent().unwrap());
    }

    /// A snapshot that fails takes its own half-written copy with it.
    ///
    /// D6: the copy ran out of space, the `.snap.tmp` of 1,02 GiB stayed, and
    /// it held exactly the room the next attempt needed — so every requeue
    /// failed identically, no object pointed at the file and
    /// `volumesnapshot rm` could not reach it. The failure here is forced with
    /// a source that cannot be read (a directory), because what the copy died
    /// of does not matter: what matters is that the pool is as it was.
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
            !volumes.join(format!("{snap}{SNAP_TMP}")).exists(),
            "the half-written copy is gone"
        );
        assert!(
            !driver.snapshot_path(&snap).exists(),
            "and nothing was renamed into place either"
        );

        let _ = std::fs::remove_dir_all(volumes.parent().unwrap());
    }

    /// A pool with no room says so, and writes nothing.
    ///
    /// The other half of the same failure: the copy that filled the disk was
    /// asked for in the first place. `statvfs` is asked BEFORE anything is
    /// opened, so the answer costs no bytes — which is the whole point, since
    /// the bytes are what nobody could get back.
    ///
    /// The two drivers are built by hand rather than through `new`, because
    /// what is under test is the POLICY and not what /tmp happens to be on
    /// today: a pool that copies has to check, and a pool that reflinks shares
    /// extents with the source and has nothing to check for.
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
        };

        let copying = FilesystemBlockDriver {
            config: config(&volumes),
            snapshot_consistency: SnapshotConsistency::NeedsQuiesce,
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
        assert!(
            !volumes.join(format!("{snap}{SNAP_TMP}")).exists(),
            "and it means it"
        );

        // A pool that reflinks is not asked the question at all: a clone of a
        // 4 TiB volume occupies no new extents, and refusing it over free
        // space would be refusing the operation this backend is best at.
        let cloning = FilesystemBlockDriver {
            config: config(&volumes),
            snapshot_consistency: SnapshotConsistency::Atomic,
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

    /// A copy that is running has already taken its room.
    ///
    /// The space check was a `statvfs` and nothing else — a statement about a
    /// moment that has passed by the time the copy it approved is halfway
    /// through. Two snapshots asked for at once each measured the whole free
    /// pool, each decided it fitted, and the second one took the filesystem to
    /// zero. On this stack that is never only a failed snapshot: the agent's
    /// database is on the same filesystem, and a full one wedges every command
    /// the node has.
    ///
    /// Written against `Room` directly and not through `snapshot`, because
    /// what is under test is arithmetic that has to hold while a copy RUNS,
    /// and a test that really filled a disk would be a test about /tmp.
    #[test]
    fn a_second_copy_measures_the_room_the_first_one_is_using() {
        let temp = tempfile::tempdir().expect("a temp dir");
        let dir = temp.path();
        let room = layout::Room::default();

        // Whatever this filesystem has free, minus a page: the first
        // reservation fits by construction, and the second one asks for the
        // same amount again.
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

        // The room comes back when the copy is over, whichever way it ended:
        // a failed copy removed its `.snap.tmp` and a finished one is already
        // in the next `statvfs`.
        drop(first);
        let _second = room
            .reserve(dir, half)
            .expect("the room the first copy held is free again");
    }

    /// What a killed process left behind goes when the pool is opened.
    ///
    /// Two shapes, one sweep. The `.snap.tmp` half is the second half of D6,
    /// for the copies that were already lying there: an agent restarted onto
    /// a full disk has to come back to a pool it can work in. A tmp file WITH
    /// its finished snapshot beside it stays — that pair belongs to
    /// `drop_snapshot`.
    ///
    /// The probe half is the one file in a pool that had no owner at all: a
    /// process killed inside `probe_reflink` left up to 4 KiB under a pid
    /// name, and nothing collected it — not `drop_snapshot`, which needs an
    /// object, and not the old sweep, which only looked at `.snap.tmp`.
    ///
    /// And nothing else in the directory is touched, which is the assertion
    /// that makes the other three worth making.
    #[test]
    fn opening_a_pool_throws_away_what_a_killed_process_left() {
        let temp = tempfile::tempdir().expect("a temp dir");
        let root = temp.path().to_path_buf();
        let images = root.join("images");
        let volumes = root.join("volumes");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&images).expect("a temp image dir");
        std::fs::create_dir_all(&volumes).expect("a temp volume dir");

        let orphan = volumes.join("aaaa.snap.tmp");
        let paired = volumes.join("bbbb.snap.tmp");
        let finished = volumes.join("bbbb.snap");
        let volume = volumes.join("cccc.raw");
        // A pid this test does not have and never will: the point is that no
        // process is asked about, not that this one is dead.
        let probe_src = volumes.join(format!("{PROBE_PREFIX}424242.src"));
        let probe_dst = volumes.join(format!("{PROBE_PREFIX}424242.dst"));
        for p in [&orphan, &paired, &finished, &volume, &probe_src, &probe_dst] {
            std::fs::write(p, b"x").expect("a file");
        }

        FilesystemBlockDriver::new(FilesystemDriverConfig {
            image_dir: images,
            volume_dir: volumes.clone(),
            qemu_img: PathBuf::from("qemu-img"),
        })
        .expect("the driver builds");

        assert!(!orphan.exists(), "the unfinished copy is gone");
        assert!(!probe_src.exists(), "and so is a probe that never returned");
        assert!(!probe_dst.exists(), "both halves of it");
        assert!(paired.exists(), "the one with a finished snapshot is not");
        assert!(
            finished.exists(),
            "and the snapshot itself certainly is not"
        );
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
}
