// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! File naming, space reservations and copy helpers for directory-backed pools.

use agent_api::base_image::{BaseImage, Destination, Sandbox};
use agent_api::storage;
use agent_api::storage::{SnapshotId, StorageError, VolumeId};
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use tracing::debug;

/// The volume itself: `<volume id>.raw`, in the pool directory.
pub(crate) fn volume_path(dir: &Path, id: &VolumeId) -> PathBuf {
    dir.join(format!("{id}.raw"))
}

/// Snapshot path beside the volumes, keyed by snapshot ID.
pub(crate) fn snapshot_path(dir: &Path, id: &SnapshotId) -> PathBuf {
    dir.join(format!("{id}.snap"))
}

/// Space reserved for in-flight copies by this driver instance. Subtract the
/// full promised size from statvfs availability until the guard is dropped.
/// Other processes and nodes do not share these reservations.
#[derive(Debug, Default)]
pub(crate) struct Room {
    promised: std::sync::Mutex<u64>,
}

/// Release this reservation when its guard is dropped.
#[derive(Debug)]
pub(crate) struct Reserved<'a> {
    room: &'a Room,
    bytes: u64,
}

impl Drop for Reserved<'_> {
    fn drop(&mut self) {
        let mut promised = self.room.promised.lock().expect("this pool's reservations");
        // Avoid arithmetic underflow if reservation bookkeeping becomes inconsistent.
        *promised = promised.saturating_sub(self.bytes);
    }
}

impl Room {
    /// Measure free space and reserve under one lock so concurrent calls on this
    /// instance cannot both spend the same measured capacity.
    pub(crate) fn reserve(&self, dir: &Path, needed: u64) -> storage::Result<Reserved<'_>> {
        let mut promised = self.promised.lock().expect("this pool's reservations");
        let stat = nix::sys::statvfs::statvfs(dir).map_err(|e| {
            StorageError::Backend(anyhow::anyhow!(
                "asking {} how much room it has: {e}",
                dir.display()
            ))
        })?;
        let free = stat.blocks_available() as u64 * stat.fragment_size() as u64;
        let spare = free.saturating_sub(*promised);
        if spare >= needed {
            *promised += needed;
            return Ok(Reserved {
                room: self,
                bytes: needed,
            });
        }
        // Include concurrent reservations when they contribute to the capacity refusal.
        let held = match *promised {
            0 => String::new(),
            other => format!(
                " ({other} of them are already promised to copies this node is still making)"
            ),
        };
        Err(StorageError::Backend(anyhow::anyhow!(
            "not enough room in {} for a snapshot: the volume is {needed} bytes and {free} are \
             free{held}. This pool copies rather than reflinks, so the copy needs the full size; \
             nothing has been written.",
            dir.display()
        )))
    }
}

/// Convert a previously probed image to raw in the configured sandbox.
pub(crate) fn convert_to_raw(
    sandbox: &Sandbox,
    qemu_img: &Path,
    image: &BaseImage,
    src: &Path,
    dst: &Path,
) -> std::io::Result<()> {
    // Create the destination before the sandbox binds it and transfers ownership.
    std::fs::File::create(dst)?;
    // Only for the sentence a person reads. The catalogue name is the file
    // name in this pool's image directory.
    let name = src
        .file_name()
        .unwrap_or(src.as_os_str())
        .to_string_lossy()
        .into_owned();
    agent_api::base_image::convert_blocking(
        sandbox,
        qemu_img,
        image,
        src,
        Destination::File(dst),
        &name,
    )
}

/// Copy with copy_file_range, falling back to a byte copy on an unsupported
/// first call. This does not force a single atomic FICLONE operation.
pub(crate) fn clone_or_copy(src: &Path, dst: &Path) -> std::io::Result<u64> {
    use nix::errno::Errno;
    use nix::fcntl::copy_file_range;

    let src_file = std::fs::File::open(src)?;
    let dst_file = std::fs::File::create(dst)?;
    let total = src_file.metadata()?.len();

    let mut remaining = total as usize;
    let mut first_call = true;

    while remaining > 0 {
        match copy_file_range(&src_file, None, &dst_file, None, remaining) {
            Ok(0) => {
                return Err(std::io::Error::new(
                    ErrorKind::UnexpectedEof,
                    "copy_file_range returned 0 before EOF",
                ));
            }
            Ok(n) => {
                remaining -= n;
                first_call = false;
            }
            Err(e @ (Errno::EOPNOTSUPP | Errno::EXDEV | Errno::EINVAL)) if first_call => {
                let _ = e;
                drop(dst_file);
                let mut s = std::fs::File::open(src)?;
                let mut d = std::fs::File::create(dst)?;
                return std::io::copy(&mut s, &mut d);
            }
            Err(e) => return Err(std::io::Error::from_raw_os_error(e as i32)),
        }
    }
    Ok(total)
}

/// Write under a temporary name, set the requested size, sync the file, then
/// rename to the final name. The containing directory is not synced here.
pub(crate) fn write_volume_file(
    src: Option<(PathBuf, Option<BaseImage>)>,
    sandbox: &Sandbox,
    qemu_img: &Path,
    tmp: &Path,
    final_path: &Path,
    size: u64,
) -> std::io::Result<()> {
    let written = write_then_rename(src, sandbox, qemu_img, tmp, final_path, size);
    // The staging name is this attempt's own since R3-F09, so the next
    // attempt never overwrites it: a failed one takes its file with it here,
    // and one killed outright is the start-up sweep's.
    if written.is_err() {
        let _ = std::fs::remove_file(tmp);
    }
    written
}

fn write_then_rename(
    src: Option<(PathBuf, Option<BaseImage>)>,
    sandbox: &Sandbox,
    qemu_img: &Path,
    tmp: &Path,
    final_path: &Path,
    size: u64,
) -> std::io::Result<()> {
    match &src {
        Some((s, None)) => {
            debug!(base = %s.display(), "cloning base image");
            clone_or_copy(s, tmp)?;
        }
        Some((s, Some(image))) => {
            debug!(base = %s.display(), format = %image.format,
                   "converting base image to raw");
            convert_to_raw(sandbox, qemu_img, image, s, tmp)?;
        }
        None => {
            std::fs::File::create(tmp)?;
        }
    }
    let f = std::fs::OpenOptions::new().write(true).open(tmp)?;
    f.set_len(size)?;
    f.sync_all()?;
    std::fs::rename(tmp, final_path)?;
    Ok(())
}
