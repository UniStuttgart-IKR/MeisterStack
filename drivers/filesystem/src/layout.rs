// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! What a pool directory looks like from the outside.
//!
//! What each file in it is called, how much room it has, and how bytes get
//! into it. None of it needs a driver: a pool is a directory, and every
//! question here is answered from the directory and the id. That is why they
//! are functions and not a second type — a driver with two classes is not a
//! driver, and the answer to `FilesystemBlockDriver`'s low cohesion is that
//! half its methods never looked at it.

use agent_api::storage;
use agent_api::storage::{SnapshotId, StorageError, VolumeId};
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use tracing::debug;

/// The volume itself: `<volume id>.raw`, in the pool directory.
pub(crate) fn volume_path(dir: &Path, id: &VolumeId) -> PathBuf {
    dir.join(format!("{id}.raw"))
}

/// Where a volume is built before it is renamed into place.
pub(crate) fn tmp_path(dir: &Path, id: &VolumeId) -> PathBuf {
    dir.join(format!("{id}.tmp"))
}

/// Where a snapshot lives: beside the volumes, under the SNAPSHOT's id
/// and a suffix of its own.
///
/// A separate suffix and not a separate directory, so that one
/// `volume_dir` is still the whole of what this backend owns and a node's
/// configuration does not grow a second path to get wrong. The id is the
/// snapshot's, which is what makes `snapshot` idempotent: asked twice,
/// the second call finds the file the first one made.
pub(crate) fn snapshot_path(dir: &Path, id: &SnapshotId) -> PathBuf {
    dir.join(format!("{id}.snap"))
}

/// The room this pool has already promised to copies that have not finished.
///
/// `statvfs` answers "how much is free NOW", and a snapshot takes as long as
/// its bytes take. Two 30 GiB snapshots asked for at once in a pool with
/// 40 GiB free both measured 40, both were let through, and the second one
/// took the filesystem to zero — which on this stack is never only a failed
/// snapshot: the agent's database is on that filesystem, and a full one wedges
/// every command the node has. The measurement was right and it was a
/// snapshot of a moment that had already passed by the time it was used.
///
/// So the check RESERVES what it approves, and gives it back when the copy is
/// over — whichever way it ended, because a copy that failed left nothing
/// behind (the error path removes its `.snap.tmp`) and a copy that succeeded
/// is already counted by the next `statvfs`.
///
/// The reservation is deliberately the full size and not what is left to
/// write. It is the upper bound, it is what the measurement WOULD have said
/// had the copy already finished, and a promise that shrank as a copy ran
/// would let a second one in on the strength of bytes the first one is about
/// to write.
///
/// In memory and per driver, which is per pool per agent. It knows nothing
/// about a second writer on a shared filesystem and never claimed to:
/// `statvfs` is still what says how much room there is, and this only
/// subtracts the copies this node started and has not finished.
#[derive(Debug, Default)]
pub(crate) struct Room {
    promised: std::sync::Mutex<u64>,
}

/// Room this pool has set aside, given back when this is dropped.
///
/// A guard and not a pair of calls, because the giving back has to happen on
/// every path out of a copy — the failure, the panic in the blocking task,
/// the early return — and "release it afterwards" is the kind of instruction
/// that survives exactly until somebody adds a `?`.
#[derive(Debug)]
pub(crate) struct Reserved<'a> {
    room: &'a Room,
    bytes: u64,
}

impl Drop for Reserved<'_> {
    fn drop(&mut self) {
        let mut promised = self.room.promised.lock().expect("this pool's reservations");
        // Saturating, so a lock that was poisoned and remade — or any future
        // bookkeeping mistake — cannot underflow into a pool that believes it
        // has promised sixteen exabytes and refuses every snapshot for ever.
        *promised = promised.saturating_sub(self.bytes);
    }
}

impl Room {
    /// Refuse a copy this pool has no room for, before a byte of it is
    /// written — and hold the room until the copy is done.
    ///
    /// The failure this prevents is the one that keeps itself alive: a
    /// snapshot that runs out of space leaves a partial copy of exactly the
    /// size that was left, the requeue tries again into a pool that is now
    /// even fuller, and the node's own root filesystem — the same one its
    /// database is on — goes to zero. That is how a chaos run turned one
    /// failed snapshot into a node that could not serve a single command.
    ///
    /// The lock is taken BEFORE the measurement and not after, which is the
    /// whole of what makes two callers at once safe: two threads that each
    /// measured first would both have read the same free space and both have
    /// decided they fit.
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
        // The promised half is named only when there is one. On an idle pool
        // it is zero and saying so would put a number in front of an operator
        // that explains nothing; when it is not zero it is the entire reason
        // this refusal happened while `df` says there is room.
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

/// What a base image will occupy once written out raw.
///
/// Only ever called for a qcow2: a qcow2 file is smaller than the disk it
/// describes, so its own length is the wrong number to check `size_bytes`
/// against. Same question, same tool and same reasoning as
/// `lvm_thin::image_virtual_size`.
pub(crate) async fn image_virtual_size(
    qemu_img: &Path,
    path: &Path,
    name: &str,
) -> storage::Result<u64> {
    let out = tokio::process::Command::new(qemu_img)
        .args(["info", "--output=json"])
        .arg(path)
        .output()
        .await
        .map_err(|e| {
            StorageError::Backend(anyhow::anyhow!(
                "running {}: {e} (a qcow2 base image needs it; is qemu-img on the agent's \
                 PATH?)",
                qemu_img.display()
            ))
        })?;
    if !out.status.success() {
        return Err(StorageError::ImageNotFound(format!(
            "{name}: qemu-img info failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    // Parsed, not scanned. The document is not flat: `children[0].info`
    // carries a `virtual-size` of its own for the FILE node — a few
    // hundred kilobytes for a fresh qcow2 — before the top-level one that
    // describes the disk. Taking the first match is how a 64M image
    // passes a check meant to reject it, which is what a test caught here
    // before this line was ever deployed.
    let info: serde_json::Value = serde_json::from_slice(&out.stdout).map_err(|e| {
        StorageError::Backend(anyhow::anyhow!("qemu-img info json for {name}: {e}"))
    })?;
    info.get("virtual-size")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| {
            StorageError::Backend(anyhow::anyhow!(
                "qemu-img info for {name} has no virtual-size"
            ))
        })
}

/// Write a non-raw base image out as raw. `qemu-img convert` and not a
/// copy, because what this backend hands the VMM is a raw file and a
/// copied qcow2 is not one.
pub(crate) fn convert_to_raw(qemu_img: &Path, src: &Path, dst: &Path) -> std::io::Result<()> {
    let out = std::process::Command::new(qemu_img)
        .arg("convert")
        .args(["-O", "raw"])
        .arg(src)
        .arg(dst)
        .output()
        .map_err(|e| std::io::Error::other(format!("running {}: {e}", qemu_img.display())))?;
    if !out.status.success() {
        return Err(std::io::Error::other(format!(
            "qemu-img convert {} -> {}: {}",
            src.display(),
            dst.display(),
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    Ok(())
}

/// Reflink if the filesystem can, copy if it cannot.
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

/// Make the file a volume is: its bytes, then its size, then its name.
///
/// The order is the whole of it. The bytes are written under a tmp name, the
/// file is grown to what the spec asked for, it is fsynced, and only then is
/// it renamed into place — so a volume that exists under its own name is a
/// volume that is finished, and an interrupted provision leaves a `.tmp`
/// that `deprovision` removes with the volume.
pub(crate) fn write_volume_file(
    src: Option<(PathBuf, bool)>,
    qemu_img: &Path,
    tmp: &Path,
    final_path: &Path,
    size: u64,
) -> std::io::Result<()> {
    match &src {
        Some((s, false)) => {
            debug!(base = %s.display(), "cloning base image");
            clone_or_copy(s, tmp)?;
        }
        Some((s, true)) => {
            debug!(base = %s.display(), "converting qcow2 base image to raw");
            convert_to_raw(qemu_img, s, tmp)?;
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
