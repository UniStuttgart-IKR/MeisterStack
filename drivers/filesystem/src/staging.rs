// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Files a pool holds only while something is being made, and who they
//! belong to.
//!
//! Astra finding R3-F09, 2026-09-25: the nfs driver roots this driver in a
//! directory every node of the pool shares, and the start-up sweep removed
//! every `.snap.tmp` without a finished `.snap` beside it. On a shared pool
//! that is the snapshot another host is copying at that very moment: host B
//! restarting deleted host A's running copy, and A's rename then failed or,
//! worse, published nothing while the caller waited for it.
//!
//! The fix is that a staging file says whose it is and what it is for, in its
//! name: `<id>.snap.tmp.<host>.<nonce>` for a snapshot copy,
//! `<id>.tmp.<host>.<nonce>` for a volume being built, and the reflink probe
//! and the clock marker below carry the host the same way. The sweep then
//! applies two different rules:
//!
//! * A file of THIS host is removed at start. The agent that wrote it is the
//!   process this one replaced, so nobody is writing into it any more. The
//!   one exception is a file this very process has open (a second driver
//!   instance over the same directory), which the in-process registry names.
//! * A file of ANOTHER host, or of nobody (the names from before this change
//!   carry no host), is removed only with a proof that its writer is gone:
//!   the writer refreshes the file's mtime every [`HEARTBEAT`] while the copy
//!   runs, so a file whose mtime is older than [`STALE_AFTER`] by the POOL's
//!   own clock has had no living writer for that long. The file is looked at
//!   a second time right before the unlink, and any change keeps it.
//!
//! The age is measured against the file server's clock and not this host's:
//! the mtime of a file on NFS is set by the server, and comparing it with a
//! local clock that is a few minutes off would turn clock skew into data
//! loss. [`pool_now`] reads the server's "now" off a marker file it creates
//! for that purpose.

use std::collections::HashSet;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::sync::{LazyLock, Mutex};
use std::time::{Duration, SystemTime};
use tracing::{debug, warn};

/// How often a running copy refreshes its staging file's mtime.
pub(crate) const HEARTBEAT: Duration = Duration::from_secs(30);

/// How long a foreign staging file must have gone without a heartbeat before
/// another host may remove it.
///
/// An hour is 120 missed heartbeats. The number is deliberately far from the
/// heartbeat: what it has to cover is not a slow copy (a slow copy still
/// beats) but a writer whose heartbeat thread is stuck behind the same hung
/// mount as the copy, or a host that was paused. Too long costs disk space
/// held by a dead copy for an hour longer; too short costs a live snapshot.
pub(crate) const STALE_AFTER: Duration = Duration::from_secs(60 * 60);

/// What every reflink probe file is called before the host.
pub(crate) const PROBE_PREFIX: &str = ".meister-reflink-probe-";

/// What the marker [`pool_now`] writes is called before the host.
const CLOCK_PREFIX: &str = ".meister-clock-";

/// The suffix a snapshot is copied under before it is renamed into place.
pub(crate) const SNAP_TMP: &str = ".snap.tmp";

/// The suffix a volume is built under before it is renamed into place.
const VOLUME_TMP: &str = ".tmp";

/// This host, as it appears in a file name.
///
/// Encoded so that it cannot contain the `.` the name is split at, and so
/// that the encoding is injective: two different node ids never become the
/// same tag, because a collision there would let one host sweep the other's
/// running copies as its own. `[A-Za-z0-9-]` stands for itself and every
/// other byte, `_` included, becomes `_` plus two hex digits.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct HostTag(String);

impl HostTag {
    pub(crate) fn new(host_id: &str) -> Result<Self, String> {
        if host_id.is_empty() {
            return Err(
                "the filesystem driver needs this node's id to name its staging files, \
                        and it was empty"
                    .into(),
            );
        }
        let mut tag = String::with_capacity(host_id.len());
        for byte in host_id.bytes() {
            if byte.is_ascii_alphanumeric() || byte == b'-' {
                tag.push(byte as char);
            } else {
                tag.push_str(&format!("_{byte:02x}"));
            }
        }
        Ok(Self(tag))
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

/// A fresh, unguessable suffix, so two attempts at the same id (a retry, or
/// two hosts after a failover) never write into the same file.
fn nonce() -> String {
    uuid::Uuid::new_v4().simple().to_string()
}

fn is_nonce(s: &str) -> bool {
    s.len() == 32 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

fn is_tag(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// Where this host copies a snapshot before it is renamed into place.
pub(crate) fn snapshot_copy(dir: &Path, id: &impl std::fmt::Display, host: &HostTag) -> PathBuf {
    dir.join(format!("{id}{SNAP_TMP}.{}.{}", host.as_str(), nonce()))
}

/// Where this host builds a volume before it is renamed into place.
pub(crate) fn volume_build(dir: &Path, id: &impl std::fmt::Display, host: &HostTag) -> PathBuf {
    dir.join(format!("{id}{VOLUME_TMP}.{}.{}", host.as_str(), nonce()))
}

/// The two files of one reflink probe.
pub(crate) fn probe_pair(dir: &Path, host: &HostTag) -> (PathBuf, PathBuf) {
    let stem = format!("{PROBE_PREFIX}{}.{}", host.as_str(), nonce());
    (
        dir.join(format!("{stem}.src")),
        dir.join(format!("{stem}.dst")),
    )
}

/// The name a volume was built under before R3-F09. Still read by `probe`
/// and removed by `deprovision`, because a pool upgraded in place may hold
/// one, and the S13 tombstone relies on finding it.
pub(crate) fn legacy_volume_build(dir: &Path, id: &impl std::fmt::Display) -> PathBuf {
    dir.join(format!("{id}{VOLUME_TMP}"))
}

/// The name a snapshot was copied under before R3-F09.
pub(crate) fn legacy_snapshot_copy(dir: &Path, id: &impl std::fmt::Display) -> PathBuf {
    dir.join(format!("{id}{SNAP_TMP}"))
}

/// Every staging file of any host for this snapshot id, or for this volume
/// id. Used by `drop_snapshot`, `deprovision` and `probe`: the object is the
/// owner, and when it goes, its staging files go with it whoever wrote them.
pub(crate) fn staged_for(
    dir: &Path,
    id: &impl std::fmt::Display,
    snapshot: bool,
) -> std::io::Result<Vec<PathBuf>> {
    let prefix = match snapshot {
        true => format!("{id}{SNAP_TMP}."),
        false => format!("{id}{VOLUME_TMP}."),
    };
    let mut found = Vec::new();
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        if let Some(name) = entry.file_name().to_str()
            && let Some(rest) = name.strip_prefix(&prefix)
            && let Some((tag, n)) = rest.split_once('.')
            && is_tag(tag)
            && is_nonce(n)
        {
            found.push(entry.path());
        }
    }
    Ok(found)
}

/// What a leftover in the pool is, as far as the sweep cares.
#[derive(Debug, PartialEq, Eq)]
enum Leftover<'a> {
    SnapshotCopy(Option<&'a str>),
    VolumeBuild(&'a str),
    Probe(Option<&'a str>),
    Clock(&'a str),
}

impl<'a> Leftover<'a> {
    fn owner(&self) -> Option<&'a str> {
        match *self {
            Self::SnapshotCopy(h) | Self::Probe(h) => h,
            Self::VolumeBuild(h) | Self::Clock(h) => Some(h),
        }
    }

    fn what(&self) -> &'static str {
        match self {
            Self::SnapshotCopy(_) => "an unfinished snapshot copy",
            Self::VolumeBuild(_) => "an unfinished volume",
            Self::Probe(_) => "a reflink probe file",
            Self::Clock(_) => "a clock marker",
        }
    }
}

/// Read a file name as one of the four shapes of staging file, or `None`.
///
/// The legacy `<id>.tmp` of a volume is deliberately not one of them: it is
/// owned by its volume object (see `legacy_volume_build`), and the sweep
/// never had it.
fn classify(name: &str) -> Option<Leftover<'_>> {
    if let Some(rest) = name.strip_prefix(PROBE_PREFIX) {
        let stem = rest
            .strip_suffix(".src")
            .or_else(|| rest.strip_suffix(".dst"))?;
        return match stem.split_once('.') {
            Some((tag, n)) if is_tag(tag) && is_nonce(n) => Some(Leftover::Probe(Some(tag))),
            // `<pid>.src` from before R3-F09: nobody's, by name.
            None if !stem.is_empty() && stem.bytes().all(|b| b.is_ascii_digit()) => {
                Some(Leftover::Probe(None))
            }
            _ => None,
        };
    }
    if let Some(rest) = name.strip_prefix(CLOCK_PREFIX) {
        let (tag, n) = rest.split_once('.')?;
        return (is_tag(tag) && is_nonce(n)).then_some(Leftover::Clock(tag));
    }
    let mut parts = name.rsplitn(3, '.');
    if let (Some(n), Some(tag), Some(stem)) = (parts.next(), parts.next(), parts.next())
        && is_nonce(n)
        && is_tag(tag)
    {
        if stem.ends_with(SNAP_TMP) {
            return Some(Leftover::SnapshotCopy(Some(tag)));
        }
        if stem.ends_with(VOLUME_TMP) {
            return Some(Leftover::VolumeBuild(tag));
        }
    }
    name.strip_suffix(SNAP_TMP)
        .filter(|id| !id.is_empty() && !id.contains('.'))
        .map(|_| Leftover::SnapshotCopy(None))
}

/// The staging files this process is writing right now, across every driver
/// instance in it. A second driver over the same directory in the same
/// process shares the host tag, and without this it would take the first
/// one's running copy for a leftover of a dead agent.
static IN_FLIGHT: LazyLock<Mutex<HashSet<PathBuf>>> = LazyLock::new(Default::default);

fn in_flight(path: &Path) -> bool {
    IN_FLIGHT
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .contains(path)
}

/// A staging file for as long as its copy runs: registered in this process,
/// and its mtime refreshed every [`HEARTBEAT`] so another host can tell it
/// from a leftover.
///
/// Dropped on every path out of the copy, which unregisters it and stops the
/// heartbeat. The heartbeat thread is not joined: it may be blocked on the
/// same hung mount the copy was, and the copy's result must not wait for it.
/// A beat that lands after the rename finds no file under this unique name
/// and does nothing.
pub(crate) struct Staged {
    path: PathBuf,
    _stop: std::sync::mpsc::Sender<()>,
}

impl Staged {
    pub(crate) fn begin(path: PathBuf) -> Self {
        Self::with_heartbeat(path, HEARTBEAT)
    }

    pub(crate) fn with_heartbeat(path: PathBuf, every: Duration) -> Self {
        IN_FLIGHT
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(path.clone());
        let (stop, stopped) = std::sync::mpsc::channel::<()>();
        let beat = path.clone();
        let spawned = std::thread::Builder::new()
            .name("staging-heartbeat".into())
            .spawn(move || {
                let mut warned = false;
                while let Err(std::sync::mpsc::RecvTimeoutError::Timeout) =
                    stopped.recv_timeout(every)
                {
                    match touch(&beat) {
                        Ok(()) => {}
                        Err(e) if e.kind() == ErrorKind::NotFound => {}
                        Err(e) if !warned => {
                            warned = true;
                            warn!(path = %beat.display(), error = %e,
                                  "could not refresh a staging file; another host may take \
                                   this copy for abandoned after an hour");
                        }
                        Err(_) => {}
                    }
                }
            });
        if let Err(e) = spawned {
            warn!(path = %path.display(), error = %e,
                  "no heartbeat thread for this copy; another host may take it for abandoned \
                   after an hour");
        }
        Self { path, _stop: stop }
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for Staged {
    fn drop(&mut self) {
        IN_FLIGHT
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(&self.path);
    }
}

/// Set the file's mtime to the file SERVER's now. `UTIME_NOW` is what makes
/// the NFS client send "set to server time" rather than this host's clock.
fn touch(path: &Path) -> std::io::Result<()> {
    use nix::sys::stat::{UtimensatFlags, utimensat};
    use nix::sys::time::TimeSpec;
    utimensat(
        nix::fcntl::AT_FDCWD,
        path,
        &TimeSpec::UTIME_OMIT,
        &TimeSpec::UTIME_NOW,
        UtimensatFlags::NoFollowSymlink,
    )
    .map_err(std::io::Error::from)
}

/// What time it is according to the filesystem `dir` is on: the mtime of a
/// file created there a moment ago. `None` if no file could be made, and
/// then no foreign file is judged at all.
fn pool_now(dir: &Path, host: &HostTag) -> Option<SystemTime> {
    let marker = dir.join(format!("{CLOCK_PREFIX}{}.{}", host.as_str(), nonce()));
    let made = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&marker)
        .and_then(|f| f.metadata())
        .and_then(|m| m.modified());
    let _ = std::fs::remove_file(&marker);
    match made {
        Ok(now) => Some(now),
        Err(e) => {
            warn!(dir = %dir.display(), error = %e,
                  "could not read the pool's clock; other hosts' leftovers are left alone");
            None
        }
    }
}

/// (inode, length, mtime): what the second look compares.
fn fingerprint(meta: &std::fs::Metadata) -> (u64, u64, Option<SystemTime>) {
    use std::os::unix::fs::MetadataExt;
    (meta.ino(), meta.len(), meta.modified().ok())
}

/// Throw away what a dead writer left in this pool: see the module
/// documentation for the two rules. Every failure is a WARN and nothing
/// more; refusing to start over a leftover file would turn a wasted gigabyte
/// into an outage.
pub(crate) fn sweep(dir: &Path, host: &HostTag) {
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) => {
            warn!(dir = %dir.display(), error = %e,
                  "could not look through the pool for leftovers");
            return;
        }
    };
    // Read once, and only if a foreign file turns up.
    let mut now: Option<Option<SystemTime>> = None;
    for entry in entries.flatten() {
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        let Some(kind) = classify(name) else {
            continue;
        };
        let Ok(first) = std::fs::symlink_metadata(&path) else {
            continue;
        };
        if !first.file_type().is_file() {
            continue;
        }
        let own = kind.owner() == Some(host.as_str());
        if own {
            if in_flight(&path) {
                continue;
            }
        } else {
            let Some(now) = *now.get_or_insert_with(|| pool_now(dir, host)) else {
                continue;
            };
            let age = first
                .modified()
                .ok()
                .and_then(|m| now.duration_since(m).ok())
                .unwrap_or(Duration::ZERO);
            if age < STALE_AFTER {
                debug!(path = %path.display(), age_secs = age.as_secs(),
                       "another host's staging file is still being written; left alone");
                continue;
            }
            // The second look: a heartbeat or a write between the first
            // stat and here means its writer is alive after all.
            match std::fs::symlink_metadata(&path) {
                Ok(second) if fingerprint(&second) == fingerprint(&first) => {}
                _ => continue,
            }
        }
        let size = first.len();
        let whose = match (own, kind.owner()) {
            (true, _) => "this host's, from an agent that is no longer running",
            (false, Some(_)) => "another host's, with no heartbeat for over an hour",
            (false, None) => "unnamed and from before R3-F09, with no write for over an hour",
        };
        match std::fs::remove_file(&path) {
            Ok(()) => warn!(path = %path.display(), size_bytes = size,
                            "removed {} left in the pool: {whose}", kind.what()),
            Err(e) if e.kind() == ErrorKind::NotFound => {}
            Err(e) => warn!(path = %path.display(), error = %e,
                            "a leftover in this pool could not be removed"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn backdate(path: &Path, by: Duration) {
        let f = std::fs::OpenOptions::new()
            .write(true)
            .open(path)
            .expect("the file");
        f.set_modified(SystemTime::now() - by).expect("backdated");
    }

    /// Two node ids never share a tag, and a tag never contains the `.` a
    /// staging name is split at.
    #[test]
    fn the_host_tag_is_injective_and_has_no_dot() {
        let a = HostTag::new("node_2e").unwrap();
        let b = HostTag::new("node.").unwrap();
        assert_ne!(a, b, "{a:?} {b:?}");
        assert!(!HostTag::new("a.b.c").unwrap().as_str().contains('.'));
        assert_eq!(HostTag::new("calvia-1").unwrap().as_str(), "calvia-1");
        assert!(HostTag::new("").is_err());
    }

    #[test]
    fn every_name_this_module_writes_is_read_back_as_its_own() {
        let dir = Path::new("/pool");
        let host = HostTag::new("n1").unwrap();
        let name = |p: PathBuf| p.file_name().unwrap().to_str().unwrap().to_string();
        let id = uuid::Uuid::new_v4();
        assert_eq!(
            classify(&name(snapshot_copy(dir, &id, &host))),
            Some(Leftover::SnapshotCopy(Some("n1")))
        );
        assert_eq!(
            classify(&name(volume_build(dir, &id, &host))),
            Some(Leftover::VolumeBuild("n1"))
        );
        let (src, dst) = probe_pair(dir, &host);
        assert_eq!(classify(&name(src)), Some(Leftover::Probe(Some("n1"))));
        assert_eq!(classify(&name(dst)), Some(Leftover::Probe(Some("n1"))));
        assert_eq!(
            classify(&format!("{id}.snap.tmp")),
            Some(Leftover::SnapshotCopy(None))
        );
        assert_eq!(classify(&format!("{id}.tmp")), None, "legacy volume tmp");
        assert_eq!(classify(&format!("{id}.raw")), None);
        assert_eq!(classify(&format!("{id}.snap")), None);
    }

    /// The heartbeat keeps a running copy's mtime fresh, which is the whole
    /// of the proof another host reads.
    #[test]
    fn a_running_copy_keeps_its_file_fresh() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp
            .path()
            .join("x.snap.tmp.n1.0123456789abcdef0123456789abcdef");
        std::fs::write(&path, b"x").unwrap();
        backdate(&path, Duration::from_secs(7200));
        let staged = Staged::with_heartbeat(path.clone(), Duration::from_millis(20));
        assert!(in_flight(&path));
        std::thread::sleep(Duration::from_millis(300));
        let age = SystemTime::now()
            .duration_since(std::fs::metadata(&path).unwrap().modified().unwrap())
            .unwrap_or(Duration::ZERO);
        assert!(age < Duration::from_secs(60), "refreshed: {age:?}");
        drop(staged);
        assert!(!in_flight(&path), "and unregistered when the copy ends");
    }

    /// The rules, one file each: this host's goes, another host's goes only
    /// when stale, a name from before the change is judged like a foreign
    /// one, and nothing that is not a staging file is touched.
    #[test]
    fn the_sweep_takes_what_is_provably_dead_and_nothing_else() {
        let temp = tempfile::tempdir().unwrap();
        let dir = temp.path();
        let me = HostTag::new("node-b").unwrap();
        let other = HostTag::new("node-a").unwrap();
        let id = uuid::Uuid::new_v4();
        let old = Duration::from_secs(2 * 3600);

        let own_snap = snapshot_copy(dir, &id, &me);
        let own_vol = volume_build(dir, &id, &me);
        let (own_probe, _) = probe_pair(dir, &me);
        let fresh_foreign = snapshot_copy(dir, &id, &other);
        let stale_foreign = volume_build(dir, &id, &other);
        let (fresh_foreign_probe, _) = probe_pair(dir, &other);
        let fresh_legacy = legacy_snapshot_copy(dir, &uuid::Uuid::new_v4());
        let stale_legacy = legacy_snapshot_copy(dir, &uuid::Uuid::new_v4());
        let legacy_vol = legacy_volume_build(dir, &id);
        let volume = dir.join(format!("{id}.raw"));
        let running_own = snapshot_copy(dir, &uuid::Uuid::new_v4(), &me);
        for p in [
            &own_snap,
            &own_vol,
            &own_probe,
            &fresh_foreign,
            &stale_foreign,
            &fresh_foreign_probe,
            &fresh_legacy,
            &stale_legacy,
            &legacy_vol,
            &volume,
            &running_own,
        ] {
            std::fs::write(p, b"x").unwrap();
        }
        backdate(&stale_foreign, old);
        backdate(&stale_legacy, old);
        backdate(&legacy_vol, old);
        backdate(&volume, old);
        let _running = Staged::with_heartbeat(running_own.clone(), Duration::from_secs(3600));

        sweep(dir, &me);

        for gone in [
            &own_snap,
            &own_vol,
            &own_probe,
            &stale_foreign,
            &stale_legacy,
        ] {
            assert!(!gone.exists(), "{} should be gone", gone.display());
        }
        for kept in [
            &fresh_foreign,
            &fresh_foreign_probe,
            &fresh_legacy,
            &legacy_vol,
            &volume,
            &running_own,
        ] {
            assert!(kept.exists(), "{} should be kept", kept.display());
        }
        let clocks: Vec<_> = std::fs::read_dir(dir)
            .unwrap()
            .flatten()
            .filter(|e| e.file_name().to_string_lossy().starts_with(CLOCK_PREFIX))
            .collect();
        assert!(clocks.is_empty(), "the clock marker cleans up after itself");
    }
}
