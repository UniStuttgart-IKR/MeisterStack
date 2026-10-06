// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Policy-controlled filesystem access, injectable clocks and the process table.
//!
//! Mutations use `Effect::LocalWrite`, which both offline and dry-run policies
//! refuse. Real and in-memory implementations share the filesystem interface;
//! clock injection allows polling tests without wall-clock delays, and process
//! injection lets a test reuse a pid or reboot a host.

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::fs::OpenOptions;
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use chrono::{DateTime, TimeDelta, Utc};

use crate::run::{Effect, Policy};

#[cfg(test)]
pub mod cut;

/// Working-tree entry type, inspected without following symlinks.
/// Snapshot copying preserves links instead of copying their targets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Entry {
    /// A regular file, and the low nine bits of its mode. The execute bit is
    /// kept because it is part of what nix hashes.
    File { mode: u32 },
    /// A symbolic link, and where it points, verbatim.
    Symlink { target: PathBuf },
    /// A directory, a socket, a fifo, a device node. Nothing this tool copies.
    Other,
}

/// Filesystem access used by deployment operations. Atomic replacement and
/// exclusive publication prevent readers from observing partially written files.
pub trait Files {
    fn read(&self, path: &Path) -> Result<Vec<u8>>;
    fn read_to_string(&self, path: &Path) -> Result<String>;
    fn exists(&self, path: &Path) -> bool;

    /// Read UTF-8 text, returning `None` only for a missing path.
    /// Unreadable, invalid-text and non-file entries are errors; callers must not
    /// interpret those as evidence that installation state is absent.
    fn read_if_present(&self, path: &Path) -> Result<Option<String>>;

    /// Replace through a same-directory temporary: write, fsync, rename, then
    /// fsync the parent directory.
    fn write_atomic(&self, path: &Path, bytes: &[u8], mode: u32) -> Result<()>;

    fn create_dir_all(&self, path: &Path) -> Result<()>;

    /// What is at this path, without following a link.
    fn entry(&self, path: &Path) -> Result<Entry>;

    /// Check the entry without following symlinks; dangling links are present.
    /// Like `exists`, this boolean cannot distinguish absence from lookup errors.
    fn is_present(&self, path: &Path) -> bool;

    /// Atomically replace a symlink within its parent directory.
    fn symlink_atomic(&self, target: &Path, link: &Path) -> Result<()>;

    /// Append one line and make it durable before returning. The journal's
    /// whole worth is that an entry written before an irreversible action is
    /// on the disk when the machine that was writing it goes away.
    fn append_fsync(&self, path: &Path, line: &str) -> Result<()>;

    /// Publish complete file contents only if the destination is absent.
    /// Unlike replacement, competing publishers cannot overwrite the winner.
    fn create_new(&self, path: &Path, bytes: &[u8], mode: u32) -> Result<()>;

    /// Remove a file. `Ok(())` when it was not there: this is used to
    /// release a lock and to drop a garbage-collector root, and in both
    /// cases "it is gone" is the outcome asked for.
    fn remove_file(&self, path: &Path) -> Result<()>;

    /// What is directly in this directory, sorted, without walking into it.
    /// An empty list for a directory that is not there — a state directory
    /// nobody has written to yet holds no runs, and that is an answer.
    fn list_dir(&self, path: &Path) -> Result<Vec<PathBuf>>;

    /// Remove an empty directory without recursively deleting its contents.
    fn remove_dir(&self, path: &Path) -> Result<()>;

    /// Rename an existing file, replacing the destination, then fsync its parent.
    /// The rename is atomic within a filesystem; this does not atomically swap a pair.
    fn rename(&self, from: &Path, to: &Path) -> Result<()>;
}

/// Normalize an empty parent path to `.` so bare relative filenames support
/// parent-directory fsync.
fn parent_of(path: &Path) -> &Path {
    match path.parent() {
        Some(dir) if !dir.as_os_str().is_empty() => dir,
        _ => Path::new("."),
    }
}

/// The real one. Refuses every write a `--dry-run` or an `--offline` run is
/// not allowed to make — and refuses it before the file is opened, so a
/// refused run cannot leave a zero-length file behind either.
pub struct RealFiles {
    pub policy: Policy,
}

impl RealFiles {
    pub fn new(policy: Policy) -> RealFiles {
        RealFiles { policy }
    }

    /// Apply LocalWrite policy uniformly, including offline output requests.
    fn may_write(&self, path: &Path) -> Result<()> {
        match self.policy.admits(Effect::LocalWrite) {
            Ok(()) => Ok(()),
            Err(why) => bail!("{} was not written: {why}.", path.display()),
        }
    }
}

impl Files for RealFiles {
    fn read(&self, path: &Path) -> Result<Vec<u8>> {
        std::fs::read(path).with_context(|| format!("reading {} failed", path.display()))
    }

    fn read_to_string(&self, path: &Path) -> Result<String> {
        std::fs::read_to_string(path).with_context(|| format!("reading {} failed", path.display()))
    }

    fn read_if_present(&self, path: &Path) -> Result<Option<String>> {
        match std::fs::read_to_string(path) {
            Ok(text) => Ok(Some(text)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e).with_context(|| format!("reading {} failed", path.display())),
        }
    }

    fn exists(&self, path: &Path) -> bool {
        path.exists()
    }

    fn write_atomic(&self, path: &Path, bytes: &[u8], mode: u32) -> Result<()> {
        self.may_write(path)?;
        let dir = parent_of(path);
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "out".to_string());
        // Use a PID-suffixed temporary with exclusive creation; collisions fail.
        // PIDs are not globally unique across hosts sharing a filesystem.
        let tmp = dir.join(format!(".{name}.tmp.{}", std::process::id()));

        let write = || -> Result<()> {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(mode)
                .open(&tmp)?;
            file.write_all(bytes)?;
            file.sync_all()?;
            Ok(())
        };
        if let Err(e) = write() {
            let _ = std::fs::remove_file(&tmp);
            return Err(e).with_context(|| format!("writing {} failed", tmp.display()));
        }
        std::fs::rename(&tmp, path).with_context(|| {
            format!(
                "moving {} into place as {} failed",
                tmp.display(),
                path.display()
            )
        })?;
        // A directory handle is opened read-only; fsync on it is what makes
        // the rename itself durable.
        std::fs::File::open(dir)
            .and_then(|d| d.sync_all())
            .with_context(|| format!("making the new {} durable failed", path.display()))?;
        Ok(())
    }

    fn create_dir_all(&self, path: &Path) -> Result<()> {
        self.may_write(path)?;
        std::fs::create_dir_all(path).with_context(|| format!("creating {} failed", path.display()))
    }

    fn entry(&self, path: &Path) -> Result<Entry> {
        // `symlink_metadata` and not `metadata`: the second one follows.
        let meta = std::fs::symlink_metadata(path)
            .with_context(|| format!("looking at {} failed", path.display()))?;
        if meta.file_type().is_symlink() {
            let target = std::fs::read_link(path)
                .with_context(|| format!("reading the link {} failed", path.display()))?;
            Ok(Entry::Symlink { target })
        } else if meta.is_file() {
            Ok(Entry::File {
                mode: meta.permissions().mode() & 0o777,
            })
        } else {
            Ok(Entry::Other)
        }
    }

    fn is_present(&self, path: &Path) -> bool {
        // Same call `entry` makes: it does not follow, so a dangling
        // symlink answers `true` here and `false` from `exists`.
        std::fs::symlink_metadata(path).is_ok()
    }

    fn symlink_atomic(&self, target: &Path, link: &Path) -> Result<()> {
        self.may_write(link)?;
        let dir = parent_of(link);
        let name = link
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "link".to_string());
        let tmp = dir.join(format!(".{name}.tmp.{}", std::process::id()));
        // A leftover from a run that died between these two lines. It is ours
        // by name and it is in the way.
        let _ = std::fs::remove_file(&tmp);
        std::os::unix::fs::symlink(target, &tmp)
            .with_context(|| format!("linking {} to {} failed", tmp.display(), target.display()))?;
        std::fs::rename(&tmp, link).with_context(|| {
            format!(
                "moving the link {} into place as {} failed",
                tmp.display(),
                link.display()
            )
        })?;
        std::fs::File::open(dir)
            .and_then(|d| d.sync_all())
            .with_context(|| format!("making the new {} durable failed", link.display()))
    }

    fn append_fsync(&self, path: &Path, line: &str) -> Result<()> {
        self.may_write(path)?;
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(path)
            .with_context(|| format!("opening {} to append failed", path.display()))?;
        // Append each event through one write_all call before fsync. Concurrent
        // writers still require external serialization.
        let mut bytes = line.as_bytes().to_vec();
        bytes.push(b'\n');
        file.write_all(&bytes)
            .with_context(|| format!("appending to {} failed", path.display()))?;
        file.sync_all()
            .with_context(|| format!("making the new line in {} durable failed", path.display()))
    }

    fn create_new(&self, path: &Path, bytes: &[u8], mode: u32) -> Result<()> {
        self.may_write(path)?;
        // Write and fsync a private temporary before publishing it with `link(2)`.
        // The link fails if another publisher won, while successful readers see complete
        // contents. Publishing an empty destination first would expose incomplete locks.
        let dir = parent_of(path);
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "out".to_string());
        // The pid and a counter in the name: two processes on one NFS state
        // directory, and two threads of one process, must not land on the
        // same temporary.
        static NONCE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let tmp = dir.join(format!(
            ".{name}.new.{}.{}",
            std::process::id(),
            NONCE.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        let write = || -> Result<()> {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(mode)
                .open(&tmp)?;
            file.write_all(bytes)?;
            file.sync_all()?;
            Ok(())
        };
        if let Err(e) = write() {
            let _ = std::fs::remove_file(&tmp);
            return Err(e).with_context(|| format!("writing {} failed", tmp.display()));
        }
        let published = std::fs::hard_link(&tmp, path);
        // The temporary is done with either way: when the link was made,
        // the name is the file; when it was not, there is nothing to keep.
        let _ = std::fs::remove_file(&tmp);
        published.with_context(|| format!("creating {} failed", path.display()))?;
        // The directory too: a lock that is not durable is a lock a power
        // cut hands to the next run.
        std::fs::File::open(dir)
            .and_then(|d| d.sync_all())
            .with_context(|| format!("making the new {} durable failed", path.display()))
    }

    fn remove_file(&self, path: &Path) -> Result<()> {
        self.may_write(path)?;
        match std::fs::remove_file(path) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) => {
                return Err(e).with_context(|| format!("removing {} failed", path.display()));
            }
        }
        std::fs::File::open(parent_of(path))
            .and_then(|d| d.sync_all())
            .with_context(|| format!("making the removal of {} durable failed", path.display()))
    }

    fn rename(&self, from: &Path, to: &Path) -> Result<()> {
        self.may_write(from)?;
        self.may_write(to)?;
        std::fs::rename(from, to)
            .with_context(|| format!("moving {} to {} failed", from.display(), to.display()))?;
        std::fs::File::open(parent_of(to))
            .and_then(|d| d.sync_all())
            .with_context(|| format!("making the move to {} durable failed", to.display()))
    }

    fn remove_dir(&self, path: &Path) -> Result<()> {
        self.may_write(path)?;
        match std::fs::remove_dir(path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e).with_context(|| format!("removing {} failed", path.display())),
        }
    }

    fn list_dir(&self, path: &Path) -> Result<Vec<PathBuf>> {
        let entries = match std::fs::read_dir(path) {
            Ok(entries) => entries,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => {
                return Err(e).with_context(|| format!("reading {} failed", path.display()));
            }
        };
        let mut out = Vec::new();
        for entry in entries {
            let entry = entry.with_context(|| format!("reading {} failed", path.display()))?;
            out.push(entry.path());
        }
        // Sorted, so that a listing is the same listing twice: a receipt
        // that names runs in the order a directory happened to hand them
        // over is a receipt nobody can diff.
        out.sort();
        Ok(out)
    }
}

/// In-memory filesystem recording attempted writes, including policy refusals.
#[derive(Debug, Default)]
pub struct MemFiles {
    policy: Policy,
    files: RefCell<BTreeMap<PathBuf, Vec<u8>>>,
    modes: RefCell<BTreeMap<PathBuf, u32>>,
    links: RefCell<BTreeMap<PathBuf, PathBuf>>,
    /// Paths that are neither a file nor a link: what a test uses to make a
    /// fifo or a socket appear in a listing.
    others: RefCell<BTreeSet<PathBuf>>,
    dirs: RefCell<BTreeSet<PathBuf>>,
    attempts: RefCell<Vec<String>>,
}

impl MemFiles {
    pub fn new() -> MemFiles {
        MemFiles::default()
    }

    pub fn with_policy(mut self, policy: Policy) -> MemFiles {
        self.policy = policy;
        self
    }

    /// Put a file there before the code under test looks for it.
    pub fn given(self, path: impl Into<PathBuf>, contents: impl Into<Vec<u8>>) -> MemFiles {
        self.files.borrow_mut().insert(path.into(), contents.into());
        self
    }

    /// The same, with the execute bit set.
    pub fn given_exec(self, path: impl Into<PathBuf>, contents: impl Into<Vec<u8>>) -> MemFiles {
        let path = path.into();
        self.modes.borrow_mut().insert(path.clone(), 0o755);
        self.given(path, contents)
    }

    pub fn given_symlink(self, link: impl Into<PathBuf>, target: impl Into<PathBuf>) -> MemFiles {
        self.links.borrow_mut().insert(link.into(), target.into());
        self
    }

    /// Something that is not a file and not a link — a fifo, a socket.
    pub fn given_other(self, path: impl Into<PathBuf>) -> MemFiles {
        self.others.borrow_mut().insert(path.into());
        self
    }

    /// Where a link in this test filesystem points.
    pub fn link_target(&self, path: impl AsRef<Path>) -> Option<PathBuf> {
        self.links.borrow().get(path.as_ref()).cloned()
    }

    /// Every write, create or append this run asked for, refused ones
    /// included, in order.
    pub fn attempts(&self) -> Vec<String> {
        self.attempts.borrow().clone()
    }

    /// What ended up on the "disk", for a test that wants to read it back.
    pub fn content(&self, path: impl AsRef<Path>) -> Option<Vec<u8>> {
        self.files.borrow().get(path.as_ref()).cloned()
    }

    pub fn paths(&self) -> Vec<PathBuf> {
        self.files.borrow().keys().cloned().collect()
    }

    /// Every file under `dir` and what it holds: a disk a test can compare
    /// with another.
    pub fn contents_under(&self, dir: impl AsRef<Path>) -> BTreeMap<PathBuf, Vec<u8>> {
        let dir = dir.as_ref();
        self.files
            .borrow()
            .iter()
            .filter(|(path, _)| path.starts_with(dir))
            .map(|(path, bytes)| (path.clone(), bytes.clone()))
            .collect()
    }

    fn may_write(&self, what: &str, path: &Path) -> Result<()> {
        self.attempts
            .borrow_mut()
            .push(format!("{what} {}", path.display()));
        match self.policy.admits(Effect::LocalWrite) {
            Ok(()) => Ok(()),
            Err(why) => bail!("{} was not written: {why}.", path.display()),
        }
    }
}

impl Files for MemFiles {
    fn read(&self, path: &Path) -> Result<Vec<u8>> {
        match self.files.borrow().get(path) {
            Some(bytes) => Ok(bytes.clone()),
            None => bail!(
                "reading {} failed: no such file in this test.",
                path.display()
            ),
        }
    }

    fn read_to_string(&self, path: &Path) -> Result<String> {
        let bytes = self.read(path)?;
        String::from_utf8(bytes).with_context(|| format!("{} is not utf-8", path.display()))
    }

    fn read_if_present(&self, path: &Path) -> Result<Option<String>> {
        // Only a missing entry returns None; other entry types produce read errors.
        if !self.exists(path) {
            return Ok(None);
        }
        self.read_to_string(path).map(Some)
    }

    fn exists(&self, path: &Path) -> bool {
        self.files.borrow().contains_key(path)
            || self.dirs.borrow().contains(path)
            || self.links.borrow().contains_key(path)
            || self.others.borrow().contains(path)
    }

    fn write_atomic(&self, path: &Path, bytes: &[u8], mode: u32) -> Result<()> {
        self.may_write(&format!("write({mode:04o})"), path)?;
        self.files
            .borrow_mut()
            .insert(path.to_path_buf(), bytes.to_vec());
        Ok(())
    }

    fn create_dir_all(&self, path: &Path) -> Result<()> {
        self.may_write("mkdir", path)?;
        self.dirs.borrow_mut().insert(path.to_path_buf());
        Ok(())
    }

    fn entry(&self, path: &Path) -> Result<Entry> {
        if let Some(target) = self.links.borrow().get(path) {
            return Ok(Entry::Symlink {
                target: target.clone(),
            });
        }
        if self.others.borrow().contains(path) || self.dirs.borrow().contains(path) {
            return Ok(Entry::Other);
        }
        if self.files.borrow().contains_key(path) {
            let mode = self.modes.borrow().get(path).copied().unwrap_or(0o644);
            return Ok(Entry::File { mode });
        }
        bail!(
            "looking at {} failed: no such file in this test.",
            path.display()
        )
    }

    fn is_present(&self, path: &Path) -> bool {
        // The fake checks membership without following links; unlike RealFiles, its
        // `exists` and `is_present` therefore agree for dangling symlinks.
        self.exists(path)
    }

    fn symlink_atomic(&self, target: &Path, link: &Path) -> Result<()> {
        self.may_write(&format!("link(-> {})", target.display()), link)?;
        self.links
            .borrow_mut()
            .insert(link.to_path_buf(), target.to_path_buf());
        Ok(())
    }

    fn append_fsync(&self, path: &Path, line: &str) -> Result<()> {
        self.may_write("append", path)?;
        let mut files = self.files.borrow_mut();
        let buf = files.entry(path.to_path_buf()).or_default();
        buf.extend_from_slice(line.as_bytes());
        buf.push(b'\n');
        Ok(())
    }

    fn create_new(&self, path: &Path, bytes: &[u8], mode: u32) -> Result<()> {
        self.may_write(&format!("create_new({mode:04o})"), path)?;
        if self.exists(path) {
            bail!(
                "creating {} failed: it already exists in this test.",
                path.display()
            );
        }
        self.files
            .borrow_mut()
            .insert(path.to_path_buf(), bytes.to_vec());
        self.modes.borrow_mut().insert(path.to_path_buf(), mode);
        Ok(())
    }

    fn remove_file(&self, path: &Path) -> Result<()> {
        self.may_write("remove", path)?;
        self.files.borrow_mut().remove(path);
        self.modes.borrow_mut().remove(path);
        self.links.borrow_mut().remove(path);
        Ok(())
    }

    fn rename(&self, from: &Path, to: &Path) -> Result<()> {
        self.may_write("rename", from)?;
        self.may_write("rename", to)?;
        let bytes =
            self.files.borrow().get(from).cloned().ok_or_else(|| {
                anyhow::anyhow!("moving {} failed: it is not there", from.display())
            })?;
        let mode = self.modes.borrow().get(from).copied();
        self.files.borrow_mut().remove(from);
        self.modes.borrow_mut().remove(from);
        self.files.borrow_mut().insert(to.to_path_buf(), bytes);
        if let Some(mode) = mode {
            self.modes.borrow_mut().insert(to.to_path_buf(), mode);
        }
        Ok(())
    }

    fn remove_dir(&self, path: &Path) -> Result<()> {
        self.may_write("rmdir", path)?;
        let left = self.list_dir(path)?;
        if !left.is_empty() {
            bail!(
                "removing {} failed: it still holds {} entry/entries in this test.",
                path.display(),
                left.len()
            );
        }
        self.dirs.borrow_mut().remove(path);
        Ok(())
    }

    fn list_dir(&self, path: &Path) -> Result<Vec<PathBuf>> {
        // Whatever lies directly under this path, whether somebody made the
        // directory in this test or only put a file in it.
        let mut out = BTreeSet::new();
        let mut take = |candidate: &Path| {
            if let Ok(rest) = candidate.strip_prefix(path)
                && let Some(first) = rest.components().next()
            {
                out.insert(path.join(first));
            }
        };
        for known in self.files.borrow().keys() {
            take(known);
        }
        for known in self.dirs.borrow().iter() {
            take(known);
        }
        for known in self.links.borrow().keys() {
            take(known);
        }
        Ok(out.into_iter().collect())
    }
}

/// What the kernel says of one pid right now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessState {
    /// No process has this pid, or only a zombie that runs nothing.
    Gone,
    /// A process runs under this pid, started this many clock ticks after boot.
    Running { start: u64 },
    /// The kernel did not say.
    Unreadable,
}

/// Process identity: this process's pid, the boot it runs in, and which
/// process holds a pid now. A pid alone is reused; the start time of the
/// pid and the boot tell one holder from the next.
pub trait Processes {
    fn own_pid(&self) -> u32;
    /// `/proc/sys/kernel/random/boot_id`; `None` when it cannot be read.
    fn boot_id(&self) -> Option<String>;
    fn state_of(&self, pid: u32) -> ProcessState;
}

/// This process and the kernel's process table, read from procfs.
pub struct RealProcesses;

impl Processes for RealProcesses {
    fn own_pid(&self) -> u32 {
        std::process::id()
    }

    fn boot_id(&self) -> Option<String> {
        let id = std::fs::read_to_string("/proc/sys/kernel/random/boot_id").ok()?;
        let id = id.trim();
        (!id.is_empty()).then(|| id.to_string())
    }

    fn state_of(&self, pid: u32) -> ProcessState {
        match std::fs::read_to_string(format!("/proc/{pid}/stat")) {
            Ok(stat) => proc_stat_state(&stat).unwrap_or(ProcessState::Unreadable),
            // Without procfs every pid reads as missing; only the kernel's
            // own answer to signal 0 says that nothing runs there.
            Err(_) if no_process_has(pid) => ProcessState::Gone,
            Err(_) => ProcessState::Unreadable,
        }
    }
}

/// Signal 0 answers ESRCH for a pid no process has. Pid 0 and pids beyond
/// `i32` name no process a lock could have been written by.
fn no_process_has(pid: u32) -> bool {
    match i32::try_from(pid) {
        Ok(pid) if pid > 0 => matches!(
            nix::sys::signal::kill(nix::unistd::Pid::from_raw(pid), None),
            Err(nix::errno::Errno::ESRCH)
        ),
        _ => true,
    }
}

/// `/proc/<pid>/stat` (proc_pid_stat(5)): the command name sits in
/// parentheses and may hold anything, so the fields are counted from the
/// last `)`. Field 3 is the state, field 22 the start time.
pub fn proc_stat_state(stat: &str) -> Option<ProcessState> {
    let mut fields = stat.rsplit_once(')')?.1.split_whitespace();
    let state = fields.next()?;
    let start = fields.nth(18)?.parse().ok()?;
    if matches!(state, "Z" | "X" | "x") {
        return Some(ProcessState::Gone);
    }
    Some(ProcessState::Running { start })
}

/// Injectable UTC timestamps and sleep, with a controllable test clock.
pub trait Clock {
    fn now(&self) -> DateTime<Utc>;
    fn sleep(&self, d: Duration);
}

pub struct RealClock;

impl Clock for RealClock {
    fn now(&self) -> DateTime<Utc> {
        Utc::now()
    }

    fn sleep(&self, d: Duration) {
        std::thread::sleep(d);
    }
}

/// A clock a test moves by hand. `sleep` advances it instead of waiting, so a
/// bounded wait — "poll the unit for ninety seconds" — is a test that runs in
/// a millisecond and still pins how long the code was willing to wait.
pub struct FakeClock {
    at: RefCell<DateTime<Utc>>,
    slept: RefCell<Vec<Duration>>,
}

impl FakeClock {
    pub fn at(start: DateTime<Utc>) -> FakeClock {
        FakeClock {
            at: RefCell::new(start),
            slept: RefCell::new(Vec::new()),
        }
    }

    /// A fixed, obviously-not-real instant, for tests that only need the
    /// timestamp to be the same on every run.
    pub fn fixed() -> FakeClock {
        FakeClock::at(
            DateTime::parse_from_rfc3339("2026-01-01T00:00:00Z")
                .expect("a literal this file controls")
                .with_timezone(&Utc),
        )
    }

    /// Every sleep that was asked for, in order.
    pub fn slept(&self) -> Vec<Duration> {
        self.slept.borrow().clone()
    }

    pub fn advance(&self, d: Duration) {
        let step = TimeDelta::from_std(d).unwrap_or(TimeDelta::zero());
        let mut at = self.at.borrow_mut();
        *at += step;
    }
}

impl Clock for FakeClock {
    fn now(&self) -> DateTime<Utc> {
        *self.at.borrow()
    }

    fn sleep(&self, d: Duration) {
        self.slept.borrow_mut().push(d);
        self.advance(d);
    }
}

#[cfg(test)]
mod tests {
    use super::{ProcessState, Processes, RealProcesses, parent_of, proc_stat_state};

    #[test]
    fn a_proc_stat_line_is_read_past_a_command_name_with_parentheses() {
        let line = "4242 (a) b (c)) S 1 4242 4242 0 -1 4194560 100 0 0 0 1 2 0 0 20 0 1 0 \
                    98765 1000 100 18446744073709551615 0 0 0 0 0 0 0 0 0 0 0 0 17 3";
        assert_eq!(
            proc_stat_state(line),
            Some(ProcessState::Running { start: 98765 })
        );
    }

    #[test]
    fn a_zombie_runs_nothing_under_its_pid() {
        let line = "4242 (gone) Z 1 4242 4242 0 -1 4194560 100 0 0 0 1 2 0 0 20 0 1 0 98765";
        assert_eq!(proc_stat_state(line), Some(ProcessState::Gone));
    }

    #[test]
    fn this_process_is_running_in_a_boot_the_kernel_names() {
        let me = RealProcesses;
        assert!(matches!(
            me.state_of(me.own_pid()),
            ProcessState::Running { .. }
        ));
        assert!(me.boot_id().is_some());
    }

    #[test]
    fn a_pid_beyond_every_pid_max_is_gone() {
        assert_eq!(RealProcesses.state_of(2_147_483_646), ProcessState::Gone);
    }

    #[test]
    fn a_bare_relative_name_lives_in_the_current_directory() {
        assert_eq!(
            parent_of(std::path::Path::new("plan.json")),
            std::path::Path::new(".")
        );
        assert_eq!(
            parent_of(std::path::Path::new("out/plan.json")),
            std::path::Path::new("out")
        );
        assert_eq!(
            parent_of(std::path::Path::new("/tmp/plan.json")),
            std::path::Path::new("/tmp")
        );
        assert_eq!(
            parent_of(std::path::Path::new("/")),
            std::path::Path::new(".")
        );
    }

    use super::*;
    use std::os::unix::fs::MetadataExt;

    #[test]
    fn an_atomic_write_leaves_no_temporary_and_the_mode_asked_for() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("manifest.json");
        let files = RealFiles::new(Policy::real());
        files.write_atomic(&path, b"{\"schema\":1}", 0o600).unwrap();

        assert_eq!(std::fs::read(&path).unwrap(), b"{\"schema\":1}");
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "a manifest is not world-readable by accident");
        let left: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(left, vec!["manifest.json"], "no temporary was left behind");
    }

    #[test]
    fn an_exclusive_create_publishes_a_whole_file_and_refuses_a_second() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("lock");
        let files = RealFiles::new(Policy::real());
        files.create_new(&path, b"confirm pid 4711", 0o600).unwrap();

        assert_eq!(std::fs::read(&path).unwrap(), b"confirm pid 4711");
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        assert_eq!(
            std::fs::metadata(&path).unwrap().nlink(),
            1,
            "the temporary the file was published from is gone"
        );
        let left: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(left, vec!["lock"], "no temporary was left behind");

        // The second one loses, and loses without touching the first.
        let err = files
            .create_new(&path, b"revert pid 4712", 0o600)
            .unwrap_err()
            .to_string();
        assert!(err.contains("creating"), "{err}");
        assert_eq!(std::fs::read(&path).unwrap(), b"confirm pid 4711");
        let left: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            left,
            vec!["lock"],
            "the loser left no temporary behind either"
        );
    }

    #[test]
    fn a_second_write_replaces_the_first_whole() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("m.json");
        let files = RealFiles::new(Policy::real());
        files.write_atomic(&path, b"first", 0o644).unwrap();
        files.write_atomic(&path, b"second", 0o644).unwrap();
        assert_eq!(files.read_to_string(&path).unwrap(), "second");
    }

    #[test]
    fn appending_keeps_whole_lines() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("journal.jsonl");
        let files = RealFiles::new(Policy::real());
        files.append_fsync(&path, "{\"seq\":1}").unwrap();
        files.append_fsync(&path, "{\"seq\":2}").unwrap();
        assert_eq!(
            files.read_to_string(&path).unwrap(),
            "{\"seq\":1}\n{\"seq\":2}\n"
        );
    }

    #[test]
    fn a_dry_run_writes_nothing_and_says_why() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("manifest.json");
        let files = RealFiles::new(Policy::dry_run());

        let err = files
            .write_atomic(&path, b"x", 0o644)
            .unwrap_err()
            .to_string();
        assert!(err.contains("manifest.json was not written"), "{err}");
        assert!(err.contains("--dry-run"), "{err}");
        assert!(files.create_dir_all(&dir.path().join("runs")).is_err());
        assert!(files.append_fsync(&path, "x").is_err());

        let left: Vec<_> = std::fs::read_dir(dir.path()).unwrap().collect();
        assert!(left.is_empty(), "not even an empty file was created");
    }

    #[test]
    fn an_offline_run_writes_nothing_either() {
        let dir = tempfile::tempdir().unwrap();
        let files = RealFiles::new(Policy::offline());
        let err = files
            .write_atomic(&dir.path().join("p.json"), b"x", 0o644)
            .unwrap_err()
            .to_string();
        assert!(err.contains("--offline"), "{err}");
    }

    #[test]
    fn the_test_files_record_every_attempt_including_the_refused_ones() {
        let files = MemFiles::new()
            .with_policy(Policy::dry_run())
            .given("/repo/fleet.toml", "schema = 2\n");
        assert_eq!(
            files.read_to_string(Path::new("/repo/fleet.toml")).unwrap(),
            "schema = 2\n"
        );
        assert!(
            files
                .write_atomic(Path::new("/out/m.json"), b"{}", 0o600)
                .is_err()
        );
        assert_eq!(files.attempts(), vec!["write(0600) /out/m.json"]);
        assert_eq!(files.paths(), vec![PathBuf::from("/repo/fleet.toml")]);
        assert!(files.content("/out/m.json").is_none());
    }

    #[test]
    fn the_test_files_can_also_be_written_to() {
        let files = MemFiles::new();
        files.create_dir_all(Path::new("/state/runs")).unwrap();
        files
            .write_atomic(Path::new("/state/m.json"), b"{}", 0o644)
            .unwrap();
        files
            .append_fsync(Path::new("/state/j.jsonl"), "a")
            .unwrap();
        files
            .append_fsync(Path::new("/state/j.jsonl"), "b")
            .unwrap();
        assert!(files.exists(Path::new("/state/runs")));
        assert_eq!(files.content("/state/j.jsonl").unwrap(), b"a\nb\n");
        assert_eq!(
            files.attempts(),
            vec![
                "mkdir /state/runs",
                "write(0644) /state/m.json",
                "append /state/j.jsonl",
                "append /state/j.jsonl"
            ]
        );
    }

    #[test]
    fn a_missing_file_says_which_one() {
        let files = MemFiles::new();
        let err = files
            .read(Path::new("/repo/flake.lock"))
            .unwrap_err()
            .to_string();
        assert!(err.contains("/repo/flake.lock"), "{err}");
    }

    #[test]
    fn a_fake_clock_sleeps_without_sleeping() {
        let clock = FakeClock::fixed();
        let before = clock.now();
        clock.sleep(Duration::from_secs(90));
        assert_eq!(clock.slept(), vec![Duration::from_secs(90)]);
        assert_eq!((clock.now() - before).num_seconds(), 90);
        assert_eq!(clock.now().to_rfc3339(), "2026-01-01T00:01:30+00:00");
    }
}
