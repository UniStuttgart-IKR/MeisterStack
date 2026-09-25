// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! The second door: files and the clock.
//!
//! The pre-v1 tool had one narrow door for commands and none for anything
//! else, so a `--dry-run` that ran no command still wrote files
//! (`fleet.rs`, `main.rs`, `ops.rs` all called `std::fs` directly) and a
//! rollout slept on the real clock, which made "wait for the replica to be
//! healthy" a test that takes two minutes or a test that does not exist.
//!
//! Both doors answer to the same [`Policy`]: a write is an
//! [`Effect::LocalWrite`], so a dry run refuses it for the same reason and
//! with the same kind of sentence it refuses a `nix build`. There is no
//! second rule table to keep in step with the first.
//!
//! New code does not call `std::fs`, `std::thread::sleep` or `Utc::now`
//! directly; `tests/no_direct_effects.rs` is what keeps that true.

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

/// What a path in a working tree is, WITHOUT following a symbolic link.
///
/// The distinction is the whole point of `--dev`: a link that points at
/// `~/.ssh/id_ed25519` is copied as a link and stays dangling in the nix
/// store; the same path followed would copy the key itself.
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

/// Every file this tool reads or writes goes through here.
///
/// `write_atomic` is the only way to create a file, because every file this
/// tool writes is a file somebody else reads: a manifest a build consumes, a
/// `known_hosts` an ssh reads, a receipt an operator attaches to a ticket. A
/// half-written one of those is worse than a missing one.
pub trait Files {
    fn read(&self, path: &Path) -> Result<Vec<u8>>;
    fn read_to_string(&self, path: &Path) -> Result<String>;
    fn exists(&self, path: &Path) -> bool;

    /// The file's text, `None` when there is no file at this path — and an
    /// error for everything else.
    ///
    /// Astra finding MD06, 2026-09-25: a caller that asks "is there an
    /// installation mark on this disk" has three answers to tell apart, not
    /// two. "No such file" is the one that means "not installed"; a file
    /// that is there and cannot be read (an I/O error, bytes that are not
    /// utf-8, a directory where a file was expected) is a disk whose
    /// history this program does not know, and a guard that folds that
    /// into "not installed" is a guard that does not guard. `exists` cannot
    /// carry the distinction either: it answers `false` for a path it is
    /// not allowed to look at.
    fn read_if_present(&self, path: &Path) -> Result<Option<String>>;

    /// Write the whole file or none of it: a temporary in the same directory,
    /// `fsync`, `rename`, then `fsync` of the directory. Same directory
    /// because `rename` is only atomic within a filesystem, and the directory
    /// `fsync` because a rename that is not durable is a file that exists
    /// until the machine loses power.
    fn write_atomic(&self, path: &Path, bytes: &[u8], mode: u32) -> Result<()>;

    fn create_dir_all(&self, path: &Path) -> Result<()>;

    /// What is at this path, without following a link.
    fn entry(&self, path: &Path) -> Result<Entry>;

    /// Whether anything at all is at this exact path — file, symlink or
    /// other — without following a symlink to ask whether ITS target is
    /// there too. `exists` follows; this does not.
    ///
    /// Astra finding F16, 2026-09-23: a caller that has to tell "this path
    /// was deleted" apart from "this path is a dangling symlink, which is
    /// allowed and stays dangling" cannot use `exists` for that — a dangling
    /// symlink IS present and `exists` says it is not, because it followed
    /// the link to a target that is not there.
    fn is_present(&self, path: &Path) -> bool;

    /// Make `link` point at `target`, replacing whatever is there. Atomic for
    /// the same reason `write_atomic` is: a snapshot with half a link in it
    /// is a snapshot nix would evaluate.
    fn symlink_atomic(&self, target: &Path, link: &Path) -> Result<()>;

    /// Append one line and make it durable before returning. The journal's
    /// whole worth is that an entry written before an irreversible action is
    /// on the disk when the machine that was writing it goes away.
    fn append_fsync(&self, path: &Path, line: &str) -> Result<()>;

    /// Create this file, or fail because somebody else already did.
    ///
    /// The other half of [`Files::write_atomic`]: that one replaces what is
    /// there, and this one refuses to. It is what a lock is — `O_EXCL` is
    /// the only thing on a POSIX filesystem that two processes can race for
    /// and have exactly one of them win — so it is a door of its own rather
    /// than a flag on the other, which somebody would eventually pass the
    /// wrong way round.
    fn create_new(&self, path: &Path, bytes: &[u8], mode: u32) -> Result<()>;

    /// Remove a file. `Ok(())` when it was not there: this is used to
    /// release a lock and to drop a garbage-collector root, and in both
    /// cases "it is gone" is the outcome asked for.
    fn remove_file(&self, path: &Path) -> Result<()>;

    /// What is directly in this directory, sorted, without walking into it.
    /// An empty list for a directory that is not there — a state directory
    /// nobody has written to yet holds no runs, and that is an answer.
    fn list_dir(&self, path: &Path) -> Result<Vec<PathBuf>>;

    /// Remove an EMPTY directory. Not a recursive delete: the only
    /// directories this tool removes are ones it has just emptied itself
    /// (a release's garbage-collector roots), and a recursive delete in a
    /// deployment tool is a foot-gun waiting for a wrong path.
    fn remove_dir(&self, path: &Path) -> Result<()>;

    // --- lane 5A ---
    /// Move a file that is ALREADY THERE, replacing whatever is at `to`.
    ///
    /// Its own door rather than a read and a write, because what is wanted
    /// is the one thing a rename gives and a copy does not: a reader either
    /// sees the old file or the new one, never a half of either. That is
    /// what makes a key rotation survivable — the pair a service opens is
    /// always a pair somebody wrote whole. The directory is made durable
    /// afterwards for the reason `write_atomic` does it: a rename that is
    /// not on the disk is a rename that did not happen.
    fn rename(&self, from: &Path, to: &Path) -> Result<()>;
    // --- end lane 5A ---
}

/// The directory a file lives in, as something that can be opened.
///
/// `Path::new("plan.json").parent()` is `Some("")` and not `None`, and an
/// empty path opens nothing: the temporary lands beside the file either way,
/// the rename works, and only the directory `fsync` fails — so a bare
/// relative `--out` used to write the file and then report an error about
/// it. Both spellings of "the current directory" become `.` here.
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

    /// A write is a `local-write`, and the policy that decides about
    /// `nix build` decides about this too.
    ///
    /// Note for M2: there is no exception to this for `plan --offline`. The
    /// offline contract is "no nix, no network, no file written", so an
    /// offline plan is provisional and goes to stdout; `--out` together with
    /// `--offline` is refused with a sentence rather than given a policy of
    /// its own.
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
        // The pid in the name so that two operators on one NFS state
        // directory cannot land on the same temporary, and `create_new` so
        // that the loser of such a race is an error rather than a corruption.
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
        // One `write_all` rather than two: a single write of a short line to
        // a file opened O_APPEND is what keeps two writers from interleaving
        // halves of a line.
        let mut bytes = line.as_bytes().to_vec();
        bytes.push(b'\n');
        file.write_all(&bytes)
            .with_context(|| format!("appending to {} failed", path.display()))?;
        file.sync_all()
            .with_context(|| format!("making the new line in {} durable failed", path.display()))
    }

    fn create_new(&self, path: &Path, bytes: &[u8], mode: u32) -> Result<()> {
        self.may_write(path)?;
        // Astra finding MD03, 2026-09-25: this used to open `path` itself
        // with `O_EXCL` and write the bytes into it afterwards — so the NAME
        // was there before the contents were, and a process that lost the
        // race and read the file in that window read nothing. For a lock
        // that names its holder, nothing looked like nobody, and the reader
        // removed the name and took the lock for itself.
        //
        // So the bytes go into a private temporary first, whole and fsynced,
        // and the name is published with `link(2)`: it fails with `EEXIST`
        // when the name is taken, as exclusively as `O_EXCL` does, and when
        // it succeeds the file behind the name is already complete. Not a
        // rename: a rename REPLACES, and the whole point here is to lose the
        // race rather than win it silently.
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

    // --- lane 5A ---
    fn rename(&self, from: &Path, to: &Path) -> Result<()> {
        self.may_write(from)?;
        self.may_write(to)?;
        std::fs::rename(from, to)
            .with_context(|| format!("moving {} to {} failed", from.display(), to.display()))?;
        std::fs::File::open(parent_of(to))
            .and_then(|d| d.sync_all())
            .with_context(|| format!("making the move to {} durable failed", to.display()))
    }
    // --- end lane 5A ---

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

/// What a test writes into and reads back. It records every write ATTEMPT,
/// including the ones the policy refused, so a test can say "this run wrote
/// nothing" and mean it rather than mean "no file happened to appear".
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
        // Only a path nothing at all is at is "not there": a directory, a
        // link or an `other` at this path is something this test put there
        // to be found and not read, which is the case `read_to_string`
        // reports.
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
        // The same membership check `entry` makes: nothing here follows a
        // link to ask whether its target is there too, so this and `exists`
        // happen to agree in this fake filesystem (unlike `RealFiles`,
        // where a dangling symlink tells them apart).
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

    // --- lane 5A ---
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
    // --- end lane 5A ---

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

/// Time, as something a test can hold still.
///
/// `now` is UTC and nothing else: every timestamp this tool writes ends up in
/// a manifest or a journal that two machines compare, and a local time zone
/// in either of those is a bug waiting for a flight to Stuttgart.
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
    use super::parent_of;

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

    // Astra finding MD03, 2026-09-25.
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
