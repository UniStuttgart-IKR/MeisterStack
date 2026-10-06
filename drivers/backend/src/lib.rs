// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Process lifecycle helpers for vhost-user device and storage backends.
//!
//! Drivers choose commands and attachment formats. This crate handles process
//! setup, socket-file readiness, logging, identity checks and termination.
//! Reusing an owned backend requires both a live child and an existing socket.

use std::path::Path;
use std::time::Duration;

use agent_api::CgroupHandle;
use agent_api::device::DeviceError;
use agent_api::storage::StorageError;
use nix::sys::signal::Signal;
use tracing::{Instrument, debug, info, warn};

/// How often the spawn wait re-checks for the socket.
const POLL_INTERVAL: Duration = Duration::from_millis(50);

/// How long a backend gets to honour SIGTERM before it is killed outright.
const TERM_GRACE: Duration = Duration::from_secs(2);

/// The kernel truncates `/proc/<pid>/comm` to `TASK_COMM_LEN - 1` characters,
/// so a longer expected name would never match anything.
const COMM_LEN: usize = 15;

/// How much of a dead backend's log to hang on the error that reports it.
const TAIL_CHARS: usize = 800;

/// Backend process failure or surrounding I/O failure.
#[derive(Debug, thiserror::Error)]
pub enum BackendError {
    /// Backend startup or exit failure, including its diagnostic log tail.
    #[error("{0}")]
    Died(String),
    #[error(transparent)]
    Failed(#[from] anyhow::Error),
}

pub type Result<T> = std::result::Result<T, BackendError>;

/// Map shared backend failures into the device API error vocabulary.
impl From<BackendError> for DeviceError {
    fn from(e: BackendError) -> Self {
        match e {
            BackendError::Died(m) => DeviceError::BackendDied(m),
            BackendError::Failed(e) => DeviceError::Backend(e),
        }
    }
}

impl From<BackendError> for StorageError {
    fn from(e: BackendError) -> Self {
        match e {
            BackendError::Died(m) => StorageError::BackendDied(m),
            BackendError::Failed(e) => StorageError::Backend(e),
        }
    }
}

/// Spawn, signal and restart-identity policy shared by one driver's backends.
#[derive(Clone, Debug)]
pub struct BackendKind {
    /// Names the process in errors and logs. The binary's own name, so a
    /// message stays greppable against `ps`.
    label: &'static str,
    /// What `/proc/<pid>/comm` must say for a process to be this backend,
    /// already cut to the length the kernel cuts it to.
    comm: String,
    /// setsid(2) at spawn, and therefore killpg(2) at teardown.
    own_session: bool,
    /// `RLIMIT_NOFILE` for the child, when the default 1024 is not enough.
    nofile_limit: Option<u64>,
    /// `/dev/null` on stdin, so a detached daemon cannot read the agent's.
    stdin_null: bool,
    /// Optional backend identity. A vhost-user backend can map guest memory,
    /// so its host privileges remain part of the VM's isolation boundary.
    vmm_user: Option<agent_api::VmmUser>,
}

impl BackendKind {
    /// Create a separate session so the backend can be signalled as a process
    /// group. Its PID is also its process-group ID. Apply the requested fd limit.
    pub fn detached(label: &'static str, comm: &str, nofile_limit: u64) -> Self {
        Self {
            label,
            comm: truncate_comm(comm),
            own_session: true,
            nofile_limit: Some(nofile_limit),
            stdin_null: true,
            vmm_user: None,
        }
    }

    /// Keep the backend in the agent's session and signal only its PID. Group
    /// signalling is reserved for backends started in their own session.
    pub fn child(label: &'static str, comm: &str) -> Self {
        Self {
            label,
            comm: truncate_comm(comm),
            own_session: false,
            nofile_limit: None,
            stdin_null: false,
            vmm_user: None,
        }
    }

    /// Choose a backend identity. Drivers decide whether identity switching is
    /// compatible with their workload; virtiofsd keeps the agent identity.
    pub fn as_user(mut self, user: Option<agent_api::VmmUser>) -> Self {
        self.vmm_user = user;
        self
    }

    /// Spawn the caller's command and wait for the socket path to appear.
    /// This readiness check does not connect to or validate the socket protocol.
    pub async fn spawn(
        &self,
        mut cmd: tokio::process::Command,
        io: BackendIo<'_>,
    ) -> Result<(u32, Backend)> {
        let BackendIo {
            socket,
            log,
            timeout,
            cgroup,
            span,
        } = io;

        // Remove stale sockets before readiness polling.
        let _ = tokio::fs::remove_file(socket).await;

        let log_file = std::fs::File::create(log).map_err(|e| BackendError::Failed(e.into()))?;
        // Transfer the socket directory and log before dropping backend identity.
        // The log path remains readable when failure reporting reopens it.
        if let Some(user) = &self.vmm_user {
            if let Some(dir) = socket.parent() {
                user.take(dir)
                    .map_err(|e| BackendError::Failed(anyhow::anyhow!("{}: {e}", dir.display())))?;
            }
            user.take(log)
                .map_err(|e| BackendError::Failed(anyhow::anyhow!("{}: {e}", log.display())))?;
        }
        let log_dup = log_file
            .try_clone()
            .map_err(|e| BackendError::Failed(e.into()))?;
        cmd.stdout(log_file).stderr(log_dup);
        if self.stdin_null {
            cmd.stdin(std::process::Stdio::null());
        }

        // Umask 007 keeps backend-created sockets accessible to the VMM user and
        // group while denying world access. Socket base mode 0777 yields 0770.
        let (own_session, nofile_limit) = (self.own_session, self.nofile_limit);
        // Cloned into the closure: `pre_exec` outlives this call.
        let user = self.vmm_user.clone();
        if own_session || nofile_limit.is_some() || user.is_some() {
            // SAFETY: pre_exec uses owned values and syscalls without allocation,
            // file opening or locking in the forked child.
            unsafe {
                cmd.pre_exec(move || {
                    if own_session {
                        nix::unistd::setsid().map_err(std::io::Error::from)?;
                    }
                    if let Some(limit) = nofile_limit {
                        let _ = nix::sys::resource::setrlimit(
                            nix::sys::resource::Resource::RLIMIT_NOFILE,
                            limit,
                            limit,
                        );
                    }
                    if let Some(user) = &user {
                        // `umask` first, so it applies to the socket the
                        // backend binds; then the credentials, which cannot
                        // be undone.
                        libc::umask(0o007);
                        user.switch_to()?;
                    }
                    Ok(())
                });
            }
        }

        let mut child = cmd.spawn().map_err(|e| match &self.vmm_user {
            Some(user) => BackendError::Died(format!("{} {}", self.label, user.cannot_switch(&e))),
            None => BackendError::Failed(e.into()),
        })?;
        // Every early return after spawn must kill and reap the child through
        // `abandon`; dropping a Tokio Child alone does not stop it. A caller
        // that drops this future mid-spawn returns early too, and the guard
        // kills the child then.
        let unready = KillUnlessReady {
            kind: self,
            child: &mut child,
        };
        let Some(pid) = unready.child.id() else {
            // Run cleanup for the exited child to ensure it is reaped.
            self.abandon(unready.child).await;
            return Err(BackendError::Died(format!(
                "{} exited before pid could be read",
                self.label
            )));
        };
        debug!(
            pid,
            backend = self.label,
            "backend spawned, waiting for socket"
        );

        if let Some(cg) = cgroup
            && let Err(e) = cg.attach_pid(pid)
        {
            self.abandon(unready.child).await;
            return Err(BackendError::Failed(anyhow::anyhow!("cgroup attach: {e}")));
        }

        // Measure socket readiness separately; cold backend startup can dominate creation time.
        let label = self.label;
        let waited = async {
            let deadline = tokio::time::Instant::now() + timeout;
            loop {
                if socket.exists() {
                    break;
                }
                if let Ok(Some(status)) = unready.child.try_wait() {
                    return Err(BackendError::Died(format!(
                        "{label} exited with {status} before its socket appeared; log tail:\n{}",
                        tail_log(log)
                    )));
                }
                if tokio::time::Instant::now() >= deadline {
                    return Err(BackendError::Died(format!(
                        "{label} socket did not appear within {timeout:?}; log tail:\n{}",
                        tail_log(log)
                    )));
                }
                tokio::time::sleep(POLL_INTERVAL).await;
            }
            Ok(())
        }
        .instrument(span)
        .await;
        // Kill and reap failed startups, including socket timeouts. An already
        // collected child makes cleanup a no-op.
        if let Err(e) = waited {
            self.abandon(unready.child).await;
            return Err(e);
        }

        unready.ready();
        Ok((pid, Backend { child }))
    }

    /// Kill and reap a child after failed startup. Cleanup is explicit because
    /// a synchronous destructor cannot await the child's exit.
    async fn abandon(&self, child: &mut tokio::process::Child) {
        if let Some(pid) = child.id() {
            warn!(
                pid,
                backend = self.label,
                "giving up on a spawned backend; killing it"
            );
        }
        // Kill and reap immediately: this backend never reached socket readiness.
        let _ = child.kill().await;
    }

    /// Stop an owned child with SIGTERM, then SIGKILL after grace. Detached
    /// backends receive group signals; plain children receive process signals.
    pub async fn stop(&self, mut backend: Backend) {
        if let Some(pid) = backend.child.id() {
            debug!(
                pid,
                backend = self.label,
                process_group = self.own_session,
                "sending SIGTERM to backend"
            );
            self.signal(pid, Signal::SIGTERM);
        }
        if tokio::time::timeout(TERM_GRACE, backend.child.wait())
            .await
            .is_err()
        {
            warn!(
                backend = self.label,
                "backend ignored SIGTERM, sending SIGKILL"
            );
            let _ = backend.child.kill().await; // SIGKILL + reap
        }
    }

    /// Send SIGTERM to an identity-checked backend from a previous agent.
    /// This path does not wait for exit or escalate to SIGKILL.
    pub fn stop_adopted(&self, pid: u32, socket: &Path) {
        if !self.is_ours(pid, socket) {
            return;
        }
        info!(pid, backend = self.label, socket = %socket.display(),
              "stopping adopted backend");
        self.signal(pid, Signal::SIGTERM);
    }

    /// Match the expected process name and recorded socket bytes in its command
    /// line. Both checks are needed because PIDs can be reused by another backend
    /// of the same kind. An unreadable or absent process fails the check.
    pub fn is_ours(&self, pid: u32, socket: &Path) -> bool {
        if self.comm.is_empty() {
            return false;
        }
        let comm_matches = std::fs::read_to_string(format!("/proc/{pid}/comm"))
            .map(|comm| comm.trim() == self.comm)
            .unwrap_or(false);
        if !comm_matches {
            return false;
        }
        // Match NUL-delimited arguments directly so spaces cannot merge argument boundaries.
        let Ok(cmdline) = std::fs::read(format!("/proc/{pid}/cmdline")) else {
            return false;
        };
        let needle = socket.as_os_str().as_encoded_bytes();
        !needle.is_empty() && cmdline.windows(needle.len()).any(|w| w == needle)
    }

    fn signal(&self, pid: u32, sig: Signal) {
        let pid = nix::unistd::Pid::from_raw(pid as i32);
        let _ = if self.own_session {
            // setsid(2) at spawn, so the pid is the pgid of a group that holds
            // the backend and nothing else.
            nix::sys::signal::killpg(pid, sig)
        } else {
            // No setsid(2) at spawn: this process is in the AGENT's group.
            nix::sys::signal::kill(pid, sig)
        };
    }
}

/// A spawned backend nobody has been handed yet. Dropped before [`ready`],
/// as when the future spawning it is cancelled, it kills the backend: nothing
/// else knows of it, so nothing else would ever stop it.
///
/// [`ready`]: KillUnlessReady::ready
struct KillUnlessReady<'a> {
    kind: &'a BackendKind,
    child: &'a mut tokio::process::Child,
}

impl KillUnlessReady<'_> {
    /// The backend is up and goes to the caller.
    fn ready(self) {
        std::mem::forget(self);
    }
}

impl Drop for KillUnlessReady<'_> {
    fn drop(&mut self) {
        // `None` once `abandon` or `try_wait` reaped it: then its pid may
        // belong to someone else already and is not signalled.
        if let Some(pid) = self.child.id() {
            warn!(
                pid,
                backend = self.kind.label,
                "the start of this backend was abandoned; killing it"
            );
            self.kind.signal(pid, Signal::SIGKILL);
        }
    }
}

/// Where one backend's files live and how long it gets to come up.
pub struct BackendIo<'a> {
    /// Socket path whose presence is used as the startup readiness signal.
    pub socket: &'a Path,
    pub log: &'a Path,
    pub timeout: Duration,
    /// The VM's slice, so a teardown of the VM reaps the backend with it.
    pub cgroup: Option<&'a CgroupHandle>,
    /// The `backend_spawn` span, built by the caller: the drivers name their
    /// id field differently and the field names are what the traces are read by.
    pub span: tracing::Span,
}

/// A running backend process this driver owns.
pub struct Backend {
    child: tokio::process::Child,
}

impl Backend {
    pub fn pid(&self) -> Option<u32> {
        self.child.id()
    }

    /// `try_wait` is the only liveness answer that cannot be confused by pid
    /// reuse, and it is available exactly while the backend is our own child.
    pub fn is_running(&mut self) -> bool {
        matches!(self.child.try_wait(), Ok(None))
    }

    /// Reuse only a live child whose socket still exists.
    pub fn is_reusable(&mut self, socket: &Path) -> bool {
        self.is_running() && socket.exists()
    }
}

/// Liveness of a process we may not own: `kill(pid, 0)`. It answers for an
/// adopted backend, which `try_wait` cannot.
pub fn pid_is_alive(pid: u32) -> bool {
    nix::sys::signal::kill(nix::unistd::Pid::from_raw(pid as i32), None).is_ok()
}

/// The tail of a backend's log, for the error that reports its death.
pub fn tail_log(path: &Path) -> String {
    std::fs::read_to_string(path)
        .map(|s| {
            s.chars()
                .rev()
                .take(TAIL_CHARS)
                .collect::<String>()
                .chars()
                .rev()
                .collect()
        })
        .unwrap_or_else(|_| "<no log>".into())
}

/// Teardown is idempotent: a file that is already gone is a file removed.
pub async fn remove_if_present(path: &Path) -> std::io::Result<()> {
    match tokio::fs::remove_file(path).await {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        other => other,
    }
}

fn truncate_comm(comm: &str) -> String {
    comm.chars().take(COMM_LEN).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Truncate expected comm names to the kernel limit.
    #[test]
    fn the_expected_comm_is_cut_where_the_kernel_cuts_it() {
        let long = BackendKind::child("crosvm", "an-extremely-long-binary-name");
        assert_eq!(long.comm, "an-extremely-lo");
        assert_eq!(long.comm.chars().count(), COMM_LEN);

        // The names actually in use are short enough to be unaffected, which
        // is why this stayed invisible for as long as it did.
        assert_eq!(
            BackendKind::detached("vhost-user-nvrm", "vhost-user-nvrm", 1).comm,
            "vhost-user-nvrm"
        );
        assert_eq!(
            BackendKind::detached("virtiofsd", "virtiofsd", 1).comm,
            "virtiofsd"
        );
    }

    /// Use this test binary's argv[0] as an argument known to exist in its cmdline.
    fn own_cmdline_argument() -> std::path::PathBuf {
        let raw = std::fs::read(format!("/proc/{}/cmdline", std::process::id())).expect("linux");
        let first = raw.split(|b| *b == 0).next().expect("argv[0]");
        std::path::PathBuf::from(String::from_utf8(first.to_vec()).expect("utf-8 argv[0]"))
    }

    /// A binary path that has no file name at all leaves nothing to compare
    /// against, and matching everything would be worse than matching nothing:
    /// teardown would signal a stranger's process.
    #[test]
    fn a_backend_with_no_expected_name_owns_nothing() {
        let anonymous = BackendKind::child("crosvm", "");
        let arg = own_cmdline_argument();
        assert!(!anonymous.is_ours(std::process::id(), &arg));
        assert!(!anonymous.is_ours(1, &arg));
    }

    /// The adoption check against a live process: this test binary is one.
    #[test]
    fn a_running_process_is_recognised_by_its_comm() {
        let me =
            std::fs::read_to_string(format!("/proc/{}/comm", std::process::id())).expect("linux");
        let kind = BackendKind::child("test", me.trim());
        let arg = own_cmdline_argument();
        assert!(kind.is_ours(std::process::id(), &arg));
        assert!(!BackendKind::child("test", "definitely-not-me").is_ours(std::process::id(), &arg));
    }

    /// Distinguish sibling backends by socket argument as well as process name.
    #[test]
    fn a_sibling_backend_of_the_same_kind_is_not_this_one() {
        let me =
            std::fs::read_to_string(format!("/proc/{}/comm", std::process::id())).expect("linux");
        let kind = BackendKind::detached("virtiofsd", me.trim(), 1);
        let pid = std::process::id();

        // Same kind, same pid, right socket: ours.
        assert!(kind.is_ours(pid, &own_cmdline_argument()));

        // The same process with another consumer's socket must not match.
        let sibling =
            std::path::Path::new("/run/meisterstack/nfs/2f3a4b5c-0000-0000-0000-000000000000.sock");
        assert!(!kind.is_ours(pid, sibling));

        // An empty marker matches everywhere in a byte search, so it is
        // refused outright rather than allowed to mean "any".
        assert!(!kind.is_ours(pid, std::path::Path::new("")));
    }

    #[test]
    fn liveness_of_a_pid_that_cannot_exist() {
        assert!(pid_is_alive(std::process::id()));
        // Use an impossible positive PID. u32::MAX becomes -1 for kill(2),
        // which addresses every permitted process instead of an absent one.
        assert!(!pid_is_alive(i32::MAX as u32));
    }

    #[test]
    fn a_missing_log_reads_as_no_log_rather_than_an_empty_tail() {
        assert_eq!(tail_log(Path::new("/nonexistent/backend.log")), "<no log>");
    }

    /// A failed cgroup attachment must kill and reap the spawned process.
    /// A sleeping child exercises process cleanup without requiring a backend.
    #[tokio::test]
    async fn a_backend_whose_slice_cannot_be_written_is_killed_and_reaped() {
        let temp = tempfile::tempdir().expect("a temp dir");
        let log = temp.path().join("backend.log");
        let socket = temp.path().join("backend.sock");

        let mut cmd = tokio::process::Command::new("sleep");
        cmd.arg("600");

        // A missing slice causes cgroup.procs writes to fail with ENOENT.
        let cgroup = CgroupHandle {
            path: temp.path().join("no-such-slice"),
        };

        let kind = BackendKind::child("sleep", "sleep");
        let err = kind
            .spawn(
                cmd,
                BackendIo {
                    socket: &socket,
                    log: &log,
                    timeout: Duration::from_secs(30),
                    cgroup: Some(&cgroup),
                    span: tracing::Span::none(),
                },
            )
            .await
            .map(|(pid, _)| pid)
            .expect_err("a backend that cannot enter its slice is not a backend");
        assert!(
            format!("{err}").contains("cgroup attach"),
            "the error names what failed: {err}"
        );

        // Verify failed startups are killed and reaped, leaving no zombie in `/proc`.
        let mut left = Vec::new();
        for line in std::fs::read_dir("/proc").expect("linux") {
            let Ok(entry) = line else { continue };
            let name = entry.file_name();
            let Some(pid) = name.to_str().and_then(|s| s.parse::<u32>().ok()) else {
                continue;
            };
            let Ok(cmdline) = std::fs::read(format!("/proc/{pid}/cmdline")) else {
                continue;
            };
            // Match the exact NUL-delimited fixture argument to exclude unrelated sleep processes.
            if cmdline
                .split(|b| *b == 0)
                .eq([&b"sleep"[..], &b"600"[..], &b""[..]])
            {
                left.push(pid);
            }
        }
        assert!(
            left.is_empty(),
            "the spawned backend is still around: {left:?}"
        );
    }

    /// Only the tail is quoted: a backend that logged a megabyte before dying
    /// must not put a megabyte into an API error.
    #[test]
    fn the_log_tail_is_the_last_of_it() {
        let temp = tempfile::tempdir().expect("a temp dir");
        let path = temp.path().join("backend.log");
        let body: String = std::iter::repeat_n('x', TAIL_CHARS)
            .chain("THE END".chars())
            .collect();
        std::fs::write(&path, format!("THE BEGINNING{body}")).unwrap();

        let tail = tail_log(&path);
        assert_eq!(tail.chars().count(), TAIL_CHARS);
        assert!(tail.ends_with("THE END"), "{tail}");
        assert!(!tail.contains("THE BEGINNING"));
    }
}
