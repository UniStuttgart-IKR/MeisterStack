// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! The helper process the vhost-user drivers all run, in one place.
//!
//! `nvrm`, `crosvm-gpu` and `nfs` each start a process that serves exactly one
//! VM over a unix socket, and each of them carried its own copy of the same
//! mechanics: spawn it with the right process hygiene, do not come back until
//! it is listening, keep a log and quote its tail when the thing dies, tear it
//! down with SIGTERM-then-SIGKILL, and recognise a backend adopted from a
//! previous agent by its `comm`. That is what lives here.
//!
//! What a backend IS stays with the driver: which binary, which arguments,
//! which environment, what it hands back as an attachment, what it admits.
//! Those are the parts the three drivers genuinely disagree about, and
//! flattening them would be the wrong kind of sharing.
//!
//! A backend is never reused across a death. They exit when their VMM hangs
//! up, by design, and handing that corpse to the next boot would produce a VM
//! whose device is a socket nobody is listening on: a dead backend is replaced
//! by Teardown then Provision.

use std::path::Path;
use std::time::Duration;

use agent_api::CgroupHandle;
use agent_api::device::DeviceError;
use agent_api::storage::StorageError;
use macros::generated;
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

/// What went wrong with a backend process, in the two shapes every driver
/// needs: the process is gone, or the machinery around it failed.
#[generated(model = ClaudeOpus, version = "5")]
#[derive(Debug, thiserror::Error)]
pub enum BackendError {
    /// The backend exited, or never came up. Carries the log tail, because
    /// the message is the only thing between an operator and a file whose
    /// name they do not know.
    #[error("{0}")]
    Died(String),
    #[error(transparent)]
    Failed(#[from] anyhow::Error),
}

pub type Result<T> = std::result::Result<T, BackendError>;

/// The device and storage halves of the agent API keep their own error enums,
/// and both have exactly these two variants for a backend. Converting here
/// rather than at every call site is what lets a driver write `?`.
#[generated(model = ClaudeOpus, version = "5")]
impl From<BackendError> for DeviceError {
    fn from(e: BackendError) -> Self {
        match e {
            BackendError::Died(m) => DeviceError::BackendDied(m),
            BackendError::Failed(e) => DeviceError::Backend(e),
        }
    }
}

#[generated(model = ClaudeOpus, version = "5")]
impl From<BackendError> for StorageError {
    fn from(e: BackendError) -> Self {
        match e {
            BackendError::Died(m) => StorageError::BackendDied(m),
            BackendError::Failed(e) => StorageError::Backend(e),
        }
    }
}

/// What kind of process one driver's backend is: how it is spawned, how it is
/// signalled, and how it is recognised once it is no longer our child.
///
/// A driver builds one of these at construction time and keeps it; it is the
/// only place the three drivers' deliberate differences are written down.
#[generated(model = ClaudeOpus, version = "5")]
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
}

#[generated(model = ClaudeOpus, version = "5")]
impl BackendKind {
    /// A backend that gets a session of its own.
    ///
    /// setsid(2) buys three things at once: it never dies with the shell that
    /// happened to start the agent, it becomes its own process group leader so
    /// teardown can signal the GROUP and not orphan anything it forked, and
    /// its pid is also its pgid, which is what makes signalling an adopted
    /// backend by its recorded pid correct. It also gets `nofile_limit`
    /// descriptors, because one desktop guest can hold hundreds of files open
    /// at once and the backend needs one host descriptor for each.
    pub fn detached(label: &'static str, comm: &str, nofile_limit: u64) -> Self {
        Self {
            label,
            comm: truncate_comm(comm),
            own_session: true,
            nofile_limit: Some(nofile_limit),
            stdin_null: true,
        }
    }

    /// A backend that stays a plain child in the agent's own session, and is
    /// therefore signalled as a single PROCESS.
    ///
    /// The asymmetry with `detached` is deliberate and load-bearing: killpg(2)
    /// on a process that never called setsid(2) addresses the group it
    /// inherited, which is the agent's own — teardown would take the agent
    /// down with the backend.
    pub fn child(label: &'static str, comm: &str) -> Self {
        Self {
            label,
            comm: truncate_comm(comm),
            own_session: false,
            nofile_limit: None,
            stdin_null: false,
        }
    }

    /// Start `cmd` and do not come back until the backend is listening.
    ///
    /// The caller owns the command line — binary, arguments, environment —
    /// and this owns everything downstream of it. Waiting for the socket is
    /// not optional: the VMM connects to it during `vm.create`, and a socket
    /// that is not there yet is a failed VM.
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

        // A socket left behind by a previous backend would make the wait below
        // succeed instantly, on a socket nobody is listening on.
        let _ = tokio::fs::remove_file(socket).await;

        let log_file = std::fs::File::create(log).map_err(|e| BackendError::Failed(e.into()))?;
        let log_dup = log_file
            .try_clone()
            .map_err(|e| BackendError::Failed(e.into()))?;
        cmd.stdout(log_file).stderr(log_dup);
        if self.stdin_null {
            cmd.stdin(std::process::Stdio::null());
        }

        let (own_session, nofile_limit) = (self.own_session, self.nofile_limit);
        if own_session || nofile_limit.is_some() {
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
                    Ok(())
                });
            }
        }

        let mut child = cmd.spawn().map_err(|e| BackendError::Failed(e.into()))?;
        let pid = child.id().ok_or_else(|| {
            BackendError::Died(format!("{} exited before pid could be read", self.label))
        })?;
        debug!(
            pid,
            backend = self.label,
            "backend spawned, waiting for socket"
        );

        if let Some(cg) = cgroup {
            cg.attach_pid(pid)
                .map_err(|e| BackendError::Failed(anyhow::anyhow!("cgroup attach: {e}")))?;
        }

        // Waiting for the socket is where a backend spawn actually spends its
        // time — seconds, on a cold GPU — so it gets a span of its own rather
        // than disappearing into the create it is 90% of. The span comes from
        // the caller because only the driver knows what its id is called.
        let label = self.label;
        async {
            let deadline = tokio::time::Instant::now() + timeout;
            loop {
                if socket.exists() {
                    break;
                }
                if let Ok(Some(status)) = child.try_wait() {
                    return Err(BackendError::Died(format!(
                        "{label} exited with {status} before its socket appeared; log tail:\n{}",
                        tail_log(log)
                    )));
                }
                if tokio::time::Instant::now() >= deadline {
                    // A backend that missed its deadline must not be left
                    // running: nothing would ever collect it again.
                    let _ = child.start_kill();
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
        .await?;

        Ok((pid, Backend { child }))
    }

    /// Stop a backend that is still our child: SIGTERM, then SIGKILL if it is
    /// ignored. Whether the signal goes to the process or to its group is the
    /// difference `detached` and `child` exist to record.
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

    /// Stop a backend adopted from a previous agent.
    ///
    /// It is no longer our child, so the pid on the record is the only handle
    /// on it. Ignoring it would leave a backend running for a VM that is gone
    /// — the driver silently failing exactly the promise a teardown makes.
    /// A pid is reusable, so it is signalled only when `comm` still says the
    /// process is this backend.
    pub fn stop_adopted(&self, pid: u32) {
        if !self.is_ours(pid) {
            return;
        }
        info!(pid, backend = self.label, "stopping adopted backend");
        self.signal(pid, Signal::SIGTERM);
    }

    /// Is `pid` still this backend?
    ///
    /// The question only comes up after an agent restart, when the backend is
    /// no longer our child and the recorded pid is all we have. A pid is
    /// reusable, so acting on the record alone would eventually reach somebody
    /// else's process; `comm` is the cheap check that it is still the process
    /// we wrote down.
    pub fn is_ours(&self, pid: u32) -> bool {
        if self.comm.is_empty() {
            return false;
        }
        std::fs::read_to_string(format!("/proc/{pid}/comm"))
            .map(|comm| comm.trim() == self.comm)
            .unwrap_or(false)
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

/// Where one backend's files live and how long it gets to come up.
#[generated(model = ClaudeOpus, version = "5")]
pub struct BackendIo<'a> {
    /// The socket the backend is expected to listen on. Also the readiness
    /// signal: the backend creates it when, and only when, it is serving.
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
#[generated(model = ClaudeOpus, version = "5")]
pub struct Backend {
    child: tokio::process::Child,
}

#[generated(model = ClaudeOpus, version = "5")]
impl Backend {
    pub fn pid(&self) -> Option<u32> {
        self.child.id()
    }

    /// `try_wait` is the only liveness answer that cannot be confused by pid
    /// reuse, and it is available exactly while the backend is our own child.
    pub fn is_running(&mut self) -> bool {
        matches!(self.child.try_wait(), Ok(None))
    }

    /// May this backend be handed to another create for the same device?
    ///
    /// Only when it is verifiably alive AND its socket is still there. A dead
    /// one has to be respawned, never handed back as an attachment carrying a
    /// stale pid.
    pub fn is_reusable(&mut self, socket: &Path) -> bool {
        self.is_running() && socket.exists()
    }
}

/// Liveness of a process we may not own: `kill(pid, 0)`. It answers for an
/// adopted backend, which `try_wait` cannot.
#[generated(model = ClaudeOpus, version = "5")]
pub fn pid_is_alive(pid: u32) -> bool {
    nix::sys::signal::kill(nix::unistd::Pid::from_raw(pid as i32), None).is_ok()
}

/// The tail of a backend's log, for the error that reports its death.
#[generated(model = ClaudeOpus, version = "5")]
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
#[generated(model = ClaudeOpus, version = "5")]
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
#[generated(model = ClaudeOpus, version = "5")]
mod tests {
    use super::*;

    /// A binary whose name is longer than the kernel's `comm` field would
    /// never match its own process, so the expectation is cut to the same
    /// length the kernel cuts the real thing to.
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

    /// A binary path that has no file name at all leaves nothing to compare
    /// against, and matching everything would be worse than matching nothing:
    /// teardown would signal a stranger's process.
    #[test]
    fn a_backend_with_no_expected_name_owns_nothing() {
        let anonymous = BackendKind::child("crosvm", "");
        assert!(!anonymous.is_ours(std::process::id()));
        assert!(!anonymous.is_ours(1));
    }

    /// The adoption check against a live process: this test binary is one.
    #[test]
    fn a_running_process_is_recognised_by_its_comm() {
        let me =
            std::fs::read_to_string(format!("/proc/{}/comm", std::process::id())).expect("linux");
        let kind = BackendKind::child("test", me.trim());
        assert!(kind.is_ours(std::process::id()));
        assert!(!BackendKind::child("test", "definitely-not-me").is_ours(std::process::id()));
    }

    #[test]
    fn liveness_of_a_pid_that_cannot_exist() {
        assert!(pid_is_alive(std::process::id()));
        // Above any `pid_max` Linux will hand out, so there is nothing there
        // to answer. Not `u32::MAX`: that is -1 to kill(2), which means
        // "every process I may signal" and always succeeds.
        assert!(!pid_is_alive(i32::MAX as u32));
    }

    #[test]
    fn a_missing_log_reads_as_no_log_rather_than_an_empty_tail() {
        assert_eq!(tail_log(Path::new("/nonexistent/backend.log")), "<no log>");
    }

    /// Only the tail is quoted: a backend that logged a megabyte before dying
    /// must not put a megabyte into an API error.
    #[test]
    fn the_log_tail_is_the_last_of_it() {
        let path = std::env::temp_dir().join(format!("meister-tail-{}.log", std::process::id()));
        let body: String = std::iter::repeat_n('x', TAIL_CHARS)
            .chain("THE END".chars())
            .collect();
        std::fs::write(&path, format!("THE BEGINNING{body}")).unwrap();

        let tail = tail_log(&path);
        assert_eq!(tail.chars().count(), TAIL_CHARS);
        assert!(tail.ends_with("THE END"), "{tail}");
        assert!(!tail.contains("THE BEGINNING"));

        std::fs::remove_file(&path).unwrap();
    }
}
