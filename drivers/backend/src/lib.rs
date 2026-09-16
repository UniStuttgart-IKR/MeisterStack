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
//! previous agent by its `comm` and by the socket on its command line. That is
//! what lives here.
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

/// What kind of process one driver's backend is: how it is spawned, how it is
/// signalled, and how it is recognised once it is no longer our child.
///
/// A driver builds one of these at construction time and keeps it; it is the
/// only place the three drivers' deliberate differences are written down.
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
    /// Who this backend runs as, when that is not the agent.
    ///
    /// Beside the VMM and not behind it, because vhost-user is not a
    /// boundary: the backend maps the guest's memory and CH says so
    /// ("Cloud Hypervisor gives vhost-user devices complete control over the
    /// guest"). A root backend beside an unprivileged VMM leaves the guest
    /// exactly one process away from root, which is what Stufe 3 is for.
    /// `None` is every node that has ever run this.
    vmm_user: Option<agent_api::VmmUser>,
}

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
            vmm_user: None,
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
            vmm_user: None,
        }
    }

    /// Run this backend as somebody else.
    ///
    /// One builder for all four backends, which is the whole reason this
    /// crate exists: `nvrm`, `input`, `crosvm-gpu` and `virtiofsd` had four
    /// copies of the same spawn and now have one, so "the backends run as the
    /// VMM user" is a single seam rather than four.
    ///
    /// Which of them actually gets one is the driver's decision and not this
    /// crate's. `virtiofsd` is the exception in the tree today: it changes
    /// file ownership inside the share on the guest's behalf, so it stays the
    /// agent and is sandboxed differently (`--sandbox=namespace`).
    pub fn as_user(mut self, user: Option<agent_api::VmmUser>) -> Self {
        self.vmm_user = user;
        self
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
        // The directory the backend will bind its socket in, and its own log,
        // change hands while the agent still can give them away. The log is
        // handed over as well as passed as a descriptor, because a driver
        // that quotes the tail of a dead backend's log comes back to the
        // PATH — see `tail_log`.
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

        // The backend's socket is what the VMM connects to, so it has to be
        // openable by the VMM — which is the same user, so the backend's own
        // group is exactly right and world-reachable is not. The socket is
        // made by the BACKEND, so a umask is the only way to say that from
        // here; it comes out `0770`, because a socket's base mode is `0777`
        // and not a file's `0666`.
        let (own_session, nofile_limit) = (self.own_session, self.nofile_limit);
        // Cloned into the closure: `pre_exec` outlives this call.
        let user = self.vmm_user.clone();
        if own_session || nofile_limit.is_some() || user.is_some() {
            // SAFETY: setsid, setrlimit, umask and `switch_to` are syscalls
            // on values the closure owns — nothing here allocates, opens a
            // file or takes a lock, which is what a forked child may not do.
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
    ///
    /// `socket` is the unix socket THIS consumer's backend was spawned with,
    /// off the attachment the record holds, and it is what makes the signal
    /// safe: see `is_ours`.
    pub fn stop_adopted(&self, pid: u32, socket: &Path) {
        if !self.is_ours(pid, socket) {
            return;
        }
        info!(pid, backend = self.label, socket = %socket.display(),
              "stopping adopted backend");
        self.signal(pid, Signal::SIGTERM);
    }

    /// Is `pid` still the backend we wrote down — this one, and not another
    /// of the same kind?
    ///
    /// The question comes up after an agent restart, when the backend is no
    /// longer our child and the recorded pid is all we have. Two checks,
    /// because one is not enough:
    ///
    /// - `comm` says the process is a backend of this kind. That much was
    ///   here before, and on its own it is exactly the wrong amount of
    ///   certainty: a node runs one `virtiofsd` per share and one
    ///   `vhost-user-nvrm` per GPU, so `comm` matching means "some backend of
    ///   this kind", and a recycled pid on a busy node is most likely to be
    ///   recycled by the same busy thing. A teardown that trusted `comm`
    ///   alone would eventually `killpg` a LIVE VM's backend — and killpg,
    ///   because these get a session of their own, takes the whole group.
    /// - `/proc/<pid>/cmdline` contains the socket this consumer's backend
    ///   was spawned with. Every backend here is spawned with its socket path
    ///   on the command line, the path carries the consumer's uuid, and no
    ///   two consumers share one. That is identity and not a family
    ///   resemblance.
    ///
    /// A dead pid has no `comm` and no `cmdline` to read, so this subsumes
    /// liveness, which is what the two `get`/`stat` callers rely on.
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
        // NUL-separated, so the needle is looked for in the raw bytes rather
        // than in a rendered string: an argument boundary is a NUL and never
        // a space, and joining with spaces first would let a path with a
        // space in it match across two arguments.
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

/// Where one backend's files live and how long it gets to come up.
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

    /// The first argument of this test binary, which is its own path, and
    /// therefore a string `/proc/self/cmdline` is guaranteed to contain.
    /// Stands in for a backend's socket path, which is what the real callers
    /// pass.
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

    /// The half `comm` alone could never see, and the reason this position
    /// exists: a node runs one `virtiofsd` per share and one crosvm per GPU,
    /// so "the process at this pid is a backend of this kind" is true of
    /// every OTHER consumer's backend too. The socket on the command line is
    /// what tells this one from its siblings — and killpg on a sibling would
    /// take a live VM's whole backend group down.
    #[test]
    fn a_sibling_backend_of_the_same_kind_is_not_this_one() {
        let me =
            std::fs::read_to_string(format!("/proc/{}/comm", std::process::id())).expect("linux");
        let kind = BackendKind::detached("virtiofsd", me.trim(), 1);
        let pid = std::process::id();

        // Same kind, same pid, right socket: ours.
        assert!(kind.is_ours(pid, &own_cmdline_argument()));

        // Same kind, same pid, ANOTHER consumer's socket: not ours, and this
        // is the case that used to come back true.
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
