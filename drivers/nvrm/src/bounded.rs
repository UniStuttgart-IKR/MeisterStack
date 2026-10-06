// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! A helper process run to completion within a deadline, one at a time.
//!
//! `vgpuprofile` talks to the GPU driver, and a wedged driver leaves it in an
//! ioctl that does not return. Run unbounded, it hangs the agent's start or
//! an admission with it. Here the helper gets a deadline, is killed when it
//! passes, and is waited for only a little longer: a process stuck in the
//! kernel does not die of SIGKILL until the call returns, and the agent does
//! not wait for that.
//!
//! Such a helper is kept rather than dropped: its process unreaped, and the
//! two threads draining its pipes blocked for as long as it holds them. While
//! it lives no other helper is started, nor for a backoff after any kill. A
//! tenant chooses the type an admission resolves, and every request naming a
//! new one would otherwise leave one more stuck process and two more threads
//! behind, and wait out a whole deadline under the agent's operations lock
//! first. So at most one such process and two such threads are left over,
//! and an admission during the backoff fails at once.

use std::io::Read;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::{Mutex, PoisonError, mpsc};
use std::time::{Duration, Instant};

use tracing::warn;

/// How often the helper is asked whether it has exited.
const POLL: Duration = Duration::from_millis(10);

/// How long a killed helper gets to be reaped, and a finished one's pipes to
/// be read to the end, before the agent goes on without it.
const GRACE: Duration = Duration::from_secs(1);

/// What is kept of each output stream; the rest is read and dropped, so a
/// chatty helper never blocks on a full pipe.
const OUTPUT_LIMIT: u64 = 64 * 1024;

/// A helper that ran to its end.
#[derive(Debug)]
pub(crate) struct Finished {
    pub(crate) status: ExitStatus,
    pub(crate) stdout: Vec<u8>,
    pub(crate) stderr: Vec<u8>,
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum RunError {
    #[error("could not start it: {0}")]
    Spawn(std::io::Error),
    #[error("could not wait for it: {0}")]
    Wait(std::io::Error),
    #[error("it did not finish within {deadline:?} and was killed (pid {pid})")]
    TimedOut { deadline: Duration, pid: u32 },
    #[error(
        "an earlier run (pid {pid}) was killed at its deadline and has not exited; no other is \
         started beside it"
    )]
    StillRunning { pid: u32 },
    #[error("an earlier run was killed at its deadline; no other is started for another {left:?}")]
    BackingOff { left: Duration },
}

/// Runs one helper at a time, and none while one it killed still lives or
/// was killed less than its backoff ago.
pub(crate) struct Runner {
    backoff: Duration,
    /// Held for the whole of each run. Holds the last kill for as long as it
    /// bars the next run.
    killed: Mutex<Option<Killed>>,
}

/// A helper killed at its deadline, or after its wait failed.
struct Killed {
    /// Kept while it has not exited; `None` once it has been reaped.
    child: Option<Child>,
    at: Instant,
}

impl Runner {
    pub(crate) fn new(backoff: Duration) -> Self {
        Self {
            backoff,
            killed: Mutex::new(None),
        }
    }

    /// Run `cmd` with no stdin and its output captured, and wait at most
    /// `deadline` for it to finish. Refused at once, without starting
    /// anything, while a helper killed earlier has not exited or was killed
    /// less than the backoff ago.
    pub(crate) fn output_within(
        &self,
        cmd: Command,
        deadline: Duration,
    ) -> Result<Finished, RunError> {
        let mut killed = self.killed.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(earlier) = killed.as_mut() {
            earlier.bars(self.backoff)?;
        }
        *killed = None;
        run(cmd, deadline, &mut killed)
    }
}

impl Killed {
    /// Kill `child` and reap it within [`GRACE`]; it is kept if it did not
    /// exit by then.
    fn kill(mut child: Child) -> Self {
        let _ = child.kill();
        let exited = matches!(wait_until(&mut child, Instant::now() + GRACE), Ok(Some(_)));
        if !exited {
            // Stuck in the kernel. Better one kept process than an agent that
            // waits for a driver that never answers.
            warn!(
                pid = child.id(),
                "a killed helper did not exit; no other is started until it does"
            );
        }
        Self {
            child: (!exited).then_some(child),
            at: Instant::now(),
        }
    }

    /// Refuse while the killed helper lives (forgetting it once it has
    /// exited), and then until `backoff` has passed since the kill.
    fn bars(&mut self, backoff: Duration) -> Result<(), RunError> {
        if let Some(child) = &mut self.child {
            // An error says there is no such child left to wait for.
            if matches!(child.try_wait(), Ok(None)) {
                let pid = child.id();
                warn!(
                    pid,
                    "a helper killed at its deadline still runs; refusing to start another"
                );
                return Err(RunError::StillRunning { pid });
            }
            self.child = None;
        }
        let since = self.at.elapsed();
        if since < backoff {
            return Err(RunError::BackingOff {
                left: backoff - since,
            });
        }
        Ok(())
    }
}

fn run(
    mut cmd: Command,
    deadline: Duration,
    killed: &mut Option<Killed>,
) -> Result<Finished, RunError> {
    let mut child = cmd
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(RunError::Spawn)?;
    let stdout = drain(child.stdout.take());
    let stderr = drain(child.stderr.take());
    match wait_until(&mut child, Instant::now() + deadline) {
        Ok(Some(status)) => Ok(Finished {
            status,
            stdout: collected(stdout),
            stderr: collected(stderr),
        }),
        Ok(None) => {
            let pid = child.id();
            *killed = Some(Killed::kill(child));
            Err(RunError::TimedOut { deadline, pid })
        }
        Err(e) => {
            *killed = Some(Killed::kill(child));
            Err(RunError::Wait(e))
        }
    }
}

/// The exit status, or `None` once `end` has passed without one.
fn wait_until(child: &mut Child, end: Instant) -> std::io::Result<Option<ExitStatus>> {
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(Some(status));
        }
        if Instant::now() >= end {
            return Ok(None);
        }
        std::thread::sleep(POLL);
    }
}

/// Read a stream to its end on a thread of its own, keeping the first
/// [`OUTPUT_LIMIT`] bytes.
fn drain(stream: Option<impl Read + Send + 'static>) -> mpsc::Receiver<Vec<u8>> {
    let (tx, rx) = mpsc::channel();
    if let Some(mut stream) = stream {
        std::thread::spawn(move || {
            let mut kept = Vec::new();
            let _ = (&mut stream).take(OUTPUT_LIMIT).read_to_end(&mut kept);
            let _ = std::io::copy(&mut stream, &mut std::io::sink());
            let _ = tx.send(kept);
        });
    }
    rx
}

/// What a drained stream held. A pipe a grandchild still holds open is not
/// waited for past [`GRACE`].
fn collected(stream: mpsc::Receiver<Vec<u8>>) -> Vec<u8> {
    stream.recv_timeout(GRACE).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sh(script: &str) -> Command {
        let mut cmd = Command::new("/bin/sh");
        cmd.args(["-c", script]);
        cmd
    }

    /// A runner that bars nothing after a kill but the killed helper itself.
    fn without_backoff() -> Runner {
        Runner::new(Duration::ZERO)
    }

    /// A kill as the runner records it, made just now.
    fn killed(child: Option<Child>) -> Option<Killed> {
        Some(Killed {
            child,
            at: Instant::now(),
        })
    }

    /// A helper that finishes in time hands over its status and both streams.
    #[test]
    fn a_helper_that_finishes_is_heard_out() {
        let done = without_backoff()
            .output_within(
                sh("echo said; echo why >&2; exit 3"),
                Duration::from_secs(10),
            )
            .expect("finished");
        assert_eq!(done.status.code(), Some(3));
        assert_eq!(done.stdout, b"said\n");
        assert_eq!(done.stderr, b"why\n");
    }

    /// R2-10: a helper that does not finish is killed at its deadline and
    /// reaped before the caller is told, so nothing of it is left running.
    #[test]
    fn a_helper_that_hangs_is_killed_and_reaped_at_its_deadline() {
        let failed = without_backoff()
            .output_within(sh("exec sleep 600"), Duration::from_millis(200))
            .map(|_| ())
            .expect_err("it hangs");
        let said = failed.to_string();
        let RunError::TimedOut { pid, .. } = failed else {
            panic!("not a timeout: {said}")
        };
        let left = std::path::Path::new(&format!("/proc/{pid}")).exists();
        if left {
            // The failure is reported, and the sleep does not outlive it.
            let _ = nix::sys::signal::kill(
                nix::unistd::Pid::from_raw(pid as i32),
                nix::sys::signal::Signal::SIGKILL,
            );
        }
        assert!(said.contains("did not finish within"), "{said}");
        assert!(!left, "the helper, pid {pid}, is still there");
    }

    /// A helper still alive after its kill, as one stuck in the kernel is
    /// until its call returns, bars every later run, which starts nothing.
    /// An unkilled child stands in for it: SIGKILL ends any process a test
    /// can make.
    #[test]
    fn a_killed_helper_that_still_runs_bars_the_next() {
        let runner = without_backoff();
        let stuck = sh("exec sleep 600").spawn().expect("running");
        let pid = stuck.id();
        *runner.killed.lock().expect("unpoisoned") = killed(Some(stuck));
        let dir = tempfile::tempdir().expect("a temp dir");
        let marker = dir.path().join("ran");

        let ran = runner.output_within(
            sh(&format!(": > '{}'", marker.display())),
            Duration::from_secs(10),
        );
        let mut stuck = runner
            .killed
            .lock()
            .expect("unpoisoned")
            .take()
            .and_then(|k| k.child)
            .expect("still kept");
        stuck.kill().expect("killed");
        stuck.wait().expect("reaped");
        let said = ran.map(|_| ()).expect_err("barred");
        assert!(
            matches!(said, RunError::StillRunning { pid: p } if p == pid),
            "{said}"
        );
        assert!(!marker.exists(), "nothing was started");
    }

    /// Once the kept helper has exited and the backoff has passed, it is
    /// reaped and forgotten, and the next run goes ahead.
    #[test]
    fn a_kept_helper_that_has_exited_bars_nothing_after_the_backoff() {
        let runner = without_backoff();
        let mut gone = sh("exit 0").spawn().expect("running");
        let _ = gone.wait();
        *runner.killed.lock().expect("unpoisoned") = killed(Some(gone));
        runner
            .output_within(sh("exit 0"), Duration::from_secs(10))
            .expect("ran");
        assert!(runner.killed.lock().expect("unpoisoned").is_none());
    }

    /// N6: after a helper was killed, none starts until the backoff has
    /// passed, even once the killed one is gone: an admission naming a type
    /// not resolved yet fails at once instead of waiting out another deadline.
    #[test]
    fn after_a_kill_no_helper_starts_until_the_backoff_has_passed() {
        let runner = Runner::new(Duration::from_secs(3600));
        runner
            .output_within(sh("exec sleep 600"), Duration::from_millis(200))
            .map(|_| ())
            .expect_err("it hangs");
        let dir = tempfile::tempdir().expect("a temp dir");
        let marker = dir.path().join("ran");

        let said = runner
            .output_within(
                sh(&format!(": > '{}'", marker.display())),
                Duration::from_secs(10),
            )
            .map(|_| ())
            .expect_err("backing off");
        assert!(matches!(said, RunError::BackingOff { .. }), "{said}");
        assert!(!marker.exists(), "nothing was started");
    }
}
