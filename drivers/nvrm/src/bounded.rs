// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! A helper process run to completion within a deadline.
//!
//! `vgpuprofile` talks to the GPU driver, and a wedged driver leaves it in an
//! ioctl that does not return. Run unbounded, it hangs the agent's start or
//! an admission with it. Here the helper gets a deadline, is killed when it
//! passes, and is waited for only a little longer: a process stuck in the
//! kernel does not die of SIGKILL until the call returns, and the agent does
//! not wait for that.

use std::io::Read;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::mpsc;
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
    #[error("it did not finish within {deadline:?} and was killed")]
    TimedOut { deadline: Duration },
}

/// Run `cmd` with no stdin and its output captured, and wait at most
/// `deadline` for it to finish.
pub(crate) fn output_within(mut cmd: Command, deadline: Duration) -> Result<Finished, RunError> {
    let mut child = cmd
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(RunError::Spawn)?;
    let stdout = drain(child.stdout.take());
    let stderr = drain(child.stderr.take());
    let status = match wait_until(&mut child, Instant::now() + deadline) {
        Ok(Some(status)) => status,
        Ok(None) => {
            kill_and_reap(&mut child);
            return Err(RunError::TimedOut { deadline });
        }
        Err(e) => {
            kill_and_reap(&mut child);
            return Err(RunError::Wait(e));
        }
    };
    Ok(Finished {
        status,
        stdout: collected(stdout),
        stderr: collected(stderr),
    })
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

fn kill_and_reap(child: &mut Child) {
    let _ = child.kill();
    if !matches!(wait_until(child, Instant::now() + GRACE), Ok(Some(_))) {
        // Stuck in the kernel; it is reaped when the agent exits. Better a
        // zombie than an agent that waits for a driver that never answers.
        warn!(
            pid = child.id(),
            "a killed helper did not exit; leaving it behind"
        );
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

    /// A helper that finishes in time hands over its status and both streams.
    #[test]
    fn a_helper_that_finishes_is_heard_out() {
        let done = output_within(
            sh("echo said; echo why >&2; exit 3"),
            Duration::from_secs(10),
        )
        .expect("finished");
        assert_eq!(done.status.code(), Some(3));
        assert_eq!(done.stdout, b"said\n");
        assert_eq!(done.stderr, b"why\n");
    }

    /// R2-10: a helper that does not finish is killed at its deadline, and
    /// the caller is told so instead of waiting for it.
    #[test]
    fn a_helper_that_hangs_is_killed_at_its_deadline() {
        let started = Instant::now();
        let said = output_within(sh("exec sleep 600"), Duration::from_millis(200))
            .expect_err("it hangs")
            .to_string();
        assert!(said.contains("did not finish within"), "{said}");
        assert!(
            started.elapsed() < Duration::from_secs(60),
            "the caller went on: {:?}",
            started.elapsed()
        );
    }
}
