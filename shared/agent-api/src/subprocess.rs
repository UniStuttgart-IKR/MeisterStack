// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Child processes with a deadline: a wedged `ip`, `nft`, `arping` or `curl` must not stall the
//! agent's command pump or a lock held around it (R2-5, R3-F08).
//!
//! Here because both the agent and the network driver depend on this crate and neither may
//! depend on the other; the driver is to leave the tree as a project of its own.
//!
//! A child past its deadline is killed and reaped within [`REAP_BOUND`]. One still not reaped
//! then (uninterruptible sleep on a dead mount) is not waited for: a background task keeps
//! waiting for it, so no caller is held longer than its deadline plus the bound.
//!
//! Memory is bounded the same way: a child that writes more than [`OUTPUT_CAP`] to stdout or
//! stderr is killed and reaped as well (N5).

use std::future::Future;
use std::io;
use std::process::{ExitStatus, Output, Stdio};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::process::{Child, Command};
use tracing::{debug, warn};

/// How long a killed child may take to be reaped before it is left to the background.
pub const REAP_BOUND: Duration = Duration::from_secs(5);

/// How many bytes of each of stdout and stderr a run keeps. The largest answer expected here is
/// `nft -j` listing every tap's chain, a few KiB per guest, so the cap leaves room for thousands
/// of guests. More is a broken or hostile child, and the agent's memory is not its to fill.
pub const OUTPUT_CAP: usize = 16 << 20;

/// Why a bounded run produced no exit status.
#[derive(Debug, thiserror::Error)]
pub enum RunError {
    #[error("{what} could not be started: {source}")]
    Spawn {
        what: String,
        #[source]
        source: io::Error,
    },
    #[error("talking to {what} failed: {source}")]
    Io {
        what: String,
        #[source]
        source: io::Error,
    },
    #[error("{what} did not answer within {}s and was stopped", .deadline.as_secs())]
    TimedOut { what: String, deadline: Duration },
    #[error("{what} wrote more than {cap} bytes to {stream} and was stopped")]
    OutputTooLarge {
        what: String,
        stream: &'static str,
        cap: usize,
    },
}

/// Run `command` to its exit within `deadline`: `input` on stdin (none means `/dev/null`),
/// stdout and stderr drained together up to [`OUTPUT_CAP`] each, the exit waited for. Past the
/// deadline or the cap, or on a failed pipe, the child is killed and reaped, bounded, and the
/// run is an error naming `what`.
pub async fn output_within(
    command: &mut Command,
    input: Option<&[u8]>,
    deadline: Duration,
    what: &str,
) -> Result<Output, RunError> {
    let stdin = match input {
        Some(_) => Stdio::piped(),
        None => Stdio::null(),
    };
    let mut child = command
        .stdin(stdin)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|source| RunError::Spawn {
            what: what.to_string(),
            source,
        })?;
    match tokio::time::timeout(deadline, talk(&mut child, input, OUTPUT_CAP)).await {
        Ok(Ok(output)) => Ok(output),
        Ok(Err(stopped)) => {
            kill_and_reap(child, what).await;
            let what = what.to_string();
            Err(match stopped {
                Stopped::Io(source) => RunError::Io { what, source },
                Stopped::TooLarge { stream } => RunError::OutputTooLarge {
                    what,
                    stream,
                    cap: OUTPUT_CAP,
                },
            })
        }
        Err(_) => {
            kill_and_reap(child, what).await;
            Err(RunError::TimedOut {
                what: what.to_string(),
                deadline,
            })
        }
    }
}

/// Why talking to a child stopped before its exit.
#[derive(Debug)]
enum Stopped {
    Io(io::Error),
    /// The child wrote more than the cap to this stream.
    TooLarge {
        stream: &'static str,
    },
}

impl From<io::Error> for Stopped {
    fn from(e: io::Error) -> Self {
        Stopped::Io(e)
    }
}

/// Feed stdin, drain stdout and stderr up to `cap` bytes each, then wait; the three pipes at
/// once, so a child blocked on one of them never stalls the others. The first pipe to fail or
/// overflow ends the talk at once rather than waiting for the others.
async fn talk(child: &mut Child, input: Option<&[u8]>, cap: usize) -> Result<Output, Stopped> {
    let stdin = child.stdin.take();
    let mut stdout = child
        .stdout
        .take()
        .ok_or_else(|| io::Error::other("stdout was not piped"))?;
    let mut stderr = child
        .stderr
        .take()
        .ok_or_else(|| io::Error::other("stderr was not piped"))?;
    let feed = async move {
        let (Some(mut stdin), Some(input)) = (stdin, input) else {
            return Ok(());
        };
        // Dropped at the end of this block, which is the child's end of input.
        match stdin.write_all(input).await {
            // A child that stops reading says why in its status and on stderr.
            Err(e) if e.kind() == io::ErrorKind::BrokenPipe => Ok(()),
            written => written.map_err(Stopped::Io),
        }
    };
    let (_, out, err) = tokio::try_join!(
        feed,
        read_capped(&mut stdout, cap, "stdout"),
        read_capped(&mut stderr, cap, "stderr")
    )?;
    let status = child.wait().await?;
    Ok(Output {
        status,
        stdout: out,
        stderr: err,
    })
}

/// Read `stream` to its end, but never more than `cap` bytes of it: one byte past the cap is
/// read only to tell "exactly the cap" from "more".
async fn read_capped<R: AsyncRead + Unpin>(
    stream: &mut R,
    cap: usize,
    name: &'static str,
) -> Result<Vec<u8>, Stopped> {
    let mut out = Vec::new();
    let limit = u64::try_from(cap).unwrap_or(u64::MAX).saturating_add(1);
    stream.take(limit).read_to_end(&mut out).await?;
    match out.len() > cap {
        true => Err(Stopped::TooLarge { stream: name }),
        false => Ok(out),
    }
}

/// Kill `child` and reap it within [`REAP_BOUND`]; one that will not die in time is left to a
/// background task that keeps waiting for it, with a warning naming `what`.
pub async fn kill_and_reap(child: Child, what: &str) {
    reap_killed(child, what, REAP_BOUND).await;
}

/// Where a killed child was reaped.
#[derive(Debug, PartialEq, Eq)]
enum Reaped {
    InTime,
    InBackground,
}

/// What reaping needs of a child. A seam so the bound is testable: a process that survives
/// SIGKILL cannot be made on purpose.
trait Killable: Send + 'static {
    fn start_kill(&mut self) -> io::Result<()>;
    fn wait(&mut self) -> impl Future<Output = io::Result<ExitStatus>> + Send;
}

impl Killable for Child {
    fn start_kill(&mut self) -> io::Result<()> {
        Child::start_kill(self)
    }

    fn wait(&mut self) -> impl Future<Output = io::Result<ExitStatus>> + Send {
        Child::wait(self)
    }
}

async fn reap_killed<C: Killable>(mut child: C, what: &str, bound: Duration) -> Reaped {
    // "Already gone" is the outcome a kill wants.
    if let Err(e) = child.start_kill() {
        debug!(what, error = %e, "the child was already gone when it was stopped");
    }
    match tokio::time::timeout(bound, child.wait()).await {
        Ok(Ok(_)) => Reaped::InTime,
        Ok(Err(e)) => {
            debug!(what, error = %e, "reaping a stopped child");
            Reaped::InTime
        }
        Err(_) => {
            warn!(
                what,
                ?bound,
                "a killed child was not reaped in time (uninterruptible sleep?); a background \
                   task keeps waiting for it"
            );
            let what = what.to_string();
            tokio::spawn(async move {
                if child.wait().await.is_ok() {
                    debug!(what, "a child left to the background was reaped");
                }
            });
            Reaped::InBackground
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A child that ignores SIGKILL, as one in uninterruptible sleep does.
    struct Unkillable;

    impl Killable for Unkillable {
        fn start_kill(&mut self) -> io::Result<()> {
            Ok(())
        }

        fn wait(&mut self) -> impl Future<Output = io::Result<ExitStatus>> + Send {
            std::future::pending()
        }
    }

    fn sh(script: &str) -> Command {
        let mut command = Command::new("sh");
        command.args(["-c", script]);
        command
    }

    /// The reap is bounded: a child that will not die costs the bound, not the caller's life.
    #[tokio::test(start_paused = true)]
    async fn a_killed_child_that_will_not_die_is_left_to_the_background() {
        let reaped = reap_killed(Unkillable, "unkillable", REAP_BOUND).await;
        assert_eq!(reaped, Reaped::InBackground);
    }

    /// A command past its deadline is stopped and the call returns. A busy loop rather than
    /// `sleep`, whose forked child the kill would not reach.
    #[tokio::test]
    async fn a_command_past_its_deadline_is_stopped_and_the_call_returns() {
        let deadline = Duration::from_millis(200);
        let outcome = output_within(&mut sh("while :; do :; done"), None, deadline, "spin").await;
        assert!(
            matches!(outcome, Err(RunError::TimedOut { .. })),
            "{outcome:?}"
        );
    }

    /// Input goes in on stdin, and stdout and stderr both come back.
    #[tokio::test]
    async fn input_is_fed_and_both_pipes_are_drained() {
        let output = output_within(
            &mut sh("cat; echo said >&2"),
            Some(b"hello"),
            Duration::from_secs(5),
            "cat",
        )
        .await
        .expect("a run");
        assert!(output.status.success());
        assert_eq!(output.stdout, b"hello");
        assert_eq!(output.stderr, b"said\n");
    }

    /// A child that never stops printing is stopped at the cap, not followed into memory (N5).
    #[tokio::test]
    async fn a_child_that_prints_without_end_is_stopped_at_the_cap() {
        let deadline = Duration::from_secs(60);
        let outcome = output_within(&mut Command::new("yes"), None, deadline, "yes").await;
        assert!(
            matches!(
                outcome,
                Err(RunError::OutputTooLarge {
                    stream: "stdout",
                    ..
                })
            ),
            "{outcome:?}"
        );
    }

    /// The cap holds for stderr as well, which every caller reads into its error (N5).
    #[tokio::test]
    async fn a_child_that_complains_without_end_is_stopped_at_the_cap() {
        let deadline = Duration::from_secs(60);
        let outcome = output_within(&mut sh("yes >&2"), None, deadline, "yes").await;
        assert!(
            matches!(
                outcome,
                Err(RunError::OutputTooLarge {
                    stream: "stderr",
                    ..
                })
            ),
            "{outcome:?}"
        );
    }

    /// Output up to the cap is kept whole: the cap is a ceiling, not a truncation (N5).
    #[tokio::test]
    async fn output_of_exactly_the_cap_is_kept_whole() {
        let mut stream: &[u8] = &[b'x'; 64];
        let kept = read_capped(&mut stream, 64, "stdout")
            .await
            .expect("at the cap");
        assert_eq!(kept.len(), 64);
    }

    /// A child that exits without reading its input still reports its status and its words.
    #[tokio::test]
    async fn a_child_that_reads_none_of_its_input_still_reports_its_exit() {
        let input = vec![b'x'; 1 << 20];
        let output = output_within(
            &mut sh("echo refused >&2; exit 3"),
            Some(&input),
            Duration::from_secs(5),
            "refuser",
        )
        .await
        .expect("a run, not a pipe error");
        assert_eq!(output.status.code(), Some(3));
        assert_eq!(output.stderr, b"refused\n");
    }
}
