// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! The guest's serial line: recorded always, held by at most one client.
//!
//! ## Why this module exists at all
//!
//! `console` says a console is one-way, and for reading it still is. But a
//! file has no input path — you cannot write into `<id>.serial` and have the
//! guest see it — so an interactive console cannot be built on the device
//! configuration `vm logs` was built on. Cloud Hypervisor gives a device
//! exactly one mode, so the choice is not "both" but "which".
//!
//! The serial device therefore moves from `mode: File` to `mode: Socket`, and
//! this module becomes what CH's file writing used to be: it connects to that
//! socket for the VM's whole life, appends everything the guest says to the
//! same `<id>.serial` the reader already knows, and — when somebody is
//! attached — hands the same bytes to them as well.
//!
//! **`vm logs` is unchanged by any of this.** It reads the same file, bounded
//! by the same `trim`, filtered by the same `LogFilter`. That was the
//! requirement, and it is why the recording is not simply "forward to whoever
//! is attached": nobody is attached almost all of the time, and the log has
//! to exist anyway.
//!
//! ## Why the failure mode is acceptable now
//!
//! `console`'s note refuses a pipe or a socket, because "a pipe whose reader
//! goes away kills the writer: an agent restart would then take every VM on
//! the node with it". That is true of a pipe and NOT true of this socket, and
//! the difference is CH's own doing: its `SocketConsole` holds a 1 MiB ring
//! while nobody is connected and replays it on connect. A reader that goes
//! away costs nothing — the guest writes on, CH buffers, and the next
//! connection gets the backlog. The agent restarting loses output only if the
//! guest produced more than a megabyte in the gap, which is four times what
//! this node keeps anyway.
//!
//! That is also why the recorder is level-triggered rather than started once:
//! the reconcile pass asks for it every time it runs, so a task that ended
//! for any reason is simply made again on the next pass, and CH's buffer
//! covers the gap.
//!
//! ## One holder
//!
//! A serial line is one line. Two people typing into it interleave their
//! keystrokes into one stream of nonsense, and neither can tell which half of
//! the mess was theirs — so the second attach is refused rather than merged.
//! Reading is not affected: `vm logs` works while somebody holds the line,
//! and so does another person's `vm logs`, because reading is the file.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use agent_api::VmId;
use anyhow::{Context, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

/// How much of the guest's output one attached client may fall behind before
/// its own copy starts being dropped.
///
/// Dropped for the CLIENT and never for the recording: the file is written
/// first and unconditionally, so a slow reader can lose what it sees on
/// screen and can never make a hole in `vm logs`. Sixty-four chunks is a
/// screenful many times over — a client that far behind is not reading.
const HOLDER_BACKLOG: usize = 64;

/// What one client sends towards the guest in a single write.
///
/// Small on purpose: a console carries keystrokes, and a client that could
/// hand the guest a megabyte in one call would be a client that can stall the
/// serial device for everybody who reads it afterwards.
pub const MAX_INPUT: usize = 4096;

/// The serial lines of every VM this node runs.
#[derive(Default)]
pub struct Consoles {
    lines: Mutex<HashMap<VmId, Arc<Line>>>,
}

/// One VM's line: a way to write to the guest, and the one holder if there is
/// one.
pub struct Line {
    id: VmId,
    /// The write half of the connection to CH. Behind an async mutex because
    /// a write is awaited and two holders must never interleave — there is
    /// only ever one holder, so this is uncontended and says so.
    to_guest: tokio::sync::Mutex<Option<UnixStream>>,
    /// `Some` while somebody is attached. Reading it is what the recorder
    /// does per chunk, so it is a plain mutex and never held across an await.
    holder: Mutex<Option<mpsc::Sender<Vec<u8>>>>,
}

/// What an attach hands back: the guest's output from now on, and the token
/// that gives the line up again.
///
/// `Debug` names the VM and nothing else — a console's CONTENTS are the most
/// revealing thing a VM has, and a struct that printed its buffer into a log
/// line would be the one place they leaked.
pub struct Held {
    pub output: mpsc::Receiver<Vec<u8>>,
    line: Arc<Line>,
}

impl std::fmt::Debug for Held {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Held({})", self.line.id)
    }
}

impl Drop for Held {
    /// Giving the line back is not a thing a client can forget: whatever ends
    /// the session — a clean detach, a dropped connection, a panic in the
    /// handler — the holder slot is free again by the time this returns.
    fn drop(&mut self) {
        *self.line.holder.lock().expect("holder") = None;
        info!(vm_id = %self.line.id, "console released");
    }
}

impl Held {
    /// The guest's next chunk, or `None` when the line has ended.
    pub async fn recv(&mut self) -> Option<Vec<u8>> {
        self.output.recv().await
    }

    /// A handle that can type into the guest without holding the line.
    ///
    /// The HOLDING is this `Held` and belongs to whoever is reading, because
    /// reading is what a session is: when the reader stops, the line is free.
    /// A writer that also held it would keep the line alive for a client that
    /// had stopped listening.
    pub fn writer(&self) -> ConsoleWriter {
        ConsoleWriter {
            line: self.line.clone(),
        }
    }

    /// Send keystrokes to the guest.
    ///
    /// Refused rather than truncated past `MAX_INPUT`: a client that sends
    /// more than that in one call is not typing, and quietly keeping the
    /// first four kilobytes would be this layer deciding which half of
    /// somebody's input the guest gets.
    pub async fn write(&self, bytes: &[u8]) -> Result<()> {
        self.writer().write(bytes).await
    }
}

/// Types into a guest, and holds nothing.
///
/// Its own type rather than a method on `Consoles`, because holding and
/// writing have different lifetimes: the session ends when the READER stops,
/// and a writer that kept the line alive would hold it open for a client that
/// had already gone.
#[derive(Clone)]
pub struct ConsoleWriter {
    line: Arc<Line>,
}

impl ConsoleWriter {
    /// Refused rather than truncated past `MAX_INPUT`: a client that sends
    /// more than that in one call is not typing, and keeping the first four
    /// kilobytes would be this layer deciding which half of somebody's input
    /// the guest gets.
    pub async fn write(&self, bytes: &[u8]) -> Result<()> {
        anyhow::ensure!(
            bytes.len() <= MAX_INPUT,
            "a console write is at most {MAX_INPUT} bytes; this one is {}",
            bytes.len()
        );
        let mut guard = self.line.to_guest.lock().await;
        let stream = guard
            .as_mut()
            .context("the console connection to this vm is gone; attach again")?;
        stream
            .write_all(bytes)
            .await
            .context("writing to the guest")
    }
}

impl Consoles {
    /// Make sure this VM's line is being recorded, and do nothing if it
    /// already is.
    ///
    /// Called from the reconcile pass, so "already is" is the answer almost
    /// every time and has to be cheap: one map lookup. A line whose task has
    /// ended is removed by the task itself, so its absence here IS the
    /// condition to act on — no liveness flag, nothing to get out of step.
    pub async fn ensure(self: &Arc<Self>, id: &VmId, socket: &Path) {
        if self.lines.lock().expect("lines").contains_key(id) {
            return;
        }
        // A VM that has been created but not booted has no socket yet, and a
        // node that has just restarted may reach this before CH is listening.
        // Neither is worth a word: the next pass asks again.
        let stream = match UnixStream::connect(socket).await {
            Ok(stream) => stream,
            Err(e) => {
                debug!(vm_id = %id, error = %e, "no console socket yet");
                return;
            }
        };
        let (reader, writer) = split(stream);
        let line = Arc::new(Line {
            id: *id,
            to_guest: tokio::sync::Mutex::new(Some(writer)),
            holder: Mutex::new(None),
        });
        self.lines.lock().expect("lines").insert(*id, line.clone());
        info!(vm_id = %id, "recording the guest's serial line");

        let consoles = self.clone();
        let id = *id;
        let sink = ring_path(socket);
        tokio::spawn(async move {
            if let Err(e) = record(reader, &sink, &line).await {
                warn!(vm_id = %id, error = format!("{e:#}"), "console recording ended");
            }
            // The task IS the liveness: gone from the map means the next
            // reconcile pass makes it again.
            consoles.lines.lock().expect("lines").remove(&id);
        });
    }

    /// Take the line, if nobody else has it.
    ///
    /// `None` for a VM whose line is not being recorded — a VM that is not
    /// running, or one whose recorder has not been made yet. The caller turns
    /// that into a different sentence from "somebody else has it", because
    /// they are different problems.
    pub fn attach(&self, id: &VmId) -> Option<Result<Held>> {
        let line = self.lines.lock().expect("lines").get(id)?.clone();
        let mut holder = line.holder.lock().expect("holder");
        if holder.is_some() {
            return Some(Err(anyhow::anyhow!(
                "somebody else is holding this console; a serial line is one line, \
                 and two writers make one stream neither of them can read"
            )));
        }
        let (tx, output) = mpsc::channel(HOLDER_BACKLOG);
        *holder = Some(tx);
        drop(holder);
        info!(vm_id = %id, "console held");
        Some(Ok(Held {
            output,
            line: line.clone(),
        }))
    }

    /// Whether this VM's line is recorded and whether anybody holds it — for
    /// a status read that must not disturb either.
    pub fn state(&self, id: &VmId) -> (bool, bool) {
        match self.lines.lock().expect("lines").get(id) {
            Some(line) => (true, line.holder.lock().expect("holder").is_some()),
            None => (false, false),
        }
    }

    /// Forget a VM's line — on destroy, so a re-used id cannot inherit one.
    pub fn forget(&self, id: &VmId) {
        self.lines.lock().expect("lines").remove(id);
    }
}

/// The ring file that belongs to a console socket.
///
/// Derived rather than passed, so that the two names cannot drift: the driver
/// spells the socket `<id>.serial.sock` beside the file `<id>.serial`, and
/// this is the same sentence read backwards.
fn ring_path(socket: &Path) -> PathBuf {
    let path = socket.to_path_buf();
    match path.extension().and_then(|e| e.to_str()) {
        Some("sock") => path.with_extension(""),
        _ => path,
    }
}

/// Read the guest forever: to the file first, to the holder second.
///
/// The order is the contract. `vm logs` must not depend on anybody being
/// attached, and a client that cannot keep up must not be able to make a hole
/// in what was recorded — so the write that can fail slowly happens after the
/// write that must not.
async fn record(mut reader: UnixStream, sink: &Path, line: &Arc<Line>) -> Result<()> {
    let mut file = tokio::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(sink)
        .await
        .with_context(|| format!("opening {} to record the console", sink.display()))?;

    let mut buf = vec![0u8; 8192];
    loop {
        let read = reader.read(&mut buf).await.context("reading the console")?;
        if read == 0 {
            // CH closed the connection: the VM is gone, or its serial device
            // is. Either way this line is over and the map entry goes with it.
            return Ok(());
        }
        let chunk = &buf[..read];
        file.write_all(chunk)
            .await
            .context("recording the console")?;

        // The holder's copy, and only if there is one. `try_send` and not
        // `send`: a client that has stopped reading must not be able to stall
        // the recording, which is the one thing here that has to keep up.
        let holder = line.holder.lock().expect("holder").clone();
        if let Some(tx) = holder
            && tx.try_send(chunk.to_vec()).is_err()
        {
            debug!(vm_id = %line.id, "console holder is behind; dropped a chunk");
        }
    }
}

/// One connection, used from two tasks.
///
/// `UnixStream::into_split` would be the tidy way and it is not available for
/// what this needs: the write half lives in the `Line` for as long as
/// somebody may type, and the read half in a task that outlives every holder.
/// A second connection to the same socket is not an option either — CH serves
/// one client and would hand the second the line instead of the first.
fn split(stream: UnixStream) -> (UnixStream, UnixStream) {
    // Both halves are the same fd, duplicated: reads and writes on a socket
    // are independent directions and need no coordination between them.
    let std_stream = stream
        .into_std()
        .expect("a tokio UnixStream converts back while nothing is polling it");
    let cloned = std_stream
        .try_clone()
        .expect("duplicating a unix socket fd cannot fail for a live socket");
    std_stream
        .set_nonblocking(true)
        .expect("already nonblocking");
    cloned.set_nonblocking(true).expect("already nonblocking");
    (
        UnixStream::from_std(std_stream).expect("a nonblocking socket"),
        UnixStream::from_std(cloned).expect("a nonblocking socket"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The socket and the file it records into are one name apart, and the
    /// derivation is what keeps them that way.
    #[test]
    fn the_ring_file_belongs_to_its_socket() {
        assert_eq!(
            ring_path(Path::new("/run/vms/abc.serial.sock")),
            Path::new("/run/vms/abc.serial")
        );
        // Not a socket path: left alone rather than mangled.
        assert_eq!(
            ring_path(Path::new("/run/vms/abc.serial")),
            Path::new("/run/vms/abc.serial")
        );
    }

    /// A VM nobody is recording cannot be attached to, and that is a
    /// different answer from "somebody else has it".
    #[test]
    fn attaching_to_a_vm_with_no_line_is_not_the_same_as_a_busy_line() {
        let consoles = Consoles::default();
        let id: VmId = "11111111-1111-1111-1111-111111111111".parse().unwrap();
        assert!(consoles.attach(&id).is_none(), "no line at all");
        assert_eq!(consoles.state(&id), (false, false));
    }

    /// One holder, and the slot frees itself when the holder goes away —
    /// whatever ended the session.
    #[tokio::test]
    async fn a_second_attach_is_refused_until_the_first_lets_go() {
        let (ours, _theirs) = UnixStream::pair().unwrap();
        let id: VmId = "22222222-2222-2222-2222-222222222222".parse().unwrap();
        let line = Arc::new(Line {
            id,
            to_guest: tokio::sync::Mutex::new(Some(ours)),
            holder: Mutex::new(None),
        });
        let consoles = Consoles::default();
        consoles.lines.lock().unwrap().insert(id, line.clone());

        assert_eq!(consoles.state(&id), (true, false), "recorded, unheld");
        let held = consoles.attach(&id).expect("a line").expect("free");
        assert_eq!(consoles.state(&id), (true, true), "held");

        let refused = consoles
            .attach(&id)
            .expect("still a line")
            .expect_err("already held");
        assert!(refused.to_string().contains("one line"), "{refused}");

        // Dropping is releasing: nothing has to be called for the next person
        // to get in.
        drop(held);
        assert_eq!(consoles.state(&id), (true, false));
        assert!(consoles.attach(&id).expect("a line").is_ok());
    }

    /// A write bigger than a keystroke burst is refused rather than cut in
    /// half.
    #[tokio::test]
    async fn an_oversized_write_is_refused_whole() {
        let (ours, mut theirs) = UnixStream::pair().unwrap();
        let id: VmId = "33333333-3333-3333-3333-333333333333".parse().unwrap();
        let line = Arc::new(Line {
            id,
            to_guest: tokio::sync::Mutex::new(Some(ours)),
            holder: Mutex::new(None),
        });
        let (tx, output) = mpsc::channel(1);
        *line.holder.lock().unwrap() = Some(tx);
        let held = Held { output, line };

        held.write(b"ls\n").await.expect("a keystroke burst");
        let mut buf = [0u8; 3];
        theirs.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ls\n", "it reached the guest unchanged");

        let too_much = vec![b'x'; MAX_INPUT + 1];
        let refused = held.write(&too_much).await.expect_err("too much");
        assert!(refused.to_string().contains("at most"), "{refused}");
    }
}
