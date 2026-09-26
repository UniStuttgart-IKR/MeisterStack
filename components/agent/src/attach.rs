// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Record guest serial output and allow one interactive holder per VM.
//!
//! The recorder connects to the VMM serial socket, appends output to the log
//! file, then forwards a copy to the holder. A slow holder drops its own chunks
//! without blocking recording. Reconciliation recreates a finished recorder;
//! output during disconnection depends on the VMM's buffering.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use agent_api::VmId;
use anyhow::{Context, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

/// Maximum queued output chunks per holder. Full queues drop the holder's
/// copy after recording it to disk.
const HOLDER_BACKLOG: usize = 64;

/// Maximum bytes accepted in one write to the guest.
pub const MAX_INPUT: usize = 4096;

/// The serial lines of every VM this node runs.
#[derive(Default)]
pub struct Consoles {
    lines: Mutex<HashMap<VmId, Arc<Line>>>,
}

/// A VM serial writer and its optional interactive holder.
pub struct Line {
    id: VmId,
    /// Serial connection used for writes, serialized across writer handles.
    to_guest: tokio::sync::Mutex<Option<UnixStream>>,
    /// Active holder, read per output chunk. Never hold this mutex across await.
    holder: Mutex<Option<mpsc::Sender<Vec<u8>>>>,
}

/// Output receiver and exclusive holder token. Debug output omits console data.
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
    /// Release the holder slot when the session token is dropped.
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

    /// Return a writer without extending the lifetime of the holder token.
    pub fn writer(&self) -> ConsoleWriter {
        ConsoleWriter {
            line: self.line.clone(),
        }
    }

    /// Write at most `MAX_INPUT` bytes; reject oversized input without truncation.
    pub async fn write(&self, bytes: &[u8]) -> Result<()> {
        self.writer().write(bytes).await
    }
}

/// A writer whose lifetime is independent of the holder token.
#[derive(Clone)]
pub struct ConsoleWriter {
    line: Arc<Line>,
}

impl ConsoleWriter {
    /// Write at most `MAX_INPUT` bytes; reject oversized input without truncation.
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
    /// Start recording if the VM has no recorder. A finished task removes its
    /// entry so a later reconciliation can reconnect.
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

    /// Acquire the exclusive holder. Return `None` without a recorder and an
    /// error when another holder exists.
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

/// Derive the recording path by removing the socket's `.sock` extension.
fn ring_path(socket: &Path) -> PathBuf {
    let path = socket.to_path_buf();
    match path.extension().and_then(|e| e.to_str()) {
        Some("sock") => path.with_extension(""),
        _ => path,
    }
}

/// Append output to the log before forwarding a nonblocking copy to the holder.
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

        // Forward without awaiting: a slow holder must not block recording.
        let holder = line.holder.lock().expect("holder").clone();
        if let Some(tx) = holder
            && tx.try_send(chunk.to_vec()).is_err()
        {
            debug!(vm_id = %line.id, "console holder is behind; dropped a chunk");
        }
    }
}

/// Duplicate the same socket for independent read and write tasks. A second
/// connection would compete for the VMM's single console client.
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

    /// The recording path shares the socket stem.
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

    /// Distinguish an unavailable recorder from an occupied holder slot.
    #[test]
    fn attaching_to_a_vm_with_no_line_is_not_the_same_as_a_busy_line() {
        let consoles = Consoles::default();
        let id: VmId = "11111111-1111-1111-1111-111111111111".parse().unwrap();
        assert!(consoles.attach(&id).is_none(), "no line at all");
        assert_eq!(consoles.state(&id), (false, false));
    }

    /// Dropping the holder token permits the next attachment.
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

    /// Oversized input is rejected without writing a prefix.
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
