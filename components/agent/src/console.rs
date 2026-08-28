// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! The guest's one-way output, bounded and readable.
//!
//! Cloud Hypervisor is configured with `console` and `serial` in `mode:
//! "File"` and writes both to `<run>/<id>.console` and `<id>.serial`. Nothing
//! in this tree ever read, bounded, rotated or removed them, and both
//! consequences of that are real: a guest in a boot loop or with a kernel log
//! storm fills the node's disk and takes the agent down with it, and every vm
//! id that ever existed leaves two files behind for good. `destroy` in the
//! hypervisor driver now removes them; this module is the other half.
//!
//! ## Why a hole and not a rotation
//!
//! The writer is a live process that holds an open fd with an offset into the
//! file, and that rules out every ordinary way of shortening a log:
//!
//! - Renaming it away leaves cloud-hypervisor writing into an unlinked inode.
//!   Its output then goes nowhere anybody can read, and the blocks stay
//!   allocated until the VMM exits — the exact opposite of the intent.
//! - `ftruncate` to zero does not move the writer's offset. Its next write
//!   lands where it always would, and the file comes back the same apparent
//!   size with a hole in front of it, minus the tail we wanted to keep.
//! - A pipe or a socket would put the agent in the path of the guest's
//!   output, and a pipe whose reader goes away kills the writer: an agent
//!   restart would then take every VM on the node with it. That trade is not
//!   worth a log file.
//!
//! `fallocate(PUNCH_HOLE)` is the one operation that does what is wanted: it
//! frees the blocks of the HEAD of the file and leaves everything else —
//! including the writer's offset and the bytes it has yet to write — exactly
//! as it was. The file's apparent length goes on growing and its disk usage
//! does not, which is the trade being made and the reason `ls -l` will show a
//! large number for a chatty guest while `du` shows [`RING_BYTES`].
//!
//! The reader is the same rule from the other end: the last [`RING_BYTES`],
//! which is precisely the region a punch is guaranteed to have left alone.

use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

use agent_api::ConsoleStream;
use macros::generated;
use tracing::{debug, warn};

/// How much of each stream is kept. One wants the END of a console log
/// essentially always — a panic, an emergency shell, the last thing before it
/// stopped — so this is a tail and not a sample.
///
/// 256 KiB is a few thousand lines of kernel output, which is more than the
/// whole of a boot, and it is small enough that a node running a hundred VMs
/// spends 50 MiB on all of them together.
pub const RING_BYTES: u64 = 256 * 1024;

/// Bound one file, if it has outgrown the ring.
///
/// Cheap enough to call on every reconcile pass: a `stat` for a file that is
/// still small, one `fallocate` for one that is not. Never an error a pass
/// has to handle — an output file that cannot be bounded is a degradation,
/// not a reason to stop reconciling the VM it belongs to.
#[generated(model = ClaudeOpus, version = "5")]
pub fn trim(path: &Path) {
    let file = match std::fs::OpenOptions::new().write(true).open(path) {
        Ok(f) => f,
        // A VM that has been created but never started has no file yet, and a
        // driver that writes none never will. Both are the normal case, not
        // something to say anything about.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return,
        Err(e) => {
            warn!(path = %path.display(), error = format!("{e:#}"),
                  "cannot open the console file to bound it");
            return;
        }
    };
    let len = match file.metadata() {
        Ok(m) => m.len(),
        Err(e) => {
            warn!(path = %path.display(), error = format!("{e:#}"),
                  "cannot measure the console file");
            return;
        }
    };
    let Some(head) = len.checked_sub(RING_BYTES).filter(|h| *h > 0) else {
        return;
    };

    use nix::fcntl::{FallocateFlags, fallocate};
    // KEEP_SIZE as well as PUNCH_HOLE: the apparent length must not change,
    // because the writer's offset is measured against it and shortening the
    // file under a live writer is the whole class of mistake this avoids.
    let flags = FallocateFlags::FALLOC_FL_PUNCH_HOLE | FallocateFlags::FALLOC_FL_KEEP_SIZE;
    match fallocate(&file, flags, 0, head as i64) {
        Ok(()) => debug!(path = %path.display(), freed_bytes = head,
                         "punched the head out of the console file"),
        // Degraded, and it heals by itself if the node is ever moved to a
        // filesystem that can do this. WARN and not ERROR for that reason —
        // but it IS the case where the disk can still fill, so it is not a
        // debug line either.
        Err(e) => warn!(path = %path.display(), error = %e,
                        "cannot punch a hole in the console file; it stays as large as the \
                         guest makes it"),
    }
}

/// Bound every stream of one VM. What a reconcile pass calls.
///
/// Takes the paths rather than the hypervisor: the driver is the only party
/// that knows WHERE they are and this module is the only one that knows what
/// to do with them, and keeping the trait out of here is what makes both
/// halves testable against a file on disk.
pub fn trim_all(paths: &[(ConsoleStream, std::path::PathBuf)]) {
    for (_, path) in paths {
        trim(path);
    }
}

/// The end of one stream, at most `lines` lines of it.
///
/// Reads the last [`RING_BYTES`] and nothing more, whatever the file's
/// apparent length says: that window is exactly the part a punch leaves
/// alone, and reading further back would be reading a hole. `None` for a file
/// that is not there — a VM that has never started — which the caller renders
/// as empty rather than as an error.
#[generated(model = ClaudeOpus, version = "5")]
pub fn tail(path: &Path, lines: usize) -> Option<String> {
    let mut file = std::fs::File::open(path).ok()?;
    let len = file.metadata().ok()?.len();
    let from = len.saturating_sub(RING_BYTES);
    file.seek(SeekFrom::Start(from)).ok()?;
    let mut bytes = Vec::with_capacity(RING_BYTES as usize);
    file.take(RING_BYTES).read_to_end(&mut bytes).ok()?;

    // A punch reads back as zeros, and the window can overlap one when the
    // file grew between the trim and this read. They are not output and no
    // console ever emits them, so dropping them costs nothing and saves the
    // reader a screenful of NULs.
    bytes.retain(|b| *b != 0);

    // Lossy, deliberately: a console carries whatever the guest put on the
    // wire, half a UTF-8 sequence at the window boundary included, and a
    // `vm logs` that refuses to print because byte 3 is not valid UTF-8 is
    // useless exactly when it is needed.
    let text = String::from_utf8_lossy(&bytes);
    // The first line of the window is very likely a fragment — the window
    // starts at a byte offset, not at a newline — so it is dropped once
    // there is more than one line and the read did not start at the file's
    // beginning.
    let mut out: Vec<&str> = text.lines().collect();
    if from > 0 && out.len() > 1 {
        out.remove(0);
    }
    if out.len() > lines {
        out.drain(..out.len() - lines);
    }
    Some(out.join("\n"))
}

/// Both streams of one VM, in the shape the API hands out: one entry per
/// stream that has anything, `console` first.
///
/// A VM with no output at all comes back as an empty list and not as an
/// error: "it printed nothing" is an answer, and the commonest one for a VM
/// that has just been created.
#[generated(model = ClaudeOpus, version = "5")]
pub fn read_all(
    paths: Vec<(ConsoleStream, std::path::PathBuf)>,
    lines: usize,
) -> Vec<(ConsoleStream, String)> {
    paths
        .into_iter()
        .filter_map(|(stream, path)| Some((stream, tail(&path, lines)?)))
        .collect()
}

/// How many lines a caller gets when it asks for none. A screenful and a bit:
/// enough to see a panic without paging the whole ring over a session.
pub const DEFAULT_LINES: usize = 200;

#[cfg(test)]
#[generated(model = ClaudeOpus, version = "5")]
mod tests {
    use super::*;
    use std::io::Write;
    use std::os::unix::fs::MetadataExt;

    fn scratch(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join("meister-console-tests");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(name);
        let _ = std::fs::remove_file(&path);
        path
    }

    /// The whole point of the module, with a writer that behaves the way
    /// cloud-hypervisor's does: one open fd, appending, never reopening.
    ///
    /// A guest that prints far more than the ring holds must not make the
    /// file cost more than the ring, and must still be readable — with the
    /// END of what it printed, which is the half anybody ever wants.
    #[test]
    fn a_guest_that_outtalks_the_ring_neither_grows_it_nor_loses_its_tail() {
        let path = scratch("loop.console");
        let mut writer = std::fs::File::create(&path).unwrap();

        // Ten rounds of "print a lot, then a pass trims" — a boot loop, in
        // miniature. The writer never learns that anything happened to the
        // file, which is the property being tested.
        let mut printed = 0u64;
        for round in 0..10 {
            for line in 0..2000 {
                let text = format!("round {round} line {line} {}\n", "x".repeat(60));
                printed += text.len() as u64;
                writer.write_all(text.as_bytes()).unwrap();
            }
            writer.flush().unwrap();
            trim(&path);
        }
        assert!(printed > 4 * RING_BYTES, "the test has to outrun the ring");

        let meta = std::fs::metadata(&path).unwrap();
        // What the file COSTS is bounded. What it claims to be is not, and
        // that is the documented trade: a punched hole keeps the writer's
        // offset valid, which is the only reason this works at all.
        let on_disk = meta.blocks() * 512;
        assert!(
            on_disk <= (RING_BYTES + RING_BYTES / 2) as i64 as u64,
            "the file occupies {on_disk} bytes, the ring is {RING_BYTES}"
        );
        assert!(
            meta.len() > RING_BYTES,
            "the apparent length is not bounded"
        );

        // And the end of the output is there, exactly.
        let text = tail(&path, 5).unwrap();
        let last: Vec<&str> = text.lines().collect();
        assert_eq!(last.len(), 5);
        assert!(last[4].starts_with("round 9 line 1999"), "{}", last[4]);
        // No NUL from the punched region reached the reader.
        assert!(!text.contains('\0'));
    }

    /// A file that fits in the ring is left completely alone: no punching, no
    /// blocks freed, and the first line is still the first line.
    #[test]
    fn a_quiet_guest_is_not_touched_at_all() {
        let path = scratch("quiet.console");
        std::fs::write(&path, "one\ntwo\nthree\n").unwrap();
        trim(&path);
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "one\ntwo\nthree\n");
        assert_eq!(tail(&path, 100).unwrap(), "one\ntwo\nthree");
        // and asking for fewer lines than there are gives the last of them
        assert_eq!(tail(&path, 2).unwrap(), "two\nthree");
    }

    /// A VM that has printed nothing, and one that has never started: empty
    /// and absent, and neither is an error. `read_all` renders both as
    /// "nothing to show", which is an answer.
    #[test]
    fn no_output_at_all_is_an_answer_and_not_a_failure() {
        let empty = scratch("empty.console");
        std::fs::write(&empty, "").unwrap();
        assert_eq!(tail(&empty, 10).as_deref(), Some(""));
        trim(&empty); // and bounding it does nothing

        let missing = scratch("never-started.console");
        assert_eq!(tail(&missing, 10), None);
        trim(&missing); // no file, no warning, no panic
    }

    /// Both streams of one VM, as the API hands them out. A stream whose
    /// file does not exist is left OUT rather than reported as empty: a
    /// direct-kernel boot writes only `console`, and a `serial: ""` beside it
    /// would be a claim that the firmware said nothing when there was no
    /// firmware.
    #[test]
    fn a_vm_answers_with_the_streams_it_actually_has() {
        let console = scratch("both.console");
        let serial = scratch("both.serial");
        std::fs::write(&console, "kernel says hello\n").unwrap();
        let paths = vec![
            (ConsoleStream::Console, console.clone()),
            (ConsoleStream::Serial, serial.clone()),
        ];

        let only_console = read_all(paths.clone(), 10);
        assert_eq!(only_console.len(), 1);
        assert_eq!(only_console[0].0, ConsoleStream::Console);
        assert_eq!(only_console[0].1, "kernel says hello");

        // And with both files there, both come back, console first.
        std::fs::write(&serial, "firmware says hello\n").unwrap();
        let both = read_all(paths.clone(), 10);
        assert_eq!(
            both.iter().map(|(s, _)| *s).collect::<Vec<_>>(),
            ConsoleStream::ALL
        );

        // A VM that has never started answers with nothing at all, and that
        // is an answer.
        let nothing = vec![
            (ConsoleStream::Console, scratch("gone.console")),
            (ConsoleStream::Serial, scratch("gone.serial")),
        ];
        assert!(read_all(nothing.clone(), 10).is_empty());
        trim_all(&nothing); // and bounding it is a no-op, not a panic
    }

    /// Trimming twice in a row is trimming once: the second pass finds a file
    /// that is already inside the ring and does nothing. A reconcile pass
    /// runs every few seconds, so this is the normal case and not an edge.
    #[test]
    fn trimming_is_idempotent() {
        let path = scratch("twice.console");
        let mut writer = std::fs::File::create(&path).unwrap();
        writer
            .write_all(&vec![b'a'; (RING_BYTES * 3) as usize])
            .unwrap();
        writer.flush().unwrap();

        trim(&path);
        let after_one = std::fs::metadata(&path).unwrap().blocks();
        trim(&path);
        let after_two = std::fs::metadata(&path).unwrap().blocks();
        assert_eq!(after_one, after_two);
    }
}
