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

/// Which of a console's lines a caller wants to see.
///
/// Applied HERE, at the ring, and that placement is the whole point: the
/// truncation to `lines` happens at the same place, and a filter that ran
/// afterwards could only narrow what was already the last N lines. On a
/// chatty guest that is nothing at all — ask for the last five lines of a VM
/// whose init prints a heartbeat every ten seconds and every one of the five
/// is the heartbeat. Filtering first makes `lines` mean "the last N lines
/// that matter", which is what somebody asking for it meant.
///
/// Plain substring and not a regex, deliberately. It is what a person reaches
/// for, it cannot be made to backtrack, and a pattern language a NODE runs on
/// behalf of a remote caller is an attack surface a reading aid has not
/// earned. A client that wants more can still pipe the answer.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LogFilter {
    /// Drop a line containing any of these.
    pub hide: Vec<String>,
    /// Keep only lines containing at least one of these. Empty keeps
    /// everything, which is what a caller that named none meant.
    pub only: Vec<String>,
}

impl LogFilter {
    pub fn new(hide: Vec<String>, only: Vec<String>) -> Self {
        Self { hide, only }
    }

    pub fn is_empty(&self) -> bool {
        self.hide.is_empty() && self.only.is_empty()
    }

    /// `only` narrows first, then `hide` narrows again — so naming both is
    /// two cuts rather than a contradiction: "only the lines about the disk,
    /// and not the ones that are just polling it" is one sentence a person
    /// can mean.
    pub fn keeps(&self, line: &str) -> bool {
        let wanted = self.only.is_empty() || self.only.iter().any(|n| line.contains(n));
        wanted && !self.hide.iter().any(|n| line.contains(n))
    }
}

/// The end of one stream, at most `lines` lines of it.
///
/// Reads the last [`RING_BYTES`] and nothing more, whatever the file's
/// apparent length says: that window is exactly the part a punch leaves
/// alone, and reading further back would be reading a hole. `None` for a file
/// that is not there — a VM that has never started — which the caller renders
/// as empty rather than as an error.
pub fn tail(path: &Path, lines: usize, keep: &LogFilter) -> Option<String> {
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
    // Before the truncation and after the fragment: what a caller asked to
    // see decides WHICH lines the last `lines` of them are. See `LogFilter`.
    if !keep.is_empty() {
        out.retain(|line| keep.keeps(line));
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
pub fn read_all(
    paths: Vec<(ConsoleStream, std::path::PathBuf)>,
    lines: usize,
    keep: &LogFilter,
    wanted: &[ConsoleStream],
) -> Vec<(ConsoleStream, String)> {
    paths
        .into_iter()
        .filter(|(stream, _)| wanted.contains(stream))
        .filter_map(|(stream, path)| Some((stream, tail(&path, lines, keep)?)))
        .collect()
}

/// How many lines a caller gets when it asks for none. A screenful and a bit:
/// enough to see a panic without paging the whole ring over a session.
pub const DEFAULT_LINES: usize = 200;

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::os::unix::fs::MetadataExt;

    /// A file of this test's own, in a directory of its own.
    ///
    /// The guard comes back with the path and the caller binds it: the file
    /// used to live in one directory shared by every test of this module and
    /// by every run on the machine, which is only safe for as long as no two
    /// of them ever pick the same name.
    fn scratch(name: &str) -> (tempfile::TempDir, std::path::PathBuf) {
        let temp = tempfile::Builder::new()
            .prefix("meister-console-")
            .tempdir()
            .expect("a temp dir");
        let path = temp.path().join(name);
        (temp, path)
    }

    /// The whole point of the module, with a writer that behaves the way
    /// cloud-hypervisor's does: one open fd, appending, never reopening.
    ///
    /// A guest that prints far more than the ring holds must not make the
    /// file cost more than the ring, and must still be readable — with the
    /// END of what it printed, which is the half anybody ever wants.
    #[test]
    fn a_guest_that_outtalks_the_ring_neither_grows_it_nor_loses_its_tail() {
        let (_temp, path) = scratch("loop.console");
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
        let text = tail(&path, 5, &LogFilter::default()).unwrap();
        let last: Vec<&str> = text.lines().collect();
        assert_eq!(last.len(), 5);
        assert!(last[4].starts_with("round 9 line 1999"), "{}", last[4]);
        // No NUL from the punched region reached the reader.
        assert!(!text.contains('\0'));
    }

    /// The whole reason the filter lives HERE: it runs before `lines`, so
    /// `lines` means "the last N that matter".
    ///
    /// Filtered afterwards — which is where this started, in the client — the
    /// same request answers with nothing at all: the last five lines of a
    /// guest whose init prints a heartbeat every ten seconds are five
    /// heartbeats, and hiding them leaves an empty screen.
    #[test]
    fn the_filter_runs_before_the_truncation_and_not_after() {
        let (_temp, path) = scratch("chatty.console");
        let mut text = String::from("something went wrong\n");
        for t in (0..200).step_by(10) {
            text.push_str(&format!("nested alive t={t}s\n"));
        }
        std::fs::write(&path, &text).unwrap();

        // Unfiltered, the last five lines are five heartbeats — which is the
        // problem, stated as a test.
        let raw = tail(&path, 5, &LogFilter::default()).unwrap();
        assert_eq!(raw.lines().count(), 5);
        assert!(raw.lines().all(|l| l.contains("alive t=")));

        // Filtered first, the same five-line window finds the one line that
        // was ever worth reading.
        let quiet = LogFilter::new(vec!["alive t=".into()], Vec::new());
        assert_eq!(tail(&path, 5, &quiet).unwrap(), "something went wrong");
    }

    /// `only` narrows, `hide` narrows again, and naming both is two cuts
    /// rather than a contradiction.
    #[test]
    fn only_and_hide_narrow_in_that_order() {
        let (_temp, path) = scratch("mixed.console");
        std::fs::write(
            &path,
            "disk: attaching vda\ndisk: polling vda\nnet: link up\nmemory: ok\n",
        )
        .unwrap();

        let disk = LogFilter::new(Vec::new(), vec!["disk:".into()]);
        assert_eq!(
            tail(&path, 100, &disk).unwrap(),
            "disk: attaching vda\ndisk: polling vda"
        );

        let interesting = LogFilter::new(vec!["polling".into()], vec!["disk:".into()]);
        assert_eq!(
            tail(&path, 100, &interesting).unwrap(),
            "disk: attaching vda"
        );

        // Several needles on the same side: any of them keeps a line.
        let two = LogFilter::new(Vec::new(), vec!["net:".into(), "memory:".into()]);
        assert_eq!(tail(&path, 100, &two).unwrap(), "net: link up\nmemory: ok");

        // A filter that matches nothing answers with nothing, and that is an
        // answer — not an error, and not the unfiltered console.
        let nothing = LogFilter::new(Vec::new(), vec!["nowhere".into()]);
        assert_eq!(tail(&path, 100, &nothing).unwrap(), "");
    }

    /// An empty needle is dropped at the edge rather than sent, because an
    /// empty `only` matches every line and would make the flag mean its own
    /// opposite. Here: a filter nobody filled in changes nothing.
    #[test]
    fn a_filter_nobody_asked_for_leaves_the_console_exactly_as_it_was() {
        let (_temp, path) = scratch("untouched.console");
        std::fs::write(&path, "one\ntwo\nthree\n").unwrap();
        assert_eq!(
            tail(&path, 100, &LogFilter::default()).unwrap(),
            tail(&path, 100, &LogFilter::new(Vec::new(), Vec::new())).unwrap()
        );
        assert!(LogFilter::default().is_empty());
    }

    /// A file that fits in the ring is left completely alone: no punching, no
    /// blocks freed, and the first line is still the first line.
    #[test]
    fn a_quiet_guest_is_not_touched_at_all() {
        let (_temp, path) = scratch("quiet.console");
        std::fs::write(&path, "one\ntwo\nthree\n").unwrap();
        trim(&path);
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "one\ntwo\nthree\n");
        assert_eq!(
            tail(&path, 100, &LogFilter::default()).unwrap(),
            "one\ntwo\nthree"
        );
        // and asking for fewer lines than there are gives the last of them
        assert_eq!(tail(&path, 2, &LogFilter::default()).unwrap(), "two\nthree");
    }

    /// A VM that has printed nothing, and one that has never started: empty
    /// and absent, and neither is an error. `read_all` renders both as
    /// "nothing to show", which is an answer.
    #[test]
    fn no_output_at_all_is_an_answer_and_not_a_failure() {
        let (_temp, empty) = scratch("empty.console");
        std::fs::write(&empty, "").unwrap();
        assert_eq!(tail(&empty, 10, &LogFilter::default()).as_deref(), Some(""));
        trim(&empty); // and bounding it does nothing

        let (_temp, missing) = scratch("never-started.console");
        assert_eq!(tail(&missing, 10, &LogFilter::default()), None);
        trim(&missing); // no file, no warning, no panic
    }

    /// Both streams of one VM, as the API hands them out. A stream whose
    /// file does not exist is left OUT rather than reported as empty: a
    /// direct-kernel boot writes only `console`, and a `serial: ""` beside it
    /// would be a claim that the firmware said nothing when there was no
    /// firmware.
    #[test]
    fn a_vm_answers_with_the_streams_it_actually_has() {
        let (_temp, console) = scratch("both.console");
        let (_temp, serial) = scratch("both.serial");
        std::fs::write(&console, "kernel says hello\n").unwrap();
        let paths = vec![
            (ConsoleStream::Console, console.clone()),
            (ConsoleStream::Serial, serial.clone()),
        ];

        let only_console = read_all(
            paths.clone(),
            10,
            &LogFilter::default(),
            &ConsoleStream::ALL,
        );
        assert_eq!(only_console.len(), 1);
        assert_eq!(only_console[0].0, ConsoleStream::Console);
        assert_eq!(only_console[0].1, "kernel says hello");

        // And with both files there, both come back, console first.
        std::fs::write(&serial, "firmware says hello\n").unwrap();
        let both = read_all(
            paths.clone(),
            10,
            &LogFilter::default(),
            &ConsoleStream::ALL,
        );
        assert_eq!(
            both.iter().map(|(s, _)| *s).collect::<Vec<_>>(),
            ConsoleStream::ALL
        );

        // A VM that has never started answers with nothing at all, and that
        // is an answer.
        let (_console_temp, gone_console) = scratch("gone.console");
        let (_serial_temp, gone_serial) = scratch("gone.serial");
        let nothing = vec![
            (ConsoleStream::Console, gone_console),
            (ConsoleStream::Serial, gone_serial),
        ];
        assert!(
            read_all(
                nothing.clone(),
                10,
                &LogFilter::default(),
                &ConsoleStream::ALL
            )
            .is_empty()
        );
        trim_all(&nothing); // and bounding it is a no-op, not a panic
    }

    /// Trimming twice in a row is trimming once: the second pass finds a file
    /// that is already inside the ring and does nothing. A reconcile pass
    /// runs every few seconds, so this is the normal case and not an edge.
    #[test]
    fn trimming_is_idempotent() {
        let (_temp, path) = scratch("twice.console");
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
