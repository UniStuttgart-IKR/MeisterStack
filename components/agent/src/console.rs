// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Bound and read guest console log files.
//!
//! The VMM writes the console file; the serial recorder writes the serial file.
//! Hole punching releases old blocks without changing open writers' offsets or
//! apparent file length. Readers use the last `RING_BYTES` bytes. Trimming is
//! periodic and best effort; unsupported filesystems can leave logs unbounded.

use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

use agent_api::ConsoleStream;
use tracing::{debug, warn};

/// Target retained tail per stream after a successful trim.
pub const RING_BYTES: u64 = 256 * 1024;

/// Punch out bytes before the retained tail. Missing files are ignored;
/// other failures are logged without interrupting reconciliation.
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
    // Preserve apparent length so hole punching does not invalidate a live writer's offset.
    let flags = FallocateFlags::FALLOC_FL_PUNCH_HOLE | FallocateFlags::FALLOC_FL_KEEP_SIZE;
    match fallocate(&file, flags, 0, head as i64) {
        Ok(()) => debug!(path = %path.display(), freed_bytes = head,
                         "punched the head out of the console file"),
        // Warn because failed trimming leaves disk usage unbounded; later passes can retry.
        Err(e) => warn!(path = %path.display(), error = %e,
                        "cannot punch a hole in the console file; it stays as large as the \
                         guest makes it"),
    }
}

/// Trim the paths supplied by the hypervisor driver.
pub fn trim_all(paths: &[(ConsoleStream, std::path::PathBuf)]) {
    for (_, path) in paths {
        trim(path);
    }
}

/// Substring filters applied before the line limit, so the limit counts
/// matching lines within the retained byte window.
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

    /// Apply the inclusion filter, then exclude any hidden substrings.
    pub fn keeps(&self, line: &str) -> bool {
        let wanted = self.only.is_empty() || self.only.iter().any(|n| line.contains(n));
        wanted && !self.hide.iter().any(|n| line.contains(n))
    }
}

/// Read at most `RING_BYTES`, filter, and keep the last `lines` matches.
/// Return `None` on open, metadata, seek, or read failure.
pub fn tail(path: &Path, lines: usize, keep: &LogFilter) -> Option<String> {
    let mut file = std::fs::File::open(path).ok()?;
    let len = file.metadata().ok()?.len();
    let from = len.saturating_sub(RING_BYTES);
    file.seek(SeekFrom::Start(from)).ok()?;
    let mut bytes = Vec::with_capacity(RING_BYTES as usize);
    file.take(RING_BYTES).read_to_end(&mut bytes).ok()?;

    // Discard NUL bytes, including any hole exposed by concurrent trimming.
    bytes.retain(|b| *b != 0);

    // Accept arbitrary guest bytes and partial UTF-8 at the window boundary.
    let text = String::from_utf8_lossy(&bytes);
    // A byte-offset window can begin mid-line. Drop that fragment when
    // reading beyond the file start and another line is available.
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

/// Read selected streams in input order. Omit streams whose files cannot be
/// read; readable empty files remain present with empty output.
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

/// Default maximum number of returned lines.
pub const DEFAULT_LINES: usize = 200;

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::os::unix::fs::MetadataExt;

    /// Keep each test's file in a separate temporary directory.
    fn scratch(name: &str) -> (tempfile::TempDir, std::path::PathBuf) {
        let temp = tempfile::Builder::new()
            .prefix("meister-console-")
            .tempdir()
            .expect("a temp dir");
        let path = temp.path().join(name);
        (temp, path)
    }

    /// Hole punching preserves an open writer's offset and retains its latest output.
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
        // Allocated blocks are bounded while apparent length preserves the writer's offset.
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

    /// Filtering precedes the line limit.
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

        // Filter before selecting the requested line window.
        let quiet = LogFilter::new(vec!["alive t=".into()], Vec::new());
        assert_eq!(tail(&path, 5, &quiet).unwrap(), "something went wrong");
    }

    /// Inclusion and exclusion filters compose.
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

    /// An empty filter leaves output unchanged.
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

    /// An empty file yields empty output; a missing file yields `None`.
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

    /// Return readable streams and omit missing files.
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

    /// Repeating a trim preserves allocated size, though apparent length is unchanged.
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
