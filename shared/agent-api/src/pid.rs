// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Whether the process at a recorded pid is still the process that was
//! recorded.
//!
//! A pid is not an identity. Linux hands the number out again, and on a node
//! that starts and stops VMs for a living it hands it out again soon: the
//! agent writes `vmm_pid` down, the VMM dies, something else on the machine
//! gets the number, and every later use of that record is now about a
//! stranger. The uses are not harmless — one of them is `SIGKILL`.
//!
//! What makes this answerable is that every process this agent starts is
//! started FOR one object and carries that object's uuid on its command line:
//! cloud-hypervisor gets `--api-socket <run_dir>/<vm id>.sock`, virtiofsd gets
//! `--socket-path <run_dir>/<volume id>.sock`. The uuid is the marker, the
//! command line is where it can be read back, and neither can be true of a
//! process the agent did not start.

/// Does the process at `pid` still carry `marker` on its command line?
///
/// `false` for a dead pid — a process that is gone has no `cmdline` to read —
/// so this subsumes liveness and callers do not need a second probe. `false`
/// for an empty marker too: an empty needle is found in every haystack, and a
/// caller that had nothing to compare against must not be told "yes".
///
/// Searched in the RAW bytes. `/proc/<pid>/cmdline` separates arguments with
/// NUL, so rendering it to a string first would join two arguments with a
/// space and let a marker match across the boundary between them — and it
/// would also lose a command line that is not valid UTF-8, which is a
/// process this agent should still be able to recognise as not its own.
pub fn process_carries(pid: u32, marker: &str) -> bool {
    let needle = marker.as_bytes();
    if needle.is_empty() {
        return false;
    }
    let Ok(cmdline) = std::fs::read(format!("/proc/{pid}/cmdline")) else {
        return false;
    };
    cmdline.windows(needle.len()).any(|w| w == needle)
}

/// Is there a process at `pid` at all?
///
/// Only ever asked to tell the two halves of a `process_carries` "no" apart —
/// the process is gone, or somebody else holds the number — because those
/// deserve different log lines and one of them is not worth waking anybody
/// for. `/proc` and not `kill(pid, 0)`: this is a question, and a caller that
/// reaches for a signal to ask it is one typo away from sending a real one.
pub fn process_exists(pid: u32) -> bool {
    std::path::Path::new(&format!("/proc/{pid}")).exists()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The test binary is a live process with a known command line, which is
    /// everything this needs to be exercised honestly.
    #[test]
    fn a_live_process_is_recognised_by_what_it_was_started_for() {
        let me = std::process::id();
        let raw = std::fs::read(format!("/proc/{me}/cmdline")).expect("linux");
        let argv0 = String::from_utf8(raw.split(|b| *b == 0).next().expect("argv[0]").to_vec())
            .expect("utf-8 argv[0]");

        assert!(process_carries(me, &argv0));

        // The case the whole module is for: the pid is ALIVE and answers
        // every liveness probe there is, and it is not the process that was
        // written down. A recorded uuid that belongs to a VM this process
        // never was.
        assert!(!process_carries(me, "9f1c7b2e-0000-4000-8000-000000000000"));

        // Nothing to compare against is not a match.
        assert!(!process_carries(me, ""));

        // And a pid that cannot exist. Not `u32::MAX`: as an argument to
        // kill(2) that is -1, and this module's callers are the ones holding
        // the signal.
        assert!(!process_carries(i32::MAX as u32, &argv0));

        // The two halves of a "no", which are the same answer and a different
        // log line.
        assert!(process_exists(me));
        assert!(!process_exists(i32::MAX as u32));
    }
}
