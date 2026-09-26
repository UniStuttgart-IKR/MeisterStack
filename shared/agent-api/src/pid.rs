// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Check recorded process IDs against resource markers in `/proc`.
//!
//! VMM and backend command lines contain a VM or volume UUID in their socket
//! path. Checking this marker reduces the risk of acting on a reused PID; it is
//! a command-line check, not a kernel process handle or an authentication check.

/// Check for a nonempty marker in raw `/proc/<pid>/cmdline` bytes.
/// Raw matching preserves NUL argument boundaries and non-UTF-8 arguments.
/// Missing/unreadable processes and empty markers return false; this is not
/// an atomic process-identity-and-signal operation.
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

/// Check whether a procfs entry exists, distinguishing absence from a
/// process whose command line fails the resource-marker check.
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

        // A live process with no matching resource marker is not the recorded owner.
        assert!(!process_carries(me, "9f1c7b2e-0000-4000-8000-000000000000"));

        // Nothing to compare against is not a match.
        assert!(!process_carries(me, ""));

        // And a pid that cannot exist. Not `u32::MAX`: as an argument to
        // kill(2) that is -1, and this module's callers are the ones holding
        // the signal.
        assert!(!process_carries(i32::MAX as u32, &argv0));

        // Distinguish an existing nonmatching process from an absent PID.
        assert!(process_exists(me));
        assert!(!process_exists(i32::MAX as u32));
    }
}
