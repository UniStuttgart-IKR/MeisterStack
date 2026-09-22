// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! There is one way this tool connects to a host, and this test is what
//! keeps it one.
//!
//! `transport.rs` can be reviewed once; a second call site that builds its
//! own ssh options cannot be reviewed at all, because nobody will look for
//! it. The pre-v1 tool had three ways — `accept-new`, `no` plus
//! `UserKnownHostsFile=/dev/null`, and `nixos-rebuild` with no options —
//! and the one that changed machines was the one with no options. So the
//! source is read: outside `legacy/`, the three spellings that turn host
//! key verification off do not appear, and the one that turns it on appears
//! in exactly one file.
//!
//! A source-reading test is blunt. It is chosen for the same reason
//! `no_direct_effects.rs` is: the alternative is a promise in a comment.

use std::path::{Path, PathBuf};

/// The pre-v1 wing. It keeps its options until L3 retires it, and it is the
/// only place they may be.
const EXEMPT: &[&str] = &["legacy"];

/// What must not be in new code, and why each one is a refusal rather than a
/// preference.
const FORBIDDEN: &[(&str, &str)] = &[
    (
        "StrictHostKeyChecking=accept-new",
        "trust on first use is trust in whoever answers first; enrol the host instead",
    ),
    (
        "StrictHostKeyChecking=no",
        "this accepts any key at all, including a new one on a known host",
    ),
    (
        "UserKnownHostsFile=/dev/null",
        "a fleet's trust is the known_hosts file in its repository",
    ),
    (
        "-o StrictHostKeyChecking",
        "the options are separate arguments; see transport::Ssh::opts",
    ),
];

#[test]
fn nothing_outside_the_old_wing_turns_host_key_checking_off() {
    let src = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut checked = 0usize;
    let mut found = Vec::new();

    for file in rust_files(&src) {
        let relative = file
            .strip_prefix(&src)
            .expect("walked from src")
            .to_string_lossy()
            .into_owned();
        if EXEMPT.iter().any(|e| relative.starts_with(e)) {
            continue;
        }
        checked += 1;
        let text = std::fs::read_to_string(&file).expect("the file we just walked to");
        for (line_no, line) in text.lines().enumerate() {
            // A comment is not a call site. `transport.rs` explains what the
            // pre-v1 tool did and why it does not do it, and a rule that
            // forbade naming the thing would only make the explanation
            // disappear. A line of CODE that mentions one is still caught:
            // only a line that begins as a comment is skipped, so
            // `.arg("StrictHostKeyChecking=no") // why` is not.
            if line.trim_start().starts_with("//") {
                continue;
            }
            for (needle, why) in FORBIDDEN {
                if line.contains(needle) {
                    found.push(format!(
                        "{relative}:{}: `{needle}` — {why}\n    {}",
                        line_no + 1,
                        line.trim()
                    ));
                }
            }
        }
    }

    assert!(
        checked > 0,
        "this test scanned no file, so it proves nothing"
    );
    assert!(
        found.is_empty(),
        "{} place(s) outside legacy/ weaken host key verification:\n{}",
        found.len(),
        found.join("\n")
    );
}

#[test]
fn the_one_place_that_sets_it_sets_it_to_yes() {
    let src = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut setters = Vec::new();
    for file in rust_files(&src) {
        let relative = file
            .strip_prefix(&src)
            .expect("walked from src")
            .to_string_lossy()
            .into_owned();
        if EXEMPT.iter().any(|e| relative.starts_with(e)) {
            continue;
        }
        let text = std::fs::read_to_string(&file).expect("the file we just walked to");
        // The string as it is BUILT, not as it is mentioned in prose: a
        // module comment explaining the decision is not a second call site.
        if text.contains("\"StrictHostKeyChecking=yes\".to_string()") {
            setters.push(relative);
        }
    }
    assert_eq!(
        setters,
        vec!["transport.rs".to_string()],
        "exactly one file builds the ssh options"
    );
}

fn rust_files(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(next) = stack.pop() {
        for entry in std::fs::read_dir(&next).expect("src is readable") {
            let path = entry.expect("a directory entry").path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().is_some_and(|e| e == "rs") {
                out.push(path);
            }
        }
    }
    out.sort();
    out
}
