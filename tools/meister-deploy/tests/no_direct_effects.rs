// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! The two doors are only doors if nobody walks past them.
//!
//! `--dry-run writes nothing` and `--offline touches no network` are claims
//! about EVERY path through this binary, and a unit test can only ever pin
//! the paths it calls. So this test reads the source instead: new code spawns
//! no process of its own, opens no file of its own, and asks no clock of its
//! own. Two files are exempt, because they are the doors themselves.
//! `legacy/` was exempt as well until M5B removed it; the exemption went
//! with the directory.
//!
//! A source-reading test is a blunt instrument, and it is chosen on purpose:
//! the alternative is a promise in a comment.

use std::path::{Path, PathBuf};

/// The doors.
const EXEMPT: &[&str] = &["effects.rs", "run.rs"];

/// What new code must not say, and what to say instead.
///
/// `std::process::ExitCode` and `std::process::id` are deliberately NOT here:
/// neither reaches outside this process — one is how a binary returns its
/// verdict, the other names the process itself — and forbidding the whole
/// `std::process::` path would only teach people to write `use std::process`
/// on its own line. What is forbidden is spawning.
const FORBIDDEN: &[(&str, &str)] = &[
    ("std::fs::", "use the Files trait from effects.rs"),
    ("use std::fs;", "use the Files trait from effects.rs"),
    ("File::open", "use the Files trait from effects.rs"),
    ("File::create", "use the Files trait from effects.rs"),
    ("OpenOptions", "use the Files trait from effects.rs"),
    ("std::process::Command", "use the Runner trait from run.rs"),
    ("process::Command", "use the Runner trait from run.rs"),
    ("Command::new", "use the Runner trait from run.rs"),
    ("thread::sleep", "use the Clock trait from effects.rs"),
    ("SystemTime::now", "use the Clock trait from effects.rs"),
    ("Utc::now", "use the Clock trait from effects.rs"),
    ("Local::now", "use the Clock trait from effects.rs"),
];

#[test]
fn new_code_goes_through_the_two_doors() {
    let src = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut checked = Vec::new();
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
        checked.push(relative.clone());
        let text = std::fs::read_to_string(&file).expect("the file we just walked to");
        for (line_no, line) in text.lines().enumerate() {
            // A rule needs a way to be discussed rather than worked around:
            // a line that says why it is an exception is one somebody read.
            if line.contains("no-direct-effects: ok") {
                continue;
            }
            for (needle, instead) in FORBIDDEN {
                if line.contains(needle) {
                    found.push(format!(
                        "{relative}:{}: `{needle}` — {instead}\n    {}",
                        line_no + 1,
                        line.trim()
                    ));
                }
            }
        }
    }

    assert!(
        !checked.is_empty(),
        "this test scanned no file at all, which means it proves nothing"
    );
    assert!(
        found.is_empty(),
        "{} place(s) in new code reach past the two doors:\n{}",
        found.len(),
        found.join("\n")
    );
}

#[test]
fn the_exemptions_are_the_ones_that_were_meant() {
    let src = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
    // If `effects.rs` or `run.rs` were ever renamed, the list above would
    // silently exempt nothing and the test would go green for the wrong
    // reason — or exempt a file that no longer exists and hide a new one.
    for exempt in EXEMPT {
        assert!(
            src.join(exempt).exists(),
            "{exempt} is exempted but does not exist"
        );
    }
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
