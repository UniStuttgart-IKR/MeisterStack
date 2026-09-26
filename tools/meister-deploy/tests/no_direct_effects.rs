// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Source-string guard for process, filesystem and clock operations outside
//! the designated effect modules. This is a bounded spelling check, not a
//! complete static proof that all effects pass through policy admission.

use std::path::{Path, PathBuf};

/// The doors.
const EXEMPT: &[&str] = &["effects.rs", "run.rs"];

/// Forbidden direct-effect spellings and suggested interfaces. ExitCode and
/// process IDs are allowed because they do not spawn subprocesses.
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
            // Allow explicitly annotated exceptions to the source-string check.
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
