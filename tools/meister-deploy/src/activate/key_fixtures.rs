// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! The identity key files of one rotation, as the unit tests and the crash
//! tests of `keys` lay them out.

use super::DEFAULT_PKI_DIR;
use crate::effects::MemFiles;

/// The identity files named by suffix, each holding the pair it belongs
/// to: `("crt.prev", "old")` is `identity.crt.prev` with `old crt`.
pub(super) fn key_layout(there: &[(&str, &str)]) -> MemFiles {
    there.iter().fold(MemFiles::new(), |files, (name, pair)| {
        let what = name.split('.').next().unwrap_or(name);
        let path = format!("{DEFAULT_PKI_DIR}/identity.{name}");
        files.given(path, format!("{pair} {what}\n"))
    })
}

/// A rotation with a prepared pair, ready to switch.
pub(super) fn rotating() -> MemFiles {
    key_layout(&[
        ("key", "old"),
        ("crt", "old"),
        ("key.next", "new"),
        ("crt.next", "new"),
    ])
}
