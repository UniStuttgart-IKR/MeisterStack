// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Nix is the single derivation (D2), and this is how that stays true.
//!
//! The pre-v1 tool derived a fleet twice — ten rules in `fleet.rs`, twelve in
//! `nix/fleet.nix` — and kept them in step with a shell script that nobody
//! ran in CI, because there is no CI. The failure mode was not that the two
//! disagreed loudly; it was that they disagreed about one host, once.
//!
//! So `inventory.rs` reads the file and applies precedence, and that is all.
//! The moment somebody writes a port, an environment variable name or a peer
//! list into it, the second derivation is back. A test cannot prove the
//! absence of a derivation, but it can name the shapes the old one had and
//! refuse them, which is enough to make the next person stop and think.

use std::path::PathBuf;

/// What a deployment value looks like when it is being derived rather than
/// read. Every one of these was in the old `fleet.rs`.
const FORBIDDEN: &[(&str, &str)] = &[
    ("MEISTER_", "an environment variable is a rendered setting, and Nix renders"),
    (":50051", "a port is a setting, and settings come from the manifest"),
    (":3000", "a port is a setting, and settings come from the manifest"),
    (":50050", "a port is a setting, and settings come from the manifest"),
    (":2379", "an etcd endpoint is derived by Nix from the group"),
    (":2380", "an etcd peer url is derived by Nix from the group"),
    ("controller_addrs", "an agent's controllers are derived by Nix"),
    ("cloud_addrs", "a cluster's clouds are derived by Nix"),
    ("advertise", "an advertised address is derived by Nix"),
    ("initial_cluster", "a raft peer set is derived by Nix"),
    ("bootstrap_token", "a token is never derived from a plan file"),
];

#[test]
fn the_inventory_reader_derives_no_deployment_value() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/inventory.rs");
    let text = std::fs::read_to_string(&path).expect("src/inventory.rs is part of this crate");
    assert!(
        text.len() > 1_000,
        "this test read {} bytes and would pass on an empty file",
        text.len()
    );

    let mut found = Vec::new();
    for (line_no, line) in text.lines().enumerate() {
        for (needle, why) in FORBIDDEN {
            if line.contains(needle) {
                found.push(format!(
                    "src/inventory.rs:{}: `{needle}` — {why}\n    {}",
                    line_no + 1,
                    line.trim()
                ));
            }
        }
    }
    assert!(
        found.is_empty(),
        "{} place(s) look like a second derivation:\n{}",
        found.len(),
        found.join("\n")
    );
}
