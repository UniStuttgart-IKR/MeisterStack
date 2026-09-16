// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! The other half of the proof: the same node, with one capability.
//!
//! `unprivileged_ch.rs` shows what an agent with NO rights does. This one
//! shows that the single capability the unit grants by default buys exactly
//! what it is supposed to and nothing else — the taps, the bridges and the
//! nftables tap guard come back, and the CAP_SYS_ADMIN backends stay out.
//!
//! It cannot be run by `cargo test` on its own, because a test process does
//! not get to give itself a capability. It needs a unit, so it is `#[ignore]`
//! and started as one:
//!
//! ```text
//! cargo test -p meister-agent --test unprivileged_caps --no-run
//! sudo systemd-run --system --quiet -P \
//!   -p User=$USER -p AmbientCapabilities=CAP_NET_ADMIN \
//!   -p PrivateNetwork=yes -p PrivateMounts=yes \
//!   --setenv=MEISTER_CH=$PWD/bin/cloud-hypervisor \
//!   ./target/debug/deps/unprivileged_caps-<hash> --ignored --nocapture
//! ```
//!
//! `PrivateNetwork=yes` is not politeness, it is what makes this safe to run
//! on somebody's workstation: building the network driver PROGRAMS nftables
//! (`Nft::new` writes `add table netdev meister`, deliberately, because
//! anything less would prove the binary exists rather than that this process
//! may use it). In a unit with its own network namespace that table dies
//! with the unit, and the host keeps none of it.
//!
//! A system unit and not a user one, for the reason `nix/agent.nix` gives:
//! `user@.service` never carries `cpuset`.

use std::path::PathBuf;

/// Does this process hold CAP_NET_ADMIN — effective or ambient?
fn holds_net_admin() -> bool {
    let status = std::fs::read_to_string("/proc/self/status").expect("/proc/self/status");
    let set = |name: &str| {
        status
            .lines()
            .find_map(|line| line.strip_prefix(name))
            .and_then(|rest| u64::from_str_radix(rest.trim(), 16).ok())
            .unwrap_or(0)
    };
    (set("CapEff:") | set("CapAmb:")) & (1 << 12) != 0
}

/// A node that configures both halves: a network and a storage backend that
/// needs more than this unit was given.
fn config(root: &std::path::Path) -> meister_agent::config::AgentConfig {
    let ch = std::env::var("MEISTER_CH").unwrap_or_else(|_| "/usr/bin/cloud-hypervisor".into());
    let toml = format!(
        r#"node_id = "cap-net-admin-e2e"

[paths]
db_path = "{root}/agent.redb"
run_dir = "{root}/run"
image_dir = "{root}/images"
volume_dir = "{root}/volumes"
cgroup_root = "{root}/cgroup"

[hypervisor.cloud-hypervisor]
binary = "{ch}"
timeout_ms = 10000

[network]
default_bridge = "meister_br0"

[volume.lvm-thin]
vg = "vg-that-is-not-here"
thin_pool = "pool"
"#,
        root = root.display(),
    );
    toml::from_str(&toml).expect("the config parses")
}

#[tokio::test]
#[ignore = "needs a unit with AmbientCapabilities=CAP_NET_ADMIN; see the module note"]
async fn one_capability_buys_the_taps_and_nothing_else() {
    assert!(
        holds_net_admin(),
        "this test has to run with CAP_NET_ADMIN; see the invocation at the top of this file"
    );
    assert_ne!(
        nix::unistd::geteuid().as_raw(),
        0,
        "and it has to run as somebody who is NOT root, or it proves nothing"
    );
    // The binary is there or the hypervisor row is a fatal deficiency, which
    // is a different test's subject.
    let ch = PathBuf::from(
        std::env::var("MEISTER_CH").unwrap_or_else(|_| "/usr/bin/cloud-hypervisor".into()),
    );
    assert!(ch.exists(), "MEISTER_CH names {} — not there", ch.display());

    let temp = tempfile::Builder::new()
        .prefix("ms-cap-net-admin-")
        .tempdir()
        .expect("a directory");
    let root = temp.path().to_path_buf();
    for dir in ["images", "volumes", "run", "cgroup"] {
        std::fs::create_dir_all(root.join(dir)).expect("a directory");
    }
    let cfg = config(&root);

    // First the verdict, then the thing itself.
    let screen = meister_agent::drivers::screen(&cfg, &meister_agent::privileges::Host);
    assert!(
        !screen.skip.contains("linux"),
        "CAP_NET_ADMIN is what a tap, a bridge and the guard need: {:?}",
        screen.gaps
    );
    assert!(
        screen.skip.contains("lvm-thin"),
        "and it is not what device-mapper needs: {:?}",
        screen.gaps
    );
    assert!(screen.fatal.is_none(), "{:?}", screen.fatal);
    for gap in &screen.gaps {
        println!("still missing: {gap}");
    }

    // And the drivers, built for real. The network row going through here is
    // the whole point: `Nft::new` programs a table, so this succeeding is a
    // measurement and not a claim — with CAP_NET_ADMIN the node is exactly
    // what it is as root.
    let drivers = meister_agent::drivers::Drivers::from_config(&cfg)
        .await
        .expect("a node with CAP_NET_ADMIN comes up");
    assert!(
        drivers.networking.is_some() && drivers.bridge.is_some(),
        "the network driver was built, which means nftables was programmed"
    );
    assert!(
        !drivers.storage.contains_key("lvm-thin"),
        "and the backend that needs CAP_SYS_ADMIN was left out"
    );
    assert!(drivers.hypervisor.is_some(), "the hypervisor is there");
    println!(
        "with CAP_NET_ADMIN: taps yes, nftables yes, lvm-thin no — {} storage backend(s)",
        drivers.storage.len()
    );
}
