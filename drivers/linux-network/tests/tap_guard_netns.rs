// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Change the address guard of a tap a guest is using, and check what passes (NL4-1).
//!
//! Requires `ip`, `nft`, `ping`, and isolated network and mount namespaces:
//!
//! ```text
//! unshare -rnm --propagation private sh -c \
//!   'mount -t tmpfs none /run && mkdir -p /run/netns && \
//!    cargo test -p meister-linux-network-driver \
//!    --test tap_guard_netns -- --ignored --nocapture'
//! ```
//!
//! Load `veth` and `bridge` on the host first; a user namespace cannot autoload kernel
//! modules. The guest is a network namespace on the far end of a veth that carries the name
//! the driver gives the NIC's tap: the guard hooks the host end's ingress, which is where a
//! guest's frames arrive on a real tap too.

use agent_api::networking::{NetworkError, NicDriver, NicId, NicSpec};
use meister_linux_network_driver::{LinuxNetworkDriver, nftables::NftConfig};

const BRIDGE: &str = "msguard0";
const GUEST: &str = "ms-guarded";
const GUEST_MAC: &str = "52:54:00:00:4c:01";
/// The subnet the guest keeps throughout, with the host's and the guest's address in it.
const KEPT: (&str, &str, &str) = ("10.7.1.0/24", "10.7.1.1", "10.7.1.9");
/// The subnet taken from the guest and given back.
const TAKEN: (&str, &str, &str) = ("10.7.2.0/24", "10.7.2.1", "10.7.2.9");

fn run(program: &str, args: &[&str]) -> (bool, String) {
    let out = std::process::Command::new(program)
        .args(args)
        .output()
        .unwrap_or_else(|e| panic!("running {program} {}: {e}", args.join(" ")));
    let mut text = String::from_utf8_lossy(&out.stdout).into_owned();
    text.push_str(&String::from_utf8_lossy(&out.stderr));
    (out.status.success(), text)
}

fn ip(args: &[&str]) -> String {
    let (ok, text) = run("ip", args);
    assert!(ok, "ip {} failed: {text}", args.join(" "));
    text
}

fn inside(netns: &str, args: &[&str]) -> String {
    let mut all = vec!["netns", "exec", netns];
    all.extend_from_slice(args);
    ip(&all)
}

/// Whether one ping from the guest's address `from` reaches the host's address `to`.
fn reaches(from: &str, to: &str) -> bool {
    run(
        "ip",
        &[
            "netns", "exec", GUEST, "ping", "-c", "1", "-W", "1", "-I", from, to,
        ],
    )
    .0
}

/// The packets the tap's source-address rules dropped so far, IPv4 and ARP together.
fn source_drops(tap: &str) -> u64 {
    let chain = format!("meister-{tap}");
    let (ok, rules) = run("nft", &["list", "chain", "netdev", "meister", &chain]);
    assert!(ok, "no chain {chain}: {rules}");
    rules
        .lines()
        .filter(|l| l.contains("comment \"src-ip\"") || l.contains("comment \"src-arp\""))
        .map(|l| {
            l.split_once("packets ")
                .and_then(|(_, after)| after.split_whitespace().next())
                .and_then(|n| n.parse::<u64>().ok())
                .unwrap_or_else(|| panic!("no counter on: {l}"))
        })
        .sum()
}

fn driver() -> LinuxNetworkDriver {
    LinuxNetworkDriver::build(
        None,
        NftConfig {
            binary: "nft".into(),
            guarded: common::net::Ipv4Ranges::default(),
        },
        None,
    )
    .expect("the driver comes up in this namespace")
}

/// The guest's NIC, allowed to send from `subnets`.
fn allowing(subnets: &[&str]) -> NicSpec {
    NicSpec {
        bridge: BRIDGE.into(),
        mac: GUEST_MAC.parse().expect("a mac"),
        vxlan_id: None,
        physnet: None,
        floating_ips: Vec::new(),
        routed_subnets: subnets.iter().map(|s| s.to_string()).collect(),
    }
}

/// The host's bridge with an address in both subnets, and the guest behind `tap` on it.
fn host_and_guest(tap: &str) {
    ip(&["link", "add", BRIDGE, "type", "bridge"]);
    ip(&["link", "set", BRIDGE, "up"]);
    for (subnet, host, _) in [KEPT, TAKEN] {
        let prefix = subnet.split_once('/').expect("a prefix").1;
        ip(&["addr", "add", &format!("{host}/{prefix}"), "dev", BRIDGE]);
    }
    ip(&["netns", "add", GUEST]);
    ip(&[
        "link", "add", tap, "type", "veth", "peer", "name", "eth0", "netns", GUEST,
    ]);
    inside(GUEST, &["ip", "link", "set", "lo", "up"]);
    inside(GUEST, &["ip", "link", "set", "eth0", "address", GUEST_MAC]);
    inside(GUEST, &["ip", "link", "set", "eth0", "up"]);
    for (subnet, _, guest) in [KEPT, TAKEN] {
        let prefix = subnet.split_once('/').expect("a prefix").1;
        inside(
            GUEST,
            &[
                "ip",
                "addr",
                "add",
                &format!("{guest}/{prefix}"),
                "dev",
                "eth0",
            ],
        );
    }
}

/// A subnet taken from a running guest is dropped at its tap from the moment the guard is
/// updated, the subnet it keeps goes on passing, and a subnet given back passes again.
#[tokio::test]
#[ignore = "needs its own network and mount namespace; see the module note"]
async fn a_subnet_taken_from_a_running_tap_is_dropped_and_one_given_back_passes() {
    let d = driver();
    let nic = NicId::from_u128(0x4c4_0001);
    let tap = LinuxNetworkDriver::tap_name(&nic);
    host_and_guest(&tap);
    d.create(&nic, &allowing(&[KEPT.0, TAKEN.0]))
        .await
        .expect("the guest's link is on the bridge and guarded");
    assert!(reaches(KEPT.2, KEPT.1), "the kept subnet passes at first");
    assert!(reaches(TAKEN.2, TAKEN.1), "and so does the other");

    d.update_guard(&nic, &allowing(&[KEPT.0]))
        .await
        .expect("the guard takes the subnet away");
    let before = source_drops(&tap);
    assert!(
        !reaches(TAKEN.2, TAKEN.1),
        "a source in the subnet taken away is dropped at the tap"
    );
    assert!(
        source_drops(&tap) > before,
        "by the source-address rule, which counted it"
    );
    assert!(reaches(KEPT.2, KEPT.1), "the kept subnet goes on passing");

    d.update_guard(&nic, &allowing(&[KEPT.0, TAKEN.0]))
        .await
        .expect("the guard gives the subnet back");
    assert!(
        reaches(TAKEN.2, TAKEN.1),
        "a source in the subnet given back passes again"
    );

    NicDriver::destroy(&d, &nic).await.expect("the link goes");
    ip(&["netns", "del", GUEST]);
    ip(&["link", "del", BRIDGE]);
}

/// A NIC with no tap on the host is named as gone, not reported as a failed nft script.
#[tokio::test]
#[ignore = "needs its own network and mount namespace; see the module note"]
async fn updating_the_guard_of_a_nic_without_a_tap_says_the_nic_is_gone() {
    let nic = NicId::from_u128(0x4c4_0002);
    let refused = driver()
        .update_guard(&nic, &allowing(&[KEPT.0]))
        .await
        .expect_err("there is no tap to guard");
    assert!(
        matches!(refused, NetworkError::NicNotFound(id) if id == nic),
        "{refused}"
    );
}
