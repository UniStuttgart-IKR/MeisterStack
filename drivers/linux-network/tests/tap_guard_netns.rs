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

/// One guest on a bridge of its own, with addresses of its own, so the tests of this file can
/// run side by side without two bridges of the host claiming the same subnet.
struct Site {
    /// The guest's NIC. The driver names its tap after the leading eight hex digits of the id,
    /// so those differ from site to site.
    nic: NicId,
    bridge: &'static str,
    guest: &'static str,
    /// The subnet a test takes from the guest.
    taken: Subnet,
    /// A second subnet the guest has an address in: kept throughout, or never given.
    other: Subnet,
}

/// A subnet, with the host's and the guest's address in it.
struct Subnet {
    cidr: &'static str,
    host: &'static str,
    guest: &'static str,
}

const ONE_OF_TWO_TAKEN: Site = Site {
    nic: NicId::from_u128(0x4c40_0001 << 96),
    bridge: "msguard0",
    guest: "ms-guarded",
    taken: Subnet {
        cidr: "10.7.2.0/24",
        host: "10.7.2.1",
        guest: "10.7.2.9",
    },
    other: Subnet {
        cidr: "10.7.1.0/24",
        host: "10.7.1.1",
        guest: "10.7.1.9",
    },
};
const LAST_TAKEN: Site = Site {
    nic: NicId::from_u128(0x4c40_0003 << 96),
    bridge: "msguard1",
    guest: "ms-guarded1",
    taken: Subnet {
        cidr: "10.7.4.0/24",
        host: "10.7.4.1",
        guest: "10.7.4.9",
    },
    other: Subnet {
        cidr: "10.7.3.0/24",
        host: "10.7.3.1",
        guest: "10.7.3.9",
    },
};
const GUEST_MAC: &str = "52:54:00:00:4c:01";

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

/// Whether one ping from the guest's address in `subnet` reaches the host's address in it.
fn reaches(site: &Site, subnet: &Subnet) -> bool {
    run(
        "ip",
        &[
            "netns",
            "exec",
            site.guest,
            "ping",
            "-c",
            "1",
            "-W",
            "1",
            "-I",
            subnet.guest,
            subnet.host,
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
fn allowing(site: &Site, subnets: &[&str]) -> NicSpec {
    NicSpec {
        bridge: site.bridge.into(),
        mac: GUEST_MAC.parse().expect("a mac"),
        vxlan_id: None,
        physnet: None,
        floating_ips: Vec::new(),
        routed_subnets: subnets.iter().map(|s| s.to_string()).collect(),
        address_space_known: false,
    }
}

/// The guest's NIC as the agent readdresses it when a re-send takes its last subnet away.
fn no_subnet_left(site: &Site) -> NicSpec {
    NicSpec {
        address_space_known: true,
        ..allowing(site, &[])
    }
}

/// The host's bridge with an address in both subnets, and the guest behind `tap` on it.
fn host_and_guest(site: &Site, tap: &str) {
    ip(&["link", "add", site.bridge, "type", "bridge"]);
    ip(&["link", "set", site.bridge, "up"]);
    ip(&["netns", "add", site.guest]);
    ip(&[
        "link", "add", tap, "type", "veth", "peer", "name", "eth0", "netns", site.guest,
    ]);
    inside(site.guest, &["ip", "link", "set", "lo", "up"]);
    inside(
        site.guest,
        &["ip", "link", "set", "eth0", "address", GUEST_MAC],
    );
    inside(site.guest, &["ip", "link", "set", "eth0", "up"]);
    for subnet in [&site.taken, &site.other] {
        let prefix = subnet.cidr.split_once('/').expect("a prefix").1;
        ip(&[
            "addr",
            "add",
            &format!("{}/{prefix}", subnet.host),
            "dev",
            site.bridge,
        ]);
        inside(
            site.guest,
            &[
                "ip",
                "addr",
                "add",
                &format!("{}/{prefix}", subnet.guest),
                "dev",
                "eth0",
            ],
        );
    }
}

/// The guest's link, its namespace and the host's bridge, gone.
async fn take_down(site: &Site, d: &LinuxNetworkDriver, nic: &NicId) {
    NicDriver::destroy(d, nic).await.expect("the link goes");
    ip(&["netns", "del", site.guest]);
    ip(&["link", "del", site.bridge]);
}

/// A subnet taken from a running guest is dropped at its tap from the moment the guard is
/// updated, the subnet it keeps goes on passing, and a subnet given back passes again.
#[tokio::test]
#[ignore = "needs its own network and mount namespace; see the module note"]
async fn a_subnet_taken_from_a_running_tap_is_dropped_and_one_given_back_passes() {
    let site = ONE_OF_TWO_TAKEN;
    let d = driver();
    let nic = site.nic;
    let tap = LinuxNetworkDriver::tap_name(&nic);
    host_and_guest(&site, &tap);
    d.create(&nic, &allowing(&site, &[site.other.cidr, site.taken.cidr]))
        .await
        .expect("the guest's link is on the bridge and guarded");
    assert!(
        reaches(&site, &site.other),
        "the kept subnet passes at first"
    );
    assert!(reaches(&site, &site.taken), "and so does the other");

    d.update_guard(&nic, &allowing(&site, &[site.other.cidr]))
        .await
        .expect("the guard takes the subnet away");
    let before = source_drops(&tap);
    assert!(
        !reaches(&site, &site.taken),
        "a source in the subnet taken away is dropped at the tap"
    );
    assert!(
        source_drops(&tap) > before,
        "by the source-address rule, which counted it"
    );
    assert!(
        reaches(&site, &site.other),
        "the kept subnet goes on passing"
    );

    d.update_guard(&nic, &allowing(&site, &[site.other.cidr, site.taken.cidr]))
        .await
        .expect("the guard gives the subnet back");
    assert!(
        reaches(&site, &site.taken),
        "a source in the subnet given back passes again"
    );

    take_down(&site, &d, &nic).await;
}

/// The last subnet taken from a running guest is dropped at its tap like any other: the guard
/// stays an allowlist, now of no subnet, and does not fall back to the pool ban, which on a
/// node without a floating pool lets every source through. (NL4-1)
#[tokio::test]
#[ignore = "needs its own network and mount namespace; see the module note"]
async fn the_last_subnet_taken_from_a_running_tap_is_dropped_and_the_guard_stays_closed() {
    let site = LAST_TAKEN;
    let d = driver();
    let nic = site.nic;
    let tap = LinuxNetworkDriver::tap_name(&nic);
    host_and_guest(&site, &tap);
    d.create(&nic, &allowing(&site, &[site.taken.cidr]))
        .await
        .expect("the guest's link is on the bridge and guarded");
    assert!(
        reaches(&site, &site.taken),
        "its one subnet passes at first"
    );

    d.update_guard(&nic, &no_subnet_left(&site))
        .await
        .expect("the guard takes the last subnet away");
    let before = source_drops(&tap);
    assert!(
        !reaches(&site, &site.taken),
        "a source in the last subnet taken away is dropped at the tap"
    );
    assert!(
        source_drops(&tap) > before,
        "by the source-address rule, which counted it"
    );
    assert!(
        !reaches(&site, &site.other),
        "and so is a source the guest was never given: the guard did not open"
    );

    take_down(&site, &d, &nic).await;
}

/// A NIC with no tap on the host is named as gone, not reported as a failed nft script.
#[tokio::test]
#[ignore = "needs its own network and mount namespace; see the module note"]
async fn updating_the_guard_of_a_nic_without_a_tap_says_the_nic_is_gone() {
    let nic = NicId::from_u128(0x4c40_0002 << 96);
    let refused = driver()
        .update_guard(
            &nic,
            &allowing(&ONE_OF_TWO_TAKEN, &[ONE_OF_TWO_TAKEN.other.cidr]),
        )
        .await
        .expect_err("there is no tap to guard");
    assert!(
        matches!(refused, NetworkError::NicNotFound(id) if id == nic),
        "{refused}"
    );
}
