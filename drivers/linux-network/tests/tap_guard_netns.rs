// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Change the address guard of a tap a guest is using, and check what passes (NL4-1, NL5-2).
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
    /// A second subnet the guest has an address in and keeps sending from.
    other: Subnet,
    /// A third the guest has an address in and is never allowed to send from.
    never: Subnet,
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
    never: Subnet {
        cidr: "10.7.5.0/24",
        host: "10.7.5.1",
        guest: "10.7.5.9",
    },
};
/// A guest with one routed subnet (`taken`, cut from `ROUTED_POOL`) and an address of its own
/// outside every pool (`other`), on a node whose floating pool holds `never`.
const NO_PREFIX_LEFT: Site = Site {
    nic: NicId::from_u128(0x4c40_0003 << 96),
    bridge: "msguard1",
    guest: "ms-guarded1",
    taken: Subnet {
        cidr: "10.7.4.0/24",
        host: "10.7.4.1",
        guest: "10.7.4.9",
    },
    other: Subnet {
        cidr: "10.30.3.0/24",
        host: "10.30.3.1",
        guest: "10.30.3.9",
    },
    never: Subnet {
        cidr: "10.255.6.0/24",
        host: "10.255.6.1",
        guest: "10.255.6.9",
    },
};
/// The floating pool of the node `NO_PREFIX_LEFT` is on.
const FLOATING_POOL: &str = "10.255.0.0/16";
/// The cloud's routed pool `NO_PREFIX_LEFT`'s routed subnet was cut from, which the node guards
/// beside its floating pool.
const ROUTED_POOL: &str = "10.7.0.0/16";
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

/// The comments of the allowlist's rules, IPv4 and ARP.
const SOURCE_RULES: [&str; 2] = ["src-ip", "src-arp"];
/// And of the pool ban's.
const POOL_RULES: [&str; 2] = ["pool-ip", "pool-arp"];

/// The packets the tap's rules commented as one of `rules` dropped so far, together.
fn drops(tap: &str, rules: [&str; 2]) -> u64 {
    let chain = format!("meister-{tap}");
    let (ok, listed) = run("nft", &["list", "chain", "netdev", "meister", &chain]);
    assert!(ok, "no chain {chain}: {listed}");
    listed
        .lines()
        .filter(|l| {
            rules
                .iter()
                .any(|r| l.contains(&format!("comment \"{r}\"")))
        })
        .map(|l| {
            l.split_once("packets ")
                .and_then(|(_, after)| after.split_whitespace().next())
                .and_then(|n| n.parse::<u64>().ok())
                .unwrap_or_else(|| panic!("no counter on: {l}"))
        })
        .sum()
}

fn driver() -> LinuxNetworkDriver {
    driver_guarding(&[])
}

/// A driver on a node whose guarded ranges are `ranges`.
fn driver_guarding(ranges: &[&str]) -> LinuxNetworkDriver {
    let ranges: Vec<String> = ranges.iter().map(|r| r.to_string()).collect();
    LinuxNetworkDriver::build(
        None,
        NftConfig {
            binary: "nft".into(),
            guarded: common::net::Ipv4Ranges::parse(&ranges).expect("guarded ranges"),
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
    }
}

/// The host's bridge with an address in each subnet, and the guest behind `tap` on it.
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
    for subnet in [&site.taken, &site.other, &site.never] {
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
/// updated, the subnet it keeps goes on passing, and a subnet given back passes again; a source
/// it was never given is dropped throughout.
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
    assert!(
        !reaches(&site, &site.never),
        "a source it was never given does not"
    );

    d.update_guard(&nic, &allowing(&site, &[site.other.cidr]))
        .await
        .expect("the guard takes the subnet away");
    let before = drops(&tap, SOURCE_RULES);
    assert!(
        !reaches(&site, &site.taken),
        "a source in the subnet taken away is dropped at the tap"
    );
    assert!(
        drops(&tap, SOURCE_RULES) > before,
        "by the source-address rule, which counted it"
    );
    assert!(
        reaches(&site, &site.other),
        "the kept subnet goes on passing"
    );
    assert!(
        !reaches(&site, &site.never),
        "and a source it was never given stays dropped"
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

/// A re-send that leaves a guest's document no prefix at all puts its tap on the pool ban over
/// the node's guarded ranges, its floating pool and the routed pool: the routed subnet just
/// taken is dropped and counted, as is a pool address that is not the guest's, and a source of
/// its own outside every pool goes on passing, since the document says nothing of its address
/// space. (NL5-2, RR5-1)
#[tokio::test]
#[ignore = "needs its own network and mount namespace; see the module note"]
async fn a_guest_left_no_prefix_is_kept_off_every_pool_and_keeps_its_own_sources() {
    let site = NO_PREFIX_LEFT;
    let d = driver_guarding(&[FLOATING_POOL, ROUTED_POOL]);
    let nic = site.nic;
    let tap = LinuxNetworkDriver::tap_name(&nic);
    host_and_guest(&site, &tap);
    d.create(&nic, &allowing(&site, &[site.taken.cidr]))
        .await
        .expect("the guest's link is on the bridge and guarded");
    assert!(
        reaches(&site, &site.taken),
        "its routed subnet passes at first"
    );

    // The re-send after its last routed subnet went names no prefix.
    d.update_guard(&nic, &allowing(&site, &[]))
        .await
        .expect("the guard follows the document");
    let before = drops(&tap, POOL_RULES);
    assert!(
        !reaches(&site, &site.taken),
        "a source in the routed subnet taken away is dropped at the tap"
    );
    assert!(
        drops(&tap, POOL_RULES) > before,
        "by the pool rule, since the subnet was cut from a pool the node guards"
    );
    let before = drops(&tap, POOL_RULES);
    assert!(
        !reaches(&site, &site.never),
        "a pool address that is not the guest's is dropped at the tap"
    );
    assert!(
        drops(&tap, POOL_RULES) > before,
        "by the pool rule, which counted it"
    );
    assert!(
        reaches(&site, &site.other),
        "an address of its own outside every pool goes on passing"
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
