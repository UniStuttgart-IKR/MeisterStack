// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Exercise router SNAT, floating-IP translation and standby ARP suppression.
//!
//! Requires isolated network and mount namespaces, `ip`, `nft`, `arping`,
//! `ping`, and the kernel modules listed in `gateway_netns.rs`.
//!
//! ```text
//! unshare -rnm --propagation private sh -c \
//!   'mount -t tmpfs none /run && cargo test -p meister-linux-network-driver \
//!    --test gateway_datapath -- --ignored --nocapture'
//! ```
//!
//! ```text
//! outside -- provider bridge -- router namespace -- overlay bridge -- guest
//! 203.0.113.1                 203.0.113.10 / 10.7.1.1               10.7.1.9
//!                            floating IP: 203.0.113.55
//! ```
//!
//! Both endpoints are network namespaces. The outside route to the floating
//! IP is installed manually; this test does not exercise BGP or a guest VMM.
//! Neighbour caches are flushed before standby checks, so these checks do not
//! establish failover behaviour with cached neighbours.

use std::collections::BTreeMap;

use agent_api::networking::{BridgeDriver, NatKind, NatRule, RouterId, RouterPhase, RouterSpec};
use meister_linux_network_driver::{
    LinuxNetworkDriver, VxlanConfig,
    nftables::NftConfig,
    router::{GatewayConfig, provider_bridge, router_netns},
};

const PHYSNET: &str = "ext";
const UPLINK: &str = "upl0";
const GIVEN_AWAY: &str = "pxlink";
const VNI: u32 = 10_008;

/// The "internet": one namespace on the provider network, holding the address
/// the router's default route points at.
const OUTSIDE: &str = "ms-outside";
const OUTSIDE_ADDR: &str = "203.0.113.1";
/// The tenant's guest that HOLDS the floating address: one namespace on the
/// overlay bridge.
const GUEST: &str = "ms-guest";
const GUEST_ADDR: &str = "10.7.1.9";
/// A second guest of the same tenant, holding nothing. It is what proves the
/// order of the two postrouting rules means something: this one leaves behind
/// the router's own address and the one above leaves as its own.
const PLAIN: &str = "ms-plain";
const PLAIN_ADDR: &str = "10.7.1.20";
const ROUTER_EXTERNAL: &str = "203.0.113.10";
const ROUTER_INTERNAL: &str = "10.7.1.1";
const FLOATING: &str = "203.0.113.55";

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

/// A command inside a namespace, with whether it worked and what it said.
fn tried(netns: &str, args: &[&str]) -> (bool, String) {
    let mut all = vec!["netns", "exec", netns];
    all.extend_from_slice(args);
    run("ip", &all)
}

fn inside(netns: &str, args: &[&str]) -> String {
    let (ok, text) = tried(netns, args);
    assert!(ok, "in {netns}: {} failed: {text}", args.join(" "));
    text
}

/// Run one ping with a one-second timeout and retain its output.
fn ping(from: &str, to: &str) -> (bool, String) {
    let (ok, text) = tried(from, &["ping", "-c", "1", "-W", "1", to]);
    println!(
        "$ ip netns exec {from} ping -c1 -W1 {to}\n{}",
        text.lines()
            .filter(|l| l.contains("bytes from")
                || l.contains("packet loss")
                || l.contains("Unreachable"))
            .collect::<Vec<_>>()
            .join("\n")
    );
    (ok, text)
}

/// Who answers an ARP request for `addr` on `dev`, if anybody does.
fn arping(from: &str, dev: &str, addr: &str) -> bool {
    let (ok, text) = tried(from, &["arping", "-c", "1", "-w", "1", "-I", dev, addr]);
    println!(
        "$ ip netns exec {from} arping -c1 -w1 -I {dev} {addr}\n{}",
        text.lines()
            .filter(|l| l.contains("Unicast reply") || l.contains("Received"))
            .collect::<Vec<_>>()
            .join("\n")
    );
    ok
}

/// Read the counter of the named rule in the router namespace.
fn counter(netns: &str, name: &str) -> u64 {
    let rules = inside(netns, &["nft", "list", "table", "ip", "meister-rt"]);
    let line = rules
        .lines()
        .find(|l| l.contains(&format!("comment \"{name}\"")))
        .unwrap_or_else(|| panic!("no rule named {name} in:\n{rules}"));
    println!("  {}", line.trim());
    let after = line
        .split_once("packets ")
        .unwrap_or_else(|| panic!("no counter on: {line}"))
        .1;
    after
        .split_whitespace()
        .next()
        .and_then(|n| n.parse().ok())
        .unwrap_or_else(|| panic!("no count on: {line}"))
}

/// The connection tracking table of a namespace, one flow per line.
fn conntrack(netns: &str) -> String {
    inside(netns, &["cat", "/proc/net/nf_conntrack"])
}

fn spec(id: RouterId, active: bool) -> RouterSpec {
    RouterSpec {
        id,
        physnet: PHYSNET.into(),
        external_addr: format!("{ROUTER_EXTERNAL}/24"),
        external_gateway: OUTSIDE_ADDR.into(),
        vxlan_id: VNI,
        internal_addr: format!("{ROUTER_INTERNAL}/24"),
        nats: vec![
            NatRule {
                kind: NatKind::Snat,
                external_ip: ROUTER_EXTERNAL.into(),
                logical_ip: String::new(),
            },
            NatRule {
                kind: NatKind::DnatAndSnat,
                external_ip: FLOATING.into(),
                logical_ip: GUEST_ADDR.into(),
            },
        ],
        routed_subnets: Vec::new(),
        active,
    }
}

/// A namespace with one leg in `bridge`, an address and a default route.
fn party(name: &str, host_link: &str, leg: &str, bridge: &str, addr: &str, gateway: &str) {
    ip(&["netns", "add", name]);
    ip(&[
        "link", "add", host_link, "type", "veth", "peer", "name", leg, "netns", name,
    ]);
    ip(&["link", "set", host_link, "master", bridge, "up"]);
    inside(name, &["ip", "link", "set", "lo", "up"]);
    inside(name, &["ip", "link", "set", leg, "up"]);
    inside(name, &["ip", "addr", "add", addr, "dev", leg]);
    inside(name, &["ip", "route", "add", "default", "via", gateway]);
}

#[tokio::test]
#[ignore = "needs its own network and mount namespace; see the module note"]
async fn a_guest_reaches_the_outside_and_the_outside_reaches_it_back() {
    let state = tempfile::Builder::new()
        .prefix("ms-neutron-agent-")
        .tempdir()
        .expect("a state directory");

    ip(&["link", "add", UPLINK, "type", "dummy"]);
    ip(&["link", "set", UPLINK, "up"]);
    ip(&["link", "add", GIVEN_AWAY, "type", "dummy"]);
    ip(&["link", "set", GIVEN_AWAY, "up"]);

    let d = LinuxNetworkDriver::build(
        Some(VxlanConfig {
            uplink: UPLINK.into(),
            mtu: 1450,
            evpn: false,
        }),
        NftConfig {
            binary: "nft".into(),
            guarded: common::net::Ipv4Ranges::default(),
        },
        Some(GatewayConfig {
            physnets: BTreeMap::from([(PHYSNET.to_string(), GIVEN_AWAY.to_string())]),
            ip: "ip".into(),
            arping: "arping".into(),
            state_dir: state.path().to_path_buf(),
        }),
    )
    .expect("the driver comes up");

    // The two bridges this node has before any router exists: the provider
    // network's, and the tenant's overlay.
    let external = d
        .ensure_physnet(PHYSNET, GIVEN_AWAY)
        .await
        .expect("the interface is given away");
    let internal = d.ensure_overlay(VNI).await.expect("the tenant's wire");
    assert_eq!(external, provider_bridge(PHYSNET));

    // The outside, whose default route points back at the router so that a
    // reply to a SNATed packet comes back the way it went.
    ip(&["netns", "add", OUTSIDE]);
    ip(&[
        "link", "add", "outside0", "type", "veth", "peer", "name", "wan", "netns", OUTSIDE,
    ]);
    ip(&["link", "set", "outside0", "master", &external, "up"]);
    inside(OUTSIDE, &["ip", "link", "set", "lo", "up"]);
    inside(OUTSIDE, &["ip", "link", "set", "wan", "up"]);
    inside(
        OUTSIDE,
        &[
            "ip",
            "addr",
            "add",
            &format!("{OUTSIDE_ADDR}/24"),
            "dev",
            "wan",
        ],
    );

    // The two guests: namespaces on the tenant's overlay bridge, with the
    // router as their way out.
    party(
        GUEST,
        "guest0",
        "eth0",
        &internal,
        &format!("{GUEST_ADDR}/24"),
        ROUTER_INTERNAL,
    );
    party(
        PLAIN,
        "plain0",
        "eth0",
        &internal,
        &format!("{PLAIN_ADDR}/24"),
        ROUTER_INTERNAL,
    );

    let id = RouterId::from_u128(0x6b00_00a5);
    let netns = router_netns(&id);

    // --- 1. the standby is silent ----------------------------------------
    println!("\n=== 1. the standby is silent ===");
    let standby = d
        .ensure_router(&spec(id, false))
        .await
        .expect("a standby is fully built");
    assert_eq!(standby.phase, RouterPhase::Ready, "{}", standby.message);
    assert!(standby.announce.is_empty(), "and announces nothing");

    let (reached, said) = ping(GUEST, OUTSIDE_ADDR);
    assert!(
        !reached,
        "a standby must not carry the tenant's traffic: {said}"
    );
    assert!(
        !arping(GUEST, "eth0", ROUTER_INTERNAL),
        "and must not answer for the gateway address on the tenant's wire"
    );
    assert!(
        !arping(OUTSIDE, "wan", FLOATING),
        "nor for the floating address on the provider network"
    );

    // --- 2. promotion is one Ensure --------------------------------------
    println!("\n=== 2. promotion is one Ensure ===");
    let active = d
        .ensure_router(&spec(id, true))
        .await
        .expect("the same router, made active");
    assert!(active.active);
    assert_eq!(
        active.announce,
        [format!("{ROUTER_EXTERNAL}/32"), format!("{FLOATING}/32")],
        "its own address and the floating one it holds"
    );
    assert!(
        arping(GUEST, "eth0", ROUTER_INTERNAL),
        "now it answers for the gateway the tenant is pointed at"
    );

    // --- 3. out, and the order of the two rules is the meaning ------------
    println!("\n=== 3. out, through the router ===");
    // The outside has no tenant route. Replies and rule counters distinguish
    // floating-IP SNAT from the router's default SNAT.
    let (fip_before, snat_before) = (counter(&netns, "fip-out"), counter(&netns, "snat"));
    let (reached, said) = ping(GUEST, OUTSIDE_ADDR);
    assert!(reached, "the guest reaches the outside: {said}");
    assert!(
        counter(&netns, "fip-out") > fip_before,
        "the holder of the floating address leaves as that address"
    );
    assert_eq!(
        counter(&netns, "snat"),
        snat_before,
        "and never behind the router's, or the reservation it holds would do nothing"
    );

    let (reached, said) = ping(PLAIN, OUTSIDE_ADDR);
    assert!(reached, "and so does a guest that holds nothing: {said}");
    assert!(
        counter(&netns, "snat") > snat_before,
        "that one behind the router's own address"
    );

    // --- 3b. ensured again, it keeps its connections -----------------------
    println!("\n=== 3b. ensured again, it keeps its connections ===");
    // IKR-B70: deleting the external address makes the kernel drop every flow masqueraded
    // behind it, so a pass over a router that is right must not take its addresses away.
    let masqueraded = format!("src={PLAIN_ADDR} dst={OUTSIDE_ADDR}");
    assert!(
        conntrack(&netns).contains(&masqueraded),
        "the ping above left a masqueraded flow"
    );
    d.ensure_router(&spec(id, true))
        .await
        .expect("the same router, ensured again");
    assert!(
        conntrack(&netns).contains(&masqueraded),
        "and an ensure that changes nothing keeps it"
    );

    // --- 4. in, through the floating address ------------------------------
    println!("\n=== 4. in, through the floating address ===");
    // The route BGP would have installed; see the module note.
    inside(
        OUTSIDE,
        &[
            "ip",
            "route",
            "add",
            &format!("{FLOATING}/32"),
            "via",
            ROUTER_EXTERNAL,
        ],
    );
    let before = counter(&netns, "fip-in");
    let (reached, said) = ping(OUTSIDE, FLOATING);
    assert!(
        reached,
        "the outside reaches the guest at its floating address: {said}"
    );
    assert!(
        counter(&netns, "fip-in") > before,
        "and it is the dnat half of the 1:1 pair that carried it"
    );

    // --- 5. and back to standby -------------------------------------------
    println!("\n=== 5. and back to standby ===");
    d.ensure_router(&spec(id, false))
        .await
        .expect("standby again");
    // Flush cached neighbours to test standby ARP suppression. This does not
    // exercise failover with existing neighbour entries.
    inside(GUEST, &["ip", "neigh", "flush", "all"]);
    inside(OUTSIDE, &["ip", "neigh", "flush", "all"]);
    assert!(
        !arping(GUEST, "eth0", ROUTER_INTERNAL),
        "silent again on the tenant's wire"
    );
    assert!(
        !arping(OUTSIDE, "wan", FLOATING),
        "and on the provider network"
    );
    let (reached, _) = ping(GUEST, OUTSIDE_ADDR);
    assert!(!reached, "and it carries nothing");

    d.destroy_router(&id).await.expect("the router goes");
    for ns in [OUTSIDE, GUEST, PLAIN] {
        ip(&["netns", "del", ns]);
    }
}
