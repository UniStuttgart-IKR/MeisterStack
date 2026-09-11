// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! The gateway slot against a real kernel: namespaces, veth pairs, addresses,
//! routes and nftables, built by the driver and read back off the links.
//!
//! `#[ignore]` for the reason the etcd tests carry it: it needs something the
//! workspace cannot provide. Here that is a network namespace of its own to
//! build in, a private mount namespace so that `ip netns` may pin namespaces
//! under `/var/run/netns`, and `nft`, `ip` and `sysctl` on PATH. Run it with
//!
//! ```text
//! unshare -rnm --propagation private sh -c \
//!   'mount -t tmpfs none /run && mkdir -p /run/netns && \
//!    cargo test -p meister-linux-network-driver \
//!    --test gateway_netns -- --ignored --nocapture'
//! ```
//!
//! `-r` maps the caller to root, `-n` gives the test its own network stack —
//! so the links it creates are nobody else's — and `-m` plus the tmpfs is what
//! makes `/var/run/netns` a directory this user may write to. The `mkdir` is
//! part of the recipe and not an afterthought: a fresh tmpfs over `/run` has
//! no `netns` directory, and `ip netns` does not make one for a file somebody
//! else writes — without it the test dies planting its dead namespace, four
//! assertions before anything interesting. Nothing outside that namespace is
//! touched, and everything in it goes away when it exits.
//!
//! One thing has to be true OUTSIDE the namespace: `dummy`, `veth`, `vxlan`,
//! `nft_ct`, `nft_nat` and `nft_masq` have to be loaded already. A process in a user
//! namespace may not autoload a kernel module, and the failure reads as
//! "Unknown device type" or as nft refusing a rule with "No such file or
//! directory". On a node this does not arise — the agent is real root and the
//! kernel autoloads what the first router asks for, exactly as it does for
//! the tap guard's `netdev` table today.
//!
//! What it proves is the half of N-A3 that no rendering test can: that the
//! things this driver claims to build are actually there afterwards, and that
//! the same call twice is one router.

use std::collections::BTreeMap;

use agent_api::networking::{BridgeDriver, NatKind, NatRule, RouterId, RouterPhase, RouterSpec};
use meister_linux_network_driver::{
    LinuxNetworkDriver, VxlanConfig,
    nftables::NftConfig,
    router::{GatewayConfig, provider_bridge, router_netns, veth_external, veth_internal},
};

const PHYSNET: &str = "ext";
const UPLINK: &str = "upl0";
const GIVEN_AWAY: &str = "pxlink";
const VNI: u32 = 10_007;

fn ip(args: &[&str]) -> String {
    let out = std::process::Command::new("ip")
        .args(args)
        .output()
        .unwrap_or_else(|e| panic!("running ip {}: {e}", args.join(" ")));
    assert!(
        out.status.success(),
        "ip {} failed: {}",
        args.join(" "),
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn maybe_ip(args: &[&str]) -> bool {
    std::process::Command::new("ip")
        .args(args)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn link_exists(name: &str) -> bool {
    maybe_ip(&["link", "show", name])
}

fn netns_exists(name: &str) -> bool {
    ip(&["netns", "list"])
        .lines()
        .filter_map(|l| l.split_whitespace().next())
        .any(|n| n == name)
}

fn in_netns(netns: &str, args: &[&str]) -> String {
    let mut all = vec!["netns", "exec", netns];
    all.extend_from_slice(args);
    let out = std::process::Command::new("ip")
        .args(&all)
        .output()
        .unwrap_or_else(|e| panic!("running ip {}: {e}", all.join(" ")));
    assert!(
        out.status.success(),
        "ip {} failed: {}",
        all.join(" "),
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn sysctl(netns: &str, key: &str) -> String {
    in_netns(netns, &["sysctl", "-n", key]).trim().to_string()
}

fn spec(id: RouterId, active: bool) -> RouterSpec {
    RouterSpec {
        id,
        physnet: PHYSNET.into(),
        external_addr: "203.0.113.10/24".into(),
        external_gateway: "203.0.113.1".into(),
        vxlan_id: VNI,
        internal_addr: "10.7.1.1/24".into(),
        nats: vec![
            NatRule {
                kind: NatKind::Snat,
                external_ip: "203.0.113.10".into(),
                logical_ip: String::new(),
            },
            NatRule {
                kind: NatKind::DnatAndSnat,
                external_ip: "203.0.113.55".into(),
                logical_ip: "10.7.1.9".into(),
            },
        ],
        routed_subnets: vec!["10.7.2.0/24".into()],
        active,
    }
}

fn driver(state_dir: &std::path::Path) -> LinuxNetworkDriver {
    LinuxNetworkDriver::build(
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
            state_dir: state_dir.to_path_buf(),
        }),
    )
    .expect("the driver comes up in this namespace")
}

#[tokio::test]
#[ignore = "needs its own network and mount namespace; see the module note"]
async fn a_router_is_built_and_taken_down_again() {
    let state = tempfile::Builder::new()
        .prefix("ms-neutron-agent-")
        .tempdir()
        .expect("a state directory");
    let dir = state.path().to_path_buf();
    // The uplink the overlay encapsulates over, and the interface this node
    // gives away. Both dummies: nothing has to carry a frame for the driver
    // to build the shape being asserted.
    ip(&["link", "add", UPLINK, "type", "dummy"]);
    ip(&["link", "set", UPLINK, "up"]);
    ip(&["link", "add", GIVEN_AWAY, "type", "dummy"]);
    // Jumbo, because that is the case the veth default gets wrong: the
    // operator's wire takes 9000 and every port this driver hangs into the
    // same bridge has to be told so, or the bridge falls to the smallest one.
    ip(&["link", "set", GIVEN_AWAY, "mtu", "9000"]);
    ip(&["link", "set", GIVEN_AWAY, "up"]);

    let d = driver(&dir);

    // --- the provider network -------------------------------------------
    let bridge = d
        .ensure_physnet(PHYSNET, GIVEN_AWAY)
        .await
        .expect("an interface with no address is one that was given away");
    assert_eq!(bridge, provider_bridge(PHYSNET));
    assert!(link_exists(&bridge));
    assert!(
        ip(&["-o", "link", "show", GIVEN_AWAY]).contains(&format!("master {bridge}")),
        "the interface is the bridge's now"
    );
    assert_eq!(d.physnets(), [PHYSNET]);

    // Festlegung 1, the half that is a refusal: an address on the interface
    // means somebody is still using it.
    ip(&["addr", "add", "192.0.2.1/24", "dev", GIVEN_AWAY]);
    let err = d
        .ensure_physnet(PHYSNET, GIVEN_AWAY)
        .await
        .expect_err("this interface has not been given away")
        .to_string();
    assert!(err.contains("192.0.2.1/24"), "{err}");
    assert!(err.contains("no address on the host"), "{err}");
    ip(&["addr", "del", "192.0.2.1/24", "dev", GIVEN_AWAY]);

    // --- the router ------------------------------------------------------
    let id = RouterId::from_u128(0x6b00_0001);
    let netns = router_netns(&id);

    // A corpse wearing the name, first: a zero-byte file under /run/netns is
    // what is left when the bind mount goes and the file does not, and
    // everything then behaves as if the namespace existed — `add` says the
    // name is taken, `exec` says "Invalid argument", and without
    // `clear_dead_netns` the router is Failed on this machine for ever. The
    // lab produced one of these on 2026-09-10 and could not get rid of it.
    std::fs::write(format!("/var/run/netns/{netns}"), b"").expect("plant a dead namespace");
    assert!(
        netns_exists(&netns),
        "the corpse is listed like a namespace"
    );

    let state = d
        .ensure_router(&spec(id, true))
        .await
        .expect("the router builds over the corpse");
    assert_eq!(state.phase, RouterPhase::Ready, "{}", state.message);
    assert!(state.active);
    assert_eq!(
        state.announce,
        ["10.7.2.0/24", "203.0.113.10/32", "203.0.113.55/32"],
        "its own address, the floating address it holds, and the routed subnet"
    );

    assert!(netns_exists(&netns));
    // The MTUs, and the two are not the same question: the inside leg is on
    // the overlay bridge and must not drag it up, the outside leg is on a
    // wire the operator handed over and whose MTU is theirs.
    assert!(
        in_netns(&netns, &["ip", "-o", "link", "show", "int"]).contains("mtu 1450"),
        "the inside leg takes the overlay's mtu"
    );
    assert!(
        in_netns(&netns, &["ip", "-o", "link", "show", "ext"]).contains("mtu 9000"),
        "and the outside leg takes the mtu of the interface that was given \
         away, not the veth default: {}",
        in_netns(&netns, &["ip", "-o", "link", "show", "ext"])
    );
    // The point of reading it rather than leaving it unset: a bridge takes
    // the MTU of its smallest port, so a leg on the veth default would have
    // pulled the operator's 9000-byte provider network down to 1500 — which
    // is what manacor's `vlan128` did on 2026-09-10.
    assert!(
        ip(&["-o", "link", "show", &bridge]).contains("mtu 9000"),
        "and the provider bridge keeps the operator's mtu: {}",
        ip(&["-o", "link", "show", &bridge])
    );
    // Both legs, each with the address the spec named and each in the bridge
    // the spec implies.
    assert!(in_netns(&netns, &["ip", "-o", "addr", "show", "ext"]).contains("203.0.113.10/24"));
    assert!(in_netns(&netns, &["ip", "-o", "addr", "show", "int"]).contains("10.7.1.1/24"));
    // The prefix this router announces has to be a route it HAS, or the
    // replies to a guest addressed out of it go back out of `ext` on the
    // default route and nothing works — not even the router's own ARP.
    let routes = in_netns(&netns, &["ip", "route"]);
    assert!(
        routes.contains("10.7.2.0/24 dev int"),
        "the routed subnet is on the inside leg: {routes}"
    );
    for (host, bridge) in [
        (veth_external(&id), provider_bridge(PHYSNET)),
        (veth_internal(&id), format!("meister-vx{VNI}")),
    ] {
        assert!(
            ip(&["-o", "link", "show", &host]).contains(&format!("master {bridge}")),
            "{host} belongs in {bridge}"
        );
    }
    assert!(
        in_netns(&netns, &["ip", "route", "show", "default"]).contains("via 203.0.113.1"),
        "the outside leg has a way out"
    );
    assert_eq!(sysctl(&netns, "net.ipv4.ip_forward"), "1");
    // Active: both legs answer for themselves.
    assert_eq!(sysctl(&netns, "net.ipv4.conf.ext.arp_ignore"), "0");
    assert_eq!(sysctl(&netns, "net.ipv4.conf.int.arp_ignore"), "0");

    // The rules are in the ROUTER's namespace and nowhere else.
    let rules = in_netns(&netns, &["nft", "list", "table", "ip", "meister-rt"]);
    assert!(rules.contains("dnat to 10.7.1.9"), "{rules}");
    assert!(rules.contains("snat to 203.0.113.55"), "{rules}");
    assert!(rules.contains("masquerade"), "{rules}");
    assert!(rules.contains("ct state invalid"), "{rules}");

    // The same call twice is one router, and this is the step where "twice"
    // used to cost something visible: the ruleset is rendered with a `flush
    // chain` in front of it, so every pass threw the counters away. They are
    // what an operator reads to find out whether a floating address carries
    // anything, so a second ensure has to leave them alone.
    in_netns(
        &netns,
        &[
            "nft",
            "add",
            "rule",
            "ip",
            "meister-rt",
            "forward",
            "counter",
            "comment",
            "\"probe\"",
        ],
    );
    let before = in_netns(&netns, &["nft", "list", "table", "ip", "meister-rt"]);
    assert!(before.contains("probe"), "the marker is in the ruleset");
    d.ensure_router(&spec(id, true))
        .await
        .expect("the same router again");
    let after = in_netns(&netns, &["nft", "list", "table", "ip", "meister-rt"]);
    assert!(
        after.contains("probe"),
        "an unchanged router must not reload its own ruleset: {after}"
    );

    // --- twice is once ---------------------------------------------------
    let again = d.ensure_router(&spec(id, true)).await.expect("idempotent");
    assert_eq!(again.phase, RouterPhase::Ready);
    assert_eq!(
        ip(&["netns", "list"])
            .lines()
            .filter(|l| l.contains(&netns))
            .count(),
        1,
        "the same Ensure twice is one router"
    );

    // --- the farewell: a stopping node stops speaking, and stays built -----
    // The measured failure this answers: manacor was stopped with `systemctl
    // stop`, its cluster made the standby active eight seconds later, and
    // manacor went on answering ARP for 10.128.1.210 — two MACs replied to
    // one arping. A namespace outlives the agent, the DestroyRouter went to a
    // node that was already down, and the start-up sweep keeps every
    // namespace whose record is still there.
    let silenced = d.fall_silent().await.expect("a node on its way out");
    assert_eq!(silenced, [id], "the one router that spoke here fell silent");
    assert_eq!(sysctl(&netns, "net.ipv4.conf.ext.arp_ignore"), "8");
    assert_eq!(sysctl(&netns, "net.ipv4.conf.int.arp_ignore"), "8");
    assert!(
        netns_exists(&netns) && link_exists(&veth_external(&id)),
        "silent, not gone: a restart must not be an outage"
    );
    assert!(
        !d.list_routers().await.expect("still one router")[0].active,
        "and the RECORD says standby, so the node does not shout on its way back up"
    );
    assert!(
        d.fall_silent().await.expect("twice is once").is_empty(),
        "a second farewell has nothing left to silence"
    );
    // And the promotion back is the one pass it always was.
    let back = d
        .ensure_router(&spec(id, true))
        .await
        .expect("told to speak again");
    assert!(back.active);
    assert_eq!(sysctl(&netns, "net.ipv4.conf.ext.arp_ignore"), "0");

    // --- the failover, and it is two sysctls ------------------------------
    let standby = d
        .ensure_router(&spec(id, false))
        .await
        .expect("converging to standby");
    assert!(!standby.active);
    assert!(
        standby.announce.is_empty(),
        "a standby announces nothing, which IS the withdraw"
    );
    assert_eq!(sysctl(&netns, "net.ipv4.conf.ext.arp_ignore"), "8");
    assert_eq!(sysctl(&netns, "net.ipv4.conf.int.arp_ignore"), "8");
    assert!(
        netns_exists(&netns) && link_exists(&veth_external(&id)),
        "and it is still fully built, or the promotion would not be a sysctl"
    );

    // --- what the node says about it --------------------------------------
    let listed = d.list_routers().await.expect("one router here");
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].id, id);
    assert_eq!(listed[0].phase, RouterPhase::Ready);
    assert_eq!(
        d.router_status(&id).await.unwrap().phase,
        RouterPhase::Ready
    );
    assert!(
        d.router_status(&RouterId::from_u128(0xdead)).await.is_err(),
        "a router this node does not hold is not found"
    );

    // A leg that went away is Failed with the leg named — what IS, not what
    // was asked.
    in_netns(&netns, &["ip", "link", "del", "int"]);
    let broken = d.router_status(&id).await.unwrap();
    assert_eq!(broken.phase, RouterPhase::Failed);
    assert!(broken.message.contains("int"), "{}", broken.message);
    assert!(
        broken.announce.is_empty(),
        "a router that is not there announces nothing, whatever it was asked to be"
    );

    // --- the sweep --------------------------------------------------------
    let orphan = router_netns(&RouterId::from_u128(0x6b00_0002));
    ip(&["netns", "add", &orphan]);
    let swept = d.sweep_routers().await.expect("a sweep");
    assert_eq!(
        swept,
        std::slice::from_ref(&orphan),
        "only the one no record names"
    );
    assert!(!netns_exists(&orphan));
    assert!(netns_exists(&netns), "the live one is untouched");

    // --- letting go -------------------------------------------------------
    d.destroy_router(&id).await.expect("the router goes");
    assert!(!netns_exists(&netns));
    assert!(!link_exists(&veth_external(&id)));
    assert!(!link_exists(&veth_internal(&id)));
    assert!(d.list_routers().await.unwrap().is_empty());
    // Idempotent: one that is not there is done, not an error.
    d.destroy_router(&id).await.expect("twice is once here too");
}
