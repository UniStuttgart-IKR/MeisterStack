// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Check router namespaces, links, addresses, routes and nftables against Linux.
//!
//! Requires `ip`, `nft`, `sysctl`, and isolated network and mount namespaces:
//!
//! ```text
//! unshare -rnm --propagation private sh -c \
//!   'mount -t tmpfs none /run && mkdir -p /run/netns && \
//!    cargo test -p meister-linux-network-driver \
//!    --test gateway_netns -- --ignored --nocapture'
//! ```
//!
//! Load `dummy`, `veth`, `vxlan`, `nft_ct`, `nft_nat` and `nft_masq` on the
//! host first; a user namespace cannot autoload kernel modules. The private
//! `/run` holds test namespace mounts and the planted stale namespace file.

use std::collections::BTreeMap;
use std::os::unix::fs::PermissionsExt;

use agent_api::networking::{
    BridgeDriver, NatKind, NatRule, NicDriver, NicId, NicSpec, RouterId, RouterPhase, RouterSpec,
};
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

/// Whether the host's IPv6 is off on a link of this namespace, as the kernel says.
fn host_ipv6_disabled(link: &str) -> bool {
    std::fs::read_to_string(format!("/proc/sys/net/ipv6/conf/{link}/disable_ipv6"))
        .unwrap_or_else(|e| panic!("the IPv6 switch of {link}: {e}"))
        .trim()
        == "1"
}

/// One test at a time in this kernel: a sweep removes every router namespace its driver holds
/// no record for, the other test's included.
static KERNEL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn spec(id: RouterId, active: bool) -> RouterSpec {
    spec_on(PHYSNET, VNI, id, active)
}

fn spec_on(physnet: &str, vni: u32, id: RouterId, active: bool) -> RouterSpec {
    RouterSpec {
        id,
        physnet: physnet.into(),
        external_addr: "203.0.113.10/24".into(),
        external_gateway: "203.0.113.1".into(),
        vxlan_id: vni,
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
        sole_gateway: false,
    }
}

fn driver(state_dir: &std::path::Path) -> LinuxNetworkDriver {
    driver_on(state_dir, "nft", (PHYSNET, UPLINK, GIVEN_AWAY))
}

/// A driver with its own `nft` and its own `(physnet, uplink, interface given away)`.
fn driver_on(
    state_dir: &std::path::Path,
    nft: &str,
    (physnet, uplink, given_away): (&str, &str, &str),
) -> LinuxNetworkDriver {
    LinuxNetworkDriver::build(
        Some(VxlanConfig {
            uplink: uplink.into(),
            mtu: 1450,
            evpn: false,
        }),
        NftConfig {
            binary: nft.into(),
            guarded: common::net::Ipv4Ranges::default(),
        },
        Some(GatewayConfig {
            physnets: BTreeMap::from([(physnet.to_string(), given_away.to_string())]),
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
    let _kernel = KERNEL.lock().await;
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

    // A stale namespace file must be removed before the namespace can be rebuilt.
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
    // A veth with a smaller MTU would lower the provider bridge MTU.
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

    // An unchanged ensure must preserve nftables counters and existing rules.
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

    // Shutdown suppresses ARP without destroying the router namespace.
    let outcome = d.fall_silent().await.expect("a node on its way out");
    assert_eq!(
        outcome.silenced,
        [id],
        "the one router that spoke here fell silent"
    );
    assert!(outcome.complete(), "nothing failed to fall silent");
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
    // Controller-loss handling also uses fall_silent. Keep a readable standby
    // record so reconnect can reactivate the existing namespace.
    let silent = d.list_routers().await.expect("still one router");
    assert!(
        silent[0].announce.is_empty(),
        "the withdraw: a silent router asks the fabric for nothing, not even \
         the floating address it was translating"
    );
    // Addresses remain configured while arp_ignore suppresses replies.
    // Reactivation can reuse the namespace.
    let on_ext = in_netns(&netns, &["ip", "-o", "addr", "show", "ext"]);
    assert!(
        on_ext.contains("203.0.113.10/24") && on_ext.contains("203.0.113.55/32"),
        "the standby keeps its own address and the floating one it holds, and \
         answers for neither: {on_ext}"
    );
    let second = d.fall_silent().await.expect("twice is once");
    assert!(
        second.silenced == [id] && second.complete(),
        "a second farewell silences the live namespace again, whatever its record says (R2-1)"
    );
    assert_eq!(sysctl(&netns, "net.ipv4.conf.ext.arp_ignore"), "8");
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

/// An active router whose rules fail is left silent: activation is the last step of a pass,
/// after the rules and the record, so no namespace answers ARP that no record names (R2-1).
#[tokio::test]
#[ignore = "needs its own network and mount namespace; see the module note"]
async fn a_router_whose_rules_fail_is_left_silent_not_active() {
    const SECOND: (&str, &str, &str) = ("ex2", "upl2", "pxlink2");
    const SECOND_VNI: u32 = 10_008;
    let _kernel = KERNEL.lock().await;
    let state = tempfile::Builder::new()
        .prefix("ms-neutron-agent-r2-1-")
        .tempdir()
        .expect("a state directory");
    let dir = state.path();
    // `nft`, until the refusal file exists: then it refuses every script, as a kernel without
    // a NAT module would.
    let refusal = dir.join("refuse");
    let nft = dir.join("nft");
    std::fs::write(
        &nft,
        format!(
            "#!/bin/sh\nif [ -e '{}' ]; then cat > /dev/null; echo refused >&2; exit 1; fi\n\
             exec nft \"$@\"\n",
            refusal.display()
        ),
    )
    .expect("an nft wrapper");
    std::fs::set_permissions(&nft, std::fs::Permissions::from_mode(0o755)).expect("and it runs");
    let (physnet, uplink, given_away) = SECOND;
    for link in [uplink, given_away] {
        ip(&["link", "add", link, "type", "dummy"]);
        ip(&["link", "set", link, "up"]);
    }
    let d = driver_on(dir, &nft.display().to_string(), SECOND);
    d.ensure_physnet(physnet, given_away)
        .await
        .expect("the interface was given away");
    let id = RouterId::from_u128(0x6b00_0003);
    let netns = router_netns(&id);

    std::fs::write(&refusal, b"").expect("nft refuses from now on");
    d.ensure_router(&spec_on(physnet, SECOND_VNI, id, true))
        .await
        .expect_err("a router whose rules were refused is not built");

    assert!(
        netns_exists(&netns),
        "the half-built namespace is still there"
    );
    assert_eq!(sysctl(&netns, "net.ipv4.conf.ext.arp_ignore"), "8");
    assert_eq!(sysctl(&netns, "net.ipv4.conf.int.arp_ignore"), "8");

    // The gate is a gate and not a wall: once nft takes the rules the same pass activates.
    std::fs::remove_file(&refusal).expect("nft takes rules again");
    d.ensure_router(&spec_on(physnet, SECOND_VNI, id, true))
        .await
        .expect("the same router, rules accepted");
    assert_eq!(sysctl(&netns, "net.ipv4.conf.ext.arp_ignore"), "0");
    d.destroy_router(&id).await.expect("the router goes");
}

/// IKR-B77: the host's IPv6 is off on every link the driver makes for guests' and tenants'
/// frames, and in a router's namespace, so the host sends nothing of its own into them.
#[tokio::test]
#[ignore = "needs its own network and mount namespace; see the module note"]
async fn the_host_speaks_no_ipv6_on_the_wires_it_builds() {
    const THIRD: (&str, &str, &str) = ("ex3", "upl3", "pxlink3");
    const THIRD_VNI: u32 = 10_009;
    let _kernel = KERNEL.lock().await;
    let state = tempfile::Builder::new()
        .prefix("ms-neutron-agent-b77-")
        .tempdir()
        .expect("a state directory");
    let (physnet, uplink, given_away) = THIRD;
    for link in [uplink, given_away] {
        ip(&["link", "add", link, "type", "dummy"]);
        ip(&["link", "set", link, "up"]);
    }
    let d = driver_on(state.path(), "nft", THIRD);
    d.ensure_physnet(physnet, given_away)
        .await
        .expect("the interface was given away");
    let id = RouterId::from_u128(0x6b00_0004);
    d.ensure_router(&spec_on(physnet, THIRD_VNI, id, true))
        .await
        .expect("a router");
    let nic = NicId::from_u128(0x77);
    let tap = d
        .create(
            &nic,
            &NicSpec {
                bridge: "unused".into(),
                mac: "52:54:00:00:00:77".parse().expect("a mac"),
                vxlan_id: Some(THIRD_VNI),
                physnet: None,
                floating_ips: Vec::new(),
                routed_subnets: Vec::new(),
            },
        )
        .await
        .expect("a tap on the tenant's wire")
        .tap_name;

    for link in [
        tap,
        format!("meister-vx{THIRD_VNI}"),
        format!("mvx{THIRD_VNI}"),
        provider_bridge(physnet),
        veth_external(&id),
        veth_internal(&id),
    ] {
        assert!(host_ipv6_disabled(&link), "{link} has the host's IPv6 on");
        assert!(
            !ip(&["-6", "-o", "addr", "show", "dev", &link]).contains("inet6"),
            "{link} has an IPv6 address"
        );
    }
    let netns = router_netns(&id);
    for leg in ["ext", "int"] {
        assert_eq!(
            sysctl(&netns, &format!("net.ipv6.conf.{leg}.disable_ipv6")),
            "1",
            "the router's {leg} leg"
        );
    }

    NicDriver::destroy(&d, &nic).await.expect("the tap goes");
    d.destroy_router(&id).await.expect("the router goes");
}

/// Set the host's IPv6 switch of a link of this namespace, as an agent before IKR-B77 left it.
fn set_host_ipv6_disabled(link: &str, disabled: bool) {
    let path = format!("/proc/sys/net/ipv6/conf/{link}/disable_ipv6");
    std::fs::write(&path, if disabled { "1" } else { "0" })
        .unwrap_or_else(|e| panic!("writing {path}: {e}"));
}

/// IKR-B77: the taps and overlays an older agent made, which running guests keep using, have
/// the host's IPv6 turned off at agent start; a link of another name is left as it is.
#[tokio::test]
#[ignore = "needs its own network and mount namespace; see the module note"]
async fn the_startup_mend_turns_the_host_ipv6_off_on_links_made_before() {
    let _kernel = KERNEL.lock().await;
    let state = tempfile::Builder::new()
        .prefix("ms-neutron-agent-b77-mend-")
        .tempdir()
        .expect("a state directory");
    let older = ["msk0b77aaaa", "meister-vx10011", "mvx10011"];
    let operators = "opr0b77";
    for link in older.into_iter().chain([operators]) {
        ip(&["link", "add", link, "type", "dummy"]);
        ip(&["link", "set", link, "up"]);
        set_host_ipv6_disabled(link, false);
    }
    let d = driver(state.path());

    let mended = NicDriver::mend_existing_links(&d)
        .await
        .expect("every link was mended");

    for link in older {
        assert!(mended.iter().any(|m| m == link), "{link} in {mended:?}");
        assert!(host_ipv6_disabled(link), "{link} has the host's IPv6 on");
    }
    assert!(
        !host_ipv6_disabled(operators),
        "a link this driver does not name is not its to change"
    );
    for link in older.into_iter().chain([operators]) {
        ip(&["link", "del", link]);
    }
}
