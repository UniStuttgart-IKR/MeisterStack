// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! The gateway slot: a tenant router as a network namespace with two legs.
//!
//! ## The shape, and why it is this one
//!
//! A router is a box that is on two networks and on neither host. A network
//! namespace is exactly that box: its own routing table, its own conntrack,
//! its own nftables, its own addresses — so two tenants' routers on one node
//! cannot see each other's routes, and neither of them can see the host's.
//! One veth pair per leg carries it out of the namespace: one end in the
//! namespace, the other enslaved to a bridge this node already has — the
//! provider bridge for the outside, the tenant's overlay bridge for the
//! inside.
//!
//! Nothing here is new machinery. The overlay bridge is M5's, the provider
//! bridge is one `ensure` with an interface in it, and the NAT is `nft`
//! reading a script on stdin exactly as the tap guard does. What 6k adds is
//! where those pieces stand relative to each other.
//!
//! ## Active and standby are the same build
//!
//! Festlegung 7: HA is a BGP withdraw, so a standby has to be a router that
//! is finished and silent rather than a router that is not there. Both nodes
//! get the whole namespace, both legs, both addresses and every rule; the
//! standby differs in two facts and nothing else —
//!
//! * it announces nothing (`RouterState::announce` is empty, and the
//!   announcement pass hands the empty set to FRR), and
//! * both its legs answer no ARP (`arp_ignore = 8`), so nothing on either
//!   wire learns it is there.
//!
//! A failover is therefore one `EnsureRouter` with `active = true` on the
//! standby, and no build at all. That is what makes it fast, and it is why
//! `active` is a field of the spec rather than a command of its own.
//!
//! ## `ip netns` and not netlink
//!
//! The same trade this driver makes with `nft` and the FRR half makes with
//! `vtysh`: `ip netns add` PINS the namespace under `/var/run/netns`, and
//! that is what lets an operator standing at the node run
//! `ip netns exec meister-rt-<id> ip a` and see what this code built. A
//! netlink implementation would build the identical namespace and leave
//! nobody a way to look into it.
//!
//! ## The record, and the sweep it makes possible
//!
//! One JSON file per router under `<run_dir>/routers`, holding the spec it
//! was built from. It is in `run_dir` on purpose: a namespace lives in the
//! kernel and dies with the machine, so a record that outlived a reboot would
//! be a record of something that is gone. The two are lost together, which is
//! the property the sweep needs — a namespace of ours with no record beside
//! it is one a `kill -9` left half-built, and nothing else would ever remove
//! it.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Stdio;

use agent_api::networking::{
    self, NatKind, NetworkError, RouterId, RouterPhase, RouterSpec, RouterState,
};
use tracing::{debug, info, instrument, warn};

use crate::nftables::{LEG_EXTERNAL, LEG_INTERNAL, ROUTER_TABLE, address_of, router_ruleset};

/// The bridge one provider network gets on this node.
pub const PROVIDER_PREFIX: &str = "meister-px-";

/// The namespace one router gets.
pub const NETNS_PREFIX: &str = "meister-rt-";

/// `ip`, when nobody names a path. PATH, which is right on a NixOS node — the
/// same default `nft` takes.
pub const DEFAULT_IP: &str = "ip";

/// `arping`, when nobody names a path. iputils' one, which is what NixOS puts
/// on PATH and what the agent image carries for this.
pub const DEFAULT_ARPING: &str = "arping";

/// What `[network.provider]` resolves to.
#[derive(Clone, Debug)]
pub struct GatewayConfig {
    /// The interfaces this node gave away, by provider network name.
    pub physnets: BTreeMap<String, String>,
    /// Where `ip` is.
    pub ip: String,
    /// Where `arping` is. Used for one thing only: the gratuitous ARP a
    /// router sends when it becomes the active one.
    pub arping: String,
    /// Where the router records go. `<run_dir>/routers`, and it has to be on
    /// a filesystem that dies with the machine — see the module doc.
    pub state_dir: PathBuf,
}

/// The bridge a provider network's interface is put into.
pub fn provider_bridge(physnet: &str) -> String {
    format!("{PROVIDER_PREFIX}{physnet}")
}

/// The namespace one router lives in.
pub fn router_netns(id: &RouterId) -> String {
    format!("{NETNS_PREFIX}{id}")
}

/// The short form of a router's id, for the two link names that have to fit
/// in `IFNAMSIZ`. Eight hex digits, exactly as a tap name takes.
fn router_key(id: &RouterId) -> String {
    id.simple().to_string()[..8].to_string()
}

/// The host end of the router's outside leg — the one enslaved to the
/// provider bridge.
pub fn veth_external(id: &RouterId) -> String {
    format!("rtx{}", router_key(id))
}

/// The host end of the router's inside leg — the one enslaved to the tenant's
/// overlay bridge.
pub fn veth_internal(id: &RouterId) -> String {
    format!("rti{}", router_key(id))
}

/// A physnet name whose bridge would not fit in an interface name, refused in
/// words.
///
/// `IFNAMSIZ` is 16 with the NUL, so a link name is 15 characters and
/// `meister-px-` spends 11 of them. Four are left, which is enough for the
/// names a provider network actually gets (`ext`, `dmz`, `wan`) and is worth
/// saying out loud rather than discovering as a netlink `EINVAL` at start-up.
/// The same check `check_overlay_name` makes for a VNI, for the same reason.
pub fn check_physnet_name(physnet: &str) -> networking::Result<()> {
    const MAX: usize = 15;
    if physnet.is_empty() {
        return Err(NetworkError::InvalidSpec(
            "a provider network needs a name: [network.provider] physnets = { ext = \"eth1\" }"
                .to_string(),
        ));
    }
    if !physnet
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err(NetworkError::InvalidSpec(format!(
            "the provider network {physnet:?} has a name that cannot be part of an interface \
             name; letters, digits, - and _ only"
        )));
    }
    let bridge = provider_bridge(physnet);
    if bridge.len() > MAX {
        return Err(NetworkError::InvalidSpec(format!(
            "the provider network {physnet:?} would need the bridge {bridge:?}, which is {} \
             characters and an interface name may be {MAX}; give it a shorter name",
            bridge.len()
        )));
    }
    Ok(())
}

/// What this driver wrote down about one router it built.
///
/// The spec and nothing derived from it: everything else — the namespace
/// name, the link names, the prefixes to announce — is a function of the spec
/// and would be a second truth if it were stored beside it.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct RouterRecord {
    spec: RouterSpec,
}

/// The prefixes an ACTIVE router asks the fabric to send it.
///
/// Its own function and not a loop inside the caller, for the reason
/// `floating_prefixes` is one tier up: which addresses end up announced is the
/// whole of the failover semantics, and it is worth asserting.
///
/// Three sorts, and the third is the only one that is not a host route:
///
/// * the router's own external address, which is what an `snat` rule hides a
///   subnet behind,
/// * every floating address it holds a 1:1 pair for, because that address
///   lives on THIS router now and the fabric has to be told where,
/// * the routed subnets, as prefixes. Festlegung 5: no NAT, and the prefix is
///   announced by every active router of the subnet — stateless, so two of
///   them announcing it is ECMP and not a conflict.
pub fn router_prefixes(spec: &RouterSpec) -> Vec<String> {
    if !spec.active {
        return Vec::new();
    }
    let mut out = vec![crate::frr::host_prefix(address_of(&spec.external_addr))];
    for nat in spec.nats.iter().filter(|n| n.kind == NatKind::DnatAndSnat) {
        out.push(crate::frr::host_prefix(address_of(&nat.external_ip)));
    }
    for subnet in &spec.routed_subnets {
        // Canonical, so that two spellings of one subnet are one announcement:
        // `10.7.1.7/24` and `10.7.1.0/24` are the same prefix and FRR would
        // otherwise be handed both.
        match subnet
            .parse::<common::net::Ipv4Range>()
            .ok()
            .and_then(|r| r.to_cidr())
        {
            Some(cidr) => out.push(cidr),
            None => warn!(subnet = %subnet, router = %spec.id,
                          "this routed subnet is not a prefix, so it is not announced"),
        }
    }
    out.sort();
    out.dedup();
    out
}

/// Every address a router that has just become active has to shout about, in
/// the order it shouts.
///
/// The router's own outside address first, then one per floating address —
/// which is the same list `router_prefixes` announces to the fabric, minus the
/// routed subnets. A routed subnet is reached through the fabric and its next
/// hop is the outside address, so shouting about the outside address covers it
/// too; a floating address is a /32 that answers ARP on the wire and has to be
/// shouted about on its own.
///
/// Empty for a standby, and that is the whole of the safety: `arp_ignore = 8`
/// makes a standby silent, and a standby that sent a gratuitous ARP would
/// point every neighbour at a namespace that then answers nothing.
pub fn garp_addresses(spec: &RouterSpec) -> Vec<String> {
    if !spec.active {
        return Vec::new();
    }
    let mut out = vec![address_of(&spec.external_addr).to_string()];
    for nat in spec.nats.iter().filter(|n| n.kind == NatKind::DnatAndSnat) {
        out.push(address_of(&nat.external_ip).to_string());
    }
    out.dedup();
    out
}

/// How one gratuitous ARP is spelled, as an operator would type it.
///
/// `-U` is iputils' unsolicited mode: the address is the SENDER of the ARP and
/// no reply is expected, which is exactly "everyone please forget the MAC you
/// have for this". Three of them, because ARP is on the wire and unacked, and
/// `-w 1` so that a failover never waits on this — the data path is already
/// live when it runs, the shout only shortens the neighbour's cache.
///
/// On the outside leg only. The inside leg is the tenant's default gateway and
/// its address does not move between nodes: both nodes hold the same
/// `internal_addr`, and the guests never see the MAC change because only one
/// of the two ever answers.
pub fn garp_command<'a>(arping: &'a str, netns: &'a str, address: &'a str) -> Vec<&'a str> {
    vec![
        "netns",
        "exec",
        netns,
        arping,
        "-U",
        "-c",
        "3",
        "-w",
        "1",
        "-I",
        LEG_EXTERNAL,
        address,
    ]
}

/// The two sysctl values that decide whether a leg answers for itself.
///
/// `arp_ignore = 8` is "reply for no local address at all", which is what
/// makes a standby silent on both wires without taking a link down — the
/// namespace stays complete, so becoming active is a sysctl and not a build.
fn arp_ignore(active: bool) -> &'static str {
    match active {
        true => "0",
        false => "8",
    }
}

impl crate::LinuxNetworkDriver {
    /// This node's gateway slot, or the sentence it owes whoever asked for a
    /// router.
    pub(crate) fn gateway(&self) -> networking::Result<&GatewayConfig> {
        self.gateway.as_ref().ok_or_else(|| {
            NetworkError::InvalidSpec(
                "this node has no [network.provider] section, so it gave no interface away \
                 and holds no gateway slot"
                    .to_string(),
            )
        })
    }

    /// Run `ip`, with the arguments spelled exactly as an operator would type
    /// them.
    async fn ip(&self, args: &[&str]) -> networking::Result<String> {
        let binary = &self.gateway()?.ip;
        let out = tokio::process::Command::new(binary)
            .args(args)
            .stdin(Stdio::null())
            .output()
            .await
            .map_err(|e| {
                NetworkError::Backend(anyhow::anyhow!("running {binary} {}: {e}", args.join(" ")))
            })?;
        if !out.status.success() {
            return Err(NetworkError::Backend(anyhow::anyhow!(
                "{binary} {} failed: {}",
                args.join(" "),
                String::from_utf8_lossy(&out.stderr).trim()
            )));
        }
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    }

    /// The same, for a step that is allowed to have happened already.
    ///
    /// `ip link add` on a link that is there says "File exists" and exits
    /// non-zero, and a level-triggered ensure must not turn that into a
    /// failure. Everything this is used for is checked afterwards by asking
    /// whether the thing now exists, so a swallowed error that was NOT the
    /// idempotent one still surfaces — one step later, and as the fact rather
    /// than as the complaint.
    async fn ip_again(&self, args: &[&str]) {
        if let Err(e) = self.ip(args).await {
            debug!(error = %format!("{e:#}"), args = %args.join(" "), "ip step already done");
        }
    }

    /// Are the rules in this namespace already the rules we would write?
    ///
    /// See the caller for why this exists. Conservative in the one direction
    /// that matters: anything it cannot establish is a "no", and a "no" costs
    /// one `nft -f` — which is what every pass did before this.
    async fn ruleset_is_current(&self, netns: &str, rules: &str, spec: &RouterSpec) -> bool {
        let dir = match self.gateway() {
            Ok(g) => &g.state_dir,
            Err(_) => return false,
        };
        let path = Self::record_path(dir, &spec.id);
        let Some(record) = Self::read_record(&path).await else {
            return false;
        };
        if router_ruleset(&record.spec).ok().as_deref() != Some(rules) {
            return false;
        }
        self.ip(&[
            "netns",
            "exec",
            netns,
            self.nft.binary(),
            "list",
            "table",
            "ip",
            ROUTER_TABLE,
        ])
        .await
        .is_ok()
    }

    /// A namespace that is listed and cannot be entered is a corpse: take the
    /// name back.
    ///
    /// `ip netns add` PINS a namespace with a bind mount under `/run/netns`,
    /// and what is left when the mount goes without the file is a zero-byte
    /// regular file wearing the name. Everything then behaves as if the
    /// namespace existed and nothing works in it: `add` says the name is
    /// taken, `exec` and `ip -n` say "Invalid argument", and the router is
    /// Failed on that machine for ever — level-triggered or not, every pass
    /// re-derives the same broken state. Seen in the lab on 2026-09-10, where
    /// the cause was the agent's own mount namespace (`MountFlags` in
    /// nix/agent.nix); a hard reset of a machine can leave the same thing
    /// behind, so the driver answers it rather than only the deployment.
    ///
    /// Only ever runs against a name that is UNUSABLE — a live namespace
    /// answers `ip -n <ns> link show` and is left exactly alone, which is
    /// what keeps this from being a router that rebuilds itself every pass.
    async fn clear_dead_netns(&self, netns: &str) {
        if self.ip(&["-n", netns, "-o", "link", "show"]).await.is_ok() {
            return;
        }
        if !self
            .netns_present()
            .await
            .is_ok_and(|live| live.iter().any(|n| n == netns))
        {
            return;
        }
        warn!(
            netns,
            "a namespace of this name is listed and cannot be entered; taking the name back"
        );
        self.ip_again(&["netns", "delete", netns]).await;
    }

    /// A sysctl inside a router's namespace.
    async fn netns_sysctl(&self, netns: &str, key: &str, value: &str) -> networking::Result<()> {
        self.ip(&[
            "netns",
            "exec",
            netns,
            "sysctl",
            "-q",
            "-w",
            &format!("{key}={value}"),
        ])
        .await
        .map(|_| ())
    }

    /// Program nftables inside a router's namespace.
    ///
    /// The script goes in on stdin for the reason the tap guard's does: a rule
    /// containing a set literal never has to survive an argv split.
    async fn netns_nft(&self, netns: &str, script: &str) -> networking::Result<()> {
        use tokio::io::AsyncWriteExt;
        let g = self.gateway()?;
        let mut child = tokio::process::Command::new(&g.ip)
            .args(["netns", "exec", netns, self.nft.binary(), "-f", "-"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| NetworkError::Backend(anyhow::anyhow!("running {}: {e}", g.ip)))?;
        child
            .stdin
            .take()
            .ok_or_else(|| NetworkError::Backend(anyhow::anyhow!("nft stdin vanished")))?
            .write_all(script.as_bytes())
            .await
            .map_err(|e| NetworkError::Backend(e.into()))?;
        let out = child
            .wait_with_output()
            .await
            .map_err(|e| NetworkError::Backend(e.into()))?;
        if out.status.success() {
            return Ok(());
        }
        Err(NetworkError::Backend(anyhow::anyhow!(
            "nft refused the router ruleset in {netns}: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        )))
    }

    /// The shout a router gives when it has just become the active one.
    ///
    /// Measured on manacor on 2026-09-10: a planned failover moved the control
    /// plane in 4,4 s, the router's own address came back after 0,21 s — one
    /// probe interval — and the floating address after **5,20 s**. The whole
    /// of that difference is one neighbour's ARP cache. `arp_ignore` stops the
    /// old node ANSWERING, it does not tell anyone who has already asked, so a
    /// warm entry keeps pointing at the node that fell silent until it ages
    /// out. A gratuitous ARP is the sentence that was missing: the new active
    /// node says the address is at ITS MAC, unasked, and the neighbour
    /// overwrites the entry it has.
    ///
    /// Best effort throughout, and deliberately: the data path is already live
    /// when this runs — `arp_ignore` is 0, the addresses are on the leg and
    /// the rules are in place — so a node without `arping` loses the 5 seconds
    /// back and nothing else. It must never turn a completed failover into a
    /// failed one.
    ///
    /// Every address is spawned before any is waited on, so the whole shout
    /// costs the one second of `-w 1` no matter how many floating addresses a
    /// router carries.
    async fn announce_garp(&self, netns: &str, spec: &RouterSpec) {
        let addresses = garp_addresses(spec);
        let Ok(g) = self.gateway() else {
            return;
        };
        let mut running = Vec::new();
        for address in &addresses {
            let child = tokio::process::Command::new(&g.ip)
                .args(garp_command(&g.arping, netns, address))
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::piped())
                .spawn();
            match child {
                Ok(child) => running.push((address, child)),
                Err(e) => warn!(address = %address, error = %e,
                                "no gratuitous ARP for this address: {} could not be started",
                                g.arping),
            }
        }
        let mut announced = Vec::new();
        for (address, child) in running {
            match child.wait_with_output().await {
                Ok(out) if out.status.success() => announced.push(address.as_str()),
                Ok(out) => warn!(address = %address,
                                 error = %String::from_utf8_lossy(&out.stderr).trim(),
                                 "this address was not announced by gratuitous ARP"),
                Err(e) => warn!(address = %address, error = %e,
                                "this address was not announced by gratuitous ARP"),
            }
        }
        if !announced.is_empty() {
            info!(netns = %netns, addresses = %announced.join(", "),
                  "this router is the active one now and has said so on the outside wire");
        }
    }

    /// The namespaces of ours that exist right now.
    ///
    /// Read off `ip netns list` and not off the records, because the ones this
    /// is about are precisely the ones no record names. What marks a namespace
    /// as ours is its name, which is also what keeps the sweep off every other
    /// namespace on the node.
    async fn netns_present(&self) -> networking::Result<Vec<String>> {
        Ok(self
            .ip(&["netns", "list"])
            .await?
            .lines()
            // `ip netns list` prints `<name> (id: 0)` for a namespace that has
            // an nsid, and a bare name for one that has not.
            .filter_map(|line| line.split_whitespace().next())
            .filter(|name| name.starts_with(NETNS_PREFIX))
            .map(str::to_string)
            .collect())
    }

    fn record_path(dir: &Path, id: &RouterId) -> PathBuf {
        dir.join(format!("{id}.json"))
    }

    async fn read_record(path: &Path) -> Option<RouterRecord> {
        let bytes = tokio::fs::read(path).await.ok()?;
        match serde_json::from_slice(&bytes) {
            Ok(record) => Some(record),
            Err(e) => {
                warn!(path = %path.display(), error = %format!("{e:#}"),
                      "a router record here cannot be read");
                None
            }
        }
    }

    /// One router as it IS: the record says what it should be, the kernel says
    /// whether it is.
    async fn state_of(&self, spec: &RouterSpec, live: &[String]) -> RouterState {
        let netns = router_netns(&spec.id);
        let announce = router_prefixes(spec);
        let (phase, message) = if !live.contains(&netns) {
            (
                RouterPhase::Failed,
                format!("the network namespace {netns} is gone"),
            )
        } else {
            match self.ip(&["-n", &netns, "-o", "link", "show"]).await {
                Err(e) => (RouterPhase::Failed, format!("{e:#}")),
                Ok(links) => {
                    let missing: Vec<&str> = [LEG_EXTERNAL, LEG_INTERNAL]
                        .into_iter()
                        // `ip -o link show` prints `2: ext@if7: <...>`, so the
                        // name is followed by `@` or `:` and never bare.
                        .filter(|leg| {
                            !links.contains(&format!(" {leg}@"))
                                && !links.contains(&format!(" {leg}:"))
                        })
                        .collect();
                    match missing.is_empty() {
                        true => (RouterPhase::Ready, String::new()),
                        false => (
                            RouterPhase::Failed,
                            format!("the leg(s) {} are gone from {netns}", missing.join(", ")),
                        ),
                    }
                }
            }
        };
        RouterState {
            id: spec.id,
            location: netns,
            phase,
            message,
            active: spec.active,
            // A router that is not there announces nothing, whatever it was
            // asked to be: an announcement is a promise to carry traffic.
            announce: match phase {
                RouterPhase::Ready => announce,
                RouterPhase::Failed => Vec::new(),
            },
        }
    }

    /// Festlegung 1, carried out: the interface belongs to the bridge, and the
    /// host has no address on it.
    #[instrument(skip_all, fields(physnet = %name, interface = %interface))]
    pub(crate) async fn ensure_physnet_impl(
        &self,
        name: &str,
        interface: &str,
    ) -> networking::Result<String> {
        check_physnet_name(name)?;
        let index = self.link_index(interface).await?.ok_or_else(|| {
            NetworkError::InvalidSpec(format!(
                "[network.provider] physnets names {interface:?} for the provider network \
                 {name:?}, and this node has no such interface"
            ))
        })?;
        // The one refusal that is a REFUSAL and not a repair. An address here
        // is somebody still using this interface — a management address, a
        // leftover from DHCP — and a router put on it would answer for a
        // network the host is also on, which is exactly the confusion the
        // "give an interface away" rule exists to prevent. The operator has to
        // decide, so this node does not come up.
        let addresses = self.global_addresses(index).await?;
        if !addresses.is_empty() {
            return Err(NetworkError::InvalidSpec(format!(
                "the interface {interface:?} carries {}, so it has not been given away; a \
                 provider network's interface must have no address on the host. Move the \
                 address somewhere else, or point [network.provider] physnets.{name} at the \
                 interface this node really does not use",
                addresses.join(", ")
            )));
        }

        let bridge = provider_bridge(name);
        networking::BridgeDriver::ensure(self, &bridge).await?;
        let bridge_index = self.link_index(&bridge).await?.ok_or_else(|| {
            NetworkError::Backend(anyhow::anyhow!("bridge {bridge} vanished after create"))
        })?;
        self.enslave(index, bridge_index).await?;
        info!(bridge = %bridge, "provider network ready: the interface is the bridge's now");
        Ok(bridge)
    }

    /// N-A3, the whole of it: the namespace, both legs, the addresses, the
    /// route, the rules and the two sysctls that decide whether it speaks.
    ///
    /// Level-triggered from end to end. Every step is either "make it if it is
    /// not there" or "make it say this" — the addresses are flushed and set
    /// rather than added, the route is `replace`, and the ruleset is
    /// add-then-flush — so the second Ensure with the same spec changes
    /// nothing and the second Ensure with a different one converges to it.
    #[instrument(skip_all, fields(router = %spec.id, physnet = %spec.physnet,
                                  vni = spec.vxlan_id, active = spec.active))]
    pub(crate) async fn ensure_router_impl(
        &self,
        spec: &RouterSpec,
    ) -> networking::Result<RouterState> {
        let g = self.gateway()?;
        if !g.physnets.contains_key(&spec.physnet) {
            let mut have: Vec<&str> = g.physnets.keys().map(String::as_str).collect();
            have.sort_unstable();
            return Err(NetworkError::InvalidSpec(format!(
                "this node has no gateway slot on the provider network {:?}; it gave away [{}]",
                spec.physnet,
                have.join(", ")
            )));
        }
        // Rendered before anything is built: a spec whose rules cannot be
        // rendered is a spec that must not leave a half-made namespace behind.
        let rules = router_ruleset(spec).map_err(|e| {
            NetworkError::InvalidSpec(format!("this router names an address that is not one: {e}"))
        })?;

        // What this router was BEFORE this pass, read while the record is
        // still the old one: a standby that is being made active is the moment
        // the outside wire has to be told, and it is the only one. See
        // `announce_garp`.
        let was_active = Self::read_record(&Self::record_path(&g.state_dir, &spec.id))
            .await
            .is_some_and(|record| record.spec.active);

        let external_bridge = provider_bridge(&spec.physnet);
        // The tenant's wire, built on demand exactly as a VM's NIC builds it.
        // A gateway node with no `[network.vxlan]` section says so here, in
        // `ensure_overlay`'s own words.
        let internal_bridge = networking::BridgeDriver::ensure_overlay(self, spec.vxlan_id).await?;

        let netns = router_netns(&spec.id);
        self.clear_dead_netns(&netns).await;
        self.ip_again(&["netns", "add", &netns]).await;
        // `lo` is down in a fresh namespace, and conntrack's own traffic and
        // every locally originated probe need it.
        self.ip_again(&["-n", &netns, "link", "set", "lo", "up"])
            .await;

        // What the operator's wire takes, read off the interface they gave
        // away. `None` only if that interface has vanished under us, and then
        // the leg keeps the veth default — the same answer as before this was
        // read at all.
        let provider_mtu = match g.physnets.get(&spec.physnet) {
            Some(interface) => self.link_mtu(interface).await?,
            None => None,
        };

        for (host, leg, bridge) in [
            (veth_external(&spec.id), LEG_EXTERNAL, &external_bridge),
            (veth_internal(&spec.id), LEG_INTERNAL, &internal_bridge),
        ] {
            if self.link_index(&host).await?.is_none() {
                self.ip(&[
                    "link", "add", &host, "type", "veth", "peer", "name", leg, "netns", &netns,
                ])
                .await?;
            }
            let host_index = self.link_index(&host).await?.ok_or_else(|| {
                NetworkError::Backend(anyhow::anyhow!("veth {host} vanished after create"))
            })?;
            let bridge_index = self
                .link_index(bridge)
                .await?
                .ok_or_else(|| NetworkError::BridgeNotFound(bridge.clone()))?;
            self.enslave(host_index, bridge_index).await?;
            // The INSIDE leg takes the overlay's MTU for the reason a tap
            // does: a Linux bridge takes the MTU of its smallest port, so a
            // 1500-byte veth in a 1450-byte bridge drags the bridge back up
            // and the first full-size frame is dropped by the VXLAN device
            // with nothing in any log to say why.
            //
            // The OUTSIDE leg is on the provider bridge, which is a wire this
            // control plane did not make and whose MTU is the operator's —
            // the interface they gave away carries it, and THAT is the number
            // this leg takes. Giving it the overlay's MTU was simply wrong,
            // and so was the repair that followed: leaving it unset does not
            // "let the bridge decide", because a bridge takes the MTU of its
            // SMALLEST port. On manacor, whose `vlan128` is 9000, the veth
            // default of 1500 pulled the whole provider bridge from 9000 down
            // to 1500 the moment the first router was built on it — measured
            // 2026-09-10, and the reason this reads the interface instead of
            // trusting a default.
            let leg_mtu = match leg == LEG_INTERNAL {
                true => self.vxlan_mtu(),
                false => provider_mtu,
            };
            if let Some(mtu) = leg_mtu {
                let mtu = mtu.to_string();
                self.ip_again(&["link", "set", &host, "mtu", &mtu]).await;
                self.ip_again(&["-n", &netns, "link", "set", leg, "mtu", &mtu])
                    .await;
            }
            self.ip(&["-n", &netns, "link", "set", leg, "up"]).await?;
        }

        for (leg, addr) in [
            (LEG_EXTERNAL, &spec.external_addr),
            (LEG_INTERNAL, &spec.internal_addr),
        ] {
            // Flush and set, not add: the spec is the truth, and a router that
            // was re-addressed must not keep answering for the address it had.
            self.ip_again(&["-n", &netns, "addr", "flush", "dev", leg])
                .await;
            self.ip(&["-n", &netns, "addr", "add", addr, "dev", leg])
                .await?;
        }
        // Every floating address as a /32 on the outside leg, beside the
        // router's own.
        //
        // Not for the local stack -- the DNAT in `prerouting` runs BEFORE the
        // routing decision, so a packet for the address is translated and
        // forwarded whether or not the address is configured here. It is for
        // ARP: on a provider network that is plain layer 2, whatever wants to
        // reach the floating address asks who has it, and without this nobody
        // answers. The announcement (`router_prefixes`) is the other half and
        // the one that works where the provider network is ROUTED to; a
        // deployment normally has one of the two, and having both costs an
        // address the standby does not answer for anyway.
        for nat in spec.nats.iter().filter(|n| n.kind == NatKind::DnatAndSnat) {
            let fip = format!("{}/32", address_of(&nat.external_ip));
            self.ip(&["-n", &netns, "addr", "add", &fip, "dev", LEG_EXTERNAL])
                .await?;
        }

        self.ip(&[
            "-n",
            &netns,
            "route",
            "replace",
            "default",
            "via",
            &spec.external_gateway,
            "dev",
            LEG_EXTERNAL,
        ])
        .await?;

        // And a route for every prefix this router ANNOUNCES, onto the
        // inside leg.
        //
        // Announcing a routed subnet and not knowing where it is was the
        // whole of the hole: the fabric was told "the prefix is here", the
        // packets arrived, and the router sent the replies back out of `ext`
        // on its default route, because the only inside route it had was the
        // /24 of its own `internal_addr`. A guest addressed out of a routed
        // subnet could therefore reach nothing at all — not even the router
        // itself, whose ARP reply went the wrong way. Found in the lab the
        // first time a guest was given an address out of a /29.
        //
        // `scope link` and via no gateway: the prefix is ON the overlay, the
        // guests answer for their own addresses there, and a next hop would
        // be a second thing to be wrong about. Replace and not add, so the
        // second pass is the first.
        for prefix in &spec.routed_subnets {
            self.ip_again(&[
                "-n",
                &netns,
                "route",
                "replace",
                prefix,
                "dev",
                LEG_INTERNAL,
                "scope",
                "link",
            ])
            .await;
        }

        self.netns_sysctl(&netns, "net.ipv4.ip_forward", "1")
            .await?;
        // The standby half, and the only thing that separates it from the
        // active one on the wire. Both legs, because a standby must be silent
        // towards the tenant as well as towards the fabric: an ARP reply on
        // the overlay would make it the tenant's default gateway.
        for leg in [LEG_EXTERNAL, LEG_INTERNAL] {
            self.netns_sysctl(
                &netns,
                &format!("net.ipv4.conf.{leg}.arp_ignore"),
                arp_ignore(spec.active),
            )
            .await?;
        }

        // The rules, only when they are not already the rules that are there.
        //
        // Level-triggered means the same plan twice is one router, and this is
        // the one step where "twice" used to cost something visible: the
        // ruleset is rendered with `flush chain` in front of it, so every pass
        // — one every five seconds — threw the counters away and started them
        // at nought. The counters are what an operator reads to find out
        // whether a floating address is carrying anything, and a counter that
        // is reset before it can be read is not evidence. Found in the lab
        // while trying to use exactly that as the proof of SNAT.
        //
        // Two questions, and both have to be yes to skip: the record beside
        // the namespace renders the same ruleset (so nothing about this router
        // has changed), and the table is really in the namespace (so a
        // namespace that was rebuilt under us is filled in again).
        if !self.ruleset_is_current(&netns, &rules, spec).await {
            self.netns_nft(&netns, &rules).await?;
        }

        // Last, and only when everything above worked: a record is this
        // driver's statement that the namespace beside it is finished. One
        // written earlier would make the sweep spare a half-built router for
        // ever.
        let dir = &self.gateway()?.state_dir;
        tokio::fs::create_dir_all(dir).await.map_err(|e| {
            NetworkError::Backend(anyhow::anyhow!("creating {}: {e}", dir.display()))
        })?;
        let record = serde_json::to_vec_pretty(&RouterRecord { spec: spec.clone() })
            .map_err(|e| NetworkError::Backend(e.into()))?;
        let path = Self::record_path(dir, &spec.id);
        tokio::fs::write(&path, &record).await.map_err(|e| {
            NetworkError::Backend(anyhow::anyhow!("writing {}: {e}", path.display()))
        })?;

        // After the record and not before it: the shout is a statement that
        // this node is carrying the address, and the record is what makes that
        // true across a restart of the agent.
        if spec.active && !was_active {
            self.announce_garp(&netns, spec).await;
        }

        info!(netns = %netns, external = %spec.external_addr, internal = %spec.internal_addr,
              nats = spec.nats.len(), routed = spec.routed_subnets.len(),
              "router ready");
        Ok(self.state_of(spec, &[netns]).await)
    }

    /// Everything this driver made for one router, gone.
    ///
    /// The namespace first and the host-side legs after it: deleting a
    /// namespace takes its half of every veth pair with it, and the kernel
    /// removes the other half — so the two `link del` calls are for the
    /// interrupted build where the pair was made and the move into the
    /// namespace was not.
    #[instrument(skip_all, fields(router = %id))]
    pub(crate) async fn destroy_router_impl(&self, id: &RouterId) -> networking::Result<()> {
        let netns = router_netns(id);
        self.ip_again(&["netns", "del", &netns]).await;
        for host in [veth_external(id), veth_internal(id)] {
            if self.link_index(&host).await?.is_some() {
                self.ip_again(&["link", "del", &host]).await;
            }
        }
        let path = Self::record_path(&self.gateway()?.state_dir, id);
        if let Err(e) = tokio::fs::remove_file(&path).await
            && e.kind() != std::io::ErrorKind::NotFound
        {
            warn!(path = %path.display(), error = %e, "could not remove the router record");
        }
        info!(netns = %netns, "router removed");
        Ok(())
    }

    pub(crate) async fn list_routers_impl(&self) -> networking::Result<Vec<RouterState>> {
        let dir = &self.gateway()?.state_dir;
        let live = self.netns_present().await?;
        let mut entries = match tokio::fs::read_dir(dir).await {
            Ok(e) => e,
            // A node that has never been given a router has no directory, and
            // that is not a failure: it is the answer.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => {
                return Err(NetworkError::Backend(anyhow::anyhow!(
                    "reading {}: {e}",
                    dir.display()
                )));
            }
        };
        let mut out = Vec::new();
        while let Some(entry) = entries
            .next_entry()
            .await
            .map_err(|e| NetworkError::Backend(e.into()))?
        {
            let path = entry.path();
            if path.extension().is_none_or(|e| e != "json") {
                continue;
            }
            if let Some(record) = Self::read_record(&path).await {
                out.push(self.state_of(&record.spec, &live).await);
            }
        }
        out.sort_by_key(|r| r.id);
        Ok(out)
    }

    pub(crate) async fn router_status_impl(
        &self,
        id: &RouterId,
    ) -> networking::Result<RouterState> {
        let path = Self::record_path(&self.gateway()?.state_dir, id);
        let record = Self::read_record(&path)
            .await
            .ok_or(NetworkError::RouterNotFound(*id))?;
        let live = self.netns_present().await?;
        Ok(self.state_of(&record.spec, &live).await)
    }

    /// The namespaces of ours that no record names, taken down once.
    ///
    /// The router twin of `sweep_orphan_overlays`, and the failure it answers
    /// is the one that cannot heal itself: `ensure_router` writes its record
    /// last, so a `kill -9` in the middle leaves a namespace with two legs in
    /// two bridges that nothing on this node knows about. It is not reference
    /// -counted from anywhere, nobody will ask for it again, and it would
    /// stand for the life of the machine.
    #[instrument(skip_all)]
    pub(crate) async fn sweep_routers_impl(&self) -> networking::Result<Vec<String>> {
        let dir = self.gateway()?.state_dir.clone();
        let mut swept = Vec::new();
        for netns in self.netns_present().await? {
            let named = netns
                .strip_prefix(NETNS_PREFIX)
                .and_then(|id| id.parse::<RouterId>().ok())
                .map(|id| Self::record_path(&dir, &id))
                .is_some_and(|path| path.exists());
            if named {
                continue;
            }
            self.ip_again(&["netns", "del", &netns]).await;
            info!(netns = %netns, "orphaned router removed: no record on this node names it");
            swept.push(netns);
        }
        Ok(swept)
    }

    /// Every router of ours, made standby, in place.
    ///
    /// One `ensure_router` per record with `active` turned off, and nothing
    /// of its own: whatever a standby is, is whatever that call builds, and a
    /// second implementation of "silent" here would be a second definition of
    /// failover to keep in step with the first. The record is rewritten as a
    /// side effect of the same call, which is the half that matters after a
    /// restart — a node that comes back reading `active = false` waits to be
    /// told, instead of shouting from the first pass.
    ///
    /// Best effort per router: one namespace that will not co-operate must
    /// not keep the others speaking.
    #[instrument(skip_all)]
    pub(crate) async fn fall_silent_impl(&self) -> networking::Result<Vec<RouterId>> {
        let mut silenced = Vec::new();
        for router in self.list_routers_impl().await? {
            if !router.active {
                continue;
            }
            let path = Self::record_path(&self.gateway()?.state_dir, &router.id);
            let Some(record) = Self::read_record(&path).await else {
                continue;
            };
            let mut spec = record.spec;
            spec.active = false;
            match self.ensure_router_impl(&spec).await {
                Ok(_) => {
                    info!(router = %spec.id,
                          "this node is going and its router falls silent; the standby speaks now");
                    silenced.push(spec.id);
                }
                Err(e) => warn!(router = %spec.id, error = %format!("{e:#}"),
                                "this router could not be silenced on the way out"),
            }
        }
        Ok(silenced)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use agent_api::networking::{NatKind, NatRule};

    fn spec(active: bool) -> RouterSpec {
        RouterSpec {
            id: RouterId::from_u128(0x1a2b_3c4d_5e6f_0000_0000_0000_0000_0000),
            physnet: "ext".into(),
            external_addr: "203.0.113.10/24".into(),
            external_gateway: "203.0.113.1".into(),
            vxlan_id: 10_000,
            internal_addr: "10.7.1.1/24".into(),
            nats: Vec::new(),
            routed_subnets: Vec::new(),
            active,
        }
    }

    /// The three names an operator greps for, and the one that has to fit in
    /// an interface name.
    #[test]
    fn a_router_is_named_after_its_id_everywhere_it_appears() {
        let s = spec(true);
        assert_eq!(
            router_netns(&s.id),
            "meister-rt-1a2b3c4d-5e6f-0000-0000-000000000000"
        );
        assert_eq!(veth_external(&s.id), "rtx1a2b3c4d");
        assert_eq!(veth_internal(&s.id), "rti1a2b3c4d");
        for link in [veth_external(&s.id), veth_internal(&s.id)] {
            assert!(link.len() <= 15, "{link} would not fit in IFNAMSIZ");
        }
        assert_eq!(provider_bridge("ext"), "meister-px-ext");
    }

    /// The prefix costs eleven of the fifteen characters an interface name
    /// has, so a provider network's name has four. Said in words at start-up
    /// rather than discovered as a netlink EINVAL.
    #[test]
    fn a_physnet_whose_bridge_would_not_fit_is_refused_in_words() {
        assert!(check_physnet_name("ext").is_ok());
        assert!(check_physnet_name("dmz1").is_ok());
        let err = check_physnet_name("public").unwrap_err().to_string();
        assert!(
            err.contains("meister-px-public") && err.contains("15"),
            "{err}"
        );
        let err = check_physnet_name("").unwrap_err().to_string();
        assert!(err.contains("needs a name"), "{err}");
        let err = check_physnet_name("ex t").unwrap_err().to_string();
        assert!(err.contains("interface name"), "{err}");
    }

    /// What an active router asks the fabric for, and the standby's answer to
    /// the same question: nothing. That difference IS the failover — see
    /// Festlegung 7.
    #[test]
    fn only_an_active_router_asks_the_fabric_for_anything() {
        let mut s = spec(true);
        s.nats = vec![
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
        ];
        s.routed_subnets = vec!["10.7.2.7/24".into()];
        assert_eq!(
            router_prefixes(&s),
            [
                // the routed subnet, canonicalised: the spelling an operator
                // used is not what FRR is handed
                "10.7.2.0/24",
                // the router's own address, which snat hides the subnet behind
                "203.0.113.10/32",
                // and the floating address, because it lives on this router now
                "203.0.113.55/32",
            ]
        );

        s.active = false;
        assert!(
            router_prefixes(&s).is_empty(),
            "a standby announces nothing, which is the whole of the withdraw"
        );
    }

    /// A subnet nobody can turn into a prefix is left out and said out loud,
    /// never announced as something else.
    #[test]
    fn a_routed_subnet_that_is_not_a_prefix_is_not_announced() {
        let mut s = spec(true);
        s.routed_subnets = vec!["10.7.2.1-10.7.2.9".into(), "not-a-subnet".into()];
        assert_eq!(router_prefixes(&s), ["203.0.113.10/32"]);
    }

    /// D-B4: what a node that has just become active says on the outside
    /// wire, and in which words.
    ///
    /// The words matter, because nobody sees them in a unit test twice: this
    /// is the one place the argv is written down, and a typo in it is five
    /// seconds of a dead floating address in front of an audience.
    #[test]
    fn the_new_active_node_shouts_for_its_address_and_for_every_floating_one() {
        let mut s = spec(true);
        s.nats = vec![
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
        ];
        s.routed_subnets = vec!["10.7.2.0/24".into()];
        assert_eq!(
            garp_addresses(&s),
            [
                // the router's own outside address, bare: `arping` wants an
                // address and not a prefix
                "203.0.113.10",
                // and the floating address, which is the one that cost the
                // 5,2 s in the lab
                "203.0.113.55",
            ],
            "a routed subnet is reached through the outside address and needs \
             no shout of its own"
        );

        s.active = false;
        assert!(
            garp_addresses(&s).is_empty(),
            "a standby that shouted would point every neighbour at a namespace \
             that answers nothing"
        );

        assert_eq!(
            garp_command("arping", "meister-rt-1a2b3c4d", "203.0.113.55"),
            [
                "netns",
                "exec",
                "meister-rt-1a2b3c4d",
                "arping",
                "-U",
                "-c",
                "3",
                "-w",
                "1",
                "-I",
                "ext",
                "203.0.113.55",
            ],
            "unsolicited, three times, bounded by a second, on the outside leg"
        );
    }

    /// The standby is silent on BOTH wires. On the fabric because it announces
    /// nothing, and on the tenant's overlay because it answers no ARP — an
    /// ARP reply there would make it the tenant's gateway while the active
    /// router is the one carrying the traffic.
    #[test]
    fn a_standby_answers_no_arp_and_an_active_router_answers_normally() {
        assert_eq!(arp_ignore(true), "0");
        assert_eq!(arp_ignore(false), "8");
    }
}
