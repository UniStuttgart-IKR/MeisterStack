// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Render and apply tap source guards and router NAT rules.
//! Each tap has a netdev ingress chain: MAC pinning, then an IPv4/ARP allowlist
//! or guarded-pool rules. Provider NICs receive only MAC pinning. IPv6 source
//! addresses and inbound guest traffic have no address policy here.
//! Router NAT uses a separate ip-family table inside each router namespace.

use std::process::Stdio;

use agent_api::networking::{NetworkError, NicSpec};
use common::net::{Ipv4Ranges, RangeError};
use tracing::{debug, info, instrument, warn};

/// The table this driver owns. Nothing else writes into it, and a `nft list
/// table netdev meister` is the whole of what this stack has to say about
/// filtering.
pub const TABLE: &str = "meister";

/// Allow the unspecified source used by DHCP and ARP address probes.
const UNSPECIFIED: &str = "0.0.0.0";

/// The chain that guards one tap.
pub fn chain_name(tap: &str) -> String {
    format!("meister-{tap}")
}

/// Where to find `nft`, and whether this node filters at all.
#[derive(Clone, Debug)]
pub struct NftConfig {
    /// The binary. `nft` = whatever PATH says, which is right on a NixOS node
    /// and wrong nowhere in particular.
    pub binary: String,
    /// Locally configured floating-pool ranges. Keep them aligned with cloud allocation;
    /// the controller session does not synchronize this catalogue.
    pub guarded: Ipv4Ranges,
}

/// Render one complete tap chain for an nft batch.
pub fn ruleset(tap: &str, spec: &NicSpec, guarded: &Ipv4Ranges) -> Result<String, RangeError> {
    let chain = chain_name(tap);
    let mut s = String::new();

    // add-then-flush rather than delete-then-add: `delete` on a chain that is
    // not there fails, and a failing line aborts the whole atomic script. This
    // way the first apply and the hundredth are the same three lines.
    s.push_str(&format!("add table netdev {TABLE}\n"));
    s.push_str(&format!(
        "add chain netdev {TABLE} {chain} \
         {{ type filter hook ingress device {tap} priority 0; policy accept; }}\n"
    ));
    s.push_str(&format!("flush chain netdev {TABLE} {chain}\n"));

    let rule = |body: &str| format!("add rule netdev {TABLE} {chain} {body}\n");

    // 1. Always, on every tap. We handed out this MAC.
    s.push_str(&rule(&format!(
        "ether saddr != {} counter drop comment \"mac-spoof\"",
        spec.mac
    )));

    // Provider NICs use operator-managed address space; apply MAC pinning only.
    if spec.physnet.is_some() {
        return Ok(s);
    }

    let floating = Ipv4Ranges::parse(&spec.floating_ips)?;
    let subnets = Ipv4Ranges::parse(&spec.routed_subnets)?;

    if !subnets.is_empty() {
        // 3. The tenant's address space is known, so say exactly what it is.
        let mut allowed: Vec<String> = vec![subnets.to_nft(), UNSPECIFIED.to_string()];
        if !floating.is_empty() {
            allowed.insert(1, floating.to_nft());
        }
        let allowed = allowed.join(", ");
        s.push_str(&rule(&format!(
            "meta protocol ip ip saddr != {{ {allowed} }} counter drop comment \"src-ip\""
        )));
        s.push_str(&rule(&format!(
            "meta protocol arp arp saddr ip != {{ {allowed} }} counter drop comment \"src-arp\""
        )));
        return Ok(s);
    }

    if !guarded.is_empty() {
        // Accept this VM's reservations before rejecting other guarded-pool sources.
        if !floating.is_empty() {
            let mine = floating.to_nft();
            s.push_str(&rule(&format!(
                "meta protocol ip ip saddr {{ {mine} }} accept"
            )));
            s.push_str(&rule(&format!(
                "meta protocol arp arp saddr ip {{ {mine} }} accept"
            )));
        }
        let pool = guarded.to_nft();
        s.push_str(&rule(&format!(
            "meta protocol ip ip saddr {{ {pool} }} counter drop comment \"pool-ip\""
        )));
        s.push_str(&rule(&format!(
            "meta protocol arp arp saddr ip {{ {pool} }} counter drop comment \"pool-arp\""
        )));
    }
    Ok(s)
}

/// Take one tap's chain away. Flush first: nftables refuses to delete a chain
/// that still holds rules, and a chain left behind would go on filtering a tap
/// name the next VM could be given.
pub fn teardown(tap: &str) -> String {
    let chain = chain_name(tap);
    format!("flush chain netdev {TABLE} {chain}\ndelete chain netdev {TABLE} {chain}\n")
}

// --- the router's own table, inside its own namespace -----------------------

/// Router NAT table inside the network namespace, separate from host tap guards.
pub const ROUTER_TABLE: &str = "meister-rt";

/// The router's leg on the provider network, inside the namespace.
pub const LEG_EXTERNAL: &str = "ext";
/// Its leg on the tenant's overlay, inside the namespace.
pub const LEG_INTERNAL: &str = "int";

/// Render router NAT and forwarding rules.
/// Place per-address SNAT before subnet SNAT. Use masquerade for the router's
/// own external address and explicit SNAT for another address.
pub fn router_ruleset(spec: &agent_api::networking::RouterSpec) -> Result<String, RangeError> {
    use agent_api::networking::NatKind;

    let mut s = String::new();
    // add-then-flush, exactly as the tap chains: a `delete` of a chain that is
    // not there fails, and a failing line aborts the whole atomic script.
    s.push_str(&format!("add table ip {ROUTER_TABLE}\n"));
    for (chain, decl) in [
        ("prerouting", "type nat hook prerouting priority dstnat"),
        ("postrouting", "type nat hook postrouting priority srcnat"),
        ("forward", "type filter hook forward priority filter"),
    ] {
        s.push_str(&format!(
            "add chain ip {ROUTER_TABLE} {chain} {{ {decl}; policy accept; }}\n"
        ));
        s.push_str(&format!("flush chain ip {ROUTER_TABLE} {chain}\n"));
    }

    let rule = |chain: &str, body: &str| format!("add rule ip {ROUTER_TABLE} {chain} {body}\n");

    // Drop invalid conntrack traffic and accept established or related flows.
    s.push_str(&rule(
        "forward",
        "ct state invalid counter drop comment \"ct-invalid\"",
    ));
    s.push_str(&rule(
        "forward",
        "ct state established,related counter accept comment \"ct-established\"",
    ));

    let external = address_of(&spec.external_addr);

    // The 1:1 pairs first, both directions.
    for nat in spec.nats.iter().filter(|n| n.kind == NatKind::DnatAndSnat) {
        let outside = one_address(&nat.external_ip)?;
        let inside = one_address(&nat.logical_ip)?;
        s.push_str(&rule(
            "prerouting",
            &format!(
                "iifname \"{LEG_EXTERNAL}\" ip daddr {outside} counter dnat to {inside} \
                 comment \"fip-in\""
            ),
        ));
        s.push_str(&rule(
            "postrouting",
            &format!(
                "oifname \"{LEG_EXTERNAL}\" ip saddr {inside} counter snat to {outside} \
                 comment \"fip-out\""
            ),
        ));
    }

    // ... and the whole-subnet rule behind them.
    for nat in spec.nats.iter().filter(|n| n.kind == NatKind::Snat) {
        // An empty logical_ip selects the subnet of the router's internal address.
        let inside = match nat.logical_ip.trim().is_empty() {
            true => prefix_of(&spec.internal_addr)?,
            false => prefix_of(&nat.logical_ip)?,
        };
        let how = match nat.external_ip.trim().is_empty() || nat.external_ip.trim() == external {
            true => "counter masquerade".to_string(),
            false => format!("counter snat to {}", one_address(&nat.external_ip)?),
        };
        s.push_str(&rule(
            "postrouting",
            &format!("oifname \"{LEG_EXTERNAL}\" ip saddr {inside} {how} comment \"snat\""),
        ));
    }
    Ok(s)
}

/// The address half of `a.b.c.d/n`, or the whole string when there is no
/// prefix on it. What `ip addr add` is given, and what an `snat` rule is
/// compared against.
pub fn address_of(cidr: &str) -> &str {
    let cidr = cidr.trim();
    match cidr.split_once('/') {
        Some((addr, _)) => addr,
        None => cidr,
    }
}

/// Require a single IPv4 address for an address-to-address NAT rule.
fn one_address(raw: &str) -> Result<String, RangeError> {
    let range: common::net::Ipv4Range = raw.parse()?;
    match range.len() == 1 {
        true => Ok(range.first().to_string()),
        false => Err(RangeError::Malformed(format!(
            "{raw} is a range of {} addresses, and a nat rule is about one",
            range.len()
        ))),
    }
}

/// The canonical prefix a CIDR names — `10.7.1.1/24` is the subnet
/// `10.7.1.0/24`, which is what a source-address match has to say.
fn prefix_of(raw: &str) -> Result<String, RangeError> {
    let range: common::net::Ipv4Range = raw.parse()?;
    range
        .to_cidr()
        .ok_or_else(|| RangeError::Malformed(format!("{raw} is not a prefix")))
}

/// The `nft` process, and the one thing worth saying about running it: the
/// script goes in on stdin, so a rule containing a set literal never has to
/// survive an argv split.
#[derive(Clone, Debug)]
pub struct Nft {
    binary: String,
}

impl Nft {
    /// Create the guard table to verify both nft availability and permission to use it.
    pub fn new(binary: String) -> Result<Self, NetworkError> {
        let nft = Self { binary };
        let script = format!("add table netdev {TABLE}\n");
        match nft.run_blocking(&script) {
            Ok(()) => {
                info!(table = TABLE, "nftables ready");
                Ok(nft)
            }
            Err(e) => Err(NetworkError::Backend(anyhow::anyhow!(
                "this node cannot program nftables ({e}); every tap gets a mac-pinning rule, \
                 so a node that cannot write them must not pretend to. Install nftables, run \
                 the agent as root, or point `nft` in the agent config at the right binary"
            ))),
        }
    }

    /// Expose the nft executable for commands run inside router namespaces.
    pub fn binary(&self) -> &str {
        &self.binary
    }

    fn run_blocking(&self, script: &str) -> anyhow::Result<()> {
        use std::io::Write;
        let mut child = std::process::Command::new(&self.binary)
            .args(["-f", "-"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| anyhow::anyhow!("running {}: {e}", self.binary))?;
        child
            .stdin
            .take()
            .ok_or_else(|| anyhow::anyhow!("nft stdin vanished"))?
            .write_all(script.as_bytes())?;
        let out = child.wait_with_output()?;
        if out.status.success() {
            return Ok(());
        }
        anyhow::bail!(
            "nft refused the ruleset: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        )
    }

    async fn run(&self, script: &str) -> anyhow::Result<()> {
        use tokio::io::AsyncWriteExt;
        let mut child = tokio::process::Command::new(&self.binary)
            .args(["-f", "-"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| anyhow::anyhow!("running {}: {e}", self.binary))?;
        child
            .stdin
            .take()
            .ok_or_else(|| anyhow::anyhow!("nft stdin vanished"))?
            .write_all(script.as_bytes())
            .await?;
        let out = child.wait_with_output().await?;
        if out.status.success() {
            return Ok(());
        }
        anyhow::bail!(
            "nft refused the ruleset: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        )
    }

    /// Build this tap's chain. Atomic and idempotent: the whole script is one
    /// nft transaction, so a tap is never half-guarded.
    #[instrument(skip_all, fields(tap = %tap))]
    pub async fn guard(
        &self,
        tap: &str,
        spec: &NicSpec,
        guarded: &Ipv4Ranges,
    ) -> Result<(), NetworkError> {
        let script = ruleset(tap, spec, guarded).map_err(|e| {
            NetworkError::InvalidSpec(format!("this nic names an address that is not one: {e}"))
        })?;
        debug!(script = %script.trim(), "applying tap rules");
        self.run(&script)
            .await
            .map_err(|e| NetworkError::Backend(anyhow::anyhow!(e)))?;
        info!(
            floating = spec.floating_ips.len(),
            subnets = spec.routed_subnets.len(),
            mode = if spec.routed_subnets.is_empty() {
                "pool-guard"
            } else {
                "allowlist"
            },
            "tap guarded"
        );
        Ok(())
    }

    /// Best-effort chain deletion before tap removal; failures are logged at debug level.
    #[instrument(skip_all, fields(tap = %tap))]
    pub async fn unguard(&self, tap: &str) {
        if let Err(e) = self.run(&teardown(tap)).await {
            debug!(error = %format!("{e:#}"), "no chain to remove for this tap");
        }
    }

    /// Remove chains absent from the supplied tap inventory.
    /// The caller must provide a complete inventory; this function does not inspect VM records.
    #[instrument(skip_all)]
    pub async fn reap(&self, live_taps: &[String]) {
        let existing = match self.chains().await {
            Ok(c) => c,
            Err(e) => {
                warn!(error = %format!("{e:#}"), "could not list the tap chains, skipping the reap");
                return;
            }
        };
        let wanted: Vec<String> = live_taps.iter().map(|t| chain_name(t)).collect();
        let stale: Vec<&String> = existing.iter().filter(|c| !wanted.contains(c)).collect();
        if stale.is_empty() {
            return;
        }
        let script: String = stale
            .iter()
            .map(|chain| {
                format!("flush chain netdev {TABLE} {chain}\ndelete chain netdev {TABLE} {chain}\n")
            })
            .collect();
        match self.run(&script).await {
            Ok(()) => info!(count = stale.len(), "reaped tap chains with no tap"),
            Err(e) => warn!(error = %format!("{e:#}"), "could not reap stale tap chains"),
        }
    }

    /// The chain names in our table, out of `nft -j list table`.
    async fn chains(&self) -> anyhow::Result<Vec<String>> {
        let out = tokio::process::Command::new(&self.binary)
            .args(["-j", "list", "table", "netdev", TABLE])
            .output()
            .await?;
        if !out.status.success() {
            // No table = nothing to reap, which is the state of a node that
            // has not booted a VM yet.
            return Ok(Vec::new());
        }
        Ok(chain_names(&String::from_utf8_lossy(&out.stdout)))
    }
}

/// Extract chain names from nft JSON; malformed or unexpected input returns no names.
pub fn chain_names(json: &str) -> Vec<String> {
    let Ok(doc) = serde_json::from_str::<serde_json::Value>(json) else {
        return Vec::new();
    };
    doc.get("nftables")
        .and_then(|n| n.as_array())
        .map(|items| {
            items
                .iter()
                .filter_map(|item| item.get("chain")?.get("name")?.as_str())
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use agent_api::types::mac_addr::MacAddr;

    fn spec(floating: &[&str], subnets: &[&str]) -> NicSpec {
        NicSpec {
            physnet: None,
            bridge: "meister_br0".into(),
            mac: "52:54:00:11:22:33".parse::<MacAddr>().unwrap(),
            vxlan_id: None,
            floating_ips: floating.iter().map(|s| s.to_string()).collect(),
            routed_subnets: subnets.iter().map(|s| s.to_string()).collect(),
        }
    }

    /// Provider NICs keep MAC pinning without tenant address rules.
    #[test]
    fn a_tap_on_a_provider_network_is_fenced_by_its_mac_and_by_nothing_else() {
        let mut on_the_wire = spec(&["203.0.113.7"], &["10.31.0.0/24"]);
        on_the_wire.physnet = Some("ext".into());
        let script = ruleset("msk0", &on_the_wire, &pool(&["10.255.0.0/16"])).unwrap();
        let only = rules(&script);
        assert_eq!(only.len(), 1, "{only:?}");
        assert!(only[0].contains("mac-spoof"), "{only:?}");

        // The same spec WITHOUT the physnet is the overlay tap it always was,
        // fenced to the tenant's own space.
        let overlay = spec(&["203.0.113.7"], &["10.31.0.0/24"]);
        let script = ruleset("msk0", &overlay, &pool(&["10.255.0.0/16"])).unwrap();
        let fenced = rules(&script);
        assert!(fenced.iter().any(|r| r.contains("src-arp")), "{fenced:?}");
        assert!(
            fenced.iter().any(|r| r.contains("10.31.0.0-10.31.0.255")),
            "{fenced:?}"
        );
    }

    fn pool(entries: &[&str]) -> Ipv4Ranges {
        Ipv4Ranges::parse(&entries.iter().map(|s| s.to_string()).collect::<Vec<_>>()).unwrap()
    }

    fn rules(script: &str) -> Vec<&str> {
        script
            .lines()
            .filter_map(|l| l.strip_prefix("add rule netdev meister meister-msk0 "))
            .collect()
    }

    /// The compatibility invariant of this milestone, at the tier that enforces
    /// it: a node with no pool and a VM with no reservations gets ONE rule, and
    /// it is the one that is true of every VM this stack has ever booted.
    #[test]
    fn a_tap_with_nothing_configured_still_gets_its_mac_pinned() {
        let script = ruleset("msk0", &spec(&[], &[]), &Ipv4Ranges::default()).unwrap();
        let only = rules(&script);
        assert_eq!(only.len(), 1, "{script}");
        assert_eq!(
            only[0],
            "ether saddr != 52:54:00:11:22:33 counter drop comment \"mac-spoof\""
        );
    }

    /// Use add and flush so both initial and repeated batches can create the chain.
    #[test]
    fn the_chain_is_rebuilt_whole_and_applying_twice_is_applying_once() {
        let script = ruleset("msk0", &spec(&[], &[]), &pool(&["10.255.0.0/16"])).unwrap();
        assert!(script.starts_with("add table netdev meister\n"), "{script}");
        assert!(
            script.contains(
                "add chain netdev meister meister-msk0 { type filter hook ingress device msk0 \
             priority 0; policy accept; }"
            ),
            "{script}"
        );
        assert!(
            script.contains("flush chain netdev meister meister-msk0\n"),
            "{script}"
        );
        assert!(
            !script.contains("delete chain"),
            "a delete would abort the transaction"
        );
    }

    /// Part A: the pool is forbidden on every tap, and the VM's own
    /// reservations are the exception — accepted BEFORE the ban, or the ban
    /// would win.
    #[test]
    fn the_pool_is_banned_everywhere_except_where_it_is_held() {
        let guarded = pool(&["10.255.0.0/16", "203.0.113.7"]);
        let holder = ruleset("msk0", &spec(&["10.255.0.7"], &[]), &guarded).unwrap();
        let held = rules(&holder);
        assert_eq!(held.len(), 5, "{holder}");
        assert_eq!(held[1], "meta protocol ip ip saddr { 10.255.0.7 } accept");
        assert_eq!(
            held[2],
            "meta protocol arp arp saddr ip { 10.255.0.7 } accept"
        );
        assert!(
            held[3].starts_with(
                "meta protocol ip ip saddr { 10.255.0.0-10.255.255.255, 203.0.113.7 } counter drop"
            ),
            "{}",
            held[3]
        );
        assert!(held[4].contains("arp saddr ip") && held[4].contains("counter drop"));
        // The accepts come first, or the exception is not one.
        assert!(holder.find("accept\n").unwrap() < holder.find("pool-ip").unwrap());

        // A VM of the same tenant WITHOUT the reservation gets the ban and no
        // exception — which is the "A2 is dropped" half of the E2E.
        let plain = ruleset("msk0", &spec(&[], &[]), &guarded).unwrap();
        let other = rules(&plain);
        assert_eq!(other.len(), 3);
        assert!(other[1].contains("pool-ip"), "{}", other[1]);
    }

    /// Part B: a tenant whose address space is written down gets the strong
    /// rule instead of the weak one — these, and nothing else.
    #[test]
    fn a_tenant_with_a_routed_subnet_gets_an_allowlist_instead() {
        let script = ruleset(
            "msk0",
            &spec(&["10.255.0.7"], &["10.7.1.0/24"]),
            &pool(&["10.255.0.0/16"]),
        )
        .unwrap();
        let listed = rules(&script);
        assert_eq!(listed.len(), 3, "{script}");
        assert_eq!(
            listed[1],
            "meta protocol ip ip saddr != { 10.7.1.0-10.7.1.255, 10.255.0.7, 0.0.0.0 } \
             counter drop comment \"src-ip\""
        );
        assert!(listed[2].contains("arp saddr ip != {"), "{}", listed[2]);
        // The pool ban is gone, and it is not missing: an allowlist that does
        // not contain a pool address already forbids it, and the cloud refuses
        // a subnet that overlaps a pool.
        assert!(!script.contains("pool-ip"), "{script}");
    }

    /// Allow initial DHCP and ARP probes before a guest has an address.
    #[test]
    fn a_guest_may_always_speak_before_it_has_an_address() {
        let script = ruleset("msk0", &spec(&[], &["10.7.1.0/24"]), &Ipv4Ranges::default()).unwrap();
        assert!(script.contains("0.0.0.0"), "{script}");
    }

    /// Every drop carries a counter and a name. That is the proof in the E2E
    /// and the hook a security-group story reads later.
    #[test]
    fn every_drop_is_counted_and_named() {
        for script in [
            ruleset("msk0", &spec(&[], &[]), &Ipv4Ranges::default()).unwrap(),
            ruleset(
                "msk0",
                &spec(&["10.255.0.7"], &[]),
                &pool(&["10.255.0.0/16"]),
            )
            .unwrap(),
            ruleset(
                "msk0",
                &spec(&[], &["10.7.1.0/24"]),
                &pool(&["10.255.0.0/16"]),
            )
            .unwrap(),
        ] {
            for rule in rules(&script).iter().filter(|r| r.contains("drop")) {
                assert!(rule.contains("counter "), "uncounted drop: {rule}");
                assert!(rule.contains("comment \""), "unnamed drop: {rule}");
            }
        }
    }

    /// An address that is not one must be a refusal and not a chain that says
    /// something else. `nft` would refuse it too — but at VM-boot time, in a
    /// message about syntax rather than about the spec.
    #[test]
    fn an_address_that_is_not_one_is_refused_before_nft_sees_it() {
        let err = ruleset(
            "msk0",
            &spec(&["not-an-address"], &[]),
            &Ipv4Ranges::default(),
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("not-an-address"), "{err}");
    }

    /// Flush before delete, because nftables refuses to delete a chain that
    /// still holds rules — and a chain left behind would filter a tap name.
    #[test]
    fn a_teardown_empties_the_chain_before_removing_it() {
        let script = teardown("msk0");
        assert_eq!(
            script,
            "flush chain netdev meister meister-msk0\n\
             delete chain netdev meister meister-msk0\n"
        );
    }

    /// The one place `nft`'s json shape is assumed, asserted instead — a reap
    /// that silently found nothing would look exactly like a clean node.
    #[test]
    fn the_chain_names_come_out_of_the_json_listing() {
        let json = r#"{"nftables":[
            {"metainfo":{"version":"1.1.6","json_schema_version":1}},
            {"chain":{"family":"netdev","table":"meister","name":"meister-msk1","dev":"msk1"}},
            {"rule":{"family":"netdev","table":"meister","chain":"meister-msk1"}},
            {"chain":{"family":"netdev","table":"meister","name":"meister-msk2","dev":"msk2"}}
        ]}"#;
        assert_eq!(chain_names(json), ["meister-msk1", "meister-msk2"]);
        assert!(
            chain_names("not json").is_empty(),
            "a broken listing reaps nothing"
        );
        assert!(chain_names(r#"{"nftables":[]}"#).is_empty());
    }

    /// The name is what an operator greps for, and what the E2E greps for.
    #[test]
    fn a_chain_is_named_after_its_tap() {
        assert_eq!(chain_name("msk1a2b3c4d"), "meister-msk1a2b3c4d");
    }

    // --- the router's table ---------------------------------------------------

    use agent_api::networking::{NatKind, NatRule, RouterId, RouterSpec};

    fn router(nats: Vec<NatRule>) -> RouterSpec {
        RouterSpec {
            id: RouterId::from_u128(1),
            physnet: "ext".into(),
            external_addr: "203.0.113.10/24".into(),
            external_gateway: "203.0.113.1".into(),
            vxlan_id: 10_000,
            internal_addr: "10.7.1.1/24".into(),
            nats,
            routed_subnets: Vec::new(),
            active: true,
        }
    }

    fn router_rules<'a>(script: &'a str, chain: &str) -> Vec<&'a str> {
        let prefix = format!("add rule ip meister-rt {chain} ");
        script
            .lines()
            .filter_map(|l| l.strip_prefix(prefix.as_str()))
            .collect()
    }

    fn snat(external: &str, logical: &str) -> NatRule {
        NatRule {
            kind: NatKind::Snat,
            external_ip: external.into(),
            logical_ip: logical.into(),
        }
    }

    fn fip(external: &str, logical: &str) -> NatRule {
        NatRule {
            kind: NatKind::DnatAndSnat,
            external_ip: external.into(),
            logical_ip: logical.into(),
        }
    }

    /// A router without NAT still renders forwarding rules.
    #[test]
    fn a_router_that_translates_nothing_still_forwards_and_counts() {
        let script = router_ruleset(&router(Vec::new())).unwrap();
        assert!(script.starts_with("add table ip meister-rt\n"), "{script}");
        assert!(
            script.contains(
                "add chain ip meister-rt postrouting \
                 { type nat hook postrouting priority srcnat; policy accept; }"
            ),
            "{script}"
        );
        assert!(
            !script.contains("delete chain"),
            "a delete would abort the transaction, exactly as on the tap side"
        );
        assert!(router_rules(&script, "prerouting").is_empty(), "{script}");
        assert!(router_rules(&script, "postrouting").is_empty(), "{script}");
        assert_eq!(
            router_rules(&script, "forward"),
            [
                "ct state invalid counter drop comment \"ct-invalid\"",
                "ct state established,related counter accept comment \"ct-established\"",
            ]
        );
    }

    /// Empty logical_ip selects the canonical internal subnet.
    #[test]
    fn snat_without_a_subnet_means_the_one_the_router_is_standing_in() {
        let script = router_ruleset(&router(vec![snat("203.0.113.10", "")])).unwrap();
        assert_eq!(
            router_rules(&script, "postrouting"),
            ["oifname \"ext\" ip saddr 10.7.1.0/24 counter masquerade comment \"snat\""]
        );
    }

    /// Use explicit SNAT when a rule names another external address.
    #[test]
    fn a_snat_rule_naming_another_address_is_rendered_as_that_address() {
        let script = router_ruleset(&router(vec![snat("203.0.113.77", "10.7.9.0/24")])).unwrap();
        assert_eq!(
            router_rules(&script, "postrouting"),
            ["oifname \"ext\" ip saddr 10.7.9.0/24 counter snat to 203.0.113.77 comment \"snat\""]
        );
    }

    /// Per-address NAT precedes subnet SNAT.
    #[test]
    fn a_floating_address_is_a_pair_and_it_comes_before_the_subnet_rule() {
        let script = router_ruleset(&router(vec![
            snat("203.0.113.10", ""),
            fip("203.0.113.55", "10.7.1.9"),
        ]))
        .unwrap();
        assert_eq!(
            router_rules(&script, "prerouting"),
            ["iifname \"ext\" ip daddr 203.0.113.55 counter dnat to 10.7.1.9 comment \"fip-in\""]
        );
        assert_eq!(
            router_rules(&script, "postrouting"),
            [
                "oifname \"ext\" ip saddr 10.7.1.9 counter snat to 203.0.113.55 \
                 comment \"fip-out\"",
                "oifname \"ext\" ip saddr 10.7.1.0/24 counter masquerade comment \"snat\"",
            ]
        );
    }

    /// Every drop and every translation carries a counter and a name, exactly
    /// as on the tap side: `nft list table ip meister-rt` inside the namespace
    /// is what proves which rule did what.
    #[test]
    fn every_router_rule_is_counted_and_named() {
        let script = router_ruleset(&router(vec![
            snat("203.0.113.10", ""),
            fip("203.0.113.55", "10.7.1.9"),
        ]))
        .unwrap();
        for chain in ["prerouting", "postrouting", "forward"] {
            for rule in router_rules(&script, chain) {
                assert!(rule.contains("counter "), "uncounted: {rule}");
                assert!(rule.contains("comment \""), "unnamed: {rule}");
            }
        }
    }

    /// Reject address ranges where a NAT rule requires one address.
    #[test]
    fn a_nat_rule_that_names_a_range_instead_of_an_address_is_refused() {
        let err = router_ruleset(&router(vec![fip("203.0.113.55", "10.7.1.0/24")]))
            .unwrap_err()
            .to_string();
        assert!(err.contains("nat rule is about one"), "{err}");

        let err = router_ruleset(&router(vec![fip("not-an-address", "10.7.1.9")]))
            .unwrap_err()
            .to_string();
        assert!(err.contains("not-an-address"), "{err}");
    }

    /// The two helpers the rest of the driver reads a CIDR with.
    #[test]
    fn the_address_half_of_a_cidr_is_what_a_router_answers_for() {
        assert_eq!(address_of("203.0.113.10/24"), "203.0.113.10");
        assert_eq!(address_of("203.0.113.10"), "203.0.113.10");
        assert_eq!(prefix_of("10.7.1.1/24").unwrap(), "10.7.1.0/24");
        assert!(prefix_of("10.7.1.1-10.7.1.9").is_err());
    }
}
