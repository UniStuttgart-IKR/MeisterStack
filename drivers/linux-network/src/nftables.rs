// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! What a tap is allowed to send, enforced where the guest's frames first
//! reach the host.
//!
//! ## Why netdev/ingress and not the filter chains
//!
//! A tap on a bridge is not routed and not forwarded by the IP stack, so
//! nothing a guest sends passes `hook forward` unless somebody has turned
//! `br_netfilter` on — a module with its own performance story and its own
//! surprises, and one this driver has no business demanding. The netdev family
//! attaches a chain to ONE device at its ingress, which for a tap means
//! exactly the frames the guest emitted, before bridging, before anything. It
//! is the earliest and cheapest place to say no, it sees ARP as readily as IP
//! because it sees raw frames, and it needs no module and no sysctl.
//!
//! One chain per tap, named after it (`meister-msk1a2b3c4d`), in one table
//! (`netdev meister`) this driver owns outright. The chain is rebuilt whole on
//! every create — `add` then `flush` then the rules, in one atomic `nft -f` —
//! so applying it twice is applying it once, and a tap whose VM was given
//! another address gets the new truth at its next boot rather than an
//! accumulation of both.
//!
//! ## The three rules, in the order they matter
//!
//! 1. **MAC pinning, on every tap there is.** We hand out the MAC addresses,
//!    so a frame from this tap with any other source MAC is a frame nobody
//!    legitimately sent. This one does not depend on floating addresses, on
//!    pools, or on anything being configured: it is true of every VM this
//!    stack has ever booted, and a guest running `ip link set eth0 address …`
//!    is either confused or hostile.
//!
//! 2. **The pool guard**, when the node has `guarded_ranges` and the VM's
//!    tenant has no routed subnet. Source addresses (and ARP claims) inside
//!    the floating pool are dropped on EVERY tap, with an accept in front of
//!    it for the addresses this VM actually holds. No IPAM is needed for this
//!    and none is wanted: we forbid only the addresses we hand out, never the
//!    tenant's own — which we do not know and have no business knowing.
//!
//! 3. **The allowlist**, when the tenant HAS routed subnets. Then the tenant's
//!    address space is written down, so the rule can be the strong one:
//!    these subnets, these floating addresses, and nothing else. This is the
//!    same guard turned inside out, and it is why Part B completes Part A
//!    rather than sitting beside it.
//!
//! Every drop carries a `counter` and a comment. That is the proof in the E2E
//! — `nft list chain netdev meister meister-<tap>` shows which rule stopped
//! what — and it is the hook a future Phase-D security-group story reads
//! rather than reinvents.
//!
//! ## What is deliberately NOT filtered
//!
//! IPv6 and everything that is neither IPv4 nor ARP pass untouched. The
//! address model of this milestone is IPv4 (see `common::net`), and a rule
//! written against addresses nobody allocates would be a rule nobody can
//! debug. A node that wants v6 anti-spoofing wants a v6 address model first.
//! Inbound traffic is untouched too: this is an egress guard, and what may
//! reach a guest is the environment's firewall, not ours.

use std::process::Stdio;

use agent_api::networking::{NetworkError, NicSpec};
use common::net::{Ipv4Ranges, RangeError};
use tracing::{debug, info, instrument, warn};

/// The table this driver owns. Nothing else writes into it, and a `nft list
/// table netdev meister` is the whole of what this stack has to say about
/// filtering.
pub const TABLE: &str = "meister";

/// `0.0.0.0`, which a guest sources from before it has an address at all
/// (DHCP DISCOVER, and the ARP probe of duplicate-address detection). Always
/// allowed: it is not an address anybody can impersonate with, and dropping it
/// would break the one thing a fresh guest does first.
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
    /// The union of every floating pool's ranges, from the agent's own
    /// `guarded_ranges`.
    ///
    /// Deliberate duplication of what the cloud holds in FloatingPool objects,
    /// and the honest v1 trade: the deny rule needs the whole union on the
    /// node, and the node has no way to ask the cloud for it — the session
    /// carries commands about VMs, not a catalogue of pools.
    ///
    /// REFACTOR, not built here: push the pools down the session the way the
    /// vni is pushed down, and this key becomes a fallback. That is the same
    /// milestone as pushing a VXLAN peer list down (see the module doc in
    /// lib.rs), it is the same mechanism twice, and doing either one alone
    /// buys half a feature.
    pub guarded: Ipv4Ranges,
}

/// The rules for one tap, as an `nft -f` script.
///
/// Pure and returned as text rather than executed, because the interesting
/// part of this driver is WHICH rules a spec produces and that is worth
/// asserting without a kernel. The runner below is four lines around a pipe.
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
        // 2. The tenant's own addresses are unknown, so forbid only ours —
        //    with this VM's own reservations accepted in front of the ban.
        //    Accept and not "!=" so that a VM holding two of the pool's
        //    addresses needs one rule per direction and not one per address.
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

/// The `nft` process, and the one thing worth saying about running it: the
/// script goes in on stdin, so a rule containing a set literal never has to
/// survive an argv split.
#[derive(Clone, Debug)]
pub struct Nft {
    binary: String,
}

impl Nft {
    /// Check at start-up that this node can actually program nftables, exactly
    /// as the lvm-thin driver checks its pool there rather than at the first
    /// volume.
    ///
    /// It is a hard error and not a warning, and that is the security half of
    /// this milestone in one decision: MAC pinning applies to every VM, so a
    /// node that cannot write rules is a node that cannot keep the promise
    /// this driver now makes. Starting anyway and logging about it would be a
    /// stack that says it pins MACs and does not.
    ///
    /// Creating the table is the check. Anything less — `nft --version` — would
    /// prove the binary exists and not that this process may use it, and the
    /// failure that actually happens is the second one.
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

    /// Take the chain away with the tap.
    ///
    /// A failure is a warning and not an error, on purpose: the caller is a
    /// teardown, the tap itself is about to be deleted, and a netdev chain
    /// whose device is gone is removed by the kernel anyway. Failing the
    /// teardown over it would strand a VM whose disks are already released.
    #[instrument(skip_all, fields(tap = %tap))]
    pub async fn unguard(&self, tap: &str) {
        if let Err(e) = self.run(&teardown(tap)).await {
            debug!(error = %format!("{e:#}"), "no chain to remove for this tap");
        }
    }

    /// Every chain in the table whose tap no longer exists.
    ///
    /// Called at start-up with the taps this node knows about. A chain left
    /// behind by a `kill -9` between "delete the chain" and "delete the tap"
    /// is harmless while the tap is gone — but tap names are derived from NIC
    /// uuids, so it would be a stale rule waiting for a name nobody will reuse.
    /// Reaping them keeps `nft list ruleset` honest, which is what the E2E
    /// asserts and what an operator reads.
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

/// The chain names in `nft -j list table` output.
///
/// Its own function so the JSON shape is asserted rather than assumed: `nft`'s
/// json_schema_version has moved before and this is the one place a change
/// would be silent — a reap that finds nothing looks exactly like a node with
/// nothing to reap.
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
            bridge: "meister_br0".into(),
            mac: "52:54:00:11:22:33".parse::<MacAddr>().unwrap(),
            vxlan_id: None,
            floating_ips: floating.iter().map(|s| s.to_string()).collect(),
            routed_subnets: subnets.iter().map(|s| s.to_string()).collect(),
        }
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

    /// The chain is built with add-then-flush and never with delete: a delete
    /// of a chain that is not there fails, and a failing line aborts the whole
    /// atomic script — so the first apply would work and every one after a
    /// restart would not.
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

    /// `0.0.0.0` is always in the allowlist. It is what a guest sources from
    /// before it has an address at all — DHCP DISCOVER and the ARP probe of
    /// duplicate-address detection — and it is not an address anybody can
    /// impersonate with.
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
}
