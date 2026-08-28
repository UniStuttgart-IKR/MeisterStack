// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! BGP to the host, and EVPN instead of multicast — both of them FRR's work,
//! not ours.
//!
//! ## Why adapt rather than build
//!
//! A BGP speaker is a protocol implementation with thirty years of corner
//! cases in it, and writing a bad one is the classic way to take a network
//! down from the inside. FRR is the one in every switch OS worth naming, it
//! is one package in nixpkgs, and it takes its configuration as text. So this
//! module is a renderer and a `vtysh` call: it decides WHAT to say and FRR
//! decides how to say it. The same relationship the storage side has with
//! virtiofsd, and the same reason.
//!
//! ## What "BGP to the host" means here
//!
//! The agent announces a `/32` for every floating address held by a VM that is
//! RUNNING ON THIS NODE, and withdraws it the moment that stops being true.
//! The set is recomputed from the reconciler's own observation on every pass
//! and applied as a whole — level-triggered, not event-driven, exactly like
//! everything else in this stack. A missed transition is not a stuck route; it
//! is a route the next pass corrects.
//!
//! **The withdraw semantics ARE the failover**, and that is the sentence worth
//! keeping. Move a VM to another node and two things happen without anybody
//! coordinating them: the first node's next pass no longer sees the VM and
//! withdraws the `/32`, and the second node's next pass sees it and announces
//! the same `/32`. The upstream router's best path moves. That is MetalLB's
//! BGP mode, arrived at from the other direction — and the reason a floating
//! address is worth having as an object rather than as a note in a runbook.
//!
//! ## What is deliberately NOT announced
//!
//! **Routed subnets.** A subnet spans hosts by definition — it is the tenant's
//! address space, and the VMs in it are wherever the scheduler put them — so a
//! per-host announcement of one would be every node claiming the whole prefix
//! and the router load-balancing onto hosts that hold none of it. Announcing a
//! subnet is somebody's job, and that somebody is either a static route in the
//! environment or the tenant's own appliance speaking for its own space. v1
//! says so and stops there.
//!
//! **A route to the VM.** `no bgp network import-check` is set precisely
//! because the `/32` is NOT in this host's routing table: the address lives on
//! a guest behind a bridge and the guest answers for it. Installing the host
//! route would be a data path, and this milestone builds reservation,
//! enforcement and announcement — not data paths. What makes the announced
//! address actually reachable is the environment's: a route towards the
//! bridge, or the tenant appliance that claims it by ARP.
//!
//! ## EVPN
//!
//! `advertise-all-vni` in the `l2vpn evpn` address family turns FRR into the
//! thing that distributes the overlay's MAC addresses (type-2) and its
//! flooding list (type-3), which is what makes the VXLAN devices' multicast
//! group unnecessary — see `LinuxNetworkDriver::ensure_overlay`, where `evpn`
//! swaps the group for a `local` address and turns kernel learning off. Off by
//! default: multicast is M5's behaviour, it needs no daemon at all, and a lab
//! switch carries it.

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::process::Stdio;

use agent_api::networking::NetworkError;
use macros::generated;
use tokio::sync::Mutex;
use tracing::{debug, info, instrument, warn};

/// One BGP peer.
#[derive(Clone, Debug)]
pub struct Neighbor {
    pub address: String,
    pub remote_asn: u32,
}

/// `[network.bgp]`, resolved.
#[derive(Clone, Debug)]
pub struct BgpConfig {
    pub asn: u32,
    /// The BGP identifier, an address in dotted form. Set explicitly rather
    /// than left to FRR's own pick: FRR would take the highest address on the
    /// box, which on a node full of bridges and taps is whatever the last VM
    /// happened to create.
    pub router_id: String,
    pub neighbors: Vec<Neighbor>,
    /// Where `vtysh` is. FRR is an external daemon out of nixpkgs, exactly as
    /// virtiofsd is on the storage side.
    pub vtysh: PathBuf,
    /// FRR's vty socket directory, for a node that does not use the default
    /// `/var/run/frr` — which is every second agent on one host, and every
    /// FRR in a network namespace.
    pub vty_socket: Option<PathBuf>,
    /// Where the rendered fragment is written before `vtysh -f` reads it.
    /// A file and not a pipe, because an operator debugging a session wants to
    /// read exactly what this node asked FRR for.
    pub fragment: PathBuf,
    /// Add the `l2vpn evpn` half. Comes from `[network.vxlan] evpn`, not from
    /// this section: it is a property of how the overlay works and the BGP
    /// section is only where it is carried out.
    pub evpn: bool,
}

/// The FRR fragment for a set of announcements.
///
/// Pure, and returned as text: which lines this node asks FRR for is the whole
/// of what is interesting here, and it is worth asserting without a daemon.
///
/// `withdrawn` are the prefixes that were announced last time and are not any
/// more. They need explicit `no network` lines because `vtysh -f` MERGES — it
/// is FRR's own reload path and it adds what it reads. A renderer that only
/// ever emitted `network` lines would be a renderer whose announcements never
/// went away, which is the one thing this feature is for.
#[generated(model = ClaudeOpus, version = "5")]
pub fn fragment(
    cfg: &BgpConfig,
    announced: &BTreeSet<String>,
    withdrawn: &BTreeSet<String>,
) -> String {
    let mut s = String::new();
    s.push_str("! meisterstack: generated, do not edit\n");
    s.push_str(&format!("router bgp {}\n", cfg.asn));
    s.push_str(&format!(" bgp router-id {}\n", cfg.router_id));
    // Modern FRR refuses to advertise anything to an eBGP peer without an
    // explicit policy (RFC 8212). That is the right default for a router on
    // the internet and the wrong one for a host announcing its own /32s to
    // the rack switch, which is what this is.
    s.push_str(" no bgp ebgp-requires-policy\n");
    // The /32 is NOT in this host's routing table and is not meant to be: the
    // address lives on a guest behind a bridge. Without this, FRR would
    // originate nothing and the fragment would look like it worked.
    s.push_str(" no bgp network import-check\n");
    for n in &cfg.neighbors {
        s.push_str(&format!(
            " neighbor {} remote-as {}\n",
            n.address, n.remote_asn
        ));
    }
    s.push_str(" address-family ipv4 unicast\n");
    for n in &cfg.neighbors {
        s.push_str(&format!("  neighbor {} activate\n", n.address));
    }
    for prefix in announced {
        s.push_str(&format!("  network {prefix}\n"));
    }
    for prefix in withdrawn {
        s.push_str(&format!("  no network {prefix}\n"));
    }
    s.push_str(" exit-address-family\n");
    if cfg.evpn {
        s.push_str(" address-family l2vpn evpn\n");
        for n in &cfg.neighbors {
            s.push_str(&format!("  neighbor {} activate\n", n.address));
        }
        // The whole EVPN half in one line: FRR reads the kernel's VXLAN
        // devices and their bridges, advertises the MACs it learns on them as
        // type-2 routes and the VTEP itself as type-3, and the receiving
        // nodes program their own FDBs from that. What used to be a multicast
        // group is now a BGP session.
        s.push_str("  advertise-all-vni\n");
        s.push_str(" exit-address-family\n");
    }
    s.push_str("exit\n");
    s
}

/// A floating address as a host route.
pub fn host_prefix(address: &str) -> String {
    format!("{address}/32")
}

/// FRR, kept level with what this node should be announcing.
pub struct Frr {
    cfg: BgpConfig,
    /// What the last successful apply left FRR saying. The diff against it is
    /// what produces the `no network` lines — see `fragment`.
    ///
    /// In memory and not read back from FRR, deliberately: an agent restart
    /// starts with an empty set, so the first pass after one re-announces
    /// everything (which is idempotent) and withdraws nothing (which is right
    /// — FRR kept running and kept its own state, and a withdrawal of
    /// something we never announced is a no-op FRR ignores).
    announced: Mutex<BTreeSet<String>>,
}

#[generated(model = ClaudeOpus, version = "5")]
impl Frr {
    /// Check at start-up that FRR is there and answering, exactly as the
    /// lvm-thin driver looks for its pool there.
    ///
    /// A hard error, because `[network.bgp]` being present is a node SAYING it
    /// announces its floating addresses. Starting without a daemon to say it
    /// to would be a node whose addresses look announced in every log line and
    /// reach nothing — the failure this check exists to make loud.
    pub async fn new(cfg: BgpConfig) -> Result<Self, NetworkError> {
        let frr = Self {
            cfg,
            announced: Mutex::new(BTreeSet::new()),
        };
        // `show version` needs a live daemon behind the vty socket, which is
        // the thing actually being checked. A `--help` would prove the binary
        // exists and not that FRR is running.
        match frr.vtysh(&["-c", "show version"]).await {
            Ok(out) => {
                info!(
                    asn = frr.cfg.asn,
                    router_id = %frr.cfg.router_id,
                    neighbors = frr.cfg.neighbors.len(),
                    evpn = frr.cfg.evpn,
                    version = out.lines().next().unwrap_or("").trim(),
                    "frr ready"
                );
                Ok(frr)
            }
            Err(e) => Err(NetworkError::Backend(anyhow::anyhow!(
                "[network.bgp] is configured but frr does not answer ({e}); this node would \
                 claim to announce its floating addresses and announce nothing. Start frr \
                 (bgpd and zebra), or point `vtysh`/`vty_socket` at the right paths"
            ))),
        }
    }

    async fn vtysh(&self, args: &[&str]) -> anyhow::Result<String> {
        let mut cmd = tokio::process::Command::new(&self.cfg.vtysh);
        if let Some(dir) = &self.cfg.vty_socket {
            cmd.arg("--vty_socket").arg(dir);
        }
        let out = cmd
            .args(args)
            .stdin(Stdio::null())
            .output()
            .await
            .map_err(|e| anyhow::anyhow!("running {}: {e}", self.cfg.vtysh.display()))?;
        let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
        if !out.status.success() {
            anyhow::bail!(
                "vtysh {} failed ({}): {}{}",
                args.join(" "),
                out.status,
                String::from_utf8_lossy(&out.stderr).trim(),
                stdout.trim()
            );
        }
        Ok(stdout)
    }

    /// Make FRR announce exactly `want` and nothing else.
    ///
    /// Level-triggered and idempotent: the caller hands over the whole set on
    /// every reconcile pass, and a pass that changes nothing writes nothing —
    /// which matters, because `vtysh -f` is not free and a reconcile pass runs
    /// every thirty seconds for the lifetime of the node.
    #[instrument(skip_all, fields(want = want.len()))]
    pub async fn announce(&self, want: BTreeSet<String>) -> Result<(), NetworkError> {
        let mut announced = self.announced.lock().await;
        if *announced == want {
            debug!("announcements unchanged");
            return Ok(());
        }
        let added: BTreeSet<String> = want.difference(&announced).cloned().collect();
        let removed: BTreeSet<String> = announced.difference(&want).cloned().collect();

        // The whole desired set is rendered, not only the additions: a
        // fragment an operator opens should say what this node is announcing,
        // not what changed the last time somebody looked.
        let text = fragment(&self.cfg, &want, &removed);
        if let Some(dir) = self.cfg.fragment.parent() {
            tokio::fs::create_dir_all(dir).await.map_err(|e| {
                NetworkError::Backend(anyhow::anyhow!(
                    "creating {} for the frr fragment: {e}",
                    dir.display()
                ))
            })?;
        }
        tokio::fs::write(&self.cfg.fragment, &text)
            .await
            .map_err(|e| {
                NetworkError::Backend(anyhow::anyhow!(
                    "writing {}: {e}",
                    self.cfg.fragment.display()
                ))
            })?;
        let path = self.cfg.fragment.display().to_string();
        self.vtysh(&["-f", &path])
            .await
            .map_err(|e| NetworkError::Backend(anyhow::anyhow!(e)))?;

        info!(
            announced = want.len(),
            added = added.len(),
            withdrawn = removed.len(),
            "bgp announcements applied"
        );
        for prefix in &added {
            info!(prefix = %prefix, "prefix announced");
        }
        // The withdraw IS the failover: the same address announced from
        // whichever node the VM is on next, and the upstream's best path moves
        // on its own. Worth an info line each, because that is the moment an
        // operator is looking for when a service moved.
        for prefix in &removed {
            info!(prefix = %prefix, "prefix withdrawn");
        }
        *announced = want;
        Ok(())
    }
}

#[async_trait::async_trait]
impl agent_api::networking::RouteAnnouncer for Frr {
    async fn announce(&self, prefixes: BTreeSet<String>) {
        if let Err(e) = Frr::announce(self, prefixes).await {
            // Warn and not error: the next reconcile pass hands over the same
            // set and tries again, which is the whole point of the thing being
            // level-triggered. An announcement that failed once is a
            // degradation that heals itself, and the level contract says WARN.
            warn!(error = %format!("{e:#}"),
                  "could not apply the bgp announcements, retrying next pass");
        }
    }
}

#[cfg(test)]
#[generated(model = ClaudeOpus, version = "5")]
mod tests {
    use super::*;

    fn cfg(evpn: bool) -> BgpConfig {
        BgpConfig {
            asn: 65_001,
            router_id: "10.0.0.1".into(),
            neighbors: vec![Neighbor {
                address: "10.0.0.254".into(),
                remote_asn: 65_000,
            }],
            vtysh: PathBuf::from("vtysh"),
            vty_socket: None,
            fragment: PathBuf::from("/run/meisterstack/meister-bgp.conf"),
            evpn,
        }
    }

    fn set(items: &[&str]) -> BTreeSet<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    /// The whole announcement in one fragment: the peer, the two settings
    /// without which it would silently say nothing, and one /32 per address.
    #[test]
    fn a_floating_address_is_announced_as_a_host_route() {
        let text = fragment(&cfg(false), &set(&["10.255.0.7/32"]), &BTreeSet::new());
        assert!(text.contains("router bgp 65001\n"), "{text}");
        assert!(text.contains(" bgp router-id 10.0.0.1\n"), "{text}");
        assert!(
            text.contains(" neighbor 10.0.0.254 remote-as 65000\n"),
            "{text}"
        );
        assert!(text.contains("  neighbor 10.0.0.254 activate\n"), "{text}");
        assert!(text.contains("  network 10.255.0.7/32\n"), "{text}");
        assert_eq!(host_prefix("10.255.0.7"), "10.255.0.7/32");
    }

    /// The two lines that decide whether ANY of this works, asserted by name.
    /// Without the first, modern FRR refuses to advertise to an eBGP peer
    /// without a policy (RFC 8212); without the second it originates nothing,
    /// because the /32 is deliberately not in this host's routing table.
    #[test]
    fn the_two_settings_that_make_the_announcement_happen_at_all_are_there() {
        let text = fragment(&cfg(false), &set(&["10.255.0.7/32"]), &BTreeSet::new());
        assert!(text.contains(" no bgp ebgp-requires-policy\n"), "{text}");
        assert!(text.contains(" no bgp network import-check\n"), "{text}");
    }

    /// The withdraw, which is the failover. `vtysh -f` MERGES, so a prefix
    /// that is gone needs an explicit `no network` — a renderer that only
    /// emitted `network` lines would be one whose announcements never went
    /// away, and that is the one thing this feature is for.
    #[test]
    fn a_prefix_that_is_gone_is_withdrawn_by_name() {
        let text = fragment(
            &cfg(false),
            &set(&["10.255.0.8/32"]),
            &set(&["10.255.0.7/32"]),
        );
        assert!(text.contains("  network 10.255.0.8/32\n"), "{text}");
        assert!(text.contains("  no network 10.255.0.7/32\n"), "{text}");
        assert!(!text.contains("  network 10.255.0.7/32\n"), "{text}");
    }

    /// Nothing to announce is still a valid fragment: the session stays up and
    /// says nothing, which is what a node with no floating VMs on it should be
    /// saying.
    #[test]
    fn a_node_with_nothing_on_it_still_speaks_bgp() {
        let text = fragment(&cfg(false), &BTreeSet::new(), &BTreeSet::new());
        assert!(text.contains("router bgp 65001"), "{text}");
        assert!(
            !text.lines().any(|l| l.trim_start().starts_with("network ")),
            "nothing is announced: {text}"
        );
        assert!(text.ends_with("exit\n"), "{text}");
    }

    /// EVPN is a second address family and nothing else changes. Off by
    /// default, because multicast is M5's behaviour and needs no daemon.
    #[test]
    fn evpn_adds_one_address_family_and_the_line_that_does_the_work() {
        let off = fragment(&cfg(false), &BTreeSet::new(), &BTreeSet::new());
        assert!(!off.contains("l2vpn evpn"), "{off}");
        assert!(!off.contains("advertise-all-vni"), "{off}");

        let on = fragment(&cfg(true), &BTreeSet::new(), &BTreeSet::new());
        assert!(on.contains(" address-family l2vpn evpn\n"), "{on}");
        assert!(on.contains("  advertise-all-vni\n"), "{on}");
        assert!(on.contains("  neighbor 10.0.0.254 activate\n"), "{on}");
        // ... and the ipv4 family is still there, because the floating
        // addresses are announced whether or not the overlay uses evpn.
        assert!(on.contains(" address-family ipv4 unicast\n"), "{on}");
    }

    /// Routed subnets are never in here, and the fragment is where that
    /// decision shows: a subnet spans hosts, so a per-host announcement of one
    /// would be every node claiming the whole prefix.
    #[test]
    fn only_host_routes_are_ever_announced() {
        let text = fragment(
            &cfg(true),
            &set(&["10.255.0.7/32", "203.0.113.9/32"]),
            &BTreeSet::new(),
        );
        for line in text
            .lines()
            .filter(|l| l.trim_start().starts_with("network "))
        {
            assert!(line.ends_with("/32"), "not a host route: {line}");
        }
    }
}
