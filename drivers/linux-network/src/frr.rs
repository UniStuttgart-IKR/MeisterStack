// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Render FRR configuration and apply it through vtysh.
//! The agent supplies floating host routes and active-router prefixes. EVPN uses
//! the same fragment to configure overlay learning. Applied prefixes are cached
//! only in memory; restart and external FRR changes are not fully reconciled.

use std::collections::BTreeSet;
use std::path::PathBuf;

use agent_api::networking::NetworkError;
use agent_api::subprocess::output_within;
use tokio::sync::Mutex;
use tracing::{debug, info, instrument, warn};

/// How long one `vtysh` may run. Longer than `ip`'s deadline: applying a fragment of many
/// prefixes makes bgpd work, and a timed-out apply is retried whole.
const VTYSH_DEADLINE: std::time::Duration = std::time::Duration::from_secs(30);

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
    /// Explicit IPv4-form BGP router identifier.
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

/// Render desired announcements and explicit withdrawals.
/// vtysh merges configuration, so omitting a former prefix does not withdraw it.
pub fn fragment(
    cfg: &BgpConfig,
    announced: &BTreeSet<String>,
    withdrawn: &BTreeSet<String>,
) -> String {
    let mut s = String::new();
    s.push_str("! meisterstack: generated, do not edit\n");
    s.push_str(&format!("router bgp {}\n", cfg.asn));
    s.push_str(&format!(" bgp router-id {}\n", cfg.router_id));
    // Permit the configured host peers without an explicit eBGP export policy.
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
        // Enable EVPN advertisement for the kernel's VNIs.
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
    /// Prefixes from the last successful apply in this process.
    /// An agent restart loses withdrawal history; this is not read back from FRR.
    announced: Mutex<BTreeSet<String>>,
}

impl Frr {
    /// Require vtysh to reach FRR before registering the announcer.
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

    /// Run `vtysh`, bounded by [`VTYSH_DEADLINE`]: a wedged one would hold the announcement
    /// lock and every later announcement behind it (R2-5).
    async fn vtysh(&self, args: &[&str]) -> anyhow::Result<String> {
        let mut cmd = tokio::process::Command::new(&self.cfg.vtysh);
        if let Some(dir) = &self.cfg.vty_socket {
            cmd.arg("--vty_socket").arg(dir);
        }
        let what = format!("{} {}", self.cfg.vtysh.display(), args.join(" "));
        let out = output_within(cmd.args(args), None, VTYSH_DEADLINE, &what).await?;
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

    /// Apply changes relative to the in-memory prefix set.
    /// Equal sets skip all configuration, including the first empty-set EVPN apply.
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
        // Log withdrawals separately for migration and failover diagnosis.
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
            // Leave the cached set unchanged so a later pass retries the failed apply.
            warn!(error = %format!("{e:#}"),
                  "could not apply the bgp announcements, retrying next pass");
        }
    }
}

#[cfg(test)]
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

    /// Keep the host-announcement policy and import-check settings explicit.
    #[test]
    fn the_two_settings_that_make_the_announcement_happen_at_all_are_there() {
        let text = fragment(&cfg(false), &set(&["10.255.0.7/32"]), &BTreeSet::new());
        assert!(text.contains(" no bgp ebgp-requires-policy\n"), "{text}");
        assert!(text.contains(" no bgp network import-check\n"), "{text}");
    }

    /// Removed prefixes need explicit no-network commands in a merged fragment.
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

    /// Preserve every supplied prefix; the caller decides which resources may announce it.
    #[test]
    fn whatever_the_pass_hands_over_is_what_this_node_says() {
        let text = fragment(
            &cfg(true),
            &set(&["10.255.0.7/32", "203.0.113.9/32", "10.7.2.0/24"]),
            &BTreeSet::new(),
        );
        let announced: Vec<&str> = text
            .lines()
            .filter_map(|l| l.trim_start().strip_prefix("network "))
            .collect();
        assert_eq!(
            announced,
            ["10.255.0.7/32", "10.7.2.0/24", "203.0.113.9/32"],
            "sorted, because the set is: {text}"
        );
    }
}
