// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Tenant routers implemented as network namespaces with provider and overlay veths.
//! Active and standby routers both have addresses and NAT state; standby suppresses
//! ARP replies and route announcements. This is not a distributed fencing mechanism.
//! A JSON spec under run_dir identifies each router across agent restarts. Router
//! listing skips unreadable records, while overlay ownership checks reject them.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Stdio;

use agent_api::networking::{
    self, NatKind, NetworkError, RouterId, RouterPhase, RouterReason, RouterSpec, RouterState,
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

/// Validate provider names against the 15-byte generated bridge-name limit.
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

/// Record the spec used to construct a router; link names are derived from its ID.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct RouterRecord {
    spec: RouterSpec,
}

/// Overlay ownership must include unreadable router inventory as uncertainty.
pub(crate) async fn overlay_vnis(dir: &Path) -> networking::Result<Vec<u32>> {
    let mut entries = match tokio::fs::read_dir(dir).await {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(NetworkError::Backend(e.into())),
    };
    let mut vnis = Vec::new();
    while let Some(entry) = entries
        .next_entry()
        .await
        .map_err(|e| NetworkError::Backend(e.into()))?
    {
        let path = entry.path();
        if path.extension().is_none_or(|e| e != "json") {
            continue;
        }
        let bytes = tokio::fs::read(&path)
            .await
            .map_err(|e| NetworkError::Backend(e.into()))?;
        let record: RouterRecord = serde_json::from_slice(&bytes).map_err(|e| {
            NetworkError::Backend(anyhow::anyhow!(
                "cannot establish router ownership from {}: {e}",
                path.display()
            ))
        })?;
        vnis.push(record.spec.vxlan_id);
    }
    Ok(vnis)
}

/// Return an active router's external host route, floating host routes and routed prefixes.
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

/// Return external addresses for gratuitous ARP on activation. Standby returns none.
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

/// Build an unsolicited ARP command on the external leg.
/// The internal leg receives no equivalent announcement here.
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

/// Suppress replies for all local addresses when standby.
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

    /// Best-effort ip operation: all errors are logged and swallowed.
    /// Callers must verify required postconditions separately; not every caller does.
    async fn ip_again(&self, args: &[&str]) {
        if let Err(e) = self.ip(args).await {
            debug!(error = %format!("{e:#}"), args = %args.join(" "), "ip step already done");
        }
    }

    /// Compare the persisted spec's rendered rules and require the table to exist.
    /// This does not compare the installed rules with the desired rules.
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

    /// Delete a listed namespace when link inspection fails.
    /// The current probe does not distinguish an invalid namespace from a transient error.
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

    /// Send external gratuitous ARPs after activation, with best-effort error handling.
    /// Children start before waiting; arping supplies its own requested deadline.
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

    /// List namespace names with this driver's prefix.
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
        let links = match live.contains(&netns) {
            // Not asked at all when the namespace is gone: `ip -n` on a
            // namespace that is not there would answer with an error, and
            // "we could not look" is a different statement from "it is gone".
            false => None,
            true => Some(self.ip(&["-n", &netns, "-o", "link", "show"]).await),
        };
        let (phase, reason, message) = classify(&netns, links);
        RouterState {
            id: spec.id,
            location: netns,
            phase,
            reason,
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
        // Refuse a provider interface carrying a non-link-local host address.
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

    /// Ensure namespace, veths, addresses, routes, NAT and ARP mode.
    /// Address replacement runs on every call; obsolete explicit subnet routes are not removed.
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
            // Use overlay MTU internally and the provider interface's MTU externally.
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
        // Assign floating /32s externally so the active router can answer provider ARP.
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

        // Route advertised subnets directly onto the overlay.
        // Errors are swallowed here and obsolete subnet routes are not deleted.
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

        // Skip unchanged rendered rules when the table exists, preserving counters.
        // External rule changes within an existing table are not detected.
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

    /// Delete the namespace and host veths, then remove the router record.
    #[instrument(skip_all, fields(router = %id))]
    pub(crate) async fn destroy_router_impl(&self, id: &RouterId) -> networking::Result<()> {
        let netns = router_netns(id);
        self.ip_again(&["netns", "del", &netns]).await;
        // Keep the record if the namespace name remains after deletion.
        // This checks the named mount, not every possible reference to the namespace.
        if self.netns_present().await?.iter().any(|n| n == &netns) {
            return Err(NetworkError::Backend(anyhow::anyhow!(
                "the namespace {netns} is still listed after `ip netns del`, so this router was \
                 not taken down; its record is kept and the teardown is retried"
            )));
        }
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

    /// Sweep named namespaces without record files after an interrupted build.
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
            // Report a sweep only after the namespace name disappears.
            if self.netns_present().await?.iter().any(|n| n == &netns) {
                warn!(netns = %netns,
                      "this orphaned namespace is still listed after `ip netns del`; \
                       it is not reported as swept");
                continue;
            }
            info!(netns = %netns, "orphaned router removed: no record on this node names it");
            swept.push(netns);
        }
        Ok(swept)
    }

    /// Make readable active records standby through ensure_router.
    /// Continue after individual failures; unreadable records are omitted by listing.
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

/// Classify namespace absence, inspection failure and missing named legs separately.
/// Ready means both leg names exist; it does not verify routes, rules or packet flow.
fn classify(
    netns: &str,
    links: Option<networking::Result<String>>,
) -> (RouterPhase, Option<RouterReason>, String) {
    let Some(links) = links else {
        return (
            RouterPhase::Failed,
            Some(RouterReason::NetnsGone),
            format!("the network namespace {netns} is gone"),
        );
    };
    let links = match links {
        Ok(links) => links,
        Err(e) => {
            return (
                RouterPhase::Failed,
                Some(RouterReason::DriverUnreachable),
                format!("{e:#}"),
            );
        }
    };
    let missing: Vec<&str> = [LEG_EXTERNAL, LEG_INTERNAL]
        .into_iter()
        // `ip -o link show` prints `2: ext@if7: <...>`, so the name is
        // followed by `@` or `:` and never bare.
        .filter(|leg| !links.contains(&format!(" {leg}@")) && !links.contains(&format!(" {leg}:")))
        .collect();
    match missing.is_empty() {
        true => (RouterPhase::Ready, None, String::new()),
        false => (
            RouterPhase::Failed,
            Some(RouterReason::LegGone),
            format!("the leg(s) {} are gone from {netns}", missing.join(", ")),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use agent_api::networking::{NatKind, NatRule};

    /// A shell script wearing a binary's name -- the pattern
    /// `drivers/input/tests/backend.rs` uses, for the same reason: what is
    /// being asserted here is how this driver reads an answer, and an answer
    /// can be written down without the kernel that would otherwise give it.
    fn fake_binary(dir: &Path, name: &str, body: &str) -> String {
        use std::os::unix::fs::PermissionsExt;
        let path = dir.join(name);
        std::fs::write(&path, format!("#!/bin/sh\n{body}")).expect("a fake binary");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))
            .expect("and it is executable");
        path.display().to_string()
    }

    /// A driver whose `ip` and `nft` are the two scripts above.
    fn fake_driver(dir: &Path, ip_body: &str) -> crate::LinuxNetworkDriver {
        let ip = fake_binary(dir, "ip", ip_body);
        // `Nft::new` proves at start-up that this process may write a table;
        // the fake says yes and reads the script off stdin so that nothing
        // here dies of a broken pipe.
        let nft = fake_binary(dir, "nft", "cat > /dev/null\nexit 0\n");
        crate::LinuxNetworkDriver::build(
            None,
            crate::nftables::NftConfig {
                binary: nft,
                guarded: common::net::Ipv4Ranges::default(),
            },
            Some(GatewayConfig {
                physnets: BTreeMap::from([("ext".to_string(), "pxlink".to_string())]),
                ip,
                arping: "arping".to_string(),
                state_dir: dir.to_path_buf(),
            }),
        )
        .expect("the driver comes up against the fakes")
    }

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

    #[tokio::test]
    async fn router_ownership_preserves_an_overlay_across_driver_restart() {
        let dir = tempfile::tempdir().unwrap();
        let router = spec(true);
        let path = dir.path().join(format!("{}.json", router.id));
        std::fs::write(
            &path,
            serde_json::to_vec(&RouterRecord {
                spec: router.clone(),
            })
            .unwrap(),
        )
        .unwrap();
        // No local VM is present. Both a fresh driver and its replacement must
        // refuse deletion before issuing any netlink mutation.
        for _ in 0..2 {
            let driver = fake_driver(dir.path(), "exit 0\n");
            assert!(!driver.remove_unused_overlay(router.vxlan_id).await.unwrap());
        }
        std::fs::write(&path, b"unreadable router").unwrap();
        let driver = fake_driver(dir.path(), "exit 0\n");
        assert!(driver.remove_unused_overlay(router.vxlan_id).await.is_err());
    }

    #[test]
    fn any_remaining_router_or_vm_port_blocks_overlay_removal() {
        use rtnetlink::packet_route::link::LinkAttribute as A;
        for port in ["router-inside", "guest-tap"] {
            assert!(crate::is_overlay_consumer(
                &[A::Controller(7), A::IfName(port.into())],
                7,
                "vx10000"
            ));
        }
        assert!(!crate::is_overlay_consumer(
            &[A::Controller(7), A::IfName("vx10000".into())],
            7,
            "vx10000"
        ));
        assert!(!crate::is_overlay_consumer(
            &[A::Controller(8), A::IfName("router-inside".into())],
            7,
            "vx10000"
        ));
        assert!(crate::is_overlay_consumer(
            &[A::Controller(7)],
            7,
            "vx10000"
        ));
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

    /// Check the external gratuitous ARP address list and command arguments.
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
    /// A failed namespace deletion must retain the record and report failure.
    #[tokio::test]
    async fn a_teardown_that_leaves_the_namespace_behind_is_not_ok() {
        let temp = tempfile::Builder::new()
            .prefix("ms-router-s10-")
            .tempdir()
            .expect("a state directory");
        let dir = temp.path();
        let s = spec(true);
        let netns = router_netns(&s.id);
        let record = crate::LinuxNetworkDriver::record_path(dir, &s.id);
        std::fs::write(
            &record,
            serde_json::to_vec(&RouterRecord { spec: s.clone() }).expect("a record"),
        )
        .expect("the record this node wrote when it built the router");

        let busy = fake_driver(
            dir,
            &format!(
                r#"case "$1 $2" in
"netns del") echo "Cannot remove namespace file: Device or resource busy" >&2; exit 1;;
"netns list") echo "{netns} (id: 0)";;
*) exit 0;;
esac
"#
            ),
        );
        let err = busy
            .destroy_router_impl(&s.id)
            .await
            .expect_err("a namespace that is still there is not a router that was taken down");
        assert!(matches!(err, NetworkError::Backend(_)), "{err:#}");
        let said = format!("{err:#}");
        assert!(said.contains(&netns), "{said}");
        assert!(
            record.exists(),
            "the record is this node's claim on the address, and it is kept until the \
             namespace is actually gone"
        );

        // And the other half, so that the gate is a gate and not a wall: the
        // same teardown against a kernel that DID let go removes the record
        // and answers Ok.
        let gone = fake_driver(dir, "exit 0\n");
        gone.destroy_router_impl(&s.id)
            .await
            .expect("a namespace that is off the list is a router that is gone");
        assert!(!record.exists(), "and then the record goes with it");
    }

    #[test]
    fn a_router_says_which_of_the_three_things_is_wrong_with_it() {
        let netns = "meister-rt-1a2b3c4d-5e6f-0000-0000-000000000000";

        // Nothing was asked, because there was nothing to ask about.
        let (phase, reason, message) = classify(netns, None);
        assert_eq!(phase, RouterPhase::Failed);
        assert_eq!(reason, Some(RouterReason::NetnsGone));
        assert!(message.contains(netns), "{message}");

        // Both legs there: `ip -o link show` prints them with the `@peer`
        // suffix a veth carries.
        let links = format!(
            "1: lo: <LOOPBACK>\n2: {LEG_EXTERNAL}@if7: <UP>\n3: {LEG_INTERNAL}@if8: <UP>\n"
        );
        let (phase, reason, message) = classify(netns, Some(Ok(links.clone())));
        assert_eq!(phase, RouterPhase::Ready);
        assert_eq!(reason, None, "a Ready router explains itself");
        assert!(message.is_empty());

        // One leg gone: the namespace is there and the router is not usable.
        let half = links.replace(&format!("3: {LEG_INTERNAL}@if8: <UP>\n"), "");
        let (phase, reason, message) = classify(netns, Some(Ok(half)));
        assert_eq!(phase, RouterPhase::Failed);
        assert_eq!(reason, Some(RouterReason::LegGone));
        assert!(message.contains(LEG_INTERNAL), "{message}");

        // And the one that is not a statement about the router at all.
        let (phase, reason, message) = classify(
            netns,
            Some(Err(NetworkError::Backend(anyhow::anyhow!(
                "ip: command not found"
            )))),
        );
        assert_eq!(phase, RouterPhase::Failed);
        assert_eq!(reason, Some(RouterReason::DriverUnreachable));
        assert!(message.contains("command not found"), "{message}");
    }
}
