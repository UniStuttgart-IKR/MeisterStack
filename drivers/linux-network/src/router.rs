// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Tenant routers implemented as network namespaces with provider and overlay veths.
//! Active and standby routers both have addresses and NAT state; standby suppresses
//! ARP replies and route announcements. This is not a distributed fencing mechanism.
//! A JSON spec under run_dir identifies each router across agent restarts. An unreadable
//! record is listed as an unknown router, the sweep spares its namespace, and overlay
//! ownership checks reject it (R3-F07).

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use agent_api::networking::{
    self, NatKind, NetworkError, RouterId, RouterPhase, RouterReason, RouterSpec, RouterState,
};
use agent_api::subprocess::output_within;
use tracing::{debug, info, instrument, warn};

use crate::COMMAND_DEADLINE;
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

/// Record files under the gateway state directory. A missing directory means no router was
/// ever given: empty, not a failure. Interrupted-publish temp files (`<id>.json.tmp`) are skipped.
async fn record_files(dir: &Path) -> networking::Result<Vec<PathBuf>> {
    let mut entries = match tokio::fs::read_dir(dir).await {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => {
            return Err(NetworkError::Backend(
                anyhow::Error::new(e).context(format!("reading {}", dir.display())),
            ));
        }
    };
    let mut files = Vec::new();
    while let Some(entry) = entries
        .next_entry()
        .await
        .map_err(|e| NetworkError::Backend(e.into()))?
    {
        let path = entry.path();
        if path.extension().is_some_and(|e| e == "json") {
            files.push(path);
        }
    }
    Ok(files)
}

/// Overlay ownership must include unreadable router inventory as uncertainty: any unreadable
/// record, even one vanishing mid-walk, fails the whole answer so no overlay is deleted on a guess.
pub(crate) async fn overlay_vnis(dir: &Path) -> networking::Result<Vec<u32>> {
    let mut vnis = Vec::new();
    for path in record_files(dir).await? {
        let record = crate::LinuxNetworkDriver::read_record(&path)
            .await
            .map_err(|e| {
                let why = match e {
                    RecordError::Missing => anyhow::anyhow!("the record vanished while read"),
                    RecordError::Invalid(e) => e,
                };
                NetworkError::Backend(why.context(format!(
                    "cannot establish router ownership from {}",
                    path.display()
                )))
            })?;
        vnis.push(record.spec.vxlan_id);
    }
    Ok(vnis)
}

/// Why a router record could not be read: absent, or present but unreadable (R3-F07).
enum RecordError {
    /// No file at this path: nothing names this router.
    Missing,
    /// A file is there but does not parse as a record (torn write, unknown format).
    Invalid(anyhow::Error),
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

/// The sysctl that holds one leg's ARP mode.
fn arp_ignore_key(leg: &str) -> String {
    format!("net.ipv4.conf.{leg}.arp_ignore")
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
    ///
    /// Bounded by [`COMMAND_DEADLINE`]: a hung `ip` (stuck netns mount, unresponsive netlink)
    /// would block the agent's serial pump and the node's `ops` lock (R3-F08, R2-5).
    async fn ip(&self, args: &[&str]) -> networking::Result<String> {
        let binary = &self.gateway()?.ip;
        let what = format!("{binary} {}", args.join(" "));
        let out = output_within(
            tokio::process::Command::new(binary).args(args),
            None,
            COMMAND_DEADLINE,
            &what,
        )
        .await
        .map_err(|e| NetworkError::Backend(e.into()))?;
        if !out.status.success() {
            return Err(NetworkError::Backend(anyhow::anyhow!(
                "{what} failed: {}",
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
        let Ok(record) = Self::read_record(&path).await else {
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
    /// containing a set literal never has to survive an argv split. Bounded like `ip`,
    /// stdin included: a script `nft` does not drain would hang there first (R3-F08).
    async fn netns_nft(&self, netns: &str, script: &str) -> networking::Result<()> {
        let g = self.gateway()?;
        let out = output_within(
            tokio::process::Command::new(&g.ip).args([
                "netns",
                "exec",
                netns,
                self.nft.binary(),
                "-f",
                "-",
            ]),
            Some(script.as_bytes()),
            COMMAND_DEADLINE,
            &format!("nft in {netns}"),
        )
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
    /// All addresses at once under one deadline, so a wedged `arping` costs the deadline once.
    async fn announce_garp(&self, netns: &str, spec: &RouterSpec) {
        let Ok(g) = self.gateway() else {
            return;
        };
        let addresses = garp_addresses(spec);
        let shouts = addresses.iter().map(|address| async move {
            let mut command = tokio::process::Command::new(&g.ip);
            command.args(garp_command(&g.arping, netns, address));
            let what = format!("{} for {address}", g.arping);
            let outcome = output_within(&mut command, None, COMMAND_DEADLINE, &what).await;
            (address, outcome)
        });
        let mut announced = Vec::new();
        for (address, outcome) in futures::future::join_all(shouts).await {
            match outcome {
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

    /// The router id a record's file name names (`<id>.json`).
    ///
    /// It survives a record that no longer parses, and is then the only id that listing,
    /// silencing and sweeping have to go on (R3-F07).
    fn record_id(path: &Path) -> Option<RouterId> {
        path.file_stem()?.to_str()?.parse().ok()
    }

    /// Read one router record, distinguishing a missing record from an unreadable one (R3-F07).
    async fn read_record(path: &Path) -> Result<RouterRecord, RecordError> {
        let bytes = match tokio::fs::read(path).await {
            Ok(bytes) => bytes,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Err(RecordError::Missing),
            Err(e) => return Err(RecordError::Invalid(e.into())),
        };
        match serde_json::from_slice(&bytes) {
            Ok(record) => Ok(record),
            Err(e) => {
                warn!(path = %path.display(), error = %format!("{e:#}"),
                      "a router record here cannot be read");
                Err(RecordError::Invalid(e.into()))
            }
        }
    }

    /// Publish a router record atomically (temp file, fsync, rename) so no reader sees a torn
    /// record; a stale temp file from a crash is truncated, not tripped over (R3-F07).
    async fn publish_record(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
        use tokio::io::AsyncWriteExt;
        let tmp = path.with_extension("json.tmp");
        let mut file = tokio::fs::File::create(&tmp).await?;
        file.write_all(bytes).await?;
        file.sync_all().await?;
        drop(file);
        tokio::fs::rename(&tmp, path).await
    }

    /// Write the record for `spec` under `dir`, atomically: a crash mid-write leaves the old or
    /// the new record, never a torn one.
    async fn store_record(dir: &Path, spec: &RouterSpec) -> networking::Result<()> {
        tokio::fs::create_dir_all(dir).await.map_err(|e| {
            NetworkError::Backend(anyhow::anyhow!("creating {}: {e}", dir.display()))
        })?;
        let record = serde_json::to_vec_pretty(&RouterRecord { spec: spec.clone() })
            .map_err(|e| NetworkError::Backend(e.into()))?;
        let path = Self::record_path(dir, &spec.id);
        Self::publish_record(&path, &record)
            .await
            .map_err(|e| NetworkError::Backend(anyhow::anyhow!("writing {}: {e}", path.display())))
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
            .is_ok_and(|record| record.spec.active);

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
        // Legs created below are born silent: only the last step of a complete pass lets an
        // active router answer, so a pass that fails midway leaves no answering namespace (R2-1).
        self.netns_sysctl(
            &netns,
            "net.ipv4.conf.default.arp_ignore",
            arp_ignore(false),
        )
        .await?;

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
        // A standby falls silent before it is given anything to answer for.
        if !spec.active {
            self.set_arp_mode(&netns, false).await?;
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

        // Skip unchanged rendered rules when the table exists, preserving counters.
        // External rule changes within an existing table are not detected.
        if !self.ruleset_is_current(&netns, &rules, spec).await {
            self.netns_nft(&netns, &rules).await?;
        }

        // Only when everything above worked: a record is this driver's statement that the
        // namespace beside it is finished. One written earlier would make the sweep spare a
        // half-built router for ever.
        Self::store_record(&g.state_dir, spec).await?;

        // Activation last, after the rules and the record: no namespace answers ARP without
        // its NAT or before its record says active (R2-1).
        if spec.active {
            self.set_arp_mode(&netns, true).await?;
        }

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

    /// A `RouterState` for a record this build could not read.
    ///
    /// The id survives in the record's file name, so the router is named even when it cannot
    /// be described. Reported as `Failed`/`DriverUnreachable` rather than a new `RouterPhase`
    /// (wire vocabulary shared with the cluster controller): "this node could not find out",
    /// not "gone". Omitting it would read as never built while it may still answer ARP (R3-F07).
    fn unknown_router_state(id: RouterId, why: &anyhow::Error) -> RouterState {
        let netns = router_netns(&id);
        RouterState {
            id,
            location: netns.clone(),
            phase: RouterPhase::Failed,
            reason: Some(RouterReason::DriverUnreachable),
            message: format!(
                "the record for {netns} exists but this build could not read it: {why:#}"
            ),
            // Not claimed active: the record that would say so did not parse. `fall_silent_impl`
            // silences this namespace regardless of this flag.
            active: false,
            announce: Vec::new(),
        }
    }

    pub(crate) async fn list_routers_impl(&self) -> networking::Result<Vec<RouterState>> {
        let dir = &self.gateway()?.state_dir;
        let live = self.netns_present().await?;
        let mut out = Vec::new();
        for path in record_files(dir).await? {
            match Self::read_record(&path).await {
                Ok(record) => out.push(self.state_of(&record.spec, &live).await),
                // Raced with a destroy between listing and read: no longer a router, left out.
                Err(RecordError::Missing) => {}
                // Reported as unknown, never dropped (R3-F07).
                Err(RecordError::Invalid(e)) => {
                    if let Some(id) = Self::record_id(&path) {
                        out.push(Self::unknown_router_state(id, &e));
                    }
                }
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
            .map_err(|_| NetworkError::RouterNotFound(*id))?;
        let live = self.netns_present().await?;
        Ok(self.state_of(&record.spec, &live).await)
    }

    /// Sweep named namespaces without record files after an interrupted build.
    #[instrument(skip_all)]
    pub(crate) async fn sweep_routers_impl(&self) -> networking::Result<Vec<String>> {
        let dir = self.gateway()?.state_dir.clone();
        let mut swept = Vec::new();
        for netns in self.netns_present().await? {
            let record_path = netns_router_id(&netns).map(|id| Self::record_path(&dir, &id));
            if let Some(path) = &record_path {
                match Self::read_record(path).await {
                    Ok(_) => continue,
                    // An existing but unreadable record still claims the namespace;
                    // listing reports it as unknown and the dead man silences it (R3-F07).
                    Err(RecordError::Invalid(_)) => {
                        warn!(netns = %netns,
                              "a router record here exists but cannot be read; treating it as \
                               an unknown router rather than sweeping its namespace");
                        continue;
                    }
                    Err(RecordError::Missing) => {}
                }
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

    /// Silence every router namespace on this node, from the kernel's list as well as the
    /// records (R2-1, R3-F06, R3-F07).
    ///
    /// The kernel is the truth here: a namespace with no record, with one that says standby or
    /// with one that does not parse can still answer ARP. So every live `meister-rt-` namespace
    /// gets `arp_ignore=8` on every leg it has, whatever its record says, and a record still
    /// saying active is rewritten standby so the announcement pass withdraws it. Failures are
    /// named per router so the dead man retries; a pass that could not list the namespaces or
    /// the records is an error, after everything it could reach was silenced.
    #[instrument(skip_all)]
    pub(crate) async fn fall_silent_impl(&self) -> networking::Result<networking::Silencing> {
        let dir = self.gateway()?.state_dir.clone();
        let live = self.netns_present().await;
        let records = record_files(&dir).await;
        let (routers, unnamed) = silencing_targets(
            records.as_deref().unwrap_or_default(),
            live.as_deref().unwrap_or_default(),
        );
        let mut outcome = networking::Silencing::default();
        for id in routers {
            match self.silence_router(&dir, id, live.as_deref().ok()).await {
                Ok(()) => outcome.silenced.push(id),
                Err(e) => {
                    warn!(router = %id, error = %format!("{e:#}"),
                          "this router could not be silenced");
                    outcome.failed.push(id);
                }
            }
        }
        let unnamed = self.silence_unnamed(&unnamed).await;
        live?;
        records?;
        unnamed?;
        Ok(outcome)
    }

    /// Silence one router: its namespace unless the kernel's list proves it absent, and its
    /// record if that still says active. Both are tried; the first failure is the answer.
    async fn silence_router(
        &self,
        dir: &Path,
        id: RouterId,
        live: Option<&[String]>,
    ) -> networking::Result<()> {
        let netns = router_netns(&id);
        let kernel = match live.is_some_and(|live| !live.contains(&netns)) {
            true => Ok(()),
            false => self.silence_legs(&netns).await,
        };
        let record = Self::record_standby(dir, &id).await;
        kernel.and(record)
    }

    /// Rewrite a record that still says active as standby, so the router announces nothing and
    /// its next activation shouts again. A missing, standby or unreadable record claims nothing
    /// a rewrite could withdraw and is left as it is.
    async fn record_standby(dir: &Path, id: &RouterId) -> networking::Result<()> {
        let Ok(mut record) = Self::read_record(&Self::record_path(dir, id)).await else {
            return Ok(());
        };
        if !record.spec.active {
            return Ok(());
        }
        record.spec.active = false;
        Self::store_record(dir, &record.spec).await
    }

    /// Silence live namespaces that carry this driver's prefix but no router id. None of them is
    /// this driver's, but an unknown namespace is no proof of a silent one.
    async fn silence_unnamed(&self, unnamed: &[String]) -> networking::Result<()> {
        let mut failed = Vec::new();
        for netns in unnamed {
            if let Err(e) = self.silence_legs(netns).await {
                warn!(netns = %netns, error = %format!("{e:#}"),
                      "this namespace carries the router prefix and could not be silenced");
                failed.push(netns.as_str());
            }
        }
        match failed.is_empty() {
            true => Ok(()),
            false => Err(NetworkError::Backend(anyhow::anyhow!(
                "the namespaces {} carry the router prefix and could not be silenced",
                failed.join(", ")
            ))),
        }
    }

    /// Silence the legs a namespace has, as the kernel lists them (N3).
    ///
    /// A leg that is not there cannot answer ARP and counts as silenced, so a namespace without
    /// legs does not keep every pass from completing. A leg that is there and refuses the
    /// sysctl, or a namespace that cannot be looked into, is a failure: unknown is not silent.
    async fn silence_legs(&self, netns: &str) -> networking::Result<()> {
        let links = self.ip(&["-n", netns, "-o", "link", "show"]).await?;
        let mut outcome = Ok(());
        for leg in legs_present(&links) {
            let set = self
                .netns_sysctl(netns, &arp_ignore_key(leg), arp_ignore(false))
                .await;
            outcome = outcome.and(set);
        }
        outcome
    }

    /// Set both legs' ARP mode: answering for an active router, `arp_ignore=8` for a standby.
    ///
    /// Both legs, because a standby must be silent towards the tenant as well as towards the
    /// fabric: an ARP reply on the overlay would make it the tenant's default gateway. Both are
    /// tried even when the first fails, so a silencing pass never leaves a leg it could reach.
    async fn set_arp_mode(&self, netns: &str, active: bool) -> networking::Result<()> {
        let mut outcome = Ok(());
        for leg in [LEG_EXTERNAL, LEG_INTERNAL] {
            let set = self
                .netns_sysctl(netns, &arp_ignore_key(leg), arp_ignore(active))
                .await;
            outcome = outcome.and(set);
        }
        outcome
    }
}

/// The router id a namespace name carries, if it is one of this driver's.
fn netns_router_id(netns: &str) -> Option<RouterId> {
    netns.strip_prefix(NETNS_PREFIX)?.parse().ok()
}

/// The routers a silencing pass covers: every one a record names and every one a live
/// namespace names. Live prefixed namespaces whose name carries no router id come back apart.
fn silencing_targets(records: &[PathBuf], live: &[String]) -> (BTreeSet<RouterId>, Vec<String>) {
    let mut routers: BTreeSet<RouterId> = records
        .iter()
        .filter_map(|path| crate::LinuxNetworkDriver::record_id(path))
        .collect();
    let mut unnamed = Vec::new();
    for netns in live {
        match netns_router_id(netns) {
            Some(id) => {
                routers.insert(id);
            }
            None => unnamed.push(netns.clone()),
        }
    }
    (routers, unnamed)
}

/// The router legs an `ip -o link show` listing names.
fn legs_present(links: &str) -> Vec<&'static str> {
    [LEG_EXTERNAL, LEG_INTERNAL]
        .into_iter()
        // `ip -o link show` prints `2: ext@if7: <...>`, so the name is
        // followed by `@` or `:` and never bare.
        .filter(|leg| links.contains(&format!(" {leg}@")) || links.contains(&format!(" {leg}:")))
        .collect()
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
    let present = legs_present(&links);
    let missing: Vec<&str> = [LEG_EXTERNAL, LEG_INTERNAL]
        .into_iter()
        .filter(|leg| !present.contains(leg))
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
    ///
    /// Written by a child `sh`, not by this process: a test thread forking at the same moment
    /// would inherit a write descriptor of ours and make executing the fake fail with ETXTBSY.
    fn fake_binary(dir: &Path, name: &str, body: &str) -> String {
        use std::io::Write;
        let path = dir.join(name);
        let mut writer = std::process::Command::new("sh")
            .args(["-c", "cat > \"$1\" && chmod 755 \"$1\"", "sh"])
            .arg(&path)
            .stdin(std::process::Stdio::piped())
            .spawn()
            .expect("a shell to write the fake");
        writer
            .stdin
            .take()
            .expect("its stdin")
            .write_all(format!("#!/bin/sh\n{body}").as_bytes())
            .expect("the fake's text");
        assert!(writer.wait().expect("the shell exits").success());
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

    /// A stale `.tmp` file from a torn write is overwritten by the next publish (R3-F07).
    #[tokio::test]
    async fn a_stale_tmp_file_from_a_torn_write_is_overwritten_not_tripped_over() {
        let temp = tempfile::Builder::new()
            .prefix("ms-router-r3f07-publish-")
            .tempdir()
            .expect("a directory");
        let path = temp.path().join("record.json");
        let tmp = path.with_extension("json.tmp");
        std::fs::write(&tmp, b"garbage a crash left behind mid-write")
            .expect("a stale tmp file, as a torn write would leave one");

        crate::LinuxNetworkDriver::publish_record(&path, b"{\"the\":\"new record\"}")
            .await
            .expect("a stale tmp file must not block the next publish");

        assert!(!tmp.exists(), "the tmp name is consumed by the rename");
        assert_eq!(
            std::fs::read(&path).expect("the published record"),
            b"{\"the\":\"new record\"}"
        );
    }

    /// An unparseable record is an unknown router: listed, silenced, and not swept (R3-F07).
    #[tokio::test]
    async fn a_broken_record_is_unknown_not_silently_omitted_nor_swept_as_foreign() {
        let temp = tempfile::Builder::new()
            .prefix("ms-router-r3f07-broken-")
            .tempdir()
            .expect("a state directory");
        let dir = temp.path();
        let id = RouterId::from_u128(0x6b00_00f0_7000_0000_0000_0000_0000_0001);
        let netns = router_netns(&id);
        let path = crate::LinuxNetworkDriver::record_path(dir, &id);
        std::fs::write(&path, b"{ this is not valid json").expect("a torn or corrupted record");

        let d = fake_driver(
            dir,
            &format!(
                r#"case "$1 $2" in
"netns list") echo "{netns} (id: 0)";;
*) exit 0;;
esac
"#
            ),
        );

        // Reported, not silently dropped.
        let listed = d.list_routers_impl().await.expect("a listing");
        assert_eq!(
            listed.len(),
            1,
            "the broken record is reported, not omitted"
        );
        assert_eq!(listed[0].id, id);
        assert_eq!(listed[0].phase, RouterPhase::Failed);
        assert_eq!(listed[0].reason, Some(RouterReason::DriverUnreachable));
        assert!(
            listed[0].message.contains(&netns),
            "the operator's sentence names the namespace: {}",
            listed[0].message
        );

        // Silenced by the namespace the file name still gives.
        let outcome = d.fall_silent_impl().await.expect("a farewell pass");
        assert_eq!(
            outcome.silenced,
            [id],
            "an unknown router is silenced unconditionally, because no broken record can say \
             whether it was active"
        );
        assert!(outcome.complete());

        // Not swept as a foreign namespace.
        let swept = d.sweep_routers_impl().await.expect("a sweep");
        assert!(
            swept.is_empty(),
            "a namespace with a record -- even a broken one -- is not \"no record at all\": \
             {swept:?}"
        );
        assert!(
            path.exists(),
            "the broken record itself is untouched by any of the three passes"
        );
    }

    /// Both of a router's legs, as a fully built namespace has them.
    const BOTH_LEGS: [&str; 2] = [LEG_EXTERNAL, LEG_INTERNAL];

    /// The shell lines a fake `ip -n <netns> -o link show` answers with: `lo` and `legs`, each
    /// spelled as a veth end, which is how the real one prints them.
    fn link_listing(legs: &[&str]) -> String {
        let mut out = "echo '1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536'; ".to_string();
        for (n, leg) in legs.iter().enumerate() {
            out += &format!(
                "echo '{}: {leg}@if{}: <BROADCAST,UP> mtu 1500'; ",
                n + 2,
                n + 7
            );
        }
        out
    }

    /// A fake `ip` that appends every call to `log`, lists the namespaces `listed` with the
    /// legs `legs` in each, and refuses the sysctls inside the namespace `refuse`.
    fn logging_ip(log: &Path, listed: &[String], legs: &[&str], refuse: Option<&str>) -> String {
        let listing = listed
            .iter()
            .map(|netns| format!("echo '{netns} (id: 0)'; "))
            .collect::<String>();
        let refusal = refuse
            .map(|netns| {
                format!("\"netns exec {netns} sysctl \"*) echo 'permission denied' >&2; exit 1;;\n")
            })
            .unwrap_or_default();
        format!(
            "echo \"$*\" >> '{log}'\ncase \"$*\" in\n\"netns list\") {listing}:;;\n\
             \"-n \"*\" -o link show\") {links}:;;\n{refusal}esac\nexit 0\n",
            log = log.display(),
            links = link_listing(legs),
        )
    }

    /// The legs the fake `ip` was told to silence (`arp_ignore=8`) inside `netns`.
    fn silenced_legs(log: &Path, netns: &str) -> Vec<&'static str> {
        let calls = std::fs::read_to_string(log).unwrap_or_default();
        [LEG_EXTERNAL, LEG_INTERNAL]
            .into_iter()
            .filter(|leg| {
                let call =
                    format!("netns exec {netns} sysctl -q -w net.ipv4.conf.{leg}.arp_ignore=8");
                calls.lines().any(|line| line == call)
            })
            .collect()
    }

    fn write_record(dir: &Path, spec: &RouterSpec) -> PathBuf {
        let path = crate::LinuxNetworkDriver::record_path(dir, &spec.id);
        let record = serde_json::to_vec(&RouterRecord { spec: spec.clone() }).expect("a record");
        std::fs::write(&path, record).expect("the record this node wrote");
        path
    }

    fn read_spec(path: &Path) -> RouterSpec {
        let bytes = std::fs::read(path).expect("the record is still there");
        serde_json::from_slice::<RouterRecord>(&bytes)
            .expect("and it parses")
            .spec
    }

    /// A namespace a failed pass left behind with no record is silenced from the kernel's list
    /// (R2-1).
    #[tokio::test]
    async fn a_live_namespace_with_no_record_is_silenced_by_the_dead_man() {
        let temp = tempfile::tempdir().expect("a state directory");
        let dir = temp.path();
        let log = dir.join("ip.log");
        let netns = router_netns(&spec(true).id);
        let d = fake_driver(
            dir,
            &logging_ip(&log, std::slice::from_ref(&netns), &BOTH_LEGS, None),
        );

        let outcome = d.fall_silent_impl().await.expect("a silencing pass");

        assert_eq!(outcome.silenced, [spec(true).id]);
        assert!(outcome.complete());
        assert_eq!(silenced_legs(&log, &netns), [LEG_EXTERNAL, LEG_INTERNAL]);
    }

    /// A record that says standby is no proof the kernel is silent: the namespace is silenced
    /// all the same (R2-1).
    #[tokio::test]
    async fn a_namespace_whose_record_says_standby_is_silenced_all_the_same() {
        let temp = tempfile::tempdir().expect("a state directory");
        let dir = temp.path();
        let log = dir.join("ip.log");
        let standby = spec(false);
        let netns = router_netns(&standby.id);
        write_record(dir, &standby);
        let d = fake_driver(
            dir,
            &logging_ip(&log, std::slice::from_ref(&netns), &BOTH_LEGS, None),
        );

        let outcome = d.fall_silent_impl().await.expect("a silencing pass");

        assert_eq!(outcome.silenced, [standby.id]);
        assert_eq!(silenced_legs(&log, &netns), [LEG_EXTERNAL, LEG_INTERNAL]);
    }

    /// A silenced router's record says standby afterwards, so it announces nothing and its
    /// next activation shouts again (R2-1).
    #[tokio::test]
    async fn an_active_record_is_rewritten_standby_when_its_router_falls_silent() {
        let temp = tempfile::tempdir().expect("a state directory");
        let dir = temp.path();
        let active = spec(true);
        let path = write_record(dir, &active);
        let d = fake_driver(dir, &logging_ip(&dir.join("ip.log"), &[], &BOTH_LEGS, None));

        d.fall_silent_impl().await.expect("a silencing pass");

        assert!(!read_spec(&path).active);
    }

    /// Without the kernel's list the recorded routers are still silenced, and the pass is not
    /// complete: a namespace no record names may be answering (R2-1).
    #[tokio::test]
    async fn a_pass_that_cannot_list_the_namespaces_silences_the_recorded_ones_and_fails() {
        let temp = tempfile::tempdir().expect("a state directory");
        let dir = temp.path();
        let log = dir.join("ip.log");
        let active = spec(true);
        write_record(dir, &active);
        let ip = format!(
            "echo \"$*\" >> '{}'\ncase \"$*\" in\n\"netns list\") exit 1;;\n\
             \"-n \"*\" -o link show\") {}:;;\nesac\nexit 0\n",
            log.display(),
            link_listing(&BOTH_LEGS),
        );
        let d = fake_driver(dir, &ip);

        let err = d.fall_silent_impl().await;

        assert!(err.is_err(), "an unlisted kernel is not a silent one");
        assert_eq!(
            silenced_legs(&log, &router_netns(&active.id)),
            [LEG_EXTERNAL, LEG_INTERNAL]
        );
    }

    /// One router that cannot be silenced does not stop the others, and leaves the pass partial
    /// so the dead man tries again (R3-F06).
    #[tokio::test]
    async fn one_router_that_cannot_be_silenced_leaves_the_pass_partial() {
        let temp = tempfile::tempdir().expect("a state directory");
        let dir = temp.path();
        let mut ok = spec(true);
        ok.id = RouterId::from_u128(0x6b00_0000_0000_0000_0000_0000_0000_0001);
        let mut bad = spec(true);
        bad.id = RouterId::from_u128(0x6b00_0000_0000_0000_0000_0000_0000_0002);
        write_record(dir, &ok);
        write_record(dir, &bad);
        let listed = [router_netns(&ok.id), router_netns(&bad.id)];
        let ip = logging_ip(&dir.join("ip.log"), &listed, &BOTH_LEGS, Some(&listed[1]));
        let d = fake_driver(dir, &ip);

        let outcome = d.fall_silent_impl().await.expect("a silencing pass");

        assert_eq!(outcome.silenced, [ok.id]);
        assert_eq!(outcome.failed, [bad.id]);
        assert!(!outcome.complete());
    }

    /// A namespace without legs cannot answer ARP: it counts as silenced and the pass completes,
    /// with no sysctl tried on a leg that is not there (N3).
    #[tokio::test]
    async fn a_namespace_without_legs_counts_as_silenced() {
        let temp = tempfile::tempdir().expect("a state directory");
        let dir = temp.path();
        let log = dir.join("ip.log");
        let netns = router_netns(&spec(true).id);
        let d = fake_driver(
            dir,
            &logging_ip(&log, std::slice::from_ref(&netns), &[], None),
        );

        let outcome = d.fall_silent_impl().await.expect("a silencing pass");

        assert_eq!(outcome.silenced, [spec(true).id]);
        assert!(outcome.complete());
        let calls = std::fs::read_to_string(&log).expect("the fake's log");
        assert!(!calls.contains("sysctl"), "{calls}");
    }

    /// A leg that is there and refuses the sysctl is a failure, even when the other leg is gone
    /// (N3).
    #[tokio::test]
    async fn a_leg_that_is_there_and_refuses_the_sysctl_is_a_failure() {
        let temp = tempfile::tempdir().expect("a state directory");
        let dir = temp.path();
        let netns = router_netns(&spec(true).id);
        let listed = std::slice::from_ref(&netns);
        let ip = logging_ip(&dir.join("ip.log"), listed, &[LEG_EXTERNAL], Some(&netns));
        let d = fake_driver(dir, &ip);

        let outcome = d.fall_silent_impl().await.expect("a silencing pass");

        assert_eq!(outcome.failed, [spec(true).id]);
        assert!(!outcome.complete());
    }

    /// A hung `ip` is killed within the deadline and does not block the next command (R3-F08).
    /// The fake busy-loops rather than `sleep`, whose forked child the kill would not reach.
    #[tokio::test]
    async fn a_hung_ip_is_killed_within_the_deadline_and_a_following_command_runs() {
        let temp = tempfile::Builder::new()
            .prefix("ms-router-r3f08-hang-")
            .tempdir()
            .expect("a directory");
        let d = fake_driver(
            temp.path(),
            "case \"$1 $2\" in\n\"netns list\") while :; do :; done;;\n*) exit 0;;\nesac\n",
        );

        let start = std::time::Instant::now();
        let err = d
            .ip(&["netns", "list"])
            .await
            .expect_err("a command that never answers is an error, not an eternal wait");
        let elapsed = start.elapsed();
        assert!(
            elapsed < COMMAND_DEADLINE + std::time::Duration::from_secs(3),
            "bounded by the deadline this driver keeps, not by the fake's own hang: {elapsed:?}"
        );
        assert!(
            format!("{err:#}").contains("did not answer within"),
            "{err:#}"
        );

        // The child was killed and reaped, so the next command is not blocked by the hang.
        let out = d
            .ip(&["true"])
            .await
            .expect("a following command must not inherit the hang");
        assert_eq!(out, "");
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
