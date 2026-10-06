// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Schema-2 fleet inventory parsing, validation, inheritance, and presentation. Scalars use
//! defaults < group < host; conflicting equal-rank groups require an explicit host override.
//! Lists accumulate in precedence order with duplicates removed.
//!
//! Nix derives deployment settings and converts inventory spellings such as disk.size_gb,
//! persistence.device, and ssh.host_key into manifest fields. This reader does not derive
//! deployment settings.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};

use crate::effects::Files;

/// Supported inventory schema. Earlier schemas require migration before parsing.
pub const SCHEMA: u32 = 2;

/// Ssh defaults when nobody said otherwise. Not policy, a floor: an
/// inventory that says nothing still has to name a user and a port for the
/// transport to be spelled out in the plan.
const DEFAULT_SSH_USER: &str = "root";
const DEFAULT_SSH_PORT: u16 = 22;

// ---------------------------------------------------------------------------
// The file
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FleetHeader {
    pub name: String,
    /// The DNS domain the hosts are named in. Some things need a NAME rather
    /// than an address — an issuer url, a certificate subject — and this is
    /// what they are built from, by Nix.
    #[serde(default)]
    pub domain: Option<String>,
}

/// What an ssh connection is, where a whole host is not being described.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SshOverrides {
    #[serde(default)]
    pub user: Option<String>,
    #[serde(default)]
    pub port: Option<u16>,
}

/// The same, plus the one thing only a host can have: its own key. There is
/// no `host_key` in `[defaults]` or in a group on purpose — a key shared by
/// several machines is not an identity.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostSsh {
    #[serde(default)]
    pub user: Option<String>,
    #[serde(default)]
    pub port: Option<u16>,
    /// Trusted `SHA256:…` fingerprint, recorded here by the operator.
    /// `keys enroll` writes known_hosts; a missing fingerprint means unenrolled.
    #[serde(default)]
    pub host_key: Option<String>,
}

/// Boot mode shared with nix/lib/inventory.nix. UEFI supports automated boot fallback; direct
/// and GRUB hosts support switch rollback only. The unsupported spelling bios is diagnosed
/// explicitly.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BootMode {
    /// An ESP, systemd-boot, a boot menu — and a way back from a boot.
    #[default]
    Uefi,
    /// Kernel, initrd and command line come from outside the machine.
    Direct,

    /// Use an existing GRUB loader. This flake does not install it; activation switches
    /// userland and reboots separately. Recovery from an unsuccessful boot requires the
    /// existing loader or console.
    Grub,
}

impl BootMode {
    pub fn as_str(self) -> &'static str {
        match self {
            BootMode::Uefi => "uefi",
            BootMode::Direct => "direct",
            BootMode::Grub => "grub",
        }
    }

    /// Hand-written rather than derived, so that `bios` gets the sentence it
    /// has earned instead of serde's "unknown variant".
    pub fn parse(text: &str) -> Result<BootMode> {
        match text {
            "uefi" => Ok(BootMode::Uefi),
            "direct" => Ok(BootMode::Direct),
            "grub" => Ok(BootMode::Grub),
            // Use grub for a preinstalled loader; bios does not describe an installation mode
            // supported by this flake.
            "bios" => bail!(
                "boot = \"bios\": this flake installs uefi or direct, and it deploys to a \
                 machine that already has grub — that value is `grub`. The difference is who \
                 made the loader: `meister-install` writes systemd-boot or nothing at all, \
                 and a grub host brings its own (its image, or its host module). A grub host \
                 has no boot fallback either way, because `bootctl set-oneshot` is what a \
                 boot fallback is made of."
            ),

            other => bail!(
                "boot = {other:?}: a host of this fleet boots uefi (it has an ESP and a boot \
                 menu of its own), direct (a hypervisor hands it kernel, initrd and command \
                 line) or grub (it boots itself out of a loader this flake did not install)."
            ),
        }
    }
}

impl<'de> Deserialize<'de> for BootMode {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> std::result::Result<BootMode, D::Error> {
        let text = String::deserialize(d)?;
        BootMode::parse(&text).map_err(serde::de::Error::custom)
    }
}

impl std::fmt::Display for BootMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.pad(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RebootPolicy {
    Auto,
    Approve,
    Never,
}

impl RebootPolicy {
    pub fn as_str(self) -> &'static str {
        match self {
            RebootPolicy::Auto => "auto",
            RebootPolicy::Approve => "approve",
            RebootPolicy::Never => "never",
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RolloutOverrides {
    #[serde(default)]
    pub max_unavailable: Option<u32>,
    #[serde(default)]
    pub reboot: Option<RebootPolicy>,
    /// What a canary is chosen by: `hardware-class`, `site`, or a name the
    /// operator gave a class of machines.
    #[serde(default)]
    pub canary: Option<String>,
}

/// Check ids. These accumulate rather than override: a group that adds a
/// check makes its members stricter, and a level that could silently drop a
/// required check would be a level nobody can review.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChecksOverrides {
    #[serde(default)]
    pub required: Vec<String>,
    #[serde(default)]
    pub functional: Vec<String>,
}

/// Target binary-cache configuration, shared with the workstation build/cache workflow.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedOverrides {
    #[serde(default)]
    pub substituters: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Defaults {
    #[serde(default)]
    pub ssh: SshOverrides,
    #[serde(default)]
    pub profiles: Vec<String>,
    /// How these machines are booted, where nobody says otherwise.
    #[serde(default)]
    pub boot: Option<BootMode>,
    #[serde(default)]
    pub rollout: RolloutOverrides,
    #[serde(default)]
    pub checks: ChecksOverrides,
    #[serde(default)]
    pub managed: ManagedOverrides,
}

/// References to what the operator already has. No secret is named here, and
/// none may be: this file is committed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Operator {
    /// The `meister` CLI configuration used to cordon and drain a node.
    /// Without it, an interrupting step on an agent is blocked with a
    /// sentence rather than taken anyway.
    #[serde(default)]
    pub cli_config: Option<String>,
    #[serde(default)]
    pub cli_profile: Option<String>,
    /// Where `tools/meister-ca` keeps its directory, relative to this file.
    #[serde(default)]
    pub ca_dir: Option<String>,
    /// Path to the Nix signing key, relative to the inventory. Keep the private file
    /// untracked and configure its public key as trusted on targets.
    #[serde(default)]
    pub signing_key: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GroupKind {
    Raft,
    Compute,
    Custom,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Group {
    pub id: String,
    pub kind: GroupKind,
    #[serde(default)]
    pub profiles: Vec<String>,
    #[serde(default)]
    pub ssh: SshOverrides,
    /// A group of machines that are all booted the same way — a rack of
    /// guests on one hypervisor, say.
    #[serde(default)]
    pub boot: Option<BootMode>,
    #[serde(default)]
    pub rollout: RolloutOverrides,
    #[serde(default)]
    pub checks: ChecksOverrides,
    #[serde(default)]
    pub managed: ManagedOverrides,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Deployment {
    Nixos,
    Context,
}

impl Deployment {
    pub fn as_str(self) -> &'static str {
        match self {
            Deployment::Nixos => "nixos",
            Deployment::Context => "context",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Network {
    pub address: String,
    pub prefix: u8,
    #[serde(default)]
    pub interface: Option<String>,
    #[serde(default)]
    pub gateway: Option<String>,
    /// Whether Nix configures this interface statically. False leaves configuration to the
    /// host while retaining the address for transport. The resolved manifest records the
    /// address; configuration ownership is represented by the evaluated system.
    #[serde(default, rename = "static")]
    pub r#static: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Networks {
    #[serde(default)]
    pub management: Option<Network>,
    #[serde(default)]
    pub storage: Option<Network>,
    #[serde(default)]
    pub tenant: Option<Network>,
    #[serde(default)]
    pub bmc: Option<Network>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Gpu {
    pub model: String,
    pub pci: String,
    #[serde(default)]
    pub selected_for: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Nic {
    pub name: String,
    pub mac: String,
    pub role: String,
    #[serde(default)]
    pub rdma: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Hardware {
    #[serde(default)]
    pub cpu: Option<String>,
    #[serde(default)]
    pub memory_gb: Option<u32>,
    #[serde(default)]
    pub gpus: Vec<Gpu>,
    #[serde(default)]
    pub nics: Vec<Nic>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Disk {
    /// The disk's own serial, as `lsblk -o SERIAL` prints it.
    #[serde(default)]
    pub serial: Option<String>,
    #[serde(default)]
    pub wwn: Option<String>,
    #[serde(default)]
    pub size_gb: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Install {
    pub disk: Disk,
    pub layout: String,
    #[serde(default)]
    pub preserve: Vec<String>,
    /// Public SSH keys embedded in the installer medium. Empty disables installer SSH;
    /// private keys must never be embedded.
    #[serde(default)]
    pub authorized_keys: Vec<String>,
}

fn yes() -> bool {
    true
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Persistence {
    pub path: String,
    /// `label:…`, `uuid:…`, `partlabel:…` or `serial:…`. Never a device
    /// path: what the kernel called a disk last boot is not what it will
    /// call it next boot.
    pub device: String,
    /// Default true, because the failure this guards is a database that
    /// quietly landed on the root filesystem.
    #[serde(default = "yes")]
    pub required: bool,
    #[serde(default = "yes")]
    pub preserve_on_reinstall: bool,
}

/// The one escape hatch, and it is named. Anything an operator overrides per
/// host goes under `deviations.settings.<role>`, so a review can list the
/// hosts that are not like the others by grepping for one word.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
// No `Eq`: a `toml::Value` can hold a float, and a float is not equal to
// itself in every case the trait promises. Nothing here compares deviations
// for equality; the manifest, which does, carries them as json.
pub struct Deviations {
    #[serde(default)]
    pub settings: BTreeMap<String, toml::Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Host {
    /// What a plan refers to. Never changes, never reused.
    pub id: String,
    /// What the machine calls itself.
    pub name: String,
    pub deployment: Deployment,
    #[serde(default)]
    pub roles: Vec<String>,
    #[serde(default)]
    pub groups: Vec<String>,
    #[serde(default)]
    pub controller_group: Option<String>,
    #[serde(default)]
    pub site: Option<String>,
    #[serde(default)]
    pub failure_domain: Option<String>,
    #[serde(default)]
    pub networks: Networks,
    #[serde(default)]
    pub profiles: Vec<String>,
    /// Operator modules imported for this host only.
    #[serde(default)]
    pub modules: Vec<String>,
    /// What a verification suite may assume of this machine.
    #[serde(default)]
    pub capabilities: Vec<String>,
    #[serde(default)]
    pub hardware: Hardware,
    /// How this machine is booted. Precedence like every other scalar:
    /// defaults < group < host.
    #[serde(default)]
    pub boot: Option<BootMode>,
    #[serde(default)]
    pub install: Option<Install>,
    #[serde(default)]
    pub persistence: Vec<Persistence>,
    #[serde(default)]
    pub ssh: HostSsh,
    #[serde(default)]
    pub rollout: RolloutOverrides,
    #[serde(default)]
    pub checks: ChecksOverrides,
    #[serde(default)]
    pub managed: ManagedOverrides,
    #[serde(default)]
    pub deviations: Deviations,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Service {
    pub id: String,
    pub kind: String,
    /// Default true: something named in this file is this fleet's business
    /// unless it says otherwise.
    #[serde(default = "yes")]
    pub managed: bool,
    #[serde(default)]
    pub host: Option<String>,
    #[serde(default)]
    pub endpoint: Option<BTreeMap<String, String>>,
    #[serde(default)]
    pub trust_ref: Option<String>,
    /// Default true, so that forgetting to say it blocks rather than ships.
    #[serde(default = "yes")]
    pub required: bool,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
struct Raw {
    schema: u32,
    fleet: FleetHeader,
    #[serde(default)]
    defaults: Defaults,
    #[serde(default)]
    operator: Option<Operator>,
    #[serde(default)]
    group: Vec<Group>,
    #[serde(default)]
    host: Vec<Host>,
    #[serde(default)]
    service: Vec<Service>,
}

/// Enough of the file to tell which schema it is, ignoring everything else.
#[derive(Deserialize)]
struct SchemaProbe {
    #[serde(default)]
    schema: Option<u32>,

    /// The one table that was really in the lab's inventory. It is probed
    /// for by name because `deny_unknown_fields` would only say "unknown
    /// field", and this one has an answer: the provider moved.
    #[serde(default)]
    opennebula: Option<toml::Value>,
}

// ---------------------------------------------------------------------------
// The inventory, checked
// ---------------------------------------------------------------------------

/// A `fleet.toml` that parsed and hangs together. Keyed by id and therefore
/// in id order, not file order: two people who sort their file differently
/// get the same output from `inventory --json`.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Inventory {
    pub schema: u32,
    pub fleet: FleetHeader,
    pub defaults: Defaults,
    pub operator: Option<Operator>,
    pub groups: BTreeMap<String, Group>,
    pub hosts: BTreeMap<String, Host>,
    pub services: BTreeMap<String, Service>,
}

/// What ssh this host is reached with, after precedence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EffectiveSsh {
    pub user: String,
    pub port: u16,
    pub host_key: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EffectiveRollout {
    pub max_unavailable: u32,
    pub reboot: RebootPolicy,
    pub canary: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EffectiveChecks {
    pub required: Vec<String>,
    pub functional: Vec<String>,
}

/// What defaults, groups and the host add up to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Settings {
    pub ssh: EffectiveSsh,
    /// Accumulated in precedence order and de-duplicated, first mention
    /// wins: a profile list is an import order, and reordering it changes
    /// which module's option definition is the last word.
    pub profiles: Vec<String>,
    pub boot: BootMode,
    pub rollout: EffectiveRollout,
    pub checks: EffectiveChecks,
    /// Target caches accumulated and deduplicated in precedence order, preserving fetch
    /// preference.
    pub substituters: Vec<String>,
}

/// A host plus what it inherited — what `inventory --json` prints.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct HostView {
    pub id: String,
    pub host: Host,
    pub effective: Settings,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Report {
    pub schema: u32,
    pub fleet: FleetHeader,
    pub operator: Option<Operator>,
    pub groups: BTreeMap<String, Group>,
    pub hosts: Vec<HostView>,
    pub services: BTreeMap<String, Service>,
}

impl Inventory {
    /// Read the file and check it. The two steps are one call because an
    /// inventory that parsed and does not hang together is not something any
    /// caller here has a use for.
    pub fn load(files: &dyn Files, path: &Path) -> Result<Inventory> {
        let text = files.read_to_string(path)?;
        Inventory::parse(&text, &path.display().to_string())
    }

    pub fn parse(text: &str, origin: &str) -> Result<Inventory> {
        check_schema(text, origin)?;
        let raw: Raw = toml::from_str(text)
            .map_err(|e| anyhow::anyhow!("{origin} is not a valid fleet inventory: {e}"))?;

        let mut groups = BTreeMap::new();
        for group in raw.group {
            check_identifier("group id", &group.id, origin)?;
            if groups.insert(group.id.clone(), group.clone()).is_some() {
                bail!("{origin} declares the group {:?} twice.", group.id);
            }
        }
        let mut hosts = BTreeMap::new();
        for host in raw.host {
            check_identifier("host id", &host.id, origin)?;
            check_dns_label("host name", &host.name, origin)?;
            if hosts.insert(host.id.clone(), host.clone()).is_some() {
                bail!("{origin} declares the host {:?} twice.", host.id);
            }
        }
        let mut services = BTreeMap::new();
        for service in raw.service {
            check_identifier("service id", &service.id, origin)?;
            if services
                .insert(service.id.clone(), service.clone())
                .is_some()
            {
                bail!("{origin} declares the service {:?} twice.", service.id);
            }
        }

        let inventory = Inventory {
            schema: raw.schema,
            fleet: raw.fleet,
            defaults: raw.defaults,
            operator: raw.operator,
            groups,
            hosts,
            services,
        };
        inventory.check(origin)?;
        Ok(inventory)
    }

    /// Everything that can be decided from this file alone, and nothing that
    /// cannot. No address is pinged, no name resolved, no store path looked
    /// at: `validate` is an offline verb and stays one.
    fn check(&self, origin: &str) -> Result<()> {
        check_dns_label("fleet name", &self.fleet.name, origin)?;
        if let Some(domain) = &self.fleet.domain {
            check_dns_name("fleet domain", domain, origin)?;
        }
        if self.hosts.is_empty() {
            bail!("{origin} declares no host, so there is no fleet to deploy.");
        }

        let known: BTreeSet<&String> = self.groups.keys().collect();
        for (id, host) in &self.hosts {
            for group in &host.groups {
                if !known.contains(group) {
                    bail!("{origin}: host {id} is in the group {group:?}, which is not declared.");
                }
            }
            if let Some(group) = &host.controller_group
                && !known.contains(group)
            {
                bail!("{origin}: host {id} reports to the group {group:?}, which is not declared.");
            }
            if host.groups.len() != host.groups.iter().collect::<BTreeSet<_>>().len() {
                bail!("{origin}: host {id} lists one of its groups twice.");
            }
            if host.roles.is_empty() {
                bail!("{origin}: host {id} has no role, so nothing would be deployed to it.");
            }

            match host.deployment {
                Deployment::Nixos => {
                    if host.networks.management.is_none() {
                        bail!(
                            "{origin}: host {id} is deployed as nixos and has no \
                             networks.management, which is the address it would be reached at."
                        );
                    }
                }
                Deployment::Context => {
                    if host.install.is_some() {
                        bail!(
                            "{origin}: host {id} is deployed as context and carries an \
                             install table. A context VM is instantiated by somebody else; \
                             this tool never installs one."
                        );
                    }
                }
            }

            if let Some(install) = &host.install {
                check_install(id, install, origin)?;
                let preserved: BTreeSet<&String> = install.preserve.iter().collect();
                for entry in &host.persistence {
                    if entry.preserve_on_reinstall && !preserved.contains(&entry.path) {
                        bail!(
                            "{origin}: host {id} keeps {:?} across a reinstall but \
                             install.preserve does not list it.",
                            entry.path
                        );
                    }
                }
            }
            for entry in &host.persistence {
                check_device_ref(id, &entry.device, origin)?;
            }
            // Precedence has to be decidable for every host, and a conflict
            // between two groups is a fact about the file, not about the run
            // that happens to hit it first.
            self.effective(id)?;
        }

        // Cloud-role hosts must resolve to the same first raft group, or all have no raft
        // group. Nix performs additional group validation.
        let mut clouds: BTreeSet<Option<&String>> = BTreeSet::new();
        for host in self.hosts.values() {
            if !host.roles.iter().any(|r| r == "cloud") {
                continue;
            }
            clouds.insert(host.groups.iter().find(|g| {
                self.groups
                    .get(*g)
                    .map(|group| group.kind == GroupKind::Raft)
                    .unwrap_or(false)
            }));
        }
        if clouds.len() > 1 {
            let named: Vec<&str> = clouds
                .iter()
                .map(|g| g.map(String::as_str).unwrap_or("no raft group"))
                .collect();
            bail!(
                "{origin}: this fleet has two clouds ({}); a fleet has one, and a cluster told \
                 two addresses does not know which is its own.",
                named.join(", ")
            );
        }

        for (id, service) in &self.services {
            if let Some(host) = &service.host
                && !self.hosts.contains_key(host)
            {
                bail!("{origin}: service {id} runs on {host:?}, which is not a declared host.");
            }
            if !service.managed && service.host.is_some() {
                bail!(
                    "{origin}: service {id} is not managed and names a host of this fleet. \
                     One of the two is wrong."
                );
            }
        }
        Ok(())
    }

    /// Defaults, then the host's groups, then the host. Pure, total, and the
    /// only place precedence is spelled out.
    pub fn effective(&self, host_id: &str) -> Result<Settings> {
        let host = self
            .hosts
            .get(host_id)
            .ok_or_else(|| anyhow::anyhow!("there is no host {host_id:?} in this inventory."))?;
        // In the order the host wrote them, so that the sentence about a
        // conflict names the groups the way the operator sees them.
        let groups: Vec<&Group> = host
            .groups
            .iter()
            .filter_map(|id| self.groups.get(id))
            .collect();

        let user = settle(
            host_id,
            "ssh.user",
            &groups,
            host.ssh.user.clone(),
            |g| g.ssh.user.clone(),
            self.defaults.ssh.user.clone(),
        )?
        .unwrap_or_else(|| DEFAULT_SSH_USER.to_string());
        let port = settle(
            host_id,
            "ssh.port",
            &groups,
            host.ssh.port,
            |g| g.ssh.port,
            self.defaults.ssh.port,
        )?
        .unwrap_or(DEFAULT_SSH_PORT);

        // The default is `uefi`, and it is the conservative one: a machine
        // that boots itself is the only one that can take a boot back by
        // itself (D5).
        let boot = settle(
            host_id,
            "boot",
            &groups,
            host.boot,
            |g| g.boot,
            self.defaults.boot,
        )?
        .unwrap_or_default();

        let max_unavailable = settle(
            host_id,
            "rollout.max_unavailable",
            &groups,
            host.rollout.max_unavailable,
            |g| g.rollout.max_unavailable,
            self.defaults.rollout.max_unavailable,
        )?
        .unwrap_or(1);
        let reboot = settle(
            host_id,
            "rollout.reboot",
            &groups,
            host.rollout.reboot,
            |g| g.rollout.reboot,
            self.defaults.rollout.reboot,
        )?
        // The conservative end of the three: a reboot nobody approved is
        // the failure this whole tool exists to prevent.
        .unwrap_or(RebootPolicy::Approve);
        let canary = settle(
            host_id,
            "rollout.canary",
            &groups,
            host.rollout.canary.clone(),
            |g| g.rollout.canary.clone(),
            self.defaults.rollout.canary.clone(),
        )?;

        let mut profiles = Vec::new();
        push_new(&mut profiles, &self.defaults.profiles);
        for group in &groups {
            push_new(&mut profiles, &group.profiles);
        }
        push_new(&mut profiles, &host.profiles);

        let mut required = Vec::new();
        push_new(&mut required, &self.defaults.checks.required);
        for group in &groups {
            push_new(&mut required, &group.checks.required);
        }
        push_new(&mut required, &host.checks.required);

        let mut functional = Vec::new();
        push_new(&mut functional, &self.defaults.checks.functional);
        for group in &groups {
            push_new(&mut functional, &group.checks.functional);
        }
        push_new(&mut functional, &host.checks.functional);

        let mut substituters = Vec::new();
        push_new(&mut substituters, &self.defaults.managed.substituters);
        for group in &groups {
            push_new(&mut substituters, &group.managed.substituters);
        }
        push_new(&mut substituters, &host.managed.substituters);

        Ok(Settings {
            ssh: EffectiveSsh {
                user,
                port,
                host_key: host.ssh.host_key.clone(),
            },
            profiles,
            boot,
            rollout: EffectiveRollout {
                max_unavailable,
                reboot,
                canary,
            },
            checks: EffectiveChecks {
                required,
                functional,
            },
            substituters,
        })
    }

    pub fn report(&self) -> Result<Report> {
        let mut hosts = Vec::new();
        for (id, host) in &self.hosts {
            hosts.push(HostView {
                id: id.clone(),
                host: host.clone(),
                effective: self.effective(id)?,
            });
        }
        Ok(Report {
            schema: self.schema,
            fleet: self.fleet.clone(),
            operator: self.operator.clone(),
            groups: self.groups.clone(),
            hosts,
            services: self.services.clone(),
        })
    }

    /// The table a person reads. Columns are padded to the widest value, so
    /// a fleet of seventy stays one screen wide per column rather than
    /// seventy different widths.
    pub fn table(&self) -> Result<String> {
        let mut rows = vec![[
            "ID".to_string(),
            "NAME".to_string(),
            "DEPLOY".to_string(),
            "ADDRESS".to_string(),
            "ROLES".to_string(),
            "GROUPS".to_string(),
            "PROFILES".to_string(),
            "ENROLLED".to_string(),
        ]];
        for (id, host) in &self.hosts {
            let settings = self.effective(id)?;
            rows.push([
                id.clone(),
                host.name.clone(),
                host.deployment.as_str().to_string(),
                host.networks
                    .management
                    .as_ref()
                    .map(|n| format!("{}/{}", n.address, n.prefix))
                    .unwrap_or_else(|| "-".to_string()),
                join_or_dash(&host.roles),
                join_or_dash(&host.groups),
                join_or_dash(&settings.profiles),
                if settings.ssh.host_key.is_some() {
                    "yes".to_string()
                } else {
                    "no".to_string()
                },
            ]);
        }
        let mut widths = [0usize; 8];
        for row in &rows {
            for (i, cell) in row.iter().enumerate() {
                widths[i] = widths[i].max(cell.chars().count());
            }
        }
        let mut out = String::new();
        for row in &rows {
            let line: Vec<String> = row
                .iter()
                .enumerate()
                .map(|(i, cell)| format!("{cell:<width$}", width = widths[i]))
                .collect();
            out.push_str(line.join("  ").trim_end());
            out.push('\n');
        }
        Ok(out)
    }
}

fn join_or_dash(items: &[String]) -> String {
    if items.is_empty() {
        "-".to_string()
    } else {
        items.join(",")
    }
}

fn push_new(into: &mut Vec<String>, more: &[String]) {
    for item in more {
        if !into.iter().any(|seen| seen == item) {
            into.push(item.clone());
        }
    }
}

/// Resolve one scalar: explicit host value, otherwise one agreed group value, otherwise the
/// default. A host override resolves group disagreement.
fn settle<T: PartialEq + std::fmt::Debug>(
    host_id: &str,
    key: &str,
    groups: &[&Group],
    from_host: Option<T>,
    get: impl Fn(&Group) -> Option<T>,
    from_defaults: Option<T>,
) -> Result<Option<T>> {
    if from_host.is_some() {
        return Ok(from_host);
    }
    Ok(one_of(host_id, key, groups, get)?.or(from_defaults))
}

/// Return the agreed value from equal-rank groups; reject conflicting values with both group
/// names.
fn one_of<T: PartialEq + std::fmt::Debug>(
    host_id: &str,
    key: &str,
    groups: &[&Group],
    get: impl Fn(&Group) -> Option<T>,
) -> Result<Option<T>> {
    let mut chosen: Option<(&str, T)> = None;
    for group in groups {
        let Some(value) = get(group) else { continue };
        match &chosen {
            None => chosen = Some((group.id.as_str(), value)),
            Some((first, seen)) if *seen != value => bail!(
                "host {host_id} is in the groups {first} and {}, and they set {key} to \
                 {seen:?} and {value:?}. Two groups of equal rank cannot both decide it: \
                 set {key} on the host, or take it out of one of the groups.",
                group.id
            ),
            Some(_) => {}
        }
    }
    Ok(chosen.map(|(_, value)| value))
}

fn check_schema(text: &str, origin: &str) -> Result<()> {
    let probe: SchemaProbe =
        toml::from_str(text).map_err(|e| anyhow::anyhow!("{origin} is not valid toml: {e}"))?;

    if probe.opennebula.is_some() {
        bail!(
            "{origin} has an `[opennebula]` table. It is not part of a schema {SCHEMA} \
             inventory: it was parsed and exported by the pre-v1 plan and read by nothing, \
             and the OpenNebula adapter moved to the lab repository \
             (~/git/meisterstack-lab/providers/opennebula/). Delete the table. Where a \
             machine IS instantiated is the provider's business and not this fleet's; what \
             this inventory says about such a host is `deployment = \"context\"`."
        );
    }

    match probe.schema {
        Some(SCHEMA) => Ok(()),
        Some(1) | None => bail!(
            "{origin} has no `schema = {SCHEMA}` line, so it is the pre-v1 inventory. \
             Nothing reads that one any more — the verbs that did went with M5B. \
             Migrating it means writing the hosts as `[[host]]` with an `id`, a \
             `deployment` and their groups, and letting Nix derive the addresses."
        ),
        Some(other) => {
            bail!("{origin} says `schema = {other}`, and this tool reads schema {SCHEMA}.")
        }
    }
}

fn check_install(host_id: &str, install: &Install, origin: &str) -> Result<()> {
    match (&install.disk.serial, &install.disk.wwn) {
        (None, None) => bail!(
            "{origin}: host {host_id} has an install table whose disk names neither a \
             serial nor a wwn. An installation formats a disk, and the only safe way to \
             say which one is an identifier the disk carries itself."
        ),
        _ => {
            for (what, value) in [("serial", &install.disk.serial), ("wwn", &install.disk.wwn)] {
                if let Some(value) = value
                    && (value.starts_with("/dev/") || value.starts_with("/sys/"))
                {
                    bail!(
                        "{origin}: host {host_id} names {value:?} as its disk {what}. \
                         A device path is what the kernel called a disk during one boot; \
                         it is not the disk. Use the serial from `lsblk -o SERIAL`."
                    );
                }
            }
            if install.layout.is_empty() {
                bail!("{origin}: host {host_id} has an install table with no layout.");
            }
            // Reject private material and require an SSH public-key prefix before embedding
            // authorized keys.
            for key in &install.authorized_keys {
                if key.contains("PRIVATE KEY") {
                    bail!(
                        "{origin}: host {host_id} has something with \"PRIVATE KEY\" in it \
                         under install.authorized_keys. That list is baked into an installer \
                         medium, which is a file anybody who holds the medium can read. Only \
                         public halves belong in it."
                    );
                }
                let looks_like_a_key = key
                    .split_once(' ')
                    .map(|(kind, rest)| {
                        (kind.starts_with("ssh-")
                            || kind.starts_with("ecdsa-")
                            || kind.starts_with("sk-"))
                            && !rest.trim().is_empty()
                    })
                    .unwrap_or(false);
                if !looks_like_a_key {
                    bail!(
                        "{origin}: host {host_id} names {key:?} in install.authorized_keys, \
                         and that is not an ssh public key. One line per key, as \
                         `~/.ssh/id_ed25519.pub` holds it: `ssh-ed25519 AAAA... comment`."
                    );
                }
            }
            Ok(())
        }
    }
}

/// A persistent mount is bound to something the disk carries, never to a
/// device path.
fn check_device_ref(host_id: &str, device: &str, origin: &str) -> Result<()> {
    const KINDS: [&str; 4] = ["label:", "uuid:", "partlabel:", "serial:"];
    if KINDS.iter().any(|kind| device.starts_with(kind)) {
        return Ok(());
    }
    bail!(
        "{origin}: host {host_id} binds a persistent path to {device:?}. \
         It has to start with one of {}, because a device path can point at a \
         different disk after a reboot.",
        KINDS.join(", ")
    )
}

/// RFC 1123: what a machine may be called, and what a certificate can carry.
fn check_dns_label(what: &str, value: &str, origin: &str) -> Result<()> {
    let ok = !value.is_empty()
        && value.len() <= 63
        && value
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        && !value.starts_with('-')
        && !value.ends_with('-');
    if ok {
        Ok(())
    } else {
        bail!(
            "{origin}: {value:?} is not a valid {what}. It has to be a dns label: \
             lower-case letters, digits and hyphens, at most 63 of them, not starting \
             or ending with a hyphen."
        )
    }
}

fn check_dns_name(what: &str, value: &str, origin: &str) -> Result<()> {
    if value.is_empty() || value.len() > 253 {
        bail!("{origin}: {value:?} is not a valid {what}.");
    }
    for label in value.split('.') {
        check_dns_label(what, label, origin)?;
    }
    Ok(())
}

/// IDs are ASCII alphanumeric, hyphen or underscore, up to 63 bytes, starting alphanumeric.
/// They need not be DNS labels.
fn check_identifier(what: &str, value: &str, origin: &str) -> Result<()> {
    let ok = !value.is_empty()
        && value.len() <= 63
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        && value.starts_with(|c: char| c.is_ascii_alphanumeric());
    if ok {
        Ok(())
    } else {
        bail!(
            "{origin}: {value:?} is not a valid {what}. It has to start with a letter or \
             a digit and may then carry letters, digits, hyphens and underscores, at most \
             63 of them."
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> &'static str {
        include_str!("../tests/fixtures/fleet-v2.toml")
    }

    fn parse(text: &str) -> Result<Inventory> {
        Inventory::parse(text, "fleet.toml")
    }

    #[test]
    fn two_clouds_are_refused_by_the_parser_and_not_only_by_nix() {
        // L2 finding N11: `validate` said ok to an inventory `nix eval`
        // refuses, and the operator found out one build later.
        let text = format!(
            "{}\n{}",
            fixture(),
            r#"
[[group]]
id = "cloud_b"
kind = "raft"

[[host]]
id = "cloud-b"
name = "meister-cloud-b"
deployment = "nixos"
roles = ["cloud"]
groups = ["cloud_b"]
site = "ikr-lab"
failure_domain = "rack2"
networks.management = { address = "10.128.1.104", prefix = 24, interface = "eno1" }
"#
        );
        let err = parse(&text).unwrap_err().to_string();
        assert!(err.contains("two clouds"), "{err}");
        assert!(err.contains("cloud_b"), "{err}");
        // The same words nix/lib/inventory.nix uses, so that an operator
        // who has seen one of the two recognises the other.
        assert!(err.contains("does not know which is its own"), "{err}");
    }

    #[test]
    fn two_cloud_hosts_in_one_group_are_a_cloud_and_not_two() {
        // The shape a real fleet has: a cloud of three replicas in one
        // raft group. The rule is about GROUPS, not about hosts.
        let text = fixture().replace(
            r#"[[host]]
id = "gpu-01"
name = "agent-2b"
deployment = "nixos"
roles = ["agent"]"#,
            r#"[[host]]
id = "cloud-b"
name = "meister-cloud-b"
deployment = "nixos"
roles = ["cloud"]
groups = ["cloud"]
site = "ikr-lab"
failure_domain = "rack2"
networks.management = { address = "10.128.1.104", prefix = 24, interface = "eno1" }

[[host]]
id = "gpu-01"
name = "agent-2b"
deployment = "nixos"
roles = ["agent"]"#,
        );
        parse(&text).expect("one cloud, two of its hosts");
    }

    #[test]
    fn a_host_that_brings_its_own_loader_has_a_word_for_it() {
        // A managed disk image uses GRUB and must not request a UEFI boot fallback.
        assert_eq!(BootMode::parse("grub").unwrap(), BootMode::Grub);
        assert_eq!(BootMode::Grub.as_str(), "grub");

        let text = fixture().replace(
            r#"roles = ["cloud", "addons"]"#,
            "boot = \"grub\"\nroles = [\"cloud\", \"addons\"]",
        );
        let inventory = parse(&text).unwrap();
        assert_eq!(
            inventory.effective("cloud-a").unwrap().boot,
            BootMode::Grub,
            "precedence carries it like every other setting"
        );
        // And the round trip through the contract's own spelling.
        let json = serde_json::to_string(&BootMode::Grub).unwrap();
        assert_eq!(json, "\"grub\"");
        assert_eq!(
            serde_json::from_str::<crate::manifest::BootMode>(&json).unwrap(),
            crate::manifest::BootMode::Grub
        );
    }

    #[test]
    fn bios_is_still_refused_and_now_names_the_value_that_exists() {
        let err = BootMode::parse("bios").unwrap_err().to_string();
        assert!(err.contains("that value is `grub`"), "{err}");
        assert!(err.contains("no boot fallback"), "{err}");
    }

    #[test]
    fn a_network_belongs_to_the_host_unless_the_plan_says_static() {
        // The default, which is the case an operator does not have to think
        // about: the address is how this tool reaches the host, and the
        // host's own configuration owns the interface.
        let inventory = parse(fixture()).unwrap();
        let net = inventory.hosts["cloud-a"]
            .networks
            .management
            .as_ref()
            .unwrap();
        assert_eq!(net.address, "10.128.1.103");
        assert!(!net.r#static, "an address is not a claim on the interface");

        // And the fleet saying otherwise, which nix/lib/inventory.nix turns
        // into `networking.interfaces.<if>.ipv4.addresses`.
        let text = fixture().replace(
            r#"networks.management = { address = "10.128.1.103", prefix = 24, interface = "eno1" }"#,
            r#"networks.management = { address = "10.128.1.103", prefix = 24, interface = "eno1", static = true }"#,
        );
        let claimed = parse(&text).unwrap();
        assert!(
            claimed.hosts["cloud-a"]
                .networks
                .management
                .as_ref()
                .unwrap()
                .r#static
        );
    }

    #[test]
    fn the_fixture_reads_back_as_the_brief_wrote_it() {
        let inventory = parse(fixture()).unwrap();
        assert_eq!(inventory.schema, 2);
        assert_eq!(inventory.fleet.name, "uni-lab");
        assert_eq!(inventory.fleet.domain.as_deref(), Some("lab"));
        assert_eq!(inventory.hosts.len(), 3);
        assert_eq!(inventory.groups.len(), 2);
        assert_eq!(inventory.services.len(), 1);
        assert_eq!(
            inventory.operator.as_ref().unwrap().cli_profile.as_deref(),
            Some("cloud-mtls")
        );
        let gpu = &inventory.hosts["gpu-01"];
        assert_eq!(gpu.hardware.gpus[0].pci, "0000:41:00.0");
        assert!(gpu.hardware.nics[0].rdma);
        assert_eq!(gpu.capabilities, vec!["kvm", "vfio", "rdma"]);
        assert!(gpu.deviations.settings.contains_key("agent"));
    }

    #[test]
    fn substituters_accumulate_the_way_profiles_do() {
        // Nothing said anywhere is a fleet that is only ever pushed to.
        let inventory = parse(fixture()).unwrap();
        assert_eq!(
            inventory.effective("cloud-a").unwrap().substituters,
            vec![] as Vec<String>
        );

        // A fleet-wide cache, a group that adds a regional mirror, a host
        // that adds one of its own: the list is the ORDER nix tries them
        // in, so it accumulates rather than overriding.
        let text = fixture()
            .replace(
                "[defaults]",
                "[defaults]\nmanaged = { substituters = [\"http://build/cache\"] }",
            )
            .replace(
                r#"[[group]]
id = "compute_pro6000""#,
                r#"[[group]]
managed = { substituters = ["http://rack1/cache"] }
id = "compute_pro6000""#,
            )
            .replace(
                r#"id = "gpu-01""#,
                r#"id = "gpu-01"
managed = { substituters = ["http://gpu-01-local/cache"] }"#,
            );
        let inventory = parse(&text).unwrap();
        assert_eq!(
            inventory.effective("gpu-01").unwrap().substituters,
            vec![
                "http://build/cache",
                "http://rack1/cache",
                "http://gpu-01-local/cache"
            ]
        );
        // And a host that is in no such group gets the fleet's answer only.
        assert_eq!(
            inventory.effective("cloud-a").unwrap().substituters,
            vec!["http://build/cache"]
        );
    }

    #[test]
    fn precedence_runs_defaults_then_group_then_host() {
        let inventory = parse(fixture()).unwrap();
        let cloud = inventory.effective("cloud-a").unwrap();
        assert_eq!(cloud.ssh.user, "root", "from defaults");
        assert_eq!(cloud.ssh.port, 22, "from defaults");
        assert_eq!(
            cloud.profiles,
            vec!["base", "controller"],
            "defaults first, then the group's"
        );
        assert_eq!(cloud.rollout.reboot, RebootPolicy::Approve);
        assert_eq!(cloud.checks.required, vec!["units", "session", "mounts"]);

        let gpu = inventory.effective("gpu-01").unwrap();
        assert_eq!(gpu.ssh.port, 2222, "the host overrides the default");
        assert_eq!(gpu.rollout.reboot, RebootPolicy::Never, "from its group");
        assert_eq!(gpu.profiles, vec!["base", "compute-gpu-pro6000"]);
        assert_eq!(
            gpu.checks.required,
            vec!["units", "session", "mounts", "gpu"],
            "a group adds checks, it does not replace them"
        );
    }

    #[test]
    fn a_host_key_is_a_host_key_and_not_a_default() {
        let inventory = parse(fixture()).unwrap();
        assert!(
            inventory
                .effective("cloud-a")
                .unwrap()
                .ssh
                .host_key
                .is_some()
        );
        assert!(
            inventory
                .effective("ctx-agent-1")
                .unwrap()
                .ssh
                .host_key
                .is_none(),
            "not enrolled is a state, not a default"
        );
        let text = fixture().replace(
            "ssh = { user = \"root\", port = 22 }",
            "ssh = { user = \"root\", port = 22, host_key = \"SHA256:x\" }",
        );
        let err = parse(&text).unwrap_err().to_string();
        assert!(err.contains("host_key"), "{err}");
    }

    #[test]
    fn two_groups_that_disagree_name_the_host_the_key_and_both_groups() {
        let text = format!(
            "{}\n[[group]]\nid = \"rack-b\"\nkind = \"custom\"\nrollout = {{ reboot = \"auto\" }}\n",
            fixture().replace(
                "groups = [\"compute_pro6000\"]",
                "groups = [\"compute_pro6000\", \"rack-b\"]"
            )
        );
        let err = parse(&text).unwrap_err().to_string();
        assert!(err.contains("gpu-01"), "{err}");
        assert!(err.contains("compute_pro6000"), "{err}");
        assert!(err.contains("rack-b"), "{err}");
        assert!(err.contains("rollout.reboot"), "{err}");
        assert!(err.contains("Never") || err.contains("Auto"), "{err}");
    }

    #[test]
    fn two_groups_that_agree_are_not_a_conflict() {
        let text = format!(
            "{}\n[[group]]\nid = \"rack-b\"\nkind = \"custom\"\nrollout = {{ reboot = \"never\" }}\n",
            fixture().replace(
                "groups = [\"compute_pro6000\"]",
                "groups = [\"compute_pro6000\", \"rack-b\"]"
            )
        );
        let inventory = parse(&text).unwrap();
        assert_eq!(
            inventory.effective("gpu-01").unwrap().rollout.reboot,
            RebootPolicy::Never
        );
    }

    #[test]
    fn a_host_settles_what_its_groups_could_not() {
        let text = format!(
            "{}\n[[group]]\nid = \"rack-b\"\nkind = \"custom\"\nrollout = {{ reboot = \"auto\" }}\n",
            fixture()
                .replace(
                    "groups = [\"compute_pro6000\"]",
                    "groups = [\"compute_pro6000\", \"rack-b\"]"
                )
                .replace(
                    "ssh.port = 2222",
                    "ssh.port = 2222\nrollout = { reboot = \"approve\" }"
                )
        );
        let inventory = parse(&text).unwrap();
        assert_eq!(
            inventory.effective("gpu-01").unwrap().rollout.reboot,
            RebootPolicy::Approve
        );
    }

    #[test]
    fn the_old_schema_says_what_to_do_with_it() {
        let err = parse("[fleet]\nname = \"one-box\"\n")
            .unwrap_err()
            .to_string();
        assert!(err.contains("pre-v1 inventory"), "{err}");
        assert!(err.contains("schema = 2"), "{err}");

        let err = parse("schema = 1\n[fleet]\nname = \"one-box\"\n")
            .unwrap_err()
            .to_string();
        assert!(err.contains("pre-v1 inventory"), "{err}");

        let err = parse("schema = 3\n[fleet]\nname = \"one-box\"\n")
            .unwrap_err()
            .to_string();
        assert!(err.contains("schema = 3"), "{err}");
    }

    #[test]
    fn a_key_nobody_declared_is_refused() {
        let text = fixture().replace("[defaults]", "[nonsense]\nfrontend = \"x\"\n\n[defaults]");
        let err = parse(&text).unwrap_err().to_string();
        assert!(err.contains("nonsense"), "{err}");
    }

    /// The table that was really there gets a sentence rather than "unknown
    /// field", because there is something to say about it: the provider it
    /// named lives somewhere else now.
    #[test]
    fn the_opennebula_table_is_refused_by_name_and_says_where_it_went() {
        let text = fixture().replace("[operator]", "[opennebula]\nfrontend = \"x\"\n\n[operator]");
        let err = parse(&text).unwrap_err().to_string();
        assert!(err.contains("[opennebula]"), "{err}");
        assert!(err.contains("meisterstack-lab"), "{err}");
        assert!(err.contains("deployment = \"context\""), "{err}");
    }

    #[test]
    fn a_group_that_is_not_declared_is_refused() {
        let text = fixture().replace("groups = [\"cloud\"]", "groups = [\"clod\"]");
        let err = parse(&text).unwrap_err().to_string();
        assert!(err.contains("cloud-a"), "{err}");
        assert!(err.contains("\"clod\""), "{err}");
    }

    #[test]
    fn two_hosts_with_one_id_are_refused() {
        let text = fixture().replace("id = \"gpu-01\"", "id = \"cloud-a\"");
        let err = parse(&text).unwrap_err().to_string();
        assert!(err.contains("cloud-a"), "{err}");
        assert!(err.contains("twice"), "{err}");
    }

    #[test]
    fn a_name_that_is_not_a_dns_label_is_refused() {
        let text = fixture().replace("name = \"meister-cloud\"", "name = \"Meister_Cloud\"");
        let err = parse(&text).unwrap_err().to_string();
        assert!(err.contains("dns label"), "{err}");
        assert!(err.contains("Meister_Cloud"), "{err}");
    }

    #[test]
    fn a_group_id_may_carry_an_underscore_because_it_is_never_in_dns() {
        let inventory = parse(fixture()).unwrap();
        assert!(inventory.groups.contains_key("compute_pro6000"));
    }

    // ---------------------------------------------------------------
    // Boot-mode validation
    // ---------------------------------------------------------------

    #[test]
    fn a_host_boots_uefi_unless_somebody_said_otherwise() {
        let inventory = parse(fixture()).unwrap();
        for id in ["cloud-a", "gpu-01", "ctx-agent-1"] {
            assert_eq!(
                inventory.effective(id).unwrap().boot,
                BootMode::Uefi,
                "{id} inherited the default"
            );
        }
    }

    #[test]
    fn boot_follows_defaults_then_group_then_host() {
        // Defaults reach everybody.
        let text = fixture().replace(
            "[defaults]\nssh = { user = \"root\", port = 22 }",
            "[defaults]\nboot = \"direct\"\nssh = { user = \"root\", port = 22 }",
        );
        let inventory = parse(&text).unwrap();
        assert_eq!(
            inventory.effective("cloud-a").unwrap().boot,
            BootMode::Direct
        );

        // A group overrides the defaults for its members and nobody else.
        let text = text.replace(
            "id = \"compute_pro6000\"\nkind = \"compute\"",
            "id = \"compute_pro6000\"\nkind = \"compute\"\nboot = \"uefi\"",
        );
        let inventory = parse(&text).unwrap();
        assert_eq!(inventory.effective("gpu-01").unwrap().boot, BootMode::Uefi);
        assert_eq!(
            inventory.effective("cloud-a").unwrap().boot,
            BootMode::Direct
        );

        // And the host has the last word.
        let text = text.replace(
            "id = \"gpu-01\"\nname = \"agent-2b\"",
            "id = \"gpu-01\"\nname = \"agent-2b\"\nboot = \"direct\"",
        );
        let inventory = parse(&text).unwrap();
        assert_eq!(
            inventory.effective("gpu-01").unwrap().boot,
            BootMode::Direct
        );
    }

    #[test]
    fn two_groups_that_disagree_about_boot_are_a_sentence() {
        let text = fixture()
            .replace(
                "id = \"cloud\"\nkind = \"raft\"",
                "id = \"cloud\"\nkind = \"raft\"\nboot = \"uefi\"",
            )
            .replace(
                "id = \"compute_pro6000\"\nkind = \"compute\"",
                "id = \"compute_pro6000\"\nkind = \"compute\"\nboot = \"direct\"",
            )
            .replace(
                "groups = [\"compute_pro6000\"]",
                "groups = [\"compute_pro6000\", \"cloud\"]",
            );
        // The conflict is found while the file is read, not when somebody
        // asks: an inventory that cannot be settled is not an inventory.
        let err = parse(&text).unwrap_err().to_string();
        assert!(err.contains("set boot on the host"), "{err}");
        assert!(err.contains("cannot both decide it"), "{err}");
    }

    #[test]
    fn bios_is_refused_by_name_and_says_why() {
        let text = fixture().replace(
            "id = \"cloud-a\"\nname = \"meister-cloud\"",
            "id = \"cloud-a\"\nname = \"meister-cloud\"\nboot = \"bios\"",
        );
        let err = parse(&text).unwrap_err().to_string();
        assert!(err.contains("uefi or direct"), "{err}");
        assert!(err.contains("no boot fallback"), "{err}");

        // And a word that is neither lists the two that are.
        let text = fixture().replace(
            "id = \"cloud-a\"\nname = \"meister-cloud\"",
            "id = \"cloud-a\"\nname = \"meister-cloud\"\nboot = \"netboot\"",
        );
        let err = parse(&text).unwrap_err().to_string();
        assert!(err.contains("netboot"), "{err}");
        assert!(err.contains("uefi"), "{err}");
    }

    #[test]
    fn an_installer_medium_carries_public_keys_and_only_those() {
        let with_key = |keys: &str| {
            fixture().replace(
                "layout = \"disko/single-nvme.nix\", preserve = [\"/var/lib/meister-data\"] }",
                &format!(
                    "layout = \"disko/single-nvme.nix\", preserve = [\"/var/lib/meister-data\"], \
                     authorized_keys = [{keys}] }}"
                ),
            )
        };

        let ok = parse(&with_key(
            "\"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA silas@manacor\"",
        ))
        .unwrap();
        assert_eq!(
            ok.hosts["cloud-a"]
                .install
                .as_ref()
                .unwrap()
                .authorized_keys
                .len(),
            1
        );

        // An empty list is the default and means: no sshd on the medium.
        let none = parse(fixture()).unwrap();
        assert!(
            none.hosts["cloud-a"]
                .install
                .as_ref()
                .unwrap()
                .authorized_keys
                .is_empty()
        );

        let err = parse(&with_key("\"hunter2\"")).unwrap_err().to_string();
        assert!(err.contains("not an ssh public key"), "{err}");

        let err = parse(&with_key("\"-----BEGIN OPENSSH PRIVATE KEY----- b64\""))
            .unwrap_err()
            .to_string();
        assert!(err.contains("PRIVATE KEY"), "{err}");
        assert!(err.contains("anybody who holds the medium"), "{err}");
    }

    #[test]
    fn a_device_path_is_never_a_disk() {
        let text = fixture().replace("serial = \"S6PENX0T123456\"", "serial = \"/dev/nvme0n1\"");
        let err = parse(&text).unwrap_err().to_string();
        assert!(err.contains("/dev/nvme0n1"), "{err}");
        assert!(err.contains("lsblk -o SERIAL"), "{err}");
    }

    #[test]
    fn an_install_disk_needs_a_serial_or_a_wwn() {
        let text = fixture().replace("serial = \"S6PENX0T123456\", ", "");
        let err = parse(&text).unwrap_err().to_string();
        assert!(err.contains("neither a serial nor a wwn"), "{err}");

        let text = fixture().replace(
            "serial = \"S6PENX0T123456\"",
            "wwn = \"eui.0025388a71b1c2d3\"",
        );
        assert!(parse(&text).is_ok(), "a wwn alone is enough");
    }

    #[test]
    fn a_persistent_path_is_bound_to_something_the_disk_carries() {
        let text = fixture().replace("device = \"label:meister-data\"", "device = \"/dev/sdb1\"");
        let err = parse(&text).unwrap_err().to_string();
        assert!(err.contains("/dev/sdb1"), "{err}");
        assert!(err.contains("label:"), "{err}");
    }

    #[test]
    fn preserved_data_has_to_be_named_in_install_preserve() {
        let text = fixture().replace("preserve = [\"/var/lib/meister-data\"]", "preserve = []");
        let err = parse(&text).unwrap_err().to_string();
        assert!(err.contains("cloud-a"), "{err}");
        assert!(err.contains("install.preserve"), "{err}");
    }

    #[test]
    fn a_nixos_host_without_an_address_is_refused() {
        let text = fixture().replace(
            "networks.management = { address = \"10.128.1.103\", prefix = 24, interface = \"eno1\" }\n",
            "",
        );
        let err = parse(&text).unwrap_err().to_string();
        assert!(err.contains("networks.management"), "{err}");
    }

    #[test]
    fn a_context_host_is_never_installed_by_this_tool() {
        let text = fixture().replace(
            "id = \"ctx-agent-1\"",
            "id = \"ctx-agent-1\"\ninstall = { disk = { serial = \"x\" }, layout = \"d.nix\" }",
        );
        let err = parse(&text).unwrap_err().to_string();
        assert!(err.contains("ctx-agent-1"), "{err}");
        assert!(err.contains("never installs one"), "{err}");
    }

    #[test]
    fn an_unmanaged_service_does_not_claim_a_host_of_this_fleet() {
        let text = fixture().replace(
            "trust_ref = \"trust/external-ca.crt\"",
            "trust_ref = \"trust/external-ca.crt\"\nhost = \"cloud-a\"",
        );
        let err = parse(&text).unwrap_err().to_string();
        assert!(err.contains("observability-external"), "{err}");
    }

    #[test]
    fn a_report_carries_the_host_and_what_it_inherited() {
        let inventory = parse(fixture()).unwrap();
        let report = inventory.report().unwrap();
        assert_eq!(report.hosts.len(), 3);
        let json = serde_json::to_string(&report).unwrap();
        assert!(json.contains(r#""effective""#), "{json}");
        assert!(json.contains(r#""compute-gpu-pro6000""#));
        // Nothing derived: the json carries what the file said and what
        // precedence made of it, and no address of anybody else.
        assert!(!json.contains("peers"), "{json}");
    }

    #[test]
    fn the_table_lines_up_and_says_who_is_enrolled() {
        let inventory = parse(fixture()).unwrap();
        let table = inventory.table().unwrap();
        let lines: Vec<&str> = table.lines().collect();
        assert_eq!(lines.len(), 4, "a header and three hosts:\n{table}");
        assert!(lines[0].starts_with("ID "), "{table}");
        assert!(lines.iter().any(|l| l.contains("ctx-agent-1")), "{table}");
        assert!(lines.iter().any(|l| l.contains("context")), "{table}");
        // Every row starts its NAME where the header does.
        let column = lines[0].find("NAME").unwrap();
        for line in &lines {
            assert_ne!(
                line.chars().nth(column),
                Some(' '),
                "column {column} is ragged:\n{table}"
            );
        }
    }

    #[test]
    fn an_inventory_with_no_host_is_not_a_fleet() {
        let err = parse("schema = 2\n[fleet]\nname = \"empty\"\n")
            .unwrap_err()
            .to_string();
        assert!(err.contains("no host"), "{err}");
    }

    #[test]
    fn a_host_with_no_role_is_refused() {
        let text = fixture().replace("roles = [\"cloud\", \"addons\"]", "roles = []");
        let err = parse(&text).unwrap_err().to_string();
        assert!(err.contains("no role"), "{err}");
    }

    #[test]
    fn something_that_is_not_toml_says_so() {
        let err = parse("schema = 2\nthis is not toml")
            .unwrap_err()
            .to_string();
        assert!(err.contains("not valid toml"), "{err}");
    }
}
