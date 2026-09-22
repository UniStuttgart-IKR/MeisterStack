// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! The first two of the four contracts: what Nix says, and what `resolve`
//! made of it.
//!
//! [`NixManifest`] is the `meisterDeployment` attribute of an operator's
//! flake — the whole of what Nix derived from `fleet.toml`, evaluated once and
//! handed over as JSON. [`ResolvedFleet`] is that, plus who asked and from
//! which tree, with an id over its content. Nothing between the two derives a
//! deployment value: `resolve` joins, checks and names, and that is all it is
//! allowed to do, because Nix is the single derivation (D2) and a second one
//! in Rust would be a second answer to keep in step.
//!
//! **This module is the contract for lane 1B.** Two rules make it one rather
//! than a suggestion:
//!
//! * Every field is required. The ones that may have no value are `null`,
//!   not absent — a missing key is a field somebody forgot, and the two
//!   cases have to be told apart.
//! * Every struct is `deny_unknown_fields`. A key Nix emits and Rust does
//!   not know is an error here, not a value quietly dropped on the way to a
//!   receipt.
//!
//! Numbers are integers. Sizes are bytes (`size_bytes`), not gigabytes, even
//! where the inventory is written in gigabytes: the conversion belongs to the
//! one derivation. File modes are strings (`"0600"`), because `0600` in JSON
//! is the number six hundred.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Result, bail};
use chrono::{DateTime, Utc};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::ids::{IdKind, content_id};

pub const NIX_MANIFEST_SCHEMA: &str = "meister-deploy/nix-manifest/1";
pub const RESOLVED_FLEET_SCHEMA: &str = "meister-deploy/resolved-fleet/1";

// ---------------------------------------------------------------------------
// Pieces both contracts share
// ---------------------------------------------------------------------------

/// The fleet's own name, and the `schema` of the inventory it came from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Fleet {
    pub name: String,
    /// The DNS domain hosts are named in, or null for a fleet that has none.
    pub domain: Option<String>,
    /// The inventory schema this was derived from. `2` for v1 of this tool.
    pub schema: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum GroupKind {
    /// Members form a raft quorum, so how many may be unavailable follows
    /// from the size and is not an operator's choice.
    Raft,
    /// Members are interchangeable workload carriers.
    Compute,
    /// Neither: a grouping the operator uses for selection only.
    Custom,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Quorum {
    pub size: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RebootPolicy {
    /// A reboot may happen without anybody being asked.
    Auto,
    /// A reboot needs `--approve reboot=<plan_id>`.
    Approve,
    /// A plan that would need a reboot is blocked instead.
    Never,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Rollout {
    /// Which class this host is the canary of, or null. Hosts of one class
    /// share a kernel, a driver, a hypervisor and a NIC — a canary is only
    /// evidence for the class it belongs to.
    pub canary_class: Option<String>,
    pub max_unavailable: u32,
    pub reboot: RebootPolicy,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Group {
    pub kind: GroupKind,
    /// Host ids, in the order the derivation put them. Derived by Nix from
    /// host membership; never computed here.
    pub members: Vec<String>,
    /// Present for `raft`, null otherwise.
    pub quorum: Option<Quorum>,
    pub profiles: Vec<String>,
    pub rollout: Rollout,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Deployment {
    /// A NixOS host this flake builds a system for and `meister-deploy`
    /// takes forward closure by closure.
    Nixos,
    /// A VM somebody else instantiated, served by the pre-v1 push until L3.
    Context,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Ssh {
    pub user: String,
    pub port: u16,
    /// `SHA256:…` of the host key, as `keys enroll` wrote it into the
    /// operator's `known_hosts`. Null for a host that is not enrolled yet —
    /// which is a state, not a failure, and never "healthy".
    pub host_key_fingerprint: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Network {
    pub address: String,
    pub prefix: u8,
    pub interface: Option<String>,
    pub gateway: Option<String>,
}

/// The four networks a host can be on. Only `management` is a fleet-wide
/// requirement: it is the one `meister-deploy` reaches the host over.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Networks {
    pub management: Network,
    pub storage: Option<Network>,
    pub tenant: Option<Network>,
    pub bmc: Option<Network>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Gpu {
    pub model: String,
    /// The PCI address, `0000:41:00.0`. Checked against `lspci` before an
    /// activation that claims to have configured it.
    pub pci: String,
    /// What it is bound to: `vfio`, `nvrm`, or null for unassigned.
    pub selected_for: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Nic {
    pub name: String,
    pub mac: String,
    /// `management`, `storage`, `tenant`.
    pub role: String,
    pub rdma: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Hardware {
    /// The CPU as the operator declared it, or null when it is not declared.
    pub cpu: Option<String>,
    pub memory_gb: Option<u32>,
    pub gpus: Vec<Gpu>,
    pub nics: Vec<Nic>,
    /// `kvm`, `vfio`, `rdma`: what a verification suite may assume. A
    /// capability that is declared and missing blocks; one that is not
    /// declared makes its suite `not_applicable`.
    pub capabilities: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Disk {
    /// The disk's own serial. Never a device path: `/dev/sda` is a name the
    /// kernel hands out in boot order, and installing over the wrong one is
    /// not recoverable.
    pub serial: String,
    pub wwn: Option<String>,
    pub size_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Install {
    pub disk: Disk,
    /// The disko layout module, relative to the operator's repository.
    pub layout: String,
    /// Paths a reinstall keeps. Checked against `persistence` before an
    /// install is planned.
    pub preserve: Vec<String>,
    /// PUBLIC ssh keys that may reach the installer MEDIUM, and the thing
    /// that decides whether that medium has an sshd at all. Empty is the
    /// default and means the console is the only way in — which is the right
    /// answer for an image somebody carries to a machine by hand.
    pub authorized_keys: Vec<String>,
}

/// How a host gets its kernel: the contract's copy of
/// [`crate::inventory::BootMode`].
///
/// Two types for one word, like [`RebootPolicy`] beside it, and for the same
/// reason: this one is part of a JSON contract that other programs read
/// (`deny_unknown_fields`, a JSON Schema, a stable spelling), and the other
/// is how a TOML file somebody edits is parsed. Nix writes this one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum BootMode {
    /// The machine boots itself: an ESP, systemd-boot, a boot menu — and
    /// therefore a way back from a boot (`bootctl set-oneshot`).
    Uefi,
    /// A hypervisor hands it kernel, initrd and command line. No loader
    /// inside, no boot menu, and the next boot is the provider's fact and
    /// not the guest's.
    Direct,
}

impl BootMode {
    pub fn as_str(self) -> &'static str {
        match self {
            BootMode::Uefi => "uefi",
            BootMode::Direct => "direct",
        }
    }
}

impl std::fmt::Display for BootMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.pad(self.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Persistence {
    pub path: String,
    /// `label:meister-data` or `serial:S6PENX0T123456`. A label or a serial,
    /// never a device path, for the same reason as [`Disk::serial`].
    pub device_ref: String,
    /// A required mount that is missing blocks the host. There is no fallback
    /// to the root filesystem: a database that silently lands on the wrong
    /// disk is worse than a host that refuses to come up.
    pub required: bool,
    pub preserve_on_reinstall: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SecretKind {
    IdentityKey,
    ServingKey,
    SecretsKey,
    CaBundle,
    Crl,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum SecretSourceKind {
    /// Issued by `tools/meister-ca` from a CSR.
    MeisterCa,
    /// The private half never leaves the target: `meister-activate keygen`
    /// made it there and only the CSR travelled.
    TargetGenerated,
    /// A file the operator keeps outside this tool.
    OperatorFile,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SecretSource {
    pub kind: SecretSourceKind,
    /// What to ask the source for: a CA subject, a path, a serial.
    #[serde(rename = "ref")]
    pub reference: String,
}

/// How key material gets to the place a unit reads it.
///
/// One way, and one way only: a file, owned by the service user, mode
/// `0600`, under the fleet's `pki.dir`. There WAS a second way — systemd's
/// `LoadCredential` — and it was measured in a VM in M0 (probe S11) and
/// dropped: systemd puts a credential in `/run/credentials/<unit>/` as
/// `root:root 0440`, and every loader in this codebase refuses a key whose
/// group can read it (`pki/pem.rs`, `proto/lib.rs`, `cli/config.rs`). The
/// options were to loosen the loaders or to stop using credentials for
/// keys. Loosening a refusal that exists to keep a private key private is
/// not a trade this fleet makes, so the enum has one variant and the
/// contract has one answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum Delivery {
    /// Written to `target_path` with `owner` and `mode`.
    File,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Reload {
    pub unit: String,
    /// `restart`, `reload`, `try-reload-or-restart`.
    pub action: String,
}

/// A pointer to key material — never the material. A manifest is a file an
/// operator commits, diffs and attaches to a ticket.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SecretRef {
    pub id: String,
    pub kind: SecretKind,
    pub source: SecretSource,
    pub target_path: String,
    pub owner: String,
    /// As a string, `"0600"`.
    pub mode: String,
    pub delivery: Delivery,
    /// What to poke after it changed, or null when nothing has to be poked.
    pub reload: Option<Reload>,
}

/// The checks a host has to pass, by id. `required` blocks; `functional` is
/// recorded and does not.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HostChecks {
    pub required: Vec<String>,
    pub functional: Vec<String>,
}

/// What a host boots. Kept apart from `toplevel_out` because a changed kernel
/// is a reboot and a changed userland is not, and the plan needs to tell them
/// apart without opening the closure.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Boot {
    pub kernel_out: String,
    pub initrd_out: String,
    /// sha256 over the kernel command line, because the command line changes
    /// without any store path changing.
    pub kernel_params_sha256: String,
    pub kernel_version: String,
    /// Who decides which of the three above this machine actually starts.
    pub mode: BootMode,
    /// For a `direct` host: the whole command line its provider is handed,
    /// `<kernel params> init=<toplevel>/init`. Null for a `uefi` host, which
    /// reads its own boot menu and has nobody outside it to hand anything
    /// to.
    ///
    /// The `init=` is why this is not the same as the kernel params: a NixOS
    /// system is started by `<toplevel>/init`, and a guest whose loader does
    /// not say which toplevel would boot a new kernel into whatever userland
    /// the initrd finds.
    pub cmdline: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Build {
    /// The derivation, which exists before anything is built — a manifest is
    /// produced by `nix eval` and must not need a build.
    pub toplevel_drv: String,
    /// The output path the derivation will have. Still only a promise at
    /// manifest time; the release is what records that it exists.
    pub toplevel_out: String,
    pub installer_drv: Option<String>,
    /// Null for a `direct` host: `raw-efi` IS an EFI image — it makes an ESP
    /// and installs systemd-boot into it — so an image of that format for a
    /// machine with no boot loader would contradict its own host.
    pub disk_image_drv: Option<String>,
    /// The kernel, the initrd and the command line in one directory, for a
    /// host whose hypervisor loads them. Null for a `uefi` host.
    pub direct_boot_drv: Option<String>,
    pub boot: Boot,
}

/// The five settings blocks a host can carry, as the rendered TOML would be,
/// in JSON. Secret-free: what is in here is committed and diffed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EffectiveSettings {
    pub agent: Option<serde_json::Value>,
    pub cloud: Option<serde_json::Value>,
    pub cluster: Option<serde_json::Value>,
    pub etcd: Option<serde_json::Value>,
    pub observability: Option<serde_json::Value>,
}

/// Something the fleet depends on that is not one of its hosts: an external
/// observability stack, an identity provider, somebody else's etcd.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Service {
    pub kind: String,
    /// Whether this tool deploys it. An unmanaged service is observed and
    /// never changed.
    pub managed: bool,
    /// The host id it runs on, or null when it is somebody else's.
    pub host: Option<String>,
    /// Named endpoints, e.g. `{"loki": "http://10.0.5.10:3100/…"}`.
    pub endpoint: Option<BTreeMap<String, String>>,
    /// A trust anchor path in the operator's repository, or null.
    pub trust_ref: Option<String>,
    /// Whether it being unreachable blocks a run.
    pub required: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MeisterstackPackage {
    pub drv: String,
    pub version: String,
    /// The revision of THIS repository the binaries were built from.
    pub src_rev: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CloudHypervisorPackage {
    pub drv: String,
    pub version: String,
    /// One digest per patch, in the order they are applied. A reordered
    /// series is a different hypervisor.
    pub patches_sha256: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PackageRef {
    pub drv: String,
    pub version: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Packages {
    pub meisterstack: MeisterstackPackage,
    pub cloud_hypervisor: CloudHypervisorPackage,
    /// The GPU stack, or null for a fleet that declares no `leandro` input.
    /// A CPU-only fleet builds without it; that is what keeps the flake
    /// buildable in a sandbox without anybody's home directory.
    pub leandro: Option<PackageRef>,
    pub guest_tiny: PackageRef,
}

// ---------------------------------------------------------------------------
// A: what Nix says
// ---------------------------------------------------------------------------

/// What an operator's `fleet.toml` says, after Nix applied precedence and
/// resolved the addresses — the cheap half of `meisterDeployment`, evaluated
/// without building a single module.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NixInventory {
    pub fleet: Fleet,
    pub groups: BTreeMap<String, Group>,
    pub hosts: BTreeMap<String, InventoryHost>,
    pub services: BTreeMap<String, Service>,
}

/// A host as the inventory describes it: who it is and where, never what it
/// will run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct InventoryHost {
    /// The host name. The key of the map is the host ID, and the two are
    /// allowed to differ: an id is what a plan refers to and never changes,
    /// a name is what the machine calls itself.
    pub name: String,
    /// The address `meister-deploy` reaches it at — the management network's,
    /// repeated here because that is the one thing every code path needs.
    pub address: String,
    pub deployment: Deployment,
    pub ssh: Ssh,
    pub roles: Vec<String>,
    pub groups: Vec<String>,
    /// The cluster group this agent reports to, or null.
    pub controller_group: Option<String>,
    pub site: Option<String>,
    /// What fails together: a rack, a room, a power feed.
    pub failure_domain: Option<String>,
    pub networks: Networks,
    pub profiles: Vec<String>,
    /// Operator modules imported for this host, relative to their repository.
    pub modules: Vec<String>,
    /// Per-host overrides the operator wrote out, kept verbatim so that a
    /// review can see what was deviated from and why.
    pub deviations: BTreeMap<String, serde_json::Value>,
    pub hardware: Hardware,
    /// Null for a host that is never installed by this tool.
    pub install: Option<Install>,
}

/// A host as Nix evaluated it: what it will run, and what has to be true.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NixHost {
    pub effective_settings: EffectiveSettings,
    pub build: Build,
    /// `{"agent_toml_out": "/nix/store/…-agent.toml"}`: the rendered
    /// configuration files, by role.
    pub config_artifacts: BTreeMap<String, String>,
    /// Every systemd unit this host's system generation carries, by name.
    ///
    /// Names and not units: what a plan does with them is tell this stack's
    /// units from the operator's own. A unit nobody here declared is a unit
    /// whose disruption this tool cannot predict, which is what an
    /// `unknowns[]` entry says out loud instead of guessing.
    pub units: Vec<String>,
    pub secret_refs: Vec<SecretRef>,
    pub persistence: Vec<Persistence>,
    pub checks: HostChecks,
    pub rollout: Rollout,
}

/// `nix eval --json <repo>#meisterDeployment`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NixManifest {
    pub schema: String,
    pub inventory: NixInventory,
    /// Keyed by host id, the same ids as `inventory.hosts`. Two maps rather
    /// than one because the inventory half is cheap and the evaluated half
    /// is not: `resolve --hosts a,b` asks Nix for a subset of this one.
    pub hosts: BTreeMap<String, NixHost>,
    pub packages: Packages,
}

impl NixManifest {
    /// Parse and check the schema string. The schema is checked first and on
    /// its own, so that a manifest from a future version of this tool says
    /// which version it is rather than listing thirty unknown fields.
    pub fn from_json(text: &str, origin: &str) -> Result<NixManifest> {
        check_schema(text, origin, NIX_MANIFEST_SCHEMA)?;
        parse(text, origin, NIX_MANIFEST_SCHEMA)
    }
}

// ---------------------------------------------------------------------------
// B: what resolve made of it
// ---------------------------------------------------------------------------

/// Which `meister-deploy` produced this.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Tool {
    pub name: String,
    pub version: String,
    /// The revision this binary was built from, or null when it was built
    /// outside a git tree.
    pub git_rev: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SecretScan {
    pub ok: bool,
    /// The files that looked like key material, by path.
    pub hits: Vec<String>,
}

/// What `--dev` had to record to be allowed at all.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DevMode {
    /// sha256 over the snapshot of every tracked and untracked file, path
    /// and content. This is what makes a dirty tree nameable: git would name
    /// only what is committed, and Nix would ignore the untracked files in
    /// silence.
    pub content_hash: String,
    pub untracked_files: Vec<String>,
    pub secret_scan: SecretScan,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FlakeInput {
    pub url: String,
    pub rev: Option<String>,
    pub nar_hash: String,
}

/// Where this came from, precisely enough to get back to it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Source {
    pub repo_path: String,
    pub git_rev: Option<String>,
    pub tree_hash: Option<String>,
    pub dirty: bool,
    /// `git:<rev>:<tree_hash>` for a clean tree, `dev:<content hash>` for a
    /// snapshot. One string, two namespaces, never confusable — a `dev:`
    /// fingerprint in a receipt is a receipt for something nobody can check
    /// out again, and it has to be obvious.
    pub fingerprint: String,
    /// Null unless `--dev` was used.
    pub dev_mode: Option<DevMode>,
    pub flake_lock: BTreeMap<String, FlakeInput>,
    pub inventory_path: String,
    pub inventory_sha256: String,
    /// Null when this tool evaluated the flake itself, which is the normal
    /// case. Set when the evaluation was handed over (`resolve --from`).
    ///
    /// The distinction is worth a field rather than a note, because it is
    /// the one thing a reader of a manifest cannot work out afterwards: the
    /// SOURCE below is this repository either way — read with git, here —
    /// but whether the systems named in the manifest are what that tree
    /// evaluates to was checked by somebody else. The digest is of the file
    /// that was handed over, so the claim is at least nameable.
    pub provided_evaluation: Option<ProvidedEvaluation>,
}

/// An evaluation this tool did not perform.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProvidedEvaluation {
    /// What the file was called where it was read.
    pub origin: String,
    /// sha256 of its bytes.
    pub sha256: String,
}

/// A host, whole: what the inventory said and what Nix evaluated, joined.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ResolvedHost {
    pub name: String,
    pub address: String,
    pub deployment: Deployment,
    pub ssh: Ssh,
    pub roles: Vec<String>,
    pub groups: Vec<String>,
    pub controller_group: Option<String>,
    pub site: Option<String>,
    pub failure_domain: Option<String>,
    pub networks: Networks,
    pub profiles: Vec<String>,
    pub modules: Vec<String>,
    pub deviations: BTreeMap<String, serde_json::Value>,
    pub hardware: Hardware,
    pub effective_settings: EffectiveSettings,
    pub build: Build,
    pub config_artifacts: BTreeMap<String, String>,
    /// Every systemd unit this host's system generation carries, by name.
    pub units: Vec<String>,
    pub secret_refs: Vec<SecretRef>,
    pub persistence: Vec<Persistence>,
    pub install: Option<Install>,
    pub checks: HostChecks,
    pub rollout: Rollout,
}

/// `manifest.json`: one fleet, one tree, one id.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ResolvedFleet {
    pub schema: String,
    /// sha256 over everything else here. Not part of its own input.
    pub manifest_id: String,
    pub created_at: DateTime<Utc>,
    pub tool: Tool,
    pub source: Source,
    pub fleet: Fleet,
    pub groups: BTreeMap<String, Group>,
    pub hosts: BTreeMap<String, ResolvedHost>,
    pub services: BTreeMap<String, Service>,
    pub packages: Packages,
    /// Whether this describes only part of the fleet — `resolve --hosts a,b`.
    ///
    /// A partial manifest LOOKS complete: it has an inventory, groups and
    /// packages, and a plan built over it would quietly cover two hosts of
    /// seventy. So it says so, and M2's `plan` refuses a fleet-wide plan over
    /// one and requires its selection to be a subset of `evaluated_hosts`.
    pub partial: bool,
    /// The hosts this manifest was resolved for — the keys of `hosts`, stated
    /// where a reader will look for them.
    pub evaluated_hosts: Vec<String>,
}

impl ResolvedFleet {
    pub fn from_json(text: &str, origin: &str) -> Result<ResolvedFleet> {
        check_schema(text, origin, RESOLVED_FLEET_SCHEMA)?;
        parse(text, origin, RESOLVED_FLEET_SCHEMA)
    }

    /// Pretty, with a trailing newline: this file is committed and diffed.
    pub fn to_json(&self) -> Result<Vec<u8>> {
        let mut bytes = serde_json::to_vec_pretty(self)
            .map_err(|e| anyhow::anyhow!("writing the manifest as json failed: {e}"))?;
        bytes.push(b'\n');
        Ok(bytes)
    }

    /// Recompute the id and compare. What `validate` uses to say that a
    /// manifest is the one it claims to be.
    pub fn id_matches(&self) -> Result<bool> {
        Ok(content_id(IdKind::Manifest, self)? == self.manifest_id)
    }
}

// ---------------------------------------------------------------------------
// resolve
// ---------------------------------------------------------------------------

/// Join what Nix said with who asked, check that it hangs together, and name
/// it. Pure: no clock, no file, no command — `now` and `source` are handed
/// in, which is what makes "the same tree resolves to the same id" a test
/// rather than a hope.
///
/// `selection` is what `--hosts` asked for, or `None` for the whole fleet.
/// It is checked rather than trusted: the restriction happens in Nix, and if
/// the evaluated set and the asked-for set ever drift apart, a partial
/// manifest would be silently wrong about which hosts it covers.
pub fn resolve(
    nix: NixManifest,
    source: Source,
    tool: Tool,
    now: DateTime<Utc>,
    selection: Option<&[String]>,
) -> Result<ResolvedFleet> {
    if nix.schema != NIX_MANIFEST_SCHEMA {
        bail!(
            "this manifest says its schema is {:?}, and this tool speaks {NIX_MANIFEST_SCHEMA:?}.",
            nix.schema
        );
    }
    let NixManifest {
        schema: _,
        inventory,
        hosts: evaluated,
        packages,
    } = nix;

    // The two halves are keyed by the same ids, and a mismatch is a bug in
    // the derivation rather than a host to guess about.
    let declared: BTreeSet<&String> = inventory.hosts.keys().collect();
    let built: BTreeSet<&String> = evaluated.keys().collect();
    let missing: Vec<&str> = declared.difference(&built).map(|s| s.as_str()).collect();
    if !missing.is_empty() {
        bail!(
            "the inventory declares {} but nothing was evaluated for them; \
             a resolve of a subset has to name the same hosts in both halves.",
            missing.join(", ")
        );
    }
    let extra: Vec<&str> = built.difference(&declared).map(|s| s.as_str()).collect();
    if !extra.is_empty() {
        bail!(
            "{} was evaluated but is not in the inventory.",
            extra.join(", ")
        );
    }

    let mut hosts = BTreeMap::new();
    for (id, host) in inventory.hosts {
        let built = evaluated
            .get(&id)
            .expect("both halves were just compared")
            .clone();
        for group in &host.groups {
            if !inventory.groups.contains_key(group) {
                bail!("host {id} is in group {group}, and no such group is declared.");
            }
        }
        if let Some(group) = &host.controller_group
            && !inventory.groups.contains_key(group)
        {
            bail!("host {id} reports to group {group}, and no such group is declared.");
        }
        hosts.insert(
            id,
            ResolvedHost {
                name: host.name,
                address: host.address,
                deployment: host.deployment,
                ssh: host.ssh,
                roles: host.roles,
                groups: host.groups,
                controller_group: host.controller_group,
                site: host.site,
                failure_domain: host.failure_domain,
                networks: host.networks,
                profiles: host.profiles,
                modules: host.modules,
                deviations: host.deviations,
                hardware: host.hardware,
                effective_settings: built.effective_settings,
                build: built.build,
                config_artifacts: built.config_artifacts,
                units: built.units,
                secret_refs: built.secret_refs,
                persistence: built.persistence,
                install: host.install,
                checks: built.checks,
                rollout: built.rollout,
            },
        );
    }

    for (id, group) in &inventory.groups {
        for member in &group.members {
            if !hosts.contains_key(member) {
                bail!("group {id} lists {member} as a member, and no such host is declared.");
            }
        }
    }
    for (id, service) in &inventory.services {
        if let Some(host) = &service.host
            && !hosts.contains_key(host)
        {
            bail!("service {id} runs on {host}, and no such host is declared.");
        }
    }

    if let Some(selection) = selection {
        let asked: BTreeSet<&String> = selection.iter().collect();
        let got: BTreeSet<&String> = hosts.keys().collect();
        if asked != got {
            let missing: Vec<&str> = asked.difference(&got).map(|s| s.as_str()).collect();
            let extra: Vec<&str> = got.difference(&asked).map(|s| s.as_str()).collect();
            bail!(
                "this resolve asked for {} and got {}{}{}.",
                selection.join(", "),
                hosts.keys().cloned().collect::<Vec<_>>().join(", "),
                if missing.is_empty() {
                    String::new()
                } else {
                    format!("; nothing was evaluated for {}", missing.join(", "))
                },
                if extra.is_empty() {
                    String::new()
                } else {
                    format!("; nobody asked for {}", extra.join(", "))
                }
            );
        }
    }
    let evaluated_hosts: Vec<String> = hosts.keys().cloned().collect();

    let mut resolved = ResolvedFleet {
        schema: RESOLVED_FLEET_SCHEMA.to_string(),
        // Filled in below. It is over everything else, so it cannot be here
        // yet, and it is removed from its own input in any case.
        manifest_id: String::new(),
        created_at: now,
        tool,
        source,
        fleet: inventory.fleet,
        groups: inventory.groups,
        hosts,
        services: inventory.services,
        packages,
        partial: selection.is_some(),
        evaluated_hosts,
    };
    resolved.manifest_id = content_id(IdKind::Manifest, &resolved)?;
    Ok(resolved)
}

// ---------------------------------------------------------------------------
// Parsing, with sentences
// ---------------------------------------------------------------------------

/// One of the two contracts this module knows, whichever the file said it was.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Contract {
    NixManifest(Box<NixManifest>),
    ResolvedFleet(Box<ResolvedFleet>),
}

impl Contract {
    /// What to print when it parsed: which contract, and enough of its
    /// content that "it validated" is a statement about something.
    pub fn describe(&self) -> String {
        match self {
            Contract::NixManifest(m) => format!(
                "{NIX_MANIFEST_SCHEMA} for the fleet {:?}, {} host(s): {}",
                m.inventory.fleet.name,
                m.hosts.len(),
                m.hosts.keys().cloned().collect::<Vec<_>>().join(", ")
            ),
            Contract::ResolvedFleet(f) => format!(
                "{RESOLVED_FLEET_SCHEMA} {} for the fleet {:?}, {} host(s)",
                f.manifest_id,
                f.fleet.name,
                f.hosts.len()
            ),
        }
    }
}

/// Read a contract object and say which one it was. This is the hook lane 1B
/// hangs its `manifest-json` check on: `nix eval --json …#meisterDeployment`
/// piped into `meister-deploy validate --manifest -` fails the flake check
/// when the derivation and these types have drifted apart.
pub fn parse_contract(text: &str, origin: &str) -> Result<Contract> {
    let schema = schema_of(text, origin)?;
    match schema.as_str() {
        NIX_MANIFEST_SCHEMA => Ok(Contract::NixManifest(Box::new(parse(
            text,
            origin,
            NIX_MANIFEST_SCHEMA,
        )?))),
        RESOLVED_FLEET_SCHEMA => {
            let fleet: ResolvedFleet = parse(text, origin, RESOLVED_FLEET_SCHEMA)?;
            if !fleet.id_matches()? {
                bail!(
                    "{origin} carries the id {} and its content hashes to {}; \
                     it was edited after it was resolved.",
                    fleet.manifest_id,
                    content_id(IdKind::Manifest, &fleet)?
                );
            }
            Ok(Contract::ResolvedFleet(Box::new(fleet)))
        }
        other => bail!(
            "{origin} says its schema is {other:?}; this tool validates \
             {NIX_MANIFEST_SCHEMA:?} and {RESOLVED_FLEET_SCHEMA:?}."
        ),
    }
}

#[derive(Deserialize)]
struct SchemaProbe {
    schema: String,
}

/// Read only the `schema` field, and say what was found against what is
/// spoken. A manifest written by a newer tool has fields this one does not
/// know, and "unknown field `foo`" is the wrong sentence for that.
fn check_schema(text: &str, origin: &str, want: &str) -> Result<()> {
    let found = schema_of(text, origin)?;
    if found != want {
        bail!("{origin} says its schema is {found:?}, and this tool speaks {want:?}.");
    }
    Ok(())
}

/// The `schema` field, or a sentence about why there is none.
fn schema_of(text: &str, origin: &str) -> Result<String> {
    match serde_json::from_str::<SchemaProbe>(text) {
        Ok(probe) => Ok(probe.schema),
        Err(e) if e.is_syntax() || e.is_eof() => bail!("{origin} is not valid json: {e}."),
        Err(_) => bail!("{origin} has no `schema` field, so there is nothing to check it against."),
    }
}

/// Check the `schema` field, then parse the whole thing — the way every
/// contract file in this tool is read. Public because the contracts that
/// come after these two ([`crate::release`], [`crate::plan`],
/// [`crate::receipt`]) are read exactly the same way, and a second copy of
/// "which sentence for which kind of malformed file" would drift.
pub fn parse_checked<T: serde::de::DeserializeOwned>(
    text: &str,
    origin: &str,
    kind: &str,
) -> Result<T> {
    check_schema(text, origin, kind)?;
    parse(text, origin, kind)
}

fn parse<T: serde::de::DeserializeOwned>(text: &str, origin: &str, kind: &str) -> Result<T> {
    // `from_str` rather than `from_value`: it keeps the line and column, and
    // a line number is what somebody staring at a 4000-line manifest needs.
    serde_json::from_str(text).map_err(|e| anyhow::anyhow!("{origin} is not a valid {kind}: {e}."))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> String {
        include_str!("../tests/fixtures/nix-manifest-onebox.json").to_string()
    }

    fn source() -> Source {
        Source {
            repo_path: "/home/silas/git/meisterstack-lab".to_string(),
            git_rev: Some("f83cd70e0b1d1f0b4c8b9c2a0a1b2c3d4e5f6071".to_string()),
            tree_hash: Some("8a1c2b3d4e5f60718293a4b5c6d7e8f901234567".to_string()),
            dirty: false,
            fingerprint: "git:f83cd70e0b1d1f0b4c8b9c2a0a1b2c3d4e5f6071:\
                          8a1c2b3d4e5f60718293a4b5c6d7e8f901234567"
                .to_string(),
            dev_mode: None,
            flake_lock: BTreeMap::from([(
                "nixpkgs".to_string(),
                FlakeInput {
                    url: "github:NixOS/nixpkgs/b6018f87".to_string(),
                    rev: Some("b6018f87".to_string()),
                    nar_hash: "sha256-0000000000000000000000000000000000000000000=".to_string(),
                },
            )]),
            inventory_path: "fleet.toml".to_string(),
            inventory_sha256: "9f2c".to_string(),
            provided_evaluation: None,
        }
    }

    fn tool() -> Tool {
        Tool {
            name: "meister-deploy".to_string(),
            version: "0.1.0".to_string(),
            git_rev: Some("f83cd70".to_string()),
        }
    }

    fn now() -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2026-09-21T12:00:00Z")
            .unwrap()
            .with_timezone(&Utc)
    }

    #[test]
    fn the_fixture_is_a_nix_manifest() {
        let manifest = NixManifest::from_json(&fixture(), "the fixture").unwrap();
        assert_eq!(manifest.inventory.fleet.name, "one-box");
        assert_eq!(manifest.inventory.hosts.len(), 3);
        assert_eq!(manifest.hosts.len(), 3);
        assert_eq!(
            manifest.inventory.hosts["box"].roles,
            vec!["cloud", "cluster", "agent", "addons"]
        );
        assert_eq!(manifest.inventory.groups["box"].kind, GroupKind::Raft);
        assert!(
            manifest.packages.leandro.is_none(),
            "a CPU fleet builds without it"
        );
    }

    #[test]
    fn a_nix_manifest_survives_a_round_trip() {
        let manifest = NixManifest::from_json(&fixture(), "the fixture").unwrap();
        let text = serde_json::to_string(&manifest).unwrap();
        let again = NixManifest::from_json(&text, "the round trip").unwrap();
        assert_eq!(manifest, again);
    }

    #[test]
    fn a_resolved_fleet_survives_a_round_trip() {
        let manifest = NixManifest::from_json(&fixture(), "the fixture").unwrap();
        let resolved = resolve(manifest, source(), tool(), now(), None).unwrap();
        let text = String::from_utf8(resolved.to_json().unwrap()).unwrap();
        let again = ResolvedFleet::from_json(&text, "the round trip").unwrap();
        assert_eq!(resolved, again);
        assert!(again.id_matches().unwrap());
    }

    #[test]
    fn resolve_derives_nothing_and_joins_everything() {
        let manifest = NixManifest::from_json(&fixture(), "the fixture").unwrap();
        let resolved = resolve(manifest.clone(), source(), tool(), now(), None).unwrap();
        let host = &resolved.hosts["box"];
        // From the inventory half...
        assert_eq!(host.address, "10.0.0.10");
        assert_eq!(host.ssh.port, 22);
        // ...and from the evaluated half, under the same id.
        assert_eq!(
            host.build.toplevel_out,
            manifest.hosts["box"].build.toplevel_out
        );
        assert_eq!(host.rollout.reboot, RebootPolicy::Approve);
        assert_eq!(host.checks.required, vec!["units", "session", "mounts"]);
        assert_eq!(resolved.schema, RESOLVED_FLEET_SCHEMA);
    }

    #[test]
    fn a_host_carries_the_units_of_its_generation() {
        let manifest = NixManifest::from_json(&fixture(), "the fixture").unwrap();
        let resolved = resolve(manifest.clone(), source(), tool(), now(), None).unwrap();
        // The list travels from the evaluated half to the resolved host
        // whole and in order: a plan that reordered it would change the
        // manifest id for nothing.
        assert_eq!(resolved.hosts["box"].units, manifest.hosts["box"].units);
        assert!(
            resolved.hosts["box"]
                .units
                .contains(&"meister-cloud-controller.service".to_string()),
            "{:?}",
            resolved.hosts["box"].units
        );
        // And it is a per-host fact and not a fleet-wide one: an agent has
        // no controller unit, which is exactly the difference a plan reads.
        assert!(
            !resolved.hosts["n1"]
                .units
                .contains(&"meister-cloud-controller.service".to_string()),
            "{:?}",
            resolved.hosts["n1"].units
        );
        assert!(
            resolved.hosts["n1"]
                .units
                .contains(&"meister-agent.service".to_string())
        );
    }

    #[test]
    fn a_changed_unit_list_is_a_different_manifest_id() {
        let before = resolve(
            NixManifest::from_json(&fixture(), "a").unwrap(),
            source(),
            tool(),
            now(),
            None,
        )
        .unwrap();
        let mut manifest = NixManifest::from_json(&fixture(), "b").unwrap();
        manifest
            .hosts
            .get_mut("n1")
            .unwrap()
            .units
            .push("somebody-elses.service".to_string());
        let after = resolve(manifest, source(), tool(), now(), None).unwrap();
        assert_ne!(
            before.manifest_id, after.manifest_id,
            "a unit an operator's own module brought onto a host is part of what that host is"
        );
    }

    #[test]
    fn the_same_manifest_resolves_to_the_same_id() {
        let a = resolve(
            NixManifest::from_json(&fixture(), "a").unwrap(),
            source(),
            tool(),
            now(),
            None,
        )
        .unwrap();
        let b = resolve(
            NixManifest::from_json(&fixture(), "b").unwrap(),
            source(),
            tool(),
            now(),
            None,
        )
        .unwrap();
        assert_eq!(a.manifest_id, b.manifest_id);
        assert!(a.manifest_id.starts_with("manifest-"));
    }

    #[test]
    fn a_different_tree_is_a_different_manifest_id() {
        let clean = resolve(
            NixManifest::from_json(&fixture(), "a").unwrap(),
            source(),
            tool(),
            now(),
            None,
        )
        .unwrap();
        let mut dev_source = source();
        dev_source.dirty = true;
        dev_source.fingerprint = "dev:9f2c3d".to_string();
        dev_source.dev_mode = Some(DevMode {
            content_hash: "9f2c3d".to_string(),
            untracked_files: vec!["profiles/new.nix".to_string()],
            secret_scan: SecretScan {
                ok: true,
                hits: vec![],
            },
        });
        let dev = resolve(
            NixManifest::from_json(&fixture(), "b").unwrap(),
            dev_source,
            tool(),
            now(),
            None,
        )
        .unwrap();
        assert_ne!(clean.manifest_id, dev.manifest_id);
    }

    #[test]
    fn the_same_tree_resolved_again_is_the_same_manifest() {
        let later = now() + chrono::TimeDelta::hours(3);
        let a = resolve(
            NixManifest::from_json(&fixture(), "a").unwrap(),
            source(),
            tool(),
            now(),
            None,
        )
        .unwrap();
        let b = resolve(
            NixManifest::from_json(&fixture(), "b").unwrap(),
            source(),
            tool(),
            later,
            None,
        )
        .unwrap();
        // `created_at` differs and the id does not: the timestamp says when
        // the question was asked, not what the answer was.
        assert_ne!(a.created_at, b.created_at);
        assert_eq!(a.manifest_id, b.manifest_id);
        assert!(b.id_matches().unwrap());
    }

    #[test]
    fn the_same_tree_at_two_paths_is_the_same_manifest() {
        let here = resolve(
            NixManifest::from_json(&fixture(), "a").unwrap(),
            source(),
            tool(),
            now(),
            None,
        )
        .unwrap();
        let mut elsewhere_source = source();
        elsewhere_source.repo_path = "/build/ci/checkout-4711".to_string();
        let there = resolve(
            NixManifest::from_json(&fixture(), "b").unwrap(),
            elsewhere_source,
            tool(),
            now(),
            None,
        )
        .unwrap();
        assert_ne!(here.source.repo_path, there.source.repo_path);
        assert_eq!(
            here.manifest_id, there.manifest_id,
            "the same commit cloned onto a CI runner is the same fleet"
        );
        assert!(there.id_matches().unwrap());
    }

    #[test]
    fn a_newer_build_of_the_tool_resolves_to_the_same_manifest() {
        let old = resolve(
            NixManifest::from_json(&fixture(), "a").unwrap(),
            source(),
            tool(),
            now(),
            None,
        )
        .unwrap();
        let newer = resolve(
            NixManifest::from_json(&fixture(), "b").unwrap(),
            source(),
            Tool {
                name: "meister-deploy".to_string(),
                version: "0.2.0".to_string(),
                git_rev: Some("aaaaaaa".to_string()),
            },
            now(),
            None,
        )
        .unwrap();
        assert_ne!(old.tool, newer.tool);
        assert_eq!(old.manifest_id, newer.manifest_id);
    }

    #[test]
    fn a_changed_host_is_still_a_changed_manifest() {
        // The other half of the bargain: what the fleet SAYS decides the id.
        let before = resolve(
            NixManifest::from_json(&fixture(), "a").unwrap(),
            source(),
            tool(),
            now(),
            None,
        )
        .unwrap();
        let mut changed = NixManifest::from_json(&fixture(), "b").unwrap();
        changed.inventory.hosts.get_mut("n1").unwrap().address = "10.0.0.99".to_string();
        let after = resolve(changed, source(), tool(), now(), None).unwrap();
        assert_ne!(before.manifest_id, after.manifest_id);
    }

    #[test]
    fn a_partial_resolve_says_so_and_lists_what_it_covers() {
        let whole = resolve(
            NixManifest::from_json(&fixture(), "a").unwrap(),
            source(),
            tool(),
            now(),
            None,
        )
        .unwrap();
        assert!(!whole.partial);
        assert_eq!(whole.evaluated_hosts, vec!["box", "n1", "n2"]);

        let mut subset = NixManifest::from_json(&fixture(), "b").unwrap();
        subset.hosts.remove("n2");
        subset.inventory.hosts.remove("n2");
        subset.inventory.groups.get_mut("compute").unwrap().members = vec!["n1".to_string()];
        let selection = vec!["box".to_string(), "n1".to_string()];
        let part = resolve(subset, source(), tool(), now(), Some(&selection)).unwrap();
        assert!(part.partial);
        assert_eq!(part.evaluated_hosts, vec!["box", "n1"]);
        assert_ne!(
            part.manifest_id, whole.manifest_id,
            "it is a different statement"
        );
    }

    #[test]
    fn a_selection_the_evaluation_did_not_honour_is_refused() {
        // The restriction happens in nix; if it ever stops matching what was
        // asked for, a partial manifest would be wrong about its own extent.
        let manifest = NixManifest::from_json(&fixture(), "a").unwrap();
        let selection = vec!["box".to_string(), "n1".to_string()];
        let err = resolve(manifest, source(), tool(), now(), Some(&selection))
            .unwrap_err()
            .to_string();
        assert!(err.contains("asked for box, n1"), "{err}");
        assert!(err.contains("nobody asked for n2"), "{err}");
    }

    #[test]
    fn a_half_evaluated_manifest_is_refused() {
        let mut manifest = NixManifest::from_json(&fixture(), "the fixture").unwrap();
        manifest.hosts.remove("n2");
        let err = resolve(manifest, source(), tool(), now(), None)
            .unwrap_err()
            .to_string();
        assert!(err.contains("n2"), "{err}");
        assert!(err.contains("nothing was evaluated"), "{err}");
    }

    #[test]
    fn a_host_in_a_group_nobody_declared_is_refused() {
        let mut manifest = NixManifest::from_json(&fixture(), "the fixture").unwrap();
        manifest
            .inventory
            .hosts
            .get_mut("n1")
            .unwrap()
            .groups
            .push("compute_pro6000".to_string());
        let err = resolve(manifest, source(), tool(), now(), None)
            .unwrap_err()
            .to_string();
        assert!(err.contains("n1 is in group compute_pro6000"), "{err}");
    }

    #[test]
    fn a_group_with_a_member_nobody_declared_is_refused() {
        let mut manifest = NixManifest::from_json(&fixture(), "the fixture").unwrap();
        manifest
            .inventory
            .groups
            .get_mut("box")
            .unwrap()
            .members
            .push("n7".to_string());
        let err = resolve(manifest, source(), tool(), now(), None)
            .unwrap_err()
            .to_string();
        assert!(err.contains("group box lists n7"), "{err}");
    }

    #[test]
    fn another_schema_version_is_a_sentence_and_not_a_field_list() {
        let text = fixture().replace(NIX_MANIFEST_SCHEMA, "meister-deploy/nix-manifest/2");
        let err = NixManifest::from_json(&text, "m.json")
            .unwrap_err()
            .to_string();
        assert!(err.contains("nix-manifest/2"), "{err}");
        assert!(err.contains("nix-manifest/1"), "{err}");
        assert!(!err.contains("unknown field"), "{err}");
    }

    #[test]
    fn a_field_nobody_declared_is_refused_with_its_name() {
        let text = fixture().replace(r#""schema": ""#, r#""surprise": 1, "schema": ""#);
        let err = NixManifest::from_json(&text, "m.json")
            .unwrap_err()
            .to_string();
        assert!(err.contains("unknown field `surprise`"), "{err}");
        assert!(err.contains("m.json"), "{err}");
    }

    #[test]
    fn a_missing_field_says_which_one_and_where() {
        let text = fixture().replace(r#""toplevel_out""#, r#""toplevel_output""#);
        let err = NixManifest::from_json(&text, "m.json")
            .unwrap_err()
            .to_string();
        assert!(err.contains("toplevel_out"), "{err}");
        assert!(err.contains("line"), "{err}");
    }

    #[test]
    fn a_null_where_a_value_belongs_is_not_an_omission() {
        // `installer_drv` may be null; `toplevel_out` may not. Both are keys
        // that have to be there.
        let text = fixture().replace(
            r#""installer_drv": null"#,
            r#""installer_drv": "/nix/store/x.drv""#,
        );
        assert!(NixManifest::from_json(&text, "m.json").is_ok());
        let text = fixture().replace(r#""kernel_version": "6.12.41","#, "");
        assert!(NixManifest::from_json(&text, "m.json").is_err());
    }

    #[test]
    fn something_that_is_not_json_at_all_says_so() {
        let err = NixManifest::from_json("error: attribute missing", "nix output")
            .unwrap_err()
            .to_string();
        assert!(err.contains("not valid json"), "{err}");
        assert!(err.contains("nix output"), "{err}");
    }

    #[test]
    fn validate_takes_either_contract_and_says_which() {
        let nix = parse_contract(&fixture(), "m.json").unwrap();
        assert!(
            nix.describe().contains(NIX_MANIFEST_SCHEMA),
            "{}",
            nix.describe()
        );
        assert!(nix.describe().contains("3 host(s)"), "{}", nix.describe());

        let resolved = resolve(
            NixManifest::from_json(&fixture(), "a").unwrap(),
            source(),
            tool(),
            now(),
            None,
        )
        .unwrap();
        let text = String::from_utf8(resolved.to_json().unwrap()).unwrap();
        let back = parse_contract(&text, "manifest.json").unwrap();
        assert!(back.describe().contains(&resolved.manifest_id));
    }

    #[test]
    fn a_manifest_edited_after_the_fact_is_refused() {
        let resolved = resolve(
            NixManifest::from_json(&fixture(), "a").unwrap(),
            source(),
            tool(),
            now(),
            None,
        )
        .unwrap();
        let text = String::from_utf8(resolved.to_json().unwrap())
            .unwrap()
            .replace("10.0.0.11", "10.0.0.99");
        let err = parse_contract(&text, "manifest.json")
            .unwrap_err()
            .to_string();
        assert!(err.contains("edited after it was resolved"), "{err}");
        assert!(err.contains(&resolved.manifest_id), "{err}");
    }

    #[test]
    fn a_third_schema_is_named_and_not_guessed_at() {
        let err = parse_contract(r#"{"schema":"meister-deploy/plan/1"}"#, "p.json")
            .unwrap_err()
            .to_string();
        assert!(err.contains("meister-deploy/plan/1"), "{err}");
        assert!(err.contains(NIX_MANIFEST_SCHEMA), "{err}");
    }

    #[test]
    fn a_mode_stays_a_string_because_0600_is_not_six_hundred() {
        let manifest = NixManifest::from_json(&fixture(), "the fixture").unwrap();
        let secret = &manifest.hosts["box"].secret_refs[0];
        assert_eq!(secret.mode, "0600");
        assert_eq!(secret.delivery, Delivery::File);
        assert_eq!(secret.source.kind, SecretSourceKind::TargetGenerated);
    }

    #[test]
    fn a_key_handed_over_by_systemd_is_not_a_delivery_this_tool_speaks() {
        // M0's probe S11 measured what `LoadCredential` produces and the
        // loaders refuse it. A manifest that asks for it is a manifest from
        // before that decision, and it gets a sentence rather than a key
        // nobody can read.
        let text = fixture().replace(
            "\"delivery\": \"file\"",
            "\"delivery\": \"systemd-credential\"",
        );
        let err = NixManifest::from_json(&text, "an older manifest")
            .unwrap_err()
            .to_string();
        assert!(err.contains("systemd-credential"), "{err}");
        assert!(err.contains("`file`"), "{err}");
    }
}
