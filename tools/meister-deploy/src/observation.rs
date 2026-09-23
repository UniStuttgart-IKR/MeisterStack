// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! What a host IS, as of a moment — and the second, providerless way of
//! learning where to reach it.
//!
//! Everything the planner decides, it decides from a [`ReleaseManifest`] (the
//! intent) and an [`Observations`] snapshot (the fact). The snapshot is a
//! file: `plan --observation snap.json` reads one, lane 2A writes one from
//! `meister-activate status --json` and a shell probe, and a test writes one
//! by hand. That is deliberate — a planner that gathers its own facts can
//! only be tested against a fleet, and the rules in [`crate::plan`] are
//! exactly the rules nobody wants to first exercise on seventy machines.
//!
//! Three things this module refuses to do:
//!
//! * **Guess.** Every field that could not be read is `null` and never a
//!   default. A `current_system` of `""` would plan an upgrade for a host
//!   nobody could talk to.
//! * **Let a target file change the fleet.** [`Targets`] says where a host
//!   answers today — a lab VM gets a fresh address on every instantiation —
//!   and nothing else. Roles, endpoints and settings come from the manifest,
//!   and [`bind_targets`] proves it leaves the manifest untouched.
//! * **Interpret `provider_ref`.** It is whatever the adapter wants to find
//!   its own resource again with. This tool carries it into the receipt and
//!   never reads it, which is what keeps the provider interface honest.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Result, bail};
use chrono::{DateTime, Utc};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::manifest::ResolvedFleet;

pub const OBSERVATION_SCHEMA: &str = "meister-deploy/observation/1";
pub const TARGETS_SCHEMA: &str = "meister-deploy/targets/1";

/// Who a host says it is.
///
/// Three answers to three different questions, and a rollout needs all three:
/// the host key is who ssh is talking to, the machine id is whether this is
/// the same installation as yesterday, and the hostname is what the host
/// believes about itself. Two hosts cloned from one disk image share a
/// machine id, which is exactly the failure L04 exists to catch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Identity {
    pub hostname: Option<String>,
    pub machine_id: Option<String>,
    /// `SHA256:…`, the same spelling `keys enroll` wrote into `known_hosts`.
    pub host_key_fingerprint: Option<String>,
}

impl Identity {
    pub fn unknown() -> Identity {
        Identity {
            hostname: None,
            machine_id: None,
            host_key_fingerprint: None,
        }
    }
}

/// What the generation a host BOOTED says it boots.
///
/// Read from `/run/booted-system`, not from the running kernel: the three
/// fields are the ones a release promises, so they compare directly, and a
/// comparison against `uname -r` alone would miss a changed initrd and a
/// changed command line entirely.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BootedKernel {
    pub kernel_store_path: String,
    pub initrd_store_path: String,
    pub kernel_params_sha256: String,
}

/// What `meister-activate` still holds on the target.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum TxnState {
    /// The closure is there and the profile has not been moved.
    Staged,
    /// Activated, waiting for a `confirm` before the revert timer fires.
    Pending,
    Confirmed,
    Reverted,
    /// The record is there and does not say a coherent thing — a half-written
    /// file, a state this tool does not know. Never treated as any of the
    /// four above.
    Inconsistent,
}

/// One transaction record on the target.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Txn {
    pub id: String,
    pub state: TxnState,
    /// The system this transaction was about, so that a resume can tell "the
    /// one I started" from "one somebody else left behind".
    pub target_system: Option<String>,
    /// When the revert timer fires, for a `pending` one.
    pub deadline: Option<DateTime<Utc>>,
    /// The run that opened it, when the record says.
    pub run_id: Option<String>,
}

/// A lock somebody holds on this host.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Lock {
    pub run_id: String,
    pub operator: String,
    pub pid: u32,
    pub acquired_at: DateTime<Utc>,
}

/// One member of an etcd cluster, as etcd itself reports it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EtcdMember {
    /// The member id, hex, as `etcdctl member list -w json` prints it.
    pub id: String,
    pub name: String,
    pub peer_urls: Vec<String>,
    /// From `endpoint health -w json`. Unknown is not healthy.
    pub healthy: bool,
}

/// What one host knows about its own raft group.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EtcdView {
    /// This host's own member id, or null when it could not be told apart.
    pub member_id: Option<String>,
    pub healthy: bool,
    /// Every member this host can see, not only the healthy ones: a member
    /// that has vanished from the list is a membership change, and that is a
    /// different and worse thing than a member that is down.
    pub members: Vec<EtcdMember>,
}

/// A mount point that is there.
///
/// The planner only asks whether a required path is IN this list. That is
/// the whole check and the limit is documented on purpose: a path that is
/// not a mount point is a path on the root disk, which is the failure V19 is
/// about. Whether the right disk is behind it is a question for the
/// `mounts` readiness check, which can compare the device.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Mount {
    pub path: String,
    /// What is mounted there, as the kernel spells it.
    pub device: String,
    pub fstype: String,
}

// --- lane 4A: what the machine under the closure is ------------------------
//
// Three facts a release cannot be talked out of and an inventory can only
// CLAIM: how much room the store has, which cards are in the slots, which
// interfaces answer. They are read for the preflight of §6 — a closure that
// does not fit, a GPU that is not in the machine the fleet says it is in, a
// NIC the inventory names and nobody can see.
//
// Addresses, ids and MACs, and nothing else. The vendor:device pair is what
// tells one card from another; the rest of `lspci` — revisions, subsystem
// ids, kernel drivers — would be a second inventory this tool would then
// have to keep in step with the first.

/// One PCI device, as the machine lists it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PciDevice {
    /// The full domain address, `0000:41:00.0` — the spelling
    /// `hardware.gpus[].pci` uses. `lspci -n` leaves the domain off on a
    /// machine that has only domain 0, so the probe puts it back.
    pub address: String,
    /// `10de:2684`, lower case, as `lspci -n` prints it and as
    /// `/sys/bus/pci/devices/*/{vendor,device}` spell it once the `0x` is
    /// gone.
    pub vendor_device: String,
}

/// One network interface, as the machine lists it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NetworkInterface {
    /// The kernel's name for it. NOT what `hardware.nics[].name` has to
    /// match: a name is handed out at boot and a MAC is burned in, so the
    /// MAC is what the preflight compares and the name is what it prints so
    /// that a person can find the card.
    pub name: String,
    /// Lower case, colon separated, as `/sys/class/net/*/address` writes it.
    pub mac: String,
}

// --- end lane 4A ---

/// One host, as of `Observations::taken_at`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HostObservation {
    /// Whether the host answered at all. Everything below is null or empty
    /// when it did not — and `false` here never means "not asked", which is
    /// what `unknown_reason` is for.
    pub reachable: bool,
    pub identity: Identity,
    /// `/run/current-system`: what is active right now.
    pub current_system: Option<String>,
    /// `/run/booted-system`: what was active when the machine came up.
    pub booted_system: Option<String>,
    /// Where the boot loader's default points — the next boot, which is a
    /// third fact and not the same as either of the two above.
    pub next_boot_system: Option<String>,
    /// The system profile's generation number.
    pub generation: Option<u64>,
    /// `uname -r` — the kernel that is executing.
    pub kernel_running: Option<String>,
    /// What the booted generation says it boots. Null when it could not be
    /// read, which the planner treats as "a reboot may be needed" rather
    /// than as "no reboot needed".
    pub kernel_booted: Option<BootedKernel>,
    /// Unit name to `systemctl is-active` answer.
    pub units: BTreeMap<String, String>,
    pub mounts: Vec<Mount>,
    /// Secret id to a fingerprint of what is on the host, or null when the
    /// file is not there. The fingerprint is whatever the deliverer can
    /// compare without reading the secret out — a certificate serial, a
    /// public key's digest.
    pub credentials: BTreeMap<String, Option<String>>,
    /// Null for a host that is not an etcd member.
    pub etcd: Option<EtcdView>,
    /// How many guests are running, for a host with the agent role. Null
    /// when it was not asked, which is not the same as zero.
    pub vms_running: Option<u32>,
    pub open_txns: Vec<Txn>,
    pub lock: Option<Lock>,
    /// What the host actually has: `kvm`, `vfio`, `rdma`. A capability the
    /// manifest declares and this list does not carry is a capability that
    /// was not found — a prober that could not decide says so in
    /// `unknown_reason` instead of leaving it out quietly.
    pub capabilities: Vec<String>,
    /// Whether this host has an identity and a known host key — installed
    /// but not enrolled is a state of its own and never "healthy".
    pub enrolled: bool,
    // --- lane 4A: the machine under the closure ---
    /// Free bytes on the filesystem that carries `/nix`, as `df -B1` gives
    /// them. Null when nobody could read it, which is not zero: zero would
    /// block every host whose probe lost a line.
    pub disk_free_nix_bytes: Option<u64>,
    /// Every PCI device the machine lists. EMPTY means the probe found no
    /// way to ask (no `lspci`, no `/sys/bus/pci`), and the preflight reads
    /// it that way: an empty list is not "this machine has no cards".
    pub pci: Vec<PciDevice>,
    /// Every network interface with a MAC. Empty has the same meaning as
    /// for `pci`.
    pub nics: Vec<NetworkInterface>,
    /// The units the RUNNING generation carries, by name, as they are listed
    /// in `/run/current-system/etc/systemd/system`. The manifest's
    /// `hosts.<id>.units[]` is the same question about the generation a
    /// release would put there, and the difference between the two is what
    /// the planner calls an unknown.
    ///
    /// Empty means nobody could list the directory — never "this generation
    /// has no units".
    pub generation_units: Vec<String>,
    // --- end lane 4A ---
    /// Why this observation is not to be trusted, in one sentence. Any value
    /// here blocks the host: it is the probe saying it does not know.
    pub unknown_reason: Option<String>,
}

impl HostObservation {
    /// A host nobody could reach, and why.
    pub fn unreachable(reason: impl Into<String>) -> HostObservation {
        HostObservation {
            reachable: false,
            unknown_reason: Some(reason.into()),
            ..HostObservation::empty()
        }
    }

    /// Nothing known. Every "not asked" is null rather than a zero value.
    pub fn empty() -> HostObservation {
        HostObservation {
            reachable: false,
            identity: Identity::unknown(),
            current_system: None,
            booted_system: None,
            next_boot_system: None,
            generation: None,
            kernel_running: None,
            kernel_booted: None,
            units: BTreeMap::new(),
            mounts: Vec::new(),
            credentials: BTreeMap::new(),
            etcd: None,
            vms_running: None,
            open_txns: Vec::new(),
            lock: None,
            capabilities: Vec::new(),
            enrolled: false,
            // --- lane 4A ---
            disk_free_nix_bytes: None,
            pci: Vec::new(),
            nics: Vec::new(),
            generation_units: Vec::new(),
            // --- end lane 4A ---
            unknown_reason: None,
        }
    }

    pub fn is_mounted(&self, path: &str) -> bool {
        self.mounts.iter().any(|m| m.path == path)
    }

    pub fn has_capability(&self, name: &str) -> bool {
        self.capabilities.iter().any(|c| c == name)
    }

    // --- lane 4A ---

    /// Whether a PCI address the inventory names is in the machine.
    ///
    /// Case-insensitive on the hex, because `lspci` prints lower case and an
    /// operator writing `0000:41:00.0` by hand from a datasheet may not.
    pub fn has_pci(&self, address: &str) -> bool {
        self.pci
            .iter()
            .any(|d| d.address.eq_ignore_ascii_case(address))
    }

    /// Whether a MAC the inventory names answered on some interface.
    pub fn has_mac(&self, mac: &str) -> bool {
        self.nics.iter().any(|n| n.mac.eq_ignore_ascii_case(mac))
    }

    // --- end lane 4A ---
}

/// A snapshot of a fleet, or of the part of it somebody looked at.
///
/// This is both the `--observation` input file and, later, lane 2A's cache
/// under `.meister-deploy/observations/`. One type for both, because a plan
/// embeds the snapshot it was made from and a reader has to be able to take
/// that embedded thing and hand it back to the tool.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Observations {
    pub schema: String,
    pub taken_at: DateTime<Utc>,
    /// Whether this snapshot is too thin to decide anything on: an `--offline`
    /// plan, or a run where the probe itself could not be trusted. A
    /// provisional snapshot makes every interrupting action `blocked`.
    pub provisional: bool,
    pub hosts: BTreeMap<String, HostObservation>,
}

impl Observations {
    /// The empty snapshot an `--offline` plan is made from: nothing was
    /// asked, and it says so rather than pretending every host is fine.
    pub fn provisional(taken_at: DateTime<Utc>) -> Observations {
        Observations {
            schema: OBSERVATION_SCHEMA.to_string(),
            taken_at,
            provisional: true,
            hosts: BTreeMap::new(),
        }
    }

    pub fn from_json(text: &str, origin: &str) -> Result<Observations> {
        crate::manifest::parse_checked(text, origin, OBSERVATION_SCHEMA)
    }

    pub fn to_json(&self) -> Result<Vec<u8>> {
        let mut bytes = serde_json::to_vec_pretty(self)
            .map_err(|e| anyhow::anyhow!("writing the observation as json failed: {e}"))?;
        bytes.push(b'\n');
        Ok(bytes)
    }

    pub fn host(&self, id: &str) -> Option<&HostObservation> {
        self.hosts.get(id)
    }
}

/// Where one host answers, as some provider found it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Target {
    pub address: String,
    pub port: u16,
    pub ssh_user: String,
    /// What the adapter saw. Compared against the manifest, never written
    /// into it: a target file that could change an enrolled host's key would
    /// be a target file that can impersonate a host.
    pub host_key_fingerprint: Option<String>,
    /// Opaque. Carried into the receipt and never interpreted here.
    pub provider_ref: String,
    pub observed: TargetObserved,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TargetObserved {
    pub reachable_at: DateTime<Utc>,
    pub capabilities: Vec<String>,
}

/// `targets.json`: the provider-neutral half of the lab adapter's contract.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Targets {
    pub schema: String,
    /// The adapter's own run reference. Carried into the receipt so that a
    /// green run can be pointed back at the resources it used.
    pub run_ref: String,
    /// Keyed by host id — the fleet's ids, not the provider's.
    pub targets: BTreeMap<String, Target>,
}

impl Targets {
    pub fn from_json(text: &str, origin: &str) -> Result<Targets> {
        crate::manifest::parse_checked(text, origin, TARGETS_SCHEMA)
    }

    pub fn to_json(&self) -> Result<Vec<u8>> {
        let mut bytes = serde_json::to_vec_pretty(self)
            .map_err(|e| anyhow::anyhow!("writing the targets as json failed: {e}"))?;
        bytes.push(b'\n');
        Ok(bytes)
    }
}

/// Where this tool reaches one host, after the manifest and the target file
/// have been reconciled.
///
/// This is what lane 2A's transport builds its ssh options from, and it is
/// frozen into the plan: a selection is only frozen if the addresses are
/// frozen with it, or a second `apply` of the same plan could talk to a
/// machine that has since taken over the name.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Endpoint {
    pub address: String,
    pub port: u16,
    pub ssh_user: String,
    pub host_key_fingerprint: Option<String>,
    /// Null when the endpoint came from the manifest alone.
    pub provider_ref: Option<String>,
}

/// Reconcile a target file with the manifest for the hosts a run will touch.
///
/// Returns one [`Endpoint`] per selected host. Every refusal below is a
/// sentence and stops the run (L08): a target set that does not line up with
/// the fleet is the one situation where carrying on means talking to a
/// machine nobody identified.
pub fn bind_targets(
    resolved: &ResolvedFleet,
    targets: &Targets,
    selected: &[String],
) -> Result<BTreeMap<String, Endpoint>> {
    if targets.schema != TARGETS_SCHEMA {
        bail!(
            "this target file says its schema is {:?}, and this tool speaks {TARGETS_SCHEMA:?}.",
            targets.schema
        );
    }

    // A host id that is not in the fleet: either the adapter and the
    // inventory disagree about a name, or this file belongs to another
    // fleet. Both are the operator's to fix and neither is guessable.
    let strangers: Vec<&str> = targets
        .targets
        .keys()
        .filter(|id| !resolved.hosts.contains_key(*id))
        .map(|s| s.as_str())
        .collect();
    if !strangers.is_empty() {
        bail!(
            "the target file names {}, and the fleet {:?} has no such host. \
             Target ids are the inventory's host ids.",
            strangers.join(", "),
            resolved.fleet.name
        );
    }

    // Two hosts at one address is either a copy-paste in the adapter or two
    // VMs that got the same lease. Either way the second `apply` would
    // change a machine that is already somebody else's.
    let mut seen: BTreeMap<(&str, u16), &str> = BTreeMap::new();
    for (id, target) in &targets.targets {
        if let Some(other) = seen.insert((&target.address, target.port), id) {
            bail!(
                "the target file puts {other} and {id} both at {}:{}; \
                 two hosts cannot be one machine.",
                target.address,
                target.port
            );
        }
    }

    let mut out = BTreeMap::new();
    for id in selected {
        let host = match resolved.hosts.get(id) {
            Some(host) => host,
            // The caller selected from the fleet, so this cannot happen from
            // `plan`; it can from a caller that built its own list.
            None => bail!("the fleet {:?} has no host {id}.", resolved.fleet.name),
        };
        let Some(target) = targets.targets.get(id) else {
            bail!(
                "the run covers {id} and the target file {:?} has no entry for it. \
                 Add it, or take the host out of the selection.",
                targets.run_ref
            );
        };
        // The manifest's fingerprint is what `keys enroll` recorded after
        // somebody read it off a console. A provider that reports a
        // different one is reporting a different machine, and the answer to
        // that is never "use the new one".
        if let (Some(declared), Some(seen)) =
            (&host.ssh.host_key_fingerprint, &target.host_key_fingerprint)
            && declared != seen
        {
            bail!(
                "the target file says {id} has the host key {seen} and the fleet has it \
                 enrolled as {declared}. If the machine was reinstalled, enroll it again \
                 with `keys enroll {id} --fingerprint <seen at the console> --replace \
                 --reason <why>`."
            );
        }
        out.insert(
            id.clone(),
            Endpoint {
                address: target.address.clone(),
                port: target.port,
                ssh_user: target.ssh_user.clone(),
                // The enrolled fingerprint wins where there is one: it is the
                // one a human read off a console, and it is what ssh will be
                // told to expect.
                host_key_fingerprint: host
                    .ssh
                    .host_key_fingerprint
                    .clone()
                    .or_else(|| target.host_key_fingerprint.clone()),
                provider_ref: Some(target.provider_ref.clone()),
            },
        );
    }
    Ok(out)
}

/// The endpoints the manifest alone gives, for a run without a target file.
pub fn manifest_endpoints(
    resolved: &ResolvedFleet,
    selected: &[String],
) -> Result<BTreeMap<String, Endpoint>> {
    let mut out = BTreeMap::new();
    for id in selected {
        let Some(host) = resolved.hosts.get(id) else {
            bail!("the fleet {:?} has no host {id}.", resolved.fleet.name);
        };
        out.insert(
            id.clone(),
            Endpoint {
                address: host.address.clone(),
                port: host.ssh.port,
                ssh_user: host.ssh.user.clone(),
                host_key_fingerprint: host.ssh.host_key_fingerprint.clone(),
                provider_ref: None,
            },
        );
    }
    Ok(out)
}

/// Every host id a target file mentions, for a caller that wants to check
/// coverage before it selects.
pub fn target_ids(targets: &Targets) -> BTreeSet<&String> {
    targets.targets.keys().collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixtures::{at, onebox};

    fn target(address: &str, fingerprint: Option<&str>) -> Target {
        Target {
            address: address.to_string(),
            port: 22,
            ssh_user: "root".to_string(),
            host_key_fingerprint: fingerprint.map(str::to_string),
            provider_ref: "one:vm:4711".to_string(),
            observed: TargetObserved {
                reachable_at: at("2026-09-21T12:00:00Z"),
                capabilities: vec!["kvm".to_string()],
            },
        }
    }

    fn targets_for(entries: &[(&str, Target)]) -> Targets {
        Targets {
            schema: TARGETS_SCHEMA.to_string(),
            run_ref: "lab-run-7".to_string(),
            targets: entries
                .iter()
                .map(|(id, t)| ((*id).to_string(), t.clone()))
                .collect(),
        }
    }

    fn ids(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| (*s).to_string()).collect()
    }

    #[test]
    fn an_observation_reads_back_from_its_own_json() {
        let mut hosts = BTreeMap::new();
        let mut one = HostObservation::empty();
        one.reachable = true;
        one.current_system = Some("/nix/store/a-system".to_string());
        one.units
            .insert("meister-agent.service".to_string(), "active".to_string());
        one.credentials.insert("identity".to_string(), None);
        one.mounts.push(Mount {
            path: "/var/lib/meister-data".to_string(),
            device: "/dev/disk/by-label/meister-data".to_string(),
            fstype: "ext4".to_string(),
        });
        hosts.insert("n1".to_string(), one);
        let snapshot = Observations {
            schema: OBSERVATION_SCHEMA.to_string(),
            taken_at: at("2026-09-21T12:00:00Z"),
            provisional: false,
            hosts,
        };
        let text = String::from_utf8(snapshot.to_json().unwrap()).unwrap();
        assert_eq!(
            Observations::from_json(&text, "the round trip").unwrap(),
            snapshot
        );
    }

    #[test]
    fn an_observation_of_another_schema_says_which_one_it_is() {
        let err =
            Observations::from_json(r#"{"schema":"meister-deploy/targets/1"}"#, "a target file")
                .unwrap_err()
                .to_string();
        assert!(err.contains(OBSERVATION_SCHEMA), "{err}");
        assert!(err.contains("meister-deploy/targets/1"), "{err}");
    }

    #[test]
    fn a_field_nobody_read_is_null_and_not_a_zero() {
        let empty = HostObservation::empty();
        let value = serde_json::to_value(&empty).unwrap();
        for field in [
            "current_system",
            "booted_system",
            "next_boot_system",
            "generation",
            "kernel_running",
            "kernel_booted",
            "etcd",
            "vms_running",
            "lock",
            "unknown_reason",
        ] {
            assert!(value[field].is_null(), "{field} should be null");
        }
        // `vms_running` in particular: a host nobody asked is not a host
        // with no guests on it.
        assert!(!empty.reachable);
    }

    #[test]
    fn a_provisional_snapshot_says_so_and_knows_nothing() {
        let snapshot = Observations::provisional(at("2026-09-21T12:00:00Z"));
        assert!(snapshot.provisional);
        assert!(snapshot.hosts.is_empty());
        assert!(snapshot.host("box").is_none());
    }

    #[test]
    fn targets_never_touch_the_manifest() {
        let resolved = onebox();
        let before = crate::canonical::to_vec(&serde_json::to_value(&resolved).unwrap());
        let targets = targets_for(&[
            ("box", target("192.168.122.31", None)),
            ("n1", target("192.168.122.32", None)),
        ]);
        let bound = bind_targets(&resolved, &targets, &ids(&["box", "n1"])).unwrap();
        let after = crate::canonical::to_vec(&serde_json::to_value(&resolved).unwrap());
        assert_eq!(before, after, "the fleet is the same bytes afterwards");

        // The address moved, and nothing else did.
        assert_eq!(bound["box"].address, "192.168.122.31");
        assert_eq!(resolved.hosts["box"].address, "10.0.0.10");
        assert_eq!(bound["box"].ssh_user, "root");
        assert_eq!(
            bound["box"].host_key_fingerprint,
            resolved.hosts["box"].ssh.host_key_fingerprint
        );
        assert_eq!(bound["box"].provider_ref.as_deref(), Some("one:vm:4711"));
    }

    #[test]
    fn a_target_for_a_host_the_fleet_does_not_have_stops_the_run() {
        let resolved = onebox();
        let targets = targets_for(&[("n9", target("192.168.122.39", None))]);
        let err = bind_targets(&resolved, &targets, &ids(&["n1"]))
            .unwrap_err()
            .to_string();
        assert!(err.contains("names n9"), "{err}");
        assert!(err.contains("one-box"), "{err}");
    }

    #[test]
    fn two_hosts_at_one_address_stop_the_run() {
        let resolved = onebox();
        let targets = targets_for(&[
            ("n1", target("192.168.122.32", None)),
            ("n2", target("192.168.122.32", None)),
        ]);
        let err = bind_targets(&resolved, &targets, &ids(&["n1", "n2"]))
            .unwrap_err()
            .to_string();
        assert!(err.contains("both at 192.168.122.32:22"), "{err}");
    }

    #[test]
    fn a_selected_host_with_no_target_stops_the_run() {
        let resolved = onebox();
        let targets = targets_for(&[("n1", target("192.168.122.32", None))]);
        let err = bind_targets(&resolved, &targets, &ids(&["n1", "n2"]))
            .unwrap_err()
            .to_string();
        assert!(err.contains("the run covers n2"), "{err}");
        assert!(err.contains("lab-run-7"), "{err}");
    }

    #[test]
    fn a_host_key_that_is_not_the_enrolled_one_stops_the_run() {
        let resolved = onebox();
        let targets = targets_for(&[(
            "box",
            target("192.168.122.31", Some("SHA256:somebody-else")),
        )]);
        let err = bind_targets(&resolved, &targets, &ids(&["box"]))
            .unwrap_err()
            .to_string();
        assert!(err.contains("SHA256:somebody-else"), "{err}");
        assert!(err.contains("keys enroll box --fingerprint"), "{err}");
    }

    #[test]
    fn an_unenrolled_host_takes_the_fingerprint_the_adapter_saw() {
        // n2 has no fingerprint in the fixture: nothing to contradict, and
        // the adapter's answer is all there is. It is still not "enrolled" —
        // that is `keys enroll`'s word and this only carries it.
        let resolved = onebox();
        assert!(resolved.hosts["n2"].ssh.host_key_fingerprint.is_none());
        let targets = targets_for(&[("n2", target("192.168.122.33", Some("SHA256:fresh")))]);
        let bound = bind_targets(&resolved, &targets, &ids(&["n2"])).unwrap();
        assert_eq!(
            bound["n2"].host_key_fingerprint.as_deref(),
            Some("SHA256:fresh")
        );
    }

    #[test]
    fn a_target_that_is_not_in_the_run_is_carried_along_and_ignored() {
        let resolved = onebox();
        let targets = targets_for(&[
            ("n1", target("192.168.122.32", None)),
            ("n2", target("192.168.122.33", None)),
        ]);
        let bound = bind_targets(&resolved, &targets, &ids(&["n1"])).unwrap();
        assert_eq!(bound.keys().collect::<Vec<_>>(), vec!["n1"]);
        assert_eq!(target_ids(&targets).len(), 2);
    }

    #[test]
    fn without_a_target_file_the_manifest_is_the_endpoint() {
        let resolved = onebox();
        let bound = manifest_endpoints(&resolved, &ids(&["box", "n1"])).unwrap();
        assert_eq!(bound["box"].address, "10.0.0.10");
        assert_eq!(bound["box"].port, 22);
        assert_eq!(bound["n1"].provider_ref, None);
    }

    #[test]
    fn a_target_file_reads_back_from_its_own_json() {
        let targets = targets_for(&[("n1", target("192.168.122.32", Some("SHA256:x")))]);
        let text = String::from_utf8(targets.to_json().unwrap()).unwrap();
        assert_eq!(
            Targets::from_json(&text, "the round trip").unwrap(),
            targets
        );
    }
}
