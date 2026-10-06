// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Host observations and provider-neutral endpoint binding.
//!
//! The planner consumes a release and a saved snapshot without probing hosts.
//! Unavailable scalar values remain null; collection fields may be empty.
//! Target files may change endpoints, but not fleet membership or roles.
//! Provider references are opaque metadata carried into receipts.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Result, bail};
use chrono::{DateTime, Utc};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::manifest::ResolvedFleet;

pub const OBSERVATION_SCHEMA: &str = "meister-deploy/observation/1";
pub const TARGETS_SCHEMA: &str = "meister-deploy/targets/1";

/// Host identity: SSH fingerprint, installation machine ID and hostname.
/// Machine IDs also detect cloned installations.
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

/// Kernel, initrd and command-line identity from `/run/booted-system`.
/// All three are compared with the release; `uname -r` alone is insufficient.
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
    /// Confirmation intent persisted before disarming the revert timer.
    Confirming,
    /// Rollback intent persisted before restoring the profile.
    /// The host may still run either system until rollback completes.
    Reverting,

    Confirmed,
    Reverted,
    /// Unreadable transaction state, including malformed or unsupported records.
    Inconsistent,
}

/// One transaction record on the target.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Txn {
    pub id: String,
    pub state: TxnState,
    /// Desired system, used to associate a transaction with a resumed run.
    pub target_system: Option<String>,
    /// When the revert timer fires, for a `pending` one.
    pub deadline: Option<DateTime<Utc>>,
    /// The run that opened it, when the record says.
    pub run_id: Option<String>,
}

/// Host lock ownership view.
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
    /// All reported members, including unhealthy ones; missing membership is a topology change.
    pub members: Vec<EtcdMember>,
}

/// Observed mount point and source.
/// The planner checks path presence; the mounts readiness check can compare sources.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Mount {
    pub path: String,
    /// What is mounted there, as the kernel spells it.
    pub device: String,
    pub fstype: String,
}

/// One PCI device, as the machine lists it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PciDevice {
    /// Full PCI domain address, for example `0000:41:00.0`, matching inventory syntax.
    pub address: String,
    /// Lowercase vendor/device pair, for example `10de:2684`.
    pub vendor_device: String,
}

/// One network interface, as the machine lists it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NetworkInterface {
    /// Kernel interface name for diagnostics; preflight matches interfaces by MAC.
    pub name: String,
    /// Lower case, colon separated, as `/sys/class/net/*/address` writes it.
    pub mac: String,
}

/// One host, as of `Observations::taken_at`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HostObservation {
    /// Whether the host answered. Unreachable hosts have empty or null observations;
    /// `unknown_reason` records why an answer is unavailable or incomplete.
    pub reachable: bool,
    pub identity: Identity,
    /// `/run/current-system`: what is active right now.
    pub current_system: Option<String>,
    /// `/run/booted-system`: what was active when the machine came up.
    pub booted_system: Option<String>,
    /// Kernel boot ID from `/proc/sys/kernel/random/boot_id`, if readable.
    /// Resume uses it to distinguish a completed reboot from an unchanged boot.
    #[serde(default)]
    pub boot_id: Option<String>,
    /// Resolved system profile target. This does not inspect boot-loader defaults or one-shot entries.
    pub next_boot_system: Option<String>,
    /// The system profile's generation number.
    pub generation: Option<u64>,
    /// `uname -r` — the kernel that is executing.
    pub kernel_running: Option<String>,
    /// Booted kernel identity, if all three fields were read. Missing identity may require a reboot.
    pub kernel_booted: Option<BootedKernel>,
    /// Unit name to `systemctl is-active` answer.
    pub units: BTreeMap<String, String>,
    pub mounts: Vec<Mount>,
    /// Secret reference to observed digest or file metadata; null when unavailable.
    /// Public files are hashed; private files are described by mode and owner.
    pub credentials: BTreeMap<String, Option<String>>,
    /// Null for a host that is not an etcd member.
    pub etcd: Option<EtcdView>,
    /// Number of entries returned by the agent VM listing, if available; no phase filtering.
    pub vms_running: Option<u32>,
    pub open_txns: Vec<Txn>,
    pub lock: Option<Lock>,
    /// Detected device capabilities: `kvm`, `vfio` and `rdma`.
    /// Missing capabilities and failed individual probes can both leave entries absent.
    pub capabilities: Vec<String>,
    /// Whether all manifest identity keys and companion certificates were found.
    /// This does not report SSH host-key enrollment.
    pub enrolled: bool,
    /// Free bytes on the filesystem containing `/nix`; null when unreadable.
    pub disk_free_nix_bytes: Option<u64>,
    /// Reported PCI devices. Empty does not distinguish an empty inventory from a failed probe.
    pub pci: Vec<PciDevice>,
    /// Interfaces with nonzero MAC addresses. Empty can also mean probing failed.
    pub nics: Vec<NetworkInterface>,
    /// Unit names in `/run/current-system/etc/systemd/system`.
    /// Empty can mean an empty directory or an unavailable listing.
    pub generation_units: Vec<String>,
    /// Reason the host observation cannot be trusted for planning.
    pub unknown_reason: Option<String>,
}

impl HostObservation {
    /// Unreachable observation with a reason.
    pub fn unreachable(reason: impl Into<String>) -> HostObservation {
        HostObservation {
            reachable: false,
            unknown_reason: Some(reason.into()),
            ..HostObservation::empty()
        }
    }

    /// Empty observation with nullable fields left unknown.
    pub fn empty() -> HostObservation {
        HostObservation {
            reachable: false,
            identity: Identity::unknown(),
            current_system: None,
            booted_system: None,
            boot_id: None,
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

            disk_free_nix_bytes: None,
            pci: Vec::new(),
            nics: Vec::new(),
            generation_units: Vec::new(),

            unknown_reason: None,
        }
    }

    pub fn is_mounted(&self, path: &str) -> bool {
        self.mounts.iter().any(|m| m.path == path)
    }

    pub fn has_capability(&self, name: &str) -> bool {
        self.capabilities.iter().any(|c| c == name)
    }

    /// Case-insensitive match for a full PCI domain address.
    pub fn has_pci(&self, address: &str) -> bool {
        self.pci
            .iter()
            .any(|d| d.address.eq_ignore_ascii_case(address))
    }

    /// Whether a MAC the inventory names answered on some interface.
    pub fn has_mac(&self, mac: &str) -> bool {
        self.nics.iter().any(|n| n.mac.eq_ignore_ascii_case(mac))
    }
}

/// Fleet snapshot used as plan input and saved under `observations/`.
/// Plans embed this same representation for replay.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Observations {
    pub schema: String,
    pub taken_at: DateTime<Utc>,
    /// Marks insufficient evidence, such as an offline snapshot.
    /// Interrupting actions are blocked for provisional snapshots.
    pub provisional: bool,
    pub hosts: BTreeMap<String, HostObservation>,
}

impl Observations {
    /// Empty, provisional snapshot for offline planning.
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
    /// Adapter fingerprint, checked against any fingerprint recorded in the manifest.
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
    /// Opaque adapter run reference carried into the receipt.
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

/// Endpoint bound to a selected host and frozen into the plan.
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

/// Validate target membership, endpoint uniqueness and enrolled fingerprints.
/// Return an endpoint for every selected host, or reject the target set.
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

    // Reject host IDs absent from the manifest.
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

    // Reject duplicate address/port pairs, including targets outside the selection.
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
            // Validate selections supplied by callers other than the planner.
            None => bail!("the fleet {:?} has no host {id}.", resolved.fleet.name),
        };
        let Some(target) = targets.targets.get(id) else {
            bail!(
                "the run covers {id} and the target file {:?} has no entry for it. \
                 Add it, or take the host out of the selection.",
                targets.run_ref
            );
        };
        // An adapter cannot replace a fingerprint already recorded in the manifest.
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
                // Prefer the manifest fingerprint when present.
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
        // Unknown guest count must remain distinct from zero.
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
        // Without a manifest fingerprint, carry the adapter value without enrolling it.
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
