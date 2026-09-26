// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Collect host observations with one bounded SSH probe per host.
//!
//! The POSIX shell probe prints framed `key=value` records. Missing scalar
//! answers remain unknown; incomplete framing sets `unknown_reason`.
//! A compatible `meister-activate status --json` response supplies system,
//! transaction and lock information. Raw transaction-file fallback currently
//! cannot decode the helper writer's `TxnRecord` schema.
//!
//! Hosts without an enrolled SSH fingerprint are recorded as unreachable
//! without connecting. Probe failures remain per-host observations; there are
//! no retries. The default worker pool has eight threads.

use std::collections::BTreeMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use anyhow::{Result, bail};
use chrono::{DateTime, Utc};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::manifest::{ResolvedHost, SecretKind};
use crate::observation::{
    BootedKernel, EtcdMember, EtcdView, HostObservation, Lock, Mount, OBSERVATION_SCHEMA,
    Observations, Txn,
};
use crate::run::{Cmd, Runner, shell_quote};
use crate::transport::{PROBE_DEADLINE, Ssh, Target};

pub const ACTIVATE_STATUS_SCHEMA: &str = "meister-deploy/activate-status/1";

/// Default maximum number of concurrent host probes.
pub const DEFAULT_CONCURRENCY: usize = 8;

/// Where a managed host keeps what `meister-activate` owns.
pub const DEPLOY_DIR: &str = "/var/lib/meisterstack/deploy";

/// Default local etcd client URL, matching `nix/etcd.nix`.
/// `effective_settings.etcd.client_url` may override it.
pub const DEFAULT_ETCD_CLIENT_URL: &str = "http://127.0.0.1:2379";

/// Map roles to the unit names rendered by the NixOS modules.
pub fn units_for_role(role: &str) -> &'static [&'static str] {
    match role {
        "agent" => &["meister-agent.service"],
        "cluster" => &["meister-cluster-controller.service"],
        "cloud" => &["meister-cloud-controller.service"],
        // All six addon services must be observed.
        "addons" => &[
            "kanidm.service",
            "garage.service",
            "prometheus.service",
            "loki.service",
            "tempo.service",
            "grafana.service",
        ],
        _ => &[],
    }
}

/// Unit carrying the agent-to-cluster or cluster-to-cloud session, if applicable.
pub fn session_unit(roles: &[String]) -> Option<&'static str> {
    if roles.iter().any(|r| r == "agent") {
        Some("meister-agent.service")
    } else if roles.iter().any(|r| r == "cluster") {
        Some("meister-cluster-controller.service")
    } else {
        None
    }
}

/// One file the probe looks for, and how it is allowed to describe it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialProbe {
    /// The `secret_refs[].id` of the manifest, which is the key of
    /// `HostObservation::credentials`.
    pub id: String,
    pub path: String,
    /// Hash content only for public file extensions.
    /// Other files are described by mode and owner so private-key digests do not enter reports.
    pub public: bool,
}

/// Host-specific probe inputs derived from the manifest, with helper/socket defaults.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeSpec {
    pub units: Vec<String>,
    /// Persistence paths checked with `findmnt -M` for exact mount points.
    /// `--target` would also match an ancestor filesystem.
    pub mounts: Vec<String>,
    pub credentials: Vec<CredentialProbe>,
    /// Companion certificates required alongside identity keys for service enrollment.
    pub identity_certs: Vec<String>,
    /// Ask etcd when this host is supposed to be a member.
    pub etcd: Option<EtcdProbe>,
    /// The node socket to count guests over, for a host with the agent
    /// role.
    pub agent_socket: Option<String>,
    /// Where `meister-activate` keeps its records.
    pub deploy_dir: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EtcdProbe {
    pub client_url: String,
    /// The member name the fleet configured, so that this host's own entry
    /// can be told from its peers'.
    pub member_name: Option<String>,
}

impl ProbeSpec {
    /// What to ask this host, derived from its manifest entry alone.
    pub fn for_host(host: &ResolvedHost) -> ProbeSpec {
        let mut units: Vec<String> = Vec::new();
        for role in &host.roles {
            for unit in units_for_role(role) {
                if !units.iter().any(|u| u == unit) {
                    units.push((*unit).to_string());
                }
            }
        }
        // etcd is not a role: it is a settings block the one derivation
        // renders next to a controller. A host that has it runs the unit.
        let etcd = host.effective_settings.etcd.as_ref().map(|settings| {
            if !units.iter().any(|u| u == "etcd.service") {
                units.push("etcd.service".to_string());
            }
            EtcdProbe {
                client_url: settings
                    .get("client_url")
                    .and_then(|v| v.as_str())
                    .unwrap_or(DEFAULT_ETCD_CLIENT_URL)
                    .to_string(),
                member_name: settings
                    .get("name")
                    .and_then(|v| v.as_str())
                    .map(str::to_string),
            }
        });
        if host.effective_settings.observability.is_some()
            && !units.iter().any(|u| u == "alloy.service")
        {
            units.push("alloy.service".to_string());
        }

        let mut credentials = Vec::new();
        let mut identity_certs = Vec::new();
        for secret in &host.secret_refs {
            credentials.push(CredentialProbe {
                id: secret.id.clone(),
                path: secret.target_path.clone(),
                // Public-file classification follows the filename extension used by readiness checks.
                public: is_certificate(&secret.target_path),
            });
            // Certificate refs may share `identity_key` with key refs; do not append `.crt` twice.
            if secret.kind == SecretKind::IdentityKey && !is_certificate(&secret.target_path) {
                let beside = certificate_beside(&secret.target_path);
                if !identity_certs.contains(&beside) {
                    identity_certs.push(beside);
                }
            }
        }

        ProbeSpec {
            units,
            mounts: host.persistence.iter().map(|p| p.path.clone()).collect(),
            credentials,
            identity_certs,
            etcd,
            agent_socket: host
                .roles
                .iter()
                .any(|r| r == "agent")
                .then(|| agent_socket_of(host)),
            deploy_dir: DEPLOY_DIR.to_string(),
        }
    }

    /// Generate a read-only POSIX shell probe with framed `key=value` output.
    /// `printf` and quoted substitutions preserve empty values without word splitting.
    /// Individual command errors are suppressed and leave missing answers.
    pub fn script(&self) -> String {
        let mut s = String::new();
        s.push_str("printf 'probe=%s\\n' start\n");
        // Read the kernel hostname without requiring the `hostname` utility.
        s.push_str("printf 'hostname=%s\\n' \"$(cat /proc/sys/kernel/hostname 2>/dev/null)\"\n");
        s.push_str("printf 'machine_id=%s\\n' \"$(cat /etc/machine-id 2>/dev/null)\"\n");
        // Resolve current, booted and profile links independently to store paths.
        s.push_str(
            "printf 'current_system=%s\\n' \"$(readlink -f /run/current-system 2>/dev/null)\"\n",
        );
        s.push_str(
            "printf 'booted_system=%s\\n' \"$(readlink -f /run/booted-system 2>/dev/null)\"\n",
        );
        // Resume compares this boot ID with the value recorded before reboot.
        s.push_str(
            "printf 'boot_id=%s\\n' \"$(cat /proc/sys/kernel/random/boot_id 2>/dev/null)\"\n",
        );
        s.push_str(
            "printf 'next_boot_system=%s\\n' \
             \"$(readlink -f /nix/var/nix/profiles/system 2>/dev/null)\"\n",
        );
        // `system-42-link` -> 42. The unresolved link, because the resolved
        // one is a store path and carries no generation number.
        s.push_str(
            "printf 'generation=%s\\n' \"$(readlink /nix/var/nix/profiles/system 2>/dev/null \
             | sed -n 's/.*system-\\([0-9][0-9]*\\)-link$/\\1/p')\"\n",
        );
        s.push_str("printf 'kernel_running=%s\\n' \"$(uname -r 2>/dev/null)\"\n");
        // Hash the booted generation's kernel-params bytes to match the release boot identity.
        s.push_str(
            "printf 'kernel_booted=%s\\n' \
             \"$(readlink -f /run/booted-system/kernel 2>/dev/null)\"\n",
        );
        s.push_str(
            "printf 'initrd_booted=%s\\n' \
             \"$(readlink -f /run/booted-system/initrd 2>/dev/null)\"\n",
        );
        s.push_str(
            "printf 'kernel_params_sha256=%s\\n' \
             \"$(sha256sum /run/booted-system/kernel-params 2>/dev/null | cut -d' ' -f1)\"\n",
        );

        if !self.units.is_empty() {
            s.push_str("for u in ");
            for unit in &self.units {
                s.push_str(&shell_quote(unit));
                s.push(' ');
            }
            // Inactive units still print a useful state despite a nonzero exit status.
            s.push_str(
                "; do printf 'unit=%s\\t%s\\n' \"$u\" \
                 \"$(systemctl is-active \"$u\" 2>/dev/null)\"; done\n",
            );
        }

        if !self.mounts.is_empty() {
            s.push_str("for m in ");
            for path in &self.mounts {
                s.push_str(&shell_quote(path));
                s.push(' ');
            }
            s.push_str(
                "; do printf 'mount=%s\\t%s\\n' \"$m\" \
                 \"$(findmnt -n -M \"$m\" -o SOURCE,FSTYPE 2>/dev/null | tr -s ' ')\"; done\n",
            );
        }

        for cred in &self.credentials {
            let path = shell_quote(&cred.path);
            let id = shell_quote(&cred.id);
            if cred.public {
                s.push_str(&format!(
                    "if [ -f {path} ]; then printf 'cred=%s\\tsha256:%s\\n' {id} \
                     \"$(sha256sum {path} 2>/dev/null | cut -d' ' -f1)\"; \
                     else printf 'cred_missing=%s\\n' {id}; fi\n"
                ));
            } else {
                // Describe private-file permissions and ownership without hashing content.
                s.push_str(&format!(
                    "if [ -f {path} ]; then printf 'cred=%s\\tmode:%s owner:%s\\n' {id} \
                     \"$(stat -c %a {path} 2>/dev/null)\" \
                     \"$(stat -c %U:%G {path} 2>/dev/null)\"; \
                     else printf 'cred_missing=%s\\n' {id}; fi\n"
                ));
            }
        }

        for cert in &self.identity_certs {
            let path = shell_quote(cert);
            s.push_str(&format!(
                "if [ -f {path} ]; then printf 'identity_cert=%s\\tpresent\\n' {path}; \
                 else printf 'identity_cert=%s\\tmissing\\n' {path}; fi\n"
            ));
        }

        // Require character devices; ordinary files do not establish capability.
        s.push_str("if [ -c /dev/kvm ]; then printf 'cap=%s\\n' kvm; fi\n");
        s.push_str("if [ -c /dev/vfio/vfio ]; then printf 'cap=%s\\n' vfio; fi\n");
        // An empty infiniband directory only establishes that the core module loaded.
        s.push_str(
            "if [ -n \"$(ls -A /sys/class/infiniband 2>/dev/null)\" ]; then \
             printf 'cap=%s\\n' rdma; fi\n",
        );

        // Measure the filesystem containing `/nix`; an unreadable result remains null.
        s.push_str(
            "printf 'disk_free_nix=%s\\n' \
             \"$(df -B1 --output=avail /nix 2>/dev/null | tail -n 1 | tr -d ' ')\"\n",
        );

        // Prefer sysfs, which needs no pciutils package. Strip vendor/device `0x` prefixes;
        // directory names already contain full PCI domain addresses.
        s.push_str("if [ -d /sys/bus/pci/devices ]; then\n");
        s.push_str("  for d in /sys/bus/pci/devices/*; do\n");
        s.push_str(
            "    if [ -r \"$d/vendor\" ]; then printf 'pci=%s\\t%s:%s\\n' \"${d##*/}\" \
                    \"$(cut -c3- \"$d/vendor\" 2>/dev/null)\" \
                    \"$(cut -c3- \"$d/device\" 2>/dev/null)\"; fi\n",
        );
        s.push_str("  done\n");
        s.push_str("elif command -v lspci >/dev/null 2>/dev/null; then\n");
        // Use `-D` to preserve the PCI domain; columns are address, class and vendor/device ID.
        s.push_str(
            "  lspci -Dn 2>/dev/null | while read -r a c v r; do \
                    printf 'pci=%s\\t%s\\n' \"$a\" \"$v\"; done\n",
        );
        s.push_str("fi\n");

        // Report kernel interface names and MACs; preflight matches MACs.
        s.push_str(
            "for n in /sys/class/net/*; do \
                    if [ -r \"$n/address\" ]; then printf 'nic=%s\\t%s\\n' \"${n##*/}\" \
                    \"$(cat \"$n/address\" 2>/dev/null)\"; fi; done\n",
        );

        // Pack generation unit names into one record. The substitution isolates `cd`.
        s.push_str(
            "printf 'gen_units=%s\\n' \
             \"$(cd /run/current-system/etc/systemd/system 2>/dev/null && printf '%s ' *)\"\n",
        );


        if let Some(etcd) = &self.etcd {
            let url = shell_quote(&etcd.client_url);
            // Skip stopped etcd members. Bound running-member queries with both etcd and shell timeouts.
            // Keep stderr and stdout redirections explicit for the read-only script checks.
            s.push_str("if systemctl is-active etcd.service >/dev/null 2>/dev/null; then\n");
            s.push_str(&format!(
                "  printf 'etcd_members=%s\\n' \"$(timeout 20 etcdctl --endpoints={url} \
                 --command-timeout=10s member list -w json 2>/dev/null | tr -d '\\n')\"\n"
            ));
            s.push_str(&format!(
                "  printf 'etcd_health=%s\\n' \"$(timeout 20 etcdctl --endpoints={url} \
                 --command-timeout=10s endpoint health -w json 2>/dev/null | tr -d '\\n')\"\n"
            ));
            s.push_str("fi\n");
        }

        if let Some(socket) = &self.agent_socket {
            let socket = shell_quote(socket);
            // Query the agent socket explicitly; target hosts need no operator CLI profile.
            s.push_str(&format!(
                "if [ -S {socket} ]; then printf 'vms=%s\\n' \
                 \"$(timeout 20 meister --endpoint unix://{socket} agent vm ls -o json \
                 2>/dev/null | tr -d '\\n')\"; fi\n",
                socket = socket
            ));
        }

        // Prefer a compatible helper response for system, transaction and lock state.
        s.push_str(
            "if command -v meister-activate >/dev/null 2>/dev/null; then \
             printf 'activate=%s\\n' \"$(timeout 30 meister-activate status --json 2>/dev/null \
             | tr -d '\\n')\"; fi\n",
        );
        // Read raw records as fallback. The transaction parser currently expects the
        // observation view schema, which differs from the helper's on-disk schema.
        let deploy = shell_quote(&self.deploy_dir);
        s.push_str(&format!(
            "if [ -f {deploy}/lock/owner.json ]; then printf 'lock_file=%s\\n' \
             \"$(cat {deploy}/lock/owner.json 2>/dev/null | tr -d '\\n')\"; fi\n"
        ));
        s.push_str(&format!(
            "for t in {deploy}/txn/*.json; do if [ -f \"$t\" ]; then \
             printf 'txn_file=%s\\n' \"$(cat \"$t\" 2>/dev/null | tr -d '\\n')\"; fi; done\n"
        ));

        // End framing also gives the script a successful final command.
        s.push_str("printf 'probe=%s\\n' end\n");
        s
    }

    /// The command that asks it.
    pub fn command(&self, ssh: &Ssh, target: &Target, deadline: Duration) -> Cmd {
        ssh.ask(target, &self.script(), deadline)
    }
}

/// Classify public file extensions consistently with credential readiness checks.
pub fn is_certificate(path: &str) -> bool {
    path.ends_with(".crt") || path.ends_with(".pem") || path.ends_with(".crl")
}

/// The certificate beside a key: `identity.key` -> `identity.crt`.
fn certificate_beside(key_path: &str) -> String {
    match key_path.strip_suffix(".key") {
        Some(stem) => format!("{stem}.crt"),
        None => format!("{key_path}.crt"),
    }
}

/// Agent socket: `<paths.run_dir>/agent.sock`, matching the agent configuration.
/// Default to the run directory rendered by `nix/agent.nix`.
fn agent_socket_of(host: &ResolvedHost) -> String {
    host.effective_settings
        .agent
        .as_ref()
        .and_then(|a| a.get("paths"))
        .and_then(|p| p.get("run_dir"))
        .and_then(|s| s.as_str())
        .map(|dir| format!("{}/agent.sock", dir.trim_end_matches('/')))
        // Default used by the fleet derivation.
        .unwrap_or_else(|| "/run/meisterstack/agent/agent.sock".to_string())
}

// ---------------------------------------------------------------------------
// What `meister-activate status --json` says
// ---------------------------------------------------------------------------

/// Target helper status contract. Nullable fields retain shell observations when absent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ActivateStatus {
    pub schema: String,
    pub current_system: Option<String>,
    pub booted_system: Option<String>,
    /// Resolved system profile target; this field does not inspect boot-loader entries.
    pub next_boot_system: Option<String>,
    pub generation: Option<u64>,
    pub kernel_running: Option<String>,
    pub kernel_booted: Option<BootedKernel>,
    /// Open transaction views. More than one is inconsistent for receipt interpretation.
    pub open_txns: Vec<Txn>,
    pub lock: Option<Lock>,
}

impl ActivateStatus {
    pub fn from_json(text: &str, origin: &str) -> Result<ActivateStatus> {
        crate::manifest::parse_checked(text, origin, ACTIVATE_STATUS_SCHEMA)
    }
}

// ---------------------------------------------------------------------------
// Reading the answer
// ---------------------------------------------------------------------------

/// Parse a host's probe output without effects. Unparseable fields stay unknown or empty;
/// missing framing sets `unknown_reason`. The caller decides reachability.
pub fn parse_probe(
    text: &str,
    spec: &ProbeSpec,
    host_key_fingerprint: Option<String>,
) -> HostObservation {
    let mut obs = HostObservation {
        reachable: true,
        ..HostObservation::empty()
    };
    obs.identity.host_key_fingerprint = host_key_fingerprint;

    let mut saw_start = false;
    let mut saw_end = false;
    let mut etcd_members: Option<String> = None;
    let mut etcd_health: Option<String> = None;
    let mut kernel_booted: Option<String> = None;
    let mut initrd_booted: Option<String> = None;
    let mut kernel_params: Option<String> = None;
    let mut identity_certs: Vec<(String, bool)> = Vec::new();
    let mut activate: Option<String> = None;
    let mut txn_lines: Vec<String> = Vec::new();
    let mut lock_line: Option<String> = None;

    for line in text.lines() {
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let value = value.trim_end_matches(['\r']);
        let some = |v: &str| {
            let v = v.trim();
            if v.is_empty() {
                None
            } else {
                Some(v.to_string())
            }
        };
        match key {
            "probe" if value == "start" => saw_start = true,
            "probe" if value == "end" => saw_end = true,
            "hostname" => obs.identity.hostname = some(value),
            "machine_id" => obs.identity.machine_id = some(value),
            "current_system" => obs.current_system = some(value),
            "booted_system" => obs.booted_system = some(value),
            "boot_id" => obs.boot_id = some(value),
            "next_boot_system" => obs.next_boot_system = some(value),
            "generation" => obs.generation = some(value).and_then(|v| v.parse().ok()),
            "kernel_running" => obs.kernel_running = some(value),
            "kernel_booted" => kernel_booted = some(value),
            "initrd_booted" => initrd_booted = some(value),
            "kernel_params_sha256" => kernel_params = some(value),
            "unit" => {
                if let Some((unit, state)) = value.split_once('\t') {
                    obs.units.insert(
                        unit.to_string(),
                        some(state).unwrap_or_else(|| "unknown".to_string()),
                    );
                }
            }
            "mount" => {
                if let Some((path, rest)) = value.split_once('\t') {
                    let mut fields = rest.split_whitespace();
                    // A nonempty exact-mount query adds this path; an absent answer adds nothing.
                    if let (Some(device), Some(fstype)) = (fields.next(), fields.next()) {
                        obs.mounts.push(Mount {
                            path: path.to_string(),
                            device: device.to_string(),
                            fstype: fstype.to_string(),
                        });
                    }
                }
            }
            "cred" => {
                if let Some((id, fingerprint)) = value.split_once('\t') {
                    obs.credentials.insert(id.to_string(), some(fingerprint));
                }
            }
            "cred_missing" => {
                if let Some(id) = some(value) {
                    obs.credentials.insert(id, None);
                }
            }
            "identity_cert" => {
                if let Some((path, state)) = value.split_once('\t') {
                    identity_certs.push((path.to_string(), state.trim() == "present"));
                }
            }
            "cap" => {
                if let Some(cap) = some(value)
                    && !obs.capabilities.contains(&cap)
                {
                    obs.capabilities.push(cap);
                }
            }

            "disk_free_nix" => {
                obs.disk_free_nix_bytes = some(value).and_then(|v| v.parse().ok());
            }
            "pci" => {
                if let Some((address, id)) = value.split_once('\t')
                    && let (Some(address), Some(id)) = (some(address), some(id))
                {
                    obs.pci.push(crate::observation::PciDevice {
                        address: address.to_ascii_lowercase(),
                        vendor_device: id.to_ascii_lowercase(),
                    });
                }
            }
            "nic" => {
                if let Some((name, mac)) = value.split_once('\t')
                    && let (Some(name), Some(mac)) = (some(name), some(mac))
                    // Exclude all-zero MAC addresses, which cannot identify a host interface.
                    && mac != "00:00:00:00:00:00"
                {
                    obs.nics.push(crate::observation::NetworkInterface {
                        name,
                        mac: mac.to_ascii_lowercase(),
                    });
                }
            }
            "gen_units" => {
                obs.generation_units = value
                    .split_whitespace()
                    // Ignore the literal glob left by an empty directory.
                    .filter(|name| *name != "*")
                    .map(str::to_string)
                    .collect();
                obs.generation_units.sort();
                obs.generation_units.dedup();
            }

            "etcd_members" => etcd_members = some(value),
            "etcd_health" => etcd_health = some(value),
            "vms" => obs.vms_running = some(value).and_then(|v| count_vms(&v)),
            "activate" => activate = some(value),
            "lock_file" => lock_line = some(value),
            "txn_file" => {
                if let Some(line) = some(value) {
                    txn_lines.push(line);
                }
            }
            _ => {}
        }
    }

    // Require the complete boot identity triple for reboot classification.
    if let (Some(kernel), Some(initrd), Some(digest)) =
        (kernel_booted, initrd_booted, kernel_params)
    {
        obs.kernel_booted = Some(BootedKernel {
            kernel_store_path: kernel,
            initrd_store_path: initrd,
            kernel_params_sha256: digest,
        });
    }

    if let Some(etcd) = &spec.etcd {
        obs.etcd = etcd_view(
            etcd,
            etcd_members.as_deref(),
            etcd_health.as_deref(),
            obs.units.get("etcd.service").map(String::as_str),
        );
    }

    // Service enrollment requires the manifest's keys and companion certificates.
    obs.enrolled = identity_is_complete(spec, &obs.credentials, &identity_certs);

    for line in &txn_lines {
        if let Ok(txn) = serde_json::from_str::<Txn>(line) {
            obs.open_txns.push(txn);
        }
    }
    if let Some(line) = &lock_line {
        obs.lock = serde_json::from_str::<Lock>(line).ok();
    }

    // Overlay non-null helper fields and nonempty transaction lists on shell observations.
    if let Some(text) = &activate
        && let Ok(status) = ActivateStatus::from_json(text, "meister-activate status --json")
    {
        merge_activate(&mut obs, status);
    }

    // Missing start or end framing makes the reachable host's observation incomplete.
    if !saw_start || !saw_end {
        obs.unknown_reason = Some(format!(
            "the probe of this host did not answer whole ({}); it was reached and what it \
             said is not a complete picture, so nothing is concluded from it.",
            if saw_start {
                "the answer stops in the middle"
            } else {
                "the answer does not begin where the probe begins"
            }
        ));
    }
    obs
}

/// Everything a `--json` answer carries, over what the shell said.
fn merge_activate(obs: &mut HostObservation, status: ActivateStatus) {
    if status.current_system.is_some() {
        obs.current_system = status.current_system;
    }
    if status.booted_system.is_some() {
        obs.booted_system = status.booted_system;
    }
    if status.next_boot_system.is_some() {
        obs.next_boot_system = status.next_boot_system;
    }
    if status.generation.is_some() {
        obs.generation = status.generation;
    }
    if status.kernel_running.is_some() {
        obs.kernel_running = status.kernel_running;
    }
    if status.kernel_booted.is_some() {
        obs.kernel_booted = status.kernel_booted;
    }
    // Only a nonempty helper transaction list replaces raw-file observations.
    if !status.open_txns.is_empty() {
        obs.open_txns = status.open_txns;
    }
    if status.lock.is_some() {
        obs.lock = status.lock;
    }
}

/// Count entries in an array or an object's `items` array; return `None` for other shapes.
/// Entries are not filtered by VM phase.
fn count_vms(text: &str) -> Option<u32> {
    let value: serde_json::Value = serde_json::from_str(text).ok()?;
    match value {
        serde_json::Value::Array(items) => Some(items.len() as u32),
        // The cli wraps a listing in an object with `items` at some tiers.
        serde_json::Value::Object(map) => match map.get("items") {
            Some(serde_json::Value::Array(items)) => Some(items.len() as u32),
            _ => None,
        },
        _ => None,
    }
}

/// Whether the required identity key metadata and companion certificates were observed.
fn identity_is_complete(
    spec: &ProbeSpec,
    credentials: &BTreeMap<String, Option<String>>,
    certs: &[(String, bool)],
) -> bool {
    // A manifest without identity certificates has no enrollment requirement here.
    if spec.identity_certs.is_empty() {
        return true;
    }
    let keys_present = spec
        .credentials
        .iter()
        .filter(|c| spec.identity_certs.contains(&certificate_beside(&c.path)))
        .all(|c| credentials.get(&c.id).is_some_and(|v| v.is_some()));
    let certs_present = spec
        .identity_certs
        .iter()
        .all(|path| certs.iter().any(|(p, present)| p == path && *present));
    keys_present && certs_present
}

/// Etcd topology and health from this host's local member.
/// Only explicit endpoint-health answers mark members healthy; local health is
/// counted separately for each host by readiness checks.
fn etcd_view(
    probe: &EtcdProbe,
    members_json: Option<&str>,
    health_json: Option<&str>,
    unit_state: Option<&str>,
) -> Option<EtcdView> {
    // A stopped member remains present in the observation with unhealthy status.
    let active = unit_state == Some("active");
    let healthy = health_json.is_some_and(endpoint_is_healthy);
    let members = members_json.map(parse_members).unwrap_or_default();
    if !active && members.is_empty() {
        return Some(EtcdView {
            member_id: None,
            healthy: false,
            members: Vec::new(),
        });
    }
    let member_id = probe.member_name.as_ref().and_then(|name| {
        members
            .iter()
            .find(|m| &m.name == name)
            .map(|m| m.id.clone())
    });
    let mut members = members;
    if healthy && let Some(id) = &member_id {
        for m in members.iter_mut() {
            if &m.id == id {
                m.healthy = true;
            }
        }
    }
    Some(EtcdView {
        member_id,
        healthy,
        members,
    })
}

/// Parse etcd member-list JSON, converting numeric IDs to hexadecimal strings.
fn parse_members(text: &str) -> Vec<EtcdMember> {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(text) else {
        return Vec::new();
    };
    let Some(list) = value.get("members").and_then(|m| m.as_array()) else {
        return Vec::new();
    };
    list.iter()
        .filter_map(|m| {
            let id = match m.get("ID") {
                Some(serde_json::Value::Number(n)) => n.as_u64().map(|n| format!("{n:x}")),
                Some(serde_json::Value::String(s)) => Some(s.clone()),
                _ => None,
            }?;
            Some(EtcdMember {
                id,
                // Retain unnamed members that have not started.
                name: m
                    .get("name")
                    .and_then(|n| n.as_str())
                    .unwrap_or_default()
                    .to_string(),
                peer_urls: m
                    .get("peerURLs")
                    .and_then(|u| u.as_array())
                    .map(|urls| {
                        urls.iter()
                            .filter_map(|u| u.as_str().map(str::to_string))
                            .collect()
                    })
                    .unwrap_or_default(),
                healthy: false,
            })
        })
        .collect()
}

/// `etcdctl endpoint health -w json`: `[{"endpoint":…,"health":true,…}]`.
fn endpoint_is_healthy(text: &str) -> bool {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(text) else {
        return false;
    };
    match value.as_array() {
        Some(entries) => {
            !entries.is_empty()
                && entries
                    .iter()
                    .all(|e| e.get("health").and_then(|h| h.as_bool()).unwrap_or(false))
        }
        None => false,
    }
}

// ---------------------------------------------------------------------------
// Asking
// ---------------------------------------------------------------------------

/// Thread-safe host-probe interface for SSH and controlled test implementations.
pub trait Prober: Sync {
    /// Fingerprint in the operator's known-hosts file, or `None` when unenrolled.
    fn enrolled_fingerprint(&self, target: &Target) -> Result<Option<String>>;

    /// One round trip. `Err` means the host did not answer.
    fn ask(&self, target: &Target, spec: &ProbeSpec) -> Result<String>;
}

/// The real one: `ssh` with the fleet's one set of options.
pub struct SshProber<'a> {
    pub runner: &'a (dyn Runner + Sync),
    pub ssh: &'a Ssh,
    pub deadline: Duration,
}

impl<'a> SshProber<'a> {
    pub fn new(runner: &'a (dyn Runner + Sync), ssh: &'a Ssh) -> SshProber<'a> {
        SshProber {
            runner,
            ssh,
            deadline: PROBE_DEADLINE,
        }
    }

    pub fn with_deadline(mut self, deadline: Duration) -> SshProber<'a> {
        self.deadline = deadline;
        self
    }
}

impl Prober for SshProber<'_> {
    fn enrolled_fingerprint(&self, target: &Target) -> Result<Option<String>> {
        self.ssh.enrolled_fingerprint(self.runner, target)
    }

    fn ask(&self, target: &Target, spec: &ProbeSpec) -> Result<String> {
        let out = self
            .runner
            .run(&spec.command(self.ssh, target, self.deadline))?;
        Ok(out.stdout)
    }
}

/// One host of a snapshot: where it is, and what to ask it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostProbe {
    pub target: Target,
    pub spec: ProbeSpec,
}

impl HostProbe {
    pub fn new(target: Target, spec: ProbeSpec) -> HostProbe {
        HostProbe { target, spec }
    }
}

/// Observe one host. Missing enrollment skips SSH; lookup or probe errors become
/// unreachable observations. Successful but incomplete output remains reachable
/// with `unknown_reason` set.
pub fn observe_host(prober: &dyn Prober, probe: &HostProbe) -> HostObservation {
    let fingerprint = match prober.enrolled_fingerprint(&probe.target) {
        Ok(Some(fingerprint)) => fingerprint,
        Ok(None) => {
            return HostObservation::unreachable(format!(
                "host {} is not enrolled; run keys enroll. Nothing was asked of it: with no \
                 key in the fleet's known_hosts there is no way to tell the machine that \
                 answers from any other machine.",
                probe.target.host_id
            ));
        }
        Err(e) => {
            return HostObservation::unreachable(format!(
                "the fleet's known_hosts could not be read for host {}: {e:#}",
                probe.target.host_id
            ));
        }
    };

    match prober.ask(&probe.target, &probe.spec) {
        Ok(text) => parse_probe(&text, &probe.spec, Some(fingerprint)),
        Err(e) => {
            let mut obs = HostObservation::unreachable(format!(
                "host {} did not answer: {e:#}",
                probe.target.host_id
            ));
            // Retain the enrolled fingerprint when the connection fails.
            obs.identity.host_key_fingerprint = Some(fingerprint);
            obs
        }
    }
}

/// Probe hosts in a bounded pool with caller-supplied snapshot time.
/// Each prober call must enforce its own deadline; queued hosts run in later waves.
pub fn observe_fleet(
    prober: &dyn Prober,
    probes: &[HostProbe],
    taken_at: DateTime<Utc>,
    concurrency: usize,
) -> Result<Observations> {
    if concurrency == 0 {
        bail!("a snapshot of nothing at a time is not a snapshot; ask for at least one host.");
    }
    let hosts: Mutex<BTreeMap<String, HostObservation>> = Mutex::new(BTreeMap::new());
    let next = AtomicUsize::new(0);
    let threads = concurrency.min(probes.len().max(1));

    std::thread::scope(|scope| {
        for _ in 0..threads {
            scope.spawn(|| {
                loop {
                    let index = next.fetch_add(1, Ordering::SeqCst);
                    let Some(probe) = probes.get(index) else {
                        return;
                    };
                    let observation = observe_host(prober, probe);
                    hosts
                        .lock()
                        .expect("the observation map is only ever locked to insert")
                        .insert(probe.target.host_id.clone(), observation);
                }
            });
        }
    });

    Ok(Observations {
        schema: OBSERVATION_SCHEMA.to_string(),
        taken_at,
        provisional: false,
        hosts: hosts
            .into_inner()
            .expect("every thread has ended, so nothing holds the lock"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixtures::{at, onebox_enrolled};
    use crate::run::{Matcher, Output, StrictFake};

    fn spec_for(id: &str) -> ProbeSpec {
        let fleet = onebox_enrolled();
        ProbeSpec::for_host(&fleet.hosts[id])
    }

    fn target(id: &str) -> Target {
        Target::new(id, "10.0.0.11", 22, "root")
    }

    /// What a healthy `box` says: four roles, etcd, two mounts, three
    /// credentials.
    fn healthy_answer(spec: &ProbeSpec) -> String {
        let mut s = String::from("probe=start\n");
        s.push_str("hostname=meister-box\n");
        s.push_str("machine_id=8f0a1b2c3d4e5f60718293a4b5c6d7e8\n");
        s.push_str(
            "current_system=/nix/store/oooooooooooooooooooooooooooooooo-nixos-system-box-25.11\n",
        );
        s.push_str(
            "booted_system=/nix/store/oooooooooooooooooooooooooooooooo-nixos-system-box-25.11\n",
        );
        s.push_str(
            "next_boot_system=/nix/store/oooooooooooooooooooooooooooooooo-nixos-system-box-25.11\n",
        );
        s.push_str("generation=42\n");
        s.push_str("kernel_running=6.12.41\n");
        s.push_str(
            "kernel_booted=/nix/store/kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkk-linux-6.12.41/bzImage\n",
        );
        s.push_str(
            "initrd_booted=/nix/store/kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkk-initrd-linux-6.12.41/initrd\n",
        );
        s.push_str("kernel_params_sha256=3b8fkkkkkkkk\n");
        for unit in &spec.units {
            s.push_str(&format!("unit={unit}\tactive\n"));
        }
        for path in &spec.mounts {
            s.push_str(&format!("mount={path}\t/dev/disk/by-label/data ext4\n"));
        }
        for cred in &spec.credentials {
            if cred.public {
                s.push_str(&format!("cred={}\tsha256:abc123\n", cred.id));
            } else {
                s.push_str(&format!(
                    "cred={}\tmode:600 owner:meister:meister\n",
                    cred.id
                ));
            }
        }
        for cert in &spec.identity_certs {
            s.push_str(&format!("identity_cert={cert}\tpresent\n"));
        }
        s.push_str("cap=kvm\n");

        s.push_str("disk_free_nix=41231765504\n");
        s.push_str("pci=0000:00:01.0\t8086:1237\n");
        s.push_str("pci=0000:41:00.0\t10de:2684\n");
        s.push_str("nic=lo\t00:00:00:00:00:00\n");
        s.push_str("nic=eno1\tB8:CE:F6:00:00:01\n");
        s.push_str("gen_units=-.slice basic.target meister-agent.service sshd.service\n");

        s.push_str(
            "etcd_members={\"header\":{},\"members\":[{\"ID\":1234605616436508552,\
             \"name\":\"box\",\"peerURLs\":[\"https://10.0.0.10:2380\"],\
             \"clientURLs\":[\"http://127.0.0.1:2379\"]}]}\n",
        );
        s.push_str(
            "etcd_health=[{\"endpoint\":\"http://127.0.0.1:2379\",\"health\":true,\"took\":\"1ms\"}]\n",
        );
        s.push_str("vms=[]\n");
        s.push_str("probe=end\n");
        s
    }

    /// Managed manifests use `identity_key` for both key and certificate refs.
    #[test]
    fn a_certificate_that_is_itself_an_identity_ref_needs_no_certificate_beside_it() {
        use crate::manifest::{Delivery, SecretKind, SecretRef, SecretSource};
        let mut fleet = onebox_enrolled();
        let host = fleet.hosts.get_mut("n1").expect("n1 is in the fixture");
        // Mirror per-file, per-unit identity refs from `nix/lib/manifest.nix`.
        host.secret_refs.push(SecretRef {
            id: "identity-crt-agent".to_string(),
            kind: SecretKind::IdentityKey,
            source: SecretSource {
                kind: crate::manifest::SecretSourceKind::MeisterCa,
                reference: "system:node:n1".to_string(),
            },
            target_path: "/var/lib/meisterstack/pki/identity.crt".to_string(),
            owner: "meister".to_string(),
            mode: "0644".to_string(),
            delivery: Delivery::File,
            reload: None,
        });
        let spec = ProbeSpec::for_host(&fleet.hosts["n1"]);
        assert_eq!(
            spec.identity_certs,
            vec!["/var/lib/meisterstack/pki/identity.crt".to_string()],
            "a certificate had a certificate derived from it"
        );
        // A companion certificate must not be expanded into `identity.crt.crt`.
        let answer = healthy_answer(&spec);
        let obs = parse_probe(&answer, &spec, Some("SHA256:enrolled-n1".to_string()));
        assert!(obs.enrolled, "{:?}", obs.credentials);
    }

    #[test]
    fn a_spec_asks_only_what_the_manifest_named() {
        let spec = spec_for("box");
        // box is cloud + cluster + agent + addons, and it renders etcd.
        assert!(spec.units.contains(&"meister-agent.service".to_string()));
        assert!(
            spec.units
                .contains(&"meister-cloud-controller.service".to_string())
        );
        assert!(
            spec.units
                .contains(&"meister-cluster-controller.service".to_string())
        );
        assert!(spec.units.contains(&"grafana.service".to_string()));
        assert!(spec.units.contains(&"etcd.service".to_string()));
        // The paths come from the manifest, never from a default in here.
        assert_eq!(
            spec.mounts,
            vec![
                "/var/lib/meister-data".to_string(),
                "/var/lib/etcd".to_string()
            ]
        );
        assert_eq!(
            spec.credentials
                .iter()
                .map(|c| c.id.as_str())
                .collect::<Vec<_>>(),
            vec!["identity", "ca-bundle", "serving"]
        );
        // A certificate may be hashed; a private key may not.
        let by_id = |id: &str| {
            spec.credentials
                .iter()
                .find(|c| c.id == id)
                .expect("the fixture has it")
                .public
        };
        assert!(by_id("ca-bundle"), "a ca bundle is public");
        assert!(!by_id("identity"), "an identity key is not");
        assert!(!by_id("serving"), "a serving key is not");
        assert_eq!(
            spec.identity_certs,
            vec!["/var/lib/meisterstack/pki/identity.crt".to_string()]
        );
        assert_eq!(
            spec.agent_socket.as_deref(),
            Some("/run/meisterstack/agent/agent.sock"),
            "the socket is `<run_dir>/agent.sock`, which is what the agent opens"
        );
        assert_eq!(
            spec.etcd.as_ref().unwrap().member_name.as_deref(),
            Some("box")
        );
    }

    #[test]
    fn a_host_without_the_agent_role_is_not_asked_about_guests() {
        let fleet = onebox_enrolled();
        let mut host = fleet.hosts["box"].clone();
        host.roles = vec!["cloud".to_string()];
        let spec = ProbeSpec::for_host(&host);
        assert!(spec.agent_socket.is_none());
        assert!(!spec.script().contains("agent vm ls"));
        assert!(!spec.units.contains(&"meister-agent.service".to_string()));
    }

    #[test]
    fn the_whole_answer_of_a_healthy_host_is_read() {
        let spec = spec_for("box");
        let obs = parse_probe(
            &healthy_answer(&spec),
            &spec,
            Some("SHA256:enrolled-box".to_string()),
        );
        assert!(obs.reachable);
        assert_eq!(obs.unknown_reason, None);
        assert_eq!(obs.identity.hostname.as_deref(), Some("meister-box"));
        assert_eq!(
            obs.identity.host_key_fingerprint.as_deref(),
            Some("SHA256:enrolled-box")
        );
        // Three system facts, separately.
        assert!(obs.current_system.is_some());
        assert_eq!(obs.current_system, obs.booted_system);
        assert_eq!(obs.current_system, obs.next_boot_system);
        assert_eq!(obs.generation, Some(42));
        assert_eq!(obs.kernel_running.as_deref(), Some("6.12.41"));
        let booted = obs.kernel_booted.as_ref().expect("the triple was read");
        assert!(booted.kernel_store_path.ends_with("bzImage"));
        assert!(booted.initrd_store_path.ends_with("initrd"));
        assert_eq!(booted.kernel_params_sha256, "3b8fkkkkkkkk");
        assert_eq!(obs.units["etcd.service"], "active");
        assert!(obs.is_mounted("/var/lib/etcd"));
        assert!(obs.has_capability("kvm"));
        assert_eq!(obs.vms_running, Some(0));
        assert!(obs.enrolled);
        let etcd = obs.etcd.as_ref().expect("box is a raft member");
        assert!(etcd.healthy);
        assert_eq!(etcd.member_id.as_deref(), Some("1122334455667788"));
        assert_eq!(etcd.members.len(), 1);
        assert_eq!(etcd.members[0].peer_urls, vec!["https://10.0.0.10:2380"]);
        assert!(etcd.members[0].healthy, "its own member, its own answer");
        // A private key is described, never hashed.
        assert_eq!(
            obs.credentials["identity"].as_deref(),
            Some("mode:600 owner:meister:meister")
        );
        assert_eq!(
            obs.credentials["ca-bundle"].as_deref(),
            Some("sha256:abc123")
        );
    }



    #[test]
    fn the_hardware_of_a_healthy_host_is_read() {
        let spec = spec_for("box");
        let obs = parse_probe(&healthy_answer(&spec), &spec, None);

        assert_eq!(obs.disk_free_nix_bytes, Some(41_231_765_504));

        // PCI addresses include the domain and use lowercase inventory syntax.
        assert_eq!(obs.pci.len(), 2, "{:?}", obs.pci);
        assert!(obs.has_pci("0000:41:00.0"));
        assert_eq!(obs.pci[1].vendor_device, "10de:2684");
        // Matching is case-insensitive.
        assert!(obs.has_pci("0000:41:00.0".to_uppercase().as_str()));
        assert!(!obs.has_pci("0000:42:00.0"));

        // Exclude the all-zero loopback MAC from identity matching.
        assert_eq!(obs.nics.len(), 1, "{:?}", obs.nics);
        assert_eq!(obs.nics[0].name, "eno1");
        assert_eq!(obs.nics[0].mac, "b8:ce:f6:00:00:01", "lower case, always");
        assert!(obs.has_mac("B8:CE:F6:00:00:01"));
        assert!(!obs.has_mac("b8:ce:f6:00:00:99"));

        // The generation's units, sorted, including the one whose name
        // begins with a dash.
        assert_eq!(
            obs.generation_units,
            vec![
                "-.slice",
                "basic.target",
                "meister-agent.service",
                "sshd.service"
            ]
        );
    }

    #[test]
    fn a_machine_that_could_not_be_asked_about_its_hardware_says_nothing_about_it() {
        // Unavailable disk and PCI answers remain unknown, rather than reporting zero capacity.
        let spec = spec_for("box");
        let answer = healthy_answer(&spec)
            .replace("disk_free_nix=41231765504\n", "disk_free_nix=\n")
            .replace("pci=0000:00:01.0\t8086:1237\n", "")
            .replace("pci=0000:41:00.0\t10de:2684\n", "")
            .replace("nic=lo\t00:00:00:00:00:00\n", "")
            .replace("nic=eno1\tB8:CE:F6:00:00:01\n", "")
            // Ignore unmatched unit globs.
            .replace(
                "gen_units=-.slice basic.target meister-agent.service sshd.service\n",
                "gen_units=*\n",
            );
        let obs = parse_probe(&answer, &spec, None);
        assert_eq!(obs.disk_free_nix_bytes, None);
        assert!(obs.pci.is_empty());
        assert!(obs.nics.is_empty());
        assert!(obs.generation_units.is_empty());
        // Complete framing does not imply every field was available.
        assert_eq!(obs.unknown_reason, None);
    }

    #[test]
    fn the_probe_asks_the_kernel_before_it_asks_a_package() {
        // Prefer sysfs; `lspci -Dn` preserves full PCI domains in fallback output.
        let script = spec_for("box").script();
        assert!(
            script.contains("/sys/bus/pci/devices"),
            "the probe does not read the kernel's own list:\n{script}"
        );
        assert!(
            script.contains("lspci -Dn"),
            "the fallback would print addresses without a domain:\n{script}"
        );
        assert!(
            script.contains("df -B1 --output=avail /nix"),
            "the free space of the store is asked about /nix and not about /:\n{script}"
        );
        assert!(
            script.contains("/run/current-system/etc/systemd/system"),
            "nobody asks which units the running generation carries:\n{script}"
        );
    }



    #[test]
    fn a_path_that_is_not_a_mount_point_is_absent_and_not_a_mount() {
        let spec = spec_for("box");
        let answer = healthy_answer(&spec).replace(
            "mount=/var/lib/etcd\t/dev/disk/by-label/data ext4\n",
            "mount=/var/lib/etcd\t\n",
        );
        let obs = parse_probe(&answer, &spec, None);
        assert!(obs.is_mounted("/var/lib/meister-data"));
        assert!(
            !obs.is_mounted("/var/lib/etcd"),
            "findmnt said nothing, so the path is on the root disk"
        );
        assert_eq!(
            obs.unknown_reason, None,
            "a missing mount is a fact, not a doubt"
        );
    }

    #[test]
    fn a_missing_credential_is_null_and_says_so() {
        let spec = spec_for("box");
        let answer = healthy_answer(&spec)
            .replace(
                "cred=identity\tmode:600 owner:meister:meister\n",
                "cred_missing=identity\n",
            )
            .replace(
                "identity_cert=/var/lib/meisterstack/pki/identity.crt\tpresent\n",
                "identity_cert=/var/lib/meisterstack/pki/identity.crt\tmissing\n",
            );
        let obs = parse_probe(&answer, &spec, None);
        assert_eq!(obs.credentials["identity"], None);
        assert!(!obs.enrolled, "no key and no certificate is unenrolled");
    }

    #[test]
    fn a_key_without_a_certificate_is_not_an_identity() {
        let spec = spec_for("box");
        let answer = healthy_answer(&spec).replace(
            "identity_cert=/var/lib/meisterstack/pki/identity.crt\tpresent\n",
            "identity_cert=/var/lib/meisterstack/pki/identity.crt\tmissing\n",
        );
        let obs = parse_probe(&answer, &spec, None);
        assert!(obs.credentials["identity"].is_some(), "the key is there");
        assert!(!obs.enrolled, "and nobody signed for it");
    }

    #[test]
    fn a_degraded_raft_group_is_read_as_two_of_three() {
        let spec = spec_for("box");
        // Retain all three members when one is unhealthy; local health is reported separately.
        let members = "etcd_members={\"members\":[\
             {\"ID\":1,\"name\":\"cloud-a\",\"peerURLs\":[\"https://10.0.1.10:2380\"]},\
             {\"ID\":2,\"name\":\"cloud-b\",\"peerURLs\":[\"https://10.0.1.11:2380\"]},\
             {\"ID\":3,\"name\":\"cloud-c\",\"peerURLs\":[\"https://10.0.1.12:2380\"]}]}";
        let answer = healthy_answer(&spec).replace(
            "etcd_members={\"header\":{},\"members\":[{\"ID\":1234605616436508552,\
                 \"name\":\"box\",\"peerURLs\":[\"https://10.0.0.10:2380\"],\
                 \"clientURLs\":[\"http://127.0.0.1:2379\"]}]}",
            members,
        );
        let obs = parse_probe(&answer, &spec, None);
        let etcd = obs.etcd.as_ref().expect("a member");
        assert_eq!(etcd.members.len(), 3);
        assert_eq!(etcd.members[0].id, "1");
        assert!(etcd.healthy, "this host answered healthy about itself");
        // Report the returned membership even when the local host is absent from it.
        assert_eq!(etcd.member_id, None);
        assert!(
            etcd.members.iter().all(|m| !m.healthy),
            "a peer this host cannot ask is not reported healthy"
        );
    }

    #[test]
    fn an_etcd_member_whose_unit_is_down_is_a_view_and_not_an_absence() {
        let spec = spec_for("box");
        let answer = healthy_answer(&spec)
            .replace(
                "unit=etcd.service\tactive\n",
                "unit=etcd.service\tinactive\n",
            )
            .lines()
            .filter(|l| !l.starts_with("etcd_"))
            .collect::<Vec<_>>()
            .join("\n");
        let obs = parse_probe(&format!("{answer}\n"), &spec, None);
        let etcd = obs
            .etcd
            .as_ref()
            .expect("a member with a dead unit is still a member");
        assert!(!etcd.healthy, "D8: no answer from a member is not healthy");
        assert!(etcd.members.is_empty());
    }

    #[test]
    fn a_socket_that_answered_nothing_useful_leaves_the_count_unknown() {
        let spec = spec_for("box");
        for line in ["vms=\n", "vms=null\n", "vms=Error: connection refused\n"] {
            let answer = healthy_answer(&spec).replace("vms=[]\n", line);
            let obs = parse_probe(&answer, &spec, None);
            assert_eq!(
                obs.vms_running, None,
                "{line:?} is not a count, and unknown is not zero"
            );
        }
        let answer =
            healthy_answer(&spec).replace("vms=[]\n", "vms=[{\"id\":\"a\"},{\"id\":\"b\"}]\n");
        assert_eq!(parse_probe(&answer, &spec, None).vms_running, Some(2));
    }

    #[test]
    fn half_an_answer_is_reachable_and_not_to_be_planned_on() {
        let spec = spec_for("box");
        let whole = healthy_answer(&spec);
        let half: String = whole.lines().take(6).map(|l| format!("{l}\n")).collect();
        let obs = parse_probe(&half, &spec, None);
        assert!(obs.reachable, "the host answered");
        assert!(
            obs.unknown_reason
                .as_deref()
                .is_some_and(|r| r.contains("did not answer whole")),
            "{:?}",
            obs.unknown_reason
        );
        // Retain fields parsed before the truncated response.
        assert_eq!(obs.identity.hostname.as_deref(), Some("meister-box"));
    }

    #[test]
    fn rubbish_is_not_an_observation() {
        let spec = spec_for("box");
        let obs = parse_probe(
            "\u{1}\u{2}binary rubbish\nand a line without an equals sign\n",
            &spec,
            None,
        );
        assert!(obs.unknown_reason.is_some());
        assert_eq!(obs.current_system, None);
        assert_eq!(obs.generation, None);
        assert!(obs.units.is_empty());
        assert!(!obs.enrolled);
    }

    #[test]
    fn the_helper_wins_where_it_speaks_and_only_there() {
        let spec = spec_for("box");
        let status = serde_json::json!({
            "schema": ACTIVATE_STATUS_SCHEMA,
            "current_system": "/nix/store/newnewnew-nixos-system-box-25.11",
            "booted_system": null,
            "next_boot_system": "/nix/store/newnewnew-nixos-system-box-25.11",
            "generation": 43,
            "kernel_running": null,
            "kernel_booted": null,
            "open_txns": [{
                "id": "txn-1",
                "state": "pending",
                "target_system": "/nix/store/newnewnew-nixos-system-box-25.11",
                "deadline": "2026-09-21T12:05:00Z",
                "run_id": "0192f0c0-0000-7000-8000-000000000001"
            }],
            "lock": {
                "run_id": "0192f0c0-0000-7000-8000-000000000001",
                "operator": "silas",
                "pid": 4711,
                "acquired_at": "2026-09-21T12:00:00Z"
            }
        });
        let answer = format!(
            "{}activate={}\nprobe=end\n",
            healthy_answer(&spec).trim_end_matches("probe=end\n"),
            serde_json::to_string(&status).unwrap()
        );
        let obs = parse_probe(&answer, &spec, None);
        assert_eq!(
            obs.current_system.as_deref(),
            Some("/nix/store/newnewnew-nixos-system-box-25.11"),
            "the helper moved the profile, so it is the authority"
        );
        assert_eq!(obs.generation, Some(43));
        // Where the helper said null, the shell answer stands.
        assert!(
            obs.booted_system
                .as_deref()
                .is_some_and(|s| s.contains("oooooooooo")),
            "{:?}",
            obs.booted_system
        );
        assert_eq!(obs.kernel_running.as_deref(), Some("6.12.41"));
        assert!(obs.kernel_booted.is_some());
        assert_eq!(obs.open_txns.len(), 1);
        assert_eq!(obs.open_txns[0].id, "txn-1");
        assert_eq!(obs.lock.as_ref().map(|l| l.pid), Some(4711));
        assert_eq!(obs.unknown_reason, None);
    }


    #[test]
    fn a_decision_in_flight_comes_across_the_wire_as_the_word_it_is() {
        // Observation views must preserve in-flight decision states.
        for word in ["confirming", "reverting"] {
            let spec = spec_for("box");
            let txn = serde_json::json!({
                "id": "txn-8", "state": word,
                "target_system": "/nix/store/newnewnew-nixos-system-box-25.11",
                "deadline": "2026-09-21T12:05:00Z", "run_id": null
            });
            let answer = format!(
                "{}txn_file={}\nprobe=end\n",
                healthy_answer(&spec).trim_end_matches("probe=end\n"),
                serde_json::to_string(&txn).unwrap()
            );
            let obs = parse_probe(&answer, &spec, None);
            assert_eq!(obs.open_txns.len(), 1, "{word}");
            assert_eq!(obs.open_txns[0].id, "txn-8", "{word}");
            // Preserve the helper status-view state spelling on serialization.
            assert_eq!(
                serde_json::to_value(obs.open_txns[0].state).unwrap(),
                serde_json::Value::String(word.to_string()),
                "{word}"
            );
        }
    }

    #[test]
    fn a_helper_answer_this_tool_does_not_speak_is_ignored_not_guessed() {
        let spec = spec_for("box");
        for bad in [
            "{\"schema\":\"meister-deploy/activate-status/2\",\"current_system\":\"/nix/store/x\"}",
            "{\"current_system\":\"/nix/store/x\"}",
            "not json at all",
        ] {
            let answer = format!(
                "{}activate={bad}\nprobe=end\n",
                healthy_answer(&spec).trim_end_matches("probe=end\n")
            );
            let obs = parse_probe(&answer, &spec, None);
            assert!(
                obs.current_system
                    .as_deref()
                    .is_some_and(|s| s.contains("oooooooooo")),
                "{bad}: the shell answer stands"
            );
            assert!(obs.open_txns.is_empty());
        }
    }

    #[test]
    fn the_records_are_read_from_the_files_when_the_helper_is_not_there() {
        let spec = spec_for("box");
        let txn = serde_json::json!({
            "id": "txn-7", "state": "staged", "target_system": null,
            "deadline": null, "run_id": null
        });
        let lock = serde_json::json!({
            "run_id": "0192f0c0-0000-7000-8000-000000000009",
            "operator": "someone-else", "pid": 99,
            "acquired_at": "2026-09-21T11:00:00Z"
        });
        let answer = format!(
            "{}txn_file={}\nlock_file={}\nprobe=end\n",
            healthy_answer(&spec).trim_end_matches("probe=end\n"),
            serde_json::to_string(&txn).unwrap(),
            serde_json::to_string(&lock).unwrap()
        );
        let obs = parse_probe(&answer, &spec, None);
        assert_eq!(obs.open_txns.len(), 1);
        assert_eq!(obs.open_txns[0].id, "txn-7");
        assert_eq!(obs.lock.as_ref().unwrap().operator, "someone-else");
    }

    #[test]
    fn a_host_that_is_not_enrolled_is_not_even_asked() {
        struct Fake;
        impl Prober for Fake {
            fn enrolled_fingerprint(&self, _: &Target) -> Result<Option<String>> {
                Ok(None)
            }
            fn ask(&self, _: &Target, _: &ProbeSpec) -> Result<String> {
                panic!("a host with no key in known_hosts must not be contacted")
            }
        }
        let obs = observe_host(&Fake, &HostProbe::new(target("n1"), spec_for("n1")));
        assert!(!obs.reachable);
        assert!(
            obs.unknown_reason
                .as_deref()
                .is_some_and(|r| r.contains("not enrolled; run keys enroll")),
            "{:?}",
            obs.unknown_reason
        );
    }

    #[test]
    fn a_host_that_did_not_answer_keeps_the_key_the_fleet_enrolled() {
        let runner = StrictFake::new()
            .expect(
                Matcher::prefix("ssh-keygen", ["-F"]),
                Output::stdout(
                    "10.0.0.11 ssh-ed25519 \
                     AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n",
                ),
            )
            .expect(
                Matcher::prefix("ssh", ["-o"]),
                Output::failing(255, "ssh: connect to host 10.0.0.11 port 22: timed out"),
            );
        let ssh = Ssh::with_known_hosts("/repo/known_hosts");
        let prober = SshProber::new(&runner, &ssh);
        let obs = observe_host(&prober, &HostProbe::new(target("n1"), spec_for("n1")));
        runner.verify().unwrap();
        assert!(!obs.reachable);
        assert!(obs.identity.host_key_fingerprint.is_some());
        assert!(
            obs.unknown_reason
                .as_deref()
                .is_some_and(|r| r.contains("did not answer")),
            "{:?}",
            obs.unknown_reason
        );
        // Leave unavailable facts unknown.
        assert_eq!(obs.current_system, None);
        assert!(obs.units.is_empty());
        assert_eq!(obs.vms_running, None);
    }

    /// Concurrency probe with a condition-variable barrier.
    /// A sequential implementation times out before the expected probes meet.
    struct CountingProber {
        answers: BTreeMap<String, Result<String, String>>,
        /// Number of simultaneous probes required to release the barrier.
        expected: usize,
        state: Mutex<Concurrency>,
        gate: std::sync::Condvar,
    }

    #[derive(Default)]
    struct Concurrency {
        in_flight: usize,
        max_in_flight: usize,
        /// Sticky barrier state; later waves need not meet again.
        released: bool,
        timed_out: bool,
    }

    impl Prober for CountingProber {
        fn enrolled_fingerprint(&self, target: &Target) -> Result<Option<String>> {
            Ok(Some(format!("SHA256:enrolled-{}", target.host_id)))
        }

        fn ask(&self, target: &Target, _: &ProbeSpec) -> Result<String> {
            {
                let mut state = self
                    .state
                    .lock()
                    .expect("the counter is only locked in here");
                state.in_flight += 1;
                state.max_in_flight = state.max_in_flight.max(state.in_flight);
                if state.in_flight >= self.expected {
                    state.released = true;
                }
                self.gate.notify_all();
                while !state.released && !state.timed_out {
                    let (next, wait) = self
                        .gate
                        .wait_timeout(state, Duration::from_secs(5))
                        .expect("the counter is only locked in here");
                    state = next;
                    if wait.timed_out() {
                        state.timed_out = true;
                    }
                }
                state.in_flight -= 1;
            }
            match self.answers.get(&target.host_id) {
                Some(Ok(text)) => Ok(text.clone()),
                Some(Err(why)) => bail!("{why}"),
                None => bail!("this test has no answer for {}", target.host_id),
            }
        }
    }

    #[test]
    fn the_hosts_are_asked_at_the_same_time_and_one_that_fails_stops_nobody() {
        let spec = spec_for("box");
        let whole = healthy_answer(&spec);
        let ids = ["h1", "h2", "h3", "h4", "h5", "h6", "h7", "h8"];
        let mut answers = BTreeMap::new();
        for id in ids {
            // Simulate two SSH deadline failures.
            let answer = if id == "h3" || id == "h7" {
                Err("ssh did not finish within 60s and its process group was killed".to_string())
            } else {
                Ok(whole.clone())
            };
            answers.insert(id.to_string(), answer);
        }
        let prober = CountingProber {
            answers,
            expected: ids.len(),
            state: Mutex::new(Concurrency::default()),
            gate: std::sync::Condvar::new(),
        };
        let probes: Vec<HostProbe> = ids
            .iter()
            .map(|id| HostProbe::new(target(id), spec.clone()))
            .collect();

        let snapshot = observe_fleet(&prober, &probes, at("2026-09-21T12:00:00Z"), ids.len())
            .expect("a snapshot");

        let state = prober.state.lock().unwrap();
        assert!(
            !state.timed_out,
            "the hosts were asked one after another: only {} were ever in flight",
            state.max_in_flight
        );
        assert_eq!(state.max_in_flight, ids.len());
        drop(state);

        assert_eq!(
            snapshot.hosts.len(),
            ids.len(),
            "every host is in the snapshot"
        );
        assert!(!snapshot.provisional);
        assert_eq!(snapshot.taken_at, at("2026-09-21T12:00:00Z"));
        for id in ids {
            let obs = &snapshot.hosts[id];
            if id == "h3" || id == "h7" {
                assert!(!obs.reachable, "{id}");
                assert!(
                    obs.unknown_reason
                        .as_deref()
                        .is_some_and(|r| r.contains("did not answer")),
                    "{id}: {:?}",
                    obs.unknown_reason
                );
            } else {
                assert!(obs.reachable, "{id}");
                assert_eq!(obs.unknown_reason, None, "{id}");
                assert_eq!(obs.generation, Some(42), "{id}");
            }
        }
    }

    #[test]
    fn a_pool_smaller_than_the_fleet_still_asks_every_host() {
        let spec = spec_for("box");
        let whole = healthy_answer(&spec);
        let ids = ["h1", "h2", "h3", "h4"];
        let answers = ids
            .iter()
            .map(|id| ((*id).to_string(), Ok(whole.clone())))
            .collect();
        // A concurrency limit of two processes four hosts in two waves.
        let prober = CountingProber {
            answers,
            expected: 2,
            state: Mutex::new(Concurrency::default()),
            gate: std::sync::Condvar::new(),
        };
        let probes: Vec<HostProbe> = ids
            .iter()
            .map(|id| HostProbe::new(target(id), spec.clone()))
            .collect();
        let snapshot =
            observe_fleet(&prober, &probes, at("2026-09-21T12:00:00Z"), 2).expect("a snapshot");
        assert_eq!(snapshot.hosts.len(), 4);
        let state = prober.state.lock().unwrap();
        assert_eq!(state.max_in_flight, 2, "the pool was the bound");
        assert!(!state.timed_out);
    }

    #[test]
    fn a_snapshot_of_no_hosts_is_a_snapshot_and_a_pool_of_none_is_not() {
        struct Nobody;
        impl Prober for Nobody {
            fn enrolled_fingerprint(&self, _: &Target) -> Result<Option<String>> {
                panic!("nothing to ask")
            }
            fn ask(&self, _: &Target, _: &ProbeSpec) -> Result<String> {
                panic!("nothing to ask")
            }
        }
        let snapshot =
            observe_fleet(&Nobody, &[], at("2026-09-21T12:00:00Z"), 8).expect("an empty snapshot");
        assert!(snapshot.hosts.is_empty());
        assert!(!snapshot.provisional);
        let err = observe_fleet(&Nobody, &[], at("2026-09-21T12:00:00Z"), 0)
            .unwrap_err()
            .to_string();
        assert!(err.contains("at least one host"), "{err}");
    }

    #[test]
    fn the_observation_is_the_file_the_planner_reads() {
        let spec = spec_for("box");
        let obs = parse_probe(&healthy_answer(&spec), &spec, None);
        let snapshot = Observations {
            schema: OBSERVATION_SCHEMA.to_string(),
            taken_at: at("2026-09-21T12:00:00Z"),
            provisional: false,
            hosts: BTreeMap::from([("box".to_string(), obs)]),
        };
        let text = String::from_utf8(snapshot.to_json().unwrap()).unwrap();
        let read = Observations::from_json(&text, "the snapshot this test wrote")
            .expect("what this module writes is what the planner reads");
        assert_eq!(read, snapshot);
    }
}
