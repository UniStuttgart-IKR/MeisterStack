// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! What a host IS, asked once and written down.
//!
//! [`crate::observation`] is the TYPE a snapshot has; this module is how one
//! comes about. The shape is deliberate in four ways.
//!
//! **One round trip per host.** `plan`, `status` and `check` want the same
//! two dozen facts, and asking for them one `ssh` at a time turns seventy
//! hosts into a thousand connections — which is slow, and which is also
//! twenty different moments pretending to be one snapshot. So there is one
//! POSIX-sh script per host, it prints `key=value` lines, and every verb
//! reads the same answer. `tests/probe_reads_only.rs` reads the generated
//! script and fails if it contains a command that could write, start or
//! stop anything: the script is the part of this tool that runs on somebody
//! else's machine, so "read-only" has to be a property of its text and not
//! a claim in a comment.
//!
//! **Two sources, one type.** A managed host has `meister-activate` in its
//! closure, and `meister-activate status --json` is the authority on the
//! three system facts, the open transactions and the lock, because it is
//! what wrote them. A host that does not have it yet — one that is
//! installed and not enrolled, one still served by the context push — can
//! still be read with `readlink` and `systemctl`. Both land in the same
//! [`HostObservation`], the activate answer wins where it speaks, and
//! nothing about the fleet's verdicts depends on which of the two answered.
//! [`ActivateStatus`] is therefore a contract lane 2C implements, not an
//! internal detail: `meister-deploy schema activate-status` prints it.
//!
//! **Null is an answer and zero is not.** Every field that could not be read
//! stays `None`. `vms_running: None` means nobody was able to ask, and
//! `Some(0)` means the node said it runs none — the planner's maintenance
//! step turns on exactly that difference, and a probe that reported `0` for
//! "the socket did not answer" would drain a host that is running guests.
//!
//! **A host that hangs does not hold the fleet.** Each host has its own
//! deadline (the `Cmd` carries it, so `Real` kills the process group when it
//! passes), the hosts are asked in parallel with a bounded pool, and a host
//! that could not be reached becomes `reachable: false` with a sentence
//! rather than an error that ends the run. Nothing is retried here: a
//! retry is a decision about how long an operator waits, and it belongs to
//! the verb.

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

/// How many hosts are asked at once by default.
///
/// Eight, because a probe is one ssh and a sleeping fleet answers in well
/// under a second, while seventy connections at once is a number that
/// depends on the workstation's file descriptors and on how many of them
/// the operator's ssh agent is willing to sign for. A bounded pool is also
/// what keeps the wall clock of a snapshot close to the deadline of its
/// slowest host rather than to the sum of all of them.
pub const DEFAULT_CONCURRENCY: usize = 8;

/// Where a managed host keeps what `meister-activate` owns.
pub const DEPLOY_DIR: &str = "/var/lib/meisterstack/deploy";

/// The etcd client url every member of this fleet serves on.
///
/// Loopback on purpose and not a guess: `nix/etcd.nix` binds
/// `listenClientUrls` to `127.0.0.1:2379` in both its shapes, so that a
/// replica which has lost quorum stalls on its own member instead of
/// quietly writing through a healthy neighbour. Only peer traffic leaves
/// the host. A fleet that ever changes that renders `client_url` into
/// `effective_settings.etcd`, and [`ProbeSpec::for_host`] reads it.
pub const DEFAULT_ETCD_CLIENT_URL: &str = "http://127.0.0.1:2379";

/// Which unit carries which role.
///
/// The names are the ones the modules define (`nix/agent.nix`,
/// `nix/controllers.nix`, `nix/addons.nix`): a role is a claim about what a
/// host runs, and this is where that claim becomes something
/// `systemctl is-active` can answer.
pub fn units_for_role(role: &str) -> &'static [&'static str] {
    match role {
        "agent" => &["meister-agent.service"],
        "cluster" => &["meister-cluster-controller.service"],
        "cloud" => &["meister-cloud-controller.service"],
        // Six services behind one role. They are what an operator means by
        // "the addons are up", and a role that answered for one of them
        // would be a role that hides the other five.
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

/// Which of a host's units carries a session to the tier above it, if any.
///
/// The agent's session to its cluster controller, the cluster's to the
/// cloud. Used by the `session` readiness check, which is the one check
/// that is about a connection rather than about a process.
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
    /// Whether the content may be hashed.
    ///
    /// A certificate, a CA bundle and a CRL are public: their sha256 is a
    /// version somebody can compare, and printing it costs nothing. A
    /// private key is not, and the digest of a private key is a digest of a
    /// private key — it would be in a journal, in a receipt and in whatever
    /// ticket the receipt is attached to. So a key is described by its mode
    /// and its owner, which is what a loader refuses it for (M0 probe S11),
    /// and never by its content.
    pub public: bool,
}

/// What to ask ONE host. Everything host-specific comes from the manifest:
/// the probe has no list of paths of its own, because a path this tool
/// invented would be a path the fleet does not use.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeSpec {
    pub units: Vec<String>,
    /// The `persistence[].path` entries. Asked with `findmnt -M`, which
    /// answers only for a real mount point — `--target` would answer `/`
    /// for a path that is a directory on the root disk, which is exactly
    /// the failure V19 is about.
    pub mounts: Vec<String>,
    pub credentials: Vec<CredentialProbe>,
    /// The certificate beside each identity key. `enrolled` is about a
    /// service identity: a key without a certificate is a key nobody
    /// countersigned.
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
                // The path decides, not the kind: a `ca_bundle` is public
                // and so is a `crl`, and both are named `*.crt`/`*.pem` by
                // the one derivation — but a `serving_key` is a key however
                // it is spelled, and hashing it because its kind sounded
                // public would be the one mistake that cannot be taken
                // back.
                public: is_certificate(&secret.target_path),
            });
            if secret.kind == SecretKind::IdentityKey {
                identity_certs.push(certificate_beside(&secret.target_path));
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

    /// The script, as it is sent. One string, POSIX sh, and every line of it
    /// only reads.
    ///
    /// Written with `printf '<key>=%s\n' "$(…)"` rather than `echo`: a value
    /// that came out empty is then an empty value rather than a line that
    /// disappeared, and nothing is word-split on the way out. Every
    /// substitution sends its diagnostics to `/dev/null`, because a missing
    /// tool is a missing answer and not a broken probe — these hosts run
    /// four different role sets and two different generations of image.
    pub fn script(&self) -> String {
        let mut s = String::new();
        s.push_str("printf 'probe=%s\\n' start\n");
        // Who it is. `/proc/sys/kernel/hostname` rather than the `hostname`
        // program, which an appliance image may not have.
        s.push_str("printf 'hostname=%s\\n' \"$(cat /proc/sys/kernel/hostname 2>/dev/null)\"\n");
        s.push_str("printf 'machine_id=%s\\n' \"$(cat /etc/machine-id 2>/dev/null)\"\n");
        // The three system facts, as three separate questions. `readlink -f`
        // because the profile is a symlink to a symlink and the store path
        // is what a release names.
        s.push_str(
            "printf 'current_system=%s\\n' \"$(readlink -f /run/current-system 2>/dev/null)\"\n",
        );
        s.push_str(
            "printf 'booted_system=%s\\n' \"$(readlink -f /run/booted-system 2>/dev/null)\"\n",
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
        // What the BOOTED generation says it boots: three fields, compared
        // straight against the release's `boot`. The digest is over the
        // bytes of `kernel-params`, which is the file NixOS writes the
        // command line into without a trailing newline — so the same sha256
        // the one derivation computes over `boot.kernelParams`.
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
            // `is-active` exits non-zero for an inactive unit and still
            // prints its answer, which is the answer this asks for.
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
                // A private key is described and never read: the mode and
                // the owner are what its loader refuses it for.
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

        s.push_str("if [ -e /dev/kvm ]; then printf 'cap=%s\\n' kvm; fi\n");
        s.push_str("if [ -e /dev/vfio/vfio ]; then printf 'cap=%s\\n' vfio; fi\n");
        // The directory exists as soon as the ib core module is loaded, so
        // the question is whether it has a device in it.
        s.push_str(
            "if [ -n \"$(ls -A /sys/class/infiniband 2>/dev/null)\" ]; then \
             printf 'cap=%s\\n' rdma; fi\n",
        );

        if let Some(etcd) = &self.etcd {
            let url = shell_quote(&etcd.client_url);
            // Only when the unit is actually running: `etcdctl` against a
            // stopped member waits for its own timeout to tell us what
            // `systemctl` already said. The command timeout is etcd's own,
            // and `timeout` is the one that also covers an etcdctl which
            // ignores it.
            // Both descriptors to /dev/null separately rather than `2>&1`:
            // this script is read by a test that allows exactly one
            // redirection target, and a duplicated descriptor is a
            // redirection whose target that reader has to work out.
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
            // The node's own socket, over the node's own cli, with the
            // endpoint named explicitly: a target host has no operator
            // profile, and a count that came from `ps` would count a
            // hypervisor that is exiting.
            s.push_str(&format!(
                "if [ -S {socket} ]; then printf 'vms=%s\\n' \
                 \"$(timeout 20 meister --endpoint unix://{socket} agent vm ls -o json \
                 2>/dev/null | tr -d '\\n')\"; fi\n",
                socket = socket
            ));
        }

        // What `meister-activate` holds, if it is there. One line, compact
        // json, and it is the authority on the transactions and the lock
        // because it is what wrote them.
        s.push_str(
            "if command -v meister-activate >/dev/null 2>/dev/null; then \
             printf 'activate=%s\\n' \"$(timeout 30 meister-activate status --json 2>/dev/null \
             | tr -d '\\n')\"; fi\n",
        );
        // And the records themselves, for a host whose helper is not there
        // or could not answer — a resume must not depend on the program
        // whose crash it is recovering from.
        let deploy = shell_quote(&self.deploy_dir);
        s.push_str(&format!(
            "if [ -f {deploy}/lock/owner.json ]; then printf 'lock_file=%s\\n' \
             \"$(cat {deploy}/lock/owner.json 2>/dev/null | tr -d '\\n')\"; fi\n"
        ));
        s.push_str(&format!(
            "for t in {deploy}/txn/*.json; do if [ -f \"$t\" ]; then \
             printf 'txn_file=%s\\n' \"$(cat \"$t\" 2>/dev/null | tr -d '\\n')\"; fi; done\n"
        ));

        // Always the last line, and it always succeeds: the exit code of
        // the whole script is then the exit code of this echo and not of
        // whatever question happened to be asked last.
        s.push_str("printf 'probe=%s\\n' end\n");
        s
    }

    /// The command that asks it.
    pub fn command(&self, ssh: &Ssh, target: &Target, deadline: Duration) -> Cmd {
        ssh.ask(target, &self.script(), deadline)
    }
}

/// Whether a path holds public material this tool may hash.
///
/// Public, because the readiness check that judges a key's mode has to make
/// the same distinction from the same rule: a certificate is described by
/// its digest, a key by its mode.
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

/// Where the node socket is, as the host's own configuration names it.
fn agent_socket_of(host: &ResolvedHost) -> String {
    host.effective_settings
        .agent
        .as_ref()
        .and_then(|a| a.get("paths"))
        .and_then(|p| p.get("socket"))
        .and_then(|s| s.as_str())
        .unwrap_or("/run/meisterstack/agent.sock")
        .to_string()
}

// ---------------------------------------------------------------------------
// What `meister-activate status --json` says
// ---------------------------------------------------------------------------

/// The answer of the target-side helper — **a contract, implemented by lane
/// 2C's `meister-activate`.**
///
/// It carries what only the target knows: which transaction is open, what
/// state it is in, who holds the lock. It also repeats the three system
/// facts, because it can read them without a second round trip and because
/// it is the program that moved the profile.
///
/// Every field is optional except the schema: a helper that could not read
/// something says null, exactly like the shell probe does.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ActivateStatus {
    pub schema: String,
    pub current_system: Option<String>,
    pub booted_system: Option<String>,
    /// Where the boot loader's default points. The helper knows this
    /// better than a `readlink` does once a `--mode boot` activation has
    /// set a one-shot entry.
    pub next_boot_system: Option<String>,
    pub generation: Option<u64>,
    pub kernel_running: Option<String>,
    pub kernel_booted: Option<BootedKernel>,
    /// At most one, by `meister-activate`'s own rule. Two is a state this
    /// tool has no rule for and [`crate::receipt::TxnView`] calls
    /// inconsistent.
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

/// Turn one host's answer into one host's observation.
///
/// Pure, and every failure to understand something is a null rather than an
/// error: a probe that answered half way is a half answer about a host that
/// is up, and throwing it away would turn a slow disk into an unreachable
/// machine. What IS an error — the host never answered — is decided by the
/// caller, which is the only one that knows whether the command ran.
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
                    // findmnt answered: this path IS a mount point. It
                    // answered nothing: the path is a directory on the root
                    // disk, and being ABSENT from `mounts` is how that is
                    // said — the planner reads exactly that (V19).
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

    // The booted kernel is a triple or it is nothing: a reboot class
    // decided from two of the three fields would be a reboot class decided
    // from a guess, and null is the answer the planner reads
    // conservatively.
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

    // A service identity is a key AND the certificate somebody signed for
    // it. A host with neither is `unenrolled`, which is a state and never a
    // failure — it is what a bootstrap is for.
    obs.enrolled = identity_is_complete(spec, &obs.credentials, &identity_certs);

    for line in &txn_lines {
        if let Ok(txn) = serde_json::from_str::<Txn>(line) {
            obs.open_txns.push(txn);
        }
    }
    if let Some(line) = &lock_line {
        obs.lock = serde_json::from_str::<Lock>(line).ok();
    }

    // The helper wins where it speaks: it wrote the transaction records and
    // it moved the profile, so its answer about either is the better one.
    // Where it says null, the shell probe's answer stands.
    if let Some(text) = &activate
        && let Ok(status) = ActivateStatus::from_json(text, "meister-activate status --json")
    {
        merge_activate(&mut obs, status);
    }

    // A probe whose first and last line are both there answered whole.
    // Anything else is an answer this tool will not plan on: the host is
    // reachable and what it said cannot be trusted to be complete, which is
    // precisely what `unknown_reason` means.
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
    // The records: the helper's list REPLACES what the files said, because
    // the helper is what keeps them and it can tell a half-written one from
    // a finished one.
    if !status.open_txns.is_empty() {
        obs.open_txns = status.open_txns;
    }
    if status.lock.is_some() {
        obs.lock = status.lock;
    }
}

/// How many guests the node says it runs, out of `agent vm ls -o json`.
///
/// `None` when the answer is not a list of objects: the socket was there and
/// something else came back, and "I could not tell" is not "none running".
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

/// Whether every identity this host's manifest names is there, key and
/// certificate both.
fn identity_is_complete(
    spec: &ProbeSpec,
    credentials: &BTreeMap<String, Option<String>>,
    certs: &[(String, bool)],
) -> bool {
    // A host whose manifest names no identity has nothing to be enrolled
    // with. It is not "not enrolled" — there is no certificate it is
    // missing — and a rollout of such a host is not waiting for one.
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

/// What one member says about its raft group.
///
/// `healthy` is this host's OWN member, from its own loopback endpoint —
/// which is the field the planner counts (D8), and it counts it once per
/// member because every member is probed. `members[].healthy` is only
/// `true` where a health answer said so; for a peer this host cannot ask,
/// the type's documented meaning of `false` is "unknown is not healthy",
/// and the peer's own observation carries the truth about it.
fn etcd_view(
    probe: &EtcdProbe,
    members_json: Option<&str>,
    health_json: Option<&str>,
    unit_state: Option<&str>,
) -> Option<EtcdView> {
    // A member whose unit is not running is a member that is down, and that
    // is a view rather than an absence: `None` here would be read as "this
    // host is not an etcd member at all".
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

/// `etcdctl member list -w json`: `{"members":[{"ID":…,"name":…,"peerURLs":[…]}]}`.
///
/// The ID is a 64-bit number in json and hex everywhere a person sees it
/// (`etcdctl` prints hex, the type holds hex), so it is converted once here.
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
                // A member that has not started yet has no name. It is still
                // a member, and the topology check is about exactly that.
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

/// Who can ask a host something.
///
/// A trait rather than a function so that the fan-out below can be tested
/// without an ssh: the one implementation that matters is [`SshProber`], and
/// a test's implementation answers from a table and can be made to block,
/// which is how "a hanging host does not hold the others" becomes a
/// measurement.
///
/// `Sync`, because the hosts are asked in parallel.
pub trait Prober: Sync {
    /// The fingerprint the operator's `known_hosts` holds for this host, or
    /// `None` for a host nobody enrolled.
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

/// Ask one host, and turn every way of failing into an observation.
///
/// Three outcomes and all three are data:
///
/// * The fleet has no host key for it — nothing is even attempted, and the
///   sentence says to enrol it. This is where `keys enroll` is enforced on
///   the read path; `StrictHostKeyChecking=yes` would also refuse, with a
///   message about a broken host rather than about a step nobody ran.
/// * It did not answer: `reachable: false` and why.
/// * It answered: whatever it said, with `unknown_reason` when the answer
///   was not whole.
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
            // What IS known stays known: the fleet enrolled this key, and a
            // host that did not answer has not lost its identity.
            obs.identity.host_key_fingerprint = Some(fingerprint);
            obs
        }
    }
}

/// Ask a whole fleet, in a bounded pool, and write down the moment.
///
/// `taken_at` is a value rather than a clock reading, like everywhere else
/// in this crate: a snapshot is a fact about a moment, and which moment is
/// the caller's to decide (and a test's to pin).
///
/// One host cannot hold the others: each `ask` carries its own deadline, and
/// the pool moves on to the next host as soon as a thread is free. The whole
/// call therefore takes as long as the slowest host in the worst wave, not
/// the sum of the fleet.
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
            Some("/run/meisterstack/agent.sock")
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
        // What the probe of a member of a three-member group looks like when
        // one member is down: the membership still has three entries — a
        // member that vanished would be a membership change and a different,
        // worse thing — and this host's own endpoint is healthy.
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
        // This host is `box`, which is not in that membership: the topology
        // check in the planner is what that is for, and the probe reports
        // what etcd said rather than repairing it.
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
        // And what it did say is still there, because it was said.
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
        // Nothing was invented about it.
        assert_eq!(obs.current_system, None);
        assert!(obs.units.is_empty());
        assert_eq!(obs.vms_running, None);
    }

    /// A prober that can be told to hold a host, and that counts how many
    /// hosts are being asked at the same moment.
    ///
    /// No sleeping: the blocking hosts wait on a condition variable until
    /// the expected number of them are in flight, so a SEQUENTIAL
    /// implementation of `observe_fleet` would sit on the timeout below and
    /// the test would say so. The timeout is the only real time in here.
    struct CountingProber {
        answers: BTreeMap<String, Result<String, String>>,
        /// How many probes must be in flight at once before any of them is
        /// allowed to finish.
        expected: usize,
        state: Mutex<Concurrency>,
        gate: std::sync::Condvar,
    }

    #[derive(Default)]
    struct Concurrency {
        in_flight: usize,
        max_in_flight: usize,
        /// Set once `expected` probes have met. Sticky, because the point
        /// is that they DID meet once; a later wave that finds the gate
        /// open has already been counted.
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
            // Two of the eight are gone, and their failure is the message a
            // real ssh deadline produces.
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
        // Two at a time, and each pair has to meet before it may finish:
        // two waves, and every host answered.
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
