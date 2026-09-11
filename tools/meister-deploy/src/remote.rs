// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! What a node says about itself, in one round trip.
//!
//! `plan` and `check` want the same dozen facts, and asking for them one ssh
//! at a time turns twelve hosts into a hundred and fifty connections. So
//! there is ONE script, it prints `key=value` lines, and both verbs read the
//! same answer. It writes nothing and starts nothing — this is the read-only
//! half of the tool, and the lab is only ever read.
//!
//! The ssh options are the ones `deploy/push.sh` and `deploy/check.sh` use,
//! read from the same `deploy/env` variables, so that a shell that has
//! sourced that file and this binary agree about which key reaches which
//! fleet.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::Result;

use crate::fleet::{Node, Role};
use crate::run::{Cmd, Runner};

#[derive(Debug, Clone)]
pub struct Ssh {
    pub key: Option<String>,
    pub port: u16,
    /// `false` = throwaway VMs: don't pin host keys. The lab re-instantiates
    /// its twelve, so their host keys change under you, and `check.sh` has
    /// had `MEISTER_SSH_STRICT=no` for exactly that reason.
    pub strict: bool,
    pub connect_timeout: u32,
}

impl Default for Ssh {
    fn default() -> Self {
        Ssh {
            key: None,
            port: 22,
            strict: true,
            connect_timeout: 5,
        }
    }
}

impl Ssh {
    /// The same four variables `deploy/env` holds, so `. deploy/env` in front
    /// of this binary means what it means in front of the scripts.
    pub fn from_env() -> Ssh {
        let expand = |p: String| match p.strip_prefix("~/") {
            Some(rest) => match std::env::var("HOME") {
                Ok(home) => format!("{home}/{rest}"),
                Err(_) => p.clone(),
            },
            None => p,
        };
        Ssh {
            key: std::env::var("MEISTER_SSH_KEY").ok().map(expand),
            port: std::env::var("MEISTER_SSH_PORT")
                .ok()
                .and_then(|p| p.parse().ok())
                .unwrap_or(22),
            strict: std::env::var("MEISTER_SSH_STRICT").as_deref() != Ok("no"),
            connect_timeout: 5,
        }
    }

    pub fn opts(&self) -> Vec<String> {
        let mut out = Vec::new();
        if let Some(k) = &self.key {
            out.push("-i".into());
            out.push(k.clone());
        }
        out.push("-p".into());
        out.push(self.port.to_string());
        if self.strict {
            out.push("-o".into());
            out.push("StrictHostKeyChecking=accept-new".into());
        } else {
            out.push("-o".into());
            out.push("StrictHostKeyChecking=no".into());
            out.push("-o".into());
            out.push("UserKnownHostsFile=/dev/null".into());
        }
        out.push("-o".into());
        out.push(format!("ConnectTimeout={}", self.connect_timeout));
        // The banner of a host that is up but not ours is noise in every
        // parsed answer below.
        out.push("-o".into());
        out.push("LogLevel=ERROR".into());
        out
    }

    pub fn ask(&self, node: &Node, script: &str) -> Cmd {
        Cmd::read("ssh")
            .args(self.opts())
            .arg(format!("{}@{}", node.ssh_user, node.address))
            .arg(script)
    }

    pub fn tell(&self, node: &Node, what: &str, script: &str) -> Cmd {
        Cmd::change("ssh", what)
            .args(self.opts())
            .arg(format!("{}@{}", node.ssh_user, node.address))
            .arg(script)
    }

    /// rsync over this same ssh. `-e` takes ONE string, which is why the
    /// options are joined here and nowhere else.
    pub fn rsync(&self, what: &str, sources: &[String], dest: &str) -> Cmd {
        Cmd::change("rsync", what)
            .arg("-L")
            .arg("-e")
            .arg(format!("ssh {}", self.opts().join(" ")))
            .args(sources.to_vec())
            .arg(dest)
    }

    /// The same, for a handful of small files whose CONTENT is the question.
    ///
    /// Two options more, and each answers half of "did anything move?":
    ///
    /// * `-c` decides that by checksum instead of by size and mtime. On a
    ///   certificate it is the honest question — `keys init` writing the same
    ///   bytes again gives the file a new mtime and no new content — and on
    ///   files this size it costs nothing.
    /// * `-i` makes rsync say, one line per file, what it did. A file it
    ///   transferred is a line beginning `<` or `>`; a file it left alone
    ///   prints nothing at all.
    ///
    /// Not on [`Self::rsync`] itself, which carries the binaries: there the
    /// checksum is a read of every byte of a hundred megabytes to learn what
    /// the mtime already said.
    pub fn rsync_itemized(&self, what: &str, sources: &[String], dest: &str) -> Cmd {
        Cmd::change("rsync", what)
            .arg("-L")
            .arg("-i")
            .arg("-c")
            .arg("-e")
            .arg(format!("ssh {}", self.opts().join(" ")))
            .args(sources.to_vec())
            .arg(dest)
    }
}

/// Everything the probe below can say. Absent rather than empty: a node that
/// did not answer is not a node with no units.
#[derive(Debug, Clone, Default)]
pub struct Probe {
    pub reachable: bool,
    pub hostname: Option<String>,
    /// `/run/current-system`, which is what a deployed store path IS on a
    /// NixOS box. Compared against what the plan would build: that difference
    /// is the whole definition of drift.
    pub system: Option<String>,
    pub role: Option<String>,
    pub pki: BTreeSet<String>,
    pub units: BTreeMap<String, String>,
    pub kvm: bool,
    pub vms: usize,
    pub ram: Option<String>,
    pub etcd: Option<String>,
    pub disk: Option<String>,
    pub failure: Option<String>,
}

/// The units worth asking after on any node. Asking for all of them
/// everywhere costs nothing (`systemctl is-active` on an unknown unit says
/// `inactive`) and means one script rather than one per role.
const UNITS: &[&str] = &[
    "meister-cloud-controller",
    "meister-cluster-controller",
    "meister-agent",
    "etcd",
    "kanidm",
    "garage",
    "prometheus",
    "loki",
    "tempo",
    "grafana",
];

/// The files `keys push` lays down, under the fixed names the templates name.
pub const PKI_FILES: &[&str] = &[
    "ca.crt",
    "serving.crt",
    "serving.key",
    "identity.crt",
    "identity.key",
    "secrets.key",
];

/// One script, one round trip, and it writes nothing.
///
/// `set +e` throughout by construction: every line is allowed to fail, and a
/// missing tool is a missing line rather than a dead probe — these hosts run
/// four different role sets and a fifth image generation.
pub fn probe_script() -> String {
    let units = UNITS.join(" ");
    let pki = PKI_FILES.join(" ");
    format!(
        r#"echo "hostname=$(cat /proc/sys/kernel/hostname 2>/dev/null)"
echo "system=$(readlink /run/current-system 2>/dev/null)"
echo "role=$(cat /run/meister-role 2>/dev/null | tr '\n' ' ')"
for f in {pki}; do [ -f /opt/meisterstack/pki/$f ] && echo "pki=$f"; done
for u in {units}; do echo "unit=$u:$(systemctl is-active $u 2>/dev/null)"; done
[ -e /dev/kvm ] && echo "kvm=yes"
echo "vms=$(ps -C cloud-hypervisor --no-headers 2>/dev/null | wc -l)"
free -m 2>/dev/null | awk '/^Mem:/ {{print "ram="$3"/"$2" MiB"}}'
df -h --output=pcent / 2>/dev/null | tail -1 | tr -d ' %' | sed 's/^/disk=/'
if systemctl is-active etcd >/dev/null 2>&1; then
  echo "etcd=$(etcdctl endpoint health 2>&1 | head -1)"
fi
# The one thing a unit's own state cannot say: an agent whose session to its
# controller is failing is `active` and useless (the chaos run's D8). -b as
# well as --since, or a freshly rebooted node reports the failures it had
# while the controller was still coming up.
if journalctl -u meister-agent -b --since "-2 min" --no-pager 2>/dev/null \
   | grep -q "controller session failed"; then
  echo "failure=the agent's controller session is failing (journalctl -u meister-agent)"
fi
true"#
    )
}

pub fn probe(runner: &dyn Runner, ssh: &Ssh, node: &Node) -> Result<Probe> {
    let out = runner.run(&ssh.ask(node, &probe_script()))?;
    let mut p = Probe {
        reachable: out.ok(),
        ..Probe::default()
    };
    if !p.reachable {
        return Ok(p);
    }
    for line in out.stdout.lines() {
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let value = value.trim().to_string();
        match key {
            "hostname" if !value.is_empty() => p.hostname = Some(value),
            "system" if !value.is_empty() => p.system = Some(value),
            "role" if !value.is_empty() => p.role = Some(value),
            "pki" => {
                p.pki.insert(value);
            }
            "unit" => {
                if let Some((u, state)) = value.split_once(':') {
                    p.units.insert(u.to_string(), state.to_string());
                }
            }
            "kvm" => p.kvm = value == "yes",
            "vms" => p.vms = value.parse().unwrap_or(0),
            "ram" => p.ram = Some(value),
            "disk" => p.disk = Some(value),
            "etcd" => p.etcd = Some(value),
            "failure" => p.failure = Some(value),
            _ => {}
        }
    }
    Ok(p)
}

impl Probe {
    /// Which of this role's units are not running. Empty is healthy; the
    /// point of returning the names is that "unhealthy" without a name is a
    /// thing nobody can act on.
    pub fn stopped_units(&self, node: &Node) -> Vec<String> {
        let mut out = Vec::new();
        for role in &node.roles {
            match role {
                Role::Addons => {
                    for u in ["kanidm", "garage", "prometheus", "loki", "tempo", "grafana"] {
                        if self.units.get(u).map(String::as_str) != Some("active") {
                            out.push(u.to_string());
                        }
                    }
                }
                other => {
                    if let Some(u) = other.unit()
                        && self.units.get(u).map(String::as_str) != Some("active")
                    {
                        out.push(u.to_string());
                    }
                }
            }
        }
        out
    }

    /// The certificates this role needs, and which of them are missing. The
    /// names are what `deploy/push.sh pki` writes and what the baked
    /// templates point at — a node missing one is a node its cluster will
    /// never see again.
    pub fn missing_keys(&self, node: &Node) -> Vec<String> {
        let mut want: BTreeSet<&str> = BTreeSet::from(["ca.crt"]);
        for role in &node.roles {
            match role {
                Role::Cloud | Role::Cluster => {
                    want.extend(["serving.crt", "serving.key", "identity.crt", "identity.key"]);
                }
                Role::Agent => {
                    want.extend(["identity.crt", "identity.key"]);
                }
                // The six services terminate TLS with the same pair the
                // controllers do; they have no client identity of their own.
                Role::Addons => {
                    want.extend(["serving.crt", "serving.key"]);
                }
            }
        }
        want.into_iter()
            .filter(|f| !self.pki.contains(*f))
            .map(str::to_string)
            .collect()
    }

    /// Healthy enough to move on to the next replica of this group.
    pub fn healthy(&self, node: &Node) -> Result<(), String> {
        if !self.reachable {
            return Err("not reachable over ssh".to_string());
        }
        let stopped = self.stopped_units(node);
        if !stopped.is_empty() {
            return Err(format!("not active: {}", stopped.join(", ")));
        }
        if let Some(f) = &self.failure {
            return Err(f.clone());
        }
        // A controller replica is only as good as its etcd member: a node
        // whose unit is up and whose raft is not is exactly the shape that
        // takes a group down when the rollout moves to the next replica.
        if (node.has(Role::Cloud) || node.has(Role::Cluster))
            && let Some(etcd) = &self.etcd
            && !etcd.contains("is healthy")
        {
            return Err(format!("etcd: {etcd}"));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fleet::Plan;
    use crate::run::Fake;

    const PLAN: &str = r#"
[fleet]
name = "t"
[[node]]
name = "c1"
group = "g"
roles = ["cloud", "cluster"]
address = "10.0.0.1"
[[node]]
name = "a1"
group = "g"
address = "10.0.0.2"
"#;

    fn plan() -> Plan {
        Plan::parse(PLAN).unwrap()
    }

    #[test]
    fn the_ssh_options_are_the_ones_the_scripts_use() {
        let ssh = Ssh {
            key: Some("/home/silas/.ssh/id_ed25519".into()),
            strict: false,
            ..Ssh::default()
        };
        let line = ssh.ask(plan().node("a1").unwrap(), "hostname").line();
        assert!(line.contains("-i /home/silas/.ssh/id_ed25519"), "{line}");
        assert!(line.contains("StrictHostKeyChecking=no"), "{line}");
        assert!(line.contains("UserKnownHostsFile=/dev/null"), "{line}");
        assert!(line.contains("root@10.0.0.2"), "{line}");
    }

    #[test]
    fn a_probe_is_one_round_trip_and_reads_every_answer() {
        let fake = Fake::new().reply(
            "10.0.0.1",
            "hostname=c1\n\
             system=/nix/store/aaaa-nixos-system\n\
             role=cloud cluster \n\
             pki=ca.crt\npki=serving.crt\npki=serving.key\n\
             unit=meister-cloud-controller:active\n\
             unit=meister-cluster-controller:active\n\
             unit=etcd:active\n\
             kvm=yes\nvms=3\nram=900/2000 MiB\ndisk=41\n\
             etcd=127.0.0.1:2379 is healthy: successfully committed proposal\n",
        );
        let plan = plan();
        let node = plan.node("c1").unwrap();
        let p = probe(&fake, &Ssh::default(), node).unwrap();

        assert_eq!(fake.lines().len(), 1, "one ssh, not fifteen");
        assert_eq!(p.system.as_deref(), Some("/nix/store/aaaa-nixos-system"));
        assert_eq!(p.role.as_deref(), Some("cloud cluster"));
        assert_eq!(p.vms, 3);
        assert!(p.kvm);
        assert_eq!(p.stopped_units(node), Vec::<String>::new());
        // Two roles on one box, and the identity pair is still missing.
        assert_eq!(p.missing_keys(node), vec!["identity.crt", "identity.key"]);
        assert!(p.healthy(node).is_ok());
    }

    #[test]
    fn active_is_not_healthy_when_the_session_is_failing() {
        let fake = Fake::new().reply(
            "10.0.0.2",
            "hostname=a1\nunit=meister-agent:active\n\
             failure=the agent's controller session is failing (journalctl -u meister-agent)\n",
        );
        let plan = plan();
        let node = plan.node("a1").unwrap();
        let p = probe(&fake, &Ssh::default(), node).unwrap();
        assert_eq!(p.stopped_units(node), Vec::<String>::new());
        assert!(
            p.healthy(node).unwrap_err().contains("session is failing"),
            "the chaos run's D8: a unit being active is not the same as a node that works"
        );
    }

    #[test]
    fn a_controller_whose_etcd_is_unhealthy_stops_the_rollout() {
        let fake = Fake::new().reply(
            "10.0.0.1",
            "unit=meister-cloud-controller:active\nunit=meister-cluster-controller:active\n\
             etcd=context deadline exceeded\n",
        );
        let plan = plan();
        let node = plan.node("c1").unwrap();
        let p = probe(&fake, &Ssh::default(), node).unwrap();
        assert!(p.healthy(node).unwrap_err().contains("deadline"));
    }

    #[test]
    fn a_host_that_does_not_answer_is_not_a_host_with_no_units() {
        let fake = Fake::new().failing("10.0.0.2", "ssh: connect to host 10.0.0.2: timed out");
        let plan = plan();
        let node = plan.node("a1").unwrap();
        let p = probe(&fake, &Ssh::default(), node).unwrap();
        assert!(!p.reachable);
        assert!(p.units.is_empty());
        assert_eq!(p.healthy(node).unwrap_err(), "not reachable over ssh");
    }
}
