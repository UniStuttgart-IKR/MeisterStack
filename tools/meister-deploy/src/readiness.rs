// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Is this host what the fleet says it should be — as data, not as output.
//!
//! One pure function over one host: what the manifest declares, what the
//! snapshot found, and (when there is one) what the release says it should
//! run. Out come [`CheckResult`]s, which are the same objects a release
//! records, a receipt carries and a report prints. A check that only
//! existed as a printed line could be none of those.
//!
//! Three rules hold everywhere in here.
//!
//! **A host nobody could reach gets `unknown`, never `pass` and never
//! `fail`.** "It is broken" and "I could not look" are different answers,
//! and a required `unknown` blocks exactly like a required failure
//! ([`crate::checks::acceptance`]) — so nothing is lost by being honest, and
//! an operator can tell a down host from a broken one.
//!
//! **`required` comes from the inventory, with three exceptions.**
//! `checks.required` is the operator's list. `identity`, `enrolled` and
//! `system` are required whatever it says, and each for its own reason: a
//! machine whose host key is not the enrolled one is not the machine this
//! release is about; a host without a service identity is `unenrolled`,
//! which is a state and never "healthy"; and `check --release` asks whether
//! the fleet runs that release, so it cannot answer yes about a host that
//! does not. The three are marked in their `reason`.
//!
//! **Nothing here changes anything.** No test VM, no etcd key — the pre-v1
//! `deploy/check.sh` wrote one (`etcdctl put meister-check`) and that is
//! exactly the sort of write a read-only verb must not make. The one effect
//! that remains is honest and unavoidable: an ssh login leaves lines in the
//! target's journal. That is the probe's footprint, and it is not state.

use chrono::{DateTime, Utc};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::checks::{CheckResult, Evidence, EvidenceKind, Status, Subject};
use crate::manifest::{ResolvedFleet, ResolvedHost, SecretKind};
use crate::observation::{HostObservation, Observations};
use crate::observe::{is_certificate, session_unit, units_for_role};
use crate::release::ReleaseManifest;

pub const STATUS_SCHEMA: &str = "meister-deploy/status/1";

/// The ids that are required however the inventory is written. See the
/// module note.
pub const ALWAYS_REQUIRED: &[&str] = &["identity", "enrolled", "system"];

/// What `status --json` and `check --json` print: the snapshot they read and
/// the verdicts they drew from it, in one object that names its own schema.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct StatusReport {
    pub schema: String,
    /// The release these checks were made against, or null for a `status`
    /// that only had a manifest.
    pub release_id: Option<String>,
    pub manifest_id: String,
    pub generated_at: DateTime<Utc>,
    /// The snapshot, whole, so that a reader can see what the verdicts were
    /// drawn from — and hand it back to `plan --observation`.
    pub observation: Observations,
    pub checks: Vec<CheckResult>,
}

impl StatusReport {
    pub fn to_json(&self) -> anyhow::Result<Vec<u8>> {
        let mut bytes = serde_json::to_vec_pretty(self)
            .map_err(|e| anyhow::anyhow!("writing the status as json failed: {e}"))?;
        bytes.push(b'\n');
        Ok(bytes)
    }

    pub fn from_json(text: &str, origin: &str) -> anyhow::Result<StatusReport> {
        crate::manifest::parse_checked(text, origin, STATUS_SCHEMA)
    }
}

/// Every check for one host.
///
/// Pure: no command, no file, no clock. `duration_ms` is 0 for all of them
/// because none of them does anything — the time was spent in the probe, and
/// claiming a duration here would be claiming work.
pub fn readiness(
    id: &str,
    host: &ResolvedHost,
    obs: &HostObservation,
    release: Option<&ReleaseManifest>,
) -> Vec<CheckResult> {
    let ctx = Ctx {
        id,
        host,
        obs,
        release_id: release.map(|r| r.release_id.clone()),
        desired: release
            .and_then(|r| r.artifacts.get(id))
            .map(|a| a.toplevel.store_path.clone()),
    };

    let mut out = vec![ctx.identity(), ctx.enrolled(), ctx.units(), ctx.mounts()];
    out.extend(ctx.system());
    out.extend(ctx.session());
    out.extend(ctx.credentials());
    out.extend(ctx.etcd());
    out.extend(ctx.capabilities());
    out
}

/// Every check for every selected host, in host order.
pub fn readiness_of(
    fleet: &ResolvedFleet,
    selected: &[String],
    observation: &Observations,
    release: Option<&ReleaseManifest>,
) -> Vec<CheckResult> {
    let mut out = Vec::new();
    for id in selected {
        let Some(host) = fleet.hosts.get(id) else {
            continue;
        };
        let missing = HostObservation::unreachable(format!(
            "the snapshot {} holds nothing about {id}; it was not asked.",
            observation.taken_at.to_rfc3339()
        ));
        let obs = observation.host(id).unwrap_or(&missing);
        out.extend(readiness(id, host, obs, release));
    }
    out
}

/// What one host's checks are drawn from.
struct Ctx<'a> {
    id: &'a str,
    host: &'a ResolvedHost,
    obs: &'a HostObservation,
    release_id: Option<String>,
    /// The system this host should be running, when a release says.
    desired: Option<String>,
}

impl Ctx<'_> {
    fn result(
        &self,
        id: &str,
        status: Status,
        expected: impl Into<String>,
        observed: impl Into<String>,
        reason: impl Into<String>,
    ) -> CheckResult {
        let always = ALWAYS_REQUIRED.contains(&id);
        let reason = reason.into();
        CheckResult {
            id: id.to_string(),
            subject: Subject::host(self.id),
            required: always || self.host.checks.required.iter().any(|r| r == id),
            status,
            expected: expected.into(),
            observed: observed.into(),
            reason: if always {
                format!("{reason} (this check is required whatever the inventory says)")
            } else {
                reason
            },
            duration_ms: 0,
            evidence: vec![Evidence {
                kind: EvidenceKind::Command,
                reference: format!("meister-deploy status: the probe of {}", self.id),
            }],
            release_id: self.release_id.clone(),
            config_id: None,
        }
    }

    /// The answer for everything, when the host did not answer.
    fn unreachable(&self, id: &str, expected: impl Into<String>) -> CheckResult {
        self.result(
            id,
            Status::Unknown,
            expected,
            String::new(),
            self.obs
                .unknown_reason
                .clone()
                .unwrap_or_else(|| "the host did not answer".to_string()),
        )
    }

    fn identity(&self) -> CheckResult {
        let expected = format!(
            "the host key {} and a machine id",
            self.host
                .ssh
                .host_key_fingerprint
                .as_deref()
                .unwrap_or("(none enrolled)")
        );
        if !self.obs.reachable {
            return self.unreachable("identity", expected);
        }
        match (
            &self.host.ssh.host_key_fingerprint,
            &self.obs.identity.host_key_fingerprint,
            &self.obs.identity.machine_id,
        ) {
            (None, _, _) => self.result(
                "identity",
                Status::Fail,
                expected,
                self.obs
                    .identity
                    .host_key_fingerprint
                    .clone()
                    .unwrap_or_default(),
                format!(
                    "the fleet has no host key for {}. Read the fingerprint off its console \
                     and run `keys enroll {} --fingerprint SHA256:…`; until then nothing \
                     can tell this machine from another at the same address.",
                    self.id, self.id
                ),
            ),
            (Some(declared), Some(seen), _) if declared != seen => self.result(
                "identity",
                Status::Fail,
                expected,
                seen.clone(),
                format!(
                    "another machine answered for {}: the fleet enrolled {declared} and \
                     {seen} replied. Either it was reinstalled — then enroll it again with \
                     --replace --reason — or it is not the machine you think it is.",
                    self.id
                ),
            ),
            (Some(_), None, _) => self.unreachable("identity", "the host key the fleet enrolled"),
            (Some(declared), Some(_), machine_id) => self.result(
                "identity",
                Status::Pass,
                expected,
                format!(
                    "{declared}, machine id {}",
                    machine_id.as_deref().unwrap_or("(unknown)")
                ),
                match machine_id {
                    Some(_) => "the machine that answered is the enrolled one".to_string(),
                    // Not a failure: an appliance image may not expose one,
                    // and the host key is the stronger statement anyway.
                    None => "the host key matches; the machine id could not be read".to_string(),
                },
            ),
        }
    }

    fn enrolled(&self) -> CheckResult {
        let expected = "a service identity: the key and the certificate under pki.dir";
        if !self.obs.reachable {
            return self.unreachable("enrolled", expected);
        }
        if self.obs.enrolled {
            self.result(
                "enrolled",
                Status::Pass,
                expected,
                "key and certificate are there",
                "this host has an identity in this fleet",
            )
        } else {
            self.result(
                "enrolled",
                Status::Fail,
                expected,
                self.obs
                    .credentials
                    .iter()
                    .map(|(id, value)| format!("{id}={}", value.as_deref().unwrap_or("missing")))
                    .collect::<Vec<_>>()
                    .join(", "),
                format!(
                    "{} is installed and not enrolled, which is a state of its own and never \
                     healthy. `plan --kind bootstrap` is what delivers an identity.",
                    self.id
                ),
            )
        }
    }

    fn units(&self) -> CheckResult {
        let mut wanted: Vec<&str> = Vec::new();
        for role in &self.host.roles {
            wanted.extend(units_for_role(role));
        }
        if self.host.effective_settings.etcd.is_some() {
            wanted.push("etcd.service");
        }
        if self.host.effective_settings.observability.is_some() {
            wanted.push("alloy.service");
        }
        let expected = format!("active: {}", wanted.join(", "));
        if !self.obs.reachable {
            return self.unreachable("units", expected);
        }
        if wanted.is_empty() {
            return self.result(
                "units",
                Status::NotApplicable,
                expected,
                String::new(),
                format!("{} has no role that runs a unit", self.id),
            );
        }
        let mut bad: Vec<String> = Vec::new();
        let mut unknown: Vec<&str> = Vec::new();
        for unit in &wanted {
            match self.obs.units.get(*unit).map(String::as_str) {
                Some("active") => {}
                Some(state) => bad.push(format!("{unit}={state}")),
                // The probe asks about every unit of every role it was
                // told about, so a unit with no answer is a unit the probe
                // could not ask about — not one that is down.
                None => unknown.push(unit),
            }
        }
        let observed = self
            .obs
            .units
            .iter()
            .map(|(unit, state)| format!("{unit}={state}"))
            .collect::<Vec<_>>()
            .join(", ");
        if !bad.is_empty() {
            self.result(
                "units",
                Status::Fail,
                expected,
                observed,
                format!("not active: {}", bad.join(", ")),
            )
        } else if !unknown.is_empty() {
            self.result(
                "units",
                Status::Unknown,
                expected,
                observed,
                format!("nothing was said about {}", unknown.join(", ")),
            )
        } else {
            self.result(
                "units",
                Status::Pass,
                expected,
                observed,
                "every unit of this host's roles is active",
            )
        }
    }

    fn mounts(&self) -> CheckResult {
        let required: Vec<&str> = self
            .host
            .persistence
            .iter()
            .filter(|p| p.required)
            .map(|p| p.path.as_str())
            .collect();
        let expected = format!("mounted: {}", required.join(", "));
        if required.is_empty() {
            return self.result(
                "mounts",
                Status::NotApplicable,
                "nothing this host must have mounted",
                String::new(),
                format!("{} declares no required persistence", self.id),
            );
        }
        if !self.obs.reachable {
            return self.unreachable("mounts", expected);
        }
        let missing: Vec<&str> = required
            .iter()
            .filter(|path| !self.obs.is_mounted(path))
            .copied()
            .collect();
        let observed = self
            .obs
            .mounts
            .iter()
            .map(|m| format!("{} on {} ({})", m.device, m.path, m.fstype))
            .collect::<Vec<_>>()
            .join(", ");
        if missing.is_empty() {
            self.result(
                "mounts",
                Status::Pass,
                expected,
                observed,
                "every required path is its own mount point",
            )
        } else {
            self.result(
                "mounts",
                Status::Fail,
                expected,
                observed,
                format!(
                    "{} is not a mount point, so what is written there is on the root disk \
                     and there is no fallback to it: this is the case a required persistence \
                     entry exists to prevent.",
                    missing.join(", ")
                ),
            )
        }
    }

    /// Three facts, three checks: what runs, what the next boot will run,
    /// and what the running generation booted.
    fn system(&self) -> Vec<CheckResult> {
        let Some(desired) = &self.desired else {
            // Without a release there is no "should", and inventing one
            // would be inventing the answer.
            return vec![self.result(
                "system",
                Status::NotApplicable,
                "a release to compare against",
                self.obs.current_system.clone().unwrap_or_default(),
                "this was a status without a release, so nothing was compared".to_string(),
            )];
        };
        let expected = desired.clone();
        if !self.obs.reachable {
            return vec![
                self.unreachable("system", expected.clone()),
                self.unreachable("next-boot", expected.clone()),
                self.unreachable("booted", expected),
            ];
        }

        let current = match &self.obs.current_system {
            Some(current) if current == desired => self.result(
                "system",
                Status::Pass,
                expected.clone(),
                current.clone(),
                "this host runs the release",
            ),
            Some(current) => self.result(
                "system",
                Status::Fail,
                expected.clone(),
                current.clone(),
                "this host runs a different system than the release names",
            ),
            None => self.result(
                "system",
                Status::Unknown,
                expected.clone(),
                String::new(),
                "/run/current-system could not be read",
            ),
        };
        let next_boot = match &self.obs.next_boot_system {
            Some(next) if next == desired => self.result(
                "next-boot",
                Status::Pass,
                expected.clone(),
                next.clone(),
                "the next boot comes up on the release",
            ),
            Some(next) => self.result(
                "next-boot",
                Status::Fail,
                expected.clone(),
                next.clone(),
                "the next boot would come up on something else — a switch without a boot \
                 entry, or a rollback that was never finished",
            ),
            None => self.result(
                "next-boot",
                Status::Unknown,
                expected.clone(),
                String::new(),
                "the system profile could not be read",
            ),
        };
        let booted = match &self.obs.booted_system {
            Some(booted) if booted == desired => self.result(
                "booted",
                Status::Pass,
                expected,
                booted.clone(),
                "the running generation is the one the release names",
            ),
            Some(booted) => self.result(
                "booted",
                Status::Fail,
                expected,
                booted.clone(),
                "the machine booted a different generation than it runs: a reboot is \
                 pending, and until it happens the kernel and the initrd are the old ones",
            ),
            None => self.result(
                "booted",
                Status::Unknown,
                expected,
                String::new(),
                "/run/booted-system could not be read",
            ),
        };
        vec![current, next_boot, booted]
    }

    /// Whether the unit that carries a session upwards is up — and, for an
    /// agent, whether its own socket answered.
    ///
    /// The limit, and it is the honest one: this is a unit and a socket, not
    /// a session. A controller that accepts connections and rejects this
    /// node's certificate leaves both of these green. The positive proof
    /// that a node can do work is `verify --suite vm-lifecycle`, which is
    /// M4B; what is here is what a read-only probe can say.
    fn session(&self) -> Option<CheckResult> {
        let unit = session_unit(&self.host.roles)?;
        let is_agent = self.host.roles.iter().any(|r| r == "agent");
        let expected = if is_agent {
            format!("{unit} active and the node socket answering")
        } else {
            format!("{unit} active")
        };
        if !self.obs.reachable {
            return Some(self.unreachable("session", expected));
        }
        let state = self.obs.units.get(unit).map(String::as_str);
        if state != Some("active") {
            return Some(self.result(
                "session",
                match state {
                    Some(_) => Status::Fail,
                    None => Status::Unknown,
                },
                expected,
                format!("{unit}={}", state.unwrap_or("(nothing said)")),
                "the unit that carries this host's session upwards is not running",
            ));
        }
        if is_agent {
            return Some(match self.obs.vms_running {
                Some(n) => self.result(
                    "session",
                    Status::Pass,
                    expected,
                    format!("{unit}=active, {n} guest(s)"),
                    "the node's own socket answered, so the agent is serving its api",
                ),
                None => self.result(
                    "session",
                    Status::Unknown,
                    expected,
                    format!("{unit}=active, the socket said nothing"),
                    "the unit is active and the node socket did not answer, so whether the \
                     agent can do work is not known from here",
                ),
            });
        }
        Some(self.result(
            "session",
            Status::Pass,
            expected,
            format!("{unit}=active"),
            "the unit that carries this host's session upwards is running",
        ))
    }

    /// Every secret the manifest names is there — and a private key is not
    /// readable by anybody but its owner.
    fn credentials(&self) -> Option<CheckResult> {
        if self.host.secret_refs.is_empty() {
            return None;
        }
        let expected = format!(
            "present: {}",
            self.host
                .secret_refs
                .iter()
                .map(|s| s.id.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        );
        if !self.obs.reachable {
            return Some(self.unreachable("credentials", expected));
        }
        let mut missing: Vec<&str> = Vec::new();
        let mut loose: Vec<String> = Vec::new();
        let mut unknown: Vec<&str> = Vec::new();
        for secret in &self.host.secret_refs {
            match self.obs.credentials.get(&secret.id) {
                None => unknown.push(&secret.id),
                Some(None) => missing.push(&secret.id),
                Some(Some(value)) => {
                    // A private key whose group or others can read it is a
                    // key every loader in this codebase refuses (M0 probe
                    // S11), so the unit that needs it would not start.
                    if !is_certificate(&secret.target_path)
                        && let Some(mode) = mode_of(value)
                        && mode & 0o077 != 0
                    {
                        loose.push(format!("{} is {mode:04o}", secret.id));
                    }
                }
            }
        }
        let observed = self
            .obs
            .credentials
            .iter()
            .map(|(id, value)| format!("{id}={}", value.as_deref().unwrap_or("missing")))
            .collect::<Vec<_>>()
            .join(", ");
        Some(if !missing.is_empty() {
            self.result(
                "credentials",
                Status::Fail,
                expected,
                observed,
                format!("not on the host: {}", missing.join(", ")),
            )
        } else if !loose.is_empty() {
            self.result(
                "credentials",
                Status::Fail,
                expected,
                observed,
                format!(
                    "{} — a private key whose group or others can read it is refused by \
                     every loader in this codebase, so the unit that needs it will not \
                     start. The mode is 0600, and the way to get there is `keys deliver`, \
                     not a chmod that loosens a loader.",
                    loose.join(", ")
                ),
            )
        } else if !unknown.is_empty() {
            self.result(
                "credentials",
                Status::Unknown,
                expected,
                observed,
                format!("nothing was said about {}", unknown.join(", ")),
            )
        } else {
            self.result(
                "credentials",
                Status::Pass,
                expected,
                observed,
                "every secret the manifest names is on the host, and every key is 0600",
            )
        })
    }

    /// This host's own etcd member, from its own endpoint.
    fn etcd(&self) -> Option<CheckResult> {
        // A host whose fleet renders no etcd settings is not a member, and
        // a check about a group it is not in would be a check about nothing.
        self.host.effective_settings.etcd.as_ref()?;
        let expected = "this host's own etcd member is healthy";
        if !self.obs.reachable {
            return Some(self.unreachable("etcd", expected));
        }
        Some(match &self.obs.etcd {
            Some(view) if view.healthy => self.result(
                "etcd",
                Status::Pass,
                expected,
                format!(
                    "member {} of {}",
                    view.member_id.as_deref().unwrap_or("(unnamed)"),
                    view.members.len()
                ),
                "the member on this host answered that it is healthy",
            ),
            Some(view) => self.result(
                "etcd",
                Status::Fail,
                expected,
                format!(
                    "member {}, {} member(s) in its view",
                    view.member_id.as_deref().unwrap_or("(unnamed)"),
                    view.members.len()
                ),
                "this host is a member of a raft group and its own endpoint is not healthy; \
                 a controller whose unit is up and whose raft is not is what takes a group \
                 down when a rollout moves to the next replica",
            ),
            None => self.result(
                "etcd",
                Status::Unknown,
                expected,
                String::new(),
                "the fleet renders etcd for this host and the probe got no answer from it",
            ),
        })
    }

    /// Every capability the inventory declares was found.
    fn capabilities(&self) -> Option<CheckResult> {
        let declared = &self.host.hardware.capabilities;
        if declared.is_empty() {
            return None;
        }
        let expected = format!("found: {}", declared.join(", "));
        if !self.obs.reachable {
            return Some(self.unreachable("capabilities", expected));
        }
        let missing: Vec<&str> = declared
            .iter()
            .filter(|cap| !self.obs.has_capability(cap))
            .map(|s| s.as_str())
            .collect();
        Some(if missing.is_empty() {
            self.result(
                "capabilities",
                Status::Pass,
                expected,
                self.obs.capabilities.join(", "),
                "every capability the inventory declares is on the host",
            )
        } else {
            self.result(
                "capabilities",
                Status::Fail,
                expected,
                self.obs.capabilities.join(", "),
                format!(
                    "declared and not found: {}. A capability a verification suite assumes \
                     and a host does not have is a suite that would pass on a machine that \
                     cannot do the work.",
                    missing.join(", ")
                ),
            )
        })
    }
}

/// The octal mode out of what the probe said about a credential file:
/// `mode:600 owner:meister:meister`.
fn mode_of(value: &str) -> Option<u32> {
    let rest = value.strip_prefix("mode:")?;
    let digits = rest.split_whitespace().next()?;
    u32::from_str_radix(digits, 8).ok()
}

/// Which secret ids a host is supposed to have, for a caller that wants to
/// name them without walking the manifest.
pub fn secret_ids(host: &ResolvedHost) -> Vec<&str> {
    host.secret_refs.iter().map(|s| s.id.as_str()).collect()
}

/// Whether this host's manifest names an identity at all — the difference
/// between "not enrolled" and "nothing to be enrolled with".
pub fn declares_identity(host: &ResolvedHost) -> bool {
    host.secret_refs
        .iter()
        .any(|s| s.kind == SecretKind::IdentityKey)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checks::{Acceptance, acceptance};
    use crate::fixtures::{at, observed, onebox_enrolled, release_of};
    use crate::observation::Mount;

    fn fleet_and_release() -> (ResolvedFleet, ReleaseManifest) {
        let fleet = onebox_enrolled();
        let release = release_of(fleet.clone());
        (fleet, release)
    }

    fn checks_of(
        fleet: &ResolvedFleet,
        release: &ReleaseManifest,
        observation: &Observations,
        id: &str,
    ) -> Vec<CheckResult> {
        readiness(id, &fleet.hosts[id], &observation.hosts[id], Some(release))
    }

    fn by_id<'a>(checks: &'a [CheckResult], id: &str) -> &'a CheckResult {
        checks
            .iter()
            .find(|c| c.id == id)
            .unwrap_or_else(|| panic!("there is no check {id} in {:?}", ids(checks)))
    }

    fn ids(checks: &[CheckResult]) -> Vec<&str> {
        checks.iter().map(|c| c.id.as_str()).collect()
    }

    #[test]
    fn a_healthy_host_passes_every_check_and_says_what_each_one_proved() {
        let (fleet, release) = fleet_and_release();
        let observation = observed(&release, at("2026-09-21T12:00:00Z"));
        let checks = checks_of(&fleet, &release, &observation, "box");
        for check in &checks {
            assert!(
                matches!(check.status, Status::Pass | Status::NotApplicable),
                "{}: {} ({})",
                check.id,
                check.status,
                check.reason
            );
            assert!(!check.reason.is_empty(), "{} has no reason", check.id);
            assert_eq!(
                check.release_id.as_deref(),
                Some(release.release_id.as_str())
            );
        }
        assert_eq!(acceptance(&checks), Acceptance::Accepted);
        // The three system facts are three checks.
        assert!(ids(&checks).contains(&"system"));
        assert!(ids(&checks).contains(&"next-boot"));
        assert!(ids(&checks).contains(&"booted"));
        // And box is a raft member of one, with credentials and a capability.
        assert_eq!(by_id(&checks, "etcd").status, Status::Pass);
        assert_eq!(by_id(&checks, "credentials").status, Status::Pass);
        assert_eq!(by_id(&checks, "capabilities").status, Status::Pass);
        assert_eq!(by_id(&checks, "session").status, Status::Pass);
    }

    #[test]
    fn the_inventorys_required_list_decides_and_three_ids_decide_themselves() {
        let (fleet, release) = fleet_and_release();
        let observation = observed(&release, at("2026-09-21T12:00:00Z"));
        let checks = checks_of(&fleet, &release, &observation, "box");
        // The fixture's list.
        for id in ["units", "session", "mounts"] {
            assert!(by_id(&checks, id).required, "{id} is in checks.required");
        }
        for id in ALWAYS_REQUIRED {
            assert!(
                by_id(&checks, id).required,
                "{id} is required by construction"
            );
            assert!(
                by_id(&checks, id)
                    .reason
                    .contains("required whatever the inventory says"),
                "{id} says why"
            );
        }
        // And something the inventory did not ask for is recorded, not
        // required.
        assert!(!by_id(&checks, "etcd").required);
        assert!(!by_id(&checks, "capabilities").required);
    }

    #[test]
    fn a_host_that_did_not_answer_is_unknown_everywhere_and_never_a_pass() {
        let (fleet, release) = fleet_and_release();
        let mut observation = observed(&release, at("2026-09-21T12:00:00Z"));
        *observation.hosts.get_mut("box").unwrap() =
            HostObservation::unreachable("ssh did not finish within 60s");
        let checks = checks_of(&fleet, &release, &observation, "box");
        for check in &checks {
            assert!(
                matches!(check.status, Status::Unknown | Status::NotApplicable),
                "{} is {}",
                check.id,
                check.status
            );
            assert_ne!(check.status, Status::Pass);
        }
        // A required unknown blocks, which is the point of not calling it a
        // failure and not calling it a pass.
        match acceptance(&checks) {
            Acceptance::Blocked { reasons } => {
                assert!(
                    reasons.iter().any(|r| r.contains("did not finish")),
                    "{reasons:?}"
                );
            }
            Acceptance::Accepted => panic!("an unreachable host is not accepted"),
        }
    }

    #[test]
    fn another_machine_at_the_address_fails_the_identity_check() {
        let (fleet, release) = fleet_and_release();
        let mut observation = observed(&release, at("2026-09-21T12:00:00Z"));
        observation
            .hosts
            .get_mut("box")
            .unwrap()
            .identity
            .host_key_fingerprint = Some("SHA256:somebody-else".to_string());
        let checks = checks_of(&fleet, &release, &observation, "box");
        let identity = by_id(&checks, "identity");
        assert_eq!(identity.status, Status::Fail);
        assert!(identity.required);
        assert!(
            identity.reason.contains("another machine answered"),
            "{}",
            identity.reason
        );
        assert!(
            identity.reason.contains("--replace --reason"),
            "{}",
            identity.reason
        );
    }

    #[test]
    fn a_host_without_a_service_identity_is_never_healthy() {
        let (fleet, release) = fleet_and_release();
        let mut observation = observed(&release, at("2026-09-21T12:00:00Z"));
        let obs = observation.hosts.get_mut("box").unwrap();
        obs.enrolled = false;
        obs.credentials.insert("identity".to_string(), None);
        let checks = checks_of(&fleet, &release, &observation, "box");
        assert_eq!(by_id(&checks, "enrolled").status, Status::Fail);
        assert!(by_id(&checks, "enrolled").required);
        assert!(
            by_id(&checks, "enrolled").reason.contains("never\nhealthy")
                || by_id(&checks, "enrolled").reason.contains("never healthy"),
            "{}",
            by_id(&checks, "enrolled").reason
        );
        assert_eq!(by_id(&checks, "credentials").status, Status::Fail);
        assert!(matches!(acceptance(&checks), Acceptance::Blocked { .. }));
    }

    #[test]
    fn a_key_the_group_can_read_is_a_key_no_loader_takes() {
        let (fleet, release) = fleet_and_release();
        let mut observation = observed(&release, at("2026-09-21T12:00:00Z"));
        // What `LoadCredential` produces, and what M0's probe S11 measured:
        // root:root 0440. Every loader in this codebase refuses it.
        observation
            .hosts
            .get_mut("box")
            .unwrap()
            .credentials
            .insert(
                "identity".to_string(),
                Some("mode:440 owner:root:root".to_string()),
            );
        let checks = checks_of(&fleet, &release, &observation, "box");
        let credentials = by_id(&checks, "credentials");
        assert_eq!(credentials.status, Status::Fail);
        assert!(
            credentials.reason.contains("0440"),
            "{}",
            credentials.reason
        );
        assert!(
            credentials
                .reason
                .contains("not a chmod that loosens a loader"),
            "{}",
            credentials.reason
        );
        // A certificate's digest is not a mode and is not judged as one.
        assert_eq!(
            mode_of("sha256:abc123"),
            None,
            "a digest is not a file mode"
        );
        assert_eq!(mode_of("mode:600 owner:meister:meister"), Some(0o600));
    }

    #[test]
    fn a_required_path_that_is_not_a_mount_point_has_no_fallback() {
        let (fleet, release) = fleet_and_release();
        let mut observation = observed(&release, at("2026-09-21T12:00:00Z"));
        observation.hosts.get_mut("box").unwrap().mounts = vec![Mount {
            path: "/var/lib/meister-data".to_string(),
            device: "/dev/disk/by-label/meister-data".to_string(),
            fstype: "ext4".to_string(),
        }];
        let checks = checks_of(&fleet, &release, &observation, "box");
        let mounts = by_id(&checks, "mounts");
        assert_eq!(mounts.status, Status::Fail);
        assert!(mounts.reason.contains("/var/lib/etcd"), "{}", mounts.reason);
        assert!(mounts.reason.contains("no fallback"), "{}", mounts.reason);
    }

    #[test]
    fn the_three_system_facts_are_reported_apart() {
        let (fleet, release) = fleet_and_release();
        let mut observation = observed(&release, at("2026-09-21T12:00:00Z"));
        let obs = observation.hosts.get_mut("box").unwrap();
        // Switched to the release and not rebooted into it: what runs is
        // right, what booted is not, and a reader has to be able to see
        // both.
        obs.booted_system = Some("/nix/store/previous-nixos-system-box-25.11".to_string());
        let checks = checks_of(&fleet, &release, &observation, "box");
        assert_eq!(by_id(&checks, "system").status, Status::Pass);
        assert_eq!(by_id(&checks, "next-boot").status, Status::Pass);
        assert_eq!(by_id(&checks, "booted").status, Status::Fail);
        assert!(
            by_id(&checks, "booted")
                .reason
                .contains("reboot is \npending")
                || by_id(&checks, "booted")
                    .reason
                    .contains("reboot is pending"),
            "{}",
            by_id(&checks, "booted").reason
        );
        // `system` is required by construction, `booted` is not — a pending
        // reboot is a fact to report and not a reason to refuse a fleet.
        assert!(by_id(&checks, "system").required);
        assert!(!by_id(&checks, "booted").required);
    }

    #[test]
    fn a_status_without_a_release_compares_nothing_and_says_so() {
        let (fleet, release) = fleet_and_release();
        let observation = observed(&release, at("2026-09-21T12:00:00Z"));
        let checks = readiness("box", &fleet.hosts["box"], &observation.hosts["box"], None);
        let system = by_id(&checks, "system");
        assert_eq!(system.status, Status::NotApplicable);
        assert!(
            system.reason.contains("without a release"),
            "{}",
            system.reason
        );
        assert!(ids(&checks).iter().all(|id| *id != "next-boot"));
        assert_eq!(system.release_id, None);
        // A `not_applicable` does not block, even though `system` is
        // required: there was nothing to compare against.
        assert_eq!(acceptance(&checks), Acceptance::Accepted);
    }

    #[test]
    fn an_agent_whose_socket_says_nothing_is_not_a_working_agent() {
        let (fleet, release) = fleet_and_release();
        let mut observation = observed(&release, at("2026-09-21T12:00:00Z"));
        observation.hosts.get_mut("n1").unwrap().vms_running = None;
        let checks = checks_of(&fleet, &release, &observation, "n1");
        let session = by_id(&checks, "session");
        assert_eq!(session.status, Status::Unknown);
        assert!(
            session.required,
            "session is in the fixture's required list"
        );
        assert!(
            session.reason.contains("did not answer"),
            "{}",
            session.reason
        );
        assert!(matches!(acceptance(&checks), Acceptance::Blocked { .. }));
    }

    #[test]
    fn a_dead_unit_is_a_failure_and_a_missing_answer_is_not() {
        let (fleet, release) = fleet_and_release();
        let mut observation = observed(&release, at("2026-09-21T12:00:00Z"));
        observation
            .hosts
            .get_mut("box")
            .unwrap()
            .units
            .insert("etcd.service".to_string(), "failed".to_string());
        let checks = checks_of(&fleet, &release, &observation, "box");
        assert_eq!(by_id(&checks, "units").status, Status::Fail);
        assert!(
            by_id(&checks, "units")
                .reason
                .contains("etcd.service=failed")
        );

        let mut observation = observed(&release, at("2026-09-21T12:00:00Z"));
        observation.hosts.get_mut("box").unwrap().units.clear();
        let checks = checks_of(&fleet, &release, &observation, "box");
        assert_eq!(
            by_id(&checks, "units").status,
            Status::Unknown,
            "nothing said is not the same as nothing running"
        );
    }

    #[test]
    fn a_member_whose_raft_is_gone_fails_even_with_a_live_unit() {
        let (fleet, release) = fleet_and_release();
        let mut observation = observed(&release, at("2026-09-21T12:00:00Z"));
        let obs = observation.hosts.get_mut("box").unwrap();
        obs.etcd.as_mut().unwrap().healthy = false;
        let checks = checks_of(&fleet, &release, &observation, "box");
        assert_eq!(by_id(&checks, "etcd").status, Status::Fail);
        assert_eq!(by_id(&checks, "units").status, Status::Pass);
        assert!(
            by_id(&checks, "etcd").reason.contains("takes a group down"),
            "{}",
            by_id(&checks, "etcd").reason
        );
    }

    #[test]
    fn a_host_the_snapshot_never_mentioned_is_unknown_and_not_absent() {
        let (fleet, release) = fleet_and_release();
        let mut observation = observed(&release, at("2026-09-21T12:00:00Z"));
        observation.hosts.remove("n2");
        let checks = readiness_of(
            &fleet,
            &["n1".to_string(), "n2".to_string()],
            &observation,
            Some(&release),
        );
        let n2: Vec<&CheckResult> = checks
            .iter()
            .filter(|c| c.subject.host.as_deref() == Some("n2"))
            .collect();
        assert!(!n2.is_empty(), "n2 is in the answer");
        assert!(n2.iter().all(|c| c.status != Status::Pass));
        assert!(
            n2.iter()
                .any(|c| c.reason.contains("holds nothing about n2")),
            "{:?}",
            n2.iter().map(|c| &c.reason).collect::<Vec<_>>()
        );
    }

    #[test]
    fn a_status_report_is_a_contract_object_that_reads_back() {
        let (fleet, release) = fleet_and_release();
        let observation = observed(&release, at("2026-09-21T12:00:00Z"));
        let report = StatusReport {
            schema: STATUS_SCHEMA.to_string(),
            release_id: Some(release.release_id.clone()),
            manifest_id: fleet.manifest_id.clone(),
            generated_at: at("2026-09-21T12:00:01Z"),
            observation: observation.clone(),
            checks: readiness_of(&fleet, &fleet.evaluated_hosts, &observation, Some(&release)),
        };
        let text = String::from_utf8(report.to_json().unwrap()).unwrap();
        let read = StatusReport::from_json(&text, "what this test wrote").unwrap();
        assert_eq!(read, report);
        // The snapshot travels whole, so a reader can hand it to `plan`.
        assert_eq!(read.observation, observation);
    }
}
