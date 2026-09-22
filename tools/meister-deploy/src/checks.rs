// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! A check is a data object, not a line of output.
//!
//! One shape for every check in this tool — the readiness checks a rollout
//! runs, the `nix flake check` results a release records, the verification
//! suites of M4 — because they all end up in the same three places: a
//! release, a receipt, and a report somebody reads afterwards. A check that
//! only exists as a printed line cannot be any of those.
//!
//! The important part is [`Status`] having five values rather than two. "I
//! could not tell" and "I did not look" are not passes, and the difference
//! between them is the difference between a broken probe and a machine that
//! was never reachable. A tool that folds them into `fail` makes people
//! ignore failures; one that folds them into `pass` ships.

use serde::{Deserialize, Serialize};

/// What a check found. `pass` and `fail` are the easy two.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Pass,
    Fail,
    /// It ran and could not decide: the probe timed out, the answer did not
    /// parse, the host was unreachable. Never a pass.
    Unknown,
    /// It should have run and did not: the hardware is declared but the host
    /// is unreachable, the suite was cut short. Never a pass.
    Skipped,
    /// It does not apply here: a GPU suite on a host that declares no GPU.
    /// This is the ONLY non-pass that does not block, and it is why the
    /// distinction from `skipped` has to be made by whoever writes the check.
    NotApplicable,
}

impl Status {
    /// Whether a REQUIRED check with this status stops the run.
    pub fn blocks_when_required(self) -> bool {
        match self {
            Status::Pass | Status::NotApplicable => false,
            Status::Fail | Status::Unknown | Status::Skipped => true,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Status::Pass => "pass",
            Status::Fail => "fail",
            Status::Unknown => "unknown",
            Status::Skipped => "skipped",
            Status::NotApplicable => "not_applicable",
        }
    }
}

impl std::fmt::Display for Status {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.pad(self.as_str())
    }
}

/// What a check looked at: a host of the fleet, or a resource the fleet
/// manages (a VM, a volume, a cluster). Exactly one of the two.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Subject {
    pub host: Option<String>,
    pub resource: Option<String>,
}

impl Subject {
    pub fn host(id: impl Into<String>) -> Subject {
        Subject {
            host: Some(id.into()),
            resource: None,
        }
    }

    pub fn resource(id: impl Into<String>) -> Subject {
        Subject {
            host: None,
            resource: Some(id.into()),
        }
    }

    fn describe(&self) -> String {
        match (&self.host, &self.resource) {
            (Some(h), _) => h.clone(),
            (None, Some(r)) => r.clone(),
            (None, None) => "the fleet".to_string(),
        }
    }
}

/// Where a check's verdict came from. The kind is what keeps a report honest:
/// `mock` and `hardware` are both evidence, and only one of them is evidence
/// that a GPU worked.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceKind {
    Hardware,
    Vm,
    Mock,
    Log,
    Command,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Evidence {
    pub kind: EvidenceKind,
    /// Where to look: a command line, a log path, a VM id, a store path.
    #[serde(rename = "ref")]
    pub reference: String,
}

/// One check, its verdict, and enough around it to argue with the verdict.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CheckResult {
    /// Stable across runs, so two receipts can be compared: `units`,
    /// `session`, `mounts`, `config-box`.
    pub id: String,
    pub subject: Subject,
    /// Whether a non-pass stops the run. Set by the plan, not by the check.
    pub required: bool,
    pub status: Status,
    /// What was supposed to be true, in the check's own terms.
    pub expected: String,
    /// What was found. Empty when nothing was found — which is what
    /// `unknown` usually means.
    pub observed: String,
    /// One sentence for a human. Required even on a pass: a report of forty
    /// green lines is only useful if each line says what it proved.
    pub reason: String,
    pub duration_ms: u64,
    pub evidence: Vec<Evidence>,
    /// Which release this was checked against, and which configuration —
    /// null when the check is older than either.
    pub release_id: Option<String>,
    pub config_id: Option<String>,
}

/// The verdict over a set of checks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Acceptance {
    Accepted,
    Blocked { reasons: Vec<String> },
}

impl Acceptance {
    pub fn is_accepted(&self) -> bool {
        matches!(self, Acceptance::Accepted)
    }
}

/// Required checks decide. A required check that did not pass — including one
/// that could not tell and one that never ran — blocks, and the reason names
/// the check, its subject and what it expected, because "readiness failed" is
/// not something anybody can act on.
pub fn acceptance(results: &[CheckResult]) -> Acceptance {
    let reasons: Vec<String> = results
        .iter()
        .filter(|r| r.required && r.status.blocks_when_required())
        .map(|r| {
            format!(
                "{} on {} is {}: expected {}, found {}{}",
                r.id,
                r.subject.describe(),
                r.status,
                if r.expected.is_empty() {
                    "a pass"
                } else {
                    &r.expected
                },
                if r.observed.is_empty() {
                    "nothing"
                } else {
                    &r.observed
                },
                if r.reason.is_empty() {
                    String::new()
                } else {
                    format!(" ({})", r.reason)
                }
            )
        })
        .collect();
    if reasons.is_empty() {
        Acceptance::Accepted
    } else {
        Acceptance::Blocked { reasons }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn check(id: &str, required: bool, status: Status) -> CheckResult {
        CheckResult {
            id: id.to_string(),
            subject: Subject::host("box"),
            required,
            status,
            expected: "active".to_string(),
            observed: "inactive".to_string(),
            reason: "systemctl said so".to_string(),
            duration_ms: 12,
            evidence: vec![Evidence {
                kind: EvidenceKind::Command,
                reference: "ssh box systemctl is-active meister-agent".to_string(),
            }],
            release_id: None,
            config_id: None,
        }
    }

    #[test]
    fn a_pass_and_a_not_applicable_let_the_run_through() {
        let results = vec![
            check("units", true, Status::Pass),
            check("gpu", true, Status::NotApplicable),
        ];
        assert_eq!(acceptance(&results), Acceptance::Accepted);
    }

    #[test]
    fn a_required_unknown_blocks_just_like_a_failure() {
        for status in [Status::Fail, Status::Unknown, Status::Skipped] {
            let results = vec![check("session", true, status)];
            match acceptance(&results) {
                Acceptance::Blocked { reasons } => {
                    assert_eq!(reasons.len(), 1);
                    assert!(reasons[0].contains("session on box"), "{}", reasons[0]);
                    assert!(reasons[0].contains(status.as_str()), "{}", reasons[0]);
                }
                Acceptance::Accepted => panic!("{status} must not pass for a required check"),
            }
        }
    }

    #[test]
    fn an_optional_failure_is_recorded_and_does_not_block() {
        let results = vec![
            check("units", true, Status::Pass),
            check("observability", false, Status::Fail),
        ];
        assert_eq!(acceptance(&results), Acceptance::Accepted);
    }

    #[test]
    fn every_blocking_check_gets_its_own_sentence() {
        let results = vec![
            check("units", true, Status::Fail),
            check("mounts", true, Status::Unknown),
            check("session", true, Status::Pass),
        ];
        match acceptance(&results) {
            Acceptance::Blocked { reasons } => assert_eq!(reasons.len(), 2, "{reasons:?}"),
            Acceptance::Accepted => panic!("two required checks did not pass"),
        }
    }

    #[test]
    fn a_check_survives_a_round_trip_through_json() {
        let before = check("units", true, Status::Pass);
        let text = serde_json::to_string(&before).unwrap();
        let after: CheckResult = serde_json::from_str(&text).unwrap();
        assert_eq!(before, after);
        assert!(text.contains(r#""status":"pass""#), "{text}");
        assert!(text.contains(r#""kind":"command""#), "{text}");
        assert!(text.contains(r#""ref":"ssh box"#), "{text}");
    }

    #[test]
    fn not_applicable_keeps_its_underscore_spelling() {
        let text = serde_json::to_string(&Status::NotApplicable).unwrap();
        assert_eq!(text, r#""not_applicable""#);
    }

    #[test]
    fn a_field_nobody_declared_is_refused() {
        let text = r#"{"kind":"mock","ref":"x","note":"also"}"#;
        let err = serde_json::from_str::<Evidence>(text)
            .unwrap_err()
            .to_string();
        assert!(err.contains("unknown field `note`"), "{err}");
    }
}
