// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! `CertificateSigningRequest`: the object, the one phase word, and the
//! verbs that approve or deny one.

use super::*;

#[derive(Deserialize)]
pub(super) struct Csr {
    metadata: Meta,
    spec: CsrSpec,
    #[serde(default)]
    status: CsrStatus,
}

#[derive(Deserialize)]
pub(super) struct CsrSpec {
    username: String,
}

#[derive(Deserialize, Default)]
pub(super) struct CsrStatus {
    #[serde(default)]
    conditions: Vec<CsrCondition>,
    #[serde(default)]
    certificate: Option<String>,
}

#[derive(Deserialize)]
pub(super) struct CsrCondition {
    #[serde(rename = "type")]
    kind: String,
    #[serde(default)]
    by: String,
}

/// The server decides this too, and the two have to agree — the table is
/// worthless if it says Pending about a request that has a certificate on it.
/// Same precedence as `CsrStatus::phase` in controller-api: a denial outranks
/// an approval that produced nothing, a certificate outranks its approval.
pub(super) fn csr_phase(status: &CsrStatus) -> &'static str {
    let has = |k: &str| status.conditions.iter().any(|c| c.kind == k);
    if has("Denied") {
        "Denied"
    } else if has("Failed") {
        "Failed"
    } else if status.certificate.is_some() {
        "Issued"
    } else if has("Approved") {
        "Approved"
    } else {
        "Pending"
    }
}

pub(super) fn csr_row(c: Csr) -> Vec<String> {
    let by = c
        .status
        .conditions
        .iter()
        .map(|cond| cond.by.clone())
        .find(|b| !b.is_empty())
        .unwrap_or_default();
    vec![
        c.metadata.name,
        c.spec.username,
        csr_phase(&c.status).to_string(),
        by,
    ]
}

pub async fn csr(ctx: &Ctx<'_>, cmd: &CsrCmd) -> Result<()> {
    // Deliberately still a PUT on a subresource and not a patch: approving is
    // its own verb in this API (`auth::Verb::Approve`), because it is the one
    // write that hands out a credential and must not be reachable through a
    // generic write.
    let (name, decision, said) = match cmd {
        CsrCmd::Approve { name } => (name, json!({ "approved": true }), "Approved"),
        CsrCmd::Deny { name, reason } => (
            name,
            json!({
                "approved": false,
                "reason": reason.clone().unwrap_or_else(|| "Denied".into()),
            }),
            "Denied",
        ),
        // See the note in `tenant`.
        CsrCmd::Read(_) | CsrCmd::Rm { .. } => unreachable!("dispatched generically"),
    };
    let path = format!(
        "{}/approval",
        ctx.path("certificatesigningrequests", Some(name))?
    );
    let body = ctx
        .client
        .put(&path, Some(serde_json::to_vec(&decision)?))
        .await?;
    output::emit_line(ctx.global, &body, said)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The two phase functions — this one and `CsrStatus::phase` in
    /// controller-api — have to agree, or the table says Pending about a
    /// request that has a certificate on it.
    #[test]
    fn a_request_has_one_phase_and_the_precedence_matches_the_servers() {
        let cond = |kind: &str| CsrCondition {
            kind: kind.into(),
            by: "ops".into(),
        };
        let mut status = CsrStatus::default();
        assert_eq!(csr_phase(&status), "Pending");
        status.conditions.push(cond("Approved"));
        assert_eq!(csr_phase(&status), "Approved");
        status.certificate = Some("pem".into());
        assert_eq!(csr_phase(&status), "Issued");
        status.conditions.push(cond("Denied"));
        assert_eq!(csr_phase(&status), "Denied");
    }
}
