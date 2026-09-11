// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! The `CertificateSigningRequest` kind: how a client asks to be
//! known. Moved out of `resources.rs` unchanged.

use super::*;

/// A request for a client certificate. K8s' shape, because the flow is K8s'
/// flow: the client keeps its key and sends a CSR, somebody with the right to
/// approve says yes, and the signer turns the approved request into a
/// certificate the client then collects.
#[derive(Clone, Debug, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CsrSpec {
    /// The PKCS#10 request, PEM. A public key and a name; the private half
    /// never existed on this machine.
    pub request: String,
    /// Who the certificate is for. The signer writes THIS into the subject,
    /// not whatever the request said about itself.
    pub username: String,
    #[serde(default = "default_signer")]
    pub signer_name: String,
}

fn default_signer() -> String {
    SIGNER_USER_CLIENT.to_string()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub enum CsrConditionType {
    Approved,
    Denied,
    Failed,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct CsrCondition {
    #[serde(rename = "type")]
    pub kind: CsrConditionType,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub reason: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub message: String,
    pub last_update_time: DateTime<Utc>,
    /// The identity that set this condition. K8s does not record it on the
    /// object; here it is the whole audit trail there is, and a credential
    /// handed out by nobody in particular is worse than no record at all.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub by: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct CsrStatus {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub conditions: Vec<CsrCondition>,
    /// The signed certificate, PEM, once there is one. Public by nature —
    /// this is the half of the pair that is meant to be handed around.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub certificate: Option<String>,
}

impl CsrStatus {
    pub fn has(&self, kind: CsrConditionType) -> bool {
        self.conditions.iter().any(|c| c.kind == kind)
    }

    pub fn approved(&self) -> bool {
        self.has(CsrConditionType::Approved)
    }

    pub fn denied(&self) -> bool {
        self.has(CsrConditionType::Denied)
    }

    /// One word for `csr ls`, and the order matters: a denial outranks an
    /// approval that never produced anything, and a certificate outranks the
    /// approval that caused it.
    pub fn phase(&self) -> &'static str {
        if self.denied() {
            "Denied"
        } else if self.has(CsrConditionType::Failed) {
            "Failed"
        } else if self.certificate.is_some() {
            "Issued"
        } else if self.approved() {
            "Approved"
        } else {
            "Pending"
        }
    }

    /// Record a condition. Setting the same one twice is setting it, not
    /// appending: a request is approved once, and a list that grew every time
    /// somebody retried would turn the audit trail into noise.
    pub fn set(&mut self, condition: CsrCondition) {
        match self
            .conditions
            .iter_mut()
            .find(|c| c.kind == condition.kind)
        {
            Some(existing) => *existing = condition,
            None => self.conditions.push(condition),
        }
    }
}

pub type CertificateSigningRequest = Object<CsrSpec, CsrStatus>;
