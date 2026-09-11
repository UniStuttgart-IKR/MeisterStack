// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! The `User` kind and the certificates it is known by. Moved out
//! of `resources.rs` unchanged.

use super::*;

/// A person. The object is the authorization side of an identity: the
/// certificate says who somebody is, this says what they may do and whose
/// tenant they are in, and the two are kept apart so that a role change is an
/// edit rather than a re-issue.
#[derive(Clone, Debug, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UserSpec {
    pub tenant: String,
    #[serde(default)]
    pub role: crate::auth::Role,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub description: String,
}

/// One certificate this user has been issued.
///
/// A fingerprint and two dates — never the certificate, and above all never
/// the key. The point of recording them is that an operator can see how many
/// credentials are out there for a name and when they die, which is exactly
/// what a fingerprint answers and exactly what storing the PEM would add
/// nothing to.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct IssuedCertificate {
    /// `sha256:<hex>` over the DER.
    pub fingerprint: String,
    pub issued_at: DateTime<Utc>,
    pub not_after: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub serial: String,
    /// The CertificateSigningRequest this came out of, so the trail from a
    /// live credential back to the request and its approver is one hop.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub request: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct UserStatus {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub certificates: Vec<IssuedCertificate>,
}

impl UserStatus {
    /// Certificates that have not expired at `now`. What `user ls` counts,
    /// because an expired fingerprint is history rather than a credential.
    pub fn live(&self, now: DateTime<Utc>) -> impl Iterator<Item = &IssuedCertificate> {
        self.certificates.iter().filter(move |c| c.not_after > now)
    }
}

pub type User = Object<UserSpec, UserStatus>;

/// The only signer this control plane has. Named anyway, exactly as K8s names
/// its own: a CSR that asks for a signer nobody runs must be refused rather
/// than quietly signed by whoever happens to be listening.
pub const SIGNER_USER_CLIENT: &str = "meister.io/user-client";

// --- server-owned counters ---------------------------------------------------
