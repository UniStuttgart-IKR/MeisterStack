// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Tenant secret values, sealed before storage in etcd.

use super::*;

/// Mutable tenant secret whose values are encrypted before storage. Writes accept data; API
/// reads expose only key names. metadata.generation lets consumers detect updated values
/// without changing the resource name.
#[derive(Clone, Debug, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SecretSpec {
    /// Whose it is. Server-filled from the caller for the same reason a
    /// volume's is.
    #[serde(default)]
    pub tenant: String,
    /// Stored values are base64(nonce || ciphertext || tag), bound to secrets/name/key through
    /// authenticated additional data. Write handlers seal plaintext; read handlers clear this
    /// map and fill keys. An empty map is omitted from serialization.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub data: BTreeMap<String, String>,
    /// Key names exposed by read projections; plaintext and ciphertext values are omitted.
    #[serde(default, skip_deserializing, skip_serializing_if = "Vec::is_empty")]
    pub keys: Vec<String>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub description: String,
}

pub type Secret = Object<SecretSpec, ()>;

impl Secret {
    /// Return the read projection with only the secret's key names and metadata.
    #[must_use]
    pub fn redacted(mut self) -> Self {
        self.spec.keys = self.spec.data.keys().cloned().collect();
        self.spec.data.clear();
        self
    }
}
