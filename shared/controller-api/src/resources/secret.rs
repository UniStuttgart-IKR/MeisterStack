// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! The `Secret` kind: a tenant's own bytes, sealed before they
//! reach etcd. Moved out of `resources.rs` unchanged.

use super::*;

/// A tenant's own bytes, by key, sealed before they reach the store.
///
/// The one resource of this control plane whose spec is WRITE-ONLY: `data`
/// goes in and never comes back out, and what a read answers with is `keys`.
/// That is not politeness, it is the whole difference between this and
/// `spec.vm.cloud_init.user_data` — a value that can be read back through the
/// API is a value every operator, every backup of an etcd snapshot and every
/// `GET` in a log has seen.
///
/// Nothing here is immutable. A password is a thing that gets rotated, and a
/// `Secret` that could only be deleted and recreated would be one whose name
/// every VM referring to it has to be edited for. `metadata.generation`
/// counts instead, which is what tells a consumer that what it read is stale.
#[derive(Clone, Debug, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SecretSpec {
    /// Whose it is. Server-filled from the caller for the same reason a
    /// volume's is.
    #[serde(default)]
    pub tenant: String,
    /// The sealed values, by key.
    ///
    /// CIPHERTEXT on a stored object — `base64(nonce || ciphertext || tag)`,
    /// one entry per key, each bound to `secrets/<name>/<key>` by the AAD.
    /// On the way IN it is the plaintext the client sent, for exactly as long
    /// as it takes the handler to seal it; on the way OUT it is emptied and
    /// `keys` is filled instead. See `redacted`.
    ///
    /// `skip_serializing_if` is what makes the redaction structural rather
    /// than something every handler has to remember: an emptied map is not in
    /// the document at all, so a handler that forgot to redact would answer
    /// with ciphertext at worst, and never with a value.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub data: BTreeMap<String, String>,
    /// Which keys this secret has. Derived, and the whole of what a read
    /// gets.
    ///
    /// Never deserialized: a client that sent it would be a client stating a
    /// fact about somebody else's `data`. Empty on a STORED object, which is
    /// why it is skipped there too — the store holds `data`, and `keys` is
    /// made out of it at the edge.
    #[serde(default, skip_deserializing, skip_serializing_if = "Vec::is_empty")]
    pub keys: Vec<String>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub description: String,
}

pub type Secret = Object<SecretSpec, ()>;

impl Secret {
    /// The object as a READ answers with it: no values, and the key names
    /// instead.
    ///
    /// Consuming, so that a handler cannot hold on to the unredacted one by
    /// accident. Every route that hands a `Secret` to a client goes through
    /// here, and the test at the bottom of the cloud's `api/secrets.rs`
    /// walks the routes to say so.
    #[must_use]
    pub fn redacted(mut self) -> Self {
        self.spec.keys = self.spec.data.keys().cloned().collect();
        self.spec.data.clear();
        self
    }
}
