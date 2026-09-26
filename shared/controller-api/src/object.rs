// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Resource envelopes with apiVersion, kind, metadata, spec and status.
//!
//! `resourceVersion` exposes etcd's modification revision for object CAS.
//! `generation` tracks accepted spec changes; `uid` identifies an incarnation
//! independently of the reusable object name.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize, de::DeserializeOwned};

#[derive(Clone, Debug, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Metadata {
    pub name: String,
    #[serde(default)]
    pub uid: String,
    /// etcd mod_revision as a string; empty on objects not yet stored.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub resource_version: String,
    /// Client spec revision: 1 on create, incremented by API writes that change
    /// the spec. Metadata-only and controller binding writes do not increment it.
    /// `observedGeneration` identifies the intent last acted on; resourceVersion
    /// changes for all persisted writes and serves CAS. Legacy objects default
    /// to generation 0 until their next client spec change.
    #[serde(default)]
    pub generation: u64,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub labels: BTreeMap<String, String>,
    /// Metadata carried with the object but not matched by selectors, including
    /// the originating request's trace context.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub annotations: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub creation_timestamp: Option<DateTime<Utc>>,
    /// Set by DELETE; the reconciler tears down, then removes the object.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deletion_timestamp: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub finalizers: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
// Reject unknown envelope fields so misspellings fail explicitly instead of
// being silently discarded before resource-specific validation.
#[serde(rename_all = "camelCase", deny_unknown_fields)]
// `status` is `#[serde(default)]`, so the schema wants to name that default —
// which needs the bound serde never had to state.
#[schemars(bound = "S: JsonSchema, St: JsonSchema + Default + Serialize")]
pub struct Object<S, St> {
    pub api_version: String,
    pub kind: String,
    pub metadata: Metadata,
    pub spec: S,
    /// Omit status when it serializes to null, as for Secret's unit status.
    /// Meaningful objects, including an empty status object, remain present.
    #[serde(default, skip_serializing_if = "says_nothing")]
    pub status: St,
}

/// Omit status only when its serialized value is null. Empty object status
/// remains present; unit status is omitted.
fn says_nothing<St: Serialize>(status: &St) -> bool {
    serde_json::to_value(status).is_ok_and(|v| v.is_null())
}

impl<S, St: Default> Object<S, St> {
    pub fn new(api_version: &str, kind: &str, name: &str, spec: S) -> Self {
        Self {
            api_version: api_version.to_string(),
            kind: kind.to_string(),
            metadata: Metadata {
                name: name.to_string(),
                uid: uuid::Uuid::new_v4().to_string(),
                creation_timestamp: Some(Utc::now()),
                ..Metadata::default()
            },
            spec,
            status: St::default(),
        }
    }
}

/// Originating request trace context, persisted for later reconciliation
/// and command dispatch across task/process boundaries.
pub const ANNOTATION_TRACEPARENT: &str = "meister.io/traceparent";

/// Mark preview objects so dry-run identity survives copying or saving the body.
/// Write paths remove this annotation from resubmitted objects.
pub const ANNOTATION_DRY_RUN: &str = "meister.io/dry-run";

/// Source cloud generation on a mirrored object. The cluster reports it
/// back so unchanged secrets need not be resent; the local object's
/// generation counts different writes.
pub const ANNOTATION_CLOUD_GENERATION: &str = "meister.io/cloud-generation";

impl Metadata {
    /// The trace context this object was created under, if it has one. Not
    /// parsed here — controller-api has no telemetry dependency, and the
    /// components that propagate it do.
    pub fn traceparent(&self) -> Option<&str> {
        self.annotations
            .get(ANNOTATION_TRACEPARENT)
            .map(String::as_str)
    }

    pub fn set_traceparent(&mut self, traceparent: &str) {
        self.annotations
            .insert(ANNOTATION_TRACEPARENT.to_string(), traceparent.to_string());
    }
}

impl<S, St> Object<S, St> {
    pub fn is_deleting(&self) -> bool {
        self.metadata.deletion_timestamp.is_some()
    }
}

/// Object bounds every store operation needs.
pub trait StoredObject: Serialize + DeserializeOwned + Clone + Send + Sync + 'static {
    fn metadata(&self) -> &Metadata;
    fn metadata_mut(&mut self) -> &mut Metadata;
}

/// Associate registry path and envelope kind with the stored Rust type,
/// preventing callers from choosing a different resource directory.
pub trait Resource: StoredObject {
    /// The registry directory: `<prefix>/registry/<RESOURCE>/<name>`. Also the
    /// path segment the REST API serves it under, and the word the
    /// authorization rules name it by.
    const RESOURCE: &'static str;
    /// The `kind` of the envelope, as a client spells it in a body.
    const KIND: &'static str;
    /// Resource name syntax. Operator-assigned names default to DNS labels;
    /// resources with derived names override it.
    const NAME_SHAPE: NameShape = NameShape::DnsLabel;

    /// Derive status from facts already present on the object before persistence.
    ///
    /// Called by the store after mutation and before serialization. Implementations
    /// must be total and perform no I/O; the supplied time is their only clock.
    /// Cross-resource observations must first be copied onto the object by their
    /// reconciler. The default leaves status unchanged.
    fn settle(&mut self, _now: DateTime<Utc>) {}
}

/// Resource-specific name syntax. DNS-label rules apply by default;
/// FloatingIp and Image names additionally allow dots for addresses and
/// filenames. All names remain bounded and exclude path traversal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NameShape {
    /// Lowercase alphanumerics and `-`, starting and ending alphanumeric.
    /// Kubernetes' own answer, and the default here for the same reason: it
    /// survives an etcd key, a file name and an interface name.
    DnsLabel,
    /// The same, plus `.` inside it — a file name with an extension, and an
    /// IPv4 address. Still one path segment, still no uppercase, no space,
    /// no non-ASCII, and still no `..` anywhere in it.
    Dotted,
}

impl<S, St> StoredObject for Object<S, St>
where
    S: Serialize + DeserializeOwned + Clone + Send + Sync + 'static,
    St: Serialize + DeserializeOwned + Default + Clone + Send + Sync + 'static,
{
    fn metadata(&self) -> &Metadata {
        &self.metadata
    }
    fn metadata_mut(&mut self) -> &mut Metadata {
        &mut self.metadata
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn object() -> Object<(), ()> {
        Object::new("meister.io/v1", "Vm", "web-1", ())
    }

    /// The trace context is an annotation, not a label: labels are what a
    /// selector matches on, and nobody will ever select VMs by which request
    /// created them.
    #[test]
    fn the_trace_context_round_trips_as_an_annotation() {
        let tp = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";
        let mut obj = object();
        assert_eq!(
            obj.metadata.traceparent(),
            None,
            "objects start without one"
        );
        obj.metadata.set_traceparent(tp);
        assert_eq!(obj.metadata.traceparent(), Some(tp));
        assert!(obj.metadata.labels.is_empty(), "it is not a label");

        let json = serde_json::to_value(&obj).unwrap();
        assert_eq!(json["metadata"]["annotations"][ANNOTATION_TRACEPARENT], tp);
        let back: Object<(), ()> = serde_json::from_value(json).unwrap();
        assert_eq!(back.metadata.traceparent(), Some(tp));
    }

    /// Objects written before annotations existed still load, and objects
    /// without one do not carry an empty map through etcd.
    #[test]
    fn an_object_without_annotations_neither_needs_nor_writes_them() {
        let without = r#"{"apiVersion":"meister.io/v1","kind":"Vm",
                          "metadata":{"name":"web-1"},"spec":null,"status":null}"#;
        let obj: Object<(), ()> = serde_json::from_str(without).expect("loads");
        assert_eq!(obj.metadata.traceparent(), None);
        let json = serde_json::to_value(&obj).unwrap();
        assert!(
            json["metadata"].get("annotations").is_none(),
            "not serialised when empty"
        );
    }

    /// Setting it twice is setting it, not appending: a VM has one origin.
    #[test]
    fn a_second_stamp_replaces_the_first() {
        let mut obj = object();
        obj.metadata
            .set_traceparent("00-11111111111111111111111111111111-2222222222222222-01");
        obj.metadata
            .set_traceparent("00-33333333333333333333333333333333-4444444444444444-01");
        assert_eq!(obj.metadata.annotations.len(), 1);
        assert!(obj.metadata.traceparent().unwrap().contains("3333"));
    }
}
