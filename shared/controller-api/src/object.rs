// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! The K8s-style object envelope: apiVersion/kind/metadata around a
//! spec/status pair. `resourceVersion` is the etcd mod_revision and the only
//! concurrency control (compare-and-swap on update).

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use macros::generated;
use serde::{Deserialize, Serialize, de::DeserializeOwned};

#[generated(model = ClaudeFable, version = "5")]
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Metadata {
    pub name: String,
    #[serde(default)]
    pub uid: String,
    /// etcd mod_revision as a string; empty on objects not yet stored.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub resource_version: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub labels: BTreeMap<String, String>,
    /// Non-identifying metadata, K8s' own distinction: labels are what a
    /// selector matches on, annotations are what something carries along.
    /// The trace context is the first of them and the reason the field
    /// exists — it belongs to the request, not to the VM.
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

#[generated(model = ClaudeFable, version = "5")]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Object<S, St> {
    pub api_version: String,
    pub kind: String,
    pub metadata: Metadata,
    pub spec: S,
    #[serde(default)]
    pub status: St,
}

#[generated(model = ClaudeFable, version = "5")]
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

/// The W3C trace context of the request that created this object.
///
/// It is on the object because nothing in this control plane is a call stack:
/// a POST writes and returns, and the reconciler that acts on the object
/// wakes up later, in another task, possibly after a restart. There is no
/// ambient context to inherit, so the context travels as data — exactly like
/// the spec does, and through the same store.
///
/// It says which REQUEST this object came from, and it stays what it was: the
/// provisioning chain from that request down to the backend spawn is one
/// trace, and the level-triggered work afterwards (requeues, drift commands
/// years later) is deliberately not part of it. A trace that grew for the
/// lifetime of a VM would be unreadable and would never end.
pub const ANNOTATION_TRACEPARENT: &str = "meister.io/traceparent";

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

/// What a resource is called: the directory it lives in under the registry
/// prefix, and the `kind` its envelope wears.
///
/// The two used to be a pair of loose constants per resource, and every store
/// call took the first of them as a `&str` parameter NEXT to the type it was
/// reading — so `store.get::<Node>(RESOURCE_VMS, name)` compiled and read a
/// Node out of the vms directory. Bound to the type, that sentence cannot be
/// written down: the name follows from what is being read.
pub trait Resource: StoredObject {
    /// The registry directory: `<prefix>/registry/<RESOURCE>/<name>`. Also the
    /// path segment the REST API serves it under, and the word the
    /// authorization rules name it by.
    const RESOURCE: &'static str;
    /// The `kind` of the envelope, as a client spells it in a body.
    const KIND: &'static str;
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
