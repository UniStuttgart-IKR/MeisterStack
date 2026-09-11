// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! The K8s-style object envelope: apiVersion/kind/metadata around a
//! spec/status pair. `resourceVersion` is the etcd mod_revision and the only
//! concurrency control (compare-and-swap on update).

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
    /// How often a CLIENT has changed this object's spec. `1` when it is
    /// created, `+1` on every API write that leaves a different spec behind.
    ///
    /// Kubernetes' field with Kubernetes' meaning, and it is here to make one
    /// specific lie impossible: a `PUT` on a running VM used to change
    /// `spec.vm`, answer 200 and do nothing at all, because a node takes a
    /// spec once — when it creates the instance. Nothing in the API said so.
    /// Paired with `observedGeneration` in a status, this is what says it:
    /// `observedGeneration < generation` means exactly "the spec was changed
    /// after the controller last acted on it".
    ///
    /// Three things deliberately do NOT count. A write that leaves the spec
    /// as it was — a label, an annotation, a patch that says nothing new —
    /// is not a change of intent. A controller's own write is not a CLIENT's
    /// intent: the scheduler's binding puts a `nodeName` in the spec, and a
    /// generation that counted it would tick on every placement and never
    /// mean anything again. And `resourceVersion` is not this: that counts
    /// every write of any kind and is the compare-and-swap; this counts the
    /// ones a controller has to do something about.
    ///
    /// `0` is what an object written before this field existed carries. Its
    /// `observedGeneration` is `0` too, so the pair reads "in sync", which is
    /// true — and the first spec change makes it `1`.
    #[serde(default)]
    pub generation: u64,
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

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
// `deny_unknown_fields` at the ENVELOPE, and it is the same rule the spec
// types already carry, one layer out. Without it a key nobody claims falls
// away silently: `{"metdata": {"name": "web-1"}, …}` used to come back as
// "metadata.name must be set" — a true sentence about the wrong thing, and
// the client is left believing the server read a name it never saw. The
// generic type is the right place for it, because this is one statement about
// the envelope every resource wears and not a special case for one kind.
#[serde(rename_all = "camelCase", deny_unknown_fields)]
// `status` is `#[serde(default)]`, so the schema wants to name that default —
// which needs the bound serde never had to state.
#[schemars(bound = "S: JsonSchema, St: JsonSchema + Default + Serialize")]
pub struct Object<S, St> {
    pub api_version: String,
    pub kind: String,
    pub metadata: Metadata,
    pub spec: S,
    /// Left out entirely when it serialises to nothing.
    ///
    /// A resource whose status type is `()` — `Secret` is the one today —
    /// used to answer every GET with `"status": null`. Honest ("this kind has
    /// no status") and still noise in a JSON API, and noise a client has to
    /// learn to ignore. The rule is generic on purpose: it is one statement
    /// about the envelope every resource wears, not a special case for one
    /// kind, and a status that says something (an all-default struct is still
    /// `{}`) is still there.
    #[serde(default, skip_serializing_if = "says_nothing")]
    pub status: St,
}

/// Does this status serialise to `null`?
///
/// Asked of the VALUE rather than of the type, because a `skip_serializing_if`
/// gets a value and Rust has no stable way to ask "is this `()`". `()` is the
/// one type in this tree that answers yes; an empty struct serialises to `{}`
/// and stays in the document, which is right — `{}` is a status that exists
/// and is empty, `null` is a status that was never a thing.
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

/// What a `?dryRun=All` answer wears, so that nobody can mistake it for a
/// thing that exists.
///
/// On the object rather than beside it, because the object is what travels: a
/// preview handed to a person, pasted into a file and fed back to `apply` has
/// to be recognisable at every one of those steps, and a field of the HTTP
/// response would survive none of them. The write path strips it — a client
/// that sends it back is sending a document it was given, not making a claim.
pub const ANNOTATION_DRY_RUN: &str = "meister.io/dry-run";

/// The `metadata.generation` of the CLOUD object a mirrored copy stands for.
///
/// On the copy rather than derived, because the two objects count different
/// things: the cluster's own generation counts writes made here, and this is
/// the version of the thing up there that this copy was made from. It is what
/// the cluster reports back in `ClusterStatus.secrets`, and therefore what
/// lets the cloud stop re-sending a secret that has not changed.
///
/// An annotation and not a field, by the rule annotations are for: it is
/// non-identifying, nothing selects on it, and it belongs to the ACT of
/// mirroring rather than to what a Secret is.
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
    /// What a name of this kind may look like. See [`NameShape`]; the DNS
    /// label is the answer for everything an operator names, and the two
    /// resources whose name is not a word an operator chose say so in the
    /// resource table.
    const NAME_SHAPE: NameShape = NameShape::DnsLabel;
}

/// What a name may hold.
///
/// A name goes to three places downstream and the DNS label is the
/// intersection of what all three survive — but those three places do not
/// all apply to every resource, and treating them as if they did made two
/// resources impossible to create at all:
///
/// * a `FloatingIp` is NAMED after its address, and no address has ever been
///   a DNS label. Every reservation was a 422.
/// * an `Image` is named after the file a node looks it up as, and a file
///   with an extension — `debian.raw`, which is every image anybody has —
///   could not be catalogued.
///
/// Neither of those names ever becomes a network interface, which is the one
/// downstream place that actually demands the label. So the rule stays where
/// it is earned and is widened by exactly one character where it is not.
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
