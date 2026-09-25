// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Spec-only PUT, JSON merge patch and bounded conflict retries.

use super::*;

// --- the spec-only PUT ------------------------------------------------------

/// A PUT body for a resource whose STATUS belongs to a controller.
///
/// Deliberately not the resource's own `Object` type. What separates a client
/// that round-trips an object it just read from one that is trying to write
/// status is whether it SAID anything about status, and a typed `St` cannot
/// tell "absent" from "the default" — every field of a NodeStatus defaults,
/// so an omitted status deserialises into a perfectly good "not ready, no
/// capacity, no heartbeat" that would then be a write of exactly that.
// `deny_unknown_fields`, like every spec type it wraps: this is the body of a
// PUT, and a key the server does not know is a key a client believed in.
#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SpecUpdate<S> {
    pub api_version: String,
    pub kind: String,
    pub metadata: crate::object::Metadata,
    pub spec: S,
    /// What the client said about status, if it said anything. `None` is
    /// "did not mention it", which is the only shape that is not a write.
    #[serde(default)]
    pub status: Option<serde_json::Value>,
}

/// Apply writable spec and metadata fields while retaining server identity,
/// creation/deletion timestamps, finalizers and status. Status may be omitted
/// or echoed unchanged; an altered status is refused. The supplied resource
/// version remains the condition used by the store.
pub fn apply_spec_update<S, St>(
    body: SpecUpdate<S>,
    name: &str,
    current: Object<S, St>,
) -> std::result::Result<Object<S, St>, ApiError>
where
    Object<S, St>: Resource,
    S: serde::Serialize,
    St: serde::Serialize,
{
    let expected = <Object<S, St> as Resource>::KIND;
    if body.api_version != API_VERSION || body.kind != expected {
        return Err(invalid(format!(
            "expected apiVersion {API_VERSION}, kind {expected}"
        )));
    }
    if body.metadata.name != name {
        return Err(invalid("metadata.name does not match the path"));
    }
    if let Some(sent) = &body.status {
        let mut held = serde_json::to_value(&current.status).map_err(|e| {
            ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "Internal", e.to_string())
        })?;
        let mut sent = sent.clone();
        // `lastHeartbeat` is served, not stored (D-C7): a GET joins it in from
        // the lease, and what etcd still holds under that key is the instant
        // left there before the field moved out. So what a client read and
        // what the store has never agree, and neither is the client's to
        // send. Left in the comparison, every `node label` and every cordon
        // was a 422 — the regression S1 and S11 found the night the lease
        // shipped.
        for status in [&mut held, &mut sent] {
            if let Some(fields) = status.as_object_mut() {
                fields.remove("lastHeartbeat");
            }
        }
        if sent != held {
            return Err(invalid(format!(
                "status belongs to the controller; send this {expected} back with the status it \
                 was read with, or leave status out"
            )));
        }
    }
    let mut next = current.clone();
    next.spec = body.spec;
    // The client's half of metadata, and only that half.
    next.metadata.labels = body.metadata.labels;
    next.metadata.annotations = body.metadata.annotations;
    // What makes the write a compare-and-swap rather than a last-writer-wins.
    next.metadata.resource_version = body.metadata.resource_version;
    carry_generation(&current, &mut next)?;
    Ok(next)
}

// --- the merge patch --------------------------------------------------------

/// JSON Merge Patch, RFC 7386, and nothing else.
///
/// Object into object recursively, `null` deletes the key, everything else
/// replaces what was there — arrays included, whole. That last clause is the
/// format's one sharp edge and it is deliberate: there is no way to say
/// "append", so a patch that means to change one element of a list sends the
/// list. JSON Patch (RFC 6902) is the format that can, and it costs a client
/// a document nobody can read; Strategic Merge is the one Kubernetes grew
/// afterwards, and it costs a SERVER a merge key per field.
pub fn merge_patch(target: &mut serde_json::Value, patch: &serde_json::Value) {
    let serde_json::Value::Object(fields) = patch else {
        *target = patch.clone();
        return;
    };
    if !target.is_object() {
        *target = serde_json::Value::Object(serde_json::Map::new());
    }
    let map = target.as_object_mut().expect("just made one");
    for (key, value) in fields {
        if value.is_null() {
            map.remove(key);
            continue;
        }
        merge_patch(
            map.entry(key.clone()).or_insert(serde_json::Value::Null),
            value,
        );
    }
}

/// Merge a patch into the current object and deserialize the PUT body.
/// Reject status, validate any supplied kind and apiVersion, and preserve the
/// current resourceVersion unless the patch supplies a condition. Type errors
/// after merging are client validation errors. PUT admission runs afterwards.
pub fn apply_merge_patch<T, B>(
    current: &T,
    patch: &serde_json::Value,
) -> std::result::Result<B, ApiError>
where
    T: Resource,
    B: serde::de::DeserializeOwned,
{
    let Some(fields) = patch.as_object() else {
        return Err(invalid("a merge patch is a json object; see RFC 7386"));
    };
    let expected = T::KIND;
    if fields.contains_key("status") {
        return Err(invalid(format!(
            "status belongs to the controller; patch the spec of this {expected} and leave \
             status out"
        )));
    }
    for (field, want) in [("apiVersion", API_VERSION), ("kind", expected)] {
        if let Some(said) = fields.get(field)
            && said.as_str() != Some(want)
        {
            return Err(invalid(format!(
                "the patch names {field} {said}; this route serves apiVersion {API_VERSION}, \
                 kind {expected}"
            )));
        }
    }

    let mut document = serde_json::to_value(current)
        .map_err(|e| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "Internal", e.to_string()))?;
    merge_patch(&mut document, patch);
    serde_json::from_value(document).map_err(|e| {
        invalid(format!(
            "the patch leaves something that is no longer a {expected}: {e}"
        ))
    })
}

/// How many times an unconditional PATCH reads, merges and writes before it
/// gives the client the conflict.
///
/// Three, and the number is a budget rather than a guess: each pass costs one
/// read and one write, the writer being lost to is the heartbeat and it
/// touches an object every three seconds, and a client that has already
/// failed twice in the microseconds between a read and a write is looking at
/// something other than a race. An unbounded retry would be a handler that
/// never returns while a hot object stays hot.
pub const PATCH_ATTEMPTS: u32 = 3;

/// Did the client state the version it means to patch against?
///
/// `null` counts as not stating one: in a merge patch `null` REMOVES a key,
/// so a body that says `"resourceVersion": null` has asked for the version to
/// be dropped, which is the unconditional case spelled out loud.
pub(super) fn patch_states_version(patch: &serde_json::Value) -> bool {
    patch
        .get("metadata")
        .and_then(|m| m.get("resourceVersion"))
        .is_some_and(|v| !v.is_null())
}

/// Retry a read/merge/write CAS conflict only when the client supplied no
/// resourceVersion. An explicit version is a condition that must not be rebased.
/// Other errors, including AlreadyExists and Terminating, are not retried.
/// The closure creates a fresh future for each bounded attempt.
pub async fn patch_with_retry<T, F, Fut>(
    patch: &serde_json::Value,
    mut once: F,
) -> std::result::Result<T, ApiError>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = std::result::Result<T, ApiError>>,
{
    let conditional = patch_states_version(patch);
    for attempt in 1..=PATCH_ATTEMPTS {
        match once().await {
            Err(e) if !conditional && e.reason() == "Conflict" && attempt < PATCH_ATTEMPTS => {
                // Debug: a lost race that the next pass wins is not news, and
                // an info line per heartbeat collision would be the log.
                debug!(
                    attempt,
                    reason = e.message(),
                    "unconditional patch lost a race; again"
                );
            }
            outcome => return outcome,
        }
    }
    unreachable!("the last attempt returns its outcome")
}
