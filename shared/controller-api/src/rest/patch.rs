// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Writing part of an object: the spec-only PUT, the JSON merge patch, and
//! the retry a compare-and-swap needs. Moved out of `rest.rs` unchanged.

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

/// Apply a spec-only PUT onto the object as it is stored.
///
/// The one write path for the fields an operator owns on a controller-owned
/// object: `spec.schedulable` on a Node, the same on a Cluster. Everything
/// else about the object is server-owned and survives the round trip
/// untouched — uid, creation, deletion, finalizers, and status.
///
/// Status is REFUSED rather than silently kept, which is the one place this
/// differs from `update_vm`. The difference is who is being talked to: a VM
/// spec is a document a client authored and re-sends whole, so quietly
/// keeping the server's half is the only way a client can round-trip one at
/// all. A Node object is authored by the controller from what an agent
/// reported, and the only reason to PUT one is to flip a field of `spec` — so
/// a body that also carries a different status is a client that believes it
/// can set `ready` or `capacity`, and telling it no is worth more than
/// accepting the write and discarding half of it. A body that repeats the
/// status it just read is not that, and passes.
///
/// The resourceVersion is the CLIENT's, exactly as in `update_vm`: it is what
/// makes the store's compare-and-swap a compare-and-swap. A body without one
/// is refused by the store with the same message every other update gets.
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
        let held = serde_json::to_value(&current.status).map_err(|e| {
            ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "Internal", e.to_string())
        })?;
        if sent != &held {
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

/// The body a PATCH turns into: the object as it stands, with the patch
/// applied, read back as the type this route's PUT takes.
///
/// This is what makes PATCH a PUT with a server-filled body rather than a
/// second write path. Whatever the PUT handler does afterwards — the
/// ownership checks, the fields it keeps, the sentences it refuses with —
/// happens to a patched object exactly as it happens to one a client sent
/// whole, because it is the same handler.
///
/// Three things are decided before the merge and one after it:
///
/// * `status` in a patch is refused, as it is on a PUT. `SpecUpdate` already
///   has that rule for the objects a controller owns, and the reason is the
///   same for the rest: a client that believes it can set a phase is a client
///   to tell no, rather than one to accept the write from and discard half of.
/// * `apiVersion` and `kind` may be there and have to be right if they are —
///   a patch is usually three lines and naming neither is the normal case.
/// * `metadata.resourceVersion` is optional. Named, it is the client's
///   compare-and-swap against exactly that version; not named, the merged
///   document keeps the one just read, so a writer that slipped in between
///   still loses the race and is told.
/// * And the type check runs AFTER the merge, which is the whole reason the
///   patched document goes back through `from_value`: a patch that puts a
///   string where a bool belongs is a 422 about the object, not a 500 about
///   us.
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

/// Run a PATCH's read-merge-write, and run it again if the client stated no
/// condition and lost the compare-and-swap.
///
/// The bug this exists for: `PATCH /nodes/x {"spec":{"schedulable":false}}`
/// reads the object, merges, and writes with a CAS against the version it
/// just read — while the agent's heartbeat writes `status` into the same
/// object every three seconds. A cordon that lands in that window is a 409
/// for a client that never asked for one. The client stated no
/// `resourceVersion`, so the version in the CAS is not the client's condition
/// at all: it is this server's own bookkeeping, and losing a race against it
/// is this server's problem to solve. Kubernetes answers the same way, in the
/// same place.
///
/// A client that DID state a version stated a condition, and the first 409 is
/// the answer — retrying would merge its patch onto a document it has never
/// seen, which is precisely what it asked not to happen.
///
/// Only `Conflict` is retried. `AlreadyExists` and `Terminating` are 409 too
/// and are both facts about the object rather than races: trying them again
/// three times would be three times the same answer, one third as fast.
///
/// `once` is a closure returning a fresh future rather than an `AsyncFnMut`:
/// an async closure's future borrows the closure, and a future that borrows
/// something is a future axum cannot prove is `Send`. The caller hands over a
/// factory instead, and each pass builds its own.
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
