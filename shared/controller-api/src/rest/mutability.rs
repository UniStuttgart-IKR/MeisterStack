// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Field ownership, immutable-field checks and generation accounting.

use super::*;

/// Update restriction for a dotted field path, with a client-facing reason.
/// The kind distinguishes immutable, server-owned and structurally mutable fields.
#[derive(Clone, Copy, Debug)]
pub struct Owned {
    /// A dotted path into the serialised object: `spec.vm`, `spec.nodeName`.
    pub path: &'static str,
    /// Published restriction kind so clients can distinguish ownership from shape
    /// and lifetime immutability.
    pub kind: Mutability,
    /// What follows the path in the refusal. Written to read as one sentence:
    /// `"is immutable; delete the vm and create it again"`.
    pub because: &'static str,
    /// Optional schema guidance, separate from the current refusal reason.
    /// This note does not change enforcement or the 422 response.
    pub note: Option<&'static str>,
    /// Allowed old/new-value predicate for a Structural field. `check_owned`
    /// uses it instead of equality, covering partial immutability and grow-only
    /// values through one enforcement path. Function pointers keep tables const.
    pub permits: Option<fn(&serde_json::Value, &serde_json::Value) -> bool>,
}

/// Field restriction published with schemas for client-side editing guidance.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub enum Mutability {
    /// The controller acts on it exactly once, when it creates the thing.
    Immutable,
    /// A controller writes it.
    ServerOwned,
    /// Only selected structural changes are allowed, as defined by the predicate
    /// and explanation; for example, referenced-disk hot-plug within a VM spec.
    Structural,
}

impl Mutability {
    pub fn as_str(self) -> &'static str {
        match self {
            Mutability::Immutable => "immutable",
            Mutability::ServerOwned => "serverOwned",
            Mutability::Structural => "structural",
        }
    }
}

impl Owned {
    /// A field a controller WRITES. Changing it is refusing to let the server
    /// do its job.
    pub const fn server_owned(path: &'static str, because: &'static str) -> Self {
        Self {
            path,
            kind: Mutability::ServerOwned,
            because,
            note: None,
            permits: None,
        }
    }

    /// A field the controller acts on exactly once, at create. Changing it is
    /// asking for a different thing, and the sentence says how to get one.
    pub const fn immutable(path: &'static str, because: &'static str) -> Self {
        Self {
            path,
            kind: Mutability::Immutable,
            because,
            note: None,
            permits: None,
        }
    }

    /// Define a field with an allowed-change predicate, enforced by the
    /// same `check_owned` loop as other mutability rules.
    pub const fn structural(
        path: &'static str,
        because: &'static str,
        permits: fn(&serde_json::Value, &serde_json::Value) -> bool,
    ) -> Self {
        Self {
            path,
            kind: Mutability::Structural,
            because,
            note: None,
            permits: Some(permits),
        }
    }

    /// The same row, carrying what is known to be coming for the field.
    /// `const` and consuming, so a table stays one expression per row.
    pub const fn noting(self, note: &'static str) -> Self {
        Self {
            note: Some(note),
            ..self
        }
    }
}

/// Reject changes to server-owned or immutable fields with 422. Equal
/// values round-trip. Omitting a field from PUT means clearing it; PATCH
/// merges onto the stored object before this check.
pub fn check_owned<T: serde::Serialize>(
    current: &T,
    next: &T,
    fields: &[Owned],
) -> std::result::Result<(), ApiError> {
    let internal = |e: serde_json::Error| {
        ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "Internal", e.to_string())
    };
    let (current, next) = (
        serde_json::to_value(current).map_err(internal)?,
        serde_json::to_value(next).map_err(internal)?,
    );
    for field in fields {
        let (was, now) = (at(&current, field.path), at(&next, field.path));
        // A structural row asks its own predicate; every other row asks
        // equality, which is the same thing with `|a, b| a == b` and is
        // spelled separately only so that the common case reads as what it is.
        let allowed = match field.permits {
            Some(permits) => permits(was, now),
            None => was == now,
        };
        if !allowed {
            return Err(invalid_field(
                field.path,
                format!("{} {}", field.path, field.because),
            ));
        }
    }
    Ok(())
}

/// Read a dotted JSON path, treating an absent value as null so optional-field
/// serialization choices do not alter ownership checks.
pub(super) fn at<'a>(document: &'a serde_json::Value, path: &str) -> &'a serde_json::Value {
    const NOTHING: &serde_json::Value = &serde_json::Value::Null;
    let mut here = document;
    for segment in path.split('.') {
        match here.get(segment) {
            Some(next) => here = next,
            None => return NOTHING,
        }
    }
    here
}

/// Increment generation only when an API update changes the serialized spec.
/// Call after restoring server-owned fields so controller decisions are not
/// counted as new client intent. Store mutations do not call this helper.
pub fn carry_generation<S: serde::Serialize, St>(
    current: &Object<S, St>,
    next: &mut Object<S, St>,
) -> std::result::Result<(), ApiError> {
    let internal = |e: serde_json::Error| {
        ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "Internal", e.to_string())
    };
    let same = serde_json::to_value(&current.spec).map_err(internal)?
        == serde_json::to_value(&next.spec).map_err(internal)?;
    next.metadata.generation = current.metadata.generation + u64::from(!same);
    Ok(())
}

/// Validate apiVersion and kind against the handler's resource type.
pub fn check_envelope<S, St>(body: &Object<S, St>) -> std::result::Result<(), ApiError>
where
    Object<S, St>: Resource,
{
    let expected = <Object<S, St> as Resource>::KIND;
    if body.api_version != API_VERSION || body.kind != expected {
        return Err(invalid(format!(
            "expected apiVersion {API_VERSION}, kind {expected}"
        )));
    }
    Ok(())
}
