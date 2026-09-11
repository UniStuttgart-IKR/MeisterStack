// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Who owns which field: the table a tier keeps, the check that reads it, and
//! the two envelope rules that go with it. Moved out of `rest.rs` unchanged.

use super::*;

/// One field an update may not change, and the half-sentence that says why.
///
/// The rule, whole, and the reason the two kinds share a type: *a field the
/// controller acts on exactly once — when it creates the thing — is
/// immutable; a field a controller WRITES belongs to the server; everything
/// else is free.* Both are refusals to a client and both name a path, so what
/// differs between them is only the sentence, and the sentence belongs beside
/// the field rather than in a second enum.
#[derive(Clone, Copy, Debug)]
pub struct Owned {
    /// A dotted path into the serialised object: `spec.vm`, `spec.nodeName`.
    pub path: &'static str,
    /// Which of the two this is. The refusal is the same either way; a client
    /// reading the published table needs to tell them apart, because they are
    /// different sentences to a person: "you cannot change this, ever" and
    /// "this is not yours to set".
    pub kind: Mutability,
    /// What follows the path in the refusal. Written to read as one sentence:
    /// `"is immutable; delete the vm and create it again"`.
    pub because: &'static str,
    /// What is KNOWN to be coming for this field, if anything — published
    /// beside the refusal so a client learns it from the server rather than
    /// from a release note.
    ///
    /// Not a second reason and never part of the 422: a refusal is about
    /// today, and mixing "you may not" with "you will be able to" into one
    /// sentence would make the message longer without making it truer. It is
    /// here because `/schemas` is what a form reads, and a form that greys a
    /// field out can say why it is grey AND that it will not always be.
    ///
    /// `None` for almost every row, which is the honest default: most
    /// immutable fields are immutable because the thing they describe was
    /// decided once, and nothing is coming for them.
    pub note: Option<&'static str>,
    /// For a [`Mutability::Structural`] row: whether a given change is one of
    /// the changes this field allows.
    ///
    /// `check_owned` asks THIS instead of comparing the two values, so the
    /// row is enforced in the same one place every other row is. That is the
    /// whole reason it is a field and not a second check beside the table: a
    /// structural rule enforced somewhere else is a rule the next handler
    /// forgets to call.
    ///
    /// A pair and not a projection, because the two rules that need it are
    /// different shapes. `spec.vm` freezes a PART of the document and could
    /// be written as "project, then compare"; `spec.sizeGib` may only grow,
    /// which no projection of one side can express — it is a fact about the
    /// two numbers together. One signature covers both, and the projection
    /// version is one line inside the predicate.
    ///
    /// A function pointer and not a closure, so the tables stay `const`.
    pub permits: Option<fn(&serde_json::Value, &serde_json::Value) -> bool>,
}

/// Why a field may not be written.
///
/// Published under `/schemas` so a form can grey a field out with a reason
/// rather than discovering it as a 422 after somebody typed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub enum Mutability {
    /// The controller acts on it exactly once, when it creates the thing.
    Immutable,
    /// A controller writes it.
    ServerOwned,
    /// Immutable in its SHAPE: parts of it may change and the rest may not,
    /// and the `because` sentence says which is which.
    ///
    /// The third word exists because the second one became a lie. `spec.vm`
    /// is immutable in everything except `volumes[]` from its second entry
    /// on — a disk plugged into a running VM is an edit of the spec, not a
    /// verb — and a form that greyed the whole document out on the strength
    /// of "immutable" would be greying out the one part a tenant may use.
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

    /// A field that is fixed in SOME way rather than in every way: `permits`
    /// says which changes go through, and `check_owned` asks it instead of
    /// comparing.
    ///
    /// One row, one enforcement point, and that is deliberate. The
    /// alternative — leaving the field out of the table and checking it in
    /// the two update handlers — is a rule the third handler forgets, and the
    /// first field this exists for is `spec.vm`, where forgetting means a
    /// client rewriting a booted VM's kernel command line.
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

/// Refuse an update that changes a field it does not own.
///
/// Before this, every one of these fields was silently put back: `update_vm`
/// at the cluster reset `spec.nodeName` to the stored value, the cloud reset
/// `spec.clusterName` and `spec.tenant`, and a client that sent something
/// else got 200 and an object that was not what it sent. That is the lie this
/// removes — and for `spec.vm` it is worse than a lie, because a node takes a
/// spec once and "delete it and make it again" is, with volumes that do not
/// survive a VM today, somebody's data.
///
/// A value equal to the stored one passes. A value that DIFFERS is 422, and
/// that includes a field left out of a PUT: a PUT already has to round-trip
/// the object it read — that is where its `resourceVersion` comes from — so a
/// body that dropped a field is a body that means to clear it. PATCH never
/// meets this: the patch is merged onto the stored object first, so a field
/// the patch does not mention is already the stored value.
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

/// A dotted path into a document, or `Null` where nothing is.
///
/// Absent and `null` come out the same, deliberately: a field left out of a
/// body and a field written as `null` are the same statement about it, and a
/// rule that told them apart would depend on whether a struct spells its
/// empty case `Option::None` or `skip_serializing_if`.
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

/// Carry `metadata.generation` across an API write: one more than the stored
/// object's if this write leaves a different spec behind, the same if it does
/// not.
///
/// Every update handler of both tiers calls this, in the one line before it
/// hands the object to the store, and that placement is the whole rule: what
/// counts is what a CLIENT asked for, so the comparison happens after the
/// handler has put the server's own fields back — the scheduler's binding,
/// the tenant, the ownership marks. A `PUT` that only re-sends those is a
/// round trip and not a change, and it must not tick.
///
/// The compare is on the SERIALISED spec rather than on the field a handler
/// happens to care about, because the field a handler happens to care about
/// is exactly what gets forgotten when a spec grows one. Two specs that
/// serialise the same are the same intent, whatever they are made of.
///
/// Reconcilers never come through here. They write with `store.mutate`, which
/// does not touch the count — a binding is the server's decision about a
/// client's intent, not a new intent.
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

/// The envelope a POST or PUT body has to wear, read off the type the handler
/// deserialised it into. Checked at every write edge of both tiers, because a
/// body that names another kind is a client sending the wrong document to the
/// right URL — and the fields it does not know about would be defaulted away
/// silently.
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
