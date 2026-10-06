// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! How a write that claims something ends once its question was asked again from inside the
//! store: kept when it won, undone when it lost. Shared by every handler whose claim a
//! concurrent write can beat between its check and its write (a range, a network, a default
//! mark), whatever the claim is about.

use std::future::Future;

use super::*;

/// How a write already in the store ends once its claim's question was asked again (`lost`):
/// kept when it won (`Ok(None)`); undone by `undo` and refused when it lost, or when the
/// question could not be answered, since a claim not known to have won is undone like one that
/// lost. (RR5-6)
///
/// An undo that fails leaves the write standing on what won, and no pass, retry or reconnect
/// clears that; only a person does. That is an ERROR, and the answer is `claim_not_taken_back`
/// rather than the refusal: a 409 would tell the client that nothing was written, and
/// `patch_with_retry` would take it for a lost compare-and-swap, run the request again over
/// the write that stayed, find nothing left to judge and answer 200. (NL6-3)
///
/// `name` and `kind` say whose write it was, in the log and in the answer.
pub(super) async fn settle_claim(
    name: &str,
    kind: &str,
    lost: Result<Option<String>, ApiError>,
    undo: impl Future<Output = Result<(), ApiError>>,
) -> Result<(), ApiError> {
    let refusal = match lost {
        Ok(None) => return Ok(()),
        Ok(Some(why)) => conflict(why),
        Err(e) => e,
    };
    #[cfg(test)]
    super::admission_tests::undo_gate(name).await;
    match undo.await {
        Ok(()) => Err(refusal),
        Err(e) => {
            error!(name, kind, refusal = %refusal.message(), error = %e.message(),
                   "could not take back a write that lost its claim; it now stands on another \
                    claim and has to be undone by hand");
            Err(controller_api::claim_not_taken_back(format!(
                "{}; taking this {kind}'s write back failed too ({}), so {name} stands as \
                 written and has to be undone by hand",
                refusal.message(),
                e.message()
            )))
        }
    }
}

/// Undo a create: the object this request created, by its uid and revision, since a name
/// taken back after somebody else took it would be their object. (IKR-B81)
pub(super) async fn take_back<T: Resource>(st: &ApiState, created: &T) -> Result<(), ApiError> {
    controller_api::deletion::take_back_created(&st.store, created).await?;
    Ok(())
}

/// Undo an update: `before` written back over the revision `written` holds, and over nothing
/// anybody wrote since, which is theirs and stays. The whole request is undone (labels, quota,
/// every field it named), since it is refused whole.
pub(super) async fn put_back<S, St>(
    st: &ApiState,
    before: &controller_api::Object<S, St>,
    written: &controller_api::Object<S, St>,
) -> Result<(), ApiError>
where
    controller_api::Object<S, St>: Resource + Clone,
    S: serde::Serialize,
{
    let mut back = before.clone();
    back.metadata.resource_version = written.metadata.resource_version.clone();
    controller_api::carry_generation(written, &mut back)?;
    st.store.update(&back).await?;
    Ok(())
}
