// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! How a write that makes a tenant hold more gets in: look, decide, and write
//! only if nobody else got in since the looking began.
//!
//! The quota checks (`check_quota`, `check_storage_quota`) read the fence
//! first and hand it back with their yes; the write then goes through
//! `create_fenced`/`update_fenced`, which refuses it if the fence moved. A
//! refusal of that kind is not an answer for the client — it is "somebody
//! else was admitted meanwhile" — so the whole decision is made again, from a
//! store that now includes them. See `controller_api::store::Fence` for why
//! a per-object compare-and-swap could not say this (F03).

use super::*;

/// How many times an admission decides again after another one for the same
/// tenant got in first. A liveness bound and not a correctness one, the same
/// number `EtcdStore::mutate` and `floating::allocate` use: every round lost
/// is a write that DID land, so eight in a row is a tenant under a burst,
/// and the client is better told so than kept waiting.
const ADMISSION_ROUNDS: usize = 8;

/// Run `attempt` until it is decided: `Some` is the answer, `None` is "the
/// fence moved, decide again".
///
/// A closure that hands back a future rather than an `async` closure, and
/// the callers write it `move || async move` over references they copied in:
/// axum needs a handler's future to be `Send` for every lifetime, and the
/// compiler cannot prove that of an async closure's borrow of itself.
pub(super) async fn admit<T, F, Fut>(tenant: &str, mut attempt: F) -> Result<T, ApiError>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<Option<T>, ApiError>>,
{
    for _ in 0..ADMISSION_ROUNDS {
        if let Some(decided) = attempt().await? {
            return Ok(decided);
        }
        debug!(
            tenant,
            "another admission for this tenant got in first; deciding again"
        );
    }
    Err(conflict(format!(
        "tenant {tenant} is being changed by {ADMISSION_ROUNDS} other requests at once; try again"
    )))
}

/// Create `obj`, through the fence where there is one. An object with no
/// tenant has no ceiling and no fence, and is created exactly as before.
pub(super) async fn create_under<T: Resource>(
    st: &ApiState,
    obj: &T,
    fence: Option<&Fence>,
) -> Result<Option<T>, ApiError> {
    Ok(match fence {
        Some(fence) => st.store.create_fenced(obj, fence).await?,
        None => Some(st.store.create(obj).await?),
    })
}

/// Update `obj`, through the fence where there is one.
pub(super) async fn update_under<T: Resource>(
    st: &ApiState,
    obj: &T,
    fence: Option<&Fence>,
) -> Result<Option<T>, ApiError> {
    Ok(match fence {
        Some(fence) => st.store.update_fenced(obj, fence).await?,
        None => Some(st.store.update(obj).await?),
    })
}
