// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! The `events` resource. Read-only, and the only one that is.
//!
//! The module is not called `events` and the file is: `controller_api::events`
//! is the shared half that every file here records through, and a sibling
//! module of that name would shadow it through `use super::*`. Same for
//! `floating`.

use super::*;

// --- events ----------------------------------------------------------------

/// Everything that happened to one VM, recently.
///
/// Scoped through the VM, not through the events: the caller has to be
/// allowed to read the OBJECT, and then it gets the object's history. Doing
/// it the other way round — filtering the event list by the caller's tenant —
/// would answer 200 with an empty list for somebody else's VM, and "there is
/// nothing" is a different and less honest sentence than "that is not yours".
pub(super) async fn vm_events(
    State(st): State<ApiState>,
    Path(name): Path<String>,
    caller: Caller,
    role: CallerRole,
    tenant: CallerTenant,
) -> Result<Json<serde_json::Value>, ApiError> {
    let vm: Vm = st.store.get(&name).await?;
    Grant::new(caller, role, tenant).allows(Scope::of(vm.spec.tenant.as_deref()), Verb::Read)?;
    let items = events::about(&st.store, Vm::KIND, &vm.metadata.uid, &name).await;
    Ok(Json(
        json!({ "apiVersion": API_VERSION, "kind": "EventList", "items": items }),
    ))
}

/// The whole log, filtered to what the caller may see.
///
/// A member gets its own tenant's and nothing else — the same rule the VM
/// list follows, and for the same reason: a listing is an inventory, and an
/// event names the object it is about. Events with no tenant are the
/// operator's estate (a node's heartbeat, a cluster reconnecting) and only an
/// admin sees them, which is the conservative direction and the one an
/// unscoped VM already takes.
pub(super) async fn list_events(
    State(st): State<ApiState>,
    caller: Caller,
    role: CallerRole,
    tenant: CallerTenant,
    axum::extract::Query(q): axum::extract::Query<controller_api::ListQuery>,
    axum::extract::Query(narrow): axum::extract::Query<events::EventQuery>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let selector = controller_api::Selector::parse(q.label_selector.as_deref())?;
    // Parsed once for the whole listing, and before anything is read: a
    // malformed `since` is a refusal about the request, not a filter that
    // quietly matches nothing.
    let since = narrow.since()?;
    let who = Grant::new(caller, role, tenant).listing(q.tenant.as_deref());
    let mut items = events::all(&st.store).await;
    items.retain(|e| {
        who.keeps(e.spec.tenant.as_deref())
            && selector.selects(&e.metadata.labels)
            && narrow.selects(e, since)
    });
    Ok(Json(
        json!({ "apiVersion": API_VERSION, "kind": "EventList", "items": items }),
    ))
}
