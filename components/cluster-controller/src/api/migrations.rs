// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Cluster migration requests, admission checks and ownership-aware deletion.

use super::*;

pub(super) async fn list_vm_migrations(
    State(st): State<ApiState>,
    axum::extract::Query(q): axum::extract::Query<controller_api::ListQuery>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let selector = controller_api::Selector::parse(q.label_selector.as_deref())?;
    let mut items = st.store.list::<controller_api::VmMigration>().await?;
    items.retain(|m| {
        q.tenant.as_deref().is_none_or(|t| m.spec.tenant == t)
            && selector.selects(&m.metadata.labels)
    });
    Ok(Json(
        json!({ "apiVersion": API_VERSION, "kind": "VmMigrationList", "items": items }),
    ))
}

pub(super) async fn get_vm_migration(
    State(st): State<ApiState>,
    Path(name): Path<String>,
) -> Result<Json<controller_api::VmMigration>, ApiError> {
    Ok(Json(st.store.get(&name).await?))
}

/// Create migration intent after synchronous eligibility checks.
/// The reconciler selects and prepares the target, then drives the transfer.
/// An explicit migration ignores `evacuation: never`: that policy controls
/// automatic drains, while this request explicitly authorizes moving the VM.
pub(super) async fn create_vm_migration(
    State(st): State<ApiState>,
    dry: controller_api::DryRun,
    Json(body): Json<controller_api::VmMigration>,
) -> Result<(StatusCode, Json<controller_api::VmMigration>), ApiError> {
    check_envelope(&body)?;
    if body.metadata.name.is_empty() {
        return Err(invalid("metadata.name must be set"));
    }
    if body.spec.vm.is_empty() {
        return Err(invalid("spec.vm must name the vm to move"));
    }
    let vm: Vm = match st.store.get::<Vm>(&body.spec.vm).await {
        Ok(v) => v,
        // 404 and never 403, by the argument `check_volume_refs` makes: a 403
        // would confirm that a VM of that name exists somewhere.
        Err(StoreError::NotFound(_)) => {
            return Err(ApiError::new(
                StatusCode::NOT_FOUND,
                "NotFound",
                format!("no vm {:?} here", body.spec.vm),
            ));
        }
        Err(e) => return Err(e.into()),
    };
    let target = body.spec.target_node.as_deref();
    if let Some(why) = crate::migration::admission::refusal(&st.store, &vm, target).await? {
        return Err(invalid(why));
    }

    let mut spec = body.spec;
    // Whose it is follows the VM and is not the caller's to state: a record
    // of what happened to somebody's VM belongs in their history.
    spec.tenant = vm.spec.tenant.clone().unwrap_or_default();
    let migration = controller_api::VmMigration::declare(&body.metadata.name, spec);
    let created = match dry.preview(&migration) {
        Some(preview) => preview,
        None => st.store.create(&migration).await?,
    };
    info!(migration = %created.metadata.name, vm = %created.spec.vm, "migration requested");
    Ok((StatusCode::CREATED, Json(created)))
}

/// In-flight records retain operation ownership and capacity reservations.
/// A version-checked delete prevents racing a pending migration's prepare claim.
pub(super) async fn delete_vm_migration(
    State(st): State<ApiState>,
    Path(name): Path<String>,
) -> Result<controller_api::Removed, ApiError> {
    let migration: controller_api::VmMigration = st.store.get(&name).await?;
    if !migration.status.phase().kind().is_final()
        && migration.status.phase().kind() != controller_api::VmMigrationPhaseKind::Pending
    {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "MigrationInFlight",
            "resolve the migration before deleting its ownership record",
        ));
    }
    st.store
        .delete_if::<controller_api::VmMigration>(&name, &migration.metadata.resource_version)
        .await?;
    Ok(controller_api::removed(
        controller_api::VmMigration::KIND,
        &name,
        controller_api::Removal::Gone,
    ))
}
