// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! The `users` resource — this tier IS the directory.

use super::*;

// --- users -----------------------------------------------------------------

pub(super) async fn list_users(
    State(st): State<ApiState>,
    axum::extract::Query(q): axum::extract::Query<controller_api::ListQuery>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let selector = controller_api::Selector::parse(q.label_selector.as_deref())?;
    // A user IS in a tenant, so `?tenant=` narrows here as it does on the
    // objects a tenant owns. Nobody is confined at this route — the directory
    // is an admin's — so there is nothing to reconcile it with.
    let mut items = st.store.list::<User>().await?;
    items.retain(|u| {
        q.tenant.as_deref().is_none_or(|t| u.spec.tenant == t)
            && selector.selects(&u.metadata.labels)
    });
    Ok(Json(
        json!({ "apiVersion": API_VERSION, "kind": "UserList", "items": items }),
    ))
}

pub(super) async fn create_user(
    State(st): State<ApiState>,
    dry: controller_api::DryRun,
    Json(body): Json<User>,
) -> Result<(StatusCode, Json<User>), ApiError> {
    check_envelope(&body)?;
    if body.metadata.name.is_empty() {
        return Err(invalid("metadata.name must be set"));
    }
    check_user_name(&body.metadata.name)?;
    check_tenant(&st, &body.spec.tenant).await?;

    let mut user = User::declare(&body.metadata.name, body.spec);
    user.metadata.labels = body.metadata.labels;
    // status is the record of certificates this server issued; a client that
    // could write it could invent a credential history.
    let created = match dry.preview(&user) {
        Some(preview) => preview,
        None => st.store.create(&user).await?,
    };
    info!(user = %created.metadata.name, tenant = %created.spec.tenant,
          role = created.spec.role.as_str(), "user created");
    Ok((StatusCode::CREATED, Json(created)))
}

pub(super) async fn get_user(
    State(st): State<ApiState>,
    Path(name): Path<String>,
) -> Result<Json<User>, ApiError> {
    Ok(Json(st.store.get(&name).await?))
}

pub(super) async fn update_user(
    State(st): State<ApiState>,
    Path(name): Path<String>,
    dry: controller_api::DryRun,
    Json(mut body): Json<User>,
) -> Result<Json<User>, ApiError> {
    if body.metadata.name != name {
        return Err(invalid("metadata.name does not match the path"));
    }
    check_user_name(&name)?;
    check_tenant(&st, &body.spec.tenant).await?;
    let current: User = st.store.get(&name).await?;
    keep_server_owned(&mut body.metadata, &current.metadata);
    // The issued-certificate record is this server's, not the client's.
    body.status = current.status.clone();
    controller_api::carry_generation(&current, &mut body)?;
    let updated = match dry.preview(&body) {
        Some(preview) => preview,
        None => st.store.update(&body).await?,
    };
    info!(user = %name, role = updated.spec.role.as_str(), "user updated");
    Ok(Json(updated))
}

/// Deleting a user does NOT revoke the certificates they hold — nothing here
/// has a revocation list. What it does is take the name out of the directory,
/// and the directory is what the guard consults on every request: from the
/// next call onwards that certificate authenticates to somebody the cloud
/// does not know, and somebody the cloud does not know may do nothing.
///
/// That is the whole revocation story of this milestone, and it is worth
/// saying out loud rather than implying: it works at the cloud, and the
/// cluster tier keeps honouring the certificate until it expires.
pub(super) async fn delete_user(
    State(st): State<ApiState>,
    Path(name): Path<String>,
) -> Result<controller_api::Removed, ApiError> {
    let user: User = st.store.get(&name).await?;
    let live = user.status.live(Utc::now()).count();
    st.store.delete::<User>(&name).await?;
    info!(user = %name, live_certificates = live, "user deleted");
    Ok(
        controller_api::removed(User::KIND, &name, controller_api::Removal::Gone)
            // How many certificates this person is still holding when their
            // entry went. Under `details`, which is where a resource's own
            // answer goes now that the top level of this body is the same for
            // every kind.
            .detail("liveCertificates", serde_json::json!(live)),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The prefix a certificate is read for. A user wearing it would be
    /// issued one that skips the directory and every check behind it.
    #[test]
    fn the_system_prefix_is_not_for_people() {
        assert!(check_user_name("alice").is_ok());
        assert!(
            check_user_name("system-admin").is_ok(),
            "the hyphen is not the prefix"
        );
        assert!(check_user_name("system:masters").is_err());
        assert!(check_user_name("system:node:manacor").is_err());
    }
}
