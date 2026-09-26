// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Tenant secret CRUD. Values are sealed before storage and omitted from all
//! API responses. Dispatch resolves them separately for agents.

use super::*;

pub(super) async fn list_secrets(
    State(st): State<ApiState>,
    caller: Caller,
    role: CallerRole,
    tenant: CallerTenant,
    axum::extract::Query(q): axum::extract::Query<controller_api::ListQuery>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let selector = controller_api::Selector::parse(q.label_selector.as_deref())?;
    let who = Grant::new(caller, role, tenant).listing(q.tenant.as_deref());
    let mut items: Vec<controller_api::Secret> = st.store.list().await?;
    items.retain(|s| {
        who.keeps(Some(s.spec.tenant.as_str())) && selector.selects(&s.metadata.labels)
    });
    // Redacted on the way out of the list exactly as on the way out of a GET.
    // A listing that showed values would be the same leak with more of them.
    let items: Vec<controller_api::Secret> = items
        .into_iter()
        .map(controller_api::Secret::redacted)
        .collect();
    Ok(Json(json!({
        "apiVersion": API_VERSION,
        "kind": "SecretList",
        "items": items,
    })))
}

pub(super) async fn get_secret(
    State(st): State<ApiState>,
    Path(name): Path<String>,
    caller: Caller,
    role: CallerRole,
    tenant: CallerTenant,
) -> Result<Json<controller_api::Secret>, ApiError> {
    let secret: controller_api::Secret = st.store.get(&name).await?;
    Grant::new(caller, role, tenant)
        .allows(Scope::of(Some(secret.spec.tenant.as_str())), Verb::Read)?;
    Ok(Json(secret.redacted()))
}

/// Require the configured sealing key; absence returns 501 without storing plaintext.
fn sealer(st: &ApiState) -> Result<&controller_api::secrets::Kek, ApiError> {
    st.kek.as_deref().ok_or_else(|| {
        ApiError::new(
            StatusCode::NOT_IMPLEMENTED,
            "NotImplemented",
            "this cloud-controller has no secrets_key configured, so it cannot store a secret \
             without storing it in the clear. Put 32 bytes at the path secrets_key names \
             (push.sh pki does it) and restart both controller tiers",
        )
    })
}

/// Refuse a key nobody can use.
///
/// The key names travel in an AAD (`secrets/<name>/<key>`), so a key
/// containing `/` would let two different slots produce the same additional
/// data — which is the one thing the AAD exists to prevent. The rest of the
/// rule is cloud-init's: these become file names and environment names often
/// enough that the K8s alphabet is the right one.
fn check_keys(data: &std::collections::BTreeMap<String, String>) -> Result<(), ApiError> {
    if data.is_empty() {
        return Err(invalid(
            "spec.data must name at least one key; an empty secret is a name and nothing else",
        ));
    }
    for key in data.keys() {
        let usable = !key.is_empty()
            && key.len() <= 253
            && key
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.');
        if !usable {
            return Err(controller_api::invalid_field(
                "spec.data",
                format!(
                    "{key:?} is not a usable key; letters, digits, '-', '_' and '.', at most \
                     253 of them"
                ),
            ));
        }
    }
    Ok(())
}

pub(super) async fn create_secret(
    State(st): State<ApiState>,
    caller: Caller,
    role: CallerRole,
    tenant: CallerTenant,
    dry: controller_api::DryRun,
    Json(body): Json<controller_api::Secret>,
) -> Result<(StatusCode, Json<controller_api::Secret>), ApiError> {
    check_envelope(&body)?;
    if body.metadata.name.is_empty() {
        return Err(invalid("metadata.name must be set"));
    }
    let who = Grant::new(caller, role, tenant);
    let owner = who
        .tenant_for_create(Some(body.spec.tenant.clone()))
        .ok_or_else(|| invalid("spec.tenant must name a tenant"))?;
    who.allows(Scope::of(Some(owner.as_str())), Verb::Write)?;
    check_tenant(&st, &owner).await?;
    check_keys(&body.spec.data)?;
    let kek = sealer(&st)?;

    let sealed = kek
        .seal_all(
            controller_api::Secret::RESOURCE,
            &body.metadata.name,
            &body.spec.data,
        )
        .map_err(|e| {
            ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Internal",
                format!("sealing failed: {e:#}"),
            )
        })?;
    let mut secret = controller_api::Secret::declare(
        &body.metadata.name,
        controller_api::SecretSpec {
            tenant: owner.clone(),
            data: sealed,
            // Derived at every read and never stored. See `SecretSpec`.
            keys: Vec::new(),
            description: body.spec.description,
        },
    );
    secret.metadata.labels = body.metadata.labels;
    let created = match dry.preview(&secret) {
        Some(preview) => preview,
        None => st.store.create(&secret).await?,
    };
    // The name, the tenant and HOW MANY keys. Never a key name and never a
    // length: a log line is the one place a secret leaks without anybody
    // meaning to.
    info!(secret = %created.metadata.name, tenant = %owner,
          keys = created.spec.data.len(), "secret created");
    Ok((StatusCode::CREATED, Json(created.redacted())))
}

/// Replace every secret value. Reads are redacted, so PUT requires the complete
/// plaintext key set; tenant ownership remains unchanged.
pub(super) async fn update_secret(
    State(st): State<ApiState>,
    Path(name): Path<String>,
    caller: Caller,
    role: CallerRole,
    tenant: CallerTenant,
    dry: controller_api::DryRun,
    Json(body): Json<controller_api::Secret>,
) -> Result<Json<controller_api::Secret>, ApiError> {
    if body.metadata.name != name {
        return Err(invalid("metadata.name does not match the path"));
    }
    check_envelope(&body)?;
    let current: controller_api::Secret = st.store.get(&name).await?;
    Grant::new(caller, role, tenant)
        .allows(Scope::of(Some(current.spec.tenant.as_str())), Verb::Write)?;
    check_keys(&body.spec.data)?;
    let kek = sealer(&st)?;

    let sealed = kek
        .seal_all(controller_api::Secret::RESOURCE, &name, &body.spec.data)
        .map_err(|e| {
            ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Internal",
                format!("sealing failed: {e:#}"),
            )
        })?;
    let mut next = current.clone();
    next.metadata.resource_version = body.metadata.resource_version;
    next.metadata.labels = body.metadata.labels;
    next.spec.data = sealed;
    next.spec.description = body.spec.description;
    // A fresh nonce per value means the ciphertext differs even when the
    // plaintext does not, so this counts every write. That is the honest
    // answer here and not a defect: this tier cannot tell a rotation from a
    // re-send without opening both, and a consumer treating a re-send as a
    // rotation costs one re-read.
    controller_api::carry_generation(&current, &mut next)?;
    match dry.preview(&next) {
        Some(preview) => Ok(Json(preview.redacted())),
        None => Ok(Json(st.store.update(&next).await?.redacted())),
    }
}

pub(super) async fn delete_secret(
    State(st): State<ApiState>,
    Path(name): Path<String>,
    caller: Caller,
    role: CallerRole,
    tenant: CallerTenant,
) -> Result<controller_api::Removed, ApiError> {
    let current: controller_api::Secret = st.store.get(&name).await?;
    Grant::new(caller, role, tenant)
        .allows(Scope::of(Some(current.spec.tenant.as_str())), Verb::Write)?;
    // Allow deletion while VMs reference the secret: existing guests retain their
    // seed, while later dispatches must resolve the secret again.
    // Delete mirrored copies before the source object, which otherwise leaves no
    // deletion evidence to reconcile. Only locally connected clusters are contacted;
    // a failed or disconnected cluster can retain its sealed copy.
    for cluster in st.sessions.connected() {
        let op = cloud_command::Op::DeleteSecret(proto::DeleteSecret {
            name: name.clone(),
            uid: current.metadata.uid.clone(),
        });
        if let Err(e) = st.sessions.send_command(&cluster, "", op).await {
            warn!(secret = %name, %cluster, error = format!("{e:#}"),
                  "the mirrored copy could not be removed; it stays there sealed");
        }
    }
    // Astra finding S19, 2026-09-23: names are global (`create_secret` keys
    // by `metadata.name`) and the Acks above are an unbounded pause — a
    // delete that resumed after this pauses could land on an object that was
    // removed and recreated under the same name while it waited, deleting
    // whatever a DIFFERENT tenant now holds there. `delete_if` is the same
    // compare-and-swap `update_fenced` guards a write with, so a name that no
    // longer names the object read above answers with `Conflict` — 409 — and
    // not a silent delete of the wrong thing.
    st.store
        .delete_if::<controller_api::Secret>(&name, &current.metadata.resource_version)
        .await?;
    info!(secret = %name, tenant = %current.spec.tenant, "secret deleted");
    Ok(controller_api::removed(
        controller_api::Secret::KIND,
        &name,
        controller_api::Removal::Gone,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The redaction, which is the whole read side of this resource.
    #[test]
    fn a_read_answers_with_key_names_and_never_with_values() {
        let secret = controller_api::Secret::declare(
            "db",
            controller_api::SecretSpec {
                tenant: "acme".into(),
                data: [
                    ("password".to_string(), "c2VhbGVk".to_string()),
                    ("username".to_string(), "c2VhbGVkMg==".to_string()),
                ]
                .into_iter()
                .collect(),
                keys: Vec::new(),
                description: "the app's database".into(),
            },
        );

        let read = secret.redacted();
        assert_eq!(read.spec.keys, ["password", "username"]);
        assert!(read.spec.data.is_empty());
        assert_eq!(read.spec.tenant, "acme", "the rest of the object stays");
        assert_eq!(read.spec.description, "the app's database");

        // And the document a client actually receives has no `data` at all —
        // the redaction is structural, not a field set to something empty.
        let document = serde_json::to_value(&read).expect("serialises");
        assert!(document["spec"].get("data").is_none(), "{document}");
        assert_eq!(document["spec"]["keys"][0], "password");
    }

    /// The key alphabet, and the one entry in it that is about the crypto
    /// rather than about cloud-init: a `/` would let two slots share an AAD.
    #[test]
    fn a_key_that_could_collide_in_the_aad_is_refused() {
        let data =
            |key: &str| std::collections::BTreeMap::from([(key.to_string(), "value".to_string())]);
        for good in ["password", "DB_PASSWORD", "tls.key", "a-b_c.1"] {
            check_keys(&data(good)).unwrap_or_else(|e| panic!("{good:?}: {e:?}"));
        }
        for bad in ["", "a/b", "secrets/db/password", "a b", "ä"] {
            let refused = check_keys(&data(bad)).expect_err("{bad:?}");
            assert!(format!("{refused:?}").contains("usable key"), "{bad:?}");
        }
        // A secret with no keys is a name and nothing else.
        let refused = check_keys(&std::collections::BTreeMap::new()).expect_err("nothing to store");
        assert!(format!("{refused:?}").contains("at least one key"));
    }
}
