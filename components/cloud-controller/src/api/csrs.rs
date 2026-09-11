// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! The `certificatesigningrequests` resource and its `approval` subresource.

use super::*;

// --- certificate signing requests ------------------------------------------

/// What a PUT to `.../approval` says. Deliberately not the whole object: the
/// only thing an approver decides is yes or no and why, and a handler that
/// took a full object would have to work out which of its fields it was
/// allowed to believe.
#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct Approval {
    approved: bool,
    #[serde(default)]
    reason: Option<String>,
    #[serde(default)]
    message: Option<String>,
}

pub(super) async fn list_csrs(
    State(st): State<ApiState>,
    axum::extract::Query(q): axum::extract::Query<controller_api::ListQuery>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let selector = controller_api::Selector::parse(q.label_selector.as_deref())?;
    let mut items = st.store.list::<CertificateSigningRequest>().await?;
    items.retain(|c| selector.selects(&c.metadata.labels));
    Ok(Json(json!({
        "apiVersion": API_VERSION,
        "kind": "CertificateSigningRequestList",
        "items": items,
    })))
}

/// Accept a request for a certificate.
///
/// `metadata.name` may be empty, and normally is: certificate requests happen
/// to the same person repeatedly, so a name the client picked would collide
/// with its own last one. The server derives `<username>-<8 of the uid>`,
/// which is unique because the uid is.
///
/// Three checks, and each of them exists because of something a client could
/// otherwise get away with:
///
///   - the request has to parse and its signature has to check out, or the
///     store would fill with documents the signer will choke on later;
///   - the name in the request has to be the name being asked for, so that
///     what the client signed is what it asked for;
///   - a caller who is not an admin may only ask for its own name. This is
///     the one that matters: without it, `auto_approve` plus any member's
///     certificate is a path to the administrator's.
pub(super) async fn create_csr(
    State(st): State<ApiState>,
    caller: Caller,
    CallerRole(role): CallerRole,
    dry: controller_api::DryRun,
    Json(body): Json<CertificateSigningRequest>,
) -> Result<(StatusCode, Json<CertificateSigningRequest>), ApiError> {
    check_envelope(&body)?;
    if body.spec.username.is_empty() {
        return Err(invalid("spec.username must say who the certificate is for"));
    }
    if body.spec.signer_name != SIGNER_USER_CLIENT {
        return Err(invalid(format!(
            "unknown signer {:?}; this control plane runs {SIGNER_USER_CLIENT}",
            body.spec.signer_name
        )));
    }
    if !caller.may_act_for(role, &body.spec.username) {
        return Err(forbidden(format!(
            "{} may only request a certificate for itself, not for {:?}",
            caller.name(),
            body.spec.username
        )));
    }

    // Parses, and the key inside it signed it — otherwise anybody could
    // submit somebody else's public key and have the CA vouch for a key they
    // do not hold. A request made out to one name and submitted under another
    // is either a mistake or an attempt; the answer is the same either way.
    let made_out_to = pki::requested_name(&body.spec.request)
        .map_err(|e| invalid(format!("spec.request: {e:#}")))?;
    if made_out_to != body.spec.username {
        return Err(invalid(format!(
            "the request is made out to {made_out_to:?} but asks for {:?}; sign the request with \
             the name you are asking for",
            body.spec.username
        )));
    }

    // The name in the directory is the name the certificate will carry.
    let user: User = match st.store.get(&body.spec.username).await {
        Ok(u) => u,
        Err(StoreError::NotFound(_)) => {
            return Err(invalid(format!(
                "no user {:?}; create it first (meister user create)",
                body.spec.username
            )));
        }
        Err(e) => return Err(e.into()),
    };

    let mut csr = CertificateSigningRequest::declare(
        &body.metadata.name,
        CsrSpec {
            request: body.spec.request,
            username: body.spec.username,
            signer_name: body.spec.signer_name,
        },
    );
    if csr.metadata.name.is_empty() {
        // Requests are things that happen repeatedly to the same person, so
        // the default name carries who and which — the uid is already unique
        // and already on the object.
        csr.metadata.name = format!("{}-{}", csr.spec.username, &csr.metadata.uid[..8]);
    }
    csr.metadata.labels = body.metadata.labels;

    if st.signing.as_ref().is_some_and(|s| s.auto_approve) {
        let by = format!("{} (auto_approve)", caller.name());
        approve_and_sign(&st, &mut csr, &user, &by).await?;
    }

    let created = match dry.preview(&csr) {
        Some(preview) => preview,
        None => st.store.create(&csr).await?,
    };
    info!(csr = %created.metadata.name, user = %created.spec.username,
          phase = created.status.phase(), "certificate request accepted");
    Ok((StatusCode::CREATED, Json(created)))
}

pub(super) async fn get_csr(
    State(st): State<ApiState>,
    Path(name): Path<String>,
) -> Result<Json<CertificateSigningRequest>, ApiError> {
    Ok(Json(st.store.get(&name).await?))
}

pub(super) async fn delete_csr(
    State(st): State<ApiState>,
    Path(name): Path<String>,
) -> Result<controller_api::Removed, ApiError> {
    let _: CertificateSigningRequest = st.store.get(&name).await?;
    st.store.delete::<CertificateSigningRequest>(&name).await?;
    Ok(controller_api::removed(
        CertificateSigningRequest::KIND,
        &name,
        controller_api::Removal::Gone,
    ))
}

/// Approve or deny, and — on approval — sign, because this process is both
/// the approver and the signer.
///
/// Kubernetes splits those two roles across two components and that split is
/// worth something there: the approver decides policy and the signer holds
/// the key, and they can be operated by different people. Here one process
/// holds the key and serves the API, so splitting them would be ceremony
/// around a boundary that does not exist. The condition still records who
/// approved, which is the part of the split that carries the meaning.
pub(super) async fn approve_csr(
    State(st): State<ApiState>,
    Path(name): Path<String>,
    caller: Caller,
    dry: controller_api::DryRun,
    Json(decision): Json<Approval>,
) -> Result<Json<CertificateSigningRequest>, ApiError> {
    // The one write route that answers a dry run with a refusal instead of a
    // preview, and the reason is what the write PRODUCES: a certificate.
    //
    // Everything else here can be shown because showing it costs nothing — no
    // object exists afterwards either way. An approval signs, and a signature
    // handed out "as a preview" is a live credential with no record of having
    // been issued: the thing the CSR object exists to be. Answering with the
    // condition and no certificate would be a preview of the half that does
    // not matter.
    if dry.requested() {
        return Err(invalid(
            "dryRun is not offered on approval; approving signs a certificate, and a signature \
             cannot be shown without being issued. Read the request with GET first",
        ));
    }
    let mut csr: CertificateSigningRequest = st.store.get(&name).await?;
    if csr.status.denied() {
        return Err(conflict(format!("{name} was denied; a denial is final")));
    }
    if csr.status.certificate.is_some() {
        // Idempotent: the certificate is already there and re-signing would
        // hand out a second credential for one request.
        return Ok(Json(csr));
    }

    if !decision.approved {
        csr.status.set(CsrCondition {
            kind: CsrConditionType::Denied,
            reason: decision.reason.unwrap_or_else(|| "Denied".into()),
            message: decision.message.unwrap_or_default(),
            last_update_time: Utc::now(),
            by: caller.name().to_string(),
        });
        info!(csr = %name, by = caller.name(), "certificate request denied");
        return Ok(Json(st.store.update(&csr).await?));
    }

    let user: User = match st.store.get(&csr.spec.username).await {
        Ok(u) => u,
        Err(StoreError::NotFound(_)) => {
            return Err(invalid(format!(
                "the user {:?} this request was made for no longer exists",
                csr.spec.username
            )));
        }
        Err(e) => return Err(e.into()),
    };
    approve_and_sign(&st, &mut csr, &user, caller.name()).await?;
    Ok(Json(st.store.update(&csr).await?))
}

/// Stamp the approval, sign, and record the fingerprint on the user.
///
/// The subject comes from the directory and nowhere else: the common name is
/// the user object's name and the one group is the role it carries. Nothing a
/// client wrote reaches the certificate.
pub(super) async fn approve_and_sign(
    st: &ApiState,
    csr: &mut CertificateSigningRequest,
    user: &User,
    by: &str,
) -> Result<(), ApiError> {
    let Some(signing) = &st.signing else {
        return Err(ApiError::new(
            StatusCode::NOT_IMPLEMENTED,
            "NoSigner",
            "this cloud-controller has no CA configured (ca_cert/ca_key); it can record \
             certificate requests but not sign them",
        ));
    };

    let now = Utc::now();
    // The role's group goes into the certificate, and since the permission
    // table it is LABELLING and not a permission. Nothing in the
    // authorization path reads it any more: the cloud takes the role out of
    // the directory on every request, and a tier without a directory
    // authorizes no person at all. It stays because a certificate that says
    // what it is for is readable by the person holding it — `openssl x509
    // -subject` is how somebody finds out which of their four credentials
    // this one is — and because taking it out would change nothing except
    // that.
    let subject = pki::ca::Subject {
        common_name: user.metadata.name.clone(),
        organization: Some(user.spec.role.group().to_string()),
    };
    let issued = signing
        .ca
        .sign_csr(
            &csr.spec.request,
            &subject,
            Duration::days(signing.ttl_days),
            now,
        )
        .map_err(|e| {
            ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Internal",
                format!("signing failed: {e:#}"),
            )
        })?;

    csr.status.set(CsrCondition {
        kind: CsrConditionType::Approved,
        reason: "Approved".into(),
        message: String::new(),
        last_update_time: now,
        by: by.to_string(),
    });
    csr.status.certificate = Some(issued.pem);

    let record = IssuedCertificate {
        fingerprint: issued.info.fingerprint.clone(),
        issued_at: now,
        not_after: issued.info.not_after,
        serial: issued.info.serial.clone(),
        request: csr.metadata.name.clone(),
    };
    // Expired entries go at the same moment: the list is there to say what
    // credentials exist, and one that has died is history rather than a
    // credential. Without this the object grows for ever.
    st.store
        .mutate::<User, _>(&user.metadata.name, |u| {
            u.status.certificates.retain(|c| c.not_after > now);
            u.status.certificates.push(record.clone());
        })
        .await?;

    info!(csr = %csr.metadata.name, user = %user.metadata.name, by,
          role = user.spec.role.as_str(), fingerprint = %issued.info.fingerprint,
          not_after = %issued.info.not_after.to_rfc3339(), "certificate issued");
    Ok(())
}
