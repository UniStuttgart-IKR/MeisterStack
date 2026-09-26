// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! The `images` catalogue.

use super::*;

// --- images ----------------------------------------------------------------

/// Require a bare filename matching the source basename.
/// The catalogue name is passed unchanged to the node's image directory.
pub(super) fn check_image_name(name: &str, source: &str) -> Result<(), ApiError> {
    if name.is_empty() || name.contains('/') || name == "." || name == ".." {
        return Err(invalid(
            "metadata.name must be the image's bare file name (no path separators)",
        ));
    }
    let base = source.rsplit('/').next().unwrap_or(source);
    if !base.is_empty() && base != name {
        return Err(invalid(format!(
            "metadata.name must match the file spec.source points at ({base:?}); v1 hands the \
             name to the node verbatim and distributes nothing"
        )));
    }
    Ok(())
}

/// Require an HTTP(S) URL and a lowercase SHA-256 digest together.
/// Path-based registrations have neither; this endpoint cannot verify their bytes.
pub(super) fn check_fetchable(spec: &ImageSpec) -> Result<(), ApiError> {
    match (&spec.url, &spec.sha256) {
        (None, None) => Ok(()),
        (Some(_), None) => Err(invalid(
            "spec.sha256 is required with spec.url; an image fetched over a network and not \
             checked is an image somebody else chooses the contents of",
        )),
        (None, Some(_)) => Err(invalid(
            "spec.sha256 without spec.url is a promise nobody checks; nothing fetches a \
             path-based image",
        )),
        (Some(url), Some(sha256)) => {
            if sha256.len() != 64 || !sha256.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err(invalid(format!(
                    "spec.sha256 {sha256:?} must be 64 hex characters"
                )));
            }
            if sha256.bytes().any(|b| b.is_ascii_uppercase()) {
                return Err(invalid("spec.sha256 must be lowercase"));
            }
            // The node runs `curl`, which speaks more than http. A scheme
            // this control plane has not thought about is refused here rather
            // than discovered on a node — `file://` in particular would make
            // an image mean something different on every machine.
            if !(url.starts_with("http://") || url.starts_with("https://")) {
                return Err(invalid(
                    "spec.url must be http:// or https://; a node fetches this, and a scheme \
                     that means something different on every machine is not an image",
                ));
            }
            Ok(())
        }
    }
}

/// Restrict path-based registrations to identities not confined to a tenant.
/// Such registrations adopt files in a node-wide namespace and could otherwise
/// expose cached bytes from another tenant. Tenant registrations require a URL
/// and checksum. Anonymous mode remains unrestricted.
pub(super) fn check_source_kind(spec: &ImageSpec, confined: Option<&str>) -> Result<(), ApiError> {
    if spec.url.is_some() {
        return Ok(());
    }
    let Some(tenant) = confined else {
        // An operator's path registration is bound to the digest the first
        // node computes of the file (Astra finding S02, 2026-09-23, rest a):
        // `ImageStateReport.digest`, mirrored unchanged through
        // `ImageNodeState.digest`, pinned onto `status.digest` by
        // `first_bound_digest` the first time a node's report carries one,
        // and held to for ever after by `settle_image`'s rule 2b — a later
        // report of different bytes under this name fails the image with
        // `DigestMismatch` rather than going on being `Ready`.
        return Ok(());
    };
    Err(invalid(format!(
        "an image without spec.url and spec.sha256 adopts a file that is already on the nodes, \
         under a name every tenant shares; tenant {tenant:?} has to say where the bytes come \
         from instead — a url and its checksum — and an operator registers the ones that are \
         already there"
    )))
}

/// List owned and public images, then apply the label selector.
pub(super) async fn list_images(
    State(st): State<ApiState>,
    caller: Caller,
    role: CallerRole,
    tenant: CallerTenant,
    axum::extract::Query(q): axum::extract::Query<controller_api::ListQuery>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let selector = controller_api::Selector::parse(q.label_selector.as_deref())?;
    let who = Grant::new(caller, role, tenant).listing(q.tenant.as_deref());
    let mut items = st.store.list::<Image>().await?;
    // A public image is somebody else's object every tenant may boot from, so
    // it survives the confinement — and `?tenant=` too, for the same reason:
    // the question is "what may this tenant use", not "what does it own".
    items.retain(|i| {
        (i.spec.public || who.keeps(i.spec.tenant.as_deref()))
            && selector.selects(&i.metadata.labels)
    });
    Ok(Json(
        json!({ "apiVersion": API_VERSION, "kind": "ImageList", "items": items }),
    ))
}

pub(super) async fn create_image(
    State(st): State<ApiState>,
    caller: Caller,
    role: CallerRole,
    tenant: CallerTenant,
    dry: controller_api::DryRun,
    Json(body): Json<Image>,
) -> Result<(StatusCode, Json<Image>), ApiError> {
    check_envelope(&body)?;
    if body.spec.source.is_empty() {
        return Err(invalid("spec.source must say where the image already is"));
    }
    check_image_name(&body.metadata.name, &body.spec.source)?;
    check_fetchable(&body.spec)?;

    let who = Grant::new(caller, role, tenant);
    check_source_kind(&body.spec, who.confined_to())?;
    let owner = who.tenant_for_create(body.spec.tenant.clone());
    // `public` is deliberately not gated beyond this: publishing an image
    // grants a read of a file every node can already open by path, and a
    // member that may create the catalogue entry may say who else sees it.
    who.allows(
        Scope::image(owner.as_deref(), body.spec.public),
        Verb::Write,
    )?;
    if let Some(t) = &owner {
        check_tenant(&st, t).await?;
    }

    let mut image = Image::declare(
        &body.metadata.name,
        ImageSpec {
            tenant: owner,
            ..body.spec
        },
    );
    image.metadata.labels = body.metadata.labels;
    // Derive phase from node evidence, including for path images.
    // A new image remains Pending/AwaitingNode until a node reports its bytes;
    // dry-run and stored creates use the same derivation.
    image.settle(chrono::Utc::now());
    let created = match dry.preview(&image) {
        Some(preview) => preview,
        None => st.store.create(&image).await?,
    };
    info!(image = %created.metadata.name, tenant = ?created.spec.tenant,
          public = created.spec.public, "image registered");
    Ok((StatusCode::CREATED, Json(created)))
}

pub(super) async fn get_image(
    State(st): State<ApiState>,
    Path(name): Path<String>,
    caller: Caller,
    role: CallerRole,
    tenant: CallerTenant,
) -> Result<Json<Image>, ApiError> {
    let image: Image = st.store.get(&name).await?;
    Grant::new(caller, role, tenant).allows(
        Scope::image(image.spec.tenant.as_deref(), image.spec.public),
        Verb::Read,
    )?;
    Ok(Json(image))
}

/// Refuse deletion while a VM references the image, then request cache removal
/// and delete the catalogue entry. This guard does not inspect Volume base-image
/// references or reserve against concurrent new references.
pub(super) async fn delete_image(
    State(st): State<ApiState>,
    Path(name): Path<String>,
    caller: Caller,
    role: CallerRole,
    tenant: CallerTenant,
) -> Result<controller_api::Removed, ApiError> {
    let image: Image = st.store.get(&name).await?;
    let who = Grant::new(caller, role, tenant);
    who.allows(
        Scope::image(image.spec.tenant.as_deref(), image.spec.public),
        Verb::Write,
    )?;

    let vms = st.store.list::<Vm>().await?;
    // `list` drops what it cannot decode, and a dropped VM is a reference not
    // seen. Refusing to answer beats answering "nothing references it" from a
    // list that is not all of them.
    if vms.len() != st.store.count::<Vm>().await? {
        return Err(conflict(
            "cannot tell whether anything still references this image (some vm objects did not \
             decode); refusing to delete",
        ));
    }
    // Every VM counts, whoever's it is: the invariant this refusal keeps is
    // the catalogue's, not one tenant's. Which of them get NAMED is another
    // question — a public image somebody else booted from must not turn its
    // owner's delete into a listing of another tenant's VMs.
    let holders: Vec<&Vm> = vms
        .iter()
        .filter(|v| base_images(&v.spec.vm).contains(&name))
        .collect();
    if !holders.is_empty() {
        let visible: Vec<String> = holders
            .iter()
            .filter(|v| {
                who.allows(Scope::of(v.spec.tenant.as_deref()), Verb::Read)
                    .is_ok()
            })
            .map(|v| v.metadata.name.clone())
            .collect();
        let detail = match visible.len() {
            0 => format!("{} vm(s), none of them yours", holders.len()),
            n if n == holders.len() => visible.join(", "),
            n => format!(
                "{} (and {} more, not yours)",
                visible.join(", "),
                holders.len() - n
            ),
        };
        return Err(conflict(format!("image {name} is still used by: {detail}")));
    }

    // Ask every locally connected cluster to drop cached copies before deleting
    // the catalogue object. `status.nodes` can lag behind actual cache use.
    // Failures are logged; disconnected clusters receive no durable deletion intent.
    // Keeping the object until after this broadcast permits an operator retry if
    // the process crashes before the store delete.
    for cluster in st.sessions.connected() {
        let op = cloud_command::Op::DropImage(proto::DropImage {
            name: name.clone(),
            uid: image.metadata.uid.clone(),
        });
        if let Err(e) = st.sessions.send_command(&cluster, "", op).await {
            warn!(image = %name, %cluster, error = format!("{e:#}"),
                  "could not tell this cluster to drop the image; its nodes keep their cached \
                   copies until they next hear otherwise");
        }
    }
    st.store.delete::<Image>(&name).await?;
    Ok(controller_api::removed(
        Image::KIND,
        &name,
        controller_api::Removal::Gone,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A registration that adopts a file already on the nodes is an
    /// operator's to make.
    ///
    /// Astra finding S02, 2026-09-23: the catalogue name is the file name on
    /// every node, `delete_image` removes the object and nothing else, and a
    /// path-based registration says "the bytes are already there". Put
    /// together, a member could register the name of an image somebody else
    /// had fetched and boot a VM off bytes nobody meant them to have.
    #[test]
    fn adopting_a_file_that_is_already_there_is_an_operators_to_do() {
        let path_based = ImageSpec {
            source: "/mnt/vmstore/images/nixos.raw".into(),
            ..Default::default()
        };
        let fetchable = ImageSpec {
            source: "nixos.raw".into(),
            url: Some("https://images.example/nixos.raw".into()),
            sha256: Some("a".repeat(64)),
            ..Default::default()
        };

        // A member — anybody `confined_to` one tenant — has to say where the
        // bytes come from.
        let err = format!(
            "{:?}",
            check_source_kind(&path_based, Some("acme")).unwrap_err()
        );
        assert!(err.contains("acme"), "the refusal names the tenant: {err}");
        assert!(err.contains("url"), "and what to do instead: {err}");
        check_source_kind(&fetchable, Some("acme")).expect("a url and a checksum is a claim");

        // An operator, an admin, a system identity and anonymous are not
        // confined, and register what is already on the estate's disks.
        check_source_kind(&path_based, None).expect("the estate is theirs");
        check_source_kind(&fetchable, None).expect("and so is the other kind");
    }

    /// The catalogue is only worth a 422 if its names are the names the node
    /// will look up. A path that disagrees with the object name is a
    /// reference that would resolve here and fail down there.
    #[test]
    fn an_image_name_has_to_be_the_file_the_node_will_look_for() {
        assert!(check_image_name("nixos.raw", "/mnt/nfs/images/nixos.raw").is_ok());
        assert!(check_image_name("nixos.raw", "nixos.raw").is_ok());
        assert!(check_image_name("ubuntu", "/mnt/nfs/images/ubuntu-24.04.raw").is_err());
        assert!(check_image_name("a/b", "/mnt/a/b").is_err());
        assert!(check_image_name("", "x").is_err());
        assert!(check_image_name("..", "/mnt/..").is_err());
    }
}
