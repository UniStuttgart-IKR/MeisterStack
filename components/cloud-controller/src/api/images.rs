// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! The `images` catalogue.

use super::*;

// --- images ----------------------------------------------------------------

/// The catalogue name IS the reference: it is what a VM's `base_image` says,
/// and what the node's block driver then looks up under its own image_dir. v1
/// distributes nothing, so the only way those two namespaces can line up is
/// for the name to be the file name — and a catalogue entry that cannot line
/// up would be worse than no entry at all, because the 422 it buys is a
/// promise the agent goes on to break.
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

/// The two rules a fetchable image has to obey, and both are about the
/// checksum rather than about the URL.
///
/// A URL without one is refused because an image fetched over a network and
/// not checked is an image whose contents somebody else chooses — every VM in
/// the fleet booting whatever answered. And a checksum without a URL is
/// refused because it would be a promise nobody checks: nothing fetches a
/// path image, so nothing would ever compare it, and an operator reading the
/// object would believe otherwise.
///
/// The shape is validated here rather than at the node for the reason every
/// other spec rule is: the node is the last place to find out, and by then
/// somebody is waiting for a VM.
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

/// A member's catalogue is its own images plus the public ones — which is
/// what a shared base image is for, and why the list is not simply filtered
/// to one tenant the way the VM list is.
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

    let url = body.spec.url.clone();
    let mut image = Image::declare(
        &body.metadata.name,
        ImageSpec {
            tenant: owner,
            ..body.spec
        },
    );
    image.metadata.labels = body.metadata.labels;
    // A path image is Ready the moment it is registered: it is a catalogue
    // entry over storage somebody else already filled, and this control plane
    // has never claimed to check it — saying anything else would be inventing
    // a promise where there was none. A URL image is Pending until a node
    // that has fetched it says otherwise, because the node is what fetches.
    image.status.phase = if url.is_some() {
        controller_api::ImagePhase::Pending
    } else {
        controller_api::ImagePhase::Ready
    };
    image.status.message = url
        .is_some()
        .then(|| "not fetched by any node yet".to_string());
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

/// A hard delete, because an image object owns no resource anywhere and there
/// is nothing for a teardown to do — but only once nothing names it. The
/// catalogue's whole job is that "every base_image names an Image" holds, and
/// deleting out from under a VM would break it silently, at the exact moment
/// nobody is looking.
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
