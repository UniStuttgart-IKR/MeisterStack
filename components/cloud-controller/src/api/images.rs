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
            check_url_shape(url)
        }
    }
}

/// The shape an image url must have before any node is asked to fetch it.
///
/// Astra finding R3-F10, 2026-09-25: this used to be a prefix check, so any
/// http(s) target was accepted from a member and fetched by a node from
/// inside the management network. The node is where the real decision is
/// made -- it knows its `[images] allowed_sources` and what a name resolves
/// to (`meister-agent`'s `images::egress`) -- but a url no node would ever
/// fetch is refused here, where the person writing it can still be told:
/// only http and https (`file://` would mean a different file on every
/// machine), no user name or password, ports 80 and 443 only, one strict
/// spelling of the host (`common::fetch_url`, the parser the node uses too),
/// and no address literal that is loopback, link-local or a metadata
/// address. A private-range literal passes here: whether a node may reach
/// it is the node's list to say.
pub(super) fn check_url_shape(url: &str) -> Result<(), ApiError> {
    use common::fetch_url::{AddrClass, FetchUrl, Host, classify};
    let parsed = FetchUrl::parse(url).map_err(|why| invalid(format!("spec.url: {why}")))?;
    if !parsed.port_allowed() {
        return Err(invalid(format!(
            "spec.url names port {}; a node fetches images from ports 80 and 443 only",
            parsed.port
        )));
    }
    if let Host::Ip(addr) = parsed.host
        && classify(addr) == AddrClass::Never
    {
        return Err(invalid(format!(
            "spec.url points at {addr}, a loopback, link-local, multicast or metadata \
             address; no node fetches an image from there"
        )));
    }
    Ok(())
}

/// Whose registration a PATH-based image may be, and why it is not
/// everybody's.
///
/// Astra finding S02, 2026-09-23. A registration with no url and no checksum
/// says: "the bytes are already on the node, under this name". It names a
/// file this control plane has never seen and cannot check, in a namespace
/// every tenant shares — the catalogue name IS the file name, on every node —
/// and `delete_image` removes the catalogue entry without removing anything
/// from any node. So a tenant could register the NAME of an image somebody
/// else had fetched, take the bytes that are still lying there, and boot a
/// VM off them. Nothing in the object would look wrong.
///
/// The line is `Operator`, the same line `Grant::confined_to` draws
/// everywhere else, and it is the honest one: adopting a file that is already
/// on a node is a statement about the node's disk, and whoever runs the
/// estate can already put anything on that disk. A member has no such
/// standing and now has to say where the bytes come from — a url and a
/// checksum, which is a claim this control plane can hold them to.
///
/// Anonymous mode says yes, here as it does everywhere else; that is the mode
/// the lab has run in since M1.
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
    // Nothing is stamped here any more, and that is F16.
    //
    // A path image used to be `Ready` the moment it was registered — the
    // argument was that a catalogue entry over storage somebody else filled
    // is not this control plane's to check. But `Ready` is not "we make no
    // claim", it is a claim, and the chaos run found an entry pointing at
    // nothing wearing it for as long as anybody looked. A VM booting from it
    // failed at the node with the storage driver's own words.
    //
    // The phase is derived now (`settle_image`), out of `status.nodes[]` and
    // nothing else, so a fresh image of either kind is
    // `Pending { AwaitingNode }` until a node has said something about the
    // bytes. `dry.preview` sees the same value a create would store, because
    // the derivation runs on the object and not in the store.
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

    // The nodes are told next, exactly the way a deleted secret's mirrored
    // copies are (`delete_secret`): every cluster this replica is talking to,
    // one command each, and a cluster that does not answer is logged and
    // left. Astra finding S02, 2026-09-23 (rest b).
    //
    // `status.nodes[]` would name fewer clusters — only the ones this image
    // has been SEEN on — but that list is only ever as fresh as the last
    // heartbeat that changed it, and a cluster whose report is running behind
    // is exactly the one this must not skip. A cluster the image was never on
    // gets a command its nodes answer with nothing to do.
    //
    // Before the store delete and not after: what this loses on a crash
    // between the two is a broadcast the object is still there to retry (an
    // operator can delete again, or a retry loop can). The other order would
    // lose the ability to tell the nodes at all, which is the defect this
    // closes.
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

    /// Astra finding R3-F10, 2026-09-25: the url is held to one strict shape
    /// before any node is asked to fetch it.
    #[test]
    fn an_image_url_no_node_would_fetch_is_refused_at_create() {
        let spec = |url: &str| ImageSpec {
            source: "x.raw".into(),
            url: Some(url.into()),
            sha256: Some("a".repeat(64)),
            ..Default::default()
        };
        for ok in [
            "https://cloud-images.ubuntu.com/noble/x.img",
            "http://mirror.example:80/x.raw",
            "http://10.0.8.21/x.raw",
        ] {
            check_fetchable(&spec(ok)).unwrap_or_else(|e| panic!("{ok}: {e:?}"));
        }
        for bad in [
            "file:///etc/passwd",
            "http://user:pw@mirror.example/x.raw",
            "http://mirror.example:8080/x.raw",
            "http://127.0.0.1/x.raw",
            "http://169.254.169.254/latest/meta-data/",
            "http://[::1]/x.raw",
            "http://2130706433/x.raw",
            "gopher://mirror.example/x",
        ] {
            assert!(
                check_fetchable(&spec(bad)).is_err(),
                "{bad} should be refused"
            );
        }
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
