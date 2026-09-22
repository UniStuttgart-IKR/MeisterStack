// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! The admission edge against a real etcd: what a caller may USE, and how
//! much of it a tenant may hold.
//!
//! `#[ignore]` for the reason `tickets_etcd` is: the handlers read and write
//! the store, and the workspace's ordinary run has nothing to talk to. Start
//! one and name it:
//!
//! ```text
//! etcd --data-dir /tmp/ms-admission-etcd \
//!      --listen-client-urls http://127.0.0.1:23700 \
//!      --advertise-client-urls http://127.0.0.1:23700 \
//!      --listen-peer-urls http://127.0.0.1:23701 \
//!      --initial-advertise-peer-urls http://127.0.0.1:23701 \
//!      --initial-cluster default=http://127.0.0.1:23701
//!
//! MEISTER_TEST_ETCD=http://127.0.0.1:23700 \
//!   cargo test -p meister-cloud-controller admission -- --ignored
//! ```
//!
//! The handlers are called directly, with the extractor values the guard
//! would have produced: what is under test is the object half of the policy
//! and the arithmetic, not the middleware in front of them.

use super::*;
use controller_api::auth::{GROUP_ADMINS, GROUP_MEMBERS, Identity, Role};
use controller_api::rest::{Caller, CallerRole, CallerTenant, DryRun};
use controller_api::{ImageSpec, StoragePoolSpec, TenantSpec, VolumeSpec};

/// The endpoint the etcd above is listening on.
fn endpoint() -> String {
    std::env::var("MEISTER_TEST_ETCD").unwrap_or_else(|_| "http://127.0.0.1:23700".to_string())
}

/// One replica of a cloud, over a prefix of its own: a failed run leaves
/// nothing the next one trips over. `prefix` is shared by the two replicas of
/// the concurrency tests, which is what makes them one cloud.
async fn replica(prefix: &str) -> ApiState {
    let store = Arc::new(
        EtcdStore::connect(&[endpoint()], prefix)
            .await
            .expect("an etcd to talk to — see the module note"),
    );
    ApiState {
        store: store.clone(),
        sessions: Arc::new(crate::session::SessionRegistry::new()),
        signing: None,
        vni_base: 10_000,
        routed_pools: Arc::new(Vec::new()),
        advertise: None,
        overcommit: controller_api::Overcommit::default(),
        scheduler: Arc::new(controller_api::FirstFit),
        kek: None,
        tickets: Arc::new(controller_api::tickets::Tickets::new(store)),
        sibling: controller_api::forward::Sibling {
            serves_tls: false,
            tls: None,
        },
    }
}

fn fresh_prefix(what: &str) -> String {
    format!("/admission-test/{what}/{}", uuid::Uuid::new_v4())
}

/// A cloud with two tenants, a default pool, and two images owned by `a`:
/// one private, one public.
async fn cloud(what: &str) -> ApiState {
    let st = replica(&fresh_prefix(what)).await;
    for tenant in ["a", "b"] {
        st.store
            .create(&Tenant::declare(tenant, TenantSpec::default()))
            .await
            .expect("a tenant");
    }
    st.store
        .create(&StoragePool::declare(
            "disks",
            StoragePoolSpec {
                driver: "filesystem".into(),
                default: true,
                cluster: "c1".into(),
                ..Default::default()
            },
        ))
        .await
        .expect("a pool");
    for (name, public) in [("private-a.raw", false), ("public-a.raw", true)] {
        st.store
            .create(&Image::declare(
                name,
                ImageSpec {
                    source: format!("/images/{name}"),
                    tenant: Some("a".into()),
                    public,
                    ..Default::default()
                },
            ))
            .await
            .expect("an image");
    }
    st
}

/// What the guard hands a handler for a member of `tenant`.
fn member(tenant: &str) -> (Caller, CallerRole, CallerTenant) {
    (
        Caller(Some(Identity::new(
            format!("someone-in-{tenant}"),
            vec![GROUP_MEMBERS.into()],
        ))),
        CallerRole(Some(Role::Member)),
        CallerTenant(Some(tenant.to_string())),
    )
}

fn admin() -> (Caller, CallerRole, CallerTenant) {
    (
        Caller(Some(Identity::new("root", vec![GROUP_ADMINS.into()]))),
        CallerRole(Some(Role::Admin)),
        CallerTenant(None),
    )
}

fn grant((caller, role, tenant): (Caller, CallerRole, CallerTenant)) -> Grant {
    Grant::new(caller, role, tenant)
}

/// A VM for `tenant` whose one disk is seeded from `image`, or blank.
fn vm(name: &str, tenant: &str, image: Option<&str>, vcpus: u32) -> Vm {
    let mut disk = json!({ "size_bytes": 1073741824u64 });
    if let Some(image) = image {
        disk["base_image"] = json!(image);
    }
    let spec: VmSpec = serde_json::from_value(json!({
        "tenant": tenant,
        "vm": {
            "vcpus": vcpus,
            "memory_mib": 512,
            "boot": {"kind": "firmware", "firmware": "fw"},
            "volumes": [disk],
        },
    }))
    .expect("a vm spec");
    new_vm(name, spec)
}

fn volume(name: &str, tenant: &str, gib: u64, image: Option<&str>) -> Volume {
    new_volume(
        name,
        VolumeSpec {
            tenant: tenant.into(),
            size_gib: gib,
            base_image: image.map(str::to_string),
            ..Default::default()
        },
    )
}

async fn create_vm_as(
    st: &ApiState,
    who: (Caller, CallerRole, CallerTenant),
    body: Vm,
) -> Result<Vm, ApiError> {
    create_vm_traced(
        st.clone(),
        grant(who),
        body,
        DryRun::default(),
        telemetry::TraceParent::parse_or_root(None),
    )
    .await
    .map(|(_, Json(vm))| vm)
}

async fn create_volume_as(
    st: &ApiState,
    who: (Caller, CallerRole, CallerTenant),
    body: Volume,
) -> Result<Volume, ApiError> {
    let (caller, role, tenant) = who;
    create_volume(
        State(st.clone()),
        caller,
        role,
        tenant,
        DryRun::default(),
        Json(body),
    )
    .await
    .map(|(_, Json(v))| v)
}

// --- F01: an image is used on the terms it is read on ---------------------

/// A private image is somebody's, and naming it in a disk is a way of READING
/// it: the bytes end up on the new disk, where the tenant who named it can
/// read every one of them. So using one has to need what reading one needs.
///
/// The direct read was always refused; the reference was only asked whether
/// the image exists and has not failed. This holds the two together: a member
/// of `b` who knows the name of `a`'s private image gets exactly as far
/// through a VM or a volume as through `GET /images/<name>` — and a public
/// image, which is what sharing one means, goes on working for everybody.
#[tokio::test]
#[ignore = "needs an etcd; see the module note"]
async fn an_image_is_used_on_the_terms_it_is_read_on() {
    let st = cloud("f01").await;

    // The direct read, which has always said no.
    let (caller, role, tenant) = member("b");
    let read = get_image(
        State(st.clone()),
        Path("private-a.raw".to_string()),
        caller,
        role,
        tenant,
    )
    .await
    .map(|Json(image)| image)
    .expect_err("b may not read a's private image");
    assert_eq!(read.status(), StatusCode::FORBIDDEN);

    // Through a VM's disk. The refusal is the one an unknown name gets:
    // telling a guesser that this name exists and is somebody else's is the
    // thing a 404-shaped answer is for.
    let used = create_vm_as(&st, member("b"), vm("web", "b", Some("private-a.raw"), 1))
        .await
        .expect_err("b may not boot from a's private image either");
    assert_eq!(used.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert!(
        used.message().contains("unknown base_image"),
        "{}",
        used.message()
    );
    assert!(
        st.store.get::<Vm>("web").await.is_err(),
        "and nothing was written"
    );

    // Through a Volume's seed, the other place a base image is named.
    let seeded = create_volume_as(
        &st,
        member("b"),
        volume("data", "b", 1, Some("private-a.raw")),
    )
    .await
    .expect_err("nor seed a disk from it");
    assert_eq!(seeded.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert!(
        seeded.message().contains("unknown base_image"),
        "{}",
        seeded.message()
    );

    // A public image is somebody else's object that everybody may boot from,
    // and that is what it is for.
    create_vm_as(&st, member("b"), vm("web", "b", Some("public-a.raw"), 1))
        .await
        .expect("a public image is b's to use");
    create_volume_as(
        &st,
        member("b"),
        volume("data", "b", 1, Some("public-a.raw")),
    )
    .await
    .expect("and to seed a disk from");

    // The owner uses its own private image, and an admin — who may read it —
    // may use it too, for somebody else.
    create_vm_as(&st, member("a"), vm("own", "a", Some("private-a.raw"), 1))
        .await
        .expect("a's own image");
    create_vm_as(&st, admin(), vm("placed", "b", Some("private-a.raw"), 1))
        .await
        .expect("an admin reads every image, so it may use every image");
}

/// A PUT of a volume, as a client that read it and changed the size sends it.
async fn resize_volume_as(
    st: &ApiState,
    who: (Caller, CallerRole, CallerTenant),
    name: &str,
    gib: u64,
) -> Result<Volume, ApiError> {
    let mut body: Volume = st.store.get(name).await.expect("the volume");
    body.spec.size_gib = gib;
    let (caller, role, tenant) = who;
    update_volume(
        State(st.clone()),
        Path(name.to_string()),
        caller,
        role,
        tenant,
        DryRun::default(),
        Json(body),
    )
    .await
    .map(|Json(v)| v)
}

/// Give `tenant` a ceiling of `gib` in the default pool.
async fn storage_quota(st: &ApiState, tenant: &str, gib: u64) {
    st.store
        .mutate::<StoragePool, _>("disks", |p| {
            p.spec.quota.insert(tenant.to_string(), gib);
        })
        .await
        .expect("the pool");
}

// --- F02: growing a volume is creating that much storage ------------------

/// `StorageUsage::of` has had an `except` since it was written, "so that
/// resizing one is measured exactly like creating one that size" — and the
/// resize never asked it. `spec.sizeGib` became growable with storage B and
/// went through `check_owned` and nothing else, so a tenant with ten GiB made
/// a one-GiB volume and grew it to a hundred.
#[tokio::test]
#[ignore = "needs an etcd; see the module note"]
async fn growing_a_volume_is_held_to_the_ceiling_creating_it_would_be() {
    let st = cloud("f02").await;
    storage_quota(&st, "b", 10).await;

    create_volume_as(&st, member("b"), volume("data", "b", 1, None))
        .await
        .expect("one GiB of ten");

    let refused = resize_volume_as(&st, member("b"), "data", 100)
        .await
        .expect_err("a hundred GiB is past a ceiling of ten");
    assert_eq!(refused.status(), StatusCode::CONFLICT);
    assert!(
        refused.message().contains("quota there is 10 GiB"),
        "the sentence names the ceiling: {}",
        refused.message()
    );
    let held: Volume = st.store.get("data").await.expect("the volume");
    assert_eq!(held.spec.size_gib, 1, "and the spec did not move");

    // The volume's own old size comes out of the sum and its new size goes
    // back in: ten exactly is inside a ceiling of ten, eleven is not.
    resize_volume_as(&st, member("b"), "data", 10)
        .await
        .expect("growing to the ceiling itself");
    resize_volume_as(&st, member("b"), "data", 11)
        .await
        .expect_err("one past it");

    // And an edit that does not grow anything is not a quota question at all,
    // even for a tenant an operator has since put under water.
    storage_quota(&st, "b", 5).await;
    let mut body: Volume = st.store.get("data").await.expect("the volume");
    body.spec.description = "still ten".into();
    let (caller, role, tenant) = member("b");
    update_volume(
        State(st.clone()),
        Path("data".to_string()),
        caller,
        role,
        tenant,
        DryRun::default(),
        Json(body),
    )
    .await
    .map(|Json(v)| v)
    .expect("a description is not storage");
}
