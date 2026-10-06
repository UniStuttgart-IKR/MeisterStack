// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Admission tests against external etcd. Run the ignored tests with:
//!
//! ```text
//! etcd --data-dir /tmp/ms-admission-etcd \
//! --listen-client-urls http://127.0.0.1:23700 \
//! --advertise-client-urls http://127.0.0.1:23700 \
//! --listen-peer-urls http://127.0.0.1:23701 \
//! --initial-advertise-peer-urls http://127.0.0.1:23701 \
//! --initial-cluster default=http://127.0.0.1:23701
//!
//! MEISTER_TEST_ETCD=http://127.0.0.1:23700 \
//! cargo test -p meister-cloud-controller admission -- --ignored
//! ```
//!
//! Handlers are called directly with extracted grants; these tests cover object
//! authorization and quota admission, not authentication middleware.

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

/// Using an image requires the same read permission as fetching its object.
/// Cross-tenant private images are rejected for VM and volume creation;
/// public images remain usable across tenants.
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

// --- F03: one slot is one admission, however the requests interleave ------

/// Pause the first `parties` admissions after quota checks and before writes.
/// This forces competing requests to observe the same initial usage. Gates are
/// tenant-scoped so parallel tests do not interfere; retries pass through.
static GATES: std::sync::LazyLock<std::sync::Mutex<std::collections::HashMap<String, Gate>>> =
    std::sync::LazyLock::new(Default::default);

/// One tenant's gate: the barrier, and how many admissions it still holds.
type Gate = (Arc<tokio::sync::Barrier>, usize);

fn hold_admissions(tenant: &str, parties: usize) {
    GATES.lock().unwrap().insert(
        tenant.to_string(),
        (Arc::new(tokio::sync::Barrier::new(parties)), parties),
    );
}

/// Called by the handlers after the quota has been looked at and before the
/// write. A no-op for every tenant no test is holding.
pub(super) async fn admission_gate(tenant: &str) {
    let barrier = {
        let mut gates = GATES.lock().unwrap();
        match gates.get_mut(tenant) {
            Some((barrier, left)) if *left > 0 => {
                *left -= 1;
                Some(barrier.clone())
            }
            _ => None,
        }
    };
    if let Some(barrier) = barrier {
        barrier.wait().await;
    }
}

/// A tenant of this test's own, with `quota`, created through `st`.
async fn racing_tenant(st: &ApiState, quota: controller_api::TenantQuota) -> String {
    let name = format!("r-{}", &uuid::Uuid::new_v4().simple().to_string()[..12]);
    st.store
        .create(&Tenant::declare(
            &name,
            TenantSpec {
                quota,
                ..Default::default()
            },
        ))
        .await
        .expect("a tenant");
    name
}

/// Two replicas of one cloud: two connections, one store underneath — which
/// is what a cloud behind a load balancer is.
async fn two_replicas(what: &str) -> (ApiState, ApiState) {
    let prefix = fresh_prefix(what);
    let one = replica(&prefix).await;
    let two = replica(&prefix).await;
    one.store
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
    (one, two)
}

/// Exactly one of two results is a success, and the other is a refusal.
fn exactly_one<T>(a: Result<T, ApiError>, b: Result<T, ApiError>) -> ApiError {
    match (a, b) {
        (Ok(_), Err(e)) | (Err(e), Ok(_)) => e,
        (Ok(_), Ok(_)) => panic!("both were admitted into one slot"),
        (Err(a), Err(b)) => panic!("neither was admitted: {} / {}", a.message(), b.message()),
    }
}

/// F03: one VM slot left, two creates, two replicas — and both have looked at
/// the quota before either has written.
///
/// The quota check read the VM list and the create then wrote a key of its
/// own, so the compare-and-swap on that key protected the key and nothing
/// else: two requests that each saw "0 of 1" each wrote a VM, and the tenant
/// held two. The gate below makes exactly that interleaving happen.
#[tokio::test]
#[ignore = "needs an etcd; see the module note"]
async fn one_vm_slot_is_one_vm_however_two_replicas_interleave() {
    let (one, two) = two_replicas("f03-vm").await;
    let tenant = racing_tenant(
        &one,
        controller_api::TenantQuota {
            max_vms: Some(1),
            ..Default::default()
        },
    )
    .await;

    hold_admissions(&tenant, 2);
    let (a, b) = tokio::join!(
        create_vm_as(&one, member(&tenant), vm("vm-a", &tenant, None, 1)),
        create_vm_as(&two, member(&tenant), vm("vm-b", &tenant, None, 1)),
    );
    let refused = exactly_one(a, b);
    assert_eq!(refused.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert!(
        refused.message().contains("its quota is 1"),
        "the loser is told about the quota, not about a race: {}",
        refused.message()
    );
    let held = one
        .store
        .list::<Vm>()
        .await
        .unwrap()
        .into_iter()
        .filter(|v| v.spec.tenant.as_deref() == Some(tenant.as_str()))
        .count();
    assert_eq!(held, 1, "and the store holds one");
}

/// The same for storage: ten GiB, two six-GiB volumes.
#[tokio::test]
#[ignore = "needs an etcd; see the module note"]
async fn one_storage_slot_is_one_volume_however_two_replicas_interleave() {
    let (one, two) = two_replicas("f03-volume").await;
    let tenant = racing_tenant(&one, Default::default()).await;
    storage_quota(&one, &tenant, 10).await;

    hold_admissions(&tenant, 2);
    let (a, b) = tokio::join!(
        create_volume_as(&one, member(&tenant), volume("data-a", &tenant, 6, None)),
        create_volume_as(&two, member(&tenant), volume("data-b", &tenant, 6, None)),
    );
    let refused = exactly_one(a, b);
    assert_eq!(refused.status(), StatusCode::CONFLICT);
    assert!(
        refused.message().contains("quota there is 10 GiB"),
        "{}",
        refused.message()
    );
}

/// And for growing: two one-GiB volumes, ten GiB of room, both grown to six
/// at once. F02 put the resize through the quota; this is that check under
/// the same race.
#[tokio::test]
#[ignore = "needs an etcd; see the module note"]
async fn two_resizes_into_one_slot_are_one_resize() {
    let (one, two) = two_replicas("f03-resize").await;
    let tenant = racing_tenant(&one, Default::default()).await;
    storage_quota(&one, &tenant, 10).await;
    for name in ["data-a", "data-b"] {
        create_volume_as(&one, member(&tenant), volume(name, &tenant, 1, None))
            .await
            .expect("room for both");
    }

    hold_admissions(&tenant, 2);
    let (a, b) = tokio::join!(
        resize_volume_as(&one, member(&tenant), "data-a", 6),
        resize_volume_as(&two, member(&tenant), "data-b", 6),
    );
    let refused = exactly_one(a, b);
    assert_eq!(refused.status(), StatusCode::CONFLICT);
    let sizes: u64 = one
        .store
        .list::<Volume>()
        .await
        .unwrap()
        .iter()
        .filter(|v| v.spec.tenant == tenant)
        .map(|v| v.spec.size_gib)
        .sum();
    assert_eq!(sizes, 7, "six and one, inside ten");
}

/// No gate at all: sixteen creates at once across two replicas, room for two.
///
/// The tests above force the one interleaving that used to break; this one
/// lets the runtime pick, and holds the rule over whatever it picked. Every
/// request is either admitted or told about the quota — none of them is told
/// about a race it did not cause.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs an etcd; see the module note"]
async fn two_slots_are_two_vms_under_any_interleaving() {
    let (one, two) = two_replicas("f03-many").await;
    let tenant = racing_tenant(
        &one,
        controller_api::TenantQuota {
            max_vms: Some(2),
            ..Default::default()
        },
    )
    .await;

    let mut asks = tokio::task::JoinSet::new();
    for i in 0..16 {
        let st = if i % 2 == 0 { one.clone() } else { two.clone() };
        let tenant = tenant.clone();
        asks.spawn(async move {
            create_vm_as(
                &st,
                member(&tenant),
                vm(&format!("vm-{i}"), &tenant, None, 1),
            )
            .await
        });
    }
    let (mut admitted, mut refused) = (0, 0);
    while let Some(answer) = asks.join_next().await {
        match answer.expect("the task") {
            Ok(_) => admitted += 1,
            Err(e) => {
                assert_eq!(
                    e.status(),
                    StatusCode::UNPROCESSABLE_ENTITY,
                    "{}",
                    e.message()
                );
                assert!(e.message().contains("its quota is 2"), "{}", e.message());
                refused += 1;
            }
        }
    }
    assert_eq!((admitted, refused), (2, 14));
}

/// A VM for `tenant` whose cloud-init block is exactly `cloud_init` — the
/// counterpart to `vm` above, for the cases that turn on the block's shape
/// rather than on its disk.
fn vm_with_cloud_init(name: &str, tenant: &str, cloud_init: serde_json::Value) -> Vm {
    let spec: VmSpec = serde_json::from_value(json!({
        "tenant": tenant,
        "vm": {
            "vcpus": 1,
            "memory_mib": 512,
            "boot": {"kind": "firmware", "firmware": "fw"},
            "volumes": [{ "size_bytes": 1073741824u64 }],
            "cloud_init": cloud_init,
        },
    }))
    .expect("a vm spec");
    new_vm(name, spec)
}

/// Astra finding S21, 2026-09-23: `cloud_init.user_data_from` used to be
/// refused at the door with "unknown field", before the checks right below —
/// which already knew how to read it — ever got a look at it. The node-side
/// schema (`agent_api::spec::CloudInit`) stays strict; this is the edge that
/// has to accept the reference itself, so `check_volume_refs` can validate it
/// here, where a person is still holding the request, and the cluster tier
/// can resolve it later.
#[tokio::test]
#[ignore = "needs an etcd; see the module note"]
async fn a_cloud_init_secret_reference_is_accepted_and_checked() {
    let st = cloud("f21").await;
    st.store
        .create(&controller_api::Secret::declare(
            "db",
            controller_api::SecretSpec {
                tenant: "a".into(),
                data: [("password".to_string(), "s3kr3t".to_string())]
                    .into_iter()
                    .collect(),
                ..Default::default()
            },
        ))
        .await
        .expect("a secret");

    // The reference alone, with no literal beside it — exactly the shape
    // that used to be "unknown field `user_data_from`".
    let created = create_vm_as(
        &st,
        member("a"),
        vm_with_cloud_init(
            "web",
            "a",
            json!({ "user_data_from": { "secret": "db", "key": "password" } }),
        ),
    )
    .await
    .expect("a reference to this tenant's own secret is not malformed");
    assert_eq!(
        created.spec.vm["cloud_init"]["user_data_from"]["secret"], "db",
        "the reference travels unresolved out of the cloud — that is the cluster's job"
    );

    // A key the secret does not have is refused HERE, where a person is
    // still holding the request, and not three tiers down as a Failed VM.
    let bad_key = create_vm_as(
        &st,
        member("a"),
        vm_with_cloud_init(
            "web2",
            "a",
            json!({ "user_data_from": { "secret": "db", "key": "nope" } }),
        ),
    )
    .await
    .expect_err("db has no key \"nope\"");
    assert_eq!(bad_key.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert!(bad_key.message().contains("nope"), "{}", bad_key.message());

    // Somebody else's secret is the 404 an unknown volume gets, for the same
    // reason: a 403 would confirm that a secret of that name exists.
    let unknown = create_vm_as(
        &st,
        member("b"),
        vm_with_cloud_init(
            "web3",
            "b",
            json!({ "user_data_from": { "secret": "db", "key": "password" } }),
        ),
    )
    .await
    .expect_err("b has no secret named db");
    assert_eq!(unknown.status(), StatusCode::NOT_FOUND);
}

/// The structural half of the same rule, both directions: `cloud_init` needs
/// exactly one starting point. "Both" was already refused before this
/// finding — `user_data_said_twice` — but only once the block could be
/// parsed at all; "neither" is new, because `user_data` stopped being the
/// one required field that made an empty block impossible to write.
#[tokio::test]
#[ignore = "needs an etcd; see the module note"]
async fn a_cloud_init_naming_neither_or_both_a_literal_and_a_reference_is_refused() {
    let st = cloud("f21-shape").await;

    let neither = create_vm_as(&st, member("a"), vm_with_cloud_init("web", "a", json!({})))
        .await
        .expect_err("a cloud_init with no starting point");
    assert_eq!(neither.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert!(
        neither.message().contains("needs a starting point"),
        "{}",
        neither.message()
    );

    let both = create_vm_as(
        &st,
        member("a"),
        vm_with_cloud_init(
            "web2",
            "a",
            json!({
                "user_data": "#cloud-config\n",
                "user_data_from": { "secret": "db", "key": "password" },
            }),
        ),
    )
    .await
    .expect_err("a cloud_init naming both a literal and a reference");
    assert_eq!(both.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert!(
        both.message().contains("two starting points"),
        "{}",
        both.message()
    );
}

// --- IKR-B68: a floating address goes through its tenant's own router ------

/// A private pool for the reservations below, and a router for each tenant.
async fn cloud_with_routers(what: &str) -> ApiState {
    let st = cloud(what).await;
    st.store
        .create(&FloatingPool::declare(
            "lab",
            controller_api::FloatingPoolSpec {
                cidrs: vec!["198.51.100.0/24".into()],
                default: true,
                ..Default::default()
            },
        ))
        .await
        .expect("a pool");
    for (tenant, inside) in [("a", "10.42.0.1/24"), ("b", "10.77.0.1/24")] {
        st.store
            .create(&controller_api::Router::declare(
                &format!("{tenant}-out"),
                controller_api::RouterSpec {
                    tenant: tenant.into(),
                    provider_network: "ext".into(),
                    internal_addr: inside.into(),
                    ..Default::default()
                },
            ))
            .await
            .expect("a router");
    }
    st
}

async fn reserve_as(
    st: &ApiState,
    who: (Caller, CallerRole, CallerTenant),
    router: &str,
    inside: &str,
) -> Result<FloatingIp, ApiError> {
    let (caller, role, tenant) = who;
    let body = FloatingIp::declare(
        "",
        controller_api::FloatingIpSpec {
            router: router.into(),
            internal_address: inside.into(),
            ..Default::default()
        },
    );
    create_floating_ip(
        State(st.clone()),
        caller,
        role,
        tenant,
        DryRun::default(),
        Json(body),
    )
    .await
    .map(|(_, Json(ip))| ip)
}

/// The lab's repro: a router that does not exist, another tenant's router,
/// and an inside end off the router's prefix were all reserved.
#[tokio::test]
#[ignore = "needs an etcd; see the module note"]
async fn a_floating_address_is_bound_only_to_its_tenants_router_and_inside_prefix() {
    let st = cloud_with_routers("b68").await;
    for (router, inside, field) in [
        ("no-such-router", "10.42.0.9", "spec.router"),
        ("b-out", "10.77.0.10", "spec.router"),
        ("a-out", "10.128.1.103", "spec.internalAddress"),
        ("a-out", "10.42.0.1", "spec.internalAddress"),
    ] {
        let err = reserve_as(&st, member("a"), router, inside)
            .await
            .expect_err("not a's own way in");
        assert_eq!(
            err.field(),
            Some(field),
            "{router} {inside}: {}",
            err.message()
        );
    }
    // The missing router and b's router read the same: nothing of b's is named.
    let foreign = reserve_as(&st, member("a"), "b-out", "10.77.0.10")
        .await
        .expect_err("b's router");
    assert!(
        !foreign.message().contains("tenant b"),
        "{}",
        foreign.message()
    );

    let ok = reserve_as(&st, member("a"), "a-out", "10.42.0.9")
        .await
        .expect("a guest behind a's own router");
    assert_eq!(ok.spec.router, "a-out");

    // And an update is held to the same rule.
    let (caller, role, tenant) = member("a");
    let mut moved = ok.clone();
    moved.spec.router = "b-out".into();
    let err = update_floating_ip(
        State(st.clone()),
        Path(ok.metadata.name.clone()),
        caller,
        role,
        tenant,
        DryRun::default(),
        Json(moved),
    )
    .await
    .map(|Json(ip)| ip)
    .expect_err("re-pointed at b's router");
    assert_eq!(err.field(), Some("spec.router"));
}

/// A rollback takes back the object its create made. (IKR-B81)
#[tokio::test]
#[ignore = "needs an etcd; see the module doc"]
async fn a_take_back_removes_what_the_create_made() {
    let st = replica(&fresh_prefix("take-back")).await;
    let created = st
        .store
        .create(&StoragePool::declare("spare", StoragePoolSpec::default()))
        .await
        .expect("the create that lost its race");

    controller_api::deletion::take_back_created(&st.store, &created)
        .await
        .expect("taken back");

    assert!(matches!(
        st.store.get::<StoragePool>("spare").await,
        Err(StoreError::NotFound(_))
    ));
}

/// A rollback leaves what somebody else made under the name since, and that is
/// a rollback done, not an error. (IKR-B81)
#[tokio::test]
#[ignore = "needs an etcd; see the module doc"]
async fn a_take_back_leaves_an_object_made_again_under_the_name() {
    let st = replica(&fresh_prefix("take-back")).await;
    let created = st
        .store
        .create(&StoragePool::declare("spare", StoragePoolSpec::default()))
        .await
        .expect("the create that lost its race");
    st.store
        .delete::<StoragePool>("spare")
        .await
        .expect("it went");
    let theirs = st
        .store
        .create(&StoragePool::declare("spare", StoragePoolSpec::default()))
        .await
        .expect("somebody else's");

    controller_api::deletion::take_back_created(&st.store, &created)
        .await
        .expect("nothing of ours is left");

    let stays: StoragePool = st.store.get("spare").await.expect("theirs stays");
    assert_eq!(stays.metadata.uid, theirs.metadata.uid);
}
