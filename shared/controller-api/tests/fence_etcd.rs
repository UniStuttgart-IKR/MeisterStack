// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Multi-object admission fences against a real etcd.
//!
//! Ignored by default; requires a running etcd:
//!
//! ```text
//! MEISTER_TEST_ETCD=http://127.0.0.1:23700 \
//!   cargo test -p meister-controller-api --test fence_etcd -- --ignored
//! ```

use meister_controller_api::resources::new_volume;
use meister_controller_api::{EtcdStore, StoreError, Volume, VolumeSpec};

fn endpoint() -> String {
    std::env::var("MEISTER_TEST_ETCD").unwrap_or_else(|_| "http://127.0.0.1:23700".to_string())
}

async fn store() -> EtcdStore {
    let prefix = format!("/fence-test/{}", uuid::Uuid::new_v4());
    EtcdStore::connect(&[endpoint()], &prefix)
        .await
        .expect("an etcd to talk to — see the module note")
}

fn volume(name: &str) -> Volume {
    new_volume(
        name,
        VolumeSpec {
            tenant: "acme".into(),
            pool: "disks".into(),
            size_gib: 1,
            ..Default::default()
        },
    )
}

/// Two writers read the same fence; the first goes through and moves it, the
/// second is told to look again — with DIFFERENT names, which is the whole
/// case a per-key compare-and-swap could not see.
#[tokio::test]
#[ignore = "needs a local etcd; see the module note"]
async fn of_two_writers_that_read_one_fence_the_second_looks_again() {
    let store = store().await;
    let seen_by_a = store.fence("quota/acme").await.unwrap();
    let seen_by_b = store.fence("quota/acme").await.unwrap();
    assert_eq!(seen_by_a, seen_by_b);

    let a = store
        .create_fenced(&volume("data-a"), &seen_by_a)
        .await
        .expect("no store error");
    assert!(a.is_some(), "the first through the door gets in");
    let b = store
        .create_fenced(&volume("data-b"), &seen_by_b)
        .await
        .expect("no store error");
    assert!(b.is_none(), "the second is told the fence moved");
    assert!(
        store.get::<Volume>("data-b").await.is_err(),
        "and nothing of it was written"
    );

    // Looking again is what gets it in.
    let again = store.fence("quota/acme").await.unwrap();
    assert_ne!(again, seen_by_b);
    let b = store
        .create_fenced(&volume("data-b"), &again)
        .await
        .unwrap()
        .expect("through, on a fresh look");
    assert_eq!(
        b.metadata.generation, 1,
        "a create is generation 1 either way"
    );

    // A fence of somebody else's is a different door.
    let other = store.fence("quota/globex").await.unwrap();
    store
        .create_fenced(&volume("data-c"), &other)
        .await
        .unwrap()
        .expect("another tenant is not held up");
}

/// A name that is taken is the error `create` gives, not "look again":
/// looking again would never make the name free.
#[tokio::test]
#[ignore = "needs a local etcd; see the module note"]
async fn a_taken_name_is_a_collision_and_not_a_moved_fence() {
    let store = store().await;
    store.create(&volume("data")).await.unwrap();
    let fence = store.fence("quota/acme").await.unwrap();
    let err = store
        .create_fenced(&volume("data"), &fence)
        .await
        .expect_err("the name is taken");
    assert!(matches!(err, StoreError::AlreadyExists(_)), "{err}");
}

/// The update half: a stale fence is "look again", a stale OBJECT is the
/// caller's conflict, exactly as `update` answers it.
#[tokio::test]
#[ignore = "needs a local etcd; see the module note"]
async fn an_update_tells_a_moved_fence_from_a_moved_object() {
    let store = store().await;
    let held = store.create(&volume("data")).await.unwrap();

    let fence = store.fence("quota/acme").await.unwrap();
    // Somebody else goes through the door.
    store
        .create_fenced(&volume("other"), &fence)
        .await
        .unwrap()
        .expect("in");
    let mut grown = held.clone();
    grown.spec.size_gib = 2;
    assert!(
        store.update_fenced(&grown, &fence).await.unwrap().is_none(),
        "the fence moved: look again"
    );

    // Somebody else writes the object itself.
    store
        .mutate::<Volume, _>("data", |v| v.spec.description = "moved".into())
        .await
        .unwrap();
    let fresh = store.fence("quota/acme").await.unwrap();
    let err = store
        .update_fenced(&grown, &fresh)
        .await
        .expect_err("the caller's version is stale");
    assert!(matches!(err, StoreError::Conflict(_)), "{err}");

    // From the current object and a current fence, it goes through.
    let mut current: Volume = store.get("data").await.unwrap();
    current.spec.size_gib = 2;
    let stored = store
        .update_fenced(&current, &fresh)
        .await
        .unwrap()
        .expect("through");
    assert_eq!(stored.spec.size_gib, 2);
    assert_ne!(
        store.fence("quota/acme").await.unwrap(),
        fresh,
        "and it moved the fence"
    );
}
