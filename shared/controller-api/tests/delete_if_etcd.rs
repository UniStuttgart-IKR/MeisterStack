// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Revision-guarded delete cannot remove an object recreated under the same name.
//!
//! Ignored by default; requires a running etcd:
//!
//! ```text
//! MEISTER_TEST_ETCD=http://127.0.0.1:23700 \
//!   cargo test -p meister-controller-api --test delete_if_etcd -- --ignored
//! ```

use meister_controller_api::{EtcdStore, Secret, SecretSpec, StoreError};

fn endpoint() -> String {
    std::env::var("MEISTER_TEST_ETCD").unwrap_or_else(|_| "http://127.0.0.1:23700".to_string())
}

async fn store() -> EtcdStore {
    let prefix = format!("/delete-if-test/{}", uuid::Uuid::new_v4());
    EtcdStore::connect(&[endpoint()], &prefix)
        .await
        .expect("an etcd to talk to — see the module note")
}

fn secret(tenant: &str) -> Secret {
    Secret::declare(
        "db",
        SecretSpec {
            tenant: tenant.to_string(),
            data: [("password".to_string(), "s3kr3t".to_string())]
                .into_iter()
                .collect(),
            ..Default::default()
        },
    )
}

/// A revision-guarded delete must reject a secret recreated under the same
/// name after authorization, preserving the replacement tenant's object.
#[tokio::test]
#[ignore = "needs a local etcd; see the module note"]
async fn a_delete_does_not_remove_a_secret_that_was_recreated_under_the_same_name() {
    let store = store().await;

    let a_read = store.create(&secret("acme")).await.expect("A's secret");
    let a_saw_rev = a_read.metadata.resource_version.clone();

    // The object A read is gone, and a different tenant now holds the name.
    store.delete::<Secret>("db").await.expect("removed");
    let b_owns = store.create(&secret("globex")).await.expect("B's secret");
    assert_ne!(
        b_owns.metadata.uid, a_read.metadata.uid,
        "a fresh create is a fresh uid, which is the whole point"
    );

    // A's paused delete resumes and finds the name occupied by an object
    // whose resource_version it never read.
    let err = store
        .delete_if::<Secret>("db", &a_saw_rev)
        .await
        .expect_err("the name means somebody else's secret now");
    assert!(matches!(err, StoreError::Conflict(_)), "{err}");

    let still: Secret = store.get("db").await.expect("B's secret is untouched");
    assert_eq!(still.metadata.uid, b_owns.metadata.uid);
    assert_eq!(still.spec.tenant, "globex", "not acme's");

    // The ordinary case, for the other half of the guard: a delete against
    // the resource_version actually there goes through.
    store
        .delete_if::<Secret>("db", &still.metadata.resource_version)
        .await
        .expect("B deleting B's own secret, current version, is not a conflict");
    assert!(store.get::<Secret>("db").await.is_err(), "and it is gone");
}
