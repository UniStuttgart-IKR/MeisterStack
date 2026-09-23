// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! `mutate_if` against a real etcd: the same ABA `delete_if` guards against
//! (see `delete_if_etcd`), one write instead of one delete.
//!
//! `#[ignore]` for the reason `fence_etcd` is. Start an etcd and name it:
//!
//! ```text
//! MEISTER_TEST_ETCD=http://127.0.0.1:23700 \
//!   cargo test -p meister-controller-api --test mutate_if_etcd -- --ignored
//! ```
//!
//! Astra finding S20, 2026-09-23: `mutate` re-reads BY NAME on every CAS
//! retry with no identity check at all. `mutate_if` is given the uid the
//! caller resolved `name` from, and re-checks it after every read —
//! including a retry's, because a recreation can land between any two of
//! them, not only before the first.

use meister_controller_api::resources::new_vm;
use meister_controller_api::{EtcdStore, StoreError, Vm, VmSpec};

fn endpoint() -> String {
    std::env::var("MEISTER_TEST_ETCD").unwrap_or_else(|_| "http://127.0.0.1:23700".to_string())
}

async fn store() -> EtcdStore {
    let prefix = format!("/mutate-if-test/{}", uuid::Uuid::new_v4());
    EtcdStore::connect(&[endpoint()], &prefix)
        .await
        .expect("an etcd to talk to — see the module note")
}

fn vm() -> Vm {
    new_vm(
        "web-1",
        VmSpec {
            class: Default::default(),
            cluster_selector: Default::default(),
            node_selector: Default::default(),
            anti_affinity: Vec::new(),
            node_name: None,
            cluster_name: None,
            run_strategy: Default::default(),
            evacuation: Default::default(),
            tenant: None,
            vm: serde_json::json!({}),
        },
    )
}

/// A write resolved against one vm's uid must not land on a DIFFERENT vm
/// made under the same name in between — the shape a scheduler's name reuse
/// or a client's recreate both take.
#[tokio::test]
#[ignore = "needs a local etcd; see the module note"]
async fn a_mutate_does_not_land_on_an_object_recreated_under_the_same_name() {
    let store = store().await;

    let first = store.create(&vm()).await.expect("the first vm");
    let stale_uid = first.metadata.uid.clone();

    // "web-1" is torn down and a different vm is made under the same name.
    store.delete::<Vm>("web-1").await.expect("torn down");
    let second = store.create(&vm()).await.expect("a new vm, same name");
    assert_ne!(second.metadata.uid, stale_uid);
    let rev_before = second.metadata.resource_version.clone();

    // A write resolved against the FIRST vm's uid must not land on the
    // second, however many CAS retries it takes to notice.
    let err = store
        .mutate_if::<Vm, _>("web-1", &stale_uid, |v| {
            v.status.node_name = Some("agent-1".to_string());
        })
        .await
        .expect_err("the name now belongs to a vm this write never resolved");
    assert!(matches!(err, StoreError::Conflict(_)), "{err}");

    let untouched: Vm = store.get("web-1").await.expect("the second vm");
    assert_eq!(untouched.metadata.uid, second.metadata.uid);
    assert_eq!(
        untouched.metadata.resource_version, rev_before,
        "no write landed at all, not even one with the field unset"
    );
    assert!(untouched.status.node_name.is_none());

    // The ordinary case: a write resolved against the object that is
    // actually there goes through exactly as `mutate` would have.
    let landed = store
        .mutate_if::<Vm, _>("web-1", &second.metadata.uid, |v| {
            v.status.node_name = Some("agent-1".to_string());
        })
        .await
        .expect("the current uid is not a conflict");
    assert_eq!(landed.status.node_name.as_deref(), Some("agent-1"));
}
