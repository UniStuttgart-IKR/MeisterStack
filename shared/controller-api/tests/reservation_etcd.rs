// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! `CapacityReservation` against a real etcd: the create-only write that
//! makes one migration's promise unique, and the guarded release that gives
//! it back.
//!
//! `#[ignore]` for the reason `delete_if_etcd` is. Start an etcd and name it:
//!
//! ```text
//! MEISTER_TEST_ETCD=http://127.0.0.1:23700 \
//!   cargo test -p meister-controller-api --test reservation_etcd -- --ignored
//! ```
//!
//! Astra finding S07, 2026-09-23: nothing reserved room at a live migration's
//! destination between `prepare` and the guest's arrival, so N migrations
//! aimed at one node all measured themselves against the same numbers and all
//! passed. The reservation is the missing entry, and the two store facts it
//! needs are exactly these: it can be written once, and it can be given back
//! by the writer and by nobody else.

use meister_controller_api::{
    CapacityReservation, CapacityReservationSpec, EtcdStore, StoreError, reserved_on,
};

fn endpoint() -> String {
    std::env::var("MEISTER_TEST_ETCD").unwrap_or_else(|_| "http://127.0.0.1:23700".to_string())
}

async fn store() -> EtcdStore {
    let prefix = format!("/reservation-test/{}", uuid::Uuid::new_v4());
    EtcdStore::connect(&[endpoint()], &prefix)
        .await
        .expect("an etcd to talk to — see the module note")
}

fn reservation(migration: &str, migration_uid: &str, node: &str) -> CapacityReservation {
    CapacityReservation::declare(
        migration,
        CapacityReservationSpec {
            node: node.to_string(),
            vm: "web-1".to_string(),
            vm_uid: "vm-uid-1".to_string(),
            migration: migration.to_string(),
            migration_uid: migration_uid.to_string(),
            vcpus: 4,
            mem_mib: 4096,
        },
    )
}

/// One migration, one promise. The write is create-only — the same
/// compare-on-create-revision every `create` in this store makes — so a
/// second replica that reaches `prepare` for the same migration finds the
/// room already spoken for by that migration rather than booking it twice.
#[tokio::test]
#[ignore = "needs a local etcd; see the module note"]
async fn a_migration_can_reserve_room_once_and_not_twice() {
    let store = store().await;

    let held = store
        .create(&reservation("web-1-20260923t193810", "m-uid-1", "agent-2"))
        .await
        .expect("the first promise");
    assert!(
        !held.metadata.resource_version.is_empty(),
        "a reservation comes back with the revision it was written at; the \
         confirmation after the fact is an ordering over exactly that"
    );

    let again = store
        .create(&reservation("web-1-20260923t193810", "m-uid-1", "agent-3"))
        .await
        .expect_err("the same migration may not promise a second machine");
    assert!(matches!(again, StoreError::AlreadyExists(_)), "{again}");

    // And the reading the scheduler does: what is promised on a node, out of
    // the objects rather than out of anybody's memory.
    store
        .create(&reservation("web-2-20260923t193811", "m-uid-2", "agent-2"))
        .await
        .expect("a second migration, a second promise");
    let all: Vec<CapacityReservation> = store.list().await.expect("the listing");
    assert_eq!(reserved_on("agent-2", &all).mem_mib, 8192);
    assert_eq!(reserved_on("agent-3", &all).mem_mib, 0, "nothing there");
}

/// A reservation outlives nothing — and the giving back is guarded, because
/// a migration is named for a vm and a moment and a record can be made again
/// under a name that was used before.
///
/// The ABA S19 closed for secrets, in the one place where losing it costs a
/// machine: the first migration's late release would otherwise remove the
/// SECOND one's promise, and the node would then be offered to an ordinary
/// create while a guest was still flying into it.
#[tokio::test]
#[ignore = "needs a local etcd; see the module note"]
async fn a_release_gives_back_only_the_promise_the_releaser_made() {
    let store = store().await;
    let name = "web-1-20260923t193810";

    let first = store
        .create(&reservation(name, "m-uid-1", "agent-2"))
        .await
        .expect("the first migration's promise");
    let first_saw = first.metadata.resource_version.clone();

    // The first migration ends, and a second record is made under the same
    // name — and reserves again.
    store
        .delete_if::<CapacityReservation>(name, &first_saw)
        .await
        .expect("the writer gives back what it wrote");
    let second = store
        .create(&reservation(name, "m-uid-2", "agent-2"))
        .await
        .expect("a later migration of the same name");
    assert_eq!(second.spec.migration_uid, "m-uid-2");

    // The first migration's release resumes, against a version that is no
    // longer there.
    let stale = store
        .delete_if::<CapacityReservation>(name, &first_saw)
        .await
        .expect_err("that promise is not the one standing any more");
    assert!(matches!(stale, StoreError::Conflict(_)), "{stale}");

    let still: CapacityReservation = store.get(name).await.expect("the second one is untouched");
    assert_eq!(still.spec.migration_uid, "m-uid-2");

    // And its own writer gives it back.
    store
        .delete_if::<CapacityReservation>(name, &still.metadata.resource_version)
        .await
        .expect("the second migration releases its own");
    assert!(
        store.get::<CapacityReservation>(name).await.is_err(),
        "and the room is a node's again"
    );
}
