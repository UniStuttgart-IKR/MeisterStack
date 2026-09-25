// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! The capacity commit against a real etcd: both roads to a node, two
//! replicas, one slot — and at most one of them gets it.
//!
//! `#[ignore]` for the reason `reservation_etcd` is. Start an etcd and name
//! it:
//!
//! ```text
//! MEISTER_TEST_ETCD=http://127.0.0.1:23700 \
//!   cargo test -p meister-controller-api --test capacity_etcd -- --ignored
//! ```
//!
//! Astra finding R3-F05, 2026-09-24: ordinary placement booked capacity in a
//! process-local mutex from a per-pass snapshot and bound by CAS on the VM
//! object alone, while a migration's reservation was a separate object — so
//! two controller replicas could each succeed against the same free
//! capacity. B reads 8 GiB free, A reserves and confirms 6 for a migration, B
//! binds 6 from its old snapshot: 12 of 8. Both roads make the same claim
//! now and confirm it against one reading, and these are the interleavings
//! the finding named, run against the store rather than argued.

use chrono::Utc;
use meister_controller_api::{
    CapacityReservation, EtcdStore, Node, NodeCapacity, NodeSpec, Overcommit, RunStrategy,
    StoreError, Vm, VmMigration, VmMigrationSpec, VmSpec, capacity, free_on, reserved_on,
    resources::new_vm,
};

fn endpoint() -> String {
    std::env::var("MEISTER_TEST_ETCD").unwrap_or_else(|_| "http://127.0.0.1:23700".to_string())
}

async fn store() -> EtcdStore {
    let prefix = format!("/capacity-test/{}", uuid::Uuid::new_v4());
    EtcdStore::connect(&[endpoint()], &prefix)
        .await
        .expect("an etcd to talk to; see the module note")
}

/// A machine with 8 vCPUs and 8 GiB.
fn node(name: &str) -> Node {
    let mut n = Node::declare(name, NodeSpec::default());
    n.status.ready = true;
    n.status.capacity = NodeCapacity {
        vcpus: 8,
        mem_mib: 8192,
        ..Default::default()
    };
    n
}

/// A guest of `mem_mib`, bound to `on` or to nobody.
fn guest(name: &str, on: Option<&str>, mem_mib: u64) -> Vm {
    new_vm(
        name,
        VmSpec {
            class: Default::default(),
            evacuation: Default::default(),
            cluster_selector: Default::default(),
            node_selector: Default::default(),
            anti_affinity: Vec::new(),
            node_name: on.map(str::to_string),
            cluster_name: None,
            run_strategy: RunStrategy::Running,
            tenant: Some("acme".into()),
            vm: serde_json::json!({"vcpus": 2, "memory_mib": mem_mib}),
        },
    )
}

fn migration(vm: &str) -> VmMigration {
    VmMigration::declare(
        &format!("{vm}-{}", Utc::now().format("%Y%m%dt%H%M%S")),
        VmMigrationSpec {
            tenant: "acme".into(),
            vm: vm.to_string(),
            target_node: None,
        },
    )
}

/// What a replica sees when it takes its snapshot: the room on `node`
/// before any promise, and what is promised there.
async fn snapshot(store: &EtcdStore, node: &Node) -> (u64, u64) {
    let (vms, held): (Vec<Vm>, Vec<CapacityReservation>) =
        store.list2().await.expect("one reading of both");
    let room = free_on(
        &node.metadata.name,
        &node.status.capacity,
        &vms,
        Overcommit::default(),
    );
    (
        room.mem_mib,
        reserved_on(&node.metadata.name, &held).mem_mib,
    )
}

/// The interleaving of the finding, both ways round, and the one where both
/// write before either confirms: whoever's claim the store ordered first
/// keeps the slot, on both replicas, whichever road each is on.
#[tokio::test]
#[ignore = "needs a local etcd; see the module note"]
async fn a_placement_and_a_migration_racing_for_one_slot_commit_at_most_once() {
    let store = store().await;
    let overcommit = Overcommit::default();
    let agent_2 = store
        .create(&node("agent-2"))
        .await
        .expect("the destination");
    // Two 6 GiB guests, and a machine with room for one of them.
    let flying = store
        .create(&guest("web-1", Some("agent-1"), 6144))
        .await
        .expect("the guest a migration is moving");
    let landing = store
        .create(&guest("web-2", None, 6144))
        .await
        .expect("the guest a placement is deciding on");
    let moving = store
        .create(&migration("web-1"))
        .await
        .expect("the migration");

    // Replica B takes its snapshot: 8 GiB free on agent-2, nothing promised.
    assert_eq!(snapshot(&store, &agent_2).await, (8192, 0));

    // Replica A: a migration's `prepare` claims agent-2 and confirms.
    let a = store
        .create(&CapacityReservation::of(&moving, &flying, "agent-2"))
        .await
        .expect("the migration's claim");
    assert!(
        capacity::claim_holds(&store, &a, overcommit)
            .await
            .expect("a reading"),
        "the first claim on an empty machine holds"
    );

    // Replica B, deciding from its old snapshot, claims agent-2 for the
    // placement. The create-only write SUCCEEDS — a unique key is not a sum
    // — and the confirmation is what says no.
    let b = store
        .create(&CapacityReservation::for_placement(&landing, "agent-2"))
        .await
        .expect("the placement's claim, as a key");
    assert!(
        !capacity::claim_holds(&store, &b, overcommit)
            .await
            .expect("a reading"),
        "and it does not hold: the migration's claim was written first"
    );
    // So B binds nothing and gives the claim back; the node carries exactly
    // one guest's promise.
    capacity::release(&store, &b).await;
    assert_eq!(snapshot(&store, &agent_2).await, (8192, 6144));

    // The mirror image: the migration fails and gives its room back, and
    // next time the placement's claim is the earlier one.
    capacity::release(&store, &a).await;
    assert_eq!(snapshot(&store, &agent_2).await, (8192, 0));
    let b = store
        .create(&CapacityReservation::for_placement(&landing, "agent-2"))
        .await
        .expect("the placement claims first");
    let a = store
        .create(&CapacityReservation::of(&moving, &flying, "agent-2"))
        .await
        .expect("the migration claims second");
    // Both written before either confirms — and it does not matter which
    // confirms first, because the order is the store's and not the callers'.
    assert!(
        !capacity::claim_holds(&store, &a, overcommit)
            .await
            .expect("a reading"),
        "the migration's later claim yields"
    );
    assert!(
        capacity::claim_holds(&store, &b, overcommit)
            .await
            .expect("a reading"),
        "the placement's earlier claim holds"
    );
    // Asked again in the other order, the verdicts are the same.
    assert!(
        capacity::claim_holds(&store, &b, overcommit)
            .await
            .expect("a reading")
    );
    assert!(
        !capacity::claim_holds(&store, &a, overcommit)
            .await
            .expect("a reading")
    );
    capacity::release(&store, &a).await;

    // The placement commits: the binding under its claim, then the release.
    let mut bound = landing.clone();
    bound.spec.node_name = Some("agent-2".into());
    let bound = store
        .update_if_standing(&bound, &b)
        .await
        .expect("the binding, while the claim stands");
    assert_eq!(bound.spec.node_name.as_deref(), Some("agent-2"));
    capacity::release(&store, &b).await;

    // And a migration that comes AFTER the binding is measured against the
    // bound guest — no claim stands for it any more, and none has to.
    let late = store
        .create(&CapacityReservation::of(&moving, &flying, "agent-2"))
        .await
        .expect("a claim after the fact");
    assert!(
        !capacity::claim_holds(&store, &late, overcommit)
            .await
            .expect("a reading"),
        "the machine is full of a guest that was bound a moment ago"
    );
    assert_eq!(snapshot(&store, &agent_2).await, (2048, 6144));
}

/// The invariant, read off the store at every step: between the claim and
/// the release the guest is counted at least once, and for the length of
/// the release exactly twice — which refuses a third claim it could have
/// carried, and never admits one it could not.
#[tokio::test]
#[ignore = "needs a local etcd; see the module note"]
async fn a_guest_is_counted_at_every_revision_between_claim_and_release() {
    let store = store().await;
    let overcommit = Overcommit::default();
    let agent_2 = store.create(&node("agent-2")).await.expect("the machine");
    let landing = store
        .create(&guest("web-2", None, 6144))
        .await
        .expect("a 6 GiB guest");
    let small = store
        .create(&guest("web-3", None, 2048))
        .await
        .expect("a 2 GiB guest");

    // Claimed: promised, not bound.
    let b = store
        .create(&CapacityReservation::for_placement(&landing, "agent-2"))
        .await
        .expect("the claim");
    assert!(
        capacity::claim_holds(&store, &b, overcommit)
            .await
            .expect("a reading")
    );
    assert_eq!(snapshot(&store, &agent_2).await, (8192, 6144));

    // Bound and not yet released: bound AND promised. A 2 GiB guest would
    // fit beside the 6 GiB one, and is refused for the length of one round
    // trip — the safe direction.
    let mut bound = landing.clone();
    bound.spec.node_name = Some("agent-2".into());
    store
        .update_if_standing(&bound, &b)
        .await
        .expect("the binding under the claim");
    assert_eq!(snapshot(&store, &agent_2).await, (2048, 6144));
    let c = store
        .create(&CapacityReservation::for_placement(&small, "agent-2"))
        .await
        .expect("a third claim");
    assert!(
        !capacity::claim_holds(&store, &c, overcommit)
            .await
            .expect("a reading"),
        "counted twice, the machine looks full; nothing is admitted on a double count"
    );
    capacity::release(&store, &c).await;

    // Released: bound, once.
    capacity::release(&store, &b).await;
    assert_eq!(snapshot(&store, &agent_2).await, (2048, 0));
    let c = store
        .create(&CapacityReservation::for_placement(&small, "agent-2"))
        .await
        .expect("the third claim again");
    assert!(
        capacity::claim_holds(&store, &c, overcommit)
            .await
            .expect("a reading"),
        "and now the 2 GiB guest fits beside the bound one"
    );
    capacity::release(&store, &c).await;

    // Releasing what was already released takes nothing and is not an
    // error; a stale release cannot take a LATER claim under the same key.
    capacity::release(&store, &b).await;
    let again = store
        .create(&CapacityReservation::for_placement(&landing, "agent-2"))
        .await
        .expect("a later claim under the same key");
    capacity::release(&store, &b).await;
    let standing: CapacityReservation = store
        .get(&again.metadata.name)
        .await
        .expect("the later claim is untouched by the earlier release");
    assert_eq!(
        standing.metadata.resource_version,
        again.metadata.resource_version
    );
}

/// The guard on the binding: a claim the reaper took, or a sibling
/// released, cannot become a binding — and neither can a claim that stands
/// carry a binding onto a VM that moved.
#[tokio::test]
#[ignore = "needs a local etcd; see the module note"]
async fn a_binding_is_refused_once_its_claim_is_gone() {
    let store = store().await;
    store.create(&node("agent-2")).await.expect("the machine");
    let landing = store
        .create(&guest("web-2", None, 6144))
        .await
        .expect("the guest");
    let mut bound = landing.clone();
    bound.spec.node_name = Some("agent-2".into());

    // The reaper takes the claim between the confirmation and the binding.
    let b = store
        .create(&CapacityReservation::for_placement(&landing, "agent-2"))
        .await
        .expect("the claim");
    store
        .delete_if::<CapacityReservation>(&b.metadata.name, &b.metadata.resource_version)
        .await
        .expect("the reaper");
    let refused = store
        .update_if_standing(&bound, &b)
        .await
        .expect_err("a binding whose claim is gone");
    assert!(matches!(refused, StoreError::Conflict(_)), "{refused}");
    assert!(
        refused.to_string().contains("no longer stands"),
        "the conflict says it was the claim: {refused}"
    );
    let still: Vm = store.get("web-2").await.expect("the guest");
    assert_eq!(still.spec.node_name, None, "nothing was bound");

    // The claim stands, but the VM moved under the writer: the ordinary
    // conflict, and still nothing bound onto a stale object.
    let b = store
        .create(&CapacityReservation::for_placement(&landing, "agent-2"))
        .await
        .expect("the claim again");
    let mut edited = landing.clone();
    edited
        .metadata
        .labels
        .insert("tier".to_string(), "web".to_string());
    store.update(&edited).await.expect("a client's edit");
    let refused = store
        .update_if_standing(&bound, &b)
        .await
        .expect_err("a binding onto an object that moved");
    assert!(matches!(refused, StoreError::Conflict(_)), "{refused}");
    assert!(
        refused.to_string().contains("concurrent write"),
        "the conflict says it was the vm: {refused}"
    );

    // Both stand: the binding is written, and the claim is untouched by it
    // — its own release takes it, and nothing else does.
    let current: Vm = store.get("web-2").await.expect("the guest as it is now");
    let mut bound = current.clone();
    bound.spec.node_name = Some("agent-2".into());
    let bound = store
        .update_if_standing(&bound, &b)
        .await
        .expect("the binding, both standing");
    assert_eq!(bound.spec.node_name.as_deref(), Some("agent-2"));
    let claim: CapacityReservation = store.get(&b.metadata.name).await.expect("the claim");
    assert_eq!(
        claim.metadata.resource_version, b.metadata.resource_version,
        "the binding did not move the claim"
    );
    capacity::release(&store, &b).await;
    assert!(
        store
            .get::<CapacityReservation>(&b.metadata.name)
            .await
            .is_err(),
        "and the room is the node's again, minus the guest bound to it"
    );
}
