// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! The capacity commit: one claim on a node, confirmed against one reading of the store,
//! for both roads a guest takes to a machine. The claim is a [`CapacityReservation`]; the
//! shared steps (confirmation after the create-only write, and release) live here so
//! placement and migration answer "does this guest fit" alike (R3-F05).

use tracing::{debug, warn};

use crate::resources::{CapacityReservation, Node, Vm};
use crate::scheduler::{Overcommit, free_on, reservation_holds};
use crate::store::{EtcdStore, StoreError};

/// Whether the node can carry this claim, counting every claim written before it.
///
/// A unique key proves nothing about a sum: two replicas can each see room and both create,
/// overcommitting the node. So the writer asks where it stands in the queue, in etcd's
/// revision order, which every replica derives the same way. See [`reservation_holds`].
///
/// VMs and reservations come from one transaction at one revision (`EtcdStore::list2`):
/// a guest moves from one half to the other (bound first, released after), and two reads
/// could count it in neither. The node's capacity is an operator's number, read beside them.
///
/// `Err` means "could not be established" and is never read as "fits" (R3-F04). Callers
/// prepare or bind on `Ok(true)` alone; on `Err` they end the step with the claim standing,
/// and the next pass finds it and asks again.
pub async fn claim_holds(
    store: &EtcdStore,
    mine: &CapacityReservation,
    overcommit: Overcommit,
) -> anyhow::Result<bool> {
    let node = store.get::<Node>(&mine.spec.node).await;
    let seen = store.list2::<Vm, CapacityReservation>().await;
    confirmed(node, seen, mine, overcommit)
}

/// The decision half of [`claim_holds`] over the readings as they came back: a failed
/// reading is a failed verdict, never a pass.
///
/// Split from the reads so each failure is testable without a store that fails on cue (R3-F04).
pub fn confirmed(
    node: Result<Node, StoreError>,
    seen: Result<(Vec<Vm>, Vec<CapacityReservation>), StoreError>,
    mine: &CapacityReservation,
    overcommit: Overcommit,
) -> anyhow::Result<bool> {
    let node = node.map_err(|e| {
        anyhow::anyhow!(
            "node {} could not be read to confirm its room: {e}",
            mine.spec.node
        )
    })?;
    let (vms, held) = seen.map_err(|e| {
        anyhow::anyhow!(
            "the vms and reservations could not be listed to confirm the room on {}: {e}",
            mine.spec.node
        )
    })?;
    // Room before any promise (the queue is measured against it), via the same function
    // the candidate list uses so the two cannot drift.
    let room = free_on(&mine.spec.node, &node.status.capacity, &vms, overcommit);
    Ok(reservation_holds(room, mine, &held))
}

/// Give back the room `mine` holds: this claim at the revision it was read, nothing else.
///
/// Guarded by the claim's resourceVersion because a move can be asked for again under the
/// same key; an unguarded late release would take a later claim and offer the node while a
/// guest was still on its way in. Best effort: a missed release is left to the reaper.
pub async fn release(store: &EtcdStore, mine: &CapacityReservation) {
    let name = &mine.metadata.name;
    match store
        .delete_if::<CapacityReservation>(name, &mine.metadata.resource_version)
        .await
    {
        Ok(()) => debug!(reservation = %name, node = %mine.spec.node, "the room was given back"),
        Err(StoreError::NotFound(_)) => {}
        Err(StoreError::Conflict(_)) => {
            debug!(reservation = %name, "the claim was already taken by somebody else's release")
        }
        Err(e) => warn!(reservation = %name, error = %format!("{e:#}"),
                        "the claim was not given back; the reaper will take it"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::object::Resource;
    use crate::resources::{
        Claimant, NodeCapacity, NodeSpec, RunStrategy, STALE_PLACEMENT_AFTER_SECS, VmMigration,
        VmMigrationSpec, VmSpec, new_vm, orphaned_reservations,
    };
    use chrono::{Duration, Utc};
    use std::time::Duration as StdDuration;

    fn guest(name: &str, on: Option<&str>) -> Vm {
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
                vm: serde_json::json!({"vcpus": 4, "memory_mib": 4096}),
            },
        )
    }

    fn node(name: &str) -> Node {
        let mut n = Node::declare(name, NodeSpec::default());
        n.status.capacity = NodeCapacity {
            vcpus: 8,
            mem_mib: 8192,
            ..Default::default()
        };
        n
    }

    fn migration(vm: &str) -> VmMigration {
        VmMigration::declare(
            &format!("{vm}-20260924t120000"),
            VmMigrationSpec {
                tenant: "acme".into(),
                vm: vm.to_string(),
                target_node: None,
            },
        )
    }

    /// A claim as the store would hand it back, with the revision it was written at.
    fn written(mut claim: CapacityReservation, at: i64) -> CapacityReservation {
        claim.metadata.resource_version = at.to_string();
        claim
    }

    /// A node or list reading that fails is an error, never a passed check (R3-F04).
    #[test]
    fn a_reading_that_fails_is_not_a_passed_check() {
        let mine = written(
            CapacityReservation::of(
                &migration("web-1"),
                &guest("web-1", Some("agent-1")),
                "agent-2",
            ),
            10,
        );
        let broken = || StoreError::Timeout("get", StdDuration::from_secs(5));
        let overcommit = Overcommit::default();

        // With both readings the claim holds: an empty machine, nothing promised ahead.
        let all_read = confirmed(
            Ok(node("agent-2")),
            Ok((Vec::new(), vec![mine.clone()])),
            &mine,
            overcommit,
        );
        assert!(matches!(all_read, Ok(true)), "{all_read:?}");

        // The node could not be read.
        let no_node = confirmed(
            Err(broken()),
            Ok((Vec::new(), vec![mine.clone()])),
            &mine,
            overcommit,
        );
        assert!(no_node.is_err(), "an unread node is not room: {no_node:?}");

        // The vms and reservations could not be listed: bound guests and the claim queue.
        let no_lists = confirmed(Ok(node("agent-2")), Err(broken()), &mine, overcommit);
        assert!(
            no_lists.is_err(),
            "an unread fleet is not a place in its queue: {no_lists:?}"
        );
    }

    /// Placement and migration claims stand in one queue, in the store's order (R3-F05).
    #[test]
    fn a_placement_and_a_migration_stand_in_one_queue() {
        let flying = guest("web-1", Some("agent-1"));
        let landing = guest("web-2", None);
        let overcommit = Overcommit::default();
        // agent-2 has 8 GiB; each guest asks for 4 and a 4 GiB guest is already bound there.
        let already = guest("web-0", Some("agent-2"));

        let moving = written(
            CapacityReservation::of(&migration("web-1"), &flying, "agent-2"),
            10,
        );
        let placing = written(CapacityReservation::for_placement(&landing, "agent-2"), 11);
        let both = vec![moving.clone(), placing.clone()];

        let seen = || Ok((vec![already.clone()], both.clone()));
        assert!(
            confirmed(Ok(node("agent-2")), seen(), &moving, overcommit).unwrap(),
            "the earlier write keeps the slot"
        );
        assert!(
            !confirmed(Ok(node("agent-2")), seen(), &placing, overcommit).unwrap(),
            "and the later one yields, whichever road it is on"
        );

        // The mirror image: the placement was written first.
        let moving = written(
            CapacityReservation::of(&migration("web-1"), &flying, "agent-2"),
            12,
        );
        let placing = written(CapacityReservation::for_placement(&landing, "agent-2"), 11);
        let both = vec![moving.clone(), placing.clone()];
        let seen = || Ok((vec![already.clone()], both.clone()));
        assert!(confirmed(Ok(node("agent-2")), seen(), &placing, overcommit).unwrap());
        assert!(!confirmed(Ok(node("agent-2")), seen(), &moving, overcommit).unwrap());

        // A bound guest is counted whichever claim asks: a claim written after it yields.
        let bound_first = guest("web-0", Some("agent-2"));
        let second_bound = guest("web-3", Some("agent-2"));
        let late = written(CapacityReservation::for_placement(&landing, "agent-2"), 20);
        assert!(
            !confirmed(
                Ok(node("agent-2")),
                Ok((vec![bound_first, second_bound], vec![late.clone()])),
                &late,
                overcommit
            )
            .unwrap(),
            "two bound guests fill the machine; the claim after them yields"
        );
    }

    /// A placement claim is keyed by the guest's uid, never colliding with a migration (R3-F05).
    #[test]
    fn a_placement_claim_is_named_for_the_guest_and_not_for_a_migration() {
        let landing = guest("web-2", None);
        let claim = CapacityReservation::for_placement(&landing, "agent-2");
        assert_eq!(
            claim.metadata.name,
            format!("place.{}", landing.metadata.uid)
        );
        assert_eq!(claim.spec.claimant, Claimant::Placement);
        assert_eq!(claim.spec.mem_mib, 4096, "the guest's size travelled");
        assert!(claim.is_placement_of(&landing));
        assert!(
            !claim.belongs_to(&migration("web-2")),
            "and no migration can mistake it for its own"
        );

        // The same name made again gets a different uid and key.
        let again = guest("web-2", None);
        assert_ne!(
            CapacityReservation::for_placement(&again, "agent-2")
                .metadata
                .name,
            claim.metadata.name
        );
        assert!(!claim.is_placement_of(&again));
    }

    /// A placement claim is an orphan once bound, gone, deleting or stale, not before (R3-F05).
    #[test]
    fn a_placement_claim_outlives_nothing() {
        let now = Utc::now();
        let landing = guest("web-2", None);
        let claim = CapacityReservation::for_placement(&landing, "agent-2");
        let held = std::slice::from_ref(&claim);
        let names = |orphans: Vec<&CapacityReservation>| -> Vec<String> {
            orphans.iter().map(|r| r.metadata.name.clone()).collect()
        };

        // Live: the guest exists, is unbound, and the claim is young.
        assert!(
            orphaned_reservations(held, &[], std::slice::from_ref(&landing), now).is_empty(),
            "a placement in flight keeps its room"
        );

        // Bound — anywhere. The binding is the count from here on.
        let mut bound = landing.clone();
        bound.spec.node_name = Some("agent-2".into());
        assert_eq!(
            names(orphaned_reservations(
                held,
                &[],
                std::slice::from_ref(&bound),
                now
            )),
            vec![claim.metadata.name.clone()],
            "a bound guest's claim is a double count"
        );
        let mut elsewhere = landing.clone();
        elsewhere.spec.node_name = Some("agent-3".into());
        assert_eq!(
            names(orphaned_reservations(
                held,
                &[],
                std::slice::from_ref(&elsewhere),
                now
            )),
            vec![claim.metadata.name.clone()],
        );

        // Gone, and on its way out.
        assert_eq!(
            names(orphaned_reservations(held, &[], &[], now)),
            vec![claim.metadata.name.clone()],
            "a guest that is gone is coming for nothing"
        );
        let mut leaving = landing.clone();
        leaving.metadata.deletion_timestamp = Some(now);
        assert_eq!(
            names(orphaned_reservations(
                held,
                &[],
                std::slice::from_ref(&leaving),
                now
            )),
            vec![claim.metadata.name.clone()],
        );

        // A later guest of the same NAME is not this guest.
        let namesake = guest("web-2", None);
        assert_eq!(
            names(orphaned_reservations(
                held,
                &[],
                std::slice::from_ref(&namesake),
                now
            )),
            vec![claim.metadata.name.clone()],
            "the uid is the identity, not the name"
        );

        // Stood too long: the writer is not coming back; measured from the claim's own stamp.
        let made = claim
            .metadata
            .creation_timestamp
            .expect("the store stamps every object it makes");
        let later = made + Duration::seconds(STALE_PLACEMENT_AFTER_SECS + 1);
        assert_eq!(
            names(orphaned_reservations(
                held,
                &[],
                std::slice::from_ref(&landing),
                later
            )),
            vec![claim.metadata.name.clone()],
            "a claim older than a placement can take is abandoned"
        );
        let just_in_time = made + Duration::seconds(STALE_PLACEMENT_AFTER_SECS);
        assert!(
            orphaned_reservations(held, &[], std::slice::from_ref(&landing), just_in_time)
                .is_empty(),
            "and one exactly at the bound is still the writer's"
        );

        // And a claim with no creation time at all is nobody's.
        let mut unstamped = claim.clone();
        unstamped.metadata.creation_timestamp = None;
        assert_eq!(
            orphaned_reservations(
                std::slice::from_ref(&unstamped),
                &[],
                std::slice::from_ref(&landing),
                now
            )
            .len(),
            1
        );

        // A migration's promise ignores the VM rules: its guest is bound to the source mid-move.
        let flying = guest("web-1", Some("agent-1"));
        let mut moving = migration("web-1");
        moving.status.reported = Some(crate::resources::VmMigrationReported::by(
            "agent-2",
            crate::resources::VmMigrationPhaseKind::Preparing,
            crate::resources::VmMigrationReason::Dispatched,
            None,
            now,
        ));
        moving.settle(now);
        let promise = CapacityReservation::of(&moving, &flying, "agent-2");
        assert!(
            orphaned_reservations(
                std::slice::from_ref(&promise),
                std::slice::from_ref(&moving),
                std::slice::from_ref(&flying),
                later
            )
            .is_empty(),
            "a migration's promise lives with its migration, however old"
        );
        // A promise written before `claimant` existed reads as a migration's.
        let old: CapacityReservation = serde_json::from_value(serde_json::json!({
            "apiVersion": "meister.io/v1",
            "kind": "CapacityReservation",
            "metadata": {"name": moving.metadata.name},
            "spec": {
                "node": "agent-2", "vm": "web-1", "vmUid": flying.metadata.uid,
                "migration": moving.metadata.name, "migrationUid": moving.metadata.uid,
                "vcpus": 4, "memMib": 4096
            }
        }))
        .expect("an object from before `claimant`");
        assert_eq!(old.spec.claimant, Claimant::Migration);
        assert!(old.belongs_to(&moving));
    }
}
