// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! The reconciler's tests, verbatim out of `reconcile.rs`. The module path
//! is unchanged (`reconcile::tests`), so every test still answers to the name
//! it had before.

use super::*;

/// A bound, running VM whose spec refers to these volumes by name.
fn volume_vm(volumes: &[&str]) -> Vm {
    let entries: Vec<serde_json::Value> = volumes
        .iter()
        .map(|n| serde_json::json!({ "volume": n }))
        .collect();
    let mut vm = controller_api::resources::new_vm(
        "web-1",
        controller_api::VmSpec {
            class: Default::default(),
            evacuation: Default::default(),
            cluster_selector: Default::default(),
            node_selector: Default::default(),
            anti_affinity: Vec::new(),
            node_name: Some("agent-1".into()),
            cluster_name: None,
            run_strategy: RunStrategy::Running,
            tenant: None,
            vm: serde_json::json!({ "volumes": entries }),
        },
    );
    #[allow(deprecated)]
    vm.status.assign(controller_api::VmPhase::of(
        VmPhaseKind::Running,
        Utc::now(),
    ));
    vm
}

fn released(node: Option<&str>, vm: Option<&str>) -> Volume {
    let mut v = controller_api::resources::new_volume(
        "data",
        controller_api::VolumeSpec {
            pool: "fast".into(),
            size_gib: 10,
            ..Default::default()
        },
    );
    v.metadata.deletion_timestamp = Some(Utc::now());
    #[allow(deprecated)]
    v.status.assign(controller_api::VolumePhase::of(
        VolumePhaseKind::Releasing,
        Utc::now(),
    ));
    v.status.node = node.map(str::to_string);
    v.status.attached_to = vm.map(str::to_string);
    v
}

fn pool(name: &str, driver: &str, nodes: &[&str]) -> StoragePool {
    StoragePool::declare(
        name,
        controller_api::StoragePoolSpec {
            driver: driver.into(),
            nodes: nodes.iter().map(|n| n.to_string()).collect(),
            ..Default::default()
        },
    )
}

fn said(entries: &[(&str, &[(&str, Locality)])]) -> NodeLocalities {
    entries
        .iter()
        .map(|(node, drivers)| {
            (
                node.to_string(),
                drivers
                    .iter()
                    .map(|(d, l)| (d.to_string(), *l))
                    .collect::<BTreeMap<_, _>>(),
            )
        })
        .collect()
}

/// The round trip the whole axis rests on: what the nodes said in their
/// Hello is what the pool's status says, and it is the DRIVER's answer
/// rather than anything an admin typed.
#[test]
fn a_pool_takes_the_locality_the_nodes_that_serve_it_report() {
    let nodes = said(&[
        ("manacor", &[("lvm-thin", Locality::NodeLocal)]),
        ("soller", &[("lvm-thin", Locality::NodeLocal)]),
        // A third node that runs a different backend has nothing to say
        // about this pool, whatever it says about its own.
        ("inca", &[("nfs", Locality::Shared)]),
    ]);
    assert_eq!(
        pool_locality(&pool("fast", "lvm-thin", &[]), &nodes),
        PoolLocality::Agreed(Locality::NodeLocal)
    );
    assert_eq!(
        pool_locality(&pool("bulk", "nfs", &[]), &nodes),
        PoolLocality::Agreed(Locality::Shared)
    );
}

/// Only the nodes the pool NAMES are asked. A node outside the list may
/// run the same backend and is still not part of this pool's answer —
/// which is the difference between "this driver is node-local" and "this
/// POOL is node-local", and the second is the one a placement reads.
#[test]
fn a_node_the_pool_does_not_name_is_not_asked() {
    let nodes = said(&[
        ("manacor", &[("nfs", Locality::Shared)]),
        // A stale binary, but outside the pool: it must not make the pool
        // Failed, because it is not part of it.
        ("soller", &[("nfs", Locality::NodeLocal)]),
    ]);
    assert_eq!(
        pool_locality(&pool("bulk", "nfs", &["manacor"]), &nodes),
        PoolLocality::Agreed(Locality::Shared)
    );
    assert!(
        matches!(
            pool_locality(&pool("bulk", "nfs", &[]), &nodes),
            PoolLocality::Split { .. }
        ),
        "an empty list is every node, and then the stale one IS in it"
    );
}

/// Two nodes saying different things about one backend cannot be a
/// configuration — locality is compiled into the driver — so it is a
/// version mix, and the pool says so instead of picking a winner.
#[test]
fn nodes_that_disagree_are_a_split_naming_both_and_what_each_said() {
    let nodes = said(&[
        ("manacor", &[("nfs", Locality::Shared)]),
        ("soller", &[("nfs", Locality::NodeLocal)]),
    ]);
    assert_eq!(
        pool_locality(&pool("bulk", "nfs", &[]), &nodes),
        PoolLocality::Split {
            other: "manacor",
            other_says: Locality::Shared,
            node: "soller",
            says: Locality::NodeLocal,
        }
    );
}

/// Silence is not a disagreement and not a default. A pool nobody has
/// reported on stays Pending with no locality at all, and placement falls
/// back to the soft preference it always had.
#[test]
fn silence_leaves_the_pool_without_a_locality_rather_than_with_a_guess() {
    // nobody runs the backend
    assert_eq!(
        pool_locality(
            &pool("fast", "lvm-thin", &[]),
            &said(&[("manacor", &[("nfs", Locality::Shared)])])
        ),
        PoolLocality::Unheard
    );
    // ... and an agent that predates the field reports no entry at all
    assert_eq!(
        pool_locality(&pool("fast", "lvm-thin", &[]), &said(&[("manacor", &[])])),
        PoolLocality::Unheard
    );
    assert_eq!(
        pool_locality(&pool("fast", "lvm-thin", &[]), &NodeLocalities::new()),
        PoolLocality::Unheard
    );
}

/// What a verdict becomes on the object. The one that matters is the
/// third: a version mix does not erase what was already known, and the
/// sentence names both machines so an operator knows which two to look at.
#[test]
fn a_verdict_becomes_a_phase_and_keeps_what_was_already_known() {
    assert_eq!(
        pool_status("nfs", PoolLocality::Agreed(Locality::Shared), None),
        (StoragePoolPhaseKind::Ready, Some(Locality::Shared), None)
    );
    assert_eq!(
        pool_status("nfs", PoolLocality::Unheard, Some(Locality::Shared)),
        (StoragePoolPhaseKind::Pending, None, None),
        "nobody said anything this pass, so nothing is known this pass"
    );

    let (phase, locality, message) = pool_status(
        "nfs",
        PoolLocality::Split {
            other: "manacor",
            other_says: Locality::Shared,
            node: "soller",
            says: Locality::NodeLocal,
        },
        Some(Locality::Shared),
    );
    assert_eq!(phase, StoragePoolPhaseKind::Failed);
    assert_eq!(
        locality,
        Some(Locality::Shared),
        "the better of the two guesses survives; the phase says not to trust it"
    );
    let message = message.expect("a sentence");
    assert!(
        message.contains("manacor") && message.contains("soller"),
        "{message}"
    );
    assert!(
        message.contains("shared") && message.contains("node-local"),
        "{message}"
    );
    assert!(message.contains("version mix"), "{message}");
    assert!(
        message.contains("nfs"),
        "the driver they disagree about: {message}"
    );
}

/// Detach before delete, as the one rule with data on the other side of
/// it.
///
/// A volume somebody holds keeps everything and the pass comes back. A
/// volume nobody holds but a node made keeps everything too, because this
/// tier cannot make bytes go away — the deprovision is a command to that
/// node. Only a volume that was never provisioned anywhere goes at once,
/// and it goes because there is nothing to lose.
#[test]
fn a_released_volume_only_goes_when_nothing_is_left_to_lose() {
    let none: [String; 0] = [];
    assert_eq!(
        release_action(&released(Some("manacor"), Some("web")), &none),
        Release::HeldBy(HeldBy::Vm("web")),
        "a consumer outranks everything: that is what has to end first"
    );
    assert_eq!(
        release_action(&released(None, Some("web")), &none),
        Release::HeldBy(HeldBy::Vm("web"))
    );
    assert_eq!(
        release_action(&released(Some("manacor"), None), &none),
        Release::WaitingForNode("manacor")
    );
    assert_eq!(release_action(&released(None, None), &none), Release::Drop);
}

/// The second holder storage B adds, and the sentence that tells it from
/// the first.
///
/// A snapshot standing on a file that has been deleted is a snapshot of
/// nothing, so the bytes stay until the last copy of them goes — the same
/// `HeldBy` shape a VM produces, with a different way out: a VM lets go
/// when it is deleted, a snapshot has to be deleted itself, and the two
/// sentences say so.
///
/// (`lvm-thin` would hold its origin LV on its own, because a thin
/// snapshot shares the origin's blocks. This rule is what makes
/// `filesystem` behave the same way, so an operator sees one storage
/// system rather than one per backend.)
#[test]
fn a_snapshot_holds_the_volume_it_was_taken_of() {
    let held = ["snap-1".to_string()];
    let none: [String; 0] = [];
    assert_eq!(
        release_action(&released(Some("manacor"), None), &held),
        Release::HeldBy(HeldBy::Snapshot("snap-1"))
    );
    // The VM comes first, because a VM is what a person will look for.
    assert_eq!(
        release_action(&released(Some("manacor"), Some("web")), &held),
        Release::HeldBy(HeldBy::Vm("web"))
    );
    // Two sentences, two ways out.
    assert!(
        HeldBy::Vm("web").sentence().contains("delete the vm first"),
        "{}",
        HeldBy::Vm("web").sentence()
    );
    assert!(
        HeldBy::Snapshot("snap-1")
            .sentence()
            .contains("held by snapshot snap-1"),
        "{}",
        HeldBy::Snapshot("snap-1").sentence()
    );

    // And which snapshots hold: this volume's, and not the ones already
    // on their way out — holding for those would make two deletes wait
    // for each other.
    let snap = |name: &str, of: &str, deleting: bool| {
        let mut s = controller_api::new_volume_snapshot(
            name,
            controller_api::VolumeSnapshotSpec {
                volume: of.into(),
                ..Default::default()
            },
        );
        if deleting {
            s.metadata.deletion_timestamp = Some(Utc::now());
        }
        s
    };
    let all = [
        snap("snap-1", "data", false),
        snap("snap-2", "other", false),
        snap("snap-3", "data", true),
    ];
    assert_eq!(snapshots_holding(&all, "data"), vec!["snap-1".to_string()]);
    assert!(snapshots_holding(&all, "nothing").is_empty());
    assert_eq!(
        release_action(&released(Some("manacor"), None), &none),
        Release::WaitingForNode("manacor"),
        "no snapshot, no hold"
    );
}

/// And the finalizer is what makes any of that possible: without it the
/// store would have dropped the object on the DELETE and the rule above
/// would never get a chance to run.
#[test]
fn a_volume_carries_the_finalizer_that_holds_it_back() {
    let v = released(Some("manacor"), Some("web"));
    assert!(
        v.metadata
            .finalizers
            .contains(&controller_api::VOLUME_RELEASE_FINALIZER.to_string()),
        "{:?}",
        v.metadata.finalizers
    );
}

fn at(secs: i64) -> DateTime<Utc> {
    DateTime::from_timestamp(1_800_000_000 + secs, 0).unwrap()
}

fn bound_to(node: Option<&str>) -> Vm {
    controller_api::resources::new_vm(
        "t",
        controller_api::VmSpec {
            class: Default::default(),
            evacuation: Default::default(),
            cluster_selector: Default::default(),
            node_selector: Default::default(),
            anti_affinity: Vec::new(),
            node_name: node.map(str::to_string),
            cluster_name: None,
            run_strategy: RunStrategy::Running,
            tenant: None,
            vm: serde_json::json!({}),
        },
    )
}

fn sessions(names: &[&str]) -> HashSet<String> {
    names.iter().map(|s| s.to_string()).collect()
}

/// The whole of leaderless ownership: my sessions, my VMs.
#[test]
fn a_bound_vm_is_only_reconciled_by_the_replica_its_node_talks_to() {
    let mine = sessions(&["node-a"]);
    assert!(may_reconcile(&bound_to(Some("node-a")), &mine));
    assert!(!may_reconcile(&bound_to(Some("node-b")), &mine));
    // and a replica holding no session at all owns no bound VM
    assert!(!may_reconcile(&bound_to(Some("node-a")), &sessions(&[])));
}

/// Unbound is everybody's: the scheduler only offers nodes of the local
/// session map, so binding and ownership land on the same replica anyway.
#[test]
fn an_unbound_vm_may_be_scheduled_by_any_replica() {
    assert!(may_reconcile(&bound_to(None), &sessions(&[])));
    assert!(may_reconcile(&bound_to(None), &sessions(&["node-a"])));
}

/// D13: a finished drain says what it moved.
///
/// `leaving` is a snapshot and goes to zero exactly when the work is done, so
/// the report of a drain that had emptied a machine read
/// `{"report.moved":0,"report.staying":3,"really_moved":1}` — a number that
/// is true about now and useless as an answer to "how did the drain go". The
/// cumulative half is a difference against the last pass, which is why it
/// needs no memory beyond the number itself.
#[test]
fn a_drain_counts_what_it_actually_moved() {
    let was = |names: &[&str], total: u32| controller_api::Draining {
        leaving: names.len() as u32,
        leaving_vms: names.iter().map(|n| n.to_string()).collect(),
        staying: 0,
        reasons: Vec::new(),
        complete: false,
        moved_total: total,
    };
    let elsewhere = |name: &str| {
        let mut vm = bound_to(Some("agent-2a"));
        vm.metadata.name = name.to_string();
        vm.status.node_name = Some("agent-2a".into());
        vm
    };
    let here = |name: &str| {
        let mut vm = bound_to(Some("agent-1a"));
        vm.metadata.name = name.to_string();
        vm.status.node_name = Some("agent-1a".into());
        vm
    };

    // Two were leaving; one has arrived on another machine, one is still on
    // its way.
    let vms = [elsewhere("mc-m3-a"), here("mc-m3-b")];
    assert_eq!(
        departed(
            Some(&was(&["mc-m3-a", "mc-m3-b"], 0)),
            &["mc-m3-b".to_string()],
            &[],
            &vms,
            "agent-1a"
        ),
        1
    );

    // The first pass of a drain has moved nothing by definition — there is no
    // previous list, and reading "not here" as "left" would count the fleet.
    assert_eq!(departed(None, &[], &[], &vms, "agent-1a"), 0);
}

/// And the three things that are not a move, each of which would let a drain
/// flatter itself.
#[test]
fn a_drain_does_not_count_what_it_did_not_move() {
    let was = controller_api::Draining {
        leaving: 1,
        leaving_vms: vec!["mc-m3-a".to_string()],
        staying: 0,
        reasons: Vec::new(),
        complete: false,
        moved_total: 0,
    };
    let mut vm = bound_to(Some("agent-2a"));
    vm.metadata.name = "mc-m3-a".into();
    vm.status.node_name = Some("agent-2a".into());

    // It came back onto the staying list — a live migration that could not
    // find a target does exactly this — so it did not leave.
    let staying = [controller_api::StayingVm {
        vm: "mc-m3-a".to_string(),
        reason: controller_api::StayReason::NoTarget.as_str().to_string(),
        message: "mc-m3-a stays".to_string(),
    }];
    assert_eq!(
        departed(
            Some(&was),
            &[],
            &staying,
            std::slice::from_ref(&vm),
            "agent-1a"
        ),
        0
    );

    // Somebody deleted it during the drain. A machine emptied by deletion is
    // not a machine a drain emptied.
    let mut deleted = vm.clone();
    deleted.metadata.deletion_timestamp = Some(Utc::now());
    assert_eq!(
        departed(
            Some(&was),
            &[],
            &[],
            std::slice::from_ref(&deleted),
            "agent-1a"
        ),
        0
    );
    assert_eq!(departed(Some(&was), &[], &[], &[], "agent-1a"), 0);

    // The binding fell and this node still reports the guest — the window
    // between letting go and the old node tearing it down. Still here.
    let mut still_here = vm.clone();
    still_here.spec.node_name = None;
    still_here.status.node_name = Some("agent-1a".into());
    assert_eq!(
        departed(
            Some(&was),
            &[],
            &[],
            std::slice::from_ref(&still_here),
            "agent-1a"
        ),
        0
    );
}

/// A VM bound to `agent-1a` in the phase given.
fn on_agent_1a(phase: VmPhaseKind) -> Vm {
    let mut vm = bound_to(Some("agent-1a"));
    #[allow(deprecated)]
    vm.status
        .assign(controller_api::VmPhase::of(phase, Utc::now()));
    vm
}

/// D10: a VM on a node nobody has heard from stops claiming to be Running.
///
/// The run measured three minutes and the lab's inventory showed days —
/// eleven guests on manacor reporting `Running` while the agent that would
/// know had been dead for twenty hours. Frozen clock, because the rule is
/// about a duration and a test that waited for one would be a test nobody
/// runs.
#[test]
fn a_vm_on_a_silent_node_stops_claiming_to_be_running() {
    let timeout = controller_api::HEARTBEAT_TIMEOUT_SECS;
    let vm = on_agent_1a(VmPhaseKind::Running);

    // Inside the watchdog: the node is quiet but not yet late.
    assert!(unheard_of(&vm, Some(at(0)), at(timeout)).is_none());

    // One second past it, and the phase is no longer a claim anybody can
    // make. The sentence names the node and when it was last heard, because
    // that is what sends an operator to the right machine.
    let said = unheard_of(&vm, Some(at(0)), at(timeout + 1)).expect("past the watchdog");
    assert!(said.contains("agent-1a"), "{said}");
    assert!(said.contains(&at(0).to_rfc3339()), "{said}");
    assert!(said.contains("not known here"), "{said}");

    // A node that has never reported at all — every node after a controller
    // restart, and the one the object exists for because somebody said Hello
    // once.
    assert!(
        unheard_of(&vm, None, at(0))
            .expect("never reported")
            .contains("has never reported")
    );
}

/// Which phases the silence can make untrue, and which it may not touch.
///
/// The ones it may not are not a convenience: `Failed` is a fact this tier
/// established and the requeue curve acts on, `Stopped` is a phase where
/// nothing is expected to be running anyway, and `Quarantined` is
/// deliberately nobody's to touch. Replacing any of them with "nobody knows"
/// would trade a fact for an absence.
#[test]
fn the_watchdog_only_takes_back_a_claim_about_a_guest() {
    let timeout = controller_api::HEARTBEAT_TIMEOUT_SECS + 1;
    for phase in [
        VmPhaseKind::Running,
        VmPhaseKind::Paused,
        VmPhaseKind::Provisioning,
    ] {
        assert!(
            unheard_of(&on_agent_1a(phase), Some(at(0)), at(timeout)).is_some(),
            "{phase:?} claims a guest and has to be given up"
        );
    }
    for phase in [
        VmPhaseKind::Pending,
        VmPhaseKind::Stopped,
        VmPhaseKind::Failed,
        VmPhaseKind::Quarantined,
        VmPhaseKind::Unknown,
    ] {
        assert!(
            unheard_of(&on_agent_1a(phase), Some(at(0)), at(timeout)).is_none(),
            "{phase:?} is not a claim a silence can make untrue"
        );
    }

    // And a VM that is not on a node at all: there is no machine whose
    // silence could mean anything about it.
    let mut unbound = bound_to(None);
    #[allow(deprecated)]
    unbound.status.assign(controller_api::VmPhase::of(
        VmPhaseKind::Running,
        Utc::now(),
    ));
    assert!(unheard_of(&unbound, Some(at(0)), at(timeout)).is_none());
}

/// `Unknown` is not `Failed`, and this is the difference that costs
/// something: `Failed` is what the requeue curve kicks, so a VM whose node
/// merely stopped talking would be re-created somewhere on the strength of no
/// evidence at all. It is also not stable, so no lifecycle command is derived
/// from it — a Stop sent at a guest nobody has looked at, down a session that
/// does not exist.
#[test]
fn unknown_is_neither_failed_nor_settled() {
    assert!(!VmPhaseKind::Unknown.is_stable());
    assert_eq!(VmPhaseKind::Unknown.as_str(), "Unknown");
    assert_eq!(VmPhaseKind::parse("Unknown"), Some(VmPhaseKind::Unknown));
    for strategy in [
        RunStrategy::Running,
        RunStrategy::Stopped,
        RunStrategy::Paused,
    ] {
        assert!(
            lifecycle_command(strategy, VmPhaseKind::Unknown).is_none(),
            "{strategy:?} sent a command at a phase nobody has observed"
        );
    }
}

/// A volume placed on a node, for the ownership tests below.
fn placed_on(node: Option<&str>) -> Volume {
    let mut v = controller_api::resources::new_volume(
        "data",
        controller_api::VolumeSpec {
            pool: "fast".into(),
            size_gib: 10,
            ..Default::default()
        },
    );
    v.status.node = node.map(str::to_string);
    v
}

/// D1, the whole of it: three replicas, one delivery, and the two that
/// cannot reach the node do not touch the object.
///
/// Before this rule existed, all three reconciled every volume. The one
/// holding the node's session provisioned it; the other two asked their own
/// registries, were told "node agent-1a has no active session", and wrote
/// that on the object as `Failed`. In the mini-chaos run EVERY provision on a
/// three-replica cluster went through `Failed` at least once, and a client
/// reading a phase it is entitled to treat as final saw a failure that had
/// not happened.
#[test]
fn a_placed_volume_is_only_reconciled_by_the_replica_its_node_talks_to() {
    let volume = placed_on(Some("agent-1a"));

    // The three replicas of cluster-1, as the run had them: .104 holds the
    // node's session, .110 and .111 do not.
    let holder = sessions(&["agent-1a"]);
    let other = sessions(&["agent-1b"]);
    let empty = sessions(&[]);

    assert!(
        may_reconcile_volume(&volume, &holder),
        "the replica holding the session provisions it"
    );
    assert!(
        !may_reconcile_volume(&volume, &other),
        "and a replica that cannot reach the node does not find out by sending"
    );
    assert!(!may_reconcile_volume(&volume, &empty));

    // Deleting changes nothing about who acts: destroying bytes is something
    // only that node can do, so a deleting volume waits for its replica
    // exactly as a deleting VM does.
    let mut deleting = volume.clone();
    deleting.metadata.deletion_timestamp = Some(Utc::now());
    #[allow(deprecated)]
    deleting.status.assign(controller_api::VolumePhase::of(
        VolumePhaseKind::Releasing,
        Utc::now(),
    ));
    assert!(may_reconcile_volume(&deleting, &holder));
    assert!(!may_reconcile_volume(&deleting, &other));
}

/// A snapshot of `data`, standing where the dispatch left it.
fn snapshot_on(node: Option<&str>) -> VolumeSnapshot {
    let mut s = controller_api::resources::new_volume_snapshot(
        "data-1",
        controller_api::VolumeSnapshotSpec {
            volume: "data".into(),
            ..Default::default()
        },
    );
    s.status.node = node.map(str::to_string);
    s
}

/// D1 a third time, on the object it was never applied to (chaos B-C1).
///
/// `take_snapshots` walked every snapshot on every replica. The one holding
/// the node's session took the copy; the other two asked their own registry,
/// were told the node has no active session, and `note_snapshot_failed` wrote
/// that onto the object as `Failed` — the same wrong sentence on the same
/// three-replica cluster the volume half showed, on an object a client is
/// entitled to read as final.
#[test]
fn a_dispatched_snapshot_is_only_reconciled_by_the_replica_its_node_talks_to() {
    let snapshot = snapshot_on(Some("agent-1a"));

    let holder = sessions(&["agent-1a"]);
    let other = sessions(&["agent-1b"]);
    let empty = sessions(&[]);

    assert!(
        may_reconcile_snapshot(&snapshot, &holder),
        "the replica holding the session takes the copy"
    );
    assert!(
        !may_reconcile_snapshot(&snapshot, &other),
        "and a replica that cannot reach the node does not find out by sending"
    );
    assert!(!may_reconcile_snapshot(&snapshot, &empty));

    // Deleting changes nothing about who acts, for the volume's reason:
    // destroying bytes is something only that node can do.
    let mut deleting = snapshot.clone();
    deleting.metadata.deletion_timestamp = Some(Utc::now());
    assert!(may_reconcile_snapshot(&deleting, &holder));
    assert!(!may_reconcile_snapshot(&deleting, &other));
}

/// A snapshot nobody has dispatched yet belongs to everybody, and it answers
/// the question exactly as an unplaced volume does.
///
/// It has to: a fresh snapshot on a cluster whose replicas hold different
/// nodes would otherwise be taken by nobody. What keeps the dispatch honest
/// is the volume it copies — the node comes from `volume.status.node`, and a
/// volume is only ever placed onto a node of the placing replica's own
/// session map.
#[test]
fn an_undispatched_snapshot_may_be_taken_by_any_replica_that_holds_its_volume() {
    for names in [&[][..], &["agent-1a"][..], &["agent-1b"][..]] {
        let held = sessions(names);
        assert!(may_reconcile_snapshot(&snapshot_on(None), &held));
        assert_eq!(
            may_reconcile_volume(&placed_on(Some("agent-1a")), &held),
            may_reconcile_snapshot(&snapshot_on(Some("agent-1a")), &held),
            "sessions {names:?}"
        );
    }
}

/// And the other half, which is the same one the VM rule has: a volume
/// nobody has placed yet belongs to everybody.
///
/// It has to, or a fresh volume on a cluster whose replicas hold different
/// nodes would be placed by nobody. What keeps the placement honest is the
/// candidate list — `connected` is the local session map — so whoever wins
/// the placement CAS placed it on a node it already owns.
#[test]
fn an_unplaced_volume_may_be_placed_by_any_replica() {
    assert!(may_reconcile_volume(&placed_on(None), &sessions(&[])));
    assert!(may_reconcile_volume(
        &placed_on(None),
        &sessions(&["agent-1a"])
    ));
    assert!(may_reconcile_volume(
        &placed_on(None),
        &sessions(&["agent-9z"])
    ));
}

/// The rule is exactly the VM rule, and this is what says so.
///
/// Two rules that are meant to be one and are written twice drift: the VM
/// half already grew a second arm (a VM whose binding fell is the old node's
/// business until it lets go), and if the volume half ever needs one, this
/// test is where the difference has to be argued rather than discovered.
#[test]
fn a_volume_and_a_vm_answer_the_same_question_the_same_way() {
    for names in [&[][..], &["agent-1a"][..], &["agent-1b"][..]] {
        let held = sessions(names);
        assert_eq!(
            may_reconcile(&bound_to(Some("agent-1a")), &held),
            may_reconcile_volume(&placed_on(Some("agent-1a")), &held),
            "sessions {names:?}"
        );
        assert_eq!(
            may_reconcile(&bound_to(None), &held),
            may_reconcile_volume(&placed_on(None), &held),
            "sessions {names:?}"
        );
    }
}

/// Draining is one bit and it belongs to the scheduler alone.
///
/// The session is what decides who reconciles a VM and what makes a
/// candidate `connected`; `spec.schedulable` is a separate field that
/// only ever narrows the set FirstFit may pick from. So a cordoned node
/// goes on owning, running and reconciling everything already bound to
/// it, and the only thing that changes is that nothing new lands there —
/// which is why cordon cannot evict, migrate or stop anything, and why
/// there is nothing in this file that would have to be careful not to.
#[test]
fn draining_a_node_changes_only_what_the_scheduler_may_pick() {
    let mine = sessions(&["manacor"]);
    let running = bound_to(Some("manacor"));
    // Bound: still this replica's, drained or not — `may_reconcile` does
    // not look at the node object at all, only at the session map, and
    // cordoning writes neither.
    assert!(may_reconcile(&running, &mine));

    let drained = Candidate {
        accepts: Vec::new(),
        kind: controller_api::CandidateKind::Node,
        labels: Default::default(),
        hosted: Vec::new(),
        name: "manacor".into(),
        connected: true,
        alive: true,
        schedulable: false,
        unhealthy: Vec::new(),
        // Room to spare: this test is about the drain and nothing else.
        free: controller_api::Capacity {
            vcpus: 64,
            mem_mib: 65536,
        },
        machine: None,
        // A compute node, because every VM requires one: without the
        // claim this test would pass for the wrong reason — not placed
        // because the node runs no VMs, rather than because it is
        // drained.
        catalogue: vec!["hypervisor/cloud-hypervisor".to_string()],
    };
    // Nothing NEW goes there, and the sentence on the object says which
    // of the reasons it is.
    let waiting = bound_to(None);
    assert_eq!(
        controller_api::FirstFit.assign(&waiting, std::slice::from_ref(&drained)),
        None
    );
    let (why, sentence) =
        controller_api::pending_reason_of(&waiting, std::slice::from_ref(&drained));
    assert_eq!(why, controller_api::PendingReason::NoneUsable);
    assert!(sentence.contains("connected and schedulable"), "{sentence}");

    // Uncordon: the same candidate, the same VM, placed.
    let back = Candidate {
        schedulable: true,
        ..drained
    };
    assert_eq!(
        controller_api::FirstFit
            .assign(&waiting, std::slice::from_ref(&back))
            .as_deref(),
        Some("manacor")
    );
}

/// Deleting changes nothing about who acts: only the node's own replica
/// can order the teardown, so a deleting VM on a foreign node waits.
#[test]
fn deleting_does_not_widen_ownership() {
    let mut vm = bound_to(Some("node-b"));
    vm.metadata.deletion_timestamp = Some(at(0));
    assert!(!may_reconcile(&vm, &sessions(&["node-a"])));
    assert!(may_reconcile(&vm, &sessions(&["node-b"])));
}

/// The whole retry timeline as a table: arm on first sighting, kick when
/// the policy's delay has passed, reset the moment the phase recovers —
/// and never touch a VM that is wanted Stopped, unbound, or whose policy
/// says Failed is final.
#[test]
fn the_requeue_timeline() {
    use controller_api::requeue::{CrashLoopBackoff, NoRequeue};
    let failed = |last: Option<chrono::DateTime<Utc>>, attempts: u32| {
        let mut vm = bound_to(Some("node-a"));
        #[allow(deprecated)]
        vm.status
            .assign(controller_api::VmPhase::of(VmPhaseKind::Failed, Utc::now()));
        vm.status.last_requeue = last;
        vm.status.requeue_attempts = attempts;
        vm
    };
    // healthy VM without bookkeeping: nothing; with leftovers: reset
    assert_eq!(
        requeue_decision(&bound_to(Some("node-a")), &CrashLoopBackoff, at(0)),
        Requeue::Not
    );
    let mut recovered = bound_to(Some("node-a"));
    recovered.status.requeue_attempts = 3;
    assert_eq!(
        requeue_decision(&recovered, &CrashLoopBackoff, at(0)),
        Requeue::Reset
    );
    // first sighting arms the clock, sends nothing
    assert_eq!(
        requeue_decision(&failed(None, 0), &CrashLoopBackoff, at(0)),
        Requeue::Arm
    );
    // attempt 0 is due after 10s, not after 9
    assert_eq!(
        requeue_decision(&failed(Some(at(0)), 0), &CrashLoopBackoff, at(9)),
        Requeue::Not
    );
    assert_eq!(
        requeue_decision(&failed(Some(at(0)), 0), &CrashLoopBackoff, at(10)),
        Requeue::Kick
    );
    // attempt 3 waits its 80s
    assert_eq!(
        requeue_decision(&failed(Some(at(0)), 3), &CrashLoopBackoff, at(79)),
        Requeue::Not
    );
    assert_eq!(
        requeue_decision(&failed(Some(at(0)), 3), &CrashLoopBackoff, at(80)),
        Requeue::Kick
    );
    // "none" restores the old world: Failed stays Failed
    assert_eq!(
        requeue_decision(&failed(Some(at(0)), 0), &NoRequeue, at(3600)),
        Requeue::Not
    );
    // wanted Stopped or never bound: not this mechanism's business
    let mut stopped = failed(Some(at(0)), 0);
    stopped.spec.run_strategy = RunStrategy::Stopped;
    assert_eq!(
        requeue_decision(&stopped, &CrashLoopBackoff, at(3600)),
        Requeue::Not
    );
    let mut unbound = failed(Some(at(0)), 0);
    unbound.spec.node_name = None;
    assert_eq!(
        requeue_decision(&unbound, &CrashLoopBackoff, at(3600)),
        Requeue::Not
    );
}

// ---- the joint cross product ------------------------------------------
//
// `lifecycle_command` and `requeue_decision` are the two pure decisions
// `reconcile_vm` takes about a VM, and it takes them both in the same
// pass, about the same object. Each has its own table above; what neither
// can say alone is what the pair does together — and that is the thing
// that can go wrong, because both of them can end in a message to the
// node. The cross product below is every combination of their inputs,
// with the joint answer.

/// The requeue side's whole input, spread over every dimension it reads.
/// `elapsed` is seconds since `last_requeue`; -5 is a clock that went
/// backwards, 9/10 and 79/80 straddle the CrashLoopBackoff delays for
/// attempt 0 and attempt 3.
fn requeue_inputs() -> Vec<(Option<i64>, u32)> {
    let mut out = Vec::new();
    for elapsed in [
        None,
        Some(-5),
        Some(0),
        Some(9),
        Some(10),
        Some(79),
        Some(80),
        Some(3600),
    ] {
        for attempts in [0u32, 3] {
            out.push((elapsed, attempts));
        }
    }
    out
}

fn policies() -> Vec<(&'static str, Box<dyn RequeuePolicy>)> {
    use controller_api::requeue::{CrashLoopBackoff, NoRequeue, RetryCount};
    vec![
        ("none", Box::new(NoRequeue)),
        ("count(2)", Box::new(RetryCount(2))),
        ("crash-loop-backoff", Box::new(CrashLoopBackoff)),
    ]
}

/// One cell of the joint space, built from the two functions' dimensions.
#[allow(clippy::type_complexity)]
fn joint_cells() -> Vec<(String, Vm, DateTime<Utc>, usize)> {
    let mut out = Vec::new();
    for (policy_index, (policy_name, _)) in policies().into_iter().enumerate() {
        for phase in VmPhaseKind::ALL {
            for strategy in RunStrategy::ALL {
                for node in [None, Some("node-a")] {
                    for (elapsed, attempts) in requeue_inputs() {
                        let mut vm = bound_to(node);
                        vm.spec.run_strategy = strategy;
                        #[allow(deprecated)]
                        vm.status
                            .assign(controller_api::VmPhase::of(phase, Utc::now()));
                        vm.status.requeue_attempts = attempts;
                        vm.status.last_requeue = elapsed.map(|e| at(-e));
                        let label = format!(
                            "policy={policy_name} phase={phase:?} strategy={strategy:?} \
                             node={node:?} elapsed={elapsed:?} attempts={attempts}"
                        );
                        out.push((label, vm, at(0), policy_index));
                    }
                }
            }
        }
    }
    out
}

/// What the requeue side must answer, as an ordered list of guards rather
/// than as a copy of `requeue_decision`'s control flow.
fn expected_requeue(vm: &Vm, policy: &dyn RequeuePolicy, now: DateTime<Utc>) -> Requeue {
    if vm.status.phase().kind() != VmPhaseKind::Failed {
        // Not Failed: nothing to retry, but bookkeeping left over from an
        // earlier Failed has to be cleared or the next failure would
        // inherit somebody else's attempt count.
        return if vm.status.requeue_attempts > 0 || vm.status.last_requeue.is_some() {
            Requeue::Reset
        } else {
            Requeue::Not
        };
    }
    if vm.spec.run_strategy == RunStrategy::Stopped {
        return Requeue::Not; // a VM nobody wants running needs no healing
    }
    if vm.spec.node_name.is_none() {
        return Requeue::Not; // no node to kick; the Pending path owns it
    }
    let Some(since) = vm.status.last_requeue else {
        return Requeue::Arm; // first sighting: start the clock, send nothing
    };
    let Some(delay) = policy.next_delay(vm.status.requeue_attempts) else {
        return Requeue::Not; // the policy says Failed is final
    };
    match now.signed_duration_since(since).to_std() {
        Ok(elapsed) if elapsed >= delay => Requeue::Kick,
        // Includes a clock that went backwards: to_std() refuses a
        // negative span, and waiting is the safe reading of it.
        _ => Requeue::Not,
    }
}

/// Every cell of both decisions at once — 2304 of them — against the
/// guards above. What this buys over the two tables separately is the
/// next test; this one is what makes it trustworthy.
#[test]
fn the_joint_cross_product_decides_what_the_guards_say() {
    let policies = policies();
    let mut cells = 0usize;
    for (label, vm, now, policy_index) in joint_cells() {
        let policy = policies[policy_index].1.as_ref();
        assert_eq!(
            requeue_decision(&vm, policy, now),
            expected_requeue(&vm, policy, now),
            "{label}"
        );
        cells += 1;
    }
    assert_eq!(
        cells,
        3 * VmPhaseKind::ALL.len() * 3 * 2 * 16,
        "the joint space is not the size it was"
    );
}

/// The invariant the pair exists to keep and neither half can state: the
/// two never both send. A Kick re-sends the whole spec as a Create; a
/// lifecycle command names a transition on a record the agent already
/// has. Both in one pass would be the controller arguing with itself
/// about the same VM in the same tick — and the node would see the two in
/// whichever order they happened to leave.
///
/// It holds structurally, and it is worth pinning because it holds for a
/// reason that is easy to lose: Kick fires only at Failed, and Failed is
/// exactly one of the phases `lifecycle_command` refuses to argue with.
/// Moving Failed to the stable side of that line — which has been done
/// once already, see 6315d84 — would break this silently.
#[test]
fn a_requeue_kick_and_a_lifecycle_command_never_fire_in_the_same_pass() {
    let policies = policies();
    let mut kicks = 0usize;
    let mut commands = 0usize;
    for (label, vm, now, policy_index) in joint_cells() {
        let requeue = requeue_decision(&vm, policies[policy_index].1.as_ref(), now);
        let command = lifecycle_command(vm.spec.run_strategy, vm.status.phase().kind());
        if requeue == Requeue::Kick {
            kicks += 1;
            assert!(
                command.is_none(),
                "kick and {command:?} in one pass: {label}"
            );
            assert_eq!(
                vm.status.phase().kind(),
                VmPhaseKind::Failed,
                "a kick outside Failed: {label}"
            );
        }
        if command.is_some() {
            commands += 1;
            assert!(
                matches!(requeue, Requeue::Not | Requeue::Reset),
                "{command:?} alongside {requeue:?}: {label}"
            );
        }
    }
    // Both actually occur; an invariant nothing reaches proves nothing.
    assert!(
        kicks > 0 && commands > 0,
        "kicks={kicks} commands={commands}"
    );
}

/// The one overlap that IS allowed, and why it is harmless: Reset writes
/// nothing but the VM's own retry bookkeeping, so it can share a pass
/// with a command without the two meaning anything to each other. It is
/// also the only requeue answer that can: Arm and Kick both need Failed,
/// and Failed gets no command.
#[test]
fn only_reset_may_share_a_pass_with_a_command() {
    let policies = policies();
    let mut shared = 0usize;
    for (label, vm, now, policy_index) in joint_cells() {
        let requeue = requeue_decision(&vm, policies[policy_index].1.as_ref(), now);
        if lifecycle_command(vm.spec.run_strategy, vm.status.phase().kind()).is_none() {
            continue;
        }
        assert_ne!(requeue, Requeue::Arm, "{label}");
        assert_ne!(requeue, Requeue::Kick, "{label}");
        if requeue == Requeue::Reset {
            shared += 1;
        }
    }
    assert!(
        shared > 0,
        "the permitted overlap never occurs, so it is not being tested"
    );
}

/// Quarantined is the phase that exists so nothing automatic touches the
/// VM, and both halves have to honour it — `lifecycle_command` by not
/// arguing with it, `requeue_decision` by not treating it as a failure to
/// heal. Stated over the whole space because it is the one guarantee an
/// operator is given by name (see BACKEND_DIED_REASON in the agent).
#[test]
fn nothing_automatic_touches_a_quarantined_vm() {
    let policies = policies();
    for (label, vm, now, policy_index) in joint_cells() {
        if vm.status.phase().kind() != VmPhaseKind::Quarantined {
            continue;
        }
        assert_eq!(
            lifecycle_command(vm.spec.run_strategy, vm.status.phase().kind()),
            None,
            "{label}"
        );
        let requeue = requeue_decision(&vm, policies[policy_index].1.as_ref(), now);
        assert!(
            matches!(requeue, Requeue::Not | Requeue::Reset),
            "{requeue:?} on a quarantined vm: {label}"
        );
    }
}

/// The retry bookkeeping only ever survives a phase that is still Failed:
/// the moment the VM leaves it, the counters are cleared. Without this a
/// VM that failed once, recovered, and failed again a week later would
/// start its second life on the far end of the backoff curve.
#[test]
fn leaving_failed_always_clears_the_bookkeeping() {
    let policies = policies();
    for (label, vm, now, policy_index) in joint_cells() {
        if vm.status.phase().kind() == VmPhaseKind::Failed {
            continue;
        }
        let has_bookkeeping = vm.status.requeue_attempts > 0 || vm.status.last_requeue.is_some();
        let requeue = requeue_decision(&vm, policies[policy_index].1.as_ref(), now);
        assert_eq!(
            requeue == Requeue::Reset,
            has_bookkeeping,
            "{requeue:?} with bookkeeping={has_bookkeeping}: {label}"
        );
    }
}

fn vm_with(run_strategy: RunStrategy) -> Vm {
    controller_api::resources::new_vm(
        "t",
        controller_api::VmSpec {
            class: Default::default(),
            evacuation: Default::default(),
            cluster_selector: Default::default(),
            node_selector: Default::default(),
            anti_affinity: Vec::new(),
            node_name: None,
            cluster_name: None,
            run_strategy,
            tenant: None,
            vm: serde_json::json!({ "vcpus": 1 }),
        },
    )
}

/// The agent has no RunStrategy type: the variant name travels in
/// spec_json and its own serde is what has to accept it. The other half
/// of the contract is guarded in the agent's types.rs.
#[test]
fn the_run_strategy_travels_as_the_agents_desired_state() {
    for (strategy, spelling) in [
        (RunStrategy::Running, "Running"),
        (RunStrategy::Stopped, "Stopped"),
        (RunStrategy::Paused, "Paused"),
    ] {
        let doc: serde_json::Value = serde_json::from_str(
            &build_spec_json(&vm_with(strategy), &VolumeUids::new(), None).unwrap(),
        )
        .unwrap();
        assert_eq!(doc["desired"], spelling);
        // and nothing else about the spec is touched on the way through
        assert_eq!(doc["vcpus"], 1);
    }
}

/// The guest's hostname comes from the object's own name, and this tier
/// is where it is filled in because it is the last one that knows it: a
/// node holds a uid and nothing else, so a seed built down there could
/// only ever derive a uuid for a hostname.
///
/// And it is filled in only where it was left out. A VM with no
/// cloud-init block gets nothing added to its spec at all, which is the
/// property the whole feature is judged on.
#[test]
fn the_seeds_hostname_comes_from_the_vm_object_and_only_when_it_was_left_out() {
    let seeded = |cloud_init: serde_json::Value| {
        let mut vm = bound_to(None);
        vm.metadata.name = "web-1".into();
        vm.spec.vm = serde_json::json!({"vcpus": 1, "cloud_init": cloud_init});
        let doc: serde_json::Value =
            serde_json::from_str(&build_spec_json(&vm, &VolumeUids::new(), None).unwrap()).unwrap();
        doc
    };

    let filled = seeded(serde_json::json!({"user_data": "x"}));
    assert_eq!(filled["cloud_init"]["local_hostname"], "web-1");
    assert_eq!(filled["cloud_init"]["user_data"], "x", "untouched");

    // Somebody who said one keeps it.
    let theirs = seeded(serde_json::json!({"user_data": "x", "local_hostname": "chosen"}));
    assert_eq!(theirs["cloud_init"]["local_hostname"], "chosen");

    // No block, nothing added: the spec that goes down is the spec that
    // came in, plus the `desired` this function has always written.
    let mut plain = bound_to(None);
    plain.spec.vm = serde_json::json!({"vcpus": 1});
    let doc: serde_json::Value =
        serde_json::from_str(&build_spec_json(&plain, &VolumeUids::new(), None).unwrap()).unwrap();
    assert!(doc.get("cloud_init").is_none());
    assert_eq!(
        doc.as_object().map(|o| o.len()),
        Some(2),
        "vcpus and desired, and nothing invented"
    );
}

/// The name a person wrote is swapped for the uid a node can act on —
/// the same rule `CreateInstance.id` follows for the VM itself. An inline
/// entry beside it is untouched.
#[test]
fn the_spec_that_reaches_a_node_names_volumes_by_uid() {
    let mut vm = controller_api::resources::new_vm(
        "web-1",
        serde_json::from_value(serde_json::json!({
            "vm": {
                "vcpus": 1,
                "memory_mib": 64,
                "boot": {"kind": "firmware", "firmware": "/fw"},
                "volumes": [
                    {"volume": "data-1"},
                    {"base_image": "tiny.raw", "size_bytes": 2048}
                ]
            }
        }))
        .unwrap(),
    );
    vm.spec.run_strategy = RunStrategy::Running;

    let mut uids = VolumeUids::new();
    uids.insert(
        "data-1".to_string(),
        "11111111-2222-3333-4444-555555555555".into(),
    );
    let doc: serde_json::Value =
        serde_json::from_str(&build_spec_json(&vm, &uids, None).unwrap()).unwrap();
    assert_eq!(
        doc["volumes"][0]["volume"], "11111111-2222-3333-4444-555555555555",
        "a name is what people call it; a uid is which one it is"
    );
    assert!(doc["volumes"][1].get("volume").is_none());
    assert_eq!(doc["volumes"][1]["size_bytes"], 2048);

    // A name with no uid is a volume that vanished between the two reads,
    // and a spec still carrying a name is one a node cannot act on.
    let err = build_spec_json(&vm, &VolumeUids::new(), None).expect_err("refused");
    assert!(format!("{err:#}").contains("data-1"), "{err:#}");
}

/// The reference becomes the value, and the reference itself always goes.
///
/// The second half is the safety net and the reason it is unconditional:
/// the agent's `CloudInit` is `deny_unknown_fields`, so a spec that
/// reached a node still carrying `user_data_from` is a REFUSED create.
/// Loud, and never a guest that boots without its configuration.
#[test]
fn a_secret_reference_is_replaced_by_its_value_before_the_spec_travels() {
    let with = |cloud_init: serde_json::Value| {
        let mut vm = controller_api::resources::new_vm(
            "web-1",
            serde_json::from_value(serde_json::json!({
                "vm": { "vcpus": 1, "memory_mib": 512, "cloud_init": cloud_init }
            }))
            .unwrap(),
        );
        vm.spec.run_strategy = RunStrategy::Running;
        vm
    };

    let vm = with(serde_json::json!({
        "user_data_from": { "secret": "db", "key": "password" }
    }));
    let doc: serde_json::Value = serde_json::from_str(
        &build_spec_json(&vm, &VolumeUids::new(), Some("#cloud-config\n")).unwrap(),
    )
    .unwrap();
    assert_eq!(doc["cloud_init"]["user_data"], "#cloud-config\n");
    assert!(
        doc["cloud_init"].get("user_data_from").is_none(),
        "the reference does not travel: {doc}"
    );
    // And the hostname the same pass fills in is still filled in.
    assert_eq!(doc["cloud_init"]["local_hostname"], "web-1");

    // Unresolved — which cannot happen through a dispatch, because the
    // caller stops at NotReady — still strips the field rather than
    // sending it. The guest gets no user-data and the node refuses
    // nothing; what the object says is the Pending reason.
    let doc: serde_json::Value =
        serde_json::from_str(&build_spec_json(&vm, &VolumeUids::new(), None).unwrap()).unwrap();
    assert!(doc["cloud_init"].get("user_data_from").is_none(), "{doc}");
    assert!(doc["cloud_init"].get("user_data").is_none(), "{doc}");

    // A literal cloud-init is untouched by any of this.
    let literal = with(serde_json::json!({ "user_data": "#cloud-config\nmine\n" }));
    let doc: serde_json::Value = serde_json::from_str(
        &build_spec_json(&literal, &VolumeUids::new(), Some("not this")).unwrap(),
    )
    .unwrap();
    assert_eq!(doc["cloud_init"]["user_data"], "#cloud-config\nmine\n");
}

fn volume_at(node: Option<&str>, phase: VolumePhaseKind) -> Volume {
    let mut v = controller_api::resources::new_volume(
        "data-1",
        controller_api::VolumeSpec {
            pool: "local".into(),
            size_gib: 1,
            ..Default::default()
        },
    );
    v.status.node = node.map(str::to_string);
    #[allow(deprecated)]
    v.status
        .assign(controller_api::VolumePhase::of(phase, Utc::now()));
    v
}

/// Every row of the lifecycle table that is a pure rule, as values.
///
/// The interesting one is the last: a volume whose node reported `Gone`
/// has had that node cleared, so it reaches `Drop` through the rule the
/// never-placed case already needed. That is what completes a delete, and
/// it is why the ingest clears the node rather than inventing a phase.
#[test]
fn the_release_table_reads_the_same_rule_for_both_ways_of_being_empty() {
    let none: [String; 0] = [];
    // Held: everything stays, and the sentence is the one an operator
    // acts on.
    assert_eq!(
        release_action(&released(Some("manacor"), Some("web-1")), &none),
        Release::HeldBy(HeldBy::Vm("web-1"))
    );
    // Nobody holds it and a node has the bytes: the deprovision is next.
    assert_eq!(
        release_action(&released(Some("manacor"), None), &none),
        Release::WaitingForNode("manacor")
    );
    // Never placed: nothing to lose.
    assert_eq!(release_action(&released(None, None), &none), Release::Drop);
    // Placed, then the node said Gone and the ingest cleared it: the very
    // same answer, which is the whole point.
    let mut after_gone = released(Some("manacor"), None);
    after_gone.status.node = None;
    assert_eq!(release_action(&after_gone, &none), Release::Drop);
}

/// A placement chooses a node and says so, and nothing more. It used to
/// write `Provisioning` — a phase claiming a node was making the volume
/// while nothing had told any node anything, which is exactly why every
/// standalone volume sat in it for ever.
#[test]
fn a_placed_volume_is_still_pending_until_the_command_goes() {
    let v = volume_at(Some("manacor"), VolumePhaseKind::Pending);
    assert_eq!(v.status.phase().kind(), VolumePhaseKind::Pending);
    assert!(
        v.status.backend.is_empty(),
        "the backend name arrives with the dispatch"
    );
}

/// The agent spec a Provision carries: the pool decides the driver, the
/// GiB become bytes, and the params merge with the volume's word on top.
#[test]
fn the_pools_driver_and_params_are_what_reach_the_node() {
    let merged = merge_params(
        Some(&serde_json::json!({"vg": "vg0", "thin": "pool0"})),
        Some(&serde_json::json!({"thin": "pool1"})),
    )
    .expect("merged");
    assert_eq!(merged["vg"], "vg0", "the pool is the default");
    assert_eq!(merged["thin"], "pool1", "and the volume is the request");

    assert_eq!(
        merge_params(Some(&serde_json::json!({"vg": "vg0"})), None).unwrap()["vg"],
        "vg0"
    );
    assert!(merge_params(None, None).is_none());
    // Either side not an object: the later word stands whole rather than
    // being merged into something with no keys.
    assert_eq!(
        merge_params(
            Some(&serde_json::json!("pool")),
            Some(&serde_json::json!(7))
        )
        .unwrap(),
        serde_json::json!(7)
    );
}

/// A GiB is a whiteboard unit and a driver wants bytes. Asserted because
/// getting it wrong is a disk a thousand times the wrong size, and
/// `saturating_mul` is what keeps an absurd number from wrapping into a
/// small one.
#[test]
fn gibibytes_become_bytes_without_wrapping() {
    let gib = |n: u64| n.saturating_mul(1024 * 1024 * 1024);
    assert_eq!(gib(1), 1_073_741_824);
    assert_eq!(gib(10), 10_737_418_240);
    assert_eq!(gib(u64::MAX), u64::MAX, "absurd stays absurd, never small");
}

/// A report older than the last thing this tier did is evidence about
/// nothing. The case that matters is a stale `Gone`: acting on it would
/// clear the node off a volume whose bytes are on it.
#[test]
fn a_report_from_before_the_last_command_changes_nothing() {
    let t = |secs: i64| Utc::now() + chrono::Duration::seconds(secs);
    use controller_api::mirror::is_current;
    assert!(is_current(None, None, t(0)), "nothing has been done yet");
    assert!(
        !is_current(Some(t(10)), None, t(5)),
        "older than the delete"
    );
    assert!(
        is_current(Some(t(10)), None, t(10)),
        "the status that set the floor"
    );
    assert!(is_current(Some(t(5)), Some(t(10)), t(11)));
    assert!(
        !is_current(Some(t(5)), Some(t(10)), t(9)),
        "the later of the two is the floor"
    );
}

/// The drift a hot-plug is driven by: what the SPEC asks for against what
/// the NODE says it has open.
///
/// Read off `status.volumes` and never off `observedGeneration`, and the
/// last two cases are why. A generation says a spec was written; what has
/// to be answered here is whether the bytes are open, and an agent
/// restart or an attach that failed inside the node leaves the first
/// satisfied and the second false.
#[test]
fn the_drift_is_what_the_node_has_against_what_the_spec_asks_for() {
    let vm = |wanted: &[&str], held: &[(&str, bool)], phase: VmPhaseKind| {
        let mut v = volume_vm(wanted);
        #[allow(deprecated)]
        v.status
            .assign(controller_api::VmPhase::of(phase, Utc::now()));
        v.status.volumes = held
            .iter()
            .map(|(name, attached)| controller_api::VolumeAttachmentStatus {
                name: (*name).to_string(),
                attached: *attached,
            })
            .collect();
        v
    };

    // Settled: what it asks for is what it has.
    assert!(volume_drift(&vm(&["data-1"], &[("data-1", true)], VmPhaseKind::Running)).is_none());
    // A VM with no referenced disks never drifts, which is every VM
    // before this milestone.
    assert!(volume_drift(&vm(&[], &[], VmPhaseKind::Running)).is_none());

    // The attach: the spec grew an entry the node has not got.
    let drift = volume_drift(&vm(
        &["data-1", "data-2"],
        &[("data-1", true)],
        VmPhaseKind::Running,
    ))
    .expect("one disk is missing");
    assert_eq!(drift.attach, vec!["data-2".to_string()]);
    assert!(drift.release.is_empty());

    // The detach: the node has one the spec no longer names.
    let drift = volume_drift(&vm(
        &["data-1"],
        &[("data-1", true), ("data-2", true)],
        VmPhaseKind::Running,
    ))
    .expect("one disk is spare");
    assert!(drift.attach.is_empty());
    assert_eq!(drift.release, vec!["data-2".to_string()]);

    // A disk the node reports as NOT attached is drift as much as one it
    // does not mention: an attach that failed inside the node acked its
    // command, so "told" would say this was finished and it is not.
    let drift = volume_drift(&vm(&["data-1"], &[("data-1", false)], VmPhaseKind::Running))
        .expect("asked for, not open");
    assert_eq!(drift.attach, vec!["data-1".to_string()]);

    // And no drift is acted on where there is no record to diff against.
    // Pending goes through the create path; Failed is on the requeue
    // curve, which re-sends this very spec with a backoff — plugging a
    // disk into a VM that will not boot would be a command per pass.
    for phase in [
        VmPhaseKind::Pending,
        VmPhaseKind::Failed,
        VmPhaseKind::Provisioning,
    ] {
        assert!(
            volume_drift(&vm(&["data-1", "data-2"], &[("data-1", true)], phase)).is_none(),
            "{phase:?}"
        );
    }
}

/// A node-local volume on another machine is not an attach, it is a move,
/// and the two must be told apart before a node is handed a path that is
/// not on it.
#[test]
fn a_node_local_volume_pins_a_vm_to_the_machine_that_holds_it() {
    let binding =
        |locality, node: Option<&str>, pool_nodes: Vec<String>| controller_api::VolumeBinding {
            volume: "data-2".into(),
            node: node.map(str::to_string),
            locality,
            // This test is about the NAME half; the claim half is
            // `a_networked_volume_is_reachable_by_whoever_carries_the_driver`.
            driver: None,
            pool_nodes,
        };
    let here = binding(Some(Locality::NodeLocal), Some("agent-1"), vec![]);
    assert!(!here.pins_elsewhere("agent-1"));
    assert!(here.pins_elsewhere("agent-2"), "the bytes are on agent-1");

    // Shared opens the pool's nodes and nothing beyond them.
    let shared = binding(
        Some(Locality::Shared),
        Some("agent-1"),
        vec!["agent-1".into(), "agent-2".into()],
    );
    assert!(!shared.pins_elsewhere("agent-2"));
    assert!(shared.pins_elsewhere("agent-3"));

    // And silence never pins: an unplaced volume, a pool nobody reported
    // a locality for, a shared pool that names no nodes.
    assert!(!binding(Some(Locality::NodeLocal), None, vec![]).pins_elsewhere("agent-2"));
    assert!(!binding(None, Some("agent-1"), vec![]).pins_elsewhere("agent-2"));
    assert!(!binding(Some(Locality::Shared), Some("agent-1"), vec![]).pins_elsewhere("agent-9"));
}

/// Whether a guest has to stand still is the NODE's answer, not a table
/// here. It used to be a driver-name comparison against `lvm-thin`, and
/// that was true until `filesystem` learned to reflink: the same driver
/// copies on ext4 and clones on XFS, and only the node that probed its
/// own pool knows which.
///
/// `None` — nothing learned — must fall through to the pause. A node from
/// before the claim sends only the bare entry, and reading that as
/// "atomic" would tear a copy on every one of them.
#[test]
fn the_catalogue_says_whether_a_copy_needs_a_standstill() {
    use common::capability::{SnapshotConsistency, snapshot_claim};

    let catalogue = |profiles: &[String]| -> Vec<String> {
        profiles
            .iter()
            .map(|p| common::capability::entry(common::capability::VOLUME, Some(p)))
            .collect()
    };

    let modern = catalogue(&[
        "filesystem".into(),
        snapshot_claim("filesystem", SnapshotConsistency::Atomic),
        snapshot_claim("nfs", SnapshotConsistency::NeedsQuiesce),
    ]);
    assert_eq!(
        consistency_in(&modern, "filesystem"),
        Some(SnapshotConsistency::Atomic)
    );
    assert_eq!(
        consistency_in(&modern, "nfs"),
        Some(SnapshotConsistency::NeedsQuiesce)
    );
    // A backend this node says nothing about.
    assert_eq!(consistency_in(&modern, "lvm-thin"), None);

    // An agent from before the claim: the bare entry only, which says
    // "I can" and nothing about how.
    let old = catalogue(&["lvm-thin".into(), "lvm-thin/snapshot".into()]);
    assert_eq!(
        consistency_in(&old, "lvm-thin"),
        None,
        "nothing learned, so the caller pauses"
    );
    assert_eq!(consistency_in(&[], "filesystem"), None);
}

/// The quiesce sequence, which is the part of a snapshot with something
/// at stake in it.
///
/// Three rules, and each is a different thing that goes wrong otherwise:
/// a pause that failed cancels the work (a copy nobody was told is torn
/// is worse than no copy); the resume runs whatever happened (a guest
/// left paused by a backup is an outage this stack caused); and a resume
/// that failed does not replace the work's answer (the operator has two
/// problems and hiding the first behind the second helps with neither).
#[tokio::test]
async fn the_guest_is_resumed_whatever_the_copy_did() {
    use std::sync::Mutex as StdMutex;
    let guest = ("vm-uid".to_string(), "agent-1".to_string());

    let log: Arc<StdMutex<Vec<String>>> = Arc::new(StdMutex::new(Vec::new()));
    let tell = |fails: Option<Halt>, log: Arc<StdMutex<Vec<String>>>| {
        move |node: String, vm: String, halt: Halt| {
            let log = log.clone();
            async move {
                log.lock().unwrap().push(format!("{halt:?} {vm}@{node}"));
                match fails {
                    Some(f) if f == halt => Err(anyhow::anyhow!("no session")),
                    _ => Ok(()),
                }
            }
        }
    };
    let working = |log: Arc<StdMutex<Vec<String>>>| async move {
        log.lock().unwrap().push("snapshot".into());
        Ok::<_, anyhow::Error>(())
    };

    // The happy path, and the order IS the assertion.
    quiesced(Some(&guest), tell(None, log.clone()), working(log.clone()))
        .await
        .expect("the copy is taken");
    assert_eq!(
        *log.lock().unwrap(),
        vec![
            "Pause vm-uid@agent-1".to_string(),
            "snapshot".into(),
            "Resume vm-uid@agent-1".into(),
        ]
    );

    // The copy failed: the guest still comes back, and the failure is the
    // answer.
    log.lock().unwrap().clear();
    let failing = {
        let log = log.clone();
        async move {
            log.lock().unwrap().push("snapshot".into());
            Err::<(), _>(anyhow::anyhow!("the backend refused"))
        }
    };
    let err = quiesced(Some(&guest), tell(None, log.clone()), failing)
        .await
        .expect_err("the copy failed");
    assert!(format!("{err:#}").contains("the backend refused"));
    assert_eq!(
        log.lock().unwrap().last().map(String::as_str),
        Some("Resume vm-uid@agent-1"),
        "a guest left paused by a failed backup is an outage this stack caused"
    );

    // The pause failed: the copy is NOT taken, and there is nothing to
    // resume because nothing was stopped.
    log.lock().unwrap().clear();
    let err = quiesced(
        Some(&guest),
        tell(Some(Halt::Pause), log.clone()),
        working(log.clone()),
    )
    .await
    .expect_err("no pause, no copy");
    assert!(format!("{err:#}").contains("pausing the vm"), "{err:#}");
    assert_eq!(
        *log.lock().unwrap(),
        vec!["Pause vm-uid@agent-1".to_string()]
    );

    // The resume failed: logged, and the work's answer stands. An
    // operator has two problems and needs to be told about the first.
    log.lock().unwrap().clear();
    quiesced(
        Some(&guest),
        tell(Some(Halt::Resume), log.clone()),
        working(log.clone()),
    )
    .await
    .expect("the copy was taken, whatever the resume did");

    // And nothing to quiesce is the work and nothing else — an atomic
    // backend, a volume nobody holds, a guest that is not running.
    log.lock().unwrap().clear();
    quiesced(None, tell(None, log.clone()), working(log.clone()))
        .await
        .expect("no pause needed");
    assert_eq!(*log.lock().unwrap(), vec!["snapshot".to_string()]);
}

/// The drift a resize is driven by, and the two ways it can half-happen.
///
/// `grew` reads `status.sizeGib` — what the node MEASURED — against
/// `spec.sizeGib` — what was asked for. Not `observedGeneration`, for the
/// reason hot-plug's drift is not read off it either: a generation says a
/// spec was written, and what has to be answered is whether the room is
/// there.
#[test]
fn a_resize_is_driven_by_what_the_node_measured() {
    let volume = |spec_gib: u64, status_gib: u64| {
        let mut v = controller_api::resources::new_volume(
            "data",
            controller_api::VolumeSpec {
                pool: "fast".into(),
                size_gib: spec_gib,
                ..Default::default()
            },
        );
        #[allow(deprecated)]
        v.status.assign(controller_api::VolumePhase::of(
            VolumePhaseKind::Ready,
            Utc::now(),
        ));
        v.status.node = Some("agent-1".into());
        v.status.size_gib = status_gib;
        v
    };
    assert!(grew(&volume(2, 1)), "asked for more than the node has");
    assert!(!grew(&volume(1, 1)), "settled");
    assert!(
        !grew(&volume(1, 2)),
        "lvm rounds up, so a bigger measurement than the request is ordinary"
    );
    // Zero is "not measured" and cannot be compared: a volume nobody has
    // reported on yet is not one that shrank to nothing, and reading it
    // as drift would send a resize at every volume of every pass.
    assert!(!grew(&volume(10, 0)));
}

/// A resize that half-happened, as the sentence an operator reads.
///
/// The two halves are not symmetric and not reversible: the backend grows
/// first and the guest is told second, on what may be a different
/// machine. When the second fails there is nothing to roll back — there
/// is no shrinking — so the honest state is "the room is there, the guest
/// does not know", and the phase stays Ready because the object is not
/// broken.
#[test]
fn a_resize_that_half_happened_says_which_half() {
    let said = guest_not_told(2, "node agent-2 has no active session");
    assert!(said.contains("backend grew to 2 GiB"), "{said}");
    assert!(said.contains("the guest was not told"), "{said}");
    assert!(
        said.contains("node agent-2 has no active session"),
        "and the reason, verbatim: {said}"
    );
    assert!(
        said.contains("retry resizes only the notification"),
        "and what a retry does: {said}"
    );
}

/// A node that said "I cannot serve this VM" stops being a candidate for
/// it, for a while and not for ever.
///
/// Without the memory the scheduler would very likely choose it again —
/// nothing else about the node changed — and the VM would walk a loop of
/// one refused create per pass. With a permanent memory an operator who
/// installs the missing driver would have to clear a field nobody told
/// them about.
#[test]
fn a_node_that_cannot_serve_a_vm_is_no_candidate_for_it_for_a_while() {
    let now = Utc::now();
    let mut vm = volume_vm(&[]);
    vm.status.refused_by = vec![
        controller_api::VmRefusal {
            node: "agent-2".into(),
            message: "volume driver \"lvm-thin\" is not configured on this node".into(),
            until: now + chrono::Duration::minutes(5),
        },
        controller_api::VmRefusal {
            node: "agent-3".into(),
            message: "this node cannot run a vm".into(),
            until: now - chrono::Duration::minutes(1),
        },
    ];
    assert_eq!(refusing_now(&vm, now), vec!["agent-2".to_string()]);
    // An expired one is simply not counted, and it is not swept: the next
    // create either succeeds and nobody looks again, or is refused and
    // overwrites the entry.
    assert_eq!(vm.status.refused_by.len(), 2);
    // And later, neither counts.
    assert!(refusing_now(&vm, now + chrono::Duration::minutes(10)).is_empty());
    // A VM nobody refused constrains nothing, which is every VM.
    assert!(refusing_now(&volume_vm(&[]), now).is_empty());

    // The refusal keeps the NODE'S OWN sentence. It is what an operator
    // reads to find out why a VM moved, and a summary written here would
    // lose the one thing the node knew and this tier does not.
    assert!(vm.status.refused_by[0].message.contains("lvm-thin"));
}

/// Who reconciles an unbound VM.
///
/// The ordinary rule is "the replica whose session the node is on". A VM
/// whose binding fell has no node — but it usually still has an OLD one
/// that has to be told to destroy the instance, and only one replica can
/// tell it. So the answer follows the old node until that node has let
/// go, and becomes "anybody" afterwards, which is the ordinary scheduling
/// case and what this arm always meant.
#[test]
fn an_unbinding_vm_belongs_to_the_replica_that_can_reach_the_node_it_leaves() {
    let sessions =
        |names: &[&str]| -> HashSet<String> { names.iter().map(|n| (*n).to_string()).collect() };
    let mut vm = volume_vm(&[]);

    // Bound: the replica that has the node.
    assert!(may_reconcile(&vm, &sessions(&["agent-1"])));
    assert!(!may_reconcile(&vm, &sessions(&["agent-2"])));

    // Unbound, old node still on the object: the replica that has THAT.
    vm.spec.node_name = None;
    vm.status.node_name = Some("agent-1".into());
    assert!(may_reconcile(&vm, &sessions(&["agent-1"])));
    assert!(
        !may_reconcile(&vm, &sessions(&["agent-2"])),
        "another replica cannot tell agent-1 anything"
    );

    // The old node has let go: anybody may place it.
    vm.status.node_name = None;
    assert!(may_reconcile(&vm, &sessions(&["agent-2"])));
    assert!(may_reconcile(&vm, &sessions(&[])));
}

/// A volume that follows its vm to another node is dispatched THERE, and
/// never handed back to the pass that picks a node out of the pool.
///
/// The lab found this as a livelock rather than a wrong node. `no-nic` was
/// placed on agent-1b because agent-1a had no memory left; its volume `ns-b`
/// was open on agent-1a; the vm pass cleared `status.node` so the volume
/// would be re-opened, and `place_volume` — which takes the first feasible
/// node of the pool and has never heard of a vm — put it straight back on
/// agent-1a. Every five seconds, for as long as anybody watched, with the
/// guest `Pending` throughout:
///
/// ```text
/// INFO  the record follows the vm; the bytes stay where they are  from=agent-1a to=agent-1b
/// WARN  vm reconcile failed: volume ns-b is being re-opened on agent-1b
/// ```
///
/// So the assertion is about both halves at once: what the vm pass writes,
/// and what the volume pass then does with it.
#[test]
fn a_volume_following_its_vm_is_provisioned_on_the_vms_node_not_placed_again() {
    let mut v = volume_at(Some("agent-1a"), VolumePhaseKind::Ready);
    follow_vm(&mut v, "no-nic", "agent-1b");

    assert_eq!(v.status.node.as_deref(), Some("agent-1b"));
    assert_eq!(v.status.phase().kind(), VolumePhaseKind::Pending);
    assert_eq!(
        v.status.phase().message(),
        Some("following no-nic to agent-1b")
    );
    assert_eq!(
        v.status.phase().reason(),
        Some(controller_api::VolumeReason::Following),
        "and the category behind the sentence"
    );

    // The half that closes the loop: the next volume pass reaches the node
    // the vm is on. `Next::Place` here would be the livelock.
    assert_eq!(next_for(&v), Next::Provision("agent-1b"));
}

/// And the case that must keep working: a volume nobody has placed is still
/// placed by the pass whose job that is.
#[test]
fn a_volume_without_a_node_is_still_the_placers_business() {
    let v = volume_at(None, VolumePhaseKind::Pending);
    assert_eq!(next_for(&v), Next::Place);
}

// --- routers ----------------------------------------------------------------

fn gateway_node(name: &str, physnets: &[&str], connected: bool) -> Candidate {
    let mut c = gateway_elsewhere(name, physnets, connected);
    c.connected = connected;
    c
}

/// A gateway machine that is UP but whose session hangs off another replica —
/// which is what a three-replica cluster looks like from any one of them.
fn gateway_elsewhere(name: &str, physnets: &[&str], alive: bool) -> Candidate {
    Candidate {
        name: name.into(),
        connected: false,
        alive,
        schedulable: true,
        unhealthy: Vec::new(),
        free: Default::default(),
        catalogue: physnets
            .iter()
            .map(|p| format!("network/{}", common::capability::gateway_claim(p)))
            .collect(),
        kind: controller_api::CandidateKind::Node,
        labels: Default::default(),
        accepts: Vec::new(),
        hosted: Vec::new(),
        machine: None,
    }
}

fn provider(name: &str, physnet: &str) -> controller_api::ProviderNetwork {
    controller_api::ProviderNetwork::declare(
        name,
        controller_api::ProviderNetworkSpec {
            physnet: physnet.into(),
            cidr: "198.51.100.0/24".into(),
            gateway: "198.51.100.1".into(),
            allocation: vec!["198.51.100.10-198.51.100.20".into()],
            description: String::new(),
        },
    )
}

fn ready_router(name: &str) -> controller_api::Router {
    let mut r = controller_api::Router::declare(
        name,
        controller_api::RouterSpec {
            tenant: "acme".into(),
            provider_network: "ext".into(),
            vni: Some(10_007),
            internal_addr: "10.42.0.1/24".into(),
            ..Default::default()
        },
    );
    r.metadata.uid = format!("uid-{name}");
    r.status.external_addr = "198.51.100.10/24".into();
    r
}

/// The happy plan, field by field: the provider network's facts and the
/// router's own, resolved once, so that nothing behind the backend seam ever
/// has to look an object up.
#[test]
fn a_planned_router_carries_resolved_facts_and_not_object_names() {
    let field = [gateway_node("gw-1", &["ext"], true)];
    let plan = plan_router(
        &ready_router("acme-out"),
        &[provider("ext", "ext")],
        &Default::default(),
        &field,
    )
    .expect("a plan");
    assert_eq!(plan.id, "uid-acme-out", "a node keys it by uid");
    assert_eq!(plan.physnet, "ext");
    assert_eq!(plan.external_gateway, "198.51.100.1");
    assert_eq!(plan.external_addr, "198.51.100.10/24");
    assert_eq!(plan.vni, 10_007);
    assert_eq!(plan.internal_addr, "10.42.0.1/24");
    assert_eq!(plan.nodes, ["gw-1"]);
    assert_eq!(plan.active.as_deref(), Some("gw-1"));
    assert!(plan.release.is_empty());
}

/// A node that is up and fell off the priority list is TOLD; one that fell
/// off because it went away is not.
///
/// The second half is the one worth a test. A machine that is down still has
/// the netns and is very probably still forwarding; there is no session to
/// tell it anything down, and it may be the machine that comes back and takes
/// the router again. Tidying it up is the sweep's business, when it reports
/// what it holds.
#[test]
fn a_node_that_is_up_and_fell_off_the_list_is_told_to_let_go() {
    let mut cordoned = gateway_node("gw-old", &["ext"], true);
    cordoned.schedulable = false;
    let field = [gateway_node("gw-1", &["ext"], true), cordoned];
    let mut router = ready_router("acme-out");
    router.status.nodes = vec!["gw-old".into(), "gw-1".into()];
    let plan = plan_router(
        &router,
        &[provider("ext", "ext")],
        &Default::default(),
        &field,
    )
    .expect("a plan");
    assert_eq!(plan.nodes, ["gw-1"]);
    assert_eq!(plan.release, ["gw-old"]);

    // The same router, with that machine gone instead of cordoned.
    let gone = [
        gateway_node("gw-1", &["ext"], true),
        gateway_node("gw-old", &["ext"], false),
    ];
    let plan = plan_router(
        &router,
        &[provider("ext", "ext")],
        &Default::default(),
        &gone,
    )
    .expect("a plan");
    assert!(
        plan.release.is_empty(),
        "nothing to say and nobody to say it to"
    );
}

/// D-B3: the machine that was away when it fell off the list is told the
/// moment it is back, and not one pass later.
///
/// This is the hole the second half of the test above left. A node that is
/// down is not told — there is nobody to tell — and the SAME pass takes it off
/// `status.nodes`, so the next pass derives the release list out of the list it
/// has just shortened and the machine is never told at all. On manacor it came
/// back holding a whole namespace for an address another node was carrying by
/// then. `status.releasing` is the debt, written down.
#[test]
fn a_machine_that_was_away_when_it_fell_off_is_told_when_it_comes_back() {
    let mut router = ready_router("acme-out");
    router.status.nodes = vec!["gw-old".into(), "gw-1".into()];

    // Three gateway machines and a list two long, which is the lab's shape:
    // whoever comes back last is not planned back on, because the two that
    // hold the router are left where they are.
    //
    // The pass that loses it: gw-old is gone, so nobody can be told anything,
    // and the machine drops off the list this pass writes.
    let gone = [
        gateway_node("gw-1", &["ext"], true),
        gateway_node("gw-2", &["ext"], true),
        gateway_node("gw-old", &["ext"], false),
    ];
    let plan = plan_router(
        &router,
        &[provider("ext", "ext")],
        &Default::default(),
        &gone,
    )
    .expect("a plan");
    assert_eq!(plan.nodes, ["gw-1", "gw-2"]);
    assert!(plan.release.is_empty(), "nobody to say it to");
    let owed = still_owed(&router, &plan.nodes, &[]);
    assert_eq!(owed, ["gw-old"], "so it is written down instead");

    // What the pass wrote: the list without it, and the debt beside it.
    router.status.nodes = plan.nodes.clone();
    router.status.releasing = owed;

    // And the pass after it comes back. It is not planned back on — the two
    // that hold the router are left where they are — so the debt is paid.
    let back = [
        gateway_node("gw-1", &["ext"], true),
        gateway_node("gw-2", &["ext"], true),
        gateway_node("gw-old", &["ext"], true),
    ];
    let plan = plan_router(
        &router,
        &[provider("ext", "ext")],
        &Default::default(),
        &back,
    )
    .expect("a plan");
    assert!(
        plan.release.contains(&"gw-old".to_string()),
        "the machine that came back is told to let go: {:?}",
        plan.release
    );

    // The destroy lands, and the debt is gone. It is the ACK that clears it,
    // and nothing else: a destroy nobody could deliver is still owed.
    assert!(
        still_owed(&router, &plan.nodes, &["gw-old".to_string()]).is_empty(),
        "an acknowledged release is done"
    );
    assert_eq!(
        still_owed(&router, &plan.nodes, &[]),
        ["gw-old"],
        "and an undeliverable one is not"
    );

    // The other way out of the debt, without a command: the machine is planned
    // back onto this very router.
    let planned_again = ["gw-1".to_string(), "gw-old".to_string()];
    assert!(
        !still_owed(&router, &planned_again, &[]).contains(&"gw-old".to_string()),
        "a machine that holds the router again owes nothing"
    );
}

/// Four different operator problems and four different sentences. A router
/// that is Pending has to say which machine to go and look at, and "no
/// gateway node" said to somebody whose two gateway nodes are cordoned is
/// exactly the wrong answer.
#[test]
fn a_router_that_cannot_be_planned_says_which_of_the_reasons_it_is() {
    let networks = [provider("ext", "ext")];
    let plan = |router: &controller_api::Router, field: &[Candidate]| {
        plan_router(router, &networks, &Default::default(), field)
            .expect_err("no plan")
            .1
    };

    // Nobody gave an interface away for this wire.
    let said = plan(&ready_router("r"), &[gateway_node("gw-1", &["dmz"], true)]);
    assert!(said.contains("network.provider"), "{said}");

    // Everybody who did is down.
    let said = plan(&ready_router("r"), &[gateway_node("gw-1", &["ext"], false)]);
    assert!(said.contains("down, drained or unhealthy"), "{said}");
    assert!(said.contains("gw-1"), "{said}");

    // Everybody who did takes another class.
    let mut strict = gateway_node("gw-1", &["ext"], true);
    strict.accepts = vec!["gpu".into()];
    let said = plan(&ready_router("r"), &[strict]);
    assert!(said.contains("accepts the class"), "{said}");

    // Everybody who did has already refused this router.
    let mut refused = ready_router("r");
    refused.status.refused = vec!["gw-1".into()];
    let said = plan(&refused, &[gateway_node("gw-1", &["ext"], true)]);
    assert!(said.contains("has refused this router"), "{said}");
}

/// The three things a router needs before a machine can be chosen at all —
/// and each of them is a sentence about a field somebody has to fill in,
/// because this stack allocates no tenant addresses and resolves no tenant
/// at the cluster tier.
#[test]
fn a_router_missing_its_overlay_or_its_addresses_says_which_one() {
    let field = [gateway_node("gw-1", &["ext"], true)];
    let networks = [provider("ext", "ext")];
    let said = |router: &controller_api::Router| {
        plan_router(router, &networks, &Default::default(), &field)
            .expect_err("no plan")
            .1
    };

    let mut no_network = ready_router("r");
    no_network.spec.provider_network = "elsewhere".into();
    assert!(said(&no_network).contains("no provider network"), "network");

    let mut no_vni = ready_router("r");
    no_vni.spec.vni = None;
    assert!(said(&no_vni).contains("spec.vni"), "vni");

    let mut no_inside = ready_router("r");
    no_inside.spec.internal_addr.clear();
    assert!(said(&no_inside).contains("spec.internalAddr"), "inside");

    let mut no_outside = ready_router("r");
    no_outside.status.external_addr.clear();
    assert!(said(&no_outside).contains("no free address"), "outside");
}

/// The failover, as the planner sees it: the list does not move, and the
/// active one is the first entry that is still live. That is decision 7 —
/// both machines already hold the whole router, so what changes is who
/// speaks.
#[test]
fn a_failover_changes_who_speaks_and_not_what_is_built() {
    let mut router = ready_router("acme-out");
    router.status.nodes = vec!["gw-1".into(), "gw-2".into()];
    router.status.active_node = "gw-1".into();
    let networks = [provider("ext", "ext")];

    let both_up = [
        gateway_node("gw-1", &["ext"], true),
        gateway_node("gw-2", &["ext"], true),
    ];
    let plan = plan_router(&router, &networks, &Default::default(), &both_up).expect("a plan");
    assert_eq!(plan.nodes, ["gw-1", "gw-2"]);
    assert_eq!(plan.active.as_deref(), Some("gw-1"));

    let first_gone = [
        gateway_node("gw-1", &["ext"], false),
        gateway_node("gw-2", &["ext"], true),
    ];
    let plan = plan_router(&router, &networks, &Default::default(), &first_gone).expect("a plan");
    assert_eq!(
        plan.active.as_deref(),
        Some("gw-2"),
        "the standby speaks now"
    );
    assert!(
        plan.release.is_empty(),
        "and nothing is torn down: the machine that went quiet keeps its netns"
    );
}

/// The ownership rule, and why it is looser than a VM's. A router with two
/// gateway nodes has two sessions, possibly on two replicas, and the very
/// case it exists for is the one where the obvious owner just went away.
#[test]
fn a_router_belongs_to_any_replica_that_can_reach_one_of_its_machines() {
    let mut router = ready_router("acme-out");
    let nobodys = HashSet::new();
    assert!(
        may_reconcile_router(&router, &nobodys),
        "one that is on no machine belongs to everybody"
    );

    router.status.nodes = vec!["gw-1".into(), "gw-2".into()];
    assert!(!may_reconcile_router(&router, &nobodys));
    let holds_the_standby: HashSet<String> = ["gw-2".to_string()].into_iter().collect();
    assert!(
        may_reconcile_router(&router, &holds_the_standby),
        "the replica holding the standby is the one that can promote it"
    );
}

/// A create the node refused is an ANSWER and not a guess, and the object has
/// to take it whatever an earlier report left on it.
///
/// The lab case this comes from: a guest reported Provisioning, then failed
/// inside cloud-hypervisor because its initramfs was not on that machine, and
/// the node dropped the record. No report was ever coming again — the node
/// keeps none for a VM it refused — so the phase stayed Provisioning, the
/// message stayed empty, and `heal_if_failed` never saw a Failed VM to kick.
#[test]
fn a_create_the_node_refused_is_written_over_whatever_a_report_left_behind() {
    let said = || Some("ch vm.boot -> 500: cannot open initramfs file".to_string());

    // The ack half, unchanged: a guess moves only a VM nobody has reported
    // on yet.
    assert_eq!(
        vms::create_answer(None, VmPhaseKind::Pending),
        Some((VmPhaseKind::Provisioning, None))
    );
    assert_eq!(vms::create_answer(None, VmPhaseKind::Provisioning), None);
    assert_eq!(vms::create_answer(None, VmPhaseKind::Running), None);

    // The refusal half: written from Pending, and — the fix — written from
    // the phase a report had already put there.
    for reported in [
        VmPhaseKind::Pending,
        VmPhaseKind::Provisioning,
        VmPhaseKind::Running,
    ] {
        assert_eq!(
            vms::create_answer(said(), reported),
            Some((VmPhaseKind::Failed, said())),
            "a refusal from {reported:?} has to land, or nothing ever retries"
        );
    }

    // And the one phase it may not overwrite: an operator's word about a VM
    // outranks a machine's.
    assert_eq!(vms::create_answer(said(), VmPhaseKind::Quarantined), None);
}

/// A router is planned onto the machines the FLEET has, not onto the ones
/// this process happens to hold a session for.
///
/// The lab's finding, and the reason `Candidate::alive` exists. cluster-1 has
/// three replicas and two gateway nodes; the sessions landed on two different
/// replicas, and every replica then planned the router onto the one machine
/// it could see and around the other. The router came up with a priority list
/// of one — a standby that does not exist — and no failover behind it.
///
/// Sending is not the same question and is already answered: a router's
/// commands go through `Dispatch`, which forwards to the replica holding the
/// session.
#[test]
fn a_routers_list_is_the_fleets_and_not_one_replicas_reach() {
    let router = ready_router("r");
    let plan_here = |router: &controller_api::Router, field: &[Candidate]| {
        plan_router(
            router,
            &[provider("ext", "ext")],
            &Default::default(),
            field,
        )
        .expect("a plan")
    };
    // Both up, neither session here.
    let elsewhere = [
        gateway_elsewhere("gw-1", &["ext"], true),
        gateway_elsewhere("gw-2", &["ext"], true),
    ];
    let plan = plan_here(&router, &elsewhere);
    assert_eq!(plan.nodes, vec!["gw-1".to_string(), "gw-2".to_string()]);
    assert_eq!(plan.active.as_deref(), Some("gw-1"));

    // Mixed, which is the ordinary case: one session here, one over there.
    let mixed = [
        gateway_node("gw-1", &["ext"], true),
        gateway_elsewhere("gw-2", &["ext"], true),
    ];
    let plan = plan_here(&router, &mixed);
    assert_eq!(plan.nodes, vec!["gw-1".to_string(), "gw-2".to_string()]);

    // And a machine that is really DOWN is still not on it — the fix widens
    // what counts as reachable, it does not stop counting.
    let one_down = [
        gateway_elsewhere("gw-1", &["ext"], false),
        gateway_elsewhere("gw-2", &["ext"], true),
    ];
    let plan = plan_here(&router, &one_down);
    assert_eq!(plan.nodes, vec!["gw-2".to_string()]);
    assert_eq!(plan.active.as_deref(), Some("gw-2"));
}

/// Whose machines a replica may SPEAK about, which is not whose it may
/// command.
///
/// Every replica runs the placement pass for an unbound VM and each sees only
/// the machines whose sessions it holds, so the three took turns writing
/// their own view onto one object: "no connected candidate offers
/// [network/vxlan]" from the replica that holds no machine with an overlay,
/// then the real reason, then the first one again. Seen in the lab while
/// proving the class refusal, and it is what a tenant reads.
///
/// The rule: a replica that cannot reach a suitable machine asks the Node
/// objects whether ANYBODY holds one. If somebody does, it says nothing —
/// the replica with the session places it, and it is the only one that may.
/// Only when nobody anywhere can take the VM is the sentence written, and
/// then it is the same sentence everywhere because it comes out of the same
/// store.
#[test]
fn a_replica_speaks_about_a_pending_vm_only_when_nobody_anywhere_can_take_it() {
    let node = |name: &str, ready: bool, held: bool| {
        let mut n = controller_api::Node::declare(name, controller_api::NodeSpec::default());
        n.status.ready = ready;
        n.status.session_endpoint = held.then(|| "10.0.0.9:3001".to_string());
        n
    };

    // Case 1 — this replica's own reach is enough: nothing is widened,
    // because there is nothing to widen.
    let mut mine = [gateway_node("gw-1", &["ext"], true)];
    placement::widen_to_fleet(&mut mine, &[]);
    assert!(mine[0].connected, "a machine of my own stays mine");

    // Case 2 — the machine is somebody else's: this replica cannot command
    // it and must still know it is there.
    let mut theirs = [gateway_elsewhere("gw-2", &["ext"], true)];
    assert!(!theirs[0].connected, "not this replica's session");
    placement::widen_to_fleet(&mut theirs, &[node("gw-2", true, true)]);
    assert!(
        theirs[0].connected,
        "a node object naming a session endpoint is a machine somebody holds"
    );

    // Case 3 — nobody holds it, so nobody can take the VM and the sentence
    // is the fleet's answer rather than one replica's.
    let mut nobodys = [gateway_elsewhere("gw-3", &["ext"], true)];
    placement::widen_to_fleet(&mut nobodys, &[node("gw-3", true, false)]);
    assert!(!nobodys[0].connected, "ready but nobody's session");
    placement::widen_to_fleet(&mut nobodys, &[node("gw-3", false, true)]);
    assert!(
        !nobodys[0].connected,
        "an endpoint on a node that is not ready"
    );
    // And a node object that is not there at all.
    placement::widen_to_fleet(&mut nobodys, &[]);
    assert!(!nobodys[0].connected);
}

/// Who gets told to let a router go, and who has to keep it — the three cases
/// `7df0fb4` turns on.
///
/// **(a) The router is really gone.** Its object is deleted outright at this
/// tier (`handle_delete_router`; the kind carries no finalizer), so nothing
/// stores it, and the machines that still hold it say so in their next status
/// report. That is the one thing swept from the ingest path, and the delay is
/// one report — see `session::tests::a_router_the_list_does_not_name_this_
/// second_is_not_an_orphan`.
///
/// **(b) The list is short for one pass.** A heartbeat that has just expired,
/// a cordon somebody is about to take back: the object is still stored, so
/// the ingest says nothing at all and the netns stays. Same test.
///
/// **(c) A machine really dropped off the list.** That is this test: the
/// RECONCILER names it, out of a plan it has just computed — and it names it
/// whether or not this replica holds its session, because the commands go
/// through `Dispatch`. Before, the filter was `connected`, so on a
/// three-replica cluster the release was silently skipped most of the time
/// and the machine was never told: the same pass shortens `status.nodes`, and
/// the next pass builds this list out of the list it just shortened.
#[test]
fn a_machine_that_dropped_off_a_routers_list_is_told_wherever_its_session_is() {
    let mut router = ready_router("r");
    router.status.nodes = vec!["gw-1".into(), "gw-2".into()];

    // gw-2 is cordoned, so it drops off the plan — and its session hangs off
    // a sibling, which is the ordinary case on three replicas.
    let mut cordoned = gateway_elsewhere("gw-2", &["ext"], true);
    cordoned.schedulable = false;
    let field = [gateway_node("gw-1", &["ext"], true), cordoned];
    let plan = plan_router(
        &router,
        &[provider("ext", "ext")],
        &Default::default(),
        &field,
    )
    .expect("a plan");
    assert_eq!(plan.nodes, vec!["gw-1".to_string()]);
    assert_eq!(
        plan.release,
        vec!["gw-2".to_string()],
        "it is up, it dropped off, and whose replica holds it is not the question"
    );

    // A machine that is really DOWN is not told — there is nobody to tell,
    // and it may be the one that comes back and takes the router again.
    let gone = [
        gateway_node("gw-1", &["ext"], true),
        gateway_elsewhere("gw-2", &["ext"], false),
    ];
    let plan = plan_router(
        &router,
        &[provider("ext", "ext")],
        &Default::default(),
        &gone,
    )
    .expect("a plan");
    assert_eq!(plan.nodes, vec!["gw-1".to_string()]);
    assert!(
        plan.release.is_empty(),
        "nobody to tell: {:?}",
        plan.release
    );
}

/// The two facts a router's history has to carry, and why one of them is not
/// the phase.
///
/// A failover is Active on one machine and then Active on another: no phase
/// change at all, and the one moment a tenant's traffic really moved. The
/// rule is written here as the predicate `note` uses, so that the three
/// cases stay apart — the first machine a router ever gets is not news of
/// this kind, and neither is losing the last one (that IS a phase change).
#[test]
fn the_machine_a_router_forwards_on_is_news_of_its_own() {
    let moved = |was: &str, now: &str| !now.is_empty() && !was.is_empty() && was != now;

    assert!(moved("gw-1", "gw-2"), "the failover");
    assert!(!moved("gw-1", "gw-1"), "the same machine is not news");
    assert!(
        !moved("", "gw-1"),
        "the first machine it ever gets is the phase's news, not this"
    );
    assert!(
        !moved("gw-1", ""),
        "losing the last one is a phase change, and says so with its own sentence"
    );
}
