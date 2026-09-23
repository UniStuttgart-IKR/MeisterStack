// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Seventy hosts, and the properties that have to hold for all of them.
//!
//! The unit tests in `plan.rs` pin each rule on the smallest fleet that can
//! show it. These pin what has to be true of EVERY plan over a fleet big
//! enough to have shapes nobody wrote down: four hardware classes, three
//! raft groups, three machines that carry two tiers at once, sixty-one
//! agents split over two controller groups.
//!
//! Each property is one a bug would break quietly. "Two members of a raft
//! group in one wave" does not fail a test somewhere else; it takes an etcd
//! cluster down in a lab at four in the afternoon.

mod support;

use std::collections::{BTreeMap, BTreeSet};
use std::time::Instant;

use meister_deploy::manifest::GroupKind;
use meister_deploy::observation::Observations;
use meister_deploy::plan::{
    ActionKind, DeploymentPlan, HostVerdict, PlanKind, PlanPolicy, WorkloadControl, plan, select,
};
use meister_deploy::release::ReleaseManifest;

use support::{CLASSES, MULTI_ROLE, at, fleet70, observed, release_of, with_new_systems};

const TAKEN: &str = "2026-09-21T11:59:00Z";
const NOW: &str = "2026-09-21T12:00:00Z";

fn policy() -> PlanPolicy {
    PlanPolicy::new(PlanKind::Upgrade).with_workload_control(Some(WorkloadControl {
        cli_config: "cli.toml".to_string(),
        cli_profile: Some("cloud-mtls".to_string()),
    }))
}

/// The whole fleet running one release, and a new release for `changed`.
fn upgrade(changed: &[String]) -> (ReleaseManifest, Observations) {
    let base = fleet70();
    let running = release_of(base.clone());
    let observation = observed(&running, at(TAKEN));
    (with_new_systems(base, changed, false), observation)
}

fn everything() -> Vec<String> {
    fleet70().hosts.keys().cloned().collect()
}

fn planned(release: &ReleaseManifest, expr: &str, observation: &Observations) -> DeploymentPlan {
    plan(release, expr, observation, None, &policy(), at(NOW)).expect("seventy hosts plan")
}

#[test]
fn the_generated_fleet_is_the_shape_these_tests_assume() {
    let fleet = fleet70();
    assert_eq!(fleet.hosts.len(), 70);
    assert_eq!(fleet.groups.len(), 3 + CLASSES.len());
    let raft: Vec<&String> = fleet
        .groups
        .iter()
        .filter(|(_, g)| g.kind == GroupKind::Raft)
        .map(|(id, _)| id)
        .collect();
    assert_eq!(raft, ["cloud", "cluster-1", "cluster-2"]);
    for id in MULTI_ROLE {
        assert_eq!(fleet.hosts[id].roles, ["cluster", "agent"]);
    }
    assert_eq!(select(&fleet, "role=agent").unwrap().len(), 61 + 3);
    assert_eq!(select(&fleet, "role=cloud").unwrap().len(), 3);
}

#[test]
fn every_selected_host_is_changed_once_or_unchanged_or_blocked() {
    let (release, observation) = upgrade(&everything());
    let plan = planned(&release, "all", &observation);
    assert_eq!(plan.selection.targets.len(), 70);

    for id in &plan.selection.targets {
        let host = &plan.hosts[id];
        let activations = plan
            .actions_for(id)
            .iter()
            .filter(|a| a.kind == ActionKind::Activate && !a.is_blocked())
            .count();
        match host.verdict {
            HostVerdict::Change => assert_eq!(
                activations, 1,
                "{id} is being taken forward and has {activations} activations"
            ),
            HostVerdict::Unchanged => assert_eq!(activations, 0, "{id} needs nothing"),
            other => assert_eq!(activations, 0, "{id} is {other} and must not be activated"),
        }
    }
    // The fleet is healthy and every system changed, so every host moves.
    assert!(
        plan.hosts
            .values()
            .all(|h| h.verdict == HostVerdict::Change),
        "{:?}",
        plan.hosts
            .iter()
            .filter(|(_, h)| h.verdict != HostVerdict::Change)
            .map(|(id, h)| (id.clone(), h.reasons.clone()))
            .collect::<Vec<_>>()
    );
}

#[test]
fn no_host_is_in_two_waves() {
    let (release, observation) = upgrade(&everything());
    let plan = planned(&release, "all", &observation);
    for id in &plan.selection.targets {
        let waves: BTreeSet<u32> = plan.actions_for(id).iter().map(|a| a.wave).collect();
        assert_eq!(waves.len(), 1, "{id} has steps in the waves {waves:?}");
        assert_eq!(
            waves.into_iter().next().unwrap(),
            plan.hosts[id].wave,
            "{id}: its steps and its summary disagree about the wave"
        );
    }
}

#[test]
fn two_members_of_a_raft_group_are_never_in_one_wave() {
    let (release, observation) = upgrade(&everything());
    let plan = planned(&release, "all", &observation);
    let fleet = &release.resolved_fleet;
    for (id, group) in &fleet.groups {
        if group.kind != GroupKind::Raft {
            continue;
        }
        let mut seen: BTreeMap<u32, Vec<&String>> = BTreeMap::new();
        for member in &group.members {
            if plan.hosts[member].verdict != HostVerdict::Change {
                continue;
            }
            seen.entry(plan.hosts[member].wave)
                .or_default()
                .push(member);
        }
        for (wave, members) in seen {
            assert_eq!(
                members.len(),
                1,
                "group {id} has {members:?} in wave {wave}: that is a lost quorum"
            );
        }
    }
}

#[test]
fn a_compute_group_never_loses_more_at_once_than_it_allows() {
    let (release, observation) = upgrade(&everything());
    let plan = planned(&release, "all", &observation);
    let fleet = &release.resolved_fleet;
    for (id, group) in &fleet.groups {
        if group.kind == GroupKind::Raft {
            continue;
        }
        let allowed = plan.groups[id].allowed_unavailable as usize;
        assert!(allowed > 0, "group {id} allows nothing and is not blocked");
        let mut per_wave: BTreeMap<u32, usize> = BTreeMap::new();
        for member in &group.members {
            if plan.hosts[member].verdict != HostVerdict::Change {
                continue;
            }
            *per_wave.entry(plan.hosts[member].wave).or_default() += 1;
        }
        for (wave, count) in per_wave {
            assert!(
                count <= allowed,
                "group {id} puts {count} hosts in wave {wave} and allows {allowed}"
            );
        }
    }
}

#[test]
fn each_class_has_one_canary_and_it_goes_alone_and_first() {
    let (release, observation) = upgrade(&everything());
    let plan = planned(&release, "all", &observation);

    let mut canaries: BTreeMap<&str, &String> = BTreeMap::new();
    for (id, host) in &plan.hosts {
        if host.canary {
            assert!(
                canaries.insert(&host.class, id).is_none(),
                "the class {} has two canaries",
                host.class
            );
        }
    }
    // Four agent classes and the controllers.
    assert_eq!(canaries.len(), CLASSES.len() + 1, "{canaries:?}");

    for (class, canary) in &canaries {
        let wave = plan.hosts[*canary].wave;
        // The canary of a class that spans two tiers is the first one the
        // ORDER allows, not the first by id: the tier rule wins.
        for (id, host) in &plan.hosts {
            if &host.class != class || id == *canary || host.verdict != HostVerdict::Change {
                continue;
            }
            assert!(
                host.wave > wave,
                "{id} is in wave {} and the canary {canary} of its class is in {wave}",
                host.wave
            );
        }
    }
}

#[test]
fn a_node_is_taken_forward_before_the_node_that_gives_it_orders() {
    let (release, observation) = upgrade(&everything());
    let plan = planned(&release, "all", &observation);
    let fleet = &release.resolved_fleet;

    for (id, host) in &fleet.hosts {
        let Some(group) = &host.controller_group else {
            continue;
        };
        if !host.roles.iter().any(|r| r == "agent") {
            continue;
        }
        for controller in &fleet.groups[group].members {
            if controller == id || !fleet.hosts[controller].roles.iter().any(|r| r == "cluster") {
                continue;
            }
            assert!(
                plan.hosts[controller].wave > plan.hosts[id].wave,
                "{controller} (wave {}) gives orders to {id} (wave {})",
                plan.hosts[controller].wave,
                plan.hosts[id].wave
            );
        }
    }
    // And the cloud tier comes after every cluster.
    let last_cluster = fleet
        .hosts
        .iter()
        .filter(|(_, h)| h.roles.iter().any(|r| r == "cluster"))
        .map(|(id, _)| plan.hosts[id].wave)
        .max()
        .expect("there are clusters");
    for (id, host) in &fleet.hosts {
        if host.roles.iter().any(|r| r == "cloud") {
            assert!(
                plan.hosts[id].wave > last_cluster,
                "the cloud host {id} is in wave {} and a cluster is in {last_cluster}",
                plan.hosts[id].wave
            );
        }
    }
}

#[test]
fn a_multi_role_host_is_one_interruption_at_its_highest_tier() {
    let (release, observation) = upgrade(&everything());
    let plan = planned(&release, "all", &observation);
    for id in MULTI_ROLE {
        let steps = plan.actions_for(id);
        assert_eq!(
            steps
                .iter()
                .filter(|a| a.kind == ActionKind::Activate)
                .count(),
            1,
            "{id} is one machine"
        );
        // It carries the agent role, so its guests are got out of the way.
        assert!(
            steps.iter().any(|a| a.kind == ActionKind::Drain),
            "{id} carries guests"
        );
        // And it rolls with the clusters, not with the agents.
        assert!(
            plan.hosts[id].wave > plan.hosts["agent-01"].wave,
            "{id} is a cluster and must not go before the agents"
        );
    }
}

#[test]
fn changing_one_profile_changes_exactly_the_hosts_of_that_profile() {
    // V11.
    let fleet = fleet70();
    let gpu: Vec<String> = select(&fleet, "profile=compute-gpu").expect("the profile is there");
    // Sixty-one agents over four classes: the first class gets sixteen and
    // the other three get fifteen.
    assert_eq!(gpu.len(), 15);

    let running = release_of(fleet.clone());
    let observation = observed(&running, at(TAKEN));
    let release = with_new_systems(fleet, &gpu, false);
    let plan = planned(&release, "all", &observation);

    let changed: Vec<&String> = plan
        .hosts
        .iter()
        .filter(|(_, h)| h.verdict == HostVerdict::Change)
        .map(|(id, _)| id)
        .collect();
    assert_eq!(
        changed,
        gpu.iter().collect::<Vec<_>>(),
        "a profile changed and somebody else moved"
    );
    for id in &plan.selection.targets {
        if !gpu.contains(id) {
            assert_eq!(plan.hosts[id].verdict, HostVerdict::Unchanged, "{id}");
            assert_eq!(plan.actions_for(id).len(), 2, "{id} gets two steps");
        }
    }
}

#[test]
fn the_same_inputs_are_the_same_plan_over_seventy_hosts() {
    let (release, observation) = upgrade(&everything());
    let first = planned(&release, "all", &observation);
    let second = plan(
        &release,
        "all",
        &observation,
        None,
        &policy(),
        at("2026-09-23T06:00:00Z"),
    )
    .expect("it plans again");
    assert_eq!(first.plan_id, second.plan_id);
    assert_eq!(
        first
            .actions
            .iter()
            .map(|a| (a.seq, a.host.clone(), a.kind))
            .collect::<Vec<_>>(),
        second
            .actions
            .iter()
            .map(|a| (a.seq, a.host.clone(), a.kind))
            .collect::<Vec<_>>()
    );
}

#[test]
fn a_selection_of_part_of_the_fleet_plans_only_that_part() {
    let (release, observation) = upgrade(&everything());
    let plan = planned(&release, "group=cluster-1,!host=cluster-1-c", &observation);
    assert_eq!(plan.selection.targets, ["cluster-1-a", "cluster-1-b"]);
    for action in &plan.actions {
        assert!(plan.selection.targets.contains(&action.host));
    }
    // The group is still judged whole: two of three may move, one at a time.
    assert_eq!(plan.groups["cluster-1"].size, 3);
    assert_eq!(plan.groups["cluster-1"].allowed_unavailable, 1);
    assert_ne!(
        plan.hosts["cluster-1-a"].wave,
        plan.hosts["cluster-1-b"].wave
    );
}

#[test]
fn a_degraded_raft_group_blocks_only_its_own_members() {
    let (release, mut observation) = upgrade(&everything());
    let member = observation.hosts.get_mut("cluster-2-a").expect("a member");
    member.etcd.as_mut().expect("a raft member").healthy = false;
    for host in observation.hosts.values_mut() {
        if let Some(etcd) = host.etcd.as_mut() {
            for m in &mut etcd.members {
                if m.name == "cluster-2-a" {
                    m.healthy = false;
                }
            }
        }
    }
    let plan = planned(&release, "all", &observation);
    assert!(plan.groups["cluster-2"].blocked.is_some());
    assert!(plan.groups["cluster-1"].blocked.is_none());
    // The two HEALTHY members are what the quorum rule protects. The member
    // that is already down does not go down again by being worked on — it
    // is the one host a degraded group most needs a plan for (lab finding
    // W8, 2026-09-23: a bootstrap of three could be started and never
    // finished, because the third member was refused once the first two
    // formed a quorum).
    for id in ["cluster-2-b", "cluster-2-c"] {
        assert_eq!(plan.hosts[id].verdict, HostVerdict::Blocked, "{id}");
    }
    assert_eq!(
        plan.hosts["cluster-2-a"].verdict,
        HostVerdict::Change,
        "the member that is down is the one the plan is for"
    );
    for id in ["cluster-1-a", "agent-01", "cloud-a"] {
        assert_eq!(plan.hosts[id].verdict, HostVerdict::Change, "{id}");
    }
    assert!(plan.is_blocked());
}

#[test]
fn seventy_hosts_are_planned_in_well_under_a_second() {
    // The number in the report comes from this test's own output.
    let (release, observation) = upgrade(&everything());
    let started = Instant::now();
    let plan = planned(&release, "all", &observation);
    let elapsed = started.elapsed();
    println!(
        "plan over {} hosts: {} action(s), {} wave(s), {:?}",
        plan.selection.targets.len(),
        plan.actions.len(),
        plan.last_wave() + 1,
        elapsed
    );
    assert!(
        elapsed.as_secs() < 5,
        "seventy hosts took {elapsed:?}; the planner does no i/o and should not be near this"
    );
}
