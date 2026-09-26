// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Planner invariants across the representative space in space/mod.rs.
//!
//! Most assertions inspect a single decision. Stop-convergence tests use the
//! small model below and assume its actions succeed; they do not establish
//! that real drivers terminate or clean up resources under every failure.

mod space;

use std::time::{Duration, SystemTime};

use agent_api::VmState;
use meister_agent::reconcile::{Action, Observed, ReportedPhase, plan, report_status};
use meister_agent::types::{Desired, Operation, Phase, VmRecord};

use space::{Cell, SPACE_SIZE, base_now, describe, walk};

// ---------------------------------------------------------------------------
// 1. Totality
// ---------------------------------------------------------------------------

/// Exercise every representative input at the epoch, its deadline, and a later
/// instant. Each must return a decision without panicking.
#[test]
fn every_input_decides_and_none_of_them_panics() {
    let clocks = [
        SystemTime::UNIX_EPOCH,
        base_now() - Duration::from_secs(1),
        base_now(),
        base_now() + Duration::from_secs(60 * 60 * 24 * 365 * 50),
    ];
    let mut decided = 0usize;
    let seen = walk(|cell| {
        for now in clocks {
            // A panic here fails the test; what is asserted is the other half
            // — that the answer is a real action and not a placeholder.
            let action = plan(&cell.record, &cell.obs, now);
            assert!(
                is_a_real_action(action),
                "undecided at {now:?}: {}",
                describe(cell)
            );
            decided += 1;
        }
    });
    assert_eq!(seen, SPACE_SIZE);
    assert_eq!(decided, SPACE_SIZE * clocks.len());
}

fn is_a_real_action(action: Action) -> bool {
    match action {
        Action::None
        | Action::Blocked
        | Action::Quarantined
        | Action::Adopt { .. }
        | Action::Provision
        | Action::Start
        | Action::SignalShutdown
        | Action::Stop
        | Action::Pause
        | Action::Resume
        | Action::Teardown
        | Action::Arrived => true,
    }
}

/// Without a deadline, planning is independent of the clock.
#[test]
fn without_a_deadline_the_clock_changes_nothing() {
    walk(|cell| {
        if cell.record.stop_deadline.is_some() {
            return;
        }
        let epoch = plan(&cell.record, &cell.obs, SystemTime::UNIX_EPOCH);
        let late = plan(
            &cell.record,
            &cell.obs,
            base_now() + Duration::from_secs(1 << 30),
        );
        assert_eq!(epoch, late, "{}", describe(cell));
    });
}

// ---------------------------------------------------------------------------
// 2. Quarantine is absorbing except for explicit lifecycle intents
// ---------------------------------------------------------------------------

/// Actions that repair a VM toward running. Quarantined records must never
/// receive these automatically, preserving state for diagnosis.
fn is_repair(action: Action) -> bool {
    matches!(
        action,
        Action::Provision | Action::Start | Action::Resume | Action::Adopt { .. } | Action::Pause
    )
}

#[test]
fn a_quarantined_record_is_never_repaired_automatically() {
    walk(|cell| {
        if cell.record.unhealthy.is_none() {
            return;
        }
        let action = plan(&cell.record, &cell.obs, cell.now);
        assert!(
            !is_repair(action),
            "repaired a quarantined vm: {action:?} - {}",
            describe(cell)
        );
    });
}

/// Quarantine does not alter unblocked Stop or Absent decisions.
/// set_desired also clears the marker when accepting a lifecycle request.
#[test]
fn quarantine_never_blocks_the_maintenance_intents() {
    walk(|cell| {
        if cell.record.unhealthy.is_none() || cell.record.operation.is_some() {
            return;
        }
        if !matches!(cell.record.desired, Desired::Absent | Desired::Stopped) {
            return;
        }
        let mut healthy = cell.record.clone();
        healthy.unhealthy = None;
        assert_eq!(
            plan(&cell.record, &cell.obs, cell.now),
            plan(&healthy, &cell.obs, cell.now),
            "the marker changed a maintenance decision: {}",
            describe(cell)
        );
    });
}

/// Without an operation or an explicit maintenance intent, an unhealthy
/// record remains quarantined for every observation in this test space.
#[test]
fn quarantine_is_a_fixpoint_for_every_observation() {
    walk(|cell| {
        if cell.record.unhealthy.is_none() || cell.record.operation.is_some() {
            return;
        }
        if !matches!(
            cell.record.desired,
            Desired::Running | Desired::Paused | Desired::Halted
        ) {
            return;
        }
        assert_eq!(
            plan(&cell.record, &cell.obs, cell.now),
            Action::Quarantined,
            "{}",
            describe(cell)
        );
    });
}

/// Backend liveness affects planning only through the persisted unhealthy marker.
#[test]
fn backend_liveness_reaches_plan_only_through_the_persisted_marker() {
    walk(|cell| {
        let mut flipped = cell.obs;
        flipped.backends_alive = !cell.obs.backends_alive;
        assert_eq!(
            plan(&cell.record, &cell.obs, cell.now),
            plan(&cell.record, &flipped, cell.now),
            "backends_alive changed a decision directly: {}",
            describe(cell)
        );
    });
}

/// Receive failure affects planning only within the Receiving phase.
#[test]
fn a_failed_reception_decides_nothing_outside_the_receiving_phase() {
    walk(|cell| {
        if cell.record.phase == Phase::Receiving {
            return;
        }
        let mut flipped = cell.obs;
        flipped.receive_failed = !cell.obs.receive_failed;
        assert_eq!(
            plan(&cell.record, &cell.obs, cell.now),
            plan(&cell.record, &flipped, cell.now),
            "receive_failed changed a decision outside a reception: {}",
            describe(cell)
        );
    });
}

/// Within the receive branch, failure selects teardown unless Running
/// already establishes arrival. Prefer observed arrival even with a stale
/// failure bit; higher-priority operation and maintenance guards still apply.
#[test]
fn a_failed_reception_only_ever_gives_back() {
    let mut seen = false;
    walk(|cell| {
        if cell.record.phase != Phase::Receiving || !cell.obs.receive_failed {
            return;
        }
        // Operation ownership, explicit lifecycle intent and quarantine take
        // precedence over the failed-receive branch.
        let action = plan(&cell.record, &cell.obs, cell.now);
        if cell.record.operation.is_some()
            || cell.record.unhealthy.is_some()
            || !matches!(cell.record.desired, Desired::Running | Desired::Paused)
        {
            let mut waiting = cell.obs;
            waiting.receive_failed = false;
            assert_eq!(
                action,
                plan(&cell.record, &waiting, cell.now),
                "the give-back outranked a stated intent: {}",
                describe(cell)
            );
            return;
        }
        if cell.obs.guest == Some(VmState::Running) {
            assert_eq!(
                action,
                Action::Arrived,
                "a guest that is here is here: {}",
                describe(cell)
            );
            return;
        }
        assert_eq!(
            action,
            Action::Teardown,
            "a guest that is not coming was {action:?}: {}",
            describe(cell)
        );
        assert!(!is_repair(action));
        seen = true;
    });
    assert!(seen, "no cell ever reached the give-back");
}

// ---------------------------------------------------------------------------
// 3. Desired::Absent never provisions
// ---------------------------------------------------------------------------

/// Absent intent permits only teardown or waiting for an active operation.
#[test]
fn absent_never_builds_anything_up() {
    walk(|cell| {
        if cell.record.desired != Desired::Absent {
            return;
        }
        let action = plan(&cell.record, &cell.obs, cell.now);
        assert!(
            matches!(action, Action::Teardown | Action::Blocked),
            "an absent vm was told to {action:?}: {}",
            describe(cell)
        );
    });
}

/// Absent selects teardown once no operation owns the record.
/// Unresolved migration operations can retain ownership across agent restarts.
#[test]
fn absent_reaches_teardown_from_every_state_in_one_pass() {
    walk(|cell| {
        if cell.record.desired != Desired::Absent || cell.record.operation.is_some() {
            return;
        }
        assert_eq!(
            plan(&cell.record, &cell.obs, cell.now),
            Action::Teardown,
            "{}",
            describe(cell)
        );
    });
}

/// All four operations block, which is what lets the enumerated space carry
/// only one representative in that dimension and stay honest about it.
#[test]
fn every_operation_variant_blocks() {
    let operations = [
        Operation::Snapshotting { target: "t".into() },
        Operation::Restoring { source: "s".into() },
        Operation::MigratingOut { peer: "p".into() },
        Operation::MigratingIn { peer: "p".into() },
    ];
    for op in operations {
        for desired in space::all_desired() {
            let mut record = space::blank_record();
            record.operation = Some(op.clone());
            record.desired = desired;
            let obs = Observed {
                tracked: true,
                vmm_alive: true,
                socket_responsive: true,
                backends_alive: true,
                guest: Some(VmState::Running),
                receive_failed: false,
            };
            assert_eq!(
                plan(&record, &obs, base_now()),
                Action::Blocked,
                "{op:?} did not block a {desired:?} vm"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// 4. An expired stop deadline forces the vmm down in finitely many steps
// ---------------------------------------------------------------------------

/// Model successful Stop and an ignored power-button request.
/// This assumes teardown effects succeed; executor error paths require
/// separate tests and are not proven by this model.
fn step(record: &mut VmRecord, obs: &mut Observed, action: Action) {
    match action {
        // provisioner::stop: destroy the vmm (kill it if it survives),
        // tear the device backends down, clear vmm_pid / stop_deadline /
        // unhealthy, keep volumes and taps — so the phase stays Provisioned.
        Action::Stop => {
            record.vmm_pid = None;
            record.stop_deadline = None;
            record.unhealthy = None;
            obs.vmm_alive = false;
            obs.socket_responsive = false;
            obs.tracked = false;
            obs.backends_alive = true; // nothing left to be dead
            obs.guest = None;
        }
        // hypervisor::power_button: the request lands, and this guest
        // ignores it. Nothing about the world changes.
        Action::SignalShutdown => {}
        Action::None => {}
        other => panic!("a stopped vm was told to {other:?}, which this model does not expect"),
    }
}

/// Under the successful-stop model, every unblocked Stopped state converges
/// with the VMM down and at most one Stop action.
#[test]
fn an_expired_deadline_brings_the_vmm_down_in_a_bounded_number_of_steps() {
    let mut worst = 0usize;
    walk(|cell| {
        if cell.record.desired != Desired::Stopped || cell.record.operation.is_some() {
            return;
        }
        let mut record = cell.record.clone();
        let mut obs = cell.obs;
        // Past every deadline the space contains, which is what "expired"
        // means here — including the None case, where there was no grace at
        // all and the hard stop is immediate.
        let now = base_now() + Duration::from_secs(3600);

        // Cleanup is needed for a live VMM or a provisioned record whose PID
        // remains after its VMM died.
        let had_work = cell.obs.vmm_alive
            || (cell.record.phase == Phase::Provisioned && cell.record.vmm_pid.is_some());

        let mut stops = 0usize;
        let mut steps = 0usize;
        loop {
            let action = plan(&record, &obs, now);
            if action == Action::None {
                break;
            }
            assert!(
                steps < 8,
                "no fixpoint after {steps} steps, still {action:?}: {}",
                describe(cell)
            );
            if action == Action::Stop {
                stops += 1;
            }
            step(&mut record, &mut obs, action);
            steps += 1;
        }
        worst = worst.max(steps);

        assert!(
            !obs.vmm_alive,
            "converged with a live vmm: {}",
            describe(cell)
        );
        assert_eq!(
            stops,
            usize::from(had_work),
            "stop ran {stops} time(s) for {} work: {}",
            if had_work { "real" } else { "no" },
            describe(cell)
        );
        if stops > 0 {
            // Successful modeled Stop clears the PID and deadline to prevent repeated stopping.
            assert!(record.vmm_pid.is_none(), "stop left a pid behind");
            assert_eq!(record.stop_deadline, None, "stop left the grace armed");
        }
        // And it stays converged: the fixpoint is a property of the record,
        // not of the instant it was reached at.
        assert_eq!(
            plan(&record, &obs, now + Duration::from_secs(1 << 20)),
            Action::None,
            "the fixpoint came undone with the clock: {}",
            describe(cell)
        );
    });
    // One Stop, and at most one: a live vmm goes down in a single step, a
    // posthumous cleanup likewise, and neither needs a second.
    assert_eq!(worst, 1, "the stop path grew a step");
}

/// Request guest shutdown once, then select Stop when the grace period expires.
#[test]
fn an_ignored_power_button_escalates_when_the_grace_runs_out() {
    let armed = base_now() + Duration::from_secs(30);
    let mut record = space::blank_record();
    record.desired = Desired::Stopped;
    record.stop_deadline = Some(armed);
    record.vmm_pid = Some(space::PID);
    let mut obs = Observed {
        tracked: true,
        vmm_alive: true,
        socket_responsive: true,
        backends_alive: true,
        guest: Some(VmState::Running),
        receive_failed: false,
    };

    // Inside the grace the answer never changes, however often the pass runs
    // — and it never changes into a hard stop by itself either.
    for elapsed in [0, 1, 15, 29] {
        let now = base_now() + Duration::from_secs(elapsed);
        assert_eq!(
            plan(&record, &obs, now),
            Action::SignalShutdown,
            "at +{elapsed}s"
        );
        step(&mut record, &mut obs, Action::SignalShutdown);
    }

    // The grace runs out and the next pass takes the decision away from the
    // guest.
    let now = armed + Duration::from_secs(1);
    assert_eq!(plan(&record, &obs, now), Action::Stop);
    step(&mut record, &mut obs, Action::Stop);
    assert_eq!(
        plan(&record, &obs, now),
        Action::None,
        "and stops exactly once"
    );
    assert!(!obs.vmm_alive);
}

/// Repeated planning cannot extend the stop deadline. `next_stop_deadline`
/// separately checks how lifecycle requests update it.
#[test]
fn passes_inside_the_grace_cannot_postpone_it() {
    let armed = base_now() + Duration::from_secs(30);
    let mut record = space::blank_record();
    record.desired = Desired::Stopped;
    record.stop_deadline = Some(armed);
    record.vmm_pid = Some(space::PID);
    let obs = Observed {
        tracked: true,
        vmm_alive: true,
        socket_responsive: true,
        backends_alive: true,
        guest: Some(VmState::Running),
        receive_failed: false,
    };
    for elapsed in 0..30 {
        assert_eq!(
            plan(&record, &obs, base_now() + Duration::from_secs(elapsed)),
            Action::SignalShutdown
        );
        assert_eq!(record.stop_deadline, Some(armed), "the deadline moved");
    }
    assert_eq!(plan(&record, &obs, armed), Action::Stop);
}

/// A phase that never reached Provisioned has no vmm to stop and no backends
/// to tear down; the stop path must not run for it, or a record that failed
/// halfway through provisioning would be "stopped" forever, once per pass.
#[test]
fn a_vm_that_never_came_up_is_not_stopped_posthumously() {
    for phase in space::all_phases() {
        if phase == Phase::Provisioned {
            continue;
        }
        let mut record = space::blank_record();
        record.desired = Desired::Stopped;
        record.phase = phase;
        record.vmm_pid = Some(space::PID);
        let obs = Observed {
            tracked: false,
            vmm_alive: false,
            socket_responsive: false,
            backends_alive: true,
            guest: None,
            receive_failed: false,
        };
        assert_eq!(plan(&record, &obs, base_now()), Action::None, "{phase:?}");
    }
}

/// Unblocked Stopped states select only actions handled by this model.
#[test]
fn a_stopped_intent_only_ever_names_stop_signal_or_nothing() {
    let mut seen: Vec<&'static str> = Vec::new();
    walk(|cell: &Cell| {
        if cell.record.desired != Desired::Stopped || cell.record.operation.is_some() {
            return;
        }
        let name = match plan(&cell.record, &cell.obs, cell.now) {
            Action::Stop => "Stop",
            Action::SignalShutdown => "SignalShutdown",
            Action::None => "None",
            other => panic!("{other:?} from a stopped vm: {}", describe(cell)),
        };
        if !seen.contains(&name) {
            seen.push(name);
        }
    });
    seen.sort_unstable();
    assert_eq!(
        seen,
        ["None", "SignalShutdown", "Stop"],
        "all three must actually occur"
    );
}
// ---------------------------------------------------------------------------
// 5. No phase leaves this node mute
// ---------------------------------------------------------------------------

/// Each nonsettled reported phase has a reason across the representative
/// space, failure counts and last-error values. Running, Stopped and Paused
/// omit reasons.
#[test]
fn no_reported_phase_but_a_settled_one_leaves_this_node_without_a_reason() {
    let mut settled = 0usize;
    let mut explained = 0usize;
    let mut words: Vec<&'static str> = Vec::new();
    let seen = walk(|cell: &Cell| {
        for failures in [0u32, 1, 7] {
            for last_error in [None, Some("the volume driver said no")] {
                let reported = report_status(&cell.record, &cell.obs, failures, last_error);
                match reported.phase {
                    ReportedPhase::Running | ReportedPhase::Stopped | ReportedPhase::Paused => {
                        assert!(
                            reported.reason.is_none(),
                            "{:?} needs no reason and carries {:?}: {}",
                            reported.phase,
                            reported.reason,
                            describe(cell)
                        );
                        settled += 1;
                    }
                    phase => {
                        let reason = reported.reason.unwrap_or_else(|| {
                            panic!("{phase:?} without a reason: {}", describe(cell))
                        });
                        if !words.contains(&reason.as_str()) {
                            words.push(reason.as_str());
                        }
                        explained += 1;
                    }
                }
            }
        }
    });
    assert_eq!(seen, SPACE_SIZE);
    assert!(settled > 0 && explained > 0, "{settled} / {explained}");
    // Pin the reasons reachable in this input space. Its generic quarantine
    // marker produces Unrecorded; BackendGone and ResumeIneffective are covered
    // with their specific markers in `reconcile::tests`.
    words.sort_unstable();
    assert_eq!(
        words,
        [
            "AwaitingGuest",
            "Backoff",
            "GuestLeft",
            "ReceiveFailed",
            "Unrecorded",
            "VmmGone",
            "Working",
        ]
    );
}
