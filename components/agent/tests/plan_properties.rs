// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! What must hold across the whole space, not cell by cell.
//!
//! The table next door says what every input decides. These say what the
//! decisions mean together — the four invariants the agent's safety rests on,
//! each checked by walking the same 64.000 cells rather than by sampling
//! them. Over a finite space exhaustion is not a weaker proof than a
//! randomised property runner; it is a stronger one, and it needs no
//! generator to be trusted.
//!
//! Two of the four are statements about a single decision (totality,
//! Absent never provisions) and fall out of the walk directly. Two are
//! statements about a sequence of them (quarantine is absorbing, an expired
//! deadline terminates), and those need a model of what the executor does to
//! the world between two passes — `model` below, kept deliberately small and
//! honest about what it assumes.

mod space;

use std::time::{Duration, SystemTime};

use agent_api::VmState;
use meister_agent::reconcile::{Action, Observed, plan};
use meister_agent::types::{Desired, Operation, Phase, VmRecord};

use space::{Cell, SPACE_SIZE, base_now, describe, walk};

// ---------------------------------------------------------------------------
// 1. Totality
// ---------------------------------------------------------------------------

/// No input panics, and none of them is undecided. `plan` has no `unwrap` on
/// a caller's value and no arithmetic on the clock today; this is what says so
/// tomorrow, when it has.
///
/// The clock is swept along with the space rather than held at one instant:
/// the epoch, the deadline's own second, and a time far enough past any
/// deadline that a naive `duration_since` would be the interesting case.
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
        | Action::Teardown => true,
    }
}

/// The clock cannot make a decision out of thin air either: a cell without a
/// deadline decides the same at every instant. Anything else would mean the
/// pass is reading time it has no business reading.
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

/// The actions that change the VM in the direction of running again. A
/// quarantined record must never see one of these from an automatic pass —
/// that is the entire point of the marker: a dead vhost-user backend cannot
/// be reconnected, and a reconciler that helpfully re-provisioned would
/// destroy the state a human is about to look at.
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

/// The other half of the same rule: quarantine is not a prison. The two
/// intents a human states to get out of it — destroy and stop — still reach
/// the VM, and they reach it with exactly the action they would have had
/// without the marker. `set_desired` clears the marker when the intent is
/// stated; `plan` must not stand in the way before that.
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

/// Absorbing in the sense that matters operationally: once marked, the
/// automatic passes cannot un-mark. `plan` never answers anything that would
/// lead the reconciler to clear `unhealthy` — the only writer of that field
/// on the clearing side is `set_desired`, and `provisioner::stop`/`resume`,
/// both of which are reached by a stated intent. So from `plan` alone, a
/// quarantined VM with a Running or Paused intent stays exactly where it is,
/// pass after pass, for every observation the world can present.
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

/// The structural half of quarantine, and the reason the marker is persisted
/// rather than recomputed: `plan` never reads `backends_alive`. Backend
/// liveness reaches the decision only through the `unhealthy` field the pass
/// writes to the store first — so an agent restart cannot silently un-
/// quarantine a VM by observing a world in which the backend is simply
/// absent rather than newly dead.
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

// ---------------------------------------------------------------------------
// 3. Desired::Absent never provisions
// ---------------------------------------------------------------------------

/// A VM on its way out is never built up again, whatever the world looks
/// like: not re-provisioned, not started, not adopted, not resumed. The only
/// thing that may still happen to it is the teardown itself — or nothing,
/// while an operation owns it.
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

/// And it gets there from anywhere in one pass. Stating Absent is the
/// strongest intent there is: it outranks the quarantine gate, every phase,
/// and every observation — only an in-flight operation may delay it, and that
/// one is cleared on the next startup pass.
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

/// What the executor promises each action does to the world, coarse enough to
/// be readable and no coarser. This is a MODEL, not the executor: it encodes
/// the post-conditions `Reconciler::execute` and `Provisioner::stop` are
/// written to guarantee, and if one of them ever stops guaranteeing them this
/// model is what has gone stale. Kept to the one branch this property needs —
/// desired = Stopped — so there is little of it to go stale.
///
/// The guest is modelled as uncooperative on purpose: it never acts on the
/// power button. That is precisely the case the deadline exists for, and a
/// guest that shuts down politely would make the property vacuous.
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

/// Every starting point with a Stopped intent, driven with the clock past any
/// deadline: the pass converges within a bounded number of steps, the vmm is
/// down when it does, and `Stop` ran exactly where there was something to
/// stop — no more (a second stop on every pass, forever) and no less (device
/// backends left running under a vmm that already exited).
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

        // What there is to clean up, decided before the first pass: a live
        // vmm, or a dead one whose Stop path never ran (`vmm_pid` is what
        // that path clears, and only a provisioned record ever had one).
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
            // Stop's own post-conditions: the pid it clears is what keeps the
            // next pass from stopping the same VM again, and the grace it
            // disarms has nothing left to wait for.
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

/// The escalation itself, which the test above skips past by starting with
/// the clock already expired: a guest that ignores the power button is asked
/// once, and once the grace runs out it is stopped whether it likes it or
/// not. The deadline is what makes "ask nicely" terminate.
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

/// The grace can only ever run out, never be pushed back: `plan` reads the
/// deadline, it never writes one, so no number of passes inside the grace can
/// extend it. (`next_stop_deadline` is the other half of that guarantee and
/// is tested in reconcile.rs.)
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
        };
        assert_eq!(plan(&record, &obs, base_now()), Action::None, "{phase:?}");
    }
}

/// The convergence guarantee the whole level-triggered design rests on,
/// stated over the space: from any cell, `plan` either says None already or
/// names an action, and the actions a Stopped intent can name are exactly the
/// two the model knows how to apply. Nothing else can appear there — which is
/// what makes the model above a complete one rather than a hopeful one.
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
