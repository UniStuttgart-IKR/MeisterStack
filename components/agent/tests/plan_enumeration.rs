// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Every cell of `plan`'s input space, against the table it is the
//! implementation of.
//!
//! The nine hand-written cases in `reconcile.rs` say what the interesting
//! corners mean. This says what ALL of it means: 64.000 cells, each with an
//! expected action, checked on every `cargo test`. What it buys is the thing
//! the interesting corners cannot buy — that reordering two `if`s, or adding
//! a variant to `Desired`, cannot quietly change an answer nobody happened to
//! write a test for.
//!
//! The oracle is deliberately not shaped like `plan`. `plan` is nested
//! control flow; the table below is a flat priority list of named guards,
//! first match wins. A table that mirrored the implementation line for line
//! would only restate it, and this file would prove nothing.

mod space;

use std::time::SystemTime;

use agent_api::VmState;
use meister_agent::reconcile::{Action, plan};
use meister_agent::types::{Desired, Phase};

use space::{Cell, SPACE_SIZE, describe, walk};

/// One row of the decision table: the guard that claims the cell, and the
/// action it claims it for.
struct Row {
    /// Why this row decides — printed verbatim when a cell disagrees, so a
    /// failure says which rule was expected to fire and not just which two
    /// enum variants differ.
    why: &'static str,
    when: fn(&Cell) -> bool,
    then: fn(&Cell) -> Action,
}

/// The agent's whole decision, in priority order. Read top to bottom: the
/// first guard that holds is the answer.
const TABLE: &[Row] = &[
    Row {
        why: "an operation owns the vm; the reconciler keeps its hands off until it is done",
        when: |c| c.record.operation.is_some(),
        then: |_| Action::Blocked,
    },
    Row {
        why: "Absent outranks everything below it, quarantine included - teardown IS the repair",
        when: |c| c.record.desired == Desired::Absent,
        then: |_| Action::Teardown,
    },
    // ---- desired = Stopped, and the vmm is already gone --------------------
    Row {
        why: "the guest powered itself off; the stop path still has to run, and vmm_pid says it has not",
        when: |c| {
            c.record.desired == Desired::Stopped
                && !c.obs.vmm_alive
                && c.record.phase == Phase::Provisioned
                && c.record.vmm_pid.is_some()
        },
        then: |_| Action::Stop,
    },
    Row {
        why: "stopped, vmm gone, and the stop path either already ran (vmm_pid cleared) or never had anything to do",
        when: |c| c.record.desired == Desired::Stopped && !c.obs.vmm_alive,
        then: |_| Action::None,
    },
    // ---- desired = Stopped, vmm still alive --------------------------------
    Row {
        why: "stopped, and a guest that is down or paused cannot act on a power button",
        when: |c| {
            c.record.desired == Desired::Stopped
                && matches!(
                    c.obs.guest,
                    Some(VmState::Defined | VmState::Stopped | VmState::Paused)
                )
        },
        then: |_| Action::Stop,
    },
    Row {
        why: "stopped, guest still up, and the grace period has time left on it",
        when: |c| {
            c.record.desired == Desired::Stopped
                && c.record.stop_deadline.is_some_and(|d| c.now < d)
        },
        then: |_| Action::SignalShutdown,
    },
    Row {
        why: "stopped, guest still up, and no grace left (expired, or never armed)",
        when: |c| c.record.desired == Desired::Stopped,
        then: |_| Action::Stop,
    },
    // ---- the quarantine gate ----------------------------------------------
    Row {
        why: "unhealthy: no automatic repair below this line - only the two intents above it get through",
        when: |c| c.record.unhealthy.is_some(),
        then: |_| Action::Quarantined,
    },
    Row {
        why: "Halted is reserved for a guest-initiated shutdown the agent does not implement yet",
        when: |c| c.record.desired == Desired::Halted,
        then: |_| Action::None,
    },
    // ---- desired = Running or Paused, healthy ------------------------------
    Row {
        why: "the resource chain has not finished; there is nothing to talk to yet",
        when: |c| c.record.phase != Phase::Provisioned,
        then: |_| Action::Provision,
    },
    Row {
        why: "provisioned, but there is no live vmm answering its socket",
        when: |c| !c.obs.vmm_alive || !c.obs.socket_responsive,
        then: |_| Action::Provision,
    },
    Row {
        why: "a live vmm this process holds no handle to, and a pid to take it over by",
        when: |c| !c.obs.tracked && c.record.vmm_pid.is_some(),
        then: |c| Action::Adopt {
            vmm_pid: c.record.vmm_pid.expect("guard checked it"),
        },
    },
    Row {
        why: "a live vmm this process holds no handle to and no pid for; start over",
        when: |c| !c.obs.tracked,
        then: |_| Action::Provision,
    },
    Row {
        why: "the vmm answers but its guest state is unreadable; wait rather than guess",
        when: |c| c.obs.guest.is_none(),
        then: |_| Action::None,
    },
    Row {
        why: "running is wanted and the guest is down",
        when: |c| {
            c.record.desired == Desired::Running
                && matches!(c.obs.guest, Some(VmState::Defined | VmState::Stopped))
        },
        then: |_| Action::Start,
    },
    Row {
        why: "running is wanted and the guest is paused",
        when: |c| c.record.desired == Desired::Running && c.obs.guest == Some(VmState::Paused),
        then: |_| Action::Resume,
    },
    Row {
        why: "paused is wanted and the guest is running",
        when: |c| c.record.desired == Desired::Paused && c.obs.guest == Some(VmState::Running),
        then: |_| Action::Pause,
    },
    Row {
        why: "paused is wanted and the guest is down: start it; the next pass pauses it",
        when: |c| {
            c.record.desired == Desired::Paused
                && matches!(c.obs.guest, Some(VmState::Defined | VmState::Stopped))
        },
        then: |_| Action::Start,
    },
    Row {
        why: "the guest is already in the state that was asked for",
        when: |_| true,
        then: |_| Action::None,
    },
];

fn expect(cell: &Cell) -> (Action, &'static str) {
    let row = TABLE
        .iter()
        .find(|r| (r.when)(cell))
        .expect("the last row's guard is `true`, so some row always claims the cell");
    ((row.then)(cell), row.why)
}

#[test]
fn every_cell_of_the_input_space_decides_what_the_table_says() {
    let mut mismatches: Vec<String> = Vec::new();
    let seen = walk(|cell| {
        let (expected, why) = expect(cell);
        let got = plan(&cell.record, &cell.obs, cell.now);
        if got != expected {
            // Collected, not asserted one by one: a change of behaviour is
            // usually a whole region of the space moving at once, and the
            // shape of that region is what says which rule moved.
            mismatches.push(format!(
                "  {}\n    expected {expected:?} - {why}\n    got      {got:?}",
                describe(cell)
            ));
        }
    });
    assert_eq!(
        seen, SPACE_SIZE,
        "the enumeration no longer walks the space it claims to"
    );
    assert!(
        mismatches.is_empty(),
        "{} of {seen} cells disagree with the decision table:\n{}",
        mismatches.len(),
        // Ten is enough to see the shape; the count above says how big it is.
        mismatches
            .iter()
            .take(10)
            .cloned()
            .collect::<Vec<_>>()
            .join("\n")
    );
}

/// A discriminant name for the census — `Adopt` carries a pid, and the census
/// counts decisions, not pids.
fn label(action: Action) -> &'static str {
    match action {
        Action::None => "None",
        Action::Blocked => "Blocked",
        Action::Quarantined => "Quarantined",
        Action::Adopt { .. } => "Adopt",
        Action::Provision => "Provision",
        Action::Start => "Start",
        Action::SignalShutdown => "SignalShutdown",
        Action::Stop => "Stop",
        Action::Pause => "Pause",
        Action::Resume => "Resume",
        Action::Teardown => "Teardown",
    }
}

/// How much of the space each action owns. Every number below is derived from
/// the guards by hand, independently of both `plan` and the table above — so
/// this test agreeing is three derivations of the same function meeting, and
/// their sum being exactly `SPACE_SIZE` is the proof that the partition has
/// no hole in it.
///
/// It is also the tripwire with the widest reach in this file: any change to
/// `plan` that the table happens to follow still has to move a number here.
#[test]
fn each_action_owns_the_share_of_the_space_the_guards_give_it() {
    use std::collections::BTreeMap;
    let mut census: BTreeMap<&'static str, usize> = BTreeMap::new();
    let seen = walk(|cell| {
        *census
            .entry(label(plan(&cell.record, &cell.obs, cell.now)))
            .or_default() += 1;
    });
    assert_eq!(seen, SPACE_SIZE);

    let expected: BTreeMap<&'static str, usize> = BTreeMap::from([
        // An operation blocks regardless of everything else: exactly half.
        ("Blocked", 32_000),
        // Of the other half, Absent is one desired state in five.
        ("Teardown", 6_400),
        // Quarantine sits below Absent and below the whole Stopped branch, so
        // it can only claim the three remaining intents: 32000 · 3/5 · 1/2.
        ("Quarantined", 9_600),
        // Stopped is 6400 cells. Dead vmm needing the posthumous stop:
        // 3200 · 1/5 (phase) · 1/2 (pid) = 320. Live vmm with a guest that is
        // down or paused: 3200 · 3/5 = 1920. Live vmm, guest up or unreadable,
        // grace gone: 3200 · 2/5 · 3/4 = 960.
        ("Stop", 3_200),
        // The same branch, grace left: 3200 · 2/5 · 1/4.
        ("SignalShutdown", 320),
        // Phase unfinished 5120, no live socket 960, untracked without a pid
        // 80 — see the Adopt derivation for the last two factors.
        ("Provision", 6_160),
        // Healthy, provisioned, live and responsive, untracked, pid present:
        // 32000 · 2/5 · 1/5 · (1/2)^5.
        ("Adopt", 80),
        // The last 160 cells are tracked with a readable guest: 128 of them,
        // 16 per (desired, guest) pair. Start owns four pairs, Resume and
        // Pause one each.
        ("Start", 64),
        ("Resume", 16),
        ("Pause", 16),
        // Stopped and already down 2880, Halted 3200, guest unreadable 32,
        // guest already right 32.
        ("None", 6_144),
    ]);
    assert_eq!(census, expected, "the shape of the decision space moved");
    assert_eq!(
        expected.values().sum::<usize>(),
        SPACE_SIZE,
        "the hand-derived shares do not partition the space"
    );
}

/// Below the Stopped branch only Running and Paused survive, so the final
/// catch-all arm of `plan`'s lifecycle match is unreachable — every
/// (desired, guest) pair that gets there is named explicitly. The half of
/// that which can be seen from outside is asserted here: the three actions
/// only that match produces belong to exactly the six pairs the table names,
/// and no other intent ever yields one. The day a sixth `Desired` slips past
/// the gates above, this set grows and says so.
#[test]
fn only_running_and_paused_ever_reach_the_lifecycle_match() {
    use std::collections::BTreeSet;
    let mut pairs: BTreeSet<String> = BTreeSet::new();
    walk(|cell| {
        let action = plan(&cell.record, &cell.obs, cell.now);
        if matches!(action, Action::Start | Action::Resume | Action::Pause) {
            pairs.insert(format!(
                "{:?}+{:?} -> {action:?}",
                cell.record.desired, cell.obs.guest
            ));
        }
    });
    assert_eq!(
        pairs.into_iter().collect::<Vec<_>>(),
        vec![
            "Paused+Some(Defined) -> Start",
            "Paused+Some(Running) -> Pause",
            "Paused+Some(Stopped) -> Start",
            "Running+Some(Defined) -> Start",
            "Running+Some(Paused) -> Resume",
            "Running+Some(Stopped) -> Start",
        ]
    );
}

/// `plan` is a function of its arguments and nothing else — no clock read
/// inside, no global. Cheap to state, and it is the assumption every other
/// test in this file rests on.
#[test]
fn the_same_cell_always_decides_the_same_way() {
    let later = space::base_now() + std::time::Duration::from_secs(3600);
    walk(|cell| {
        let once = plan(&cell.record, &cell.obs, cell.now);
        let twice = plan(&cell.record, &cell.obs, cell.now);
        assert_eq!(once, twice, "{}", describe(cell));
        // and the only way the clock gets in is through the argument
        let _: Action = plan(&cell.record, &cell.obs, later);
    });
}

/// Guards the enumerator itself: if a dimension quietly loses a value, every
/// other test in this file goes on passing over a smaller space.
#[test]
fn the_space_has_the_dimensions_it_claims() {
    assert_eq!(space::all_operations().len(), 2);
    assert_eq!(space::all_desired().len(), 5);
    assert_eq!(space::all_phases().len(), 5);
    assert_eq!(space::all_deadlines().len(), 4);
    assert_eq!(space::all_unhealthy().len(), 2);
    assert_eq!(space::all_guests().len(), 5);
    let product = space::all_operations().len()
        * space::all_desired().len()
        * space::all_phases().len()
        * space::all_deadlines().len()
        * space::all_unhealthy().len()
        * space::all_guests().len()
        * 2 // vmm_pid
        * 2 // tracked
        * 2 // vmm_alive
        * 2 // socket_responsive
        * 2; // backends_alive
    assert_eq!(product, SPACE_SIZE);
}

/// The boundary the fourth deadline cell exists for: `plan` compares with
/// `<`, so the instant a deadline names is already past, not still pending.
#[test]
fn a_deadline_is_expired_at_the_instant_it_names() {
    let now: SystemTime = space::base_now();
    let mut record = space::blank_record();
    record.desired = Desired::Stopped;
    let obs = meister_agent::reconcile::Observed {
        tracked: true,
        vmm_alive: true,
        socket_responsive: true,
        backends_alive: true,
        guest: Some(VmState::Running),
    };
    record.stop_deadline = Some(now + std::time::Duration::from_secs(1));
    assert_eq!(plan(&record, &obs, now), Action::SignalShutdown);
    record.stop_deadline = Some(now);
    assert_eq!(
        plan(&record, &obs, now),
        Action::Stop,
        "`now < deadline` is false at the deadline itself"
    );
}
