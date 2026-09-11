// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Every cell of `plan`'s input space, against the table it is the
//! implementation of.
//!
//! The nine hand-written cases in `reconcile.rs` say what the interesting
//! corners mean. This says what ALL of it means: 179.200 cells, each with an
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
    // ---- the two migration phases -----------------------------------------
    // Below every INTENT above and above every REPAIR below, which is the
    // whole of the authority a migration has over a record: a destroy, a stop
    // and a quarantine all still reach it, and the reconciler's own idea of
    // what to fix does not.
    Row {
        why: "the guest arrived: a receiving record becomes an ordinary provisioned vm",
        when: |c| c.record.phase == Phase::Receiving && c.obs.guest == Some(VmState::Running),
        then: |_| Action::Arrived,
    },
    Row {
        why: "the guest is not coming: a receiving record gives back what it made for it",
        when: |c| c.record.phase == Phase::Receiving && c.obs.receive_failed,
        then: |_| Action::Teardown,
    },
    Row {
        why: "a migration owns this record; the reconciler repairs nothing a migration owns",
        when: |c| matches!(c.record.phase, Phase::Receiving | Phase::Migrated),
        then: |_| Action::None,
    },
    // ---- desired = Running or Paused, healthy ------------------------------
    Row {
        why: "the resource chain has not finished; there is nothing to talk to yet",
        when: |c| c.record.phase != Phase::Provisioned,
        then: |_| Action::Provision,
    },
    Row {
        // Provision and NOT Quarantined, and the chaos run is the reason it
        // is written out here: a killed VMM was expected to quarantine and
        // recovers instead. It recovers on purpose. A dead VMM takes its
        // backends with it, so there is nothing left in place to diagnose and
        // the only two answers are "build it again" or "stay down until a
        // person looks". The quarantine is for the other shape — a backend
        // that died under a LIVE vmm — and `reconcile::backend_died_under_vmm`
        // holds the argument.
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
        Action::Arrived => "Arrived",
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

    // Every share below is twice what it was before `receive_failed` joined
    // the space — the axis is read at exactly one place, so every other guard
    // simply claims both halves of each cell it claimed before. The two that
    // are not a doubling are the two the new guard moved, and they are marked.
    let expected: BTreeMap<&'static str, usize> = BTreeMap::from([
        // An operation blocks regardless of everything else: exactly half.
        ("Blocked", 89_600),
        // Of the other half, Absent is one desired state in five (17920),
        // plus the 1024 receiving cells the failed reception gives back —
        // see the migration gate below for where that number comes from.
        ("Teardown", 18_944),
        // Quarantine sits below Absent and below the whole Stopped branch, so
        // it can only claim the three remaining intents: 89600 · 3/5 · 1/2.
        ("Quarantined", 26_880),
        // Stopped is 17920 cells. Dead vmm needing the posthumous stop:
        // 8960 · 1/7 (phase) · 1/2 (pid) = 640 — unchanged by the two
        // migration phases, because the guard names `Provisioned`. Live vmm
        // with a guest that is down or paused: 8960 · 3/5 = 5376. Live vmm,
        // guest up or unreadable, grace gone: 8960 · 2/5 · 3/4 = 2688.
        ("Stop", 8_704),
        // The same branch, grace left: 8960 · 2/5 · 1/4.
        ("SignalShutdown", 896),
        // The migration gate, and it is BELOW the four above: of the 17920
        // healthy Running/Paused cells left, 2/7 are in the two migration
        // phases = 5120, and the receiving half's Running fifth arrives.
        // 2560 · 1/5 = 512.
        ("Arrived", 512),
        // Phase unfinished 10240, no live socket 1920, untracked without a
        // pid 160 — see the Adopt derivation for the last two factors.
        ("Provision", 12_320),
        // Healthy, provisioned, live and responsive, untracked, pid present:
        // 64000 · 2/5 · 1/5 · (1/2)^5.
        ("Adopt", 160),
        // The last 320 cells are tracked with a readable guest: 256 of them,
        // 32 per (desired, guest) pair. Start owns four pairs, Resume and
        // Pause one each.
        ("Start", 128),
        ("Resume", 32),
        ("Pause", 32),
        // Stopped and already down 8320, Halted 8960, the migration gate's
        // 5120 minus the 1024 that now tear down (2560 Migrated plus the 2048
        // Receiving whose guest is not yet Running, half of which have
        // `receive_failed`), guest unreadable 64, guest already right 64.
        ("None", 20_992),
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
    assert_eq!(space::all_phases().len(), 7);
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
        * 2 // backends_alive
        * 2; // receive_failed
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
        receive_failed: false,
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
