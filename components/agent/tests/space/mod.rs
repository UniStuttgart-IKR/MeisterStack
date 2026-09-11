// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! The whole input space of `reconcile::plan`, as one walkable set.
//!
//! `plan` is the agent's only decision: everything the reconciler does to a
//! VM it does because this function said so. It is pure and its inputs are
//! finite, so it can be checked not by sampling but by exhaustion — every
//! cell, every pass. This module is the enumerator both nets share; the
//! answers live next door (`plan_enumeration.rs` tables them,
//! `plan_properties.rs` states what must hold across all of them).
//!
//! The dimensions are the ones `plan` can see, plus the one it deliberately
//! cannot: `backends_alive` is in the space so that its absence from every
//! decision is a checked fact rather than an assumption (see
//! `plan_properties.rs`).

#![allow(dead_code)] // each test binary uses a different part of this module

use std::time::{Duration, SystemTime};

use agent_api::VmState;
use meister_agent::reconcile::Observed;
use meister_agent::types::{Desired, Operation, Phase, VmRecord};

/// One point of the space: what `plan` is asked about, and when.
#[derive(Clone)]
pub struct Cell {
    pub record: VmRecord,
    pub obs: Observed,
    pub now: SystemTime,
}

/// The clock the space is written against. Fixed, so a failing cell is the
/// same cell tomorrow.
pub fn base_now() -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000)
}

/// The pid a record carries when it has one — any value does, `plan` only
/// ever passes it through into `Adopt`.
pub const PID: u32 = 4242;

/// Every `Desired`, guarded against silently shrinking: the `match` turns a
/// new variant into a compile error right here, so the decision table has to
/// be told what the variant means before this net closes again. Same trick in
/// `all_phases` and `all_guests`.
pub fn all_desired() -> Vec<Desired> {
    let all = [
        Desired::Running,
        Desired::Stopped,
        Desired::Paused,
        Desired::Absent,
        Desired::Halted,
    ];
    all.iter().for_each(|d| match d {
        Desired::Running
        | Desired::Stopped
        | Desired::Paused
        | Desired::Absent
        | Desired::Halted => {}
    });
    all.to_vec()
}

pub fn all_phases() -> Vec<Phase> {
    let all = [
        Phase::Provisioning,
        Phase::VolumesDone,
        Phase::NetworkDone,
        Phase::DevicesDone,
        Phase::Provisioned,
        Phase::Receiving,
        Phase::Migrated,
    ];
    all.iter().for_each(|p| match p {
        Phase::Provisioning
        | Phase::VolumesDone
        | Phase::NetworkDone
        | Phase::DevicesDone
        | Phase::Provisioned
        | Phase::Receiving
        | Phase::Migrated => {}
    });
    all.to_vec()
}

/// Guest state as the hypervisor reports it, plus the `None` that means the
/// state could not be read at all.
pub fn all_guests() -> Vec<Option<VmState>> {
    let all = [
        None,
        Some(VmState::Defined),
        Some(VmState::Running),
        Some(VmState::Paused),
        Some(VmState::Stopped),
    ];
    all.iter().for_each(|g| match g {
        None
        | Some(VmState::Defined)
        | Some(VmState::Running)
        | Some(VmState::Paused)
        | Some(VmState::Stopped) => {}
    });
    all.to_vec()
}

/// The four deadlines that matter, `now` itself among them: `plan` compares
/// with `<`, so the instant the deadline names is already expired, and that
/// boundary is worth a cell of its own rather than an argument.
pub fn all_deadlines() -> Vec<Option<SystemTime>> {
    vec![
        None,
        Some(base_now() - Duration::from_secs(1)),
        Some(base_now()),
        Some(base_now() + Duration::from_secs(30)),
    ]
}

/// Present or absent. Which operation it is does not reach `plan` — that all
/// four variants block is checked separately, in `plan_properties.rs`, rather
/// than paid for five times over in every other dimension.
pub fn all_operations() -> Vec<Option<Operation>> {
    vec![None, Some(Operation::Snapshotting { target: "t".into() })]
}

/// Present or absent, likewise: the reason string is carried to the operator,
/// never read for a decision.
pub fn all_unhealthy() -> Vec<Option<String>> {
    vec![None, Some("backend died".to_string())]
}

/// 2 · 5 · 7 · 4 · 2 · 2 · 2 · 2 · 2 · 2 · 5 · 2 — operation, desired, phase,
/// stop_deadline, unhealthy, vmm_pid, tracked, vmm_alive, socket_responsive,
/// backends_alive, guest, receive_failed. Asserted by the walk, so the space
/// cannot shrink behind a passing test.
///
/// The phase axis grew from five to seven with live migration, and the two
/// new values are deliberately IN the space rather than beside it: a phase
/// that `plan` returns early for is exactly the kind of thing that has to be
/// enumerated, because the claim being made about it is that nothing below
/// the early return can reach it.
///
/// `receive_failed` doubled it again, and it is carried on every cell rather
/// than only on the receiving ones for the reason `backends_alive` is: the
/// claim is that a reception that will not finish decides EXACTLY one thing
/// and decides it nowhere else, and a dimension enumerated only where it is
/// expected to matter cannot say that.
pub const SPACE_SIZE: usize = 179_200;

/// A record with nothing interesting in it; the walk dresses it up per cell,
/// and the hand-written cases build on it too.
pub fn blank_record() -> VmRecord {
    VmRecord::blank()
}

/// Visit every cell exactly once. Returns how many there were, which the
/// callers assert against `SPACE_SIZE`.
pub fn walk(mut visit: impl FnMut(&Cell)) -> usize {
    let mut seen = 0usize;
    let now = base_now();
    for operation in all_operations() {
        for desired in all_desired() {
            for phase in all_phases() {
                for stop_deadline in all_deadlines() {
                    for unhealthy in all_unhealthy() {
                        for vmm_pid in [None, Some(PID)] {
                            let mut record = blank_record();
                            record.operation = operation.clone();
                            record.desired = desired;
                            record.phase = phase;
                            record.stop_deadline = stop_deadline;
                            record.unhealthy = unhealthy.clone();
                            record.vmm_pid = vmm_pid;
                            for tracked in [false, true] {
                                for vmm_alive in [false, true] {
                                    for socket_responsive in [false, true] {
                                        for backends_alive in [false, true] {
                                            for guest in all_guests() {
                                                for receive_failed in [false, true] {
                                                    let cell = Cell {
                                                        record: record.clone(),
                                                        obs: Observed {
                                                            tracked,
                                                            vmm_alive,
                                                            socket_responsive,
                                                            backends_alive,
                                                            guest,
                                                            receive_failed,
                                                        },
                                                        now,
                                                    };
                                                    visit(&cell);
                                                    seen += 1;
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    seen
}

/// One cell in one line, so a failure names the input instead of describing
/// it. Deadlines are printed relative to `now` — "+30s" is what the reader
/// needs, "1970-01-12T13:46:40Z" is not.
pub fn describe(cell: &Cell) -> String {
    let deadline = match cell.record.stop_deadline {
        None => "none".to_string(),
        Some(d) => match d.duration_since(cell.now) {
            Ok(dt) if dt.is_zero() => "now".to_string(),
            Ok(dt) => format!("+{}s", dt.as_secs()),
            Err(e) => format!("-{}s", e.duration().as_secs()),
        },
    };
    format!(
        "operation={} desired={:?} phase={:?} deadline={deadline} unhealthy={} vmm_pid={:?} \
         | tracked={} vmm_alive={} socket={} backends_alive={} guest={:?} receive_failed={}",
        cell.record.operation.is_some(),
        cell.record.desired,
        cell.record.phase,
        cell.record.unhealthy.is_some(),
        cell.record.vmm_pid,
        cell.obs.tracked,
        cell.obs.vmm_alive,
        cell.obs.socket_responsive,
        cell.obs.backends_alive,
        cell.obs.guest,
        cell.obs.receive_failed,
    )
}
