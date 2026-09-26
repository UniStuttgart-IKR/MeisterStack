// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Finite planner inputs shared by decision-table and property tests.
//!
//! The walk covers representative values for every current decision dimension,
//! including inconsistent observations. It does not model all record contents,
//! I/O failures or executor behavior. Backend liveness is included to verify
//! that it affects planning only through the persisted unhealthy marker.

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

/// Fixed planning clock for reproducible failure cells.
pub fn base_now() -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000)
}

/// Representative recorded PID, passed through into Adopt without interpretation.
pub const PID: u32 = 4242;

/// Enumerate Desired variants. The exhaustive match forces review when a new
/// variant is added; the length assertions also guard the current list.
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

/// Cover absent, earlier, exact and later deadlines. Equality is expired because
/// the planner compares with <.
pub fn all_deadlines() -> Vec<Option<SystemTime>> {
    vec![
        None,
        Some(base_now() - Duration::from_secs(1)),
        Some(base_now()),
        Some(base_now() + Duration::from_secs(30)),
    ]
}

/// Represent operation presence with one variant; separate property tests
/// check that every variant blocks planning.
pub fn all_operations() -> Vec<Option<Operation>> {
    vec![None, Some(Operation::Snapshotting { target: "t".into() })]
}

/// Only unhealthy-marker presence affects planning, not its message.
pub fn all_unhealthy() -> Vec<Option<String>> {
    vec![None, Some("backend died".to_string())]
}

/// Number of combinations across operation presence, desired state, phase,
/// stop deadline, unhealthy marker, PID presence and observation dimensions.
/// The tests check the product so an accidental reduction cannot pass silently.
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

/// Render a failing cell on one line with deadlines relative to the planning time.
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
