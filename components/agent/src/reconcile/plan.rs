// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Pure reconciliation decisions over a persisted record, an observation and a supplied clock.
//!
//! Keep I/O and clock reads in the caller so the planner remains deterministic.
//! The enumeration tests cover the finite input space defined in `tests/space`.

use super::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    None,
    Blocked,
    /// VM carries an unhealthy marker: the reconciler must not repair it
    /// automatically. Manual lifecycle actions (start/stop/destroy) clear the
    /// marker.
    Quarantined,
    Adopt {
        vmm_pid: u32,
    },
    Provision,
    Start,
    SignalShutdown,
    Stop,
    Pause,
    Resume,
    Teardown,
    /// Record an observed migration arrival without changing host resources.
    Arrived,
}

pub fn plan(record: &VmRecord, obs: &Observed, now: SystemTime) -> Action {
    if record.operation.is_some() {
        return Action::Blocked;
    }

    if record.desired == Desired::Absent {
        return Action::Teardown;
    }

    if record.desired == Desired::Stopped {
        if !obs.vmm_alive {
            // Stop clears the recorded PID and device backends even if the VMM has
            // already exited. The phase stays Provisioned because disks and taps remain;
            // a cleared PID prevents repeated stops.
            return if record.phase == Phase::Provisioned && record.vmm_pid.is_some() {
                Action::Stop
            } else {
                Action::None
            };
        }
        return match obs.guest {
            Some(VmState::Defined) | Some(VmState::Stopped) => Action::Stop,
            // A paused guest never gets to see the power button, so waiting
            // out the grace period buys nothing but the wait.
            Some(VmState::Paused) => Action::Stop,
            _ => match record.stop_deadline {
                Some(deadline) if now < deadline => Action::SignalShutdown,
                _ => Action::Stop,
            },
        };
    }

    // Quarantine gate: teardown and stop above stay allowed (that IS the
    // manual maintenance path), but no automatic provision/start/resume.
    if record.unhealthy.is_some() {
        return Action::Quarantined;
    }

    if record.desired == Desired::Halted {
        return Action::None;
    }

    // Migration phases suppress automatic repair. Explicit stop and deletion
    // remain handled above; an operation marker blocks all actions at entry.
    match record.phase {
        Phase::Receiving => {
            // A running guest establishes arrival. Cloud Hypervisor reports Defined
            // while receiving and uses its event file while the API socket is blocked.
            return match obs.guest {
                Some(VmState::Running) => Action::Arrived,
                // Trust the driver's failure indicator for cleanup. The record's receive
                // deadline alone never sets this indicator.
                _ if obs.receive_failed => Action::Teardown,
                _ => Action::None,
            };
        }
        Phase::Migrated => return Action::None,
        _ => {}
    }

    if record.phase != Phase::Provisioned {
        return Action::Provision;
    }

    if !obs.vmm_alive || !obs.socket_responsive {
        return Action::Provision;
    }

    if !obs.tracked {
        return match record.vmm_pid {
            Some(pid) => Action::Adopt { vmm_pid: pid },
            None => Action::Provision,
        };
    }

    let Some(guest) = obs.guest else {
        return Action::None;
    };
    match (record.desired, guest) {
        (Desired::Running, VmState::Defined | VmState::Stopped) => Action::Start,
        (Desired::Running, VmState::Paused) => Action::Resume,
        (Desired::Running, VmState::Running) => Action::None,
        (Desired::Paused, VmState::Running) => Action::Pause,
        (Desired::Paused, VmState::Paused) => Action::None,
        (Desired::Paused, VmState::Defined | VmState::Stopped) => Action::Start,
        _ => Action::None,
    }
}

/// Arm the grace period only when entering Stopped. Repeated controller
/// commands must not extend it; leaving Stopped clears it.
pub fn next_stop_deadline(
    from: Desired,
    armed: Option<SystemTime>,
    to: Desired,
    proposed: Option<SystemTime>,
) -> Option<SystemTime> {
    match to {
        Desired::Stopped if from != Desired::Stopped => proposed,
        Desired::Stopped => armed,
        _ => None,
    }
}

/// Select controller-managed records absent from the controller snapshot.
///
/// Local records and records already being removed are excluded. Receiving
/// VMs and records with an incoming migration attempt remain protected because
/// the destination binding may not yet have moved. Migrated source records can
/// be reaped after they disappear from the snapshot.
pub fn sync_orphans<'a>(
    snapshot: &HashSet<VmId>,
    records: impl IntoIterator<Item = (VmId, &'a VmRecord)>,
) -> Vec<VmId> {
    records
        .into_iter()
        .filter(|(id, r)| {
            r.managed_by_controller
                && r.desired != Desired::Absent
                && r.phase != Phase::Receiving
                && !r.migration.as_ref().is_some_and(|m| m.incoming)
                && !snapshot.contains(id)
        })
        .map(|(id, _)| id)
        .collect()
}
