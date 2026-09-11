// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! What a pass WOULD do: one pure function, and the two decisions that hang
//! off the same reasoning.
//!
//! Nothing in this file may touch the world, read a clock or return early on
//! an error, and that is not tidiness: `plan` is total over its inputs and
//! `tests/space` walks every one of the 89 600 of them. A function that
//! reached for the time or for a driver could not be walked, and the four
//! safety invariants the agent rests on would go back to being sampled.
//!
//! Moved out of `reconcile.rs` unchanged.

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
    /// A guest that was on its way has arrived: the record stops being a
    /// destination and becomes an ordinary provisioned VM.
    ///
    /// The one action in this list that changes nothing on the host. It is
    /// here rather than inside the driver because the phase is the agent's
    /// bookkeeping, and because the moment is only knowable by asking the
    /// hypervisor — which is what `observe` already does every pass.
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
            // The VMM exits on its own when the guest powers off. The record
            // then still says Provisioned and the device backends are still
            // running — the Stop path tears those down and tolerates the
            // dead VMM, so it must run exactly once even posthumously.
            //
            // Exactly once, and the phase cannot say when: stop() keeps the
            // volumes and taps and therefore leaves the phase at Provisioned,
            // so the phase alone would ask for the same stop on every pass,
            // forever. `vmm_pid` is what stop() clears, and so is what tells
            // a VM that still has to be cleaned up from one that already was.
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

    // A migration owns this record while it lasts, and the reconciler owns
    // nothing a migration owns: without this gate the first pass after
    // `PrepareMigration` would read `phase != Provisioned` as an unfinished
    // provision and rebuild the VMM the guest is moving into, and the first
    // pass after a successful send would read a VM with no VMM as one to
    // start — a second copy of a guest that is running on another machine.
    //
    // **Where it sits is the whole of its authority, and it sits low.**
    // Everything above it is somebody saying what should happen to this VM —
    // a destroy, a stop, a quarantine somebody has to look at — and a
    // migration does not outrank any of those. It only outranks the REPAIRS,
    // which are the passes' own idea of what to do, and which are exactly
    // what must not fire here.
    match record.phase {
        Phase::Receiving => {
            // The one thing this gate does rather than prevents. `get_state`
            // answers `Defined` for the whole of a reception — the driver
            // reads the event file instead of the api socket, because v53's
            // receive call blocks that socket — and turns into the guest's
            // real state the moment `migration-receive-finished` is written.
            return match obs.guest {
                Some(VmState::Running) => Action::Arrived,
                // The other end of a reception, and it had none. A transfer
                // that failed leaves this node holding a VMM, a fabric
                // connection and a set of taps for a guest that the SOURCE is
                // still running — the lab measured two cloud-hypervisors and
                // two live NVMe/TCP sessions on one 100-GiB block — and
                // nothing ever took them back: not the next pass, which read
                // "still waiting", not a restart, which cleared the marker
                // and left the phase, and not the deletion of the VM object,
                // which reached the source only.
                //
                // A receive is a create by another entrance and it ends the
                // way a create ends: what it made, it gives back. Below the
                // intents and above the repairs, in the same gate and for the
                // same reason — a destroy, a stop and a quarantine still
                // outrank it, and no repair may fire on a record whose guest
                // belongs to another machine.
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

/// The stop deadline a lifecycle transition leaves behind. Arming happens on
/// the way INTO Stopped and nowhere else: the controller derives its Stop
/// level-triggered and repeats it until the phase moves, and a repeat that
/// re-armed the grace would push the hard stop out of reach forever. Leaving
/// Stopped disarms — nothing else is waiting on that deadline.
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

/// What a desired-state snapshot means for the records this node holds: a
/// managed record the controller does not list has been deleted while the
/// session was down, and tearing it down is the whole point of sending the
/// snapshot. Everything else survives it — above all the VMs created
/// straight on the agent's unix socket, which are never in a snapshot and
/// are not the controller's to reap. Records already on their way out are
/// left to the pass that is removing them.
///
/// # The migration exception, and what it cost to find
///
/// A snapshot lists the VMs BOUND to this node, and for the whole of a live
/// migration the destination is not one of them: the binding moves at the
/// very end, after the guest has arrived. So a destination whose session
/// dropped mid-migration used to come back, be handed a snapshot that did not
/// name the guest it was about to receive, and tear down the VMM the stream
/// was pointed at.
///
/// The E2E found the sharper half of it. The destination's AGENT was killed
/// during `Preparing` and its VMM was not — a VMM is not a child of the
/// session — so the transfer ran to completion into a process nobody was
/// managing, the source's VMM exited, and the guest was on the destination
/// while the control plane, hearing nothing, called the migration failed.
/// When the agent came back the snapshot told it to destroy exactly that
/// guest.
///
/// `Receiving` therefore survives a snapshot, and it is ended by the explicit
/// `DestroyInstance` that both the migration's failure path and its success
/// path send — which this function has never stood in the way of.
///
/// **`Migrated` does NOT**, and the difference is what the record is holding.
/// A migrated record holds nothing: its guest is on another machine and its
/// VMM is gone, so a teardown of it detaches disks that outlive it and
/// destroys nothing. It was in the exception for one pass, out of symmetry,
/// and the E2E showed within a minute what symmetry cost — the destroy that
/// should have taken it away failed once, the snapshot would not touch it
/// either, and the record sat there refusing the guest's way back with "this
/// node already has a record of that vm". The reap is the second way out that
/// record needs.
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
                && !snapshot.contains(id)
        })
        .map(|(id, _)| id)
        .collect()
}
