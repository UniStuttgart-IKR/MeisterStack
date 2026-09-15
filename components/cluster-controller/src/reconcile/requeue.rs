// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! The requeue decision: what a Failed VM's history says the pass may do to
//! it now. Moved out of `reconcile.rs` unchanged.

use super::*;

/// What the requeue policy wants done about this VM right now. Pure — the
/// whole retry timeline is testable as a table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Requeue {
    Not,
    /// Failed, first sighting: start the clock, send nothing yet.
    Arm,
    /// The delay for this attempt has passed: re-send the intent.
    Kick,
    /// The phase left Failed with bookkeeping still on the object.
    Reset,
}

pub fn requeue_decision(vm: &Vm, policy: &dyn RequeuePolicy, now: DateTime<Utc>) -> Requeue {
    if vm.status.phase().kind() != VmPhaseKind::Failed {
        return if vm.status.requeue_attempts > 0 || vm.status.last_requeue.is_some() {
            Requeue::Reset
        } else {
            Requeue::Not
        };
    }
    // A Failed VM that is wanted Stopped needs no healing; unbound Failed
    // (create dispatch failed before any node ack) restarts through the
    // Pending path once a kick cannot reach it anyway.
    if vm.spec.run_strategy == RunStrategy::Stopped || vm.spec.node_name.is_none() {
        return Requeue::Not;
    }
    let Some(since) = vm.status.last_requeue else {
        return Requeue::Arm;
    };
    match policy.next_delay(vm.status.requeue_attempts) {
        None => Requeue::Not,
        Some(delay) => match now.signed_duration_since(since).to_std() {
            Ok(elapsed) if elapsed >= delay => Requeue::Kick,
            _ => Requeue::Not,
        },
    }
}
