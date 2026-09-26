// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Shared drain policy for node and cluster evacuation.
//!
//! Each tier supplies VM facts to a pure decision function, then executes the
//! chosen migration, restart or refusal through its own inventory and sessions.

use crate::{Evacuation, RunStrategy, StayReason, Vm, VmPhaseKind};

/// What a drain should do about one VM.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// Already on its way: a mark is set, or the binding has already fallen.
    /// Counted as moving and touched by nothing.
    Moving,
    /// Standing still. Let the binding go and let the scheduler decide again
    /// — the reschedule that already exists, at whichever tier is asking.
    Reschedule,
    /// Stop it, place it again, start it: one operation, and the guest sees a
    /// reboot. Only ever for `evacuation = restart`.
    Restart,
    /// Move it while it runs. No passthrough device, no persistent
    /// node-local disk, and a tier that HAS live migration.
    Live,
    /// It stays, and this says why.
    Stays(StayReason),
}

/// Facts gathered from each tier's inventory for the shared drain decision.
#[derive(Clone, Debug, Default)]
pub struct DrainFacts {
    /// Whether passthrough or paravirtual device state prevents supported live
    /// migration; that state is not carried in the guest-memory transfer.
    pub has_device: bool,
    /// Persistent node-local volume that pins the VM against relocation.
    /// Inline disks are excluded because restart evacuation recreates them.
    pub node_local_disk: Option<String>,
    /// Whether this tier can perform live relocation for the VM.
    /// False at cloud scope, where cross-cluster live migration is unsupported.
    pub live_possible: bool,
    /// Machine-compatibility refusal from `live_migration_refusal`, when
    /// that prevents live evacuation. None on other refusal paths.
    pub live_refusal: Option<String>,
}

/// Choose drain action in policy order: preserve in-flight evacuation,
/// then reject relocation of persistent node-local data. Apply the owner's
/// evacuation policy after those guards; stopped guests can move without
/// interrupting a running workload.
pub fn verdict(vm: &Vm, facts: &DrainFacts) -> Verdict {
    // Already going: a mark from an earlier pass, or a binding that has
    // already fallen and is waiting for a placement.
    if vm.status.evacuating.is_some() {
        return Verdict::Moving;
    }
    // Only a persistent disk pins. An ephemeral one is not in `facts` at all.
    if let Some(_disk) = &facts.node_local_disk {
        return Verdict::Stays(StayReason::NodeLocalDisk);
    }
    // Standing still is the easy case and does not consult `evacuation` at
    // all: nothing is running, so nothing is being interrupted, and moving a
    // stopped VM is what a client may ask for by hand anyway.
    let at_rest = vm.spec.run_strategy == RunStrategy::Stopped
        && vm.status.phase().kind() == VmPhaseKind::Stopped;
    if at_rest {
        return Verdict::Reschedule;
    }
    // A device rules out live and nothing else. What is left is the owner's
    // answer, which is the next arm.
    let could_live = facts.live_possible && !facts.has_device;
    match vm.spec.evacuation {
        // Honor explicit restart evacuation even when live migration is possible;
        // the owner has already authorized the interruption.
        Evacuation::Restart => Verdict::Restart,
        Evacuation::Never if could_live => Verdict::Live,
        // The default, and the ordinary end of a drain: the owner never said
        // this VM could be interrupted, and this tier cannot move it without
        // interrupting it.
        Evacuation::Never => Verdict::Stays(StayReason::EvacuationNever),
    }
}

/// Explain a drain refusal and the constraint an operator would need to change.
pub fn sentence(reason: StayReason, vm: &str, facts: &DrainFacts) -> String {
    match reason {
        StayReason::EvacuationNever => format!(
            "{vm} stays: evacuation is never{}",
            match (facts.has_device, facts.live_refusal.as_deref()) {
                (true, _) =>
                    ", and a vm with a device cannot move live in any case; set spec.evacuation \
                     = restart to move it by reboot"
                        .to_string(),
                // The machine, and not the owner. Said in full because it is
                // the one refusal on this list that a spec field does not fix
                // — see `DrainFacts::live_refusal`.
                (false, Some(why)) => format!(
                    ", and it could not have moved live either: {why}. Set spec.evacuation = \
                     restart to move it by reboot"
                ),
                (false, None) => "; set spec.evacuation = restart to move it by reboot".to_string(),
            }
        ),
        StayReason::NodeLocalDisk => {
            let disk = facts.node_local_disk.as_deref().unwrap_or("a local disk");
            format!(
                "{vm} stays: volume {disk} is node-local, so its bytes are on this machine and no \
                 move takes them with it"
            )
        }
        StayReason::NoTarget => {
            format!("{vm} would move and there is nowhere for it to go yet")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::object::Resource as _;
    use crate::{Evacuating, VmSpec, resources::new_vm};
    use chrono::Utc;

    fn vm(strategy: RunStrategy, phase: VmPhaseKind, evacuation: Evacuation) -> Vm {
        let mut v = new_vm(
            "web-1",
            VmSpec {
                class: Default::default(),
                cluster_selector: Default::default(),
                node_selector: Default::default(),
                anti_affinity: Vec::new(),
                node_name: Some("agent-1".into()),
                cluster_name: None,
                run_strategy: strategy,
                evacuation,
                tenant: None,
                vm: serde_json::json!({ "vcpus": 1 }),
            },
        );
        // Through the derivation, which is the only way in: the node the
        // spec names is what said it, because a resting word with no machine
        // behind it is refused (see `VmReported`).
        v.status.reported = Some(crate::VmReported::by(
            "agent-1",
            phase,
            crate::VmReason::Unrecorded,
            None,
            Utc::now(),
        ));
        v.settle(Utc::now());
        v
    }

    fn plain() -> DrainFacts {
        DrainFacts {
            has_device: false,
            node_local_disk: None,
            live_possible: false,
            live_refusal: None,
        }
    }

    /// The table from the brief, row by row, at a tier that cannot move a
    /// running VM without stopping it — which is every tier today and the
    /// cloud for ever.
    #[test]
    fn the_drain_table_says_what_the_brief_says() {
        // Stopped: moves, and nobody had to allow it.
        assert_eq!(
            verdict(
                &vm(
                    RunStrategy::Stopped,
                    VmPhaseKind::Stopped,
                    Evacuation::Never
                ),
                &plain()
            ),
            Verdict::Reschedule,
            "a stopped vm moves whatever its owner said about reboots"
        );

        // Running, restart: one operation the guest sees as a reboot.
        assert_eq!(
            verdict(
                &vm(
                    RunStrategy::Running,
                    VmPhaseKind::Running,
                    Evacuation::Restart
                ),
                &plain()
            ),
            Verdict::Restart
        );

        // Running, never: stays, and is listed.
        assert_eq!(
            verdict(
                &vm(
                    RunStrategy::Running,
                    VmPhaseKind::Running,
                    Evacuation::Never
                ),
                &plain()
            ),
            Verdict::Stays(StayReason::EvacuationNever)
        );

        // Told to stop and not stopped yet is NOT at rest: the intent and the
        // observation are two facts, and only both make a vm standing still.
        assert_eq!(
            verdict(
                &vm(
                    RunStrategy::Stopped,
                    VmPhaseKind::Running,
                    Evacuation::Never
                ),
                &plain()
            ),
            Verdict::Stays(StayReason::EvacuationNever)
        );
    }

    /// Live is the one row that depends on the tier, and a device is what
    /// rules it out however capable the tier is.
    #[test]
    fn live_is_offered_only_where_it_exists_and_never_with_a_device() {
        let running = vm(
            RunStrategy::Running,
            VmPhaseKind::Running,
            Evacuation::Never,
        );
        let live = DrainFacts {
            live_possible: true,
            ..plain()
        };
        assert_eq!(verdict(&running, &live), Verdict::Live);

        // A device: never live. With `never` it therefore stays, and the
        // sentence says both halves.
        let with_device = DrainFacts {
            has_device: true,
            ..live.clone()
        };
        assert_eq!(
            verdict(&running, &with_device),
            Verdict::Stays(StayReason::EvacuationNever)
        );
        let said = sentence(StayReason::EvacuationNever, "web-1", &with_device);
        assert!(said.contains("cannot move live"), "{said}");
        assert!(said.contains("spec.evacuation = restart"), "{said}");

        // And with `restart` it goes by reboot, which is the GPU case whole.
        let gpu = vm(
            RunStrategy::Running,
            VmPhaseKind::Running,
            Evacuation::Restart,
        );
        assert_eq!(verdict(&gpu, &with_device), Verdict::Restart);

        // Where live is not built, the same vm is treated as `never` — the
        // honest answer, because it is not going anywhere.
        assert_eq!(
            verdict(&running, &plain()),
            Verdict::Stays(StayReason::EvacuationNever)
        );
    }

    /// The disk beats everything, `restart` included: a vm booted where its
    /// data is not is worse than a vm that did not move.
    #[test]
    fn a_persistent_node_local_disk_outranks_what_the_owner_allowed() {
        let pinned = DrainFacts {
            node_local_disk: Some("data-1".into()),
            live_possible: true,
            ..plain()
        };
        for (strategy, phase, evacuation) in [
            (
                RunStrategy::Running,
                VmPhaseKind::Running,
                Evacuation::Restart,
            ),
            (
                RunStrategy::Running,
                VmPhaseKind::Running,
                Evacuation::Never,
            ),
            (
                RunStrategy::Stopped,
                VmPhaseKind::Stopped,
                Evacuation::Restart,
            ),
        ] {
            assert_eq!(
                verdict(&vm(strategy, phase, evacuation), &pinned),
                Verdict::Stays(StayReason::NodeLocalDisk),
                "{strategy:?}/{phase:?}/{evacuation:?}"
            );
        }
        let said = sentence(StayReason::NodeLocalDisk, "web-1", &pinned);
        assert!(said.contains("data-1"), "and names the disk: {said}");
        assert!(said.contains("node-local"), "{said}");
    }

    /// A vm already on its way is not re-decided. Without this the pass that
    /// runs while a stop is in flight would set the mark again from the top,
    /// and `since` would never age.
    #[test]
    fn a_vm_already_moving_is_left_alone() {
        let mut moving = vm(
            RunStrategy::Running,
            VmPhaseKind::Running,
            Evacuation::Restart,
        );
        moving.status.evacuating = Some(Evacuating {
            from: "agent-1".into(),
            step: crate::EvacuationStep::Stopping.as_str().to_string(),
            since: Utc::now(),
        });
        assert_eq!(verdict(&moving, &plain()), Verdict::Moving);
        // Even with a disk that would otherwise pin it: the mark is already
        // set and this pass is not the place to change its mind.
        assert_eq!(
            verdict(
                &moving,
                &DrainFacts {
                    node_local_disk: Some("data-1".into()),
                    ..plain()
                }
            ),
            Verdict::Moving
        );
    }

    /// Which stays FINISH a drain, and which one does not.
    #[test]
    fn only_a_structural_refusal_finishes_a_drain() {
        assert!(StayReason::EvacuationNever.settles_a_drain());
        assert!(StayReason::NodeLocalDisk.settles_a_drain());
        assert!(
            !StayReason::NoTarget.settles_a_drain(),
            "another machine coming back changes this one, so the drain is not done"
        );
        // The wire spellings round-trip, both ways, for every variant.
        for reason in StayReason::ALL {
            assert_eq!(StayReason::parse(reason.as_str()), Some(reason));
        }
    }
}
