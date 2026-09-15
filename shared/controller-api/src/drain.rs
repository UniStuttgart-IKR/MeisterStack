// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! What a drain does to one VM, as a table.
//!
//! Catalogue 16's second verb. `node drain` at the cluster and
//! `cluster drain` at the cloud ask the same question about the same object —
//! "may this VM be got off here, and how" — of two different inventories, so
//! the rule lives once and each tier gathers its own facts for it.
//!
//! It is a pure function over a small struct on purpose. The table is the
//! part with judgement in it and the part a person will argue with; a rule
//! that could only be exercised through an etcd and two agents is a rule
//! nobody checks.

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

/// The facts about one VM that the table reads and neither tier's object
/// carries directly.
///
/// Gathered by the caller because gathering them is where the tiers differ: a
/// cluster asks its own pools and its own nodes, the cloud asks its clusters'
/// mirrored answers. What is decided from them is the same either way.
#[derive(Clone, Debug, Default)]
pub struct DrainFacts {
    /// The VM's spec names at least one passthrough or paravirtual device.
    ///
    /// A device is the one fact that rules live migration out whatever else
    /// is true: the state of a GPU is not in the guest's memory, and NVIDIA's
    /// own vGPU live migration is deliberately out of scope here.
    pub has_device: bool,
    /// A persistent disk whose bytes are on this very machine, by name.
    ///
    /// `Some` pins the VM outright — no reschedule, no restart, no live.
    /// EPHEMERAL disks are absent from this by construction: an inline entry
    /// has no `Volume` object, it was made with the VM on that machine, and
    /// it is made fresh at the destination. Instance-store semantics, and the
    /// whole reason the ephemeral axis was worth building.
    pub node_local_disk: Option<String>,
    /// Whether this tier can move a running VM at all.
    ///
    /// False until live migration is built, and false FOREVER at the cloud:
    /// there is no live migration across clusters. When it is false a VM that
    /// would have moved live is treated exactly as `evacuation = never` —
    /// which is the honest answer, because it is not going anywhere.
    pub live_possible: bool,
    /// Why no machine here could take this guest's saved state, when that is
    /// the reason `live_possible` is false.
    ///
    /// One of [`crate::live_migration_refusal`]'s sentences, carried so that
    /// the drain's own line can say it. Without it a node in a heterogeneous
    /// fleet reports the ordinary `evacuation is never`, and an operator reads
    /// "the owner said no" about a machine that is in fact the wrong shape —
    /// which is the difference between changing a spec field and buying a
    /// matching host.
    ///
    /// `None` on every other path, including the ordinary one where live
    /// migration simply was not asked for.
    pub live_refusal: Option<String>,
}

/// The table from the brief, line for line.
///
/// The order of the arms is the order of the rules, and two of them come
/// first for a reason:
///
///   * a VM already on its way is not re-decided, or a pass that ran while a
///     stop was in flight would set the mark again from the top;
///   * a persistent node-local disk beats everything below it, `restart`
///     included. Moving that VM means booting it where its data is not, and
///     an owner who wrote `evacuation: restart` was answering a question
///     about reboots, not offering up their disk.
///
/// After that it is the owner's word: `never` stays, `restart` moves the way
/// the owner allowed, and a stopped VM moves without anybody having to allow
/// anything — nothing is running to be disturbed, which is what makes the
/// third verb the one that covers 95 % of the cases.
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
    let at_rest =
        vm.spec.run_strategy == RunStrategy::Stopped && vm.status.phase == VmPhaseKind::Stopped;
    if at_rest {
        return Verdict::Reschedule;
    }
    // A device rules out live and nothing else. What is left is the owner's
    // answer, which is the next arm.
    let could_live = facts.live_possible && !facts.has_device;
    match vm.spec.evacuation {
        // `restart` first, even where live would work: it is what the owner
        // asked for, it is cheaper to reason about, and a live migration that
        // does not converge would leave a VM the owner had already agreed to
        // reboot sitting on a machine somebody wants to switch off.
        Evacuation::Restart => Verdict::Restart,
        Evacuation::Never if could_live => Verdict::Live,
        // The default, and the ordinary end of a drain: the owner never said
        // this VM could be interrupted, and this tier cannot move it without
        // interrupting it.
        Evacuation::Never => Verdict::Stays(StayReason::EvacuationNever),
    }
}

/// The sentence beside the category, for the operator reading `node get`.
///
/// Says what would have to change, because that is the only useful thing a
/// refusal can say: a category tells a program what happened and a person
/// needs to know what to do about it.
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
        v.status.phase = phase;
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
