// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Intent against observation for a running VM, as one pure function both
//! tiers use.
//!
//! The cluster turns the answer into a command for the agent; the cloud only
//! asks whether there is one, because at its altitude a drifted intent means
//! "hand the spec down again and let the cluster do the arguing". Same table,
//! one place, so the two tiers can never disagree about what drift is.

use crate::resources::{RunStrategy, VmPhase};

/// A runtime transition the node has to be told about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lifecycle {
    Start,
    Stop,
    Pause,
    Resume,
}

/// The command a VM's declared runStrategy and its observed phase call for.
/// Level-triggered and without memory: no "last sent" state anywhere, so a
/// controller three seconds old decides exactly what one that has been up
/// for a week decides, and a lost command is simply re-derived next pass.
///
/// Only the three stable phases take part. Pending and Provisioning mean a
/// pass is already in flight and a command would race it; Failed is the
/// agent's own backoff doing its job; Quarantined exists precisely so that
/// nothing automatic touches the VM. All four converge to a stable phase or
/// to a human, and the drift is decided then.
pub fn lifecycle_command(strategy: RunStrategy, phase: VmPhase) -> Option<Lifecycle> {
    Some(match (strategy, phase) {
        (RunStrategy::Running, VmPhase::Stopped) => Lifecycle::Start,
        (RunStrategy::Running, VmPhase::Paused) => Lifecycle::Resume,
        (RunStrategy::Stopped, VmPhase::Running) => Lifecycle::Stop,
        (RunStrategy::Stopped, VmPhase::Paused) => Lifecycle::Stop,
        (RunStrategy::Paused, VmPhase::Running) => Lifecycle::Pause,
        // Not Start: the command names the intent, and the agent's own plan
        // goes from stopped to paused in one pass (start, then pause).
        // Sending Start would leave the node believing Running.
        (RunStrategy::Paused, VmPhase::Stopped) => Lifecycle::Pause,
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_stable_phase_that_disagrees_with_the_run_strategy_gets_a_command() {
        use Lifecycle::*;
        use RunStrategy::*;
        let cases = [
            (Running, VmPhase::Running, None),
            (Running, VmPhase::Stopped, Some(Start)),
            (Running, VmPhase::Paused, Some(Resume)),
            (Stopped, VmPhase::Stopped, None),
            (Stopped, VmPhase::Running, Some(Stop)),
            (Stopped, VmPhase::Paused, Some(Stop)),
            (Paused, VmPhase::Paused, None),
            (Paused, VmPhase::Running, Some(Pause)),
            // Pause, not Start: the agent's plan starts it and pauses it in
            // the same pass, and Start would name the wrong intent.
            (Paused, VmPhase::Stopped, Some(Pause)),
        ];
        for (strategy, phase, expected) in cases {
            assert_eq!(
                lifecycle_command(strategy, phase),
                expected,
                "{strategy:?} vs {phase:?}"
            );
        }
    }

    /// The two tables above are the whole cross product, and this is what
    /// says so: 3 x 7 cells, each decided, none of them twice and none of
    /// them missing. The tables stay as they are — they carry the reasoning
    /// for the interesting rows — and this closes the space around them.
    #[test]
    fn the_two_tables_together_are_the_whole_cross_product() {
        let mut cells = 0usize;
        let mut commanded = 0usize;
        for strategy in RunStrategy::ALL {
            for phase in VmPhase::ALL {
                cells += 1;
                if lifecycle_command(strategy, phase).is_some() {
                    commanded += 1;
                }
            }
        }
        assert_eq!(cells, 21, "the cross product is not the size it was");
        // Six drifted pairs get a command: the 3 x 3 stable block minus the
        // three diagonal ones where intent and observation already agree.
        assert_eq!(commanded, 6);
    }

    /// The invariant behind the whole level-triggered design, stated over all
    /// 21 cells rather than read off the tables: a command is only ever
    /// issued against a phase that has come to rest, and it never asks for
    /// the state the phase already reports. A command that argued with a
    /// phase in flight would race the pass that is producing it; one that
    /// restated a phase already reached would be sent forever, because the
    /// derivation is level-triggered and has no memory to stop it.
    #[test]
    fn a_command_is_never_a_race_and_never_a_no_op() {
        for strategy in RunStrategy::ALL {
            for phase in VmPhase::ALL {
                let Some(action) = lifecycle_command(strategy, phase) else {
                    continue;
                };
                assert!(
                    phase.is_stable(),
                    "{action:?} was sent at {phase:?}, still in motion"
                );
                let already_there = matches!(
                    (strategy, phase),
                    (RunStrategy::Running, VmPhase::Running)
                        | (RunStrategy::Stopped, VmPhase::Stopped)
                        | (RunStrategy::Paused, VmPhase::Paused)
                );
                assert!(
                    !already_there,
                    "{action:?} restates a phase already reached"
                );
            }
        }
    }

    /// And the converse, so the invariant above cannot be satisfied by simply
    /// never commanding anything: every stable phase that disagrees with the
    /// intent does get a command.
    #[test]
    fn every_stable_disagreement_gets_one() {
        for strategy in RunStrategy::ALL {
            for phase in [VmPhase::Running, VmPhase::Stopped, VmPhase::Paused] {
                let agrees = matches!(
                    (strategy, phase),
                    (RunStrategy::Running, VmPhase::Running)
                        | (RunStrategy::Stopped, VmPhase::Stopped)
                        | (RunStrategy::Paused, VmPhase::Paused)
                );
                assert_eq!(
                    lifecycle_command(strategy, phase).is_some(),
                    !agrees,
                    "{strategy:?} vs {phase:?}"
                );
            }
        }
    }

    #[test]
    fn a_phase_in_motion_is_never_argued_with() {
        // Pending and Provisioning: a pass is in flight. Failed: the agent's
        // backoff is retrying. Quarantined: the state that exists so nothing
        // automatic touches the VM.
        for phase in [
            VmPhase::Pending,
            VmPhase::Provisioning,
            VmPhase::Failed,
            VmPhase::Quarantined,
        ] {
            for strategy in [
                RunStrategy::Running,
                RunStrategy::Stopped,
                RunStrategy::Paused,
            ] {
                assert_eq!(
                    lifecycle_command(strategy, phase),
                    None,
                    "{strategy:?} vs {phase:?}"
                );
            }
        }
    }
}
