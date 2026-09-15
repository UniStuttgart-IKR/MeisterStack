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

use chrono::{DateTime, Utc};

use crate::resources::{RunStrategy, VmPhaseKind};

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
pub fn lifecycle_command(strategy: RunStrategy, phase: VmPhaseKind) -> Option<Lifecycle> {
    Some(match (strategy, phase) {
        (RunStrategy::Running, VmPhaseKind::Stopped) => Lifecycle::Start,
        (RunStrategy::Running, VmPhaseKind::Paused) => Lifecycle::Resume,
        (RunStrategy::Stopped, VmPhaseKind::Running) => Lifecycle::Stop,
        (RunStrategy::Stopped, VmPhaseKind::Paused) => Lifecycle::Stop,
        (RunStrategy::Paused, VmPhaseKind::Running) => Lifecycle::Pause,
        // Not Start: the command names the intent, and the agent's own plan
        // goes from stopped to paused in one pass (start, then pause).
        // Sending Start would leave the node believing Running.
        (RunStrategy::Paused, VmPhaseKind::Stopped) => Lifecycle::Pause,
        _ => return None,
    })
}

/// May this VM let its binding go — the question both tiers' `reschedule`
/// asks, as one function so that they cannot answer it differently.
///
/// The intent half has never been in doubt: nobody moves a VM somebody still
/// wants running, so `runStrategy` must say `Stopped`. What was wrong was the
/// observation half, which demanded `phase == Stopped` and nothing else.
///
/// D12, measured: a VM on a node that executes no commands sits at `Failed`
/// and can never reach `Stopped` — because reaching `Stopped` is something
/// that node would have to do. The one API call that would rescue it was
/// refused, with the advice to do what had already been done:
///
/// ```text
/// $ meister vm get mc-r1 -o json | jq -r '.spec.runStrategy, .status.phase().kind()'
/// Stopped
/// Failed
/// $ meister vm reschedule mc-r1
/// Error: 422: reschedule needs a stopped vm (phase Failed); stop it first
/// ```
///
/// So `Failed` and `Unknown` are stopped enough. Neither is a guest anybody
/// is promising is running: `Failed` is the node's own word that it is not,
/// and `Unknown` (D10) is nobody knowing — and what an operator asserts by
/// asking for a reschedule of an `Unknown` VM is exactly that the machine is
/// gone. It is the one case here that is a judgement rather than a
/// derivation, and it is theirs to make: the alternative is the dead end this
/// rule exists to open, and the guards that remain are real — a node-local
/// disk still refuses to follow, and a backend write lock is still a write
/// lock.
///
/// `Paused` is NOT enough, and that is the pair worth stating: a paused guest
/// has its memory, its disks open and its VMM alive, so moving the binding
/// would be two VMMs on one disk the moment the old one is resumed.
/// `Pending` and `Provisioning` are a pass in flight, and `Quarantined` is
/// deliberately nobody's to touch.
pub fn stopped_enough(strategy: RunStrategy, phase: VmPhaseKind) -> bool {
    strategy == RunStrategy::Stopped
        && matches!(
            phase,
            VmPhaseKind::Stopped | VmPhaseKind::Failed | VmPhaseKind::Unknown
        )
}

/// Why not, in the words the two halves need to be told apart.
///
/// The old sentence said "phase Running; stop it first" to somebody who had
/// just stopped it — during the thirty-second grace `vm ls` already shows
/// `RUN Stopped` while the phase is still `Running`, and being told to do
/// what you have done is how an operator concludes the API is broken. The two
/// cases are different waits: one is on a person, the other is on a guest.
pub fn not_stopped_enough(strategy: RunStrategy, phase: VmPhaseKind) -> String {
    match strategy {
        RunStrategy::Stopped => format!(
            "this vm has been told to stop and is still {}; wait for it to come to rest, then \
             let the binding go",
            phase.as_str()
        ),
        _ => format!(
            "reschedule needs a vm nobody wants running (runStrategy {}, phase {}); set \
             runStrategy to Stopped first, then let the binding go",
            strategy.as_str(),
            phase.as_str()
        ),
    }
}

/// What holds a VM at this tier: a machine one floor down, a cluster one
/// floor up. Only the words of the refusal differ.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Holder {
    Node,
    Cluster,
}

impl Holder {
    fn as_str(self) -> &'static str {
        match self {
            Holder::Node => "node",
            Holder::Cluster => "cluster",
        }
    }
}

/// Why an `Unknown` binding may not be let go right now — or `None`, meaning
/// it may.
///
/// `stopped_enough` calls `Unknown` stopped enough, and on its own that is a
/// claim nobody can back: `Unknown` is precisely the phase in which the
/// control plane does not know whether a guest is running. Rescheduling on
/// that would place the VM a second time while the first one may still hold
/// its disks open — two VMMs on one file, which is the outcome the whole
/// binding rule exists to prevent.
///
/// So the phase alone is not enough, and the second half is EVIDENCE: the
/// holder has to be talking. A heartbeat that is current is exactly that — it
/// is written by the replica holding the holder's session, every beat, and it
/// is the same fact the watchdog read to call the phase `Unknown` in the first
/// place. With the holder back, the ordinary stop runs first and the phase
/// settles into one this call takes anyway; with the holder silent, this
/// refuses and says what the two ways out are.
///
/// `Failed` is untouched, and that is the pair worth stating: `Failed` is the
/// holder's OWN word that the guest is not running, which is evidence. Only
/// `Unknown` is an absence of evidence.
pub fn unknown_needs_its_holder(
    phase: VmPhaseKind,
    holder: Holder,
    name: &str,
    last_heartbeat: Option<DateTime<Utc>>,
    now: DateTime<Utc>,
) -> Option<String> {
    if phase != VmPhaseKind::Unknown {
        return None;
    }
    if !crate::heartbeat_expired(last_heartbeat, now) {
        return None;
    }
    let what = holder.as_str();
    let since = match last_heartbeat {
        Some(last) => format!("has not reported since {}", last.to_rfc3339()),
        None => "has never reported".to_string(),
    };
    Some(format!(
        "{what} {name} {since}, more than {}s ago, and that is why this vm's phase is Unknown: the guest may still be running there. Letting the binding go now would place the vm a second time while the first one still holds its disks open. Wait for {name} to report — the phase then settles into one this call takes — or drain the {what}, which is how the control plane is told what became of its guests",
        crate::HEARTBEAT_TIMEOUT_SECS
    ))
}

/// The event a released `Unknown` binding leaves behind.
///
/// Part of the rule and not decoration: this is the one call in the API that
/// lets a person assert something the control plane cannot see, so the object
/// carries the record that it was asserted, and by which phase it was covered.
pub fn released_while_unknown(holder: Holder, name: &str) -> String {
    format!(
        "the binding to {} {name} was let go while the phase was Unknown; {name} was reporting at the time, so the guest was asked to stop before the vm was placed again",
        holder.as_str()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// D12: the phase a wedged VM is actually in is the phase the one call
    /// that would rescue it used to refuse.
    #[test]
    fn a_reschedule_takes_every_phase_that_is_not_a_promise_about_a_guest() {
        use RunStrategy::*;
        // Stopped enough: nothing is claiming this guest runs.
        for phase in [
            VmPhaseKind::Stopped,
            VmPhaseKind::Failed,
            VmPhaseKind::Unknown,
        ] {
            assert!(stopped_enough(Stopped, phase), "{phase:?}");
        }
        // And not: a paused guest holds its memory and its disks, a pass is
        // in flight, or the VM is deliberately nobody's.
        for phase in [
            VmPhaseKind::Running,
            VmPhaseKind::Paused,
            VmPhaseKind::Pending,
            VmPhaseKind::Provisioning,
            VmPhaseKind::Quarantined,
        ] {
            assert!(!stopped_enough(Stopped, phase), "{phase:?}");
        }
        // The intent half is unchanged and unconditional: nobody moves a VM
        // somebody still wants running, whatever it is doing.
        for strategy in [Running, Paused] {
            for phase in VmPhaseKind::ALL {
                assert!(!stopped_enough(strategy, phase), "{strategy:?} {phase:?}");
            }
        }
    }

    /// Silas' rule: `Unknown` is stopped enough only while the holder is
    /// there to be asked.
    ///
    /// The phase says nobody knows what the guest is doing. Letting the
    /// binding go on that alone is an assertion no one can back — and if it
    /// is wrong, it is two VMMs on one disk. A current heartbeat is the
    /// evidence: the holder is talking, so the ordinary stop runs first.
    #[test]
    fn an_unknown_binding_needs_its_holder_to_be_talking() {
        let at = |secs: i64| DateTime::from_timestamp(1_800_000_000 + secs, 0).unwrap();
        let now = at(1_000);

        // Silent: refused, and the sentence carries the four things a person
        // needs — who is silent, since when, what may still be running, and
        // the two ways out.
        let why = unknown_needs_its_holder(
            VmPhaseKind::Unknown,
            Holder::Node,
            "agent-1a",
            Some(at(0)),
            now,
        )
        .expect("a silent node refuses");
        assert!(why.contains("node agent-1a"), "{why}");
        assert!(why.contains(&at(0).to_rfc3339()), "{why}");
        assert!(why.contains("may still be running"), "{why}");
        assert!(why.contains("drain the node"), "{why}");

        // Never heard from at all is the same refusal, said honestly.
        let never =
            unknown_needs_its_holder(VmPhaseKind::Unknown, Holder::Node, "agent-1a", None, now)
                .expect("a node that never reported refuses");
        assert!(never.contains("has never reported"), "{never}");

        // Talking: allowed. The holder can be asked to stop the guest, which
        // is the whole difference.
        assert_eq!(
            unknown_needs_its_holder(
                VmPhaseKind::Unknown,
                Holder::Node,
                "agent-1a",
                Some(at(1_000)),
                now,
            ),
            None
        );

        // Every other phase is untouched, `Failed` above all: that is the
        // holder's OWN word that the guest is not running, which is evidence.
        for phase in VmPhaseKind::ALL {
            if phase == VmPhaseKind::Unknown {
                continue;
            }
            assert_eq!(
                unknown_needs_its_holder(phase, Holder::Node, "agent-1a", None, now),
                None,
                "{phase:?}"
            );
        }

        // One rule, two tiers: the cloud asks it about a cluster and gets the
        // same shape with the other noun.
        let up = unknown_needs_its_holder(
            VmPhaseKind::Unknown,
            Holder::Cluster,
            "cluster-1",
            None,
            now,
        )
        .expect("a silent cluster refuses too");
        assert!(up.contains("cluster cluster-1"), "{up}");
        assert!(up.contains("drain the cluster"), "{up}");
    }

    /// The event half of the same rule: what the object is left carrying.
    #[test]
    fn a_binding_let_go_while_unknown_says_so_on_the_object() {
        let said = released_while_unknown(Holder::Node, "agent-1a");
        assert!(said.contains("while the phase was Unknown"), "{said}");
        assert!(said.contains("agent-1a"), "{said}");
    }

    /// And the two sentences, because the wrong one is what made the dead end
    /// look like a bug in the client.
    #[test]
    fn the_refusal_says_which_of_the_two_waits_this_is() {
        // Told to stop, still stopping: the wait is on the guest, and telling
        // an operator to stop it again is telling them to do what they did.
        let waiting = not_stopped_enough(RunStrategy::Stopped, VmPhaseKind::Running);
        assert!(waiting.contains("has been told to stop"), "{waiting}");
        assert!(!waiting.contains("stop it first"), "{waiting}");
        // Nobody has asked for it to stop at all: the wait is on a person.
        let unasked = not_stopped_enough(RunStrategy::Running, VmPhaseKind::Running);
        assert!(unasked.contains("runStrategy to Stopped"), "{unasked}");
    }

    #[test]
    fn a_stable_phase_that_disagrees_with_the_run_strategy_gets_a_command() {
        use Lifecycle::*;
        use RunStrategy::*;
        let cases = [
            (Running, VmPhaseKind::Running, None),
            (Running, VmPhaseKind::Stopped, Some(Start)),
            (Running, VmPhaseKind::Paused, Some(Resume)),
            (Stopped, VmPhaseKind::Stopped, None),
            (Stopped, VmPhaseKind::Running, Some(Stop)),
            (Stopped, VmPhaseKind::Paused, Some(Stop)),
            (Paused, VmPhaseKind::Paused, None),
            (Paused, VmPhaseKind::Running, Some(Pause)),
            // Pause, not Start: the agent's plan starts it and pauses it in
            // the same pass, and Start would name the wrong intent.
            (Paused, VmPhaseKind::Stopped, Some(Pause)),
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
            for phase in VmPhaseKind::ALL {
                cells += 1;
                if lifecycle_command(strategy, phase).is_some() {
                    commanded += 1;
                }
            }
        }
        assert_eq!(
            cells,
            RunStrategy::ALL.len() * VmPhaseKind::ALL.len(),
            "the cross product is not the size it was"
        );
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
            for phase in VmPhaseKind::ALL {
                let Some(action) = lifecycle_command(strategy, phase) else {
                    continue;
                };
                assert!(
                    phase.is_stable(),
                    "{action:?} was sent at {phase:?}, still in motion"
                );
                let already_there = matches!(
                    (strategy, phase),
                    (RunStrategy::Running, VmPhaseKind::Running)
                        | (RunStrategy::Stopped, VmPhaseKind::Stopped)
                        | (RunStrategy::Paused, VmPhaseKind::Paused)
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
            for phase in [
                VmPhaseKind::Running,
                VmPhaseKind::Stopped,
                VmPhaseKind::Paused,
            ] {
                let agrees = matches!(
                    (strategy, phase),
                    (RunStrategy::Running, VmPhaseKind::Running)
                        | (RunStrategy::Stopped, VmPhaseKind::Stopped)
                        | (RunStrategy::Paused, VmPhaseKind::Paused)
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
            VmPhaseKind::Pending,
            VmPhaseKind::Provisioning,
            VmPhaseKind::Failed,
            VmPhaseKind::Quarantined,
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
