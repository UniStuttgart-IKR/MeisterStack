// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Deterministic crash enumeration for `meister-activate`.
//!
//! An enumeration runs a verb once uncut to count its mutating effects `n`,
//! then once per cut `k` in `0..=n` on a fresh host: effects `0..k` land and
//! the process dies at `k`; `k == n` is the run that finishes. Every cut is
//! judged frozen, before anybody recovers it (O0), then after each successor
//! has recovered it (I-A1, I-A2), and the same successor once more must change
//! nothing (I-A5). A [`Scenario`] has a default for none of these. The model
//! of the host judges, never what the code under test says of itself.

use std::collections::BTreeMap;
use std::fmt::Debug;
use std::sync::Arc;

use super::*;
use crate::effects::cut::{CutPoint, Op};
use crate::effects::{FakeClock, ProcessState};

mod confirm;
mod keys;

const DEPLOY: &str = "/var/lib/meisterstack/deploy";

fn clock() -> FakeClock {
    FakeClock::at(crate::fixtures::at("2026-09-22T12:00:00Z"))
}

/// One incarnation of `meister-activate`. Every earlier one has crashed, so
/// only its own pid runs, started at a tick of its own in the one boot.
struct FakeProcesses(u32);

fn started(pid: u32) -> ProcessState {
    ProcessState::Running {
        start: u64::from(pid) * 100,
    }
}

impl Processes for FakeProcesses {
    fn own_pid(&self) -> u32 {
        self.0
    }

    fn boot_id(&self) -> Option<String> {
        Some("boot-1".to_string())
    }

    fn state_of(&self, pid: u32) -> ProcessState {
        if pid == self.0 {
            started(pid)
        } else {
            ProcessState::Gone
        }
    }
}

fn helper<'a>(
    runner: &'a dyn Runner,
    files: &'a dyn Files,
    clock: &'a FakeClock,
    me: &'a dyn Processes,
) -> Helper<'a> {
    Helper::new(runner, files, clock, DEPLOY, "/exe").with_processes(me)
}

/// The invariants, by the names the crash-test plan gives them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Invariant {
    /// The frozen host: nothing said of it is false, and nothing on it is
    /// moved without a record that guards it.
    O0,
    /// The recovered host is in one of the end states the scenario allows.
    IA1,
    /// No timer for a closed transaction, and no revert after `confirming`.
    IA2,
    /// The same recovery once more changes nothing.
    IA5,
}

/// One invariant a cut broke, and how.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Breach {
    invariant: Invariant,
    detail: String,
}

impl Breach {
    fn of(invariant: Invariant, detail: impl Into<String>) -> Breach {
        Breach {
            invariant,
            detail: detail.into(),
        }
    }
}

/// A breach, with the cut of the verb, the cut of the recovery if that
/// crashed too, and the successor.
#[derive(Debug)]
struct Found {
    cut: usize,
    recovery_cut: Option<usize>,
    by: String,
    breach: Breach,
}

impl std::fmt::Display for Found {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "cut {}", self.cut)?;
        if let Some(j) = self.recovery_cut {
            write!(f, ", recovery cut {j}")?;
        }
        write!(
            f,
            ", then {}: {:?} {}",
            self.by, self.breach.invariant, self.breach.detail
        )
    }
}

/// Fail with every breach, one per line.
fn assert_no_breach(found: &[Found]) {
    let lines: Vec<String> = found.iter().map(Found::to_string).collect();
    assert!(lines.is_empty(), "{}", lines.join("\n"));
}

/// One verb under the cut, what may come after it, and how the model of the
/// host judges both.
trait Scenario {
    type World;
    /// What the frozen host showed that the recovered one is judged by.
    type Seen;
    type Successor: Copy + Debug;
    type Snapshot: PartialEq + Debug;

    fn world(&self) -> Self::World;
    /// The verb, as the process that dies, and what it answered.
    fn run(&self, world: &Self::World, cut: &Arc<CutPoint>) -> Result<()>;
    /// O0, on the frozen host.
    fn frozen(&self, world: &Self::World) -> (Vec<Breach>, Self::Seen);
    fn successors(&self) -> Vec<Self::Successor>;
    /// What comes after the crash, its effects through `cut`. Its processes
    /// take pids from `first_pid` on: every recovery is a new incarnation.
    /// Answers with what the successors answered that the model does not
    /// allow.
    fn recover(
        &self,
        world: &Self::World,
        by: Self::Successor,
        cut: &Arc<CutPoint>,
        first_pid: u32,
    ) -> Vec<Breach>;
    /// I-A1 and I-A2, on the host `by` recovered.
    fn settled(&self, world: &Self::World, by: Self::Successor, seen: &Self::Seen) -> Vec<Breach>;
    fn snapshot(&self, world: &Self::World) -> Self::Snapshot;
}

/// The effects one uncut run of the verb makes. A verb that refuses the
/// host it starts from, or finishes without an effect, leaves only the cut
/// at the end, and every end state would be judged on a host nothing moved.
fn trace_of<S: Scenario>(scenario: &S) -> Vec<Op> {
    let cut = CutPoint::new();
    if let Err(e) = scenario.run(&scenario.world(), &cut) {
        panic!("VACUOUS: the uncut verb failed on the host it starts from: {e:#}");
    }
    let trace = cut.trace();
    assert!(!trace.is_empty(), "VACUOUS: the uncut verb made no effect");
    trace
}

/// A cut armed inside the run must fire exactly there; one armed at `n` is
/// the finished run. Anything else tested nothing.
fn assert_fired(cut: &CutPoint, k: usize, n: usize) {
    let at = cut.frozen_at().map(|op| op.ordinal);
    let expected = (k < n).then_some(k);
    assert_eq!(
        at, expected,
        "VACUOUS: armed at {k} of {n} effects, fired at {at:?}"
    );
}

/// A fresh host on which the verb died at effect `k` of `n`.
fn crashed_at<S: Scenario>(scenario: &S, k: usize, n: usize) -> S::World {
    let (world, cut) = (scenario.world(), CutPoint::new());
    cut.arm_after(k);
    // Nobody hears what a process that died answered; `trace_of` judged
    // the answer of the run that finishes.
    let _ = scenario.run(&world, &cut);
    assert_fired(&cut, k, n);
    world
}

/// Recover uncut and judge the answers and the result, then recover once
/// more (I-A5).
fn settle<S: Scenario>(
    scenario: &S,
    world: &S::World,
    by: S::Successor,
    seen: &S::Seen,
) -> Vec<Breach> {
    let mut breaches = scenario.recover(world, by, &CutPoint::new(), 20);
    breaches.extend(scenario.settled(world, by, seen));
    let before = scenario.snapshot(world);
    breaches.extend(scenario.recover(world, by, &CutPoint::new(), 30));
    let after = scenario.snapshot(world);
    if after != before {
        breaches.push(Breach::of(
            Invariant::IA5,
            format!("{by:?} once more turned {before:#?} into {after:#?}"),
        ));
    }
    breaches
}

fn found(
    cut: usize,
    recovery_cut: Option<usize>,
    by: impl Debug,
    breaches: Vec<Breach>,
) -> impl Iterator<Item = Found> {
    let by = format!("{by:?}");
    breaches.into_iter().map(move |breach| Found {
        cut,
        recovery_cut,
        by: by.clone(),
        breach,
    })
}

/// Every cut of the verb, judged frozen and after every successor.
fn every_crash<S: Scenario>(scenario: &S) -> Vec<Found> {
    let n = trace_of(scenario).len();
    let mut all = Vec::new();
    for k in 0..=n {
        for by in scenario.successors() {
            let world = crashed_at(scenario, k, n);
            let (mut breaches, seen) = scenario.frozen(&world);
            breaches.extend(settle(scenario, &world, by, &seen));
            all.extend(found(k, None, by, breaches));
        }
    }
    all
}

/// Every cut of the verb, then every cut of each successor's recovery,
/// judged frozen again, and then that successor once more, uncut.
fn every_crash_during_recovery<S: Scenario>(scenario: &S) -> Vec<Found> {
    let n = trace_of(scenario).len();
    let mut all = Vec::new();
    for k in 0..=n {
        for by in scenario.successors() {
            let m = {
                let (world, cut) = (crashed_at(scenario, k, n), CutPoint::new());
                // `settle` judges this same recovery's answers.
                let _ = scenario.recover(&world, by, &cut, 10);
                cut.trace().len()
            };
            for j in 0..m {
                let (world, cut) = (crashed_at(scenario, k, n), CutPoint::new());
                cut.arm_after(j);
                // Nobody hears what a recovery that died answered.
                let _ = scenario.recover(&world, by, &cut, 10);
                assert_fired(&cut, j, m);
                let (mut breaches, seen) = scenario.frozen(&world);
                breaches.extend(settle(scenario, &world, by, &seen));
                all.extend(found(k, Some(j), by, breaches));
            }
        }
    }
    all
}
