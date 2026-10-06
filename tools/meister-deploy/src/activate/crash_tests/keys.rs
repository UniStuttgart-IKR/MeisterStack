// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Key rotation: files only, no target model. Which pair is in use is read
//! off the bytes on the disk; `keys status` is what gets judged.

use super::*;
use crate::activate::key_fixtures::rotating;
use crate::effects::MemFiles;
use crate::effects::cut::CutFiles;
use crate::run::StrictFake;

const KIND: KeyKind = KeyKind::Identity;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum KeyVerb {
    Switch,
    Revert,
    Remove,
}

impl KeyVerb {
    fn run(self, files: &dyn Files, pid: u32) -> Result<KeysRecord> {
        let (runner, clock, me) = (StrictFake::new(), clock(), FakeProcesses(pid));
        let helper = helper(&runner, files, &clock, &me);
        match self {
            KeyVerb::Switch => helper.keys_switch(KIND, Some("run-1")),
            KeyVerb::Revert => helper.keys_revert(KIND, Some("verify failed")),
            KeyVerb::Remove => helper.keys_remove(KIND),
        }
    }
}

fn pki(name: &str) -> String {
    format!("{DEFAULT_PKI_DIR}/identity.{name}")
}

/// What a whole switch leaves: the new pair in use, the old one aside.
fn switched() -> MemFiles {
    let files = rotating();
    KeyVerb::Switch.run(&files, 1).expect("an uncut switch");
    files
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Pair {
    Old,
    New,
}

/// The whole pair at `key` and `crt`, or at `key.<suffix>` and
/// `crt.<suffix>`, read straight off the disk.
fn pair_at(files: &MemFiles, suffix: Option<&str>) -> Option<Pair> {
    let text = |name: &str| {
        let name = suffix.map_or(name.to_string(), |s| format!("{name}.{s}"));
        files
            .content(pki(&name))
            .map(|b| String::from_utf8_lossy(&b).into_owned())
    };
    match (text("key")?.as_str(), text("crt")?.as_str()) {
        ("old key\n", "old crt\n") => Some(Pair::Old),
        ("new key\n", "new crt\n") => Some(Pair::New),
        _ => None,
    }
}

/// Anything of a rotation beside the pair in use.
fn beside_the_pair(files: &MemFiles) -> bool {
    files.paths().iter().any(|path| {
        let path = path.to_string_lossy();
        path.ends_with(".next") || path.ends_with(".prev")
    })
}

/// Every file on the host, the record included, and what it holds.
fn on_disk(files: &MemFiles) -> BTreeMap<PathBuf, Vec<u8>> {
    files.contents_under("/")
}

fn copy_of(files: &MemFiles) -> MemFiles {
    on_disk(files)
        .into_iter()
        .fold(MemFiles::new(), |copy, (path, bytes)| {
            copy.given(path, bytes)
        })
}

fn keys_state(files: &MemFiles) -> KeysState {
    let (runner, clock, me) = (StrictFake::new(), clock(), FakeProcesses(9));
    let helper = helper(&runner, files, &clock, &me);
    helper.keys_status(KIND).expect("status reads").state
}

/// `keys status` claims nothing the files do not show. Inconsistent claims
/// nothing; `none` is false once a rotation has begun, which it has in every
/// scenario here.
fn status_is_false(files: &MemFiles) -> Option<String> {
    let state = keys_state(files);
    let (in_use, aside) = (pair_at(files, None), pair_at(files, Some("prev")));
    let true_ = match state {
        KeysState::Switched => in_use == Some(Pair::New) && aside == Some(Pair::Old),
        KeysState::Confirmed => in_use == Some(Pair::New) && !beside_the_pair(files),
        KeysState::Reverted => in_use == Some(Pair::Old) && !beside_the_pair(files),
        KeysState::Prepared | KeysState::Overlap => in_use == Some(Pair::Old),
        KeysState::Inconsistent => true,
        KeysState::None => false,
    };
    (!true_).then(|| format!("status {state} with {in_use:?} in use and {aside:?} aside"))
}

/// An operator who trusts `keys status` may run `keys remove` at any time.
/// It finishes with the new pair in use, or refuses and changes nothing.
fn remove_takes_the_last_pair(files: &MemFiles) -> Option<String> {
    let copy = copy_of(files);
    let before = on_disk(&copy);
    match KeyVerb::Remove.run(&copy, 9) {
        Ok(_) if pair_at(&copy, None) == Some(Pair::New) => None,
        Ok(_) => Some(format!(
            "keys remove left {:?} in use",
            pair_at(&copy, None)
        )),
        Err(_) if on_disk(&copy) == before => None,
        Err(e) => Some(format!("keys remove failed half way: {e:#}")),
    }
}

/// One key verb, and the host it starts from.
struct KeyRotation {
    verb: KeyVerb,
    from: fn() -> MemFiles,
}

impl KeyRotation {
    /// The verb, from the host it starts from in a rotation.
    fn of(verb: KeyVerb) -> KeyRotation {
        let from = match verb {
            KeyVerb::Switch => rotating,
            KeyVerb::Revert | KeyVerb::Remove => switched,
        };
        KeyRotation { verb, from }
    }

    /// Whether a key file is no longer where the verb found it.
    fn moved(&self, files: &MemFiles) -> bool {
        files.contents_under(DEFAULT_PKI_DIR) != (self.from)().contents_under(DEFAULT_PKI_DIR)
    }

    /// The pair in use and the status each successor ends with. Taken back
    /// before it moved a file, a switch is still the rotation it was:
    /// `keys revert` refuses with nothing to put back, the old pair stays in
    /// use and the prepared one waits, so the status is `overlap` and never
    /// `reverted`.
    fn ends(&self, by: KeySuccessor, moved: bool) -> &'static [(Pair, KeysState)] {
        match (self.verb, by) {
            (KeyVerb::Switch, KeySuccessor::RunAgain) => &[(Pair::New, KeysState::Switched)],
            (KeyVerb::Switch, KeySuccessor::TakeBack) if !moved => {
                &[(Pair::Old, KeysState::Overlap)]
            }
            (KeyVerb::Switch, KeySuccessor::TakeBack) | (KeyVerb::Revert, _) => {
                &[(Pair::Old, KeysState::Reverted)]
            }
            (KeyVerb::Remove, KeySuccessor::RunAgain) => &[(Pair::New, KeysState::Confirmed)],
            // Not a successor of a removal: nothing it leaves is an end.
            (KeyVerb::Remove, KeySuccessor::TakeBack) => &[],
        }
    }
}

/// What comes after a crash in a key verb.
#[derive(Debug, Clone, Copy)]
enum KeySuccessor {
    /// The same verb, as a resume or an operator repeats it.
    RunAgain,
    /// `keys revert`, as a failed verification asks for it.
    TakeBack,
}

impl Scenario for KeyRotation {
    type World = MemFiles;
    /// A key file had moved off where the verb found it.
    type Seen = bool;
    type Successor = KeySuccessor;
    type Snapshot = BTreeMap<PathBuf, Vec<u8>>;

    fn world(&self) -> MemFiles {
        (self.from)()
    }

    fn run(&self, files: &MemFiles, cut: &Arc<CutPoint>) -> Result<()> {
        self.verb.run(&CutFiles(files, cut.clone()), 1).map(drop)
    }

    fn frozen(&self, files: &MemFiles) -> (Vec<Breach>, bool) {
        let breaches = [status_is_false(files), remove_takes_the_last_pair(files)]
            .into_iter()
            .flatten()
            .map(|detail| Breach::of(Invariant::O0, detail))
            .collect();
        (breaches, self.moved(files))
    }

    fn successors(&self) -> Vec<KeySuccessor> {
        match self.verb {
            KeyVerb::Switch => vec![KeySuccessor::RunAgain, KeySuccessor::TakeBack],
            KeyVerb::Revert | KeyVerb::Remove => vec![KeySuccessor::RunAgain],
        }
    }

    /// A successor finishes, or refuses and changes nothing: a verb whose
    /// layout is already behind it refuses. Where it ends is `settled`'s.
    fn recover(
        &self,
        files: &MemFiles,
        by: KeySuccessor,
        cut: &Arc<CutPoint>,
        first_pid: u32,
    ) -> Vec<Breach> {
        let verb = match by {
            KeySuccessor::RunAgain => self.verb,
            KeySuccessor::TakeBack => KeyVerb::Revert,
        };
        let before = on_disk(files);
        match verb.run(&CutFiles(files, cut.clone()), first_pid) {
            Err(e) if on_disk(files) != before => vec![Breach::of(
                Invariant::IA1,
                format!("keys {verb:?} failed half way: {e:#}"),
            )],
            _ => Vec::new(),
        }
    }

    /// I-A1: the pair in use and the status this successor ends with, and
    /// a status that is true. A layout only a person can resolve is not an
    /// end state.
    fn settled(&self, files: &MemFiles, by: KeySuccessor, moved: &bool) -> Vec<Breach> {
        let state = keys_state(files);
        let in_use = pair_at(files, None);
        let ends = self.ends(by, *moved);
        let mut breaches: Vec<Breach> = status_is_false(files)
            .into_iter()
            .map(|detail| Breach::of(Invariant::IA1, detail))
            .collect();
        if !in_use.is_some_and(|pair| ends.contains(&(pair, state))) {
            breaches.push(Breach::of(
                Invariant::IA1,
                format!("{in_use:?} in use, status {state}, where {by:?} ends at {ends:?}"),
            ));
        }
        breaches
    }

    fn snapshot(&self, files: &MemFiles) -> Self::Snapshot {
        on_disk(files)
    }
}

#[test]
fn every_crash_in_a_key_switch_is_finished_by_running_it_again_or_taken_back() {
    assert_no_breach(&every_crash(&KeyRotation::of(KeyVerb::Switch)));
}

#[test]
fn every_crash_in_a_key_revert_is_finished_by_running_it_again() {
    assert_no_breach(&every_crash(&KeyRotation::of(KeyVerb::Revert)));
}

#[test]
fn every_crash_in_a_key_removal_is_finished_by_running_it_again() {
    assert_no_breach(&every_crash(&KeyRotation::of(KeyVerb::Remove)));
}

/// The record is written first by a switch and last by a revert or a
/// removal, so a recovery that dies as well leaves nothing a later one
/// misreads.
#[test]
fn a_crash_while_recovering_a_key_rotation_is_recovered_too() {
    for verb in [KeyVerb::Switch, KeyVerb::Revert, KeyVerb::Remove] {
        assert_no_breach(&every_crash_during_recovery(&KeyRotation::of(verb)));
    }
}

#[test]
#[should_panic(expected = "VACUOUS")]
fn an_armed_cut_that_never_fires_fails() {
    // Armed with the count of a longer verb, a shorter one never reaches the cut.
    let n = trace_of(&KeyRotation::of(KeyVerb::Switch)).len();
    crashed_at(&KeyRotation::of(KeyVerb::Remove), n - 1, n);
}

#[test]
#[should_panic(expected = "VACUOUS")]
fn a_verb_that_refuses_the_host_it_starts_from_fails() {
    // Nothing has switched yet, so there is nothing to remove: every cut
    // would be judged on a host the verb never touched.
    let refusing = KeyRotation {
        verb: KeyVerb::Remove,
        from: rotating,
    };
    trace_of(&refusing);
}
