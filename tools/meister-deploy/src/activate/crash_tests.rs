// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Deterministic crash enumeration for key rotation and confirm (spike).
//!
//! Each enumeration runs a verb once uncut to count its mutating effects `n`,
//! then once per cut `k` in `0..=n` on a fresh host: effects `0..k` land and the
//! process dies at `k`; `k == n` is the run that finishes. Successors recover,
//! and the invariants are judged by the model of the host (files, profile,
//! running system, timer), never by what the code under test says of itself.
//! Line citations are to activate.rs on main d8aa577f, before the seam.

use std::cell::RefCell;
use std::sync::Arc;

use super::*;
use crate::effects::cut::{CutFiles, CutPoint, CutRunner, Mode as Cut, Op};
use crate::effects::{FakeClock, MemFiles};
use crate::run::{Output, Policy, StrictFake};

const TOP: &str = "/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-nixos-system-box-25.11";
const PREV: &str = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-nixos-system-box-25.11";
const DEPLOY: &str = "/var/lib/meisterstack/deploy";
const ID: &str = "c1";
const KIND: KeyKind = KeyKind::Identity;

fn clock() -> FakeClock {
    FakeClock::at(crate::fixtures::at("2026-09-22T12:00:00Z"))
}

/// One incarnation of `meister-activate`. Every earlier one has crashed, so
/// only its own pid is alive.
struct FakeProcesses(u32);

impl Processes for FakeProcesses {
    fn own_pid(&self) -> u32 {
        self.0
    }

    fn alive(&self, pid: u32) -> bool {
        pid == self.0
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

// -----------------------------------------------------------------------
// key rotation: Files only, no target model
// -----------------------------------------------------------------------

#[derive(Debug, Clone, Copy)]
enum KeyVerb {
    Switch,
    Revert,
    Remove,
}

impl KeyVerb {
    /// The host each verb starts from in a rotation.
    fn host(self) -> MemFiles {
        match self {
            KeyVerb::Switch => rotating(),
            KeyVerb::Revert | KeyVerb::Remove => switched(),
        }
    }

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

/// The new pair prepared beside the one in use.
fn rotating() -> MemFiles {
    MemFiles::new()
        .given(pki("key"), "old key\n")
        .given(pki("crt"), "old crt\n")
        .given(pki("key.next"), "new key\n")
        .given(pki("crt.next"), "new crt\n")
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

/// The whole pair a service would load, read straight off the disk.
fn pair_in_use(files: &MemFiles) -> Option<Pair> {
    let text = |name| {
        files
            .content(pki(name))
            .map(|b| String::from_utf8_lossy(&b).into_owned())
    };
    match (text("key")?.as_str(), text("crt")?.as_str()) {
        ("old key\n", "old crt\n") => Some(Pair::Old),
        ("new key\n", "new crt\n") => Some(Pair::New),
        _ => None,
    }
}

fn keys_state(files: &MemFiles) -> KeysState {
    let (runner, clock, me) = (StrictFake::new(), clock(), FakeProcesses(9));
    let helper = helper(&runner, files, &clock, &me);
    helper.keys_status(KIND).expect("status reads").state
}

/// The status a recovered rotation may show for the pair it left in use.
fn status_fits(pair: Pair, state: KeysState) -> bool {
    match pair {
        Pair::New => matches!(state, KeysState::Switched | KeysState::Confirmed),
        Pair::Old => state == KeysState::Reverted,
    }
}

fn key_trace(verb: KeyVerb) -> Vec<Op> {
    let cut = CutPoint::new(Cut::Refuse);
    cut.observe();
    verb.run(&CutFiles(&verb.host(), cut.clone()), 1)
        .expect("an uncut run");
    cut.trace()
}

/// What one crash in a key verb broke: at the frozen disk, and after the
/// successor repeats the verb or, where it refuses, takes the rotation back.
fn key_crash(verb: KeyVerb, k: usize, n: usize) -> Vec<String> {
    let files = verb.host();
    let cut = CutPoint::new(Cut::Refuse);
    cut.arm_after(k);
    let _ = verb.run(&CutFiles(&files, cut.clone()), 1);
    assert_fired(&cut, k, n);

    let mut broken = Vec::new();
    // DV-F08: `switched` only for the whole new pair (activate.rs:1569).
    if keys_state(&files) == KeysState::Switched && pair_in_use(&files) != Some(Pair::New) {
        broken.push("frozen: switched without the new pair in use".to_string());
    }
    if verb.run(&files, 2).is_err() {
        let _ = KeyVerb::Revert.run(&files, 2);
    }
    let state = keys_state(&files);
    match pair_in_use(&files) {
        None => broken.push(format!("recovered: no whole pair, status {state}")),
        Some(pair) if !status_fits(pair, state) => {
            broken.push(format!("recovered: {pair:?} in use, status {state}"));
        }
        Some(_) => {}
    }
    broken
}

/// Every cut of one verb, with what it broke, for the pinned comparison.
fn key_crashes(verb: KeyVerb) -> Vec<(usize, String)> {
    let n = key_trace(verb).len();
    eprintln!("keys {verb:?}: {n} effects, {} cuts", n + 1);
    (0..=n)
        .flat_map(|k| key_crash(verb, k, n).into_iter().map(move |b| (k, b)))
        .collect()
}

fn pinned(known: &[(usize, &str)]) -> Vec<(usize, String)> {
    known.iter().map(|(k, b)| (*k, b.to_string())).collect()
}

#[test]
fn every_crash_in_keys_switch_is_resolvable() {
    // Open: a crash between the last two renames (activate.rs:1651-1652)
    // cannot be finished (no `.key.next`), and the revert that can run
    // leaves `.crt.next` for a key it deleted.
    let known = [(3, "recovered: Old in use, status inconsistent")];
    assert_eq!(key_crashes(KeyVerb::Switch), pinned(&known));
}

#[test]
fn every_crash_in_keys_revert_is_resolvable() {
    // Open: after the removes at activate.rs:1687-1688, `.prev` alone reads as
    // `switched` (:1569) with the current pair half or wholly gone; between
    // the renames (:1689-1690) no verb can finish the way back; and a revert
    // that finished its renames but not its record (:1702) reads `none`.
    let known = [
        (1, "frozen: switched without the new pair in use"),
        (2, "frozen: switched without the new pair in use"),
        (3, "recovered: no whole pair, status inconsistent"),
        (4, "recovered: Old in use, status none"),
        (5, "recovered: Old in use, status none"),
    ];
    assert_eq!(key_crashes(KeyVerb::Revert), pinned(&known));
}

#[test]
fn every_crash_in_keys_remove_is_resolvable() {
    // Open: with both `.prev` gone (activate.rs:1717-1718) and the record not
    // yet `confirmed` (:1728), status is `none` (:1580), which the resume
    // table makes RecoveryRequired (receipt.rs:845-856) for a finished rotation.
    let known = [
        (2, "recovered: New in use, status none"),
        (3, "recovered: New in use, status none"),
    ];
    assert_eq!(key_crashes(KeyVerb::Remove), pinned(&known));
}

// -----------------------------------------------------------------------
// confirm: the target model
// -----------------------------------------------------------------------

/// What systemd and `switch-to-configuration` hold, which no file says.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Machine {
    timer_active: bool,
    running: String,
    generation: u64,
}

/// A NixOS target behind the `Runner` seam, modelled on `Moving`
/// (activate.rs:2026-2049): the profile lives in `files`, the rest in `machine`.
struct Host {
    files: MemFiles,
    machine: RefCell<Machine>,
    clock: FakeClock,
}

#[derive(Debug, PartialEq)]
struct Snapshot {
    files: Vec<(PathBuf, Option<Vec<u8>>)>,
    profile: Option<String>,
    machine: Machine,
}

fn txn_path() -> PathBuf {
    PathBuf::from(format!("{DEPLOY}/txn/{ID}.json"))
}

/// What `activate` leaves for `confirm` (activate.rs:601-614).
fn pending() -> TxnRecord {
    let now = clock().now();
    TxnRecord {
        schema: TXN_SCHEMA.to_string(),
        id: ID.to_string(),
        run_id: None,
        previous: SystemPoint {
            toplevel: Some(PREV.to_string()),
            generation: Some(41),
        },
        desired: TOP.to_string(),
        mode: Mode::Switch,
        started_at: now,
        deadline: Some(now + TimeDelta::try_seconds(300).expect("in range")),
        state: TxnState::Pending,
        reason: None,
        changed_at: now,
        retired_by_force: None,
    }
}

impl Host {
    /// TOP switched in as generation 42 over PREV (41), its timer armed.
    fn waiting_for_confirm() -> Host {
        let record = pending().to_json().expect("serializes");
        Host {
            files: MemFiles::new()
                .given_symlink(SYSTEM_PROFILE, "system-42-link")
                .given_symlink(format!("{SYSTEM_PROFILE}-41-link"), PREV)
                .given_symlink(format!("{SYSTEM_PROFILE}-42-link"), TOP)
                .given(txn_path(), record),
            machine: RefCell::new(Machine {
                timer_active: true,
                running: TOP.to_string(),
                generation: 42,
            }),
            clock: clock(),
        }
    }

    /// nix-env(1) `--set`: a new generation for the system, the profile on it.
    fn set_profile(&self, system: &str) -> Result<Output> {
        let generation = {
            let mut machine = self.machine.borrow_mut();
            machine.generation += 1;
            machine.generation
        };
        let link = format!("system-{generation}-link");
        let profile = Path::new(SYSTEM_PROFILE);
        self.files
            .symlink_atomic(Path::new(system), &profile.with_file_name(&link))?;
        self.files.symlink_atomic(Path::new(&link), profile)?;
        Ok(Output::stdout(""))
    }

    /// systemctl(1) `stop`: 5 for a unit that is not loaded, as a stopped or
    /// elapsed `--collect` timer is (activate.rs:2564-2567 expects it).
    fn stop_timer(&self) -> Output {
        let was_active = std::mem::replace(&mut self.machine.borrow_mut().timer_active, false);
        if was_active {
            Output::stdout("")
        } else {
            Output::failing(5, "Unit meister-revert-c1.timer not loaded.")
        }
    }

    /// systemctl(1) `is-active`: `active` and 0, or `inactive` and 3.
    fn timer_state(&self) -> Output {
        if self.machine.borrow().timer_active {
            Output::stdout("active\n")
        } else {
            Output {
                status: 3,
                ..Output::stdout("inactive\n")
            }
        }
    }

    fn profile(&self) -> Option<String> {
        let link = self.files.link_target(SYSTEM_PROFILE)?;
        let generation = Path::new(SYSTEM_PROFILE).with_file_name(link);
        Some(self.files.link_target(generation)?.display().to_string())
    }

    fn record(&self) -> Option<TxnRecord> {
        let bytes = self.files.content(txn_path())?;
        TxnRecord::from_json(std::str::from_utf8(&bytes).ok()?, "the model").ok()
    }

    fn listed(&self) -> bool {
        let me = FakeProcesses(9);
        let status = helper(self, &self.files, &self.clock, &me).status();
        status.is_ok_and(|s| s.open_txns.iter().any(|t| t.id == ID))
    }

    fn snapshot(&self) -> Snapshot {
        Snapshot {
            files: self
                .files
                .paths()
                .into_iter()
                .map(|p| (p.clone(), self.files.content(p)))
                .collect(),
            profile: self.profile(),
            machine: self.machine.borrow().clone(),
        }
    }

    fn lock_leftovers(&self) -> usize {
        let held = |p: &PathBuf| p.to_string_lossy().contains(".deciding");
        self.files.paths().iter().filter(|p| held(p)).count()
    }
}

/// The exit-code check the real runner makes (run.rs:553-568).
fn accepted(cmd: &Cmd, out: Output) -> Result<Output> {
    let ok = match &cmd.expect {
        Expect::ExitZero => out.ok(),
        Expect::AnyExit => true,
        Expect::Codes(codes) => codes.contains(&out.status),
    };
    if !ok {
        bail!("{} exited {}", cmd.line(), out.status);
    }
    Ok(out)
}

impl Runner for Host {
    fn run(&self, cmd: &Cmd) -> Result<Output> {
        let args: Vec<&str> = cmd.args.iter().map(String::as_str).collect();
        let out = match (cmd.program.as_str(), args.as_slice()) {
            // uname(1); `status` asks on its way past (activate.rs:414-422).
            ("uname", ["-r"]) => Output::stdout("6.12.41\n"),
            ("nix-env", ["-p", _, "--set", system]) => self.set_profile(system)?,
            // systemd-run(1) `--on-active`: a transient timer (activate.rs:751-783).
            ("systemd-run", _) => {
                self.machine.borrow_mut().timer_active = true;
                Output::stdout("")
            }
            ("systemctl", ["stop", _]) => self.stop_timer(),
            ("systemctl", ["is-active", _]) => self.timer_state(),
            // switch-to-configuration `switch`: that system now runs (activate.rs:695-698).
            (program, ["switch"]) if program.ends_with("/bin/switch-to-configuration") => {
                let system = program.trim_end_matches("/bin/switch-to-configuration");
                self.machine.borrow_mut().running = system.to_string();
                Output::stdout("")
            }
            _ => bail!("the target model has no rule for `{}`", cmd.line()),
        };
        accepted(cmd, out)
    }

    fn policy(&self) -> Policy {
        Policy::real()
    }
}

/// `confirm` as pid 1, through the cut.
fn confirm_through(host: &Host, cut: &Arc<CutPoint>) {
    let (files, runner) = (
        CutFiles(&host.files, cut.clone()),
        CutRunner(host, cut.clone()),
    );
    let me = FakeProcesses(1);
    let _ = helper(&runner, &files, &host.clock, &me).confirm(ID);
}

/// The dead man: an armed timer elapses once (systemd.timer(5)) and runs
/// `revert --by-timer` with the unit's reason (activate.rs:772-775).
fn timer_fires(host: &Host, me: &dyn Processes) {
    let armed = std::mem::replace(&mut host.machine.borrow_mut().timer_active, false);
    if armed {
        let because = Some("nobody confirmed this activation before its deadline");
        let helper = helper(host, &host.files, &host.clock, me);
        let _ = helper.revert(ID, because, RevertAsker::Deadline);
    }
}

/// A resumed run (receipt.rs:928-952, execute.rs:2166-2176): pending or
/// confirming is verified and confirmed, or taken back when the host is not
/// ready; anything else is `VerifyOnly`, `RolledBack` or a person's.
fn resume(host: &Host, me: &dyn Processes) {
    let Some(record) = host.record() else { return };
    let ready = host.machine.borrow().running == record.desired;
    let helper = helper(host, &host.files, &host.clock, me);
    let _ = match record.state {
        TxnState::Pending | TxnState::Confirming if ready => helper.confirm(ID),
        TxnState::Pending | TxnState::Confirming => {
            helper.revert(ID, Some("not ready"), RevertAsker::Operator)
        }
        _ => return,
    };
}

/// O0, on the frozen host: an open record on a host that has moved off its
/// previous system has an armed timer or a durable intent.
fn o0(host: &Host) -> Option<String> {
    let moved = host.profile().as_deref() != Some(PREV) || host.machine.borrow().running != PREV;
    let Some(record) = host.record() else {
        return moved.then(|| "O0: the host moved and no record says so".to_string());
    };
    let unguarded = matches!(record.state, TxnState::Pending | TxnState::Staged)
        && !host.machine.borrow().timer_active;
    (moved && unguarded)
        .then(|| format!("O0: {} on a moved host with no timer", record.state_word()))
}

/// I-A1 and I-A2 on the settled host.
fn settled(host: &Host, intent_persisted: bool) -> Vec<String> {
    let Some(record) = host.record() else {
        return vec!["I-A1: the record is gone".to_string()];
    };
    let Machine {
        timer_active,
        running,
        ..
    } = host.machine.borrow().clone();
    let profile = host.profile().unwrap_or_default();
    let on = |system: &str| running == system && profile == system;
    let listed = host.listed();
    let fits = match record.state {
        TxnState::Confirmed => on(TOP),
        TxnState::Reverted => on(PREV),
        // No dead man on purpose: the timer leaves an intent alone (activate.rs:1016-1018).
        TxnState::Confirming | TxnState::Reverting | TxnState::Inconsistent => listed,
        TxnState::Pending | TxnState::Staged => listed && (timer_active || on(PREV)),
    };
    let mut broken = Vec::new();
    if !fits {
        broken.push(format!(
            "I-A1: {} with running {running}, profile {profile}, timer {timer_active}",
            record.state_word()
        ));
    }
    if intent_persisted && record.state == TxnState::Reverted {
        broken.push("I-A2: reverted after confirming was persisted".to_string());
    }
    if !record.is_open() && timer_active {
        broken.push(format!(
            "I-A2: {} with its timer armed",
            record.state_word()
        ));
    }
    broken
}

/// Every invariant one crash in `confirm` breaks, and its lock leftovers (I-A4).
fn confirm_crash(k: usize, n: usize) -> (Vec<String>, usize) {
    let host = Host::waiting_for_confirm();
    let cut = CutPoint::new(Cut::Refuse);
    cut.arm_after(k);
    confirm_through(&host, &cut);
    assert_fired(&cut, k, n);

    let mut broken: Vec<String> = o0(&host).into_iter().collect();
    let intent = host
        .record()
        .is_some_and(|r| matches!(r.state, TxnState::Confirming | TxnState::Confirmed));
    timer_fires(&host, &FakeProcesses(2));
    resume(&host, &FakeProcesses(3));
    broken.extend(settled(&host, intent));
    let before = host.snapshot();
    resume(&host, &FakeProcesses(4));
    if host.snapshot() != before {
        broken.push("I-A5: a second resume changed the host".to_string());
    }
    (broken, host.lock_leftovers())
}

fn confirm_trace() -> Vec<Op> {
    let (host, cut) = (Host::waiting_for_confirm(), CutPoint::new(Cut::Refuse));
    cut.observe();
    confirm_through(&host, &cut);
    cut.trace()
}

#[test]
fn every_crash_in_confirm_finishes_not_reverts() {
    let trace = confirm_trace();
    let n = trace.len();
    let mut leftovers = Vec::new();
    for k in 0..=n {
        let (broken, left) = confirm_crash(k, n);
        assert!(broken.is_empty(), "cut at {k} of {trace:#?}: {broken:#?}");
        leftovers.extend((left > 0).then_some(k));
    }
    eprintln!(
        "confirm: {n} effects, {} cuts, I-A4 warning at cuts {leftovers:?}",
        n + 1
    );
}

// -----------------------------------------------------------------------
// the harness itself
// -----------------------------------------------------------------------

#[test]
fn the_cut_trace_is_identical_twice() {
    let first = confirm_trace();
    assert!(!first.is_empty());
    assert_eq!(first, confirm_trace());
}

#[test]
#[should_panic(expected = "VACUOUS")]
fn an_armed_cut_that_never_fires_fails() {
    // Armed with the count of a longer verb, a shorter one never reaches the cut.
    let n = key_trace(KeyVerb::Switch).len();
    let files = KeyVerb::Remove.host();
    let cut = CutPoint::new(Cut::Refuse);
    cut.arm_after(n - 1);
    let _ = KeyVerb::Remove.run(&CutFiles(&files, cut.clone()), 1);
    assert_fired(&cut, n - 1, n);
}

#[test]
fn land_then_fail_at_k_leaves_what_refuse_leaves_at_k_plus_one() {
    let frozen = |k, mode| {
        let (host, cut) = (Host::waiting_for_confirm(), CutPoint::new(mode));
        cut.arm_after(k);
        confirm_through(&host, &cut);
        host.snapshot()
    };
    for k in 0..confirm_trace().len() {
        assert_eq!(
            frozen(k, Cut::LandThenFail),
            frozen(k + 1, Cut::Refuse),
            "cut at {k}"
        );
    }
}

/// DCT-H1: a crashed holder's pid, recycled by an unrelated process, reads
/// as alive to `kill(pid, 0)`.
struct Recycled(u32);

impl Processes for Recycled {
    fn own_pid(&self) -> u32 {
        self.0
    }

    fn alive(&self, pid: u32) -> bool {
        pid == self.0 || pid == 1
    }
}

#[test]
fn a_recycled_pid_in_a_dead_holders_lock_disarms_the_dead_man() {
    // Pins open hypothesis DCT-H1: confirm dies holding the lock (cut at 2,
    // before any decision), its pid is reused, and the deadline gives up
    // after DEADLINE_PATIENCE (activate.rs:984-990): pending, no timer.
    let host = Host::waiting_for_confirm();
    let cut = CutPoint::new(Cut::Refuse);
    cut.arm_after(2);
    confirm_through(&host, &cut);
    timer_fires(&host, &Recycled(2));
    resume(&host, &Recycled(3));
    assert_eq!(host.record().map(|r| r.state), Some(TxnState::Pending));
    assert!(!host.machine.borrow().timer_active);
    assert!(settled(&host, false)[0].starts_with("I-A1: pending"));
}
