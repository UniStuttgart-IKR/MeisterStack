// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! `confirm` against a model of the target: the profile lives in the files,
//! the running system and the revert timer in [`Machine`], which no file says.

use std::cell::RefCell;

use super::*;
use crate::effects::MemFiles;
use crate::effects::cut::{CutFiles, CutRunner};
use crate::run::{Output, Policy};

const TOP: &str = "/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-nixos-system-box-25.11";
const PREV: &str = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-nixos-system-box-25.11";
const ID: &str = "c1";
/// The pid `confirm` runs as when it dies.
const DYING_PID: u32 = 1;

/// What systemd and `switch-to-configuration` hold.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Machine {
    timer_active: bool,
    running: String,
    generation: u64,
}

/// A NixOS target behind the `Runner` seam, modelled on the `Moving` runner
/// of the activation tests.
struct Host {
    files: MemFiles,
    machine: RefCell<Machine>,
    clock: FakeClock,
}

#[derive(Debug, PartialEq)]
struct Snapshot {
    files: BTreeMap<PathBuf, Vec<u8>>,
    profile: Option<String>,
    machine: Machine,
}

fn txn_path() -> PathBuf {
    PathBuf::from(format!("{DEPLOY}/txn/{ID}.json"))
}

fn lock_path() -> PathBuf {
    PathBuf::from(format!("{DEPLOY}/txn/{ID}.deciding"))
}

/// What `activate` leaves for `confirm`: the record of a switch with a deadline.
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
    /// elapsed `--collect` timer is.
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

    fn snapshot(&self) -> Snapshot {
        Snapshot {
            files: self.files.contents_under("/"),
            profile: self.profile(),
            machine: self.machine.borrow().clone(),
        }
    }

    fn lock_leftovers(&self) -> usize {
        let held = |p: &PathBuf| p.to_string_lossy().contains(".deciding");
        self.files.paths().iter().filter(|p| held(p)).count()
    }

    /// A process on this host, its effects through `cut`.
    fn through<T>(
        &self,
        cut: &Arc<CutPoint>,
        me: &dyn Processes,
        act: impl FnOnce(&Helper<'_>) -> T,
    ) -> T {
        let (files, runner) = (
            CutFiles(&self.files, cut.clone()),
            CutRunner(self, cut.clone()),
        );
        act(&helper(&runner, &files, &self.clock, me))
    }
}

/// The exit-code check the real runner makes (`Real::run`).
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
            ("nix-env", ["-p", _, "--set", system]) => self.set_profile(system)?,
            // systemd-run(1) `--on-active`: a transient timer.
            ("systemd-run", _) => {
                self.machine.borrow_mut().timer_active = true;
                Output::stdout("")
            }
            ("systemctl", ["stop", _]) => self.stop_timer(),
            ("systemctl", ["is-active", _]) => self.timer_state(),
            // switch-to-configuration `switch`: that system now runs.
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

/// The dead man: an armed timer elapses once (systemd.timer(5)) and runs
/// `revert --by-timer` with the unit's reason.
fn timer_fires(host: &Host, cut: &Arc<CutPoint>, me: &dyn Processes) -> Result<()> {
    let armed = std::mem::replace(&mut host.machine.borrow_mut().timer_active, false);
    if !armed {
        return Ok(());
    }
    let because = Some("nobody confirmed this activation before its deadline");
    host.through(cut, me, |helper| {
        helper.revert(ID, because, RevertAsker::Deadline).map(drop)
    })
}

/// A resumed run (`receipt::next_step`, `Executor::resume_point`): pending
/// or confirming is confirmed when the host runs what it should, and taken
/// back when it does not; anything else is `VerifyOnly`, `RolledBack` or a
/// person's.
fn resume(host: &Host, cut: &Arc<CutPoint>, me: &dyn Processes) -> Result<()> {
    let Some(record) = host.record() else {
        return Ok(());
    };
    let ready = host.machine.borrow().running == record.desired;
    host.through(cut, me, |helper| match record.state {
        TxnState::Pending | TxnState::Confirming if ready => helper.confirm(ID).map(drop),
        TxnState::Pending | TxnState::Confirming => helper
            .revert(ID, Some("not ready"), RevertAsker::Operator)
            .map(drop),
        _ => Ok(()),
    })
}

/// O0: a host moved off its previous system has a record, and an open record
/// on a moved host has an armed timer or a durable intent.
fn unguarded(host: &Host) -> Option<String> {
    let moved = host.profile().as_deref() != Some(PREV) || host.machine.borrow().running != PREV;
    let Some(record) = host.record() else {
        return moved.then(|| "the host moved and no record says so".to_string());
    };
    let unguarded = matches!(record.state, TxnState::Pending | TxnState::Staged)
        && !host.machine.borrow().timer_active;
    (moved && unguarded).then(|| format!("{} on a moved host with no timer", record.state_word()))
}

/// The one end each order of successors leaves on a host that runs what
/// it should: a resume confirms, and a timer that comes first takes back
/// what nobody had begun to confirm. A transaction left `confirming`,
/// `reverting` or `inconsistent` here is one a recovery could not finish.
fn the_end(by: ConfirmSuccessor, intent_persisted: bool) -> (TxnState, &'static str) {
    match by {
        ConfirmSuccessor::TimerFirst if !intent_persisted => (TxnState::Reverted, PREV),
        ConfirmSuccessor::TimerFirst | ConfirmSuccessor::ResumeFirst => (TxnState::Confirmed, TOP),
    }
}

/// I-A1 and I-A2 on the host `by` recovered.
fn judged(host: &Host, by: ConfirmSuccessor, intent_persisted: bool) -> Vec<Breach> {
    let Some(record) = host.record() else {
        return vec![Breach::of(Invariant::IA1, "the record is gone")];
    };
    let Machine {
        timer_active,
        running,
        ..
    } = host.machine.borrow().clone();
    let profile = host.profile().unwrap_or_default();
    let (end, system) = the_end(by, intent_persisted);
    let mut breaches = Vec::new();
    if record.state != end || running != system || profile != system {
        breaches.push(Breach::of(
            Invariant::IA1,
            format!(
                "{} with running {running}, profile {profile}, timer {timer_active}, where \
                 {by:?} ends {} on {system}",
                record.state_word(),
                end.as_str_lower()
            ),
        ));
    }
    if intent_persisted && record.state == TxnState::Reverted {
        breaches.push(Breach::of(
            Invariant::IA2,
            "reverted after confirming was persisted",
        ));
    }
    if !record.is_open() && timer_active {
        breaches.push(Breach::of(
            Invariant::IA2,
            format!("{} with its timer armed", record.state_word()),
        ));
    }
    breaches
}

/// `confirm` on a host waiting for it.
struct Confirm;

/// Who comes first after a crash in `confirm`: the timer, or a resume. Both
/// orders happen; the timer does not wait for the workstation.
#[derive(Debug, Clone, Copy)]
enum ConfirmSuccessor {
    TimerFirst,
    ResumeFirst,
}

impl Scenario for Confirm {
    type World = Host;
    /// A confirmation intent was on the disk.
    type Seen = bool;
    type Successor = ConfirmSuccessor;
    type Snapshot = Snapshot;

    fn world(&self) -> Host {
        Host::waiting_for_confirm()
    }

    fn run(&self, host: &Host, cut: &Arc<CutPoint>) -> Result<()> {
        host.through(cut, &FakeProcesses(DYING_PID), |helper| {
            helper.confirm(ID).map(drop)
        })
    }

    fn frozen(&self, host: &Host) -> (Vec<Breach>, bool) {
        let breaches = unguarded(host)
            .into_iter()
            .map(|detail| Breach::of(Invariant::O0, detail))
            .collect();
        let intent = host
            .record()
            .is_some_and(|r| matches!(r.state, TxnState::Confirming | TxnState::Confirmed));
        (breaches, intent)
    }

    fn successors(&self) -> Vec<ConfirmSuccessor> {
        vec![ConfirmSuccessor::TimerFirst, ConfirmSuccessor::ResumeFirst]
    }

    /// The host runs what it should, so a resume confirms, and the
    /// deadline's revert leaves an intent alone: no successor has a reason
    /// to fail.
    fn recover(
        &self,
        host: &Host,
        by: ConfirmSuccessor,
        cut: &Arc<CutPoint>,
        first_pid: u32,
    ) -> Vec<Breach> {
        let (first, second) = (FakeProcesses(first_pid), FakeProcesses(first_pid + 1));
        let answers = match by {
            ConfirmSuccessor::TimerFirst => [
                ("the timer", timer_fires(host, cut, &first)),
                ("the resume", resume(host, cut, &second)),
            ],
            ConfirmSuccessor::ResumeFirst => [
                ("the resume", resume(host, cut, &first)),
                ("the timer", timer_fires(host, cut, &second)),
            ],
        };
        answers
            .into_iter()
            .filter_map(|(who, answer)| {
                let e = answer.err()?;
                Some(Breach::of(Invariant::IA1, format!("{who} failed: {e:#}")))
            })
            .collect()
    }

    fn settled(&self, host: &Host, by: ConfirmSuccessor, intent_persisted: &bool) -> Vec<Breach> {
        judged(host, by, *intent_persisted)
    }

    fn snapshot(&self, host: &Host) -> Snapshot {
        host.snapshot()
    }
}

/// A resume finishes a confirmation wherever it died. The timer, first,
/// takes back only one whose intent was not on the disk yet: the cuts before
/// `confirming` is written.
#[test]
fn every_crash_in_confirm_is_finished_unless_the_timer_comes_before_its_intent() {
    assert_no_breach(&every_crash(&Confirm));
    // I-A4 counts, it does not fail: nothing removes the lock of a decision
    // that died after taking it.
    let n = trace_of(&Confirm).len();
    let left: Vec<usize> = (0..=n)
        .filter(|&k| {
            let host = crashed_at(&Confirm, k, n);
            // Its answers were judged above; here only what it leaves counts.
            let _ = Confirm.recover(&host, ConfirmSuccessor::TimerFirst, &CutPoint::new(), 2);
            host.lock_leftovers() > 0
        })
        .collect();
    eprintln!("confirm: {n} effects, I-A4 warning at cuts {left:?}");
}

#[test]
fn the_cut_trace_is_identical_twice() {
    let first = trace_of(&Confirm);
    assert!(!first.is_empty());
    assert_eq!(first, trace_of(&Confirm));
}

/// DCT-H1: the pid of a crashed holder, now an unrelated process's that
/// started later. Signal 0 says "running"; the start time says otherwise.
struct Recycled(u32);

impl Processes for Recycled {
    fn own_pid(&self) -> u32 {
        self.0
    }

    fn boot_id(&self) -> Option<String> {
        Some("boot-1".to_string())
    }

    fn state_of(&self, pid: u32) -> ProcessState {
        match pid {
            DYING_PID => ProcessState::Running { start: 99_999 },
            pid if pid == self.0 => started(pid),
            _ => ProcessState::Gone,
        }
    }
}

#[test]
fn a_recycled_pid_does_not_keep_a_dead_holders_lock() {
    // Confirm dies right after it took the lock, before it decided anything,
    // and its pid goes to another process: the deadline takes the lock over
    // and takes the machine back.
    let trace = trace_of(&Confirm);
    let lock = lock_path().display().to_string();
    let took_it = trace
        .iter()
        .find(|op| op.what == "create_new" && op.on == lock)
        .expect("confirm takes the decision lock");
    let host = crashed_at(&Confirm, took_it.ordinal + 1, trace.len());
    let held = host.files.content(lock_path()).expect("the lock is left");
    let holder = Holder::parse(&String::from_utf8_lossy(&held)).map(|h| h.pid);
    assert_eq!(
        holder,
        Some(DYING_PID),
        "the lock names the pid that is recycled"
    );

    timer_fires(&host, &CutPoint::new(), &Recycled(20)).expect("the deadline decides");
    resume(&host, &CutPoint::new(), &Recycled(21)).expect("a reverted record is left alone");
    assert_eq!(host.record().map(|r| r.state), Some(TxnState::Reverted));
    assert_eq!(
        judged(&host, ConfirmSuccessor::TimerFirst, false),
        Vec::new()
    );
}
