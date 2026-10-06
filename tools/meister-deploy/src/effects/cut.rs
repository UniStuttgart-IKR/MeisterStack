// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Deterministic crash points behind the `Files` and `Runner` seams (test only).
//!
//! A [`CutPoint`] numbers the mutating effects a run attempts, from 0 when it
//! is made or armed. Armed at `k`, effects `0..k` land, effect `k` is
//! where the process dies, and every later effect is refused: a dead process
//! makes no more changes. Reads pass through, because reading changes nothing a
//! successor could find. This is Floppy's cut (floppy-disk `dev.rs:126-139`)
//! moved from block writes to file and command effects. Unlike Floppy, labels
//! are not taken from a thread-local: the method or program is the label.
//!
//! An effect that lands and whose caller dies before it hears so needs no
//! mode of its own: under freeze-after semantics it leaves the world the cut
//! at `k + 1` leaves, which the spike checked for every cut of `confirm`.

use std::path::Path;
use std::sync::{Arc, Mutex, MutexGuard};

use anyhow::Result;

use crate::effects::{Entry, Files};
use crate::run::{Cmd, Effect, Output, Policy, Runner};

/// One mutating effect, as the trace records it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Op {
    pub ordinal: usize,
    /// The `Files` method, or the program.
    pub what: String,
    /// The path, or the arguments.
    pub on: String,
}

/// The error every effect from the cut on answers with.
#[derive(Debug)]
pub struct Crashed(pub usize);

impl std::fmt::Display for Crashed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "this process crashed at mutating effect {}", self.0)
    }
}

impl std::error::Error for Crashed {}

#[derive(Debug)]
struct State {
    ops: usize,
    at: Option<usize>,
    frozen: Option<Op>,
    trace: Vec<Op>,
}

/// Shared by every decorator of one simulated process. `Arc` and `Mutex`
/// rather than `Rc` and `RefCell`, so a decorator stays `Sync` for callers
/// that require it.
#[derive(Debug)]
pub struct CutPoint {
    state: Mutex<State>,
}

impl CutPoint {
    /// A cut that is not armed: every effect lands and is traced.
    pub fn new() -> Arc<CutPoint> {
        Arc::new(CutPoint {
            state: Mutex::new(State {
                ops: 0,
                at: None,
                frozen: None,
                trace: Vec::new(),
            }),
        })
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Crash at the `k`-th mutating effect from now. Clears the trace.
    pub fn arm_after(&self, k: usize) {
        let mut st = self.lock();
        st.ops = 0;
        st.at = Some(k);
        st.frozen = None;
        st.trace.clear();
    }

    /// The effect the process died at, if the run reached it.
    pub fn frozen_at(&self) -> Option<Op> {
        self.lock().frozen.clone()
    }

    /// The effects that landed since it was made or armed.
    pub fn trace(&self) -> Vec<Op> {
        self.lock().trace.clone()
    }

    /// `Err` with the ordinal the process died at, for this effect and
    /// every one after it.
    fn admit(&self, what: &str, on: String) -> Result<(), usize> {
        let mut st = self.lock();
        if let Some(frozen) = &st.frozen {
            return Err(frozen.ordinal);
        }
        let op = Op {
            ordinal: st.ops,
            what: what.to_string(),
            on,
        };
        st.ops += 1;
        if st.at == Some(op.ordinal) {
            st.frozen = Some(op.clone());
            return Err(op.ordinal);
        }
        st.trace.push(op);
        Ok(())
    }

    /// Run one mutating effect through the cut.
    fn effect<T>(&self, what: &str, on: String, land: impl FnOnce() -> Result<T>) -> Result<T> {
        match self.admit(what, on) {
            Ok(()) => land(),
            Err(at) => Err(Crashed(at).into()),
        }
    }
}

fn shown(path: &Path) -> String {
    path.display().to_string()
}

/// `Files` with its eight mutating methods counted; reads pass through.
pub struct CutFiles<'a>(pub &'a dyn Files, pub Arc<CutPoint>);

impl Files for CutFiles<'_> {
    fn read(&self, path: &Path) -> Result<Vec<u8>> {
        self.0.read(path)
    }

    fn read_to_string(&self, path: &Path) -> Result<String> {
        self.0.read_to_string(path)
    }

    fn exists(&self, path: &Path) -> bool {
        self.0.exists(path)
    }

    fn read_if_present(&self, path: &Path) -> Result<Option<String>> {
        self.0.read_if_present(path)
    }

    fn entry(&self, path: &Path) -> Result<Entry> {
        self.0.entry(path)
    }

    fn is_present(&self, path: &Path) -> bool {
        self.0.is_present(path)
    }

    fn list_dir(&self, path: &Path) -> Result<Vec<std::path::PathBuf>> {
        self.0.list_dir(path)
    }

    fn write_atomic(&self, path: &Path, bytes: &[u8], mode: u32) -> Result<()> {
        let land = || self.0.write_atomic(path, bytes, mode);
        self.1.effect("write_atomic", shown(path), land)
    }

    fn create_dir_all(&self, path: &Path) -> Result<()> {
        self.1.effect("create_dir_all", shown(path), || {
            self.0.create_dir_all(path)
        })
    }

    fn symlink_atomic(&self, target: &Path, link: &Path) -> Result<()> {
        let land = || self.0.symlink_atomic(target, link);
        self.1.effect("symlink_atomic", shown(link), land)
    }

    fn append_fsync(&self, path: &Path, line: &str) -> Result<()> {
        let land = || self.0.append_fsync(path, line);
        self.1.effect("append_fsync", shown(path), land)
    }

    fn create_new(&self, path: &Path, bytes: &[u8], mode: u32) -> Result<()> {
        let land = || self.0.create_new(path, bytes, mode);
        self.1.effect("create_new", shown(path), land)
    }

    fn remove_file(&self, path: &Path) -> Result<()> {
        self.1
            .effect("remove_file", shown(path), || self.0.remove_file(path))
    }

    fn remove_dir(&self, path: &Path) -> Result<()> {
        self.1
            .effect("remove_dir", shown(path), || self.0.remove_dir(path))
    }

    fn rename(&self, from: &Path, to: &Path) -> Result<()> {
        let on = format!("{} -> {}", shown(from), shown(to));
        self.1.effect("rename", on, || self.0.rename(from, to))
    }
}

/// `Runner` with every command that changes something counted (run.rs:26-43).
pub struct CutRunner<'a>(pub &'a dyn Runner, pub Arc<CutPoint>);

fn mutates(effect: Effect) -> bool {
    matches!(
        effect,
        Effect::TargetWrite | Effect::Key | Effect::LocalWrite
    )
}

impl Runner for CutRunner<'_> {
    fn run(&self, cmd: &Cmd) -> Result<Output> {
        if !mutates(cmd.effect) {
            return self.0.run(cmd);
        }
        self.1
            .effect(&cmd.program, cmd.args.join(" "), || self.0.run(cmd))
    }

    fn policy(&self) -> Policy {
        self.0.policy()
    }
}
