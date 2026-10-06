// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! The backends this driver instance started, and what each counts as.
//!
//! Admission does not rest on this ledger: it counts the devices of every VM
//! record in the agent's store, which survives a restart where this does not.
//! The ledger adds what the store cannot show yet or any more: a backend
//! being spawned, and a running child whose record is gone. Nothing is kept
//! on disk, so nothing in the backends' run directory, which the backend user
//! may write, can change what is admitted.

use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::{Mutex, MutexGuard, PoisonError};

use agent_api::device::{self, DeviceError, DeviceId};
use backend::Backend;

use crate::admission::Claim;

/// What the driver holds of a backend's process.
enum Process {
    /// Being spawned, under the token of the [`Reservation`] that holds it.
    Starting {
        token: u64,
    },
    Child(Backend),
}

struct Entry {
    process: Process,
    claim: Claim,
}

impl Entry {
    fn is_start(&self, token: u64) -> bool {
        matches!(self.process, Process::Starting { token: held } if held == token)
    }
}

#[derive(Default)]
pub(crate) struct Ledger {
    entries: HashMap<DeviceId, Entry>,
    /// Tells one start of a device from a later one, so a start that is
    /// given up removes its own entry and never its successor's.
    last_token: u64,
}

/// The ledger behind its lock. No update panics halfway, so a ledger whose
/// lock was poisoned is still consistent and stays usable.
pub(crate) fn lock(ledger: &Mutex<Ledger>) -> MutexGuard<'_, Ledger> {
    ledger.lock().unwrap_or_else(PoisonError::into_inner)
}

/// A start's place on the ledger while its backend is spawned. Dropped
/// without [`Reservation::commit`], because the spawn failed or because the
/// future that creates the device was cancelled mid-spawn, it gives the place
/// back, so neither a phantom claim nor "already being started" outlives it.
pub(crate) struct Reservation<'a> {
    ledger: &'a Mutex<Ledger>,
    id: DeviceId,
    token: u64,
}

impl<'a> Reservation<'a> {
    /// Hold `id`'s place. Refused while another start of it is under way.
    pub(crate) fn hold(
        ledger: &'a Mutex<Ledger>,
        id: &DeviceId,
        claim: Claim,
    ) -> device::Result<Self> {
        let token = lock(ledger).start(id, claim)?;
        Ok(Self {
            ledger,
            id: *id,
            token,
        })
    }

    /// The backend is up and its entry becomes the child's. Returns the child
    /// when the device was destroyed during the spawn, so the caller stops it
    /// instead of leaving it running uncounted.
    #[must_use]
    pub(crate) fn commit(self, child: Backend) -> Option<Backend> {
        let unclaimed = lock(self.ledger).started(&self.id, self.token, child);
        std::mem::forget(self);
        unclaimed
    }
}

impl Drop for Reservation<'_> {
    fn drop(&mut self) {
        lock(self.ledger).abandon(&self.id, self.token);
    }
}

impl Ledger {
    fn start(&mut self, id: &DeviceId, claim: Claim) -> device::Result<u64> {
        if let Some(Entry {
            process: Process::Starting { .. },
            ..
        }) = self.entries.get(id)
        {
            return Err(DeviceError::Backend(anyhow::anyhow!(
                "device {id} is already being started"
            )));
        }
        self.last_token += 1;
        let token = self.last_token;
        self.entries.insert(
            *id,
            Entry {
                process: Process::Starting { token },
                claim,
            },
        );
        Ok(token)
    }

    fn started(&mut self, id: &DeviceId, token: u64, child: Backend) -> Option<Backend> {
        match self.entries.get_mut(id) {
            Some(entry) if entry.is_start(token) => {
                entry.process = Process::Child(child);
                None
            }
            _ => Some(child),
        }
    }

    fn abandon(&mut self, id: &DeviceId, token: u64) {
        if self
            .entries
            .get(id)
            .is_some_and(|entry| entry.is_start(token))
        {
            self.entries.remove(id);
        }
    }

    /// Drop a device; its child, when this driver instance spawned it.
    pub(crate) fn forget(&mut self, id: &DeviceId) -> Option<Backend> {
        match self.entries.remove(id)?.process {
            Process::Child(child) => Some(child),
            Process::Starting { .. } => None,
        }
    }

    /// The pid of `id`'s backend if it can serve again. One that cannot is
    /// forgotten, so its replacement is started afresh.
    pub(crate) fn reusable(&mut self, id: &DeviceId, socket: &Path) -> device::Result<Option<u32>> {
        let Some(entry) = self.entries.get_mut(id) else {
            return Ok(None);
        };
        let pid = match &mut entry.process {
            Process::Starting { .. } => {
                return Err(DeviceError::Backend(anyhow::anyhow!(
                    "device {id} is already being started"
                )));
            }
            Process::Child(child) => child.is_reusable(socket).then(|| child.pid().unwrap_or(0)),
        };
        if pid.is_none() {
            self.entries.remove(id);
        }
        Ok(pid)
    }

    /// What this driver started for devices no record in `recorded` names:
    /// starts under way and children still running. A child that has exited
    /// holds nothing and is dropped.
    pub(crate) fn unrecorded(&mut self, recorded: &HashSet<DeviceId>) -> Vec<Claim> {
        self.entries.retain(|_, entry| match &mut entry.process {
            Process::Starting { .. } => true,
            Process::Child(child) => child.is_running(),
        });
        self.entries
            .iter()
            .filter(|(id, _)| !recorded.contains(id))
            .map(|(_, entry)| entry.claim.clone())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn claim(mib: u64) -> Claim {
        Claim::new(mib, None)
    }

    /// A start under way counts for an admission that cannot see its record.
    #[test]
    fn a_start_under_way_counts_until_its_record_is_seen() {
        let ledger = Mutex::new(Ledger::default());
        let starting = DeviceId::new_v4();
        let _held = Reservation::hold(&ledger, &starting, claim(4096)).expect("held");
        assert_eq!(lock(&ledger).unrecorded(&HashSet::new()), vec![claim(4096)]);
        assert!(
            lock(&ledger)
                .unrecorded(&HashSet::from([starting]))
                .is_empty(),
            "the record counts it, so the ledger does not count it twice"
        );
    }

    /// A start that is given up gives its place back.
    #[test]
    fn a_start_given_up_gives_its_place_back() {
        let ledger = Mutex::new(Ledger::default());
        let failed = DeviceId::new_v4();
        drop(Reservation::hold(&ledger, &failed, claim(8192)).expect("held"));
        assert!(lock(&ledger).unrecorded(&HashSet::new()).is_empty());
        Reservation::hold(&ledger, &failed, claim(8192)).expect("and can start again");
    }

    /// A second start of a device whose first is under way is refused.
    #[test]
    fn a_device_is_started_once_at_a_time() {
        let ledger = Mutex::new(Ledger::default());
        let id = DeviceId::new_v4();
        let _first = Reservation::hold(&ledger, &id, claim(1024)).expect("held");
        let said = Reservation::hold(&ledger, &id, claim(1024))
            .err()
            .expect("the first is still starting")
            .to_string();
        assert!(said.contains("already being started"), "{said}");
    }

    /// A start destroyed and begun again: the first one, given up late,
    /// does not take the second one's place with it.
    #[test]
    fn a_start_given_up_late_leaves_its_successor_alone() {
        let ledger = Mutex::new(Ledger::default());
        let id = DeviceId::new_v4();
        let first = Reservation::hold(&ledger, &id, claim(1024)).expect("held");
        assert!(lock(&ledger).forget(&id).is_none(), "destroyed mid-spawn");
        let _second = Reservation::hold(&ledger, &id, claim(2048)).expect("started again");
        drop(first);
        assert_eq!(lock(&ledger).unrecorded(&HashSet::new()), vec![claim(2048)]);
    }
}
