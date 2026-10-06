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

use agent_api::device::{self, DeviceError, DeviceId};
use backend::Backend;

use crate::admission::Claim;

/// What the driver holds of a backend's process.
enum Process {
    /// Admitted and being spawned.
    Starting,
    Child(Backend),
}

struct Entry {
    process: Process,
    claim: Claim,
}

#[derive(Default)]
pub(crate) struct Ledger {
    entries: HashMap<DeviceId, Entry>,
}

impl Ledger {
    /// Hold `id`'s place while its backend is spawned. Refused while another
    /// start of the same device is under way.
    pub(crate) fn start(&mut self, id: &DeviceId, claim: Claim) -> device::Result<()> {
        if let Some(Entry {
            process: Process::Starting,
            ..
        }) = self.entries.get(id)
        {
            return Err(DeviceError::Backend(anyhow::anyhow!(
                "device {id} is already being started"
            )));
        }
        self.entries.insert(
            *id,
            Entry {
                process: Process::Starting,
                claim,
            },
        );
        Ok(())
    }

    /// Record that an admitted backend is up. Returns the child when its
    /// entry was forgotten during the spawn, so the caller stops it instead of
    /// leaving it running uncounted.
    #[must_use]
    pub(crate) fn started(&mut self, id: &DeviceId, child: Backend) -> Option<Backend> {
        match self.entries.get_mut(id) {
            Some(entry) => {
                entry.process = Process::Child(child);
                None
            }
            None => Some(child),
        }
    }

    /// Drop a device; its child, when this driver instance spawned it.
    pub(crate) fn forget(&mut self, id: &DeviceId) -> Option<Backend> {
        match self.entries.remove(id)?.process {
            Process::Child(child) => Some(child),
            Process::Starting => None,
        }
    }

    /// The pid of `id`'s backend if it can serve again. One that cannot is
    /// forgotten, so its replacement is started afresh.
    pub(crate) fn reusable(&mut self, id: &DeviceId, socket: &Path) -> device::Result<Option<u32>> {
        let Some(entry) = self.entries.get_mut(id) else {
            return Ok(None);
        };
        let pid = match &mut entry.process {
            Process::Starting => {
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
            Process::Starting => true,
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
        let mut ledger = Ledger::default();
        let starting = DeviceId::new_v4();
        ledger.start(&starting, claim(4096)).expect("held");
        assert_eq!(ledger.unrecorded(&HashSet::new()), vec![claim(4096)]);
        assert!(
            ledger.unrecorded(&HashSet::from([starting])).is_empty(),
            "the record counts it, so the ledger does not count it twice"
        );
    }

    /// A backend that failed to start gives its place back.
    #[test]
    fn a_forgotten_start_gives_its_place_back() {
        let mut ledger = Ledger::default();
        let failed = DeviceId::new_v4();
        ledger.start(&failed, claim(8192)).expect("held");
        assert!(ledger.forget(&failed).is_none(), "no child was spawned");
        assert!(ledger.unrecorded(&HashSet::new()).is_empty());
    }
}
