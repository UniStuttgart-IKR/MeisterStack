// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! The driver's admission ledger: every backend it knows of and what each
//! counts as on the card, including backends that outlived an agent restart.
//!
//! When a backend is up, the driver writes `<id>.claim` beside its socket:
//! the pid and the claim it was admitted as. A new driver instance reads those
//! back before it can admit anything, so guests that kept running count again.
//! A socket whose claim cannot be read stands for a backend whose share of the
//! card is unknown, and nothing is admitted beside it.

use std::collections::{BTreeSet, HashMap};
use std::path::{Path, PathBuf};

use agent_api::device::{self, DeviceError, DeviceId};
use backend::Backend;

use crate::{
    Claim, VgpuType, refuse_budget_overrun, refuse_card_overcommit, refuse_instance_overflow,
};

const SOCKET: &str = "sock";
const CLAIM: &str = "claim";

/// `<run_dir>/<id>.<extension>`: every file the driver keeps for a device.
pub(crate) fn device_file(run_dir: &Path, id: &DeviceId, extension: &str) -> PathBuf {
    run_dir.join(format!("{id}.{extension}"))
}

pub(crate) fn socket_file(run_dir: &Path, id: &DeviceId) -> PathBuf {
    device_file(run_dir, id, SOCKET)
}

pub(crate) fn claim_file(run_dir: &Path, id: &DeviceId) -> PathBuf {
    device_file(run_dir, id, CLAIM)
}

/// What the driver holds of a backend's process.
enum Process {
    /// Admitted, its backend being spawned. The entry keeps the claim across
    /// the spawn so an admission meanwhile counts it.
    Starting,
    Child(Backend),
    /// Outlived an agent restart. `None` when its claim, and so its pid,
    /// could not be read.
    Adopted {
        pid: Option<u32>,
    },
}

/// What a backend counts as on the card.
#[derive(Clone, Debug, PartialEq)]
enum Account {
    Counted(Claim),
    Unknown { why: String },
}

struct Entry {
    process: Process,
    account: Account,
}

/// The content of a claim file.
#[derive(serde::Serialize, serde::Deserialize)]
struct Recorded {
    pid: u32,
    claim: Claim,
}

#[derive(Default)]
pub(crate) struct Ledger {
    entries: HashMap<DeviceId, Entry>,
}

impl Ledger {
    /// Read back what the backends in `run_dir` were admitted as. `alive`
    /// says whether a pid is still the backend of that socket; a claim whose
    /// backend is gone counts nothing.
    pub(crate) fn recovered(
        run_dir: &Path,
        alive: impl Fn(u32, &Path) -> bool,
    ) -> std::io::Result<Self> {
        let mut ledger = Self::default();
        for id in device_ids(run_dir)? {
            if let Some(entry) = survivor(run_dir, &id, &alive) {
                ledger.entries.insert(id, entry);
            }
        }
        Ok(ledger)
    }

    /// Admit `want` against everything on the card and hold its place until
    /// the backend is up, in one critical section, so that a second admission
    /// during the spawn sees it.
    pub(crate) fn admit(
        &mut self,
        id: &DeviceId,
        want: &Claim,
        vgpu: Option<&VgpuType>,
        budget: Option<u64>,
    ) -> device::Result<()> {
        self.refuse_beside_unknown(id)?;
        let live: Vec<&Claim> = self.counted().collect();
        refuse_instance_overflow(&live, vgpu)?;
        refuse_card_overcommit(&live, want, id)?;
        refuse_budget_overrun(&live, want, budget, id)?;
        self.entries.insert(
            *id,
            Entry {
                process: Process::Starting,
                account: Account::Counted(want.clone()),
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
            Process::Starting | Process::Adopted { .. } => None,
        }
    }

    /// The pid of `id`'s backend if it can serve again. One that cannot is
    /// forgotten, so its replacement is admitted afresh.
    pub(crate) fn reusable(
        &mut self,
        id: &DeviceId,
        socket: &Path,
        alive: impl Fn(u32, &Path) -> bool,
    ) -> device::Result<Option<u32>> {
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
            Process::Adopted { pid } => pid.filter(|pid| alive(*pid, socket)),
        };
        if pid.is_none() {
            self.entries.remove(id);
        }
        Ok(pid)
    }

    fn counted(&self) -> impl Iterator<Item = &Claim> {
        self.entries.values().filter_map(|e| match &e.account {
            Account::Counted(claim) => Some(claim),
            Account::Unknown { .. } => None,
        })
    }

    /// Refuse while a backend whose share of the card is unknown is running:
    /// counting it as nothing could overbook the card.
    fn refuse_beside_unknown(&self, id: &DeviceId) -> device::Result<()> {
        for (other, entry) in &self.entries {
            if let Account::Unknown { why } = &entry.account {
                return Err(DeviceError::InvalidSpec(format!(
                    "device {other} outlived an agent restart and what it holds on the card \
                     is unknown ({why}); nothing is admitted beside it (device {id}) until \
                     its vm is stopped or destroyed"
                )));
            }
        }
        Ok(())
    }
}

/// Write the claim file of a backend that is up. Written aside and renamed,
/// so a later driver instance reads the whole claim or none.
pub(crate) fn record(
    run_dir: &Path,
    id: &DeviceId,
    pid: u32,
    claim: &Claim,
) -> std::io::Result<()> {
    let recorded = Recorded {
        pid,
        claim: claim.clone(),
    };
    let aside = device_file(run_dir, id, "claim.tmp");
    std::fs::write(&aside, serde_json::to_vec(&recorded)?)?;
    std::fs::rename(&aside, claim_file(run_dir, id))
}

/// Devices with a socket or a claim file in `run_dir`.
fn device_ids(run_dir: &Path) -> std::io::Result<BTreeSet<DeviceId>> {
    let mut ids = BTreeSet::new();
    for entry in std::fs::read_dir(run_dir)? {
        let path = entry?.path();
        let kept = matches!(
            path.extension().and_then(|e| e.to_str()),
            Some(SOCKET | CLAIM)
        );
        let id = path
            .file_stem()
            .and_then(|stem| stem.to_str())
            .and_then(|stem| stem.parse::<DeviceId>().ok());
        if let (true, Some(id)) = (kept, id) {
            ids.insert(id);
        }
    }
    Ok(ids)
}

/// The entry for a device found in `run_dir`, or `None` when its backend is gone.
fn survivor(run_dir: &Path, id: &DeviceId, alive: &impl Fn(u32, &Path) -> bool) -> Option<Entry> {
    let socket = socket_file(run_dir, id);
    match read_recorded(&claim_file(run_dir, id)) {
        Ok(Some(recorded)) => alive(recorded.pid, &socket).then(|| Entry {
            process: Process::Adopted {
                pid: Some(recorded.pid),
            },
            account: Account::Counted(recorded.claim),
        }),
        Ok(None) => socket.exists().then(|| {
            unknown(format!(
                "{} has no claim recorded beside it",
                socket.display()
            ))
        }),
        Err(why) => Some(unknown(why)),
    }
}

fn unknown(why: String) -> Entry {
    Entry {
        process: Process::Adopted { pid: None },
        account: Account::Unknown { why },
    }
}

/// The claim file's content, `None` when there is none.
fn read_recorded(path: &Path) -> Result<Option<Recorded>, String> {
    match std::fs::read(path) {
        Ok(bytes) => serde_json::from_slice(&bytes)
            .map(Some)
            .map_err(|e| format!("{}: {e}", path.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(format!("{}: {e}", path.display())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CARD_MIB: u64 = 8192;

    fn claim(mib: u64, vgpu_type: &str) -> Claim {
        Claim {
            mib,
            vgpu_type: Some(vgpu_type.into()),
            card_mib: Some(CARD_MIB),
        }
    }

    fn vgpu(vgpu_type: &str, profile_mib: u64, max_instance: u64) -> VgpuType {
        VgpuType {
            vgpu_type: vgpu_type.into(),
            profile_mib,
            fb_mib: profile_mib - 512,
            max_instance,
            encoder_cap: 50,
            available_mib: CARD_MIB,
        }
    }

    fn run_dir() -> tempfile::TempDir {
        tempfile::Builder::new()
            .prefix("meister-nvrm-ledger-")
            .tempdir()
            .expect("a temp dir")
    }

    /// A socket file as a running backend leaves it; the scan reads names only.
    fn socket(dir: &Path, id: &DeviceId) {
        std::fs::write(socket_file(dir, id), b"").expect("a socket stand-in");
    }

    const SURVIVOR_PID: u32 = 4242;

    fn survivor_alive(pid: u32, _: &Path) -> bool {
        pid == SURVIVOR_PID
    }

    /// IKR-B30: a guest that kept running through an agent restart counts
    /// again before the new driver admits anything, so the card is not
    /// handed out twice.
    #[test]
    fn a_restarted_driver_counts_the_backends_that_kept_running() {
        let dir = run_dir();
        let running = DeviceId::new_v4();
        socket(dir.path(), &running);
        record(
            dir.path(),
            &running,
            SURVIVOR_PID,
            &claim(8192, "RTX2070-8Q"),
        )
        .expect("written");

        let mut ledger = Ledger::recovered(dir.path(), survivor_alive).expect("read back");
        let said = ledger
            .admit(&DeviceId::new_v4(), &claim(1024, "RTX2070-1Q"), None, None)
            .expect_err("the survivor fills the card")
            .to_string();
        assert!(said.contains("8192 MiB admitted"), "{said}");
    }

    /// A claim whose backend is gone holds nothing on the card.
    #[test]
    fn a_claim_whose_backend_is_gone_counts_nothing() {
        let dir = run_dir();
        let gone = DeviceId::new_v4();
        record(
            dir.path(),
            &gone,
            SURVIVOR_PID + 1,
            &claim(8192, "RTX2070-8Q"),
        )
        .expect("written");

        let mut ledger = Ledger::recovered(dir.path(), survivor_alive).expect("read back");
        ledger
            .admit(&DeviceId::new_v4(), &claim(8192, "RTX2070-8Q"), None, None)
            .expect("the card is free");
    }

    /// A surviving socket with no readable claim is a backend of unknown
    /// size; nothing is admitted beside it rather than counting it as zero.
    #[test]
    fn a_surviving_backend_of_unknown_size_blocks_admission() {
        let dir = run_dir();
        let unrecorded = DeviceId::new_v4();
        socket(dir.path(), &unrecorded);

        let mut ledger = Ledger::recovered(dir.path(), survivor_alive).expect("read back");
        let said = ledger
            .admit(&DeviceId::new_v4(), &claim(1024, "RTX2070-1Q"), None, None)
            .expect_err("unknown is not zero")
            .to_string();
        assert!(said.contains(&unrecorded.to_string()), "{said}");
        assert!(said.contains("no claim recorded"), "{said}");
    }

    /// An admitted backend counts while it is still being spawned, so the
    /// window between admission and a running backend admits nothing twice.
    #[test]
    fn an_admitted_backend_holds_its_place_while_it_starts() {
        let mut ledger = Ledger::default();
        let one_8q = vgpu("RTX2070-8Q", 8192, 1);
        ledger
            .admit(
                &DeviceId::new_v4(),
                &claim(8192, "RTX2070-8Q"),
                Some(&one_8q),
                None,
            )
            .expect("the first 8Q");
        ledger
            .admit(
                &DeviceId::new_v4(),
                &claim(8192, "RTX2070-8Q"),
                Some(&one_8q),
                None,
            )
            .expect_err("the first one is still starting, and counts");
    }

    /// A backend that failed to start gives its place back.
    #[test]
    fn a_forgotten_admission_gives_its_place_back() {
        let mut ledger = Ledger::default();
        let failed = DeviceId::new_v4();
        ledger
            .admit(&failed, &claim(8192, "RTX2070-8Q"), None, None)
            .expect("admitted");
        assert!(ledger.forget(&failed).is_none(), "no child was spawned");
        ledger
            .admit(&DeviceId::new_v4(), &claim(8192, "RTX2070-8Q"), None, None)
            .expect("the card is free again");
    }
}
