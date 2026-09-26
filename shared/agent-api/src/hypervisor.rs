// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::CgroupHandle;
use crate::DeviceAttachment;
use crate::NicAttachment;
use crate::VolumeAttachment;

pub type VmId = Uuid;

#[derive(Clone, Copy, PartialEq, Debug, Serialize, Deserialize)]
pub enum VmState {
    Defined,
    Running,
    Paused,
    Stopped,
}

#[derive(Debug, thiserror::Error)]
pub enum HypervisorError {
    #[error("vm not found: {0}")]
    NotFound(VmId),

    #[error("invalid state for {id}: is {current:?}")]
    InvalidState { id: VmId, current: VmState },

    #[error("invalid instance spec: {0}")]
    InvalidSpec(String),

    #[error("hypervisor backend failure: {0}")]
    Backend(anyhow::Error),
}

pub type Result<T> = std::result::Result<T, HypervisorError>;

/// A VMM attachment with a stable volume-derived disk ID for later unplug
/// and resize, independent of attachment ordering.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AttachedVolume {
    /// The volume's id: one this node minted for an inline disk, the `Volume`
    /// object's uid for a referenced one. Either way stable for as long as
    /// the bytes are.
    pub id: crate::VolumeId,
    pub attachment: VolumeAttachment,
}

impl AttachedVolume {
    /// What the VMM calls this volume's disk. See [`disk_id`].
    pub fn disk_id(&self) -> String {
        disk_id(&self.id)
    }
}

/// Derive a stable disk name from the volume ID for creation and later operations.
pub fn disk_id(volume: &crate::VolumeId) -> String {
    format!("disk-{volume}")
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InstanceSpec {
    pub boot: BootSource,
    /// Attachments in spec order; the first block volume is the boot disk.
    /// Filesystem shares appear here but are configured separately from VMM disks.
    pub volumes: Vec<AttachedVolume>,
    pub vcpus: u32,
    pub memory_mib: u64,
    pub nics: Vec<NicAttachment>,
    pub devices: Vec<DeviceAttachment>,
    /// Read-only NoCloud seed file created by the agent. Kept outside
    /// `volumes` because it has no storage-provider lifecycle. Defaults to None.
    #[serde(default)]
    pub cloud_init_seed: Option<std::path::PathBuf>,
}

#[async_trait::async_trait]
pub trait Pausable: Send + Sync {
    async fn pause(&self, id: &VmId) -> Result<()>;
    async fn resume(&self, id: &VmId) -> Result<()>;
}

// for later
#[async_trait::async_trait]
pub trait Snapshottable: Send + Sync {
    async fn snapshot(&self, id: &VmId, target: &str) -> Result<()>;
    async fn restore(&self, id: &VmId, source: &str) -> Result<()>;
}
/// Optional live-migration operations, exposed by `Hypervisor::as_migratable`.
///
/// Prepare the destination with `migrate_in` before starting `migrate_out`.
/// The transport address is opaque to the control plane; see [`migration_url`].
/// Once sending may have started, errors and timeouts leave ownership ambiguous.
/// The caller must resolve the attempt using durable source and destination
/// evidence before destructive cleanup.
#[async_trait::async_trait]
pub trait Migratable: Send + Sync {
    // Start sending this VM to the prepared destination.
    //
    // `Ok` acknowledges initiation, not completion. A destination Running report
    // alone is insufficient: completion requires matching attempt evidence from
    // both endpoints.
    async fn migrate_out(&self, id: &VmId, peer: &str) -> Result<()>;

    // Prepare a receiver and return its VMM PID once it is listening.
    //
    // Required taps and disks must already exist at the paths carried in the
    // transferred configuration. The agent records the PID for later probing.
    async fn migrate_in(&self, id: &VmId, peer: &str) -> Result<u32>;

    // Return a driver-reported receive failure, if known.
    //
    // `None` supplies no evidence: reception may be pending, complete or
    // unobservable. Callers must bind the report to the active attempt and
    // apply its ownership rules before cleanup. Called once per reconcile pass.
    fn receive_failed(&self, _id: &VmId) -> Option<String> {
        None
    }

    // Return a driver-reported send failure, if known.
    //
    // A successful `migrate_out` only starts the transfer. `None` means the
    // driver has no failure evidence; a caller timeout does not prove that
    // the guest stayed on the source or permit destination teardown.
    async fn send_failed(&self, _id: &VmId) -> Option<String> {
        None
    }
}

/// Format a Cloud Hypervisor migration address as `tcp:<addr>:<port>`.
/// Use no URL slashes and bracket IPv6 literals.
pub fn migration_url(addr: &str, port: u16) -> String {
    if addr.contains(':') && !addr.starts_with('[') {
        format!("tcp:[{addr}]:{port}")
    } else {
        format!("tcp:{addr}:{port}")
    }
}
/// Optional disk hotplug, exposed through `Hypervisor::as_hotpluggable`.
/// The agent applies eligible referenced-volume changes after the boot disk.
/// Without this capability, persisted changes take effect at the next start.
#[async_trait::async_trait]
pub trait HotPluggable: Send + Sync {
    /// Plug an already attached volume into the running VMM, naming it with
    /// `disk_id`. The path or backend socket must be ready before this call.
    async fn add_disk(&self, id: &VmId, volume: &AttachedVolume) -> Result<()>;

    /// Notify the guest of a disk increase after the storage backend has grown
    /// the bytes. For a block device, the VMM checks the existing size; a file
    /// backend may also call set_len. `size_bytes` must align to the sector size.
    /// The VMM handles any required brief vCPU pause.
    async fn resize_disk(&self, id: &VmId, disk_id: &str, size_bytes: u64) -> Result<()>;

    /// Unplug by stable disk ID. Guest cooperation may be required; callers
    /// must handle mounted filesystems and must not remove the immutable boot disk.
    async fn remove_disk(&self, id: &VmId, disk_id: &str) -> Result<()>;

    /// Plug an already prepared tap into a running VM. The network driver
    /// must configure its bridge, MTU and filtering first. Unsupported
    /// hypervisors return an error rather than acknowledge an absent NIC.
    async fn add_nic(&self, id: &VmId, nic: &NicAttachment) -> Result<()> {
        let _ = nic;
        Err(HypervisorError::Backend(anyhow::anyhow!(
            "this hypervisor cannot add a nic to vm {id} while it runs"
        )))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum BootSource {
    DirectKernel {
        kernel: std::path::PathBuf,
        cmdline: String,
        initramfs: Option<std::path::PathBuf>,
    },
    Firmware {
        firmware: std::path::PathBuf,
    },
}

/// Named guest and VMM output streams. Guest console and serial contents
/// depend on the configured firmware, boot arguments and guest drivers.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ConsoleStream {
    Console,
    Serial,
    /// VMM diagnostics, requested explicitly and excluded from default guest logs.
    Vmm,
}

impl ConsoleStream {
    /// What a caller gets without asking: the guest's own two. `Vmm` is
    /// deliberately absent — see the variant.
    pub const ALL: [ConsoleStream; 2] = [ConsoleStream::Console, ConsoleStream::Serial];

    pub fn as_str(self) -> &'static str {
        match self {
            ConsoleStream::Console => "console",
            ConsoleStream::Serial => "serial",
            ConsoleStream::Vmm => "vmm",
        }
    }

    /// Parse a supported stream name. Unknown names return None so callers
    /// can ignore unsupported filters.
    pub fn parse(name: &str) -> Option<Self> {
        match name {
            "console" => Some(ConsoleStream::Console),
            "serial" => Some(ConsoleStream::Serial),
            "vmm" => Some(ConsoleStream::Vmm),
            _ => None,
        }
    }
}

#[async_trait::async_trait]
pub trait Hypervisor: Send + Sync {
    async fn create(
        &self,
        id: &VmId,
        spec: &InstanceSpec,
        cgroup: Option<&CgroupHandle>,
    ) -> Result<u32>;
    async fn destroy(&self, id: &VmId) -> Result<()>;
    async fn start(&self, id: &VmId) -> Result<()>;
    async fn shutdown(&self, id: &VmId) -> Result<()>;
    async fn power_button(&self, id: &VmId) -> Result<()>;
    async fn get_state(&self, id: &VmId) -> Result<VmState>;

    /// Paths containing guest output. The agent reads and bounds these files.
    /// An empty list means no output paths; listed files may not exist yet.
    fn console_paths(&self, _id: &VmId) -> Vec<(ConsoleStream, std::path::PathBuf)> {
        Vec::new()
    }

    /// Driver diagnostic files, bounded by the agent and served separately
    /// from guest output when explicitly requested. Files may not exist yet.
    fn diagnostic_paths(&self, _id: &VmId) -> Vec<std::path::PathBuf> {
        Vec::new()
    }

    /// Interactive console socket. The agent records it and permits one
    /// interactive client at a time. None means attachment is unsupported.
    fn console_socket(&self, _id: &VmId) -> Option<std::path::PathBuf> {
        None
    }

    // Methods required by the reconcile
    async fn adopt(&self, id: &VmId, pid: u32) -> Result<()>;
    async fn probe(&self, id: &VmId) -> bool;
    fn is_tracked(&self, id: &VmId) -> bool;

    /// Check that a live PID still belongs to this VM before adopting or acting
    /// on it. PIDs can be reused. The default checks the VM UUID in the process
    /// command line; drivers whose launch command does not identify the VM must
    /// override it. This check is not an atomic process handle.
    fn owns_pid(&self, id: &VmId, pid: u32) -> bool {
        crate::pid::process_carries(pid, &id.to_string())
    }

    /// Enumerate locally running VMMs whose IDs are absent from `known`.
    ///
    /// Inspect the machine, not an in-memory map that is empty after restart.
    /// `known` includes IDs with corrupt records: inability to decode a record
    /// does not establish that its guest is orphaned. Drivers unable to identify
    /// unmanaged VMMs return an empty list, as the default does.
    async fn strays(&self, known: &[VmId]) -> Vec<VmId> {
        let _ = known;
        Vec::new()
    }

    /// End a VMM found by `strays` after the caller's grace period. Without
    /// a recorded PID, use its API socket rather than guessing a process
    /// to signal. Ordinary owned VMMs use `destroy`.
    async fn end_stray(&self, id: &VmId) -> Result<()> {
        let _ = id;
        Err(HypervisorError::Backend(anyhow::anyhow!(
            "this hypervisor cannot end a vmm it has no record of"
        )))
    }

    /// VMM version sampled at agent startup for migration compatibility.
    /// None means unavailable; compatibility checks cannot compare an empty
    /// version. The configured CPU profile is reported separately.
    async fn version(&self) -> Option<String> {
        None
    }

    /// Guest CPU profile used by migration compatibility checks. The current
    /// Host profile exposes host CPUID, so compatibility depends on the machines.
    fn cpu_profile(&self) -> &'static str {
        ""
    }

    // optional capabilities
    fn as_pausable(&self) -> Option<&dyn Pausable> {
        None
    }
    fn as_snapshottable(&self) -> Option<&dyn Snapshottable> {
        None
    }
    fn as_migratable(&self) -> Option<&dyn Migratable> {
        None
    }
    fn as_hotpluggable(&self) -> Option<&dyn HotPluggable> {
        None
    }
}
