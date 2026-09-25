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

/// One volume the VMM is handed, and the name it will answer to afterwards.
///
/// The id beside the attachment, and the reason is hot-plug: `vm.remove-device`
/// and `vm.resize-disk` address a disk BY NAME, so a disk that may be spoken
/// about after boot needs a name that was decided before it. The name a VMM
/// picks for itself is positional — cloud-hypervisor counts `_disk0`,
/// `_disk1`, … — and a positional name moves under a detach and then names
/// the wrong disk.
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

/// The name a VMM knows a volume's disk by, derived from the volume id.
///
/// A free function and not a method so that the two sides can agree without
/// holding the same value: the driver writes it into the config at create,
/// and the agent speaks it back months later to unplug or grow that disk.
/// Derived and never allocated, for the reason every other name in the
/// storage path is: a name that has to be remembered is a name that can be
/// lost.
pub fn disk_id(volume: &crate::VolumeId) -> String {
    format!("disk-{volume}")
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InstanceSpec {
    pub boot: BootSource,
    /// In spec order; the first block volume is the boot disk. Attachments
    /// rather than paths since volumes learned to be served by a backend
    /// process — and not `disks`, because a `FsShare` in this list is a
    /// filesystem export and never appears among the VMM's disks.
    pub volumes: Vec<AttachedVolume>,
    pub vcpus: u32,
    pub memory_mib: u64,
    pub nics: Vec<NicAttachment>,
    pub devices: Vec<DeviceAttachment>,
    /// A second, read-only disk holding the cloud-init NoCloud seed.
    ///
    /// Beside `volumes` rather than inside it, and that is the point: a
    /// volume is something a storage driver made and will unmake, with a
    /// lifecycle and an attachment kind. This is a file the agent wrote out
    /// of the spec, it is always a plain path, and it is always read-only —
    /// putting it in the list would make all three of those a special case
    /// every storage driver had to know about.
    ///
    /// `None` is every VM this stack has booted so far, and its config comes
    /// out byte for byte the same.
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

/// The address form a migration stream is named by: `tcp:<addr>:<port>`.
///
/// One function because two machines have to agree on it without sharing
/// anything but the string, and because it is easy to get wrong in a way that
/// fails late: cloud-hypervisor parses it with `strip_prefix("tcp:")`, so
/// `tcp://` is not a URL with a redundant slash — it is a host called `` with
/// a port of `/1.2.3.4:9000`, and it is refused. An IPv6 literal has to be
/// bracketed, for the same reason it is everywhere else: the parser splits on
/// the LAST colon.
pub fn migration_url(addr: &str, port: u16) -> String {
    if addr.contains(':') && !addr.starts_with('[') {
        format!("tcp:[{addr}]:{port}")
    } else {
        format!("tcp:{addr}:{port}")
    }
}
/// Adding and removing a disk while the guest is running.
///
/// Disks only, and the narrowing is the honest part: NICs and passthrough
/// devices are plugged by other verbs with other rules (a NIC needs a tap
/// first, a VFIO device needs an IOMMU group free), and one trait pretending
/// to cover all three would have three methods nobody could implement
/// together. This one exists because `spec.vm.volumes[]` became mutable from
/// its second entry on, and that edit has to reach a running guest.
///
/// Optional, through `Hypervisor::as_hotpluggable`: a VMM that cannot do it
/// says so by returning `None`, and the agent then writes the record and lets
/// the next start pick the disk up from the spec.
#[async_trait::async_trait]
pub trait HotPluggable: Send + Sync {
    /// Plug a volume into a running VM. The disk is named [`disk_id`] of the
    /// volume afterwards, which is what `remove_disk` will speak back.
    ///
    /// The volume is already attached — a path exists, or a backend process
    /// is listening — because attaching is the storage driver's half and
    /// happened before this call. What this does is tell the VMM.
    async fn add_disk(&self, id: &VmId, volume: &AttachedVolume) -> Result<()>;

    /// Notify the guest of a disk increase after the storage backend has grown
    /// the bytes. For a block device, the VMM checks the existing size; a file
    /// backend may also call set_len. `size_bytes` must align to the sector size.
    /// The VMM handles any required brief vCPU pause.
    async fn resize_disk(&self, id: &VmId, disk_id: &str, size_bytes: u64) -> Result<()>;

    /// Unplug a disk by the name `add_disk` gave it.
    ///
    /// The guest has to cooperate: a disk it has mounted does not go away
    /// because somebody asked. That is the guest's business and not this
    /// stack's, exactly as it is with EBS — the one disk a guest can never be
    /// asked about is the boot disk, and that entry is immutable.
    async fn remove_disk(&self, id: &VmId, disk_id: &str) -> Result<()>;

    /// Plug a NIC into a running VM, on a tap that already exists.
    ///
    /// The tap is the network driver's half and happened before this call —
    /// it is in its bridge, it is UP, it carries its MTU and its guard chain
    /// is in place — exactly as a volume is attached before `add_disk` tells
    /// the VMM. What this does is tell the VMM.
    ///
    /// A default, and the default is a refusal in words, for the reason
    /// `NicDriver`'s overlay methods have one: a hypervisor that cannot plug
    /// a NIC into a live guest must SAY so, because the alternative — a
    /// successful call that does nothing — is a record claiming a NIC and a
    /// guest that never sees one.
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

/// The two one-way streams a guest writes before anything inside it is
/// reachable. Named separately because they are separately useful: a
/// direct-kernel boot puts the kernel on `console`, firmware and a bootloader
/// put their prompts on `serial`, and "the VM printed nothing" means
/// different things depending on which of the two is empty.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ConsoleStream {
    Console,
    Serial,
    /// What the VMM said about the guest, rather than what the guest said.
    ///
    /// The driver's own diagnostics — `diagnostic_paths`, cloud-hypervisor's
    /// stdout and stderr. It is NOT part of the default answer, and that is
    /// the whole reason it can exist here at all: the note on
    /// `diagnostic_paths` refuses to fold these into the console because it
    /// would "put hypervisor noise in front of somebody reading their guest's
    /// boot", and that stays true. Asked for by name it is the opposite —
    /// when a VM will not start, the reason is in here and nowhere a client
    /// could reach, and the answer today is to go and look on the node.
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

    /// The stream a client named, or `None` for a word this node does not
    /// serve. Unknown is not an error at the edges: a client built against a
    /// newer node asking for a stream this one has never heard of should get
    /// the streams it CAN have, not a refusal.
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

    /// Where this VM's one-way output is kept, if this hypervisor keeps it
    /// anywhere.
    ///
    /// The agent bounds and reads those files (`crate::console` one crate
    /// over is not a thing — it is `meister_agent::console`); the driver only
    /// says where they are, because only the driver decided. An empty list is
    /// the honest answer for a hypervisor that writes none, and it makes
    /// "this VM has no output" a fact rather than an error.
    ///
    /// A path here does not promise the file exists: a VM that has been
    /// created but never started has none yet.
    fn console_paths(&self, _id: &VmId) -> Vec<(ConsoleStream, std::path::PathBuf)> {
        Vec::new()
    }

    /// Files the driver writes that must be BOUNDED but are never served.
    ///
    /// Deliberately separate from `console_paths` rather than folded into it,
    /// because the two answer different questions. `console_paths` is the
    /// guest's output and `vm logs` serves it; this is the driver's own
    /// diagnostics — a VMM's stdout and stderr — and mixing the two into one
    /// answer would put hypervisor noise in front of somebody reading their
    /// guest's boot.
    ///
    /// They still need the ring: unbounded is unbounded whoever wrote it, and
    /// a VMM that logs on every guest write fills the same disk.
    ///
    /// A path here does not promise the file exists.
    fn diagnostic_paths(&self, _id: &VmId) -> Vec<std::path::PathBuf> {
        Vec::new()
    }

    /// Where the guest's INTERACTIVE line listens, if this hypervisor offers
    /// one.
    ///
    /// A separate question from `console_paths`, and the separation is the
    /// whole design: those are files, and a file has no input path. This is a
    /// socket, and the agent both records from it — into the very file
    /// `console_paths` names for `serial` — and lends it out to at most one
    /// client at a time. See the agent's `attach` module.
    ///
    /// `None` is a hypervisor with no interactive console, and every caller
    /// treats that as "this VM cannot be attached to" rather than as an
    /// error: a driver that cannot do it should not have to pretend.
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

    /// End a VMM this agent has no record of, and everything it left behind.
    ///
    /// Beside `destroy` rather than folded into it, because the two act on
    /// different evidence and one of them is a `SIGKILL` at a recorded pid.
    /// `destroy` is "this VM of mine, whose process I own or whose pid my map
    /// names"; this is "something is serving an api socket in my run
    /// directory and no record of mine says what". The second has no pid to
    /// check and must not invent one — it speaks to the socket, which by
    /// construction reaches only the process that answers for that id here.
    ///
    /// Only ever called after a grace, and only about an id `strays` named.
    async fn end_stray(&self, id: &VmId) -> Result<()> {
        let _ = id;
        Err(HypervisorError::Backend(anyhow::anyhow!(
            "this hypervisor cannot end a vmm it has no record of"
        )))
    }

    /// What this hypervisor calls itself, e.g. `cloud-hypervisor v53.0`.
    ///
    /// Part of the node's machine profile, and there for a reason worth
    /// stating: two ends of a live migration on two BUILDS is its own way for
    /// a saved state not to restore, and it is invisible from anywhere else —
    /// a fleet mid-rollout looks identical in every other field.
    ///
    /// Asked once, at start-up, because a binary does not change under a
    /// running agent. `None` is a driver that cannot say, and an empty answer
    /// is never compared against anything: see `live_migration_refusal`.
    ///
    /// The CPUID PROFILE it gives a guest is the neighbouring question and
    /// has its own method, because the two have different lifetimes: the
    /// version is the binary's and the profile is the configuration's.
    async fn version(&self) -> Option<String> {
        None
    }

    /// The CPUID profile this hypervisor gives a guest — v53 has exactly one,
    /// `Host`, which means "hand the guest this machine's own cpuid".
    ///
    /// Which is why the pre-flight comparison one tier up is a comparison of
    /// MACHINES: with `Host` there is nothing between the silicon and the
    /// guest to make two different machines look alike. The day `CpuProfile`
    /// grows a second variant, a fleet that pins the same one everywhere is a
    /// fleet whose guests can move between models — and the field is already
    /// on the wire for it.
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
