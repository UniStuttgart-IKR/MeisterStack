// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

pub mod device;
pub mod hypervisor;
pub mod networking;
pub mod pid;
pub mod resource_limits;
/// The create document, shared with both controllers. See the module.
pub mod spec;
pub mod storage;
pub mod types;

pub use device::{
    Device, DeviceAttachment, DeviceDriver, DeviceError, DeviceId, DeviceSpec, PartitionSpec,
};
pub use hypervisor::{
    AttachedVolume, BootSource, ConsoleStream, HotPluggable, Hypervisor, HypervisorError,
    InstanceSpec, Migratable, Pausable, Snapshottable, VmId, VmState, disk_id, migration_url,
};
pub use networking::{
    BridgeDriver, NatKind, NatRule, NetworkDriver, NetworkError, Nic, NicAttachment, NicDriver,
    NicId, NicSpec, RouterId, RouterPhase, RouterSpec, RouterState,
};
pub use pid::{process_carries, process_exists};
pub use resource_limits::{
    CgroupHandle, ConfinerError, ConfinerResult, ResourceConfiner, ResourceLimits,
};
pub use spec::{BootSourceSpec, CloudInit, Desired, NewDevice, NewNic, NewVmSpec, NewVolume};
pub use storage::{
    SnapshotConsistency, SnapshotId, StorageError, Volume, VolumeAttacher, VolumeAttachment,
    VolumeDriver, VolumeHandle, VolumeId, VolumeProvider, VolumeSpec, VolumeState,
    default_volume_driver,
};
