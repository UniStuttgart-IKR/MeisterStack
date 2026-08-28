// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

pub mod device;
pub mod hypervisor;
pub mod networking;
pub mod resource_limits;
pub mod storage;
pub mod types;

pub use device::{
    Device, DeviceAttachment, DeviceDriver, DeviceError, DeviceId, DeviceSpec, PartitionSpec,
};
pub use hypervisor::{
    BootSource, HotPluggable, Hypervisor, HypervisorError, InstanceSpec, Migratable, Pausable,
    Snapshottable, VmId, VmState,
};
pub use networking::{BridgeDriver, NetworkError, Nic, NicAttachment, NicDriver, NicId, NicSpec};
pub use resource_limits::{
    CgroupHandle, ConfinerError, ConfinerResult, ResourceConfiner, ResourceLimits,
};
pub use storage::{
    BlockDriver, StorageError, Volume, VolumeAttachment, VolumeId, VolumeSpec,
    default_volume_driver,
};
