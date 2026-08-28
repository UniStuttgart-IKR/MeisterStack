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

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InstanceSpec {
    pub boot: BootSource,
    /// In spec order; the first block volume is the boot disk. Attachments
    /// rather than paths since volumes learned to be served by a backend
    /// process — and not `disks`, because a `FsShare` in this list is a
    /// filesystem export and never appears among the VMM's disks.
    pub volumes: Vec<VolumeAttachment>,
    pub vcpus: u32,
    pub memory_mib: u64,
    pub nics: Vec<NicAttachment>,
    pub devices: Vec<DeviceAttachment>,
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
// for later
#[async_trait::async_trait]
pub trait Migratable: Send + Sync {
    async fn migrate_out(&self, id: &VmId, peer: &str) -> Result<()>;
    async fn migrate_in(&self, id: &VmId, peer: &str) -> Result<()>;
}
// for later
#[async_trait::async_trait]
pub trait HotPluggable: Send + Sync {
    async fn hotplug_device(&self, id: &VmId) -> Result<()>;
    async fn unplug_device(&self, id: &VmId) -> Result<()>;
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

    // Methods required by the reconcile
    async fn adopt(&self, id: &VmId, pid: u32) -> Result<()>;
    async fn probe(&self, id: &VmId) -> bool;
    fn is_tracked(&self, id: &VmId) -> bool;

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
