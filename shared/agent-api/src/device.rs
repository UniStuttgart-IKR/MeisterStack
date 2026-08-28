// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

use crate::CgroupHandle;
use serde_json;
use uuid::Uuid;

pub type DeviceId = Uuid;

#[derive(Debug, thiserror::Error)]
pub enum DeviceError {
    #[error("device not found: {0}")]
    NotFound(DeviceId),
    #[error("invalid device spec: {0}")]
    InvalidSpec(String),
    #[error("backend process died during startup: {0}")]
    BackendDied(String),
    #[error("device backend failure: {0}")]
    Backend(anyhow::Error),
}

pub type Result<T> = std::result::Result<T, DeviceError>;

#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum PartitionSpec {
    /// VFIO-Passthrough.
    Exclusive,
    /// Cooperative shared device via vhost-user, mps...
    Mediated,
    // TODO: more MIG, SR-IOV, vGPU...
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct DeviceSpec {
    /// Device driver that handles this device for example 'crosvm-gpu', 'vfio'
    pub driver: String,
    pub partition: PartitionSpec,
    #[serde(default)]
    pub profile: Option<String>,
    pub params: Option<serde_json::Value>,
}

pub fn default_device_driver() -> String {
    "crosvm-gpu".to_string()
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub enum DeviceAttachment {
    VfioPci {
        sysfs_path: std::path::PathBuf,
    },
    VfioMdev {
        mdev_uuid: Uuid,
    },
    VhostUser {
        socket: std::path::PathBuf,
        pid: u32,
        /// Virtio device id (e.g. 16 = gpu), attached via CH's generic vhost-user device.
        device_type: u32,
        queue_sizes: Vec<u16>,
    },
}

impl DeviceAttachment {
    /// Whether this attachment needs the guest's memory to be shareable — the
    /// same question `VolumeAttachment` answers, asked of the other half of
    /// the spec. A vhost-user backend maps guest memory and cannot map what
    /// is not shared; passthrough and mdev have no backend to map anything.
    pub fn needs_shared_memory(&self) -> bool {
        matches!(self, DeviceAttachment::VhostUser { .. })
    }
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct Device {
    pub id: DeviceId,
    pub attachment: DeviceAttachment,
}

#[async_trait::async_trait]
pub trait DeviceDriver: Send + Sync {
    async fn create(
        &self,
        id: &DeviceId,
        spec: &DeviceSpec,
        cgroup: Option<&CgroupHandle>,
    ) -> Result<Device>;

    /// Tear down the device. `attachment` is the record's attachment from `create`,
    /// so a stateless driver can resolve the device even after an agent restart.
    /// Must be idempotent: destroying an already-gone device is Ok.
    async fn destroy(&self, id: &DeviceId, attachment: &DeviceAttachment) -> Result<()>;

    /// Liveness probe: Ok if the device backing this attachment is still present
    /// and usable, NotFound otherwise.
    async fn get(&self, id: &DeviceId, attachment: &DeviceAttachment) -> Result<Device>;

    fn profiles(&self) -> Vec<String> {
        Vec::new()
    }

    /// Whether this driver can serve `requested` alongside what other VMs on
    /// this node already claim from it. Called before anything is built, so a
    /// refusal costs nothing.
    ///
    /// The split of labour is the point: only the agent can read its store,
    /// and only the driver knows what a conflict IS — which param names the
    /// resource, whether two VMs may share it, what the message should say.
    /// `claimed` is every device spec of every OTHER vm on this node that
    /// names this driver; a driver that has no such constraint says nothing.
    ///
    /// Not the same thing as the admission a driver does over its own live
    /// backends (nvrm's max_instance and VRAM budget): that one is about what
    /// is running and belongs in `create`. This one is about what is
    /// declared, and it has to survive an agent restart — which is why the
    /// specs come from the caller's store rather than from driver state.
    fn admit(
        &self,
        requested: &[(DeviceId, DeviceSpec)],
        claimed: &[(crate::VmId, DeviceSpec)],
    ) -> Result<()> {
        let _ = (requested, claimed);
        Ok(())
    }
}
