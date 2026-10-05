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

/// Refuse device parameters a vm spec may not set. `allowed` names the keys a
/// tenant may choose; every other backend setting belongs to the node's
/// `[device.<driver>]` configuration, reached from a spec through a profile.
/// The refusal names the key and where it belongs.
pub fn refuse_params_outside(
    driver: &str,
    allowed: &[&str],
    params: &serde_json::Value,
) -> std::result::Result<(), String> {
    let serde_json::Value::Object(fields) = params else {
        return Err(format!("{driver} params must be an object, not {params}"));
    };
    match fields.keys().find(|key| !allowed.contains(&key.as_str())) {
        Some(key) => Err(format!(
            "{driver} params.{key} is the node's to set and not a spec's; {}, and everything \
             else comes from [device.{driver}] on the node",
            what_a_spec_may_name(allowed)
        )),
        None => Ok(()),
    }
}

fn what_a_spec_may_name(allowed: &[&str]) -> String {
    if allowed.is_empty() {
        "a vm spec chooses one of the node's profiles (spec.profile)".to_string()
    } else {
        format!(
            "a vm spec may name [{}] and a profile (spec.profile)",
            allowed.join(", ")
        )
    }
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
    /// Vhost-user attachments require shared guest memory; passthrough and
    /// mdev attachments have no backend process mapping it.
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

    /// Check declared device claims before creating resources. `claimed`
    /// contains this driver's specs from every other VM in the persistent
    /// store, so conflicts remain visible after agent restart.
    ///
    /// Drivers may separately enforce live-backend limits in `create`, such
    /// as NVRM VRAM and instance budgets.
    fn admit(
        &self,
        requested: &[(DeviceId, DeviceSpec)],
        claimed: &[(crate::VmId, DeviceSpec)],
    ) -> Result<()> {
        let _ = (requested, claimed);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A key outside the allowlist is refused by name, with where it belongs.
    #[test]
    fn a_spec_may_set_only_the_keys_its_driver_allows() {
        let allowed = ["vgpu_type"];
        refuse_params_outside("nvrm", &allowed, &serde_json::json!({ "vgpu_type": "4Q" }))
            .expect("allowed");
        let said = refuse_params_outside("nvrm", &allowed, &serde_json::json!({ "env": {} }))
            .expect_err("not allowed");
        assert!(said.contains("params.env"), "{said}");
        assert!(said.contains("[device.nvrm]"), "{said}");
    }

    /// With nothing allowed, the refusal points at profiles instead of an empty list.
    #[test]
    fn a_driver_that_allows_nothing_points_at_its_profiles() {
        refuse_params_outside("crosvm-gpu", &[], &serde_json::json!({})).expect("no keys");
        let said = refuse_params_outside("crosvm-gpu", &[], &serde_json::json!({ "vulkan": true }))
            .expect_err("not a spec's");
        assert!(said.contains("spec.profile"), "{said}");
        assert!(!said.contains("[]"), "{said}");
    }

    #[test]
    fn params_that_are_not_an_object_are_refused() {
        refuse_params_outside("crosvm-gpu", &[], &serde_json::json!("venus"))
            .expect_err("a string is not a parameter set");
    }
}
