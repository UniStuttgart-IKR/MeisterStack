// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! One upstream vhost-device-input process per explicitly selected evdev device.

use std::collections::HashMap;
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::path::PathBuf;
use std::time::Duration;

use agent_api::CgroupHandle;
use agent_api::device::{
    self, Device, DeviceAttachment, DeviceDriver, DeviceError, DeviceId, DeviceSpec, PartitionSpec,
};
use backend::{Backend, BackendIo, BackendKind};
use tokio::sync::Mutex;
use tracing::{debug, info, instrument};

const VIRTIO_ID_INPUT: u32 = 18;

const INPUT_QUEUE_SIZES: [u16; 2] = [256, 256];

const NOFILE_LIMIT: u64 = 1024;

pub const PROFILE_EVDEV: &str = "evdev";

pub const DEFAULT_SOCKET_TIMEOUT_MS: u64 = 5000;

#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InputParams {
    pub evdev: Option<PathBuf>,
}

pub struct InputDriverConfig {
    pub binary: PathBuf,
    pub run_dir: PathBuf,
    pub socket_timeout: Duration,
    pub vmm_user: Option<agent_api::VmmUser>,
}

pub struct InputDriver {
    config: InputDriverConfig,
    process: BackendKind,
    active: Mutex<HashMap<DeviceId, Backend>>,
}

impl InputDriver {
    pub fn new(config: InputDriverConfig) -> device::Result<Self> {
        std::fs::create_dir_all(&config.run_dir).map_err(|e| DeviceError::Backend(e.into()))?;
        if !config.binary.exists() {
            return Err(DeviceError::Backend(anyhow::anyhow!(
                "vhost-device-input binary not found at {}",
                config.binary.display()
            )));
        }
        Ok(Self {
            process: BackendKind::detached(
                "vhost-device-input",
                "vhost-device-input",
                NOFILE_LIMIT,
            )
            .as_user(config.vmm_user.clone()),
            config,
            active: Mutex::new(HashMap::new()),
        })
    }

    // Upstream appends the event-list index to the command-line prefix.
    fn socket_prefix(&self, id: &DeviceId) -> PathBuf {
        self.config.run_dir.join(format!("{id}.sock"))
    }

    fn socket_path(&self, id: &DeviceId) -> PathBuf {
        self.config.run_dir.join(format!("{id}.sock0"))
    }

    fn log_path(&self, id: &DeviceId) -> PathBuf {
        self.config.run_dir.join(format!("{id}.log"))
    }

    fn source(spec: &DeviceSpec) -> device::Result<PathBuf> {
        if spec.profile.as_deref().unwrap_or(PROFILE_EVDEV) != PROFILE_EVDEV {
            return Err(DeviceError::InvalidSpec(
                "input supports only the evdev profile".into(),
            ));
        }
        let params: InputParams =
            serde_json::from_value(spec.params.clone().unwrap_or_else(|| serde_json::json!({})))
                .map_err(|e| DeviceError::InvalidSpec(format!("invalid input params: {e}")))?;
        let path = params.evdev.ok_or_else(|| {
            DeviceError::InvalidSpec(
                "params.evdev must name a host /dev/input/eventN device".into(),
            )
        })?;
        let path = std::fs::canonicalize(&path).map_err(|e| {
            DeviceError::InvalidSpec(format!("input device {}: {e}", path.display()))
        })?;
        // Upstream parses event-list as comma-separated UTF-8 paths.
        if path.to_str().is_none_or(|s| s.contains(',')) {
            return Err(DeviceError::InvalidSpec(
                "input path must be UTF-8 without commas".into(),
            ));
        }
        let metadata =
            std::fs::metadata(&path).map_err(|e| DeviceError::InvalidSpec(e.to_string()))?;
        if !metadata.file_type().is_char_device() {
            return Err(DeviceError::InvalidSpec(
                "input source must be a character device".into(),
            ));
        }
        Ok(path)
    }

    fn claimed_node(spec: &DeviceSpec) -> Option<u64> {
        let path = Self::source(spec).ok()?;
        // Device numbers also identify aliases created with mknod.
        Some(std::fs::metadata(path).ok()?.rdev())
    }

    fn attachment(socket: PathBuf, pid: u32) -> DeviceAttachment {
        DeviceAttachment::VhostUser {
            socket,
            pid,
            device_type: VIRTIO_ID_INPUT,
            queue_sizes: INPUT_QUEUE_SIZES.to_vec(),
        }
    }
}

#[async_trait::async_trait]
impl DeviceDriver for InputDriver {
    #[instrument(skip_all, fields(device_id = %id))]
    async fn create(
        &self,
        id: &DeviceId,
        spec: &DeviceSpec,
        cgroup: Option<&CgroupHandle>,
    ) -> device::Result<Device> {
        if spec.partition != PartitionSpec::Mediated {
            return Err(DeviceError::InvalidSpec(format!(
                "input driver only supports Mediated, got {:?}",
                spec.partition
            )));
        }

        let socket = self.socket_path(id);
        let source = Self::source(spec)?;
        let mut active = self.active.lock().await;
        {
            if let Some(running) = active.get_mut(id) {
                if running.is_reusable(&socket) {
                    let pid = running.pid().unwrap_or(0);
                    return Ok(Device {
                        id: *id,
                        attachment: Self::attachment(socket, pid),
                    });
                }
                if let Some(stale) = active.remove(id) {
                    self.process.stop(stale).await;
                }
            }
        }

        debug!(source = %source.display(), "starting vhost-device-input backend");
        let mut cmd = tokio::process::Command::new(&self.config.binary);
        cmd.arg("--socket-path")
            .arg(self.socket_prefix(id))
            .arg("--event-list")
            .arg(&source)
            .env_clear()
            .envs(std::env::vars().filter(|(k, _)| k == "PATH" || k == "HOME"));

        let (pid, child) = self
            .process
            .spawn(
                cmd,
                BackendIo {
                    socket: &socket,
                    log: &self.log_path(id),
                    timeout: self.config.socket_timeout,
                    cgroup,
                    span: tracing::info_span!("backend_spawn", driver = "input", device_id = %id),
                },
            )
            .await?;
        info!(pid, source = %source.display(), "input backend ready");

        active.insert(*id, child);

        Ok(Device {
            id: *id,
            attachment: Self::attachment(socket, pid),
        })
    }

    #[instrument(skip_all, fields(device_id = %id))]
    async fn destroy(&self, id: &DeviceId, attachment: &DeviceAttachment) -> device::Result<()> {
        let mut active = self.active.lock().await;
        let entry = active.remove(id);

        match entry {
            Some(child) => self.process.stop(child).await,
            None => {
                if let DeviceAttachment::VhostUser { socket, pid, .. } = attachment
                    && *socket == self.socket_path(id)
                {
                    self.process.stop_adopted(*pid, &self.socket_prefix(id));
                }
            }
        }

        for p in [self.socket_path(id), self.log_path(id)] {
            backend::remove_if_present(&p)
                .await
                .map_err(|e| DeviceError::Backend(e.into()))?;
        }
        Ok(())
    }

    #[instrument(level = "trace", skip_all, fields(device_id = %id))]
    async fn get(&self, id: &DeviceId, attachment: &DeviceAttachment) -> device::Result<Device> {
        let DeviceAttachment::VhostUser { socket, pid, .. } = attachment else {
            return Err(DeviceError::NotFound(*id));
        };
        if *socket != self.socket_path(id) || !self.process.is_ours(*pid, &self.socket_prefix(id)) {
            return Err(DeviceError::NotFound(*id));
        }
        Ok(Device {
            id: *id,
            attachment: attachment.clone(),
        })
    }

    fn profiles(&self) -> Vec<String> {
        vec![PROFILE_EVDEV.to_string()]
    }

    fn admit(
        &self,
        requested: &[(DeviceId, DeviceSpec)],
        claimed: &[(agent_api::VmId, DeviceSpec)],
    ) -> device::Result<()> {
        for (index, (id, spec)) in requested.iter().enumerate() {
            Self::source(spec)?;
            let Some(node) = Self::claimed_node(spec) else {
                continue;
            };

            if let Some((holder, _)) = claimed
                .iter()
                .find(|(_, held)| Self::claimed_node(held) == Some(node))
            {
                return Err(DeviceError::InvalidSpec(format!(
                    "host input device {} is already claimed by vm {holder} on this node; \
                     one evdev node belongs to one guest at a time (device {id})",
                    node
                )));
            }

            if let Some((twin, _)) = requested[..index]
                .iter()
                .find(|(_, other)| Self::claimed_node(other) == Some(node))
            {
                return Err(DeviceError::InvalidSpec(format!(
                    "host input device {} is named twice by this vm, by device {twin} and \
                     by device {id}; one evdev node belongs to one guest at a time",
                    node
                )));
            }
        }
        Ok(())
    }
}
