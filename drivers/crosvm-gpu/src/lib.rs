// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

use agent_api::CgroupHandle;
use agent_api::device::{
    self, Device, DeviceAttachment, DeviceDriver, DeviceError, DeviceId, DeviceSpec, PartitionSpec,
};
use backend::{Backend, BackendIo, BackendKind};
use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Duration;
use tokio::sync::Mutex;
use tracing::{debug, info, instrument};

/// Virtio device id for gpu; crosvm's backend serves a control and a cursor queue.
const VIRTIO_ID_GPU: u32 = 16;
const GPU_QUEUE_SIZES: [u16; 2] = [512, 16];

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GpuParams {
    pub backend: String, // virglrenderer or gfxstream
    pub vulkan: bool,
    pub context_types: String,
    pub external_blob: bool,
    pub pci_bar_size: u64, // basically VRAM
    pub implicit_render_server: bool,
}

impl Default for GpuParams {
    fn default() -> Self {
        Self {
            backend: "virglrenderer".into(),
            vulkan: true,
            context_types: "venus".into(),
            external_blob: true,
            pci_bar_size: 256 * 1024 * 1024,
            implicit_render_server: true,
        }
    }
}

fn crosvm_params_json(params: &GpuParams) -> device::Result<String> {
    let value = serde_json::to_value(params).map_err(|e| DeviceError::Backend(e.into()))?;
    let obj = value
        .as_object()
        .expect("GpuParams serializes to a JSON object");
    let kebab: serde_json::Map<String, serde_json::Value> = obj
        .iter()
        .map(|(k, v)| (k.replace('_', "-"), v.clone()))
        .collect();
    serde_json::to_string(&serde_json::Value::Object(kebab))
        .map_err(|e| DeviceError::Backend(e.into()))
}

pub struct CrosvmGpuDriverConfig {
    pub crosvm_bin: PathBuf,
    pub run_dir: PathBuf,
    pub defaults: GpuParams,
    pub profiles: HashMap<String, serde_json::Value>,
    pub socket_timeout: Duration,
}

pub struct CrosvmGpuDriver {
    config: CrosvmGpuDriverConfig,
    /// crosvm is spawned as a plain child of the agent, in the agent's own
    /// process group — so it is signalled as a single process, and NOT as a
    /// group the way the detached backends are. See `BackendKind::child`.
    process: BackendKind,
    children: Mutex<HashMap<DeviceId, Backend>>,
}

impl CrosvmGpuDriver {
    pub fn new(config: CrosvmGpuDriverConfig) -> device::Result<Self> {
        std::fs::create_dir_all(&config.run_dir).map_err(|e| DeviceError::Backend(e.into()))?;

        for (name, overrides) in &config.profiles {
            Self::merge_params(&config.defaults, Some(overrides), None).map_err(|e| {
                DeviceError::InvalidSpec(format!("gpu profile {name:?} is invalid: {e}"))
            })?;
        }

        // The adopted-backend check compares `/proc/<pid>/comm` against the
        // configured binary's own name, so a node that points `binary` at a
        // wrapper gets that wrapper's name and not a hardcoded guess.
        let comm = config
            .crosvm_bin
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default()
            .to_string();

        Ok(Self {
            process: BackendKind::child("crosvm", &comm),
            config,
            children: Mutex::new(HashMap::new()),
        })
    }

    fn socket_path(&self, id: &DeviceId) -> PathBuf {
        self.config.run_dir.join(format!("{id}.sock"))
    }

    fn log_path(&self, id: &DeviceId) -> PathBuf {
        self.config.run_dir.join(format!("{id}.log"))
    }

    fn merge_params(
        defaults: &GpuParams,
        profile: Option<&serde_json::Value>,
        spec_params: Option<&serde_json::Value>,
    ) -> anyhow::Result<GpuParams> {
        let mut value = serde_json::to_value(defaults)?;
        let obj = value
            .as_object_mut()
            .expect("GpuParams serializes to an object");

        for (layer, overrides) in [("profile", profile), ("params", spec_params)] {
            let Some(overrides) = overrides else { continue };
            let ov = overrides
                .as_object()
                .ok_or_else(|| anyhow::anyhow!("{layer} override must be a JSON object"))?;
            for (k, v) in ov {
                obj.insert(k.clone(), v.clone());
            }
        }

        serde_json::from_value(value).map_err(|e| anyhow::anyhow!("invalid gpu params: {e}"))
    }

    fn effective_params(&self, spec: &DeviceSpec) -> device::Result<GpuParams> {
        let profile = match &spec.profile {
            Some(name) => Some(self.config.profiles.get(name).ok_or_else(|| {
                let mut known: Vec<&str> =
                    self.config.profiles.keys().map(String::as_str).collect();
                known.sort_unstable();
                DeviceError::InvalidSpec(format!(
                    "unknown gpu profile {name:?}; configured profiles: [{}]",
                    known.join(", ")
                ))
            })?),
            None => None,
        };

        Self::merge_params(&self.config.defaults, profile, spec.params.as_ref())
            .map_err(|e| DeviceError::InvalidSpec(e.to_string()))
    }

    fn attachment(socket: PathBuf, pid: u32) -> DeviceAttachment {
        DeviceAttachment::VhostUser {
            socket,
            pid,
            device_type: VIRTIO_ID_GPU,
            queue_sizes: GPU_QUEUE_SIZES.to_vec(),
        }
    }
}

#[async_trait::async_trait]
impl DeviceDriver for CrosvmGpuDriver {
    #[instrument(skip_all, fields(device_id = %id))]
    async fn create(
        &self,
        id: &DeviceId,
        spec: &DeviceSpec,
        cgroup: Option<&CgroupHandle>,
    ) -> device::Result<Device> {
        if spec.partition != PartitionSpec::Mediated {
            return Err(DeviceError::InvalidSpec(format!(
                "crosvm-gpu driver only supports Mediated, got {:?}",
                spec.partition
            )));
        }

        let socket = self.socket_path(id);

        {
            let mut children = self.children.lock().await;
            if let Some(running) = children.get_mut(id) {
                if running.is_reusable(&socket) {
                    let pid = running.pid().unwrap_or(0);
                    return Ok(Device {
                        id: *id,
                        attachment: Self::attachment(socket, pid),
                    });
                }
                children.remove(id);
            }
        }

        let params = self.effective_params(spec)?;
        debug!(
            backend = %params.backend,
            vulkan = params.vulkan,
            profile = spec.profile.as_deref().unwrap_or("-"),
            "starting crosvm gpu backend"
        );

        let params_json = crosvm_params_json(&params)?;

        let mut cmd = tokio::process::Command::new(&self.config.crosvm_bin);
        cmd.args(["device", "gpu", "--socket-path"])
            .arg(&socket)
            .arg("--params")
            .arg(&params_json);

        let (pid, child) = self
            .process
            .spawn(
                cmd,
                BackendIo {
                    socket: &socket,
                    log: &self.log_path(id),
                    timeout: self.config.socket_timeout,
                    cgroup,
                    span: tracing::info_span!(
                        "backend_spawn",
                        driver = "crosvm-gpu",
                        device_id = %id
                    ),
                },
            )
            .await?;
        info!(pid, "gpu backend ready");

        self.children.lock().await.insert(*id, child);

        Ok(Device {
            id: *id,
            attachment: Self::attachment(socket, pid),
        })
    }

    #[instrument(skip_all, fields(device_id = %id))]
    async fn destroy(&self, id: &DeviceId, attachment: &DeviceAttachment) -> device::Result<()> {
        let child = self.children.lock().await.remove(id);

        match child {
            Some(child) => self.process.stop(child).await,
            // Not our child: the agent restarted since create, so the record's
            // pid is the only handle on the backend. Ignoring it would leave a
            // crosvm running for a VM that is gone.
            None => {
                if let DeviceAttachment::VhostUser { pid, .. } = attachment {
                    self.process.stop_adopted(*pid);
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
        if let Some(running) = self.children.lock().await.get(id) {
            return Ok(Device {
                id: *id,
                attachment: Self::attachment(self.socket_path(id), running.pid().unwrap_or(0)),
            });
        }
        // Not in the map: either the backend died, or the AGENT restarted and
        // this one outlived it. Only the record can tell the two apart, and
        // getting it wrong quarantines a VM whose GPU is working — the whole
        // point of adopting a VM after a restart is that its devices come with
        // it. Liveness comes from the pid, as it does for nvrm.
        let DeviceAttachment::VhostUser { pid, .. } = attachment else {
            return Err(DeviceError::NotFound(*id));
        };
        if !self.process.is_ours(*pid) {
            return Err(DeviceError::NotFound(*id));
        }
        Ok(Device {
            id: *id,
            attachment: Self::attachment(self.socket_path(id), *pid),
        })
    }

    fn profiles(&self) -> Vec<String> {
        let mut names: Vec<String> = self.config.profiles.keys().cloned().collect();
        names.sort_unstable();
        names
    }
}
