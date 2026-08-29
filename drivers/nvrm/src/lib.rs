// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Device driver for Leandro's vhost-user-nvrm backend (NVIDIA paravirtualization).
//!
//! Talks directly to the `vhost-user-nvrm` and `vgpuprofile` binaries; everything
//! the Leandro rig scripts do procedurally (env construction, vGPU type resolution,
//! process hygiene) lives here as code. One backend serves exactly one VM and
//! exits on VMM hangup by design — a dead backend is replaced by Teardown→Provision,
//! never reused.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use agent_api::CgroupHandle;
use agent_api::device::{
    self, Device, DeviceAttachment, DeviceDriver, DeviceError, DeviceId, DeviceSpec, PartitionSpec,
};
use backend::{Backend, BackendIo, BackendKind};
use tokio::sync::Mutex;
use tracing::{debug, error, info, instrument, warn};

/// VIRTIO_ID_NVRM, the device type Leandro's guest module binds to.
const VIRTIO_ID_NVRM: u32 = 60;
/// Queue 0 request/response, queue 1 host→guest events. Both are mandatory:
/// with a single queue the guest module disables event delivery.
const NVRM_QUEUE_SIZES: [u16; 2] = [256, 256];
/// A desktop guest reached 913 open FDs against the 1024 default (one fd per
/// guest RM client); the backend needs headroom.
const NOFILE_LIMIT: u64 = 65536;

/// Tunables for one backend, merged `defaults < profile < spec.params`.
/// Typed fields are the ones this driver has to reason about (validation,
/// vGPU resolution, admission); `env` passes any LEA_* knob through verbatim
/// and wins over the typed fields, so new backend knobs need no driver change.
#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NvrmParams {
    /// vGPU type (e.g. "RTX2070-4Q"), resolved against the card via vgpuprofile.
    pub vgpu_type: Option<String>,
    pub vram_limit_mib: Option<u64>,
    pub vram_profile_mib: Option<u64>,
    pub vram_reserve_mib: Option<u64>,
    pub managed_compat: Option<bool>,
    pub admin_priv: Option<bool>,
    #[serde(default)]
    pub env: HashMap<String, String>,
}

impl NvrmParams {
    fn overlay(&self, over: &NvrmParams) -> NvrmParams {
        let mut merged = self.clone();
        macro_rules! take {
            ($($f:ident),*) => { $( if over.$f.is_some() { merged.$f = over.$f.clone(); } )* };
        }
        take!(
            vgpu_type,
            vram_limit_mib,
            vram_profile_mib,
            vram_reserve_mib,
            managed_compat,
            admin_priv
        );
        merged
            .env
            .extend(over.env.iter().map(|(k, v)| (k.clone(), v.clone())));
        merged
    }

    fn validate(&self) -> device::Result<()> {
        // The backend refuses to start when both a cap and a profile are set;
        // a vgpu_type resolves to a profile, so it counts as one.
        let profile_like = self.vram_profile_mib.is_some() || self.vgpu_type.is_some();
        if self.vram_limit_mib.is_some() && profile_like {
            return Err(DeviceError::InvalidSpec(
                "vram_limit_mib and vram_profile_mib/vgpu_type are mutually exclusive \
                 (the backend refuses both, cap OR profile)"
                    .into(),
            ));
        }
        Ok(())
    }
}

/// What `vgpuprofile --select <type>` reports for one type on this card.
#[derive(Clone, Debug, PartialEq)]
pub struct VgpuType {
    pub vgpu_type: String,
    pub profile_mib: u64,
    pub fb_mib: u64,
    pub max_instance: u64,
    pub encoder_cap: u64,
}

/// How long the driver waits for a freshly spawned backend to answer on its
/// socket. The agent's config takes this as its default, so the number lives
/// with the process it is about rather than in the config that names it.
pub const DEFAULT_SOCKET_TIMEOUT_MS: u64 = 5000;

pub struct NvrmDriverConfig {
    pub binary: PathBuf,
    pub vgpuprofile_bin: PathBuf,
    pub run_dir: PathBuf,
    pub socket_timeout: Duration,
    /// Hard admission budget over the summed vGPU profile sizes of active
    /// backends. None disables the check (Leandro allows overprovisioning
    /// by design; the driver then only warns).
    pub vram_budget_mib: Option<u64>,
    pub defaults: NvrmParams,
    pub profiles: HashMap<String, NvrmParams>,
}

struct ActiveBackend {
    child: Backend,
    /// What this backend counts as for admission (vGPU profile MiB).
    admitted_mib: u64,
    vgpu_type: Option<String>,
}

pub struct NvrmDriver {
    config: NvrmDriverConfig,
    /// One backend serves one VM, in a session of its own, and is signalled
    /// as a process GROUP. See `BackendKind::detached`.
    process: BackendKind,
    vgpu_cache: Mutex<HashMap<String, VgpuType>>,
    active: Mutex<HashMap<DeviceId, ActiveBackend>>,
}

impl NvrmDriver {
    pub fn new(config: NvrmDriverConfig) -> device::Result<Self> {
        std::fs::create_dir_all(&config.run_dir).map_err(|e| DeviceError::Backend(e.into()))?;
        if !config.binary.exists() {
            return Err(DeviceError::Backend(anyhow::anyhow!(
                "vhost-user-nvrm binary not found at {}",
                config.binary.display()
            )));
        }

        config
            .defaults
            .validate()
            .map_err(|e| DeviceError::InvalidSpec(format!("nvrm defaults are invalid: {e}")))?;

        host_checks();

        // Resolve every configured vGPU type once, fail-fast at agent start:
        // an unknown type is a config error, not something to discover at the
        // first VM boot.
        let mut cache = HashMap::new();
        for (name, params) in &config.profiles {
            let merged = config.defaults.overlay(params);
            merged.validate().map_err(|e| {
                DeviceError::InvalidSpec(format!("nvrm profile {name:?} is invalid: {e}"))
            })?;
            if let Some(vtype) = &merged.vgpu_type
                && !cache.contains_key(vtype)
            {
                let resolved = resolve_vgpu_type(&config.vgpuprofile_bin, vtype).map_err(|e| {
                    DeviceError::InvalidSpec(format!(
                        "nvrm profile {name:?}: vgpu_type {vtype:?}: {e}"
                    ))
                })?;
                info!(profile = %name, vgpu_type = %vtype,
                          profile_mib = resolved.profile_mib, fb_mib = resolved.fb_mib,
                          max_instance = resolved.max_instance,
                          "vgpu type resolved against this card");
                cache.insert(vtype.clone(), resolved);
            }
        }

        Ok(Self {
            config,
            // The name is the backend's own and not the configured binary's:
            // `--nvrm` is Leandro's binary whatever a node has called the file
            // it lives in, and `comm` is what the process calls itself.
            process: BackendKind::detached("vhost-user-nvrm", "vhost-user-nvrm", NOFILE_LIMIT),
            vgpu_cache: Mutex::new(cache),
            active: Mutex::new(HashMap::new()),
        })
    }

    fn effective_params(&self, spec: &DeviceSpec) -> device::Result<NvrmParams> {
        let mut merged = self.config.defaults.clone();
        if let Some(name) = &spec.profile {
            let profile = self.config.profiles.get(name).ok_or_else(|| {
                let mut known: Vec<&str> =
                    self.config.profiles.keys().map(String::as_str).collect();
                known.sort_unstable();
                DeviceError::InvalidSpec(format!(
                    "unknown nvrm profile {name:?}; configured profiles: [{}]",
                    known.join(", ")
                ))
            })?;
            merged = merged.overlay(profile);
        }
        if let Some(params) = &spec.params {
            let params: NvrmParams = serde_json::from_value(params.clone())
                .map_err(|e| DeviceError::InvalidSpec(format!("invalid nvrm params: {e}")))?;
            merged = merged.overlay(&params);
        }
        merged.validate()?;
        Ok(merged)
    }

    /// The backend derives the vGPU identity from the socket path, so it must
    /// be unique and stable per device for its whole lifetime.
    fn socket_path(&self, id: &DeviceId) -> PathBuf {
        self.config.run_dir.join(format!("{id}.sock"))
    }

    fn log_path(&self, id: &DeviceId) -> PathBuf {
        self.config.run_dir.join(format!("{id}.log"))
    }

    fn attachment(socket: PathBuf, pid: u32) -> DeviceAttachment {
        DeviceAttachment::VhostUser {
            socket,
            pid,
            device_type: VIRTIO_ID_NVRM,
            queue_sizes: NVRM_QUEUE_SIZES.to_vec(),
        }
    }

    /// Admission over what this driver can see: its own active backends.
    /// Leandro overprovisions by design and only warns; the hard check here
    /// is opt-in via vram_budget_mib. max_instance is always enforced — it is
    /// the card's own per-type limit and exceeding it fails at VM boot anyway.
    async fn admit(&self, id: &DeviceId, vgpu: Option<&VgpuType>) -> device::Result<u64> {
        let active = self.active.lock().await;
        let Some(vgpu) = vgpu else { return Ok(0) };

        let same_type = active
            .values()
            .filter(|b| b.vgpu_type.as_deref() == Some(vgpu.vgpu_type.as_str()))
            .count() as u64;
        if same_type >= vgpu.max_instance {
            return Err(DeviceError::InvalidSpec(format!(
                "vGPU type {} allows {} instance(s) on this card, {} already active",
                vgpu.vgpu_type, vgpu.max_instance, same_type
            )));
        }

        let used: u64 = active.values().map(|b| b.admitted_mib).sum();
        if let Some(budget) = self.config.vram_budget_mib {
            if used + vgpu.profile_mib > budget {
                return Err(DeviceError::InvalidSpec(format!(
                    "vram budget exceeded: {used} MiB active + {} MiB requested > {budget} MiB \
                     (device {id})",
                    vgpu.profile_mib
                )));
            }
        } else if used + vgpu.profile_mib > 0 {
            debug!(
                used_mib = used,
                requested_mib = vgpu.profile_mib,
                "no vram budget configured, admitting without a hard check"
            );
        }
        Ok(vgpu.profile_mib)
    }

    /// The full environment for one backend, in ascending precedence:
    /// typed fields, vGPU resolution, then the free-form env map.
    fn backend_env(params: &NvrmParams, vgpu: Option<&VgpuType>) -> Vec<(String, String)> {
        let mut env: Vec<(String, String)> = Vec::new();
        let mut push = |k: &str, v: String| env.push((k.to_string(), v));

        if let Some(v) = params.vram_limit_mib {
            push("LEA_VRAM_LIMIT_MIB", v.to_string());
        }
        if let Some(v) = params.vram_profile_mib {
            push("LEA_VRAM_PROFILE_MIB", v.to_string());
        }
        if let Some(v) = params.vram_reserve_mib {
            push("LEA_VRAM_RESERVE_MIB", v.to_string());
        }
        if params.managed_compat == Some(true) {
            push("LEA_MANAGED_COMPAT", "1".into());
        }
        if params.admin_priv == Some(true) {
            push("LEA_ADMIN_PRIV", "1".into());
        }
        if let Some(v) = vgpu {
            push("LEA_VGPU_TYPE", v.vgpu_type.clone());
            push("LEA_VGPU_PROFILE_MIB", v.profile_mib.to_string());
            push("LEA_VGPU_FB_MIB", v.fb_mib.to_string());
            push("LEA_VGPU_ENCODER_CAP", v.encoder_cap.to_string());
        }

        let mut extra: Vec<_> = params.env.iter().collect();
        extra.sort_unstable_by_key(|(k, _)| k.as_str());
        for (k, v) in extra {
            env.retain(|(existing, _)| existing != k);
            env.push((k.clone(), v.clone()));
        }
        env
    }
}

/// Best-effort host preflight; hard failures belong to the backend, which
/// asserts the exact driver version itself. These only make problems
/// visible at agent start instead of at the first VM boot.
fn host_checks() {
    match std::fs::read_to_string("/sys/module/nvidia/version") {
        Ok(v) => info!(nvidia_driver = %v.trim(), "host nvidia driver detected"),
        // Not a degraded state that heals itself: without the host driver
        // loaded, every vhost-user-nvrm spawn on this node will fail. The
        // operator has to load it.
        Err(_) => error!(
            path = "/sys/module/nvidia/version",
            "nvidia driver is not loaded, vhost-user-nvrm will refuse to start"
        ),
    }
    if let Ok(out) = std::process::Command::new("nvidia-smi")
        .args(["--query-gpu=persistence_mode", "--format=csv,noheader"])
        .output()
    {
        let mode = String::from_utf8_lossy(&out.stdout);
        if mode.lines().any(|l| l.trim() == "Disabled") {
            // WARN and not ERROR, unlike the missing driver above: the gates
            // do refuse a card without it, but the backend retries past that
            // and the only lasting cost is a measurably slower start. It is
            // also hardware-dependent legacy fiddling — it matters on Turing
            // and makes no difference on Blackwell (Silas, 2026-08-28) — so a
            // node that logs this is degraded, not broken.
            warn!(
                fix = "nvidia-smi -pm 1",
                "nvidia persistence mode is disabled, backend start-up is slower"
            );
        }
    }
}

/// `vgpuprofile --select <type>`: prose goes to stderr, shell-evalable
/// KEY=VALUE lines to stdout.
///
/// The blocking form, for `new()` — agent start-up has no runtime to starve
/// and is the right place to find out that a configured type does not exist.
fn resolve_vgpu_type(bin: &Path, vtype: &str) -> anyhow::Result<VgpuType> {
    let out = std::process::Command::new(bin)
        .args(["--select", vtype])
        .output()
        .map_err(|e| anyhow::anyhow!("running {}: {e}", bin.display()))?;
    vgpu_from_output(vtype, &out)
}

/// The same query on the async path. `vgpuprofile` talks to the card and can
/// take its time about it; a blocking `output()` here would park a runtime
/// worker for that whole time and serialize every other VM's create behind it.
async fn resolve_vgpu_type_async(bin: &Path, vtype: &str) -> anyhow::Result<VgpuType> {
    let out = tokio::process::Command::new(bin)
        .args(["--select", vtype])
        .output()
        .await
        .map_err(|e| anyhow::anyhow!("running {}: {e}", bin.display()))?;
    vgpu_from_output(vtype, &out)
}

fn vgpu_from_output(vtype: &str, out: &std::process::Output) -> anyhow::Result<VgpuType> {
    if !out.status.success() {
        anyhow::bail!(
            "vgpuprofile --select {vtype} failed ({}): no such type on this card?",
            out.status
        );
    }
    parse_vgpu_select(&String::from_utf8_lossy(&out.stdout))
}

/// Parse the KEY=VALUE stdout of `vgpuprofile --select`.
fn parse_vgpu_select(stdout: &str) -> anyhow::Result<VgpuType> {
    let mut kv = HashMap::new();
    for line in stdout.lines() {
        if let Some((k, v)) = line.split_once('=') {
            kv.insert(k.trim(), v.trim());
        }
    }
    let get = |k: &str| -> anyhow::Result<&str> {
        kv.get(k).copied().ok_or_else(|| {
            anyhow::anyhow!("vgpuprofile output is missing {k}= (got: {:?})", kv.keys())
        })
    };
    let num = |k: &str| -> anyhow::Result<u64> {
        get(k)?
            .parse()
            .map_err(|e| anyhow::anyhow!("vgpuprofile {k}: {e}"))
    };
    Ok(VgpuType {
        vgpu_type: get("vgpu_type")?.to_string(),
        profile_mib: num("vgpu_profile_mib")?,
        fb_mib: num("vgpu_fb_mib")?,
        max_instance: num("vgpu_max_instance")?,
        encoder_cap: num("vgpu_encoder_cap")?,
    })
}

#[async_trait::async_trait]
impl DeviceDriver for NvrmDriver {
    #[instrument(skip_all, fields(device_id = %id))]
    async fn create(
        &self,
        id: &DeviceId,
        spec: &DeviceSpec,
        cgroup: Option<&CgroupHandle>,
    ) -> device::Result<Device> {
        if spec.partition != PartitionSpec::Mediated {
            return Err(DeviceError::InvalidSpec(format!(
                "nvrm driver only supports Mediated, got {:?}",
                spec.partition
            )));
        }

        let socket = self.socket_path(id);
        {
            let mut active = self.active.lock().await;
            if let Some(running) = active.get_mut(id) {
                if running.child.is_reusable(&socket) {
                    let pid = running.child.pid().unwrap_or(0);
                    return Ok(Device {
                        id: *id,
                        attachment: Self::attachment(socket, pid),
                    });
                }
                active.remove(id);
            }
        }

        let params = self.effective_params(spec)?;

        let vgpu = match &params.vgpu_type {
            Some(vtype) => {
                // Read the cache, then let go of it: resolving shells out to
                // vgpuprofile, and holding the lock across that would queue
                // every other create in the node behind one card query. Two
                // creates racing on the same unresolved type both resolve it
                // and both write the same answer, which costs one extra fork
                // and nothing else.
                let cached = self.vgpu_cache.lock().await.get(vtype).cloned();
                Some(match cached {
                    Some(vgpu) => vgpu,
                    // Per-VM params may name a type no profile pre-resolved.
                    None => {
                        let resolved = resolve_vgpu_type_async(&self.config.vgpuprofile_bin, vtype)
                            .await
                            .map_err(|e| DeviceError::InvalidSpec(e.to_string()))?;
                        self.vgpu_cache
                            .lock()
                            .await
                            .insert(vtype.clone(), resolved.clone());
                        resolved
                    }
                })
            }
            None => None,
        };

        let admitted_mib = self.admit(id, vgpu.as_ref()).await?;

        let env = Self::backend_env(&params, vgpu.as_ref());
        debug!(
            vgpu_type = params.vgpu_type.as_deref().unwrap_or("-"),
            profile = spec.profile.as_deref().unwrap_or("-"),
            env = ?env.iter().map(|(k, _)| k.as_str()).collect::<Vec<_>>(),
            "starting vhost-user-nvrm backend"
        );

        let mut cmd = tokio::process::Command::new(&self.config.binary);
        cmd.arg("--nvrm")
            .arg(&socket)
            .env_clear()
            .envs(std::env::vars().filter(|(k, _)| k == "PATH" || k == "HOME"))
            .envs(env);

        // The backend must be listening before cloud-hypervisor connects.
        let (pid, child) = self
            .process
            .spawn(
                cmd,
                BackendIo {
                    socket: &socket,
                    log: &self.log_path(id),
                    timeout: self.config.socket_timeout,
                    cgroup,
                    span: tracing::info_span!("backend_spawn", driver = "nvrm", device_id = %id),
                },
            )
            .await?;
        info!(pid, admitted_mib, "nvrm backend ready");

        self.active.lock().await.insert(
            *id,
            ActiveBackend {
                child,
                admitted_mib,
                vgpu_type: params.vgpu_type.clone(),
            },
        );

        Ok(Device {
            id: *id,
            attachment: Self::attachment(socket, pid),
        })
    }

    #[instrument(skip_all, fields(device_id = %id))]
    async fn destroy(&self, id: &DeviceId, attachment: &DeviceAttachment) -> device::Result<()> {
        let entry = self.active.lock().await.remove(id);

        match entry {
            Some(entry) => self.process.stop(entry.child).await,
            // Not our child: the agent restarted since create, and the
            // record's pid is the only handle left on the backend.
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
        let DeviceAttachment::VhostUser { pid, .. } = attachment else {
            return Err(DeviceError::NotFound(*id));
        };
        // Liveness by pid, and by NAME: a bare kill(pid, 0) answers "alive" for
        // whoever holds that pid now, and after an agent restart the recorded
        // one may well have been recycled. Reporting a stranger's process as
        // this device would leave the VM in the inventory with a dead backend —
        // the exact state the quarantine exists to catch. `is_ours` is the same
        // /proc/<pid>/comm check the adopted teardown makes, and it subsumes
        // liveness: a dead pid has no comm to read.
        if !self.process.is_ours(*pid) {
            return Err(DeviceError::NotFound(*id));
        }
        Ok(Device {
            id: *id,
            attachment: attachment.clone(),
        })
    }

    fn profiles(&self) -> Vec<String> {
        let mut names: Vec<String> = self.config.profiles.keys().cloned().collect();
        names.sort_unstable();
        names
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(json: serde_json::Value) -> NvrmParams {
        serde_json::from_value(json).unwrap()
    }

    #[test]
    fn overlay_later_layer_wins_and_env_merges() {
        let defaults = p(serde_json::json!({
            "vram_limit_mib": 1024,
            "managed_compat": true,
            "env": { "LEA_DEBUG": "0", "LEA_FD_CENSUS": "1" }
        }));
        let profile = p(serde_json::json!({
            "vram_limit_mib": 2048,
            "env": { "LEA_DEBUG": "1" }
        }));
        let merged = defaults.overlay(&profile);
        assert_eq!(merged.vram_limit_mib, Some(2048));
        assert_eq!(merged.managed_compat, Some(true));
        assert_eq!(merged.env["LEA_DEBUG"], "1");
        assert_eq!(merged.env["LEA_FD_CENSUS"], "1");
    }

    #[test]
    fn cap_and_profile_are_mutually_exclusive() {
        assert!(
            p(serde_json::json!({ "vram_limit_mib": 1024, "vram_profile_mib": 2048 }))
                .validate()
                .is_err()
        );
        assert!(
            p(serde_json::json!({ "vram_limit_mib": 1024, "vgpu_type": "RTX2070-4Q" }))
                .validate()
                .is_err()
        );
        assert!(
            p(serde_json::json!({ "vram_limit_mib": 1024 }))
                .validate()
                .is_ok()
        );
        assert!(
            p(serde_json::json!({ "vgpu_type": "RTX2070-4Q" }))
                .validate()
                .is_ok()
        );
    }

    #[test]
    fn free_env_overrides_typed_fields() {
        let params = p(serde_json::json!({
            "vram_limit_mib": 1024,
            "env": { "LEA_VRAM_LIMIT_MIB": "512" }
        }));
        let env = NvrmDriver::backend_env(&params, None);
        let vals: Vec<_> = env
            .iter()
            .filter(|(k, _)| k == "LEA_VRAM_LIMIT_MIB")
            .collect();
        assert_eq!(vals.len(), 1);
        assert_eq!(vals[0].1, "512");
    }

    #[test]
    fn vgpu_resolution_lands_in_env() {
        let vgpu = VgpuType {
            vgpu_type: "RTX2070-4Q".into(),
            profile_mib: 4096,
            fb_mib: 2816,
            max_instance: 2,
            encoder_cap: 50,
        };
        let env = NvrmDriver::backend_env(&NvrmParams::default(), Some(&vgpu));
        let get = |k: &str| env.iter().find(|(ek, _)| ek == k).map(|(_, v)| v.as_str());
        assert_eq!(get("LEA_VGPU_TYPE"), Some("RTX2070-4Q"));
        assert_eq!(get("LEA_VGPU_PROFILE_MIB"), Some("4096"));
        assert_eq!(get("LEA_VGPU_FB_MIB"), Some("2816"));
        assert_eq!(get("LEA_VGPU_ENCODER_CAP"), Some("50"));
    }

    #[test]
    fn parses_vgpuprofile_select_output() {
        let out = "vgpu_type=RTX2070-4Q\nvgpu_profile_mib=4096\nvgpu_fb_mib=2816\n\
                   vgpu_max_instance=2\nvgpu_segments=11\nvgpu_segment_mib=256\n\
                   vgpu_encoder_cap=50\nvgpu_available_mib=8192\n";
        let v = parse_vgpu_select(out).unwrap();
        assert_eq!(
            v,
            VgpuType {
                vgpu_type: "RTX2070-4Q".into(),
                profile_mib: 4096,
                fb_mib: 2816,
                max_instance: 2,
                encoder_cap: 50,
            }
        );
        assert!(parse_vgpu_select("prose only, no keys\n").is_err());
    }
}
