// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! NVIDIA paravirtualization through `vhost-user-nvrm`.
//!
//! Each device has a backend process and a stable socket path. `vgpuprofile`
//! resolves configured vGPU types; node configuration supplies resource limits
//! and privileged backend options.

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

/// Environment prefixes reserved for process setup and NVIDIA configuration.
/// Extra backend variables may not override these prefixes.
const PROTECTED_ENV: [&str; 4] = ["LD_", "PATH", "HOME", "NVIDIA_"];

/// Variables derived from typed parameters or vGPU resolution. Reject them
/// in the extra environment even when this device did not emit that variable,
/// so backend settings cannot bypass admission accounting.
const DRIVER_OWNED_ENV: [&str; 9] = [
    "LEA_VRAM_LIMIT_MIB",
    "LEA_VRAM_PROFILE_MIB",
    "LEA_VRAM_RESERVE_MIB",
    "LEA_MANAGED_COMPAT",
    "LEA_ADMIN_PRIV",
    "LEA_VGPU_TYPE",
    "LEA_VGPU_PROFILE_MIB",
    "LEA_VGPU_FB_MIB",
    "LEA_VGPU_ENCODER_CAP",
];

/// Only `vgpu_type` may be supplied through tenant device parameters.
/// Other options come from node defaults or operator-defined profiles.
/// The agent validates this rule at admission and the driver repeats it at use.
pub const TENANT_SETTABLE_PARAMS: [&str; 1] = ["vgpu_type"];

/// Reject parameters reserved for node configuration, naming the rejected key.
pub fn refuse_operator_only_params(params: &serde_json::Value) -> Result<(), String> {
    let serde_json::Value::Object(fields) = params else {
        return Err(format!("nvrm params must be an object, not {params}"));
    };
    for key in fields.keys() {
        if TENANT_SETTABLE_PARAMS.contains(&key.as_str()) {
            continue;
        }
        return Err(format!(
            "nvrm params.{key} is the node's to set and not a spec's; a vm spec may name \
             [{}] and a profile (spec.profile), and everything else comes from \
             [device.nvrm] on the node",
            TENANT_SETTABLE_PARAMS.join(", ")
        ));
    }
    Ok(())
}

/// Backend options merged in order: defaults, named profile, tenant parameters.
/// Tenant parameters are restricted by [`TENANT_SETTABLE_PARAMS`]; extra
/// environment entries cannot override protected or driver-owned variables.
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

    /// Admission size in MiB from the effective backend configuration: explicit
    /// cap, explicit profile size, then resolved vGPU size. Validation rejects
    /// conflicting cap and profile options.
    fn admitted_mib(&self, vgpu: Option<&VgpuType>) -> u64 {
        self.vram_limit_mib
            .or(self.vram_profile_mib)
            .or_else(|| vgpu.map(|v| v.profile_mib))
            .unwrap_or(0)
    }

    fn validate(&self) -> device::Result<()> {
        self.refuse_two_vram_policies()
    }

    /// The backend takes one VRAM policy, a cap, a profile size or a vGPU
    /// type, and refuses to start with two (Leandro vram.rs `decide`). Refusing
    /// here fails the request at admission instead of the VM at boot.
    fn refuse_two_vram_policies(&self) -> device::Result<()> {
        let set: Vec<&str> = [
            ("vram_limit_mib", self.vram_limit_mib.is_some()),
            ("vram_profile_mib", self.vram_profile_mib.is_some()),
            ("vgpu_type", self.vgpu_type.is_some()),
        ]
        .into_iter()
        .filter_map(|(name, is_set)| is_set.then_some(name))
        .collect();
        if set.len() > 1 {
            return Err(DeviceError::InvalidSpec(format!(
                "{} are mutually exclusive: the backend takes one VRAM policy (cap, profile \
                 size or vGPU type) and refuses to start with more",
                set.join(" and ")
            )));
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
    /// `vgpu_available_mib`: what the card offers all guests together. Profile
    /// sizes already carry their share of the card's carve-out, so this is the
    /// sum they are measured against (Leandro `Catalogue::admits`).
    pub available_mib: u64,
}

/// Default wait for a spawned backend's socket-file readiness, shared with agent config.
pub const DEFAULT_SOCKET_TIMEOUT_MS: u64 = 5000;

pub struct NvrmDriverConfig {
    pub binary: PathBuf,
    pub vgpuprofile_bin: PathBuf,
    pub run_dir: PathBuf,
    pub socket_timeout: Duration,
    /// Optional VRAM budget over backends in this driver instance's active map.
    /// Surviving backends are not restored to that map after an agent restart.
    pub vram_budget_mib: Option<u64>,
    pub defaults: NvrmParams,
    pub profiles: HashMap<String, NvrmParams>,
    /// Optional backend user. The account needs access to the configured NVIDIA
    /// device nodes; identity switching does not grant that access. Node parameters
    /// control whether the backend requests administrative privileges.
    pub vmm_user: Option<agent_api::VmmUser>,
}

/// What one backend counts as for admission.
#[derive(Clone, Debug, PartialEq)]
struct Claim {
    /// Admitted VRAM in MiB; see [`NvrmParams::admitted_mib`].
    mib: u64,
    /// The type as `vgpuprofile` names it (`RTX2070-4Q`). A node may configure
    /// `4Q` or `rtx2070-4q` for the same type, and the instance limit must
    /// count all of them as one.
    vgpu_type: Option<String>,
    /// The card's `vgpu_available_mib`, known only for a vGPU-typed claim.
    card_mib: Option<u64>,
}

impl Claim {
    fn of(params: &NvrmParams, vgpu: Option<&VgpuType>) -> Self {
        Self {
            mib: params.admitted_mib(vgpu),
            vgpu_type: vgpu.map(|v| v.vgpu_type.clone()),
            card_mib: vgpu.map(|v| v.available_mib),
        }
    }

    /// No cap, no profile size and no type: the backend may take the whole card.
    fn is_unbounded(&self) -> bool {
        self.mib == 0
    }
}

struct ActiveBackend {
    child: Backend,
    claim: Claim,
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
            // The name is the backend's own and not the configured binary's:
            // `--nvrm` is Leandro's binary whatever a node has called the file
            // it lives in, and `comm` is what the process calls itself.
            process: BackendKind::detached("vhost-user-nvrm", "vhost-user-nvrm", NOFILE_LIMIT)
                .as_user(config.vmm_user.clone()),
            config,
            vgpu_cache: Mutex::new(cache),
            active: Mutex::new(HashMap::new()),
        })
    }
}

impl NvrmDriverConfig {
    /// Layer defaults, the named profile and tenant parameters, and validate the result.
    fn effective_params(&self, spec: &DeviceSpec) -> device::Result<NvrmParams> {
        let mut merged = self.defaults.clone();
        if let Some(name) = &spec.profile {
            let profile = self.profiles.get(name).ok_or_else(|| {
                let mut known: Vec<&str> = self.profiles.keys().map(String::as_str).collect();
                known.sort_unstable();
                DeviceError::InvalidSpec(format!(
                    "unknown nvrm profile {name:?}; configured profiles: [{}]",
                    known.join(", ")
                ))
            })?;
            merged = merged.overlay(profile);
        }
        if let Some(params) = &spec.params {
            // Enforce tenant parameter restrictions even for callers outside the agent.
            refuse_operator_only_params(params).map_err(DeviceError::InvalidSpec)?;
            let params: NvrmParams = serde_json::from_value(params.clone())
                .map_err(|e| DeviceError::InvalidSpec(format!("invalid nvrm params: {e}")))?;
            merged = merged.overlay(&params);
        }
        merged.validate()?;
        Ok(merged)
    }
}

impl NvrmDriver {
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

    /// Check the active map against the optional VRAM budget and resolved
    /// per-type instance limit. These checks do not count surviving backends
    /// from a previous driver instance.
    async fn admit(
        &self,
        id: &DeviceId,
        want: &Claim,
        vgpu: Option<&VgpuType>,
    ) -> device::Result<()> {
        let active = self.active.lock().await;
        let live: Vec<&Claim> = active.values().map(|b| &b.claim).collect();
        refuse_instance_overflow(&live, vgpu)?;
        refuse_card_overcommit(&live, want, id)?;
        refuse_budget_overrun(&live, want, self.config.vram_budget_mib, id)
    }

    /// Build typed and resolved environment settings, then add operator variables
    /// that do not conflict with reserved process or driver-owned names.
    fn backend_env(
        params: &NvrmParams,
        vgpu: Option<&VgpuType>,
    ) -> device::Result<Vec<(String, String)>> {
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
            // Reject process-control environment keys such as PATH and LD_PRELOAD.
            if PROTECTED_ENV.iter().any(|p| k.starts_with(p)) {
                return Err(DeviceError::InvalidSpec(format!(
                    "nvrm env {k:?} is part of the process's own environment and cannot be set \
                     here; [{}] are refused",
                    PROTECTED_ENV.join(", ")
                )));
            }
            if DRIVER_OWNED_ENV.contains(&k.as_str()) {
                return Err(DeviceError::InvalidSpec(format!(
                    "nvrm env {k:?} is written from a typed field; set the field and not the \
                     variable, so that what this node admitted is what the backend runs with"
                )));
            }
            env.push((k.clone(), v.clone()));
        }
        Ok(env)
    }
}

/// Refuse one more backend of a vGPU type the card already holds `max_instance` of.
fn refuse_instance_overflow(live: &[&Claim], vgpu: Option<&VgpuType>) -> device::Result<()> {
    let Some(vgpu) = vgpu else {
        return Ok(());
    };
    let same_type = live
        .iter()
        .filter(|c| c.vgpu_type.as_deref() == Some(vgpu.vgpu_type.as_str()))
        .count() as u64;
    if same_type >= vgpu.max_instance {
        return Err(DeviceError::InvalidSpec(format!(
            "vGPU type {} allows {} instance(s) on this card, {} already active",
            vgpu.vgpu_type, vgpu.max_instance, same_type
        )));
    }
    Ok(())
}

/// Once a vGPU type is on the card, every backend on it must fit beside the
/// others: the admitted sizes together may not exceed `vgpu_available_mib`.
/// Per-type instance counts alone let mixed types overbook the card, and a
/// backend without any VRAM limit could take what the profiles promise.
fn refuse_card_overcommit(live: &[&Claim], want: &Claim, id: &DeviceId) -> device::Result<()> {
    let Some(card) = card_size(live, want) else {
        return Ok(());
    };
    if want.is_unbounded() {
        return Err(DeviceError::InvalidSpec(format!(
            "device {id} sets no VRAM limit (no vgpu_type, vram_profile_mib or \
             vram_limit_mib), and this card carries vGPU-typed backends whose profiles it \
             could take; give it a profile or a cap"
        )));
    }
    if live.iter().any(|c| c.is_unbounded()) {
        return Err(DeviceError::InvalidSpec(format!(
            "a backend without a VRAM limit is running on this card, so it cannot promise \
             device {id} a vGPU profile beside it"
        )));
    }
    let used: u64 = live.iter().map(|c| c.mib).sum();
    if used.saturating_add(want.mib) > card {
        return Err(DeviceError::InvalidSpec(format!(
            "the card offers {card} MiB to guests: {used} MiB admitted + {} MiB requested \
             does not fit (device {id})",
            want.mib
        )));
    }
    Ok(())
}

/// The card's size from any vGPU-typed claim, or `None` when no vGPU type is
/// involved. Every type resolves against the same card, so they agree; the
/// smallest is taken should they not.
fn card_size(live: &[&Claim], want: &Claim) -> Option<u64> {
    live.iter()
        .copied()
        .chain([want])
        .filter_map(|c| c.card_mib)
        .min()
}

/// Refuse a backend that would take the live claims past the node's VRAM budget.
fn refuse_budget_overrun(
    live: &[&Claim],
    want: &Claim,
    budget: Option<u64>,
    id: &DeviceId,
) -> device::Result<()> {
    let used: u64 = live.iter().map(|c| c.mib).sum();
    let wants = want.mib;
    match budget {
        Some(budget) if used.saturating_add(wants) > budget => {
            Err(DeviceError::InvalidSpec(format!(
                "vram budget exceeded: {used} MiB active + {wants} MiB requested > \
                 {budget} MiB (device {id})"
            )))
        }
        Some(_) => Ok(()),
        None => {
            if used + wants > 0 {
                debug!(
                    used_mib = used,
                    requested_mib = wants,
                    "no vram budget configured, admitting without a hard check"
                );
            }
            Ok(())
        }
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
            // Disabled persistence mode is reported as a startup-performance warning.
            warn!(
                fix = "nvidia-smi -pm 1",
                "nvidia persistence mode is disabled, backend start-up is slower"
            );
        }
    }
}

/// Resolve a configured type synchronously during driver construction.
/// The helper returns KEY=VALUE records on stdout and diagnostics on stderr.
fn resolve_vgpu_type(bin: &Path, vtype: &str) -> anyhow::Result<VgpuType> {
    let out = std::process::Command::new(bin)
        .args(["--select", vtype])
        .output()
        .map_err(|e| anyhow::anyhow!("running {}: {e}", bin.display()))?;
    vgpu_from_output(vtype, &out)
}

/// Resolve vGPU types asynchronously so GPU queries do not block a Tokio worker.
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
        available_mib: num("vgpu_available_mib")?,
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

        let params = self.config.effective_params(spec)?;

        let vgpu = match &params.vgpu_type {
            Some(vtype) => {
                // Release the cache lock before the external query. Concurrent misses may
                // resolve the same type twice and then store the same result.
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

        // Count the same effective parameters used to build the backend environment.
        let claim = Claim::of(&params, vgpu.as_ref());
        self.admit(id, &claim, vgpu.as_ref()).await?;

        let env = Self::backend_env(&params, vgpu.as_ref())?;
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
        info!(pid, admitted_mib = claim.mib, "nvrm backend ready");

        self.active
            .lock()
            .await
            .insert(*id, ActiveBackend { child, claim });

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
                if let DeviceAttachment::VhostUser { socket, pid, .. } = attachment {
                    self.process.stop_adopted(*pid, socket);
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
        // Require both backend process identity and this device's socket argument.
        // A live reused PID does not establish that the backend survived restart.
        if !self.process.is_ours(*pid, socket) {
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

    /// Refuse a request the backend would reject before the agent records or
    /// starts anything for it. VRAM is admitted in `create`, against live backends.
    fn admit(
        &self,
        requested: &[(DeviceId, DeviceSpec)],
        _claimed: &[(agent_api::VmId, DeviceSpec)],
    ) -> device::Result<()> {
        for (id, spec) in requested {
            self.config
                .effective_params(spec)
                .map_err(|e| naming_the_device(id, e))?;
        }
        Ok(())
    }
}

/// Prefix a spec refusal with the device it is about.
fn naming_the_device(id: &DeviceId, e: DeviceError) -> DeviceError {
    match e {
        DeviceError::InvalidSpec(said) => DeviceError::InvalidSpec(format!("device {id}: {said}")),
        other => other,
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

    /// IKR-B12: a vGPU type is a profile, so it cannot come with a profile size.
    #[test]
    fn a_vgpu_type_and_a_profile_size_are_mutually_exclusive() {
        let both = p(serde_json::json!({ "vgpu_type": "4Q", "vram_profile_mib": 2048 }));
        let said = both.validate().expect_err("two policies").to_string();
        assert!(said.contains("vram_profile_mib and vgpu_type"), "{said}");
    }

    /// A node configuration whose defaults and profiles the tests choose.
    fn node(defaults: serde_json::Value) -> NvrmDriverConfig {
        NvrmDriverConfig {
            binary: PathBuf::from("/nonexistent/vhost-user-nvrm"),
            vgpuprofile_bin: PathBuf::from("/nonexistent/vgpuprofile"),
            run_dir: PathBuf::from("/nonexistent/run"),
            socket_timeout: Duration::from_millis(DEFAULT_SOCKET_TIMEOUT_MS),
            vram_budget_mib: None,
            defaults: p(defaults),
            profiles: HashMap::new(),
            vmm_user: None,
        }
    }

    fn mediated(params: serde_json::Value) -> DeviceSpec {
        DeviceSpec {
            driver: "nvrm".into(),
            partition: PartitionSpec::Mediated,
            profile: None,
            params: Some(params),
        }
    }

    /// The layers are checked together: a tenant's vGPU type over a node's
    /// default profile size is refused before a backend could refuse it.
    #[test]
    fn a_tenant_vgpu_type_over_a_default_profile_size_is_refused() {
        let node = node(serde_json::json!({ "vram_profile_mib": 2048 }));
        let spec = mediated(serde_json::json!({ "vgpu_type": "4Q" }));
        let said = node
            .effective_params(&spec)
            .expect_err("the backend would not start")
            .to_string();
        assert!(said.contains("mutually exclusive"), "{said}");
    }

    /// Extra environment variables cannot override typed admission settings;
    /// unreserved backend knobs still pass through.
    #[test]
    fn free_env_may_not_argue_with_a_typed_field() {
        let params = p(serde_json::json!({
            "vram_limit_mib": 1024,
            "env": { "LEA_VRAM_LIMIT_MIB": "512" }
        }));
        let err = NvrmDriver::backend_env(&params, None).expect_err("two numbers, one device");
        let said = err.to_string();
        assert!(said.contains("LEA_VRAM_LIMIT_MIB"), "{said}");
        assert!(said.contains("typed field"), "{said}");

        // Preserve additional permitted backend parameters verbatim.
        let params = p(serde_json::json!({
            "vram_limit_mib": 1024,
            "env": { "LEA_FD_CENSUS": "1" }
        }));
        let env = NvrmDriver::backend_env(&params, None).expect("a new knob is not an argument");
        let get = |k: &str| env.iter().find(|(ek, _)| ek == k).map(|(_, v)| v.as_str());
        assert_eq!(get("LEA_FD_CENSUS"), Some("1"));
        assert_eq!(get("LEA_VRAM_LIMIT_MIB"), Some("1024"));
    }

    /// Extra device environment settings cannot replace process configuration.
    #[test]
    fn the_process_environment_is_not_a_device_knob() {
        for key in ["LD_PRELOAD", "PATH", "HOME", "NVIDIA_VISIBLE_DEVICES"] {
            let params = p(serde_json::json!({ "env": { key: "/tmp/mine" } }));
            let err = NvrmDriver::backend_env(&params, None)
                .err()
                .unwrap_or_else(|| panic!("{key} must be refused"));
            let said = err.to_string();
            assert!(said.contains(key), "the refusal names it: {said}");
        }
    }

    /// Tenant parameters accept the vGPU type and reject operator-only keys.
    #[test]
    fn a_spec_may_name_a_vgpu_type_and_nothing_else() {
        assert!(refuse_operator_only_params(&serde_json::json!({})).is_ok());
        assert!(
            refuse_operator_only_params(&serde_json::json!({ "vgpu_type": "RTX2070-4Q" })).is_ok()
        );

        for refused in ["admin_priv", "env", "vram_limit_mib", "vram_profile_mib"] {
            let params = serde_json::json!({ refused: serde_json::Value::Null });
            let said = refuse_operator_only_params(&params).expect_err("not a spec's to set");
            assert!(said.contains(refused), "{said}");
            assert!(
                said.contains("device.nvrm"),
                "and says where it belongs: {said}"
            );
        }
        assert!(refuse_operator_only_params(&serde_json::json!("nvrm")).is_err());
    }

    /// Admission size and emitted environment values come from the same parameters.
    #[test]
    fn the_admitted_budget_is_the_started_budget() {
        let vgpu = VgpuType {
            vgpu_type: "RTX2070-4Q".into(),
            profile_mib: 4096,
            fb_mib: 2816,
            max_instance: 2,
            encoder_cap: 50,
            available_mib: 8192,
        };
        let value = |env: &[(String, String)], k: &str| {
            env.iter()
                .find(|(ek, _)| ek == k)
                .map(|(_, v)| v.parse::<u64>().expect("a number"))
        };

        // A profile alone: what was resolved on the card is what is counted
        // and what the backend reads.
        let params = NvrmParams {
            vgpu_type: Some("RTX2070-4Q".into()),
            ..Default::default()
        };
        let env = NvrmDriver::backend_env(&params, Some(&vgpu)).expect("started");
        assert_eq!(params.admitted_mib(Some(&vgpu)), 4096);
        assert_eq!(value(&env, "LEA_VGPU_PROFILE_MIB"), Some(4096));

        // A cap and no profile: the cap is the number, in both places.
        let params = p(serde_json::json!({ "vram_limit_mib": 512 }));
        let env = NvrmDriver::backend_env(&params, None).expect("started");
        assert_eq!(params.admitted_mib(None), 512);
        assert_eq!(value(&env, "LEA_VRAM_LIMIT_MIB"), Some(512));

        // An explicit profile size also works without a vGPU type.
        let params = p(serde_json::json!({ "vram_profile_mib": 2048 }));
        let env = NvrmDriver::backend_env(&params, None).expect("started");
        assert_eq!(params.admitted_mib(None), 2048);
        assert_eq!(value(&env, "LEA_VRAM_PROFILE_MIB"), Some(2048));

        // And a device that asks for nothing costs nothing.
        assert_eq!(NvrmParams::default().admitted_mib(None), 0);
    }

    /// `vgpu_available_mib` of the 8 GiB card the fixtures resolve against.
    const RTX2070_MIB: u64 = 8192;

    /// A resolved type as the card describes it, for admission tests.
    fn resolved(vgpu_type: &str, profile_mib: u64, max_instance: u64) -> VgpuType {
        VgpuType {
            vgpu_type: vgpu_type.into(),
            profile_mib,
            fb_mib: profile_mib - 512,
            max_instance,
            encoder_cap: 50,
            available_mib: RTX2070_MIB,
        }
    }

    fn configured(vgpu_type: &str) -> NvrmParams {
        NvrmParams {
            vgpu_type: Some(vgpu_type.into()),
            ..Default::default()
        }
    }

    /// IKR-B13: the claim records the card's name for the type, so `4Q`,
    /// `rtx2070-4q` and `RTX2070-4Q` all count against one instance limit.
    #[test]
    fn the_instance_limit_holds_however_the_type_was_spelled() {
        let card_4q = resolved("RTX2070-4Q", 4096, 1);
        for spelling in ["4Q", "rtx2070-4q", "RTX2070-4Q"] {
            let running = Claim::of(&configured(spelling), Some(&card_4q));
            assert_eq!(running.vgpu_type.as_deref(), Some("RTX2070-4Q"));
            let said = refuse_instance_overflow(&[&running], Some(&card_4q))
                .expect_err("the card holds one 4Q, whatever the first was called")
                .to_string();
            assert!(said.contains("allows 1 instance"), "{spelling}: {said}");
        }
    }

    fn typed(vgpu: &VgpuType) -> Claim {
        Claim::of(&configured(&vgpu.vgpu_type), Some(vgpu))
    }

    fn capped(mib: u64) -> Claim {
        Claim::of(&p(serde_json::json!({ "vram_limit_mib": mib })), None)
    }

    fn device() -> DeviceId {
        DeviceId::new_v4()
    }

    /// IKR-B14, Leandro's `one_4q_admits_two_2q_and_nothing_more`: one 4Q
    /// and two 2Q fill the card, and a 1Q beside them is refused although
    /// no type has reached its own instance limit.
    #[test]
    fn mixed_vgpu_types_may_not_overbook_the_card() {
        let (q4, q2, q1) = (
            typed(&resolved("RTX2070-4Q", 4096, 2)),
            typed(&resolved("RTX2070-2Q", 2048, 4)),
            typed(&resolved("RTX2070-1Q", 1024, 8)),
        );
        refuse_card_overcommit(&[&q4, &q2], &q2, &device()).expect("4096 + 2048 + 2048 fits");
        let said = refuse_card_overcommit(&[&q4, &q2, &q2], &q1, &device())
            .expect_err("the card is full")
            .to_string();
        assert!(said.contains("8192 MiB"), "{said}");
    }

    /// A cap counts against the card like a profile once vGPU types share it.
    #[test]
    fn a_capped_backend_counts_against_the_card_beside_vgpu_types() {
        let q4 = typed(&resolved("RTX2070-4Q", 4096, 2));
        refuse_card_overcommit(&[&q4], &capped(4096), &device()).expect("exactly the card");
        refuse_card_overcommit(&[&q4], &capped(4097), &device()).expect_err("one MiB over");
    }

    /// A backend that may take the whole card cannot join vGPU-typed ones.
    #[test]
    fn an_unlimited_backend_is_refused_beside_vgpu_types() {
        let q2 = typed(&resolved("RTX2070-2Q", 2048, 4));
        let unlimited = Claim::of(&NvrmParams::default(), None);
        let said = refuse_card_overcommit(&[&q2], &unlimited, &device())
            .expect_err("it could take what the 2Q was promised")
            .to_string();
        assert!(said.contains("no VRAM limit"), "{said}");
    }

    /// And a vGPU type cannot promise its profile beside an unlimited backend.
    #[test]
    fn a_vgpu_type_is_refused_beside_an_unlimited_backend() {
        let unlimited = Claim::of(&NvrmParams::default(), None);
        let q2 = typed(&resolved("RTX2070-2Q", 2048, 4));
        let said = refuse_card_overcommit(&[&unlimited], &q2, &device())
            .expect_err("the running backend could take the profile")
            .to_string();
        assert!(said.contains("without a VRAM limit"), "{said}");
    }

    /// Without any vGPU type the card size is unknown; only the budget applies.
    #[test]
    fn without_a_vgpu_type_the_card_rule_does_not_apply() {
        refuse_card_overcommit(&[&capped(6000)], &capped(6000), &device())
            .expect("no card size to measure against");
        refuse_budget_overrun(&[&capped(6000)], &capped(6000), Some(8192), &device())
            .expect_err("but a budget still holds");
    }

    /// A `vgpuprofile` that does not print the card size cannot be admitted against.
    #[test]
    fn select_output_without_the_card_size_is_refused() {
        let out = "vgpu_type=RTX2070-4Q\nvgpu_profile_mib=4096\nvgpu_fb_mib=2816\n\
                   vgpu_max_instance=2\nvgpu_encoder_cap=50\n";
        let said = parse_vgpu_select(out)
            .expect_err("unknown card size")
            .to_string();
        assert!(said.contains("vgpu_available_mib"), "{said}");
    }

    #[test]
    fn vgpu_resolution_lands_in_env() {
        let vgpu = VgpuType {
            vgpu_type: "RTX2070-4Q".into(),
            profile_mib: 4096,
            fb_mib: 2816,
            max_instance: 2,
            encoder_cap: 50,
            available_mib: 8192,
        };
        let env = NvrmDriver::backend_env(&NvrmParams::default(), Some(&vgpu))
            .expect("nothing argues with anything");
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
                available_mib: 8192,
            }
        );
        assert!(parse_vgpu_select("prose only, no keys\n").is_err());
    }
}
