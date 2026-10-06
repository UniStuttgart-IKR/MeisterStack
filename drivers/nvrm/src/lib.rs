// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! NVIDIA paravirtualization through `vhost-user-nvrm`.
//!
//! Each device has a backend process and a stable socket path. `vgpuprofile`
//! resolves configured vGPU types; node configuration supplies resource limits
//! and privileged backend options.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::time::Duration;

use agent_api::CgroupHandle;
use agent_api::device::{
    self, ClaimedDevice, Device, DeviceAttachment, DeviceDriver, DeviceError, DeviceId, DeviceSpec,
    PartitionSpec,
};
use anyhow::Context;
use backend::{Backend, BackendIo, BackendKind};
use tokio::sync::Mutex;
use tracing::{debug, error, info, instrument, warn};

mod admission;
mod ledger;
mod paths;
mod strays;
mod vgpu;

use admission::{Claim, Wanted};
use ledger::{Existing, Ledger, Reservation};
pub use vgpu::VgpuType;

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

/// `vgpuprofile`'s host reserve, written from `vgpu_host_reserve_mib`.
const HOST_RESERVE_ENV: &str = "LEA_VGPU_HOST_RESERVE_MIB";

/// Variables derived from typed parameters or vGPU resolution. Reject them
/// in the extra environment even when this device did not emit that variable,
/// so backend settings cannot bypass admission accounting.
const DRIVER_OWNED_ENV: [&str; 10] = [
    "LEA_VRAM_LIMIT_MIB",
    "LEA_VRAM_PROFILE_MIB",
    "LEA_VRAM_RESERVE_MIB",
    "LEA_MANAGED_COMPAT",
    "LEA_ADMIN_PRIV",
    "LEA_VGPU_TYPE",
    "LEA_VGPU_PROFILE_MIB",
    "LEA_VGPU_FB_MIB",
    "LEA_VGPU_ENCODER_CAP",
    HOST_RESERVE_ENV,
];

/// Leandro's test and diagnostic switches: `LEA_TEST_*` injects faults,
/// `LEA_TRACE_*` and `LEA_CAPTURE_DIR` write guest requests to files of their
/// own naming. They are for a lab run by hand, never for a node's backends.
const DIAGNOSTIC_ENV: [&str; 3] = ["LEA_TEST_", "LEA_TRACE_", "LEA_CAPTURE_DIR"];

/// Only `vgpu_type` may be supplied through tenant device parameters.
/// Other options come from node defaults or operator-defined profiles.
/// The agent validates this rule at admission and the driver repeats it at use.
pub const TENANT_SETTABLE_PARAMS: [&str; 1] = ["vgpu_type"];

/// Reject parameters reserved for node configuration, naming the rejected key.
pub fn refuse_operator_only_params(params: &serde_json::Value) -> Result<(), String> {
    device::refuse_params_outside("nvrm", &TENANT_SETTABLE_PARAMS, params)
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

    /// What a backend started from these parameters counts as on the card.
    fn claim(&self, vgpu: Option<&VgpuType>) -> Claim {
        Claim::new(self.admitted_mib(vgpu), vgpu)
    }

    fn validate(&self) -> device::Result<()> {
        self.refuse_two_vram_policies()?;
        self.refuse_reserved_env()
    }

    /// Checked with the rest of the configuration so a node config naming a
    /// refused variable fails when the driver is built, not at the first boot.
    fn refuse_reserved_env(&self) -> device::Result<()> {
        let mut keys: Vec<&str> = self.env.keys().map(String::as_str).collect();
        keys.sort_unstable();
        keys.into_iter().try_for_each(refuse_reserved_env_key)
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

/// Default wait for a spawned backend's socket-file readiness, shared with agent config.
pub const DEFAULT_SOCKET_TIMEOUT_MS: u64 = 5000;

pub struct NvrmDriverConfig {
    pub binary: PathBuf,
    pub vgpuprofile_bin: PathBuf,
    pub run_dir: PathBuf,
    pub socket_timeout: Duration,
    /// Optional VRAM budget over the nvrm devices of every vm on record on
    /// this node, running or stopped.
    pub vram_budget_mib: Option<u64>,
    /// The host's share of the card in MiB, handed to `vgpuprofile`. Required
    /// once any vGPU type is configured or requested; see
    /// [`NvrmDriverConfig::host_reserve`].
    pub vgpu_host_reserve_mib: Option<u64>,
    pub defaults: NvrmParams,
    pub profiles: HashMap<String, NvrmParams>,
    /// Optional backend user. The account needs access to the configured NVIDIA
    /// device nodes; identity switching does not grant that access. Node parameters
    /// control whether the backend requests administrative privileges.
    pub vmm_user: Option<agent_api::VmmUser>,
}

pub struct NvrmDriver {
    config: NvrmDriverConfig,
    /// One backend serves one VM, in a session of its own, and is signalled
    /// as a process GROUP. See `BackendKind::detached`.
    process: BackendKind,
    vgpu_cache: Mutex<HashMap<String, VgpuType>>,
    /// The backends this instance started. Admission counts the agent's
    /// records first; see [`ledger`]. Held for no await, so a reservation
    /// can give its place back from a destructor.
    ledger: std::sync::Mutex<Ledger>,
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

        // Configuration first: an error in it names itself without the
        // driver having asked the card anything.
        config.validate()?;

        host_checks();

        // Resolve every configured vGPU type once, fail-fast at agent start:
        // an unknown type is a config error, not something to discover at the
        // first VM boot.
        let cache = config.resolve_profile_types()?;
        Ok(Self::assemble(config, cache))
    }

    /// The driver over a checked configuration and the types already
    /// resolved for it. Asks the host nothing.
    fn assemble(config: NvrmDriverConfig, cache: HashMap<String, VgpuType>) -> Self {
        // The name is the backend's own and not the configured binary's:
        // `--nvrm` is Leandro's binary whatever a node has called the file
        // it lives in, and `comm` is what the process calls itself.
        let process = BackendKind::detached("vhost-user-nvrm", "vhost-user-nvrm", NOFILE_LIMIT)
            .as_user(config.vmm_user.clone());
        Self {
            process,
            config,
            vgpu_cache: Mutex::new(cache),
            ledger: std::sync::Mutex::new(Ledger::default()),
        }
    }
}

impl NvrmDriverConfig {
    /// Check the defaults, every profile layered over them, and that a host
    /// reserve is configured once any of them names a vGPU type.
    fn validate(&self) -> device::Result<()> {
        self.defaults
            .validate()
            .map_err(|e| DeviceError::InvalidSpec(format!("nvrm defaults are invalid: {e}")))?;
        for (name, params) in &self.profiles {
            self.defaults.overlay(params).validate().map_err(|e| {
                DeviceError::InvalidSpec(format!("nvrm profile {name:?} is invalid: {e}"))
            })?;
        }
        if self.names_a_vgpu_type() {
            self.host_reserve()?;
        }
        Ok(())
    }

    fn names_a_vgpu_type(&self) -> bool {
        self.defaults.vgpu_type.is_some() || self.profiles.values().any(|p| p.vgpu_type.is_some())
    }

    /// Unset, `vgpuprofile` counts whatever the card holds at that moment as
    /// the host's share. After an agent restart that includes the backends of
    /// running guests, so the same type resolves smaller or not at all, and
    /// admission would measure against another card than the one those guests
    /// were admitted to. A fixed reserve makes every resolution the same.
    fn host_reserve(&self) -> device::Result<u64> {
        self.vgpu_host_reserve_mib.ok_or_else(|| {
            DeviceError::InvalidSpec(
                "a vgpu_type needs [device.nvrm].vgpu_host_reserve_mib: without it vgpuprofile \
                 counts what the card holds at the moment, running guests included, as the \
                 host's share and resolves a different card after every restart"
                    .into(),
            )
        })
    }

    /// Resolve the vGPU type of every profile against the card, once per type.
    fn resolve_profile_types(&self) -> device::Result<HashMap<String, VgpuType>> {
        let mut cache = HashMap::new();
        for (name, params) in &self.profiles {
            let Some(vtype) = self.defaults.overlay(params).vgpu_type else {
                continue;
            };
            if cache.contains_key(&vtype) {
                continue;
            }
            let resolved = resolve_vgpu_type(&self.vgpuprofile_bin, self.host_reserve()?, &vtype)
                .map_err(|e| {
                DeviceError::InvalidSpec(format!(
                    "nvrm profile {name:?}: vgpu_type {vtype:?}: {e:#}"
                ))
            })?;
            info!(profile = %name, vgpu_type = %vtype,
                  profile_mib = resolved.profile_mib, fb_mib = resolved.fb_mib,
                  max_instance = resolved.max_instance,
                  "vgpu type resolved against this card");
            cache.insert(vtype, resolved);
        }
        Ok(cache)
    }

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
        if merged.vgpu_type.is_some() {
            self.host_reserve()?;
        }
        Ok(merged)
    }
}

impl NvrmDriver {
    fn socket_path(&self, id: &DeviceId) -> PathBuf {
        paths::socket_file(&self.config.run_dir, id)
    }

    fn log_path(&self, id: &DeviceId) -> PathBuf {
        paths::log_file(&self.config.run_dir, id)
    }

    fn attachment(socket: PathBuf, pid: u32) -> DeviceAttachment {
        DeviceAttachment::VhostUser {
            socket,
            pid,
            device_type: VIRTIO_ID_NVRM,
            queue_sizes: NVRM_QUEUE_SIZES.to_vec(),
        }
    }

    /// The resolved vGPU type the parameters name, from the cache or the card.
    async fn resolve(&self, params: &NvrmParams) -> device::Result<Option<VgpuType>> {
        let Some(vtype) = &params.vgpu_type else {
            return Ok(None);
        };
        // Release the cache lock before the external query. Concurrent misses may
        // resolve the same type twice and then store the same result.
        let cached = self.vgpu_cache.lock().await.get(vtype).cloned();
        if let Some(vgpu) = cached {
            return Ok(Some(vgpu));
        }
        // Per-VM params may name a type no profile pre-resolved.
        let reserve = self.config.host_reserve()?;
        let resolved = resolve_vgpu_type_async(&self.config.vgpuprofile_bin, reserve, vtype)
            .await
            .map_err(|e| DeviceError::InvalidSpec(format!("{e:#}")))?;
        self.vgpu_cache
            .lock()
            .await
            .insert(vtype.clone(), resolved.clone());
        Ok(Some(resolved))
    }

    fn ledger(&self) -> std::sync::MutexGuard<'_, Ledger> {
        ledger::lock(&self.ledger)
    }

    /// Put a spawned backend on the ledger in place of its start.
    async fn enter_started(
        &self,
        id: &DeviceId,
        start: Reservation<'_>,
        child: Backend,
    ) -> device::Result<()> {
        if let Some(child) = start.commit(child) {
            self.process.stop(child).await;
            return Err(DeviceError::Backend(anyhow::anyhow!(
                "device {id} was destroyed while its backend started"
            )));
        }
        Ok(())
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
            refuse_reserved_env_key(k)?;
            env.push((k.clone(), v.clone()));
        }
        Ok(env)
    }
}

/// Refuse an extra backend variable this driver or the process owns, or a
/// diagnostic switch that does not belong on a production backend.
fn refuse_reserved_env_key(k: &str) -> device::Result<()> {
    // Reject process-control environment keys such as PATH and LD_PRELOAD.
    if PROTECTED_ENV.iter().any(|p| k.starts_with(p)) {
        return Err(DeviceError::InvalidSpec(format!(
            "nvrm env {k:?} is part of the process's own environment and cannot be set \
             here; [{}] are refused",
            PROTECTED_ENV.join(", ")
        )));
    }
    if DRIVER_OWNED_ENV.contains(&k) {
        return Err(DeviceError::InvalidSpec(format!(
            "nvrm env {k:?} is written from a typed field; set the field and not the \
             variable, so that what this node admitted is what the backend runs with"
        )));
    }
    if DIAGNOSTIC_ENV.iter().any(|p| k.starts_with(p)) {
        return Err(DeviceError::InvalidSpec(format!(
            "nvrm env {k:?} is a test or capture switch of the backend; [{}] inject faults \
             or write guest requests to files, and a node does not run guests with them",
            DIAGNOSTIC_ENV.join(", ")
        )));
    }
    Ok(())
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
fn resolve_vgpu_type(bin: &Path, host_reserve_mib: u64, vtype: &str) -> anyhow::Result<VgpuType> {
    let out = vgpuprofile_select(bin, host_reserve_mib, vtype)
        .output()
        .with_context(|| format!("running {}", bin.display()))?;
    vgpu_from_output(vtype, &out)
}

/// Resolve vGPU types asynchronously so GPU queries do not block a Tokio worker.
async fn resolve_vgpu_type_async(
    bin: &Path,
    host_reserve_mib: u64,
    vtype: &str,
) -> anyhow::Result<VgpuType> {
    let out = tokio::process::Command::from(vgpuprofile_select(bin, host_reserve_mib, vtype))
        .output()
        .await
        .with_context(|| format!("running {}", bin.display()))?;
    vgpu_from_output(vtype, &out)
}

/// `vgpuprofile --select <type>` with the node's host reserve and none of the
/// agent's own environment, so a type resolves the same way on every start.
fn vgpuprofile_select(bin: &Path, host_reserve_mib: u64, vtype: &str) -> std::process::Command {
    let mut cmd = std::process::Command::new(bin);
    cmd.args(["--select", vtype])
        .env_clear()
        .envs(inherited_env())
        .env(HOST_RESERVE_ENV, host_reserve_mib.to_string());
    cmd
}

/// What a helper or backend keeps of the agent's environment: PATH and HOME,
/// nothing that could steer it.
fn inherited_env() -> impl Iterator<Item = (String, String)> {
    std::env::vars().filter(|(k, _)| k == "PATH" || k == "HOME")
}

fn vgpu_from_output(vtype: &str, out: &std::process::Output) -> anyhow::Result<VgpuType> {
    if !out.status.success() {
        anyhow::bail!(
            "vgpuprofile --select {vtype} failed ({}): {}",
            out.status,
            stderr_excerpt(&out.stderr)
        );
    }
    vgpu::parse_vgpu_select(&String::from_utf8_lossy(&out.stdout))
}

/// The start of what the helper wrote to stderr, which is where its reason
/// is: a driver-version panic, or the types the card does offer.
fn stderr_excerpt(stderr: &[u8]) -> String {
    const LIMIT: usize = 2048;
    let said = String::from_utf8_lossy(stderr);
    let said = said.trim();
    if said.is_empty() {
        return "it wrote nothing to stderr".into();
    }
    match said.char_indices().nth(LIMIT) {
        Some((cut, _)) => format!("{}...", &said[..cut]),
        None => said.to_string(),
    }
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
        let existing = self.ledger().existing(id, &socket)?;
        match existing {
            Existing::Serving(pid) => {
                return Ok(Device {
                    id: *id,
                    attachment: Self::attachment(socket, pid),
                });
            }
            // Its replacement binds the same socket and must not run beside it.
            Existing::Stale(child) => self.process.stop(child).await,
            Existing::Nothing => self.refuse_backend_not_started_here(id, &socket)?,
        }

        let (params, vgpu) = self.sized(spec).await?;
        let env = Self::backend_env(&params, vgpu.as_ref())?;

        // Count the same effective parameters used to build the backend environment.
        let claim = params.claim(vgpu.as_ref());
        let admitted_mib = claim.mib;
        // Given back if the spawn fails or this future is dropped mid-spawn.
        let start = Reservation::hold(&self.ledger, id, claim)?;

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
            .envs(inherited_env())
            .envs(env);

        // The backend must be listening before cloud-hypervisor connects.
        let spawned = self
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
            .await;
        let (pid, child) = spawned?;
        info!(pid, admitted_mib, "nvrm backend ready");
        self.enter_started(id, start, child).await?;

        Ok(Device {
            id: *id,
            attachment: Self::attachment(socket, pid),
        })
    }

    #[instrument(skip_all, fields(device_id = %id))]
    async fn destroy(&self, id: &DeviceId, attachment: &DeviceAttachment) -> device::Result<()> {
        let child = self.ledger().forget(id);

        match child {
            Some(child) => self.process.stop(child).await,
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

    /// Refuse a request the backend would reject, or the card cannot hold
    /// beside the devices of every other vm record on this node, before the
    /// agent records or starts anything for it.
    ///
    /// The records are the agent's store, which no backend can write and
    /// which outlives an agent restart; a stopped vm keeps its share, so it
    /// can always start again. Starts this driver has under way that no
    /// record shows yet count as well.
    async fn admit(
        &self,
        requested: &[(DeviceId, DeviceSpec)],
        claimed: &[ClaimedDevice],
    ) -> device::Result<()> {
        let mut wanted = Vec::with_capacity(requested.len());
        for (id, spec) in requested {
            wanted.push(
                self.wanted(id, spec)
                    .await
                    .map_err(|e| naming_the_device(id, e))?,
            );
        }
        let mut held = Vec::with_capacity(claimed.len());
        for device in claimed {
            held.push(self.recorded_claim(device).await?);
        }
        let recorded: HashSet<DeviceId> = claimed
            .iter()
            .map(|d| d.id)
            .chain(requested.iter().map(|(id, _)| *id))
            .collect();
        let started = {
            let mut ledger = self.ledger();
            held.extend(ledger.unrecorded(&recorded));
            ledger.devices()
        };
        self.refuse_beside_strays(&recorded.union(&started).copied().collect())?;
        admission::admit_all(held, &wanted, self.config.vram_budget_mib)
    }
}

impl NvrmDriver {
    /// Refuse while a backend runs that neither a record nor this driver
    /// accounts for: its share of the card is unknown. Sockets nothing
    /// serves any more are cleared on the way; see [`strays`].
    fn refuse_beside_strays(&self, accounted: &HashSet<DeviceId>) -> device::Result<()> {
        let found =
            strays::strays(&self.config.run_dir, accounted, &self.process).map_err(|e| {
                DeviceError::Backend(
                    anyhow::Error::new(e).context("telling which nvrm backends run on this node"),
                )
            })?;
        if found.is_empty() {
            return Ok(());
        }
        Err(DeviceError::InvalidSpec(
            "an nvrm backend runs on this node for a device no vm record names, so its share of \
             the card is unknown and no nvrm device is admitted beside it; the agent log names \
             it for an operator"
                .into(),
        ))
    }

    /// A backend already serving this device's socket that this driver did
    /// not start (one that outlived an agent restart) is not started twice:
    /// the second would bind its socket while the first still holds its share.
    fn refuse_backend_not_started_here(&self, id: &DeviceId, socket: &Path) -> device::Result<()> {
        let serving = self.process.find_serving(socket).map_err(|e| {
            DeviceError::Backend(
                anyhow::Error::new(e).context(format!("looking for a backend of device {id}")),
            )
        })?;
        match serving {
            None => Ok(()),
            Some(pid) => Err(DeviceError::Backend(anyhow::anyhow!(
                "device {id} already has a backend running (pid {pid}) that this agent did not \
                 start; it is not started a second time"
            ))),
        }
    }

    /// A spec's effective parameters and the vGPU type they resolve to.
    async fn sized(&self, spec: &DeviceSpec) -> device::Result<(NvrmParams, Option<VgpuType>)> {
        let params = self.config.effective_params(spec)?;
        let vgpu = self.resolve(&params).await?;
        Ok((params, vgpu))
    }

    /// What a requested device would count as on the card.
    async fn wanted(&self, id: &DeviceId, spec: &DeviceSpec) -> device::Result<Wanted> {
        let (params, vgpu) = self.sized(spec).await?;
        Ok(Wanted {
            id: *id,
            claim: params.claim(vgpu.as_ref()),
            vgpu,
        })
    }

    /// What another vm's recorded device counts as. One whose share cannot
    /// be worked out from today's configuration (a profile since removed, a
    /// type the card no longer offers) could hold anything, so nothing is
    /// admitted beside it. Which vm and why goes to the operator's log; the
    /// refusal a tenant reads does not name another tenant's vm.
    async fn recorded_claim(&self, device: &ClaimedDevice) -> device::Result<Claim> {
        match self.sized(&device.spec).await {
            Ok((params, vgpu)) => Ok(params.claim(vgpu.as_ref())),
            Err(why) => {
                warn!(vm_id = %device.vm, device_id = %device.id, reason = %why,
                      "a recorded nvrm device cannot be accounted for; admitting no nvrm \
                       device on this node until its record or the configuration is corrected");
                Err(DeviceError::InvalidSpec(
                    "this node holds an nvrm device whose share of the card it cannot work out \
                     from its configuration, so it admits no other; the agent log names the \
                     device and the reason"
                        .into(),
                ))
            }
        }
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
    use admission::tests::resolved;

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
            vgpu_host_reserve_mib: None,
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

    fn with_profile(mut node: NvrmDriverConfig, name: &str, vgpu_type: &str) -> NvrmDriverConfig {
        node.profiles.insert(name.into(), configured(vgpu_type));
        node
    }

    /// IKR-B15: a node that configures a vGPU type must fix the host's share
    /// of the card, or every restart beside running guests resolves another card.
    #[test]
    fn a_configured_vgpu_type_requires_a_host_reserve() {
        let node = with_profile(node(serde_json::json!({})), "4q", "4Q");
        let said = node.validate().expect_err("no reserve").to_string();
        assert!(said.contains("vgpu_host_reserve_mib"), "{said}");

        let reserved = NvrmDriverConfig {
            vgpu_host_reserve_mib: Some(1024),
            ..node
        };
        reserved.validate().expect("a fixed reserve");
    }

    /// A tenant's vGPU type on a node without a reserve is refused at admission
    /// rather than resolved against whatever the card holds at that moment.
    #[test]
    fn a_requested_vgpu_type_without_a_host_reserve_is_refused() {
        let node = node(serde_json::json!({}));
        let spec = mediated(serde_json::json!({ "vgpu_type": "2Q" }));
        let said = node
            .effective_params(&spec)
            .expect_err("no reserve to resolve with")
            .to_string();
        assert!(said.contains("vgpu_host_reserve_mib"), "{said}");
    }

    /// The helper sees the configured reserve and none of the agent's own
    /// LEA_ settings, so resolution does not depend on how the agent was started.
    #[test]
    fn vgpuprofile_runs_with_the_configured_reserve_only() {
        let cmd = vgpuprofile_select(Path::new("/nonexistent/vgpuprofile"), 1024, "4Q");
        let set: Vec<(String, Option<String>)> = cmd
            .get_envs()
            .map(|(k, v)| {
                let value = v.map(|v| v.to_string_lossy().into_owned());
                (k.to_string_lossy().into_owned(), value)
            })
            .collect();
        assert!(
            set.contains(&(HOST_RESERVE_ENV.to_string(), Some("1024".to_string()))),
            "{set:?}"
        );
        let others: Vec<&String> = set
            .iter()
            .map(|(k, _)| k)
            .filter(|k| {
                k.as_str() != HOST_RESERVE_ENV && k.as_str() != "PATH" && k.as_str() != "HOME"
            })
            .collect();
        assert!(
            others.is_empty(),
            "only PATH and HOME are inherited: {others:?}"
        );
    }

    /// A failed resolution carries the helper's own reason from stderr.
    #[test]
    fn a_failed_resolution_says_what_vgpuprofile_said() {
        use std::os::unix::process::ExitStatusExt;
        let out = std::process::Output {
            status: std::process::ExitStatus::from_raw(1 << 8),
            stdout: Vec::new(),
            stderr: b"vgpuprofile: no type or size \"9Q\" on this card. It offers:\n".to_vec(),
        };
        let said = vgpu_from_output("9Q", &out)
            .expect_err("exit 1")
            .to_string();
        assert!(said.contains("no type or size \"9Q\""), "{said}");
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

    /// IKR-B16: fault injection and request capture never reach a backend.
    #[test]
    fn diagnostic_switches_are_not_backend_knobs() {
        for key in [
            "LEA_TEST_SHMEM_MAP_OOB",
            "LEA_TRACE_FILE",
            "LEA_TRACE_DUMP",
            "LEA_CAPTURE_DIR",
        ] {
            let params = p(serde_json::json!({ "env": { key: "1" } }));
            let said = NvrmDriver::backend_env(&params, None)
                .err()
                .unwrap_or_else(|| panic!("{key} must be refused"))
                .to_string();
            assert!(said.contains(key), "the refusal names it: {said}");
        }
    }

    /// A refused variable in node configuration fails validation, so the
    /// driver reports it when it is built; an ordinary knob still passes.
    #[test]
    fn node_config_with_a_refused_variable_does_not_validate() {
        let capture = p(serde_json::json!({ "env": { "LEA_CAPTURE_DIR": "/tmp/x" } }));
        let said = capture.validate().expect_err("capture switch").to_string();
        assert!(said.contains("LEA_CAPTURE_DIR"), "{said}");

        let debug = p(serde_json::json!({ "env": { "LEA_DEBUG": "1" } }));
        debug.validate().expect("LEA_DEBUG is an ordinary knob");
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
            let running = configured(spelling).claim(Some(&card_4q));
            assert_eq!(running.vgpu_type.as_deref(), Some("RTX2070-4Q"));
            let another = Wanted {
                id: DeviceId::new_v4(),
                claim: running.clone(),
                vgpu: Some(card_4q.clone()),
            };
            let said = admission::admit_all(vec![running], &[another], None)
                .expect_err("the card holds one 4Q, whatever the first was called")
                .to_string();
            assert!(said.contains("allows 1 instance"), "{spelling}: {said}");
        }
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

    /// A driver over `run_dir` whose `8q` and `1q` profiles are already
    /// resolved against the fixture card. Built without asking the host
    /// anything, as `new` would after resolving them.
    fn driver_in(run_dir: &Path) -> NvrmDriver {
        NvrmDriver::assemble(node_in(run_dir), the_card())
    }

    fn node_in(run_dir: &Path) -> NvrmDriverConfig {
        let mut config = node(serde_json::json!({}));
        config.run_dir = run_dir.to_path_buf();
        config.vgpu_host_reserve_mib = Some(1024);
        config.profiles.insert("8q".into(), configured("8Q"));
        config.profiles.insert("1q".into(), configured("1Q"));
        config
    }

    /// The `8Q` and `1Q` the fixture card resolves to.
    fn the_card() -> HashMap<String, VgpuType> {
        HashMap::from([
            ("8Q".to_string(), resolved("RTX2070-8Q", 8192, 1)),
            ("1Q".to_string(), resolved("RTX2070-1Q", 1024, 8)),
        ])
    }

    fn profiled(profile: &str) -> DeviceSpec {
        DeviceSpec {
            driver: "nvrm".into(),
            partition: PartitionSpec::Mediated,
            profile: Some(profile.into()),
            params: None,
        }
    }

    /// Another vm's record naming `spec`, as the agent's store hands it over.
    fn recorded(spec: DeviceSpec) -> ClaimedDevice {
        ClaimedDevice {
            vm: agent_api::VmId::new_v4(),
            id: DeviceId::new_v4(),
            spec,
        }
    }

    fn requested(spec: DeviceSpec) -> Vec<(DeviceId, DeviceSpec)> {
        vec![(DeviceId::new_v4(), spec)]
    }

    fn run_dir() -> tempfile::TempDir {
        tempfile::Builder::new()
            .prefix("meister-nvrm-")
            .tempdir()
            .expect("a temp dir")
    }

    /// IKR-B30 without claim files: a driver that has just started knows no
    /// backend, and still refuses what the vms on record would not leave room
    /// for, because admission counts the agent's records and not its own memory.
    #[tokio::test]
    async fn every_vm_on_record_counts_against_the_card_after_a_restart() {
        let dir = run_dir();
        let fresh = driver_in(dir.path());
        let held = [recorded(profiled("8q"))];
        let said = fresh
            .admit(&requested(profiled("1q")), &held)
            .await
            .expect_err("the 8Q on record fills the card")
            .to_string();
        assert!(said.contains("8192 MiB admitted"), "{said}");
        fresh
            .admit(&requested(profiled("1q")), &[])
            .await
            .expect("with no record the card is free");
    }

    /// A record whose share cannot be worked out any more could hold
    /// anything; nothing is admitted beside it, and the refusal does not
    /// name the other tenant's vm.
    #[tokio::test]
    async fn a_record_of_unknown_size_admits_nothing_beside_it() {
        let dir = run_dir();
        let driver = driver_in(dir.path());
        let gone = recorded(profiled("a-profile-since-removed"));
        let said = driver
            .admit(&requested(profiled("1q")), std::slice::from_ref(&gone))
            .await
            .expect_err("unknown is not zero")
            .to_string();
        assert!(said.contains("cannot work out"), "{said}");
        assert!(!said.contains(&gone.vm.to_string()), "{said}");
    }

    /// R2-1: the run directory is the backend user's to write, and files at
    /// the paths claim records once had are read by nobody. A FIFO there does
    /// not hang admission or teardown, a symlink is not followed, and a forged
    /// claim neither frees nor fills the card.
    #[tokio::test]
    async fn files_at_the_old_claim_paths_neither_block_nor_change_admission() {
        let dir = run_dir();
        let elsewhere = run_dir();
        let (fifo_owner, forged_owner) = (DeviceId::new_v4(), DeviceId::new_v4());
        let at = |id: &DeviceId, extension: &str| dir.path().join(format!("{id}.{extension}"));
        nix::unistd::mkfifo(
            &at(&fifo_owner, "claim"),
            nix::sys::stat::Mode::from_bits_truncate(0o600),
        )
        .expect("a fifo");
        let target = elsewhere.path().join("victim");
        std::fs::write(&target, b"untouched").expect("a file to aim at");
        std::os::unix::fs::symlink(&target, at(&fifo_owner, "claim.tmp")).expect("a symlink");
        std::fs::write(
            at(&forged_owner, "claim"),
            br#"{"pid":1,"claim":{"mib":0,"vgpu_type":null,"card_mib":null}}"#,
        )
        .expect("a forged claim");

        let driver = driver_in(dir.path());
        let bounded = |work| tokio::time::timeout(Duration::from_secs(10), work);
        let (one_1q, one_8q) = (requested(profiled("1q")), requested(profiled("8q")));
        let held = [recorded(profiled("8q"))];
        bounded(driver.admit(&one_1q, &held))
            .await
            .expect("admission does not wait on a fifo")
            .expect_err("a forged empty claim does not free the card");
        bounded(driver.admit(&one_8q, &[]))
            .await
            .expect("admission does not wait on a fifo")
            .expect("nor does anything in the directory fill it");

        let attachment = NvrmDriver::attachment(at(&fifo_owner, "sock"), u32::MAX);
        bounded(driver.destroy(&fifo_owner, &attachment))
            .await
            .expect("teardown does not wait on a fifo")
            .expect("destroyed");
        assert_eq!(
            std::fs::read(&target).expect("still there"),
            b"untouched",
            "no write went through the symlink"
        );
    }

    /// A backend that says it runs, by writing its pid into `started` (a
    /// FIFO, so the write waits for the test to read it), and then never
    /// binds its socket.
    fn never_ready_backend(dir: &Path, started: &Path) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let binary = dir.join("vhost-user-nvrm");
        let script = format!(
            "#!/bin/sh\necho $$ > '{}'\nexec sleep 600\n",
            started.display()
        );
        std::fs::write(&binary, script).expect("a fake backend");
        std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o755))
            .expect("executable");
        binary
    }

    /// R2-3: a create whose future is dropped while its backend is being
    /// spawned (a client that hung up, a cancelled request) gives the device's
    /// place on the ledger back and kills the backend it had started, instead
    /// of leaving a phantom start that refuses every later one and a process
    /// nobody counts.
    #[tokio::test]
    async fn a_create_dropped_mid_spawn_gives_its_place_back_and_stops_its_backend() {
        let dir = run_dir();
        let started = dir.path().join("started");
        nix::unistd::mkfifo(&started, nix::sys::stat::Mode::from_bits_truncate(0o600))
            .expect("a fifo");
        let mut config = node_in(&dir.path().join("run"));
        config.binary = never_ready_backend(dir.path(), &started);
        config.socket_timeout = Duration::from_secs(600);
        std::fs::create_dir_all(&config.run_dir).expect("a run dir");
        let driver = NvrmDriver::assemble(config, the_card());
        let (id, spec) = (DeviceId::new_v4(), profiled("1q"));

        let pid: i32 = tokio::select! {
            said = tokio::fs::read_to_string(&started) => {
                said.expect("the backend runs").trim().parse().expect("its pid")
            }
            created = driver.create(&id, &spec, None) => {
                let _ = std::fs::write(&started, b"");
                panic!("this backend never binds its socket: {created:?}")
            }
        };

        assert!(
            driver.ledger().unrecorded(&HashSet::new()).is_empty(),
            "the dropped start counts for nothing"
        );
        let socket = driver.socket_path(&id);
        assert!(
            matches!(
                driver.ledger().existing(&id, &socket),
                Ok(Existing::Nothing)
            ),
            "no start of this device is under way any more"
        );

        let exited = tokio::task::spawn_blocking(move || {
            use nix::sys::wait::{Id, WaitPidFlag, waitid};
            // WNOWAIT: wait for the exit and leave reaping to the runtime.
            waitid(
                Id::Pid(nix::unistd::Pid::from_raw(pid)),
                WaitPidFlag::WEXITED | WaitPidFlag::WNOWAIT,
            )
        });
        let Ok(exited) = tokio::time::timeout(Duration::from_secs(10), exited).await else {
            // Ends the wait above, so the failure is reported now and not
            // when the fake backend's own sleep runs out.
            let _ = nix::sys::signal::kill(
                nix::unistd::Pid::from_raw(pid),
                nix::sys::signal::Signal::SIGKILL,
            );
            panic!("the abandoned backend is still running");
        };
        let exited = exited.expect("the wait ran");
        assert!(
            matches!(
                exited,
                Ok(nix::sys::wait::WaitStatus::Signaled(..)) | Err(nix::errno::Errno::ECHILD)
            ),
            "{exited:?}"
        );
    }

    /// A process that passes for this device's backend: named
    /// `vhost-user-nvrm`, with the socket on its command line, and waiting
    /// on its stdin until the test kills it.
    fn a_backend_nobody_started(dir: &Path, socket: &Path) -> std::process::Child {
        use std::os::unix::fs::PermissionsExt;
        let binary = dir.join("vhost-user-nvrm");
        std::fs::write(&binary, "#!/bin/sh\nread never\n").expect("a fake backend");
        std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o755))
            .expect("executable");
        std::fs::write(socket, b"").expect("a socket stand-in");
        std::process::Command::new(&binary)
            .arg("--nvrm")
            .arg(socket)
            .stdin(std::process::Stdio::piped())
            .spawn()
            .expect("running")
    }

    fn stop(mut backend: std::process::Child) {
        backend.kill().expect("killed");
        backend.wait().expect("reaped");
    }

    /// R2-4: a socket no process serves, for a device nobody accounts for,
    /// is what a backend left behind. It holds nothing, counts nothing and
    /// is cleared away.
    #[tokio::test]
    async fn a_socket_nothing_serves_counts_nothing_and_is_removed() {
        let dir = run_dir();
        let driver = driver_in(dir.path());
        let left_behind = driver.socket_path(&DeviceId::new_v4());
        std::fs::write(&left_behind, b"").expect("a socket stand-in");

        driver
            .admit(&requested(profiled("8q")), &[])
            .await
            .expect("the card is free");
        assert!(!left_behind.exists(), "the stale socket is gone");
    }

    /// R2-4: a backend still running for a device no vm record names holds a
    /// share of the card nobody can say. Nothing is admitted beside it, and
    /// it is left running for an operator to look at, not killed.
    #[tokio::test]
    async fn a_backend_no_record_names_blocks_admission_and_is_left_running() {
        let dir = run_dir();
        let driver = driver_in(dir.path());
        let mut unnamed =
            a_backend_nobody_started(dir.path(), &driver.socket_path(&DeviceId::new_v4()));

        let said = driver
            .admit(&requested(profiled("1q")), &[])
            .await
            .expect_err("its share is unknown")
            .to_string();
        let running = unnamed.try_wait().expect("a status");
        stop(unnamed);
        assert!(said.contains("no vm record names"), "{said}");
        assert!(
            running.is_none(),
            "admission does not kill what it cannot place"
        );
    }

    /// R2-4: the same backend, found when its own device is created, is not
    /// started a second time on its socket.
    #[tokio::test]
    async fn a_device_whose_backend_outlived_the_agent_is_not_started_twice() {
        let dir = run_dir();
        let driver = driver_in(dir.path());
        let id = DeviceId::new_v4();
        let survivor = a_backend_nobody_started(dir.path(), &driver.socket_path(&id));

        let created = driver.create(&id, &profiled("1q"), None).await;
        stop(survivor);
        let said = created.expect_err("one backend per device").to_string();
        assert!(said.contains("not started a second time"), "{said}");
    }
}
