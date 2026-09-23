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

/// Environment variables the extra `env` map may not set, by prefix.
///
/// These are the PROCESS's environment and not the backend's knobs. `LD_`
/// decides which library a process loads; `PATH` and `HOME` are what `create`
/// deliberately carries over from the agent and nothing else; `NVIDIA_`
/// selects the card and the driver's behaviour on it. Astra finding S03,
/// 2026-09-23.
///
/// A prefix list and not an exact one: `LD_PRELOAD` is the famous one and it
/// is not the only one, and a list of names would be a list somebody has to
/// keep up with.
const PROTECTED_ENV: [&str; 4] = ["LD_", "PATH", "HOME", "NVIDIA_"];

/// The `LEA_*` variables this driver writes itself, and which the extra `env`
/// map therefore may not.
///
/// The other half of S03, and a list of NAMES rather than the `LEA_` prefix
/// on purpose: the map exists so that a new backend knob needs no driver
/// change, and refusing the whole prefix would take that away. What may not
/// happen is an `env` entry arguing with a typed field — that is how the
/// number `admit` counted and the number the backend ran with came to be two
/// different things. Every name here is produced from a typed field or from
/// the vGPU resolution, whether or not this particular device produced it:
/// `LEA_VGPU_PROFILE_MIB` set by hand on a device with no vGPU type would be
/// exactly the hole, and "it did not collide" is not a reason to allow it.
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

/// The nvrm params a VM spec may carry.
///
/// Astra finding S03, 2026-09-23: `spec.params` was a free JSON map that
/// deserialised into the whole of [`NvrmParams`] and won over everything the
/// node had configured. Two of those fields are not tunables at all:
/// `admin_priv` makes the backend keep `CAP_SYS_ADMIN`, and `env` is the
/// process environment — which let a VM document set `LEA_VRAM_PROFILE_MIB`
/// to any number it liked, over the top of the value `admit` had just counted
/// against the node's budget, and would have let it set `LD_PRELOAD` if the
/// backend had ever read one.
///
/// So the split is by WHO, not by shape: the node's own configuration
/// (`[device.nvrm] defaults` and `[device.nvrm].profiles.*`, written by
/// whoever runs the node) may say anything, and a spec — which arrives from a
/// tenant through two control planes — may name the vGPU type it wants and
/// nothing else. The profile id in `spec.profile` is the ordinary way to ask
/// for more; it points at a section an operator wrote.
///
/// One list and not a check in three places: the agent refuses a spec that
/// carries anything else while a person is still holding the request
/// (`types::devices_with_ids`), and [`refuse_operator_only_params`] is the
/// same rule at the point of use.
pub const TENANT_SETTABLE_PARAMS: [&str; 1] = ["vgpu_type"];

/// Refuse the nvrm params that only the node's own configuration may carry.
///
/// The sentence names the key and where it belongs, because the answer to
/// "you may not set this" is almost always "an operator can, in the node's
/// config" and a refusal that does not say so sends somebody looking for a
/// bug. See [`TENANT_SETTABLE_PARAMS`].
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

/// Tunables for one backend, merged `defaults < profile < spec.params`.
/// Typed fields are the ones this driver has to reason about (validation,
/// vGPU resolution, admission); `env` passes any LEA_* knob through verbatim,
/// so a new backend knob needs no driver change.
///
/// What a SPEC may carry of this is [`TENANT_SETTABLE_PARAMS`] and no more.
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

    /// What the backend will actually be allowed, in MiB, out of the merged
    /// params it is started from.
    ///
    /// The same order the backend itself reads them in: an explicit cap wins,
    /// then an explicit profile size, then whatever the vGPU type resolved to
    /// on this card. `validate` has already refused a cap and a profile
    /// together, so at most one of the first two is ever set.
    ///
    /// Astra finding S03, 2026-09-23: this used to be the vGPU profile alone,
    /// so a device that named a cap was admitted for one number and run with
    /// another.
    fn admitted_mib(&self, vgpu: Option<&VgpuType>) -> u64 {
        self.vram_limit_mib
            .or(self.vram_profile_mib)
            .or_else(|| vgpu.map(|v| v.profile_mib))
            .unwrap_or(0)
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
    /// Who the backend runs as. `None` is the agent, which is every node that
    /// has ever run this. See `InputDriverConfig::vmm_user`.
    ///
    /// Leandro's backend does not need root, and it is worth saying why
    /// rather than assuming: `settle_admin_privilege` in its `main.rs` DROPS
    /// `CAP_SYS_ADMIN` unless `LEA_ADMIN_PRIV=1` asks for it, with a measured
    /// argument that the capability made the display outcome worse. So it is
    /// already built to run without privilege; what it needs is access to the
    /// device nodes — `/dev/nvidiactl`, `/dev/nvidia<N>`, `/dev/nvidia-uvm`
    /// and `/dev/nvidia-uvm-tools` — and that is a group or a mode on the
    /// node, not anything this driver can grant.
    ///
    /// Its pinning ceiling is `LEA_MAX_PIN_MIB` (default 256 MiB per arena,
    /// an environment variable and not a flag), and the pages are pinned by
    /// the NVIDIA RM through `RmAllocOsDescriptor` rather than by `mlock`, so
    /// `RLIMIT_MEMLOCK` is not what bounds it. Read off Leandro's source and
    /// not measured — this tree has no vGPU-capable card.
    pub vmm_user: Option<agent_api::VmmUser>,
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
            // The same rule the agent applies to the document, applied again
            // where the params are actually used: this is the only door a
            // spec's params come through, and a driver that trusts a caller
            // to have checked is a driver that is one new caller away from
            // not being checked at all. Astra finding S03, 2026-09-23.
            refuse_operator_only_params(params).map_err(DeviceError::InvalidSpec)?;
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
    async fn admit(
        &self,
        id: &DeviceId,
        params: &NvrmParams,
        vgpu: Option<&VgpuType>,
    ) -> device::Result<u64> {
        let active = self.active.lock().await;

        // What this backend will actually be allowed, out of the same merged
        // params the process is started from. Astra finding S03, 2026-09-23:
        // admission used to count the resolved vGPU profile while the process
        // was started with whatever `vram_limit_mib`/`vram_profile_mib` said
        // — two numbers that never had to agree, so a node's budget was a
        // statement about something nobody ran.
        let wants = params.admitted_mib(vgpu);

        if let Some(vgpu) = vgpu {
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
        }

        let used: u64 = active.values().map(|b| b.admitted_mib).sum();
        if let Some(budget) = self.config.vram_budget_mib {
            if used + wants > budget {
                return Err(DeviceError::InvalidSpec(format!(
                    "vram budget exceeded: {used} MiB active + {wants} MiB requested > \
                     {budget} MiB (device {id})"
                )));
            }
        } else if used + wants > 0 {
            debug!(
                used_mib = used,
                requested_mib = wants,
                "no vram budget configured, admitting without a hard check"
            );
        }
        Ok(wants)
    }

    /// The full environment for one backend: the typed fields, the vGPU
    /// resolution, and then whatever else the node's configuration adds.
    ///
    /// Astra finding S03, 2026-09-23: `env` used to WIN over the typed
    /// fields, which made the number `admit` counted and the number the
    /// process ran with two different things. Now a key that a typed field
    /// already wrote is a refusal rather than a silent replacement, so the
    /// admitted budget is the started budget by construction, and the
    /// variables that are the process's environment rather than the backend's
    /// knobs cannot be set at all.
    ///
    /// Extra `LEA_*` keys nothing typed produced are still passed through,
    /// which is what the map is for: a new backend knob needs no driver
    /// change. They come from `[device.nvrm]` on the node and from nowhere
    /// else — a spec carrying `env` is refused two tiers earlier, and again
    /// in `effective_params`.
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
            // The process's own environment, not the backend's knobs. A
            // `LD_PRELOAD` or a `PATH` here would decide what binary the node
            // runs and with what library, which is not a thing a device
            // configuration gets to say.
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

        let admitted_mib = self.admit(id, &params, vgpu.as_ref()).await?;

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
        // Liveness by pid, and by IDENTITY: a bare kill(pid, 0) answers
        // "alive" for whoever holds that pid now, and after an agent restart
        // the recorded one may well have been recycled. Reporting a
        // stranger's process as this device would leave the VM in the
        // inventory with a dead backend — the exact state the quarantine
        // exists to catch. `is_ours` is the same check the adopted teardown
        // makes — this kind's `comm` AND this device's socket on the command
        // line — and it subsumes liveness: a dead pid has neither to read.
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

    /// This test used to be `free_env_overrides_typed_fields` and asserted
    /// the opposite: that `env` WON over the typed fields.
    ///
    /// Astra finding S03, 2026-09-23 turned that behaviour round, so the test
    /// turns round with it. What it encoded was the reason the finding
    /// exists: the number this node admits a device for came from the typed
    /// field and the number the backend ran with came from the map, and
    /// nothing made the two agree. A backend knob that no typed field
    /// produces still passes through — that is what the map is for — but a
    /// key that argues with one is now a refusal a person reads.
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

        // A knob nothing typed produces is still passed through verbatim,
        // which is the whole point of the map.
        let params = p(serde_json::json!({
            "vram_limit_mib": 1024,
            "env": { "LEA_FD_CENSUS": "1" }
        }));
        let env = NvrmDriver::backend_env(&params, None).expect("a new knob is not an argument");
        let get = |k: &str| env.iter().find(|(ek, _)| ek == k).map(|(_, v)| v.as_str());
        assert_eq!(get("LEA_FD_CENSUS"), Some("1"));
        assert_eq!(get("LEA_VRAM_LIMIT_MIB"), Some("1024"));
    }

    /// The process's own environment is not a device knob.
    ///
    /// Astra finding S03, 2026-09-23: `create` clears the environment and
    /// carries over exactly `PATH` and `HOME`, and an `env` map that could
    /// set either — or an `LD_PRELOAD` — would decide which binary the node
    /// runs and with which library.
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

    /// A spec may name the vGPU type it wants and nothing else.
    ///
    /// Astra finding S03, 2026-09-23: `spec.params` reached this driver as
    /// the whole of `NvrmParams`, so a VM document could ask for
    /// `admin_priv` — the backend keeping `CAP_SYS_ADMIN` — and could write
    /// the process's environment. Both are the node's to decide, and the node
    /// says so in `[device.nvrm]`.
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

    /// What this node admitted is what the backend is started with.
    ///
    /// Astra finding S03, 2026-09-23: admission counted the resolved vGPU
    /// profile while the process was started from the typed fields, so a
    /// device that named a cap was admitted for one number and ran with
    /// another. The test reads both out of the same params.
    #[test]
    fn the_admitted_budget_is_the_started_budget() {
        let vgpu = VgpuType {
            vgpu_type: "RTX2070-4Q".into(),
            profile_mib: 4096,
            fb_mib: 2816,
            max_instance: 2,
            encoder_cap: 50,
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

        // An explicit profile size and no vGPU type: the same again.
        let params = p(serde_json::json!({ "vram_profile_mib": 2048 }));
        let env = NvrmDriver::backend_env(&params, None).expect("started");
        assert_eq!(params.admitted_mib(None), 2048);
        assert_eq!(value(&env, "LEA_VRAM_PROFILE_MIB"), Some(2048));

        // And a device that asks for nothing costs nothing.
        assert_eq!(NvrmParams::default().admitted_mib(None), 0);
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
            }
        );
        assert!(parse_vgpu_select("prose only, no keys\n").is_err());
    }
}
