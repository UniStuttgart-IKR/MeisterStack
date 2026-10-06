// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

// Shared create-document types; local types below persist resolved resource IDs.
pub use agent_api::spec::{BootSourceSpec, Desired, NewDevice, NewNic, NewVmSpec, NewVolume};
use agent_api::{
    Device, Nic,
    device::{DeviceId, DeviceSpec, PartitionSpec, default_device_driver},
    hypervisor::VmId,
    networking::{NicId, NicSpec},
    storage::{Volume, VolumeId, VolumeSpec},
    types::mac_addr::MacAddr,
};
use anyhow::{Context, bail};
use std::collections::BTreeMap;
use uuid::Uuid;

/// Exclusive operation marker that suppresses ordinary lifecycle reconciliation.
/// Migration ownership survives startup; task loss does not end a VMM transfer.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub enum Operation {
    Snapshotting { target: String },
    Restoring { source: String },
    MigratingOut { peer: String },
    MigratingIn { peer: String },
}

/// Durable ownership of a migration, independent of the task watching the VMM.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct MigrationAttempt {
    pub id: String,
    pub peer: String,
    pub incoming: bool,
    /// Only an acknowledged send may subsequently establish `StillHere`.
    pub accepted: bool,
    #[serde(default)]
    pub unknown: Option<String>,
}

/// Persisted provisioning checkpoint, including migration-specific phases.
/// The planner treats unfinished provisioning and migration phases separately.
#[derive(Clone, Copy, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum Phase {
    Provisioning,
    VolumesDone,
    NetworkDone,
    DevicesDone,
    Provisioned,
    /// Destination resources are prepared and a VMM is receiving. Reconciliation
    /// checks arrival or receiver failure without ordinary provisioning.
    Receiving,
    /// The send API succeeded. Retain source resource records until the controller
    /// resolves ownership and requests cleanup; ordinary startup is suppressed.
    Migrated,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct AgentVmSpec {
    pub vcpus: u32,
    pub memory_mib: u64,
    pub boot: BootSourceSpec,
    pub volumes: Vec<VolumeWithId>,
    pub nics: Vec<NicWithId>,
    pub devices: Vec<DeviceWithId>,
    /// Optional NoCloud seed configuration.
    #[serde(default)]
    pub cloud_init: Option<crate::cloudinit::CloudInit>,
    /// Fetch sources resolved before provisioning. Drivers use local catalogue
    /// paths; path-only images and legacy records leave this list empty.
    #[serde(default)]
    pub images: Vec<crate::images::Source>,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct VolumeWithId {
    pub id: VolumeId,
    pub spec: VolumeSpec,
    /// The volume is externally owned: VM teardown detaches it without deleting
    /// its data. Persist ownership on this record so deletion does not depend on
    /// the presence of another table row.
    #[serde(default)]
    pub referenced: bool,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct NicWithId {
    pub id: NicId,
    pub spec: NicSpec,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct DeviceWithId {
    pub id: DeviceId,
    pub spec: DeviceSpec,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct VmRecord {
    #[serde(default)]
    pub migration: Option<MigrationAttempt>,
    pub spec: AgentVmSpec,
    #[serde(default)]
    pub desired: Desired,
    pub phase: Phase,
    #[serde(default)]
    pub operation: Option<Operation>,
    /// Wall-clock shutdown deadline retained across agent restart.
    #[serde(default)]
    pub stop_deadline: Option<std::time::SystemTime>,
    /// Advisory receive deadline, retained for persisted-record compatibility.
    /// Expiry does not prove that a receive ended and never authorizes teardown.
    #[serde(default)]
    pub receive_deadline: Option<std::time::SystemTime>,
    /// Explicit terminal evidence that this source kept the guest: the acknowledged
    /// send returned ownership, or the send was refused before any stream opened.
    /// Deadlines and ambiguous errors never populate this field.
    /// It belongs to `migration.id` and is cleared before the next attempt.
    #[serde(default)]
    pub send_failed: Option<String>,
    /// Persisted quarantine reason that suppresses automatic lifecycle repair.
    /// Backend loss under a live VMM and repeated ineffective resumes can set it.
    /// Explicit desired-state changes clear it.
    #[serde(default)]
    pub unhealthy: Option<String>,
    /// Controller-owned records may be reaped by desired-state snapshots.
    /// Local and legacy records default to false; the controller claims a record
    /// when it first names it.
    #[serde(default)]
    pub managed_by_controller: bool,
    pub volumes: Vec<Volume>,
    /// Inline disks created before an attachment could be committed. Kept across
    /// restart so failed attach/cleanup cannot discard ownership of their bytes.
    #[serde(default)]
    pub unattached_volumes: Vec<agent_api::storage::VolumeHandle>,
    pub nics: Vec<Nic>,
    pub devices: Vec<Device>,
    #[serde(default)]
    pub vmm_pid: Option<u32>,
    /// Bridge names returned by overlay creation, keyed by VNI. Teardown passes
    /// them back for driver validation; legacy records may lack these names.
    #[serde(default)]
    pub overlay_bridges: BTreeMap<u32, String>,
}

impl VmRecord {
    /// Minimal provisioned record for internal and integration test fixtures.
    pub fn blank() -> Self {
        Self {
            migration: None,
            spec: AgentVmSpec {
                vcpus: 1,
                memory_mib: 256,
                boot: BootSourceSpec::Firmware {
                    firmware: "fw".into(),
                },
                volumes: vec![],
                nics: vec![],
                devices: vec![],
                images: Vec::new(),
                cloud_init: None,
            },
            desired: Desired::Running,
            phase: Phase::Provisioned,
            operation: None,
            stop_deadline: None,
            receive_deadline: None,
            send_failed: None,
            unhealthy: None,
            managed_by_controller: false,
            volumes: vec![],
            unattached_volumes: vec![],
            nics: vec![],
            devices: vec![],
            vmm_pid: None,
            overlay_bridges: BTreeMap::new(),
        }
    }
}

/// Independent volume ownership record. `handle` is absent while provisioning
/// is pending or incomplete; retry/probe uses the same volume ID.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct VolumeRecord {
    pub spec: agent_api::storage::VolumeSpec,
    #[serde(default)]
    pub handle: Option<agent_api::storage::VolumeHandle>,
    pub phase: VolumeRecordPhase,
    /// Machine-readable cause persisted by the operation that observed it.
    /// Absent for Ready and legacy records without a recorded reason.
    #[serde(default)]
    pub reason: Option<crate::reconcile::VolumeReason>,
    #[serde(default)]
    pub message: Option<String>,
    /// Deletion timestamp used for tombstone expiry; see [`VolumeRecordPhase::Gone`].
    #[serde(default)]
    pub gone_at: Option<std::time::SystemTime>,
}

impl VolumeRecord {
    /// Backend name, or an empty string before a handle exists.
    pub fn backend(&self) -> &str {
        self.handle
            .as_ref()
            .map(|h| h.backend.as_str())
            .unwrap_or("")
    }
}

/// Snapshot record retaining source identity independently of the volume row.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SnapshotRecord {
    /// Source volume ID.
    pub volume: agent_api::storage::VolumeId,
    /// Snapshot handle, absent until creation succeeds. Persisting the record
    /// first preserves the operation identity across a crash.
    #[serde(default)]
    pub handle: Option<agent_api::storage::VolumeHandle>,
    /// Owning driver, retained independently of the source volume row.
    pub driver: String,
    pub phase: SnapshotRecordPhase,
    /// Machine-readable cause persisted by the operation that observed it.
    /// Absent for Ready and legacy records without a recorded reason.
    #[serde(default)]
    pub reason: Option<crate::reconcile::SnapshotReason>,
    #[serde(default)]
    pub message: Option<String>,
    /// Deletion timestamp using the volume tombstone expiry policy.
    #[serde(default)]
    pub gone_at: Option<std::time::SystemTime>,
}

impl SnapshotRecord {
    pub fn backend(&self) -> &str {
        self.handle
            .as_ref()
            .map(|h| h.backend.as_str())
            .unwrap_or("")
    }

    pub fn size_bytes(&self) -> u64 {
        self.handle.as_ref().map(|h| h.size_bytes).unwrap_or(0)
    }
}

/// Node-local snapshot lifecycle phase.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum SnapshotRecordPhase {
    Creating,
    Ready,
    Failed,
    /// Explicit deletion evidence retained until tombstone expiry.
    Gone,
}

impl SnapshotRecordPhase {
    pub fn as_str(self) -> &'static str {
        match self {
            SnapshotRecordPhase::Creating => "Creating",
            SnapshotRecordPhase::Ready => "Ready",
            SnapshotRecordPhase::Failed => "Failed",
            SnapshotRecordPhase::Gone => "Gone",
        }
    }
}

/// Node-local volume lifecycle phase; control-plane scheduling and finalization
/// phases are represented separately.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum VolumeRecordPhase {
    /// Creation requested; no committed handle yet.
    Provisioning,
    /// Data exists; attachment state is held by VM records.
    Ready,
    /// Creation failed with details in `message`; a repeated Provision retries it.
    Failed,
    /// Explicit deletion evidence retained until tombstone expiry. A repeated
    /// deprovision request for an unknown ID can create a fresh tombstone.
    Gone,
}

impl VolumeRecordPhase {
    pub fn as_str(self) -> &'static str {
        match self {
            VolumeRecordPhase::Provisioning => "Provisioning",
            VolumeRecordPhase::Ready => "Ready",
            VolumeRecordPhase::Failed => "Failed",
            VolumeRecordPhase::Gone => "Gone",
        }
    }
}

impl TryFrom<proto::VmSpec> for AgentVmSpec {
    type Error = anyhow::Error;
    fn try_from(p: proto::VmSpec) -> Result<Self, Self::Error> {
        let boot = match p.boot {
            Some(proto::vm_spec::Boot::DirectKernel(dk)) => BootSourceSpec::DirectKernel {
                kernel: non_empty(dk.kernel).context("kernel must be set")?,
                cmdline: dk.cmdline,
                initramfs: non_empty(dk.initramfs),
            },
            Some(proto::vm_spec::Boot::Firmware(fw)) => BootSourceSpec::Firmware {
                firmware: non_empty(fw.firmware).context("firmware must be set")?,
            },
            None => bail!("vm spec has no boot source"),
        };

        Ok(Self {
            vcpus: p.vcpus,
            memory_mib: p.memory_mib,
            boot,
            volumes: p
                .volumes
                .into_iter()
                .map(TryInto::try_into)
                .collect::<Result<Vec<_>, _>>()
                .context("invalid volume spec")?,
            nics: p
                .nics
                .into_iter()
                .map(TryInto::try_into)
                .collect::<Result<Vec<_>, _>>()
                .context("invalid nic spec")?,
            // The legacy typed proto omits image-fetch and seed fields; JSON carries them.
            cloud_init: None,
            images: Vec::new(),
            devices: p
                .devices
                .into_iter()
                .map(TryInto::try_into)
                .collect::<Result<Vec<_>, _>>()
                .context("invalid device spec")?,
        })
    }
}

impl TryFrom<proto::VolumeSpec> for VolumeWithId {
    type Error = anyhow::Error;
    fn try_from(p: proto::VolumeSpec) -> Result<Self, Self::Error> {
        Ok(Self {
            id: parse_uuid(&p.id).context("volume id")?,
            // The legacy typed proto omits driver routing, params and volume references.
            referenced: false,
            spec: VolumeSpec {
                base_image: non_empty(p.base_image),
                size_bytes: p.size_bytes,
                driver: None,
                params: None,
            },
        })
    }
}

impl TryFrom<proto::NicSpec> for NicWithId {
    type Error = anyhow::Error;
    fn try_from(p: proto::NicSpec) -> Result<Self, Self::Error> {
        Ok(Self {
            id: parse_uuid(&p.id).context("nic id")?,
            spec: NicSpec {
                bridge: non_empty(p.bridge).context("bridge must be set")?, // controller
                mac: p
                    .mac
                    .parse::<MacAddr>()
                    .map_err(|e| anyhow::anyhow!("invalid mac {:?}: {e}", p.mac))?,
                // The typed proto omits overlay, address and provider fields.
                // Tenant NICs carry these through `spec_json`.
                vxlan_id: None,
                physnet: None,
                floating_ips: Vec::new(),
                routed_subnets: Vec::new(),
            },
        })
    }
}

impl TryFrom<proto::DeviceSpec> for DeviceWithId {
    type Error = anyhow::Error;
    fn try_from(p: proto::DeviceSpec) -> Result<Self, Self::Error> {
        let partition = match p.partition.as_str() {
            "exclusive" => PartitionSpec::Exclusive,
            "mediated" => PartitionSpec::Mediated,
            other => bail!("unknown partition type {other:?}"),
        };
        let params: Option<serde_json::Value> = non_empty(p.params_json)
            .map(|s| serde_json::from_str(&s))
            .transpose()
            .context("device params_json")?;
        let driver = non_empty(p.driver_name).unwrap_or_else(default_device_driver);
        // Controller-forwarded device parameters have the same restrictions as REST input.
        refuse_operator_only_device_params(&driver, params.as_ref())?;
        Ok(Self {
            id: parse_uuid(&p.id).context("device id")?,
            // Honor the requested driver; empty means default. The typed proto has no profile field.
            spec: DeviceSpec {
                driver,
                partition,
                profile: None,
                params,
            },
        })
    }
}

/// Convert the shared create document into this node's persisted specification for the VM
/// `vm`.
pub trait NewVmSpecExt {
    fn into_spec(self, vm: VmId, default_bridge: &str) -> anyhow::Result<(AgentVmSpec, Desired)>;
}

impl NewVmSpecExt for NewVmSpec {
    fn into_spec(self, vm: VmId, default_bridge: &str) -> anyhow::Result<(AgentVmSpec, Desired)> {
        refuse_what_cannot_be_a_vm(&self)?;
        refuse_a_volume_entry_that_says_two_things(&self.volumes)?;
        let images = images_to_fetch(&self.volumes);
        Ok((
            AgentVmSpec {
                vcpus: self.vcpus,
                memory_mib: self.memory_mib,
                boot: self.boot,
                volumes: volumes_with_ids(self.volumes)?,
                nics: nics_with_ids(self.nics, &vm, default_bridge)?,
                devices: devices_with_ids(self.devices)?,
                cloud_init: self.cloud_init,
                images,
            },
            self.desired,
        ))
    }
}

/// Reject invalid VM dimensions before accessing drivers or storage.
fn refuse_what_cannot_be_a_vm(spec: &NewVmSpec) -> anyhow::Result<()> {
    if spec.vcpus == 0 {
        bail!("vcpus must be greater than zero");
    }
    if matches!(spec.desired, Desired::Absent | Desired::Halted) {
        bail!("desired {:?} is not a valid creation target", spec.desired);
    }
    if spec.volumes.is_empty() {
        bail!("a vm needs at least one volume as boot disk");
    }
    Ok(())
}

/// Whether the entry specifies volume data or provisioning options.
fn describes_its_own_bytes(v: &NewVolume) -> bool {
    v.size_bytes != 0
        || v.base_image.is_some()
        || v.base_image_url.is_some()
        || v.base_image_sha256.is_some()
        || v.driver.is_some()
}

/// Require exactly one of an inline disk description or an existing volume ID.
/// References may supply attach options but cannot redefine the stored data.
fn refuse_a_volume_entry_that_says_two_things(volumes: &[NewVolume]) -> anyhow::Result<()> {
    for v in volumes {
        if v.volume.is_none() {
            // Inline volumes require a nonzero size even when the document omits it.
            if v.size_bytes == 0 {
                bail!("an inline volume needs a size_bytes greater than zero");
            }
            continue;
        }
        if describes_its_own_bytes(v) {
            bail!("a referenced volume has its size and image already");
        }
    }
    Ok(())
}

/// Deduplicate fetch sources shared by multiple volume entries.
fn images_to_fetch(volumes: &[NewVolume]) -> Vec<crate::images::Source> {
    let mut images: Vec<crate::images::Source> = Vec::new();
    for v in volumes {
        let (Some(name), Some(url), Some(sha256)) = (
            v.base_image.as_deref(),
            v.base_image_url.as_deref(),
            v.base_image_sha256.as_deref(),
        ) else {
            // Incomplete fetch metadata is not a download request. Such entries
            // use local image lookup; the create edge validates fetch metadata.
            continue;
        };
        if !images.iter().any(|s| s.name == name) {
            images.push(crate::images::Source {
                name: name.to_string(),
                url: url.to_string(),
                sha256: sha256.to_string(),
                // Cloud catalogue identity; empty without a catalogue. See `images::Source::uid`.
                uid: v.base_image_uid.clone().unwrap_or_default(),
            });
        }
    }
    images
}

/// Preserve referenced volume IDs and allocate IDs for inline disks.
fn volumes_with_ids(volumes: Vec<NewVolume>) -> anyhow::Result<Vec<VolumeWithId>> {
    volumes
        .into_iter()
        .map(|v| match v.volume {
            // References reuse the existing ID and carry no provisioning description.
            Some(uid) => {
                let id: VolumeId = uid
                    .parse()
                    .map_err(|e| anyhow::anyhow!("volume reference {uid:?} is not a uid: {e}"))?;
                Ok(VolumeWithId {
                    id,
                    spec: VolumeSpec {
                        base_image: None,
                        size_bytes: 0,
                        driver: None,
                        // Attach options describe the connection, such as a virtiofs tag.
                        params: v.params,
                    },
                    referenced: true,
                })
            }
            None => Ok(VolumeWithId {
                id: Uuid::new_v4(),
                spec: VolumeSpec {
                    base_image: v.base_image,
                    size_bytes: v.size_bytes,
                    driver: v.driver,
                    params: v.params,
                },
                referenced: false,
            }),
        })
        .collect::<anyhow::Result<Vec<_>>>()
}

/// The id of the VM's NIC at `position`, the same for every conversion of its create document.
///
/// A NIC's id names its tap and, without a MAC in the document, its MAC. A live migration
/// converts the document again on the destination, and the arriving configuration names the
/// source's tap and MAC: a fresh id there would leave the guest on a tap nobody bridged,
/// behind a MAC guard that drops its frames. Derived from the VM's id, so two VMs never share
/// one.
fn nic_id(vm: &VmId, position: usize) -> NicId {
    use sha2::Digest;
    let digest = sha2::Sha256::new()
        .chain_update(vm.as_bytes())
        .chain_update(b"nic")
        .chain_update(position.to_be_bytes())
        .finalize();
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    uuid::Builder::from_custom_bytes(bytes).into_uuid()
}

/// The NICs of the VM `vm` whose ids are not the ones [`nic_id`] derives: a record made by an
/// agent that rolled them at random. A conversion of the VM's document on another node names
/// these NICs' taps, and without a MAC in the document their MACs, otherwise.
pub(crate) fn nics_with_rolled_ids<'a>(
    vm: &'a VmId,
    nics: &'a [NicWithId],
) -> impl Iterator<Item = &'a NicWithId> + 'a {
    nics.iter()
        .enumerate()
        .filter(move |(position, nic)| nic.id != nic_id(vm, *position))
        .map(|(_, nic)| nic)
}

/// Derive NIC IDs and default omitted MAC addresses and bridge names.
fn nics_with_ids(
    nics: Vec<NewNic>,
    vm: &VmId,
    default_bridge: &str,
) -> anyhow::Result<Vec<NicWithId>> {
    nics.into_iter()
        .enumerate()
        .map(|(position, n)| {
            let id = nic_id(vm, position);
            let mac = n.mac.unwrap_or_else(|| {
                let b = id.as_bytes();
                format!("52:54:00:{:02x}:{:02x}:{:02x}", b[0], b[1], b[2])
            });
            let mac: MacAddr = mac
                .parse()
                .map_err(|e| anyhow::anyhow!("invalid mac {mac:?}: {e}"))?;
            let bridge = match n.bridge {
                Some(b) if !b.is_empty() => b,
                _ => default_bridge.to_string(),
            };
            Ok(NicWithId {
                id,
                spec: NicSpec {
                    bridge,
                    mac,
                    vxlan_id: n.vxlan_id,
                    physnet: n.physnet,
                    floating_ips: n.floating_ips,
                    routed_subnets: n.routed_subnets,
                },
            })
        })
        .collect::<anyhow::Result<Vec<_>>>()
}

/// Reject operator-only params of the GPU drivers before creating a record.
/// The drivers also check them at use time; backend choice, sandboxing,
/// privilege and environment belong to node config.
fn refuse_operator_only_device_params(
    driver: &str,
    params: Option<&serde_json::Value>,
) -> anyhow::Result<()> {
    let Some(params) = params else {
        return Ok(());
    };
    let refused = match driver {
        crate::drivers::DRIVER_NVRM => nvrm_driver::refuse_operator_only_params(params),
        crate::drivers::DRIVER_CROSVM_GPU => crosvm_gpu_driver::refuse_operator_only_params(params),
        _ => Ok(()),
    };
    refused.map_err(|said| anyhow::anyhow!("{said}"))
}

/// Allocate device IDs and parse each partitioning mode.
fn devices_with_ids(devices: Vec<NewDevice>) -> anyhow::Result<Vec<DeviceWithId>> {
    devices
        .into_iter()
        .map(|d| {
            let partition = match d.partition.as_str() {
                "exclusive" => PartitionSpec::Exclusive,
                "mediated" => PartitionSpec::Mediated,
                other => anyhow::bail!("unknown partition type {other:?}"),
            };
            let driver = d.driver.unwrap_or_else(default_device_driver);
            refuse_operator_only_device_params(&driver, d.params.as_ref())?;
            Ok(DeviceWithId {
                id: Uuid::new_v4(),
                spec: DeviceSpec {
                    driver,
                    partition,
                    profile: d.profile,
                    params: d.params,
                },
            })
        })
        .collect::<anyhow::Result<Vec<_>>>()
}

fn parse_uuid(s: &str) -> anyhow::Result<uuid::Uuid> {
    s.parse().with_context(|| format!("invalid uuid: {s:?}"))
}

fn non_empty(s: String) -> Option<String> {
    (!s.is_empty()).then_some(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// IKR-B21: a crosvm-gpu spec chooses a profile and sets no backend
    /// parameter, neither as tenant default nor through a controller request.
    #[test]
    fn a_vm_document_may_not_configure_the_crosvm_gpu_backend() {
        let device = |driver: Option<&str>, params: serde_json::Value| NewDevice {
            driver: driver.map(str::to_string),
            partition: "mediated".into(),
            profile: Some("venus".into()),
            params: Some(params),
        };
        devices_with_ids(vec![device(Some("crosvm-gpu"), serde_json::json!({}))])
            .expect("a profile and nothing else");

        // The default driver is crosvm-gpu, so leaving the name out changes nothing.
        for driver in [Some("crosvm-gpu"), None] {
            let err = devices_with_ids(vec![device(
                driver,
                serde_json::json!({ "implicit_render_server": false }),
            )])
            .expect_err("the sandbox is the node's");
            let said = format!("{err:#}");
            assert!(said.contains("implicit_render_server"), "{said}");
            assert!(said.contains("device.crosvm-gpu"), "{said}");
        }

        let err = DeviceWithId::try_from(proto::DeviceSpec {
            id: Uuid::new_v4().to_string(),
            partition: "mediated".into(),
            driver_name: "crosvm-gpu".into(),
            params_json: r#"{"backend": "gfxstream"}"#.into(),
        })
        .expect_err("typed requests are held to the same rule");
        assert!(format!("{err:#}").contains("backend"), "{err:#}");
    }

    /// NVRM specs may select a vGPU type but cannot set backend privilege or environment.
    #[test]
    fn a_vm_document_may_not_configure_the_nvrm_backend() {
        let device = |params: serde_json::Value| NewDevice {
            driver: Some("nvrm".into()),
            partition: "mediated".into(),
            profile: Some("desktop".into()),
            params: Some(params),
        };

        let ok = devices_with_ids(vec![device(serde_json::json!({
            "vgpu_type": "RTX2070-4Q"
        }))])
        .expect("a vgpu type is a tenant's to ask for");
        assert_eq!(ok.len(), 1);
        assert_eq!(ok[0].spec.driver, "nvrm");

        for refused in ["admin_priv", "env", "vram_profile_mib"] {
            let err = devices_with_ids(vec![device(
                serde_json::json!({ refused: serde_json::Value::Null }),
            )])
            .expect_err("not a spec's to set");
            let said = format!("{err:#}");
            assert!(said.contains(refused), "{said}");
            assert!(
                said.contains("device.nvrm"),
                "and says where it belongs: {said}"
            );
        }

        // Drivers without an allowlist retain their own parameter validation.
        assert!(
            devices_with_ids(vec![NewDevice {
                driver: Some("input".into()),
                partition: "mediated".into(),
                profile: None,
                params: Some(serde_json::json!({ "evdev": "/dev/input/event0" })),
            }])
            .is_ok()
        );

        // Typed controller requests enforce the same restriction.
        let err = DeviceWithId::try_from(proto::DeviceSpec {
            id: Uuid::new_v4().to_string(),
            partition: "mediated".into(),
            driver_name: "nvrm".into(),
            params_json: r#"{"admin_priv": true}"#.into(),
        })
        .expect_err("the other door is the same door");
        assert!(format!("{err:#}").contains("admin_priv"), "{err:#}");
    }

    /// Preserve explicit device routing; an empty proto driver selects the node default.
    #[test]
    fn a_device_is_routed_to_the_driver_the_controller_named() {
        let named = DeviceWithId::try_from(proto::DeviceSpec {
            id: uuid::Uuid::nil().to_string(),
            driver_name: "nvrm".into(),
            partition: "mediated".into(),
            params_json: String::new(),
        })
        .expect("a named driver parses");
        assert_eq!(named.spec.driver, "nvrm");

        let unset = DeviceWithId::try_from(proto::DeviceSpec {
            id: uuid::Uuid::nil().to_string(),
            driver_name: String::new(),
            partition: "mediated".into(),
            params_json: String::new(),
        })
        .expect("an unset driver parses");
        assert_eq!(unset.spec.driver, default_device_driver());
    }

    /// Accept the desired-state spellings emitted by controller `build_spec_json`.
    #[test]
    fn the_run_strategy_spellings_arrive_as_desired_states() {
        for (spelling, expected) in [
            ("Running", Desired::Running),
            ("Stopped", Desired::Stopped),
            ("Paused", Desired::Paused),
        ] {
            let doc = format!(
                r#"{{"vcpus":1,"memory_mib":256,
                     "boot":{{"kind":"firmware","firmware":"fw"}},
                     "desired":"{spelling}",
                     "volumes":[{{"size_bytes":1}}]}}"#
            );
            let spec: NewVmSpec = serde_json::from_str(&doc).expect("spec parses");
            let (_, desired) = spec.into_spec(VmId::nil(), "br0").expect("spec is valid");
            assert_eq!(desired, expected);
        }
    }

    /// Preserve optional cloud-init data and accept specs that omit it.
    #[test]
    fn a_cloud_init_block_travels_and_its_absence_changes_nothing() {
        let plain = r#"{"vcpus":1,"memory_mib":256,
                        "boot":{"kind":"firmware","firmware":"fw"},
                        "volumes":[{"size_bytes":1}]}"#;
        let spec: NewVmSpec = serde_json::from_str(plain).unwrap();
        let (agent, _) = spec.into_spec(VmId::nil(), "br0").unwrap();
        assert_eq!(agent.cloud_init, None, "no block, no seed, no second disk");

        // The `##` is not decoration: user_data starts with `#cloud-config`,
        // and `"#` inside an `r#"…"#` would end the literal.
        let seeded = r##"{"vcpus":1,"memory_mib":256,
                          "boot":{"kind":"firmware","firmware":"fw"},
                          "volumes":[{"size_bytes":1}],
                          "cloud_init":{"user_data":"#cloud-config\n",
                                        "network_config":"version: 2\n",
                                        "local_hostname":"web-1"}}"##;
        let spec: NewVmSpec = serde_json::from_str(seeded).unwrap();
        let (agent, _) = spec.into_spec(VmId::nil(), "br0").unwrap();
        let config = agent.cloud_init.expect("the block travels");
        assert_eq!(config.user_data, "#cloud-config\n");
        assert_eq!(config.network_config.as_deref(), Some("version: 2\n"));
        assert_eq!(config.local_hostname.as_deref(), Some("web-1"));
        assert_eq!(config.meta_data, None, "derived, not carried");
    }

    /// An omitted desired state defaults to Running.
    #[test]
    fn a_spec_without_a_desired_state_defaults_to_running() {
        let doc = r#"{"vcpus":1,"memory_mib":256,
                      "boot":{"kind":"firmware","firmware":"fw"},
                      "volumes":[{"size_bytes":1}]}"#;
        let spec: NewVmSpec = serde_json::from_str(doc).unwrap();
        assert_eq!(
            spec.into_spec(VmId::nil(), "br0").unwrap().1,
            Desired::Running
        );
    }

    /// Parse all shipped specs with unknown-field validation.
    #[test]
    fn every_spec_in_the_repo_still_parses() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../config/json");
        let mut seen = 0;
        for entry in std::fs::read_dir(&dir).expect("config/json is where the specs live") {
            let path = entry.unwrap().path();
            if path.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }
            let raw = std::fs::read_to_string(&path).unwrap();
            let spec: NewVmSpec = serde_json::from_str(&raw)
                .unwrap_or_else(|e| panic!("{} no longer parses: {e}", path.display()));
            spec.into_spec(VmId::nil(), "br0")
                .unwrap_or_else(|e| panic!("{} is no longer valid: {e:#}", path.display()));
            seen += 1;
        }
        assert!(seen >= 3, "only {seen} specs found in {}", dir.display());
    }

    /// An omitted volume driver selects the registered default.
    #[test]
    fn a_volume_without_a_driver_stays_the_default_one() {
        let doc = r#"{"vcpus":1,"memory_mib":256,
                      "boot":{"kind":"firmware","firmware":"fw"},
                      "volumes":[{"base_image":"n.raw","size_bytes":10}]}"#;
        let spec: NewVmSpec = serde_json::from_str(doc).unwrap();
        let (spec, _) = spec.into_spec(VmId::nil(), "br0").unwrap();
        assert_eq!(spec.volumes[0].spec.driver, None);
        assert_eq!(spec.volumes[0].spec.params, None);
    }

    /// Preserve explicit volume driver names and parameters.
    #[test]
    fn a_volume_may_name_a_driver_and_carry_params_through() {
        let doc = r#"{"vcpus":1,"memory_mib":256,
                      "boot":{"kind":"firmware","firmware":"fw"},
                      "volumes":[{"size_bytes":10,"driver":"lvm-thin",
                                  "params":{"pool":"vg0/thin","snapshot_of":"base"}}]}"#;
        let spec: NewVmSpec = serde_json::from_str(doc).unwrap();
        let (spec, _) = spec.into_spec(VmId::nil(), "br0").unwrap();
        assert_eq!(spec.volumes[0].spec.driver.as_deref(), Some("lvm-thin"));
        assert_eq!(
            spec.volumes[0].spec.params.as_ref().unwrap()["pool"],
            "vg0/thin"
        );
    }

    /// Omitted NIC address lists default to empty.
    #[test]
    fn a_nic_that_names_no_addresses_gets_none() {
        let doc = r#"{"vcpus":1,"memory_mib":256,
                      "boot":{"kind":"firmware","firmware":"fw"},
                      "volumes":[{"size_bytes":1}],
                      "nics":[{}]}"#;
        let spec: NewVmSpec = serde_json::from_str(doc).unwrap();
        let (spec, _) = spec.into_spec(VmId::nil(), "br0").unwrap();
        assert_eq!(spec.nics[0].spec.bridge, "br0");
        assert_eq!(spec.nics[0].spec.vxlan_id, None);
        assert!(spec.nics[0].spec.floating_ips.is_empty());
        assert!(spec.nics[0].spec.routed_subnets.is_empty());

        // Empty address lists are omitted from persisted records.
        let json = serde_json::to_value(&spec.nics[0].spec).unwrap();
        assert!(json.get("floating_ips").is_none(), "{json}");
        assert!(json.get("routed_subnets").is_none(), "{json}");
    }

    /// Standalone specs may supply NIC addresses directly.
    #[test]
    fn a_nic_may_name_its_own_addresses() {
        let doc = r#"{"vcpus":1,"memory_mib":256,
                      "boot":{"kind":"firmware","firmware":"fw"},
                      "volumes":[{"size_bytes":1}],
                      "nics":[{"vxlan_id":10007,
                               "floating_ips":["10.255.0.7"],
                               "routed_subnets":["10.7.1.0/24"]}]}"#;
        let spec: NewVmSpec = serde_json::from_str(doc).unwrap();
        let (spec, _) = spec.into_spec(VmId::nil(), "br0").unwrap();
        assert_eq!(spec.nics[0].spec.vxlan_id, Some(10_007));
        assert_eq!(spec.nics[0].spec.floating_ips, ["10.255.0.7"]);
        assert_eq!(spec.nics[0].spec.routed_subnets, ["10.7.1.0/24"]);
    }

    /// Whether a tap's sources are on an allowlist is read off the NIC's document: a prefix in
    /// it puts them there, none leaves the pool ban, and a provider NIC is pinned by its MAC
    /// whatever it names. (NL5-2)
    #[test]
    fn a_nics_guard_is_read_off_its_document() {
        let nic = |json: &str| serde_json::from_str::<NicSpec>(json).expect("a nic");
        let prefixed = nic(
            r#"{"bridge":"br0","mac":"52:54:00:00:00:01","vxlan_id":10007,
                               "routed_subnets":["10.30.0.0/24"]}"#,
        );
        assert!(prefixed.sources_allowlisted());
        let bare = nic(r#"{"bridge":"br0","mac":"52:54:00:00:00:01","vxlan_id":10007}"#);
        assert!(!bare.sources_allowlisted());
        let provider = nic(
            r#"{"bridge":"br0","mac":"52:54:00:00:00:01","physnet":"ext",
                               "routed_subnets":["10.30.0.0/24"]}"#,
        );
        assert!(!provider.sources_allowlisted());
    }

    /// A record from a build that kept a word of its own about a NIC's address space still
    /// reads, and the word is gone: its tap is guarded by its lists, as on every other node,
    /// and the record is written back without it. (NL5-2)
    #[test]
    fn a_record_with_the_retired_address_space_word_reads_and_follows_its_lists() {
        let written = r#"{"bridge":"br0","mac":"52:54:00:00:00:01","vxlan_id":10007,
                          "address_space_known":true}"#;
        let nic: NicSpec = serde_json::from_str(written).expect("the record reads");
        assert!(
            !nic.sources_allowlisted(),
            "no prefix in the document, no allowlist"
        );
        let again = serde_json::to_value(&nic).expect("a record");
        assert!(again.get("address_space_known").is_none(), "{again}");
    }

    #[test]
    fn absent_and_halted_are_not_creation_targets() {
        for spelling in ["Absent", "Halted"] {
            let doc = format!(
                r#"{{"vcpus":1,"memory_mib":256,
                     "boot":{{"kind":"firmware","firmware":"fw"}},
                     "desired":"{spelling}",
                     "volumes":[{{"size_bytes":1}}]}}"#
            );
            let spec: NewVmSpec = serde_json::from_str(&doc).unwrap();
            assert!(spec.into_spec(VmId::nil(), "br0").is_err());
        }
    }

    fn referring(volume: &str, extra: serde_json::Value) -> serde_json::Value {
        let mut entry = serde_json::json!({ "volume": volume });
        if let (Some(e), Some(x)) = (entry.as_object_mut(), extra.as_object()) {
            for (k, v) in x {
                e.insert(k.clone(), v.clone());
            }
        }
        serde_json::json!({
            "vcpus": 1,
            "memory_mib": 64,
            "boot": {"kind": "firmware", "firmware": "/fw"},
            "volumes": [entry]
        })
    }

    /// Referenced volumes retain the supplied object ID and are attached as existing data.
    #[test]
    fn a_referenced_volume_becomes_an_attach_with_the_objects_own_id() {
        let uid = uuid::Uuid::new_v4();
        let doc = referring(&uid.to_string(), serde_json::json!({}));
        let spec: NewVmSpec = serde_json::from_value(doc).expect("a spec");
        let (spec, _) = spec.into_spec(VmId::nil(), "br0").expect("into_spec");
        assert_eq!(spec.volumes.len(), 1);
        assert!(spec.volumes[0].referenced);
        assert_eq!(spec.volumes[0].id, uid, "the object's uid, not a fresh one");
        assert_eq!(spec.volumes[0].spec.size_bytes, 0);
        assert!(spec.volumes[0].spec.base_image.is_none());
    }

    /// References reject provisioning fields but permit attach parameters.
    #[test]
    fn a_referenced_volume_may_not_also_be_described() {
        let uid = uuid::Uuid::new_v4().to_string();
        for extra in [
            serde_json::json!({"size_bytes": 1024}),
            serde_json::json!({"base_image": "tiny.raw"}),
            serde_json::json!({"base_image_url": "https://x/y.raw"}),
            serde_json::json!({"base_image_sha256": "abc"}),
            serde_json::json!({"driver": "lvm-thin"}),
        ] {
            let spec: NewVmSpec =
                serde_json::from_value(referring(&uid, extra.clone())).expect("parses");
            let err = spec
                .into_spec(VmId::nil(), "br0")
                .expect_err("refused")
                .to_string();
            assert_eq!(
                err, "a referenced volume has its size and image already",
                "for {extra}"
            );
        }

        // params alone is fine, and travels as the attach options.
        let spec: NewVmSpec =
            serde_json::from_value(referring(&uid, serde_json::json!({"params": {"tag": "d"}})))
                .expect("parses");
        let (spec, _) = spec.into_spec(VmId::nil(), "br0").expect("accepted");
        assert_eq!(spec.volumes[0].spec.params.as_ref().unwrap()["tag"], "d");
    }

    /// Inline volumes receive a fresh ID and remain VM-owned.
    #[test]
    fn an_inline_volume_is_still_made_here_and_is_still_ephemeral() {
        let doc = serde_json::json!({
            "vcpus": 1,
            "memory_mib": 64,
            "boot": {"kind": "firmware", "firmware": "/fw"},
            "volumes": [{"base_image": "tiny.raw", "size_bytes": 2048}]
        });
        let spec: NewVmSpec = serde_json::from_value(doc).expect("a spec");
        let (spec, _) = spec.into_spec(VmId::nil(), "br0").expect("into_spec");
        assert!(!spec.volumes[0].referenced);
        assert_eq!(spec.volumes[0].spec.size_bytes, 2048);
        assert_eq!(spec.volumes[0].spec.base_image.as_deref(), Some("tiny.raw"));
    }

    /// Reject malformed referenced volume IDs before allocating resources.
    #[test]
    fn a_reference_that_is_not_a_uid_is_refused() {
        let spec: NewVmSpec =
            serde_json::from_value(referring("data-1", serde_json::json!({}))).expect("parses");
        let err = spec
            .into_spec(VmId::nil(), "br0")
            .expect_err("refused")
            .to_string();
        assert!(err.contains("data-1") && err.contains("uid"), "{err}");
    }

    /// A live migration converts the create document again on the destination, and the
    /// arriving configuration names the source's tap and MAC: every conversion for one VM
    /// gives each NIC the same id and default MAC, and another VM's NICs other ones.
    #[test]
    fn a_nic_keeps_its_id_and_mac_across_conversions_of_one_vms_document() {
        let doc = r#"{"vcpus":1,"memory_mib":256,
                     "boot":{"kind":"firmware","firmware":"fw"},
                     "volumes":[{"size_bytes":1}],
                     "nics":[{"vxlan_id":10001},{}]}"#;
        let nics = |vm: VmId| {
            let spec: NewVmSpec = serde_json::from_str(doc).expect("spec parses");
            let (spec, _) = spec.into_spec(vm, "br0").expect("spec is valid");
            spec.nics
                .into_iter()
                .map(|n| (n.id, n.spec.mac))
                .collect::<Vec<_>>()
        };
        let (source, other) = (VmId::new_v4(), VmId::new_v4());

        assert_eq!(nics(source), nics(source));
        assert_ne!(nics(source)[0], nics(source)[1], "two NICs are two taps");
        assert_ne!(nics(source)[0].0, nics(other)[0].0);
    }

    /// A record whose NIC ids an older agent rolled at random is told apart from one whose
    /// ids every conversion of the VM's document derives again.
    #[test]
    fn a_nic_id_rolled_at_random_is_told_from_a_derived_one() {
        let doc = r#"{"vcpus":1,"memory_mib":256,
                     "boot":{"kind":"firmware","firmware":"fw"},
                     "volumes":[{"size_bytes":1}],
                     "nics":[{},{}]}"#;
        let vm = VmId::new_v4();
        let spec: NewVmSpec = serde_json::from_str(doc).expect("spec parses");
        let (mut spec, _) = spec.into_spec(vm, "br0").expect("spec is valid");
        assert_eq!(nics_with_rolled_ids(&vm, &spec.nics).count(), 0);

        spec.nics[1].id = NicId::new_v4();

        let rolled: Vec<_> = nics_with_rolled_ids(&vm, &spec.nics)
            .map(|nic| nic.id)
            .collect();
        assert_eq!(rolled, [spec.nics[1].id]);
    }
}
