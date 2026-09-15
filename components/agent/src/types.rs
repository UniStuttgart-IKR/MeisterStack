// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

// The create document lives in `agent-api` so that both controllers can
// deserialise `spec.vm` into it at their REST edge — the refusal a client can
// still read. What is here is everything that turns that document into this
// node's record, which is the half that needs a node to be true.
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

/// Process that requires ownership of the VM.
/// This is required to let the reconciler know to not start/stop the VM while its in one of these
/// states.
/// If one of those actions is found on startup the VM is considered orphaned.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub enum Operation {
    Snapshotting { target: String },
    Restoring { source: String },
    MigratingOut { peer: String },
    MigratingIn { peer: String },
}

/// Process of the resource creation. Only for journaling.
/// For decision-making its only relevant `Provisioned` (finished) or else (not finished).
/// This is to track the creation phase of a VM.
#[derive(Clone, Copy, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum Phase {
    Provisioning,
    VolumesDone,
    NetworkDone,
    DevicesDone,
    Provisioned,
    /// Everything a guest needs is standing here — cgroup, disks, taps,
    /// devices, seed — and a VMM is listening for the migration stream. The
    /// guest is not here yet and may never arrive.
    ///
    /// It is the same chain as `Provisioned`, cut one step short: the config
    /// travels inside the stream, so the destination must NOT create a VM
    /// (v53 refuses to receive into one) and must have everything that config
    /// NAMES already in place, at the same paths.
    ///
    /// The reconciler does nothing at all to a record in this phase. It is
    /// the cluster's migration that owns it, on the cluster's timeout, and an
    /// agent that re-provisioned here would tear down the VMM the guest is
    /// moving into.
    Receiving,
    /// The guest left this node for another one, and the record is what is
    /// left of it.
    ///
    /// NOT deleted, and that is the whole point: until the destination
    /// reports the VM Running, the source is the fallback, and a record
    /// thrown away at `send` would have thrown away the only description of a
    /// guest that may still have to come back. The cluster removes it with a
    /// `DestroyInstance` once the destination has the guest — a teardown that
    /// detaches referenced volumes and deprovisions nothing, which is what it
    /// already does for a disk that outlives its VM.
    ///
    /// The reconciler does nothing here either: there is no VMM to repair and
    /// nothing to start.
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
    /// What the guest configures itself from at first boot. `None` is a VM
    /// with no seed, which is every VM this stack has booted so far.
    #[serde(default)]
    pub cloud_init: Option<crate::cloudinit::CloudInit>,
    /// Where the base images this VM names can be fetched from, if this node
    /// does not have them yet. Beside the volumes rather than inside their
    /// specs, and that is the point: a `VolumeSpec` is the contract three
    /// storage drivers implement, all three resolve `base_image` by joining
    /// the name onto their own image_dir, and none of them has to learn what
    /// a URL is for this to work. The agent puts the bytes there first.
    ///
    /// Empty for every spec written before this existed, and empty for every
    /// path-based image afterwards — so a record written yesterday loads
    /// unchanged and behaves unchanged.
    #[serde(default)]
    pub images: Vec<crate::images::Source>,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct VolumeWithId {
    pub id: VolumeId,
    pub spec: VolumeSpec,
    /// True when the id is a `Volume` object's uid rather than one this node
    /// minted, and the disk is therefore attached rather than made.
    ///
    /// On the SPEC and not derived from the volume table, deliberately. The
    /// teardown path asks this to decide between `detach` and `deprovision`,
    /// and the difference is somebody's data — so the answer has to live on
    /// the VM's own record, where it was written when the VM was created, and
    /// not depend on a second table still having a row.
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
    pub spec: AgentVmSpec,
    #[serde(default)]
    pub desired: Desired,
    pub phase: Phase,
    #[serde(default)]
    pub operation: Option<Operation>,
    /// `time::SystemTime` to make the deadline surrive an agent restart.
    #[serde(default)]
    pub stop_deadline: Option<std::time::SystemTime>,
    /// When this node stops waiting for a guest that is on its way here.
    ///
    /// Set when the VMM starts listening and cleared when the guest arrives,
    /// and it is the half of a failed reception that no hypervisor can
    /// report: a source that was killed, or told to send to a port that does
    /// not answer, never dials at all, and the destination then waits in
    /// `accept` for as long as it is allowed to. Cloud-hypervisor writes
    /// `migration-receive-failed` for every OTHER way a transfer ends badly;
    /// nobody writes anything for a source that simply never came.
    ///
    /// A `SystemTime` and on the record for the reason `stop_deadline` is
    /// one: the agent that started the reception is not necessarily the agent
    /// that has to end it. The ghost of the lab survived a restart precisely
    /// because nothing on disk said when to give up.
    ///
    /// See `provision::Ceilings::receive` for how long, and why it is
    /// longer than the cluster's own patience rather than shorter.
    #[serde(default)]
    pub receive_deadline: Option<std::time::SystemTime>,
    /// Why the last send this node was told to make did NOT take the guest
    /// away, if one did not.
    ///
    /// The third of the three things a source can say about a migration, and
    /// the only one the record could not express. `operation =
    /// MigratingOut` is "sending" and `phase = Migrated` is "gone"; a send
    /// that failed leaves the record exactly as it was — `Provisioned`, no
    /// marker, guest running — which is indistinguishable from a VM nobody
    /// ever asked to move. So the sentence lives here, and
    /// `MigrationReport.outcome` reads all three off this record.
    ///
    /// It matters because of what v53 does: a failed `vm.send-migration`
    /// RESUMES the guest and goes on serving it. That is the good outcome of
    /// a bad transfer, and until this field the tier above learned of it only
    /// by a command that never answered — after which it waited out its whole
    /// transfer timeout to work out which machine had the guest.
    ///
    /// Written by the task that watched the send, cleared by the next
    /// `MigrateOut`. It therefore outlives the migration that set it, on
    /// purpose: it is the last true thing about this VM's last attempt, and
    /// there is no moment at which forgetting it would be more honest than
    /// keeping it.
    #[serde(default)]
    pub send_failed: Option<String>,
    /// Set by the reconciler when it detects a condition it must not repair
    /// automatically. While set, the reconciler quarantines the VM: no
    /// automatic Provision/Start. Cleared by explicit lifecycle actions
    /// (start/stop/destroy via API) or by a successful re-provision.
    ///
    /// **One condition writes this today, and a killed VMM is not it.** The
    /// condition is a backend process that died while the VMM went on running
    /// — a live guest doing IO into a socket nobody is serving, where an
    /// automatic restart would reboot a working machine on the strength of
    /// something nobody has looked at. A VMM that was killed takes its
    /// backends with it and leaves a record with no processes behind it;
    /// that VM is re-provisioned, deliberately and in fifteen seconds, and
    /// `reconcile::backend_died_under_vmm` is where the line between the two
    /// is drawn and argued.
    #[serde(default)]
    pub unhealthy: Option<String>,
    /// True when this record came into being over the controller session.
    /// Only these may be torn down by a desired-state snapshot: a VM created
    /// straight on the agent's unix socket belongs to whoever is at that
    /// socket, is invisible to the controller, and is not the controller's
    /// to reap. Records written before the marker existed default to false
    /// and are claimed the first time the controller names one.
    #[serde(default)]
    pub managed_by_controller: bool,
    pub volumes: Vec<Volume>,
    pub nics: Vec<Nic>,
    pub devices: Vec<Device>,
    #[serde(default)]
    pub vmm_pid: Option<u32>,
    /// Which bridge each of this VM's overlays actually got, by VNI, as the
    /// driver that built it named it.
    ///
    /// `ensure_overlay` has always answered with the name and the answer was
    /// logged and thrown away; the teardown then rebuilt it from the VNI
    /// inside the driver. That is only the same string while ONE driver
    /// builds overlays on a node — and `destroy_overlay(vni)` reaching a
    /// driver with another naming convention would take down the wrong link
    /// or none. So the name is written down where it was learned, and the
    /// teardown hands it back to the driver to check against its own.
    ///
    /// Missing for a VNI — and empty on every record written before this
    /// existed — means "nobody wrote it down", which is not the same as "it
    /// has none": the driver then answers for its own naming as it did
    /// before, and the record says nothing either way.
    #[serde(default)]
    pub overlay_bridges: BTreeMap<u32, String>,
}

impl VmRecord {
    /// A record with nothing interesting in it: one vCPU, 256 MiB, firmware
    /// boot, nothing attached, running and provisioned. A test that is about
    /// one field dresses this up and says only what it is about.
    ///
    /// Public, and not behind `#[cfg(test)]`, because the two kinds of test
    /// that need it cannot share anything that is: the reconciler's own tests
    /// live inside the crate, and `tests/space` — the exhaustive walk over
    /// `plan`'s input space — links against it from outside. So it was
    /// written out twice, in `reconcile.rs` and in `tests/space/mod.rs`, and
    /// both copies had to be extended every time this struct gained a field.
    /// Three times they were; the fourth is what this exists to prevent.
    pub fn blank() -> Self {
        Self {
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
            nics: vec![],
            devices: vec![],
            vmm_pid: None,
            overlay_bridges: BTreeMap::new(),
        }
    }
}

/// What this node remembers about a volume it owns, with no consumer implied.
///
/// The record the `Volume` object one tier up always needed and never had.
/// It survives a restart, which is the whole point: bytes on a disk outlive
/// the process that made them, and an agent that forgot about them would be
/// an agent that cannot be asked to delete them.
///
/// `handle` is `None` between "told to make it" and "made it" — the window a
/// crash can land in, and the reason `provision` is idempotent by contract:
/// a record without a handle is picked up again and the backend hands back
/// the volume that is already there rather than a second one.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct VolumeRecord {
    pub spec: agent_api::storage::VolumeSpec,
    #[serde(default)]
    pub handle: Option<agent_api::storage::VolumeHandle>,
    pub phase: VolumeRecordPhase,
    /// Why that phase, in the one word a program may branch on.
    ///
    /// On the RECORD and not derived at report time, and that is the whole of
    /// why it is here: the two `Failed` cases are a provision the backend
    /// refused and a volume the backend has LOST, the fix for the first is a
    /// retry and the fix for the second is somebody's backup, and by the time
    /// anybody reads the report the only thing that told them apart was the
    /// driver's own prose. The pass that asked the driver is what knows, so
    /// the pass writes it down.
    ///
    /// `None` on a record from a build before this field — read as
    /// `VolumeReason::Unrecorded`, whose `message` is untouched — and on
    /// `Ready`, which needs no reason.
    #[serde(default)]
    pub reason: Option<crate::reconcile::VolumeReason>,
    #[serde(default)]
    pub message: Option<String>,
    /// When this record became a tombstone, if it did. See
    /// [`VolumeRecordPhase::Gone`].
    #[serde(default)]
    pub gone_at: Option<std::time::SystemTime>,
}

impl VolumeRecord {
    /// The name the backend knows it by, or empty while there is none.
    pub fn backend(&self) -> &str {
        self.handle
            .as_ref()
            .map(|h| h.backend.as_str())
            .unwrap_or("")
    }
}

/// What this node remembers about a snapshot it took.
///
/// The volume's id is on it, and that is not redundancy: a snapshot outlives
/// its volume, so once the volume's record is gone this is the only place
/// that says what the copy is OF — and an operator reading `agent snapshot
/// ls` on a node is asking exactly that.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SnapshotRecord {
    /// The `Volume` this is a copy of.
    pub volume: agent_api::storage::VolumeId,
    /// The backend's name for the copy. `None` between "told to take it" and
    /// "took it" — the same window a volume record has, and the same reason:
    /// the record is written first so a crash leaves a trace.
    #[serde(default)]
    pub handle: Option<agent_api::storage::VolumeHandle>,
    /// Which backend made it. Kept beside the handle because the volume's own
    /// record may be gone by the time this has to be dropped.
    pub driver: String,
    pub phase: SnapshotRecordPhase,
    /// Why that phase, in the one word a program may branch on. On the record
    /// and written by the pass that asked the driver — see
    /// [`VolumeRecord::reason`], which is here for the same reasons.
    ///
    /// `None` on a record from a build before this field (read as
    /// `SnapshotReason::Unrecorded`) and on `Ready`, which needs no reason.
    #[serde(default)]
    pub reason: Option<crate::reconcile::SnapshotReason>,
    #[serde(default)]
    pub message: Option<String>,
    /// When this record became a tombstone, if it did. Same mechanism, same
    /// TTL and same argument as [`VolumeRecordPhase::Gone`].
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

/// Where a snapshot is, as the NODE sees it. The volume's four, one word
/// different: a copy is `Creating` rather than `Provisioning`, because that
/// is what the object above it says and two spellings of one state is how a
/// parser starts guessing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum SnapshotRecordPhase {
    Creating,
    Ready,
    Failed,
    /// Dropped. Kept as a tombstone for the reason `VolumeRecordPhase::Gone`
    /// gives at length: absence from a report is "this node does not know".
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

/// Where a volume is, as the NODE sees it.
///
/// Four values and not the control plane's five: `Pending` is a phase of the
/// object before any node was told about it, so a node can never be in it —
/// being told is what creates the record. `Releasing` likewise belongs to the
/// object's finalizer and not to any bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum VolumeRecordPhase {
    /// Told to make it; no handle yet, or the last attempt is still running.
    Provisioning,
    /// The data exists. Attached or not — that is a VM record's business.
    Ready,
    /// The backend refused, and said why in `message`. The tier above
    /// requeues, and the kick is another Provision, which is idempotent.
    Failed,
    /// Deprovisioned. The record is KEPT as a tombstone rather than deleted,
    /// because absence from a status report means "this node does not know",
    /// and the tier above may only release a volume on an explicit `Gone`.
    /// Swept once it is old enough that nobody can still be waiting for it —
    /// and a Deprovision for an id this node has never heard of makes a fresh
    /// tombstone, so the sweep can never strand the tier above.
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
            // The proto path carries neither a fetchable image nor a seed,
            // the same way it carries neither driver nor params: the
            // controller sends spec_json (control-plane.md §6), and that is
            // where anything beyond the four original fields travels.
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
            // The proto path carries neither driver nor params; the
            // controller sends spec_json (see control-plane.md §6), and that
            // is where a routed volume travels. Same TODO the device
            // conversion below carries, and it will be closed the same way.
            // The typed proto path never carries a reference: a reference
            // is a field of the JSON spec, and the controller has sent
            // spec_json for every VM since long before this.
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
                // sends explicit
                // bridges
                mac: p
                    .mac
                    .parse::<MacAddr>()
                    .map_err(|e| anyhow::anyhow!("invalid mac {:?}: {e}", p.mac))?,
                // The proto NicSpec carries neither the overlay nor the
                // addresses nor the provider network: the controller sends
                // spec_json (control-plane.md §6) and that is where a
                // tenant-bound NIC travels. Same reason the volume conversion
                // above carries no driver.
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
        let params = non_empty(p.params_json)
            .map(|s| serde_json::from_str(&s))
            .transpose()
            .context("device params_json")?;
        Ok(Self {
            id: parse_uuid(&p.id).context("device id")?,
            // `driver_name` IS in the proto and is honoured here: routing a
            // device to the driver the controller named is the whole point of
            // the field, and silently sending every device to the node's
            // default was a lie the record then remembered forever.
            // An empty string is proto3's "unset" and keeps the old meaning,
            // so a controller that does not fill the field changes nothing.
            //
            // TODO(proto): `profile` still has no field; extend control.proto
            // when the controller learns to pick one.
            spec: DeviceSpec {
                driver: non_empty(p.driver_name).unwrap_or_else(default_device_driver),
                partition,
                profile: None,
                params,
            },
        })
    }
}

/// `NewVmSpec::into_spec`, as an extension trait because the type now belongs
/// to `agent-api` and the record it builds belongs here. One method, one
/// implementor: this is the tier boundary written as a trait rather than a
/// second copy of the document on this side of it.
pub trait NewVmSpecExt {
    fn into_spec(self, default_bridge: &str) -> anyhow::Result<(VmId, AgentVmSpec, Desired)>;
}

impl NewVmSpecExt for NewVmSpec {
    fn into_spec(self, default_bridge: &str) -> anyhow::Result<(VmId, AgentVmSpec, Desired)> {
        refuse_what_cannot_be_a_vm(&self)?;
        let vm_id = Uuid::new_v4();
        refuse_a_volume_entry_that_says_two_things(&self.volumes)?;
        let images = images_to_fetch(&self.volumes);
        Ok((
            vm_id,
            AgentVmSpec {
                vcpus: self.vcpus,
                memory_mib: self.memory_mib,
                boot: self.boot,
                volumes: volumes_with_ids(self.volumes)?,
                nics: nics_with_ids(self.nics, default_bridge)?,
                devices: devices_with_ids(self.devices)?,
                cloud_init: self.cloud_init,
                images,
            },
            self.desired,
        ))
    }
}

/// The three ways a create document is not a VM at all.
///
/// Read off the document alone: none of the three needs a node, a driver or
/// a store to answer, so they are answered before anything is built.
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

/// Whether a volume entry says anything about the bytes behind it.
fn describes_its_own_bytes(v: &NewVolume) -> bool {
    v.size_bytes != 0
        || v.base_image.is_some()
        || v.base_image_url.is_some()
        || v.base_image_sha256.is_some()
        || v.driver.is_some()
}

/// A volume entry describes a disk to be made, or names one that exists —
/// never both, and never neither.
///
/// A referenced volume has its size and its image already. Refused here
/// rather than quietly ignored: a spec that says both is a spec whose author
/// believes one of the two, and the wrong belief is the one where a 10 GiB
/// disk silently stays 1 GiB.
fn refuse_a_volume_entry_that_says_two_things(volumes: &[NewVolume]) -> anyhow::Result<()> {
    for v in volumes {
        if v.volume.is_none() {
            // An inline entry describes a disk to be made, and a disk of
            // no size is not one. Said here rather than left to serde,
            // which is what carried this refusal before the field could
            // default: a missing field is a sentence about a document and
            // this is a sentence about a disk.
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

/// The fetchable half, lifted out of the volumes and deduplicated: two
/// volumes off one base image are one download.
fn images_to_fetch(volumes: &[NewVolume]) -> Vec<crate::images::Source> {
    let mut images: Vec<crate::images::Source> = Vec::new();
    for v in volumes {
        let (Some(name), Some(url), Some(sha256)) = (
            v.base_image.as_deref(),
            v.base_image_url.as_deref(),
            v.base_image_sha256.as_deref(),
        ) else {
            // A url without a checksum, or either without a base_image,
            // asks for nothing: the create edge refuses that shape, and
            // here it simply means "look this name up locally", which is
            // what a path-based image has always meant.
            continue;
        };
        if !images.iter().any(|s| s.name == name) {
            images.push(crate::images::Source {
                name: name.to_string(),
                url: url.to_string(),
                sha256: sha256.to_string(),
            });
        }
    }
    images
}

/// One id per disk, and the fork the storage half turns on.
///
/// An entry that NAMES a volume carries nothing else — the size and the
/// image belong to the disk that already exists — and an entry that
/// describes one carries everything.
fn volumes_with_ids(volumes: Vec<NewVolume>) -> anyhow::Result<Vec<VolumeWithId>> {
    volumes
        .into_iter()
        .map(|v| match v.volume {
            // A referenced volume: the id IS the object's uid, and there
            // is nothing else in the entry to carry — the size and the
            // image belong to the disk that already exists, and
            // `refuse_a_volume_entry_that_says_two_things` refused the
            // entry before this if it named them.
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
                        // The attach options — a virtiofs tag today. The
                        // one field a reference may still carry, because
                        // it is a property of the CONNECTION rather than
                        // of the bytes.
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

/// One id per nic, and the two things a create document may leave out: the
/// mac address, derived from that id, and the bridge, which is this node's
/// default when the document names none.
fn nics_with_ids(nics: Vec<NewNic>, default_bridge: &str) -> anyhow::Result<Vec<NicWithId>> {
    nics.into_iter()
        .map(|n| {
            let id = Uuid::new_v4();
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

/// One id per device, and the one word of the document that is not free
/// text: how the card is partitioned.
fn devices_with_ids(devices: Vec<NewDevice>) -> anyhow::Result<Vec<DeviceWithId>> {
    devices
        .into_iter()
        .map(|d| {
            let partition = match d.partition.as_str() {
                "exclusive" => PartitionSpec::Exclusive,
                "mediated" => PartitionSpec::Mediated,
                other => anyhow::bail!("unknown partition type {other:?}"),
            };
            Ok(DeviceWithId {
                id: Uuid::new_v4(),
                spec: DeviceSpec {
                    driver: d.driver.unwrap_or_else(default_device_driver),
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

    /// `DeviceSpec.driver_name` is a real proto field, so a device the
    /// controller routed to `nvrm` must not land on the node's default
    /// driver. Unset stays unset: proto3 has no absent string, and an empty
    /// one still means "whatever this node defaults to".
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

    /// The controller has no Desired type of its own: it writes the variant
    /// name into `spec_json` and this serde is what has to accept it. Both
    /// halves of that contract are spelled by hand, so guard this one here
    /// and the other in the controller's `build_spec_json` test.
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
            let (_, _, desired) = spec.into_spec("br0").expect("spec is valid");
            assert_eq!(desired, expected);
        }
    }

    /// The cloud-init block: a spec without one is byte for byte the spec it
    /// always was, and a spec with one carries it through to the agent's own
    /// type. `NewVmSpec` is `deny_unknown_fields`, so this also holds the
    /// spelling of every key in it — a rename here would be a spec file that
    /// stops parsing on a node.
    #[test]
    fn a_cloud_init_block_travels_and_its_absence_changes_nothing() {
        let plain = r#"{"vcpus":1,"memory_mib":256,
                        "boot":{"kind":"firmware","firmware":"fw"},
                        "volumes":[{"size_bytes":1}]}"#;
        let spec: NewVmSpec = serde_json::from_str(plain).unwrap();
        let (_, agent, _) = spec.into_spec("br0").unwrap();
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
        let (_, agent, _) = spec.into_spec("br0").unwrap();
        let config = agent.cloud_init.expect("the block travels");
        assert_eq!(config.user_data, "#cloud-config\n");
        assert_eq!(config.network_config.as_deref(), Some("version: 2\n"));
        assert_eq!(config.local_hostname.as_deref(), Some("web-1"));
        assert_eq!(config.meta_data, None, "derived, not carried");
    }

    /// A create carrying runStrategy=Stopped provisions the VM without it
    /// ending up Running: the intent travels in the spec and the reconciler
    /// takes it from there (see `plan`).
    #[test]
    fn a_spec_without_a_desired_state_defaults_to_running() {
        let doc = r#"{"vcpus":1,"memory_mib":256,
                      "boot":{"kind":"firmware","firmware":"fw"},
                      "volumes":[{"size_bytes":1}]}"#;
        let spec: NewVmSpec = serde_json::from_str(doc).unwrap();
        assert_eq!(spec.into_spec("br0").unwrap().2, Desired::Running);
    }

    /// The repo's own spec files, parsed as they are on disk. `NewVmSpec` is
    /// `deny_unknown_fields`, so this catches a field renamed as well as one
    /// added — and it is the promise the volume driver/params fields were
    /// added under: every spec written before them means exactly what it did.
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
            spec.into_spec("br0")
                .unwrap_or_else(|e| panic!("{} is no longer valid: {e:#}", path.display()));
            seen += 1;
        }
        assert!(seen >= 3, "only {seen} specs found in {}", dir.display());
    }

    /// A volume that names no driver stays what it was: the default, which
    /// `Drivers::from_config` always registers.
    #[test]
    fn a_volume_without_a_driver_stays_the_default_one() {
        let doc = r#"{"vcpus":1,"memory_mib":256,
                      "boot":{"kind":"firmware","firmware":"fw"},
                      "volumes":[{"base_image":"n.raw","size_bytes":10}]}"#;
        let spec: NewVmSpec = serde_json::from_str(doc).unwrap();
        let (_, spec, _) = spec.into_spec("br0").unwrap();
        assert_eq!(spec.volumes[0].spec.driver, None);
        assert_eq!(spec.volumes[0].spec.params, None);
    }

    /// And one that does names it, with params the agent hands through
    /// untouched — the same shape a device request has, so a storage backend
    /// takes its options the way a gpu backend already does.
    #[test]
    fn a_volume_may_name_a_driver_and_carry_params_through() {
        let doc = r#"{"vcpus":1,"memory_mib":256,
                      "boot":{"kind":"firmware","firmware":"fw"},
                      "volumes":[{"size_bytes":10,"driver":"lvm-thin",
                                  "params":{"pool":"vg0/thin","snapshot_of":"base"}}]}"#;
        let spec: NewVmSpec = serde_json::from_str(doc).unwrap();
        let (_, spec, _) = spec.into_spec("br0").unwrap();
        assert_eq!(spec.volumes[0].spec.driver.as_deref(), Some("lvm-thin"));
        assert_eq!(
            spec.volumes[0].spec.params.as_ref().unwrap()["pool"],
            "vg0/thin"
        );
    }

    /// The compatibility invariant of this milestone at the tier that reads
    /// it: a NIC that says nothing about addresses means what it has always
    /// meant, and the two new lists come out empty. `deny_unknown_fields` is
    /// what makes the other direction hold too — a field renamed here fails
    /// this test and every spec in the repo along with it.
    #[test]
    fn a_nic_that_names_no_addresses_gets_none() {
        let doc = r#"{"vcpus":1,"memory_mib":256,
                      "boot":{"kind":"firmware","firmware":"fw"},
                      "volumes":[{"size_bytes":1}],
                      "nics":[{}]}"#;
        let spec: NewVmSpec = serde_json::from_str(doc).unwrap();
        let (_, spec, _) = spec.into_spec("br0").unwrap();
        assert_eq!(spec.nics[0].spec.bridge, "br0");
        assert_eq!(spec.nics[0].spec.vxlan_id, None);
        assert!(spec.nics[0].spec.floating_ips.is_empty());
        assert!(spec.nics[0].spec.routed_subnets.is_empty());

        // ... and the record that goes to disk carries neither key, so an
        // agent from before this milestone reads it back unchanged.
        let json = serde_json::to_value(&spec.nics[0].spec).unwrap();
        assert!(json.get("floating_ips").is_none(), "{json}");
        assert!(json.get("routed_subnets").is_none(), "{json}");
    }

    /// The standalone road: a cluster with no cloud above it has no FloatingIp
    /// objects to resolve, so the addresses go straight in the spec — and the
    /// same file is what the controller's injection produces, which is why
    /// there is only one shape to test.
    #[test]
    fn a_nic_may_name_its_own_addresses() {
        let doc = r#"{"vcpus":1,"memory_mib":256,
                      "boot":{"kind":"firmware","firmware":"fw"},
                      "volumes":[{"size_bytes":1}],
                      "nics":[{"vxlan_id":10007,
                               "floating_ips":["10.255.0.7"],
                               "routed_subnets":["10.7.1.0/24"]}]}"#;
        let spec: NewVmSpec = serde_json::from_str(doc).unwrap();
        let (_, spec, _) = spec.into_spec("br0").unwrap();
        assert_eq!(spec.nics[0].spec.vxlan_id, Some(10_007));
        assert_eq!(spec.nics[0].spec.floating_ips, ["10.255.0.7"]);
        assert_eq!(spec.nics[0].spec.routed_subnets, ["10.7.1.0/24"]);
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
            assert!(spec.into_spec("br0").is_err());
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

    /// The reference reaches the node as a uid and turns into an entry that
    /// is ATTACHED rather than made. The id is the object's, not one this
    /// node minted, which is what lets the node find the record it already
    /// has.
    #[test]
    fn a_referenced_volume_becomes_an_attach_with_the_objects_own_id() {
        let uid = uuid::Uuid::new_v4();
        let doc = referring(&uid.to_string(), serde_json::json!({}));
        let spec: NewVmSpec = serde_json::from_value(doc).expect("a spec");
        let (_, spec, _) = spec.into_spec("br0").expect("into_spec");
        assert_eq!(spec.volumes.len(), 1);
        assert!(spec.volumes[0].referenced);
        assert_eq!(spec.volumes[0].id, uid, "the object's uid, not a fresh one");
        assert_eq!(spec.volumes[0].spec.size_bytes, 0);
        assert!(spec.volumes[0].spec.base_image.is_none());
    }

    /// A referenced volume has its size and its image already, and saying so
    /// twice is saying it in two places that can disagree. `params` is the
    /// exception: an attach option is a property of the connection.
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
            let err = spec.into_spec("br0").expect_err("refused").to_string();
            assert_eq!(
                err, "a referenced volume has its size and image already",
                "for {extra}"
            );
        }

        // params alone is fine, and travels as the attach options.
        let spec: NewVmSpec =
            serde_json::from_value(referring(&uid, serde_json::json!({"params": {"tag": "d"}})))
                .expect("parses");
        let (_, spec, _) = spec.into_spec("br0").expect("accepted");
        assert_eq!(spec.volumes[0].spec.params.as_ref().unwrap()["tag"], "d");
    }

    /// An inline entry is unchanged, ephemeral, and gets an id this node
    /// minted — which is every volume this stack has ever made.
    #[test]
    fn an_inline_volume_is_still_made_here_and_is_still_ephemeral() {
        let doc = serde_json::json!({
            "vcpus": 1,
            "memory_mib": 64,
            "boot": {"kind": "firmware", "firmware": "/fw"},
            "volumes": [{"base_image": "tiny.raw", "size_bytes": 2048}]
        });
        let spec: NewVmSpec = serde_json::from_value(doc).expect("a spec");
        let (_, spec, _) = spec.into_spec("br0").expect("into_spec");
        assert!(!spec.volumes[0].referenced);
        assert_eq!(spec.volumes[0].spec.size_bytes, 2048);
        assert_eq!(spec.volumes[0].spec.base_image.as_deref(), Some("tiny.raw"));
    }

    /// A reference that is not a uid is a controller that did not resolve it,
    /// and the node says so rather than minting an id and making a disk.
    #[test]
    fn a_reference_that_is_not_a_uid_is_refused() {
        let spec: NewVmSpec =
            serde_json::from_value(referring("data-1", serde_json::json!({}))).expect("parses");
        let err = spec.into_spec("br0").expect_err("refused").to_string();
        assert!(err.contains("data-1") && err.contains("uid"), "{err}");
    }
}
