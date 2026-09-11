// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Storage as the agent sees it: a volume is PROVISIONED, and separately
//! ATTACHED to whatever is going to read it.
//!
//! # The two verbs, and why they had to come apart
//!
//! There used to be one trait and one verb. `BlockDriver::create` took the
//! VM's cgroup handle, because a backend process belongs in the VM's slice
//! from the moment it is spawned; `destroy` took an attachment, because that
//! is where the record remembered which device the data was on. Both are
//! true of a CONNECTION and neither is true of a VOLUME, and together they
//! made "delete this VM" and "delete this disk" the same act. A volume could
//! not outlive its VM because the trait had no way to say what a volume was
//! when no VM was holding it.
//!
//! So: [`VolumeProvider`] makes and unmakes the data, and knows nothing about
//! any consumer. [`VolumeAttacher`] makes and unmakes the connection, and the
//! cgroup lives here — virtiofsd, a vhost-user-blk backend, an `nvme connect`
//! session are properties of the attachment and go when it does. A driver
//! implements one or both; all three in this tree implement both, which makes
//! them the degenerate case (provision and attach land on the same node) and
//! is exactly what the split has to keep cheap.
//!
//! # One consumer at a time
//!
//! RWO, written down rather than half-supported. Multi-attach needs reference
//! counting at detach — without it the one VM that stops tears the device out
//! from under the other — and a `VolumeHandle` therefore identifies at most
//! one live attachment. That is what lets [`VolumeAttacher::detach`] take the
//! handle beside the attachment: under RWO the volume names its connection.
//!
//! # What is still missing above this file
//!
//! A `Volume` resource with its own lifecycle, a scheduler that picks where a
//! volume is provisioned, a controller that attaches one to a node rather
//! than creating one on it. This file is the seam those need and not the
//! thing itself. The next backend the shape is for is the replicated one:
//! `VhostUserBlk` is what an SPDK-style backend hands over, and
//! `needs_shared_memory` is the one thing the hypervisor has to be told.

use uuid::Uuid;

use crate::CgroupHandle;

pub type VolumeId = Uuid;

/// A snapshot's identity, handed down from the `VolumeSnapshot` object's uid.
///
/// A type of its own beside `VolumeId` and not an alias for it, because the
/// two are never interchangeable in a signature: `snapshot(handle, id)` takes
/// the volume it is OF and the name the snapshot will have, and a driver that
/// swapped them would name a snapshot after the disk it came from.
pub type SnapshotId = Uuid;

/// Where a backend's bytes are. Defined in `common::capability` because the
/// tier that ACTS on the answer — the scheduler, one crate over — must not
/// depend on this one, and re-exported here because a driver is what states
/// it. See [`VolumeProvider::locality`].
pub use common::capability::Locality;

#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    #[error("volume not found: {0}")]
    NotFound(VolumeId),
    #[error("base image not found: {0}")]
    ImageNotFound(String),
    #[error("invalid volume spec: {0}")]
    InvalidSpec(String),
    /// A backend process (virtiofsd, a vhost-user-blk daemon) died or never
    /// came up. Separate from `Backend` for the same reason `DeviceError`
    /// separates it: it names a process, and the message carries its log.
    #[error("storage backend process died: {0}")]
    BackendDied(String),
    /// This backend does not do that at all — not "it failed", but "there is
    /// no such verb here".
    ///
    /// Its own variant because the tier above branches on it: a pool whose
    /// driver cannot snapshot is a 422 at the API edge, where a person is
    /// still holding the request, rather than a `Failed` object twenty
    /// seconds later. Everything else on this enum is a thing that went
    /// wrong; this is a thing that was never going to happen.
    #[error("this backend cannot do that: {0}")]
    Unsupported(String),
    #[error("storage backend failure: {0}")]
    Backend(anyhow::Error),
}

/// What a backend has to be given for its snapshot to be worth anything.
///
/// A property of the BACKEND and not of the request, which is why it is asked
/// rather than passed: whether a copy has to happen at a standstill is a fact
/// about how the copy is made, and a caller cannot know it.
///
/// Defined in `common::capability` and re-exported here, exactly as
/// [`Locality`] is and for the same reason: since it travels in the catalogue
/// (`volume/<backend>/snapshot:atomic`), the tier that ACTS on it is a
/// controller, and no controller depends on this crate.
pub use common::capability::SnapshotConsistency;

pub type Result<T> = std::result::Result<T, StorageError>;

/// What the guest is asked for. `driver` and `params` are the same two fields
/// a device spec carries, and for the same reason: the agent routes on the
/// driver name and hands the params through untouched, so a backend can take
/// options nothing between here and it has to know about.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct VolumeSpec {
    pub base_image: Option<String>,
    pub size_bytes: u64,
    /// None = the default driver, `filesystem`. A serde default rather than a
    /// required field on purpose: every spec written before storage had more
    /// than one backend goes on meaning what it meant.
    #[serde(default)]
    pub driver: Option<String>,
    #[serde(default)]
    pub params: Option<serde_json::Value>,
}

/// The default when a spec names no driver — the mirror of
/// `device::default_device_driver`, and the reason today's specs stay valid.
///
/// The string itself lives in `common::capability` because the scheduler one
/// tier up needs the same one: a volume asking for the default constrains
/// nothing, and the two halves saying that differently would strand VMs.
pub fn default_volume_driver() -> String {
    common::capability::DEFAULT_VOLUME_DRIVER.to_string()
}

/// How the created volume reaches the VMM. The mirror image of
/// `DeviceAttachment`: either the host hands over something the hypervisor can
/// open by path, or a backend process is speaking vhost-user and what is
/// handed over is its socket.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub enum VolumeAttachment {
    /// Block device or file on the host (filesystem, LVM-thin, NFS).
    Path(std::path::PathBuf),
    /// vhost-user-blk socket of a storage backend process (SPDK/Mayastor
    /// style). `memory.shared` follows, exactly as it does for devices — the
    /// backend maps guest memory, and it cannot map what is not shared.
    VhostUserBlk {
        socket: std::path::PathBuf,
        pid: u32,
    },
    /// A virtiofs export: virtiofsd speaks vhost-user-fs on `socket`, and the
    /// guest mounts it with `mount -t virtiofs <tag> …`. Needs shared memory
    /// like every vhost-user attachment.
    ///
    /// Not a block device, and the one place that matters is the VMM config:
    /// this is a `fs` entry, not a disk, so `is_block` is what the two call
    /// sites that care ask rather than matching the variant themselves.
    FsShare {
        socket: std::path::PathBuf,
        tag: String,
        pid: u32,
    },
}

impl VolumeAttachment {
    /// Whether this attachment needs the guest's memory to be shareable. One
    /// named predicate, because the answer has to be the same for volumes and
    /// devices and the hypervisor driver asks it of both.
    pub fn needs_shared_memory(&self) -> bool {
        matches!(
            self,
            VolumeAttachment::VhostUserBlk { .. } | VolumeAttachment::FsShare { .. }
        )
    }

    /// Whether this attachment is a block device the guest can boot from.
    /// A share is a filesystem export and appears nowhere near the disk list.
    pub fn is_block(&self) -> bool {
        !matches!(self, VolumeAttachment::FsShare { .. })
    }

    /// The pid of the backend process serving this volume, if there is one.
    ///
    /// The mirror of the match the reconciler runs over device attachments,
    /// and it exists so that liveness is asked the same way of both halves of
    /// a VM: a backend that is no longer in the VM's cgroup slice is a dead
    /// backend, whether it was serving a GPU or a share.
    pub fn backend_pid(&self) -> Option<u32> {
        match self {
            VolumeAttachment::Path(_) => None,
            VolumeAttachment::VhostUserBlk { pid, .. } | VolumeAttachment::FsShare { pid, .. } => {
                Some(*pid)
            }
        }
    }
}

/// A provisioned volume: what exists on a backend, named the way that backend
/// names it, with no consumer implied.
///
/// The thing the old trait had no word for. It is what `provision` hands back
/// and what `deprovision` takes — so deleting the data needs no attachment,
/// which is the whole point: when a volume outlives its VM there is no
/// attachment at that moment to hand anybody.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct VolumeHandle {
    /// The control plane's name for the volume.
    pub id: VolumeId,
    /// What the BACKEND calls it — `/var/lib/meister/volumes/<id>.raw`,
    /// `/dev/vg0/vm-<id>`, a share directory. A path for every backend in
    /// this tree and a `String` all the same, because the next one names its
    /// volumes and does not path them (a LINSTOR resource, an NVMe subsystem
    /// NQN).
    ///
    /// Every backend here derives it from `id`, and that is not a
    /// coincidence: a `provision` that succeeds and whose handle is then lost
    /// must not produce a second volume on the next try. Written down as a
    /// rule where the Volume object gets its name.
    pub backend: String,
    pub size_bytes: u64,
    /// The spec's `params`, carried forward.
    ///
    /// Attaching needs the half of the request the volume itself does not
    /// remember — virtiofs's tag is the one today, and it is a property of
    /// the connection rather than of the bytes. Kept on the handle rather
    /// than passed beside it so that `attach` needs nothing but a handle and
    /// a cgroup, which is what makes an attacher usable by something that
    /// never saw the spec.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub params: Option<serde_json::Value>,
}

impl VolumeHandle {
    /// `backend` as a path, for the backends whose name for a volume is one.
    pub fn path(&self) -> std::path::PathBuf {
        std::path::PathBuf::from(&self.backend)
    }
}

/// What a backend can say about a volume that is there.
///
/// Absence is `StorageError::NotFound` and not a field in here: a caller
/// asking about a volume wants the answer or the error, and a struct with a
/// `present: false` in it is an answer every caller has to remember to check.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct VolumeState {
    pub size_bytes: u64,
}

/// A volume that is provisioned AND attached — what a VM's record holds for
/// as long as the VM is holding it.
///
/// Two fields and no third: `id` and `size_bytes` are the handle's, asked
/// through it rather than copied beside it, because a second copy in a record
/// is a value that can be wrong.
///
/// Read through `VolumeRepr` so that every record ever written still loads.
/// Three shapes so far, each one a strictly smaller statement than the next:
/// a bare path, then a path-or-socket attachment, and now an attachment with
/// the provisioned volume behind it. Written in the current shape always —
/// one restart migrates the store, and nothing has to be told to.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(from = "VolumeRepr")]
pub struct Volume {
    pub handle: VolumeHandle,
    pub attachment: VolumeAttachment,
    /// Whether the connection this `attachment` describes has already been
    /// given back.
    ///
    /// A stopped VM keeps its volumes and loses its backend processes, so a
    /// record can outlive the attachment written on it — and the record is
    /// the only place that can say so. Without this the teardown after a stop
    /// detaches a second time, and a second detach is not a no-op: the
    /// driver's own map no longer has the entry, so it falls back to the pid
    /// on this attachment, which by then may belong to somebody else.
    ///
    /// `false` in every record ever written, which is the truth for all of
    /// them: before this existed nothing marked a detach, so nothing had been
    /// detached and left on record.
    ///
    /// Not an `Option<VolumeAttachment>` — the attachment is still what it
    /// was, and the deprovision path and `lvm-thin`'s device-path recovery
    /// both still read it. What changed is whether anybody is holding it.
    #[serde(default)]
    pub detached: bool,
}

impl Volume {
    /// A volume as it comes off a fresh attach: connected, nobody has given
    /// it back yet.
    pub fn attached(handle: VolumeHandle, attachment: VolumeAttachment) -> Self {
        Self {
            handle,
            attachment,
            detached: false,
        }
    }
}

impl Volume {
    pub fn id(&self) -> VolumeId {
        self.handle.id
    }

    pub fn size_bytes(&self) -> u64 {
        self.handle.size_bytes
    }
}

#[derive(serde::Deserialize)]
#[serde(untagged)]
enum VolumeRepr {
    Current {
        handle: VolumeHandle,
        attachment: VolumeAttachment,
        #[serde(default)]
        detached: bool,
    },
    /// Records from before provisioning and attaching came apart: one
    /// attachment, and whatever the backend had made behind it left unsaid.
    Attached {
        id: VolumeId,
        attachment: VolumeAttachment,
        size_bytes: u64,
    },
    /// Pre-attachment records, from the agent's redb store.
    Legacy {
        id: VolumeId,
        path: std::path::PathBuf,
        size_bytes: u64,
    },
}

impl From<VolumeRepr> for Volume {
    fn from(repr: VolumeRepr) -> Self {
        // What a migrated record can say about the volume behind its
        // attachment, which is: where it was, when the attachment was a path.
        //
        // Enough, and it is worth saying why. `backend` is read by exactly one
        // deprovision path — lvm-thin, recovering the volume group from the
        // device path, which a `Path` attachment carries. Every other backend
        // derives its own name from the id and asks the handle for nothing.
        // A share's backend directory is derived from the id too, so an
        // FsShare record losing its path here costs nothing.
        let migrate = |id, attachment: VolumeAttachment, size_bytes| Volume {
            // A record from before the flag existed was written by a stop
            // that did not mark anything, so nothing on it had been given
            // back: `false` is the migration and also the truth.
            detached: false,
            handle: VolumeHandle {
                id,
                backend: match &attachment {
                    VolumeAttachment::Path(p) => p.to_string_lossy().into_owned(),
                    _ => String::new(),
                },
                size_bytes,
                // The spec is where params come from, and a re-provision reads
                // it again. Nothing on the teardown path wants them.
                params: None,
            },
            attachment,
        };
        match repr {
            VolumeRepr::Current {
                handle,
                attachment,
                detached,
            } => Volume {
                handle,
                attachment,
                detached,
            },
            VolumeRepr::Attached {
                id,
                attachment,
                size_bytes,
            } => migrate(id, attachment, size_bytes),
            VolumeRepr::Legacy {
                id,
                path,
                size_bytes,
            } => migrate(id, VolumeAttachment::Path(path), size_bytes),
        }
    }
}

/// The half that owns the DATA. Knows about no consumer at all.
///
/// No cgroup anywhere in it, and that absence is the trait's whole content: a
/// volume is not a process, so there is no slice for it to belong to. A
/// backend that spawns something to SERVE the volume spawns it in
/// [`VolumeAttacher::attach`], where there is a consumer whose slice it
/// belongs in.
#[async_trait::async_trait]
pub trait VolumeProvider: Send + Sync {
    /// Make the volume, or hand back the one that is already there.
    ///
    /// Idempotent by contract, and the contract is load-bearing: a provision
    /// that succeeds and whose handle is then lost — a controller that dies
    /// before writing it down — must be found again by the next call rather
    /// than answered with a second volume. Every backend here manages that by
    /// deriving its name from `id`.
    async fn provision(&self, id: &VolumeId, spec: &VolumeSpec) -> Result<VolumeHandle>;

    /// Destroy the volume AND its data. Idempotent: deprovisioning an
    /// already-gone volume is Ok.
    ///
    /// No attachment, which is the point of the split. A volume that outlived
    /// its VM has none at the moment it is deleted, and a signature that
    /// asked for one made "tear down this VM" and "delete this disk" the same
    /// act.
    async fn deprovision(&self, handle: &VolumeHandle) -> Result<()>;

    /// What is there, or `NotFound`. Asked of the DATA — no attachment
    /// needed, so it can be asked of a volume nobody is holding.
    async fn describe(&self, handle: &VolumeHandle) -> Result<VolumeState>;

    /// Where this backend's bytes are, once and for all.
    ///
    /// **No default, deliberately.** A default would be a value the author of
    /// the next backend never had to think about, and the one thing a wrong
    /// answer here does is place a VM on a node where its disk is not. So the
    /// compiler asks, every time: an LVM volume group is on one machine
    /// ([`Locality::NodeLocal`]), an NFS export is the same bytes on every
    /// node that mounts it ([`Locality::Shared`]), an NVMe-oF namespace is
    /// somewhere else entirely ([`Locality::Networked`]).
    ///
    /// A property of the DRIVER and not of the pool, which is why it is a
    /// method here and not a field an admin fills in: `StoragePoolSpec` has no
    /// locality, and an admin who could write one into it could tell the
    /// scheduler that an lvm-thin pool is shared.
    ///
    /// `&self` rather than an associated const because a backend may one day
    /// answer from its configuration — the same `nfs` driver serves block
    /// files and shares, and a future driver reading a plugin's topology at
    /// start-up is exactly the shape this leaves room for.
    fn locality(&self) -> Locality;

    // --- snapshots ---------------------------------------------------------
    //
    // On the PROVIDER and not on the attacher, which is the same cut
    // `locality` made and for the same reason: a snapshot is a statement
    // about DATA and needs no consumer. A volume nobody is holding can be
    // snapshotted, and one being held is snapshotted by the node that made
    // it — which under a `shared` pool is not the node the VM runs on.
    //
    // Defaulted, unlike `locality`. A default there would have been a value
    // nobody thought about; here it is the honest answer of most backends,
    // and the compiler asking every driver "can you snapshot?" would only
    // produce four copies of "no".

    /// Grow the volume to `size_bytes`. Never shrink.
    ///
    /// Idempotent: a backend that already has that size is `Ok`, not an
    /// error. That is what lets the tier above be level-triggered — a resize
    /// whose answer was lost is simply asked again.
    ///
    /// **Always the driver, even for a volume nothing is holding.** The
    /// hypervisor's `vm.resize-disk` grows a FILE on its own, which would
    /// make this call redundant for `filesystem` under a running VM — but it
    /// does nothing at all for a block device (see the VMM half of the resize
    /// in the cluster's `ResizeAttachment`), and a volume that is not
    /// attached has no VMM to ask. One place that grows the bytes, and the
    /// hypervisor's job is only to tell the guest.
    ///
    /// Default `Unsupported`, and the same argument as the snapshot verbs:
    /// the refusal is a variant, so the tier above answers 422 at the edge.
    async fn resize(&self, handle: &VolumeHandle, size_bytes: u64) -> Result<VolumeHandle> {
        let _ = (handle, size_bytes);
        Err(StorageError::Unsupported("resize".into()))
    }

    /// Whether this backend can snapshot at all, and what it needs if it can.
    ///
    /// `None` = it cannot, and that is what puts `volume/<driver>/snapshot`
    /// in or out of the node's catalogue — the same spelling a GPU profile
    /// claims, so a pool whose driver cannot do it is refused at the API edge
    /// instead of failing later.
    fn snapshot_support(&self) -> Option<SnapshotConsistency> {
        None
    }

    /// Freeze what the volume holds right now under `id`.
    ///
    /// Idempotent by the same contract `provision` has and for the same
    /// reason: the handle can be lost between the call and the write. Every
    /// backend derives the snapshot's name from `id`, so asking twice finds
    /// the first one rather than making a second.
    ///
    /// The returned handle names the SNAPSHOT, not the volume — it is what
    /// `drop_snapshot` and `provision_from` are given.
    async fn snapshot(&self, handle: &VolumeHandle, id: &SnapshotId) -> Result<VolumeHandle> {
        let _ = (handle, id);
        Err(StorageError::Unsupported("snapshot".into()))
    }

    /// Destroy a snapshot and its data. Idempotent: one that is already gone
    /// is `Ok`.
    async fn drop_snapshot(&self, handle: &VolumeHandle) -> Result<()> {
        let _ = handle;
        Err(StorageError::Unsupported("drop_snapshot".into()))
    }

    /// Make a new, WRITEABLE volume holding what a snapshot holds.
    ///
    /// Beside `provision` rather than a flag on it, because the two start
    /// from different things: `provision` starts from a base image out of
    /// this node's catalogue, and this starts from a handle. A backend that
    /// can do it cheaply does (a second thin snapshot of the snapshot); one
    /// that cannot copies.
    ///
    /// `spec.size_bytes` is the size asked for and must be at least the
    /// snapshot's — growing on the way out is fine, shrinking is not, and a
    /// backend that cannot tell says so with `InvalidSpec`.
    async fn provision_from(
        &self,
        id: &VolumeId,
        snapshot: &VolumeHandle,
        spec: &VolumeSpec,
    ) -> Result<VolumeHandle> {
        let _ = (id, snapshot, spec);
        Err(StorageError::Unsupported("provision_from".into()))
    }

    /// Let go of whatever THIS NODE holds for the volume, and touch no data.
    ///
    /// The verb a live migration needed and no backend had. After a guest
    /// moves, the source is left with a volume record, possibly a per-node
    /// claim, and no business with either: the bytes belong to the
    /// destination now and the object one tier up says so. `deprovision` is
    /// the wrong call by a mile — for `filesystem` and `lvm-thin` it destroys
    /// somebody's disk.
    ///
    /// So this is the narrow one. Everything a node holds ABOUT the volume
    /// goes; everything the volume IS stays. For most backends that is
    /// nothing at all, which is why the default does nothing and answers
    /// `Ok`: a `filesystem` pool's file IS the data and an `lvm-thin` LV IS
    /// the data, and neither node-local backend can be the source of a live
    /// migration in the first place.
    ///
    /// The one backend with something to release is `nvmeof-import`, whose
    /// claim file is a per-node reservation over a namespace somebody else
    /// owns. Left behind, it is a name spoken for on a machine that has
    /// nothing to do with it any more, and the next volume assigned that
    /// namespace there is refused over a conflict with a guest that left.
    ///
    /// Idempotent, and `Ok` for a handle this backend has never seen: "let go
    /// of something you are not holding" is already done.
    async fn forget(&self, handle: &VolumeHandle) -> Result<()> {
        let _ = handle;
        Ok(())
    }
}

/// The half that owns the CONNECTION, and everything that lives as long as
/// one: virtiofsd, a vhost-user-blk backend, an `nvme connect` session.
///
/// The cgroup is here and only here. A backend process belongs in the
/// consumer's slice from the moment it is spawned, and the consumer is what
/// an attachment has and a volume does not.
///
/// `handle` beside `attachment` on the teardown methods is RWO written into
/// the signature: one consumer at a time, so the volume names its connection.
/// The day multi-attach arrives, the second consumer needs an attachment
/// identity of its own AND reference counting at detach — which is why it is
/// declared unsupported here rather than half-built.
#[async_trait::async_trait]
pub trait VolumeAttacher: Send + Sync {
    /// Make the volume reachable, and say how.
    async fn attach(
        &self,
        handle: &VolumeHandle,
        cgroup: Option<&CgroupHandle>,
    ) -> Result<VolumeAttachment>;

    /// Take the connection down, keeping the data.
    ///
    /// What a stopped VM needs and `deprovision` is far too much for: the
    /// volume stays, only the process serving it goes. A backend whose
    /// attachment is a plain path has nothing to do here and says so by
    /// doing nothing.
    async fn detach(&self, handle: &VolumeHandle, attachment: &VolumeAttachment) -> Result<()> {
        let _ = (handle, attachment);
        Ok(())
    }

    /// Liveness of the CONNECTION: Ok if what this attachment names is still
    /// there and usable, `NotFound` otherwise. The mirror of `describe`, one
    /// layer out — a share whose virtiofsd died is gone by this question and
    /// perfectly present by that one.
    async fn stat(
        &self,
        handle: &VolumeHandle,
        attachment: &VolumeAttachment,
    ) -> Result<VolumeState>;
}

/// A backend that does both halves on one node.
///
/// A blanket supertrait, the same shape `NetworkDriver` has and for the same
/// reason: the agent's driver table registers one row per driver and hands
/// back one `Arc`. Every backend in this tree is one of these — which is the
/// degenerate case the split has to keep cheap, and the thing position 6 of
/// the storage brief measures.
///
/// A provider-only backend (LINSTOR on a node with no VMs) does not implement
/// this, and registering one is a second table rather than a change here.
pub trait VolumeDriver: VolumeProvider + VolumeAttacher {}

impl<T: VolumeProvider + VolumeAttacher + ?Sized> VolumeDriver for T {}

#[cfg(test)]
mod tests {
    use super::*;

    /// A volume as a record holds it: provisioned somewhere, attached here.
    fn attached(attachment: VolumeAttachment, size_bytes: u64) -> Volume {
        Volume {
            handle: VolumeHandle {
                id: Uuid::nil(),
                backend: "/backend/name".to_string(),
                size_bytes,
                params: None,
            },
            attachment,
            detached: false,
        }
    }

    /// The whole point of the serde defaults: a spec written before storage
    /// had a driver field means exactly what it meant.
    #[test]
    fn a_spec_without_a_driver_is_still_a_valid_spec() {
        let spec: VolumeSpec = serde_json::from_str(r#"{"base_image":"a.raw","size_bytes":10}"#)
            .expect("today's spec parses");
        assert_eq!(spec.driver, None);
        assert_eq!(spec.params, None);
        assert_eq!(default_volume_driver(), "filesystem");
    }

    #[test]
    fn a_spec_may_name_a_driver_and_hand_it_params() {
        let spec: VolumeSpec = serde_json::from_str(
            r#"{"base_image":null,"size_bytes":1,"driver":"lvm-thin","params":{"pool":"vg0/thin"}}"#,
        )
        .unwrap();
        assert_eq!(spec.driver.as_deref(), Some("lvm-thin"));
        assert_eq!(spec.params.unwrap()["pool"], "vg0/thin");
    }

    /// A record from before the attachment split still loads, and loads as
    /// what it was: a path. Without this the agent's store would drop the
    /// record on the next restart — `Store::list` skips what it cannot decode
    /// — and the VM would go on running with nobody left who knows about it.
    #[test]
    fn a_pre_attachment_record_loads_as_a_path() {
        let legacy = r#"{"id":"00000000-0000-0000-0000-000000000001",
                         "path":"/var/lib/meister/volumes/x.raw","size_bytes":42}"#;
        let vol: Volume = serde_json::from_str(legacy).expect("legacy record loads");
        assert_eq!(vol.size_bytes(), 42);
        assert_eq!(vol.handle.backend, "/var/lib/meister/volumes/x.raw");
        match vol.attachment {
            VolumeAttachment::Path(p) => {
                assert_eq!(
                    p,
                    std::path::PathBuf::from("/var/lib/meister/volumes/x.raw")
                )
            }
            other => panic!("legacy path became {other:?}"),
        }
    }

    /// And it is written back in the new shape, so one restart migrates the
    /// store without anything having to be told to.
    #[test]
    fn a_loaded_record_is_written_back_in_the_current_shape() {
        let legacy = r#"{"id":"00000000-0000-0000-0000-000000000001",
                         "path":"/x.raw","size_bytes":42}"#;
        let vol: Volume = serde_json::from_str(legacy).unwrap();
        let round: serde_json::Value = serde_json::to_value(&vol).unwrap();
        assert_eq!(round["attachment"]["Path"], "/x.raw");
        assert!(round.get("path").is_none());
        assert!(
            round.get("size_bytes").is_none(),
            "it lives on the handle now"
        );
        assert_eq!(round["handle"]["backend"], "/x.raw");
        // and the current shape reads back unchanged
        let again: Volume = serde_json::from_value(round).unwrap();
        assert!(matches!(again.attachment, VolumeAttachment::Path(_)));
        assert_eq!(again.size_bytes(), 42);
    }

    #[test]
    fn a_vhost_user_volume_round_trips_and_asks_for_shared_memory() {
        let vol = attached(
            VolumeAttachment::VhostUserBlk {
                socket: "/run/blk.sock".into(),
                pid: 7,
            },
            1,
        );
        assert!(vol.attachment.needs_shared_memory());
        let json = serde_json::to_string(&vol).unwrap();
        let back: Volume = serde_json::from_str(&json).unwrap();
        match back.attachment {
            VolumeAttachment::VhostUserBlk { socket, pid } => {
                assert_eq!(socket, std::path::PathBuf::from("/run/blk.sock"));
                assert_eq!(pid, 7);
            }
            other => panic!("{other:?}"),
        }
        assert!(!VolumeAttachment::Path("/x".into()).needs_shared_memory());
    }

    /// The third form, through the same untagged migration the other two go
    /// through. `VolumeRepr::Current` carries it because it carries whatever
    /// `VolumeAttachment` is — which is the whole reason the enum extension
    /// is not a store break.
    #[test]
    fn a_share_round_trips_through_the_migrating_repr() {
        let vol = attached(
            VolumeAttachment::FsShare {
                socket: "/run/fs.sock".into(),
                tag: "share".into(),
                pid: 11,
            },
            0,
        );
        let json = serde_json::to_string(&vol).unwrap();
        let back: Volume = serde_json::from_str(&json).unwrap();
        match back.attachment {
            VolumeAttachment::FsShare { socket, tag, pid } => {
                assert_eq!(socket, std::path::PathBuf::from("/run/fs.sock"));
                assert_eq!(tag, "share");
                assert_eq!(pid, 11);
            }
            other => panic!("{other:?}"),
        }
    }

    /// The record shape that existed between the attachment split and the
    /// provider/attacher one: an attachment and a size, with nothing said
    /// about the volume behind it. It has to keep loading, and what it turns
    /// into has to be enough to DELETE the volume — which for the one backend
    /// that reads `backend` (lvm-thin, recovering its volume group) means the
    /// device path off the attachment.
    #[test]
    fn a_pre_handle_record_loads_and_keeps_the_path_its_backend_needs() {
        let attached = r#"{"id":"00000000-0000-0000-0000-000000000001",
                           "attachment":{"Path":"/dev/vg0/vm-x"},
                           "size_bytes":4096}"#;
        let vol: Volume = serde_json::from_str(attached).expect("a pre-handle record loads");
        assert_eq!(vol.handle.backend, "/dev/vg0/vm-x");
        assert_eq!(vol.size_bytes(), 4096);
        assert!(vol.handle.params.is_none());
        assert_eq!(vol.handle.path(), std::path::PathBuf::from("/dev/vg0/vm-x"));
    }

    /// A migrated share record carries no backend path, and that is not a
    /// loss: a share directory is derived from the volume id, so the backend
    /// that owns it never asks the handle where it is. Stated here because
    /// the alternative — guessing a path — would delete the wrong directory.
    #[test]
    fn a_migrated_share_record_keeps_no_path_and_needs_none() {
        let attached = r#"{"id":"00000000-0000-0000-0000-000000000001",
                           "attachment":{"FsShare":{"socket":"/run/x.sock",
                                                    "tag":"share","pid":11}},
                           "size_bytes":0}"#;
        let vol: Volume = serde_json::from_str(attached).unwrap();
        assert!(vol.handle.backend.is_empty());
        assert_eq!(
            vol.id(),
            Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap()
        );
        assert!(vol.attachment.backend_pid() == Some(11));
    }

    /// The handle is what `deprovision` gets, and it carries no attachment.
    /// Stated as a round trip because that is the promise the whole split
    /// rests on: a volume can be described, and deleted, with no consumer in
    /// the picture at all.
    #[test]
    fn a_handle_round_trips_without_an_attachment_anywhere_in_it() {
        let handle = VolumeHandle {
            id: Uuid::nil(),
            backend: "/dev/vg0/vm-x".into(),
            size_bytes: 8,
            params: Some(serde_json::json!({"kind": "share", "tag": "data"})),
        };
        let json = serde_json::to_value(&handle).unwrap();
        assert!(json.get("attachment").is_none());
        let back: VolumeHandle = serde_json::from_value(json).unwrap();
        assert_eq!(back.backend, "/dev/vg0/vm-x");
        assert_eq!(back.params.unwrap()["tag"], "data");

        // No params is the ordinary case and must not become `null` on disk.
        let plain = VolumeHandle {
            id: Uuid::nil(),
            backend: "/x.raw".into(),
            size_bytes: 1,
            params: None,
        };
        let json = serde_json::to_value(&plain).unwrap();
        assert!(json.get("params").is_none());
        assert!(
            serde_json::from_value::<VolumeHandle>(json)
                .unwrap()
                .params
                .is_none()
        );
    }

    /// A share is a vhost-user backend, so the VM's memory has to be
    /// shareable; and it is not a disk, so it has no business in the disk
    /// list. Both answers come from here rather than from a match at each
    /// call site.
    #[test]
    fn a_share_needs_shared_memory_and_is_not_a_block_device() {
        let share = VolumeAttachment::FsShare {
            socket: "/run/fs.sock".into(),
            tag: "share".into(),
            pid: 11,
        };
        assert!(share.needs_shared_memory());
        assert!(!share.is_block());
        assert!(VolumeAttachment::Path("/a.raw".into()).is_block());
        assert!(
            VolumeAttachment::VhostUserBlk {
                socket: "/s".into(),
                pid: 1
            }
            .is_block()
        );
    }

    /// Liveness is asked of a volume exactly as it is asked of a device: a
    /// pid, or nothing to ask about.
    #[test]
    fn only_a_backend_served_volume_has_a_pid() {
        assert_eq!(VolumeAttachment::Path("/a.raw".into()).backend_pid(), None);
        assert_eq!(
            VolumeAttachment::VhostUserBlk {
                socket: "/s".into(),
                pid: 9
            }
            .backend_pid(),
            Some(9)
        );
        assert_eq!(
            VolumeAttachment::FsShare {
                socket: "/s".into(),
                tag: "t".into(),
                pid: 11
            }
            .backend_pid(),
            Some(11)
        );
    }

    /// The three snapshot verbs default to a refusal, and `snapshot_support`
    /// defaults to "cannot".
    ///
    /// Unlike `locality`, where the compiler asks every driver because a
    /// wrong answer puts a VM on a node without its disk. Here a default IS
    /// the answer of most backends, and making the compiler ask would only
    /// produce four copies of "no". What makes that safe is that the refusal
    /// is a VARIANT and not a message: the tier above branches on
    /// `Unsupported` to answer 422 at the edge instead of `Failed` later.
    #[tokio::test]
    async fn a_backend_that_says_nothing_about_snapshots_cannot_take_one() {
        struct Plain;

        #[async_trait::async_trait]
        impl VolumeProvider for Plain {
            fn locality(&self) -> Locality {
                Locality::NodeLocal
            }
            async fn provision(&self, id: &VolumeId, spec: &VolumeSpec) -> Result<VolumeHandle> {
                Ok(VolumeHandle {
                    id: *id,
                    backend: format!("/plain/{id}"),
                    size_bytes: spec.size_bytes,
                    params: None,
                })
            }
            async fn deprovision(&self, _: &VolumeHandle) -> Result<()> {
                Ok(())
            }
            async fn describe(&self, h: &VolumeHandle) -> Result<VolumeState> {
                Ok(VolumeState {
                    size_bytes: h.size_bytes,
                })
            }
        }

        let plain = Plain;
        assert!(plain.snapshot_support().is_none());

        let handle = VolumeHandle {
            id: Uuid::nil(),
            backend: "/plain/x".into(),
            size_bytes: 1,
            params: None,
        };
        let spec = VolumeSpec {
            base_image: None,
            size_bytes: 1,
            driver: None,
            params: None,
        };
        for refusal in [
            plain.snapshot(&handle, &Uuid::nil()).await.err(),
            plain.drop_snapshot(&handle).await.err(),
            plain
                .provision_from(&Uuid::nil(), &handle, &spec)
                .await
                .err(),
        ] {
            let e = refusal.expect("a backend that cannot, refusing");
            assert!(
                matches!(e, StorageError::Unsupported(_)),
                "the variant is what the tier above branches on: {e:?}"
            );
        }

        // And the two consistencies round-trip as the strings the proto and
        // the catalogue speak, because a second spelling is how a parser
        // starts guessing.
        for c in [
            SnapshotConsistency::Atomic,
            SnapshotConsistency::NeedsQuiesce,
        ] {
            assert_eq!(SnapshotConsistency::parse(c.as_str()), Some(c));
        }
        assert_eq!(SnapshotConsistency::Atomic.as_str(), "atomic");
        assert_eq!(SnapshotConsistency::NeedsQuiesce.as_str(), "needs-quiesce");
        assert_eq!(SnapshotConsistency::parse("maybe"), None);
    }
}
