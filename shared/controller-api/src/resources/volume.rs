// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! The `Volume` and `VolumeSnapshot` kinds: a disk with a life
//! of its own, and a point in time of one. Moved out of
//! `resources.rs` unchanged.

use super::*;

/// What a volume IS, from the guest's side. Two products, not one setting.
///
/// A block device and a mounted directory are different things to ask for and
/// different things to attach: "attach" means `Path`/`VhostUserBlk` for the
/// first and `FsShare` for the second, and the guest either boots from it or
/// mounts it by tag. Naming it on the object is what stops "attach this
/// volume" from being a sentence whose meaning depends on which backend
/// happened to serve it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub enum VolumeMode {
    /// A block device. The default, because it is what a disk has always
    /// been here and what a VM boots from.
    #[default]
    Block,
    /// A directory the guest mounts. `nfs` in share mode today.
    Filesystem,
}

impl VolumeMode {
    pub const ALL: [VolumeMode; 2] = [VolumeMode::Block, VolumeMode::Filesystem];

    pub fn as_str(self) -> &'static str {
        match self {
            VolumeMode::Block => "Block",
            VolumeMode::Filesystem => "Filesystem",
        }
    }
}

/// How many consumers a volume admits at once.
///
/// One, and it is written down rather than left to be discovered. Multi-attach
/// needs reference counting at detach — without it the one VM that stops tears
/// the device out from under the other — and a field with one variant is what
/// says the second one was considered and refused, rather than forgotten.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub enum AccessMode {
    /// Read-write by one consumer at a time.
    #[default]
    ReadWriteOnce,
}

reasons! {
    /// Why a volume is what it is. Eight, and each one is a sentence this
    /// file's reconciler already writes: `Unplaced` is
    /// `storage_pending_reason`, `Following` is "following <vm> to <node>"
    /// and its cloud twin "moving to <cluster> with its vm", `Dispatched` is
    /// the claim written before `ProvisionVolume` goes out, `Reported` is the
    /// node's word arriving, `Undeliverable` is "provision could not be
    /// delivered", `SourceMissing` is "snapshot <s> does not exist here any
    /// more", and `HeldBy` is the `Releasing` a DELETE leaves behind while a
    /// consumer still holds the bytes.
    VolumeReason [8] {
        /// Nobody recorded one — see `VmReason::Unrecorded`.
        #[default]
        Unrecorded => "Unrecorded",
        /// No node that could provision it is a candidate: none runs the
        /// driver, none is up, or none has the room.
        Unplaced => "Unplaced",
        /// It is moving because its VM is: the disk follows the guest, and
        /// the phase says so rather than describing bytes that are being
        /// made from scratch.
        Following => "Following",
        /// A node has been asked to make it.
        Dispatched => "Dispatched",
        /// The node's own word, verbatim in the message.
        Reported => "Reported",
        /// The command did not reach the node. Its own reason and not
        /// `Reported`, because nothing was reported: the sentence is this
        /// tier's, about a session, and the fix is on the network.
        Undeliverable => "Undeliverable",
        /// What the provision would have copied FROM is not there any more —
        /// the snapshot, or the pool.
        SourceMissing => "SourceMissing",
        /// Deleted while a consumer still holds it. The data is still there
        /// and goes when the last one lets go; the sentence names the holder.
        HeldBy => "HeldBy",
    }
}

phases! {
    /// Where a volume is in its own life. Its OWN phase, and that is the whole
    /// point of the object: a volume is Ready with no VM anywhere near it, and a
    /// VM being torn down does not move it.
    ///
    /// Spelled like `VmPhaseKind` and not camelCase, which is what it was until
    /// the lab pointed out that a client then needs two comparisons for the same
    /// question. Free to change today because no volume object has ever been
    /// stored outside a test; it would not be free tomorrow.
    VolumePhase / VolumePhaseKind / VolumeReason / VolumePhaseWire [5] {
        /// Reserved, not yet placed on a node that can provision it.
        Pending { reason, message, since } => "Pending",
        /// A node was chosen and is making it.
        Provisioning { reason, message, since } => "Provisioning",
        /// The data exists. Attached or not — that is `status.attachedTo`.
        Ready { message, since } => "Ready",
        /// Deleted while a consumer still held it. The data is still there and
        /// goes when the last one lets go. See the finalizer on `new_volume`.
        Releasing { reason, message, since } => "Releasing",
        /// The backend refused, and said why in the message.
        Failed { reason, message, since } => "Failed",
    }
}

impl VolumePhaseKind {
    /// The one end a volume has: its data exists. `Failed` rides the requeue
    /// curve and `Releasing` is waiting for a consumer to let go, so neither
    /// is an end — a `Releasing` that stands for a quarter of an hour is
    /// exactly the case D4 is about, and it has to be able to say so.
    pub fn is_terminal(self) -> bool {
        matches!(self, VolumePhaseKind::Ready)
    }
}

/// A volume a tenant holds: a size, a pool, a kind, and a life of its own.
///
/// The object the whole brief is about. Everything a `VmSpec`'s embedded
/// volume entry says is about a disk that is made for one VM and unmade with
/// it; this says the same things about something that exists on its own, and
/// the difference is entirely in who deletes it.
///
/// # Persistent, and why that needs no field
///
/// A `Volume` object is PERSISTENT by being one. The ephemeral case is the
/// inline entry in `spec.vm.volumes[]` — made with the VM, gone with it — and
/// the two are told apart by where the disk is written down rather than by a
/// flag on either. There is deliberately no `ephemeral: true` here: it would
/// be a second way of saying what the shape already says, and a second way of
/// saying something is a way for the two to disagree. Somebody who wants
/// scratch space writes it inline and gets it.
#[derive(Clone, Debug, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VolumeSpec {
    /// Whose it is. Never empty on a STORED object, defaulted on the way in
    /// for the same reason `FloatingIpSpec.tenant` is: the request a member
    /// sends names no tenant, and the server fills in their own. A required
    /// field would make the self-service path a deserialization error.
    #[serde(default)]
    pub tenant: String,
    /// Which pool it came out of. Server-set at create (the named pool, or
    /// the default one) and immutable afterwards — a volume that could be
    /// re-pointed at another pool would be a volume whose data is in a place
    /// its object does not name.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub pool: String,
    /// How big, in GiB. The unit an operator writes on a whiteboard, and the
    /// same unit the pool's quota is in so that neither has to convert.
    #[serde(default)]
    pub size_gib: u64,
    #[serde(default, skip_serializing_if = "is_block_mode")]
    pub mode: VolumeMode,
    #[serde(default)]
    pub access_mode: AccessMode,
    /// The base image to clone in, by catalogue name. `None` = an empty
    /// volume, which is what a data disk is.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base_image: Option<String>,
    /// A `VolumeSnapshot` in the same tenant to start from, by name.
    ///
    /// The third and last thing a new volume can start from — empty, a
    /// catalogue image, or somebody's own point in time — and it EXCLUDES
    /// `baseImage`: two starting points is a spec whose author believes one
    /// of them, and a silent winner would hand somebody a disk they did not
    /// ask for. 422 when both are set.
    ///
    /// Immutable like everything else on this spec: where a volume came from
    /// is decided once, and re-pointing it afterwards would be a field whose
    /// value the data has stopped matching.
    ///
    /// Absent on every volume ever written before snapshots existed, which is
    /// what makes the field additive.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from_snapshot: Option<String>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub description: String,
}

fn is_block_mode(mode: &VolumeMode) -> bool {
    matches!(mode, VolumeMode::Block)
}

/// What the control plane observed about a volume.
#[derive(Clone, Debug, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct VolumeStatus {
    /// The phase, with the reason it is that phase and since when.
    ///
    /// Flat on the wire — `phase`, `reason`, `message`, `since` as siblings
    /// right here — so every client that reads `status.phase` as a string
    /// goes on reading it as a string. See `resources::phase`.
    #[serde(flatten)]
    pub(super) phase: VolumePhase,
    /// The name the BACKEND knows this volume by — `/tmp/vols/<uid>.raw`,
    /// `/dev/vg0/vm-<uid>`, an export directory.
    ///
    /// EVIDENCE FROM THE NODE, and empty until the node has said it. The same
    /// rule every other field of a status obeys, and it took a defect to get
    /// it here: this used to be filled in at create with `vol-<uid>`, a name
    /// no backend in this tree ever gives a volume (`filesystem` says
    /// `<uid>.raw`, `lvm-thin` says `vm-<uid>`), and it was then replaced by
    /// the real one on the first report. Between those two moments the object
    /// named a path that did not exist anywhere, and an operator who looked
    /// in that window went looking for the wrong file.
    ///
    /// The identity that must not be allocated is `metadata.uid`, and it is
    /// not: every backend derives its own name from it, so a provision whose
    /// handle is lost finds its volume again rather than making a second one.
    /// That rule never needed a second copy of the answer up here.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub backend: String,
    /// The node that provisioned it. `None` while Pending.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node: Option<String>,
    /// Every node that has this volume OPEN right now. Normally one, empty
    /// while nobody holds it, and TWO for the length of a live migration.
    ///
    /// `status.node` keeps the meaning it has always had — the machine that
    /// made the bytes, the volume's home — and this is the other half that
    /// was hiding inside it: who has it attached. Until a VM could move while
    /// it ran, those were one fact. A live migration is the case that
    /// separates them, because the destination has to open the disk BEFORE
    /// the source lets go: there is no instant in a live migration at which
    /// exactly one machine has the volume open, so a field that can name only
    /// one machine cannot describe one.
    ///
    /// The one exception to `AccessMode`, written down rather than implied: a
    /// second entry is legitimate only while a `VmMigration` for the VM
    /// holding this volume is `Preparing` or `Running`
    /// (`second_open_is_a_migration`). Outside that window a second open is a
    /// conflict exactly as it was before this field existed — one consumer,
    /// one machine.
    ///
    /// Sorted and without duplicates, so that two writers adding the same
    /// node produce one entry and a reader can compare two of these for
    /// equality. Empty on every volume written before the field, which reads
    /// as "no node has said yet" rather than "nobody has it".
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub open_on: Vec<String>,
    /// Which CLUSTER's record holds this volume — at the cloud tier only.
    ///
    /// Empty at the cluster, always, exactly as `Vm.status.clusterName` is:
    /// a cluster is what that process IS.
    ///
    /// It exists because a pool may name more than one cluster, and then
    /// "which cluster is this volume's" stops being derivable from the pool.
    /// Written where the cloud DISPATCHES — the same statement
    /// `Vm.status.clusterName` makes, and for the same reason: it is the one
    /// thing this tier knows rather than guesses, because it is what it sent.
    /// It moves when a stopped VM's binding moves and the disk follows.
    ///
    /// `None` on every volume written before the field, which reads as "its
    /// pool's home" and is what such a volume's cluster has always been.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cluster: Option<String>,
    /// The VM holding it, by name, inside the same tenant. `None` = nobody
    /// is, which is a perfectly good state and the one the whole object
    /// exists to make possible.
    ///
    /// Singular because `AccessMode` has one variant. The day it has two,
    /// this becomes a list AND detach starts counting — both together or
    /// neither.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attached_to: Option<String>,
    /// How big the volume actually IS, in GiB, as the node measured it.
    ///
    /// The evidence half of `spec.sizeGib`, which is the intent. Two fields
    /// and not one because a resize is not instantaneous and can half-happen:
    /// the backend grows and the guest is told, in that order and on
    /// possibly two different machines, and between the two the spec says 2
    /// and this says 1 — which is exactly what an operator needs to see.
    ///
    /// Rounded UP from the node's byte count, because a number beside
    /// `sizeGib` has to be comparable to it and a 1.5 GiB LV reported as 1
    /// would read as smaller than the disk it is.
    ///
    /// Zero on every volume written before this field existed and on every
    /// one no node has reported yet, which reads as "not measured".
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub size_gib: u64,
    /// The last `metadata.generation` this object's controller ACTED on —
    /// the same field, with the same meaning, that `Vm`, `FloatingIp` and
    /// `RoutedSubnet` carry.
    ///
    /// It is here because a client could not tell "the child does not report
    /// it" from "the child is behind": a console that showed
    /// `generation 1, observed 0` on every volume in the estate was showing
    /// the first and meaning the second. Set where the tier dispatches — the
    /// cloud when the cluster acked the command it sent, the cluster when a
    /// node did — so what it says is "the change has been picked up", which
    /// is the honest thing a control plane knows about itself.
    ///
    /// `0` on every volume written before this field existed, whose
    /// `generation` is `0` too: the pair reads "in sync", which is true.
    #[serde(default)]
    pub observed_generation: u64,
    /// When the node's word about this volume was observed.
    ///
    /// The floor `status_is_current` compares a report against, and it earns
    /// its place for the same reason the VM's does: a report built before the
    /// last command landed describes the volume from BEFORE it. Read as
    /// current, a stale one would take a `Gone` that answered an older
    /// deprovision and delete an object whose bytes were just re-made.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_at: Option<DateTime<Utc>>,
    /// How many times a Failed provision has been kicked, and when last —
    /// the same two fields `VmStatus` keeps and read by the same
    /// `RequeuePolicy`. A backend that refused once may well succeed on the
    /// next pass (a thin pool that was full, an export that was remounting),
    /// and a volume that stayed Failed for ever would be a VM that stays
    /// Pending for ever behind it.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub requeue_attempts: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_requeue: Option<DateTime<Utc>>,
}

impl VolumeStatus {
    /// Record that `node` has the volume open. Idempotent, and it keeps the
    /// list sorted so that "the same two nodes" is one value and not two.
    ///
    /// Returns whether anything changed, because every writer of this field
    /// is inside a store mutation that must not churn a revision per report.
    pub fn open_here(&mut self, node: &str) -> bool {
        match self.open_on.binary_search_by(|n| n.as_str().cmp(node)) {
            Ok(_) => false,
            Err(at) => {
                self.open_on.insert(at, node.to_string());
                true
            }
        }
    }

    /// Record that `node` has let go. Idempotent for the same reason.
    pub fn closed_here(&mut self, node: &str) -> bool {
        match self.open_on.binary_search_by(|n| n.as_str().cmp(node)) {
            Ok(at) => {
                self.open_on.remove(at);
                true
            }
            Err(_) => false,
        }
    }

    /// A node that has this volume open and is not the one asking. `None`
    /// when nobody else has it, which is the ordinary case.
    ///
    /// The question an attach asks before it grows the list, and the reason
    /// it returns a NAME rather than a bool: whoever refuses has to say which
    /// machine is in the way.
    pub fn open_elsewhere(&self, node: &str) -> Option<&str> {
        self.open_on
            .iter()
            .map(String::as_str)
            .find(|open| *open != node)
    }
}

/// May a volume be open on a SECOND node right now?
///
/// The single exception to `AccessMode`, in one function so that the rule can
/// be tested without a store and cannot be spelled two ways in two files.
/// Yes exactly while a live migration of the VM holding it is in flight —
/// `Preparing` (the destination is opening the disk) or `Running` (the stream
/// is in the air and the source still owns the guest). `Pending` is not
/// enough: nothing has been made ready yet, so a second open at that point is
/// a second open. `Succeeded` and `Failed` are not enough either: one side
/// has let go by then, and a list that still names two is a leak rather than
/// a migration.
///
/// `None` — no migration at all — is the ordinary answer, and it is no.
pub fn second_open_is_a_migration(phase: Option<VmMigrationPhaseKind>) -> bool {
    matches!(
        phase,
        Some(VmMigrationPhaseKind::Preparing) | Some(VmMigrationPhaseKind::Running)
    )
}

/// A volume, with the finalizer that makes "detach before delete" the one
/// path out.
///
/// The same shape `new_vm` has and for a sharper reason. A DELETE on a volume
/// somebody is holding must not take the data: it marks the object
/// `Releasing`, the consumer lets go in its own time, and the deprovision
/// happens then. At the end of getting this wrong for a floating address is a
/// tenant that cannot be reached; at the end of getting it wrong here is data
/// that is gone.
pub fn new_volume(name: &str, spec: VolumeSpec) -> Volume {
    let mut volume = Volume::declare(name, spec);
    volume
        .metadata
        .finalizers
        .push(VOLUME_RELEASE_FINALIZER.to_string());
    volume
}

/// The finalizer `new_volume` puts on, spelled once.
pub const VOLUME_RELEASE_FINALIZER: &str = "meister.io/release";

pub type Volume = Object<VolumeSpec, VolumeStatus>;

/// A point in time of a volume — and an object that outlives it.
///
/// The asymmetry is the design. A snapshot names the volume it was taken of
/// and keeps meaning something after that volume is deleted, because what it
/// holds is a copy and not a reference. So a `Volume` DELETE with a snapshot
/// standing does not fail — it becomes `Releasing` with "held by snapshot
/// <s>", the same `HeldBy` sentence a VM produces, and the data goes when the
/// last snapshot of it does. Two reasons a volume can be held, one shape.
///
/// (`lvm-thin` would hold its origin LV itself — a thin snapshot shares the
/// origin's blocks — so this rule is what makes `filesystem` and `lvm-thin`
/// behave the same from an operator's chair rather than each behaving like
/// its backend.)
///
/// Crash-consistent, and that is written here rather than in a release note:
/// what a snapshot holds is what the disk held at that instant, which is what
/// the guest would have found after losing power. There is no guest agent in
/// this stack and no `fsfreeze` — exactly EBS without one. A database that
/// needs more than that flushes before asking.
#[derive(Clone, Debug, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VolumeSnapshotSpec {
    /// Whose it is. Filled in by the server from the caller, like every other
    /// tenant field here.
    #[serde(default)]
    pub tenant: String,
    /// The `Volume` this is a copy of, by name, in the same tenant.
    ///
    /// Immutable, and it is the one field that could not be anything else: a
    /// snapshot re-pointed at another volume would be a name over bytes that
    /// came from somewhere else.
    #[serde(default)]
    pub volume: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub description: String,
}

reasons! {
    /// Why a snapshot is what it is. Five, and all five are already in the
    /// snapshot reconciler: `Dispatched` is the claim written before
    /// `TakeSnapshot` goes out, `Reported` is the node's own sentence on the
    /// status road, `Requeued` is the failed-copy kick, and `SourceGone` is
    /// the ingest path that finds the node no longer has the copy at all.
    VolumeSnapshotReason [5] {
        /// Nobody recorded one — see `VmReason::Unrecorded`.
        #[default]
        Unrecorded => "Unrecorded",
        /// A node has been told to take it.
        Dispatched => "Dispatched",
        /// The node's own word, verbatim in the message.
        Reported => "Reported",
        /// A copy that failed is being tried again.
        Requeued => "Requeued",
        /// The node no longer has the copy, so it will be taken again.
        SourceGone => "SourceGone",
    }
}

phases! {
    /// How far a snapshot got.
    VolumeSnapshotPhase / VolumeSnapshotPhaseKind / VolumeSnapshotReason
        / VolumeSnapshotPhaseWire [4] {
        /// Written down; the node has not been told yet.
        Pending { reason, message, since } => "Pending",
        /// A node was told and is taking it.
        Creating { reason, message, since } => "Creating",
        /// The copy exists.
        Ready { message, since } => "Ready",
        /// The backend refused, and said why in the message.
        Failed { reason, message, since } => "Failed",
    }
}

impl VolumeSnapshotPhaseKind {
    /// The copy exists, and nothing takes that back. `Failed` is a wait: the
    /// same requeue curve every other backend refusal here rides.
    pub fn is_terminal(self) -> bool {
        matches!(self, VolumeSnapshotPhaseKind::Ready)
    }
}

/// What the control plane observed about a snapshot.
#[derive(Clone, Debug, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct VolumeSnapshotStatus {
    /// The phase, with the reason it is that phase and since when.
    ///
    /// Flat on the wire — `phase`, `reason`, `message`, `since` as siblings
    /// right here — so every client that reads `status.phase` as a string
    /// goes on reading it as a string. See `resources::phase`.
    #[serde(flatten)]
    pub(super) phase: VolumeSnapshotPhase,
    /// The node that took it — the volume's provisioning node, which under a
    /// `shared` pool need not be the node the VM runs on. Copied onto the
    /// snapshot at dispatch so that a later `DropSnapshot` goes to the machine
    /// that has the bytes, even if the volume has since gone.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node: Option<String>,
    /// What the BACKEND calls it. Evidence, like `VolumeStatus::backend`, and
    /// empty until the node has said it.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub backend: String,
    /// How big the copy is, in GiB, as the node measured it. Zero until it
    /// has said.
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub size_gib: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_at: Option<DateTime<Utc>>,
    /// The same two fields every other requeueable status keeps, read by the
    /// same `RequeuePolicy`: a copy that failed because the pool was momentarily
    /// full is worth another try, and one that stayed Failed for ever would be
    /// a snapshot nobody can make and nobody is told about.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub requeue_attempts: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_requeue: Option<DateTime<Utc>>,
}

fn is_zero_u64(n: &u64) -> bool {
    *n == 0
}

pub type VolumeSnapshot = Object<VolumeSnapshotSpec, VolumeSnapshotStatus>;

/// A snapshot, with the finalizer that keeps the bytes on the node until this
/// object says they may go.
///
/// The same rule `new_volume` writes down, one object over: a DELETE marks
/// the object, the reconciler tells the node, and only the node's word that
/// the copy is gone takes the object away. Without it a `volumesnapshot rm`
/// would remove the row and leave an LV nobody can name.
pub fn new_volume_snapshot(name: &str, spec: VolumeSnapshotSpec) -> VolumeSnapshot {
    let mut snapshot = VolumeSnapshot::declare(name, spec);
    snapshot
        .metadata
        .finalizers
        .push(VOLUME_RELEASE_FINALIZER.to_string());
    snapshot
}
