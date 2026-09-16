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
    /// Why a volume is what it is.
    ///
    /// One list out of two vocabularies, the shape `VmReason` explains. This
    /// tier's own seven are each a sentence the reconcilers already write:
    /// `Unplaced` is `storage_pending_reason`, `Following` is "following
    /// <vm> to <node>" and its cloud twin "moving to <cluster> with its vm",
    /// `Dispatched` is the claim written before `ProvisionVolume` goes out,
    /// `Undeliverable` is "provision could not be delivered", `SourceMissing`
    /// is "snapshot <s> does not exist here any more", `HeldBy` is the
    /// `Releasing` a DELETE leaves behind while a consumer still holds the
    /// bytes.
    ///
    /// The four after them are the NODE's (`proto::reasons::VOLUME`). The
    /// pair that earns the change is `DriverRefused` against `NotOnBackend`:
    /// a refused provision costs a requeue, a volume the backend has LOST
    /// costs somebody their data, and under the old `Reported` both were one
    /// word with the driver's prose beside it.
    VolumeReason [12] {
        /// Nobody recorded one — see `VmReason::Unrecorded`.
        #[default]
        Unrecorded => "Unrecorded",
        /// Nobody has been asked yet: the volume is written down, and either
        /// no pass has placed it or the placed node has not been told.
        ///
        /// Not `Unplaced`, which is the planner having LOOKED and found
        /// nowhere. Spelled as the image's, the pool's, the copy's and the
        /// router's are, so that "nobody has said anything yet" is one word
        /// across this crate.
        AwaitingNode => "AwaitingNode",
        /// No node that could provision it is a candidate: none runs the
        /// driver, none is up, or none has the room.
        Unplaced => "Unplaced",
        /// It is moving because its VM is: the disk follows the guest, and
        /// the phase says so rather than describing bytes that are being
        /// made from scratch.
        Following => "Following",
        /// A node has been ASKED — to make the bytes, or to unmake them. The
        /// second half is the release in flight: the `DeprovisionVolume` has
        /// gone out and the node has not answered `Gone` yet.
        Dispatched => "Dispatched",
        /// The command did not reach the node. This tier's own word, about a
        /// session rather than about bytes: nothing was reported at all, and
        /// the fix is on the network.
        Undeliverable => "Undeliverable",
        /// What the provision would have copied FROM is not there any more —
        /// the snapshot, or the pool.
        SourceMissing => "SourceMissing",
        /// Deleted while a consumer still holds it. The data is still there
        /// and goes when the last one lets go; the sentence names the holder.
        HeldBy => "HeldBy",
        // ------------------------------------------------------------------
        // The node's own words from here down: `proto::reasons::VOLUME`, off
        // `VolumeStateReport.reason`, written onto the object unchanged and
        // relayed to the cloud as they came.
        // ------------------------------------------------------------------

        /// `Provisioning`: the node has written its record and the driver has
        /// been asked, or is being asked right now.
        Working => "Working",
        /// `Failed`: the backend said no. The sentence is what it said.
        DriverRefused => "DriverRefused",
        /// `Failed`: the backend has no volume of that name any more, and it
        /// did when the node last wrote its record. Found by the node's
        /// `adopt` at start-up, and its own word because the operator fix is
        /// not a retry — this is somebody's data missing.
        NotOnBackend => "NotOnBackend",
        /// `Releasing`/gone: the node was told to deprovision and has. The
        /// tombstone a release is allowed to act on.
        Deprovisioned => "Deprovisioned",
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
    VolumePhase / VolumePhaseKind / VolumeReason / VolumePhaseWire / VolumeReported [5] {
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

/// Does the claim on this volume still hold?
///
/// **The whole of D4.** `attachedTo` is the CLAIM and `openOn` is the
/// OBSERVATION, and the claim falls only when both halves say it may: no `Vm`
/// object carries it any more (`claimantGone`, written by the pass that lists
/// the VMs) and no machine reports the bytes open.
///
/// It used to fall on the way OUT of a teardown — `release_volumes` cleared
/// it as the `DestroyInstance` was dispatched — and that is one command's
/// round trip too early. Between the dispatch and the node's `detach` there
/// was an object saying nobody held the disk while a VMM still had it open,
/// and that is exactly the window in which a DELETE takes somebody's data:
/// `Release::HeldBy` reads this field, finds nothing, and lets the
/// deprovision go.
///
/// A reschedule of the SAME VM keeps the claim, and it keeps it for free:
/// the name is the same name, so the pass that lists the VMs finds the object
/// and `claimantGone` stays false. That is the case a timeout-based answer
/// would have got wrong.
pub fn volume_claim_holds(status: &VolumeStatus) -> bool {
    match status.attached_to {
        // Nothing to drop, so nothing to decide. `true` rather than `false`
        // because the question is "may the claim stay", and a volume with no
        // claim is not one whose claim has fallen.
        None => true,
        Some(_) => !status.claimant_gone || !status.open_on.is_empty(),
    }
}

/// What a volume IS, out of the facts on it.
///
/// One rule for both tiers, and the first derivation in this file with a real
/// ORDER to it — three of them, and each one exists because two writers used
/// to reach different answers about the same volume:
///
/// 1. **A volume being released is `Releasing`, whatever anybody says about
///    the bytes.** The `deletionTimestamp` is the decision and the phase
///    follows it. Before this, three edges each stamped `Releasing` when they
///    set the timestamp (two REST handlers and the quota pass) and the node
///    report path carried a special case to avoid undoing them — an object
///    whose own status could contradict its own metadata if any one of the
///    four was missed.
/// 2. **Otherwise the last word, and `Ready` demands a machine.** A word with
///    no `node` is this tier's own conclusion: a dispatch, a missing source,
///    a command that did not arrive. None of those is evidence that bytes
///    exist. See `VolumeReported`.
/// 3. **Otherwise it is waiting for a node,** and the sentence says which
///    kind of waiting: nothing has placed it, or the node it was placed on
///    has not been told yet. That second state used to be `Pending` with
///    nothing beside it.
pub fn settle_volume(deleting: bool, status: &VolumeStatus) -> VolumePhase {
    let said = status.reported.as_ref();
    if deleting {
        // Who is holding it, if anybody. The pass that lists snapshots wrote
        // the sentence down (`status.holder`), because the derivation cannot
        // read another object.
        if let Some(holder) = &status.holder {
            return VolumePhase::new(
                VolumePhaseKind::Releasing,
                VolumeReason::HeldBy,
                Some(holder.clone()),
                UNSTAMPED,
            );
        }
        // The node answering `Gone` is the tombstone a release acts on, and
        // it is the one word from below that belongs on a `Releasing` phase.
        let gone = said.is_some_and(|r| r.reason == VolumeReason::Deprovisioned);
        return VolumePhase::new(
            VolumePhaseKind::Releasing,
            if gone {
                VolumeReason::Deprovisioned
            } else {
                VolumeReason::Dispatched
            },
            said.and_then(|r| r.message.clone())
                .or_else(|| Some("waiting for the node to say the bytes are gone".to_string())),
            UNSTAMPED,
        );
    }
    if let Some(phase) = said.and_then(VolumeReported::phase) {
        return phase;
    }
    VolumePhase::new(
        VolumePhaseKind::Pending,
        VolumeReason::AwaitingNode,
        Some(match &status.node {
            Some(node) => format!("{node} was chosen; the provision has not gone out yet"),
            None => "not placed yet".to_string(),
        }),
        UNSTAMPED,
    )
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
    /// The last word anybody established about the bytes — a node's on the
    /// status road, a cluster's one tier up, or this tier's own (a dispatch
    /// that went out, a source that is missing, a command that could not be
    /// delivered).
    ///
    /// The first of the facts `settle_volume` reads. An empty `node` on it is
    /// this tier's own conclusion and cannot make the volume `Ready`: only a
    /// machine that made the bytes may say they exist. See `VolumeReported`.
    ///
    /// `None` on a volume nobody has said anything about — a fresh one, and
    /// one whose node has just reported the bytes gone.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reported: Option<VolumeReported>,
    /// What still holds the bytes of a volume that is being released, as a
    /// sentence naming it.
    ///
    /// Written by the release pass, which is the only party that can know:
    /// the holder may be a VM (`attachedTo`, on this object) or a
    /// `VolumeSnapshot` (another object entirely, listed once per pass). The
    /// derivation may not read that second one — `settle` sees this object
    /// and nothing else — so the pass that lists them writes down the answer.
    ///
    /// `None` on every volume nothing holds, which is nearly all of them.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub holder: Option<String>,
    /// That no `Vm` object names this volume any more — the VM was deleted,
    /// or its spec stopped referring to it.
    ///
    /// The half of D4 that the derivation cannot see: `attachedTo` is a NAME,
    /// and whether an object of that name still exists is a question about
    /// another object. So the pass that lists the VMs writes the answer down,
    /// every pass, and `volume_claim_holds` reads it beside `openOn`.
    ///
    /// False on a volume nothing ever claimed, which is also the honest
    /// default: a claim is only ever dropped on evidence, and "nobody has
    /// looked" is not evidence.
    #[serde(default, skip_serializing_if = "is_false")]
    pub claimant_gone: bool,
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
    /// Returns whether anything changed, because the writer of this field is
    /// inside a store mutation that must not churn a revision per report.
    ///
    /// **One writer, since D4:** the volume half of a node's status report
    /// (`VolumeStateReport.open`). There used to be five — the dispatch in
    /// `hold_volumes`, the release, both ends of a live migration, and a pass
    /// that derived the set from the union of every VM's
    /// `attached_volumes` — and the last of them is where D-B2's shape came
    /// from: five writers of one set, each right about its own half and none
    /// of them able to see what the others knew.
    ///
    /// What replaced them is the node saying it directly, and saying it until
    /// the `detach` has actually run: `openOn` is now true exactly while some
    /// machine has the bytes open, which is the whole of what a delete has to
    /// wait for.
    pub fn open_here(&mut self, node: &str) -> bool {
        match self.open_on.binary_search_by(|n| n.as_str().cmp(node)) {
            Ok(_) => false,
            Err(at) => {
                self.open_on.insert(at, node.to_string());
                true
            }
        }
    }

    /// Record that `node` has let go. Idempotent for the same reason, and
    /// with the same one writer — see [`Self::open_here`].
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
    /// Why a snapshot is what it is.
    ///
    /// One list out of two vocabularies, the shape `VmReason` explains. This
    /// tier's five are in the snapshot reconciler: `AwaitingNode` is the
    /// moment between the request and the dispatch, `Dispatched` is the claim
    /// written before `TakeSnapshot` goes out, `Requeued` is the failed-copy
    /// kick, `SourceGone` is a volume or a copy that is not there any more,
    /// and `Undeliverable` is a dispatch that never reached a node. The
    /// node's three are `proto::reasons::SNAPSHOT`.
    VolumeSnapshotReason [9] {
        /// Nobody recorded one — see `VmReason::Unrecorded`.
        #[default]
        Unrecorded => "Unrecorded",
        /// Written down, and no node has been told yet. The word every
        /// snapshot wears for the moment between the request and the
        /// dispatch, and the reason `Pending` no longer has to mean
        /// "Unrecorded" on a fresh object.
        AwaitingNode => "AwaitingNode",
        /// A node has been told to take it.
        Dispatched => "Dispatched",
        /// A copy that failed is being tried again.
        Requeued => "Requeued",
        /// What the copy would be taken FROM is not there: the volume was
        /// deleted between the request and the dispatch, or the node no
        /// longer has the copy it once reported. Somebody has to ask again.
        SourceGone => "SourceGone",
        /// The dispatch never reached the node. This tier's own word, about a
        /// session rather than about bytes — `VolumeReason::Undeliverable`
        /// one field over, and for the same reason: a node that never
        /// accepted the command sends no report about it, so `Creating` would
        /// stand for ever.
        Undeliverable => "Undeliverable",

        // ------------------------------------------------------------------
        // The node's own words: `proto::reasons::SNAPSHOT`, off
        // `SnapshotStateReport.reason`.
        // ------------------------------------------------------------------

        /// `Creating`: the record is written and the driver has been asked.
        Working => "Working",
        /// `Failed`: the backend said no. The sentence is what it said.
        DriverRefused => "DriverRefused",
        /// Gone: the node was told to drop it and has — including for an id
        /// it never had, which is the same answer to the tier above.
        Dropped => "Dropped",
    }
}

phases! {
    /// How far a snapshot got.
    VolumeSnapshotPhase / VolumeSnapshotPhaseKind / VolumeSnapshotReason
        / VolumeSnapshotPhaseWire / VolumeSnapshotReported [4] {
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
    /// The last word anybody established about this copy — the one fact
    /// `settle_volume_snapshot` derives from.
    ///
    /// A node's word arrives on the status road; this tier's own conclusions
    /// (the dispatch that went out, the volume that is not there any more,
    /// the command that could not be delivered, the requeue) are written here
    /// too, with an empty `node`. That is not a blurring of the two: the
    /// empty `node` is what stops this tier from writing `Ready`, which only
    /// a machine holding the bytes may say. See `VolumeSnapshotReported`.
    ///
    /// `None` on a copy nobody has said anything about, which is every copy
    /// for the moment between the request and the dispatch.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reported: Option<VolumeSnapshotReported>,
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

/// What a copy IS, out of the last word anybody said about it.
///
/// One rule for both tiers, and the thinnest derivation in this file, because
/// a snapshot really is only ever "what the last party established": nothing
/// schedules it (it goes to the node its volume is on), nothing else holds it,
/// and there is no claim on it to fall.
///
/// What the one place buys is therefore not an ordering but three guarantees
/// that were spread over seven writers before:
///
/// * **`Ready` demands a machine.** A word with no `node` is this tier's own
///   conclusion, and this tier may not conclude that bytes exist — see
///   `VolumeSnapshotReported`. A dispatch that anticipated `Ready` would be
///   the F16 mistake one object over.
/// * **No phase without a reason.** A copy nobody has said anything about is
///   `Pending { AwaitingNode }` and not `Pending { Unrecorded }`, which is
///   what a fresh object read as before.
/// * **One `since`.** It moves with the word and not with the report, so
///   "Creating since" is not "last heard from".
pub fn settle_volume_snapshot(status: &VolumeSnapshotStatus) -> VolumeSnapshotPhase {
    match status
        .reported
        .as_ref()
        .and_then(VolumeSnapshotReported::phase)
    {
        Some(phase) => phase,
        None => VolumeSnapshotPhase::new(
            VolumeSnapshotPhaseKind::Pending,
            VolumeSnapshotReason::AwaitingNode,
            Some("no node has been told to take it yet".to_string()),
            UNSTAMPED,
        ),
    }
}

#[cfg(test)]
mod snapshot_tests {
    use super::*;

    fn at(secs: i64) -> DateTime<Utc> {
        DateTime::from_timestamp(1_800_000_000 + secs, 0).expect("an instant")
    }

    fn snapshot() -> VolumeSnapshot {
        new_volume_snapshot("nightly-1", VolumeSnapshotSpec::default())
    }

    /// The table: what was last said about the copy, and what the copy
    /// therefore IS.
    #[test]
    fn a_copy_is_the_last_word_anybody_said_about_it() {
        let mut fresh = snapshot();
        fresh.settle(at(0));
        assert_eq!(
            fresh.status.phase().kind(),
            VolumeSnapshotPhaseKind::Pending
        );
        assert_eq!(
            fresh.status.phase().reason(),
            Some(VolumeSnapshotReason::AwaitingNode),
            "a fresh copy says what it is waiting for instead of nothing"
        );

        let cases: &[(
            VolumeSnapshotReported,
            VolumeSnapshotPhaseKind,
            VolumeSnapshotReason,
        )] = &[
            (
                VolumeSnapshotReported::here(
                    VolumeSnapshotPhaseKind::Creating,
                    VolumeSnapshotReason::Dispatched,
                    None,
                    at(0),
                ),
                VolumeSnapshotPhaseKind::Creating,
                VolumeSnapshotReason::Dispatched,
            ),
            (
                VolumeSnapshotReported::by(
                    "manacor",
                    VolumeSnapshotPhaseKind::Failed,
                    VolumeSnapshotReason::DriverRefused,
                    Some("no room in the thin pool".into()),
                    at(0),
                ),
                VolumeSnapshotPhaseKind::Failed,
                VolumeSnapshotReason::DriverRefused,
            ),
            (
                VolumeSnapshotReported::here(
                    VolumeSnapshotPhaseKind::Failed,
                    VolumeSnapshotReason::Undeliverable,
                    Some("no session".into()),
                    at(0),
                ),
                VolumeSnapshotPhaseKind::Failed,
                VolumeSnapshotReason::Undeliverable,
            ),
            (
                VolumeSnapshotReported::here(
                    VolumeSnapshotPhaseKind::Pending,
                    VolumeSnapshotReason::Requeued,
                    None,
                    at(0),
                ),
                VolumeSnapshotPhaseKind::Pending,
                VolumeSnapshotReason::Requeued,
            ),
        ];
        for (word, kind, reason) in cases {
            let mut copy = snapshot();
            copy.status.reported = Some(word.clone());
            copy.settle(at(0));
            assert_eq!(copy.status.phase().kind(), *kind, "{word:?}");
            assert_eq!(
                copy.status.phase().reason().unwrap_or_default(),
                *reason,
                "{word:?}"
            );
        }
    }

    /// `Ready` demands a machine. F16's rule, one object over and enforced by
    /// the derivation rather than by every writer remembering it: a word with
    /// no `node` is this tier's own conclusion, and this tier cannot have
    /// seen the bytes.
    #[test]
    fn this_tier_cannot_conclude_that_a_copy_exists() {
        let mut invented = snapshot();
        invented.status.reported = Some(VolumeSnapshotReported::here(
            VolumeSnapshotPhaseKind::Ready,
            VolumeSnapshotReason::Unrecorded,
            None,
            at(0),
        ));
        invented.settle(at(0));
        assert_eq!(
            invented.status.phase().kind(),
            VolumeSnapshotPhaseKind::Pending,
            "a resting word nobody with the evidence said is not a word"
        );
        assert_eq!(
            invented.status.phase().reason(),
            Some(VolumeSnapshotReason::AwaitingNode)
        );

        let mut seen = snapshot();
        seen.status.reported = Some(VolumeSnapshotReported::by(
            "manacor",
            VolumeSnapshotPhaseKind::Ready,
            VolumeSnapshotReason::Unrecorded,
            None,
            at(0),
        ));
        seen.settle(at(0));
        assert_eq!(seen.status.phase().kind(), VolumeSnapshotPhaseKind::Ready);
    }

    /// Two reports of the same thing are one word: neither the stamp nor the
    /// instant the word was established moves. A field that advanced per
    /// report would make every ten-second heartbeat an etcd revision (D-C7).
    #[test]
    fn a_report_that_says_the_same_thing_moves_neither_stamp() {
        let said = |at| {
            VolumeSnapshotReported::by(
                "manacor",
                VolumeSnapshotPhaseKind::Ready,
                VolumeSnapshotReason::Unrecorded,
                None,
                at,
            )
        };
        let mut copy = snapshot();
        copy.status.reported = Some(said(at(0)));
        copy.settle(at(0));
        assert_eq!(copy.status.phase().since(), at(0));

        assert!(
            said(at(600)).same_word(&said(at(0))),
            "the instant is not part of the word"
        );
        copy.settle(at(600));
        assert_eq!(copy.status.phase().since(), at(0));
    }
}

#[cfg(test)]
mod volume_tests {
    use super::*;

    fn at(secs: i64) -> DateTime<Utc> {
        DateTime::from_timestamp(1_800_000_000 + secs, 0).expect("an instant")
    }

    fn volume() -> Volume {
        new_volume(
            "data-1",
            VolumeSpec {
                pool: "fast".to_string(),
                size_gib: 10,
                ..Default::default()
            },
        )
    }

    /// The table: the facts on a volume, and the phase they add up to.
    ///
    /// One row per rule of `settle_volume`, in the order the rules run, and
    /// the order is what the table is FOR: a volume being released is
    /// `Releasing` whatever the bytes are doing, and that used to be four
    /// writers agreeing.
    #[test]
    fn what_is_known_about_a_volume_is_what_the_volume_is() {
        // Nothing at all.
        let mut fresh = volume();
        fresh.settle(at(0));
        assert_eq!(fresh.status.phase().kind(), VolumePhaseKind::Pending);
        assert_eq!(
            fresh.status.phase().reason(),
            Some(VolumeReason::AwaitingNode)
        );
        assert_eq!(fresh.status.phase().message(), Some("not placed yet"));

        // Placed, not asked. This state used to be `Pending` with nothing
        // beside it, which is what an operator saw for as long as a pool had
        // no node to serve it.
        let mut placed = volume();
        placed.status.node = Some("agent-1a".to_string());
        placed.settle(at(0));
        assert_eq!(
            placed.status.phase().message(),
            Some("agent-1a was chosen; the provision has not gone out yet")
        );

        // A node's word.
        let mut made = volume();
        made.status.reported = Some(VolumeReported::by(
            "agent-1a",
            VolumePhaseKind::Ready,
            VolumeReason::Unrecorded,
            None,
            at(0),
        ));
        made.settle(at(0));
        assert_eq!(made.status.phase().kind(), VolumePhaseKind::Ready);

        // The backend lost the bytes — its own word, and the pair that
        // earns the reason field: a refused provision costs a requeue, this
        // costs somebody their data.
        let mut lost = volume();
        lost.status.reported = Some(VolumeReported::by(
            "agent-1a",
            VolumePhaseKind::Failed,
            VolumeReason::NotOnBackend,
            Some("the backend has no volume data-1".into()),
            at(0),
        ));
        lost.settle(at(0));
        assert_eq!(lost.status.phase().kind(), VolumePhaseKind::Failed);
        assert_eq!(
            lost.status.phase().reason(),
            Some(VolumeReason::NotOnBackend)
        );
    }

    /// A volume being released is `Releasing`, whatever a node says about the
    /// bytes.
    ///
    /// The rule that used to live in four places: two REST delete handlers
    /// and the quota pass each stamped the word when they set the timestamp,
    /// and the node-report path carried a special case so as not to undo
    /// them. Any one of the four missed left an object whose own status
    /// contradicted its own metadata.
    #[test]
    fn a_volume_being_released_says_so_whatever_the_bytes_are_doing() {
        let mut deleting = volume();
        deleting.status.reported = Some(VolumeReported::by(
            "agent-1a",
            VolumePhaseKind::Ready,
            VolumeReason::Unrecorded,
            None,
            at(0),
        ));
        deleting.settle(at(0));
        assert_eq!(deleting.status.phase().kind(), VolumePhaseKind::Ready);

        // The timestamp is the whole of the decision.
        deleting.metadata.deletion_timestamp = Some(at(10));
        deleting.settle(at(10));
        assert_eq!(deleting.status.phase().kind(), VolumePhaseKind::Releasing);
        assert_eq!(
            deleting.status.phase().reason(),
            Some(VolumeReason::Dispatched),
            "the deprovision is in flight"
        );

        // Somebody is holding it: the sentence the release pass wrote down,
        // because it is the only party that can list the snapshots.
        deleting.status.holder = Some("held by vm web-1".to_string());
        deleting.settle(at(20));
        assert_eq!(deleting.status.phase().reason(), Some(VolumeReason::HeldBy));
        assert_eq!(deleting.status.phase().message(), Some("held by vm web-1"));

        // The node answered `Gone`: the tombstone a release acts on.
        deleting.status.holder = None;
        deleting.status.reported = Some(VolumeReported::by(
            "agent-1a",
            VolumePhaseKind::Pending,
            VolumeReason::Deprovisioned,
            Some("agent-1a no longer has the bytes".into()),
            at(30),
        ));
        deleting.settle(at(30));
        assert_eq!(
            deleting.status.phase().reason(),
            Some(VolumeReason::Deprovisioned)
        );
        assert_eq!(
            deleting.status.phase().since(),
            at(10),
            "still Releasing, so the stamp has not moved since it became so"
        );
    }

    /// `Ready` demands a machine. A dispatch, a missing source and a command
    /// that never arrived are all this tier's own conclusions, and none of
    /// them is evidence that bytes exist.
    #[test]
    fn this_tier_cannot_conclude_that_the_bytes_exist() {
        let mut invented = volume();
        invented.status.reported = Some(VolumeReported::here(
            VolumePhaseKind::Ready,
            VolumeReason::Unrecorded,
            None,
            at(0),
        ));
        invented.settle(at(0));
        assert_eq!(invented.status.phase().kind(), VolumePhaseKind::Pending);
        assert_eq!(
            invented.status.phase().reason(),
            Some(VolumeReason::AwaitingNode)
        );
    }
}

#[cfg(test)]
mod claim_tests {
    use super::*;

    fn at(secs: i64) -> DateTime<Utc> {
        DateTime::from_timestamp(1_800_000_000 + secs, 0).expect("an instant")
    }

    fn attached() -> Volume {
        let mut v = new_volume(
            "data-1",
            VolumeSpec {
                pool: "fast".to_string(),
                size_gib: 10,
                ..Default::default()
            },
        );
        v.status.node = Some("agent-1a".to_string());
        v.status.attached_to = Some("web-1".to_string());
        v.status.open_on = vec!["agent-1a".to_string()];
        v.status.reported = Some(VolumeReported::by(
            "agent-1a",
            VolumePhaseKind::Ready,
            VolumeReason::Unrecorded,
            None,
            at(0),
        ));
        v
    }

    /// **D4.** The claim falls when the last holder has gone AND no machine
    /// reports the bytes open — not when a `DestroyInstance` is dispatched.
    ///
    /// The window between those two is one command's round trip, and in it
    /// the object said nobody held a disk a VMM still had open. That is
    /// exactly where a DELETE takes somebody's data: `Release::HeldBy` reads
    /// `attachedTo`, finds nothing, and lets the deprovision go.
    #[test]
    fn a_claim_falls_only_when_the_bytes_are_nobodys() {
        // The ordinary state: a guest has it.
        let mut held = attached();
        held.settle(at(0));
        assert_eq!(held.status.attached_to.as_deref(), Some("web-1"));

        // The destroy is quittanced and the VM object is going. The node
        // still reports the disk open, because the `detach` has not run.
        held.status.claimant_gone = true;
        held.settle(at(10));
        assert_eq!(
            held.status.attached_to.as_deref(),
            Some("web-1"),
            "the VMM still has it open; the claim is what stops a delete taking the data"
        );
        assert!(!volume_claim_holds(&VolumeStatus {
            claimant_gone: true,
            open_on: Vec::new(),
            ..held.status.clone()
        }));

        // The node reports the disk closed: now it is nobody's.
        held.status.open_on.clear();
        held.settle(at(20));
        assert_eq!(held.status.attached_to, None, "and now the claim falls");
        assert!(
            !held.status.claimant_gone,
            "the fact goes with the claim it was about"
        );
    }

    /// A reschedule of the SAME VM keeps the claim, and keeps it for free:
    /// the name is the same name, so the pass that lists the VMs finds the
    /// object and writes `claimantGone = false` again.
    ///
    /// This is the case a timeout would have got wrong — the disk is
    /// re-opened on another machine of the same pool, and a claim that had
    /// expired in between would have let a second guest take it.
    #[test]
    fn a_reschedule_of_the_same_vm_keeps_its_disk() {
        let mut moving = attached();
        // The old node lets go and the object is still there.
        moving.status.open_on.clear();
        moving.status.claimant_gone = false;
        moving.settle(at(10));
        assert_eq!(moving.status.attached_to.as_deref(), Some("web-1"));

        // And the new node opens it.
        moving.status.open_on = vec!["agent-1b".to_string()];
        moving.settle(at(20));
        assert_eq!(moving.status.attached_to.as_deref(), Some("web-1"));
    }

    /// A volume nobody ever claimed is not a volume whose claim has fallen.
    #[test]
    fn nothing_is_dropped_from_a_volume_with_no_claim() {
        let mut free = attached();
        free.status.attached_to = None;
        free.status.open_on.clear();
        assert!(
            volume_claim_holds(&free.status),
            "there is nothing to drop, so there is nothing to decide"
        );
        free.settle(at(0));
        assert_eq!(free.status.attached_to, None);
    }
}
