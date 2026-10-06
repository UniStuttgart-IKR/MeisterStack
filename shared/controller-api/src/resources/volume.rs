// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Persistent volumes, attachment claims and point-in-time snapshots.

use super::*;

/// Guest-visible volume kind: a block disk or a shared filesystem directory.
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

/// Maximum concurrent consumers permitted by the volume access mode.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub enum AccessMode {
    /// Read-write by one consumer at a time.
    #[default]
    ReadWriteOnce,
}

reasons! {
    /// Volume reason categories combine placement, dispatch, source, and release decisions with
    /// node observations. Preserve DriverRefused separately from NotOnBackend: a rejected
    /// provision and lost backend data require different recovery.
    VolumeReason [12] {
        /// Nobody recorded one — see `VmReason::Unrecorded`.
        #[default]
        Unrecorded => "Unrecorded",
        /// No provision has been dispatched yet, or placement is waiting for a usable
        /// destination.
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
    /// Volume lifecycle independent of a consuming VM. Ready requires evidence that the bytes
    /// exist; release waits for consumers and backend cleanup.
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

/// Retain the attachment claim until the claimant VM is gone and no node
/// reports the bytes open. Dispatching destroy is insufficient: detach may
/// still be in progress. Rescheduling the same VM preserves its claim.
pub fn volume_claim_holds(status: &VolumeStatus) -> bool {
    match status.attached_to {
        // Nothing to drop, so nothing to decide. `true` rather than `false`
        // because the question is "may the claim stay", and a volume with no
        // claim is not one whose claim has fallen.
        None => true,
        Some(_) => !status.claimant_gone || !status.open_on.is_empty(),
    }
}

/// Derive volume phase in precedence order: deletion means Releasing, then use
/// the latest observation, otherwise wait for placement or provisioning. Ready
/// requires a node observation; controller dispatch is not evidence of bytes.
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

/// Persistent tenant volume with its own lifecycle. Referenced Volume objects survive VM
/// deletion; inline spec.vm.volumes entries are instance storage created and removed with their
/// VM.
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
    /// Immutable source snapshot name in the same tenant. Mutually exclusive with baseImage;
    /// specifying both is rejected. Absence represents an empty or image-backed volume and
    /// preserves older records.
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
    /// Observation used by settle_volume. Node and mirrored cluster reports establish backend
    /// state; controller conclusions have an empty node and cannot establish Ready. None means
    /// no retained observation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reported: Option<VolumeReported>,
    /// Release blocker recorded by the pass that lists consumers, including VMs and snapshots.
    /// settle sees only this object, so the external relationship must be recorded here. None
    /// means no known blocker.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub holder: Option<String>,
    /// Evidence that no VM object refers to the volume. The listing pass refreshes it and
    /// volume_claim_holds combines it with openOn. The default false does not authorize
    /// dropping a claim before inspection.
    #[serde(default, skip_serializing_if = "is_false")]
    pub claimant_gone: bool,
    /// Backend-reported volume identifier, empty until observed. Backends derive stable names
    /// from metadata.uid, so retrying provision can rediscover the same storage without a
    /// controller-invented path.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub backend: String,
    /// The node that provisioned it. `None` while Pending.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node: Option<String>,
    /// Nodes reporting this volume open, sorted and deduplicated. This differs
    /// from `status.node`, the provisioning location. A second open is allowed
    /// only during Preparing or Running migration; see `second_open_is_a_migration`.
    /// An empty list on older records means no observation, not verified closure.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub open_on: Vec<String>,
    /// Owning cluster recorded by cloud dispatch and updated when a stopped VM's disk follows
    /// its new placement. Empty at the cluster tier. Older records without this field fall back
    /// to the pool's home cluster.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cluster: Option<String>,
    /// VM holding the volume within its tenant, or None when unclaimed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attached_to: Option<String>,
    /// The uid of the VM object in `attachedTo`: the claim belongs to that
    /// object and not to whatever carries its name later (IKR-B81). None on a
    /// claim written before claims carried a uid; such a claim is nobody's
    /// to adopt by name, and the claimant pass binds it or lets it fall. The
    /// cloud tier mirrors only the name and leaves this empty.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attached_uid: Option<String>,
    /// Observed backend size in GiB, rounded up from bytes. Zero means unmeasured. This can lag
    /// requested spec.sizeGib while a resize is in progress.
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub size_gib: u64,
    /// Resize size still awaiting guest notification; zero means none. Persisted before
    /// resizing the backend, then cleared after notification or when no running guest holds the
    /// volume. Cloud objects keep zero because that tier does not execute resize.
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub untold_gib: u64,
    /// Last metadata.generation acknowledged by the next tier after dispatch. It records that
    /// the change was picked up, not that all effects are complete. Older records default to
    /// zero.
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
    /// Whether the claim on this volume is the VM object `uid`'s. A claim with
    /// no uid is nobody's for this question; see `attached_uid`.
    pub fn claimed_by(&self, uid: &str) -> bool {
        self.attached_to.is_some() && self.attached_uid.as_deref() == Some(uid)
    }

    /// Whether the VM `name`/`uid` may let go of this claim: by uid, or — for
    /// a claim from before claims carried a uid — by the name it was written
    /// under. Taking a claim or carrying its record along (`claimed_by`)
    /// never accepts a name.
    pub fn held_by(&self, name: &str, uid: &str) -> bool {
        match self.attached_uid.as_deref() {
            Some(held) => held == uid,
            None => self.attached_to.as_deref() == Some(name),
        }
    }

    /// Record a node-reported open attachment, retaining sorted set semantics.
    /// Return whether it changed so unchanged reports do not create revisions.
    /// Only the volume status report owns this observation; command dispatch
    /// does not establish that attach or detach finished.
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

/// Permit a second-node open only during Preparing or Running migration of the holding VM.
/// Pending, terminal migrations, and absent migrations do not provide this exception to
/// AccessMode.
pub fn second_open_is_a_migration(phase: Option<VmMigrationPhaseKind>) -> bool {
    matches!(
        phase,
        Some(VmMigrationPhaseKind::Preparing) | Some(VmMigrationPhaseKind::Running)
    )
}

/// Construct a volume with its detach-before-delete finalizer. Deletion requests enter release;
/// deprovision waits until consumers let go.
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

/// A crash-consistent volume snapshot. It can remain after deletion is
/// requested for its origin: the origin stays Releasing until snapshot holds
/// are removed. Backend dependencies therefore remain protected.
///
/// There is no guest freeze; applications needing stronger consistency must
/// flush or quiesce before requesting the snapshot.
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
    /// Snapshot reasons combine controller dispatch, requeue, and source checks with the node
    /// reason vocabulary in proto::reasons::SNAPSHOT.
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
    /// Snapshot evidence consumed by settle_volume_snapshot. Controller conclusions use an
    /// empty node and cannot establish Ready; completion requires an identified machine
    /// observation. None precedes the first decision.
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

/// Derive snapshot phase from the last observation. Ready requires a node;
/// without an observation use Pending with AwaitingNode. The phase timestamp
/// changes with the kind, not with repeated reports.
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

    /// IKR-B81: a claim is the claimant OBJECT's. Its uid answers "is this
    /// mine", a claim from before claims carried one answers no to every
    /// VM, and the uid goes with the claim when it falls.
    #[test]
    fn a_claim_is_the_claimant_objects_and_falls_with_its_uid() {
        let mut held = attached();
        assert!(
            !held.status.claimed_by("u-web-1"),
            "no uid: nobody's to adopt"
        );
        assert!(
            held.status.held_by("web-1", "u-web-1-again"),
            "but its own vm, by the name it was written under, may let go of it"
        );
        held.status.attached_uid = Some("u-web-1".into());
        assert!(held.status.claimed_by("u-web-1"));
        assert!(!held.status.held_by("web-1", "u-web-1-again"));
        assert!(
            !held.status.claimed_by("u-web-1-again"),
            "the same name, another vm"
        );

        held.status.claimant_gone = true;
        held.status.open_on.clear();
        held.settle(at(10));
        assert_eq!(held.status.attached_uid, None);
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
