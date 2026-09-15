// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! The `Image` kind: the catalogue a VM boots from. Moved out of
//! `resources.rs` unchanged.

use super::*;

/// How the bytes are laid out where `source` points. The agent's block driver
/// already tells raw from qcow2 by itself; carrying it here is for the operator
/// reading `image ls` and for the storage backends that will need it to decide
/// between a copy and a clone.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum ImageFormat {
    #[default]
    Raw,
    Qcow2,
}

/// The image catalogue — a cloud resource from the start, because an image is
/// the one thing every tier below has to agree on by name.
///
/// v1 is a catalogue and a reference check, nothing else. `source` says where
/// the bytes already are (a path on shared storage, later a URL); no blob ever
/// travels through the control plane, and which machines hold a copy is
/// `status.nodes[]`, reported by the nodes themselves.
#[derive(Clone, Debug, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ImageSpec {
    /// The file name a node looks up under its own image_dir, and what a VM's
    /// `base_image` says. For a URL image this is the name the fetched bytes
    /// land under; for a path image it is where they already are.
    pub source: String,
    /// Where the bytes can be fetched from, if nobody has put them there by
    /// hand. Absent = the catalogue entry over existing shared storage this
    /// resource has always been, unchanged in every respect.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    /// What those bytes must hash to, lowercase hex. Mandatory with `url` and
    /// meaningless without one — checked at the create edge, because an image
    /// fetched over a network and not checked is an image somebody else can
    /// choose the contents of.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    #[serde(default)]
    pub format: ImageFormat,
    #[serde(default)]
    pub size_bytes: u64,
    /// Whose image this is. Absent = unscoped, the shape every image in the
    /// catalogue had before this milestone.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant: Option<String>,
    /// Readable by every tenant, writable by none but its owner. The base
    /// images a lab shares — one nixos.raw everybody boots from — are exactly
    /// this, and without it every tenant would need its own copy of the
    /// catalogue entry pointing at the same file.
    #[serde(default, skip_serializing_if = "is_false")]
    pub public: bool,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub labels: BTreeMap<String, String>,
}

reasons! {
    /// Why an image is what it is.
    ///
    /// One list out of two vocabularies, the shape `VmReason` explains. This
    /// tier has one word of its own — `AwaitingNode`, the wait before anybody
    /// has looked — and the four after it are the NODE's
    /// (`proto::reasons::IMAGE`). They are the whole of F16 in a closed set:
    /// `NotFound` is a catalogue entry pointing at bytes that are not there,
    /// `NotAFile` is a directory under the name, `ChecksumMismatch` is bytes
    /// that arrived and hash to something else, `FetchFailed` is bytes that
    /// did not arrive. All four used to be one word — `Reported` — with the
    /// node's prose beside it, so "roll-out still running" and "this will
    /// never work" were the same value.
    ImageReason [6] {
        /// Nobody recorded one — see `VmReason::Unrecorded`.
        #[default]
        Unrecorded => "Unrecorded",
        /// No node has said anything about the bytes yet. A URL image before
        /// anybody fetched it, and — from the derivation lane on — a path
        /// image before anybody looked.
        AwaitingNode => "AwaitingNode",

        // ------------------------------------------------------------------
        // The node's own words: `proto::reasons::IMAGE`, off
        // `ImageStateReport.reason`. No `Unrecorded` among them — the node's
        // image table is held in memory and re-derived from its disk, so
        // there is no stored opinion from an older build for one to come out
        // of.
        // ------------------------------------------------------------------

        /// The bytes are not at the path the node looks at. F16's word: a
        /// catalogue entry over shared storage nobody filled used to read
        /// `Ready` because no node had ever been asked to look.
        NotFound => "NotFound",
        /// Something IS under the name and it is a directory. `Ready` about
        /// one would hand a storage driver a path it cannot open.
        NotAFile => "NotAFile",
        /// The bytes arrived and hash to something other than `spec.sha256`.
        /// Its own word because the fix is a different one — the bytes at the
        /// url changed, or the checksum in the spec is wrong.
        ChecksumMismatch => "ChecksumMismatch",
        /// The bytes did not arrive at all, or could not be put in place.
        FetchFailed => "FetchFailed",
    }
}

phases! {
    /// Whether the bytes are there and are the right bytes.
    ///
    /// A path image is `Ready` the moment it is registered: it is a catalogue
    /// entry over storage somebody else already filled, and this control plane
    /// has never claimed to check it. A URL image starts `Pending` — nobody has
    /// fetched it yet — and moves when a node says what happened. F16 is
    /// exactly the first half of that sentence being a promise nobody kept;
    /// the derivation lane is where it stops being made.
    ImagePhase / ImagePhaseKind / ImageReason / ImagePhaseWire [3] {
        Pending { reason, message, since } => "Pending",
        Ready { message, since } => "Ready",
        Failed { reason, message, since } => "Failed",
    }
}

impl ImagePhaseKind {
    /// Both ends, and this is the one enum where `Failed` IS one: nothing
    /// retries an image. A checksum that does not match will not start
    /// matching, and a file that is not there appears when somebody puts it
    /// there — which is a new fact from a node and not a timer.
    pub fn is_terminal(self) -> bool {
        matches!(self, ImagePhaseKind::Ready | ImagePhaseKind::Failed)
    }
}

/// One node's word about one image.
///
/// The detail behind `ImageStatus::phase`, which is the UNION and therefore
/// says "Failed" the moment any node cannot use the bytes — true, and not
/// enough to act on: a rollout in progress and a checksum that will never
/// match look the same from up there, and the first is a wait while the
/// second is a mistake.
#[derive(Clone, Debug, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ImageNodeState {
    /// The node, as the cluster holding it calls it.
    pub name: String,
    /// And which cluster that is. Not decoration: node names are scoped to a
    /// cluster, so two clusters can each have a `node-1`, and a list keyed by
    /// the bare name would let one cluster's report overwrite another's. It
    /// is also what makes replacing this cluster's lines on every report a
    /// well-defined act.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub cluster: String,
    /// `Ready` or `Failed`. A node never says `Pending`: an image it has no
    /// opinion about is simply not in its report, and therefore not here.
    pub phase: ImagePhaseKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

/// `deny_unknown_fields` is off here and on every other spec and status in
/// this file, and the reason is `#[serde(flatten)]` below: serde cannot do
/// both, because a flattened field is exactly the thing that collects the
/// keys the outer struct does not know. The looseness is the same looseness
/// every status now reads with — one object stored before this change must
/// not break `list()` (decision 6) — and a status is server-written, so
/// there is no client typo for it to have caught.
///
/// The ONE key that was worth refusing is still refused, by name: see
/// `available_on`.
#[derive(Clone, Debug, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
// The private unit field below is not the `_priv: ()` non-exhaustive trick
// clippy is looking for — nothing about this struct is sealed, and adding a
// field to it is what every milestone does. It is a serde refusal; see
// `available_on`.
#[allow(clippy::manual_non_exhaustive)]
pub struct ImageStatus {
    /// The phase, with the reason it is that phase and since when.
    ///
    /// Flat on the wire — `phase`, `reason`, `message`, `since` as siblings
    /// right here — so every client that reads `status.phase` as a string
    /// goes on reading it as a string. See `resources::phase`.
    #[serde(flatten)]
    pub(super) phase: ImagePhase,
    /// Which nodes have the bytes, and which could not read them.
    ///
    /// Sorted by cluster and then by node, so two consecutive reports of the
    /// same facts are the same document and the mirror writes nothing.
    /// Empty = nobody has said anything yet, or every cluster reporting is
    /// older than the field — not "no nodes have it".
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub nodes: Vec<ImageNodeState>,
    /// `status.availableOn`, which is gone — declared here so that it can go
    /// on being REFUSED rather than silently dropped.
    ///
    /// It meant "not tracked" from v1 on and nothing ever wrote it; since
    /// `status.nodes[]` exists, the question it pretended to answer has a
    /// real answer beside it. A client that read the empty list and concluded
    /// "no cluster has this image" was reading a field, not a fact
    /// (fremdsicht 4), so an old client that still sends it has to hear about
    /// it instead of believing the server kept its value.
    ///
    /// `deny_unknown_fields` used to carry that and cannot any more — see the
    /// type's own comment. A named field can, and is better in one way: it
    /// says WHICH key is refused and why, right here, instead of leaving the
    /// answer to an attribute somebody would remove without knowing what it
    /// was holding up.
    #[serde(
        default,
        rename = "availableOn",
        deserialize_with = "refuse_available_on",
        skip_serializing
    )]
    #[schemars(skip)]
    // Never read, and that is the whole of it: its only job is to exist under
    // that name so serde hands the key here and the deserializer refuses it.
    #[allow(dead_code)]
    available_on: (),
}

/// The refusal itself, in serde's own words, so the sentence a client reads
/// is the one an unknown field has always produced.
fn refuse_available_on<'de, D: serde::Deserializer<'de>>(_: D) -> Result<(), D::Error> {
    Err(serde::de::Error::unknown_field(
        "availableOn",
        &["phase", "reason", "message", "since", "nodes"],
    ))
}

/// No finalizer: an image object owns no resource anywhere, so there is
/// nothing for a teardown to do and DELETE can mean delete.
pub type Image = Object<ImageSpec, ImageStatus>;
