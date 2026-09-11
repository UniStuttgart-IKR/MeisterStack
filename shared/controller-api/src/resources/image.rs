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

/// Whether the bytes are there and are the right bytes.
///
/// A path image is `Ready` the moment it is registered: it is a catalogue
/// entry over storage somebody else already filled, and this control plane
/// has never claimed to check it. A URL image starts `Pending` — nobody has
/// fetched it yet — and moves when a node says what happened.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub enum ImagePhase {
    #[default]
    Pending,
    Ready,
    Failed,
}

impl ImagePhase {
    pub const ALL: [ImagePhase; 3] = [ImagePhase::Pending, ImagePhase::Ready, ImagePhase::Failed];

    /// The spelling that goes on the wire (control.proto: ImageStateReport).
    /// `parse` is its inverse and the tests hold them to it.
    pub fn as_str(self) -> &'static str {
        match self {
            ImagePhase::Pending => "Pending",
            ImagePhase::Ready => "Ready",
            ImagePhase::Failed => "Failed",
        }
    }

    /// Unknown input is rejected rather than defaulted — a drifting node
    /// should be visible, not silently "Pending". The rule VmPhase follows.
    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|p| p.as_str() == s)
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
    pub phase: ImagePhase,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ImageStatus {
    #[serde(default)]
    pub phase: ImagePhase,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    /// Which nodes have the bytes, and which could not read them.
    ///
    /// Sorted by cluster and then by node, so two consecutive reports of the
    /// same facts are the same document and the mirror writes nothing.
    /// Empty = nobody has said anything yet, or every cluster reporting is
    /// older than the field — not "no nodes have it".
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub nodes: Vec<ImageNodeState>,
}

/// No finalizer: an image object owns no resource anywhere, so there is
/// nothing for a teardown to do and DELETE can mean delete.
pub type Image = Object<ImageSpec, ImageStatus>;
