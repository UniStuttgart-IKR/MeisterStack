// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Image catalogue entries and evidence reported by nodes.

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

/// Cloud image catalogue entry. Nodes report availability; the catalogue does not itself
/// distribute image bytes.
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
    /// Image reason categories combine controller decisions with node failures. AwaitingNode
    /// precedes any observation; DigestMismatch compares path-image digests. Node reasons
    /// distinguish missing files, non-files, checksum failures, and fetch failures.
    ImageReason [7] {
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

        // --------------------------------------------------------------
        // This tier's own second word. Never sent by a node — no field on
        // `ImageStateReport` carries it — because comparing every `Ready`
        // line's digest to the one this catalogue entry is bound to is a
        // fact only the tier that HOLDS `status.digest` can state.
        // --------------------------------------------------------------

        /// A Ready observation disagrees with the digest already bound to this catalogue entry.
        DigestMismatch => "DigestMismatch",
    }
}

phases! {
    /// Image availability derived from node observations, including complete
    /// inventories. Registration alone cannot establish Ready. See [`settle_image`].
    ImagePhase / ImagePhaseKind / ImageReason / ImagePhaseWire / ImageReported [3] {
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

/// One node's image observation, qualified by cluster because node names are cluster-scoped.
#[derive(Clone, Debug, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ImageNodeState {
    /// The node, as the cluster holding it calls it.
    pub name: String,
    /// Cluster containing this node; node names are not globally unique.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub cluster: String,
    /// `Ready` or `Failed`. A node never says `Pending`: an image it has no
    /// opinion about is simply not in its report, and therefore not here.
    pub phase: ImagePhaseKind,
    /// Node reason used directly by image phase derivation.
    #[serde(default, skip_serializing_if = "is_unrecorded_image_reason")]
    pub reason: ImageReason,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    /// SHA-256 reported for a Ready path image. Absent for failures, URL images bound by
    /// spec.sha256, and older reporters. The first reported digest binds the catalogue;
    /// subsequent reports must match.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub digest: Option<String>,
}

fn is_unrecorded_image_reason(reason: &ImageReason) -> bool {
    *reason == ImageReason::Unrecorded
}

/// Server-written image status permits unknown fields for flattened phase compatibility. The
/// removed availableOn field is explicitly rejected rather than silently discarded.
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
    /// Digest pinned once from the first Ready path-image observation. Later disagreement fails
    /// the image. URL images instead use spec.sha256; unobserved path images remain unbound.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub digest: Option<String>,
    /// Compatibility rejection for the removed status.availableOn field. Availability is
    /// represented by status.nodes; this field must neither serialize nor silently accept
    /// client input.
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

/// Derive image state from observations. No observations means AwaitingNode.
/// Checksum mismatch, a non-file or disagreement with the pinned digest takes
/// precedence over readiness. Otherwise one Ready node is sufficient; if all
/// report failure, retain the failure and identify its node. Per-node details
/// remain available even when the aggregate is Ready.
pub fn settle_image(spec: &ImageSpec, status: &ImageStatus) -> ImagePhase {
    let said = |line: &ImageNodeState| match &line.message {
        Some(message) => format!("{}: {message}", line.name),
        None => format!("{} says {}", line.name, line.reason.as_str()),
    };
    // Rule 2, before anything else.
    if let Some(bytes) = status.nodes.iter().find(|n| {
        matches!(
            n.reason,
            ImageReason::ChecksumMismatch | ImageReason::NotAFile
        )
    }) {
        return ImagePhase::new(
            ImagePhaseKind::Failed,
            bytes.reason,
            Some(said(bytes)),
            UNSTAMPED,
        );
    }
    // Rule 2b. Only once this catalogue entry is bound to a digest at all —
    // `first_bound_digest` is what binds `status.digest`, and until then
    // there is nothing here to disagree with.
    if let Some(pinned) = &status.digest
        && let Some(bad) = status.nodes.iter().find(|n| {
            n.phase == ImagePhaseKind::Ready && n.digest.as_deref().is_some_and(|d| d != pinned)
        })
    {
        return ImagePhase::new(
            ImagePhaseKind::Failed,
            ImageReason::DigestMismatch,
            Some(format!(
                "the file under {} on {} is not the one this image was bound to",
                spec.source, bad.name
            )),
            UNSTAMPED,
        );
    }
    // Rule 3. The sentence is the node's if it gave one, which it does not:
    // a node with the bytes has nothing to add.
    if let Some(ready) = status
        .nodes
        .iter()
        .find(|n| n.phase == ImagePhaseKind::Ready)
    {
        return ImagePhase::said(ImagePhaseKind::Ready, ready.message.clone(), UNSTAMPED);
    }
    // Rule 4.
    if let Some(first) = status.nodes.first() {
        return ImagePhase::new(
            ImagePhaseKind::Failed,
            first.reason,
            Some(said(first)),
            UNSTAMPED,
        );
    }
    // Rule 1, and the sentence says what is being waited FOR, which differs:
    // a url image is waiting for a fetch, a path image for somebody to look
    // at a file that is supposed to be there already.
    ImagePhase::new(
        ImagePhaseKind::Pending,
        ImageReason::AwaitingNode,
        Some(match &spec.url {
            Some(_) => "not fetched by any node yet".to_string(),
            None => format!("no node has looked for {} yet", spec.source),
        }),
        UNSTAMPED,
    )
}

/// Return the first digest on a Ready observation. Ingest calls this only while status.digest
/// is absent and sorts observations by (cluster, name) before choosing. Once bound,
/// settle_image rejects disagreement.
pub fn first_bound_digest(nodes: &[ImageNodeState]) -> Option<String> {
    nodes
        .iter()
        .find(|n| n.phase == ImagePhaseKind::Ready && n.digest.is_some())
        .and_then(|n| n.digest.clone())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(secs: i64) -> DateTime<Utc> {
        DateTime::from_timestamp(1_800_000_000 + secs, 0).expect("an instant")
    }

    fn line(node: &str, phase: ImagePhaseKind, reason: ImageReason) -> ImageNodeState {
        ImageNodeState {
            name: node.to_string(),
            cluster: "cluster-1".to_string(),
            phase,
            reason,
            message: None,
            digest: None,
        }
    }

    fn image(url: Option<&str>, nodes: Vec<ImageNodeState>) -> Image {
        let mut image = Image::declare(
            "debian.raw",
            ImageSpec {
                source: "debian.raw".to_string(),
                url: url.map(str::to_string),
                ..Default::default()
            },
        );
        image.status.nodes = nodes;
        image
    }

    /// The table: what the fleet said, and what the image therefore IS.
    ///
    /// One case per rule of `settle_image`, in the order the rules run, so a
    /// rule that stops mattering shows up as a row that no longer decides.
    #[test]
    fn what_the_fleet_said_about_an_image_is_what_the_image_is() {
        let cases: &[(&str, Vec<ImageNodeState>, ImagePhaseKind, ImageReason)] = &[
            (
                "nobody has looked",
                vec![],
                ImagePhaseKind::Pending,
                ImageReason::AwaitingNode,
            ),
            (
                "one node has the bytes",
                vec![line("a", ImagePhaseKind::Ready, ImageReason::Unrecorded)],
                ImagePhaseKind::Ready,
                ImageReason::Unrecorded,
            ),
            (
                // The rule that changed. A fetch that failed on one machine
                // is a fact about that machine, and the union used to let it
                // speak for the image.
                "one node has them and one could not fetch them",
                vec![
                    line("a", ImagePhaseKind::Ready, ImageReason::Unrecorded),
                    line("b", ImagePhaseKind::Failed, ImageReason::FetchFailed),
                ],
                ImagePhaseKind::Ready,
                ImageReason::Unrecorded,
            ),
            (
                // And the rule that did not. A checksum is a fact about the
                // BYTES and beats a node that is happy with them.
                "one node has them and one says they are the wrong bytes",
                vec![
                    line("a", ImagePhaseKind::Ready, ImageReason::Unrecorded),
                    line("b", ImagePhaseKind::Failed, ImageReason::ChecksumMismatch),
                ],
                ImagePhaseKind::Failed,
                ImageReason::ChecksumMismatch,
            ),
            (
                "a directory under the catalogue name",
                vec![
                    line("a", ImagePhaseKind::Ready, ImageReason::Unrecorded),
                    line("b", ImagePhaseKind::Failed, ImageReason::NotAFile),
                ],
                ImagePhaseKind::Failed,
                ImageReason::NotAFile,
            ),
            (
                // F16, all the way through: every node that looked found
                // nothing, so the catalogue entry points at nothing.
                "every node that looked found no file",
                vec![
                    line("a", ImagePhaseKind::Failed, ImageReason::NotFound),
                    line("b", ImagePhaseKind::Failed, ImageReason::NotFound),
                ],
                ImagePhaseKind::Failed,
                ImageReason::NotFound,
            ),
        ];
        for (about, nodes, phase, reason) in cases {
            let settled = settle_image(
                &image(None, nodes.clone()).spec,
                &ImageStatus {
                    nodes: nodes.clone(),
                    ..Default::default()
                },
            );
            assert_eq!(settled.kind(), *phase, "{about}");
            assert_eq!(settled.reason().unwrap_or_default(), *reason, "{about}");
        }
    }

    /// A digest line carries into the table above too, once pinned: agreeing
    /// digests settle exactly as bare `Ready` does, and a disagreeing one
    /// fails the image — Astra finding S02, 2026-09-23 (rest a).
    #[test]
    fn a_digest_that_disagrees_with_the_pinned_one_fails_the_image() {
        let digest_line = |node: &str, digest: &str| ImageNodeState {
            digest: Some(digest.to_string()),
            ..line(node, ImagePhaseKind::Ready, ImageReason::Unrecorded)
        };

        // Nothing pinned yet: a lone digest settles as an ordinary `Ready`,
        // exactly as it did before this field existed.
        let settled = settle_image(
            &image(None, vec![]).spec,
            &ImageStatus {
                nodes: vec![digest_line("a", "1111")],
                digest: None,
                ..Default::default()
            },
        );
        assert_eq!(settled.kind(), ImagePhaseKind::Ready);

        // Pinned, and every node agrees: still `Ready`.
        let settled = settle_image(
            &image(None, vec![]).spec,
            &ImageStatus {
                nodes: vec![digest_line("a", "1111"), digest_line("b", "1111")],
                digest: Some("1111".to_string()),
                ..Default::default()
            },
        );
        assert_eq!(settled.kind(), ImagePhaseKind::Ready);

        // Pinned, and a second node's bytes are not the ones this catalogue
        // entry was bound to.
        let settled = settle_image(
            &image(None, vec![]).spec,
            &ImageStatus {
                nodes: vec![digest_line("a", "1111"), digest_line("b", "2222")],
                digest: Some("1111".to_string()),
                ..Default::default()
            },
        );
        assert_eq!(settled.kind(), ImagePhaseKind::Failed);
        assert_eq!(settled.reason(), Some(ImageReason::DigestMismatch));
        let message = settled.message().expect("a sentence");
        assert!(message.contains("debian.raw"), "{message}");
        assert!(message.contains('b'), "names the node: {message}");

        // A `Failed` line's own (absent) digest is not a disagreement — only
        // a `Ready` line that actively claims different bytes is one.
        let settled = settle_image(
            &image(None, vec![]).spec,
            &ImageStatus {
                nodes: vec![
                    digest_line("a", "1111"),
                    line("b", ImagePhaseKind::Failed, ImageReason::NotFound),
                ],
                digest: Some("1111".to_string()),
                ..Default::default()
            },
        );
        assert_eq!(settled.kind(), ImagePhaseKind::Ready);
    }

    /// Which digest a catalogue entry binds to: the first `Ready` line that
    /// has one, in the order the ingest already sorts by — never the newest,
    /// which would let a later report move a binding that is supposed to be
    /// fixed once made.
    #[test]
    fn the_first_digest_a_ready_node_reports_is_the_one_that_is_bound() {
        assert_eq!(first_bound_digest(&[]), None, "nobody has said anything");

        assert_eq!(
            first_bound_digest(&[line("a", ImagePhaseKind::Ready, ImageReason::Unrecorded)]),
            None,
            "ready, but no digest — a url image, or a path image from before this field"
        );

        let with_digest = |node: &str, digest: &str| ImageNodeState {
            digest: Some(digest.to_string()),
            ..line(node, ImagePhaseKind::Ready, ImageReason::Unrecorded)
        };
        assert_eq!(
            first_bound_digest(&[
                line("a", ImagePhaseKind::Failed, ImageReason::NotFound),
                with_digest("b", "aaaa"),
                with_digest("c", "bbbb"),
            ]),
            Some("aaaa".to_string()),
            "the first READY line with a digest, not the first line of any kind"
        );
    }

    /// New catalogue entries remain pending until a node reports the bytes. The initial message
    /// distinguishes local availability from an outstanding URL fetch.
    #[test]
    fn a_freshly_registered_image_waits_for_a_node_whichever_kind_it_is() {
        let mut path = image(None, vec![]);
        path.settle(at(0));
        assert_eq!(path.status.phase().kind(), ImagePhaseKind::Pending);
        assert_eq!(
            path.status.phase().reason(),
            Some(ImageReason::AwaitingNode)
        );
        assert_eq!(
            path.status.phase().message(),
            Some("no node has looked for debian.raw yet")
        );
        assert_eq!(path.status.phase().since(), at(0));

        let mut fetched = image(Some("https://example.invalid/debian.raw"), vec![]);
        fetched.settle(at(0));
        assert_eq!(fetched.status.phase().kind(), ImagePhaseKind::Pending);
        assert_eq!(
            fetched.status.phase().message(),
            Some("not fetched by any node yet")
        );
    }

    /// The stamp belongs to the WORD: a derivation that runs on every write
    /// must not move it, or "Ready since" becomes "last written".
    #[test]
    fn settling_twice_over_the_same_word_does_not_move_the_stamp() {
        let mut image = image(
            None,
            vec![line("a", ImagePhaseKind::Ready, ImageReason::Unrecorded)],
        );
        image.settle(at(0));
        assert_eq!(image.status.phase().since(), at(0));
        image.settle(at(600));
        assert_eq!(image.status.phase().since(), at(0));

        // A new word IS the moment of the change.
        image.status.nodes = vec![line("a", ImagePhaseKind::Failed, ImageReason::NotFound)];
        image.settle(at(900));
        assert_eq!(image.status.phase().kind(), ImagePhaseKind::Failed);
        assert_eq!(image.status.phase().since(), at(900));
    }
}
