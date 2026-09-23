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
    /// tier has two words of its own — `AwaitingNode`, the wait before
    /// anybody has looked, and `DigestMismatch`, this tier's own comparison
    /// against `status.digest` — and the four after them are the NODE's
    /// (`proto::reasons::IMAGE`). They are the whole of F16 in a closed set:
    /// `NotFound` is a catalogue entry pointing at bytes that are not there,
    /// `NotAFile` is a directory under the name, `ChecksumMismatch` is bytes
    /// that arrived and hash to something else, `FetchFailed` is bytes that
    /// did not arrive. All four used to be one word — `Reported` — with the
    /// node's prose beside it, so "roll-out still running" and "this will
    /// never work" were the same value.
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

        /// A `Ready` node's digest disagrees with `status.digest`, the first
        /// one this catalogue entry was bound to.
        ///
        /// Astra finding S02, 2026-09-23 (rest a). `check_source_kind` keeps
        /// a member from adopting a file that is already on the nodes, but an
        /// operator's own path registration had no checksum to bind it to
        /// bytes at all — so a swap of the file after the fact, or two
        /// registrations that were never the same file to begin with, went
        /// unnoticed. See `settle_image` and `first_bound_digest`.
        DigestMismatch => "DigestMismatch",
    }
}

phases! {
    /// Whether the bytes are there and are the right bytes.
    ///
    /// **Every variant of this needs an observation, and that is F16's
    /// answer.** A path image used to be `Ready` the moment it was
    /// registered, on the argument that a catalogue entry over storage
    /// somebody else filled is not this control plane's to check — but
    /// `Ready` is not "we make no claim", it is a claim, and the chaos-extrem
    /// run found an entry pointing at nothing wearing it for as long as
    /// anybody looked. A VM booting from it failed at the node, with the
    /// storage driver's own words, one tier away from the object that had
    /// promised the bytes were fine.
    ///
    /// So the node is what looks — at a url image it fetched and at a path
    /// image it merely finds, and it lists its whole image directory so that
    /// an entry nothing uses is described too (`StatusReport.images_complete`).
    /// The phase is derived from those words and from nothing else; see
    /// [`settle_image`] for the four rules and `ImageNodeState` for what one
    /// machine's word looks like.
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
    /// WHY, in the node's own closed word — the fact `settle` derives the
    /// image's phase from.
    ///
    /// `Unrecorded` (absent on the wire) for a `Ready` line and for a cluster
    /// older than the field. It is the difference between a roll-out still
    /// running and bytes that will never be right: `FetchFailed` on one node
    /// is a node's problem, `ChecksumMismatch` anywhere is the image's.
    #[serde(default, skip_serializing_if = "is_unrecorded_image_reason")]
    pub reason: ImageReason,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    /// The sha256 this node bound a PATH image's bytes to, if it is a `Ready`
    /// line and the node has one.
    ///
    /// Astra finding S02, 2026-09-23 (rest a). `None` for every `Failed` line
    /// (nothing to hash), for a url image (its checksum is `spec.sha256` and
    /// this field would only repeat it), and for a node or a cluster older
    /// than the field. `first_bound_digest` reads the first one of these that
    /// shows up as `ImageStatus.digest`, and `settle_image` holds every later
    /// `Ready` line to it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub digest: Option<String>,
}

fn is_unrecorded_image_reason(reason: &ImageReason) -> bool {
    *reason == ImageReason::Unrecorded
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
    /// The sha256 this catalogue entry is bound to, once a node's report
    /// binds it.
    ///
    /// Astra finding S02, 2026-09-23 (rest a). A path registration has no
    /// checksum by construction — that is `check_source_kind`'s TODO, closed
    /// here — so nothing bound the catalogue name to particular bytes until
    /// this existed. Set once, from `first_bound_digest`, and never moved:
    /// `settle_image` fails the image the moment a LATER `Ready` line
    /// disagrees with it, which is the whole point of pinning it rather than
    /// tracking whatever the newest report says.
    ///
    /// `None` for a url image (bound by `spec.sha256` from creation, which
    /// this would only repeat) and for one nobody has looked at yet.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub digest: Option<String>,
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

/// What the fleet's words about an image ADD UP TO. The whole of F16's
/// controller half, and the first derivation of this round.
///
/// A pure function of the spec and `status`, which is the only fact there is
/// about an image: no node has ever been asked a question about one, they
/// simply say what is on their disks. Five rules, in this order:
///
/// 1. **Nobody has said anything → `Pending { AwaitingNode }`.** This is F16.
///    A path image used to be `Ready` the moment it was registered — a
///    catalogue entry over shared storage somebody else was supposed to have
///    filled — and the chaos run found one pointing at nothing, `Ready`, for
///    as long as anybody looked. `Ready` demands an observation now, and
///    there is no path that writes it without one.
/// 2. **A fact about the BYTES beats everything.** `ChecksumMismatch` and
///    `NotAFile` are true wherever the bytes are: a checksum that did not
///    match will not start matching, and a directory under the catalogue name
///    is a path no storage driver can open. One node saying either is the
///    image's answer. **A digest that disagrees with `status.digest` is the
///    same kind of fact, for the image kind that had no checksum at all:**
///    Astra finding S02, 2026-09-23 (rest a). A path registration's bytes
///    were never bound to anything until a node hashed them, so a later
///    report of different bytes under the same name is exactly what this
///    rule is for — it is just read off a different field, because there was
///    no `spec.sha256` to compare against.
/// 3. **Otherwise one `Ready` is enough.** A fact about a NODE — `NotFound`,
///    `FetchFailed` — is not a fact about the image, and this is the rule
///    that CHANGED: the union used to let any `Failed` win, so a four-node
///    fleet mid-roll-out showed a working image as broken. `ImageNodeState`'s
///    own doc comment has said so since it was written ("a rollout in
///    progress and a checksum that will never match look the same from up
///    there, and the first is a wait while the second is a mistake"); the
///    per-node list is where that detail now lives, and it is complete.
/// 4. **Every node that looked failed → `Failed`,** with the first line's
///    word and a sentence naming the machine.
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

/// The digest a catalogue entry binds to, the first time any `Ready` line
/// carries one.
///
/// Astra finding S02, 2026-09-23 (rest a). Pure, and read once — the ingest
/// that mirrors a cluster's report calls this only while `status.digest` is
/// still `None`, so ONE report from ONE node decides it and nothing after
/// that reopens the question; see `settle_image`'s rule 2b for what happens
/// once it is set.
///
/// `nodes` is read in order and the first match wins, which is deterministic
/// because the ingest sorts it by `(cluster, name)` before this runs — two
/// clusters racing to report first pick the same answer wherever the choice
/// is actually made.
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

    /// F16 at the create edge: a path image is not `Ready` because it was
    /// registered. It used to be, and the chaos run found one over a file
    /// nobody had ever looked at wearing the word.
    ///
    /// The sentence differs by kind because the WAIT differs: a url image is
    /// waiting for a fetch, a path image for somebody to look at a file that
    /// is supposed to be there already.
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
