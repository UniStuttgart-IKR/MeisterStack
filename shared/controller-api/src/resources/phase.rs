// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Phases carry a kind, reason, message and transition timestamp.
//!
//! The macros define comparable `XPhaseKind` enums, evidence-bearing `XPhase`
//! values and their flat wire representation. Resource-specific derivation and
//! stability predicates remain explicit. A phase timestamp changes only when
//! the kind changes; legacy records without a reason remain readable.

use super::*;

/// The type of one field of a phase variant.
///
/// In type position, and a macro because the variant lists spell FIELD NAMES
/// (`{ reason, message, since }`) and something has to turn each name into a
/// type. `macro_rules` is the only thing in the language that can branch on
/// which name it was.
macro_rules! phase_field {
    (reason, $reason:ty) => {
        $reason
    };
    (message, $reason:ty) => {
        String
    };
    (since, $reason:ty) => {
        DateTime<Utc>
    };
}

/// The value one field of a phase variant gets when the phase is built from
/// its parts. The same trick one macro up, in expression position.
macro_rules! phase_value {
    (reason, $reason:expr, $message:expr, $since:expr) => {
        $reason
    };
    (message, $reason:expr, $message:expr, $since:expr) => {
        $message
    };
    (since, $reason:expr, $message:expr, $since:expr) => {
        $since
    };
}

/// Extract a reason by variant arity: three fields include reason, two are resting states, and
/// other shapes fail compilation. Pass bindings explicitly to preserve macro hygiene.
macro_rules! phase_reason_of {
    ($reason:ident, $message:ident, $since:ident) => {
        Some(*$reason)
    };
    ($message:ident, $since:ident) => {
        None
    };
}

/// Generate phase kinds, evidence-bearing phases, wire forms and observations.
/// Each resource invokes the macro beside its reason definitions.
///
/// ```ignore
/// phases! {
///     VolumePhase / VolumePhaseKind / VolumeReason / VolumePhaseWire / VolumeReported [2] {
///         Pending { reason, message, since } => "Pending",
///         Ready { message, since } => "Ready",
///     }
/// }
/// ```
///
/// The array length must match the variants. Every variant retains a message
/// and transition timestamp; only variants declaring `reason` carry a category.
macro_rules! phases {
    ($(
        $(#[$about:meta])*
        $phase:ident / $kind:ident / $reason:ident / $wire:ident / $said:ident [$count:literal] {
            $(
                $(#[$variant_about:meta])*
                $variant:ident { $($field:ident),* } => $word:literal,
            )*
        }
    )*) => { $(
        $(#[$about])*
        ///
        /// The WORD of the phase: what this enum was before struktur 4, under
        /// the name without `Kind`. Everything that compares, matches or
        /// labels uses this; what the object stores is the phase beside it,
        /// which carries the reason as well.
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
        pub enum $kind {
            $( $(#[$variant_about])* $variant, )*
        }

        impl $kind {
            /// Every variant, in declaration order — see `RunStrategy::ALL`.
            pub const ALL: [$kind; $count] = [ $( $kind::$variant ),* ];

            /// The spelling that goes on the wire, in both directions and at
            /// both tiers. `parse` is its inverse and the tests hold them to
            /// it.
            pub fn as_str(self) -> &'static str {
                match self { $( $kind::$variant => $word, )* }
            }

            /// Unknown input is rejected rather than defaulted — a drifting
            /// peer should be visible, not silently the first variant.
            pub fn parse(s: &str) -> Option<Self> {
                Self::ALL.into_iter().find(|k| k.as_str() == s)
            }
        }

        impl Default for $kind {
            /// The first variant. Every one of these declares the
            /// nothing-has-happened-yet state first, which is what the
            /// `Default` derive used to pick and what an object nobody has
            /// looked at has always read as.
            fn default() -> Self {
                Self::ALL[0]
            }
        }

        $(#[$about])*
        ///
        /// The word WITH its evidence, which is what the object stores and
        /// what `status.phase()` hands out.
        #[derive(Clone, Debug, PartialEq, Eq)]
        pub enum $phase {
            $( $(#[$variant_about])* $variant { $( $field: phase_field!($field, $reason) ),* }, )*
        }

        impl $phase {
            /// The phase `kind` with everything the caller knows about it.
            ///
            /// The reason is DROPPED for a variant that carries none — a
            /// `Ready` has no category behind it, and taking one here rather
            /// than at every call site is what lets a mechanical migration
            /// pass the same tuple everywhere.
            pub fn new(
                kind: $kind,
                reason: $reason,
                message: Option<String>,
                since: DateTime<Utc>,
            ) -> Self {
                let message = message.unwrap_or_default();
                match kind {
                    $( $kind::$variant => $phase::$variant {
                        $( $field: phase_value!($field, reason, message, since) ),*
                    }, )*
                }
            }

            /// The phase, and nobody recorded why. The honest value for a
            /// writer that has nothing to say — see [`Self::new`] and
            /// decision 6 of the brief: the next pass replaces it.
            pub fn of(kind: $kind, since: DateTime<Utc>) -> Self {
                Self::new(kind, <$reason>::Unrecorded, None, since)
            }

            /// The phase with a sentence and no category — what a report from
            /// the tier below gives this tier today.
            pub fn said(kind: $kind, message: Option<String>, since: DateTime<Utc>) -> Self {
                Self::new(kind, <$reason>::Unrecorded, message, since)
            }

            pub fn kind(&self) -> $kind {
                match self { $( $phase::$variant { .. } => $kind::$variant, )* }
            }

            /// When the KIND last changed, as this tier saw it. Never moves
            /// while the word stays the same — see `assign`.
            pub fn since(&self) -> DateTime<Utc> {
                match self { $( $phase::$variant { since, .. } => *since, )* }
            }

            /// Optional category for reason-bearing variants. Bind all fields so
            /// phase_reason_of can distinguish variants by arity.
            #[allow(unused_variables)]
            pub fn reason(&self) -> Option<$reason> {
                match self {
                    $( $phase::$variant { $($field,)* } => phase_reason_of!($($field),*), )*
                }
            }

            /// Wire reason, or an empty string for resting variants and Unrecorded. Keeping
            /// Unrecorded absent preserves the representation of older objects and is shared by
            /// relays, serialization, and metrics.
            pub fn reason_word(&self) -> &'static str {
                match self.reason() {
                    Some(reason) if reason != <$reason>::Unrecorded => reason.as_str(),
                    _ => "",
                }
            }

            /// The sentence, and `None` rather than `Some("")`: an empty
            /// message is "nobody said anything", which is the rule
            /// `mirror::observe` has always applied and the reason a clearing
            /// report is not a write.
            pub fn message(&self) -> Option<&str> {
                match self {
                    $( $phase::$variant { message, .. } =>
                        (!message.is_empty()).then_some(message.as_str()), )*
                }
            }
        }

        impl Default for $phase {
            fn default() -> Self {
                Self::of($kind::default(), UNSTAMPED)
            }
        }

        /// Flat status wire representation: phase, reason, message, and since are sibling
        /// fields. Phase remains a string rather than an externally tagged enum.
        #[derive(Clone, Debug, Default, Serialize, Deserialize, JsonSchema)]
        pub struct $wire {
            #[serde(default)]
            pub phase: $kind,
            #[serde(default, skip_serializing_if = "Option::is_none")]
            pub reason: Option<String>,
            #[serde(default, skip_serializing_if = "Option::is_none")]
            pub message: Option<String>,
            #[serde(default, skip_serializing_if = "Option::is_none")]
            pub since: Option<DateTime<Utc>>,
        }

        impl From<$phase> for $wire {
            fn from(phase: $phase) -> Self {
                Self {
                    phase: phase.kind(),
                    // `Unrecorded` is absent rather than a word, so an object
                    // nobody has recorded a reason for looks on the wire
                    // exactly as it did before this field existed — and reads
                    // back as `Unrecorded`, which is the same value.
                    reason: (!phase.reason_word().is_empty())
                        .then(|| phase.reason_word().to_string()),
                    message: phase.message().map(str::to_string),
                    since: (phase.since() != UNSTAMPED).then(|| phase.since()),
                }
            }
        }

        /// Recorded evidence used by pure phase derivation. An empty node identifies a
        /// controller conclusion; resting states that assert observed guest or storage state
        /// require a machine identity. Reconcile passes record external facts before settle
        /// reads them.
        #[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
        #[serde(rename_all = "camelCase", deny_unknown_fields)]
        pub struct $said {
            /// The word, as the party that said it spelled it.
            #[serde(default)]
            pub phase: $kind,
            /// And why, in this resource's one closed vocabulary — the
            /// node's words and this tier's, in one list. See `$reason`.
            #[serde(default)]
            pub reason: $reason,
            #[serde(default, skip_serializing_if = "Option::is_none")]
            pub message: Option<String>,
            /// Time this observation was first established. Repeated equivalent reports retain
            /// it; same_word excludes this timestamp to avoid needless store updates.
            pub at: DateTime<Utc>,
            /// The machine or cluster whose word this is, and empty for this
            /// tier's own conclusion. See the type's own doc.
            #[serde(default, skip_serializing_if = "String::is_empty")]
            pub node: String,
        }

        impl $said {
            /// A word from a peer: a node at the cluster, a cluster at the
            /// cloud.
            pub fn by(
                node: &str,
                phase: $kind,
                reason: $reason,
                message: Option<String>,
                at: DateTime<Utc>,
            ) -> Self {
                Self { phase, reason, message, at, node: node.to_string() }
            }

            /// A word this tier established itself — see `node`. It can never
            /// put an object into a resting state.
            pub fn here(
                phase: $kind,
                reason: $reason,
                message: Option<String>,
                at: DateTime<Utc>,
            ) -> Self {
                Self { phase, reason, message, at, node: String::new() }
            }

            /// Do these two say the same thing? Everything but `at`.
            ///
            /// The churn guard every ingest uses, and the reason it is here
            /// rather than at each of them: a peer reports every ten seconds
            /// and says what it said last time, so what must not count as a
            /// difference is the INSTANT. See `at`.
            pub fn same_word(&self, other: &Self) -> bool {
                self.phase == other.phase
                    && self.reason == other.reason
                    && self.message == other.message
                    && self.node == other.node
            }

            /// The phase this word amounts to, or `None` when nobody with the
            /// evidence said it. See the type's own doc for the rule.
            pub fn phase(&self) -> Option<$phase> {
                let resting = $phase::new(self.phase, self.reason, None, UNSTAMPED)
                    .reason()
                    .is_none();
                (!resting || !self.node.is_empty()).then(|| {
                    $phase::new(self.phase, self.reason, self.message.clone(), UNSTAMPED)
                })
            }
        }

        impl From<$wire> for $phase {
            /// Decode older or unfamiliar wire states without failing resource reads. Preserve
            /// unrecognized text in the message while mapping to a known fallback.
            fn from(wire: $wire) -> Self {
                // A word this binary does not know is not dropped: it goes to
                // the front of the sentence. See `read` — the same reader the
                // status road uses, so a drifting peer looks the same
                // whichever wire it drifted across.
                let (reason, message) =
                    <$reason>::read(wire.reason.as_deref().unwrap_or_default(), wire.message);
                Self::new(wire.phase, reason, message, wire.since.unwrap_or_else(Utc::now))
            }
        }

        impl Serialize for $phase {
            fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                $wire::from(self.clone()).serialize(serializer)
            }
        }

        impl<'de> Deserialize<'de> for $phase {
            fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
                Ok(Self::from($wire::deserialize(d)?))
            }
        }

        /// The schema `/schemas` publishes is the FLAT one, because the flat
        /// one is what a client sees. Delegated rather than derived: a
        /// data-carrying enum's derived schema would describe a shape nothing
        /// ever writes.
        impl JsonSchema for $phase {
            fn schema_name() -> std::borrow::Cow<'static, str> {
                <$wire as JsonSchema>::schema_name()
            }
            fn schema_id() -> std::borrow::Cow<'static, str> {
                <$wire as JsonSchema>::schema_id()
            }
            fn json_schema(generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
                <$wire as JsonSchema>::json_schema(generator)
            }
            fn inline_schema() -> bool {
                <$wire as JsonSchema>::inline_schema()
            }
        }
    )* };
}

/// The seven reason enums are the same shape as well: `Copy`, `ALL`,
/// `as_str`, `parse` — `RunStrategy`'s shape, which is the one every closed
/// set in this crate wears.
///
/// `Unrecorded` is not optional and is not generated: every list declares it
/// FIRST and marks it `#[default]`, because it is what a phase written before
/// struktur 4 reads back as and what a writer with nothing to say records.
macro_rules! reasons {
    ($(
        $(#[$about:meta])*
        $name:ident [$count:literal] {
            $( $(#[$variant_about:meta])* $variant:ident => $word:literal, )*
        }
    )*) => { $(
        $(#[$about])*
        ///
        /// Serialised as its own word, because a reason is also a FACT on a
        /// status now (`ImageNodeState::reason`, `Vm.status.reported.reason`)
        /// and not only a field of a phase. Reading is total, like every
        /// other read in this file: a word this binary does not know is
        /// `Unrecorded` and never an error, so one object written by a newer
        /// replica cannot break `list()`.
        #[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, JsonSchema)]
        pub enum $name {
            $( $(#[$variant_about])* $variant, )*
        }

        impl Serialize for $name {
            fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serializer.serialize_str(self.as_str())
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
                // The word only. A fact field carries no sentence of its own
                // to rescue an unknown word into — the ingest that wrote the
                // fact already applied [`Self::read`] to the wire it came off.
                Ok(Self::parse(&String::deserialize(d)?).unwrap_or_default())
            }
        }

        impl $name {
            /// Every variant, in declaration order — see `RunStrategy::ALL`.
            pub const ALL: [$name; $count] = [ $( $name::$variant ),* ];

            /// The word on the wire and in a metric label. PascalCase, like
            /// the phase it sits beside — `PendingReason` spells its own
            /// categories in kebab-case and predates this file.
            pub fn as_str(self) -> &'static str {
                match self { $( $name::$variant => $word, )* }
            }

            /// Its inverse. `None` for a word this binary does not know,
            /// which the readers turn into `Unrecorded` rather than an error.
            pub fn parse(s: &str) -> Option<Self> {
                Self::ALL.into_iter().find(|r| r.as_str() == s)
            }

            /// Parse a stored or reported reason. Empty input is Unrecorded; known
            /// words retain their category. Unknown words become Unrecorded and are
            /// prefixed to the message so version skew remains visible.
            pub fn read(word: &str, message: Option<String>) -> (Self, Option<String>) {
                if word.is_empty() {
                    return (Self::Unrecorded, message);
                }
                match Self::parse(word) {
                    Some(reason) => (reason, message),
                    None => (
                        Self::Unrecorded,
                        Some(match message {
                            Some(said) if !said.is_empty() => format!("{word}: {said}"),
                            _ => word.to_string(),
                        }),
                    ),
                }
            }
        }
    )* };
}

/// Generate status phase access and restricted stamping methods. Resource::settle
/// implementations own phase writes; callers record evidence instead of assigning phases
/// directly.
macro_rules! phased {
    ($( $status:ident / $phase:ident; )*) => { $(
        impl $status {
            /// What this tier says this object is doing, with the reason and
            /// the sentence that go with it.
            pub fn phase(&self) -> &$phase {
                &self.phase
            }

            /// Expose phase kind, reason, age, and terminal status for common stuck detection.
            /// Each resource defines terminal semantics, including whether Failed is final or
            /// retryable.
            pub fn standing(&self) -> crate::stuck::Standing {
                crate::stuck::Standing {
                    word: self.phase.kind().as_str(),
                    terminal: self.phase.kind().is_terminal(),
                    reason: self.phase.reason_word(),
                    since: self.phase.since(),
                }
            }

            /// Store a derived phase. Only resource `settle` implementations may call
            /// this method. Preserve `since` while the kind is unchanged, except for
            /// the first derivation of an UNSTAMPED object.
            pub(super) fn stamp(&mut self, phase: $phase, now: DateTime<Utc>) {
                let since = if phase.kind() == self.phase.kind() && self.phase.since() != UNSTAMPED
                {
                    self.phase.since()
                } else {
                    now
                };
                self.phase = $phase::new(
                    phase.kind(),
                    phase.reason().unwrap_or_default(),
                    phase.message().map(str::to_string),
                    since,
                );
            }
        }
    )* };
}

phased! {
    VmStatus / VmPhase;
    VolumeStatus / VolumePhase;
    VolumeSnapshotStatus / VolumeSnapshotPhase;
    ImageStatus / ImagePhase;
    StoragePoolStatus / StoragePoolPhase;
    RouterStatus / RouterPhase;
    VmMigrationStatus / VmMigrationPhase;
}

/// Epoch sentinel for an unstamped phase. Default status decoding uses it, and serialization
/// omits it so an unobserved object has no transition timestamp.
pub const UNSTAMPED: DateTime<Utc> = DateTime::<Utc>::UNIX_EPOCH;

#[cfg(test)]
mod tests {
    use super::*;

    /// One table for all seven, because the property is the same one: the
    /// word is the only thing that travels, and `parse` is its inverse. A
    /// variant added without a word is already a compile error (`as_str`
    /// matches exhaustively); this is the other direction.
    macro_rules! assert_kinds_round_trip {
        ($($kind:ident),*) => {$({
            for kind in $kind::ALL {
                assert_eq!(
                    $kind::parse(kind.as_str()),
                    Some(kind),
                    "{:?} does not survive its own word",
                    kind
                );
            }
            assert_eq!(
                $kind::ALL.len(),
                $kind::ALL
                    .iter()
                    .map(|k| k.as_str())
                    .collect::<std::collections::BTreeSet<_>>()
                    .len(),
                "two variants of {} share a word",
                stringify!($kind)
            );
            assert!($kind::parse("Ascended").is_none(), "a word we do not have");
            assert_eq!($kind::default(), $kind::ALL[0]);
        })*};
    }

    #[test]
    fn every_phase_kind_round_trips_through_its_word() {
        assert_kinds_round_trip!(
            VmPhaseKind,
            VolumePhaseKind,
            VolumeSnapshotPhaseKind,
            ImagePhaseKind,
            StoragePoolPhaseKind,
            RouterPhaseKind,
            VmMigrationPhaseKind
        );
    }

    /// The same for the reasons, and `Unrecorded` is checked by name: every
    /// list has to have it, because it is what a phase written before this
    /// change reads back as.
    macro_rules! assert_reasons_round_trip {
        ($($reason:ident),*) => {$({
            for reason in $reason::ALL {
                assert_eq!($reason::parse(reason.as_str()), Some(reason));
            }
            assert_eq!($reason::ALL[0], $reason::Unrecorded, "Unrecorded comes first");
            assert_eq!($reason::default(), $reason::Unrecorded);
            // The brief capped a list at eight. That cap is gone, and what
            // took its place is the rule it stood for: ONE list per resource,
            // out of the controller's words and the node's, with no stock
            // reasons in it — see `VmReason` and
            // `every_word_a_node_can_say_parses_into_the_reason_of_its_resource`.
            // A cap over a union of two vocabularies would have been a reason
            // to drop a word somebody writes.
            for reason in $reason::ALL {
                assert!(!reason.as_str().is_empty(), "every reason has a word");
                let (read, message) = $reason::read(reason.as_str(), None);
                assert_eq!(read, reason, "a word this binary knows reads as itself");
                assert_eq!(message, None, "and leaves the sentence alone");
            }
        })*};
    }

    #[test]
    fn every_reason_round_trips_through_its_word_and_starts_at_unrecorded() {
        assert_reasons_round_trip!(
            VmReason,
            VolumeReason,
            VolumeSnapshotReason,
            ImageReason,
            StoragePoolReason,
            RouterReason,
            VmMigrationReason
        );
    }

    fn at(secs: i64) -> DateTime<Utc> {
        DateTime::from_timestamp(1_800_000_000 + secs, 0).expect("an instant")
    }

    /// The whole of decision 1: four SIBLING fields, `phase` spelled exactly
    /// as it was before this change. A client that reads `status.phase` as a
    /// string goes on reading it as a string.
    #[test]
    fn the_wire_form_of_a_phase_is_four_sibling_fields() {
        let phase = VmPhase::new(
            VmPhaseKind::Pending,
            VmReason::Unplaced,
            Some("no candidate has room".into()),
            at(0),
        );
        assert_eq!(
            serde_json::to_value(&phase).expect("a phase serialises"),
            serde_json::json!({
                "phase": "Pending",
                "reason": "Unplaced",
                "message": "no candidate has room",
                "since": "2027-01-15T08:00:00Z",
            })
        );
    }

    /// A resting variant has no category behind it, so it carries no key —
    /// and neither does a reason nobody recorded. Both read back the same
    /// way, which is what makes the absence safe.
    #[test]
    fn a_variant_without_a_reason_and_an_unrecorded_one_both_carry_no_key() {
        let ready = VolumePhase::said(VolumePhaseKind::Ready, None, at(0));
        assert_eq!(ready.reason(), None);
        let wire = serde_json::to_value(&ready).expect("serialises");
        assert!(wire.get("reason").is_none(), "{wire}");
        assert!(wire.get("message").is_none(), "an empty message is absent");

        let pending = VolumePhase::of(VolumePhaseKind::Pending, at(0));
        assert_eq!(pending.reason(), Some(VolumeReason::Unrecorded));
        let wire = serde_json::to_value(&pending).expect("serialises");
        assert!(wire.get("reason").is_none(), "{wire}");
    }

    /// Reading is total, and this is the test that says so: none of these is
    /// an error, because one object written before struktur 4 must not break
    /// `list()`.
    #[test]
    fn nothing_a_stored_phase_can_say_is_a_read_error() {
        let read = |doc: serde_json::Value| {
            serde_json::from_value::<VmPhase>(doc).expect("never a read error")
        };

        // No reason at all — every object stored before this change.
        let bare = read(serde_json::json!({ "phase": "Pending" }));
        assert_eq!(bare.kind(), VmPhaseKind::Pending);
        assert_eq!(bare.reason(), Some(VmReason::Unrecorded));
        assert_eq!(bare.message(), None);

        // A word this binary does not have — a drifting peer, or a newer
        // controller's object read by an older one. Not an error, and not
        // dropped either: decision 2 of the derivation lane keeps the word at
        // the front of the sentence, because "I was told something I do not
        // understand" must not read as "nobody said anything".
        let drifted = read(
            serde_json::json!({ "phase": "Failed", "reason": "Ascended", "message": "it left" }),
        );
        assert_eq!(drifted.reason(), Some(VmReason::Unrecorded));
        assert_eq!(drifted.message(), Some("Ascended: it left"));
        let bare_drift = read(serde_json::json!({ "phase": "Failed", "reason": "Ascended" }));
        assert_eq!(bare_drift.message(), Some("Ascended"));

        // No phase either: the field has always been `#[serde(default)]`.
        assert_eq!(read(serde_json::json!({})).kind(), VmPhaseKind::Pending);

        // A reason on a variant that has no slot for one: dropped, not
        // refused.
        let resting = read(serde_json::json!({ "phase": "Running", "reason": "Refused" }));
        assert_eq!(resting.reason(), None);
    }

    /// A missing `since` is the moment of the read and not the epoch: an
    /// object that has never been stamped must not look like it has been
    /// stuck since 1970 (see `stuck`).
    #[test]
    fn a_phase_with_no_since_is_stamped_at_the_read() {
        let before = Utc::now();
        let read: VmPhase =
            serde_json::from_value(serde_json::json!({ "phase": "Running" })).expect("a phase");
        assert!(read.since() >= before && read.since() <= Utc::now());

        // And the other direction: an unstamped phase carries no key rather
        // than a 1970 nobody can read.
        let fresh = VmPhase::default();
        assert_eq!(fresh.since(), UNSTAMPED);
        let wire = serde_json::to_value(&fresh).expect("serialises");
        assert!(wire.get("since").is_none(), "{wire}");
    }

    /// Equivalent evidence must retain its established timestamp and avoid redundant status
    /// writes.
    #[test]
    fn a_write_that_does_not_change_the_word_does_not_move_the_stamp() {
        let mut status = VmStatus::default();
        assert_eq!(status.phase().since(), UNSTAMPED);

        // The first derivation is the first stamp, even onto the word the
        // object was born with.
        status.stamp(VmPhase::of(VmPhaseKind::Pending, UNSTAMPED), at(0));
        assert_eq!(status.phase().since(), at(0));

        // The same word again, later: the reason and the sentence move, the
        // stamp does not.
        status.stamp(
            VmPhase::new(
                VmPhaseKind::Pending,
                VmReason::Unplaced,
                Some("no candidate has room".into()),
                UNSTAMPED,
            ),
            at(600),
        );
        assert_eq!(status.phase().since(), at(0), "the word did not change");
        assert_eq!(status.phase().reason(), Some(VmReason::Unplaced));
        assert_eq!(status.phase().message(), Some("no candidate has room"));

        // A different word: the stamp is the moment of the change.
        status.stamp(VmPhase::of(VmPhaseKind::Running, UNSTAMPED), at(900));
        assert_eq!(status.phase().since(), at(900));

        // And a reason derived onto a resting word is dropped rather than
        // kept — so the value is stable under a second identical write,
        // which is what lets a caller compare against it as a churn guard.
        status.stamp(
            VmPhase::new(VmPhaseKind::Running, VmReason::Unplaced, None, UNSTAMPED),
            at(1200),
        );
        assert_eq!(status.phase().reason(), None);
        assert_eq!(status.phase().since(), at(900));
    }

    /// Every reasoned variant really does hold the reason it was given, and
    /// every resting one really does drop it. One loop over all eight VM
    /// phases, so a variant that changes shape fails here rather than in a
    /// reconciler.
    #[test]
    fn a_reason_survives_exactly_the_variants_that_have_a_slot_for_it() {
        for kind in VmPhaseKind::ALL {
            let phase = VmPhase::new(kind, VmReason::Refused, Some("because".into()), at(7));
            assert_eq!(phase.kind(), kind);
            assert_eq!(phase.since(), at(7));
            assert_eq!(
                phase.message(),
                Some("because"),
                "{kind:?} keeps the sentence"
            );
            match kind {
                VmPhaseKind::Running | VmPhaseKind::Stopped | VmPhaseKind::Paused => {
                    assert_eq!(phase.reason(), None, "{kind:?} is a resting state")
                }
                _ => assert_eq!(phase.reason(), Some(VmReason::Refused), "{kind:?}"),
            }
        }
    }

    /// Require controller reason enums to accept every node wire reason. Pools have
    /// controller-derived reasons and migrations carry typed outcomes, so neither has a proto
    /// reason list.
    #[test]
    fn every_word_a_node_can_say_parses_into_the_reason_of_its_resource() {
        macro_rules! assert_speaks {
            ($resource:literal, $words:expr, $reason:ident) => {{
                for word in $words {
                    assert!(
                        $reason::parse(word).is_some(),
                        "{} says {word:?} and {} cannot read it",
                        $resource,
                        stringify!($reason)
                    );
                    // And it survives the reader the status road uses, with
                    // the sentence untouched — an unknown word is the only
                    // case that rewrites one.
                    let (reason, message) = $reason::read(word, Some("said".into()));
                    assert_eq!(reason.as_str(), *word);
                    assert_eq!(message.as_deref(), Some("said"));
                }
            }};
        }
        assert_speaks!("Vm", proto::reasons::VM, VmReason);
        assert_speaks!("Volume", proto::reasons::VOLUME, VolumeReason);
        assert_speaks!("Snapshot", proto::reasons::SNAPSHOT, VolumeSnapshotReason);
        assert_speaks!("Image", proto::reasons::IMAGE, ImageReason);
        assert_speaks!("Router", proto::reasons::ROUTER, RouterReason);

        // The table's own shape, so that a sixth list added over there is a
        // failure here rather than a list nobody parses.
        assert_eq!(
            proto::reasons::ALL
                .iter()
                .map(|(resource, _)| *resource)
                .collect::<Vec<_>>(),
            ["Vm", "Volume", "Snapshot", "Image", "Router"]
        );
    }
}
