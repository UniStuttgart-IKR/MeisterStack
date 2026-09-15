// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! A phase that carries why it is what it is.
//!
//! Until this file a phase was one word and an assignment: whoever came past
//! the object last stamped it out of whatever their code path happened to
//! know, and the sentence beside it lived in a separate `status.message`
//! field that another writer could clear. The chaos-extrem run produced the
//! bill — a `StoragePool` pointer that stood on `Pending` for six minutes
//! and said nothing (D-C11), an `Image` on `Ready` whose file was never
//! looked at (F16), a node that fell out with nothing anywhere saying so
//! (D-C1).
//!
//! So a phase is a value with fields now: the word, the CATEGORY behind it,
//! the sentence, and since when. `Pending`, `Failed` and `Unknown` cannot be
//! built without a reason slot at all — the type is what enforces it rather
//! than a review.
//!
//! Two types per resource and not one, because the two answer different
//! questions. `XPhaseKind` is the word — `Copy`, comparable, the thing a
//! `match` branches on and a metric label carries, and it is exactly the enum
//! that used to be called `XPhase`. `XPhase` is the word WITH its evidence,
//! which is what the object stores.
//!
//! # Why a macro
//!
//! Seven resources, and the machinery is the same for all of them: a kind, a
//! data-carrying phase, the four getters, and the flat wire form. Written out
//! it is seven times ninety lines whose only differences are the variant
//! names — and seven places for the wire form to drift apart, which is the
//! defect this file exists to answer. The resource table (`resources!`) made
//! the same argument one file up. What stays hand-written is everything that
//! is a JUDGEMENT about one resource: `is_stable`, `is_final`, `is_terminal`
//! and the doc comments, because those are the sentences somebody has to be
//! able to disagree with.

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

/// Does this variant's field list carry a reason?
///
/// By ARITY, and the bindings are passed in rather than spelled here: a
/// `macro_rules` body writes identifiers in its own hygiene context, so a
/// bare `reason` in here would not be the `reason` the pattern at the
/// expansion site bound. Three fields is a reasoned variant, two is a
/// resting one, and any other number is a compile error — which is the check
/// this is for.
macro_rules! phase_reason_of {
    ($reason:ident, $message:ident, $since:ident) => {
        Some(*$reason)
    };
    ($message:ident, $since:ident) => {
        None
    };
}

/// Everything in this file writes seven copies of the same shape; this is the
/// shape. See the module comment for why it is a macro.
///
/// One invocation per resource, beside the resource it belongs to:
///
/// ```ignore
/// phases! {
///     /// Where a volume is in its own life.
///     VolumePhase / VolumePhaseKind / VolumeReason / VolumePhaseWire [5] {
///         /// Reserved, not yet placed on a node that can provision it.
///         Pending { reason, message, since } => "Pending",
///         /// The data exists.
///         Ready { message, since } => "Ready",
///     }
/// }
/// ```
///
/// The count in brackets is the length of `ALL`, spelled out rather than
/// counted: `ALL` keeps the `[Kind; N]` type it has always had — the tables
/// that walk it walk an array — and a wrong number is a compile error.
///
/// Every variant carries `message` and `since`. A message is EVIDENCE and not
/// a reason: a node reporting `Running` with "host rebooted" is saying
/// something, and a `Ready` variant that could not hold it would drop a
/// sentence this control plane used to show. `since` is on every variant
/// because "how long has it been like this" is a question about any of them
/// (see `stuck`).
macro_rules! phases {
    ($(
        $(#[$about:meta])*
        $phase:ident / $kind:ident / $reason:ident / $wire:ident [$count:literal] {
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

            /// The category behind the phase, or `None` on a variant that
            /// carries none (the resting states).
            ///
            /// The pattern binds every field of the variant, because it is the
            /// ARITY of that list that says which of the two shapes this
            /// variant is — see `phase_reason_of`. On a resting variant the
            /// bindings are then unused, which is the allow below and not a
            /// mistake.
            #[allow(unused_variables)]
            pub fn reason(&self) -> Option<$reason> {
                match self {
                    $( $phase::$variant { $($field,)* } => phase_reason_of!($($field),*), )*
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

        /// The flat form on the wire: `phase`, `reason`, `message` and
        /// `since` as SIBLINGS in the status, exactly where `phase` and
        /// `message` have always been.
        ///
        /// That is decision 1 of the brief and it is serde rather than a
        /// design concession: the CLI, Tofu, the UI and the chaos harness read
        /// `status.phase` as a string, and a tagged enum would have made every
        /// one of them read `status.phase.Pending.reason` instead. The status
        /// struct carries this through `#[serde(flatten)]`.
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
                    reason: phase
                        .reason()
                        .filter(|r| *r != <$reason>::Unrecorded)
                        .map(|r| r.as_str().to_string()),
                    message: phase.message().map(str::to_string),
                    since: (phase.since() != UNSTAMPED).then(|| phase.since()),
                }
            }
        }

        impl From<$wire> for $phase {
            /// Reading is TOTAL and that is the whole of decision 6: one
            /// object written before this field existed must not break
            /// `list()`. A missing reason reads as `Unrecorded`, a reason
            /// this binary does not know reads as `Unrecorded`, a missing
            /// `since` reads as the moment of the read.
            fn from(wire: $wire) -> Self {
                Self::new(
                    wire.phase,
                    wire.reason
                        .as_deref()
                        .and_then(<$reason>::parse)
                        .unwrap_or_default(),
                    wire.message,
                    wire.since.unwrap_or_else(Utc::now),
                )
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
        #[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
        pub enum $name {
            $( $(#[$variant_about])* $variant, )*
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
        }
    )* };
}

/// The instant a phase nobody has stamped carries.
///
/// A `DateTime<Utc>` has no `Default`, and a phase has to have one — every
/// status struct derives `Default` and the store decodes an absent status
/// into it. The epoch is the value that cannot be mistaken for an
/// observation, and it is SKIPPED on the way out: an object whose phase has
/// never been assigned carries no `since` at all rather than a 1970 nobody
/// can read.
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
            assert!($reason::ALL.len() <= 8, "at most eight reasons per resource");
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
        // controller's object read by an older one.
        let drifted = read(serde_json::json!({ "phase": "Failed", "reason": "Ascended" }));
        assert_eq!(drifted.reason(), Some(VmReason::Unrecorded));

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
}
