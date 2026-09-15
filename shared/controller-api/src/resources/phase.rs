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

            /// The reason as it goes on a WIRE: the word, or the empty
            /// string for a variant that carries none and for `Unrecorded`.
            ///
            /// One function because the rule is one rule and it is applied in
            /// two dozen places: a relay to the tier above, the flat wire
            /// form, a metric label. `Unrecorded` travels as ABSENT — an
            /// object nobody recorded a reason for looks exactly as it did
            /// before the field existed, and reads back as `Unrecorded`,
            /// which is the same value. A tier that sent the word instead
            /// would turn "nobody said" into something a reader could match
            /// on.
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
                    reason: (!phase.reason_word().is_empty())
                        .then(|| phase.reason_word().to_string()),
                    message: phase.message().map(str::to_string),
                    since: (phase.since() != UNSTAMPED).then(|| phase.since()),
                }
            }
        }

        impl From<$wire> for $phase {
            /// Reading is TOTAL and that is the whole of decision 6: one
            /// object written before this field existed must not break
            /// `list()`. A missing reason reads as `Unrecorded`, a reason
            /// this binary does not know reads as `Unrecorded` WITH the word
            /// kept at the front of the sentence (decision 2 of the
            /// derivation lane), a missing `since` reads as the moment of the
            /// read.
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

            /// A word off a wire and the sentence it arrived with, read the
            /// honest way.
            ///
            /// The one reader for both wires a reason crosses: a stored
            /// object being decoded, and a status report from the tier below.
            /// Three cases, and only the third does anything:
            ///
            /// * an empty word is `Unrecorded` and the sentence is untouched
            ///   — a peer that predates the field said nothing, which is not
            ///   the same as saying something wrong.
            /// * a word this binary knows is itself.
            /// * a word it does NOT know is `Unrecorded`, and **the word is
            ///   rescued into the front of the sentence**.
            ///
            /// That last line is the whole of decision 2 and it replaces
            /// dropping the string. A word arrives that this tier cannot
            /// name in exactly two situations — a newer agent rolled out
            /// under an older controller, or a rename that only landed on one
            /// side — and both are a drift somebody has to see. Dropped, it
            /// showed up as an object with no reason at all, which reads as
            /// "nobody recorded one": the two states a control plane must
            /// never confuse are "I have nothing to say" and "I was told
            /// something I do not understand".
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

/// The one read path and the one write path for a stored phase.
///
/// Seven status structs, the same two methods, so they are generated here
/// beside the phase they hand out rather than seven times over. `assign` is
/// the interesting one: see its doc for the rule about `since`.
macro_rules! phased {
    ($( $status:ident / $phase:ident; )*) => { $(
        impl $status {
            /// What this tier says this object is doing, with the reason and
            /// the sentence that go with it.
            pub fn phase(&self) -> &$phase {
                &self.phase
            }

            /// Put a phase on this object — the ONE way the field moves.
            ///
            /// It exists to own a rule that every one of the sixty-odd
            /// assignments it replaced got wrong in the same way: **`since`
            /// belongs to the WORD, not to the write.** A status report
            /// arrives every ten seconds and says the same thing it said
            /// last time; a stamp taken at each of those would make
            /// "Running since" mean "last heard from", and the object's own
            /// churn guard would see a change where there was none. So the
            /// stored instant survives a write that does not change the
            /// kind.
            ///
            /// The exception is an object nobody has stamped at all
            /// ([`UNSTAMPED`]): its first assignment IS the first stamp,
            /// even when the word it lands on is the word it was born with.
            ///
            /// Deprecated from the day it was written, and that is the point.
            /// A phase is going to be DERIVED — `settle(now)` out of the spec
            /// and the facts in the status, at one place per resource — and
            /// until that exists every writer that still stamps a phase out
            /// of what its own code path happens to know carries
            /// `#[allow(deprecated)]`. So the list of them is a `grep`, the
            /// compiler keeps it honest, and the proof the round is finished
            /// is that this function can be deleted and everything still
            /// compiles.
            #[deprecated(note = "struktur 4: wird durch settle() ersetzt")]
            pub fn assign(&mut self, phase: $phase) {
                let at = phase.since();
                self.stamp(phase, at);
            }

            /// The derived phase, onto the object, with the stamp rule
            /// applied — the ONE place the field moves once `assign` is
            /// gone.
            ///
            /// `pub(super)`, so it is reachable from the `Resource::settle`
            /// implementations beside the resource table and from nowhere
            /// else in this workspace. That is what makes a phase a
            /// derivation rather than an assignment: there is no function a
            /// reconciler can call to put a word on an object.
            ///
            /// `now` is used only when the WORD changes. A derivation runs on
            /// every write — a status report arrives every ten seconds and
            /// says what it said last time — and a stamp taken per write
            /// would make "Running since" mean "last heard from" and turn
            /// every one of those reports into an etcd revision. The one
            /// exception is an object nobody has stamped at all
            /// ([`UNSTAMPED`]): its first derivation IS its first stamp, even
            /// onto the word it was born with.
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

    /// `since` belongs to the WORD, and this is the rule that says so.
    ///
    /// It is the anti-churn rule, and the cost of getting it wrong is the
    /// defect this whole round also fixes one field over (D-C7): a status
    /// report arrives every ten seconds saying what it said last time, and a
    /// stamp taken per write would turn "Running since" into "last heard
    /// from" and make every one of those reports an etcd revision.
    #[test]
    fn a_write_that_does_not_change_the_word_does_not_move_the_stamp() {
        let mut status = VmStatus::default();
        assert_eq!(status.phase().since(), UNSTAMPED);

        // The first assignment is the first stamp, even onto the word the
        // object was born with.
        #[allow(deprecated)]
        status.assign(VmPhase::of(VmPhaseKind::Pending, at(0)));
        assert_eq!(status.phase().since(), at(0));

        // The same word again, later: the reason and the sentence move, the
        // stamp does not.
        #[allow(deprecated)]
        status.assign(VmPhase::new(
            VmPhaseKind::Pending,
            VmReason::Unplaced,
            Some("no candidate has room".into()),
            at(600),
        ));
        assert_eq!(status.phase().since(), at(0), "the word did not change");
        assert_eq!(status.phase().reason(), Some(VmReason::Unplaced));
        assert_eq!(status.phase().message(), Some("no candidate has room"));

        // A different word: the stamp is the moment of the change.
        #[allow(deprecated)]
        status.assign(VmPhase::of(VmPhaseKind::Running, at(900)));
        assert_eq!(status.phase().since(), at(900));

        // And a reason assigned onto a resting word is dropped rather than
        // kept — so the value is stable under a second identical write,
        // which is what lets a caller compare against it as a churn guard.
        #[allow(deprecated)]
        status.assign(VmPhase::new(
            VmPhaseKind::Running,
            VmReason::Unplaced,
            None,
            at(1200),
        ));
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

    /// Every word a node can put on the wire is a word this tier can name —
    /// the other end of the agent's own
    /// `the_reason_table_is_the_list_in_the_round_report`, against the very
    /// same lists.
    ///
    /// This is the guard behind decision 1 of the derivation lane: there is
    /// ONE reason list per resource, and a phase that came up from a node
    /// carries the NODE's word rather than a generic "Reported". That only
    /// holds while both ends spell the words alike, and the failure mode
    /// without a test is quiet — the word parses as nothing, the object reads
    /// `Unrecorded`, and the only place it shows is a lab.
    ///
    /// Storage pools and migrations are absent from `proto::reasons` on
    /// purpose and so are absent here: a node reports drivers and never a
    /// pool, and a migration's word from below is a typed outcome in a field
    /// of its own.
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
