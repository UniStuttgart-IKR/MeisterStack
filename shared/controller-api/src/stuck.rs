// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! No non-terminal state without a deadline.
//!
//! Decision 7 of struktur 4, and D-C1 is what asks for it: a node fell out of
//! the lab and nothing anywhere said so. The VMs on it went to
//! `Unknown { Silent }` — which is the honest phase and exactly right — and
//! then stood there for four and a half days with no event, no metric and no
//! line in any listing that distinguished them from a VM that went Unknown
//! nine seconds ago.
//!
//! What a deadline buys here is a NUMBER and a SENTENCE, and nothing else.
//! **Nothing is promoted.** `Unknown` never becomes `Failed`, however long it
//! stands — Silas' rule `unknown_needs_its_holder`, and the argument is on
//! `VmPhase::Unknown`: `Failed` is the phase the requeue curve acts on, so a
//! timer that promoted a silence would be this tier re-creating a guest
//! somewhere on the strength of no evidence at all. The eleven guests the
//! mini-chaos run found alive on manacor, twenty hours after their agent
//! died, are the reason.
//!
//! This file is the rule and its tests. The pass that reads it — one event on
//! crossing, one gauge `meister_phase_stuck{kind,phase,reason}` — is the
//! derivation lane's (D7).

use std::time::Duration;

use chrono::{DateTime, Utc};

/// A phase that means "nobody has placed this yet".
///
/// Five minutes, and it is the shortest of the three because it is the one
/// nothing outside this control plane is waiting on: placement is this tier's
/// own work, it happens on the reconcile tick, and a VM that has not been
/// placed after sixty ticks is not going to be placed by the sixty-first. The
/// chaos run's `S1` and `F13` both settle in seconds when they settle at all.
pub const STUCK_AFTER_PENDING: Duration = Duration::from_secs(5 * 60);

/// A phase that means "a machine has been told and is working".
///
/// Fifteen minutes, three times the placement budget, because what is being
/// waited on is somebody else's work on real hardware: a qcow2 being copied,
/// an LV being zeroed, a namespace being connected, a guest being started.
/// The longest legitimate one measured in the lab is an image fetch, and a
/// deadline that fired during a normal one would be an alarm that teaches
/// people to ignore alarms.
pub const STUCK_AFTER_PROVISIONING: Duration = Duration::from_secs(15 * 60);

/// A phase that means "nobody knows".
///
/// Ten minutes: twenty heartbeat timeouts, so it cannot fire on a session
/// that is merely reconnecting, and short enough that D-C1's four and a half
/// days would have been four and a half days of a raised gauge instead of
/// silence. Between the other two on purpose — a silence is more urgent than
/// a copy in flight and less urgent than a placement, because the thing it is
/// about may be perfectly fine and unreachable.
pub const STUCK_AFTER_UNKNOWN: Duration = Duration::from_secs(10 * 60);

/// How long a phase spelled `word` may stand before it is worth saying so, or
/// `None` for a word that may stand for ever.
///
/// Keyed off the WORD and not off a type, and that is what makes one function
/// serve all seven resources: the seven `XPhaseKind` enums share their
/// spellings by design (`as_str` at both tiers, in the proto, in the CLI), so
/// `Creating` on a snapshot and `Provisioning` on a volume are the same
/// statement about the same kind of wait.
///
/// The words with no deadline are the two ends of every one of these enums:
/// a resting state (`Ready`, `Running`, `Stopped`, `Paused`, `Active`,
/// `Standby`, `Succeeded`) has nothing in flight to be late, and `Failed` is
/// left out deliberately — it is the phase the requeue curve already acts on,
/// and a second deadline over the top of a backoff curve would be two things
/// shouting about one VM.
pub fn stuck_after(word: &str) -> Option<Duration> {
    match word {
        "Pending" => Some(STUCK_AFTER_PENDING),
        // One budget for every word that means "a machine is working on it",
        // whichever resource is saying it.
        "Provisioning" | "Creating" | "Preparing" | "Releasing" | "Receiving" => {
            Some(STUCK_AFTER_PROVISIONING)
        }
        "Unknown" => Some(STUCK_AFTER_UNKNOWN),
        _ => None,
    }
}

/// How far past its deadline this phase is, or `None` while it still has
/// time — or has no deadline at all.
///
/// `terminal` is the caller's answer from `XPhaseKind::is_terminal`, and it
/// comes first because it is the question that can make the rest moot: a
/// phase nothing is going to move again cannot be late for anything. It is
/// asked separately rather than derived from the word because it is a
/// JUDGEMENT about one resource — `Failed` is an end for an `Image` and a
/// backoff for a `Vm`, out of the same five letters.
///
/// The value is the OVERSHOOT and not the age, because that is what a
/// sentence needs: "Pending for 5m over its 5m budget" says something
/// "Pending for 10m" does not. Strictly positive when it is `Some`, so a
/// caller can print it without checking.
///
/// A `since` in the future — a clock stepped back by NTP, a report from a
/// machine whose clock is ahead — yields `None` rather than a huge number:
/// the same choice `heartbeat::expired` makes, and for the same reason.
pub fn stuck(
    terminal: bool,
    word: &str,
    since: DateTime<Utc>,
    now: DateTime<Utc>,
) -> Option<Duration> {
    if terminal {
        return None;
    }
    let budget = stuck_after(word)?;
    let age = now.signed_duration_since(since).to_std().ok()?;
    age.checked_sub(budget).filter(|over| !over.is_zero())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::resources::{
        ImagePhaseKind, RouterPhaseKind, StoragePoolPhaseKind, VmMigrationPhaseKind, VmPhaseKind,
        VolumePhaseKind, VolumeSnapshotPhaseKind,
    };

    fn at(secs: i64) -> DateTime<Utc> {
        DateTime::from_timestamp(1_800_000_000 + secs, 0).expect("an instant")
    }

    #[test]
    fn a_phase_is_late_only_after_its_own_budget_and_by_how_much() {
        let pending = |elapsed: i64| stuck(false, "Pending", at(0), at(elapsed));
        assert_eq!(pending(0), None, "a phase that has just changed");
        assert_eq!(pending(299), None, "one second inside the budget");
        assert_eq!(pending(300), None, "exactly at it is not past it");
        assert_eq!(
            pending(301),
            Some(Duration::from_secs(1)),
            "the overshoot and not the age"
        );
        assert_eq!(pending(3_600), Some(Duration::from_secs(3_300)));

        // The three budgets, each on a word that really carries it.
        assert_eq!(
            stuck(false, "Provisioning", at(0), at(301)),
            None,
            "a machine gets three times the placement budget"
        );
        assert_eq!(
            stuck(false, "Provisioning", at(0), at(901)),
            Some(Duration::from_secs(1))
        );
        assert_eq!(
            stuck(false, "Unknown", at(0), at(601)),
            Some(Duration::from_secs(1))
        );
        assert_eq!(stuck(false, "Unknown", at(0), at(600)), None);
    }

    /// The words that may stand for ever, and the one that is left out on
    /// purpose.
    #[test]
    fn a_resting_phase_and_a_failed_one_are_never_late() {
        for word in [
            "Ready",
            "Running",
            "Stopped",
            "Paused",
            "Active",
            "Standby",
            "Succeeded",
            "Quarantined",
            // Failed has the requeue curve; a second deadline over a backoff
            // would be two things shouting about one object.
            "Failed",
        ] {
            assert_eq!(stuck_after(word), None, "{word}");
            assert_eq!(stuck(false, word, at(0), at(86_400)), None, "{word}");
        }
        // And a word this binary does not have — a peer from the future —
        // carries no deadline rather than the shortest one.
        assert_eq!(stuck_after("Ascended"), None);
    }

    /// A terminal phase is not late for anything, whatever its word says.
    ///
    /// The half that matters is a `VmMigration`: `Preparing` carries the
    /// provisioning budget, and a migration that is `Succeeded` is done —
    /// asking the word alone would put a deadline on a record nobody is
    /// waiting for.
    #[test]
    fn nothing_that_has_come_to_rest_can_be_late() {
        assert_eq!(stuck(true, "Pending", at(0), at(86_400)), None);
        assert_eq!(stuck(true, "Unknown", at(0), at(86_400)), None);
        assert_eq!(
            stuck(false, "Unknown", at(0), at(86_400)),
            Some(Duration::from_secs(86_400 - 600)),
            "and the same phase that is NOT terminal is very late indeed"
        );
    }

    /// D-C1, as the number it would have been: `Unknown` since a Friday
    /// afternoon, read on the following Wednesday.
    #[test]
    fn the_node_that_fell_out_would_have_been_a_number() {
        let four_and_a_half_days = 4 * 86_400 + 43_200;
        let over = stuck(
            VmPhaseKind::Unknown.is_terminal(),
            VmPhaseKind::Unknown.as_str(),
            at(0),
            at(four_and_a_half_days),
        )
        .expect("very late");
        assert_eq!(over.as_secs(), four_and_a_half_days as u64 - 600);
        // Nothing here promotes it. The phase is still Unknown, and that is
        // `unknown_needs_its_holder`: only the node coming back replaces it.
        assert!(!VmPhaseKind::Unknown.is_stable());
    }

    /// A clock that went backwards makes a phase look young, not infinitely
    /// old — the same choice `heartbeat::expired` makes.
    #[test]
    fn a_since_in_the_future_is_not_late() {
        assert_eq!(stuck(false, "Pending", at(600), at(0)), None);
    }

    /// Every one of the seven enums answers `is_terminal`, and every word it
    /// calls terminal really has no deadline left over.
    ///
    /// The table rather than seven tests, because the property is one: a
    /// phase this stack has judged an END must not be able to come out of
    /// `stuck` as late. A variant added to any of these enums shows up here.
    #[test]
    fn every_terminal_word_is_out_of_reach_of_every_deadline() {
        let words: Vec<(bool, &'static str)> = VmPhaseKind::ALL
            .iter()
            .map(|k| (k.is_terminal(), k.as_str()))
            .chain(
                VolumePhaseKind::ALL
                    .iter()
                    .map(|k| (k.is_terminal(), k.as_str())),
            )
            .chain(
                VolumeSnapshotPhaseKind::ALL
                    .iter()
                    .map(|k| (k.is_terminal(), k.as_str())),
            )
            .chain(
                ImagePhaseKind::ALL
                    .iter()
                    .map(|k| (k.is_terminal(), k.as_str())),
            )
            .chain(
                StoragePoolPhaseKind::ALL
                    .iter()
                    .map(|k| (k.is_terminal(), k.as_str())),
            )
            .chain(
                RouterPhaseKind::ALL
                    .iter()
                    .map(|k| (k.is_terminal(), k.as_str())),
            )
            .chain(
                VmMigrationPhaseKind::ALL
                    .iter()
                    .map(|k| (k.is_terminal(), k.as_str())),
            )
            .collect();

        for (terminal, word) in &words {
            let late = stuck(*terminal, word, at(0), at(86_400));
            if *terminal {
                assert_eq!(late, None, "{word} is an end and cannot be late");
            }
        }

        // And the other direction, so the table cannot pass by having no
        // deadlines at all: at least one word of it really is late.
        assert!(
            words
                .iter()
                .any(|(t, w)| stuck(*t, w, at(0), at(86_400)).is_some())
        );
    }
}
