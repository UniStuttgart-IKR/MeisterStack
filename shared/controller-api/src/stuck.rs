// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Report resources that exceed phase-specific observation deadlines.
//!
//! Crossing a deadline emits an event and updates the
//! `meister_phase_stuck{kind,phase,reason}` gauge. It does not change the phase:
//! lost contact with a node cannot establish that its guest stopped or authorize
//! a replacement guest.

use std::collections::BTreeMap;
use std::time::Duration;

use chrono::{DateTime, Utc};

use crate::events::{self, Happening};
use crate::resources::EventType;
use crate::store::EtcdStore;

/// Diagnostic threshold for Pending resources awaiting placement or prerequisites.
pub const STUCK_AFTER_PENDING: Duration = Duration::from_secs(5 * 60);

/// Diagnostic threshold for provisioning work, allowing longer backend operations.
pub const STUCK_AFTER_PROVISIONING: Duration = Duration::from_secs(15 * 60);

/// Diagnostic threshold for prolonged Unknown state; this does not prove failure.
pub const STUCK_AFTER_UNKNOWN: Duration = Duration::from_secs(10 * 60);

/// Diagnostic phase deadline shared across resource kinds. Stable and
/// terminal phases have no deadline; Failed is handled by retry policy.
/// Exceeding a deadline does not change state or authorize cleanup.
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

/// Return positive time past the phase budget. Terminal phases, phases without
/// a deadline and timestamps in the future yield None. Resource-specific
/// terminal semantics come from the caller; a deadline never changes phase.
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

/// Phase facts consumed by the shared deadline checker, built by status.standing().
#[derive(Clone, Copy, Debug)]
pub struct Standing {
    /// `XPhaseKind::as_str`.
    pub word: &'static str,
    /// `XPhaseKind::is_terminal` — the judgement each enum makes for itself.
    pub terminal: bool,
    /// `XPhase::reason_word`: the closed word, or empty where the phase has
    /// no slot for one and where nobody recorded one.
    pub reason: &'static str,
    /// When the WORD last changed. Not when the object was last written —
    /// that is the difference this round's `stamp` rule exists to keep, and
    /// it is what makes "Unknown for four days" a number at all.
    pub since: DateTime<Utc>,
}

/// One object that has just crossed its deadline.
#[derive(Debug, PartialEq, Eq)]
pub struct Crossed {
    pub kind: &'static str,
    pub name: String,
    pub uid: String,
    pub tenant: Option<String>,
    pub word: &'static str,
    pub reason: &'static str,
    /// How far past the budget, at the pass that noticed.
    pub over: Duration,
}

impl Crossed {
    /// The sentence an operator reads. It names the overshoot rather than the
    /// age, because "5m over its 5m budget" says something "10m" does not.
    pub fn sentence(&self) -> String {
        let since = match self.reason {
            "" => String::new(),
            reason => format!(" ({reason})"),
        };
        format!(
            "{} has been {}{} for {}s longer than the {}s this phase is given; nothing here \
             will change it on account of that",
            self.name,
            self.word,
            since,
            self.over.as_secs(),
            stuck_after(self.word)
                .map(|b| b.as_secs())
                .unwrap_or_default()
        )
    }
}

/// Per-pass overdue counts for gauges and recent deadline crossings for
/// events. Rebuild counts each pass; emit edges only near the crossing.
#[derive(Default, Debug)]
pub struct Late {
    counted: BTreeMap<(&'static str, &'static str, &'static str), i64>,
    crossed: Vec<Crossed>,
}

/// Object identity and tenant context for deadline events and metrics.
pub struct About<'a> {
    pub kind: &'static str,
    pub name: &'a str,
    pub uid: &'a str,
    /// Whose object it is, which is who gets to read the event. `None` =
    /// unscoped, and then only an admin sees it.
    pub tenant: Option<&'a str>,
}

impl<'a> About<'a> {
    /// The identity out of the envelope, with the tenant off the spec.
    pub fn of<T: crate::object::Resource>(
        metadata: &'a crate::object::Metadata,
        tenant: Option<&'a str>,
    ) -> Self {
        Self {
            kind: T::KIND,
            name: &metadata.name,
            uid: &metadata.uid,
            tenant,
        }
    }
}

impl Late {
    /// Count an overdue object and record an event only when its overshoot
    /// is less than one pass interval. Missing the crossing window may lose
    /// the event; the current overdue gauge remains accurate.
    pub fn look(
        &mut self,
        about: About<'_>,
        standing: Standing,
        now: DateTime<Utc>,
        tick: Duration,
    ) {
        let Some(over) = stuck(standing.terminal, standing.word, standing.since, now) else {
            return;
        };
        *self
            .counted
            .entry((about.kind, standing.word, standing.reason))
            .or_default() += 1;
        if over < tick {
            self.crossed.push(Crossed {
                kind: about.kind,
                name: about.name.to_string(),
                uid: about.uid.to_string(),
                tenant: about.tenant.map(str::to_string),
                word: standing.word,
                reason: standing.reason,
                over,
            });
        }
    }

    /// The level, onto the gauge. Every pass, whether or not anything is
    /// late: `reset` first, so a cell nothing fills this time disappears.
    pub fn publish(&self) {
        let objects = telemetry::metrics::objects();
        objects.reset_stuck();
        for ((kind, word, reason), n) in &self.counted {
            objects.set_stuck(kind, word, reason, *n);
        }
    }

    /// The edges, as events. Warning, because a deadline crossed is something
    /// somebody has to look at — and the one thing it is NOT is a verdict
    /// about the object.
    pub async fn report(&self, store: &EtcdStore) {
        for crossed in &self.crossed {
            events::record(
                store,
                Happening {
                    kind: crossed.kind,
                    name: &crossed.name,
                    uid: &crossed.uid,
                    reason: events::reason::PHASE_STUCK,
                    message: crossed.sentence(),
                    event_type: EventType::Warning,
                    tenant: crossed.tenant.as_deref(),
                },
            )
            .await;
        }
    }

    /// What crossed, for a caller that wants to log it. Empty on nearly every
    /// pass, which is the state this whole file exists to tell apart from
    /// "nobody is looking".
    pub fn crossed(&self) -> &[Crossed] {
        &self.crossed
    }

    /// How many objects are late, over all kinds — one number for a log line.
    pub fn total(&self) -> i64 {
        self.counted.values().sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::resources::{
        ImagePhaseKind, RouterPhaseKind, StoragePoolPhaseKind, VmMigrationPhaseKind, VmPhaseKind,
        VolumePhaseKind, VolumeSnapshotPhaseKind,
    };

    fn about<'a>(kind: &'static str, name: &'a str) -> About<'a> {
        About {
            kind,
            name,
            uid: name,
            tenant: None,
        }
    }

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

    /// Terminal status has no deadline even if its phase word otherwise has one.
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

    /// Every terminal phase across resource kinds is excluded from stuck detection.
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

    /// Count currently overdue resources and emit events during the crossing window.
    /// Neither diagnostic changes the object's phase.
    #[test]
    fn a_deadline_is_a_level_and_an_edge_and_never_a_verdict() {
        let tick = Duration::from_secs(60);
        let silent = |since| Standing {
            word: VmPhaseKind::Unknown.as_str(),
            terminal: VmPhaseKind::Unknown.is_terminal(),
            reason: "Silent",
            since,
        };
        let budget = STUCK_AFTER_UNKNOWN.as_secs() as i64;

        // Inside the budget: nothing at all.
        let mut early = Late::default();
        early.look(about("Vm", "web-1"), silent(at(0)), at(budget), tick);
        assert_eq!(early.total(), 0);
        assert!(early.crossed().is_empty());

        // The pass that notices: counted AND reported.
        let mut crossing = Late::default();
        crossing.look(
            About {
                tenant: Some("acme"),
                ..about("Vm", "web-1")
            },
            silent(at(0)),
            at(budget + 30),
            tick,
        );
        assert_eq!(crossing.total(), 1);
        let [one] = crossing.crossed() else {
            panic!("exactly one crossing, got {:?}", crossing.crossed())
        };
        assert_eq!(one.word, "Unknown");
        assert_eq!(one.reason, "Silent");
        assert_eq!(one.over, Duration::from_secs(30));
        let said = one.sentence();
        assert!(said.contains("web-1") && said.contains("Unknown"), "{said}");
        assert!(said.contains("Silent"), "{said}");
        assert!(
            said.contains("nothing here will change it"),
            "the sentence says it is not a verdict: {said}"
        );

        // Every later pass: still counted, never reported again.
        for over in [tick.as_secs() as i64, 4 * 24 * 3600] {
            let mut later = Late::default();
            later.look(about("Vm", "web-1"), silent(at(0)), at(budget + over), tick);
            assert_eq!(later.total(), 1, "the level stands");
            assert!(
                later.crossed().is_empty(),
                "and the edge fired once, {over}s ago"
            );
        }
    }

    /// The gauge's labels are counts per (kind, phase, reason), so two VMs
    /// silent for the same reason are one series with a two in it — and a
    /// third late for another reason is its own.
    #[test]
    fn the_late_are_counted_by_kind_phase_and_reason() {
        let tick = Duration::from_secs(60);
        let standing = |word: &'static str, reason: &'static str| Standing {
            word,
            terminal: false,
            reason,
            since: at(0),
        };
        let mut late = Late::default();
        let now = at(STUCK_AFTER_UNKNOWN.as_secs() as i64 + 7 * 24 * 3600);
        for name in ["web-1", "web-2"] {
            late.look(about("Vm", name), standing("Unknown", "Silent"), now, tick);
        }
        late.look(
            about("Vm", "db-1"),
            standing("Pending", "Unplaced"),
            now,
            tick,
        );
        late.look(
            about("Volume", "data-1"),
            standing("Releasing", "HeldBy"),
            now,
            tick,
        );
        assert_eq!(late.total(), 4);
        // Nothing crossed in this pass: all four are days past their budget.
        assert!(late.crossed().is_empty());
    }
}
