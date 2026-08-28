// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Where a session loop dials next, and how long it waits before it starts
//! the order over.
//!
//! Both tiers dial out: an agent to its cluster-controller replicas, a
//! cluster-controller to its cloud replicas. The two sessions are different
//! protocols and stay apart — different messages, different dispatch,
//! different reasons to end. What is not different is the schedule around
//! them, and it was written twice: hash the endpoint list into a preference
//! order, dial the current entry, walk to the next one when a session ends,
//! and wait only once the whole order has refused.
//!
//! That schedule is pure and has no generics in it, which is why this is the
//! part worth sharing. It also means the rule the ha-cloud report asked for —
//! reset the backoff on an established Hello, not on a clean end — is
//! testable, which it was not while it lived inline in two loops.
//!
//! Sleeping is the caller's: `ended` hands back a duration rather than
//! waiting, so this module needs no runtime and no dependency.

use std::time::Duration;

use crate::hrw;

/// The first delay, and the one every reset returns to.
const BASE_BACKOFF: Duration = Duration::from_millis(500);
/// Where the doubling stops. Long enough that a whole control plane being
/// down costs nothing to wait for, short enough that its return is noticed
/// within half a minute.
const MAX_BACKOFF: Duration = Duration::from_secs(30);

#[derive(Debug)]
pub struct Redial {
    order: Vec<String>,
    position: usize,
    backoff: Duration,
}

impl Redial {
    /// The preference order for `id` over `endpoints`, by rendezvous hashing:
    /// every dialler derives its own, so the replicas need no registry of who
    /// serves whom and no agreement with each other about it. Computed once —
    /// the list does not change while the process runs.
    ///
    /// Panics on an empty endpoint list: a loop with nowhere to dial is a
    /// configuration error the caller has to catch before starting one (both
    /// callers do — the agent runs standalone, the cluster skips the task).
    pub fn new(id: &str, endpoints: &[String]) -> Self {
        assert!(
            !endpoints.is_empty(),
            "a redial schedule needs at least one endpoint"
        );
        Self {
            order: hrw::preference_order(id, endpoints),
            position: 0,
            backoff: BASE_BACKOFF,
        }
    }

    /// Where to dial now.
    pub fn endpoint(&self) -> &str {
        &self.order[self.position]
    }

    /// How far down the order this dialler has drifted, and how long the
    /// order is — both only ever used for the log line that says so.
    pub fn position(&self) -> (usize, usize) {
        (self.position, self.order.len())
    }

    /// The entries this dialler passed over to get where it is: the ones it
    /// would rather be on. Empty when it is on its favourite, which is what
    /// lets a caller skip the rehome probe entirely.
    pub fn ahead(&self) -> &[String] {
        &self.order[..self.position]
    }

    /// A session ended. `established` is whether it got as far as a Hello.
    ///
    /// Returns how long to wait before the next dial; `None` means dial the
    /// next endpoint at once. A replica that is merely dead should cost one
    /// redial, not a backoff — the whole point of knowing the others is not
    /// waiting for the one that died. Once the whole order has refused,
    /// nobody is there and waiting is the right answer.
    ///
    /// The reset is on `established` and not on a clean end, because the
    /// backoff is about not finding anybody: a session that said Hello found
    /// somebody, and however it ended afterwards, the next outage should not
    /// start on the delay the last one climbed to.
    pub fn ended(&mut self, established: bool) -> Option<Duration> {
        if established {
            self.backoff = BASE_BACKOFF;
        }
        self.position += 1;
        if self.position < self.order.len() {
            return None;
        }
        self.position = 0;
        let wait = self.backoff;
        self.backoff = (self.backoff * 2).min(MAX_BACKOFF);
        Some(wait)
    }

    /// Back to the top of the order, without a wait and without advancing:
    /// a better-ranked replica answered and the session is being given up
    /// FOR it, not because of it.
    ///
    /// Resets the backoff for the same reason `ended(true)` does, and more
    /// plainly: a rehome only happens because a probe reached somebody.
    pub fn rehome(&mut self) {
        self.position = 0;
        self.backoff = BASE_BACKOFF;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn endpoints(n: usize) -> Vec<String> {
        (0..n).map(|i| format!("http://r{i}:50051")).collect()
    }

    /// One endpoint: every ended session is the whole order refusing, so
    /// every one of them waits, and the wait doubles to the cap.
    #[test]
    fn a_lone_endpoint_waits_after_every_failure_and_the_wait_doubles() {
        let mut r = Redial::new("node-a", &endpoints(1));
        let waits: Vec<Duration> = (0..8)
            .map(|_| r.ended(false).expect("always waits"))
            .collect();
        assert_eq!(waits[0], BASE_BACKOFF);
        assert_eq!(waits[1], BASE_BACKOFF * 2);
        assert_eq!(waits[2], BASE_BACKOFF * 4);
        assert_eq!(
            *waits.last().unwrap(),
            MAX_BACKOFF,
            "and it stops at the cap"
        );
        assert!(
            waits.windows(2).all(|w| w[1] >= w[0]),
            "never goes backwards"
        );
    }

    /// Three endpoints, none of them there: two instant redials, then one
    /// wait. The dead replicas cost a dial each, not a backoff each.
    #[test]
    fn a_dead_replica_costs_one_redial_and_the_wait_comes_after_the_last() {
        let mut r = Redial::new("node-a", &endpoints(3));
        assert_eq!(r.ended(false), None);
        assert_eq!(r.ended(false), None);
        assert_eq!(r.ended(false), Some(BASE_BACKOFF), "the order is exhausted");
        // and it starts over from the favourite
        assert_eq!(r.position(), (0, 3));
    }

    /// The rule the ha-cloud report asked for. A session that said Hello
    /// found somebody; a failure hours ago must not decide how long this one
    /// takes to heal.
    #[test]
    fn an_established_session_resets_the_backoff_however_it_ended() {
        let mut r = Redial::new("node-a", &endpoints(1));
        for _ in 0..5 {
            r.ended(false);
        }
        // deep in the backoff, then a session that reached its Hello
        assert_eq!(r.ended(true), Some(BASE_BACKOFF));
        // and the next failure starts the curve over rather than resuming it
        assert_eq!(r.ended(false), Some(BASE_BACKOFF * 2));
    }

    /// The half that keeps the reset honest: a dial that never reached a
    /// Hello leaves the curve where it was.
    #[test]
    fn a_session_that_never_said_hello_does_not_reset_anything() {
        let mut r = Redial::new("node-a", &endpoints(1));
        r.ended(false);
        r.ended(false);
        assert_eq!(r.ended(false), Some(BASE_BACKOFF * 4));
    }

    /// A rehome is not a failure: it does not advance, does not wait, and the
    /// backoff it leaves behind is whatever the established session reset it
    /// to.
    #[test]
    fn a_rehome_goes_back_to_the_favourite_without_waiting() {
        let mut r = Redial::new("cluster-a", &endpoints(3));
        r.ended(false);
        r.ended(false);
        assert_eq!(r.position().0, 2);
        assert_eq!(r.ahead().len(), 2, "two entries it would rather be on");
        r.rehome();
        assert_eq!(r.position(), (0, 3));
        assert!(
            r.ahead().is_empty(),
            "on its favourite, nothing to probe for"
        );
    }

    /// A rehome only happens because a probe reached somebody, so it resets
    /// the curve as plainly as an established session does.
    #[test]
    fn a_rehome_resets_the_backoff() {
        let mut r = Redial::new("cluster-a", &endpoints(1));
        r.ended(false);
        r.ended(false);
        r.rehome();
        assert_eq!(r.ended(false), Some(BASE_BACKOFF));
    }

    /// The order is this dialler's own and stable across restarts — the whole
    /// point of hashing it rather than agreeing on it. (`hrw` is where the
    /// distribution itself is tested.)
    #[test]
    fn the_order_is_a_permutation_of_the_endpoints_and_is_stable() {
        let eps = endpoints(4);
        let once = Redial::new("node-a", &eps);
        let twice = Redial::new("node-a", &eps);
        assert_eq!(once.order, twice.order);
        let mut sorted = once.order.clone();
        sorted.sort();
        let mut expected = eps.clone();
        expected.sort();
        assert_eq!(sorted, expected, "every endpoint appears exactly once");
        // and a different dialler generally gets a different favourite
        let other = Redial::new("node-b", &eps);
        assert_eq!(other.order.len(), 4);
    }

    /// `ahead` is what the cluster probes for a better replica; it must never
    /// contain the endpoint currently being used, or a rehome would give up a
    /// healthy session for itself.
    #[test]
    fn ahead_never_contains_the_current_endpoint() {
        let mut r = Redial::new("cluster-a", &endpoints(4));
        for _ in 0..3 {
            assert!(!r.ahead().contains(&r.endpoint().to_string()));
            r.ended(false);
        }
    }
}
