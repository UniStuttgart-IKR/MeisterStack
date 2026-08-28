// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! When a peer that has stopped talking counts as gone.
//!
//! Both tiers ask the same question about the tier below them — the cluster
//! about its nodes, the cloud about its clusters — and both answered it with
//! the same function and the same constant, written twice. It is the same
//! question: the peer reports on a fixed interval, and the only thing a dead
//! one leaves behind is a timestamp that stops moving.

use chrono::{DateTime, Utc};

/// How long a peer may stay silent before it counts as gone.
///
/// Both tiers report every 10s, so this tolerates two missed reports; with the
/// 5s reconcile tick a killed peer shows up as down within ~35s. One constant
/// because it is one SLA — the number that changes here is the number that has
/// to change at both tiers.
pub const HEARTBEAT_TIMEOUT_SECS: i64 = 30;

/// A peer that has not reported within the timeout is down, whatever its
/// session looks like.
///
/// No heartbeat at all counts as expired, and that is the case worth naming:
/// the object exists because somebody said Hello once, not because anybody is
/// running now. After a controller restart every peer is in exactly that
/// state, and treating it as alive would schedule onto nodes nobody has heard
/// from since before the restart.
pub fn expired(last: Option<DateTime<Utc>>, now: DateTime<Utc>) -> bool {
    match last {
        Some(hb) => now.signed_duration_since(hb).num_seconds() > HEARTBEAT_TIMEOUT_SECS,
        None => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(secs: i64) -> DateTime<Utc> {
        DateTime::from_timestamp(1_800_000_000 + secs, 0).unwrap()
    }

    #[test]
    fn a_heartbeat_expires_only_after_the_timeout() {
        assert!(!expired(Some(at(0)), at(HEARTBEAT_TIMEOUT_SECS)));
        assert!(expired(Some(at(0)), at(HEARTBEAT_TIMEOUT_SECS + 1)));
    }

    /// The object exists because someone said Hello once — that is not a
    /// reason to schedule onto it after a controller restart.
    #[test]
    fn a_peer_that_never_reported_is_expired() {
        assert!(expired(None, at(0)));
    }

    /// `signed_duration_since` goes negative rather than wrapping, so a clock
    /// that went backwards makes a peer look newer, not infinitely old. The
    /// alternative — an unsigned subtraction — would expire every peer on the
    /// node at once the first time NTP stepped the clock back.
    #[test]
    fn a_clock_that_went_backwards_does_not_expire_a_peer() {
        assert!(!expired(Some(at(60)), at(0)));
    }
}
