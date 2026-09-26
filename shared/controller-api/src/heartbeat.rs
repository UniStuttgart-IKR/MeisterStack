// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Shared heartbeat expiry policy for node and cluster peers.
//!
//! A stopped heartbeat establishes lost contact, not the termination of workloads
//! on the peer.

use chrono::{DateTime, Utc};

/// Shared peer-silence threshold. Reconciliation detects expiry on its next
/// pass, so detection latency also includes the reconciliation interval.
pub const HEARTBEAT_TIMEOUT_SECS: i64 = 30;

/// Treat absent or expired heartbeat evidence as disconnected, regardless of
/// whether a transport session still appears open.
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

    /// Signed elapsed time prevents a backward clock step from wrapping into an
    /// extremely old heartbeat.
    #[test]
    fn a_clock_that_went_backwards_does_not_expire_a_peer() {
        assert!(!expired(Some(at(60)), at(0)));
    }
}
