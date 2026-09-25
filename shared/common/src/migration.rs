// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Migration capability negotiation and legacy diagnostic matching.
//!
//! The attempt protocol requires matching VM and migration IDs on commands and
//! reports. The legacy error-string matcher remains available, but its result
//! is not migration outcome evidence and must not authorize cleanup or repair.
//! See `docs/MIGRATION.md` for the ownership contract.

/// Legacy diagnostic text emitted for a failed send.
///
/// Matching this text does not establish source ownership. Cleanup and repair
/// require durable evidence tied to the VM incarnation and migration attempt.
pub const GUEST_NOT_GIVEN_UP: &str = "The guest was not given up";

/// Both endpoints must advertise this before any migration is prepared.
pub const ATTEMPT_PROTOCOL: &str = "migration/attempt-v2";

/// Match the legacy diagnostic through any agent or forwarding prefixes.
/// This is a text classifier, not migration outcome evidence.
pub fn guest_stayed(error: &str) -> bool {
    error.contains(GUEST_NOT_GIVEN_UP)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Recognize the diagnostic after agent and forwarding prefixes are added.
    #[test]
    fn the_sentence_survives_every_wrapper_the_lab_put_around_it() {
        let from_the_lab = "the source's answer did not come back: the replica at \
             10.128.1.104:3001 answered 503 Service Unavailable: agent agent-1a rejected \
             command: vm 6da35260-9ef6-4b05-bf0b-2d744a2db285 is still running here 0s after \
             the send to tcp:10.128.1.107:49000 started: cloud-hypervisor is serving the guest \
             here again, so the transfer ended without it leaving. The guest was not given up";
        assert!(guest_stayed(from_the_lab));
    }

    // Unrelated session failures must not match the legacy diagnostic.
    #[test]
    fn an_ambiguous_failure_is_not_this_answer() {
        assert!(!guest_stayed("node agent-1a has no active session"));
        assert!(!guest_stayed("deadline has elapsed"));
        assert!(!guest_stayed("connection reset by peer"));
    }
}
