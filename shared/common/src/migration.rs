// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! The one sentence a source node and a cluster controller both have to read.
//!
//! ## Why a constant and not a proto field
//!
//! A failed `MigrateOut` comes back as an error STRING — that is the shape of
//! a command answer on the session, and giving migration its own typed
//! outcome is a `shared/proto` change. Until there is one, the two tiers have
//! to agree on how the source says the one thing that is not ambiguous, and
//! agreeing on it in one place beats each side spelling it out for itself.

/// The source's word that the transfer ended and the guest stayed.
///
/// # Why this sentence is different from every other failure
///
/// From the moment `MigrateOut` has gone out, an error normally says nothing
/// about which machine holds the guest: a command that timed out is the
/// sharpest case, because a source stops answering exactly when its VMM
/// exited, which is what SUCCESS looks like. That is why the send's error
/// path records the reason and waits for the destination rather than tearing
/// anything down.
///
/// This one answer is not like that. cloud-hypervisor hands the guest back on
/// a failed send, the source watched it happen and is serving the guest
/// again, and it says so while the transfer is seconds old. Waiting out the
/// transfer timeout on top of that is waiting for a question that has been
/// answered.
///
/// Round 4's e2e measured the cost: three migrations of `fabric-probe` sat in
/// `Running` carrying this very sentence as their note, ninety seconds on and
/// with ten minutes to go, over a guest that had never stopped running on the
/// source.
pub const GUEST_NOT_GIVEN_UP: &str = "The guest was not given up";

/// Whether a failed `MigrateOut` is the source saying the guest stayed here.
///
/// A `contains` and not an equality, because the answer travels wrapped: the
/// agent's own prefix goes on at the session edge and a forwarding replica
/// adds its own before that, so what a reconciler reads is
/// `the replica at … answered 503 …: agent agent-1a rejected command: vm … .
/// The guest was not given up`.
pub fn guest_stayed(error: &str) -> bool {
    error.contains(GUEST_NOT_GIVEN_UP)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The wrapping this has to survive, as the lab produced it — agent
    /// prefix, forwarding replica, http status and all.
    #[test]
    fn the_sentence_survives_every_wrapper_the_lab_put_around_it() {
        let from_the_lab = "the source's answer did not come back: the replica at \
             10.128.1.104:3001 answered 503 Service Unavailable: agent agent-1a rejected \
             command: vm 6da35260-9ef6-4b05-bf0b-2d744a2db285 is still running here 0s after \
             the send to tcp:10.128.1.107:49000 started: cloud-hypervisor is serving the guest \
             here again, so the transfer ended without it leaving. The guest was not given up";
        assert!(guest_stayed(from_the_lab));
    }

    /// And the failures that are still ambiguous must not be read as this
    /// one: a timeout is what SUCCESS looks like from the source's side.
    #[test]
    fn an_ambiguous_failure_is_not_this_answer() {
        assert!(!guest_stayed("node agent-1a has no active session"));
        assert!(!guest_stayed("deadline has elapsed"));
        assert!(!guest_stayed("connection reset by peer"));
    }
}
