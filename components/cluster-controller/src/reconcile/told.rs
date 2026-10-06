// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! What this replica told a node lately, so that a level-triggered pass which
//! reaches the same conclusion every time it runs does not send the same
//! command every time it runs (IKR-B74).
//!
//! A pass runs on every write to any VM. While one guest took its stop grace,
//! that was a `Stop` to its node every 85 ms and an `EnsureRouter` to every
//! gateway for every router, many times a second. Both commands are
//! idempotent, so saying them again is never wrong, only noise; this keeps
//! the repeat to once per [`RETELL_AFTER`].
//!
//! In memory and per replica on purpose: after a restart, or on the replica
//! that takes a session over, the first pass tells again, which is exactly
//! what an idempotent command is for. Entries older than [`RETELL_AFTER`] are
//! dropped on every write, so the memo holds at most what was said within it.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use controller_api::Lifecycle;
use controller_api::network::RouterPlan;

/// How long the same thing, said to the same node, stays said.
pub(crate) const RETELL_AFTER: Duration = Duration::from_secs(30);

/// One memo per kind of command, each keyed by the object's uid.
#[derive(Default)]
pub(crate) struct Told {
    lifecycle: Memo<LifecycleSaid>,
    routers: Memo<RouterPlan>,
}

/// A lifecycle command as it went down: to which node, which action, and for
/// which generation of the VM. Another node or a newer generation is news,
/// even with the same action.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct LifecycleSaid {
    pub(crate) node: String,
    pub(crate) action: Lifecycle,
    pub(crate) generation: u64,
}

impl Told {
    /// Whether exactly this went to the VM `uid` within [`RETELL_AFTER`].
    pub(crate) fn lifecycle_lately(&self, uid: &str, said: &LifecycleSaid) -> bool {
        self.lifecycle.said_lately(uid, said)
    }

    pub(crate) fn note_lifecycle(&self, uid: &str, said: LifecycleSaid) {
        self.lifecycle.note(uid, said);
    }

    /// Whether exactly this plan was carried down within [`RETELL_AFTER`].
    pub(crate) fn router_lately(&self, plan: &RouterPlan) -> bool {
        self.routers.said_lately(&plan.id, plan)
    }

    pub(crate) fn note_router(&self, plan: &RouterPlan) {
        self.routers.note(&plan.id, plan.clone());
    }

    /// Forget a router's plan, so the next pass carries it down whatever it is.
    pub(crate) fn forget_router(&self, uid: &str) {
        self.routers.forget(uid);
    }
}

/// The last thing said about each uid, and when.
struct Memo<T> {
    said: Mutex<HashMap<String, (T, Instant)>>,
}

impl<T> Default for Memo<T> {
    fn default() -> Self {
        Self {
            said: Mutex::new(HashMap::new()),
        }
    }
}

impl<T: PartialEq> Memo<T> {
    fn said_lately(&self, uid: &str, what: &T) -> bool {
        self.lock()
            .get(uid)
            .is_some_and(|(said, at)| said == what && at.elapsed() < RETELL_AFTER)
    }

    fn note(&self, uid: &str, what: T) {
        let mut said = self.lock();
        said.retain(|_, (_, at)| at.elapsed() < RETELL_AFTER);
        said.insert(uid.to_string(), (what, Instant::now()));
    }

    fn forget(&self, uid: &str) {
        self.lock().remove(uid);
    }

    /// The map, whatever a panicking holder left: a memo of what was said is
    /// as good after a poisoning as before, and at worst says something once more.
    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, (T, Instant)>> {
        self.said
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn said(node: &str, action: Lifecycle, generation: u64) -> LifecycleSaid {
        LifecycleSaid {
            node: node.into(),
            action,
            generation,
        }
    }

    /// The same action to the same VM is said once; another action, or
    /// another VM, is news.
    #[test]
    fn the_same_command_to_the_same_object_is_said_once_within_the_window() {
        let told = Told::default();
        let stop = said("agent-1", Lifecycle::Stop, 1);
        assert!(!told.lifecycle_lately("u-1", &stop));
        told.note_lifecycle("u-1", stop.clone());
        assert!(told.lifecycle_lately("u-1", &stop));
        assert!(!told.lifecycle_lately("u-1", &said("agent-1", Lifecycle::Start, 1)));
        assert!(!told.lifecycle_lately("u-2", &stop));
    }

    /// The same action for a newer generation, or to another node, is news.
    #[test]
    fn a_new_generation_or_another_node_is_news() {
        let told = Told::default();
        told.note_lifecycle("u-1", said("agent-1", Lifecycle::Stop, 1));
        assert!(!told.lifecycle_lately("u-1", &said("agent-1", Lifecycle::Stop, 2)));
        assert!(!told.lifecycle_lately("u-1", &said("agent-2", Lifecycle::Stop, 1)));
    }
}
