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
    lifecycle: Memo<Lifecycle>,
    routers: Memo<RouterPlan>,
}

impl Told {
    /// Whether `action` went to the VM `uid` within [`RETELL_AFTER`].
    pub(crate) fn lifecycle_lately(&self, uid: &str, action: Lifecycle) -> bool {
        self.lifecycle.said_lately(uid, &action)
    }

    pub(crate) fn note_lifecycle(&self, uid: &str, action: Lifecycle) {
        self.lifecycle.note(uid, action);
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

    /// The same action to the same VM is said once; another action, or
    /// another VM, is news.
    #[test]
    fn the_same_command_to_the_same_object_is_said_once_within_the_window() {
        let told = Told::default();
        assert!(!told.lifecycle_lately("u-1", Lifecycle::Stop));
        told.note_lifecycle("u-1", Lifecycle::Stop);
        assert!(told.lifecycle_lately("u-1", Lifecycle::Stop));
        assert!(!told.lifecycle_lately("u-1", Lifecycle::Start));
        assert!(!told.lifecycle_lately("u-2", Lifecycle::Stop));
    }
}
