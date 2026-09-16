// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Writing down what happened to an object.
//!
//! `VmStatus.message` holds one sentence, so "it failed three times and came
//! up on the fourth" was written down nowhere at all. This is the record of
//! the transitions, and it is only useful if three things hold. Two of them
//! live here; the third lives at every call site and is the one worth saying
//! out loud.
//!
//! **They expire.** Every event is written under an etcd lease, so etcd
//! deletes it and nothing has to be alive for that to happen — no sweeper
//! task, no reconcile pass, no partial cleanup after a crash. A control plane
//! that was down for two hours comes back to an event log that has already
//! tidied itself.
//!
//! **They are aggregated.** The object's NAME is derived from what it is
//! about and why, so the twentieth occurrence of the same thing finds the
//! object the first one made and raises `count` and `last_seen`. The window
//! is the TTL: once the object has expired, the next occurrence starts a new
//! one, which is the honest meaning of "recently, this happened N times".
//!
//! **They are made on CHANGE, never per pass.** Nothing here can enforce
//! that, because it is a property of where `record` is called from. The
//! reconcilers are level-triggered — every pass re-derives every decision
//! from the store and reaches the same conclusion — so an event per pass
//! would be one write per VM per tick, for ever. Every call site in this tree
//! sits inside a branch that has already established that something moved:
//! the CAS that bound a VM succeeded, the sentence on the object differs from
//! the one about to be written, the phase that arrived is not the phase that
//! was stored. The rule is written into the tests those call sites have.

use chrono::Utc;
use tracing::warn;

use crate::object::Resource;
use crate::resources::{Event, EventSpec, EventType};
use crate::store::{EtcdStore, StoreError};

/// How long an event stays readable.
///
/// One hour, and the number is a trade between two failures. Too short and
/// the record is gone before anybody looks at it — the whole point is being
/// able to ask afterwards why a VM failed three times. Too long and `count`
/// stops meaning anything: an object that has been aggregating for a week
/// says "this happened 4000 times" about a period nobody has in mind.
///
/// An hour is the span an operator is actually asking about when a VM will
/// not come up, and it bounds the store at "one object per (thing, reason)
/// that happened in the last hour" rather than at anything that grows.
pub const TTL_SECS: i64 = 3600;

/// The reasons, as a closed set.
///
/// Short CamelCase words, Kubernetes' own convention, and the rule that comes
/// with it is the one a metric label has: a reason is what a filter matches
/// and what an aggregation groups by, so it may never carry a number, a name
/// or a sentence. Those go in the message.
///
/// Constants rather than free strings because the aggregation key is built
/// from this: two spellings of the same reason are two objects that each
/// count half of what happened.
pub mod reason {
    /// A VM was bound to a node or a cluster.
    pub const SCHEDULED: &str = "Scheduled";
    /// And could not be. The message says which of the reasons.
    pub const FAILED_SCHEDULING: &str = "FailedScheduling";
    /// A binding was taken back — because a client asked for a reschedule, or
    /// because the node said it cannot serve this VM at all. The message says
    /// which, and in the second case it is the node's own sentence.
    pub const UNBOUND: &str = "Unbound";
    /// A create or an update was refused because the tenant is at its
    /// ceiling.
    pub const QUOTA_EXCEEDED: &str = "QuotaExceeded";
    /// The phase the tier below reports is not the one that was stored.
    pub const PHASE_CHANGED: &str = "PhaseChanged";
    /// A non-terminal phase that has stood longer than its budget — see
    /// `crate::stuck`. Recorded ONCE, when the deadline is crossed, and
    /// never a promotion: the object keeps the phase it had.
    pub const PHASE_STUCK: &str = "PhaseStuck";
    /// A peer's heartbeat stopped, or came back.
    pub const PEER_LOST: &str = "PeerLost";
    pub const PEER_READY: &str = "PeerReady";
    /// A live migration entered a phase. One event per phase, on the
    /// migration object itself and not on the VM — a VM's history is what
    /// happened to the guest, and the phases of a move belong to the record
    /// of that move. The two that also matter to the guest (it arrived; it
    /// did not) are written on the VM as `Scheduled` and as this.
    pub const MIGRATING: &str = "Migrating";
    /// A router's ACTIVE machine changed — the failover, as an event.
    ///
    /// Beside `PHASE_CHANGED` and not folded into it, because they are two
    /// different facts and only one of them is the one somebody is paged
    /// about: a router that goes Active→Active on a new machine has not
    /// changed phase at all, and that is exactly the moment a tenant's
    /// traffic moved. Without it the failover was in a log line on one
    /// replica and nowhere an operator reads.
    pub const ACTIVE_CHANGED: &str = "ActiveChanged";
}

/// What is being written down. Built by the caller, spent by `record`.
pub struct Happening<'a> {
    /// The kind of the object this is about, spelled as its envelope does.
    pub kind: &'a str,
    /// What a person calls it.
    pub name: &'a str,
    /// Which one it is. Names get reused; this is what keeps two VMs'
    /// histories from merging because somebody recreated one under the same
    /// name. Empty for an object that has no uid of its own to give.
    pub uid: &'a str,
    /// One of `reason`.
    pub reason: &'a str,
    pub message: String,
    pub event_type: EventType,
    /// Whose object it was about. `None` = unscoped, and then only an admin
    /// ever sees the event — the same rule an unscoped VM has.
    pub tenant: Option<&'a str>,
}

/// The aggregation key, as a name.
///
/// Deterministic in (kind, uid, reason) and in nothing else, which is what
/// makes the second occurrence find the first one's object with a plain `get`
/// instead of a scan. The uid is in it rather than the name for the reason
/// the field is: a VM deleted and recreated under the same name is a
/// different VM, and its history is its own.
///
/// Lowercased and joined with `-`, so the result is one path segment and
/// therefore a name the store accepts (`EtcdStore::check_name`). A uid is a
/// uuid and a reason is a CamelCase word, so neither can contain a slash.
pub fn name_of(kind: &str, uid: &str, name: &str, reason: &str) -> String {
    // The uid where there is one, the name where there is not — a Node has no
    // uid of its own in this control plane, and its name IS its identity.
    let identity = if uid.is_empty() { name } else { uid };
    format!(
        "{}-{}-{}",
        kind.to_lowercase(),
        identity.to_lowercase(),
        reason.to_lowercase()
    )
}

/// Write it down, or say nothing and carry on.
///
/// Never returns an error and never propagates one, and that is deliberate
/// rather than lazy: this is called from inside a reconcile pass and from
/// inside an API handler that is already refusing a request, and in both
/// places an event that could not be written must not become the reason the
/// real work failed. A store that will not take an event is degraded, not
/// broken — WARN, and the next occurrence tries again.
///
/// Create first and fall back to aggregating, rather than the other way
/// round: the first occurrence is the common case for a given key, and
/// `AlreadyExists` is exactly the signal that this has happened before.
pub async fn record(store: &EtcdStore, happening: Happening<'_>) {
    let now = Utc::now();
    let name = name_of(
        happening.kind,
        happening.uid,
        happening.name,
        happening.reason,
    );
    let event = Event::declare(
        &name,
        EventSpec {
            involved_kind: happening.kind.to_string(),
            involved_name: happening.name.to_string(),
            involved_uid: happening.uid.to_string(),
            reason: happening.reason.to_string(),
            message: happening.message.clone(),
            event_type: happening.event_type,
            tenant: happening.tenant.map(str::to_string),
            count: 1,
            first_seen: now,
            last_seen: now,
        },
    );

    match store.create_with_ttl(&event, TTL_SECS).await {
        Ok(_) => {}
        // It has happened before and the object is still inside its window:
        // raise the count and say when, and keep the sentence current — the
        // twentieth failure's message is the one worth reading, not the
        // first's.
        //
        // Through `mutate`, so two replicas noticing the same thing at once
        // both land. The put behind it keeps the key's lease (see
        // `EtcdStore::update`), so aggregating an event does not make it
        // permanent — the deadline stays the one the first occurrence set,
        // and a thing that goes on happening gets a fresh object afterwards.
        Err(StoreError::AlreadyExists(_)) => {
            let message = happening.message;
            if let Err(e) = store
                .mutate::<Event, _>(&name, |e| {
                    e.spec.count = e.spec.count.saturating_add(1);
                    e.spec.last_seen = now;
                    e.spec.message = message.clone();
                })
                .await
            {
                warn!(event = %name, error = format!("{e:#}"), "could not aggregate an event");
            }
        }
        Err(e) => warn!(event = %name, error = format!("{e:#}"), "could not record an event"),
    }
}

/// Every event about one object, newest activity first.
///
/// Filtered by the involved object rather than looked up by key: one object
/// has one event per reason, and what a person asking `vm events` wants is
/// all of them.
pub async fn about(store: &EtcdStore, kind: &str, uid: &str, name: &str) -> Vec<Event> {
    let mut all = all(store).await;
    all.retain(|e| {
        e.spec.involved_kind == kind
            && if uid.is_empty() {
                e.spec.involved_name == name
            } else {
                e.spec.involved_uid == uid
            }
    });
    all
}

/// Everything still inside its window, newest activity first.
///
/// A read that fails is an empty list and a warning rather than an error: an
/// event log is the one resource whose absence must not stop anybody from
/// looking at the objects it is about.
pub async fn all(store: &EtcdStore) -> Vec<Event> {
    let mut events = match store.list::<Event>().await {
        Ok(events) => events,
        Err(e) => {
            warn!(error = format!("{e:#}"), "could not read the event log");
            Vec::new()
        }
    };
    // By when it last happened, not by when it started: an old object that is
    // still going is the interesting one.
    events.sort_by(|a, b| b.spec.last_seen.cmp(&a.spec.last_seen));
    events
}

/// What a client may ask the event log to narrow to, beside the two filters
/// every listing has.
///
/// The log used to come back whole. The console filtered it in the browser
/// and said so on screen; a `curl` had nothing. All three of these are
/// FILTERS and none is a permission — the tenant door was already shut, once,
/// before this narrows anything.
#[derive(Debug, Default, serde::Deserialize)]
pub struct EventQuery {
    /// `involvedName=web-1`, matched against `spec.involvedName`.
    #[serde(default, rename = "involvedName")]
    pub involved_name: Option<String>,
    /// `kind=Vm`, matched against `spec.involvedKind`, case-insensitively —
    /// a person types `vm` and the API says `Vm`, and refusing that would be
    /// pedantry about a filter.
    #[serde(default)]
    pub kind: Option<String>,
    /// `since=2026-09-09T06:00:00Z`, RFC 3339, matched against
    /// `spec.lastSeen`.
    ///
    /// An absolute instant and not a duration, deliberately: "the last hour"
    /// is a question about the CLIENT's clock, and a server that answered it
    /// would be answering with its own. The CLI turns `--since 1h` into an
    /// instant before it asks.
    #[serde(default)]
    pub since: Option<String>,
}

impl EventQuery {
    /// The floor, parsed once for the whole listing.
    pub fn since(&self) -> Result<Option<chrono::DateTime<Utc>>, crate::rest::ApiError> {
        let Some(raw) = self
            .since
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        else {
            return Ok(None);
        };
        chrono::DateTime::parse_from_rfc3339(raw)
            .map(|t| Some(t.with_timezone(&Utc)))
            .map_err(|e| {
                crate::rest::invalid_field(
                    "since",
                    format!("since={raw:?} is not an RFC 3339 instant: {e}"),
                )
            })
    }

    /// Does this event survive the narrowing? `since` is passed in rather
    /// than reparsed, because it is one answer for the whole list.
    pub fn selects(&self, event: &Event, since: Option<chrono::DateTime<Utc>>) -> bool {
        self.involved_name
            .as_deref()
            .is_none_or(|name| event.spec.involved_name == name)
            && self
                .kind
                .as_deref()
                .is_none_or(|kind| event.spec.involved_kind.eq_ignore_ascii_case(kind))
            && since.is_none_or(|floor| event.spec.last_seen >= floor)
    }
}

/// The kind an event is about, for the callers that hold a typed object.
pub fn kind_of<T: Resource>() -> &'static str {
    T::KIND
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The three narrowings, and the one that is a refusal rather than a
    /// filter: a `since` that is not an instant is a mistake in the request
    /// and answering it with an empty list would hide it.
    #[test]
    fn the_event_log_narrows_to_one_object_and_one_window() {
        let at = |minutes: i64| Utc::now() - chrono::Duration::minutes(minutes);
        let event = |kind: &str, name: &str, minutes: i64| {
            let mut e = Event::declare(
                "e",
                EventSpec {
                    involved_kind: kind.into(),
                    involved_name: name.into(),
                    reason: "Scheduled".into(),
                    first_seen: at(minutes),
                    last_seen: at(minutes),
                    ..Default::default()
                },
            );
            e.metadata.uid = format!("{kind}-{name}");
            e
        };
        // Through serde rather than by hand, so the wire NAMES are covered
        // too: `involvedName` is what a client sends and the field is
        // `involved_name`.
        let query = |doc: serde_json::Value| -> EventQuery {
            serde_json::from_value(doc).expect("a query")
        };

        let web = event("Vm", "web-1", 5);
        let db = event("Vm", "db-1", 5);
        let old = event("Vm", "web-1", 300);
        let volume = event("Volume", "web-1", 5);

        let name = query(serde_json::json!({"involvedName": "web-1"}));
        assert!(name.selects(&web, None));
        assert!(!name.selects(&db, None));
        assert!(name.selects(&volume, None), "a name, whatever kind it is");

        // A person types `vm`, the API says `Vm`, and refusing that would be
        // pedantry about a filter.
        let kind = query(serde_json::json!({"kind": "vm", "involvedName": "web-1"}));
        assert!(kind.selects(&web, None));
        assert!(!kind.selects(&volume, None));

        let window = query(serde_json::json!({"since": "2020-01-01T00:00:00Z"}));
        let floor = Some(at(60));
        assert!(window.selects(&web, floor));
        assert!(!window.selects(&old, floor), "older than the window");

        // What the handler passes in, out of the query it was given.
        assert_eq!(
            query(serde_json::json!({"since": "2020-01-01T00:00:00Z"}))
                .since()
                .unwrap(),
            Some(
                chrono::DateTime::parse_from_rfc3339("2020-01-01T00:00:00Z")
                    .unwrap()
                    .with_timezone(&Utc)
            )
        );
        assert!(query(serde_json::json!({})).since().unwrap().is_none());
        let refused = query(serde_json::json!({"since": "yesterday"}))
            .since()
            .expect_err("not an instant");
        assert_eq!(
            refused.status(),
            axum::http::StatusCode::UNPROCESSABLE_ENTITY
        );
        assert_eq!(refused.field(), Some("since"));
    }

    /// The aggregation key, and the two things it has to separate. Same
    /// object and same reason is one row; a different reason or a different
    /// object is another.
    #[test]
    fn the_name_is_what_makes_the_second_occurrence_find_the_first() {
        let a = name_of(
            "Vm",
            "11111111-1111-1111-1111-111111111111",
            "web",
            "Scheduled",
        );
        let again = name_of(
            "Vm",
            "11111111-1111-1111-1111-111111111111",
            "web",
            "Scheduled",
        );
        assert_eq!(a, again, "the same thing twice is one object");

        let other_reason = name_of(
            "Vm",
            "11111111-1111-1111-1111-111111111111",
            "web",
            "FailedScheduling",
        );
        assert_ne!(a, other_reason);

        // A VM deleted and recreated under the same name is a different VM,
        // and its history is its own.
        let reborn = name_of(
            "Vm",
            "22222222-2222-2222-2222-222222222222",
            "web",
            "Scheduled",
        );
        assert_ne!(a, reborn, "the uid and not the name is the identity");

        // An object with no uid of its own — a Node — is identified by name,
        // which is what its identity actually is here.
        let node = name_of("Node", "", "manacor", "PeerLost");
        assert_eq!(node, "node-manacor-peerlost");

        // And the result is one path segment, so the store takes it.
        for name in [a, other_reason, node] {
            assert!(!name.contains('/'), "{name}");
            assert_ne!(name, ".");
            assert_ne!(name, "..");
        }
    }

    /// The reasons are the closed set the aggregation key is built from, so
    /// two spellings of one reason would be two objects each counting half.
    /// They carry no number, no name and no sentence — those go in the
    /// message, for the reason a metric label carries none.
    #[test]
    fn a_reason_is_a_word_and_never_a_sentence() {
        for word in [
            reason::SCHEDULED,
            reason::FAILED_SCHEDULING,
            reason::UNBOUND,
            reason::QUOTA_EXCEEDED,
            reason::PHASE_CHANGED,
            reason::PEER_LOST,
            reason::PEER_READY,
        ] {
            assert!(!word.contains(' '), "{word}");
            assert!(!word.is_empty());
            assert!(
                word.chars().all(|c| c.is_ascii_alphabetic()),
                "{word} is not a bare CamelCase word"
            );
        }
    }

    /// An hour, and why it is not longer: `count` means "this often, lately",
    /// and a window nobody has in mind makes the number meaningless.
    #[test]
    fn the_window_is_the_one_an_operator_is_asking_about() {
        assert_eq!(TTL_SECS, 3600);
    }
}
