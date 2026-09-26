// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Record aggregated resource transitions with an etcd TTL.
//!
//! An event name identifies its subject and reason; repeated occurrences update
//! its count and last-seen time. The lease expires the record without a sweeper.
//! Callers must record changes, not every reconciliation pass.

use chrono::Utc;
use tracing::warn;

use crate::object::Resource;
use crate::resources::{Event, EventSpec, EventType};
use crate::store::{EtcdStore, StoreError};

/// Event retention from creation. Aggregation preserves this original lease.
pub const TTL_SECS: i64 = 3600;

/// Stable event reason keys. Names, counts and free-form details belong
/// in messages, since reason participates in filtering and aggregation.
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
    /// Migration phase transition recorded on the migration object.
    /// Guest-relevant outcomes may also produce VM events.
    pub const MIGRATING: &str = "Migrating";
    /// Router active-node change, including failover without a phase change.
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

/// Lowercase aggregation key from kind, UID (or name when UID is absent) and
/// reason. It separates recreated objects and lets repeated events find the
/// same record. Callers supply the resource identity and a bounded reason.
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

/// Best-effort event recording: log store errors without failing the
/// primary operation. Create the first occurrence, or aggregate when the
/// existing key reports AlreadyExists.
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
        // Increment count and update the latest message/time through CAS retry.
        // Preserve the original lease so repeated events do not extend retention.
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

/// Return all events for the object, across reasons, newest activity first.
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

/// List retained events, newest activity first. Store failure logs a warning
/// and returns an empty list so event availability does not block object access.
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

/// Additional event-list filters applied after tenant authorization.
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
    /// RFC 3339 lower bound for lastSeen. Clients convert relative durations
    /// to absolute instants using their own clock before requesting.
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

    /// Aggregation reasons use stable words; variable names, counts and explanations
    /// belong in the message so repeated occurrences share one key.
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
