// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! The `Event` kind: what happened, as an object with an expiry.
//! Moved out of `resources.rs` unchanged.

use super::*;

/// Normal or Warning, and Kubernetes' own two words for it.
///
/// The distinction earns its place: a dashboard and a person both want "show
/// me what went wrong" to be one filter rather than a list of reasons somebody
/// has to keep up to date.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub enum EventType {
    #[default]
    Normal,
    Warning,
}

impl EventType {
    pub fn as_str(self) -> &'static str {
        match self {
            EventType::Normal => "Normal",
            EventType::Warning => "Warning",
        }
    }
}

/// Something that happened to an object, kept for a while.
///
/// `VmStatus.message` holds exactly one sentence, so why a VM failed three
/// times and came up on the fourth was written down nowhere. This is the
/// record of the transitions themselves, cut to what is actually useful:
/// Kubernetes' shape without the fields nobody reads.
///
/// Three properties decide whether this is worth having at all, and all three
/// are enforced elsewhere rather than described here:
///
/// * **They expire.** Written through `EtcdStore::create_with_ttl`, so etcd
///   reaps them and nothing has to be alive for that to happen. Events
///   without an expiry fill a store and nobody ever tidies them.
/// * **They are aggregated.** The object's NAME is derived from what it is
///   about and why (see `events::name_of`), so the same thing happening
///   twenty times finds the object it made the first time and raises `count`.
/// * **They are made on CHANGE, never per pass.** That one is a property of
///   every call site: the reconcilers are level-triggered and re-derive
///   everything every few seconds, so an event per pass would be a store
///   filling at one write per VM per tick.
#[derive(Clone, Debug, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EventSpec {
    /// What this is about: the kind, the name a person calls it, and the uid
    /// that says WHICH one. The uid is in the name of the event object too —
    /// names get reused, and two VMs' histories must not merge because
    /// somebody recreated one under the same name.
    pub involved_kind: String,
    pub involved_name: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub involved_uid: String,
    /// A short CamelCase word, from a closed set (`events::reason`). What a
    /// filter matches on and what an aggregation groups by — so it may never
    /// carry a number, a name or a sentence, for the reason a metric label
    /// may not.
    pub reason: String,
    /// The sentence. This is where the numbers and the names go.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub message: String,
    #[serde(default)]
    pub event_type: EventType,
    /// Whose object this was about. Absent = unscoped, and then only an admin
    /// sees it — the same rule, and the same conservative direction, that an
    /// unscoped VM has.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant: Option<String>,
    #[serde(default)]
    pub count: u32,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
}

/// No finalizer, and no status: an event owns nothing, and there is nothing
/// about one that a controller observes afterwards.
pub type Event = Object<EventSpec, ()>;

// --- who may call, and on whose behalf --------------------------------------
//
// These three live at the cloud tier only, and that is the design decision
// rather than an omission: one directory, one truth. A cluster authenticates
// against the same CA and reads the role out of the certificate; it does not
// keep a second copy of the people.
