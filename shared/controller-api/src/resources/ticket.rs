// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Short-lived, single-use credentials scoped to one console URL.

use super::*;

/// Internal console ticket, keyed by its bearer token in metadata.name. A leased etcd entry
/// expires after thirty seconds and an atomic take permits one redemption across replicas.
/// Never expose this resource through REST discovery or listing.
#[derive(Clone, Debug, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TicketSpec {
    /// The one path this opens. A ticket for `web-1`'s console is not a
    /// ticket for `web-2`'s, and binding it here means the guard does not
    /// have to trust the query string about anything else.
    #[serde(default)]
    pub path: String,
    /// The caller as they were when they asked. Not a new permission: what a
    /// ticket carries is the permission its holder already had, frozen, so it
    /// can never open a door they could not have walked through themselves.
    #[serde(default)]
    pub bearer: TicketBearer,
}

/// Identity and role captured when the ticket is minted.
#[derive(Clone, Debug, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TicketBearer {
    #[serde(default)]
    pub name: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub groups: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<crate::auth::Role>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant: Option<String>,
}

pub type Ticket = Object<TicketSpec, ()>;
