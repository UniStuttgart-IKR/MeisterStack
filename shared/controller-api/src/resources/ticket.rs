// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! The `Ticket` kind: one credential, for one URL, for thirty seconds, as an
//! object several replicas can share.

use super::*;

/// A console ticket, stored.
///
/// It is an object for one reason: it has to be redeemable exactly once by a
/// stack of replicas that share nothing but their etcd (Fremdsicht 6). The
/// token is `metadata.name`, so redeeming is a keyed take and not a search,
/// and the thirty seconds are an etcd lease rather than a field anybody has
/// to sweep.
///
/// Nothing serves this kind at REST and nothing ever should: a client that
/// could LIST tickets could read every outstanding credential of every other
/// client. Both tiers name it in their `NOT_SERVED` table, which is where a
/// row of `resources!` says so out loud.
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

/// Who minted the ticket, in the fields an `Identity` and a role are made of.
///
/// Flat and not the `Identity` type itself, because `Identity` is a runtime
/// value and this is a wire document: a stored shape that follows a type
/// nothing else serialises is a shape that changes when that type does.
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
