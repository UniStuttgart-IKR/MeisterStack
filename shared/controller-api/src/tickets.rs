// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Path-bound, single-use console tickets with a 30-second etcd lease.
//!
//! Browsers cannot attach an Authorization header to a WebSocket constructor.
//! An authenticated request therefore mints a short-lived ticket carrying the
//! caller's current grant. Redemption atomically deletes and returns the record,
//! so only one replica can accept it. Tickets expire even if unused.

use std::sync::Arc;
use std::time::Duration;

use tracing::warn;

use crate::auth::{Identity, Role};
use crate::object::Resource;
use crate::resources::{Ticket, TicketBearer, TicketSpec};
use crate::store::{EtcdStore, Result};

/// Lifetime of an unused ticket, enforced by its etcd lease.
pub const TICKET_TTL: Duration = Duration::from_secs(30);

/// What a redeemed ticket puts back on the request: the caller as they were
/// when they asked for it.
#[derive(Clone, Debug)]
pub struct Bearer {
    pub identity: Identity,
    pub role: Option<Role>,
    pub tenant: Option<String>,
}

/// The tickets this TIER has outstanding.
///
/// Not "this replica": that was the defect. See the module note.
pub struct Tickets {
    store: Arc<EtcdStore>,
}

impl Tickets {
    pub fn new(store: Arc<EtcdStore>) -> Self {
        Self { store }
    }

    /// Mint a path-bound, expiring ticket with the caller's existing grant.
    /// Use 31 random bytes encoded as 62 lowercase hex characters to fit the
    /// 63-byte resource-name limit.
    pub async fn mint(&self, bearer: Bearer, path: &str) -> Result<String> {
        use ring::rand::SecureRandom as _;
        let mut raw = [0u8; 31];
        // Fail if secure randomness is unavailable; never substitute a predictable token.
        ring::rand::SystemRandom::new()
            .fill(&mut raw)
            .expect("the system random generator");
        let token: String = raw.iter().map(|b| format!("{b:02x}")).collect();
        let object = Ticket::new(
            crate::resources::API_VERSION,
            Ticket::KIND,
            &token,
            TicketSpec {
                path: path.to_string(),
                bearer: TicketBearer {
                    name: bearer.identity.name,
                    groups: bearer.identity.groups,
                    role: bearer.role,
                    tenant: bearer.tenant,
                },
            },
        );
        // No sweep anywhere in this file: the lease is the expiry, and etcd
        // is what runs it.
        self.store
            .create_with_ttl(&object, TICKET_TTL.as_secs() as i64)
            .await?;
        Ok(token)
    }

    /// Redeem once for the exact path. Missing, spent, expired, mismatched and
    /// unreadable tickets all return None without exposing which condition failed.
    pub async fn redeem(&self, token: &str, path: &str) -> Option<Bearer> {
        // Atomically take before validation: even presentation on the wrong path
        // consumes the ticket, and another replica cannot redeem it again.
        let taken = match self.store.take::<Ticket>(token).await {
            Ok(taken) => taken,
            Err(e) => {
                warn!(error = %format!("{e:#}"), "reading a console ticket failed");
                return None;
            }
        };
        let ticket = taken?;
        if ticket.spec.path != path {
            return None;
        }
        // No expiry check here: the lease IS the expiry, so a ticket that is
        // too old is a key that is not there any more, and the take above has
        // already answered `None` for it.
        Some(Bearer {
            identity: Identity::new(ticket.spec.bearer.name, ticket.spec.bearer.groups),
            role: ticket.spec.bearer.role,
            tenant: ticket.spec.bearer.tenant,
        })
    }

    /// How many are outstanding. For the tests and for nothing else.
    pub async fn outstanding(&self) -> usize {
        self.store.list::<Ticket>().await.map_or(0, |t| t.len())
    }
}

/// Extract the first exact ticket query parameter without matching key suffixes.
pub fn from_query(query: Option<&str>) -> Option<&str> {
    query?
        .split('&')
        .find_map(|pair| pair.strip_prefix("ticket="))
        .filter(|t| !t.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_query_parameter_is_read_and_nothing_that_looks_like_it() {
        assert_eq!(from_query(Some("ticket=abc")), Some("abc"));
        assert_eq!(from_query(Some("lines=10&ticket=abc")), Some("abc"));
        assert_eq!(from_query(Some("myticket=abc")), None);
        assert_eq!(from_query(Some("ticket=")), None);
        assert_eq!(from_query(None), None);
    }

    /// Ticket storage uses strict camelCase spec fields and no status.
    #[test]
    fn a_stored_ticket_carries_the_path_and_the_caller_and_no_status() {
        let object = Ticket::new(
            crate::resources::API_VERSION,
            Ticket::KIND,
            &"ab".repeat(31),
            TicketSpec {
                path: "/apis/meister.io/v1/vms/web-1/console".into(),
                bearer: TicketBearer {
                    name: "alice".into(),
                    groups: vec![crate::auth::GROUP_MEMBERS.to_string()],
                    role: Some(Role::Member),
                    tenant: Some("acme".into()),
                },
            },
        );
        let doc = serde_json::to_value(&object).expect("a ticket serialises");
        assert_eq!(doc["kind"], "Ticket");
        assert_eq!(doc["spec"]["path"], "/apis/meister.io/v1/vms/web-1/console");
        assert_eq!(doc["spec"]["bearer"]["name"], "alice");
        assert_eq!(doc["spec"]["bearer"]["role"], "member");
        assert_eq!(doc["spec"]["bearer"]["tenant"], "acme");
        assert!(doc.get("status").is_none(), "a ticket observes nothing");

        // And back, because the redeem on the other replica is a decode.
        let back: Ticket = serde_json::from_value(doc).expect("and parses");
        assert_eq!(back.spec.bearer.groups, vec![crate::auth::GROUP_MEMBERS]);
        assert_eq!(back.spec.bearer.role, Some(Role::Member));
    }

    /// Minted hexadecimal tokens fit the store's lowercase name syntax and
    /// 63-character limit.
    #[test]
    fn a_token_is_a_name_this_store_accepts() {
        let token: String = (0u8..31).map(|b| format!("{b:02x}")).collect();
        assert_eq!(token.len(), 62);
        assert!(token.len() <= 63, "a name in this store is a dns label");
        assert!(
            token
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        );
        assert!(token.starts_with(|c: char| c.is_ascii_alphanumeric()));
        assert!(token.ends_with(|c: char| c.is_ascii_alphanumeric()));
    }
}
