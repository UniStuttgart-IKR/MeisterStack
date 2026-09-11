// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! One credential, for one URL, for thirty seconds.
//!
//! It exists for exactly one reason and should exist for no other: a browser
//! opening a `WebSocket` cannot set an `Authorization` header. The API is
//! `new WebSocket(url)` and that is all of it — no headers, no body, no
//! options. So a page holding a perfectly good bearer token has no way to
//! present it, and the only thing left that reaches the server is the query
//! string.
//!
//! A token in a query string is a token in an access log, which is why this
//! one is shaped the way it is: it is minted by an authenticated request, it
//! names the one path it opens, it is redeemed exactly once, and it is dead
//! thirty seconds after it was made whether it was used or not. What it
//! carries is not a new permission — it is the permission the caller ALREADY
//! had, frozen at the moment they asked, so a ticket can never open a door
//! its holder could not have walked through with their own credential.
//!
//! **It lives in the tier's etcd, and that is the fix** (Fremdsicht 6). It
//! used to live in the memory of the process that minted it, and this module
//! said so and called it a trade: "talk to the address you were served from".
//! That is not a trade a browser can keep. A cloud behind one name with three
//! replicas hands the mint to whichever one the load balancer picked and the
//! `WebSocket` to whichever one it picks next, so two consoles in three were
//! refused at an HA cloud — and the refusal was indistinguishable from a
//! forged ticket.
//!
//! **Exactly once, across replicas.** Redeeming is a delete that returns what
//! it deleted (`EtcdStore::take`), so the exclusivity is etcd's own and not a
//! lock anybody here holds. A get followed by a delete would be two round
//! trips with a window between them, and in that window the sister replica
//! reads the same ticket and opens the same console a second time.
//!
//! **Thirty seconds is a lease.** The object is created with a TTL and etcd
//! reaps the key itself, so an unused ticket needs no sweeper, no pass and
//! nobody alive at all — the same mechanism `Event` already uses. There is no
//! second clock in this process, deliberately: one question, one answer.

use std::sync::Arc;
use std::time::Duration;

use tracing::warn;

use crate::auth::{Identity, Role};
use crate::object::Resource;
use crate::resources::{Ticket, TicketBearer, TicketSpec};
use crate::store::{EtcdStore, Result};

/// How long a ticket lives, used or not.
///
/// Thirty seconds is a person clicking a button and a page opening a socket,
/// with room for a slow network — and short enough that a ticket in a log or
/// a shoulder-surfed URL is already dead by the time anybody reads it.
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

    /// A ticket for `path`, carrying `bearer`'s permission and nothing more.
    ///
    /// 248 bits from the system's own generator. Not a uuid: a uuid is an
    /// identifier and this is a secret, and the two have different jobs even
    /// where they have the same length.
    ///
    /// Lowercase hex and not base64, and thirty-one bytes rather than
    /// thirty-two, because the token is `metadata.name` now: a name in this
    /// store is a DNS label — one etcd key segment, no uppercase, at most 63
    /// bytes. Sixty-two hex characters fit; sixty-four did not, and finding
    /// that out is what the integration test is for. 248 bits is not a
    /// weakening anybody can use — it is a thirty-second secret with 2^248
    /// values.
    pub async fn mint(&self, bearer: Bearer, path: &str) -> Result<String> {
        use ring::rand::SecureRandom as _;
        let mut raw = [0u8; 31];
        // A generator that cannot produce randomness is not a case to paper
        // over with a weaker secret: nothing else in this process would work
        // either (rustls uses the same one), and a panic here is louder and
        // shorter than a ticket somebody can guess.
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

    /// Spend a ticket on the path it was made for. `None` for a ticket that
    /// was never issued, was already spent, has expired, or names another
    /// path — four different mistakes with one answer, because telling them
    /// apart would tell a guesser which half they got right.
    ///
    /// A store that cannot be reached is a fifth, and it answers the same
    /// way: a console that fails closed does not open, and one that failed
    /// open would be this whole file undone.
    pub async fn redeem(&self, token: &str, path: &str) -> Option<Bearer> {
        // Taken before it is judged: a ticket presented at all is a ticket
        // spent, so a wrong path cannot be retried against the right one. The
        // take is one round trip and the delete inside it is what makes it
        // exclusive — the sister replica's take of the same key finds nothing.
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

/// The `ticket=` of a query string, if there is one.
///
/// Hand-parsed rather than through a query extractor because the guard sees a
/// path and a query and no route yet — and because this must not be fooled by
/// a parameter that merely ENDS in `ticket`.
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

    /// The stored shape, which is now a wire document and has to read like
    /// one.
    ///
    /// `camelCase` and `deny_unknown_fields` like every other spec here, and
    /// no `status`: a ticket is a thing that is taken, not a thing anything
    /// observes.
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

    /// A token is a name in this store, so it has to be one.
    ///
    /// Two rules, and the mint broke both on the way here: base64url carries
    /// uppercase, and thirty-two bytes of hex is 64 characters against a
    /// limit of 63. Neither shows up anywhere but a live store, which is why
    /// this test states them where the mint can be read beside them.
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
