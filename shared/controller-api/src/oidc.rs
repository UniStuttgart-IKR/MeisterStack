// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! People log in at an identity provider; this is the link of the chain that
//! believes the result.
//!
//! One more link and nothing else. It produces the same `Identity { name,
//! groups }` the other two produce, and everything downstream of it —
//! `grant_of`, `permits`, `permits_object` — is untouched and unaware.
//!
//! **The division of labour, which is the whole design.** A token proves
//! WHO. The user directory says WHAT THEY MAY DO. Nothing in this file reads
//! a role out of a claim, and that is not a simplification to be lifted
//! later: `auth::permits` already documents why the cloud reads the role off
//! the `User` object rather than off the credential — because the directory
//! is the truth and a role change there has to take effect at once. A role
//! carried in a token would take effect when the token was next minted,
//! which is the opposite property.
//!
//! It follows that a token for somebody the directory does not know is worth
//! nothing here, and that already happens without a line of code in this
//! file: `rest::grant_of` answers `(None, None)` for a name it cannot find,
//! and `permits` refuses every verb — reads included — to a caller with no
//! role. A person who has authenticated and is not in the directory gets a
//! 403 that says so, which is the same answer somebody whose account was
//! deleted gets, and for the same reason.
//!
//! Certificates stay what they were. Machines — `system:node:<name>`,
//! `system:cluster:<name>` — authenticate with mTLS and always will:
//! certificates are for things that have no browser, OIDC is for people, and
//! not mixing those two is the decision this whole feature rests on.

use std::sync::Arc;

use anyhow::{Result, bail};
use chrono::{DateTime, Utc};
use meister_oidc::cache::KeyCache;
use meister_oidc::jwt::{Validation, VerifyError, looks_like_a_jwt, verify};
use tracing::debug;

use crate::auth::{AuthRequest, Authenticator, Identity, SYSTEM_PREFIX};

/// The group every identity out of a token carries.
///
/// It is not a permission and nothing in `permits` looks at it — `Role` is
/// read only from `meister:admins` and `meister:members`, and this is
/// neither. It is there so that an audit line says how somebody got in, and
/// so that `rest::provision_from_directory` can tell an identity the
/// provider vouched for from one a certificate did.
pub const GROUP_OIDC: &str = "meister:oidc";

/// The prefix under which a token's tenant claim travels, when the operator
/// has configured one.
///
/// Carried as a group because a group is what an `Identity` has room for and
/// because it belongs in the audit line: what the provider SAID about
/// somebody's tenant is worth seeing next to what the directory made of it.
/// Read in exactly one place — first-login provisioning — and by nothing
/// that decides anything.
pub const GROUP_OIDC_TENANT_PREFIX: &str = "meister:oidc-tenant:";

/// The tenant a token claimed, if it claimed one.
pub fn claimed_tenant(identity: &Identity) -> Option<&str> {
    identity
        .groups
        .iter()
        .find_map(|g| g.strip_prefix(GROUP_OIDC_TENANT_PREFIX))
        .filter(|t| !t.is_empty())
}

pub struct OidcAuthenticator {
    validation: Validation,
    cache: Arc<KeyCache>,
    /// Which claim carries the tenant, for first-login provisioning. `None`
    /// when that is switched off, which is the default.
    tenant_claim: Option<String>,
}

impl OidcAuthenticator {
    pub fn new(validation: Validation, cache: Arc<KeyCache>, tenant_claim: Option<String>) -> Self {
        Self {
            validation,
            cache,
            tenant_claim,
        }
    }

    /// The whole of `authenticate` with the clock passed in, the same shape
    /// `MtlsAuthenticator` uses and for the same reason: expiry is most of
    /// what this checks, and a test has to be able to say "and an hour
    /// later".
    pub fn authenticate_at(
        &self,
        req: &AuthRequest,
        now: DateTime<Utc>,
    ) -> Result<Option<Identity>> {
        let Some(header) = &req.authorization else {
            return Ok(None);
        };
        let Some(presented) = header.strip_prefix("Bearer ") else {
            return Ok(None);
        };
        let token = presented.trim();
        // Not a token of ours. Passing it on rather than refusing it is what
        // lets the static development token live in the same chain — see
        // `looks_like_a_jwt`, where the reasoning is.
        if !looks_like_a_jwt(token) {
            return Ok(None);
        }

        let verified = match self
            .cache
            .with_keys(|keys| verify(token, keys, &self.validation, now))
        {
            Ok(v) => v,
            Err(VerifyError::UnknownKey { kid }) => {
                // The one failure a refetch could turn into a success. Ask
                // for one — rate limited, and asking never blocks this
                // request — and refuse this one. See `meister_oidc::cache`
                // for why refusing beats waiting.
                let asked = self.cache.request_refresh_at(now);
                if !self.cache.loaded() {
                    bail!(
                        "the identity provider's signing keys have not been fetched yet; \
                         try again in a moment"
                    );
                }
                debug!(
                    kid = kid.as_deref().unwrap_or("<none>"),
                    asked_provider = asked,
                    "a token named a signing key we do not have"
                );
                bail!(
                    "the token was signed with a key the identity provider has not \
                     published; if its keys have just rotated, try again in a moment"
                );
            }
            Err(e) => bail!("{e}"),
        };

        let name = check_name(&verified.username)?;
        let mut groups = vec![GROUP_OIDC.to_string()];
        if let Some(claim) = &self.tenant_claim
            && let Some(tenant) = verified
                .claims
                .rest
                .get(claim)
                .and_then(|v| v.as_str())
                .map(str::trim)
                .filter(|t| !t.is_empty())
        {
            groups.push(format!("{GROUP_OIDC_TENANT_PREFIX}{tenant}"));
        }
        Ok(Some(Identity::new(name, groups)))
    }
}

/// What a claim is allowed to be a name.
///
/// The `system:` refusal is the one that matters and it is not a hygiene
/// check. `Identity::is_system` decides by prefix, and `permits` gives a
/// system identity everything — that is right for a node, whose name comes
/// out of a certificate this stack's own CA issued. A name that came out of
/// somebody else's token must never be able to claim it: an identity
/// provider that can be persuaded to mint a `sub` of `system:node:manacor`
/// would otherwise be an identity provider that can do anything here.
///
/// The rest is what an object name and a log line can survive. `store`
/// refuses a name with a slash at the write, which is a good second line and
/// a bad first one: by then the name has already been through routing and an
/// audit line.
fn check_name(name: &str) -> Result<String> {
    if name.starts_with(SYSTEM_PREFIX) {
        bail!(
            "the token names {name:?}; {SYSTEM_PREFIX}* is this stack's own machinery and \
             an identity provider does not get to mint one"
        );
    }
    if name == "." || name == ".." {
        bail!("the token names {name:?}, which is not a usable name");
    }
    if let Some(bad) = name
        .chars()
        .find(|c| *c == '/' || c.is_whitespace() || c.is_control())
    {
        bail!("the token's name contains {bad:?}, which is not allowed in one");
    }
    // Long enough for a DN or a uuid, short enough that nothing downstream
    // has to worry about it.
    if name.chars().count() > 253 {
        bail!("the token's name is longer than 253 characters");
    }
    Ok(name.to_string())
}

impl Authenticator for OidcAuthenticator {
    fn authenticate(&self, req: &AuthRequest) -> Result<Option<Identity>> {
        self.authenticate_at(req, Utc::now())
    }

    /// The one link in this stack whose readiness is not its construction: it
    /// is built from an issuer URL and can only check a signature once the
    /// provider's JWKS has been fetched at least once.
    ///
    /// `loaded` and not "has usable keys", which would be the stricter
    /// reading and the wrong one: a provider that answered with an empty key
    /// set has been REACHED, and that is a different problem from one that
    /// cannot be reached at all — the refresher already says so with its own
    /// warning. What this answers is the question the discovery document
    /// asks: has this link ever been in a position to authenticate anybody.
    fn ready(&self) -> bool {
        self.cache.loaded()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use meister_oidc::jwks::Keys;
    use meister_oidc::testing::{TestIdp, claims};
    use serde_json::json;
    use std::time::Duration;

    use crate::auth::{AuthChain, Authenticated, BearerAuthenticator, Role};

    const ISS: &str = "https://idp.example.org";
    const AUD: &str = "meisterstack";
    const EXP: i64 = 1_798_761_600;

    fn now() -> DateTime<Utc> {
        DateTime::from_timestamp(EXP - 300, 0).unwrap()
    }

    fn bearer(token: &str) -> AuthRequest {
        AuthRequest {
            peer_certs: Vec::new(),
            authorization: Some(format!("Bearer {token}")),
        }
    }

    /// An authenticator whose cache already holds this provider's key.
    fn authenticator(
        idp: &TestIdp,
        tenant_claim: Option<&str>,
    ) -> (OidcAuthenticator, Arc<KeyCache>) {
        let (cache, _handle) = KeyCache::new(Duration::from_secs(60));
        let cache = Arc::new(cache);
        cache.install(idp.keys());
        let auth = OidcAuthenticator::new(
            Validation::new(ISS, vec![AUD.to_string()]),
            cache.clone(),
            tenant_claim.map(str::to_string),
        );
        (auth, cache)
    }

    /// D11: this link is configured the moment it is built and ready only
    /// once the provider's keys have been fetched, and it says which.
    ///
    /// The lab ran for hours with `auth: "mtls,oidc"` in the discovery
    /// document while the issuer was unreachable — the refresher logged
    /// "keeping the ones we have" over a key set that had never existed, and
    /// every token would have been refused.
    #[test]
    fn the_oidc_link_is_not_ready_until_a_key_set_has_landed() {
        use crate::auth::Authenticator;

        let (cache, _handle) = KeyCache::new(Duration::from_secs(60));
        let cache = Arc::new(cache);
        let auth = OidcAuthenticator::new(
            Validation::new(ISS, vec![AUD.to_string()]),
            cache.clone(),
            None,
        );
        assert!(
            !auth.ready(),
            "an issuer in a config file is not a provider that has answered"
        );

        // A provider that answers with an EMPTY key set has still been
        // reached, and that is a different problem from one that cannot be:
        // the refresher warns about it in its own words, and this link is not
        // the place to say it a second time.
        cache.install(meister_oidc::jwks::Keys::default());
        assert!(auth.ready());

        let idp = TestIdp::new("k1");
        cache.install(idp.keys());
        assert!(auth.ready());
    }

    #[test]
    fn a_token_becomes_an_identity_with_the_name_the_claim_gave() {
        let idp = TestIdp::new("k1");
        let (auth, _) = authenticator(&idp, None);
        let token = idp.token(&claims(ISS, AUD, "alice", EXP));

        let id = auth
            .authenticate_at(&bearer(&token), now())
            .unwrap()
            .expect("a valid token is recognised");
        assert_eq!(id.name, "alice");
        assert_eq!(id.groups, vec![GROUP_OIDC.to_string()]);
    }

    /// The division of labour, asserted rather than described: a token
    /// establishes a NAME and nothing else. No group it carries implies a
    /// role, and `permits` therefore gives it nothing until the directory
    /// has been asked.
    #[test]
    fn a_token_never_carries_a_role_however_hard_it_tries() {
        let idp = TestIdp::new("k1");
        let (auth, _) = authenticator(&idp, None);
        let mut c = claims(ISS, AUD, "alice", EXP);
        // Everything a token could say to try to be an administrator.
        c["role"] = json!("admin");
        c["roles"] = json!(["admin", "cluster-admin"]);
        c["groups"] = json!([
            crate::auth::GROUP_ADMINS,
            crate::auth::GROUP_MASTERS,
            crate::auth::GROUP_NODES
        ]);

        let id = auth
            .authenticate_at(&bearer(&idp.token(&c)), now())
            .unwrap()
            .unwrap();
        assert_eq!(id.groups, vec![GROUP_OIDC.to_string()]);
        assert_eq!(id.claimed_role(), None, "no claim becomes a role");
        assert!(!id.is_system());

        // And with no role established, `permits` refuses every verb — reads
        // included. That is the answer somebody the directory does not know
        // gets, and it is the answer the brief asks for.
        for verb in [crate::auth::Verb::Read, crate::auth::Verb::Write] {
            assert!(!crate::auth::permits(
                &id,
                None,
                None,
                &crate::auth::Attempt {
                    resource: "vms",
                    subresource: None,
                    verb,
                },
                None
            ));
        }
        // Once the directory says who they are, the same identity works.
        assert!(crate::auth::permits(
            &id,
            Some(Role::Member),
            Some("acme"),
            &crate::auth::Attempt {
                resource: "vms",
                subresource: None,
                verb: crate::auth::Verb::Read,
            },
            None
        ));
    }

    /// The one refusal that would be a total bypass if it were missing.
    ///
    /// `permits` gives a `system:` identity everything, because a
    /// `system:node:manacor` name comes out of a certificate this stack's own
    /// CA issued. A `sub` is somebody else's string. An identity provider
    /// that can be talked into minting one of these must not be an identity
    /// provider that owns this control plane.
    #[test]
    fn a_token_may_not_name_itself_part_of_the_stacks_own_machinery() {
        let idp = TestIdp::new("k1");
        let (auth, _) = authenticator(&idp, None);
        for forged in [
            "system:node:manacor",
            "system:cluster:alpha",
            "system:masters",
            "system:",
        ] {
            let token = idp.token(&claims(ISS, AUD, forged, EXP));
            let err = auth.authenticate_at(&bearer(&token), now()).unwrap_err();
            assert!(
                err.to_string().contains("machinery"),
                "{forged:?} was accepted: {err}"
            );
        }
    }

    /// A name has to survive a url, an object key and a log line.
    #[test]
    fn a_name_that_is_not_a_name_is_refused() {
        let idp = TestIdp::new("k1");
        let (auth, _) = authenticator(&idp, None);
        for bad in ["a/b", "..", ".", "with space", "tab\there", "nul\0byte"] {
            let token = idp.token(&claims(ISS, AUD, bad, EXP));
            assert!(
                auth.authenticate_at(&bearer(&token), now()).is_err(),
                "{bad:?} was accepted as a name"
            );
        }
        // The shapes a real provider actually sends, all fine.
        for good in [
            "f81d4fae-7dec-11d0-a765-00a0c91e6bf6",
            "alice@example.org",
            "CN=alice",
            "auth0|5f3c",
        ] {
            let token = idp.token(&claims(ISS, AUD, good, EXP));
            assert_eq!(
                auth.authenticate_at(&bearer(&token), now())
                    .unwrap()
                    .unwrap()
                    .name,
                good
            );
        }
    }

    // --- living in the same chain as the static token ----------------------

    /// The chain contract says `Err` ends the walk, and both bearer links
    /// read the same header. This is the test that says they can coexist:
    /// the oidc link claims what is a JWT and passes on what is not.
    #[test]
    fn the_oidc_link_and_the_static_token_share_one_header() {
        let idp = TestIdp::new("k1");
        let (oidc, _) = authenticator(&idp, None);
        let chain = AuthChain::new(vec![
            Box::new(oidc),
            Box::new(BearerAuthenticator::new(
                "the-lab-token",
                Identity::new("dev-bearer", vec![crate::auth::GROUP_MASTERS.to_string()]),
            )),
        ]);

        // A token: the oidc link takes it.
        let jwt = idp.token(&claims(ISS, AUD, "alice", EXP));
        assert_eq!(
            chain.authenticate(&bearer(&jwt)).unwrap(),
            Authenticated::As(Identity::new("alice", vec![GROUP_OIDC.to_string()]))
        );

        // The static token: not a jwt, so the oidc link passes and the one
        // behind it recognises it. This is the assertion that the bootstrap
        // path still exists — without it, turning oidc on would have taken
        // the way in for a brand new user with it.
        assert_eq!(
            chain.authenticate(&bearer("the-lab-token")).unwrap(),
            Authenticated::As(Identity::new(
                "dev-bearer",
                vec![crate::auth::GROUP_MASTERS.to_string()]
            ))
        );

        // Neither: refused by the link that knows about opaque tokens.
        assert!(chain.authenticate(&bearer("wrong")).is_err());

        // And no credential at all is still "nobody presented anything",
        // not a refusal from either link.
        let err = chain.authenticate(&AuthRequest::default()).unwrap_err();
        assert!(err.to_string().contains("no credentials"), "{err}");
    }

    /// A BROKEN token is the oidc link's, and it must not be handed on. If
    /// it were, a token this link had just refused would get a second
    /// opinion from a weaker one behind it, which is the bypass the chain's
    /// "Err ends the walk" rule exists to prevent.
    #[test]
    fn a_token_the_oidc_link_refused_does_not_reach_the_link_behind_it() {
        let idp = TestIdp::new("k1");
        let (oidc, _) = authenticator(&idp, None);
        let chain = AuthChain::new(vec![
            Box::new(oidc),
            // A link that says yes to everything. If the walk ever reaches
            // it, this test fails loudly rather than subtly.
            Box::new(BearerAuthenticator::new(
                idp.tampered(&claims(ISS, AUD, "alice", EXP)),
                Identity::new("should-never-happen", vec![]),
            )),
        ]);
        let err = chain
            .authenticate(&bearer(&idp.tampered(&claims(ISS, AUD, "alice", EXP))))
            .unwrap_err();
        assert!(err.to_string().contains("does not match"), "{err}");
    }

    /// Not our header at all. A basic-auth request has to reach whatever is
    /// behind us unchanged.
    #[test]
    fn another_authentication_scheme_is_not_ours() {
        let idp = TestIdp::new("k1");
        let (auth, _) = authenticator(&idp, None);
        for header in ["Basic dXNlcjpwdw==", "Negotiate abc", "bearer lowercase"] {
            let req = AuthRequest {
                peer_certs: Vec::new(),
                authorization: Some(header.to_string()),
            };
            assert!(auth.authenticate_at(&req, now()).unwrap().is_none());
        }
        assert!(
            auth.authenticate_at(&AuthRequest::default(), now())
                .unwrap()
                .is_none()
        );
    }

    // --- the key cache, from the authenticator's side ----------------------

    /// An unknown key id asks the provider — once per interval, however many
    /// tokens arrive. This is the rate limit seen from the request path: an
    /// attacker minting tokens with random key ids gets one fetch a minute,
    /// not one per token.
    #[test]
    fn a_flood_of_unknown_keys_is_refused_and_asks_the_provider_once() {
        let idp = TestIdp::new("k1");
        let (auth, cache) = authenticator(&idp, None);

        let mut asked = 0;
        for i in 0..500 {
            let other = TestIdp::new(&format!("forged-{i}"));
            let token = other.token(&claims(ISS, AUD, "alice", EXP));
            let err = auth.authenticate_at(&bearer(&token), now()).unwrap_err();
            assert!(err.to_string().contains("has not published"), "{err}");
            // The cache's own counter is what the rate limit is written
            // against; asking it here is asking the same question the
            // authenticator asked.
            if cache.request_refresh_at(now()) {
                asked += 1;
            }
        }
        assert_eq!(asked, 0, "the first request used the interval up");

        // A minute later, one more ask gets through.
        let later = now() + chrono::Duration::seconds(61);
        assert!(cache.request_refresh_at(later));
    }

    /// Before the first fetch lands, every token is refused — and the
    /// sentence says which of the two empty states this is, because "try
    /// again in a moment" and "that key does not exist" are different
    /// problems for whoever is reading the 401.
    #[test]
    fn a_cache_that_has_never_fetched_says_so_rather_than_blaming_the_token() {
        let idp = TestIdp::new("k1");
        let (cache, _handle) = KeyCache::new(Duration::from_secs(60));
        let auth = OidcAuthenticator::new(
            Validation::new(ISS, vec![AUD.to_string()]),
            Arc::new(cache),
            None,
        );
        let token = idp.token(&claims(ISS, AUD, "alice", EXP));
        let err = auth.authenticate_at(&bearer(&token), now()).unwrap_err();
        assert!(err.to_string().contains("not been fetched yet"), "{err}");
    }

    /// A provider that publishes an empty set is a different answer from one
    /// that has not been asked, and it reads differently.
    #[test]
    fn a_provider_with_no_keys_is_not_a_provider_we_have_not_asked() {
        let idp = TestIdp::new("k1");
        let (cache, _handle) = KeyCache::new(Duration::from_secs(60));
        let cache = Arc::new(cache);
        cache.install(Keys::default());
        let auth = OidcAuthenticator::new(Validation::new(ISS, vec![AUD.to_string()]), cache, None);
        let token = idp.token(&claims(ISS, AUD, "alice", EXP));
        let err = auth.authenticate_at(&bearer(&token), now()).unwrap_err();
        assert!(err.to_string().contains("has not published"), "{err}");
    }

    // --- the tenant claim, when it travels at all --------------------------

    /// With provisioning off — the default — no tenant claim leaves the
    /// token, however loudly it is stated.
    #[test]
    fn a_tenant_claim_stays_in_the_token_unless_an_operator_asked_for_it() {
        let idp = TestIdp::new("k1");
        let (auth, _) = authenticator(&idp, None);
        let mut c = claims(ISS, AUD, "alice", EXP);
        c["tenant"] = json!("acme");

        let id = auth
            .authenticate_at(&bearer(&idp.token(&c)), now())
            .unwrap()
            .unwrap();
        assert_eq!(id.groups, vec![GROUP_OIDC.to_string()]);
        assert_eq!(claimed_tenant(&id), None);
    }

    #[test]
    fn a_configured_tenant_claim_travels_as_a_group_that_decides_nothing() {
        let idp = TestIdp::new("k1");
        let (auth, _) = authenticator(&idp, Some("tenant"));
        let mut c = claims(ISS, AUD, "alice", EXP);
        c["tenant"] = json!("acme");

        let id = auth
            .authenticate_at(&bearer(&idp.token(&c)), now())
            .unwrap()
            .unwrap();
        assert_eq!(claimed_tenant(&id), Some("acme"));
        // It is a group, and it is still not a role and still not a system
        // identity. Nothing in `permits` reads it.
        assert_eq!(id.claimed_role(), None);
        assert!(!id.is_system());
        assert!(crate::auth::Role::from_groups(&id.groups).is_none());

        // A claim that is absent, empty or the wrong type is simply not a
        // tenant, rather than an error: whether that costs the person
        // anything is `provision`'s decision, not this one's.
        for missing in [json!(""), json!("   "), json!(42), json!(["acme"])] {
            let mut c = claims(ISS, AUD, "alice", EXP);
            c["tenant"] = missing.clone();
            let id = auth
                .authenticate_at(&bearer(&idp.token(&c)), now())
                .unwrap()
                .unwrap();
            assert_eq!(claimed_tenant(&id), None, "{missing} became a tenant");
        }
    }

    /// Expiry is most of what this checks, so the clock is a parameter.
    #[test]
    fn an_expired_token_is_refused_at_the_authenticator_too() {
        let idp = TestIdp::new("k1");
        let (auth, _) = authenticator(&idp, None);
        let token = idp.token(&claims(ISS, AUD, "alice", EXP));
        let much_later = DateTime::from_timestamp(EXP + 86_400, 0).unwrap();
        let err = auth
            .authenticate_at(&bearer(&token), much_later)
            .unwrap_err();
        assert!(err.to_string().contains("expired"), "{err}");
    }
}
