// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Convert verified OIDC tokens into control-plane identities.
//!
//! Tokens establish identity; the cloud User directory supplies roles and tenant
//! membership. Token role claims grant no permissions, and names in the reserved
//! `system:` namespace are refused. Machine sessions use their own credentials.

use std::sync::Arc;

use anyhow::{Result, bail};
use chrono::{DateTime, Utc};
use meister_oidc::cache::KeyCache;
use meister_oidc::jwt::{Validation, VerifyError, looks_like_a_jwt, verify};
use tracing::debug;

use crate::auth::{AuthRequest, Authenticator, Identity, SYSTEM_PREFIX};

/// Marker for OIDC authentication, used for audit and first-login provisioning.
/// It grants no role; the directory supplies authorization.
pub const GROUP_OIDC: &str = "meister:oidc";

/// Carry the provider's tenant claim for audit and first-login provisioning.
/// Authorization reads the resulting directory membership, not this claim.
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

    /// Authenticate with an explicit clock for deterministic expiry checks.
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
                // An unknown signing key requests a rate-limited background refresh.
                // Reject this request rather than waiting for provider I/O.
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

/// Validate an OIDC-derived identity name before routing or persistence.
/// Reject the reserved `system:` namespace so provider claims cannot
/// impersonate machine identities.
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

    /// Report whether a JWKS fetch has completed. This is discovery
    /// readiness, not proof that the fetched set contains a usable signing key.
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

    /// OIDC discovery distinguishes configured authentication from a loaded key set.
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

        // An installed empty key set counts as fetched; readiness does not guarantee
        // that any incoming token has a matching signing key.
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

    /// Token claims establish identity without granting a role; directory lookup
    /// is still required for authorization.
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

    /// Reject reserved system names from provider-controlled subjects so external
    /// identity cannot impersonate stack machinery.
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

        // Non-JWT static tokens defer to the later bearer authenticator, preserving
        // bootstrap access when OIDC is enabled.
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

    /// An OIDC rejection terminates authentication rather than allowing a weaker
    /// later authenticator to accept the rejected token.
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

    /// Unknown-key floods trigger at most one refresh per interval, not one
    /// provider request per token.
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

    /// Distinguish an unfetched key cache from a fetched set lacking the token's key.
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
