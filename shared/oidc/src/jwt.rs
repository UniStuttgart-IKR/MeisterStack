// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! One token, checked.
//!
//! The order of the checks in `verify` is part of what it means and is
//! written to be read top to bottom: the algorithm is pinned before a key is
//! chosen, the key is chosen before the signature is checked, and the
//! signature is checked before a single claim is believed. Nothing below the
//! signature line reads anything an attacker could have written, because
//! everything below it has been signed by the provider.

use std::collections::BTreeMap;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use chrono::{DateTime, Utc};
use serde::Deserialize;
use serde_json::Value;

use crate::jwks::{Alg, Keys, b64};

/// A minute either way, which is what an unsynchronised laptop is worth. Big
/// enough that a clock a few seconds out does not lock somebody out, small
/// enough that it does not meaningfully extend the life of a stolen token.
pub const DEFAULT_LEEWAY: Duration = Duration::from_secs(60);

/// The claim that names the person, unless an operator says otherwise.
///
/// `sub` and not `email`, and this is not a shrug at a default. `sub` is the
/// one claim OIDC requires to be stable and never reassigned; an address
/// changes when somebody marries or moves team, and a name that changes is a
/// name that silently detaches a person from everything they own here — or,
/// worse, reattaches them to what the previous holder of that address owned.
pub const DEFAULT_USERNAME_CLAIM: &str = "sub";

/// What a token has to satisfy. All of it is the operator's, none of it is
/// the token's.
#[derive(Clone, Debug)]
pub struct Validation {
    /// Exactly the `iss` the token must carry, and the same string the
    /// discovery document was fetched under.
    pub issuer: String,
    /// Any one of these in `aud` is enough. Empty is a configuration error
    /// caught when the validation is built, not here: a token with no
    /// audience check is a token issued for some other service that this one
    /// will happily accept.
    pub audience: Vec<String>,
    /// The pin. What the provider advertises is not what we accept.
    pub allowed: Vec<Alg>,
    /// Which claim is the username.
    pub username_claim: String,
    /// Clock drift, applied to `exp` and `nbf` in the generous direction.
    pub leeway: Duration,
}

impl Validation {
    pub fn new(issuer: impl Into<String>, audience: Vec<String>) -> Self {
        Self {
            issuer: issuer.into(),
            audience,
            allowed: Alg::DEFAULT_ALLOWED.to_vec(),
            username_claim: DEFAULT_USERNAME_CLAIM.to_string(),
            leeway: DEFAULT_LEEWAY,
        }
    }
}

/// The registered claims this crate looks at, plus everything else so that a
/// configured `username_claim` can be any of them.
#[derive(Debug, Default, Deserialize)]
pub struct Claims {
    #[serde(default)]
    pub iss: Option<String>,
    #[serde(default)]
    pub aud: Option<Audience>,
    #[serde(default)]
    pub exp: Option<i64>,
    #[serde(default)]
    pub nbf: Option<i64>,
    #[serde(default)]
    pub iat: Option<i64>,
    #[serde(flatten)]
    pub rest: BTreeMap<String, Value>,
}

/// `aud` is one string or a list of them; RFC 7519 allows both and providers
/// use both.
#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum Audience {
    One(String),
    Many(Vec<String>),
}

impl Audience {
    fn contains_any(&self, wanted: &[String]) -> bool {
        match self {
            Audience::One(a) => wanted.iter().any(|w| w == a),
            Audience::Many(all) => all.iter().any(|a| wanted.iter().any(|w| w == a)),
        }
    }
}

/// A token that passed. `username` is the claim the operator nominated, and
/// it is the only thing a caller of this crate is expected to use.
#[derive(Debug)]
pub struct Verified {
    pub username: String,
    pub claims: Claims,
}

/// Why a token did not pass.
///
/// `UnknownKey` is its own variant for one reason: it is the only failure
/// that a refetch could turn into a success, and the caller has to be able
/// to tell it apart to decide whether to ask the provider again. Every other
/// way a token can be wrong stays wrong.
#[derive(Debug)]
pub enum VerifyError {
    UnknownKey { kid: Option<String> },
    Invalid(anyhow::Error),
}

impl std::fmt::Display for VerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VerifyError::UnknownKey { kid } => write!(
                f,
                "the token names a signing key ({}) the provider has not published",
                kid.as_deref().unwrap_or("<no kid>")
            ),
            VerifyError::Invalid(e) => write!(f, "{e:#}"),
        }
    }
}

impl std::error::Error for VerifyError {}

fn invalid(e: impl Into<anyhow::Error>) -> VerifyError {
    VerifyError::Invalid(e.into())
}

#[derive(Debug, Deserialize)]
struct Header {
    alg: String,
    #[serde(default)]
    kid: Option<String>,
    #[serde(default)]
    crit: Option<Vec<String>>,
}

/// Whether a bearer value is a signed JWT at all.
///
/// This exists so that two links of the same authenticator chain can share
/// the `Authorization: Bearer` header without fighting over it. The chain's
/// contract is that `Err` ends the walk, so an OIDC link that refused every
/// bearer value it could not verify would take the static development token
/// down with it — the token would never reach the link that knows it. A JWT
/// is recognisable by shape, so the OIDC link claims what is one and passes
/// on what is not.
///
/// Deliberately a shape test and not a validity test: something that IS a
/// JWT and is broken must be REFUSED by the OIDC link, not handed on to a
/// weaker one. Only things that were never JWTs get passed along.
pub fn looks_like_a_jwt(token: &str) -> bool {
    let mut parts = token.split('.');
    let (Some(header), Some(payload), Some(_), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return false;
    };
    if header.is_empty() || payload.is_empty() {
        return false;
    }
    // A JOSE header is base64url json with an `alg`. Anything that decodes
    // that far was meant to be a token, whatever else is wrong with it.
    let Ok(raw) = b64(header) else { return false };
    serde_json::from_slice::<serde_json::Map<String, Value>>(&raw)
        .is_ok_and(|h| h.get("alg").is_some_and(Value::is_string))
}

/// Check one token against one set of keys.
pub fn verify(
    token: &str,
    keys: &Keys,
    v: &Validation,
    now: DateTime<Utc>,
) -> Result<Verified, VerifyError> {
    if v.audience.is_empty() {
        return Err(invalid(anyhow!(
            "no audience is configured; a token would be accepted whoever it was issued for"
        )));
    }

    // Bound once, and every slice below is a slice of THIS string. The
    // signature is checked over `header.payload` as a range of it, so a
    // second `trim()` producing a different string would be checking a
    // signature over bytes nobody signed.
    let token = token.trim();

    // Three parts and no more. A five-part string is a JWE — encrypted, not
    // signed — and there is nothing here that could check it, so it is
    // refused as a shape rather than misread as a signature.
    let mut parts = token.split('.');
    let (Some(raw_header), Some(raw_payload), Some(raw_sig), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(invalid(anyhow!(
            "not a signed jwt: expected three dot-separated parts"
        )));
    };

    let header: Header = serde_json::from_slice(&b64(raw_header).map_err(invalid)?)
        .context("the jwt header")
        .map_err(invalid)?;

    // The pin, in two halves. `Alg::parse` has no `none` and no `HS*`, so a
    // header naming either dies here with its own name in the message; the
    // allow-list then narrows what is left to what this operator asked for.
    let alg = Alg::parse(&header.alg).ok_or_else(|| {
        invalid(anyhow!(
            "{:?} is not a signature algorithm this stack accepts; \
             only asymmetric algorithms are implemented",
            header.alg
        ))
    })?;
    if !v.allowed.contains(&alg) {
        return Err(invalid(anyhow!(
            "{} is not in the configured allowed_algorithms",
            alg.as_str()
        )));
    }
    // RFC 7515 section 4.1.11: a header extension listed in `crit` MUST be
    // understood or the token MUST be rejected. We understand none of them.
    if let Some(crit) = &header.crit
        && !crit.is_empty()
    {
        return Err(invalid(anyhow!(
            "the token marks header extensions critical ({}) and none is understood",
            crit.join(",")
        )));
    }

    let key = keys
        .get(header.kid.as_deref())
        .ok_or(VerifyError::UnknownKey {
            kid: header.kid.clone(),
        })?;

    // Over the two raw parts and the dot between them, exactly as they
    // arrived: re-encoding the header would check a signature over bytes the
    // provider never signed.
    let signed_len = raw_header.len() + 1 + raw_payload.len();
    let signed = &token.as_bytes()[..signed_len];
    let sig = b64(raw_sig).context("the signature").map_err(invalid)?;
    key.verify(alg, signed, &sig).map_err(invalid)?;

    // --- everything below this line is signed by the provider -------------

    let claims: Claims = serde_json::from_slice(&b64(raw_payload).map_err(invalid)?)
        .context("the jwt claims")
        .map_err(invalid)?;

    match claims.iss.as_deref() {
        Some(iss) if iss == v.issuer => {}
        Some(iss) => {
            return Err(invalid(anyhow!(
                "the token was issued by {iss:?}, not by {:?}",
                v.issuer
            )));
        }
        None => return Err(invalid(anyhow!("the token carries no iss"))),
    }

    match &claims.aud {
        Some(aud) if aud.contains_any(&v.audience) => {}
        Some(_) => {
            return Err(invalid(anyhow!(
                "the token was issued for another audience than {}",
                v.audience.join(",")
            )));
        }
        None => return Err(invalid(anyhow!("the token carries no aud"))),
    }

    let leeway = chrono::Duration::from_std(v.leeway).unwrap_or_else(|_| chrono::Duration::zero());
    match claims.exp.and_then(|e| DateTime::from_timestamp(e, 0)) {
        Some(exp) if now <= exp + leeway => {}
        Some(exp) => {
            return Err(invalid(anyhow!("the token expired at {exp}")));
        }
        // No expiry is the static-token failure mode with extra steps, and
        // OIDC requires the claim. A token without one is not one of ours.
        None => return Err(invalid(anyhow!("the token carries no usable exp"))),
    }
    if let Some(nbf) = claims.nbf.and_then(|n| DateTime::from_timestamp(n, 0))
        && now + leeway < nbf
    {
        return Err(invalid(anyhow!("the token is not valid before {nbf}")));
    }

    let username = username_of(&claims, &v.username_claim).map_err(invalid)?;
    Ok(Verified { username, claims })
}

/// The nominated claim, as a non-empty string.
///
/// A top-level claim and not a path: providers put the username at the top
/// level, a dotted path would need an escape for a claim name containing a
/// dot, and an identity that depends on getting an escape right is worse
/// than one that does not.
fn username_of(claims: &Claims, claim: &str) -> Result<String> {
    // `sub` is a registered claim and lands in the struct, not in `rest`, so
    // the common case has to be answered from the field.
    let value = match claim {
        "iss" => claims.iss.clone().map(Value::String),
        _ => claims.rest.get(claim).cloned(),
    };
    let value = value.with_context(|| format!("the token carries no {claim:?} claim"))?;
    let Value::String(name) = value else {
        bail!("the {claim:?} claim is not a string");
    };
    let name = name.trim().to_string();
    if name.is_empty() {
        bail!("the {claim:?} claim is empty");
    }
    Ok(name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jwks::JwkSet;
    use crate::testing::{TestIdp, claims, unsigned};
    use serde_json::json;

    const ISS: &str = "https://idp.example.org";
    const AUD: &str = "meisterstack";
    /// 2027-01-01, so the fixtures do not start failing on a Tuesday.
    const EXP: i64 = 1_798_761_600;

    fn now() -> DateTime<Utc> {
        DateTime::from_timestamp(EXP - 300, 0).unwrap()
    }

    fn validation() -> Validation {
        Validation::new(ISS, vec![AUD.to_string()])
    }

    fn good(idp: &TestIdp) -> String {
        idp.token(&claims(ISS, AUD, "u-1234", EXP))
    }

    /// The baseline the rest of this module breaks one piece at a time.
    #[test]
    fn a_well_formed_token_names_its_subject() {
        let idp = TestIdp::new("k1");
        let v = verify(&good(&idp), &idp.keys(), &validation(), now()).unwrap();
        assert_eq!(v.username, "u-1234");
        assert_eq!(v.claims.iss.as_deref(), Some(ISS));
    }

    // --- the table of refusals --------------------------------------------

    /// `alg: none`. The oldest one there is: a token that says it needs no
    /// signature, accepted by anything that reads the header before deciding.
    #[test]
    fn a_token_that_says_it_needs_no_signature_is_not_a_token() {
        let idp = TestIdp::new("k1");
        let err = verify(
            &unsigned(&claims(ISS, AUD, "u-1234", EXP)),
            &idp.keys(),
            &validation(),
            now(),
        )
        .unwrap_err();
        assert!(err.to_string().contains("none"), "{err}");
        assert!(matches!(err, VerifyError::Invalid(_)));
    }

    /// Algorithm confusion, both halves.
    ///
    /// The classic form is to take the provider's PUBLIC key, present it to
    /// an HMAC verifier as the shared secret, and sign your own tokens with
    /// it. That needs a symmetric code path to reach, and there is none —
    /// `HS256` does not parse into an `Alg` at all, so the attack stops at
    /// the header rather than at a key comparison.
    ///
    /// The second half is the same idea between two asymmetric families: a
    /// header naming an RSA algorithm over an EC key. That one is refused by
    /// the key itself, in `PublicKey::verify`.
    #[test]
    fn an_algorithm_the_token_picked_is_not_an_algorithm_we_will_use() {
        let idp = TestIdp::new("k1");
        let c = claims(ISS, AUD, "u-1234", EXP);

        for lie in ["HS256", "HS384", "HS512", "none", "NONE", ""] {
            let token = idp.sign_with(&json!({"alg": lie, "kid": idp.kid}), &c);
            let err = verify(&token, &idp.keys(), &validation(), now()).unwrap_err();
            assert!(
                err.to_string().contains("asymmetric"),
                "{lie:?} was refused for the wrong reason: {err}"
            );
        }

        // A real ES256 signature under a header claiming RS256. The
        // signature bytes are genuine; the pairing is not.
        let token = idp.sign_with(&json!({"alg": "RS256", "kid": idp.kid}), &c);
        let err = verify(&token, &idp.keys(), &validation(), now()).unwrap_err();
        assert!(err.to_string().contains("this key is EC"), "{err}");
    }

    /// The pin is the operator's list, not the provider's menu. An algorithm
    /// this crate CAN check is still refused when it was not asked for.
    #[test]
    fn an_algorithm_outside_the_configured_list_is_refused_even_though_we_could_check_it() {
        let idp = TestIdp::new("k1");
        let mut v = validation();
        v.allowed = vec![Alg::Rs256];
        let err = verify(&good(&idp), &idp.keys(), &v, now()).unwrap_err();
        assert!(err.to_string().contains("allowed_algorithms"), "{err}");

        v.allowed = vec![Alg::Rs256, Alg::Es256];
        assert!(verify(&good(&idp), &idp.keys(), &v, now()).is_ok());
    }

    /// An unknown `kid` is its own answer, because it is the only one a
    /// refetch could change. The caller uses this to decide whether to ask
    /// the provider again — see `cache`.
    #[test]
    fn an_unknown_key_id_is_told_apart_from_every_other_failure() {
        let idp = TestIdp::new("k1");
        let other = TestIdp::new("k2");
        // Signed by k2, checked against a set holding only k1.
        let token = other.token(&claims(ISS, AUD, "u-1234", EXP));
        let err = verify(&token, &idp.keys(), &validation(), now()).unwrap_err();
        match &err {
            VerifyError::UnknownKey { kid } => assert_eq!(kid.as_deref(), Some("k2")),
            other => panic!("expected UnknownKey, got {other:?}"),
        }
        assert!(err.to_string().contains("k2"), "{err}");
    }

    /// And a key id that is known but wrong is NOT an unknown key: the
    /// signature simply does not check out, and no refetch will help.
    #[test]
    fn a_signature_from_the_wrong_key_under_a_known_id_is_a_plain_refusal() {
        let idp = TestIdp::new("k1");
        let impostor = TestIdp::new("k1");
        let token = impostor.token(&claims(ISS, AUD, "u-1234", EXP));
        let err = verify(&token, &idp.keys(), &validation(), now()).unwrap_err();
        assert!(matches!(err, VerifyError::Invalid(_)), "{err}");
        assert!(err.to_string().contains("does not match"), "{err}");
    }

    #[test]
    fn a_tampered_signature_is_refused() {
        let idp = TestIdp::new("k1");
        let token = idp.tampered(&claims(ISS, AUD, "u-1234", EXP));
        let err = verify(&token, &idp.keys(), &validation(), now()).unwrap_err();
        assert!(err.to_string().contains("does not match"), "{err}");
    }

    /// A tampered PAYLOAD, which is the same refusal for a different reason
    /// and the one that matters: the claim being edited is the username.
    #[test]
    fn a_payload_edited_after_signing_is_refused() {
        let idp = TestIdp::new("k1");
        let token = good(&idp);
        let (header, rest) = token.split_once('.').unwrap();
        let (_, sig) = rest.split_once('.').unwrap();
        let forged = crate::testing::b64(claims(ISS, AUD, "admin", EXP).to_string().as_bytes());
        let err = verify(
            &format!("{header}.{forged}.{sig}"),
            &idp.keys(),
            &validation(),
            now(),
        )
        .unwrap_err();
        assert!(err.to_string().contains("does not match"), "{err}");
    }

    #[test]
    fn an_expired_token_is_refused_and_a_minute_of_drift_is_not() {
        let idp = TestIdp::new("k1");
        let token = good(&idp);
        let v = validation();

        let just_expired = DateTime::from_timestamp(EXP + 30, 0).unwrap();
        assert!(
            verify(&token, &idp.keys(), &v, just_expired).is_ok(),
            "half a minute past expiry is clock drift, not an expired token"
        );

        let long_gone = DateTime::from_timestamp(EXP + 3600, 0).unwrap();
        let err = verify(&token, &idp.keys(), &v, long_gone).unwrap_err();
        assert!(err.to_string().contains("expired"), "{err}");
    }

    #[test]
    fn a_token_from_the_future_is_refused_until_it_is_not() {
        let idp = TestIdp::new("k1");
        let mut c = claims(ISS, AUD, "u-1234", EXP);
        let nbf = EXP - 100;
        c["nbf"] = json!(nbf);
        let token = idp.token(&c);

        let early = DateTime::from_timestamp(nbf - 3600, 0).unwrap();
        let err = verify(&token, &idp.keys(), &validation(), early).unwrap_err();
        assert!(err.to_string().contains("not valid before"), "{err}");

        let drift = DateTime::from_timestamp(nbf - 30, 0).unwrap();
        assert!(verify(&token, &idp.keys(), &validation(), drift).is_ok());
    }

    /// A token with no expiry is the static bearer token wearing a hat, and
    /// OIDC requires the claim in any case.
    #[test]
    fn a_token_without_an_expiry_is_refused() {
        let idp = TestIdp::new("k1");
        let mut c = claims(ISS, AUD, "u-1234", EXP);
        c.as_object_mut().unwrap().remove("exp");
        let err = verify(&idp.token(&c), &idp.keys(), &validation(), now()).unwrap_err();
        assert!(err.to_string().contains("exp"), "{err}");
    }

    #[test]
    fn a_token_from_another_issuer_is_refused() {
        let idp = TestIdp::new("k1");
        let token = idp.token(&claims("https://other.example", AUD, "u-1234", EXP));
        let err = verify(&token, &idp.keys(), &validation(), now()).unwrap_err();
        assert!(err.to_string().contains("other.example"), "{err}");

        let mut c = claims(ISS, AUD, "u-1234", EXP);
        c.as_object_mut().unwrap().remove("iss");
        let err = verify(&idp.token(&c), &idp.keys(), &validation(), now()).unwrap_err();
        assert!(err.to_string().contains("no iss"), "{err}");
    }

    /// A token for another service is not a token for this one, however
    /// impeccably it is signed by the right provider.
    #[test]
    fn a_token_for_another_audience_is_refused() {
        let idp = TestIdp::new("k1");
        let token = idp.token(&claims(ISS, "grafana", "u-1234", EXP));
        let err = verify(&token, &idp.keys(), &validation(), now()).unwrap_err();
        assert!(err.to_string().contains("another audience"), "{err}");

        // aud as a list, which half the providers send.
        let mut c = claims(ISS, AUD, "u-1234", EXP);
        c["aud"] = json!(["grafana", AUD]);
        assert!(verify(&idp.token(&c), &idp.keys(), &validation(), now()).is_ok());

        c["aud"] = json!(["grafana", "prometheus"]);
        assert!(verify(&idp.token(&c), &idp.keys(), &validation(), now()).is_err());

        c.as_object_mut().unwrap().remove("aud");
        let err = verify(&idp.token(&c), &idp.keys(), &validation(), now()).unwrap_err();
        assert!(err.to_string().contains("no aud"), "{err}");
    }

    /// A validation with no audience would accept every token the provider
    /// ever issued, for any service. It is refused rather than allowed to be
    /// a very permissive setting.
    #[test]
    fn a_validation_with_no_audience_refuses_everything() {
        let idp = TestIdp::new("k1");
        let mut v = validation();
        v.audience.clear();
        let err = verify(&good(&idp), &idp.keys(), &v, now()).unwrap_err();
        assert!(
            err.to_string().contains("no audience is configured"),
            "{err}"
        );
    }

    #[test]
    fn an_identity_without_a_name_is_not_an_identity() {
        let idp = TestIdp::new("k1");
        let mut c = claims(ISS, AUD, "u-1234", EXP);

        c.as_object_mut().unwrap().remove("sub");
        let err = verify(&idp.token(&c), &idp.keys(), &validation(), now()).unwrap_err();
        assert!(err.to_string().contains("no \"sub\""), "{err}");

        c["sub"] = json!("   ");
        let err = verify(&idp.token(&c), &idp.keys(), &validation(), now()).unwrap_err();
        assert!(err.to_string().contains("empty"), "{err}");

        c["sub"] = json!(1234);
        let err = verify(&idp.token(&c), &idp.keys(), &validation(), now()).unwrap_err();
        assert!(err.to_string().contains("not a string"), "{err}");
    }

    /// Which claim is the name is the operator's, because providers disagree
    /// about it — and getting it wrong is not a typo, it is a different
    /// person.
    #[test]
    fn the_username_claim_is_configurable_and_defaults_to_sub() {
        let idp = TestIdp::new("k1");
        let token = good(&idp);
        assert_eq!(DEFAULT_USERNAME_CLAIM, "sub");

        let mut v = validation();
        v.username_claim = "preferred_username".into();
        assert_eq!(
            verify(&token, &idp.keys(), &v, now()).unwrap().username,
            "u-1234-by-name"
        );

        v.username_claim = "not_a_claim".into();
        let err = verify(&token, &idp.keys(), &v, now()).unwrap_err();
        assert!(err.to_string().contains("not_a_claim"), "{err}");
    }

    // --- shapes that are not tokens ---------------------------------------

    #[test]
    fn something_that_is_not_three_parts_is_not_a_jwt() {
        let idp = TestIdp::new("k1");
        for junk in [
            "",
            "not-a-token",
            "a.b",
            "a.b.c.d.e",
            "!!!.!!!.!!!",
            "eyJhbGciOiJFUzI1NiJ9",
        ] {
            assert!(
                verify(junk, &idp.keys(), &validation(), now()).is_err(),
                "{junk:?} was accepted"
            );
        }
    }

    /// RFC 7515 section 4.1.11: a `crit` header we do not understand means
    /// the token must be refused, and we understand none of them.
    #[test]
    fn a_critical_header_extension_we_do_not_understand_is_refused() {
        let idp = TestIdp::new("k1");
        let token = idp.sign_with(
            &json!({"alg": "ES256", "kid": idp.kid, "crit": ["exp"], "exp": 1}),
            &claims(ISS, AUD, "u-1234", EXP),
        );
        let err = verify(&token, &idp.keys(), &validation(), now()).unwrap_err();
        assert!(err.to_string().contains("critical"), "{err}");
    }

    /// The shape test that lets the OIDC link and the static bearer token
    /// share one header. Anything that was never a JWT is passed on; a
    /// broken JWT is not, because passing that on would mean a token the
    /// OIDC link refused getting a second opinion from a weaker link.
    #[test]
    fn a_jwt_is_recognisable_by_shape_and_an_opaque_token_is_not() {
        let idp = TestIdp::new("k1");
        assert!(looks_like_a_jwt(&good(&idp)));
        assert!(looks_like_a_jwt(&unsigned(&claims(ISS, AUD, "u", EXP))));
        // Broken in every way but still a jwt: the OIDC link owns these.
        assert!(looks_like_a_jwt(&idp.tampered(&claims(ISS, AUD, "u", EXP))));
        assert!(looks_like_a_jwt(&idp.token(&json!({}))));

        for opaque in [
            "",
            "s3cr3t",
            "dev-token-for-the-lab",
            "a.b.c",
            "a.b",
            "..",
            "eyJhbGciOiJFUzI1NiJ9..",
            // Valid base64url json, but no `alg`: not a JOSE header.
            &format!("{}.x.y", crate::testing::b64(b"{\"typ\":\"JWT\"}")),
        ] {
            assert!(!looks_like_a_jwt(opaque), "{opaque:?} was claimed as a jwt");
        }
    }

    /// The RSA path, against RFC 7515's own worked example — key, signing
    /// input and signature all lifted from appendix A.2. Our tests otherwise
    /// generate EC keys, so without this the whole `RS256` branch would only
    /// ever have been checked against itself.
    #[test]
    fn the_rs256_path_verifies_the_rfc_7515_example() {
        const N: &str = "ofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd_wWJcyQoTbji9k0l8W26mPddxHmfHQp-Vaw-4qP\
            CJrcS2mJPMEzP1Pt0Bm4d4QlL-yRT-SFd2lZS-pCgNMsD1W_YpRPEwOWvG6b32690r2jZ47soMZo9wGzjb_7\
            OMg0LOL-bSf63kpaSHSXndS5z5rexMdbBYUsLA9e-KXBdQOS-UTo7WTBEMa2R2CapHg665xsmtdVMTBQY4uD\
            Zlxvb3qCo5ZwKh9kG4LT6_I5IhlJH7aGhyxXFvUK-DWNmoudF8NAco9_h9iaGNj8q2ethFkMLs91kzk2PAcD\
            TW9gb54h4FRWyuXpoQ";
        const SIGNING_INPUT: &str = "eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MT\
            kzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ";
        const SIG: &str = "cC4hiUPoj9Eetdgtv3hF80EGrhuB__dzERat0XF9g2VtQgr9PJbu3XOiZj5RZmh7AAuHIm\
            4Bh-0Qc_lF5YKt_O8W2Fp5jujGbds9uJdbF9CUAr7t1dnZcAcQjbKBYNX4BAynRFdiuB--f_nZLgrnbyTyWz\
            O75vRK5h6xBArLIARNPvkSjtQBMHlb1L07Qe7K0GarZRmB_eSN9383LcOLn6_dO--xi12jzDwusC-eOkHWEs\
            qtFZESc6BfI7noOPqvhJ1phCnvWh6IeYI2w9QOYEUipUTI8np6LbgGY9Fs98rqVt5AXLIhWkWywlVmtVrBp0\
            igcN_IoypGlUPQGe77Rw";

        let set: JwkSet = serde_json::from_value(serde_json::json!({
            "keys": [{"kty": "RSA", "kid": "rfc", "use": "sig", "n": N, "e": "AQAB"}]
        }))
        .unwrap();
        let keys = Keys::parse(&set);
        let key = keys.get(Some("rfc")).expect("the rfc's key parsed");

        key.verify(
            Alg::Rs256,
            SIGNING_INPUT.as_bytes(),
            &crate::jwks::b64(SIG).unwrap(),
        )
        .expect("the rfc's own signature checks out");

        // And the same key refuses the same bytes under any other algorithm.
        for wrong in [Alg::Rs384, Alg::Rs512] {
            assert!(
                key.verify(
                    wrong,
                    SIGNING_INPUT.as_bytes(),
                    &crate::jwks::b64(SIG).unwrap()
                )
                .is_err(),
                "{wrong:?} accepted an RS256 signature"
            );
        }
        assert!(
            key.verify(
                Alg::Es256,
                SIGNING_INPUT.as_bytes(),
                &crate::jwks::b64(SIG).unwrap()
            )
            .is_err(),
            "an RSA key answered an EC algorithm"
        );
    }
}
