// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! The provider's public keys: what a JWKS document says, and what of it we
//! are willing to believe.
//!
//! Two rules run through this file and both exist to stop the same attack.
//!
//! The first is that an algorithm is something WE decide, not something the
//! token announces. `Alg` has no `none` and no `HS*` variant, so a header
//! naming either does not parse into an algorithm this crate can hand to a
//! verifier; there is no code path from an attacker's `alg` to a symmetric
//! check, because there is no symmetric check.
//!
//! The second is that a key and an algorithm have to agree in KIND. An RSA
//! key cannot be asked to verify an ECDSA signature and an EC key cannot be
//! asked to verify an RSA one, which is checked in `PublicKey::verify`
//! rather than assumed. The classic confusion — take the provider's RSA
//! public key, call it an HMAC secret, sign your own token with it — needs
//! both of those doors open. Here neither is a door.

use anyhow::{Context, Result, bail};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ring::signature;
use serde::Deserialize;

/// Base64url without padding: every field of a JWT and every field of a JWK.
pub fn b64(raw: &str) -> Result<Vec<u8>> {
    URL_SAFE_NO_PAD
        .decode(raw.as_bytes())
        .context("not base64url")
}

/// The signature algorithms this crate can check.
///
/// The list is short and it is asymmetric all the way through, which is the
/// point: `none` and `HS256` are not variants that happen to be unused, they
/// are values this type cannot hold. See the module docs.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Alg {
    Rs256,
    Rs384,
    Rs512,
    Es256,
    Es384,
}

impl Alg {
    /// What an operator may put in `allowed_algorithms`, and what a JOSE
    /// header may say. Anything else is not an algorithm as far as this
    /// crate is concerned.
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "RS256" => Alg::Rs256,
            "RS384" => Alg::Rs384,
            "RS512" => Alg::Rs512,
            "ES256" => Alg::Es256,
            "ES384" => Alg::Es384,
            _ => return None,
        })
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Alg::Rs256 => "RS256",
            Alg::Rs384 => "RS384",
            Alg::Rs512 => "RS512",
            Alg::Es256 => "ES256",
            Alg::Es384 => "ES384",
        }
    }

    /// The two an operator gets without saying anything. Both asymmetric,
    /// both what every provider worth pointing at offers.
    pub const DEFAULT_ALLOWED: [Alg; 2] = [Alg::Rs256, Alg::Es256];

    fn is_rsa(self) -> bool {
        matches!(self, Alg::Rs256 | Alg::Rs384 | Alg::Rs512)
    }
}

/// The curves a JWK may name. Two, matching the two `ES*` algorithms.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Curve {
    P256,
    P384,
}

impl Curve {
    fn coordinate_len(self) -> usize {
        match self {
            Curve::P256 => 32,
            Curve::P384 => 48,
        }
    }
}

/// One usable key, with the JOSE encodings already unwrapped.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PublicKey {
    /// Modulus and exponent, big-endian, exactly as ring wants them.
    Rsa { n: Vec<u8>, e: Vec<u8> },
    /// The uncompressed SEC1 point, `0x04 || x || y`.
    Ec { curve: Curve, point: Vec<u8> },
}

impl PublicKey {
    /// Check one signature over `signed` (the token's `header.payload`).
    ///
    /// The kind check comes first and is not a formality: it is the half of
    /// the algorithm pin that a configured allow-list cannot do. An operator
    /// who allows both `RS256` and `ES256` has said nothing about which key
    /// may be used for which, and without this an EC key and an RSA
    /// algorithm would reach ring as a decoding error rather than as the
    /// refusal it is.
    pub fn verify(&self, alg: Alg, signed: &[u8], sig: &[u8]) -> Result<()> {
        match (self, alg.is_rsa()) {
            (PublicKey::Rsa { n, e }, true) => {
                let params = match alg {
                    Alg::Rs256 => &signature::RSA_PKCS1_2048_8192_SHA256,
                    Alg::Rs384 => &signature::RSA_PKCS1_2048_8192_SHA384,
                    Alg::Rs512 => &signature::RSA_PKCS1_2048_8192_SHA512,
                    _ => unreachable!("is_rsa said so"),
                };
                signature::RsaPublicKeyComponents { n, e }
                    .verify(params, signed, sig)
                    .map_err(|_| anyhow::anyhow!("the signature does not match the key"))
            }
            (PublicKey::Ec { curve, point }, false) => {
                // FIXED, not ASN1: JWS puts r and s side by side as fixed
                // width integers, where X.509 would wrap them in a DER
                // sequence. Same curve, different encoding, and the ASN.1
                // parameters would reject every real token.
                let params = match (alg, curve) {
                    (Alg::Es256, Curve::P256) => &signature::ECDSA_P256_SHA256_FIXED,
                    (Alg::Es384, Curve::P384) => &signature::ECDSA_P384_SHA384_FIXED,
                    _ => bail!(
                        "{} is not the algorithm for this key's curve {:?}",
                        alg.as_str(),
                        curve
                    ),
                };
                signature::UnparsedPublicKey::new(params, point)
                    .verify(signed, sig)
                    .map_err(|_| anyhow::anyhow!("the signature does not match the key"))
            }
            (PublicKey::Rsa { .. }, false) => {
                bail!("{} is an EC algorithm and this key is RSA", alg.as_str())
            }
            (PublicKey::Ec { .. }, true) => {
                bail!("{} is an RSA algorithm and this key is EC", alg.as_str())
            }
        }
    }
}

/// One entry of a JWKS document, still in its wire shape.
#[derive(Debug, Deserialize)]
pub struct Jwk {
    pub kty: String,
    #[serde(default)]
    pub kid: Option<String>,
    /// `sig` or `enc`. Absent means the provider did not say, which RFC 7517
    /// leaves as "usable for either".
    #[serde(default, rename = "use")]
    pub use_: Option<String>,
    #[serde(default)]
    pub alg: Option<String>,
    #[serde(default)]
    pub crv: Option<String>,
    #[serde(default)]
    pub n: Option<String>,
    #[serde(default)]
    pub e: Option<String>,
    #[serde(default)]
    pub x: Option<String>,
    #[serde(default)]
    pub y: Option<String>,
}

impl Jwk {
    fn to_key(&self) -> Result<PublicKey> {
        match self.kty.as_str() {
            "RSA" => {
                let n = b64(self.n.as_deref().context("an RSA jwk without n")?).context("n")?;
                let e = b64(self.e.as_deref().context("an RSA jwk without e")?).context("e")?;
                if n.is_empty() || e.is_empty() {
                    bail!("an RSA jwk with an empty n or e");
                }
                Ok(PublicKey::Rsa { n, e })
            }
            "EC" => {
                let curve = match self.crv.as_deref() {
                    Some("P-256") => Curve::P256,
                    Some("P-384") => Curve::P384,
                    other => bail!("unsupported EC curve {:?}", other.unwrap_or("<none>")),
                };
                let x = b64(self.x.as_deref().context("an EC jwk without x")?).context("x")?;
                let y = b64(self.y.as_deref().context("an EC jwk without y")?).context("y")?;
                // Leading zeroes are significant in a coordinate and a
                // provider is entitled to encode them; a short field is a
                // wrong field, not one to left-pad and hope.
                let want = curve.coordinate_len();
                if x.len() != want || y.len() != want {
                    bail!(
                        "coordinates for {:?} are {} and {} bytes, expected {want}",
                        curve,
                        x.len(),
                        y.len()
                    );
                }
                let mut point = Vec::with_capacity(1 + 2 * want);
                point.push(0x04);
                point.extend_from_slice(&x);
                point.extend_from_slice(&y);
                Ok(PublicKey::Ec { curve, point })
            }
            other => bail!("unsupported key type {other:?}"),
        }
    }
}

/// A JWKS document as the provider serves it.
#[derive(Debug, Default, Deserialize)]
pub struct JwkSet {
    #[serde(default)]
    pub keys: Vec<Jwk>,
}

/// The usable half of a JWKS: what survived parsing, by `kid`.
///
/// A key that does not parse is dropped with a warning rather than failing
/// the whole document, and that direction is deliberate. Providers publish
/// encryption keys, curves we do not implement and occasionally a malformed
/// entry, and a set that refused to load because of one of them would turn
/// somebody else's stray key into an outage here.
#[derive(Debug, Default)]
pub struct Keys {
    by_kid: Vec<(Option<String>, PublicKey)>,
}

impl Keys {
    pub fn parse(set: &JwkSet) -> Self {
        let mut by_kid = Vec::new();
        for jwk in &set.keys {
            if jwk.use_.as_deref().is_some_and(|u| u != "sig") {
                continue;
            }
            match jwk.to_key() {
                Ok(key) => by_kid.push((jwk.kid.clone(), key)),
                Err(e) => tracing::warn!(
                    kid = jwk.kid.as_deref().unwrap_or("<none>"),
                    error = %format!("{e:#}"),
                    "skipping an unusable key from the provider"
                ),
            }
        }
        Self { by_kid }
    }

    pub fn len(&self) -> usize {
        self.by_kid.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_kid.is_empty()
    }

    /// The key a token's `kid` names.
    ///
    /// A token with no `kid` is answered only when the set holds exactly one
    /// key. That is RFC 7515's own reading — a `kid` is a hint for choosing
    /// among several — and the alternative, trying every key in turn, would
    /// mean a token verifying against a key its issuer never meant for it.
    pub fn get(&self, kid: Option<&str>) -> Option<&PublicKey> {
        match kid {
            Some(kid) => self
                .by_kid
                .iter()
                .find(|(k, _)| k.as_deref() == Some(kid))
                .map(|(_, key)| key),
            None if self.by_kid.len() == 1 => self.by_kid.first().map(|(_, key)| key),
            None => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::TestIdp;

    fn set(json: serde_json::Value) -> Keys {
        Keys::parse(&serde_json::from_value(json).expect("the fixture parses"))
    }

    #[test]
    fn only_asymmetric_algorithms_have_names_here() {
        for good in ["RS256", "RS384", "RS512", "ES256", "ES384"] {
            assert_eq!(Alg::parse(good).map(Alg::as_str), Some(good));
        }
        // Not "unsupported": absent. There is no value of this type that
        // means a symmetric check or no check at all.
        for bad in [
            "none", "None", "HS256", "HS512", "PS256", "EdDSA", "", "rs256",
        ] {
            assert!(Alg::parse(bad).is_none(), "{bad:?} parsed as an algorithm");
        }
        assert_eq!(Alg::DEFAULT_ALLOWED.to_vec(), vec![Alg::Rs256, Alg::Es256]);
    }

    /// One bad key in a document does not cost us the good ones. Providers
    /// publish encryption keys and curves we do not implement, and a set
    /// that refused to load over one of them would be somebody else's stray
    /// key causing an outage here.
    #[test]
    fn an_unusable_key_is_dropped_and_the_rest_of_the_set_survives() {
        let idp = TestIdp::new("good");
        let (x, y) = idp.coordinates();
        let keys = set(serde_json::json!({"keys": [
            {"kty": "OKP", "kid": "ed", "crv": "Ed25519", "x": "AAAA"},
            {"kty": "EC", "kid": "wrong-curve", "crv": "P-521", "x": "AA", "y": "AA"},
            {"kty": "EC", "kid": "short", "crv": "P-256", "x": "AA", "y": "AA"},
            {"kty": "RSA", "kid": "no-e", "n": "AQAB"},
            {"kty": "EC", "kid": "good", "crv": "P-256", "use": "sig", "x": x, "y": y},
        ]}));
        assert_eq!(keys.len(), 1);
        assert!(keys.get(Some("good")).is_some());
        assert!(keys.get(Some("short")).is_none());
    }

    /// An encryption key is not a signing key, whatever else it is.
    #[test]
    fn a_key_marked_for_encryption_is_not_offered_for_signatures() {
        let idp = TestIdp::new("k");
        let (x, y) = idp.coordinates();
        let keys = set(serde_json::json!({"keys": [
            {"kty": "EC", "kid": "k", "crv": "P-256", "use": "enc", "x": x, "y": y},
        ]}));
        assert!(keys.is_empty());
    }

    /// A token with no `kid` is answered only when there is nothing to
    /// choose between. Trying every key in turn would mean a token verifying
    /// against a key its issuer never meant for it.
    #[test]
    fn a_token_without_a_key_id_is_answered_only_by_an_unambiguous_set() {
        let one = TestIdp::new("a");
        assert!(one.keys().get(None).is_some());

        let two = TestIdp::new("b");
        let (ax, ay) = one.coordinates();
        let (bx, by) = two.coordinates();
        let keys = set(serde_json::json!({"keys": [
            {"kty": "EC", "kid": "a", "crv": "P-256", "x": ax, "y": ay},
            {"kty": "EC", "kid": "b", "crv": "P-256", "x": bx, "y": by},
        ]}));
        assert!(keys.get(None).is_none(), "two keys and no kid is a guess");
        assert!(keys.get(Some("b")).is_some());
        assert!(keys.get(Some("c")).is_none());
    }

    /// A coordinate is fixed width and a short one is a wrong one. Left
    /// padding it would turn a malformed key into a key that verifies
    /// nothing while looking like it works.
    #[test]
    fn a_short_coordinate_is_a_broken_key_and_not_one_to_pad() {
        let idp = TestIdp::new("k");
        let (x, y) = idp.coordinates();
        let truncated = &x[..x.len() - 2];
        let keys = set(serde_json::json!({"keys": [
            {"kty": "EC", "kid": "k", "crv": "P-256", "x": truncated, "y": y},
        ]}));
        assert!(keys.is_empty());
    }

    #[test]
    fn base64url_is_the_unpadded_kind() {
        assert_eq!(b64("AQAB").unwrap(), vec![0x01, 0x00, 0x01]);
        // The padded, non-url alphabet is a different encoding and not one
        // a JOSE field is ever in.
        assert!(b64("AQAB==").is_err());
        assert!(b64("++//").is_err());
    }
}
