// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! An identity provider that fits in a test process.
//!
//! This is the file that makes the claim in the brief true — that none of
//! this needs a running provider to prove. It generates a key pair, publishes
//! it as a JWKS the real parser reads, and signs tokens the real verifier
//! checks. Nothing here is a mock of our own code: the only thing it stands
//! in for is somebody else's http server.
//!
//! It can also forge. `sign_with` takes the header verbatim, so a test can
//! say `alg: none`, name a key that does not exist, or claim `HS256` over an
//! RSA signature — which is what the table of refusals in `jwt` is written
//! against.
//!
//! Behind the `testing` feature so that the controller's own tests can build
//! tokens too. Resolver 2 keeps a dev-dependency's features out of a plain
//! `cargo build`, so none of this reaches a shipped binary.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ring::rand::SystemRandom;
use ring::signature::{self, EcdsaKeyPair, KeyPair};
use serde_json::{Value, json};

use crate::jwks::{JwkSet, Keys};

pub fn b64(raw: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(raw)
}

/// A provider with exactly one P-256 signing key.
pub struct TestIdp {
    pub kid: String,
    key: EcdsaKeyPair,
    /// The uncompressed SEC1 point, `0x04 || x || y`.
    point: Vec<u8>,
    rng: SystemRandom,
}

impl TestIdp {
    pub fn new(kid: &str) -> Self {
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&signature::ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
            .expect("generating a p-256 key");
        let key = EcdsaKeyPair::from_pkcs8(
            &signature::ECDSA_P256_SHA256_FIXED_SIGNING,
            pkcs8.as_ref(),
            &rng,
        )
        .expect("reading back the key just generated");
        let point = key.public_key().as_ref().to_vec();
        Self {
            kid: kid.to_string(),
            key,
            point,
            rng,
        }
    }

    /// The x and y coordinates, base64url, as a JWK carries them.
    pub fn coordinates(&self) -> (String, String) {
        let body = &self.point[1..];
        let (x, y) = body.split_at(body.len() / 2);
        (b64(x), b64(y))
    }

    /// What this provider would publish at its `jwks_uri`.
    pub fn jwk_set_json(&self) -> Value {
        let (x, y) = self.coordinates();
        json!({"keys": [{
            "kty": "EC", "crv": "P-256", "use": "sig", "alg": "ES256",
            "kid": self.kid, "x": x, "y": y,
        }]})
    }

    pub fn jwk_set(&self) -> JwkSet {
        serde_json::from_value(self.jwk_set_json()).expect("our own key set parses")
    }

    pub fn keys(&self) -> Keys {
        Keys::parse(&self.jwk_set())
    }

    /// A token with the header this provider would really write.
    pub fn token(&self, claims: &Value) -> String {
        self.sign_with(
            &json!({"alg": "ES256", "typ": "JWT", "kid": self.kid}),
            claims,
        )
    }

    /// A token with whatever header the test wants, signed for real.
    ///
    /// The signature is genuine even when the header lies about it, which is
    /// exactly the shape of the algorithm-confusion attack: a real signature
    /// under a header that asks for it to be checked another way.
    pub fn sign_with(&self, header: &Value, claims: &Value) -> String {
        let signing_input = format!(
            "{}.{}",
            b64(header.to_string().as_bytes()),
            b64(claims.to_string().as_bytes())
        );
        let sig = self
            .key
            .sign(&self.rng, signing_input.as_bytes())
            .expect("signing");
        format!("{signing_input}.{}", b64(sig.as_ref()))
    }

    /// The same token with one bit of the signature turned over.
    pub fn tampered(&self, claims: &Value) -> String {
        let token = self.token(claims);
        let (head, sig) = token.rsplit_once('.').expect("three parts");
        let mut raw = URL_SAFE_NO_PAD.decode(sig).expect("our own signature");
        raw[0] ^= 0x01;
        format!("{head}.{}", b64(&raw))
    }
}

/// A token with `alg: none` and no signature at all — the oldest JWT attack
/// there is, and one a library that trusts the header still falls for.
pub fn unsigned(claims: &Value) -> String {
    format!(
        "{}.{}.",
        b64(json!({"alg": "none", "typ": "JWT"}).to_string().as_bytes()),
        b64(claims.to_string().as_bytes())
    )
}

/// The claims a well-behaved provider would issue, as a starting point for a
/// test that wants to break exactly one of them.
pub fn claims(issuer: &str, audience: &str, subject: &str, exp: i64) -> Value {
    json!({
        "iss": issuer,
        "aud": audience,
        "sub": subject,
        "exp": exp,
        "iat": exp - 300,
        "preferred_username": format!("{subject}-by-name"),
        "email": format!("{subject}@example.org"),
    })
}
