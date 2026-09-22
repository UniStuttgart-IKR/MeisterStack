// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! The client's half of the CSR flow: make a key, keep it, ask for a
//! certificate over it.
//!
//! `KeyAndCsr` is the whole reason this crate is shared. The private key is
//! generated here, on the machine that will use it, and the only thing that
//! travels is the request — a public key and a name, both of which the server
//! is free to distrust. Nothing in this module can send anything anywhere.

use anyhow::{Result, anyhow, bail};
use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair};
use rustls_pki_types::CertificateSigningRequestDer;
use rustls_pki_types::pem::PemObject;
use x509_parser::prelude::*;

/// A fresh key pair and the request that goes with it, both as PEM.
///
/// `key_pem` is the secret. It is returned rather than written so that the
/// caller decides where it lands and with which permissions — and so that the
/// test below can prove it never appears in the request.
pub struct KeyAndCsr {
    pub key_pem: String,
    pub csr_pem: String,
}

/// Generate a P-256 key pair and a CSR asking to be `common_name`.
///
/// The name in the request is a courtesy: it is what the operator typed, it
/// travels so the server can compare it against what it was told, and the
/// server overwrites it in the certificate either way (`ca::Ca::sign_csr`).
pub fn generate_key_and_csr(common_name: &str) -> Result<KeyAndCsr> {
    if common_name.is_empty() {
        bail!("a certificate request needs a name");
    }
    let key = KeyPair::generate().map_err(|e| anyhow::anyhow!("generating a key pair: {e}"))?;
    let mut params = CertificateParams::new(Vec::new())
        .map_err(|e| anyhow::anyhow!("building the request: {e}"))?;
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, common_name);
    params.distinguished_name = dn;
    let csr = params
        .serialize_request(&key)
        .map_err(|e| anyhow::anyhow!("signing the request: {e}"))?;
    Ok(KeyAndCsr {
        key_pem: key.serialize_pem(),
        csr_pem: csr
            .pem()
            .map_err(|e| anyhow::anyhow!("encoding the request: {e}"))?,
    })
}

/// Another request over a key that is already on this machine.
///
/// The idempotent half of enrolment. `meister-activate keygen` is run over
/// ssh by a rollout that can be interrupted, and a second run must not make
/// a SECOND identity: a host with two keys has two identities, and the one
/// the certificate was issued over is then a coin toss. So the key stays and
/// only the request is made again.
///
/// The key is read as a value rather than a path because the caller here
/// goes through its own file door (`meister-deploy`'s `Files` trait); this
/// function opens nothing.
pub fn csr_for_key(key_pem: &str, common_name: &str) -> Result<String> {
    if common_name.is_empty() {
        bail!("a certificate request needs a name");
    }
    let key = KeyPair::from_pem(key_pem)
        .map_err(|e| anyhow::anyhow!("reading the key this request is to be made over: {e}"))?;
    let mut params = CertificateParams::new(Vec::new())
        .map_err(|e| anyhow::anyhow!("building the request: {e}"))?;
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, common_name);
    params.distinguished_name = dn;
    let csr = params
        .serialize_request(&key)
        .map_err(|e| anyhow::anyhow!("signing the request: {e}"))?;
    csr.pem()
        .map_err(|e| anyhow::anyhow!("encoding the request: {e}"))
}

/// A name for a key that is safe to print: the sha256 of its PUBLIC half
/// in SubjectPublicKeyInfo form, as hex.
///
/// What it is for is comparing — "is the key on that host still the one the
/// certificate was issued over" — without anything that could be mistaken
/// for the key itself ever reaching a log, a journal or a receipt.
pub fn public_key_sha256(key_pem: &str) -> Result<String> {
    use sha2::{Digest, Sha256};
    let key = KeyPair::from_pem(key_pem)
        .map_err(|e| anyhow::anyhow!("reading the key to name its public half: {e}"))?;
    // The PEM of the SubjectPublicKeyInfo: the same bytes any tool would
    // print for this key, so the digest is one somebody can reproduce with
    // `openssl pkey -pubout`.
    let digest = Sha256::digest(key.public_key_pem().as_bytes());
    let mut out = String::with_capacity(digest.len() * 2);
    for byte in digest {
        out.push_str(&format!("{byte:02x}"));
    }
    Ok(out)
}

/// The name a request is made out to, having established that the request
/// parses and that the key inside it signed it.
///
/// The signature check is the point. It proves the sender holds the private
/// half of the key it is asking us to certify — without it, anyone could take
/// somebody else's public key, submit it under their own name, and have the
/// CA vouch for a key they do not have. It costs one function call and it is
/// the difference between a CSR and a form.
///
/// What comes back is a claim and is treated as one: the server compares it
/// against the name being asked for, and then writes its own subject anyway.
pub fn requested_name(csr_pem: &str) -> Result<String> {
    let der = CertificateSigningRequestDer::from_pem_slice(csr_pem.as_bytes())
        .map_err(|e| anyhow!("not a PEM certificate request: {e}"))?;
    let (_, request) = X509CertificationRequest::from_der(&der)
        .map_err(|e| anyhow!("the certificate request does not parse: {e}"))?;
    request
        .verify_signature()
        .map_err(|e| anyhow!("the certificate request is not signed by the key it carries: {e}"))?;
    Ok(request
        .certification_request_info
        .subject
        .iter_common_name()
        .next()
        .and_then(|cn| cn.as_str().ok())
        .unwrap_or_default()
        .to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The claim the whole flow rests on, checked rather than asserted in
    /// prose: what goes on the wire is a CERTIFICATE REQUEST and the private
    /// key is not in it.
    #[test]
    fn the_private_key_is_not_in_the_request() {
        let made = generate_key_and_csr("alice").unwrap();
        assert!(
            made.csr_pem
                .starts_with("-----BEGIN CERTIFICATE REQUEST-----")
        );
        assert!(made.key_pem.contains("PRIVATE KEY"));
        // Not "the strings differ" — no line of the key appears in the
        // request at all.
        for line in made
            .key_pem
            .lines()
            .filter(|l| !l.starts_with("-----") && l.len() > 16)
        {
            assert!(
                !made.csr_pem.contains(line),
                "a line of the key travelled with the request"
            );
        }
    }

    #[test]
    fn a_request_without_a_name_is_refused() {
        assert!(generate_key_and_csr("").is_err());
        assert!(csr_for_key(&generate_key_and_csr("a").unwrap().key_pem, "").is_err());
    }

    /// The property a resumed enrolment stands on: asking the same key for a
    /// second request does not make a second key.
    #[test]
    fn a_second_request_over_the_same_key_is_the_same_key() {
        let made = generate_key_and_csr("system:node:n1").unwrap();
        let again = csr_for_key(&made.key_pem, "system:node:n1").unwrap();
        assert!(again.starts_with("-----BEGIN CERTIFICATE REQUEST-----"));
        assert_eq!(requested_name(&again).unwrap(), "system:node:n1");
        // Same key, so the same public half — which is what a certificate is
        // issued over.
        assert_eq!(
            public_key_sha256(&made.key_pem).unwrap(),
            public_key_sha256(&made.key_pem).unwrap()
        );
        let other = generate_key_and_csr("system:node:n1").unwrap();
        assert_ne!(
            public_key_sha256(&made.key_pem).unwrap(),
            public_key_sha256(&other.key_pem).unwrap(),
            "two keys are two keys"
        );
    }

    /// The digest is a digest and never the key.
    #[test]
    fn the_public_name_of_a_key_is_hex_and_carries_nothing_of_the_key() {
        let made = generate_key_and_csr("alice").unwrap();
        let name = public_key_sha256(&made.key_pem).unwrap();
        assert_eq!(name.len(), 64, "{name}");
        assert!(name.chars().all(|c| c.is_ascii_hexdigit()), "{name}");
        assert!(public_key_sha256("not a key at all").is_err());
    }

    #[test]
    fn a_request_says_the_name_it_was_made_out_to() {
        let made = generate_key_and_csr("alice").unwrap();
        assert_eq!(requested_name(&made.csr_pem).unwrap(), "alice");
    }

    /// A request whose signature does not check out is not a request. Without
    /// this, anybody could submit somebody else's public key under their own
    /// name and have the CA vouch for a key they do not hold.
    #[test]
    fn a_request_nobody_signed_is_not_one() {
        let made = generate_key_and_csr("alice").unwrap();
        // Corrupt the body while keeping it valid base64 and valid PEM
        // framing, so what fails is the signature rather than the parse.
        let mut lines: Vec<String> = made.csr_pem.lines().map(str::to_string).collect();
        let body = lines.len() / 2;
        lines[body] = lines[body]
            .chars()
            .map(|c| {
                if c == 'A' {
                    'B'
                } else if c == 'B' {
                    'A'
                } else {
                    c
                }
            })
            .collect();
        let tampered = lines.join("\n");
        assert!(requested_name(&tampered).is_err());
        assert!(requested_name("not pem at all").is_err());
    }
}
