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
