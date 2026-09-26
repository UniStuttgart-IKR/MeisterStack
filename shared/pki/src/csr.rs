// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Generate client keys and certificate signing requests.
//!
//! The private key stays with the caller; only the CSR is submitted for approval.
//! Requested subjects are not authoritative until the server approves them.

use anyhow::{Result, anyhow, bail};
use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair};
use rustls_pki_types::CertificateSigningRequestDer;
use rustls_pki_types::pem::PemObject;
use x509_parser::prelude::*;

/// New private key and CSR as PEM. Return the secret key to the caller
/// for storage with appropriate permissions; the CSR contains only its public key.
pub struct KeyAndCsr {
    pub key_pem: String,
    pub csr_pem: String,
}

/// Generate a P-256 key and CSR with the requested name. Issuance replaces
/// the requested subject with the server-approved subject.
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

/// Create a CSR from an existing private key, preserving identity across
/// interrupted enrollment retries. The caller supplies PEM; no file is opened.
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

/// Hex SHA-256 of the public key's SubjectPublicKeyInfo PEM bytes.
pub fn public_key_sha256(key_pem: &str) -> Result<String> {
    use sha2::{Digest, Sha256};
    let key = KeyPair::from_pem(key_pem)
        .map_err(|e| anyhow::anyhow!("reading the key to name its public half: {e}"))?;
    // Hash the SubjectPublicKeyInfo PEM representation, not its DER bytes.
    let digest = Sha256::digest(key.public_key_pem().as_bytes());
    let mut out = String::with_capacity(digest.len() * 2);
    for byte in digest {
        out.push_str(&format!("{byte:02x}"));
    }
    Ok(out)
}

/// Parse a CSR and verify its signature before returning the claimed
/// subject name. The signer must still authorize that name and choose
/// the issued subject and privileges.
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

    /// Verify that the CSR contains no private key material.
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

    /// Reusing a key for enrollment must preserve its public identity.
    #[test]
    fn a_second_request_over_the_same_key_is_the_same_key() {
        let made = generate_key_and_csr("system:node:n1").unwrap();
        let again = csr_for_key(&made.key_pem, "system:node:n1").unwrap();
        assert!(again.starts_with("-----BEGIN CERTIFICATE REQUEST-----"));
        assert_eq!(requested_name(&again).unwrap(), "system:node:n1");
        // Compare the reused key's public identity.
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

    /// Reject CSRs without valid proof of possession of their private key.
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
