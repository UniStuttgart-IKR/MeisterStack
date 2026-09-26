// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Build REST server and CLI client rustls configurations from PEM files.
//!
//! Centralizes the crypto provider, trust roots, client identities and ALPN.

use std::collections::BTreeSet;
use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result};
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, CertificateRevocationListDer};

use crate::pem::{load_certs, load_private_key};

/// Advertise only HTTP/1.1 on the REST TLS port; gRPC uses separate tonic transport.
const ALPN_HTTP11: &[u8] = b"http/1.1";

/// REST TLS with optional client certificates when client_ca is set,
/// allowing bearer login to reach the authentication chain. Presented
/// certificates are verified, including the CRL loaded at startup.
/// Application-level revocation checks reload separately.
pub fn server_config(
    cert: &Path,
    key: &Path,
    client_ca: Option<&Path>,
    crl: Option<&Path>,
) -> Result<Arc<ServerConfig>> {
    let chain = load_certs(cert)?;
    let key = load_private_key(key)?;

    let builder = ServerConfig::builder_with_provider(crate::provider())
        .with_safe_default_protocol_versions()
        .context("no usable TLS protocol versions")?;

    let mut config = match client_ca {
        Some(ca) => {
            let mut verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(
                Arc::new(roots(ca)?),
                crate::provider(),
            )
            .allow_unauthenticated();
            if let Some(path) = crl {
                verifier = verifier
                    .with_crls(read_crl(path)?.der)
                    // Check revocation on the leaf certificate; trust anchors are excluded.
                    .only_check_end_entity_revocation()
                    // Allow certificates whose issuer has no loaded CRL. Application-level
                    // revocation checks reload separately in controller_api::auth.
                    .allow_unknown_revocation_status();
            }
            let verifier = verifier
                .build()
                .context("building the client certificate verifier")?;
            builder.with_client_cert_verifier(verifier)
        }
        None => builder.with_no_client_auth(),
    }
    .with_single_cert(chain, key)
    .context("the certificate and the key do not go together")?;

    config.alpn_protocols = vec![ALPN_HTTP11.to_vec()];
    Ok(Arc::new(config))
}

/// Client TLS: whom to trust, and — for mTLS — who we are.
pub fn client_config(
    ca: Option<&Path>,
    identity: Option<(&Path, &Path)>,
) -> Result<Arc<ClientConfig>> {
    let roots = match ca {
        Some(path) => roots(path)?,
        // No CA named: the platform's own roots. A lab CA will not be among
        // them, which is the point — a missing ca_cert should fail loudly at
        // the handshake, not fall back to trusting whatever answers.
        None => RootCertStore { roots: Vec::new() },
    };

    let builder = ClientConfig::builder_with_provider(crate::provider())
        .with_safe_default_protocol_versions()
        .context("no usable TLS protocol versions")?
        .with_root_certificates(roots);

    let mut config = match identity {
        Some((cert, key)) => builder
            .with_client_auth_cert(load_certs(cert)?, load_private_key(key)?)
            .context("the client certificate and key do not go together")?,
        None => builder.with_no_client_auth(),
    };
    config.alpn_protocols = vec![ALPN_HTTP11.to_vec()];
    Ok(Arc::new(config))
}

/// Every certificate in a bundle, as a trust root.
pub fn roots(path: &Path) -> Result<RootCertStore> {
    let mut store = RootCertStore::empty();
    for cert in load_certs(path)? {
        store
            .add(cert)
            .with_context(|| format!("{} is not usable as a trust root", path.display()))?;
    }
    Ok(store)
}

/// One parsed CRL supplies DER for TLS and serials for application
/// checks. Normalize serials when comparing X.509 colon-separated hex
/// with OpenSSL text.
#[derive(Debug, Default)]
pub struct Crl {
    pub der: Vec<CertificateRevocationListDer<'static>>,
    pub serials: BTreeSet<String>,
    /// Highest representable X509v3 CRL Number in the loaded bundle.
    pub number: Option<u64>,
}

/// Normalize certificate serials across colon-separated X.509 text and
/// OpenSSL uppercase hex, removing DER sign padding before comparison.
pub fn normalise_serial(serial: &str) -> String {
    let mut out: String = serial
        .chars()
        .filter(|c| c.is_ascii_hexdigit())
        .map(|c| c.to_ascii_lowercase())
        .collect();
    if out.len() % 2 == 1 {
        out.insert(0, '0');
    }
    while out.len() > 2 && out.starts_with("00") {
        out.drain(..2);
    }
    out
}

/// Parse PEM CRLs and reject files containing no list, distinguishing
/// an unreadable list from an explicitly empty revocation set.
pub fn read_crl(path: &Path) -> Result<Crl> {
    let der: Vec<CertificateRevocationListDer<'static>> =
        CertificateRevocationListDer::pem_file_iter(path)
            .with_context(|| format!("reading the revocation list {}", path.display()))?
            .collect::<std::result::Result<_, _>>()
            .with_context(|| format!("parsing the revocation list {}", path.display()))?;
    if der.is_empty() {
        anyhow::bail!(
            "{} contains no certificate revocation list. An empty file is not an empty \
             list: it is a file this process cannot tell anything from.",
            path.display()
        );
    }
    let mut serials = BTreeSet::new();
    let mut number: Option<u64> = None;
    for one in &der {
        let (_, crl) = x509_parser::prelude::parse_x509_crl(one.as_ref())
            .map_err(|e| anyhow::anyhow!("{} is not a usable crl: {e}", path.display()))?;
        for revoked in crl.iter_revoked_certificates() {
            serials.insert(revoked.raw_serial_as_string());
        }
        // Report the highest CRL number representable as u64; ignore oversized values.
        if let Some(n) = crl
            .crl_number()
            .and_then(|n| n.to_string().parse::<u64>().ok())
            && number.is_none_or(|have| n > have)
        {
            number = Some(n);
        }
    }
    Ok(Crl {
        der,
        serials,
        number,
    })
}

/// Copy the peer chain as DER bytes, leaf first, for authentication independent of a TLS session.
pub fn der_chain(certs: &[CertificateDer<'static>]) -> Vec<Vec<u8>> {
    certs.iter().map(|c| c.to_vec()).collect()
}
