// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! rustls configs out of PEM paths — the server side for the two REST APIs,
//! the client side for the CLI.
//!
//! Both ends are here because they are the same three files read three ways,
//! and because the one thing that must agree between them (which crypto
//! provider, which ALPN) is easier to keep true in one file than in two.

use std::collections::BTreeSet;
use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result};
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, CertificateRevocationListDer};

use crate::pem::{load_certs, load_private_key};

/// This stack speaks HTTP/1.1 and nothing else over TLS: the REST APIs are
/// hyper's http1 server, and gRPC lives on its own port with tonic's own TLS.
/// Advertising h2 here would be advertising a protocol nobody serves.
const ALPN_HTTP11: &[u8] = b"http/1.1";

/// Server TLS for a REST API.
///
/// `client_ca` is the switch that turns mTLS on. When it is set the server
/// *asks* for a client certificate but does not insist on one: a request with
/// no certificate has to reach the authenticator chain to be told 401 in
/// words, and a handshake that fails instead would leave `meister login` — a
/// client that by definition has no certificate yet — with nothing to talk to.
/// `crl` is the revocation list this port checks a client certificate
/// against at the HANDSHAKE. It is read once, here, and lives in the
/// `ServerConfig` — rustls has no way to replace it in a config a listener
/// already holds, so what reloads is the application-level check in
/// `controller_api::auth` (D11, measured in M0 probe S10). This half is the
/// belt: a certificate that is on the list when this process starts does not
/// get as far as an authenticator.
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
                    // The end entity and not the whole chain: the list this
                    // CA publishes is about the certificates it issued, and
                    // its own trust anchor is excluded from a revocation
                    // check anyway.
                    .only_check_end_entity_revocation()
                    // A certificate no list mentions is not a certificate
                    // this port refuses. rustls' default is the other way
                    // round, and it would turn a bundle holding a second CA
                    // — one this fleet verifies against and does not publish
                    // a list for — into a lockout. What is authoritative
                    // about revocation here is the reloadable check in
                    // `controller_api::auth`, which reads the same file and
                    // answers the same way about a serial that is on it.
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

/// A certificate revocation list, read once for both of the places that
/// need it.
///
/// The same "one parse, both answers" as [`crate::cert::CertInfo`]: rustls
/// wants DER for its handshake-time check, and the application-level check
/// wants the serials to compare an authenticated certificate against. Two
/// readers would be two chances to disagree about what the file says.
///
/// The serials are exactly what `x509-parser` prints for them — lowercase
/// hex, colon separated, over the raw DER integer — which is the SAME
/// function `CertInfo::serial` comes out of, so the two are comparable
/// without a conversion. Callers that have to compare with openssl's
/// spelling (upper case, no separators) normalise both sides; see
/// `controller_api::auth::normalise_serial`.
#[derive(Debug, Default)]
pub struct Crl {
    pub der: Vec<CertificateRevocationListDer<'static>>,
    pub serials: BTreeSet<String>,
    /// The `X509v3 CRL Number` extension: a list that goes backwards is a
    /// list somebody restored from a backup, and an operator wants to see
    /// the number rather than guess.
    pub number: Option<u64>,
}

/// One spelling for a serial number, because this stack has three.
///
/// `x509-parser` prints `64:35:c9:…` (lowercase, colon separated) and it is
/// what both a certificate and a CRL entry come out of here. openssl's
/// `index.txt` and `x509 -serial` print `6435C9…` (upper case, no
/// separators), and that is the one an operator reads off a receipt and
/// retypes. A leading zero byte is DER's sign padding and says nothing about
/// the number.
///
/// Comparing serials is the whole of revocation, so the comparison is made
/// in exactly one function and every caller goes through it — the
/// controllers' authenticator, the session registries, and the deployment
/// tool, which all have to mean the same certificate by the same number.
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

/// Read a CRL file (PEM, as `openssl ca -gencrl` writes it).
///
/// A file with no list in it is an error and not an empty list: "nothing is
/// revoked" and "the list could not be read" are the two answers that must
/// never be confused, because one of them is the one an attacker wants.
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
        // The highest of them, for a bundle holding more than one list.
        // `BigUint` because that is what a CRL number is; a number this
        // stack cannot hold in a u64 is reported as none rather than
        // truncated.
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

/// The peer's certificate chain as plain DER, leaf first.
///
/// Plain `Vec<u8>` rather than a rustls type on purpose: this is what crosses
/// into `controller_api::auth`, and an authenticator should be testable from a
/// certificate on disk without a TLS session ever having existed.
pub fn der_chain(certs: &[CertificateDer<'static>]) -> Vec<Vec<u8>> {
    certs.iter().map(|c| c.to_vec()).collect()
}
