// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! rustls configs out of PEM paths — the server side for the two REST APIs,
//! the client side for the CLI.
//!
//! Both ends are here because they are the same three files read three ways,
//! and because the one thing that must agree between them (which crypto
//! provider, which ALPN) is easier to keep true in one file than in two.

use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result};
use macros::generated;
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use rustls_pki_types::CertificateDer;

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
#[generated(model = ClaudeOpus, version = "5")]
pub fn server_config(
    cert: &Path,
    key: &Path,
    client_ca: Option<&Path>,
) -> Result<Arc<ServerConfig>> {
    let chain = load_certs(cert)?;
    let key = load_private_key(key)?;

    let builder = ServerConfig::builder_with_provider(crate::provider())
        .with_safe_default_protocol_versions()
        .context("no usable TLS protocol versions")?;

    let mut config = match client_ca {
        Some(ca) => {
            let verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(
                Arc::new(roots(ca)?),
                crate::provider(),
            )
            .allow_unauthenticated()
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
#[generated(model = ClaudeOpus, version = "5")]
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
#[generated(model = ClaudeOpus, version = "5")]
pub fn roots(path: &Path) -> Result<RootCertStore> {
    let mut store = RootCertStore::empty();
    for cert in load_certs(path)? {
        store
            .add(cert)
            .with_context(|| format!("{} is not usable as a trust root", path.display()))?;
    }
    Ok(store)
}

/// The peer's certificate chain as plain DER, leaf first.
///
/// Plain `Vec<u8>` rather than a rustls type on purpose: this is what crosses
/// into `controller_api::auth`, and an authenticator should be testable from a
/// certificate on disk without a TLS session ever having existed.
pub fn der_chain(certs: &[CertificateDer<'static>]) -> Vec<Vec<u8>> {
    certs.iter().map(|c| c.to_vec()).collect()
}
