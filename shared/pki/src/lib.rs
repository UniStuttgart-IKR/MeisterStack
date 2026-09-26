// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Shared X.509 identity, certificate issuance and TLS configuration.
//!
//! Controllers and the CLI use the same PEM loading and trust primitives.
//! Private keys remain local files; API certificate requests carry public keys.

pub mod ca;
pub mod cert;
pub mod csr;
pub mod pem;
pub mod tls;

pub use ca::Ca;
pub use cert::{CertInfo, fingerprint};
pub use csr::{KeyAndCsr, csr_for_key, generate_key_and_csr, public_key_sha256, requested_name};
pub use pem::{load_certs, load_private_key, write_secret};

/// Install ring as the default provider for tonic. Local rustls builders
/// select it explicitly; an already installed default is left unchanged.
pub fn install_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

pub(crate) fn provider() -> std::sync::Arc<rustls::crypto::CryptoProvider> {
    std::sync::Arc::new(rustls::crypto::ring::default_provider())
}
