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

/// The one crypto provider this stack uses.
///
/// Everything here builds its rustls configs against this explicitly, so the
/// process-wide default is irrelevant to us. Installing it anyway is for
/// tonic: its `tls-ring` code path asks for the process default and panics
/// without one, and a controller that dies at the first gRPC handshake is a
/// bad way to find that out. Idempotent — a second call is a no-op.
pub fn install_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

pub(crate) fn provider() -> std::sync::Arc<rustls::crypto::CryptoProvider> {
    std::sync::Arc::new(rustls::crypto::ring::default_provider())
}
