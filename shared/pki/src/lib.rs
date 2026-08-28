// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! The X.509 half of the control plane: what a certificate says, who signed
//! it, and how to make a TLS config out of a few PEM files.
//!
//! It is a crate of its own for one reason — the CLI needs it. `meister login`
//! generates a key pair, builds a CSR and then talks https to a controller,
//! which is the same set of primitives the controllers use from the other
//! side. Putting them in controller-api would have dragged etcd into the CLI.
//!
//! One rule runs through all of it: **a private key is a file on one machine
//! and never anything else.** Nothing here serialises a key into an object, a
//! config value or a log line; the only key that ever leaves a function is
//! the one `csr::generate` hands its caller to write to disk.

pub mod ca;
pub mod cert;
pub mod csr;
pub mod pem;
pub mod tls;

pub use ca::Ca;
pub use cert::{CertInfo, fingerprint};
pub use csr::{KeyAndCsr, generate_key_and_csr, requested_name};
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
