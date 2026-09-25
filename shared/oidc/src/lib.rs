// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Shared OIDC token verification and CLI login support.
//!
//! Provider tokens establish identity. Controller authorization comes from the
//! User directory, not token role claims; see `controller_api::oidc`. The CLI
//! uses device authorization and refresh grants from the same crate.

pub mod cache;
pub mod device;
pub mod discovery;
pub mod http;
pub mod jwks;
pub mod jwt;
#[cfg(any(test, feature = "testing"))]
pub mod testing;

pub use cache::{KeyCache, RefreshHandle};
pub use discovery::{Discovery, HttpKeySource, KeySource, Provider};
pub use jwks::{Alg, Curve, Jwk, JwkSet, Keys, PublicKey};
pub use jwt::{Claims, Validation, Verified, VerifyError, looks_like_a_jwt, verify};
