// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! OpenID Connect: the token half and the login half.
//!
//! Its own crate for the reason `pki` is one — both ends of the stack need
//! it and neither depends on the other. The cloud controller verifies the
//! tokens people arrive with (`jwt`, `jwks`, `cache`), the CLI is what gets
//! them one (`device`), and the two share the wire types, the base64url and
//! the small https client that talks to a provider.
//!
//! The rule this crate exists to keep, stated once here because every module
//! below assumes it: **a token proves who, and nothing else.** No role, no
//! tenant, no permission is read out of a claim. What a person may do is the
//! user directory's answer and stays the user directory's answer, so that a
//! role change there takes effect on the next request rather than on the
//! next token. See `controller_api::oidc`, which is the one place this crate
//! meets an `Identity`.

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
pub use jwt::{Claims, Validation, Verified, verify};
