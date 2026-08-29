// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Where the provider keeps things, asked once, plus the task that keeps the
//! keys current.
//!
//! `KeySource` is the seam the brief asks for and the reason none of this
//! needs a running identity provider to test: everything above it — the
//! cache, the rate limit, the authenticator, the whole table of tokens that
//! must be refused — talks to a trait, and the test hands it a document.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use serde::Deserialize;
use tokio::sync::Mutex;
use tracing::{debug, info, warn};

use crate::cache::{KeyCache, RefreshHandle};
use crate::jwks::{JwkSet, Keys};

/// The `.well-known/openid-configuration` document, in the parts we use.
#[derive(Clone, Debug, Deserialize)]
pub struct Discovery {
    pub issuer: String,
    pub jwks_uri: String,
    #[serde(default)]
    pub token_endpoint: Option<String>,
    #[serde(default)]
    pub device_authorization_endpoint: Option<String>,
}

/// A provider, resolved.
#[derive(Clone, Debug)]
pub struct Provider {
    pub issuer: String,
    pub jwks_uri: String,
    pub token_endpoint: Option<String>,
    pub device_authorization_endpoint: Option<String>,
    pub ca: Option<PathBuf>,
}

/// The url the document lives at, per RFC 8414: the issuer with the
/// well-known path appended, and not a path the issuer replaces.
pub fn discovery_url(issuer: &str) -> String {
    format!(
        "{}/.well-known/openid-configuration",
        issuer.trim_end_matches('/')
    )
}

/// Check the document against the issuer it was asked for.
///
/// RFC 8414 section 3.3, and it is not a formality: without it a provider
/// that has been persuaded to serve somebody else's document — or a config
/// with a typo pointing at the wrong tenant of the same provider — hands
/// this controller a `jwks_uri` of the attacker's choosing, and every token
/// that key signs is then a valid token here.
pub fn check_issuer(doc: &Discovery, expected: &str) -> Result<()> {
    if doc.issuer.trim_end_matches('/') != expected.trim_end_matches('/') {
        bail!(
            "the discovery document at {expected:?} says its issuer is {:?}; \
             refusing to take a key set from it",
            doc.issuer
        );
    }
    if doc.jwks_uri.is_empty() {
        bail!("the discovery document for {expected:?} names no jwks_uri");
    }
    Ok(())
}

pub async fn discover(issuer: &str, ca: Option<&std::path::Path>) -> Result<Provider> {
    let url = discovery_url(issuer);
    let doc: Discovery = crate::http::get(&url, ca)
        .await?
        .json()
        .with_context(|| format!("reading the discovery document at {url}"))?;
    check_issuer(&doc, issuer)?;
    Ok(Provider {
        issuer: doc.issuer,
        jwks_uri: doc.jwks_uri,
        token_endpoint: doc.token_endpoint,
        device_authorization_endpoint: doc.device_authorization_endpoint,
        ca: ca.map(|p| p.to_path_buf()),
    })
}

/// Where a key set comes from. One method, so that a test can be a closure
/// over a string.
#[async_trait::async_trait]
pub trait KeySource: Send + Sync {
    async fn fetch(&self) -> Result<JwkSet>;
    /// For log lines only.
    fn describe(&self) -> String;
}

/// The real one: discovery once, then the `jwks_uri` it named.
///
/// Discovery is repeated only if it has never succeeded. A provider that
/// moves its `jwks_uri` between two fetches is a provider that will be
/// followed at the next restart, and re-reading the document on every fetch
/// would double the traffic for a change that happens once a decade.
pub struct HttpKeySource {
    issuer: String,
    ca: Option<PathBuf>,
    jwks_uri: Mutex<Option<String>>,
}

impl HttpKeySource {
    pub fn new(issuer: impl Into<String>, ca: Option<PathBuf>) -> Self {
        Self {
            issuer: issuer.into(),
            ca,
            jwks_uri: Mutex::new(None),
        }
    }
}

#[async_trait::async_trait]
impl KeySource for HttpKeySource {
    async fn fetch(&self) -> Result<JwkSet> {
        let mut cached = self.jwks_uri.lock().await;
        let uri = match cached.clone() {
            Some(uri) => uri,
            None => {
                let provider = discover(&self.issuer, self.ca.as_deref()).await?;
                info!(
                    issuer = %provider.issuer,
                    jwks_uri = %provider.jwks_uri,
                    "discovered the identity provider"
                );
                *cached = Some(provider.jwks_uri.clone());
                provider.jwks_uri
            }
        };
        drop(cached);
        crate::http::get(&uri, self.ca.as_deref())
            .await?
            .json()
            .with_context(|| format!("reading the key set at {uri}"))
    }

    fn describe(&self) -> String {
        self.issuer.clone()
    }
}

/// Keep a cache current: once at start-up, on every nudge, and on a timer.
///
/// Runs until the nudge channel closes, which happens when the last
/// authenticator holding it is dropped — so a controller shutting down takes
/// this with it and nothing has to be told twice.
pub async fn refresh_forever(
    cache: Arc<KeyCache>,
    source: Arc<dyn KeySource>,
    mut handle: RefreshHandle,
    interval: Duration,
    retry: Duration,
) {
    loop {
        match source.fetch().await {
            Ok(set) => {
                let keys = Keys::parse(&set);
                if keys.is_empty() {
                    // Not an error to us: the provider answered, and what it
                    // said was "nothing usable". Loud, because every token
                    // will now be refused and the reason is at the far end.
                    warn!(
                        provider = %source.describe(),
                        "the identity provider published no usable signing keys"
                    );
                }
                debug!(provider = %source.describe(), keys = keys.len(), "key set refreshed");
                cache.install(keys);
            }
            Err(e) => warn!(
                provider = %source.describe(),
                error = %format!("{e:#}"),
                "could not refresh the identity provider's keys, keeping the ones we have"
            ),
        }

        // A cache that has never loaded retries at the short interval: at
        // start-up the provider may simply not be up yet, and an hour is a
        // long time to be answering 401 to everybody.
        let wait = if cache.loaded() { interval } else { retry };
        tokio::select! {
            got = handle.rx.recv() => {
                if got.is_none() {
                    debug!("nothing holds the key cache any more, stopping the refresher");
                    return;
                }
            }
            _ = tokio::time::sleep(wait) => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn doc(issuer: &str) -> Discovery {
        Discovery {
            issuer: issuer.to_string(),
            jwks_uri: "https://idp.example.org/keys".into(),
            token_endpoint: None,
            device_authorization_endpoint: None,
        }
    }

    #[test]
    fn the_well_known_path_is_appended_not_substituted() {
        assert_eq!(
            discovery_url("https://idp.example.org/realms/lab"),
            "https://idp.example.org/realms/lab/.well-known/openid-configuration"
        );
        // A trailing slash is the operator's, not a second path segment.
        assert_eq!(
            discovery_url("https://idp.example.org/"),
            "https://idp.example.org/.well-known/openid-configuration"
        );
    }

    /// A document that names a different issuer is a document that gets to
    /// choose our signing keys. It does not.
    #[test]
    fn a_document_that_disowns_the_issuer_is_refused() {
        let err =
            check_issuer(&doc("https://elsewhere.example"), "https://idp.example.org").unwrap_err();
        assert!(err.to_string().contains("elsewhere.example"), "{err}");

        check_issuer(&doc("https://idp.example.org"), "https://idp.example.org").unwrap();
        // The trailing slash is the one difference that is not one.
        check_issuer(&doc("https://idp.example.org/"), "https://idp.example.org").unwrap();
    }

    #[test]
    fn a_document_without_a_jwks_uri_is_refused() {
        let mut d = doc("https://idp.example.org");
        d.jwks_uri = String::new();
        assert!(check_issuer(&d, "https://idp.example.org").is_err());
    }
}
