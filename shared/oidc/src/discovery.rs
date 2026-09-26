// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! OIDC discovery and background signing-key refresh.
//!
//! [`KeySource`] separates document retrieval from cache and verification logic,
//! allowing those paths to be tested without a live provider.

use std::path::PathBuf;
use std::sync::{Arc, Weak};
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

/// Match discovery issuer to configuration, ignoring trailing slashes.
/// Reject mismatches before trusting the document's signing-key location.
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

/// HTTP key source caching the first successful discovery document.
/// Subsequent refreshes reuse its JWKS URI until this source is reconstructed.
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

/// Refresh at startup, on a nudge and periodically. Hold the cache weakly
/// so dropping the last authenticator also drops the sender and ends this task.
pub async fn refresh_forever(
    cache: Weak<KeyCache>,
    source: Arc<dyn KeySource>,
    mut handle: RefreshHandle,
    interval: Duration,
    retry: Duration,
) {
    loop {
        let Some(cache) = cache.upgrade() else {
            debug!("nothing holds the key cache any more, stopping the refresher");
            return;
        };
        match source.fetch().await {
            Ok(set) => {
                let keys = Keys::parse(&set);
                if keys.is_empty() {
                    // Warn when the provider returns no usable keys because token verification will fail.
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
        // Held only while fetching. Waiting on a strong handle would keep
        // the cache alive for up to an hour after its last user left.
        drop(cache);
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
        // Issuer comparison ignores a trailing slash.
        check_issuer(&doc("https://idp.example.org/"), "https://idp.example.org").unwrap();
    }

    /// Advance the paused test runtime until the refresher reaches its next wait.
    async fn settle() {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    /// Scripted key source for exercising cache, refresh and authentication without a provider.
    struct Scripted {
        answers: Mutex<Vec<Result<String, String>>>,
        calls: std::sync::atomic::AtomicUsize,
    }

    impl Scripted {
        fn new(answers: Vec<Result<String, String>>) -> Arc<Self> {
            Arc::new(Self {
                answers: Mutex::new(answers),
                calls: std::sync::atomic::AtomicUsize::new(0),
            })
        }

        fn calls(&self) -> usize {
            self.calls.load(std::sync::atomic::Ordering::SeqCst)
        }
    }

    #[async_trait::async_trait]
    impl KeySource for Scripted {
        async fn fetch(&self) -> Result<JwkSet> {
            self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let mut answers = self.answers.lock().await;
            // The last answer repeats, so a test can say "and from then on".
            let answer = if answers.len() > 1 {
                answers.remove(0)
            } else {
                answers.first().cloned().unwrap_or_else(|| Ok("{}".into()))
            };
            match answer {
                Ok(body) => Ok(serde_json::from_str(&body)?),
                Err(e) => bail!("{e}"),
            }
        }

        fn describe(&self) -> String {
            "scripted".into()
        }
    }

    /// Fetch initially and on refresh requests, with cache-wide throttling.
    #[tokio::test(start_paused = true)]
    async fn a_nudge_fetches_and_the_first_fetch_happens_without_one() {
        let idp = crate::testing::TestIdp::new("k1");
        let source = Scripted::new(vec![Ok(idp.jwk_set_json().to_string())]);
        let (cache, handle) = KeyCache::new(Duration::from_secs(60));
        let cache = Arc::new(cache);

        let task = tokio::spawn(refresh_forever(
            Arc::downgrade(&cache),
            source.clone(),
            handle,
            Duration::from_secs(3600),
            Duration::from_secs(60),
        ));

        // Startup fetch does not require a login request.
        settle().await;
        assert!(cache.loaded());
        assert_eq!(cache.with_keys(|k| k.len()), 1);
        assert_eq!(source.calls(), 1);

        // A request meets an unknown key id and asks.
        assert!(cache.request_refresh());
        settle().await;
        assert_eq!(source.calls(), 2);

        // Suppress repeated refresh requests within the minimum interval.
        for _ in 0..100 {
            assert!(!cache.request_refresh());
        }
        settle().await;
        assert_eq!(source.calls(), 2, "the interval held");

        task.abort();
    }

    /// Failed refresh retains previously cached keys.
    #[tokio::test(start_paused = true)]
    async fn a_failed_fetch_keeps_the_keys_we_already_had() {
        let idp = crate::testing::TestIdp::new("k1");
        let source = Scripted::new(vec![
            Ok(idp.jwk_set_json().to_string()),
            Err("connection refused".into()),
        ]);
        let (cache, handle) = KeyCache::new(Duration::from_secs(0));
        let cache = Arc::new(cache);

        let task = tokio::spawn(refresh_forever(
            Arc::downgrade(&cache),
            source.clone(),
            handle,
            Duration::from_secs(3600),
            Duration::from_secs(60),
        ));
        settle().await;
        assert_eq!(cache.with_keys(|k| k.len()), 1);

        assert!(cache.request_refresh());
        settle().await;
        assert!(source.calls() >= 2, "the failing fetch was attempted");
        assert_eq!(cache.with_keys(|k| k.len()), 1, "and cost us nothing");
        assert!(cache.loaded());

        task.abort();
    }

    /// The refresher is owned by the authenticator it feeds: when the last
    /// holder of the nudge channel goes, so does it. Nothing has to be told.
    #[tokio::test(start_paused = true)]
    async fn the_refresher_stops_when_nothing_holds_the_cache_any_more() {
        let source = Scripted::new(vec![Ok(r#"{"keys":[]}"#.into())]);
        let (cache, handle) = KeyCache::new(Duration::from_secs(60));
        let cache = Arc::new(cache);

        let task = tokio::spawn(refresh_forever(
            Arc::downgrade(&cache),
            source,
            handle,
            Duration::from_secs(3600),
            Duration::from_secs(60),
        ));
        settle().await;
        drop(cache);
        settle().await;
        assert!(task.await.is_ok(), "it returned rather than being killed");
    }

    #[test]
    fn a_document_without_a_jwks_uri_is_refused() {
        let mut d = doc("https://idp.example.org");
        d.jwks_uri = String::new();
        assert!(check_issuer(&d, "https://idp.example.org").is_err());
    }
}
