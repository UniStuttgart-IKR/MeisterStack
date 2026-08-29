// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! The provider's keys, held between requests, and the one rate limit that
//! keeps holding them from becoming a way to hit the provider.
//!
//! The shape here is decided by the shape of the thing above it: an
//! `Authenticator` is a synchronous function, and fetching a document is
//! not. So the request path never fetches. It reads the cache, and when a
//! token names a key the cache does not have it drops a note on a channel
//! and **refuses the request**. A background task picks the note up and
//! fetches; the next request carrying that key succeeds.
//!
//! Refusing rather than waiting is the deliberate half. Waiting would mean
//! a request blocking a worker thread on somebody else's http server, and a
//! provider that has become slow would turn into an API that has stopped
//! answering. One request loses a race with a key rotation; nothing else
//! does.
//!
//! And the note is rate limited, which is the attack this file exists to
//! close. A refetch per unknown `kid` is a request per token, and tokens are
//! free to make: an attacker with a shell script and a random `kid` per
//! token would have this controller hammering its own identity provider.
//! `min_interval` is the ceiling on that, and it is per cache rather than
//! per `kid` — counting `kid`s would only move the unbounded thing.

use std::sync::Mutex;
use std::time::Duration;

use chrono::{DateTime, Utc};
use tokio::sync::mpsc;

use crate::jwks::Keys;

/// The floor between two fetches asked for by the request path. Long enough
/// that a token flood is one fetch, short enough that a real key rotation
/// costs one person one retry.
pub const DEFAULT_MIN_REFETCH_INTERVAL: Duration = Duration::from_secs(60);

/// How often to refetch with nobody asking, so that a rotation is usually
/// picked up before any request meets an unknown key at all.
pub const DEFAULT_REFRESH_INTERVAL: Duration = Duration::from_secs(3600);

struct State {
    keys: Keys,
    /// Whether a fetch has ever succeeded. Distinguishes "the provider
    /// publishes no keys" from "we have not asked yet", which are the same
    /// empty set and very different answers to give a caller.
    loaded: bool,
    last_request: Option<DateTime<Utc>>,
}

pub struct KeyCache {
    state: Mutex<State>,
    min_interval: Duration,
    /// Capacity one, and `try_send` on a full channel is a success: a second
    /// note while the first is unread says nothing the first did not.
    nudge: mpsc::Sender<()>,
}

/// The other end of the nudge channel, handed to whatever drives the fetch.
pub struct RefreshHandle {
    pub rx: mpsc::Receiver<()>,
}

impl KeyCache {
    pub fn new(min_interval: Duration) -> (Self, RefreshHandle) {
        let (tx, rx) = mpsc::channel(1);
        (
            Self {
                state: Mutex::new(State {
                    keys: Keys::default(),
                    loaded: false,
                    last_request: None,
                }),
                min_interval,
                nudge: tx,
            },
            RefreshHandle { rx },
        )
    }

    /// Read the keys under the lock without cloning one out of it.
    pub fn with_keys<R>(&self, f: impl FnOnce(&Keys) -> R) -> R {
        let state = self
            .state
            .lock()
            .expect("the key cache lock is not held across an await");
        f(&state.keys)
    }

    /// Whether a fetch has ever landed.
    pub fn loaded(&self) -> bool {
        self.state.lock().expect("see with_keys").loaded
    }

    /// What a fetch found. Replaces wholesale: a JWKS document is the
    /// provider's complete current answer, and merging would keep a key the
    /// provider has just withdrawn.
    pub fn install(&self, keys: Keys) {
        let mut state = self.state.lock().expect("see with_keys");
        state.keys = keys;
        state.loaded = true;
    }

    /// Ask for a refetch on behalf of a request that met an unknown key.
    ///
    /// Returns whether the ask went through, which is the whole of the rate
    /// limit and the thing the test asserts. A `false` is not an error: it
    /// means somebody asked recently enough that this request's answer would
    /// not have been any different.
    pub fn request_refresh_at(&self, now: DateTime<Utc>) -> bool {
        let mut state = self.state.lock().expect("see with_keys");
        let floor = chrono::Duration::from_std(self.min_interval)
            .unwrap_or_else(|_| chrono::Duration::zero());
        if let Some(last) = state.last_request
            && now < last + floor
        {
            return false;
        }
        state.last_request = Some(now);
        drop(state);
        // Never blocks and never panics outside a runtime: a full channel
        // already carries the message this one would have.
        let _ = self.nudge.try_send(());
        true
    }

    pub fn request_refresh(&self) -> bool {
        self.request_refresh_at(Utc::now())
    }
}

impl std::fmt::Debug for KeyCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let state = self.state.lock().expect("see with_keys");
        write!(
            f,
            "KeyCache({} keys, loaded={})",
            state.keys.len(),
            state.loaded
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(secs: i64) -> DateTime<Utc> {
        DateTime::from_timestamp(1_800_000_000 + secs, 0).unwrap()
    }

    /// The rate limit, which is the point of this file. A flood of tokens
    /// with invented key ids is one fetch per minute and not one per token.
    #[test]
    fn a_flood_of_unknown_key_ids_asks_the_provider_once_per_interval() {
        let (cache, mut handle) = KeyCache::new(Duration::from_secs(60));

        assert!(
            cache.request_refresh_at(at(0)),
            "the first ask goes through"
        );
        for i in 1..1000 {
            assert!(
                !cache.request_refresh_at(at(i % 60)),
                "ask {i} inside the interval must not reach the provider"
            );
        }
        assert!(
            cache.request_refresh_at(at(60)),
            "and once it is up, it does"
        );

        // One note on the channel however many asks were refused: the
        // background task is being told "fetch", not "fetch 1000 times".
        assert!(handle.rx.try_recv().is_ok());
        assert!(handle.rx.try_recv().is_err());
    }

    /// The empty cache is not the same as a provider with no keys, and the
    /// request path has to be able to say which it met.
    #[test]
    fn a_cache_that_has_never_fetched_says_so() {
        let (cache, _handle) = KeyCache::new(Duration::from_secs(60));
        assert!(!cache.loaded());
        assert_eq!(cache.with_keys(|k| k.len()), 0);

        cache.install(Keys::default());
        assert!(cache.loaded(), "an empty answer is still an answer");
    }

    /// A fetch replaces; it does not merge. A withdrawn key has to stop
    /// verifying tokens the moment the provider stops publishing it.
    #[test]
    fn installing_replaces_the_whole_set() {
        let (cache, _handle) = KeyCache::new(Duration::from_secs(60));
        let set: crate::jwks::JwkSet = serde_json::from_str(
            r#"{"keys":[{"kty":"EC","kid":"a","crv":"P-256","x":"","y":""}]}"#,
        )
        .unwrap();
        cache.install(Keys::parse(&set));
        // That key is malformed and dropped, which is its own assertion.
        assert_eq!(cache.with_keys(|k| k.len()), 0);
        cache.install(Keys::default());
        assert_eq!(cache.with_keys(|k| k.len()), 0);
    }
}
