// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! The device authorization grant, RFC 8628 — how a person logs in from a
//! terminal.
//!
//! The alternative was the authorization code flow with a redirect back to
//! `localhost`, and it was rejected for a practical reason rather than a
//! security one: this CLI is most often run over ssh on a machine with no
//! browser, and a redirect to that machine's `localhost` goes nowhere the
//! person can see. The device flow prints a code and a url instead, and the
//! browser can be on any device in the room.
//!
//! What comes back is a short-lived access token and, if the provider was
//! asked for offline access, a refresh token. Both matter. An access token
//! measured in minutes with no way to renew it means a person logs in again
//! every time they run two commands, which is not what they will do — they
//! will use the static bearer token instead, and the whole exercise will
//! have made things worse.

use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use serde::Deserialize;
use tracing::debug;

use crate::discovery::Provider;

/// The scopes asked for unless the operator says otherwise.
///
/// `offline_access` is what makes a refresh token appear at all, and it is
/// in the default for the reason in the module docs.
pub const DEFAULT_SCOPE: &str = "openid profile email offline_access";

/// What the provider says when the person still has to go and approve.
///
/// Five seconds if it does not say, which is RFC 8628's own default.
const FALLBACK_POLL_INTERVAL: u64 = 5;

/// RFC 8628 section 3.5: `slow_down` means add five seconds and try again.
const SLOW_DOWN_STEP: Duration = Duration::from_secs(5);

/// The provider's answer to "somebody wants to log in".
#[derive(Debug, Deserialize)]
pub struct DeviceAuth {
    pub device_code: String,
    pub user_code: String,
    pub verification_uri: String,
    /// The url with the code already in it, for a provider that offers one.
    /// Worth using where it exists: it is the difference between reading a
    /// code off a screen and following a link.
    #[serde(default)]
    pub verification_uri_complete: Option<String>,
    #[serde(default)]
    pub expires_in: Option<u64>,
    #[serde(default)]
    pub interval: Option<u64>,
}

impl DeviceAuth {
    pub fn poll_interval(&self) -> Duration {
        Duration::from_secs(self.interval.unwrap_or(FALLBACK_POLL_INTERVAL).clamp(1, 60))
    }

    pub fn expires_in(&self) -> Duration {
        Duration::from_secs(self.expires_in.unwrap_or(600))
    }
}

/// What a successful token endpoint call returns.
#[derive(Debug, Deserialize)]
pub struct Tokens {
    pub access_token: String,
    #[serde(default)]
    pub refresh_token: Option<String>,
    #[serde(default)]
    pub id_token: Option<String>,
    #[serde(default)]
    pub expires_in: Option<u64>,
    #[serde(default)]
    pub token_type: Option<String>,
}

/// What a failing one returns. OAuth puts the reason in the body, and the
/// three that are not failures at all are in here.
#[derive(Debug, Deserialize)]
struct OauthError {
    error: String,
    #[serde(default)]
    error_description: Option<String>,
}

impl OauthError {
    fn message(&self) -> String {
        match &self.error_description {
            Some(d) if !d.is_empty() => format!("{} ({})", self.error, d),
            _ => self.error.clone(),
        }
    }
}

fn endpoint<'a>(url: &'a Option<String>, what: &str, issuer: &str) -> Result<&'a str> {
    url.as_deref().filter(|u| !u.is_empty()).with_context(|| {
        format!("the discovery document for {issuer} names no {what}; this provider cannot be used this way")
    })
}

/// Step one: ask the provider to start a login, and get the code to show.
pub async fn start(provider: &Provider, client_id: &str, scope: &str) -> Result<DeviceAuth> {
    let url = endpoint(
        &provider.device_authorization_endpoint,
        "device_authorization_endpoint",
        &provider.issuer,
    )?;
    crate::http::post_form(
        url,
        &[("client_id", client_id), ("scope", scope)],
        provider.ca.as_deref(),
    )
    .await?
    .json()
    .context("starting the device login")
}

/// What one poll of the token endpoint found.
enum Poll {
    Got(Box<Tokens>),
    /// Nobody has approved yet. Keep waiting.
    Pending,
    /// Keep waiting, but less often.
    SlowDown,
}

async fn poll_once(
    token_endpoint: &str,
    client_id: &str,
    device_code: &str,
    ca: Option<&Path>,
) -> Result<Poll> {
    let res = crate::http::post_form(
        token_endpoint,
        &[
            ("client_id", client_id),
            ("device_code", device_code),
            ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
        ],
        ca,
    )
    .await?;

    if res.status.is_success() {
        let tokens: Tokens =
            serde_json::from_slice(&res.body).context("the provider's token answer")?;
        return Ok(Poll::Got(Box::new(tokens)));
    }

    // Everything else arrives as a 400 with a machine-readable reason. A
    // body that is not one of those is a provider doing something else, and
    // guessing about it would be worse than saying so.
    let Ok(err) = serde_json::from_slice::<OauthError>(&res.body) else {
        bail!(
            "the provider answered {} while waiting for approval: {}",
            res.status,
            String::from_utf8_lossy(&res.body).trim()
        );
    };
    match err.error.as_str() {
        "authorization_pending" => Ok(Poll::Pending),
        "slow_down" => Ok(Poll::SlowDown),
        "expired_token" => bail!("the login code expired before it was approved"),
        "access_denied" => bail!("the login was refused at the identity provider"),
        _ => bail!("the identity provider refused the login: {}", err.message()),
    }
}

/// Step two: wait for the person to finish in their browser.
///
/// `notify` is called once per poll with how long is left, so that the
/// caller can print whatever it prints — this crate has no opinion about a
/// terminal.
pub async fn wait_for_approval(
    provider: &Provider,
    client_id: &str,
    auth: &DeviceAuth,
    mut notify: impl FnMut(Duration),
) -> Result<Tokens> {
    let url = endpoint(&provider.token_endpoint, "token_endpoint", &provider.issuer)?;
    let mut interval = auth.poll_interval();
    let deadline = tokio::time::Instant::now() + auth.expires_in();

    loop {
        let left = deadline.saturating_duration_since(tokio::time::Instant::now());
        if left.is_zero() {
            bail!(
                "nobody approved the login within {}s; run the command again for a fresh code",
                auth.expires_in().as_secs()
            );
        }
        notify(left);
        tokio::time::sleep(interval.min(left)).await;

        match poll_once(url, client_id, &auth.device_code, provider.ca.as_deref()).await? {
            Poll::Got(tokens) => return Ok(*tokens),
            Poll::Pending => {}
            Poll::SlowDown => {
                interval += SLOW_DOWN_STEP;
                debug!(
                    interval = interval.as_secs(),
                    "the provider asked us to slow down"
                );
            }
        }
    }
}

/// Trade a refresh token for a fresh access token.
///
/// A provider is allowed to rotate the refresh token as it does this and
/// several do, so the caller has to store what comes back rather than
/// keeping the one it sent.
pub async fn refresh(provider: &Provider, client_id: &str, refresh_token: &str) -> Result<Tokens> {
    let url = endpoint(&provider.token_endpoint, "token_endpoint", &provider.issuer)?;
    let res = crate::http::post_form(
        url,
        &[
            ("client_id", client_id),
            ("refresh_token", refresh_token),
            ("grant_type", "refresh_token"),
        ],
        provider.ca.as_deref(),
    )
    .await?;
    if res.status.is_success() {
        return serde_json::from_slice(&res.body).context("the provider's token answer");
    }
    match serde_json::from_slice::<OauthError>(&res.body) {
        // The one an operator has to be able to act on: the refresh token is
        // spent, revoked or expired, and the answer is to log in again.
        Ok(e) if e.error == "invalid_grant" => bail!(
            "the stored refresh token is no longer accepted ({}); log in again",
            e.message()
        ),
        Ok(e) => bail!("the identity provider refused the refresh: {}", e.message()),
        Err(_) => bail!(
            "the provider answered {} to the refresh: {}",
            res.status,
            String::from_utf8_lossy(&res.body).trim()
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn provider() -> Provider {
        Provider {
            issuer: "https://idp.example.org".into(),
            jwks_uri: "https://idp.example.org/keys".into(),
            token_endpoint: Some("https://idp.example.org/token".into()),
            device_authorization_endpoint: None,
            ca: None,
        }
    }

    /// A provider that does not offer the device grant has to say so in
    /// words, not fail at a request to an empty url.
    #[test]
    fn a_provider_without_the_device_endpoint_says_which_one_is_missing() {
        let p = provider();
        let err = endpoint(
            &p.device_authorization_endpoint,
            "device_authorization_endpoint",
            &p.issuer,
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("device_authorization_endpoint"),
            "{err}"
        );
        assert!(err.to_string().contains("idp.example.org"), "{err}");

        endpoint(&p.token_endpoint, "token_endpoint", &p.issuer).unwrap();
    }

    /// The provider's own interval is used, its absence is RFC 8628's five
    /// seconds, and a provider asking us to poll every hour or every
    /// millisecond gets a bound instead.
    #[test]
    fn the_poll_interval_comes_from_the_provider_within_reason() {
        let mk = |interval: Option<u64>| DeviceAuth {
            device_code: "d".into(),
            user_code: "ABCD-EFGH".into(),
            verification_uri: "https://idp.example.org/device".into(),
            verification_uri_complete: None,
            expires_in: None,
            interval,
        };
        assert_eq!(mk(Some(3)).poll_interval(), Duration::from_secs(3));
        assert_eq!(mk(None).poll_interval(), Duration::from_secs(5));
        assert_eq!(mk(Some(0)).poll_interval(), Duration::from_secs(1));
        assert_eq!(mk(Some(99999)).poll_interval(), Duration::from_secs(60));
        assert_eq!(mk(None).expires_in(), Duration::from_secs(600));
    }

    /// The three answers that are not failures, and the ones that are.
    #[test]
    fn an_oauth_error_body_carries_its_reason() {
        let e: OauthError = serde_json::from_str(
            r#"{"error":"authorization_pending","error_description":"still waiting"}"#,
        )
        .unwrap();
        assert_eq!(e.error, "authorization_pending");
        assert_eq!(e.message(), "authorization_pending (still waiting)");

        let e: OauthError = serde_json::from_str(r#"{"error":"slow_down"}"#).unwrap();
        assert_eq!(e.message(), "slow_down");
    }

    /// A refresh token is optional in the type and required in practice; the
    /// default scope is what makes the provider send one.
    #[test]
    fn the_default_scope_asks_for_offline_access() {
        assert!(DEFAULT_SCOPE.contains("openid"));
        assert!(
            DEFAULT_SCOPE.contains("offline_access"),
            "without it there is no refresh token and nobody will use this"
        );
    }
}
