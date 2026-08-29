// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! `meister login --oidc` — a person logs in, from a terminal.
//!
//! The device authorization grant and not a redirect to `localhost`, and the
//! reason is practical rather than cryptographic: this CLI is most often run
//! over ssh on a machine with no browser, and a redirect to that machine's
//! `localhost` goes somewhere nobody can see. A code and a url can be
//! carried to whatever device has a browser.
//!
//! What is stored afterwards is one file per profile, at 0600, next to
//! everything else this CLI keeps secret — and the refresh token in it is
//! the part that decides whether any of this gets used. Access tokens last
//! minutes. Without a refresh token a person logs in again between two
//! commands, which they will not do; they will go back to the static bearer
//! token, and the exercise will have made things worse.

use std::path::Path;

use anyhow::{Context, Result, bail};
use chrono::{DateTime, Utc};
use meister_oidc::device::{self, DEFAULT_SCOPE};
use meister_oidc::discovery::{self, Provider};
use serde::{Deserialize, Serialize};

use crate::config::{Credential, OidcSource, Target};
use crate::{GlobalArgs, OutputFormat};

/// How much of an access token's life has to be left for it to be worth
/// sending. A request takes a moment and clocks drift; a token that expires
/// while it is in flight is a 401 for no reason.
const FRESHNESS_MARGIN: chrono::TimeDelta = chrono::TimeDelta::seconds(60);

/// What one logged-in profile keeps on disk.
///
/// The issuer and the client id are in here as well as in the config so that
/// a profile that has been repointed at another provider is caught: the
/// session is then somebody else's and the answer is to log in again, not to
/// send a token the new provider never issued.
#[derive(Debug, Serialize, Deserialize)]
pub struct Session {
    pub issuer: String,
    pub client_id: String,
    pub access_token: String,
    #[serde(default)]
    pub refresh_token: Option<String>,
    pub expires_at: DateTime<Utc>,
    #[serde(default)]
    pub scope: Option<String>,
}

impl Session {
    pub fn load(path: &Path) -> Result<Self> {
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("reading the oidc session {}", path.display()))?;
        serde_json::from_str(&raw)
            .with_context(|| format!("parsing the oidc session {}", path.display()))
    }

    /// 0600, through the same writer the private key goes through. A session
    /// file is a credential; it is not config that happens to be sensitive.
    pub fn save(&self, path: &Path) -> Result<()> {
        pki::write_secret(path, &serde_json::to_string_pretty(self)?)
            .with_context(|| format!("writing the oidc session {}", path.display()))
    }

    /// The access token, if it is still worth sending.
    pub fn usable_at(&self, now: DateTime<Utc>) -> Option<String> {
        (now + FRESHNESS_MARGIN < self.expires_at).then(|| self.access_token.clone())
    }

    pub fn usable_now(&self) -> Option<String> {
        self.usable_at(Utc::now())
    }

    /// Fold what the provider just returned into the stored session.
    ///
    /// The refresh token is replaced only when a new one came back, because
    /// a provider is entitled to rotate it and several do — but one that
    /// does not rotate simply omits the field, and dropping the old one then
    /// would end the session at its first renewal.
    fn apply(&mut self, tokens: device::Tokens, now: DateTime<Utc>) {
        self.access_token = tokens.access_token;
        if let Some(fresh) = tokens.refresh_token {
            self.refresh_token = Some(fresh);
        }
        self.expires_at = now + chrono::TimeDelta::seconds(tokens.expires_in.unwrap_or(300) as i64);
    }
}

fn provider_of(src: &OidcSource) -> impl std::future::Future<Output = Result<Provider>> + '_ {
    discovery::discover(&src.issuer, src.ca_cert.as_deref())
}

/// Renew a session whose access token has run out, before anything is sent.
///
/// Called once per command, for every command. It is a no-op for every
/// credential that is not a stale OIDC session, which is all of them until
/// somebody configures a provider.
pub async fn freshen(target: &mut Target) -> Result<()> {
    if !matches!(target.credential, Credential::StaleOidc) {
        return Ok(());
    }
    let src = target
        .oidc
        .clone()
        .context("internal: a stale oidc session without a source")?;
    let mut session = Session::load(&src.tokens)?;
    if session.issuer != src.issuer || session.client_id != src.client_id {
        bail!(
            "the session at {} belongs to {} and this profile now points at {}; \
             run: meister login --oidc",
            src.tokens.display(),
            session.issuer,
            src.issuer
        );
    }
    let Some(refresh_token) = session.refresh_token.clone() else {
        bail!(
            "the session at {} has expired and carries no refresh token \
             (the provider was not asked for offline access); run: meister login --oidc",
            src.tokens.display()
        );
    };

    let provider = provider_of(&src).await?;
    let tokens = device::refresh(&provider, &src.client_id, &refresh_token).await?;
    session.apply(tokens, Utc::now());
    session.save(&src.tokens)?;
    tracing::debug!(
        profile = %target.profile_name,
        expires_at = %session.expires_at,
        "renewed the oidc session"
    );
    target.credential = Credential::Bearer(session.access_token);
    Ok(())
}

/// `meister login --oidc`.
pub async fn login(target: &Target, global: &GlobalArgs) -> Result<()> {
    let Some(src) = target.oidc.clone() else {
        bail!(
            "profile {:?} names no identity provider; add:\n\n\
             [profiles.{}]\n\
             credential = {{ type = \"oidc\", issuer = \"https://idp.example.org\", \
             client_id = \"meisterstack\" }}\n",
            target.profile_name,
            target.profile_name
        );
    };

    let provider = provider_of(&src).await?;
    let scope = src.scope.as_deref().unwrap_or(DEFAULT_SCOPE);
    let auth = device::start(&provider, &src.client_id, scope).await?;

    // On stderr, all of it: what this command PRINTS on stdout is the
    // machine-readable result, and a code somebody has to read is neither.
    match &auth.verification_uri_complete {
        Some(complete) => eprintln!("\nto finish logging in, open\n\n    {complete}\n"),
        None => eprintln!(
            "\nto finish logging in, open\n\n    {}\n\nand enter the code\n\n    {}\n",
            auth.verification_uri, auth.user_code
        ),
    }

    let mut announced = false;
    let tokens = device::wait_for_approval(&provider, &src.client_id, &auth, |left| {
        if !announced {
            announced = true;
            eprintln!("waiting up to {}s for approval ...", left.as_secs());
        }
    })
    .await?;

    if tokens.refresh_token.is_none() {
        // Not fatal, but it is the difference between a login that lasts a
        // day and one that lasts five minutes, and the fix is at the
        // provider rather than here.
        eprintln!(
            "warning: the provider returned no refresh token; this session ends when the \
             access token does.\n         Ask for \"offline_access\" in the profile's scope, \
             and check that the client is allowed it."
        );
    }

    let now = Utc::now();
    let mut session = Session {
        issuer: src.issuer.clone(),
        client_id: src.client_id.clone(),
        access_token: String::new(),
        refresh_token: None,
        expires_at: now,
        scope: Some(scope.to_string()),
    };
    session.apply(tokens, now);
    session.save(&src.tokens)?;

    match global.output {
        OutputFormat::Json => println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "profile": target.profile_name,
                "issuer": session.issuer,
                "clientId": session.client_id,
                "expiresAt": session.expires_at,
                "renewable": session.refresh_token.is_some(),
                "session": src.tokens,
            }))?
        ),
        OutputFormat::Table => {
            println!("{}", session.issuer);
            eprintln!(
                "  profile     {}\n  expires     {}\n  renewable   {}\n  session     {}",
                target.profile_name,
                session.expires_at,
                if session.refresh_token.is_some() {
                    "yes"
                } else {
                    "no"
                },
                src.tokens.display()
            );
            // Said plainly because it is the thing people get wrong about
            // OIDC: the provider has said who you are and nothing else. What
            // you may do here is the cloud's user directory's answer, and if
            // it does not know this name yet, every command is a 403 until
            // an administrator enters it.
            eprintln!(
                "\nthe provider has said WHO you are. What you may do is the cloud's user\n\
                 directory's answer -- if it does not know this name, an administrator runs\n\
                 `meister cloud user create` before anything else works."
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn session(expires_in: i64) -> Session {
        Session {
            issuer: "https://idp.example.org".into(),
            client_id: "meisterstack".into(),
            access_token: "at-1".into(),
            refresh_token: Some("rt-1".into()),
            expires_at: Utc::now() + chrono::TimeDelta::seconds(expires_in),
            scope: None,
        }
    }

    /// A token that expires while the request is in flight is a 401 for no
    /// reason, so the margin is on the near side of expiry.
    #[test]
    fn a_token_about_to_expire_is_already_stale() {
        assert!(session(3600).usable_now().is_some());
        assert!(session(30).usable_now().is_none(), "inside the margin");
        assert!(session(-1).usable_now().is_none());
    }

    /// A provider that rotates the refresh token is followed; one that does
    /// not, and therefore omits the field, does not lose the one we hold.
    /// Getting this backwards ends every session at its first renewal.
    #[test]
    fn a_refresh_token_is_replaced_only_when_a_new_one_arrives() {
        let now = Utc::now();

        let mut s = session(0);
        s.apply(
            serde_json::from_str(r#"{"access_token":"at-2","expires_in":300}"#).unwrap(),
            now,
        );
        assert_eq!(s.access_token, "at-2");
        assert_eq!(s.refresh_token.as_deref(), Some("rt-1"), "kept");
        assert_eq!(s.expires_at, now + chrono::TimeDelta::seconds(300));

        let mut s = session(0);
        s.apply(
            serde_json::from_str(
                r#"{"access_token":"at-3","refresh_token":"rt-2","expires_in":600}"#,
            )
            .unwrap(),
            now,
        );
        assert_eq!(s.refresh_token.as_deref(), Some("rt-2"), "rotated");
    }

    /// A provider that says nothing about lifetime gets the short assumption
    /// rather than the long one: guessing high means sending dead tokens.
    #[test]
    fn a_provider_that_names_no_lifetime_is_assumed_to_be_brief() {
        let now = Utc::now();
        let mut s = session(0);
        s.apply(
            serde_json::from_str(r#"{"access_token":"at"}"#).unwrap(),
            now,
        );
        assert_eq!(s.expires_at, now + chrono::TimeDelta::seconds(300));
    }

    /// The file is a credential and is written like one.
    #[test]
    fn a_session_file_is_written_at_0600_and_reads_back() {
        let dir = std::env::temp_dir().join(format!("meister-oidc-test-{}", std::process::id()));
        let path = dir.join("p.json");
        let s = session(3600);
        s.save(&path).unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "a session file is a credential");
        }

        let back = Session::load(&path).unwrap();
        assert_eq!(back.access_token, s.access_token);
        assert_eq!(back.refresh_token, s.refresh_token);
        std::fs::remove_dir_all(&dir).ok();
    }
}
