// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! OIDC device login and session refresh. Sessions are stored per profile at mode 0600.

use std::path::Path;

use anyhow::{Context, Result, bail};
use chrono::{DateTime, Utc};
use meister_oidc::device::{self, DEFAULT_SCOPE};
use meister_oidc::discovery::{self, Provider};
use serde::{Deserialize, Serialize};

use crate::config::{Credential, OidcSource, Target};
use crate::{GlobalArgs, OutputFormat};

/// Refresh tokens within sixty seconds of the recorded expiry.
const FRESHNESS_MARGIN: chrono::TimeDelta = chrono::TimeDelta::seconds(60);

/// Persisted OIDC session. The refresh path checks issuer and client ID
/// against the current profile before contacting the provider.
#[derive(Debug, Serialize, Deserialize)]
pub struct Session {
    pub issuer: String,
    pub client_id: String,
    pub access_token: String,
    /// Preferred bearer when present. The control plane requires the configured
    /// identity claim, commonly supplied by the provider in an ID token.
    #[serde(default)]
    pub id_token: Option<String>,
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

    /// Write the session through the private-key writer, with mode 0600.
    pub fn save(&self, path: &Path) -> Result<()> {
        pki::write_secret(path, &serde_json::to_string_pretty(self)?)
            .with_context(|| format!("writing the oidc session {}", path.display()))
    }

    /// Use the ID token when present; otherwise use the access token.
    pub fn bearer(&self) -> String {
        self.id_token
            .clone()
            .unwrap_or_else(|| self.access_token.clone())
    }

    /// Return a bearer before the recorded access-token expiry minus the margin.
    /// The ID token's own expiry is not inspected here.
    pub fn usable_at(&self, now: DateTime<Utc>) -> Option<String> {
        (now + FRESHNESS_MARGIN < self.expires_at).then(|| self.bearer())
    }

    pub fn usable_now(&self) -> Option<String> {
        self.usable_at(Utc::now())
    }

    /// Apply a token response, retaining the refresh token if it was not rotated.
    fn apply(&mut self, tokens: device::Tokens, now: DateTime<Utc>) {
        self.access_token = tokens.access_token;
        if let Some(fresh) = tokens.refresh_token {
            self.refresh_token = Some(fresh);
        }
        // Do not retain an old ID token when refresh returns only an access token.
        self.id_token = tokens.id_token;
        self.expires_at = now + chrono::TimeDelta::seconds(tokens.expires_in.unwrap_or(300) as i64);
    }
}

fn provider_of(src: &OidcSource) -> impl std::future::Future<Output = Result<Provider>> + '_ {
    discovery::discover(&src.issuer, src.ca_cert.as_deref())
}

/// Renew a StaleOidc credential before a command; other credentials are unchanged.
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
    target.credential = Credential::Bearer(session.bearer());
    Ok(())
}

/// `meister login --oidc`.
pub async fn login(target: &Target, global: &GlobalArgs) -> Result<()> {
    let Some(src) = target.oidc.clone() else {
        // Keep configuration guidance off machine-readable stdout.
        eprintln!(
            "profile {:?} names no identity provider. Add:\n\n\
             [profiles.{}]\n\
             credential = {{ type = \"oidc\", issuer = \"https://idp.example.org\", \
             client_id = \"meisterstack\" }}\n",
            target.profile_name, target.profile_name
        );
        bail!(
            "profile {:?} has no oidc credential to log in with",
            target.profile_name
        );
    };

    let provider = provider_of(&src).await?;
    let scope = src.scope.as_deref().unwrap_or(DEFAULT_SCOPE);
    let auth = device::start(&provider, &src.client_id, scope).await?;

    // Login instructions go to stderr; stdout contains only the result.
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
        // Without a refresh token, the user must log in again after expiry.
        eprintln!(
            "warning: the provider returned no refresh token; this session ends when the \
             access token does.\n         Ask for \"offline_access\" in the profile's scope, \
             and check that the client is allowed it."
        );
    }

    if tokens.id_token.is_none() {
        // Warn that the fallback access token may lack the required identity claim.
        eprintln!(
            "warning: the provider returned no id_token, so the access token is what will be \
             sent.\n         This control plane looks a person up by \"preferred_username\", \
             which several providers\n         put only in the id_token. Ask for \"openid\" in \
             the profile's scope."
        );
    }

    let now = Utc::now();
    let mut session = Session {
        issuer: src.issuer.clone(),
        client_id: src.client_id.clone(),
        access_token: String::new(),
        id_token: None,
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
            // Provider authentication does not grant a role in the cloud user directory.
            eprintln!(
                "\nthe provider has said WHO you are. What you may do is the cloud's user\n\
                 directory's answer -- if it does not know this name, an administrator runs\n\
                 `meister user create` before anything else works."
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
            id_token: None,
            refresh_token: Some("rt-1".into()),
            expires_at: Utc::now() + chrono::TimeDelta::seconds(expires_in),
            scope: None,
        }
    }

    /// Treat tokens inside the expiry margin as stale.
    #[test]
    fn a_token_about_to_expire_is_already_stale() {
        assert!(session(3600).usable_now().is_some());
        assert!(session(30).usable_now().is_none(), "inside the margin");
        assert!(session(-1).usable_now().is_none());
    }

    /// Keep the previous refresh token unless the provider rotates it.
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
        // See the note in `config.rs`: a pid is not a unique name.
        let dir = tempfile::tempdir().expect("a directory of our own");
        let path = dir.path().join("p.json");
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
    }

    /// Prefer a returned ID token; fall back to the access token when refresh omits it.
    #[test]
    fn the_token_that_carries_the_name_is_the_one_that_is_sent() {
        let now = Utc::now();
        let kanidm = r#"{"access_token":"at-2","id_token":"id-2",
                         "refresh_token":"rt-2","expires_in":900,
                         "token_type":"bearer","scope":"openid profile"}"#;

        let mut s = session(0);
        s.apply(serde_json::from_str(kanidm).unwrap(), now);
        assert_eq!(s.id_token.as_deref(), Some("id-2"));
        assert_eq!(s.access_token, "at-2", "both are kept");
        assert_eq!(s.bearer(), "id-2", "and the id_token is what travels");
        assert_eq!(s.usable_at(now).as_deref(), Some("id-2"));

        // Without an ID token, use the access token.
        let mut s = session(0);
        s.apply(
            serde_json::from_str(r#"{"access_token":"at-3","expires_in":900}"#).unwrap(),
            now,
        );
        assert_eq!(s.bearer(), "at-3");

        // Drop a previous ID token when refresh does not replace it.
        let mut s = session(0);
        s.apply(serde_json::from_str(kanidm).unwrap(), now);
        s.apply(
            serde_json::from_str(r#"{"access_token":"at-4","expires_in":900}"#).unwrap(),
            now,
        );
        assert_eq!(s.id_token, None);
        assert_eq!(s.bearer(), "at-4");
        assert_eq!(
            s.refresh_token.as_deref(),
            Some("rt-2"),
            "and the refresh token keeps its own, opposite rule"
        );
    }

    /// A session file written before the field existed still loads, and the
    /// CLI then behaves exactly as it did: the access token is the bearer.
    #[test]
    fn a_session_from_before_the_id_token_still_reads() {
        let older = r#"{"issuer":"https://idp.example.org","client_id":"x",
                        "access_token":"at-1","refresh_token":"rt-1",
                        "expires_at":"2030-01-01T00:00:00Z"}"#;
        let s: Session = serde_json::from_str(older).expect("an older session");
        assert_eq!(s.id_token, None);
        assert_eq!(s.bearer(), "at-1");
    }
}
