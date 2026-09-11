// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

pub const ENV_CONFIG: &str = "MEISTER_CONFIG";
pub const ENV_PROFILE: &str = "MEISTER_PROFILE";
pub const ENV_ENDPOINT: &str = "MEISTER_ENDPOINT";
pub const ENV_TOKEN: &str = "MEISTER_TOKEN";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
#[derive(Default)]
pub enum CredentialSource {
    #[default]
    None,
    TokenFile {
        path: PathBuf,
    },
    Env {
        var: String,
    },
    Command {
        command: Vec<String>,
    },
    Mtls {
        cert: PathBuf,
        key: PathBuf,
    },
    /// A person, logged in at an identity provider.
    ///
    /// The two paths of this file are the whole difference from the shapes
    /// above it: `issuer` and `client_id` say WHO issues tokens, and
    /// `tokens` says where the ones this machine holds are kept. Nothing
    /// secret is in here -- the same rule the token file and the certificate
    /// follow -- and the file `tokens` names is written at 0600 by
    /// `meister login --oidc`.
    Oidc {
        issuer: String,
        client_id: String,
        /// Where the access and refresh tokens live. Defaults to
        /// `<config dir>/oidc/<profile>.json`.
        #[serde(default)]
        tokens: Option<PathBuf>,
        /// The CA that signed the provider, for one that is not on the
        /// public internet. Absent = the platform's own roots.
        #[serde(default)]
        ca_cert: Option<PathBuf>,
        /// What to ask the provider for. Defaults to
        /// `openid profile email offline_access` -- and `offline_access` is
        /// the part that matters, because it is what makes a refresh token
        /// appear. Without one a person logs in again every few minutes,
        /// which they will not do; they will use the static token instead.
        #[serde(default)]
        scope: Option<String>,
    },
}

/// Everything `meister login --oidc` and the refresh need, resolved.
///
/// It travels on the `Target` rather than only inside the credential
/// because it is needed exactly when there is no credential yet: the whole
/// job of `meister login --oidc` is to create the file the credential would
/// have been read from.
#[derive(Debug, Clone)]
pub struct OidcSource {
    pub tokens: PathBuf,
    pub issuer: String,
    pub client_id: String,
    pub ca_cert: Option<PathBuf>,
    pub scope: Option<String>,
}

/// One endpoint under a name: where it is, how to trust it, who we are to it.
///
/// There is no `tier` key any more, and its absence is the whole point of
/// this milestone. A tier was a thing the OPERATOR had to know and keep in
/// step with the endpoint, and getting it wrong was a refusal from the CLI
/// about its own config rather than an answer from the server. What is here
/// now is a server that says what it is (`GET /apis/meister.io/v1`) and a CLI
/// that asks.
///
/// `deny_unknown_fields` therefore turns an old profile into a parse error
/// naming `tier`, which is wanted: a profile that still carries one was
/// written against a CLI that checked it, and saying so beats ignoring it.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    pub endpoint: String,
    #[serde(default)]
    pub ca_cert: Option<PathBuf>,
    #[serde(default)]
    pub credential: CredentialSource,
    #[serde(default = "default_timeout_secs")]
    pub timeout_secs: u64,
}

fn default_timeout_secs() -> u64 {
    30
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default)]
    pub default_profile: Option<String>,
    #[serde(default)]
    pub profiles: BTreeMap<String, Profile>,
    #[serde(skip)]
    pub dir: Option<PathBuf>,
}

/// Default config Paths are $MEISTER_CONFIG >> $XDG_CONFIG_HOME/meisterstack/config.toml >>
/// ~/.config/meisterstack/config.toml
pub fn default_config_path() -> Result<PathBuf> {
    if let Ok(p) = std::env::var(ENV_CONFIG) {
        return Ok(PathBuf::from(p));
    }
    let base = match std::env::var("XDG_CONFIG_HOME") {
        Ok(p) if !p.is_empty() => PathBuf::from(p),
        _ => {
            let home = std::env::var("HOME").context("neither XDG_CONFIG_HOME nor HOME is set")?;
            PathBuf::from(home).join(".config")
        }
    };
    Ok(base.join("meisterstack").join("config.toml"))
}

impl Config {
    /// The certificate and key a profile DECLARES, whether or not they exist
    /// and whatever credential this particular call ended up resolving to.
    ///
    /// `meister login` needs the declaration rather than the resolution, and
    /// the difference is exactly the bootstrap case: the first login is made
    /// with a bearer token — `MEISTER_TOKEN` wins over the profile — and the
    /// resolved credential is then a token, while the two paths the
    /// certificate belongs in are still the profile's.
    pub fn declared_mtls(&self, profile: &str) -> Option<(PathBuf, PathBuf)> {
        match &self.profiles.get(profile)?.credential {
            CredentialSource::Mtls { cert, key } => Some((
                resolve_path(self.dir.as_deref(), cert.clone()),
                resolve_path(self.dir.as_deref(), key.clone()),
            )),
            _ => None,
        }
    }

    pub fn load(path: &Path) -> Result<Self> {
        match std::fs::read_to_string(path) {
            Ok(raw) => {
                let mut cfg: Config = toml::from_str(&raw)
                    .with_context(|| format!("parsing config file {}", path.display()))?;
                cfg.dir = path.parent().map(Path::to_path_buf);
                Ok(cfg)
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(e).with_context(|| format!("reading config file {}", path.display())),
        }
    }
}

#[derive(Debug, Default)]
pub struct Overrides {
    pub profile: Option<String>,
    pub endpoint: Option<String>,
    /// `meister login` sets this, and only it.
    ///
    /// A profile that names an mtls credential whose files do not exist yet
    /// is the normal state before the first login — the whole point of the
    /// command is to create them. Refusing to resolve such a profile would
    /// mean the one command that fills it in could never be run against it.
    /// Every other command still fails, loudly, because for them a missing
    /// certificate is exactly the problem it looks like.
    pub tolerate_missing_credential: bool,
}

#[derive(Debug)]
/// A resolved target: what the client needs and nothing else.
///
/// `tier` is not here and is not anywhere any more: what an endpoint is, is
/// something the endpoint says. `ca_cert` is the CA an `https://` endpoint is
/// verified against, and it is required for one — a lab CA is in nobody's
/// system trust store, so falling back to those would only turn a clear error
/// into an obscure handshake failure.
pub struct Target {
    pub profile_name: String,
    pub endpoint: String,
    pub ca_cert: Option<PathBuf>,
    pub credential: Credential,
    pub timeout_secs: u64,
    /// The identity provider this profile logs in at, if it names one.
    ///
    /// Present whether or not there is a session yet: `meister login --oidc`
    /// needs it precisely when there is none.
    pub oidc: Option<OidcSource>,
}

pub enum Credential {
    None,
    Bearer(String),
    Mtls {
        cert: PathBuf,
        key: PathBuf,
    },
    /// An OIDC session whose access token has run out.
    ///
    /// Its own state rather than "no credential" because the two need
    /// different things done about them: this one is renewed silently from
    /// the refresh token, and that renewal is a network call, so it cannot
    /// happen where the credential is read. `oidc::freshen` is the one thing
    /// that turns this into a `Bearer`, and `Client::new` refuses to send a
    /// request that still holds one.
    StaleOidc,
}

impl std::fmt::Debug for Credential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Credential::None => f.write_str("None"),
            Credential::Bearer(_) => f.write_str("Bearer(<redacted>)"),
            Credential::Mtls { cert, .. } => {
                write!(f, "Mtls {{ cert: {} }}", cert.display())
            }
            Credential::StaleOidc => f.write_str("StaleOidc"),
        }
    }
}

pub fn resolve(config: &Config, ov: &Overrides) -> Result<Target> {
    let profile_name = ov
        .profile
        .clone()
        .or_else(|| std::env::var(ENV_PROFILE).ok().filter(|s| !s.is_empty()))
        .or_else(|| config.default_profile.clone());

    let endpoint_override = ov
        .endpoint
        .clone()
        .or_else(|| std::env::var(ENV_ENDPOINT).ok().filter(|s| !s.is_empty()));

    let (name, profile) = match &profile_name {
        Some(name) => {
            let p = config.profiles.get(name).ok_or_else(|| {
                let known: Vec<&str> = config.profiles.keys().map(String::as_str).collect();
                anyhow::anyhow!(
                    "unknown profile {name:?}; configured profiles: {}",
                    if known.is_empty() {
                        "<none>".into()
                    } else {
                        known.join(", ")
                    }
                )
            })?;
            (name.clone(), Some(p))
        }
        None => ("<flags>".to_string(), None),
    };

    let endpoint = endpoint_override
        .or_else(|| profile.map(|p| p.endpoint.clone()))
        .ok_or_else(|| {
            anyhow::anyhow!("no endpoint: pass --endpoint, set {ENV_ENDPOINT}, or select a profile")
        })?;

    let oidc = profile.and_then(|p| oidc_source(&p.credential, config.dir.as_deref(), &name));

    // The same shape of refusal `Client::new` makes for a client certificate
    // over plain http, and for a sharper reason. A static lab token over
    // http is a lab operator's decision about a string they minted. An OIDC
    // access token is a live credential from somebody else's identity
    // provider, good for whatever else that provider protects, and putting
    // one on the wire in clear is not a configuration anybody means.
    if oidc.is_some() && endpoint.starts_with("http://") {
        bail!(
            "profile {name:?} logs in at an identity provider but its endpoint {endpoint} is \
             plain http; the access token would be readable by anything on the path"
        );
    }

    let credential = match std::env::var(ENV_TOKEN).ok().filter(|s| !s.is_empty()) {
        Some(token) => Credential::Bearer(token),
        None => match profile.map(|p| &p.credential) {
            Some(src) => load_credential(src, config.dir.as_deref(), ov, oidc.as_ref())?,
            None => Credential::None,
        },
    };

    Ok(Target {
        profile_name: name,
        endpoint,
        ca_cert: profile
            .and_then(|p| p.ca_cert.clone())
            .map(|p| resolve_path(config.dir.as_deref(), p)),
        credential,
        timeout_secs: profile
            .map(|p| p.timeout_secs)
            .unwrap_or_else(default_timeout_secs),
        oidc,
    })
}

/// The identity provider a profile names, with every path made absolute.
///
/// The default token path hangs off the config file, exactly as the default
/// certificate path does, so that a config directory and the credentials it
/// refers to move as one.
fn oidc_source(src: &CredentialSource, base: Option<&Path>, profile: &str) -> Option<OidcSource> {
    let CredentialSource::Oidc {
        issuer,
        client_id,
        tokens,
        ca_cert,
        scope,
    } = src
    else {
        return None;
    };
    let tokens = match tokens.clone() {
        Some(p) => resolve_path(base, p),
        None => match base {
            Some(dir) => dir.join("oidc").join(format!("{profile}.json")),
            // No config file to hang it off. `~/.config/meisterstack` is
            // where one would have been.
            None => resolve_path(
                None,
                PathBuf::from("~/.config/meisterstack/oidc").join(format!("{profile}.json")),
            ),
        },
    };
    Some(OidcSource {
        tokens,
        issuer: issuer.clone(),
        client_id: client_id.clone(),
        ca_cert: ca_cert.clone().map(|p| resolve_path(base, p)),
        scope: scope.clone(),
    })
}

fn load_credential(
    src: &CredentialSource,
    base: Option<&Path>,
    ov: &Overrides,
    oidc: Option<&OidcSource>,
) -> Result<Credential> {
    match src {
        CredentialSource::None => Ok(Credential::None),

        CredentialSource::Oidc { .. } => {
            let Some(oidc) = oidc else {
                bail!("internal: an oidc credential without a resolved source");
            };
            if !oidc.tokens.exists() {
                if ov.tolerate_missing_credential {
                    // The state every oidc profile is in before its first
                    // login, and `meister login --oidc` is the command that
                    // ends it. Same pass the mtls arm gets, for the same
                    // reason.
                    return Ok(Credential::None);
                }
                bail!(
                    "no session at {}; run: meister login --oidc",
                    oidc.tokens.display()
                );
            }
            check_secret_permissions(&oidc.tokens)?;
            // Whether it is still usable is read here; RENEWING it is not,
            // because renewing is a network call. See `Credential::StaleOidc`.
            match crate::oidc::Session::load(&oidc.tokens)?.usable_now() {
                Some(access) => Ok(Credential::Bearer(access)),
                None => Ok(Credential::StaleOidc),
            }
        }

        CredentialSource::Env { var } => {
            let token = std::env::var(var)
                .with_context(|| format!("credential env var {var} is not set"))?;
            Ok(Credential::Bearer(token.trim().to_string()))
        }

        CredentialSource::TokenFile { path } => {
            let path = resolve_path(base, path.clone());
            check_secret_permissions(&path)?;
            let token = std::fs::read_to_string(&path)
                .with_context(|| format!("reading token file {}", path.display()))?;
            Ok(Credential::Bearer(token.trim().to_string()))
        }

        CredentialSource::Command { command } => {
            let Some((bin, args)) = command.split_first() else {
                bail!("credential command is empty");
            };
            let out = std::process::Command::new(bin)
                .args(args)
                .stdin(std::process::Stdio::null())
                .output()
                .with_context(|| format!("running credential command {bin}"))?;
            if !out.status.success() {
                bail!(
                    "credential command {bin} failed with {}: {}",
                    out.status,
                    String::from_utf8_lossy(&out.stderr).trim()
                );
            }
            let token = String::from_utf8(out.stdout)
                .context("credential command produced non-utf8 output")?;
            let token = token.trim().to_string();
            if token.is_empty() {
                bail!("credential command {bin} produced no output");
            }
            Ok(Credential::Bearer(token))
        }

        CredentialSource::Mtls { cert, key } => {
            let cert = resolve_path(base, cert.clone());
            let key = resolve_path(base, key.clone());
            if ov.tolerate_missing_credential && (!cert.exists() || !key.exists()) {
                // The state a profile is in before its first login. Going on
                // without a credential is right: against a controller with no
                // chain this simply works, and against one with a chain it
                // earns a 401 that says what is missing — both better answers
                // than refusing to run the command that would fix it.
                return Ok(Credential::None);
            }
            check_secret_permissions(&key)?;
            Ok(Credential::Mtls { cert, key })
        }
    }
}

#[cfg(unix)]
fn check_secret_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let meta = std::fs::metadata(path).with_context(|| format!("reading {}", path.display()))?;
    let mode = meta.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        bail!(
            "permissions {:04o} on {} are too open; run: chmod 600 {}",
            mode,
            path.display(),
            path.display()
        );
    }
    Ok(())
}

#[cfg(not(unix))]
fn check_secret_permissions(_path: &Path) -> Result<()> {
    Ok(())
}

fn resolve_path(base: Option<&Path>, path: PathBuf) -> PathBuf {
    let path = expand_tilde(path);
    if path.is_absolute() {
        return path;
    }
    match base {
        Some(b) => b.join(path),
        None => path,
    }
}

fn expand_tilde(path: PathBuf) -> PathBuf {
    let Ok(rest) = path.strip_prefix("~") else {
        return path;
    };
    match std::env::var("HOME") {
        Ok(home) => PathBuf::from(home).join(rest),
        Err(_) => path,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The example, live and commented-out halves both. Same rule as the
    /// other three: prose is `# text`, a commented-out setting is `#key = …`
    /// with no space, and an example that does not parse is worse than none.
    ///
    /// `Profile` is `deny_unknown_fields`, so this also catches a profile key
    /// renamed in the code and left behind here.
    #[test]
    fn the_example_config_parses_commented_keys_included() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../config/examples/cli.toml");
        let raw = std::fs::read_to_string(&path).expect("the example is where it says");
        let live: Config =
            toml::from_str(&raw).expect("config/examples/cli.toml parses as written");
        assert_eq!(live.default_profile.as_deref(), Some("lab"));
        assert_eq!(live.profiles.len(), 5);
        // The mTLS profile is the one an operator copies; if its shape ever
        // stops being the shape the client accepts, this is where it shows.
        let mtls = &live.profiles["cloud-mtls"];
        assert!(mtls.endpoint.starts_with("https://"));
        assert!(mtls.ca_cert.is_some(), "an https profile needs its CA");
        assert!(matches!(mtls.credential, CredentialSource::Mtls { .. }));
        let oidc = &live.profiles["cloud-oidc"];
        assert!(matches!(oidc.credential, CredentialSource::Oidc { .. }));

        // The credential shapes at the bottom are prose, deliberately: they
        // are alternatives for one field, and uncommenting them all at once
        // would be four values for `credential`. Each is parsed on its own.
        for line in raw
            .lines()
            .filter(|l| l.trim_start().starts_with("#   { type ="))
        {
            let value = line.trim_start().trim_start_matches('#').trim();
            let doc = format!(
                "default_profile = \"p\"\n[profiles.p]\n\
                 endpoint = \"unix:///x.sock\"\ncredential = {value}"
            );
            toml::from_str::<Config>(&doc)
                .unwrap_or_else(|e| panic!("credential example {value:?} does not parse: {e}"));
        }

        let uncommented: String = raw
            .lines()
            .map(|l| match l.strip_prefix('#') {
                Some(rest) if !rest.starts_with(' ') && !rest.is_empty() => rest,
                _ if l.starts_with('#') => "",
                _ => l,
            })
            .collect::<Vec<_>>()
            .join("\n");
        toml::from_str::<Config>(&uncommented)
            .expect("every commented key in the example is a real one");
    }

    fn config_with() -> Config {
        let mut profiles = BTreeMap::new();
        profiles.insert(
            "p".to_string(),
            Profile {
                endpoint: "https://example:8443".into(),
                ca_cert: None,
                credential: CredentialSource::None,
                timeout_secs: 30,
            },
        );
        Config {
            default_profile: Some("p".into()),
            profiles,
            dir: None,
        }
    }

    /// A profile written for the CLI before this milestone carries `tier`,
    /// and `deny_unknown_fields` makes that a parse error that NAMES the key.
    ///
    /// Loud on purpose. Ignoring it would leave an operator with a config
    /// that still says something the CLI no longer reads, and the first time
    /// that mattered would be the first time they wondered why a profile was
    /// not being checked against a command any more.
    #[test]
    fn a_profile_that_still_carries_a_tier_is_a_parse_error_that_says_so() {
        let doc = "default_profile = \"p\"\n[profiles.p]\ntier = \"cloud\"\n\
                   endpoint = \"http://x:3000\"";
        let err = toml::from_str::<Config>(doc).unwrap_err().to_string();
        assert!(err.contains("tier"), "{err}");
    }

    #[test]
    fn unknown_profile_lists_known_ones() {
        let cfg = config_with();
        let ov = Overrides {
            profile: Some("nope".into()),
            ..Default::default()
        };
        let err = resolve(&cfg, &ov).unwrap_err();
        assert!(err.to_string().contains("nope"), "{err}");
    }

    #[test]
    fn flag_endpoint_beats_profile() {
        let cfg = config_with();
        let ov = Overrides {
            endpoint: Some("unix:///tmp/a.sock".into()),
            ..Default::default()
        };
        let t = resolve(&cfg, &ov).unwrap();
        assert_eq!(t.endpoint, "unix:///tmp/a.sock");
    }

    #[test]
    fn works_without_config_file() {
        let cfg = Config::default();
        let ov = Overrides {
            endpoint: Some("unix:///tmp/a.sock".into()),
            ..Default::default()
        };
        let t = resolve(&cfg, &ov).unwrap();
        assert_eq!(t.profile_name, "<flags>");
        assert!(matches!(t.credential, Credential::None));
        assert!(t.ca_cert.is_none());
    }

    /// The state every mtls profile is in before its first login. Only
    /// `meister login` gets this pass; for anything else a missing
    /// certificate is the problem it looks like.
    #[test]
    fn login_may_resolve_a_profile_whose_certificate_does_not_exist_yet() {
        let mut cfg = config_with();
        cfg.profiles.get_mut("p").unwrap().credential = CredentialSource::Mtls {
            cert: PathBuf::from("/nonexistent/x.crt"),
            key: PathBuf::from("/nonexistent/x.key"),
        };
        assert!(resolve(&cfg, &Overrides::default()).is_err());

        let ov = Overrides {
            tolerate_missing_credential: true,
            ..Default::default()
        };
        let t = resolve(&cfg, &ov).unwrap();
        assert!(matches!(t.credential, Credential::None));
    }

    /// The CA a profile names travels with the target now, resolved against
    /// the config file so that a config and its pki/ directory move as one.
    #[test]
    fn the_profiles_ca_reaches_the_client_as_an_absolute_path() {
        let mut cfg = config_with();
        cfg.dir = Some(PathBuf::from("/etc/meisterstack"));
        cfg.profiles.get_mut("p").unwrap().ca_cert = Some(PathBuf::from("pki/ca.crt"));
        let t = resolve(&cfg, &Overrides::default()).unwrap();
        assert_eq!(
            t.ca_cert.as_deref(),
            Some(Path::new("/etc/meisterstack/pki/ca.crt"))
        );
    }

    #[test]
    fn missing_endpoint_is_an_error() {
        let cfg = Config::default();
        assert!(resolve(&cfg, &Overrides::default()).is_err());
    }

    fn oidc_config(tokens: Option<&str>) -> Config {
        let mut cfg = config_with();
        cfg.dir = Some(PathBuf::from("/etc/meisterstack"));
        cfg.profiles.get_mut("p").unwrap().credential = CredentialSource::Oidc {
            issuer: "https://idp.example.org".into(),
            client_id: "meisterstack".into(),
            tokens: tokens.map(PathBuf::from),
            ca_cert: None,
            scope: None,
        };
        cfg
    }

    /// The session file hangs off the config file by default, exactly as the
    /// certificate does, so that a config directory and the credentials it
    /// refers to move as one.
    #[test]
    fn an_oidc_profile_keeps_its_session_next_to_the_config() {
        let ov = Overrides {
            tolerate_missing_credential: true,
            ..Default::default()
        };
        let t = resolve(&oidc_config(None), &ov).unwrap();
        let src = t.oidc.expect("the profile names a provider");
        assert_eq!(src.tokens, Path::new("/etc/meisterstack/oidc/p.json"));
        assert_eq!(src.issuer, "https://idp.example.org");

        // A named path is still resolved against the config file.
        let t = resolve(&oidc_config(Some("sessions/x.json")), &ov).unwrap();
        assert_eq!(
            t.oidc.unwrap().tokens,
            Path::new("/etc/meisterstack/sessions/x.json")
        );
    }

    /// An access token from somebody else's identity provider is good for
    /// whatever else that provider protects. It does not go on the wire in
    /// clear, whatever the profile says.
    #[test]
    fn an_oidc_profile_refuses_a_plain_http_endpoint() {
        let mut cfg = oidc_config(None);
        cfg.profiles.get_mut("p").unwrap().endpoint = "http://10.128.1.103:3000".into();
        let ov = Overrides {
            tolerate_missing_credential: true,
            ..Default::default()
        };
        let err = resolve(&cfg, &ov).unwrap_err();
        assert!(err.to_string().contains("plain http"), "{err}");

        // https is what the example uses, and it resolves.
        cfg.profiles.get_mut("p").unwrap().endpoint = "https://10.128.1.103:3000".into();
        assert!(resolve(&cfg, &ov).is_ok());
    }

    /// The state every oidc profile is in before its first login. `meister
    /// login` gets the same pass the mtls arm gets, because it is the one
    /// command that can end that state; everything else says what to run.
    #[test]
    fn login_may_resolve_an_oidc_profile_that_has_never_logged_in() {
        let cfg = oidc_config(Some("/nonexistent/session.json"));
        let err = resolve(&cfg, &Overrides::default()).unwrap_err();
        assert!(err.to_string().contains("login --oidc"), "{err}");

        let ov = Overrides {
            tolerate_missing_credential: true,
            ..Default::default()
        };
        let t = resolve(&cfg, &ov).unwrap();
        assert!(matches!(t.credential, Credential::None));
        // And the source is there anyway -- which is the whole reason it is
        // on the Target: `login --oidc` needs it precisely now.
        assert!(t.oidc.is_some());
    }

    /// A live session is a bearer token; a dead one is its own state, so
    /// that the one place that may renew it is forced to be a place that
    /// can await.
    #[test]
    fn a_session_is_a_token_while_it_lasts_and_a_renewal_afterwards() {
        // A pid is not a unique name: it comes back round, and a crashed run
        // leaves its directory behind for the process that inherits the
        // number. `tempfile` is unique and cleans up on a panic too.
        let dir = tempfile::tempdir().expect("a directory of our own");
        let path = dir.path().join("s.json");

        let write = |secs: i64, id_token: Option<&str>| {
            let s = crate::oidc::Session {
                issuer: "https://idp.example.org".into(),
                client_id: "meisterstack".into(),
                access_token: "at-1".into(),
                id_token: id_token.map(str::to_string),
                refresh_token: Some("rt-1".into()),
                expires_at: chrono::Utc::now() + chrono::TimeDelta::seconds(secs),
                scope: None,
            };
            s.save(&path).unwrap();
        };

        let cfg = oidc_config(Some(path.to_str().unwrap()));
        write(3600, None);
        let t = resolve(&cfg, &Overrides::default()).unwrap();
        assert!(matches!(&t.credential, Credential::Bearer(a) if a == "at-1"));

        write(-1, None);
        let t = resolve(&cfg, &Overrides::default()).unwrap();
        assert!(matches!(t.credential, Credential::StaleOidc));
    }

    #[test]
    fn bearer_is_redacted_in_debug() {
        let c = Credential::Bearer("super-secret".into());
        assert!(!format!("{c:?}").contains("super-secret"));
    }
}
