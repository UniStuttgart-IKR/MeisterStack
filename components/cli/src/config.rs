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
    /// OIDC provider settings and the path to the local session file.
    Oidc {
        issuer: String,
        client_id: String,
        /// Where the access and refresh tokens live. Defaults to
        /// `<config dir>/oidc/<profile>.json`.
        #[serde(default)]
        tokens: Option<PathBuf>,
        /// Private CA for the identity provider; otherwise use the built-in public roots.
        #[serde(default)]
        ca_cert: Option<PathBuf>,
        /// Requested scopes. Defaults to `openid profile email offline_access`.
        #[serde(default)]
        scope: Option<String>,
    },
}

/// Resolved OIDC settings, available even before a session exists.
#[derive(Debug, Clone)]
pub struct OidcSource {
    pub tokens: PathBuf,
    pub issuer: String,
    pub client_id: String,
    pub ca_cert: Option<PathBuf>,
    pub scope: Option<String>,
}

/// Named endpoint, trust roots and credentials. The server advertises its tier
/// through discovery; obsolete profile keys such as `tier` are rejected.
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

/// System profile file, used when no user configuration exists.
pub const SYSTEM_CONFIG: &str = "/etc/meisterstack/cli.toml";

/// Config lookup: MEISTER_CONFIG, existing user config, existing system config.
/// The user path uses XDG_CONFIG_HOME, falling back to ~/.config; it is also
/// returned when neither configuration file exists.
pub fn default_config_path() -> Result<PathBuf> {
    let base = match std::env::var("XDG_CONFIG_HOME") {
        Ok(p) if !p.is_empty() => PathBuf::from(p),
        _ => {
            let home = std::env::var("HOME").context("neither XDG_CONFIG_HOME nor HOME is set")?;
            PathBuf::from(home).join(".config")
        }
    };
    let user = base.join("meisterstack").join("config.toml");
    Ok(pick_config_path(
        std::env::var(ENV_CONFIG).ok().map(PathBuf::from),
        user,
        PathBuf::from(SYSTEM_CONFIG),
        |p| p.is_file(),
    ))
}

/// Select the override, user file, system file, or default user path, in that order.
fn pick_config_path(
    env_override: Option<PathBuf>,
    user: PathBuf,
    system: PathBuf,
    is_file: impl Fn(&Path) -> bool,
) -> PathBuf {
    if let Some(p) = env_override {
        return p;
    }
    if is_file(&user) {
        return user;
    }
    if is_file(&system) {
        return system;
    }
    user
}

impl Config {
    /// Resolve the profile's declared certificate paths even when a bearer token
    /// overrides authentication during certificate enrollment.
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
    /// Allow enrollment before the profile's certificate or OIDC session exists.
    pub tolerate_missing_credential: bool,
}

#[derive(Debug)]
/// Resolved endpoint and credentials. HTTPS requires an explicit controller CA.
pub struct Target {
    pub profile_name: String,
    pub endpoint: String,
    pub ca_cert: Option<PathBuf>,
    pub credential: Credential,
    pub timeout_secs: u64,
    /// OIDC settings, retained when login has not created a session yet.
    pub oidc: Option<OidcSource>,
}

pub enum Credential {
    None,
    Bearer(String),
    Mtls {
        cert: PathBuf,
        key: PathBuf,
    },
    /// Expired OIDC session. `oidc::freshen` must renew it before Client construction.
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

    // Do not send OIDC credentials to a plaintext HTTP endpoint.
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

/// Resolve provider settings and session paths relative to the config directory.
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
                    // Enrollment may run before its session file exists.
                    return Ok(Credential::None);
                }
                bail!(
                    "no session at {}; run: meister login --oidc",
                    oidc.tokens.display()
                );
            }
            check_secret_permissions(&oidc.tokens)?;
            // Load here; asynchronous renewal belongs to `oidc::freshen`.
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
                // Enrollment may authenticate without the certificate it is about to create.
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

    /// Validate active settings and uncommented examples against the current schema.
    #[test]
    fn the_example_config_parses_commented_keys_included() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../config/examples/cli.toml");
        let raw = std::fs::read_to_string(&path).expect("the example is where it says");
        let live: Config =
            toml::from_str(&raw).expect("config/examples/cli.toml parses as written");
        assert_eq!(live.default_profile.as_deref(), Some("lab"));
        assert_eq!(live.profiles.len(), 5);
        // The example must provide the CA and client identity required by HTTPS.
        let mtls = &live.profiles["cloud-mtls"];
        assert!(mtls.endpoint.starts_with("https://"));
        assert!(mtls.ca_cert.is_some(), "an https profile needs its CA");
        assert!(matches!(mtls.credential, CredentialSource::Mtls { .. }));
        let oidc = &live.profiles["cloud-oidc"];
        assert!(matches!(oidc.credential, CredentialSource::Oidc { .. }));

        // Credential alternatives are parsed separately; they cannot all be enabled together.
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

    /// Reject obsolete profile fields instead of silently ignoring them.
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

    /// Only enrollment may resolve a missing client identity.
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

    /// Resolve relative CA paths against the config directory.
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

    /// Default session files live beside the profile configuration.
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

    /// Refuse plaintext transport for OIDC profiles.
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

    /// Only login may proceed without an OIDC session file.
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
        // Login still needs the resolved provider settings.
        assert!(t.oidc.is_some());
    }

    /// Expired sessions must be renewed before client construction.
    #[test]
    fn a_session_is_a_token_while_it_lasts_and_a_renewal_afterwards() {
        // Use isolated temporary state for each test.
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

    // The machine's config is a fallback and never an override.
    #[test]
    fn the_machines_config_is_taken_only_when_the_person_has_none() {
        let user = PathBuf::from("/home/x/.config/meisterstack/config.toml");
        let system = PathBuf::from(SYSTEM_CONFIG);
        let env = Some(PathBuf::from("/tmp/mine.toml"));
        // The environment wins whatever exists.
        assert_eq!(
            pick_config_path(env.clone(), user.clone(), system.clone(), |_| true),
            PathBuf::from("/tmp/mine.toml")
        );
        // The person's file wins by existing.
        assert_eq!(
            pick_config_path(None, user.clone(), system.clone(), |_| true),
            user
        );
        // Without it, the machine's — when the machine has one.
        assert_eq!(
            pick_config_path(None, user.clone(), system.clone(), |p| p == system),
            system
        );
        // And with neither, the person's path: that is where a login writes.
        assert_eq!(
            pick_config_path(None, user.clone(), system, |_| false),
            user
        );
    }
}
