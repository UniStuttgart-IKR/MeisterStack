// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Authentication configuration, request middleware, directory grants and whoami.

use super::*;

/// What the guard needs to answer a request.
#[derive(Clone)]
pub struct AuthState {
    pub chain: Arc<AuthChain>,
    /// Cloud User directory used for current role and tenant grants. None
    /// refuses ordinary users at this tier; certificate groups are no fallback.
    pub directory: Option<Arc<EtcdStore>>,
    /// Create a `User` for an identity out of a token that the directory
    /// does not know yet. `auth.oidc.provision_unknown_users`, off by
    /// default. See `provision`.
    pub provision_oidc_users: bool,
    /// This tier's peer kind and name for exact sibling authorization.
    /// Matching siblings may read and perform narrowly allowed forwarded writes;
    /// None disables sibling privileges.
    pub own_peer: Option<(&'static str, String)>,
    /// Tier-wide etcd ticket store, shared across replicas. Tickets are
    /// checked before the credential chain so browser upgrades need no
    /// authorization header. None disables ticket authentication.
    pub tickets: Option<Arc<crate::tickets::Tickets>>,
}

impl AuthState {
    pub fn anonymous() -> Self {
        Self {
            chain: Arc::new(AuthChain::default()),
            directory: None,
            provision_oidc_users: false,
            own_peer: None,
            tickets: None,
        }
    }
}

/// Put the guard in front of a router.
pub fn guard(router: Router, state: AuthState) -> Router {
    router.layer(axum::middleware::from_fn_with_state(state, authorize))
}

// --- who am i ---------------------------------------------------------------

/// Authenticated endpoint for the resolved caller identity and grant.
/// In anonymous mode it reports anonymous. Discovery remains public.
pub const WHOAMI_PATH: &str = "/apis/meister.io/v1/whoami";

/// Return identity, groups and tier, adding directory role and tenant when known.
/// Unknown directory fields are omitted rather than reported as null.
pub(super) async fn who_am_i(
    tier: State<Tier>,
    caller: Caller,
    role: CallerRole,
    tenant: CallerTenant,
) -> Json<serde_json::Value> {
    let mut body = serde_json::json!({
        "apiVersion": API_VERSION,
        "kind": "Whoami",
        "name": caller.name(),
        // Credential groups are descriptive claims; the separate role field comes
        // from directory authorization.
        "groups": caller.0.as_ref().map(|i| i.groups.clone()).unwrap_or_default(),
        "tier": tier.as_str(),
    });
    if let Some(role) = role.0 {
        body["role"] = serde_json::Value::String(role.as_str().to_string());
    }
    if let Some(tenant) = tenant.0.filter(|t| !t.is_empty()) {
        body["tenant"] = serde_json::Value::String(tenant);
    }
    Json(body)
}

/// The one route, ready to be merged into a tier's router.
pub fn whoami(tier: Tier) -> Router {
    Router::new()
        .route(WHOAMI_PATH, get(who_am_i))
        .with_state(tier)
}

/// Authenticate, then authorize, then hand the identity to the handler.
pub(super) async fn authorize(
    State(st): State<AuthState>,
    mut req: Request,
    next: Next,
) -> Response {
    let method = req.method().as_str().to_string();
    let path = req.uri().path().to_string();

    // Bypass object authentication for unclassified routes such as health probes,
    // which must work without presenting credentials.
    let Some(attempt) = classify(&method, &path) else {
        return next.run(req).await;
    };

    // Redeem a path-bound console ticket before checking header credentials.
    // It carries the grant captured at minting, expires after thirty seconds,
    // and can be redeemed once.
    if let Some(token) = crate::tickets::from_query(req.uri().query())
        && let Some(tickets) = &st.tickets
    {
        let Some(bearer) = tickets.redeem(token, &path).await else {
            warn!(%method, %path, "console ticket rejected");
            return deny(
                StatusCode::UNAUTHORIZED,
                "Unauthorized",
                "that console ticket is not one, or is spent, or has expired".to_string(),
                None,
            );
        };
        if !permits(
            &bearer.identity,
            bearer.role,
            bearer.tenant.as_deref(),
            &attempt,
            None,
        ) {
            warn!(%method, %path, identity = %bearer.identity, "forbidden");
            return deny(
                StatusCode::FORBIDDEN,
                "Forbidden",
                format!(
                    "{} may not {:?} {}",
                    bearer.identity.name, attempt.verb, attempt.resource
                ),
                None,
            );
        }
        info!(%method, %path, identity = %bearer.identity, "authorized by ticket");
        req.extensions_mut()
            .insert(Authenticated::As(bearer.identity.clone()));
        req.extensions_mut().insert(bearer.identity);
        req.extensions_mut().insert(CallerRole(bearer.role));
        req.extensions_mut().insert(CallerTenant(bearer.tenant));
        return next.run(req).await;
    }

    let auth_request = AuthRequest {
        peer_certs: req
            .extensions()
            .get::<PeerCerts>()
            .map(|c| c.0.clone())
            .unwrap_or_default(),
        authorization: req
            .headers()
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string),
    };

    let who = match st.chain.authenticate(&auth_request) {
        Ok(who) => who,
        Err(rejected) => {
            // Keep authentication refusals visible at warning level for audit.
            warn!(%method, %path, reason = %rejected, "unauthenticated");
            return deny(
                StatusCode::UNAUTHORIZED,
                "Unauthorized",
                rejected.to_string(),
                None,
            );
        }
    };

    let identity = match &who {
        // No chain configured: the mode this stack ran in for four
        // milestones, and nothing to check.
        Authenticated::Anonymous => {
            req.extensions_mut().insert(who.clone());
            return next.run(req).await;
        }
        Authenticated::As(identity) => identity.clone(),
    };

    let (role, tenant) = match grant_of(&st, &identity).await {
        Ok(grant) => grant,
        Err(response) => return response,
    };

    // The forwarding marker permits only the explicitly allowed sibling writes;
    // it does not replace identity authorization.
    let forwarded = req.headers().contains_key(crate::forward::FORWARDED);
    if !permits(
        &identity,
        role,
        tenant.as_deref(),
        &attempt,
        st.own_peer
            .as_ref()
            .map(|(kind, name)| crate::auth::OwnPeer {
                kind,
                name: name.as_str(),
                forwarded,
            }),
    ) {
        // Warn for the same reason `unauthenticated` above is one.
        warn!(%method, %path, identity = %identity, ?role, ?tenant, "forbidden");
        return deny(
            StatusCode::FORBIDDEN,
            "Forbidden",
            format!(
                "{} may not {:?} {}",
                identity.name, attempt.verb, attempt.resource
            ),
            None,
        );
    }

    // The audit line. Info rather than debug because the REST API's only
    // client is a person with a CLI — this is human-scale traffic, and an
    // operator who has just turned a chain on wants to see who is calling.
    info!(%method, %path, identity = %identity, ?role, ?tenant, "authorized");
    req.extensions_mut().insert(who);
    req.extensions_mut().insert(identity);
    req.extensions_mut().insert(CallerRole(role));
    req.extensions_mut().insert(CallerTenant(tenant));
    next.run(req).await
}

/// Resolve role and tenant together from the caller's directory entry.
pub(super) async fn grant_of(
    st: &AuthState,
    identity: &Identity,
) -> Result<(Option<Role>, Option<String>), Response> {
    // Nodes and controllers have no object in the directory and never will;
    // asking etcd about them on every request would be a lookup whose answer
    // is known.
    if identity.is_system() {
        return Ok((None, None));
    }
    let Some(store) = &st.directory else {
        // This tier cannot resolve a current human grant. Refuse rather than
        // reuse certificate role claims that may outlive directory demotion.
        return Err(deny(
            StatusCode::FORBIDDEN,
            "Forbidden",
            format!(
                "{} presented a user certificate and this endpoint keeps no user directory; \
                 what a user may do is decided at the cloud. Work there, or present a \
                 break-glass certificate here.",
                identity.name
            ),
            None,
        ));
    };
    match store.get::<User>(&identity.name).await {
        Ok(user) => {
            let tenant = Some(user.spec.tenant).filter(|t| !t.is_empty());
            Ok((Some(user.spec.role), tenant))
        }
        // An unknown directory user has no grant unless explicit OIDC
        // first-login provisioning admits them.
        Err(StoreError::NotFound(_)) => match provision(st, identity).await {
            Ok(Some(user)) => Ok((
                Some(user.spec.role),
                Some(user.spec.tenant).filter(|t| !t.is_empty()),
            )),
            Ok(None) => Ok((None, None)),
            Err(e) => {
                // Log provisioning failure and retain the unknown-user denial.
                warn!(
                    identity = %identity,
                    error = %format!("{e:#}"),
                    "could not provision a user for a token this provider vouched for"
                );
                Ok((None, None))
            }
        },
        // The directory is unreachable. Refusing beats guessing: this is the
        // only thing standing between a certificate and a write.
        Err(e) => Err(deny(
            StatusCode::SERVICE_UNAVAILABLE,
            "Timeout",
            format!("cannot reach the user directory: {e}"),
            None,
        )),
    }
}

/// Optionally provision an unknown OIDC identity as a Member. Requires an
/// explicitly configured tenant claim naming an existing tenant; certificate
/// identities do not use this path. Disabled by default. This may create the
/// directory entry during the user's first authenticated GET.
pub(super) async fn provision(st: &AuthState, identity: &Identity) -> anyhow::Result<Option<User>> {
    if !st.provision_oidc_users || !identity.has_group(crate::oidc::GROUP_OIDC) {
        return Ok(None);
    }
    let Some(store) = &st.directory else {
        return Ok(None);
    };
    let Some(tenant) = crate::oidc::claimed_tenant(identity) else {
        anyhow::bail!("the token carries no tenant claim, so there is no tenant to put them in");
    };
    if let Err(e) = store.get::<crate::resources::Tenant>(tenant).await {
        anyhow::bail!("the token claims tenant {tenant:?}, which does not exist here: {e}");
    }

    let mut user = User::new(
        API_VERSION,
        User::KIND,
        &identity.name,
        crate::resources::UserSpec {
            tenant: tenant.to_string(),
            role: Role::Member,
            description: "created at first login from an oidc token".into(),
        },
    );
    match store.create(&user).await {
        Ok(created) => {
            info!(
                identity = %identity,
                tenant = %tenant,
                "created a user at first login"
            );
            Ok(Some(created))
        }
        // Two of this person's requests raced and the other one won. That is
        // a success, not a conflict: read what it wrote.
        Err(StoreError::AlreadyExists(_)) => {
            user = store.get::<User>(&identity.name).await?;
            Ok(Some(user))
        }
        Err(e) => Err(e.into()),
    }
}

/// Authenticated identity, or None for anonymous mode and ungated routes.
#[derive(Clone, Debug, Default)]
pub struct Caller(pub Option<Identity>);

/// Directory-derived role, separate from the credential identity and its labels.
#[derive(Clone, Copy, Debug)]
pub struct CallerRole(pub Option<Role>);

/// Directory-derived tenant used with CallerRole for object authorization.
#[derive(Clone, Debug, Default)]
pub struct CallerTenant(pub Option<String>);

impl<S: Send + Sync> axum::extract::FromRequestParts<S> for Caller {
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        _: &S,
    ) -> std::result::Result<Self, Self::Rejection> {
        Ok(Caller(parts.extensions.get::<Identity>().cloned()))
    }
}

impl<S: Send + Sync> axum::extract::FromRequestParts<S> for CallerRole {
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        _: &S,
    ) -> std::result::Result<Self, Self::Rejection> {
        Ok(parts
            .extensions
            .get::<CallerRole>()
            .copied()
            .unwrap_or(CallerRole(None)))
    }
}

impl<S: Send + Sync> axum::extract::FromRequestParts<S> for CallerTenant {
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        _: &S,
    ) -> std::result::Result<Self, Self::Rejection> {
        Ok(parts
            .extensions
            .get::<CallerTenant>()
            .cloned()
            .unwrap_or_default())
    }
}

impl Caller {
    pub fn name(&self) -> &str {
        self.0
            .as_ref()
            .map(|i| i.name.as_str())
            .unwrap_or("anonymous")
    }

    /// Allow self-service; acting for another user requires established
    /// admin authority or a system identity. Use the current directory role,
    /// not a certificate's stale role group. Anonymous mode remains unrestricted.
    pub fn may_act_for(&self, role: Option<Role>, username: &str) -> bool {
        let Some(identity) = &self.0 else {
            return true;
        };
        identity.name == username || identity.is_system() || role == Some(Role::Admin)
    }
}

// --- turning config keys into a chain and a listener ------------------------

/// Shared controller authentication configuration. Credential values live in
/// referenced files rather than directly in TOML.
#[derive(Debug, Default, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthConfig {
    /// Authenticator order; defaults to mtls then bearer, omitting unconfigured links.
    /// An empty resulting chain is refused unless `anonymous` is set. First rejection
    /// ends the chain, so order matters when a request carries multiple credentials.
    pub chain: Option<Vec<String>>,
    /// Admit every request without credentials. Only valid when no authenticator
    /// is configured, and off by default: an empty chain serves anybody as an
    /// administrator, so it has to be asked for rather than fallen into by a
    /// configuration that forgot its client CA.
    #[serde(default)]
    pub anonymous: bool,
    /// File containing a static development/bootstrap token without built-in expiry
    /// or rotation. Replacing the credential requires operational management.
    pub bearer_token_file: Option<std::path::PathBuf>,
    /// Who that token is. Defaults to a name that says what it is.
    pub bearer_identity: Option<String>,
    /// Bearer identity groups, defaulting to system:masters for directory bootstrap.
    pub bearer_groups: Option<Vec<String>>,
    /// The identity provider, when this tier has one. See `OidcConfig`.
    pub oidc: Option<OidcConfig>,
    /// Optional public CRL file. Unreadable configured files fail startup;
    /// application revocation checks reload replacements during operation.
    pub crl: Option<std::path::PathBuf>,
    // --- end lane 5A ---------------------------------------------------
}

/// Cloud OIDC configuration. User authorization requires the directory, which
/// the cluster tier does not provide.
#[derive(Debug, Default, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OidcConfig {
    /// Issuer URL used for discovery. The returned document must name the exact
    /// same issuer before its signing-key location is accepted.
    pub issuer: String,
    /// Who we are to the provider. Also the default audience, because for
    /// most providers those are the same string.
    pub client_id: String,
    /// Which audiences a token may carry. Defaults to `[client_id]`. A token
    /// issued for another service is not a token for this one.
    pub audience: Option<Vec<String>>,
    /// Stable username claim, defaulting to sub. Mutable values such as email can
    /// disconnect an identity from its existing directory entry.
    pub username_claim: Option<String>,
    /// Pinned accepted signature algorithms, defaulting to RS256 and ES256.
    /// Provider-advertised algorithms do not expand this allowlist.
    pub allowed_algorithms: Option<Vec<String>>,
    /// Clock drift allowed on `exp` and `nbf`, seconds. Default 60.
    pub leeway_secs: Option<u64>,
    /// Minimum interval between unknown-key-triggered fetches, in seconds; default 60.
    /// Bounds provider requests under a flood of fabricated key IDs.
    pub min_refetch_interval_secs: Option<u64>,
    /// How often to refetch the keys with nobody asking, seconds. Default
    /// 3600, so that a rotation is usually picked up before any request
    /// meets an unknown key at all.
    pub refresh_interval_secs: Option<u64>,
    /// The CA that signed the provider, for a provider that is not on the
    /// public internet. Absent = the platform's own roots, which is right
    /// for a real provider and wrong for a lab one.
    pub ca_cert: Option<std::path::PathBuf>,
    /// Opt-in OIDC first-login provisioning; disabled by default. The grant
    /// is always Member and requires a claim naming an existing tenant.
    /// Role claims cannot grant administrator access.
    pub provision_unknown_users: Option<bool>,
    /// Which claim names the tenant a provisioned user lands in. Required
    /// for `provision_unknown_users`, and useless without it.
    pub tenant_claim: Option<String>,
}

pub(super) const DEFAULT_CHAIN: [&str; 3] = ["mtls", "oidc", "bearer"];

/// Controller tier assembling authentication and authorization.
/// Only the cloud has the person directory needed to derive roles.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tier {
    Cloud,
    Cluster,
}

impl Tier {
    /// What a discovery document says under `tier`. The one word that used to
    /// be a key in every CLI profile.
    pub fn as_str(self) -> &'static str {
        match self {
            Tier::Cloud => "cloud",
            Tier::Cluster => "cluster",
        }
    }
}

/// Resolve authenticator configuration without file or network access.
/// Default chains omit unconfigured links; explicit unusable links are errors.
/// An empty chain needs `auth.anonymous`, and that flag needs an empty chain.
/// Session-serving processes must meet the mTLS requirement. File readability,
/// file contents and provider discovery are checked during actual construction.
pub fn check_chain(
    cfg: &AuthConfig,
    has_client_ca: bool,
    tier: Tier,
    serves_sessions: bool,
) -> Result<Vec<&'static str>> {
    let explicit = cfg.chain.is_some();
    let names: Vec<String> = cfg
        .chain
        .clone()
        .unwrap_or_else(|| DEFAULT_CHAIN.iter().map(|s| s.to_string()).collect());

    // Reject bearer-before-OIDC ordering: both inspect Authorization and the
    // static bearer link would reject JWTs before OIDC could validate them.
    let position = |want: &str| names.iter().position(|n| n == want);
    if let (Some(bearer), Some(oidc)) = (position("bearer"), position("oidc"))
        && bearer < oidc
    {
        anyhow::bail!(
            "auth.chain puts \"bearer\" before \"oidc\"; the static token link refuses \
             every bearer value it does not recognise and the chain stops there, so no \
             token would ever reach the oidc link. Put \"oidc\" first."
        );
    }

    // Publish only authenticators that will actually be built, excluding default
    // links omitted for missing configuration.
    let mut built: Vec<&'static str> = Vec::new();
    for name in &names {
        match name.as_str() {
            "oidc" => match &cfg.oidc {
                Some(_) if tier == Tier::Cloud => built.push("oidc"),
                Some(_) => anyhow::bail!(
                    "auth.oidc is configured at the cluster tier, which keeps no user \
                     directory and so cannot turn a token's name into a role. Machines \
                     authenticate here with certificates."
                ),
                None if explicit => {
                    anyhow::bail!("auth.chain names \"oidc\" but no [auth.oidc] is configured")
                }
                None => {}
            },
            "mtls" => {
                if has_client_ca {
                    built.push("mtls");
                } else if explicit {
                    anyhow::bail!("auth.chain names \"mtls\" but no client_ca is configured");
                }
            }
            "bearer" => match &cfg.bearer_token_file {
                Some(_) => built.push("bearer"),
                None if explicit => anyhow::bail!(
                    "auth.chain names \"bearer\" but no auth.bearer_token_file is configured"
                ),
                None => {}
            },
            other => anyhow::bail!(
                "unknown authenticator {other:?} in auth.chain; known: {}",
                DEFAULT_CHAIN.join(", ")
            ),
        }
    }
    // Last, so that a chain naming a link it cannot build hears about THAT
    // first: "no bearer_token_file" is a sentence about one line of the
    // config, and these two are about the whole shape of it.
    mtls_or_no_peers(&names, explicit, serves_sessions)?;
    anonymous_only_when_asked(&built, cfg.anonymous)?;
    Ok(built)
}

/// Refuse an empty chain that nobody asked for, and a request for anonymous
/// access beside authenticators that would never let it happen.
pub(super) fn anonymous_only_when_asked(built: &[&str], anonymous: bool) -> Result<()> {
    match (built.is_empty(), anonymous) {
        (true, false) => anyhow::bail!(
            "no authenticator is configured, so every request would be served anonymously \
             and with every permission. Configure one (client_ca for mtls, [auth.oidc], or \
             auth.bearer_token_file), or write `anonymous = true` under [auth] for a \
             throwaway local controller."
        ),
        (false, true) => anyhow::bail!(
            "auth.anonymous = true, and the chain still builds {built:?}: a request without \
             credentials would be refused anyway. Remove one of the two."
        ),
        _ => Ok(()),
    }
}

/// Load files and construct the authenticators selected by `check_chain`.
pub fn build_chain(
    cfg: &AuthConfig,
    client_ca: Option<&std::path::Path>,
    base: Option<&std::path::Path>,
    tier: Tier,
    serves_sessions: bool,
) -> Result<AuthChain> {
    Ok(build_chain_with_revocations(cfg, client_ca, base, tier, serves_sessions)?.0)
}

// --- lane 5A ---------------------------------------------------------------
/// The same, and it hands back the revocation list it built the chain with.
///
/// Two functions rather than a second parameter on one, because the list is
/// wanted by somebody ELSE as well: the session registries close a running
/// session whose certificate is revoked, and a periodic task reloads the
/// file. There has to be exactly one `Revocations` in a process — two would
/// be two answers to one question, half a minute apart — so it is built here
/// and handed out.
pub fn build_chain_with_revocations(
    cfg: &AuthConfig,
    client_ca: Option<&std::path::Path>,
    base: Option<&std::path::Path>,
    tier: Tier,
    serves_sessions: bool,
) -> Result<(AuthChain, Option<std::sync::Arc<crate::auth::Revocations>>)> {
    let revocations = match &cfg.crl {
        Some(path) => {
            let path = pki::pem::resolve(base, path);
            Some(crate::auth::Revocations::load(&path).with_context(|| {
                format!(
                    "the revocation list {} could not be read. `auth.crl` is set, so this \
                     controller is configured to enforce revocation and will not start \
                     without it; `meister-ca --index-rebuild --gencrl` writes one.",
                    path.display()
                )
            })?)
        }
        None => None,
    };
    let chain = build_links(cfg, client_ca, base, tier, serves_sessions, &revocations)?;
    Ok((chain, revocations))
}
// --- end lane 5A -----------------------------------------------------------

fn build_links(
    cfg: &AuthConfig,
    client_ca: Option<&std::path::Path>,
    base: Option<&std::path::Path>,
    tier: Tier,
    serves_sessions: bool,
    revocations: &Option<std::sync::Arc<crate::auth::Revocations>>,
) -> Result<AuthChain> {
    let built = check_chain(cfg, client_ca.is_some(), tier, serves_sessions)?;
    let mut links: Vec<Box<dyn crate::auth::Authenticator>> = Vec::new();
    for name in &built {
        match *name {
            "oidc" => {
                let oidc = cfg.oidc.as_ref().expect("check_chain named it");
                links.push(Box::new(build_oidc(oidc, base)?));
            }
            "mtls" => {
                let ca = pki::pem::resolve(base, client_ca.expect("check_chain named it"));
                links.push(Box::new(
                    crate::auth::MtlsAuthenticator::from_pem_file(&ca)?
                        // --- lane 5A: the one place both ports pass ---
                        .with_revocations(revocations.clone()),
                ));
                info!(
                    ca = %ca.display(),
                    crl = revocations.as_ref().map(|r| r.path().display().to_string()),
                    "mtls authenticator"
                );
            }
            "bearer" => {
                let path = pki::pem::resolve(
                    base,
                    cfg.bearer_token_file
                        .as_ref()
                        .expect("check_chain named it"),
                );
                let token = std::fs::read_to_string(&path)
                    .with_context(|| format!("reading the bearer token {}", path.display()))?
                    .trim()
                    .to_string();
                if token.is_empty() {
                    anyhow::bail!("{} is empty", path.display());
                }
                let identity = Identity::new(
                    cfg.bearer_identity
                        .clone()
                        .unwrap_or_else(|| "dev-bearer".to_string()),
                    cfg.bearer_groups
                        .clone()
                        .unwrap_or_else(|| vec![crate::auth::GROUP_MASTERS.to_string()]),
                );
                warn!(identity = %identity, "static bearer token enabled, development path");
                links.push(Box::new(crate::auth::BearerAuthenticator::new(
                    token, identity,
                )));
            }
            other => unreachable!("check_chain returned {other:?}"),
        }
    }
    Ok(AuthChain::named(links, built))
}

/// Require mTLS in a configured authentication chain when serving peer
/// sessions, which authenticate by certificate. REST-only endpoints
/// have no peer requirement and receive a warning instead.
pub(super) fn mtls_or_no_peers(
    names: &[String],
    explicit: bool,
    serves_sessions: bool,
) -> Result<()> {
    // A defaulted chain names mtls already, and a chain that names it and
    // could not build it is refused by the loop below with a better sentence
    // ("no client_ca is configured").
    if !explicit || names.iter().any(|n| n == "mtls") {
        return Ok(());
    }
    if !serves_sessions {
        warn!(
            chain = ?names,
            "auth.chain has no \"mtls\" link; this process serves no session port, so it \
             admits no clusters and no nodes and nothing is being locked out"
        );
        return Ok(());
    }
    anyhow::bail!(
        "auth.chain names {names:?} and no \"mtls\": the session ports authenticate peers by \
         certificate only; a chain without mtls cannot admit a cluster or a node. Write \
         [\"mtls\", \"bearer\"] and point client_ca at a CA (tools/meister-ca makes a \
         throwaway one)."
    )
}

/// Build the OIDC authenticator and its background key refresher.
/// Startup does not wait for the provider; tokens fail until usable keys
/// arrive while other authenticators remain available. The task ends
/// when the authenticator is no longer held.
pub(super) fn build_oidc(
    cfg: &OidcConfig,
    base: Option<&std::path::Path>,
) -> Result<crate::oidc::OidcAuthenticator> {
    use meister_oidc::cache::{DEFAULT_MIN_REFETCH_INTERVAL, DEFAULT_REFRESH_INTERVAL, KeyCache};
    use meister_oidc::jwks::Alg;
    use meister_oidc::jwt::{DEFAULT_LEEWAY, DEFAULT_USERNAME_CLAIM, Validation};

    if cfg.issuer.trim().is_empty() {
        anyhow::bail!("auth.oidc.issuer is empty");
    }
    if cfg.client_id.trim().is_empty() {
        anyhow::bail!("auth.oidc.client_id is empty");
    }
    let audience = cfg
        .audience
        .clone()
        .unwrap_or_else(|| vec![cfg.client_id.clone()]);
    if audience.iter().all(|a| a.trim().is_empty()) {
        // An empty audience is not a permissive setting, it is no check at
        // all: every token the provider ever minted, for any service it
        // serves, would be accepted here.
        anyhow::bail!("auth.oidc.audience is empty; a token for any service would be accepted");
    }

    let allowed = match &cfg.allowed_algorithms {
        None => Alg::DEFAULT_ALLOWED.to_vec(),
        Some(names) => {
            let mut out = Vec::new();
            for name in names {
                let alg = Alg::parse(name).with_context(|| {
                    format!(
                        "auth.oidc.allowed_algorithms names {name:?}; only asymmetric \
                         algorithms are accepted (RS256, RS384, RS512, ES256, ES384)"
                    )
                })?;
                out.push(alg);
            }
            if out.is_empty() {
                anyhow::bail!("auth.oidc.allowed_algorithms is empty; no token could be checked");
            }
            out
        }
    };

    let mut validation = Validation::new(cfg.issuer.trim(), audience);
    validation.allowed = allowed;
    validation.username_claim = cfg
        .username_claim
        .clone()
        .unwrap_or_else(|| DEFAULT_USERNAME_CLAIM.to_string());
    validation.leeway = cfg
        .leeway_secs
        .map(Duration::from_secs)
        .unwrap_or(DEFAULT_LEEWAY);

    // Provisioning needs a tenant and refuses to guess one: without the
    // claim there is nothing to put in the `User` object, and a default
    // tenant would be a room everybody the provider knows shares.
    let provision = cfg.provision_unknown_users.unwrap_or(false);
    let tenant_claim = cfg.tenant_claim.clone().filter(|c| !c.trim().is_empty());
    if provision && tenant_claim.is_none() {
        anyhow::bail!(
            "auth.oidc.provision_unknown_users is on but no auth.oidc.tenant_claim is set; \
             there would be no tenant to put a new user in"
        );
    }
    if provision {
        warn!(
            issuer = %cfg.issuer,
            tenant_claim = tenant_claim.as_deref().unwrap_or(""),
            "first-login provisioning is on: everybody the identity provider knows has a \
             foot in the door"
        );
    }

    let ca = cfg.ca_cert.as_ref().map(|p| pki::pem::resolve(base, p));
    let (cache, handle) = KeyCache::new(
        cfg.min_refetch_interval_secs
            .map(Duration::from_secs)
            .unwrap_or(DEFAULT_MIN_REFETCH_INTERVAL),
    );
    let cache = Arc::new(cache);
    let source: Arc<dyn meister_oidc::discovery::KeySource> = Arc::new(
        meister_oidc::discovery::HttpKeySource::new(cfg.issuer.trim(), ca.clone()),
    );
    let interval = cfg
        .refresh_interval_secs
        .map(Duration::from_secs)
        .unwrap_or(DEFAULT_REFRESH_INTERVAL);
    tokio::spawn(meister_oidc::discovery::refresh_forever(
        // Weak: the task must not keep the cache — and with it the channel
        // that tells the task to stop — alive on its own.
        Arc::downgrade(&cache),
        source,
        handle,
        interval,
        DEFAULT_MIN_REFETCH_INTERVAL,
    ));

    info!(
        issuer = %cfg.issuer,
        username_claim = %validation.username_claim,
        algorithms = %validation
            .allowed
            .iter()
            .map(|a| a.as_str())
            .collect::<Vec<_>>()
            .join(","),
        provision_unknown_users = provision,
        "oidc authenticator"
    );
    Ok(crate::oidc::OidcAuthenticator::new(
        validation,
        cache,
        tenant_claim.filter(|_| provision),
    ))
}
