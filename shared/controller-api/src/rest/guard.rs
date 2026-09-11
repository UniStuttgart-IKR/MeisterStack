// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Who is asking, and what they may do: the chain built from config, the
//! middleware that runs it, what a caller is once it has run, and `whoami`.
//! Moved out of `rest.rs` unchanged.

use super::*;

/// What the guard needs to answer a request.
#[derive(Clone)]
pub struct AuthState {
    pub chain: Arc<AuthChain>,
    /// Where the `User` objects are, when this tier has them.
    ///
    /// The cloud passes its store and the role comes out of the directory,
    /// because the directory is the truth and a role change there has to take
    /// effect at once. The cluster passes `None` — it has no users of its own
    /// on purpose (one directory, one truth) — and since the permission table
    /// that means it authorizes no person at all: a user certificate is
    /// refused there with a sentence saying where the answer lives. It used
    /// to read the role off the certificate instead, which is what made the
    /// group in a certificate a permission rather than a label.
    pub directory: Option<Arc<EtcdStore>>,
    /// Create a `User` for an identity out of a token that the directory
    /// does not know yet. `auth.oidc.provision_unknown_users`, off by
    /// default. See `provision`.
    pub provision_oidc_users: bool,
    /// The tier this router IS: `("cluster", name)` or `("cloud", name)`.
    ///
    /// The single exception to "a machine identity has nothing at REST": a
    /// replica of this same tier may read here, because that is how a
    /// `vm logs` reaches the replica that holds the session. Both tiers pass
    /// one now — the cloud's console and log forwards need exactly what the
    /// cluster's needed, one scope up. `None` is a tier with no siblings,
    /// which is what a test router is.
    pub own_peer: Option<(&'static str, String)>,
    /// The console tickets this TIER has outstanding, where it mints any.
    /// `None` is a tier that does not — the `?ticket=` parameter is then
    /// simply not a credential, and a request carrying one is judged by the
    /// chain like every other.
    ///
    /// "This tier" and not "this replica": the tickets live in the tier's own
    /// etcd, so a browser that minted at one replica and opens its socket at
    /// the next one is served rather than refused.
    ///
    /// Here rather than in a handler because a ticket has to be honoured
    /// BEFORE the chain runs: the whole point of it is a request that carries
    /// no header at all.
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

/// Where a caller asks the server who it thinks they are.
///
/// Every client so far had to guess. The name in a console's account menu was
/// either its own configuration (bearer mode) or a claim out of the caller's
/// own token (OIDC) — both statements ABOUT the caller that the server had
/// never confirmed — and what the caller MAY do was found out by trying:
/// `GET /tenants` and `GET /clusters` at startup, two requests whose only
/// purpose was to ask a question no route answered.
///
/// GATED, unlike the discovery beside it, and the difference is what the
/// answer is made of. A discovery document says what this endpoint serves,
/// which is true before anybody has said hello. This is the DIRECTORY's word
/// about one person, and a directory that answers questions about its
/// entries to anybody who asks is a directory of names for somebody to try
/// credentials against. In anonymous mode — no chain configured at all — it
/// answers `anonymous`, which is exactly what the server believes.
pub const WHOAMI_PATH: &str = "/apis/meister.io/v1/whoami";

/// `{name, tenant, role, groups, tier}` — with the two the directory
/// establishes left out where there is no directory.
///
/// Absent rather than null, and that is the honest shape: the cluster tier
/// keeps no users on purpose, so it cannot say what a role is, and a `null`
/// role would read as "no permissions" rather than "not decided here". A
/// client reads `tier` and knows which of the two answers it is holding.
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
        // What the CERTIFICATE or the token says, which is a label and not a
        // permission — `role` below is the permission, and it comes from the
        // directory. Both are here because a person holding a credential
        // should be able to read what it was issued for.
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

    // Not an API object route — /healthz, /readyz. Never gated, and the
    // ordering matters: a probe presents no credential, so authenticating
    // first would answer 401 to the question "are you up", and an operator
    // cannot tell that from "you are down".
    let Some(attempt) = classify(&method, &path) else {
        return next.run(req).await;
    };

    // A ticket first, because a ticket is what a request that CANNOT carry a
    // header presents instead. It is not a way around the chain: what it
    // carries is the permission its holder already had when they asked for
    // it, and it opens the one path it was minted for, once, for thirty
    // seconds. See `crate::tickets`.
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
            // Warn rather than the info the level contract would give a
            // refusal that degrades nothing: this pair and `forbidden` below
            // are the only trace a credential that should not exist leaves,
            // and a rejection an operator has to raise the level to see is a
            // rejection nobody sees. Deliberate, and the one place in this
            // tree where audit visibility outranks the contract.
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

    // A sibling passing on what a person asked it, once. It is what opens
    // the one write a replica cannot serve on its own — see
    // `OwnPeer::forwarded` — and nothing else about this request depends on
    // it.
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

/// What this identity may do and whose tenant it is in, from the directory
/// where there is one.
///
/// The two travel together because they come out of the same object and are
/// worth exactly nothing apart: a role without a tenant cannot scope, and a
/// tenant without a role cannot decide.
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
        // No directory at this tier, so there is nobody to look this name up
        // in — and until the permission table there was a compromise here:
        // the certificate's own group was taken as the answer. That made the
        // group a PERMISSION, which is exactly the thing a demotion cannot
        // take back until the certificate expires.
        //
        // There is one user directory in this stack and it is the cloud's. A
        // tier without it authorizes no person at all, and says so in a
        // sentence rather than through a 403 about a resource. Machine
        // identities returned above and are unaffected; so is anonymous mode,
        // which never reaches here.
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
        // A valid credential for a name the directory does not know. Not an
        // error: it is somebody whose account was removed, and the honest
        // answer is that they may do nothing, said in words.
        //
        // It is also every OIDC user's first request, which is why the one
        // switch that can change this answer is here. Off, the answer stays
        // "nothing", and a token for somebody an administrator has not
        // entered in the directory is worth exactly as much as a certificate
        // for a deleted account.
        Err(StoreError::NotFound(_)) => match provision(st, identity).await {
            Ok(Some(user)) => Ok((
                Some(user.spec.role),
                Some(user.spec.tenant).filter(|t| !t.is_empty()),
            )),
            Ok(None) => Ok((None, None)),
            Err(e) => {
                // Not fatal to the request: it falls back to the answer it
                // would have had, which is "you may do nothing". Warn,
                // because an operator who switched this on wants to know it
                // is not working.
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

/// Make a `User` for somebody the identity provider vouched for and the
/// directory has never seen.
///
/// **Switched on, this means that everybody the identity provider knows has
/// a foot in the door.** That sentence is the switch's whole risk and it is
/// why the default is off: with it on, the directory stops being a list an
/// administrator wrote and becomes a list the provider writes.
///
/// Four things bound it, and none of them is decoration:
///
/// * Only an identity out of a token. A certificate for an unknown name is
///   still nobody — that path has its own bootstrap (`system:masters`) and
///   does not need a second one.
/// * The role is always `Member`, hard-coded here, never read from a claim.
///   Deriving a role from a token would contradict the invariant the rest of
///   this file is built on: the directory is the truth about what somebody
///   may do.
/// * The tenant comes from the claim the operator nominated. There is no
///   default tenant, because a default would be one room everybody the
///   provider knows shares.
/// * That tenant has to EXIST. This is the bound that makes the switch
///   defensible: what a stranger gets a foot into is a room an administrator
///   has already built and named, not one their own token invented.
///
/// Yes, this writes during a GET. It is the one write in the request path
/// and it happens once per person, ever; the alternative — provisioning from
/// a background task — would mean the first command after a login failing
/// for reasons nobody could act on.
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

/// The identity a handler is running for, when the chain established one.
///
/// `None` covers both anonymous mode and the routes that are never gated. A
/// handler that has to tell those apart is a handler that has stopped working
/// in anonymous mode, which is why they are the same value here.
#[derive(Clone, Debug, Default)]
pub struct Caller(pub Option<Identity>);

/// The role the guard established for this request, where it could.
///
/// Its own extension rather than a field on `Caller` because it is a
/// different KIND of fact: `Caller` is what the certificate said, this is
/// what the directory says, and the whole point of keeping a directory is
/// that the second one can disagree with the first.
#[derive(Clone, Copy, Debug)]
pub struct CallerRole(pub Option<Role>);

/// The tenant the directory puts this caller in, where there is a directory.
///
/// Its own extension and its own extractor for the same reason `CallerRole`
/// is: a handler asks for what it needs. Almost all of them need both, and
/// the pair is what `permits_object` takes.
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

    /// May this caller act for `username`?
    ///
    /// Anonymous mode says yes to everything, as it does everywhere else.
    /// Otherwise: yourself always, anybody else only if you are an admin or
    /// the stack itself. This is the check that keeps
    /// `certificatesigningrequests` from being a privilege escalation — a
    /// member may renew their own certificate, and must not be able to ask
    /// for the administrator's.
    ///
    /// `role` is the ESTABLISHED role, not the one the certificate claims,
    /// and the difference is the whole reason it is a parameter. A user
    /// demoted from admin to member still carries `O=meister:admins` until
    /// their certificate is re-issued; reading the claim here would let them
    /// go on requesting certificates for other people — with
    /// `csr_auto_approve`, a certificate for anybody in the directory — for
    /// the remaining life of a credential the operator believes they have
    /// taken away.
    pub fn may_act_for(&self, role: Option<Role>, username: &str) -> bool {
        let Some(identity) = &self.0 else {
            return true;
        };
        identity.name == username || identity.is_system() || role == Some(Role::Admin)
    }
}

// --- turning config keys into a chain and a listener ------------------------

/// The `[auth]` table of a controller config, identical at both tiers.
///
/// Nothing in here is a secret: a token lives in a file whose path is named
/// here, exactly as every certificate does. A credential that can be pasted
/// into a TOML file is a credential that ends up in a git history.
#[derive(Debug, Default, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthConfig {
    /// Which authenticators, in which order. Absent = "mtls", "bearer" —
    /// each of which contributes a link only if it has what it needs, so an
    /// empty `[auth]` table is still the anonymous mode.
    ///
    /// Order is the security-relevant part and that is why it is spelled out
    /// rather than inferred: the chain stops at the first hard no, so what
    /// comes first decides what a request with two credentials is judged as.
    pub chain: Option<Vec<String>>,
    /// The development bearer token. One static string, no expiry, no
    /// rotation — it exists so that a brand new user can ask for the
    /// certificate they do not have yet, and so that a lab has a way in
    /// without a CA. Treat a leak as permanent.
    pub bearer_token_file: Option<std::path::PathBuf>,
    /// Who that token is. Defaults to a name that says what it is.
    pub bearer_identity: Option<String>,
    /// And what it may do. Defaults to `system:masters` — break glass —
    /// because the bootstrap this token exists for is creating the first
    /// tenant and the first user, and until those exist there is no directory
    /// entry for an ordinary admin to be found in.
    pub bearer_groups: Option<Vec<String>>,
    /// The identity provider, when this tier has one. See `OidcConfig`.
    pub oidc: Option<OidcConfig>,
}

/// The `[auth.oidc]` table.
///
/// Cloud only. The cluster tier keeps no user directory — that is a design
/// decision of this stack and `auth::permits` says why — and without one it
/// cannot turn a name into a role, so a token would authenticate somebody it
/// could then permit nothing. It stays on certificates.
#[derive(Debug, Default, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OidcConfig {
    /// The issuer url, exactly as the provider spells it in its own
    /// documents. `.well-known/openid-configuration` is appended to it and
    /// the document that comes back has to name this same string, or the
    /// keys it points at are not taken.
    pub issuer: String,
    /// Who we are to the provider. Also the default audience, because for
    /// most providers those are the same string.
    pub client_id: String,
    /// Which audiences a token may carry. Defaults to `[client_id]`. A token
    /// issued for another service is not a token for this one.
    pub audience: Option<Vec<String>>,
    /// Which claim is the username. Defaults to `sub`.
    ///
    /// Worth a deliberate answer rather than a default accepted by silence:
    /// providers put it in different places, and `email` — the tempting one
    /// — is a trap, because an address changes and a name that changes
    /// silently detaches a person from everything they own here.
    pub username_claim: Option<String>,
    /// Which signature algorithms are accepted. Defaults to RS256 and
    /// ES256, both asymmetric.
    ///
    /// What the provider ADVERTISES is not what we accept: this is the pin,
    /// and without one an attacker gets to choose the algorithm their token
    /// is checked under.
    pub allowed_algorithms: Option<Vec<String>>,
    /// Clock drift allowed on `exp` and `nbf`, seconds. Default 60.
    pub leeway_secs: Option<u64>,
    /// The floor between two key fetches asked for by a request that met an
    /// unknown key id, seconds. Default 60.
    ///
    /// This is a rate limit and not a tuning knob: without it a token with a
    /// random `kid` is one request to the identity provider, and tokens are
    /// free to make.
    pub min_refetch_interval_secs: Option<u64>,
    /// How often to refetch the keys with nobody asking, seconds. Default
    /// 3600, so that a rotation is usually picked up before any request
    /// meets an unknown key at all.
    pub refresh_interval_secs: Option<u64>,
    /// The CA that signed the provider, for a provider that is not on the
    /// public internet. Absent = the platform's own roots, which is right
    /// for a real provider and wrong for a lab one.
    pub ca_cert: Option<std::path::PathBuf>,
    /// Create a `User` for somebody the directory does not know yet.
    ///
    /// Switched on, this means that everybody the identity provider knows
    /// has a foot in the door.
    ///
    /// Off by default, and that default is the recommendation. What it buys
    /// is that a new colleague does not need an admin before their first
    /// command; what it costs is that the directory stops being a list an
    /// administrator wrote. Three things bound it, and all three are
    /// deliberate: the role is always `member` and is never read from a
    /// claim, the tenant must come from `oidc_tenant_claim`, and the tenant
    /// must already exist — so what somebody gets a foot into is a room an
    /// administrator has already built.
    pub provision_unknown_users: Option<bool>,
    /// Which claim names the tenant a provisioned user lands in. Required
    /// for `provision_unknown_users`, and useless without it.
    pub tenant_claim: Option<String>,
}

pub(super) const DEFAULT_CHAIN: [&str; 3] = ["mtls", "oidc", "bearer"];

/// Which tier is assembling a chain.
///
/// One difference and only one: the cloud keeps the user directory and the
/// cluster does not. Everything that needs to know a caller's ROLE needs the
/// directory, so an authenticator that establishes only a name is usable at
/// one tier and not at the other.
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

/// Assemble the authenticator chain the config asks for.
///
/// A link that has nothing to work with is left out rather than added and
/// left useless — but only when the chain was defaulted. A chain that NAMES
/// an authenticator it cannot build is an operator who thinks a door is shut
/// that is not, and that is an error, loudly.
///
/// `serves_sessions` is whether this process also listens on its gRPC session
/// port, and it decides the one refusal below that is not about the REST edge
/// at all — see `mtls_or_no_peers`.
pub fn build_chain(
    cfg: &AuthConfig,
    client_ca: Option<&std::path::Path>,
    base: Option<&std::path::Path>,
    tier: Tier,
    serves_sessions: bool,
) -> Result<AuthChain> {
    let explicit = cfg.chain.is_some();
    let names: Vec<String> = cfg
        .chain
        .clone()
        .unwrap_or_else(|| DEFAULT_CHAIN.iter().map(|s| s.to_string()).collect());

    // Both bearer links read the same header, and the chain stops at the
    // first hard no: a static-token link in front of the oidc link refuses
    // every JWT before the oidc link ever sees one, so the oidc link is not
    // merely deprioritised, it is unreachable. An operator who has written
    // that has configured a door they believe is open and is not, which is
    // the same mistake this function already refuses in the other direction.
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

    let mut links: Vec<Box<dyn crate::auth::Authenticator>> = Vec::new();
    // What went in, in order, for the discovery document. Collected here
    // rather than read back off the config, because the config NAMES links
    // that are then left out for want of a CA or a token file, and what a
    // client needs to know is which ones are actually standing.
    let mut built: Vec<&'static str> = Vec::new();
    for name in &names {
        match name.as_str() {
            "oidc" => match &cfg.oidc {
                Some(oidc) if tier == Tier::Cloud => {
                    links.push(Box::new(build_oidc(oidc, base)?));
                    built.push("oidc");
                }
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
            "mtls" => match client_ca {
                Some(ca) => {
                    let ca = pki::pem::resolve(base, ca);
                    links.push(Box::new(crate::auth::MtlsAuthenticator::from_pem_file(
                        &ca,
                    )?));
                    built.push("mtls");
                    info!(ca = %ca.display(), "mtls authenticator");
                }
                None if explicit => {
                    anyhow::bail!("auth.chain names \"mtls\" but no client_ca is configured")
                }
                None => {}
            },
            "bearer" => match &cfg.bearer_token_file {
                Some(path) => {
                    let path = pki::pem::resolve(base, path);
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
                    built.push("bearer");
                }
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
    // config, and this one is about the whole shape of it.
    mtls_or_no_peers(&names, explicit, serves_sessions)?;
    Ok(AuthChain::named(links, built))
}

/// A chain without `mtls` locks the control plane out of itself.
///
/// The chain is per CONTROLLER and not per port: the same links guard the
/// REST edge and the gRPC session edge. And nothing dials a session port with
/// a bearer token — a cluster shows `system:cluster:<name>`, a node shows
/// `system:node:<name>`, both by certificate and only by certificate. So
/// `chain = ["bearer"]` — the obvious lab configuration, and the one two
/// separate briefs handed a client author — leaves the cloud with no
/// clusters and the cluster with no nodes, silently: the sessions fail with
/// "no credentials were presented" in a log nobody reads, and every VM stays
/// Pending for ever.
///
/// A startup error and not a warning, because there is nothing to degrade to.
/// The exception is a process that listens on no session port at all: it has
/// no peers to admit, so nothing is being locked out, and a WARN is the
/// honest weight of "you have made a REST-only endpoint".
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

/// One `OidcAuthenticator`, plus the background task that keeps its keys
/// current.
///
/// The task is spawned here rather than handed back for a caller to spawn,
/// because there is nothing a caller could usefully decide about it: it
/// lives exactly as long as the authenticator it feeds, and stops on its own
/// when the last one is dropped.
///
/// Nothing is fetched before this returns, and that is deliberate. A
/// controller that refused to start because the identity provider was down
/// would be a controller that cannot be restarted during somebody else's
/// outage. Until the first fetch lands, tokens are refused with a sentence
/// saying so, and certificates and the static token still work.
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
