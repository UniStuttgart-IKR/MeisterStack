// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! The REST edge both controllers share: how a request gets served, and who
//! it is by the time a handler sees it.
//!
//! Two things live here because they are two halves of one thing. TLS
//! termination is where a peer certificate becomes available, and the
//! authenticator chain is the only reason anybody wants one — `axum::serve`
//! cannot hand a handler the certificate of the connection it arrived on, so
//! the mTLS path drives hyper by hand and puts the chain on the request as an
//! extension. The policy itself is `auth`, deliberately kept clear of axum:
//! what a member may do should be decidable without a web framework.
//!
//! Plain HTTP is the default and stays the default. No TLS config means
//! `axum::serve` exactly as before, no chain means every request is anonymous
//! and may do anything, and the two are independent — a lab can have TLS
//! without auth or (with a bearer token) auth without TLS.

use std::sync::Arc;

use anyhow::{Context, Result};
use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::{Json, Router};
use macros::generated;
use rustls::ServerConfig;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tower::ServiceExt;
use tracing::{debug, info, warn};

use crate::auth::{AuthChain, AuthRequest, Authenticated, Identity, Role, classify, permits};
use crate::object::{Object, Resource};
use crate::resources::{API_VERSION, User};
use crate::store::{EtcdStore, StoreError};

/// The peer's certificate chain, leaf first, DER.
///
/// Put on the request by the accept loop below and read by the authenticator
/// chain. Absent means plain HTTP, or TLS where the peer sent no certificate
/// — to an authenticator those are the same thing, and the difference is not
/// worth a second variant.
#[derive(Clone, Debug, Default)]
pub struct PeerCerts(pub Vec<Vec<u8>>);

/// Serve the API on `listener`, terminating TLS if there is a config for it.
///
/// The plain path is the same `axum::serve` call this has always been. The
/// TLS path is a hand-rolled accept loop for one reason only: it is the only
/// way to get the peer's certificate onto the request.
#[generated(model = ClaudeOpus, version = "5")]
pub async fn serve(
    listener: TcpListener,
    router: Router,
    tls: Option<Arc<ServerConfig>>,
) -> Result<()> {
    let Some(config) = tls else {
        return axum::serve(listener, router)
            .await
            .context("serving the rest api");
    };

    let acceptor = TlsAcceptor::from(config);
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(accepted) => accepted,
            // One refused connection is not a reason to stop listening.
            Err(e) => {
                warn!(error = format!("{e:#}"), "accept failed");
                continue;
            }
        };
        // Measured, not assumed: without this a plain-http request on
        // loopback answers in 0.4ms and a TLS one in 43ms. The handshake
        // itself costs under 3ms — the other 40 are one delayed ACK, because
        // Nagle holds the small record that completes the exchange until the
        // peer acknowledges the previous one. axum::serve leaves this to the
        // caller (its `tap_io`), and this loop IS the caller.
        if let Err(e) = stream.set_nodelay(true) {
            debug!(%peer, error = format!("{e:#}"), "could not set TCP_NODELAY");
        }
        let acceptor = acceptor.clone();
        let router = router.clone();
        tokio::spawn(async move {
            let stream = match acceptor.accept(stream).await {
                Ok(s) => s,
                // Debug, not warn: a handshake that fails is usually a client
                // without the CA, and an API server that logs a warning per
                // stranger is an API server that logs.
                Err(e) => {
                    debug!(%peer, error = format!("{e:#}"), "tls handshake failed");
                    return;
                }
            };
            let certs = stream
                .get_ref()
                .1
                .peer_certificates()
                .map(pki::tls::der_chain)
                .unwrap_or_default();

            let service = hyper::service::service_fn(
                move |mut req: hyper::Request<hyper::body::Incoming>| {
                    let router = router.clone();
                    req.extensions_mut().insert(PeerCerts(certs.clone()));
                    async move { router.oneshot(req).await }
                },
            );
            if let Err(e) = hyper::server::conn::http1::Builder::new()
                .serve_connection(hyper_util::rt::TokioIo::new(stream), service)
                .await
            {
                debug!(%peer, error = format!("{e:#}"), "connection ended");
            }
        });
    }
}

/// What the guard needs to answer a request.
#[derive(Clone)]
pub struct AuthState {
    pub chain: Arc<AuthChain>,
    /// Where the `User` objects are, when this tier has them.
    ///
    /// The cloud passes its store and the role comes out of the directory,
    /// because the directory is the truth and a role change there has to take
    /// effect at once. The cluster passes `None` and reads the role off the
    /// certificate — it has no users of its own on purpose (one directory,
    /// one truth), and the price is that a demotion reaches it when the
    /// certificate is re-issued.
    pub directory: Option<Arc<EtcdStore>>,
}

impl AuthState {
    pub fn anonymous() -> Self {
        Self {
            chain: Arc::new(AuthChain::default()),
            directory: None,
        }
    }
}

/// Put the guard in front of a router.
pub fn guard(router: Router, state: AuthState) -> Router {
    router.layer(axum::middleware::from_fn_with_state(state, authorize))
}

fn deny(status: StatusCode, reason: &'static str, message: String) -> Response {
    (
        status,
        Json(serde_json::json!({ "error": message, "reason": reason })),
    )
        .into_response()
}

/// What a handler answers with when it cannot answer with the object: the
/// status, the K8s-style machine-readable `reason`, and the sentence a person
/// reads. Both tiers serve the same API shape, so an error from one has to
/// look like an error from the other — down to the body, which is the one
/// `deny` above already writes for the refusals the guard makes.
///
/// The fields are private on purpose: the constructors below are the whole
/// vocabulary, and a status paired with a reason nobody else uses is how two
/// endpoints start answering the same problem differently.
///
/// `Debug` so that a test — and a `?` in a log line — can see WHICH refusal
/// this is. It prints the fields; the constructors stay the only way to make
/// one.
#[derive(Debug)]
#[generated(model = ClaudeOpus, version = "5")]
pub struct ApiError {
    status: StatusCode,
    reason: &'static str,
    message: String,
}

#[generated(model = ClaudeOpus, version = "5")]
impl ApiError {
    pub fn new(status: StatusCode, reason: &'static str, message: impl Into<String>) -> Self {
        Self {
            status,
            reason,
            message: message.into(),
        }
    }
}

#[generated(model = ClaudeOpus, version = "5")]
impl From<StoreError> for ApiError {
    fn from(e: StoreError) -> Self {
        let (status, reason) = match &e {
            StoreError::NotFound(_) => (StatusCode::NOT_FOUND, "NotFound"),
            StoreError::AlreadyExists(_) => (StatusCode::CONFLICT, "AlreadyExists"),
            StoreError::Conflict(_) => (StatusCode::CONFLICT, "Conflict"),
            StoreError::Invalid(_) => (StatusCode::UNPROCESSABLE_ENTITY, "Invalid"),
            StoreError::Backend(_) => (StatusCode::INTERNAL_SERVER_ERROR, "Internal"),
            // Not 500: the store did not fail, it did not answer. A caller
            // that retries is doing the right thing, and 503 is how to say so.
            StoreError::Timeout(..) => (StatusCode::SERVICE_UNAVAILABLE, "Timeout"),
        };
        Self::new(status, reason, e.to_string())
    }
}

#[generated(model = ClaudeOpus, version = "5")]
impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        deny(self.status, self.reason, self.message)
    }
}

/// 422 — the request cannot be carried out as written.
pub fn invalid(message: impl Into<String>) -> ApiError {
    ApiError::new(StatusCode::UNPROCESSABLE_ENTITY, "Invalid", message)
}

/// 409 — somebody else owns this, or already did it.
pub fn conflict(message: impl Into<String>) -> ApiError {
    ApiError::new(StatusCode::CONFLICT, "Conflict", message)
}

/// 403 — the caller is known and may not.
pub fn forbidden(message: impl Into<String>) -> ApiError {
    ApiError::new(StatusCode::FORBIDDEN, "Forbidden", message)
}

/// The envelope a POST or PUT body has to wear, read off the type the handler
/// deserialised it into. Checked at every write edge of both tiers, because a
/// body that names another kind is a client sending the wrong document to the
/// right URL — and the fields it does not know about would be defaulted away
/// silently.
#[generated(model = ClaudeOpus, version = "5")]
pub fn check_envelope<S, St>(body: &Object<S, St>) -> std::result::Result<(), ApiError>
where
    Object<S, St>: Resource,
{
    let expected = <Object<S, St> as Resource>::KIND;
    if body.api_version != API_VERSION || body.kind != expected {
        return Err(invalid(format!(
            "expected apiVersion {API_VERSION}, kind {expected}"
        )));
    }
    Ok(())
}

/// Authenticate, then authorize, then hand the identity to the handler.
#[generated(model = ClaudeOpus, version = "5")]
async fn authorize(State(st): State<AuthState>, mut req: Request, next: Next) -> Response {
    let method = req.method().as_str().to_string();
    let path = req.uri().path().to_string();

    // Not an API object route — /healthz, /readyz. Never gated, and the
    // ordering matters: a probe presents no credential, so authenticating
    // first would answer 401 to the question "are you up", and an operator
    // cannot tell that from "you are down".
    let Some(attempt) = classify(&method, &path) else {
        return next.run(req).await;
    };

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

    if !permits(&identity, role, tenant.as_deref(), &attempt) {
        // Warn for the same reason `unauthenticated` above is one.
        warn!(%method, %path, identity = %identity, ?role, ?tenant, "forbidden");
        return deny(
            StatusCode::FORBIDDEN,
            "Forbidden",
            format!(
                "{} may not {:?} {}",
                identity.name, attempt.verb, attempt.resource
            ),
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
#[generated(model = ClaudeOpus, version = "5")]
async fn grant_of(
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
        // No directory at this tier: the certificate's claim is all there is,
        // and it carries a role but never a tenant. See `permits` — a member
        // here is read-only, exactly as in M4.5.
        return Ok((identity.claimed_role(), None));
    };
    match store.get::<User>(&identity.name).await {
        Ok(user) => {
            let tenant = Some(user.spec.tenant).filter(|t| !t.is_empty());
            Ok((Some(user.spec.role), tenant))
        }
        // A valid certificate for a name the directory does not know. Not an
        // error: it is somebody whose account was removed, and the honest
        // answer is that they may do nothing, said in words.
        Err(StoreError::NotFound(_)) => Ok((None, None)),
        // The directory is unreachable. Refusing beats guessing: this is the
        // only thing standing between a certificate and a write.
        Err(e) => Err(deny(
            StatusCode::SERVICE_UNAVAILABLE,
            "Timeout",
            format!("cannot reach the user directory: {e}"),
        )),
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
#[generated(model = ClaudeOpus, version = "5")]
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
}

const DEFAULT_CHAIN: [&str; 2] = ["mtls", "bearer"];

/// Assemble the authenticator chain the config asks for.
///
/// A link that has nothing to work with is left out rather than added and
/// left useless — but only when the chain was defaulted. A chain that NAMES
/// an authenticator it cannot build is an operator who thinks a door is shut
/// that is not, and that is an error, loudly.
#[generated(model = ClaudeOpus, version = "5")]
pub fn build_chain(
    cfg: &AuthConfig,
    client_ca: Option<&std::path::Path>,
    base: Option<&std::path::Path>,
) -> Result<AuthChain> {
    let explicit = cfg.chain.is_some();
    let names: Vec<String> = cfg
        .chain
        .clone()
        .unwrap_or_else(|| DEFAULT_CHAIN.iter().map(|s| s.to_string()).collect());

    let mut links: Vec<Box<dyn crate::auth::Authenticator>> = Vec::new();
    for name in &names {
        match name.as_str() {
            "mtls" => match client_ca {
                Some(ca) => {
                    let ca = pki::pem::resolve(base, ca);
                    links.push(Box::new(crate::auth::MtlsAuthenticator::from_pem_file(
                        &ca,
                    )?));
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
    Ok(AuthChain::new(links))
}

/// Build the server TLS config, if the operator asked for one.
///
/// `None` back means plain HTTP, which is the default and the shape the lab
/// runs in today. Half a config — a certificate without its key — is an
/// error rather than a silent downgrade to plain: that is precisely the
/// mistake that would leave an API server open while its operator believes
/// otherwise.
#[generated(model = ClaudeOpus, version = "5")]
pub fn server_tls(
    cert: Option<&std::path::Path>,
    key: Option<&std::path::Path>,
    client_ca: Option<&std::path::Path>,
    base: Option<&std::path::Path>,
) -> Result<Option<Arc<ServerConfig>>> {
    match (cert, key) {
        (None, None) => {
            if client_ca.is_some() {
                anyhow::bail!(
                    "client_ca is set but tls_cert/tls_key are not; there is no TLS session for a \
                     client certificate to arrive on"
                );
            }
            Ok(None)
        }
        (Some(cert), Some(key)) => {
            let cert = pki::pem::resolve(base, cert);
            let key = pki::pem::resolve(base, key);
            let ca = client_ca.map(|p| pki::pem::resolve(base, p));
            let config = pki::tls::server_config(&cert, &key, ca.as_deref())?;
            info!(cert = %cert.display(), mtls = ca.is_some(), "tls enabled");
            Ok(Some(config))
        }
        _ => anyhow::bail!("tls_cert and tls_key go together; set both or neither"),
    }
}

#[cfg(test)]
#[generated(model = ClaudeOpus, version = "5")]
mod tests {
    use super::*;

    fn cfg(toml: &str) -> AuthConfig {
        toml::from_str(toml).expect("the auth table parses")
    }

    /// One error vocabulary for both tiers' handlers. The row that is a
    /// decision rather than a spelling is the last one: an etcd that did not
    /// ANSWER is a 503 the caller should retry, not a 500 saying the store
    /// broke — and both endpoints have to say it the same way, because one
    /// CLI reads both.
    #[test]
    fn a_store_error_carries_the_status_both_tiers_agreed_on() {
        let cases = [
            (
                StoreError::NotFound("vms/x".into()),
                StatusCode::NOT_FOUND,
                "NotFound",
            ),
            (
                StoreError::AlreadyExists("vms/x".into()),
                StatusCode::CONFLICT,
                "AlreadyExists",
            ),
            (
                StoreError::Conflict("lost the cas".into()),
                StatusCode::CONFLICT,
                "Conflict",
            ),
            (
                StoreError::Invalid("no name".into()),
                StatusCode::UNPROCESSABLE_ENTITY,
                "Invalid",
            ),
            (
                StoreError::Timeout("get", std::time::Duration::from_secs(5)),
                StatusCode::SERVICE_UNAVAILABLE,
                "Timeout",
            ),
        ];
        for (error, status, reason) in cases {
            let said = error.to_string();
            let mapped = ApiError::from(error);
            assert_eq!((mapped.status, mapped.reason), (status, reason));
            // the store's own sentence reaches the operator, not a summary
            assert_eq!(mapped.message, said);
        }
    }

    /// A body that names another kind is the wrong document at the right URL;
    /// the fields it does not know about would otherwise be defaulted away in
    /// silence.
    #[test]
    fn an_envelope_naming_another_kind_is_refused() {
        use crate::resources::{Counter, CounterSpec};
        let mut counter = Counter::declare("vni", CounterSpec { next: 1 });
        assert!(check_envelope(&counter).is_ok());

        counter.kind = "Vm".into();
        assert!(
            check_envelope(&counter).is_err(),
            "a body that names another kind is the wrong document at this URL"
        );
        counter.kind = Counter::KIND.into();
        counter.api_version = "meister.io/v2".into();
        assert!(check_envelope(&counter).is_err());
    }

    /// The default: an `[auth]` table that configures nothing builds nothing,
    /// and nothing is the anonymous mode.
    #[test]
    fn an_auth_table_with_nothing_in_it_is_still_anonymous() {
        let chain = build_chain(&cfg(""), None, None).unwrap();
        assert!(chain.is_empty());
        assert_eq!(
            chain.authenticate(&AuthRequest::default()).unwrap(),
            Authenticated::Anonymous
        );
    }

    /// A chain that names a door it cannot shut is an operator who believes
    /// the door is shut. Loud, not silent.
    #[test]
    fn naming_an_authenticator_that_cannot_be_built_is_an_error() {
        let err = build_chain(&cfg(r#"chain = ["mtls"]"#), None, None).unwrap_err();
        assert!(err.to_string().contains("client_ca"), "{err}");
        let err = build_chain(&cfg(r#"chain = ["bearer"]"#), None, None).unwrap_err();
        assert!(err.to_string().contains("bearer_token_file"), "{err}");
        let err = build_chain(&cfg(r#"chain = ["magic"]"#), None, None).unwrap_err();
        assert!(err.to_string().contains("magic"), "{err}");
    }

    /// The check that keeps certificatesigningrequests from being a way up.
    /// Without it, `csr_auto_approve` plus any member's certificate is a path
    /// to the administrator's.
    #[test]
    fn a_member_may_ask_for_its_own_certificate_and_nobody_elses() {
        let alice = Caller(Some(Identity::new(
            "alice",
            vec![crate::auth::GROUP_MEMBERS.into()],
        )));
        assert!(alice.may_act_for(Some(Role::Member), "alice"));
        assert!(!alice.may_act_for(Some(Role::Member), "root"));

        let admin = Caller(Some(Identity::new(
            "ops",
            vec![crate::auth::GROUP_ADMINS.into()],
        )));
        assert!(admin.may_act_for(Some(Role::Admin), "alice"));

        let node = Caller(Some(Identity::new("system:node:manacor", vec![])));
        assert!(node.may_act_for(None, "alice"));

        // Anonymous mode says yes to everything, here as everywhere else.
        assert!(Caller::default().may_act_for(None, "root"));
        assert_eq!(Caller::default().name(), "anonymous");
    }

    /// A demoted admin still carries `O=meister:admins` until the
    /// certificate is re-issued. What decides is the directory, or the
    /// demotion would not take effect where it matters most — with
    /// `csr_auto_approve`, requesting somebody else's certificate IS
    /// becoming them.
    #[test]
    fn a_demoted_admin_stops_being_able_to_ask_for_other_peoples_certificates() {
        let demoted = Caller(Some(Identity::new(
            "ops",
            vec![crate::auth::GROUP_ADMINS.into()],
        )));
        assert!(
            demoted.may_act_for(Some(Role::Admin), "alice"),
            "while still an admin"
        );
        assert!(
            !demoted.may_act_for(Some(Role::Member), "alice"),
            "the certificate still says admin; the directory does not"
        );
        assert!(
            demoted.may_act_for(Some(Role::Member), "ops"),
            "still itself"
        );
    }

    /// Half a TLS config is the mistake worth catching: an API server that
    /// silently stayed plain while its operator believed it was not.
    #[test]
    fn half_a_tls_config_is_refused_rather_than_downgraded() {
        assert!(server_tls(None, None, None, None).unwrap().is_none());
        let some = std::path::Path::new("x.pem");
        assert!(server_tls(Some(some), None, None, None).is_err());
        assert!(server_tls(None, Some(some), None, None).is_err());
        // and a client CA with no TLS session to arrive on
        assert!(server_tls(None, None, Some(some), None).is_err());
    }
}
