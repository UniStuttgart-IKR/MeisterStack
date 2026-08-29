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
use std::time::Duration;

use anyhow::{Context, Result};
use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::{Json, Router};
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
    /// Create a `User` for an identity out of a token that the directory
    /// does not know yet. `auth.oidc.provision_unknown_users`, off by
    /// default. See `provision`.
    pub provision_oidc_users: bool,
}

impl AuthState {
    pub fn anonymous() -> Self {
        Self {
            chain: Arc::new(AuthChain::default()),
            directory: None,
            provision_oidc_users: false,
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
pub struct ApiError {
    status: StatusCode,
    reason: &'static str,
    message: String,
}

impl ApiError {
    pub fn new(status: StatusCode, reason: &'static str, message: impl Into<String>) -> Self {
        Self {
            status,
            reason,
            message: message.into(),
        }
    }
}

impl From<StoreError> for ApiError {
    fn from(e: StoreError) -> Self {
        let (status, reason) = match &e {
            StoreError::NotFound(_) => (StatusCode::NOT_FOUND, "NotFound"),
            StoreError::AlreadyExists(_) => (StatusCode::CONFLICT, "AlreadyExists"),
            StoreError::Terminating(_) => (StatusCode::CONFLICT, "Terminating"),
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

// --- the spec-only PUT ------------------------------------------------------

/// A PUT body for a resource whose STATUS belongs to a controller.
///
/// Deliberately not the resource's own `Object` type. What separates a client
/// that round-trips an object it just read from one that is trying to write
/// status is whether it SAID anything about status, and a typed `St` cannot
/// tell "absent" from "the default" — every field of a NodeStatus defaults,
/// so an omitted status deserialises into a perfectly good "not ready, no
/// capacity, no heartbeat" that would then be a write of exactly that.
#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SpecUpdate<S> {
    pub api_version: String,
    pub kind: String,
    pub metadata: crate::object::Metadata,
    pub spec: S,
    /// What the client said about status, if it said anything. `None` is
    /// "did not mention it", which is the only shape that is not a write.
    #[serde(default)]
    pub status: Option<serde_json::Value>,
}

/// Apply a spec-only PUT onto the object as it is stored.
///
/// The one write path for the fields an operator owns on a controller-owned
/// object: `spec.schedulable` on a Node, the same on a Cluster. Everything
/// else about the object is server-owned and survives the round trip
/// untouched — uid, creation, deletion, finalizers, and status.
///
/// Status is REFUSED rather than silently kept, which is the one place this
/// differs from `update_vm`. The difference is who is being talked to: a VM
/// spec is a document a client authored and re-sends whole, so quietly
/// keeping the server's half is the only way a client can round-trip one at
/// all. A Node object is authored by the controller from what an agent
/// reported, and the only reason to PUT one is to flip a field of `spec` — so
/// a body that also carries a different status is a client that believes it
/// can set `ready` or `capacity`, and telling it no is worth more than
/// accepting the write and discarding half of it. A body that repeats the
/// status it just read is not that, and passes.
///
/// The resourceVersion is the CLIENT's, exactly as in `update_vm`: it is what
/// makes the store's compare-and-swap a compare-and-swap. A body without one
/// is refused by the store with the same message every other update gets.
pub fn apply_spec_update<S, St>(
    body: SpecUpdate<S>,
    name: &str,
    current: Object<S, St>,
) -> std::result::Result<Object<S, St>, ApiError>
where
    Object<S, St>: Resource,
    St: serde::Serialize,
{
    let expected = <Object<S, St> as Resource>::KIND;
    if body.api_version != API_VERSION || body.kind != expected {
        return Err(invalid(format!(
            "expected apiVersion {API_VERSION}, kind {expected}"
        )));
    }
    if body.metadata.name != name {
        return Err(invalid("metadata.name does not match the path"));
    }
    if let Some(sent) = &body.status {
        let held = serde_json::to_value(&current.status).map_err(|e| {
            ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "Internal", e.to_string())
        })?;
        if sent != &held {
            return Err(invalid(format!(
                "status belongs to the controller; send this {expected} back with the status it \
                 was read with, or leave status out"
            )));
        }
    }
    let mut next = current;
    next.spec = body.spec;
    // The client's half of metadata, and only that half.
    next.metadata.labels = body.metadata.labels;
    next.metadata.annotations = body.metadata.annotations;
    // What makes the write a compare-and-swap rather than a last-writer-wins.
    next.metadata.resource_version = body.metadata.resource_version;
    Ok(next)
}

/// Authenticate, then authorize, then hand the identity to the handler.
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
async fn provision(st: &AuthState, identity: &Identity) -> anyhow::Result<Option<User>> {
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

const DEFAULT_CHAIN: [&str; 3] = ["mtls", "oidc", "bearer"];

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

/// Assemble the authenticator chain the config asks for.
///
/// A link that has nothing to work with is left out rather than added and
/// left useless — but only when the chain was defaulted. A chain that NAMES
/// an authenticator it cannot build is an operator who thinks a door is shut
/// that is not, and that is an error, loudly.
pub fn build_chain(
    cfg: &AuthConfig,
    client_ca: Option<&std::path::Path>,
    base: Option<&std::path::Path>,
    tier: Tier,
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
    for name in &names {
        match name.as_str() {
            "oidc" => match &cfg.oidc {
                Some(oidc) if tier == Tier::Cloud => {
                    links.push(Box::new(build_oidc(oidc, base)?));
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
fn build_oidc(
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

/// Build the server TLS config, if the operator asked for one.
///
/// `None` back means plain HTTP, which is the default and the shape the lab
/// runs in today. Half a config — a certificate without its key — is an
/// error rather than a silent downgrade to plain: that is precisely the
/// mistake that would leave an API server open while its operator believes
/// otherwise.
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
        let chain = build_chain(&cfg(""), None, None, Tier::Cloud).unwrap();
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
        let err = build_chain(&cfg(r#"chain = ["mtls"]"#), None, None, Tier::Cloud).unwrap_err();
        assert!(err.to_string().contains("client_ca"), "{err}");
        let err = build_chain(&cfg(r#"chain = ["bearer"]"#), None, None, Tier::Cloud).unwrap_err();
        assert!(err.to_string().contains("bearer_token_file"), "{err}");
        let err = build_chain(&cfg(r#"chain = ["magic"]"#), None, None, Tier::Cloud).unwrap_err();
        assert!(err.to_string().contains("magic"), "{err}");
        let err = build_chain(&cfg(r#"chain = ["oidc"]"#), None, None, Tier::Cloud).unwrap_err();
        assert!(err.to_string().contains("auth.oidc"), "{err}");
    }

    fn oidc_cfg(extra: &str) -> AuthConfig {
        oidc_chain(r#"["oidc"]"#, extra)
    }

    fn oidc_chain(chain: &str, extra: &str) -> AuthConfig {
        cfg(&format!(
            "chain = {chain}\n[oidc]\nissuer = \"https://idp.example.org\"\n\
             client_id = \"meisterstack\"\n{extra}"
        ))
    }

    /// The tier split, which is not a policy choice but an arithmetic one:
    /// authorization needs a role, a role needs the directory, and the
    /// cluster has no directory. A token there would authenticate somebody
    /// the tier could then permit nothing, which is worse than refusing the
    /// configuration.
    #[tokio::test]
    async fn the_cluster_tier_refuses_an_oidc_link_because_it_has_no_directory() {
        let err = build_chain(&oidc_cfg(""), None, None, Tier::Cluster).unwrap_err();
        assert!(err.to_string().contains("user directory"), "{err}");
        // And the same table at the cloud is simply a chain of one.
        let chain = build_chain(&oidc_cfg(""), None, None, Tier::Cloud).unwrap();
        assert_eq!(chain.len(), 1);
    }

    /// Both bearer links read the same header and the chain stops at the
    /// first hard no, so a static-token link in front of the oidc link does
    /// not deprioritise it — it makes it unreachable. The default order has
    /// oidc first for exactly this reason.
    #[tokio::test]
    async fn a_static_token_link_in_front_of_the_oidc_link_is_refused() {
        let err = build_chain(
            &oidc_chain(r#"["mtls", "bearer", "oidc"]"#, ""),
            None,
            None,
            Tier::Cloud,
        )
        .unwrap_err();
        assert!(err.to_string().contains("would ever reach"), "{err}");
        assert_eq!(DEFAULT_CHAIN, ["mtls", "oidc", "bearer"]);
    }

    /// The pin is a list of algorithms WE accept, so a name that is not one
    /// has to be an error at start-up rather than a token refused later.
    #[tokio::test]
    async fn only_asymmetric_algorithms_may_be_configured() {
        let err = build_chain(
            &oidc_cfg("allowed_algorithms = [\"HS256\"]"),
            None,
            None,
            Tier::Cloud,
        )
        .unwrap_err();
        assert!(format!("{err:#}").contains("asymmetric"), "{err:#}");

        assert!(
            build_chain(
                &oidc_cfg("allowed_algorithms = [\"RS256\", \"ES384\"]"),
                None,
                None,
                Tier::Cloud
            )
            .is_ok()
        );
    }

    /// A token with no audience check is a token issued for some other
    /// service that this one accepts. Refused as a configuration.
    #[tokio::test]
    async fn an_empty_audience_is_a_configuration_error_and_not_a_permissive_setting() {
        let err = build_chain(&oidc_cfg("audience = []"), None, None, Tier::Cloud).unwrap_err();
        assert!(err.to_string().contains("any service"), "{err}");
    }

    /// Provisioning without a tenant claim has nothing to put in the object
    /// it would create, and a default tenant would be one room everybody the
    /// provider knows shares.
    #[tokio::test]
    async fn first_login_provisioning_refuses_to_guess_a_tenant() {
        let err = build_chain(
            &oidc_cfg("provision_unknown_users = true"),
            None,
            None,
            Tier::Cloud,
        )
        .unwrap_err();
        assert!(err.to_string().contains("tenant_claim"), "{err}");

        assert!(
            build_chain(
                &oidc_cfg("provision_unknown_users = true\ntenant_claim = \"groups\""),
                None,
                None,
                Tier::Cloud
            )
            .is_ok()
        );
    }

    /// The default has to do nothing, and "nothing" here has three
    /// independent reasons — so all three are asserted rather than one
    /// standing in for the others. Each of them returns before the store is
    /// ever reached, which is why this can be tested without an etcd.
    #[tokio::test]
    async fn first_login_provisioning_does_nothing_unless_everything_asks_for_it() {
        let oidc_user = Identity::new(
            "alice",
            vec![
                crate::oidc::GROUP_OIDC.to_string(),
                format!("{}acme", crate::oidc::GROUP_OIDC_TENANT_PREFIX),
            ],
        );

        // The switch, off. This is the shipped default and the one that
        // matters most.
        let st = AuthState::anonymous();
        assert!(provision(&st, &oidc_user).await.unwrap().is_none());

        // The switch on, but the identity did not come out of a token. A
        // certificate for a name the directory does not know stays nobody:
        // that path has its own bootstrap and does not need a second one.
        let st = AuthState {
            provision_oidc_users: true,
            ..AuthState::anonymous()
        };
        let from_a_certificate = Identity::new("alice", vec![crate::auth::GROUP_MEMBERS.into()]);
        assert!(provision(&st, &from_a_certificate).await.unwrap().is_none());

        // The switch on and a token, but no directory to write into. The
        // cluster tier, which `build_chain` refuses an oidc link at anyway.
        assert!(provision(&st, &oidc_user).await.unwrap().is_none());
    }

    /// The tenant a token claimed, and the fact that it is a group nothing
    /// else reads. `Role::from_groups` looks only at the two role groups, so
    /// neither marker can become a permission by accident.
    #[test]
    fn the_markers_an_oidc_identity_carries_decide_nothing() {
        let id = Identity::new(
            "alice",
            vec![
                crate::oidc::GROUP_OIDC.to_string(),
                format!("{}acme", crate::oidc::GROUP_OIDC_TENANT_PREFIX),
            ],
        );
        assert_eq!(crate::oidc::claimed_tenant(&id), Some("acme"));
        assert_eq!(id.claimed_role(), None);
        assert!(!id.is_system());
        assert!(!permits(
            &id,
            None,
            None,
            &crate::auth::Attempt {
                resource: "vms",
                subresource: None,
                verb: crate::auth::Verb::Read
            }
        ));
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

    /// The spec-only PUT, as the two draining routes use it: spec is taken,
    /// server-owned metadata survives, the client's resourceVersion is what
    /// the store will compare against, and a status that differs from the one
    /// held is refused rather than dropped on the floor.
    #[test]
    fn a_spec_only_put_takes_the_spec_and_refuses_a_written_status() {
        use crate::resources::{Node, NodeSpec, NodeStatus};

        let mut current = Node::declare(
            "manacor",
            NodeSpec {
                schedulable: true,
                ..NodeSpec::default()
            },
        );
        current.metadata.uid = "the-uid".into();
        current.metadata.resource_version = "41".into();
        current.metadata.finalizers.push("keep-me".into());
        current.status = NodeStatus {
            ready: true,
            vms: 3,
            ..NodeStatus::default()
        };

        let put = |status: Option<serde_json::Value>, version: &str| SpecUpdate {
            api_version: API_VERSION.into(),
            kind: "Node".into(),
            metadata: crate::object::Metadata {
                name: "manacor".into(),
                resource_version: version.into(),
                // A client that sends back what it read sends uid and
                // creation too; both are the server's and are ignored.
                uid: "somebody-elses-uid".into(),
                ..Default::default()
            },
            spec: NodeSpec {
                schedulable: false,
                ..NodeSpec::default()
            },
            status,
        };

        // Status left out: the drain lands, everything server-owned survives,
        // and the version that goes to the store is the CLIENT's.
        let next =
            apply_spec_update(put(None, "42"), "manacor", current.clone()).expect("accepted");
        assert!(!next.spec.schedulable);
        assert_eq!(next.metadata.uid, "the-uid");
        assert_eq!(next.metadata.finalizers, vec!["keep-me".to_string()]);
        assert_eq!(next.metadata.resource_version, "42");
        assert!(next.status.ready, "status is untouched");
        assert_eq!(next.status.vms, 3);

        // Status echoed back unchanged: a round trip, not a write.
        let echoed = serde_json::to_value(&current.status).unwrap();
        assert!(apply_spec_update(put(Some(echoed), "41"), "manacor", current.clone()).is_ok());

        // Status changed: refused, and the sentence says whose it is.
        let forged = serde_json::json!({"ready": true, "vms": 999});
        let err = apply_spec_update(put(Some(forged), "41"), "manacor", current.clone())
            .expect_err("a written status is not silently dropped");
        assert_eq!(err.status, StatusCode::UNPROCESSABLE_ENTITY);
        assert!(err.message.contains("belongs to the controller"), "{err:?}");

        // And the envelope is checked here as it is at every other write edge.
        let mut wrong = put(None, "41");
        wrong.kind = "Vm".into();
        assert!(apply_spec_update(wrong, "manacor", current.clone()).is_err());
        let mut renamed = put(None, "41");
        renamed.metadata.name = "elsewhere".into();
        assert!(apply_spec_update(renamed, "manacor", current).is_err());
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
