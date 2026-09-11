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
use axum::Router;
use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use rustls::ServerConfig;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tower::ServiceExt;
use tracing::{debug, info, warn};

use crate::auth::{AuthChain, AuthRequest, Authenticated, Identity, Role, classify, permits};
use crate::object::{ANNOTATION_DRY_RUN, Object, Resource};
use crate::resources::{API_VERSION, User};
use crate::store::{EtcdStore, StoreError};

mod discovery;
mod guard;
mod mutability;
mod patch;
mod schemas;
mod status;

pub use discovery::*;
pub use guard::*;
pub use mutability::*;
pub use patch::*;
pub use schemas::*;
pub use status::*;

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

/// The one place a refusal is written down. Every 4xx and 5xx this API gives
/// comes through here, the guard's included.
fn deny(
    status: StatusCode,
    reason: &'static str,
    message: String,
    field: Option<&str>,
) -> Response {
    let mut body = serde_json::json!({
        "apiVersion": API_VERSION,
        "kind": KIND_STATUS,
        "status": "Failure",
        "code": status.as_u16(),
        "reason": reason,
        "message": message,
    });
    // `details` carries exactly one thing today and is left out when it has
    // nothing: an empty object in every error body would be a field a client
    // learns to ignore. It is K8s' extension point and it is not being
    // filled in ahead of a use.
    if let Some(field) = field {
        body["details"] = serde_json::json!({ "field": field });
    }
    (status, axum::Json(body)).into_response()
}

/// `axum::Json`, with this API's refusal instead of axum's plain text.
///
/// A drop-in: it extracts and it renders, so a handler writes `Json` and
/// means both, exactly as before. The only difference is the third of the
/// three refusals above — a body that does not parse, or that parses into
/// something this route does not read.
///
/// 400 `BadRequest` for both, deliberately, where axum splits them into 400
/// and 422. 422 in THIS API means "the request is well-formed and cannot be
/// carried out" — the mutability table, a quota, a name rule — and it is
/// answered by a handler that read the object. A body that never became an
/// object was not understood at all, and giving it the same word as a quota
/// refusal would put two very different things under one code.
///
/// The serde sentence travels as-is. It names the field and the offset, which
/// is the one piece of information the client cannot work out for itself.
pub struct Json<T>(pub T);

impl<T, S> axum::extract::FromRequest<S> for Json<T>
where
    T: serde::de::DeserializeOwned,
    S: Send + Sync,
{
    type Rejection = ApiError;

    async fn from_request(req: Request, state: &S) -> std::result::Result<Self, Self::Rejection> {
        match axum::Json::<T>::from_request(req, state).await {
            Ok(axum::Json(value)) => Ok(Self(value)),
            Err(rejection) => Err(ApiError::new(
                StatusCode::BAD_REQUEST,
                "BadRequest",
                rejection.body_text(),
            )),
        }
    }
}

impl<T: serde::Serialize> IntoResponse for Json<T> {
    fn into_response(self) -> Response {
        axum::Json(self.0).into_response()
    }
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
    /// The path this refusal is about, where it is about one — `details.field`
    /// in the body. Set by `invalid_field` and by nothing else: a client that
    /// wants to point at the input that was wrong needs the path in a form it
    /// did not have to parse out of a sentence.
    field: Option<String>,
}

impl ApiError {
    pub fn new(status: StatusCode, reason: &'static str, message: impl Into<String>) -> Self {
        Self {
            field: None,
            status,
            reason,
            message: message.into(),
        }
    }

    /// The sentence a person reads, for the one caller that is not an HTTP
    /// handler: the cluster's session, which has to put this refusal into a
    /// `CommandResult` so that it comes out of the cloud's REST edge as the
    /// cluster's own words rather than as "the command failed".
    pub fn message(&self) -> &str {
        &self.message
    }

    pub fn status(&self) -> StatusCode {
        self.status
    }

    /// The path this refusal is about, where it is about one. `details.field`
    /// as a caller inside the process sees it — `vm_spec`'s tests, which have
    /// to say that a serde sentence arrived with an address and not only with
    /// prose.
    pub fn field(&self) -> Option<&str> {
        self.field.as_deref()
    }

    /// The machine-readable half. One caller: `patch_with_retry`, which has
    /// to tell a compare-and-swap that lost from the three other refusals
    /// that also answer 409 and would all be retried forever.
    pub fn reason(&self) -> &'static str {
        self.reason
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
        deny(
            self.status,
            self.reason,
            self.message,
            self.field.as_deref(),
        )
    }
}

/// 422 — the request cannot be carried out as written.
pub fn invalid(message: impl Into<String>) -> ApiError {
    ApiError::new(StatusCode::UNPROCESSABLE_ENTITY, "Invalid", message)
}

/// The same, about one named field: the sentence for a person and the path
/// for a program. `check_owned` is the caller that made this worth having.
pub fn invalid_field(field: &str, message: impl Into<String>) -> ApiError {
    ApiError {
        field: Some(field.to_string()),
        ..invalid(message)
    }
}

/// 409 — somebody else owns this, or already did it.
pub fn conflict(message: impl Into<String>) -> ApiError {
    ApiError::new(StatusCode::CONFLICT, "Conflict", message)
}

/// 403 — the caller is known and may not.
pub fn forbidden(message: impl Into<String>) -> ApiError {
    ApiError::new(StatusCode::FORBIDDEN, "Forbidden", message)
}

// --- the preview ------------------------------------------------------------

/// `?dryRun=All` — run the whole request except the write, and answer with the
/// object as it WOULD have been stored.
///
/// Kubernetes' spelling and Kubernetes' single accepted value, deliberately:
/// a client that knows one control plane should not have to learn a second
/// word for the same idea, and "All" is a list of stages that has exactly one
/// member in both systems.
///
/// What it is FOR is the UI. A model's suggestion is shown as the object it
/// would produce before anybody agrees to it, and that is only worth
/// something if the preview went through the same validation, the same
/// mutability table, the same quota arithmetic and the same name rule as the
/// real thing. So this is not a separate code path: the handler runs to the
/// last line and stops there.
///
/// What it deliberately does NOT do: no event, no dispatch, no reconciler
/// wake-up. Nothing downstream of a dry run happens, because nothing was
/// written for anything downstream to notice.
///
/// The agent's own `dry_run` (`agent vm observe`, over the node socket) is a
/// different question — "what would this node build" — and stays where it is.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DryRun(bool);

/// The one value K8s accepts, and the one this accepts.
const DRY_RUN_ALL: &str = "All";

impl DryRun {
    /// For the handful of callers that have to branch before they have an
    /// object to hand back — the scheduler preview, and the tests.
    pub fn requested(self) -> bool {
        self.0
    }

    /// The last line of a write handler: the object as it would have been
    /// written, marked, or `None` for "this is a real request, go and write
    /// it".
    ///
    /// Takes the object the handler built, borrowed exactly as the write
    /// would take it, so the call site reads as the write it replaces.
    ///
    /// Two fields the STORE would have filled in are filled in here, because
    /// a preview that differed from the real answer in a field a client reads
    /// would be a preview of a different object:
    ///
    ///   * `generation` — `create` sets it to 1 and an update carried its own
    ///     through `carry_generation`, so `max(1)` is right for both.
    ///   * `resourceVersion` is deliberately NOT invented. It is etcd's
    ///     revision; nothing happened, so there is no revision, and an empty
    ///     one is the true statement. It is also what makes a preview fed
    ///     back to `apply` behave as a create rather than as a conditional
    ///     write against a version that never existed.
    ///
    /// The mark itself is `ANNOTATION_DRY_RUN`.
    pub fn preview<S, St>(self, object: &Object<S, St>) -> Option<Object<S, St>>
    where
        S: Clone,
        St: Clone,
    {
        self.0.then(|| {
            let mut object = object.clone();
            object.metadata.generation = object.metadata.generation.max(1);
            object.metadata.resource_version = String::new();
            object
                .metadata
                .annotations
                .insert(ANNOTATION_DRY_RUN.to_string(), "true".to_string());
            object
        })
    }
}

impl<S: Send + Sync> axum::extract::FromRequestParts<S> for DryRun {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        _state: &S,
    ) -> std::result::Result<Self, Self::Rejection> {
        let Some(value) = parts.uri.query().and_then(dry_run_value) else {
            return Ok(Self(false));
        };
        if value == DRY_RUN_ALL {
            return Ok(Self(true));
        }
        // A typo is refused rather than read as "no". `?dryrun=all` that
        // silently wrote the object would be the worst answer this parameter
        // could give — the caller asked to be shown and was obeyed instead.
        Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "BadRequest",
            format!("dryRun={value:?} is not a stage; the only value is {DRY_RUN_ALL:?}"),
        ))
    }
}

/// The `dryRun` value out of a raw query string, percent-decoding nothing:
/// the only value that means anything is an ASCII word, and a value that
/// needed decoding is a value that is wrong.
///
/// Written by hand rather than through a typed `Query`, because a typed one
/// would have to be a struct per route — every list route already has its own
/// — and `serde_urlencoded` refuses a query with keys the struct does not
/// name.
fn dry_run_value(query: &str) -> Option<&str> {
    query.split('&').find_map(|pair| {
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        (key == "dryRun").then_some(value)
    })
}

// --- narrowing a listing ----------------------------------------------------

/// The two things a client may ask a list route to narrow by.
///
/// Both are FILTERS and neither is a permission: a listing hands out what the
/// caller may see and these say which part of it to render. A member asking
/// for another tenant's objects gets an empty list rather than a 403, because
/// "there is nothing here for you" is what a filter says and the refusal was
/// already made, once, by `permits_object`.
#[derive(Debug, Default, serde::Deserialize)]
pub struct ListQuery {
    /// `labelSelector=k=v,k2=v2`, matched against `metadata.labels`.
    #[serde(default, rename = "labelSelector")]
    pub label_selector: Option<String>,
    /// `tenant=acme`, matched against `spec.tenant`.
    #[serde(default)]
    pub tenant: Option<String>,
}

/// Equality selectors, comma-separated, and deliberately nothing else.
///
/// Kubernetes' set-based half (`in`, `notin`, `!k`) is not here and is not
/// missing: it is a second grammar to parse, a second thing to document and a
/// second thing to get subtly wrong, and every use this control plane has for
/// a selector — a nodeSelector, a clusterSelector, `node ls -l zone=lab` — is
/// an equality. When something needs the other half it can be added; until
/// then a selector is a thing an operator can read at a glance.
#[derive(Debug, Default)]
pub struct Selector(Vec<(String, String)>);

impl Selector {
    /// Parse what the client sent. An empty or absent selector selects
    /// everything, which is what a listing without one has always done.
    pub fn parse(raw: Option<&str>) -> std::result::Result<Self, ApiError> {
        let Some(raw) = raw.map(str::trim).filter(|r| !r.is_empty()) else {
            return Ok(Self::default());
        };
        let mut pairs = Vec::new();
        for term in raw.split(',') {
            let term = term.trim();
            if term.is_empty() {
                continue;
            }
            let Some((key, value)) = term.split_once('=') else {
                return Err(invalid(format!(
                    "{term:?} is not a selector; write it as key=value, comma-separated"
                )));
            };
            let key = key.trim();
            if key.is_empty() {
                return Err(invalid(format!("{term:?} has an empty key")));
            }
            pairs.push((key.to_string(), value.trim().to_string()));
        }
        Ok(Self(pairs))
    }

    /// Every pair must be present with that value. An empty selector selects
    /// everything; a selector with a key nothing carries selects nothing.
    pub fn selects(&self, labels: &std::collections::BTreeMap<String, String>) -> bool {
        self.0
            .iter()
            .all(|(k, v)| labels.get(k).is_some_and(|have| have == v))
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

// --- cors -------------------------------------------------------------------

/// The REST edge's own configuration table (`[api]`).
///
/// One key today. Its own table rather than two more top-level keys because
/// what belongs to the HTTP edge and what belongs to the control plane are
/// different things to reason about, and `[auth]` set the shape.
#[derive(Clone, Debug, Default, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApiConfig {
    /// Origins a browser may be shown this API from. Empty (the default) =
    /// no CORS headers at all, and a browser gets nothing.
    #[serde(default)]
    pub cors_origins: Vec<String>,
}

/// What a request's `Origin` is allowed to be answered with, if anything.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Allow {
    /// The configured `*`. Answered as `*`, and deliberately without
    /// `Allow-Credentials` — the standard forbids the pair, and a browser
    /// that saw both would drop the response, so sending them would be a
    /// wildcard that silently works for nothing.
    Any,
    /// The caller's exact origin, echoed. Never the configured LIST: a
    /// browser matches one value against its own origin, and a list is a
    /// header it rejects.
    Exact(String),
}

/// Decide, from the configured list and the request's `Origin`.
///
/// Exact string equality and nothing else. Origins are already a normalised
/// form — scheme, host, optional port — and a matcher with wildcards or
/// suffix rules is how `https://ui.lab.example.attacker.com` gets let in.
fn allow_origin(configured: &[String], origin: Option<&str>) -> Option<Allow> {
    let origin = origin?;
    if configured.iter().any(|o| o == "*") {
        return Some(Allow::Any);
    }
    configured
        .iter()
        .any(|o| o == origin)
        .then(|| Allow::Exact(origin.to_string()))
}

impl Allow {
    fn header(&self) -> &str {
        match self {
            Allow::Any => "*",
            Allow::Exact(origin) => origin,
        }
    }
}

/// The methods this API answers on an object route. Written out rather than
/// read off the router: a preflight is a promise about what a browser may
/// send next, and it should say what this API serves and not what one path
/// happens to have registered.
const CORS_METHODS: &str = "GET, POST, PUT, PATCH, DELETE";

/// What a browser is allowed to send. `Content-Type` is on the list because
/// `application/merge-patch+json` is not one of the three values a browser
/// sends without asking — which is exactly why a PATCH triggers a preflight
/// at all.
const CORS_HEADERS: &str = "Authorization, Content-Type";

/// How long a browser may remember a preflight, in seconds.
const CORS_MAX_AGE: &str = "600";

/// Put the CORS layer in front of a router — and in front of its GUARD.
///
/// The ordering is the whole of why this is written by hand rather than
/// layered on afterwards: a preflight carries no `Authorization` header by
/// definition, so anything that authenticates before it is answered turns
/// every browser request into a 401 that the browser reports as a CORS
/// failure. So this goes outermost, and the caller wraps `guard`'s result.
///
/// An empty list is the default and means no CORS headers anywhere,
/// preflights included: a browser then gets nothing, which is what an API
/// with no web interface in front of it should give it. An origin that is not
/// on the list is answered exactly as one that sent no `Origin` at all — the
/// browser blocks the answer, and the server has not lied about who may read
/// it.
pub fn cors(router: Router, origins: Vec<String>) -> Router {
    router.layer(axum::middleware::from_fn_with_state(
        Arc::new(origins),
        cors_layer,
    ))
}

async fn cors_layer(
    State(configured): State<Arc<Vec<String>>>,
    req: Request,
    next: Next,
) -> Response {
    // The API and nothing else. `/healthz` and `/readyz` are a load
    // balancer's and a probe's, not a page's — and leaving them entirely
    // untouched is what keeps "is this replica up" an answer with no
    // negotiation in it.
    if !req.uri().path().starts_with("/apis/") {
        return next.run(req).await;
    }
    let origin = req
        .headers()
        .get(axum::http::header::ORIGIN)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let allow = allow_origin(&configured, origin.as_deref());

    // The preflight, answered here and never passed on — only for an origin
    // that is allowed. Anything else falls through and is whatever this
    // router already answered an OPTIONS with, which is a 405.
    if req.method() == axum::http::Method::OPTIONS
        && let Some(allow) = &allow
    {
        return (
            StatusCode::NO_CONTENT,
            [
                ("access-control-allow-origin", allow.header()),
                ("access-control-allow-methods", CORS_METHODS),
                ("access-control-allow-headers", CORS_HEADERS),
                ("access-control-max-age", CORS_MAX_AGE),
                ("vary", "Origin"),
            ],
        )
            .into_response();
    }

    let mut response = next.run(req).await;
    if let Some(allow) = allow {
        let headers = response.headers_mut();
        if let Ok(value) = allow.header().parse() {
            headers.insert("access-control-allow-origin", value);
        }
        // Without this a shared cache would hand one origin's answer, with
        // its Allow-Origin header, to a request from another.
        headers.insert("vary", axum::http::HeaderValue::from_static("Origin"));
    }
    response
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
mod tests;
