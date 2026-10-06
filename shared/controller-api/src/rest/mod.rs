// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Shared REST serving and request helpers.
//!
//! The TLS listener attaches peer certificates to requests for authentication.
//! Authorization policy lives in `auth`; directory resolution lives in `guard`.
//! TLS and authentication are configured independently. Anonymous, unrestricted
//! access exists only where `auth.anonymous` asks for it.

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

/// DER peer certificate chain, leaf first, attached by the listener.
/// Absence means either plaintext or TLS without a presented client certificate.
#[derive(Clone, Debug, Default)]
pub struct PeerCerts(pub Vec<Vec<u8>>);

/// Serve HTTP or TLS. The TLS accept loop additionally attaches peer
/// certificates for request authentication.
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
        // Disable Nagle to avoid delayed-ACK latency for small TLS records.
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
    // Omit details unless there is a structured field path to report.
    if let Some(field) = field {
        body["details"] = serde_json::json!({ "field": field });
    }
    (status, axum::Json(body)).into_response()
}

/// JSON extractor/response using the shared Status error envelope.
/// Malformed JSON and deserialization failures are 400 BadRequest;
/// handlers reserve 422 for understood but invalid requests. Preserve
/// the serde error details.
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

/// Shared handler error: HTTP status, stable reason and readable message.
/// Private fields keep status/reason combinations behind named constructors.
#[derive(Debug)]
pub struct ApiError {
    status: StatusCode,
    reason: &'static str,
    message: String,
    /// Optional structured input path, emitted as details.field without requiring
    /// clients to parse the message.
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

    /// Message reused when a REST refusal travels through a session CommandResult.
    pub fn message(&self) -> &str {
        &self.message
    }

    pub fn status(&self) -> StatusCode {
        self.status
    }

    /// Structured field path for in-process callers and validation tests.
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

/// 500 — a write this request made lost its claim and could not be taken back: it stands in
/// the store on what won the claim until a person undoes it. Not a `Conflict`, which says that
/// nothing was written and which `patch_with_retry` takes for a lost compare-and-swap and runs
/// again. (NL6-3)
pub fn claim_not_taken_back(message: impl Into<String>) -> ApiError {
    ApiError::new(
        StatusCode::INTERNAL_SERVER_ERROR,
        "ClaimNotTakenBack",
        message,
    )
}

/// 403 — the caller is known and may not.
pub fn forbidden(message: impl Into<String>) -> ApiError {
    ApiError::new(StatusCode::FORBIDDEN, "Forbidden", message)
}

// --- the preview ------------------------------------------------------------

/// Parse the supported preview request, `?dryRun=All`. Handlers run validation
/// and admission, then return a marked object without persisting or dispatching
/// it. This is separate from the agent socket's local provisioning dry run.
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

    /// Return a marked preview, or None for a real write. Use generation at
    /// least 1 and clear resourceVersion because no etcd revision was created.
    /// The caller must run its ordinary validation before reaching this helper.
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

/// Extract the first literal dryRun query value without percent-decoding.
/// Only the expected ASCII spelling is accepted.
fn dry_run_value(query: &str) -> Option<&str> {
    query.split('&').find_map(|pair| {
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        (key == "dryRun").then_some(value)
    })
}

// --- narrowing a listing ----------------------------------------------------

/// Additional list filters applied within authorized inventory.
/// A confined caller filtering for another tenant receives an empty list.
#[derive(Debug, Default, serde::Deserialize)]
pub struct ListQuery {
    /// `labelSelector=k=v,k2=v2`, matched against `metadata.labels`.
    #[serde(default, rename = "labelSelector")]
    pub label_selector: Option<String>,
    /// `tenant=acme`, matched against `spec.tenant`.
    #[serde(default)]
    pub tenant: Option<String>,
}

/// Comma-separated equality selectors. Set membership and negation syntax
/// are unsupported.
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

/// HTTP-edge configuration under the shared `[api]` table.
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
    /// Wildcard origin response without Allow-Credentials, which cannot be combined
    /// with wildcard Access-Control-Allow-Origin.
    Any,
    /// The caller's exact origin, echoed. Never the configured LIST: a
    /// browser matches one value against its own origin, and a list is a
    /// header it rejects.
    Exact(String),
}

/// Allow an exact configured Origin or the explicit wildcard entry.
/// Do not interpret suffixes or partial host patterns.
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

/// Methods advertised by API CORS preflight; individual route support may vary.
const CORS_METHODS: &str = "GET, POST, PUT, PATCH, DELETE";

/// Allowed browser request headers. Merge-patch JSON requires Content-Type
/// permission during preflight.
const CORS_HEADERS: &str = "Authorization, Content-Type";

/// How long a browser may remember a preflight, in seconds.
const CORS_MAX_AGE: &str = "600";

/// Wrap the authentication guard with CORS so unauthenticated browser
/// preflights can be answered. Empty allowed origins emits no CORS
/// headers; unlisted origins receive no browser access grant.
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
    // Apply CORS only to API routes, leaving health and readiness probes unchanged.
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

/// Build optional REST TLS. No configuration selects HTTP; a partial
/// certificate/key pair is an error. TLS loads its CRL at startup;
/// application revocation checks reload separately.
pub fn server_tls(
    cert: Option<&std::path::Path>,
    key: Option<&std::path::Path>,
    client_ca: Option<&std::path::Path>,
    base: Option<&std::path::Path>,
    crl: Option<&std::path::Path>,
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
            let crl = crl.map(|p| pki::pem::resolve(base, p));
            let config = pki::tls::server_config(&cert, &key, ca.as_deref(), crl.as_deref())?;
            info!(
                cert = %cert.display(),
                mtls = ca.is_some(),
                crl = crl.as_ref().map(|p| p.display().to_string()),
                "tls enabled"
            );
            Ok(Some(config))
        }
        _ => anyhow::bail!("tls_cert and tls_key go together; set both or neither"),
    }
}

#[cfg(test)]
mod tests;
