// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! The `Status` kind: what a route that does not exist answers, what a method
//! no route registers answers, and what readiness says. Moved out of
//! `rest.rs` unchanged.

use super::*;

/// The `kind` every refusal of this API wears.
///
/// Kubernetes' own, and here for Kubernetes' reason: every OTHER answer this
/// API gives is an object with a `kind`, so a client that switches on `kind`
/// had one special case — the errors, which were
/// `{"error": ..., "reason": ...}` and nothing else. Now there is no special
/// case, and "read `kind`" is the whole of what a client has to know.
pub const KIND_STATUS: &str = "Status";

/// The three refusals that come from axum and not from a handler, given the
/// same body as every other one.
///
/// A client that switches on `body.kind` had a special case left after
/// `KIND_STATUS` landed, and it was the whole first row of an API: a path
/// nobody serves, a method a path does not have, and a body that is not JSON
/// are all answered BEFORE any handler runs, and axum answers them in plain
/// text. So the one thing a client must know — read `kind` — stopped being
/// true exactly where a client is most likely to be wrong.
///
/// Both tiers wrap their router in this, and it is the last thing wrapped so
/// that it sees the whole route table. The `Json` extractor below is the
/// third of the three; it cannot live here because it is a type a handler
/// names.
pub fn statuses(router: Router) -> Router {
    router
        .fallback(no_route)
        .method_not_allowed_fallback(wrong_method)
}

/// 404 for a path this endpoint does not serve, naming the method and the
/// path. Not the bare "no route": which endpoint a client is talking to is
/// half the answer here — the two tiers serve DIFFERENT resource sets on the
/// same paths, and "no route for GET /apis/meister.io/v1/tenants" against a
/// cluster is a complete diagnosis where "404" is a puzzle.
pub(super) async fn no_route(method: axum::http::Method, uri: axum::http::Uri) -> Response {
    deny(
        StatusCode::NOT_FOUND,
        "NotFound",
        format!("no route for {method} {}", uri.path()),
        None,
    )
}

/// 405 for a path that exists without this method.
///
/// The `Allow` header is axum's: it knows the methods the route has and adds
/// the header to whatever this returns, as long as this does not set one
/// itself. So the header is right by construction rather than by a second
/// list here that could disagree with the routes.
pub(super) async fn wrong_method(method: axum::http::Method, uri: axum::http::Uri) -> Response {
    deny(
        StatusCode::METHOD_NOT_ALLOWED,
        "MethodNotAllowed",
        format!(
            "{method} is not a method of {}; see the Allow header",
            uri.path()
        ),
        None,
    )
}

// --- readiness --------------------------------------------------------------

/// How long `/readyz` waits for the store before it calls itself not ready.
///
/// One second, and it is a SECOND bound inside the store's own five: the
/// store's timeout is a liveness bound for work that has to finish, and this
/// is a probe a load balancer asks every few seconds. A probe that took five
/// seconds to say "not ready" is a probe that keeps sending traffic to a
/// replica that cannot serve it for as long as it takes to notice.
pub const READY_TIMEOUT: Duration = Duration::from_secs(1);

/// What `/readyz` answers, at both tiers.
///
/// `/healthz` stays "the process is alive" and this is "the process can
/// serve", which are different questions and used to have the same answer:
/// both routes were the same handler, so a replica whose etcd was gone
/// answered `ok` to readiness and 500 to every real request — and kept
/// getting traffic from the load balancer in front of it.
///
/// Ready means "can read and write", and the store is the whole of that. A
/// session to the cloud or to a node is deliberately NOT part of it: a
/// replica with no session serves every REST request correctly, and a
/// readiness that included sessions would take a whole tier out of rotation
/// because one gRPC stream was reconnecting.
pub async fn readiness(store: &EtcdStore) -> Response {
    match tokio::time::timeout(READY_TIMEOUT, store.probe()).await {
        Ok(Ok(())) => (StatusCode::OK, "ok").into_response(),
        // The store answered with a refusal, which is still an answer about
        // the store and not about this replica's ability to reach it — but
        // either way this replica cannot serve, and that is what is asked.
        Ok(Err(e)) => not_ready(&format!("{e}")),
        Err(_) => not_ready(&format!(
            "the store did not answer within {}s",
            READY_TIMEOUT.as_secs()
        )),
    }
}

pub(super) fn not_ready(why: &str) -> Response {
    deny(
        StatusCode::SERVICE_UNAVAILABLE,
        "Unavailable",
        format!("this replica cannot reach its store: {why}"),
        None,
    )
}

/// Is the thing gone, or going?
///
/// The one difference a client has to act on, and the only reason a DELETE
/// needs two codes: a resource whose teardown is somebody else's work is
/// still readable after the request, and a client that polled for its
/// disappearance would otherwise never learn whether to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Removal {
    /// It is not there any more. `200`.
    Gone,
    /// It is marked, and a controller has a teardown to run before the object
    /// goes. `202`, and the object still answers a GET until it has.
    Going,
}

/// The one body a DELETE answers with, whatever the resource.
///
/// Before this there were four shapes behind one verb: the object itself, a
/// `{"deleted": name}`, the same with an extra key, and a
/// `{"releasing": …, "attachedTo": …}`. A client had to know, per resource,
/// which one it was about to get — which is exactly the thing a
/// machine-readable envelope exists to prevent, and what the tofu provider
/// wrote down as its own workaround.
///
/// It is K8s' `Status`, and it is the SAME envelope every refusal already
/// wears (see `deny`): `kind`, `code`, `reason`, `message`, and `details` for
/// whatever this particular resource has to add. So the rule a client learns
/// once — read `kind` — holds for the whole verb.
pub struct Removed {
    removal: Removal,
    message: String,
    details: serde_json::Map<String, serde_json::Value>,
}

/// `DELETE` answered: the kind and name that went, and whether it is gone.
pub fn removed(kind: &str, name: &str, removal: Removal) -> Removed {
    let mut details = serde_json::Map::new();
    details.insert("kind".to_string(), serde_json::json!(kind));
    details.insert("name".to_string(), serde_json::json!(name));
    Removed {
        removal,
        message: match removal {
            Removal::Gone => format!("{kind} {name} deleted"),
            Removal::Going => format!("{kind} {name} is being deleted"),
        },
        details,
    }
}

impl Removed {
    /// A sentence of this resource's own, where the default one leaves
    /// something out that the caller has to know.
    pub fn saying(mut self, message: impl Into<String>) -> Self {
        self.message = message.into();
        self
    }

    /// One more fact under `details`. That is where a resource's own answer
    /// goes — K8s' extension point, and the reason the top level of this body
    /// can stay the same for every kind.
    pub fn detail(mut self, key: &str, value: serde_json::Value) -> Self {
        self.details.insert(key.to_string(), value);
        self
    }

    /// The document, for a caller that wants to look at it rather than send
    /// it. Used by the tests and by nothing else.
    pub fn body(&self) -> serde_json::Value {
        let code = match self.removal {
            Removal::Gone => StatusCode::OK,
            Removal::Going => StatusCode::ACCEPTED,
        };
        serde_json::json!({
            "apiVersion": API_VERSION,
            "kind": KIND_STATUS,
            "status": "Success",
            "code": code.as_u16(),
            "reason": match self.removal {
                Removal::Gone => "Deleted",
                Removal::Going => "Deleting",
            },
            "message": self.message,
            "details": serde_json::Value::Object(self.details.clone()),
        })
    }
}

impl IntoResponse for Removed {
    fn into_response(self) -> Response {
        let code = match self.removal {
            Removal::Gone => StatusCode::OK,
            Removal::Going => StatusCode::ACCEPTED,
        };
        (code, axum::Json(self.body())).into_response()
    }
}
