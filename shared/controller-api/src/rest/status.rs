// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Status envelopes for errors, readiness, deletion and unmatched routes.

use super::*;

/// Kind used by the shared error envelope.
pub const KIND_STATUS: &str = "Status";

/// Use the shared Status envelope for unknown routes and unsupported
/// methods. Wrap the complete router; malformed bodies are handled by
/// the separate Json extractor.
pub fn statuses(router: Router) -> Router {
    router
        .fallback(no_route)
        .method_not_allowed_fallback(wrong_method)
}

/// Return a Status 404 naming the unsupported method and path.
pub(super) async fn no_route(method: axum::http::Method, uri: axum::http::Uri) -> Response {
    deny(
        StatusCode::NOT_FOUND,
        "NotFound",
        format!("no route for {method} {}", uri.path()),
        None,
    )
}

/// Return a Status 405. Axum supplies Allow from registered route methods;
/// this response deliberately does not override it.
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

/// Readiness probe deadline, shorter than ordinary store-operation timeouts.
pub const READY_TIMEOUT: Duration = Duration::from_secs(1);

/// Read/write readiness against etcd. Peer sessions are excluded: their
/// normal reconnects do not make the REST process unusable. `/healthz`
/// checks process liveness separately.
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

/// Whether DELETE completed immediately or started asynchronous teardown.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Removal {
    /// It is not there any more. `200`.
    Gone,
    /// It is marked, and a controller has a teardown to run before the object
    /// goes. `202`, and the object still answers a GET until it has.
    Going,
}

/// Shared DELETE Status envelope. Immediate deletion returns 200;
/// accepted cleanup with remaining finalizers returns 202.
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
