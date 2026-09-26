// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Discovery for the resources, verbs, subresources and features of a tier.

use super::*;

// --- discovery --------------------------------------------------------------

/// Unauthenticated discovery lives at the API group/version root.
/// With no resource segment, request classification leaves it outside object auth.
pub const DISCOVERY_PATH: &str = "/apis/meister.io/v1";

/// Resource routes actually offered by this endpoint. Verbs reflect its router,
/// while tenant scope comes from the shared authorization classification.
#[derive(Clone, Copy, Debug)]
pub struct ApiResource {
    /// The path segment, and the `RESOURCE` of the type behind it.
    pub name: &'static str,
    pub kind: &'static str,
    pub verbs: &'static [&'static str],
    /// The segments that hang under an object of this kind — `logs`,
    /// `events`, `approval`, `nodes`. Empty is left out of the document.
    pub subresources: &'static [&'static str],
    /// The update handler's actual mutability table, also published in discovery.
    /// Some(empty) means reviewed with no owned fields; None means unspecified.
    pub owned: Option<&'static [Owned]>,
    /// Builder for the complete object schema, including its envelope.
    /// A function pointer permits const route tables; None means unpublished shape.
    pub schema: Option<fn() -> serde_json::Value>,
}

impl ApiResource {
    pub const fn new(
        name: &'static str,
        kind: &'static str,
        verbs: &'static [&'static str],
        subresources: &'static [&'static str],
    ) -> Self {
        Self {
            name,
            kind,
            verbs,
            subresources,
            owned: None,
            schema: None,
        }
    }

    /// Associate the mutability table enforced by this resource's update handler.
    pub const fn owning(mut self, owned: &'static [Owned]) -> Self {
        self.owned = Some(owned);
        self
    }

    /// The table, or an empty one for a resource nobody has declared yet.
    pub fn owned_fields(&self) -> &'static [Owned] {
        match self.owned {
            Some(owned) => owned,
            None => &[],
        }
    }

    /// Name how to build this resource's schema. Call it as
    /// `.shaped(schema_of::<Vm>)`.
    pub const fn shaped(mut self, schema: fn() -> serde_json::Value) -> Self {
        self.schema = Some(schema);
        self
    }

    fn to_json(self) -> serde_json::Value {
        let mut row = serde_json::json!({
            "name": self.name,
            "kind": self.kind,
            "verbs": self.verbs,
            "tenantScoped": crate::auth::is_tenant_scoped(self.name),
        });
        if !self.subresources.is_empty() {
            row["subresources"] = serde_json::json!(self.subresources);
        }
        row
    }
}

/// Named behaviors beyond resource verbs, such as dry-run support.
/// Clients use discovery instead of assuming a query parameter is honored.
pub mod features {
    /// `?dryRun=All` on a write: every check the real request makes is made,
    /// and nothing is stored.
    pub const DRY_RUN: &str = "dryRun";
    /// `?labelSelector=k=v,k2=v2` on a listing.
    pub const LABEL_SELECTOR: &str = "labelSelector";
    /// `?tenant=` on a listing. A FILTER and not a permission — it narrows
    /// what comes back and lets nobody past anything.
    pub const TENANT_FILTER: &str = "tenantFilter";
    /// `GET /vms/{name}/console` answers a WebSocket handshake as well as the
    /// raw upgrade, and `POST /vms/{name}/console/ticket` mints the
    /// short-lived credential a browser needs to open one.
    pub const CONSOLE_WEBSOCKET: &str = "console.websocket";
    /// `GET /whoami` — the server's own word about who the caller is.
    pub const WHOAMI: &str = "whoami";
}

/// Build the discovery value once for router construction and direct testing.
pub fn discovery_document(
    tier: Tier,
    auth: &str,
    resources: &'static [ApiResource],
    features: &'static [&'static str],
) -> serde_json::Value {
    serde_json::json!({
        "apiVersion": API_VERSION,
        "kind": "APIResourceList",
        "tier": tier.as_str(),
        "auth": auth,
        "features": features,
        "observedGeneration": carries_observed_generation(resources),
        "resources": resources.iter().map(|r| r.to_json()).collect::<Vec<_>>(),
    })
}

/// Derive kinds exposing observedGeneration from their published schemas.
/// Its completion meaning remains resource-specific; field presence alone
/// is not proof that all requested side effects finished.
fn carries_observed_generation(resources: &'static [ApiResource]) -> Vec<&'static str> {
    resources
        .iter()
        .filter(|r| {
            r.schema
                .is_some_and(|build| schema_has_field(&build(), "status.observedGeneration"))
        })
        .map(|r| r.kind)
        .collect()
}

/// Static discovery fields plus the authentication chain. Recompute
/// authentication readiness for each response as remote keys become available.
#[derive(Clone)]
pub(super) struct Discovery {
    document: Arc<serde_json::Value>,
    chain: Arc<crate::auth::AuthChain>,
}

pub(super) async fn api_resources(State(st): State<Discovery>) -> Json<serde_json::Value> {
    let mut doc = (*st.document).clone();
    doc["auth"] = serde_json::json!(st.chain.describe());
    Json(doc)
}

/// Create the discovery route. Resource routes are registered separately;
/// tests verify that their published descriptions agree.
pub fn discovery(
    tier: Tier,
    chain: Arc<crate::auth::AuthChain>,
    resources: &'static [ApiResource],
    features: &'static [&'static str],
) -> Router {
    Router::new()
        .route(DISCOVERY_PATH, get(api_resources))
        .with_state(Discovery {
            // Built once, as it always was: `auth` is the only key in it that
            // can change while the process runs, and the handler replaces
            // that one.
            document: Arc::new(discovery_document(
                tier,
                &chain.describe(),
                resources,
                features,
            )),
            chain,
        })
        .merge(
            Router::new()
                .route(SCHEMAS_PATH, get(api_schemas))
                .with_state(Arc::new(schema_document(resources))),
        )
}
