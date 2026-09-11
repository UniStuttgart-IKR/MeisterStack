// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! The discovery document: what this tier serves, under which verbs, with
//! which subresources and which features. Moved out of `rest.rs` unchanged.

use super::*;

// --- discovery --------------------------------------------------------------

/// Where a client asks an endpoint what it is and what it serves.
///
/// Deliberately the group-version itself and not a path under it: the one
/// question a client has before it knows anything is "what is here", and it
/// has to be answerable without a credential. `classify` sees no resource
/// segment here and returns `None`, so the guard lets it past exactly as it
/// lets /healthz past — see the test.
pub const DISCOVERY_PATH: &str = "/apis/meister.io/v1";

/// One row of the discovery document: a resource this endpoint really serves.
///
/// `verbs` is what the ROUTER offers, not what the resource could in
/// principle support, and that is the whole value of the document: a client
/// that reads `update` here may PUT, and one that does not read it must not
/// try. Whether the objects belong to a tenant is not a field — it is
/// `auth::is_tenant_scoped`, asked once here rather than written down twice.
#[derive(Clone, Copy, Debug)]
pub struct ApiResource {
    /// The path segment, and the `RESOURCE` of the type behind it.
    pub name: &'static str,
    pub kind: &'static str,
    pub verbs: &'static [&'static str],
    /// The segments that hang under an object of this kind — `logs`,
    /// `events`, `approval`, `nodes`. Empty is left out of the document.
    pub subresources: &'static [&'static str],
    /// The very table this resource's update handler hands to `check_owned`,
    /// not a copy of it. That is the whole point: what `/schemas` publishes
    /// is what the server enforces, because it is the same `const`.
    ///
    /// `Some(&[])` and `None` are different answers and the type says so:
    /// an empty table is "nothing here is the server's, and somebody checked",
    /// `None` is "nobody has looked yet". A resource a client may edit owes
    /// it the first and not the second.
    pub owned: Option<&'static [Owned]>,
    /// The JSON Schema of the whole object, envelope included.
    ///
    /// A function pointer rather than a value because a schema is built at
    /// runtime and this table is a `const`. `None` is a resource whose shape
    /// is not published yet, and the test at the bottom of each tier's api.rs
    /// says which of those are allowed.
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

    /// Name the mutability table this resource's handler enforces.
    ///
    /// Builders rather than more parameters on `new`: a row that says nothing
    /// about shape stays one line, and the two things being added here are
    /// exactly the two a client had to be told in prose before.
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

/// The behaviours an endpoint has that are not a resource and not a verb.
///
/// A client learns what exists from `resources` and what may be done to it
/// from `verbs`. Everything else it had to learn by TRYING — and the worst
/// case of that is in the report this list comes from: `?dryRun=All` was
/// accepted, ignored, and written, so a client that assumed the Kubernetes
/// convention and "previewed" created real objects. It is implemented now,
/// and a client still could not tell a server that has it from one that
/// silently drops the parameter.
///
/// So: names, in the document, beside the resources. A name here is a promise
/// about behaviour that the reference spells out once; absent is "do not
/// try", which is a thing a client can act on.
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

/// The whole document, built once when the router is.
///
/// A function rather than a handler body so that a test can read what an
/// endpoint would say without a socket, and so that the router serves a value
/// it does not rebuild per request.
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

/// The kinds whose status carries `observedGeneration`, by name.
///
/// "Write, then wait for `observedGeneration >= generation`" is the one rule
/// a declarative client needs in order to know when a write has landed, and
/// until this list existed there was no way to ask which kinds it holds for:
/// the field arrived on four kinds and the reference said so in prose, in a
/// document that is behind the server by construction. A provider had to
/// hard-code a list and be wrong on the next release.
///
/// Derived from the very schema `/schemas` publishes rather than written out
/// here, so a kind that grows the field is in this list the same day, and a
/// kind whose shape is not published at all is honestly absent rather than
/// silently claimed.
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

/// What the discovery route serves: the document, and the chain that has to
/// be asked again every time.
///
/// Everything in the document is decided when the router is built and one
/// thing is not — whether a configured authenticator can authenticate
/// anybody. D11: the lab's cloud answered `auth: "mtls,oidc"` for hours while
/// the provider was unreachable and no key had ever been fetched, because the
/// string was taken once at start-up. Taking it once at start-up in the other
/// direction would be just as wrong: at start-up nothing has loaded yet, so
/// every deployment would advertise `oidc:degraded` for ever.
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

/// The one route, ready to be merged into a tier's router.
///
/// The routes themselves are NOT built from `resources`: they stay written
/// out one by one where they always were, and the table beside them is a
/// second statement that a test holds to the first. Deriving one from the
/// other would make the document true by construction and therefore worth
/// nothing.
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
