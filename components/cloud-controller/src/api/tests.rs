// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! The cloud edge's router-contract tests, verbatim out of `mod.rs`. The
//! module path is unchanged (`api::tests`), so every test still answers to
//! the name it had before.

use super::*;

/// The three refusals a client never used to get as `kind: Status`.
///
/// They come from axum before any handler runs — a path nobody serves, a
/// method a path does not have, a body that is not this route's object —
/// so they were plain text, and a client switching on `body.kind` fell
/// into a special case at exactly the moment it was most likely to be
/// wrong. No store is reached by any of the three, which is what lets
/// them be tested against a router with no etcd behind it.
#[tokio::test]
async fn every_refusal_before_a_handler_is_a_status_object() {
    use tower::ServiceExt;

    let ask = async |method: &str, path: &str, body: &'static str| {
        let response = test_router()
            .await
            .oneshot(
                axum::http::Request::builder()
                    .method(method)
                    .uri(path)
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(body))
                    .unwrap(),
            )
            .await
            .expect("the router answers");
        let status = response.status();
        let allow = response
            .headers()
            .get(axum::http::header::ALLOW)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);
        let bytes = axum::body::to_bytes(response.into_body(), 64 * 1024)
            .await
            .expect("a body");
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap_or_else(|_| {
            panic!("{status} was not json: {}", String::from_utf8_lossy(&bytes))
        });
        (status, json, allow)
    };

    // A path this endpoint does not serve. It names the method and the
    // path, because the two tiers serve different resources on the same
    // prefix and "404" alone does not say which one you are talking to.
    let (status, body, _) = ask("GET", "/apis/meister.io/v1/nonesuch", "").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body["kind"], "Status");
    assert_eq!(body["code"], 404);
    assert_eq!(body["reason"], "NotFound");
    assert!(
        body["message"]
            .as_str()
            .is_some_and(|m| m.contains("GET") && m.contains("/apis/meister.io/v1/nonesuch")),
        "{body}"
    );

    // A path that exists without this method. The `Allow` header is
    // axum's, built from the real route table.
    let (status, body, allow) = ask("DELETE", "/apis/meister.io/v1/vms", "").await;
    assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED);
    assert_eq!(body["kind"], "Status");
    assert_eq!(body["code"], 405);
    assert_eq!(body["reason"], "MethodNotAllowed");
    let allow = allow.expect("axum sets Allow beside a 405");
    assert!(allow.contains("GET"), "{allow}");

    // And a body that never became an object. 400 rather than 422: 422
    // here means "understood and refused", and this was not understood.
    let (status, body, _) = ask("POST", "/apis/meister.io/v1/vms", "{ not json").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["kind"], "Status");
    assert_eq!(body["code"], 400);
    assert_eq!(body["reason"], "BadRequest");
    assert!(
        body["message"].as_str().is_some_and(|m| !m.is_empty()),
        "serde's own sentence travels: {body}"
    );
}

/// A router with no etcd behind it. `EtcdStore::connect` is lazy — it
/// builds a channel and dials nothing — and the two tests below never
/// reach a handler, so nothing here ever asks the store a question.
async fn test_router() -> Router {
    let store = Arc::new(
        EtcdStore::connect(&["http://127.0.0.1:1".to_string()], "/discovery-test")
            .await
            .expect("the etcd client is built lazily"),
    );
    router(
        store.clone(),
        Arc::new(crate::session::SessionRegistry::new()),
        Settings {
            signing: None,
            kek: None,
            sibling: controller_api::forward::Sibling {
                serves_tls: false,
                tls: None,
            },
            vni_base: 10_000,
            routed_pools: Vec::new(),
            advertise: None,
            overcommit: controller_api::Overcommit::default(),
            scheduler: Arc::new(controller_api::FirstFit),
            tickets: Arc::new(controller_api::tickets::Tickets::new(store.clone())),
        },
        // Two links that are ready by construction, named the way a
        // real chain names its own: what the document says under `auth`
        // is asked of the CHAIN now, not handed in as a string (D11).
        Arc::new(controller_api::AuthChain::named(
            vec![Box::new(token("a")), Box::new(token("b"))],
            vec!["mtls", "bearer"],
        )),
    )
}

/// A link that is ready the moment it is built, which is every link but
/// the oidc one.
fn token(secret: &str) -> controller_api::BearerAuthenticator {
    controller_api::BearerAuthenticator::new(
        secret,
        controller_api::Identity::new("root", vec![controller_api::GROUP_MASTERS.into()]),
    )
}

/// Which methods does this path really have?
///
/// Asked with TRACE, which no route registers: axum answers 404 for a
/// path it does not route and 405 with an `Allow` header for one it does,
/// and neither answer runs a handler. So this reads the router's real
/// routing table with no store, no session and no second process. `None`
/// is "this path is not served at all".
async fn allowed(path: &str) -> Option<Vec<String>> {
    use tower::ServiceExt;
    let response = test_router()
        .await
        .oneshot(
            axum::http::Request::builder()
                .method("TRACE")
                .uri(path)
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .expect("the router answers");
    if response.status() == StatusCode::NOT_FOUND {
        return None;
    }
    Some(
        response
            .headers()
            .get(axum::http::header::ALLOW)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .split(',')
            .map(|m| m.trim().to_string())
            .collect(),
    )
}

async fn serves(path: &str) -> bool {
    allowed(path).await.is_some()
}

/// And the verbs are a promise as well. `Allow` on the 405 is where the
/// router says which methods it has, so this holds every cell of the
/// table to it: `list`/`create` on the collection path, `get`/`update`/
/// `patch`/`delete` on the object path.
#[tokio::test]
async fn the_verbs_in_the_discovery_table_are_the_methods_the_router_allows() {
    for row in RESOURCES {
        let collection = allowed(&format!("/apis/meister.io/v1/{}", row.name))
            .await
            .unwrap_or_default();
        let object = allowed(&format!("/apis/meister.io/v1/{}/x", row.name))
            .await
            .unwrap_or_default();
        for (verb, method, on) in [
            ("list", "GET", &collection),
            ("create", "POST", &collection),
            ("get", "GET", &object),
            ("update", "PUT", &object),
            ("patch", "PATCH", &object),
            ("delete", "DELETE", &object),
        ] {
            assert_eq!(
                row.verbs.contains(&verb),
                on.iter().any(|m| m == method),
                "{} claims {verb:?} and the router allows {on:?}",
                row.name
            );
        }
    }
}

/// The discovery document is a promise, and this is the half that keeps
/// it: every row of `RESOURCES`, and every subresource a row names, is a
/// path this router really serves.
#[tokio::test]
async fn every_row_of_the_discovery_table_is_a_path_this_router_serves() {
    for row in RESOURCES {
        assert!(
            serves(&format!("/apis/meister.io/v1/{}", row.name)).await,
            "{} is in the discovery table and not in the router",
            row.name
        );
        for sub in row.subresources {
            assert!(
                serves(&format!("/apis/meister.io/v1/{}/x/{sub}", row.name)).await,
                "{}/{sub} is in the discovery table and not in the router",
                row.name
            );
        }
    }
    // And the probe can tell the difference, or the loop above proves
    // nothing.
    assert!(!serves("/apis/meister.io/v1/widgets").await);
}

/// The other half of the same promise. A feature name is a client's only
/// way to tell a server that HAS a behaviour from one that silently drops
/// the parameter — which is exactly what `?dryRun=All` did before it was
/// built, and why a client that trusted the convention created real
/// objects while it believed it was previewing.
///
/// So each name that is a ROUTE is held to its route. `dryRun`,
/// `labelSelector` and `tenantFilter` are query parameters on routes the
/// table above already checks, and their own tests are beside the
/// handlers that read them.
#[tokio::test]
async fn every_feature_this_endpoint_names_is_one_it_has() {
    use controller_api::rest::features;

    for feature in FEATURES {
        let path = match *feature {
            features::CONSOLE_WEBSOCKET => "/apis/meister.io/v1/vms/x/console/ticket",
            features::WHOAMI => controller_api::rest::WHOAMI_PATH,
            features::DRY_RUN | features::LABEL_SELECTOR | features::TENANT_FILTER => continue,
            other => panic!("{other} is named in FEATURES and known to no test"),
        };
        assert!(
            serves(path).await,
            "{feature} is announced and {path} is not served"
        );
    }
}

/// What a client reads before it knows anything else about this endpoint.
#[tokio::test]
async fn the_discovery_route_says_which_tier_this_is_and_what_it_checks() {
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    let response = test_router()
        .await
        .oneshot(
            axum::http::Request::builder()
                .uri(controller_api::DISCOVERY_PATH)
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .expect("the router answers");
    assert_eq!(response.status(), StatusCode::OK);

    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let doc: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(doc["kind"], "APIResourceList");
    assert_eq!(doc["tier"], "cloud");
    assert_eq!(doc["auth"], "mtls,bearer");
    assert_eq!(doc["resources"].as_array().unwrap().len(), RESOURCES.len());
}

/// Every row of the mutability table, against a real object of that
/// kind, through the function the handlers call.
///
/// The table is a promise to a client — the API reference prints it — so
/// it is held to real objects and not to a hand-written document: a field
/// renamed in a spec would break this test and not just the prose.
#[test]
fn every_owned_field_refuses_a_different_value_and_takes_the_same_one() {
    // `(table, a stored object, the same object with ONE field moved)`.
    // Each pair differs in exactly the field named beside it.
    let cases: Vec<(&str, &[Owned], serde_json::Value, serde_json::Value)> = vec![
        (
            "spec.vm",
            VM_OWNED,
            json!({"spec": {"vm": {"vcpus": 2}, "tenant": "acme"}}),
            json!({"spec": {"vm": {"vcpus": 4}, "tenant": "acme"}}),
        ),
        (
            "spec.clusterSelector",
            VM_OWNED,
            json!({"spec": {"clusterSelector": {"zone": "lab"}}}),
            json!({"spec": {"clusterSelector": {"zone": "dev"}}}),
        ),
        (
            "spec.tenant",
            VM_OWNED,
            json!({"spec": {"tenant": "acme"}}),
            json!({"spec": {"tenant": "globex"}}),
        ),
        (
            "spec.clusterName",
            VM_OWNED,
            json!({"spec": {"clusterName": "cluster-1"}}),
            json!({"spec": {"clusterName": "cluster-2"}}),
        ),
        (
            "spec.vni",
            TENANT_OWNED,
            json!({"spec": {"vni": 4097}}),
            json!({"spec": {"vni": 4098}}),
        ),
        (
            "spec.address",
            FLOATING_IP_OWNED,
            json!({"spec": {"address": "10.255.0.7"}}),
            json!({"spec": {"address": "10.255.0.8"}}),
        ),
        (
            "spec.pool",
            FLOATING_IP_OWNED,
            json!({"spec": {"pool": "lab"}}),
            json!({"spec": {"pool": "public"}}),
        ),
        (
            "spec.cidr",
            ROUTED_SUBNET_OWNED,
            json!({"spec": {"cidr": "10.7.1.0/24"}}),
            json!({"spec": {"cidr": "10.7.2.0/24"}}),
        ),
        (
            "spec.driver",
            STORAGE_POOL_OWNED,
            json!({"spec": {"driver": "lvm-thin"}}),
            json!({"spec": {"driver": "nfs"}}),
        ),
        // Downwards, because upwards is what storage B opened. The
        // direction is the whole of the row now, and the test beside this
        // one says both halves.
        (
            "spec.sizeGib",
            VOLUME_OWNED,
            json!({"spec": {"sizeGib": 20}}),
            json!({"spec": {"sizeGib": 10}}),
        ),
        (
            "spec.baseImage",
            VOLUME_OWNED,
            json!({"spec": {"baseImage": "debian.raw"}}),
            json!({"spec": {"baseImage": "ubuntu.raw"}}),
        ),
    ];

    for (path, table, current, moved) in cases {
        controller_api::check_owned(&current, &current, table)
            .unwrap_or_else(|e| panic!("{path} unchanged: {}", e.message()));
        let refused = controller_api::check_owned(&current, &moved, table).expect_err(path);
        assert_eq!(
            refused.status(),
            axum::http::StatusCode::UNPROCESSABLE_ENTITY
        );
        assert_eq!(refused.reason(), "Invalid");
        assert!(
            refused.message().starts_with(&format!("{path} ")),
            "the refusal names the field: {}",
            refused.message()
        );
    }
}

/// What stays editable, and it is the half that matters: these are the
/// fields an operator actually edits, and a table that caught them would
/// have made the API read-only in practice.
#[test]
fn the_free_fields_stay_free() {
    let vm = |strategy: &str, label: &str| {
        json!({
            "metadata": {"labels": {"tier": label}, "annotations": {"note": label}},
            "spec": {"vm": {"vcpus": 2}, "tenant": "acme", "runStrategy": strategy},
        })
    };
    controller_api::check_owned(&vm("Running", "web"), &vm("Stopped", "db"), VM_OWNED)
        .expect("runStrategy, labels and annotations are the client's");

    let pool = |quota: u32| json!({"spec": {"driver": "lvm-thin", "quota": {"acme": quota}}});
    controller_api::check_owned(&pool(10), &pool(50), STORAGE_POOL_OWNED)
        .expect("a quota is what an admin edits a pool for");

    // The assign is the one thing updating a reservation is FOR.
    let ip = |vm: serde_json::Value| json!({"spec": {"address": "10.255.0.7", "vm": vm}});
    controller_api::check_owned(&ip(json!(null)), &ip(json!("web")), FLOATING_IP_OWNED)
        .expect("assigning is not changing which address this is");
}

/// Who sees the whole cloud and who sees one room of it.
///
/// The line is `Operator` and not `Admin`: an operator's job is the
/// estate, and an estate you can only see one tenant's share of is not
/// one you can run. Below it a listing is filtered, which is what makes a
/// viewer a viewer of its own room.
#[test]
fn a_viewer_and_a_member_are_confined_to_their_tenant_and_an_operator_is_not() {
    let grant = |role: Option<Role>| {
        Grant::new(
            Caller(Some(controller_api::Identity::new(
                "someone",
                role.map(|r| vec![r.group().to_string()])
                    .unwrap_or_default(),
            ))),
            CallerRole(role),
            CallerTenant(Some("acme".to_string())),
        )
    };
    assert_eq!(grant(Some(Role::Viewer)).confined_to(), Some("acme"));
    assert_eq!(grant(Some(Role::Member)).confined_to(), Some("acme"));
    assert_eq!(grant(Some(Role::Operator)).confined_to(), None);
    assert_eq!(grant(Some(Role::Admin)).confined_to(), None);
    // Anonymous mode and the machines see everything, as they always did.
    assert_eq!(
        Grant::new(Caller(None), CallerRole(None), CallerTenant(None)).confined_to(),
        None
    );
    assert_eq!(
        Grant::new(
            Caller(Some(controller_api::Identity::new(
                "system:masters",
                vec![]
            ))),
            CallerRole(None),
            CallerTenant(Some("acme".to_string())),
        )
        .confined_to(),
        None
    );
}

/// D-P10: one rule for whose an object is, and the VM was the exception.
///
/// A volume, a floating address and a secret each refuse a create that ends
/// up with no tenant; a VM did not, so `vm ls` showed `TENANT -` beside disks
/// that could not have been made that way. The three are the rule.
///
/// What the rule IS, in one place, because the reference now says it: the
/// tenant is what the client named, or the caller's own when they are
/// confined to one, and a create that ends with neither is refused. So a
/// member never meets the refusal (their own is filled in), and an admin —
/// who is confined to nothing — says which tenant.
#[test]
fn a_create_with_no_tenant_at_all_is_refused_for_every_tenant_scoped_kind() {
    let grant = |role: Option<Role>, tenant: Option<&str>| {
        Grant::new(
            Caller(Some(controller_api::Identity::new(
                "someone",
                role.map(|r| vec![r.group().to_string()])
                    .unwrap_or_default(),
            ))),
            CallerRole(role),
            CallerTenant(tenant.map(str::to_string)),
        )
    };

    // A member's create names nothing and gets their own room.
    let member = grant(Some(Role::Member), Some("acme"));
    assert_eq!(member.tenant_for_create(None), Some("acme".to_string()));
    assert_eq!(
        member.tenant_for_create(Some(String::new())),
        Some("acme".to_string()),
        "an empty string is not a name"
    );

    // An admin is confined to nothing, so an unnamed create has no owner at
    // all — and that is the `None` every tenant-scoped create now refuses.
    let admin = grant(Some(Role::Admin), None);
    assert_eq!(admin.tenant_for_create(None), None);
    assert_eq!(
        admin.tenant_for_create(Some("acme".into())),
        Some("acme".to_string()),
        "and naming one is how an admin creates for somebody"
    );

    // The sentence a `None` becomes is the same word at all four edges, so
    // that an operator who has read it once has read it everywhere.
    let refusal = admin
        .tenant_for_create(None)
        .ok_or_else(|| invalid("spec.tenant must name a tenant"))
        .expect_err("nobody owns it");
    assert_eq!(refusal.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(refusal.message(), "spec.tenant must name a tenant");
}

/// `?tenant=` is a filter and never a door.
///
/// The case the whole shape exists for is the last one: a member asking
/// about another tenant sees NOTHING — not a 403, which would confirm the
/// tenant exists, and not its own objects, which would answer a question
/// nobody asked.
#[test]
fn asking_about_another_tenants_objects_is_an_empty_list_and_not_a_refusal() {
    let grant = |role: Option<Role>, tenant: Option<&str>| {
        Grant::new(
            Caller(Some(controller_api::Identity::new(
                "someone",
                role.map(|r| vec![r.group().to_string()])
                    .unwrap_or_default(),
            ))),
            CallerRole(role),
            CallerTenant(tenant.map(str::to_string)),
        )
    };
    let member = || grant(Some(Role::Member), Some("acme"));
    let admin = || grant(Some(Role::Admin), None);

    // Nobody confined, nothing asked: everything, as every listing has
    // always answered an admin.
    let all = admin().listing(None);
    assert_eq!(all, TenantFilter::All);
    assert!(all.keeps(Some("acme")) && all.keeps(None));

    // Nobody confined, one asked: that one.
    let asked = admin().listing(Some("acme"));
    assert!(asked.keeps(Some("acme")));
    assert!(!asked.keeps(Some("globex")));
    assert!(!asked.keeps(None), "an unscoped object is nobody's");

    // Confined, nothing asked: its own, which is what it always got.
    let own = member().listing(None);
    assert!(own.keeps(Some("acme")));
    assert!(!own.keeps(Some("globex")));

    // Confined and asking for its own: the same.
    assert_eq!(
        member().listing(Some("acme")),
        TenantFilter::Only("acme".into())
    );

    // Confined and asking for somebody else's: nothing at all.
    let elsewhere = member().listing(Some("globex"));
    assert_eq!(elsewhere, TenantFilter::Nothing);
    assert!(!elsewhere.keeps(Some("globex")));
    assert!(!elsewhere.keeps(Some("acme")), "not its own either");
}

/// The other half of the promise: a resource this control plane has is
/// either served here or written down as one this tier does not serve. A
/// new row in `controller_api::resources` fails this test until somebody
/// decides which of the two it is.
/// The tables this tier really enforces, held to the schemas it really
/// publishes.
///
/// Not a copy of either: `RESOURCES` names the same `const` the update
/// handlers hand to `check_owned`, and the schema comes from the type
/// serde deserialises. So this fails the day somebody renames a spec
/// field and forgets the table — which is the failure the prose version
/// of this table could never catch.
#[test]
fn every_mutability_table_names_fields_that_exist() {
    controller_api::assert_tables_match_schemas(RESOURCES);
}

/// A resource a client may write says what it may not write.
///
/// The one exception is spelled out rather than assumed: creating and
/// deleting is not editing, so a resource with no update verb owes
/// nobody a table.
#[test]
fn every_writable_resource_publishes_its_mutability() {
    for row in RESOURCES {
        let editable = row.verbs.contains(&"update") || row.verbs.contains(&"patch");
        assert!(
            row.schema.is_some(),
            "{} publishes no schema; a client cannot render it",
            row.kind
        );
        if editable {
            assert!(
                row.owned.is_some(),
                "{} can be edited and has declared no mutability table. If everything in \
                 its spec really is the client's, say so with `.owning(&[])` and a \
                 sentence — an empty table is an answer, a missing one is not",
                row.kind
            );
        }
    }
}

#[test]
fn every_resource_of_this_control_plane_is_served_here_or_named_as_not_served() {
    for (resource, kind) in controller_api::resources::ALL_RESOURCES {
        match RESOURCES.iter().find(|r| r.name == *resource) {
            Some(row) => assert_eq!(row.kind, *kind, "{resource} names the wrong kind"),
            None => assert!(
                NOT_SERVED.contains(resource),
                "{resource} is new here: serve it, or say in NOT_SERVED why this tier does not"
            ),
        }
    }
    for row in RESOURCES {
        assert!(
            !NOT_SERVED.contains(&row.name),
            "{} is in both lists",
            row.name
        );
    }
}
