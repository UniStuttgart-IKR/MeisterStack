// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! The REST layer's tests, verbatim out of `rest.rs`. The module path is
//! unchanged (`rest::tests`), so every test still answers to the name it had
//! before.

/// `?dryRun` is read out of a raw query, so the tests are about the query
/// and not about a struct. The typo case is the one that matters: a value
/// read as "no" would write the object somebody asked to be shown.
#[test]
fn a_dry_run_is_asked_for_by_one_word_and_no_other() {
    assert_eq!(dry_run_value("dryRun=All"), Some("All"));
    // Beside other parameters, in either order, and with its own value
    // left empty.
    assert_eq!(dry_run_value("tenant=acme&dryRun=All"), Some("All"));
    assert_eq!(dry_run_value("dryRun=All&tenant=acme"), Some("All"));
    assert_eq!(dry_run_value("dryRun="), Some(""));
    // A key that merely starts the same way is a different key.
    assert_eq!(dry_run_value("dryRunAll=1"), None);
    assert_eq!(dry_run_value("notdryRun=All"), None);
    assert_eq!(dry_run_value("tenant=acme"), None);
    assert_eq!(dry_run_value(""), None);
}

/// What the preview says about the object, and the two fields it fills in
/// on the store's behalf.
#[test]
fn a_preview_is_the_object_that_would_have_been_written() {
    use crate::resources::{Vm, VmSpec};

    let mut vm = Vm::declare(
        "web-1",
        serde_json::from_value::<VmSpec>(serde_json::json!({ "vm": {} })).expect("a spec"),
    );
    vm.metadata.resource_version = "17".into();

    // Not asked for: nothing at all happens, and the caller writes.
    assert!(DryRun::default().preview(&vm).is_none());

    let preview = DryRun(true).preview(&vm).expect("asked for");
    assert_eq!(
        preview.metadata.annotations.get(ANNOTATION_DRY_RUN),
        Some(&"true".to_string())
    );
    assert_eq!(preview.metadata.name, "web-1");
    assert_eq!(preview.metadata.uid, vm.metadata.uid, "the same object");
    // `create` would have set this; a preview that said 0 would be a
    // preview of a document no store ever holds.
    assert_eq!(preview.metadata.generation, 1);
    // And this one it would NOT have set to anything a client can use:
    // nothing happened, so there is no revision.
    assert!(preview.metadata.resource_version.is_empty());

    // An update carries its own number through rather than being reset.
    vm.metadata.generation = 4;
    let preview = DryRun(true).preview(&vm).expect("asked for");
    assert_eq!(preview.metadata.generation, 4);
}
use super::*;

fn cfg(toml: &str) -> AuthConfig {
    toml::from_str(toml).expect("the auth table parses")
}

/// An authenticator that recognises nothing, so that every GATED route
/// under this chain would be a 401.
struct Never;
impl crate::auth::Authenticator for Never {
    fn authenticate(&self, _: &AuthRequest) -> Result<Option<Identity>> {
        Ok(None)
    }
}

/// The whole of CORS, against a router that answers the way the real one
/// does: a route that exists for GET and not for OPTIONS.
#[tokio::test]
async fn a_browser_is_shown_this_api_only_from_an_origin_that_was_named() {
    use axum::body::Body;
    use axum::http::Request as HttpRequest;

    let app = |origins: &[&str]| {
        cors(
            Router::new()
                .route("/apis/meister.io/v1/vms/{name}", get(|| async { "vm" }))
                .route("/healthz", get(|| async { "ok" })),
            origins.iter().map(|o| o.to_string()).collect(),
        )
    };
    let send = async |app: Router, method: &str, path: &str, origin: Option<&str>| {
        let mut req = HttpRequest::builder().method(method).uri(path);
        if let Some(origin) = origin {
            req = req.header("origin", origin);
        }
        app.oneshot(req.body(Body::empty()).unwrap()).await.unwrap()
    };
    let head = |r: &Response, name: &str| {
        r.headers()
            .get(name)
            .map(|v| v.to_str().unwrap().to_string())
    };
    const UI: &str = "https://ui.lab.example";

    // The preflight a `PATCH ... merge-patch+json` triggers. Answered
    // before the guard, with no credential in it anywhere.
    let listed = app(&[UI]);
    let pre = send(
        listed.clone(),
        "OPTIONS",
        "/apis/meister.io/v1/vms/web-1",
        Some(UI),
    )
    .await;
    assert_eq!(pre.status(), StatusCode::NO_CONTENT);
    assert_eq!(
        head(&pre, "access-control-allow-origin").as_deref(),
        Some(UI)
    );
    assert_eq!(
        head(&pre, "access-control-allow-methods").as_deref(),
        Some(CORS_METHODS)
    );
    assert_eq!(
        head(&pre, "access-control-allow-headers").as_deref(),
        Some(CORS_HEADERS)
    );
    assert_eq!(
        head(&pre, "access-control-max-age").as_deref(),
        Some(CORS_MAX_AGE)
    );

    // A real answer carries the origin back, and `Vary` so that a cache
    // cannot hand it to somebody else.
    let real = send(
        listed.clone(),
        "GET",
        "/apis/meister.io/v1/vms/web-1",
        Some(UI),
    )
    .await;
    assert_eq!(real.status(), StatusCode::OK);
    assert_eq!(
        head(&real, "access-control-allow-origin").as_deref(),
        Some(UI)
    );
    assert_eq!(head(&real, "vary").as_deref(), Some("Origin"));

    // An origin nobody named is answered exactly as one that sent none:
    // the browser blocks it, and the server has not lied about who may
    // read it.
    let stranger = send(
        listed.clone(),
        "GET",
        "/apis/meister.io/v1/vms/web-1",
        Some("https://evil"),
    )
    .await;
    assert_eq!(stranger.status(), StatusCode::OK);
    assert!(head(&stranger, "access-control-allow-origin").is_none());
    // ... and its preflight is the 405 an OPTIONS on this route has
    // always been, not a 204 that promises something.
    let refused = send(
        listed.clone(),
        "OPTIONS",
        "/apis/meister.io/v1/vms/web-1",
        Some("https://evil"),
    )
    .await;
    assert_eq!(refused.status(), StatusCode::METHOD_NOT_ALLOWED);

    // `/healthz` is not a route a browser negotiates for.
    let probe = send(listed, "OPTIONS", "/healthz", Some(UI)).await;
    assert_eq!(probe.status(), StatusCode::METHOD_NOT_ALLOWED);
    assert!(head(&probe, "access-control-allow-origin").is_none());

    // The default: no list, no headers, and a preflight that is a 405
    // exactly as it was before any of this existed.
    let closed = app(&[]);
    let pre = send(
        closed.clone(),
        "OPTIONS",
        "/apis/meister.io/v1/vms/web-1",
        Some(UI),
    )
    .await;
    assert_eq!(pre.status(), StatusCode::METHOD_NOT_ALLOWED);
    let real = send(closed, "GET", "/apis/meister.io/v1/vms/web-1", Some(UI)).await;
    assert!(head(&real, "access-control-allow-origin").is_none());

    // `*` is allowed and means it — and carries no credentials header,
    // which the standard forbids alongside it.
    let open = app(&["*"]);
    let real = send(
        open,
        "GET",
        "/apis/meister.io/v1/vms/web-1",
        Some("https://anywhere"),
    )
    .await;
    assert_eq!(
        head(&real, "access-control-allow-origin").as_deref(),
        Some("*")
    );
    assert!(head(&real, "access-control-allow-credentials").is_none());
}

/// Exact equality, and the reason it is not a pattern.
#[test]
fn an_origin_matches_by_being_the_same_string() {
    let listed = vec!["https://ui.lab.example".to_string()];
    assert_eq!(
        allow_origin(&listed, Some("https://ui.lab.example")),
        Some(Allow::Exact("https://ui.lab.example".into()))
    );
    // A suffix match would let every one of these in.
    for near in [
        "https://ui.lab.example.attacker.com",
        "http://ui.lab.example",
        "https://ui.lab.example:8443",
        "https://UI.lab.example",
    ] {
        assert_eq!(allow_origin(&listed, Some(near)), None, "{near}");
    }
    // No Origin at all is not an origin to answer.
    assert_eq!(allow_origin(&listed, None), None);
    assert_eq!(allow_origin(&[], Some("https://ui.lab.example")), None);
    assert_eq!(
        allow_origin(&["*".to_string()], Some("https://anywhere")),
        Some(Allow::Any)
    );
}

/// A preflight is not a write, and the guard must not meet it as one.
#[test]
fn a_preflight_is_not_classified_as_anything() {
    assert!(crate::auth::classify("OPTIONS", "/apis/meister.io/v1/vms/web-1").is_none());
    assert!(crate::auth::classify("OPTIONS", "/apis/meister.io/v1/vms").is_none());
    // And every other method is still what it was.
    assert_eq!(
        crate::auth::classify("PATCH", "/apis/meister.io/v1/vms/web-1")
            .unwrap()
            .verb,
        crate::auth::Verb::Write
    );
}

/// A replica whose store does not answer says so, and says it inside its
/// own second rather than the store's five.
///
/// The endpoint accepts the connection and then goes silent, which is
/// what a blackholed etcd looks like from here — and it is the case the
/// bound exists for, because a refused connection was always instant.
/// The etcd client connects lazily, so the store is built without ever
/// having spoken to anything.
#[tokio::test(start_paused = true)]
async fn a_replica_that_cannot_read_its_store_is_not_ready() {
    use axum::body::to_bytes;

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = listener.local_addr().unwrap().to_string();
    tokio::spawn(async move {
        let _held = listener.accept().await;
        std::future::pending::<()>().await;
    });
    let store = EtcdStore::connect(&[endpoint], "/meister")
        .await
        .expect("the etcd client connects lazily");

    let started = tokio::time::Instant::now();
    let response = readiness(&store).await;
    assert_eq!(
        started.elapsed(),
        READY_TIMEOUT,
        "our second, not the store's five"
    );
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);

    // And it is a `Status` like every other refusal, so a client that
    // switches on `kind` reads this one too.
    let body: serde_json::Value =
        serde_json::from_slice(&to_bytes(response.into_body(), 64 * 1024).await.unwrap()).unwrap();
    assert_eq!(body["kind"], KIND_STATUS);
    assert_eq!(body["reason"], "Unavailable");
    assert_eq!(body["code"], 503);
    assert!(
        body["message"]
            .as_str()
            .unwrap()
            .contains("cannot reach its store"),
        "{}",
        body["message"]
    );
}

/// Every refusal this API can give, through the one function that writes
/// them down.
///
/// The point of the shape is that a client switching on `kind` has no
/// special case left: an error IS an object of this API. So the test
/// asserts the envelope on every reason rather than the sentence on one.
#[tokio::test]
async fn every_refusal_is_a_status_object_and_names_its_reason() {
    use axum::body::to_bytes;

    // The whole vocabulary, and the status each is paired with. A reason
    // that appears here with two different codes is two endpoints
    // answering the same problem differently, which is what keeping the
    // constructors private is for.
    let refusals: Vec<(ApiError, StatusCode, &str)> = vec![
        (
            StoreError::NotFound("vms/web-1".into()).into(),
            StatusCode::NOT_FOUND,
            "NotFound",
        ),
        (
            StoreError::AlreadyExists("vms/web-1".into()).into(),
            StatusCode::CONFLICT,
            "AlreadyExists",
        ),
        (
            StoreError::Terminating("vms/web-1".into()).into(),
            StatusCode::CONFLICT,
            "Terminating",
        ),
        (
            conflict("somebody else got there"),
            StatusCode::CONFLICT,
            "Conflict",
        ),
        (
            invalid("spec.vm must be an object"),
            StatusCode::UNPROCESSABLE_ENTITY,
            "Invalid",
        ),
        (
            forbidden("alice may not Write an object of tenant globex"),
            StatusCode::FORBIDDEN,
            "Forbidden",
        ),
        (
            ApiError::new(StatusCode::SERVICE_UNAVAILABLE, "Unavailable", "no session"),
            StatusCode::SERVICE_UNAVAILABLE,
            "Unavailable",
        ),
        (
            ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Internal",
                "etcd said no",
            ),
            StatusCode::INTERNAL_SERVER_ERROR,
            "Internal",
        ),
        (
            ApiError::new(StatusCode::UNAUTHORIZED, "Unauthorized", "no credential"),
            StatusCode::UNAUTHORIZED,
            "Unauthorized",
        ),
        (
            StoreError::Timeout("vms", std::time::Duration::from_secs(2)).into(),
            StatusCode::SERVICE_UNAVAILABLE,
            "Timeout",
        ),
    ];

    for (refusal, code, reason) in refusals {
        let sentence = refusal.message().to_string();
        let response = refusal.into_response();
        assert_eq!(response.status(), code, "{reason}");
        let body: serde_json::Value =
            serde_json::from_slice(&to_bytes(response.into_body(), 64 * 1024).await.unwrap())
                .unwrap();
        assert_eq!(body["apiVersion"], API_VERSION);
        assert_eq!(body["kind"], KIND_STATUS, "a client switches on this");
        assert_eq!(body["status"], "Failure");
        assert_eq!(body["code"], code.as_u16());
        assert_eq!(body["reason"], reason);
        assert_eq!(body["message"], sentence);
        assert!(
            body.get("details").is_none(),
            "{reason} is not about a field, so it carries no details"
        );
    }
}

/// A refusal that IS about a field points at it, so a client need not
/// parse the path out of a sentence written for a person.
#[tokio::test]
async fn a_refusal_about_one_field_carries_its_path() {
    let response = invalid_field("spec.vm", "spec.vm is immutable; delete the vm").into_response();
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let body: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(response.into_body(), 64 * 1024)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(body["reason"], "Invalid");
    assert_eq!(body["details"]["field"], "spec.vm");
    // And the sentence still stands on its own — `details` is the machine
    // half, not a replacement for saying what is wrong.
    assert_eq!(body["message"], "spec.vm is immutable; delete the vm");
}

/// The three answers `check_owned` has, on the three shapes a field can
/// arrive in.
#[test]
fn the_same_value_passes_a_different_one_is_refused_and_the_path_is_named() {
    #[derive(serde::Serialize)]
    #[serde(rename_all = "camelCase")]
    struct Spec {
        vm: serde_json::Value,
        node_name: Option<String>,
        selector: std::collections::BTreeMap<String, String>,
    }
    #[derive(serde::Serialize)]
    struct Doc {
        spec: Spec,
    }
    let doc = |vcpus: u32, node: Option<&str>, zone: Option<&str>| Doc {
        spec: Spec {
            vm: serde_json::json!({ "vcpus": vcpus }),
            node_name: node.map(str::to_string),
            selector: zone
                .map(|z| [("zone".to_string(), z.to_string())].into())
                .unwrap_or_default(),
        },
    };
    let fields = &[
        Owned::immutable("spec.vm", "is immutable; delete the vm and create it again"),
        Owned::server_owned("spec.nodeName", "is set by the scheduler"),
        Owned::immutable("spec.selector", "is immutable"),
    ];

    let current = doc(2, Some("manacor"), Some("lab"));
    // Sent back as read: a round trip.
    check_owned(&current, &doc(2, Some("manacor"), Some("lab")), fields).expect("unchanged");

    // Each field, changed on its own, names itself and says the way out.
    let vm = check_owned(&current, &doc(4, Some("manacor"), Some("lab")), fields)
        .expect_err("spec.vm moved");
    assert_eq!(vm.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(vm.reason(), "Invalid");
    assert_eq!(
        vm.message(),
        "spec.vm is immutable; delete the vm and create it again"
    );

    let bound = check_owned(&current, &doc(2, Some("cala"), Some("lab")), fields)
        .expect_err("spec.nodeName moved");
    assert_eq!(bound.message(), "spec.nodeName is set by the scheduler");

    let selector = check_owned(&current, &doc(2, Some("manacor"), Some("dev")), fields)
        .expect_err("spec.selector moved");
    assert!(selector.message().starts_with("spec.selector "));

    // A field DROPPED from a PUT body is a field the client means to
    // clear, and it is refused as such. A PUT already had to read the
    // object to get its resourceVersion, so round-tripping it is the
    // normal flow and not a burden this adds.
    let cleared = check_owned(&current, &doc(2, None, Some("lab")), fields)
        .expect_err("a dropped server-owned field is a cleared one");
    assert_eq!(cleared.message(), "spec.nodeName is set by the scheduler");

    // And a field that is absent on BOTH sides is not a difference: null
    // and missing are one statement, whichever way a struct spells it.
    let unbound = doc(2, None, Some("lab"));
    check_owned(&unbound, &doc(2, None, Some("lab")), fields).expect("both say nothing");
}

/// A path into something that is not there is `null` and not a panic: a
/// table may name a field a body left out entirely.
#[test]
fn a_path_that_leads_nowhere_reads_as_nothing() {
    let doc = serde_json::json!({ "spec": { "vm": { "vcpus": 2 } } });
    assert_eq!(at(&doc, "spec.vm.vcpus"), &serde_json::json!(2));
    assert!(at(&doc, "spec.tenant").is_null());
    assert!(at(&doc, "spec.vm.vcpus.deeper").is_null());
    assert!(at(&doc, "status.phase").is_null());
}

/// The pair, exercised through the one function that maintains it.
///
/// `carry_generation` runs at the END of an update handler — after the
/// server has put its own fields back — so what these cases are really
/// asking is "did the CLIENT leave a different spec behind".
#[test]
fn a_write_counts_when_it_leaves_a_different_spec_and_not_otherwise() {
    #[derive(Clone, serde::Serialize, serde::Deserialize, PartialEq, Debug)]
    struct Spec {
        size: u32,
        node: Option<String>,
    }
    let stored = |generation: u64| {
        let mut o: Object<Spec, ()> = Object::new(
            API_VERSION,
            "Vm",
            "web-1",
            Spec {
                size: 2,
                node: Some("manacor".into()),
            },
        );
        o.metadata.generation = generation;
        o
    };

    // The same spec sent back: a round trip, not an intent.
    let current = stored(1);
    let mut next = current.clone();
    carry_generation(&current, &mut next).unwrap();
    assert_eq!(next.metadata.generation, 1, "a PUT that says nothing new");

    // A label is not a spec.
    let mut next = current.clone();
    next.metadata.labels.insert("tier".into(), "web".into());
    carry_generation(&current, &mut next).unwrap();
    assert_eq!(next.metadata.generation, 1, "metadata is not intent");

    // A different spec is.
    let mut next = current.clone();
    next.spec.size = 4;
    carry_generation(&current, &mut next).unwrap();
    assert_eq!(next.metadata.generation, 2);

    // The scheduler's binding travels in the spec and is the SERVER's
    // decision. It reaches the store through `mutate`, which never comes
    // through here — so a binding cannot tick the count, and the proof is
    // that the count follows the spec the handler hands over, whatever a
    // client tried to put in the field.
    let mut next = current.clone();
    next.spec.node = Some("cala".into());
    next.spec.node = current.spec.node.clone(); // what the handler does
    carry_generation(&current, &mut next).unwrap();
    assert_eq!(
        next.metadata.generation, 1,
        "a client that tried to re-point a bound VM changed nothing"
    );

    // An object written before the field existed reads as in sync, and
    // its first real change makes it 1.
    let old = stored(0);
    let mut next = old.clone();
    next.spec.size = 8;
    carry_generation(&old, &mut next).unwrap();
    assert_eq!(next.metadata.generation, 1);
}

/// The Node and Cluster PUT path counts too, and through the same
/// function: `apply_spec_update` is where those two land, and a cordon is
/// exactly the kind of intent the pair is for — the cluster reconciler
/// stops placing on this node, and until it has, the two numbers differ.
#[test]
fn a_spec_only_put_counts_the_same_way() {
    let mut current: crate::resources::Node = Object::new(
        API_VERSION,
        "Node",
        "manacor",
        crate::resources::NodeSpec {
            schedulable: true,
            ..Default::default()
        },
    );
    current.metadata.generation = 7;

    let body = |schedulable: bool| SpecUpdate {
        api_version: API_VERSION.to_string(),
        kind: "Node".to_string(),
        metadata: crate::object::Metadata {
            name: "manacor".to_string(),
            ..Default::default()
        },
        spec: crate::resources::NodeSpec {
            schedulable,
            ..Default::default()
        },
        status: None,
    };

    let unchanged = apply_spec_update(body(true), "manacor", current.clone()).unwrap();
    assert_eq!(unchanged.metadata.generation, 7, "the same cordon twice");
    let cordoned = apply_spec_update(body(false), "manacor", current).unwrap();
    assert_eq!(cordoned.metadata.generation, 8);
}

/// A store that loses the compare-and-swap the first `n` times it is
/// written to, then takes the write. The heartbeat, in a test: something
/// else touched the object between this handler's read and its write.
struct RacyStore {
    losses_left: std::cell::Cell<u32>,
    passes: std::cell::Cell<u32>,
}

impl RacyStore {
    fn losing(times: u32) -> Self {
        Self {
            losses_left: std::cell::Cell::new(times),
            passes: std::cell::Cell::new(0),
        }
    }

    /// One read-merge-write, exactly as a `patch_object!` arm does it.
    async fn read_merge_write(&self) -> std::result::Result<&'static str, ApiError> {
        self.passes.set(self.passes.get() + 1);
        let left = self.losses_left.get();
        if left > 0 {
            self.losses_left.set(left - 1);
            return Err(StoreError::Conflict("vms/web-1".into()).into());
        }
        Ok("written")
    }
}

/// A cordon that lands in the heartbeat's window is not the client's
/// problem when the client stated no condition.
///
/// `PATCH /nodes/x {"spec":{"schedulable":false}}` names no
/// `resourceVersion`, so the version in the store's compare-and-swap is
/// this server's own bookkeeping and losing to the agent's three-second
/// status write is this server's race to run again.
#[tokio::test]
async fn an_unconditional_patch_runs_the_race_again_and_a_conditional_one_is_told() {
    let unconditional = serde_json::json!({ "spec": { "schedulable": false } });
    let store = RacyStore::losing(1);
    assert_eq!(
        patch_with_retry(&unconditional, || store.read_merge_write())
            .await
            .expect("the second pass wins"),
        "written"
    );
    assert_eq!(store.passes.get(), 2, "read, merged and wrote twice");

    // The same patch WITH a version is a client that stated a condition,
    // and the condition failed. Retrying would merge its patch onto a
    // document it has never seen — which is the thing it asked not to
    // happen.
    let conditional = serde_json::json!({
        "metadata": { "resourceVersion": "41" },
        "spec": { "schedulable": false },
    });
    let store = RacyStore::losing(1);
    let told = patch_with_retry(&conditional, || store.read_merge_write())
        .await
        .expect_err("the first conflict is the answer");
    assert_eq!(told.status(), StatusCode::CONFLICT);
    assert_eq!(store.passes.get(), 1, "and it was tried once");

    // `null` removes a key in a merge patch, so a body that says it has
    // asked for no condition out loud.
    let store = RacyStore::losing(1);
    let dropped = serde_json::json!({ "metadata": { "resourceVersion": null } });
    assert!(
        patch_with_retry(&dropped, || store.read_merge_write())
            .await
            .is_ok(),
        "a version being REMOVED is not a version being stated"
    );
}

/// The budget is a budget: a client that keeps losing is told, rather
/// than held while a hot object stays hot.
#[tokio::test]
async fn a_patch_that_never_wins_is_given_the_conflict_after_three_passes() {
    let store = RacyStore::losing(u32::MAX);
    let told = patch_with_retry(&serde_json::json!({ "spec": {} }), || {
        store.read_merge_write()
    })
    .await
    .expect_err("still losing");
    assert_eq!(told.status(), StatusCode::CONFLICT);
    assert_eq!(store.passes.get(), PATCH_ATTEMPTS);
}

/// Three of the four refusals that answer 409 are facts about the object
/// and not races. Trying them again would be the same answer, three
/// times, one third as fast.
#[tokio::test]
async fn only_a_lost_compare_and_swap_is_tried_again() {
    for (e, reason) in [
        (
            StoreError::AlreadyExists("vms/web-1".into()),
            "AlreadyExists",
        ),
        (StoreError::Terminating("vms/web-1".into()), "Terminating"),
    ] {
        let passes = std::cell::Cell::new(0);
        let refusal: ApiError = e.into();
        assert_eq!(refusal.reason(), reason);
        let told = patch_with_retry(&serde_json::json!({}), || {
            passes.set(passes.get() + 1);
            let same: ApiError = match reason {
                "AlreadyExists" => StoreError::AlreadyExists("vms/web-1".into()).into(),
                _ => StoreError::Terminating("vms/web-1".into()).into(),
            };
            std::future::ready(Err::<(), _>(same))
        })
        .await
        .expect_err("refused");
        assert_eq!(told.reason(), reason);
        assert_eq!(passes.get(), 1, "{reason} is not a race");
    }
}

const DISCOVERY_ROWS: &[ApiResource] = &[
    ApiResource::new(
        "vms",
        "Vm",
        &["get", "list", "create", "update", "delete"],
        &["logs", "events"],
    ),
    ApiResource::new("clusters", "Cluster", &["get", "list", "update"], &[]),
];

/// The document a client reads to learn what an object looks like.
#[test]
fn the_schema_document_carries_a_shape_and_a_mutability_table() {
    const ROWS: &[ApiResource] = &[
        ApiResource::new("vms", "Vm", &["get", "update"], &[])
            .owning(&[
                Owned::immutable("spec.vm", "is immutable; delete the vm and create it again"),
                Owned::server_owned("spec.nodeName", "is set by the scheduler"),
            ])
            .shaped(schema_of::<crate::resources::Vm>),
        // A resource that publishes nothing is simply absent, rather than
        // present with an empty shape a client would have to test for.
        ApiResource::new("events", "Event", &["list"], &[]),
    ];

    let doc = schema_document(ROWS);
    assert_eq!(doc["apiVersion"], API_VERSION);
    assert_eq!(doc["kind"], "SchemaList");
    assert!(doc["schemas"]["Event"].is_null(), "no schema, no row");

    let vm = &doc["schemas"]["Vm"];
    assert_eq!(vm["resource"], "vms");
    // The envelope, not just the spec: a client renders `metadata` and
    // `status` too, and had to be told about them in prose before.
    let props = &vm["schema"]["properties"];
    for field in ["apiVersion", "kind", "metadata", "spec", "status"] {
        assert!(!props[field].is_null(), "the schema is missing {field}");
    }

    // The mutability table, in the shape a form can use: which field,
    // which kind, and the server's own sentence.
    let mutability = vm["mutability"].as_array().expect("a list");
    assert_eq!(mutability.len(), 2);
    assert_eq!(mutability[0]["field"], "spec.vm");
    assert_eq!(mutability[0]["mutability"], "immutable");
    assert_eq!(
        mutability[0]["because"], "spec.vm is immutable; delete the vm and create it again",
        "the same sentence the 422 would have carried"
    );
    assert_eq!(mutability[1]["mutability"], "serverOwned");
    // Nothing is coming for either of these two, and a row that says
    // nothing carries no key rather than a null a client has to test for.
    assert!(mutability[0].get("note").is_none());
    assert!(mutability[1].get("note").is_none());

    // And the check that makes the table worth publishing.
    assert_tables_match_schemas(ROWS);
}

/// A row may also say what is KNOWN to be coming, and that is a second
/// key rather than a longer refusal: the 422 is about today, and a form
/// greying a field out wants both sentences apart.
#[test]
fn a_row_can_carry_what_is_coming_without_changing_the_refusal() {
    const ROWS: &[ApiResource] = &[ApiResource::new("vms", "Vm", &["get", "update"], &[])
        .owning(&[
            Owned::immutable("spec.vm", "is immutable; delete the vm and create it again")
                .noting("volumes[] becomes mutable from the second entry in storage B"),
        ])
        .shaped(schema_of::<crate::resources::Vm>)];
    let row = &schema_document(ROWS)["schemas"]["Vm"]["mutability"][0];
    assert_eq!(
        row["note"],
        "volumes[] becomes mutable from the second entry in storage B"
    );
    assert_eq!(
        row["because"], "spec.vm is immutable; delete the vm and create it again",
        "the refusal is unchanged by the note beside it"
    );

    // And the note is not what a client is refused with: `check_owned`
    // has never read it and must not start.
    let vm = |vcpus| serde_json::json!({"spec": {"vm": {"vcpus": vcpus}}});
    let err = check_owned(&vm(1), &vm(2), ROWS[0].owned_fields()).expect_err("refused");
    assert_eq!(
        err.message(),
        "spec.vm is immutable; delete the vm and create it again"
    );
}

/// A third word, because the second one became a lie.
///
/// `spec.vm` is immutable in everything except `volumes[]` from its
/// second entry on, and a form that greyed the whole document out on the
/// strength of "immutable" would be greying out the one part a tenant may
/// use. So the row says `structural`, and — the part that matters more —
/// it is enforced HERE, through the same loop every other row goes
/// through, rather than by a check beside the table that a third update
/// handler forgets to call.
#[test]
fn a_structural_row_is_published_as_one_and_enforced_through_the_same_loop() {
    /// Everything but the last element of `list` is frozen — a toy stand
    /// in for `vm_shape_unchanged`, so this test is about the MECHANISM.
    fn all_but_the_last(value: &serde_json::Value) -> serde_json::Value {
        let Some(items) = value.get("list").and_then(serde_json::Value::as_array) else {
            return value.clone();
        };
        let mut out = value.clone();
        out["list"] = serde_json::Value::Array(
            items
                .iter()
                .take(items.len().saturating_sub(1))
                .cloned()
                .collect(),
        );
        out
    }

    fn only_the_last_moves(current: &serde_json::Value, next: &serde_json::Value) -> bool {
        all_but_the_last(current) == all_but_the_last(next)
    }
    const ROWS: &[ApiResource] = &[ApiResource::new("vms", "Vm", &["get", "update"], &[])
        .owning(&[Owned::structural(
            "spec.vm",
            "is immutable except for its last list entry",
            only_the_last_moves,
        )])
        .shaped(schema_of::<crate::resources::Vm>)];

    let row = &schema_document(ROWS)["schemas"]["Vm"]["mutability"][0];
    assert_eq!(row["mutability"], "structural");
    assert_eq!(
        row["because"], "spec.vm is immutable except for its last list entry",
        "and the sentence says WHICH part moves"
    );

    let vm = |list: serde_json::Value| serde_json::json!({"spec": {"vm": {"list": list}}});
    let fields = ROWS[0].owned_fields();
    // The free part moves.
    check_owned(
        &vm(serde_json::json!([1, 2])),
        &vm(serde_json::json!([1, 9])),
        fields,
    )
    .expect("the last entry");
    // The frozen part does not.
    check_owned(
        &vm(serde_json::json!([1, 2])),
        &vm(serde_json::json!([9, 2])),
        fields,
    )
    .expect_err("the first entry");
    // And a value the projection cannot read compares whole, exactly as
    // an ordinary immutable row would.
    let bare = |n| serde_json::json!({"spec": {"vm": {"vcpus": n}}});
    check_owned(&bare(1), &bare(1), fields).expect("a round trip");
    check_owned(&bare(1), &bare(2), fields).expect_err("still immutable");
}

/// The walker has to be able to say no, or the assertion above is a
/// tautology.
#[test]
fn a_field_that_does_not_exist_is_not_found() {
    let schema = schema_of::<crate::resources::Vm>();
    assert!(schema_has_field(&schema, "spec.runStrategy"));
    assert!(schema_has_field(&schema, "metadata.generation"));
    assert!(schema_has_field(&schema, "status.observedGeneration"));

    for absent in [
        "spec.sizeGib",
        "spec.runStrategyy",
        "spec",
        "metadata.nope",
        "nope.nope",
    ] {
        if absent == "spec" {
            assert!(schema_has_field(&schema, absent), "spec itself is a field");
            continue;
        }
        assert!(
            !schema_has_field(&schema, absent),
            "{absent} is not a field"
        );
    }
}

/// The document says what the ROUTER offers, and whose the objects are is
/// asked of `auth::is_tenant_scoped` rather than written down a second
/// time — two lists of tenant-scoped resources is one list too many.
#[test]
fn a_discovery_row_names_the_verbs_and_asks_auth_whose_the_objects_are() {
    let doc = discovery_document(
        Tier::Cloud,
        "mtls,oidc",
        DISCOVERY_ROWS,
        &[features::DRY_RUN],
    );
    assert_eq!(doc["apiVersion"], API_VERSION);
    assert_eq!(doc["kind"], "APIResourceList");
    assert_eq!(doc["tier"], "cloud");
    assert_eq!(doc["auth"], "mtls,oidc");

    let vms = &doc["resources"][0];
    assert_eq!(vms["name"], "vms");
    assert_eq!(vms["kind"], "Vm");
    assert_eq!(vms["verbs"][2], "create");
    assert_eq!(vms["tenantScoped"], true);
    assert_eq!(vms["subresources"][0], "logs");

    let clusters = &doc["resources"][1];
    assert_eq!(clusters["tenantScoped"], false);
    assert!(
        clusters.get("subresources").is_none(),
        "an empty list is left out rather than sent as []"
    );
    assert_eq!(
        discovery_document(Tier::Cluster, "none", &[], &[])["tier"],
        "cluster"
    );
}

/// A client has to be able to ask what is here BEFORE it knows how to
/// identify itself. `classify` finds no resource segment in the
/// group-version path, so the guard hands it straight on — the same pass
/// /healthz gets, and for a related reason.
///
/// `/schemas` is beside it now, which is what the comment over
/// `SCHEMAS_PATH` always said and what the code did not do: it answered
/// 401, so a build-time generator needed a credential for a document that
/// holds nothing but field names. The shape of an object is not a secret.
#[tokio::test]
async fn the_discovery_route_answers_a_caller_that_has_no_credential() {
    use tower::ServiceExt;

    assert!(classify("GET", DISCOVERY_PATH).is_none());
    assert!(classify("GET", "/apis/meister.io/v1/").is_none());
    assert!(classify("GET", SCHEMAS_PATH).is_none());
    // The document, and nothing that merely starts like it: a path under
    // it is not served at all, and one that only shares the prefix is an
    // ordinary resource with an ordinary door.
    assert!(classify("GET", "/apis/meister.io/v1/schemas/Vm").is_some());
    assert!(classify("GET", "/apis/meister.io/v1/schematics").is_some());
    // And `whoami` next door stays gated: the answer there is the
    // directory's word about a person, not the shape of an object.
    assert!(classify("GET", WHOAMI_PATH).is_some());

    let router = guard(
        discovery(
            Tier::Cloud,
            Arc::new(AuthChain::named(vec![Box::new(Never)], vec!["mtls"])),
            DISCOVERY_ROWS,
            &[],
        ),
        AuthState {
            chain: Arc::new(AuthChain::new(vec![Box::new(Never)])),
            directory: None,
            provision_oidc_users: false,
            own_peer: None,
            tickets: None,
        },
    );
    for path in [DISCOVERY_PATH, SCHEMAS_PATH] {
        let response = router
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .uri(path)
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .expect("the router answers");
        assert_eq!(response.status(), StatusCode::OK, "{path}");
    }
}

/// What the document says under `auth` is what is STANDING, not what the
/// config named: the default chain names three links and builds none of
/// them without a CA or a token file, and telling a client otherwise
/// would send it looking for a certificate nothing would check.
#[test]
fn a_chain_names_the_links_it_actually_built() {
    assert_eq!(
        build_chain(&cfg(""), None, None, Tier::Cloud, false)
            .unwrap()
            .describe(),
        "none"
    );

    // A pid is not a unique name: it comes back round, and a crashed run
    // leaves its directory behind for whoever inherits the number. `tempfile`
    // is unique, and it cleans up on a panic as well as on a pass.
    let dir = tempfile::tempdir().expect("a directory of our own");
    let token = dir.path().join("token");
    std::fs::write(&token, "s3cret").unwrap();
    let chain = build_chain(
        &cfg(&format!(
            "chain = [\"bearer\"]\nbearer_token_file = \"{}\"",
            token.display()
        )),
        None,
        None,
        Tier::Cloud,
        false,
    )
    .unwrap();
    assert_eq!(chain.describe(), "bearer");
}

/// D11: a link that is configured and cannot authenticate anybody yet says
/// so, and stops saying so the moment it can.
///
/// The lab's cloud offered `auth: "mtls,oidc"` for hours while the provider
/// was unreachable and no signing key had ever been fetched — every token
/// would have been refused, and the discovery document promised otherwise.
/// A client that reads it gets a promise that does not hold and finds out at
/// the far end.
///
/// `:degraded` rather than dropping the word: "this deployment has no
/// identity provider" and "the identity provider is unreachable" are
/// different sentences for different people, and one of them is an operator
/// who has to go and look at Keycloak.
#[test]
fn a_link_that_cannot_authenticate_anybody_yet_says_degraded() {
    /// A link whose readiness is not its construction — the shape the oidc
    /// authenticator has, with the fetch replaced by a switch.
    struct Loading(std::sync::atomic::AtomicBool);
    impl crate::auth::Authenticator for Loading {
        fn authenticate(&self, _: &AuthRequest) -> anyhow::Result<Option<Identity>> {
            Ok(None)
        }
        fn ready(&self) -> bool {
            self.0.load(std::sync::atomic::Ordering::Relaxed)
        }
    }

    let loading = Arc::new(Loading(std::sync::atomic::AtomicBool::new(false)));
    struct Shared(Arc<Loading>);
    impl crate::auth::Authenticator for Shared {
        fn authenticate(&self, req: &AuthRequest) -> anyhow::Result<Option<Identity>> {
            self.0.authenticate(req)
        }
        fn ready(&self) -> bool {
            self.0.ready()
        }
    }

    let chain = AuthChain::named(
        vec![Box::new(Never), Box::new(Shared(loading.clone()))],
        vec!["mtls", "oidc"],
    );
    assert_eq!(
        chain.describe(),
        "mtls,oidc:degraded",
        "configured is not ready, and the document has to tell them apart"
    );

    // The keys land. Nothing was rebuilt, and the answer changes — which is
    // the half a snapshot at start-up would have got wrong in the other
    // direction: at boot nothing has loaded, so a cached string would read
    // `degraded` for ever.
    loading.0.store(true, std::sync::atomic::Ordering::Relaxed);
    assert_eq!(chain.describe(), "mtls,oidc");

    // And a link whose readiness IS its construction never says it: an mTLS
    // authenticator holds the CA it was given.
    assert_eq!(
        AuthChain::named(vec![Box::new(Never)], vec!["mtls"]).describe(),
        "mtls"
    );
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
    let chain = build_chain(&cfg(""), None, None, Tier::Cloud, false).unwrap();
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
    let err = build_chain(&cfg(r#"chain = ["mtls"]"#), None, None, Tier::Cloud, false).unwrap_err();
    assert!(err.to_string().contains("client_ca"), "{err}");
    let err = build_chain(
        &cfg(r#"chain = ["bearer"]"#),
        None,
        None,
        Tier::Cloud,
        false,
    )
    .unwrap_err();
    assert!(err.to_string().contains("bearer_token_file"), "{err}");
    let err =
        build_chain(&cfg(r#"chain = ["magic"]"#), None, None, Tier::Cloud, false).unwrap_err();
    assert!(err.to_string().contains("magic"), "{err}");
    let err = build_chain(&cfg(r#"chain = ["oidc"]"#), None, None, Tier::Cloud, false).unwrap_err();
    assert!(err.to_string().contains("auth.oidc"), "{err}");
}

/// The configuration two separate briefs handed a client author, and the
/// one that cost both of them a day: `chain = ["bearer"]` locks the
/// control plane out of itself. The chain is per CONTROLLER, the session
/// ports authenticate by certificate only, and nothing dials one with a
/// token — so the cloud gets no clusters, the cluster gets no nodes, and
/// every VM stays Pending while the REST edge answers 200 to everything.
///
/// A startup error, because there is nothing to degrade to. The one
/// exception is a process listening on no session port: it has no peers
/// to admit, so nothing is locked out.
#[test]
fn a_chain_without_mtls_is_a_startup_error_where_there_are_peers() {
    // As above — and this one never cleaned up at all.
    let dir = tempfile::tempdir().expect("a directory of our own");
    let token = dir.path().join("token");
    std::fs::write(&token, "s3cret").unwrap();
    let bearer_only = cfg(&format!(
        "chain = [\"bearer\"]\nbearer_token_file = \"{}\"",
        token.display()
    ));

    let err = build_chain(&bearer_only, None, None, Tier::Cloud, true).unwrap_err();
    assert!(
        err.to_string().contains("certificate only"),
        "and it says why: {err}"
    );
    assert!(
        err.to_string().contains("mtls"),
        "and what to write instead: {err}"
    );

    // No session port, no peers, nothing locked out: a warning and a
    // chain that stands.
    let chain = build_chain(&bearer_only, None, None, Tier::Cloud, false)
        .expect("a rest-only endpoint may be bearer-only");
    assert_eq!(chain.describe(), "bearer");

    // And a DEFAULTED chain is never this error: it names mtls already,
    // and it drops the link when there is no CA — which is the anonymous
    // lab that has always worked.
    assert!(build_chain(&cfg(""), None, None, Tier::Cloud, true).is_ok());
    let _ = std::fs::remove_file(&token);
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
    let err = build_chain(&oidc_cfg(""), None, None, Tier::Cluster, false).unwrap_err();
    assert!(err.to_string().contains("user directory"), "{err}");
    // And the same table at the cloud is simply a chain of one.
    let chain = build_chain(&oidc_cfg(""), None, None, Tier::Cloud, false).unwrap();
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
        false,
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
        false,
    )
    .unwrap_err();
    assert!(format!("{err:#}").contains("asymmetric"), "{err:#}");

    assert!(
        build_chain(
            &oidc_cfg("allowed_algorithms = [\"RS256\", \"ES384\"]"),
            None,
            None,
            Tier::Cloud,
            false
        )
        .is_ok()
    );
}

/// A token with no audience check is a token issued for some other
/// service that this one accepts. Refused as a configuration.
#[tokio::test]
async fn an_empty_audience_is_a_configuration_error_and_not_a_permissive_setting() {
    let err = build_chain(&oidc_cfg("audience = []"), None, None, Tier::Cloud, false).unwrap_err();
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
        false,
    )
    .unwrap_err();
    assert!(err.to_string().contains("tenant_claim"), "{err}");

    assert!(
        build_chain(
            &oidc_cfg("provision_unknown_users = true\ntenant_claim = \"groups\""),
            None,
            None,
            Tier::Cloud,
            false
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
        },
        None
    ));
}

/// A tier that keeps no user directory authorizes no person at all.
///
/// This used to answer with the role the CERTIFICATE claimed, and that is
/// precisely what made the group in a certificate a permission: a demoted
/// admin went on being an admin here for the rest of the credential's
/// life. One directory, and it is the cloud's.
#[tokio::test]
async fn a_tier_without_a_directory_refuses_a_person_and_lets_the_machines_past() {
    let st = AuthState::anonymous();

    for groups in [
        vec![crate::auth::GROUP_ADMINS.to_string()],
        vec![crate::auth::GROUP_MEMBERS.to_string()],
        vec![],
    ] {
        let person = Identity::new("alice", groups);
        let refused = grant_of(&st, &person)
            .await
            .expect_err("no directory to look her up in");
        assert_eq!(refused.status(), StatusCode::FORBIDDEN);
    }

    // Break glass and the machines never had a directory entry and never
    // will; they returned before the lookup and are unaffected.
    for machine in [
        "system:masters",
        "system:cluster:cluster-1",
        "system:node:manacor",
    ] {
        let who = Identity::new(machine, vec![]);
        let (role, tenant) = grant_of(&st, &who).await.expect("no lookup for a machine");
        assert!(role.is_none() && tenant.is_none());
    }
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
    let next = apply_spec_update(put(None, "42"), "manacor", current.clone()).expect("accepted");
    assert!(!next.spec.schedulable);
    assert_eq!(next.metadata.uid, "the-uid");
    assert_eq!(next.metadata.finalizers, vec!["keep-me".to_string()]);
    assert_eq!(next.metadata.resource_version, "42");
    assert!(next.status.ready, "status is untouched");
    assert_eq!(next.status.vms, 3);

    // Status echoed back unchanged: a round trip, not a write.
    let echoed = serde_json::to_value(&current.status).unwrap();
    assert!(apply_spec_update(put(Some(echoed), "41"), "manacor", current.clone()).is_ok());

    // Echoed back with the heartbeat a GET joins in from the lease, which is
    // never the instant etcd still holds under that key: still a round trip.
    // The night D-C7's lease shipped, this was a 422 on every `node label`
    // and every cordon (S1, S11), because the join moved a field the store
    // does not.
    let mut moved = serde_json::to_value(&current.status).unwrap();
    moved["lastHeartbeat"] = serde_json::json!("2027-01-15T08:00:00Z");
    assert!(apply_spec_update(put(Some(moved), "41"), "manacor", current.clone()).is_ok());

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

/// RFC 7386, the four rules that are the whole format. The array one is
/// the sharp edge: a patch that changes one element sends the list.
#[test]
fn a_merge_patch_recurses_into_objects_and_replaces_everything_else() {
    let mut doc = serde_json::json!({
        "spec": {
            "schedulable": true,
            "labels": { "zone": "a", "disk": "nvme" },
            "cidrs": ["10.0.0.0/24", "10.0.1.0/24"],
        },
        "status": { "ready": true },
    });
    merge_patch(
        &mut doc,
        &serde_json::json!({
            "spec": {
                "schedulable": false,
                "labels": { "gpu": "a100", "zone": null },
                "cidrs": ["10.9.0.0/24"],
            },
        }),
    );
    // Objects merge, key by key, as deep as the patch goes.
    assert_eq!(doc["spec"]["labels"]["disk"], "nvme");
    assert_eq!(doc["spec"]["labels"]["gpu"], "a100");
    // null removes, and removes only what it names.
    assert!(doc["spec"]["labels"].get("zone").is_none());
    // A scalar replaces, and an array replaces WHOLE.
    assert_eq!(doc["spec"]["schedulable"], false);
    assert_eq!(doc["spec"]["cidrs"], serde_json::json!(["10.9.0.0/24"]));
    // What the patch said nothing about is untouched.
    assert_eq!(doc["status"]["ready"], true);

    // A patch that is not an object replaces outright, at any depth.
    let mut scalar = serde_json::json!({ "a": { "b": 1 } });
    merge_patch(&mut scalar, &serde_json::json!({ "a": 7 }));
    assert_eq!(scalar["a"], 7);
    // ... and a non-object target that a patch descends into becomes one.
    let mut leaf = serde_json::json!({ "a": 7 });
    merge_patch(&mut leaf, &serde_json::json!({ "a": { "b": 1 } }));
    assert_eq!(leaf["a"]["b"], 1);
}

/// A PATCH is a PUT with a server-filled body: what comes out of here is
/// what the update handler would have been sent, resourceVersion and all.
#[test]
fn a_patch_becomes_the_body_the_put_would_have_taken() {
    use crate::resources::{Node, NodeSpec, NodeStatus};

    let mut current = Node::declare(
        "manacor",
        NodeSpec {
            accepts: Vec::new(),
            schedulable: true,
            drain: false,
            labels: [("zone".to_string(), "a".to_string())]
                .into_iter()
                .collect(),
        },
    );
    current.metadata.resource_version = "41".into();
    current.status = NodeStatus {
        ready: true,
        vms: 3,
        ..NodeStatus::default()
    };

    // The cordon, as `meister node cordon` sends it: three lines, no
    // apiVersion, no kind, no resourceVersion.
    let body: SpecUpdate<NodeSpec> = apply_merge_patch(
        &current,
        &serde_json::json!({ "spec": { "schedulable": false } }),
    )
    .expect("accepted");
    assert!(!body.spec.schedulable);
    assert_eq!(body.kind, "Node");
    // What the patch did not mention survived the round trip.
    assert_eq!(body.spec.labels["zone"], "a");
    // Not named: the compare-and-swap is against the version just read,
    // so a writer between the read and the write still loses.
    assert_eq!(body.metadata.resource_version, "41");
    // The echoed status is the one held, which is what makes it a round
    // trip rather than a write. `apply_spec_update` says so.
    let next = apply_spec_update(body, "manacor", current.clone()).expect("accepted");
    assert!(!next.spec.schedulable);
    assert!(next.status.ready, "status is untouched");

    // Named: the client's own compare-and-swap, against exactly that one.
    let body: SpecUpdate<NodeSpec> = apply_merge_patch(
        &current,
        &serde_json::json!({ "metadata": { "resourceVersion": "40" } }),
    )
    .expect("accepted");
    assert_eq!(body.metadata.resource_version, "40");
}

/// The label round trip the CLI's `node label` is: a key is added beside
/// the ones already there, and `null` takes one away and leaves the rest.
#[test]
fn patching_one_label_leaves_the_others_where_they_were() {
    use crate::resources::{Node, NodeSpec};

    let current = Node::declare(
        "manacor",
        NodeSpec {
            accepts: Vec::new(),
            schedulable: true,
            drain: false,
            labels: [("zone".to_string(), "a".to_string())]
                .into_iter()
                .collect(),
        },
    );
    let body: SpecUpdate<NodeSpec> = apply_merge_patch(
        &current,
        &serde_json::json!({ "spec": { "labels": { "gpu": "a100" } } }),
    )
    .unwrap();
    assert_eq!(body.spec.labels["zone"], "a");
    assert_eq!(body.spec.labels["gpu"], "a100");

    let mut with_gpu = current.clone();
    with_gpu.spec.labels = body.spec.labels;
    let body: SpecUpdate<NodeSpec> = apply_merge_patch(
        &with_gpu,
        &serde_json::json!({ "spec": { "labels": { "gpu": null } } }),
    )
    .unwrap();
    assert!(!body.spec.labels.contains_key("gpu"));
    assert_eq!(body.spec.labels["zone"], "a", "and the rest stayed");
}

/// The four refusals, and the one that is a decision rather than a
/// spelling: the type check runs AFTER the merge, so a patch that puts a
/// string where a bool belongs is a 422 about the object and not a 500
/// about us.
#[test]
fn a_patch_is_refused_for_the_reason_it_is_wrong() {
    use crate::resources::{Node, NodeSpec};

    let current = Node::declare("manacor", NodeSpec::default());
    let refused = |patch: serde_json::Value| {
        apply_merge_patch::<Node, SpecUpdate<NodeSpec>>(&current, &patch).expect_err("refused")
    };

    let status = refused(serde_json::json!({ "status": { "ready": true } }));
    assert_eq!(status.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(
        status.message.contains("belongs to the controller"),
        "{status:?}"
    );

    let kind = refused(serde_json::json!({ "kind": "Vm" }));
    assert!(kind.message.contains("kind Node"), "{kind:?}");
    let version = refused(serde_json::json!({ "apiVersion": "meister.io/v2" }));
    assert!(version.message.contains("meister.io/v1"), "{version:?}");

    let typed = refused(serde_json::json!({ "spec": { "schedulable": "yes" } }));
    assert_eq!(
        typed.status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "a mistyped field is the client's problem, not a 500"
    );
    assert!(typed.message.contains("no longer a Node"), "{typed:?}");

    let not_an_object = refused(serde_json::json!([{ "op": "replace" }]));
    assert!(
        not_an_object.message.contains("RFC 7386"),
        "{not_an_object:?}"
    );

    // And the envelope, named and right, is simply allowed.
    assert!(
        apply_merge_patch::<Node, SpecUpdate<NodeSpec>>(
            &current,
            &serde_json::json!({ "apiVersion": API_VERSION, "kind": "Node" })
        )
        .is_ok()
    );
}

/// Equality, comma-separated, and every pair has to hold.
#[test]
fn a_selector_is_equality_and_all_of_it() {
    let labels: std::collections::BTreeMap<String, String> = [("zone", "lab"), ("disk", "nvme")]
        .into_iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    let selects = |raw: &str| Selector::parse(Some(raw)).unwrap().selects(&labels);

    assert!(selects("zone=lab"));
    assert!(selects("zone=lab,disk=nvme"));
    assert!(selects(" zone = lab , disk = nvme "), "spaces are trimmed");
    assert!(!selects("zone=lab,disk=ssd"), "every pair has to hold");
    assert!(!selects("rack=b3"), "a key nothing carries selects nothing");
    // A value may be empty, and then it has to be empty on the object.
    assert!(!selects("zone="));

    // No selector selects everything, which is what a listing has always
    // done.
    assert!(Selector::parse(None).unwrap().selects(&labels));
    assert!(Selector::parse(Some("")).unwrap().selects(&labels));
    assert!(Selector::parse(Some("  ")).unwrap().is_empty());
    assert!(
        Selector::default().selects(&Default::default()),
        "and it selects an object with no labels at all"
    );
    // But a real selector does not select an unlabelled object.
    assert!(
        !Selector::parse(Some("zone=lab"))
            .unwrap()
            .selects(&Default::default())
    );
}

/// A term that is not one is a 422 that says what it should have been,
/// rather than a silent empty list.
#[test]
fn a_term_that_is_not_a_pair_is_refused_with_the_shape_it_should_have_had() {
    let e = Selector::parse(Some("zone")).unwrap_err();
    assert_eq!(e.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(e.message.contains("key=value"), "{e:?}");
    assert!(Selector::parse(Some("=lab")).is_err(), "an empty key");
    // A trailing comma is somebody's shell, not a mistake worth a 422.
    assert!(Selector::parse(Some("zone=lab,")).is_ok());
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

/// The route that saves every client the probe run. Before it, a console
/// asked `GET /tenants` and `GET /clusters` at startup for no other
/// reason than to find out what it was allowed to see.
///
/// Three shapes, and each says something different: what the directory
/// established (cloud), what a tier without a directory can honestly say
/// (cluster: name, groups, tier — and no role), and what a server with no
/// chain at all believes (anonymous).
#[tokio::test]
async fn whoami_answers_with_the_directory_and_not_with_the_credential() {
    use axum::body::Body;
    use axum::http::Request as HttpRequest;

    let ask = async |tier: Tier, who: Option<(Identity, Option<Role>, Option<&str>)>| {
        let mut req = HttpRequest::builder()
            .method("GET")
            .uri(WHOAMI_PATH)
            .body(Body::empty())
            .unwrap();
        if let Some((identity, role, tenant)) = who {
            // What the guard puts on the request once the chain and the
            // directory have both spoken.
            req.extensions_mut().insert(identity.clone());
            req.extensions_mut().insert(CallerRole(role));
            req.extensions_mut()
                .insert(CallerTenant(tenant.map(str::to_string)));
        }
        let response = whoami(tier).oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = http_body_util::BodyExt::collect(response.into_body())
            .await
            .unwrap()
            .to_bytes();
        serde_json::from_slice::<serde_json::Value>(&bytes).unwrap()
    };

    let alice = Identity::new("alice", vec![crate::auth::GROUP_MEMBERS.to_string()]);
    let cloud = ask(
        Tier::Cloud,
        Some((alice.clone(), Some(Role::Member), Some("acme"))),
    )
    .await;
    assert_eq!(cloud["kind"], "Whoami");
    assert_eq!(cloud["name"], "alice");
    assert_eq!(cloud["tier"], "cloud");
    assert_eq!(cloud["role"], "member", "what the DIRECTORY says");
    assert_eq!(cloud["tenant"], "acme");
    assert_eq!(cloud["groups"][0], crate::auth::GROUP_MEMBERS);

    // No directory here, so no role and no tenant — absent rather than
    // null, because "not decided at this tier" is not "no permissions".
    let cluster = ask(Tier::Cluster, Some((alice, None, None))).await;
    assert_eq!(cluster["tier"], "cluster");
    assert!(cluster.get("role").is_none(), "{cluster}");
    assert!(cluster.get("tenant").is_none(), "{cluster}");
    assert_eq!(cluster["name"], "alice");

    // And the mode this stack ran in for four milestones.
    let nobody = ask(Tier::Cloud, None).await;
    assert_eq!(nobody["name"], "anonymous");
    assert_eq!(nobody["groups"], serde_json::json!([]));
    assert!(nobody.get("role").is_none());
}

/// A tier that mints no tickets is a tier where `?ticket=` is not a
/// credential at all, rather than one where it is a weaker one.
///
/// The half of the ticket story that can still be told in process. The other
/// half — a ticket minted, spent once, and refused at the second replica —
/// moved to `tests/tickets_etcd.rs` when the tickets moved into etcd: a
/// redeem is a round trip to the store now, because that is the only place
/// "once" is true for more than one replica (Fremdsicht 6).
#[tokio::test]
async fn a_ticket_parameter_is_no_credential_at_a_tier_that_mints_none() {
    use axum::body::Body;
    use axum::http::Request as HttpRequest;

    let console = "/apis/meister.io/v1/vms/web-1/console";
    let unticketed = guard(
        Router::new().route(
            "/apis/meister.io/v1/vms/{name}/console",
            get(|| async { "console" }),
        ),
        AuthState {
            chain: Arc::new(AuthChain::new(vec![Box::new(Never)])),
            directory: None,
            provision_oidc_users: false,
            own_peer: None,
            tickets: None,
        },
    );
    let response = unticketed
        .oneshot(
            HttpRequest::builder()
                .uri(format!("{console}?ticket=whatever-this-is"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

/// One body behind one verb.
///
/// There were four shapes before this: the object itself, `{"deleted": name}`,
/// the same with a resource's extra key, and `{"releasing": …, "attachedTo":
/// …}`. A client had to know per resource which one a DELETE was about to
/// hand it — the tofu provider wrote the workaround down and this is the
/// thing it worked around.
///
/// It is the same envelope every refusal wears, so the one rule a client
/// learns — read `kind` — holds for the whole verb. `202` is the only
/// difference that means anything: the object is marked and somebody else has
/// a teardown to run, so it still answers a GET.
#[test]
fn a_delete_answers_one_shape_whatever_the_resource() {
    let gone = removed("Tenant", "acme", Removal::Gone).body();
    assert_eq!(gone["apiVersion"], API_VERSION);
    assert_eq!(gone["kind"], KIND_STATUS);
    assert_eq!(gone["status"], "Success");
    assert_eq!(gone["code"], 200);
    assert_eq!(gone["reason"], "Deleted");
    assert_eq!(gone["message"], "Tenant acme deleted");
    assert_eq!(gone["details"]["kind"], "Tenant");
    assert_eq!(gone["details"]["name"], "acme");

    let going = removed("Vm", "web-1", Removal::Going).body();
    assert_eq!(going["code"], 202);
    assert_eq!(going["reason"], "Deleting");
    assert_eq!(going["message"], "Vm web-1 is being deleted");

    // What a resource has to add of its own goes under `details`, which is
    // what keeps the top level the same for every kind.
    let held = removed("Volume", "data-1", Removal::Going)
        .saying("volume data-1 is attached to vm web-1; its data stays until that vm lets go")
        .detail("attachedTo", serde_json::json!("web-1"))
        .body();
    assert_eq!(held["kind"], KIND_STATUS, "still the same envelope");
    assert_eq!(held["details"]["attachedTo"], "web-1");
    assert_eq!(held["details"]["name"], "data-1");
    assert!(held["message"].as_str().unwrap().contains("web-1"));
}

/// Which kinds a declarative client may wait on, in a form it can read.
///
/// "Write, then wait for `observedGeneration >= generation`" needs to know
/// which kinds carry the field, and there was no way to ask: it arrived on
/// four kinds and the reference said so in prose, in a document that is
/// behind the server by construction (tofu). The list is derived from the
/// same schema `/schemas` publishes, so it cannot drift from it.
#[test]
fn the_discovery_names_the_kinds_that_carry_observed_generation() {
    let doc = discovery_document(Tier::Cloud, "none", PROBE_RESOURCES, &[]);
    let named: Vec<&str> = doc["observedGeneration"]
        .as_array()
        .expect("a list, not prose")
        .iter()
        .map(|k| k.as_str().expect("a kind name"))
        .collect();
    assert_eq!(named, ["Vm"], "{doc}");

    // And it is the schema's own answer, not a second list to keep in step.
    for kind in named {
        let row = PROBE_RESOURCES
            .iter()
            .find(|r| r.kind == kind)
            .expect("a row of the table it was built from");
        let build = row.schema.expect("a row without a schema cannot be in it");
        assert!(schema_has_field(&build(), "status.observedGeneration"));
    }
}

/// Two rows: one kind whose status carries the field and one whose does not.
/// Written out here rather than borrowed from a tier, so the test states the
/// rule instead of restating whichever kinds happen to have it today.
const PROBE_RESOURCES: &[ApiResource] = &[
    ApiResource::new("vms", "Vm", &["get"], &[]).shaped(schema_of::<crate::resources::Vm>),
    ApiResource::new("events", "Event", &["list"], &[])
        .shaped(schema_of::<crate::resources::Event>),
];

/// The five source directories this construction site owns.
///
/// Rooted at the workspace and not at this crate: the two controllers, the
/// CLI and the wire they speak are as much this site's as `controller-api`
/// is, and a rule that only held for one of them would be a rule the next
/// brief breaks in the other four.
#[cfg(test)]
const SITE: [&str; 5] = [
    "components/cloud-controller/src",
    "components/cluster-controller/src",
    "components/cli/src",
    "shared/controller-api/src",
    "shared/proto/src",
];

/// Nothing on this construction site writes where somebody else writes, or
/// binds a port somebody else could be holding.
///
/// A run on `main` failed once while another stack was up on this machine —
/// one failure out of a hundred and twenty-nine, green on the second run —
/// and a flake nobody can reproduce is a flake everybody learns to re-run
/// past. Two rules, kept by reading the sources rather than by everybody
/// remembering: a directory a test writes in comes from `tempfile`, which is
/// unique and survives a panic; a listener asks for port `0` and reads back
/// what it was given.
///
/// Scoped to the controller half of the tree by name. The agent half has the
/// same rule and its own copy of this question to answer — the numbers above
/// are its test binary, not this one.
#[test]
fn no_source_of_this_construction_site_names_a_fixed_temp_path_or_port() {
    // Split so that this test's own source does not match itself.
    let temp_dir = concat!("env::", "temp_dir(");
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("the workspace root is two above this crate")
        .to_path_buf();

    let mut checked = 0usize;
    let mut sins: Vec<String> = Vec::new();
    for dir in SITE {
        let base = root.join(dir);
        assert!(
            base.is_dir(),
            "{} is not where this test looks",
            base.display()
        );
        for file in rust_files(&base) {
            let source = std::fs::read_to_string(&file).expect("a source file");
            checked += 1;
            for (i, line) in source.lines().enumerate() {
                let at = format!("{dir}/{}:{}", file.file_name().unwrap().display(), i + 1);
                if line.contains(temp_dir) {
                    sins.push(format!("{at}: a temp path of its own instead of tempfile"));
                }
                if let Some(addr) = bound_address(line)
                    && !addr.ends_with(":0")
                {
                    sins.push(format!("{at}: binds {addr:?} instead of port 0"));
                }
            }
        }
    }
    assert!(
        checked > 40,
        "the walk found almost nothing: {checked} files"
    );
    assert!(sins.is_empty(), "{}", sins.join("\n"));
}

/// Every `.rs` file under a directory, recursively.
#[cfg(test)]
fn rust_files(dir: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(here) = stack.pop() {
        for entry in std::fs::read_dir(&here).expect("a readable directory") {
            let path = entry.expect("a directory entry").path();
            match path.is_dir() {
                true => stack.push(path),
                false if path.extension().is_some_and(|e| e == "rs") => out.push(path),
                false => {}
            }
        }
    }
    out
}

/// The address a `bind(` on this line asks for, if it asks for a literal one.
#[cfg(test)]
fn bound_address(line: &str) -> Option<&str> {
    let after = line.split_once("bind(\"")?.1;
    let addr = after.split_once('"')?.0;
    // A path is a unix socket and another question; this rule is about ports.
    addr.contains(':').then_some(addr)
}

/// No sentence printed from here has a hole in the middle of it.
///
/// A message that runs over two source lines needs a backslash at the break;
/// without it, the indentation of the second line lands inside the sentence
/// and the operator reads "…the binding was let go while the phase was
/// Unknown;                  the vm may still be running". Six of these have
/// been found one at a time, by reading, over four briefs — the fifth and
/// sixth in `lifecycle.rs`, in a file an earlier brief had already fixed one
/// in.
///
/// The agent half of this construction site keeps the same rule with its own
/// copy of the question (`no_sentence_of_this_construction_site_is_broken_by_
/// a_missing_backslash` in `meister-agent`), for the same reason the temp-path
/// rule above is kept twice: each half must be able to fail on its own.
///
/// The shape is exact: a run of four or more spaces inside a string literal,
/// with the end of a word or a punctuation mark before it and the start of a
/// lowercase word after it. That is a broken continuation and it is not
/// anything else — a padded table column and a captured command line both
/// have runs of spaces in them, and neither has a sentence running through
/// it.
#[test]
fn no_sentence_of_this_construction_site_is_broken_by_a_missing_backslash() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("the workspace root is two above this crate")
        .to_path_buf();

    let mut checked = 0usize;
    let mut holes: Vec<String> = Vec::new();
    for dir in SITE {
        let base = root.join(dir);
        assert!(
            base.is_dir(),
            "{} is not where this test looks",
            base.display()
        );
        for file in rust_files(&base) {
            let source = std::fs::read_to_string(&file).expect("a source file");
            checked += 1;
            for (i, line) in source.lines().enumerate() {
                if line.trim_start().starts_with("//") {
                    continue;
                }
                if let Some(said) = broken_sentence(line) {
                    let at = format!("{dir}/{}:{}", file.file_name().unwrap().display(), i + 1);
                    holes.push(format!("{at}: {said}"));
                }
            }
        }
    }
    assert!(
        checked > 40,
        "the walk found almost nothing: {checked} files"
    );
    assert!(holes.is_empty(), "{}", holes.join("\n"));
}

/// The literal on this line, if a sentence runs through a run of spaces in it.
#[cfg(test)]
fn broken_sentence(line: &str) -> Option<&str> {
    let start = line.find('"')? + 1;
    let end = line.rfind('"')?;
    let inner = line.get(start..end).filter(|s| !s.is_empty())?;
    let bytes = inner.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] != b' ' {
            i += 1;
            continue;
        }
        let run = bytes[i..].iter().take_while(|b| **b == b' ').count();
        let (before, after) = (bytes.get(i.wrapping_sub(1)), bytes.get(i + run));
        let word_before = before.is_some_and(|b| b.is_ascii_lowercase() || b";,.".contains(b));
        let word_after = after.is_some_and(u8::is_ascii_lowercase);
        if run >= 4 && i > 0 && word_before && word_after {
            return Some(inner);
        }
        i += run;
    }
    None
}
