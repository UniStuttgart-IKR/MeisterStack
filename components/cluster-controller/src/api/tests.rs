// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! The edge's tests, verbatim out of `api.rs`. The module path is unchanged
//! (`api::tests`), so every test still answers to the name it had before.

use super::*;

/// An instance store is as node-local as bytes get, and it has no
/// `Volume` object to be caught by.
///
/// The refusal beside this one reads the VM's REFERENCED volumes, so an
/// inline disk went straight through a check written for exactly its kind
/// of problem (migration D6). Unreachable while the migration reconciler
/// is missing, and that is the only reason it never bit: a `POST
/// /vmmigrations` would have been accepted and had to fail later, or —
/// worse — arrive somewhere the file does not exist.
#[test]
fn an_inline_disk_is_named_as_the_reason_a_vm_cannot_move_live() {
    let running = |volumes: serde_json::Value| {
        let mut vm = controller_api::resources::new_vm(
            "web-1",
            VmSpec {
                class: Default::default(),
                cluster_selector: Default::default(),
                node_selector: Default::default(),
                anti_affinity: Vec::new(),
                node_name: Some("agent-1".into()),
                cluster_name: None,
                run_strategy: controller_api::RunStrategy::Running,
                evacuation: Default::default(),
                tenant: None,
                vm: json!({ "volumes": volumes }),
            },
        );
        #[allow(deprecated)]
        vm.status.assign(controller_api::VmPhase::of(
            controller_api::VmPhaseKind::Running,
            Utc::now(),
        ));
        vm
    };
    let somewhere_to_go = MigrationFacts {
        targets: vec!["agent-2".to_string()],
        ..Default::default()
    };

    // The boot disk is an instance store: nothing follows it.
    let inline = running(json!([{ "base_image": "tiny.raw", "size_bytes": 2048 }]));
    let why =
        migration_refusal(&inline, &somewhere_to_go, None).expect("an inline disk is a refusal");
    assert!(why.contains("spec.vm.volumes[0]"), "which disk: {why}");
    assert!(why.contains("instance-store"), "{why}");

    // And it is found wherever it stands, not only first.
    let second = running(json!([
        { "volume": "data-1" },
        { "base_image": "scratch.raw", "size_bytes": 2048 },
    ]));
    let why = migration_refusal(&second, &somewhere_to_go, None).expect("still a refusal");
    assert!(why.contains("spec.vm.volumes[1]"), "which disk: {why}");

    // A VM whose disks are all objects is not refused for this.
    let referenced = running(json!([{ "volume": "data-1" }]));
    assert_eq!(migration_refusal(&referenced, &somewhere_to_go, None), None);
}

/// A browser's handshake gets an answer a browser understands, at this
/// tier too.
///
/// The cloud learned this in fremdsicht 6: a WebSocket client that gets
/// `Upgrade: meister-console` and no `Sec-WebSocket-Accept` throws the
/// connection away without a word. The cluster kept answering every
/// client the raw form (fremdsicht 7) although the handshake and the
/// framing sit in `controller-api` and are shared. What is still only the
/// cloud's is the ticket, and that is why this tier goes on naming
/// `console` and not `console.websocket`.
#[test]
fn the_upgrade_answers_in_the_dialect_it_was_asked_in() {
    let raw = switching(None);
    assert_eq!(raw.status(), StatusCode::SWITCHING_PROTOCOLS);
    assert_eq!(raw.headers()["upgrade"], "meister-console");
    assert!(
        !raw.headers().contains_key("sec-websocket-accept"),
        "the CLI's console is not a websocket"
    );

    // The vector out of RFC 6455 section 1.3, which is what the shared
    // module is held to one crate over.
    let accept = controller_api::websocket::accept_key("dGhlIHNhbXBsZSBub25jZQ==");
    let framed = switching(Some(accept));
    assert_eq!(framed.headers()["upgrade"], "websocket");
    assert_eq!(
        framed.headers()["sec-websocket-accept"],
        "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
    );
}

fn running_vm(name: &str) -> Vm {
    let mut vm = controller_api::resources::new_vm(
        name,
        VmSpec {
            class: Default::default(),
            cluster_selector: Default::default(),
            node_selector: Default::default(),
            anti_affinity: Vec::new(),
            node_name: Some("agent-1".into()),
            cluster_name: None,
            run_strategy: controller_api::RunStrategy::Running,
            evacuation: Default::default(),
            tenant: None,
            vm: serde_json::json!({ "vcpus": 1 }),
        },
    );
    #[allow(deprecated)]
    vm.status.assign(controller_api::VmPhase::of(
        controller_api::VmPhaseKind::Running,
        Utc::now(),
    ));
    vm.status.node_name = Some("agent-1".into());
    vm
}

fn somewhere_to_go() -> MigrationFacts {
    MigrationFacts {
        node_local_disk: None,
        unready_disk: None,
        targets: vec!["agent-2".into()],
        source_node: "agent-1".into(),
        // No profile anywhere: an agent from before the field, which is what
        // every one of the four refusals below has to keep working over.
        source_machine: None,
        machines: Default::default(),
    }
}

/// The same fleet, with both machines describing themselves.
///
/// `mangle` is what makes the destination differ, and it takes the profile so
/// that a test says in one line which of the four rules it is about.
fn machines(mangle: impl FnOnce(&mut controller_api::MachineProfile)) -> MigrationFacts {
    let here = controller_api::MachineProfile {
        cpu_vendor: "GenuineIntel".into(),
        cpu_model: "Intel(R) Xeon(R) Gold 6248R".into(),
        cpu_flags: "fpu lm vmx".into(),
        cpu_profile: "Host".into(),
        hypervisor_version: "cloud-hypervisor v53.0".into(),
        kernel: "6.12.0".into(),
        ..Default::default()
    };
    let mut there = here.clone();
    mangle(&mut there);
    let here_again = here.clone();
    MigrationFacts {
        source_machine: Some(here),
        machines: [
            ("agent-1".to_string(), Some(here_again)),
            ("agent-2".to_string(), Some(there)),
        ]
        .into_iter()
        .collect(),
        ..somewhere_to_go()
    }
}

/// The four refusals of a live migration, each one a fact no waiting
/// changes — which is why they are answered while a person is still at
/// the keyboard rather than twenty seconds later as a Failed object.
#[test]
fn a_live_migration_is_refused_with_a_sentence_that_names_the_way_out() {
    // The happy shape first, so the rest is about one thing at a time.
    assert_eq!(
        migration_refusal(&running_vm("web-1"), &somewhere_to_go(), None),
        None
    );

    // Not running: there is nothing to move, and the cheaper verb is
    // named.
    for phase in [
        controller_api::VmPhaseKind::Stopped,
        controller_api::VmPhaseKind::Paused,
        controller_api::VmPhaseKind::Pending,
    ] {
        let mut vm = running_vm("web-1");
        #[allow(deprecated)]
        vm.status
            .assign(controller_api::VmPhase::of(phase, Utc::now()));
        let why = migration_refusal(&vm, &somewhere_to_go(), None).expect("not running");
        assert!(why.contains(phase.as_str()), "{why}");
        assert!(why.contains("vm reschedule"), "and the way out: {why}");
    }

    // A device: cloud-hypervisor cannot carry it, and the way out is a
    // reboot the owner has to allow.
    let mut with_device = running_vm("gpu-1");
    with_device.spec.vm = serde_json::json!({
        "vcpus": 1,
        "devices": [{ "driver": "nvrm", "profile": "4q" }]
    });
    let why = migration_refusal(&with_device, &somewhere_to_go(), None).expect("a device");
    assert!(why.contains("does not migrate live"), "{why}");
    assert!(why.contains("spec.evacuation = restart"), "{why}");

    // A node-local disk: the bytes stay behind, so the guest would not
    // find them.
    let pinned = MigrationFacts {
        node_local_disk: Some("data-1".into()),
        ..somewhere_to_go()
    };
    let why = migration_refusal(&running_vm("web-1"), &pinned, None).expect("a local disk");
    assert!(why.contains("volume data-1 is node-local"), "{why}");

    // Nowhere to go, asked both ways round. A NAMED node is refused by
    // name, because somebody who named one asked about that one.
    let nowhere = MigrationFacts {
        targets: Vec::new(),
        ..somewhere_to_go()
    };
    let why = migration_refusal(&running_vm("web-1"), &nowhere, None).expect("nowhere");
    assert!(why.contains("nowhere to go"), "{why}");

    let why = migration_refusal(&running_vm("web-1"), &somewhere_to_go(), Some("agent-9"))
        .expect("not a candidate");
    assert!(why.contains("node agent-9 cannot take this vm"), "{why}");
    assert!(
        why.contains("running a hypervisor"),
        "and what it needs: {why}"
    );

    // And a named node that IS a candidate goes through.
    assert_eq!(
        migration_refusal(&running_vm("web-1"), &somewhere_to_go(), Some("agent-2")),
        None
    );
}

/// The one flag an explicit request overrides, and the reason it does.
///
/// A drain honours `evacuation: never` — the owner said their guest must
/// not be interrupted, and a drain is nobody asking. An explicit POST is
/// an operator saying "move this one, now", and there is nothing left for
/// the flag to protect them from: a live migration does not interrupt the
/// guest, which is the whole point of it.
#[test]
fn an_explicit_request_overrides_evacuation_never() {
    let mut vm = running_vm("web-1");
    vm.spec.evacuation = controller_api::Evacuation::Never;
    assert_eq!(migration_refusal(&vm, &somewhere_to_go(), None), None);
    vm.spec.evacuation = controller_api::Evacuation::Restart;
    assert_eq!(migration_refusal(&vm, &somewhere_to_go(), None), None);
}

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

/// The crate's shared test router, with a registry nothing has dialled into:
/// the two tests below never reach a handler.
async fn test_router() -> Router {
    super::test_router(Arc::new(crate::session::SessionRegistry::new())).await
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

/// A feature name is a promise too, and this tier's list is shorter than
/// the cloud's by exactly the thing it does not have: no
/// `console.websocket`, because it mints no tickets and no browser
/// belongs at a cluster endpoint.
#[tokio::test]
async fn every_feature_this_endpoint_names_is_one_it_has() {
    use controller_api::rest::features;

    assert!(
        !FEATURES.contains(&features::CONSOLE_WEBSOCKET),
        "this tier serves the raw console and nothing framed"
    );
    for feature in FEATURES {
        let path = match *feature {
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
    assert_eq!(doc["tier"], "cluster");
    assert_eq!(doc["auth"], "mtls,bearer");
    assert_eq!(doc["resources"].as_array().unwrap().len(), RESOURCES.len());
}

/// A cloud-owned object is the cloud's to change, and a PATCH is a PUT:
/// `patch_vm` hands its merged body to `update_vm`, which asks this
/// before anything else, so the refusal is the same 409 with the same
/// sentence whichever method the operator used.
#[test]
fn a_cloud_owned_vm_is_refused_here_whichever_way_it_is_written() {
    let spec = || VmSpec {
        class: Default::default(),
        node_name: None,
        cluster_name: None,
        run_strategy: controller_api::RunStrategy::Running,
        evacuation: Default::default(),
        tenant: None,
        cluster_selector: Default::default(),
        node_selector: Default::default(),
        anti_affinity: Vec::new(),
        vm: json!({}),
    };
    let local = Vm::declare("web", spec());
    assert!(
        refuse_if_cloud_owned(&local).is_ok(),
        "local operation is free"
    );

    let mut owned = Vm::declare("web", spec());
    owned.metadata.labels.insert(
        controller_api::LABEL_MANAGED_BY.to_string(),
        controller_api::MANAGED_BY_CLOUD.to_string(),
    );
    let refused = refuse_if_cloud_owned(&owned).expect_err("the cloud owns it");
    let said = format!("{refused:?}");
    assert!(said.contains("Conflict"), "{said}");
    assert!(said.contains("managed by the cloud"), "{said}");
}

/// The other half of the promise: a resource this control plane has is
/// either served here or written down as one this tier does not serve. A
/// new row in `controller_api::resources` fails this test until somebody
/// decides which of the two it is.
/// The cluster tier's own table, and the label rule beside it.
///
/// A PATCH never meets any of this — it is merged onto the stored object
/// first, so an unmentioned field is already the stored value — which is
/// what makes the same handler safe for both verbs. The test says so by
/// running a real merge patch through and expecting it to pass.
#[test]
fn a_bound_vm_refuses_a_moved_spec_and_takes_a_patch_that_says_nothing_about_it() {
    let stored = |vcpus: u32| {
        json!({
            "metadata": {"name": "web-1", "labels": {
                "meister.io/managed-by": "cloud",
                "meister.io/cloud-uid": "uid-1",
            }},
            "spec": {
                "vm": {"vcpus": vcpus},
                "nodeName": "manacor",
                "nodeSelector": {"zone": "lab"},
                "runStrategy": "Running",
            },
        })
    };
    let current = stored(2);

    controller_api::check_owned(&current, &stored(2), VM_OWNED).expect("a round trip");

    for (path, moved) in [
        ("spec.vm", stored(4)),
        (
            "spec.nodeName",
            json!({"spec": {"vm": {"vcpus": 2}, "nodeName": "cala",
                            "nodeSelector": {"zone": "lab"}}}),
        ),
        (
            "spec.nodeSelector",
            json!({"spec": {"vm": {"vcpus": 2}, "nodeName": "manacor",
                            "nodeSelector": {"zone": "dev"}}}),
        ),
    ] {
        let refused = controller_api::check_owned(&current, &moved, VM_OWNED).expect_err(path);
        assert!(
            refused.message().starts_with(&format!("{path} ")),
            "{}",
            refused.message()
        );
    }

    // runStrategy is free, and it has to be: it is the whole of what a
    // level-triggered lifecycle reads.
    let stopped = json!({
        "spec": {"vm": {"vcpus": 2}, "nodeName": "manacor",
                 "nodeSelector": {"zone": "lab"}, "runStrategy": "Stopped"},
    });
    controller_api::check_owned(&current, &stopped, VM_OWNED).expect("stopping a vm");

    // And the PATCH path: whatever the patch does not mention is already
    // the stored value by the time the table sees it.
    let mut patched = current.clone();
    controller_api::merge_patch(&mut patched, &json!({"spec": {"runStrategy": "Stopped"}}));
    controller_api::check_owned(&current, &patched, VM_OWNED)
        .expect("a three-line patch names none of the owned fields");
}

/// The row storage B rewrote: `spec.vm` is immutable in everything except
/// `volumes[]` from its SECOND entry on, and there only for entries that
/// name a `Volume` object.
///
/// Six edits, and each one is a different sentence about the same field.
/// The three that pass are the whole of declarative hot-plug — attach is
/// an entry appearing, detach is one disappearing, and neither is a verb.
/// The three that are refused are the ones where saying yes would cost
/// somebody something they cannot get back: a guest's root disk swapped
/// underneath it, an instance store nobody agreed to make, and the rest
/// of a booted VM's document.
#[test]
fn a_vm_takes_a_second_disk_and_refuses_everything_else_about_its_spec() {
    let vm = |volumes: serde_json::Value, vcpus: u32| {
        json!({"spec": {"vm": {"vcpus": vcpus, "volumes": volumes},
                        "nodeName": "manacor", "runStrategy": "Running"}})
    };
    let boot = json!({"volume": "root-1"});
    let data = json!({"volume": "data-2"});
    let store = json!({"size_bytes": 1073741824});
    let one = vm(json!([boot, store]), 2);

    let allowed = [
        ("attaching a second disk", vm(json!([boot, store, data]), 2)),
        (
            "attaching it in front of the inline one",
            vm(json!([boot, data, store]), 2),
        ),
    ];
    for (what, next) in allowed {
        controller_api::check_owned(&one, &next, VM_OWNED).expect(what);
    }
    // ... and detaching it again.
    let two = vm(json!([boot, store, data]), 2);
    controller_api::check_owned(&two, &one, VM_OWNED).expect("detaching the second disk");
    controller_api::check_owned(&two, &two, VM_OWNED).expect("a round trip");

    let refused = [
        // The boot entry. There is no moment at which a running guest
        // survives having its root disk swapped.
        ("the boot entry", vm(json!([data, store]), 2)),
        ("dropping the boot entry", vm(json!([store]), 2)),
        // An instance store came into being with the VM and goes with it.
        ("an inline disk", vm(json!([boot]), 2)),
        (
            "a new inline disk",
            vm(json!([boot, store, json!({"size_bytes": 42})]), 2),
        ),
        (
            "editing an inline disk",
            vm(json!([boot, json!({"size_bytes": 42})]), 2),
        ),
        // And everything else in the document, exactly as before.
        ("the vcpus", vm(json!([boot, store]), 4)),
    ];
    for (what, next) in refused {
        let err = controller_api::check_owned(&one, &next, VM_OWNED).expect_err(what);
        assert!(
            err.message().starts_with("spec.vm "),
            "{what}: {}",
            err.message()
        );
        assert!(
            err.message().contains("boot entry"),
            "the sentence says what is fixed: {}",
            err.message()
        );
    }

    // A VM with no volumes at all is the one every VM before this
    // milestone is, and it compares exactly as it always did.
    let bare = json!({"spec": {"vm": {"vcpus": 2}}});
    controller_api::check_owned(&bare, &bare, VM_OWNED).expect("a round trip");
    controller_api::check_owned(&bare, &json!({"spec": {"vm": {"vcpus": 4}}}), VM_OWNED)
        .expect_err("still immutable");
}

/// The two labels that say which cloud owns a VM are the cloud's, in both
/// directions: a client may not adopt its VM into a cloud, and may not
/// orphan one out of the cloud that has it.
#[test]
fn the_cloud_ownership_labels_may_not_be_written_from_here() {
    let vm = |labels: serde_json::Value| -> Vm {
        serde_json::from_value(json!({
            "apiVersion": API_VERSION, "kind": "Vm",
            "metadata": {"name": "web-1", "labels": labels},
            "spec": {"vm": {}},
        }))
        .unwrap()
    };
    let owned = vm(json!({"meister.io/managed-by": "cloud", "meister.io/cloud-uid": "uid-1"}));
    let free = vm(json!({"tier": "web"}));

    check_owner_labels(&owned.metadata, &owned.metadata).expect("sent back as read");
    check_owner_labels(&free.metadata, &free.metadata).expect("a vm nobody claims");

    let adopted = check_owner_labels(&free.metadata, &owned.metadata).expect_err("forged the mark");
    assert!(
        adopted.message().contains("managed-by"),
        "{}",
        adopted.message()
    );
    let orphaned =
        check_owner_labels(&owned.metadata, &free.metadata).expect_err("stripped the mark");
    assert!(
        orphaned.message().contains("managed-by"),
        "{}",
        orphaned.message()
    );

    // A label of the client's own is neither, and stays editable.
    let relabelled = vm(json!({
        "meister.io/managed-by": "cloud", "meister.io/cloud-uid": "uid-1", "tier": "db",
    }));
    check_owner_labels(&owned.metadata, &relabelled.metadata).expect("its own labels are its own");
}

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

/// A volume starts from exactly one thing, and both tiers say so.
///
/// Empty, a catalogue image, or somebody's own point in time. A spec that
/// named two would be a spec whose author believes one of them, and a
/// silent winner hands somebody a disk they did not ask for — a blank one
/// where they asked for their data, which is the direction that costs.
#[test]
fn a_volume_starts_from_an_image_or_from_a_snapshot_and_never_both() {
    let volume = |image: Option<&str>, snapshot: Option<&str>| {
        let mut v = new_volume("data", controller_api::VolumeSpec::default());
        v.spec.size_gib = 1;
        v.spec.base_image = image.map(str::to_string);
        v.spec.from_snapshot = snapshot.map(str::to_string);
        v
    };
    check_one_seed(&volume(None, None)).expect("an empty disk");
    check_one_seed(&volume(Some("debian.raw"), None)).expect("from the catalogue");
    check_one_seed(&volume(None, Some("snap-1"))).expect("from a point in time");

    let refused = check_one_seed(&volume(Some("debian.raw"), Some("snap-1")))
        .expect_err("two starting points");
    let said = format!("{refused:?}");
    assert!(said.contains("not both"), "{said}");
    assert!(said.contains("fromSnapshot"), "and which field: {said}");

    // An empty string is not a starting point. A client that round-trips
    // a stored object sends `""` for a field it never set, and refusing
    // that would refuse an ordinary PUT.
    check_one_seed(&volume(Some(""), Some("snap-1"))).expect("an empty image is no image");
}

/// A pool whose backend cannot take a copy is a 422 at the edge, and the
/// sentence names something an operator can act on.
///
/// "The pool cannot" is not actionable; "the filesystem driver on agent-1
/// reports no snapshot support" is. The answer comes out of the node
/// CATALOGUE — the same `volume/<driver>/snapshot` claim a GPU profile
/// makes — which is why it is available here at all rather than twenty
/// seconds later as a Failed object.
#[test]
fn the_snapshot_claim_is_what_a_pool_is_asked_for() {
    let claim = |driver: &str| {
        common::capability::entry(
            common::capability::VOLUME,
            Some(&format!("{driver}/{}", common::capability::SNAPSHOT)),
        )
    };
    assert_eq!(claim("lvm-thin"), "volume/lvm-thin/snapshot");
    // The claim names the BACKEND, and that is the whole reason it is
    // nested: one node may serve two backends and disagree with itself.
    assert_ne!(claim("lvm-thin"), claim("filesystem"));

    let node = |name: &str, claims: &[&str]| {
        let mut n = Node::declare(name, NodeSpec::default());
        n.status.capacity.capabilities = claims.iter().map(|c| (*c).to_string()).collect();
        n
    };
    let with = node("agent-1", &[&claim("lvm-thin"), "volume/lvm-thin"]);
    let without = node("agent-2", &["volume/filesystem"]);
    assert!(
        with.status
            .capacity
            .capabilities
            .contains(&claim("lvm-thin"))
    );
    assert!(
        !without
            .status
            .capacity
            .capabilities
            .contains(&claim("filesystem")),
        "a backend that answers None claims nothing"
    );
}

/// The one exception to `spec.nodeName` being the scheduler's, and the
/// two conditions it needs.
///
/// `runStrategy` is the INTENT and the phase is the OBSERVATION, and a VM
/// that has been told to stop and has not finished stopping satisfies the
/// first and not the second. Moving that one would be moving something
/// that is still running, which is exactly what this is not: no live
/// migration, no restart of anything that is up.
/// Silas' rule at this tier: an `Unknown` binding is let go only while the
/// machine holding it is reporting, and 409 says so when it is not.
///
/// `stopped_enough` calls `Unknown` stopped enough (D12), and on its own that
/// was an assertion nobody could back — `Unknown` is exactly the phase in
/// which this control plane does not know whether the guest is running. The
/// second half is evidence: a current heartbeat is the node's session, and
/// with the node back the ordinary stop runs before the binding moves.
#[test]
fn an_unknown_binding_is_only_let_go_while_its_node_reports() {
    let at = |secs: i64| chrono::DateTime::from_timestamp(1_800_000_000 + secs, 0).unwrap();
    let now = at(1_000);
    let mut vm = controller_api::resources::new_vm(
        "web-1",
        VmSpec {
            class: Default::default(),
            cluster_selector: Default::default(),
            node_selector: Default::default(),
            anti_affinity: Vec::new(),
            node_name: Some("agent-1a".into()),
            cluster_name: None,
            run_strategy: controller_api::RunStrategy::Stopped,
            evacuation: Default::default(),
            tenant: None,
            vm: json!({}),
        },
    );
    #[allow(deprecated)]
    vm.status.assign(controller_api::VmPhase::of(
        controller_api::VmPhaseKind::Unknown,
        Utc::now(),
    ));

    // Silent: 409, because nothing about the request is malformed — the state
    // of the world refuses it, and that state ends by itself.
    let refused = holder_refusal(&vm, "agent-1a", Some(at(0)), now).expect_err("a silent node");
    assert_eq!(refused.status(), axum::http::StatusCode::CONFLICT);
    assert!(
        refused.message().contains("node agent-1a"),
        "{}",
        refused.message()
    );
    assert!(
        refused.message().contains("drain the node"),
        "{}",
        refused.message()
    );

    // Reporting: it goes through.
    holder_refusal(&vm, "agent-1a", Some(at(1_000)), now).expect("a node that is talking");

    // `Failed` is the node's own word that the guest is not running, so it is
    // untouched even when the node has since gone quiet.
    let mut failed = vm.clone();
    #[allow(deprecated)]
    failed.status.assign(controller_api::VmPhase::of(
        controller_api::VmPhaseKind::Failed,
        Utc::now(),
    ));
    holder_refusal(&failed, "agent-1a", None, now).expect("Failed is evidence");

    // And what the object is left carrying when the release does land.
    let unbound = |from: &Vm| {
        let mut v = from.clone();
        v.spec.node_name = None;
        v
    };
    let said = release_event(&vm, &unbound(&vm)).expect("an Unknown release is noted");
    assert!(said.contains("while the phase was Unknown"), "{said}");
    assert!(said.contains("agent-1a"), "{said}");
    // Nothing to note when nothing was let go, or when the phase was evidence.
    assert_eq!(release_event(&vm, &vm), None);
    assert_eq!(release_event(&failed, &unbound(&failed)), None);
}

/// A vm bound to a node, in the two states that decide whether the binding
/// may be let go: what the owner ASKED for and what the node REPORTS.
fn bound_vm(strategy: controller_api::RunStrategy, phase: controller_api::VmPhaseKind) -> Vm {
    let mut v = controller_api::resources::new_vm(
        "web-1",
        VmSpec {
            class: Default::default(),
            cluster_selector: Default::default(),
            node_selector: Default::default(),
            anti_affinity: Vec::new(),
            node_name: Some("agent-1".into()),
            cluster_name: None,
            run_strategy: strategy,
            evacuation: Default::default(),
            tenant: None,
            vm: json!({}),
        },
    );
    #[allow(deprecated)]
    v.status
        .assign(controller_api::VmPhase::of(phase, Utc::now()));
    v
}

/// The same vm with its binding cleared, which is the edit under test.
fn let_go(from: &Vm) -> Vm {
    let mut v = from.clone();
    v.spec.node_name = None;
    v
}

#[test]
fn a_binding_may_only_be_let_go_of_a_vm_that_is_standing_still() {
    use controller_api::{RunStrategy, VmPhaseKind};

    let stopped = bound_vm(RunStrategy::Stopped, VmPhaseKind::Stopped);
    check_reschedule(&stopped, &let_go(&stopped)).expect("a stopped vm may move");
    // Sending it back unchanged is not a reschedule and is always fine.
    check_reschedule(&stopped, &stopped).expect("a round trip");

    for (strategy, phase, why) in [
        (RunStrategy::Running, VmPhaseKind::Running, "running"),
        (
            RunStrategy::Stopped,
            VmPhaseKind::Running,
            "asked to stop, still up",
        ),
        (
            RunStrategy::Running,
            VmPhaseKind::Stopped,
            "stopped, but meant to run",
        ),
        (
            RunStrategy::Stopped,
            VmPhaseKind::Paused,
            "memory and disks still open",
        ),
    ] {
        let current = bound_vm(strategy, phase);
        let refused = check_reschedule(&current, &let_go(&current)).expect_err(why);
        assert!(
            refused.message().contains(phase.as_str()),
            "and it names the phase a person can act on: {}",
            refused.message()
        );
    }
}

/// D12: `Failed` and `Unknown` are stopped enough, and they are the phases a
/// VM on a node that executes nothing is actually in. Before this the only
/// exit from that state was a pair of hands.
#[test]
fn a_vm_whose_node_executes_nothing_is_standing_still_enough() {
    use controller_api::{RunStrategy, VmPhaseKind};

    for phase in [VmPhaseKind::Failed, VmPhaseKind::Unknown] {
        let current = bound_vm(RunStrategy::Stopped, phase);
        check_reschedule(&current, &let_go(&current))
            .unwrap_or_else(|e| panic!("{phase:?} may move: {}", e.message()));
    }
}

/// The table half of the same rule: the predicate opens the SHAPE of the
/// edit — clearing it — and nothing else. Re-pointing a binding at another
/// node stays refused, which is what keeps a client from moving a VM by hand.
#[test]
fn a_binding_may_be_cleared_by_hand_and_never_re_pointed() {
    let moved = json!({"spec": {"nodeName": "agent-2", "vm": {},
                                "nodeSelector": {}, "runStrategy": "Stopped"}});
    let here = json!({"spec": {"nodeName": "agent-1", "vm": {},
                               "nodeSelector": {}, "runStrategy": "Stopped"}});
    let gone = json!({"spec": {"nodeName": null, "vm": {},
                               "nodeSelector": {}, "runStrategy": "Stopped"}});
    controller_api::check_owned(&here, &gone, VM_OWNED).expect("letting go");
    let refused =
        controller_api::check_owned(&here, &moved, VM_OWNED).expect_err("re-pointing it by hand");
    assert!(
        refused.message().contains("may only clear it"),
        "{}",
        refused.message()
    );
}
/// The machine, refused while a person is still at the keyboard.
///
/// The fifth refusal, and the one that is not about this VM at all: a live
/// migration moves a MACHINE STATE, and cloud-hypervisor v53 checks the CPUID
/// before a transfer and nothing else. Without this the operator's command is
/// accepted, a VMM is built on the destination, disks are opened on it, the
/// guest is paused — and then it fails two milliseconds after the vCPUs are
/// made, in a log file nothing in this stack reads. That is D-X1, and it cost
/// the lab two nights.
///
/// A named node is answered about BY NAME, because somebody who typed
/// `--to agent-2` asked about agent-2.
#[test]
fn a_migration_into_a_machine_that_cannot_hold_the_state_is_refused_at_the_edge() {
    let vm = running_vm("web-1");

    // The fleet as it usually is: two machines of one kind, and nothing to
    // say about them.
    assert_eq!(migration_refusal(&vm, &machines(|_| {}), None), None);
    assert_eq!(
        migration_refusal(&vm, &machines(|_| {}), Some("agent-2")),
        None
    );

    // A destination of another make. Refused either way, and the sentence is
    // the one `live_migration_refusal` wrote — this edge does not paraphrase
    // it, because the whole value of it is that it names both machines.
    let other = |m: &mut controller_api::MachineProfile| {
        m.cpu_vendor = "AuthenticAMD".into();
        m.cpu_model = "AMD EPYC 7543".into();
    };
    let why = migration_refusal(&vm, &machines(other), None).expect("nowhere it fits");
    assert!(why.contains("make of cpu"), "{why}");
    assert!(why.contains("agent-1") && why.contains("agent-2"), "{why}");
    let named = migration_refusal(&vm, &machines(other), Some("agent-2")).expect("not agent-2");
    assert_eq!(named, why, "a named node gets the answer about that node");

    // And the guard that keeps a rolling upgrade working: a node that has
    // said nothing about itself refuses nothing. `somewhere_to_go` is exactly
    // that fleet, and it is what every other refusal in this file is tested
    // against.
    assert_eq!(migration_refusal(&vm, &somewhere_to_go(), None), None);

    // The order matters as much as the rule. A vm that is not running, or
    // whose disk is node-local, is refused for THAT — the machine comparison
    // never gets a chance to answer a question nobody asked.
    let mut stopped = vm.clone();
    #[allow(deprecated)]
    stopped.status.assign(controller_api::VmPhase::of(
        controller_api::VmPhaseKind::Stopped,
        Utc::now(),
    ));
    let why = migration_refusal(&stopped, &machines(other), None).expect("not running");
    assert!(why.contains("only a running vm"), "{why}");
}
