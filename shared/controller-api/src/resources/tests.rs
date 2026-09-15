// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! The resource table's tests, verbatim out of `resources.rs`.
//! The module path is unchanged (`resources::tests`), so every
//! test still answers to the name it had before.

use super::*;

/// The set half of `openOn`: idempotent both ways, sorted, and the
/// return value says whether a store write is worth making. A report
/// arrives every ten seconds from every node; a field that claimed to
/// have changed each time would churn a revision per heartbeat.
#[test]
fn a_volume_is_opened_and_closed_by_name_and_the_list_stays_a_set() {
    let mut status = VolumeStatus::default();
    assert!(status.open_here("agent-2"));
    assert!(
        !status.open_here("agent-2"),
        "the second open changes nothing"
    );
    assert!(status.open_here("agent-1"));
    assert_eq!(status.open_on, vec!["agent-1", "agent-2"], "sorted");

    assert_eq!(status.open_elsewhere("agent-1"), Some("agent-2"));
    assert!(status.closed_here("agent-2"));
    assert!(
        !status.closed_here("agent-2"),
        "closing twice changes nothing"
    );
    assert_eq!(status.open_elsewhere("agent-1"), None, "only we have it");
    assert_eq!(
        status.open_elsewhere("agent-3"),
        Some("agent-1"),
        "and the name is what a refusal has to print"
    );
}

/// The one exception to `AccessMode`, at both its edges.
#[test]
fn only_a_migration_under_way_lets_two_nodes_hold_one_volume() {
    assert!(!second_open_is_a_migration(None));
    assert!(!second_open_is_a_migration(Some(
        VmMigrationPhaseKind::Pending
    )));
    assert!(second_open_is_a_migration(Some(
        VmMigrationPhaseKind::Preparing
    )));
    assert!(second_open_is_a_migration(Some(
        VmMigrationPhaseKind::Running
    )));
    assert!(!second_open_is_a_migration(Some(
        VmMigrationPhaseKind::Succeeded
    )));
    assert!(!second_open_is_a_migration(Some(
        VmMigrationPhaseKind::Failed
    )));
}

/// One pool, two spellings, one answer — and the short form first,
/// because that is where a volume of a pool that grew a list was already
/// made.
#[test]
fn a_pool_says_which_clusters_serve_it_however_it_was_written() {
    let pool = |cluster: &str, clusters: &[&str]| StoragePoolSpec {
        driver: "nfs".into(),
        cluster: cluster.to_string(),
        clusters: clusters.iter().map(|c| c.to_string()).collect(),
        ..Default::default()
    };

    // The ordinary case, unchanged: one cluster, and it is the home.
    let one = pool("cluster-1", &[]);
    assert_eq!(one.served_by(), vec!["cluster-1"]);
    assert_eq!(one.home(), Some("cluster-1"));
    assert!(one.serves("cluster-1") && !one.serves("cluster-2"));

    // The list alone, for a pool written that way from the start.
    let listed = pool("", &["cluster-2", "cluster-3"]);
    assert_eq!(listed.served_by(), vec!["cluster-2", "cluster-3"]);
    assert_eq!(listed.home(), Some("cluster-2"), "the first is the home");

    // Both, which is what an existing pool looks like after somebody
    // widened it: the short form stays first, so the home does not move
    // out from under the volumes already there.
    let widened = pool("cluster-1", &["cluster-2"]);
    assert_eq!(widened.served_by(), vec!["cluster-1", "cluster-2"]);
    assert_eq!(widened.home(), Some("cluster-1"));

    // And saying the same cluster twice is saying it once.
    let doubled = pool("cluster-1", &["cluster-1", "cluster-2"]);
    assert_eq!(doubled.served_by(), vec!["cluster-1", "cluster-2"]);

    // A pool naming nothing has no home. The create edge refuses it; this
    // is what the rest of the tree sees if one is edited into existence.
    assert_eq!(pool("", &[]).home(), None);
}

/// `spec.clusters` is a CLAIM, and this is the evidence against it.
///
/// Silence never counts as agreement: a cluster that predates the field
/// says nothing, and "did not say" must not pass for "the same export".
#[test]
fn two_clusters_disagree_unless_both_describe_the_same_backend() {
    let at = |cluster: &str, params: Option<serde_json::Value>| PoolAtCluster {
        cluster: cluster.to_string(),
        params,
        ..Default::default()
    };
    let export = |path: &str| Some(serde_json::json!({ "share_root": path }));

    let mut status = StoragePoolStatus::default();
    assert_eq!(StoragePoolSpec::disagreeing(&status), None, "nobody spoke");

    status.clusters = vec![at("cluster-1", export("/srv/ms"))];
    assert_eq!(StoragePoolSpec::disagreeing(&status), None, "one spoke");

    status.clusters.push(at("cluster-2", export("/srv/ms")));
    assert_eq!(
        StoragePoolSpec::disagreeing(&status),
        None,
        "the same export on both sides is what the claim says"
    );

    status.clusters.push(at("cluster-3", export("/srv/other")));
    assert_eq!(
        StoragePoolSpec::disagreeing(&status),
        Some(("cluster-1", "cluster-3")),
        "and the first two that differ are named"
    );

    // An older cluster saying nothing is not the same export.
    let quiet = StoragePoolStatus {
        clusters: vec![at("cluster-1", export("/srv/ms")), at("cluster-2", None)],
        ..Default::default()
    };
    assert_eq!(
        StoragePoolSpec::disagreeing(&quiet),
        Some(("cluster-1", "cluster-2")),
        "a pool crossing clusters is checked, and an unanswered half is not agreement"
    );
}

/// Two phases, one spelling. A client that asks "is this thing ready"
/// should not need to know which kind of thing it is holding — the lab
/// found `Running` beside `provisioning` and had to compare twice.
///
/// And the second half, which is what makes it worth a test: the category
/// behind a pending VM now reaches the API, in the same words the metric
/// label uses, so a dashboard and a client cannot disagree about what
/// happened.
#[test]
fn the_phases_are_spelled_alike_and_the_pending_category_reaches_the_api() {
    assert_eq!(
        serde_json::to_value(VmPhaseKind::Provisioning).unwrap(),
        serde_json::json!("Provisioning")
    );
    assert_eq!(
        serde_json::to_value(VolumePhaseKind::Provisioning).unwrap(),
        serde_json::json!("Provisioning")
    );
    assert_eq!(
        serde_json::to_value(VolumePhaseKind::Releasing).unwrap(),
        serde_json::json!("Releasing")
    );

    // Absent by default and absent from the wire, so every object written
    // before this field existed reads back as what it was. `reason` is what
    // `pendingReason` became in struktur 4: the same closed word in the same
    // place, one key shorter.
    let s = VmStatus::default();
    assert_eq!(s.phase().reason(), Some(VmReason::Unrecorded));
    let wire = serde_json::to_value(&s).unwrap();
    assert!(wire.get("reason").is_none(), "{wire}");
    assert!(wire.get("pendingReason").is_none(), "{wire}");

    // And when it is there it is one of the closed set.
    let mut s = VmStatus::default();
    s.assign(VmPhase::new(
        VmPhaseKind::Pending,
        VmReason::Unplaced,
        Some("no candidate has room".into()),
        Utc::now(),
    ));
    let wire = serde_json::to_value(&s).unwrap();
    assert_eq!(wire["reason"], "Unplaced");
    assert_eq!(wire["message"], "no candidate has room");
    assert_eq!(wire["phase"], "Pending", "still a sibling, still a string");
}

/// The registration table read back through the trait: no two resources
/// share a directory, and none shares a kind. A duplicated row would file
/// one resource's objects under another's name — and since the store now
/// derives that name from the type, nothing at a call site could ever
/// catch it.
#[test]
fn every_resource_has_its_own_directory_and_its_own_kind() {
    let directories: std::collections::BTreeSet<&str> =
        ALL_RESOURCES.iter().map(|(r, _)| *r).collect();
    let kinds: std::collections::BTreeSet<&str> = ALL_RESOURCES.iter().map(|(_, k)| *k).collect();
    assert_eq!(directories.len(), ALL_RESOURCES.len(), "{directories:?}");
    assert_eq!(kinds.len(), ALL_RESOURCES.len(), "{kinds:?}");
    // A directory is a single path segment, because it is one: the key is
    // `<prefix>/registry/<resource>/<name>` and the REST route below it
    // matches one segment.
    assert!(
        ALL_RESOURCES
            .iter()
            .all(|(r, _)| !r.is_empty() && !r.contains('/')),
        "a resource directory is one path segment"
    );
}

/// The agent spells phases by hand (it must not depend on this crate), so
/// guard the contract from both ends: every variant parses from the name
/// serde and Debug use, and nothing else parses at all.
/// The lists are only worth walking if they are complete. The `match`
/// arms are the guard: an eighth phase or a fourth run strategy stops
/// this file compiling, and the length check catches an entry dropped
/// from the list without the enum changing.
#[test]
fn the_variant_lists_name_every_variant() {
    for phase in VmPhaseKind::ALL {
        match phase {
            VmPhaseKind::Pending
            | VmPhaseKind::Provisioning
            | VmPhaseKind::Running
            | VmPhaseKind::Stopped
            | VmPhaseKind::Paused
            | VmPhaseKind::Failed
            | VmPhaseKind::Quarantined
            | VmPhaseKind::Unknown => {}
        }
    }
    for strategy in RunStrategy::ALL {
        match strategy {
            RunStrategy::Running | RunStrategy::Stopped | RunStrategy::Paused => {}
        }
    }
    for phase in RouterPhaseKind::ALL {
        match phase {
            RouterPhaseKind::Pending
            | RouterPhaseKind::Provisioning
            | RouterPhaseKind::Active
            | RouterPhaseKind::Standby
            | RouterPhaseKind::Failed
            | RouterPhaseKind::Unknown => {}
        }
    }
    for kind in NatKind::ALL {
        match kind {
            NatKind::Snat | NatKind::DnatAndSnat | NatKind::Routed => {}
        }
    }
    // No duplicates hiding a missing one.
    let spellings: std::collections::BTreeSet<_> =
        VmPhaseKind::ALL.iter().map(|p| p.as_str()).collect();
    assert_eq!(spellings.len(), VmPhaseKind::ALL.len());
    assert_eq!(VmPhaseKind::ALL.iter().filter(|p| p.is_stable()).count(), 3);

    let spellings: std::collections::BTreeSet<_> =
        RouterPhaseKind::ALL.iter().map(|p| p.as_str()).collect();
    assert_eq!(spellings.len(), RouterPhaseKind::ALL.len());
    let spellings: std::collections::BTreeSet<_> =
        NatKind::ALL.iter().map(|k| k.as_str()).collect();
    assert_eq!(spellings.len(), NatKind::ALL.len());
}

/// A router's phase travels the same road a VM's does — the agent spells
/// it by hand into `proto::RouterReport.phase` and this tier parses it —
/// so the contract is guarded from both ends: every variant parses from
/// the name it writes, and a word this tier does not have is refused
/// rather than defaulted to Pending.
#[test]
fn every_router_phase_parses_from_its_own_spelling() {
    for phase in RouterPhaseKind::ALL {
        assert_eq!(RouterPhaseKind::parse(phase.as_str()), Some(phase));
    }
    assert_eq!(RouterPhaseKind::parse("Ascended"), None);
    assert_eq!(
        RouterPhaseKind::parse("active"),
        None,
        "the case is part of it"
    );
    assert_eq!(RouterPhaseKind::default(), RouterPhaseKind::Pending);
}

/// OVN's spelling, unchanged all the way down: the string in the object,
/// the string serde writes and the string `proto::NatRule.kind` carries
/// are one string, so nothing on the way translates and nothing on the
/// way can translate wrongly.
#[test]
fn a_nat_kind_is_spelled_ovns_way_in_the_object_and_on_the_wire() {
    for kind in NatKind::ALL {
        assert_eq!(NatKind::parse(kind.as_str()), Some(kind));
        assert_eq!(
            serde_json::to_value(kind).unwrap(),
            serde_json::json!(kind.as_str()),
            "serde and as_str must not disagree"
        );
    }
    assert_eq!(NatKind::Snat.as_str(), "snat");
    assert_eq!(NatKind::DnatAndSnat.as_str(), "dnat_and_snat");
    // The third is not OVN's and not a translation: it is how an
    // announcement reaches a node through a message that has no field for
    // one. See `NatKind::Routed`.
    assert_eq!(NatKind::Routed.as_str(), "routed");
    // Not OVN's, and therefore not ours: a rule whose kind nobody
    // understood must not quietly become a masquerade.
    assert_eq!(NatKind::parse("dnat"), None);
    assert_eq!(NatKind::parse("dnat-and-snat"), None);
}

/// A router with no opinion translates its whole tenant, and the two
/// roads to that answer agree.
///
/// `snat` is the one field in this tree that defaults to TRUE, so the
/// derived `Default` would have said `false` and disagreed with serde:
/// a router created through the API would masquerade and one built in a
/// reconciler would not, which is the kind of split nothing catches until
/// a tenant cannot reach anything.
#[test]
fn a_router_that_says_nothing_translates_its_whole_tenant() {
    assert!(RouterSpec::default().snat);
    let parsed: RouterSpec = serde_json::from_str(r#"{"tenant":"acme"}"#).expect("a spec");
    assert!(parsed.snat, "serde and Default must not disagree");
    // And saying so explicitly is still a thing a client may do.
    let off: RouterSpec =
        serde_json::from_str(r#"{"tenant":"acme","snat":false}"#).expect("a spec");
    assert!(!off.snat);
}

/// The class pair, both halves, and the rule that keeps it additive.
///
/// A workload that named no class is of its own kind's class, and a node
/// that named no `accepts` takes everything — which is every node and
/// every VM ever written. Reading either empty list the other way round
/// would strand a fleet on upgrade.
#[test]
fn a_workload_that_names_no_class_is_of_its_own_kinds_class() {
    let mut vm = VmSpec {
        node_name: None,
        cluster_name: None,
        run_strategy: Default::default(),
        evacuation: Default::default(),
        tenant: None,
        class: Default::default(),
        cluster_selector: Default::default(),
        node_selector: Default::default(),
        anti_affinity: Vec::new(),
        vm: serde_json::json!({}),
    };
    assert_eq!(vm.class(), CLASS_VM);
    vm.class = "gpu".into();
    assert_eq!(vm.class(), "gpu");
    assert_eq!(RouterSpec::default().class(), CLASS_ROUTER);

    // A node that said nothing takes everything.
    assert!(accepts_class(&[], CLASS_VM));
    assert!(accepts_class(&[], CLASS_ROUTER));
    assert!(accepts_class(&[], "gpu"));
    // One that said something is EXCLUSIVE — that is the whole point of
    // the field, and it is why it is an operator's statement and not a
    // machine's.
    let only_routers = ["router".to_string()];
    assert!(accepts_class(&only_routers, CLASS_ROUTER));
    assert!(!accepts_class(&only_routers, CLASS_VM));
    let both = ["router".to_string(), "vm".to_string()];
    assert!(accepts_class(&both, CLASS_VM) && accepts_class(&both, CLASS_ROUTER));

    // And the same question about a whole fleet, which is what the cloud
    // asks: derived from the machines, so that both tiers answer it the same
    // way instead of one of them not being able to ask at all.
    let machine = |name: &str, accepts: &[&str], ready: bool| NodeSummary {
        name: name.into(),
        ready,
        schedulable: true,
        accepts: accepts.iter().map(|a| a.to_string()).collect(),
        ..Default::default()
    };
    assert!(
        cluster_accepts(&[]).is_empty(),
        "an empty fleet said nothing, which is not the same as refusing"
    );
    assert!(
        cluster_accepts(&[
            machine("gw-1", &["router"], true),
            machine("a-1", &[], true)
        ])
        .is_empty(),
        "one machine that takes anything makes the fleet open"
    );
    let gateways_only = cluster_accepts(&[
        machine("gw-1", &["router"], true),
        machine("gw-2", &["router", "gpu"], true),
    ]);
    assert_eq!(gateways_only, vec!["gpu".to_string(), "router".to_string()]);
    assert!(!accepts_class(&gateways_only, CLASS_VM), "and it refuses");
    // A machine that is down is not what a fleet can be held to: the fleet's
    // only general-purpose box being away is exactly the case the cloud must
    // see, because binding a VM there would leave it Pending one tier down.
    assert_eq!(
        cluster_accepts(&[
            machine("gw-1", &["router"], true),
            machine("a-1", &[], false),
        ]),
        vec!["router".to_string()]
    );

    // And the empty class travels as nothing at all, so a VM written
    // before the field has a spec that is byte-identical to what it was.
    let document = serde_json::to_value(&vm).unwrap();
    assert_eq!(document["class"], serde_json::json!("gpu"));
    vm.class = String::new();
    let document = serde_json::to_value(&vm).unwrap();
    assert!(document.get("class").is_none(), "{document}");
    assert!(
        serde_json::to_value(NodeSpec::default())
            .unwrap()
            .get("accepts")
            .is_none()
    );
}

#[test]
fn every_phase_parses_from_its_own_spelling() {
    for phase in [
        VmPhaseKind::Pending,
        VmPhaseKind::Provisioning,
        VmPhaseKind::Running,
        VmPhaseKind::Stopped,
        VmPhaseKind::Paused,
        VmPhaseKind::Failed,
        VmPhaseKind::Quarantined,
    ] {
        assert_eq!(VmPhaseKind::parse(&format!("{phase:?}")), Some(phase));
        assert_eq!(VmPhaseKind::parse(phase.as_str()), Some(phase));
    }
    assert_eq!(VmPhaseKind::parse("running"), None);
    assert_eq!(VmPhaseKind::parse(""), None);
}

/// The generation pair is spelled the way the rest of this API is.
///
/// Both of these statuses were EMPTY structs before they carried a field,
/// so neither had ever needed a rename — and the first field added to
/// them went out as `observed_generation` while every other status said
/// `observedGeneration`. A client reading one convention would have
/// silently read `0` from the other, which is "applied".
#[test]
fn every_status_spells_the_generation_pair_the_same_way() {
    let wire = |status: serde_json::Value| status["observedGeneration"] == serde_json::json!(7);
    assert!(wire(
        serde_json::to_value(VmStatus {
            observed_generation: 7,
            ..Default::default()
        })
        .unwrap()
    ));
    assert!(wire(
        serde_json::to_value(FloatingIpStatus {
            observed_generation: 7
        })
        .unwrap()
    ));
    assert!(wire(
        serde_json::to_value(RoutedSubnetStatus {
            observed_generation: 7
        })
        .unwrap()
    ));
    assert!(wire(
        serde_json::to_value(RouterStatus {
            observed_generation: 7,
            ..Default::default()
        })
        .unwrap()
    ));

    // And it reads back, so an object stored by this version is one this
    // version understands.
    let back: FloatingIpStatus =
        serde_json::from_value(serde_json::json!({"observedGeneration": 7})).unwrap();
    assert_eq!(back.observed_generation, 7);
}

/// Ownership is a fact about the stored object, never about the request.
///
/// It used to be enforced by putting the stored labels back over whatever
/// a client sent — silently. The reading half stays here; the refusal
/// that replaced the silence is `check_owner_labels` at the cluster's
/// update route, because a refusal needs a request to refuse.
#[test]
fn the_cloud_ownership_labels_are_readable_as_one_fact() {
    let mut cloud_owned = Metadata::default();
    cloud_owned.mark_managed_by_cloud("uid-1");
    assert!(cloud_owned.managed_by_cloud());
    assert_eq!(cloud_owned.cloud_uid(), Some("uid-1"));

    let unmarked = Metadata::default();
    assert!(!unmarked.managed_by_cloud());
    assert_eq!(unmarked.cloud_uid(), None);
}

/// One word for `csr ls`, and the order it comes out in. A denial
/// outranks an approval that never produced anything; a certificate
/// outranks the approval that caused it.
#[test]
fn a_request_has_exactly_one_phase_and_the_precedence_is_fixed() {
    let at = Utc::now();
    let cond = |kind| CsrCondition {
        kind,
        reason: String::new(),
        message: String::new(),
        last_update_time: at,
        by: "ops".into(),
    };

    let mut status = CsrStatus::default();
    assert_eq!(status.phase(), "Pending");
    status.set(cond(CsrConditionType::Approved));
    assert_eq!(status.phase(), "Approved");
    status.certificate = Some("-----BEGIN CERTIFICATE-----".into());
    assert_eq!(status.phase(), "Issued");
    status.set(cond(CsrConditionType::Denied));
    assert_eq!(
        status.phase(),
        "Denied",
        "a denial outranks the certificate"
    );

    // Approving twice is approving, not appending: a request is approved
    // once, and a list that grew on every retry would be noise where an
    // audit trail should be.
    let mut twice = CsrStatus::default();
    twice.set(cond(CsrConditionType::Approved));
    twice.set(cond(CsrConditionType::Approved));
    assert_eq!(twice.conditions.len(), 1);
}

/// The list on a user is what credentials EXIST, and one that has died is
/// history rather than a credential.
#[test]
fn a_user_counts_only_the_certificates_that_are_still_alive() {
    let now = Utc::now();
    let cert = |offset_days: i64| IssuedCertificate {
        fingerprint: format!("sha256:{offset_days}"),
        issued_at: now,
        not_after: now + chrono::Duration::days(offset_days),
        serial: String::new(),
        request: String::new(),
    };
    let status = UserStatus {
        certificates: vec![cert(-1), cert(30)],
    };
    assert_eq!(status.live(now).count(), 1);
}

/// Defaults matter here: a user object written with a bare spec must not
/// come back as an administrator.
#[test]
fn a_user_without_a_role_is_a_member() {
    let user: User = serde_json::from_value(serde_json::json!({
        "apiVersion": API_VERSION, "kind": User::KIND,
        "metadata": { "name": "alice" }, "spec": { "tenant": "acme" }
    }))
    .unwrap();
    assert_eq!(user.spec.role, crate::auth::Role::Member);
    assert_eq!(user.spec.role.group(), crate::auth::GROUP_MEMBERS);
    assert!(user.status.certificates.is_empty());
}

/// The signer is named on the request, exactly as K8s names its own: a
/// request for a signer nobody runs must be refusable rather than
/// quietly signed by whoever is listening.
#[test]
fn a_request_without_a_signer_gets_the_only_one_there_is() {
    let csr: CertificateSigningRequest = serde_json::from_value(serde_json::json!({
        "apiVersion": API_VERSION, "kind": CertificateSigningRequest::KIND,
        "metadata": { "name": "alice-1" },
        "spec": { "request": "-----BEGIN CERTIFICATE REQUEST-----", "username": "alice" }
    }))
    .unwrap();
    assert_eq!(csr.spec.signer_name, SIGNER_USER_CLIENT);
    assert_eq!(csr.status.phase(), "Pending");
}

#[test]
fn a_node_without_a_spec_is_schedulable() {
    let node: Node = serde_json::from_value(serde_json::json!({
        "apiVersion": API_VERSION, "kind": Node::KIND,
        "metadata": { "name": "manacor" }, "spec": {}
    }))
    .unwrap();
    assert!(node.spec.schedulable);
    assert!(!node.status.ready);
}

/// Locality is on the pool's STATUS and nowhere in its spec, and that is
/// the whole rule: it is the driver's answer, collected from the nodes
/// that run it, and an admin who could type it into a spec could tell the
/// scheduler that an LVM pool is shared.
#[test]
fn a_pool_states_its_locality_and_cannot_be_told_one() {
    let mut pool = StoragePool::declare(
        "fast",
        StoragePoolSpec {
            driver: "lvm-thin".into(),
            ..Default::default()
        },
    );
    let spec = serde_json::to_value(&pool.spec).unwrap();
    assert!(
        spec.get("locality").is_none(),
        "the spec has no locality and never gets one: {spec}"
    );

    pool.status.assign(StoragePoolPhase::of(
        StoragePoolPhaseKind::Ready,
        Utc::now(),
    ));
    pool.status.locality = Some(Locality::NodeLocal);
    let status = serde_json::to_value(&pool.status).unwrap();
    assert_eq!(status["phase"], "Ready");
    assert_eq!(status["locality"], "node-local");

    // A pool nothing is known about carries neither key, which is what
    // every pool written before this field looks like on the way back in.
    let old: StoragePoolStatus = serde_json::from_str("{}").unwrap();
    assert_eq!(old.phase().kind(), StoragePoolPhaseKind::Pending);
    assert_eq!(old.locality, None);
}

/// A node's localities ride beside the flat catalogue rather than in it,
/// and an old object that has neither still loads.
#[test]
fn a_node_reports_a_locality_per_volume_backend() {
    let capacity: NodeCapacity = serde_json::from_str(
        r#"{"vcpus":8,"memMib":1024,
            "capabilities":["volume/lvm-thin","volume/nfs"],
            "volumeLocalities":{"lvm-thin":"node-local","nfs":"shared"}}"#,
    )
    .unwrap();
    assert_eq!(
        capacity.volume_localities.get("nfs"),
        Some(&Locality::Shared)
    );
    assert_eq!(capacity.capabilities.len(), 2);

    // The fleet's etcd is full of objects from before the field, and
    // "did not say" is not "node-local".
    let old: NodeCapacity =
        serde_json::from_str(r#"{"vcpus":8,"memMib":1024,"gpuProfiles":["nvrm/4q"]}"#).unwrap();
    assert!(old.volume_localities.is_empty());
    assert_eq!(old.capabilities, vec!["nvrm/4q".to_string()]);
}

/// The ephemeral/persistent axis is structural, so the proof is an
/// absence: a Volume object has no way to say it is scratch, and adding
/// one would be a second statement about something the shape already
/// says.
#[test]
fn a_volume_object_cannot_be_declared_ephemeral() {
    let spec = serde_json::to_value(VolumeSpec {
        tenant: "acme".into(),
        pool: "fast".into(),
        size_gib: 10,
        ..Default::default()
    })
    .unwrap();
    assert!(spec.get("ephemeral").is_none());
    // ... and a client that sends one is TOLD, which is what changed:
    // the key used to be dropped in silence, so a person who believed in
    // it went on believing in it. `deny_unknown_fields` is now on every
    // spec type here, and this is one of the sentences it makes.
    let refused =
        serde_json::from_str::<VolumeSpec>(r#"{"pool":"fast","sizeGib":10,"ephemeral":true}"#)
            .expect_err("a field this object does not have");
    assert!(
        refused.to_string().contains("unknown field `ephemeral`"),
        "{refused}"
    );
}

/// The projection the hot-plug rule is written as, on its own.
///
/// Three statements, and each is a different reason: the boot entry never
/// moves because a guest does not survive having its root disk swapped;
/// an inline entry never moves because it is an instance store that came
/// into being with the VM; everything outside `volumes[]` never moves
/// because it was decided when the node took the spec, once.
///
/// Two specs that project the same are two specs an update may go
/// between — which is exactly the comparison `check_owned` makes.
#[test]
fn the_frozen_shape_of_a_vm_is_everything_but_its_pluggable_disks() {
    let boot = serde_json::json!({"volume": "root-1"});
    let data = serde_json::json!({"volume": "data-2"});
    let store = serde_json::json!({"size_bytes": 1});
    let vm = |volumes: serde_json::Value| serde_json::json!({"vcpus": 2, "volumes": volumes});

    // A referenced entry after the first is invisible to the projection,
    // wherever it sits in the list.
    let one = frozen_vm_shape(&vm(serde_json::json!([boot, store])));
    for same in [
        vm(serde_json::json!([boot, store])),
        vm(serde_json::json!([boot, store, data])),
        vm(serde_json::json!([boot, data, store])),
        vm(serde_json::json!([boot, data, store, data])),
    ] {
        assert_eq!(frozen_vm_shape(&same), one);
    }

    // And these four are four different VMs.
    for different in [
        vm(serde_json::json!([data, store])), // another boot disk
        vm(serde_json::json!([boot])),        // the instance store gone
        vm(serde_json::json!([store, boot])), // the boot entry moved
        serde_json::json!({"vcpus": 4, "volumes": [boot, store]}),
    ] {
        assert_ne!(frozen_vm_shape(&different), one);
    }

    // A document with no volumes projects to itself, which is every VM
    // written before any of this and is why the row still refuses them
    // exactly as it always did.
    let bare = serde_json::json!({"vcpus": 2, "boot": {"kind": "firmware"}});
    assert_eq!(frozen_vm_shape(&bare), bare);
    // ... and so does one that is not an object at all.
    assert_eq!(
        frozen_vm_shape(&serde_json::json!(null)),
        serde_json::json!(null)
    );
}

/// The naming seam both tiers ask about, and the empty-vs-absent case is
/// the whole reason it is one function: a `Volume` says "nobody's" with
/// `""` and a `Vm` says it with `None`.
#[test]
fn a_name_means_something_only_inside_its_own_tenant() {
    assert!(same_tenancy("acme", Some("acme")));
    assert!(!same_tenancy("acme", Some("globex")), "somebody else's");
    // The admin's own unscoped estate, spelled two different ways on the
    // two objects, still matches itself.
    assert!(same_tenancy("", None));
    assert!(
        same_tenancy("", Some("")),
        "an empty tenant is no tenant, not a tenant called empty"
    );
    // And neither empty side reaches across into the other.
    assert!(
        !same_tenancy("acme", None),
        "an unscoped vm names no tenant's volume"
    );
    assert!(
        !same_tenancy("", Some("acme")),
        "a member does not get the admin's disks"
    );
}

/// The cloud-init reference, and the one shape that is refused rather
/// than resolved.
#[test]
fn a_vm_names_one_source_for_its_user_data_or_the_spec_is_wrong() {
    let spec = |vm: serde_json::Value| {
        serde_json::from_value::<VmSpec>(serde_json::json!({ "vm": vm })).expect("a spec")
    };

    let from = spec(serde_json::json!({
        "cloud_init": { "user_data_from": { "secret": "db", "key": "password" } }
    }));
    assert_eq!(
        from.user_data_from(),
        Some(("db".to_string(), "password".to_string()))
    );
    assert!(!from.user_data_said_twice());

    // A literal alone is every VM ever written before this field.
    let literal = spec(serde_json::json!({
        "cloud_init": { "user_data": "#cloud-config\n" }
    }));
    assert_eq!(literal.user_data_from(), None);
    assert!(!literal.user_data_said_twice());

    // Both is a spec whose author believes one of them.
    assert!(
        spec(serde_json::json!({
            "cloud_init": {
                "user_data": "#cloud-config\n",
                "user_data_from": { "secret": "db", "key": "password" }
            }
        }))
        .user_data_said_twice()
    );
    // An EMPTY literal beside a reference is not "both": it is the shape
    // a client that filled the struct in gets, and refusing it would
    // refuse the ordinary case.
    assert!(
        !spec(serde_json::json!({
            "cloud_init": {
                "user_data": "",
                "user_data_from": { "secret": "db", "key": "password" }
            }
        }))
        .user_data_said_twice()
    );

    // Half a reference is no reference. Nothing here panics on a document
    // that is not the shape it expects — every one of these is something
    // a client can send.
    for half in [
        serde_json::json!({ "cloud_init": { "user_data_from": {} } }),
        serde_json::json!({ "cloud_init": { "user_data_from": { "secret": "db" } } }),
        serde_json::json!({ "cloud_init": { "user_data_from": { "key": "k" } } }),
        serde_json::json!({ "cloud_init": { "user_data_from": { "secret": "", "key": "k" } } }),
        serde_json::json!({ "cloud_init": { "user_data_from": "db/password" } }),
        serde_json::json!({ "cloud_init": 7 }),
        serde_json::json!({}),
    ] {
        assert_eq!(spec(half.clone()).user_data_from(), None, "{half}");
    }
}

/// The one field of `spec.vm` this control plane reads, and the rule that
/// separates the two kinds of disk: an entry that NAMES a volume refers
/// to an object, an entry that describes one is ephemeral and this tier
/// has nothing to say about it.
#[test]
fn a_vm_spec_names_the_volumes_it_refers_to_and_no_others() {
    let spec = |vm: serde_json::Value| {
        serde_json::from_value::<VmSpec>(serde_json::json!({ "vm": vm })).expect("a spec")
    };
    assert_eq!(
        spec(serde_json::json!({
            "volumes": [
                {"volume": "data-1"},
                {"base_image": "tiny.raw", "size_bytes": 1024},
                {"volume": "data-2", "params": {"tag": "shared"}}
            ]
        }))
        .referenced_volumes(),
        vec!["data-1".to_string(), "data-2".into()],
        "inline entries are ephemeral and are not references"
    );

    // Every VM ever written before the field.
    assert!(
        spec(serde_json::json!({"volumes": [{"size_bytes": 1}]}))
            .referenced_volumes()
            .is_empty()
    );
    // And total: a document that is not a VM at all yields nothing rather
    // than an error, because whether it is one is the edge's question.
    assert!(
        spec(serde_json::json!(null))
            .referenced_volumes()
            .is_empty()
    );
    assert!(spec(serde_json::json!({})).referenced_volumes().is_empty());
    assert!(
        spec(serde_json::json!({"volumes": "not a list"}))
            .referenced_volumes()
            .is_empty()
    );
    assert!(
        spec(serde_json::json!({"volumes": [{"volume": ""}]}))
            .referenced_volumes()
            .is_empty(),
        "an empty name is no name"
    );
}

/// The 422 a person sees while they are still holding the request. The
/// node refuses the same shape — that is the one that cannot be bypassed
/// — but by then it is a Failed VM instead of an answer.
#[test]
fn a_reference_that_also_describes_the_disk_is_named_field_by_field() {
    let spec = |vm: serde_json::Value| {
        serde_json::from_value::<VmSpec>(serde_json::json!({ "vm": vm })).expect("a spec")
    };
    for (field, value) in [
        ("size_bytes", serde_json::json!(2048)),
        ("base_image", serde_json::json!("tiny.raw")),
        ("base_image_url", serde_json::json!("https://x/y.raw")),
        ("base_image_sha256", serde_json::json!("abc")),
        ("driver", serde_json::json!("lvm-thin")),
    ] {
        let entry = serde_json::json!({"volume": "data-1", field: value});
        assert_eq!(
            spec(serde_json::json!({ "volumes": [entry] })).malformed_volume_reference(),
            Some(field),
            "{field} describes a disk the reference already has"
        );
    }

    // `params` is the exception: attach options belong to the connection,
    // and two VMs of one volume may mount it under two names.
    assert_eq!(
        spec(serde_json::json!({
            "volumes": [{"volume": "data-1", "params": {"tag": "data"}}]
        }))
        .malformed_volume_reference(),
        None
    );
    // An inline entry describes a disk because that is what it IS.
    assert_eq!(
        spec(serde_json::json!({
            "volumes": [{"base_image": "tiny.raw", "size_bytes": 2048}]
        }))
        .malformed_volume_reference(),
        None
    );
    // A null is not a statement, and a document that is not a VM at all
    // is somebody else's question.
    assert_eq!(
        spec(serde_json::json!({
            "volumes": [{"volume": "data-1", "base_image": null}]
        }))
        .malformed_volume_reference(),
        None
    );
    assert_eq!(
        spec(serde_json::json!({})).malformed_volume_reference(),
        None
    );
}

/// `status.availableOn` is gone, and gone rather than left empty.
///
/// It meant "not tracked" from v1 on and nothing ever wrote it; since
/// `status.nodes[]` exists, the question it pretended to answer has a
/// real answer beside it. A client that read the empty list and concluded
/// "no cluster has this image" was reading a field, not a fact
/// (fremdsicht 4). Both halves are asserted: the key is not written, and
/// a document that still carries it is refused rather than silently
/// dropped — so an old client hears about it instead of believing the
/// server kept its value.
#[test]
fn an_image_status_neither_writes_nor_accepts_available_on() {
    let written = serde_json::to_value(ImageStatus::default()).expect("serialises");
    assert!(written.get("availableOn").is_none(), "{written}");

    let old = serde_json::json!({"phase": "Ready", "availableOn": ["cluster-1"]});
    let refusal = serde_json::from_value::<ImageStatus>(old)
        .expect_err("a field nobody claims is not silently dropped")
        .to_string();
    assert!(refusal.contains("unknown field `availableOn`"), "{refusal}");
}

/// A drain says what is LEAVING, which is what it can honestly count.
///
/// The field was called `moved` and read like a total. It never was one:
/// what it counted was VMs still on the machine and on their way off it,
/// so a VM that had arrived somewhere else left the count — and a
/// finished drain reported `0 moved, 1 staying (done)` after two VMs had
/// moved (migration D4, seen in the E2E). Now it is named for the
/// snapshot it is, and it carries the names beside the number, the same
/// way `staying` carries `reasons`.
#[test]
fn a_drain_counts_what_is_leaving_and_names_it() {
    let leaving = Draining {
        leaving: 2,
        leaving_vms: vec!["web-1".to_string(), "web-2".to_string()],
        staying: 0,
        reasons: Vec::new(),
        complete: false,
        moved_total: 0,
    };
    let doc = serde_json::to_value(&leaving).expect("serialises");
    assert!(
        doc.get("moved").is_none(),
        "the word that read like a total is gone rather than kept beside the truth: {doc}"
    );
    assert_eq!(doc["leaving"], 2);
    assert_eq!(doc["leavingVms"], serde_json::json!(["web-1", "web-2"]));

    // A drain at rest: nobody is leaving, and the list is absent rather
    // than an empty array — the same rule every other list in this tree
    // follows.
    let done = Draining {
        staying: 1,
        reasons: vec![StayingVm {
            vm: "db-1".to_string(),
            reason: StayReason::NodeLocalDisk.as_str().to_string(),
            message: "db-1 stays: its disk is on this machine".to_string(),
        }],
        complete: true,
        ..Draining::default()
    };
    let doc = serde_json::to_value(&done).expect("serialises");
    assert_eq!(doc["leaving"], 0);
    assert!(doc.get("leavingVms").is_none(), "{doc}");
    assert_eq!(doc["complete"], true);
    // And the number a person means by "how did the drain go" is beside
    // it, absent while it is zero like every other count in this tree.
    assert!(doc.get("movedTotal").is_none(), "{doc}");
    let moved = Draining {
        moved_total: 3,
        complete: true,
        ..Draining::default()
    };
    assert_eq!(
        serde_json::to_value(&moved).expect("serialises")["movedTotal"],
        3
    );
}

/// A typo on the ENVELOPE, asked of every kind in the table.
///
/// `deny_unknown_fields` at every spec type closed the INSIDE of the
/// document and left the outside open: `metdata` was a key nobody
/// claimed, it fell away in silence, and what came back was a complaint
/// about the name being missing. True, and about the wrong thing — the
/// client is left believing the server read a name it never saw. Asked of
/// every kind because the rule is on the generic envelope, and a rule on
/// the envelope is a rule about every resource that wears one.
#[test]
fn a_typo_in_the_envelope_is_named_and_not_swallowed_for_any_kind() {
    fn refusal<T: serde::de::DeserializeOwned>(kind: &str) -> String {
        // Written out rather than built with `json!`, because the order
        // of the keys is part of what is asked: the unknown one comes
        // before `spec`, so what the reader hits first is the typo and
        // not a spec that is missing everything.
        let doc = format!(
            r#"{{"apiVersion":"{API_VERSION}","kind":"{kind}",
                 "metdata":{{"name":"probe"}},"spec":{{}},"status":{{}}}}"#
        );
        match serde_json::from_str::<T>(&doc) {
            Err(e) => e.to_string(),
            Ok(_) => panic!("{kind} accepted an envelope field nobody claims"),
        }
    }

    // One line per row of `resources!`, in its order. The count is
    // asserted below, so a new resource has to be named here too.
    let said: [(&str, String); 20] = [
        ("Vm", refusal::<Vm>("Vm")),
        ("Node", refusal::<Node>("Node")),
        ("Cluster", refusal::<Cluster>("Cluster")),
        ("Image", refusal::<Image>("Image")),
        ("Tenant", refusal::<Tenant>("Tenant")),
        ("User", refusal::<User>("User")),
        (
            "CertificateSigningRequest",
            refusal::<CertificateSigningRequest>("CertificateSigningRequest"),
        ),
        ("Counter", refusal::<Counter>("Counter")),
        ("FloatingPool", refusal::<FloatingPool>("FloatingPool")),
        ("FloatingIp", refusal::<FloatingIp>("FloatingIp")),
        ("RoutedSubnet", refusal::<RoutedSubnet>("RoutedSubnet")),
        (
            "ProviderNetwork",
            refusal::<ProviderNetwork>("ProviderNetwork"),
        ),
        ("Router", refusal::<Router>("Router")),
        ("StoragePool", refusal::<StoragePool>("StoragePool")),
        ("Volume", refusal::<Volume>("Volume")),
        (
            "VolumeSnapshot",
            refusal::<VolumeSnapshot>("VolumeSnapshot"),
        ),
        ("VmMigration", refusal::<VmMigration>("VmMigration")),
        ("Ticket", refusal::<Ticket>("Ticket")),
        ("Secret", refusal::<Secret>("Secret")),
        ("Event", refusal::<Event>("Event")),
    ];
    assert_eq!(
        said.len(),
        ALL_RESOURCES.len(),
        "a resource was added to the table and not to this test"
    );
    for (kind, message) in said {
        assert!(
            message.contains("unknown field `metdata`"),
            "{kind} did not name the typo: {message}"
        );
    }
}

/// The envelope's one rule about `status`, asked of every kind in the
/// table — because `skip_serializing_if` on a generic field is a change
/// to every resource and not to the one that made it worth doing.
///
/// `Secret` and `Event` have no status at all (`St = ()`), and both used
/// to answer every GET with `"status": null` — honest, and still a field
/// a client has to learn to ignore. They are now simply absent. Every
/// other kind keeps its status even when it is entirely default, because
/// `{}` is a status that exists and is empty, which is a different thing.
#[test]
fn only_a_kind_with_no_status_at_all_leaves_the_field_out() {
    fn status_of<St: Serialize + Default>() -> Option<serde_json::Value> {
        let object: Object<serde_json::Value, St> =
            Object::new(API_VERSION, "Probe", "probe", serde_json::json!({}));
        serde_json::to_value(&object)
            .expect("an envelope serialises")
            .get("status")
            .cloned()
    }

    // One line per row of `resources!`, in its order. The count is
    // asserted below, so a new resource has to say which half it is in.
    let with_status: [(&str, Option<serde_json::Value>); 17] = [
        ("Vm", status_of::<VmStatus>()),
        ("Node", status_of::<NodeStatus>()),
        ("Cluster", status_of::<ClusterStatus>()),
        ("Image", status_of::<ImageStatus>()),
        ("Tenant", status_of::<TenantStatus>()),
        ("User", status_of::<UserStatus>()),
        (
            "CertificateSigningRequest",
            status_of::<crate::resources::CsrStatus>(),
        ),
        ("Counter", status_of::<CounterStatus>()),
        ("FloatingPool", status_of::<FloatingPoolStatus>()),
        ("FloatingIp", status_of::<FloatingIpStatus>()),
        ("RoutedSubnet", status_of::<RoutedSubnetStatus>()),
        ("ProviderNetwork", status_of::<ProviderNetworkStatus>()),
        ("Router", status_of::<RouterStatus>()),
        ("StoragePool", status_of::<StoragePoolStatus>()),
        ("Volume", status_of::<VolumeStatus>()),
        ("VolumeSnapshot", status_of::<VolumeSnapshotStatus>()),
        ("VmMigration", status_of::<VmMigrationStatus>()),
    ];
    let without_status = [
        ("Secret", status_of::<()>()),
        ("Ticket", status_of::<()>()),
        ("Event", status_of::<()>()),
    ];
    assert_eq!(
        with_status.len() + without_status.len(),
        ALL_RESOURCES.len(),
        "a resource was added to the table and not to this test"
    );

    for (kind, status) in with_status {
        let status = status.unwrap_or_else(|| panic!("{kind} keeps its status"));
        assert!(!status.is_null(), "{kind} serialised a null status");
    }
    for (kind, status) in without_status {
        assert!(status.is_none(), "{kind} has no status and must show none");
    }
}

/// A typo in a spec field used to be a setting that does not exist.
///
/// `POST /tenants` with `spec.quota = {"vms": 10, ...}` answered 201 and
/// stored `{"vni": 10000}` — the quota simply gone, because the fields
/// are called `maxVms`, `maxVcpus`, `maxMemMib`. Nothing was wrong until
/// a limit did not bite. A form checking against `/schemas` catches it; a
/// `curl` never does.
///
/// So: `deny_unknown_fields` on every spec type in this file and on every
/// type nested inside one, and one line here per type. A new spec type
/// that forgets it fails this test the first time somebody adds a row.
///
/// The one document that is NOT covered by a derive here is `spec.vm`: it
/// is another crate's, it stays a `Value` on the way through, and it is
/// deserialised into `agent_api::spec::NewVmSpec` at the edge instead —
/// which is `deny_unknown_fields` too. See `crate::vm_spec`.
#[test]
fn a_typo_in_a_spec_field_is_a_refusal_and_not_a_setting() {
    fn refuses<T: serde::de::DeserializeOwned>(kind: &str) {
        let Err(e) = serde_json::from_str::<T>(r#"{"maxVmss": 10}"#) else {
            panic!("{kind} took a field it does not have");
        };
        assert!(
            e.to_string().starts_with("unknown field `maxVmss`"),
            "{kind}: {e}"
        );
        // And the sentence names the alternatives, which is the half a
        // person acts on.
        assert!(e.to_string().contains("expected"), "{kind}: {e}");
    }

    refuses::<VmSpec>("VmSpec");
    refuses::<AntiAffinity>("AntiAffinity");
    refuses::<NodeSpec>("NodeSpec");
    refuses::<ClusterSpec>("ClusterSpec");
    refuses::<ImageSpec>("ImageSpec");
    refuses::<EventSpec>("EventSpec");
    refuses::<TenantSpec>("TenantSpec");
    // The one from the report: the quota is a nested object, and denying
    // only at the top level would have left exactly this case open.
    refuses::<TenantQuota>("TenantQuota");
    refuses::<FloatingPoolSpec>("FloatingPoolSpec");
    refuses::<FloatingIpSpec>("FloatingIpSpec");
    refuses::<RoutedSubnetSpec>("RoutedSubnetSpec");
    refuses::<ProviderNetworkSpec>("ProviderNetworkSpec");
    refuses::<RouterSpec>("RouterSpec");
    // Nested inside a router's status, and the reason the nested types are
    // named here at all: denying only at the top level is what let the tenant
    // quota through as an empty object. See `TenantQuota` above.
    refuses::<NatRule>("NatRule");
    refuses::<StoragePoolSpec>("StoragePoolSpec");
    refuses::<VolumeSpec>("VolumeSpec");
    refuses::<VolumeSnapshotSpec>("VolumeSnapshotSpec");
    refuses::<SecretSpec>("SecretSpec");
    refuses::<UserSpec>("UserSpec");
    refuses::<CounterSpec>("CounterSpec");
    refuses::<CsrSpec>("CsrSpec");

    // The very case the console found, whole: a quota nobody typed
    // correctly is now a refusal rather than an empty spec.
    let tenant =
        serde_json::from_str::<TenantSpec>(r#"{"quota":{"vms":10,"vcpus":40,"memMib":65536}}"#)
            .expect_err("the field names are maxVms, maxVcpus, maxMemMib");
    assert!(
        tenant.to_string().contains("unknown field `vms`"),
        "{tenant}"
    );
}

/// D8's field, on the wire an operator and a script both read.
///
/// `type` is a reserved word in Rust and is not one in JSON, and the
/// spelling here is the API's — a client written against `type` must not
/// find `type_`. The other half is the absence: a node that says nothing
/// carries no key at all, so "nothing wrong" and "an agent too old to
/// know" look the same, which is exactly what they are.
#[test]
fn a_node_condition_is_spelled_type_and_message_and_vanishes_when_empty() {
    let mut node = Node::declare("agent-1a", NodeSpec::default());
    node.status.ready = true;
    let quiet = serde_json::to_value(&node).unwrap();
    assert!(
        quiet["status"].get("conditions").is_none(),
        "a healthy node carries no conditions key: {quiet}"
    );

    node.status.conditions = vec![NodeCondition {
        type_: NodeConditionType::StoreUnhealthy.as_str().into(),
        message: "the store took an I/O error and must be re-opened".into(),
    }];
    let wedged = serde_json::to_value(&node).unwrap();
    assert_eq!(wedged["status"]["conditions"][0]["type"], "StoreUnhealthy");
    assert_eq!(
        wedged["status"]["conditions"][0]["message"],
        "the store took an I/O error and must be re-opened"
    );

    // And back, because the cloud's copy of a node is parsed out of json
    // rather than handed over as a struct.
    let back: Node = serde_json::from_value(wedged).unwrap();
    assert_eq!(back.status.conditions, node.status.conditions);

    // The three words, spelled once. A rename here is a rename of the
    // agent's contract and of every dashboard that greps for one.
    assert_eq!(
        NodeConditionType::ALL.map(NodeConditionType::as_str),
        ["DiskPressure", "StoreUnhealthy", "CgroupUnusable"]
    );
    assert_eq!(
        NodeConditionType::parse("DiskPressure"),
        Some(NodeConditionType::DiskPressure)
    );
    // A word from a newer agent is not an error. The node is taken out of
    // the running by the list being non-empty; parsing is only for the
    // short spelling in a table.
    assert_eq!(NodeConditionType::parse("FanFailure"), None);
}
/// The pre-flight check, as a table.
///
/// A live migration does not move a program, it moves a MACHINE STATE — vCPU
/// registers, MSRs, the nested-virtualisation state — and cloud-hypervisor
/// v53 checks the CPUID before a transfer and nothing else. So a mismatch is
/// discovered two milliseconds after the destination's vCPUs are made, in a
/// log line the control plane never reads, after the stream is open and the
/// guest is paused. The lab spent two nights on that (D-X1).
///
/// This is the question asked BEFORE anything is opened. Being wrong in the
/// refusing direction costs nothing — the guest keeps running and a drain
/// moves it by reboot — and being wrong the other way costs a transfer that
/// cannot succeed.
#[test]
fn a_machine_state_is_only_moved_where_it_can_be_restored() {
    use crate::MachineProfile;

    let metal = || MachineProfile {
        cpu_vendor: "GenuineIntel".into(),
        cpu_model: "Intel(R) Xeon(R) Gold 6248R".into(),
        cpu_flags: "fpu lm vmx".into(),
        cpu_profile: "Host".into(),
        hypervisor_version: "cloud-hypervisor v53.0".into(),
        kernel: "6.12.0".into(),
        ..Default::default()
    };
    let refusal = |a: &MachineProfile, b: &MachineProfile| {
        crate::live_migration_refusal("agent-1", a, "agent-2", b)
    };

    // Two machines that are the same machine. Nothing is refused, which is
    // the case that has to keep working or the feature is a fleet that cannot
    // migrate.
    assert_eq!(refusal(&metal(), &metal()), None);

    // **Silence is never a refusal.** An agent from before the field says
    // nothing, and a comparison needs two sides — otherwise a rolling upgrade
    // stops every migration on the fleet halfway through.
    assert_eq!(refusal(&MachineProfile::default(), &metal()), None);
    assert_eq!(refusal(&metal(), &MachineProfile::default()), None);
    assert_eq!(
        refusal(&MachineProfile::default(), &MachineProfile::default()),
        None
    );

    // The vendor. No profile papers over Intel against AMD.
    let amd = MachineProfile {
        cpu_vendor: "AuthenticAMD".into(),
        cpu_model: "AMD EPYC 7543".into(),
        ..metal()
    };
    let why = refusal(&metal(), &amd).expect("not the same make of cpu");
    assert!(why.starts_with("live migration refused:"), "{why}");
    assert!(why.contains("make of cpu"), "{why}");
    assert!(
        why.contains("Xeon(R) Gold 6248R") && why.contains("EPYC 7543"),
        "both machines are named, because an operator has to know which two: {why}"
    );
    assert!(
        why.contains("vm reschedule"),
        "and what to do instead: {why}"
    );

    // The model, within one vendor. v53 pins `profile: Host`, which means
    // "give the guest exactly this machine's cpuid", so two generations are
    // two different machines.
    let older = MachineProfile {
        cpu_model: "Intel(R) Xeon(R) E5-2670".into(),
        ..metal()
    };
    let why = refusal(&metal(), &older).expect("different models");
    assert!(why.contains("different cpu models"), "{why}");
    assert!(why.contains("profile Host"), "and why that matters: {why}");

    // The profile itself, for the day `CpuProfile` has a second variant.
    let downgraded = MachineProfile {
        cpu_profile: "Nehalem".into(),
        ..metal()
    };
    let why = refusal(&metal(), &downgraded).expect("different profiles");
    assert!(why.contains("different cpu profiles"), "{why}");

    // And the one the lab measured. Two nested machines, and nothing that
    // shows they are on one physical host.
    let nested = |host: &str| MachineProfile {
        nested: true,
        hypervisor: "KVM".into(),
        host: host.into(),
        ..metal()
    };
    let why = refusal(&nested(""), &nested("")).expect("cannot be shown to be one host");
    assert!(why.contains("themselves guests"), "{why}");
    assert!(
        why.contains("D-X1"),
        "and where the answer came from: {why}"
    );
    // Named, and different: the same refusal, and now it can say the names.
    let why = refusal(&nested("palma"), &nested("campos")).expect("two hosts");
    assert!(
        why.contains("host palma") && why.contains("host campos"),
        "{why}"
    );
    // Named, and the same. This is the counter-proof the report says only
    // Silas can run, and it is the configuration in which it goes through.
    assert_eq!(refusal(&nested("palma"), &nested("palma")), None);
    // One nested and one not is not the nested rule at all — a nested guest's
    // state moving onto metal is a different question and this does not
    // pretend to answer it.
    assert_eq!(refusal(&nested("palma"), &metal()), None);

    // The kernel and the hypervisor version are named and never refused on
    // alone: a fleet mid-upgrade differs in both and migrates perfectly well.
    let newer = MachineProfile {
        kernel: "6.13.1".into(),
        hypervisor_version: "cloud-hypervisor v54.0".into(),
        ..metal()
    };
    assert_eq!(refusal(&metal(), &newer), None);
}

/// The flat wire form of all seven phases, in one place.
///
/// The whole of decision 1 of struktur 4, and the reason it is one test
/// rather than seven: what a client reads is `status.phase` as a STRING with
/// `reason`, `message` and `since` beside it, and the seven resources must
/// not drift apart about that. The CLI, Tofu, the UI and the chaos harness
/// all read it this way; a tagged enum would have made every one of them read
/// `status.phase.Pending.reason` instead.
#[test]
fn every_status_wears_its_phase_flat() {
    let at = DateTime::from_timestamp(1_800_000_000, 0).expect("an instant");
    let said = |m: &str| Some(m.to_string());

    let mut vm = VmStatus::default();
    vm.assign(VmPhase::new(
        VmPhaseKind::Pending,
        VmReason::Unplaced,
        said("no candidate has room (3 looked at)"),
        at,
    ));
    let mut volume = VolumeStatus::default();
    volume.assign(VolumePhase::new(
        VolumePhaseKind::Releasing,
        VolumeReason::HeldBy,
        said("held by vm web-1"),
        at,
    ));
    let mut snapshot = VolumeSnapshotStatus::default();
    snapshot.assign(VolumeSnapshotPhase::new(
        VolumeSnapshotPhaseKind::Creating,
        VolumeSnapshotReason::Dispatched,
        said("agent-1a was told"),
        at,
    ));
    let mut image = ImageStatus::default();
    image.assign(ImagePhase::new(
        ImagePhaseKind::Pending,
        ImageReason::AwaitingNode,
        said("not fetched by any node yet"),
        at,
    ));
    let mut pool = StoragePoolStatus::default();
    pool.assign(StoragePoolPhase::new(
        StoragePoolPhaseKind::Pending,
        StoragePoolReason::ClusterHasNoPool,
        said("cluster-1 reports no pool named mc-fs"),
        at,
    ));
    let mut router = RouterStatus::default();
    router.assign(RouterPhase::new(
        RouterPhaseKind::Unknown,
        RouterReason::Silent,
        said("node agent-1b last reported 2026-09-15T16:42:25Z"),
        at,
    ));
    let mut migration = VmMigrationStatus::default();
    migration.assign(VmMigrationPhase::new(
        VmMigrationPhaseKind::Failed,
        VmMigrationReason::Abandoned,
        said("the destination was not ready after 120s"),
        at,
    ));

    let four = |status: serde_json::Value, phase: &str, reason: &str, message: &str| {
        assert_eq!(status["phase"], phase, "{status}");
        assert_eq!(status["reason"], reason, "{status}");
        assert_eq!(status["message"], message, "{status}");
        assert_eq!(status["since"], "2027-01-15T08:00:00Z", "{status}");
    };
    let wire = |s: &dyn StatusWire| s.wire();

    four(
        wire(&vm),
        "Pending",
        "Unplaced",
        "no candidate has room (3 looked at)",
    );
    four(wire(&volume), "Releasing", "HeldBy", "held by vm web-1");
    four(
        wire(&snapshot),
        "Creating",
        "Dispatched",
        "agent-1a was told",
    );
    four(
        wire(&image),
        "Pending",
        "AwaitingNode",
        "not fetched by any node yet",
    );
    four(
        wire(&pool),
        "Pending",
        "ClusterHasNoPool",
        "cluster-1 reports no pool named mc-fs",
    );
    four(
        wire(&router),
        "Unknown",
        "Silent",
        "node agent-1b last reported 2026-09-15T16:42:25Z",
    );
    four(
        wire(&migration),
        "Failed",
        "Abandoned",
        "the destination was not ready after 120s",
    );
}

/// One trait so the assertion above can be written once for seven types.
/// Nothing outside this test file has any use for it.
trait StatusWire {
    fn wire(&self) -> serde_json::Value;
}
impl<T: Serialize> StatusWire for T {
    fn wire(&self) -> serde_json::Value {
        serde_json::to_value(self).expect("a status serialises")
    }
}
