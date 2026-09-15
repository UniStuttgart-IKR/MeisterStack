// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! The session's tests, verbatim out of `session.rs`. The module path is
//! unchanged (`session::tests`), so every test still answers to the name it
//! had before.

use super::ingest::*;
use super::*;
use proto::{ClusterCapacity, VmStatusReport};

/// The cluster is the only party that knows any of this, so the cloud
/// copies it word for word rather than rewording it — a tier that
/// reworded it would be a tier that could get it wrong.
#[test]
fn a_reported_node_reaches_the_cluster_object_unchanged() {
    let reported = proto::NodeReport {
        name: "manacor".into(),
        ready: true,
        schedulable: false,
        drain: true,
        labels: [("zone".to_string(), "a".to_string())]
            .into_iter()
            .collect(),
        vcpus: 32,
        mem_mib: 65_536,
        capabilities: vec!["nvrm/4q".into()],
        accepts: vec!["router".into()],
        vms: 3,
        conditions: vec![proto::NodeCondition {
            r#type: "DiskPressure".into(),
            message: "/var/lib/meisterstack has no room left".into(),
        }],
        draining: None,
        images_complete: false,
    };
    let kept = node_summary(&reported);
    assert_eq!(kept.name, "manacor");
    assert!(kept.ready);
    assert!(!kept.schedulable, "the drain travels up with the rest");
    assert_eq!(kept.labels["zone"], "a");
    assert_eq!((kept.vcpus, kept.mem_mib, kept.vms), (32, 65_536, 3));
    assert_eq!(kept.capabilities, vec!["nvrm/4q".to_string()]);
    // And the node's own word about itself, which is what tells a wedged
    // machine from a healthy one at the tier that places on clusters.
    assert_eq!(kept.conditions.len(), 1);
    assert_eq!(kept.conditions[0].type_, "DiskPressure");
    assert_eq!(
        kept.conditions[0].message,
        "/var/lib/meisterstack has no room left"
    );
    assert_eq!(
        kept.draining, None,
        "and a machine nobody is emptying has no evidence to carry"
    );

    // The evidence half, word for word — the cluster owns the object and
    // this tier holds no second opinion about it.
    let draining = proto::NodeReport {
        draining: Some(proto::DrainingReport {
            leaving: 1,
            leaving_vms: vec!["web-2".into()],
            moved_total: 4,
            staying: 1,
            complete: false,
            reasons: vec![proto::StayingVm {
                vm: "db-1".into(),
                reason: "evacuation-never".into(),
                message: "its owner said evacuation: never".into(),
            }],
        }),
        ..reported
    };
    assert_eq!(
        node_summary(&draining).draining,
        Some(controller_api::Draining {
            leaving: 1,
            leaving_vms: vec!["web-2".into()],
            moved_total: 4,
            staying: 1,
            complete: false,
            reasons: vec![controller_api::StayingVm {
                vm: "db-1".into(),
                reason: "evacuation-never".into(),
                message: "its owner said evacuation: never".into(),
            }],
        })
    );
}

/// Reaching the cluster is what can fail here, and the sentence has to
/// name it: `vm_logs` and the node PATCH both turn this into the same 503,
/// and an operator reading it has to know which cluster is away.
#[tokio::test]
async fn a_cluster_with_no_session_is_named_in_the_refusal() {
    let registry = SessionRegistry::new();
    let e = registry
        .send_command(
            "cluster-1",
            "",
            cloud_command::Op::UpdateNode(proto::UpdateNode {
                name: "manacor".into(),
                schedulable: Some(false),
                drain: None,
                labels: Default::default(),
                remove_labels: Vec::new(),
                accepts: None,
            }),
        )
        .await
        .expect_err("nothing is connected");
    assert!(e.to_string().contains("cluster-1"), "{e}");
    assert!(e.to_string().contains("no active session"), "{e}");
}

fn status(complete: bool, uids: &[&str]) -> ClusterStatus {
    ClusterStatus {
        nodes: Vec::new(),
        routers: Vec::new(),
        routers_complete: true,
        nodes_ready: 1,
        nodes_total: 1,
        capacity: Some(ClusterCapacity::default()),
        vms: uids
            .iter()
            .map(|u| VmStatusReport {
                id: (*u).to_string(),
                phase: "Running".into(),
                message: String::new(),
                attached_volumes: Vec::new(),
                node: String::new(),
                volumes: Vec::new(),
                reason: String::new(),
                nics: Vec::new(),
            })
            .collect(),
        vms_complete: complete,
        // No volumes and no pools in this fixture: what it exercises is
        // the VM half, and an empty COMPLETE volume list would be a
        // statement about volumes it never made.
        volumes: Vec::new(),
        volumes_complete: false,
        snapshots: Vec::new(),
        snapshots_complete: false,
        secrets: Vec::new(),
        pools: Vec::new(),
        images: Vec::new(),
    }
}

fn at(secs: i64) -> DateTime<Utc> {
    DateTime::from_timestamp(1_800_000_000 + secs, 0).unwrap()
}

/// The absence proof a cross-cluster reschedule waits on, and everything
/// it is careful NOT to conclude.
///
/// The question is never "does this VM exist" — absence answers that for
/// nobody — but "does this cluster still name this VM", and only a list
/// the cluster itself calls complete answers it.
#[test]
fn only_a_complete_list_proves_a_vm_has_left_its_cluster() {
    let vm = |name: &str, uid: &str, bound: Option<&str>, reported: Option<&str>| {
        let mut v = controller_api::resources::new_vm(
            name,
            controller_api::VmSpec {
                class: Default::default(),
                cluster_selector: Default::default(),
                node_selector: Default::default(),
                anti_affinity: Vec::new(),
                node_name: None,
                cluster_name: bound.map(str::to_string),
                run_strategy: controller_api::RunStrategy::Stopped,
                evacuation: Default::default(),
                tenant: None,
                vm: serde_json::json!({}),
            },
        );
        v.metadata.uid = uid.to_string();
        v.status.cluster_name = reported.map(str::to_string);
        v
    };

    // The one that is leaving: no binding, and cluster-1 still named as
    // where it last was.
    let leaving = vm("moving", "u-move", None, Some("cluster-1"));
    // Still bound there — untouched however silent its cluster is.
    let staying = vm("staying", "u-stay", Some("cluster-1"), Some("cluster-1"));
    // Never placed anywhere: nothing to leave.
    let fresh = vm("fresh", "u-fresh", None, None);
    // Leaving a DIFFERENT cluster. cluster-1's list says nothing about it.
    let elsewhere = vm("elsewhere", "u-else", None, Some("cluster-2"));
    let vms = vec![leaving, staying, fresh, elsewhere];

    let named =
        |v: Vec<&Vm>| -> Vec<String> { v.into_iter().map(|v| v.metadata.name.clone()).collect() };

    // An empty COMPLETE list is the interesting case and the one the
    // early return in `ingest_status` used to swallow: a cluster that has
    // just let go of the last VM it had names none.
    assert_eq!(
        named(leaving_cluster(&vms, "cluster-1", &status(true, &[]))),
        vec!["moving".to_string()]
    );

    // Still named: the destroy has not landed yet, and nothing is
    // concluded.
    assert!(leaving_cluster(&vms, "cluster-1", &status(true, &["u-move"])).is_empty());

    // Incomplete says nothing at all, however short the list is.
    assert!(leaving_cluster(&vms, "cluster-1", &status(false, &[])).is_empty());

    // And another cluster's complete list is another cluster's business.
    assert_eq!(
        named(leaving_cluster(&vms, "cluster-2", &status(true, &[]))),
        vec!["elsewhere".to_string()]
    );
}

/// The voice as the registry would pick it at a given instant. The tests
/// run on a fixed clock so that a silence is a silence and not a race.
fn voice(reg: &SessionRegistry, cluster: &str, now: DateTime<Utc>) -> Option<u64> {
    SessionRegistry::speaker(&reg.sessions.lock().unwrap(), cluster, now)
}

fn uids(reg: &SessionRegistry, cluster: &str, now: DateTime<Utc>) -> Option<HashSet<String>> {
    reg.report_at(cluster, now).map(|r| r.uids)
}

/// A session, as far as the registry is concerned: a channel nobody reads.
fn dial(reg: &SessionRegistry, cluster: &str, at: DateTime<Utc>) -> u64 {
    let (tx, rx) = mpsc::channel(1);
    // The receiver has to outlive the test or the sender reports closed;
    // leaking it is cheaper than threading it through every assertion.
    Box::leak(Box::new(rx));
    reg.open(None, cluster, &tx, at)
}

/// The blocker this whole re-keying exists for: three replicas of one
/// cluster used to overwrite each other, so the second Hello silently
/// unplugged the first.
#[test]
fn three_replicas_of_a_cluster_are_three_sessions_of_one_group() {
    let reg = SessionRegistry::new();
    let ids: Vec<u64> = (0..3).map(|i| dial(&reg, "c1", at(i))).collect();
    assert_eq!(reg.sessions.lock().unwrap().len(), 3);
    assert_eq!(reg.connected(), ["c1".to_string()].into_iter().collect());

    // Losing one leaves the others standing, and the cluster stays up
    // until the last of them has gone.
    assert_eq!(reg.close(ids[2]), None);
    assert_eq!(reg.close(ids[0]), None);
    assert_eq!(reg.connected(), ["c1".to_string()].into_iter().collect());
    assert_eq!(reg.close(ids[1]).as_deref(), Some("c1"));
    assert!(reg.connected().is_empty());
    // and a session that already left cannot report its cluster down twice
    assert_eq!(reg.close(ids[1]), None);
}

/// One voice per cluster, and it is the newest session that has actually
/// spoken: within one stream the cluster's answers are ordered against our
/// commands, between two streams they are not (see `speaker`). A newcomer
/// takes the voice with its first status rather than on its Hello, so the
/// handover lands on a list that was just built.
#[test]
fn the_voice_is_the_newest_session_that_has_spoken() {
    let reg = SessionRegistry::new();
    let old = dial(&reg, "c1", at(0));
    let new = dial(&reg, "c1", at(1));

    // Nobody has spoken yet, so the first to speak is listened to.
    assert!(reg.record_report(old, &status(true, &["uid-a"]), at(2)));
    assert_eq!(
        uids(&reg, "c1", at(2)),
        Some(["uid-a".to_string()].into_iter().collect())
    );

    // The newer session speaks up: it takes the voice, and its own list is
    // what the cloud reasons with from here.
    assert!(reg.record_report(new, &status(true, &["uid-b"]), at(3)));
    assert_eq!(
        uids(&reg, "c1", at(3)),
        Some(["uid-b".to_string()].into_iter().collect())
    );

    // The demoted one is a heartbeat now, and stops holding evidence — so
    // that taking the voice back can only ever start from "unknown".
    assert!(!reg.record_report(old, &status(true, &["uid-a"]), at(4)));
    assert_eq!(
        uids(&reg, "c1", at(4)),
        Some(["uid-b".to_string()].into_iter().collect())
    );
    assert_eq!(reg.close(new), None);
    assert_eq!(
        uids(&reg, "c1", at(5)),
        None,
        "the voice changed hands; nothing is known yet"
    );
}

/// The half of the voice rule that keeps a wedged replica from taking its
/// cluster with it: a cluster-controller on the minority side of an etcd
/// partition holds its session open and says nothing, while its healthy
/// siblings keep the heartbeat fresh — so silence, not liveness, has to be
/// what moves the voice on.
#[test]
fn a_session_that_falls_silent_yields_the_voice_to_one_that_has_not() {
    let reg = SessionRegistry::new();
    let healthy = dial(&reg, "c1", at(0));
    let wedged = dial(&reg, "c1", at(1)); // newer Hello

    // Both talk once, so the newer one holds the voice.
    assert!(reg.record_report(wedged, &status(true, &["uid-a"]), at(2)));
    assert!(!reg.record_report(healthy, &status(true, &["uid-a"]), at(3)));
    assert_eq!(voice(&reg, "c1", at(3)), Some(wedged));

    // Now the wedged one goes quiet — session open, store unreadable, so
    // nothing on the wire — while the healthy one keeps reporting.
    assert_eq!(
        voice(&reg, "c1", at(2 + MUTE_AFTER_SECS)),
        Some(wedged),
        "a gap inside the tolerance must not move the voice"
    );
    assert!(reg.record_report(healthy, &status(true, &["uid-b"]), at(3 + MUTE_AFTER_SECS)));
    assert_eq!(voice(&reg, "c1", at(3 + MUTE_AFTER_SECS)), Some(healthy));
    // and the cloud now reasons about the cluster from the replica that
    // can actually read it
    assert_eq!(
        uids(&reg, "c1", at(3 + MUTE_AFTER_SECS)),
        Some(["uid-b".to_string()].into_iter().collect())
    );

    // A group where nobody has spoken at all still has a voice: the newest
    // Hello holds it, and the wait for its first status is the honest one.
    let quiet = SessionRegistry::new();
    let first = dial(&quiet, "c2", at(0));
    let second = dial(&quiet, "c2", at(1));
    assert_eq!(voice(&quiet, "c2", at(9999)), Some(second));
    assert_ne!(voice(&quiet, "c2", at(9999)), Some(first));
}

/// Grouping is by name and the entries are per connection: two clusters
/// never see each other's sessions, and one cluster's speaker is not the
/// other's.
#[test]
fn groups_do_not_reach_into_each_other() {
    let reg = SessionRegistry::new();
    let c1 = dial(&reg, "c1", at(0));
    let c2 = dial(&reg, "c2", at(1));
    assert!(reg.record_report(c1, &status(true, &["uid-a"]), at(2)));
    assert!(reg.record_report(c2, &status(true, &[]), at(2)));
    assert_eq!(reg.report("c1").unwrap().uids.len(), 1);
    assert!(reg.report("c2").unwrap().uids.is_empty());
    assert_eq!(reg.close(c1).as_deref(), Some("c1"));
    assert!(
        reg.report("c2").is_some(),
        "c1 leaving says nothing about c2"
    );
}

/// The whole teardown proof rests on this: a list the cluster could not
/// build completely must leave the cloud knowing nothing, not knowing an
/// empty set. "Unknown" blocks a delete; "empty" would authorise it.
#[test]
fn an_incomplete_report_is_forgotten_rather_than_believed() {
    let reg = SessionRegistry::new();
    let id = dial(&reg, "c1", at(0));
    reg.record_report(id, &status(true, &["uid-a", "uid-b"]), at(1));
    assert_eq!(reg.report("c1").unwrap().uids.len(), 2);

    reg.record_report(id, &status(false, &[]), at(2));
    assert!(
        reg.report("c1").is_none(),
        "an incomplete list must not stand as a fact"
    );
}

#[test]
fn a_cluster_nobody_reported_on_is_unknown_not_empty() {
    let reg = SessionRegistry::new();
    assert!(reg.report("c1").is_none());
    dial(&reg, "c1", at(0));
    assert!(
        reg.report("c1").is_none(),
        "a fresh session has told us nothing yet"
    );
}

/// D-C7 one tier up: two reports that say the same thing are one write, and
/// it is the lease.
///
/// The same rule the cluster applies to a node, applied by the cloud to a
/// cluster, and it is worth its own test because the objects are different
/// sizes and the same mistake: a `Cluster` carries its whole node list, so a
/// beat that rewrote it rewrote every `NodeSummary` with it.
#[test]
fn a_second_cluster_report_that_says_the_same_thing_writes_no_revision() {
    use super::ingest::cluster_facts_are_news;

    let summary = |name: &str, ready: bool| controller_api::NodeSummary {
        name: name.to_string(),
        ready,
        ..Default::default()
    };
    let nodes = vec![summary("agent-1a", true), summary("agent-1b", true)];
    let capacity = proto::ClusterCapacity {
        vcpus: 16,
        mem_mib: 32768,
        capabilities: vec!["network/vxlan".to_string()],
    };

    // A cluster nobody has heard from: the first report is news, because
    // `connected` is what it changes.
    let mut status = controller_api::ClusterStatus::default();
    assert!(cluster_facts_are_news(
        &status,
        2,
        2,
        3,
        &nodes,
        Some(&capacity)
    ));

    // What that report left behind.
    status.connected = true;
    status.nodes_ready = 2;
    status.nodes_total = 2;
    status.vms = 3;
    status.nodes = nodes.clone();
    status.capacity.vcpus = 16;
    status.capacity.mem_mib = 32768;
    status.capacity.capabilities = vec!["network/vxlan".to_string()];

    // The second, identical one: nothing.
    assert!(
        !cluster_facts_are_news(&status, 2, 2, 3, &nodes, Some(&capacity)),
        "the same report twice is one write"
    );

    // And each fact on its own is still news.
    assert!(cluster_facts_are_news(
        &status,
        1,
        2,
        3,
        &nodes,
        Some(&capacity)
    ));
    assert!(cluster_facts_are_news(
        &status,
        2,
        2,
        4,
        &nodes,
        Some(&capacity)
    ));
    let one_down = vec![summary("agent-1a", true), summary("agent-1b", false)];
    assert!(
        cluster_facts_are_news(&status, 2, 2, 3, &one_down, Some(&capacity)),
        "a node that went not-ready is news even while the counts agree"
    );
    assert!(cluster_facts_are_news(
        &status,
        2,
        2,
        3,
        &nodes,
        Some(&proto::ClusterCapacity {
            vcpus: 32,
            ..capacity.clone()
        })
    ));

    // A report with no capacity block says nothing about capacity, and
    // nothing is what it writes.
    assert!(!cluster_facts_are_news(&status, 2, 2, 3, &nodes, None));
}

/// F16's second half, at the seam where it is decided: a node that has listed
/// EVERY file under its image directory and not named this one has said the
/// file is not there.
///
/// It is the only evidence that ever exists for a path image nothing uses.
/// There is no command that asks a node about an image — `SyncState` carries
/// VMs — so such an entry got silence, and silence used to read `Ready`.
///
/// The asymmetry is the whole of the guard: an INCOMPLETE report contributes
/// nothing at all, because an agent from before the field, a directory that
/// could not be read and a heartbeat with no lists are all silence, and
/// reading any of them as "the file is gone" would fail a working image.
#[test]
fn a_complete_inventory_that_does_not_name_an_image_says_the_file_is_not_there() {
    let complete = |name: &str, images_complete: bool| proto::NodeReport {
        name: name.into(),
        images_complete,
        ..Default::default()
    };
    let saw = |node: &str, phase: &str, reason: &str| proto::ImageStateReport {
        name: "debian.raw".into(),
        phase: phase.into(),
        reason: reason.into(),
        message: String::new(),
        node: node.into(),
    };

    // Nobody said anything about the image, and both nodes listed everything
    // they have: two lines, both NotFound.
    let nodes = [complete("agent-1a", true), complete("agent-1b", true)];
    let names: Vec<&str> = nodes
        .iter()
        .filter(|n| n.images_complete)
        .map(|n| n.name.as_str())
        .collect();
    let lines = super::inventory::lines_of("cluster-1", "debian.raw", &[], &names);
    assert_eq!(lines.len(), 2);
    assert!(
        lines
            .iter()
            .all(|l| l.phase == controller_api::ImagePhaseKind::Failed
                && l.reason == controller_api::ImageReason::NotFound)
    );
    assert_eq!(
        lines[0].message.as_deref(),
        Some("agent-1a has no file named debian.raw")
    );

    // One of them has the bytes: its own word wins over its silence, because
    // it did not stay silent.
    let said = saw("agent-1a", "Ready", "");
    let lines = super::inventory::lines_of("cluster-1", "debian.raw", &[&said], &names);
    assert_eq!(lines.len(), 2);
    assert_eq!(lines[0].phase, controller_api::ImagePhaseKind::Ready);
    assert_eq!(lines[1].reason, controller_api::ImageReason::NotFound);

    // And a node that is not saying whether its list is complete contributes
    // nothing, however loudly it says nothing.
    let quiet = [complete("agent-1a", false)];
    let names: Vec<&str> = quiet
        .iter()
        .filter(|n| n.images_complete)
        .map(|n| n.name.as_str())
        .collect();
    assert!(
        super::inventory::lines_of("cluster-1", "debian.raw", &[], &names).is_empty(),
        "an incomplete inventory is silence, not absence"
    );
}
