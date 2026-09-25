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
    reg.open(None, cluster, &tx, at, None)
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
        digest: String::new(),
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

/// A node's reported digest reaches `ImageNodeState` unchanged, and an empty
/// one — a url image, or a node older than the field — arrives as `None`
/// rather than as an empty claim.
///
/// Astra finding S02, 2026-09-23 (rest a). `first_bound_digest` and
/// `settle_image`'s rule 2b are what DO something with this value; this is
/// only the relay that has to hand them one.
#[test]
fn a_reported_digest_relays_as_some_and_silence_relays_as_none() {
    let said = proto::ImageStateReport {
        name: "nixos.raw".into(),
        phase: "Ready".into(),
        reason: String::new(),
        message: String::new(),
        node: "agent-1a".into(),
        digest: "a".repeat(64),
    };
    let lines = super::inventory::lines_of("cluster-1", "nixos.raw", &[&said], &[]);
    assert_eq!(lines.len(), 1);
    assert_eq!(lines[0].digest.as_deref(), Some("a".repeat(64).as_str()));

    let quiet_on_digest = proto::ImageStateReport {
        digest: String::new(),
        ..said
    };
    let lines = super::inventory::lines_of("cluster-1", "nixos.raw", &[&quiet_on_digest], &[]);
    assert_eq!(lines[0].digest, None, "empty is not a digest of anything");
}

// --- lane 5A: the session that was already talking -------------------------

/// A live session on a certificate that has just been taken back is ended,
/// and the one beside it is not.
///
/// What it must NOT do is take the entry out of the map: the stream's own
/// unwinding is what calls `closed`, and `closed` is what says the cluster
/// is gone. This test holds that line as well, because the day somebody
/// "tidies up" by removing the entry here, the cloud starts listing clusters
/// nobody can reach.
#[tokio::test]
async fn a_session_whose_certificate_was_revoked_is_ended() {
    let reg = SessionRegistry::new();
    let (tx_a, mut rx_a) = mpsc::channel(4);
    let (tx_b, mut rx_b) = mpsc::channel(4);
    reg.open(None, "c1", &tx_a, at(0), Some("aa:bb:01".to_string()));
    reg.open(None, "c2", &tx_b, at(1), Some("cc:dd:02".to_string()));

    // The list is in the spelling `meister-ca` writes and the session in the
    // spelling a certificate parses to. One of them is normalised, and it is
    // the whole point of doing that in one function.
    let list = controller_api::auth::RevocationList {
        serials: ["AABB01".to_string()]
            .into_iter()
            .map(|s| controller_api::auth::normalise_serial(&s))
            .collect(),
        crl_number: Some(4),
        ..Default::default()
    };
    let ended = reg.drop_revoked(&list).await;
    assert_eq!(ended, vec![("c1".to_string(), "aa:bb:01".to_string())]);

    let said = rx_a
        .try_recv()
        .expect("the revoked session was told")
        .expect_err("and told with an error");
    assert!(said.to_string().contains("revoked"), "{said}");
    assert!(
        rx_b.try_recv().is_err(),
        "a session nobody revoked was sent something"
    );
    assert_eq!(
        reg.sessions.lock().unwrap().len(),
        2,
        "the entries belong to the streams; only their unwinding takes them away"
    );
}

/// An anonymous session carries no certificate, so no list can name it.
#[tokio::test]
async fn a_session_without_a_certificate_is_not_revoked_by_an_empty_serial() {
    let reg = SessionRegistry::new();
    let (tx, mut rx) = mpsc::channel(4);
    reg.open(None, "c1", &tx, at(0), None);
    let list = controller_api::auth::RevocationList {
        serials: ["".to_string()].into_iter().collect(),
        ..Default::default()
    };
    assert!(reg.drop_revoked(&list).await.is_empty());
    assert!(rx.try_recv().is_err());
}

/// A complete volume list that names nothing, for the delete-finishing
/// tests below.
fn empty_complete_inventory() -> ClusterStatus {
    ClusterStatus {
        volumes_complete: true,
        snapshots_complete: true,
        ..status(true, &[])
    }
}

/// A volume that is being deleted and was last observed at `observed`.
fn deleting_volume(name: &str, observed: chrono::DateTime<chrono::Utc>) -> controller_api::Volume {
    let mut v = controller_api::resources::new_volume(name, Default::default());
    v.metadata.deletion_timestamp = Some(observed);
    v.status.observed_at = Some(observed);
    v.status.cluster = Some("c1".into());
    v
}

/// Astra round 3, finding R3-F02, the verdict half: whether a complete list
/// that does not name a volume finishes its delete is asked of each revision
/// `finish_delete` is about to remove, and a revision that moved to another
/// cluster, stopped being deleted, or was observed after the report is not
/// concluded about.
#[test]
fn a_delete_is_finished_only_by_a_report_that_is_about_this_revision() {
    let t0 = chrono::Utc::now();
    let at = t0 + chrono::Duration::seconds(5);
    let report = empty_complete_inventory();
    let v = deleting_volume("data", t0);
    assert!(volume_gone(&v, "c1", &report, at));

    let mut moved = v.clone();
    moved.status.cluster = Some("c2".into());
    assert!(!volume_gone(&moved, "c1", &report, at), "moved, not gone");

    let mut alive = v.clone();
    alive.metadata.deletion_timestamp = None;
    assert!(!volume_gone(&alive, "c1", &report, at), "not being deleted");

    let mut fresher = v.clone();
    fresher.status.observed_at = Some(at + chrono::Duration::seconds(1));
    assert!(
        !volume_gone(&fresher, "c1", &report, at),
        "observed after the report was taken"
    );

    let partial = ClusterStatus {
        volumes_complete: false,
        ..empty_complete_inventory()
    };
    assert!(!volume_gone(&v, "c1", &partial, at), "not all of them");
}

async fn delete_test_store() -> EtcdStore {
    let endpoint =
        std::env::var("MEISTER_TEST_ETCD").unwrap_or_else(|_| "http://127.0.0.1:23700".to_string());
    let prefix = format!("/finish-delete-test/{}", uuid::Uuid::new_v4());
    EtcdStore::connect(&[endpoint], &prefix)
        .await
        .expect("an etcd to talk to")
}

/// Astra round 3, finding R3-F02: a volume deleted and recreated under the
/// same name between the listing and the delete is NOT removed. Before the
/// fix the delete went out by name and took the new volume with it.
///
/// `#[ignore]`: needs an etcd (`MEISTER_TEST_ETCD`).
#[tokio::test]
#[ignore = "needs an etcd (MEISTER_TEST_ETCD)"]
async fn a_volume_recreated_under_the_same_name_survives_the_old_delete() {
    let store = delete_test_store().await;
    let t0 = chrono::Utc::now();
    let listed = store
        .create(&deleting_volume("data", t0))
        .await
        .expect("the old volume");
    store
        .delete::<controller_api::Volume>("data")
        .await
        .expect("the old volume goes");
    let fresh = store
        .create(&controller_api::resources::new_volume(
            "data",
            Default::default(),
        ))
        .await
        .expect("a new volume under the same name");

    let report = empty_complete_inventory();
    finish_volume_delete(
        &store,
        &listed,
        "c1",
        &report,
        t0 + chrono::Duration::seconds(5),
    )
    .await
    .expect("finishing the delete");

    let still: controller_api::Volume = store.get("data").await.expect("the new volume");
    assert_eq!(still.metadata.uid, fresh.metadata.uid);
}

/// Astra round 3, finding R3-F02: a revision written after the listing is
/// judged again. An observation newer than the report undoes the verdict, so
/// nothing is deleted; a write that leaves the verdict standing (here a
/// label) only costs a retry, and the delete then lands.
///
/// `#[ignore]`: needs an etcd (`MEISTER_TEST_ETCD`).
#[tokio::test]
#[ignore = "needs an etcd (MEISTER_TEST_ETCD)"]
async fn a_delete_after_a_concurrent_write_judges_the_fresh_revision() {
    let store = delete_test_store().await;
    let t0 = chrono::Utc::now();
    let at = t0 + chrono::Duration::seconds(5);
    let report = empty_complete_inventory();

    let listed = store
        .create(&deleting_volume("fresher", t0))
        .await
        .expect("a volume");
    store
        .mutate::<controller_api::Volume, _>("fresher", |v| {
            v.status.observed_at = Some(at + chrono::Duration::seconds(1));
        })
        .await
        .expect("a later observation");
    finish_volume_delete(&store, &listed, "c1", &report, at)
        .await
        .expect("finishing the delete");
    store
        .get::<controller_api::Volume>("fresher")
        .await
        .expect("a fresher observation keeps it");

    let listed = store
        .create(&deleting_volume("touched", t0))
        .await
        .expect("a volume");
    store
        .mutate::<controller_api::Volume, _>("touched", |v| {
            v.metadata.labels.insert("k".into(), "v".into());
        })
        .await
        .expect("an unrelated write");
    finish_volume_delete(&store, &listed, "c1", &report, at)
        .await
        .expect("finishing the delete");
    assert!(matches!(
        store.get::<controller_api::Volume>("touched").await,
        Err(StoreError::NotFound(_))
    ));
}

/// Astra round 3, finding R3-F02, for snapshots: the same guarded delete, so
/// a snapshot recreated under the same name survives the old one's delete.
///
/// `#[ignore]`: needs an etcd (`MEISTER_TEST_ETCD`).
#[tokio::test]
#[ignore = "needs an etcd (MEISTER_TEST_ETCD)"]
async fn a_snapshot_recreated_under_the_same_name_survives_the_old_delete() {
    let store = delete_test_store().await;
    let t0 = chrono::Utc::now();
    let spec = controller_api::VolumeSnapshotSpec {
        volume: "data".into(),
        ..Default::default()
    };
    let mut old = controller_api::resources::new_volume_snapshot("snap", spec.clone());
    old.metadata.deletion_timestamp = Some(t0);
    let listed = store.create(&old).await.expect("the old snapshot");
    store
        .delete::<controller_api::VolumeSnapshot>("snap")
        .await
        .expect("the old snapshot goes");
    let fresh = store
        .create(&controller_api::resources::new_volume_snapshot(
            "snap", spec,
        ))
        .await
        .expect("a new snapshot under the same name");

    let report = empty_complete_inventory();
    finish_snapshot_delete(
        &store,
        &listed,
        "c1",
        &report,
        t0 + chrono::Duration::seconds(5),
    )
    .await
    .expect("finishing the delete");
    let still: controller_api::VolumeSnapshot = store.get("snap").await.expect("the new one");
    assert_eq!(still.metadata.uid, fresh.metadata.uid);
}

/// A vm bound to `cluster`, for the rebind tests below.
fn bound_vm(name: &str, cluster: &str) -> Vm {
    let mut v = controller_api::resources::new_vm(
        name,
        controller_api::VmSpec {
            class: Default::default(),
            cluster_selector: Default::default(),
            node_selector: Default::default(),
            anti_affinity: Vec::new(),
            node_name: None,
            cluster_name: Some(cluster.to_string()),
            run_strategy: controller_api::RunStrategy::Stopped,
            evacuation: Default::default(),
            tenant: None,
            vm: serde_json::json!({}),
        },
    );
    v.metadata.uid = format!("u-{name}");
    v
}

/// Astra round 3, finding R3-F03: the cloud's `ingest_phases` matched the
/// report to a vm of a stale listing and wrote BY NAME, so a delayed report
/// from the old cluster landed on a vm that had meanwhile been rebound, and
/// one about a deleted vm landed on a new vm recreated under its name. The
/// write now pins the uid and asks the binding again of the object it read.
///
/// `#[ignore]`: needs an etcd (`MEISTER_TEST_ETCD`).
#[tokio::test]
#[ignore = "needs an etcd (MEISTER_TEST_ETCD)"]
async fn a_report_from_the_old_cluster_does_not_land_after_a_rebind_or_a_recreate() {
    let store = delete_test_store().await;
    let ours = |v: &Vm| v.spec.cluster_name.as_deref() == Some("c1");
    let report = |uid: &str| ClusterStatus {
        vms: vec![VmStatusReport {
            id: uid.to_string(),
            phase: "Failed".into(),
            message: String::new(),
            attached_volumes: Vec::new(),
            node: String::new(),
            volumes: Vec::new(),
            reason: String::new(),
            nics: Vec::new(),
        }],
        ..status(true, &[])
    };

    // Rebound: the listing says c1, the store says c2 by the time it lands.
    let listed = vec![store.create(&bound_vm("web", "c1")).await.expect("the vm")];
    store
        .mutate::<Vm, _>("web", |v| v.spec.cluster_name = Some("c2".into()))
        .await
        .expect("rebound to c2");
    ingest_phases(&store, "c1", &report("u-web"), &listed, ours, at(10)).await;
    let after: Vm = store.get("web").await.expect("the vm");
    assert!(
        after.status.reported.is_none(),
        "c1's word must not land on a vm now bound to c2: {:?}",
        after.status.reported
    );

    // Recreated: same name, same binding, another uid.
    let listed = vec![store.create(&bound_vm("db", "c1")).await.expect("the vm")];
    store.delete::<Vm>("db").await.expect("the old vm goes");
    let mut fresh = bound_vm("db", "c1");
    fresh.metadata.uid = "u-db-2".into();
    store
        .create(&fresh)
        .await
        .expect("a new vm under the same name");
    ingest_phases(&store, "c1", &report("u-db"), &listed, ours, at(10)).await;
    let after: Vm = store.get("db").await.expect("the new vm");
    assert_eq!(after.metadata.uid, "u-db-2");
    assert!(
        after.status.reported.is_none(),
        "a report about the old uid must not land on the new vm: {:?}",
        after.status.reported
    );
}

/// Astra round 3, finding R3-F03, the placement half: the node, the disks and
/// the MAC lines from the old cluster do not land on a rebound vm either.
///
/// `#[ignore]`: needs an etcd (`MEISTER_TEST_ETCD`).
#[tokio::test]
#[ignore = "needs an etcd (MEISTER_TEST_ETCD)"]
async fn a_placement_from_the_old_cluster_does_not_land_after_a_rebind() {
    let store = delete_test_store().await;
    let ours = |v: &Vm| v.spec.cluster_name.as_deref() == Some("c1");
    let listed = vec![store.create(&bound_vm("web", "c1")).await.expect("the vm")];
    store
        .mutate::<Vm, _>("web", |v| v.spec.cluster_name = Some("c2".into()))
        .await
        .expect("rebound to c2");
    let report = ClusterStatus {
        vms: vec![VmStatusReport {
            id: "u-web".into(),
            phase: "Running".into(),
            message: String::new(),
            attached_volumes: Vec::new(),
            node: "old-node".into(),
            volumes: Vec::new(),
            reason: String::new(),
            nics: Vec::new(),
        }],
        ..status(true, &[])
    };
    ingest_placements(&store, "c1", &report, &listed, ours).await;
    let after: Vm = store.get("web").await.expect("the vm");
    assert_eq!(after.status.node_name, None, "{:?}", after.status.node_name);
}
