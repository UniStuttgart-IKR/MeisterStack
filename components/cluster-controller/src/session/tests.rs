// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! The session's tests, verbatim out of `session.rs`. The module path is
//! unchanged (`session::tests`), so every test still answers to the name it
//! had before.

use super::*;

use std::sync::atomic::{AtomicUsize, Ordering};

fn vm(uid: &str) -> Vm {
    let mut vm = controller_api::resources::new_vm(
        uid,
        controller_api::VmSpec {
            class: Default::default(),
            cluster_selector: Default::default(),
            node_selector: Default::default(),
            anti_affinity: Vec::new(),
            node_name: None,
            cluster_name: None,
            run_strategy: Default::default(),
            evacuation: Default::default(),
            tenant: None,
            vm: serde_json::json!({}),
        },
    );
    vm.metadata.uid = uid.to_string();
    vm
}

fn line(uid: &str) -> proto::VmStatusReport {
    proto::VmStatusReport {
        id: uid.into(),
        phase: "Running".into(),
        message: String::new(),
        attached_volumes: Vec::new(),
        node: String::new(),
        volumes: Vec::new(),
        pending_reason: String::new(),
        nics: Vec::new(),
    }
}

/// The N+1 this exists to stop: every agent reports every ten seconds and
/// every report needs the same list, so the reports that overlap share
/// one read of it — and a read older than the window is not reused.
#[tokio::test(start_paused = true)]
async fn the_vm_list_is_read_once_for_the_reports_that_overlap() {
    let index = VmIndex::default();
    let reads = AtomicUsize::new(0);
    let fetch = || async {
        reads.fetch_add(1, Ordering::SeqCst);
        Ok(vec![vm("uid-a")])
    };

    let (first, fresh) = index.list(fetch).await.unwrap();
    assert!(fresh, "nothing to reuse yet");
    assert_eq!(reads.load(Ordering::SeqCst), 1);

    let (second, fresh) = index.list(fetch).await.unwrap();
    assert!(!fresh, "and the caller is told it is a reused list");
    assert_eq!(reads.load(Ordering::SeqCst), 1, "fifty agents, one read");
    assert_eq!(first[0].metadata.uid, second[0].metadata.uid);

    // ... and the window is far shorter than the ten seconds between two
    // reports of the same agent, so nobody's next report reads a stale one
    tokio::time::advance(VM_INDEX_TTL).await;
    assert!(index.list(fetch).await.unwrap().1);
    assert_eq!(reads.load(Ordering::SeqCst), 2);

    // an unknown uid forces a read whatever the clock says
    index.refresh(fetch).await.unwrap();
    assert_eq!(reads.load(Ordering::SeqCst), 3);
}

/// The one thing a reused list can get wrong is what it does not contain,
/// and dropping such a report is exactly what this tier does with an
/// unknown uid — so an unknown uid, and only that, buys a re-read.
#[test]
fn an_uid_the_list_cannot_name_is_what_makes_it_worth_re_reading() {
    let known = [vm("uid-a"), vm("uid-b")];
    assert!(all_known(&known, &[line("uid-a"), line("uid-b")]));
    assert!(all_known(&known, &[]));
    // the VM created since the list was read
    assert!(!all_known(&known, &[line("uid-a"), line("uid-new")]));
    assert!(!all_known(&[], &[line("uid-a")]));
}

/// Fund 5, checked and refuted: a second Hello for a node that already
/// has a session replaces its registry entry rather than being dropped,
/// and the older stream unwinding afterwards does not take the newer
/// entry with it. Both halves are the reconnect the agent actually does.
#[test]
fn a_second_hello_replaces_the_entry_and_the_older_session_cannot_undo_it() {
    let registry = SessionRegistry::new();
    let (first, _first_rx) = mpsc::channel(1);
    let (second, _second_rx) = mpsc::channel(1);

    registry.register("node-a", &first);
    registry.register("node-a", &second);
    assert_eq!(registry.connected().len(), 1, "one node, not two entries");
    assert!(
        registry.nodes.lock().unwrap()["node-a"].same_channel(&second),
        "the newer session is the one commands go to"
    );

    // the old stream unwinds afterwards: it must not disconnect the node
    assert!(!registry.disconnect("node-a", &first));
    assert!(registry.connected().contains("node-a"));
    // and the session that IS current still reports the node down
    assert!(registry.disconnect("node-a", &second));
    assert!(registry.connected().is_empty());
}

/// A device driver's entry: it says nothing about locality, which is what
/// every driver that is not a volume backend says.
fn driver(name: &str, profiles: &[&str]) -> DriverInfo {
    DriverInfo {
        name: name.into(),
        profiles: profiles.iter().map(|p| p.to_string()).collect(),
        locality: String::new(),
    }
}

/// A volume backend's entry: one backend, and where its bytes are.
fn volume_driver(backend: &str, locality: Locality) -> DriverInfo {
    DriverInfo {
        name: capability::VOLUME.into(),
        profiles: vec![backend.into()],
        locality: locality.as_str().into(),
    }
}

#[test]
fn catalogue_flattens_to_driver_slash_profile() {
    let drivers = vec![driver("nvrm", &["2q", "8q"]), driver("vfio", &[])];
    assert_eq!(
        capacity_profiles(&drivers),
        vec!["nvrm/2q".to_string(), "nvrm/8q".into(), "vfio".into()]
    );
    assert!(capacity_profiles(&[]).is_empty());
}

/// One entry per volume backend, and the flattened catalogue comes out
/// exactly as it did when all three rode in one entry. That equivalence
/// is what makes the proto change additive: nothing downstream of
/// `capacity_profiles` learns that the shape moved.
#[test]
fn splitting_the_volume_entry_per_backend_leaves_the_catalogue_alone() {
    let one_entry = vec![DriverInfo {
        name: capability::VOLUME.into(),
        profiles: vec!["filesystem".into(), "lvm-thin".into(), "nfs".into()],
        locality: String::new(),
    }];
    let per_backend = vec![
        volume_driver("filesystem", Locality::NodeLocal),
        volume_driver("lvm-thin", Locality::NodeLocal),
        volume_driver("nfs", Locality::Shared),
    ];
    assert_eq!(
        capacity_profiles(&one_entry),
        capacity_profiles(&per_backend)
    );
    assert_eq!(
        capacity_profiles(&per_backend),
        vec![
            "volume/filesystem".to_string(),
            "volume/lvm-thin".into(),
            "volume/nfs".into()
        ]
    );
}

/// The locality half of a Hello, on its own: only volume entries carry
/// one, and a device entry contributes nothing rather than a default.
#[test]
fn only_the_volume_entries_of_a_hello_say_anything_about_locality() {
    let drivers = vec![
        driver("nvrm", &["4q"]),
        volume_driver("lvm-thin", Locality::NodeLocal),
        volume_driver("nfs", Locality::Shared),
    ];
    let said = capacity_localities(&drivers);
    assert_eq!(said.get("lvm-thin"), Some(&Locality::NodeLocal));
    assert_eq!(said.get("nfs"), Some(&Locality::Shared));
    assert_eq!(said.get("nvrm"), None, "a device driver has no locality");
    assert_eq!(said.len(), 2);
}

/// An agent that predates the field says nothing, and nothing must not
/// read as `node-local`: the first is "unknown" and only the second may
/// pin a VM to a machine.
#[test]
fn an_agent_that_predates_the_field_says_nothing_rather_than_node_local() {
    let old = vec![DriverInfo {
        name: capability::VOLUME.into(),
        profiles: vec!["filesystem".into(), "nfs".into()],
        locality: String::new(),
    }];
    assert!(capacity_localities(&old).is_empty());
    // ... and the catalogue it claims is exactly what it always was, so
    // such a node stays a candidate for every volume it could serve.
    assert_eq!(
        capacity_profiles(&old),
        vec!["volume/filesystem".to_string(), "volume/nfs".into()]
    );
}

/// The two halves of the sentence, in one test: what this node writes
/// into its capacity is what a scheduler asking for the same driver and
/// profile finds. Both sides call `common::capability` now, and this is
/// the seam where that stops being a claim about the code and starts
/// being a claim about the system.
#[test]
fn what_a_node_claims_is_what_the_scheduler_finds() {
    let drivers = vec![
        driver("nvrm", &["2q", "4q"]),
        driver("crosvm-gpu", &["venus"]),
        driver("vfio", &[]),
    ];
    let catalogue = capacity_profiles(&drivers);
    for d in &drivers {
        // a bare request finds the driver, profiles or not
        assert!(
            capability::offers(&catalogue, &d.name, None),
            "bare {}",
            d.name
        );
        for p in &d.profiles {
            assert!(
                capability::offers(&catalogue, &d.name, Some(p)),
                "{}/{p}",
                d.name
            );
        }
    }
    // and nothing this node did not claim
    assert!(!capability::offers(&catalogue, "nvrm", Some("8q")));
    assert!(!capability::offers(&catalogue, "lvm-thin", None));
}

/// The one place in this stack where "dispatched" is not "observed".
///
/// Every other spec change is a document the node takes whole, so telling
/// it is all this tier can honestly claim and `observedGeneration` moves
/// at the dispatch. A hot-plug is different: the command is acked the
/// moment the node has it, and the attach can still fail INSIDE the node
/// — the driver, or the guest being told. So the generation closes when
/// the node reports the set, which is what this pair of asserts is.
#[test]
fn a_hot_plug_closes_when_the_node_reports_the_disks_and_not_when_it_is_told() {
    let vm = |names: &[&str]| {
        let entries: Vec<serde_json::Value> = names
            .iter()
            .map(|n| serde_json::json!({ "volume": n }))
            .collect();
        let mut v = controller_api::resources::new_vm(
            "web-1",
            controller_api::VmSpec {
                class: Default::default(),
                cluster_selector: Default::default(),
                node_selector: Default::default(),
                anti_affinity: Vec::new(),
                node_name: Some("agent-1".into()),
                cluster_name: None,
                run_strategy: Default::default(),
                evacuation: Default::default(),
                tenant: None,
                vm: serde_json::json!({ "volumes": entries }),
            },
        );
        v.metadata.generation = 2;
        v
    };
    let settled =
        |observed: &[controller_api::VolumeAttachmentStatus]| observed.iter().all(|v| v.attached);

    // Told, not yet done: the second disk is in the spec and the node
    // does not report it. The generation must NOT close here.
    let asked = vm(&["data-1", "data-2"]);
    let mid = observed_attachments(&asked, &["data-1"]);
    assert_eq!(
        mid.iter().map(|v| v.name.as_str()).collect::<Vec<_>>(),
        vec!["data-1", "data-2"],
        "spec order, so it reads against what somebody wrote"
    );
    assert_eq!(
        mid.iter().map(|v| v.attached).collect::<Vec<_>>(),
        vec![true, false]
    );
    assert!(!settled(&mid));

    // The report that closes it.
    let done = observed_attachments(&asked, &["data-1", "data-2"]);
    assert!(settled(&done));

    // A disk the node has that the spec no longer names is not in the
    // answer: the spec is the question, and letting it in would leave a
    // detach permanently unsettled.
    let detaching = vm(&["data-1"]);
    let after = observed_attachments(&detaching, &["data-1", "data-2"]);
    assert_eq!(after.len(), 1);
    assert!(settled(&after), "the detach is done as far as data-1 goes");

    // And a VM with no referenced disks has nothing to observe, which is
    // every VM before this milestone: an empty list is trivially settled
    // and the generation goes on closing at the dispatch.
    assert!(observed_attachments(&vm(&[]), &[]).is_empty());
}

/// A destination that tore a failed migration down comes off `openOn`.
///
/// The books said `openOn: ["agent-1a","agent-1b"]` while agent-1b held no
/// vmm, no record and no `nvme list-subsys` entry — the teardown was right
/// and nothing ever told the volume object about it, because the pass that
/// maintains `openOn` reads the VMs a node REPORTS and agent-1b reported the
/// vm no longer.
///
/// The rule is two statements from one report, and both have to be there:
/// "I still have this disk" and "nothing here is using it".
#[test]
fn a_node_that_still_has_the_disk_and_no_guest_on_it_has_let_go() {
    let disk = "ce298d89-02f0-41fc-9a83-5db4663b23bd";
    let other = "cb469ada-6782-4a80-a6f9-857a2219bb3f";

    // The destination after the teardown: it knows the volume, no vm holds it.
    let after = proto::StatusReport {
        vms: Vec::new(),
        volumes: vec![proto::VolumeStateReport {
            id: disk.into(),
            phase: "Ready".into(),
            ..Default::default()
        }],
        ..Default::default()
    };
    assert!(ingest::let_go_of(&after, disk));

    // The same node while the guest is actually on it: it has not let go.
    let mut during = after.clone();
    during.vms = vec![proto::VmStatusReport {
        id: "6da35260-9ef6-4b05-bf0b-2d744a2db285".into(),
        attached_volumes: vec![disk.into()],
        ..Default::default()
    }];
    assert!(!ingest::let_go_of(&during, disk));

    // A disk this node has never been told about is not this node's word.
    // `hold_volumes` writes a node into `openOn` the moment the create goes
    // out, before any report, and clearing it on that silence would undo the
    // dispatch's own work one beat later.
    assert!(!ingest::let_go_of(&after, other));

    // A heartbeat-only report says "not saying" about both lists at once.
    assert!(!ingest::let_go_of(&proto::StatusReport::default(), disk));
}
/// The machine profile makes the trip from the node's own `/proc` to the
/// object the destination choice reads.
///
/// Field for field, because the two types are a contract between two
/// processes and the translation is written out rather than derived: a rename
/// on either side should be a compile error, and a field that quietly stopped
/// travelling would turn the pre-flight check into a comparison of two empty
/// profiles — which refuses nothing, silently.
#[test]
fn what_a_node_says_about_its_machine_arrives_as_the_object_says_it() {
    let said = proto::MachineProfile {
        cpu_vendor: "GenuineIntel".into(),
        cpu_model: "Intel(R) Xeon(R) Gold 6248R".into(),
        cpu_flags: "fpu lm vmx".into(),
        nested: true,
        hypervisor: "KVM".into(),
        cpu_profile: "Host".into(),
        hypervisor_version: "cloud-hypervisor v53.0".into(),
        kernel: "6.12.0".into(),
        host: "palma".into(),
    };
    let object = super::hello::machine_profile(&said);
    assert_eq!(object.cpu_vendor, "GenuineIntel");
    assert_eq!(object.cpu_model, "Intel(R) Xeon(R) Gold 6248R");
    assert_eq!(object.cpu_flags, "fpu lm vmx");
    assert!(object.nested);
    assert_eq!(object.hypervisor, "KVM");
    assert_eq!(object.cpu_profile, "Host");
    assert_eq!(object.hypervisor_version, "cloud-hypervisor v53.0");
    assert_eq!(object.kernel, "6.12.0");
    assert_eq!(object.host, "palma");

    // The sentence a refusal is built from, and the three things it names:
    // what the cpu is, that the machine is itself a guest, and which host —
    // which is the one an operator can act on.
    assert_eq!(
        object.describe(),
        "Intel(R) Xeon(R) Gold 6248R on nested KVM (host palma)"
    );

    // And the shape that says nothing: an agent from before the field sends
    // no profile at all, and one that could read none of it sends an empty
    // one. Both are "did not say", and nothing is ever refused on one.
    let quiet = super::hello::machine_profile(&proto::MachineProfile::default());
    assert!(!quiet.said_anything());
    assert!(controller_api::live_migration_refusal("a", &quiet, "b", &object).is_none());
    assert!(controller_api::live_migration_refusal("a", &object, "b", &quiet).is_none());
}

/// The two vocabularies, joined at the hop that has both.
///
/// A node knows one thing about a router — the namespace and its legs are
/// there, or they are not — and the object above is about a router living on
/// two machines at once. Reading the node's word as the tier's own dropped
/// every report from every healthy gateway node with "unknown router phase",
/// ten seconds apart, and left `Failed` as the only thing a node could ever
/// say.
#[test]
fn a_healthy_node_says_ready_and_the_tier_above_knows_which_kind_of_ready() {
    use controller_api::RouterPhaseKind;

    // The same word, two answers, and which one it is is the CONTROLLER's
    // decision and not the node's.
    assert_eq!(
        super::ingest::observed_phase(proto::ROUTER_READY, true),
        Some(RouterPhaseKind::Active)
    );
    assert_eq!(
        super::ingest::observed_phase(proto::ROUTER_READY, false),
        Some(RouterPhaseKind::Standby)
    );
    // Broken is broken on either machine, and it is the one report a standby
    // is listened to for at all.
    assert_eq!(
        super::ingest::observed_phase(proto::ROUTER_FAILED, false),
        Some(RouterPhaseKind::Failed)
    );
    assert_eq!(
        super::ingest::observed_phase(proto::ROUTER_FAILED, true),
        Some(RouterPhaseKind::Failed)
    );
    // And a word from a road nobody has written yet is refused rather than
    // defaulted — the same rule the rest of this session follows.
    assert_eq!(super::ingest::observed_phase("Draining", true), None);
    assert_eq!(super::ingest::observed_phase("Active", true), None);
}

/// A node that reports a router the list does not name RIGHT NOW is not an
/// orphan, and the difference is not academic.
///
/// `status.nodes` is rewritten by every pass, so a machine is off it for one
/// pass whenever a heartbeat has just expired or a cordon is about to be
/// taken back. Ordering a destroy from the reading of a status report then
/// fights the very next `EnsureRouter` — and because that send is answered
/// or times out after a minute, it holds the node's whole status ingest for
/// that minute, which starves the heartbeat, which takes the machine off the
/// list for real. A chaos run walked into exactly that loop and two agents
/// stopped answering any command at all.
///
/// Letting a machine go is the reconciler's, out of a plan it just computed
/// (`RouterPlan.release`). What is swept from here is only what NOBODY
/// stores.
#[tokio::test]
async fn a_router_the_list_does_not_name_this_second_is_not_an_orphan() {
    let report = |id: &str| StatusReport {
        routers: vec![proto::RouterReport {
            id: id.to_string(),
            phase: proto::ROUTER_READY.to_string(),
            ..Default::default()
        }],
        ..Default::default()
    };

    let mut stored = controller_api::Router::declare(
        "lab-out",
        controller_api::RouterSpec {
            tenant: "lab".into(),
            provider_network: "ext".into(),
            ..Default::default()
        },
    );
    stored.metadata.uid = "7fcc6298-0000-0000-0000-000000000001".into();
    // On the list — and, the case that mattered, NOT on it this second.
    stored.status.nodes = vec!["gw-1".into()];
    let fleet = [stored];

    let mine = report("7fcc6298-0000-0000-0000-000000000001");
    assert!(
        super::ingest::held_here(&fleet, &mine.routers[0].id).is_some(),
        "somebody stores it, so it is not an orphan — whatever list it is on"
    );
    // The same answer for the machine that is momentarily off the list: what
    // decides an orphan is whether ANYBODY stores the router.
    assert!(super::ingest::held_here(&fleet, &mine.routers[0].id).is_some());

    // And the real orphan: a netns nobody has an object for.
    let stranger = report("deadbeef-0000-0000-0000-000000000001");
    assert!(
        super::ingest::held_here(&fleet, &stranger.routers[0].id).is_none(),
        "this one is nobody's, and it is the only kind this path sweeps"
    );

    // The node's road leaves both machine fields empty; the cluster fills
    // them when it passes the report on.
    assert!(mine.routers[0].node.is_empty());
    assert!(mine.routers[0].nodes.is_empty());
}

/// D-C7: two heartbeats that say the same thing are ONE write, and it is the
/// lease.
///
/// The number that made this a defect: twelve PUTs in a twenty-second watch
/// on a lab where nobody was doing anything, every one of them a whole `Node`
/// object — `machine.cpuFlags` and all, about 1.5 kB — rewritten because
/// `lastHeartbeat` had moved 108 ms. 1.13 etcd revisions a second at idle,
/// 8.3 MB an hour, and a fleet that fills its own quota in six days.
///
/// So this is the rule in one assertion: what decides whether the OBJECT is
/// written is `ready`, `capacity`, `vms` and `conditions` — and never the
/// beat. The beat is a key of its own (`store.beat`), written every time,
/// about sixty bytes.
#[test]
fn a_second_heartbeat_that_says_the_same_thing_writes_no_node_revision() {
    use super::ingest::{NodeFacts, node_facts_are_news};

    let facts = |vcpus: u32, mem_mib: u64, vms: u32, conditions: &[&str]| NodeFacts {
        vcpus,
        mem_mib,
        vms,
        conditions: Some(
            conditions
                .iter()
                .map(|t| controller_api::NodeCondition {
                    type_: (*t).to_string(),
                    message: String::new(),
                })
                .collect(),
        ),
    };

    // A node nobody has heard from: the first report is news, because `ready`
    // is what it changes.
    let mut node = Node::declare("agent-1c", controller_api::NodeSpec::default());
    assert!(
        node_facts_are_news(&node.status, &facts(8, 16384, 3, &[])),
        "the first report of a node makes it ready"
    );

    // What that report left behind.
    node.status.ready = true;
    node.status.vms = 3;
    node.status.capacity.vcpus = 8;
    node.status.capacity.mem_mib = 16384;

    // And the second, identical one: nothing. This is the whole of D-C7 —
    // ten seconds later, the same machine, the same guests, no revision.
    assert!(
        !node_facts_are_news(&node.status, &facts(8, 16384, 3, &[])),
        "the same report twice is one write"
    );

    // Each of the four facts on its own is still news, because each of them
    // is something an operator or a scheduler acts on.
    assert!(node_facts_are_news(&node.status, &facts(8, 16384, 4, &[])));
    assert!(node_facts_are_news(&node.status, &facts(16, 16384, 3, &[])));
    assert!(node_facts_are_news(&node.status, &facts(8, 32768, 3, &[])));
    assert!(
        node_facts_are_news(&node.status, &facts(8, 16384, 3, &["DiskPressure"])),
        "a node saying its disk is full is news whatever else stayed the same"
    );

    // A report with no `node` block says nothing about health, and a `None`
    // must not be read as "nothing is wrong": that shape is the
    // heartbeat-only report an agent sends when it could not read its own
    // state, and a write here would clear a veto on the strength of a
    // failure.
    node.status.conditions = vec![controller_api::NodeCondition {
        type_: "DiskPressure".into(),
        message: "no room in /var".into(),
    }];
    assert!(
        !node_facts_are_news(
            &node.status,
            &NodeFacts {
                vcpus: 8,
                mem_mib: 16384,
                vms: 3,
                conditions: None,
            }
        ),
        "silence about health leaves the list alone and writes nothing"
    );
}
