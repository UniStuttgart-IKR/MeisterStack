// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! The reconciler's tests, verbatim out of `reconcile.rs`. The module path
//! is unchanged (`reconcile::tests`), so every test still answers to the name
//! it had before.

use super::*;
use controller_api::{VmSpec, resources::new_vm};

/// A VM has an address in its status, and it is named for what the
/// control plane really knows.
///
/// Tofu found a `VmStatus` with a phase, a node, a cluster and no address
/// of any kind; the only readable one anywhere was `FloatingIp.spec.
/// address`, which a client had to go and look up itself. The floating
/// half is this cloud's own object and is written down here. The IP a
/// guest gave itself is not, and never will be: nobody here knows it.
#[test]
fn a_floating_address_becomes_a_line_of_the_vms_status() {
    let reservation = |tenant: &str, addr: &str, vm: Option<&str>| {
        let mut ip = controller_api::FloatingIp::declare(
            addr,
            controller_api::FloatingIpSpec {
                tenant: tenant.to_string(),
                address: addr.to_string(),
                vm: vm.map(str::to_string),
                ..Default::default()
            },
        );
        ip.metadata.uid = addr.to_string();
        ip
    };
    let owned_by = |name: &str, tenant: Option<&str>| {
        new_vm(
            name,
            VmSpec {
                class: Default::default(),
                cluster_selector: Default::default(),
                node_selector: Default::default(),
                anti_affinity: Vec::new(),
                node_name: None,
                cluster_name: Some("cluster-1".into()),
                run_strategy: RunStrategy::Running,
                evacuation: Default::default(),
                tenant: tenant.map(str::to_string),
                vm: serde_json::json!({}),
            },
        )
    };
    let mut vm = owned_by("web-1", Some("acme"));

    let held = [
        reservation("acme", "192.0.2.9", Some("web-1")),
        reservation("acme", "192.0.2.4", Some("web-1")),
        // Somebody else's, and one nobody has pointed anywhere.
        reservation("globex", "192.0.2.5", Some("web-1")),
        reservation("acme", "192.0.2.6", None),
    ];
    let lines = addresses_of(&held, &vm);
    assert_eq!(lines.len(), 2, "{lines:?}");
    // Sorted, so a second pass over the same facts writes nothing.
    assert_eq!(lines[0].address.as_deref(), Some("192.0.2.4"));
    assert_eq!(lines[1].address.as_deref(), Some("192.0.2.9"));
    assert!(
        lines
            .iter()
            .all(|l| l.kind == controller_api::VmAddressKind::FloatingIp && l.mac.is_none())
    );

    // What this tier does not own is kept: the lines a node's taps put
    // there stay exactly where they are.
    vm.status.addresses = vec![controller_api::VmAddress {
        kind: controller_api::VmAddressKind::Mac,
        nic: "eth0".to_string(),
        mac: Some("52:54:00:12:34:56".to_string()),
        address: None,
    }];
    let lines = addresses_of(&held, &vm);
    assert_eq!(lines.len(), 3);
    assert_eq!(lines[0].kind, controller_api::VmAddressKind::Mac);

    // A VM nobody owns has no addresses to find.
    let orphan = owned_by("web-2", None);
    assert!(addresses_of(&held, &orphan).is_empty());
}

/// Two writers, one list, and neither may undo the other.
///
/// `ingest_placements` writes the MAC lines out of the cluster's report and
/// `stamp_vm_addresses` writes the floating lines out of this cloud's own
/// objects, both every ten seconds and neither aware of the other. This walks
/// them in both orders and asserts a FIXPOINT — which is a statement about
/// the ORDER of the list as much as its content: an agreement on content with
/// a disagreement on order is two passes rewriting each other's document for
/// ever, and the etcd revisions to prove it.
#[test]
fn the_mac_writer_and_the_floating_writer_reach_the_same_list_from_either_side() {
    let reservation = |addr: &str| {
        let mut ip = controller_api::FloatingIp::declare(
            addr,
            controller_api::FloatingIpSpec {
                tenant: "acme".to_string(),
                address: addr.to_string(),
                vm: Some("web-1".to_string()),
                ..Default::default()
            },
        );
        ip.metadata.uid = addr.to_string();
        ip
    };
    let held = [reservation("192.0.2.4"), reservation("192.0.2.9")];
    let reported = [
        proto::NicReport {
            name: "nics[0]".into(),
            mac: "52:54:00:11:22:33".into(),
        },
        proto::NicReport {
            name: "nics[1]".into(),
            mac: "52:54:00:aa:bb:cc".into(),
        },
    ];

    let mut vm = new_vm(
        "web-1",
        VmSpec {
            class: Default::default(),
            cluster_selector: Default::default(),
            node_selector: Default::default(),
            anti_affinity: Vec::new(),
            node_name: None,
            cluster_name: Some("cluster-1".into()),
            run_strategy: RunStrategy::Running,
            evacuation: Default::default(),
            tenant: Some("acme".into()),
            vm: serde_json::json!({}),
        },
    );

    // The cluster's report first, this cloud's own objects second.
    vm.status.addresses = controller_api::addresses_with(&vm.status.addresses, &reported);
    vm.status.addresses = addresses_of(&held, &vm);
    let settled = vm.status.addresses.clone();
    assert_eq!(
        settled
            .iter()
            .map(|a| (
                a.kind,
                a.nic.as_str(),
                a.mac.as_deref(),
                a.address.as_deref()
            ))
            .collect::<Vec<_>>(),
        [
            (
                controller_api::VmAddressKind::Mac,
                "nics[0]",
                Some("52:54:00:11:22:33"),
                None
            ),
            (
                controller_api::VmAddressKind::Mac,
                "nics[1]",
                Some("52:54:00:aa:bb:cc"),
                None
            ),
            (
                controller_api::VmAddressKind::FloatingIp,
                "",
                None,
                Some("192.0.2.4")
            ),
            (
                controller_api::VmAddressKind::FloatingIp,
                "",
                None,
                Some("192.0.2.9")
            ),
        ]
    );

    // And a second pass of each, in either order, has nothing to write.
    assert_eq!(
        controller_api::addresses_with(&settled, &reported),
        settled,
        "the mac writer is at rest"
    );
    assert_eq!(
        addresses_of(&held, &vm),
        settled,
        "and so is the floating one"
    );

    // The cluster from before the field, arriving on a VM that already has
    // both halves: it changes nothing at all.
    assert_eq!(controller_api::addresses_with(&settled, &[]), settled);
}

fn at(secs: i64) -> DateTime<Utc> {
    DateTime::from_timestamp(1_800_000_000 + secs, 0).unwrap()
}

fn vm() -> Vm {
    new_vm(
        "t",
        VmSpec {
            class: Default::default(),
            cluster_selector: Default::default(),
            node_selector: Default::default(),
            anti_affinity: Vec::new(),
            node_name: None,
            cluster_name: Some("cluster-1".into()),
            run_strategy: RunStrategy::Running,
            evacuation: Default::default(),
            tenant: None,
            vm: serde_json::json!({ "vcpus": 1 }),
        },
    )
}

fn bound_to(cluster: Option<&str>) -> Vm {
    new_vm(
        "t",
        VmSpec {
            class: Default::default(),
            cluster_selector: Default::default(),
            node_selector: Default::default(),
            anti_affinity: Vec::new(),
            node_name: None,
            cluster_name: cluster.map(str::to_string),
            run_strategy: RunStrategy::Running,
            evacuation: Default::default(),
            tenant: None,
            vm: serde_json::json!({}),
        },
    )
}

fn sessions(names: &[&str]) -> HashSet<String> {
    names.iter().map(|s| s.to_string()).collect()
}

/// The owner's answer has to reach the tier that ACTS on it, and this
/// session is the only road: a cloud-owned vm answers 409 at the
/// cluster's own edge, so nobody can set it down there by hand.
///
/// Without this the cluster's drain table read `never` for every
/// cloud-managed vm — the safe direction, and still a `node drain` that
/// listed a vm whose owner had agreed to a reboot as one that will not
/// move.
#[test]
fn the_owners_evacuation_answer_travels_down_with_the_spec() {
    let sent = |v: &Vm| -> serde_json::Value {
        serde_json::from_str(&build_spec_json(v).expect("a spec")).expect("json")
    };

    let default = vm();
    assert_eq!(
        sent(&default)["evacuation"],
        "never",
        "the default travels as a value, not as an absence: the tier below has to be able to \
         tell it from a field it does not understand"
    );

    let mut opted_in = vm();
    opted_in.spec.evacuation = controller_api::Evacuation::Restart;
    assert_eq!(sent(&opted_in)["evacuation"], "restart");
    // And it is the spelling the other side parses.
    assert_eq!(
        controller_api::Evacuation::parse(
            sent(&opted_in)["evacuation"].as_str().expect("a string")
        ),
        Some(controller_api::Evacuation::Restart)
    );
}

/// The stop that a cluster drain sends, and the one thing about it that
/// must never leak upwards: the owner's `runStrategy` does not change.
///
/// This tier sends no lifecycle commands — it sends a spec, and the
/// cluster derives the lifecycle from it — so the only way to stop a
/// guest from here is to say `Stopped` in the DISPATCH while saying
/// nothing different on the object. That is what makes the VM come back
/// Running on the new cluster with nobody having to remember to restore
/// anything, and what makes a lost mark fail in the safe direction: the
/// next dispatch carries the real strategy and the guest starts.
#[test]
fn a_cluster_drain_stops_a_vm_in_the_dispatch_and_not_on_the_object() {
    let strategy = |v: &Vm| -> String {
        let sent: serde_json::Value =
            serde_json::from_str(&build_spec_json(v).expect("a spec")).expect("json");
        sent["runStrategy"]
            .as_str()
            .expect("a strategy")
            .to_string()
    };

    let mut running = vm();
    assert_eq!(strategy(&running), "Running", "nothing in flight");

    running.status.evacuating = Some(controller_api::Evacuating {
        from: "cluster-1".into(),
        step: controller_api::EvacuationStep::Stopping
            .as_str()
            .to_string(),
        since: at(0),
    });
    assert_eq!(
        strategy(&running),
        "Stopped",
        "while the guest is being asked to power off"
    );
    assert_eq!(
        running.spec.run_strategy,
        RunStrategy::Running,
        "and the owner's intent is untouched, which is what starts it again at the other end"
    );

    // The second step is past the stop: the binding has fallen and what
    // travels is the real strategy again.
    running.status.evacuating = Some(controller_api::Evacuating {
        from: "cluster-1".into(),
        step: controller_api::EvacuationStep::Moving.as_str().to_string(),
        since: at(0),
    });
    assert_eq!(strategy(&running), "Running");

    // A step from a newer binary is not a reason to stop somebody's VM.
    running.status.evacuating = Some(controller_api::Evacuating {
        from: "cluster-1".into(),
        step: "Handshaking".into(),
        since: at(0),
    });
    assert_eq!(
        strategy(&running),
        "Running",
        "an unknown step decides nothing"
    );
}

/// The middle of a move-by-restart is a VM that is deliberately off, and
/// the only thing that tells that from drift is this mark. So it has to
/// survive the store — which is the whole of what "survives a controller
/// restart" means here.
#[test]
fn the_evacuation_mark_survives_the_store() {
    let mut moving = vm();
    moving.status.evacuating = Some(controller_api::Evacuating {
        from: "cluster-1".into(),
        step: controller_api::EvacuationStep::Stopping
            .as_str()
            .to_string(),
        since: at(7),
    });
    let round: Vm =
        serde_json::from_str(&serde_json::to_string(&moving).expect("out")).expect("back");
    assert_eq!(round.status.evacuating, moving.status.evacuating);

    // And a VM that is not moving carries no field at all, so every VM
    // written before this reads back exactly as it did.
    let plain = serde_json::to_value(vm()).expect("out");
    assert!(
        plain["status"].get("evacuating").is_none(),
        "{}",
        plain["status"]
    );
    assert!(
        plain["spec"].get("evacuation").is_none(),
        "and the spec half is skipped at its default too: {}",
        plain["spec"]
    );
}

/// Leaderless ownership, one floor up: my sessions, my VMs.
#[test]
fn a_bound_vm_is_only_reconciled_by_the_replica_its_cluster_talks_to() {
    let mine = sessions(&["cluster-1"]);
    assert!(may_reconcile(&bound_to(Some("cluster-1")), &mine));
    assert!(!may_reconcile(&bound_to(Some("cluster-2")), &mine));
    // a replica holding no session at all owns no bound VM
    assert!(!may_reconcile(&bound_to(Some("cluster-1")), &sessions(&[])));
}

/// Unbound is everybody's: the scheduler is only offered clusters of the
/// local session map, so the binding and the ownership land together.
#[test]
fn an_unbound_vm_may_be_scheduled_by_any_replica() {
    assert!(may_reconcile(&bound_to(None), &sessions(&[])));
    assert!(may_reconcile(&bound_to(None), &sessions(&["cluster-1"])));
}

/// Deleting widens nothing: only the cluster's own replica can order the
/// teardown, so a deleting VM on a foreign cluster waits.
#[test]
fn deleting_does_not_widen_ownership() {
    let mut vm = bound_to(Some("cluster-2"));
    vm.metadata.deletion_timestamp = Some(at(0));
    assert!(!may_reconcile(&vm, &sessions(&["cluster-1"])));
    assert!(may_reconcile(&vm, &sessions(&["cluster-2"])));
}

/// The race this gate exists for, in both directions: a status built
/// before the create landed names no such VM either — as proof of
/// teardown it would delete a live VM, and as proof of absence it would
/// have the create dispatched all over again.
#[test]
fn a_status_older_than_what_we_know_proves_nothing() {
    let mut v = vm();
    v.metadata.deletion_timestamp = Some(at(100));
    v.status.observed_at = Some(at(120)); // the create ack
    assert!(
        !status_is_current(&v, at(110)),
        "a status from before the ack says nothing"
    );
    assert!(status_is_current(&v, at(121)));
    // The status the mirror wrote from is evidence about itself: it set
    // the floor, and it must not be shut out by it.
    v.status.observed_at = Some(at(130));
    assert!(status_is_current(&v, at(130)));
    assert!(!status_is_current(&v, at(129)));
}

/// A VM the cloud never got as far as handing over has no floor to clear.
#[test]
fn a_vm_nothing_ever_happened_to_needs_no_proof() {
    let v = vm();
    assert!(status_is_current(&v, at(0)));
}

#[test]
fn the_run_strategy_travels_as_the_cluster_tiers_spec() {
    let mut v = vm();
    v.spec.run_strategy = RunStrategy::Stopped;
    let doc: serde_json::Value = serde_json::from_str(&build_spec_json(&v).unwrap()).unwrap();
    assert_eq!(doc["runStrategy"], "Stopped");
    assert_eq!(doc["vm"]["vcpus"], 1);
    // The binding is ours and stays ours.
    assert!(doc.get("clusterName").is_none());
    assert!(doc["vm"].get("desired").is_none());
}

/// The document the cluster receives has to be the document the cluster's
/// own VmSpec accepts — one spec format the whole way down.
#[test]
fn the_cluster_tier_parses_what_the_cloud_sends() {
    let json = build_spec_json(&vm()).unwrap();
    let spec: VmSpec = serde_json::from_str(&json).unwrap();
    assert_eq!(spec.run_strategy, RunStrategy::Running);
    assert!(spec.node_name.is_none() && spec.cluster_name.is_none());
}

// --- the address book ----------------------------------------------------

fn owned(name: &str, tenant: Option<&str>) -> Vm {
    new_vm(
        name,
        VmSpec {
            class: Default::default(),
            cluster_selector: Default::default(),
            node_selector: Default::default(),
            anti_affinity: Vec::new(),
            node_name: None,
            cluster_name: Some("cluster-1".into()),
            run_strategy: RunStrategy::Running,
            evacuation: Default::default(),
            tenant: tenant.map(str::to_string),
            vm: serde_json::json!({}),
        },
    )
}

fn book() -> AddressBook {
    let ip = |address: &str, tenant: &str, vm: Option<&str>| {
        controller_api::FloatingIp::declare(
            address,
            controller_api::resources::FloatingIpSpec {
                internal_address: String::new(),
                router: String::new(),
                tenant: tenant.into(),
                pool: "lab".into(),
                address: address.into(),
                vm: vm.map(str::to_string),
            },
        )
    };
    let net = |name: &str, tenant: &str, cidr: &str| {
        controller_api::RoutedSubnet::declare(
            name,
            controller_api::RoutedSubnetSpec {
                tenant: tenant.into(),
                cidr: cidr.into(),
                ..controller_api::RoutedSubnetSpec::default()
            },
        )
    };
    AddressBook {
        reservations: vec![
            ip("10.255.0.9", "acme", Some("web")),
            ip("10.255.0.7", "acme", Some("web")),
            ip("10.255.0.8", "acme", Some("db")),
            ip("10.255.0.5", "acme", None),
            // The same VM NAME under another tenant. A VM name is unique
            // in this store, so this cannot happen today — and the filter
            // that keeps it unable to matter is the one under test.
            ip("203.0.113.4", "other", Some("web")),
        ],
        subnets: vec![
            net("acme-net", "acme", "10.7.1.0/24"),
            net("other-net", "other", "10.7.2.0/24"),
        ],
        // acme has a way out; the prefix its guests source from is the one
        // behind that router, and it belongs on the same list.
        routers: vec![{
            controller_api::Router::declare(
                "acme-out",
                controller_api::RouterSpec {
                    tenant: "acme".into(),
                    provider_network: "ext".into(),
                    internal_addr: "10.42.0.1/24".into(),
                    ..Default::default()
                },
            )
        }],
    }
}

/// The two listings that used to happen per dispatch happen once per pass,
/// and every VM of that pass is answered out of the one book. What each of
/// them gets back is exactly what its own listing would have given it:
/// its tenant's subnets, and the addresses assigned to it BY NAME AND BY
/// TENANT — an assignment naming another tenant's VM is not that VM's
/// permission to source from the address.
#[test]
fn one_address_book_answers_for_every_vm_of_the_pass() {
    let book = book();

    let web = book.for_vm(&owned("web", Some("acme")));
    assert_eq!(web.floating_ips, ["10.255.0.7", "10.255.0.9"], "sorted");
    assert_eq!(
        web.routed_subnets,
        ["10.42.0.0/24", "10.7.1.0/24"],
        "the tenant's routed subnet AND the prefix behind its router, sorted"
    );

    // The same book, a second VM, no second listing.
    let db = book.for_vm(&owned("db", Some("acme")));
    assert_eq!(db.floating_ips, ["10.255.0.8"]);
    assert_eq!(db.routed_subnets, ["10.42.0.0/24", "10.7.1.0/24"]);

    // A VM of the tenant that holds nothing assigned to it still gets the
    // tenant's subnets, and none of anybody's addresses.
    let idle = book.for_vm(&owned("idle", Some("acme")));
    assert!(idle.floating_ips.is_empty());
    assert_eq!(idle.routed_subnets, ["10.42.0.0/24", "10.7.1.0/24"]);
    // And the other tenant's router is not acme's business.
    let theirs = book.for_vm(&owned("web", Some("other")));
    assert_eq!(theirs.routed_subnets, ["10.7.2.0/24"]);
}

/// What a dispatch may honestly claim to have applied, and for whom.
///
/// The command carries the addresses of ONE VM's tenant that are assigned
/// to THAT VM, plus its tenant's subnets — so those are the objects whose
/// `observedGeneration` a successful dispatch may move, and no others. An
/// address reserved but not assigned travelled in nothing and stays
/// `pending`, which is the true answer and the whole reason the column
/// exists.
#[test]
fn a_dispatch_stamps_the_addresses_it_carried_and_no_others() {
    let mut book = book();
    // Two clients' worth of intent, so that the numbers are not all 1.
    for ip in &mut book.reservations {
        ip.metadata.generation = 3;
    }
    for net in &mut book.subnets {
        net.metadata.generation = 5;
    }

    let carried = book.for_vm(&owned("web", Some("acme"))).carried;
    let mut names: Vec<_> = carried
        .iter()
        .map(|(resource, name, generation)| (*resource, name.as_str(), *generation))
        .collect();
    names.sort();
    assert_eq!(
        names,
        [
            ("floatingips", "10.255.0.7", 3),
            ("floatingips", "10.255.0.9", 3),
            ("routedsubnets", "acme-net", 5),
        ],
        "its own addresses and its tenant's subnet, each with the number that travelled"
    );

    // Not carried, so not stamped: an address of the same tenant that is
    // assigned to nobody, one assigned to another VM, and the other
    // tenant's everything.
    for (_, name, _) in &names {
        assert!(
            !["10.255.0.5", "10.255.0.8", "203.0.113.4", "other-net"].contains(name),
            "{name} did not travel in this command"
        );
    }

    // And a VM with nothing of its own still carries its tenant's subnet,
    // which is what a routed subnet IS — it reaches a node inside some
    // VM's create or it reaches none.
    let idle = book.for_vm(&owned("idle", Some("acme"))).carried;
    assert_eq!(idle, [("routedsubnets", "acme-net".to_string(), 5)]);
}

/// The generation is read when the command is BUILT and never again.
///
/// An assign that lands between building the command and writing the
/// status has not travelled, and stamping whatever the object says at
/// write time would make `APPLIED` say `yes` about an address no node has
/// heard of — in exactly the window the column exists to show.
#[test]
fn what_is_stamped_is_what_the_command_carried_and_not_what_is_stored_after() {
    let mut book = book();
    for ip in &mut book.reservations {
        ip.metadata.generation = 2;
    }
    let carried = book.for_vm(&owned("web", Some("acme"))).carried;

    // The client changes an assignment while the command is in flight.
    for ip in &mut book.reservations {
        ip.metadata.generation = 9;
    }

    assert!(
        carried
            .iter()
            .all(|(resource, _, generation)| *resource != "floatingips" || *generation == 2),
        "the command still carries what it was built with"
    );
}

/// A reservation belongs to a tenant by definition, so a VM without one
/// has no way to be given anything — and an empty tenant string is not a
/// tenant either.
#[test]
fn a_vm_without_a_tenant_holds_nothing() {
    let book = book();
    for vm in [owned("web", None), owned("web", Some(""))] {
        let none = book.for_vm(&vm);
        assert!(none.floating_ips.is_empty() && none.routed_subnets.is_empty());
        assert!(none.carried.is_empty(), "and nothing to stamp");
    }
}

/// A secret travels once, and a cluster that was offline for the delete
/// loses its copy when it comes back.
///
/// Both used to be impossible to state: a cluster reported its volumes and
/// said nothing about its secrets, so the mirror re-sent every secret to
/// every cluster on every pass, and a `secret rm` that missed a cluster
/// left a sealed copy there for ever — nothing afterwards ever mentioned
/// it again.
#[test]
fn a_secret_travels_once_and_a_leftover_copy_is_collected() {
    let secret = |name: &str, uid: &str, generation: u64| {
        let mut s = controller_api::Secret::declare(
            name,
            controller_api::SecretSpec {
                tenant: "acme".into(),
                ..Default::default()
            },
        );
        s.metadata.uid = uid.to_string();
        s.metadata.generation = generation;
        s
    };
    let line = |name: &str, uid: &str, generation: u64| proto::SecretStateReport {
        name: name.into(),
        uid: uid.into(),
        generation,
    };

    let db = secret("db", "uid-db", 3);
    let api = secret("api", "uid-api", 1);

    // What the cluster says it has.
    let held = vec![line("db", "uid-db", 3), line("gone", "uid-gone", 1)];

    assert!(already_there(&held, &db), "it is there, at this version");
    assert!(!already_there(&held, &api), "this one has never been sent");
    // A rotation is a new generation of the same secret and has to travel.
    assert!(!already_there(&held, &secret("db", "uid-db", 4)));
    // And a name somebody reused is not the same secret.
    assert!(!already_there(&held, &secret("db", "uid-other", 3)));
    // A replica that has heard nothing yet sends everything, which is what
    // every replica did on every pass before this existed.
    assert!(!already_there(&[], &db));

    // The leftover: cloud-managed, named by the cluster, and no object up
    // here answers to it.
    let ours = [db, api];
    let stale: Vec<&str> = leftovers(&held, &ours).map(|s| s.name.as_str()).collect();
    assert_eq!(stale, ["gone"]);
}
