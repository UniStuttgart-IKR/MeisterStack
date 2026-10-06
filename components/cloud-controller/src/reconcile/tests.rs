// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Tests for src/reconcile decisions and API contracts.
//! Store-backed cases explicitly require etcd; value-level cases run without it.

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

/// MAC and floating-address writers converge in either order, including list
/// ordering, so repeated reconciliation does not produce spurious revisions.
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

/// Drain dispatch overrides runStrategy to Stopped without changing owner intent.
/// The destination therefore receives the original strategy after evacuation.
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

/// IKR-B71: a node selector, an anti-affinity term and a class set at the
/// cloud reach the cluster's scheduler; the cluster selector, answered here,
/// does not travel.
#[test]
fn the_node_half_of_placement_travels_to_the_cluster() {
    let mut v = vm();
    v.spec.class = "gpu".into();
    v.spec.node_selector = [("network-node".to_string(), "cobra3".to_string())].into();
    v.spec.cluster_selector = [("region".to_string(), "stuttgart".to_string())].into();
    v.spec.anti_affinity = vec![controller_api::resources::AntiAffinity {
        selector: [("app".to_string(), "web".to_string())].into(),
        required: true,
    }];
    let spec: VmSpec = serde_json::from_str(&build_spec_json(&v).unwrap()).unwrap();
    assert_eq!(spec.class, "gpu");
    assert_eq!(spec.node_selector, v.spec.node_selector);
    assert_eq!(spec.anti_affinity, v.spec.anti_affinity);
    assert!(spec.cluster_selector.is_empty());
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
        .map(|c| (c.resource, c.name.as_str(), c.generation))
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
    let idle: Vec<_> = idle
        .iter()
        .map(|c| (c.resource, c.name.as_str(), c.generation))
        .collect();
    assert_eq!(idle, [("routedsubnets", "acme-net", 5)]);
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
            .all(|c| c.resource != "floatingips" || c.generation == 2),
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

/// F04, the cloud half: a volume the cluster has already spoken about is sent
/// again when its spec moves past what was last sent — and only then.
///
/// The dedup used to be `observed_at` alone, which is "the cluster has this
/// volume" and not "the cluster has this SPEC". `spec.sizeGib` became growable
/// at the cloud edge with storage B, so the resize was accepted, bumped the
/// generation, and never left this tier: the object said 20 GiB and the
/// cluster held 10 for ever.
#[test]
fn an_observed_volume_whose_spec_moved_is_handed_down_again() {
    let mut volume = controller_api::resources::new_volume(
        "data",
        controller_api::VolumeSpec {
            tenant: "acme".into(),
            pool: "disks".into(),
            size_gib: 10,
            ..Default::default()
        },
    );
    // What `create` stamps.
    volume.metadata.generation = 1;
    assert!(
        needs_dispatch(&volume),
        "never seen by the cluster: send it"
    );

    // Sent (the dispatch writes what it sent), then reported (the mirror
    // writes that the cluster spoke). Fully observed at 10 GiB.
    volume.status.observed_generation = 1;
    volume.status.observed_at = Some(Utc::now());
    assert!(
        !needs_dispatch(&volume),
        "observed and current: not a write per pass down there"
    );

    // A client grows it. The edge bumps the generation exactly as it does
    // for any spec change.
    let current = volume.clone();
    volume.spec.size_gib = 20;
    controller_api::carry_generation(&current, &mut volume).expect("serialisable");
    assert_eq!(volume.metadata.generation, 2);
    assert!(
        needs_dispatch(&volume),
        "a generation the cluster has never been sent goes down"
    );
    let sent: controller_api::VolumeSpec =
        serde_json::from_str(&serde_json::to_string(&volume.spec).unwrap()).unwrap();
    assert_eq!(sent.size_gib, 20, "and what goes down is the new size");

    // Once it has gone, the dedup holds again.
    volume.status.observed_generation = 2;
    assert!(!needs_dispatch(&volume));
}

// --- IKR-B74: a drift is told again after a while, not on every pass -------

/// A stopping guest: Stopped asked for, Running reported, the current
/// generation acked by the cluster `told` seconds after `at(0)`.
fn stopping(told: i64) -> Vm {
    let mut v = vm();
    v.spec.run_strategy = RunStrategy::Stopped;
    v.status.reported = Some(controller_api::VmReported::by(
        "cluster-1",
        VmPhaseKind::Running,
        controller_api::VmReason::Unrecorded,
        None,
        at(0),
    ));
    v.settle(at(0));
    v.status.observed_generation = v.metadata.generation;
    v.status.observed_at = Some(at(told));
    v.status.handed_down = Some(controller_api::HandedDown {
        at: at(told),
        labels: v.metadata.labels.clone(),
    });
    v
}

/// The lab's loop: every ack was a write, the write started the next pass,
/// and the pass dispatched the same create again. Now the cluster that acked
/// the intent is left to act on it for `RETELL_AFTER`.
#[test]
fn a_drift_the_cluster_acked_lately_is_not_dispatched_again() {
    let v = stopping(10);
    assert!(!must_hand_down(&v, false, at(11)), "told a second ago");
    assert!(
        !must_hand_down(&v, false, at(39)),
        "still inside the window"
    );
    assert!(must_hand_down(&v, false, at(40)), "told again after it");
}

/// What is news goes down at once, whatever was said a moment ago: a cluster
/// that lacks the VM, and a spec generation it has not been sent.
#[test]
fn a_missing_vm_or_a_new_generation_is_dispatched_at_once() {
    let v = stopping(10);
    assert!(must_hand_down(&v, true, at(11)));
    let mut edited = stopping(10);
    edited.metadata.generation += 1;
    assert!(must_hand_down(&edited, false, at(11)));
}

/// An evacuation mark is new intent: a dispatch from before it says nothing
/// about it, one after it does.
#[test]
fn only_a_dispatch_after_the_intent_counts_as_told() {
    let v = stopping(10);
    assert!(answered_since(&v, at(5), at(11)));
    assert!(!answered_since(&v, at(12), at(13)));
}

/// `stopping(10)` with a new generation the cluster refused at `at(refused)`.
fn refused_at(refused: i64) -> Vm {
    let mut v = stopping(10);
    v.metadata.generation += 1;
    v.status.hand_down_refused = Some(controller_api::HandDownRefused {
        at: at(refused),
        generation: v.metadata.generation,
        labels: v.metadata.labels.clone(),
        message: "the shape of a vm is fixed once it exists".into(),
    });
    v
}

/// The same loop over a detour: a cluster that refuses a re-send goes on
/// reporting the VM, and each report started a pass that asked again. The
/// refusal holds the same intent back for `RETELL_AFTER`, held or missing.
#[test]
fn an_intent_the_cluster_refused_lately_is_not_asked_again() {
    let v = refused_at(20);
    assert!(!must_hand_down(&v, false, at(21)), "refused a second ago");
    assert!(!must_hand_down(&v, true, at(21)), "missing is no news");
    assert!(
        !must_hand_down(&v, false, at(49)),
        "still inside the window"
    );
    assert!(must_hand_down(&v, false, at(50)), "asked again after it");
}

/// What was refused is that intent and no other: an edit since goes down at
/// once.
#[test]
fn new_intent_after_a_refusal_goes_down_at_once() {
    let mut edited = refused_at(20);
    edited.metadata.generation += 1;
    assert!(must_hand_down(&edited, false, at(21)));
    let mut relabelled = refused_at(20);
    relabelled
        .metadata
        .labels
        .insert("app".into(), "web".into());
    assert!(must_hand_down(&relabelled, false, at(21)));
}

/// A refusal after an evacuation mark answers it as an ack would: the stop
/// is asked once per window, refused or not.
#[test]
fn a_refusal_after_the_intent_counts_as_answered() {
    let v = refused_at(20);
    assert!(answered_since(&v, at(15), at(21)));
    assert!(!answered_since(&v, at(25), at(26)));
}

/// A label-only edit of a bound, acked VM goes down at once: labels move no
/// generation, and the neighbours' anti-affinity at the cluster reads them.
#[test]
fn a_label_edit_of_an_acked_vm_is_handed_down() {
    let mut v = stopping(10);
    v.spec.run_strategy = RunStrategy::Running;
    assert!(!must_hand_down(&v, false, at(11)), "nothing new");
    v.metadata.labels.insert("app".into(), "web".into());
    assert!(must_hand_down(&v, false, at(11)));
}

/// A VM handed down before the record existed goes down once more, so the
/// cluster's copy gets the labels it never carried.
#[test]
fn a_vm_handed_down_before_labels_travelled_goes_down_once_more() {
    let mut v = stopping(10);
    v.spec.run_strategy = RunStrategy::Running;
    v.status.handed_down = None;
    assert!(must_hand_down(&v, false, at(11)));
}

/// A phase the cluster reported a moment ago is not a hand-down: the drift
/// it shows goes down unless the cluster itself acked the intent lately.
#[test]
fn a_fresh_report_does_not_stand_in_for_a_hand_down() {
    let mut v = stopping(10);
    v.status.observed_at = Some(at(100));
    assert!(must_hand_down(&v, false, at(101)));
}

// --- IKR-B78: a cluster is offered only where one node can take the VM -----

/// A ready node of 4 vCPUs and `mem_mib`, nothing bound.
fn reported_node(name: &str, mem_mib: u64) -> controller_api::NodeSummary {
    controller_api::NodeSummary {
        name: name.into(),
        ready: true,
        schedulable: true,
        vcpus: 4,
        mem_mib,
        ..Default::default()
    }
}

/// The cluster `ikr-netlab` with two nodes of `mem_mib` each.
fn netlab(mem_mib: u64) -> Cluster {
    let mut cluster = Cluster::declare("ikr-netlab", Default::default());
    cluster.status.nodes = vec![
        reported_node("cobra0", mem_mib),
        reported_node("cobra1", mem_mib),
    ];
    cluster.status.capacity.vcpus = 8;
    cluster.status.capacity.mem_mib = 2 * mem_mib;
    cluster
}

/// `vm()`, unbound, asking for one vCPU and `mem_mib`.
fn asking(mem_mib: u64) -> Vm {
    let mut v = vm();
    v.spec.cluster_name = None;
    v.spec.vm = serde_json::json!({ "vcpus": 1, "memory_mib": mem_mib });
    v
}

/// The pass's ledger over one cluster, as `expire_and_collect_clusters`
/// builds it.
fn ledger_of(cluster: &Cluster, vms: &[Vm]) -> std::sync::Mutex<Ledger> {
    let name = cluster.metadata.name.clone();
    let mut ledger = Ledger::default();
    ledger.nodes.insert(name.clone(), rooms(cluster, vms));
    ledger.clusters.push(Candidate {
        name: name.clone(),
        connected: true,
        alive: true,
        schedulable: true,
        unhealthy: Vec::new(),
        free: free_on(&name, &cluster.status.capacity, vms, Overcommit::default()),
        catalogue: vec!["hypervisor/cloud-hypervisor".to_string()],
        kind: CandidateKind::Cluster,
        labels: Default::default(),
        accepts: Vec::new(),
        hosted: Vec::new(),
        machine: None,
    });
    std::sync::Mutex::new(ledger)
}

/// `rooms_of` with each unreported VM booked by its own asks, as
/// `unreported_on` books a VM without volumes.
fn rooms(cluster: &Cluster, vms: &[Vm]) -> Vec<NodeRoom> {
    let booked: Vec<Wanted> = unreported(&cluster.metadata.name, vms)
        .map(|v| Wanted::of(v, None, None))
        .collect();
    rooms_of(cluster, &booked, Overcommit::default())
}

/// The lab's repro: 4096 MiB asked, every node with 2048 MiB. The sum of the
/// cluster had room, the cloud bound, and the VM sat Pending a tier down.
#[test]
fn a_cluster_is_offered_only_where_one_node_can_take_the_vm() {
    let rooms = rooms(&netlab(2048), &[]);
    let too_big = asking(4096);
    assert!(!Wanted::of(&too_big, None, None).served_by("ikr-netlab", &rooms));
    let fits = asking(1024);
    assert!(Wanted::of(&fits, None, None).served_by("ikr-netlab", &rooms));

    let (category, sentence) = node_level_reason(&too_big, 1);
    assert_eq!(category, controller_api::PendingReason::NoCapacity);
    assert!(sentence.contains("4096 MiB"), "{sentence}");
}

/// A burst of creates in one pass: each 2560 MiB VM fits the cluster's sum
/// three times over two 4096 MiB nodes, and only one fits each node. The
/// third is not bound, because the first two took their room off a node
/// and not only off the sum.
#[test]
fn vms_bound_in_one_pass_take_their_room_off_the_nodes() {
    let ledger = ledger_of(&netlab(4096), &[]);
    let burst: Vec<Vm> = (0..3).map(|_| asking(2560)).collect();
    let picked: Vec<bool> = burst
        .iter()
        .map(|v| {
            pick_cluster(
                &controller_api::FirstFit,
                &ledger,
                v,
                &Wanted::of(v, None, None),
            )
            .is_ok()
        })
        .collect();
    assert_eq!(picked, [true, true, false]);
}

/// A VM bound to the cluster that it has not reported yet holds a node's
/// room as surely as one it placed; one it reported is in its own numbers
/// and is not counted twice.
#[test]
fn a_vm_bound_but_not_reported_yet_holds_a_nodes_room() {
    let cluster = netlab(4096);
    let mut sent = asking(3072);
    sent.spec.cluster_name = Some("ikr-netlab".into());
    let roomy: Vec<u64> = rooms(&cluster, std::slice::from_ref(&sent))
        .iter()
        .map(|r| r.room.mem_mib)
        .collect();
    assert_eq!(roomy, [1024, 4096]);

    sent.status.reported = Some(controller_api::VmReported::by(
        "ikr-netlab",
        VmPhaseKind::Pending,
        controller_api::VmReason::Unrecorded,
        None,
        at(0),
    ));
    assert!(
        rooms(&cluster, std::slice::from_ref(&sent))
            .iter()
            .all(|r| r.room.mem_mib == 4096)
    );
}

/// The pass that binds a VM and every pass after it, until the cluster
/// reports it, book it on the same node: the one its selector picks, not the
/// roomiest of all. Booked elsewhere, the selected node looked free again a
/// pass later.
#[test]
fn a_vm_bound_but_not_reported_yet_is_booked_where_its_binding_booked_it() {
    let mut cluster = netlab(4096);
    cluster.status.nodes[0]
        .labels
        .insert("disk".into(), "ssd".into());
    cluster.status.nodes[1].mem_mib = 6144;
    let mut ssd = asking(3072);
    ssd.spec.node_selector.insert("disk".into(), "ssd".into());
    let ledger = ledger_of(&cluster, &[]);
    pick_cluster(
        &controller_api::FirstFit,
        &ledger,
        &ssd,
        &Wanted::of(&ssd, None, None),
    )
    .expect("bound");
    let booked =
        |rooms: &[NodeRoom]| -> Vec<u64> { rooms.iter().map(|r| r.room.mem_mib).collect() };
    let at_binding = booked(&ledger.lock().unwrap().nodes["ikr-netlab"]);

    ssd.spec.cluster_name = Some("ikr-netlab".into());
    let next_pass = booked(&rooms(&cluster, std::slice::from_ref(&ssd)));

    assert_eq!(at_binding, [1024, 6144]);
    assert_eq!(next_pass, at_binding);
}

/// What the cluster holds without a node comes off a node before the next
/// VM is measured.
#[test]
fn what_a_cluster_holds_unplaced_holds_a_nodes_room() {
    let mut cluster = netlab(4096);
    cluster.status.unplaced = vec![
        Capacity {
            vcpus: 1,
            mem_mib: 3072,
        };
        2
    ];
    let rooms = rooms(&cluster, &[]);
    let more_than_is_left = asking(2048);
    assert!(!Wanted::of(&more_than_is_left, None, None).served_by("ikr-netlab", &rooms));
}

/// A cluster whose list of what waits there for a node stops short offers no
/// room on any node: what the rest takes is not known. (IKR-B78)
#[test]
fn a_cluster_whose_unplaced_list_was_cut_short_offers_no_room() {
    let mut cluster = netlab(4096);
    cluster.status.unplaced_omitted = 1;
    let rooms = rooms(&cluster, &[]);
    assert!(!Wanted::of(&asking(512), None, None).served_by("ikr-netlab", &rooms));
}

// --- IKR-B81: a write lands on the object that was judged -------------------

/// A store under a fresh prefix of the test etcd (`MEISTER_TEST_ETCD`).
async fn test_store(area: &str) -> EtcdStore {
    let endpoint =
        std::env::var("MEISTER_TEST_ETCD").unwrap_or_else(|_| "http://127.0.0.1:23700".into());
    EtcdStore::connect(&[endpoint], &format!("/{area}/{}", uuid::Uuid::new_v4()))
        .await
        .expect("an etcd to talk to")
}

/// `netlab(mem_mib)`, connected and heard from now, in `store`.
async fn connected_netlab(store: &EtcdStore, mem_mib: u64) {
    let mut cluster = netlab(mem_mib);
    cluster.status.connected = true;
    cluster.status.capacity.capabilities = vec!["hypervisor/cloud-hypervisor".to_string()];
    store.create(&cluster).await.expect("the cluster");
    store
        .beat::<Cluster>("ikr-netlab", Utc::now())
        .await
        .expect("its heartbeat");
}

/// A preview answers with the pass's own decision and sentence: bound where
/// one node takes the VM, and the node-level sentence where none does.
#[tokio::test]
#[ignore = "needs an etcd; see api::admission_tests"]
async fn a_preview_says_what_the_pass_would_decide() {
    let store = test_store("preview-test").await;
    connected_netlab(&store, 2048).await;
    let preview = |vm: Vm| {
        let store = &store;
        async move {
            would_place(store, &controller_api::FirstFit, Overcommit::default(), &vm)
                .await
                .expect("a preview")
        }
    };

    assert_eq!(
        preview(asking(1024)).await,
        "would place on cluster ikr-netlab"
    );
    assert_eq!(
        preview(asking(4096)).await,
        node_level_reason(&asking(4096), 1).1
    );
}

/// What a dispatch carried is stamped onto the reservation it was read from,
/// not onto one released and reserved again under the same address since.
#[tokio::test]
#[ignore = "needs an etcd; see api::admission_tests"]
async fn a_stamp_for_an_old_reservation_leaves_the_new_one_alone() {
    let store = test_store("stamp-test").await;
    let reservation = || {
        controller_api::FloatingIp::declare(
            "198.51.100.9",
            controller_api::FloatingIpSpec {
                tenant: "acme".into(),
                address: "198.51.100.9".into(),
                ..Default::default()
            },
        )
    };
    let old = store.create(&reservation()).await.expect("the old one");
    let carried = Carried {
        resource: controller_api::FloatingIp::RESOURCE,
        name: old.metadata.name.clone(),
        uid: old.metadata.uid.clone(),
        generation: old.metadata.generation,
    };
    store
        .delete::<controller_api::FloatingIp>("198.51.100.9")
        .await
        .expect("released");
    store.create(&reservation()).await.expect("reserved again");

    stamp_addresses(&store, &[carried]).await;

    let new: controller_api::FloatingIp = store.get("198.51.100.9").await.expect("the new one");
    assert_eq!(
        new.status.observed_generation, 0,
        "nothing travelled for it"
    );
}

/// The lab's loop end to end: a cluster that keeps the VM and refuses its
/// re-send is asked once over three passes, and the refusal is on the VM.
/// Each pass is one the cluster's report started. (IKR-B74)
#[tokio::test]
#[ignore = "needs an etcd; see api::admission_tests"]
async fn a_cluster_that_refuses_a_resend_is_asked_once_in_three_passes() {
    let store = test_store("refused-test").await;
    let registry = Arc::new(crate::session::SessionRegistry::new());
    let asked = registry.refusing("cluster-1", "the shape of a vm is fixed once it exists");
    // Stored at generation 1 and never acked: a generation to send.
    let held = store.create(&vm()).await.expect("a bound vm");
    let report = crate::session::Report {
        at: Utc::now(),
        uids: [held.metadata.uid.clone()].into_iter().collect(),
        routers: None,
    };

    for _ in 0..3 {
        let listed: Vm = store.get("t").await.expect("the vm");
        hand_down(
            &store,
            &registry,
            &OnceCell::new(),
            &listed,
            "cluster-1",
            &report,
            "",
        )
        .await
        .expect("a pass");
    }

    assert_eq!(asked.load(std::sync::atomic::Ordering::SeqCst), 1);
    let after: Vm = store.get("t").await.expect("the vm");
    let refusal = after.status.hand_down_refused.expect("the refusal is kept");
    assert_eq!(refusal.generation, held.metadata.generation);
    assert!(refusal.message.contains("shape"), "{}", refusal.message);
}

/// The teardown of a VM that was never placed deletes that VM and not one
/// made under its name since.
#[tokio::test]
#[ignore = "needs an etcd; see api::admission_tests"]
async fn a_teardown_judged_on_an_old_vm_leaves_the_recreated_one() {
    let store = test_store("teardown-test").await;
    let unplaced = || {
        let mut v = vm();
        v.spec.cluster_name = None;
        v.metadata.deletion_timestamp = Some(Utc::now());
        v
    };
    let old = store.create(&unplaced()).await.expect("the old vm");
    store.delete::<Vm>("t").await.expect("it goes");
    let mut fresh = vm();
    fresh.spec.cluster_name = None;
    let fresh = store.create(&fresh).await.expect("a new vm of that name");

    teardown(&store, &crate::session::SessionRegistry::new(), &old, "")
        .await
        .expect("a pass");

    let still: Vm = store.get("t").await.expect("the new vm");
    assert_eq!(still.metadata.uid, fresh.metadata.uid);
}
