// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! The overlay's user count, which is read off the records rather than
//! kept, and the address guards a re-sent spec moves (NL4-1).

use super::*;
use agent_api::networking::{NetworkError, NicId, NicSpec};

/// How the fake answers `update_guard` instead of swapping the guard.
type GuardRefusal = fn(&NicId) -> NetworkError;

/// Record NIC and overlay operations together to verify cross-resource teardown order.
#[derive(Default)]
struct RecordingNet {
    taps_destroyed: std::sync::Mutex<Vec<agent_api::networking::NicId>>,
    overlays_destroyed: std::sync::Mutex<Vec<u32>>,
    /// What the teardown said this overlay was called, per removal — the
    /// record's own answer, or `None` where no record wrote one down.
    overlays_named: std::sync::Mutex<Vec<Option<String>>>,
    /// Every tap created, with the spec it was built from, in order.
    taps_created: std::sync::Mutex<Vec<(NicId, NicSpec)>>,
    /// Every guard swapped, with the spec it was built from, in order.
    guards_updated: std::sync::Mutex<Vec<(NicId, NicSpec)>>,
    /// `Some` refuses every guard swap with the error it makes.
    guard_refusal: std::sync::Mutex<Option<GuardRefusal>>,
}

#[async_trait::async_trait]
impl agent_api::networking::NicDriver for RecordingNet {
    async fn create(
        &self,
        id: &agent_api::networking::NicId,
        spec: &agent_api::networking::NicSpec,
    ) -> agent_api::networking::Result<agent_api::networking::Nic> {
        self.taps_created.lock().unwrap().push((*id, spec.clone()));
        Ok(agent_api::networking::Nic {
            id: *id,
            tap_name: format!("tap{id}"),
            mtu: None,
            // Preserve the requested MAC in the fake attachment for status reporting.
            mac: Some(spec.mac),
        })
    }
    async fn destroy(
        &self,
        id: &agent_api::networking::NicId,
    ) -> agent_api::networking::Result<()> {
        self.taps_destroyed.lock().unwrap().push(*id);
        Ok(())
    }
    async fn get(
        &self,
        id: &agent_api::networking::NicId,
    ) -> agent_api::networking::Result<agent_api::networking::Nic> {
        Ok(agent_api::networking::Nic {
            id: *id,
            tap_name: format!("tap{id}"),
            mtu: None,
            // Liveness only, as on a real node: `get` sets nothing and
            // therefore knows nothing.
            mac: None,
        })
    }
    async fn update_guard(&self, id: &NicId, spec: &NicSpec) -> agent_api::networking::Result<()> {
        if let Some(refuse) = *self.guard_refusal.lock().unwrap() {
            return Err(refuse(id));
        }
        self.guards_updated
            .lock()
            .unwrap()
            .push((*id, spec.clone()));
        Ok(())
    }
}

#[async_trait::async_trait]
impl agent_api::networking::BridgeDriver for RecordingNet {
    async fn ensure(&self, _: &str) -> agent_api::networking::Result<()> {
        Ok(())
    }
    async fn ensure_address(&self, _: &str, _: IpAddr, _: u8) -> agent_api::networking::Result<()> {
        Ok(())
    }
    async fn destroy(&self, _: &str) -> agent_api::networking::Result<()> {
        Ok(())
    }
    async fn ensure_overlay(&self, vni: u32) -> agent_api::networking::Result<String> {
        Ok(format!("meister-vx{vni}"))
    }
    async fn destroy_overlay(
        &self,
        vni: u32,
        recorded: Option<&str>,
    ) -> agent_api::networking::Result<()> {
        self.overlays_destroyed.lock().unwrap().push(vni);
        self.overlays_named
            .lock()
            .unwrap()
            .push(recorded.map(str::to_string));
        Ok(())
    }
}

/// Overlay users are derived from persisted records, including after reopening the store.
#[tokio::test]
async fn an_overlay_goes_when_its_last_vm_does_and_a_restart_does_not_confuse_the_count() {
    let temp = tempfile::tempdir().expect("a temp dir");
    let root = temp.path().to_path_buf();
    let db = root.join("agent.redb");

    let vni = 10_042;
    let (first_id, first) = overlay_vm(vni);
    let (second_id, second) = overlay_vm(vni);
    // A third VM on a DIFFERENT wire, which must never be counted and
    // whose overlay must never be touched.
    let (other_id, other) = overlay_vm(10_043);

    let net = Arc::new(RecordingNet::default());
    let build = |store: Arc<crate::store::Store>| {
        Provisioner::new(
            store,
            Drivers {
                confiner: Arc::new(cgroup_driver::CgroupV2::new(root.join("cgroup"))),
                hypervisor: Some(Arc::new(EmptyHypervisor)),
                hypervisor_name: Some("empty".into()),
                storage: std::collections::HashMap::new(),
                networking: Some(net.clone()),
                bridge: Some(net.clone()),
                announcer: None,
                devices: std::collections::HashMap::new(),
            },
            Arc::new(crate::images::Cache::new(root.join("images"))),
            root.join("images"),
            root.join("run"),
            "br0".to_string(),
            None,
            None,
        )
    };

    {
        let store = Arc::new(crate::store::Store::open(&db).expect("a store"));
        store.put(&first_id, &first).expect("first record");
        store.put(&second_id, &second).expect("second record");
        store.put(&other_id, &other).expect("third record");

        build(store).teardown(&first_id).await.expect("first goes");
    }

    assert_eq!(
        net.taps_destroyed.lock().unwrap().len(),
        1,
        "the first vm's tap came down"
    );
    assert!(
        net.overlays_destroyed.lock().unwrap().is_empty(),
        "the second vm still uses the wire, so the overlay stays: {:?}",
        net.overlays_destroyed.lock().unwrap()
    );

    // The agent restarts here. Nothing is carried over but the file.
    {
        let store = Arc::new(crate::store::Store::open(&db).expect("the store, reopened"));
        assert!(
            store.get(&first_id).expect("a read").is_none(),
            "the torn-down record did not survive"
        );
        build(store)
            .teardown(&second_id)
            .await
            .expect("second goes");
    }

    assert_eq!(
        *net.overlays_destroyed.lock().unwrap(),
        vec![vni],
        "the last vm on the wire took the overlay with it, and only that one"
    );

    // Remaining references keep the overlay alive.
    {
        let store = Arc::new(crate::store::Store::open(&db).expect("the store, again"));
        assert!(store.get(&other_id).expect("a read").is_some());
    }
    assert!(
        !net.overlays_destroyed.lock().unwrap().contains(&10_043),
        "a tenant with a live vm keeps its overlay"
    );
}

/// The count is over records and not over taps, so a VM whose record is
/// still there holds the overlay open even when it has no tap on the host
/// yet — the window between "told to run it" and "run_chain got that far".
#[test]
fn a_vm_that_has_not_made_its_tap_yet_still_counts_as_a_user() {
    let temp = tempfile::tempdir().expect("a temp dir");
    let root = temp.path().to_path_buf();
    let store = crate::store::Store::open(&root.join("a.redb")).expect("a store");

    let vni = 10_099;
    let (leaving, leaving_record) = overlay_vm(vni);
    let (arriving, mut arriving_record) = overlay_vm(vni);
    // Told to run, nothing built yet.
    arriving_record.phase = Phase::Provisioning;
    arriving_record.nics.clear();
    store.put(&leaving, &leaving_record).expect("a record");
    store.put(&arriving, &arriving_record).expect("a record");

    assert_eq!(
        overlay_users(&store, vni, &leaving).expect("a count"),
        1,
        "the vm mid-provision is a user of the wire"
    );
    assert_eq!(
        overlay_users(&store, 10_100, &leaving).expect("a count"),
        0,
        "and a wire nobody named has none"
    );
}

/// Pass the persisted bridge name to cleanup; legacy records supply None.
#[tokio::test]
async fn the_teardown_names_the_bridge_the_record_says_the_overlay_got() {
    let temp = tempfile::tempdir().expect("a temp dir");
    let root = temp.path().to_path_buf();
    let db = root.join("agent.redb");

    let named_vni = 10_055;
    let old_vni = 10_056;
    let (named_id, mut named) = overlay_vm(named_vni);
    named
        .overlay_bridges
        .insert(named_vni, "meister-vx10055".to_string());
    // A record from before the field existed: it deserialises with an empty
    // map, which is what `Default::default()` is here.
    let (old_id, old) = overlay_vm(old_vni);

    let net = Arc::new(RecordingNet::default());
    let store = Arc::new(crate::store::Store::open(&db).expect("a store"));
    store.put(&named_id, &named).expect("a record");
    store.put(&old_id, &old).expect("a record");
    let provisioner = Provisioner::new(
        store,
        Drivers {
            confiner: Arc::new(cgroup_driver::CgroupV2::new(root.join("cgroup"))),
            hypervisor: Some(Arc::new(EmptyHypervisor)),
            hypervisor_name: Some("empty".into()),
            storage: std::collections::HashMap::new(),
            networking: Some(net.clone()),
            bridge: Some(net.clone()),
            announcer: None,
            devices: std::collections::HashMap::new(),
        },
        Arc::new(crate::images::Cache::new(root.join("images"))),
        root.join("images"),
        root.join("run"),
        "br0".to_string(),
        None,
        None,
    );

    provisioner.teardown(&named_id).await.expect("it goes");
    provisioner.teardown(&old_id).await.expect("it goes too");

    assert_eq!(
        *net.overlays_destroyed.lock().unwrap(),
        vec![named_vni, old_vni],
        "each was the last vm on its own wire"
    );
    assert_eq!(
        *net.overlays_named.lock().unwrap(),
        vec![Some("meister-vx10055".to_string()), None],
        "the record's name where there is one, and nothing invented where there is not"
    );
}

/// An unreadable row conservatively counts as a user of every overlay.
#[test]
fn a_record_this_build_cannot_read_still_holds_the_wire_open() {
    let temp = tempfile::tempdir().expect("a temp dir");
    let root = temp.path().to_path_buf();
    let store = crate::store::Store::open(&root.join("a.redb")).expect("a store");

    let vni = 10_077;
    let (leaving, leaving_record) = overlay_vm(vni);
    store.put(&leaving, &leaving_record).expect("a record");
    // A row from a build that wrote a field this one does not know how to
    // read back. A valid key, so nothing else about it is unusual.
    let damaged = VmId::new_v4();
    store
        .put_raw(&damaged.to_string(), br#"{"spec":"from a later build"}"#)
        .expect("a raw row");

    assert_eq!(
        store.list().expect("a list").len(),
        1,
        "the ordinary reader passes over it, which is what this is about"
    );
    assert_eq!(
        overlay_users(&store, vni, &leaving).expect("a count"),
        1,
        "the unreadable row is a user of the wire this vm is leaving"
    );
    assert_eq!(
        overlay_users(&store, 10_078, &leaving).expect("a count"),
        1,
        "and of every other wire, because nobody can say it is not"
    );
}

// --- a re-sent spec's addresses on a VM that exists (NL4-1) ------------------

const KEPT: &str = "10.7.1.0/24";
const TAKEN: &str = "10.7.2.0/24";

/// A provisioner whose network driver is `net`, over `store`.
fn provisioner_on(
    root: &std::path::Path,
    store: Arc<crate::store::Store>,
    net: Arc<RecordingNet>,
) -> Provisioner {
    Provisioner::new(
        store,
        Drivers {
            confiner: Arc::new(cgroup_driver::CgroupV2::new(root.join("cgroup"))),
            hypervisor: Some(Arc::new(EmptyHypervisor)),
            hypervisor_name: Some("empty".into()),
            storage: std::collections::HashMap::new(),
            networking: Some(net.clone()),
            bridge: Some(net),
            announcer: None,
            devices: std::collections::HashMap::new(),
        },
        Arc::new(crate::images::Cache::new(root.join("images"))),
        root.join("images"),
        root.join("run"),
        "br0".to_string(),
        None,
        None,
    )
}

/// A running VM with one tap whose guard allows `subnets`, stored, and its id.
fn running_vm_allowing(store: &crate::store::Store, subnets: &[&str]) -> (VmId, VmRecord) {
    let (id, mut record) = overlay_vm(10_400);
    record.spec.nics[0].spec.routed_subnets = subnets.iter().map(|s| s.to_string()).collect();
    store.put(&id, &record).expect("a record");
    (id, record)
}

/// The spec of `record` re-sent with its one NIC allowing `subnets`.
fn resent_allowing(record: &VmRecord, subnets: &[&str]) -> AgentVmSpec {
    let mut spec = record.spec.clone();
    spec.nics[0].spec.routed_subnets = subnets.iter().map(|s| s.to_string()).collect();
    spec
}

fn held_subnets(store: &crate::store::Store, id: &VmId) -> Vec<String> {
    held_nic(store, id).routed_subnets
}

/// The record's spec of the VM's one NIC.
fn held_nic(store: &crate::store::Store, id: &VmId) -> NicSpec {
    store
        .get(id)
        .expect("a read")
        .expect("the record")
        .spec
        .nics[0]
        .spec
        .clone()
}

/// A subnet the re-sent spec no longer names leaves the running tap's guard at once, and the
/// record with it, so a later start does not let it back in.
#[tokio::test]
async fn a_subnet_taken_from_a_running_vm_leaves_its_tap_guard_and_its_record() {
    let temp = tempfile::tempdir().expect("a temp dir");
    let store = Arc::new(crate::store::Store::open(&temp.path().join("a.redb")).expect("a store"));
    let (id, record) = running_vm_allowing(&store, &[KEPT, TAKEN]);
    let net = Arc::new(RecordingNet::default());

    provisioner_on(temp.path(), store.clone(), net.clone())
        .sync_in_place(&id, &resent_allowing(&record, &[KEPT]))
        .await
        .expect("the re-sent spec is taken in");

    let updated = net.guards_updated.lock().unwrap().clone();
    assert_eq!(updated.len(), 1, "one guard swapped: {updated:?}");
    assert_eq!(updated[0].0, record.spec.nics[0].id);
    assert_eq!(updated[0].1.routed_subnets, [KEPT]);
    assert_eq!(held_subnets(&store, &id), [KEPT]);
}

/// A subnet the re-sent spec adds is let through the running tap's guard at once.
#[tokio::test]
async fn a_subnet_given_to_a_running_vm_is_let_through_its_tap_guard() {
    let temp = tempfile::tempdir().expect("a temp dir");
    let store = Arc::new(crate::store::Store::open(&temp.path().join("a.redb")).expect("a store"));
    let (id, record) = running_vm_allowing(&store, &[KEPT]);
    let net = Arc::new(RecordingNet::default());

    provisioner_on(temp.path(), store.clone(), net.clone())
        .sync_in_place(&id, &resent_allowing(&record, &[KEPT, TAKEN]))
        .await
        .expect("the re-sent spec is taken in");

    let updated = net.guards_updated.lock().unwrap().clone();
    assert_eq!(updated.len(), 1, "one guard swapped: {updated:?}");
    assert_eq!(updated[0].1.routed_subnets, [KEPT, TAKEN]);
    assert_eq!(held_subnets(&store, &id), [KEPT, TAKEN]);
}

/// A floating address taken away is a change to the guard as much as a subnet is.
#[tokio::test]
async fn a_floating_address_taken_from_a_running_vm_leaves_its_tap_guard() {
    let temp = tempfile::tempdir().expect("a temp dir");
    let store = Arc::new(crate::store::Store::open(&temp.path().join("a.redb")).expect("a store"));
    let (id, mut record) = overlay_vm(10_401);
    record.spec.nics[0].spec.floating_ips = vec!["10.255.0.7".into()];
    store.put(&id, &record).expect("a record");
    let mut resent = record.spec.clone();
    resent.nics[0].spec.floating_ips.clear();
    let net = Arc::new(RecordingNet::default());

    provisioner_on(temp.path(), store.clone(), net.clone())
        .sync_in_place(&id, &resent)
        .await
        .expect("the re-sent spec is taken in");

    let updated = net.guards_updated.lock().unwrap().clone();
    assert_eq!(updated.len(), 1, "one guard swapped: {updated:?}");
    assert!(updated[0].1.floating_ips.is_empty(), "{updated:?}");
}

/// Re-sending what the VM already has swaps no guard; a re-send is idempotent.
#[tokio::test]
async fn a_resent_spec_with_the_same_addresses_swaps_no_guard() {
    let temp = tempfile::tempdir().expect("a temp dir");
    let store = Arc::new(crate::store::Store::open(&temp.path().join("a.redb")).expect("a store"));
    let (id, record) = running_vm_allowing(&store, &[KEPT, TAKEN]);
    let net = Arc::new(RecordingNet::default());

    provisioner_on(temp.path(), store.clone(), net.clone())
        .sync_in_place(&id, &record.spec)
        .await
        .expect("nothing to do is done");

    assert!(net.guards_updated.lock().unwrap().is_empty());
}

/// Only the address lists follow a re-sent NIC: the guard keeps pinning the MAC the guest was
/// created with, which is the MAC it still sends from.
#[tokio::test]
async fn a_resent_nic_keeps_the_mac_it_was_created_with_and_takes_only_its_addresses() {
    let temp = tempfile::tempdir().expect("a temp dir");
    let store = Arc::new(crate::store::Store::open(&temp.path().join("a.redb")).expect("a store"));
    let (id, record) = running_vm_allowing(&store, &[KEPT, TAKEN]);
    let mut resent = resent_allowing(&record, &[KEPT]);
    resent.nics[0].spec.mac = "52:54:00:00:00:99".parse().expect("a mac");
    let net = Arc::new(RecordingNet::default());

    provisioner_on(temp.path(), store.clone(), net.clone())
        .sync_in_place(&id, &resent)
        .await
        .expect("the re-sent spec is taken in");

    let updated = net.guards_updated.lock().unwrap().clone();
    assert_eq!(updated[0].1.mac, record.spec.nics[0].spec.mac);
    assert_eq!(updated[0].1.routed_subnets, [KEPT]);
    let held = store.get(&id).expect("a read").expect("the record");
    assert_eq!(held.spec.nics[0].spec.mac, record.spec.nics[0].spec.mac);
}

/// A guard the driver refuses leaves the record on the old lists, so the next re-send sees the
/// difference again and tries again, instead of the record claiming a guard the tap lacks.
#[tokio::test]
async fn a_guard_the_driver_refuses_leaves_the_record_on_the_old_addresses_for_the_retry() {
    let temp = tempfile::tempdir().expect("a temp dir");
    let store = Arc::new(crate::store::Store::open(&temp.path().join("a.redb")).expect("a store"));
    let (id, record) = running_vm_allowing(&store, &[KEPT, TAKEN]);
    let net = Arc::new(RecordingNet::default());
    *net.guard_refusal.lock().unwrap() =
        Some(|_| NetworkError::Backend(anyhow!("nft refused the ruleset")));
    let provisioner = provisioner_on(temp.path(), store.clone(), net.clone());
    let resent = resent_allowing(&record, &[KEPT]);

    let refused = provisioner
        .sync_in_place(&id, &resent)
        .await
        .expect_err("a refused guard is the caller's error");
    assert!(
        format!("{refused:#}").contains("nft refused the ruleset"),
        "{refused:#}"
    );
    assert_eq!(held_subnets(&store, &id), [KEPT, TAKEN]);

    *net.guard_refusal.lock().unwrap() = None;
    provisioner
        .sync_in_place(&id, &resent)
        .await
        .expect("the retry takes it in");
    assert_eq!(held_subnets(&store, &id), [KEPT]);
}

/// A NIC whose tap is not on the host has no guard to swap; the record takes the new lists,
/// and they are what its next start guards it with.
#[tokio::test]
async fn a_nic_without_a_tap_takes_the_new_addresses_into_the_record_alone() {
    let temp = tempfile::tempdir().expect("a temp dir");
    let store = Arc::new(crate::store::Store::open(&temp.path().join("a.redb")).expect("a store"));
    let (id, record) = running_vm_allowing(&store, &[KEPT, TAKEN]);
    let net = Arc::new(RecordingNet::default());
    *net.guard_refusal.lock().unwrap() = Some(|nic| NetworkError::NicNotFound(*nic));

    provisioner_on(temp.path(), store.clone(), net.clone())
        .sync_in_place(&id, &resent_allowing(&record, &[KEPT]))
        .await
        .expect("a missing tap is not a failure");

    assert_eq!(held_subnets(&store, &id), [KEPT]);
}

/// The last prefix a re-send takes from a running VM leaves its tap guarded as the re-sent
/// document says, on the pool ban, and the record with it: no node keeps an allowlist of its
/// own for a NIC whose document names no prefix. The ban covers the node's guarded ranges, the
/// routed pools the subnet was cut from among them, so the subnet taken stays dropped
/// (tap_guard_netns, RR5-1). That a tenant's guests keep their network's prefix is the
/// controller's to send (NL5-1); this tier holds no word about it. (NL5-2)
#[tokio::test]
async fn the_last_prefix_taken_from_a_running_vm_leaves_its_tap_as_the_document_says() {
    let temp = tempfile::tempdir().expect("a temp dir");
    let store = Arc::new(crate::store::Store::open(&temp.path().join("a.redb")).expect("a store"));
    let (id, record) = running_vm_allowing(&store, &[TAKEN]);
    let net = Arc::new(RecordingNet::default());

    provisioner_on(temp.path(), store.clone(), net.clone())
        .sync_in_place(&id, &resent_allowing(&record, &[]))
        .await
        .expect("the re-sent spec is taken in");

    let updated = net.guards_updated.lock().unwrap().clone();
    assert_eq!(updated.len(), 1, "one guard swapped: {updated:?}");
    assert!(
        updated[0].1.routed_subnets.is_empty() && !updated[0].1.sources_allowlisted(),
        "{updated:?}"
    );
    assert!(held_subnets(&store, &id).is_empty());
}

/// A NIC readdressed by a re-send on one node hands the network driver exactly the spec a node
/// that creates its tap from the re-sent document alone hands it, whatever the first node held
/// before: the guard is the document's, never a node's, so an evacuation or a re-create on
/// another node changes nothing about it. Decided at the driver seam; a driver renders one
/// spec one way. (NL5-2, RR5-10)
#[tokio::test]
async fn a_readdressed_tap_is_guarded_as_a_tap_made_from_the_same_document_elsewhere() {
    for (held, sent) in [
        (&[KEPT, TAKEN][..], &[KEPT][..]),
        (&[TAKEN][..], &[][..]),
        (&[][..], &[KEPT][..]),
    ] {
        let here = tempfile::tempdir().expect("a temp dir");
        let store =
            Arc::new(crate::store::Store::open(&here.path().join("a.redb")).expect("a store"));
        let (id, record) = running_vm_allowing(&store, held);
        let resent = resent_allowing(&record, sent);
        let net_here = Arc::new(RecordingNet::default());
        provisioner_on(here.path(), store, net_here.clone())
            .sync_in_place(&id, &resent)
            .await
            .expect("the re-sent spec is taken in");

        let elsewhere = tempfile::tempdir().expect("a temp dir");
        let store_elsewhere =
            Arc::new(crate::store::Store::open(&elsewhere.path().join("b.redb")).expect("a store"));
        let net_elsewhere = Arc::new(RecordingNet::default());
        let mut fresh = record.clone();
        fresh.spec = resent.clone();
        fresh.nics.clear();
        provisioner_on(elsewhere.path(), store_elsewhere, net_elsewhere.clone())
            .attach_nics(&id, &mut fresh, &resent)
            .await
            .expect("the tap is made from the document");

        let swapped = net_here.guards_updated.lock().unwrap().clone();
        let created = net_elsewhere.taps_created.lock().unwrap().clone();
        assert_eq!(swapped.len(), 1, "{held:?} -> {sent:?}: {swapped:?}");
        assert_eq!(created.len(), 1, "{held:?} -> {sent:?}: {created:?}");
        assert_eq!(swapped[0].1, created[0].1, "{held:?} -> {sent:?}");
    }
}

/// A NIC whose document never names a prefix stays on the pool ban when its floating addresses
/// change: its address space is unknown, and an allowlist would cut its guest off from the
/// addresses it uses.
#[tokio::test]
async fn a_nic_that_never_had_a_subnet_stays_on_the_pool_ban_when_its_floating_addresses_change() {
    let temp = tempfile::tempdir().expect("a temp dir");
    let store = Arc::new(crate::store::Store::open(&temp.path().join("a.redb")).expect("a store"));
    let (id, mut record) = overlay_vm(10_402);
    record.spec.nics[0].spec.floating_ips = vec!["10.255.0.7".into()];
    store.put(&id, &record).expect("a record");
    let mut resent = record.spec.clone();
    resent.nics[0].spec.floating_ips.clear();
    let net = Arc::new(RecordingNet::default());

    provisioner_on(temp.path(), store.clone(), net.clone())
        .sync_in_place(&id, &resent)
        .await
        .expect("the re-sent spec is taken in");

    let updated = net.guards_updated.lock().unwrap().clone();
    assert_eq!(updated.len(), 1, "one guard swapped: {updated:?}");
    assert!(!updated[0].1.sources_allowlisted(), "{updated:?}");
    assert!(!held_nic(&store, &id).sources_allowlisted());
}
