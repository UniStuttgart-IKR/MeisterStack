// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! The overlay's user count, which is read off the records rather than
//! kept.

use super::*;

/// Record NIC and overlay operations together to verify cross-resource teardown order.
#[derive(Default)]
struct RecordingNet {
    taps_destroyed: std::sync::Mutex<Vec<agent_api::networking::NicId>>,
    overlays_destroyed: std::sync::Mutex<Vec<u32>>,
    /// What the teardown said this overlay was called, per removal — the
    /// record's own answer, or `None` where no record wrote one down.
    overlays_named: std::sync::Mutex<Vec<Option<String>>>,
}

#[async_trait::async_trait]
impl agent_api::networking::NicDriver for RecordingNet {
    async fn create(
        &self,
        id: &agent_api::networking::NicId,
        spec: &agent_api::networking::NicSpec,
    ) -> agent_api::networking::Result<agent_api::networking::Nic> {
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
