// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! What a device adds to the VM's slice.

use super::*;

#[test]
fn each_device_backend_adds_headroom() {
    let one = Provisioner::limits_for(&spec(
        2,
        2048,
        vec![device("nvrm", PartitionSpec::Mediated)],
    ));
    let two = Provisioner::limits_for(&spec(
        2,
        2048,
        vec![
            device("nvrm", PartitionSpec::Mediated),
            device("crosvm-gpu", PartitionSpec::Mediated),
        ],
    ));
    assert_eq!(one.memory_max, Some((2048 + 112 + 512) * 1024 * 1024));
    assert_eq!(two.memory_max, Some((2048 + 112 + 1024) * 1024 * 1024));
}

#[test]
fn vfio_pinning_gets_extra_headroom() {
    let l = Provisioner::limits_for(&spec(
        2,
        2048,
        vec![device("vfio", PartitionSpec::Exclusive)],
    ));
    assert_eq!(l.memory_max, Some((2048 + 112 + 512 + 256) * 1024 * 1024));
}

/// The wiring of `DeviceDriver::admit`, which the input driver is the first
/// driver in this tree to implement.
///
/// Worth its own test for exactly that reason: the trait had a default that
/// said yes to everything, so the road from the store through
/// `check_device_admission` into a driver's refusal had never carried a `no`.
/// Here it does — the OTHER records in the store become the claim list, and
/// the refusal stops the provision before a cgroup, a disk or a backend
/// exists.
#[test]
fn a_host_input_node_another_vm_holds_is_refused_before_anything_is_built() {
    let temp = tempfile::tempdir().expect("a temp dir");
    let root = temp.path().to_path_buf();
    let store = Arc::new(crate::store::Store::open(&root.join("a.redb")).expect("a store"));

    // Any binary that really exists: the driver refuses to build without
    // one, and admission never runs it.
    let mut devices: HashMap<String, Arc<dyn agent_api::device::DeviceDriver>> = HashMap::new();
    devices.insert(
        "input".to_string(),
        Arc::new(
            input_driver::InputDriver::new(input_driver::InputDriverConfig {
                binary: std::env::current_exe().expect("this test binary"),
                run_dir: root.join("run").join("input"),
                socket_timeout: std::time::Duration::from_millis(1),
                vmm_user: None,
            })
            .expect("a driver over a binary that exists"),
        ),
    );

    let provisioner = Provisioner::new(
        store.clone(),
        Drivers {
            confiner: Arc::new(cgroup_driver::CgroupV2::new(root.join("cgroup"))),
            hypervisor: Some(Arc::new(EmptyHypervisor)),
            hypervisor_name: Some("empty".into()),
            storage: HashMap::new(),
            networking: None,
            bridge: None,
            announcer: None,
            devices,
        },
        Arc::new(crate::images::Cache::new(root.join("images"))),
        root.join("images"),
        root.join("run"),
        "br0".to_string(),
        None,
        None,
    );

    let evdev = |node: &str| DeviceWithId {
        id: uuid::Uuid::new_v4(),
        spec: DeviceSpec {
            driver: "input".into(),
            partition: PartitionSpec::Mediated,
            profile: Some("evdev".into()),
            params: Some(serde_json::json!({ "evdev": node })),
        },
    };

    // The guest that has the node, as a record in the store — which is the
    // only place a claim lives, and why a teardown gives the node back.
    let holder = VmId::new_v4();
    let mut held = spec_record();
    held.spec.devices = vec![evdev("/dev/input/event0")];
    store.put(&holder, &held).expect("the holder's record");

    let err = provisioner
        .check_device_admission(
            &VmId::new_v4(),
            &spec(1, 256, vec![evdev("/dev/input/event0")]),
        )
        .expect_err("the node is taken");
    // The whole chain: anyhow's outermost message is the context the
    // provisioner adds, and the driver's sentence is under it.
    let err = format!("{err:#}");
    assert!(err.contains("/dev/input/event0"), "{err}");
    assert!(err.contains(&holder.to_string()), "{err}");
    assert!(err.contains("input"), "the message names the driver: {err}");

    // A different host device is a different claim, and a fifo device
    // claims nothing at all.
    provisioner
        .check_device_admission(
            &VmId::new_v4(),
            &spec(1, 256, vec![evdev("/dev/input/event1")]),
        )
        .expect("another node is not this node");
    provisioner
        .check_device_admission(
            &VmId::new_v4(),
            &spec(1, 256, vec![device("input", PartitionSpec::Mediated)]),
        )
        .expect("a device with no host node to claim");
}
