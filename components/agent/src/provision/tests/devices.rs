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

/// Device admission receives other VMs' persisted claims before allocating resources.
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

    // Use distinct, universally available character devices as evdev stand-ins.
    // Admission checks device numbers without requiring host input hardware.
    const NODE_A: &str = "/dev/null";
    const NODE_B: &str = "/dev/zero";

    // The guest that has the node, as a record in the store — which is the
    // only place a claim lives, and why a teardown gives the node back.
    let holder = VmId::new_v4();
    let mut held = spec_record();
    held.spec.devices = vec![evdev(NODE_A)];
    store.put(&holder, &held).expect("the holder's record");

    let err = provisioner
        .check_device_admission(&VmId::new_v4(), &spec(1, 256, vec![evdev(NODE_A)]))
        .expect_err("the node is taken");
    // Inspect the full error chain, including the underlying driver refusal.
    let err = format!("{err:#}");
    assert!(err.contains(NODE_A), "{err}");
    assert!(err.contains(&holder.to_string()), "{err}");
    assert!(err.contains("input"), "the message names the driver: {err}");

    // A different host device is a different claim.
    provisioner
        .check_device_admission(&VmId::new_v4(), &spec(1, 256, vec![evdev(NODE_B)]))
        .expect("another node is not this node");
    // Input admission requires a host device path.
    let err = provisioner
        .check_device_admission(
            &VmId::new_v4(),
            &spec(1, 256, vec![device("input", PartitionSpec::Mediated)]),
        )
        .expect_err("an input device has to name its host node");
    let err = format!("{err:#}");
    assert!(err.contains("params.evdev"), "{err}");
}
