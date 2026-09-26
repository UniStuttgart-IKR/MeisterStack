// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! The teardown: which disks are this VM's to unmake, which driver
//! unmakes them, and whose process a kill is allowed to signal.

use super::*;

/// Read volume ownership from the persisted VM spec: retain referenced data
/// and deprovision inline disks during teardown.
#[test]
fn teardown_reads_which_disks_were_this_vms_to_unmake() {
    let referenced = VolumeId::new_v4();
    let inline = VolumeId::new_v4();
    let mut record = VmRecord {
        spec: crate::types::AgentVmSpec {
            vcpus: 1,
            memory_mib: 64,
            boot: crate::types::BootSourceSpec::Firmware {
                firmware: "fw".into(),
            },
            volumes: vec![
                crate::types::VolumeWithId {
                    id: referenced,
                    spec: agent_api::storage::VolumeSpec {
                        base_image: None,
                        size_bytes: 0,
                        driver: None,
                        params: None,
                    },
                    referenced: true,
                },
                crate::types::VolumeWithId {
                    id: inline,
                    spec: agent_api::storage::VolumeSpec {
                        base_image: None,
                        size_bytes: 4096,
                        driver: None,
                        params: None,
                    },
                    referenced: false,
                },
            ],
            nics: vec![],
            devices: vec![],
            images: Vec::new(),
            cloud_init: None,
        },
        desired: Default::default(),
        phase: crate::types::Phase::Provisioned,
        operation: None,
        stop_deadline: None,
        receive_deadline: None,
        send_failed: None,
        migration: None,
        unhealthy: None,
        managed_by_controller: true,
        unattached_volumes: Vec::new(),
        volumes: vec![],
        nics: vec![],
        devices: vec![],
        vmm_pid: None,
        overlay_bridges: Default::default(),
    };
    assert!(volume_is_referenced(&record, &referenced));
    assert!(!volume_is_referenced(&record, &inline));

    // A record from before the field: every volume in it was made by that
    // VM, so the safe default is also the true one.
    record.spec.volumes.clear();
    assert!(!volume_is_referenced(&record, &referenced));
}

/// Resolve referenced-volume drivers from the standalone volume table.
/// A missing row currently falls back to the default driver, which can miss connection cleanup.
#[test]
fn a_referenced_volume_is_torn_down_by_the_driver_that_made_it() {
    let referenced = VolumeId::new_v4();
    let inline = VolumeId::new_v4();
    let entry = |id, referenced| crate::types::VolumeWithId {
        id,
        spec: agent_api::storage::VolumeSpec {
            base_image: None,
            size_bytes: 0,
            // Leave driver names unset to exercise persisted ownership lookup.
            driver: None,
            params: None,
        },
        referenced,
    };
    let record = VmRecord {
        spec: crate::types::AgentVmSpec {
            vcpus: 1,
            memory_mib: 64,
            boot: crate::types::BootSourceSpec::Firmware {
                firmware: "fw".into(),
            },
            volumes: vec![entry(referenced, true), entry(inline, false)],
            nics: vec![],
            devices: vec![],
            images: Vec::new(),
            cloud_init: None,
        },
        desired: Default::default(),
        phase: crate::types::Phase::Provisioned,
        operation: None,
        stop_deadline: None,
        receive_deadline: None,
        send_failed: None,
        migration: None,
        unhealthy: None,
        managed_by_controller: true,
        unattached_volumes: Vec::new(),
        volumes: vec![],
        nics: vec![],
        devices: vec![],
        vmm_pid: None,
        overlay_bridges: Default::default(),
    };

    let temp = tempfile::tempdir().expect("a temp dir");
    let root = temp.path().to_path_buf();
    let store = crate::store::Store::open(&root.join("a.redb")).expect("a store");
    store
        .put_volume(
            &referenced,
            &crate::types::VolumeRecord {
                spec: agent_api::storage::VolumeSpec {
                    base_image: None,
                    size_bytes: 0,
                    driver: Some("nvmeof-import".into()),
                    params: None,
                },
                handle: None,
                phase: crate::types::VolumeRecordPhase::Ready,
                reason: None,
                message: None,
                gone_at: None,
            },
        )
        .expect("a volume record");

    assert_eq!(
        volume_driver_name(&store, &record, &referenced),
        "nvmeof-import",
        "the volume table is what knows; the vm's spec cannot"
    );
    // An inline entry keeps reading off the spec — it IS this VM's disk,
    // and the volume table has no row for it.
    assert_eq!(
        volume_driver_name(&store, &record, &inline),
        default_volume_driver()
    );
    // The current fallback for a missing row is filesystem. That can leave
    // a connection open if the missing row named a driver with active cleanup.
    assert_eq!(
        volume_driver_name(&store, &record, &VolumeId::new_v4()),
        default_volume_driver()
    );
}

/// Start a shell loop with the VM marker as argv[0] and wait for /proc to show it.
/// The loop prevents the shell from replacing itself with sleep and losing the marker.
fn a_process_carrying(marker: &str) -> std::process::Child {
    let mut child = std::process::Command::new("sh")
        .arg("-c")
        .arg("while :; do sleep 1; done")
        .arg(marker)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("a process to stand in for a vmm");
    for _ in 0..500 {
        if agent_api::process_carries(child.id(), marker) {
            return child;
        }
        std::thread::sleep(std::time::Duration::from_millis(2));
    }
    // Nothing here can go on without it, and a stand-in left running
    // would outlive the test run.
    let _ = child.kill();
    let _ = child.wait();
    panic!("the stand-in never showed {marker} on its command line");
}

fn still_alive(child: &mut std::process::Child) -> bool {
    matches!(child.try_wait(), Ok(None))
}

/// Cgroup membership alone cannot identify a reused PID. Require the VM identity too.
#[tokio::test]
async fn the_teardown_kill_asks_whose_process_it_is_before_signalling() {
    let temp = tempfile::tempdir().expect("a temp dir");
    let root = temp.path().to_path_buf();
    let store = Arc::new(crate::store::Store::open(&root.join("a.redb")).expect("a store"));
    let cgroup_root = root.join("cgroup");

    let provisioner = Provisioner::new(
        store.clone(),
        Drivers {
            confiner: Arc::new(cgroup_driver::CgroupV2::new(cgroup_root.clone())),
            hypervisor: Some(Arc::new(EmptyHypervisor)),
            hypervisor_name: Some("empty".into()),
            storage: HashMap::new(),
            networking: None,
            bridge: None,
            announcer: None,
            devices: HashMap::new(),
        },
        Arc::new(crate::images::Cache::new(root.join("images"))),
        root.join("images"),
        root.join("run"),
        "br0".to_string(),
        None,
        None,
    );

    // Compare a matching VMM identity with an unrelated process using the recorded PID.
    for (name, carries_the_id, expect_alive) in [
        ("a stranger on a reused pid", false, true),
        ("this vm's own vmm", true, false),
    ] {
        let vm = VmId::new_v4();
        let marker = match carries_the_id {
            true => vm.to_string(),
            // A live process with a uuid on it that is not this VM's:
            // the likeliest reuse of all on a node that runs vms.
            false => VmId::new_v4().to_string(),
        };
        let mut child = a_process_carrying(&marker);
        let pid = child.id();

        // The slice the confiner will read, with the pid in it.
        let slice = cgroup_root.join(vm.to_string());
        std::fs::create_dir_all(&slice).expect("a fake slice");
        std::fs::write(slice.join("cgroup.procs"), format!("{pid}\n")).expect("its members");

        let mut record = spec_record();
        record.vmm_pid = Some(pid);
        store.put(&vm, &record).expect("a record");
        provisioner.stop(&vm, record).await.expect("the vm stops");

        // Give a signal that WAS sent the moment it needs to land.
        for _ in 0..100 {
            if !still_alive(&mut child) {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert_eq!(
            still_alive(&mut child),
            expect_alive,
            "{name}: pid {pid} came out of the stop wrong"
        );
        let _ = child.kill();
        let _ = child.wait();
    }
}

/// Desired Absent must remain reported until teardown removes the record;
/// omitting a live source could permit placement of another guest.
#[tokio::test]
async fn a_vm_on_its_way_out_is_still_named_while_its_vmm_runs() {
    let temp = tempfile::tempdir().expect("a temp dir");
    let root = temp.path().to_path_buf();
    let store = Arc::new(crate::store::Store::open(&root.join("a.redb")).expect("a store"));
    let drivers = Drivers {
        confiner: Arc::new(cgroup_driver::CgroupV2::new(root.join("cgroup"))),
        hypervisor: Some(Arc::new(EmptyHypervisor)),
        hypervisor_name: Some("empty".into()),
        storage: HashMap::new(),
        networking: None,
        bridge: None,
        announcer: None,
        devices: HashMap::new(),
    };
    let provisioner = Arc::new(Provisioner::new(
        store.clone(),
        drivers.clone(),
        Arc::new(crate::images::Cache::new(root.join("images"))),
        root.join("images"),
        root.join("run"),
        "br0".to_string(),
        None,
        None,
    ));
    let reconciler = crate::reconcile::Reconciler::new(
        store.clone(),
        drivers,
        provisioner,
        Arc::new(tokio::sync::Mutex::new(())),
    );

    let vm = VmId::new_v4();
    let mut vmm = a_process_carrying(&vm.to_string());
    let disk = VolumeId::new_v4();
    let handle = agent_api::storage::VolumeHandle {
        id: disk,
        backend: format!("/fake/{disk}.raw"),
        size_bytes: 4096,
        params: None,
    };
    let mut record = spec_record();
    // The intent is written and nothing else has happened yet: the VMM is
    // running and the disk is open.
    record.desired = Desired::Absent;
    record.vmm_pid = Some(vmm.id());
    // Referenced storage remains independently owned after VM cleanup.
    record.spec.volumes = vec![crate::types::VolumeWithId {
        id: disk,
        spec: agent_api::storage::VolumeSpec {
            base_image: None,
            size_bytes: 4096,
            driver: Some("filesystem".into()),
            params: None,
        },
        referenced: true,
    }];
    record.volumes = vec![agent_api::storage::Volume::attached(
        handle.clone(),
        agent_api::storage::VolumeAttachment::Path(handle.path()),
    )];
    store.put(&vm, &record).expect("a record");

    let said = reconciler.report().await.expect("a report");
    assert_eq!(said.len(), 1, "the node still has this vm");
    assert_eq!(said[0].id, vm);
    assert_eq!(said[0].phase, crate::reconcile::ReportedPhase::Provisioning);
    assert_eq!(
        said[0].reason,
        Some(crate::reconcile::VmReason::Stopping),
        "and the word says why, because `Provisioning` alone would read as \
         a vm being built"
    );
    assert_eq!(
        said[0].volumes,
        vec![disk],
        "with the disk it has not let go of yet"
    );
    assert!(
        still_alive(&mut vmm),
        "the premise: the vmm is still serving the guest"
    );

    // Deleted VM records no longer appear in node reports.
    store.delete(&vm).expect("the record goes");
    assert!(reconciler.report().await.expect("a report").is_empty());

    let _ = vmm.kill();
    let _ = vmm.wait();
}

/// The default owns_pid requires the VM UUID in the process command line.
#[test]
fn a_recorded_pid_is_this_vms_vmm_only_while_it_carries_the_vms_name() {
    use agent_api::hypervisor::Hypervisor;

    let vm = VmId::new_v4();
    let other = VmId::new_v4();
    let hv = EmptyHypervisor;

    let mut mine = a_process_carrying(&vm.to_string());
    let mut stranger = a_process_carrying("not-a-vm-of-this-node");

    assert!(hv.owns_pid(&vm, mine.id()));
    // A live process carrying another VM's identity must not match.
    assert!(!hv.owns_pid(&other, mine.id()));
    assert!(!hv.owns_pid(&vm, stranger.id()));

    // A pid that cannot exist answers no, so liveness needs no second
    // probe. Not `u32::MAX`: to kill(2) that is -1.
    assert!(!hv.owns_pid(&vm, i32::MAX as u32));

    for child in [&mut mine, &mut stranger] {
        let _ = child.kill();
        let _ = child.wait();
    }
}
