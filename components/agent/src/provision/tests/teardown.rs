// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! The teardown: which disks are this VM's to unmake, which driver
//! unmakes them, and whose process a kill is allowed to signal.

use super::*;

/// The teardown fork, as a value: a referenced entry is detached and its
/// data stays, an inline one is deprovisioned with the VM. Read off the
/// VM's own spec, because the difference between the two is somebody's
/// data and the answer must not depend on a second table.
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
        unhealthy: None,
        managed_by_controller: true,
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

/// Which DRIVER tears a referenced volume down — the other half of the
/// same fork, and the one that was wrong.
///
/// A referenced entry carries no driver: the VM's spec says
/// `{"volume": "<uid>"}` and nothing else, because the disk is not this
/// VM's to describe. The teardown read that entry anyway and fell through
/// to `filesystem`, whose `detach` does nothing — so nothing noticed
/// while every backend's detach was a no-op for a plain path.
///
/// The first driver whose detach MATTERS found it: an NVMe-oF session
/// stayed connected on the node after its VM was gone. An nfs virtiofsd
/// would have too.
#[test]
fn a_referenced_volume_is_torn_down_by_the_driver_that_made_it() {
    let referenced = VolumeId::new_v4();
    let inline = VolumeId::new_v4();
    let entry = |id, referenced| crate::types::VolumeWithId {
        id,
        spec: agent_api::storage::VolumeSpec {
            base_image: None,
            size_bytes: 0,
            // Neither entry names one, which is the whole point: an
            // inline entry may, a referenced one never does.
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
        unhealthy: None,
        managed_by_controller: true,
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
    // And a referenced volume this node has no row for falls back rather
    // than failing: a teardown must finish even when the table has lost
    // its row, and the worst that then happens is a no-op detach.
    assert_eq!(
        volume_driver_name(&store, &record, &VolumeId::new_v4()),
        default_volume_driver()
    );
}

/// A live process whose command line carries `marker` — a stand-in for a
/// VMM started with a socket named after its VM.
///
/// A LOOP and not a `sleep`, and the difference is the whole reason this
/// helper has a comment: `sh -c 'sleep 30 …'` is a single command, and
/// every shell worth the name execs it in place rather than forking —
/// which replaces the command line with `sleep 30` and takes the marker
/// with it. A loop cannot be exec'd away, so the `sh` stays and so does
/// its argv. The marker rides as `$0`, which is argv[3] and is never
/// rewritten.
///
/// It does not return until `/proc` agrees, so nothing downstream races
/// the exec.
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

/// A recorded pid that now belongs to somebody else is not signalled.
///
/// The cgroup slice is REAL here — the file the confiner reads is written
/// with the foreign process's pid in it — because the slice was the whole
/// of the old guard and the point is that it is not enough. A slice
/// outlives the crash that failed to remove it, a pid outlives the
/// process it named, and between the record and a SIGKILL there was
/// nothing else. Without the identity check this test kills a process
/// that has nothing to do with MeisterStack.
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

    // The two cases, run through the same path: a process this VM's
    // record could plausibly name, and a process that merely holds the
    // number now.
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

/// The default `Hypervisor::owns_pid` reads the VM's uuid off the
/// process's command line, which is the contract every driver in this
/// tree meets: one process per VM, given a socket named after that VM.
#[test]
fn a_recorded_pid_is_this_vms_vmm_only_while_it_carries_the_vms_name() {
    use agent_api::hypervisor::Hypervisor;

    let vm = VmId::new_v4();
    let other = VmId::new_v4();
    let hv = EmptyHypervisor;

    let mut mine = a_process_carrying(&vm.to_string());
    let mut stranger = a_process_carrying("not-a-vm-of-this-node");

    assert!(hv.owns_pid(&vm, mine.id()));
    // The same live process, asked about a DIFFERENT vm: a record whose
    // pid was recycled by another VM's vmm is the likeliest reuse of all
    // on a node that runs vms for a living.
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
