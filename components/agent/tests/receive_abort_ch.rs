// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Ignored integration test for explicit receive failure against Cloud Hypervisor v53.
//! A malformed stream must trigger receiver cleanup while preserving referenced data.
//! It needs no guest image because the receiver has not created a guest.
//!
//! ```text
//! MEISTER_CH=$PWD/bin/cloud-hypervisor \
//!   cargo test -p meister-agent --test receive_abort_ch -- --ignored --nocapture
//! ```
//!
//! The test uses fixed local ports 47311 and 47312; run it without competing listeners.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use meister_agent::drivers::Drivers;
use meister_agent::provision::Provisioner;
use meister_agent::reconcile::{Action, Reconciler, Trigger};
use meister_agent::store::Store;
use meister_agent::types::{AgentVmSpec, BootSourceSpec, Phase, VolumeWithId};

/// Where the v53 binary is. The repo builds one into `bin/`.
fn cloud_hypervisor() -> PathBuf {
    PathBuf::from(std::env::var("MEISTER_CH").expect(
        "MEISTER_CH must name a cloud-hypervisor v53 binary; see the module note at the top",
    ))
}

/// Everything this test writes, under one directory that goes at the end.
fn rig(name: &str) -> tempfile::TempDir {
    tempfile::Builder::new()
        .prefix(&format!("ms-runde4-agent-{name}-"))
        .tempdir()
        .expect("a directory")
}

/// Cgroup test double over ordinary directories. Unlike cgroupfs, these
/// directories contain regular files, so cleanup removes the tree recursively.
struct LooseSlices(cgroup_driver::CgroupV2);

impl agent_api::ResourceConfiner for LooseSlices {
    fn create_slice(
        &self,
        name: &str,
        parent: Option<&agent_api::CgroupHandle>,
        limits: &agent_api::ResourceLimits,
    ) -> agent_api::ConfinerResult<agent_api::CgroupHandle> {
        self.0.create_slice(name, parent, limits)
    }
    fn destroy_slice(&self, cg: &agent_api::CgroupHandle) -> agent_api::ConfinerResult<()> {
        let _ = std::fs::remove_dir_all(&cg.path);
        Ok(())
    }
    fn open_slice(&self, name: &str) -> agent_api::CgroupHandle {
        self.0.open_slice(name)
    }
    fn pids_in_slice(&self, name: &str) -> agent_api::ConfinerResult<Vec<u32>> {
        self.0.pids_in_slice(name)
    }
    fn kill_slice(&self, name: &str) -> agent_api::ConfinerResult<()> {
        self.0.kill_slice(name)
    }
}

fn node(root: &std::path::Path, store: Arc<Store>) -> (Arc<Provisioner>, Reconciler) {
    for dir in ["images", "volumes", "run", "cgroup"] {
        std::fs::create_dir_all(root.join(dir)).expect("a directory");
    }
    let mut storage: std::collections::HashMap<String, Arc<dyn agent_api::storage::VolumeDriver>> =
        std::collections::HashMap::new();
    storage.insert(
        "filesystem".to_string(),
        Arc::new(
            filesystem_driver::FilesystemBlockDriver::new(
                filesystem_driver::FilesystemDriverConfig {
                    image_dir: root.join("images"),
                    volume_dir: root.join("volumes"),
                    qemu_img: "qemu-img".into(),
                    // No base image, so nothing is converted here.
                    convert: agent_api::base_image::Sandbox::default(),
                },
            )
            .expect("a filesystem pool"),
        ),
    );
    let drivers = Drivers {
        confiner: Arc::new(LooseSlices(cgroup_driver::CgroupV2::new(
            root.join("cgroup"),
        ))),
        hypervisor: Some(Arc::new(
            cloud_hypervisor_driver::CloudHypervisorDriver::new(
                cloud_hypervisor(),
                root.join("run"),
                Duration::from_secs(5),
                cloud_hypervisor_driver::DEFAULT_UNPLUG_TIMEOUT,
            )
            .expect("a hypervisor driver"),
        )),
        hypervisor_name: Some("cloud-hypervisor".into()),
        storage,
        networking: None,
        bridge: None,
        announcer: None,
        devices: std::collections::HashMap::new(),
    };
    let provisioner = Arc::new(Provisioner::new(
        store.clone(),
        drivers.clone(),
        Arc::new(meister_agent::images::Cache::new(root.join("images"))),
        root.join("images"),
        root.join("run"),
        "br0".to_string(),
        None,
        None,
    ));
    let ops = Arc::new(tokio::sync::Mutex::new(()));
    let reconciler = Reconciler::new(store, drivers, provisioner.clone(), ops);
    (provisioner, reconciler)
}

/// A vm with one REFERENCED disk, which is the only shape a live migration
/// takes: the file exists before the reception and has to exist after it.
fn arriving_vm(store: &Store, root: &std::path::Path) -> AgentVmSpec {
    let volume = agent_api::storage::VolumeId::new_v4();
    let path = root.join("volumes").join(format!("{volume}.raw"));
    std::fs::write(&path, vec![0u8; 1 << 20]).expect("a disk");
    let spec = agent_api::storage::VolumeSpec {
        base_image: None,
        size_bytes: 1 << 20,
        driver: Some("filesystem".into()),
        params: None,
    };
    store
        .put_volume(
            &volume,
            &meister_agent::types::VolumeRecord {
                spec: spec.clone(),
                handle: Some(agent_api::storage::VolumeHandle {
                    id: volume,
                    backend: path.display().to_string(),
                    size_bytes: 1 << 20,
                    params: None,
                }),
                phase: meister_agent::types::VolumeRecordPhase::Ready,
                reason: None,
                message: None,
                gone_at: None,
            },
        )
        .expect("a volume record");
    AgentVmSpec {
        vcpus: 1,
        memory_mib: 256,
        boot: BootSourceSpec::Firmware {
            firmware: "unused-a-reception-builds-no-guest".into(),
        },
        volumes: vec![VolumeWithId {
            id: volume,
            spec,
            referenced: true,
        }],
        nics: vec![],
        devices: vec![],
        images: Vec::new(),
        cloud_init: None,
    }
}

fn alive(pid: u32) -> bool {
    std::path::Path::new(&format!("/proc/{pid}")).exists()
}

/// A malformed stream must end the receiving VMM and release its attachments
/// without deleting the referenced disk.
#[tokio::test]
#[ignore = "needs a cloud-hypervisor v53 binary in MEISTER_CH; see the module note"]
async fn a_stream_that_breaks_leaves_no_vmm_no_record_and_no_disk_held() {
    let temp = rig("receive-abort");
    let root = temp.path().to_path_buf();
    let store = Arc::new(Store::open(&root.join("agent.redb")).expect("a store"));
    let (dest, reconciler) = node(&root, store.clone());

    let id = agent_api::VmId::new_v4();
    let listen = "tcp:127.0.0.1:47311";
    dest.prepare_migration(id, arriving_vm(&store, &root), listen, true, "attempt-1")
        .await
        .expect("a listening vmm");

    let record = store.get(&id).expect("a lookup").expect("a record");
    let pid = record.vmm_pid.expect("a vmm");
    assert_eq!(record.phase, Phase::Receiving);
    assert!(alive(pid), "cloud-hypervisor is up and listening");
    assert_eq!(record.volumes.len(), 1, "and the disk is attached to it");
    println!("listening: pid {pid} on {listen}, record Receiving");

    // Receivers run at INFO so failed-restore diagnostics identify the component.
    let vmm_log = std::fs::read_to_string(root.join("run").join(format!("{id}.log")))
        .expect("the vmm writes its own log");
    assert!(
        vmm_log.contains("VmReceiveMigration"),
        "the receiving vmm is not explaining itself:\n{vmm_log}"
    );
    println!(
        "the receiving vmm speaks: {}",
        vmm_log.lines().next().unwrap_or("")
    );

    // Send an invalid stream and disconnect to provoke explicit receive-failure evidence.
    {
        use std::io::Write;
        let mut stream =
            std::net::TcpStream::connect("127.0.0.1:47311").expect("the vmm is listening");
        stream.write_all(b"not a migration").expect("wrote");
    }

    // The pass. It may take a moment for v53 to write the line.
    let mut acted = Action::None;
    for _ in 0..100 {
        tokio::time::sleep(Duration::from_millis(100)).await;
        acted = reconciler
            .reconcile(id, Trigger::Periodic)
            .await
            .expect("a pass");
        if acted == Action::Teardown {
            break;
        }
    }
    assert_eq!(acted, Action::Teardown, "the pass gave the reception back");

    // And now the invariants, asked of the machine rather than of the code.
    for _ in 0..50 {
        if !alive(pid) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(!alive(pid), "the vmm process {pid} is still here");
    assert!(
        store.get(&id).expect("a lookup").is_none(),
        "the record is still here"
    );
    assert!(
        std::net::TcpStream::connect("127.0.0.1:47311").is_err(),
        "something is still listening on the migration port"
    );
    // Failed-receive cleanup preserves independently owned volume data.
    let volumes = store.list_volumes().expect("the volume table");
    assert_eq!(volumes.len(), 1);
    assert_eq!(
        volumes[0].1.phase,
        meister_agent::types::VolumeRecordPhase::Ready
    );
    let bytes = volumes[0]
        .1
        .handle
        .as_ref()
        .expect("a handle")
        .backend
        .clone();
    assert!(
        std::path::Path::new(&bytes).exists(),
        "the volume's bytes went with the reception"
    );
    println!("all invariants held: no vmm, no record, no listener, the disk is untouched");

    // Retry reception after cleanup removes the failed attempt.
    dest.prepare_migration(
        id,
        arriving_vm(&store, &root),
        "tcp:127.0.0.1:47312",
        true,
        "attempt-2",
    )
    .await
    .expect("the same vm, the same node, no restart in between");
    let again = store.get(&id).expect("a lookup").expect("a record");
    assert_eq!(again.phase, Phase::Receiving);
    println!("and the same vm can be received again, without a restart");
    let _ = dest.teardown(&id).await;
}
