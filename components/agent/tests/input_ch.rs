// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Agent integration with upstream virtio-input. Requires MEISTER_CH,
//! MEISTER_INPUT_BACKEND, MEISTER_KERNEL, MEISTER_INITRD, MEISTER_INPUT_DEVICE
//! and MEISTER_INPUT_FIXTURE_PID (Leandro-Test's input_device.py, emitting F24).
//! The initramfs must print MS-INPUT-READY, MS-INPUT-EVENT and MS-INPUT-DONE.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use meister_agent::drivers::Drivers;
use meister_agent::provision::Provisioner;
use meister_agent::store::Store;
use meister_agent::types::{
    AgentVmSpec, BootSourceSpec, Desired, DeviceWithId, Phase, VolumeWithId,
};

fn from_env(var: &str) -> PathBuf {
    let raw = std::env::var(var)
        .unwrap_or_else(|_| panic!("{var} must be set; see the module note at the top"));
    let path = PathBuf::from(raw);
    assert!(path.exists(), "{var} names {} — not there", path.display());
    path
}

fn rig(name: &str) -> tempfile::TempDir {
    tempfile::Builder::new()
        .prefix(&format!("ms-input-agent-{name}-"))
        .tempdir()
        .expect("a directory")
}

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

fn node(
    root: &Path,
    store: Arc<Store>,
) -> (Arc<Provisioner>, Arc<dyn agent_api::device::DeviceDriver>) {
    for dir in ["images", "volumes", "run", "cgroup"] {
        std::fs::create_dir_all(root.join(dir)).expect("a directory");
    }
    let input: Arc<dyn agent_api::device::DeviceDriver> = Arc::new(
        input_driver::InputDriver::new(input_driver::InputDriverConfig {
            binary: from_env("MEISTER_INPUT_BACKEND"),
            run_dir: root.join("run").join("input"),
            socket_timeout: Duration::from_millis(input_driver::DEFAULT_SOCKET_TIMEOUT_MS),
            vmm_user: None,
        })
        .expect("a driver over the upstream backend"),
    );
    let mut devices: std::collections::HashMap<String, Arc<dyn agent_api::device::DeviceDriver>> =
        std::collections::HashMap::new();
    devices.insert("input".to_string(), input.clone());

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
                from_env("MEISTER_CH"),
                root.join("run"),
                Duration::from_secs(10),
                cloud_hypervisor_driver::DEFAULT_UNPLUG_TIMEOUT,
            )
            .expect("a hypervisor driver"),
        )),
        hypervisor_name: Some("cloud-hypervisor".into()),
        storage,
        networking: None,
        bridge: None,
        announcer: None,
        devices,
    };
    let provisioner = Arc::new(Provisioner::new(
        store,
        drivers,
        Arc::new(meister_agent::images::Cache::new(root.join("images"))),
        root.join("images"),
        root.join("run"),
        "br0".to_string(),
        None,
        None,
    ));
    (provisioner, input)
}

fn vm_with_a_keyboard(root: &Path) -> (AgentVmSpec, agent_api::device::DeviceId) {
    std::fs::hard_link(
        from_env("MEISTER_KERNEL"),
        root.join("images").join("kernel"),
    )
    .or_else(|_| {
        std::fs::copy(
            from_env("MEISTER_KERNEL"),
            root.join("images").join("kernel"),
        )
        .map(|_| ())
    })
    .expect("the kernel is readable");
    std::fs::hard_link(
        from_env("MEISTER_INITRD"),
        root.join("images").join("initrd"),
    )
    .or_else(|_| {
        std::fs::copy(
            from_env("MEISTER_INITRD"),
            root.join("images").join("initrd"),
        )
        .map(|_| ())
    })
    .expect("the initramfs is readable");

    let device = agent_api::device::DeviceId::new_v4();
    let spec = AgentVmSpec {
        vcpus: 1,
        memory_mib: 512,
        boot: BootSourceSpec::DirectKernel {
            kernel: "kernel".into(),
            cmdline: "console=hvc0 rdinit=/init panic=1".into(),
            initramfs: Some("initrd".into()),
        },
        volumes: vec![VolumeWithId {
            id: agent_api::storage::VolumeId::new_v4(),
            spec: agent_api::storage::VolumeSpec {
                base_image: None,
                size_bytes: 1 << 20,
                driver: Some("filesystem".into()),
                params: None,
            },
            referenced: false,
        }],
        nics: vec![],
        devices: vec![DeviceWithId {
            id: device,
            spec: agent_api::device::DeviceSpec {
                driver: "input".into(),
                partition: agent_api::device::PartitionSpec::Mediated,
                profile: Some("evdev".into()),
                params: Some(serde_json::json!({"evdev": from_env("MEISTER_INPUT_DEVICE")})),
            },
        }],
        images: Vec::new(),
        cloud_init: None,
    };
    (spec, device)
}

async fn wait_for(console: &Path, marker: &str, seconds: u64) -> String {
    let mut last = String::new();
    for _ in 0..(seconds * 10) {
        last = std::fs::read_to_string(console).unwrap_or_default();
        if last.contains(marker) {
            return last;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("the guest never said {marker:?}; its console so far:\n{last}");
}

fn alive(pid: u32) -> bool {
    Path::new(&format!("/proc/{pid}")).exists()
}

#[tokio::test]
#[ignore = "needs a real cloud-hypervisor, vhost-device-input, kernel and initramfs; see the module note"]
async fn an_evdev_key_arrives_in_the_guest() {
    let temp = rig("keyboard");
    let root = temp.path().to_path_buf();
    let store = Arc::new(Store::open(&root.join("agent.redb")).expect("a store"));
    let (node, driver) = node(&root, store.clone());
    let (spec, device_id) = vm_with_a_keyboard(&root);

    let id = agent_api::VmId::new_v4();
    node.provision(id, spec, Desired::Running, false)
        .await
        .expect("the vm boots");

    let record = store.get(&id).expect("a lookup").expect("a record");
    assert_eq!(record.phase, Phase::Provisioned);
    let vmm = record.vmm_pid.expect("a vmm");
    assert!(alive(vmm), "cloud-hypervisor is up");

    assert_eq!(record.devices.len(), 1);
    let agent_api::device::DeviceAttachment::VhostUser {
        socket,
        pid: backend,
        device_type,
        queue_sizes,
    } = record.devices[0].attachment.clone()
    else {
        panic!("a vhost-user attachment");
    };
    assert_eq!(device_type, 18);
    assert_eq!(queue_sizes, vec![256, 256]);
    assert!(alive(backend), "the input backend is up");
    driver
        .get(&device_id, &record.devices[0].attachment)
        .await
        .expect("and the driver recognises its own backend");
    println!(
        "vmm {vmm}, vhost-device-input {backend} on {}",
        socket.display()
    );

    let console = root.join("run").join(format!("{id}.console"));

    let boot = wait_for(&console, "MS-INPUT input:", 90).await;
    print!("{boot}");
    assert!(
        boot.contains("device=0x0012"),
        "no virtio-input device on the guest's bus:\n{boot}"
    );

    wait_for(&console, "MS-INPUT-READY", 60).await;
    let fixture_pid: u32 = std::env::var("MEISTER_INPUT_FIXTURE_PID")
        .unwrap()
        .parse()
        .unwrap();
    assert!(
        tokio::process::Command::new("kill")
            .args(["-USR1", &fixture_pid.to_string()])
            .status()
            .await
            .unwrap()
            .success()
    );
    let done = wait_for(&console, "MS-INPUT-DONE", 60).await;
    assert!(
        done.contains("MS-INPUT-EVENT: type=1 code=194 value=1"),
        "F24 missing: {done}"
    );
    assert!(
        done.contains("MS-INPUT-EVENT: type=0 code=0 value=0"),
        "SYN missing: {done}"
    );

    node.teardown(&id).await.expect("teardown");
    for _ in 0..200 {
        if !alive(backend) && !alive(vmm) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert!(!alive(vmm), "the vmm {vmm} is still here");
    assert!(!alive(backend), "the input backend {backend} is still here");
    assert!(!socket.exists(), "the socket is still here");
    assert!(
        store.get(&id).expect("a lookup").is_none(),
        "the record is still here"
    );
    println!("torn down: no vmm, no backend, no socket, no record");
}
