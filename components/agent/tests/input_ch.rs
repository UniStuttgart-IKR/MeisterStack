// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! A guest that really gets a keyboard, through the agent.
//!
//! `#[ignore]` for the reason `receive_abort_ch.rs` next door carries it:
//! this one needs four things from outside the process, and the workspace's
//! ordinary run has none of them.
//!
//! ```text
//! MEISTER_CH=$PWD/bin/cloud-hypervisor \
//! MEISTER_INPUT_BACKEND=~/git/Leandro/target/release/vhost-user-input \
//! MEISTER_KERNEL=$PWD/images/vmlinux.elf \
//! MEISTER_INITRD=/path/to/ms-input-initrd \
//!   cargo test -p meister-agent --test input_ch -- --ignored --nocapture
//! ```
//!
//! What it is for is the half no stand-in can state. The driver's own tests
//! start a process and check what the driver does with it; they cannot check
//! that the thing the driver hands cloud-hypervisor is a device a GUEST
//! finds. Here a VMM is really spawned with `generic_vhost_user` built from
//! this driver's attachment, a kernel really boots on it, and the two lines
//! `1 30 1` and `0 0 0` written into the pipe this driver made really come
//! out of `/dev/input/event0` inside the guest.
//!
//! The guest is a static init and the modules it needs, in an initramfs; it
//! is NOT part of this repo, for the same reason `tiny-initrd` is not (see
//! `deploy/push.sh`, MEISTER_GUEST_FILES). What this test needs of it is a
//! contract of four lines on the console:
//!
//! * `MS-INPUT bus: <dev> device=0x0012` — one per virtio device on the bus,
//!   `0x12` being virtio-input. This line alone is the proof when a guest has
//!   no `virtio_input` driver at all.
//! * `MS-INPUT input: <dev> name=<name>` — what the input core registered.
//! * `MS-INPUT-READY` — the guest is now reading `/dev/input/event0`. The
//!   host writes the pipe only after this, so an event cannot be pushed at a
//!   device that is not listening yet.
//! * `MS-INPUT-EVENT: type=<t> code=<c> value=<v>` per event read, then
//!   `MS-INPUT-DONE`.
//!
//! The kernel is booted with `console=hvc0`, which is the console
//! cloud-hypervisor writes to a FILE (`drivers/cloud-hypervisor/src/
//! config.rs`) — so the proof is a file this test reads and not a socket it
//! has to be connected to at the right moment.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use meister_agent::drivers::Drivers;
use meister_agent::provision::Provisioner;
use meister_agent::store::Store;
use meister_agent::types::{
    AgentVmSpec, BootSourceSpec, Desired, DeviceWithId, Phase, VolumeWithId,
};

/// The four paths this test cannot invent.
fn from_env(var: &str) -> PathBuf {
    let raw = std::env::var(var)
        .unwrap_or_else(|_| panic!("{var} must be set; see the module note at the top"));
    let path = PathBuf::from(raw);
    assert!(path.exists(), "{var} names {} — not there", path.display());
    path
}

/// Everything this test writes, under one directory that goes at the end.
fn rig(name: &str) -> tempfile::TempDir {
    tempfile::Builder::new()
        .prefix(&format!("ms-input-agent-{name}-"))
        .tempdir()
        .expect("a directory")
}

/// A cgroup driver over an ordinary directory tree, for the reason
/// `receive_abort_ch.rs` gives: `CgroupV2::destroy_slice` is a bare
/// `remove_dir` and cannot take a directory whose files it made itself away,
/// so a teardown would end in a failure that is a test artefact. Everything
/// under test here is on the other side of that line.
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

/// One node with a hypervisor, the default volume backend and the input
/// driver, and nothing else — no network, because a keyboard needs none and
/// every extra driver is another way for the test to fail for a reason that
/// is not the one it is about. The volume backend is not optional: a spec
/// with no block volume is refused before anything is built (`a boot disk is
/// required`), even for a guest that boots entirely out of its initramfs.
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
            // The same place `drivers::build_input` puts it.
            run_dir: root.join("run").join("input"),
            socket_timeout: Duration::from_millis(input_driver::DEFAULT_SOCKET_TIMEOUT_MS),
        })
        .expect("a driver over Leandro's backend"),
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

/// The guest, and one device: `{ driver: "input", profile: "fifo" }` — the
/// spec a `meister vm create --spec` file carries.
fn vm_with_a_keyboard(root: &Path) -> (AgentVmSpec, agent_api::device::DeviceId) {
    // The two guest files are linked into the image directory under fixed
    // names, because a boot source names a file THERE rather than a path
    // (`provision::seed`).
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
            // hvc0, so the guest's words land in a file rather than in a
            // socket nobody is connected to. panic=1 so a guest that cannot
            // boot ends instead of holding the test open.
            cmdline: "console=hvc0 rdinit=/init panic=1".into(),
            initramfs: Some("initrd".into()),
        },
        // A blank disk the guest never touches: it boots out of its
        // initramfs and powers off. It is here because a spec without one is
        // refused, and that refusal is the agent's and not this test's to
        // argue with.
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
                profile: Some("fifo".into()),
                params: None,
            },
        }],
        images: Vec::new(),
        cloud_init: None,
    };
    (spec, device)
}

/// Wait for `marker` to turn up in the guest's console, and hand back
/// everything said so far. The console is a file cloud-hypervisor appends to,
/// so this is a read and not a connection.
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

/// The whole sentence: a VM with `devices: [{driver: "input", profile:
/// "fifo"}]` boots with a virtio-input device on its bus, and a key pressed
/// by writing into the host pipe arrives in the guest.
#[tokio::test]
#[ignore = "needs a real cloud-hypervisor, vhost-user-input, kernel and initramfs; see the module note"]
async fn a_key_written_into_the_pipe_arrives_in_the_guest() {
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

    // What the driver wrote down, and what the VMM was therefore configured
    // with. The numbers are the two that make this a keyboard rather than
    // some other device: 18 is virtio-input and both rings have to be there.
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
        "vmm {vmm}, vhost-user-input {backend} on {}",
        socket.display()
    );

    // The pipe, where `drivers::build_input` puts it.
    let fifo = root
        .join("run")
        .join("input")
        .join(format!("{device_id}.fifo"));
    assert!(
        fifo.exists(),
        "the pipe the driver made is {}",
        fifo.display()
    );

    let console = root.join("run").join(format!("{id}.console"));

    // The bus, which answers whether or not the guest has a driver for it.
    let boot = wait_for(&console, "MS-INPUT input:", 90).await;
    print!("{boot}");
    assert!(
        boot.contains("device=0x0012"),
        "no virtio-input device on the guest's bus:\n{boot}"
    );

    // And the other half, for a guest that DOES have virtio_input. A guest
    // without it says so and the test stops at the bus — which is the proof
    // in that case, and it is reported as that.
    if !boot.contains("MS-INPUT-READY") {
        let done = wait_for(&console, "MS-INPUT-DONE", 60).await;
        println!(
            "the guest has no virtio-input driver; the device on the bus is the proof:\n{done}"
        );
    } else {
        // KEY_A down, SYN, KEY_A up, SYN — the four lines Leandro's usage
        // note gives, which is the smallest thing that is a keypress.
        std::fs::write(&fifo, b"1 30 1\n0 0 0\n1 30 0\n0 0 0\n").expect("the pipe takes a write");
        let done = wait_for(&console, "MS-INPUT-DONE", 60).await;
        print!("{done}");
        assert!(
            done.contains("MS-INPUT-EVENT: type=1 code=30 value=1"),
            "KEY_A never arrived in the guest:\n{done}"
        );
        assert!(
            done.contains("MS-INPUT-EVENT: type=0 code=0 value=0"),
            "the press arrived without its SYN:\n{done}"
        );
    }

    // And the teardown, which is the only thing that ever collects this
    // backend: nothing else would.
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
        !fifo.exists(),
        "the pipe is still here, and a writer on a readerless pipe blocks for ever"
    );
    assert!(
        store.get(&id).expect("a lookup").is_none(),
        "the record is still here"
    );
    println!("torn down: no vmm, no backend, no socket, no pipe, no record");
}
