// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Stufe 3 against a real cloud-hypervisor: the tap arrives as a descriptor,
//! and the VMM that gets it has no rights of its own.
//!
//! `#[ignore]` for the reason `receive_abort_ch.rs` next door carries it:
//! these need a VMM binary, a kernel, an initramfs and a tap that somebody
//! privileged prepared, and the workspace's ordinary run has none of them.
//!
//! ```text
//! # once, as root — the agent's own job on a real node, and the one part of
//! # it these tests do not do themselves:
//! sudo ip tuntap add dev s0tap0 mode tap user $USER
//! sudo ip link set s0tap0 up mtu 1450
//! sudo ip addr add 10.77.0.1/24 dev s0tap0
//!
//! MEISTER_CH=$PWD/bin/cloud-hypervisor \
//! MEISTER_KERNEL=$PWD/images/vmlinux.elf \
//! MEISTER_INITRD=/path/to/ms-net-initrd \
//! MEISTER_TAP=s0tap0 \
//! MEISTER_HOST_IP=10.77.0.1 \
//!   cargo test -p meister-agent --test stufe3_ch -- --ignored --nocapture
//! ```
//!
//! and for the user switch, which needs the right to make one:
//!
//! ```text
//! sudo useradd -r -M -s /usr/sbin/nologin -G kvm meister-vmm
//! sudo -E MEISTER_CH=… MEISTER_KERNEL=… MEISTER_INITRD=… MEISTER_TAP=… \
//!         MEISTER_HOST_IP=… MEISTER_VMM_USER=meister-vmm \
//!   cargo test -p meister-agent --test stufe3_ch -- --ignored --nocapture
//! ```
//!
//! # What the guest has to say
//!
//! The initramfs is not part of this repo, for the reason `tiny-initrd` is
//! not (`deploy/push.sh`, `MEISTER_GUEST_FILES`). What these tests need of it
//! is a contract of four lines on the serial console:
//!
//! * `MS-S0-NICS: <names>` — what `/sys/class/net` holds. This alone is the
//!   proof when a guest has no NIC: the line is there and `eth0` is not.
//! * `MS-S0-MAC: <addr>` and `MS-S0-MTU: <n>` — read off the interface. The
//!   MTU is the interesting one: the agent set it on the TAP and the
//!   `vm.add-net` body never mentioned it, so a correct number here is the
//!   whole argument for leaving the field out (see `config::net_config`).
//! * `MS-S0-PING-OK` or `MS-S0-PING-FAIL` — an ICMP echo to `MEISTER_HOST_IP`.
//!   Frames really crossing the tap, in both directions.
//!
//! The kernel is booted with `console=ttyS0`, which is the UART — emulated
//! by the VMM itself and needing no driver in the guest, so a guest whose
//! virtio-console is a module still speaks. The driver gives that line a
//! socket (see `config.rs` on why a device has one mode), so these tests do
//! what the agent does with it: connect and write the transcript down.

use std::path::{Path, PathBuf};
use std::time::Duration;

use agent_api::{BootSource, Hypervisor, InstanceSpec, NicAttachment, VmId};
use cloud_hypervisor_driver::CloudHypervisorDriver;

/// A path this test cannot invent.
fn from_env(var: &str) -> PathBuf {
    let raw = std::env::var(var)
        .unwrap_or_else(|_| panic!("{var} must be set; see the module note at the top"));
    let path = PathBuf::from(raw);
    assert!(path.exists(), "{var} names {} — not there", path.display());
    path
}

fn tap() -> String {
    std::env::var("MEISTER_TAP").expect("MEISTER_TAP must name a prepared, UP tap this user owns")
}

fn host_ip() -> String {
    std::env::var("MEISTER_HOST_IP").unwrap_or_else(|_| "10.77.0.1".to_string())
}

/// Everything this test writes, under one directory that goes at the end.
///
/// Short on purpose: the VMM's API socket lives in here and an `AF_UNIX` path
/// is 108 bytes, which a `tempfile` prefix under a deep target directory can
/// exhaust on its own. That cost a run.
fn rig(name: &str) -> tempfile::TempDir {
    tempfile::Builder::new()
        .prefix(&format!("ms3-{name}-"))
        .tempdir()
        .expect("a directory")
}

/// A VM with one NIC on the prepared tap, booted from a kernel and an
/// initramfs, whose serial line is a file in `dir`.
fn spec(mtu: Option<u32>) -> InstanceSpec {
    InstanceSpec {
        boot: BootSource::DirectKernel {
            kernel: from_env("MEISTER_KERNEL"),
            // `ms.linger` keeps the guest alive after it has reported, which
            // is what makes a hot-plug observable from here.
            cmdline: "console=ttyS0 rdinit=/init ms.linger=25".into(),
            initramfs: Some(from_env("MEISTER_INITRD")),
        },
        volumes: vec![],
        vcpus: 2,
        memory_mib: 512,
        nics: vec![NicAttachment {
            tap_name: tap(),
            mac: "02:00:00:aa:bb:01".parse().unwrap(),
            mtu,
        }],
        devices: vec![],
        cloud_init_seed: None,
    }
}

/// Copy the guest's serial line off the VMM's socket into a file.
///
/// Exactly what the agent itself does with that socket, and for the same
/// reason: cloud-hypervisor's serial device has one mode, it is a socket
/// because a socket is the only form somebody can type into, and the side
/// that wants a transcript writes one. v53 holds a 1 MiB ring while nobody
/// is connected and replays it on connect, so nothing said before this task
/// gets there is lost.
fn tail_serial(socket: PathBuf, into: PathBuf) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        use tokio::io::AsyncReadExt;
        use tokio::io::AsyncWriteExt;
        let mut stream = loop {
            match tokio::net::UnixStream::connect(&socket).await {
                Ok(s) => break s,
                Err(_) => tokio::time::sleep(Duration::from_millis(50)).await,
            }
        };
        let mut file = tokio::fs::File::create(&into).await.expect("a transcript");
        let mut buf = [0u8; 4096];
        while let Ok(read) = stream.read(&mut buf).await {
            if read == 0 {
                break;
            }
            let _ = file.write_all(&buf[..read]).await;
            let _ = file.flush().await;
        }
    })
}

/// The transcript, the socket it comes off, and the task that moves it.
async fn serial_transcript(
    ch: &CloudHypervisorDriver,
    id: &VmId,
    dir: &Path,
) -> (PathBuf, tokio::task::JoinHandle<()>) {
    let socket = ch
        .console_socket(id)
        .expect("this driver serves a serial socket");
    let file = dir.join("serial.log");
    let handle = tail_serial(socket, file.clone());
    (file, handle)
}

/// What the guest said, once it has said the line this is waiting for.
async fn guest_said(console: &Path, until: &str, timeout: Duration) -> String {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let text = std::fs::read_to_string(console).unwrap_or_default();
        if text.contains(until) {
            return text;
        }
        if tokio::time::Instant::now() >= deadline {
            let lines: Vec<&str> = text.lines().filter(|l| l.contains("MS-S0")).collect();
            panic!("the guest never said {until:?}; it said: {lines:#?}");
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

/// The guest's `MS-S0-` lines, which is the only part of its console this
/// asserts on.
fn ours(text: &str) -> Vec<String> {
    text.lines()
        .filter(|l| l.contains("MS-S0"))
        .map(|l| l.trim().to_string())
        .collect()
}

/// The user the VMM and its backends should run as, when the run was given
/// one. `None` means "as whoever is running this test", which is what a
/// machine with no `meister-vmm` and no way to make one gets.
fn vmm_user() -> Option<agent_api::VmmUser> {
    let name = std::env::var("MEISTER_VMM_USER").unwrap_or_default();
    if name.is_empty() {
        return None;
    }
    Some(agent_api::VmmUser::resolve(&name).expect("MEISTER_VMM_USER must name a real user"))
}

fn driver(dir: &Path) -> CloudHypervisorDriver {
    let user = vmm_user();
    CloudHypervisorDriver::new(
        from_env("MEISTER_CH"),
        dir.join("vms"),
        Duration::from_secs(10),
        Duration::from_secs(30),
    )
    .expect("the driver builds")
    .with_tap_fds(true)
    .with_vmm_user(user)
    // The rig's own directory stands in for the node's image and volume
    // directories: the kernel and initramfs come from outside it, and CH
    // covers those itself because they are in the create document.
    .with_landlock_paths(vec![dir.to_path_buf()])
}

/// S1: the tap crosses as a descriptor and the guest gets a working NIC.
///
/// This is the whole of Stufe 3's network half in one test, and every line of
/// it was a separate failure first:
///
/// * `vm.create` carries no `net` — v53 nulls every fd in it and says so in
///   its own source twice.
/// * `vm.add-net` carries the open tap as `SCM_RIGHTS` and `num_queues: 2` —
///   one descriptor, two queues, or the call is refused by name.
/// * the body carries no `mtu` — `set_mtu` is `SIOCSIFMTU` and this VMM is
///   not allowed to; the guest is told 1450 anyway, off the tap.
/// * the VMM opens `/dev/net/tun` never. It could not: the test runs as an
///   ordinary user with no capabilities at all.
#[tokio::test]
#[ignore = "needs a real cloud-hypervisor, kernel, initramfs and a prepared tap; see the module note"]
async fn a_guest_gets_its_nic_as_a_file_descriptor_and_reaches_the_host() {
    let dir = rig("fdnet");
    let ch = driver(dir.path());
    let id = VmId::new_v4();
    let spec = spec(Some(1450));

    ch.create(&id, &spec, None)
        .await
        .expect("vm.create + add-net");
    let (console, tail) = serial_transcript(&ch, &id, dir.path()).await;
    ch.start(&id).await.expect("vm.boot");

    let said = guest_said(&console, "MS-S0-DONE", Duration::from_secs(60)).await;
    let lines = ours(&said);
    println!("guest: {lines:#?}");

    assert!(
        lines
            .iter()
            .any(|l| l.contains("MS-S0-NICS") && l.contains("eth0")),
        "the guest has no eth0: {lines:#?}"
    );
    assert!(
        lines
            .iter()
            .any(|l| l.contains("MS-S0-MAC: 02:00:00:aa:bb:01")),
        "the mac in the add-net body did not reach the guest: {lines:#?}"
    );
    // The MTU the agent set on the tap, which the body never named. If this
    // is 1500 the guest fell back to the Ethernet default and an overlay VM
    // would be silently dropping frames.
    assert!(
        lines.iter().any(|l| l.contains("MS-S0-MTU: 1450")),
        "the guest did not learn the tap's mtu: {lines:#?}"
    );
    assert!(
        lines.iter().any(|l| l == "MS-S0-PING-OK"),
        "the guest could not reach {}: {lines:#?}",
        host_ip()
    );

    ch.destroy(&id).await.expect("teardown");
    tail.abort();
    assert!(
        !ch.probe(&id).await,
        "the vmm is still answering after destroy"
    );
}

/// S1, the other half: a NIC plugged into a guest that is already running
/// goes the same way.
///
/// The same call, and that is the point — v53 routes `vm.add-net` by whether
/// it owns a VM yet, so the driver has one path for both and nothing here is
/// a second mechanism. What this adds over the test above is the answer:
/// a running VMM replies with the PCI address it put the device at, and the
/// guest sees a second interface.
#[tokio::test]
#[ignore = "needs a real cloud-hypervisor, kernel, initramfs and a prepared tap; see the module note"]
async fn a_nic_plugged_into_a_running_guest_goes_the_same_way() {
    let second = std::env::var("MEISTER_TAP2").unwrap_or_default();
    if second.is_empty() {
        eprintln!("MEISTER_TAP2 names no second prepared tap; nothing to hot-plug");
        return;
    }
    let dir = rig("hotplug");
    let ch = driver(dir.path());
    let id = VmId::new_v4();

    ch.create(&id, &spec(Some(1450)), None)
        .await
        .expect("vm.create + add-net");
    let (console, tail) = serial_transcript(&ch, &id, dir.path()).await;
    ch.start(&id).await.expect("vm.boot");
    guest_said(&console, "MS-S0-DONE", Duration::from_secs(60)).await;

    let nic = NicAttachment {
        tap_name: second,
        mac: "02:00:00:aa:bb:02".parse().unwrap(),
        mtu: Some(1500),
    };
    ch.as_hotpluggable()
        .expect("this driver hot-plugs")
        .add_nic(&id, &nic)
        .await
        .expect("vm.add-net on a booted vm");

    let said = guest_said(&console, "MS-S0-HOTPLUG-NICS", Duration::from_secs(30)).await;
    let lines = ours(&said);
    println!("guest: {lines:#?}");
    assert!(
        lines
            .iter()
            .any(|l| l.contains("MS-S0-HOTPLUG-NICS") && l.contains("eth1")),
        "the guest never saw a second interface: {lines:#?}"
    );

    ch.destroy(&id).await.expect("teardown");
    tail.abort();
}

/// S3: the sandbox is on, and it bites the one thing it is documented to
/// bite.
///
/// Landlock is applied at `vm_create`, so the ruleset is closed before the
/// guest exists and cannot be widened afterwards — "the process cannot access
/// any resources outside of the ruleset during its lifetime, even if it were
/// compromised", which is the point and also the cost. CH's own note is
/// explicit: "Hotplugging any new file-backed resources to above guest will
/// result in Permission Denied error."
///
/// So this asserts both halves. A disk hot-plugged out of a directory the
/// rules name goes in; one out of a directory nothing names is refused, by
/// the kernel, not by this stack. A test that only showed the refusal would
/// pass just as well against a ruleset that denied everything.
#[tokio::test]
#[ignore = "needs a real cloud-hypervisor, kernel, initramfs and a prepared tap; see the module note"]
async fn landlock_lets_a_hotplug_from_a_named_directory_in_and_keeps_the_rest_out() {
    let dir = rig("landlock");
    let ch = driver(dir.path());
    let id = VmId::new_v4();

    // Inside the rules: the rig is a `landlock_paths` entry.
    let allowed = dir.path().join("extra.raw");
    std::fs::write(&allowed, vec![0u8; 8 * 1024 * 1024]).expect("a disk");
    // Outside: a second directory nothing has a rule for.
    let elsewhere = rig("elsewhere");
    let denied = elsewhere.path().join("extra.raw");
    std::fs::write(&denied, vec![0u8; 8 * 1024 * 1024]).expect("a disk");
    if let Some(user) = vmm_user() {
        // Ownership is NOT what this test is about, so both files are handed
        // over up front: a refusal that turned out to be `EACCES` from the
        // mode would prove nothing about Landlock.
        user.take(&allowed).expect("chown");
        user.take(&denied).expect("chown");
    }

    ch.create(&id, &spec(Some(1450)), None)
        .await
        .expect("vm.create + add-net");
    let (console, tail) = serial_transcript(&ch, &id, dir.path()).await;
    ch.start(&id).await.expect("vm.boot");
    guest_said(&console, "MS-S0-DONE", Duration::from_secs(60)).await;

    let hot = ch.as_hotpluggable().expect("this driver hot-plugs");
    let volume = |path: &Path| agent_api::AttachedVolume {
        id: uuid_from(path),
        attachment: agent_api::VolumeAttachment::Path(path.to_path_buf()),
    };

    hot.add_disk(&id, &volume(&allowed))
        .await
        .expect("a disk from a directory the ruleset names");

    let refused = hot
        .add_disk(&id, &volume(&denied))
        .await
        .expect_err("a disk from outside the ruleset must be refused");
    let said = format!("{refused:#}");
    println!("refused: {said}");
    assert!(
        said.to_lowercase().contains("permission denied") || said.contains("EACCES"),
        "the refusal should be the kernel's and name it: {said}"
    );

    ch.destroy(&id).await.expect("teardown");
    tail.abort();
}

/// A volume id derived from a path, so the two `add_disk` calls above get
/// different disk names without a fixture holding them.
fn uuid_from(path: &Path) -> uuid::Uuid {
    let mut bytes = [0u8; 16];
    for (i, b) in path.to_string_lossy().bytes().enumerate() {
        bytes[i % 16] ^= b;
    }
    uuid::Uuid::from_bytes(bytes)
}
