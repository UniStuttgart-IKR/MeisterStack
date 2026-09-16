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
/// What `ps` says about a pid, in one field.
fn ps(pid: u32, field: &str) -> String {
    let out = std::process::Command::new("ps")
        .args(["-o", field, "-p", &pid.to_string(), "--no-headers"])
        .output()
        .expect("ps");
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

/// Whether this process holds an open descriptor on `target`.
///
/// The proof that a tap arrived as a descriptor rather than by name: the
/// entry is in the VMM's fd table and the VMM is a process that could not
/// have opened it — unprivileged, and Landlocked without a rule for
/// `/dev/net/tun`.
fn holds(pid: u32, target: &str) -> bool {
    let Ok(entries) = std::fs::read_dir(format!("/proc/{pid}/fd")) else {
        return false;
    };
    entries.flatten().any(|e| {
        std::fs::read_link(e.path())
            .map(|link| link.to_string_lossy() == target)
            .unwrap_or(false)
    })
}

/// S4: the whole of Stufe 3 on one machine, in one test.
///
/// Every assertion here is a sentence from the brief, and together they are
/// the claim: a guest running on this node is one process away from nothing,
/// not one process away from root.
///
/// * `ps -o user` says the VMM is `MEISTER_VMM_USER` — or says it is the
///   user running the test, when the run was given no switch to make, and
///   then this test states that rather than pretending.
/// * the VMM holds a `/dev/net/tun` descriptor it could not have opened.
/// * `CapEff` is empty: not "fewer capabilities", none.
/// * the guest boots and reaches the host.
/// * the teardown leaves no process and no file.
/// * and the agent's own socket is closed to the VMM user, shown by trying
///   it from a process that IS that user.
#[tokio::test]
#[ignore = "needs a real cloud-hypervisor, kernel, initramfs, a prepared tap and (for the switch) root; see the module note"]
async fn the_vmm_runs_as_somebody_else_and_cannot_reach_the_agent() {
    let dir = rig("proof");
    let user = vmm_user();
    let ch = driver(dir.path());
    let id = VmId::new_v4();

    ch.create(&id, &spec(Some(1450)), None)
        .await
        .expect("vm.create + add-net");
    let (console, tail) = serial_transcript(&ch, &id, dir.path()).await;
    ch.start(&id).await.expect("vm.boot");
    let said = guest_said(&console, "MS-S0-DONE", Duration::from_secs(60)).await;
    let lines = ours(&said);
    println!("guest: {lines:#?}");

    let pid = vmm_pid(dir.path(), &id);
    let who = ps(pid, "user");
    let expected = match &user {
        Some(user) => user.name.clone(),
        None => whoami(),
    };
    println!("vmm pid {pid} runs as {who:?} (expected {expected:?})");
    assert!(
        who == expected || expected.starts_with(&who),
        "the vmm runs as {who:?} and not as {expected:?}"
    );
    if user.is_none() {
        println!(
            "NOTE: MEISTER_VMM_USER was not set, so no user change was attempted. \
             Everything below still holds; the switch itself is unproved in this run."
        );
    }

    // The tap. It is in the VMM's fd table, and the VMM is Landlocked with
    // no rule for /dev/net/tun and (with a switch) has no capability at all
    // — so it did not open this itself.
    assert!(
        holds(pid, "/dev/net/tun"),
        "the vmm holds no tap descriptor, so the tap did not arrive as one"
    );
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).expect("status");
    let field = |name: &str| {
        status
            .lines()
            .find(|l| l.starts_with(name))
            .unwrap_or_default()
            .to_string()
    };
    let cap_eff = field("CapEff:");
    let groups = field("Groups:");
    println!("vmm {cap_eff} | {groups}");
    if user.is_some() {
        assert!(
            cap_eff.ends_with("0000000000000000"),
            "a vmm that changed user should hold no capabilities: {cap_eff}"
        );
        // The supplementary groups, and this is not a detail. `setgid` alone
        // would leave the agent's inherited list in place — including group
        // 0 for a root agent — and a VMM carrying group 0 reaches every
        // `0660 root:root` file on the node, the agent's own socket first
        // among them. `Command::uid` drops the list; this is where that is
        // checked rather than assumed.
        assert_eq!(
            groups.trim(),
            "Groups:",
            "the vmm inherited supplementary groups from the agent: {groups}"
        );
    }

    assert!(
        lines.iter().any(|l| l == "MS-S0-PING-OK"),
        "the guest could not reach {}: {lines:#?}",
        host_ip()
    );

    // The three files the VMM made for itself. Owned by it, and closed to
    // the world: the api socket is a control channel — CH's own threat model
    // calls its API "trusted" and says Landlock does not protect it, "it does
    // not prevent access to AF_UNIX sockets" — so the permissions on it are
    // this stack's job and not the VMM's. The console is what the guest
    // printed.
    if let Some(user) = &user {
        use std::os::unix::fs::MetadataExt;
        use std::os::unix::fs::PermissionsExt;
        for path in [
            dir.path().join("vms").join(format!("{id}.sock")),
            ch.console_socket(&id).expect("a serial socket"),
            dir.path().join("vms").join(format!("{id}.console")),
        ] {
            let meta = std::fs::metadata(&path).expect("the vmm made this");
            let mode = meta.permissions().mode() & 0o777;
            println!(
                "{} is {mode:o} uid={} gid={}",
                path.display(),
                meta.uid(),
                meta.gid()
            );
            // Nothing for the world, and the group put back: CH's own
            // `umask(0o077)` leaves these `0700`/`0600`, which an agent that
            // is not root could not read. See `relax_to_the_group`.
            assert_eq!(mode & 0o007, 0, "{} is open to the world", path.display());
            assert_eq!(
                mode & 0o060,
                0o060,
                "{} is closed to its group",
                path.display()
            );
            assert_eq!(meta.uid(), user.uid, "{}", path.display());
            assert_eq!(meta.gid(), user.gid, "{}", path.display());
        }
    }

    // The agent's socket, in the shape `api.rs` gives it: 0660, owned by
    // whoever runs the agent. Tried from a process that IS the VMM user.
    if let Some(user) = &user {
        let sock = dir.path().join("agent.sock");
        let _listener = std::os::unix::net::UnixListener::bind(&sock).expect("a socket");
        std::fs::set_permissions(&sock, {
            use std::os::unix::fs::PermissionsExt;
            std::fs::Permissions::from_mode(0o660)
        })
        .expect("0660");
        let errno = connect_as(user, &sock);
        println!("connecting to the agent socket as {user}: errno {errno}");
        assert_ne!(
            errno, COULD_NOT_SWITCH,
            "the probe could not become {user}, so it proves nothing"
        );
        assert_eq!(
            errno,
            nix::libc::EACCES,
            "the vmm user could open the agent's socket, which is the whole \
             thing Stufe 3 is for"
        );
    }

    ch.destroy(&id).await.expect("teardown");
    tail.abort();
    assert!(!ch.probe(&id).await, "the vmm still answers");
    assert!(
        !std::path::Path::new(&format!("/proc/{pid}")).exists(),
        "the vmm process is still there"
    );
    // Nothing of this VM is left in the run directory but the log the driver
    // keeps on purpose.
    let left: Vec<String> = std::fs::read_dir(dir.path().join("vms"))
        .expect("the run dir")
        .flatten()
        .map(|e| e.file_name().to_string_lossy().to_string())
        .filter(|n| n.starts_with(&id.to_string()))
        .collect();
    assert!(
        left.iter().all(|n| n.contains(".log.gone-")),
        "the teardown left {left:?}"
    );
}

fn whoami() -> String {
    let uid = nix::unistd::Uid::effective();
    nix::unistd::User::from_uid(uid)
        .ok()
        .flatten()
        .map(|u| u.name)
        .unwrap_or_else(|| uid.to_string())
}

/// The VMM's pid, off the one place this test can read it without the
/// driver's private map: `fuser`-style, by who holds the api socket.
///
/// The driver knows, but does not publish it — and it should not: a pid is
/// not an identity, and the driver says so at length. For a test on one
/// machine the process holding the socket IS the VMM.
fn vmm_pid(dir: &Path, id: &VmId) -> u32 {
    let socket = dir.join("vms").join(format!("{id}.sock"));
    let target = socket.to_string_lossy().to_string();
    for entry in std::fs::read_dir("/proc").expect("/proc").flatten() {
        let Ok(pid) = entry.file_name().to_string_lossy().parse::<u32>() else {
            continue;
        };
        let Ok(cmdline) = std::fs::read(format!("/proc/{pid}/cmdline")) else {
            continue;
        };
        if cmdline
            .windows(target.len())
            .any(|w| w == target.as_bytes())
        {
            return pid;
        }
    }
    panic!("no process names {target}");
}

/// A `connect_as` child that could not become the user it was asked to.
/// Its own code, so that a failed switch can never be read as a successful
/// connect — which it was, for one run, and the test passed nothing.
const COULD_NOT_SWITCH: i32 = 111;

/// Try to connect to `socket` as `user`, and answer with the errno.
///
/// A forked child rather than a spawned helper, because the question is
/// about a uid and not about a program: no interpreter has to be on this
/// machine for the answer to be true. The child does the two things the
/// kernel cares about — group before user, which is the order that cannot be
/// undone — and exits with the errno as its status.
///
/// The credential change goes through the raw syscalls and not through
/// `nix`, and that is the difference between this test working and not.
/// glibc's `setuid` is `__nptl_setxid`: it broadcasts to every thread of the
/// process and waits for them. This child is the fork of a tokio runtime, so
/// glibc's idea of the thread list is stale, the broadcast fails, and the
/// call comes back as an error — after which a connect as the ORIGINAL user
/// succeeds and looks like a hole in the permissions. The syscall changes
/// the calling thread only, which in a forked child is the whole process.
fn connect_as(user: &agent_api::VmmUser, socket: &Path) -> i32 {
    use nix::unistd::{ForkResult, fork};
    // SAFETY: the child calls only socket syscalls before `_exit` and never
    // returns into the test harness.
    match unsafe { fork() }.expect("fork") {
        ForkResult::Child => {
            let code = (|| -> i32 {
                // SAFETY: FFI calls with scalar arguments.
                unsafe {
                    // The supplementary groups FIRST, and this is the line
                    // that cost a run. `setgid` replaces the primary group
                    // and leaves the inherited list alone — so a child of a
                    // root process keeps group 0 in it, and a socket that is
                    // `0660 root:root` is then reachable through its GROUP
                    // bits by a process whose uid is 907. Measured exactly
                    // that way: `0660` let the probe in and `0600` did not.
                    //
                    // `std::process::Command::uid` does this for us in the
                    // real spawn — it documents "a call to `setgroups(0,
                    // NULL)` in the child process if no groups have been
                    // specified" — so the probe has to, or it is not asking
                    // the same question the VMM answers.
                    if nix::libc::syscall(nix::libc::SYS_setgroups, 0, std::ptr::null::<u32>()) != 0
                    {
                        return COULD_NOT_SWITCH;
                    }
                    if nix::libc::syscall(nix::libc::SYS_setgid, user.gid) != 0 {
                        return COULD_NOT_SWITCH;
                    }
                    if nix::libc::syscall(nix::libc::SYS_setuid, user.uid) != 0 {
                        return COULD_NOT_SWITCH;
                    }
                    if nix::libc::geteuid() != user.uid {
                        return COULD_NOT_SWITCH;
                    }
                }
                match std::os::unix::net::UnixStream::connect(socket) {
                    Ok(_) => 0,
                    Err(e) => e.raw_os_error().unwrap_or(0),
                }
            })();
            // `_exit` and not `std::process::exit`: running atexit handlers
            // in the fork of a tokio runtime would run the runtime's.
            // SAFETY: FFI call that does not return.
            unsafe { nix::libc::_exit(code) }
        }
        ForkResult::Parent { child } => {
            match nix::sys::wait::waitpid(child, None).expect("waitpid") {
                nix::sys::wait::WaitStatus::Exited(_, code) => code,
                other => panic!("the child did not exit: {other:?}"),
            }
        }
    }
}

/// S4, the other half: the vhost-user backend is the same unprivileged user,
/// and the socket it makes is not readable by the node.
///
/// This is the half that decides whether Stufe 3 buys anything for a display
/// VM, and the argument is not ours. QEMU: "There is not considered to be
/// security boundary between QEMU and the vhost-user & vfio-user backends."
/// Cloud Hypervisor: "Cloud Hypervisor gives vhost-user devices complete
/// control over the guest." A root backend beside an unprivileged VMM is a
/// root VMM with extra steps.
///
/// `input` and not `nvrm`, and that is a property of this machine rather than
/// a choice: the card here is a GeForce RTX 2070 with no vGPU, so there is no
/// mdev device for `nvrm` to serve. The seam is the same one either way —
/// `drivers/backend` spawns all three — and Leandro's nvrm backend is built
/// to run unprivileged already: its own `settle_admin_privilege` DROPS
/// `CAP_SYS_ADMIN` unless `LEA_ADMIN_PRIV=1` asks for it.
#[tokio::test]
#[ignore = "needs Leandro's vhost-user-input in MEISTER_INPUT_BACKEND and (for the switch) root; see the module note"]
async fn a_vhost_user_backend_runs_as_the_same_user_as_the_vmm() {
    let backend = std::env::var("MEISTER_INPUT_BACKEND").unwrap_or_default();
    if backend.is_empty() {
        eprintln!("MEISTER_INPUT_BACKEND names no backend binary; nothing to spawn");
        return;
    }
    let dir = rig("backend");
    let user = vmm_user();
    let driver = input_driver::InputDriver::new(input_driver::InputDriverConfig {
        binary: PathBuf::from(&backend),
        run_dir: dir.path().join("input"),
        socket_timeout: Duration::from_secs(10),
        vmm_user: user.clone(),
    })
    .expect("a driver over Leandro's backend");

    // The `fifo` profile, because it needs no host device: what is under test
    // is the process and the file it makes, not where its events come from.
    let id = agent_api::DeviceId::new_v4();
    let device = agent_api::device::DeviceDriver::create(
        &driver,
        &id,
        &agent_api::DeviceSpec {
            driver: "input".into(),
            partition: agent_api::PartitionSpec::Mediated,
            profile: Some("fifo".into()),
            params: None,
        },
        None,
    )
    .await
    .expect("the backend starts");

    let agent_api::DeviceAttachment::VhostUser { socket, pid, .. } = device.attachment.clone()
    else {
        panic!("the input driver did not hand back a vhost-user attachment");
    };
    let who = ps(pid, "user");
    let expected = match &user {
        Some(user) => user.name.clone(),
        None => whoami(),
    };
    println!("backend pid {pid} runs as {who:?} (expected {expected:?})");
    assert!(
        who == expected || expected.starts_with(&who),
        "the backend runs as {who:?} and not as {expected:?}"
    );

    // And the socket the VMM will connect to is the backend's own, with
    // nothing for the world: the VMM is the same user, so nothing wider is
    // needed, and what a guest sends through its input device is nobody
    // else's business.
    //
    // `0770` and not `0660`, which is worth knowing rather than asserting
    // loosely: a socket's base mode is `0777` where a regular file's is
    // `0666`, so the same `umask 007` produces different numbers for the
    // console FILE and for the sockets beside it. The execute bit means
    // nothing on a socket; the bits that matter are the last three.
    {
        use std::os::unix::fs::MetadataExt;
        use std::os::unix::fs::PermissionsExt;
        let meta = std::fs::metadata(&socket).expect("the backend's socket");
        println!(
            "backend socket {} is {:o} uid={} gid={}",
            socket.display(),
            meta.permissions().mode() & 0o777,
            meta.uid(),
            meta.gid()
        );
        if let Some(user) = &user {
            assert_eq!(
                meta.permissions().mode() & 0o007,
                0,
                "world bits on the backend's socket"
            );
            assert_eq!(meta.permissions().mode() & 0o770, 0o770);
            assert_eq!(meta.uid(), user.uid);
            assert_eq!(meta.gid(), user.gid);
        }
    }

    agent_api::device::DeviceDriver::destroy(&driver, &id, &device.attachment)
        .await
        .expect("teardown");
    assert!(
        !std::path::Path::new(&format!("/proc/{pid}")).exists(),
        "the backend is still there"
    );
}
