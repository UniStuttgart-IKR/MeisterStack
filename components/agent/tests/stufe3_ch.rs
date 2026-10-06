// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Ignored integration tests for descriptor-based tap handoff to Cloud Hypervisor.
//! Requires a VMM binary, kernel, initramfs and a preconfigured tap.
//!
//! ```text
//! # Prepare the tap once with privileges:
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
//! The user-switch test also requires permission to change credentials:
//!
//! ```text
//! sudo useradd -r -M -s /usr/sbin/nologin -G kvm meister-vmm
//! sudo -E MEISTER_CH=… MEISTER_KERNEL=… MEISTER_INITRD=… MEISTER_TAP=… \
//!         MEISTER_HOST_IP=… MEISTER_VMM_USER=meister-vmm \
//!   cargo test -p meister-agent --test stufe3_ch -- --ignored --nocapture
//! ```
//!
//! Supply an external initramfs that writes these markers to the serial console:
//! * `MS-S0-NICS: <names>` from `/sys/class/net`.
//! * `MS-S0-MAC: <addr>` and `MS-S0-MTU: <n>` from the guest interface.
//! * `MS-S0-PING-OK` or `MS-S0-PING-FAIL` after pinging `MEISTER_HOST_IP`.
//!
//! The guest boots with `console=ttyS0`. The test records the UART socket, as
//! the agent does, independently of the guest's virtio-console driver.

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

/// Use a short temporary path to keep VMM socket names within the AF_UNIX path limit.
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

/// Copy the VMM serial socket to a transcript file. Cloud Hypervisor v53
/// replays its bounded ring buffer when a reader connects.
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

/// Optional VMM identity from the environment; absence retains the test process identity.
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
    // Allow hotplug paths under the fixture root. Cloud Hypervisor derives
    // initial kernel and initramfs rules from the create document.
    .with_landlock_paths(vec![dir.to_path_buf()])
}

/// Verify tap-descriptor delivery with guest-reported MAC, MTU and host reachability.
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
    // Verify the guest sees the tap's 1450-byte MTU through descriptor handoff.
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

/// Verify the same add-net path exposes a second NIC to a running guest.
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

/// With MEISTER_VMM_USER set, Landlock allows a disk in a configured directory
/// and refuses one outside it. Both files receive identical ownership first.
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
        // Grant ordinary file access first so only Landlock distinguishes the paths.
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

/// Inspect the process fd table. A tap descriptor in an unprivileged,
/// Landlocked VMM demonstrates handoff without opening `/dev/net/tun` there.
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

/// Check VMM credentials, tap descriptors, guest connectivity and cleanup.
/// Credential-switch and socket-permission assertions require MEISTER_VMM_USER.
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

    // Verify descriptor handoff to a VMM without permission to open the tap itself.
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
    if let Some(user) = &user {
        assert!(
            cap_eff.ends_with("0000000000000000"),
            "a vmm that changed user should hold no capabilities: {cap_eff}"
        );
        // Require the VMM user's configured supplementary groups. Inherited root
        // groups could expose agent files; dropping every group could deny device access.
        let mut seen: Vec<u32> = groups
            .trim_start_matches("Groups:")
            .split_whitespace()
            .filter_map(|g| g.parse().ok())
            .collect();
        seen.sort_unstable();
        let mut wanted = user.groups.clone();
        wanted.sort_unstable();
        wanted.dedup();
        assert_eq!(
            seen, wanted,
            "the vmm's groups are {seen:?} and {}'s are {wanted:?}",
            user.name
        );
        assert!(
            !seen.contains(&0),
            "the vmm carries group 0, which is every 0660 root file on the node"
        );
    }

    assert!(
        lines.iter().any(|l| l == "MS-S0-PING-OK"),
        "the guest could not reach {}: {lines:#?}",
        host_ip()
    );

    // Check permissions on VMM-created files. Its trusted API socket requires
    // filesystem access control because Landlock does not restrict AF_UNIX connections.
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

/// Find the process whose command line names this test VM's API socket.
/// This scans argv, not socket ownership, and is only a test lookup.
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

/// Distinct child status for a failed user switch, separate from connect success.
const COULD_NOT_SWITCH: i32 = 111;

/// Connect as another user in a forked child and return errno through its exit status.
/// Set groups before dropping the UID. Use raw credential syscalls: glibc
/// setxid broadcasts to threads, whose bookkeeping is stale after forking
/// the Tokio runtime; the raw calls affect only the surviving child thread.
fn connect_as(user: &agent_api::VmmUser, socket: &Path) -> i32 {
    use nix::unistd::{ForkResult, fork};
    // SAFETY: the child calls only socket syscalls before `_exit` and never
    // returns into the test harness.
    match unsafe { fork() }.expect("fork") {
        ForkResult::Child => {
            let code = (|| -> i32 {
                // SAFETY: FFI calls with scalar arguments.
                unsafe {
                    // Drop inherited supplementary groups before switching gid and uid.
                    // This probe checks primary-user access; unlike the real VMM launcher,
                    // it does not install the target user's supplementary groups.
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
            // Avoid inherited atexit handlers after forking the Tokio runtime.
            // SAFETY: _exit terminates without returning or running those handlers.
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

/// Check input-backend credentials and socket permissions through the shared
/// backend launcher. The credential assertions require MEISTER_VMM_USER.
#[tokio::test]
#[ignore = "needs MEISTER_INPUT_BACKEND, MEISTER_INPUT_DEVICE readable by the VMM user, and root"]
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
        evdev: std::env::var_os("MEISTER_INPUT_DEVICE")
            .map(PathBuf::from)
            .into_iter()
            .collect(),
    })
    .expect("a driver over the upstream backend");

    // The fixture must be readable by the backend user.
    let id = agent_api::DeviceId::new_v4();
    let device = agent_api::device::DeviceDriver::create(
        &driver,
        &id,
        &agent_api::DeviceSpec {
            driver: "input".into(),
            partition: agent_api::PartitionSpec::Mediated,
            profile: Some("evdev".into()),
            params: Some(serde_json::json!({"evdev": std::env::var("MEISTER_INPUT_DEVICE").expect("input fixture path")})),
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

    // The backend socket must deny world access. Umask 007 yields socket mode
    // 0770 from base mode 0777, unlike regular files (0660 from 0666). Socket
    // execute bits are irrelevant to connection access.
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
