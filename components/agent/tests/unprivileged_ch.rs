// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Ignored integration test for a nonroot agent with no effective capabilities.
//! Requires delegated cpu/memory cgroups, KVM access, curl, an agent binary with
//! http-api and debug-mutations enabled, Cloud Hypervisor, a kernel and initramfs.
//! MEISTER_INPUT_BACKEND is optional.
//!
//! ```text
//! systemd-run --user --scope -p Delegate=yes --setenv=RUST_LOG=info \
//!   env MEISTER_AGENT=$PWD/target/debug/meister-agent \
//!       MEISTER_CH=$PWD/bin/cloud-hypervisor \
//!       MEISTER_KERNEL=$PWD/images/vmlinux.elf \
//!       MEISTER_INITRD=$PWD/images/initrd \
//!   cargo test -p meister-agent --test unprivileged_ch -- --ignored --nocapture
//! ```
//!
//! The test checks prerequisite reporting, a NIC-free guest boot, cgroup membership
//! and teardown through the local Unix API. Guest files are supplied externally;
//! either console stream must contain a Linux printk-style timestamp.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

/// A path this test cannot invent.
fn from_env(var: &str) -> PathBuf {
    let raw = std::env::var(var)
        .unwrap_or_else(|_| panic!("{var} must be set; see the module note at the top"));
    let path = PathBuf::from(raw);
    assert!(path.exists(), "{var} names {} — not there", path.display());
    path
}

/// This process's cgroup, absolute.
fn own_cgroup() -> PathBuf {
    let relative = std::fs::read_to_string("/proc/self/cgroup")
        .expect("/proc/self/cgroup")
        .lines()
        .find_map(|line| line.strip_prefix("0::").map(str::to_string))
        .expect("a cgroup2 line");
    let mounts = std::fs::read_to_string("/proc/self/mounts").expect("/proc/self/mounts");
    let mount = mounts
        .lines()
        .find_map(|line| {
            let mut f = line.split_whitespace();
            let _device = f.next()?;
            let point = f.next()?;
            (f.next()? == "cgroup2").then(|| PathBuf::from(point))
        })
        .expect("a cgroup2 mount");
    mount.join(relative.trim().trim_start_matches('/'))
}

/// Prepare a delegated cgroup subtree for the agent. Move the test processes
/// to a sibling before enabling controllers, satisfying the no-internal-process
/// rule. Then create the agent cgroup; pre_exec moves the agent into it before
/// startup so its configured root models a delegated service unit.
fn delegated_subtree() -> PathBuf {
    let scope = own_cgroup();
    let controllers = std::fs::read_to_string(scope.join("cgroup.controllers")).unwrap_or_default();
    assert!(
        controllers.contains("memory") && controllers.contains("cpu"),
        "this test has to run inside a delegated cgroup subtree, and {} offers only {controllers:?}\
         \nstart it with: systemd-run --user --scope -p Delegate=yes … (see the module note)",
        scope.display()
    );

    let rig = scope.join("rig");
    std::fs::create_dir_all(&rig).expect("a cgroup for the test rig");
    for pid in std::fs::read_to_string(scope.join("cgroup.procs"))
        .expect("the scope's processes")
        .split_whitespace()
    {
        std::fs::write(rig.join("cgroup.procs"), pid)
            .unwrap_or_else(|e| panic!("moving {pid} into {}: {e}", rig.display()));
    }
    std::fs::write(scope.join("cgroup.subtree_control"), "+cpu +memory")
        .expect("the scope hands cpu and memory to its children");

    let agent = scope.join("agent");
    std::fs::create_dir_all(&agent).expect("a cgroup for the agent");
    agent
}

/// Configure a compute node plus unavailable LVM, NFS, NVMe-oF and network
/// backends. Startup must report their missing privileges and continue with
/// the usable hypervisor.
fn config(root: &Path, cgroup_root: &Path, input_backend: Option<&Path>) -> PathBuf {
    let ch = from_env("MEISTER_CH");
    let device = match input_backend {
        Some(backend) => format!(
            "[device.input]\nbinary = \"{}\"\nsocket_timeout_ms = 5000\n",
            backend.display()
        ),
        None => String::new(),
    };
    let toml = format!(
        r#"node_id = "unprivileged-e2e"
stop_grace_secs = 5

[paths]
db_path = "{root}/agent.redb"
run_dir = "{root}/run"
image_dir = "{root}/images"
volume_dir = "{root}/volumes"
cgroup_root = "{cgroup}"

[hypervisor.cloud-hypervisor]
binary = "{ch}"
timeout_ms = 10000

[network]
default_bridge = "meister_br0"

[volume.lvm-thin]
vg = "vg-that-is-not-here"
thin_pool = "pool"

[volume.nfs]
share_root = "{root}/nfs"

[volume.nvmeof]

{device}"#,
        root = root.display(),
        cgroup = cgroup_root.display(),
        ch = ch.display(),
    );
    let path = root.join("agent.toml");
    std::fs::write(&path, toml).expect("the config");
    path
}

fn curl(socket: &Path, args: &[&str]) -> String {
    let out = Command::new("curl")
        .arg("-s")
        .arg("--unix-socket")
        .arg(socket)
        .args(args)
        .output()
        .expect("curl is on PATH");
    String::from_utf8_lossy(&out.stdout).to_string()
}

fn alive(pid: u32) -> bool {
    Path::new(&format!("/proc/{pid}")).exists()
}

fn wait_for(what: &str, seconds: u64, mut ready: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(seconds);
    while Instant::now() < deadline {
        if ready() {
            return;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    panic!("{what} did not happen within {seconds}s");
}

/// A capability-free agent in a delegated cgroup boots a guest and reports unavailable backends.
#[test]
#[ignore = "needs a real cloud-hypervisor, kernel and initramfs, and a delegated cgroup subtree; see the module note"]
fn an_agent_without_any_rights_boots_a_guest_and_says_what_it_cannot_do() {
    // Require CapEff=0 so privileged execution cannot invalidate the test premise.
    let status = std::fs::read_to_string("/proc/self/status").expect("/proc/self/status");
    let effective = status
        .lines()
        .find_map(|line| line.strip_prefix("CapEff:"))
        .map(|rest| rest.trim().to_string())
        .expect("CapEff");
    assert_ne!(
        nix::unistd::geteuid().as_raw(),
        0,
        "this test is about an agent that is not root"
    );
    assert_eq!(
        effective, "0000000000000000",
        "this test is about an agent with no capability at all"
    );

    let temp = tempfile::Builder::new()
        .prefix("ms-unprivileged-")
        .tempdir()
        .expect("a directory");
    let root = temp.path().to_path_buf();
    for dir in ["images", "volumes", "run"] {
        std::fs::create_dir_all(root.join(dir)).expect("a directory");
    }
    // The two guest files, under the fixed names a boot source names.
    for (var, name) in [("MEISTER_KERNEL", "kernel"), ("MEISTER_INITRD", "initrd")] {
        let from = from_env(var);
        let to = root.join("images").join(name);
        std::fs::hard_link(&from, &to)
            .or_else(|_| std::fs::copy(&from, &to).map(|_| ()))
            .expect("the guest file is readable");
    }

    let cgroup_root = delegated_subtree();
    let input_backend = std::env::var("MEISTER_INPUT_BACKEND")
        .ok()
        .map(PathBuf::from);
    let config = config(&root, &cgroup_root, input_backend.as_deref());

    // The agent, in its own cgroup and nowhere else. `pre_exec` writes "0"
    // into `cgroup.procs`, which cgroup v2 reads as "the process doing the
    // writing" — so the agent is in the directory before it is the agent.
    let log = root.join("agent.log");
    let journal = std::fs::File::create(&log).expect("a log file");
    let procs = cgroup_root.join("cgroup.procs");
    let mut command = Command::new(from_env("MEISTER_AGENT"));
    command
        .arg("--config")
        .arg(&config)
        .env("RUST_LOG", "info")
        .stdout(journal.try_clone().expect("a handle"))
        .stderr(journal);
    unsafe {
        use std::os::unix::process::CommandExt;
        command.pre_exec(move || std::fs::write(&procs, "0"));
    }
    let mut agent = command.spawn().expect("the agent starts");

    let socket = root.join("run").join("agent.sock");
    let said = || std::fs::read_to_string(&log).unwrap_or_default();
    wait_for("the agent's socket", 30, || {
        assert!(
            agent.try_wait().expect("a look").is_none(),
            "the agent died:\n{}",
            said()
        );
        socket.exists()
    });

    // --- what it said about itself ----------------------------------------
    let boot = said();
    print!("{boot}");
    for sentence in [
        "lvm-thin: needs CAP_SYS_ADMIN",
        "nfs: needs CAP_SYS_ADMIN",
        "nvmeof: needs",
        "linux: needs CAP_NET_ADMIN",
        "tap guard off: guests on this node are not filtered",
    ] {
        assert!(
            boot.contains(sentence),
            "the agent never said {sentence:?}:\n{boot}"
        );
    }
    assert!(
        boot.contains("the rights this agent came up with") && boot.contains("CapEff=0000"),
        "the primitives are said too, not only the verdict:\n{boot}"
    );
    assert!(
        boot.contains("hung itself below its delegated cgroup root"),
        "the agent has to move itself out of its own cgroup root:\n{boot}"
    );
    assert!(
        std::fs::read_to_string(cgroup_root.join("supervisor").join("cgroup.procs"))
            .expect("the supervisor subgroup")
            .split_whitespace()
            .any(|pid| pid.parse::<u32>() == Ok(agent.id())),
        "and it is really in there"
    );

    // --- the guest, over the socket and nothing else ----------------------
    let spec = root.join("vm.json");
    std::fs::write(
        &spec,
        r#"{
          "vcpus": 1,
          "memory_mib": 512,
          "boot": { "kind": "direct_kernel", "kernel": "kernel", "initramfs": "initrd",
                    "cmdline": "console=hvc0 panic=1" },
          "volumes": [ { "size_bytes": 1048576 } ],
          "nics": [],
          "devices": []
        }"#,
    )
    .expect("a spec");
    let created = curl(
        &socket,
        &[
            "-X",
            "POST",
            "-H",
            "content-type: application/json",
            "--data",
            &format!("@{}", spec.display()),
            "http://localhost/vms",
        ],
    );
    let id = created
        .split('"')
        .nth(3)
        .unwrap_or_default()
        .trim()
        .to_string();
    assert!(
        !id.is_empty() && id.len() == 36,
        "the create answered {created:?}; the agent said:\n{}",
        said()
    );
    println!("vm {id} created through {}", socket.display());

    let record = curl(&socket, &[&format!("http://localhost/vms/{id}")]);
    assert!(
        record.contains("\"phase\":\"Provisioned\""),
        "the vm is not up: {record}"
    );
    let vmm: u32 = record
        .split("\"vmm_pid\":")
        .nth(1)
        .and_then(|rest| {
            rest.trim_start()
                .split(|c: char| !c.is_ascii_digit())
                .next()
                .and_then(|n| n.parse().ok())
        })
        .expect("a vmm pid in the record");
    assert!(alive(vmm), "cloud-hypervisor {vmm} is up");

    // The cgroup half of the proof, while the guest is running: the VM's own
    // slice, inside the delegated subtree, with a limit really written into
    // it. Without the supervisor move this file does not exist.
    let slice = std::fs::read_dir(&cgroup_root)
        .expect("the delegated root")
        .filter_map(Result::ok)
        .map(|e| e.path())
        .find(|p| p.is_dir() && p.file_name().is_some_and(|n| n != "supervisor"))
        .expect("the vm's slice is under the delegated root");
    let limit = std::fs::read_to_string(slice.join("memory.max")).expect("a memory limit");
    println!(
        "slice {} limits memory to {}",
        slice.display(),
        limit.trim()
    );
    assert_ne!(limit.trim(), "max", "the slice really carries the limit");
    assert!(
        std::fs::read_to_string(slice.join("cgroup.procs"))
            .expect("the slice's processes")
            .split_whitespace()
            .any(|pid| pid.parse::<u32>() == Ok(vmm)),
        "and the vmm is really in it"
    );

    // Read the driver's virtio-console file and the agent's recorded serial file.
    let vms = root.join("run").join("vms");
    // Accept a printk-style timestamp from either stream; this avoids depending
    // on a distribution banner or on which console driver the kernel provides.
    let booted = || {
        [
            vms.join(format!("{id}.console")),
            vms.join(format!("{id}.serial")),
        ]
        .iter()
        .any(|path| {
            std::fs::read_to_string(path)
                .unwrap_or_default()
                .lines()
                .any(|line| {
                    let line = line.trim_start();
                    line.starts_with('[') && line.contains("] ")
                })
        })
    };
    let deadline = Instant::now() + Duration::from_secs(90);
    while Instant::now() < deadline && !booted() {
        std::thread::sleep(Duration::from_millis(200));
    }
    if !booted() {
        // Collect VMM files when guest output is absent to aid boot and console diagnosis.
        let files: Vec<String> = std::fs::read_dir(&vms)
            .expect("the vmm's directory")
            .filter_map(Result::ok)
            .map(|e| {
                format!(
                    "{} ({} bytes)",
                    e.path().display(),
                    e.metadata().map(|m| m.len()).unwrap_or(0)
                )
            })
            .collect();
        panic!(
            "no guest ever printed to a console here.\nfiles: {files:#?}\nconsole:\n{}\nagent:\n{}",
            std::fs::read_to_string(vms.join(format!("{id}.console"))).unwrap_or_default(),
            said(),
        );
    }
    let console = std::fs::read_to_string(vms.join(format!("{id}.console"))).unwrap_or_default();
    println!(
        "the guest is talking ({} bytes on hvc0), first kernel line: {}",
        console.len(),
        console
            .lines()
            .find(|l| l.trim_start().starts_with('['))
            .unwrap_or_default()
            .trim()
    );

    // --- and the teardown, which has to leave nothing --------------------
    curl(
        &socket,
        &["-X", "DELETE", &format!("http://localhost/vms/{id}")],
    );
    wait_for("the vmm to go", 30, || !alive(vmm));
    let gone = curl(&socket, &[&format!("http://localhost/vms/{id}")]);
    assert!(
        !gone.contains("\"phase\""),
        "the record is still here: {gone}"
    );
    assert!(
        !slice.exists(),
        "the slice is still here: {}",
        slice.display()
    );

    // The agent goes the way its unit would stop it.
    nix::sys::signal::kill(
        nix::unistd::Pid::from_raw(agent.id() as i32),
        nix::sys::signal::Signal::SIGTERM,
    )
    .expect("sigterm");
    let _ = agent.wait();
    println!("torn down: no vmm, no slice, no record — and never a capability");
}
