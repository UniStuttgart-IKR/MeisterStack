// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! The driver against a process, without Leandro's binary.
//!
//! What the lib's own tests cannot say: they reason about a spec and never
//! fork anything, so the half that matters on a node — a backend is started,
//! it is waited for, it is recognised again after a restart, and teardown
//! really ends it — needs a process. The real backend needs a VMM to talk to
//! and a guest to talk about; here a stand-in takes the same arguments, makes
//! the socket the driver waits for and stays until it is signalled. The real
//! one is exercised in `components/agent/tests/input_ch.rs`.
//!
//! The stand-in is a shell script, and its FILE NAME is load-bearing: an
//! adopted backend is recognised by `/proc/<pid>/comm`
//! (`BackendKind::is_ours`), and for an interpreted file the kernel takes
//! `comm` from the script rather than from the interpreter. So the script is
//! called `vhost-user-input`, the process calls itself `vhost-user-inpu` —
//! cut where the kernel cuts it — and the identity check has something real
//! to answer.

use std::path::{Path, PathBuf};
use std::time::Duration;

use agent_api::device::{
    Device, DeviceAttachment, DeviceDriver, DeviceError, DeviceId, DeviceSpec, PartitionSpec,
};
use meister_input_driver::{InputDriver, InputDriverConfig, PROFILE_EVDEV, PROFILE_FIFO};

/// A backend that comes up: it makes the socket and waits to be signalled.
const LISTENS: &str = r#"
socket=; src=
while [ "$#" -gt 0 ]; do
  case "$1" in
    --socket) socket=$2; shift 2 ;;
    --fifo|--evdev) src=$2; shift 2 ;;
    --name) shift 2 ;;
    *) echo "unexpected argument: $1" >&2; exit 2 ;;
  esac
done
[ -n "$socket" ] || { echo "no --socket" >&2; exit 2; }
[ -n "$src" ] || { echo "no --fifo and no --evdev" >&2; exit 2; }
[ -e "$src" ] || { echo "source $src does not exist" >&2; exit 2; }
echo "fake vhost-user-input: $socket <- $src"
trap 'rm -f "$socket"; exit 0' TERM
: > "$socket"
while : ; do sleep 0.05; done
"#;

/// A backend that starts and never serves — the shape of every real failure
/// that is not a crash: a card that is busy, a permission that is missing.
const NEVER_LISTENS: &str = r#"
echo "fake vhost-user-input: not listening today" >&2
while : ; do sleep 0.05; done
"#;

struct Rig {
    temp: tempfile::TempDir,
}

impl Rig {
    fn new(body: &str) -> Self {
        let temp = tempfile::Builder::new()
            .prefix("ms-input-driver-")
            .tempdir()
            .expect("a directory");
        // Named after the backend, because that name becomes the process's
        // `comm` and `comm` is half of the identity check.
        let script = temp.path().join("vhost-user-input");
        std::fs::write(&script, format!("#!/bin/sh\n{body}")).expect("a script");
        std::fs::set_permissions(&script, std::os::unix::fs::PermissionsExt::from_mode(0o755))
            .expect("an executable script");
        Self { temp }
    }

    fn driver(&self, timeout: Duration) -> InputDriver {
        InputDriver::new(InputDriverConfig {
            binary: self.temp.path().join("vhost-user-input"),
            run_dir: self.temp.path().join("run").join("input"),
            socket_timeout: timeout,
        })
        .expect("a driver over the stand-in")
    }

    fn run_dir(&self) -> PathBuf {
        self.temp.path().join("run").join("input")
    }
}

fn spec(profile: &str, params: Option<serde_json::Value>) -> DeviceSpec {
    DeviceSpec {
        driver: "input".into(),
        partition: PartitionSpec::Mediated,
        profile: Some(profile.to_string()),
        params,
    }
}

fn alive(pid: u32) -> bool {
    Path::new(&format!("/proc/{pid}")).exists()
}

fn pid_of(device: &Device) -> u32 {
    let DeviceAttachment::VhostUser { pid, .. } = &device.attachment else {
        panic!("a vhost-user attachment");
    };
    *pid
}

/// Wait for a process to really be gone. SIGTERM is asynchronous and the
/// alternative is a sleep somebody has to tune.
async fn wait_gone(pid: u32) {
    for _ in 0..200 {
        if !alive(pid) {
            return;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!("the backend at pid {pid} is still running");
}

/// One device end to end: the process, the two files it needs, and what the
/// VMM is handed about it.
#[tokio::test]
async fn a_fifo_device_is_a_process_a_socket_and_a_pipe() {
    let rig = Rig::new(LISTENS);
    let driver = rig.driver(Duration::from_secs(5));
    let id = DeviceId::new_v4();

    let device = driver
        .create(&id, &spec(PROFILE_FIFO, None), None)
        .await
        .expect("the stand-in comes up");

    let DeviceAttachment::VhostUser {
        socket,
        pid,
        device_type,
        queue_sizes,
    } = &device.attachment
    else {
        panic!("a vhost-user attachment");
    };
    assert_eq!(*device_type, 18, "virtio-input");
    assert_eq!(queue_sizes, &vec![256, 256]);
    assert!(alive(*pid), "the backend is running");
    assert_eq!(socket, &rig.run_dir().join(format!("{id}.sock")));
    assert!(socket.exists(), "the driver waited for the socket");

    // The pipe a gate writes into, made by the driver and not by the
    // backend — so it is there the moment `create` returns.
    let fifo = rig.run_dir().join(format!("{id}.fifo"));
    let meta = std::fs::metadata(&fifo).expect("the pipe is there");
    assert!(
        std::os::unix::fs::FileTypeExt::is_fifo(&meta.file_type()),
        "and it is a pipe"
    );

    // The backend was given both paths, in the two arguments Leandro's
    // binary takes. This is read off /proc rather than mocked: what the
    // driver puts on a command line is the whole of its contract with the
    // backend.
    let cmdline = std::fs::read(format!("/proc/{pid}/cmdline")).expect("linux");
    let args: Vec<String> = cmdline
        .split(|b| *b == 0)
        .filter(|s| !s.is_empty())
        .map(|s| String::from_utf8_lossy(s).into_owned())
        .collect();
    assert!(args.contains(&"--socket".to_string()), "{args:?}");
    assert!(args.contains(&"--fifo".to_string()), "{args:?}");
    assert!(args.contains(&fifo.display().to_string()), "{args:?}");
    assert!(!args.contains(&"--evdev".to_string()), "{args:?}");

    // And the liveness probe agrees with all of it.
    driver
        .get(&id, &device.attachment)
        .await
        .expect("the device this driver just made is its own");

    driver
        .destroy(&id, &device.attachment)
        .await
        .expect("teardown");
    wait_gone(*pid).await;
    assert!(!socket.exists(), "the socket went with the backend");
    assert!(
        !fifo.exists(),
        "and the pipe too: a writer on a readerless pipe blocks for ever"
    );
    assert!(
        driver.get(&id, &device.attachment).await.is_err(),
        "a torn-down device is not found"
    );
}

/// The evdev profile forwards a node this driver did not make, so it makes no
/// pipe and it must not take the node away.
#[tokio::test]
async fn an_evdev_device_forwards_a_node_and_leaves_it_where_it_is() {
    let rig = Rig::new(LISTENS);
    let node = rig.temp.path().join("event0");
    std::fs::write(&node, b"").expect("a stand-in for a host input node");
    let driver = rig.driver(Duration::from_secs(5));
    let id = DeviceId::new_v4();

    let device = driver
        .create(
            &id,
            &spec(
                PROFILE_EVDEV,
                Some(serde_json::json!({ "evdev": node, "name": "a named device" })),
            ),
            None,
        )
        .await
        .expect("the stand-in comes up");
    let pid = pid_of(&device);

    let cmdline = std::fs::read(format!("/proc/{pid}/cmdline")).expect("linux");
    let raw = String::from_utf8_lossy(&cmdline).replace('\0', " ");
    assert!(raw.contains("--evdev"), "{raw}");
    assert!(raw.contains(&node.display().to_string()), "{raw}");
    assert!(
        raw.contains("--name"),
        "the name reaches the backend: {raw}"
    );
    assert!(raw.contains("a named device"), "{raw}");
    assert!(!raw.contains("--fifo"), "{raw}");
    assert!(
        !rig.run_dir().join(format!("{id}.fifo")).exists(),
        "no pipe for a device that forwards a host node"
    );

    driver
        .destroy(&id, &device.attachment)
        .await
        .expect("teardown");
    wait_gone(pid).await;
    assert!(
        node.exists(),
        "the host's input node is not this driver's to remove"
    );
}

/// A backend that never serves must fail the create with the reason in hand,
/// and it must not be left behind: nothing would ever collect it.
#[tokio::test]
async fn a_backend_that_never_listens_fails_the_create_and_says_why() {
    let rig = Rig::new(NEVER_LISTENS);
    let driver = rig.driver(Duration::from_millis(300));
    let id = DeviceId::new_v4();

    let Err(err) = driver.create(&id, &spec(PROFILE_FIFO, None), None).await else {
        panic!("a device was reported for a backend that is not listening");
    };
    assert!(
        matches!(err, DeviceError::BackendDied(_)),
        "the shape of it matters: {err:?}"
    );
    let msg = err.to_string();
    assert!(msg.contains("socket did not appear"), "{msg}");
    // The log tail rides on the message, because the file's name is the one
    // thing an operator does not have.
    assert!(msg.contains("not listening today"), "{msg}");
}

/// The same device asked for twice gets the backend that is already serving
/// it, and not a second one on the same socket. Leandro's rig measured what
/// the other answer costs: seven orphaned backends, the oldest four hours
/// old (`scripts/lib/rig.sh`, `_lea_stop_stale`).
#[tokio::test]
async fn a_second_create_for_one_device_is_the_backend_that_is_already_there() {
    let rig = Rig::new(LISTENS);
    let driver = rig.driver(Duration::from_secs(5));
    let id = DeviceId::new_v4();

    let first = driver
        .create(&id, &spec(PROFILE_FIFO, None), None)
        .await
        .expect("a backend");
    let again = driver
        .create(&id, &spec(PROFILE_FIFO, None), None)
        .await
        .expect("the same backend");
    assert_eq!(pid_of(&first), pid_of(&again), "one backend, not two");

    driver
        .destroy(&id, &first.attachment)
        .await
        .expect("teardown");
    wait_gone(pid_of(&first)).await;
}

/// Teardown after an agent restart, which is the case the identity check
/// exists for: the backend is no longer anybody's child, and the pid on the
/// record is the only handle left on it. A driver that shrugged here would
/// leave a backend serving a VM that is gone — and this backend does not end
/// itself when it has nothing to serve.
#[tokio::test]
async fn a_backend_adopted_from_a_previous_agent_is_still_stopped() {
    let rig = Rig::new(LISTENS);
    let id = DeviceId::new_v4();

    let device = {
        let before = rig.driver(Duration::from_secs(5));
        before
            .create(&id, &spec(PROFILE_FIFO, None), None)
            .await
            .expect("a backend")
        // `before` is dropped here: the process survives, the handle does
        // not. That is exactly what an agent restart leaves behind.
    };
    let pid = pid_of(&device);
    assert!(alive(pid), "the backend outlived the driver that made it");

    let after = rig.driver(Duration::from_secs(5));
    after
        .destroy(&id, &device.attachment)
        .await
        .expect("teardown of an adopted backend");
    wait_gone(pid).await;
    assert!(
        !rig.run_dir().join(format!("{id}.fifo")).exists(),
        "the files went too"
    );
}

/// Teardown is idempotent, and it has to be: a reconciler that retries one
/// must be able to finish.
#[tokio::test]
async fn destroying_the_same_device_twice_is_done_twice() {
    let rig = Rig::new(LISTENS);
    let driver = rig.driver(Duration::from_secs(5));
    let id = DeviceId::new_v4();

    let device = driver
        .create(&id, &spec(PROFILE_FIFO, None), None)
        .await
        .expect("a backend");
    driver
        .destroy(&id, &device.attachment)
        .await
        .expect("the first teardown");
    driver
        .destroy(&id, &device.attachment)
        .await
        .expect("and the second, which has nothing left to do");
}
