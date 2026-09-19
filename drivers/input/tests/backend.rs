// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Process lifecycle and upstream CLI contract. Character devices stand in for evdev.

use agent_api::device::{DeviceAttachment, DeviceDriver, DeviceId, DeviceSpec, PartitionSpec};
use meister_input_driver::{InputDriver, InputDriverConfig};
use std::{
    path::{Path, PathBuf},
    time::Duration,
};

const LISTENS: &str = r#"
[ "$1" = --socket-path ] && [ "$3" = --event-list ] || exit 2
socket=${2}0
[ -c "$4" ] || exit 3
trap 'rm -f "$socket"; exit 0' TERM
: > "$socket"
while :; do sleep 0.05; done
"#;

fn driver(root: &Path, binary: PathBuf, timeout: Duration) -> InputDriver {
    InputDriver::new(InputDriverConfig {
        binary,
        run_dir: root.join("run"),
        socket_timeout: timeout,
        vmm_user: None,
    })
    .unwrap()
}

fn fake(root: &Path, body: &str) -> InputDriver {
    use std::os::unix::fs::PermissionsExt;
    let binary = root.join("vhost-device-input");
    std::fs::write(&binary, format!("#!/bin/sh\n{body}")).unwrap();
    std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o755)).unwrap();
    driver(root, binary, Duration::from_millis(500))
}

fn spec(path: &Path) -> DeviceSpec {
    DeviceSpec {
        driver: "input".into(),
        partition: PartitionSpec::Mediated,
        profile: Some("evdev".into()),
        params: Some(serde_json::json!({"evdev": path})),
    }
}

fn pid(attachment: &DeviceAttachment) -> u32 {
    let DeviceAttachment::VhostUser { pid, .. } = attachment else {
        panic!("not vhost-user")
    };
    *pid
}

async fn gone(pid: u32) {
    for _ in 0..200 {
        // try_wait reaps an owned child; adopted children may remain zombies until reaped.
        let stat = std::fs::read_to_string(format!("/proc/{pid}/stat"));
        if stat.is_err() || stat.unwrap().split(") ").nth(1).unwrap().starts_with('Z') {
            return;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!("backend {pid} still running");
}

#[tokio::test]
async fn lifecycle_and_restart_use_the_socket_prefix() {
    let temp = tempfile::tempdir().unwrap();
    let before = fake(temp.path(), LISTENS);
    let id = DeviceId::new_v4();
    let spec = spec(Path::new("/dev/null"));
    let device = before.create(&id, &spec, None).await.unwrap();
    let DeviceAttachment::VhostUser {
        socket,
        device_type,
        queue_sizes,
        ..
    } = &device.attachment
    else {
        unreachable!()
    };
    assert_eq!(socket, &temp.path().join(format!("run/{id}.sock0")));
    assert!(socket.exists());
    assert_eq!(*device_type, 18);
    assert_eq!(queue_sizes, &[256, 256]);
    assert_eq!(
        pid(&before.create(&id, &spec, None).await.unwrap().attachment),
        pid(&device.attachment)
    );
    before.get(&id, &device.attachment).await.unwrap();
    assert!(
        before
            .get(&DeviceId::new_v4(), &device.attachment)
            .await
            .is_err()
    );
    drop(before);
    let after = fake(temp.path(), LISTENS);
    after.get(&id, &device.attachment).await.unwrap();
    after.destroy(&id, &device.attachment).await.unwrap();
    gone(pid(&device.attachment)).await;
    after.destroy(&id, &device.attachment).await.unwrap();
    assert!(!socket.exists());
    assert!(Path::new("/dev/null").exists());
}

#[tokio::test]
async fn owned_teardown_and_concurrent_create() {
    let temp = tempfile::tempdir().unwrap();
    let driver = fake(temp.path(), LISTENS);
    let id = DeviceId::new_v4();
    let spec = spec(Path::new("/dev/null"));
    let (a, b) = tokio::join!(
        driver.create(&id, &spec, None),
        driver.create(&id, &spec, None)
    );
    let a = a.unwrap();
    assert_eq!(pid(&a.attachment), pid(&b.unwrap().attachment));
    driver.destroy(&id, &a.attachment).await.unwrap();
    gone(pid(&a.attachment)).await;
    assert!(driver.get(&id, &a.attachment).await.is_err());
}

#[tokio::test]
async fn failure_includes_backend_log() {
    let temp = tempfile::tempdir().unwrap();
    let driver = fake(temp.path(), "echo test-failure >&2; exit 1");
    let error = driver
        .create(&DeviceId::new_v4(), &spec(Path::new("/dev/null")), None)
        .await
        .unwrap_err();
    assert!(error.to_string().contains("test-failure"), "{error}");
}

#[tokio::test]
async fn timeout_stops_the_backend() {
    let temp = tempfile::tempdir().unwrap();
    let driver = fake(
        temp.path(),
        "echo $$ > \"$2.pid\"; echo waiting >&2; while :; do sleep 0.05; done",
    );
    let id = DeviceId::new_v4();
    let error = driver
        .create(&id, &spec(Path::new("/dev/null")), None)
        .await
        .unwrap_err();
    assert!(error.to_string().contains("waiting"), "{error}");
    let pid = std::fs::read_to_string(temp.path().join(format!("run/{id}.sock.pid"))).unwrap();
    gone(pid.trim().parse().unwrap()).await;
}

#[tokio::test]
async fn rejects_legacy_and_invalid_sources() {
    let temp = tempfile::tempdir().unwrap();
    let driver = fake(temp.path(), LISTENS);
    let id = DeviceId::new_v4();
    let mut s = spec(Path::new("/dev/null"));
    s.profile = Some("fifo".into());
    assert!(driver.create(&id, &s, None).await.is_err());
    s.profile = None;
    s.params = None;
    assert!(driver.create(&id, &s, None).await.is_err());
    s.params = Some(serde_json::json!({"evdev": "/dev/null", "name": "old"}));
    assert!(driver.create(&id, &s, None).await.is_err());
    for path in [temp.path(), Path::new("/does-not-exist")] {
        assert!(driver.create(&id, &spec(path), None).await.is_err());
    }
    s = spec(Path::new("/dev/null"));
    s.partition = PartitionSpec::Exclusive;
    assert!(driver.create(&id, &s, None).await.is_err());
}

#[test]
fn admission_excludes_aliases_and_duplicates() {
    let temp = tempfile::tempdir().unwrap();
    let driver = fake(temp.path(), LISTENS);
    let alias = temp.path().join("event");
    std::os::unix::fs::symlink("/dev/null", &alias).unwrap();
    let a = (DeviceId::new_v4(), spec(Path::new("/dev/null")));
    let b = (DeviceId::new_v4(), spec(&alias));
    assert!(
        driver
            .admit(
                std::slice::from_ref(&b),
                &[(agent_api::VmId::new_v4(), a.1.clone())]
            )
            .is_err()
    );
    assert!(driver.admit(&[a, b], &[]).is_err());
    assert!(
        driver
            .admit(
                &[(DeviceId::new_v4(), spec(Path::new("/dev/zero")))],
                &[(agent_api::VmId::new_v4(), spec(Path::new("/dev/null")))]
            )
            .is_ok()
    );
    assert_eq!(driver.profiles(), ["evdev"]);
}

/// The verifier receives the socket path and must check guest event delivery.
#[tokio::test]
#[ignore = "requires MEISTER_INPUT_BACKEND, MEISTER_INPUT_DEVICE and MEISTER_INPUT_VERIFY"]
async fn upstream_guest_delivery() {
    let temp = tempfile::tempdir().unwrap();
    let driver = driver(
        temp.path(),
        std::env::var_os("MEISTER_INPUT_BACKEND").unwrap().into(),
        Duration::from_secs(5),
    );
    let id = DeviceId::new_v4();
    let source = PathBuf::from(std::env::var_os("MEISTER_INPUT_DEVICE").unwrap());
    let device = driver.create(&id, &spec(&source), None).await.unwrap();
    driver.get(&id, &device.attachment).await.unwrap();
    let DeviceAttachment::VhostUser { socket, .. } = &device.attachment else {
        unreachable!()
    };
    let result = tokio::process::Command::new(std::env::var_os("MEISTER_INPUT_VERIFY").unwrap())
        .arg(socket)
        .status()
        .await;
    driver.destroy(&id, &device.attachment).await.unwrap();
    gone(pid(&device.attachment)).await;
    assert!(!socket.exists());
    assert!(result.unwrap().success(), "guest verification failed");
}
