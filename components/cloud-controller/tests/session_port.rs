// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! A replica that was told to serve cluster sessions and cannot, says so.
//!
//! The session server used to be spawned and forgotten: tonic binds inside
//! the future, so a port somebody else held came back as one ERROR line from
//! a task nobody awaited, and the process went on answering `/readyz` 200 off
//! a healthy store — a replica in rotation that no cluster could ever dial.
//!
//! `#[ignore]` because readiness is only reached through the store, and the
//! workspace's ordinary run has no etcd. Start one and name it:
//!
//! ```text
//! MEISTER_TEST_ETCD=http://127.0.0.1:23700 \
//!   cargo test -p meister-cloud-controller --test session_port -- --ignored
//! ```

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const BIN: &str = env!("CARGO_BIN_EXE_meister-cloud-controller");

fn etcd() -> String {
    std::env::var("MEISTER_TEST_ETCD").unwrap_or_else(|_| "http://127.0.0.1:23700".to_string())
}

/// A port nobody holds right now. Racy in principle, and harmless here: the
/// worst case is a REST bind that fails, which ends the process just as the
/// assertion below wants — and is then caught by the stderr check.
fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// Whether `/readyz` answers 200 right now.
fn ready(port: u16) -> bool {
    let Ok(mut stream) = TcpStream::connect(("127.0.0.1", port)) else {
        return false;
    };
    let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
    if stream
        .write_all(b"GET /readyz HTTP/1.0\r\nHost: localhost\r\n\r\n")
        .is_err()
    {
        return false;
    }
    let mut answer = String::new();
    let _ = stream.read_to_string(&mut answer);
    answer.starts_with("HTTP/1.1 200") || answer.starts_with("HTTP/1.0 200")
}

#[test]
#[ignore = "needs an etcd; see the module note"]
fn a_session_port_it_cannot_bind_is_not_a_ready_replica() {
    // Somebody else's, for the whole test.
    let taken = TcpListener::bind("127.0.0.1:0").unwrap();
    let session = taken.local_addr().unwrap();
    let api = free_port();

    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("cloud.toml");
    std::fs::write(
        &config,
        format!(
            "cloud_name = \"session-port\"\n\
             listen_api = \"127.0.0.1:{api}\"\n\
             listen_session = \"{session}\"\n\
             etcd_endpoints = \"{}\"\n\
             etcd_prefix = \"/session-port-test/{}\"\n",
            etcd(),
            std::process::id()
        ),
    )
    .unwrap();

    let mut child = Command::new(BIN)
        .arg("--config")
        .arg(&config)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("the controller binary was just built");

    // Long enough for the etcd dial and a REST bind many times over. What is
    // being watched for is either end: the process giving up, or the replica
    // calling itself ready while its session port belongs to somebody else.
    let deadline = Instant::now() + Duration::from_secs(20);
    let mut said_ready = false;
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break Some(status);
        }
        if ready(api) {
            said_ready = true;
            break None;
        }
        if Instant::now() >= deadline {
            break None;
        }
        std::thread::sleep(Duration::from_millis(100));
    };
    if status.is_none() {
        let _ = child.kill();
    }
    let output = child.wait_with_output().unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        !said_ready,
        "the replica answered /readyz 200 while its session port was never bound:\n{stderr}"
    );
    let status = status.expect("the process gave up rather than serving on without sessions");
    assert!(!status.success(), "and it said so with its exit code");
    assert!(
        stderr.contains("listen_session") && stderr.contains(&session.to_string()),
        "the sentence names the key and the address: {stderr}"
    );
    drop(taken);
}
