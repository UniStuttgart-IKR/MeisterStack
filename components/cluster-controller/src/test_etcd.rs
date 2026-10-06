// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! The etcd this crate's `#[ignore]`d store tests talk to. Start one and name it:
//!
//! ```text
//! etcd --data-dir /tmp/ms-test-etcd \
//!   --listen-client-urls http://127.0.0.1:23700 \
//!   --advertise-client-urls http://127.0.0.1:23700 \
//!   --listen-peer-urls http://127.0.0.1:23701 \
//!   --initial-advertise-peer-urls http://127.0.0.1:23701 \
//!   --initial-cluster default=http://127.0.0.1:23701
//!
//! MEISTER_TEST_ETCD=http://127.0.0.1:23700 \
//!   cargo test -p meister-cluster-controller -- --ignored
//! ```

use controller_api::EtcdStore;

/// Where the test etcd listens: `MEISTER_TEST_ETCD`, or the address the note above gives it.
fn endpoint() -> String {
    std::env::var("MEISTER_TEST_ETCD").unwrap_or_else(|_| "http://127.0.0.1:23700".to_string())
}

/// A key prefix of its own under `area`: no two runs share a key, and one left behind names
/// the tests that wrote it.
pub(crate) fn fresh_prefix(area: &str) -> String {
    format!("/{area}/{}", uuid::Uuid::new_v4())
}

/// A connection to the test etcd under `prefix`. Two under one prefix are two replicas over
/// one store.
pub(crate) async fn connect(prefix: &str) -> EtcdStore {
    EtcdStore::connect(&[endpoint()], prefix)
        .await
        .expect("an etcd to talk to; see crate::test_etcd")
}

/// A store under a fresh prefix of the test etcd.
pub(crate) async fn fresh_store(area: &str) -> EtcdStore {
    connect(&fresh_prefix(area)).await
}
