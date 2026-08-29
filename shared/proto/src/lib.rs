// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

// The generated oneof enums have variants of very different sizes — a
// Command carries a whole VmSpec, an Ack carries nothing. Boxing them is not
// ours to decide: this is prost's output, regenerated on every build.
#[allow(clippy::large_enum_variant)]
mod generated {
    tonic::include_proto!("meisterstack.v1");
}
pub use generated::*;

use anyhow::Context;
use std::path::Path;
use std::time::Duration;

use tonic::transport::{Certificate, Channel, ClientTlsConfig, Endpoint, Identity};

/// How long a session dial may spend getting a connection.
///
/// Both tiers dial down a preference order (HRW) and walk to the next entry
/// when one refuses. A refusal is instant; a blackholed endpoint — fenced
/// host, dropped SYN, a route that goes nowhere — says nothing at all, and
/// the kernel's own give-up is `tcp_syn_retries` deep: six retries, about
/// two minutes. For those two minutes the caller is stuck on a replica it
/// will never reach while the next one in its order sits there answering.
///
/// Three seconds is far above any real handshake on a lab network and far
/// below the point where failover stops being failover.
pub const DIAL_TIMEOUT: Duration = Duration::from_secs(3);

/// Open a plain channel to a session endpoint, bounded by `DIAL_TIMEOUT`.
///
/// Here rather than in each component because the two session loops are the
/// same loop one tier apart, and this is the one line of it that has nothing
/// to do with which messages travel over the result.
pub async fn dial(addr: &str) -> Result<Channel, tonic::transport::Error> {
    Endpoint::from_shared(addr.to_string())?
        .connect_timeout(DIAL_TIMEOUT)
        .connect()
        .await
}

/// The same dial with a credential, when there is one.
///
/// `None` is the plain dial above and the default: every session in this
/// stack ran that way for five milestones and the lab still does. It lives
/// here for the same reason `dial` does — all three tiers that dial out are
/// the same loop, and by M5 all three of them can carry a certificate.
pub async fn dial_tls(addr: &str, tls: Option<&ClientTlsConfig>) -> anyhow::Result<Channel> {
    let mut endpoint = Endpoint::from_shared(addr.to_string())?.connect_timeout(DIAL_TIMEOUT);
    if let Some(tls) = tls {
        endpoint = endpoint.tls_config(tls.clone())?;
    }
    Ok(endpoint.connect().await?)
}

/// Whom to trust on the other end, and who we are.
///
/// The CA is required and the identity is not: a peer that only verifies the
/// server still gets an encrypted session, and a peer with a certificate but
/// no CA to check the server against would authenticate itself to whoever
/// answered — which is why THAT combination is an error rather than a
/// half-configuration.
///
/// Reads PEM and nothing else. The permission check on the key is here
/// because this is the one function in this crate that opens a secret, and a
/// key the group can read is a key that has left the machine already —
/// same rule and same message as `pki::load_private_key`, which the tiers
/// that depend on `pki` go through instead.
pub fn client_tls(ca: &Path, identity: Option<(&Path, &Path)>) -> anyhow::Result<ClientTlsConfig> {
    // tonic's tls-ring path asks for the process-wide default provider and
    // panics without one. Idempotent, and the first gRPC handshake is a bad
    // place to find out it was never installed.
    let _ = rustls::crypto::ring::default_provider().install_default();

    let ca_pem =
        std::fs::read(ca).with_context(|| format!("reading the session CA {}", ca.display()))?;
    let mut config = ClientTlsConfig::new().ca_certificate(Certificate::from_pem(ca_pem));
    if let Some((cert, key)) = identity {
        check_key_permissions(key)?;
        let cert_pem =
            std::fs::read(cert).with_context(|| format!("reading {}", cert.display()))?;
        let key_pem = std::fs::read(key).with_context(|| format!("reading {}", key.display()))?;
        config = config.identity(Identity::from_pem(cert_pem, key_pem));
    }
    Ok(config)
}

#[cfg(unix)]
fn check_key_permissions(path: &Path) -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let meta = std::fs::metadata(path).with_context(|| format!("reading {}", path.display()))?;
    let mode = meta.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        anyhow::bail!(
            "permissions {:04o} on {} are too open; run: chmod 600 {}",
            mode,
            path.display(),
            path.display()
        );
    }
    Ok(())
}

#[cfg(not(unix))]
fn check_key_permissions(_path: &Path) -> anyhow::Result<()> {
    Ok(())
}
