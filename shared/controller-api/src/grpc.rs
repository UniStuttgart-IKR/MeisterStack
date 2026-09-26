// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! TLS setup, authentication and supervision for gRPC session listeners.
//!
//! Tonic supplies peer certificates to the shared authentication chain. Session
//! identity checks bind a machine certificate to the peer named by Hello.

use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result};
use tonic::transport::{Certificate, ClientTlsConfig, Identity as TlsIdentity, ServerTlsConfig};
use tracing::info;

use crate::auth::{AuthChain, AuthRequest, Authenticated, GROUP_ADMINS};

/// Build session-server TLS, or return None for an unconfigured plaintext port.
/// Client certificates are optional at the handshake so the authentication chain
/// can report missing credentials through the session protocol.
pub fn server_tls(
    cert: Option<&Path>,
    key: Option<&Path>,
    client_ca: Option<&Path>,
    base: Option<&Path>,
) -> Result<Option<ServerTlsConfig>> {
    let (Some(cert), Some(key)) = (cert, key) else {
        if cert.is_some() || key.is_some() {
            anyhow::bail!("tls_cert and tls_key go together; set both or neither");
        }
        // Reject a client CA without server TLS instead of silently serving plaintext
        // under a configuration that appears to require certificate authentication.
        if client_ca.is_some() {
            anyhow::bail!(
                "client_ca is set but tls_cert/tls_key are not; a port without an identity \
                 cannot ask for client certificates. Set both, or remove client_ca"
            );
        }
        return Ok(None);
    };
    let cert = pki::pem::resolve(base, cert);
    let key = pki::pem::resolve(base, key);
    let cert_pem = std::fs::read(&cert).with_context(|| format!("reading {}", cert.display()))?;
    // The permission check, and the reason the key is read twice: one path
    // through `pki` refuses a key anybody can read.
    let _ = pki::load_private_key(&key)?;
    let key_pem = std::fs::read(&key).with_context(|| format!("reading {}", key.display()))?;

    let mut config = ServerTlsConfig::new().identity(TlsIdentity::from_pem(cert_pem, key_pem));
    if let Some(ca) = client_ca {
        let ca = pki::pem::resolve(base, ca);
        let ca_pem = std::fs::read(&ca).with_context(|| format!("reading {}", ca.display()))?;
        config = config
            .client_ca_root(Certificate::from_pem(ca_pem))
            .client_auth_optional(true);
        info!(ca = %ca.display(), "session port asks for client certificates");
    }
    info!(cert = %cert.display(), "session port terminates tls");
    Ok(Some(config))
}

/// Resolve client TLS paths relative to the configuration file, then use the
/// shared proto builder also used by agents.
pub fn client_tls(
    ca: Option<&Path>,
    identity: Option<(&Path, &Path)>,
    base: Option<&Path>,
) -> Result<Option<ClientTlsConfig>> {
    let Some(ca) = ca else {
        if identity.is_some() {
            anyhow::bail!(
                "a client certificate was configured without a CA to verify the server with; \
                 name the CA too"
            );
        }
        return Ok(None);
    };
    let ca = pki::pem::resolve(base, ca);
    let identity =
        identity.map(|(cert, key)| (pki::pem::resolve(base, cert), pki::pem::resolve(base, key)));
    let identity = identity.as_ref().map(|(c, k)| (c.as_path(), k.as_path()));
    Ok(Some(proto::client_tls(&ca, identity)?))
}

/// Who opened this session, by the same chain the REST edge uses.
pub fn authenticate_session<T>(
    chain: &AuthChain,
    request: &tonic::Request<T>,
) -> Result<Authenticated, tonic::Status> {
    let peer_certs = request
        .peer_certs()
        .map(|certs| pki::tls::der_chain(certs.as_slice()))
        .unwrap_or_default();
    chain
        .authenticate(&AuthRequest {
            peer_certs,
            authorization: bearer_of(request),
        })
        .map_err(|rejected| tonic::Status::unauthenticated(rejected.to_string()))
}

/// gRPC metadata carries the same header name as HTTP does. Nothing dials
/// these ports with a bearer token today; it is here so that the chain means
/// the same thing at both edges rather than quietly meaning less at one.
fn bearer_of<T>(request: &tonic::Request<T>) -> Option<String> {
    request
        .metadata()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
}

/// Require a machine credential authorized for the Hello peer kind and
/// name. User REST credentials cannot open sessions. An empty authentication
/// chain retains anonymous mode.
pub fn check_session_identity(
    who: &Authenticated,
    kind: &str,
    peer: &str,
) -> Result<(), tonic::Status> {
    let Authenticated::As(identity) = who else {
        return Ok(());
    };
    if !identity.is_system() && !identity.has_group(GROUP_ADMINS) {
        return Err(tonic::Status::permission_denied(format!(
            "{} is not a system identity; sessions are for nodes and controllers",
            identity.name
        )));
    }
    if !identity.may_speak_for(kind, peer) {
        return Err(tonic::Status::permission_denied(format!(
            "the certificate names {}, but the hello says {kind} {peer:?}",
            identity.name
        )));
    }
    Ok(())
}

/// The chain a session server was built with, for the handler to reach.
pub type SessionAuth = Arc<AuthChain>;

/// Bind the session listener before reporting startup success. A bind
/// failure must stop startup rather than leave a healthy REST-only shell.
/// Use the transport defaults: TCP_NODELAY enabled, no TCP keepalive.
pub fn bind_sessions(listen: &str) -> Result<tonic::transport::server::TcpIncoming> {
    let addr: std::net::SocketAddr = listen
        .parse()
        .with_context(|| format!("listen_session {listen:?} is not an address"))?;
    let incoming = tonic::transport::server::TcpIncoming::bind(addr)
        .with_context(|| format!("listen_session: cannot bind {addr}"))?;
    Ok(incoming.with_nodelay(Some(true)))
}

/// A running session server, as the task it runs in.
pub type SessionServer = tokio::task::JoinHandle<std::result::Result<(), tonic::transport::Error>>;

/// Serve REST alongside the session listener and exit if that server
/// ends. None selects an intentional REST-only deployment. Individual
/// peer reconnects do not imply listener failure.
pub async fn serve_beside(
    rest: impl std::future::Future<Output = Result<()>>,
    sessions: Option<SessionServer>,
) -> Result<()> {
    let Some(sessions) = sessions else {
        return rest.await;
    };
    tokio::select! {
        served = rest => served,
        ended = sessions => Err(match ended {
            Ok(Ok(())) => anyhow::anyhow!("the session server stopped"),
            Ok(Err(e)) => anyhow::Error::new(e).context("the session server stopped"),
            Err(e) => anyhow::Error::new(e).context("the session server's task ended"),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::{GROUP_MEMBERS, GROUP_NODES, Identity};

    fn as_(name: &str, group: &str) -> Authenticated {
        Authenticated::As(Identity::new(name, vec![group.to_string()]))
    }

    #[test]
    fn anonymous_sessions_are_unchanged() {
        assert!(check_session_identity(&Authenticated::Anonymous, "node", "manacor").is_ok());
    }

    /// A user's certificate is perfectly good for the REST API and is not a
    /// node.
    #[test]
    fn a_user_certificate_does_not_open_a_session() {
        let err =
            check_session_identity(&as_("alice", GROUP_MEMBERS), "node", "manacor").unwrap_err();
        assert_eq!(err.code(), tonic::Code::PermissionDenied);
        assert!(err.message().contains("not a system identity"), "{err}");
    }

    #[test]
    fn a_node_certificate_may_only_report_as_its_own_node() {
        assert!(
            check_session_identity(&as_("system:node:manacor", GROUP_NODES), "node", "manacor")
                .is_ok()
        );
        let err = check_session_identity(
            &as_("system:node:manacor", GROUP_NODES),
            "node",
            "manacor-b",
        )
        .unwrap_err();
        assert!(err.message().contains("manacor"), "{err}");
    }

    #[test]
    fn half_a_session_tls_config_is_refused() {
        let some = Path::new("x.pem");
        assert!(server_tls(None, None, None, None).unwrap().is_none());
        assert!(server_tls(Some(some), None, None, None).is_err());
        // A client certificate with nothing to check the server against would
        // authenticate us to whoever answered.
        assert!(client_tls(None, Some((some, some)), None).is_err());
        assert!(client_tls(None, None, None).unwrap().is_none());
    }

    /// A session port somebody else holds is a start-up error that names the
    /// key and the address — not a line from a task nobody awaits.
    #[tokio::test]
    async fn a_session_port_that_is_taken_is_refused_at_start_up() {
        let taken = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = taken.local_addr().unwrap().to_string();
        let err = bind_sessions(&addr).expect_err("somebody else holds it");
        let said = format!("{err:#}");
        assert!(
            said.contains("listen_session") && said.contains(&addr),
            "{said}"
        );
        drop(taken);
        bind_sessions(&addr).expect("and once it is free, it is ours");
    }

    /// The REST half is served for as long as the session server runs, and
    /// no longer: a session server that ends — with an error or without one
    /// — ends the replica, with the reason.
    #[tokio::test]
    async fn a_session_server_that_ends_ends_the_replica() {
        let failed: SessionServer = tokio::spawn(async {
            // What a stopped tonic server hands back; any transport error
            // will do, and a refused connect is the cheapest to make.
            tonic::transport::Endpoint::from_static("http://127.0.0.1:1")
                .connect()
                .await
                .map(|_| ())
        });
        let rest = std::future::pending::<Result<()>>();
        let err = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            serve_beside(rest, Some(failed)),
        )
        .await
        .expect("the replica did not go on serving")
        .expect_err("and it says why");
        assert!(
            format!("{err:#}").contains("session server stopped"),
            "{err:#}"
        );

        let quiet: SessionServer = tokio::spawn(async { Ok(()) });
        let err = serve_beside(std::future::pending::<Result<()>>(), Some(quiet))
            .await
            .expect_err("a server that returns is a server that stopped");
        assert!(format!("{err}").contains("session server stopped"), "{err}");

        // A REST-only replica is served exactly as before.
        serve_beside(async { Ok(()) }, None)
            .await
            .expect("no session port, nothing to supervise");
    }
}
