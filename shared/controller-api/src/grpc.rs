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

/// Server TLS for a session port. `None` = plain gRPC, as today.
///
/// Client authentication is optional here for the same reason it is optional
/// at the REST edge: a peer with no certificate has to get far enough to be
/// told so in words. The chain is what refuses it, and a refusal that names
/// the reason is worth more than a handshake that resets.
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
        // A client_ca without a server identity is an operator who believes
        // this port demands client certificates. Returning Ok(None) here would
        // hand them plain gRPC and say nothing — the REST edge refuses the same
        // combination, and a session port has more to lose by staying quiet.
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

/// Client TLS for dialling a session port: whom to trust, and who we are.
///
/// The config paths are this crate's business — they are relative to the file
/// that named them — and building the thing out of PEM is `proto`'s, because
/// the agent tier dials with a certificate too and does not depend on this
/// crate. One builder, three tiers.
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

/// Once the Hello has said which peer this is: may that certificate say so?
///
/// Two questions, and both of them are the point of putting certificates on
/// the sessions at all. A session is for the stack's own machinery, so a
/// user's certificate — valid, in the directory, perfectly good for the REST
/// API — must not open one. And a certificate that names a peer must name
/// THIS peer, or one node's key would let it report as any other, including
/// as the node whose VMs it wants to be told about.
///
/// Anonymous mode is anonymous mode: no chain, no check, exactly as before.
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

/// Take the session port NOW, at start-up, where a refusal is an exit code.
///
/// `Server::serve(addr)` binds inside its future, and both tiers spawned that
/// future and forgot it: a port somebody else held came back as one error
/// line from a task nobody awaited, while the REST half went on answering
/// `/readyz` 200 off a healthy store. A replica in rotation that no peer can
/// ever dial is the worst of the available answers, because nothing about it
/// looks wrong from the load balancer.
///
/// The accept options are the ones `serve` would have set with a default
/// builder (`TCP_NODELAY` on, no keepalive), so a session is exactly the
/// session it was.
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

/// Serve the REST API, and end the moment the session server ends.
///
/// The session port is not an optional extra on a replica configured to have
/// one: it is how every peer of this tier reaches it. So a server that stops
/// ends the process, with the reason, and whatever supervises the process
/// sees an exit rather than a replica that answers every probe and is dialled
/// by nobody. `None` is a REST-only replica (`listen_session` empty), which
/// is a real configuration and is served exactly as before.
///
/// What this is NOT is a readiness input for the streams themselves: a
/// session that drops and redials is ordinary, and `readiness` says why it
/// leaves those out. This is about the listener.
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
