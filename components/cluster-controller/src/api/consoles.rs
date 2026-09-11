// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! The console edge: the upgrade, the wait for the agent to open one, and
//! the pump that carries bytes both ways. Moved out of `api.rs` unchanged.

use super::*;

/// Take a VM's serial line, for a client that reached THIS replica.
///
/// Two callers and the same route: a sibling replica forwarding a console it
/// cannot serve, and anybody talking to this tier directly. Both get the same
/// answer, which is the point — a forward is not a special case, it is this
/// route being used by a process instead of a person.
///
/// Only nodes this replica holds. A replica that does not hold the node
/// refuses rather than forwarding again: a cluster's replicas all see the
/// same `session_endpoint`, so a second hop could only ever be a mistake, and
/// a mistake that bounces a live stream between two processes.
pub(super) async fn vm_console(
    State(st): State<ApiState>,
    Path(name): Path<String>,
    req: axum::extract::Request,
) -> Result<axum::response::Response, ApiError> {
    let vm: Vm = st.store.get(&name).await?;
    let Some(node) = vm.spec.node_name.clone() else {
        return Err(invalid(format!(
            "vm {name} is not placed on a node yet, so there is no console to hold"
        )));
    };
    if !st.registry.connected().contains(&node) {
        return Err(ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "Unavailable",
            format!("this replica does not hold node {node}'s session"),
        ));
    }

    let (mut parts, body) = req.into_parts();
    drop(body);
    // The same handshake the cloud answers, out of the same module: a client
    // that asks for `Upgrade: websocket` gets a real one, and a CLI that asks
    // for the raw upgrade gets what it always got. This tier had neither and
    // answered every client with the raw form (fremdsicht 7), so a break-glass
    // session from anything that speaks WebSocket threw the connection away.
    //
    // What is still only the cloud's is the TICKET, and it stays that way:
    // this tier keeps no directory, so it has nobody to mint one for.
    let websocket = controller_api::websocket::handshake(&parts.headers);
    let Some(on_upgrade) = parts.extensions.remove::<hyper::upgrade::OnUpgrade>() else {
        return Err(invalid(
            "a console is an upgraded connection; send Connection: upgrade",
        ));
    };

    let session_id = uuid::Uuid::new_v4().to_string();
    let mut events = st.registry.consoles.expect_local(&session_id);
    let asked = st
        .registry
        .send_to(
            &node,
            proto::ControllerMessage {
                kind: Some(proto::controller_message::Kind::ConsoleOpen(
                    proto::ConsoleOpen {
                        session_id: session_id.clone(),
                        vm_id: vm.metadata.uid.clone(),
                    },
                )),
            },
        )
        .await;
    if !asked {
        st.registry.consoles.forget_local(&session_id);
        return Err(ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "Unavailable",
            format!("node {node} has no active session"),
        ));
    }

    // Answered before the upgrade, for the reason the cloud edge has: after a
    // 101 there is no status code left for a refusal to travel on.
    match tokio::time::timeout(CONSOLE_OPEN_TIMEOUT, events.recv()).await {
        Ok(Some(crate::session::LocalConsoleEvent::Opened(Ok(())))) => {}
        Ok(Some(crate::session::LocalConsoleEvent::Opened(Err(why))))
        | Ok(Some(crate::session::LocalConsoleEvent::Closed(why))) => {
            st.registry.consoles.forget_local(&session_id);
            return Err(conflict(why));
        }
        Ok(Some(crate::session::LocalConsoleEvent::Data(_))) | Ok(None) => {
            st.registry.consoles.forget_local(&session_id);
            return Err(ApiError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "Unavailable",
                "the console ended before it began",
            ));
        }
        Err(_) => {
            st.registry.consoles.forget_local(&session_id);
            return Err(ApiError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "Unavailable",
                format!(
                    "node {node} did not answer about this console within {}s",
                    CONSOLE_OPEN_TIMEOUT.as_secs()
                ),
            ));
        }
    }

    let registry = st.registry.clone();
    let framed = websocket.is_some();
    tokio::spawn(async move {
        if let Ok(upgraded) = on_upgrade.await {
            let io = hyper_util::rt::TokioIo::new(upgraded);
            // The framing is an ADAPTER and ends here, exactly as at the cloud:
            // below this line the pump speaks raw bytes and does not know
            // which sort of client it has.
            let stream: Box<dyn Duplex> = match framed {
                true => Box::new(controller_api::websocket::adapt(io)),
                false => Box::new(io),
            };
            console_pump(stream, events, &registry, &node, &session_id).await;
        }
        registry.consoles.forget_local(&session_id);
        let _ = registry
            .send_to(
                &node,
                proto::ControllerMessage {
                    kind: Some(proto::controller_message::Kind::ConsoleClose(
                        proto::ConsoleClose {
                            session_id,
                            reason: "the client's console ended".to_string(),
                        },
                    )),
                },
            )
            .await;
    });

    Ok(switching(websocket))
}

/// A stream both sorts of client end up behind.
///
/// A trait object rather than two calls to a generic `console_pump`, because
/// the two arms would otherwise be two copies of the same spawn.
pub(super) trait Duplex:
    tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send
{
}

impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send> Duplex for T {}

/// The 101 that opens the line, in whichever dialect was asked for.
///
/// A WebSocket client that got `Upgrade: meister-console` and no
/// `Sec-WebSocket-Accept` threw the connection away without a word — the
/// cloud's own bug before fremdsicht 6, and this tier's until now.
pub(super) fn switching(websocket: Option<String>) -> axum::response::Response {
    let response = axum::response::Response::builder()
        .status(StatusCode::SWITCHING_PROTOCOLS)
        .header(axum::http::header::CONNECTION, "upgrade");
    match websocket {
        Some(accept) => response
            .header(axum::http::header::UPGRADE, "websocket")
            .header("sec-websocket-accept", accept),
        None => response.header(axum::http::header::UPGRADE, "meister-console"),
    }
    .body(axum::body::Body::empty())
    .expect("a fixed response")
}

/// How long to wait for the node to say whether the line was given.
pub(super) const CONSOLE_OPEN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(8);

/// Both directions of one console session at this tier.
pub(super) async fn console_pump<S>(
    stream: S,
    mut events: tokio::sync::mpsc::Receiver<crate::session::LocalConsoleEvent>,
    registry: &crate::session::SessionRegistry,
    node: &str,
    session_id: &str,
) where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let (mut from_client, mut to_client) = tokio::io::split(stream);
    let mut buf = vec![0u8; 4096];
    loop {
        tokio::select! {
            event = events.recv() => match event {
                Some(crate::session::LocalConsoleEvent::Data(bytes)) => {
                    if to_client.write_all(&bytes).await.is_err() {
                        break;
                    }
                }
                Some(crate::session::LocalConsoleEvent::Closed(_)) | None => break,
                Some(crate::session::LocalConsoleEvent::Opened(_)) => {}
            },
            read = from_client.read(&mut buf) => match read {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    let sent = registry
                        .send_to(
                            node,
                            proto::ControllerMessage {
                                kind: Some(proto::controller_message::Kind::ConsoleInput(
                                    proto::ConsoleData {
                                        session_id: session_id.to_string(),
                                        data: buf[..n].to_vec(),
                                    },
                                )),
                            },
                        )
                        .await;
                    if !sent {
                        break;
                    }
                }
            },
        }
    }
}
