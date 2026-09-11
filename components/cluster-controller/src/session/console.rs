// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! The console relay: one tcp connection at the cluster's edge, one node
//! at the far end, and the frames between them.
//!
//! The relay holds the routes (session id -> node) and the two directions a
//! frame can travel; the `on_console_*` below are the arms of the pump that
//! feed it. Verbatim out of `session.rs`.

use super::*;

/// Where a console session's frames go, in both directions.
///
/// This tier reads none of them. It knows two things: which node serves a
/// given `session_id`, and where "up" currently is — and both are facts about
/// connections rather than about consoles, which is why they live beside the
/// session map rather than in a console module.
#[derive(Default)]
pub struct ConsoleRelay {
    /// The cloud session's sender, while there is one. `None` between
    /// connections, and a frame that arrives then is dropped rather than
    /// queued: the client at the other end is gone with the session, and a
    /// queue would only deliver its output to whoever reconnects next.
    upward: Mutex<Option<mpsc::Sender<ClusterMessage>>>,
    /// Which node serves which console session. A relay has to know, because
    /// input arrives with a session_id and nothing else.
    routes: Mutex<HashMap<String, String>>,
    /// Sessions this replica is FORWARDING to a sibling instead of serving:
    /// the write half of that socket, for the keystrokes travelling down.
    ///
    /// A session is in exactly one of these two maps. `routes` is "a node of
    /// mine has it", this is "a sibling of mine has it", and which one it is
    /// was decided once, when the session was opened.
    forwards: Mutex<HashMap<String, Arc<tokio::sync::Mutex<tokio::net::tcp::OwnedWriteHalf>>>>,
    /// Sessions a REST handler on THIS replica is serving: a client that
    /// reached this tier directly, or a sibling forwarding one to us.
    ///
    /// The third and last place a session can be. A frame from a node is
    /// offered here first and goes up the cloud session only if nobody local
    /// wants it — which is what makes a forwarded console come out at the
    /// sibling that asked rather than at the cloud twice.
    local: Mutex<HashMap<String, mpsc::Sender<LocalConsoleEvent>>>,
}

/// What a console handler on this replica is waiting to hear from a node.
#[derive(Debug)]
pub enum LocalConsoleEvent {
    Opened(Result<(), String>),
    Data(Vec<u8>),
    Closed(String),
}

impl ConsoleRelay {
    /// The cloud session is up; frames may travel. Replacing an existing
    /// sender is the normal case on a re-home — the old one is dead.
    pub fn cloud_connected(&self, tx: mpsc::Sender<ClusterMessage>) {
        *self.upward.lock().unwrap() = Some(tx);
    }

    /// The cloud session ended. Every route with it: the sessions those
    /// frames belonged to are over, and a node still holding a line learns so
    /// when its own close arrives or when this tier tells it.
    pub fn cloud_gone(&self) -> Vec<(String, String)> {
        *self.upward.lock().unwrap() = None;
        self.routes.lock().unwrap().drain().collect()
    }

    /// Start serving one session from this replica's own REST edge.
    pub fn expect_local(&self, session_id: &str) -> mpsc::Receiver<LocalConsoleEvent> {
        let (tx, rx) = mpsc::channel(64);
        self.local
            .lock()
            .unwrap()
            .insert(session_id.to_string(), tx);
        rx
    }

    pub fn forget_local(&self, session_id: &str) {
        self.local.lock().unwrap().remove(session_id);
    }

    /// Offer a node's frame to a local handler. `false` when none wants it,
    /// and the caller then sends it up the cloud session.
    pub async fn to_local(&self, session_id: &str, event: LocalConsoleEvent) -> bool {
        let tx = self.local.lock().unwrap().get(session_id).cloned();
        match tx {
            Some(tx) => tx.send(event).await.is_ok(),
            None => false,
        }
    }

    pub fn route(&self, session_id: &str, node_id: &str) {
        self.routes
            .lock()
            .unwrap()
            .insert(session_id.to_string(), node_id.to_string());
    }

    pub fn node_for(&self, session_id: &str) -> Option<String> {
        self.routes.lock().unwrap().get(session_id).cloned()
    }

    pub fn forget(&self, session_id: &str) -> Option<String> {
        self.forwards.lock().unwrap().remove(session_id);
        self.routes.lock().unwrap().remove(session_id)
    }

    /// Take over a socket to the sibling that holds the node, and pump its
    /// side of the session upwards for as long as it lasts.
    ///
    /// The reader task IS the session's life: when the sibling closes, it
    /// tells the cloud and forgets the forward, so nothing has to poll for a
    /// connection that has gone.
    pub async fn forwarded(self: &Arc<Self>, session_id: &str, stream: tokio::net::TcpStream) {
        let (mut reader, writer) = stream.into_split();
        self.forwards.lock().unwrap().insert(
            session_id.to_string(),
            Arc::new(tokio::sync::Mutex::new(writer)),
        );

        let relay = self.clone();
        let session_id = session_id.to_string();
        tokio::spawn(async move {
            use tokio::io::AsyncReadExt;
            let mut buf = vec![0u8; 8192];
            loop {
                let read = reader.read(&mut buf).await;
                let Ok(n) = read else { break };
                if n == 0 {
                    break;
                }
                let sent = relay
                    .upward(ClusterMessage {
                        kind: Some(proto::cluster_message::Kind::ConsoleOutput(
                            proto::ConsoleData {
                                session_id: session_id.clone(),
                                data: buf[..n].to_vec(),
                            },
                        )),
                    })
                    .await;
                if !sent {
                    break;
                }
            }
            relay.forwards.lock().unwrap().remove(&session_id);
            let _ = relay
                .upward(ClusterMessage {
                    kind: Some(proto::cluster_message::Kind::ConsoleClose(
                        proto::ConsoleClose {
                            session_id,
                            reason: "the forwarded console ended".to_string(),
                        },
                    )),
                })
                .await;
        });
    }

    /// Keystrokes for a session this replica is forwarding. `false` when it
    /// is not one — the caller then tries its own nodes.
    pub async fn write_forward(&self, session_id: &str, data: &[u8]) -> Option<bool> {
        use tokio::io::AsyncWriteExt;
        // The handle is taken out under the plain lock and the WRITE happens
        // under the async one: a std mutex held across an await would make
        // this future un-Send, and an async mutex on the map would make
        // `forget` — which is sync, and called from a Drop-shaped path —
        // impossible.
        let writer = self.forwards.lock().unwrap().get(session_id).cloned()?;
        let mut writer = writer.lock().await;
        Some(writer.write_all(data).await.is_ok())
    }

    /// Hand one frame upwards. `false` when there is nowhere to hand it —
    /// the caller stops rather than retrying, because a console frame is only
    /// worth anything to the client that asked for it.
    pub async fn upward(&self, msg: ClusterMessage) -> bool {
        let tx = self.upward.lock().unwrap().clone();
        match tx {
            Some(tx) => tx.send(msg).await.is_ok(),
            None => false,
        }
    }
}

/// The console, on its way up. This tier reads none of it — it finds where
/// "up" is and hands the frame over unopened, which is the same rule
/// `vm logs` follows for the node's document.
pub(super) async fn on_console_opened(session: &Session, opened: proto::ConsoleOpened) {
    let outcome = match opened.error.is_empty() {
        true => Ok(()),
        false => Err(opened.error.clone()),
    };
    // A handler on this replica first: a console opened for a sibling's
    // forward, or for somebody talking to this tier directly, must come out
    // here and not at the cloud.
    if session
        .registry
        .consoles
        .to_local(&opened.session_id, LocalConsoleEvent::Opened(outcome))
        .await
    {
        return;
    }
    let ended = opened.error.is_empty();
    if !session
        .registry
        .consoles
        .upward(ClusterMessage {
            kind: Some(proto::cluster_message::Kind::ConsoleOpened(opened.clone())),
        })
        .await
        || !ended
    {
        // Refused, or nowhere to send it: either way this session_id is over
        // and the route goes with it.
        session.registry.consoles.forget(&opened.session_id);
    }
}

/// Console bytes, upward. Nobody left to hand them to means the node is told
/// to give the line back.
pub(super) async fn on_console_output(
    session: &Session,
    node_id: Option<&str>,
    data: proto::ConsoleData,
) {
    if session
        .registry
        .consoles
        .to_local(&data.session_id, LocalConsoleEvent::Data(data.data.clone()))
        .await
    {
        return;
    }
    if !session
        .registry
        .consoles
        .upward(ClusterMessage {
            kind: Some(proto::cluster_message::Kind::ConsoleOutput(data.clone())),
        })
        .await
    {
        // The cloud session is gone. Tell the node to give the line back
        // rather than letting it hold one for a client that cannot be
        // reached.
        if let Some(node) = session.registry.consoles.forget(&data.session_id)
            && let Some(id) = node_id
            && node == id
        {
            let _ = session
                .registry
                .send_to(
                    &node,
                    ControllerMessage {
                        kind: Some(proto::controller_message::Kind::ConsoleClose(
                            proto::ConsoleClose {
                                session_id: data.session_id.clone(),
                                reason: "the cloud session ended".to_string(),
                            },
                        )),
                    },
                )
                .await;
        }
    }
}

/// The line ended at the node. Whoever is holding it hears so, once.
pub(super) async fn on_console_close(session: &Session, close: proto::ConsoleClose) {
    if session
        .registry
        .consoles
        .to_local(
            &close.session_id,
            LocalConsoleEvent::Closed(close.reason.clone()),
        )
        .await
    {
        session.registry.consoles.forget_local(&close.session_id);
        return;
    }
    session.registry.consoles.forget(&close.session_id);
    let _ = session
        .registry
        .consoles
        .upward(ClusterMessage {
            kind: Some(proto::cluster_message::Kind::ConsoleClose(close)),
        })
        .await;
}
