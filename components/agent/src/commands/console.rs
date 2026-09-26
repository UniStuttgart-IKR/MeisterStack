// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Controller commands for acquiring, writing and releasing guest serial sessions.

use super::*;

impl Agent {
    /// Open a serial session and forward its output. Always answer with
    /// `ConsoleOpened`, carrying the attach error when the session is refused.
    pub(crate) async fn console_open(
        &self,
        open: proto::ConsoleOpen,
        tx: tokio::sync::mpsc::Sender<AgentMessage>,
    ) {
        let session_id = open.session_id.clone();
        let refuse = |error: String| AgentMessage {
            kind: Some(agent_message::Kind::ConsoleOpened(proto::ConsoleOpened {
                session_id: session_id.clone(),
                error,
            })),
        };

        let id: VmId = match open.vm_id.parse() {
            Ok(id) => id,
            Err(e) => {
                let _ = tx.send(refuse(format!("invalid vm id: {e}"))).await;
                return;
            }
        };
        let held = match self.reconciler.consoles.attach(&id) {
            None => {
                let _ = tx
                    .send(refuse(format!(
                        "vm {id} has no console line right now; it is not running, or its \
                         serial line has not been picked up yet"
                    )))
                    .await;
                return;
            }
            Some(Err(e)) => {
                let _ = tx.send(refuse(format!("{e:#}"))).await;
                return;
            }
            Some(Ok(held)) => held,
        };
        if tx.send(refuse(String::new())).await.is_err() {
            return;
        }

        // The output task owns the holder and releases it whenever the task ends.
        let writer = held.writer();
        let mut mine = held;
        let up = session_id.clone();
        let pump = tokio::spawn(async move {
            loop {
                let Some(bytes) = mine.recv().await else {
                    break;
                };
                let frame = AgentMessage {
                    kind: Some(agent_message::Kind::ConsoleOutput(proto::ConsoleData {
                        session_id: up.clone(),
                        data: bytes,
                    })),
                };
                if tx.send(frame).await.is_err() {
                    break;
                }
            }
            let _ = tx
                .send(AgentMessage {
                    kind: Some(agent_message::Kind::ConsoleClose(proto::ConsoleClose {
                        session_id: up,
                        reason: "the guest's line ended".to_string(),
                    })),
                })
                .await;
        });

        info!(session = %session_id, vm_id = %id, "console session opened");
        self.console_sessions
            .lock()
            .expect("console sessions")
            .insert(session_id, ConsoleSession { writer, pump });
    }

    /// Forward console input. Close the session if writing fails, including queue overflow.
    pub(crate) async fn console_input(&self, data: proto::ConsoleData) {
        let writer = {
            let sessions = self.console_sessions.lock().expect("console sessions");
            sessions.get(&data.session_id).map(|s| s.writer.clone())
        };
        let Some(writer) = writer else { return };
        if let Err(e) = writer.write(&data.data).await {
            warn!(session = %data.session_id, error = format!("{e:#}"), "console write failed");
            self.console_close(&data.session_id);
        }
    }

    /// Give the line back. Idempotent: a close for a session that is already
    /// gone is the normal race between both ends deciding to stop.
    pub(crate) fn console_close(&self, session_id: &str) {
        let session = self
            .console_sessions
            .lock()
            .expect("console sessions")
            .remove(session_id);
        if let Some(session) = session {
            session.pump.abort();
            info!(session = %session_id, "console session closed");
        }
    }
}
