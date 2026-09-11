// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! The guest's serial line, as the tier above borrows it: take it, type
//! into it, give it back.

use super::*;

impl Agent {
    /// Take a VM's serial line for the tier above, and start sending it up.
    ///
    /// Answered with `ConsoleOpened` either way — a refusal is an answer, and
    /// a client that got silence could not tell "busy" from "the stream is
    /// broken". The error text is the one `attach` wrote, because it is the
    /// one that names which of the two refusals this is.
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

        // The output pump OWNS the handle, so the line is released the moment
        // this task ends — whether it was aborted, the stream dropped, or the
        // guest's line closed. Nothing has to notice that a client went away.
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

    /// Keystrokes from the tier above.
    ///
    /// A write that fails ends the session rather than being reported: the
    /// only reasons it can fail are the guest being gone and the caller
    /// sending more than a burst, and neither is something the next keystroke
    /// would fix.
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
