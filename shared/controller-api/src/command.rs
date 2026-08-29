// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Sending one command down a session and waiting for its result.
//!
//! Both tiers hold a bidi session with the tier below them — the cluster with
//! its agents, the cloud with its clusters — and both let a reconcile pass
//! await an ack without owning the stream: the command carries a request_id,
//! the peer's CommandResult carries it back, and a oneshot registered under
//! that id is what joins the two. The proto messages differ; none of the
//! bookkeeping does, down to the three failure paths and which of them has to
//! take the entry back out of the map.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;

use anyhow::bail;
use tokio::sync::{mpsc, oneshot};
use tracing::warn;

/// What came back from the peer. `Rejected` is the peer's own answer and
/// therefore a fact about the VM; every other failure is a fact about the
/// session, and a session that broke says nothing about any VM.
///
/// `Acked` carries the peer's payload, which is empty for every command that
/// only changes something and says "done". One command asks a question
/// instead — the console fetch — and its answer comes back here rather than
/// through a second channel: the session is already the only direction that
/// works (the node dialled us), and `Pending` already matches a request to
/// the result that carries its id.
#[derive(Debug)]
pub enum Ack {
    Acked(Vec<u8>),
    Rejected(String),
}

/// Who the command is going to, as the error a person reads names them: an
/// `agent` one tier down, a `cluster` one tier up. The noun is the whole of
/// the difference between the two tiers' sentences.
pub struct Peer<'a> {
    pub kind: &'a str,
    pub name: &'a str,
}

/// The commands of one session registry that are still out, by request_id.
///
/// Owns the ack timeout as well, because a registry that could be asked to
/// wait a different length of time per call is a registry whose patience is
/// an accident of the call site rather than a property of the tier.
/// What one waiting caller is handed: the peer's payload, or the peer's own
/// refusal. Named because the map below is otherwise four nested generics
/// deep and says nothing at a glance.
type Answer = Result<Vec<u8>, String>;

pub struct Pending {
    waiting: Mutex<HashMap<String, oneshot::Sender<Answer>>>,
    timeout: Duration,
}

impl Pending {
    pub fn new(timeout: Duration) -> Self {
        Self {
            waiting: Mutex::default(),
            timeout,
        }
    }

    /// Put `build(request_id)` on the session and wait for the peer's result.
    ///
    /// The session channel is a PARAMETER and is deliberately not looked up in
    /// here: the caller has therefore already found it by the time anything is
    /// registered, so the "no session" path has nothing to clean up. The other
    /// order leaks one entry per attempt, and a level-triggered pass retries
    /// every tick for as long as a VM is bound to a peer that is gone — so the
    /// leak is unbounded, not a one-off. Nothing can beat the registration
    /// either way round: the result only ever comes back over the stream, and
    /// nothing is on the stream until the send below.
    pub async fn send<M>(
        &self,
        peer: Peer<'_>,
        tx: &mpsc::Sender<Result<M, tonic::Status>>,
        build: impl FnOnce(String) -> M,
    ) -> anyhow::Result<Ack> {
        let Peer { kind, name } = peer;
        let timeout = self.timeout;
        let request_id = uuid::Uuid::new_v4().to_string();
        let (ack_tx, ack_rx) = oneshot::channel();
        self.waiting
            .lock()
            .unwrap()
            .insert(request_id.clone(), ack_tx);

        // Bounded like the ack, and for the same reason. A peer that is alive
        // but stuck stops draining its stream; the buffer fills, and an
        // unbounded write would park the one reconcile task there — no
        // scheduling, no teardown, no heartbeat expiry, for every other peer
        // too. Send is cancel-safe, so a timeout leaves nothing half-written.
        match tokio::time::timeout(timeout, tx.send(Ok(build(request_id.clone())))).await {
            Ok(Ok(())) => {}
            Ok(Err(_)) => {
                self.forget(&request_id);
                bail!("session to {name} closed while sending");
            }
            Err(_) => {
                self.forget(&request_id);
                bail!("{kind} {name} would not take a command within {timeout:?}");
            }
        }

        match tokio::time::timeout(timeout, ack_rx).await {
            Ok(Ok(Ok(payload))) => Ok(Ack::Acked(payload)),
            Ok(Ok(Err(msg))) => Ok(Ack::Rejected(msg)),
            Ok(Err(_)) => bail!("session to {name} dropped before the result"),
            Err(_) => {
                self.forget(&request_id);
                bail!("{kind} {name} did not answer within {timeout:?}")
            }
        }
    }

    /// A CommandResult arrived: hand it to whoever is waiting for it.
    pub fn resolve(&self, request_id: &str, outcome: Answer) {
        if let Some(tx) = self.waiting.lock().unwrap().remove(request_id) {
            let _ = tx.send(outcome);
        } else {
            // Nobody is waiting any more: the caller's ack timeout fired
            // first and forgot the id, and the peer answered afterwards.
            warn!(request_id, "result for an unknown request");
        }
    }

    fn forget(&self, request_id: &str) {
        self.waiting.lock().unwrap().remove(request_id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TIMEOUT: Duration = Duration::from_secs(15);

    /// A message that is nothing but the id it was built with, which is all
    /// this module ever does to one.
    fn pending() -> Pending {
        Pending::new(TIMEOUT)
    }

    fn in_flight(p: &Pending) -> usize {
        p.waiting.lock().unwrap().len()
    }

    /// The happy path, and the shape of it: the command reaches the stream
    /// carrying the id the ack is later matched on, and the entry is gone
    /// once the answer has been handed over.
    #[tokio::test]
    async fn a_command_is_answered_by_the_result_that_carries_its_id() {
        let pending = std::sync::Arc::new(pending());
        let (tx, mut rx) = mpsc::channel::<Result<String, tonic::Status>>(1);
        let answering = pending.clone();
        tokio::spawn(async move {
            let id = rx.recv().await.unwrap().unwrap();
            answering.resolve(&id, Ok(Vec::new()));
        });
        let peer = Peer {
            kind: "agent",
            name: "manacor",
        };
        assert!(matches!(
            pending.send(peer, &tx, |id| id).await.unwrap(),
            Ack::Acked(p) if p.is_empty()
        ));
        assert_eq!(in_flight(&pending), 0);
    }

    /// The peer's own refusal is an answer, not a broken session: it comes
    /// back as `Rejected` and the caller decides what it means for the VM.
    #[tokio::test]
    async fn a_refusal_from_the_peer_is_an_answer() {
        let pending = std::sync::Arc::new(pending());
        let (tx, mut rx) = mpsc::channel::<Result<String, tonic::Status>>(1);
        let answering = pending.clone();
        tokio::spawn(async move {
            let id = rx.recv().await.unwrap().unwrap();
            answering.resolve(&id, Err("no such vm".into()));
        });
        let peer = Peer {
            kind: "cluster",
            name: "c1",
        };
        let answer = pending.send(peer, &tx, |id| id).await.unwrap();
        assert!(matches!(answer, Ack::Rejected(m) if m == "no such vm"));
        assert_eq!(in_flight(&pending), 0);
    }

    /// The leak this shape exists to prevent, in the two places it can start:
    /// a session that has closed under us, and one that never answers. A pass
    /// retries every tick for as long as a VM is bound to a peer that is
    /// gone, so an entry left behind per attempt grows without bound.
    #[tokio::test(start_paused = true)]
    async fn a_command_that_goes_nowhere_leaves_nothing_behind() {
        let pending = pending();
        let peer = || Peer {
            kind: "agent",
            name: "gone",
        };

        let (closed, rx) = mpsc::channel::<Result<String, tonic::Status>>(1);
        drop(rx);
        let err = pending.send(peer(), &closed, |id| id).await.unwrap_err();
        assert!(err.to_string().contains("closed while sending"), "{err}");
        assert_eq!(in_flight(&pending), 0);

        // A peer that takes the command and says nothing: the wait is bounded
        // and the entry goes with it.
        let (mute, _held) = mpsc::channel::<Result<String, tonic::Status>>(1);
        let err = pending.send(peer(), &mute, |id| id).await.unwrap_err();
        assert!(err.to_string().contains("did not answer"), "{err}");
        assert_eq!(in_flight(&pending), 0);
    }

    /// The noun in the sentence is the tier's, so an operator reading a log
    /// is told which kind of peer went quiet.
    #[tokio::test(start_paused = true)]
    async fn the_error_names_the_peer_the_way_its_tier_does() {
        let pending = pending();
        let (mute, _held) = mpsc::channel::<Result<String, tonic::Status>>(1);
        let err = pending
            .send(
                Peer {
                    kind: "cluster",
                    name: "c1",
                },
                &mute,
                |id| id,
            )
            .await
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            format!("cluster c1 did not answer within {TIMEOUT:?}")
        );
    }
}
