// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Correlate session commands with replies by request ID.
//!
//! Each command registers a oneshot sender before transmission. Replies resolve
//! it; send failures and timeouts remove pending entries. The two session tiers
//! provide their own protobuf message types.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;

use anyhow::bail;
use tokio::sync::{mpsc, oneshot};
use tracing::warn;

/// Correlated peer response or session failure. Rejected carries a peer
/// answer; transport failure does not establish VM state. Acked payloads
/// include replies such as console data and migration endpoint information.
#[derive(Debug)]
pub enum Ack {
    Acked(Vec<u8>),
    Rejected(Refusal),
}

/// Who the command is going to, as the error a person reads names them: an
/// `agent` one tier down, a `cluster` one tier up. The noun is the whole of
/// the difference between the two tiers' sentences.
pub struct Peer<'a> {
    pub kind: &'a str,
    pub name: &'a str,
}

/// A pending command's peer payload or structured refusal.
type Answer = Result<Vec<u8>, Refusal>;

/// A typed refusal: the sentence a person reads and the REST reason word a
/// caller branches on instead of matching prose. One type for both ends of a
/// session: the answer a peer sent back (`Ack::Rejected`), and a handler's
/// own failure this tier copies into its `ErrorMsg.reason` (`unavailable`).
/// Legacy peers may send an empty reason, so callers must retain a
/// conservative fallback.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Refusal {
    pub message: String,
    pub reason: String,
}

/// Agent-defined reason that requests placement recovery after structural refusal.
/// It lives in proto so the agent need not depend on controller-api.
pub use proto::CANNOT_SERVE;

/// Agent-defined reason for a source that refused a send before opening a stream.
pub use proto::CANNOT_SEND;

impl Refusal {
    pub fn new(message: impl Into<String>, reason: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            reason: reason.into(),
        }
    }

    /// A refusal from a peer that does not send reasons, or an internal one
    /// that has no better word than "it did not work".
    pub fn plain(message: impl Into<String>) -> Self {
        Self::new(message, String::new())
    }

    /// "The party that holds the answer is out of reach right now." A caller
    /// that retries is right, and the tier above should say 503 rather than
    /// invent a disagreement.
    pub fn unavailable(message: impl Into<String>) -> Self {
        Self::new(message, "Unavailable")
    }

    /// The refusal `error` carries, wherever it sits: under the line a session
    /// adds ("agent … rejected command"), under a forward's ("the replica at …
    /// answered 409"), or as the source of another error type. The outermost
    /// one wins, because it is the word of the tier nearest the caller.
    pub fn in_chain(error: &anyhow::Error) -> Option<&Refusal> {
        // `chain()` follows `source()` and so passes over a refusal attached
        // as anyhow context, which anyhow's own downcast finds.
        error.downcast_ref::<Refusal>().or_else(|| {
            error
                .chain()
                .find_map(|cause| cause.downcast_ref::<Refusal>())
        })
    }

    /// The refusal `error` carries when its word is `reason`: how a caller asks
    /// "did the node say `CannotServe`" without reading prose.
    pub fn saying<'e>(error: &'e anyhow::Error, reason: &str) -> Option<&'e Refusal> {
        Self::in_chain(error).filter(|refusal| refusal.reason == reason)
    }

    /// The word `error` carries, or the legacy empty reason when it carries none.
    pub fn reason_of(error: &anyhow::Error) -> &str {
        Self::in_chain(error).map_or("", |refusal| refusal.reason.as_str())
    }
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

/// Preserve the refusal reason through anyhow error chains so callers can
/// choose recovery behavior without matching message prose.
impl std::error::Error for Refusal {}

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

    /// Register a request, send it on the supplied session, and await its
    /// reply. Resolve the session before calling so a missing peer creates
    /// no pending entry. Register before sending so an immediate reply is matched.
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

        // Bound enqueue time as well as ACK time. A peer that stops draining its
        // stream must not stall unrelated reconciliation. A timed-out send is cancelled.
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
            Ok(Ok(Err(refusal))) => Ok(Ack::Rejected(refusal)),
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
            answering.resolve(&id, Err(Refusal::plain("no such vm")));
        });
        let peer = Peer {
            kind: "cluster",
            name: "c1",
        };
        let answer = pending.send(peer, &tx, |id| id).await.unwrap();
        assert!(
            matches!(answer, Ack::Rejected(r) if r.message == "no such vm" && r.reason.is_empty())
        );
        assert_eq!(in_flight(&pending), 0);
    }

    /// An error type of somebody else's whose `source()` is a refusal.
    #[derive(Debug)]
    struct Carrying(Refusal);

    impl std::fmt::Display for Carrying {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("fetching the console")
        }
    }

    impl std::error::Error for Carrying {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            Some(&self.0)
        }
    }

    /// NL-A5: the word is found under whatever the tiers above wrap it in: the
    /// line a session adds, a forward's line over that, another error type's
    /// `source()`, and a refusal attached as context.
    #[test]
    fn a_refusal_is_found_anywhere_in_the_chain() {
        let session = anyhow::Error::new(Refusal::new("no gateway slot", CANNOT_SERVE))
            .context("agent gw-1 rejected command");
        assert_eq!(Refusal::reason_of(&session), CANNOT_SERVE);
        let forwarded = session.context("the replica at 10.0.0.9:3001 answered 409 Conflict");
        assert_eq!(
            Refusal::in_chain(&forwarded).map(|r| r.message.as_str()),
            Some("no gateway slot")
        );

        let wrapped = anyhow::Error::new(Carrying(Refusal::unavailable("gw-1 is gone")))
            .context("serving the logs");
        assert_eq!(Refusal::reason_of(&wrapped), "Unavailable");

        let attached = anyhow::anyhow!("console unreachable").context(Refusal::unavailable("x"));
        assert_eq!(Refusal::reason_of(&attached), "Unavailable");
    }

    /// The tier nearest the caller speaks: its refusal is the word, not the one
    /// under it.
    #[test]
    fn the_outermost_refusal_is_the_word() {
        let e = anyhow::Error::new(Refusal::new("no gateway slot", CANNOT_SERVE))
            .context(Refusal::unavailable("the replica holding gw-1 is gone"));
        assert_eq!(Refusal::reason_of(&e), "Unavailable");
        assert!(Refusal::saying(&e, CANNOT_SERVE).is_none());
    }

    /// An error with no refusal in it carries the legacy empty reason, and a
    /// refusal with another word is not the one asked about.
    #[test]
    fn only_a_refusal_with_the_word_asked_about_is_found() {
        let silent = anyhow::anyhow!("node gw-1 has no active session").context("ensure");
        assert_eq!(Refusal::reason_of(&silent), "");
        assert!(Refusal::saying(&silent, CANNOT_SERVE).is_none());

        let send = anyhow::Error::new(Refusal::new("vm has a device", CANNOT_SEND));
        assert!(Refusal::saying(&send, CANNOT_SERVE).is_none());
        assert_eq!(
            Refusal::saying(&send, CANNOT_SEND).map(|r| r.message.as_str()),
            Some("vm has a device")
        );
    }

    /// Closed sessions and unanswered commands must remove pending entries so
    /// repeated reconciliation cannot leak one entry per attempt.
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
