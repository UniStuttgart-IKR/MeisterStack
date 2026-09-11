// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! One command to one node, from whichever replica is holding the object.
//!
//! ## Why this exists
//!
//! Everything else this tier reconciles is owned by the replica that holds
//! the node's session: a VM, a volume and a snapshot are all about ONE
//! machine, so the replica that can reach it takes the object and the others
//! leave it alone (`reconcile::may_reconcile`). No forwarding, no leader.
//!
//! A live migration is the one object that is about TWO machines, and the two
//! sessions can hang off two different replicas. Then no ownership rule can
//! work: whichever replica took it can reach one end and not the other. The
//! defect that found this (rollout 59, D-P2) is exactly that shape — the
//! migration reconciler called the LOCAL registry for the source's session,
//! and on a three-replica cluster a migration only ran when the same replica
//! happened to hold both ends. Measured: roughly one attempt in three, and
//! the other two answered "node agent-1a has no active session" about a node
//! that was up and healthy.
//!
//! So a migration forwards, the way a console read has since the cluster grew
//! replicas: the replica that holds the object looks at
//! `Node.status.session_endpoint`, which the holder wrote at Hello, and asks
//! that replica to say the sentence for it. Once — the hop carries
//! `x-meister-forwarded` and a replica that sees the header and holds no
//! session answers rather than passing it on again.
//!
//! ## What may travel this way
//!
//! `NodeCommand`, and nothing else. The commands a migration sends, as a
//! closed enum with no room in it for anything else: this is a door through
//! which one control-plane process tells another process's agent what to do,
//! and a generic "send this command" route would be a remote shell for
//! anybody holding a replica's certificate. Widening it is a decision, not a
//! detail — it was four for the whole of the migration work, and `ForgetVolume`
//! is the fifth because the source of a finished migration has to be told to
//! let go of a disk it no longer has any business with.

use std::sync::Arc;

use anyhow::bail;
use controller_api::{EtcdStore, Node, StoreError};
use proto::command;
use tracing::{debug, info};

use crate::logs::{FORWARDED, Forward, Holder, decide_holder};
use crate::session::SessionRegistry;

/// What `holder` says this tier is talking about — the same pair the console
/// forward uses, because it is the same fact: a node's session, held by one
/// replica of this cluster.
const ABOUT: controller_api::forward::About = controller_api::forward::About {
    peer: "node",
    tier: "cluster",
};

/// Where a forwarded command lands. `{name}` is the node.
pub const COMMAND_PATH: &str = "/apis/meister.io/v1/nodes/{name}/commands";

/// The commands one replica of this cluster may have another replica's agent
/// carry out.
///
/// A type of its own rather than `proto::command::Op`: the protobuf types
/// carry no serde derives, the hop is JSON, and — the actual reason — this
/// enum is the whole of what a sibling may be talked into doing. Every
/// variant here is something the migration reconciler sends today; nothing
/// here is reachable by a client.
///
/// Two fields the protobuf messages have are deliberately absent.
/// `PrepareMigration.listen` is always empty (the destination picks the
/// address, because it is the only party that knows which of its addresses a
/// peer can reach) and `ProvisionVolume.from_snapshot` is always empty (a
/// migrating guest's disk exists already). A field that is always empty is
/// not a field, and putting one on this wire would be putting a lever there
/// for somebody to find.
///
/// **The two router commands are the widening the doc above calls a
/// decision, made.** A router is the second object in this control plane that
/// is about several machines at once — it is built on its whole priority list
/// — and it is worse than a migration in the way that matters here: the
/// failover it exists for is exactly the moment the machine an ownership rule
/// would have hung it on stops answering. A reconciler asking its own session
/// registry would build the half of the list it can reach and call the rest
/// unreachable, which is D-P2 one object over. So they travel this road, and
/// the enum stays closed around them.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "command", rename_all = "camelCase")]
pub enum NodeCommand {
    /// Make a VMM that listens for an arriving guest.
    #[serde(rename_all = "camelCase")]
    PrepareMigration { id: String, spec_json: String },
    /// Send the guest to the address the destination named.
    #[serde(rename_all = "camelCase")]
    MigrateOut { id: String, peer: String },
    /// Let go of this VM: the record, the VMM and the volumes it attached.
    #[serde(rename_all = "camelCase")]
    Destroy { id: String },
    /// Open a disk here, so the arriving configuration finds it by path.
    #[serde(rename_all = "camelCase")]
    ProvisionVolume { id: String, spec_json: String },
    /// Build or re-state one tenant router on this node, with the `active`
    /// bit this node should carry. Level-triggered: the same one twice is one
    /// router.
    ///
    /// Spelled out field by field rather than carrying `proto::EnsureRouter`,
    /// because the protobuf types have no serde derives and this hop is JSON
    /// — the same reason every other variant here is spelled out. `into_op`
    /// is where the two shapes meet, and it is the only place.
    #[serde(rename_all = "camelCase")]
    EnsureRouter {
        id: String,
        physnet: String,
        external_addr: String,
        external_gateway: String,
        vni: u32,
        internal_addr: String,
        nats: Vec<controller_api::NatRule>,
        active: bool,
    },
    /// Let go of one router: the netns, both legs and the rules.
    #[serde(rename_all = "camelCase")]
    DestroyRouter { id: String },
    /// Let go of a disk's RECORD and keep every byte of it.
    ///
    /// The last thing the source of a finished migration is told, and the one
    /// command on this wire whose whole point is that it destroys nothing.
    /// See `ForgetVolume` in control.proto for the distance between this and
    /// a deprovision.
    #[serde(rename_all = "camelCase")]
    ForgetVolume { id: String },
}

impl NodeCommand {
    /// What goes down the session. The two empty fields are filled in here
    /// and nowhere else — see the type's doc for why they are not on the
    /// wire.
    pub fn into_op(self) -> command::Op {
        match self {
            Self::PrepareMigration { id, spec_json } => {
                command::Op::PrepareMigration(proto::PrepareMigration {
                    id,
                    spec_json,
                    listen: String::new(),
                })
            }
            Self::MigrateOut { id, peer } => {
                command::Op::MigrateOut(proto::MigrateOut { id, peer })
            }
            Self::Destroy { id } => command::Op::Destroy(proto::DestroyInstance { id }),
            Self::ProvisionVolume { id, spec_json } => {
                command::Op::ProvisionVolume(proto::ProvisionVolume {
                    id,
                    spec_json,
                    from_snapshot: String::new(),
                })
            }
            Self::EnsureRouter {
                id,
                physnet,
                external_addr,
                external_gateway,
                vni,
                internal_addr,
                nats,
                active,
            } => command::Op::EnsureRouter(proto::EnsureRouter {
                id,
                physnet,
                external_addr,
                external_gateway,
                vni,
                internal_addr,
                nats: nats
                    .into_iter()
                    .map(|r| proto::NatRule {
                        kind: r.kind.as_str().to_string(),
                        external_ip: r.external_ip,
                        logical_ip: r.logical_ip,
                    })
                    .collect(),
                active,
            }),
            Self::DestroyRouter { id } => command::Op::DestroyRouter(proto::DestroyRouter { id }),
            Self::ForgetVolume { id } => command::Op::ForgetVolume(proto::ForgetVolume { id }),
        }
    }

    /// For the log line, and for the sentence a failure carries: an operator
    /// reading "the destination could not be torn down" wants to know which
    /// command that was.
    pub fn name(&self) -> &'static str {
        match self {
            Self::PrepareMigration { .. } => "prepare-migration",
            Self::MigrateOut { .. } => "migrate-out",
            Self::Destroy { .. } => "destroy",
            Self::ProvisionVolume { .. } => "provision-volume",
            Self::EnsureRouter { .. } => "ensure-router",
            Self::DestroyRouter { .. } => "destroy-router",
            Self::ForgetVolume { .. } => "forget-volume",
        }
    }
}

/// Everything a command needs to reach a node from any replica: the sessions
/// this process holds, the store that says where the others are, and the
/// credential to speak to one.
pub struct Dispatch {
    registry: Arc<SessionRegistry>,
    store: Arc<EtcdStore>,
    forward: Arc<Forward>,
}

impl Dispatch {
    pub fn new(
        registry: Arc<SessionRegistry>,
        store: Arc<EtcdStore>,
        forward: Arc<Forward>,
    ) -> Self {
        Self {
            registry,
            store,
            forward,
        }
    }

    /// Send one command to `node` and wait for its ack, wherever the session
    /// is.
    ///
    /// The ack's payload comes back unopened, because one caller reads it:
    /// `PrepareMigration` answers with the address the destination is
    /// listening at.
    pub async fn send(&self, node: &str, cmd: NodeCommand) -> anyhow::Result<Vec<u8>> {
        let here = self.registry.connected().contains(node);
        // Only asked for when it is needed, which is the uncommon half — a
        // single-replica cluster never reads this object at all.
        let endpoint = if here {
            None
        } else {
            match self.store.get::<Node>(node).await {
                Ok(n) => n.status.session_endpoint,
                // The node object is gone and the migration still names it.
                // Not a reason to fail differently: nobody holds a session
                // for it.
                Err(StoreError::NotFound(_)) => None,
                Err(e) => return Err(e.into()),
            }
        };
        self.deliver(node, cmd, here, endpoint.as_deref()).await
    }

    /// The decision and the hop, without the store: who holds the session is
    /// two facts, and this is what is done with them.
    ///
    /// Split out so that the forward can be proved with two registries in one
    /// process and no etcd behind either of them.
    async fn deliver(
        &self,
        node: &str,
        cmd: NodeCommand,
        here: bool,
        endpoint: Option<&str>,
    ) -> anyhow::Result<Vec<u8>> {
        // Never forwarded: this is a reconcile pass and not a request that
        // came in over HTTP. A command that arrived here as a forward is
        // served by the route, which passes `true` to the same rule.
        match decide_holder(ABOUT, here, endpoint, false) {
            Holder::Here => self.registry.send_command(node, "", cmd.into_op()).await,
            Holder::Sibling(endpoint) => {
                info!(cluster = %self.forward.cluster, node, %endpoint, command = cmd.name(),
                      "forwarding a migration command to the replica that holds the session");
                let path = COMMAND_PATH.replace("{name}", node);
                let body = serde_json::to_vec(&cmd)?;
                let answer = controller_api::forward::relay(
                    &self.forward.sibling,
                    &endpoint,
                    hyper::Method::POST,
                    &path,
                    body.into(),
                )
                .await?;
                if !answer.status.is_success() {
                    // The sibling's own sentence. What it refused with is the
                    // AGENT's answer where there is one — the route hands a
                    // rejection back as the node said it — so collapsing this
                    // into "the forward failed" would lose the only thing
                    // worth reading.
                    bail!(
                        "the replica at {endpoint} answered {}: {}",
                        answer.status,
                        said(&answer.body)
                    );
                }
                Ok(answer.body.to_vec())
            }
            // The same fact "this node has no active session" always was: the
            // party that can act is out of reach. The migration records it
            // and the next pass tries again.
            Holder::Nowhere(why) => {
                debug!(node, command = cmd.name(), reason = %why, "nobody to send to");
                bail!("{why}")
            }
        }
    }
}

/// The `message` of this API's refusal, or the body as it stands when it is
/// not one. The read half of the same forward has this; a write needs it for
/// exactly the same reason.
fn said(body: &bytes::Bytes) -> String {
    #[derive(serde::Deserialize)]
    struct Refusal {
        message: String,
    }
    match serde_json::from_slice::<Refusal>(body) {
        Ok(r) => r.message,
        Err(_) => String::from_utf8_lossy(body).trim().to_string(),
    }
}

/// Serve a command that a sibling replica forwarded here.
///
/// The route's whole body, so that the rule it applies is beside the rule the
/// sender applies: this end passes `forwarded = true`, which is what makes a
/// second hop impossible.
///
/// `forwarded` is the header and not a credential — the caller still has to
/// present this cluster's own `system:cluster:<name>` certificate, which the
/// permission table checks before this runs. What the header does is make a
/// direct call refusable: nothing but a forward has any business here, and a
/// request without it is answered rather than served.
pub async fn serve_forwarded(
    registry: &SessionRegistry,
    node: &str,
    forwarded: bool,
    cmd: NodeCommand,
) -> Result<Vec<u8>, controller_api::ApiError> {
    if !forwarded {
        return Err(controller_api::ApiError::new(
            axum::http::StatusCode::BAD_REQUEST,
            "BadRequest",
            format!(
                "this route is how one replica of this cluster asks another to reach node \
                 {node}; a request that is not a forward ({FORWARDED}) has no business here"
            ),
        ));
    }
    let here = registry.connected().contains(node);
    match decide_holder(ABOUT, here, None, true) {
        Holder::Here => registry
            .send_command(node, "", cmd.into_op())
            .await
            .map_err(|e| {
                // The agent's own refusal, or a session that went away
                // between the forward and the send. Both are "the party that
                // can act did not act", which is a 503 the sender turns back
                // into a sentence on the migration.
                controller_api::ApiError::new(
                    axum::http::StatusCode::SERVICE_UNAVAILABLE,
                    "Unavailable",
                    format!("{e:#}"),
                )
            }),
        // Forwarded here and the session is not here either: the node moved
        // between the write and the read. Never a second hop.
        Holder::Sibling(_) | Holder::Nowhere(_) => Err(controller_api::ApiError::new(
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            "Unavailable",
            match decide_holder(ABOUT, here, None, true) {
                Holder::Nowhere(why) => why,
                _ => unreachable!("a forwarded request never forwards again"),
            },
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use tokio::sync::mpsc;

    /// A registry with one node dialled into it, and a task that answers
    /// whatever is sent down that session with `payload`.
    ///
    /// This is the agent's half and nothing more: it reads the request id off
    /// the envelope and resolves it, which is what `on_result` does when a
    /// real agent answers.
    fn agent_on(
        registry: &Arc<SessionRegistry>,
        node: &str,
        payload: Vec<u8>,
    ) -> tokio::task::JoinHandle<Option<command::Op>> {
        let (tx, mut rx) = mpsc::channel(4);
        registry.attach(node, &tx);
        let registry = registry.clone();
        tokio::spawn(async move {
            let msg = rx.recv().await?;
            let Ok(proto::ControllerMessage {
                kind: Some(proto::controller_message::Kind::Command(cmd)),
            }) = msg
            else {
                return None;
            };
            registry.answer(&cmd.request_id, payload);
            cmd.op
        })
    }

    /// A dispatcher whose store is never asked anything: every test below
    /// hands the endpoint in, which is what `deliver` is separated for.
    async fn dispatch(registry: Arc<SessionRegistry>) -> Dispatch {
        Dispatch::new(
            registry,
            Arc::new(
                EtcdStore::connect(&["http://127.0.0.1:1".to_string()], "/dispatch-test")
                    .await
                    .expect("the etcd client is built lazily"),
            ),
            Arc::new(Forward {
                cluster: "cluster-1".into(),
                sibling: controller_api::forward::Sibling {
                    serves_tls: false,
                    tls: None,
                },
            }),
        )
    }

    /// D-P2, with the two replicas the lab had: the migration is reconciled
    /// by one replica and the node it has to talk to is dialled into the
    /// other.
    ///
    /// Before the forward this answered "node agent-1a has no active
    /// session" about a node that was up — and on a three-replica cluster
    /// that was two migrations out of three.
    #[tokio::test]
    async fn a_command_for_a_node_another_replica_holds_reaches_that_node() {
        // The replica that holds the session, with a REST edge in front of
        // it — the same router a real replica serves.
        let holder = Arc::new(SessionRegistry::new());
        let agent = agent_on(
            &holder,
            "agent-1a",
            br#"{"peer":"10.0.0.7:49000"}"#.to_vec(),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = listener.local_addr().unwrap().to_string();
        let router = crate::api::test_router(holder.clone()).await;
        tokio::spawn(async move { axum::serve(listener, router).await });

        // And the replica that holds the migration, which holds no session
        // for this node at all.
        let elsewhere = Arc::new(SessionRegistry::new());
        assert!(!elsewhere.connected().contains("agent-1a"));

        let payload = dispatch(elsewhere)
            .await
            .deliver(
                "agent-1a",
                NodeCommand::PrepareMigration {
                    id: "uid-1".into(),
                    spec_json: "{}".into(),
                },
                false,
                Some(&endpoint),
            )
            .await
            .expect("the command reaches the node through its holder");

        assert_eq!(
            String::from_utf8_lossy(&payload),
            r#"{"peer":"10.0.0.7:49000"}"#,
            "and the destination's answer comes back unopened"
        );
        let op = agent.await.unwrap().expect("the agent was told something");
        let command::Op::PrepareMigration(prepare) = op else {
            panic!("the command that arrived is the command that was sent: {op:?}");
        };
        assert_eq!(prepare.id, "uid-1");
        assert_eq!(prepare.listen, "", "the destination picks its own address");
    }

    /// The other end of the same hop: a replica that was forwarded a command
    /// for a node it does not hold either answers instead of passing it on.
    #[tokio::test]
    async fn a_forwarded_command_never_forwards_again() {
        let registry = SessionRegistry::new();
        let refused = serve_forwarded(
            &registry,
            "agent-1a",
            true,
            NodeCommand::Destroy { id: "uid-1".into() },
        )
        .await
        .expect_err("nobody here holds it");
        assert_eq!(
            refused.status(),
            axum::http::StatusCode::SERVICE_UNAVAILABLE
        );
        assert!(
            refused.message().contains("node has moved"),
            "the sentence says why there is no second hop: {}",
            refused.message()
        );

        // And a call that is not a forward is not served at all: this route
        // is the tier talking to itself.
        let refused = serve_forwarded(
            &registry,
            "agent-1a",
            false,
            NodeCommand::Destroy { id: "uid-1".into() },
        )
        .await
        .expect_err("only a forward belongs here");
        assert_eq!(refused.status(), axum::http::StatusCode::BAD_REQUEST);
    }

    /// A node nobody has dialled into is the third outcome, and it is the
    /// one the migration writes onto its object.
    #[tokio::test]
    async fn a_node_no_replica_holds_is_out_of_reach_rather_than_local() {
        let refused = dispatch(Arc::new(SessionRegistry::new()))
            .await
            .deliver(
                "agent-1a",
                NodeCommand::Destroy { id: "uid-1".into() },
                false,
                None,
            )
            .await
            .expect_err("there is nobody to send to");
        assert!(
            refused.to_string().contains("advertise_api"),
            "the sentence names the key an operator would set: {refused:#}"
        );
    }

    /// The wire form is a contract between two processes of the same build,
    /// and it is still worth pinning: a rename here is a migration that stops
    /// working across a rolling upgrade.
    #[test]
    fn the_commands_travel_as_themselves() {
        let cmd = NodeCommand::MigrateOut {
            id: "uid-1".into(),
            peer: "10.0.0.7:49000".into(),
        };
        let wire = serde_json::to_string(&cmd).unwrap();
        assert_eq!(
            wire,
            r#"{"command":"migrateOut","id":"uid-1","peer":"10.0.0.7:49000"}"#
        );
        assert_eq!(serde_json::from_str::<NodeCommand>(&wire).unwrap(), cmd);

        // The two fields that are not on the wire are filled in on the way
        // to the session, and only there.
        let op = NodeCommand::ProvisionVolume {
            id: "uid-2".into(),
            spec_json: "{}".into(),
        }
        .into_op();
        let command::Op::ProvisionVolume(provision) = op else {
            panic!("a provision");
        };
        assert_eq!(provision.from_snapshot, "");

        // The fifth, and the one whose whole point is that it destroys
        // nothing: the source of a finished migration is told to let go of a
        // disk whose home has moved. Pinned beside the others because the
        // distance between this word and `deprovisionVolume` is somebody's
        // data, and the two must never be reachable from one another by a
        // typo.
        let forget = NodeCommand::ForgetVolume { id: "uid-3".into() };
        let wire = serde_json::to_string(&forget).unwrap();
        assert_eq!(wire, r#"{"command":"forgetVolume","id":"uid-3"}"#);
        assert_eq!(serde_json::from_str::<NodeCommand>(&wire).unwrap(), forget);
        assert_eq!(forget.name(), "forget-volume");
        let command::Op::ForgetVolume(op) = forget.into_op() else {
            panic!("a forget, and nothing that touches bytes");
        };
        assert_eq!(op.id, "uid-3");

        // And nothing else can be talked in: the enum is the door.
        assert!(
            serde_json::from_str::<NodeCommand>(r#"{"command":"createInstance","id":"uid-1"}"#)
                .is_err(),
            "a command this tier does not forward is not a command"
        );
        assert!(
            serde_json::from_str::<NodeCommand>(r#"{"command":"deprovisionVolume","id":"uid-3"}"#)
                .is_err(),
            "and the one command that would destroy the disk is not on this wire"
        );
    }
}
