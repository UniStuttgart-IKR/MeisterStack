// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Forward the closed set of node commands needed by operations spanning sessions.
//!
//! Migration, router placement and image cleanup may reach nodes held by different
//! replicas. Dispatch uses the local registry or the Node's advertised sibling
//! endpoint. A forwarded request cannot be forwarded again. Authentication follows
//! the configured sibling transport and the receiving API permission policy.

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

/// Commands accepted by the sibling command route.
/// Keep this set explicit: adding a variant expands what a permitted caller can
/// ask a node to do. PrepareMigration.listen is selected by the destination, and
/// ProvisionVolume.from_snapshot is omitted because migration uses existing disks.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "command", rename_all = "camelCase")]
pub enum NodeCommand {
    /// Make a VMM that listens for an arriving guest.
    #[serde(rename_all = "camelCase")]
    PrepareMigration {
        id: String,
        spec_json: String,
        migration_id: String,
    },
    /// Send the guest to the address the destination named.
    #[serde(rename_all = "camelCase")]
    MigrateOut {
        id: String,
        peer: String,
        migration_id: String,
    },
    #[serde(rename_all = "camelCase")]
    CleanupMigration {
        id: String,
        migration_id: String,
        source: bool,
    },
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
        /// Absent from a replica that predates it, which keeps the node's dead man silencing.
        #[serde(default)]
        sole_gateway: bool,
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
    /// An image was deleted at the cloud; let go of whatever this node
    /// fetched for it. See `DropImage` in control.proto.
    #[serde(rename_all = "camelCase")]
    DropImage { name: String, uid: String },
}

impl NodeCommand {
    /// What goes down the session. The two empty fields are filled in here
    /// and nowhere else — see the type's doc for why they are not on the
    /// wire.
    pub fn into_op(self) -> command::Op {
        match self {
            Self::PrepareMigration {
                id,
                spec_json,
                migration_id,
            } => command::Op::PrepareMigration(proto::PrepareMigration {
                id,
                spec_json,
                listen: String::new(),
                migration_id,
            }),
            Self::MigrateOut {
                id,
                peer,
                migration_id,
            } => command::Op::MigrateOut(proto::MigrateOut {
                id,
                peer,
                migration_id,
            }),
            Self::CleanupMigration {
                id,
                migration_id,
                source,
            } => command::Op::CleanupMigration(proto::CleanupMigration {
                id,
                migration_id,
                source,
            }),
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
                sole_gateway,
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
                sole_gateway,
            }),
            Self::DestroyRouter { id } => command::Op::DestroyRouter(proto::DestroyRouter { id }),
            Self::ForgetVolume { id } => command::Op::ForgetVolume(proto::ForgetVolume { id }),
            Self::DropImage { name, uid } => command::Op::DropImage(proto::DropImage { name, uid }),
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
            Self::CleanupMigration { .. } => "cleanup-migration",
            Self::ProvisionVolume { .. } => "provision-volume",
            Self::EnsureRouter { .. } => "ensure-router",
            Self::DestroyRouter { .. } => "destroy-router",
            Self::ForgetVolume { .. } => "forget-volume",
            Self::DropImage { .. } => "drop-image",
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
                    let refusal = controller_api::forward::refusal_in(&answer.body);
                    if TYPED_REFUSALS.contains(&refusal.reason.as_str()) {
                        // Shaped like the local session's refusal: a line naming
                        // who answered, over the node's typed refusal. A status
                        // line prints the chain (`{:#}`) to keep the node's words.
                        return Err(anyhow::Error::new(refusal).context(format!(
                            "the replica at {endpoint} answered {}",
                            answer.status
                        )));
                    }
                    bail!(
                        "the replica at {endpoint} answered {}: {}",
                        answer.status,
                        refusal.message
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

/// The node words a forward carries back as words, so that the replica that
/// asked acts on a node's typed refusal as it would on its own session's:
/// `CannotServe` places elsewhere, `CannotSend` tears a migration's
/// destination down. Every other refusal travels as a sentence.
const TYPED_REFUSALS: [&str; 2] = [controller_api::CANNOT_SERVE, controller_api::CANNOT_SEND];

/// The node's typed refusal under `e`, with its word as this tier spells it.
fn typed_refusal(e: &anyhow::Error) -> Option<(&'static str, &controller_api::Refusal)> {
    let refusal = controller_api::Refusal::in_chain(e)?;
    let word = TYPED_REFUSALS
        .into_iter()
        .find(|word| *word == refusal.reason)?;
    Some((word, refusal))
}

/// Serve a sibling-forwarded command with second-hop forwarding disabled.
/// The header marks routing state, not identity. Middleware must authenticate
/// this cluster's system certificate; a request without the header is refused.
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
            .map_err(|e| match typed_refusal(&e) {
                // The node's typed answer keeps its word across the hop; see
                // `TYPED_REFUSALS`.
                Some((word, refusal)) => controller_api::ApiError::new(
                    axum::http::StatusCode::CONFLICT,
                    word,
                    refusal.message.clone(),
                ),
                // The agent's untyped refusal, or a session that went away
                // between the forward and the send. Both are "the party that
                // can act did not act", which is a 503 the sender turns back
                // into a sentence on the migration.
                None => controller_api::ApiError::new(
                    axum::http::StatusCode::SERVICE_UNAVAILABLE,
                    "Unavailable",
                    format!("{e:#}"),
                ),
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
    use controller_api::NetworkBackend as _;

    /// `holder`'s REST edge on a free local port: the route a sibling forwards to.
    async fn serve_edge(holder: Arc<SessionRegistry>) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = listener.local_addr().unwrap().to_string();
        let router = crate::api::test_router(holder).await;
        tokio::spawn(async move { axum::serve(listener, router).await });
        endpoint
    }

    /// A dispatcher whose store is never asked anything: the tests below hand
    /// the endpoint in, which is what `deliver` is separated for, or command a
    /// node whose session `registry` holds.
    async fn dispatch(registry: Arc<SessionRegistry>) -> Dispatch {
        let store = EtcdStore::connect(&["http://127.0.0.1:1".to_string()], "/dispatch-test")
            .await
            .expect("the etcd client is built lazily");
        dispatch_over(registry, Arc::new(store))
    }

    /// A dispatcher over `registry` that reads from `store` which replica holds the other nodes.
    fn dispatch_over(registry: Arc<SessionRegistry>, store: Arc<EtcdStore>) -> Dispatch {
        Dispatch::new(
            registry,
            store,
            Arc::new(Forward {
                cluster: "cluster-1".into(),
                sibling: controller_api::forward::Sibling {
                    serves_tls: false,
                    tls: None,
                },
            }),
        )
    }

    /// One router, active on `gw-1`: the plan the router reconciler hands its backend.
    fn router_on_gw_1() -> controller_api::RouterPlan {
        controller_api::RouterPlan {
            id: "uid-r".into(),
            name: "acme-out".into(),
            physnet: "ext".into(),
            external_addr: "198.51.100.10/24".into(),
            external_gateway: "198.51.100.1".into(),
            vni: 10_007,
            internal_addr: "10.42.0.1/24".into(),
            nats: Vec::new(),
            nodes: vec!["gw-1".into()],
            active: Some("gw-1".into()),
            release: Vec::new(),
            sole_gateway: true,
        }
    }

    /// What an agent answers an EnsureRouter for a physnet it has no gateway slot for.
    fn no_gateway_slot() -> controller_api::Refusal {
        controller_api::Refusal::new(
            "no gateway slot for physnet ext",
            controller_api::CANNOT_SERVE,
        )
    }

    /// The router backend's verdict on `gw-1` refusing structurally: a refusal with the
    /// node's own sentence, not a node it could not reach.
    fn assert_refused_by_gw_1(out: &controller_api::RouterOutcome) {
        assert_eq!(out.refused, ["gw-1"], "{out:?}");
        assert_eq!(out.phase, controller_api::RouterPhaseKind::Failed);
        assert_eq!(out.reason, controller_api::RouterReason::Refused);
        let said = out.message.as_deref().unwrap_or_default();
        assert!(said.contains("no gateway slot for physnet ext"), "{said}");
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
        let agent =
            holder.agent_answering("agent-1a", Ok(br#"{"peer":"10.0.0.7:49000"}"#.to_vec()));
        let endpoint = serve_edge(holder.clone()).await;

        // And the replica that holds the migration, which holds no session
        // for this node at all.
        let elsewhere = Arc::new(SessionRegistry::new());
        assert!(!elsewhere.connected().contains("agent-1a"));

        let payload = dispatch(elsewhere)
            .await
            .deliver(
                "agent-1a",
                NodeCommand::PrepareMigration {
                    migration_id: "attempt".into(),
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
        assert_eq!(prepare.migration_id, "attempt");
        assert_eq!(prepare.listen, "", "the destination picks its own address");
    }

    /// NL-A1: a source's `CannotSend` reaches the replica that holds the migration as the
    /// same typed refusal its own session would have handed it, so that replica tears the
    /// destination down instead of waiting on an unknown outcome.
    #[tokio::test]
    async fn a_forwarded_refusal_to_send_keeps_its_word() {
        let holder = Arc::new(SessionRegistry::new());
        let agent = holder.agent_answering(
            "agent-1a",
            Err(controller_api::Refusal::new(
                "vm uid-1 has 1 device(s) (crosvm-gpu)",
                controller_api::CANNOT_SEND,
            )),
        );
        let endpoint = serve_edge(holder.clone()).await;

        let refused = dispatch(Arc::new(SessionRegistry::new()))
            .await
            .deliver(
                "agent-1a",
                NodeCommand::MigrateOut {
                    migration_id: "attempt".into(),
                    id: "uid-1".into(),
                    peer: "tcp:10.0.0.9:49000".into(),
                },
                false,
                Some(&endpoint),
            )
            .await
            .expect_err("the source refused");

        let refusal =
            controller_api::Refusal::in_chain(&refused).expect("a typed refusal, not a sentence");
        assert_eq!(refusal.reason, controller_api::CANNOT_SEND);
        assert_eq!(refusal.message, "vm uid-1 has 1 device(s) (crosvm-gpu)");
        assert!(
            format!("{refused:#}").contains("vm uid-1 has 1 device(s) (crosvm-gpu)"),
            "the node's sentence is in the chain a status line prints: {refused:#}"
        );
        assert!(
            matches!(agent.await.unwrap(), Some(command::Op::MigrateOut(_))),
            "the source was asked"
        );
    }

    /// An untyped refusal stays a sentence across the hop: nothing the replica that asked
    /// could act on is invented for it.
    #[tokio::test]
    async fn a_forwarded_untyped_refusal_stays_a_sentence() {
        let holder = Arc::new(SessionRegistry::new());
        let _agent = holder.agent_answering(
            "agent-1a",
            Err(controller_api::Refusal::plain("sending vm uid-1: refused")),
        );
        let endpoint = serve_edge(holder.clone()).await;

        let refused = dispatch(Arc::new(SessionRegistry::new()))
            .await
            .deliver(
                "agent-1a",
                NodeCommand::MigrateOut {
                    migration_id: "attempt".into(),
                    id: "uid-1".into(),
                    peer: "tcp:10.0.0.9:49000".into(),
                },
                false,
                Some(&endpoint),
            )
            .await
            .expect_err("the source refused");

        assert!(
            controller_api::Refusal::in_chain(&refused).is_none(),
            "{refused:#}"
        );
        assert!(
            format!("{refused:#}").contains("sending vm uid-1: refused"),
            "{refused:#}"
        );
    }

    /// NL-A5: a node's `CannotServe` for a router, through this replica's own session, is a
    /// refusal the router backend remembers, and not a node it could not reach.
    #[tokio::test]
    async fn a_router_a_node_cannot_serve_is_refused_and_not_unreachable() {
        let registry = Arc::new(SessionRegistry::new());
        let agent = registry.agent_answering("gw-1", Err(no_gateway_slot()));

        let out = controller_api::MeisterNetwork
            .realise(&dispatch(registry).await, &router_on_gw_1())
            .await;

        assert_refused_by_gw_1(&out);
        assert!(matches!(
            agent.await.unwrap(),
            Some(command::Op::EnsureRouter(_))
        ));
    }

    /// NL-A5 across the hop: the same refusal from a node another replica holds, found
    /// through the endpoint that replica wrote onto the node object, reads the same.
    #[tokio::test]
    #[ignore = "needs an etcd; see crate::test_etcd"]
    async fn a_router_a_node_of_another_replica_cannot_serve_is_refused_and_not_unreachable() {
        let holder = Arc::new(SessionRegistry::new());
        let agent = holder.agent_answering("gw-1", Err(no_gateway_slot()));
        let store = crate::test_etcd::fresh_store("dispatch-router").await;
        let mut gw = Node::declare("gw-1", controller_api::NodeSpec::default());
        gw.status.session_endpoint = Some(serve_edge(holder).await);
        store.create(&gw).await.expect("the node object");

        let elsewhere = dispatch_over(Arc::new(SessionRegistry::new()), Arc::new(store));
        let out = controller_api::MeisterNetwork
            .realise(&elsewhere, &router_on_gw_1())
            .await;

        assert_refused_by_gw_1(&out);
        assert!(matches!(
            agent.await.unwrap(),
            Some(command::Op::EnsureRouter(_))
        ));
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
            migration_id: "attempt".into(),
            id: "uid-1".into(),
            peer: "10.0.0.7:49000".into(),
        };
        let wire = serde_json::to_string(&cmd).unwrap();
        assert_eq!(
            wire,
            r#"{"command":"migrateOut","id":"uid-1","peer":"10.0.0.7:49000","migrationId":"attempt"}"#
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

        // The sixth, and the one whose reach is every node in the cluster
        // rather than one VM's two ends — see the type's own doc for why
        // that earns it this door too. Astra finding S02, 2026-09-23 (rest
        // b).
        let dropped = NodeCommand::DropImage {
            name: "ubuntu.raw".into(),
            uid: "uid-4".into(),
        };
        let wire = serde_json::to_string(&dropped).unwrap();
        assert_eq!(
            wire,
            r#"{"command":"dropImage","name":"ubuntu.raw","uid":"uid-4"}"#
        );
        assert_eq!(serde_json::from_str::<NodeCommand>(&wire).unwrap(), dropped);
        assert_eq!(dropped.name(), "drop-image");
        let command::Op::DropImage(op) = dropped.into_op() else {
            panic!("a drop-image");
        };
        assert_eq!(op.name, "ubuntu.raw");
        assert_eq!(op.uid, "uid-4");

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

    /// IKR-B76: a router command forwarded by a replica that predates `soleGateway` is read as
    /// not sole, which keeps the node's dead man silencing the router as it did.
    #[test]
    fn a_router_command_without_the_sole_gateway_word_keeps_the_dead_man_silencing() {
        let older = r#"{"command":"ensureRouter","id":"uid-1","physnet":"ext",
            "externalAddr":"198.51.100.10/24","externalGateway":"198.51.100.1","vni":10007,
            "internalAddr":"10.42.0.1/24","nats":[],"active":true}"#;
        let command = serde_json::from_str::<NodeCommand>(older).expect("an older command");
        let command::Op::EnsureRouter(router) = command.into_op() else {
            panic!("an ensure-router");
        };
        assert!(router.active && !router.sole_gateway);
    }
}
