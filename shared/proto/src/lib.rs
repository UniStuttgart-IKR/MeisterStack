// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

// The generated oneof enums have variants of very different sizes — a
// Command carries a whole VmSpec, an Ack carries nothing. Boxing them is not
// ours to decide: this is prost's output, regenerated on every build.
#[allow(clippy::large_enum_variant)]
mod generated {
    tonic::include_proto!("meisterstack.v1");
}
pub use generated::*;

use anyhow::Context;
use std::path::Path;
use std::time::Duration;

use tonic::transport::{Certificate, Channel, ClientTlsConfig, Endpoint, Identity};

/// `ErrorMsg.reason` for a refusal that is about the NODE rather than about
/// the attempt.
///
/// Here — beside the message it is a field of — because it is a wire value
/// and both ends of the wire need the same string, and because the two ends
/// are deliberately not allowed to share anything else: the agent does not
/// depend on `controller-api`, on purpose, so a constant in there could not
/// be the one the agent writes.
///
/// What it means: a create the node refused STRUCTURALLY — no hypervisor, a
/// driver it does not have, a backend a volume names and it lacks — leaving
/// no record behind. It will never work on this node, however often it is
/// asked, so the tier above answers it by taking the binding back and placing
/// the VM somewhere else. A failure AFTER the record exists is the opposite:
/// a boot that did not work may work next time in the same place, and that is
/// a `Failed` VM with a requeue where it is.
///
/// Empty from an agent that predates it, which reads as the second — the
/// conservative one, because re-placing a VM that merely failed to boot would
/// walk it around the cluster.
pub const CANNOT_SERVE: &str = "CannotServe";

/// `RouterReport.phase` as a NODE spells it, and the whole vocabulary of that
/// road: the namespace and its two legs are there, or they are not.
///
/// Here for the reason [`CANNOT_SERVE`] is here — a wire value both ends need
/// and the two ends deliberately share nothing else — and because these two
/// words are NOT the tier above's `RouterPhase`. That one is about a router
/// living on several machines at once (`Active`, `Standby`, `Pending`,
/// `Unknown`, …) and a node knows none of that: whether a healthy node means
/// Active or Standby depends on which of them the CONTROLLER made active, and
/// the controller is what joins the two vocabularies (see the cluster's
/// `observed_phase`). Reading the node's word as the tier's own was a bug
/// with a very quiet shape: `Ready` parsed as nothing, so every report from
/// every healthy gateway node was dropped with a warning, and the only thing
/// a node could tell the tier above was that something had broken.
pub const ROUTER_READY: &str = "Ready";

/// `RouterReport.phase` for a router this node cannot serve right now: the
/// namespace is gone, or a leg of it is. See [`ROUTER_READY`].
pub const ROUTER_FAILED: &str = "Failed";

/// How long a session dial may spend getting a connection.
///
/// Both tiers dial down a preference order (HRW) and walk to the next entry
/// when one refuses. A refusal is instant; a blackholed endpoint — fenced
/// host, dropped SYN, a route that goes nowhere — says nothing at all, and
/// the kernel's own give-up is `tcp_syn_retries` deep: six retries, about
/// two minutes. For those two minutes the caller is stuck on a replica it
/// will never reach while the next one in its order sits there answering.
///
/// Three seconds is far above any real handshake on a lab network and far
/// below the point where failover stops being failover.
pub const DIAL_TIMEOUT: Duration = Duration::from_secs(3);

/// How often a session asks the other end whether it is still there.
///
/// A dial has a timeout and an ESTABLISHED session had none, and those are
/// two different questions. A connection that is blackholed after it was
/// made — a fenced host, a route that changed under it, the source address
/// of the machine moving — accepts everything written to it, answers
/// nothing, and reports nothing: the kernel's socket is open, so
/// `tx.send` succeeds, the reconcile loop keeps running, and the read side
/// simply never wakes. Measured on manacor on 2026-09-10: the agent kept
/// working for **five minutes** while the controller counted it as gone
/// after thirty seconds, and only a restart of the unit ended it.
///
/// An HTTP/2 PING is the echo that answers it. No ping back within
/// [`KEEPALIVE_TIMEOUT`] and the connection is broken from below: the
/// stream ends with an error, the session loop falls out of its pump, and
/// the redial order is walked from the top — which is the behaviour both
/// tiers already have for every other way a session can end.
pub const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(10);

/// How long a session waits for the echo before it calls the connection dead.
///
/// [`KEEPALIVE_INTERVAL`] plus this is the worst case from "the wire went
/// black" to "this end knows", and it has to fit inside the liveness window
/// of the tier above — 30s, `controller_api::heartbeat::HEARTBEAT_TIMEOUT_SECS`,
/// spelled there and deliberately not shared with this crate, because the
/// agent does not depend on the controller. 15s of the 30 leaves the other
/// half for the redial to land somewhere and say Hello, so a black session
/// costs a node its heartbeat at worst once.
pub const KEEPALIVE_TIMEOUT: Duration = Duration::from_secs(5);

/// The settings every session endpoint in this stack takes, applied in one
/// place because all three tiers that dial out are the same loop.
///
/// `keep_alive_while_idle`: a session stream is open the whole time, so the
/// connection is never idle in HTTP/2's sense — but a session that has just
/// been dialled and not yet answered is, and that is exactly the window in
/// which the endpoint being black matters most.
fn session_endpoint(addr: &str) -> Result<Endpoint, tonic::transport::Error> {
    Ok(Endpoint::from_shared(addr.to_string())?
        .connect_timeout(DIAL_TIMEOUT)
        .http2_keep_alive_interval(KEEPALIVE_INTERVAL)
        .keep_alive_timeout(KEEPALIVE_TIMEOUT)
        .keep_alive_while_idle(true))
}

/// Open a plain channel to a session endpoint, bounded by `DIAL_TIMEOUT`.
///
/// Here rather than in each component because the two session loops are the
/// same loop one tier apart, and this is the one line of it that has nothing
/// to do with which messages travel over the result.
pub async fn dial(addr: &str) -> Result<Channel, tonic::transport::Error> {
    session_endpoint(addr)?.connect().await
}

/// The same dial with a credential, when there is one.
///
/// `None` is the plain dial above and the default: every session in this
/// stack ran that way for five milestones and the lab still does. It lives
/// here for the same reason `dial` does — all three tiers that dial out are
/// the same loop, and by M5 all three of them can carry a certificate.
pub async fn dial_tls(addr: &str, tls: Option<&ClientTlsConfig>) -> anyhow::Result<Channel> {
    let mut endpoint = session_endpoint(addr)?;
    if let Some(tls) = tls {
        endpoint = endpoint.tls_config(tls.clone())?;
    }
    Ok(endpoint.connect().await?)
}

/// Whom to trust on the other end, and who we are.
///
/// The CA is required and the identity is not: a peer that only verifies the
/// server still gets an encrypted session, and a peer with a certificate but
/// no CA to check the server against would authenticate itself to whoever
/// answered — which is why THAT combination is an error rather than a
/// half-configuration.
///
/// Reads PEM and nothing else. The permission check on the key is here
/// because this is the one function in this crate that opens a secret, and a
/// key the group can read is a key that has left the machine already —
/// same rule and same message as `pki::load_private_key`, which the tiers
/// that depend on `pki` go through instead.
pub fn client_tls(ca: &Path, identity: Option<(&Path, &Path)>) -> anyhow::Result<ClientTlsConfig> {
    // tonic's tls-ring path asks for the process-wide default provider and
    // panics without one. Idempotent, and the first gRPC handshake is a bad
    // place to find out it was never installed.
    let _ = rustls::crypto::ring::default_provider().install_default();

    let ca_pem =
        std::fs::read(ca).with_context(|| format!("reading the session CA {}", ca.display()))?;
    let mut config = ClientTlsConfig::new().ca_certificate(Certificate::from_pem(ca_pem));
    if let Some((cert, key)) = identity {
        check_key_permissions(key)?;
        let cert_pem =
            std::fs::read(cert).with_context(|| format!("reading {}", cert.display()))?;
        let key_pem = std::fs::read(key).with_context(|| format!("reading {}", key.display()))?;
        config = config.identity(Identity::from_pem(cert_pem, key_pem));
    }
    Ok(config)
}

#[cfg(unix)]
fn check_key_permissions(path: &Path) -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let meta = std::fs::metadata(path).with_context(|| format!("reading {}", path.display()))?;
    let mode = meta.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        anyhow::bail!(
            "permissions {:04o} on {} are too open; run: chmod 600 {}",
            mode,
            path.display(),
            path.display()
        );
    }
    Ok(())
}

#[cfg(not(unix))]
fn check_key_permissions(_path: &Path) -> anyhow::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use prost::Message;

    /// D-B1: a session that goes black has to be noticed before the tier above
    /// gives up on this node, and that is arithmetic rather than a feeling.
    ///
    /// The window is `controller_api::heartbeat::HEARTBEAT_TIMEOUT_SECS`, 30
    /// seconds, spelled here as a number for the reason `CANNOT_SERVE` is
    /// spelled here as a string: the agent does not depend on the controller,
    /// on purpose, so the constant cannot be shared. If that number ever moves,
    /// this test is what says these two have to move with it.
    #[test]
    fn a_black_session_is_noticed_with_time_to_spare_before_the_node_expires() {
        const LIVENESS_WINDOW: Duration = Duration::from_secs(30);
        let notice = KEEPALIVE_INTERVAL + KEEPALIVE_TIMEOUT;
        assert!(
            notice * 2 <= LIVENESS_WINDOW,
            "noticing takes {notice:?}, and the other half of the window is \
             what the redial needs to land somewhere and say Hello"
        );
        assert!(
            KEEPALIVE_TIMEOUT < KEEPALIVE_INTERVAL,
            "a ping that is still outstanding when the next one is due is a \
             connection nobody ever declares dead"
        );
        assert!(
            DIAL_TIMEOUT < notice,
            "an endpoint that never completes a handshake is the dial's \
             business, and it must give up first"
        );
    }

    /// The settings are on BOTH ways of dialling, because the difference
    /// between them is a certificate and nothing else. A session that was
    /// given TLS and no keepalive would be the lab's exact case — the agent
    /// there dials with a certificate.
    #[test]
    fn both_dials_build_the_same_endpoint() {
        assert!(session_endpoint("http://10.0.8.21:9443").is_ok());
        assert!(
            session_endpoint("not an endpoint at all").is_err(),
            "a bad address is refused here, before anything is connected"
        );
    }

    /// The VM half of a status report over the wire and back, with the two
    /// lists a node fills in it.
    ///
    /// `nics` is the one that needs saying: it is `repeated`, so an old peer
    /// sends no bytes for it at all and a new peer decodes that as the empty
    /// list — which is exactly the shape the controllers read as "this peer
    /// said nothing", never as "this VM has no addresses". The test asserts
    /// both directions of that: a report WITH taps survives whole, and a
    /// report encoded without the field decodes empty rather than failing.
    #[test]
    fn a_vm_status_report_carries_its_taps_over_the_wire() {
        let report = VmStatusReport {
            id: "6f1d5f7c-0000-4000-8000-00000000000a".into(),
            phase: "Running".into(),
            message: String::new(),
            attached_volumes: vec!["9d2b1a44-0000-4000-8000-00000000000b".into()],
            node: "manacor".into(),
            volumes: vec![VolumeAttachment {
                name: "data-1".into(),
                attached: true,
            }],
            // Empty on purpose: this is a `Running` line, and `Running`
            // needs no reason. The field has a test of its own below.
            reason: String::new(),
            nics: vec![
                NicReport {
                    name: "nics[0]".into(),
                    mac: "52:54:00:11:22:33".into(),
                },
                NicReport {
                    name: "nics[1]".into(),
                    mac: "52:54:00:aa:bb:cc".into(),
                },
            ],
        };
        let back = VmStatusReport::decode(report.encode_to_vec().as_slice()).unwrap();
        assert_eq!(back, report);

        // What an agent from before the field puts on the wire: the same
        // message with nothing where `nics` is. It decodes, and it decodes
        // empty.
        let old = VmStatusReport {
            nics: Vec::new(),
            ..report.clone()
        };
        let back = VmStatusReport::decode(old.encode_to_vec().as_slice()).unwrap();
        assert!(back.nics.is_empty());
        assert_eq!(back.attached_volumes, report.attached_volumes);

        // And it rides on the status both tiers already send.
        let status = StatusReport {
            vms: vec![report.clone()],
            routers: Vec::new(),
            ..Default::default()
        };
        let back = StatusReport::decode(status.encode_to_vec().as_slice()).unwrap();
        assert_eq!(back.vms, vec![report]);
    }

    /// The two messages the node half of the cloud tier is made of, over the
    /// wire and back. A map and an `optional bool` are the two shapes prost
    /// treats differently from everything else here, and both carry meaning:
    /// unset `schedulable` is "leave the drain as it is", which is not the
    /// same as `false`.
    #[test]
    fn a_node_report_and_an_update_survive_the_wire() {
        let report = NodeReport {
            name: "manacor".into(),
            ready: true,
            schedulable: false,
            drain: true,
            labels: [("zone".to_string(), "a".to_string())]
                .into_iter()
                .collect(),
            vcpus: 32,
            mem_mib: 64 * 1024,
            capabilities: vec!["nvrm/4q".into(), "network/vxlan".into()],
            accepts: vec!["router".into()],
            vms: 3,
            // The node's own word about itself, relayed. On the wire because
            // the tier above places on clusters and has to be able to tell a
            // cluster with a wedged machine from one with a free one.
            conditions: vec![NodeCondition {
                r#type: "StoreUnhealthy".into(),
                message: "the node's database refuses writes".into(),
            }],
            // The evidence of the drain the `drain` flag above only asked
            // for. A submessage rather than a flag, so absent is a real
            // answer and means "nobody is emptying this machine".
            draining: Some(DrainingReport {
                leaving: 1,
                leaving_vms: vec!["web-2".into()],
                moved_total: 4,
                staying: 2,
                complete: false,
                reasons: vec![StayingVm {
                    vm: "db-1".into(),
                    reason: "evacuation-never".into(),
                    message: "its owner said evacuation: never".into(),
                }],
            }),
        };
        let back = NodeReport::decode(report.encode_to_vec().as_slice()).unwrap();
        assert_eq!(back, report);

        // A cluster from before the field, and a machine nobody is emptying,
        // put the same thing on the wire: nothing. It has to decode as absent
        // rather than as a zeroed report, or the cloud would grow a drain
        // column reading `0 moved, 0 leaving, 0 staying` for every node in
        // the fleet.
        let quiet = NodeReport {
            draining: None,
            ..report.clone()
        };
        let back = NodeReport::decode(quiet.encode_to_vec().as_slice()).unwrap();
        assert_eq!(back.draining, None);
        assert!(back.drain, "and the ask beside it is untouched");

        let update = UpdateNode {
            name: "manacor".into(),
            schedulable: Some(false),
            drain: Some(true),
            labels: [("gpu".to_string(), "a100".to_string())]
                .into_iter()
                .collect(),
            remove_labels: vec!["zone".into()],
            accepts: Some(AcceptsUpdate {
                classes: vec!["router".into()],
            }),
        };
        let back = UpdateNode::decode(update.encode_to_vec().as_slice()).unwrap();
        assert_eq!(back, update);

        // Saying nothing about the cordon or the drain is not saying false.
        let labels_only = UpdateNode {
            schedulable: None,
            drain: None,
            accepts: None,
            ..update.clone()
        };
        let back = UpdateNode::decode(labels_only.encode_to_vec().as_slice()).unwrap();
        assert_eq!(back.schedulable, None);
        assert_eq!(back.drain, None, "and the drain is the same shape");
        assert_eq!(back.accepts, None, "and so is the classes list");

        // The classes are a SUBMESSAGE for exactly this: present-and-empty is
        // "take everything again", which a bare repeated field could not tell
        // from "said nothing about it".
        let open_again = UpdateNode {
            accepts: Some(AcceptsUpdate::default()),
            ..update.clone()
        };
        let back = UpdateNode::decode(open_again.encode_to_vec().as_slice()).unwrap();
        assert_eq!(back.accepts, Some(AcceptsUpdate::default()));
        assert!(back.accepts.expect("present").classes.is_empty());

        // And the report rides on the status the cluster already sends.
        let status = ClusterStatus {
            nodes: vec![report.clone()],
            ..Default::default()
        };
        let back = ClusterStatus::decode(status.encode_to_vec().as_slice()).unwrap();
        assert_eq!(back.nodes, vec![report]);
    }

    /// The router's road between the two control planes: down as a decision,
    /// up as a report — and the two fields that are filled on THIS road and
    /// empty on the one below it.
    #[test]
    fn a_router_travels_down_as_a_decision_and_back_as_a_report() {
        let create = CreateRouter {
            name: "lab-out".into(),
            spec_json: r#"{"tenant":"lab","providerNetwork":"ext"}"#.into(),
            uid: "u-7".into(),
            network_name: "ext".into(),
            network_json: r#"{"physnet":"ext","cidr":"10.128.1.0/24"}"#.into(),
            external_addr: "10.128.1.200/24".into(),
            nats: vec![
                NatRule {
                    kind: "snat".into(),
                    external_ip: "10.128.1.200".into(),
                    logical_ip: "10.42.0.0/24".into(),
                },
                NatRule {
                    kind: "routed".into(),
                    external_ip: String::new(),
                    logical_ip: "10.43.0.0/24".into(),
                },
            ],
            announced: vec!["10.43.0.0/24".into()],
        };
        let back = CreateRouter::decode(create.encode_to_vec().as_slice()).unwrap();
        assert_eq!(back, create);

        let delete = DeleteRouter {
            name: "lab-out".into(),
            uid: "u-7".into(),
        };
        let back = DeleteRouter::decode(delete.encode_to_vec().as_slice()).unwrap();
        assert_eq!(back, delete);

        // Both ride in the same envelope everything else does.
        let command = CloudCommand {
            request_id: "r-1".into(),
            traceparent: String::new(),
            op: Some(cloud_command::Op::CreateRouter(create.clone())),
        };
        let back = CloudCommand::decode(command.encode_to_vec().as_slice()).unwrap();
        assert_eq!(back.op, Some(cloud_command::Op::CreateRouter(create)));

        // And the report comes back with the machine on it. `node` and
        // `nodes` are what the road one tier down leaves empty — a node
        // naming itself to the controller that addressed it says nothing —
        // so a report from an AGENT has to decode with both empty and still
        // carry its phase.
        let report = RouterReport {
            id: "u-7".into(),
            phase: "Active".into(),
            reason: String::new(),
            message: String::new(),
            active: true,
            node: "agent-1b".into(),
            nodes: vec!["agent-1b".into(), "agent-1c".into()],
        };
        let back = RouterReport::decode(report.encode_to_vec().as_slice()).unwrap();
        assert_eq!(back, report);

        let from_a_node = RouterReport {
            node: String::new(),
            nodes: Vec::new(),
            ..report.clone()
        };
        let back = RouterReport::decode(from_a_node.encode_to_vec().as_slice()).unwrap();
        assert!(back.node.is_empty() && back.nodes.is_empty());
        assert_eq!(back.phase, "Active");

        let status = ClusterStatus {
            routers: vec![report.clone()],
            routers_complete: true,
            ..Default::default()
        };
        let back = ClusterStatus::decode(status.encode_to_vec().as_slice()).unwrap();
        assert_eq!(back.routers, vec![report]);
        assert!(back.routers_complete);
    }
    /// `reason` on all five reports, both directions, and what a reporter
    /// from before the field looks like.
    ///
    /// The word is a STRING on the wire and not an enum, so the compatibility
    /// question is not "does it parse" but "does an empty one read as
    /// silence": every phase that needs no reason sends nothing at all, and so
    /// does every agent and every cluster built before this round. Both have
    /// to decode as the empty string and never as an error, because one old
    /// reporter in a fleet may not break a list.
    ///
    /// The five are the five that carry a phase upwards. `reason` sits beside
    /// `message` on each and replaces nothing: the message is the sentence an
    /// operator reads, this is the word a program branches on.
    #[test]
    fn every_report_carries_its_reason_and_an_empty_one_is_silence() {
        let vm = VmStatusReport {
            id: "6f1d5f7c-0000-4000-8000-00000000000a".into(),
            phase: "Provisioning".into(),
            reason: "Backoff".into(),
            message: "the volume driver said no".into(),
            ..Default::default()
        };
        let volume = VolumeStateReport {
            id: "9d2b1a44-0000-4000-8000-00000000000b".into(),
            phase: "Failed".into(),
            reason: "NotOnBackend".into(),
            ..Default::default()
        };
        let image = ImageStateReport {
            name: "nixos.raw".into(),
            phase: "Failed".into(),
            reason: "NotFound".into(),
            ..Default::default()
        };
        let router = RouterReport {
            id: "u-7".into(),
            phase: "Failed".into(),
            reason: "NetnsGone".into(),
            ..Default::default()
        };
        let pool = StoragePoolStatusReport {
            name: "mc-fs".into(),
            phase: "Pending".into(),
            reason: "ClusterHasNoPool".into(),
            ..Default::default()
        };

        let status = StatusReport {
            vms: vec![vm.clone()],
            volumes: vec![volume.clone()],
            images: vec![image.clone()],
            routers: vec![router.clone()],
            ..Default::default()
        };
        let back = StatusReport::decode(status.encode_to_vec().as_slice()).unwrap();
        assert_eq!(back.vms, vec![vm.clone()]);
        assert_eq!(back.volumes, vec![volume]);
        assert_eq!(back.images, vec![image]);
        assert_eq!(back.routers, vec![router]);

        // The pool's road is the cluster's, one tier further up, and the same
        // field travels there.
        let cluster = ClusterStatus {
            pools: vec![pool.clone()],
            ..Default::default()
        };
        let back = ClusterStatus::decode(cluster.encode_to_vec().as_slice()).unwrap();
        assert_eq!(back.pools, vec![pool]);

        // And what a reporter that predates the field sends: nothing where
        // the word would be. It decodes empty, which is what every reader
        // reads as "did not say".
        let old = VmStatusReport {
            reason: String::new(),
            ..vm
        };
        let back = VmStatusReport::decode(old.encode_to_vec().as_slice()).unwrap();
        assert!(back.reason.is_empty());
        assert_eq!(back.phase, "Provisioning");
        assert_eq!(back.message, "the volume driver said no");
    }
}
