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

/// Wire reason for structural node refusal before creating a VM record.
/// Controllers may then release placement and choose another node. An
/// empty legacy reason retains the conservative same-node failure path.
pub const CANNOT_SERVE: &str = "CannotServe";

/// Node router readiness vocabulary, distinct from the controller's
/// Active/Standby/Unknown placement phases. Controllers combine readiness
/// with their active-node decision.
pub const ROUTER_READY: &str = "Ready";

/// `RouterReport.phase` for a router this node cannot serve right now: the
/// namespace is gone, or a leg of it is. See [`ROUTER_READY`].
pub const ROUTER_FAILED: &str = "Failed";

/// Node reason vocabulary shared across the wire. Tests compare agent
/// enums with these lists and require controller reason enums to parse them.
/// Storage-pool reasons are derived by the cluster from driver reports.
pub mod reasons {
    /// `VmStatusReport.reason`. Derived fresh on every heartbeat out of what
    /// `observe` sees, so `Unrecorded` here means a RECORD from another build
    /// of the agent, not a missing field.
    pub const VM: &[&str] = &[
        "Working",
        "Backoff",
        "AwaitingGuest",
        "GuestLeft",
        "ReceiveFailed",
        "VmmGone",
        "BackendGone",
        "ResumeIneffective",
        "Stopping",
        "Unrecorded",
    ];

    /// `VolumeStateReport.reason`, written onto the node's own volume record
    /// by the pass that asked the driver.
    pub const VOLUME: &[&str] = &[
        "Working",
        "DriverRefused",
        "NotOnBackend",
        "Deprovisioned",
        "Unrecorded",
    ];

    /// `SnapshotStateReport.reason`. The volume's words minus the one a copy
    /// cannot be in: only `adopt` finds `NotOnBackend` and it walks volumes.
    pub const SNAPSHOT: &[&str] = &["Working", "DriverRefused", "Dropped", "Unrecorded"];

    /// `ImageStateReport.reason`. No `Unrecorded`: the node's image table is
    /// held in memory and re-derived from the disk, so there is no stored
    /// opinion from an older build for one to come out of.
    pub const IMAGE: &[&str] = &["NotFound", "NotAFile", "ChecksumMismatch", "FetchFailed"];

    /// Router failure reasons distinguish missing state from an unsuccessful probe.
    pub const ROUTER: &[&str] = &["NetnsGone", "LegGone", "DriverUnreachable"];

    /// The five lists with the name of the resource each belongs to, for a
    /// guard that wants to walk all of them.
    pub const ALL: [(&str, &[&str]); 5] = [
        ("Vm", VM),
        ("Volume", VOLUME),
        ("Snapshot", SNAPSHOT),
        ("Image", IMAGE),
        ("Router", ROUTER),
    ];
}

/// Connection deadline before trying the next preferred endpoint.
/// Bounds blackholed connections that would otherwise wait for TCP retries.
pub const DIAL_TIMEOUT: Duration = Duration::from_secs(3);

/// HTTP/2 keepalive interval for established sessions. A missing reply
/// within KEEPALIVE_TIMEOUT ends the transport and allows redial.
pub const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(10);

/// HTTP/2 ping-response deadline. The configured interval plus this
/// deadline is below the controller heartbeat window; scheduling and
/// reconnection time can still delay recovery.
pub const KEEPALIVE_TIMEOUT: Duration = Duration::from_secs(5);

/// Apply shared dial and keepalive settings. Idle keepalive also covers
/// the interval before an established connection starts its session stream.
fn session_endpoint(addr: &str) -> Result<Endpoint, tonic::transport::Error> {
    Ok(Endpoint::from_shared(addr.to_string())?
        .connect_timeout(DIAL_TIMEOUT)
        .http2_keep_alive_interval(KEEPALIVE_INTERVAL)
        .keep_alive_timeout(KEEPALIVE_TIMEOUT)
        .keep_alive_while_idle(true))
}

/// Open a plain session channel within DIAL_TIMEOUT.
pub async fn dial(addr: &str) -> Result<Channel, tonic::transport::Error> {
    session_endpoint(addr)?.connect().await
}

/// Open a session channel with optional TLS; None selects plain transport.
pub async fn dial_tls(addr: &str, tls: Option<&ClientTlsConfig>) -> anyhow::Result<Channel> {
    let mut endpoint = session_endpoint(addr)?;
    if let Some(tls) = tls {
        endpoint = endpoint.tls_config(tls.clone())?;
    }
    Ok(endpoint.connect().await?)
}

/// Load a required server CA and optional client identity from PEM.
/// Reject private keys with group/world permissions. A client certificate
/// without server verification is not a supported partial configuration.
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

    /// Keep configured ping timing below the 30-second controller heartbeat
    /// window. This checks constants, not runtime failure-detection latency.
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

    /// Plain and TLS dial paths use the same keepalive configuration.
    #[test]
    fn both_dials_build_the_same_endpoint() {
        assert!(session_endpoint("http://10.0.8.21:9443").is_ok());
        assert!(
            session_endpoint("not an endpoint at all").is_err(),
            "a bad address is refused here, before anything is connected"
        );
    }

    /// Round-trip VM NIC reports and verify omitted repeated fields decode
    /// as empty for legacy senders. Empty reports must not invent address evidence.
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

    /// Round-trip node control fields. Missing schedulable means unchanged,
    /// not false; optional presence must survive encoding.
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
            // F16's half of the message: whether this node's share of
            // `ClusterStatus.images` is EVERY file under its image directory.
            // Only then may the cloud read a missing name as a missing file.
            images_complete: true,
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

        // Missing legacy drain fields remain absent rather than a zeroed report.
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

        // Agent reports omit cluster placement fields while retaining router phase.
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

    /// Image deletion carries the same registration name and UID through
    /// cloud-to-cluster and cluster-to-agent command envelopes.
    #[test]
    fn a_dropped_image_names_the_same_uid_on_both_hops() {
        let drop = DropImage {
            name: "ubuntu.raw".into(),
            uid: "4f3c0000-0000-0000-0000-00000000000a".into(),
        };

        let cloud_command = CloudCommand {
            request_id: "req-1".into(),
            traceparent: String::new(),
            op: Some(cloud_command::Op::DropImage(drop.clone())),
        };
        let back = CloudCommand::decode(cloud_command.encode_to_vec().as_slice()).unwrap();
        assert_eq!(back.op, Some(cloud_command::Op::DropImage(drop.clone())));

        let command = Command {
            request_id: "req-1".into(),
            traceparent: String::new(),
            op: Some(command::Op::DropImage(drop.clone())),
        };
        let back = Command::decode(command.encode_to_vec().as_slice()).unwrap();
        assert_eq!(back.op, Some(command::Op::DropImage(drop)));
    }

    /// URL image reports and older senders can omit the digest. Empty is
    /// missing evidence; fetched URL images use the configured checksum.
    #[test]
    fn an_images_digest_is_empty_unless_a_node_bound_one() {
        let image = ImageStateReport {
            name: "nixos.raw".into(),
            phase: "Ready".into(),
            digest: "a".repeat(64),
            ..Default::default()
        };
        let back = ImageStateReport::decode(image.encode_to_vec().as_slice()).unwrap();
        assert_eq!(back.digest, "a".repeat(64));

        let from_before_the_field = ImageStateReport {
            digest: String::new(),
            ..image
        };
        let back =
            ImageStateReport::decode(from_before_the_field.encode_to_vec().as_slice()).unwrap();
        assert!(back.digest.is_empty());
    }

    /// Round-trip reason strings on all phase-bearing reports. Missing
    /// legacy fields decode empty; messages remain separate operator details.
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
            images_complete: true,
            routers: vec![router.clone()],
            ..Default::default()
        };
        let back = StatusReport::decode(status.encode_to_vec().as_slice()).unwrap();
        assert_eq!(back.vms, vec![vm.clone()]);
        assert_eq!(back.volumes, vec![volume]);
        assert_eq!(back.images, vec![image]);
        assert_eq!(back.routers, vec![router]);
        // The flag that lets a reader turn a missing name into a missing
        // file. A node from before it sends nothing, which decodes `false` —
        // and `false` is the value nobody may conclude anything from.
        assert!(back.images_complete);
        assert!(
            !StatusReport::decode(
                StatusReport {
                    images: status.images.clone(),
                    ..Default::default()
                }
                .encode_to_vec()
                .as_slice()
            )
            .unwrap()
            .images_complete
        );

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
