// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Translate router commands into the network-driver contract and serialize
//! router changes with VM resource operations. Unknown NAT kinds are refused.

use super::*;
use agent_api::networking::{NatKind, NatRule, RouterId, RouterSpec};

/// Wire encoding for routed prefixes: `logical_ip` carries the prefix and
/// `external_ip` is unused. These entries become announcements, not NAT rules.
const NAT_ROUTED: &str = "routed";

/// Convert a router command to the driver spec, rejecting unknown NAT kinds.
pub(crate) fn router_spec(r: proto::EnsureRouter) -> anyhow::Result<RouterSpec> {
    let id: RouterId = r.id.parse().context("router id")?;
    let mut nats = Vec::new();
    let mut routed_subnets = Vec::new();
    for nat in r.nats {
        if nat.kind == NAT_ROUTED {
            routed_subnets.push(nat.logical_ip);
            continue;
        }
        let kind = NatKind::parse(&nat.kind).ok_or_else(|| {
            anyhow!(
                "router {id} has a nat rule of kind {:?}; this agent knows {}, {} and {}",
                nat.kind,
                NatKind::Snat.as_str(),
                NatKind::DnatAndSnat.as_str(),
                NAT_ROUTED
            )
        })?;
        nats.push(NatRule {
            kind,
            external_ip: nat.external_ip,
            logical_ip: nat.logical_ip,
        });
    }
    Ok(RouterSpec {
        id,
        physnet: r.physnet,
        external_addr: r.external_addr,
        external_gateway: r.external_gateway,
        vxlan_id: r.vni,
        internal_addr: r.internal_addr,
        nats,
        routed_subnets,
        active: r.active,
        sole_gateway: r.sole_gateway,
    })
}

/// Read a router command after taking back what it withdraws, before anything in it can be
/// refused (NL2-2, NL-A2).
///
/// Everything else in the command can be refused (a NAT kind from a newer controller, a
/// provider network this node no longer serves). A refused demotion would leave the old
/// namespace answering ARP for an address the controller has made active on another node, and
/// a refused withdrawal of the sole-gateway claim would leave the dead man keeping the router
/// answering while another node claims its provider network (IKR-B76). The driver's own pass
/// takes both back again as its first steps.
async fn read_after_withdrawals(
    bridge: Option<&dyn agent_api::networking::BridgeDriver>,
    r: proto::EnsureRouter,
) -> anyhow::Result<RouterSpec> {
    take_back_withdrawn(bridge, &r).await?;
    router_spec(r)
}

/// Take back what a router command withdraws, by the router's id alone: the sole-gateway claim
/// the command no longer makes, then a demotion's silencing. Both are tried even when the first
/// fails, and the first failure is the answer. Only an id that does not parse names no router.
/// A node without a bridge driver built none.
async fn take_back_withdrawn(
    bridge: Option<&dyn agent_api::networking::BridgeDriver>,
    r: &proto::EnsureRouter,
) -> anyhow::Result<()> {
    let Some(bridge) = bridge else {
        return Ok(());
    };
    if r.sole_gateway && r.active {
        return Ok(());
    }
    let id: RouterId = r.id.parse().context("router id")?;
    let withdrawn = match r.sole_gateway {
        true => Ok(()),
        false => bridge
            .withdraw_sole_gateway(&id)
            .await
            .with_context(|| format!("withdrawing router {id}'s sole-gateway claim")),
    };
    let silenced = match r.active {
        true => Ok(()),
        false => bridge
            .silence_router(&id)
            .await
            .with_context(|| format!("silencing router {id} ahead of its demotion")),
    };
    withdrawn.and(silenced)
}

impl Agent {
    /// Take back what the command withdraws first (a demotion, the sole-gateway claim), then
    /// validate the provider-network capability and ensure the router under the operations
    /// lock. Repeated ensure requests also update active/standby state.
    pub(super) async fn handle_ensure_router(&self, r: proto::EnsureRouter) -> anyhow::Result<()> {
        // Serialize router changes with VM provisioning because both mutate shared bridges, the
        // silencing of a demotion included. The driver bounds every ip/nft call, so a wedged one
        // cannot hold this lock (R3-F08).
        let _guard = self.ops.lock().await;
        let spec = read_after_withdrawals(self.reconciler.drivers().bridge.as_deref(), r).await?;
        cannot_serve(self.network.validate_router(&spec.physnet))?;
        let bridge = cannot_serve(
            self.reconciler
                .drivers()
                .bridge()
                .context("this node cannot build a router"),
        )?;
        let state = bridge
            .ensure_router(&spec)
            .await
            .with_context(|| format!("building router {}", spec.id))?;
        info!(
            router = %state.id, location = %state.location, phase = state.phase.as_str(),
            active = state.active, announce = state.announce.len(),
            "router ensured"
        );
        Ok(())
    }

    /// Destroy a router idempotently; an absent router is already removed.
    pub(super) async fn handle_destroy_router(
        &self,
        r: proto::DestroyRouter,
    ) -> anyhow::Result<()> {
        let id: RouterId = r.id.parse().context("router id")?;
        let Some(bridge) = self.reconciler.drivers().bridge.as_ref() else {
            // Without a networking driver, there is no local router to remove.
            return Ok(());
        };
        let _guard = self.ops.lock().await;
        bridge
            .destroy_router(&id)
            .await
            .with_context(|| format!("removing router {id}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn message() -> proto::EnsureRouter {
        proto::EnsureRouter {
            id: "1a2b3c4d-5e6f-0000-0000-000000000000".into(),
            physnet: "ext".into(),
            external_addr: "203.0.113.10/24".into(),
            external_gateway: "203.0.113.1".into(),
            vni: 10_000,
            internal_addr: "10.7.1.1/24".into(),
            nats: Vec::new(),
            active: true,
            sole_gateway: false,
        }
    }

    fn nat(kind: &str, external: &str, logical: &str) -> proto::NatRule {
        proto::NatRule {
            kind: kind.into(),
            external_ip: external.into(),
            logical_ip: logical.into(),
        }
    }

    /// Preserve router-command fields in the driver specification.
    #[test]
    fn an_ensure_router_becomes_the_spec_a_driver_is_given() {
        let spec = router_spec(message()).expect("a well-formed message");
        assert_eq!(spec.id.to_string(), "1a2b3c4d-5e6f-0000-0000-000000000000");
        assert_eq!(spec.physnet, "ext");
        assert_eq!(spec.external_addr, "203.0.113.10/24");
        assert_eq!(spec.external_gateway, "203.0.113.1");
        assert_eq!(spec.vxlan_id, 10_000);
        assert_eq!(spec.internal_addr, "10.7.1.1/24");
        assert!(spec.active);
        assert!(spec.nats.is_empty() && spec.routed_subnets.is_empty());
        assert!(!spec.sole_gateway);
    }

    /// IKR-B76: the controller's word that no other node can take the router over reaches the
    /// driver, whose dead man reads it off the record.
    #[test]
    fn a_sole_gateway_reaches_the_driver() {
        let mut m = message();
        m.sole_gateway = true;
        assert!(router_spec(m).expect("a well-formed message").sole_gateway);
    }

    /// OVN's two kinds, spelled the way the contract spells them.
    #[test]
    fn both_nat_kinds_arrive_typed() {
        let mut m = message();
        m.nats = vec![
            nat("snat", "203.0.113.10", ""),
            nat("dnat_and_snat", "203.0.113.55", "10.7.1.9"),
        ];
        let spec = router_spec(m).expect("two rules this build knows");
        assert_eq!(spec.nats.len(), 2);
        assert_eq!(spec.nats[0].kind, NatKind::Snat);
        assert_eq!(spec.nats[1].kind, NatKind::DnatAndSnat);
        assert_eq!(spec.nats[1].logical_ip, "10.7.1.9");
    }

    /// The routed subnets, in the shape the contract had no field for: they
    /// leave the NAT list and become the announcement list. See `NAT_ROUTED`.
    #[test]
    fn a_routed_subnet_is_not_a_nat_rule_and_does_not_become_one() {
        let mut m = message();
        m.nats = vec![
            nat("snat", "203.0.113.10", ""),
            nat("routed", "", "10.7.2.0/24"),
        ];
        let spec = router_spec(m).expect("one rule and one prefix");
        assert_eq!(spec.routed_subnets, ["10.7.2.0/24"]);
        assert_eq!(spec.nats.len(), 1, "the prefix is not a translation");
        assert_eq!(spec.nats[0].kind, NatKind::Snat);
    }

    /// Reject unknown NAT kinds and include the invalid value in the error.
    #[test]
    fn a_nat_kind_this_build_does_not_know_is_refused_by_name() {
        let mut m = message();
        m.nats = vec![nat("dnat-and-snat", "203.0.113.55", "10.7.1.9")];
        let err = router_spec(m).expect_err("not a kind").to_string();
        assert!(err.contains("dnat-and-snat"), "{err}");
        assert!(
            err.contains("snat") && err.contains("routed"),
            "it says what it does know: {err}"
        );
    }

    #[test]
    fn an_id_that_is_not_an_id_is_refused_before_anything_is_built() {
        let mut m = message();
        m.id = "not-a-uuid".into();
        assert!(router_spec(m).is_err());
    }

    /// A bridge that records the routers it was told to silence and whose sole-gateway claim
    /// it was told to withdraw, or refuses either.
    #[derive(Default)]
    struct RecordingBridge {
        silenced: std::sync::Mutex<Vec<RouterId>>,
        withdrawn: std::sync::Mutex<Vec<RouterId>>,
        refuse_silence: bool,
        refuse_withdrawal: bool,
    }

    fn denied() -> agent_api::networking::NetworkError {
        agent_api::networking::NetworkError::Backend(anyhow!("permission denied"))
    }

    #[async_trait::async_trait]
    impl agent_api::networking::BridgeDriver for RecordingBridge {
        async fn ensure(&self, _name: &str) -> agent_api::networking::Result<()> {
            Ok(())
        }
        async fn ensure_address(
            &self,
            _name: &str,
            _addr: std::net::IpAddr,
            _prefix_len: u8,
        ) -> agent_api::networking::Result<()> {
            Ok(())
        }
        async fn destroy(&self, _name: &str) -> agent_api::networking::Result<()> {
            Ok(())
        }
        async fn silence_router(&self, id: &RouterId) -> agent_api::networking::Result<()> {
            if self.refuse_silence {
                return Err(denied());
            }
            self.silenced.lock().unwrap().push(*id);
            Ok(())
        }
        async fn withdraw_sole_gateway(&self, id: &RouterId) -> agent_api::networking::Result<()> {
            if self.refuse_withdrawal {
                return Err(denied());
            }
            self.withdrawn.lock().unwrap().push(*id);
            Ok(())
        }
    }

    /// A demotion this agent cannot read is silenced all the same, by its id (NL2-2, NL3-6).
    #[tokio::test]
    async fn a_demotion_the_agent_refuses_to_read_is_silenced_all_the_same() {
        let mut m = message();
        m.active = false;
        m.nats = vec![nat("dnat-and-snat", "203.0.113.55", "10.7.1.9")];
        let id: RouterId = m.id.parse().unwrap();
        let bridge = RecordingBridge::default();

        let err = read_after_withdrawals(Some(&bridge), m)
            .await
            .expect_err("the rest of it is refused");

        assert!(err.to_string().contains("dnat-and-snat"), "{err:#}");
        assert_eq!(*bridge.silenced.lock().unwrap(), [id]);
    }

    /// A promotion is read without silencing anything: the router is about to answer.
    #[tokio::test]
    async fn a_promotion_is_read_without_silencing_the_router() {
        let bridge = RecordingBridge::default();

        let spec = read_after_withdrawals(Some(&bridge), message())
            .await
            .expect("a well-formed promotion");

        assert!(spec.active);
        assert!(bridge.silenced.lock().unwrap().is_empty());
    }

    /// A demotion that cannot be silenced goes no further: the error is the answer (NL2-2).
    #[tokio::test]
    async fn a_demotion_that_cannot_be_silenced_is_an_error() {
        let mut m = message();
        m.active = false;
        let bridge = RecordingBridge {
            refuse_silence: true,
            ..Default::default()
        };

        let err = read_after_withdrawals(Some(&bridge), m)
            .await
            .expect_err("a router that may still answer is not demoted");

        assert!(format!("{err:#}").contains("permission denied"), "{err:#}");
    }

    /// NL-A2: an active router's command that no longer makes the sole-gateway claim and that
    /// this agent refuses to read withdraws the claim all the same, by the router's id, so the
    /// dead man does not keep the router answering for it.
    #[tokio::test]
    async fn a_withdrawn_sole_gateway_claim_is_taken_back_although_the_command_is_refused() {
        let mut m = message();
        m.nats = vec![nat("dnat-and-snat", "203.0.113.55", "10.7.1.9")];
        let id: RouterId = m.id.parse().unwrap();
        let bridge = RecordingBridge::default();

        let err = read_after_withdrawals(Some(&bridge), m)
            .await
            .expect_err("the rest of it is refused");

        assert!(err.to_string().contains("dnat-and-snat"), "{err:#}");
        assert_eq!(*bridge.withdrawn.lock().unwrap(), [id]);
        assert!(
            bridge.silenced.lock().unwrap().is_empty(),
            "and an active router is not silenced"
        );
    }

    /// A command that makes the sole-gateway claim withdraws nothing: the pass records it.
    #[tokio::test]
    async fn a_sole_gateway_command_is_read_without_withdrawing_its_claim() {
        let mut m = message();
        m.sole_gateway = true;
        let bridge = RecordingBridge::default();

        read_after_withdrawals(Some(&bridge), m)
            .await
            .expect("a well-formed command");

        assert!(bridge.withdrawn.lock().unwrap().is_empty());
    }

    /// A demotion whose claim cannot be withdrawn is silenced all the same, and the failed
    /// withdrawal is the answer.
    #[tokio::test]
    async fn a_demotion_whose_claim_cannot_be_withdrawn_is_silenced_all_the_same() {
        let mut m = message();
        m.active = false;
        let id: RouterId = m.id.parse().unwrap();
        let bridge = RecordingBridge {
            refuse_withdrawal: true,
            ..Default::default()
        };

        let err = read_after_withdrawals(Some(&bridge), m)
            .await
            .expect_err("a claim that may stand is not withdrawn");

        assert!(format!("{err:#}").contains("sole-gateway claim"), "{err:#}");
        assert_eq!(*bridge.silenced.lock().unwrap(), [id]);
    }
}
