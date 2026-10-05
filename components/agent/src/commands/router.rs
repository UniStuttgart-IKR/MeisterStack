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
    })
}

impl Agent {
    /// Validate the provider-network capability, then ensure the router under
    /// the operations lock. Repeated ensure requests also update active/standby state.
    pub(super) async fn handle_ensure_router(&self, r: proto::EnsureRouter) -> anyhow::Result<()> {
        let spec = router_spec(r)?;
        cannot_serve(self.network.validate_router(&spec.physnet))?;
        let bridge = cannot_serve(
            self.reconciler
                .drivers()
                .bridge()
                .context("this node cannot build a router"),
        )?;
        // Serialize router creation with VM provisioning because both mutate shared bridges.
        // The driver bounds every ip/nft call it makes, so a wedged one cannot hold this lock
        // indefinitely (R3-F08).
        let _guard = self.ops.lock().await;
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
}
