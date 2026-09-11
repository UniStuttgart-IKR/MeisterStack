// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! The two verbs about a tenant router, and the translation in front of them.
//!
//! Everything here is either a refusal or one call into the network driver's
//! trait. This file holds no idea of a namespace, a veth or an nft rule —
//! that is `drivers/linux-network`, and the whole reason the gateway slot is
//! six trait methods is that a second backend (OVN, a DPU offload) answers
//! them with a logical router and nothing in this file changes.
//!
//! ## What the wire says and what a driver is given
//!
//! `EnsureRouter` is protobuf; `RouterSpec` is what a driver takes. The
//! translation is a pure function so that WHICH spec a message produces can
//! be asserted without a node — the same shape `NicWithId::try_from` has for
//! the NIC half.

use super::*;
use agent_api::networking::{NatKind, NatRule, RouterId, RouterSpec};

/// The `NatRule.kind` that is not a NAT at all.
///
/// **What the contract did not have.** Festlegung 5 gives a router two jobs:
/// translate (`snat`, `dnat_and_snat`) and ANNOUNCE — a routed subnet gets no
/// NAT, the prefix is simply advertised by every active router of the subnet.
/// `EnsureRouter` has no field for that list, and `shared/proto` is locked for
/// both construction sites of 6k, so the prefixes ride in as rules of a third
/// kind: `logical_ip` is the prefix and `external_ip` is empty.
///
/// It is a proposal and not a fact yet — the cluster half has to send it, and
/// the report says so. The alternative, once the contract may move, is one
/// `repeated string routed_subnets` on `EnsureRouter`, at which point this
/// constant becomes a compatibility branch and nothing else.
const NAT_ROUTED: &str = "routed";

/// One `EnsureRouter` as a driver takes it.
///
/// Refuses rather than drops, everywhere. A NAT kind this build does not know
/// is a rule that would silently not be applied — the tier above would see a
/// Ready router that translates nothing — so it is an error naming the string.
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
    /// Build the router, or say why this node never can.
    ///
    /// Idempotent by id exactly as `Create` is: the controller sends it once
    /// and repeats it on every reconnect, and the standby's promotion is the
    /// same message with `active = true`.
    ///
    /// The physnet is checked HERE and not in the driver, and the difference
    /// is the word `CannotServe`: "this node gave no interface away to `ext`"
    /// is a fact about the node that the next attempt will not change, so the
    /// cluster has to stop counting this node as a candidate — N-C3 makes it
    /// a Condition. Everything the driver refuses afterwards is about this
    /// attempt and is answered where it happened.
    pub(super) async fn handle_ensure_router(&self, r: proto::EnsureRouter) -> anyhow::Result<()> {
        let spec = router_spec(r)?;
        cannot_serve(self.network.validate_router(&spec.physnet))?;
        let bridge = cannot_serve(
            self.reconciler
                .drivers()
                .bridge()
                .context("this node cannot build a router"),
        )?;
        // One lock for the whole build, the same one every other mutating
        // verb takes: a router's legs join bridges that a VM's provisioning
        // is also making, and two of those at once on one node is two
        // netlink conversations about the same link.
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

    /// Let the router go. Idempotent by contract: one this node does not hold
    /// is `Ok`, because a teardown of something that is not there has already
    /// happened.
    pub(super) async fn handle_destroy_router(
        &self,
        r: proto::DestroyRouter,
    ) -> anyhow::Result<()> {
        let id: RouterId = r.id.parse().context("router id")?;
        let Some(bridge) = self.reconciler.drivers().bridge.as_ref() else {
            // No network driver at all: this node built no router and has
            // none to remove. Saying so as a failure would leave the tier
            // above retrying a removal for ever.
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

    /// The whole message, field for field, in the form a driver takes.
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

    /// A kind this build cannot render is a refusal naming the string, never
    /// a rule quietly left out: the tier above would otherwise see a Ready
    /// router that translates nothing.
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
