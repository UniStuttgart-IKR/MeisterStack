// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! `ProviderNetwork` and `Router`: the objects, their rows and their verbs.
//!
//! One file, as the two handlers at the cloud are: a provider network is what
//! an operator gave away and a router is a tenant's way out over one, and
//! reading either row without the other tells half a story.

use super::*;

#[derive(Deserialize)]
pub(super) struct ProviderNetwork {
    metadata: Meta,
    #[serde(default)]
    spec: ProviderNetworkSpec,
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub(super) struct ProviderNetworkSpec {
    #[serde(default)]
    physnet: String,
    #[serde(default)]
    cidr: String,
    #[serde(default)]
    gateway: String,
    #[serde(default)]
    allocation: Vec<String>,
    #[serde(default)]
    description: String,
}

pub(super) fn provider_network_row(n: ProviderNetwork) -> Vec<String> {
    vec![
        n.metadata.name,
        n.spec.physnet,
        or_dash(Some(n.spec.cidr).filter(|v| !v.is_empty())),
        or_dash(Some(n.spec.gateway).filter(|v| !v.is_empty())),
        joined(&n.spec.allocation),
        n.spec.description,
    ]
}

pub async fn provider_network(ctx: &Ctx<'_>, cmd: &ProviderNetworkCmd) -> Result<()> {
    let ProviderNetworkCmd::Create {
        name,
        physnet,
        cidr,
        gateway,
        allocation,
        description,
    } = cmd
    else {
        unreachable!("dispatched generically")
    };
    let mut object = json!({
        "apiVersion": "meister.io/v1",
        "kind": "ProviderNetwork",
        "metadata": { "name": name },
        "spec": {
            // The physnet is what joins this object to an interface out
            // there, so it defaults to the object's own name: an operator who
            // calls the network `ext` and the physnet `ext` should type it
            // once.
            "physnet": physnet.clone().unwrap_or_else(|| name.clone()),
            "description": description.clone().unwrap_or_default(),
        },
    });
    if let Some(cidr) = cidr {
        object["spec"]["cidr"] = json!(cidr);
    }
    if let Some(gateway) = gateway {
        object["spec"]["gateway"] = json!(gateway);
    }
    if !allocation.is_empty() {
        object["spec"]["allocation"] = json!(allocation);
    }
    let body = ctx.post("providernetworks", object).await?;
    output::emit_note(
        ctx.global,
        &body,
        name,
        "note: a node offers this network by naming the physnet in its own \
         [network.provider] section; until one does, routers on it stay pending",
    )
}

#[derive(Deserialize)]
pub(super) struct Router {
    metadata: Meta,
    #[serde(default)]
    spec: RouterSpec,
    #[serde(default)]
    status: RouterStatus,
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub(super) struct RouterSpec {
    #[serde(default)]
    tenant: String,
    #[serde(default)]
    provider_network: String,
    #[serde(default)]
    internal_addr: String,
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub(super) struct RouterStatus {
    #[serde(default)]
    phase: String,
    #[serde(default)]
    external_addr: String,
    #[serde(default)]
    cluster: String,
    #[serde(default)]
    active_node: String,
    #[serde(default)]
    nats: Vec<NatRule>,
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub(super) struct NatRule {
    #[serde(default)]
    kind: String,
}

pub(super) fn router_row(r: Router) -> Vec<String> {
    // The rules by kind rather than one by one: a router with a masquerade
    // and nine floating addresses is one cell, and `router get` is where the
    // list itself is read.
    let mut snat = 0;
    let mut dnat = 0;
    let mut routed = 0;
    for rule in &r.status.nats {
        match rule.kind.as_str() {
            "snat" => snat += 1,
            "dnat_and_snat" => dnat += 1,
            "routed" => routed += 1,
            _ => {}
        }
    }
    vec![
        r.metadata.name,
        r.spec.tenant,
        r.spec.provider_network,
        or_dash(Some(r.status.phase).filter(|v| !v.is_empty())),
        or_dash(Some(r.status.external_addr).filter(|v| !v.is_empty())),
        or_dash(Some(r.spec.internal_addr).filter(|v| !v.is_empty())),
        or_dash(Some(r.status.cluster).filter(|v| !v.is_empty())),
        or_dash(Some(r.status.active_node).filter(|v| !v.is_empty())),
        format!("{snat}/{dnat}/{routed}"),
    ]
}

pub async fn router(ctx: &Ctx<'_>, cmd: &RouterCmd) -> Result<()> {
    match cmd {
        RouterCmd::Create {
            name,
            network,
            internal_addr,
            vni,
            no_snat,
            routed_subnets,
            description,
        } => {
            let Some(tenant) = ctx.global.tenant.as_deref() else {
                bail!(
                    "say whose way out this is with -t/--tenant; a router is the gateway of \
                     one tenant's overlay"
                );
            };
            let mut object = json!({
                "apiVersion": "meister.io/v1",
                "kind": "Router",
                "metadata": { "name": name },
                "spec": {
                    "tenant": tenant,
                    "providerNetwork": network,
                    "description": description.clone().unwrap_or_default(),
                },
            });
            // Sent only when it is FALSE: the field defaults to true at the
            // server, an absent key and a `false` key are different requests,
            // and writing `true` here would make every router carry a
            // decision nobody made.
            if *no_snat {
                object["spec"]["snat"] = json!(false);
            }
            if let Some(inside) = internal_addr {
                object["spec"]["internalAddr"] = json!(inside);
            }
            // Only when it was named: at a cloud the tenant answers this and
            // a number typed here would override the answer.
            if let Some(vni) = vni {
                object["spec"]["vni"] = json!(vni);
            }
            if !routed_subnets.is_empty() {
                object["spec"]["routedSubnets"] = json!(routed_subnets);
            }
            let body = ctx.post("routers", object).await?;
            output::emit_note(
                ctx.global,
                &body,
                name,
                "note: where it runs is the cluster's decision; `meister router get` names the \
                 gateway nodes it was planned on and which of them is active",
            )
        }
        RouterCmd::Read(_) | RouterCmd::Rm { .. } => unreachable!("dispatched generically"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The rule cell is a count per kind and never a list: a router with a
    /// masquerade and nine floating addresses has to fit in a column, and the
    /// rules themselves are what `router get` is for.
    #[test]
    fn the_rules_are_counted_by_kind_in_one_cell() {
        let router: Router = serde_json::from_str(
            r#"{
                "metadata": {"name": "acme-out"},
                "spec": {"tenant": "acme", "providerNetwork": "ext", "snat": true,
                         "internalAddr": "10.42.0.1/24"},
                "status": {"phase": "Active", "externalAddr": "198.51.100.10/24",
                           "cluster": "cluster-1", "activeNode": "gw-1",
                           "nats": [{"kind": "snat"}, {"kind": "dnat_and_snat"},
                                    {"kind": "dnat_and_snat"}, {"kind": "routed"}]}
            }"#,
        )
        .expect("a router");
        let row = router_row(router);
        assert_eq!(row[0], "acme-out");
        assert_eq!(row[3], "Active");
        assert_eq!(row[7], "gw-1");
        assert_eq!(row[8], "1/2/1", "snat/dnat/routed");
    }

    /// A router nothing has placed yet reads as dashes and not as empty
    /// cells — the same rule every other table here follows, so a column
    /// that is not answered yet is visibly not answered.
    #[test]
    fn an_unplaced_router_shows_dashes_rather_than_gaps() {
        let router: Router = serde_json::from_str(
            r#"{"metadata": {"name": "acme-out"},
                "spec": {"tenant": "acme", "providerNetwork": "ext"}}"#,
        )
        .expect("a router");
        let row = router_row(router);
        assert_eq!(row[3], "-", "no phase yet");
        assert_eq!(row[6], "-", "no cluster yet");
        assert_eq!(row[8], "0/0/0");
    }
}
