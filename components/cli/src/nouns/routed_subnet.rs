// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! `RoutedSubnet`: the object, its row and its verbs.

use super::*;

#[derive(Deserialize)]
pub(super) struct RoutedSubnet {
    metadata: Meta,
    #[serde(default)]
    spec: RoutedSubnetSpec,
}

#[derive(Deserialize, Default)]
pub(super) struct RoutedSubnetSpec {
    #[serde(default)]
    tenant: String,
    #[serde(default)]
    cidr: String,
    #[serde(default)]
    description: String,
}

pub(super) fn routed_subnet_row(s: RoutedSubnet) -> Vec<String> {
    vec![
        s.metadata.name,
        s.spec.tenant,
        s.spec.cidr,
        s.spec.description,
    ]
}

pub async fn routed_subnet(ctx: &Ctx<'_>, cmd: &RoutedSubnetCmd) -> Result<()> {
    let RoutedSubnetCmd::Create {
        name,
        cidr,
        prefix_len,
        description,
    } = cmd
    else {
        unreachable!("dispatched generically")
    };
    let Some(tenant) = ctx.global.tenant.as_deref() else {
        bail!("say whose subnet this is with -t/--tenant; a routed subnet is cut for one tenant");
    };
    let mut object = json!({
        "apiVersion": "meister.io/v1",
        "kind": "RoutedSubnet",
        "metadata": { "name": name },
        "spec": {
            "tenant": tenant,
            "description": description.clone().unwrap_or_default(),
        },
    });
    if let Some(cidr) = cidr {
        object["spec"]["cidr"] = json!(cidr);
    }
    if let Some(prefix_len) = prefix_len {
        object["spec"]["prefixLen"] = json!(prefix_len);
    }
    let body = ctx.post("routedsubnets", object).await?;
    output::emit(ctx.global, &body, |body| {
        // The cidr is the result — the server may have cut it — so that is
        // what a success prints, not the name the caller already knows.
        let created: RoutedSubnet = serde_json::from_slice(body).context("parsing the subnet")?;
        Ok(View::line(created.spec.cidr))
    })
}
