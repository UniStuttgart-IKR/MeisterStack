// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! `Tenant`: the object, its quota columns, its row and its verbs.

use super::*;

#[derive(Deserialize)]
pub(super) struct Tenant {
    metadata: Meta,
    #[serde(default)]
    spec: TenantSpec,
    #[serde(default)]
    status: TenantStatus,
}

#[derive(Deserialize, Default)]
pub(super) struct TenantSpec {
    #[serde(default)]
    description: String,
    /// The tenant's overlay network, allocated by the cloud. Absent on a
    /// tenant from before overlays existed.
    #[serde(default)]
    vni: Option<u32>,
    #[serde(default)]
    quota: TenantQuota,
}

/// An absent quota dimension is unlimited.
#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub(super) struct TenantQuota {
    #[serde(default)]
    max_vms: Option<u32>,
    #[serde(default)]
    max_vcpus: Option<u32>,
    #[serde(default)]
    max_mem_mib: Option<u64>,
}

/// Usage computed by the server when reading the tenant.
#[derive(Deserialize, Default)]
pub(super) struct TenantStatus {
    #[serde(default)]
    used: TenantUsage,
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub(super) struct TenantUsage {
    #[serde(default)]
    vms: u32,
    #[serde(default)]
    vcpus: u32,
    #[serde(default)]
    mem_mib: u64,
}

/// Render used/limit, or usage alone when unlimited.
pub(super) fn used_of(used: u64, limit: Option<u64>) -> String {
    match limit {
        Some(limit) => format!("{used}/{limit}"),
        None => used.to_string(),
    }
}

/// Format per-tenant limits in one comma-separated cell.
pub(super) fn quota_column(quota: &std::collections::BTreeMap<String, u32>) -> String {
    if quota.is_empty() {
        return "-".to_string();
    }
    quota
        .iter()
        .map(|(t, n)| format!("{t}={n}"))
        .collect::<Vec<_>>()
        .join(",")
}

/// `used/limit`, one row per tenant. See `used_of` for why it is one cell.
pub(super) fn tenant_row(t: Tenant) -> Vec<String> {
    vec![
        t.metadata.name,
        or_dash(t.spec.vni.map(|v| v.to_string())),
        used_of(
            t.status.used.vms as u64,
            t.spec.quota.max_vms.map(u64::from),
        ),
        used_of(
            t.status.used.vcpus as u64,
            t.spec.quota.max_vcpus.map(u64::from),
        ),
        used_of(t.status.used.mem_mib, t.spec.quota.max_mem_mib),
        t.spec.description,
    ]
}

/// The tenant `tenant create` posts. `networkPrefixes` goes only when some are named: a cloud
/// of the release before refuses the field as unknown, and a tenant without prefixes must
/// still be creatable there.
fn create_body(
    name: &str,
    description: Option<&str>,
    network_prefixes: &[String],
) -> serde_json::Value {
    let mut tenant = json!({
        "apiVersion": "meister.io/v1",
        "kind": "Tenant",
        "metadata": { "name": name },
        "spec": { "description": description.unwrap_or_default() },
    });
    if !network_prefixes.is_empty() {
        tenant["spec"]["networkPrefixes"] = json!(network_prefixes);
    }
    tenant
}

// Convenience commands use merge patches for individual spec fields.

pub async fn tenant(ctx: &Ctx<'_>, cmd: &TenantCmd) -> Result<()> {
    match cmd {
        TenantCmd::Create {
            name,
            description,
            network_prefixes,
        } => {
            let body = ctx
                .post(
                    "tenants",
                    create_body(name, description.as_deref(), network_prefixes),
                )
                .await?;
            output::emit_line(ctx.global, &body, name)
        }
        TenantCmd::NetworkPrefixes {
            name,
            prefixes,
            none: _,
        } => {
            // A merge patch replaces a list whole; `--none` sends the empty one.
            let body = ctx
                .patch(
                    "tenants",
                    name,
                    json!({ "spec": { "networkPrefixes": prefixes } }),
                )
                .await?;
            output::emit_line(ctx.global, &body, name)
        }
        TenantCmd::Quota {
            name,
            max_vms,
            max_vcpus,
            max_mem_mib,
            unlimited,
        } => {
            let named = max_vms.is_some() || max_vcpus.is_some() || max_mem_mib.is_some();
            if !named && !*unlimited {
                bail!("name at least one of --max-vms, --max-vcpus, --max-mem-mib, or --unlimited");
            }
            // Null removes a quota key; unspecified limits otherwise remain unchanged.
            let value = |v: Option<serde_json::Value>| {
                if *unlimited {
                    serde_json::Value::Null
                } else {
                    v.unwrap_or(serde_json::Value::Null)
                }
            };
            let mut quota = serde_json::Map::new();
            for (key, v) in [
                ("maxVms", max_vms.map(|v| json!(v))),
                ("maxVcpus", max_vcpus.map(|v| json!(v))),
                ("maxMemMib", max_mem_mib.map(|v| json!(v))),
            ] {
                let v = value(v);
                // --unlimited removes every limit.
                if *unlimited || !v.is_null() {
                    quota.insert(key.to_string(), v);
                }
            }
            let body = ctx
                .patch("tenants", name, json!({ "spec": { "quota": quota } }))
                .await?;
            output::emit_note(
                ctx.global,
                &body,
                name,
                "note: the quota counts every phase, pending vms included, and a vm that is \
                 terminating still counts until its object is gone",
            )
        }
        // `ls`, `get` and `rm` never reach here: `main::dispatch` sends the
        // three verbs that need no code per resource straight to `generic`.
        TenantCmd::Read(_) | TenantCmd::Rm { .. } => unreachable!("dispatched generically"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A tenant created without network prefixes is posted without the field, so a cloud that
    /// does not know it yet still takes the tenant; named prefixes go as they were given.
    #[test]
    fn network_prefixes_are_posted_only_when_named() {
        let bare = create_body("acme", None, &[]);
        assert_eq!(bare["spec"], json!({ "description": "" }));

        let prefixes = ["10.30.0.0/24".to_string()];
        let declared = create_body("acme", Some("web"), &prefixes);
        assert_eq!(
            declared["spec"],
            json!({ "description": "web", "networkPrefixes": ["10.30.0.0/24"] })
        );
    }
}
