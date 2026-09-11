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

/// Every field absent = unlimited, which is what a tenant from before quotas
/// existed says and therefore what it goes on meaning.
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

/// What the server computed this tenant is holding. Never stored anywhere —
/// the read that hands the object out is what fills it in.
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

/// `used/limit`, or just the number when there is no limit.
///
/// One cell rather than two columns per dimension: what an operator asks of
/// `tenant ls` is "how close is this tenant to its ceiling", and the answer is
/// a fraction. A tenant with no quota shows the count alone, because `4/-`
/// reads like a limit somebody forgot to set rather than one nobody wanted.
pub(super) fn used_of(used: u64, limit: Option<u64>) -> String {
    match limit {
        Some(limit) => format!("{used}/{limit}"),
        None => used.to_string(),
    }
}

/// The quota column: what each tenant was granted here, `tenant=n` per entry.
///
/// One line per object and no raw spaces in a value, which is the house rule
/// — the map is what makes a public pool auditable at a glance, and a column
/// that wrapped would make `floatingpool ls | grep` useless.
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

// --- the sugar: a create, and the verbs that set one field ------------------
//
// Every "set" verb below is ONE merge patch. They used to be a GET, an edit
// and a PUT — a read-modify-write in a client, which is a race the operator
// was shown as a 409 and could do nothing about. What the server now
// compares is the version it read itself, half a millisecond earlier.

pub async fn tenant(ctx: &Ctx<'_>, cmd: &TenantCmd) -> Result<()> {
    match cmd {
        TenantCmd::Create { name, description } => {
            let body = ctx
                .post(
                    "tenants",
                    json!({
                        "apiVersion": "meister.io/v1",
                        "kind": "Tenant",
                        "metadata": { "name": name },
                        "spec": { "description": description.clone().unwrap_or_default() },
                    }),
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
            // `--unlimited` is `null` on each key, which is what a merge patch
            // says removal with — and the whole reason a quota can now be
            // taken off without reading the object first. A named limit is
            // set and an unnamed one is not mentioned, so it stays.
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
                // An unnamed limit under --unlimited is still nulled: that is
                // what "take the whole quota off" means.
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
