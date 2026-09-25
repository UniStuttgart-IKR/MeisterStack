// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! `StoragePool`: the object, its row and its verbs.

use super::*;

// Storage pool display and mutation.

#[derive(Deserialize)]
pub(super) struct StoragePool {
    metadata: Meta,
    #[serde(default)]
    spec: StoragePoolSpec,
    #[serde(default)]
    status: StoragePoolStatus,
}

#[derive(Deserialize, Default)]
pub(super) struct StoragePoolSpec {
    #[serde(default)]
    driver: String,
    #[serde(default)]
    nodes: Vec<String>,
    #[serde(default)]
    cluster: String,
    #[serde(default)]
    default: bool,
    #[serde(default)]
    quota: std::collections::BTreeMap<String, u64>,
    #[serde(default)]
    description: String,
}

#[derive(Deserialize, Default)]
pub(super) struct StoragePoolStatus {
    #[serde(default)]
    phase: Option<String>,
    #[serde(default)]
    locality: Option<String>,
    #[serde(default)]
    nodes: Vec<String>,
}

pub(super) fn storage_pool_row(p: StoragePool) -> Vec<String> {
    let phase = p.status.phase.clone();
    vec![
        p.metadata.name,
        p.spec.driver,
        // Show readiness separately from backend configuration.
        or_dash(phase),
        // Missing locality is unknown; Failed pools display a conflict.
        match p.status.phase.as_deref() {
            Some("Failed") => "conflict".to_string(),
            _ => or_dash(p.status.locality),
        },
        // Only cloud pools name a cluster.
        or_dash(Some(p.spec.cluster).filter(|c| !c.is_empty())),
        if p.spec.default { "yes" } else { "-" }.to_string(),
        // Prefer configured nodes, then reported nodes; otherwise display all.
        match (p.spec.nodes.is_empty(), p.status.nodes.is_empty()) {
            (false, _) => joined(&p.spec.nodes),
            (true, false) => joined(&p.status.nodes),
            (true, true) => "all".to_string(),
        },
        gib_quota(&p.spec.quota),
        p.spec.description,
    ]
}

/// Read unique volume backend names from node or cluster capabilities.
/// Lookup failures suppress the optional post-create advisory.
async fn volume_drivers(ctx: &Ctx<'_>) -> Vec<String> {
    let (resource, path) = if ctx.disc.is_cloud() {
        ("clusters", ["status", "capacity"])
    } else {
        ("nodes", ["status", "capabilities"])
    };
    let Ok(path_str) = ctx.path(resource, None) else {
        return Vec::new();
    };
    let Ok(body) = ctx.client.get(&path_str).await else {
        return Vec::new();
    };
    let Ok(list) = serde_json::from_slice::<serde_json::Value>(&body) else {
        return Vec::new();
    };
    let mut out: Vec<String> = list
        .get("items")
        .and_then(serde_json::Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default()
        .iter()
        .flat_map(|item| {
            let mut at = item;
            for step in path {
                at = at.get(step).unwrap_or(&serde_json::Value::Null);
            }
            // Cloud capabilities are nested under status.capacity.
            let entries = at
                .get("capabilities")
                .or(Some(at))
                .and_then(serde_json::Value::as_array)
                .cloned()
                .unwrap_or_default();
            entries
                .into_iter()
                .filter_map(|e| e.as_str().and_then(volume_backend).map(str::to_string))
                .collect::<Vec<_>>()
        })
        .collect();
    out.sort();
    out.dedup();
    out
}

/// `volume/lvm-thin` -> `lvm-thin`, and nothing else out of a catalogue that
/// also carries devices and networks.
fn volume_backend(capability: &str) -> Option<&str> {
    capability
        .strip_prefix("volume/")
        .filter(|d| !d.is_empty() && !d.contains('/'))
}

/// Warn only when a nonempty catalogue lacks the requested backend.
fn unknown_driver(driver: &str, offered: &[String]) -> Option<String> {
    if offered.is_empty() || offered.iter().any(|d| d == driver) {
        return None;
    }
    Some(format!(
        "note: no node in this fleet claims volume/{driver}; the pool stays Pending until \
         one does. What is claimed today: {}",
        offered.join(", ")
    ))
}

/// Format per-tenant GiB limits; * is the default limit.
pub(super) fn gib_quota(quota: &std::collections::BTreeMap<String, u64>) -> String {
    if quota.is_empty() {
        return "-".to_string();
    }
    quota
        .iter()
        .map(|(t, n)| format!("{t}={n}Gi"))
        .collect::<Vec<_>>()
        .join(",")
}

pub async fn storage_pool(ctx: &Ctx<'_>, cmd: &StoragePoolCmd) -> Result<()> {
    match cmd {
        StoragePoolCmd::Create {
            name,
            driver,
            nodes,
            cluster,
            params,
            default,
            description,
        } => {
            let mut object = json!({
                "apiVersion": "meister.io/v1",
                "kind": "StoragePool",
                "metadata": { "name": name },
                "spec": {
                    "driver": driver,
                    "nodes": nodes,
                    "default": default,
                    "description": description.clone().unwrap_or_default(),
                },
            });
            // Omit the cloud-only cluster field unless supplied.
            if let Some(cluster) = cluster {
                object["spec"]["cluster"] = json!(cluster);
            }
            // Parse backend parameters as JSON; the storage driver interprets them.
            if let Some(params) = params {
                object["spec"]["params"] = serde_json::from_str(params)
                    .with_context(|| format!("--params is not valid json: {params}"))?;
            }
            // Look up advertised backends for an advisory; pools may precede their serving nodes.
            let offered = volume_drivers(ctx).await;
            let body = ctx.post("storagepools", object).await?;
            match unknown_driver(driver, &offered) {
                Some(note) => output::emit_note_owned(ctx.global, &body, name, note),
                None => output::emit_line(ctx.global, &body, name),
            }
        }
        StoragePoolCmd::Quota { pool, tenant, gib } => {
            let body = ctx
                .patch(
                    "storagepools",
                    pool,
                    json!({ "spec": { "quota": { tenant: gib } } }),
                )
                .await?;
            output::emit_line(ctx.global, &body, &gib.to_string())
        }
        // `ls`, `get` and `rm` never reach here: `main::dispatch` sends the
        // three verbs that need no code per resource straight to `generic`.
        StoragePoolCmd::Read(_) | StoragePoolCmd::Rm { .. } => {
            unreachable!("dispatched generically")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pool(json: &str) -> StoragePool {
        serde_json::from_str(json).expect("a pool")
    }

    /// Pending and failed pools must be distinguishable from ready pools.
    #[test]
    fn a_pool_that_will_never_serve_a_disk_says_so_in_the_table() {
        let pending = storage_pool_row(pool(
            r#"{"metadata":{"name":"mc-thin"},"spec":{"driver":"lvm-thin"},
                "status":{"phase":"Pending"}}"#,
        ));
        assert_eq!(pending[0], "mc-thin");
        assert_eq!(pending[2], "Pending");

        let ready = storage_pool_row(pool(
            r#"{"metadata":{"name":"mc-fs"},"spec":{"driver":"filesystem","default":true},
                "status":{"phase":"Ready","locality":"node-local"}}"#,
        ));
        assert_eq!(ready[2], "Ready");
        assert_eq!(ready[3], "node-local", "the locality column is unchanged");

        // Missing phase remains unknown.
        let fresh = storage_pool_row(pool(
            r#"{"metadata":{"name":"mc-new"},"spec":{"driver":"nfs"},"status":{}}"#,
        ));
        assert_eq!(fresh[2], "-");

        // A failed pool keeps the locality conflict indicator.
        let conflicted = storage_pool_row(pool(
            r#"{"metadata":{"name":"mc-nfs"},"spec":{"driver":"nfs"},
                "status":{"phase":"Failed","locality":"shared"}}"#,
        ));
        assert_eq!(conflicted[2], "Failed");
        assert_eq!(conflicted[3], "conflict");
    }

    /// Keep the row width aligned with its headers.
    #[test]
    fn a_pool_row_is_the_same_width_as_its_header() {
        let row = storage_pool_row(pool(
            r#"{"metadata":{"name":"mc-fs"},"spec":{"driver":"filesystem"},"status":{}}"#,
        ));
        assert_eq!(
            row.len(),
            9,
            "pool driver phase locality cluster default nodes quota description"
        );
    }

    /// Derive backend names from capabilities rather than a fixed help list.
    #[test]
    fn what_a_fleet_offers_comes_out_of_its_catalogue_and_not_out_of_a_list() {
        // Ignore non-volume capabilities.
        assert_eq!(
            volume_backend("volume/nvmeof-import"),
            Some("nvmeof-import")
        );
        assert_eq!(volume_backend("nvrm/4q"), None);
        assert_eq!(volume_backend("network/vxlan"), None);
        assert_eq!(volume_backend("volume/"), None);
        // Reject extra path segments.
        assert_eq!(volume_backend("volume/a/b"), None);

        let offered = ["filesystem".to_string(), "nvmeof-import".to_string()];
        assert_eq!(unknown_driver("nvmeof-import", &offered), None);
        let said = unknown_driver("lvm-thin", &offered).expect("nobody claims it");
        assert!(
            said.contains("no node in this fleet claims volume/lvm-thin"),
            "{said}"
        );
        assert!(
            said.contains("filesystem, nvmeof-import"),
            "and the note names what IS claimed: {said}"
        );
        assert!(
            said.contains("stays Pending"),
            "a note and not a refusal, because the create is legitimate: {said}"
        );

        // A failed or empty lookup must not claim the fleet offers no storage.
        assert_eq!(unknown_driver("lvm-thin", &[]), None);
    }

    /// Display the default quota alongside tenant overrides.
    #[test]
    fn the_quota_column_shows_the_ceiling_a_create_is_refused_against() {
        let row = storage_pool_row(pool(
            r#"{"metadata":{"name":"nvme"},"spec":{"driver":"nvmeof-import",
                "quota":{"*":100,"acme":500}},"status":{"phase":"Ready"}}"#,
        ));
        assert_eq!(
            row[7], "*=100Gi,acme=500Gi",
            "the row for everybody nobody named, first because it sorts first"
        );

        // The server filters other tenants' quota entries.
        let row = storage_pool_row(pool(
            r#"{"metadata":{"name":"nvme"},"spec":{"driver":"nvmeof-import",
                "quota":{"*":100}},"status":{}}"#,
        ));
        assert_eq!(row[7], "*=100Gi");
    }
}
