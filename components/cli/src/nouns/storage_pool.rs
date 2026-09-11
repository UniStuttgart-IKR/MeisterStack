// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! `StoragePool`: the object, its row and its verbs.

use super::*;

// --- storage: two nouns this CLI never had, and the tables for them ---------

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
        // The API has always been honest here and the table was not: a pool
        // whose driver no node offers is `Pending`, and without this column
        // it stood in the listing looking exactly like a `Ready` one. `-`
        // for a pool nobody has decided about yet, which is the state
        // between the create and the first pass.
        or_dash(phase),
        // Absent is "the nodes have not said", which is a different fact from
        // any of the three values and must not be printed as one of them. A
        // pool that is Failed says so here instead, because a locality nobody
        // agrees on is worse than no locality at all.
        match p.status.phase.as_deref() {
            Some("Failed") => "conflict".to_string(),
            _ => or_dash(p.status.locality),
        },
        // At the cloud the pool points at a cluster; at the cluster tier
        // there is none, and a dash is the honest reading of that.
        or_dash(Some(p.spec.cluster).filter(|c| !c.is_empty())),
        if p.spec.default { "yes" } else { "-" }.to_string(),
        // Empty means every node can reach it, which is a different fact from
        // "no node can" and has to read differently. At the cloud the list an
        // admin wrote is empty and the mirrored one is what to show.
        match (p.spec.nodes.is_empty(), p.status.nodes.is_empty()) {
            (false, _) => joined(&p.spec.nodes),
            (true, false) => joined(&p.status.nodes),
            (true, true) => "all".to_string(),
        },
        gib_quota(&p.spec.quota),
        p.spec.description,
    ]
}

/// Every volume backend this endpoint's fleet claims, sorted and once each.
///
/// Out of the catalogue and nowhere else: a node publishes `volume/<driver>`
/// beside `network/vxlan` and `nvrm/4q`, a cluster publishes the union of its
/// ready nodes', and both spellings are read here so that the answer is the
/// same word at either tier.
///
/// Empty on anything that goes wrong -- a caller who may not list nodes, an
/// endpoint that answers nothing, a fleet nobody has dialled into. This is a
/// note beside a create that has already happened, and a note that could fail
/// a create would be worse than no note.
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
            // The cloud's list is one level deeper: a cluster publishes its
            // union under `status.capacity.capabilities`.
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

/// The sentence for a driver the fleet does not claim, or nothing.
///
/// Nothing when the fleet claims it, and nothing when the fleet claimed
/// NOTHING: an empty catalogue means the question could not be asked, and a
/// note reading "this fleet offers none" would turn a failed lookup into a
/// statement about the machines.
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

/// `tenant=n` per entry, comma-joined — the same shape the floating pool's
/// quota column has, and for the same reason: one line per object, and no raw
/// space in a value.
///
/// `*=100Gi` is the ceiling for every tenant nobody named, and it is a row
/// like any other because that is what it is in the object: since D-P11 the
/// server states it on every read, so this column shows the number a create
/// is actually refused against instead of a dash.
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
            // Only when given: the cluster tier has no such field and would
            // refuse an empty one as a written statement rather than as
            // silence.
            if let Some(cluster) = cluster {
                object["spec"]["cluster"] = json!(cluster);
            }
            // Handed to the driver untouched. This control plane routes on
            // `driver` and reads nothing else in here, so what it has to be
            // is valid json and the backend's business after that.
            if let Some(params) = params {
                object["spec"]["params"] = serde_json::from_str(params)
                    .with_context(|| format!("--params is not valid json: {params}"))?;
            }
            // D-P8: what backends exist is a fact about the FLEET, and the
            // help text used to answer it out of a list that was already
            // wrong -- `nvmeof-import` has worked since the storage
            // milestone and was never in it. So the answer comes out of the
            // catalogue the nodes publish, at create time, where it is right
            // by construction.
            //
            // A note and not a refusal: a pool whose driver nobody offers is
            // accepted on purpose (it stands `Pending`, which is what lets an
            // operator declare a pool before the machine that serves it comes
            // up), and the phase column says so afterwards. What was missing
            // was anybody saying it at the moment it can still be a typo.
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

    /// D14: the one column that says a pool is unusable.
    ///
    /// `storagepool create mc-thin --driver lvm-thin` on a fleet where no
    /// node offers lvm-thin is accepted without complaint and stands
    /// `Pending` in the API for ever. The table showed driver, locality,
    /// cluster, default, nodes and quota — everything except the field that
    /// says the pool will never serve a disk — so it read exactly like the
    /// healthy one beside it.
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

        // A pool nobody has decided about yet — the window between the create
        // and the first pass — is a dash and not a guess.
        let fresh = storage_pool_row(pool(
            r#"{"metadata":{"name":"mc-new"},"spec":{"driver":"nfs"},"status":{}}"#,
        ));
        assert_eq!(fresh[2], "-");

        // And the `Failed` reading of the locality column stays where it was:
        // a locality the nodes disagree about is worse than none, and the
        // phase column beside it now says the same thing in its own word.
        let conflicted = storage_pool_row(pool(
            r#"{"metadata":{"name":"mc-nfs"},"spec":{"driver":"nfs"},
                "status":{"phase":"Failed","locality":"shared"}}"#,
        ));
        assert_eq!(conflicted[2], "Failed");
        assert_eq!(conflicted[3], "conflict");
    }

    /// The header and the row have to be the same width, in the same order.
    /// An off-by-one here is a table whose `quota` column holds a description.
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

    /// D-P8: the help for `--driver` named `lvm-thin | filesystem | nfs`, a
    /// list that stopped being true when `nvmeof-import` started working. A
    /// list in a help string is a list nobody updates; the catalogue is not.
    #[test]
    fn what_a_fleet_offers_comes_out_of_its_catalogue_and_not_out_of_a_list() {
        // A node's catalogue is one flat list with devices and networks in
        // it, and only the volume half is a backend.
        assert_eq!(
            volume_backend("volume/nvmeof-import"),
            Some("nvmeof-import")
        );
        assert_eq!(volume_backend("nvrm/4q"), None);
        assert_eq!(volume_backend("network/vxlan"), None);
        assert_eq!(volume_backend("volume/"), None);
        // `volume/lvm-thin/thin` is not a backend name; a driver resolves no
        // profiles here and a second slash means the entry is about
        // something else.
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

        // A catalogue nobody could read says nothing at all, rather than
        // turning a failed lookup into a statement about the machines.
        assert_eq!(unknown_driver("lvm-thin", &[]), None);
    }

    /// D-P11: a pool's ceiling was a constant in the server's source. The
    /// table said `QUOTA -` and a refused create said "its quota there is
    /// 100 GiB", and there was nowhere to look it up.
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

        // A member sees their own and the one for everybody, which is what
        // the server redacts down to -- and never another tenant's.
        let row = storage_pool_row(pool(
            r#"{"metadata":{"name":"nvme"},"spec":{"driver":"nvmeof-import",
                "quota":{"*":100}},"status":{}}"#,
        ));
        assert_eq!(row[7], "*=100Gi");
    }
}
