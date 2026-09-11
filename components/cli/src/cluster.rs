// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! The two machine nouns: a node, and the cluster a node is in.
//!
//! They are one act against two inventories. Draining stops NEW placements
//! and nothing else — the VMs already there go on running, go on being
//! reconciled, and are neither evicted nor migrated — and labelling writes
//! what a VM's selector selects against. That is true of a node and of a
//! cluster, one word apart, so the verbs are written once.
//!
//! A node is the one noun whose PATH depends on which endpoint answered, and
//! that is the tiering showing through rather than a special case: a cluster
//! has its own nodes and serves them at `/nodes`, and a cloud has none of its
//! own and serves somebody else's at `/clusters/{c}/nodes`. The discovery
//! document decides which, and `--cluster` is required at one and refused at
//! the other.

use anyhow::{Result, bail};
use bytes::Bytes;
use chrono::{DateTime, Utc};
use serde::Deserialize;
use serde_json::json;

use crate::generic::{Ctx, DISCOVERY};
use crate::output::{self, View, age, joined, mem, or_dash, readiness};
use crate::{ClusterCmd, NodeCmd};

/// A node, as either endpoint serves it.
///
/// One struct for two documents on purpose: the cluster serves the stored
/// `Node` object and the cloud serves what the cluster last reported, and the
/// cloud's route dresses its report in the same envelope so that one table
/// renders both and `-o json` reads the same at either. What the cloud's copy
/// does not have is a uid, a resourceVersion and a heartbeat — it is
/// evidence, and evidence has no version.
#[derive(Clone, Deserialize)]
struct Node {
    metadata: Meta,
    #[serde(default)]
    spec: NodeSpec,
    #[serde(default)]
    status: NodeStatus,
}

#[derive(Clone, Deserialize)]
struct Meta {
    name: String,
}

#[derive(Clone, Deserialize)]
struct NodeSpec {
    #[serde(default = "yes")]
    schedulable: bool,
    #[serde(default)]
    drain: bool,
    #[serde(default)]
    labels: std::collections::BTreeMap<String, String>,
    /// What this machine takes. Empty is every machine that was never told
    /// otherwise, which is nearly all of them.
    #[serde(default)]
    accepts: Vec<String>,
}

fn yes() -> bool {
    true
}

impl Default for NodeSpec {
    fn default() -> Self {
        Self {
            schedulable: true,
            drain: false,
            labels: Default::default(),
            accepts: Vec::new(),
        }
    }
}

#[derive(Clone, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct NodeStatus {
    #[serde(default)]
    ready: bool,
    #[serde(default)]
    last_heartbeat: Option<DateTime<Utc>>,
    #[serde(default)]
    capacity: Capacity,
    /// Which replica of this cluster holds this node's session, when the
    /// cluster is running more than one. Empty everywhere else, and never
    /// shown by the cloud: which replica holds a node is the cluster's own
    /// business and nobody above it decides anything with it.
    #[serde(default)]
    session_endpoint: Option<String>,
    /// What the drain of this node has done so far. `None` on a node nobody
    /// asked to empty, which is nearly all of them — and the reason the
    /// `staying` column appears only in a listing that has one.
    #[serde(default)]
    draining: Option<Draining>,
    /// What the node says is wrong with itself. Empty on a healthy machine
    /// and on every agent that predates the field.
    #[serde(default)]
    conditions: Vec<NodeCondition>,
}

/// One thing a node says is wrong with itself. The sentence is in `node get`;
/// the listing has room for the word only.
#[derive(Clone, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct NodeCondition {
    #[serde(default, rename = "type")]
    type_: String,
    #[serde(default)]
    #[allow(dead_code)]
    message: String,
}

/// The evidence a drain leaves, as much of it as a listing shows. The
/// sentences are in `node get`, which is where somebody who wants them looks.
#[derive(Clone, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct Draining {
    #[serde(default)]
    leaving: u32,
    #[serde(default)]
    staying: u32,
    #[serde(default)]
    complete: bool,
    /// What the drain has actually got off the machine so far. `leaving` is
    /// a fact about now and goes to zero when the work is done, so without
    /// this a finished drain read `0 leaving, 2 staying (done)` and looked
    /// like one that had done nothing.
    #[serde(default)]
    moved_total: u32,
}

#[derive(Clone, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct Capacity {
    #[serde(default)]
    vcpus: u32,
    #[serde(default)]
    mem_mib: u64,
    // The alias is the mixed-version case, not tidiness: a controller that
    // predates the rename still sends `gpuProfiles`, and without this the
    // column would come out empty against every node in a fleet that has not
    // been rolled out yet.
    #[serde(default, alias = "gpuProfiles")]
    capabilities: Vec<String>,
}

/// Which columns this listing has: the ones the endpoint that answered can
/// actually fill in.
///
/// Two of them are conditional, and for the same reason rather than as a
/// convenience. A cloud's copy of a node carries no heartbeat — it is what
/// the cluster last REPORTED, and the cluster is what watches the clock — so
/// a heartbeat column there would read `never` under every node and mean
/// "this endpoint does not know", which is not what `never` says. And a
/// session endpoint exists only where a cluster runs more than one replica.
/// A column nobody can fill is worse than a missing one: it invites an answer
/// that is not there.
#[derive(Clone, Copy)]
struct NodeColumns {
    heartbeat: bool,
    session: bool,
    /// Somebody is emptying a machine here. A column nobody can fill is worse
    /// than a missing one, and on the ordinary fleet — nothing being drained
    /// — every cell of this one would be a dash.
    draining: bool,
    /// Somebody has told a machine here which workloads it takes. Same rule
    /// as the column above: a fleet where nobody has said so does not grow a
    /// column of dashes.
    accepts: bool,
}

impl NodeColumns {
    fn headers(self) -> Vec<&'static str> {
        let mut out = vec!["node", "ready"];
        if self.draining {
            out.push("drain");
        }
        if self.heartbeat {
            out.push("heartbeat");
        }
        out.extend(["vcpus", "mem", "capabilities", "labels"]);
        if self.accepts {
            out.push("accepts");
        }
        if self.session {
            out.push("session");
        }
        out
    }
}

pub fn node_table(body: &Bytes, now: DateTime<Utc>) -> Result<View> {
    let list: output::List<Node> =
        serde_json::from_slice(body).map_err(|e| anyhow::anyhow!("parsing node list: {e}"))?;
    let columns = NodeColumns {
        heartbeat: list.items.iter().any(|n| n.status.last_heartbeat.is_some()),
        session: list
            .items
            .iter()
            .any(|n| n.status.session_endpoint.is_some()),
        draining: list
            .items
            .iter()
            .any(|n| n.spec.drain || n.status.draining.is_some()),
        accepts: list.items.iter().any(|n| !n.spec.accepts.is_empty()),
    };
    let rows = list
        .items
        .into_iter()
        .map(|n| node_row(n, now, columns))
        .collect();
    Ok(View::table_of_columns(
        columns.headers(),
        rows,
        "no nodes known here",
    ))
}

fn node_row(node: Node, now: DateTime<Utc>, columns: NodeColumns) -> Vec<String> {
    let cap = node.status.capacity;
    let conditions: Vec<&str> = node
        .status
        .conditions
        .iter()
        .map(|c| c.type_.as_str())
        .collect();
    let mut row = vec![
        node.metadata.name,
        readiness(
            node.status.ready,
            node.spec.schedulable,
            node.spec.drain,
            &conditions,
        ),
    ];
    if columns.draining {
        row.push(match &node.status.draining {
            None => "-".to_string(),
            // Moved first, because it is the one an operator is waiting to
            // read: it is the answer to "did the drain do anything", and the
            // other two are the answer to "is it finished".
            Some(d) if d.complete => format!(
                "{} moved, {} leaving, {} staying (done)",
                d.moved_total, d.leaving, d.staying
            ),
            Some(d) => format!(
                "{} moved, {} leaving, {} staying",
                d.moved_total, d.leaving, d.staying
            ),
        });
    }
    if columns.heartbeat {
        row.push(age(node.status.last_heartbeat, now));
    }
    row.extend([
        cap.vcpus.to_string(),
        mem(cap.mem_mib),
        joined(&cap.capabilities),
        label_column(&node.spec.labels),
    ]);
    if columns.accepts {
        // Empty is not "nothing" here, it is "everything" — the field is
        // exclusive when it is set — so the cell says the word rather than a
        // dash a reader would take for "takes none".
        row.push(match node.spec.accepts.is_empty() {
            true => "any".to_string(),
            false => joined(&node.spec.accepts),
        });
    }
    if columns.session {
        row.push(or_dash(node.status.session_endpoint));
    }
    row
}

/// `k=v` per entry, comma-joined — one cell, no raw space, so `node ls | awk`
/// keeps working. Labels are what a `nodeSelector` matches on, and reading
/// them off the object is the only way to know what a selector will find.
fn label_column(labels: &std::collections::BTreeMap<String, String>) -> String {
    if labels.is_empty() {
        return "-".to_string();
    }
    labels
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join(",")
}

/// Where this endpoint keeps nodes.
///
/// The discovery document decides, not a flag default and not a profile: a
/// cluster serves its own at `/nodes`, and a cloud serves a cluster's under
/// the cluster that has them. Getting `--cluster` wrong is therefore a
/// sentence about this endpoint rather than a 404 from it.
pub fn node_path(ctx: &Ctx<'_>, cluster: Option<&str>, name: Option<&str>) -> Result<String> {
    if ctx.disc.is_cloud() {
        let Some(cluster) = cluster else {
            bail!(
                "this endpoint is a cloud, where a node belongs to a cluster; say which with \
                 --cluster"
            );
        };
        // Not through `Discovery::path`: at this tier nodes are a subresource
        // of `clusters` and the document says so — the check is that
        // `clusters` is served and names `nodes` under it.
        let row = ctx.disc.resource("clusters")?;
        if !row.subresources.iter().any(|s| s == "nodes") {
            bail!("this cloud does not serve the nodes of a cluster");
        }
        return Ok(match name {
            Some(name) => format!("{DISCOVERY}/clusters/{cluster}/nodes/{name}"),
            None => format!("{DISCOVERY}/clusters/{cluster}/nodes"),
        });
    }
    if cluster.is_some() {
        bail!(
            "this endpoint is a {} and has only its own nodes; drop --cluster",
            ctx.disc.tier
        );
    }
    ctx.disc.path("nodes", name)
}

pub async fn node(ctx: &Ctx<'_>, cluster: Option<&str>, cmd: &NodeCmd) -> Result<()> {
    match cmd {
        NodeCmd::Ls { selector } => {
            let path = format!(
                "{}{}",
                node_path(ctx, cluster, None)?,
                crate::generic::query(ctx.global, selector.as_deref())
            );
            let body = ctx.client.get(&path).await?;
            let now = Utc::now();
            output::emit(ctx.global, &body, |body| node_table(body, now))
        }
        NodeCmd::Get { name } => {
            let body = ctx
                .client
                .get(&node_path(ctx, cluster, Some(name))?)
                .await?;
            output::emit(ctx.global, &body, |body| {
                let object: serde_json::Value = serde_json::from_slice(body)
                    .map_err(|e| anyhow::anyhow!("parsing the node: {e}"))?;
                Ok(output::fields(crate::generic::flatten(&object)))
            })
        }
        NodeCmd::Cordon { name } => cordon(ctx, cluster, name, false).await,
        NodeCmd::Uncordon { name } => cordon(ctx, cluster, name, true).await,
        NodeCmd::Drain { name } => drain(ctx, cluster, name, true).await,
        NodeCmd::Undrain { name } => drain(ctx, cluster, name, false).await,
        NodeCmd::Accepts { name, classes } => accepts(ctx, cluster, name, classes).await,
        NodeCmd::Label { name, pairs, rm } => {
            let patch = crate::client::labels_patch(pairs, rm)?;
            let body = ctx
                .client
                .patch(&node_path(ctx, cluster, Some(name))?, patch)
                .await?;
            output::emit_line(ctx.global, &body, "labelled")
        }
    }
}

/// Stop placing new vms here. Moves nothing — that is the other verb.
async fn cordon(ctx: &Ctx<'_>, cluster: Option<&str>, name: &str, schedulable: bool) -> Result<()> {
    let body = ctx
        .client
        .patch(
            &node_path(ctx, cluster, Some(name))?,
            json!({ "spec": { "schedulable": schedulable } }),
        )
        .await?;
    output::emit_note(
        ctx.global,
        &body,
        if schedulable {
            "uncordoned"
        } else {
            "cordoned"
        },
        "note: a cordon stops new placements only; the vms already on this node keep running. \
         `node drain` is the one that moves them",
    )
}

/// Say what this machine takes. An empty list takes everything back.
///
/// Sent whole rather than as an add or a remove, and that is the shape of the
/// statement: what a machine accepts is one decision an operator reads off
/// one line, not a set somebody accumulates a class at a time. `node accepts
/// gw-1` with nothing after it is therefore the way back, and it is the same
/// request with an empty list rather than a verb of its own.
async fn accepts(
    ctx: &Ctx<'_>,
    cluster: Option<&str>,
    name: &str,
    classes: &[String],
) -> Result<()> {
    let body = ctx
        .client
        .patch(
            &node_path(ctx, cluster, Some(name))?,
            json!({ "spec": { "accepts": classes } }),
        )
        .await?;
    if classes.is_empty() {
        return output::emit_line(ctx.global, &body, "everything");
    }
    output::emit_note(
        ctx.global,
        &body,
        &classes.join(","),
        "note: this is exclusive: the node stops taking every class not named here, \
         the ordinary `vm` class included. The vms already on it keep running",
    )
}

/// Empty the machine. Two separate fields on purpose: this one says nothing
/// about `schedulable`, so an `undrain` gives back exactly the cordon the
/// operator had set — and not one this command invented.
async fn drain(ctx: &Ctx<'_>, cluster: Option<&str>, name: &str, on: bool) -> Result<()> {
    let body = ctx
        .client
        .patch(
            &node_path(ctx, cluster, Some(name))?,
            json!({ "spec": { "drain": on } }),
        )
        .await?;
    output::emit_note(
        ctx.global,
        &body,
        if on { "draining" } else { "undrained" },
        if on {
            "note: a stopped vm is placed again, a running one only with `vm evacuation NAME \
             restart`, and one with a persistent node-local disk never. `node get` says what \
             stayed and why"
        } else {
            "note: the vms that already moved stay where they went"
        },
    )
}

/// The same two verbs one tier up, over the Cluster object, with the same
/// narrow meaning.
pub async fn cluster(ctx: &Ctx<'_>, cmd: &ClusterCmd) -> Result<()> {
    let (name, patch, said) = match cmd {
        ClusterCmd::Cordon { name } => (
            name,
            json!({ "spec": { "schedulable": false } }),
            "cordoned",
        ),
        ClusterCmd::Uncordon { name } => (
            name,
            json!({ "spec": { "schedulable": true } }),
            "uncordoned",
        ),
        ClusterCmd::Drain { name } => (name, json!({ "spec": { "drain": true } }), "draining"),
        ClusterCmd::Undrain { name } => (name, json!({ "spec": { "drain": false } }), "undrained"),
        ClusterCmd::Label { name, pairs, rm } => {
            let body = ctx
                .patch("clusters", name, crate::client::labels_patch(pairs, rm)?)
                .await?;
            return output::emit_line(ctx.global, &body, "labelled");
        }
        // `ls` and `get` never reach here: `main::dispatch` sends the two
        // verbs that need no code per resource straight to `generic`.
        ClusterCmd::Read(_) => unreachable!("dispatched generically"),
    };
    let body = ctx.patch("clusters", name, patch).await?;
    let note = match said {
        "draining" => {
            "note: there is no live migration across clusters, so a running vm leaves only with \
             `vm evacuation NAME restart` and a reboot. `cluster get` says what stayed and why"
        }
        "undrained" => "note: the vms that already moved stay where they went",
        _ => {
            "note: a cordon stops new placements only; the vms already on this cluster keep \
             running. `cluster drain` is the one that moves them"
        }
    };
    output::emit_note(ctx.global, &body, said, note)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn discovery(tier: &str) -> crate::generic::Discovery {
        let resources = if tier == "cloud" {
            r#"[{"name":"clusters","kind":"Cluster","verbs":["get","list"],
                 "subresources":["nodes"]}]"#
        } else {
            r#"[{"name":"nodes","kind":"Node","verbs":["get","list","patch"]}]"#
        };
        serde_json::from_str(&format!(
            r#"{{"tier":"{tier}","auth":"none","resources":{resources}}}"#
        ))
        .unwrap()
    }

    fn ctx(tier: &str) -> Ctx<'static> {
        // Only the discovery half is exercised here; nothing below builds a
        // request, which is why this can be a target that resolves to nothing.
        static GLOBAL: std::sync::OnceLock<crate::GlobalArgs> = std::sync::OnceLock::new();
        let global = GLOBAL.get_or_init(crate::GlobalArgs::for_tests);
        Ctx {
            client: crate::client::Client::new(&crate::config::Target {
                profile_name: "test".into(),
                endpoint: "http://127.0.0.1:1".into(),
                ca_cert: None,
                credential: crate::config::Credential::None,
                timeout_secs: 1,
                oidc: None,
            })
            .unwrap(),
            global,
            disc: discovery(tier),
            endpoint: "http://127.0.0.1:1".into(),
            profile: "test".into(),
        }
    }

    /// Which path a node lives at is the endpoint's answer and not a flag
    /// default: a cluster has its own, a cloud has somebody else's.
    #[test]
    fn the_endpoint_decides_where_a_node_is_and_says_so_when_the_flag_is_wrong() {
        let cloud = ctx("cloud");
        assert_eq!(
            node_path(&cloud, Some("c1"), None).unwrap(),
            "/apis/meister.io/v1/clusters/c1/nodes"
        );
        assert_eq!(
            node_path(&cloud, Some("c1"), Some("manacor")).unwrap(),
            "/apis/meister.io/v1/clusters/c1/nodes/manacor"
        );
        let e = node_path(&cloud, None, None).unwrap_err().to_string();
        assert!(e.contains("--cluster"), "{e}");

        let cluster = ctx("cluster");
        assert_eq!(
            node_path(&cluster, None, Some("manacor")).unwrap(),
            "/apis/meister.io/v1/nodes/manacor"
        );
        let e = node_path(&cluster, Some("c1"), None)
            .unwrap_err()
            .to_string();
        assert!(e.contains("drop --cluster"), "{e}");
    }

    /// A node the controller has only ever heard Hello from carries no
    /// capacity at all; the table must still render it.
    #[test]
    fn a_bare_node_object_renders_a_full_row() {
        let node: Node =
            serde_json::from_str(r#"{"metadata":{"name":"manacor"},"spec":{},"status":{}}"#)
                .unwrap();
        assert!(node.spec.schedulable);
        assert_eq!(
            readiness(
                node.status.ready,
                node.spec.schedulable,
                node.spec.drain,
                &[]
            ),
            "no"
        );
        let all = NodeColumns {
            heartbeat: true,
            session: false,
            draining: false,
            accepts: false,
        };
        let with_classes = NodeColumns {
            accepts: true,
            ..all
        };
        assert_eq!(
            node_row(node.clone(), Utc::now(), all),
            vec!["manacor", "no", "never", "0", "-", "-", "-"]
        );

        // The classes column, when a fleet has anybody who named any. Empty
        // is "any" and not a dash: the field is EXCLUSIVE when it is set, so
        // a dash would read as "takes none", which is the opposite.
        assert_eq!(
            node_row(node.clone(), Utc::now(), with_classes).last(),
            Some(&"any".to_string())
        );
        let mut gateway = node;
        gateway.spec.accepts = vec!["router".into()];
        assert_eq!(
            node_row(gateway, Utc::now(), with_classes).last(),
            Some(&"router".to_string())
        );
    }

    /// The cloud's copy of a node and the cluster's own object render through
    /// the same row, which is what makes one `node ls` serve both endpoints.
    #[test]
    fn one_table_renders_a_stored_node_and_a_reported_one() {
        let body = Bytes::from(
            r#"{"items":[
                {"metadata":{"name":"manacor"},
                 "spec":{"schedulable":false,"labels":{"zone":"a"}},
                 "status":{"ready":true,"capacity":{"vcpus":32,"memMib":65536,
                           "capabilities":["nvrm/4q"]}}}]}"#,
        );
        let View::Table(table) = node_table(&body, Utc::now()).unwrap() else {
            panic!("a table")
        };
        let rendered = table.render();
        assert!(rendered[0].starts_with("NODE"), "{rendered:?}");
        assert!(!rendered[0].contains("SESSION"), "nothing to show yet");
        assert!(
            !rendered[0].contains("HEARTBEAT"),
            "and no clock behind this one either: {rendered:?}"
        );
        assert!(rendered[1].contains("cordoned"), "{rendered:?}");
        assert!(
            !rendered[0].contains("DRAIN"),
            "a cordon is not a drain, and nothing here is being emptied: {rendered:?}"
        );
        assert!(rendered[1].contains("zone=a"), "{rendered:?}");
    }

    /// The session column appears only where there is something in it: one
    /// replica has nothing to say there, and the cloud is never told at all.
    #[test]
    fn the_session_column_appears_only_where_a_replica_holds_one() {
        let body = Bytes::from(
            r#"{"items":[{"metadata":{"name":"a"},"spec":{},
                 "status":{"sessionEndpoint":"http://10.0.0.2:3001"}}]}"#,
        );
        let View::Table(table) = node_table(&body, Utc::now()).unwrap() else {
            panic!("a table")
        };
        let rendered = table.render();
        assert!(rendered[0].contains("SESSION"), "{rendered:?}");
        assert!(rendered[1].contains("http://10.0.0.2:3001"), "{rendered:?}");
    }
}
