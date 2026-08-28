// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! `meister cluster …` — drives the cluster-controller's K8s-style REST API.
//! Same client, same feel as the agent tier; the spec file is the agent's
//! NewVmSpec JSON, wrapped server-side into a Vm object.
//!
//! The VM verbs themselves are one level down, in [`crate::vm`]: this tier
//! and the cloud tier serve the same object and only place it differently.

use anyhow::Result;
use chrono::{DateTime, Utc};
use macros::generated;
use serde::Deserialize;

use crate::client::Client;
use crate::config::Target;
use crate::output::{self, age, joined, mem, readiness};
use crate::{ClusterCmd, ClusterNodeCmd, ClusterVmCmd, GlobalArgs, vm};

const NODES: &str = "/apis/meister.io/v1/nodes";

#[derive(Deserialize)]
struct Node {
    metadata: Meta,
    #[serde(default)]
    spec: NodeSpec,
    #[serde(default)]
    status: NodeStatus,
}

#[derive(Deserialize)]
struct Meta {
    name: String,
}

#[derive(Deserialize)]
struct NodeSpec {
    #[serde(default = "yes")]
    schedulable: bool,
}

fn yes() -> bool {
    true
}

impl Default for NodeSpec {
    fn default() -> Self {
        Self { schedulable: true }
    }
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct NodeStatus {
    #[serde(default)]
    ready: bool,
    #[serde(default)]
    last_heartbeat: Option<DateTime<Utc>>,
    #[serde(default)]
    capacity: Capacity,
}

#[derive(Deserialize, Default)]
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

/// Every verb of this tier that destroys something, and the whole list of it.
/// Naming them here rather than guarding inside each verb is the point: a
/// verb missing from this list is a verb that deletes without asking, and
/// that is now a visible omission instead of an invisible one.
#[generated(model = ClaudeOpus, version = "5")]
fn destructive(cmd: &ClusterCmd) -> Option<(&'static str, &str)> {
    match cmd {
        ClusterCmd::Vm {
            cmd: ClusterVmCmd::Destroy { name },
        } => Some(("vm", name)),
        _ => None,
    }
}

#[generated(model = ClaudeFable, version = "5")]
pub async fn run(target: &Target, cmd: &ClusterCmd, global: &GlobalArgs) -> Result<()> {
    if let Some((kind, name)) = destructive(cmd) {
        output::confirm_destructive(global, target, kind, name)?;
    }

    let client = Client::new(target)?;
    match cmd {
        ClusterCmd::Nodes => nodes(&client, global).await,
        ClusterCmd::Events => {
            vm::events(&client, global, vm::EVENTS, "nothing has happened recently").await
        }
        ClusterCmd::Node { cmd } => run_node(&client, cmd, global).await,
        ClusterCmd::Vm { cmd } => run_vm(&client, cmd, global).await,
    }
}

/// The inventory, not the live sessions: a node that is down stays listed as
/// not ready, with the capacity it last had.
#[generated(model = ClaudeOpus, version = "5")]
async fn nodes(client: &Client, global: &GlobalArgs) -> Result<()> {
    let body = client.get(NODES).await?;
    let now = Utc::now();
    output::emit(global, &body, |body| {
        output::table_of(
            body,
            "parsing node list",
            &["node", "ready", "heartbeat", "vcpus", "mem", "capabilities"],
            "no nodes known to this cluster",
            |node: Node| node_row(node, now),
        )
    })
}

#[generated(model = ClaudeOpus, version = "5")]
fn node_row(node: Node, now: DateTime<Utc>) -> Vec<String> {
    let cap = node.status.capacity;
    vec![
        node.metadata.name,
        readiness(node.status.ready, node.spec.schedulable).into(),
        age(node.status.last_heartbeat, now),
        cap.vcpus.to_string(),
        mem(cap.mem_mib),
        joined(&cap.capabilities),
    ]
}

/// Cordon and uncordon, through the same read-edit-write every other spec
/// change in this CLI goes through: the object is read, one field of its spec
/// is set, and the whole thing goes back with the resourceVersion it was read
/// at. That is the compare-and-swap — two operators cordoning at once, and
/// the loser is told rather than silently overwriting.
#[generated(model = ClaudeOpus, version = "5")]
async fn run_node(client: &Client, cmd: &ClusterNodeCmd, global: &GlobalArgs) -> Result<()> {
    let (name, schedulable) = match cmd {
        ClusterNodeCmd::Cordon { name } => (name, false),
        ClusterNodeCmd::Uncordon { name } => (name, true),
    };
    let body = client
        .patch_spec(
            &format!("{NODES}/{name}"),
            "parsing the node object",
            &format!("node {name}"),
            &|spec| {
                spec.insert("schedulable".to_string(), serde_json::json!(schedulable));
                Ok(())
            },
        )
        .await?;
    output::emit_note(
        global,
        &body,
        if schedulable {
            "uncordoned"
        } else {
            "cordoned"
        },
        "note: draining stops new placements only; the vms already on this node keep running",
    )
}

/// The same eight verbs the cloud tier has, over the same object — the tier
/// is the difference, and it is the whole difference. What this tier cannot
/// do is name a tenant: there is no user directory here to name one from, so
/// a VM created straight at a cluster belongs to nobody.
#[generated(model = ClaudeFable, version = "5")]
async fn run_vm(client: &Client, cmd: &ClusterVmCmd, global: &GlobalArgs) -> Result<()> {
    match cmd {
        ClusterVmCmd::Create {
            name,
            spec,
            run_strategy,
        } => vm::create(client, global, name, spec, run_strategy.as_deref(), None).await,
        ClusterVmCmd::Ls => {
            vm::list(
                client,
                global,
                vm::Placement::Node,
                "no vms in this cluster",
            )
            .await
        }
        ClusterVmCmd::Logs { name, lines } => vm::logs(client, global, vm::VMS, name, *lines).await,
        ClusterVmCmd::Events { name } => {
            vm::events(
                client,
                global,
                &format!("{}/{name}/events", vm::VMS),
                "nothing has happened to this vm recently",
            )
            .await
        }
        ClusterVmCmd::Inspect { name } => vm::inspect(client, name).await,
        ClusterVmCmd::Destroy { name } => vm::destroy(client, global, name).await,
        ClusterVmCmd::Start { name } => vm::run_strategy(client, name, "Running", global).await,
        ClusterVmCmd::Stop { name } => vm::run_strategy(client, name, "Stopped", global).await,
        ClusterVmCmd::Pause { name } => vm::run_strategy(client, name, "Paused", global).await,
        ClusterVmCmd::Resume { name } => vm::run_strategy(client, name, "Running", global).await,
    }
}

#[cfg(test)]
#[generated(model = ClaudeOpus, version = "5")]
mod tests {
    use super::*;

    /// A node the controller has only ever heard Hello from carries no
    /// capacity at all; the table must still render it.
    #[test]
    fn a_bare_node_object_parses() {
        let node: Node =
            serde_json::from_str(r#"{"metadata":{"name":"manacor"},"spec":{},"status":{}}"#)
                .unwrap();
        assert_eq!(node.metadata.name, "manacor");
        assert!(node.spec.schedulable);
        assert_eq!(readiness(node.status.ready, node.spec.schedulable), "no");
        assert_eq!(mem(node.status.capacity.mem_mib), "-");

        let row = node_row(node, Utc::now());
        assert_eq!(row, vec!["manacor", "no", "never", "0", "-", "-"]);
    }
}
