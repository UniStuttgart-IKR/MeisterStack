// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! The VM object, as the cluster and the cloud tier both serve it.
//!
//! Two command trees, because two tiers: `meister cluster vm` places a VM on
//! a node, `meister cloud vm` places it on a cluster, and an operator is
//! talking to different machines when they say the two. Underneath, it is one
//! object at one path with one spec — so the verbs stay apart and the
//! machinery under them lives here, where a fix to it is a fix at both tiers.

use std::path::Path;

use anyhow::{Context, Result, anyhow};
use serde::Deserialize;
use serde_json::json;

use crate::GlobalArgs;
use crate::client::{Client, is_conflict};
use crate::output::{self, or_dash};

/// The same path at both tiers, and not a coincidence: the cloud serves the
/// same kind under the same group, one level up.
pub const VMS: &str = "/apis/meister.io/v1/vms";

#[derive(Deserialize)]
pub struct Vm {
    metadata: Meta,
    spec: Spec,
    #[serde(default)]
    status: Status,
}

#[derive(Deserialize)]
struct Meta {
    name: String,
    #[serde(default, rename = "deletionTimestamp")]
    deletion_timestamp: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Spec {
    /// Where the cluster tier put it, and where the cloud tier did. Exactly
    /// one of the two is ever filled in, and which one is the tier talking.
    #[serde(default)]
    node_name: Option<String>,
    #[serde(default)]
    cluster_name: Option<String>,
    #[serde(default)]
    run_strategy: Option<String>,
    /// Whose VM this is, as the cloud handed it down. A VM created straight
    /// at the cluster tier has none — there is no directory there to name one
    /// from.
    #[serde(default)]
    tenant: Option<String>,
}

#[derive(Deserialize, Default)]
struct Status {
    #[serde(default)]
    phase: Option<String>,
    #[serde(default)]
    message: Option<String>,
}

/// The one column the two tiers do not share.
#[derive(Copy, Clone)]
pub enum Placement {
    Node,
    Cluster,
}

impl Placement {
    const fn headers(self) -> &'static [&'static str] {
        match self {
            Self::Node => &["name", "tenant", "run", "node", "phase", "note"],
            Self::Cluster => &["name", "tenant", "run", "cluster", "phase", "note"],
        }
    }
}

/// The listing row. `note` is last on purpose: it is the only cell here that
/// can carry a server sentence, spaces and all.
fn row(placement: Placement, vm: Vm) -> Vec<String> {
    // Terminating is a fact about the object, and it outranks whatever phase
    // the tier below last reported for it.
    let phase = if vm.metadata.deletion_timestamp.is_some() {
        "Terminating".to_string()
    } else {
        or_dash(vm.status.phase)
    };
    let placed = match placement {
        Placement::Node => vm.spec.node_name,
        Placement::Cluster => vm.spec.cluster_name,
    };
    vec![
        vm.metadata.name,
        or_dash(vm.spec.tenant),
        or_dash(vm.spec.run_strategy),
        or_dash(placed),
        phase,
        vm.status.message.unwrap_or_default(),
    ]
}

/// The object a `vm create` sends: the agent's NewVmSpec, read off disk and
/// wrapped in the api object the tier takes.
///
/// `tenant` is omitted rather than sent as null when nobody named one: the
/// server fills a member's own tenant in, and a key that is there saying
/// "nothing" is not the same request as one that is absent. The cluster tier
/// never names one at all.
fn object(
    name: &str,
    spec: &Path,
    run_strategy: Option<&str>,
    tenant: Option<&str>,
) -> Result<serde_json::Value> {
    let raw =
        std::fs::read(spec).with_context(|| format!("reading spec file {}", spec.display()))?;
    let vm_spec: serde_json::Value =
        serde_json::from_slice(&raw).context("spec file is not valid json")?;
    let mut object = json!({
        "apiVersion": "meister.io/v1",
        "kind": "Vm",
        "metadata": { "name": name },
        "spec": {
            "runStrategy": run_strategy.unwrap_or("Running"),
            "vm": vm_spec,
        },
    });
    if let Some(tenant) = tenant {
        object["spec"]["tenant"] = json!(tenant);
    }
    Ok(object)
}

pub async fn create(
    client: &Client,
    global: &GlobalArgs,
    name: &str,
    spec: &Path,
    run_strategy: Option<&str>,
    tenant: Option<&str>,
) -> Result<()> {
    let object = object(name, spec, run_strategy, tenant)?;
    let body = client.post(VMS, Some(serde_json::to_vec(&object)?)).await?;
    output::emit_line(global, &body, name)
}

pub async fn list(
    client: &Client,
    global: &GlobalArgs,
    placement: Placement,
    empty_note: &'static str,
) -> Result<()> {
    let body = client.get(VMS).await?;
    output::emit(global, &body, |body| {
        output::table_of(
            body,
            "parsing vm list",
            placement.headers(),
            empty_note,
            |vm| row(placement, vm),
        )
    })
}

/// One stream of a guest's one-way output, as every tier serves it.
#[derive(Deserialize)]
pub struct LogStream {
    pub stream: String,
    pub text: String,
}

/// `vm logs`, at whichever tier the client is pointed at.
///
/// Printed as text and not as a table: a console is lines, and a table cell
/// with a kernel oops in it is a table nobody can read. Under `-o json` the
/// document goes out as the server sent it, which is what a script wants.
///
/// A VM that has printed nothing prints nothing — an empty answer is an
/// answer, and it is the commonest one for a VM that has only just been
/// created.
pub async fn logs(
    client: &Client,
    global: &GlobalArgs,
    path: &str,
    name: &str,
    lines: Option<u32>,
) -> Result<()> {
    let query = match lines {
        Some(n) => format!("?lines={n}"),
        None => String::new(),
    };
    let body = client.get(&format!("{path}/{name}/logs{query}")).await?;
    output::emit(global, &body, |body| {
        let streams: Vec<LogStream> =
            serde_json::from_slice(body).context("parsing the console output")?;
        let spoken: Vec<&LogStream> = streams.iter().filter(|s| !s.text.is_empty()).collect();
        // A header per stream, but only when there is more than one: a
        // direct-kernel boot puts everything on `console`, and a lone banner
        // over the whole output is noise.
        let named = spoken.len() > 1;
        let mut out = String::new();
        for stream in spoken {
            if named {
                out.push_str(&format!("=== {} ===\n", stream.stream));
            }
            out.push_str(&stream.text);
            out.push('\n');
        }
        Ok(output::View::text(out))
    })
}

/// The path every tier serves the log under.
pub const EVENTS: &str = "/apis/meister.io/v1/events";

/// One recorded happening, as every tier serves it.
#[derive(Deserialize)]
pub struct Event {
    pub spec: EventSpec,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EventSpec {
    pub involved_kind: String,
    pub involved_name: String,
    pub reason: String,
    #[serde(default)]
    pub message: String,
    #[serde(default)]
    pub event_type: String,
    #[serde(default)]
    pub count: u32,
    pub last_seen: chrono::DateTime<chrono::Utc>,
}

/// The event log, at whichever tier the client is pointed at.
///
/// `count` has a column of its own because it is the difference between "this
/// went wrong" and "this went wrong twenty times", and the message is last
/// because it is the one cell that carries a server sentence with spaces in
/// it.
pub async fn events(
    client: &Client,
    global: &GlobalArgs,
    path: &str,
    empty_note: &'static str,
) -> Result<()> {
    let body = client.get(path).await?;
    let now = chrono::Utc::now();
    output::emit(global, &body, |body| {
        output::table_of(
            body,
            "parsing the event log",
            &["age", "type", "object", "reason", "count", "message"],
            empty_note,
            |e: Event| {
                vec![
                    output::age(Some(e.spec.last_seen), now),
                    e.spec.event_type,
                    format!("{}/{}", e.spec.involved_kind, e.spec.involved_name),
                    e.spec.reason,
                    e.spec.count.to_string(),
                    e.spec.message,
                ]
            },
        )
    })
}

/// The whole object, at either tier, and only ever as json: an inspect is
/// what an operator reads when the table left something out.
pub async fn inspect(client: &Client, name: &str) -> Result<()> {
    output::print_json(&client.get(&format!("{VMS}/{name}")).await?);
    Ok(())
}

/// Terminating is what a delete answers with, never "gone": the object is
/// marked and the tier below acts on it, which is the same promise the phase
/// column makes in `vm ls`.
pub async fn destroy(client: &Client, global: &GlobalArgs, name: &str) -> Result<()> {
    let body = client.delete(&format!("{VMS}/{name}")).await?;
    output::emit_line(global, &body, "Terminating")
}

/// start/stop/pause/resume are sugar, not a second API: runStrategy is a
/// spec field like any other, so each verb is a read-modify-write of it and
/// the controller derives the command from the drift it causes. Which also
/// means the answer here is "the intent is recorded", never "the vm is
/// stopped" — that arrives later, in `vm ls`, from the node itself.
///
/// Shared by both tiers verbatim, because the two really do serve the same
/// path: `vms/<name>` with a runStrategy in the spec. One function, and the
/// sentence above is true at both of them.
pub async fn run_strategy(
    client: &Client,
    name: &str,
    strategy: &str,
    global: &GlobalArgs,
) -> Result<()> {
    let path = format!("{VMS}/{name}");
    let subject = format!("vm {name}");
    let set = |spec: &mut serde_json::Map<String, serde_json::Value>| {
        spec.insert("runStrategy".to_string(), json!(strategy));
        Ok(())
    };
    let mut lost: Option<anyhow::Error> = None;

    // The PUT is a CAS on resourceVersion and the controller writes the same
    // object (scheduling, status), so losing once is ordinary — re-read and
    // try again. Losing twice means something is actually contending for it,
    // and quietly hammering the object would be the wrong answer.
    for _ in 0..2 {
        match client
            .patch_spec(&path, "parsing the vm object", &subject, &set)
            .await
        {
            Ok(body) => return output::emit_line(global, &body, strategy),
            Err(e) if is_conflict(&e) => lost = Some(e),
            Err(e) => return Err(e),
        }
    }
    Err(lost
        .unwrap_or_else(|| anyhow!("update failed"))
        .context(format!("vm {name} kept changing under the update")))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vm(json: &str) -> Vm {
        serde_json::from_str(json).unwrap()
    }

    /// One struct reads both tiers' objects, and the tier decides which of
    /// the two placement fields becomes the column.
    #[test]
    fn each_tier_reads_its_own_placement_out_of_the_same_object() {
        let cluster_tier = vm(
            r#"{"metadata":{"name":"a"},"spec":{"nodeName":"manacor","runStrategy":"Running"},
                "status":{"phase":"Running"}}"#,
        );
        assert_eq!(row(Placement::Node, cluster_tier)[3], "manacor");

        let cloud_tier = vm(
            r#"{"metadata":{"name":"a"},"spec":{"clusterName":"lab","tenant":"ops"},
                "status":{}}"#,
        );
        let row = row(Placement::Cluster, cloud_tier);
        assert_eq!(row[1], "ops");
        assert_eq!(row[3], "lab");
        // Nothing placed it and nothing reported on it, and the row still has
        // a cell in every column.
        assert_eq!(row[2], "-");
        assert_eq!(row[4], "-");
    }

    /// A deletion in flight outranks the phase the tier below last reported.
    #[test]
    fn a_vm_on_its_way_out_says_so_whatever_the_last_phase_was() {
        let dying = vm(
            r#"{"metadata":{"name":"a","deletionTimestamp":"2026-01-01T00:00:00Z"},
                "spec":{},"status":{"phase":"Running"}}"#,
        );
        assert_eq!(row(Placement::Node, dying)[4], "Terminating");
    }

    /// Only the note may carry a server sentence; everything before it is one
    /// token, or `awk` reads the wrong column.
    #[test]
    fn only_the_last_column_may_carry_a_space() {
        let noisy = vm(r#"{"metadata":{"name":"a"},"spec":{},
                "status":{"phase":"Failed","message":"no node has 8 vcpus free"}}"#);
        let cells = row(Placement::Node, noisy);
        for cell in &cells[..cells.len() - 1] {
            assert!(!cell.contains(' '), "{cell:?} carries a raw space");
        }
    }

    /// The tenant key is absent, not null, when nobody named one — the server
    /// tells those two apart.
    #[test]
    fn an_unnamed_tenant_is_left_out_of_the_request() {
        let dir = std::env::temp_dir().join("meister-cli-vm-object-test");
        std::fs::create_dir_all(&dir).unwrap();
        let spec = dir.join("spec.json");
        std::fs::write(&spec, br#"{"vcpus":2}"#).unwrap();

        let bare = object("a", &spec, None, None).unwrap();
        assert!(bare["spec"].get("tenant").is_none());
        assert_eq!(bare["spec"]["runStrategy"], "Running");
        assert_eq!(bare["spec"]["vm"]["vcpus"], 2);
        assert_eq!(bare["kind"], "Vm");

        let owned = object("a", &spec, Some("Stopped"), Some("ops")).unwrap();
        assert_eq!(owned["spec"]["tenant"], "ops");
        assert_eq!(owned["spec"]["runStrategy"], "Stopped");

        std::fs::remove_file(&spec).unwrap();
    }
}
