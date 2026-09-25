// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! VM commands and listings at cloud and cluster endpoints.
//! Lifecycle commands update intent; observed completion arrives asynchronously.

use std::path::Path;

use anyhow::{Context, Result, bail};
use bytes::Bytes;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::generic::Ctx;
use crate::output::{self, View, or_dash};

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
    /// What a drain may do to it: `never` or `restart`. Absent is the
    /// default, which is `never` — the field is skipped on the wire at its
    /// default, so every vm written before it reads exactly right.
    #[serde(default)]
    evacuation: Option<String>,
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
    /// Present only while a move-by-restart is in flight. Read as a boolean
    /// here — which step it is in is `vm get`'s business.
    #[serde(default)]
    evacuating: Option<serde_json::Value>,
}

/// The one column the two tiers do not share.
#[derive(Copy, Clone)]
pub enum Placement {
    Node,
    Cluster,
}

impl Placement {
    /// Show evacuation policy only when at least one VM has a non-default policy.
    fn headers(self, evacuation: bool) -> Vec<&'static str> {
        let binding = match self {
            Self::Node => "node",
            Self::Cluster => "cluster",
        };
        let mut out = vec!["name", "tenant", "run"];
        if evacuation {
            out.push("evac");
        }
        out.extend([binding, "phase", "note"]);
        out
    }
}

/// The listing row. `note` is last on purpose: it is the only cell here that
/// can carry a server sentence, spaces and all.
fn row(placement: Placement, vm: Vm, evacuation: bool) -> Vec<String> {
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
    let mut row = vec![
        vm.metadata.name,
        or_dash(vm.spec.tenant),
        or_dash(vm.spec.run_strategy),
    ];
    if evacuation {
        // The default is skipped on the wire, so absent reads as `never` —
        // which is what it means, and what a drain will do about this vm.
        row.push(vm.spec.evacuation.unwrap_or_else(|| "never".to_string()));
    }
    row.extend([placed.unwrap_or_else(|| "-".to_string()), phase]);
    // `evacuating` is a mark and not a phase, and it says the one thing
    // neither of the columns beside it can: this vm is deliberately off right
    // now because somebody is emptying the machine under it.
    row.push(match vm.status.evacuating {
        Some(_) => match vm.status.message {
            Some(said) if !said.is_empty() => format!("moving; {said}"),
            _ => "moving off this machine".to_string(),
        },
        None => vm.status.message.unwrap_or_default(),
    });
    row
}

/// Wrap a NewVmSpec file in a VM resource.
/// Omit unspecified tenant and class fields so the server can apply its defaults.
fn object(
    name: &str,
    spec: &Path,
    run_strategy: Option<&str>,
    tenant: Option<&str>,
    class: Option<&str>,
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
    if let Some(class) = class {
        object["spec"]["class"] = json!(class);
    }
    Ok(object)
}

pub async fn create(
    ctx: &Ctx<'_>,
    name: &str,
    spec: &Path,
    run_strategy: Option<&str>,
    class: Option<&str>,
) -> Result<()> {
    let object = object(
        name,
        spec,
        run_strategy,
        ctx.global.tenant.as_deref(),
        class,
    )?;
    let body = ctx.post("vms", object).await?;
    output::emit_line(ctx.global, &body, name)
}

/// The vm listing, for whichever endpoint answered.
pub fn table(body: &Bytes, placement: Placement) -> Result<View> {
    let list: output::List<Vm> = serde_json::from_slice(body).context("parsing vm list")?;
    // Asked of the whole listing before any row is built: a column exists
    // because something in the answer needs it, not because the kind has the
    // field.
    let evacuation = list
        .items
        .iter()
        .any(|v| v.spec.evacuation.as_deref().is_some_and(|e| e != "never"));
    let rows = list
        .items
        .into_iter()
        .map(|vm| row(placement, vm, evacuation))
        .collect();
    Ok(View::table_of_columns(
        placement.headers(evacuation),
        rows,
        "no vms here",
    ))
}

/// A guest log stream; serialization also supports structured output.
#[derive(Deserialize, Serialize)]
pub struct LogStream {
    pub stream: String,
    pub text: String,
}

/// Render filtered guest logs as text or return the server JSON.
pub async fn logs(ctx: &Ctx<'_>, name: &str, lines: Option<u32>, keep: &LogFilter) -> Result<()> {
    let path = format!("{}/logs{}", ctx.path("vms", Some(name))?, keep.query(lines));
    let body = ctx.client.get(&path).await?;
    output::emit(ctx.global, &body, |body| {
        let streams: Vec<LogStream> =
            serde_json::from_slice(body).context("parsing the console output")?;
        Ok(View::text(render_logs(&streams)))
    })
}

/// Build server-side filters so matching happens before the line limit.
#[derive(Debug, Default, Clone)]
pub struct LogFilter {
    pub hide: Vec<String>,
    pub only: Vec<String>,
    /// Which streams. Empty = the guest's own, which is the default at every
    /// tier; `vmm` is the hypervisor's own log and comes only when asked for.
    pub streams: Vec<String>,
}

impl LogFilter {
    pub fn new(hide: &[String], only: &[String], streams: &[String]) -> Self {
        Self {
            hide: hide.to_vec(),
            only: only.to_vec(),
            streams: streams.to_vec(),
        }
    }

    /// The query for `lines` and the needles together, so that the two are
    /// spelled in one place and a caller cannot forget the `?` or the `&`.
    pub fn query(&self, lines: Option<u32>) -> String {
        let mut parts: Vec<String> = Vec::new();
        if let Some(n) = lines {
            parts.push(format!("lines={n}"));
        }
        for (key, values) in [
            ("hide", &self.hide),
            ("only", &self.only),
            ("streams", &self.streams),
        ] {
            for value in values {
                parts.push(format!("{key}={}", urlencode(value)));
            }
        }
        if parts.is_empty() {
            String::new()
        } else {
            format!("?{}", parts.join("&"))
        }
    }
}

/// Percent-encode query values, including separators and non-ASCII bytes.
fn urlencode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char)
            }
            b' ' => out.push_str("%20"),
            other => out.push_str(&format!("%{other:02X}")),
        }
    }
    out
}

/// Render nonempty streams, adding headings only when several remain.
pub fn render_logs(streams: &[LogStream]) -> String {
    // A stream the node filtered empty says nothing, rather than getting a
    // header printed over nothing.
    let spoken: Vec<(&str, String)> = streams
        .iter()
        .map(|s| (s.stream.as_str(), s.text.clone()))
        .filter(|(_, text)| !text.trim().is_empty())
        .collect();
    let named = spoken.len() > 1;
    let mut out = String::new();
    for (stream, text) in spoken {
        if named {
            out.push_str(&format!("=== {stream} ===\n"));
        }
        out.push_str(&text);
        out.push('\n');
    }
    out
}

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

/// Render events with separate repetition counts and a final message column.
pub fn event_table(body: &Bytes) -> Result<View> {
    let now = chrono::Utc::now();
    output::table_of(
        body,
        "parsing the event log",
        &["age", "type", "object", "reason", "count", "message"],
        "nothing has happened recently",
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
}

/// What happened to ONE vm, which is the vm's own subresource and not the
/// event log filtered: the caller has to be allowed to read the OBJECT, and
/// then it gets the object's history.
pub async fn vm_events(ctx: &Ctx<'_>, name: &str) -> Result<()> {
    let path = format!("{}/events", ctx.path("vms", Some(name))?);
    let body = ctx.client.get(&path).await?;
    output::emit(ctx.global, &body, event_table)
}

/// Terminating is what a delete answers with, never "gone": the object is
/// marked and the tier below acts on it, which is the same promise the phase
/// column makes in `vm ls`.
pub async fn remove(ctx: &Ctx<'_>, name: &str) -> Result<()> {
    ctx.confirm("delete", "vm", name)?;
    let body = ctx.client.delete(&ctx.path("vms", Some(name))?).await?;
    output::emit_line(ctx.global, &body, "Terminating")
}

/// Read the volume list and replace it with one merge patch.
/// The boot entry cannot be changed. The patch carries no resourceVersion from
/// this read, so concurrent list edits can overwrite each other.
pub async fn attach(ctx: &Ctx<'_>, name: &str, volume: &str, plug: bool) -> Result<()> {
    let body = ctx.client.get(&ctx.path("vms", Some(name))?).await?;
    let object: serde_json::Value = serde_json::from_slice(&body)?;
    let entries = object
        .get("spec")
        .and_then(|s| s.get("vm"))
        .and_then(|v| v.get("volumes"))
        .and_then(serde_json::Value::as_array)
        .cloned()
        .unwrap_or_default();

    let wanted = plugged(&entries, volume, plug).with_context(|| format!("vm {name}"))?;
    let body = ctx
        .patch(
            "vms",
            name,
            json!({ "spec": { "vm": { "volumes": wanted } } }),
        )
        .await?;
    // What is recorded is the INTENT. Whether the guest has the disk is
    // `vm get`'s answer — `status.volumes` — and it arrives when the node
    // says so, which is what `observedGeneration` waits for.
    output::emit_line(ctx.global, &body, volume)
}

/// Compute an attachment list without changing the boot entry.
/// Reject duplicate attachment, missing detachment and malformed lists locally.
fn plugged(
    entries: &[serde_json::Value],
    volume: &str,
    plug: bool,
) -> Result<Vec<serde_json::Value>> {
    let names = |e: &serde_json::Value| {
        e.get("volume")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|n| n == volume)
    };
    // The boot entry, whichever way round the request was: a guest does not
    // survive having its root disk swapped, and there is no moment at which
    // adding it a second time means anything either.
    if entries.first().is_some_and(names) {
        bail!("{volume} is the boot entry, and the boot entry is immutable");
    }
    let mut wanted = entries.to_vec();
    match plug {
        true => {
            if entries.iter().any(names) {
                bail!("already has {volume}");
            }
            wanted.push(json!({ "volume": volume }));
        }
        false => {
            if !entries.iter().any(names) {
                bail!("does not have {volume}");
            }
            wanted.retain(|e| !names(e));
        }
    }
    Ok(wanted)
}

/// Clear placement bindings so the controller can reschedule a stopped VM.
pub async fn reschedule(ctx: &Ctx<'_>, name: &str) -> Result<()> {
    // Clear both tier-specific bindings; the serving controller uses its own field.
    let body = ctx
        .patch(
            "vms",
            name,
            json!({ "spec": { "nodeName": null, "clusterName": null } }),
        )
        .await?;
    output::emit_note(
        ctx.global,
        &body,
        "Pending",
        "note: inline disks are an instance store: they were made with the vm on that machine \
         and are made fresh at the destination. A `Volume` object follows the vm; its bytes do \
         not move.",
    )
}

/// Create a VmMigration named from the VM and the current UTC second.
pub async fn migrate(ctx: &Ctx<'_>, name: &str, to: Option<&str>) -> Result<()> {
    // For older endpoints without migration creation, identify the owning cluster.
    // Current clouds forward creation through the cluster session.
    if ctx.disc.offering("vmmigrations", "create").is_err() {
        let cluster = ctx
            .client
            .get(&ctx.path("vms", Some(name))?)
            .await
            .ok()
            .and_then(|body| serde_json::from_slice::<serde_json::Value>(&body).ok())
            .as_ref()
            .and_then(cluster_of)
            .map(str::to_string);
        bail!(ask_the_cluster(name, cluster.as_deref(), to));
    }
    let mut spec = json!({ "vm": name });
    if let Some(node) = to {
        spec["targetNode"] = json!(node);
    }
    let object = json!({
        "apiVersion": "meister.io/v1",
        "kind": "VmMigration",
        "metadata": { "name": migration_name(name, Utc::now()) },
        "spec": spec,
    });
    let body = ctx.post("vmmigrations", object).await?;
    output::emit_note(
        ctx.global,
        &body,
        "Pending",
        "note: the guest keeps running; `vmmigration get` follows the phases, and a failure \
         leaves the vm exactly where it is",
    )
}

/// Which cluster a cloud's VM object says it runs on: the binding if there is
/// one, and otherwise where the node reported it from.
fn cluster_of(vm: &serde_json::Value) -> Option<&str> {
    for path in [("status", "clusterName"), ("spec", "clusterName")] {
        if let Some(named) = vm
            .get(path.0)
            .and_then(|o| o.get(path.1))
            .and_then(serde_json::Value::as_str)
            .filter(|c| !c.is_empty())
        {
            return Some(named);
        }
    }
    None
}

/// Explain how to reach the owning cluster when discovery lacks migration creation.
fn ask_the_cluster(vm: &str, cluster: Option<&str>, to: Option<&str>) -> String {
    let repeat = match to {
        Some(node) => format!("meister vm migrate {vm} --to {node}"),
        None => format!("meister vm migrate {vm}"),
    };
    match cluster {
        Some(cluster) => format!(
            "a live migration is a cluster's to run; ask {cluster}, which is where {vm} runs. \
             Point a profile at that cluster's api and repeat this ({repeat})"
        ),
        None => format!(
            "a live migration is a cluster's to run, and this endpoint is a cloud that cannot \
             say which one runs {vm}; `meister vm get {vm}` names it in CLUSTER. Point a \
             profile at that cluster's api and repeat this ({repeat})"
        ),
    }
}

/// Append a UTC timestamp with second precision.
/// This does not prevent same-second collisions or enforce the name length limit.
fn migration_name(vm: &str, now: DateTime<Utc>) -> String {
    format!("{vm}-{}", now.format("%Y%m%dt%H%M%S"))
}

/// Set the VM owner's permission for restart-based evacuation.
pub async fn evacuation(ctx: &Ctx<'_>, name: &str, value: &str) -> Result<()> {
    if !matches!(value, "never" | "restart") {
        anyhow::bail!("evacuation is `never` or `restart`, not {value:?}");
    }
    let body = ctx
        .patch("vms", name, json!({ "spec": { "evacuation": value } }))
        .await?;
    output::emit_line(ctx.global, &body, value)
}

pub async fn run_strategy(ctx: &Ctx<'_>, name: &str, strategy: &str) -> Result<()> {
    let body = ctx
        .patch("vms", name, json!({ "spec": { "runStrategy": strategy } }))
        .await?;
    output::emit_line(ctx.global, &body, strategy)
}

#[cfg(test)]
mod tests {

    /// Filters must reach the node as correctly escaped query parameters.
    #[test]
    fn the_flags_become_the_query_the_node_reads() {
        let none = LogFilter::default();
        assert_eq!(none.query(None), "", "nothing asked, nothing appended");
        assert_eq!(none.query(Some(20)), "?lines=20");

        let quiet = LogFilter::new(&["alive t=".into()], &[], &[]);
        assert_eq!(quiet.query(Some(5)), "?lines=5&hide=alive%20t%3D");

        // Repeatable, and `only` travels beside `hide` rather than instead
        // of it — the node narrows twice.
        let both = LogFilter::new(&["polling".into()], &["disk:".into(), "net:".into()], &[]);
        assert_eq!(both.query(None), "?hide=polling&only=disk%3A&only=net%3A");

        // The characters that would otherwise break the query out of its own
        // parameter.
        let nasty = LogFilter::new(&["a&b=c d".into()], &[], &[]);
        assert_eq!(nasty.query(None), "?hide=a%26b%3Dc%20d");

        // Naming a stream is how the hypervisor's own log is asked for; not
        // naming one leaves the default to the node.
        let vmm = LogFilter::new(&[], &[], &["vmm".into()]);
        assert_eq!(vmm.query(Some(50)), "?lines=50&streams=vmm");
    }

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
        assert_eq!(row(Placement::Node, cluster_tier, false)[3], "manacor");

        let cloud_tier = vm(
            r#"{"metadata":{"name":"a"},"spec":{"clusterName":"lab","tenant":"ops"},
                "status":{}}"#,
        );
        let row = row(Placement::Cluster, cloud_tier, false);
        assert_eq!(row[1], "ops");
        assert_eq!(row[3], "lab");
        // Nothing placed it and nothing reported on it, and the row still has
        // a cell in every column.
        assert_eq!(row[2], "-");
        assert_eq!(row[4], "-");
    }

    /// The `evac` column exists because something in the ANSWER needs it, not
    /// because the kind has the field. A column of `never` down a whole
    /// estate says nothing and costs a column.
    #[test]
    fn the_evacuation_column_appears_only_where_a_vm_has_answered() {
        let plain = Bytes::from(
            r#"{"items":[{"metadata":{"name":"a"},"spec":{"nodeName":"agent-1"},
                          "status":{"phase":"Running"}}]}"#,
        );
        let View::Table(rendered) = table(&plain, Placement::Node).unwrap() else {
            panic!("a table")
        };
        assert!(
            !rendered.render()[0].contains("EVAC"),
            "nobody said anything"
        );

        let opted_in = Bytes::from(
            r#"{"items":[
                {"metadata":{"name":"a"},"spec":{"nodeName":"agent-1","evacuation":"restart"},
                 "status":{"phase":"Running"}},
                {"metadata":{"name":"b"},"spec":{"nodeName":"agent-1"},
                 "status":{"phase":"Running"}}]}"#,
        );
        let View::Table(shown) = table(&opted_in, Placement::Node).unwrap() else {
            panic!("a table")
        };
        let rendered = shown.render();
        assert!(rendered[0].contains("EVAC"), "{rendered:?}");
        assert!(rendered[1].contains("restart"), "{rendered:?}");
        // The default is skipped on the wire, and absent has to read as what
        // it means rather than as a dash.
        assert!(
            rendered[2].contains("never"),
            "a vm that said nothing still has an answer: {rendered:?}"
        );
    }

    /// The mark is the one thing neither the phase nor the binding can say:
    /// this vm is deliberately off right now because somebody is emptying the
    /// machine under it.
    #[test]
    fn a_vm_being_moved_by_restart_says_so_in_the_note() {
        let moving = vm(r#"{"metadata":{"name":"a"},
                "spec":{"nodeName":"agent-1","runStrategy":"Running"},
                "status":{"phase":"Stopped",
                          "evacuating":{"from":"agent-1","step":"Stopping",
                                        "since":"2026-09-09T10:00:00Z"}}}"#);
        let cells = row(Placement::Node, moving, false);
        assert_eq!(cells[2], "Running", "the owner still wants it running");
        assert_eq!(cells[4], "Stopped", "and it is not, right now");
        assert!(
            cells[5].contains("moving off this machine"),
            "{:?}",
            cells[5]
        );
    }

    /// A name an operator can read back in `vmmigration ls`, and a DNS label.
    #[test]
    fn a_migration_is_named_after_the_vm_and_the_moment() {
        let at = DateTime::parse_from_rfc3339("2026-09-09T11:42:33Z")
            .unwrap()
            .with_timezone(&Utc);
        let name = migration_name("web-1", at);
        assert_eq!(name, "web-1-20260909t114233");
        assert!(
            name.chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-'),
            "a dns label: {name}"
        );
    }

    /// A deletion in flight outranks the phase the tier below last reported.
    #[test]
    fn a_vm_on_its_way_out_says_so_whatever_the_last_phase_was() {
        let dying = vm(
            r#"{"metadata":{"name":"a","deletionTimestamp":"2026-01-01T00:00:00Z"},
                "spec":{},"status":{"phase":"Running"}}"#,
        );
        assert_eq!(row(Placement::Node, dying, false)[4], "Terminating");
    }

    /// Only the note may carry a server sentence; everything before it is one
    /// token, or `awk` reads the wrong column.
    #[test]
    fn only_the_last_column_may_carry_a_space() {
        let noisy = vm(r#"{"metadata":{"name":"a"},"spec":{},
                "status":{"phase":"Failed","message":"no node has 8 vcpus free"}}"#);
        let cells = row(Placement::Node, noisy, false);
        for cell in &cells[..cells.len() - 1] {
            assert!(!cell.contains(' '), "{cell:?} carries a raw space");
        }
    }

    /// The tenant key is absent, not null, when nobody named one — the server
    /// tells those two apart.
    #[test]
    fn an_unnamed_tenant_is_left_out_of_the_request() {
        // Isolate the fixture from concurrent test runs.
        let dir = tempfile::tempdir().expect("a directory of our own");
        let spec = dir.path().join("spec.json");
        std::fs::write(&spec, br#"{"vcpus":2}"#).unwrap();

        let bare = object("a", &spec, None, None, None).unwrap();
        assert!(bare["spec"].get("tenant").is_none());
        assert_eq!(bare["spec"]["runStrategy"], "Running");
        assert_eq!(bare["spec"]["vm"]["vcpus"], 2);
        assert_eq!(bare["kind"], "Vm");

        let owned = object("a", &spec, Some("Stopped"), Some("ops"), None).unwrap();
        assert_eq!(owned["spec"]["tenant"], "ops");
        assert_eq!(owned["spec"]["runStrategy"], "Stopped");

        // Omit unspecified class so the server applies its default.
        assert!(bare["spec"].get("class").is_none());
        let gpu = object("a", &spec, None, None, Some("gpu")).unwrap();
        assert_eq!(gpu["spec"]["class"], "gpu");
    }

    /// Attachment patches replace the whole array and preserve the boot entry.
    #[test]
    fn attaching_sends_the_whole_list_and_never_touches_the_boot_entry() {
        let vol = |n: &str| serde_json::json!({ "volume": n });
        let inline = serde_json::json!({ "size_bytes": 1073741824 });
        let entries = vec![vol("root-1"), inline.clone(), vol("data-2")];

        // The attach: appended, and nothing else moves — the inline entry
        // keeps its place, which is what the server's own projection
        // requires.
        let after = plugged(&entries, "data-3", true).expect("attaching");
        assert_eq!(
            after,
            vec![vol("root-1"), inline.clone(), vol("data-2"), vol("data-3")]
        );

        // The detach: one entry gone, the rest in order.
        let after = plugged(&entries, "data-2", false).expect("detaching");
        assert_eq!(after, vec![vol("root-1"), inline]);

        // And the three refusals, each of which the server would also give.
        for (volume, plug, said) in [
            ("root-1", false, "boot entry"),
            ("root-1", true, "boot entry"),
            ("data-2", true, "already has"),
            ("data-9", false, "does not have"),
        ] {
            let e = plugged(&entries, volume, plug).expect_err(volume);
            assert!(format!("{e:#}").contains(said), "{volume}: {e:#}");
        }

        // A vm with no volumes at all takes its first one, which is the
        // boot entry — and then the server refuses it, because a vm's boot
        // disk is decided when the vm is.
        let first = plugged(&[], "data-1", true).expect("nothing to collide with");
        assert_eq!(first, vec![vol("data-1")]);
    }

    /// Legacy discovery without migration creation should identify the owning cluster.
    #[test]
    fn a_migration_asked_of_a_cloud_names_the_cluster_that_can_serve_it() {
        let vm = serde_json::json!({
            "metadata": {"name": "web-1"},
            "spec": {"clusterName": "cluster-1"},
            "status": {"clusterName": "cluster-1", "phase": "Running"},
        });
        assert_eq!(cluster_of(&vm), Some("cluster-1"));

        let said = ask_the_cluster("web-1", cluster_of(&vm), Some("agent-1c"));
        assert!(said.contains("ask cluster-1"), "{said}");
        assert!(
            said.contains("meister vm migrate web-1 --to agent-1c"),
            "the command they typed, to repeat at the right endpoint: {said}"
        );

        // A VM the cloud has not placed yet: no cluster to name, and the
        // sentence says how to find it rather than inventing one.
        let unplaced = serde_json::json!({"metadata": {"name": "web-1"}, "spec": {}});
        assert_eq!(cluster_of(&unplaced), None);
        let said = ask_the_cluster("web-1", None, None);
        assert!(said.contains("meister vm get web-1"), "{said}");
        assert!(said.ends_with("(meister vm migrate web-1)"), "{said}");

        // The binding is preferred over the report, and an empty string is
        // not a name.
        let bound = serde_json::json!({
            "spec": {"clusterName": "cluster-2"}, "status": {"clusterName": ""},
        });
        assert_eq!(cluster_of(&bound), Some("cluster-2"));
    }
}
