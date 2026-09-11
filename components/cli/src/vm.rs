// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! The VM verbs, and the two tables this CLI renders most often.
//!
//! There is one tree now and one path — `vms` out of the discovery document —
//! and the only thing the tier still decides is one column: a cloud places a
//! VM on a CLUSTER and a cluster places it on a NODE, and the listing says
//! which. Everything else about a VM reads the same at either endpoint,
//! because it is the same object.
//!
//! The four lifecycle verbs are one merge patch each. They are sugar over a
//! spec field and nothing more, which is why the answer is always "the intent
//! is recorded" and never "the vm is stopped": that arrives later, in `vm ls`,
//! from the node itself.

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
    /// `evac` is between `run` and the binding, because that is where it
    /// belongs in a reading: what the vm is meant to be doing, what may be
    /// done to it to move it, and where it is. It is shown only in a listing
    /// where at least one vm has said something other than the default — a
    /// column of `never` down the whole estate says nothing and costs a
    /// column.
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

/// The object a `vm create` sends: the agent's NewVmSpec, read off disk and
/// wrapped in the api object the tier takes.
///
/// `tenant` is omitted rather than sent as null when nobody named one: the
/// server fills a member's own tenant in, and a key that is there saying
/// "nothing" is not the same request as one that is absent. The cluster tier
/// never names one at all.
/// `class` is omitted the same way and for the same reason, one field over:
/// the server reads an absent class as the ordinary one, and a key saying
/// `"vm"` would put a decision nobody made onto every object.
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

/// One stream of a guest's one-way output, as every tier serves it.
///
/// `Serialize` as well, for the one job that writes one back: a `--hide` under
/// `-o json` has to reach the document a script reads, or the flag would be a
/// flag that silently did nothing there.
#[derive(Deserialize, Serialize)]
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
pub async fn logs(ctx: &Ctx<'_>, name: &str, lines: Option<u32>, keep: &LogFilter) -> Result<()> {
    let path = format!("{}/logs{}", ctx.path("vms", Some(name))?, keep.query(lines));
    let body = ctx.client.get(&path).await?;
    output::emit(ctx.global, &body, |body| {
        let streams: Vec<LogStream> =
            serde_json::from_slice(body).context("parsing the console output")?;
        Ok(View::text(render_logs(&streams)))
    })
}

/// Which of a console's lines the caller wants — carried to the node, not
/// applied here.
///
/// It began as a client-side filter and that was wrong, in a way the lab made
/// obvious: the server shortens to `lines` FIRST, so a filter afterwards can
/// only narrow what is already the last N lines. Ask for the last five lines
/// of a guest whose init prints a heartbeat every ten seconds and all five
/// are the heartbeat — filtering them away leaves nothing. The node holds the
/// whole ring, so the node is the only party that can filter and THEN
/// shorten, which is what `--lines 5 --hide alive` obviously means.
///
/// So this builds a query string and nothing else. Under `-o json` the
/// document is the server's, byte for byte, filter or no filter — because the
/// filtering happened before it was a document.
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

/// Percent-encoding for a query VALUE, as far as a needle needs it: a
/// dependency for eleven characters is a dependency too many, and what has to
/// be escaped is exactly what would otherwise end the value or begin another
/// parameter.
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

/// The streams a node handed back, as lines.
///
/// A header per stream, but only when there is more than one: a direct-kernel
/// boot puts everything on `console`, and a lone banner over the whole output
/// is noise. Shared with the agent tree, which reads the same document one
/// hop closer.
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

/// The event log, at whichever tier the client is pointed at.
///
/// `count` has a column of its own because it is the difference between "this
/// went wrong" and "this went wrong twenty times", and the message is last
/// because it is the one cell that carries a server sentence with spaces in
/// it.
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

/// start/stop/pause/resume are sugar, not a second API: runStrategy is a spec
/// field like any other, so each verb is one merge patch of it and the
/// controller derives the command from the drift it causes. Which also means
/// the answer here is "the intent is recorded", never "the vm is stopped" —
/// that arrives later, in `vm ls`, from the node itself.
///
/// One call and no GET in front of it. This used to be a read, an edit and a
/// compare-and-swap, and it lost that race often enough to need a retry loop:
/// the controller writes the same object on every pass. The server now
/// compares against the version it read itself, and there is nothing left to
/// lose.
/// Plug a volume into a running vm, or unplug one.
///
/// **One PATCH with the whole list**, and that is the price of the standard
/// rather than a choice: a JSON merge patch replaces an array outright (RFC
/// 7386), so "add one entry" cannot be said as a patch of one entry. The
/// client therefore reads the vm, works out the new list, and sends it — and
/// the server compares against the version IT read, so the round trip is not
/// a race the operator can lose silently.
///
/// The boot entry is never touched: it is `volumes[0]`, the server refuses a
/// change to it with a 422, and this refuses it here too so that a person
/// asking for something impossible is told without a round trip.
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

/// The list a vm's spec should carry after plugging `volume` in or taking it
/// out, or the sentence that says why it should not change at all.
///
/// Pure, because it is the whole of what this client DECIDES: everything
/// around it is one GET and one PATCH. Three refusals, and each is something
/// the server would say too — said here so that a person asking for
/// something impossible hears it without a round trip, and never instead of
/// the server, which is the refusal nobody can go around.
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

/// Let a binding go so the scheduler decides again.
///
/// One merge patch of `spec.nodeName`, exactly like `stop` is one of
/// `runStrategy`: the reschedule is a spec edit and the controller derives
/// the destroy and the placement from the drift it causes. The server refuses
/// it on a vm that is not standing still, and the sentence names the phase.
pub async fn reschedule(ctx: &Ctx<'_>, name: &str) -> Result<()> {
    // Both, because either tier may be the one holding this vm and each
    // ignores the other's binding — the same "one Vm type, two tiers" rule
    // the table column follows. At the CLOUD this is now a real move: the
    // binding falls, the old cluster is told to destroy the vm, and disks on
    // a pool both clusters serve change owner without being copied.
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

/// `vm migrate NAME [--to NODE]` — one `VmMigration` object, named after the
/// VM and the moment.
///
/// The name is generated rather than asked for, and that is the difference
/// from every other create in this CLI: a migration is not a thing an
/// operator will refer to by name later, it is a record they will read once,
/// and making them invent a name for it would be making them do bookkeeping
/// for the machine. `vmmigration ls` is how it is found.
pub async fn migrate(ctx: &Ctx<'_>, name: &str, to: Option<&str>) -> Result<()> {
    // An endpoint that cannot create one at all — an older cloud, from before
    // `CreateVmMigration` existed. The bare discovery refusal ("this endpoint
    // is a cloud and has no \"vmmigrations\"") leaves an operator at a dead
    // end, so this says which cluster runs the guest instead: one GET, and
    // only on the endpoint where the answer is needed.
    //
    // A current cloud does not come here. It serves `create` — forwarded down
    // the cluster's own session, which is how every other write this tier
    // relays travels (D-P9) — and the POST below is the whole of what a
    // client has to do differently, which is nothing.
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

/// What to tell somebody who asked a cloud to move a guest between machines.
///
/// Pure, because it is the whole of what this verb does at that endpoint and
/// because the sentence IS the fix: the old one named what the endpoint does
/// not have, this one names where to go and repeats the command they typed.
///
/// A cloud cannot forward this today, and that is not a decision anybody made
/// here — a node patch travels down the cluster's session because there is an
/// `UpdateNode` on that session to carry it, and there is no such message for
/// a migration. Until there is, saying so beats a 404.
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

/// `<vm>-<utc, to the second>`, which is a DNS label and is unique for as
/// long as nobody asks twice in one second.
///
/// Deliberately readable rather than a uuid: this is the name an operator
/// sees in `vmmigration ls` beside three others, and "web-1-20260909t114233"
/// answers "which move was that" where a uuid does not.
fn migration_name(vm: &str, now: DateTime<Utc>) -> String {
    format!("{vm}-{}", now.format("%Y%m%dt%H%M%S"))
}

/// `vm evacuation NAME never|restart`.
///
/// A word and not a flag on `node drain`, because the answer belongs to the
/// vm's OWNER and the drain belongs to the operator. An operator who could
/// pass it as a flag would be answering, for somebody else, whether their
/// guest may be rebooted.
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

    /// What the CLI now does with `--hide`: it asks, it does not filter.
    ///
    /// The filtering moved to the node, and this is what is left here — the
    /// query that carries the request. Held to the wire form because a needle
    /// with a space or an ampersand in it would otherwise end the parameter
    /// or start another one.
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
        // A directory of its own, and one that goes away on a panic as well
        // as on a pass: this used to be a FIXED path under /tmp, so two
        // `cargo test` runs at once — or one beside the leftovers of a
        // crashed one — raced over the same file.
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

        // The class travels the same road, one field over: absent when
        // nobody named one, because the server reads that as the ordinary
        // class and a key saying `"vm"` would put a decision nobody made
        // onto every object.
        assert!(bare["spec"].get("class").is_none());
        let gpu = object("a", &spec, None, None, Some("gpu")).unwrap();
        assert_eq!(gpu["spec"]["class"], "gpu");
    }

    /// The list arithmetic behind `vm attach` and `vm detach`.
    ///
    /// The whole of what this client decides. Around it is one GET and one
    /// PATCH — and the PATCH carries the WHOLE list, because a JSON merge
    /// patch replaces an array outright (RFC 7386) and "add one entry"
    /// therefore cannot be said as a patch of one entry. That is the price of
    /// the standard, and it is what the guide says.
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

    /// D-P9: `vm migrate` at a cloud ended in "this endpoint is a cloud and
    /// has no \"vmmigrations\"" — true, and a dead end. The cloud knows
    /// which cluster runs the guest, so the refusal now says where to go and
    /// repeats the command that was typed.
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
