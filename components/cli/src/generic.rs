// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Resource discovery and generic list, get, delete and apply commands.

use anyhow::{Context, Result, bail};
use bytes::Bytes;
use serde::Deserialize;

use crate::GlobalArgs;
use crate::client::Client;
use crate::output::{self, View};

/// The group-version this CLI speaks, and where the endpoint describes itself.
pub const GROUP: &str = "meister.io/v1";
pub const DISCOVERY: &str = "/apis/meister.io/v1";

/// What an endpoint said about itself.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Discovery {
    /// Server tier: `cloud` or `cluster`.
    #[serde(default)]
    pub tier: String,
    /// The authenticator links this endpoint has, comma-joined, or `none`.
    #[serde(default)]
    pub auth: String,
    #[serde(default)]
    pub resources: Vec<ApiResource>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ApiResource {
    pub name: String,
    pub kind: String,
    #[serde(default)]
    pub verbs: Vec<String>,
    #[serde(default)]
    pub tenant_scoped: bool,
    #[serde(default)]
    pub subresources: Vec<String>,
}

impl Discovery {
    /// The row for this resource, or the sentence saying where it lives.
    pub fn resource(&self, name: &str) -> Result<&ApiResource> {
        if let Some(found) = self.resources.iter().find(|r| r.name == name) {
            return Ok(found);
        }
        match lives_at(name) {
            Some(tier) => bail!(
                "this endpoint is a {} and has no {name:?}; {name} live at the {tier}",
                self.tier
            ),
            None => bail!("this endpoint is a {} and has no {name:?}", self.tier),
        }
    }

    /// Require the advertised verb. An empty verbs list preserves compatibility
    /// with servers that did not publish per-resource capabilities.
    pub fn offering(&self, name: &str, verb: &str) -> Result<&ApiResource> {
        let found = self.resource(name)?;
        if found.verbs.is_empty() || found.verbs.iter().any(|v| v == verb) {
            return Ok(found);
        }
        match lives_at(name) {
            Some(tier) => bail!(
                "this endpoint is a {} and cannot {verb} {name:?}; the {name} themselves live \
                 at the {tier}",
                self.tier
            ),
            None => bail!(
                "this endpoint is a {} and cannot {verb} {name:?}",
                self.tier
            ),
        }
    }

    /// The path of a collection, or of one object in it.
    pub fn path(&self, resource: &str, name: Option<&str>) -> Result<String> {
        let found = self.resource(resource)?;
        Ok(match name {
            Some(name) => format!("{DISCOVERY}/{}/{name}", found.name),
            None => format!("{DISCOVERY}/{}", found.name),
        })
    }

    /// The resource a document's `kind` belongs to — what `apply` needs, and
    /// the only place this CLI reads a kind off a file.
    pub fn resource_of_kind(&self, kind: &str) -> Result<&ApiResource> {
        self.resources
            .iter()
            .find(|r| r.kind == kind)
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "this endpoint is a {} and serves no kind {kind:?}",
                    self.tier
                )
            })
    }

    /// Does this endpoint keep tenants at all? The cluster tier does not, and
    /// `-t` there is an operator talking to the wrong endpoint.
    pub fn is_cloud(&self) -> bool {
        self.tier == "cloud"
    }
}

/// Resolved client, discovery and output/confirmation context.
pub struct Ctx<'a> {
    pub client: Client,
    pub global: &'a GlobalArgs,
    pub disc: Discovery,
    pub endpoint: String,
    pub profile: String,
}

impl Ctx<'_> {
    /// The path of a collection, or of one object in it.
    pub fn path(&self, resource: &str, name: Option<&str>) -> Result<String> {
        self.disc.path(resource, name)
    }

    /// One merge patch, the shape every "set one field" verb in this CLI has.
    pub async fn patch(
        &self,
        resource: &str,
        name: &str,
        patch: serde_json::Value,
    ) -> Result<Bytes> {
        self.client
            .patch(&self.path(resource, Some(name))?, patch)
            .await
    }

    /// One POST, the shape every `create` has.
    pub async fn post(&self, resource: &str, object: serde_json::Value) -> Result<Bytes> {
        self.client
            .post(
                &self.path(resource, None)?,
                Some(serde_json::to_vec(&object)?),
            )
            .await
    }

    pub fn confirm(&self, verb: &str, kind: &str, name: &str) -> Result<()> {
        output::confirm(self.global, &self.endpoint, &self.profile, verb, kind, name)
    }
}

/// Resource homes used to explain unsupported endpoint operations.
fn lives_at(resource: &str) -> Option<&'static str> {
    Some(match resource {
        "tenants"
        | "users"
        | "certificatesigningrequests"
        | "images"
        | "floatingpools"
        | "floatingips"
        | "routedsubnets"
        | "clusters" => "cloud",
        // Migration records live at the cluster; the cloud forwards creation requests.
        "nodes" | "vmmigrations" => "cluster",
        _ => return None,
    })
}

// --- the four verbs that need no code per resource --------------------------

/// List resources with server-side tenant and label filters.
pub async fn list(ctx: &Ctx<'_>, resource: &str, selector: Option<&str>) -> Result<()> {
    let kind = ctx.disc.offering(resource, "list")?.kind.clone();
    let path = format!(
        "{}{}",
        ctx.path(resource, None)?,
        query(ctx.global, selector)
    );
    let body = ctx.client.get(&path).await?;
    let placement = if ctx.disc.is_cloud() {
        crate::vm::Placement::Cluster
    } else {
        crate::vm::Placement::Node
    };
    output::emit(ctx.global, &body, |body| {
        crate::nouns::table_of_kind(&kind, body, placement)
    })
}

/// Print the JSON object or flatten its scalar fields into a table.
pub async fn get(ctx: &Ctx<'_>, resource: &str, name: &str) -> Result<()> {
    ctx.disc.offering(resource, "get")?;
    let body = ctx.client.get(&ctx.path(resource, Some(name))?).await?;
    output::emit(ctx.global, &body, |body| {
        let object: serde_json::Value =
            serde_json::from_slice(body).context("parsing the object")?;
        Ok(output::fields(flatten(&object)))
    })
}

/// `<resource> rm NAME`. The confirmation names the kind and the name.
pub async fn remove(ctx: &Ctx<'_>, resource: &str, name: &str) -> Result<()> {
    let kind = ctx.disc.offering(resource, "delete")?.kind.to_lowercase();
    ctx.confirm("delete", &kind, name)?;
    let body = ctx.client.delete(&ctx.path(resource, Some(name))?).await?;
    // Preserve the distinction between queued deletion and completed removal.
    output::emit_removal(ctx.global, &body, name)
}

/// One document of an `apply -f` file.
#[derive(Deserialize)]
struct Envelope {
    #[serde(default)]
    kind: String,
    #[serde(default)]
    metadata: EnvelopeMeta,
}

#[derive(Default, Deserialize)]
struct EnvelopeMeta {
    #[serde(default)]
    name: String,
}

/// Apply JSON documents in order, stopping at the first error.
/// Create with POST; on AlreadyExists, GET the resource version and replace with PUT.
pub async fn apply(ctx: &Ctx<'_>, files: &[std::path::PathBuf]) -> Result<()> {
    let mut applied: Vec<String> = Vec::new();
    for file in files {
        let raw = std::fs::read(file).with_context(|| format!("reading {}", file.display()))?;
        let parsed: serde_json::Value = serde_json::from_slice(&raw)
            .with_context(|| format!("{} is not valid json", file.display()))?;
        // One object, or an array of them. Both are what a person writes.
        let documents = match parsed {
            serde_json::Value::Array(items) => items,
            other => vec![other],
        };
        for (i, document) in documents.into_iter().enumerate() {
            let what = format!("{}[{i}]", file.display());
            applied.push(
                apply_one(ctx, document)
                    .await
                    .with_context(|| format!("applying {what}"))?,
            );
        }
    }
    output::emit(ctx.global, &Bytes::new(), |_| {
        Ok(View::text(applied.join("\n") + "\n"))
    })
}

async fn apply_one(ctx: &Ctx<'_>, mut document: serde_json::Value) -> Result<String> {
    let envelope: Envelope =
        serde_json::from_value(document.clone()).context("this document has no kind")?;
    if envelope.kind.is_empty() {
        bail!("this document names no kind");
    }
    if envelope.metadata.name.is_empty() {
        bail!("this document names no metadata.name");
    }
    let resource = ctx.disc.resource_of_kind(&envelope.kind)?;
    let collection = format!("{DISCOVERY}/{}", resource.name);
    let name = envelope.metadata.name.clone();

    // A member's own tenant is the server's to fill in; `-t` says it outright.
    if let Some(tenant) = ctx.global.tenant.as_deref()
        && resource.tenant_scoped
        && document.get("spec").and_then(|s| s.get("tenant")).is_none()
    {
        document["spec"]["tenant"] = serde_json::json!(tenant);
    }

    match ctx
        .client
        .post(&collection, Some(serde_json::to_vec(&document)?))
        .await
    {
        Ok(_) => Ok(format!("{} {name} created", resource.kind)),
        Err(e) if crate::client::conflict_reason(&e).as_deref() == Some("AlreadyExists") => {
            let object = format!("{collection}/{name}");
            let current = ctx.client.get(&object).await?;
            let current: serde_json::Value =
                serde_json::from_slice(&current).context("parsing the object as it stands")?;
            // Use the version read from the server for the replacement CAS.
            let version = current
                .get("metadata")
                .and_then(|m| m.get("resourceVersion"))
                .cloned()
                .unwrap_or(serde_json::Value::String(String::new()));
            document["metadata"]["resourceVersion"] = version;
            ctx.confirm("replace", &resource.kind.to_lowercase(), &name)?;
            ctx.client
                .put(&object, Some(serde_json::to_vec(&document)?))
                .await?;
            Ok(format!("{} {name} replaced", resource.kind))
        }
        Err(e) => Err(e),
    }
}

/// `api-resources` — the discovery document as a table.
pub fn api_resources(ctx: &Ctx<'_>, raw: &Bytes) -> Result<()> {
    output::emit(ctx.global, raw, |_| {
        let rows = ctx
            .disc
            .resources
            .iter()
            .map(|r| {
                vec![
                    r.name.clone(),
                    r.kind.clone(),
                    if r.tenant_scoped { "yes" } else { "-" }.to_string(),
                    output::joined(&r.verbs),
                    output::joined(&r.subresources),
                ]
            })
            .collect();
        Ok(View::table(
            &["name", "kind", "tenant-scoped", "verbs", "subresources"],
            rows,
            "this endpoint serves no resources at all",
        ))
    })
}

/// Query server-side event filters. Relative durations are resolved using the CLI clock.
pub async fn events(ctx: &Ctx<'_>, args: &crate::EventsArgs) -> Result<()> {
    let mut narrow: Vec<String> = Vec::new();
    if let Some(about) = args
        .about
        .as_deref()
        .map(str::trim)
        .filter(|a| !a.is_empty())
    {
        match about.split_once('/') {
            Some((kind, name)) => {
                narrow.push(format!("kind={}", escaped(kind)));
                narrow.push(format!("involvedName={}", escaped(name)));
            }
            None => narrow.push(format!("involvedName={}", escaped(about))),
        }
    }
    if let Some(since) = args
        .since
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        narrow.push(format!("since={}", escaped(&instant(since)?)));
    }

    let kind = ctx.disc.resource("events")?.kind.clone();
    let mut path = format!("{}{}", ctx.path("events", None)?, query(ctx.global, None));
    for pair in narrow {
        path.push(if path.contains('?') { '&' } else { '?' });
        path.push_str(&pair);
    }
    let body = ctx.client.get(&path).await?;
    let placement = if ctx.disc.is_cloud() {
        crate::vm::Placement::Cluster
    } else {
        crate::vm::Placement::Node
    };
    output::emit(ctx.global, &body, |body| {
        crate::nouns::table_of_kind(&kind, body, placement)
    })
}

/// Convert a duration in s/m/h/d or an RFC 3339 timestamp to an instant.
pub fn instant(since: &str) -> Result<String> {
    let (count, unit) = since.split_at(since.len().saturating_sub(1));
    let seconds = match (count.parse::<i64>(), unit) {
        (Ok(n), "s") => n,
        (Ok(n), "m") => n * 60,
        (Ok(n), "h") => n * 3600,
        (Ok(n), "d") => n * 86_400,
        _ => {
            // Validate timestamps locally before sending the query.
            return match chrono::DateTime::parse_from_rfc3339(since) {
                Ok(_) => Ok(since.to_string()),
                Err(e) => bail!(
                    "--since {since:?} is neither a duration (1h, 30m, 2d) nor an RFC 3339 \
                     instant: {e}"
                ),
            };
        }
    };
    let floor = chrono::Utc::now() - chrono::Duration::seconds(seconds);
    Ok(floor.to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
}

/// Display the server-reported identity, role, tenant and groups.
pub async fn whoami(ctx: &Ctx<'_>) -> Result<()> {
    let body = ctx
        .client
        .get("/apis/meister.io/v1/whoami")
        .await
        .context("asking the endpoint who we are")?;
    output::emit(ctx.global, &body, |body| {
        let me: Whoami = serde_json::from_slice(body).context("parsing the whoami document")?;
        Ok(View::table(
            &["name", "tenant", "role", "groups", "tier"],
            vec![vec![
                me.name,
                dash(me.tenant),
                dash(me.role),
                if me.groups.is_empty() {
                    "-".to_string()
                } else {
                    output::joined(&me.groups)
                },
                me.tier,
            ]],
            "this endpoint said nothing about you",
        ))
    })
}

fn dash(value: Option<String>) -> String {
    value
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| "-".into())
}

#[derive(Debug, Deserialize)]
struct Whoami {
    name: String,
    /// Absent when the endpoint has no tenant directory.
    #[serde(default)]
    tenant: Option<String>,
    #[serde(default)]
    role: Option<String>,
    #[serde(default)]
    groups: Vec<String>,
    tier: String,
}

// --- the two things that read a server's answer without knowing the kind ----

/// Encode optional tenant and label-selector filters.
pub fn query(global: &GlobalArgs, selector: Option<&str>) -> String {
    let mut parts: Vec<String> = Vec::new();
    if let Some(selector) = selector.map(str::trim).filter(|s| !s.is_empty()) {
        parts.push(format!("labelSelector={}", escaped(selector)));
    }
    if let Some(tenant) = global.tenant.as_deref() {
        parts.push(format!("tenant={}", escaped(tenant)));
    }
    if parts.is_empty() {
        return String::new();
    }
    format!("?{}", parts.join("&"))
}

/// Percent-encode all bytes outside the URL unreserved set.
fn escaped(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for byte in raw.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(byte as char)
            }
            other => out.push_str(&format!("%{other:02X}")),
        }
    }
    out
}

/// Flatten scalar leaves to dotted paths; omit nulls and empty containers.
/// Traversal follows the JSON map order.
pub fn flatten(value: &serde_json::Value) -> Vec<Vec<String>> {
    let mut out = Vec::new();
    walk("", value, &mut out);
    out
}

fn walk(prefix: &str, value: &serde_json::Value, out: &mut Vec<Vec<String>>) {
    match value {
        serde_json::Value::Object(map) => {
            for (key, value) in map {
                let path = if prefix.is_empty() {
                    key.clone()
                } else {
                    format!("{prefix}.{key}")
                };
                walk(&path, value, out);
            }
        }
        serde_json::Value::Array(items) => {
            for (i, item) in items.iter().enumerate() {
                walk(&format!("{prefix}[{i}]"), item, out);
            }
        }
        serde_json::Value::Null => {}
        serde_json::Value::String(s) => out.push(vec![prefix.to_string(), s.clone()]),
        other => out.push(vec![prefix.to_string(), other.to_string()]),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn discovery(tier: &str, resources: &str) -> Discovery {
        serde_json::from_str(&format!(
            r#"{{"tier":"{tier}","auth":"none","resources":{resources}}}"#
        ))
        .unwrap()
    }

    fn cloudish() -> Discovery {
        discovery(
            "cloud",
            r#"[{"name":"vms","kind":"Vm","verbs":["get","list","delete"],
                 "tenantScoped":true,"subresources":["logs","events"]},
                {"name":"tenants","kind":"Tenant","verbs":["get","list"],"tenantScoped":false}]"#,
        )
    }

    /// The path is built from what the endpoint said it has, and nowhere else
    /// in this CLI is a resource segment spelled out.
    #[test]
    fn the_path_comes_out_of_the_discovery_document() {
        let disc = cloudish();
        assert_eq!(disc.path("vms", None).unwrap(), "/apis/meister.io/v1/vms");
        assert_eq!(
            disc.path("vms", Some("web-1")).unwrap(),
            "/apis/meister.io/v1/vms/web-1"
        );
        assert_eq!(disc.resource("vms").unwrap().kind, "Vm");
        assert!(disc.is_cloud());
    }

    /// A noun the endpoint does not serve is a sentence and not a 404 — and
    /// the second half of it is the useful half.
    #[test]
    fn a_noun_this_endpoint_does_not_have_says_where_it_does_live() {
        let cluster = discovery(
            "cluster",
            r#"[{"name":"vms","kind":"Vm","verbs":["get","list"],"tenantScoped":true}]"#,
        );
        let e = cluster.path("tenants", None).unwrap_err().to_string();
        assert_eq!(
            e,
            "this endpoint is a cluster and has no \"tenants\"; tenants live at the cloud"
        );
        assert!(!cluster.is_cloud());

        // And the other direction, for the nouns that live downwards.
        let e = cloudish().path("nodes", None).unwrap_err().to_string();
        assert!(e.contains("nodes live at the cluster"), "{e}");
        // The unsupported resource error should identify the owning tier.
        let e = cloudish()
            .path("vmmigrations", None)
            .unwrap_err()
            .to_string();
        assert!(e.contains("vmmigrations live at the cluster"), "{e}");

        // A noun nothing in this stack has gets the short sentence rather
        // than an invented home.
        let e = cloudish().path("widgets", None).unwrap_err().to_string();
        assert_eq!(e, "this endpoint is a cloud and has no \"widgets\"");
    }

    /// `apply` reads the kind off the document and finds the path from it.
    #[test]
    fn a_document_finds_its_own_collection_by_kind() {
        let disc = cloudish();
        assert_eq!(disc.resource_of_kind("Vm").unwrap().name, "vms");
        let e = disc.resource_of_kind("Widget").unwrap_err().to_string();
        assert!(e.contains("serves no kind \"Widget\""), "{e}");
    }

    /// Send tenant and selector filters to the server.
    #[test]
    fn what_the_caller_asked_to_see_travels_as_a_query() {
        let mut global = crate::GlobalArgs::for_tests();
        assert_eq!(
            query(&global, None),
            "",
            "neither: the query of every listing so far"
        );
        assert_eq!(
            query(&global, Some("zone=lab")),
            "?labelSelector=zone%3Dlab"
        );
        assert_eq!(
            query(&global, Some(" ")),
            "",
            "an empty selector is not a selector"
        );

        global.tenant = Some("acme".into());
        assert_eq!(query(&global, None), "?tenant=acme");
        assert_eq!(
            query(&global, Some("zone=lab,disk=nvme")),
            "?labelSelector=zone%3Dlab%2Cdisk%3Dnvme&tenant=acme"
        );
    }

    /// A selector's own punctuation is encoded, so that nothing on the way
    /// reads `&` in a value as the end of it.
    #[test]
    fn a_selector_says_what_it_meant_however_it_is_spelled() {
        assert_eq!(escaped("zone=lab"), "zone%3Dlab");
        assert_eq!(escaped("a=b&c=d"), "a%3Db%26c%3Dd");
        assert_eq!(escaped("has space"), "has%20space");
        assert_eq!(escaped("plain-1.0_x~y"), "plain-1.0_x~y");
    }

    /// `get` under `-o table`: every leaf, in the order the server wrote it,
    /// and nothing for a key with nothing under it.
    #[test]
    fn an_object_flattens_to_one_line_per_leaf_in_the_servers_own_order() {
        let object = serde_json::json!({
            "apiVersion": "meister.io/v1",
            "kind": "Vm",
            "metadata": { "name": "web-1", "labels": {} },
            "spec": { "runStrategy": "Running", "vm": { "vcpus": 2 } },
            "status": { "phase": "Running", "message": null },
        });
        let rows = flatten(&object);
        let flat: Vec<String> = rows
            .iter()
            .map(|r| format!("{} = {}", r[0], r[1]))
            .collect();
        assert_eq!(
            flat,
            vec![
                "apiVersion = meister.io/v1",
                "kind = Vm",
                "metadata.name = web-1",
                "spec.runStrategy = Running",
                "spec.vm.vcpus = 2",
                "status.phase = Running",
            ]
        );
    }

    /// `--since 1h` is a question about THIS clock, so it becomes an instant
    /// here. A server that answered a duration would answer with its own.
    #[test]
    fn a_since_becomes_an_instant_before_it_is_sent() {
        let hour = instant("1h").expect("a duration");
        let parsed = chrono::DateTime::parse_from_rfc3339(&hour).expect("rfc 3339");
        let ago = chrono::Utc::now() - parsed.with_timezone(&chrono::Utc);
        assert!(
            (3595..=3605).contains(&ago.num_seconds()),
            "an hour ago, give or take the test: {hour}"
        );

        for (raw, seconds) in [("30m", 1800), ("2d", 172_800), ("45s", 45)] {
            let then = chrono::DateTime::parse_from_rfc3339(&instant(raw).unwrap()).unwrap();
            let ago = (chrono::Utc::now() - then.with_timezone(&chrono::Utc)).num_seconds();
            assert!((seconds - 5..=seconds + 5).contains(&ago), "{raw}");
        }

        // An instant is passed through as it stands.
        assert_eq!(
            instant("2026-09-09T06:00:00Z").unwrap(),
            "2026-09-09T06:00:00Z"
        );
        // And a typo is caught here rather than after a round trip.
        let err = instant("yesterday").expect_err("neither").to_string();
        assert!(err.contains("1h, 30m, 2d"), "{err}");
    }

    /// Respect advertised verbs, retaining compatibility with missing verb lists.
    #[test]
    fn an_endpoint_that_serves_one_verb_of_a_resource_says_so_for_the_others() {
        let cloud = discovery(
            "cloud",
            r#"[{"name":"vms","kind":"Vm","verbs":["get","list"],"tenantScoped":true},
                {"name":"vmmigrations","kind":"VmMigration","verbs":["create"],
                 "tenantScoped":true}]"#,
        );
        // The verb it has.
        assert_eq!(
            cloud.offering("vmmigrations", "create").unwrap().kind,
            "VmMigration"
        );
        assert_eq!(
            cloud.path("vmmigrations", None).unwrap(),
            "/apis/meister.io/v1/vmmigrations"
        );

        // And the ones it has not, with the sentence that gets somebody
        // somewhere rather than a status code.
        let e = cloud
            .offering("vmmigrations", "list")
            .unwrap_err()
            .to_string();
        assert!(e.contains("cannot list"), "{e}");
        assert!(e.contains("live at the cluster"), "{e}");

        // An absent verbs list preserves compatibility with older discovery documents.
        let old = discovery("cloud", r#"[{"name":"vms","kind":"Vm"}]"#);
        assert!(old.offering("vms", "delete").is_ok());

        // A resource that is not there at all is the sentence it always was.
        let e = cloud.offering("tenants", "list").unwrap_err().to_string();
        assert!(e.contains("has no \"tenants\""), "{e}");
    }
}
