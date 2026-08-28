// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! `meister cloud …` — drives the cloud-controller's end API. Same client and
//! same feel as the cluster tier one level down; only the nouns change
//! (clusters instead of nodes, and the catalogue, the directory and the
//! address space on top).
//!
//! The VM verbs are in [`crate::vm`], shared with the tier below: the two
//! serve the same object and only place it differently.

use anyhow::{Context, Result, anyhow};
use chrono::{DateTime, Utc};
use macros::generated;
use serde::Deserialize;
use serde_json::json;

use crate::client::Client;
use crate::config::Target;
use crate::output::{self, View, age, age_until, joined, mem, or_dash, readiness, size};
use crate::{
    CloudClusterCmd, CloudCmd, CloudCsrCmd, CloudFloatingIpCmd, CloudFloatingPoolCmd,
    CloudImageCmd, CloudRoutedSubnetCmd, CloudTenantCmd, CloudUserCmd, CloudVmCmd, GlobalArgs, vm,
};

const CLUSTERS: &str = "/apis/meister.io/v1/clusters";
const IMAGES: &str = "/apis/meister.io/v1/images";
const TENANTS: &str = "/apis/meister.io/v1/tenants";
const USERS: &str = "/apis/meister.io/v1/users";
pub(crate) const CSRS: &str = "/apis/meister.io/v1/certificatesigningrequests";
const FLOATING_POOLS: &str = "/apis/meister.io/v1/floatingpools";
const FLOATING_IPS: &str = "/apis/meister.io/v1/floatingips";
const ROUTED_SUBNETS: &str = "/apis/meister.io/v1/routedsubnets";

#[derive(Deserialize)]
struct Meta {
    name: String,
}

#[derive(Deserialize)]
struct Cluster {
    metadata: Meta,
    #[serde(default)]
    spec: ClusterSpec,
    #[serde(default)]
    status: ClusterStatus,
}

#[derive(Deserialize)]
struct ClusterSpec {
    #[serde(default = "yes")]
    schedulable: bool,
}

fn yes() -> bool {
    true
}

impl Default for ClusterSpec {
    fn default() -> Self {
        Self { schedulable: true }
    }
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct ClusterStatus {
    #[serde(default)]
    connected: bool,
    #[serde(default)]
    last_heartbeat: Option<DateTime<Utc>>,
    #[serde(default)]
    nodes_ready: u32,
    #[serde(default)]
    nodes_total: u32,
    #[serde(default)]
    capacity: Capacity,
    #[serde(default)]
    vms: u32,
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

#[derive(Deserialize)]
struct Image {
    metadata: Meta,
    spec: ImageSpec,
    #[serde(default)]
    status: ImageStatus,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ImageSpec {
    source: String,
    #[serde(default)]
    url: Option<String>,
    #[serde(default)]
    format: Option<String>,
    #[serde(default)]
    size_bytes: u64,
    #[serde(default)]
    tenant: Option<String>,
    #[serde(default)]
    public: bool,
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct ImageStatus {
    /// `availableOn` is deliberately not read: it has meant "not tracked"
    /// since v1 and the column over it was always empty, while `phase` says
    /// the thing an operator was hoping to read there.
    ///
    /// Pending / Ready / Failed. A path image is Ready the moment it is
    /// registered; a fetchable one waits for a node to say.
    #[serde(default)]
    phase: Option<String>,
}

/// Every verb of this tier that destroys something, and the whole list of it.
///
/// Naming them in one place rather than guarding inside each verb is the
/// point: for a long time only `vm destroy` asked, and the seven `rm`s beside
/// it — one of which cascades through everything a tenant owns — did not,
/// because nothing made that omission visible. A verb missing from this list
/// is now a hole somebody can see.
#[generated(model = ClaudeOpus, version = "5")]
fn destructive(cmd: &CloudCmd) -> Option<(&'static str, &str)> {
    match cmd {
        CloudCmd::Vm {
            cmd: CloudVmCmd::Destroy { name },
        } => Some(("vm", name)),
        CloudCmd::Image {
            cmd: CloudImageCmd::Rm { name },
        } => Some(("image", name)),
        CloudCmd::Tenant {
            cmd: CloudTenantCmd::Rm { name },
        } => Some(("tenant", name)),
        CloudCmd::User {
            cmd: CloudUserCmd::Rm { name },
        } => Some(("user", name)),
        CloudCmd::Csr {
            cmd: CloudCsrCmd::Rm { name },
        } => Some(("csr", name)),
        CloudCmd::Floatingpool {
            cmd: CloudFloatingPoolCmd::Rm { name },
        } => Some(("floatingpool", name)),
        CloudCmd::Floatingip {
            cmd: CloudFloatingIpCmd::Rm { address },
        } => Some(("floatingip", address)),
        CloudCmd::Routedsubnet {
            cmd: CloudRoutedSubnetCmd::Rm { name },
        } => Some(("routedsubnet", name)),
        _ => None,
    }
}

#[generated(model = ClaudeOpus, version = "5")]
pub async fn run(target: &Target, cmd: &CloudCmd, global: &GlobalArgs) -> Result<()> {
    if let Some((kind, name)) = destructive(cmd) {
        output::confirm_destructive(global, target, kind, name)?;
    }

    let client = Client::new(target)?;
    match cmd {
        CloudCmd::Clusters => clusters(&client, global).await,
        CloudCmd::Events => {
            vm::events(&client, global, vm::EVENTS, "nothing has happened recently").await
        }
        CloudCmd::Cluster { cmd } => run_cluster(&client, cmd, global).await,
        CloudCmd::Vm { cmd } => run_vm(&client, cmd, global).await,
        CloudCmd::Image { cmd } => run_image(&client, cmd, global).await,
        CloudCmd::Tenant { cmd } => run_tenant(&client, cmd, global).await,
        CloudCmd::User { cmd } => run_user(&client, cmd, global).await,
        CloudCmd::Csr { cmd } => run_csr(&client, cmd, global).await,
        CloudCmd::Floatingpool { cmd } => run_floating_pool(&client, cmd, global).await,
        CloudCmd::Floatingip { cmd } => run_floating_ip(&client, cmd, global).await,
        CloudCmd::Routedsubnet { cmd } => run_routed_subnet(&client, cmd, global).await,
    }
}

// --- the two shapes every noun in this tier is created and removed in -------

/// Create one object and answer with the name the caller already gave it.
#[generated(model = ClaudeOpus, version = "5")]
async fn create(
    client: &Client,
    global: &GlobalArgs,
    path: &str,
    object: serde_json::Value,
    name: &str,
) -> Result<()> {
    let body = client
        .post(path, Some(serde_json::to_vec(&object)?))
        .await?;
    output::emit_line(global, &body, name)
}

/// Remove one object and answer with its name. The confirmation happened in
/// [`destructive`], before any of this tier's verbs ran.
#[generated(model = ClaudeOpus, version = "5")]
async fn remove(client: &Client, global: &GlobalArgs, path: &str, name: &str) -> Result<()> {
    let body = client.delete(path).await?;
    output::emit_line(global, &body, name)
}

// --- clusters and vms -------------------------------------------------------

/// The inventory, not the live sessions: a cluster that is down stays listed
/// as not ready, with the capacity it last had.
#[generated(model = ClaudeOpus, version = "5")]
async fn clusters(client: &Client, global: &GlobalArgs) -> Result<()> {
    let body = client.get(CLUSTERS).await?;
    let now = Utc::now();
    output::emit(global, &body, |body| {
        output::table_of(
            body,
            "parsing cluster list",
            &[
                "cluster",
                "ready",
                "heartbeat",
                "nodes",
                "vcpus",
                "mem",
                "capabilities",
                "vms",
            ],
            "no clusters known to this cloud",
            |c: Cluster| cluster_row(c, now),
        )
    })
}

#[generated(model = ClaudeOpus, version = "5")]
fn cluster_row(c: Cluster, now: DateTime<Utc>) -> Vec<String> {
    let cap = c.status.capacity;
    vec![
        c.metadata.name,
        readiness(c.status.connected, c.spec.schedulable).into(),
        age(c.status.last_heartbeat, now),
        format!("{}/{}", c.status.nodes_ready, c.status.nodes_total),
        cap.vcpus.to_string(),
        mem(cap.mem_mib),
        joined(&cap.capabilities),
        c.status.vms.to_string(),
    ]
}

/// Cordon and uncordon at the cloud tier: the Node verbs one floor up, over
/// the Cluster object, through the same read-edit-write compare-and-swap.
#[generated(model = ClaudeOpus, version = "5")]
async fn run_cluster(client: &Client, cmd: &CloudClusterCmd, global: &GlobalArgs) -> Result<()> {
    if let CloudClusterCmd::Label { name, pairs, rm } = cmd {
        let body = client
            .patch_spec(
                &format!("{CLUSTERS}/{name}"),
                "parsing the cluster object",
                &format!("cluster {name}"),
                &|spec| crate::client::edit_labels(spec, pairs, rm),
            )
            .await?;
        return output::emit_line(global, &body, "labelled");
    }
    let (name, schedulable) = match cmd {
        CloudClusterCmd::Cordon { name } => (name, false),
        CloudClusterCmd::Uncordon { name } => (name, true),
        // Handled above; the binding below is about schedulability only.
        CloudClusterCmd::Label { .. } => unreachable!("returned above"),
    };
    let body = client
        .patch_spec(
            &format!("{CLUSTERS}/{name}"),
            "parsing the cluster object",
            &format!("cluster {name}"),
            &|spec| {
                spec.insert("schedulable".to_string(), json!(schedulable));
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
        "note: draining stops new placements only; the vms already on this cluster keep running",
    )
}

/// The same eight verbs as one tier down, over the same object, through the
/// same functions. What differs is only how far the intent has to travel
/// before something acts on it — and that this tier has a directory, so a VM
/// created here can be created for somebody.
#[generated(model = ClaudeOpus, version = "5")]
async fn run_vm(client: &Client, cmd: &CloudVmCmd, global: &GlobalArgs) -> Result<()> {
    match cmd {
        CloudVmCmd::Create {
            name,
            spec,
            run_strategy,
            tenant,
        } => {
            vm::create(
                client,
                global,
                name,
                spec,
                run_strategy.as_deref(),
                tenant.as_deref(),
            )
            .await
        }
        CloudVmCmd::Ls => {
            vm::list(
                client,
                global,
                vm::Placement::Cluster,
                "no vms in this cloud",
            )
            .await
        }
        CloudVmCmd::Logs { name, lines } => vm::logs(client, global, vm::VMS, name, *lines).await,
        CloudVmCmd::Events { name } => {
            vm::events(
                client,
                global,
                &format!("{}/{name}/events", vm::VMS),
                "nothing has happened to this vm recently",
            )
            .await
        }
        CloudVmCmd::Inspect { name } => vm::inspect(client, name).await,
        CloudVmCmd::Destroy { name } => vm::destroy(client, global, name).await,
        CloudVmCmd::Start { name } => vm::run_strategy(client, name, "Running", global).await,
        CloudVmCmd::Stop { name } => vm::run_strategy(client, name, "Stopped", global).await,
        CloudVmCmd::Pause { name } => vm::run_strategy(client, name, "Paused", global).await,
        CloudVmCmd::Resume { name } => vm::run_strategy(client, name, "Running", global).await,
    }
}

// --- the image catalogue ----------------------------------------------------

#[generated(model = ClaudeOpus, version = "5")]
async fn run_image(client: &Client, cmd: &CloudImageCmd, global: &GlobalArgs) -> Result<()> {
    match cmd {
        CloudImageCmd::Create {
            name,
            source,
            from_url,
            sha256,
            format,
            size,
            tenant,
            public,
        } => {
            // `source` is what a node looks the image up as, and for a
            // fetched one that is the catalogue name itself: the bytes land
            // under it. So one of the two has to be given and only one can
            // be, which clap already enforces — this turns it into the field
            // the server takes.
            let source = match (source, from_url) {
                (Some(path), _) => path.clone(),
                (None, Some(_)) => name.clone(),
                (None, None) => anyhow::bail!(
                    "say where the image is with --source <path>, or where to fetch it from \
                     with --from-url <url> --sha256 <hex>"
                ),
            };
            let mut object = json!({
                "apiVersion": "meister.io/v1",
                "kind": "Image",
                "metadata": { "name": name },
                "spec": {
                    "source": source,
                    "format": format,
                    "sizeBytes": size.unwrap_or(0),
                    "public": public,
                },
            });
            // Omitted rather than sent as null, for the reason `tenant` is:
            // an absent key and a key saying "nothing" are different
            // requests, and the second one would make every path image look
            // like a fetchable one whose url somebody forgot.
            if let Some(url) = from_url {
                object["spec"]["url"] = json!(url);
            }
            if let Some(sha256) = sha256 {
                object["spec"]["sha256"] = json!(sha256);
            }
            // Omitted rather than sent as null when nobody named one: the
            // server fills a member's own tenant in, and a key that is there
            // saying "nothing" is not the same request as one that is absent.
            if let Some(tenant) = tenant {
                object["spec"]["tenant"] = json!(tenant);
            }
            create(client, global, IMAGES, object, name).await
        }
        CloudImageCmd::Ls => {
            let body = client.get(IMAGES).await?;
            output::emit(global, &body, |body| {
                output::table_of(
                    body,
                    "parsing image list",
                    // `source` is last because it is the one cell here an
                    // operator can put a space in: it is a path they chose.
                    // Everything before it stays one token, so `awk` can cut
                    // this table up.
                    //
                    // `phase` takes the place `available-on` had. That column
                    // has meant "not tracked" since v1 and was always empty,
                    // while this says the thing somebody was hoping to read
                    // there. WHY a Failed image failed is deliberately not a
                    // column: it is a server sentence with spaces in it and
                    // the last column is spoken for. It comes out with
                    // `-o json`, and — where it is actually met — in the 422
                    // that refuses a vm naming an unusable image.
                    &[
                        "name", "tenant", "scope", "format", "size", "phase", "source",
                    ],
                    "no images in this catalogue",
                    image_row,
                )
            })
        }
        CloudImageCmd::Rm { name } => {
            remove(client, global, &format!("{IMAGES}/{name}"), name).await
        }
    }
}

/// Who owns it and who may read it are two facts, so they are two columns.
/// One column saying `tenant (public)` put a raw space in the middle of the
/// table and shifted every field behind it.
#[generated(model = ClaudeOpus, version = "5")]
fn image_row(img: Image) -> Vec<String> {
    vec![
        img.metadata.name,
        or_dash(img.spec.tenant),
        if img.spec.public { "public" } else { "private" }.to_string(),
        or_dash(img.spec.format),
        size(img.spec.size_bytes),
        or_dash(img.status.phase),
        // For a fetchable image the url is where the bytes come from and the
        // name is where they land; showing the url is what an operator wants
        // to check.
        img.spec.url.unwrap_or(img.spec.source),
    ]
}

// --- tenants, users, certificate requests -----------------------------------

#[derive(Deserialize)]
struct Tenant {
    metadata: Meta,
    #[serde(default)]
    spec: TenantSpec,
    #[serde(default)]
    status: TenantStatus,
}

#[derive(Deserialize, Default)]
struct TenantSpec {
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
struct TenantQuota {
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
struct TenantStatus {
    #[serde(default)]
    used: TenantUsage,
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct TenantUsage {
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
#[generated(model = ClaudeOpus, version = "5")]
fn used_of(used: u64, limit: Option<u64>) -> String {
    match limit {
        Some(limit) => format!("{used}/{limit}"),
        None => used.to_string(),
    }
}

#[derive(Deserialize)]
struct User {
    metadata: Meta,
    spec: UserSpec,
    #[serde(default)]
    status: UserStatus,
}

#[derive(Deserialize)]
struct UserSpec {
    tenant: String,
    #[serde(default)]
    role: String,
    #[serde(default)]
    description: String,
}

#[derive(Deserialize, Default)]
struct UserStatus {
    #[serde(default)]
    certificates: Vec<IssuedCertificate>,
}

/// Only what the table shows. The fingerprint and the serial are on the
/// object and come out of `-o json`; a column 71 characters wide, repeated
/// per certificate, is not a table.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct IssuedCertificate {
    not_after: DateTime<Utc>,
}

#[derive(Deserialize)]
struct Csr {
    metadata: Meta,
    spec: CsrSpec,
    #[serde(default)]
    status: CsrStatus,
}

#[derive(Deserialize)]
struct CsrSpec {
    username: String,
}

#[derive(Deserialize, Default)]
struct CsrStatus {
    #[serde(default)]
    conditions: Vec<CsrCondition>,
    #[serde(default)]
    certificate: Option<String>,
}

#[derive(Deserialize)]
struct CsrCondition {
    #[serde(rename = "type")]
    kind: String,
    #[serde(default)]
    by: String,
}

/// The server decides this too, and the two have to agree — the table is
/// worthless if it says Pending about a request that has a certificate on it.
/// Same precedence as `CsrStatus::phase` in controller-api: a denial outranks
/// an approval that produced nothing, a certificate outranks its approval.
#[generated(model = ClaudeOpus, version = "5")]
fn csr_phase(status: &CsrStatus) -> &'static str {
    let has = |k: &str| status.conditions.iter().any(|c| c.kind == k);
    if has("Denied") {
        "Denied"
    } else if has("Failed") {
        "Failed"
    } else if status.certificate.is_some() {
        "Issued"
    } else if has("Approved") {
        "Approved"
    } else {
        "Pending"
    }
}

#[generated(model = ClaudeOpus, version = "5")]
async fn run_tenant(client: &Client, cmd: &CloudTenantCmd, global: &GlobalArgs) -> Result<()> {
    match cmd {
        CloudTenantCmd::Create { name, description } => {
            let object = json!({
                "apiVersion": "meister.io/v1",
                "kind": "Tenant",
                "metadata": { "name": name },
                "spec": { "description": description.clone().unwrap_or_default() },
            });
            create(client, global, TENANTS, object, name).await
        }
        CloudTenantCmd::Ls => {
            let body = client.get(TENANTS).await?;
            output::emit(global, &body, |body| {
                output::table_of(
                    body,
                    "parsing tenant list",
                    &["tenant", "vni", "vms", "vcpus", "mem", "description"],
                    "no tenants",
                    |t: Tenant| {
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
                    },
                )
            })
        }
        CloudTenantCmd::Quota {
            name,
            max_vms,
            max_vcpus,
            max_mem_mib,
            unlimited,
        } => {
            if *unlimited && max_vms.is_none() && max_vcpus.is_none() && max_mem_mib.is_none() {
                // nothing to do beyond clearing, handled below
            } else if !*unlimited
                && max_vms.is_none()
                && max_vcpus.is_none()
                && max_mem_mib.is_none()
            {
                anyhow::bail!(
                    "name at least one of --max-vms, --max-vcpus, --max-mem-mib, or --unlimited"
                );
            }
            let body = client
                .patch_spec(
                    &format!("{TENANTS}/{name}"),
                    "parsing the tenant object",
                    &format!("tenant {name}"),
                    &|spec| {
                        // Read-edit-write over the WHOLE quota object, so a
                        // limit nobody named keeps the value it had. The
                        // alternative — sending only the named ones — would
                        // silently drop the others every time.
                        let mut quota = if *unlimited {
                            json!({})
                        } else {
                            spec.get("quota").cloned().unwrap_or_else(|| json!({}))
                        };
                        for (key, value) in [
                            ("maxVms", max_vms.map(|v| json!(v))),
                            ("maxVcpus", max_vcpus.map(|v| json!(v))),
                            ("maxMemMib", max_mem_mib.map(|v| json!(v))),
                        ] {
                            if let Some(value) = value {
                                quota[key] = value;
                            }
                        }
                        spec.insert("quota".to_string(), quota);
                        Ok(())
                    },
                )
                .await?;
            output::emit_note(
                global,
                &body,
                name,
                "note: the quota counts every phase, pending vms included, and a vm that is \
                 terminating still counts until its object is gone",
            )
        }
        CloudTenantCmd::Rm { name } => {
            remove(client, global, &format!("{TENANTS}/{name}"), name).await
        }
    }
}

#[generated(model = ClaudeOpus, version = "5")]
async fn run_user(client: &Client, cmd: &CloudUserCmd, global: &GlobalArgs) -> Result<()> {
    match cmd {
        CloudUserCmd::Create {
            name,
            tenant,
            role,
            description,
        } => {
            let object = json!({
                "apiVersion": "meister.io/v1",
                "kind": "User",
                "metadata": { "name": name },
                "spec": {
                    "tenant": tenant,
                    "role": role,
                    "description": description.clone().unwrap_or_default(),
                },
            });
            create(client, global, USERS, object, name).await
        }
        CloudUserCmd::Ls => {
            let body = client.get(USERS).await?;
            let now = Utc::now();
            output::emit(global, &body, |body| {
                output::table_of(
                    body,
                    "parsing user list",
                    &[
                        "user",
                        "role",
                        "tenant",
                        "certs",
                        "next-expiry",
                        "description",
                    ],
                    "no users in this directory",
                    |u: User| user_row(u, now),
                )
            })
        }
        // A read-modify-write of one spec field, exactly like the runStrategy
        // verbs: there is no second API for changing a role, there is the
        // object.
        CloudUserCmd::SetRole { name, role } => {
            let body = client
                .patch_spec(
                    &format!("{USERS}/{name}"),
                    "parsing the user object",
                    &format!("user {name}"),
                    &|spec| {
                        spec.insert("role".to_string(), json!(role));
                        Ok(())
                    },
                )
                .await?;
            output::emit_note(
                global,
                &body,
                role,
                "note: certificates already issued still carry the old role at the cluster tier \
                 until they are re-issued (meister login)",
            )
        }
        CloudUserCmd::Rm { name } => remove(client, global, &format!("{USERS}/{name}"), name).await,
    }
}

#[generated(model = ClaudeOpus, version = "5")]
fn user_row(u: User, now: DateTime<Utc>) -> Vec<String> {
    // Live ones only: an expired fingerprint is history, not a credential
    // somebody holds.
    let live: Vec<&IssuedCertificate> = u
        .status
        .certificates
        .iter()
        .filter(|c| c.not_after > now)
        .collect();
    let expiry = or_dash(
        live.iter()
            .map(|c| c.not_after)
            .min()
            .map(|t| age_until(t, now)),
    );
    vec![
        u.metadata.name,
        u.spec.role,
        u.spec.tenant,
        live.len().to_string(),
        expiry,
        u.spec.description,
    ]
}

#[generated(model = ClaudeOpus, version = "5")]
async fn run_csr(client: &Client, cmd: &CloudCsrCmd, global: &GlobalArgs) -> Result<()> {
    match cmd {
        CloudCsrCmd::Ls => {
            let body = client.get(CSRS).await?;
            output::emit(global, &body, |body| {
                output::table_of(
                    body,
                    "parsing request list",
                    &["request", "user", "phase", "by"],
                    "no certificate requests",
                    csr_row,
                )
            })
        }
        CloudCsrCmd::Inspect { name } => {
            output::print_json(&client.get(&format!("{CSRS}/{name}")).await?);
            Ok(())
        }
        CloudCsrCmd::Approve { name } => {
            approval(
                client,
                global,
                name,
                json!({ "approved": true }),
                "Approved",
            )
            .await
        }
        CloudCsrCmd::Deny { name, reason } => {
            approval(
                client,
                global,
                name,
                json!({
                    "approved": false,
                    "reason": reason.clone().unwrap_or_else(|| "Denied".into()),
                }),
                "Denied",
            )
            .await
        }
        CloudCsrCmd::Rm { name } => remove(client, global, &format!("{CSRS}/{name}"), name).await,
    }
}

/// Saying yes or no is one subresource and one verb; which of the two it was
/// is the answer.
#[generated(model = ClaudeOpus, version = "5")]
async fn approval(
    client: &Client,
    global: &GlobalArgs,
    name: &str,
    decision: serde_json::Value,
    said: &str,
) -> Result<()> {
    let body = client
        .put(
            &format!("{CSRS}/{name}/approval"),
            Some(serde_json::to_vec(&decision)?),
        )
        .await?;
    output::emit_line(global, &body, said)
}

#[generated(model = ClaudeOpus, version = "5")]
fn csr_row(c: Csr) -> Vec<String> {
    let by = c
        .status
        .conditions
        .iter()
        .map(|cond| cond.by.clone())
        .find(|b| !b.is_empty())
        .unwrap_or_default();
    vec![
        c.metadata.name,
        c.spec.username,
        csr_phase(&c.status).to_string(),
        by,
    ]
}

// --- floating pools, reservations, routed subnets ---------------------------

#[derive(Deserialize)]
struct FloatingPool {
    metadata: Meta,
    #[serde(default)]
    spec: FloatingPoolSpec,
}

#[derive(Deserialize, Default)]
struct FloatingPoolSpec {
    #[serde(default)]
    cidrs: Vec<String>,
    #[serde(default)]
    public: bool,
    #[serde(default)]
    default: bool,
    #[serde(default)]
    quota: std::collections::BTreeMap<String, u32>,
    #[serde(default)]
    description: String,
}

/// No `metadata` here, and that is the object's own doing: the name IS the
/// address, so the spec already carries it and a second copy in this struct
/// would be a field nothing reads.
#[derive(Deserialize)]
struct FloatingIp {
    #[serde(default)]
    spec: FloatingIpSpec,
}

#[derive(Deserialize, Default)]
struct FloatingIpSpec {
    #[serde(default)]
    tenant: String,
    #[serde(default)]
    pool: String,
    #[serde(default)]
    address: String,
    #[serde(default)]
    vm: Option<String>,
}

#[derive(Deserialize)]
struct RoutedSubnet {
    metadata: Meta,
    #[serde(default)]
    spec: RoutedSubnetSpec,
}

#[derive(Deserialize, Default)]
struct RoutedSubnetSpec {
    #[serde(default)]
    tenant: String,
    #[serde(default)]
    cidr: String,
    #[serde(default)]
    description: String,
}

/// The quota column: what each tenant was granted here, `tenant=n` per entry.
///
/// One line per object and no raw spaces in a value, which is the house rule
/// — the map is what makes a public pool auditable at a glance, and a column
/// that wrapped would make `floatingpool ls | grep` useless.
#[generated(model = ClaudeOpus, version = "5")]
fn quota_column(quota: &std::collections::BTreeMap<String, u32>) -> String {
    if quota.is_empty() {
        return "-".to_string();
    }
    quota
        .iter()
        .map(|(t, n)| format!("{t}={n}"))
        .collect::<Vec<_>>()
        .join(",")
}

#[generated(model = ClaudeOpus, version = "5")]
async fn run_floating_pool(
    client: &Client,
    cmd: &CloudFloatingPoolCmd,
    global: &GlobalArgs,
) -> Result<()> {
    match cmd {
        CloudFloatingPoolCmd::Create {
            name,
            cidrs,
            public,
            default,
            description,
        } => {
            let object = json!({
                "apiVersion": "meister.io/v1",
                "kind": "FloatingPool",
                "metadata": { "name": name },
                "spec": {
                    "cidrs": cidrs,
                    "public": public,
                    "default": default,
                    "description": description.clone().unwrap_or_default(),
                },
            });
            create(client, global, FLOATING_POOLS, object, name).await
        }
        CloudFloatingPoolCmd::Ls => {
            let body = client.get(FLOATING_POOLS).await?;
            output::emit(global, &body, |body| {
                output::table_of(
                    body,
                    "parsing pool list",
                    &["pool", "cidrs", "scope", "default", "quota", "description"],
                    "no floating pools; an admin creates one with \
                     `meister cloud floatingpool create`",
                    |p: FloatingPool| {
                        vec![
                            p.metadata.name,
                            joined(&p.spec.cidrs),
                            if p.spec.public { "public" } else { "private" }.to_string(),
                            if p.spec.default { "yes" } else { "-" }.to_string(),
                            quota_column(&p.spec.quota),
                            p.spec.description,
                        ]
                    },
                )
            })
        }
        // A read-modify-write of one map entry, exactly like `user set-role`:
        // there is no second API for a quota, there is the object.
        CloudFloatingPoolCmd::Quota {
            pool,
            tenant,
            count,
        } => {
            let body = client
                .patch_spec(
                    &format!("{FLOATING_POOLS}/{pool}"),
                    "parsing the pool object",
                    &format!("floating pool {pool}"),
                    &|spec| {
                        spec.entry("quota")
                            .or_insert_with(|| json!({}))
                            .as_object_mut()
                            .ok_or_else(|| anyhow!("spec.quota is not an object"))?
                            .insert(tenant.clone(), json!(count));
                        Ok(())
                    },
                )
                .await?;
            output::emit_line(global, &body, &count.to_string())
        }
        CloudFloatingPoolCmd::Rm { name } => {
            remove(client, global, &format!("{FLOATING_POOLS}/{name}"), name).await
        }
    }
}

#[generated(model = ClaudeOpus, version = "5")]
async fn run_floating_ip(
    client: &Client,
    cmd: &CloudFloatingIpCmd,
    global: &GlobalArgs,
) -> Result<()> {
    match cmd {
        CloudFloatingIpCmd::Create {
            tenant,
            pool,
            address,
            vm,
        } => {
            let mut object = json!({
                "apiVersion": "meister.io/v1",
                "kind": "FloatingIp",
                "metadata": { "name": "" },
                "spec": {},
            });
            // Omitted rather than sent empty when nobody named one — the
            // server fills a member's own tenant in, picks the default pool
            // and scans for a free address, and a key that is there saying
            // "nothing" is not the same request as one that is absent.
            for (key, value) in [
                ("tenant", tenant.as_ref()),
                ("pool", pool.as_ref()),
                ("address", address.as_ref()),
                ("vm", vm.as_ref()),
            ] {
                if let Some(v) = value {
                    object["spec"][key] = json!(v);
                }
            }
            let body = client
                .post(FLOATING_IPS, Some(serde_json::to_vec(&object)?))
                .await?;
            output::emit(global, &body, |body| {
                // The address is the result and the name, so it is the one
                // token a success prints. Unix-still, and pipeable into the
                // assign that usually follows.
                let created: FloatingIp =
                    serde_json::from_slice(body).context("parsing the reservation")?;
                Ok(View::line(created.spec.address))
            })
        }
        CloudFloatingIpCmd::Ls => {
            let body = client.get(FLOATING_IPS).await?;
            output::emit(global, &body, |body| {
                output::table_of(
                    body,
                    "parsing reservation list",
                    &["address", "tenant", "pool", "vm"],
                    "no floating addresses reserved",
                    |ip: FloatingIp| {
                        vec![
                            ip.spec.address,
                            ip.spec.tenant,
                            ip.spec.pool,
                            or_dash(ip.spec.vm),
                        ]
                    },
                )
            })
        }
        // The object changes now; the VM's tap rules follow when it is next
        // recreated.
        CloudFloatingIpCmd::Assign {
            address,
            vm,
            release,
        } => {
            let body = client
                .patch_spec(
                    &format!("{FLOATING_IPS}/{address}"),
                    "parsing the reservation",
                    &format!("floating address {address}"),
                    &|spec| match (release, vm) {
                        (true, _) => {
                            spec.remove("vm");
                            Ok(())
                        }
                        (false, Some(vm)) => {
                            spec.insert("vm".to_string(), json!(vm));
                            Ok(())
                        }
                        (false, None) => {
                            anyhow::bail!("say which vm with --vm, or --release to take it off one")
                        }
                    },
                )
                .await?;
            output::emit_note(
                global,
                &body,
                &or_dash(vm.clone()),
                "note: the vm's tap rules follow when it is next recreated; stopping and \
                 starting it keeps the tap it has",
            )
        }
        CloudFloatingIpCmd::Rm { address } => {
            remove(
                client,
                global,
                &format!("{FLOATING_IPS}/{address}"),
                address,
            )
            .await
        }
    }
}

#[generated(model = ClaudeOpus, version = "5")]
async fn run_routed_subnet(
    client: &Client,
    cmd: &CloudRoutedSubnetCmd,
    global: &GlobalArgs,
) -> Result<()> {
    match cmd {
        CloudRoutedSubnetCmd::Create {
            name,
            tenant,
            cidr,
            prefix_len,
            description,
        } => {
            let mut object = json!({
                "apiVersion": "meister.io/v1",
                "kind": "RoutedSubnet",
                "metadata": { "name": name },
                "spec": {
                    "tenant": tenant,
                    "description": description.clone().unwrap_or_default(),
                },
            });
            if let Some(cidr) = cidr {
                object["spec"]["cidr"] = json!(cidr);
            }
            if let Some(prefix_len) = prefix_len {
                object["spec"]["prefixLen"] = json!(prefix_len);
            }
            let body = client
                .post(ROUTED_SUBNETS, Some(serde_json::to_vec(&object)?))
                .await?;
            output::emit(global, &body, |body| {
                // The cidr is the result — the server may have cut it — so
                // that is what a success prints, not the name the caller
                // already knows.
                let created: RoutedSubnet =
                    serde_json::from_slice(body).context("parsing the subnet")?;
                Ok(View::line(created.spec.cidr))
            })
        }
        CloudRoutedSubnetCmd::Ls => {
            let body = client.get(ROUTED_SUBNETS).await?;
            output::emit(global, &body, |body| {
                output::table_of(
                    body,
                    "parsing subnet list",
                    &["subnet", "tenant", "cidr", "description"],
                    "no routed subnets",
                    |s: RoutedSubnet| {
                        vec![
                            s.metadata.name,
                            s.spec.tenant,
                            s.spec.cidr,
                            s.spec.description,
                        ]
                    },
                )
            })
        }
        CloudRoutedSubnetCmd::Rm { name } => {
            remove(client, global, &format!("{ROUTED_SUBNETS}/{name}"), name).await
        }
    }
}

#[cfg(test)]
#[generated(model = ClaudeOpus, version = "5")]
mod tests {
    use super::*;

    /// The two phase functions — this one and `CsrStatus::phase` in
    /// controller-api — have to agree, or the table says Pending about a
    /// request that has a certificate on it.
    #[test]
    fn a_request_has_one_phase_and_the_precedence_matches_the_servers() {
        let cond = |kind: &str| CsrCondition {
            kind: kind.into(),
            by: "ops".into(),
        };
        let mut status = CsrStatus::default();
        assert_eq!(csr_phase(&status), "Pending");
        status.conditions.push(cond("Approved"));
        assert_eq!(csr_phase(&status), "Approved");
        status.certificate = Some("pem".into());
        assert_eq!(csr_phase(&status), "Issued");
        status.conditions.push(cond("Denied"));
        assert_eq!(csr_phase(&status), "Denied");
    }

    /// A cluster the cloud has only ever heard Hello from carries no capacity
    /// at all; the table must still render it.
    #[test]
    fn a_bare_cluster_object_parses() {
        let c: Cluster =
            serde_json::from_str(r#"{"metadata":{"name":"cluster-1"},"spec":{},"status":{}}"#)
                .unwrap();
        assert_eq!(c.metadata.name, "cluster-1");
        assert!(c.spec.schedulable);
        assert_eq!(readiness(c.status.connected, c.spec.schedulable), "no");

        let row = cluster_row(c, Utc::now());
        assert_eq!(row[1], "no");
        assert_eq!(row[3], "0/0");
    }

    /// Who owns an image and who may read it are two facts. They used to
    /// share one column as `tenant (public)`, and that raw space in a middle
    /// column moved every `awk` field behind it.
    #[test]
    fn an_images_owner_and_its_scope_are_two_space_free_columns() {
        let img: Image = serde_json::from_str(
            r#"{"metadata":{"name":"debian-13"},
                "spec":{"source":"/srv/images/debian 13.raw","tenant":"ops","public":true,
                        "format":"raw","sizeBytes":2147483648},
                "status":{}}"#,
        )
        .unwrap();
        let row = image_row(img);
        assert_eq!(row[1], "ops");
        assert_eq!(row[2], "public");
        assert_eq!(row[4], "2.0Gi");
        assert_eq!(
            row[5], "-",
            "no phase on an object written before they existed"
        );
        // The only cell an operator can put a space in is the last one.
        for cell in &row[..row.len() - 1] {
            assert!(!cell.contains(' '), "{cell:?} carries a raw space");
        }
        assert_eq!(row[row.len() - 1], "/srv/images/debian 13.raw");
    }

    /// A public image with no tenant still says both things.
    #[test]
    fn a_public_image_without_an_owner_says_so_in_both_columns() {
        let img: Image = serde_json::from_str(
            r#"{"metadata":{"name":"base"},"spec":{"source":"/srv/base.raw","public":true},
                "status":{}}"#,
        )
        .unwrap();
        let row = image_row(img);
        assert_eq!(row[1], "-");
        assert_eq!(row[2], "public");
    }

    /// An expired certificate is history, not a credential somebody holds.
    #[test]
    fn only_live_certificates_are_counted() {
        let now = Utc::now();
        let user: User = serde_json::from_str(&format!(
            r#"{{"metadata":{{"name":"silas"}},
                 "spec":{{"tenant":"ops","role":"admin","description":"the operator"}},
                 "status":{{"certificates":[{{"notAfter":"{}"}},{{"notAfter":"{}"}}]}}}}"#,
            (now - chrono::Duration::days(1)).to_rfc3339(),
            (now + chrono::Duration::hours(5)).to_rfc3339(),
        ))
        .unwrap();
        let row = user_row(user, now);
        assert_eq!(row[3], "1");
        assert_eq!(row[4], "5h");
    }

    /// A quota map is one cell and stays one token, so `floatingpool ls |
    /// grep` keeps working.
    #[test]
    fn a_quota_map_is_one_comma_joined_cell() {
        let quota = std::collections::BTreeMap::from([
            ("ops".to_string(), 4_u32),
            ("web".to_string(), 1_u32),
        ]);
        assert_eq!(quota_column(&quota), "ops=4,web=1");
        assert_eq!(quota_column(&Default::default()), "-");
    }
}
