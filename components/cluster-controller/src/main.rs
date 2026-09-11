// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Cluster-controller: the K8s-style sub-API of one cluster. Owns the
//! cluster etcd prefix, serves the REST API, accepts agent sessions
//! (ControlPlane gRPC) and reconciles Vm objects onto nodes.
//! Design: docs/design/control-plane.md.

mod api;
mod cloud;
mod dispatch;
mod logs;
mod migration;
mod reconcile;
mod session;

use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use clap::Parser;
use controller_api::EtcdStore;
use tracing::{error, info, warn};

#[derive(Parser, Debug)]
#[command(name = "meister-cluster-controller")]
struct Args {
    /// TOML config; missing file = built-in defaults. Flags override it.
    #[arg(long, default_value = "/etc/meisterstack/cluster.toml")]
    config: std::path::PathBuf,
    /// REST API listen address (cluster #n defaults to 3000+n)
    #[arg(long)]
    listen_api: Option<String>,
    /// Agent session (gRPC) listen address
    #[arg(long)]
    listen_session: Option<String>,
    /// etcd endpoints, comma-separated
    #[arg(long)]
    etcd_endpoints: Option<String>,
    /// Key prefix — an all-in-one box shares one etcd across prefixes
    #[arg(long)]
    etcd_prefix: Option<String>,
    /// OTLP collector for span export, e.g. "http://127.0.0.1:4317". Unset =
    /// the fmt subscriber and nothing else, which is how this has always run.
    #[arg(long)]
    otlp_endpoint: Option<String>,
    /// The cloud-controller's session address. Unset = standalone.
    #[arg(long)]
    cloud_addr: Option<String>,
    /// The cloud-controller replicas to choose between, comma-separated. Wins
    /// over --cloud-addr; which one this cluster prefers is its own HRW order.
    #[arg(long)]
    cloud_addrs: Option<String>,
    /// Prometheus exposition address. Given bare it is 127.0.0.1:9090;
    /// absent, nothing listens. The endpoint is unauthenticated and its
    /// series name objects across every tenant, so off is the default.
    #[arg(long, num_args = 0..=1, default_missing_value = telemetry::metrics::DEFAULT_LISTEN)]
    metrics_listen: Option<String>,
}

/// The central cluster setup file — written by the NixOS module in the lab,
/// hand-edited elsewhere. Every field optional; defaults are the M1 lab
/// values, flags win over the file.
#[derive(Debug, Default, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct FileConfig {
    cluster_name: Option<String>,
    listen_api: Option<String>,
    /// Where OTHER replicas of this cluster can reach this one's REST API.
    ///
    /// `listen_api` is a BIND address and `0.0.0.0` is not one anybody can
    /// dial, so a replica that binds a wildcard cannot name itself and does
    /// not try: `Node.status.session_endpoint` stays empty and a console read
    /// that lands on the wrong replica answers 503 naming this key. Absent
    /// with a concrete `listen_api`, that address is used.
    ///
    /// Host and port, as `listen_api` is; the scheme follows the TLS
    /// configuration, because a replica dials its sibling the way its sibling
    /// serves.
    advertise_api: Option<String>,
    listen_session: Option<String>,
    etcd_endpoints: Option<String>,
    etcd_prefix: Option<String>,
    /// OTLP collector for span export. Absent = fmt only.
    otlp_endpoint: Option<String>,
    /// How a log line is written: `"human"` (the default) or `"json"`.
    ///
    /// File-only, like the tls paths below: which format a controller logs in
    /// is a property of the deployment that collects those logs, not of a
    /// run. `RUST_LOG` is the per-run knob and this changes nothing about it.
    #[serde(default)]
    log_format: telemetry::LogFormat,
    /// Where to serve the Prometheus exposition, e.g. "127.0.0.1:9090".
    /// Absent = nothing listens. Its own port and never the API router: that
    /// one is authenticated and tenant-scoped, and this one is neither.
    metrics_listen: Option<String>,
    cloud_addr: Option<String>,
    /// The cloud replicas to choose between (HA, leaderless). Order here is
    /// irrelevant — this cluster derives its own preference order over the
    /// list by rendezvous hashing (see `common::hrw`). This is also the key
    /// the ONE context writes, so it stays spelled exactly like this.
    #[serde(default)]
    cloud_addrs: Vec<String>,
    /// What to do about Failed VMs: "none", "crash-loop-backoff" (default),
    /// or a number of retries. See controller_api::requeue.
    retry: Option<controller_api::RequeueConfig>,
    /// How much more than it has a machine may be asked to carry. Absent =
    /// vcpu 4.0, memory 1.0 — and memory may not be raised, because the
    /// failure mode on that axis is the OOM killer choosing which vm
    /// survives. See controller_api::scheduler::Overcommit.
    #[serde(default)]
    admission: controller_api::Overcommit,
    /// Which placement strategy binds a VM to a node: "first-fit" (default).
    /// See controller_api::scheduler.
    scheduler: Option<controller_api::SchedulerConfig>,
    /// Which backend builds the tenant routers: "meister" (default) — the
    /// routers are built by the agents with the `linux-network` driver.
    #[serde(default)]
    network: Option<controller_api::NetworkConfig>,
    /// How long a live migration's TRANSFER may take before it is called
    /// failed, in seconds. Absent = 120.
    ///
    /// Configuration and not a constant, because how long a guest's memory
    /// takes to cross is a property of the estate and not of the code: half a
    /// gigabyte over a loopback is a third of a second, thirty-two over a
    /// busy 10G link is minutes. The other half of a migration — the
    /// destination getting ready — is local work on one machine and stays a
    /// constant. See `migration::Timeouts`.
    migration_transfer_secs: Option<u64>,

    // --- tls and auth. PEM paths, never PEM; relative to this file. ---
    /// Both unset = plain http and plain gRPC, exactly as today.
    tls_cert: Option<std::path::PathBuf>,
    tls_key: Option<std::path::PathBuf>,
    /// The CA that client certificates — an operator's, and the agents' —
    /// must chain to. Set = mTLS is offered on both ports and the mTLS
    /// authenticator joins the chain.
    client_ca: Option<std::path::PathBuf>,
    /// This cluster's own certificate for dialling the cloud, and the CA it
    /// verifies the cloud with. Separate from the pair above because the two
    /// directions are separate: a cluster can serve plain and dial TLS, or
    /// the other way round, and in the lab it will do both one at a time.
    cloud_ca: Option<std::path::PathBuf>,
    cloud_cert: Option<std::path::PathBuf>,
    cloud_key: Option<std::path::PathBuf>,
    /// The key a `Secret`'s values are opened with — 32 bytes, mode 0600,
    /// `/opt/meisterstack/pki/secrets.key` in the lab. BOTH controller tiers
    /// hold the same one: the cloud seals, and this tier opens, because this
    /// tier is what hands a node its cloud-init.
    ///
    /// Absent = this cluster stores mirrored secrets and cannot open them. A
    /// VM naming one stays Pending with a sentence saying so, which is the
    /// honest answer and not a Failed VM.
    secrets_key: Option<std::path::PathBuf>,
    #[serde(default)]
    auth: controller_api::rest::AuthConfig,
}

struct Config {
    cluster_name: String,
    listen_api: String,
    /// The resolved `advertise_api`, or the concrete `listen_api`, or None.
    /// See `advertised`.
    advertise_api: Option<String>,
    listen_session: String,
    etcd_endpoints: String,
    etcd_prefix: String,
    /// Where spans go, if anywhere. Resolved like every other key: flag over
    /// file, and absent means the fmt subscriber alone.
    otlp_endpoint: Option<String>,
    /// Which envelope a log line is written in. File-only; see `FileConfig`.
    log_format: telemetry::LogFormat,
    /// Where the Prometheus exposition listens, if anywhere. Resolved like
    /// every other key: flag over file, and absent means nothing listens.
    metrics_listen: Option<String>,
    /// Where the cloud tier is, if there is one — every replica of it. Empty
    /// is not a degraded mode: a cluster without a cloud is the standalone
    /// cluster of M1-M3.
    cloud_addrs: Vec<String>,
    /// The resolved Failed-VM policy (config `retry`).
    requeue: std::sync::Arc<dyn controller_api::RequeuePolicy>,
    /// The overcommit factors admission applies (config `[admission]`).
    admission: controller_api::Overcommit,
    /// The resolved placement strategy (config `scheduler`).
    scheduler: std::sync::Arc<dyn controller_api::Scheduler>,
    /// What builds a tenant router once it has been planned. See
    /// `controller_api::NetworkBackend`.
    network: std::sync::Arc<dyn controller_api::NetworkBackend>,
    /// How long each half of a live migration may take (config
    /// `migration_transfer_secs`).
    migration: migration::Timeouts,
    /// The directory the config was read from; PEM paths in it are relative
    /// to that, so a config and its pki/ directory travel as one unit.
    config_dir: Option<std::path::PathBuf>,
    tls_cert: Option<std::path::PathBuf>,
    tls_key: Option<std::path::PathBuf>,
    client_ca: Option<std::path::PathBuf>,
    cloud_ca: Option<std::path::PathBuf>,
    cloud_cert: Option<std::path::PathBuf>,
    cloud_key: Option<std::path::PathBuf>,
    /// The key a `Secret`'s values are opened with — 32 bytes, mode 0600,
    /// `/opt/meisterstack/pki/secrets.key` in the lab. BOTH controller tiers
    /// hold the same one: the cloud seals, and this tier opens, because this
    /// tier is what hands a node its cloud-init.
    ///
    /// Absent = this cluster stores mirrored secrets and cannot open them. A
    /// VM naming one stays Pending with a sentence saying so, which is the
    /// honest answer and not a Failed VM.
    secrets_key: Option<std::path::PathBuf>,
    auth: controller_api::rest::AuthConfig,
}

fn resolve_config(args: &Args) -> anyhow::Result<Config> {
    let file: FileConfig = match std::fs::read_to_string(&args.config) {
        Ok(raw) => {
            toml::from_str(&raw).with_context(|| format!("parsing {}", args.config.display()))?
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            info!(path = %args.config.display(), "no config file, using defaults");
            FileConfig::default()
        }
        Err(e) => return Err(e).context(format!("reading {}", args.config.display())),
    };
    let pick = |flag: &Option<String>, file: Option<String>, default: &str| {
        flag.clone().or(file).unwrap_or_else(|| default.to_string())
    };
    let cloud_addrs = cloud_endpoints(args, &file);
    Ok(Config {
        cluster_name: file.cluster_name.unwrap_or_else(|| "cluster-1".into()),
        advertise_api: advertised(
            file.advertise_api.as_deref(),
            &pick(&args.listen_api, file.listen_api.clone(), "0.0.0.0:3001"),
        ),
        listen_api: pick(&args.listen_api, file.listen_api, "0.0.0.0:3001"),
        listen_session: pick(&args.listen_session, file.listen_session, "0.0.0.0:50051"),
        etcd_endpoints: pick(
            &args.etcd_endpoints,
            file.etcd_endpoints,
            "http://127.0.0.1:2379",
        ),
        etcd_prefix: pick(&args.etcd_prefix, file.etcd_prefix, "/cluster"),
        otlp_endpoint: args.otlp_endpoint.clone().or(file.otlp_endpoint),
        log_format: file.log_format,
        metrics_listen: args.metrics_listen.clone().or(file.metrics_listen),
        cloud_addrs,
        requeue: controller_api::RequeueConfig::into_policy(file.retry)?,
        admission: {
            // Checked here and not at the first placement: an operator who
            // wrote a factor this control plane will not honour should learn
            // it from the process refusing to start, not from a vm that died
            // at three in the morning.
            file.admission.check()?;
            file.admission
        },
        scheduler: controller_api::SchedulerConfig::into_scheduler(file.scheduler)?,
        network: controller_api::NetworkConfig::into_backend(file.network)?,
        migration: migration::Timeouts::with_transfer_secs(file.migration_transfer_secs),
        config_dir: args.config.parent().map(std::path::Path::to_path_buf),
        tls_cert: file.tls_cert,
        tls_key: file.tls_key,
        client_ca: file.client_ca,
        cloud_ca: file.cloud_ca,
        cloud_cert: file.cloud_cert,
        cloud_key: file.cloud_key,
        secrets_key: file.secrets_key,
        auth: file.auth,
    })
}

/// The address other replicas of this cluster can reach this one at.
///
/// `advertise_api` if it is set, otherwise `listen_api` when that names a
/// concrete host, otherwise nothing at all. The last case is the one worth
/// spelling out: `0.0.0.0:3001` is a bind address and not a dialable one, and
/// a replica that wrote it into `Node.status.session_endpoint` would send its
/// siblings to their own loopback. Refusing to name itself is the honest
/// answer, and the 503 it leads to says which key to set.
fn advertised(advertise_api: Option<&str>, listen_api: &str) -> Option<String> {
    if let Some(explicit) = advertise_api.map(str::trim).filter(|a| !a.is_empty()) {
        return Some(explicit.to_string());
    }
    let host = match listen_api.rsplit_once(':') {
        Some((host, _)) => host,
        None => listen_api,
    };
    // The three ways of spelling "every interface", plus the empty host that
    // `:3001` is.
    let wildcard = matches!(
        host.trim_matches(|c| c == '[' || c == ']'),
        "0.0.0.0" | "::" | ""
    );
    if wildcard {
        return None;
    }
    Some(listen_api.to_string())
}

/// Every cloud replica this cluster may dial, most specific statement first.
/// A list that names the replicas is a newer and more complete statement than
/// a single address, so it wins outright rather than being merged into an
/// ambiguity — the same rule the agent applies to `controller_addrs`, and the
/// reason the lab's `cloud_addr` context stays valid as a one-element list.
fn cloud_endpoints(args: &Args, file: &FileConfig) -> Vec<String> {
    if let Some(flag) = &args.cloud_addrs {
        return flag
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
    }
    if !file.cloud_addrs.is_empty() {
        return file.cloud_addrs.clone();
    }
    args.cloud_addr
        .clone()
        .or_else(|| file.cloud_addr.clone())
        .into_iter()
        .collect()
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let cfg = resolve_config(&args)?;
    telemetry::init(telemetry::Setup {
        service_name: "meister-cluster-controller",
        default_filter: "info",
        span_close_events: false,
        otlp_endpoint: &cfg.otlp_endpoint,
        log_format: cfg.log_format,
    })?;
    info!(cluster = %cfg.cluster_name, "cluster-controller starting");
    // Before everything else, so that a misspelled address fails at start-up
    // rather than at the first scrape that never arrives. Its own listener:
    // /metrics is unauthenticated and the series behind it name every node.
    telemetry::metrics::serve(cfg.metrics_listen.as_deref()).await?;

    // Before anything builds a TLS config — tonic asks for the process
    // default and panics without one.
    pki::install_crypto_provider();
    let base = cfg.config_dir.as_deref();
    // At start-up and not at the first VM: a key file that is missing, the
    // wrong length or unreadable is an operator's mistake, and finding it out
    // here costs one restart where finding it out later costs somebody's VM
    // sitting Pending at three in the morning. The line says WHERE, never
    // what.
    let kek = match &cfg.secrets_key {
        Some(path) => {
            let path = pki::pem::resolve(base, path);
            let kek = Arc::new(controller_api::secrets::Kek::read(&path)?);
            info!(path = %kek.source().display(), "secrets key loaded");
            Some(kek)
        }
        None => {
            info!("no secrets_key configured; a vm naming a secret will stay pending");
            None
        }
    };
    let api_tls = controller_api::rest::server_tls(
        cfg.tls_cert.as_deref(),
        cfg.tls_key.as_deref(),
        cfg.client_ca.as_deref(),
        base,
    )?;
    let session_tls = controller_api::grpc::server_tls(
        cfg.tls_cert.as_deref(),
        cfg.tls_key.as_deref(),
        cfg.client_ca.as_deref(),
        base,
    )?;
    let cloud_tls = controller_api::grpc::client_tls(
        cfg.cloud_ca.as_deref(),
        match (&cfg.cloud_cert, &cfg.cloud_key) {
            (Some(c), Some(k)) => Some((c.as_path(), k.as_path())),
            (None, None) => None,
            _ => anyhow::bail!("cloud_cert and cloud_key go together; set both or neither"),
        },
        base,
    )?;
    // Empty = a REST-only endpoint, which is a real thing to run in a test
    // and a useless thing to run in a lab: no peers can dial in. It is also
    // the one configuration in which a chain without mtls is not a lockout —
    // see `build_chain`.
    let serves_sessions = !cfg.listen_session.trim().is_empty();
    let chain = Arc::new(controller_api::rest::build_chain(
        &cfg.auth,
        cfg.client_ca.as_deref(),
        base,
        controller_api::rest::Tier::Cluster,
        serves_sessions,
    )?);
    if chain.is_empty() {
        // Warn, as `csr_auto_approve` and the static bearer token are: a
        // deliberate configuration that leaves the API wide open should not
        // be the quietest of the three lines that say so.
        warn!("no authenticators configured, every request is anonymous");
    }

    let endpoints: Vec<String> = cfg
        .etcd_endpoints
        .split(',')
        .map(|s| s.trim().to_string())
        .collect();

    // etcd may still be coming up (shared boot on the control-plane VM).
    let store = loop {
        match EtcdStore::connect(&endpoints, &cfg.etcd_prefix).await {
            Ok(s) => break Arc::new(s),
            Err(e) => {
                warn!(
                    error = format!("{e:#}"),
                    retry_in_s = 2,
                    "etcd not reachable yet, retrying"
                );
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
        }
    };
    info!(endpoints = %cfg.etcd_endpoints, prefix = %cfg.etcd_prefix, "etcd store ready");

    let registry = Arc::new(session::SessionRegistry::new());

    // What a console read needs when it lands on the replica that does NOT
    // hold the node's session: this cluster's own name, which is what the
    // sibling's permission table lets read, and the credential to present.
    //
    // The cluster's own peer certificate — `system:cluster:<name>`, the one
    // it dials the cloud with — and not the serving pair, because it is that
    // NAME the sibling admits. Verified against the CA the sibling's serving
    // certificate chains to, which is `client_ca`: one CA signs both tiers in
    // this stack, and a replica asking its sibling is the cluster asking
    // itself. Absent = plain http, which is what a lab runs.
    let forward = Arc::new(logs::Forward {
        cluster: cfg.cluster_name.clone(),
        // Whether the SIBLING speaks TLS, answered by whether this replica
        // does: they run one configuration. The address it publishes carries
        // no scheme, so this is the only thing that can decide it.
        sibling: controller_api::forward::Sibling {
            serves_tls: cfg.tls_cert.is_some(),
            tls: match (&cfg.cloud_cert, &cfg.cloud_key) {
                (Some(cert), Some(key)) => Some(pki::tls::client_config(
                    cfg.client_ca
                        .as_ref()
                        .map(|ca| pki::pem::resolve(base, ca))
                        .as_deref(),
                    Some((
                        pki::pem::resolve(base, cert).as_path(),
                        pki::pem::resolve(base, key).as_path(),
                    )),
                )?),
                _ => None,
            },
        },
    });
    if let Some(advertise) = &cfg.advertise_api {
        info!(%advertise, "replicas of this cluster will be sent here for a node's console");
    } else {
        // Not an error: a single-replica cluster never needs it, and that is
        // every cluster in this stack so far. Worth one line, because the
        // 503 it leads to names this key and an operator reading the log
        // afterwards should find it here too.
        info!(
            listen_api = %cfg.listen_api,
            "no advertise_api and listen_api is a wildcard; a console read that lands on \
             another replica of this cluster will be refused"
        );
    }

    if serves_sessions {
        let session_addr = cfg.listen_session.parse().context("listen_session")?;
        let mut grpc_builder = tonic::transport::Server::builder();
        if let Some(tls) = session_tls {
            grpc_builder = grpc_builder.tls_config(tls).context("session tls")?;
        }
        let grpc = grpc_builder
            .add_service(session::service(
                registry.clone(),
                store.clone(),
                chain.clone(),
                cfg.advertise_api.clone(),
                kek.clone(),
            ))
            .serve(session_addr);
        tokio::spawn(async move {
            if let Err(e) = grpc.await {
                error!(error = format!("{e:#}"), "session server stopped");
            }
        });
        info!(endpoint = %cfg.listen_session, "agent session server listening");
    } else {
        warn!("listen_session is empty; no node can dial this replica");
    }

    {
        let store = store.clone();
        let registry = registry.clone();
        let requeue = cfg.requeue.clone();
        let scheduler = cfg.scheduler.clone();
        let network = cfg.network.clone();
        let overcommit = cfg.admission;
        let migration_timeouts = cfg.migration;
        // A live migration is about two machines and their sessions can hang
        // off two replicas, so its commands travel the way a console read
        // does. Everything else a pass sends is about one machine and is sent
        // through the registry directly, because the replica that holds the
        // object is the replica that holds the session. See `dispatch`.
        let dispatch = Arc::new(dispatch::Dispatch::new(
            registry.clone(),
            store.clone(),
            forward.clone(),
        ));
        tokio::spawn(async move {
            reconcile::run(
                store,
                registry,
                dispatch,
                scheduler,
                requeue,
                overcommit,
                kek,
                migration_timeouts,
                network,
            )
            .await;
        });
    }

    if cfg.cloud_addrs.is_empty() {
        info!("no cloud configured, running standalone");
    } else {
        info!(replicas = cfg.cloud_addrs.len(), "cloud tier configured");
        let store = store.clone();
        let cluster_name = cfg.cluster_name.clone();
        let addrs = cfg.cloud_addrs.clone();
        let tls = cloud_tls.clone();
        let registry = registry.clone();
        let forward = forward.clone();
        tokio::spawn(async move {
            cloud::run(store, registry, forward, addrs, cluster_name, tls).await
        });
    }

    let listener = tokio::net::TcpListener::bind(&cfg.listen_api)
        .await
        .with_context(|| format!("binding {}", cfg.listen_api))?;
    info!(endpoint = %cfg.listen_api, tls = api_tls.is_some(), links = chain.len(),
          "rest api listening");
    // No directory at this tier — the users live at the cloud, once — so a
    // user certificate authorizes nothing here and is refused with a sentence
    // that says so. Machines (the agents' sessions, a sibling replica) and
    // break glass are unaffected. See `AuthState::directory`.
    let router = controller_api::rest::guard(
        api::router(
            store,
            registry,
            forward,
            cfg.admission,
            cfg.scheduler.clone(),
            chain.clone(),
        ),
        controller_api::rest::AuthState {
            chain,
            directory: None,
            // No directory means nothing to provision into, and no oidc link
            // to provision for -- `build_chain` refuses one at this tier.
            provision_oidc_users: false,
            // The one machine identity this tier lets in at REST besides
            // break glass: a replica of THIS cluster, reading. See
            // `auth::permits`.
            own_peer: Some(("cluster", cfg.cluster_name.clone())),
            // No tickets at this tier: it mints none, so `?ticket=` is not a
            // credential here and a request carrying one is judged by the
            // chain like every other. See the console at the cloud.
            tickets: None,
        },
    );
    controller_api::rest::serve(listener, router, api_tls).await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(argv: &[&str]) -> Args {
        Args::parse_from(std::iter::once("meister-cluster-controller").chain(argv.iter().copied()))
    }

    fn file(toml: &str) -> FileConfig {
        toml::from_str(toml).expect("config parses")
    }

    /// A bind address is not an address anybody can dial, and a replica that
    /// wrote `0.0.0.0:3001` into a node's `session_endpoint` would send its
    /// siblings to their own loopback. Refusing to name itself is the honest
    /// answer; the 503 it leads to names the key.
    #[test]
    fn a_replica_names_itself_only_when_it_can() {
        // Explicit wins, always.
        assert_eq!(
            advertised(Some("10.0.0.2:3001"), "0.0.0.0:3001"),
            Some("10.0.0.2:3001".to_string())
        );
        assert_eq!(
            advertised(Some(" 10.0.0.2:3001 "), "127.0.0.1:3001"),
            Some("10.0.0.2:3001".to_string())
        );
        // A concrete listen address is one.
        for concrete in ["127.0.0.1:3001", "10.0.0.2:3001", "[2001:db8::1]:3001"] {
            assert_eq!(
                advertised(None, concrete),
                Some(concrete.to_string()),
                "{concrete}"
            );
        }
        // Every way of spelling "every interface" is none.
        for wildcard in ["0.0.0.0:3001", "[::]:3001", ":3001"] {
            assert_eq!(advertised(None, wildcard), None, "{wildcard}");
        }
        // And an empty key is not a key.
        assert_eq!(advertised(Some("  "), "0.0.0.0:3001"), None);
    }

    /// The lab's context still writes a single `cloud_addr` into some cluster
    /// configs; a list that names the replicas is the newer and more complete
    /// statement, so it wins rather than being merged into an ambiguity. Same
    /// rule as the agent's `controller_addrs` one tier down.
    #[test]
    fn the_replica_list_wins_over_the_single_address() {
        assert!(cloud_endpoints(&args(&[]), &file("")).is_empty());
        assert_eq!(
            cloud_endpoints(&args(&[]), &file(r#"cloud_addr = "http://one:1""#)),
            vec!["http://one:1".to_string()]
        );
        assert_eq!(
            cloud_endpoints(
                &args(&[]),
                &file(
                    r#"cloud_addr = "http://old:1"
                   cloud_addrs = ["http://a:1", "http://b:1"]"#
                )
            ),
            vec!["http://a:1".to_string(), "http://b:1".into()]
        );
        // and a flag beats the file, as every other flag here does
        assert_eq!(
            cloud_endpoints(
                &args(&["--cloud-addrs", "http://x:1, http://y:1"]),
                &file(r#"cloud_addrs = ["http://a:1"]"#)
            ),
            vec!["http://x:1".to_string(), "http://y:1".into()]
        );
    }

    /// The example, live and commented-out halves both. An example that does
    /// not parse is worse than no example — it is a file that looks like an
    /// answer — and uncommenting a line is the first thing anyone does with
    /// one, so a stale key there has to fail here rather than on a controller
    /// at start-up with `deny_unknown_fields` and no hint which line.
    ///
    /// The convention it enforces: prose is `# text`, a commented-out setting
    /// is `#key = …` with no space.
    #[test]
    fn the_example_config_parses_commented_keys_included() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../config/examples/cluster.toml");
        let raw = std::fs::read_to_string(&path).expect("the example is where it says");
        let live: FileConfig =
            toml::from_str(&raw).expect("config/examples/cluster.toml parses as written");
        assert_eq!(live.cluster_name.as_deref(), Some("cluster-1"));
        assert!(live.cloud_addrs.is_empty(), "standalone as written");

        let uncommented: String = raw
            .lines()
            .map(|l| match l.strip_prefix('#') {
                Some(rest) if !rest.starts_with(' ') && !rest.is_empty() => rest,
                _ if l.starts_with('#') => "",
                _ => l,
            })
            .collect::<Vec<_>>()
            .join("\n");
        let full: FileConfig =
            toml::from_str(&uncommented).expect("every commented key in the example is a real one");
        assert_eq!(full.cloud_addrs.len(), 2, "and a cloud when uncommented");
        assert!(full.retry.is_some());
        assert!(full.otlp_endpoint.is_some());
        // The envelope key. It is the one line in the example a fleet
        // really does uncomment, so a rename here has to fail in this test
        // rather than on twelve hosts at start-up.
        assert_eq!(full.log_format, telemetry::LogFormat::Json);
    }
}
