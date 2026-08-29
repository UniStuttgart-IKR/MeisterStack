// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Cluster-controller: the K8s-style sub-API of one cluster. Owns the
//! cluster etcd prefix, serves the REST API, accepts agent sessions
//! (ControlPlane gRPC) and reconciles Vm objects onto nodes.
//! Design: docs/design/control-plane.md.

mod api;
mod cloud;
mod logs;
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
    listen_session: Option<String>,
    etcd_endpoints: Option<String>,
    etcd_prefix: Option<String>,
    /// OTLP collector for span export. Absent = fmt only.
    otlp_endpoint: Option<String>,
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
    #[serde(default)]
    auth: controller_api::rest::AuthConfig,
}

struct Config {
    cluster_name: String,
    listen_api: String,
    listen_session: String,
    etcd_endpoints: String,
    etcd_prefix: String,
    /// Where spans go, if anywhere. Resolved like every other key: flag over
    /// file, and absent means the fmt subscriber alone.
    otlp_endpoint: Option<String>,
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
    /// The directory the config was read from; PEM paths in it are relative
    /// to that, so a config and its pki/ directory travel as one unit.
    config_dir: Option<std::path::PathBuf>,
    tls_cert: Option<std::path::PathBuf>,
    tls_key: Option<std::path::PathBuf>,
    client_ca: Option<std::path::PathBuf>,
    cloud_ca: Option<std::path::PathBuf>,
    cloud_cert: Option<std::path::PathBuf>,
    cloud_key: Option<std::path::PathBuf>,
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
        listen_api: pick(&args.listen_api, file.listen_api, "0.0.0.0:3001"),
        listen_session: pick(&args.listen_session, file.listen_session, "0.0.0.0:50051"),
        etcd_endpoints: pick(
            &args.etcd_endpoints,
            file.etcd_endpoints,
            "http://127.0.0.1:2379",
        ),
        etcd_prefix: pick(&args.etcd_prefix, file.etcd_prefix, "/cluster"),
        otlp_endpoint: args.otlp_endpoint.clone().or(file.otlp_endpoint),
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
        config_dir: args.config.parent().map(std::path::Path::to_path_buf),
        tls_cert: file.tls_cert,
        tls_key: file.tls_key,
        client_ca: file.client_ca,
        cloud_ca: file.cloud_ca,
        cloud_cert: file.cloud_cert,
        cloud_key: file.cloud_key,
        auth: file.auth,
    })
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
    let chain = Arc::new(controller_api::rest::build_chain(
        &cfg.auth,
        cfg.client_ca.as_deref(),
        base,
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
        ))
        .serve(session_addr);
    tokio::spawn(async move {
        if let Err(e) = grpc.await {
            error!(error = format!("{e:#}"), "session server stopped");
        }
    });
    info!(endpoint = %cfg.listen_session, "agent session server listening");

    {
        let store = store.clone();
        let registry = registry.clone();
        let requeue = cfg.requeue.clone();
        let scheduler = cfg.scheduler.clone();
        let overcommit = cfg.admission;
        tokio::spawn(async move {
            reconcile::run(store, registry, scheduler, requeue, overcommit).await;
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
        tokio::spawn(async move { cloud::run(store, registry, addrs, cluster_name, tls).await });
    }

    let listener = tokio::net::TcpListener::bind(&cfg.listen_api)
        .await
        .with_context(|| format!("binding {}", cfg.listen_api))?;
    info!(endpoint = %cfg.listen_api, tls = api_tls.is_some(), links = chain.len(),
          "rest api listening");
    // No directory at this tier — the users live at the cloud, once — so the
    // role comes off the certificate. See `AuthState::directory`.
    let router = controller_api::rest::guard(
        api::router(store, registry),
        controller_api::rest::AuthState {
            chain,
            directory: None,
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
    }
}
