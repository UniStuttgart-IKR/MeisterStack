// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Cloud-controller: the K8s-style END API of the whole stack. Owns the cloud
//! etcd prefix, serves the REST API, accepts cluster sessions (ClusterPlane
//! gRPC) and reconciles Vm objects onto clusters.
//!
//! Structurally this is the cluster-controller one tier up, deliberately so:
//! same config shape, same API shape, same session-plus-reconciler split, same
//! level-triggered reconcile. What differs is only what the objects mean —
//! a placement is a cluster instead of a node, and a status arrives already
//! aggregated. Design: docs/design/control-plane.md.

mod api;
mod reconcile;
mod session;

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use clap::Parser;
use controller_api::EtcdStore;
use macros::generated;
use tracing::{error, info, warn};

#[derive(Parser, Debug)]
#[command(name = "meister-cloud-controller")]
struct Args {
    /// TOML config; missing file = built-in defaults. Flags override it.
    #[arg(long, default_value = "/etc/meisterstack/cloud.toml")]
    config: std::path::PathBuf,
    /// REST API listen address (the end API of the stack)
    #[arg(long)]
    listen_api: Option<String>,
    /// Cluster session (gRPC) listen address
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
    /// Prometheus exposition address. Given bare it is 127.0.0.1:9090;
    /// absent, nothing listens. The endpoint is unauthenticated and its
    /// series name objects across every tenant, so off is the default.
    #[arg(long, num_args = 0..=1, default_missing_value = telemetry::metrics::DEFAULT_LISTEN)]
    metrics_listen: Option<String>,
}

/// The central cloud setup file — written by the NixOS module in the lab,
/// hand-edited elsewhere. Every field optional; the defaults are the lab
/// topology, flags win over the file.
#[generated(model = ClaudeOpus, version = "5")]
#[derive(Debug, Default, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct FileConfig {
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

    // --- tls and auth. Every one of these is a PEM path, never PEM. ---
    //
    // File-only, like `retry` one tier down: these are a deployment's shape
    // rather than a thing anybody flips per run, and the generator writes
    // them. Relative paths resolve against this file, so a config and its
    // pki/ directory travel as one unit.
    /// Both unset = plain http on both ports, exactly as today.
    tls_cert: Option<PathBuf>,
    tls_key: Option<PathBuf>,
    /// The CA client certificates must chain to. Set = mTLS is offered and
    /// the mTLS authenticator joins the chain.
    client_ca: Option<PathBuf>,
    /// The CA this controller signs certificate requests with. Usually the
    /// same file as client_ca — it is the same CA — but named separately
    /// because a deployment may verify against a bundle and sign with one.
    ca_cert: Option<PathBuf>,
    ca_key: Option<PathBuf>,
    /// Sign every request the moment it arrives. The lab switch.
    csr_auto_approve: Option<bool>,
    /// How long an issued client certificate lives.
    cert_ttl_days: Option<i64>,
    /// Where tenant VNI allocation starts. Every tenant gets the next number
    /// from a counter in the store; this is only its floor, and raising it
    /// moves the counter forward rather than doing nothing.
    vni_base: Option<u32>,
    /// The address space `routedsubnets` are cut out of when an admin does not
    /// name a CIDR outright, e.g. `["10.7.0.0/16"]`. Absent = every subnet has
    /// to be named, which is the honest default: this control plane does not
    /// know which prefixes an operator was actually given.
    routed_pools: Option<Vec<String>>,
    /// Which placement strategy binds a VM to a cluster: "first-fit"
    /// (default). See controller_api::scheduler.
    scheduler: Option<controller_api::SchedulerConfig>,
    #[serde(default)]
    auth: controller_api::rest::AuthConfig,
}

#[generated(model = ClaudeOpus, version = "5")]
struct Config {
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
    /// The directory the config file was read from; PEM paths in it are
    /// relative to that, so a bundle stays a bundle when it moves.
    config_dir: Option<PathBuf>,
    tls_cert: Option<PathBuf>,
    tls_key: Option<PathBuf>,
    client_ca: Option<PathBuf>,
    ca_cert: Option<PathBuf>,
    ca_key: Option<PathBuf>,
    csr_auto_approve: bool,
    cert_ttl_days: i64,
    vni_base: u32,
    routed_pools: Vec<String>,
    /// The resolved placement strategy (config `scheduler`).
    scheduler: Arc<dyn controller_api::Scheduler>,
    auth: controller_api::rest::AuthConfig,
}

/// Ninety days, and the reason to have a default at all: an operator who does
/// not think about certificate lifetime should get one that expires rather
/// than one that does not.
const DEFAULT_CERT_TTL_DAYS: i64 = 90;

#[generated(model = ClaudeOpus, version = "5")]
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
    Ok(Config {
        listen_api: pick(&args.listen_api, file.listen_api, "0.0.0.0:3000"),
        listen_session: pick(&args.listen_session, file.listen_session, "0.0.0.0:50050"),
        etcd_endpoints: pick(
            &args.etcd_endpoints,
            file.etcd_endpoints,
            "http://127.0.0.1:2379",
        ),
        etcd_prefix: pick(&args.etcd_prefix, file.etcd_prefix, "/cloud"),
        otlp_endpoint: args.otlp_endpoint.clone().or(file.otlp_endpoint),
        metrics_listen: args.metrics_listen.clone().or(file.metrics_listen),
        config_dir: args.config.parent().map(std::path::Path::to_path_buf),
        tls_cert: file.tls_cert,
        tls_key: file.tls_key,
        client_ca: file.client_ca,
        ca_cert: file.ca_cert,
        ca_key: file.ca_key,
        csr_auto_approve: file.csr_auto_approve.unwrap_or(false),
        cert_ttl_days: file.cert_ttl_days.unwrap_or(DEFAULT_CERT_TTL_DAYS),
        vni_base: file
            .vni_base
            .unwrap_or(controller_api::vni::DEFAULT_VNI_BASE),
        routed_pools: file.routed_pools.unwrap_or_default(),
        scheduler: controller_api::SchedulerConfig::into_scheduler(file.scheduler)?,
        auth: file.auth,
    })
}

/// The CA, if this controller has one.
///
/// Without it the certificatesigningrequests resource still exists and still
/// records requests; approving one answers 501. A control plane that accepted
/// requests it could never fulfil would be worse than one that says so.
#[generated(model = ClaudeOpus, version = "5")]
fn signing(cfg: &Config) -> anyhow::Result<Option<Arc<api::Signing>>> {
    let base = cfg.config_dir.as_deref();
    match (&cfg.ca_cert, &cfg.ca_key) {
        (None, None) => {
            info!("no ca configured, certificate requests are recorded but not signed");
            Ok(None)
        }
        (Some(cert), Some(key)) => {
            let ca = pki::Ca::load(
                &pki::pem::resolve(base, cert),
                &pki::pem::resolve(base, key),
            )?;
            if cfg.csr_auto_approve {
                warn!(
                    "csr_auto_approve is on: every certificate request that reaches this API \
                     is signed on arrival"
                );
            }
            info!(
                ttl_days = cfg.cert_ttl_days,
                auto_approve = cfg.csr_auto_approve,
                "ca loaded"
            );
            Ok(Some(Arc::new(api::Signing {
                ca,
                auto_approve: cfg.csr_auto_approve,
                ttl_days: cfg.cert_ttl_days,
            })))
        }
        _ => anyhow::bail!("ca_cert and ca_key go together; set both or neither"),
    }
}

#[generated(model = ClaudeOpus, version = "5")]
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let cfg = resolve_config(&args)?;
    telemetry::init(telemetry::Setup {
        service_name: "meister-cloud-controller",
        default_filter: "info",
        span_close_events: false,
        otlp_endpoint: &cfg.otlp_endpoint,
    })?;
    info!("cloud-controller starting");
    // Before the store, the sessions and the API, so that a misspelled
    // address fails at start-up rather than at the first scrape that never
    // arrives. Its own listener: /metrics is unauthenticated, and the series
    // behind it name clusters and objects across every tenant.
    telemetry::metrics::serve(cfg.metrics_listen.as_deref()).await?;

    // Before anything builds a TLS config; tonic asks for the process default
    // and panics without one, and the first gRPC handshake is a bad place to
    // find that out.
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
    let signing = signing(&cfg)?;

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
    info!(endpoint = %cfg.listen_session, "cluster session server listening");

    {
        let store = store.clone();
        let registry = registry.clone();
        let scheduler = cfg.scheduler.clone();
        tokio::spawn(async move {
            reconcile::run(store, registry, scheduler).await;
        });
    }

    let listener = tokio::net::TcpListener::bind(&cfg.listen_api)
        .await
        .with_context(|| format!("binding {}", cfg.listen_api))?;
    info!(endpoint = %cfg.listen_api, tls = api_tls.is_some(), links = chain.len(),
          "rest api listening");
    // The cloud IS the user directory, so its guard resolves roles from the
    // store rather than from the certificate — a demotion takes effect on the
    // next request here, which is not true one tier down.
    let router = controller_api::rest::guard(
        api::router(
            store.clone(),
            signing,
            cfg.vni_base,
            cfg.routed_pools.clone(),
        ),
        controller_api::rest::AuthState {
            chain,
            directory: Some(store),
        },
    );
    controller_api::rest::serve(listener, router, api_tls).await
}
#[cfg(test)]
#[generated(model = ClaudeOpus, version = "5")]
mod tests {
    use super::*;

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
            .join("../../config/examples/cloud.toml");
        let raw = std::fs::read_to_string(&path).expect("the example is where it says");
        let live: FileConfig =
            toml::from_str(&raw).expect("config/examples/cloud.toml parses as written");
        assert_eq!(live.listen_api.as_deref(), Some("0.0.0.0:3000"));
        assert!(live.otlp_endpoint.is_none(), "no exporter as written");

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
        assert!(full.otlp_endpoint.is_some());
        // The M5.1 key. Floating POOLS deliberately have none — they are
        // objects, created with a verb, and the example says so in prose.
        assert_eq!(
            full.routed_pools.as_deref(),
            Some(&["10.7.0.0/16".to_string()][..])
        );
    }
}
