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
#[derive(Debug, Default, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct FileConfig {
    /// What this cloud is called. The three replicas of one cloud SHARE it —
    /// it is the CLOUD's name and not a replica's — and it is the name in
    /// their `system:cloud:<name>` certificate, so it has to be stable across
    /// restarts and identical on all three.
    ///
    /// Default `"cloud"`, which is what a single-replica lab has always been
    /// in everything but name. Raising a second replica is where it starts to
    /// matter, and then the generator writes it.
    cloud_name: Option<String>,
    listen_api: Option<String>,
    /// Where OTHER cloud replicas should reach this one's REST API.
    ///
    /// The same key the cluster tier has, for the same reason: a cluster
    /// dials ONE replica, and a console read landing anywhere else has to be
    /// forwarded there. Absent with a wildcard `listen_api` publishes
    /// nothing rather than an address pointing at the asker's own loopback.
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
    /// This replica's own client identity — `CN=system:cloud:<cloud_name>`,
    /// `O=system:clouds`, from `tools/meister-ca --cloud <name>`.
    ///
    /// What it is FOR: asking a sibling replica for a console or a log. The
    /// serving pair cannot do it — its CN is a hostname, and the sibling's
    /// permission table admits a NAME — which is exactly the decision the
    /// image report left open ("welche Identitaet zeigt eine Cloud-Replica
    /// ihrer Schwester?"). Absent = the forward goes in plain http, which is
    /// what a lab runs, or fails with a sentence naming these keys when the
    /// sibling is https.
    identity_cert: Option<PathBuf>,
    identity_key: Option<PathBuf>,
    /// The key a `Secret`'s values are sealed with — 32 bytes, mode 0600,
    /// `/opt/meisterstack/pki/secrets.key` in the lab. The SAME file on both
    /// controller tiers: this one seals, and the cluster opens, because the
    /// cluster is what hands a node its cloud-init.
    ///
    /// Absent = `POST /secrets` answers 501. Not a degraded mode and not a
    /// warning: a secret stored in the clear would be `user_data` with a new
    /// name, so there is no path here that writes one.
    secrets_key: Option<PathBuf>,
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
    /// How much more than it has a machine may be asked to carry. Absent =
    /// vcpu 4.0, memory 1.0 — and memory may not be raised, because the
    /// failure mode on that axis is the OOM killer choosing which vm
    /// survives. See controller_api::scheduler::Overcommit.
    #[serde(default)]
    admission: controller_api::Overcommit,
    /// Which placement strategy binds a VM to a cluster: "first-fit"
    /// (default). See controller_api::scheduler.
    scheduler: Option<controller_api::SchedulerConfig>,
    #[serde(default)]
    auth: controller_api::rest::AuthConfig,
    /// The REST edge itself: today, which browser origins may be shown this
    /// API. See `controller_api::rest::ApiConfig` and the block in
    /// `config/examples/cloud.toml`.
    #[serde(default)]
    api: controller_api::rest::ApiConfig,
}

struct Config {
    /// This cloud's name, shared by its replicas. See `FileConfig`.
    cloud_name: String,
    listen_api: String,
    /// The resolved `advertise_api`, or the concrete `listen_api`, or None.
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
    /// The directory the config file was read from; PEM paths in it are
    /// relative to that, so a bundle stays a bundle when it moves.
    config_dir: Option<PathBuf>,
    tls_cert: Option<PathBuf>,
    tls_key: Option<PathBuf>,
    client_ca: Option<PathBuf>,
    identity_cert: Option<PathBuf>,
    identity_key: Option<PathBuf>,
    secrets_key: Option<PathBuf>,
    ca_cert: Option<PathBuf>,
    ca_key: Option<PathBuf>,
    csr_auto_approve: bool,
    cert_ttl_days: i64,
    vni_base: u32,
    routed_pools: Vec<String>,
    /// The overcommit factors admission applies (config `[admission]`).
    admission: controller_api::Overcommit,
    /// The resolved placement strategy (config `scheduler`).
    scheduler: Arc<dyn controller_api::Scheduler>,
    auth: controller_api::rest::AuthConfig,
    api: controller_api::rest::ApiConfig,
}

/// Ninety days, and the reason to have a default at all: an operator who does
/// not think about certificate lifetime should get one that expires rather
/// than one that does not.
const DEFAULT_CERT_TTL_DAYS: i64 = 90;

/// What a cloud is called when nobody said. One replica behind one address is
/// every deployment of this stack so far, and it never needed a name; the
/// name is what a SECOND replica needs, and that deployment writes one.
const DEFAULT_CLOUD_NAME: &str = "cloud";

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
    let listen_api = pick(&args.listen_api, file.listen_api, "0.0.0.0:3000");
    Ok(Config {
        cloud_name: file
            .cloud_name
            .map(|n| n.trim().to_string())
            .filter(|n| !n.is_empty())
            .unwrap_or_else(|| DEFAULT_CLOUD_NAME.to_string()),
        listen_api: listen_api.clone(),
        advertise_api: advertised(file.advertise_api.as_deref(), &listen_api),
        listen_session: pick(&args.listen_session, file.listen_session, "0.0.0.0:50050"),
        etcd_endpoints: pick(
            &args.etcd_endpoints,
            file.etcd_endpoints,
            "http://127.0.0.1:2379",
        ),
        etcd_prefix: pick(&args.etcd_prefix, file.etcd_prefix, "/cloud"),
        otlp_endpoint: args.otlp_endpoint.clone().or(file.otlp_endpoint),
        log_format: file.log_format,
        metrics_listen: args.metrics_listen.clone().or(file.metrics_listen),
        config_dir: args.config.parent().map(std::path::Path::to_path_buf),
        tls_cert: file.tls_cert,
        tls_key: file.tls_key,
        client_ca: file.client_ca,
        identity_cert: file.identity_cert,
        identity_key: file.identity_key,
        secrets_key: file.secrets_key,
        ca_cert: file.ca_cert,
        ca_key: file.ca_key,
        csr_auto_approve: file.csr_auto_approve.unwrap_or(false),
        cert_ttl_days: file.cert_ttl_days.unwrap_or(DEFAULT_CERT_TTL_DAYS),
        vni_base: file
            .vni_base
            .unwrap_or(controller_api::vni::DEFAULT_VNI_BASE),
        routed_pools: file.routed_pools.unwrap_or_default(),
        admission: {
            // Checked here and not at the first placement: an operator who
            // wrote a factor this control plane will not honour should learn
            // it from the process refusing to start, not from a vm that died
            // at three in the morning.
            file.admission.check()?;
            file.admission
        },
        scheduler: controller_api::SchedulerConfig::into_scheduler(file.scheduler)?,
        auth: file.auth,
        api: file.api,
    })
}

/// Where other replicas should reach this one, or `None`.
///
/// The cluster tier's `advertised`, word for word and for the same reason: a
/// wildcard bind names no address anybody else can use, and publishing one
/// would send a sibling to its own loopback. An explicit `advertise_api`
/// wins; a concrete `listen_api` is its own answer.
fn advertised(advertise_api: Option<&str>, listen_api: &str) -> Option<String> {
    if let Some(explicit) = advertise_api.map(str::trim).filter(|a| !a.is_empty()) {
        return Some(explicit.to_string());
    }
    let host = match listen_api.rsplit_once(':') {
        Some((host, _)) => host,
        None => listen_api,
    };
    let wildcard = matches!(
        host.trim_matches(|c| c == '[' || c == ']'),
        "0.0.0.0" | "::" | ""
    );
    if wildcard {
        return None;
    }
    Some(listen_api.to_string())
}

/// The CA, if this controller has one.
///
/// Without it the certificatesigningrequests resource still exists and still
/// records requests; approving one answers 501. A control plane that accepted
/// requests it could never fulfil would be worse than one that says so.
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

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let cfg = resolve_config(&args)?;
    telemetry::init(telemetry::Setup {
        service_name: "meister-cloud-controller",
        default_filter: "info",
        span_close_events: false,
        otlp_endpoint: &cfg.otlp_endpoint,
        log_format: cfg.log_format,
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
    // At start-up and not at the first POST: a key file that is missing, the
    // wrong length or unreadable is an operator's mistake, and this is the
    // cheap place to find it out. The line says WHERE, never what.
    let kek = match &cfg.secrets_key {
        Some(path) => {
            let path = pki::pem::resolve(base, path);
            let kek = Arc::new(controller_api::secrets::Kek::read(&path)?);
            info!(path = %kek.source().display(), "secrets key loaded");
            Some(kek)
        }
        None => {
            info!("no secrets_key configured; the secrets resource answers 501 on create");
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
    // Empty = a REST-only endpoint, which is a real thing to run in a test
    // and a useless thing to run in a lab: no peers can dial in. It is also
    // the one configuration in which a chain without mtls is not a lockout —
    // see `build_chain`.
    let serves_sessions = !cfg.listen_session.trim().is_empty();
    let chain = Arc::new(controller_api::rest::build_chain(
        &cfg.auth,
        cfg.client_ca.as_deref(),
        base,
        controller_api::rest::Tier::Cloud,
        serves_sessions,
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
            ))
            .serve(session_addr);
        tokio::spawn(async move {
            if let Err(e) = grpc.await {
                error!(error = format!("{e:#}"), "session server stopped");
            }
        });
        info!(endpoint = %cfg.listen_session, "cluster session server listening");
    } else {
        warn!("listen_session is empty; no cluster can dial this replica");
    }

    {
        let store = store.clone();
        let registry = registry.clone();
        let scheduler = cfg.scheduler.clone();
        let overcommit = cfg.admission;
        tokio::spawn(async move {
            reconcile::run(store, registry, scheduler, overcommit).await;
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
    // The console tickets this TIER mints and redeems. One value, given to
    // the router (which mints) and to the guard (which spends), and both
    // halves read the same etcd — so the replica a browser's WebSocket lands
    // on can spend what another replica minted. See `tickets`.
    let tickets = std::sync::Arc::new(controller_api::tickets::Tickets::new(store.clone()));
    let router = controller_api::rest::guard(
        api::router(
            store.clone(),
            registry.clone(),
            api::Settings {
                signing,
                kek: kek.clone(),
                // The credential a replica shows its sibling: this cloud's
                // own `system:cloud:<name>` identity, verified against the CA
                // it trusts its own clients with. One CA signs every tier in
                // this stack, and a replica asking its sibling is the cloud
                // asking itself. Absent = plain http, which is what a lab
                // runs.
                sibling: controller_api::forward::Sibling {
                    serves_tls: cfg.tls_cert.is_some(),
                    tls: match (&cfg.identity_cert, &cfg.identity_key) {
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
                vni_base: cfg.vni_base,
                routed_pools: cfg.routed_pools.clone(),
                advertise: cfg.advertise_api.clone(),
                overcommit: cfg.admission,
                scheduler: cfg.scheduler.clone(),
                tickets: tickets.clone(),
            },
            chain.clone(),
        ),
        controller_api::rest::AuthState {
            chain,
            directory: Some(store),
            provision_oidc_users: cfg
                .auth
                .oidc
                .as_ref()
                .and_then(|o| o.provision_unknown_users)
                .unwrap_or(false),
            // Since the console and log forwards: a replica of THIS cloud
            // may read here, which is how a `vm logs` reaches the replica
            // that holds the cluster's session. Everything else with a
            // machine identity still has nothing at this door.
            own_peer: Some(("cloud", cfg.cloud_name.clone())),
            tickets: Some(tickets),
        },
    );
    // Outside the guard, and it has to be: a browser's preflight carries no
    // credential by definition, so a chain that authenticated first would
    // answer 401 to the question the browser asks before it is willing to
    // send one. Cloud tier only — the cluster API speaks to no browser.
    if !cfg.api.cors_origins.is_empty() {
        info!(origins = ?cfg.api.cors_origins, "serving cors headers to these origins");
    }
    let router = controller_api::rest::cors(router, cfg.api.cors_origins.clone());
    controller_api::rest::serve(listener, router, api_tls).await
}
#[cfg(test)]
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
        // The envelope key. It is the one line in the example a fleet
        // really does uncomment, so a rename here has to fail in this test
        // rather than on twelve hosts at start-up.
        assert_eq!(full.log_format, telemetry::LogFormat::Json);
        // The M5.1 key. Floating POOLS deliberately have none — they are
        // objects, created with a verb, and the example says so in prose.
        assert_eq!(
            full.routed_pools.as_deref(),
            Some(&["10.7.0.0/16".to_string()][..])
        );
    }
}
