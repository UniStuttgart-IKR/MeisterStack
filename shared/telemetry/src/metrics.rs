// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Prometheus metrics with one registry per process.
//!
//! Recording is unconditional. Serving requires a configured listener separate
//! from the authenticated REST API: metrics expose infrastructure data across
//! tenants and have no API authorization layer.
//!
//! Labels must have bounded values. Fleet node, cluster and driver names are
//! allowed; VM IDs, addresses, socket paths and error text belong in logs.

use std::sync::OnceLock;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use prometheus::{
    Encoder, GaugeVec, HistogramOpts, HistogramVec, IntCounter, IntCounterVec, IntGauge,
    IntGaugeVec, Opts, Registry, TextEncoder, exponential_buckets,
};
use tracing::{info, warn};

/// Default metrics bind address when explicitly enabled without an
/// address. Loopback limits exposure of unauthenticated infrastructure data.
pub const DEFAULT_LISTEN: &str = "127.0.0.1:9090";

/// Every metric this stack publishes starts with this.
const PREFIX: &str = "meister_";

/// Which tier a series is about. Bounded by construction — there are three
/// components and there will be three.
pub const TIER_CLOUD: &str = "cloud";
pub const TIER_CLUSTER: &str = "cluster";
pub const TIER_AGENT: &str = "agent";

/// What a session is a session WITH, one word each. The cloud's peers are
/// clusters, the cluster's are nodes.
pub const PEER_CLUSTER: &str = "cluster";
pub const PEER_NODE: &str = "node";

/// The reconciler's own health: how long a pass takes, how often one fails,
/// and when the last one succeeded.
pub struct Reconcile {
    duration: HistogramVec,
    errors: IntCounterVec,
    last_success: GaugeVec,
}

impl Reconcile {
    /// One finished pass. `ok` decides which of the two counters moves: a
    /// pass that threw is not a pass that succeeded, and the gauge that stops
    /// moving is the one an alert is written against.
    pub fn pass(&self, tier: &str, kind: &str, seconds: f64, ok: bool) {
        self.duration
            .with_label_values(&[tier, kind])
            .observe(seconds);
        if ok {
            self.last_success
                .with_label_values(&[tier, kind])
                .set(unix_seconds());
        } else {
            self.errors.with_label_values(&[tier, kind]).inc();
        }
    }
}

/// Object and VM-phase gauges filled from existing reconcile inventories,
/// without extra store listings solely for metrics.
pub struct Objects {
    count: IntGaugeVec,
    vms: IntGaugeVec,
    stuck: IntGaugeVec,
}

impl Objects {
    pub fn set_count(&self, kind: &str, n: i64) {
        self.count.with_label_values(&[kind]).set(n);
    }

    /// Set the current overdue count for bounded kind/phase/reason labels.
    /// This is diagnostic only; deadlines do not promote or clean up resources.
    pub fn set_stuck(&self, kind: &str, phase: &str, reason: &str, n: i64) {
        self.stuck.with_label_values(&[kind, phase, reason]).set(n);
    }

    /// Clear overdue series before publishing the current pass, removing
    /// objects that recovered or disappeared from the inventory.
    pub fn reset_stuck(&self) {
        self.stuck.reset();
    }

    /// One phase's count. Callers set EVERY phase each pass, zero included,
    /// so that a phase nothing is in stays a flat line rather than a series
    /// that disappears out of a dashboard.
    pub fn set_vms(&self, phase: &str, n: i64) {
        self.vms.with_label_values(&[phase]).set(n);
    }
}

/// Placement counters and pending gauges with bounded reason categories.
pub struct Scheduling {
    placements: IntCounterVec,
    conflicts: IntCounterVec,
    pending: IntGaugeVec,
}

impl Scheduling {
    pub fn placed(&self, tier: &str) {
        self.placements.with_label_values(&[tier]).inc();
    }

    /// A binding CAS this replica lost. Not an error — another replica bound
    /// the same VM in the same instant — but a rate that climbs says the
    /// replicas are fighting over the same work.
    pub fn conflict(&self, tier: &str) {
        self.conflicts.with_label_values(&[tier]).inc();
    }

    /// Set every reason each pass, zero included; see `Objects::set_vms`.
    pub fn set_pending(&self, tier: &str, reason: &str, n: i64) {
        self.pending.with_label_values(&[tier, reason]).set(n);
    }
}

/// Who is dialled in, and how stale their last heartbeat is.
pub struct Sessions {
    connected: IntGaugeVec,
    heartbeat_age: GaugeVec,
}

impl Sessions {
    pub fn set_connected(&self, kind: &str, n: i64) {
        self.connected.with_label_values(&[kind]).set(n);
    }

    /// Clear heartbeat series before repopulating the current peer inventory,
    /// so removed peers do not retain frozen ages.
    pub fn reset_heartbeats(&self) {
        self.heartbeat_age.reset();
    }

    pub fn set_heartbeat_age(&self, kind: &str, peer: &str, seconds: f64) {
        self.heartbeat_age
            .with_label_values(&[kind, peer])
            .set(seconds);
    }
}

/// The store, from the caller's side: how long an operation took, how often
/// one failed and for which reason, and the newest revision anything here has
/// seen.
pub struct Etcd {
    duration: HistogramVec,
    errors: IntCounterVec,
    revision: IntGauge,
}

impl Etcd {
    pub fn observe(&self, operation: &str, seconds: f64) {
        self.duration
            .with_label_values(&[operation])
            .observe(seconds);
    }

    /// `result` is the KIND of failure — "timeout", "conflict", "backend" —
    /// and never the message. The message names keys and objects, and would
    /// make this the one label that could grow without bound.
    pub fn failed(&self, operation: &str, result: &str) {
        self.errors.with_label_values(&[operation, result]).inc();
    }

    /// Record a newly observed etcd revision. The gauge is a position rather than
    /// a count. The read-then-set is not atomic, so concurrent replies may briefly
    /// replace a higher observation with a lower one.
    pub fn saw_revision(&self, revision: i64) {
        if revision > self.revision.get() {
            self.revision.set(revision);
        }
    }
}

/// The node's own half: what it is running, what its drivers cost, and how
/// often one of its VMs ended up somewhere no pass will touch again.
pub struct AgentSide {
    vms: IntGaugeVec,
    driver: HistogramVec,
    quarantines: IntCounter,
}

impl AgentSide {
    pub fn set_vms(&self, phase: &str, n: i64) {
        self.vms.with_label_values(&[phase]).set(n);
    }

    /// One driver call. `driver` is a configured backend name and `operation`
    /// is one of a handful of verbs — both bounded, neither derived from a
    /// vm id or a path.
    pub fn driver_op(&self, driver: &str, operation: &str, seconds: f64) {
        self.driver
            .with_label_values(&[driver, operation])
            .observe(seconds);
    }

    pub fn quarantined(&self) {
        self.quarantines.inc();
    }
}

/// Everything, built once and registered once.
pub struct Metrics {
    registry: Registry,
    pub reconcile: Reconcile,
    pub objects: Objects,
    pub scheduling: Scheduling,
    pub sessions: Sessions,
    pub etcd: Etcd,
    pub agent: AgentSide,
}

static METRICS: OnceLock<Metrics> = OnceLock::new();

/// The one set of handles. Built on first use; every builder call below is
/// infallible for constant inputs, and `expect` says so rather than pushing a
/// Result into every call site that only ever wants to increment a counter.
pub fn get() -> &'static Metrics {
    METRICS.get_or_init(build)
}

pub fn reconcile() -> &'static Reconcile {
    &get().reconcile
}
pub fn objects() -> &'static Objects {
    &get().objects
}
pub fn scheduling() -> &'static Scheduling {
    &get().scheduling
}
pub fn sessions() -> &'static Sessions {
    &get().sessions
}
pub fn etcd() -> &'static Etcd {
    &get().etcd
}
pub fn agent() -> &'static AgentSide {
    &get().agent
}

/// The registry itself, for the exposition and for tests.
pub fn registry() -> &'static Registry {
    &get().registry
}

/// The exposition body, in the text format a Prometheus scrapes.
pub fn render() -> String {
    let families = registry().gather();
    let mut buf = Vec::new();
    if let Err(e) = TextEncoder::new().encode(&families, &mut buf) {
        // Degraded and self-healing: the next scrape encodes the same
        // families again. Never fatal — a monitoring endpoint must not be
        // able to take the component down.
        warn!(error = format!("{e:#}"), "encoding the metrics failed");
        return String::new();
    }
    String::from_utf8_lossy(&buf).into_owned()
}

/// Serve metrics when configured; None disables the listener. Propagate
/// bind failure to startup. This endpoint has no API authentication.
pub async fn serve(listen: Option<&str>) -> anyhow::Result<()> {
    let Some(addr) = listen.filter(|a| !a.is_empty()) else {
        return Ok(());
    };
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .map_err(|e| anyhow::anyhow!("binding the metrics endpoint {addr}: {e:#}"))?;
    info!(endpoint = %addr, "metrics endpoint listening");
    let router = axum::Router::new().route("/metrics", axum::routing::get(expose));
    tokio::spawn(async move {
        if let Err(e) = axum::serve(listener, router).await {
            warn!(error = format!("{e:#}"), "metrics endpoint stopped");
        }
    });
    Ok(())
}

async fn expose() -> impl axum::response::IntoResponse {
    (
        [(
            axum::http::header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        render(),
    )
}

/// A stopwatch for the histograms above. `Instant`, not a wall clock: a step
/// backwards in NTP must not produce a negative duration.
pub struct Timer(Instant);

impl Timer {
    pub fn start() -> Self {
        Self(Instant::now())
    }

    pub fn seconds(&self) -> f64 {
        self.0.elapsed().as_secs_f64()
    }
}

impl Default for Timer {
    fn default() -> Self {
        Self::start()
    }
}

/// Now, as Prometheus spells an instant: seconds since the epoch, as a float.
fn unix_seconds() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

fn counter(name: &str, help: &str, labels: &[&str]) -> IntCounterVec {
    IntCounterVec::new(Opts::new(format!("{PREFIX}{name}"), help), labels)
        .expect("a constant metric definition is valid")
}

fn gauge(name: &str, help: &str, labels: &[&str]) -> IntGaugeVec {
    IntGaugeVec::new(Opts::new(format!("{PREFIX}{name}"), help), labels)
        .expect("a constant metric definition is valid")
}

fn float_gauge(name: &str, help: &str, labels: &[&str]) -> GaugeVec {
    GaugeVec::new(Opts::new(format!("{PREFIX}{name}"), help), labels)
        .expect("a constant metric definition is valid")
}

fn histogram(name: &str, help: &str, labels: &[&str], buckets: Vec<f64>) -> HistogramVec {
    HistogramVec::new(
        HistogramOpts::new(format!("{PREFIX}{name}"), help).buckets(buckets),
        labels,
    )
    .expect("a constant metric definition is valid")
}

/// The buckets, chosen against what each thing actually costs rather than
/// taken from a default. A histogram whose observations all land in the top
/// bucket answers no question at all.
fn buckets(start: f64, count: usize) -> Vec<f64> {
    exponential_buckets(start, 2.0, count).expect("a constant bucket range is valid")
}

fn build() -> Metrics {
    let registry = Registry::new();

    let reconcile = Reconcile {
        // A pass is a listing plus a decision per object: sub-millisecond on
        // an empty store, seconds on a large one.
        duration: histogram(
            "reconcile_pass_duration_seconds",
            "How long one reconcile pass took, by tier and object kind.",
            &["tier", "kind"],
            buckets(0.001, 14),
        ),
        errors: counter(
            "reconcile_errors_total",
            "Reconcile passes that ended in an error, by tier and object kind.",
            &["tier", "kind"],
        ),
        last_success: float_gauge(
            "reconcile_last_success_timestamp_seconds",
            "When the last successful reconcile pass finished, in seconds since the epoch. \
             Time since is `time() - this`.",
            &["tier", "kind"],
        ),
    };

    let objects = Objects {
        count: gauge(
            "objects",
            "Stored objects, by kind, as the reconcile pass that reads them sees it.",
            &["kind"],
        ),
        vms: gauge("vms", "Vm objects by phase.", &["phase"]),
        stuck: gauge(
            "phase_stuck",
            "Objects whose phase has stood longer than that phase's budget, by kind, phase \
             and the reason behind it. Nothing is promoted on account of it; see the deadlines \
             in controller_api::stuck.",
            &["kind", "phase", "reason"],
        ),
    };

    let scheduling = Scheduling {
        placements: counter(
            "scheduler_placements_total",
            "Vms bound to a node or a cluster by this replica.",
            &["tier"],
        ),
        conflicts: counter(
            "scheduler_conflicts_total",
            "Binding writes this replica lost to another writer (compare-and-swap conflicts).",
            &["tier"],
        ),
        pending: gauge(
            "scheduler_pending_vms",
            "Unplaced Vms by the category of why they are unplaced.",
            &["tier", "reason"],
        ),
    };

    let sessions = Sessions {
        connected: gauge(
            "sessions",
            "Peers with a live session on this replica, by what kind of peer they are.",
            &["kind"],
        ),
        heartbeat_age: float_gauge(
            "heartbeat_age_seconds",
            "How long ago each peer's last heartbeat was written.",
            &["kind", "peer"],
        ),
    };

    let etcd = Etcd {
        // Bounded above by the store's own five-second request timeout, so
        // the top bucket is where a timeout lands and nothing else.
        duration: histogram(
            "etcd_operation_duration_seconds",
            "How long one etcd operation took.",
            &["operation"],
            buckets(0.0005, 14),
        ),
        errors: counter(
            "etcd_errors_total",
            "etcd operations that failed, by operation and by the kind of failure.",
            &["operation", "result"],
        ),
        revision: IntGauge::new(
            format!("{PREFIX}etcd_observed_revision"),
            "The newest store revision any operation in this process has seen.",
        )
        .expect("a constant metric definition is valid"),
    };

    let agent = AgentSide {
        vms: gauge("agent_vms", "Vms on this node by phase.", &["phase"]),
        // Driver work is process spawns, lvcreate and virtiofsd: tens of
        // milliseconds to tens of seconds.
        driver: histogram(
            "agent_driver_operation_duration_seconds",
            "How long one driver call took, by driver name and operation.",
            &["driver", "operation"],
            buckets(0.01, 12),
        ),
        quarantines: IntCounter::new(
            format!("{PREFIX}agent_quarantines_total"),
            "Vms this node put into quarantine.",
        )
        .expect("a constant metric definition is valid"),
    };

    let collectors: Vec<Box<dyn prometheus::core::Collector>> = vec![
        Box::new(reconcile.duration.clone()),
        Box::new(reconcile.errors.clone()),
        Box::new(reconcile.last_success.clone()),
        Box::new(objects.count.clone()),
        Box::new(objects.vms.clone()),
        Box::new(objects.stuck.clone()),
        Box::new(scheduling.placements.clone()),
        Box::new(scheduling.conflicts.clone()),
        Box::new(scheduling.pending.clone()),
        Box::new(sessions.connected.clone()),
        Box::new(sessions.heartbeat_age.clone()),
        Box::new(etcd.duration.clone()),
        Box::new(etcd.errors.clone()),
        Box::new(etcd.revision.clone()),
        Box::new(agent.vms.clone()),
        Box::new(agent.driver.clone()),
        Box::new(agent.quarantines.clone()),
    ];
    for collector in collectors {
        registry
            .register(collector)
            .expect("every metric is registered once, under a name of its own");
    }

    Metrics {
        registry,
        reconcile,
        objects,
        scheduling,
        sessions,
        etcd,
        agent,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Touch every series once, so that `gather` has something to say about
    /// each of them: a `*Vec` with no children is registered and invisible.
    fn touch() {
        let m = get();
        m.reconcile.pass(TIER_CLUSTER, "Vm", 0.01, true);
        m.reconcile.pass(TIER_CLOUD, "Vm", 0.01, false);
        m.objects.set_count("Node", 3);
        m.objects.set_vms("Running", 2);
        m.objects.set_stuck("Vm", "Unknown", "Silent", 1);
        m.scheduling.placed(TIER_CLUSTER);
        m.scheduling.conflict(TIER_CLUSTER);
        m.scheduling.set_pending(TIER_CLUSTER, "no-capacity", 1);
        m.sessions.set_connected(PEER_NODE, 2);
        m.sessions.set_heartbeat_age(PEER_NODE, "manacor", 1.5);
        m.etcd.observe("list", 0.002);
        m.etcd.failed("update", "conflict");
        m.etcd.saw_revision(4711);
        m.agent.set_vms("Running", 1);
        m.agent.driver_op("lvm-thin", "create", 0.4);
        m.agent.quarantined();
    }

    /// Check label names against the bounded vocabulary. This source guard
    /// does not independently prove all supplied label values are bounded.
    #[test]
    fn the_label_names_are_the_ones_that_are_bounded() {
        // tier: three components. kind: the resource table, or the two peer
        // kinds. phase: VmPhaseKind::ALL. reason: the pending categories.
        // operation: the store's verbs, or a driver's. driver: what the node
        // has configured. peer: a node or cluster name. result: the store's
        // error variants.
        const BOUNDED: [&str; 8] = [
            "tier",
            "kind",
            "phase",
            "reason",
            "operation",
            "driver",
            "peer",
            "result",
        ];
        touch();
        for family in registry().gather() {
            for metric in family.get_metric() {
                for label in metric.get_label() {
                    assert!(
                        BOUNDED.contains(&label.name()),
                        "{}: label {:?} is not in the bounded set",
                        family.name(),
                        label.name()
                    );
                }
            }
        }
    }

    /// Metric names use the common prefix, counter suffix and explicit units.
    #[test]
    fn the_names_follow_the_convention_a_dashboard_expects() {
        use prometheus::proto::MetricType;
        touch();
        for family in registry().gather() {
            let name = family.name();
            assert!(name.starts_with(PREFIX), "{name} carries no prefix");
            assert!(!family.help().is_empty(), "{name} has no HELP");
            match family.get_field_type() {
                MetricType::COUNTER => {
                    assert!(name.ends_with("_total"), "{name} is a counter")
                }
                MetricType::HISTOGRAM => {
                    assert!(name.ends_with("_seconds"), "{name} is a duration")
                }
                _ => {}
            }
        }
    }

    /// What a scrape gets: the text exposition format, with the HELP and TYPE
    /// lines a Prometheus parses and the samples under them.
    #[test]
    fn a_scrape_renders_the_text_exposition_format() {
        touch();
        let body = render();
        assert!(
            body.contains("# HELP meister_scheduler_pending_vms"),
            "{body}"
        );
        assert!(
            body.contains("# TYPE meister_scheduler_pending_vms gauge"),
            "{body}"
        );
        assert!(
            body.contains(
                r#"meister_scheduler_pending_vms{reason="no-capacity",tier="cluster"} 1"#
            ),
            "{body}"
        );
        // Require the overdue gauge in actual exposition, not just registry setup.
        assert!(
            body.contains(r#"meister_phase_stuck{kind="Vm",phase="Unknown",reason="Silent"} 1"#),
            "{body}"
        );
        // and the histogram's own three families, which is what makes a
        // quantile computable at all
        assert!(
            body.contains("meister_etcd_operation_duration_seconds_bucket"),
            "{body}"
        );
        assert!(
            body.contains("meister_etcd_operation_duration_seconds_sum"),
            "{body}"
        );
        assert!(
            body.contains("meister_etcd_operation_duration_seconds_count"),
            "{body}"
        );
    }

    /// No address, no listener. The endpoint is unauthenticated and its
    /// series name objects across every tenant, so nothing is the default.
    #[tokio::test]
    async fn without_an_address_nothing_listens() {
        serve(None).await.expect("off is not an error");
        serve(Some("")).await.expect("and so is an empty string");
    }

    /// An address that cannot be bound is an error at start-up, not a
    /// warning: an operator who asked for a port and did not get one should
    /// learn it from the thing that failed.
    #[tokio::test]
    async fn an_address_that_cannot_be_bound_is_an_error() {
        let err = serve(Some("256.256.256.256:9090"))
            .await
            .expect_err("that is not an address");
        assert!(err.to_string().contains("metrics endpoint"), "{err}");
    }
}
