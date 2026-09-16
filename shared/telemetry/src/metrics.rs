// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! The second signal: time series, scraped.
//!
//! Traces already leave this stack over OTLP and answer "what happened to
//! THIS request". Nothing answered "what is happening, continuously" — the
//! convergence times a chaos run measures from outside with a stopwatch are
//! the same quantities this publishes from inside, and the difference between
//! the two is a table from one run against a curve.
//!
//! Three decisions are worth stating rather than reading out of the code.
//!
//! **A separate library from the OTLP stack.** `opentelemetry-prometheus`
//! exists at 0.32 and would match the pinned `opentelemetry` crates, but it
//! is a bridge from the OTel METRICS sdk — which is not in this tree — and it
//! decorates what it exports: `otel_scope_name` and `otel_scope_version` on
//! every series, a `target_info` gauge beside them, and unit suffixes derived
//! from the instrument rather than written into the name. The requirement is
//! a stock Prometheus with a stock Grafana and no glue in between, and those
//! decorations are exactly the glue. `prometheus` without default features is
//! the registry and the text exposition format, nothing else, and every name,
//! bucket and label below is spelled out here rather than derived.
//!
//! **One registry per process, reached globally.** A metric is written from
//! inside a reconcile pass, a driver call and an etcd operation — three places
//! that have no state in common and would each need a handle threaded through
//! them. `prometheus` itself takes this shape (`default_registry`), and the
//! cost of the alternative is a parameter on every function between `main`
//! and the write.
//!
//! **Recording is unconditional; SERVING is not.** Without a configured
//! address nothing listens (`serve(None)`), and that is the security half:
//! the REST edge is authenticated and tenant-scoped, `/metrics` is neither,
//! and these series name nodes, clusters and drivers across every tenant.
//! The counters still count — a few atomics nobody reads — because the
//! alternative is a branch at every call site that can only ever be wrong in
//! one direction.
//!
//! ## The cardinality rule
//!
//! Never a vm id, an address, a socket path or an error text as a label
//! value. Node, cluster and driver names are bounded by the fleet and are
//! allowed; everything else that varies per object goes in the log line, not
//! in a label. A label with an unbounded value range does not fail here — it
//! fails months later in somebody's Prometheus — so
//! `the_label_names_are_the_ones_that_are_bounded` holds the list.

use std::sync::OnceLock;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use prometheus::{
    Encoder, GaugeVec, HistogramOpts, HistogramVec, IntCounter, IntCounterVec, IntGauge,
    IntGaugeVec, Opts, Registry, TextEncoder, exponential_buckets,
};
use tracing::{info, warn};

/// The address the exposition listener takes when it is switched on without
/// one being named. Loopback, because a port that answers every question
/// about every tenant's topology should be reachable from the node's own
/// scraper and not from the lab.
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

/// How many objects there are, and — for VMs — in what phase.
///
/// Set from the listings a reconcile pass already makes, and deliberately not
/// from listings of its own: a gauge that costs an etcd round trip per kind
/// per tick would be a monitoring feature that changes the thing it monitors.
/// So the kinds that appear here are the kinds a pass reads.
pub struct Objects {
    count: IntGaugeVec,
    vms: IntGaugeVec,
    stuck: IntGaugeVec,
}

impl Objects {
    pub fn set_count(&self, kind: &str, n: i64) {
        self.count.with_label_values(&[kind]).set(n);
    }

    /// How many objects are past the deadline for the phase they are in.
    ///
    /// D-C1 as a number. A node fell out of the lab and the VMs on it stood
    /// at `Unknown { Silent }` for four and a half days with nothing anywhere
    /// distinguishing them from a VM that went `Unknown` nine seconds ago —
    /// see `controller_api::stuck`, which owns the budgets. **Nothing is
    /// promoted by it**: this gauge and one event are all a deadline buys.
    ///
    /// Every label is a closed set — the kind from the resource table, the
    /// phase from an `XPhaseKind`, the reason from an `XReason` — so the
    /// series count is bounded by the code and not by the fleet.
    pub fn set_stuck(&self, kind: &str, phase: &str, reason: &str, n: i64) {
        self.stuck.with_label_values(&[kind, phase, reason]).set(n);
    }

    /// Forget every stuck series before a pass sets the ones it found.
    ///
    /// Rebuilt per pass rather than decremented, for the reason
    /// `Sessions::reset_heartbeats` is: an object that has come unstuck — or
    /// been deleted — has to LOSE its series rather than keep the last value
    /// for ever, and a pass cannot know which cells it is about to stop
    /// filling.
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

/// What the scheduler did, and what it could not do.
///
/// `pending` is the row worth the most: `reason` is the bounded CATEGORY of
/// the sentence that goes on the object, which is what makes a pending VM a
/// time series instead of a string somebody has to read.
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

    /// Drop every per-peer series before a pass re-sets them.
    ///
    /// The peer name is a label — bounded by the fleet, and the rule allows
    /// it — but a node that is removed from the inventory would otherwise
    /// leave its last age behind for ever, frozen, looking like a node whose
    /// heartbeat simply stopped. The pass that knows the whole list is the
    /// only place that can tell those apart.
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

    /// The store revision an operation just came back stamped with.
    ///
    /// A gauge by type and not a counter: it is a position in the store's
    /// history, not a count of anything this process did, and a restore moves
    /// it backwards — which a counter would have to report as a reset to
    /// zero, and `rate()` would then read as a burst of a billion.
    ///
    /// Only ever forwards here, though. Operations answer concurrently and
    /// out of order, and a gauge that took whichever answer arrived last
    /// would sawtooth around the real revision instead of following it. The
    /// read-then-set is not atomic and does not need to be: the only thing a
    /// lost race costs is one revision this process had already seen.
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

/// Bind the exposition listener and serve it, or do nothing.
///
/// `None` is off, and off is the default everywhere: this port is
/// unauthenticated and its series name objects across every tenant. Binding
/// failure is an error at start-up rather than a warning, for the reason half
/// a TLS config is one — an operator who asked for a port and did not get one
/// should be told by the thing that failed, not by a scrape that never
/// arrives.
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

    /// The rule, held rather than written down: every label VALUE this stack
    /// can produce comes out of a bounded set, so every label NAME has to be
    /// one of the names that are bounded. A vm id, an address, a socket path
    /// or an error text as a label is what takes a Prometheus down months
    /// after the commit that added it.
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

    /// The other half of "a stock Grafana with no glue": the names. Every
    /// series carries the prefix, every counter ends in `_total`, and
    /// everything measured in seconds says so in its name rather than in a
    /// unit field nothing reads.
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
        // D7's gauge, and it is here rather than in a test of its own for
        // the reason it is here at all: it was BUILT, given labels and set by
        // a pass, and simply never added to the collector list — so it went
        // through the whole of one lane's tests and one local stack invisible.
        // A series that is not in the exposition is a series nobody has.
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
