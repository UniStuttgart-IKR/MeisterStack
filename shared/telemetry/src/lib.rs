// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Tracing and log setup shared by agents and controllers.
//!
//! Without an OTLP endpoint, install only formatted logging. Configuring an
//! exporter adds an OpenTelemetry layer. Text and JSON formats use the same
//! level filter and fields; explicit trace IDs remain available without OTLP.

pub mod metrics;
pub mod traceparent;

use std::time::Duration;

use tracing::{info, warn};
use tracing_subscriber::EnvFilter;
use tracing_subscriber::Layer;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::registry::LookupSpan;
use tracing_subscriber::util::SubscriberInitExt;

pub use traceparent::TraceParent;

/// Set exactly once, by `init`, and only when an endpoint was configured.
static PROVIDER: std::sync::OnceLock<opentelemetry_sdk::trace::SdkTracerProvider> =
    std::sync::OnceLock::new();

/// `otlp_endpoint` in a component's TOML. `None` — the field absent — is the
/// fmt-only subscriber this stack has always had.
pub type OtlpEndpoint = Option<String>;

/// How long the exporter may spend shipping a batch before it gives up.
/// Bounded for the same reason everything else in this pass is: a collector
/// that stops answering must not become a component that stops working.
const EXPORT_TIMEOUT: Duration = Duration::from_secs(3);

/// Configured log format. Human is the default; JSON provides structured
/// fields for collectors.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogFormat {
    #[default]
    Human,
    Json,
}

/// What a component wants from telemetry. A struct rather than five
/// positional arguments because three of them are strings.
pub struct Setup<'a> {
    /// What a trace viewer groups spans under — one name per component, so a
    /// single trace visibly crosses `meister-cloud-controller`,
    /// `meister-cluster-controller` and `meister-agent`.
    pub service_name: &'static str,
    /// The filter when RUST_LOG says nothing. Each component keeps the one it
    /// had.
    pub default_filter: &'a str,
    /// Log a line when a span closes, with how long it was open. The agent has
    /// always done this and keeps doing it — the driver spans are where the
    /// time goes, and their close events are how that was ever measured.
    pub span_close_events: bool,
    pub otlp_endpoint: &'a OtlpEndpoint,
    /// Human for a person, Json for a collector. See `LogFormat`.
    pub log_format: LogFormat,
}

/// Build the formatter without installing a global subscriber. The writer is
/// injected for tests. JSON flattens event fields, includes the current span
/// under `span` and omits the ancestor span list. Human output uses the standard
/// formatter. Trace IDs carried by the current span remain available in both.
fn fmt_layer<S, W>(
    format: LogFormat,
    span_close_events: bool,
    writer: W,
) -> Box<dyn Layer<S> + Send + Sync>
where
    S: tracing::Subscriber + for<'a> LookupSpan<'a>,
    W: for<'a> tracing_subscriber::fmt::MakeWriter<'a> + Send + Sync + 'static,
{
    let span_events = if span_close_events {
        tracing_subscriber::fmt::format::FmtSpan::CLOSE
    } else {
        tracing_subscriber::fmt::format::FmtSpan::NONE
    };
    match format {
        LogFormat::Human => tracing_subscriber::fmt::layer()
            .with_span_events(span_events)
            .with_writer(writer)
            .boxed(),
        LogFormat::Json => tracing_subscriber::fmt::layer()
            .json()
            .flatten_event(true)
            .with_current_span(true)
            .with_span_list(false)
            .with_span_events(span_events)
            .with_writer(writer)
            .boxed(),
    }
}

/// Bring up logging, and tracing if an endpoint was configured.
pub fn init(setup: Setup<'_>) -> anyhow::Result<()> {
    let Setup {
        service_name,
        default_filter,
        span_close_events,
        otlp_endpoint,
        log_format,
    } = setup;
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| default_filter.into());
    let fmt = fmt_layer(log_format, span_close_events, std::io::stdout);

    let Some(endpoint) = otlp_endpoint else {
        tracing_subscriber::registry().with(filter).with(fmt).init();
        return Ok(());
    };

    use opentelemetry_otlp::WithExportConfig;
    let exporter = opentelemetry_otlp::SpanExporter::builder()
        .with_tonic()
        .with_endpoint(endpoint.clone())
        .with_timeout(EXPORT_TIMEOUT)
        .build()?;
    let provider = opentelemetry_sdk::trace::SdkTracerProvider::builder()
        .with_batch_exporter(exporter)
        .with_resource(
            opentelemetry_sdk::Resource::builder()
                .with_service_name(service_name)
                .build(),
        )
        .build();
    // Kept so `shutdown` at exit can flush a batch that has not left yet —
    // the last spans of a run are the interesting ones often enough to be
    // worth the line.
    let _ = PROVIDER.set(provider.clone());
    let otel = tracing_opentelemetry::layer().with_tracer(
        opentelemetry::trace::TracerProvider::tracer(&provider, service_name),
    );

    tracing_subscriber::registry()
        .with(filter)
        .with(fmt)
        .with(otel)
        .init();
    info!(endpoint = %endpoint, service = service_name, "otlp span export enabled");
    Ok(())
}

/// Flush what has not been exported yet. Called at a clean exit; a component
/// that is killed loses at most one batch, which is the trade a batch
/// exporter is. Nothing to do when no exporter was configured.
pub fn shutdown() {
    if let Some(provider) = PROVIDER.get()
        && let Err(e) = provider.shutdown()
    {
        warn!(
            error = format!("{e:#}"),
            "flushing the span exporter failed"
        );
    }
}

/// Use the active exported span context when available; otherwise keep
/// the supplied fallback trace. Do not invent a child span that was never emitted.
pub fn outgoing(fallback: &TraceParent) -> TraceParent {
    use opentelemetry::trace::TraceContextExt;
    use tracing_opentelemetry::OpenTelemetrySpanExt;

    let context = tracing::Span::current().context();
    let span_context = context.span().span_context().clone();
    if !span_context.is_valid() {
        return *fallback;
    }
    TraceParent {
        trace_id: span_context.trace_id().to_bytes(),
        span_id: span_context.span_id().to_bytes(),
        flags: span_context.trace_flags().to_u8(),
    }
}

/// Attach parent context before the span starts. `in_trace` preserves
/// that order; warn if the exporter reports an already-started span.
/// Without an exporter, explicit trace fields still correlate logs.
pub fn attach_parent(span: &tracing::Span, parent: &TraceParent) {
    use opentelemetry::trace::{
        SpanContext, SpanId, TraceContextExt, TraceFlags, TraceId, TraceState,
    };
    use tracing_opentelemetry::{OpenTelemetrySpanExt, SetParentError};

    let context = opentelemetry::Context::new().with_remote_span_context(SpanContext::new(
        TraceId::from_bytes(parent.trace_id),
        SpanId::from_bytes(parent.span_id),
        TraceFlags::new(parent.flags),
        true, // remote: this context arrived over the wire, it is not ours
        TraceState::default(),
    ));
    match span.set_parent(context) {
        Ok(()) => {}
        // No exporter, or the span was filtered out. Both are the documented
        // no-op: the trace id is on the span as a field either way.
        Err(SetParentError::LayerNotFound) | Err(SetParentError::SpanDisabled) => {}
        // A wiring mistake, and a silent one if it is not said out loud: the
        // hop below this one will show up as its own unrelated trace.
        Err(e) => warn!(error = format!("{e:#}"), trace_id = %parent.trace_id_hex(),
                        "could not continue the caller's trace"),
    }
}

/// Attach parent context before entering the span, then run work within it.
pub async fn in_trace<F: std::future::Future>(
    span: tracing::Span,
    parent: &TraceParent,
    work: F,
) -> F::Output {
    use tracing::Instrument;
    attach_parent(&span, parent);
    work.instrument(span).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::sync::{Arc, Mutex};

    /// The trace id every hop of a `vm create` carries. Written out here
    /// rather than generated, because half of what this test asserts is that
    /// this exact string can be found again in the output.
    const TRACE_ID: &str = "4bf92f3577b34da6a3ce929d0e0e4736";
    const TRACEPARENT: &str = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";

    /// A `MakeWriter` that keeps what was written. `init` installs a global
    /// subscriber, so the two formats can only be compared in one process by
    /// building the layer directly — which is what `fmt_layer` is for.
    #[derive(Clone, Default)]
    struct Buffer(Arc<Mutex<Vec<u8>>>);

    impl Write for Buffer {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Buffer {
        type Writer = Buffer;
        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    /// One line, from a span shaped like the ones the agent and both
    /// controllers actually open: a name, a field of its own, and the trace
    /// id of the work that reached it.
    fn one_line(format: LogFormat) -> String {
        let buffer = Buffer::default();
        let subscriber =
            tracing_subscriber::registry().with(fmt_layer(format, false, buffer.clone()));
        tracing::subscriber::with_default(subscriber, || {
            let parent = TraceParent::parse(TRACEPARENT).expect("the fixture is a valid header");
            let span = tracing::info_span!(
                "dispatch",
                request_id = "r-7",
                trace_id = %parent.trace_id_hex()
            );
            let _entered = span.enter();
            tracing::info!(vm = "trace-probe", "created");
        });
        let raw = buffer.0.lock().unwrap().clone();
        String::from_utf8(raw).expect("the subscriber writes utf-8")
    }

    /// Both formats retain event and trace fields; JSON exposes structured
    /// keys while human output renders them as text.
    #[test]
    fn json_makes_the_trace_id_a_key_and_human_leaves_it_in_the_text() {
        let json = one_line(LogFormat::Json);
        let line: serde_json::Value =
            serde_json::from_str(json.trim()).expect("LogFormat::Json writes one json object");

        // The envelope Loki reads as fields without a regex.
        assert_eq!(line["level"], "INFO");
        assert_eq!(line["message"], "created");
        assert_eq!(line["target"], module_path!());
        // flatten_event: the event's own field is top-level, not under
        // `fields`.
        assert_eq!(line["vm"], "trace-probe");
        // with_current_span: the span's fields, and the trace id among them.
        // `span.trace_id` is `span_trace_id` once Loki's `| json` has
        // flattened it — that is the name the derived field points at.
        assert_eq!(line["span"]["trace_id"], TRACE_ID);
        assert_eq!(line["span"]["request_id"], "r-7");
        assert_eq!(line["span"]["name"], "dispatch");
        // with_span_list(false): no `spans` array, so no label per ancestor
        // per line.
        assert!(
            line.get("spans").is_none(),
            "the ancestor list is off on purpose: {json}"
        );

        let human = one_line(LogFormat::Human);
        assert!(human.contains(TRACE_ID), "the id is in the text: {human}");
        assert!(human.contains("created"), "so is the message: {human}");
        assert!(human.contains("dispatch"), "and the span name: {human}");
        assert!(
            serde_json::from_str::<serde_json::Value>(human.trim()).is_err(),
            "LogFormat::Human is not json: {human}"
        );
    }

    /// The config key, as a config file spells it. `Human` is the default and
    /// the absence of the key is that default — a fleet that says nothing
    /// logs the way it logged yesterday.
    #[test]
    fn log_format_parses_from_toml_and_defaults_to_human() {
        #[derive(Debug, serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Cfg {
            #[serde(default)]
            log_format: LogFormat,
        }

        let json: Cfg = toml::from_str(r#"log_format = "json""#).expect("json is a value");
        assert_eq!(json.log_format, LogFormat::Json);
        let human: Cfg = toml::from_str(r#"log_format = "human""#).expect("human is a value");
        assert_eq!(human.log_format, LogFormat::Human);
        assert_eq!(
            toml::from_str::<Cfg>("")
                .expect("the key is optional")
                .log_format,
            LogFormat::Human
        );
        // A misspelling is refused rather than quietly logged the old way:
        // an operator who wrote "JSON" wants json, and a fleet that silently
        // kept the human format would be found out by an empty Loki.
        let bad = toml::from_str::<Cfg>(r#"log_format = "JSON""#).unwrap_err();
        assert!(
            bad.to_string().contains("human") && bad.to_string().contains("json"),
            "the error names the two values: {bad}"
        );
    }
}
