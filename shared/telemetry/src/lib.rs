// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Telemetry for all three components: one subscriber setup, one traceparent
//! format, one place that knows whether an exporter is attached.
//!
//! The shape is deliberately conservative. `otlp_endpoint = None` is the
//! behaviour that has been running in the lab all along — an `fmt` subscriber
//! and nothing else — and setting it adds a layer beside that one rather than
//! replacing it. Nothing about how the stack logs changes when tracing is
//! turned on, and nothing about how it traces is lost when it is turned off:
//! the trace id is a span field either way (see `traceparent`).

pub mod metrics;
pub mod traceparent;

use std::time::Duration;

use tracing::{info, warn};
use tracing_subscriber::EnvFilter;
use tracing_subscriber::layer::SubscriberExt;
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

/// What a component wants from telemetry. A struct rather than four
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
}

/// Bring up logging, and tracing if an endpoint was configured.
pub fn init(setup: Setup<'_>) -> anyhow::Result<()> {
    let Setup {
        service_name,
        default_filter,
        span_close_events,
        otlp_endpoint,
    } = setup;
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| default_filter.into());
    let fmt = tracing_subscriber::fmt::layer().with_span_events(if span_close_events {
        tracing_subscriber::fmt::format::FmtSpan::CLOSE
    } else {
        tracing_subscriber::fmt::format::FmtSpan::NONE
    });

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

/// The context to send onwards from here.
///
/// With an exporter attached this is the CURRENT span's real context, so the
/// next hop's `attach_parent` makes a genuine parent-child edge and the trace
/// is a chain. Without one there is no current context to read, and the
/// answer is `fallback` — the context this work was started under — which
/// keeps every hop on the same trace id even though the shape is flat.
///
/// Minting a synthetic child instead would be worse than either: the next hop
/// would attach to a span id nothing ever emitted, and the trace would come
/// out with a dangling reference in it.
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

/// Continue `parent` in the given span.
///
/// The span must NOT have started yet. tracing-opentelemetry mints a span's
/// trace id when its builder is consumed, and refuses `set_parent` on a span
/// that is already running — so a parent attached from inside the span's own
/// body arrives too late and is dropped. That is exactly how the first
/// version of this produced three unrelated traces that each looked fine on
/// its own, which is why `AlreadyStarted` is a warning here and not a `let
/// _ =`. Use `in_trace`, which cannot get the order wrong.
///
/// A no-op without an exporter, and deliberately so: the trace id is already
/// on the span as a field, so the fmt logs of all three components carry the
/// same id whether or not anything is collecting them. This is what turns
/// that id into a real parent-child edge when something is.
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

/// Run `work` inside `span`, continuing `parent`.
///
/// The one correct order, in one place: attach, then start. Every hop that
/// receives a context uses this rather than building the sequence by hand.
pub async fn in_trace<F: std::future::Future>(
    span: tracing::Span,
    parent: &TraceParent,
    work: F,
) -> F::Output {
    use tracing::Instrument;
    attach_parent(&span, parent);
    work.instrument(span).await
}
