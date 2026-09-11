// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

use clap::Parser;
use meister_agent::config::AgentConfig;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "meister-agent", about = "MeisterStack node agent")]
struct Args {
    /// Agent-Config path
    #[arg(long, default_value = "/etc/meisterstack/agent.toml")]
    config: PathBuf,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    // The config decides whether spans are exported, so it has to be read
    // before the subscriber exists. Nothing logs in between.
    let config = AgentConfig::load(&args.config)?;
    telemetry::init(telemetry::Setup {
        service_name: "meister-agent",
        default_filter: "info,meister_agent=debug",
        span_close_events: true,
        otlp_endpoint: &config.otlp_endpoint,
        log_format: config.log_format,
    })?;

    // Before the agent comes up, so that a misspelled address fails at
    // start-up rather than at the first scrape that never arrives.
    telemetry::metrics::serve(config.metrics_listen.as_deref()).await?;

    let result = meister_agent::run_agent(config).await;
    telemetry::shutdown();
    result
}
