// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

use clap::Parser;
use meister_agent::config::AgentConfig;
use std::path::{Path, PathBuf};

#[derive(Parser)]
#[command(name = "meister-agent", about = "MeisterStack node agent")]
struct Args {
    /// Agent-Config path
    #[arg(long, default_value = "/etc/meisterstack/agent.toml")]
    config: PathBuf,

    /// Read the config, check it, say so and exit. Starts nothing: no
    /// socket, no database, no firewall, and no lookup that would only
    /// answer on the node this config is for.
    #[arg(long)]
    check_config: bool,
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    if args.check_config {
        check_config(&args.config);
    }
    run(args)
}

/// Exit 0 and one line on stdout, or exit 1 and the parser's own sentence on
/// stderr. Nothing else: this is what a Nix check calls, and its whole job is
/// to turn a configuration file into a number.
fn check_config(path: &Path) -> ! {
    match AgentConfig::parse(path) {
        Ok(_) => {
            println!("ok: {}", path.display());
            std::process::exit(0)
        }
        Err(e) => {
            eprintln!("meister-agent: {e:#}");
            std::process::exit(1)
        }
    }
}

#[tokio::main]
async fn run(args: Args) -> anyhow::Result<()> {
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
