// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! `meister-deploy` — the plan, the order, and the evidence.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{Context, Result};
use clap::{Args, Parser, Subcommand};

use meister_deploy::effects::{Files, RealFiles};
use meister_deploy::legacy::fleet::Plan;
use meister_deploy::legacy::ops::{self, Ctx};
use meister_deploy::legacy::remote::Ssh;
use meister_deploy::legacy::run::Real;
use meister_deploy::manifest::{self, Contract};
use meister_deploy::run::Policy;

#[derive(Parser)]
#[command(
    name = "meister-deploy",
    about = "The fleet plan, the order a rollout happens in, and what the fleet looks like now",
    long_about = "Reads a fleet inventory and calls nix, ssh and tools/meister-ca. It \
                  evaluates no Nix of its own and speaks no ssh of its own: the shell tools \
                  are the ones an operator can also run by hand."
)]
struct Cli {
    #[command(subcommand)]
    cmd: Verb,
}

#[derive(Subcommand)]
enum Verb {
    /// Print the JSON Schema of a contract object, so that whatever produces
    /// one — a Nix derivation, another tool, a person — can be held to it.
    Schema {
        /// `nix-manifest`, `resolved-fleet` or `check-result`
        kind: String,
    },

    /// Check a file against the contracts. Reads nothing else and asks
    /// nobody anything.
    Validate {
        /// A `nix-manifest/1` or `resolved-fleet/1` json file, or `-` for
        /// standard input
        #[arg(long)]
        manifest: String,
    },

    /// The tool as it was before v1: the `fleet.toml` of schema 1, the rsync
    /// push to the context fleet, `nixos-rebuild --target-host` for metal.
    /// Kept whole, with the same flags, because twelve VMs are served by it
    /// today and `plan` means something else from v1 on.
    Legacy(LegacyCli),
}

#[derive(Args)]
struct LegacyCli {
    /// The plan
    #[arg(short = 'f', long, default_value = "fleet.toml", global = true)]
    fleet: PathBuf,

    /// The flake the systems and images are built from
    #[arg(long, default_value = ".", global = true)]
    flake: String,

    /// Where meister-ca keeps its directory. Overrides the plan's `ca`.
    #[arg(long, global = true)]
    ca: Option<String>,

    /// Print every command, not only the ones that change something
    #[arg(short, long, global = true)]
    verbose: bool,

    /// Say what would happen and read whatever is needed to say it, but
    /// change nothing
    #[arg(long, global = true)]
    dry_run: bool,

    #[command(subcommand)]
    cmd: LegacyVerb,
}

#[derive(Subcommand)]
enum LegacyVerb {
    /// The table: what each node is, what it is running, and whether that is
    /// what the plan says. Read-only.
    Plan {
        /// Ask no host anything — just read the plan back
        #[arg(long)]
        offline: bool,
    },

    /// Build an image: a node's name, `generic`, or `all`
    Image {
        #[arg(default_value = "all")]
        target: String,
        /// Put a copy here, named after the fleet, the node and the commit
        #[arg(long)]
        copy: Option<String>,
    },

    /// Roll the fleet forward: agents, then clusters, then clouds, then
    /// addons, one node of a raft group at a time
    Push {
        /// A node name, a role, or `all`
        #[arg(default_value = "all")]
        only: String,
        /// How long to wait for a replica to be healthy again before giving
        /// up on its group, in seconds
        #[arg(long, default_value_t = 120)]
        wait: u64,
    },

    /// Certificates and the three secrets that are not certificates
    Keys {
        #[command(subcommand)]
        cmd: KeysVerb,
    },

    /// Units, sessions, /dev/kvm, disks — and what the cloud says about its
    /// clusters and nodes, because a unit being active is not the same as a
    /// node that works
    Check {
        /// The cli to ask, and its arguments, e.g.
        /// `--cli 'meister --config cli.toml -p cloud-mtls'`
        #[arg(long)]
        cli: Option<String>,
    },

    /// Write a node's MeisterStack options as an importable Nix module, so a
    /// host with its own NixOS configuration can be a node of this fleet
    Render {
        node: String,
        /// Where to write it (default: stdout)
        #[arg(short = 'o', long)]
        out: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
enum KeysVerb {
    /// Issue everything the plan needs. Idempotent: run it again after adding
    /// a node and it adds that node.
    Init,
    /// Put them on the hosts, under the fixed names the templates point at
    Push {
        #[arg(default_value = "all")]
        only: String,
    },
}

fn main() -> ExitCode {
    match run() {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::FAILURE,
        Err(e) => {
            // Diagnostics on stderr, always: stdout carries the answer, and
            // `--json` has to stay machine-readable even when it is empty.
            eprintln!("meister-deploy: {e:#}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<bool> {
    let cli = Cli::parse();
    match &cli.cmd {
        Verb::Schema { kind } => print_schema(kind),
        Verb::Validate { manifest } => validate_manifest(manifest),
        Verb::Legacy(legacy) => run_legacy(legacy),
    }
}

/// The contract objects that have a schema today. The rest — plan, release,
/// receipt — arrive with M2 and M3, and asking for one now says so rather
/// than printing an empty object.
fn print_schema(kind: &str) -> Result<bool> {
    let schema = match kind {
        "nix-manifest" => schemars::schema_for!(manifest::NixManifest),
        "resolved-fleet" => schemars::schema_for!(manifest::ResolvedFleet),
        "check-result" => schemars::schema_for!(meister_deploy::checks::CheckResult),
        other => anyhow::bail!(
            "there is no schema called {other:?}; this tool knows nix-manifest, \
             resolved-fleet and check-result."
        ),
    };
    println!("{}", serde_json::to_string_pretty(&schema)?);
    Ok(true)
}

fn validate_manifest(from: &str) -> Result<bool> {
    let (text, origin) = if from == "-" {
        // Standard input is not a file, so it does not go through `Files`;
        // it is also the only way a Nix check can hand a manifest over
        // without writing it into the store first.
        let mut text = String::new();
        std::io::stdin()
            .read_to_string(&mut text)
            .context("reading the manifest from standard input failed")?;
        (text, "standard input".to_string())
    } else {
        let path = Path::new(from);
        let files = RealFiles::new(Policy::real());
        (files.read_to_string(path)?, from.to_string())
    };

    match manifest::parse_contract(&text, &origin) {
        Ok(contract) => {
            println!("ok: {origin} is a {}", contract.describe());
            if let Contract::NixManifest(_) = contract {
                // Saying what was NOT checked is part of the answer: these
                // types are a shape, and a shape is not a fleet.
                eprintln!(
                    "note: the shape was checked, not the fleet. Store paths were not \
                     looked up and no host was asked anything."
                );
            }
            Ok(true)
        }
        Err(e) => {
            eprintln!("meister-deploy: {e:#}");
            Ok(false)
        }
    }
}

fn run_legacy(cli: &LegacyCli) -> Result<bool> {
    let plan = Plan::load(&cli.fleet)?;
    let runner = Real {
        dry_run: cli.dry_run,
        verbose: cli.verbose,
    };
    let ssh = Ssh::from_env();

    // `render` is a pure function of the plan — no ssh, no nix, no host — so
    // it is answered before anything that could need a network.
    if let LegacyVerb::Render { node, out } = &cli.cmd {
        let node = plan.node(node)?;
        meister_deploy::legacy::render::write_module(&plan, node, out.as_deref())?;
        return Ok(true);
    }

    let ctx = Ctx {
        plan: &plan,
        runner: &runner,
        ssh: &ssh,
        flake: cli.flake.clone(),
        ca: cli.ca.clone().unwrap_or_else(|| plan.fleet.ca.clone()),
        wait: match &cli.cmd {
            LegacyVerb::Push { wait, .. } => *wait,
            _ => 0,
        },
        offline: matches!(cli.cmd, LegacyVerb::Plan { offline: true }),
    };

    match &cli.cmd {
        LegacyVerb::Plan { .. } => ops::plan(&ctx).map(|()| true),
        LegacyVerb::Image { target, copy } => {
            ops::image(&ctx, target, copy.as_deref()).map(|()| true)
        }
        LegacyVerb::Push { only, .. } => ops::push(&ctx, Some(only)).map(|()| true),
        LegacyVerb::Keys { cmd } => match cmd {
            KeysVerb::Init => ops::keys_init(&ctx).map(|()| true),
            KeysVerb::Push { only } => ops::keys_push(&ctx, Some(only)).map(|()| true),
        },
        LegacyVerb::Check { cli: cli_argv } => {
            // A whole command line in one argument, split on spaces: the cli
            // takes a config path and a profile, and asking for four flags to
            // pass three of its own would be worse than one string.
            let argv: Option<Vec<String>> = cli_argv
                .as_ref()
                .map(|s| s.split_whitespace().map(str::to_string).collect());
            ops::check(&ctx, argv.as_deref())
        }
        LegacyVerb::Render { .. } => unreachable!("answered above"),
    }
}
