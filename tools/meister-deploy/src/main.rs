// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! `meister-deploy` — the plan, the order, and the evidence.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{Context, Result};
use clap::{Args, Parser, Subcommand};

use meister_deploy::build;
use meister_deploy::effects::{Clock, Files, RealClock, RealFiles};
use meister_deploy::inventory::{self, Inventory};
use meister_deploy::legacy::fleet::Plan;
use meister_deploy::legacy::ops::{self, Ctx};
use meister_deploy::legacy::remote::Ssh;
use meister_deploy::legacy::run::Real as LegacyRunner;
use meister_deploy::manifest::{self, Contract, NixManifest, Tool};
use meister_deploy::observation::{self, Observations, Targets};
use meister_deploy::observe;
use meister_deploy::plan::{self, PlanKind};
use meister_deploy::readiness;
use meister_deploy::receipt;
use meister_deploy::release::ReleaseManifest;
use meister_deploy::run::{Cancel, Policy, Real, Runner};
use meister_deploy::state::{self, StateDir};
use meister_deploy::transport;
use meister_deploy::{nix, source, template};

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
        /// `nix-manifest`, `resolved-fleet`, `release`, `observation`,
        /// `activate-status`, `targets`, `plan`, `status`, `receipt`,
        /// `journal-event` or `check-result`
        kind: String,
    },

    /// Write a deployment repository: the inventory, the profiles, the
    /// per-host files, the disk layout and the checks. Writes only into an
    /// empty or absent directory, and never touches a MeisterStack checkout.
    Init {
        /// Where the repository goes
        dir: PathBuf,
        /// The `meisterstack` input to write into its flake.nix — a revision
        /// for a deployment that is made twice, a local checkout for a test
        #[arg(long)]
        meisterstack: Option<String>,
        /// List the files and write nothing
        #[arg(long)]
        dry_run: bool,
    },

    /// What the inventory says: the hosts, their groups, and what each one
    /// inherited. Reads one file and asks nobody anything.
    Inventory {
        /// The inventory
        #[arg(short = 'f', long, default_value = "fleet.toml")]
        fleet: PathBuf,
        /// Print it as json instead of as a table
        #[arg(long)]
        json: bool,
    },

    /// Check the inventory, or a contract file, against the types. Reads
    /// nothing else and asks nobody anything.
    Validate {
        /// The inventory
        #[arg(short = 'f', long, default_value = "fleet.toml")]
        fleet: PathBuf,
        /// A `nix-manifest/1` or `resolved-fleet/1` json file, or `-` for
        /// standard input, instead of the inventory
        #[arg(long)]
        manifest: Option<String>,
        /// Also evaluate the operator flake
        #[arg(long)]
        nix: bool,
    },

    /// Evaluate the operator's flake and write the manifest: which host is
    /// what, which system each one will run, and which tree that came from.
    Resolve {
        /// The operator's repository
        #[arg(long, default_value = ".")]
        repo: PathBuf,
        /// Where to write the manifest
        #[arg(short = 'o', long)]
        out: PathBuf,
        /// The inventory, relative to the repository
        #[arg(short = 'f', long, default_value = "fleet.toml")]
        fleet: PathBuf,
        /// Resolve a dirty tree, recording a content snapshot instead of a
        /// revision. The whole working tree is copied into the nix store.
        #[arg(long)]
        dev: bool,
        /// Only these hosts, comma-separated. The result describes that
        /// sub-fleet and nothing else.
        #[arg(long, value_delimiter = ',')]
        hosts: Vec<String>,
        /// Print the command lines that would run, and write nothing
        #[arg(long)]
        dry_run: bool,
        /// Refuse rather than reach outside this process
        #[arg(long)]
        offline: bool,
    },

    /// Realise the derivations the manifest names, sign them, measure them,
    /// and write the release that binds them. Builds no image and asks no
    /// host anything.
    Build(BuildArgs),

    /// Work out which hosts may be taken forward, in which order, and what
    /// has to still be true when it happens. Reads a release and a snapshot
    /// of the fleet; asks no host anything of its own.
    Plan(PlanArgs),

    /// Drop the garbage-collector roots of all but the newest N releases.
    /// Removes no store path: whether a closure goes is `nix store gc`'s
    /// decision.
    Gc {
        /// How many releases keep their roots
        #[arg(long, default_value_t = 3)]
        keep: usize,
        /// The operator's repository, which is where the state directory is
        #[arg(long, default_value = ".")]
        repo: PathBuf,
        /// Say which roots would go, and remove nothing
        #[arg(long)]
        dry_run: bool,
    },

    /// What the fleet looks like right now: one read-only round trip per
    /// host, and the readiness checks drawn from it. Changes nothing.
    Status(LookArgs),

    /// The readiness checks as a verdict: exit 0 when every required check
    /// passed, 2 when one of them did not. Creates no test VM and writes no
    /// etcd key.
    Check {
        #[command(flatten)]
        look: LookArgs,
        /// Which suite. `readiness` is the one that reads; `vm-lifecycle`,
        /// `gpu` and `rdma` do work on the fleet and arrive with `verify`
        /// in M4.
        #[arg(long, default_value = "readiness")]
        suite: String,
    },

    /// What a run did: its journal, folded, and its receipt once it has one.
    /// Reads the state directory and asks no host anything.
    Report {
        /// The run id, as `apply` printed it
        #[arg(long)]
        run: String,
        /// The operator's repository, which is where the state directory is
        #[arg(long, default_value = ".")]
        repo: PathBuf,
        /// Print the receipt as json instead of as a table
        #[arg(long)]
        json: bool,
    },

    /// The tool as it was before v1: the `fleet.toml` of schema 1, the rsync
    /// push to the context fleet, `nixos-rebuild --target-host` for metal.
    /// Kept whole, with the same flags, because twelve VMs are served by it
    /// today and `plan` means something else from v1 on.
    Legacy(LegacyCli),
}

/// What `status` and `check` both need: which fleet, which hosts, where
/// they answer, and whether to ask at all.
#[derive(Args)]
struct LookArgs {
    /// The release to compare against, from `build`
    #[arg(long)]
    release: Option<PathBuf>,

    /// A manifest from `resolve`, when there is no release yet. Then
    /// nothing is compared against a desired system.
    #[arg(long)]
    manifest: Option<PathBuf>,

    /// Which hosts: `all`, `host=<id>`, `group=<g>`, `role=<r>`,
    /// `profile=<p>`, `site=<s>`
    #[arg(long, default_value = "all")]
    select: String,

    /// A `targets/1` file from a provider adapter: where each host answers
    #[arg(long)]
    targets: Option<PathBuf>,

    /// The operator's repository: its `known_hosts` is what every
    /// connection is checked against, and its state directory is where the
    /// snapshot is kept. Defaults to the one the manifest was resolved
    /// from.
    #[arg(long)]
    repo: Option<PathBuf>,

    /// The ssh key to offer. Without it, ssh uses what it is configured
    /// with.
    #[arg(long)]
    identity: Option<PathBuf>,

    /// How many hosts to ask at once
    #[arg(long, default_value_t = observe::DEFAULT_CONCURRENCY)]
    at_once: usize,

    /// Do not ask anybody: answer from the last snapshot in the state
    /// directory
    #[arg(long)]
    offline: bool,

    /// Print the snapshot and the checks as json instead of a table
    #[arg(long)]
    json: bool,
}

#[derive(Args)]
struct BuildArgs {
    /// The manifest from `resolve`
    #[arg(long)]
    manifest: PathBuf,

    /// Where to write the release
    #[arg(short = 'o', long)]
    out: Option<PathBuf>,

    /// Only these hosts, comma-separated. A build of part of a fleet is for
    /// looking at: a release covers every host of its manifest.
    #[arg(long, value_delimiter = ',')]
    host: Vec<String>,

    /// The nix signing key to sign the release with. Without it, the
    /// inventory's `[operator] signing_key` is used.
    #[arg(long)]
    sign_key: Option<PathBuf>,

    /// Remote builders, in the order nix is to be offered them. Repeatable.
    #[arg(long)]
    builders: Vec<String>,

    /// Substituters to build from. Repeatable.
    #[arg(long)]
    substituters: Vec<String>,

    /// The inventory the `[operator] signing_key` reference is read from.
    /// Defaults to the one the manifest was resolved from.
    #[arg(long)]
    inventory: Option<PathBuf>,

    /// The operator's repository, whose state directory keeps the release's
    /// garbage-collector roots. Defaults to the one the manifest was
    /// resolved from — which is a path from ANOTHER machine when the
    /// manifest came from one, and then this is the flag to pass.
    #[arg(long)]
    repo: Option<PathBuf>,

    /// Print the derivations that would be built, and build nothing
    #[arg(long)]
    dry_run: bool,

    /// Refuse rather than reach outside this process
    #[arg(long)]
    offline: bool,
}

#[derive(Args)]
struct PlanArgs {
    /// The release to plan, from `build`
    #[arg(long)]
    release: PathBuf,

    /// Which hosts: `all`, `host=<id>`, `group=<g>`, `role=<r>`,
    /// `profile=<p>`, `site=<s>`; a comma is a union, a leading `!` takes
    /// away
    #[arg(long)]
    select: String,

    /// `upgrade` or `bootstrap`
    #[arg(long, default_value = "upgrade")]
    kind: String,

    /// A `targets/1` file from a provider adapter: where each host answers
    #[arg(long)]
    targets: Option<PathBuf>,

    /// An `observation/1` snapshot of the fleet to plan from. Without it,
    /// the frozen target set is asked — and nothing else is.
    #[arg(long)]
    observation: Option<PathBuf>,

    /// Plan without a snapshot and without writing anything: the result is
    /// provisional and every interrupting step in it is blocked
    #[arg(long)]
    offline: bool,

    /// Ask the hosts, and write nothing at all: no plan file and no
    /// snapshot in the state directory
    #[arg(long)]
    dry_run: bool,

    /// The operator's repository: its `known_hosts` is what the connections
    /// are checked against. Defaults to the one the manifest was resolved
    /// from.
    #[arg(long)]
    repo: Option<PathBuf>,

    /// The ssh key to offer
    #[arg(long)]
    identity: Option<PathBuf>,

    /// How many hosts to ask at once
    #[arg(long, default_value_t = observe::DEFAULT_CONCURRENCY)]
    at_once: usize,

    /// The inventory the `[operator] cli_config` reference is read from.
    /// Defaults to the one the manifest was resolved from.
    #[arg(long)]
    inventory: Option<PathBuf>,

    /// Where to write the plan. Without it the plan goes to standard output.
    #[arg(short = 'o', long)]
    out: Option<PathBuf>,
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

/// What a verb came to, and what the shell is told.
///
/// Three codes and not two: a plan that refuses to interrupt a fleet did not
/// FAIL — it worked, and the answer is no. A script that reads exit 1 for
/// both cannot tell "this tool broke" from "this rollout is not safe right
/// now", and the second one is the answer a rollout exists to give.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Answer {
    /// 0
    Yes,
    /// 1: it did not work.
    No,
    /// 2: it worked, and something in the result may not run.
    Blocked,
}

impl From<bool> for Answer {
    fn from(ok: bool) -> Answer {
        if ok { Answer::Yes } else { Answer::No }
    }
}

fn main() -> ExitCode {
    match run() {
        Ok(Answer::Yes) => ExitCode::SUCCESS,
        Ok(Answer::No) => ExitCode::FAILURE,
        Ok(Answer::Blocked) => ExitCode::from(2),
        Err(e) => {
            // Diagnostics on stderr, always: stdout carries the answer, and
            // `--json` has to stay machine-readable even when it is empty.
            eprintln!("meister-deploy: {e:#}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<Answer> {
    let cli = Cli::parse();
    match &cli.cmd {
        Verb::Schema { kind } => print_schema(kind).map(Answer::from),
        Verb::Init {
            dir,
            meisterstack,
            dry_run,
        } => init(dir, meisterstack.as_deref(), *dry_run).map(Answer::from),
        Verb::Inventory { fleet, json } => show_inventory(fleet, *json).map(Answer::from),
        Verb::Validate {
            fleet,
            manifest,
            nix,
        } => validate(fleet, manifest.as_deref(), *nix).map(Answer::from),
        Verb::Resolve {
            repo,
            out,
            fleet,
            dev,
            hosts,
            dry_run,
            offline,
        } => resolve(repo, out, fleet, *dev, hosts, *dry_run, *offline).map(Answer::from),
        Verb::Build(args) => build(args).map(Answer::from),
        Verb::Status(look) => status(look),
        Verb::Check { look, suite } => check(look, suite),
        Verb::Plan(args) => make_plan(args),
        Verb::Gc {
            keep,
            repo,
            dry_run,
        } => gc(*keep, repo, *dry_run).map(Answer::from),
        Verb::Report { run, repo, json } => report(run, repo, *json).map(Answer::from),
        Verb::Legacy(legacy) => run_legacy(legacy).map(Answer::from),
    }
}

/// The contract objects that have a schema today. The rest — plan, receipt —
/// arrive later in M2, and asking for one now says so rather than printing an
/// empty object.
fn print_schema(kind: &str) -> Result<bool> {
    let schema = match kind {
        "nix-manifest" => schemars::schema_for!(manifest::NixManifest),
        "resolved-fleet" => schemars::schema_for!(manifest::ResolvedFleet),
        "check-result" => schemars::schema_for!(meister_deploy::checks::CheckResult),
        "release" => schemars::schema_for!(meister_deploy::release::ReleaseManifest),
        "observation" => schemars::schema_for!(meister_deploy::observation::Observations),
        "targets" => schemars::schema_for!(meister_deploy::observation::Targets),
        "plan" => schemars::schema_for!(meister_deploy::plan::DeploymentPlan),
        "receipt" => schemars::schema_for!(meister_deploy::receipt::DeploymentReceipt),
        "journal-event" => schemars::schema_for!(meister_deploy::receipt::JournalEvent),
        "status" => schemars::schema_for!(readiness::StatusReport),
        // The contract lane 2C's `meister-activate status --json` answers
        // with, and the second source `observe` merges into an observation.
        "activate-status" => schemars::schema_for!(observe::ActivateStatus),
        other => anyhow::bail!(
            "there is no schema called {other:?}; this tool knows nix-manifest, \
             resolved-fleet, release, observation, activate-status, targets, plan, \
             status, receipt, journal-event and check-result."
        ),
    };
    println!("{}", serde_json::to_string_pretty(&schema)?);
    Ok(true)
}

/// Which binary wrote a manifest. `git_rev` is null unless the build set it —
/// the nix package does, a `cargo build` on somebody's laptop does not, and
/// claiming a revision that was not checked would be worse than saying so.
fn tool() -> Tool {
    Tool {
        name: "meister-deploy".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        git_rev: option_env!("MEISTER_GIT_REV").map(str::to_string),
    }
}

#[allow(clippy::too_many_arguments)]
fn resolve(
    repo: &Path,
    out: &Path,
    fleet: &Path,
    dev: bool,
    hosts: &[String],
    dry_run: bool,
    offline: bool,
) -> Result<bool> {
    if offline {
        anyhow::bail!(
            "resolve needs nix to evaluate the operator flake, and --offline forbids it. \
             There is nothing on disk this verb could answer from: the manifest IS the \
             evaluation."
        );
    }
    // Absolute, because `source.repo_path` in the manifest has to mean the
    // same thing to whoever reads it later.
    let repo = std::path::absolute(repo)
        .with_context(|| format!("{} could not be made absolute", repo.display()))?;
    let selection = if hosts.is_empty() { None } else { Some(hosts) };
    if dry_run {
        for cmd in source::commands(&repo, dev) {
            println!("{}", cmd.described());
        }
        // A dev run evaluates a snapshot directory named after its own
        // content, and that name cannot be known without reading the tree —
        // which a dry run does not do. So the line is printed with the one
        // segment that is not yet decided spelled out as what it is.
        let eval_dir = if dev {
            println!(
                "# would then copy exactly those files to {}",
                source::snapshot_dir(&repo, "<content-hash>").display()
            );
            source::snapshot_dir(&repo, "<content-hash>")
        } else {
            repo.clone()
        };
        println!(
            "{}",
            nix::eval_manifest_cmd(&nix::flake_ref(&eval_dir, dev), selection).line()
        );
        println!("# would write {}", out.display());
        return Ok(true);
    }

    let policy = Policy::real();
    // From here on something can take minutes, and a Ctrl-C has to reach the
    // child rather than leave a `nix eval` behind.
    Cancel::on_sigint()?;
    let runner = Real::new(policy);
    let files = RealFiles::new(policy);

    let tree = source::describe(&runner, &files, &repo, fleet, dev)?;
    let flake_ref = nix::flake_ref(&tree.eval_dir, dev);
    let text = nix::eval_manifest(&runner, &flake_ref, selection)?;
    let evaluated = NixManifest::from_json(&text, &format!("{flake_ref}#{}", nix::MANIFEST_ATTR))?;
    let resolved = manifest::resolve(evaluated, tree.source, tool(), RealClock.now(), selection)?;

    files.write_atomic(out, &resolved.to_json()?, 0o644)?;
    // The id on stdout and nothing else, so that it can be captured; where
    // it went goes to stderr like every other diagnostic.
    println!("{}", resolved.manifest_id);
    eprintln!("==> {}", out.display());
    if resolved.partial {
        eprintln!(
            "note: this manifest covers {} of the fleet's hosts and says so \
             (\"partial\": true). A plan over it is a plan over those hosts.",
            resolved.evaluated_hosts.len()
        );
    }
    if resolved.source.dirty {
        eprintln!(
            "note: this manifest was resolved from a dirty tree. Its fingerprint is \
             {} and nobody can check that tree out again. What nix evaluated is the \
             snapshot in {}.",
            resolved.source.fingerprint,
            tree.eval_dir.display()
        );
    }
    Ok(true)
}

// ---------------------------------------------------------------------------
// status and check
// ---------------------------------------------------------------------------

/// The fleet, the hosts, the snapshot and the verdicts — what both
/// read-only verbs work from.
struct Looked {
    fleet: manifest::ResolvedFleet,
    release: Option<ReleaseManifest>,
    selected: Vec<String>,
    observation: Observations,
    checks: Vec<meister_deploy::checks::CheckResult>,
    /// Where the snapshot was written, for a run that asked.
    written: Option<PathBuf>,
}

/// Look at the fleet: one round trip per host, or the last snapshot on disk.
fn look(args: &LookArgs) -> Result<Looked> {
    let policy = if args.offline {
        Policy::offline()
    } else {
        Policy::real()
    };
    let files = RealFiles::new(policy);

    // A release is the better answer where there is one: it says what each
    // host SHOULD run, and without that a status can only say what is.
    let (fleet, release) = match (&args.release, &args.manifest) {
        (Some(path), _) => {
            let text = files.read_to_string(path)?;
            let release = ReleaseManifest::from_json(&text, &path.display().to_string())?;
            (release.resolved_fleet.clone(), Some(release))
        }
        (None, Some(path)) => {
            let text = files.read_to_string(path)?;
            (
                manifest::ResolvedFleet::from_json(&text, &path.display().to_string())?,
                None,
            )
        }
        (None, None) => anyhow::bail!(
            "this needs to know what the fleet is: pass --release <file> from `build`, or \
             --manifest <file> from `resolve` to look without comparing against a release."
        ),
    };

    let selected = plan::select(&fleet, &args.select)?;
    let repo = args
        .repo
        .clone()
        .unwrap_or_else(|| PathBuf::from(&fleet.source.repo_path));
    let state = StateDir::in_repo(&repo);

    let (observation, written) = if args.offline {
        let snapshot = state.load_latest_observation(&files)?;
        eprintln!(
            "note: nothing was asked of any host. This is the snapshot of {}, and a fleet \
             moves.",
            snapshot.taken_at.to_rfc3339()
        );
        (snapshot, None)
    } else {
        let endpoints = match &args.targets {
            Some(path) => {
                let text = files.read_to_string(path)?;
                let targets = observation::Targets::from_json(&text, &path.display().to_string())?;
                observation::bind_targets(&fleet, &targets, &selected)?
            }
            None => observation::manifest_endpoints(&fleet, &selected)?,
        };
        Cancel::on_sigint()?;
        let runner = Real::new(policy);
        let ssh = transport::Ssh::for_repo(&repo).with_identity(args.identity.clone());
        let prober = observe::SshProber::new(&runner, &ssh);
        let probes: Vec<observe::HostProbe> = selected
            .iter()
            .map(|id| {
                observe::HostProbe::new(
                    transport::Target::from_endpoint(id, &endpoints[id]),
                    observe::ProbeSpec::for_host(&fleet.hosts[id]),
                )
            })
            .collect();
        let snapshot = observe::observe_fleet(&prober, &probes, RealClock.now(), args.at_once)?;
        let path = state.save_observation(&files, &snapshot, None)?;
        (snapshot, Some(path))
    };

    let checks = readiness::readiness_of(&fleet, &selected, &observation, release.as_ref());
    Ok(Looked {
        fleet,
        release,
        selected,
        observation,
        checks,
        written,
    })
}

fn status(args: &LookArgs) -> Result<Answer> {
    let looked = look(args)?;
    if args.json {
        println!("{}", String::from_utf8(report_of(&looked)?.to_json()?)?);
    } else {
        print!("{}", status_table(&looked));
    }
    if let Some(path) = &looked.written {
        eprintln!("==> {}", path.display());
    }
    // `status` reports; it does not judge. A fleet with a failing check is
    // not this verb failing, and `check` is the verb that says so with an
    // exit code.
    Ok(Answer::Yes)
}

fn check(args: &LookArgs, suite: &str) -> Result<Answer> {
    if suite != "readiness" {
        anyhow::bail!(
            "the suite {suite:?} does work on the fleet — it starts guests, it uses \
             hardware — so it is not something `check` does. `check --suite readiness` is \
             what reads; `verify --suite {suite}` arrives with M4 and takes a budget, a \
             deadline and an approval."
        );
    }
    let looked = look(args)?;
    if args.json {
        println!("{}", String::from_utf8(report_of(&looked)?.to_json()?)?);
    } else {
        print!("{}", status_table(&looked));
    }
    if let Some(path) = &looked.written {
        eprintln!("==> {}", path.display());
    }
    match meister_deploy::checks::acceptance(&looked.checks) {
        meister_deploy::checks::Acceptance::Accepted => {
            eprintln!(
                "==> every required check passed on {} host(s).",
                looked.selected.len()
            );
            Ok(Answer::Yes)
        }
        meister_deploy::checks::Acceptance::Blocked { reasons } => {
            for reason in &reasons {
                eprintln!("    blocked: {reason}");
            }
            eprintln!(
                "==> {} required check(s) did not pass. This is not a failure of this tool: \
                 the fleet is not ready.",
                reasons.len()
            );
            Ok(Answer::Blocked)
        }
    }
}

fn report_of(looked: &Looked) -> Result<readiness::StatusReport> {
    Ok(readiness::StatusReport {
        schema: readiness::STATUS_SCHEMA.to_string(),
        release_id: looked.release.as_ref().map(|r| r.release_id.clone()),
        manifest_id: looked.fleet.manifest_id.clone(),
        generated_at: RealClock.now(),
        observation: looked.observation.clone(),
        checks: looked.checks.clone(),
    })
}

/// One line per host, and then every check that did not pass.
fn status_table(looked: &Looked) -> String {
    use meister_deploy::checks::Status;
    let mut out = String::new();
    out.push_str(&format!(
        "==> {} host(s) of the fleet {:?}, as of {}\n",
        looked.selected.len(),
        looked.fleet.fleet.name,
        looked.observation.taken_at.format("%Y-%m-%dT%H:%M:%SZ")
    ));
    // The store path last, and not padded: it is the one column whose
    // width is not this tool's to choose, and a padded one would push
    // every other column out of line.
    out.push_str(&format!(
        "    {:<14} {:<9} {:<6} {:>4}  {:<28} {}\n",
        "HOST", "REACHABLE", "ENROLL", "GEN", "CHECKS", "SYSTEM"
    ));
    for id in &looked.selected {
        let obs = looked.observation.host(id);
        let checks: Vec<&meister_deploy::checks::CheckResult> = looked
            .checks
            .iter()
            .filter(|c| c.subject.host.as_deref() == Some(id.as_str()))
            .collect();
        let count = |status: Status| checks.iter().filter(|c| c.status == status).count();
        let summary = format!(
            "{} pass, {} fail, {} unknown",
            count(Status::Pass),
            count(Status::Fail),
            count(Status::Unknown)
        );
        out.push_str(&format!(
            "    {id:<14} {:<9} {:<6} {:>4}  {:<28} {}\n",
            match obs {
                Some(obs) if obs.reachable => "yes",
                Some(_) => "no",
                None => "-",
            },
            match obs {
                Some(obs) if obs.enrolled => "yes",
                Some(_) => "no",
                None => "-",
            },
            obs.and_then(|o| o.generation)
                .map(|g| g.to_string())
                .unwrap_or_else(|| "-".to_string()),
            summary,
            obs.and_then(|o| o.current_system.as_deref())
                .map(short)
                .unwrap_or("-"),
        ));
    }
    // Then the ones that matter, once each, with what they expected.
    for check in &looked.checks {
        if matches!(check.status, Status::Pass | Status::NotApplicable) {
            continue;
        }
        out.push_str(&format!(
            "    {} {} on {}: {}\n",
            if check.required {
                "REQUIRED"
            } else {
                "optional"
            },
            check.id,
            check.subject.host.as_deref().unwrap_or("the fleet"),
            check.reason
        ));
    }
    out
}

/// Realise what the manifest promised.
fn build(args: &BuildArgs) -> Result<bool> {
    if args.offline {
        anyhow::bail!(
            "build needs nix to realise the manifest's derivations, and --offline forbids \
             it. There is nothing on disk this verb could answer from: the release IS the \
             build."
        );
    }
    let policy = if args.dry_run {
        Policy::dry_run()
    } else {
        Policy::real()
    };
    let files = RealFiles::new(policy);

    let text = files.read_to_string(&args.manifest)?;
    let resolved = manifest::ResolvedFleet::from_json(&text, &args.manifest.display().to_string())?;
    let hosts = if args.host.is_empty() {
        None
    } else {
        Some(args.host.clone())
    };

    if args.dry_run {
        // The list, and nothing else. It is the same list a real run walks,
        // from the same function.
        let selected = hosts
            .clone()
            .unwrap_or_else(|| resolved.evaluated_hosts.clone());
        for drv in build::derivations(&resolved, &selected) {
            println!("{}\t{}", drv.what, drv.drv);
        }
        eprintln!(
            "note: nothing was built and no release was written. A real run realises these \
             derivations, signs them and writes --out."
        );
        return Ok(true);
    }

    // The signing key: `--sign-key` first, then the inventory's reference.
    // Which one it came from is said out loud, because a release signed
    // with the wrong key is a release no host of the fleet takes.
    let (sign_key, note) = match &args.sign_key {
        Some(path) => (Some(path.clone()), None),
        None => signing_key(&files, &resolved, args.inventory.as_deref()),
    };
    if let Some(note) = note {
        eprintln!("note: {note}");
    }

    // From here on something can take hours, and a Ctrl-C has to reach the
    // build rather than leave it running.
    Cancel::on_sigint()?;
    let runner = Real::new(policy).verbose(true);
    let repo = args.repo.clone().unwrap_or_else(|| repo_of(&resolved));
    let state = StateDir::in_repo(&repo);
    let builder = build::Builder {
        runner: &runner,
        files: &files,
        clock: &RealClock,
        options: build::BuildOptions {
            sign_key,
            builders: args.builders.clone(),
            substituters: args.substituters.clone(),
            hosts,
        },
        state: Some(state),
    };
    let built = builder.realise(resolved)?;

    match &args.out {
        Some(path) => {
            files.write_atomic(path, &built.release.to_json()?, 0o644)?;
            println!("{}", built.release.release_id);
            eprintln!("==> {}", path.display());
        }
        // No file: the release itself is the answer, whole, on stdout —
        // the same shape `plan` has.
        None => print!("{}", String::from_utf8(built.release.to_json()?)?),
    }
    for (host, artifacts) in &built.release.artifacts {
        eprintln!(
            "    {host:<14} {} ({} signature(s), closure {} MiB)",
            artifacts.toplevel.store_path,
            artifacts.toplevel.signatures.len(),
            artifacts.toplevel.closure_size / (1024 * 1024)
        );
    }
    if !built.roots.is_empty() {
        eprintln!(
            "    {} garbage-collector root(s) under {}",
            built.roots.len(),
            built
                .roots
                .first()
                .and_then(|p| p.parent())
                .map(|p| p.display().to_string())
                .unwrap_or_default()
        );
    }
    Ok(true)
}

/// Where the manifest was resolved from, as an absolute path.
fn repo_of(resolved: &manifest::ResolvedFleet) -> PathBuf {
    PathBuf::from(&resolved.source.repo_path)
}

/// The `[operator] signing_key` reference, from the inventory the manifest
/// was resolved from.
///
/// Missing is not an error here: `build` itself refuses a managed host
/// without a key, with the sentence that says what to do. This only looks.
fn signing_key(
    files: &dyn Files,
    resolved: &manifest::ResolvedFleet,
    override_path: Option<&Path>,
) -> (Option<PathBuf>, Option<String>) {
    let repo = repo_of(resolved);
    let inventory_path = match override_path {
        Some(path) => path.to_path_buf(),
        None => repo.join(&resolved.source.inventory_path),
    };
    let Ok(text) = files.read_to_string(&inventory_path) else {
        return (None, None);
    };
    let Ok(inventory) = Inventory::parse(&text, &inventory_path.display().to_string()) else {
        return (None, None);
    };
    match inventory
        .operator
        .as_ref()
        .and_then(|operator| operator.signing_key.clone())
    {
        Some(key) => {
            // Relative to the inventory, which is relative to the
            // repository: a key path that only worked from one directory
            // would be a key path that works on one afternoon.
            let path = if Path::new(&key).is_absolute() {
                PathBuf::from(&key)
            } else {
                inventory_path
                    .parent()
                    .map(|dir| dir.join(&key))
                    .unwrap_or_else(|| PathBuf::from(&key))
            };
            (
                Some(path),
                Some(format!(
                    "signing this release with the key `[operator] signing_key` names in {}.",
                    inventory_path.display()
                )),
            )
        }
        None => (None, None),
    }
}

/// Drop the roots of all but the newest N releases.
fn gc(keep: usize, repo: &Path, dry_run: bool) -> Result<bool> {
    let policy = if dry_run {
        Policy::dry_run()
    } else {
        Policy::real()
    };
    let files = RealFiles::new(policy);
    let state = StateDir::in_repo(repo);
    let all = build::roots(&files, &state)?;
    if all.is_empty() {
        eprintln!(
            "note: {} protects no release; there is nothing to remove.",
            state.gcroots_dir().display()
        );
        return Ok(true);
    }
    let (remove, kept) = build::gc_plan(&all, keep);
    for dir in &remove {
        println!(
            "{}\t{} root(s){}",
            dir.release_id,
            dir.links.len(),
            if dry_run { "  (would remove)" } else { "" }
        );
        if !dry_run {
            build::remove_roots(&files, dir)?;
        }
    }
    eprintln!(
        "==> {} release(s) {}, {} kept{}",
        remove.len(),
        if dry_run {
            "would lose their roots"
        } else {
            "unprotected"
        },
        kept.len(),
        if all.iter().any(|r| r.created_at.is_none()) {
            " (a directory with no .created stamp is never removed)"
        } else {
            ""
        }
    );
    eprintln!(
        "note: no store path was removed. Whether an unprotected closure goes is \
         `nix store gc`'s decision, and this tool does not make it."
    );
    Ok(true)
}

fn make_plan(args: &PlanArgs) -> Result<Answer> {
    if args.offline && args.out.is_some() {
        anyhow::bail!(
            "--offline and --out are not both possible. An offline plan is provisional: it \
             was made without asking any host anything, so it is something to read and not \
             something to apply. It goes to standard output."
        );
    }
    let policy = if args.offline {
        Policy::offline()
    } else if args.dry_run {
        Policy::dry_run()
    } else {
        Policy::real()
    };
    let files = RealFiles::new(policy);

    let text = files.read_to_string(&args.release)?;
    let release = ReleaseManifest::from_json(&text, &args.release.display().to_string())?;
    let targets = match &args.targets {
        Some(path) => {
            let text = files.read_to_string(path)?;
            Some(Targets::from_json(&text, &path.display().to_string())?)
        }
        None => None,
    };

    let observation = match (&args.observation, args.offline) {
        // A snapshot somebody else took — `status`, an earlier `plan`, a
        // test. It travels into the plan unchanged.
        (Some(path), _) => {
            let text = files.read_to_string(path)?;
            Observations::from_json(&text, &path.display().to_string())?
        }
        // Nothing was asked, and the plan says so: every interrupting step
        // in it is blocked, because nothing is known about any host.
        (None, true) => Observations::provisional(RealClock.now()),
        // Ask — and ask exactly the hosts this plan is about. A plan over
        // three hosts that probed seventy would be a plan that touched
        // sixty-seven machines nobody asked it to look at.
        (None, false) => {
            let fleet = &release.resolved_fleet;
            let selected = plan::select(fleet, &args.select)?;
            let repo = args
                .repo
                .clone()
                .unwrap_or_else(|| PathBuf::from(&fleet.source.repo_path));
            let endpoints = match &targets {
                Some(targets) => observation::bind_targets(fleet, targets, &selected)?,
                None => observation::manifest_endpoints(fleet, &selected)?,
            };
            Cancel::on_sigint()?;
            let runner = Real::new(policy);
            let ssh = transport::Ssh::for_repo(&repo).with_identity(args.identity.clone());
            let prober = observe::SshProber::new(&runner, &ssh);
            let probes: Vec<observe::HostProbe> = selected
                .iter()
                .map(|id| {
                    observe::HostProbe::new(
                        transport::Target::from_endpoint(id, &endpoints[id]),
                        observe::ProbeSpec::for_host(&fleet.hosts[id]),
                    )
                })
                .collect();
            let snapshot = observe::observe_fleet(&prober, &probes, RealClock.now(), args.at_once)?;
            // Kept before the plan is made, not after: a snapshot is
            // evidence about a moment, and a planner that then refuses
            // (a cycle, a group that cannot afford it) must not take the
            // evidence with it. A dry run keeps nothing.
            if !args.dry_run {
                let state = StateDir::in_repo(&repo);
                let path = state.save_observation(&files, &snapshot, None)?;
                eprintln!("==> {}", path.display());
            }
            snapshot
        }
    };

    let kind = match args.kind.as_str() {
        "upgrade" => PlanKind::Upgrade,
        "bootstrap" => PlanKind::Bootstrap,
        other @ ("install" | "keys-rotate" | "keys-revoke" | "retire") => anyhow::bail!(
            "the plan kind {other:?} is a contract this tool already speaks and a plan it \
             cannot build yet: `install` arrives with M3, `keys-rotate`, `keys-revoke` and \
             `retire` with M5."
        ),
        other => anyhow::bail!(
            "{other:?} is not a plan kind. This tool builds `upgrade` and `bootstrap`."
        ),
    };

    let (control, note) = workload_control(&files, &release, args.inventory.as_deref());
    if let Some(note) = note {
        eprintln!("note: {note}");
    }
    let plan = plan::plan(
        &release,
        &args.select,
        &observation,
        targets.as_ref(),
        &plan::PlanPolicy::new(kind).with_workload_control(control),
        RealClock.now(),
    )?;

    match (&args.out, args.dry_run) {
        (Some(path), false) => {
            files.write_atomic(path, &plan.to_json()?, 0o644)?;
            println!("{}", plan.plan_id);
            eprintln!("==> {}", path.display());
        }
        (Some(path), true) => {
            // The hosts were asked and nothing was written, which is what a
            // dry run of this verb is: the plan is on stdout instead.
            print!("{}", String::from_utf8(plan.to_json()?)?);
            eprintln!(
                "note: {} was not written, and no snapshot was kept.",
                path.display()
            );
        }
        // No file: the plan itself is the answer, whole, on stdout.
        (None, _) => print!("{}", String::from_utf8(plan.to_json()?)?),
    }
    eprint!("{}", plan_summary(&plan));
    Ok(if plan.is_blocked() {
        Answer::Blocked
    } else {
        Answer::Yes
    })
}

/// The `[operator] cli_config` reference D7 needs, from the inventory the
/// manifest was resolved from.
///
/// Missing is an answer and not a failure: without it every interrupting
/// step on an agent is blocked with a sentence that says what to set, which
/// is more useful than refusing to make a plan at all.
fn workload_control(
    files: &dyn Files,
    release: &ReleaseManifest,
    override_path: Option<&Path>,
) -> (Option<plan::WorkloadControl>, Option<String>) {
    let source = &release.resolved_fleet.source;
    let path = match override_path {
        Some(path) => path.to_path_buf(),
        None => Path::new(&source.repo_path).join(&source.inventory_path),
    };
    let Ok(text) = files.read_to_string(&path) else {
        return (
            None,
            Some(format!(
                "{} could not be read, so this plan has no `[operator] cli_config`. Steps \
                 that would interrupt an agent are blocked; pass --inventory <file> to point \
                 at it.",
                path.display()
            )),
        );
    };
    let inventory = match Inventory::parse(&text, &path.display().to_string()) {
        Ok(inventory) => inventory,
        Err(e) => {
            return (
                None,
                Some(format!(
                    "{} is not an inventory this tool reads ({e}), so this plan has no `[operator] cli_config`.",
                    path.display()
                )),
            );
        }
    };
    match inventory.operator.as_ref().and_then(|o| {
        o.cli_config.as_ref().map(|config| plan::WorkloadControl {
            cli_config: config.clone(),
            cli_profile: o.cli_profile.clone(),
        })
    }) {
        Some(control) => (Some(control), None),
        None => (
            None,
            Some(format!(
                "{} has no `[operator] cli_config`, so steps that would interrupt an agent \
                 are blocked.",
                path.display()
            )),
        ),
    }
}

/// What a person reads on stderr while the plan itself goes to stdout.
fn plan_summary(plan: &plan::DeploymentPlan) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "==> {} ({}, {} host(s), {} wave(s))\n",
        plan.plan_id,
        plan.kind,
        plan.selection.targets.len(),
        plan.last_wave() + 1
    ));
    out.push_str(&format!(
        "    {:<14} {:<12} {:>4}  {:<16} {:>5}  {}\n",
        "HOST", "VERDICT", "WAVE", "CLASS", "STEPS", "NOTE"
    ));
    for (id, host) in &plan.hosts {
        let steps = plan.actions_for(id);
        let blocked = steps.iter().filter(|a| a.is_blocked()).count();
        out.push_str(&format!(
            "    {id:<14} {:<12} {:>4}  {:<16} {:>5}  {}\n",
            host.verdict,
            host.wave,
            host.class,
            steps.len(),
            match (blocked, host.reboot_required, host.canary) {
                (0, false, false) => String::new(),
                (0, reboot, canary) => [
                    if reboot { "reboot" } else { "" },
                    if canary { "canary" } else { "" }
                ]
                .iter()
                .filter(|s| !s.is_empty())
                .cloned()
                .collect::<Vec<_>>()
                .join(", "),
                (n, _, _) => format!("{n} blocked"),
            }
        ));
    }
    for (id, group) in &plan.groups {
        if let Some(why) = &group.blocked {
            out.push_str(&format!("    group {id}: {why}\n"));
        }
    }
    // One sentence, however many steps it stopped. A quorum that is gone
    // stops six steps on three hosts, and printing it eighteen times is how
    // the one line that matters gets lost.
    let mut by_reason: BTreeMap<&str, BTreeMap<&str, Vec<&str>>> = BTreeMap::new();
    for action in &plan.actions {
        if let Some(why) = &action.blocked {
            by_reason
                .entry(why.as_str())
                .or_default()
                .entry(action.host.as_str())
                .or_default()
                .push(action.kind.as_str());
        }
    }
    for (reason, hosts) in by_reason {
        out.push_str(&format!("    blocked: {reason}\n"));
        for (host, kinds) in hosts {
            out.push_str(&format!("             {host}: {}\n", kinds.join(", ")));
        }
    }
    for unknown in &plan.unknowns {
        out.push_str(&format!(
            "    unknown: {}{}\n",
            unknown
                .host
                .as_ref()
                .map(|h| format!("{h}: "))
                .unwrap_or_default(),
            unknown.reason
        ));
    }
    if !plan.approvals.is_empty() {
        out.push_str("    needs: ");
        out.push_str(
            &plan
                .approvals
                .iter()
                .map(|a| format!("--approve {}={}", a.class, a.bound_plan_id))
                .collect::<Vec<_>>()
                .join(" "),
        );
        out.push('\n');
    }
    out
}

/// What a run did.
///
/// The journal is the evidence and the receipt is the summary of it, so this
/// prefers the receipt when there is one and folds the journal when there is
/// not — a run that was interrupted has no receipt, and that is exactly the
/// run somebody wants to read. Whatever the journal does not add up to
/// (`breaks`) and a last line that was torn off by a power cut are printed
/// rather than swallowed.
///
/// Exit 0 means a report was produced, whatever it says: a rollout that
/// failed is not this verb failing. Exit 1 means there is nothing here to
/// report.
fn report(run: &str, repo: &Path, json: bool) -> Result<bool> {
    let files = RealFiles::new(Policy::real());
    let state = StateDir::in_repo(repo);

    if !files.exists(&state.run_dir(run)) {
        let known = state.runs(&files)?;
        anyhow::bail!(
            "{} holds no run {run}. {}",
            state.runs_dir().display(),
            if known.is_empty() {
                "There are no runs in it at all.".to_string()
            } else {
                format!(
                    "It holds {}.",
                    known
                        .iter()
                        .rev()
                        .take(5)
                        .cloned()
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            }
        );
    }

    let journal_path = state.journal_path(run);
    let read = if files.exists(&journal_path) {
        Some(state::read_journal(&files, &journal_path)?)
    } else {
        None
    };

    // The receipt, either as it was written or as it would be written right
    // now. The second one is marked: a receipt this verb folded is a report
    // about a run that has not ended.
    let (receipt, finished) = if files.exists(&state.receipt_path(run)) {
        (Some(state.read_receipt(&files, run)?), true)
    } else {
        match (&read, files.exists(&state.plan_copy_path(run))) {
            (Some(read), true) => {
                let text = files.read_to_string(&state.plan_copy_path(run))?;
                let plan = plan::DeploymentPlan::from_json(
                    &text,
                    &state.plan_copy_path(run).display().to_string(),
                )?;
                let folded = receipt::fold(&read.events)?;
                let reference = state::journal_ref(&files, &journal_path)?;
                (
                    Some(receipt::receipt(
                        &plan,
                        &folded,
                        &reference,
                        RealClock.now(),
                    )),
                    false,
                )
            }
            _ => (None, false),
        }
    };

    match (&receipt, json) {
        (Some(receipt), true) => println!("{}", String::from_utf8(receipt.to_json()?)?),
        (Some(receipt), false) => {
            print!("{}", receipt_table(receipt));
            if !finished {
                // On stderr, like every other diagnostic: stdout is the
                // report, and a note about how it was made is not part of
                // it.
                eprintln!(
                    "note: run {run} wrote no receipt of its own, so this one was folded from \
                     its journal just now. The run has not ended."
                );
            }
        }
        (None, _) => {
            // No plan copy, so no receipt can be folded. The journal is
            // still evidence, and printing it is more use than a refusal.
            let Some(read) = &read else {
                anyhow::bail!(
                    "run {run} has neither a journal nor a receipt in {}; there is nothing \
                     to report.",
                    state.run_dir(run).display()
                );
            };
            let folded = receipt::fold(&read.events)?;
            print!("{}", run_state_table(run, &folded));
            eprintln!(
                "note: this run has no copy of its plan in {}, so no receipt could be folded \
                 from it. What is above is the journal.",
                state.run_dir(run).display()
            );
        }
    }

    if let Some(read) = &read
        && let Some(torn) = &read.torn
    {
        eprintln!("note: {torn}");
    }
    Ok(true)
}

/// The receipt as a person reads it.
fn receipt_table(receipt: &receipt::DeploymentReceipt) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "==> run {}  plan {}  release {}\n",
        receipt.run_id, receipt.plan_id, receipt.release_id
    ));
    out.push_str(&format!(
        "    outcome: {}   started {}   ended {}\n",
        receipt.outcome,
        stamp(receipt.started_at),
        stamp(receipt.ended_at),
    ));
    if let Some(operator) = &receipt.operator {
        out.push_str(&format!(
            "    operator: {}@{}\n",
            operator.user, operator.workstation
        ));
    }
    out.push_str(&format!(
        "    {:<14} {:<18} {:<18} {:>7}  {}\n",
        "HOST", "OUTCOME", "STATE", "ACTIONS", "SYSTEM"
    ));
    for (id, host) in &receipt.hosts {
        let system = match (&host.before.system, &host.after.system) {
            (Some(before), Some(after)) if before == after => short(before).to_string(),
            (Some(before), Some(after)) => format!("{} -> {}", short(before), short(after)),
            (Some(before), None) => short(before).to_string(),
            (None, Some(after)) => short(after).to_string(),
            (None, None) => "-".to_string(),
        };
        out.push_str(&format!(
            "    {id:<14} {:<18} {:<18} {:>7}  {system}\n",
            host.outcome,
            host.state,
            host.actions.len()
        ));
    }
    if !receipt.untouched.is_empty() {
        out.push_str(&format!(
            "    untouched: {}\n",
            receipt.untouched.join(", ")
        ));
    }
    for check in &receipt.checks {
        out.push_str(&format!(
            "    check {} on {}: {}\n",
            check.id,
            check
                .subject
                .host
                .as_deref()
                .or(check.subject.resource.as_deref())
                .unwrap_or("the fleet"),
            check.status
        ));
    }
    for break_ in &receipt.breaks {
        out.push_str(&format!("    break: {break_}\n"));
    }
    out.push_str(&format!(
        "    journal: {} (sha256 {})\n",
        receipt.journal_path, receipt.journal_sha256
    ));
    out
}

/// A journal with no plan beside it, as a person reads it.
fn run_state_table(run: &str, state: &receipt::RunState) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "==> run {run}  plan {}  {} line(s)\n",
        state.plan_id, state.last_seq
    ));
    out.push_str(&format!(
        "    {:<14} {:<18} {:>7}  {}\n",
        "HOST", "STATE", "ACTIONS", "OPEN"
    ));
    for (id, host) in &state.hosts {
        out.push_str(&format!(
            "    {id:<14} {:<18} {:>7}  {}\n",
            host.state,
            host.actions.len(),
            host.open_irreversible
                .as_ref()
                .map(|open| format!("{} (seq {})", open.kind, open.seq))
                .unwrap_or_default()
        ));
    }
    for break_ in &state.breaks {
        out.push_str(&format!("    break: {break_}\n"));
    }
    out
}

/// A timestamp as every other line of this tool spells one: UTC, seconds,
/// and a `Z` rather than a `+00:00` that a reader has to translate.
fn stamp(at: Option<chrono::DateTime<chrono::Utc>>) -> String {
    at.map(|t| t.format("%Y-%m-%dT%H:%M:%SZ").to_string())
        .unwrap_or_else(|| "-".to_string())
}

/// The last two segments of a store path: a table of full ones is a table
/// nobody can read, and the hash is in the name.
fn short(store_path: &str) -> &str {
    store_path
        .rsplit_once('/')
        .map(|(_, name)| name)
        .unwrap_or(store_path)
}

fn show_inventory(path: &Path, json: bool) -> Result<bool> {
    let files = RealFiles::new(Policy::real());
    let inventory = Inventory::load(&files, path)?;
    if json {
        println!("{}", serde_json::to_string_pretty(&inventory.report()?)?);
    } else {
        print!("{}", inventory.table()?);
    }
    Ok(true)
}

fn validate(fleet: &Path, manifest: Option<&str>, nix: bool) -> Result<bool> {
    if nix {
        return validate_with_nix(fleet);
    }
    match manifest {
        Some(from) => validate_manifest(from),
        None => {
            let files = RealFiles::new(Policy::real());
            match Inventory::load(&files, fleet) {
                Ok(inventory) => {
                    println!(
                        "ok: {} is a schema {} inventory for the fleet {:?}, {} host(s), \
                         {} group(s)",
                        fleet.display(),
                        inventory.schema,
                        inventory.fleet.name,
                        inventory.hosts.len(),
                        inventory.groups.len()
                    );
                    eprintln!(
                        "note: the shape was checked, not the fleet. No address was \
                         resolved, no host asked, and no deployment value derived — \
                         that is what `resolve` and Nix do."
                    );
                    Ok(true)
                }
                Err(e) => {
                    eprintln!("meister-deploy: {e:#}");
                    Ok(false)
                }
            }
        }
    }
}

/// `validate --nix`: what the inventory says, and what the flake makes of it.
///
/// Two readers, one file (D2). This verb asks the expensive reader — Nix —
/// for the CHEAP half of its answer (`meisterDeployment.inventory`, derived
/// without evaluating a single module) and compares the fleet it describes
/// with the fleet this binary read out of the TOML. What it cannot see is
/// whether a host's system builds; that is `resolve` and then `build`.
fn validate_with_nix(fleet: &Path) -> Result<bool> {
    let fleet = std::path::absolute(fleet)
        .with_context(|| format!("{} could not be made absolute", fleet.display()))?;
    // The repository is the directory the inventory lives in, because that is
    // where its flake is. An inventory somewhere else is a fleet whose
    // deployment repository nobody named.
    let repo = fleet
        .parent()
        .ok_or_else(|| anyhow::anyhow!("{} has no directory to evaluate", fleet.display()))?;

    let policy = Policy::real();
    let files = RealFiles::new(policy);
    let inventory = Inventory::load(&files, &fleet)?;

    Cancel::on_sigint()?;
    let runner = Real::new(policy);
    // `git+file://` and never a bare path or `path:`: what is evaluated is
    // what git tracks, so this verb cannot copy an ignored `keys/` into the
    // store on the way (the fix N1 of lane 1C). The price is that
    // uncommitted changes are not in the answer, and the note below says so.
    let flake_ref = nix::flake_ref(repo, false);
    let text = nix::eval_inventory(&runner, &flake_ref)?;

    let evaluated: manifest::NixInventory = serde_json::from_str(&text).with_context(|| {
        format!(
            "{flake_ref}#{}.inventory is not the shape this tool reads",
            nix::MANIFEST_ATTR
        )
    })?;

    let mine: BTreeSet<&String> = inventory
        .hosts
        .iter()
        .filter(|(_, h)| h.deployment == inventory::Deployment::Nixos)
        .map(|(id, _)| id)
        .collect();
    let theirs: BTreeSet<&String> = evaluated.hosts.keys().collect();
    if mine != theirs {
        let only_mine: Vec<&str> = mine.difference(&theirs).map(|s| s.as_str()).collect();
        let only_theirs: Vec<&str> = theirs.difference(&mine).map(|s| s.as_str()).collect();
        anyhow::bail!(
            "{} and {flake_ref} do not describe the same fleet: {} is in the inventory \
             and not in the flake, {} is in the flake and not in the inventory. A host \
             that only one of the two readers sees is a host nobody deploys.",
            fleet.display(),
            if only_mine.is_empty() {
                "nothing".to_string()
            } else {
                only_mine.join(", ")
            },
            if only_theirs.is_empty() {
                "nothing".to_string()
            } else {
                only_theirs.join(", ")
            },
        );
    }
    if evaluated.fleet.name != inventory.fleet.name {
        anyhow::bail!(
            "the inventory calls this fleet {:?} and the flake calls it {:?}.",
            inventory.fleet.name,
            evaluated.fleet.name
        );
    }

    println!(
        "ok: {} and {flake_ref} describe the fleet {:?}, {} nixos host(s): {}",
        fleet.display(),
        evaluated.fleet.name,
        theirs.len(),
        theirs
            .iter()
            .map(|s| s.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    );
    eprintln!(
        "note: the flake was evaluated as git sees it, so uncommitted changes are not in \
         this answer. What was compared is the inventory half of `meisterDeployment` — \
         the hosts and the fleet's name — and not whether their systems build; that is \
         `resolve` and `build`."
    );
    Ok(true)
}

/// `init <dir>`: the repository a deployment starts from.
///
/// Writes once, into an empty or absent directory, and never into a
/// MeisterStack checkout: the files come out of this binary
/// (`crate::template`), so the verb works offline and the template is the one
/// this version was built with.
fn init(dir: &Path, flake_ref: Option<&str>, dry_run: bool) -> Result<bool> {
    let dir = std::path::absolute(dir)
        .with_context(|| format!("{} could not be made absolute", dir.display()))?;

    if dry_run {
        // The list, and not a word about having written anything.
        for file in template::FILES {
            println!("{}", dir.join(file.path).display());
        }
        println!("{}", dir.join(".meister-deploy").display());
        eprintln!(
            "note: --dry-run wrote nothing. {} file(s) and one directory would be created; \
             `nix flake lock` would then be run in {}.",
            template::FILES.len(),
            dir.display()
        );
        return Ok(true);
    }

    let policy = Policy::real();
    let files = RealFiles::new(policy);

    // An empty or absent directory, and nothing else. A repository somebody
    // already has is a repository this verb must not write into — there is
    // no merge here, and the files it writes are the ones an operator edits.
    if files.exists(&dir) {
        let existing = files.list_dir(&dir)?;
        if !existing.is_empty() {
            anyhow::bail!(
                "{} is not empty ({} entries, e.g. {}). `init` writes a whole repository \
                 and merges with nothing: give it a new directory, or empty this one.",
                dir.display(),
                existing.len(),
                existing
                    .iter()
                    .take(3)
                    .map(|p| p
                        .file_name()
                        .map(|n| n.to_string_lossy().into_owned())
                        .unwrap_or_default())
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }
    }

    // The one file that is not copied verbatim: the flake reference of the
    // `meisterstack` input.
    let reference = flake_ref.unwrap_or(template::DEFAULT_FLAKE_REF);
    for file in template::FILES {
        let path = dir.join(file.path);
        if let Some(parent) = path.parent() {
            files.create_dir_all(parent)?;
        }
        let body = if file.path == "flake.nix" {
            template::with_flake_ref(file.body, reference)
        } else {
            file.body.to_string()
        };
        files.write_atomic(&path, body.as_bytes(), file.mode)?;
        println!("{}", path.display());
    }
    // The state directory, so that the first `resolve` has somewhere to put
    // its snapshot and its journal. It is in the template's .gitignore.
    let state = dir.join(".meister-deploy");
    files.create_dir_all(&state)?;
    println!("{}", state.display());

    // The lock file, and ONLY through nix. Writing one by hand would be
    // claiming a set of revisions nobody resolved.
    let runner = Real::new(policy);
    match runner.run(&nix::flake_lock_cmd(&dir)) {
        Ok(_) => println!("{}", dir.join("flake.lock").display()),
        Err(e) => eprintln!(
            "note: `nix flake lock` in {} did not run ({e}). The repository is complete \
             except for flake.lock; run `nix flake lock` there before the first build. \
             This tool does not write a lock file itself, because a lock file it made up \
             would name revisions nobody resolved.",
            dir.display()
        ),
    }

    eprintln!(
        "==> {}\n    1. a signing key, whose public half every host of this fleet trusts:\n\
         \x20      nix-store --generate-binary-cache-key {} keys/signing.sec signing.pub\n\
         \x20   2. git init && git add -A   (a flake sees only what git tracks)\n\
         \x20   3. edit fleet.toml, then: nix flake check\n\
         \x20   4. meister-deploy resolve --repo . --out manifest.json",
        dir.display(),
        dir.file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "my-fleet".to_string())
    );
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
    let runner = LegacyRunner {
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
