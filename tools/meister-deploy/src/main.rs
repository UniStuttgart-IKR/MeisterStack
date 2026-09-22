// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! `meister-deploy` — the plan, the order, and the evidence.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{Context, Result};
use clap::{Args, Parser, Subcommand};

use meister_deploy::effects::{Clock, Files, RealClock, RealFiles};
use meister_deploy::inventory::Inventory;
use meister_deploy::legacy::fleet::Plan;
use meister_deploy::legacy::ops::{self, Ctx};
use meister_deploy::legacy::remote::Ssh;
use meister_deploy::legacy::run::Real as LegacyRunner;
use meister_deploy::manifest::{self, Contract, NixManifest, Tool};
use meister_deploy::observation::{Observations, Targets};
use meister_deploy::plan::{self, PlanKind};
use meister_deploy::release::ReleaseManifest;
use meister_deploy::run::{Cancel, Policy, Real};
use meister_deploy::{nix, source};

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
        /// `targets`, `plan`, `receipt`, `journal-event` or `check-result`
        kind: String,
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

    /// Work out which hosts may be taken forward, in which order, and what
    /// has to still be true when it happens. Reads a release and a snapshot
    /// of the fleet; asks no host anything of its own.
    Plan(PlanArgs),

    /// The tool as it was before v1: the `fleet.toml` of schema 1, the rsync
    /// push to the context fleet, `nixos-rebuild --target-host` for metal.
    /// Kept whole, with the same flags, because twelve VMs are served by it
    /// today and `plan` means something else from v1 on.
    Legacy(LegacyCli),
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

    /// An `observation/1` snapshot of the fleet to plan from
    #[arg(long)]
    observation: Option<PathBuf>,

    /// Plan without a snapshot and without writing anything: the result is
    /// provisional and every interrupting step in it is blocked
    #[arg(long)]
    offline: bool,

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
        Verb::Plan(args) => make_plan(args),
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
        other => anyhow::bail!(
            "there is no schema called {other:?}; this tool knows nix-manifest, \
             resolved-fleet, release, observation, targets, plan, receipt, \
             journal-event and check-result."
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

fn make_plan(args: &PlanArgs) -> Result<Answer> {
    if args.offline && args.out.is_some() {
        anyhow::bail!(
            "--offline and --out are not both possible. An offline plan is provisional: it \
             was made without asking any host anything, so it is something to read and not \
             something to apply. It goes to standard output."
        );
    }
    if !args.offline && args.observation.is_none() {
        // Not a silent success and not an empty plan: taking a snapshot of
        // a fleet is lane 2A's, and saying so is the only honest answer.
        anyhow::bail!(
            "plan needs to know what the fleet is running. Pass a snapshot with \
             --observation <file>, or --offline for a provisional plan that asks nobody \
             anything. Taking the snapshot itself arrives with lane 2A."
        );
    }

    let policy = if args.offline {
        Policy::offline()
    } else {
        Policy::real()
    };
    let files = RealFiles::new(policy);

    let text = files.read_to_string(&args.release)?;
    let release = ReleaseManifest::from_json(&text, &args.release.display().to_string())?;

    let observation = match &args.observation {
        Some(path) => {
            let text = files.read_to_string(path)?;
            Observations::from_json(&text, &path.display().to_string())?
        }
        None => Observations::provisional(RealClock.now()),
    };
    let targets = match &args.targets {
        Some(path) => {
            let text = files.read_to_string(path)?;
            Some(Targets::from_json(&text, &path.display().to_string())?)
        }
        None => None,
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

    match &args.out {
        Some(path) => {
            files.write_atomic(path, &plan.to_json()?, 0o644)?;
            println!("{}", plan.plan_id);
            eprintln!("==> {}", path.display());
        }
        // No file: the plan itself is the answer, whole, on stdout.
        None => print!("{}", String::from_utf8(plan.to_json()?)?),
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
    for (id, host) in &plan.hosts {
        let steps = plan.actions_for(id);
        let blocked = steps.iter().filter(|a| a.is_blocked()).count();
        out.push_str(&format!(
            "    {id:<16} {:<12} wave {:<3} {:<24} {} step(s){}\n",
            host.verdict,
            host.wave,
            host.class,
            steps.len(),
            if blocked > 0 {
                format!(", {blocked} blocked")
            } else if host.reboot_required {
                ", reboot".to_string()
            } else {
                String::new()
            }
        ));
    }
    for (id, group) in &plan.groups {
        if let Some(why) = &group.blocked {
            out.push_str(&format!("    group {id}: {why}\n"));
        }
    }
    for reason in plan.blocked_reasons() {
        out.push_str(&format!("    blocked: {reason}\n"));
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
        // Not a silent success and not a silent skip: the flake half of
        // this verb is lane 1B's, and saying so is the only honest answer
        // this binary can give today.
        anyhow::bail!(
            "--nix needs the operator flake and its `meisterDeployment` attribute, \
             which arrives with lane 1B. Without it, `validate` checks the inventory \
             and `validate --manifest <file>` checks a contract object."
        );
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
