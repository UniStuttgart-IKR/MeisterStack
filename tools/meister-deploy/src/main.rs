// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! `meister-deploy` — the plan, the order, and the evidence.

use std::collections::BTreeSet;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{Context, Result};
use clap::{Args, Parser, Subcommand};

use meister_deploy::effects::{Clock, Files, RealClock, RealFiles};
use meister_deploy::inventory::{self, Inventory};
use meister_deploy::legacy::fleet::Plan;
use meister_deploy::legacy::ops::{self, Ctx};
use meister_deploy::legacy::remote::Ssh;
use meister_deploy::legacy::run::Real as LegacyRunner;
use meister_deploy::manifest::{self, Contract, NixManifest, Tool};
use meister_deploy::run::{Cancel, Policy, Real, Runner};
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
        /// `nix-manifest`, `resolved-fleet` or `check-result`
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
        Verb::Init {
            dir,
            meisterstack,
            dry_run,
        } => init(dir, meisterstack.as_deref(), *dry_run),
        Verb::Inventory { fleet, json } => show_inventory(fleet, *json),
        Verb::Validate {
            fleet,
            manifest,
            nix,
        } => validate(fleet, manifest.as_deref(), *nix),
        Verb::Resolve {
            repo,
            out,
            fleet,
            dev,
            hosts,
            dry_run,
            offline,
        } => resolve(repo, out, fleet, *dev, hosts, *dry_run, *offline),
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
            if only_mine.is_empty() { "nothing".to_string() } else { only_mine.join(", ") },
            if only_theirs.is_empty() { "nothing".to_string() } else { only_theirs.join(", ") },
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
