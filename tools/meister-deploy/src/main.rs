// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Fleet deployment CLI: resolve, build, plan, apply and inspect evidence.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{Context, Result};
use clap::{Args, Parser, Subcommand};

use meister_deploy::build;
use meister_deploy::effects::{Clock, Files, RealClock, RealFiles};
use meister_deploy::execute;
use meister_deploy::inventory::{self, Inventory};
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
    /// Print the JSON Schema for a deployment contract.
    Schema {
        /// Contract name: nix-manifest, resolved-fleet, release, observation,
        /// activate-status, targets, plan, status, receipt, journal-event,
        /// check-result, verify or verify-ledger.
        kind: String,
    },

    /// Write the embedded template into an empty directory; attempt nix flake lock.
    Init {
        /// Where the repository goes
        dir: PathBuf,
        /// MeisterStack flake reference. Pin a revision for repeatable deployments.
        #[arg(long)]
        meisterstack: Option<String>,
        /// List the files and write nothing
        #[arg(long)]
        dry_run: bool,
    },

    /// List inventory hosts, groups and inherited settings without probing hosts.
    Inventory {
        /// The inventory
        #[arg(short = 'f', long, default_value = "fleet.toml")]
        fleet: PathBuf,
        /// Print it as json instead of as a table
        #[arg(long)]
        json: bool,
    },

    /// Validate an inventory or contract file; optionally compare Nix inventory.
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

    /// Resolve the operator flake into a source-bound fleet manifest.
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
        /// Read a nix-manifest/1 file instead of evaluating Nix. Source identity
        /// still comes from --repo; the supplied evaluation is recorded separately.
        #[arg(long)]
        from: Option<PathBuf>,
        /// Resolve a dirty tree through a content-addressed source snapshot.
        #[arg(long)]
        dev: bool,
        /// Resolve only these comma-separated hosts; mark the manifest partial.
        #[arg(long, value_delimiter = ',')]
        hosts: Vec<String>,
        /// Print the command lines that would run, and write nothing
        #[arg(long)]
        dry_run: bool,
        /// Refuse rather than reach outside this process
        #[arg(long)]
        offline: bool,
    },

    /// Build and measure manifest derivations, sign closures, and write a release.
    Build(BuildArgs),

    /// Build one host's installer ISO, disk image or direct-boot bundle from a release.
    Image(ImageArgs),

    /// Build and retain installer media for an approved installation plan.
    /// Disk formatting requires meister-install confirm on the target.
    Install(InstallArgs),
    /// Plan rollout actions and waves from a release and host observations.
    Plan(PlanArgs),

    /// Remove old release roots and optionally observations or completed runs.
    /// Does not run Nix store garbage collection.
    Gc {
        /// How many releases keep their roots
        #[arg(long, default_value_t = state::DEFAULT_KEEP_RELEASES)]
        keep: usize,
        /// Minimum age in days before removal, in addition to retention counts.
        #[arg(long, value_name = "DAYS")]
        older_than: Option<i64>,
        /// Keep the newest N observations; always retain latest.json.
        #[arg(long, value_name = "N")]
        observations: Option<usize>,
        /// Remove eligible successful runs with receipts; retain incomplete evidence.
        #[arg(long)]
        runs: bool,
        /// The operator's repository, which is where the state directory is
        #[arg(long, default_value = ".")]
        repo: PathBuf,
        /// Say what would go, and remove nothing
        #[arg(long)]
        dry_run: bool,
    },

    /// Probe hosts and report readiness; save the observation locally.
    Status(LookArgs),

    /// Run readiness checks: exit 0 when required checks pass, otherwise 2.
    Check {
        #[command(flatten)]
        look: LookArgs,
        /// Readiness only. Workload and hardware suites use verify.
        #[arg(long, default_value = "readiness")]
        suite: String,
    },

    /// Execute an approved plan, recording actions in a journal and receipt.
    Apply(ApplyArgs),

    /// Read a run's receipt, verification result or folded journal.
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

    /// Run workload or fabric verification with a cleanup ledger.
    Verify(VerifyArgs),
    /// Enroll SSH host keys and prepare certificates. Apply delivers public credentials.
    Keys {
        #[command(subcommand)]
        cmd: KeysCmd,
    },

    /// Revoke recorded active credentials and plan CRL delivery to remaining hosts.
    /// Retains target data, known_hosts entries and inventory; remove inventory entries manually.
    Retire {
        /// The host id, as the inventory and the release spell it
        host: String,
        /// The release the delivery plan is made from
        #[arg(long)]
        release: PathBuf,
        /// Retirement note for the record and known_hosts; separate from --crl-reason.
        #[arg(long)]
        reason: Option<String>,
        /// OpenSSL revocation reason; defaults to cessationOfOperation.
        #[arg(long)]
        crl_reason: Option<String>,
        /// The operator's repository
        #[arg(long, default_value = ".")]
        repo: PathBuf,
        /// The inventory the `[operator] ca_dir` reference is read from
        #[arg(long)]
        inventory: Option<PathBuf>,
        /// `tools/meister-ca`. Looked up on PATH when it is a bare name.
        #[arg(long, default_value = "meister-ca")]
        meister_ca: PathBuf,
        /// The ssh key to offer while the remaining hosts are asked
        #[arg(long)]
        identity: Option<PathBuf>,
        /// Where the delivery plan goes
        #[arg(short = 'o', long)]
        out: Option<PathBuf>,
        /// Say what would be taken back and take nothing back
        #[arg(long)]
        dry_run: bool,
        /// Print the result as json
        #[arg(long)]
        json: bool,
    },
}


#[derive(Subcommand)]
enum KeysCmd {
    /// Enroll an SSH key after matching a fingerprint verified through the host console
    /// or another trusted channel. ssh-keyscan alone does not authenticate the host.
    Enroll {
        /// The host id, as the inventory spells it
        host: String,
        /// `SHA256:…`, read off the console of the machine you mean
        #[arg(long)]
        fingerprint: String,
        /// Replace a key this fleet already has for that host
        #[arg(long)]
        replace: bool,
        /// Why — written into `known_hosts` above the new line
        #[arg(long)]
        reason: Option<String>,
        /// Repository containing known_hosts and the host inventory.
        #[arg(long, default_value = ".")]
        repo: PathBuf,
        /// The inventory, relative to the repository or absolute
        #[arg(short = 'f', long, default_value = "fleet.toml")]
        fleet: PathBuf,
        /// Optional resolved manifest; otherwise read the host from the inventory.
        #[arg(long)]
        manifest: Option<PathBuf>,
        /// Ask the host, and write nothing
        #[arg(long)]
        dry_run: bool,
        /// Refuse rather than reach outside this process
        #[arg(long)]
        offline: bool,
        /// Print the result as json
        #[arg(long)]
        json: bool,
    },

    /// Generate or reuse a target-local key and save its CSR under pki/csr/.
    /// The private key remains on the target.
    Csr {
        /// The host id
        #[arg(long)]
        host: String,
        /// Which key: `identity` (what the host dials with) or `serving`
        /// (what a client checks its address against)
        #[arg(long, default_value = "identity")]
        kind: String,
        /// Identity role for a multi-role host: node, cluster or cloud.
        /// Selects one identity; does not provision separate per-role keys.
        #[arg(long = "as", value_name = "KIND")]
        as_kind: Option<String>,
        /// Replace the target key for an intentional rotation or reinstall.
        #[arg(long)]
        replace: bool,
        /// The manifest from `resolve`: it says where the host is and what
        /// its subject would be
        #[arg(long)]
        manifest: PathBuf,
        /// Repository for SSH trust and saved certificate requests.
        #[arg(long, default_value = ".")]
        repo: PathBuf,
        /// The ssh key to offer
        #[arg(long)]
        identity: Option<PathBuf>,
        /// Print the command line and change nothing
        #[arg(long)]
        dry_run: bool,
        /// Print the result as json
        #[arg(long)]
        json: bool,
    },

    /// Sign a CSR locally using the fleet-derived subject.
    /// The CA key stays outside the repository and is never delivered to hosts.
    Issue {
        /// The host the certificate is for
        #[arg(long)]
        host: String,
        /// node | cluster | cloud | serving
        #[arg(long)]
        kind: String,
        /// CSR file, or - for stdin. Defaults to the request saved by keys csr.
        #[arg(long)]
        csr: Option<String>,
        /// Extra serving-certificate SANs, comma-separated; host name and management address
        /// are included automatically.
        #[arg(long)]
        san: Vec<String>,
        /// How long the certificate is good for
        #[arg(long)]
        days: Option<u32>,
        #[arg(long)]
        manifest: PathBuf,
        #[arg(long, default_value = ".")]
        repo: PathBuf,
        /// The inventory the `[operator] ca_dir` reference is read from.
        /// Defaults to the one the manifest was resolved from.
        #[arg(long)]
        inventory: Option<PathBuf>,
        /// `tools/meister-ca`. Looked up on PATH when it is a bare name.
        #[arg(long, default_value = "meister-ca")]
        meister_ca: PathBuf,
        /// Print what would be signed and sign nothing
        #[arg(long)]
        dry_run: bool,
        /// Print the result as json
        #[arg(long)]
        json: bool,
    },

    /// Revoke locally, publish the CRL, and plan delivery. Apply is required
    /// for hosts to receive the new revocation list.
    Revoke {
        /// Certificate serial in OpenSSL or colon-separated form.
        #[arg(long)]
        serial: Option<String>,
        /// Revoke recorded active identity and serving certificates.
        /// Revoke .prev/.next rotation certificates separately by --serial.
        #[arg(long)]
        host: Option<String>,
        /// Refresh the CRL without revoking another certificate.
        #[arg(long)]
        refresh: bool,
        /// OpenSSL revocation reason; defaults to unspecified.
        #[arg(long)]
        crl_reason: Option<String>,
        /// The release the delivery plan is made from
        #[arg(long)]
        release: PathBuf,
        /// Hosts receiving the CRL; defaults to all.
        #[arg(long, default_value = "all")]
        select: String,
        /// The operator's repository
        #[arg(long, default_value = ".")]
        repo: PathBuf,
        /// The inventory the `[operator] ca_dir` reference is read from
        #[arg(long)]
        inventory: Option<PathBuf>,
        /// `tools/meister-ca`. Looked up on PATH when it is a bare name.
        #[arg(long, default_value = "meister-ca")]
        meister_ca: PathBuf,
        /// The ssh key to offer while the hosts are asked
        #[arg(long)]
        identity: Option<PathBuf>,
        /// Where the delivery plan goes
        #[arg(short = 'o', long)]
        out: Option<PathBuf>,
        /// Print what would be revoked and revoke nothing
        #[arg(long)]
        dry_run: bool,
        /// Print the result as json
        #[arg(long)]
        json: bool,
    },
    /// Prepare a new target key and locally signed certificate, then write a rotation plan.
    /// Apply performs the switch and cleanup; preparation already changes key files.
    Rotate {
        /// The host id
        #[arg(long)]
        host: String,
        /// Which key: `identity` (what this host dials with) or `serving`
        /// (what a client checks its address against)
        #[arg(long, default_value = "identity")]
        kind: String,
        /// Identity role for a multi-role host: node, cluster or cloud.
        /// Selects one identity; does not provision separate per-role keys.
        #[arg(long = "as", value_name = "KIND")]
        as_kind: Option<String>,
        /// How long the new certificate is good for
        #[arg(long)]
        days: Option<u32>,
        /// The release the plan is made from
        #[arg(long)]
        release: PathBuf,
        /// The operator's repository
        #[arg(long, default_value = ".")]
        repo: PathBuf,
        /// The inventory the `[operator] ca_dir` reference is read from
        #[arg(long)]
        inventory: Option<PathBuf>,
        /// `tools/meister-ca`. Looked up on PATH when it is a bare name.
        #[arg(long, default_value = "meister-ca")]
        meister_ca: PathBuf,
        /// The ssh key to offer
        #[arg(long)]
        identity: Option<PathBuf>,
        /// Where the plan goes
        #[arg(short = 'o', long)]
        out: Option<PathBuf>,
        /// Print what would be done and do none of it
        #[arg(long)]
        dry_run: bool,
        /// Print the result as json
        #[arg(long)]
        json: bool,
    },

    /// Import explicitly mapped public certificates for deployment and revocation.
    /// Private keys are not read or copied.
    Import {
        /// The directory the certificates are in
        #[arg(long)]
        from: PathBuf,
        /// Host ID and certificate filename without .crt, as HOST=STEM.
        #[arg(long = "map", value_name = "HOST=STEM")]
        map: Vec<String>,
        /// Resolved manifest used to check imported certificate subjects.
        #[arg(long)]
        manifest: PathBuf,
        /// The operator's repository, where the certificates land
        #[arg(long, default_value = ".")]
        repo: PathBuf,
        /// The inventory the `[operator] ca_dir` reference is read from
        #[arg(long)]
        inventory: Option<PathBuf>,
        /// `tools/meister-ca`. Looked up on PATH when it is a bare name.
        #[arg(long, default_value = "meister-ca")]
        meister_ca: PathBuf,
        /// Say what would be imported and import nothing
        #[arg(long)]
        dry_run: bool,
        /// Print the result as json
        #[arg(long)]
        json: bool,
    },
}

/// Shared host selection and observation options for status and check.
#[derive(Args)]
struct LookArgs {
    /// The release to compare against, from `build`
    #[arg(long)]
    release: Option<PathBuf>,

    /// Inspect a resolved fleet without comparing it against a built release.
    #[arg(long)]
    manifest: Option<PathBuf>,

    /// Which hosts: `all`, `host=<id>`, `group=<g>`, `role=<r>`,
    /// `profile=<p>`, `site=<s>`
    #[arg(long, default_value = "all")]
    select: String,

    /// A `targets/1` file from a provider adapter: where each host answers
    #[arg(long)]
    targets: Option<PathBuf>,

    /// Repository for SSH trust and saved observations; defaults to source.repo_path.
    #[arg(long)]
    repo: Option<PathBuf>,

    /// The ssh key to offer. Without it, ssh uses what it is configured
    /// with.
    #[arg(long)]
    identity: Option<PathBuf>,

    /// Inventory used to identify hosts no longer managed and locate operator references.
    #[arg(long)]
    inventory: Option<PathBuf>,
    /// How many hosts to ask at once
    #[arg(long, default_value_t = observe::DEFAULT_CONCURRENCY)]
    at_once: usize,

    /// Read the last saved observation without probing hosts.
    #[arg(long)]
    offline: bool,

    /// Print the snapshot and the checks as json instead of a table
    #[arg(long)]
    json: bool,
}


#[derive(Args)]
struct VerifyArgs {
    /// The release to verify, from `build`
    #[arg(long)]
    release: PathBuf,

    /// `vm-lifecycle`, `gpu` or `rdma`
    #[arg(long)]
    suite: String,

    /// Which hosts: `all`, `host=<id>`, `group=<g>`, `role=<r>`,
    /// `profile=<p>`, `site=<s>`
    #[arg(long, default_value = "all")]
    select: String,

    /// One host, as shorthand for `--select host=<id>`. Repeatable.
    #[arg(long)]
    host: Vec<String>,

    /// RDMA server:client host pair, repeatable. Defaults to declared selected pairs.
    #[arg(long)]
    pairs: Vec<String>,

    /// How long ONE fabric measurement may take, in seconds.
    #[arg(long, default_value_t = meister_deploy::verify::FABRIC_DEADLINE.as_secs())]
    fabric_deadline: u64,

    /// Approve test workload creation with verify=<release_id>, bound to this release.
    #[arg(long)]
    approve: Vec<String>,

    /// Concurrent batch size; an initial guest is also retained, giving 1 + budget per host.
    #[arg(long, default_value_t = meister_deploy::verify::BUDGET)]
    budget: usize,

    /// Run deadline in seconds; expiry aborts and attempts cleanup.
    #[arg(long, default_value_t = meister_deploy::verify::DEADLINE.as_secs())]
    deadline: u64,

    /// Per-guest phase deadline in seconds, including control-plane response time.
    #[arg(long, default_value_t = meister_deploy::verify::SETTLE.as_secs())]
    settle: u64,

    /// How often to ask, in seconds, while waiting.
    #[arg(long, default_value_t = meister_deploy::verify::POLL.as_secs())]
    poll: u64,

    /// Retain test guests. Skipped deletion prevents required lifecycle checks from passing.
    #[arg(long)]
    keep: bool,

    /// A `targets/1` file from a provider adapter: where each host answers
    #[arg(long)]
    targets: Option<PathBuf>,

    /// A snapshot from `status`, instead of asking the hosts again
    #[arg(long)]
    observation: Option<PathBuf>,

    /// Repository for SSH trust and verification evidence; defaults to source.repo_path.
    #[arg(long)]
    repo: Option<PathBuf>,

    /// The inventory the `[operator] cli_config` reference is read from.
    /// Defaults to the one the manifest was resolved from.
    #[arg(long)]
    inventory: Option<PathBuf>,

    /// The ssh key to offer when the hosts are asked what they are.
    #[arg(long)]
    identity: Option<PathBuf>,

    /// How many hosts to ask at once
    #[arg(long, default_value_t = observe::DEFAULT_CONCURRENCY)]
    at_once: usize,

    /// List the steps and create nothing
    #[arg(long)]
    dry_run: bool,

    /// Refused: a verification is work on the fleet
    #[arg(long)]
    offline: bool,

    /// Print the verification as json instead of as a table
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

    /// Build only selected hosts. A complete release still requires every manifest host.
    #[arg(long, value_delimiter = ',')]
    host: Vec<String>,

    /// Closure signing key; otherwise use [operator] signing_key.
    #[arg(long)]
    sign_key: Option<PathBuf>,

    /// Remote builders, in the order nix is to be offered them. Repeatable.
    #[arg(long)]
    builders: Vec<String>,

    /// Substituters to build from. Repeatable.
    #[arg(long)]
    substituters: Vec<String>,

    /// Nix max-jobs value, e.g. a number or auto; recorded in the release.
    #[arg(long)]
    max_jobs: Option<String>,

    /// A nix setting with no flag of its own: `--option <name> <value>`.
    /// Repeatable, recorded in the release.
    #[arg(long, num_args = 2, value_names = ["NAME", "VALUE"])]
    option: Vec<String>,

    /// Push signed closures to this Nix store URL. Hosts must separately configure
    /// the URL in meisterstack.managed.substituters.
    #[arg(long)]
    cache: Option<String>,

    /// Rebuild systems with Nix reproducibility checks; record the measured result.
    #[arg(long)]
    verify_reproducible: bool,
    /// The inventory the `[operator] signing_key` reference is read from.
    /// Defaults to the one the manifest was resolved from.
    #[arg(long)]
    inventory: Option<PathBuf>,

    /// Repository for release roots; override source.repo_path when using another workstation.
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
struct ImageArgs {
    /// The release from `build`
    #[arg(long)]
    release: PathBuf,

    /// Which host's medium
    #[arg(long)]
    host: String,

    /// `installer`, `disk` or `direct-boot`
    #[arg(long)]
    kind: String,

    /// Link the host-specific image into this directory.
    #[arg(short = 'o', long)]
    out: Option<PathBuf>,

    /// Repository for media roots; defaults to source.repo_path.
    #[arg(long)]
    repo: Option<PathBuf>,

    /// Print the command line that would build it, and build nothing
    #[arg(long)]
    dry_run: bool,

    /// Refuse rather than reach outside this process
    #[arg(long)]
    offline: bool,

    /// Print the result as json instead of as lines
    #[arg(long)]
    json: bool,
}
#[derive(Args)]
struct InstallArgs {
    /// The plan from `plan --kind install`
    #[arg(long)]
    plan: PathBuf,

    /// Release matching the installation plan; determines the media derivation.
    #[arg(long)]
    release: PathBuf,

    /// Which host's medium
    #[arg(long)]
    host: String,

    /// Approve installation media creation with destructive=<plan_id>.
    #[arg(long = "approve")]
    approve: Vec<String>,

    /// Link the medium here as well, for writing to a stick
    #[arg(short = 'o', long)]
    out: Option<PathBuf>,

    /// Repository for media records and roots; defaults to source.repo_path.
    #[arg(long)]
    repo: Option<PathBuf>,

    /// Print the sheet and build nothing
    #[arg(long)]
    dry_run: bool,

    /// Refuse rather than reach outside this process
    #[arg(long)]
    offline: bool,

    /// Print the media record as json instead of the sheet
    #[arg(long)]
    json: bool,
}

#[derive(Args)]
struct ApplyArgs {
    /// Plan file; --resume can use the run's saved copy.
    #[arg(long)]
    plan: Option<PathBuf>,

    /// Matching release file; --resume can use the run's saved copy.
    #[arg(long)]
    release: Option<PathBuf>,

    /// Approval bound to this plan ID; repeat for each required class.
    #[arg(long = "approve")]
    approve: Vec<String>,

    /// Resume from the journal and fresh host observations. Preserve the run's saved plan and release.
    #[arg(long)]
    resume: Option<String>,

    /// Explicitly take over the named run's locks; elapsed time alone is not ownership evidence.
    #[arg(long)]
    takeover: Option<String>,

    /// Repository for SSH trust and run evidence; defaults to source.repo_path.
    #[arg(long)]
    repo: Option<PathBuf>,

    /// The ssh key to offer
    #[arg(long)]
    identity: Option<PathBuf>,

    /// Inventory containing the operator CLI configuration reference.
    #[arg(long)]
    inventory: Option<PathBuf>,

    /// How long to wait for a host to be empty of guests, in seconds
    #[arg(long, default_value_t = 600)]
    drain_wait: u64,

    /// How long to wait for a host to come back from a reboot, in seconds
    #[arg(long, default_value_t = 600)]
    reboot_wait: u64,

    /// Reprobe and validate the plan without locks, copies or a run journal.
    #[arg(long)]
    dry_run: bool,

    /// Print one receipt JSON document, including run_id and any waiting/stopped state.
    #[arg(long)]
    json: bool,
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

    /// Plan kind: upgrade, bootstrap, install, keys-revoke or retire.
    #[arg(long, default_value = "upgrade")]
    kind: String,

    /// Permit an install plan for an existing host. The reinstall decision is
    /// bound into the plan ID and authorizes loss of target data and identity.
    #[arg(long)]
    reinstall: bool,
    /// A `targets/1` file from a provider adapter: where each host answers
    #[arg(long)]
    targets: Option<PathBuf>,

    /// Read an observation/1 snapshot instead of probing selected hosts.
    #[arg(long)]
    observation: Option<PathBuf>,

    /// Use no live probes and write no plan file; without --observation, use provisional evidence.
    #[arg(long)]
    offline: bool,

    /// Compute and print the plan without saving it or its observation; may probe hosts.
    #[arg(long)]
    dry_run: bool,

    /// Repository containing SSH trust; defaults to source.repo_path.
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

/// Command result: success, failure or a completed decision that blocks execution.
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
            from,
            dev,
            hosts,
            dry_run,
            offline,
        } => resolve(
            repo,
            out,
            fleet,
            from.as_deref(),
            *dev,
            hosts,
            *dry_run,
            *offline,
        )
        .map(Answer::from),
        Verb::Build(args) => build(args).map(Answer::from),
        Verb::Image(args) => image(args).map(Answer::from),
        Verb::Install(args) => install(args),
        Verb::Status(look) => status(look),
        Verb::Check { look, suite } => check(look, suite),
        Verb::Plan(args) => make_plan(args),
        Verb::Gc {
            keep,
            older_than,
            observations,
            runs,
            repo,
            dry_run,
        } => gc(
            &state::Retention {
                keep: *keep,
                older_than_days: *older_than,
                observations: *observations,
                runs: *runs,
            },
            repo,
            *dry_run,
        )
        .map(Answer::from),
        Verb::Apply(args) => apply(args),
        Verb::Report { run, repo, json } => report(run, repo, *json),
        Verb::Verify(args) => verify(args),
        Verb::Keys { cmd } => keys(cmd),
        Verb::Retire {
            host,
            release,
            reason,
            crl_reason,
            repo,
            inventory,
            meister_ca,
            identity,
            out,
            dry_run,
            json,
        } => retire(RetireArgs {
            host,
            release,
            reason: reason.as_deref(),
            crl_reason: crl_reason.as_deref(),
            repo,
            inventory: inventory.as_deref(),
            meister_ca,
            identity: identity.clone(),
            out: out.clone(),
            dry_run: *dry_run,
            json: *json,
        }),
    }
}

/// Print the schema of a supported versioned contract.
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
        "verify-ledger" => schemars::schema_for!(meister_deploy::verify::Ledger),
        "verify" => schemars::schema_for!(meister_deploy::verify::VerifyRun),
        other => anyhow::bail!(
            "there is no schema called {other:?}; this tool knows nix-manifest, \
             resolved-fleet, release, observation, activate-status, targets, plan, \
             status, receipt, journal-event, check-result, verify and verify-ledger."
        ),
    };
    println!("{}", serde_json::to_string_pretty(&schema)?);
    Ok(true)
}

/// Identify the producing binary; git_rev is present only when set at build time.
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
    from: Option<&Path>,
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
    // Persist an absolute source path for later manifest consumers.
    let repo = std::path::absolute(repo)
        .with_context(|| format!("{} could not be made absolute", repo.display()))?;
    let selection = if hosts.is_empty() { None } else { Some(hosts) };
    if dry_run {
        for cmd in source::commands(&repo, dev) {
            println!("{}", cmd.described());
        }
        if let Some(path) = from {
            println!("# would read the evaluation from {}", path.display());
            println!("# would write {}", out.display());
            return Ok(true);
        }
        // The snapshot hash or captured revision is unknown until source inspection.
        let (eval_dir, rev) = if dev {
            println!(
                "# would then copy exactly those files to {}",
                source::snapshot_dir(&repo, "<content-hash>").display()
            );
            (source::snapshot_dir(&repo, "<content-hash>"), None)
        } else {
            (repo.clone(), Some("<rev>"))
        };
        println!(
            "{}",
            nix::eval_manifest_cmd(&nix::flake_ref(&eval_dir, dev, rev), selection).line()
        );
        println!("# would write {}", out.display());
        return Ok(true);
    }

    let policy = Policy::real();
    // Propagate cancellation to the external evaluator.
    Cancel::on_sigint()?;
    let runner = Real::new(policy);
    let files = RealFiles::new(policy);

    let mut tree = source::describe(&runner, &files, &repo, fleet, dev)?;
    // A supplied evaluation keeps this repository's source identity and records
    // its own origin/hash separately; it is not proof of evaluation equivalence.
    let (evaluated, origin) = match from {
        Some(path) => {
            let text = files.read_to_string(path)?;
            let origin = path.display().to_string();
            // Accept only a Nix evaluation, not an already-resolved fleet.
            let evaluated = match manifest::parse_contract(&text, &origin)? {
                Contract::NixManifest(evaluated) => *evaluated,
                other => anyhow::bail!(
                    "{origin} is a {}. `resolve --from` reads an EVALUATION — what \
                     `nix eval <repo>#meisterDeployment` prints, schema {} — and turns it \
                     into a manifest; it does not take one that has already been resolved.",
                    other.describe(),
                    manifest::NIX_MANIFEST_SCHEMA
                ),
            };
            tree.source.provided_evaluation = Some(manifest::ProvidedEvaluation {
                origin: origin.clone(),
                sha256: meister_deploy::ids::sha256_hex(text.as_bytes()),
            });
            (evaluated, origin)
        }
        None => {
            // Pin evaluation to the revision captured during source inspection.
            let flake_ref = nix::flake_ref(&tree.eval_dir, dev, tree.source.git_rev.as_deref());
            let text = nix::eval_manifest(&runner, &flake_ref, selection)?;
            let origin = format!("{flake_ref}#{}", nix::MANIFEST_ATTR);
            (NixManifest::from_json(&text, &origin)?, origin)
        }
    };
    // Require the evaluated inventory to match the source inventory.
    // For --from, retain the mismatch as a warning about supplied evidence.
    if evaluated.inventory_sha256 != tree.source.inventory_sha256 {
        let what = format!(
            "the evaluation read an inventory with sha256 {} and this command read {} \
             (sha256 {}); they are not the same file. The manifest would name a file \
             nobody evaluated.",
            evaluated.inventory_sha256, tree.source.inventory_path, tree.source.inventory_sha256
        );
        if from.is_some() {
            eprintln!(
                "warning: {what} The evaluation was handed over, so this is only a warning: \
                 whatever changed in {} since it was made is not in this manifest.",
                tree.source.inventory_path
            );
        } else {
            anyhow::bail!(
                "{what} Name the inventory the flake evaluates with `-f`, or point the \
                 flake at this one. Nothing was written."
            );
        }
    }
    let resolved = manifest::resolve(evaluated, tree.source, tool(), RealClock.now(), selection)?;

    files.write_atomic(out, &resolved.to_json()?, 0o644)?;
    // Write the ID to stdout and diagnostics to stderr.
    println!("{}", resolved.manifest_id);
    eprintln!("==> {}", out.display());
    if from.is_some() {
        eprintln!(
            "note: nothing was evaluated here. The systems in this manifest are the ones \
             {origin} names, and whether they are what {} evaluates to is that file's \
             producer to answer for. The source fingerprint is this repository's, and the \
             manifest says so in `source.provided_evaluation`.",
            repo.display()
        );
    }
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

/// Fleet context and observations shared by status and check.
struct Looked {
    fleet: manifest::ResolvedFleet,
    release: Option<ReleaseManifest>,
    selected: Vec<String>,
    observation: Observations,
    checks: Vec<meister_deploy::checks::CheckResult>,
    /// Where the snapshot was written, for a run that asked.
    written: Option<PathBuf>,
    /// Hosts missing from the current inventory; listed without probing.
    unmanaged: BTreeSet<String>,
}

/// Look at the fleet: one round trip per host, or the last snapshot on disk.
fn look(args: &LookArgs) -> Result<Looked> {
    let policy = if args.offline {
        Policy::offline()
    } else {
        Policy::real()
    };
    let files = RealFiles::new(policy);

    // A release supplies the desired system for comparison.
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

    // Exclude hosts removed from the current inventory without changing the release.
    let inventory_file = match &args.inventory {
        Some(path) => inventory_path(&repo, path),
        None => Path::new(&fleet.source.repo_path).join(&fleet.source.inventory_path),
    };
    let unmanaged: BTreeSet<String> = match Inventory::load(&files, &inventory_file) {
        // A different fleet cannot establish that these hosts are unmanaged.
        Ok(inventory) if inventory.fleet.name != fleet.fleet.name => {
            eprintln!(
                "note: {} is the inventory of the fleet {:?} and this release is of {:?}, so                  it says nothing about which of these hosts are still managed. Pass                  --inventory <file> to point at the right one.",
                inventory_file.display(),
                inventory.fleet.name,
                fleet.fleet.name
            );
            BTreeSet::new()
        }
        Ok(inventory) => selected
            .iter()
            .filter(|id| !inventory.hosts.contains_key(*id))
            .cloned()
            .collect(),
        Err(e) => {
            // Missing inventory prevents unmanaged-host classification but not inspection.
            eprintln!(
                "note: {} could not be read ({e}), so nobody can say which of these hosts                  the inventory still has. Pass --inventory <file> for that half.",
                inventory_file.display()
            );
            BTreeSet::new()
        }
    };
    let asked: Vec<String> = selected
        .iter()
        .filter(|id| !unmanaged.contains(*id))
        .cloned()
        .collect();
    if !unmanaged.is_empty() {
        eprintln!(
            "note: {} is in this release and not in {}; nothing was asked of it.",
            unmanaged.iter().cloned().collect::<Vec<_>>().join(", "),
            inventory_file.display()
        );
    }

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
                observation::bind_targets(&fleet, &targets, &asked)?
            }
            None => observation::manifest_endpoints(&fleet, &asked)?,
        };
        Cancel::on_sigint()?;
        let runner = Real::new(policy);
        let ssh = transport::Ssh::for_repo(&repo).with_identity(args.identity.clone());
        let prober = observe::SshProber::new(&runner, &ssh);
        let probes: Vec<observe::HostProbe> = asked
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

    let mut checks = readiness::readiness_of(&fleet, &asked, &observation, release.as_ref());
    for id in &unmanaged {
        checks.push(readiness::unmanaged(
            id,
            state.read_retired(&files, id).as_ref(),
        ));
    }
    checks.extend(service_checks(&Real::new(policy), &fleet, args.offline));
    Ok(Looked {
        fleet,
        release,
        selected,
        observation,
        checks,
        written,
        unmanaged,
    })
}


/// How long one service endpoint has to answer.
const SERVICE_DEADLINE_SECS: u64 = 5;

/// Probe external service endpoints with bounded curl requests.
/// Offline or failed probes yield unknown/unreachable evidence, not service health.
fn service_checks(
    runner: &dyn meister_deploy::run::Runner,
    fleet: &manifest::ResolvedFleet,
    offline: bool,
) -> Vec<meister_deploy::checks::CheckResult> {
    let mut out = Vec::new();
    for (id, service) in &fleet.services {
        if service.managed {
            out.push(readiness::service(id, service, None));
            continue;
        }
        let endpoints: Vec<(&String, &String)> = service
            .endpoint
            .as_ref()
            .map(|e| e.iter().collect())
            .unwrap_or_default();
        if endpoints.is_empty() || offline {
            out.push(readiness::service(id, service, None));
            continue;
        }
        // Require every declared endpoint to answer.
        let mut verdict: Option<readiness::Reached> = None;
        for (name, url) in endpoints {
            let cmd = meister_deploy::run::Cmd::new(
                meister_deploy::run::Effect::Read,
                "curl",
                std::time::Duration::from_secs(SERVICE_DEADLINE_SECS),
            )
            .args([
                "--silent",
                "--show-error",
                "--output",
                "/dev/null",
                "--max-time",
                &SERVICE_DEADLINE_SECS.to_string(),
                "--write-out",
                "%{http_code}",
                url,
            ]);
            match runner.run(&cmd) {
                // Any HTTP response establishes reachability, including 4xx/5xx;
                // this check does not establish application health.
                Ok(done) => {
                    verdict = Some(readiness::Reached::Answered {
                        endpoint: format!("{name}={url}"),
                        detail: format!("http {}", done.stdout.trim()),
                    });
                }
                Err(e) => {
                    verdict = Some(readiness::Reached::Silent {
                        endpoint: format!("{name}={url}"),
                        detail: first_line(&e.to_string()),
                    });
                    break;
                }
            }
        }
        out.push(readiness::service(id, service, verdict));
    }
    out
}

fn first_line(text: &str) -> String {
    text.lines().next().unwrap_or("").trim().to_string()
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
    // Status exits successfully when it produces a report, even if checks fail.
    Ok(Answer::Yes)
}

/// Explain missing workload-control configuration separately from host readiness.
/// Readiness can pass while an interrupting rollout remains blocked.
fn note_about_the_workload_reference(args: &LookArgs, looked: &Looked) {
    let Some(release) = &looked.release else {
        return;
    };
    let files = RealFiles::new(Policy::real());
    let (control, why) = workload_control(&files, release, args.inventory.as_deref());
    if control.is_some() {
        return;
    }
    let agents: Vec<&str> = looked
        .selected
        .iter()
        .filter(|id| {
            looked
                .fleet
                .hosts
                .get(*id)
                .map(|host| host.roles.iter().any(|r| r == "agent"))
                .unwrap_or(false)
        })
        .map(|id| id.as_str())
        .collect();
    if agents.is_empty() {
        return;
    }
    if let Some(why) = why {
        eprintln!("note: {why}");
    }
    eprintln!(
        "note: these checks say nothing about D7. {} carries guests, and without `[operator] \
         cli_config` in the inventory no rollout can cordon or drain it — every interrupting \
         step for it is blocked in the plan, not here.",
        agents.join(", ")
    );
}

fn check(args: &LookArgs, suite: &str) -> Result<Answer> {
    if suite != "readiness" {
        anyhow::bail!(
            "the suite {suite:?} does work on the fleet — it starts guests, it uses \
             hardware — so it is not something `check` does. `check --suite readiness` is \
             what reads; `verify --suite {suite}` is the one that does the work, and it \
             takes a budget, a deadline and an approval." // --- end lane 4B ---"
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
    note_about_the_workload_reference(args, &looked);
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
    // Keep variable-length store paths in the last column.
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
                _ if looked.unmanaged.contains(id) => "unmanaged",
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
    // Print nonpassing checks after the host summary.
    for check in &looked.checks {
        // Keep the unmanaged-host explanation visible even though it is not a blocker.
        if check.status == Status::Pass
            || (check.status == Status::NotApplicable && check.id != "managed")
        {
            continue;
        }
        out.push_str(&format!(
            "    {} {} on {}: {}\n",
            if check.required {
                "REQUIRED"
            } else if check.id == "managed" {
                "note    "
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
        // Use the same derivation selection as a real build.
        let selected = hosts
            .clone()
            .unwrap_or_else(|| resolved.evaluated_hosts.clone());
        for drv in build::derivations(&resolved, &selected) {
            println!("{}\t{}", drv.what, drv.drv);
        }
        eprintln!(
            "note: nothing was built and no release was written. A real run realises these \
             derivations in ONE `nix build`, signs them{} and writes --out.",
            match &args.cache {
                Some(cache) => format!(", pushes them into {cache}"),
                None => String::new(),
            } // --- end lane 4C ---
        );
        return Ok(true);
    }

    // Prefer --sign-key, then the inventory reference; report the selected source.
    let (sign_key, note) = match &args.sign_key {
        Some(path) => (Some(path.clone()), None),
        None => signing_key(&files, &resolved, args.inventory.as_deref()),
    };
    if let Some(note) = note {
        eprintln!("note: {note}");
    }

    // Propagate cancellation to Nix builds.
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
            max_jobs: args.max_jobs.clone(),
            options: nix_options(&args.option)?,
            cache: args.cache.clone(),
            verify_reproducible: args.verify_reproducible,
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
        // Without --out, stdout contains the release document.
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
    if let Some(cache) = &built.release.build_env.cache_url {
        eprintln!(
            "    {} path(s) pushed into {cache}, signed by {}",
            built.release.artifacts.len() + built.release.packages.len(),
            built
                .release
                .build_env
                .signing_key_name
                .as_deref()
                .unwrap_or("nobody")
        );
        eprintln!(
            "note: a host fetches from that store only if its own \
             `meisterstack.managed.substituters` names it — the release records where the \
             closures went and instructs nobody."
        );
    }
    Ok(true)
}

/// Where the manifest was resolved from, as an absolute path.
fn repo_of(resolved: &manifest::ResolvedFleet) -> PathBuf {
    PathBuf::from(&resolved.source.repo_path)
}


/// Normalize Nix options; reject conflicting values for the same setting.
fn nix_options(flat: &[String]) -> Result<std::collections::BTreeMap<String, String>> {
    let mut out: std::collections::BTreeMap<String, String> = std::collections::BTreeMap::new();
    for pair in flat.chunks(2) {
        // Clap enforces pairs; retain validation for direct callers.
        let [name, value] = pair else {
            anyhow::bail!(
                "--option takes a name and a value; {:?} is half of one.",
                pair
            );
        };
        if let Some(had) = out.insert(name.clone(), value.clone())
            && &had != value
        {
            anyhow::bail!(
                "--option {name} was given twice, as {had:?} and as {value:?}. nix would take \
                 the last one and the release would record one of two answers, so say which."
            );
        }
    }
    Ok(out)
}



/// Build, measure and root a media derivation already bound into the release.
fn image(args: &ImageArgs) -> Result<bool> {
    if args.offline {
        anyhow::bail!(
            "image builds a medium, and --offline forbids it. There is nothing on disk this \
             verb could answer from: the medium IS the build."
        );
    }
    let kind = build::ImageKind::parse(&args.kind)?;
    let policy = if args.dry_run {
        Policy::dry_run()
    } else {
        Policy::real()
    };
    let files = RealFiles::new(policy);

    let text = files.read_to_string(&args.release)?;
    let release = ReleaseManifest::from_json(&text, &args.release.display().to_string())?;

    if args.dry_run {
        let drv = build::image_drv(&release, &args.host, kind)?;
        println!(
            "{}",
            build::build_cmd(&drv, &build::BuildOptions::default()).line()
        );
        eprintln!(
            "note: nothing was built, nothing was rooted and nothing was linked. The \
             derivation above is the one the release {} names for {} as its {kind} medium.",
            release.release_id, args.host
        );
        return Ok(true);
    }

    // Propagate cancellation to media builds.
    Cancel::on_sigint()?;
    let runner = Real::new(policy).verbose(true);
    let repo = args
        .repo
        .clone()
        .unwrap_or_else(|| repo_of(&release.resolved_fleet));
    let builder = build::Builder {
        runner: &runner,
        files: &files,
        clock: &RealClock,
        options: build::BuildOptions::default(),
        state: Some(StateDir::in_repo(&repo)),
    };
    let result = builder.image(&release, &args.host, kind, args.out.as_deref())?;

    if args.json {
        println!("{}", serde_json::to_string_pretty(&result)?);
    } else {
        println!("{}", result.file.as_deref().unwrap_or(&result.store_path));
        if let (Some(sha256), Some(size)) = (&result.sha256, result.size) {
            eprintln!("    sha256 {sha256}");
            eprintln!("    size   {size} bytes ({} MiB)", size / (1024 * 1024));
        }
        if let Some(root) = &result.gc_root {
            eprintln!("    root   {root}");
        }
        if let Some(link) = &result.linked_to {
            eprintln!("    linked {link}");
        }
    }
    Ok(true)
}

/// Prepare media for an approved installation plan. Target-side
/// meister-install confirm performs disk changes separately.
fn install(args: &InstallArgs) -> Result<Answer> {
    if args.offline {
        anyhow::bail!(
            "install builds an installer medium, and --offline forbids it. There is nothing \
             on disk this verb could answer from: the medium IS the build."
        );
    }
    let policy = if args.dry_run {
        Policy::dry_run()
    } else {
        Policy::real()
    };
    let files = RealFiles::new(policy);

    let text = files.read_to_string(&args.plan)?;
    let the_plan = plan::DeploymentPlan::from_json(&text, &args.plan.display().to_string())?;
    let text = files.read_to_string(&args.release)?;
    let release = ReleaseManifest::from_json(&text, &args.release.display().to_string())?;

    if the_plan.kind != PlanKind::Install {
        anyhow::bail!(
            "{} is a `{}` plan, and this verb prepares an `install`. `plan --kind install \
             --select host={}` is what makes one.",
            args.plan.display(),
            the_plan.kind,
            args.host
        );
    }
    if the_plan.release_id != release.release_id {
        anyhow::bail!(
            "the plan {} was made for the release {} and {} is {}. A medium is built out of \
             the derivation a release names, so these two have to be the same release.",
            the_plan.plan_id,
            the_plan.release_id,
            args.release.display(),
            release.release_id
        );
    }
    let Some(host_plan) = the_plan.hosts.get(&args.host) else {
        anyhow::bail!(
            "the plan {} does not cover {}; it covers {}.",
            the_plan.plan_id,
            args.host,
            the_plan.selection.targets.join(", ")
        );
    };
    if let Some(action) = the_plan
        .actions
        .iter()
        .find(|a| a.host == args.host && a.kind == plan::ActionKind::Install)
        && let Some(why) = &action.blocked
    {
        eprintln!("meister-deploy: {why}");
        eprintln!(
            "note: no medium was built. A plan that blocks the installation of {} is a plan \
             that says this machine must not be installed right now.",
            args.host
        );
        return Ok(Answer::Blocked);
    }
    let _ = host_plan;

    // Require approval bound to this exact plan.
    let granted = parse_approvals(&args.approve)?;
    let missing = plan::approvals_missing(&the_plan, &granted);
    if !missing.is_empty() {
        anyhow::bail!(
            "this installation needs {}, and nobody granted {}. Writing a medium that \
             formats a disk is the point at which somebody says yes: \
             `--approve destructive={}`.",
            the_plan
                .approvals
                .iter()
                .map(|a| a.class.to_string())
                .collect::<Vec<_>>()
                .join(", "),
            missing
                .iter()
                .map(|c| c.to_string())
                .collect::<Vec<_>>()
                .join(", "),
            the_plan.plan_id
        );
    }

    let resolved_host = release
        .resolved_fleet
        .hosts
        .get(&args.host)
        .ok_or_else(|| anyhow::anyhow!("the release knows nothing about {}", args.host))?;
    let installed = resolved_host.install.as_ref().ok_or_else(|| {
        anyhow::anyhow!(
            "{} has no `install` table, so nothing says which disk a medium of it would be \
             about.",
            args.host
        )
    })?;
    let facts = meister_deploy::install::SheetFacts {
        fleet: release.resolved_fleet.fleet.name.clone(),
        serial: installed.disk.serial.clone(),
        boot_mode: resolved_host.build.boot.mode,
        preserve: installed.preserve.clone(),
        reinstall: the_plan.reinstall,
    };

    let repo = args
        .repo
        .clone()
        .unwrap_or_else(|| repo_of(&release.resolved_fleet));
    let state = StateDir::in_repo(&repo);
    let media = meister_deploy::install::media_dir(&state);

    if args.dry_run {
        let drv = build::image_drv(&release, &args.host, build::ImageKind::Installer)?;
        println!(
            "{}",
            build::build_cmd(&drv, &build::BuildOptions::default()).line()
        );
        eprintln!(
            "note: nothing was built and nothing was written. A real run puts the medium \
             under {} and prints the sheet.",
            media.display()
        );
        return Ok(Answer::Yes);
    }

    Cancel::on_sigint()?;
    let runner = Real::new(policy).verbose(true);
    let builder = build::Builder {
        runner: &runner,
        files: &files,
        clock: &RealClock,
        options: build::BuildOptions::default(),
        state: Some(StateDir::in_repo(&repo)),
    };
    let built = builder.image(
        &release,
        &args.host,
        build::ImageKind::Installer,
        Some(&media),
    )?;
    let file = built.file.clone().ok_or_else(|| {
        anyhow::anyhow!("the installer build of {} produced no iso file", args.host)
    })?;

    // Record which plan, release and bytes the media link represents.
    let record = meister_deploy::install::MediaRecord {
        schema: meister_deploy::install::MEDIA_SCHEMA.to_string(),
        host: args.host.clone(),
        plan_id: the_plan.plan_id.clone(),
        release_id: release.release_id.clone(),
        iso: built.linked_to.clone().unwrap_or_else(|| file.clone()),
        store_path: file,
        sha256: built.sha256.clone().unwrap_or_default(),
        size: built.size.unwrap_or(0),
        built_at: RealClock.now(),
    };
    files.write_atomic(
        &media.join(format!("{}.json", args.host)),
        &record.to_json()?,
        0o644,
    )?;

    if let Some(dir) = &args.out {
        files.create_dir_all(dir)?;
        files.symlink_atomic(
            Path::new(&record.store_path),
            &dir.join(format!("{}.iso", args.host)),
        )?;
        eprintln!("    also linked into {}", dir.display());
    }

    if args.json {
        println!("{}", serde_json::to_string_pretty(&record)?);
    } else {
        print!("{}", meister_deploy::install::sheet(&record, &facts));
    }
    Ok(Answer::Yes)
}


/// Resolve the inventory's signing-key reference; missing configuration is
/// left for build validation to diagnose.
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
            // Resolve relative key paths against the inventory directory.
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


/// Compute retention decisions before removing local roots and evidence.
/// Dry-run prints the same decisions without applying them.
fn gc(retention: &state::Retention, repo: &Path, dry_run: bool) -> Result<bool> {
    let policy = if dry_run {
        Policy::dry_run()
    } else {
        Policy::real()
    };
    let files = RealFiles::new(policy);
    let state = StateDir::in_repo(repo);
    let roots = build::roots(&files, &state)?;
    let sweep = state::sweep(&files, &state, &roots, retention, RealClock.now())?;

    for removal in &sweep.remove {
        println!(
            "{}\t{}\t{} file(s){}",
            removal.kind,
            removal.what,
            removal.entries(),
            if dry_run { "  (would remove)" } else { "" }
        );
    }
    if !dry_run {
        state::carry_out(&files, &sweep)?;
    }

    for kind in ["release", "observation", "run"] {
        let going = sweep.removals_of(kind).len();
        let staying = sweep.kept_of(kind).len();
        if going == 0 && staying == 0 {
            continue;
        }
        eprintln!(
            "==> {kind}: {going} {}, {staying} kept",
            if dry_run { "would go" } else { "removed" }
        );
    }
    // Explain retained entries, including incomplete or unrecognized evidence.
    for kept in &sweep.keep {
        eprintln!("    kept {} {}: {}", kept.kind, kept.what, kept.why);
    }
    if roots.is_empty() {
        eprintln!(
            "note: {} protects no release.",
            state.gcroots_dir().display()
        );
    }
    if retention.observations.is_none() {
        eprintln!(
            "note: the snapshots under {} were not touched; `--observations N` is what \
             trims them, and `latest.json` is never removed.",
            state.observations_dir().display()
        );
    }
    if !retention.runs {
        eprintln!(
            "note: the runs under {} were not touched; `--runs` is what removes the \
             finished ones, and a run that did not end `success` is never one of them.",
            state.runs_dir().display()
        );
    }
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
        // Use the supplied snapshot without refreshing it.
        (Some(path), _) => {
            let text = files.read_to_string(path)?;
            Observations::from_json(&text, &path.display().to_string())?
        }
        // Without observations, mark evidence provisional and block interruption.
        (None, true) => Observations::provisional(RealClock.now()),
        // Probe only selected hosts.
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
            // Save evidence before planning so a planning failure does not discard it.
            // Dry-run retains nothing.
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
        "install" => PlanKind::Install,
        // Allow planning delivery of an already-published CRL.
        "keys-revoke" => PlanKind::KeysRevoke,
        // Allow planning delivery after a separately recorded retirement.
        "retire" => PlanKind::Retire,
        "keys-rotate" => anyhow::bail!(
            "the plan kind \"keys-rotate\" is not built here. A rotation is made by \
             `keys rotate`, which prepares the key on the host and issues the certificate \
             before there is anything to plan."
        ),
        other => anyhow::bail!(
            "{other:?} is not a plan kind. This tool builds `upgrade`, `bootstrap`, \
             `install`, `keys-revoke` and `retire`."
        ),
    };
    if args.reinstall && kind != PlanKind::Install {
        anyhow::bail!(
            "--reinstall belongs to `plan --kind install`: it says that a disk which already \
             carries an installation may be destroyed. An upgrade never touches a partition \
             table."
        );
    }

    let (control, note) = workload_control(&files, &release, args.inventory.as_deref());
    if let Some(note) = note {
        eprintln!("note: {note}");
    }
    let (expected, note) = expected_credentials(
        &files,
        &release,
        &args.select,
        args.repo.as_deref(),
        args.inventory.as_deref(),
    );
    if let Some(note) = note {
        eprintln!("note: {note}");
    }
    let plan = plan::plan(
        &release,
        &args.select,
        &observation,
        targets.as_ref(),
        &plan::PlanPolicy::new(kind)
            .with_workload_control(control)
            .with_expected_credentials(expected)
            .with_reinstall(args.reinstall),
        RealClock.now(),
    )?;

    match (&args.out, args.dry_run) {
        (Some(path), false) => {
            files.write_atomic(path, &plan.to_json()?, 0o644)?;
            println!("{}", plan.plan_id);
            eprintln!("==> {}", path.display());
        }
        (Some(path), true) => {
            // Dry-run prints the plan instead of writing --out.
            print!("{}", String::from_utf8(plan.to_json()?)?);
            eprintln!(
                "note: {} was not written, and no snapshot was kept.",
                path.display()
            );
        }
        // Without --out, stdout contains the plan document.
        (None, _) => print!("{}", String::from_utf8(plan.to_json()?)?),
    }
    eprint!("{}", plan_summary(&plan));
    Ok(if plan.is_blocked() {
        Answer::Blocked
    } else {
        Answer::Yes
    })
}

/// Read workload-control configuration. Missing configuration becomes a
/// planning blocker for interrupting agent actions.
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

/// Collect public credential digests and private-key presence evidence.
/// Missing files remain absent so the planner can report delivery blockers.
fn expected_credentials(
    files: &dyn Files,
    release: &ReleaseManifest,
    select: &str,
    repo: Option<&Path>,
    inventory: Option<&Path>,
) -> (
    BTreeMap<String, meister_deploy::pki::ExpectedCredentials>,
    Option<String>,
) {
    let fleet = &release.resolved_fleet;
    let Ok(selected) = plan::select(fleet, select) else {
        // Leave selector diagnostics to the planner.
        return (BTreeMap::new(), None);
    };
    let repo = repo
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from(&fleet.source.repo_path));
    let inventory_file = match inventory {
        Some(path) => inventory_path(&repo, path),
        None => Path::new(&fleet.source.repo_path).join(&fleet.source.inventory_path),
    };
    let Some(ca) = ca_directory(files, release, Some(&repo), inventory) else {
        return (
            BTreeMap::new(),
            Some(format!(
                "{} names no `[operator] ca_dir`, so this plan does not know where the CA's \
                 files are. A host that is missing one is blocked with the verb that makes \
                 it.",
                inventory_file.display()
            )),
        );
    };
    (
        meister_deploy::pki::expected_credentials(files, &repo, &ca, fleet, &selected),
        None,
    )
}

/// Resolve the inventory's CA directory, or return None when unavailable.
fn ca_directory(
    files: &dyn Files,
    release: &ReleaseManifest,
    repo: Option<&Path>,
    inventory: Option<&Path>,
) -> Option<PathBuf> {
    let fleet = &release.resolved_fleet;
    let repo = repo
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from(&fleet.source.repo_path));
    // Resolve explicit relative inventory paths against --repo.
    let inventory_file = match inventory {
        Some(path) => inventory_path(&repo, path),
        None => Path::new(&fleet.source.repo_path).join(&fleet.source.inventory_path),
    };
    let named = Inventory::load(files, &inventory_file)
        .ok()?
        .operator
        .as_ref()
        .and_then(|o| o.ca_dir.clone())?;
    Some(meister_deploy::pki::ca_dir(&inventory_file, &named))
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
    // Group repeated blocker reasons while retaining affected hosts and actions.
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

// ---------------------------------------------------------------------------
// apply
// ---------------------------------------------------------------------------

/// Validate the plan/release pair, acquire the repository lock, run the
/// executor, and report its receipt and command outcome.
fn apply(args: &ApplyArgs) -> Result<Answer> {
    let policy = if args.dry_run {
        Policy::dry_run()
    } else {
        Policy::real()
    };
    let files = RealFiles::new(policy);

    // Resume can load the plan and release saved with the run.
    // Legacy runs without a release copy need explicit files.
    let (plan_path, release_path) = match (&args.plan, &args.release, &args.resume) {
        (Some(plan), Some(release), _) => (plan.clone(), release.clone()),
        (None, None, Some(run)) => {
            let repo = args.repo.clone().unwrap_or_else(|| PathBuf::from("."));
            let state = StateDir::in_repo(&repo);
            let plan = state.plan_copy_path(run);
            let release = state.release_copy_path(run);
            for (what, path) in [("plan", &plan), ("release", &release)] {
                if !files.exists(path) {
                    anyhow::bail!(
                        "the run {run} has no copy of its {what} in {}. Name the file with \
                         --{what}; a run that began before this tool kept the release beside \
                         the plan has only the one the operator still holds.",
                        path.display()
                    );
                }
            }
            eprintln!(
                "==> resuming from {} and {}",
                plan.display(),
                release.display()
            );
            (plan, release)
        }
        (plan, release, _) => anyhow::bail!(
            "apply needs a plan and the release it was made for. {} Pass both, or pass \
             `--resume <run-id>` alone and let the run's own directory answer.",
            match (plan.is_some(), release.is_some()) {
                (true, false) => "--release is missing.",
                (false, true) => "--plan is missing.",
                _ => "Neither was named and this is not a resume.",
            }
        ),
    };

    let text = files.read_to_string(&plan_path)?;
    let the_plan = plan::DeploymentPlan::from_json(&text, &plan_path.display().to_string())?;
    let text = files.read_to_string(&release_path)?;
    let release = ReleaseManifest::from_json(&text, &release_path.display().to_string())?;
    if release.release_id != the_plan.release_id {
        anyhow::bail!(
            "{} was made for the release {} and {} is {}. A plan names the bytes it was made \
             for; another build is another plan.",
            plan_path.display(),
            the_plan.release_id,
            release_path.display(),
            release.release_id
        );
    }

    let approvals = parse_approvals(&args.approve)?;
    let repo = args
        .repo
        .clone()
        .unwrap_or_else(|| PathBuf::from(&release.resolved_fleet.source.repo_path));
    let state = StateDir::in_repo(&repo);
    let operator = state::current_operator();
    let run_id = match &args.resume {
        Some(id) => id.clone(),
        None => meister_deploy::ids::run_id(RealClock.now()).to_string(),
    };

    // Propagate cancellation to active copy and activation commands.
    Cancel::on_sigint()?;
    let cancel = Cancel::new();
    let mut runner = Real::new(policy);
    runner.cancel = cancel.clone();
    let ssh = transport::Ssh::for_repo(&repo).with_identity(args.identity.clone());
    let prober = observe::SshProber::new(&runner, &ssh);
    let look = execute::SshLook { prober: &prober };

    if args.dry_run {
        return dry_run(&the_plan, &release, &look, &state);
    }

    // Missing approvals return blocked before acquiring a lock or creating a run.
    let missing = plan::approvals_missing(&the_plan, &approvals);
    if !missing.is_empty() {
        eprintln!(
            "==> this plan needs {}, and nothing was granted for it. Read the plan, then \
             pass {}. An approval names the plan it is for, so it cannot be carried over \
             from another one.",
            missing
                .iter()
                .map(|c| c.as_str())
                .collect::<Vec<_>>()
                .join(" and "),
            missing
                .iter()
                .map(|c| format!("--approve {c}={}", the_plan.plan_id))
                .collect::<Vec<_>>()
                .join(" ")
        );
        return Ok(Answer::Blocked);
    }

    // Acquire local run ownership before invoking the executor.
    let held = match &args.takeover {
        Some(of_run) => {
            state::take_over_lock(&files, &state, of_run, &run_id, &operator, RealClock.now())?
        }
        None => state::acquire_lock(&files, &state, &run_id, &operator, RealClock.now())?,
    };
    eprintln!(
        "==> run {run_id}  plan {}  release {}",
        the_plan.plan_id, the_plan.release_id
    );
    // Plain output starts with the run ID; JSON output carries it in the receipt.
    if !args.json {
        println!("{run_id}");
    }

    let (control, note) = workload_control(&files, &release, args.inventory.as_deref());
    if let Some(note) = note {
        eprintln!("note: {note}");
    }
    let mut options = execute::ApplyOptions::new(&run_id);
    options.approvals = approvals;
    options.resume = args.resume.is_some();
    options.takeover = args.takeover.clone();
    options.workload = control;
    options.drain_wait = std::time::Duration::from_secs(args.drain_wait);
    options.reboot_wait = std::time::Duration::from_secs(args.reboot_wait);
    options.repo = repo.clone();
    options.ca_dir = ca_directory(&files, &release, Some(&repo), args.inventory.as_deref());

    let executor = execute::Executor {
        runner: &runner,
        files: &files,
        clock: &RealClock,
        look: &look,
        ssh: &ssh,
        state: &state,
        plan: &the_plan,
        release: &release,
        operator: receipt::Operator {
            user: operator.user.clone(),
            workstation: operator.workstation.clone(),
        },
        options,
        cancel,
    };
    let applied = executor.run();

    // Attempt lock release after execution; retain the execution result if release fails.
    if let Err(e) = state::release_lock(&files, &state, &held.run_id) {
        eprintln!(
            "note: the lock on {} was not released: {e:#}",
            repo.display()
        );
    }
    let applied = applied?;

    if args.json {
        println!("{}", String::from_utf8(applied.receipt.to_json()?)?);
    } else {
        print!("{}", receipt_table(&applied.receipt));
    }
    eprintln!("==> {}", state.receipt_path(&run_id).display());
    for id in &applied.blocked {
        eprintln!(
            "    blocked: {id}: {}",
            the_plan.hosts[id].reasons.join("; ")
        );
    }
    if let Some(why) = &applied.stopped {
        eprintln!("==> {why}");
    }
    // A provider handoff pauses execution and returns blocked.
    // JSON output carries waiting state in the receipt; plain output adds the handoff object.
    if let Some(wait) = &applied.waiting {
        // Avoid a second JSON document after the receipt.
        if !args.json {
            println!("{}", serde_json::to_string(&wait.to_json())?);
        }
        eprintln!(
            "==> {} is waiting for its provider. Nothing else was started.",
            wait.host
        );
        // A pending provider action returns blocked.
        return Ok(Answer::Blocked);
    }
    if applied.receipt.outcome != receipt::Outcome::Success {
        eprint!("{}", what_is_left(&applied.receipt, &state, &run_id));
    }
    Ok(answer_for(
        applied.receipt.outcome,
        applied.blocked.is_empty(),
        applied.stopped.is_some(),
    ))
}

/// Map the run outcome to an exit code. A stopped run fails even when
/// all host activations committed; cleanup may still be incomplete.
fn answer_for(outcome: receipt::Outcome, nothing_blocked: bool, stopped: bool) -> Answer {
    match (outcome, nothing_blocked, stopped) {
        (_, _, true) => Answer::No,
        (receipt::Outcome::Success, true, false) => Answer::Yes,
        // A completed run with blocked hosts returns 2.
        (receipt::Outcome::Success, false, false) => Answer::Blocked,
        _ => Answer::No,
    }
}

/// Describe retained local evidence and target transactions after a failed run.
fn what_is_left(receipt: &receipt::DeploymentReceipt, state: &StateDir, run_id: &str) -> String {
    let mut out = String::new();
    out.push_str("==> what this run left behind, and the way out:\n");
    out.push_str(&format!(
        "    1. the run itself, in {}: its journal, the plan it ran and the release it ran \
         them from. Read it with `meister-deploy report --run {run_id}`, and continue it with \
         `meister-deploy apply --resume {run_id}` — that needs no --plan and no --release, \
         they are in there.\n",
        state.run_dir(run_id).display()
    ));
    out.push_str(&format!(
        "    2. the operator's lock, {}. This run gave it back; a run that was KILLED did \
         not, and the next one then names this id and offers `--takeover {run_id}`.\n",
        state.lock_path().display()
    ));
    let open: Vec<(&String, &String)> = receipt
        .hosts
        .iter()
        .filter(|(_, host)| host.outcome != receipt::HostOutcome::Success)
        .filter_map(|(id, host)| host.txn_id.as_ref().map(|txn| (id, txn)))
        .collect();
    if open.is_empty() {
        out.push_str("    3. no transaction record: no host of this run was left holding one.\n");
    } else {
        out.push_str(
            "    3. a transaction record on each of these hosts, which is what says the \
             machine may still have to go back:\n",
        );
        for (id, txn) in open {
            out.push_str(&format!(
                "       {id}: `meister-activate txn show --txn {txn}` on that host. Finish it \
                 with `confirm` or `revert`; only if it says `inconsistent` and the machine's \
                 profile, /run/current-system and /run/booted-system all agree, put it aside \
                 with `meister-activate txn retire --txn {txn} --force --reason \"<what you \
                 found>\"`.\n"
            ));
        }
    }
    out
}

/// Reobserve and validate without repository locks, journals or target writes.
fn dry_run(
    the_plan: &plan::DeploymentPlan,
    release: &ReleaseManifest,
    look: &dyn execute::Look,
    state: &StateDir,
) -> Result<Answer> {
    let mut fresh = the_plan.observation.clone();
    fresh.taken_at = RealClock.now();
    for id in &the_plan.selection.targets {
        let Some(host) = release.resolved_fleet.hosts.get(id) else {
            continue;
        };
        let Some(endpoint) = the_plan.endpoints.get(id) else {
            continue;
        };
        let target = transport::Target::from_endpoint(id, endpoint);
        fresh.hosts.insert(id.clone(), look.observe(host, &target));
    }
    let verdict = plan::validate_against(the_plan, release, &fresh, RealClock.now());
    eprintln!(
        "==> {} ({}, {} host(s), {} wave(s))",
        the_plan.plan_id,
        the_plan.kind,
        the_plan.selection.targets.len(),
        the_plan.last_wave() + 1
    );
    for action in &the_plan.actions {
        println!(
            "{}\t{}\t{}\t{}\t{}",
            action.wave,
            action.seq,
            action.host,
            action.kind,
            match &action.blocked {
                Some(why) => format!("blocked: {why}"),
                None => action.desired.clone().unwrap_or_default(),
            }
        );
    }
    eprintln!(
        "note: nothing was locked, nothing was copied and no journal was written. {} holds \
         no run of this.",
        state.runs_dir().display()
    );
    match verdict {
        plan::Verdict::Proceed => {
            eprintln!("==> the plan still matches the fleet.");
            Ok(Answer::from(!the_plan.is_blocked()))
        }
        verdict => {
            for reason in verdict.reasons() {
                eprintln!("    {reason}");
            }
            eprintln!("==> this plan would not run against the fleet as it is now.");
            Ok(Answer::Blocked)
        }
    }
}

/// `--approve <class>=<plan_id>`, as the operator typed it.
fn parse_approvals(given: &[String]) -> Result<Vec<(plan::ApprovalClass, String)>> {
    let mut out = Vec::new();
    for text in given {
        let Some((class, plan_id)) = text.split_once('=') else {
            anyhow::bail!(
                "{text:?} is not an approval. The form is `--approve <class>=<plan_id>`, and \
                 the plan id is the one the plan you read prints."
            );
        };
        out.push((plan::ApprovalClass::parse(class)?, plan_id.to_string()));
    }
    Ok(out)
}

/// Report a saved receipt or fold the journal when no receipt exists.
/// Verification reports additionally return blocked for failed required checks.
fn report(run: &str, repo: &Path, json: bool) -> Result<Answer> {
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

    // Verification runs use a ledger and checks instead of a deployment receipt.
    if files.exists(&state.verify_path(run)) {
        let text = files.read_to_string(&state.verify_path(run))?;
        let verification = meister_deploy::verify::VerifyRun::from_json(
            &text,
            &state.verify_path(run).display().to_string(),
        )?;
        if json {
            println!(
                "{}",
                serde_json::to_string_pretty(&meister_deploy::verify::report_json(&verification))?
            );
        } else {
            print!("{}", meister_deploy::verify::report_text(&verification));
        }
        let blocked = meister_deploy::verify::blocking(&verification);
        if blocked.is_empty() {
            eprintln!(
                "==> the {} suite passed every required check over {} host(s).",
                verification.suite,
                verification.hosts.len()
            );
            return Ok(Answer::Yes);
        }
        for reason in &blocked {
            eprintln!("    blocked: {reason}");
        }
        eprintln!(
            "==> {} required check(s) of the {} suite did not pass.",
            blocked.len(),
            verification.suite
        );
        return Ok(Answer::Blocked);
    }

    let journal_path = state.journal_path(run);
    let read = if files.exists(&journal_path) {
        Some(state::read_journal(&files, &journal_path)?)
    } else {
        None
    };

    // Prefer the saved receipt; otherwise derive an explicitly unfinished view.
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
                // Keep receipt provenance on stderr.
                eprintln!(
                    "note: run {run} wrote no receipt of its own, so this one was folded from \
                     its journal just now. The run has not ended."
                );
            }
        }
        (None, _) => {
            // Without the saved plan, show folded journal state instead of a receipt.
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
    Ok(Answer::Yes)
}

// ---------------------------------------------------------------------------
// lane 4B: verification
// ---------------------------------------------------------------------------

/// Run release-bound workload/fabric checks with recorded cleanup obligations.
fn verify(args: &VerifyArgs) -> Result<Answer> {
    use meister_deploy::verify::{self, Options, Suite, Verifier};

    if args.offline {
        anyhow::bail!(
            "a verification creates guests on the fleet and deletes them again, so there is \
             nothing it can do without reaching a control plane. `check --suite readiness` \
             is the verb that only reads, and it takes --offline."
        );
    }
    let suite = Suite::parse(&args.suite)?;
    let policy = if args.dry_run {
        Policy::dry_run()
    } else {
        Policy::real()
    };
    let files = RealFiles::new(policy);

    let text = files.read_to_string(&args.release)?;
    let release = ReleaseManifest::from_json(&text, &args.release.display().to_string())?;

    // Real verification needs release-bound approval; a dry-run needs none.
    if !args.dry_run {
        match verify_approval(&args.approve)? {
            Some(id) if id == release.release_id => {}
            Some(id) => anyhow::bail!(
                "the approval names {id} and this release is {}. An approval is for the \
                 bytes it was given, not for whatever is in the file today.",
                release.release_id
            ),
            None => anyhow::bail!(
                "this creates guests on the fleet. Say so: --approve verify={}",
                release.release_id
            ),
        }
    }

    let select = if args.host.is_empty() {
        args.select.clone()
    } else {
        args.host
            .iter()
            .map(|id| format!("host={id}"))
            .collect::<Vec<_>>()
            .join(",")
    };
    let selected = plan::select(&release.resolved_fleet, &select)?;
    let repo = args
        .repo
        .clone()
        .unwrap_or_else(|| PathBuf::from(&release.resolved_fleet.source.repo_path));
    let state = StateDir::in_repo(&repo);

    Cancel::on_sigint()?;
    let runner = Real::new(policy);

    // Use observations to establish reachability, detected capabilities and
    // whether results qualify as hardware evidence.
    let observation = match &args.observation {
        Some(path) => {
            let text = files.read_to_string(path)?;
            let snapshot =
                observation::Observations::from_json(&text, &path.display().to_string())?;
            eprintln!(
                "note: nothing was asked of any host. This is the snapshot of {}, and a \
                 fleet moves.",
                snapshot.taken_at.to_rfc3339()
            );
            snapshot
        }
        None => {
            let endpoints = match &args.targets {
                Some(path) => {
                    let text = files.read_to_string(path)?;
                    let targets =
                        observation::Targets::from_json(&text, &path.display().to_string())?;
                    observation::bind_targets(&release.resolved_fleet, &targets, &selected)?
                }
                None => observation::manifest_endpoints(&release.resolved_fleet, &selected)?,
            };
            let ssh = transport::Ssh::for_repo(&repo).with_identity(args.identity.clone());
            let prober = observe::SshProber::new(&runner, &ssh);
            let probes: Vec<observe::HostProbe> = selected
                .iter()
                .map(|id| {
                    observe::HostProbe::new(
                        transport::Target::from_endpoint(id, &endpoints[id]),
                        observe::ProbeSpec::for_host(&release.resolved_fleet.hosts[id]),
                    )
                })
                .collect();
            let snapshot = observe::observe_fleet(&prober, &probes, RealClock.now(), args.at_once)?;
            if !args.dry_run {
                state.create(&files)?;
                state.save_observation(&files, &snapshot, None)?;
            }
            snapshot
        }
    };

    let (control, note) = workload_control(&files, &release, args.inventory.as_deref());
    if let Some(note) = &note {
        eprintln!("note: {note}");
    }

    let run_id = meister_deploy::ids::run_id(RealClock.now()).to_string();
    let mut options = Options::new(&run_id, suite);
    options.budget = args.budget;
    options.deadline = std::time::Duration::from_secs(args.deadline);
    options.keep = args.keep;
    options.control = control;
    options.settle = std::time::Duration::from_secs(args.settle);
    options.poll = std::time::Duration::from_secs(args.poll.max(1));
    options.fabric = std::time::Duration::from_secs(args.fabric_deadline);
    options.pairs = parse_pairs(&args.pairs)?;

    let clock = RealClock;
    // Cleanup attempts continue after cancellation.
    let cleanup_runner = Real::new(policy).unstoppable();
    // Only RDMA measurements receive direct SSH transport; guest suites use the control plane.
    let ssh = transport::Ssh::for_repo(&repo).with_identity(args.identity.clone());
    let mut verifier = Verifier::new(
        &runner,
        &files,
        &clock,
        state,
        &release,
        &observation,
        selected.clone(),
        options,
    )
    .with_cleanup_runner(&cleanup_runner);
    if suite == Suite::Rdma {
        let endpoints = observation::manifest_endpoints(&release.resolved_fleet, &selected)?;
        verifier = verifier.over_ssh(&ssh, endpoints);
    }

    if args.dry_run {
        print!("{}", verify::listing(&verifier.steps()));
        eprintln!(
            "==> this is what `verify --suite {suite}` would do. Nothing was created and \
             nothing was written."
        );
        return Ok(Answer::Yes);
    }

    // Print the run ID before execution so interrupted runs remain identifiable.
    println!("{run_id}");
    let run = verifier.run()?;

    if args.json {
        println!("{}", String::from_utf8(run.to_json()?)?);
    } else {
        print!("{}", verify::summary(&run));
    }
    eprintln!("==> {}", run.ledger_path);

    match meister_deploy::checks::acceptance(&run.checks) {
        meister_deploy::checks::Acceptance::Blocked { reasons } => {
            for reason in &reasons {
                eprintln!("    blocked: {reason}");
            }
            eprintln!(
                "==> {} required check(s) of the {suite} suite did not pass.",
                reasons.len()
            );
            Ok(Answer::Blocked)
        }
        meister_deploy::checks::Acceptance::Accepted
            if run.outcome == meister_deploy::receipt::Outcome::Aborted =>
        {
            eprintln!(
                "==> the {suite} suite did not finish, so it answered nothing. What it had \
                 made was deleted; the ledger says what it held."
            );
            Ok(Answer::Blocked)
        }
        meister_deploy::checks::Acceptance::Accepted => {
            eprintln!(
                "==> the {suite} suite passed every required check over {} host(s).",
                run.hosts.len()
            );
            Ok(Answer::Yes)
        }
    }
}

/// `--pairs <a>:<b>`, as the operator typed it.
fn parse_pairs(given: &[String]) -> Result<Vec<(String, String)>> {
    let mut out = Vec::new();
    for text in given {
        let Some((a, b)) = text.split_once(':') else {
            anyhow::bail!(
                "{text:?} is not a pair. The form is `--pairs <server>:<client>`, two host                  ids of this fleet."
            );
        };
        if a.trim().is_empty() || b.trim().is_empty() {
            anyhow::bail!("{text:?} names only one end, and a fabric measurement has two.");
        }
        if a == b {
            anyhow::bail!(
                "{text:?} names {a} at both ends. A loopback measurement says nothing about                  a fabric between two machines."
            );
        }
        out.push((a.to_string(), b.to_string()));
    }
    Ok(out)
}

/// Parse release-bound verification approval separately from plan approvals.
fn verify_approval(given: &[String]) -> Result<Option<String>> {
    let mut found = None;
    for text in given {
        let Some((class, id)) = text.split_once('=') else {
            anyhow::bail!(
                "{text:?} is not an approval. The form is `--approve verify=<release_id>`, \
                 and the release id is the one `build` printed."
            );
        };
        if class != "verify" {
            anyhow::bail!(
                "{class:?} is not a class this verb takes. A verification has one: \
                 `--approve verify=<release_id>`."
            );
        }
        if id.trim().is_empty() {
            anyhow::bail!("{text:?} names no release id.");
        }
        found = Some(id.to_string());
    }
    Ok(found)
}


// ---------------------------------------------------------------------------
// lane 3B: keys
// ---------------------------------------------------------------------------

fn keys(cmd: &KeysCmd) -> Result<Answer> {
    match cmd {
        KeysCmd::Enroll {
            host,
            fingerprint,
            replace,
            reason,
            repo,
            fleet,
            manifest,
            dry_run,
            offline,
            json,
        } => keys_enroll(
            host,
            fingerprint,
            *replace,
            reason.as_deref(),
            repo,
            fleet,
            manifest.as_deref(),
            *dry_run,
            *offline,
            *json,
        )
        .map(Answer::from),
        KeysCmd::Csr {
            host,
            kind,
            as_kind,
            replace,
            manifest,
            repo,
            identity,
            dry_run,
            json,
        } => keys_csr(
            host,
            kind,
            as_kind.as_deref(),
            *replace,
            manifest,
            repo,
            identity.as_deref(),
            *dry_run,
            *json,
        )
        .map(Answer::from),
        KeysCmd::Issue {
            host,
            kind,
            csr,
            san,
            days,
            manifest,
            repo,
            inventory,
            meister_ca,
            dry_run,
            json,
        } => keys_issue(
            host,
            kind,
            csr.as_deref(),
            san,
            *days,
            manifest,
            repo,
            inventory.as_deref(),
            meister_ca,
            *dry_run,
            *json,
        )
        .map(Answer::from),
        KeysCmd::Revoke {
            serial,
            host,
            refresh,
            crl_reason,
            release,
            select,
            repo,
            inventory,
            meister_ca,
            identity,
            out,
            dry_run,
            json,
        } => keys_revoke(KeysRevokeArgs {
            serial: serial.as_deref(),
            host: host.as_deref(),
            refresh: *refresh,
            crl_reason: crl_reason.as_deref(),
            release,
            select,
            repo,
            inventory: inventory.as_deref(),
            meister_ca,
            identity: identity.clone(),
            out: out.clone(),
            dry_run: *dry_run,
            json: *json,
        }),
        KeysCmd::Rotate {
            host,
            kind,
            as_kind,
            days,
            release,
            repo,
            inventory,
            meister_ca,
            identity,
            out,
            dry_run,
            json,
        } => keys_rotate(KeysRotateArgs {
            host,
            kind,
            as_kind: as_kind.as_deref(),
            days: *days,
            release,
            repo,
            inventory: inventory.as_deref(),
            meister_ca,
            identity: identity.clone(),
            out: out.clone(),
            dry_run: *dry_run,
            json: *json,
        }),
        KeysCmd::Import {
            from,
            map,
            manifest,
            repo,
            inventory,
            meister_ca,
            dry_run,
            json,
        } => keys_import(KeysImportArgs {
            from,
            map,
            manifest,
            repo,
            inventory: inventory.as_deref(),
            meister_ca,
            dry_run: *dry_run,
            json: *json,
        }),
    }
}


/// Everything `keys import` was told.
struct KeysImportArgs<'a> {
    from: &'a Path,
    map: &'a [String],
    manifest: &'a Path,
    repo: &'a Path,
    inventory: Option<&'a Path>,
    meister_ca: &'a Path,
    dry_run: bool,
    json: bool,
}

/// What one mapping turned out to be.
#[derive(serde::Serialize)]
struct Imported {
    host: String,
    stem: String,
    kind: String,
    cn: String,
    serial: Option<String>,
    not_after: Option<String>,
    to: String,
    /// Sibling private-key metadata; key contents are not imported.
    private_key: String,
}

/// Check mappings and certificate subjects, then copy public certificates.
/// CA-directory validation and index rebuild occur after these copies.
fn keys_import(args: KeysImportArgs<'_>) -> Result<Answer> {
    use meister_deploy::effects::Entry;
    use meister_deploy::pki;

    let policy = if args.dry_run {
        Policy::dry_run()
    } else {
        Policy::real()
    };
    let files = RealFiles::new(policy);
    let runner = Real::new(policy);

    if args.map.is_empty() {
        anyhow::bail!(
            "nothing to import: say which file belongs to which host, once per certificate, \
             as `--map <host>=<stem>`. The stem is the file name without `.crt` — a lab that \
             issued `system-node-manacor.crt` for the host `manacor` is \
             `--map manacor=system-node-manacor`."
        );
    }
    let repo = &std::path::absolute(args.repo)
        .with_context(|| format!("{} could not be made absolute", args.repo.display()))?;
    let fleet = read_manifest(&files, args.manifest)?;

    // --- the mappings, before any file is touched ----------------------
    let mut seen: BTreeMap<String, String> = BTreeMap::new();
    for entry in args.map {
        let Some((host, stem)) = entry.split_once('=') else {
            anyhow::bail!(
                "{entry:?} is not a mapping. It is `<host id>=<file stem>`, for example \
                 `--map cloud-a=system-cloud-meister`."
            );
        };
        let (host, stem) = (host.trim(), stem.trim());
        if host.is_empty() || stem.is_empty() {
            anyhow::bail!("{entry:?} has an empty half.");
        }
        if !fleet.hosts.contains_key(host) {
            anyhow::bail!(
                "{} names no host {host:?}; it covers {}.",
                args.manifest.display(),
                fleet.evaluated_hosts.join(", ")
            );
        }
        if let Some(first) = seen.insert(host.to_string(), stem.to_string()) {
            anyhow::bail!(
                "{host} is mapped twice, to {first:?} and to {stem:?}. A host of this fleet \
                 holds ONE identity certificate and one serving certificate, and which is \
                 which comes off the subject — so two client certificates for one host is a \
                 question this tool cannot answer for you."
            );
        }
    }

    // --- read each one, and hold it to the fleet's own subject ---------
    let mut plan: Vec<(Imported, Vec<u8>)> = Vec::new();
    for (host, stem) in &seen {
        let crt = args.from.join(format!("{stem}.crt"));
        if !files.exists(&crt) {
            anyhow::bail!(
                "{} is not there. The directory holds: {}",
                crt.display(),
                match files.list_dir(args.from) {
                    Ok(entries) if !entries.is_empty() => entries
                        .iter()
                        .filter_map(|p| p.file_name())
                        .map(|n| n.to_string_lossy().into_owned())
                        .collect::<Vec<_>>()
                        .join(", "),
                    _ => "nothing this tool can read".to_string(),
                }
            );
        }
        let described = runner.run(&pki::describe_cmd("openssl", &crt))?;
        let issued = pki::parse_describe(&described.stdout, &crt.display().to_string());
        let subject = issued.subject.clone().ok_or_else(|| {
            anyhow::anyhow!(
                "openssl read {} and printed no subject, so nobody can say whose certificate \
                 it is. It is either not a certificate or not readable.",
                crt.display()
            )
        })?;
        let cn = pki::cn_of(&subject).ok_or_else(|| {
            anyhow::anyhow!(
                "{} has the subject {subject:?} and no CN in it. Every certificate this \
                 fleet checks is checked on its CN.",
                crt.display()
            )
        })?;
        let kind = pki::kind_from_cn(&cn);
        let wanted = pki::subject_for(&fleet, host, kind, &[])?;
        if wanted.cn != cn {
            anyhow::bail!(
                "{} carries CN={cn}, and a {kind} certificate of {host} in this fleet is \
                 CN={}. Either the mapping is wrong — that file belongs to another machine — \
                 or the fleet renamed something since it was issued. Nothing was copied.",
                crt.display(),
                wanted.cn
            );
        }

        // Inspect sibling key permissions without reading or copying the key.
        let key = args.from.join(format!("{stem}.key"));
        let private_key = match files.entry(&key) {
            Ok(Entry::File { mode }) if mode & 0o077 == 0 => {
                format!(
                    "{} is beside it, {:o}, and stays there",
                    key.display(),
                    mode
                )
            }
            Ok(Entry::File { mode }) => anyhow::bail!(
                "{} is mode {:o}: it is readable by somebody who is not its owner. This tool \
                 will not take the certificate of a key that is lying open — fix the mode \
                 (`chmod 600`) and decide whether the key has to be replaced, because \
                 anything that could read it may have.",
                key.display(),
                mode
            ),
            _ => format!(
                "{} is not here, which is right when the key is on the target",
                key.display()
            ),
        };

        let to = pki::issued_path(repo, host, &format!("{}.crt", kind.file_stem()));
        plan.push((
            Imported {
                host: host.clone(),
                stem: stem.clone(),
                kind: kind.as_str().to_string(),
                cn,
                serial: issued.serial.clone(),
                not_after: issued.not_after.clone(),
                to: to.display().to_string(),
                private_key,
            },
            files.read(&crt)?,
        ));
    }

    // --- and only now, the writes --------------------------------------
    if args.dry_run {
        for (what, _) in &plan {
            println!(
                "{} <- {}.crt  {} CN={} serial={}",
                what.to,
                what.stem,
                what.kind,
                what.cn,
                what.serial.as_deref().unwrap_or("?")
            );
        }
        eprintln!("note: nothing was written and the index was not rebuilt.");
        return Ok(Answer::Yes);
    }

    for (what, bytes) in &plan {
        let to = Path::new(&what.to);
        files.create_dir_all(to.parent().unwrap_or(repo))?;
        files.write_atomic(to, bytes, 0o644)?;
        eprintln!("==> {}", what.to);
    }

    // Copy a supplied CA certificate only when the configured CA has none.
    let inventory_file = match args.inventory {
        Some(path) => inventory_path(repo, path),
        None => Path::new(&fleet.source.repo_path).join(&fleet.source.inventory_path),
    };
    let parsed = Inventory::load(&files, &inventory_file)?;
    let named = parsed
        .operator
        .as_ref()
        .and_then(|o| o.ca_dir.clone())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "{} has no `[operator] ca_dir`, so this tool does not know which CA these \
                 certificates belong to — and the index that makes them revocable lives \
                 there.",
                inventory_file.display()
            )
        })?;
    let ca = pki::ca_dir(&inventory_file, &named);
    pki::refuse_ca_in_repo(repo, &ca)?;
    let ca_crt = args.from.join("ca.crt");
    if files.exists(&ca_crt) && !files.exists(&ca.join("ca.crt")) {
        let bytes = files.read(&ca_crt)?;
        files.create_dir_all(&ca)?;
        files.write_atomic(&ca.join("ca.crt"), &bytes, 0o644)?;
        eprintln!("==> {}", ca.join("ca.crt").display());
    }

    // Rebuild the configured CA index after import; existing revocations are retained.
    let rebuild = pki::index_rebuild_cmd(args.meister_ca, &ca);
    runner.run(&rebuild)?;
    eprintln!("==> {} (index rebuilt)", ca.display());

    let taken: Vec<&Imported> = plan.iter().map(|(what, _)| what).collect();
    if args.json {
        println!("{}", serde_json::to_string_pretty(&taken)?);
    } else {
        for what in &taken {
            println!(
                "{:<14} {:<8} CN={} serial={} until {}",
                what.host,
                what.kind,
                what.cn,
                what.serial.as_deref().unwrap_or("?"),
                what.not_after.as_deref().unwrap_or("?")
            );
        }
    }
    eprintln!(
        "note: {} certificate(s) are in this repository and in the CA's index. No private \
         key was read or copied: each one stays where it is, and the fleet's manifest calls \
         its source `target-generated`. Commit `{}`.",
        taken.len(),
        pki::ISSUED_DIR
    );
    Ok(Answer::Yes)
}



/// Everything `retire` was told.
struct RetireArgs<'a> {
    host: &'a str,
    release: &'a Path,
    reason: Option<&'a str>,
    crl_reason: Option<&'a str>,
    repo: &'a Path,
    inventory: Option<&'a Path>,
    meister_ca: &'a Path,
    identity: Option<PathBuf>,
    out: Option<PathBuf>,
    dry_run: bool,
    json: bool,
}

/// Revoke recorded active certificates, save retirement evidence, then plan
/// CRL delivery to other hosts. Target data and inventory are not removed.
fn retire(args: RetireArgs<'_>) -> Result<Answer> {
    use meister_deploy::pki;

    let policy = if args.dry_run {
        Policy::dry_run()
    } else {
        Policy::real()
    };
    let files = RealFiles::new(policy);
    let runner = Real::new(policy);

    // Validate the fixed CRL reason separately from the free-text retirement note.
    let crl_reason = args.crl_reason.unwrap_or("cessationOfOperation");
    pki::validate_crl_reason(crl_reason)?;

    let repo = &std::path::absolute(args.repo)
        .with_context(|| format!("{} could not be made absolute", args.repo.display()))?;
    let text = files.read_to_string(args.release)?;
    let release = ReleaseManifest::from_json(&text, &args.release.display().to_string())?;
    let fleet = &release.resolved_fleet;

    if !fleet.hosts.contains_key(args.host) {
        anyhow::bail!(
            "{} names no host {:?}; it covers {}. A host that is already out of the \
             inventory AND out of the last release has nothing left here to retire — the \
             record under `.meister-deploy/retired/` is what says one was.",
            args.release.display(),
            args.host,
            fleet.evaluated_hosts.join(", ")
        );
    }

    let inventory_file = match args.inventory {
        Some(path) => inventory_path(repo, path),
        None => Path::new(&fleet.source.repo_path).join(&fleet.source.inventory_path),
    };

    // Revoke the recorded active certificates; propagate listing failures.
    let certs = pki::issued_certs(&files, repo, args.host)?;
    let mut serials: Vec<String> = Vec::new();
    let mut ran: Vec<String> = Vec::new();
    if certs.is_empty() {
        eprintln!(
            "note: {} holds no certificate for {}, so there is nothing of its to take back \
             here. If it had one, revoke it by serial — the serial is in the receipt of the \
             run that delivered it (`report --run <id>`).",
            repo.join(pki::ISSUED_DIR).join(args.host).display(),
            args.host
        );
    } else {
        let parsed = Inventory::load(&files, &inventory_file)?;
        let named = parsed
            .operator
            .as_ref()
            .and_then(|o| o.ca_dir.clone())
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "{} has no `[operator] ca_dir`, so this tool does not know which CA \
                     holds the index a revocation is written into.",
                    inventory_file.display()
                )
            })?;
        let ca = pki::ca_dir(&inventory_file, &named);
        pki::refuse_ca_in_repo(repo, &ca)?;
        for cert in &certs {
            let what = cert.display().to_string();
            // Capture serials for the retirement record before revoking.
            if let Ok(out) = runner.run(&pki::describe_cmd("openssl", cert))
                && let Some(serial) = pki::parse_describe(&out.stdout, &what).serial
            {
                serials.push(serial);
            }
            let cmd = pki::revoke_cmd(args.meister_ca, &ca, &what, Some(crl_reason));
            ran.push(cmd.line());
            if args.dry_run {
                println!("{}", cmd.described());
            } else {
                runner.run(&cmd)?;
            }
        }
        let gencrl = pki::gencrl_cmd(args.meister_ca, &ca);
        ran.push(gencrl.line());
        if args.dry_run {
            println!("{}", gencrl.described());
        } else {
            runner.run(&gencrl)?;
            let bytes = files.read(&ca.join("crl.pem"))?;
            let here = pki::crl_path(repo);
            files.create_dir_all(here.parent().unwrap_or(repo))?;
            files.write_atomic(&here, &bytes, 0o644)?;
            eprintln!(
                "==> {} ({} certificate(s) taken back)",
                here.display(),
                certs.len()
            );
        }
    }

    // --- 2. the record, and the mark ----------------------------------
    let state = StateDir::in_repo(repo);
    let now = RealClock.now();
    let last_system = state
        .load_latest_observation(&files)
        .ok()
        .and_then(|o| o.host(args.host).and_then(|h| h.current_system.clone()));
    let record = state::Retired {
        schema: state::RETIRED_SCHEMA.to_string(),
        host: args.host.to_string(),
        retired_at: now,
        last_system,
        identity_serials: serials.clone(),
        reason: args.reason.map(str::to_string),
    };
    let ssh = transport::Ssh::for_repo(repo);
    let marked = if args.dry_run {
        eprintln!(
            "note: nothing was written. {} and the `# retired` line above {}'s entry in {} \
             are what a real run would add.",
            state.retired_path(args.host).display(),
            args.host,
            ssh.known_hosts.display()
        );
        false
    } else {
        let path = state.write_retired(&files, &record)?;
        eprintln!("==> {}", path.display());
        let name = pki::target_from_host(args.host, &fleet.hosts[args.host]).known_hosts_name();
        pki::mark_retired(&files, &ssh.known_hosts, &name, args.reason, now)?
    };

    // --- 3. the rest of the fleet -------------------------------------
    let select = format!("all,!host={}", args.host);
    let answer = if fleet.hosts.len() < 2 {
        eprintln!(
            "note: {} was the only host of this fleet, so there is nobody left to hand the \
             list to and no plan was made. The revocation is in the CA and in {}.",
            args.host,
            pki::crl_path(repo).display()
        );
        Answer::Yes
    } else if args.dry_run {
        eprintln!("note: a real run would plan the delivery of the new list to `{select}`.");
        Answer::Yes
    } else {
        make_plan(&PlanArgs {
            release: args.release.to_path_buf(),
            select: select.clone(),
            kind: "retire".to_string(),
            reinstall: false,
            targets: None,
            observation: None,
            offline: false,
            dry_run: false,
            repo: Some(repo.clone()),
            identity: args.identity.clone(),
            at_once: observe::DEFAULT_CONCURRENCY,
            inventory: Some(inventory_file.clone()),
            out: args.out.clone(),
        })?
    };

    if args.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "host": args.host,
                "retired_at": now,
                "revoked": serials,
                "known_hosts_marked": marked,
                "commands": ran,
                "record": state.retired_path(args.host).display().to_string(),
            }))?
        );
    }
    eprintln!(
        "note: nothing on {} was changed or deleted — not its data, not its keys, not its \
         line in {}. Take the host out of the inventory yourself when you are ready; until \
         you do, `status` calls it `unmanaged` and names this retirement.",
        args.host,
        inventory_file.display()
    );
    Ok(answer)
}


/// The manifest, read through the same parser `validate --manifest` uses.
fn read_manifest(files: &dyn Files, path: &Path) -> Result<manifest::ResolvedFleet> {
    let text = files.read_to_string(path)?;
    manifest::ResolvedFleet::from_json(&text, &path.display().to_string())
}

/// Choose the identity role. Multi-role hosts require explicit selection
/// and separate per-role paths for simultaneous authenticated tier identities.
fn identity_kind_of(
    host_id: &str,
    host: &manifest::ResolvedHost,
    asked: Option<&str>,
) -> Result<meister_deploy::pki::CaKind> {
    use meister_deploy::pki::{CaKind, identity_kinds};
    let candidates = identity_kinds(host);
    if let Some(asked) = asked {
        let kind = CaKind::parse(asked)?;
        if kind == CaKind::Serving {
            anyhow::bail!(
                "`--as serving` is not an identity: the serving certificate is its own file \
                 and its own request. Use `keys csr --host {host_id} --kind serving`."
            );
        }
        if !candidates.contains(&kind) {
            anyhow::bail!(
                "{host_id} carries the role(s) {} and cannot be a {kind}. It can be: {}.",
                host.roles.join(", "),
                candidates
                    .iter()
                    .map(|k| k.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }
        return Ok(kind);
    }
    match candidates.as_slice() {
        [] => anyhow::bail!(
            "{host_id} carries the role(s) {} and none of them has a service identity. Only \
             a cloud, a cluster or an agent dials anything.",
            host.roles.join(", ")
        ),
        [one] => Ok(*one),
        many => anyhow::bail!(
            "{host_id} carries {} and this fleet gives it ONE identity.key — every rendered \
             configuration names the same file. So it can hold one of {}, and which one is \
             your decision: pass `--as <kind>`. (A host that really has to be two tiers at \
             once needs two key files, and this fleet's modules do not render them.)",
            host.roles.join(" and "),
            many.iter()
                .map(|k| k.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        ),
    }
}

#[allow(clippy::too_many_arguments)]
fn keys_csr(
    host_id: &str,
    kind: &str,
    as_kind: Option<&str>,
    replace: bool,
    manifest_path: &Path,
    repo: &Path,
    identity: Option<&Path>,
    dry_run: bool,
    json: bool,
) -> Result<bool> {
    use meister_deploy::activate::KeyKind;
    use meister_deploy::pki;

    let policy = if dry_run {
        Policy::dry_run()
    } else {
        Policy::real()
    };
    let files = RealFiles::new(policy);
    let runner = Real::new(policy);

    let file_kind = KeyKind::parse(kind)?;
    let fleet = read_manifest(&files, manifest_path)?;
    let host = fleet.hosts.get(host_id).ok_or_else(|| {
        anyhow::anyhow!(
            "{} names no host {host_id:?}; it covers {}.",
            manifest_path.display(),
            fleet.evaluated_hosts.join(", ")
        )
    })?;
    let ca_kind = match file_kind {
        KeyKind::Serving => pki::CaKind::Serving,
        KeyKind::Identity => identity_kind_of(host_id, host, as_kind)?,
    };
    let subject = pki::subject_for(&fleet, host_id, ca_kind, &[])?;

    let target = pki::target_from_host(host_id, host);
    let ssh = transport::Ssh::for_repo(repo).with_identity(identity.map(Path::to_path_buf));
    let cmd = pki::keygen_cmd(&ssh, &target, &subject.cn, file_kind.as_str(), replace);

    if dry_run {
        println!("{}", cmd.described());
        eprintln!(
            "note: nothing was asked and nothing was written. The request would land in {}.",
            pki::csr_path(repo, host_id, file_kind.as_str()).display()
        );
        return Ok(true);
    }

    // Check enrollment before invoking target key generation.
    ssh.require_enrolled(&runner, &target)?;
    Cancel::on_sigint()?;
    let out = runner.run(&cmd)?;
    let reply = pki::parse_keygen(&out.stdout, host_id)?;

    let path = pki::csr_path(repo, host_id, file_kind.as_str());
    files.create_dir_all(path.parent().unwrap_or(repo))?;
    files.write_atomic(&path, reply.csr_pem.as_bytes(), 0o644)?;

    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "host": host_id,
                "kind": file_kind.as_str(),
                "certificate_kind": ca_kind.as_str(),
                "subject": subject.dn,
                "requested_name": reply.subject,
                "public_key_sha256": reply.public_key_sha256,
                "created": reply.created,
                "csr": path.display().to_string(),
            }))?
        );
        return Ok(true);
    }
    println!("{}", path.display());
    eprintln!(
        "==> {host_id}: {} ({}), key {}\n    {}\n    next: meister-deploy keys issue \
         --host {host_id} --kind {} --manifest {}",
        if reply.created {
            "a new key was made on the host"
        } else {
            "the key that was already there answered again"
        },
        subject.dn,
        reply.public_key_sha256,
        path.display(),
        ca_kind.as_str(),
        manifest_path.display()
    );
    Ok(true)
}

#[allow(clippy::too_many_arguments)]
fn keys_issue(
    host_id: &str,
    kind: &str,
    csr: Option<&str>,
    san: &[String],
    days: Option<u32>,
    manifest_path: &Path,
    repo: &Path,
    inventory: Option<&Path>,
    meister_ca: &Path,
    dry_run: bool,
    json: bool,
) -> Result<bool> {
    use meister_deploy::pki;

    let policy = if dry_run {
        Policy::dry_run()
    } else {
        Policy::real()
    };
    let files = RealFiles::new(policy);
    let runner = Real::new(policy);

    let ca_kind = pki::CaKind::parse(kind)?;
    // Normalize the repository path before checking CA placement.
    let repo = &std::path::absolute(repo)
        .with_context(|| format!("{} could not be made absolute", repo.display()))?;
    let fleet = read_manifest(&files, manifest_path)?;
    if !fleet.hosts.contains_key(host_id) {
        anyhow::bail!(
            "{} names no host {host_id:?}; it covers {}.",
            manifest_path.display(),
            fleet.evaluated_hosts.join(", ")
        );
    }
    let extra: Vec<String> = san
        .iter()
        .flat_map(|s| s.split(','))
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect();
    let subject = pki::subject_for(&fleet, host_id, ca_kind, &extra)?;

    // The CA directory, from the inventory the manifest names.
    let inventory_file = match inventory {
        Some(path) => inventory_path(repo, path),
        None => Path::new(&fleet.source.repo_path).join(&fleet.source.inventory_path),
    };
    let parsed = Inventory::load(&files, &inventory_file)?;
    let named = parsed
        .operator
        .as_ref()
        .and_then(|o| o.ca_dir.clone())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "{} has no `[operator] ca_dir`, so this tool does not know which CA to sign \
                 with. It is a REFERENCE and not a secret — the directory it names holds the \
                 CA key, and it belongs outside this repository.",
                inventory_file.display()
            )
        })?;
    let ca = pki::ca_dir(&inventory_file, &named);
    pki::refuse_ca_in_repo(repo, &ca)?;

    // Verify the CSR signature before checking its requested subject.
    let source = csr.map(str::to_string).unwrap_or_else(|| {
        pki::csr_path(repo, host_id, ca_kind.file_stem())
            .display()
            .to_string()
    });
    let csr_text = if source == "-" {
        let mut text = String::new();
        std::io::stdin()
            .read_to_string(&mut text)
            .context("reading the certificate request from standard input failed")?;
        text
    } else {
        files.read_to_string(Path::new(&source))?
    };
    let requested = pki::requested_name(&csr_text).map_err(|e| {
        anyhow::anyhow!(
            "{source} is not a certificate request this CA will sign: {e}. Nothing was \
             signed."
        )
    })?;
    if requested != subject.cn {
        anyhow::bail!(
            "{source} asks to be {requested:?} and a {kind} certificate for {host_id} is \
             {:?}. The CA writes its own subject either way, so signing this would produce a \
             certificate for the right name over a key that asked for another one — which \
             means the request probably came from a different host or a different kind. \
             `keys csr --host {host_id} --kind {}` makes the matching one.",
            subject.cn,
            ca_kind.file_stem()
        );
    }

    let out_path = pki::issued_path(repo, host_id, &format!("{}.crt", ca_kind.file_stem()));
    // Require revocation of an existing active certificate before issuing its replacement.
    if files.exists(&out_path) {
        let described = runner.run(&pki::describe_cmd("openssl", &out_path))?;
        let old = pki::parse_describe(&described.stdout, &out_path.display().to_string());
        let serial = old.serial.clone().unwrap_or_default();
        let revoked = pki::revoked_here(&files, repo, &serial)?;
        if revoked != Some(true) {
            anyhow::bail!(
                "{} already holds a {} certificate for {host_id} (serial {serial}){}. Issuing \
                 a second one over a new key would leave TWO certificates that answer to \
                 {:?}, and the fleet would accept either — which is what a machine that was \
                 reinstalled, or one whose key leaked, looks like from the outside. Take the \
                 old one back first:\n    meister-deploy keys revoke --host {host_id} \
                 --reason superseded --release <release.json> --out revoke.json\n    \
                 meister-deploy apply --plan revoke.json --release <release.json>\nand then \
                 issue this one.",
                out_path.display(),
                ca_kind.file_stem(),
                match revoked {
                    None => " and this repository publishes no revocation list",
                    Some(false) => " and it is not on this repository's revocation list",
                    Some(true) => unreachable!("it was taken back"),
                },
                subject.cn
            );
        }
    }
    let csr_on_disk = if source == "-" {
        // Persist stdin requests at the normal CSR path before invoking the CA.
        let kept = pki::csr_path(repo, host_id, ca_kind.file_stem());
        files.create_dir_all(kept.parent().unwrap_or(repo))?;
        files.write_atomic(&kept, csr_text.as_bytes(), 0o644)?;
        kept
    } else {
        PathBuf::from(&source)
    };
    let sign = pki::sign_cmd(meister_ca, &ca, &csr_on_disk, &subject, &out_path, days);

    if dry_run {
        println!("{}", sign.described());
        eprintln!(
            "note: nothing was signed. It would be {} and land in {}.",
            subject.dn,
            out_path.display()
        );
        return Ok(true);
    }

    files.create_dir_all(out_path.parent().unwrap_or(repo))?;
    runner.run(&sign)?;
    let described = runner.run(&pki::describe_cmd("openssl", &out_path))?;
    let issued = pki::parse_describe(&described.stdout, &out_path.display().to_string());

    if json {
        println!("{}", serde_json::to_string_pretty(&issued)?);
        return Ok(true);
    }
    println!("{}", out_path.display());
    eprintln!(
        "==> {host_id}: {} {}
    serial {}
    until  {}",
        subject.dn,
        out_path.display(),
        issued.serial.as_deref().unwrap_or("unknown"),
        issued.not_after.as_deref().unwrap_or("unknown")
    );
    eprintln!(
        "note: it reaches the host with `plan` and `apply` — the action `deliver-secret`. \
         There is no verb that puts a file on a machine outside a run: a second road past \
         the locks and the journal is what D6 exists to prevent."
    );
    Ok(true)
}

/// Resolve relative inventory paths against the repository.
fn inventory_path(repo: &Path, fleet: &Path) -> PathBuf {
    if fleet.is_absolute() {
        fleet.to_path_buf()
    } else {
        repo.join(fleet)
    }
}

#[allow(clippy::too_many_arguments)]
fn keys_enroll(
    host: &str,
    fingerprint: &str,
    replace: bool,
    reason: Option<&str>,
    repo: &Path,
    fleet: &Path,
    manifest: Option<&Path>,
    dry_run: bool,
    offline: bool,
    json: bool,
) -> Result<bool> {
    if offline {
        anyhow::bail!(
            "enrolling a host means asking it what key it shows, and --offline forbids \
             asking. There is nothing on this disk that could answer it: the whole point of \
             this step is that the machine and the person at its console say the same thing."
        );
    }
    let policy = if dry_run {
        Policy::dry_run()
    } else {
        Policy::real()
    };
    let files = RealFiles::new(policy);
    let runner = Real::new(policy);

    // Use the manifest endpoint when supplied; initial enrollment can use the inventory.
    let target = match manifest {
        Some(path) => {
            let text = files.read_to_string(path)?;
            let resolved = manifest::ResolvedFleet::from_json(&text, &path.display().to_string())?;
            let entry = resolved.hosts.get(host).ok_or_else(|| {
                anyhow::anyhow!(
                    "{} names no host {host:?}; it covers {}.",
                    path.display(),
                    resolved.evaluated_hosts.join(", ")
                )
            })?;
            meister_deploy::pki::target_from_host(host, entry)
        }
        None => {
            let path = inventory_path(repo, fleet);
            let inventory = Inventory::load(&files, &path)?;
            meister_deploy::pki::target_from_inventory(&inventory, host)?
        }
    };

    let known_hosts = repo.join("known_hosts");
    let done = meister_deploy::pki::enroll(
        &runner,
        &files,
        &known_hosts,
        &target,
        fingerprint,
        replace,
        reason,
        RealClock.now(),
    )?;

    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "host": done.host_id,
                "known_hosts_name": done.known_hosts_name,
                "fingerprint": done.fingerprint,
                "changed": done.changed,
                "replaced": done.replaced,
                "known_hosts": known_hosts.display().to_string(),
                "inventory_line": done.toml_line,
            }))?
        );
        return Ok(true);
    }

    if !done.changed {
        println!(
            "{} is already enrolled with {} in {}.",
            done.host_id,
            done.fingerprint,
            known_hosts.display()
        );
        return Ok(true);
    }
    if let Some(before) = &done.replaced {
        println!("{} replaced {before}", done.host_id);
    }
    println!(
        "{} {} -> {}",
        done.host_id,
        done.fingerprint,
        known_hosts.display()
    );
    // Print the fingerprint update for the operator; do not rewrite the inventory.
    eprintln!(
        "note: put this into the `[[host]]` block of {} for {}:\n    {}\nThen run `resolve` \
         again — the manifest carries the fingerprint the planner compares against, and it \
         has to say what {} says.",
        inventory_path(repo, fleet).display(),
        done.host_id,
        done.toml_line,
        known_hosts.display()
    );
    Ok(true)
}



/// Arguments for revocation and CRL delivery planning.
struct KeysRevokeArgs<'a> {
    serial: Option<&'a str>,
    host: Option<&'a str>,
    refresh: bool,
    crl_reason: Option<&'a str>,
    release: &'a Path,
    select: &'a str,
    repo: &'a Path,
    inventory: Option<&'a Path>,
    meister_ca: &'a Path,
    identity: Option<PathBuf>,
    out: Option<PathBuf>,
    dry_run: bool,
    json: bool,
}

/// Revoke locally and publish the CRL before planning its delivery.
fn keys_revoke(args: KeysRevokeArgs<'_>) -> Result<Answer> {
    use meister_deploy::pki;

    let policy = if args.dry_run {
        Policy::dry_run()
    } else {
        Policy::real()
    };
    let files = RealFiles::new(policy);
    let runner = Real::new(policy);

    let asked = [args.serial.is_some(), args.host.is_some(), args.refresh]
        .iter()
        .filter(|x| **x)
        .count();
    if asked != 1 {
        anyhow::bail!(
            "say what is being taken back: `--serial <s>` (one certificate), `--host <id>` \
             (every active certificate this repository holds for that host; a `.prev`/`.next` \
             certificate mid-rotation is revoked separately, by serial) or `--refresh` (take \
             nothing back and write the list again). Exactly one of the three."
        );
    }

    // Validate the CRL reason before invoking the CA.
    let crl_reason = args.crl_reason.unwrap_or("unspecified");
    pki::validate_crl_reason(crl_reason)?;

    let repo = &std::path::absolute(args.repo)
        .with_context(|| format!("{} could not be made absolute", args.repo.display()))?;
    let text = files.read_to_string(args.release)?;
    let release = ReleaseManifest::from_json(&text, &args.release.display().to_string())?;
    let fleet = &release.resolved_fleet;

    // Resolve the configured CA and reject placement inside the repository.
    let inventory_file = match args.inventory {
        Some(path) => inventory_path(repo, path),
        None => Path::new(&fleet.source.repo_path).join(&fleet.source.inventory_path),
    };
    let parsed = Inventory::load(&files, &inventory_file)?;
    let named = parsed
        .operator
        .as_ref()
        .and_then(|o| o.ca_dir.clone())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "{} has no `[operator] ca_dir`, so this tool does not know which CA holds the \
                 index a revocation is written into.",
                inventory_file.display()
            )
        })?;
    let ca = pki::ca_dir(&inventory_file, &named);
    pki::refuse_ca_in_repo(repo, &ca)?;

    // Use certificate paths for recorded hosts, or an explicitly supplied serial.
    let mut targets: Vec<String> = Vec::new();
    if let Some(serial) = args.serial {
        targets.push(serial.to_string());
    }
    if let Some(host_id) = args.host {
        if !fleet.hosts.contains_key(host_id) {
            anyhow::bail!(
                "{} names no host {host_id:?}; it covers {}.",
                args.release.display(),
                fleet.evaluated_hosts.join(", ")
            );
        }
        // Propagate listing failures instead of treating them as no certificates.
        let certs = pki::issued_certs(&files, repo, host_id)?;
        if certs.is_empty() {
            anyhow::bail!(
                "{} holds no certificate for {host_id}, so there is nothing of its to take \
                 back. If the machine was reinstalled and its old certificate is gone from \
                 here too, revoke it by serial: it is in the receipt of the run that \
                 delivered it (`report --run <id>`), and in the log of whatever it dialled.",
                repo.join(pki::ISSUED_DIR).join(host_id).display()
            );
        }
        targets.extend(certs.iter().map(|p| p.display().to_string()));
    }

    let mut ran: Vec<String> = Vec::new();
    for what in &targets {
        let cmd = pki::revoke_cmd(args.meister_ca, &ca, what, Some(crl_reason));
        ran.push(cmd.line());
        if args.dry_run {
            println!("{}", cmd.described());
        } else {
            runner.run(&cmd)?;
        }
    }
    let gencrl = pki::gencrl_cmd(args.meister_ca, &ca);
    ran.push(gencrl.line());
    if args.dry_run {
        println!("{}", gencrl.described());
        eprintln!(
            "note: nothing was revoked and no plan was made. {} would be written and copied \
             to {}.",
            ca.join("crl.pem").display(),
            pki::crl_path(repo).display()
        );
        return Ok(Answer::Yes);
    }
    runner.run(&gencrl)?;

    // Publish the public CRL in the repository for planned delivery.
    let published = ca.join("crl.pem");
    let bytes = files.read(&published)?;
    let here = pki::crl_path(repo);
    files.create_dir_all(here.parent().unwrap_or(repo))?;
    files.write_atomic(&here, &bytes, 0o644)?;
    let described = runner.run(&pki::crl_describe_cmd("openssl", &here))?;
    let summary: BTreeMap<String, String> = described
        .stdout
        .lines()
        .filter_map(|l| l.split_once('='))
        .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
        .collect();

    eprintln!(
        "==> {}\n    crl number {}  next update {}\n    {} certificate(s) taken back in this run",
        here.display(),
        summary.get("crlNumber").map(String::as_str).unwrap_or("?"),
        summary.get("nextUpdate").map(String::as_str).unwrap_or("?"),
        targets.len()
    );

    // Build a delivery plan; apply performs the host changes.
    let answer = make_plan(&PlanArgs {
        release: args.release.to_path_buf(),
        select: args.select.to_string(),
        kind: "keys-revoke".to_string(),
        reinstall: false,
        targets: None,
        observation: None,
        offline: false,
        dry_run: false,
        repo: Some(repo.clone()),
        identity: args.identity.clone(),
        at_once: observe::DEFAULT_CONCURRENCY,
        inventory: Some(inventory_file.clone()),
        out: args.out.clone(),
    })?;

    if args.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "crl": here.display().to_string(),
                "crl_number": summary.get("crlNumber"),
                "next_update": summary.get("nextUpdate"),
                "revoked": targets,
                "commands": ran,
            }))?
        );
    }
    eprintln!(
        "note: the list is in the repository and in the CA. It reaches the hosts with \
         `apply --plan <the plan above>`; until it has, the certificates are taken back \
         here and nowhere else. Commit `{}`.",
        pki::CRL_FILE
    );
    Ok(answer)
}

/// Everything `keys rotate` was told.
struct KeysRotateArgs<'a> {
    host: &'a str,
    kind: &'a str,
    as_kind: Option<&'a str>,
    days: Option<u32>,
    release: &'a Path,
    repo: &'a Path,
    inventory: Option<&'a Path>,
    meister_ca: &'a Path,
    identity: Option<PathBuf>,
    out: Option<PathBuf>,
    dry_run: bool,
    json: bool,
}

/// Prepare a target-local replacement key and locally signed certificate
/// before creating the plan that binds them.
fn keys_rotate(args: KeysRotateArgs<'_>) -> Result<Answer> {
    use meister_deploy::activate::KeyKind;
    use meister_deploy::pki;

    let policy = if args.dry_run {
        Policy::dry_run()
    } else {
        Policy::real()
    };
    let files = RealFiles::new(policy);
    let runner = Real::new(policy);

    let file_kind = KeyKind::parse(args.kind)?;
    let repo = &std::path::absolute(args.repo)
        .with_context(|| format!("{} could not be made absolute", args.repo.display()))?;
    let text = files.read_to_string(args.release)?;
    let release = ReleaseManifest::from_json(&text, &args.release.display().to_string())?;
    let fleet = &release.resolved_fleet;
    let host = fleet.hosts.get(args.host).ok_or_else(|| {
        anyhow::anyhow!(
            "{} names no host {:?}; it covers {}.",
            args.release.display(),
            args.host,
            fleet.evaluated_hosts.join(", ")
        )
    })?;
    let ca_kind = match file_kind {
        KeyKind::Serving => pki::CaKind::Serving,
        KeyKind::Identity => identity_kind_of(args.host, host, args.as_kind)?,
    };
    let subject = pki::subject_for(fleet, args.host, ca_kind, &[])?;

    // The CA, from the inventory, and never inside the repository.
    let inventory_file = match args.inventory {
        Some(path) => inventory_path(repo, path),
        None => Path::new(&fleet.source.repo_path).join(&fleet.source.inventory_path),
    };
    let parsed = Inventory::load(&files, &inventory_file)?;
    let named = parsed
        .operator
        .as_ref()
        .and_then(|o| o.ca_dir.clone())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "{} has no `[operator] ca_dir`, so this tool does not know which CA to sign \
                 the new certificate with.",
                inventory_file.display()
            )
        })?;
    let ca = pki::ca_dir(&inventory_file, &named);
    pki::refuse_ca_in_repo(repo, &ca)?;

    let target = pki::target_from_host(args.host, host);
    let ssh = transport::Ssh::for_repo(repo).with_identity(args.identity.clone());
    // Replace any staged .next key while leaving the active key in place.
    let keygen =
        pki::keygen_beside_cmd(&ssh, &target, &subject.cn, file_kind.as_str(), true, "next");
    let csr_at = pki::next_csr_path(repo, args.host, file_kind.as_str());
    let crt_at = pki::next_issued_path(repo, args.host, file_kind.as_str());
    let relative = Path::new(pki::ISSUED_DIR)
        .join(args.host)
        .join(format!("{}.next.crt", file_kind.as_str()));

    if args.dry_run {
        println!("{}", keygen.described());
        eprintln!(
            "note: nothing was made and nothing was signed. The request would land in {} and \
             the certificate in {}.",
            csr_at.display(),
            crt_at.display()
        );
        return Ok(Answer::Yes);
    }

    ssh.require_enrolled(&runner, &target)?;
    Cancel::on_sigint()?;
    let made = runner.run(&keygen)?;
    let reply = pki::parse_keygen(&made.stdout, args.host)?;
    files.create_dir_all(csr_at.parent().unwrap_or(repo))?;
    files.write_atomic(&csr_at, reply.csr_pem.as_bytes(), 0o644)?;

    // Signed here, with the CA key that never leaves this machine.
    files.create_dir_all(crt_at.parent().unwrap_or(repo))?;
    let sign = pki::sign_cmd(args.meister_ca, &ca, &csr_at, &subject, &crt_at, args.days);
    runner.run(&sign)?;
    let described = runner.run(&pki::describe_cmd("openssl", &crt_at))?;
    let issued = pki::parse_describe(&described.stdout, &crt_at.display().to_string());
    let bytes = files.read(&crt_at)?;
    let cert_sha256 = format!("sha256:{}", meister_deploy::ids::sha256_hex(&bytes));

    let rotation = pki::rotation_of(
        host,
        pki::Prepared {
            host_id: args.host,
            kind: file_kind.as_str(),
            subject: &subject.cn,
            public_key_sha256: &reply.public_key_sha256,
            cert_sha256: &cert_sha256,
            serial: issued.serial.clone(),
            source: &relative,
        },
    )?;

    // Bind the prepared credential to a single-host rotation plan.
    let select = format!("host={}", args.host);
    let endpoints = observation::manifest_endpoints(fleet, &[args.host.to_string()])?;
    let prober = observe::SshProber::new(&runner, &ssh);
    let probe = observe::HostProbe::new(
        transport::Target::from_endpoint(args.host, &endpoints[args.host]),
        observe::ProbeSpec::for_host(host),
    );
    let observation = observe::observe_fleet(&prober, &[probe], RealClock.now(), 1)?;
    let state = StateDir::in_repo(repo);
    let kept = state.save_observation(&files, &observation, None)?;
    eprintln!("==> {}", kept.display());

    let plan = plan::plan(
        &release,
        &select,
        &observation,
        None,
        &plan::PlanPolicy::new(PlanKind::KeysRotate).with_rotations(
            [(args.host.to_string(), rotation.clone())]
                .into_iter()
                .collect(),
        ),
        RealClock.now(),
    )?;

    match &args.out {
        Some(path) => {
            files.write_atomic(path, &plan.to_json()?, 0o644)?;
            println!("{}", plan.plan_id);
            eprintln!("==> {}", path.display());
        }
        None => print!("{}", String::from_utf8(plan.to_json()?)?),
    }
    if args.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "host": args.host,
                "kind": file_kind.as_str(),
                "subject": subject.dn,
                "public_key_sha256": reply.public_key_sha256,
                "certificate": crt_at.display().to_string(),
                "serial": issued.serial,
                "not_after": issued.not_after,
                "plan_id": plan.plan_id,
            }))?
        );
    }
    eprint!("{}", plan_summary(&plan));
    eprintln!(
        "note: nothing on {} has changed yet. The new key lies beside the one in use and \
         nothing reads it; `apply` is what puts it in, and it can be interrupted after any \
         of the five phases. Commit {} and {}.",
        args.host,
        csr_at.display(),
        crt_at.display()
    );
    Ok(if plan.is_blocked() {
        Answer::Blocked
    } else {
        Answer::Yes
    })
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

/// Format timestamps in UTC to second precision.
fn stamp(at: Option<chrono::DateTime<chrono::Utc>>) -> String {
    at.map(|t| t.format("%Y-%m-%dT%H:%M:%SZ").to_string())
        .unwrap_or_else(|| "-".to_string())
}

/// Return the final store-path component for display.
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

/// Compare parsed TOML and Nix inventory host sets and fleet name.
/// This does not evaluate or build host systems.
fn validate_with_nix(fleet: &Path) -> Result<bool> {
    let fleet = std::path::absolute(fleet)
        .with_context(|| format!("{} could not be made absolute", fleet.display()))?;
    // Use the inventory directory as the operator flake root.
    let repo = fleet
        .parent()
        .ok_or_else(|| anyhow::anyhow!("{} has no directory to evaluate", fleet.display()))?;

    let policy = Policy::real();
    let files = RealFiles::new(policy);
    let inventory = Inventory::load(&files, &fleet)?;

    Cancel::on_sigint()?;
    let runner = Real::new(policy);
    // Evaluate the Git-backed flake to exclude ignored files from the source.
    // This check does not capture a revision as resolve does.
    let flake_ref = nix::flake_ref(repo, false, None);
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

/// Default ignored directory for private signing keys; commit signing.pub separately.
const KEYS_DIR: &str = "keys";

/// Write the embedded template into a new directory and attempt nix flake lock.
fn init(dir: &Path, flake_ref: Option<&str>, dry_run: bool) -> Result<bool> {
    let dir = std::path::absolute(dir)
        .with_context(|| format!("{} could not be made absolute", dir.display()))?;

    if dry_run {
        // Preview paths without creating them.
        for file in template::FILES {
            println!("{}", dir.join(file.path).display());
        }
        println!("{}", dir.join(".meister-deploy").display());
        println!("{}", dir.join(KEYS_DIR).display());
        eprintln!(
            "note: --dry-run wrote nothing. {} file(s) and two directories would be \
             created; `nix flake lock` would then be run in {}.",
            template::FILES.len(),
            dir.display()
        );
        return Ok(true);
    }

    let policy = Policy::real();
    let files = RealFiles::new(policy);

    // Refuse existing content; init does not merge repositories.
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

    // Override only the MeisterStack flake reference.
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
    // Create ignored local deployment state.
    let state = dir.join(".meister-deploy");
    files.create_dir_all(&state)?;
    println!("{}", state.display());

    // Create the ignored private-key directory required by the signing-key command.
    let keys = dir.join(KEYS_DIR);
    files.create_dir_all(&keys)?;
    println!("{}", keys.display());

    // Let Nix create flake.lock; report failure without inventing a lock file.
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
        // Read piped contract JSON without requiring a temporary file.
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
                // Schema validation does not inspect store paths or hosts.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_run_that_stopped_does_not_exit_zero() {
        use receipt::Outcome;
        // A committed activation followed by failed uncordon must fail the run.
        assert_eq!(answer_for(Outcome::Success, true, true), Answer::No);
        // A stopped run remains a failure even if other hosts were blocked.
        assert_eq!(answer_for(Outcome::Success, false, true), Answer::No);
        // Completed runs distinguish success, blockers and partial failure.
        assert_eq!(answer_for(Outcome::Success, true, false), Answer::Yes);
        assert_eq!(answer_for(Outcome::Success, false, false), Answer::Blocked);
        assert_eq!(answer_for(Outcome::Partial, true, false), Answer::No);
    }
}
