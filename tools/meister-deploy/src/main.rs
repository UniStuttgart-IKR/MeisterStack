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
        /// Take the evaluation from this `nix-manifest/1` file instead of
        /// running `nix eval` here. For a workstation that cannot evaluate
        /// the flake — a build machine did it, or a test VM was handed the
        /// answer. The SOURCE is still read from the repository below, so
        /// the fingerprint is this tree's and not the file's.
        #[arg(long)]
        from: Option<PathBuf>,
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

    // --- lane 3A: media -------------------------------------------------
    /// Build one medium of one host out of a release: the installer ISO, a
    /// prebuilt disk, or the bundle a hypervisor is handed. Evaluates
    /// nothing and asks no host anything.
    Image(ImageArgs),

    /// Prepare the first installation of a host: build its medium, keep it
    /// where the collector cannot take it, and print the sheet somebody
    /// carries to the machine. Destroys nothing — the disk is formatted at
    /// the target, by a person, with `meister-install confirm`.
    Install(InstallArgs),
    // --- end lane 3A ----------------------------------------------------
    /// Work out which hosts may be taken forward, in which order, and what
    /// has to still be true when it happens. Reads a release and a snapshot
    /// of the fleet; asks no host anything of its own.
    Plan(PlanArgs),

    /// Drop the garbage-collector roots of all but the newest N releases,
    /// and optionally trim the snapshots and the finished runs. Removes no
    /// store path: whether an unprotected closure goes is `nix store gc`'s
    /// decision.
    Gc {
        /// How many releases keep their roots
        #[arg(long, default_value_t = state::DEFAULT_KEEP_RELEASES)]
        keep: usize,
        // --- lane 4C: the other two things that pile up -----------------
        /// A second guard: nothing younger than this many days is removed,
        /// however far down the list it is. The recommended retention is
        /// `--keep 3 --older-than 14`.
        #[arg(long, value_name = "DAYS")]
        older_than: Option<i64>,
        /// Also keep only the newest N snapshots under `observations/`.
        /// Without it they are left alone; `latest.json` is never removed.
        #[arg(long, value_name = "N")]
        observations: Option<usize>,
        /// Also remove finished run directories. Never a run that did not
        /// end `success`, and never one that wrote no receipt: those are
        /// the ones somebody has to read.
        #[arg(long)]
        runs: bool,
        // --- end lane 4C ------------------------------------------------
        /// The operator's repository, which is where the state directory is
        #[arg(long, default_value = ".")]
        repo: PathBuf,
        /// Say what would go, and remove nothing
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

    /// Carry out a plan: stage the closures, take the hosts through the
    /// machine of §6 one wave at a time, and write the journal and the
    /// receipt that say what happened.
    Apply(ApplyArgs),

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

    // --- lane 4B: verification ------------------------------------------
    /// Make the fleet do the thing it exists for: create guests through the
    /// operator's own control plane, read what they printed, and delete
    /// them again. Writes a ledger before every create, and takes back only
    /// what it made.
    Verify(VerifyArgs),
    // --- end lane 4B ----------------------------------------------------
    // --- lane 3B: enrolment and certificates (one block, one verb) -----
    /// Host keys and certificates: enrol a machine against a fingerprint
    /// somebody read off its console, ask it for a certificate request, and
    /// have `tools/meister-ca` sign one. Puts nothing on a host — that is
    /// the plan's `deliver-secret`, and `apply` carries it out.
    Keys {
        #[command(subcommand)]
        cmd: KeysCmd,
    },
    // --- end lane 3B ---------------------------------------------------

    // --- lane 5B: taking a host out of service --------------------------
    /// Take a host out of service: take its certificates back, tell the
    /// fleet, and write down that it happened.
    ///
    /// What it does NOT do is as much the point as what it does. No data is
    /// deleted, no file on the machine is touched, no disk is wiped and the
    /// `known_hosts` line stays where it is — a retirement is a statement
    /// this fleet makes about a machine, not something it does to one. The
    /// machine may be off, may be stolen, may be on somebody's desk; none of
    /// that changes what has to be true here, which is that nothing it
    /// presents is believed any more.
    ///
    /// The host leaves the inventory when the OPERATOR deletes its lines.
    /// This verb never edits `fleet.toml`: an inventory a tool rewrites is
    /// an inventory whose diff says nothing.
    Retire {
        /// The host id, as the inventory and the release spell it
        host: String,
        /// The release the delivery plan is made from
        #[arg(long)]
        release: PathBuf,
        /// Why — it lands in the record and above the `known_hosts` line
        #[arg(long)]
        reason: Option<String>,
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
    // --- end lane 5B ----------------------------------------------------
}

// --- lane 3B: the `keys` verbs ------------------------------------------

#[derive(Subcommand)]
enum KeysCmd {
    /// Write a host's key into `<repo>/known_hosts`, after checking it
    /// against the fingerprint you typed.
    ///
    /// The fingerprint comes from the machine's console, its BMC or the
    /// installer's own output — never from this command. That is the whole
    /// point: `ssh-keyscan` reports whatever answers on the address, and
    /// believing it would make an impersonating host self-certifying.
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
        /// The operator's repository: its `known_hosts` is the file that is
        /// written, and its inventory says where the host is
        #[arg(long, default_value = ".")]
        repo: PathBuf,
        /// The inventory, relative to the repository or absolute
        #[arg(short = 'f', long, default_value = "fleet.toml")]
        fleet: PathBuf,
        /// A manifest from `resolve`, when there is one. A host that was
        /// never resolved is read out of the inventory instead — which is
        /// the normal case, because enrolment comes before the first
        /// `resolve` of a fresh machine.
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

    /// Ask a host for a certificate request over a key it makes itself.
    ///
    /// The private half is generated on the target and stays there; what
    /// comes back is the request, which lands under `<repo>/pki/csr/`.
    /// Running it twice does not make a second identity — the host keeps
    /// its key and answers with another request over it.
    Csr {
        /// The host id
        #[arg(long)]
        host: String,
        /// Which key: `identity` (what the host dials with) or `serving`
        /// (what a client checks its address against)
        #[arg(long, default_value = "identity")]
        kind: String,
        /// Which identity, for a host that carries more than one tier:
        /// node, cluster or cloud. One role means one answer and this can
        /// be left out.
        #[arg(long = "as", value_name = "KIND")]
        as_kind: Option<String>,
        /// Make a NEW key on the target although one is there. A rotation
        /// or a reinstall, never a repair.
        #[arg(long)]
        replace: bool,
        /// The manifest from `resolve`: it says where the host is and what
        /// its subject would be
        #[arg(long)]
        manifest: PathBuf,
        /// The operator's repository: its `known_hosts` is what the
        /// connection is checked against, and the request lands under it
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

    /// Sign a request with the fleet's CA, on this machine alone.
    ///
    /// The subject is this tool's decision and not the request's: a request
    /// is a public key and a wish. The CA key stays in `[operator] ca_dir`
    /// and never reaches a host.
    ///
    /// No network and therefore no `--offline`: signing needs nothing but
    /// this computer, so there is nothing for that flag to refuse.
    Issue {
        /// The host the certificate is for
        #[arg(long)]
        host: String,
        /// node | cluster | cloud | serving
        #[arg(long)]
        kind: String,
        /// The request. `-` reads it from standard input; without it, the
        /// one `keys csr` left under `<repo>/pki/csr/`.
        #[arg(long)]
        csr: Option<String>,
        /// Extra subject alternative names for `--kind serving`, comma
        /// separated. The host name and its management address are always
        /// in.
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
    // --- end lane 3B ----------------------------------------------------

    // --- lane 5A: taking one back ---------------------------------------
    /// Take a certificate back, and plan the delivery of the list that says
    /// so.
    ///
    /// Two halves, and they are separate on purpose. The CA writes the
    /// revocation into its own index and publishes a list — that happens
    /// here, offline, on this machine. Getting the list to the hosts is a
    /// PLAN, like every other thing this tool does to a machine, so it goes
    /// through `apply`, the locks and the journal.
    ///
    /// The list takes effect without restarting anything: a controller looks
    /// at its file again within half a minute, refuses the serials on it,
    /// and ends the sessions that are already running on one.
    Revoke {
        /// The serial to take back, in any of its spellings: `6435C9…` as
        /// openssl prints it, `64:35:c9:…` as a controller's log does.
        #[arg(long)]
        serial: Option<String>,
        /// Every ACTIVE certificate this repository holds for that host --
        /// its identity and its serving certificate are the same machine's
        /// two credentials. This is what a reinstall needs. A `.prev` or
        /// `.next` certificate left over from an in-progress rotation is
        /// not included; take that one back by `--serial` (Astra finding
        /// F11, 2026-09-23).
        #[arg(long)]
        host: Option<String>,
        /// Take nothing back: write the list again. A CRL has a lifetime
        /// (30 days), and one that has run out is a list a verifier may
        /// refuse; this is how it is renewed.
        #[arg(long)]
        refresh: bool,
        /// keyCompromise | superseded | cessationOfOperation | …
        #[arg(long)]
        reason: Option<String>,
        /// The release the delivery plan is made from
        #[arg(long)]
        release: PathBuf,
        /// Which hosts the list goes to. Every host that reads one, by
        /// default — a revocation nobody was told about is not one.
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
    /// Rotate a key: make a new one on the host, have it signed here, and
    /// write the plan that puts it in.
    ///
    /// Nothing is put anywhere by this verb. What it does is the half that
    /// cannot be planned — the key is made on the machine that will use it,
    /// and the certificate is issued on the machine that holds the CA — and
    /// then it writes a plan of five steps: prepare, overlap, switch,
    /// verify, remove. `apply` carries them out, one at a time, and a run
    /// that is interrupted picks up at the phase the host is actually at.
    Rotate {
        /// The host id
        #[arg(long)]
        host: String,
        /// Which key: `identity` (what this host dials with) or `serving`
        /// (what a client checks its address against)
        #[arg(long, default_value = "identity")]
        kind: String,
        /// Which identity, for a host that carries more than one tier:
        /// node, cluster or cloud
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
    // --- end lane 5A ----------------------------------------------------

    // --- lane 5B: certificates that are already there -------------------
    /// Take certificates a CA of this fleet already issued into this
    /// repository, so that they can be planned, compared and taken back.
    ///
    /// For a fleet that existed before this tool did. The certificates are
    /// under whatever fixed names the old road gave them
    /// (`system-node-<host>.crt`, `system-cluster-<group>.crt`), and this
    /// verb is the mapping from those names to host ids — typed by a person,
    /// because a file name is not an identity and guessing which machine a
    /// certificate belongs to is exactly the mistake that ends in a host
    /// presenting somebody else's name.
    ///
    /// The PRIVATE half is never copied, never read and never delivered. A
    /// key that is already on a machine stays on that machine; what arrives
    /// here is the public certificate, and `secret_refs` calls its source
    /// `target-generated` — which is the truth: this workstation did not
    /// make it and cannot make it again.
    ///
    /// No network, and therefore no `--offline`.
    Import {
        /// The directory the certificates are in
        #[arg(long)]
        from: PathBuf,
        /// `<host id>=<file stem>`, once per certificate. The stem is the
        /// file name without `.crt`.
        #[arg(long = "map", value_name = "HOST=STEM")]
        map: Vec<String>,
        /// The manifest from `resolve`: it says what each host's subject
        /// would be, which is what an imported certificate is held to
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
    // --- end lane 5B ----------------------------------------------------
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

    // --- lanes 5B + 5C: one flag, two readers ---
    /// The inventory. Two things are read out of it: the `[operator]
    /// cli_config` reference (D7, lane 5C) and the list of hosts the fleet
    /// still has, so that a host in the release but not in the inventory
    /// is `unmanaged` (V25, lane 5B). Defaults to the file the manifest was
    /// resolved from. `plan` and `apply` take the same flag and mean the
    /// same thing by it.
    #[arg(long)]
    inventory: Option<PathBuf>,
    // --- end lanes 5B + 5C ---
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

// --- lane 4B: verification ------------------------------------------------

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

    /// `<a>:<b>`, for the rdma suite: measure between exactly these two,
    /// with the server end first. Repeatable. Without it, every pair the
    /// inventory declares among the selected hosts is measured.
    #[arg(long)]
    pairs: Vec<String>,

    /// How long ONE fabric measurement may take, in seconds.
    #[arg(long, default_value_t = meister_deploy::verify::FABRIC_DEADLINE.as_secs())]
    fabric_deadline: u64,

    /// `verify=<release_id>`. The approval names the RELEASE and not a
    /// plan: this verb rolls nothing out, so there is no plan for an
    /// approval to hang on, and what somebody is saying yes to is guests
    /// being created against the fleet running THIS release.
    #[arg(long)]
    approve: Vec<String>,

    /// The most guests that may be alive at once. One is created on its own
    /// first, so a host sees `1 + budget` of them.
    #[arg(long, default_value_t = meister_deploy::verify::BUDGET)]
    budget: usize,

    /// The whole run, in seconds. When it passes, the guests are deleted
    /// and the outcome is `aborted`.
    #[arg(long, default_value_t = meister_deploy::verify::DEADLINE.as_secs())]
    deadline: u64,

    /// How long ONE guest gets to reach a phase, in seconds. A guest that
    /// boots in a second still needs a control plane that answers, so this
    /// is a wait on the answer rather than on the guest.
    #[arg(long, default_value_t = meister_deploy::verify::SETTLE.as_secs())]
    settle: u64,

    /// How often to ask, in seconds, while waiting.
    #[arg(long, default_value_t = meister_deploy::verify::POLL.as_secs())]
    poll: u64,

    /// Leave the guests standing instead of deleting them, and say which.
    /// A suite that deleted nothing has not shown a lifecycle, so every
    /// delete is then `skipped` and a required suite is blocked.
    #[arg(long)]
    keep: bool,

    /// A `targets/1` file from a provider adapter: where each host answers
    #[arg(long)]
    targets: Option<PathBuf>,

    /// A snapshot from `status`, instead of asking the hosts again
    #[arg(long)]
    observation: Option<PathBuf>,

    /// The operator's repository: its `known_hosts` is what every
    /// connection is checked against, and its state directory is where the
    /// ledger goes. Defaults to the one the manifest was resolved from.
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

// --- end lane 4B ----------------------------------------------------------

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

    // --- lane 4C: what nix is handed and where the result goes ----------
    /// How many derivations nix may build at once: a number, or `auto`.
    /// Passed on unread and recorded in the release.
    #[arg(long)]
    max_jobs: Option<String>,

    /// A nix setting with no flag of its own: `--option <name> <value>`.
    /// Repeatable, recorded in the release.
    #[arg(long, num_args = 2, value_names = ["NAME", "VALUE"])]
    option: Vec<String>,

    /// Push the signed closures into this nix store once they are built:
    /// `file:///srv/cache`, `s3://bucket`, `ssh-ng://host`. Recorded in the
    /// release as `build_env.cache_url`. A host fetches from it only if its
    /// own `meisterstack.managed.substituters` names it.
    #[arg(long)]
    cache: Option<String>,

    /// Build every host's system a SECOND time and let nix compare, so that
    /// the release's `bit_identical_verified` is a measurement. Expensive
    /// by construction — it is the whole fleet, twice — and without it the
    /// release says `false` with `method: null`, which is "nobody checked".
    #[arg(long)]
    verify_reproducible: bool,
    // --- end lane 4C ----------------------------------------------------
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

// --- lane 3A: media -------------------------------------------------------
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

    /// Link the result into this directory, under a name that says which
    /// host it belongs to
    #[arg(short = 'o', long)]
    out: Option<PathBuf>,

    /// The operator's repository, whose state directory keeps the
    /// garbage-collector root. Defaults to the one the manifest was resolved
    /// from.
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

    /// The release the plan was made for. Required and checked, like
    /// `apply`: the medium is built out of the derivation the RELEASE
    /// names, and another build is another release.
    #[arg(long)]
    release: PathBuf,

    /// Which host's medium
    #[arg(long)]
    host: String,

    /// `--approve destructive=<plan_id>`. The plan's own id, so an approval
    /// cannot be carried over from a plan somebody read yesterday.
    #[arg(long = "approve")]
    approve: Vec<String>,

    /// Link the medium here as well, for writing to a stick
    #[arg(short = 'o', long)]
    out: Option<PathBuf>,

    /// The operator's repository, whose state directory keeps the medium
    /// and its collector root. Defaults to the one the manifest was
    /// resolved from.
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
// --- end lane 3A ----------------------------------------------------------

#[derive(Args)]
struct ApplyArgs {
    /// The plan from `plan`. Optional with `--resume`, which reads the
    /// copy the run itself wrote.
    #[arg(long)]
    plan: Option<PathBuf>,

    /// The release the plan was made for. Checked: a plan names the bytes
    /// it is about, and another build is another plan. Optional with
    /// `--resume`, for the same reason as `--plan`.
    #[arg(long)]
    release: Option<PathBuf>,

    /// `--approve <class>=<plan_id>`, once per class the plan asks for.
    /// The id is the plan's own, so an approval cannot be carried over
    /// from one somebody read yesterday.
    #[arg(long = "approve")]
    approve: Vec<String>,

    /// Continue the run with this id: its journal is folded and every host
    /// is asked where it got to. Nothing irreversible is ever repeated.
    #[arg(long)]
    resume: Option<String>,

    /// Take over the per-host locks of this run — after a fresh
    /// observation and a re-validation, and never because time has passed.
    #[arg(long)]
    takeover: Option<String>,

    /// The operator's repository: its `known_hosts` is what every
    /// connection is checked against and its state directory is where the
    /// journal goes. Defaults to the one the manifest was resolved from.
    #[arg(long)]
    repo: Option<PathBuf>,

    /// The ssh key to offer
    #[arg(long)]
    identity: Option<PathBuf>,

    /// The inventory the `[operator] cli_config` reference is read from
    /// (D7). Defaults to the one the manifest was resolved from.
    #[arg(long)]
    inventory: Option<PathBuf>,

    /// How long to wait for a host to be empty of guests, in seconds
    #[arg(long, default_value_t = 600)]
    drain_wait: u64,

    /// How long to wait for a host to come back from a reboot, in seconds
    #[arg(long, default_value_t = 600)]
    reboot_wait: u64,

    /// Look at the fleet, check the plan against it, print the steps — and
    /// take no lock, copy nothing, write no journal
    #[arg(long)]
    dry_run: bool,

    /// Print the receipt as json instead of as a table
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

    /// `upgrade`, `bootstrap` or `install`
    #[arg(long, default_value = "upgrade")]
    kind: String,

    // --- lane 3A: first installation ---
    /// With `--kind install`: plan an installation over a host that already
    /// answers and runs a system. It destroys that machine's data, its host
    /// key and its machine id, and it is part of the plan id — so an
    /// approval for a plan without it can never be used for one with it.
    #[arg(long)]
    reinstall: bool,
    // --- end lane 3A ---
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
        // --- lane 3A: media ---
        Verb::Image(args) => image(args).map(Answer::from),
        Verb::Install(args) => install(args),
        // --- end lane 3A ---
        Verb::Status(look) => status(look),
        Verb::Check { look, suite } => check(look, suite),
        Verb::Plan(args) => make_plan(args),
        Verb::Gc {
            keep,
            // --- lane 4C ---
            older_than,
            observations,
            runs,
            // --- end lane 4C ---
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
        // --- lane 4B ---------------------------------------------------
        Verb::Verify(args) => verify(args),
        // --- end lane 4B -----------------------------------------------
        // --- lane 3B ---------------------------------------------------
        Verb::Keys { cmd } => keys(cmd),
        // --- end lane 3B -----------------------------------------------
        // --- lane 5B ---------------------------------------------------
        Verb::Retire {
            host,
            release,
            reason,
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
            repo,
            inventory: inventory.as_deref(),
            meister_ca,
            identity: identity.clone(),
            out: out.clone(),
            dry_run: *dry_run,
            json: *json,
        }),
        // --- end lane 5B -----------------------------------------------
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
        // --- lane 4B ---
        "verify-ledger" => schemars::schema_for!(meister_deploy::verify::Ledger),
        "verify" => schemars::schema_for!(meister_deploy::verify::VerifyRun),
        // --- end lane 4B ---
        other => anyhow::bail!(
            "there is no schema called {other:?}; this tool knows nix-manifest, \
             resolved-fleet, release, observation, activate-status, targets, plan, \
             status, receipt, journal-event, check-result, verify and verify-ledger."
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
    // Absolute, because `source.repo_path` in the manifest has to mean the
    // same thing to whoever reads it later.
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

    let mut tree = source::describe(&runner, &files, &repo, fleet, dev)?;
    // Where the evaluation comes from. Two roads, one result: the flake is
    // evaluated here, or an evaluation of it was handed over. What is NOT
    // handed over is the SOURCE — `tree` above is this repository, read
    // with git, so a manifest still names the tree it came from and a dirty
    // one is still refused. What the manifest then says about the
    // difference is `source.provided_evaluation`, because it is the one
    // thing a later reader could not work out.
    let (evaluated, origin) = match from {
        Some(path) => {
            let text = files.read_to_string(path)?;
            let origin = path.display().to_string();
            // The same door `validate --manifest` opens, so that a file
            // handed to this flag is read by the same parser and refused
            // with the same sentence — including a file that is a manifest
            // of the WRONG kind, which is the likely mistake.
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
            let flake_ref = nix::flake_ref(&tree.eval_dir, dev);
            let text = nix::eval_manifest(&runner, &flake_ref, selection)?;
            let origin = format!("{flake_ref}#{}", nix::MANIFEST_ATTR);
            (NixManifest::from_json(&text, &origin)?, origin)
        }
    };
    // --- lab finding W3 ---
    // The evaluation names the inventory it read by content; this command
    // read the file `-f` names. If they differ, `source.inventory_path` would
    // point at a file nobody evaluated, and everything that reads the
    // inventory back through the manifest (`keys issue` and its `[operator]
    // ca_dir`, `plan`'s cli_config, `apply`) would read the wrong one.
    // Measured in the lab on 2026-09-23: the flake evaluated `lab.toml`, the
    // default `fleet.toml` went into the manifest, and `keys issue` created a
    // CA under that file's `ca_dir`. An evaluation that was handed over
    // (`--from`) is allowed to be older than the file — the placeholder host
    // keys of a VM test are exactly that — so there it is a warning.
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
    // --- end lab finding W3 ---
    let resolved = manifest::resolve(evaluated, tree.source, tool(), RealClock.now(), selection)?;

    files.write_atomic(out, &resolved.to_json()?, 0o644)?;
    // The id on stdout and nothing else, so that it can be captured; where
    // it went goes to stderr like every other diagnostic.
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
    // --- lane 5B ---
    /// Selected hosts that the inventory does not have any more. They are
    /// listed, not probed and not judged (V25).
    unmanaged: BTreeSet<String>,
    // --- end lane 5B ---
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

    // --- lane 5B: which of these hosts the fleet still has --------------
    //
    // A release is a photograph of an inventory at a moment. When a host
    // leaves the inventory, every release that was built before the edit
    // still names it — so `status --release r.json` would go on asking a
    // machine that is nobody's any more, and a `check` would go on
    // requiring it. Reading the inventory beside the release is what closes
    // that gap, and it is READ-ONLY: what the release says about a host
    // stays what it says.
    let inventory_file = match &args.inventory {
        Some(path) => inventory_path(&repo, path),
        None => Path::new(&fleet.source.repo_path).join(&fleet.source.inventory_path),
    };
    let unmanaged: BTreeSet<String> = match Inventory::load(&files, &inventory_file) {
        // The name first, and it is not a formality. The default path comes
        // out of the manifest (`source.repo_path`), which is where `resolve`
        // RAN — on another machine, or after somebody moved a directory,
        // that path can point at a different fleet's inventory, and reading
        // one would declare every host of this release `unmanaged` on the
        // strength of a file about something else. So: same fleet, or no
        // answer.
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
            // Not a failure: a status of a fleet whose inventory is not
            // here (a release handed to somebody else, a build machine) is
            // still a status. What it cannot say is which hosts left.
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
    // --- end lane 5B ----------------------------------------------------

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
    // --- lane 5B ---
    for id in &unmanaged {
        checks.push(readiness::unmanaged(
            id,
            state.read_retired(&files, id).as_ref(),
        ));
    }
    checks.extend(service_checks(&Real::new(policy), &fleet, args.offline));
    // --- end lane 5B ---
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

// --- lane 5B: the services this fleet does not deploy ---------------------

/// How long one service endpoint has to answer.
const SERVICE_DEADLINE_SECS: u64 = 5;

/// Ask every unmanaged service of the inventory whether it is there.
///
/// One `curl` per declared endpoint, effect `read`, five seconds each. Not
/// an HTTP client in this crate: a tool that only ever has to know "did
/// something answer at this address" does not need to learn HTTP, and the
/// one command it shells out to is on every machine that can reach the
/// fleet anyway. When it is not, or when the run is offline, the verdict is
/// `unknown` and says which of the two it was.
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
        // Every declared endpoint, and the first silence wins: a service
        // whose push address answers and whose query address does not is
        // not a service that is there.
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
                // Any status code is an answer: a Loki push endpoint says
                // 405 to a GET, and 405 means somebody is there. What this
                // check is about is reachability, and claiming to know what
                // a foreign service's 200 would mean would be a claim about
                // somebody else's software.
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

// --- end lane 5B ----------------------------------------------------------

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

// --- lane 5C ---
/// What `check` does NOT look at, said out loud.
///
/// Two lab findings in one sentence (L2 §10, 4 and 14). `check` did not
/// take `--inventory` at all — `error: unexpected argument` — and it does
/// not read `[operator] cli_config`, so a fleet that is green here may
/// still be a fleet no rollout can drain: an agent with guests on it is
/// `blocked` in every plan until that reference exists (D7). An operator
/// who reads "every required check passed" after a bootstrap has not been
/// told that.
///
/// A note on stderr and never a verdict: this verb reports readiness, and
/// whether the operator's own cli is reachable is not a property of the
/// fleet.
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
// --- end lane 5C ---

fn check(args: &LookArgs, suite: &str) -> Result<Answer> {
    if suite != "readiness" {
        anyhow::bail!(
            // --- lane 4B: the verb it points at now exists ---
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
    // --- lane 5C ---
    note_about_the_workload_reference(args, &looked);
    // --- end lane 5C ---
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
            // --- lane 5B: three answers, not two ---
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
    // Then the ones that matter, once each, with what they expected.
    for check in &looked.checks {
        // --- lane 5B ---
        // `managed` is the one `not_applicable` that is printed: it does not
        // block anything (that is the point of the class) and its sentence
        // is the only place a reader learns why a host in this release is
        // not being asked anything.
        if check.status == Status::Pass
            || (check.status == Status::NotApplicable && check.id != "managed")
        {
            continue;
        }
        // --- end lane 5B ---
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
             derivations in ONE `nix build`, signs them{} and writes --out.",
            // --- lane 4C ---
            match &args.cache {
                Some(cache) => format!(", pushes them into {cache}"),
                None => String::new(),
            } // --- end lane 4C ---
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
            // --- lane 4C ---
            max_jobs: args.max_jobs.clone(),
            options: nix_options(&args.option)?,
            cache: args.cache.clone(),
            verify_reproducible: args.verify_reproducible,
            // --- end lane 4C ---
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
    // --- lane 4C ---
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
    // --- end lane 4C ---
    Ok(true)
}

/// Where the manifest was resolved from, as an absolute path.
fn repo_of(resolved: &manifest::ResolvedFleet) -> PathBuf {
    PathBuf::from(&resolved.source.repo_path)
}

// --- lane 4C --------------------------------------------------------------

/// `--option <name> <value>`, repeated, as the pairs nix is handed.
///
/// A map and not a list: nix takes the last value for a repeated setting,
/// so two `--option cores` on one command line are one setting, and a
/// release that recorded both would be recording a question rather than an
/// answer. The same name twice with different values is therefore refused
/// here rather than silently narrowed.
fn nix_options(flat: &[String]) -> Result<std::collections::BTreeMap<String, String>> {
    let mut out: std::collections::BTreeMap<String, String> = std::collections::BTreeMap::new();
    for pair in flat.chunks(2) {
        // clap's `num_args = 2` guarantees the pairing; the match is here
        // because a slice does not carry that guarantee into the types.
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

// --- end lane 4C ----------------------------------------------------------

// --- lane 3A: media -------------------------------------------------------

/// `image --release r.json --host <id> --kind installer|disk|direct-boot`.
///
/// One derivation out of the release, built, measured, rooted. It evaluates
/// nothing: the derivation path IS the evaluation the release was made from,
/// so a medium built here belongs to that release and not to whatever the
/// operator's flake says today.
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

    // A medium can take an hour to build, and a Ctrl-C has to reach it.
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

/// `install --plan p.json --release r.json --host <id> --approve destructive=<plan_id>`.
///
/// It prepares an installation and carries none out. What it does is build
/// the medium, put it where a collector cannot take it, write down what it
/// is, and print the sheet somebody reads standing in front of the machine.
/// The disk is destroyed there, by a person, by `meister-install confirm` —
/// which is why `apply` refuses an `install` action and this verb exists
/// beside it.
///
/// The approval is asked for all the same, and it is the plan's own id:
/// somebody has said "yes, this machine, this disk" before a medium that
/// will format it is written anywhere.
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

    // The approval, and it is the plan's own id.
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

    // Beside the link, so that the next `install` — and whoever picks this
    // up tomorrow — can say which plan and which release this medium is.
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

// --- end lane 3A ----------------------------------------------------------

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

// --- lane 4C --------------------------------------------------------------

/// Stop keeping what this state directory no longer has a reason to keep.
///
/// Three kinds of thing and three rules — releases by count and age,
/// snapshots by count and age, runs only when asked and never one that is
/// evidence. The decision is made whole before anything is removed
/// (`state::sweep`), so `--dry-run` prints exactly what a real run does.
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
    // Why each thing stayed, because "nothing happened" is the answer an
    // operator most often has to act on — a run that is still there is a
    // run that failed, and that is worth reading rather than guessing at.
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

// --- end lane 4C ----------------------------------------------------------

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
        // --- lane 3A: first installation ---
        "install" => PlanKind::Install,
        // --- end lane 3A ---
        // --- lane 5A ---
        // The delivery half of a revocation. `keys revoke` builds one after
        // it has written the list; this door is for the other order — a
        // certificate somebody took back with `meister-ca` by hand, and a
        // fleet that has to be told.
        "keys-revoke" => PlanKind::KeysRevoke,
        // --- end lane 5A ---
        // --- lane 5B ---
        // The delivery half of a retirement, for the same reason
        // `keys-revoke` has a door here: `retire <host>` builds one after it
        // has taken the certificates back, and this is the other order.
        "retire" => PlanKind::Retire,
        // --- end lane 5B ---
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
    // --- lane 3A ---
    if args.reinstall && kind != PlanKind::Install {
        anyhow::bail!(
            "--reinstall belongs to `plan --kind install`: it says that a disk which already \
             carries an installation may be destroyed. An upgrade never touches a partition \
             table."
        );
    }
    // --- end lane 3A ---

    let (control, note) = workload_control(&files, &release, args.inventory.as_deref());
    if let Some(note) = note {
        eprintln!("note: {note}");
    }
    // --- lane 3B: what this workstation has for the hosts ---------------
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
    // --- end lane 3B ----------------------------------------------------
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

/// What this workstation holds for each selected host's secrets (lane 3B).
///
/// The certificates `keys issue` wrote under `<repo>/pki/issued/`, and the
/// operator files under `[operator] ca_dir`. Hashed where they may be
/// hashed and named `present` where they may not — the asymmetry is
/// `crate::pki::expected_for_host`, and the read-only probe of 2A fills the
/// other side of the comparison the same way round.
///
/// A file that is not there is simply absent from the answer, and so is a
/// whole fleet whose inventory could not be read: the planner turns the
/// absence into a blocked host with the verb to run in the sentence, which
/// is more useful than refusing to make a plan.
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
        // An unusable selector is the planner's sentence to make, not this
        // function's.
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

/// `[operator] ca_dir`, resolved against the inventory that named it.
///
/// `None` when there is no inventory to read or it names none. That is an
/// answer and not a failure: a plan whose host is missing a file it cannot
/// find is blocked with a sentence, which is more useful than a verb that
/// refuses to run.
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
    // A relative `--inventory` hangs off the repository, the same rule
    // `--fleet` follows everywhere else; without one, the file the manifest
    // was resolved from.
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

// ---------------------------------------------------------------------------
// apply
// ---------------------------------------------------------------------------

/// Carry out a plan.
///
/// Four things happen here and the fifth is deliberately absent:
///
/// 1. the plan and the release are read and checked against each other —
///    a plan names the bytes it is about;
/// 2. the state directory's lock is taken for this run, which is the
///    single-writer contract of D6 for this WORKSTATION (the fleet's own
///    anchor is the per-host lock the executor takes);
/// 3. [`meister_deploy::execute`] walks the plan;
/// 4. the receipt is written and printed, and the exit code says what it
///    came to.
///
/// What is absent: a `--force`. There is `--approve <class>=<plan_id>`, and
/// an approval names the plan it is for.
fn apply(args: &ApplyArgs) -> Result<Answer> {
    let policy = if args.dry_run {
        Policy::dry_run()
    } else {
        Policy::real()
    };
    let files = RealFiles::new(policy);

    // --- lane 5C ---
    // Where the two documents come from. Named on the command line, or —
    // with `--resume` and nothing named — out of the run's own directory,
    // where `apply` put them when the run began.
    //
    // The lab needed this (finding N10): a run stopped, the operator built
    // again over the same `--out` file, and the release the run had acted
    // on was gone. There was no supported way to continue it.
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
    // --- end lane 5C ---

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

    // Ctrl-C has to reach the child: a `nix copy` of a nine-gigabyte closure
    // or a `switch-to-configuration` on the other side of an ssh is what is
    // running when somebody presses it.
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

    // --- lane 4A: an approval nobody granted is blocked, not broken ------
    //
    // `Executor::run` refuses the same thing and goes on refusing it; this
    // is the door in front of it and it exists only for the EXIT CODE. §5
    // says 2 is "blocked", and a rollout waiting for a person to say yes is
    // the plainest case of it there is. Read as 1 it cannot be told from
    // "this tool fell over", which is the distinction the third exit code
    // was introduced for (2B). Nothing is taken and nothing is written on
    // this path: the lock below is not reached.
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
    // --- end lane 4A -----------------------------------------------------

    // The workstation's door. Taken before anything is looked at, given back
    // whatever happens below.
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
    // The id on stdout and nothing else, so that a script can capture it and
    // `report --run` it afterwards.
    println!("{run_id}");

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
    // --- lane 3B: where the files this run may have to deliver are ------
    options.repo = repo.clone();
    options.ca_dir = ca_directory(&files, &release, Some(&repo), args.inventory.as_deref());
    // --- end lane 3B ----------------------------------------------------

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

    // The lock goes back whatever happened, and a failure to give it back is
    // a note rather than the error somebody reads: the run's own outcome is
    // the interesting one.
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
    // --- lane 3-integration: the halt ------------------------------------
    //
    // On stdout and on one line, whatever `--json` says: the thing that
    // reads this is the launcher that will do the loading and the
    // rebooting, and it must not have to parse a table or a sentence for
    // three store paths. (stdout already carries the run id on a line of
    // its own, so a second line is the shape this verb already has.)
    if let Some(wait) = &applied.waiting {
        println!("{}", serde_json::to_string(&wait.to_json())?);
        eprintln!(
            "==> {} is waiting for its provider. Nothing else was started.",
            wait.host
        );
        // An answer, not a failure: exit 2 is what this tool says when it
        // worked and the fleet is not where the plan wants it yet.
        return Ok(Answer::Blocked);
    }
    // --- end lane 3-integration -------------------------------------------
    // --- lane 5C: what a run that did not come through leaves behind ------
    if applied.receipt.outcome != receipt::Outcome::Success {
        eprint!("{}", what_is_left(&applied.receipt, &state, &run_id));
    }
    // --- end lane 5C ------------------------------------------------------
    match (applied.receipt.outcome, applied.blocked.is_empty()) {
        (receipt::Outcome::Success, true) => Ok(Answer::Yes),
        // It worked, and the plan refused to touch something. Exit 2 is
        // "blocked", which a script can tell from "this tool broke".
        (receipt::Outcome::Success, false) => Ok(Answer::Blocked),
        _ => Ok(Answer::No),
    }
}

// --- lane 5C ---
/// The three things a run that did not come through leaves in three
/// places, and the one sentence that was missing: how to get out.
///
/// From the lab (L2 §10, finding 8): "Ein gescheiterter Lauf hinterlaesst
/// drei Dinge an drei Orten: die Operator-Sperre im Repo, einen
/// Txn-Record auf dem Ziel und eine halbe Zeile im Journal. Die Meldungen
/// erklaeren jede einzeln gut; was fehlt, ist der eine Satz 'so kommst du
/// hier raus'." Each of those messages arrives when somebody runs into the
/// thing; none of them is printed by the run that made it.
///
/// Pure, so the wording is a test rather than a thing somebody reads once
/// on a bad evening.
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
// --- end lane 5C ---

/// Look, check, and say what would be done.
///
/// No lock, no journal, no receipt — and the runner's policy refuses every
/// command that is not a read, so this is a property of the program rather
/// than a promise made here.
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

    // --- lane 4B: a run may be a verification rather than a rollout ---
    //
    // The two write into the same run directory and are read by the same
    // verb, because they are the same question — what did this run do and
    // what did it find. A verification has no journal and no receipt; it has
    // a ledger and a set of checks, and its report draws the one line that
    // matters: what came off hardware, and what did not.
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
    // --- end lane 4B --------------------------------------------------

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
    Ok(Answer::Yes)
}

// ---------------------------------------------------------------------------
// lane 4B: verification
// ---------------------------------------------------------------------------

/// `verify --release r.json --suite <s> --approve verify=<release_id>`.
///
/// The one verb of this tool that makes something on the fleet which is not
/// part of the fleet: guests, so that the answer to "does this work" is a
/// guest that booted rather than a unit that is active. Everything it makes
/// it writes down first and takes back afterwards, and what it could not take
/// back is a check rather than a silence.
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

    // The approval names the release, because that is what is being verified.
    // A dry run creates nothing, so it needs none — and saying so is more
    // use than making somebody paste an id to read a listing.
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

    // What the machines ARE, as opposed to what the inventory says they are.
    // It decides three things: whether a host can be asked anything at all,
    // whether a declared capability is actually there, and — the one that
    // keeps a report honest — whether a guest that ran counts as hardware
    // evidence.
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
    // The one runner an interrupt does not reach, for the one piece of work
    // an interrupt ASKS for: taking the guests back. Everything else in this
    // verb goes through `runner` and stops when the operator says stop.
    let cleanup_runner = Real::new(policy).unstoppable();
    // The rdma suite is the one that reaches the hosts themselves: it runs a
    // server on one end and a client on the other. The guest suites talk to
    // a control plane and to nothing else, and are given no transport at all
    // so that they cannot.
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

    // The run id first and on its own line, like `apply`: a script that has
    // to read the ledger afterwards needs it even when the run went badly.
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

/// `--approve verify=<release_id>`, as the operator typed it.
///
/// Its own parser and not [`parse_approvals`]: the classes of that one are a
/// plan's, and a `verify` approval names a release. Spelling it `verify=` on
/// purpose, so that a person who has both commands in their shell history
/// cannot paste one into the other and have it taken.
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

// --- end lane 4B ----------------------------------------------------------

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
        // --- lane 5A ---
        KeysCmd::Revoke {
            serial,
            host,
            refresh,
            reason,
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
            reason: reason.as_deref(),
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
        // --- end lane 5A ---
        // --- lane 5B ---
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
        // --- end lane 5B ---
    }
}

// --- lane 5B: certificates that are already there -------------------------

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
    /// What was found beside the certificate, and what was done about it —
    /// which is nothing, in every case.
    private_key: String,
}

/// Take certificates this fleet's CA already issued into the repository.
///
/// Every refusal happens before anything is written, and they are all the
/// same refusal in different clothes: a certificate is an identity, and one
/// that lands under the wrong host id is a machine that can speak as
/// another. So the subject on the file has to be the subject this fleet
/// would have issued for the host it is being mapped to, and if it is not,
/// the mapping is wrong and nothing is copied.
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

        // The private half. It is LOOKED AT and nothing else: not read, not
        // copied, not delivered. A key that is already on a machine belongs
        // on that machine, and a key that travelled through a workstation
        // is a key somebody has to assume is on the workstation.
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

    // The CA's own certificate, if this directory has one and the CA
    // directory does not. Not overwritten: a CA that already has one is a
    // CA whose trust anchor is not this import's business.
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

    // And the index. Without it `meister-ca --revoke` has nothing to write
    // into, so an imported certificate would be one this fleet can check
    // and never take back. The rebuild is additive (M0 finding 7): a
    // revocation that is already recorded stays recorded.
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

// --- end lane 5B ----------------------------------------------------------

// --- lane 5B: retiring a host ---------------------------------------------

/// Everything `retire` was told.
struct RetireArgs<'a> {
    host: &'a str,
    release: &'a Path,
    reason: Option<&'a str>,
    repo: &'a Path,
    inventory: Option<&'a Path>,
    meister_ca: &'a Path,
    identity: Option<PathBuf>,
    out: Option<PathBuf>,
    dry_run: bool,
    json: bool,
}

/// Take a host out of service.
///
/// Three things happen here and they are in this order on purpose:
///
/// 1. the active certificates this repository holds for the host are taken
///    back and a new list is written and published (offline, on this
///    machine) -- a `.prev`/`.next` certificate mid-rotation is not one of
///    them; see `issued_certs` (Astra finding F11, 2026-09-23);
/// 2. the record and the `known_hosts` mark are written, so that the
///    retirement survives everything else;
/// 3. a plan is made that carries the new list to the REST of the fleet.
///
/// The host itself is not in that plan (`all,!host=<id>`) and nothing is
/// sent to it. A machine that is being retired may be off, may be broken,
/// may be somebody else's problem already — and a verb that needed it to
/// answer would be a verb that cannot retire the one host you most want to.
///
/// Nothing is deleted: not a partition, not a data directory, not the
/// certificate files on the machine, not the `known_hosts` line, not the
/// lines in `fleet.toml`. The last of those is the operator's edit, and
/// `status` says `unmanaged` about the gap until it is made.
fn retire(args: RetireArgs<'_>) -> Result<Answer> {
    use meister_deploy::pki;

    let policy = if args.dry_run {
        Policy::dry_run()
    } else {
        Policy::real()
    };
    let files = RealFiles::new(policy);
    let runner = Real::new(policy);

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

    // --- 1. the certificates ------------------------------------------
    // Astra finding F11, 2026-09-23: this used to swallow a real listing
    // failure into "no certificates", which let a retirement proceed and
    // report success while nothing was revoked. `?` here means a directory
    // that cannot be read is an error, not an empty answer.
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
            // The serial before the revocation, because afterwards the file
            // is still there and the record has to name what was taken back.
            if let Ok(out) = runner.run(&pki::describe_cmd("openssl", cert))
                && let Some(serial) = pki::parse_describe(&out.stdout, &what).serial
            {
                serials.push(serial);
            }
            let cmd = pki::revoke_cmd(args.meister_ca, &ca, &what, args.reason);
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

// --- end lane 5B ----------------------------------------------------------

/// The manifest, read through the same parser `validate --manifest` uses.
fn read_manifest(files: &dyn Files, path: &Path) -> Result<manifest::ResolvedFleet> {
    let text = files.read_to_string(path)?;
    manifest::ResolvedFleet::from_json(&text, &path.display().to_string())
}

/// Which certificate a host's `identity.key` is for.
///
/// A host with one tier has one answer. A host that carries two — a cloud
/// and a cluster, or a controller and an agent — has one `identity.key`
/// (every rendered configuration of this fleet names the same path) and
/// therefore ONE service identity, so the operator says which. Guessing
/// would put the wrong tier's name on the key a controller dials with, and
/// the far end would reject the Hello with a name nobody typed.
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

    // Before the first connection: a host this fleet has not enrolled is a
    // host ssh would refuse with "Host key verification failed", and the
    // operator would then go looking for a broken machine instead of for
    // the step that never happened.
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
    // Absolute, because the refusal below compares the CA directory with
    // the repository, and `.` compared with `pki/ca` would say they have
    // nothing to do with each other.
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

    // The request. Read before anything is decided about it, and checked:
    // `requested_name` verifies that the key inside signed it, which is what
    // tells a request from a form.
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
    // --- lane 5A: one name, one certificate ---------------------------
    //
    // A second certificate for a name whose first one is still good is a
    // second machine that can BE that name — which is exactly what a
    // revocation exists to stop. The order is therefore enforced here: take
    // the old one back, then issue the new one. It is the reinstall case
    // (V24) and it is the only case in which this refusal fires, because a
    // host that has never been issued anything has nothing to take back.
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
    // --- end lane 5A --------------------------------------------------
    let csr_on_disk = if source == "-" {
        // The CA is a program and it reads a FILE. A request that arrived on
        // standard input is put where `keys csr` would have put it, so that
        // what was signed is still there afterwards — a certificate whose
        // request nobody kept is a certificate nobody can check.
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

/// Where the inventory is: the path as given when it is absolute, and under
/// the repository when it is not — the same rule every other verb applies to
/// `--fleet`.
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

    // The manifest when there is one, the inventory otherwise. A fresh host
    // has no manifest yet — it cannot be reached, so nothing that reaches it
    // can have run — and the inventory is the file that exists at that
    // point.
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
    // The inventory is Silas' file: comments, order and all. This tool
    // prints the line and does not edit it — a tool that rewrites the file
    // it is configured by is a tool whose diffs nobody reads.
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

// --- end lane 3B ------------------------------------------------------------

// --- lane 5A: taking a certificate back --------------------------------------

/// Everything `keys revoke` was told. A struct because it is twelve things
/// and a function of twelve arguments is a function nobody calls correctly.
struct KeysRevokeArgs<'a> {
    serial: Option<&'a str>,
    host: Option<&'a str>,
    refresh: bool,
    reason: Option<&'a str>,
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

/// Revoke, publish, and plan the delivery.
///
/// The order is the whole of it: the CA first, on this machine and offline,
/// and the fleet second, through a plan. A verb that put the file on the
/// hosts itself would be a second road past the locks and the journal — the
/// same reason there is no `keys deliver` (3B).
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

    let repo = &std::path::absolute(args.repo)
        .with_context(|| format!("{} could not be made absolute", args.repo.display()))?;
    let text = files.read_to_string(args.release)?;
    let release = ReleaseManifest::from_json(&text, &args.release.display().to_string())?;
    let fleet = &release.resolved_fleet;

    // The CA directory, from the inventory the manifest names — the same
    // rule `keys issue` follows, and the same refusal if it is inside the
    // committed tree.
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

    // What is being taken back, in the CA's own terms: a file where this
    // repository has one, a serial where it does not.
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
        // Astra finding F11, 2026-09-23: propagated rather than swallowed --
        // see the matching comment in `retire`.
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
        let cmd = pki::revoke_cmd(args.meister_ca, &ca, what, args.reason);
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

    // Into the repository, where the delivery reads it from. Public and
    // committed: a list of serials is what everybody has to be able to check.
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

    // And now the fleet. The same planner, the same observation, the same
    // locks: a revocation is a plan like any other, and `apply` is what
    // carries it out.
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

/// Prepare a rotation, and plan it.
///
/// Two things happen here that cannot happen inside a plan, and they are the
/// reason this verb exists: the new key is made ON THE HOST (the private
/// half never travels, D10) and the certificate for it is issued HERE (the
/// CA key never travels either). Both are done before the plan is written,
/// so the plan can name exactly which key and which certificate it is about
/// — and a plan made for one prepared key cannot be applied against
/// another.
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
    // `--replace`: a rotation wants a NEW key. An abandoned `.next` from a
    // rotation nobody applied is exactly what may be thrown away — it never
    // served a connection — and keeping it would issue a second certificate
    // over a key that was already refused once.
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

    // And now the plan. One host, because a rotation is about one key on
    // one machine: the preparation happened on THIS host and the
    // certificate is for THIS key.
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
// --- end lane 5A -------------------------------------------------------------

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

/// Where a fleet's signing key lives, relative to the operator's
/// repository. In the template's `.gitignore`; the PUBLIC half
/// (`signing.pub`) is beside it and is committed.
const KEYS_DIR: &str = "keys";

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
        // --- lane 4C ---
        println!("{}", dir.join(KEYS_DIR).display());
        // --- end lane 4C ---
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

    // --- lane 4C: N6 --------------------------------------------------
    //
    // And `keys/`, because step 1 of the sentence below is
    // `nix-store --generate-binary-cache-key <fleet> keys/signing.sec
    // signing.pub` and nix does not make the directory: without this the
    // very first thing an operator types fails with "No such file or
    // directory" (gate M1, finding N6; lane L1 hit it again as B1).
    //
    // No `.gitkeep`: `keys/` is in the template's .gitignore, so a file in
    // it to keep it in git would be a file git ignores. What this verb
    // leaves behind is a directory on the disk, which is what the command
    // needs.
    // --- end lane 4C ---
    let keys = dir.join(KEYS_DIR);
    files.create_dir_all(&keys)?;
    println!("{}", keys.display());

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
