// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

use std::process::ExitCode;

use anyhow::Result;
use clap::{Args, Parser, Subcommand, ValueEnum};
use tracing::debug;

mod agent;
mod client;
mod cluster;
mod config;
mod console;
mod generic;
mod login;
mod nouns;
mod oidc;
mod output;
mod vm;

use config::{Config, Overrides, Target};
use generic::Ctx;

#[derive(Parser)]
#[command(
    name = "meister",
    about = "MeisterStack control CLI",
    version,
    arg_required_else_help = true
)]
struct Cli {
    #[command(flatten)]
    global: GlobalArgs,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Args, Debug)]
pub struct GlobalArgs {
    /// Which profile from the config file to talk to
    #[arg(long, short = 'p', global = true)]
    profile: Option<String>,

    /// Talk to this endpoint instead of a profile's
    #[arg(long, global = true)]
    endpoint: Option<String>,

    /// Where the profiles are; defaults to ~/.config/meisterstack/config.toml
    #[arg(long, global = true)]
    config: Option<std::path::PathBuf>,

    /// How to print the answer: a table for a person, json for a script
    #[arg(long, short = 'o', global = true, default_value = "table")]
    output: OutputFormat,

    /// Whose objects: filters a listing, and owns what a create makes
    #[arg(long, short = 't', global = true)]
    tenant: Option<String>,

    /// Do not ask before deleting or replacing something
    #[arg(long, global = true)]
    yes: bool,

    /// Show what a create, apply or set WOULD write, and write nothing
    /// (`?dryRun=All`). Every check the real request makes is made; the
    /// object comes back annotated `meister.io/dry-run`, and a `vm create`
    /// also carries what the scheduler would say in `status.message`.
    #[arg(long, global = true)]
    dry_run: bool,

    /// Say more; twice says everything
    #[arg(long, short = 'v', global = true, action = clap::ArgAction::Count)]
    verbose: u8,
}

impl GlobalArgs {
    /// The defaults, for the tests that need a `GlobalArgs` and care about
    /// none of it.
    #[cfg(test)]
    pub fn for_tests() -> Self {
        Self {
            profile: None,
            endpoint: None,
            config: None,
            output: OutputFormat::Table,
            tenant: None,
            yes: true,
            dry_run: false,
            verbose: 0,
        }
    }
}

#[derive(Copy, Clone, Debug, ValueEnum)]
pub enum OutputFormat {
    /// Columns a person reads and `awk` can cut up
    Table,
    /// The server's own object, whole
    Json,
}

// One tree, and the endpoint decides what is in it.
//
// What used to be here was three trees under three prefixes — `meister cloud
// vm ls`, `meister cluster vm ls`, `meister agent ls` — and a `tier` key in
// every profile that had to agree with which prefix an operator typed. The
// tier was never a fact about the COMMAND: `vm ls` means the same thing
// wherever it lands, and which nouns exist is something the server knows and
// says (`GET /apis/meister.io/v1`). So the prefix is gone, the profile key is
// gone, and a noun this endpoint does not serve is a sentence that says where
// it does live.
//
// The agent keeps a subtree of its own, and that is not the tier coming back
// in through the side door. A node's own socket is a different API — no
// discovery, no objects, ids instead of names, and `observe`/`reconcile`,
// which ask what one machine's processes are doing and have no counterpart
// anywhere above. It is a different thing, so it has a different word.
#[derive(Subcommand)]
enum Cmd {
    /// Virtual machines
    Vm {
        #[command(subcommand)]
        cmd: VmCmd,
    },
    /// The machines a cluster runs vms on
    Node {
        /// Whose nodes. Required at a cloud, refused at a cluster: a cluster
        /// has its own and a cloud has only somebody else's.
        #[arg(long, global = true)]
        cluster: Option<String>,
        #[command(subcommand)]
        cmd: NodeCmd,
    },
    /// The clusters a cloud places vms on
    Cluster {
        #[command(subcommand)]
        cmd: ClusterCmd,
    },
    /// Tenants — the unit a user belongs to, and a vm too
    Tenant {
        #[command(subcommand)]
        cmd: TenantCmd,
    },
    /// The user directory. A certificate says who somebody is; this says what
    /// they may do
    User {
        #[command(subcommand)]
        cmd: UserCmd,
    },
    /// Certificate requests, and saying yes or no to them
    Csr {
        #[command(subcommand)]
        cmd: CsrCmd,
    },
    /// The image catalogue every tier agrees on by name
    Image {
        #[command(subcommand)]
        cmd: ImageCmd,
    },
    /// The addresses this operator HAS, and who may take from them
    Floatingpool {
        #[command(subcommand)]
        cmd: FloatingPoolCmd,
    },
    /// Reservations out of a pool, and which vm each one is for
    Floatingip {
        #[command(subcommand)]
        cmd: FloatingIpCmd,
    },
    /// Real subnets handed to a tenant — the NAT-free half
    Routedsubnet {
        #[command(subcommand)]
        cmd: RoutedSubnetCmd,
    },
    /// The wires a cluster gave away — where a tenant gets out
    Providernetwork {
        #[command(subcommand)]
        cmd: ProviderNetworkCmd,
    },
    /// A tenant's way out over one of those
    Router {
        #[command(subcommand)]
        cmd: RouterCmd,
    },
    /// Where volumes come from
    Storagepool {
        #[command(subcommand)]
        cmd: StoragePoolCmd,
    },
    /// Disks with a life of their own
    Volume {
        #[command(subcommand)]
        cmd: VolumeCmd,
    },
    /// A tenant's own bytes. Write-only: what a read gives back is the key
    /// names
    Secret {
        #[command(subcommand)]
        cmd: SecretCmd,
    },
    /// Points in time of a disk, which outlive the disk
    Volumesnapshot {
        #[command(subcommand)]
        cmd: VolumeSnapshotCmd,
    },
    /// Live migrations: one record per move, with what stopped it if
    /// something did
    Vmmigration {
        #[command(subcommand)]
        cmd: VmMigrationCmd,
    },
    /// Everything that happened recently, newest first
    Events(EventsArgs),
    /// Create the objects in a file, or replace what is already there
    Apply(ApplyArgs),
    /// What this endpoint is, and every resource it serves
    ApiResources,
    /// Who the server thinks you are, and what it will let you do
    Whoami,
    /// Get a credential for this endpoint. Without `--oidc`: generate a key
    /// pair here, send only the request, collect the certificate. With it:
    /// log in at the profile's identity provider and store the session
    Login(LoginArgs),
    /// The node itself, over its own socket; root, local, for diagnosis
    Agent {
        #[command(subcommand)]
        cmd: AgentCmd,
    },
    /// The fleet: plan, image, push, keys, check. Runs `meister-deploy`,
    /// which is a separate binary on purpose — it needs no endpoint, no
    /// credential and no running control plane, and it is the one command
    /// that works when nothing else does
    Deploy {
        /// Everything after `deploy`, handed to `meister-deploy` unchanged
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
}

/// Hand the whole invocation to `meister-deploy`: next to this binary first
/// (a checkout's `target/release` holds both), then PATH.
fn exec_deploy(args: &[String]) -> Result<()> {
    use std::os::unix::process::CommandExt;
    let sibling = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.join("meister-deploy")))
        .filter(|p| p.is_file());
    let program = sibling.unwrap_or_else(|| "meister-deploy".into());
    let err = std::process::Command::new(&program).args(args).exec();
    anyhow::bail!(
        "cannot run {}: {err}. It is a second binary of this workspace: \
         `cargo build --release -p meister-deploy` builds it next to this one",
        program.display()
    )
}

/// What `events` narrows to. Both are filters and both are the server's
/// work: the console had to filter the whole log in the browser, and a
/// `curl` could not narrow it at all.
#[derive(clap::Args, Debug, Default)]
pub struct EventsArgs {
    /// Only about this object: `vm/web-1`, or a bare name for any kind
    #[arg(long = "for", value_name = "KIND/NAME")]
    pub about: Option<String>,
    /// Only since then: `1h`, `30m`, `2d`, or an RFC 3339 instant
    #[arg(long)]
    pub since: Option<String>,
}

/// The two verbs every resource has, whatever it is.
///
/// Neither needs a line of code per resource: the path comes out of the
/// discovery document and the table is chosen by the kind. Flattened into
/// each noun below so that `meister vm ls` and `meister tenant ls` are one
/// implementation and not twelve.
#[derive(Subcommand)]
pub enum ReadCmd {
    /// List them
    Ls {
        /// Only the ones whose labels match: `key=value`, comma-separated,
        /// and every pair has to hold
        #[arg(long, short = 'l')]
        selector: Option<String>,
    },
    /// Print one object, whole
    Get {
        /// Its name
        name: String,
    },
}

#[derive(Args, Debug)]
pub struct ApplyArgs {
    /// A file of objects: one json object, or an array of them. Repeatable
    #[arg(long, short = 'f', required = true)]
    pub file: Vec<std::path::PathBuf>,
}

/// `meister login` — sugar over the certificatesigningrequests flow, and
/// nothing more than sugar: every step of it is a call an operator could
/// make by hand.
#[derive(Args, Debug)]
pub struct LoginArgs {
    /// Log in at the profile's identity provider instead of asking for a
    /// certificate: the device grant, a code to type into a browser
    /// anywhere, and a session stored at 0600 next to the profile
    #[arg(long)]
    pub oidc: bool,
    /// Who to ask for a certificate for. Defaults to $USER
    #[arg(long)]
    pub user: Option<String>,
    /// Where to put the key and the certificate. Defaults to the paths the
    /// profile's mtls credential already names
    #[arg(long)]
    pub out: Option<std::path::PathBuf>,
    /// How long to wait for an administrator to approve. 0 = do not wait
    #[arg(long, default_value = "120")]
    pub wait_secs: u64,
}

#[derive(Subcommand)]
pub enum VmCmd {
    #[command(flatten)]
    Read(ReadCmd),
    /// Delete one. The answer is Terminating, never "gone"
    Rm {
        /// Its name
        name: String,
    },
    /// Create one from a spec file
    Create {
        /// What to call it
        name: String,
        /// The agent's NewVmSpec json — the same file every tier takes
        #[arg(long, short = 'f')]
        file: std::path::PathBuf,
        /// Running | Stopped | Paused (default Running)
        #[arg(long)]
        run_strategy: Option<String>,
        /// The scheduler class this vm asks for. Unset = `vm`, which every
        /// node takes unless an operator said otherwise with `node accepts`
        #[arg(long)]
        class: Option<String>,
    },
    /// Set runStrategy = Running
    Start {
        /// Its name
        name: String,
    },
    /// Set runStrategy = Stopped (the guest gets the node's grace period)
    Stop {
        /// Its name
        name: String,
    },
    /// Set runStrategy = Paused
    Pause {
        /// Its name
        name: String,
    },
    /// Set runStrategy = Running on a paused vm
    Resume {
        /// Its name
        name: String,
    },
    /// What the guest printed before anything inside it was reachable. One
    /// way — no attach, no input, no --follow
    Logs {
        /// Its name
        name: String,
        /// How many lines from the END (default 200)
        #[arg(long)]
        lines: Option<u32>,
        /// Hide lines containing this text. Repeatable. A reading aid in this
        /// client only — the server keeps answering with everything the guest
        /// said
        #[arg(long, value_name = "TEXT")]
        hide: Vec<String>,
        /// Show only lines containing this text. Repeatable; a line matching
        /// any of them is kept
        #[arg(long, value_name = "TEXT")]
        only: Vec<String>,
        /// Which streams: `console`, `serial`, or `vmm`. Repeatable. Default
        /// is the guest's own two; `vmm` is the hypervisor's own log, which
        /// is where the reason lives when a vm never booted at all
        #[arg(long, value_name = "STREAM")]
        streams: Vec<String>,
    },
    /// Attach to this vm's serial line and type into it. Ctrl-] detaches;
    /// exactly one person may hold a line at a time
    Connect {
        /// Its name
        name: String,
    },
    /// Plug a volume into this vm. The disk arrives while the guest runs;
    /// what the guest does with it (partition, mount) is the guest's business
    Attach {
        /// Its name
        name: String,
        /// The volume to plug in, by name, in the same tenant
        #[arg(long)]
        volume: String,
    },
    /// Unplug a volume. The data stays — this ends the connection, not the
    /// disk. A guest that still has it mounted may refuse
    Detach {
        /// Its name
        name: String,
        /// The volume to unplug
        #[arg(long)]
        volume: String,
    },
    /// Let the binding go so the scheduler decides again. Only on a stopped
    /// vm; ephemeral disks are made fresh at the destination
    Reschedule {
        /// Its name
        name: String,
    },
    /// Move this vm to another node WHILE IT RUNS. Refused for a vm with a
    /// device or a node-local disk — those move with `--evacuation restart`
    /// and a reboot, or not at all
    Migrate {
        /// Its name
        name: String,
        /// Which node to move it to. Omitted, the scheduler chooses; named,
        /// it is a hard requirement and a node that cannot take the vm is
        /// refused by name
        #[arg(long = "to", value_name = "NODE")]
        to: Option<String>,
    },
    /// What a drain may do to this vm: `never` (the default — it stays where
    /// it is) or `restart` (it may be stopped, moved and started, and the
    /// guest sees a reboot)
    Evacuation {
        /// Its name
        name: String,
        /// never | restart
        value: String,
    },
    /// What happened to this vm lately: placements, refusals, phase changes
    Events {
        /// Its name
        name: String,
    },
}

/// Cordon, drain, label.
///
/// The two verbs are two statements and not one. **Cordon** stops NEW
/// placements and moves nothing: the vms on the node go on running. **Drain**
/// empties the machine — every vm that can go, goes — and implies the cordon
/// without setting it, so an `undrain` gives back exactly the schedulability
/// that was asked for.
///
/// What "can go" is `meister vm evacuation` and the disks: a stopped vm is
/// placed again, a running one only with `evacuation = restart`, and a vm
/// with a persistent node-local disk never. `node get` lists what stayed and
/// why.
#[derive(Subcommand)]
pub enum NodeCmd {
    /// List them
    Ls {
        /// Only the ones whose labels match: `key=value`, comma-separated
        #[arg(long, short = 'l')]
        selector: Option<String>,
    },
    /// Print one, whole
    Get {
        /// Its name
        name: String,
    },
    /// Stop placing new vms here (spec.schedulable = false)
    Cordon {
        /// Its name
        name: String,
    },
    /// Take the cordon off (spec.schedulable = true)
    Uncordon {
        /// Its name
        name: String,
    },
    /// Empty this node: every vm on it that may move, moves. Implies the
    /// cordon. `node get` says what stayed and why
    Drain {
        /// Its name
        name: String,
    },
    /// Stop emptying it (spec.drain = false). The vms already moved stay
    /// where they went
    Undrain {
        /// Its name
        name: String,
    },
    /// Say which workload classes this machine takes, and nothing else.
    ///
    /// The mirror image of a selector: a selector is a workload choosing
    /// machines, this is a machine choosing workloads — Kubernetes' taint and
    /// toleration in one word. Naming none takes everything back, which is
    /// what every machine says by default; naming any is EXCLUSIVE, so a node
    /// told `router` stops taking ordinary vms
    Accepts {
        /// Its name
        name: String,
        /// The classes, e.g. `router` or `gpu`. None at all = it takes
        /// everything again
        classes: Vec<String>,
    },
    /// Write labels on it. They are what a vm's `spec.nodeSelector` selects
    /// against, and they mean whatever an operator decides they mean
    Label {
        /// Its name
        name: String,
        /// `key=value`, repeatable. Setting a key that is there replaces it
        pairs: Vec<String>,
        /// Take a key off, repeatable. Applied after the pairs, so naming a
        /// key in both means it goes
        #[arg(long = "rm")]
        rm: Vec<String>,
    },
}

#[derive(Subcommand)]
pub enum ClusterCmd {
    #[command(flatten)]
    Read(ReadCmd),
    /// Stop placing new vms on this cluster (spec.schedulable = false)
    Cordon {
        /// Its name
        name: String,
    },
    /// Take the cordon off (spec.schedulable = true)
    Uncordon {
        /// Its name
        name: String,
    },
    /// Empty this cluster: every vm on it that may move, moves — to another
    /// cluster, by reboot or not at all, because there is no live migration
    /// across clusters
    Drain {
        /// Its name
        name: String,
    },
    /// Stop emptying it (spec.drain = false)
    Undrain {
        /// Its name
        name: String,
    },
    /// Write labels on it. They are what a vm's `spec.clusterSelector`
    /// selects against
    Label {
        /// Its name
        name: String,
        /// `key=value`, repeatable. Setting a key that is there replaces it
        pairs: Vec<String>,
        /// Take a key off, repeatable. Applied after the pairs
        #[arg(long = "rm")]
        rm: Vec<String>,
    },
}

#[derive(Subcommand)]
pub enum TenantCmd {
    #[command(flatten)]
    Read(ReadCmd),
    /// Delete one, and everything in it
    Rm {
        /// Its name
        name: String,
    },
    /// Make one
    Create {
        /// What to call it
        name: String,
        /// What it is for, for the person reading `tenant ls`
        #[arg(long)]
        description: Option<String>,
    },
    /// What this tenant may hold. A limit that is not named is left as it
    /// stands; `--unlimited` takes all three off. Counted over every phase,
    /// Pending included
    Quota {
        /// Its name
        name: String,
        /// At most this many vms
        #[arg(long)]
        max_vms: Option<u32>,
        /// At most this many vcpus, summed
        #[arg(long)]
        max_vcpus: Option<u32>,
        /// At most this much memory, summed, in MiB
        #[arg(long)]
        max_mem_mib: Option<u64>,
        /// Take the whole quota off — the only way back to "unlimited",
        /// which is what a limit of 0 is not
        #[arg(long, conflicts_with_all = ["max_vms", "max_vcpus", "max_mem_mib"])]
        unlimited: bool,
    },
}

#[derive(Subcommand)]
pub enum UserCmd {
    #[command(flatten)]
    Read(ReadCmd),
    /// Delete one
    Rm {
        /// Its name
        name: String,
    },
    /// Enter somebody in the directory. Their tenant is `-t`
    Create {
        /// Their name, exactly as their certificate's CN will say it
        name: String,
        /// admin | operator | member | viewer
        #[arg(long, default_value = "member")]
        role: String,
        /// Who they are, for the person reading `user ls`
        #[arg(long)]
        description: Option<String>,
    },
    /// Change what a user may do. Takes effect on their next request
    SetRole {
        /// Their name
        name: String,
        /// admin | operator | member | viewer
        role: String,
    },
}

#[derive(Subcommand)]
pub enum CsrCmd {
    #[command(flatten)]
    Read(ReadCmd),
    /// Delete one
    Rm {
        /// Its name
        name: String,
    },
    /// Say yes, and sign
    Approve {
        /// Its name
        name: String,
    },
    /// Say no. A denial is final
    Deny {
        /// Its name
        name: String,
        /// Why, for the person who asked
        #[arg(long)]
        reason: Option<String>,
    },
}

#[derive(Subcommand)]
pub enum ImageCmd {
    #[command(flatten)]
    Read(ReadCmd),
    /// Take one out of the catalogue
    Rm {
        /// Its name
        name: String,
    },
    /// Register where an image is. v1 moves no bytes
    Create {
        /// The file name nodes look up — and what a vm's base_image says
        name: String,
        /// Where the image already is (a path on shared storage)
        #[arg(long)]
        source: Option<String>,
        /// Fetch it from here instead. The NODE fetches, on first use, into
        /// a cache keyed by the checksum
        #[arg(long, conflicts_with = "source", requires = "sha256")]
        from_url: Option<String>,
        /// What the fetched bytes must hash to, lowercase hex. Mandatory
        /// with --from-url: an image fetched over a network and not checked
        /// is an image somebody else chooses the contents of
        #[arg(long)]
        sha256: Option<String>,
        /// raw | qcow2
        #[arg(long, default_value = "raw")]
        format: String,
        /// Size in bytes, for the operator reading `image ls`
        #[arg(long)]
        size: Option<u64>,
        /// Readable by every tenant, writable only by its own
        #[arg(long)]
        public: bool,
    },
}

#[derive(Subcommand)]
pub enum FloatingPoolCmd {
    #[command(flatten)]
    Read(ReadCmd),
    /// Give the addresses back
    Rm {
        /// Its name
        name: String,
    },
    /// Declare a piece of somebody's real address space
    Create {
        /// What to call it
        name: String,
        /// A range this pool holds. Repeatable, and each may be a cidr, a
        /// single address, or `a-b`
        #[arg(long = "cidr", required = true)]
        cidrs: Vec<String>,
        /// These addresses are routable from outside. Sets the default quota
        /// to zero: a real public address is handed out one tenant at a time
        #[arg(long)]
        public: bool,
        /// Reservations that name no pool land here. At most one pool may
        /// say this
        #[arg(long)]
        default: bool,
        /// What it is, for the person reading `floatingpool ls`
        #[arg(long)]
        description: Option<String>,
    },
    /// How many addresses a tenant may hold out of this pool. The one
    /// explicit act that hands out a routable address
    Quota {
        /// The pool
        pool: String,
        /// The tenant
        tenant: String,
        /// How many
        count: u32,
    },
}

#[derive(Subcommand)]
pub enum FloatingIpCmd {
    #[command(flatten)]
    Read(ReadCmd),
    /// Give the address back to the pool
    Rm {
        /// The address
        name: String,
    },
    /// Reserve an address. The server picks the first free one unless
    /// --address names one
    Create {
        /// Which pool. Unset = the one marked default
        #[arg(long)]
        pool: Option<String>,
        /// Ask for this address specifically — the one DNS already points at
        #[arg(long)]
        address: Option<String>,
        /// Point it at a vm straight away, same as `floatingip assign`
        #[arg(long)]
        vm: Option<String>,
        /// Let a ROUTER translate it instead of handing it to the guest: the
        /// address never reaches the vm, and the router does 1:1 NAT between
        /// it and --internal-address. The road a tenant behind SNAT takes
        #[arg(long)]
        router: Option<String>,
        /// Which address inside the tenant's overlay --router translates to.
        /// This stack allocates none, so it is a thing somebody knows and
        /// writes down
        #[arg(long, requires = "router")]
        internal_address: Option<String>,
    },
    /// Point an address at a vm, or take it off one
    Assign {
        /// The address
        address: String,
        /// Which vm
        #[arg(long, conflicts_with = "release")]
        vm: Option<String>,
        /// Take the address off whatever vm has it, keeping the reservation
        #[arg(long)]
        release: bool,
    },
}

#[derive(Subcommand)]
pub enum RoutedSubnetCmd {
    #[command(flatten)]
    Read(ReadCmd),
    /// Take the subnet back
    Rm {
        /// Its name
        name: String,
    },
    /// Cut a real subnet for a tenant. Whose it is, is `-t`
    Create {
        /// What to call it
        name: String,
        /// The subnet outright. Unset = cut the first free block out of the
        /// cloud's routed_pools
        #[arg(long)]
        cidr: Option<String>,
        /// How big a block to cut when --cidr is not given (default 24)
        #[arg(long)]
        prefix_len: Option<u32>,
        /// What it is for
        #[arg(long)]
        description: Option<String>,
    },
}

/// A provider network is a wire, named by the `physnet` its nodes claim it
/// under. Declaring one says an operator has given an interface away; whether
/// any node really has is that node's own configuration, and a router on a
/// network nobody claims stays pending with a sentence saying so.
#[derive(Subcommand)]
pub enum ProviderNetworkCmd {
    #[command(flatten)]
    Read(ReadCmd),
    /// Take the network back. One that still carries routers stays
    Rm {
        /// Its name
        name: String,
    },
    /// Declare a wire this fleet was given
    Create {
        /// What to call it
        name: String,
        /// The name the nodes claim it under. Unset = the object's own name
        #[arg(long)]
        physnet: Option<String>,
        /// The subnet on the wire, so a router's address carries the right
        /// mask
        #[arg(long)]
        cidr: Option<String>,
        /// The next hop out there. Unset = no default route
        #[arg(long)]
        gateway: Option<String>,
        /// Where router addresses are cut from: a cidr, an address or an
        /// a-b range, repeatable
        #[arg(long)]
        allocation: Vec<String>,
        /// What it is for
        #[arg(long)]
        description: Option<String>,
    },
}

/// A router is one tenant's way out over one provider network: a leg on that
/// wire, a leg in the tenant's overlay, and the translations between them.
/// Where it runs is the cluster's decision — `router get` names the gateway
/// nodes it was planned on and which of them is active.
#[derive(Subcommand)]
pub enum RouterCmd {
    #[command(flatten)]
    Read(ReadCmd),
    /// Take the way out away. The floating addresses stay reserved
    Rm {
        /// Its name
        name: String,
    },
    /// Give a tenant a way out. Whose it is, is `-t`
    Create {
        /// What to call it
        name: String,
        /// Which provider network it goes out over
        #[arg(long)]
        network: String,
        /// The router's address on the tenant's overlay, cidr — what the
        /// guests point at as their gateway
        #[arg(long)]
        internal_addr: Option<String>,
        /// The tenant's overlay. Unset at a cloud, which fills it in from the
        /// tenant; a standalone cluster has no tenants and names it here
        #[arg(long)]
        vni: Option<u32>,
        /// Do not masquerade the overlay behind the router's own address.
        /// The routed-subnet deployment
        #[arg(long)]
        no_snat: bool,
        /// A routed subnet this router announces, by name, repeatable
        #[arg(long)]
        routed_subnets: Vec<String>,
        /// What it is for
        #[arg(long)]
        description: Option<String>,
    },
}

#[derive(Subcommand)]
pub enum StoragePoolCmd {
    #[command(flatten)]
    Read(ReadCmd),
    /// Take a pool out. A pool with volumes in it stays
    Rm {
        /// Its name
        name: String,
    },
    /// Declare where volumes come from
    Create {
        /// What to call it
        name: String,
        /// The backend, as a node claims it: `volume/<driver>` in its
        /// catalogue. Which ones this fleet has is asked of the fleet, not
        /// listed here -- a create that names one nobody offers says so
        #[arg(long)]
        driver: String,
        /// Which nodes can reach it, repeatable. None = all of them
        #[arg(long = "node")]
        nodes: Vec<String>,
        /// Which cluster serves it. Required at the cloud, where a pool is a
        /// pointer at one a cluster admin already made; meaningless at a
        /// cluster, which IS the cluster
        #[arg(long)]
        cluster: Option<String>,
        /// Backend options as json, handed to the driver untouched — e.g.
        /// '{"pool":"vg0/thin"}'
        #[arg(long)]
        params: Option<String>,
        /// Volumes that name no pool land here
        #[arg(long)]
        default: bool,
        /// What it is, for the person reading `storagepool ls`
        #[arg(long)]
        description: Option<String>,
    },
    /// How much a tenant may hold in this pool, in GiB
    Quota {
        /// The pool
        pool: String,
        /// The tenant, or `*` for every tenant nobody named. `storagepool ls`
        /// shows both in QUOTA
        tenant: String,
        /// How many GiB
        gib: u64,
    },
}

/// A secret is the one noun here whose `create` takes its content on the
/// command line — and therefore the one where the shell's history is part of
/// the threat model. `--from-file` exists for that: it is the form that does
/// not put the value in `~/.bash_history` or in the process list of a shared
/// machine, and it is what the guide recommends.
#[derive(Subcommand)]
pub enum SecretCmd {
    #[command(flatten)]
    Read(ReadCmd),
    /// Delete one. A vm already running keeps the seed it was given; the next
    /// boot is what stops working, which is what revoking means here
    Rm {
        /// Its name
        name: String,
    },
    /// Make one, or replace one whole. Whose it is, is `-t`
    Create {
        /// What to call it
        name: String,
        /// `key=value`, repeatable. Visible in the shell history and in `ps`;
        /// prefer --from-file for anything that matters
        #[arg(long, value_name = "KEY=VALUE")]
        from_literal: Vec<String>,
        /// `key=path`, repeatable. The file's bytes become the value, as they
        /// are — no trailing newline is stripped, because a key file's last
        /// byte is not this tool's to decide about
        #[arg(long, value_name = "KEY=PATH")]
        from_file: Vec<String>,
        /// What it is for
        #[arg(long)]
        description: Option<String>,
        /// Replace an existing secret instead of creating one. Whole: the
        /// keys not named here go
        #[arg(long)]
        replace: bool,
    },
}

#[derive(Subcommand)]
pub enum VolumeCmd {
    #[command(flatten)]
    Read(ReadCmd),
    /// Delete one. What that does to the data is the backend's answer
    Rm {
        /// Its name
        name: String,
    },
    /// Make a disk that outlives the vm using it. Whose it is, is `-t`
    Create {
        /// What to call it
        name: String,
        /// How big, in GiB
        #[arg(long)]
        size_gib: u64,
        /// Which pool. Unset = the one marked default
        #[arg(long)]
        pool: Option<String>,
        /// Clone this catalogue image into it. Unset = an empty disk
        #[arg(long)]
        base_image: Option<String>,
        /// Start from a snapshot instead. Excludes --base-image
        #[arg(long)]
        from_snapshot: Option<String>,
        /// Block | Filesystem
        #[arg(long)]
        mode: Option<String>,
        /// ReadWriteOnce | ReadWriteMany
        #[arg(long)]
        access_mode: Option<String>,
        /// What it is for
        #[arg(long)]
        description: Option<String>,
    },
    /// Grow a disk. Never shrinks; the filesystem inside is the tenant's to
    /// grow afterwards (resize2fs, growpart)
    Resize {
        /// Its name
        name: String,
        /// The new size in GiB. Must be larger than it is now
        #[arg(long)]
        size_gib: u64,
    },
}

/// A point in time of a volume, which outlives the volume.
///
/// Its own noun and not a verb on `volume`, for the reason the object is its
/// own object: it survives the disk it was taken of, so a subcommand of that
/// disk would be a subcommand of something that may not be there.
#[derive(Subcommand)]
pub enum VolumeSnapshotCmd {
    #[command(flatten)]
    Read(ReadCmd),
    /// Delete one. The copy goes; the volume it came from does not
    Rm {
        /// Its name
        name: String,
    },
    /// Freeze what a volume holds right now. Crash-consistent: no guest
    /// agent, no fsfreeze — what a guest would have found after losing power
    Create {
        /// What to call it
        name: String,
        /// The volume to copy
        #[arg(long)]
        volume: String,
        /// What it is for
        #[arg(long)]
        description: Option<String>,
    },
}

/// Read and clean up, and deliberately no `create`.
///
/// A migration is asked for with `meister vm migrate`, which is where the
/// refusals are and where the sentence naming the way out belongs. This noun
/// is what you read afterwards: which move, from where to where, and — the
/// useful one — what stopped the one that did not work.
#[derive(Subcommand)]
pub enum VmMigrationCmd {
    #[command(flatten)]
    Read(ReadCmd),
    /// Throw the record away. The vm is untouched: a migration owns nothing,
    /// and the source guest is running throughout either way
    Rm {
        /// Its name
        name: String,
    },
}

/// The node's own api, over its own socket.
///
/// It carries the noun `vm` already, although a node knows only vms today:
/// the machine will manage more than vms (containers are named), and a second
/// noun beside a nounless `agent ls` would be the next asymmetry. One word
/// more now, no rewrite of the guide later.
#[derive(Subcommand)]
pub enum AgentCmd {
    /// The vms this node is running
    Vm {
        #[command(subcommand)]
        cmd: AgentVmCmd,
    },
    /// The volumes this node owns on their own. Read-only: a volume is made
    /// and unmade over the controller session, never here
    Volume {
        #[command(subcommand)]
        cmd: AgentVolumeCmd,
    },
}

/// Reading only, and that is the whole shape of it.
///
/// The lifecycle of a volume belongs to the `Volume` object one tier up: the
/// controller decides, the node obeys, and a write verb at this socket would
/// be a second owner of somebody's data reachable by anybody in the socket
/// group. What this IS for is the question the object cannot answer — what
/// does the node itself think it has.
#[derive(Subcommand)]
pub enum AgentVolumeCmd {
    /// List them, tombstones and all
    Ls,
    /// Print one, whole
    Get {
        /// Its id — the uid the control plane handed out
        id: String,
    },
}

#[derive(Subcommand)]
pub enum AgentVmCmd {
    /// List them
    Ls,
    /// Print one, whole
    Get {
        /// Its id — the node's, not a name
        id: String,
    },
    /// Tear one down
    Rm {
        /// Its id
        id: String,
    },
    /// Create one. The node assigns the id
    Create {
        /// The agent's NewVmSpec json
        #[arg(long, short = 'f')]
        file: std::path::PathBuf,
    },
    /// Start it
    Start {
        /// Its id
        id: String,
    },
    /// Stop it. The only stop that takes a grace period, because it is the
    /// only one that waits it out
    Stop {
        /// Its id
        id: String,
        /// How long the guest gets to power itself off
        #[arg(long)]
        grace: Option<u64>,
    },
    /// Pause it
    Pause {
        /// Its id
        id: String,
    },
    /// Resume it
    Resume {
        /// Its id
        id: String,
    },
    /// What the guest printed, straight off this node's own ring
    Logs {
        /// Its id
        id: String,
        /// How many lines from the END (default 200)
        #[arg(long)]
        lines: Option<u32>,
        /// Hide lines containing this text. Repeatable. A reading aid in this
        /// client only — the server keeps answering with everything the guest
        /// said
        #[arg(long, value_name = "TEXT")]
        hide: Vec<String>,
        /// Show only lines containing this text. Repeatable; a line matching
        /// any of them is kept
        #[arg(long, value_name = "TEXT")]
        only: Vec<String>,
        /// Which streams: `console`, `serial`, or `vmm`. Repeatable. Default
        /// is the guest's own two; `vmm` is the hypervisor's own log, which
        /// is where the reason lives when a vm never booted at all
        #[arg(long, value_name = "STREAM")]
        streams: Vec<String>,
    },
    /// What this node SEES against what it was asked for, and what it would
    /// do about the difference. There is no such verb above a node
    Observe {
        /// Its id
        id: String,
    },
    /// The reconcile loop's one step, asked for by hand
    Reconcile {
        /// Its id
        id: String,
    },
}

#[tokio::main]
async fn main() -> ExitCode {
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("Error: {}", one_line(&e));
            ExitCode::FAILURE
        }
    }
}

/// anyhow's own `Debug` spreads a chain over five lines the moment anything
/// on the way up added a `.context()`, and an operator reading a terminal
/// gets one error per line or none. Whitespace inside a message collapses
/// too, so a literal wrapped across source lines stays one line here.
fn one_line(e: &anyhow::Error) -> String {
    let mut parts: Vec<String> = Vec::new();
    for cause in e.chain() {
        let flat = cause
            .to_string()
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ");
        // A context that only repeats its cause says nothing twice.
        if flat.is_empty() || parts.last().is_some_and(|last| *last == flat) {
            continue;
        }
        parts.push(flat);
    }
    parts.join(": ")
}

async fn run() -> Result<()> {
    let cli = Cli::parse();

    let filter = match cli.global.verbose {
        0 => "warn",
        1 => "info",
        _ => "debug",
    };
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| filter.into()),
        )
        .with_writer(std::io::stderr)
        .without_time()
        .init();

    let config_path = match &cli.global.config {
        Some(p) => p.clone(),
        None => config::default_config_path()?,
    };
    let cfg = Config::load(&config_path)?;

    let overrides = Overrides {
        profile: cli.global.profile.clone(),
        endpoint: cli.global.endpoint.clone(),
        // Only `meister login` may resolve a profile whose certificate is not
        // there yet — see the field.
        tolerate_missing_credential: matches!(cli.cmd, Cmd::Login(_)),
    };

    // Before the config is even read: the fleet tool has its own file
    // (fleet.toml) and needs no profile, no endpoint and no certificate.
    if let Cmd::Deploy { args } = &cli.cmd {
        return exec_deploy(args);
    }

    match &cli.cmd {
        // The node's own socket, and nothing that speaks to it goes through
        // the discovery: a unix endpoint IS a node by definition, and asking
        // it what group-version it serves would be asking the wrong question
        // of the right machine.
        Cmd::Agent { cmd } => {
            let target = target_for(&cfg, &overrides).await?;
            refuse_wrong_tree(&target, true)?;
            agent::run(&target, cmd, &cli.global).await
        }
        // Deliberately NOT through `target_for`: that renews an expired
        // session before running, and this is the command whose whole job is
        // to replace one. A revoked refresh token would otherwise fail the
        // renewal and take the login that would have fixed it with it.
        Cmd::Login(args) if args.oidc => {
            let target = config::resolve(&cfg, &overrides)?;
            debug!(profile = %target.profile_name, "resolved target");
            refuse_wrong_tree(&target, false)?;
            oidc::login(&target, &cli.global).await
        }
        Cmd::Login(args) => {
            let target = target_for(&cfg, &overrides).await?;
            refuse_wrong_tree(&target, false)?;
            login::run(&cfg, &target, args, &cli.global).await
        }
        other => {
            let target = target_for(&cfg, &overrides).await?;
            refuse_wrong_tree(&target, false)?;
            let client = client::Client::new(&target)?.previewing(cli.global.dry_run);
            // Once per invocation, before the first command. What this
            // endpoint is, and what it has.
            let raw = client.get(generic::DISCOVERY).await.map_err(|e| {
                if e.to_string().contains("404") {
                    anyhow::anyhow!("this endpoint does not serve {}", generic::GROUP)
                } else {
                    e
                }
            })?;
            let disc: generic::Discovery = serde_json::from_slice(&raw)
                .map_err(|e| anyhow::anyhow!("parsing the discovery document: {e}"))?;
            if disc.auth == "none" {
                // Once, and only when somebody asked to be told: a lab that
                // runs open is a decision, and a warning on every command
                // would be a warning nobody reads.
                tracing::info!("this endpoint runs without authentication");
            }
            let ctx = Ctx {
                client,
                global: &cli.global,
                disc,
                endpoint: target.endpoint.clone(),
                profile: target.profile_name.clone(),
            };
            dispatch(&ctx, other, &raw).await
        }
    }
}

/// The two trees, and the one sentence for mixing them up.
///
/// A `unix://` endpoint is a node's own api by definition — it has no
/// discovery, no objects and no names — so pointing a control-plane command
/// at one is not a 404 to puzzle over, it is a profile pointed at the wrong
/// thing. And the other way round for the same reason.
fn refuse_wrong_tree(target: &Target, agent_command: bool) -> Result<()> {
    let is_socket = target.endpoint.starts_with("unix://");
    match (is_socket, agent_command) {
        (true, false) => anyhow::bail!(
            "profile {:?} is a unix socket, which is a node's own API; use \"meister agent ...\"",
            target.profile_name
        ),
        (false, true) => anyhow::bail!(
            "profile {:?} is {}, which is a control plane; \"meister agent ...\" wants a node's \
             own unix socket",
            target.profile_name,
            target.endpoint
        ),
        _ => Ok(()),
    }
}

async fn dispatch(ctx: &Ctx<'_>, cmd: &Cmd, raw: &bytes::Bytes) -> Result<()> {
    match cmd {
        Cmd::Vm { cmd } => match cmd {
            VmCmd::Read(read) => read_verb(ctx, "vms", read).await,
            VmCmd::Rm { name } => vm::remove(ctx, name).await,
            VmCmd::Create {
                name,
                file,
                run_strategy,
                class,
            } => vm::create(ctx, name, file, run_strategy.as_deref(), class.as_deref()).await,
            VmCmd::Start { name } => vm::run_strategy(ctx, name, "Running").await,
            VmCmd::Stop { name } => vm::run_strategy(ctx, name, "Stopped").await,
            VmCmd::Pause { name } => vm::run_strategy(ctx, name, "Paused").await,
            VmCmd::Resume { name } => vm::run_strategy(ctx, name, "Running").await,
            VmCmd::Logs {
                name,
                lines,
                hide,
                only,
                streams,
            } => vm::logs(ctx, name, *lines, &vm::LogFilter::new(hide, only, streams)).await,
            VmCmd::Connect { name } => console::connect(ctx, name).await,
            VmCmd::Attach { name, volume } => vm::attach(ctx, name, volume, true).await,
            VmCmd::Detach { name, volume } => vm::attach(ctx, name, volume, false).await,
            VmCmd::Reschedule { name } => vm::reschedule(ctx, name).await,
            VmCmd::Migrate { name, to } => vm::migrate(ctx, name, to.as_deref()).await,
            VmCmd::Evacuation { name, value } => vm::evacuation(ctx, name, value).await,
            VmCmd::Events { name } => vm::vm_events(ctx, name).await,
        },
        Cmd::Node { cluster, cmd } => cluster::node(ctx, cluster.as_deref(), cmd).await,
        Cmd::Cluster { cmd } => match cmd {
            ClusterCmd::Read(read) => read_verb(ctx, "clusters", read).await,
            other => cluster::cluster(ctx, other).await,
        },
        Cmd::Tenant { cmd } => match cmd {
            TenantCmd::Read(read) => read_verb(ctx, "tenants", read).await,
            TenantCmd::Rm { name } => generic::remove(ctx, "tenants", name).await,
            other => nouns::tenant(ctx, other).await,
        },
        Cmd::User { cmd } => match cmd {
            UserCmd::Read(read) => read_verb(ctx, "users", read).await,
            UserCmd::Rm { name } => generic::remove(ctx, "users", name).await,
            other => nouns::user(ctx, other).await,
        },
        Cmd::Csr { cmd } => match cmd {
            CsrCmd::Read(read) => read_verb(ctx, "certificatesigningrequests", read).await,
            CsrCmd::Rm { name } => generic::remove(ctx, "certificatesigningrequests", name).await,
            other => nouns::csr(ctx, other).await,
        },
        Cmd::Image { cmd } => match cmd {
            // Not `read_verb`: `image get` says how far a rollout got, which
            // is a sentence and not a field. See `nouns::image_get`.
            ImageCmd::Read(ReadCmd::Ls { selector }) => {
                generic::list(ctx, "images", selector.as_deref()).await
            }
            ImageCmd::Read(ReadCmd::Get { name }) => nouns::image_get(ctx, name).await,
            ImageCmd::Rm { name } => generic::remove(ctx, "images", name).await,
            other => nouns::image(ctx, other).await,
        },
        Cmd::Floatingpool { cmd } => match cmd {
            FloatingPoolCmd::Read(read) => read_verb(ctx, "floatingpools", read).await,
            FloatingPoolCmd::Rm { name } => generic::remove(ctx, "floatingpools", name).await,
            other => nouns::floating_pool(ctx, other).await,
        },
        Cmd::Floatingip { cmd } => match cmd {
            FloatingIpCmd::Read(read) => read_verb(ctx, "floatingips", read).await,
            FloatingIpCmd::Rm { name } => generic::remove(ctx, "floatingips", name).await,
            other => nouns::floating_ip(ctx, other).await,
        },
        Cmd::Routedsubnet { cmd } => match cmd {
            RoutedSubnetCmd::Read(read) => read_verb(ctx, "routedsubnets", read).await,
            RoutedSubnetCmd::Rm { name } => generic::remove(ctx, "routedsubnets", name).await,
            other => nouns::routed_subnet(ctx, other).await,
        },
        Cmd::Providernetwork { cmd } => match cmd {
            ProviderNetworkCmd::Read(read) => read_verb(ctx, "providernetworks", read).await,
            ProviderNetworkCmd::Rm { name } => generic::remove(ctx, "providernetworks", name).await,
            other => nouns::provider_network(ctx, other).await,
        },
        Cmd::Router { cmd } => match cmd {
            RouterCmd::Read(read) => read_verb(ctx, "routers", read).await,
            RouterCmd::Rm { name } => generic::remove(ctx, "routers", name).await,
            other => nouns::router(ctx, other).await,
        },
        Cmd::Storagepool { cmd } => match cmd {
            StoragePoolCmd::Read(read) => read_verb(ctx, "storagepools", read).await,
            StoragePoolCmd::Rm { name } => generic::remove(ctx, "storagepools", name).await,
            other => nouns::storage_pool(ctx, other).await,
        },
        Cmd::Volume { cmd } => match cmd {
            // The one listing that asks twice: `volume ls` counts the
            // snapshots standing on each disk, and that is a second request.
            VolumeCmd::Read(ReadCmd::Ls { selector }) => {
                nouns::list_volumes(ctx, selector.as_deref()).await
            }
            VolumeCmd::Read(read) => read_verb(ctx, "volumes", read).await,
            VolumeCmd::Rm { name } => nouns::remove_volume(ctx, name).await,
            other => nouns::volume(ctx, other).await,
        },
        Cmd::Secret { cmd } => match cmd {
            SecretCmd::Read(read) => read_verb(ctx, "secrets", read).await,
            SecretCmd::Rm { name } => generic::remove(ctx, "secrets", name).await,
            other => nouns::secret(ctx, other).await,
        },
        Cmd::Vmmigration { cmd } => match cmd {
            VmMigrationCmd::Read(read) => read_verb(ctx, "vmmigrations", read).await,
            VmMigrationCmd::Rm { name } => generic::remove(ctx, "vmmigrations", name).await,
        },
        Cmd::Volumesnapshot { cmd } => match cmd {
            VolumeSnapshotCmd::Read(read) => read_verb(ctx, "volumesnapshots", read).await,
            VolumeSnapshotCmd::Rm { name } => generic::remove(ctx, "volumesnapshots", name).await,
            other => nouns::volume_snapshot(ctx, other).await,
        },
        Cmd::Events(args) => generic::events(ctx, args).await,
        Cmd::Apply(args) => generic::apply(ctx, &args.file).await,
        Cmd::ApiResources => generic::api_resources(ctx, raw),
        Cmd::Whoami => generic::whoami(ctx).await,
        // Handled before the discovery, in `run`.
        Cmd::Agent { .. } | Cmd::Login(_) | Cmd::Deploy { .. } => {
            unreachable!("dispatched above")
        }
    }
}

async fn read_verb(ctx: &Ctx<'_>, resource: &str, cmd: &ReadCmd) -> Result<()> {
    match cmd {
        ReadCmd::Ls { selector } => generic::list(ctx, resource, selector.as_deref()).await,
        ReadCmd::Get { name } => generic::get(ctx, resource, name).await,
    }
}

/// Resolve a profile and make its credential usable.
///
/// The second half is the reason this is a function rather than three lines
/// repeated four times: an expired OIDC session is renewed here, once, for
/// every command. Reading the credential cannot do it — renewing is a call
/// to the identity provider and the credential is read synchronously — so
/// there has to be exactly one place between resolving and sending, and
/// this is it.
async fn target_for(cfg: &Config, ov: &Overrides) -> anyhow::Result<Target> {
    let mut target = config::resolve(cfg, ov)?;
    debug!(profile = %target.profile_name, endpoint = %target.endpoint, "resolved target");
    oidc::freshen(&mut target).await?;
    Ok(target)
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    /// The house format is one line -- `Error: <status>: <what the server
    /// said>` -- however many `.context()` calls it passed on the way up.
    #[test]
    fn an_error_chain_collapses_to_a_single_line() {
        let e = anyhow::anyhow!("409 Conflict: the object changed")
            .context("vm web-1 kept changing under the update");
        let line = one_line(&e);
        assert_eq!(
            line,
            "vm web-1 kept changing under the update: 409 Conflict: the object changed"
        );
        assert!(!line.contains('\n'));
    }

    /// A message wrapped across source lines is still one line of output.
    #[test]
    fn a_wrapped_message_does_not_wrap_the_output() {
        let e = anyhow::anyhow!("connecting to 10.0.8.21:3000\n  - is the controller running?");
        assert_eq!(
            one_line(&e),
            "connecting to 10.0.8.21:3000 - is the controller running?"
        );
    }

    /// A context that only repeats its cause is not worth a second colon.
    #[test]
    fn a_context_that_repeats_its_cause_is_said_once() {
        let e = anyhow::anyhow!("aborted").context("aborted");
        assert_eq!(one_line(&e), "aborted");
    }

    /// A single error is the whole line, with nothing added around it.
    #[test]
    fn a_bare_error_is_printed_as_it_stands() {
        let e = anyhow::anyhow!("404 Not Found: no such vm");
        assert_eq!(one_line(&e), "404 Not Found: no such vm");
    }

    /// Every subcommand says what it does and every argument says what it is.
    ///
    /// A test rather than a review habit, because help text is the only
    /// documentation an operator has in the moment they need it, and the way
    /// it rots is one flag at a time. The walk is recursive and the global
    /// flags are in it: they are arguments of the root command.
    #[test]
    fn every_subcommand_and_every_argument_carries_a_sentence() {
        fn walk(cmd: &clap::Command, path: &str) {
            for arg in cmd.get_arguments() {
                // clap writes these two itself and they are already spoken
                // for; everything else is ours.
                if matches!(arg.get_id().as_str(), "help" | "version") {
                    continue;
                }
                assert!(
                    arg.get_help().is_some(),
                    "{path} --{} has no help",
                    arg.get_id()
                );
            }
            for sub in cmd.get_subcommands() {
                let name = sub.get_name();
                if name == "help" {
                    continue;
                }
                assert!(sub.get_about().is_some(), "{path} {name} has no about");
                walk(sub, &format!("{path} {name}"));
            }
        }
        walk(&Cli::command(), "meister");
    }

    /// The two trees are told apart by the endpoint's scheme and nothing
    /// else, and mixing them up is a sentence rather than a 404 from a server
    /// that does not serve what was asked.
    #[test]
    fn pointing_a_command_at_the_other_tree_says_which_tree_it_is() {
        let target = |endpoint: &str| Target {
            profile_name: "node".into(),
            endpoint: endpoint.into(),
            ca_cert: None,
            credential: config::Credential::None,
            timeout_secs: 30,
            oidc: None,
        };

        let e = refuse_wrong_tree(&target("unix:///run/meisterstack/agent.sock"), false)
            .unwrap_err()
            .to_string();
        assert_eq!(
            e,
            "profile \"node\" is a unix socket, which is a node's own API; use \
             \"meister agent ...\""
        );

        let e = refuse_wrong_tree(&target("http://10.0.0.1:3000"), true)
            .unwrap_err()
            .to_string();
        assert!(e.contains("wants a node's own unix socket"), "{e}");

        // And the two right ways round.
        assert!(refuse_wrong_tree(&target("unix:///x.sock"), true).is_ok());
        assert!(refuse_wrong_tree(&target("https://cloud:3000"), false).is_ok());
    }

    /// The tree itself, nailed down: the nouns are the resources this control
    /// plane has, and there is no `cloud`, no `cluster` and no `agent` PREFIX
    /// left in front of any of them.
    #[test]
    fn the_tree_is_the_nouns_and_the_tier_is_not_one_of_them() {
        let cmd = Cli::command();
        let nouns: Vec<&str> = cmd.get_subcommands().map(|s| s.get_name()).collect();
        for noun in [
            "vm",
            "node",
            "cluster",
            "tenant",
            "user",
            "csr",
            "image",
            "floatingpool",
            "floatingip",
            "routedsubnet",
            "providernetwork",
            "router",
            "storagepool",
            "volume",
            "volumesnapshot",
            "events",
            "apply",
            "api-resources",
            "login",
            "agent",
        ] {
            assert!(
                nouns.contains(&noun),
                "{noun} is not in the tree: {nouns:?}"
            );
        }

        // Every noun that is a resource has `ls`; the two verbs that need no
        // code per resource really are on all of them.
        for noun in [
            "vm",
            "node",
            "cluster",
            "tenant",
            "user",
            "volume",
            "volumesnapshot",
            "providernetwork",
            "router",
        ] {
            let sub = cmd.find_subcommand(noun).expect(noun);
            let verbs: Vec<&str> = sub.get_subcommands().map(|s| s.get_name()).collect();
            assert!(verbs.contains(&"ls"), "{noun} has no ls: {verbs:?}");
            assert!(verbs.contains(&"get"), "{noun} has no get: {verbs:?}");
        }

        // `node accepts` is the machine's half of the class pairing, and it
        // is a verb rather than a flag on `label` for the reason the doc on
        // `NodeCmd::Accepts` gives: it is a statement, not a set somebody
        // accumulates.
        let node = cmd.find_subcommand("node").expect("node");
        let verbs: Vec<&str> = node.get_subcommands().map(|s| s.get_name()).collect();
        assert!(verbs.contains(&"accepts"), "{verbs:?}");

        // The agent tree carries the noun already, and `inspect`/`destroy`
        // are gone from it.
        let agent = cmd.find_subcommand("agent").unwrap();
        let vm = agent
            .find_subcommand("vm")
            .expect("the agent tree is vm-first");
        let verbs: Vec<&str> = vm.get_subcommands().map(|s| s.get_name()).collect();
        assert!(verbs.contains(&"get") && verbs.contains(&"rm"), "{verbs:?}");
        assert!(
            !verbs.contains(&"inspect") && !verbs.contains(&"destroy"),
            "{verbs:?}"
        );
    }
}
