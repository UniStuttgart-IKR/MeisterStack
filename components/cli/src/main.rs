// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

use std::process::ExitCode;

use anyhow::Result;
use clap::{Args, Parser, Subcommand, ValueEnum};
use macros::generated;
use tracing::debug;

mod agent;
mod client;
mod cloud;
mod cluster;
mod config;
mod login;
mod output;
mod vm;

use config::{Config, Overrides, Tier};

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
    cmd: TierCmd,
}

#[derive(Args, Debug)]
pub struct GlobalArgs {
    #[arg(long, short = 'p', global = true)]
    profile: Option<String>,

    #[arg(long, global = true)]
    endpoint: Option<String>,

    #[arg(long, global = true)]
    config: Option<std::path::PathBuf>,

    #[arg(long, short = 'o', global = true, default_value = "table")]
    output: OutputFormat,

    #[arg(long, global = true)]
    yes: bool,

    #[arg(long, short = 'v', global = true, action = clap::ArgAction::Count)]
    verbose: u8,
}

#[derive(Copy, Clone, Debug, ValueEnum)]
pub enum OutputFormat {
    Table,
    Json,
}

// The three tiers do not have the same verbs, and where they differ it is
// the tier differing rather than the CLI drifting:
//
// * `agent create` takes no name and the two tiers above do. The node
//   assigns the id, because at that level the id is the directory entry.
// * `agent observe` and `agent reconcile` have no counterpart above. They
//   ask what one node's processes are actually doing, and a controller has
//   no such thing to look at -- it has what a node reported.
// * `agent stop --grace` is the only stop that takes a grace period,
//   because it is the only one that waits it out. Above it, `stop` writes a
//   runStrategy and the node it lands on applies its own.
// * `cloud vm create --tenant` exists and the cluster's does not. Naming an
//   owner needs a user directory, and that lives only at the cloud.
// * a VM is `destroy`ed and everything else is `rm`ed. A catalogue entry is
//   removed; a VM is a running machine, and the verb says which of the two
//   this is.
// * `cluster nodes` and `cloud clusters` are nouns without an `ls`, because
//   they are not managed from here: a node joins a cluster and a cluster
//   joins a cloud, and neither is created or deleted by this CLI.
//
// Everything else is symmetric on purpose -- the eight VM verbs are the
// same eight words at both tiers that have them, and every destructive verb
// at every tier goes through the same confirmation.
#[derive(Subcommand)]
enum TierCmd {
    Agent {
        #[command(subcommand)]
        cmd: AgentCmd,
    },
    Cluster {
        #[command(subcommand)]
        cmd: ClusterCmd,
    },
    Cloud {
        #[command(subcommand)]
        cmd: CloudCmd,
    },
    /// Get a client certificate from the cloud: generate a key pair here,
    /// send only the request, collect the certificate.
    Login(LoginArgs),
}

/// `meister login` — sugar over the certificatesigningrequests flow, and
/// nothing more than sugar: every step of it is a call an operator could
/// make by hand.
#[derive(Args, Debug)]
pub struct LoginArgs {
    /// Who to ask for a certificate for. Defaults to $USER.
    #[arg(long)]
    pub user: Option<String>,
    /// Where to put the key and the certificate. Defaults to the paths the
    /// profile's mtls credential already names, and otherwise to
    /// <config dir>/pki/<profile>.{key,crt}.
    #[arg(long)]
    pub out: Option<std::path::PathBuf>,
    /// How long to wait for an administrator to approve. 0 = do not wait;
    /// with the controller's csr_auto_approve the certificate is there on
    /// the first answer either way.
    #[arg(long, default_value = "120")]
    pub wait_secs: u64,
}

#[derive(Subcommand)]
pub enum AgentCmd {
    /// What the guest printed. Same one-way read as the two tiers above,
    /// straight off this node's own ring.
    Logs {
        id: String,
        /// How many lines from the END (default 200)
        #[arg(long)]
        lines: Option<u32>,
    },

    Ls,
    Inspect {
        id: String,
    },
    Observe {
        id: String,
    },
    Reconcile {
        id: String,
    },
    Create {
        #[arg(long)]
        spec: std::path::PathBuf,
    },
    Destroy {
        id: String,
    },
    Start {
        id: String,
    },
    Stop {
        id: String,
        #[arg(long)]
        grace: Option<u64>,
    },
    Pause {
        id: String,
    },
    Resume {
        id: String,
    },
}

#[derive(Subcommand)]
pub enum ClusterCmd {
    Nodes,
    /// Draining a node: what an operator decides about it, as opposed to what
    /// the agent reports. Listing them is still `meister cluster nodes`.
    Node {
        #[command(subcommand)]
        cmd: ClusterNodeCmd,
    },
    Vm {
        #[command(subcommand)]
        cmd: ClusterVmCmd,
    },
}

/// Cordon and uncordon, and deliberately nothing else.
///
/// Draining stops NEW placements. It evicts nothing, migrates nothing and
/// stops nothing: the VMs on the node go on running and go on being
/// reconciled. `meister cluster nodes` shows a drained node as `drained` in
/// the ready column.
#[derive(Subcommand)]
pub enum ClusterNodeCmd {
    /// Stop placing new vms here (spec.schedulable = false)
    Cordon { name: String },
    /// Take the drain off (spec.schedulable = true)
    Uncordon { name: String },
}

#[derive(Subcommand)]
pub enum ClusterVmCmd {
    /// What the guest printed before anything inside it was reachable:
    /// firmware, bootloader, kernel, panic, emergency shell. One way — there
    /// is deliberately no attach, no input and no --follow.
    Logs {
        name: String,
        /// How many lines from the END (default 200). The node keeps a
        /// bounded ring per stream, so this only shortens what comes out.
        #[arg(long)]
        lines: Option<u32>,
    },
    Create {
        name: String,
        /// The agent's NewVmSpec JSON (same file `meister agent create` takes)
        #[arg(long)]
        spec: std::path::PathBuf,
        /// Running | Stopped | Paused (default Running)
        #[arg(long)]
        run_strategy: Option<String>,
    },
    Ls,
    Inspect {
        name: String,
    },
    Destroy {
        name: String,
    },
    /// Set runStrategy = Running
    Start {
        name: String,
    },
    /// Set runStrategy = Stopped (the guest gets the node's grace period)
    Stop {
        name: String,
    },
    /// Set runStrategy = Paused
    Pause {
        name: String,
    },
    /// Set runStrategy = Running on a paused vm
    Resume {
        name: String,
    },
}

#[derive(Subcommand)]
pub enum CloudCmd {
    /// The clusters this cloud knows about, ready or not
    Clusters,
    /// Draining a cluster — the same verb one tier up. Listing them is still
    /// `meister cloud clusters`.
    Cluster {
        #[command(subcommand)]
        cmd: CloudClusterCmd,
    },
    Vm {
        #[command(subcommand)]
        cmd: CloudVmCmd,
    },
    Image {
        #[command(subcommand)]
        cmd: CloudImageCmd,
    },
    /// Tenants — the unit a user belongs to, and from M5 a VM too
    Tenant {
        #[command(subcommand)]
        cmd: CloudTenantCmd,
    },
    /// The user directory. A certificate says who somebody is; this says
    /// what they may do.
    User {
        #[command(subcommand)]
        cmd: CloudUserCmd,
    },
    /// Certificate requests, and saying yes or no to them
    Csr {
        #[command(subcommand)]
        cmd: CloudCsrCmd,
    },
    /// The addresses this operator HAS. Admin-only: a pool is a piece of
    /// somebody's real address space, and who may take from it is a quota.
    Floatingpool {
        #[command(subcommand)]
        cmd: CloudFloatingPoolCmd,
    },
    /// Reservations out of a pool, and which VM each one is for
    Floatingip {
        #[command(subcommand)]
        cmd: CloudFloatingIpCmd,
    },
    /// Real subnets handed to a tenant — the NAT-free half. Admin-only.
    Routedsubnet {
        #[command(subcommand)]
        cmd: CloudRoutedSubnetCmd,
    },
}

/// The Node verbs one tier up, over the Cluster object, with the same narrow
/// meaning: no new placements, and nothing already there is touched.
#[derive(Subcommand)]
pub enum CloudClusterCmd {
    /// Stop placing new vms on this cluster (spec.schedulable = false)
    Cordon { name: String },
    /// Take the drain off (spec.schedulable = true)
    Uncordon { name: String },
}

#[derive(Subcommand)]
pub enum CloudFloatingPoolCmd {
    Create {
        name: String,
        /// A range this pool holds. Repeatable, and each one may be a cidr
        /// (10.255.0.0/16), a single address (203.0.113.7) or a range
        /// (203.0.113.8-203.0.113.11) — four scattered public addresses are
        /// one pool with four of these.
        #[arg(long = "cidr", required = true)]
        cidrs: Vec<String>,
        /// These addresses are routable from outside. Sets the default quota
        /// to zero: a real public address is handed out by an admin, one
        /// tenant at a time, with `floatingpool quota`.
        #[arg(long)]
        public: bool,
        /// Reservations that name no pool land here. At most one pool may say
        /// this.
        #[arg(long)]
        default: bool,
        #[arg(long)]
        description: Option<String>,
    },
    Ls,
    /// How many addresses a tenant may hold out of this pool. This is the one
    /// explicit act that hands out a routable address.
    Quota {
        pool: String,
        tenant: String,
        count: u32,
    },
    Rm {
        name: String,
    },
}

#[derive(Subcommand)]
pub enum CloudFloatingIpCmd {
    /// Reserve an address. The server picks the first free one in the pool
    /// unless --address names one.
    Create {
        /// Whose reservation. A member's own tenant is filled in by the
        /// server; an admin reserving for somebody has to say which.
        #[arg(long)]
        tenant: Option<String>,
        /// Which pool. Unset = the one marked default.
        #[arg(long)]
        pool: Option<String>,
        /// Ask for this address specifically — the one DNS already points at.
        /// Refused with a reason rather than quietly replaced.
        #[arg(long)]
        address: Option<String>,
        /// Point it at a VM straight away, same as `floatingip assign`.
        #[arg(long)]
        vm: Option<String>,
    },
    Ls,
    /// Point an address at a VM, or take it off one. The object changes now;
    /// the VM's tap rules follow when it is next recreated.
    Assign {
        address: String,
        #[arg(long, conflicts_with = "release")]
        vm: Option<String>,
        /// Take the address off whatever VM has it, keeping the reservation.
        #[arg(long)]
        release: bool,
    },
    /// Give the address back to the pool.
    Rm {
        address: String,
    },
}

#[derive(Subcommand)]
pub enum CloudRoutedSubnetCmd {
    Create {
        name: String,
        #[arg(long)]
        tenant: String,
        /// The subnet outright. Unset = cut the first free block out of the
        /// cloud's routed_pools.
        #[arg(long)]
        cidr: Option<String>,
        /// How big a block to cut when --cidr is not given (default 24).
        #[arg(long)]
        prefix_len: Option<u32>,
        #[arg(long)]
        description: Option<String>,
    },
    Ls,
    Rm {
        name: String,
    },
}

#[derive(Subcommand)]
pub enum CloudTenantCmd {
    Create {
        name: String,
        #[arg(long)]
        description: Option<String>,
    },
    Ls,
    /// What this tenant may hold. Admin-only, and not by a rule written into
    /// the verb: `tenants` is not a resource a member may write at all, so a
    /// member raising their own ceiling is refused by the API guard.
    ///
    /// A limit that is not named is left as it stands; `--unlimited` takes
    /// all three off. Counted over every phase, Pending included.
    Quota {
        name: String,
        #[arg(long)]
        max_vms: Option<u32>,
        #[arg(long)]
        max_vcpus: Option<u32>,
        #[arg(long)]
        max_mem_mib: Option<u64>,
        /// Take the whole quota off — the inverse of setting one, and the
        /// only way back to "unlimited", which is what a limit of 0 is not.
        #[arg(long, conflicts_with_all = ["max_vms", "max_vcpus", "max_mem_mib"])]
        unlimited: bool,
    },
    Rm {
        name: String,
    },
}

#[derive(Subcommand)]
pub enum CloudUserCmd {
    Create {
        name: String,
        #[arg(long)]
        tenant: String,
        /// admin | member (default member)
        #[arg(long, default_value = "member")]
        role: String,
        #[arg(long)]
        description: Option<String>,
    },
    Ls,
    /// Change what a user may do. Takes effect at the cloud on the next
    /// request; at a cluster when the certificate is re-issued.
    SetRole {
        name: String,
        /// admin | member
        role: String,
    },
    Rm {
        name: String,
    },
}

#[derive(Subcommand)]
pub enum CloudCsrCmd {
    Ls,
    Inspect {
        name: String,
    },
    Approve {
        name: String,
    },
    Deny {
        name: String,
        #[arg(long)]
        reason: Option<String>,
    },
    Rm {
        name: String,
    },
}

#[derive(Subcommand)]
pub enum CloudVmCmd {
    /// What the guest printed before anything inside it was reachable:
    /// firmware, bootloader, kernel, panic, emergency shell. One way — there
    /// is deliberately no attach, no input and no --follow.
    Logs {
        name: String,
        /// How many lines from the END (default 200). The node keeps a
        /// bounded ring per stream, so this only shortens what comes out.
        #[arg(long)]
        lines: Option<u32>,
    },
    Create {
        name: String,
        /// The agent's NewVmSpec JSON (same file every tier takes)
        #[arg(long)]
        spec: std::path::PathBuf,
        /// Running | Stopped | Paused (default Running)
        #[arg(long)]
        run_strategy: Option<String>,
        /// Whose VM this is. A member's own tenant is filled in by the
        /// server; an admin creating a VM for somebody has to say which.
        #[arg(long)]
        tenant: Option<String>,
    },
    Ls,
    Inspect {
        name: String,
    },
    Destroy {
        name: String,
    },
    /// Set runStrategy = Running
    Start {
        name: String,
    },
    /// Set runStrategy = Stopped (the guest gets the node's grace period)
    Stop {
        name: String,
    },
    /// Set runStrategy = Paused
    Pause {
        name: String,
    },
    /// Set runStrategy = Running on a paused vm
    Resume {
        name: String,
    },
}

/// The catalogue. v1 registers where an image already is and checks that VMs
/// only name images somebody registered; it moves no bytes.
#[derive(Subcommand)]
pub enum CloudImageCmd {
    Create {
        /// The file name nodes look up — and what a VM's base_image says
        name: String,
        /// Where the image already is (shared storage path)
        #[arg(long)]
        source: String,
        /// raw | qcow2
        #[arg(long, default_value = "raw")]
        format: String,
        /// Size in bytes, for the operator reading `image ls`
        #[arg(long)]
        size: Option<u64>,
        /// Whose image this is. Filled in from the caller's own tenant when
        /// a member creates one.
        #[arg(long)]
        tenant: Option<String>,
        /// Readable by every tenant, writable only by its own. What a shared
        /// base image is.
        #[arg(long)]
        public: bool,
    },
    Ls,
    Rm {
        name: String,
    },
}

#[tokio::main]
#[generated(model = ClaudeOpus, version = "5")]
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
#[generated(model = ClaudeOpus, version = "5")]
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

#[generated(model = ClaudeOpus, version = "5")]
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
        tolerate_missing_credential: matches!(cli.cmd, TierCmd::Login(_)),
    };

    match &cli.cmd {
        TierCmd::Agent { cmd } => {
            let target = config::resolve(&cfg, Tier::Agent, &overrides)?;
            debug!(profile = %target.profile_name, endpoint = %target.endpoint, "resolved target");
            agent::run(&target, cmd, &cli.global).await
        }
        TierCmd::Cluster { cmd } => {
            let target = config::resolve(&cfg, Tier::Cluster, &overrides)?;
            debug!(profile = %target.profile_name, endpoint = %target.endpoint, "resolved target");
            cluster::run(&target, cmd, &cli.global).await
        }
        TierCmd::Cloud { cmd } => {
            let target = config::resolve(&cfg, Tier::Cloud, &overrides)?;
            debug!(profile = %target.profile_name, endpoint = %target.endpoint, "resolved target");
            cloud::run(&target, cmd, &cli.global).await
        }
        TierCmd::Login(args) => {
            let target = config::resolve(&cfg, Tier::Cloud, &overrides)?;
            debug!(profile = %target.profile_name, endpoint = %target.endpoint, "resolved target");
            login::run(&cfg, &target, args, &cli.global).await
        }
    }
}

#[cfg(test)]
#[generated(model = ClaudeOpus, version = "5")]
mod tests {
    use super::*;

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
}
