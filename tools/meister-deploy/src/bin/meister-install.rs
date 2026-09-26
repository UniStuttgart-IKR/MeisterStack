// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Interactive target installer for the embedded /etc/meister-install/target.json.
//! A person must name the host and disk serial; no boot-time installer runs
//! automatically. See [`meister_deploy::install`] for validation and disk effects.

use std::io::{self, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};

use meister_deploy::effects::{RealClock, RealFiles};
use meister_deploy::install::{self, Installer};
use meister_deploy::run::{Cancel, Policy, Real};

#[derive(Parser)]
#[command(
    name = "meister-install",
    about = "Install the host this medium was built for onto the disk you name",
    long_about = "Runs on an installer medium, as root. It refuses five ways before it does \
                  anything: the medium has to be for this host, exactly one disk has to \
                  carry the serial, that disk has to be the one the layout names, it must \
                  not already be installed, and nothing this host preserves may be on it. \
                  Then it prints what it is about to destroy."
)]
struct Cli {
    /// What this medium was built with
    #[arg(long, default_value = install::TARGET_PATH, global = true)]
    target: PathBuf,

    /// Where the target's filesystems are mounted while it is installed
    #[arg(long, default_value = install::ROOT, global = true)]
    root: PathBuf,

    /// Temporary mountpoint used to inspect installation marks.
    #[arg(long, default_value = install::PROBE_DIR, global = true)]
    probe_dir: PathBuf,

    /// Print the answer as json instead of as lines
    #[arg(long, global = true)]
    json: bool,

    /// Print every command before it runs
    #[arg(short, long, global = true)]
    verbose: bool,

    #[command(subcommand)]
    cmd: Verb,
}

#[derive(Subcommand)]
enum Verb {
    /// Install this medium's host onto the disk with this serial.
    Confirm {
        /// Host ID embedded in this installer; cannot select a different target.
        #[arg(long)]
        host: String,

        /// Disk serial from lsblk and inventory, not an unstable device path.
        #[arg(long)]
        disk: String,

        /// Optional WWN to distinguish disks sharing a serial.
        #[arg(long)]
        wwn: Option<String>,

        /// Allow replacing an existing installation, including its data and identity.
        #[arg(long)]
        reinstall: bool,

        /// The plan this installation belongs to, recorded in the mark.
        #[arg(long)]
        plan: Option<String>,

        /// Validate and print the summary without formatting; may mount partitions read-only.
        #[arg(long)]
        dry_run: bool,
    },
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            // Keep diagnostics on stderr and structured output on stdout.
            eprintln!("meister-install: {e:#}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<()> {
    let cli = Cli::parse();
    // Propagate cancellation to installer subprocesses.
    Cancel::on_sigint()?;
    // Dry-run rejects target-write/key commands; read-class probes may still mount partitions.
    let dry_run = match &cli.cmd {
        Verb::Confirm { dry_run, .. } => *dry_run,
    };
    let policy = if dry_run {
        Policy::dry_run()
    } else {
        Policy::real()
    };
    let runner = Real::new(policy).verbose(cli.verbose);
    let files = RealFiles::new(policy);
    let installer = Installer::new(&runner, &files, &RealClock)
        .with_target(cli.target.clone())
        .with_root(cli.root.clone())
        .with_probe_dir(cli.probe_dir.clone());

    match &cli.cmd {
        Verb::Confirm {
            host,
            disk,
            wwn,
            reinstall,
            plan,
            dry_run,
        } => {
            let (prepared, summary) = installer.prepare(
                host,
                disk,
                wwn.as_deref(),
                *reinstall,
                plan.as_deref(),
                *dry_run,
            )?;
            // Flush the destructive-action summary before executing any installation step.
            eprint!("{summary}");
            io::stderr()
                .flush()
                .context("printing the summary failed")?;
            let outcome = installer.execute(prepared)?;
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&outcome)?);
            } else {
                if let Some(mark) = &outcome.installed {
                    // Print the host fingerprint needed for trusted enrollment.
                    println!();
                    println!("    HOST KEY FINGERPRINT  {}", mark.host_key_fingerprint);
                    println!("    machine-id            {}", mark.machine_id);
                    println!();
                }
                println!("{}", outcome.next);
            }
        }
    }
    Ok(())
}
