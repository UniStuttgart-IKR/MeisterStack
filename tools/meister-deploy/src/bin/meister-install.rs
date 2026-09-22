// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! `meister-install` — the one command somebody types on an installer
//! medium, standing in front of a machine.
//!
//! It is the third binary of the `meister-deploy` crate: the workstation
//! half plans and builds, `meister-activate` moves a system that is already
//! there, and this one turns an empty disk into a host. It knows no fleet,
//! no network and no manifest — what it knows is
//! `/etc/meister-install/target.json`, which the medium was built with
//! ([`meister_deploy::install`] says what is in it and why).
//!
//! Nothing here runs by itself. There is no unit, no timer and no autostart
//! on the medium (D9): a person boots it, reads `/etc/issue`, and types the
//! serial of the disk. That is the whole safety model, and it is the right
//! one — an installer that formats a disk because a stick was left in a
//! drive is the failure this verb exists to prevent.

use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::Result;
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

    /// Where a partition is mounted for a moment while the installation
    /// mark is looked for
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
        /// The host, as the inventory calls it. It has to be the one this
        /// medium was built for — the flag is there so that a person types
        /// it and reads it back, not so that the medium can be pointed
        /// somewhere else.
        #[arg(long)]
        host: String,

        /// The disk's own serial, as `lsblk -o SERIAL` prints it and as the
        /// inventory records it. Never a device path: `/dev/sda` is a name
        /// the kernel hands out in boot order.
        #[arg(long)]
        disk: String,

        /// The disk's wwn, for the case where two disks carry one serial.
        /// A virtio disk has none (M0 probe S7), so this is optional.
        #[arg(long)]
        wwn: Option<String>,

        /// Install over a disk that already carries an installation mark.
        /// This destroys that machine's identity along with everything else
        /// on the disk.
        #[arg(long)]
        reinstall: bool,

        /// The plan this installation belongs to, recorded in the mark.
        #[arg(long)]
        plan: Option<String>,

        /// Check everything and print the summary — and destroy nothing.
        #[arg(long)]
        dry_run: bool,
    },
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            // Diagnostics on stderr, always: stdout carries the answer, and
            // `--json` has to stay machine-readable even when it is empty.
            eprintln!("meister-install: {e:#}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<()> {
    let cli = Cli::parse();
    // A `nixos-install` can take half an hour, and a Ctrl-C has to reach it
    // rather than leave a half-copied store on a half-mounted disk.
    Cancel::on_sigint()?;
    // `--dry-run` is a POLICY here, like everywhere else in this crate: the
    // commands that look are `read` and the four that change the machine are
    // `target-write` and `key`, so a dry run is refused by the runner rather
    // than by somebody remembering an `if`.
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
            let (outcome, summary) = installer.confirm(
                host,
                disk,
                wwn.as_deref(),
                *reinstall,
                plan.as_deref(),
                *dry_run,
            )?;
            // The summary on stderr and the answer on stdout, so that a
            // person reads the first and a script reads the second.
            eprint!("{summary}");
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&outcome)?);
            } else {
                if let Some(mark) = &outcome.installed {
                    // The one line somebody has to carry away from this
                    // console, in the shape `keys enroll` takes, and loud.
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
