// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Target-side system activation, transaction records, locks and key operations.
//! The managed NixOS closure includes this binary; apply invokes it over SSH.
//! Local transaction records preserve recovery state before the profile changes.
//! See [`meister_deploy::activate`] for ordering and recovery limits.

use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};

use meister_deploy::activate::{
    DEFAULT_PKI_DIR, Helper, KeyKind, Mode, RevertAsker, SYSTEM_PROFILE, TxnRecord, ok_reply,
};
use meister_deploy::effects::{RealClock, RealFiles};
use meister_deploy::observe::DEPLOY_DIR;
use meister_deploy::run::{Cancel, Policy, Real};

#[derive(Parser)]
#[command(
    name = "meister-activate",
    about = "Move this host's system generation, and write down the way back",
    long_about = "Runs on the target, as root. `meister-deploy apply` drives it over ssh; an \
                  operator can drive it by hand, which is the point of it being a program. \
                  Every command takes --json."
)]
struct Cli {
    /// Where the transaction records and the lock live
    #[arg(long, default_value = DEPLOY_DIR, global = true)]
    deploy_dir: PathBuf,

    /// Where this host's key material lives (`meisterstack.pki.dir`)
    #[arg(long, default_value = DEFAULT_PKI_DIR, global = true)]
    pki_dir: PathBuf,

    /// The system profile to move
    #[arg(long, default_value = SYSTEM_PROFILE, global = true)]
    profile: PathBuf,

    /// Print the answer as json instead of as a line
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
    /// Report current, booted and next systems, transactions and lock state.
    Status,

    /// Check that a complete NixOS system is present without writing state.
    Stage {
        /// The store path of the system
        toplevel: String,
    },

    /// Activate a NixOS system with a recorded rollback target.
    Activate {
        /// The transaction id — letters, digits, `-` and `_`
        #[arg(long)]
        txn: String,
        /// The store path of the system to activate
        #[arg(long)]
        toplevel: String,
        /// `switch` changes the running system now; `boot` leaves it alone
        /// and makes the new one the next boot (systemd-boot only)
        #[arg(long, default_value = "switch")]
        mode: String,
        /// Confirmation deadline in seconds; 0 disables automatic rollback.
        #[arg(long, default_value_t = 300)]
        confirm_within: u64,
        /// The run this activation belongs to
        #[arg(long)]
        run: Option<String>,
    },

    /// Keep it: stop the revert timer and say so in the record.
    Confirm {
        #[arg(long)]
        txn: String,
    },

    /// Take it back: the previous system, and the reason in the record.
    Revert {
        #[arg(long)]
        txn: String,
        /// Why — it goes into the record, which is what somebody reads
        /// afterwards
        #[arg(long)]
        because: Option<String>,
        /// Override an in-flight confirmation; requires --because.
        #[arg(long)]
        force: bool,
        /// Timer-triggered revert; refuses to override an in-flight confirmation.
        #[arg(long)]
        by_timer: bool,
    },

    /// The transaction records this host holds.
    Txn {
        #[command(subcommand)]
        cmd: TxnVerb,
    },

    /// Who is deploying to this host.
    Lock {
        #[command(subcommand)]
        cmd: LockVerb,
    },

    /// Delete the generations nothing needs any more and collect the store.
    /// Keeps the running system, the booted one, and the newest N besides.
    Gc {
        #[arg(long, default_value_t = 3)]
        keep: usize,
    },

    /// Generate or reuse a local private key and print its CSR.
    /// Replacement requires --replace.
    Keygen {
        /// Requested CN, e.g. system:node:n1; the CA controls the issued subject.
        #[arg(long)]
        subject: String,
        /// Which key: `identity` (what this host dials with) or `serving`
        /// (what a client checks this address against)
        #[arg(long, default_value = "identity")]
        kind: String,
        /// Replace the existing key for an intentional rotation or reinstall.
        #[arg(long)]
        replace: bool,
        /// Write <kind>.key.<suffix>; next prepares a rotation without replacing the active key.
        #[arg(long)]
        suffix: Option<String>,
    },

    /// Inspect, switch, revert or finalize a prepared local key rotation.
    Keys {
        #[command(subcommand)]
        cmd: KeysVerb,
    },
}

#[derive(Subcommand)]
enum KeysVerb {
    /// Where a rotation of this key has got to, read off the disk
    Status {
        #[arg(long, default_value = "identity")]
        kind: String,
    },
    /// Switch to the prepared key pair and retain the previous pair for recovery.
    Switch {
        #[arg(long, default_value = "identity")]
        kind: String,
        /// The run that owns this rotation
        #[arg(long)]
        run: Option<String>,
    },
    /// Put the pair that was in use back, and drop the one that failed
    Revert {
        #[arg(long, default_value = "identity")]
        kind: String,
        /// Why, for the record
        #[arg(long)]
        reason: Option<String>,
    },
    /// Drop the pair the switch replaced. The rotation is over.
    Remove {
        #[arg(long, default_value = "identity")]
        kind: String,
    },
}

#[derive(Subcommand)]
enum TxnVerb {
    /// Every record, open or finished
    List,
    /// One record
    Show {
        #[arg(long)]
        txn: String,
    },
    /// Archive a finished transaction so subsequent plans can proceed.
    Retire {
        #[arg(long)]
        txn: String,
        /// The run that owns it
        #[arg(long)]
        run: Option<String>,
        /// Archive an inconsistent record with --reason; staged/pending records are refused.
        #[arg(long)]
        force: bool,
        /// Reason recorded with a forced transaction retirement.
        #[arg(long)]
        reason: Option<String>,
    },
}

#[derive(Subcommand)]
enum LockVerb {
    /// Take this host for a run, or say who has it
    Acquire {
        #[arg(long)]
        run: String,
        /// Who is deploying, as the workstation knows them
        #[arg(long)]
        operator: String,
        /// Operator PID for diagnostics; 0 means unspecified.
        #[arg(long, default_value_t = 0)]
        pid: u32,
    },
    /// Give it back. Only the run that holds it may.
    Release {
        #[arg(long)]
        run: String,
    },
    /// Take a named run's lock, deliberately
    TakeOver {
        /// The run whose lock is taken — it has to be the one that is there
        #[arg(long)]
        of_run: String,
        #[arg(long)]
        run: String,
        #[arg(long)]
        operator: String,
        #[arg(long, default_value_t = 0)]
        pid: u32,
    },
    /// What the lock file says
    Show,
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            // Keep errors on stderr and structured output on stdout.
            eprintln!("meister-activate: {e:#}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<()> {
    let cli = Cli::parse();
    // Propagate cancellation to activation commands.
    Cancel::on_sigint()?;
    // Survive SIGHUP when activation restarts SSH or networking.
    Cancel::ignore_sighup()?;
    let policy = Policy::real();
    let runner = Real::new(policy).verbose(cli.verbose);
    let files = RealFiles::new(policy);
    // Bind revert timers to this executable, not a profile symlink that may change.
    let own_exe = std::env::current_exe()
        .context("this program could not find its own path, and a revert timer has to name it")?;
    let helper = Helper::new(&runner, &files, &RealClock, cli.deploy_dir.clone(), own_exe)
        .with_profile(cli.profile.clone())
        // Pass the current PATH to transient rollback units.
        .with_timer_path(std::env::var("PATH").unwrap_or_default())
        .with_pki_dir(cli.pki_dir.clone());

    match &cli.cmd {
        Verb::Status => {
            let status = helper.status()?;
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&status)?);
            } else {
                print!("{}", status_lines(&status));
            }
        }
        Verb::Stage { toplevel } => {
            helper.stage(toplevel)?;
            answer(
                &cli,
                "stage",
                serde_json::json!({ "toplevel": toplevel }),
                &format!("{toplevel} is here, whole, and is a NixOS system."),
            )?;
        }
        Verb::Activate {
            txn,
            toplevel,
            mode,
            confirm_within,
            run,
        } => {
            let record = helper.activate(
                txn,
                toplevel,
                Mode::parse(mode)?,
                *confirm_within,
                run.as_deref(),
            )?;
            answer(
                &cli,
                "activate",
                serde_json::to_value(&record)?,
                &describe(&record),
            )?;
        }
        Verb::Confirm { txn } => {
            let record = helper.confirm(txn)?;
            answer(
                &cli,
                "confirm",
                serde_json::to_value(&record)?,
                &describe(&record),
            )?;
        }
        Verb::Revert {
            txn,
            because,
            force,
            by_timer,
        } => {
            // A timer cannot request a forced override of an operator decision.
            let asked = match (by_timer, force) {
                (true, true) => anyhow::bail!(
                    "`--by-timer` and `--force` are not said together: the deadline does not \
                     overrule anybody, and a person who does is not a timer."
                ),
                (true, false) => RevertAsker::Deadline,
                (false, true) => RevertAsker::Force,
                (false, false) => RevertAsker::Operator,
            };
            let record = helper.revert(txn, because.as_deref(), asked)?;
            // Explain when a pending confirmation prevents timer rollback.
            let sentence = if record.state_word() == "confirming" {
                format!(
                    "{}: a confirmation was in flight, so nothing was taken back — the \
                     deadline means nobody spoke, and somebody did. `meister-activate \
                     confirm --txn {}` finishes it.",
                    record.id, record.id
                )
            } else {
                describe(&record)
            };
            answer(&cli, "revert", serde_json::to_value(&record)?, &sentence)?;
        }
        Verb::Txn { cmd } => match cmd {
            TxnVerb::List => {
                let records = helper.records()?;
                if cli.json {
                    println!("{}", serde_json::to_string_pretty(&records)?);
                } else {
                    for record in &records {
                        println!("{}", describe(record));
                    }
                }
            }
            TxnVerb::Show { txn } => {
                let record = helper.record(txn)?;
                if cli.json {
                    println!("{}", serde_json::to_string_pretty(&record)?);
                } else {
                    print!("{}", show_lines(&record));
                }
            }
            TxnVerb::Retire {
                txn,
                run,
                force,
                reason,
            } => {
                let record = match (force, reason) {
                    (false, None) => helper.retire(txn, run.as_deref())?,
                    (true, Some(reason)) => helper.retire_forced(txn, run.as_deref(), reason)?,
                    (true, None) => anyhow::bail!(
                        "`txn retire --force` needs `--reason <sentence>`: the archive it \
                         writes is the only account of this decision there will ever be."
                    ),
                    (false, Some(_)) => anyhow::bail!(
                        "`--reason` belongs to `--force`. An ordinary retire is a run saying \
                         it is done with a finished record, and that needs no explaining."
                    ),
                };
                let sentence = match &record.retired_by_force {
                    Some(forced) => format!(
                        "the record of {} was {} and is archived at {}: {} Nothing on this \
                         machine was changed.",
                        record.id,
                        record.state_word(),
                        helper.txn_archive(&record.id).display(),
                        forced.reason
                    ),
                    None => format!("the record of {} is retired.", record.id),
                };
                answer(&cli, "retire", serde_json::to_value(&record)?, &sentence)?;
            } // --- end lane 5C ---
        },
        Verb::Lock { cmd } => match cmd {
            LockVerb::Acquire { run, operator, pid } => {
                let lock = helper.lock_acquire(run, operator, *pid)?;
                answer(
                    &cli,
                    "lock",
                    serde_json::to_value(&lock)?,
                    &format!(
                        "this host is held by the run {} ({}).",
                        lock.run_id, lock.operator
                    ),
                )?;
            }
            LockVerb::Release { run } => {
                let lock = helper.lock_release(run)?;
                answer(
                    &cli,
                    "unlock",
                    serde_json::to_value(&lock)?,
                    &match &lock {
                        Some(lock) => format!("the run {} has given this host back.", lock.run_id),
                        None => "nobody held this host.".to_string(),
                    },
                )?;
            }
            LockVerb::TakeOver {
                of_run,
                run,
                operator,
                pid,
            } => {
                let lock = helper.lock_take_over(of_run, run, operator, *pid)?;
                answer(
                    &cli,
                    "lock",
                    serde_json::to_value(&lock)?,
                    &format!("the run {run} has taken this host over from {of_run}."),
                )?;
            }
            LockVerb::Show => {
                let lock = helper.read_lock()?;
                if cli.json {
                    println!("{}", serde_json::to_string_pretty(&lock)?);
                } else {
                    match &lock {
                        Some(lock) => println!(
                            "run {} since {} (operator {}, pid {})",
                            lock.run_id, lock.acquired_at, lock.operator, lock.pid
                        ),
                        None => println!("nobody holds this host"),
                    }
                }
            }
        },
        Verb::Gc { keep } => {
            let outcome = helper.gc(*keep)?;
            answer(
                &cli,
                "gc",
                serde_json::to_value(&outcome)?,
                &format!(
                    "{} generation(s) deleted, {} kept, {} finished record(s) removed. No \
                     generation of any other profile was touched.",
                    outcome.removed.len(),
                    outcome.kept.len(),
                    outcome.archives_removed
                ),
            )?;
        }
        Verb::Keygen {
            subject,
            kind,
            replace,
            suffix,
        } => {
            let outcome =
                helper.keygen_into(subject, KeyKind::parse(kind)?, *replace, suffix.as_deref())?;
            // Key generation uses KeygenReply directly; plain output is the CSR.
            // Do not wrap it in the generic response envelope.
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&outcome)?);
            } else {
                eprintln!(
                    "{} {} for {} ({})",
                    if outcome.created {
                        "made a new key"
                    } else {
                        "kept the key that was here and made another request"
                    },
                    helper
                        .key_path_with(KeyKind::parse(kind)?, suffix.as_deref())
                        .display(),
                    outcome.subject,
                    outcome.public_key_sha256
                );
                print!("{}", outcome.csr_pem);
            }
        } // --- end lane 3B ----------------------------------------------
        Verb::Keys { cmd } => match cmd {
            KeysVerb::Status { kind } => {
                let view = helper.keys_status(KeyKind::parse(kind)?)?;
                let said = format!(
                    "{}: {}{}",
                    view.kind,
                    view.state,
                    view.reason
                        .as_deref()
                        .map(|r| format!(" ({r})"))
                        .unwrap_or_default()
                );
                answer(&cli, "keys status", serde_json::to_value(&view)?, &said)?;
            }
            KeysVerb::Switch { kind, run } => {
                let record = helper.keys_switch(KeyKind::parse(kind)?, run.as_deref())?;
                answer(
                    &cli,
                    "keys switch",
                    serde_json::to_value(&record)?,
                    &format!(
                        "{kind}: the prepared pair is in use, the one it replaced is beside it"
                    ),
                )?;
            }
            KeysVerb::Revert { kind, reason } => {
                let record = helper.keys_revert(KeyKind::parse(kind)?, reason.as_deref())?;
                answer(
                    &cli,
                    "keys revert",
                    serde_json::to_value(&record)?,
                    &format!("{kind}: the pair that was in use is back"),
                )?;
            }
            KeysVerb::Remove { kind } => {
                let record = helper.keys_remove(KeyKind::parse(kind)?)?;
                answer(
                    &cli,
                    "keys remove",
                    serde_json::to_value(&record)?,
                    &format!("{kind}: the pair the switch replaced is gone"),
                )?;
            }
        },
    }
    Ok(())
}

/// Render a generic operation result as JSON or plain text.
fn answer(cli: &Cli, what: &str, value: serde_json::Value, line: &str) -> Result<()> {
    if cli.json {
        println!("{}", serde_json::to_string_pretty(&ok_reply(what, value))?);
    } else {
        println!("{line}");
    }
    Ok(())
}

fn describe(record: &TxnRecord) -> String {
    format!(
        "{} {} ({}) {} -> {}{}",
        record.id,
        record.state_word(),
        record.mode,
        record
            .previous
            .toplevel
            .as_deref()
            .unwrap_or("nothing")
            .rsplit('/')
            .next()
            .unwrap_or("-"),
        record.desired.rsplit('/').next().unwrap_or("-"),
        match &record.reason {
            Some(why) => format!(": {why}"),
            None => String::new(),
        }
    )
}

fn show_lines(record: &TxnRecord) -> String {
    let mut out = String::new();
    out.push_str(&format!("txn      {}\n", record.id));
    out.push_str(&format!("state    {}\n", record.state_word()));
    out.push_str(&format!("mode     {}\n", record.mode));
    out.push_str(&format!(
        "run      {}\n",
        record.run_id.as_deref().unwrap_or("-")
    ));
    out.push_str(&format!(
        "previous {} (generation {})\n",
        record.previous.toplevel.as_deref().unwrap_or("-"),
        record
            .previous
            .generation
            .map(|g| g.to_string())
            .unwrap_or_else(|| "-".to_string())
    ));
    out.push_str(&format!("desired  {}\n", record.desired));
    out.push_str(&format!("started  {}\n", record.started_at));
    // Show when the current decision state began.
    out.push_str(&format!("changed  {}\n", record.changed_at));
    out.push_str(&format!(
        "deadline {}\n",
        record
            .deadline
            .map(|d| d.to_string())
            .unwrap_or_else(|| "none (nobody is waiting for a confirm)".to_string())
    ));
    if let Some(why) = &record.reason {
        out.push_str(&format!("reason   {why}\n"));
    }
    out
}

fn status_lines(status: &meister_deploy::observe::ActivateStatus) -> String {
    let mut out = String::new();
    let or = |v: &Option<String>| v.clone().unwrap_or_else(|| "-".to_string());
    out.push_str(&format!("current    {}\n", or(&status.current_system)));
    out.push_str(&format!("booted     {}\n", or(&status.booted_system)));
    out.push_str(&format!("next boot  {}\n", or(&status.next_boot_system)));
    out.push_str(&format!(
        "generation {}\n",
        status
            .generation
            .map(|g| g.to_string())
            .unwrap_or_else(|| "-".to_string())
    ));
    out.push_str(&format!("kernel     {}\n", or(&status.kernel_running)));
    match &status.kernel_booted {
        Some(boot) => out.push_str(&format!(
            "booted kernel {} (params {})\n",
            boot.kernel_store_path, boot.kernel_params_sha256
        )),
        None => out.push_str("booted kernel -\n"),
    }
    for txn in &status.open_txns {
        out.push_str(&format!(
            "open txn   {} {:?} -> {}\n",
            txn.id,
            txn.state,
            txn.target_system.as_deref().unwrap_or("-")
        ));
    }
    match &status.lock {
        Some(lock) => out.push_str(&format!(
            "lock       run {} (operator {}, pid {})\n",
            lock.run_id, lock.operator, lock.pid
        )),
        None => out.push_str("lock       nobody\n"),
    }
    out
}
