// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! The one door to the outside.
//!
//! Everything this tool does to a machine it does by running a program that
//! was already the right answer: `nix` builds, `ssh` and `rsync` carry,
//! `nixos-rebuild` switches, `tools/meister-ca` signs. None of that is
//! reimplemented here — no ssh library, no nix evaluator — because the shell
//! tools are what an operator can run by hand when this binary is not what
//! they want, and because a deployment tool that reimplements ssh is a
//! deployment tool with its own bugs in somebody's authentication.
//!
//! Which leaves exactly one thing worth abstracting: WHICH command line, in
//! WHICH order. That is what the tests check, against [`Fake`], and it is why
//! every command goes through here rather than through `std::process` at the
//! call site.

use std::cell::RefCell;
use std::collections::VecDeque;
use std::process::Command;

use anyhow::{Context, Result, bail};

/// A command line, kept as a program and its arguments rather than as a
/// string: a certificate path with a space in it is an argument, not two.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cmd {
    pub program: String,
    pub args: Vec<String>,
    /// What this command changes, in one phrase, or `None` if it only reads.
    /// A `--dry-run` prints the changing ones and runs the reading ones —
    /// which is what makes a dry run worth anything: it looks at the fleet
    /// and then says what it would do to it.
    pub changes: Option<String>,
}

impl Cmd {
    pub fn read(program: &str) -> Cmd {
        Cmd {
            program: program.to_string(),
            args: Vec::new(),
            changes: None,
        }
    }

    pub fn change(program: &str, what: &str) -> Cmd {
        Cmd {
            program: program.to_string(),
            args: Vec::new(),
            changes: Some(what.to_string()),
        }
    }

    pub fn arg(mut self, a: impl Into<String>) -> Cmd {
        self.args.push(a.into());
        self
    }

    pub fn args<I, S>(mut self, it: I) -> Cmd
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.args.extend(it.into_iter().map(Into::into));
        self
    }

    /// The command as a human would type it. Quoted only where it has to be,
    /// so that a line printed here can be pasted into a shell — which is the
    /// whole point of printing it.
    pub fn line(&self) -> String {
        let mut out = String::from(&self.program);
        for a in &self.args {
            out.push(' ');
            if a.is_empty() || a.contains([' ', '\t', '"', '\'', '$', '&', ';', '|', '<', '>']) {
                out.push('\'');
                out.push_str(&a.replace('\'', r"'\''"));
                out.push('\'');
            } else {
                out.push_str(a);
            }
        }
        out
    }
}

#[derive(Debug, Clone, Default)]
pub struct Output {
    pub status: i32,
    pub stdout: String,
    pub stderr: String,
}

impl Output {
    pub fn ok(&self) -> bool {
        self.status == 0
    }

    pub fn trimmed(&self) -> &str {
        self.stdout.trim()
    }
}

pub trait Runner {
    /// Run it. A non-zero exit is NOT an error here — plenty of the things
    /// this tool asks are questions whose answer is "no" (is that unit
    /// running? is that file there?) — so the caller decides.
    fn run(&self, cmd: &Cmd) -> Result<Output>;

    /// Whether changes are only printed. Reading commands run either way.
    fn dry_run(&self) -> bool;
}

/// The real one: prints what it is about to do, then does it.
pub struct Real {
    pub dry_run: bool,
    /// Print reading commands too. Off by default, because `plan` against
    /// twelve hosts is twelve ssh lines nobody asked to see.
    pub verbose: bool,
}

impl Runner for Real {
    fn run(&self, cmd: &Cmd) -> Result<Output> {
        match &cmd.changes {
            Some(what) => {
                println!("  {} {}", if self.dry_run { "would" } else { "-->" }, what);
                println!("      {}", cmd.line());
                if self.dry_run {
                    return Ok(Output {
                        status: 0,
                        stdout: String::new(),
                        stderr: String::new(),
                    });
                }
            }
            None if self.verbose => println!("      {}", cmd.line()),
            None => {}
        }

        let out = Command::new(&cmd.program)
            .args(&cmd.args)
            .output()
            .with_context(|| match cmd.program.as_str() {
                // The three that are worth a sentence rather than "No such
                // file or directory": they are the tools this whole design
                // rests on, and their absence is a setup problem.
                "nix" => "nix is not on PATH, and it is what builds every image and every system"
                    .to_string(),
                "rsync" => {
                    "rsync is not on PATH; it is how binaries reach a context node".to_string()
                }
                "nixos-rebuild" => {
                    "nixos-rebuild is not on PATH; it is how a metal node is taken forward"
                        .to_string()
                }
                other => format!("running {other}"),
            })?;
        Ok(Output {
            status: out.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        })
    }

    fn dry_run(&self) -> bool {
        self.dry_run
    }
}

/// The one the tests use. It records every command line and answers from a
/// queue of canned replies, so a test reads the ORDER and the ARGUMENTS of a
/// rollout without a lab, a network or a key.
#[derive(Default)]
pub struct Fake {
    pub calls: RefCell<Vec<String>>,
    replies: RefCell<VecDeque<(String, Output)>>,
    default: Output,
    pub dry_run: bool,
}

impl Fake {
    pub fn new() -> Fake {
        Fake::default()
    }

    /// A fake that only prints changes, like `--dry-run`.
    pub fn dry() -> Fake {
        Fake {
            dry_run: true,
            ..Fake::default()
        }
    }

    /// Answer the next command whose line contains `needle` with this stdout.
    /// Matched in order, so two answers for one host stay in their order.
    pub fn reply(self, needle: &str, stdout: &str) -> Fake {
        self.replies.borrow_mut().push_back((
            needle.to_string(),
            Output {
                status: 0,
                stdout: stdout.to_string(),
                stderr: String::new(),
            },
        ));
        self
    }

    pub fn failing(self, needle: &str, stderr: &str) -> Fake {
        self.replies.borrow_mut().push_back((
            needle.to_string(),
            Output {
                status: 1,
                stdout: String::new(),
                stderr: stderr.to_string(),
            },
        ));
        self
    }

    pub fn lines(&self) -> Vec<String> {
        self.calls.borrow().clone()
    }

    /// Only the commands that change something — a rollout's actual shape,
    /// without the questions it asked along the way.
    pub fn changes(&self) -> Vec<String> {
        self.calls
            .borrow()
            .iter()
            .filter(|l| l.starts_with("! "))
            .map(|l| l[2..].to_string())
            .collect()
    }
}

impl Runner for Fake {
    fn run(&self, cmd: &Cmd) -> Result<Output> {
        let line = cmd.line();
        self.calls.borrow_mut().push(match cmd.changes {
            Some(_) => format!("! {line}"),
            None => line.clone(),
        });
        if cmd.changes.is_some() && self.dry_run {
            return Ok(Output::default());
        }
        let mut replies = self.replies.borrow_mut();
        if let Some(i) = replies
            .iter()
            .position(|(needle, _)| line.contains(needle.as_str()))
        {
            return Ok(replies.remove(i).expect("just found it").1);
        }
        Ok(self.default.clone())
    }

    fn dry_run(&self) -> bool {
        self.dry_run
    }
}

/// Run it, and a non-zero exit IS an error — for the commands where "no" is
/// not an answer, like a build or a switch. The message carries the command
/// and whatever the tool said, because "exit status 1" is not a sentence.
pub fn must(runner: &dyn Runner, cmd: &Cmd) -> Result<Output> {
    let out = runner.run(cmd)?;
    if !out.ok() {
        let detail = if out.stderr.trim().is_empty() {
            out.stdout.trim().to_string()
        } else {
            out.stderr.trim().to_string()
        };
        bail!("{} exited {}\n  {}", cmd.line(), out.status, detail);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_command_line_can_be_pasted_into_a_shell() {
        let cmd = Cmd::read("ssh")
            .arg("root@10.0.0.1")
            .arg("echo hello; systemctl is-active x");
        assert_eq!(
            cmd.line(),
            "ssh root@10.0.0.1 'echo hello; systemctl is-active x'"
        );
    }

    #[test]
    fn a_dry_run_still_reads_but_never_changes() {
        let fake = Fake {
            dry_run: true,
            ..Fake::new()
        }
        .reply("readlink", "/nix/store/aaa-system\n");
        let read = fake
            .run(
                &Cmd::read("ssh")
                    .arg("root@h")
                    .arg("readlink /run/current-system"),
            )
            .unwrap();
        assert_eq!(read.trimmed(), "/nix/store/aaa-system");

        let change = fake
            .run(&Cmd::change("nixos-rebuild", "switch box").arg("switch"))
            .unwrap();
        assert_eq!(change.stdout, "", "a change is not executed in a dry run");
        assert_eq!(fake.changes(), vec!["nixos-rebuild switch"]);
    }

    #[test]
    fn a_command_that_must_work_fails_with_what_it_said() {
        let fake = Fake::new().failing("nix build", "error: attribute 'image-nope' missing");
        let err = must(&fake, &Cmd::read("nix").arg("build").arg(".#image-nope"))
            .unwrap_err()
            .to_string();
        assert!(err.contains("image-nope"), "{err}");
        assert!(err.contains("attribute"), "{err}");
    }
}
