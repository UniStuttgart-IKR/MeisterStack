// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Subprocess execution with effect admission, deadlines and cancellation.
//!
//! Every command declares an effect class; real and fake runners enforce the
//! same policy before execution. Commands retain argv boundaries, support
//! explicit redaction and terminate their process group on timeout or cancellation.

use std::collections::VecDeque;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use nix::sys::signal::{SaFlags, SigAction, SigHandler, SigSet, Signal, killpg, sigaction};
use nix::unistd::Pid;

/// Command effect class used for policy admission. Nix evaluation has its own
/// class even when its expression only reads local files.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Effect {
    /// Touches nothing outside this process and no network: `git --version`,
    /// a local `sha256sum`. The only class an `--offline` run executes.
    Offline,
    /// Asks a question and changes nothing: `ssh … systemctl is-active`,
    /// `git rev-parse HEAD`, an HTTP GET.
    Read,
    /// `nix eval`. Reads only, but needs Nix and can take minutes.
    NixEval,
    /// `nix build`, `nix copy` into a local store: writes the local store.
    Build,
    /// Writes a file the operator owns: a manifest, a journal, `known_hosts`.
    LocalWrite,
    /// Makes or moves key material.
    Key,
    /// Changes a target host: `nix copy --to ssh-ng://`, `meister-activate`,
    /// a unit restart.
    TargetWrite,
}

impl Effect {
    pub fn as_str(self) -> &'static str {
        match self {
            Effect::Offline => "offline",
            Effect::Read => "read",
            Effect::NixEval => "nix-eval",
            Effect::Build => "build",
            Effect::LocalWrite => "local-write",
            Effect::Key => "key",
            Effect::TargetWrite => "target-write",
        }
    }
}

impl std::fmt::Display for Effect {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.pad(self.as_str())
    }
}

/// Which exit codes mean "it worked". A build's answer is yes or no; a
/// `systemctl is-active` answers a question, and "no" is an answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Expect {
    /// Anything but 0 is an error with the command line and what it said.
    ExitZero,
    /// Every exit code is an answer; the caller reads `status`.
    AnyExit,
    /// Accept these exit codes. SSH transport failures (255) remain distinguishable
    /// from expected remote statuses.
    Codes(Vec<i32>),
}

impl Expect {
    fn accepts(&self, status: i32) -> bool {
        match self {
            Expect::ExitZero => status == 0,
            Expect::AnyExit => true,
            Expect::Codes(codes) => codes.contains(&status),
        }
    }
}

/// Program and argv with mandatory effect classification and deadline.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cmd {
    pub program: String,
    pub args: Vec<String>,
    /// Working directory; repository-reading callers set it explicitly.
    pub cwd: Option<PathBuf>,
    pub env: Vec<(String, String)>,
    /// Start from an empty environment instead of inheriting this process's.
    pub env_clear: bool,
    pub stdin: Option<Vec<u8>>,
    /// How long it may take before it is killed. Not optional.
    pub deadline: Duration,
    pub expect: Expect,
    /// Exact substrings replaced with `***` in formatted commands and error output.
    pub redact: Vec<String>,
    pub effect: Effect,
}

impl Cmd {
    pub fn new(effect: Effect, program: impl Into<String>, deadline: Duration) -> Cmd {
        Cmd {
            program: program.into(),
            args: Vec::new(),
            cwd: None,
            env: Vec::new(),
            env_clear: false,
            stdin: None,
            deadline,
            expect: Expect::ExitZero,
            redact: Vec::new(),
            effect,
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

    pub fn cwd(mut self, dir: impl Into<PathBuf>) -> Cmd {
        self.cwd = Some(dir.into());
        self
    }

    pub fn env(mut self, k: impl Into<String>, v: impl Into<String>) -> Cmd {
        self.env.push((k.into(), v.into()));
        self
    }

    pub fn env_clear(mut self) -> Cmd {
        self.env_clear = true;
        self
    }

    pub fn stdin(mut self, bytes: impl Into<Vec<u8>>) -> Cmd {
        self.stdin = Some(bytes.into());
        self
    }

    pub fn expect(mut self, expect: Expect) -> Cmd {
        self.expect = expect;
        self
    }

    /// Redact this exact nonempty substring.
    pub fn redact(mut self, secret: impl Into<String>) -> Cmd {
        let secret = secret.into();
        // An empty value does not identify a secret.
        if !secret.is_empty() {
            self.redact.push(secret);
        }
        self
    }

    /// Render a redacted, shell-quoted command line.
    pub fn line(&self) -> String {
        let mut out = shell_quote(&self.redacted(&self.program));
        for a in &self.args {
            out.push(' ');
            out.push_str(&shell_quote(&self.redacted(a)));
        }
        out
    }

    /// Include working directory and environment assignments in the description.
    pub fn described(&self) -> String {
        let mut out = String::new();
        if let Some(dir) = &self.cwd {
            out.push_str(&format!("(in {}) ", dir.display()));
        }
        for (k, v) in &self.env {
            out.push_str(&format!("{k}={} ", shell_quote(&self.redacted(v))));
        }
        out.push_str(&self.line());
        out
    }

    /// Apply exact-substring redaction to command text or captured diagnostics.
    pub fn redacted(&self, text: &str) -> String {
        let mut out = text.to_string();
        for secret in &self.redact {
            out = out.replace(secret.as_str(), "***");
        }
        out
    }
}

/// Quote a POSIX shell argument using an allowlist for unquoted words.
/// [`crate::transport::Ssh::nix_sshopts`] uses the same predicate to reject
/// arguments that Nix cannot represent in its whitespace-split SSH options.
pub fn shell_quote(a: &str) -> String {
    if is_bare(a) {
        a.to_string()
    } else {
        format!("'{}'", a.replace('\'', r"'\''"))
    }
}

/// Whether an argument needs no quoting for the shell or Nix SSH options.
pub fn is_bare(a: &str) -> bool {
    let safe = |c: char| c.is_ascii_alphanumeric() || "_@%+=:,./-".contains(c);
    !a.is_empty() && a.chars().all(safe)
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Output {
    pub status: i32,
    pub stdout: String,
    pub stderr: String,
}

impl Output {
    /// A reply for a test: exit 0 and this on stdout.
    pub fn stdout(text: impl Into<String>) -> Output {
        Output {
            status: 0,
            stdout: text.into(),
            stderr: String::new(),
        }
    }

    /// A reply for a test: this exit code and this on stderr.
    pub fn failing(status: i32, stderr: impl Into<String>) -> Output {
        Output {
            status,
            stdout: String::new(),
            stderr: stderr.into(),
        }
    }

    pub fn ok(&self) -> bool {
        self.status == 0
    }

    pub fn trimmed(&self) -> &str {
        self.stdout.trim()
    }
}

/// Effect admission policy enforced before execution by both runners.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Policy {
    /// Say what would happen, and read whatever is needed to say it.
    pub dry_run: bool,
    /// Touch no network and no Nix: answer from what is already on disk.
    pub offline: bool,
}

impl Policy {
    pub fn real() -> Policy {
        Policy::default()
    }

    pub fn dry_run() -> Policy {
        Policy {
            dry_run: true,
            offline: false,
        }
    }

    pub fn offline() -> Policy {
        Policy {
            dry_run: false,
            offline: true,
        }
    }

    /// Check offline restrictions first, then dry-run restrictions.
    pub fn admits(&self, effect: Effect) -> Result<()> {
        if self.offline && effect != Effect::Offline {
            bail!("it is a {effect} command and --offline permits only offline ones");
        }
        if self.dry_run && !matches!(effect, Effect::Offline | Effect::Read) {
            bail!(
                "it is a {effect} command and --dry-run permits only offline and \
                 read-only ones"
            );
        }
        Ok(())
    }

    /// Keep refusal context in the outer error for both display formats.
    fn gate(&self, cmd: &Cmd) -> Result<()> {
        match self.admits(cmd.effect) {
            Ok(()) => Ok(()),
            Err(why) => bail!("{} was not run: {why}.", cmd.line()),
        }
    }
}

/// Cancellation token for commands running in separate process groups.
/// [`Cancel::on_sigint`] records Ctrl-C so the runner can terminate the group.
#[derive(Debug, Clone, Default)]
pub struct Cancel(Arc<AtomicBool>);

/// Set from a signal handler, so it is a plain atomic and nothing else: a
/// handler may not allocate, lock or call back into Rust that does.
static INTERRUPTED: AtomicBool = AtomicBool::new(false);
static HANDLER_INSTALLED: AtomicBool = AtomicBool::new(false);

extern "C" fn on_sigint(_signal: i32) {
    INTERRUPTED.store(true, Ordering::SeqCst);
}

impl Cancel {
    pub fn new() -> Cancel {
        Cancel::default()
    }

    pub fn cancel(&self) {
        self.0.store(true, Ordering::SeqCst);
    }

    pub fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::SeqCst) || INTERRUPTED.load(Ordering::SeqCst)
    }

    /// Ignore SIGHUP in the target helper so activation can survive an SSH disconnect.
    /// Workstation commands retain normal hangup behavior.
    pub fn ignore_sighup() -> Result<()> {
        let action = SigAction::new(SigHandler::SigIgn, SaFlags::empty(), SigSet::empty());
        // SAFETY: SIG_IGN installs no handler; there is no code to be
        // async-signal-safe about.
        unsafe { sigaction(Signal::SIGHUP, &action) }.context("ignoring SIGHUP failed")?;
        Ok(())
    }

    /// Install the process-wide SIGINT handler once, from the binary entry point.
    pub fn on_sigint() -> Result<()> {
        if HANDLER_INSTALLED.swap(true, Ordering::SeqCst) {
            return Ok(());
        }
        let action = SigAction::new(
            SigHandler::Handler(on_sigint),
            SaFlags::empty(),
            SigSet::empty(),
        );
        // SAFETY: the handler only stores into a static AtomicBool, which is
        // async-signal-safe; it allocates nothing and takes no lock.
        unsafe { sigaction(Signal::SIGINT, &action) }
            .context("installing the SIGINT handler failed")?;
        Ok(())
    }
}

pub trait Runner {
    /// Run a command and validate its exit status against [`Expect`].
    fn run(&self, cmd: &Cmd) -> Result<Output>;

    /// Admission policy, available to callers that skip unsupported phases.
    fn policy(&self) -> Policy;
}

/// Subprocess runner with deadlines and process-group cancellation.
pub struct Real {
    pub policy: Policy,
    /// Print command diagnostics to stderr, preserving stdout for results.
    pub verbose: bool,
    pub cancel: Cancel,
    /// Whether SIGINT cancels spawned commands. Cleanup runners disable cancellation
    /// so an interrupted operation can remove its temporary resources; deadlines remain.
    pub stoppable: bool,
}

impl Real {
    pub fn new(policy: Policy) -> Real {
        Real {
            policy,
            verbose: false,
            cancel: Cancel::new(),
            stoppable: true,
        }
    }

    pub fn verbose(mut self, on: bool) -> Real {
        self.verbose = on;
        self
    }

    /// A runner whose commands the operator's interrupt does not reach. See
    /// [`Real::stoppable`]; nothing but a cleanup may use it.
    pub fn unstoppable(mut self) -> Real {
        self.stoppable = false;
        self
    }
}

/// Poll child completion and cancellation every five milliseconds.
const POLL: Duration = Duration::from_millis(5);

/// Allow two seconds for graceful process-group termination.
const GRACE: Duration = Duration::from_secs(2);

impl Runner for Real {
    fn run(&self, cmd: &Cmd) -> Result<Output> {
        self.policy.gate(cmd)?;
        if self.verbose {
            eprintln!("      {}", cmd.described());
        }

        let mut builder = Command::new(&cmd.program);
        builder
            .args(&cmd.args)
            .stdin(if cmd.stdin.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if cmd.env_clear {
            builder.env_clear();
        }
        for (k, v) in &cmd.env {
            builder.env(k, v);
        }
        if let Some(dir) = &cmd.cwd {
            builder.current_dir(dir);
        }
        // Isolate the process group so timeout cleanup reaches descendant processes.
        {
            use std::os::unix::process::CommandExt;
            builder.process_group(0);
        }

        let mut child = builder.spawn().with_context(|| missing(&cmd.program))?;
        let pgid = Pid::from_raw(child.id() as i32);

        // Read both outputs and write stdin concurrently to avoid pipe deadlocks.
        let stdin_thread = cmd.stdin.clone().map(|bytes| {
            let mut pipe = child.stdin.take().expect("stdin was piped");
            std::thread::spawn(move || {
                let _ = pipe.write_all(&bytes);
                // Dropping it closes the pipe, which is what tells a `--csr -`
                // or a `nix eval --expr` that the input has ended.
            })
        });
        let mut out_pipe = child.stdout.take().expect("stdout was piped");
        let mut err_pipe = child.stderr.take().expect("stderr was piped");
        let out_thread = std::thread::spawn(move || {
            let mut buf = Vec::new();
            let _ = out_pipe.read_to_end(&mut buf);
            buf
        });
        let err_thread = std::thread::spawn(move || {
            let mut buf = Vec::new();
            let _ = err_pipe.read_to_end(&mut buf);
            buf
        });

        let started = Instant::now();
        let mut signalled: Option<Instant> = None;
        let mut killed = false;
        let mut timed_out = false;
        let mut cancelled = false;
        let status = loop {
            if let Some(status) = child.try_wait().context("waiting for the child failed")? {
                break status;
            }
            if signalled.is_none() {
                if self.stoppable && self.cancel.is_cancelled() {
                    cancelled = true;
                } else if started.elapsed() >= cmd.deadline {
                    timed_out = true;
                }
                if cancelled || timed_out {
                    let _ = killpg(pgid, Signal::SIGTERM);
                    signalled = Some(Instant::now());
                }
            } else if !killed && signalled.is_some_and(|t| t.elapsed() >= GRACE) {
                let _ = killpg(pgid, Signal::SIGKILL);
                killed = true;
            }
            std::thread::sleep(POLL);
        };

        // Terminate remaining group members before joining pipe readers: background
        // children may retain stdout/stderr after the direct child exits.
        sweep(pgid);

        if let Some(t) = stdin_thread {
            let _ = t.join();
        }
        let stdout = String::from_utf8_lossy(&out_thread.join().unwrap_or_default()).into_owned();
        let stderr = String::from_utf8_lossy(&err_thread.join().unwrap_or_default()).into_owned();

        if timed_out {
            bail!(
                "{} did not finish within {:?} and its process group was killed. \
                 The last thing it said was: {}",
                cmd.line(),
                cmd.deadline,
                last_lines(&cmd.redacted(&stderr))
            );
        }
        if cancelled {
            bail!(
                "{} was interrupted and its process group was killed.",
                cmd.line()
            );
        }

        let out = Output {
            // Signal termination has no exit code; use -1 and retain the signal diagnostic.
            status: status.code().unwrap_or(-1),
            stdout,
            stderr,
        };
        finish(cmd, out)
    }

    fn policy(&self) -> Policy {
        self.policy
    }
}

/// After reaping the child, terminate remaining group members with SIGTERM,
/// then SIGKILL after [`GRACE`]. An absent group needs no cleanup.
fn sweep(pgid: Pid) {
    let _ = killpg(pgid, Signal::SIGTERM);
    let since = Instant::now();
    while since.elapsed() < GRACE && group_is_alive(pgid) {
        std::thread::sleep(POLL);
    }
    let _ = killpg(pgid, Signal::SIGKILL);
}

/// Signal 0: does this process group still have members? The one question
/// `kill` answers without doing anything.
fn group_is_alive(pgid: Pid) -> bool {
    killpg(pgid, None).is_ok()
}

/// Apply the same exit-status contract to real and fake results.
fn finish(cmd: &Cmd, out: Output) -> Result<Output> {
    if cmd.expect.accepts(out.status) {
        return Ok(out);
    }
    let said = if out.stderr.trim().is_empty() {
        out.stdout.trim()
    } else {
        out.stderr.trim()
    };
    bail!(
        "{} exited {}. It said: {}",
        cmd.line(),
        out.status,
        last_lines(&cmd.redacted(said))
    );
}

/// Last five output lines, shared by command errors and check reports.
pub fn last_lines(text: &str) -> String {
    let text = text.trim();
    if text.is_empty() {
        return "(nothing)".to_string();
    }
    let lines: Vec<&str> = text.lines().collect();
    let from = lines.len().saturating_sub(5);
    lines[from..].join("\n  ")
}

fn missing(program: &str) -> String {
    match program {
        "nix" => "nix is not on PATH, and it is what evaluates and builds every system".to_string(),
        "git" => "git is not on PATH, and it is what a source fingerprint is read from".to_string(),
        "ssh" => "ssh is not on PATH, and it is how every target host is reached".to_string(),
        other => format!("{other} could not be started"),
    }
}

/// What a [`StrictFake`] is willing to answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Matcher {
    /// The program and the complete argv, argument for argument.
    Exact { program: String, args: Vec<String> },
    /// The program and the first n arguments. For command lines that carry a
    /// temporary path the test cannot know in advance.
    Prefix { program: String, args: Vec<String> },
}

impl Matcher {
    pub fn exact<I, S>(program: &str, args: I) -> Matcher
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Matcher::Exact {
            program: program.to_string(),
            args: args.into_iter().map(Into::into).collect(),
        }
    }

    pub fn prefix<I, S>(program: &str, args: I) -> Matcher
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Matcher::Prefix {
            program: program.to_string(),
            args: args.into_iter().map(Into::into).collect(),
        }
    }

    fn matches(&self, cmd: &Cmd) -> bool {
        match self {
            Matcher::Exact { program, args } => cmd.program == *program && cmd.args == *args,
            Matcher::Prefix { program, args } => {
                cmd.program == *program
                    && cmd.args.len() >= args.len()
                    && cmd.args[..args.len()] == args[..]
            }
        }
    }

    fn describe(&self) -> String {
        match self {
            Matcher::Exact { program, args } => format!("{program} {}", args.join(" ")),
            Matcher::Prefix { program, args } => format!("{program} {} …", args.join(" ")),
        }
    }
}

/// Strict, ordered subprocess fake. Unexpected and unused commands fail verification;
/// `Drop` checks expectations unless the caller already verified or is panicking.
/// Mutexes provide `Sync`, but concurrent callers must still obey the expected order.
pub struct StrictFake {
    policy: Policy,
    expects: Mutex<VecDeque<(Matcher, Output)>>,
    calls: Mutex<Vec<String>>,
    unexpected: Mutex<Vec<String>>,
    checked: AtomicBool,
}

/// A poisoned fake-runner mutex indicates a test panic.
fn held<T>(guard: std::sync::LockResult<T>) -> T {
    guard.expect("a StrictFake is only locked in its own methods")
}

impl Default for StrictFake {
    fn default() -> StrictFake {
        StrictFake::new()
    }
}

impl StrictFake {
    pub fn new() -> StrictFake {
        StrictFake {
            policy: Policy::real(),
            expects: Mutex::new(VecDeque::new()),
            calls: Mutex::new(Vec::new()),
            unexpected: Mutex::new(Vec::new()),
            checked: AtomicBool::new(false),
        }
    }

    pub fn with_policy(mut self, policy: Policy) -> StrictFake {
        self.policy = policy;
        self
    }

    /// The next command must match this, and will be answered with that.
    pub fn expect(self, matcher: Matcher, reply: Output) -> StrictFake {
        held(self.expects.lock()).push_back((matcher, reply));
        self
    }

    /// Every command line that reached this runner, in order, redacted the
    /// same way a log line would be.
    pub fn calls(&self) -> Vec<String> {
        held(self.calls.lock()).clone()
    }

    /// Check all expectations; calling this suppresses the equivalent Drop check.
    pub fn verify(&self) -> Result<()> {
        self.checked.store(true, Ordering::SeqCst);
        let unused = held(self.expects.lock());
        let unexpected = held(self.unexpected.lock());
        if unused.is_empty() && unexpected.is_empty() {
            return Ok(());
        }
        let mut msg = String::new();
        if !unexpected.is_empty() {
            msg.push_str(&format!(
                "{} command(s) nobody expected: {}",
                unexpected.len(),
                unexpected.join(", ")
            ));
        }
        if !unused.is_empty() {
            if !msg.is_empty() {
                msg.push_str("; ");
            }
            msg.push_str(&format!(
                "{} expectation(s) nobody used: {}",
                unused.len(),
                unused
                    .iter()
                    .map(|(m, _)| m.describe())
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
        bail!("{msg}.");
    }
}

impl Drop for StrictFake {
    fn drop(&mut self) {
        // Avoid a second panic during unwinding.
        if self.checked.load(Ordering::SeqCst) || std::thread::panicking() {
            return;
        }
        if let Err(e) = self.verify() {
            panic!("StrictFake: {e}");
        }
    }
}

impl Runner for StrictFake {
    fn run(&self, cmd: &Cmd) -> Result<Output> {
        self.policy.gate(cmd)?;
        let line = cmd.line();
        held(self.calls.lock()).push(line.clone());
        let mut expects = held(self.expects.lock());
        match expects.front() {
            Some((matcher, _)) if matcher.matches(cmd) => {
                let (_, reply) = expects.pop_front().expect("just matched it");
                drop(expects);
                finish(cmd, reply)
            }
            Some((matcher, _)) => {
                let wanted = matcher.describe();
                drop(expects);
                held(self.unexpected.lock()).push(line.clone());
                bail!("this runner expected `{wanted}` and got `{line}`.");
            }
            None => {
                drop(expects);
                held(self.unexpected.lock()).push(line.clone());
                bail!("this runner expected nothing more and got `{line}`.");
            }
        }
    }

    fn policy(&self) -> Policy {
        self.policy
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sh(script: &str, deadline: Duration) -> Cmd {
        Cmd::new(Effect::Offline, "sh", deadline)
            .arg("-c")
            .arg(script)
    }

    #[test]
    fn an_empty_argument_is_still_an_argument() {
        let cmd = Cmd::new(Effect::Offline, "printf", Duration::from_secs(5))
            .arg("[%s]")
            .arg("");
        assert_eq!(cmd.args.len(), 2);
        assert_eq!(cmd.line(), "printf '[%s]' ''");
        let out = Real::new(Policy::real()).run(&cmd).unwrap();
        assert_eq!(out.stdout, "[]", "the empty argument reached the program");
    }

    #[test]
    fn a_path_with_a_space_is_one_argument() {
        let cmd = Cmd::new(Effect::Offline, "printf", Duration::from_secs(5))
            .arg("%s|")
            .arg("/var/lib/my keys/identity.key");
        let out = Real::new(Policy::real()).run(&cmd).unwrap();
        assert_eq!(out.stdout, "/var/lib/my keys/identity.key|");
        assert_eq!(
            cmd.line(),
            "printf '%s|' '/var/lib/my keys/identity.key'",
            "and it is quoted back as one"
        );
    }

    #[test]
    fn a_deadline_kills_the_command_and_says_so() {
        // A marker nothing else in the tree sleeps for, so that pgrep below
        // is about this test and not about the machine.
        let cmd = sh("sleep 987654", Duration::from_millis(200));
        let began = Instant::now();
        let err = Real::new(Policy::real()).run(&cmd).unwrap_err().to_string();
        assert!(
            began.elapsed() < Duration::from_secs(3),
            "{:?}",
            began.elapsed()
        );
        assert!(err.contains("did not finish within"), "{err}");
        assert!(err.contains("sleep 987654"), "{err}");
        assert!(!pgrep("987654"), "the sleep outlived the deadline");
    }

    #[test]
    fn the_whole_process_group_dies_not_only_the_child() {
        // A background child must be killed with its process group.
        let cmd = sh("sleep 987655 & sleep 987655", Duration::from_millis(200));
        let err = Real::new(Policy::real()).run(&cmd).unwrap_err().to_string();
        assert!(err.contains("process group was killed"), "{err}");
        std::thread::sleep(Duration::from_millis(100));
        assert!(!pgrep("987655"), "a grandchild outlived its group");
    }

    #[test]
    fn a_grandchild_holding_the_pipe_does_not_outlast_the_command() {
        // A background child retaining stdout must not keep the reader blocked.
        let cmd = sh("sleep 987657 & echo hi", Duration::from_secs(5));
        let began = Instant::now();
        let out = Real::new(Policy::real()).run(&cmd).unwrap();
        assert!(
            began.elapsed() < Duration::from_secs(3),
            "it waited {:?}",
            began.elapsed()
        );
        assert_eq!(out.trimmed(), "hi", "and the real output still arrived");
        assert_eq!(out.status, 0);
        std::thread::sleep(Duration::from_millis(100));
        assert!(!pgrep("987657"), "the background sleep was left running");
    }

    /// Check for running processes matching the marker. Zombies hold no pipe
    /// descriptors and do not count as surviving children.
    fn pgrep(needle: &str) -> bool {
        let out = Command::new("pgrep")
            .arg("-f")
            .arg(needle)
            .output()
            .expect("pgrep is in coreutils' neighbourhood and in the dev shell");
        if !out.status.success() {
            return false;
        }
        String::from_utf8_lossy(&out.stdout)
            .lines()
            .filter_map(|pid| pid.trim().parse::<i32>().ok())
            .any(|pid| !is_zombie(pid))
    }

    fn is_zombie(pid: i32) -> bool {
        match std::fs::read_to_string(format!("/proc/{pid}/stat")) {
            // The process name may contain parentheses; state follows the final closing one.
            Ok(text) => {
                text.rfind(')')
                    .and_then(|i| text[i + 1..].trim_start().chars().next())
                    == Some('Z')
            }
            // Gone between pgrep and this read. Not running is the answer.
            Err(_) => true,
        }
    }

    #[test]
    fn a_cancelled_command_dies_too() {
        let runner = Real::new(Policy::real());
        runner.cancel.cancel();
        let err = runner
            .run(&sh("sleep 987656", Duration::from_secs(60)))
            .unwrap_err()
            .to_string();
        assert!(err.contains("was interrupted"), "{err}");
        assert!(!pgrep("987656"));
    }

    #[test]
    fn stdout_and_stderr_are_separate() {
        let out = Real::new(Policy::real())
            .run(&sh("echo answer; echo noise >&2", Duration::from_secs(5)))
            .unwrap();
        assert_eq!(out.trimmed(), "answer");
        assert_eq!(out.stderr.trim(), "noise");
    }

    #[test]
    fn stdin_reaches_the_child() {
        let cmd =
            Cmd::new(Effect::Offline, "cat", Duration::from_secs(5)).stdin(b"a csr\n".to_vec());
        let out = Real::new(Policy::real()).run(&cmd).unwrap();
        assert_eq!(out.stdout, "a csr\n");
    }

    #[test]
    fn cwd_and_a_cleared_environment_are_honoured() {
        let dir = tempfile::tempdir().unwrap();
        let cmd = sh(
            "pwd; echo \"[$HOME]\"; echo \"[$MEISTER_MARK]\"",
            Duration::from_secs(5),
        )
        .cwd(dir.path())
        .env_clear()
        .env("MEISTER_MARK", "set");
        let out = Real::new(Policy::real()).run(&cmd).unwrap();
        let lines: Vec<&str> = out.stdout.lines().collect();
        // macOS-style /private prefixes do not happen here, but a tmpdir can
        // still be a symlink, so compare what the shell resolved.
        assert!(
            lines[0].ends_with(dir.path().file_name().unwrap().to_str().unwrap()),
            "{out:?}"
        );
        assert_eq!(lines[1], "[]", "the environment was cleared");
        assert_eq!(lines[2], "[set]", "except for what was asked for");
    }

    #[test]
    fn an_unexpected_exit_code_is_an_error_with_what_it_said() {
        let err = Real::new(Policy::real())
            .run(&sh(
                "echo 'attribute image-nope missing' >&2; exit 1",
                Duration::from_secs(5),
            ))
            .unwrap_err()
            .to_string();
        assert!(err.contains("exited 1"), "{err}");
        assert!(err.contains("image-nope"), "{err}");
    }

    #[test]
    fn a_question_may_answer_no() {
        let out = Real::new(Policy::real())
            .run(&sh("exit 3", Duration::from_secs(5)).expect(Expect::AnyExit))
            .unwrap();
        assert_eq!(out.status, 3);

        let out = Real::new(Policy::real())
            .run(&sh("exit 1", Duration::from_secs(5)).expect(Expect::Codes(vec![0, 1])))
            .unwrap();
        assert_eq!(out.status, 1);

        let err = Real::new(Policy::real())
            .run(&sh("exit 255", Duration::from_secs(5)).expect(Expect::Codes(vec![0, 1])))
            .unwrap_err()
            .to_string();
        assert!(err.contains("exited 255"), "{err}");
    }

    #[test]
    fn redaction_works_in_the_line_and_in_the_error() {
        let cmd = Cmd::new(Effect::Offline, "sh", Duration::from_secs(5))
            .arg("-c")
            .arg("echo 'rejected token hunter2' >&2; exit 1")
            .env("ONE_AUTH", "meister:hunter2")
            .redact("hunter2");
        assert!(!cmd.line().contains("hunter2"), "{}", cmd.line());
        assert!(cmd.line().contains("***"), "{}", cmd.line());
        assert!(!cmd.described().contains("hunter2"), "{}", cmd.described());
        let err = Real::new(Policy::real()).run(&cmd).unwrap_err().to_string();
        assert!(!err.contains("hunter2"), "{err}");
        assert!(err.contains("***"), "{err}");
    }

    #[test]
    fn dry_run_reads_and_refuses_everything_else() {
        let runner = Real::new(Policy::dry_run());
        let out = runner
            .run(&Cmd::new(Effect::Read, "echo", Duration::from_secs(5)).arg("hello"))
            .unwrap();
        assert_eq!(out.trimmed(), "hello", "a read still runs in a dry run");

        let err = runner
            .run(&Cmd::new(Effect::Build, "nix", Duration::from_secs(5)).arg("build"))
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("--dry-run permits only offline and read-only"),
            "{err}"
        );
        assert!(err.contains("was not run"), "{err}");
    }

    #[test]
    fn offline_refuses_even_a_read() {
        let runner = Real::new(Policy::offline());
        let err = runner
            .run(&Cmd::new(Effect::NixEval, "nix", Duration::from_secs(5)).arg("eval"))
            .unwrap_err()
            .to_string();
        assert!(err.contains("--offline permits only offline ones"), "{err}");
        assert!(err.contains("nix-eval"), "{err}");
        assert!(
            runner
                .run(&Cmd::new(Effect::Read, "true", Duration::from_secs(5)))
                .is_err(),
            "a read leaves this process too"
        );
        // And nothing was fabricated: there is no Ok(status 0) path at all.
        assert!(
            runner
                .run(&Cmd::new(Effect::Offline, "true", Duration::from_secs(5)))
                .is_ok()
        );
    }

    #[test]
    fn a_strict_fake_answers_only_what_was_expected() {
        let fake = StrictFake::new()
            .expect(
                Matcher::exact("git", ["rev-parse", "HEAD"]),
                Output::stdout("f83cd70\n"),
            )
            .expect(
                Matcher::prefix("nix", ["eval", "--json"]),
                Output::stdout("{}"),
            );
        let head = fake
            .run(&Cmd::new(Effect::Read, "git", Duration::from_secs(5)).args(["rev-parse", "HEAD"]))
            .unwrap();
        assert_eq!(head.trimmed(), "f83cd70");
        let eval = fake
            .run(
                &Cmd::new(Effect::NixEval, "nix", Duration::from_secs(5)).args([
                    "eval",
                    "--json",
                    "/tmp/whatever#meisterDeployment",
                ]),
            )
            .unwrap();
        assert_eq!(eval.trimmed(), "{}");
        fake.verify().unwrap();
        assert_eq!(fake.calls().len(), 2);
    }

    #[test]
    fn an_unexpected_command_is_an_error_and_is_remembered() {
        let fake = StrictFake::new().expect(
            Matcher::exact("git", ["rev-parse", "HEAD"]),
            Output::stdout("f83cd70\n"),
        );
        let err = fake
            .run(&Cmd::new(Effect::TargetWrite, "ssh", Duration::from_secs(5)).arg("root@box"))
            .unwrap_err()
            .to_string();
        assert!(err.contains("expected `git rev-parse HEAD`"), "{err}");
        assert!(err.contains("got `ssh root@box`"), "{err}");
        let again = fake.verify().unwrap_err().to_string();
        assert!(again.contains("nobody expected"), "{again}");
        assert!(again.contains("nobody used"), "{again}");
    }

    #[test]
    fn an_unused_expectation_is_an_error() {
        let fake = StrictFake::new().expect(
            Matcher::prefix("nix", ["build"]),
            Output::stdout("/nix/store/aaa"),
        );
        let err = fake.verify().unwrap_err().to_string();
        assert!(err.contains("1 expectation(s) nobody used"), "{err}");
        assert!(err.contains("nix build …"), "{err}");
    }

    #[test]
    fn an_unused_expectation_panics_when_nobody_asked() {
        // The Drop guard is what catches the test that forgot to verify.
        let caught = std::panic::catch_unwind(|| {
            let _fake =
                StrictFake::new().expect(Matcher::prefix("nix", ["build"]), Output::stdout(""));
        });
        let msg = caught.unwrap_err();
        let msg = msg
            .downcast_ref::<String>()
            .expect("panicked with a message");
        assert!(msg.contains("nobody used"), "{msg}");
    }

    #[test]
    fn the_fake_refuses_what_the_policy_refuses() {
        let fake = StrictFake::new()
            .with_policy(Policy::offline())
            .expect(Matcher::prefix("nix", ["eval"]), Output::stdout("{}"));
        let err = fake
            .run(&Cmd::new(Effect::NixEval, "nix", Duration::from_secs(5)).arg("eval"))
            .unwrap_err()
            .to_string();
        assert!(err.contains("--offline"), "{err}");
        // The refused command never counted as a call, and the expectation is
        // still open — which verify() says, so Drop stays quiet.
        assert!(fake.calls().is_empty());
        assert!(fake.verify().is_err());
    }
}
