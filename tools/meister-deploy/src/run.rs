// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! The one door to the outside, and the door knows what it lets through.
//!
//! Everything this tool does to a machine it does by running a program that
//! was already the right answer: `nix` builds, `ssh` carries, `git` reads the
//! operator's repository, `tools/meister-ca` signs. None of that is
//! reimplemented here — no ssh library, no nix evaluator — because the shell
//! tools are what an operator can run by hand when this binary is not what
//! they want, and because a deployment tool that reimplements ssh is a
//! deployment tool with its own bugs in somebody's authentication.
//!
//! What is new against the pre-v1 door is that every [`Cmd`] carries its
//! [`Effect`] class, and [`Policy`] decides BEFORE the spawn whether a command
//! of that class may run at all. `--dry-run` and `--offline` are therefore
//! properties of this module rather than promises made at each call site, and
//! a forbidden command is an error with a sentence — never a fabricated
//! `status: 0`, which is what the old runner returned and what made a dry run
//! able to report a success nobody had.
//!
//! The second new thing is that a command cannot be built without a deadline.
//! `ssh` to a box that is rebooting, `nix build` against a substituter that
//! accepted the connection and then stopped talking: both hang forever, and a
//! rollout that hangs holds a lock on a fleet.

use std::cell::{Cell, RefCell};
use std::collections::VecDeque;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use nix::sys::signal::{SaFlags, SigAction, SigHandler, SigSet, Signal, killpg, sigaction};
use nix::unistd::Pid;

/// What a command does to the world. The class is the whole point: it is what
/// `--dry-run` and `--offline` are decided on, and it is what a journal entry
/// and an approval class are derived from later.
///
/// The order is from harmless to irreversible, and nothing is allowed to be
/// cheaper than it is: `nix eval` is [`Effect::NixEval`] and not
/// [`Effect::Read`] even though it only reads the operator's repository,
/// because it needs a Nix on the machine and an evaluation that can take
/// minutes — an `--offline` run has to say so rather than fail obscurely.
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
        f.write_str(self.as_str())
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
    /// These codes are answers, everything else is an error. `ssh` uses 255
    /// for its own failures and passes the remote code through otherwise, so
    /// "the remote said 1" and "ssh could not connect" are distinguishable.
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

/// A command line, kept as a program and its arguments rather than as a
/// string: a certificate path with a space in it is an argument, not two.
///
/// There is deliberately no constructor without a `deadline` and without an
/// [`Effect`]: both are decisions, and a default would make them somebody's
/// oversight instead.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cmd {
    pub program: String,
    pub args: Vec<String>,
    /// Where it runs. `None` means the process's own directory — which for
    /// anything reading an operator repository is the wrong answer, so the
    /// repository-reading callers all set it.
    pub cwd: Option<PathBuf>,
    pub env: Vec<(String, String)>,
    /// Start from an empty environment instead of inheriting this process's.
    pub env_clear: bool,
    pub stdin: Option<Vec<u8>>,
    /// How long it may take before it is killed. Not optional.
    pub deadline: Duration,
    pub expect: Expect,
    /// Substrings that appear as `***` wherever this command is printed — in
    /// a log line, in an error, in a journal entry. A token handed to a
    /// provider, a one-time password: the value has to travel in the argv,
    /// and it must not travel into a report somebody attaches to a ticket.
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

    /// Hide this exact substring wherever the command is printed.
    pub fn redact(mut self, secret: impl Into<String>) -> Cmd {
        let secret = secret.into();
        // An empty needle would match everywhere and hide nothing, and a
        // caller that passes one means "there is no secret here".
        if !secret.is_empty() {
            self.redact.push(secret);
        }
        self
    }

    /// The command as a human would type it, with every redacted value gone.
    /// Quoted only where it has to be, so that a line printed here can be
    /// pasted into a shell — which is the whole point of printing it.
    pub fn line(&self) -> String {
        let mut out = shell_quote(&self.redacted(&self.program));
        for a in &self.args {
            out.push(' ');
            out.push_str(&shell_quote(&self.redacted(a)));
        }
        out
    }

    /// The same, with the directory and the environment it runs in — for the
    /// journal, where "which command" alone is not enough to repeat a run.
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

    /// Apply the redaction list to any text that came from or names this
    /// command — its own argv, but also the stderr it produced, which happily
    /// echoes back the argument it did not like.
    pub fn redacted(&self, text: &str) -> String {
        let mut out = text.to_string();
        for secret in &self.redact {
            out = out.replace(secret.as_str(), "***");
        }
        out
    }
}

/// Quote an argument so that the printed line can be pasted into a shell.
///
/// An allowlist rather than a list of dangerous characters: a glob, a brace, a
/// backtick or a newline in a path all change what a pasted line means, and a
/// denylist is a list somebody forgets to extend.
fn shell_quote(a: &str) -> String {
    let safe = |c: char| c.is_ascii_alphanumeric() || "_@%+=:,./-".contains(c);
    if !a.is_empty() && a.chars().all(safe) {
        a.to_string()
    } else {
        format!("'{}'", a.replace('\'', r"'\''"))
    }
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

/// What this run is allowed to do. Checked before the spawn, by every
/// [`Runner`], including the one the tests use — so a test can pin that
/// `--offline` refuses rather than pin that a caller remembered to ask.
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

    /// Whether a command of this class may run. `--offline` is the stricter
    /// of the two, so when both are set both sentences would be true and the
    /// offline one is the one printed.
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

    /// One sentence, not a context chain: a refusal is printed with
    /// `{e}` as often as with `{e:#}`, and the reason has to survive both.
    fn gate(&self, cmd: &Cmd) -> Result<()> {
        match self.admits(cmd.effect) {
            Ok(()) => Ok(()),
            Err(why) => bail!("{} was not run: {why}.", cmd.line()),
        }
    }
}

/// A token that ends the command that is running right now.
///
/// The child runs in its own process group so that a `nix build` cannot be
/// half-killed by a Ctrl-C the shell delivered to it and not to us; the price
/// is that Ctrl-C no longer reaches the child at all, which is why this
/// exists. [`Cancel::on_sigint`] catches the signal here and kills the group
/// deliberately — one place that decides, rather than the terminal's idea of
/// a foreground process group.
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

    /// Install the SIGINT handler once, for the whole process. Called from
    /// `main`, never from a library path: a library that installs signal
    /// handlers behind its caller's back is a library that breaks the next
    /// program to link it.
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
    /// Run it, or say why it was not run. An exit code the command's
    /// [`Expect`] does not accept is an error here — the decision belongs to
    /// the command, not to every call site.
    fn run(&self, cmd: &Cmd) -> Result<Output>;

    /// What this runner refuses. Callers read it to skip a phase entirely
    /// rather than to walk into a refusal.
    fn policy(&self) -> Policy;
}

/// The real one: spawns, waits with a deadline, and kills the process GROUP
/// when the deadline passes or the operator interrupts.
pub struct Real {
    pub policy: Policy,
    /// Print every command to stderr before running it. stdout belongs to the
    /// answer — `--json` has to stay machine-readable — so diagnostics never
    /// go there.
    pub verbose: bool,
    pub cancel: Cancel,
}

impl Real {
    pub fn new(policy: Policy) -> Real {
        Real {
            policy,
            verbose: false,
            cancel: Cancel::new(),
        }
    }

    pub fn verbose(mut self, on: bool) -> Real {
        self.verbose = on;
        self
    }
}

/// How often the wait loop looks at the child. Small enough that a 200 ms
/// deadline is honoured to within a rounding error, large enough that a
/// ten-minute `nix build` is not a spin loop.
const POLL: Duration = Duration::from_millis(5);

/// How long a killed process group gets between SIGTERM and SIGKILL. `nix`
/// removes its temporary roots on SIGTERM and `ssh` closes its channel, and
/// both are worth waiting for; neither takes two seconds.
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
        // Its own process group, so that the deadline can take the whole tree
        // with it: `ssh host 'nix build'` and `sh -c '... &'` both leave
        // children that outlive the process we spawned.
        {
            use std::os::unix::process::CommandExt;
            builder.process_group(0);
        }

        let mut child = builder.spawn().with_context(|| missing(&cmd.program))?;
        let pgid = Pid::from_raw(child.id() as i32);

        // Three pipes, three threads. A child that writes more than a pipe
        // buffer to stderr while we wait on stdout deadlocks, and `nix build`
        // writes a great deal to stderr.
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
                if self.cancel.is_cancelled() {
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

        // The child is gone. Anything still in its process group is something
        // it left behind — and that something inherited the write end of our
        // stdout and stderr pipes, so `read_to_end` below would wait for IT
        // rather than for the command. `sh -c 'sleep 1000 & echo hi'` exits
        // immediately and would hang this call for a quarter of an hour: the
        // deadline would be a promise about the child alone, which is not what
        // the caller asked for. So the group is swept BEFORE the readers are
        // joined, and the joins are bounded by that rather than by patience.
        //
        // It is also the right thing on its own terms: this tool does not
        // leave background processes on an operator's machine.
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
                tail(&cmd.redacted(&stderr))
            );
        }
        if cancelled {
            bail!(
                "{} was interrupted and its process group was killed.",
                cmd.line()
            );
        }

        let out = Output {
            // A process killed by a signal has no exit code; -1 is not a code
            // any program returns, and the sentence below says which signal.
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

/// Take whatever is left of a process group: SIGTERM, up to [`GRACE`] to go,
/// then SIGKILL.
///
/// Called once the child has been reaped, so an empty group is the normal
/// case and both signals are then a no-op — `killpg` answers `ESRCH`, which
/// is the answer "nobody was left" and not an error worth a sentence.
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

/// Check the exit code against what the command expects, and turn a refusal
/// into a sentence that carries the command and what it said. Shared, so that
/// [`StrictFake`] refuses exactly what [`Real`] refuses.
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
        tail(&cmd.redacted(said))
    );
}

/// The last few lines of what a tool said. `nix` can produce a screen of
/// progress before the one line that matters, and the one line that matters
/// is at the end.
fn tail(text: &str) -> String {
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

/// The runner the tests use, and the only one they may use.
///
/// It answers a fixed sequence of expected commands and nothing else. An
/// unexpected command is an error AND is remembered; an expectation nobody
/// used is an error from [`StrictFake::verify`] and a panic from `Drop`. The
/// pre-v1 fake did neither — it answered anything with a default success and
/// forgot what it was asked — which is how a test could pass while the code
/// under it ran a command the test had never thought about.
pub struct StrictFake {
    policy: Policy,
    expects: RefCell<VecDeque<(Matcher, Output)>>,
    calls: RefCell<Vec<String>>,
    unexpected: RefCell<Vec<String>>,
    checked: Cell<bool>,
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
            expects: RefCell::new(VecDeque::new()),
            calls: RefCell::new(Vec::new()),
            unexpected: RefCell::new(Vec::new()),
            checked: Cell::new(false),
        }
    }

    pub fn with_policy(mut self, policy: Policy) -> StrictFake {
        self.policy = policy;
        self
    }

    /// The next command must match this, and will be answered with that.
    pub fn expect(self, matcher: Matcher, reply: Output) -> StrictFake {
        self.expects.borrow_mut().push_back((matcher, reply));
        self
    }

    /// Every command line that reached this runner, in order, redacted the
    /// same way a log line would be.
    pub fn calls(&self) -> Vec<String> {
        self.calls.borrow().clone()
    }

    /// Every expectation was used and no unexpected command arrived. A test
    /// that calls this takes responsibility for the answer; a test that does
    /// not gets the same verdict from `Drop`, as a panic.
    pub fn verify(&self) -> Result<()> {
        self.checked.set(true);
        let unused = self.expects.borrow();
        let unexpected = self.unexpected.borrow();
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
        // A test that already failed gets one message, not two: panicking
        // inside a panic aborts the process and takes the real failure's
        // output with it.
        if self.checked.get() || std::thread::panicking() {
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
        self.calls.borrow_mut().push(line.clone());
        let mut expects = self.expects.borrow_mut();
        match expects.front() {
            Some((matcher, _)) if matcher.matches(cmd) => {
                let (_, reply) = expects.pop_front().expect("just matched it");
                drop(expects);
                finish(cmd, reply)
            }
            Some((matcher, _)) => {
                let wanted = matcher.describe();
                drop(expects);
                self.unexpected.borrow_mut().push(line.clone());
                bail!("this runner expected `{wanted}` and got `{line}`.");
            }
            None => {
                drop(expects);
                self.unexpected.borrow_mut().push(line.clone());
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
        // sh backgrounds the first sleep and waits on the second. Without a
        // process group the background one would survive the kill, reparent
        // to init and hold the deadline's promise open for two more days.
        let cmd = sh("sleep 987655 & sleep 987655", Duration::from_millis(200));
        let err = Real::new(Policy::real()).run(&cmd).unwrap_err().to_string();
        assert!(err.contains("process group was killed"), "{err}");
        std::thread::sleep(Duration::from_millis(100));
        assert!(!pgrep("987655"), "a grandchild outlived its group");
    }

    #[test]
    fn a_grandchild_holding_the_pipe_does_not_outlast_the_command() {
        // sh backgrounds the sleep and exits at once. The sleep inherits the
        // stdout pipe, so joining the reader without sweeping the group would
        // wait for the sleep — eleven days, with a five-second deadline set.
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

    /// Is any process still RUNNING with this in its command line?
    ///
    /// A zombie does not count. Once a killed background process's parent is
    /// gone, the entry stays in the process table until init gets round to
    /// reaping it, and on a busy machine that is long enough to make this
    /// test fail for something that is not true: a zombie holds no file
    /// descriptor, so it is not what these tests are about.
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
            // "<pid> (comm) <state> …", and `comm` may itself contain spaces
            // and parentheses — so the state is the first character after the
            // LAST closing parenthesis.
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
