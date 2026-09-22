// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! One truth about ssh, and it is written down once.
//!
//! The pre-v1 tool had three: `remote.rs` offered
//! `StrictHostKeyChecking=accept-new` when it was being careful and
//! `StrictHostKeyChecking=no` plus `UserKnownHostsFile=/dev/null` when it
//! was not, and `nixos-rebuild --target-host` got no ssh options at all —
//! so the closure that changed a machine travelled over a connection nobody
//! had told anything about which machine it was. Three answers to one
//! question is how a fleet ends up trusting whoever answers on the address.
//!
//! Here there is one answer (D10):
//!
//! * `StrictHostKeyChecking=yes` against a `known_hosts` FILE IN THE
//!   OPERATOR'S REPOSITORY — public, committed, reviewed in a diff. A host
//!   that is not in it is not reachable, and the sentence says to run
//!   `keys enroll`. `accept-new` is trust-on-first-use, which is trust in
//!   whoever is faster; it appears nowhere outside `legacy/`, and
//!   `tests/ssh_is_strict.rs` reads the source to keep that true.
//! * `GlobalKnownHostsFile=/dev/null`, because the fleet's trust is the
//!   file in the repository and not whatever `/etc/ssh` on this workstation
//!   has collected.
//! * `BatchMode=yes` and `IdentitiesOnly=yes`: no prompt can hang a rollout,
//!   and the key that is used is the one that was named rather than whatever
//!   an agent happens to hold.
//! * `ConnectTimeout` and `ServerAlive*`, so that a host which stops
//!   answering mid-command ends the command instead of holding a lock on a
//!   fleet. (M0's own two-VM probe hung until a 3600-second test timeout for
//!   exactly the want of `BatchMode` and a deadline.)
//!
//! The same options are also what `nix copy --to ssh-ng://` must use, and
//! nix takes them through the environment variable `NIX_SSHOPTS` as ONE
//! string which it splits on white space. There is no quoting in that
//! splitting — nix's tokenizer does not remove quotes and neither does the
//! shell for an unquoted expansion — so a path with a space in it cannot be
//! passed that way at all. [`Ssh::nix_sshopts`] says so in a sentence
//! rather than producing a string that means something else than the
//! argument vector beside it.
//!
//! What is NOT here: anything that changes a target. [`Ssh::put`] builds the
//! command and is used by lane 2C and by `keys deliver` in M3; this lane
//! only ever asks.

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Result, bail};
use sha2::{Digest, Sha256};

use crate::observation::Endpoint;
use crate::run::{Cmd, Effect, Expect, Runner, is_bare, shell_quote};

/// How long a connection attempt may take before it is not a connection.
pub const CONNECT_TIMEOUT: u32 = 10;

/// How long a read-only probe may take. Generous on purpose: a host that is
/// busy booting answers slowly and is not a host that is gone.
pub const PROBE_DEADLINE: Duration = Duration::from_secs(60);

/// Where one host is reached, by the id the fleet knows it under.
///
/// Built from the manifest, or from the manifest reconciled with a provider's
/// target file ([`crate::observation::bind_targets`]) — never from a DNS
/// lookup here: a rollout that resolves a name itself is a rollout whose
/// answer to "which machine did you change" is "whatever the resolver said".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    pub host_id: String,
    pub address: String,
    pub port: u16,
    pub user: String,
}

impl Target {
    pub fn new(
        host_id: impl Into<String>,
        address: impl Into<String>,
        port: u16,
        user: impl Into<String>,
    ) -> Target {
        Target {
            host_id: host_id.into(),
            address: address.into(),
            port,
            user: user.into(),
        }
    }

    /// From a frozen endpoint of a plan, which is where every real run gets
    /// its targets: the plan froze the address with the selection, so a
    /// second `apply` of the same plan cannot talk to a machine that has
    /// since taken over the name.
    pub fn from_endpoint(host_id: &str, endpoint: &Endpoint) -> Target {
        Target {
            host_id: host_id.to_string(),
            address: endpoint.address.clone(),
            port: endpoint.port,
            user: endpoint.ssh_user.clone(),
        }
    }

    /// `user@address`, the one argument ssh takes for both.
    pub fn destination(&self) -> String {
        format!("{}@{}", self.user, self.address)
    }

    /// How `ssh-keygen -F` and `known_hosts` spell a host that is not on
    /// port 22: `[address]:port`.
    pub fn known_hosts_name(&self) -> String {
        if self.port == 22 {
            self.address.clone()
        } else {
            format!("[{}]:{}", self.address, self.port)
        }
    }

    /// The store url `nix copy --to` and `nix path-info --store` use.
    ///
    /// `ssh-ng` and never `ssh`: the old protocol accepts an unsigned
    /// closure from a trusted user, which is how the pre-v1 push worked and
    /// is precisely the guarantee `require-sigs = true` exists to give
    /// (M0 probe S12). A store url that takes unsigned closures would make
    /// the signing in `build` decoration.
    pub fn store_url(&self) -> String {
        format!("ssh-ng://{}", self.destination())
    }
}

/// The one set of ssh options, and the file they trust.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ssh {
    /// `<repo>/known_hosts`: public, committed, written only by
    /// `keys enroll`.
    pub known_hosts: PathBuf,
    /// The private key to offer, or none to let ssh use its configured
    /// default. Named rather than searched, because `IdentitiesOnly=yes`
    /// means the named one is the only one tried.
    pub identity: Option<PathBuf>,
    pub connect_timeout: u32,
}

impl Ssh {
    /// The transport of a fleet whose repository is at `repo`.
    pub fn for_repo(repo: &Path) -> Ssh {
        Ssh {
            known_hosts: repo.join("known_hosts"),
            identity: None,
            connect_timeout: CONNECT_TIMEOUT,
        }
    }

    pub fn with_known_hosts(known_hosts: impl Into<PathBuf>) -> Ssh {
        Ssh {
            known_hosts: known_hosts.into(),
            identity: None,
            connect_timeout: CONNECT_TIMEOUT,
        }
    }

    pub fn with_identity(mut self, identity: Option<PathBuf>) -> Ssh {
        self.identity = identity;
        self
    }

    /// The options, as separate arguments — so a key path with a space in it
    /// stays one argument.
    ///
    /// `-p <port>` is in here rather than at the call site because a host on
    /// 2222 has to be the same host in `known_hosts`, in `ssh` and in
    /// `NIX_SSHOPTS`, and three call sites are three chances to forget one.
    pub fn opts(&self, port: u16) -> Vec<String> {
        let mut out = vec![
            "-o".to_string(),
            "StrictHostKeyChecking=yes".to_string(),
            "-o".to_string(),
            format!("UserKnownHostsFile={}", self.known_hosts.display()),
            // The fleet's trust is the file in the repository. Whatever this
            // workstation's /etc/ssh/ssh_known_hosts has collected over the
            // years is not part of it.
            "-o".to_string(),
            "GlobalKnownHostsFile=/dev/null".to_string(),
            "-o".to_string(),
            "BatchMode=yes".to_string(),
            "-o".to_string(),
            "IdentitiesOnly=yes".to_string(),
            "-o".to_string(),
            format!("ConnectTimeout={}", self.connect_timeout),
            // A host that stops answering in the middle of a command: three
            // missed probes fifteen seconds apart end the connection, so the
            // command ends too. Without this, a rollout waits on a TCP
            // timeout while holding a lock.
            "-o".to_string(),
            "ServerAliveInterval=15".to_string(),
            "-o".to_string(),
            "ServerAliveCountMax=3".to_string(),
            // The banner of a host that is up and not ours is noise in every
            // parsed answer.
            "-o".to_string(),
            "LogLevel=ERROR".to_string(),
            "-p".to_string(),
            port.to_string(),
        ];
        if let Some(key) = &self.identity {
            out.push("-i".to_string());
            out.push(key.display().to_string());
        }
        out
    }

    /// The same options as the ONE string nix expects in `NIX_SSHOPTS`.
    ///
    /// Refuses rather than lies: nix splits this variable on white space and
    /// removes no quotes, so a `known_hosts` or key path containing a space —
    /// or a quote, a backslash, a newline — cannot be expressed here. The
    /// alternative would be a `nix copy` that trusts a different file than
    /// the `ssh` beside it, which is the class of bug this module exists to
    /// remove.
    pub fn nix_sshopts(&self, port: u16) -> Result<String> {
        let opts = self.opts(port);
        for arg in &opts {
            if !is_bare(arg) {
                bail!(
                    "{} cannot be passed to nix: NIX_SSHOPTS is one string that nix splits \
                     on white space, and nothing there removes quotes, so {:?} would reach \
                     ssh as more than one argument or as a different one. The known_hosts \
                     path and the key path must not contain white space, quotes or \
                     backslashes. Move the repository somewhere without them.",
                    self.known_hosts.display(),
                    arg
                );
            }
        }
        Ok(opts.join(" "))
    }

    /// Ask a host something. Read-only by construction: the effect class is
    /// [`Effect::Read`], so an `--offline` run refuses it before the spawn.
    ///
    /// `Expect::Codes([0, 1])`: the script may answer "no" — a unit that is
    /// inactive, a file that is not there — and that is an answer. 255 stays
    /// an error, which is how "ssh could not connect" is told apart from
    /// "the host said no".
    pub fn ask(&self, target: &Target, script: &str, deadline: Duration) -> Cmd {
        // `sh -c` explicitly rather than relying on the remote login shell:
        // the probe is POSIX sh and a host whose root shell is fish would
        // run it as something else.
        self.exec(target, ["sh", "-c", script], Effect::Read, deadline)
            .expect(Expect::Codes(vec![0, 1]))
    }

    /// A command on the far side, quoted for the shell that will read it.
    ///
    /// **ssh does not carry an argument vector.** It JOINS what it is given
    /// with spaces and hands the result to the remote login shell, which
    /// splits it again by its own rules. So arguments that are separate
    /// here arrive as different arguments there the moment one of them
    /// holds a space, a quote or a newline — and two of the things this
    /// tool sends do: the read-only probe, which is a whole shell script in
    /// one argument, and every `--because <sentence>` a revert carries.
    ///
    /// Measured rather than reasoned about: the first run of
    /// nix/tests/update.nix against a real sshd got an empty answer from
    /// every host, because `ssh host sh -c '<script>'` reached the target as
    /// `sh -c printf` with the rest of the script as positional arguments.
    /// Every fake runner and every PATH shim in this crate had been happy
    /// with it, because both of them receive an argv.
    ///
    /// So each argument is quoted HERE, by the same rule
    /// [`crate::run::shell_quote`] uses everywhere else. They stay separate
    /// arguments of the local `ssh` — which is what keeps a command line
    /// readable in a log and matchable in a test — and they are already the
    /// words the remote shell will read back.
    pub fn exec<I, S>(&self, target: &Target, argv: I, effect: Effect, deadline: Duration) -> Cmd
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        Cmd::new(effect, "ssh", deadline)
            .args(self.opts(target.port))
            .arg(target.destination())
            .args(argv.into_iter().map(|a| shell_quote(a.as_ref())))
    }

    /// Put bytes on a host, at a path, with an owner and a mode.
    ///
    /// Built here and used by lane 2C and by `keys deliver` (M3); nothing in
    /// this lane calls it. Three properties it has to have, and all three
    /// are the reason it is a command builder rather than an `scp`:
    ///
    /// * The content travels on **stdin**, never in the argv, because an
    ///   argv is world-readable in `/proc` on the target for as long as the
    ///   command runs.
    /// * The content is **redacted** out of every place this command is
    ///   printed — the log line, the error, the journal.
    /// * The file is created with the mode it is to have, and `install -m`
    ///   does that in one step rather than creating it readable and fixing
    ///   it afterwards.
    pub fn put(
        &self,
        target: &Target,
        path: &str,
        bytes: &[u8],
        mode: &str,
        owner: &str,
        deadline: Duration,
    ) -> Cmd {
        let text = String::from_utf8_lossy(bytes).into_owned();
        // `install` creates the temporary with the final mode, and the move
        // is atomic within the directory: a service that reads the file
        // while this runs reads the old one or the new one.
        let script = format!(
            "set -e; d=$(dirname {path}); mkdir -p \"$d\"; \
             t=$(mktemp \"$d/.meister.XXXXXX\"); cat > \"$t\"; \
             chown {owner} \"$t\"; chmod {mode} \"$t\"; mv \"$t\" {path}",
            path = shell_quote(path),
            owner = shell_quote(owner),
            mode = shell_quote(mode),
        );
        self.exec(target, ["sh", "-c", &script], Effect::TargetWrite, deadline)
            .stdin(bytes.to_vec())
            .redact(text)
    }

    /// `ssh-keygen -F <host> -f <known_hosts>`: does the fleet know this
    /// host's key?
    pub fn lookup_cmd(&self, target: &Target) -> Cmd {
        Cmd::new(Effect::Read, "ssh-keygen", Duration::from_secs(20))
            .arg("-F")
            .arg(target.known_hosts_name())
            .arg("-f")
            .arg(self.known_hosts.display().to_string())
            // Exit 1 is the answer "not in there", and it is the answer this
            // is asked for.
            .expect(Expect::Codes(vec![0, 1]))
    }

    /// The fingerprint `known_hosts` holds for this host, or `None`.
    ///
    /// This is where an observation's `host_key_fingerprint` comes from: the
    /// entry that `StrictHostKeyChecking=yes` accepted the connection
    /// against. Not from `ssh-keyscan`, which reports whatever answers on
    /// the address — that is the one thing an observation must not do,
    /// because it would make an impersonating host self-certifying.
    pub fn enrolled_fingerprint(
        &self,
        runner: &dyn Runner,
        target: &Target,
    ) -> Result<Option<String>> {
        let out = runner.run(&self.lookup_cmd(target))?;
        if out.status != 0 || out.stdout.trim().is_empty() {
            return Ok(None);
        }
        Ok(fingerprint_of(&out.stdout))
    }

    /// Refuse to connect to a host the fleet has not enrolled.
    ///
    /// Checked BEFORE the first connection attempt on purpose. ssh would
    /// also refuse — that is what `StrictHostKeyChecking=yes` is — but it
    /// would refuse with "Host key verification failed", and the operator
    /// would then go looking for a broken host rather than for the enrolment
    /// step that never happened.
    pub fn require_enrolled(&self, runner: &dyn Runner, target: &Target) -> Result<String> {
        match self.enrolled_fingerprint(runner, target)? {
            Some(fingerprint) => Ok(fingerprint),
            None => bail!(
                "host {} is not enrolled; run keys enroll. Nothing in {} carries a key for \
                 {}, so ssh would refuse the connection — and it should: accepting whatever \
                 answers on an address is how a fleet ends up taking orders from the wrong \
                 machine. Read the fingerprint off the console or the installer's output \
                 and run `keys enroll {} --fingerprint SHA256:…`.",
                target.host_id,
                self.known_hosts.display(),
                target.known_hosts_name(),
                target.host_id
            ),
        }
    }
}

/// The `SHA256:…` fingerprint out of what `ssh-keygen -F` printed.
///
/// `-F` prints the matching `known_hosts` line — `host keytype base64key` —
/// possibly behind a `# Host … found:` comment. The fingerprint of a key is
/// the sha256 of its wire bytes, base64 without padding, which is exactly
/// what `ssh-keygen -l` computes; doing it here rather than in a second
/// round trip keeps the enrolment check at one command.
///
/// Public because `keys enroll` fingerprints what `ssh-keyscan` answered
/// with in exactly this way. A second implementation of "what a host key
/// hashes to" would be a second answer to the one question this fleet's
/// trust hangs on.
pub fn fingerprint_of(keygen_output: &str) -> Option<String> {
    for line in keygen_output.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut fields = line.split_whitespace();
        let mut first = fields.next()?;
        // A `@cert-authority` or `@revoked` marker sits in FRONT of the host
        // and shifts every field by one. Reading past it rather than
        // fingerprinting the marker; which of the two it is does not change
        // where the key is.
        if first.starts_with('@') {
            first = fields.next()?;
        }
        let _host = first;
        let _keytype = fields.next()?;
        let blob = fields.next()?;
        let bytes = base64_decode(blob)?;
        let digest = Sha256::digest(&bytes);
        return Some(format!("SHA256:{}", base64_encode_unpadded(&digest)));
    }
    None
}

const B64: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn base64_decode(text: &str) -> Option<Vec<u8>> {
    let mut acc: u32 = 0;
    let mut bits = 0u32;
    let mut out = Vec::new();
    for c in text.chars() {
        if c == '=' {
            break;
        }
        let value = B64.iter().position(|b| *b as char == c)? as u32;
        acc = (acc << 6) | value;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(((acc >> bits) & 0xff) as u8);
        }
    }
    Some(out)
}

fn base64_encode_unpadded(bytes: &[u8]) -> String {
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        let take = chunk.len() + 1;
        for i in 0..take {
            out.push(B64[((n >> (18 - 6 * i)) & 0x3f) as usize] as char);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::run::{Matcher, Output, Policy, StrictFake};

    fn ssh() -> Ssh {
        Ssh::with_known_hosts("/home/silas/git/lab/known_hosts")
    }

    fn target() -> Target {
        Target::new("n1", "10.0.0.11", 22, "root")
    }

    #[test]
    fn every_option_is_its_own_argument_and_the_strict_one_is_yes() {
        let opts = ssh().opts(22);
        assert!(opts.contains(&"StrictHostKeyChecking=yes".to_string()));
        assert!(
            opts.contains(&"UserKnownHostsFile=/home/silas/git/lab/known_hosts".to_string()),
            "{opts:?}"
        );
        assert!(opts.contains(&"GlobalKnownHostsFile=/dev/null".to_string()));
        assert!(opts.contains(&"BatchMode=yes".to_string()));
        assert!(opts.contains(&"IdentitiesOnly=yes".to_string()));
        assert!(opts.contains(&"ConnectTimeout=10".to_string()));
        assert!(opts.contains(&"ServerAliveInterval=15".to_string()));
        assert!(opts.contains(&"ServerAliveCountMax=3".to_string()));
        assert!(opts.contains(&"LogLevel=ERROR".to_string()));
        // Every `-o` is followed by exactly one value, so the vector is an
        // argv and not a string somebody has to re-split.
        let os = opts.iter().filter(|a| *a == "-o").count();
        assert_eq!(os, 9, "{opts:?}");
        assert_eq!(opts.len(), os * 2 + 2, "nine options, then -p and a port");
        for (i, arg) in opts.iter().enumerate() {
            if arg == "-o" {
                assert!(
                    opts[i + 1].contains('=') && !opts[i + 1].starts_with('-'),
                    "{:?} follows a -o",
                    opts[i + 1]
                );
            }
        }
    }

    #[test]
    fn a_key_path_with_a_space_stays_one_argument() {
        let ssh = ssh().with_identity(Some(PathBuf::from("/home/silas/my keys/id_ed25519")));
        let opts = ssh.opts(2222);
        let i = opts
            .iter()
            .position(|a| a == "-i")
            .expect("the key is named");
        assert_eq!(opts[i + 1], "/home/silas/my keys/id_ed25519");
        assert!(opts.contains(&"2222".to_string()));
    }

    #[test]
    fn the_port_travels_with_the_options_and_into_the_known_hosts_name() {
        let opts = ssh().opts(2222);
        let p = opts
            .iter()
            .position(|a| a == "-p")
            .expect("the port is set");
        assert_eq!(opts[p + 1], "2222");
        assert_eq!(
            Target::new("gpu-01", "10.128.1.111", 2222, "root").known_hosts_name(),
            "[10.128.1.111]:2222"
        );
        assert_eq!(target().known_hosts_name(), "10.0.0.11");
    }

    #[test]
    fn the_nix_variable_splits_back_into_the_same_arguments() {
        let ssh = ssh();
        let opts = ssh.opts(22);
        let joined = ssh.nix_sshopts(22).unwrap();
        // The real test of a string nix will split: let a shell split it the
        // same way and compare the pieces to the argv.
        let out = crate::run::Real::new(Policy::real())
            .run(
                &Cmd::new(Effect::Offline, "sh", Duration::from_secs(10))
                    .arg("-c")
                    .arg("printf '%s\\n' $NIX_SSHOPTS")
                    .env("NIX_SSHOPTS", &joined),
            )
            .unwrap();
        let split: Vec<String> = out.stdout.lines().map(str::to_string).collect();
        assert_eq!(split, opts, "NIX_SSHOPTS split differently than the argv");
    }

    #[test]
    fn a_path_nix_cannot_be_told_about_is_a_sentence_and_not_a_guess() {
        let ssh = Ssh::with_known_hosts("/home/silas/my repo/known_hosts");
        let err = ssh.nix_sshopts(22).unwrap_err().to_string();
        assert!(err.contains("must not contain white space"), "{err}");
        assert!(err.contains("my repo"), "{err}");
        // And the argv form still works, because ssh takes arguments.
        assert!(
            ssh.opts(22)
                .contains(&"UserKnownHostsFile=/home/silas/my repo/known_hosts".to_string())
        );
    }

    #[test]
    fn a_question_is_a_read_and_may_answer_no() {
        let cmd = ssh().ask(
            &target(),
            "systemctl is-active meister-agent",
            PROBE_DEADLINE,
        );
        assert_eq!(cmd.effect, Effect::Read);
        assert_eq!(cmd.deadline, PROBE_DEADLINE);
        assert_eq!(cmd.expect, Expect::Codes(vec![0, 1]));
        assert!(cmd.line().contains("root@10.0.0.11"), "{}", cmd.line());
        assert!(cmd.line().contains("sh -c"), "{}", cmd.line());
    }

    /// The one that the VM test found: ssh carries a STRING, not an argv.
    #[test]
    fn what_reaches_the_far_side_is_what_was_meant_even_when_it_has_spaces_in_it() {
        // A script with quotes, spaces and a newline in it — which is what
        // the read-only probe is — plus an argument that is a sentence,
        // which is what `--because` carries.
        let script = "printf 'a b\n' ; printf 'c\n'";
        let cmd = ssh().ask(&target(), script, PROBE_DEADLINE);
        // ssh joins everything after the destination with spaces and hands
        // it to the remote login shell. So THAT is what has to parse back
        // into the words that were meant: let a real shell do the parsing
        // and print what it got, one argument per line.
        let after = cmd
            .args
            .iter()
            .skip_while(|a| !a.starts_with("root@"))
            .skip(1)
            .cloned()
            .collect::<Vec<_>>()
            .join(" ");
        let out = crate::run::Real::new(Policy::real())
            .run(
                &Cmd::new(Effect::Offline, "sh", Duration::from_secs(10))
                    .arg("-c")
                    // NUL-separated: one of the arguments HAS newlines in
                    // it, and a newline-separated answer could not tell an
                    // argument that contains one from two arguments.
                    .arg(format!("set -- {after}; printf '%s\\0' \"$@\"")),
            )
            .unwrap();
        let words: Vec<&str> = out.stdout.split('\0').filter(|w| !w.is_empty()).collect();
        assert_eq!(
            words,
            vec!["sh", "-c", script],
            "the far side would have seen something else than the three words that were meant"
        );

        let cmd = ssh().exec(
            &target(),
            [
                "meister-activate",
                "revert",
                "--because",
                "a unit did not come up",
            ],
            Effect::TargetWrite,
            PROBE_DEADLINE,
        );
        let after = cmd
            .args
            .iter()
            .skip_while(|a| !a.starts_with("root@"))
            .skip(1)
            .cloned()
            .collect::<Vec<_>>()
            .join(" ");
        let out = crate::run::Real::new(Policy::real())
            .run(
                &Cmd::new(Effect::Offline, "sh", Duration::from_secs(10))
                    .arg("-c")
                    .arg(format!("set -- {after}; printf '%s\\0' \"$@\"")),
            )
            .unwrap();
        assert_eq!(
            out.stdout
                .split('\0')
                .filter(|w| !w.is_empty())
                .collect::<Vec<_>>(),
            vec![
                "meister-activate",
                "revert",
                "--because",
                "a unit did not come up"
            ],
            "a reason with spaces in it became several arguments"
        );
    }

    #[test]
    fn a_probe_of_a_host_that_is_gone_is_an_error_and_not_an_empty_answer() {
        // 255 is ssh's own failure and is NOT in the accepted set, so a host
        // that could not be reached cannot be mistaken for a host with no
        // units.
        let runner = StrictFake::new().expect(
            Matcher::prefix("ssh", ["-o", "StrictHostKeyChecking=yes"]),
            Output::failing(
                255,
                "ssh: connect to host 10.0.0.11 port 22: No route to host",
            ),
        );
        let err = runner
            .run(&ssh().ask(&target(), "hostname", PROBE_DEADLINE))
            .unwrap_err()
            .to_string();
        runner.verify().unwrap();
        assert!(err.contains("255"), "{err}");
        assert!(err.contains("No route to host"), "{err}");
    }

    #[test]
    fn what_a_secret_carries_never_reaches_a_line_that_is_printed() {
        let cmd = ssh().put(
            &target(),
            "/var/lib/meisterstack/pki/identity.key",
            b"-----BEGIN PRIVATE KEY-----\nMIIBsecret\n-----END PRIVATE KEY-----\n",
            "0600",
            "meister:meister",
            Duration::from_secs(30),
        );
        assert_eq!(cmd.effect, Effect::TargetWrite);
        let line = cmd.line();
        assert!(!line.contains("MIIBsecret"), "{line}");
        assert!(!line.contains("PRIVATE KEY"), "{line}");
        assert!(
            line.contains("/var/lib/meisterstack/pki/identity.key"),
            "{line}"
        );
        // The bytes travel on stdin, which is the only place they may be.
        assert!(cmd.stdin.as_ref().unwrap().starts_with(b"-----BEGIN"));
        // And a target that echoes the content back — `sh: cannot create
        // …: <the whole thing>` — gets redacted too, because the same list
        // is applied to stderr. The limit: it is a substring match on the
        // WHOLE secret, so a target that echoed one line of a key back
        // would not be caught. Nothing in this tool sends a key anywhere
        // that echoes, and a fragment is not something a replace list can
        // find.
        let echoed = format!(
            "sh: cannot write: {}",
            String::from_utf8_lossy(cmd.stdin.as_ref().unwrap())
        );
        assert_eq!(cmd.redacted(&echoed), "sh: cannot write: ***");
        // And the mode is set on the temporary, before the file is in place.
        let script = cmd.args.last().expect("the script is the last argument");
        assert!(script.contains("chmod 0600 \"$t\""), "{script}");
        assert!(script.contains("mv \"$t\""), "{script}");
    }

    #[test]
    fn a_host_in_the_known_hosts_file_answers_with_its_fingerprint() {
        // A real `ssh-keygen -F` line for a key whose fingerprint is known:
        // the ed25519 key of all zeroes.
        let blob = "AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let runner = StrictFake::new().expect(
            Matcher::exact(
                "ssh-keygen",
                ["-F", "10.0.0.11", "-f", "/home/silas/git/lab/known_hosts"],
            ),
            Output::stdout(format!(
                "# Host 10.0.0.11 found: line 3\n10.0.0.11 ssh-ed25519 {blob}\n"
            )),
        );
        let fingerprint = ssh()
            .require_enrolled(&runner, &target())
            .expect("the host is enrolled");
        runner.verify().unwrap();
        assert!(fingerprint.starts_with("SHA256:"), "{fingerprint}");
        // Computed, not echoed: the same spelling `ssh-keygen -lf` prints.
        assert_eq!(
            fingerprint,
            "SHA256:kmYcvdi2GkPeWxB6XLjrZB8JHsy2Hm8luHMFp9GMvqk"
        );
    }

    #[test]
    fn a_host_nobody_enrolled_is_refused_before_a_connection_is_tried() {
        let runner = StrictFake::new().expect(
            Matcher::prefix("ssh-keygen", ["-F"]),
            Output::failing(1, ""),
        );
        let err = ssh()
            .require_enrolled(&runner, &target())
            .unwrap_err()
            .to_string();
        runner.verify().unwrap();
        assert!(err.contains("is not enrolled; run keys enroll"), "{err}");
        assert!(err.contains("keys enroll n1 --fingerprint"), "{err}");
        // Nothing was asked of the host itself: one command, and it was the
        // local lookup.
        assert_eq!(runner.calls().len(), 1);
        assert!(
            runner.calls()[0].starts_with("ssh-keygen"),
            "{:?}",
            runner.calls()
        );
    }

    #[test]
    fn a_marked_known_hosts_line_is_not_read_as_a_plain_key() {
        let blob = "AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let plain = fingerprint_of(&format!("10.0.0.11 ssh-ed25519 {blob}\n"));
        let marked = fingerprint_of(&format!("@cert-authority 10.0.0.11 ssh-ed25519 {blob}\n"));
        assert_eq!(plain, marked, "the marker shifts the fields, not the key");
        assert_eq!(fingerprint_of("# nothing but a comment\n"), None);
        assert_eq!(fingerprint_of(""), None);
    }

    #[test]
    fn the_store_url_is_the_protocol_that_wants_signatures() {
        assert_eq!(target().store_url(), "ssh-ng://root@10.0.0.11");
    }

    #[test]
    fn an_offline_run_asks_no_host_anything() {
        let runner = StrictFake::new().with_policy(Policy::offline());
        let err = runner
            .run(&ssh().ask(&target(), "hostname", PROBE_DEADLINE))
            .unwrap_err()
            .to_string();
        runner.verify().unwrap();
        assert!(err.contains("--offline"), "{err}");
        assert!(err.contains("read"), "{err}");
    }

    #[test]
    fn a_dry_run_may_ask_and_may_not_write() {
        let runner = StrictFake::new()
            .with_policy(Policy::dry_run())
            .expect(Matcher::prefix("ssh", ["-o"]), Output::stdout("box\n"));
        let asked = runner.run(&ssh().ask(&target(), "hostname", PROBE_DEADLINE));
        assert!(asked.is_ok(), "a dry run reads: {asked:?}");
        let written = runner.run(&ssh().put(
            &target(),
            "/tmp/x",
            b"x",
            "0600",
            "root",
            Duration::from_secs(5),
        ));
        runner.verify().unwrap();
        let err = written.unwrap_err().to_string();
        assert!(err.contains("--dry-run"), "{err}");
        assert!(err.contains("target-write"), "{err}");
    }
}
