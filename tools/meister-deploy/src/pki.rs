// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Enrolment, and the certificates that come back over a CSR.
//!
//! Two promises live in this file, and everything in it is one of the two:
//!
//! * **No host key is ever accepted blind.** `keys enroll` asks the address
//!   what key it shows, and then compares it against a fingerprint a person
//!   TYPED — off a console, a BMC screen or the installer's own output.
//!   A machine that shows a different key is not enrolled and the sentence
//!   says both fingerprints. `accept-new` would make the first answer the
//!   truth, which is trust in whoever is faster; the pre-v1 tool did exactly
//!   that (`remote.rs:25-93`), and D10 is the decision to stop.
//! * **No private key ever leaves the machine it belongs to.** The key is
//!   made on the target by `meister-activate keygen`
//!   ([`crate::activate::Helper::keygen`]); what travels back is a
//!   certificate REQUEST, which is a public key and a name. `keys issue`
//!   hands that request to `tools/meister-ca`, which signs it with a CA key
//!   that never leaves the operator. So the two halves of an identity are
//!   never in the same place, and this workstation has never held one.
//!
//! What is NOT here is a verb that puts a certificate on a host. Delivery is
//! the plan's action `deliver-secret` and `apply` carries it out — a second
//! road to a target, past the locks and past the journal, is precisely what
//! D6 exists to prevent.

use std::path::Path;
use std::time::Duration;

use anyhow::{Result, bail};
use chrono::{DateTime, Utc};

use crate::effects::Files;
use crate::manifest::ResolvedHost;
use crate::run::{Cmd, Effect, Expect, Runner};
use crate::transport::{Target, fingerprint_of};

/// How long `ssh-keyscan` may spend on one host, as its own `-T` and as the
/// deadline of the command. Two numbers because a program that ignores its
/// own timeout still has to be killed.
pub const SCAN_TIMEOUT_SECS: u32 = 10;
pub const SCAN_DEADLINE: Duration = Duration::from_secs(30);

/// The key algorithm this fleet enrols.
///
/// One and not "whatever the host offers": a host that answers with three
/// key types gives three fingerprints, and an operator reading one off a
/// console then has to know which of them to compare. Ed25519 because every
/// sshd of this decade has one and it is the shortest thing to read out
/// loud.
pub const KEY_TYPE: &str = "ssh-ed25519";

/// What the address answered with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScannedKey {
    pub keytype: String,
    /// The base64 blob, exactly as `known_hosts` spells it.
    pub blob: String,
    /// `SHA256:…`, computed here from the bytes rather than taken from
    /// anything the host said about itself.
    pub fingerprint: String,
}

impl ScannedKey {
    /// The `known_hosts` line for this key at this host.
    pub fn line(&self, known_hosts_name: &str) -> String {
        format!("{known_hosts_name} {} {}", self.keytype, self.blob)
    }
}

/// `ssh-keyscan -t ed25519 -p <port> -T <n> <address>`.
///
/// [`Effect::Read`]: it opens a connection and asks for a public key. An
/// `--offline` run refuses it before the spawn, which is right — there is
/// nothing on this disk that could answer the question.
pub fn keyscan_cmd(target: &Target) -> Cmd {
    Cmd::new(Effect::Read, "ssh-keyscan", SCAN_DEADLINE)
        .arg("-t")
        .arg("ed25519")
        .arg("-p")
        .arg(target.port.to_string())
        .arg("-T")
        .arg(SCAN_TIMEOUT_SECS.to_string())
        .arg(&target.address)
        // ssh-keyscan exits 0 with EMPTY output for a host that did not
        // answer, so the exit code is not the answer and the parser below
        // is. `Codes([0, 1])` keeps a refusal readable instead of turning
        // "nothing answered" into a runner error with no detail.
        .expect(Expect::Codes(vec![0, 1]))
}

/// The one key out of what `ssh-keyscan` printed.
///
/// Comment lines (`# 10.0.0.11:22 SSH-2.0-OpenSSH_10.0`) are what keyscan
/// writes to stdout about the banner, and they are skipped rather than
/// parsed: what is wanted is the key.
pub fn parse_keyscan(output: &str, host_id: &str) -> Result<ScannedKey> {
    for line in output.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut fields = line.split_whitespace();
        let _host = fields.next();
        let Some(keytype) = fields.next() else {
            continue;
        };
        let Some(blob) = fields.next() else {
            continue;
        };
        if keytype != KEY_TYPE {
            continue;
        }
        let Some(fingerprint) = fingerprint_of(line) else {
            bail!(
                "the key {host_id} showed is not readable: {:?} is not base64 of an ssh \
                 public key.",
                blob
            );
        };
        return Ok(ScannedKey {
            keytype: keytype.to_string(),
            blob: blob.to_string(),
            fingerprint,
        });
    }
    bail!(
        "nothing at {host_id} answered with an {KEY_TYPE} host key. Either the machine is \
         not up yet, or sshd is not listening on that port, or it offers no ed25519 key — \
         `ssh-keyscan` printed: {:?}",
        output.trim()
    )
}

/// What an enrolment came to, for the caller that has to print it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Enrolment {
    pub host_id: String,
    /// How `known_hosts` spells this host: the address, or `[address]:port`.
    pub known_hosts_name: String,
    pub fingerprint: String,
    /// False when the file already said exactly this — then nothing was
    /// written, and running the verb twice is not a change.
    pub changed: bool,
    /// The fingerprint that was there before, when one was replaced.
    pub replaced: Option<String>,
    /// The line to paste into `[[host]]` in the inventory.
    pub toml_line: String,
}

/// Compare what was typed with what answered, and write `known_hosts`.
///
/// `typed` is the fingerprint a PERSON read off the console. It is the whole
/// security of this step: without it the first machine to answer on the
/// address becomes the machine this fleet deploys to.
///
/// `--replace` is deliberately two flags (`replace` and `reason`): replacing
/// a host key is either a reinstall or an attack, and which of the two it
/// is only the operator knows. The reason lands in the file, above the line,
/// where the next reader of the diff will find it.
#[allow(clippy::too_many_arguments)]
pub fn enroll(
    runner: &dyn Runner,
    files: &dyn Files,
    known_hosts: &Path,
    target: &Target,
    typed: &str,
    replace: bool,
    reason: Option<&str>,
    now: DateTime<Utc>,
) -> Result<Enrolment> {
    let typed = normalise_fingerprint(typed)?;
    let out = runner.run(&keyscan_cmd(target))?;
    let scanned = parse_keyscan(&out.stdout, &target.host_id)?;

    if scanned.fingerprint != typed {
        bail!(
            "the key {} shows is not the one you typed: either you read another machine's \
             console, or somebody is between you and this host.\n  you typed: {typed}\n  \
             {} shows: {}\nNothing was written. Read the fingerprint off the console of the \
             machine you mean (`ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub` there) and \
             run this again.",
            target.host_id,
            target.address,
            scanned.fingerprint
        );
    }

    let name = target.known_hosts_name();
    let existing = if files.exists(known_hosts) {
        files.read_to_string(known_hosts)?
    } else {
        String::new()
    };
    let wanted = scanned.line(&name);

    let mut mine: Vec<&str> = Vec::new();
    for line in existing.lines() {
        if host_field(line).is_some_and(|h| h == name) {
            mine.push(line.trim_end());
        }
    }
    let already = mine.len() == 1 && mine[0] == wanted;
    let toml_line = format!("ssh.host_key = \"{}\"", scanned.fingerprint);

    if already {
        return Ok(Enrolment {
            host_id: target.host_id.clone(),
            known_hosts_name: name,
            fingerprint: scanned.fingerprint,
            changed: false,
            replaced: None,
            toml_line,
        });
    }

    let replaced = if mine.is_empty() {
        None
    } else {
        // Something else is already in there for this host. Refusing is the
        // point: a `known_hosts` this tool rewrites on its own is a
        // `known_hosts` that says nothing.
        let reason = match (replace, reason) {
            (true, Some(reason)) if !reason.trim().is_empty() => reason.trim().to_string(),
            (true, _) => bail!(
                "--replace without --reason. Replacing a host key is either a reinstall or \
                 an attack, and only you know which; the reason is written into \
                 {} above the new line, where the next reader of the diff will find it.",
                known_hosts.display()
            ),
            (false, _) => bail!(
                "{} already carries another key for {name} in {}:\n  {}\nIf the machine was \
                 reinstalled, say so: `keys enroll {} --fingerprint {} --replace --reason \
                 <why>`. If it was not, then something is answering on that address that was \
                 not there before, and enrolling it would be the mistake.",
                target.host_id,
                known_hosts.display(),
                mine.join("\n  "),
                target.host_id,
                scanned.fingerprint
            ),
        };
        Some((
            reason,
            mine.iter().map(|l| l.to_string()).collect::<Vec<_>>(),
        ))
    };

    let mut kept: Vec<String> = Vec::new();
    for line in existing.lines() {
        if host_field(line).is_some_and(|h| h == name) {
            continue;
        }
        kept.push(line.to_string());
    }
    if let Some((reason, _)) = &replaced {
        kept.push(format!(
            "# replaced {} {reason}",
            now.format("%Y-%m-%dT%H:%M:%SZ")
        ));
    }
    kept.push(wanted);
    let mut text = kept.join("\n");
    text.push('\n');
    // 0644: this file is public, committed and read by ssh.
    files.write_atomic(known_hosts, text.as_bytes(), 0o644)?;

    Ok(Enrolment {
        host_id: target.host_id.clone(),
        known_hosts_name: name,
        fingerprint: scanned.fingerprint.clone(),
        changed: true,
        replaced: replaced.and_then(|(_, lines)| {
            lines
                .first()
                .and_then(|line| fingerprint_of(line))
                .or_else(|| Some("an unreadable entry".to_string()))
        }),
        toml_line,
    })
}

/// The host a `known_hosts` line is about, past a `@cert-authority` or
/// `@revoked` marker. `None` for a comment or an empty line.
fn host_field(line: &str) -> Option<&str> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return None;
    }
    let mut fields = line.split_whitespace();
    let first = fields.next()?;
    if first.starts_with('@') {
        fields.next()
    } else {
        Some(first)
    }
}

/// `SHA256:<base64>` without padding, which is what `ssh-keygen -l` prints.
///
/// The padding is trimmed rather than rejected because a person copying a
/// fingerprint out of a terminal is not the person who should have to know
/// that openssh omits it.
fn normalise_fingerprint(typed: &str) -> Result<String> {
    let typed = typed.trim();
    let Some(body) = typed.strip_prefix("SHA256:") else {
        bail!(
            "{typed:?} is not a host key fingerprint. It looks like \
             `SHA256:iqjB6QZ0k2r…`, and `ssh-keygen -lf \
             /etc/ssh/ssh_host_ed25519_key.pub` on the console prints it."
        );
    };
    let body = body.trim_end_matches('=');
    if body.is_empty() {
        bail!("{typed:?} is a `SHA256:` with nothing after it.");
    }
    Ok(format!("SHA256:{body}"))
}

// ---------------------------------------------------------------------------
// Where one host is reached, before there is a manifest
// ---------------------------------------------------------------------------

/// The target of a host that has not been resolved yet.
///
/// Enrolment happens BEFORE the first `resolve` of a fresh machine — a host
/// with no key in `known_hosts` cannot be reached, so nothing that needs to
/// reach it can have run first. So this reads the inventory, which is the
/// one file that exists at that point, and applies the same precedence
/// `validate` does.
pub fn target_from_inventory(
    inventory: &crate::inventory::Inventory,
    host_id: &str,
) -> Result<Target> {
    let host = inventory
        .hosts
        .get(host_id)
        .ok_or_else(|| anyhow::anyhow!("there is no host {host_id:?} in this inventory."))?;
    let settings = inventory.effective(host_id)?;
    let address = host
        .networks
        .management
        .as_ref()
        .map(|n| n.address.clone())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "{host_id} has no `networks.management`, so this tool does not know where to \
                 reach it."
            )
        })?;
    Ok(Target::new(
        host_id,
        address,
        settings.ssh.port,
        settings.ssh.user,
    ))
}

/// The same from a manifest, for a host that has one.
pub fn target_from_host(host_id: &str, host: &ResolvedHost) -> Target {
    Target::new(
        host_id,
        host.address.clone(),
        host.ssh.port,
        host.ssh.user.clone(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::effects::MemFiles;
    use crate::run::{Matcher, Output, Policy, StrictFake};

    /// A real ed25519 host key line and the fingerprint `ssh-keygen -lf`
    /// printed for it. Checked in as a VECTOR rather than computed by the
    /// same code the test is about:
    ///
    /// ```text
    /// $ ssh-keygen -q -t ed25519 -N '' -C '' -f k
    /// $ cat k.pub
    /// ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGaYimwvsKj3dq6R/7mpM1IdGR6CKdji1qLjc488Cxol
    /// $ ssh-keygen -lf k.pub
    /// 256 SHA256:n4iE8HiaQ8h0ur9SAR4Op6czqCfYYwHSX857a4w10Ks  (ED25519)
    /// ```
    const BLOB: &str = "AAAAC3NzaC1lZDI1NTE5AAAAIGaYimwvsKj3dq6R/7mpM1IdGR6CKdji1qLjc488Cxol";
    const FINGERPRINT: &str = "SHA256:n4iE8HiaQ8h0ur9SAR4Op6czqCfYYwHSX857a4w10Ks";
    /// A second real one, for "the machine shows a different key"
    /// (`SHA256:7YqoU59AFBkQ68D2Dt184AZjYjzu7bFhTBgF1jv2m+Q`).
    const OTHER_BLOB: &str = "AAAAC3NzaC1lZDI1NTE5AAAAIBxDX2LuYkwdC3yGwD8hW6DpgdYcrFFs7fcm0OXyb7T6";

    fn target() -> Target {
        Target::new("n1", "10.0.0.11", 22, "root")
    }

    fn scan_reply(address: &str) -> Output {
        Output::stdout(format!(
            "# {address}:22 SSH-2.0-OpenSSH_10.0\n{address} ssh-ed25519 {BLOB}\n"
        ))
    }

    fn fake(target: &Target, reply: Output) -> StrictFake {
        StrictFake::new().expect(
            Matcher::prefix(
                "ssh-keyscan",
                ["-t", "ed25519", "-p", &target.port.to_string()],
            ),
            reply,
        )
    }

    /// The vector above, through the code that has to agree with
    /// `ssh-keygen -lf`.
    #[test]
    fn the_fingerprint_is_the_one_ssh_keygen_prints() {
        let scanned = parse_keyscan(&format!("10.0.0.11 ssh-ed25519 {BLOB}\n"), "n1").unwrap();
        assert_eq!(scanned.fingerprint, FINGERPRINT);
        assert_eq!(scanned.keytype, "ssh-ed25519");
    }

    #[test]
    fn a_banner_line_is_not_a_key() {
        let err = parse_keyscan("# 10.0.0.11:22 SSH-2.0-OpenSSH_10.0\n", "n1").unwrap_err();
        assert!(err.to_string().contains("nothing at n1 answered"), "{err}");
    }

    /// A host that offers only rsa is a host this fleet does not enrol, and
    /// the sentence says which key type was wanted.
    #[test]
    fn another_key_type_is_not_the_one_that_was_asked_for() {
        let err = parse_keyscan("10.0.0.11 ssh-rsa AAAAB3NzaC1yc2E=\n", "n1").unwrap_err();
        assert!(err.to_string().contains("ssh-ed25519"), "{err}");
    }

    #[test]
    fn a_matching_fingerprint_writes_the_line() {
        let target = target();
        let runner = fake(&target, scan_reply("10.0.0.11"));
        let files = MemFiles::new();
        let done = enroll(
            &runner,
            &files,
            Path::new("/repo/known_hosts"),
            &target,
            FINGERPRINT,
            false,
            None,
            crate::fixtures::at("2026-09-22T09:00:00Z"),
        )
        .unwrap();
        runner.verify().unwrap();
        assert!(done.changed);
        assert_eq!(done.fingerprint, FINGERPRINT);
        assert_eq!(done.toml_line, format!("ssh.host_key = \"{FINGERPRINT}\""));
        let written = String::from_utf8(files.content("/repo/known_hosts").unwrap()).unwrap();
        assert_eq!(written, format!("10.0.0.11 ssh-ed25519 {BLOB}\n"));
    }

    /// The whole of D10 in one test: the machine answers, and it is not the
    /// machine whose console was read.
    #[test]
    fn a_different_key_is_refused_and_both_are_named() {
        let target = target();
        let runner = fake(
            &target,
            Output::stdout(format!("10.0.0.11 ssh-ed25519 {OTHER_BLOB}\n")),
        );
        let files = MemFiles::new();
        let err = enroll(
            &runner,
            &files,
            Path::new("/repo/known_hosts"),
            &target,
            FINGERPRINT,
            false,
            None,
            crate::fixtures::at("2026-09-22T09:00:00Z"),
        )
        .unwrap_err();
        let said = err.to_string();
        assert!(said.contains("is not the one you typed"), "{said}");
        assert!(said.contains(FINGERPRINT), "the typed one is named: {said}");
        assert!(said.contains("somebody is between you"), "{said}");
        // And nothing was written.
        assert!(files.content("/repo/known_hosts").is_none(), "{said}");
    }

    #[test]
    fn a_host_that_answers_with_nothing_is_not_enrolled() {
        let target = target();
        let runner = fake(&target, Output::stdout(""));
        let files = MemFiles::new();
        let err = enroll(
            &runner,
            &files,
            Path::new("/repo/known_hosts"),
            &target,
            FINGERPRINT,
            false,
            None,
            crate::fixtures::at("2026-09-22T09:00:00Z"),
        )
        .unwrap_err();
        assert!(err.to_string().contains("nothing at n1 answered"), "{err}");
        assert!(files.content("/repo/known_hosts").is_none());
    }

    /// Twice is not a change: the second run reads the same line and writes
    /// nothing at all.
    #[test]
    fn a_host_that_is_already_in_there_is_already_enrolled() {
        let target = target();
        let runner = fake(&target, scan_reply("10.0.0.11"));
        let files = MemFiles::new().given(
            "/repo/known_hosts",
            format!("10.0.0.11 ssh-ed25519 {BLOB}\n"),
        );
        let done = enroll(
            &runner,
            &files,
            Path::new("/repo/known_hosts"),
            &target,
            FINGERPRINT,
            false,
            None,
            crate::fixtures::at("2026-09-22T09:00:00Z"),
        )
        .unwrap();
        runner.verify().unwrap();
        assert!(!done.changed);
        assert!(
            !files
                .attempts()
                .iter()
                .any(|a| a.starts_with("write") || a.starts_with("create")),
            "{:?}",
            files.attempts()
        );
    }

    #[test]
    fn another_key_for_a_host_that_is_in_there_needs_a_reason() {
        let target = target();
        let runner = fake(&target, scan_reply("10.0.0.11"));
        let files = MemFiles::new().given(
            "/repo/known_hosts",
            format!("10.0.0.11 ssh-ed25519 {OTHER_BLOB}\n"),
        );
        let err = enroll(
            &runner,
            &files,
            Path::new("/repo/known_hosts"),
            &target,
            FINGERPRINT,
            false,
            None,
            crate::fixtures::at("2026-09-22T09:00:00Z"),
        )
        .unwrap_err();
        let said = err.to_string();
        assert!(said.contains("already carries another key"), "{said}");
        assert!(said.contains("--replace --reason"), "{said}");
        assert!(
            files.content("/repo/known_hosts").unwrap()
                == format!("10.0.0.11 ssh-ed25519 {OTHER_BLOB}\n").into_bytes()
        );
    }

    #[test]
    fn replacing_without_a_reason_is_refused() {
        let target = target();
        let runner = fake(&target, scan_reply("10.0.0.11"));
        let files = MemFiles::new().given(
            "/repo/known_hosts",
            format!("10.0.0.11 ssh-ed25519 {OTHER_BLOB}\n"),
        );
        let err = enroll(
            &runner,
            &files,
            Path::new("/repo/known_hosts"),
            &target,
            FINGERPRINT,
            true,
            None,
            crate::fixtures::at("2026-09-22T09:00:00Z"),
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("--replace without --reason"),
            "{err}"
        );
    }

    /// The other hosts' lines come back byte for byte, the reason is in the
    /// file, and the new line is the only new thing.
    #[test]
    fn a_replacement_keeps_every_other_host_and_says_why() {
        let target = target();
        let runner = fake(&target, scan_reply("10.0.0.11"));
        let before = format!(
            "# the fleet\n10.0.0.10 ssh-ed25519 {OTHER_BLOB}\n\
             10.0.0.11 ssh-ed25519 {OTHER_BLOB}\n10.0.0.12 ssh-ed25519 {BLOB}\n"
        );
        let files = MemFiles::new().given("/repo/known_hosts", before);
        let done = enroll(
            &runner,
            &files,
            Path::new("/repo/known_hosts"),
            &target,
            FINGERPRINT,
            true,
            Some("n1 was reinstalled from the installer medium"),
            crate::fixtures::at("2026-09-22T09:00:00Z"),
        )
        .unwrap();
        runner.verify().unwrap();
        assert!(done.changed);
        let written = String::from_utf8(files.content("/repo/known_hosts").unwrap()).unwrap();
        assert_eq!(
            written,
            format!(
                "# the fleet\n10.0.0.10 ssh-ed25519 {OTHER_BLOB}\n\
                 10.0.0.12 ssh-ed25519 {BLOB}\n\
                 # replaced 2026-09-22T09:00:00Z n1 was reinstalled from the installer medium\n\
                 10.0.0.11 ssh-ed25519 {BLOB}\n"
            )
        );
    }

    /// A host that is not on port 22 is `[address]:port` in the file and in
    /// the scan, and the two have to be the same host.
    #[test]
    fn a_host_on_another_port_is_named_the_way_ssh_names_it() {
        let target = Target::new("n1", "10.0.0.11", 2222, "root");
        let runner = fake(&target, scan_reply("[10.0.0.11]:2222"));
        let files = MemFiles::new();
        let done = enroll(
            &runner,
            &files,
            Path::new("/repo/known_hosts"),
            &target,
            FINGERPRINT,
            false,
            None,
            crate::fixtures::at("2026-09-22T09:00:00Z"),
        )
        .unwrap();
        runner.verify().unwrap();
        assert_eq!(done.known_hosts_name, "[10.0.0.11]:2222");
        let written = String::from_utf8(files.content("/repo/known_hosts").unwrap()).unwrap();
        assert_eq!(written, format!("[10.0.0.11]:2222 ssh-ed25519 {BLOB}\n"));
        // And the scan asked for that port.
        assert!(
            runner.calls()[0].contains("-p 2222"),
            "{:?}",
            runner.calls()
        );
    }

    #[test]
    fn a_dry_run_scans_and_writes_nothing() {
        let target = target();
        let runner = StrictFake::new().with_policy(Policy::dry_run()).expect(
            Matcher::prefix("ssh-keyscan", ["-t"]),
            scan_reply("10.0.0.11"),
        );
        let files = MemFiles::new().with_policy(Policy::dry_run());
        let err = enroll(
            &runner,
            &files,
            Path::new("/repo/known_hosts"),
            &target,
            FINGERPRINT,
            false,
            None,
            crate::fixtures::at("2026-09-22T09:00:00Z"),
        )
        .unwrap_err();
        // The scan happened — it is a read — and the write is the thing the
        // policy stopped, at the door rather than at the call site.
        assert!(err.to_string().contains("--dry-run"), "{err}");
        assert!(files.content("/repo/known_hosts").is_none());
    }

    #[test]
    fn offline_asks_nobody() {
        let target = target();
        let runner = StrictFake::new().with_policy(Policy::offline());
        let files = MemFiles::new().with_policy(Policy::offline());
        let err = enroll(
            &runner,
            &files,
            Path::new("/repo/known_hosts"),
            &target,
            FINGERPRINT,
            false,
            None,
            crate::fixtures::at("2026-09-22T09:00:00Z"),
        )
        .unwrap_err();
        assert!(err.to_string().contains("--offline"), "{err}");
        runner.verify().unwrap();
    }

    #[test]
    fn a_fingerprint_that_is_not_one_is_refused_before_anything_is_asked() {
        let target = target();
        let runner = StrictFake::new();
        let files = MemFiles::new();
        for typed in ["", "abc", "MD5:aa:bb", "SHA256:"] {
            let err = enroll(
                &runner,
                &files,
                Path::new("/repo/known_hosts"),
                &target,
                typed,
                false,
                None,
                crate::fixtures::at("2026-09-22T09:00:00Z"),
            )
            .unwrap_err();
            assert!(
                err.to_string().contains("SHA256:") || err.to_string().contains("nothing after"),
                "{typed:?}: {err}"
            );
        }
        // Nobody was asked anything.
        assert!(runner.calls().is_empty(), "{:?}", runner.calls());
        runner.verify().unwrap();
    }

    /// A person pasting from a terminal should not have to know that openssh
    /// leaves the base64 padding off.
    #[test]
    fn padding_a_person_pasted_is_not_a_different_key() {
        let target = target();
        let runner = fake(&target, scan_reply("10.0.0.11"));
        let files = MemFiles::new();
        enroll(
            &runner,
            &files,
            Path::new("/repo/known_hosts"),
            &target,
            &format!("{FINGERPRINT}="),
            false,
            None,
            crate::fixtures::at("2026-09-22T09:00:00Z"),
        )
        .unwrap();
        runner.verify().unwrap();
    }

    #[test]
    fn where_a_host_is_reached_comes_from_the_inventory() {
        let text = include_str!("../tests/fixtures/fleet-v2.toml");
        let inventory = crate::inventory::Inventory::parse(text, "fleet.toml").unwrap();
        let first = inventory.hosts.keys().next().unwrap().clone();
        let target = target_from_inventory(&inventory, &first).unwrap();
        assert_eq!(target.host_id, first);
        assert!(!target.address.is_empty());
        let err = target_from_inventory(&inventory, "nobody").unwrap_err();
        assert!(err.to_string().contains("no host \"nobody\""), "{err}");
    }
}
