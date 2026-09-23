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

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use chrono::{DateTime, Utc};

use crate::activate::KeygenOutcome;
use crate::effects::Files;
use crate::manifest::ResolvedHost;

/// Reading a certificate request — the one piece of X.509 this module does
/// itself, and it does it through the crate the controllers use.
///
/// The signature check is the point: it proves the sender holds the private
/// half of the key it asks to have certified. Without it, anybody could
/// submit somebody else's public key under their own name and have this CA
/// vouch for a key they do not have.
pub use ::pki::requested_name;

use crate::run::{Cmd, Effect, Expect, Runner};
use crate::transport::{Ssh, Target, fingerprint_of};

/// Where a request waits for the CA, relative to the operator's repository.
/// Public and committed: a request is a public key and a name.
pub const CSR_DIR: &str = "pki/csr";

/// Where an issued certificate lands, relative to the operator's repository.
/// Also public, also committed — a certificate is what an operator wants to
/// see in a diff.
pub const ISSUED_DIR: &str = "pki/issued";

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

// ---------------------------------------------------------------------------
// Where the operator's own files are
// ---------------------------------------------------------------------------

/// Where a request for this host and this file waits for the CA.
pub fn csr_path(repo: &Path, host_id: &str, kind: &str) -> PathBuf {
    repo.join(CSR_DIR).join(format!("{host_id}-{kind}.csr"))
}

/// Where the certificate for this host lands.
pub fn issued_path(repo: &Path, host_id: &str, file: &str) -> PathBuf {
    repo.join(ISSUED_DIR).join(host_id).join(file)
}

// --- lane 5A ---------------------------------------------------------------

/// The fleet's revocation list, in the operator's repository.
///
/// Public and committed, like `known_hosts` and like every issued
/// certificate: a list of serials is a statement about what is no longer
/// valid, and keeping it secret would only keep it from the people who have
/// to check it.
pub const CRL_FILE: &str = "pki/crl.pem";

pub fn crl_path(repo: &Path) -> PathBuf {
    repo.join(CRL_FILE)
}

/// How long `meister-ca` may take over a revocation. openssl on two small
/// files.
pub const CA_DEADLINE: Duration = Duration::from_secs(120);

/// `meister-ca --dir <ca> --index-rebuild --revoke <what> [--reason <r>]`.
///
/// The rebuild travels with every revocation on purpose: it is additive and
/// cheap, and a revocation against a certificate that has no row in the
/// index would otherwise be a refusal an operator has to translate.
pub fn revoke_cmd(meister_ca: &Path, ca_dir: &Path, what: &str, reason: Option<&str>) -> Cmd {
    let mut cmd = Cmd::new(
        // It uses the CA key to say something and makes no key: the `key`
        // class, the same as signing.
        Effect::Key,
        meister_ca.display().to_string(),
        CA_DEADLINE,
    )
    .arg("--dir")
    .arg(ca_dir.display().to_string())
    .arg("--index-rebuild")
    .arg("--revoke")
    .arg(what);
    if let Some(reason) = reason {
        cmd = cmd.arg("--reason").arg(reason);
    }
    cmd
}

/// `meister-ca --dir <ca> --index-rebuild --gencrl`.
pub fn gencrl_cmd(meister_ca: &Path, ca_dir: &Path) -> Cmd {
    Cmd::new(Effect::Key, meister_ca.display().to_string(), CA_DEADLINE)
        .arg("--dir")
        .arg(ca_dir.display().to_string())
        .arg("--index-rebuild")
        .arg("--gencrl")
}

/// `openssl crl -in <file> -noout -crlnumber -lastupdate -nextupdate`, for
/// the sentence a revocation prints.
pub fn crl_describe_cmd(openssl: &str, crl: &Path) -> Cmd {
    Cmd::new(Effect::Offline, openssl, Duration::from_secs(30))
        .arg("crl")
        .arg("-in")
        .arg(crl.display().to_string())
        .arg("-noout")
        .arg("-crlnumber")
        .arg("-lastupdate")
        .arg("-nextupdate")
}

/// What a certificate this fleet issued for `host` is called on disk.
///
/// `keys issue` writes `<repo>/pki/issued/<host>/<file>.crt`, one per kind.
/// A revocation of a HOST is a revocation of all of them: an identity and a
/// serving certificate are the same machine's two credentials.
pub fn issued_certs(files: &dyn Files, repo: &Path, host_id: &str) -> Vec<PathBuf> {
    let dir = repo.join(ISSUED_DIR).join(host_id);
    let mut out: Vec<PathBuf> = files
        .list_dir(&dir)
        .unwrap_or_default()
        .into_iter()
        .filter(|p| p.extension().is_some_and(|e| e == "crt"))
        .collect();
    out.sort();
    out
}
// --- end lane 5A -----------------------------------------------------------

/// The directory `tools/meister-ca` keeps the CA in, as the inventory names
/// it.
///
/// Relative to the inventory FILE THAT WAS READ — which is what
/// `[operator] ca_dir = "../labpki"` means, and what every other reference
/// in that table means. The file and not the repository, because
/// `--inventory <somewhere else>` is a real flag and a relative reference in
/// a file hangs off that file.
pub fn ca_dir(inventory_file: &Path, named: &str) -> PathBuf {
    let named = Path::new(named);
    if named.is_absolute() {
        return named.to_path_buf();
    }
    let base = inventory_file.parent().unwrap_or(Path::new("."));
    normalise(&base.join(named))
}

/// `a/b/../c` -> `a/c`, without asking the filesystem.
///
/// The path is printed in error messages and compared against the
/// repository below; `..` left in makes both of those unreadable, and
/// `canonicalize` would be a file system call in a module that has a door
/// for those.
fn normalise(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for part in path.components() {
        match part {
            std::path::Component::ParentDir => {
                if !out.pop() {
                    out.push("..");
                }
            }
            std::path::Component::CurDir => {}
            other => out.push(other),
        }
    }
    out
}

/// Refuse a CA directory inside the repository.
///
/// The repository is committed; the CA key is the one file of this fleet
/// that must never be. `.gitignore` would be the other answer and it is one
/// edit away from being wrong — this is the answer that cannot be forgotten.
pub fn refuse_ca_in_repo(repo: &Path, ca: &Path) -> Result<()> {
    if ca.starts_with(repo) {
        bail!(
            "the CA directory {} is inside the operator repository {}. That repository is \
             committed, and `ca.key` is the one file of this fleet that must not be. Put it \
             beside the repository — `[operator] ca_dir = \"../labpki\"` — and nothing else \
             has to be remembered.",
            ca.display(),
            repo.display()
        );
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Subjects
// ---------------------------------------------------------------------------

/// Which identity the CA is being asked to certify.
///
/// The four `tools/meister-ca` knows, and the names are its names: this enum
/// is what `--kind` is spelled with on both sides.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaKind {
    /// `CN=system:node:<host id>`, `O=system:nodes`. An agent.
    Node,
    /// `CN=system:cluster:<group>`, `O=system:clusters`.
    Cluster,
    /// `CN=system:cloud:<group>`, `O=system:clouds`.
    Cloud,
    /// `CN=<host name>`, `O=system:controllers`, with SANs. What a client
    /// checks THIS ADDRESS against.
    Serving,
}

impl CaKind {
    pub fn as_str(self) -> &'static str {
        match self {
            CaKind::Node => "node",
            CaKind::Cluster => "cluster",
            CaKind::Cloud => "cloud",
            CaKind::Serving => "serving",
        }
    }

    pub fn parse(text: &str) -> Result<CaKind> {
        match text {
            "node" => Ok(CaKind::Node),
            "cluster" => Ok(CaKind::Cluster),
            "cloud" => Ok(CaKind::Cloud),
            "serving" => Ok(CaKind::Serving),
            other => bail!(
                "{other:?} is not a certificate kind. This tool knows: node, cluster, cloud, \
                 serving."
            ),
        }
    }

    /// Whether this kind belongs in `identity.crt` or in `serving.crt`.
    pub fn file_stem(self) -> &'static str {
        match self {
            CaKind::Serving => "serving",
            _ => "identity",
        }
    }
}

impl std::fmt::Display for CaKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.pad(self.as_str())
    }
}

/// The subject this fleet would put on a certificate of that kind for that
/// host, and the name `meister-ca` needs to build it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Subject {
    pub kind: CaKind,
    /// What goes into `--name`.
    pub name: String,
    /// The common name, which is what a request asks for and what the far
    /// end compares a Hello against (`controller-api::Identity::may_speak_for`).
    pub cn: String,
    /// The whole distinguished name, for a person to read.
    pub dn: String,
    /// The SANs a serving certificate gets. Empty for the client kinds.
    pub sans: Vec<String>,
}

/// Which identity a host's `identity.key` is for, from its roles.
///
/// A host with one of the three roles has one answer. A host that carries
/// several has several, and the fleet still gives it ONE `identity.key`:
/// `nix/controllers.nix` names `${pki.dir}/identity.crt` for the cloud tier
/// AND for the cluster tier, and `nix/agent.nix` names the same file as the
/// agent's `controller_cert`. So it holds one service identity, and which
/// one is the operator's decision — this returns the candidates rather than
/// guessing. Guessing would sign the wrong tier's name onto the key a
/// controller dials with, and the far end would refuse the Hello with a
/// name nobody typed.
pub fn identity_kinds(host: &ResolvedHost) -> Vec<CaKind> {
    let mut out = Vec::new();
    if host.roles.iter().any(|r| r == "cloud") {
        out.push(CaKind::Cloud);
    }
    if host.roles.iter().any(|r| r == "cluster") {
        out.push(CaKind::Cluster);
    }
    // The agent reads the SAME two files (`nix/agent.nix` names
    // `${pki.dir}/identity.crt` as its `controller_cert`), so a host that
    // carries an agent beside a controller is a third candidate and not a
    // fourth file.
    if host.roles.iter().any(|r| r == "agent") {
        out.push(CaKind::Node);
    }
    out
}

/// The name of the tier a controller host belongs to.
///
/// The same rule `nix/lib/inventory.nix` renders `MEISTER_CLOUD_NAME` and
/// `MEISTER_CLUSTER_NAME` with: the host's raft group, or the host id when
/// it is in none. What the fleet actually rendered wins where it is there,
/// because that is the name the far end will compare against.
pub fn tier_name(
    fleet: &crate::manifest::ResolvedFleet,
    host_id: &str,
    kind: CaKind,
) -> Result<String> {
    let host = fleet
        .hosts
        .get(host_id)
        .ok_or_else(|| anyhow::anyhow!("there is no host {host_id:?} in this manifest."))?;
    let rendered = match kind {
        CaKind::Cloud => host
            .effective_settings
            .cloud
            .as_ref()
            .and_then(|c| c.get("cloud_name")),
        CaKind::Cluster => host
            .effective_settings
            .cluster
            .as_ref()
            .and_then(|c| c.get("cluster_name")),
        _ => None,
    };
    if let Some(name) = rendered.and_then(|v| v.as_str()) {
        return Ok(name.to_string());
    }
    let raft = host.groups.iter().find(|g| {
        fleet
            .groups
            .get(*g)
            .is_some_and(|group| group.kind == crate::manifest::GroupKind::Raft)
    });
    Ok(raft.cloned().unwrap_or_else(|| host_id.to_string()))
}

/// What this fleet would have the CA write, for this host and this kind.
pub fn subject_for(
    fleet: &crate::manifest::ResolvedFleet,
    host_id: &str,
    kind: CaKind,
    extra_sans: &[String],
) -> Result<Subject> {
    let host = fleet
        .hosts
        .get(host_id)
        .ok_or_else(|| anyhow::anyhow!("there is no host {host_id:?} in this manifest."))?;
    let (name, cn, organisation) = match kind {
        CaKind::Node => (
            host_id.to_string(),
            format!("system:node:{host_id}"),
            "system:nodes",
        ),
        CaKind::Cluster => {
            let name = tier_name(fleet, host_id, kind)?;
            let cn = format!("system:cluster:{name}");
            (name, cn, "system:clusters")
        }
        CaKind::Cloud => {
            let name = tier_name(fleet, host_id, kind)?;
            let cn = format!("system:cloud:{name}");
            (name, cn, "system:clouds")
        }
        CaKind::Serving => (host.name.clone(), host.name.clone(), "system:controllers"),
    };
    let dn = format!("CN={cn}, O={organisation}");
    let mut sans: Vec<String> = Vec::new();
    if kind == CaKind::Serving {
        // What a client will have typed: the name the machine calls itself,
        // and the address the fleet reaches it at. Both, because both are
        // used — `cloud_addrs` is an address and a browser is a name.
        sans.push(host.name.clone());
        sans.push(host.address.clone());
        for san in extra_sans {
            if !sans.iter().any(|s| s == san) {
                sans.push(san.clone());
            }
        }
        sans.dedup();
    } else if !extra_sans.is_empty() {
        bail!(
            "a {kind} certificate carries no subject alternative names: it is a CLIENT \
             certificate, and what it is checked on is its CN. Only `--kind serving` takes \
             --san."
        );
    }
    Ok(Subject {
        kind,
        name,
        cn,
        dn,
        sans,
    })
}

// ---------------------------------------------------------------------------
// The request, made on the target
// ---------------------------------------------------------------------------

/// How long the helper's `keygen` may take over ssh. Generating a P-256 key
/// is instant; the deadline is for the connection.
pub const KEYGEN_DEADLINE: Duration = Duration::from_secs(60);

/// `meister-activate keygen`, over ssh.
///
/// [`Effect::TargetWrite`] and not [`Effect::Read`], because a file can come
/// into existence on the far side. It is the mildest target write there is —
/// nothing that runs is restarted, and an existing key is left exactly as it
/// is — but calling it a read would make `--dry-run` do it.
pub fn keygen_cmd(ssh: &Ssh, target: &Target, subject: &str, file: &str, replace: bool) -> Cmd {
    let mut argv = vec![
        "meister-activate".to_string(),
        "--json".to_string(),
        "keygen".to_string(),
        "--subject".to_string(),
        subject.to_string(),
        "--kind".to_string(),
        file.to_string(),
    ];
    if replace {
        argv.push("--replace".to_string());
    }
    ssh.exec(target, argv, Effect::TargetWrite, KEYGEN_DEADLINE)
}

/// What the helper answered, read back as the helper's own type.
///
/// `meister_deploy::activate::KeygenOutcome` and not a second struct beside
/// it: the two ends of this pipe are the same crate, and a copy of a
/// contract is a copy that drifts. The same decision `status --json` was
/// made under (2A/2C).
pub fn parse_keygen(text: &str, host_id: &str) -> Result<KeygenOutcome> {
    let reply: KeygenOutcome = serde_json::from_str(text.trim()).with_context(|| {
        format!("meister-activate keygen on {host_id} did not answer with the json this tool reads")
    })?;
    if !reply.csr_pem.contains("BEGIN CERTIFICATE REQUEST") {
        bail!("meister-activate keygen on {host_id} answered without a certificate request in it.");
    }
    // The one thing that must never come back. Checked rather than trusted:
    // this string is about to be written into a file in a repository
    // somebody commits.
    if reply.csr_pem.contains("PRIVATE KEY") {
        bail!(
            "meister-activate keygen on {host_id} answered with something that contains a \
             PRIVATE KEY. Nothing was written. A request is a public key and a name; if what \
             runs on that host sends a key, it is not the helper this tool speaks to."
        );
    }
    Ok(reply)
}

// ---------------------------------------------------------------------------
// The CA
// ---------------------------------------------------------------------------

/// How long `tools/meister-ca --sign-csr` may take. It is openssl on a
/// small file.
pub const SIGN_DEADLINE: Duration = Duration::from_secs(60);

/// `tools/meister-ca --dir <ca> --sign-csr <file> --kind <k> --name <n>`.
pub fn sign_cmd(
    meister_ca: &Path,
    ca_dir: &Path,
    csr: &Path,
    subject: &Subject,
    out: &Path,
    days: Option<u32>,
) -> Cmd {
    let mut cmd = Cmd::new(
        // It makes no key and it moves none; what it does is use the CA key
        // to say something. That is the `key` class, and an `--offline` run
        // is allowed to do it — signing a request needs nothing but this
        // machine.
        Effect::Key,
        meister_ca.display().to_string(),
        SIGN_DEADLINE,
    )
    .arg("--dir")
    .arg(ca_dir.display().to_string())
    .arg("--sign-csr")
    .arg(csr.display().to_string())
    .arg("--kind")
    .arg(subject.kind.as_str())
    .arg("--name")
    .arg(&subject.name)
    .arg("--out")
    .arg(out.display().to_string());
    if !subject.sans.is_empty() {
        cmd = cmd.arg("--san").arg(subject.sans.join(","));
    }
    if let Some(days) = days {
        cmd = cmd.arg("--days").arg(days.to_string());
    }
    cmd
}

/// What a certificate on disk says, without opening it with a parser of our
/// own: `openssl x509` is already the tool that signed it.
pub fn describe_cmd(openssl: &str, crt: &Path) -> Cmd {
    Cmd::new(Effect::Offline, openssl, Duration::from_secs(30))
        .arg("x509")
        .arg("-in")
        .arg(crt.display().to_string())
        .arg("-noout")
        .arg("-serial")
        .arg("-subject")
        .arg("-enddate")
        .arg("-fingerprint")
        .arg("-sha256")
}

/// The four fields `keys issue` prints, out of what `openssl x509` said.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize)]
pub struct Issued {
    pub serial: Option<String>,
    pub subject: Option<String>,
    pub not_after: Option<String>,
    pub sha256: Option<String>,
    pub path: String,
}

pub fn parse_describe(text: &str, path: &str) -> Issued {
    let mut issued = Issued {
        path: path.to_string(),
        ..Issued::default()
    };
    for line in text.lines() {
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let value = value.trim().to_string();
        match key.trim() {
            "serial" => issued.serial = Some(value),
            "subject" => issued.subject = Some(value),
            "notAfter" => issued.not_after = Some(value),
            k if k.starts_with("sha256 Fingerprint") || k == "SHA256 Fingerprint" => {
                issued.sha256 = Some(value)
            }
            _ => {}
        }
    }
    issued
}

// ---------------------------------------------------------------------------
// What should be on a host, so that the planner can compare it with what is
// ---------------------------------------------------------------------------

/// What `deliver-secret` would put on a host, by `secret_refs[].id`.
///
/// A digest for a file that may be hashed — a certificate, a CA bundle, a
/// CRL — and the word `present` for one that may not. The planner compares
/// this with [`crate::observation::HostObservation::credentials`], which the
/// read-only probe fills the same way round (2A): `sha256:<hex>` for the
/// public files, `mode:… owner:…` for the private ones.
///
/// So a public file is compared by CONTENT and a private one only by
/// existence, and that asymmetry is deliberate: the digest of a private key
/// is a digest of a private key, and it would travel into a journal, a
/// receipt and whatever ticket the receipt is attached to.
pub type ExpectedCredentials = BTreeMap<String, String>;

/// The word for a secret that is there and whose content nobody compares.
pub const PRESENT: &str = "present";

/// Where the local half of one secret reference lives, or `None` when there
/// is no local half at all.
///
/// Three sources, three answers (`nix/lib/manifest.nix` writes them):
///
/// * `operator-file` — the ref IS a path, relative to the inventory file:
///   `[operator] ca_dir = "../labpki"` makes `ca.crt` into `../labpki/ca.crt`.
/// * `meister-ca` — what `keys issue` wrote, under the repository, named
///   after the file it becomes on the target. Named after the FILE and not
///   after the kind, because a host that carries two controller tiers has
///   one `identity.crt` and two secret references to it.
/// * `target-generated` — there is no local half, and there must not be.
pub fn local_source(
    repo: &Path,
    ca_dir: &Path,
    host_id: &str,
    secret: &crate::manifest::SecretRef,
) -> Option<PathBuf> {
    use crate::manifest::SecretSourceKind;
    match secret.source.kind {
        SecretSourceKind::TargetGenerated => None,
        SecretSourceKind::OperatorFile => {
            let named = Path::new(&secret.source.reference);
            Some(if named.is_absolute() {
                named.to_path_buf()
            } else {
                // The reference is written relative to the INVENTORY
                // (`../labpki/ca.crt`), and `ca_dir` was resolved from the
                // same place — so what is left of it is its file name under
                // that directory.
                //
                // The limit, said where it lives: only the last segment is
                // kept, so a reference into a SUBDIRECTORY of `ca_dir`
                // would be read flat. `nix/lib/manifest.nix` renders
                // exactly `${caDir}/<file>` today, so this is precise; a
                // deeper layout there needs a line here.
                match named.file_name() {
                    Some(file) => ca_dir.join(file),
                    None => repo.join(named),
                }
            })
        }
        // --- lane 5A ---
        // One list for the whole fleet, and it is not about this host: a
        // revocation list names certificates, not machines, and a copy per
        // host would be a directory of files that have to be equal and a
        // day when one of them is not.
        SecretSourceKind::MeisterCa if secret.kind == crate::manifest::SecretKind::Crl => {
            Some(crl_path(repo))
        }
        // --- end lane 5A ---
        SecretSourceKind::MeisterCa => Some(issued_path(
            repo,
            host_id,
            base_name(&secret.target_path).as_str(),
        )),
    }
}

/// The last path segment of a target path, which is the name the file has on
/// the host and the name it gets here.
pub fn base_name(path: &str) -> String {
    path.rsplit('/').next().unwrap_or(path).to_string()
}

/// What every secret of this host should be, read off the operator's disk.
///
/// A missing local file is not an error here: the planner turns it into a
/// blocked host with a sentence that names the verb to run
/// (`keys csr` / `keys issue`), which is more useful than a plan that
/// refuses to exist.
pub fn expected_for_host(
    files: &dyn Files,
    repo: &Path,
    ca_dir: &Path,
    host_id: &str,
    host: &ResolvedHost,
) -> ExpectedCredentials {
    let mut out = ExpectedCredentials::new();
    for secret in &host.secret_refs {
        let Some(path) = local_source(repo, ca_dir, host_id, secret) else {
            continue;
        };
        if !files.exists(&path) {
            continue;
        }
        if crate::observe::is_certificate(&secret.target_path) {
            match files.read(&path) {
                Ok(bytes) => {
                    out.insert(
                        secret.id.clone(),
                        format!("sha256:{}", crate::ids::sha256_hex(&bytes)),
                    );
                }
                // Unreadable is not "absent": leaving it out would make a
                // bootstrap say that nobody has issued a certificate that
                // is sitting right there. A word that is not a digest
                // never equals what the host reports, so the file is
                // planned for delivery — and the run then stops at the
                // read, with the path in the sentence. One step later than
                // a refusal, and about the right file either way.
                Err(_) => {
                    out.insert(secret.id.clone(), "unreadable".to_string());
                }
            }
        } else {
            // A private file: it is there, and that is all this says.
            out.insert(secret.id.clone(), PRESENT.to_string());
        }
    }
    out
}

/// The same for every host of a selection.
pub fn expected_credentials(
    files: &dyn Files,
    repo: &Path,
    ca_dir: &Path,
    fleet: &crate::manifest::ResolvedFleet,
    hosts: &[String],
) -> BTreeMap<String, ExpectedCredentials> {
    let mut out = BTreeMap::new();
    for id in hosts {
        let Some(host) = fleet.hosts.get(id) else {
            continue;
        };
        let expected = expected_for_host(files, repo, ca_dir, id, host);
        if !expected.is_empty() {
            out.insert(id.clone(), expected);
        }
    }
    out
}

/// When `deliver-secret` is what happens next, per secret.
///
/// The rule, and the whole of it:
///
/// * a file the target has not got -> deliver it;
/// * a PUBLIC file whose digest differs -> deliver it;
/// * a PRIVATE file that is there -> leave it alone, whatever it is. A
///   `secrets.key` on a cloud is the key its stored secrets were encrypted
///   with; replacing it does not rotate anything, it makes what is stored
///   unreadable. Rotation is `keys rotate` (M5) and it is a plan of its own.
/// * a key the target made itself -> never.
pub fn needs_delivery(
    secret: &crate::manifest::SecretRef,
    expected: Option<&String>,
    observed: Option<&Option<String>>,
) -> bool {
    use crate::manifest::SecretSourceKind;
    if secret.source.kind == SecretSourceKind::TargetGenerated {
        return false;
    }
    let Some(expected) = expected else {
        // Nothing local to deliver. The planner says so in its own sentence.
        return false;
    };
    match observed {
        // Not there, or the probe says it is not there.
        None | Some(None) => true,
        Some(Some(seen)) => {
            if expected == PRESENT {
                // It is there, and a private file that is there stays.
                false
            } else {
                seen != expected
            }
        }
    }
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

    // --- position 3: subjects, the request, the CA --------------------

    /// The four subjects, against `tools/meister-ca`'s own conventions
    /// (its header, lines 19-22).
    #[test]
    fn the_four_subjects_are_the_ones_the_ca_writes() {
        let fleet = crate::fixtures::onebox_enrolled();
        // box is cloud+cluster+agent, and its one raft group is `box`.
        let cloud = subject_for(&fleet, "box", CaKind::Cloud, &[]).unwrap();
        assert_eq!(cloud.cn, "system:cloud:box");
        assert_eq!(cloud.dn, "CN=system:cloud:box, O=system:clouds");
        assert_eq!(cloud.name, "box");
        assert!(cloud.sans.is_empty());

        let cluster = subject_for(&fleet, "box", CaKind::Cluster, &[]).unwrap();
        assert_eq!(cluster.dn, "CN=system:cluster:box, O=system:clusters");

        // A node is named after the HOST ID and nothing else: the cluster
        // checks this CN against the node_id in the agent's Hello.
        let node = subject_for(&fleet, "n1", CaKind::Node, &[]).unwrap();
        assert_eq!(node.dn, "CN=system:node:n1, O=system:nodes");
        assert_eq!(node.name, "n1");

        let serving = subject_for(&fleet, "box", CaKind::Serving, &[]).unwrap();
        assert_eq!(serving.dn, "CN=meister-box, O=system:controllers");
        // The name the machine calls itself AND the address the fleet
        // reaches it at: both are typed by somebody.
        assert!(
            serving.sans.contains(&"meister-box".to_string()),
            "{serving:?}"
        );
        assert!(
            serving.sans.contains(&"10.0.0.10".to_string()),
            "{serving:?}"
        );
    }

    #[test]
    fn a_client_certificate_takes_no_subject_alternative_name() {
        let fleet = crate::fixtures::onebox_enrolled();
        let err = subject_for(&fleet, "n1", CaKind::Node, &["extra".to_string()]).unwrap_err();
        assert!(err.to_string().contains("`--kind serving`"), "{err}");
        let extra = subject_for(
            &fleet,
            "box",
            CaKind::Serving,
            &["box.lab".to_string(), "meister-box".to_string()],
        )
        .unwrap();
        assert!(extra.sans.contains(&"box.lab".to_string()));
        assert_eq!(
            extra.sans.iter().filter(|s| *s == "meister-box").count(),
            1,
            "a name that is already in is not in twice: {extra:?}"
        );
    }

    /// The name of a tier is the raft group's, the way
    /// `nix/lib/inventory.nix` renders `MEISTER_CLUSTER_NAME` — and what
    /// the fleet ACTUALLY rendered wins where it is there, because that is
    /// the name the far end compares against.
    #[test]
    fn a_tier_is_named_after_its_raft_group_unless_the_fleet_said_otherwise() {
        let mut fleet = crate::fixtures::onebox_enrolled();
        assert_eq!(tier_name(&fleet, "box", CaKind::Cluster).unwrap(), "box");
        let host = fleet.hosts.get_mut("box").unwrap();
        host.effective_settings.cluster = Some(serde_json::json!({ "cluster_name": "cp-1" }));
        assert_eq!(tier_name(&fleet, "box", CaKind::Cluster).unwrap(), "cp-1");
        // A host in no raft group is named after itself.
        assert_eq!(tier_name(&fleet, "n1", CaKind::Cloud).unwrap(), "n1");
    }

    /// A host that carries two tiers has ONE identity.key, so it has one
    /// identity, and this tool says so rather than picking.
    #[test]
    fn which_identity_a_host_can_hold_comes_from_its_roles() {
        let fleet = crate::fixtures::onebox_enrolled();
        assert_eq!(
            identity_kinds(&fleet.hosts["box"]),
            vec![CaKind::Cloud, CaKind::Cluster, CaKind::Node]
        );
        assert_eq!(identity_kinds(&fleet.hosts["n1"]), vec![CaKind::Node]);
    }

    #[test]
    fn a_kind_that_does_not_exist_lists_the_four_that_do() {
        let err = CaKind::parse("admin").unwrap_err();
        assert!(
            err.to_string().contains("node, cluster, cloud, serving"),
            "{err}"
        );
        for name in ["node", "cluster", "cloud", "serving"] {
            assert_eq!(CaKind::parse(name).unwrap().as_str(), name);
        }
        assert_eq!(CaKind::Serving.file_stem(), "serving");
        assert_eq!(CaKind::Node.file_stem(), "identity");
    }

    /// What the helper answers with is the helper's own type, and a reply
    /// carrying a key is refused before it reaches a file.
    #[test]
    fn a_reply_that_carries_a_key_is_not_a_reply() {
        let good = serde_json::json!({
            "subject": "system:node:n1",
            "kind": "identity",
            "csr_pem": "-----BEGIN CERTIFICATE REQUEST-----\nAAAA\n-----END CERTIFICATE REQUEST-----\n",
            "public_key_sha256": "ab".repeat(32),
            "created": true,
        });
        let parsed = parse_keygen(&good.to_string(), "n1").unwrap();
        assert_eq!(parsed.subject, "system:node:n1");
        assert!(parsed.created);

        let mut bad = good.clone();
        bad["csr_pem"] = serde_json::json!(
            "-----BEGIN CERTIFICATE REQUEST-----\nA\n-----END CERTIFICATE REQUEST-----\n\n-----BEGIN PRIVATE KEY-----\nB\n-----END PRIVATE KEY-----\n"
        );
        let err = parse_keygen(&bad.to_string(), "n1").unwrap_err();
        assert!(err.to_string().contains("PRIVATE KEY"), "{err}");

        let mut empty = good;
        empty["csr_pem"] = serde_json::json!("nothing at all");
        let err = parse_keygen(&empty.to_string(), "n1").unwrap_err();
        assert!(
            err.to_string().contains("without a certificate request"),
            "{err}"
        );

        assert!(parse_keygen("not json", "n1").is_err());
    }

    /// The command that asks a host for a request: it names the subject
    /// this fleet decided on, and it is a target write.
    #[test]
    fn the_keygen_command_asks_for_the_subject_this_fleet_decided() {
        let ssh = Ssh::with_known_hosts("/repo/known_hosts");
        let target = Target::new("n1", "10.0.0.11", 22, "root");
        let cmd = keygen_cmd(&ssh, &target, "system:node:n1", "identity", false);
        assert_eq!(cmd.effect, Effect::TargetWrite);
        let line = cmd.line();
        assert!(line.contains("meister-activate --json keygen"), "{line}");
        assert!(line.contains("--subject system:node:n1"), "{line}");
        assert!(line.contains("--kind identity"), "{line}");
        assert!(!line.contains("--replace"), "{line}");
        assert!(line.contains("StrictHostKeyChecking=yes"), "{line}");
        let replacing = keygen_cmd(&ssh, &target, "system:node:n1", "identity", true);
        assert!(
            replacing.line().contains("--replace"),
            "{}",
            replacing.line()
        );
    }

    /// Signing is a `key` command: it needs no network, so `--offline` may
    /// do it, and `--dry-run` may not.
    #[test]
    fn signing_is_a_key_command_and_names_what_it_signs() {
        let subject = Subject {
            kind: CaKind::Serving,
            name: "meister-box".to_string(),
            cn: "meister-box".to_string(),
            dn: "CN=meister-box, O=system:controllers".to_string(),
            sans: vec!["meister-box".to_string(), "10.0.0.10".to_string()],
        };
        let cmd = sign_cmd(
            Path::new("/opt/meister-ca"),
            Path::new("/home/silas/labpki"),
            Path::new("/repo/pki/csr/box-serving.csr"),
            &subject,
            Path::new("/repo/pki/issued/box/serving.crt"),
            Some(90),
        );
        assert_eq!(cmd.effect, Effect::Key);
        let line = cmd.line();
        assert!(line.contains("--dir /home/silas/labpki"), "{line}");
        assert!(
            line.contains("--sign-csr /repo/pki/csr/box-serving.csr"),
            "{line}"
        );
        assert!(line.contains("--kind serving"), "{line}");
        assert!(line.contains("--name meister-box"), "{line}");
        assert!(line.contains("--san meister-box,10.0.0.10"), "{line}");
        assert!(line.contains("--days 90"), "{line}");
        // A dry run may not sign. There is no `--offline` on the verb at
        // all: signing needs nothing but this machine, so there is nothing
        // for that flag to refuse — and 1C's policy table, which says
        // `--offline` runs only `offline` commands, is not loosened for one
        // verb's convenience.
        assert!(Policy::dry_run().admits(Effect::Key).is_err());

        // A client certificate has no --san at all.
        let node = Subject {
            kind: CaKind::Node,
            name: "n1".to_string(),
            cn: "system:node:n1".to_string(),
            dn: "CN=system:node:n1, O=system:nodes".to_string(),
            sans: Vec::new(),
        };
        let line = sign_cmd(
            Path::new("meister-ca"),
            Path::new("/ca"),
            Path::new("/repo/pki/csr/n1-identity.csr"),
            &node,
            Path::new("/repo/pki/issued/n1/identity.crt"),
            None,
        )
        .line();
        assert!(!line.contains("--san"), "{line}");
        assert!(!line.contains("--days"), "{line}");
    }

    /// What `openssl x509` said, as four fields.
    #[test]
    fn the_four_fields_of_an_issued_certificate_are_read_back() {
        let text = "serial=6435C9C4A191566C
                    subject=CN=system:node:n1, O=system:nodes
                    notAfter=Dec 20 16:55:20 2026 GMT
                    sha256 Fingerprint=AB:CD:EF
";
        let issued = parse_describe(text, "/repo/pki/issued/n1/identity.crt");
        assert_eq!(issued.serial.as_deref(), Some("6435C9C4A191566C"));
        assert_eq!(
            issued.subject.as_deref(),
            Some("CN=system:node:n1, O=system:nodes")
        );
        assert_eq!(
            issued.not_after.as_deref(),
            Some("Dec 20 16:55:20 2026 GMT")
        );
        assert_eq!(issued.sha256.as_deref(), Some("AB:CD:EF"));
        // A field nobody printed is null and never a guess.
        let thin = parse_describe(
            "serial=01
",
            "x",
        );
        assert_eq!(thin.not_after, None);
    }

    /// `[operator] ca_dir` is relative to the INVENTORY, which is what
    /// every other reference in that table means.
    #[test]
    fn the_ca_directory_hangs_off_the_inventory_and_not_off_the_cwd() {
        assert_eq!(
            ca_dir(Path::new("/home/silas/fleet/fleet.toml"), "../labpki"),
            PathBuf::from("/home/silas/labpki")
        );
        assert_eq!(
            ca_dir(
                Path::new("/home/silas/fleet/etc/fleet.toml"),
                "../../labpki"
            ),
            PathBuf::from("/home/silas/labpki")
        );
        assert_eq!(
            ca_dir(Path::new("/home/silas/fleet/fleet.toml"), "/srv/ca"),
            PathBuf::from("/srv/ca")
        );
        // An inventory somewhere else entirely: `--inventory` is a flag, and
        // a relative reference in a file hangs off that file.
        assert_eq!(
            ca_dir(Path::new("/tmp/elsewhere/fleet.toml"), "../ca"),
            PathBuf::from("/tmp/ca")
        );
    }

    /// The CA key is the one file of this fleet that must not be committed,
    /// and a `.gitignore` is one edit away from being wrong.
    #[test]
    fn a_ca_inside_the_repository_is_refused() {
        let repo = Path::new("/home/silas/fleet");
        let err = refuse_ca_in_repo(repo, &repo.join("pki")).unwrap_err();
        assert!(err.to_string().contains("is committed"), "{err}");
        refuse_ca_in_repo(repo, Path::new("/home/silas/labpki")).unwrap();
    }

    // --- position 5: wanted against seen ------------------------------

    /// Where the local half of each kind of secret reference lives.
    #[test]
    fn each_source_says_where_its_local_half_is() {
        use crate::manifest::{Delivery, SecretKind, SecretRef, SecretSource, SecretSourceKind};
        let repo = Path::new("/home/silas/fleet");
        let ca = Path::new("/home/silas/labpki");
        let secret = |kind, source, reference: &str, target: &str| SecretRef {
            id: "x".to_string(),
            kind,
            source: SecretSource {
                kind: source,
                reference: reference.to_string(),
            },
            target_path: target.to_string(),
            owner: "meister".to_string(),
            mode: "0644".to_string(),
            delivery: Delivery::File,
            reload: None,
        };
        // A key the target made itself has no local half, and must not.
        assert_eq!(
            local_source(
                repo,
                ca,
                "n1",
                &secret(
                    SecretKind::IdentityKey,
                    SecretSourceKind::TargetGenerated,
                    "system:node:n1",
                    "/var/lib/meisterstack/pki/identity.key"
                )
            ),
            None
        );
        // The CA's own file: under `[operator] ca_dir`.
        assert_eq!(
            local_source(
                repo,
                ca,
                "n1",
                &secret(
                    SecretKind::CaBundle,
                    SecretSourceKind::OperatorFile,
                    "../labpki/ca.crt",
                    "/var/lib/meisterstack/pki/ca.crt"
                )
            ),
            Some(PathBuf::from("/home/silas/labpki/ca.crt"))
        );
        // What `keys issue` wrote: named after the FILE it becomes on the
        // host, so that a host with two controller tiers and two references
        // to one `identity.crt` has one local file.
        assert_eq!(
            local_source(
                repo,
                ca,
                "n1",
                &secret(
                    SecretKind::IdentityKey,
                    SecretSourceKind::MeisterCa,
                    "system:node:n1",
                    "/var/lib/meisterstack/pki/identity.crt"
                )
            ),
            Some(PathBuf::from(
                "/home/silas/fleet/pki/issued/n1/identity.crt"
            ))
        );
    }

    /// A public file by content, a private one by existence — and never the
    /// other way round.
    #[test]
    fn what_may_be_hashed_is_hashed_and_what_may_not_is_only_there() {
        let fleet = crate::fixtures::onebox_enrolled();
        let repo = Path::new("/home/silas/fleet");
        let ca = Path::new("/home/silas/labpki");
        let files = MemFiles::new()
            .given(
                "/home/silas/labpki/ca.crt",
                "a certificate authority
",
            )
            .given(
                "/home/silas/fleet/pki/issued/box/serving.key",
                "a key
",
            );
        let expected = expected_for_host(&files, repo, ca, "box", &fleet.hosts["box"]);
        assert_eq!(
            expected["ca-bundle"],
            format!(
                "sha256:{}",
                crate::ids::sha256_hex(b"a certificate authority\n")
            )
        );
        // The fixture's `serving` reference is a KEY. It is there, and that
        // is all this says about it: a digest of a private key would travel
        // into a journal and a receipt.
        assert_eq!(expected["serving"], PRESENT);
        assert!(expected.values().all(|v| !v.contains("a key")));
        // The identity key was made on the target and has no local half.
        assert!(!expected.contains_key("identity"), "{expected:?}");

        // n1 has the same fleet-wide CA file and nothing of its own: no
        // certificate has been issued for it, so there is nothing else to
        // compare and nothing else to deliver.
        let bare = expected_for_host(&files, repo, ca, "n1", &fleet.hosts["n1"]);
        assert_eq!(
            bare.keys().collect::<Vec<_>>(),
            vec!["ca-bundle"],
            "{bare:?}"
        );
        // And when the CA file is not there either, the answer is empty
        // rather than a guess.
        let nothing = expected_for_host(&MemFiles::new(), repo, ca, "n1", &fleet.hosts["n1"]);
        assert!(nothing.is_empty(), "{nothing:?}");
    }

    /// The whole rule, in one table.
    #[test]
    fn when_a_file_has_to_be_put_there_and_when_it_does_not() {
        use crate::manifest::{Delivery, SecretKind, SecretRef, SecretSource, SecretSourceKind};
        let make = |source, target: &str| SecretRef {
            id: "x".to_string(),
            kind: SecretKind::CaBundle,
            source: SecretSource {
                kind: source,
                reference: "r".to_string(),
            },
            target_path: target.to_string(),
            owner: "meister".to_string(),
            mode: "0644".to_string(),
            delivery: Delivery::File,
            reload: None,
        };
        let public = make(SecretSourceKind::OperatorFile, "/pki/ca.crt");
        let private = make(SecretSourceKind::OperatorFile, "/pki/secrets.key");
        let theirs = make(SecretSourceKind::TargetGenerated, "/pki/identity.key");

        let digest = "sha256:aaaa".to_string();
        let other = Some("sha256:bbbb".to_string());
        let present = PRESENT.to_string();
        let mode = Some("mode:600 owner:meister:meister".to_string());

        // Public: missing, different, same.
        assert!(needs_delivery(&public, Some(&digest), Some(&None)));
        assert!(needs_delivery(&public, Some(&digest), None));
        assert!(needs_delivery(&public, Some(&digest), Some(&other)));
        assert!(!needs_delivery(
            &public,
            Some(&digest),
            Some(&Some(digest.clone()))
        ));
        // Private: only when it is not there. A `secrets.key` that IS there
        // is the key the cloud encrypted with; replacing it does not rotate
        // anything.
        assert!(needs_delivery(&private, Some(&present), Some(&None)));
        assert!(!needs_delivery(&private, Some(&present), Some(&mode)));
        // A key the target made: never, whatever anybody thinks they have.
        assert!(!needs_delivery(&theirs, Some(&digest), Some(&None)));
        // Nothing local: nothing to deliver. The planner makes the sentence.
        assert!(!needs_delivery(&public, None, Some(&None)));
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
