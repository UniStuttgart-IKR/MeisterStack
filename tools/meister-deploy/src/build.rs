// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! `build`: make exist what the manifest promised, and nothing else.
//!
//! **It builds the derivations of the manifest, not the flake.** `resolve`
//! evaluated the operator's repository and wrote down the `.drv` path of
//! every system it named. Building those paths rather than re-evaluating
//! `<repo>#nixosConfigurations.<host>` is what makes a release a binding: a
//! derivation path IS the evaluation, so nothing between `resolve` and
//! `build` — a commit, a `flake update`, an edited profile, a changed
//! `$NIX_PATH` — can move what gets built. If a derivation is gone from the
//! store (a garbage collection between the two steps), the answer is to
//! resolve again, and the sentence says so; it is not to evaluate something
//! that might be different now.
//!
//! **Signatures are not optional.** M0's probe S12 measured it in two VMs: a
//! host with `nix.settings.require-sigs = true` refuses an unsigned closure
//! over `ssh-ng://`, root or not, and the only way round it would be the old
//! `ssh://` store — which is the pre-v1 path and throws away the guarantee
//! `require-sigs` exists for. `--no-check-sigs` is not a flag this tool has.
//! So a build that covers a managed host and has no signing key is an error
//! with a sentence, and every store path a release names carries at least
//! one signature by the time the release is written. The key's PATH is
//! redacted out of every line this tool prints; the key's NAME (the part
//! before the colon in the key file) goes into `build_env` because a target
//! has to be told which public key to trust.
//!
//! **A release is protected from the collector.** A closure that was built,
//! signed and named in a release, and then collected before `apply` ran, is
//! an afternoon of building for nothing. So each release gets a directory of
//! indirect garbage-collector roots under the state directory, and `gc
//! --keep N` is the one thing that removes them.
//!
//! What `build` does NOT do: evaluate anything, ask any host anything, build
//! an image (that is `image`, M3), or decide anything about the fleet. It
//! realises, it measures, it signs, and it hands the result to
//! [`crate::release::bind`], which refuses it if it is not what the manifest
//! asked for.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Result, bail};
use chrono::{DateTime, Utc};
use serde::Deserialize;

use crate::checks::{CheckResult, Evidence, EvidenceKind, Status, Subject};
use crate::effects::{Clock, Files};
use crate::ids::sha256_hex;
use crate::manifest::{Deployment, ResolvedFleet};
use crate::release::{
    BootArtifacts, BuildEnv, ConfigArtifact, HostArtifacts, PackageArtifact, ReleaseManifest,
    Reproducibility, StoreArtifact, bind,
};
use crate::run::{Cmd, Effect, Expect, Runner};
use crate::state::StateDir;

/// How long one derivation may take.
///
/// Four hours, because one of these derivations is a kernel and another is a
/// NixOS system closure of several gigabytes on a cold substituter — and
/// because the alternative to a generous deadline is an operator who wraps
/// this tool in `timeout` and gets a half-built store with no journal entry
/// about it. A build that has not finished in four hours has a problem a
/// longer wait will not solve.
pub const BUILD_DEADLINE: Duration = Duration::from_secs(4 * 3600);

/// Signing walks a closure and writes a signature per path. Minutes for a
/// fleet, not hours.
pub const SIGN_DEADLINE: Duration = Duration::from_secs(600);

/// Local store queries: `path-info`, `nix-store --add-root`.
pub const STORE_DEADLINE: Duration = Duration::from_secs(300);

/// `nix --version`, `nix config show <key>`.
pub const QUERY_DEADLINE: Duration = Duration::from_secs(30);

/// What kind of thing a derivation makes, which is what decides how its
/// result is recorded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DrvKind {
    /// A host's system closure.
    Toplevel,
    /// A package the fleet's units point at.
    Package,
    /// A check the manifest requires: it passes by building.
    Check,
    /// The kernel, the initrd and the command line of a host that boots
    /// `direct`, in one directory. Built here and not by `image`, because a
    /// direct-boot host cannot be started at all without it: it is part of
    /// the release the way a toplevel is, not an image somebody may want.
    DirectBoot,
}

/// One derivation this build will realise.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Derivation {
    /// The host id, the package name, or the check id.
    pub what: String,
    pub kind: DrvKind,
    pub drv: String,
}

/// What the operator asked for.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BuildOptions {
    /// The signing key file, from `--sign-key` or `[operator] signing_key`.
    pub sign_key: Option<PathBuf>,
    /// `--builders`, offered to nix in the order they were given.
    pub builders: Vec<String>,
    pub substituters: Vec<String>,
    /// `--max-jobs`, as a string because nix takes `auto` as well as a
    /// number. Passed on unread: what a sensible parallelism is on the
    /// machine that builds is that machine's question, not this tool's.
    pub max_jobs: Option<String>,
    /// `--option <name> <value>`, for the settings that have no flag of
    /// their own. Sorted, so that the release records them in one order and
    /// two runs with the same options produce the same `build_env`.
    pub options: BTreeMap<String, String>,
    /// Where this release's closures are pushed once they are signed:
    /// `file:///srv/cache`, an `s3://` bucket, an `ssh-ng://` store. A nix
    /// store url, handed to `nix copy --to` unread — which urls nix speaks
    /// is nix's question and not a list this tool keeps in step with it.
    pub cache: Option<String>,
    /// Build every host's system a second time and let nix compare, so that
    /// `reproducibility.bit_identical_verified` is a measurement rather than
    /// a hope. Expensive by construction: it is the whole fleet, twice.
    pub verify_reproducible: bool,
    /// Only these hosts. A build of part of a fleet is for looking at, not
    /// for releasing — see [`Builder::realise`].
    pub hosts: Option<Vec<String>>,
}

/// The derivations a build over these hosts would realise, in the order it
/// would realise them.
///
/// Pure, so that `--dry-run` prints exactly the list a real run builds and
/// not a description of it. Hosts first (they are what a rollout is about),
/// then the packages, then the checks.
pub fn derivations(resolved: &ResolvedFleet, hosts: &[String]) -> Vec<Derivation> {
    let mut out = Vec::new();
    for id in hosts {
        if let Some(host) = resolved.hosts.get(id) {
            out.push(Derivation {
                what: id.clone(),
                kind: DrvKind::Toplevel,
                drv: host.build.toplevel_drv.clone(),
            });
            // Right after its own system, because it is part of how that
            // system gets started rather than a thing beside it.
            if let Some(drv) = &host.build.direct_boot_drv {
                out.push(Derivation {
                    what: direct_boot_key(id),
                    kind: DrvKind::DirectBoot,
                    drv: drv.clone(),
                });
            }
        }
    }
    let packages = &resolved.packages;
    let mut named: Vec<(String, String)> = vec![
        (
            "meisterstack".to_string(),
            packages.meisterstack.drv.clone(),
        ),
        (
            "cloud-hypervisor".to_string(),
            packages.cloud_hypervisor.drv.clone(),
        ),
        ("guest-tiny".to_string(), packages.guest_tiny.drv.clone()),
    ];
    if let Some(leandro) = &packages.leandro {
        named.push(("leandro".to_string(), leandro.drv.clone()));
    }
    for (what, drv) in named {
        out.push(Derivation {
            what,
            kind: DrvKind::Package,
            drv,
        });
    }
    // A required check that IS a derivation passes by building. The other
    // entries name readiness checks — `units`, `session`, `mounts` — which
    // are about a running host and belong to `check`, not here.
    let mut seen: BTreeSet<String> = BTreeSet::new();
    for id in hosts {
        if let Some(host) = resolved.hosts.get(id) {
            for check in &host.checks.required {
                if check.ends_with(".drv") && seen.insert(check.clone()) {
                    out.push(Derivation {
                        what: check_id(check),
                        kind: DrvKind::Check,
                        drv: check.clone(),
                    });
                }
            }
        }
    }
    out
}

/// What a host's direct-boot bundle is keyed under in the outputs map. Not
/// the host id: that key is the toplevel's.
pub fn direct_boot_key(host: &str) -> String {
    format!("{host}-direct-boot")
}

/// The id a check derivation is recorded under: `/nix/store/<hash>-config-box.drv`
/// is the check `config-box`.
fn check_id(drv: &str) -> String {
    let name = drv.rsplit('/').next().unwrap_or(drv);
    let name = name.strip_suffix(".drv").unwrap_or(name);
    match name.split_once('-') {
        Some((_hash, rest)) => rest.to_string(),
        None => name.to_string(),
    }
}

/// What `nix path-info` says about one path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathInfo {
    pub store_path: String,
    pub nar_hash: String,
    pub nar_size: u64,
    pub closure_size: u64,
    pub signatures: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct RawPathInfo {
    #[serde(rename = "narHash")]
    nar_hash: Option<String>,
    #[serde(rename = "narSize")]
    nar_size: Option<u64>,
    #[serde(rename = "closureSize")]
    closure_size: Option<u64>,
    #[serde(default)]
    signatures: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct RawPathInfoV2 {
    #[serde(rename = "storeDir")]
    store_dir: String,
    info: BTreeMap<String, RawPathInfo>,
}

/// Read `nix path-info --json`, in either of the two shapes nix produces.
///
/// Version 1 is an object keyed by full store path. Version 2 (nix 2.35
/// asks for it and will one day only produce it) wraps the same objects in
/// `info`, keyed by base name, with the store directory beside them. Both
/// are read, because a tool that only understood one of them would break on
/// whichever nix the operator's workstation has.
pub fn parse_path_info(text: &str, origin: &str) -> Result<BTreeMap<String, PathInfo>> {
    let value: serde_json::Value = serde_json::from_str(text)
        .map_err(|e| anyhow::anyhow!("{origin} did not answer with json: {e}."))?;

    let entries: Vec<(String, RawPathInfo)> = if value.get("info").is_some() {
        let v2: RawPathInfoV2 = serde_json::from_value(value)
            .map_err(|e| anyhow::anyhow!("{origin} is not a path-info answer: {e}."))?;
        v2.info
            .into_iter()
            .map(|(name, info)| (format!("{}/{name}", v2.store_dir), info))
            .collect()
    } else {
        let v1: BTreeMap<String, RawPathInfo> = serde_json::from_value(value)
            .map_err(|e| anyhow::anyhow!("{origin} is not a path-info answer: {e}."))?;
        v1.into_iter().collect()
    };

    let mut out = BTreeMap::new();
    for (path, info) in entries {
        // A path-info entry without a nar hash is an entry about a path that
        // is not in the store. Guessing a hash here would put a guess in a
        // release.
        let Some(nar_hash) = info.nar_hash else {
            bail!(
                "{origin} says nothing about the contents of {path}; a release cannot name a \
                 path whose nar hash is unknown."
            );
        };
        out.insert(
            path.clone(),
            PathInfo {
                store_path: path,
                nar_hash,
                nar_size: info.nar_size.unwrap_or(0),
                closure_size: info.closure_size.unwrap_or(0),
                signatures: info.signatures,
            },
        );
    }
    Ok(out)
}

/// `nix build --no-link --print-out-paths <drv>^*`.
///
/// `^*` asks for every output of the derivation; `--no-link` because the
/// links this tool wants are the release's own garbage-collector roots and
/// not a `result` symlink in whatever directory somebody stood in.
pub fn build_cmd(drv: &str, options: &BuildOptions) -> Cmd {
    let mut cmd = Cmd::new(Effect::Build, "nix", BUILD_DEADLINE).args([
        "build",
        "--no-link",
        "--print-out-paths",
    ]);
    cmd = with_nix_options(cmd, options);
    cmd.arg(format!("{drv}^*"))
}

/// `nix build --no-link --json <drv1>^* <drv2>^* …`: the whole fleet, once.
///
/// One invocation and not one per derivation, and the reason is nix's
/// scheduler: seventy systems handed over separately are seventy build
/// graphs built one after the other, where one graph is seventy roots nix
/// schedules across `--max-jobs` and `--builders` at the same time and whose
/// shared dependencies — one kernel, one nixpkgs, one meisterstack — are
/// realised once by construction rather than found in the store seventy
/// times.
///
/// `--json` and not `--print-out-paths`, which is what the per-derivation
/// road used: with several installables the printed paths are a LIST, and
/// deciding which of seventy systems a path belongs to by its position in
/// that list would be a guess. The json answer names the `drvPath` beside
/// every output, so the mapping is nix's own statement.
pub fn build_many_cmd(drvs: &[String], options: &BuildOptions) -> Cmd {
    let cmd = Cmd::new(Effect::Build, "nix", BUILD_DEADLINE).args(["build", "--no-link", "--json"]);
    let cmd = with_nix_options(cmd, options);
    cmd.args(drvs.iter().map(|drv| format!("{drv}^*")))
}

/// The flags this tool hands nix untouched: where it may build, what it may
/// fetch from, how much at once, and whatever else the operator named.
///
/// Recorded in `build_env` as well, because a release built on a farm and a
/// release built on a laptop are the same release and the question "where
/// did this come from" still has an answer.
fn with_nix_options(cmd: Cmd, options: &BuildOptions) -> Cmd {
    let mut cmd = cmd;
    if !options.builders.is_empty() {
        cmd = cmd.args(["--builders".to_string(), options.builders.join(" ; ")]);
    }
    if !options.substituters.is_empty() {
        cmd = cmd.args(["--substituters".to_string(), options.substituters.join(" ")]);
    }
    if let Some(jobs) = &options.max_jobs {
        cmd = cmd.args(["--max-jobs".to_string(), jobs.clone()]);
    }
    for (name, value) in &options.options {
        cmd = cmd.args(["--option".to_string(), name.clone(), value.clone()]);
    }
    cmd
}

/// What one entry of `nix build --json` says.
#[derive(Debug, Deserialize)]
struct RawBuildResult {
    #[serde(rename = "drvPath")]
    drv_path: String,
    #[serde(default)]
    outputs: BTreeMap<String, String>,
}

/// Read `nix build --json`: derivation path -> the output paths it made.
pub fn parse_build_json(text: &str, origin: &str) -> Result<BTreeMap<String, Vec<String>>> {
    let results: Vec<RawBuildResult> = serde_json::from_str(text)
        .map_err(|e| anyhow::anyhow!("{origin} did not answer with a build result: {e}."))?;
    let mut out: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for result in results {
        // `outputs` is keyed by output NAME (`out`, `dev`, …) and the names
        // are sorted here so that a derivation with two of them is refused
        // with the same sentence twice rather than with whichever order nix
        // happened to answer in.
        let paths: Vec<String> = result.outputs.into_values().collect();
        out.entry(result.drv_path).or_default().extend(paths);
    }
    Ok(out)
}

/// `nix path-info --json --closure-size <paths…>`, of the local store.
pub fn path_info_cmd(paths: &[String]) -> Cmd {
    crate::nix::path_info_cmd(None, paths)
}

/// Whether these derivations are still in the store, as one question.
///
/// `AnyExit`, because "no" is the answer this is asked for.
pub fn drv_present_cmd(drvs: &[String]) -> Cmd {
    Cmd::new(Effect::Read, "nix", STORE_DEADLINE)
        .args(["path-info", "--json"])
        .args(drvs.iter().cloned())
        .expect(Expect::AnyExit)
}

/// `nix store sign --recursive --key-file <key> <paths…>`.
///
/// `--recursive`, so that every path in the closure carries a signature:
/// `nix copy` checks each path it transfers, not only the top of the tree.
/// The key path is redacted out of every printed form of this command.
pub fn sign_cmd(key: &std::path::Path, paths: &[String]) -> Cmd {
    let key = key.display().to_string();
    Cmd::new(Effect::Build, "nix", SIGN_DEADLINE)
        .args(["store", "sign", "--recursive", "--key-file"])
        .arg(key.clone())
        .args(paths.iter().cloned())
        .redact(key)
}

/// `nix build --rebuild --no-link <drv>^*`: build it AGAIN, on top of the
/// output that is already there, and let nix compare.
///
/// nix does the comparison itself and refuses with "may not be
/// deterministic: output … differs", which is a better answer than hashing
/// two nars here would be: nix knows which output of a multi-output
/// derivation differed and it knows what to do with a fixed-output one.
///
/// One derivation per call and not the whole fleet in one, which is the
/// opposite of [`build_many_cmd`] and deliberately so: what this produces is
/// a per-host VERDICT, and a batch that exited 1 would say "something in the
/// fleet differed" — the one thing an operator cannot act on.
pub fn rebuild_cmd(drv: &str, options: &BuildOptions) -> Cmd {
    let cmd =
        Cmd::new(Effect::Build, "nix", BUILD_DEADLINE).args(["build", "--rebuild", "--no-link"]);
    // `--builders` and `--substituters` on purpose, `--max-jobs` and the
    // operator's `--option`s too: the question is whether THIS build
    // environment produces the same bytes twice, so it has to be the same
    // build environment.
    let cmd = with_nix_options(cmd, options);
    cmd.arg(format!("{drv}^*")).expect(Expect::AnyExit)
}

/// What nix says when a rebuild came out different. Matched rather than
/// guessed at, because every other non-zero exit is a check that could not
/// be MADE — a builder that went away, a disk that filled — and reporting
/// that as "not reproducible" would be this tool inventing a finding.
const NOT_DETERMINISTIC: &str = "may not be deterministic";

/// How long pushing a fleet's closures into a cache may take. Seventy
/// system closures are tens of gigabytes of nar over whatever link the cache
/// is on.
pub const CACHE_DEADLINE: Duration = Duration::from_secs(2 * 3600);

/// `nix copy --to <cache> <paths…>`: the closures, into the store a fleet
/// fetches from.
///
/// After signing, and that is the whole order: `nix copy` carries the
/// signatures that are in the local store when it runs, and a cache full of
/// unsigned paths is a cache a managed host refuses to fetch from —
/// `require-sigs = true` is as true for a substituter as for an `ssh-ng://`
/// push (M0 probe S12).
///
/// No `--no-check-sigs`, no `--all`, and nothing about the target hosts:
/// this pushes exactly the paths this release names, and what a host is
/// allowed to fetch is decided by that host's own configuration.
pub fn cache_copy_cmd(cache: &str, paths: &[String]) -> Cmd {
    Cmd::new(Effect::Build, "nix", CACHE_DEADLINE)
        .args(["copy", "--to"])
        .arg(cache.to_string())
        .args(paths.iter().cloned())
}

/// `nix-store --realise --add-root <link> <path>`: an indirect root, so the
/// closure survives a `nix-collect-garbage` between `build` and `apply`.
pub fn add_root_cmd(link: &std::path::Path, store_path: &str) -> Cmd {
    Cmd::new(Effect::Build, "nix-store", STORE_DEADLINE)
        .args(["--realise", "--add-root"])
        .arg(link.display().to_string())
        .arg(store_path)
}

/// Everything a build produced.
#[derive(Debug, Clone)]
pub struct Built {
    pub release: ReleaseManifest,
    /// The garbage-collector roots that now protect it.
    pub roots: Vec<PathBuf>,
    /// The out path of every derivation that was realised, by what it was
    /// for. Printed by a partial build, which writes no release.
    pub outputs: BTreeMap<String, String>,
}

/// The verb, with its three doors and its options in one place.
pub struct Builder<'a> {
    pub runner: &'a dyn Runner,
    pub files: &'a dyn Files,
    pub clock: &'a dyn Clock,
    pub options: BuildOptions,
    /// Where the garbage-collector roots go. `None` leaves the closures
    /// unprotected, which is only right for a build nobody will apply.
    pub state: Option<StateDir>,
}

impl Builder<'_> {
    /// Build everything this manifest names, and bind it into a release.
    ///
    /// The order matters and is the order below: check that the derivations
    /// are still there, build them, compare every path against what the
    /// manifest promised, sign, measure (so that the measurement includes
    /// the signatures), bind, root. Signing before measuring is the whole
    /// reason `signatures` in a release is worth anything.
    pub fn realise(&self, resolved: ResolvedFleet) -> Result<Built> {
        let hosts = self.hosts_of(&resolved)?;
        let partial = hosts.len() != resolved.evaluated_hosts.len();
        let drvs = derivations(&resolved, &hosts);
        if drvs.is_empty() {
            bail!("this manifest names no derivation to build.");
        }
        self.require_signing_key(&resolved, &hosts)?;
        self.require_a_key_for_the_cache()?;

        self.ensure_present(&drvs)?;

        // The artifacts, in ONE nix invocation: every system, every bundle
        // and every package of the fleet as one build graph.
        //
        // The check derivations are NOT in it, and that is the one thing
        // this does not batch. A check is a data object — id, status,
        // expected, observed, reason, duration — and a batch that failed
        // would answer "nix exited 1" for all of them together. So each one
        // is asked on its own, with `AnyExit`, and a required check that
        // does not pass is a sentence that names it. In a real fleet these
        // are few: `checks.required` is usually `units, session, mounts`,
        // which are questions about a running host and belong to `check`.
        let artifacts: Vec<&Derivation> =
            drvs.iter().filter(|d| d.kind != DrvKind::Check).collect();
        let outputs = self.build_artifacts(&artifacts)?;

        let mut checks: Vec<CheckResult> = Vec::new();
        for drv in drvs.iter().filter(|d| d.kind == DrvKind::Check) {
            let result = self.build_check(drv, &resolved)?;
            if result.status != Status::Pass {
                bail!(
                    "the required check {} did not pass, so there is no release: {}",
                    result.id,
                    result.reason
                );
            }
            checks.push(result);
        }

        // A partial build is for looking at. It cannot be a release, because
        // a release covers every host of its manifest — `release::bind`
        // enforces exactly that, and a "release" over three of four hosts
        // would let a plan quietly leave one behind.
        if partial {
            bail!(
                "this built {} of the manifest's {} host(s), so it is not a release: a \
                 release covers every host of the manifest it binds. The built system(s) \
                 are {}. For a release over part of a fleet, resolve that part: \
                 `resolve --hosts {}`.",
                hosts.len(),
                resolved.evaluated_hosts.len(),
                outputs
                    .iter()
                    .map(|(what, out)| format!("{what}: {out}"))
                    .collect::<Vec<_>>()
                    .join(", "),
                hosts.join(",")
            );
        }

        self.check_promises(&resolved, &hosts, &outputs)?;

        // Was it the same build twice? Asked here, next to the build it is
        // a claim about, and only when the operator asked for it: this
        // builds every host's system a SECOND time.
        let reproducibility = self.verify_reproducible(&resolved, &hosts)?;

        let mut to_measure: Vec<String> = outputs.values().cloned().collect();
        // The configuration files are in the closure of the systems that
        // read them, so they exist once the toplevels are built; they are
        // measured by their content rather than by a nar, because what a
        // unit reads is the file.
        let config_files = self.config_files(&resolved, &hosts)?;

        if let Some(key) = &self.options.sign_key {
            self.runner.run(&sign_cmd(key, &to_measure))?;
        }

        to_measure.sort();
        to_measure.dedup();
        let info = self.measure(&to_measure)?;
        self.require_signatures(&resolved, &hosts, &outputs, &info)?;

        // Into the cache, after the signatures are on and after they have
        // been checked: a cache is only worth having if what a host pulls
        // out of it is what a host would have accepted over ssh. A push that
        // fails is a build that fails — a release whose `cache_url` named a
        // store the closures never reached would be a release that lies
        // about where they are.
        self.push_to_cache(&to_measure)?;

        let artifacts = self.host_artifacts(&resolved, &hosts, &outputs, &info, config_files)?;
        let packages = self.packages(&drvs, &outputs, &info)?;
        let build_env = self.build_env()?;

        let release = bind(
            resolved,
            artifacts,
            packages,
            // Guest artifacts are what a verification suite boots. They are
            // not part of any host's closure and no manifest field names
            // them individually yet, so `verify` (M4B) is what fills this.
            Vec::new(),
            build_env,
            checks,
            reproducibility,
            self.clock.now(),
        )?;

        let roots = self.protect(&release)?;
        Ok(Built {
            release,
            roots,
            outputs,
        })
    }

    /// Which hosts this build covers.
    fn hosts_of(&self, resolved: &ResolvedFleet) -> Result<Vec<String>> {
        match &self.options.hosts {
            None => Ok(resolved.evaluated_hosts.clone()),
            Some(wanted) => {
                let unknown: Vec<&str> = wanted
                    .iter()
                    .filter(|id| !resolved.hosts.contains_key(*id))
                    .map(|s| s.as_str())
                    .collect();
                if !unknown.is_empty() {
                    bail!(
                        "the manifest {} knows nothing about {}; it evaluated {}.",
                        resolved.manifest_id,
                        unknown.join(", "),
                        resolved.evaluated_hosts.join(", ")
                    );
                }
                let mut hosts = wanted.clone();
                hosts.sort();
                hosts.dedup();
                Ok(hosts)
            }
        }
    }

    /// A build that covers a managed host needs a key, and says so before
    /// it spends an hour finding out.
    fn require_signing_key(&self, resolved: &ResolvedFleet, hosts: &[String]) -> Result<()> {
        if self.options.sign_key.is_some() {
            return Ok(());
        }
        let managed: Vec<&str> = hosts
            .iter()
            .filter(|id| {
                resolved
                    .hosts
                    .get(*id)
                    .map(|host| host.deployment == Deployment::Nixos)
                    .unwrap_or(false)
            })
            .map(|s| s.as_str())
            .collect();
        if managed.is_empty() {
            return Ok(());
        }
        bail!(
            "this build covers the managed host(s) {} and no signing key was given. A \
             managed host runs nix with `require-sigs = true`, so `nix copy --to \
             ssh-ng://` refuses an unsigned closure — as root as well — and there is no \
             `--no-check-sigs` here. Pass `--sign-key <file>`, or put \
             `signing_key = \"<file>\"` under `[operator]` in the inventory (and keep that \
             file out of git). Make one with `nix-store \
             --generate-binary-cache-key <fleet> <secret> <public>`, and put the public \
             half in `meisterstack.managed.trustedPublicKeys`.",
            managed.join(", ")
        );
    }

    /// A cache of unsigned closures is a cache no host of this fleet can
    /// fetch from, and finding that out after an hour of copying is finding
    /// it out too late.
    fn require_a_key_for_the_cache(&self) -> Result<()> {
        if self.options.cache.is_none() || self.options.sign_key.is_some() {
            return Ok(());
        }
        bail!(
            "this build would push into {} and has no signing key. A managed host fetches \
             from a substituter under the same rule it takes an ssh-ng:// push under — \
             `require-sigs = true` — so an unsigned cache is a cache every host of this \
             fleet would refuse. Pass `--sign-key <file>`, or `[operator] signing_key` in \
             the inventory.",
            self.options.cache.as_deref().unwrap_or_default()
        );
    }

    /// Are the derivations still in the store?
    fn ensure_present(&self, drvs: &[Derivation]) -> Result<()> {
        let paths: Vec<String> = drvs.iter().map(|d| d.drv.clone()).collect();
        let out = self.runner.run(&drv_present_cmd(&paths))?;
        if out.ok() {
            return Ok(());
        }
        // One of them is gone. Which ones is worth a command each, because
        // the answer decides what an operator does next.
        let mut gone: Vec<&Derivation> = Vec::new();
        for drv in drvs {
            let one = self
                .runner
                .run(&drv_present_cmd(std::slice::from_ref(&drv.drv)))?;
            if !one.ok() {
                gone.push(drv);
            }
        }
        if gone.is_empty() {
            // The batch failed and every single one is there: something
            // else was wrong with the question, and the answer nix gave is
            // the one worth printing.
            bail!(
                "nix would not say whether the manifest's derivations are in the store: {}",
                out.stderr.trim()
            );
        }
        bail!(
            "resolve again; the derivation {} is gone from the store{}. A manifest names \
             derivations, and a derivation that has been collected cannot be rebuilt from \
             its path — only re-evaluated, and an evaluation now might not be the one the \
             manifest describes.",
            gone.iter()
                .map(|d| format!("{} (for {})", d.drv, d.what))
                .collect::<Vec<_>>()
                .join(", "),
            if gone.len() == 1 { "" } else { " (and others)" }
        );
    }

    /// Build these derivations in one nix invocation, and say which output
    /// belongs to which of them.
    ///
    /// The mapping is nix's own (`drvPath` beside `outputs` in the json
    /// answer) and not the order of the arguments: a release that named
    /// seventy systems by the position of a line in a list would be a
    /// release that is right until nix reorders its output.
    ///
    /// Two derivations of one manifest may be the same path — two hosts of a
    /// fleet can be the same system — so the arguments are deduplicated and
    /// the answer is read back per `what`.
    fn build_artifacts(&self, drvs: &[&Derivation]) -> Result<BTreeMap<String, String>> {
        if drvs.is_empty() {
            return Ok(BTreeMap::new());
        }
        let mut wanted: Vec<String> = drvs.iter().map(|d| d.drv.clone()).collect();
        wanted.sort();
        wanted.dedup();

        let cmd = build_many_cmd(&wanted, &self.options);
        let out = self.runner.run(&cmd)?;
        let built = parse_build_json(&out.stdout, &cmd.line())?;

        let mut outputs = BTreeMap::new();
        for drv in drvs {
            let paths = built.get(&drv.drv).ok_or_else(|| {
                anyhow::anyhow!(
                    "nix built the fleet and said nothing about {} (for {}). Nothing can be \
                     named in a release that nobody can point at.",
                    drv.drv,
                    drv.what
                )
            })?;
            match paths.len() {
                1 => {
                    outputs.insert(drv.what.clone(), paths[0].clone());
                }
                0 => bail!(
                    "nix built {} and printed no output path. Nothing can be named in a \
                     release that nobody can point at.",
                    drv.drv
                ),
                // A derivation with several outputs: the manifest names one
                // out path per derivation, so which of them it meant is not
                // this tool's to guess.
                _ => bail!(
                    "the derivation {} for {} has {} outputs ({}), and the manifest names \
                     one. The one derivation has to expose a single output per host, \
                     package and check.",
                    drv.drv,
                    drv.what,
                    paths.len(),
                    paths.join(", ")
                ),
            }
        }
        Ok(outputs)
    }

    /// One derivation, through the same road as seventy. Used by `image`,
    /// which builds exactly one medium.
    fn build_one(&self, drv: &Derivation) -> Result<String> {
        let outputs = self.build_artifacts(&[drv])?;
        outputs
            .into_values()
            .next()
            .ok_or_else(|| anyhow::anyhow!("nix built {} and said nothing about it.", drv.drv))
    }

    /// A check that passes by building.
    fn build_check(&self, drv: &Derivation, resolved: &ResolvedFleet) -> Result<CheckResult> {
        let started = self.clock.now();
        let out = self
            .runner
            .run(&build_cmd(&drv.drv, &self.options).expect(Expect::AnyExit))?;
        let ended = self.clock.now();
        let duration_ms = (ended - started).num_milliseconds().max(0) as u64;
        let passed = out.ok();
        Ok(CheckResult {
            id: drv.what.clone(),
            // A check derivation is about the fleet unless its name says a
            // host, and `config-<host>` does. Guessing further would be
            // guessing.
            subject: match resolved
                .hosts
                .keys()
                .find(|id| drv.what.ends_with(&format!("-{id}")))
            {
                Some(id) => Subject::host(id),
                None => Subject::resource(&drv.what),
            },
            required: true,
            status: if passed { Status::Pass } else { Status::Fail },
            expected: "the derivation builds".to_string(),
            observed: if passed {
                out.stdout.trim().to_string()
            } else {
                crate::run::last_lines(out.stderr.trim())
            },
            reason: if passed {
                format!("{} built", drv.drv)
            } else {
                format!("{} exited {}", drv.drv, out.status)
            },
            duration_ms,
            evidence: vec![Evidence {
                kind: EvidenceKind::Command,
                reference: build_cmd(&drv.drv, &self.options).line(),
            }],
            release_id: None,
            config_id: None,
        })
    }

    /// Every built path is the path the manifest said it would be.
    ///
    /// `release::bind` checks this too and is the last word. It is checked
    /// here as well because here is where the command that produced the
    /// path can be named, and because signing a closure that is about to be
    /// refused is a waste of an operator's afternoon.
    fn check_promises(
        &self,
        resolved: &ResolvedFleet,
        hosts: &[String],
        outputs: &BTreeMap<String, String>,
    ) -> Result<()> {
        for id in hosts {
            let host = &resolved.hosts[id];
            let built = outputs
                .get(id)
                .ok_or_else(|| anyhow::anyhow!("nothing was built for {id}"))?;
            if built != &host.build.toplevel_out {
                bail!(
                    "`nix build {}^*` produced {built} and the manifest says {id} would be \
                     {}. A release binds what the manifest evaluated; it does not replace \
                     it. Resolve again if the fleet changed.",
                    host.build.toplevel_drv,
                    host.build.toplevel_out
                );
            }
        }
        Ok(())
    }

    /// The rendered configuration of every host, by content.
    fn config_files(
        &self,
        resolved: &ResolvedFleet,
        hosts: &[String],
    ) -> Result<BTreeMap<String, BTreeMap<String, ConfigArtifact>>> {
        let mut out = BTreeMap::new();
        for id in hosts {
            let host = &resolved.hosts[id];
            let mut files = BTreeMap::new();
            for (name, store_path) in &host.config_artifacts {
                let path = std::path::Path::new(store_path);
                if !self.files.exists(path) {
                    bail!(
                        "the manifest names {store_path} as {name} of {id} and it is not in \
                         the store after the build. A configuration file a unit reads has to \
                         be part of that host's system closure, which is the one \
                         derivation's job."
                    );
                }
                let bytes = self.files.read(path)?;
                files.insert(
                    name.clone(),
                    ConfigArtifact {
                        store_path: store_path.clone(),
                        sha256: sha256_hex(&bytes),
                    },
                );
            }
            out.insert(id.clone(), files);
        }
        Ok(out)
    }

    fn measure(&self, paths: &[String]) -> Result<BTreeMap<String, PathInfo>> {
        let cmd = path_info_cmd(paths);
        let out = self.runner.run(&cmd)?;
        let info = parse_path_info(&out.stdout, &cmd.line())?;
        let missing: Vec<&String> = paths.iter().filter(|p| !info.contains_key(*p)).collect();
        if !missing.is_empty() {
            bail!(
                "nix path-info said nothing about {}; a release names no path it has not \
                 measured.",
                missing
                    .iter()
                    .map(|s| s.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }
        Ok(info)
    }

    /// Build every host's system a second time and say whether the bytes
    /// came out the same.
    ///
    /// Without `--verify-reproducible` this runs nothing and answers
    /// `bit_identical_verified: false, method: null` — which is the honest
    /// shape of "nobody checked", and the reason the two fields are
    /// separate from `inputs_pinned`. Pinned inputs are a reason to EXPECT
    /// the same bytes and never evidence of them.
    ///
    /// A rebuild that could not be MADE — a builder that went away, a disk
    /// that filled, a derivation nix refused for some other reason — stops
    /// the build with what nix said. An operator who asked for a
    /// verification and got `false` without one would have been told
    /// something that is not true.
    fn verify_reproducible(
        &self,
        resolved: &ResolvedFleet,
        hosts: &[String],
    ) -> Result<Reproducibility> {
        // The manifest was resolved from a locked tree — `resolve` refuses
        // one without a `flake.lock` — so the inputs are pinned either way.
        let pinned = Reproducibility {
            inputs_pinned: true,
            bit_identical_verified: false,
            method: None,
            differences: Vec::new(),
        };
        if !self.options.verify_reproducible {
            return Ok(pinned);
        }
        let mut differences = Vec::new();
        for id in hosts {
            let host = &resolved.hosts[id];
            let drv = &host.build.toplevel_drv;
            let cmd = rebuild_cmd(drv, &self.options);
            let out = self.runner.run(&cmd)?;
            if out.ok() {
                continue;
            }
            let said = crate::run::last_lines(out.stderr.trim());
            if !said.contains(NOT_DETERMINISTIC) {
                bail!(
                    "the rebuild of {id} could not be made, so this release cannot say \
                     whether it is reproducible. `{}` exited {} and said: {said}",
                    cmd.line(),
                    out.status
                );
            }
            differences.push(format!("{id} ({drv}): {said}"));
        }
        Ok(Reproducibility {
            inputs_pinned: true,
            bit_identical_verified: differences.is_empty(),
            // Named even when the answer is `false`: what makes this field
            // worth anything is that somebody can tell "checked and
            // different" from "not checked".
            method: Some("nix build --rebuild".to_string()),
            differences,
        })
    }

    /// Push the whole release into the cache the operator named.
    ///
    /// One `nix copy` over every path of the release, for the same reason
    /// the build is one `nix build`: seventy closures that share a kernel,
    /// a nixpkgs and one meisterstack are one graph to walk, and seventy
    /// invocations would query the cache for the shared half seventy times.
    ///
    /// A build with no `--cache` runs no command here at all — not an empty
    /// one, not a probe. That is what makes `cache_url: null` in a release a
    /// statement rather than an absence.
    fn push_to_cache(&self, paths: &[String]) -> Result<()> {
        let Some(cache) = &self.options.cache else {
            return Ok(());
        };
        if paths.is_empty() {
            return Ok(());
        }
        self.runner.run(&cache_copy_cmd(cache, paths))?;
        Ok(())
    }

    /// Every managed host's system carries a signature.
    fn require_signatures(
        &self,
        resolved: &ResolvedFleet,
        hosts: &[String],
        outputs: &BTreeMap<String, String>,
        info: &BTreeMap<String, PathInfo>,
    ) -> Result<()> {
        for id in hosts {
            if resolved.hosts[id].deployment != Deployment::Nixos {
                continue;
            }
            let Some(out) = outputs.get(id) else { continue };
            let signatures = info.get(out).map(|i| i.signatures.len()).unwrap_or(0);
            if signatures == 0 {
                bail!(
                    "the store holds no signature for {out} ({id}). A managed host refuses an \
                     unsigned closure, so a release that named this path would be a release \
                     that cannot be applied. Pass --sign-key <file>."
                );
            }
        }
        Ok(())
    }

    fn host_artifacts(
        &self,
        resolved: &ResolvedFleet,
        hosts: &[String],
        outputs: &BTreeMap<String, String>,
        info: &BTreeMap<String, PathInfo>,
        mut config_files: BTreeMap<String, BTreeMap<String, ConfigArtifact>>,
    ) -> Result<BTreeMap<String, HostArtifacts>> {
        let mut out = BTreeMap::new();
        for id in hosts {
            let host = &resolved.hosts[id];
            let store_path = &outputs[id];
            let measured = info
                .get(store_path)
                .ok_or_else(|| anyhow::anyhow!("{store_path} was not measured"))?;
            out.insert(
                id.clone(),
                HostArtifacts {
                    toplevel: StoreArtifact {
                        store_path: store_path.clone(),
                        nar_hash: measured.nar_hash.clone(),
                        nar_size: measured.nar_size,
                        closure_size: measured.closure_size,
                        signatures: measured.signatures.clone(),
                    },
                    // `build` does not make images; `image` does, and
                    // `bind` allows an unbuilt one.
                    installer_iso: None,
                    disk_image: None,
                    direct_boot: self.direct_boot(id, host, outputs)?,
                    // Straight from the manifest: these three fields are
                    // what the reboot class is decided on, and `bind`
                    // refuses them if they differ from the evaluation.
                    boot: BootArtifacts {
                        kernel_store_path: host.build.boot.kernel_out.clone(),
                        initrd_store_path: host.build.boot.initrd_out.clone(),
                        kernel_params_sha256: host.build.boot.kernel_params_sha256.clone(),
                    },
                    config_files: config_files.remove(id).unwrap_or_default(),
                },
            );
        }
        Ok(out)
    }

    /// The bundle of a host that boots `direct`, measured.
    ///
    /// The kernel and the initrd are named by the paths the MANIFEST
    /// promised rather than by anything found in the bundle: those two are
    /// what `bind` compares and what the planner decides a reboot class on,
    /// and reading them back out of a directory of symlinks would be a
    /// second source for one fact. What the bundle contributes is the
    /// directory itself — one name a provider adapter can be handed — and
    /// the sha256 of the two files, which is what an adapter uploads them
    /// under.
    fn direct_boot(
        &self,
        id: &str,
        host: &crate::manifest::ResolvedHost,
        outputs: &BTreeMap<String, String>,
    ) -> Result<Option<crate::release::DirectBoot>> {
        if host.build.boot.mode != crate::manifest::BootMode::Direct {
            return Ok(None);
        }
        let bundle = outputs.get(&direct_boot_key(id)).ok_or_else(|| {
            anyhow::anyhow!(
                "{id} boots direct and nothing was built for its bundle; the manifest has to \
                 name a `direct_boot_drv` for such a host."
            )
        })?;
        let cmdline = host.build.boot.cmdline.clone().ok_or_else(|| {
            anyhow::anyhow!(
                "{id} boots direct and its manifest carries no command line. A provider that \
                 is handed a kernel and an initrd and no `init=` boots the new kernel into \
                 whatever userland the initrd finds."
            )
        })?;
        Ok(Some(crate::release::DirectBoot {
            kernel: self.file_artifact(id, "kernel", &host.build.boot.kernel_out)?,
            initrd: self.file_artifact(id, "initrd", &host.build.boot.initrd_out)?,
            cmdline,
            bundle_store_path: bundle.clone(),
        }))
    }

    /// One file of the store, by its bytes. Read rather than asked of nix:
    /// what a hypervisor loads is the FILE, and `nix path-info` answers
    /// about the store object that holds it.
    fn file_artifact(
        &self,
        id: &str,
        what: &str,
        path: &str,
    ) -> Result<crate::release::ImageArtifact> {
        let bytes = self.files.read(std::path::Path::new(path)).map_err(|e| {
            anyhow::anyhow!(
                "the {what} of {id} ({path}) could not be read after the build: {e}. A release \
                 names no file it has not measured."
            )
        })?;
        Ok(crate::release::ImageArtifact {
            store_path: path.to_string(),
            sha256: sha256_hex(&bytes),
            size: bytes.len() as u64,
        })
    }

    fn packages(
        &self,
        drvs: &[Derivation],
        outputs: &BTreeMap<String, String>,
        info: &BTreeMap<String, PathInfo>,
    ) -> Result<BTreeMap<String, PackageArtifact>> {
        let mut out = BTreeMap::new();
        for drv in drvs.iter().filter(|d| d.kind == DrvKind::Package) {
            let store_path = outputs
                .get(&drv.what)
                .ok_or_else(|| anyhow::anyhow!("nothing was built for {}", drv.what))?;
            let measured = info
                .get(store_path)
                .ok_or_else(|| anyhow::anyhow!("{store_path} was not measured"))?;
            out.insert(
                drv.what.clone(),
                PackageArtifact {
                    store_path: store_path.clone(),
                    nar_hash: measured.nar_hash.clone(),
                },
            );
        }
        Ok(out)
    }

    /// Where this build happened. Recorded, and not part of the
    /// `release_id`: the same closures built on a laptop and on a build farm
    /// are the same release.
    fn build_env(&self) -> Result<BuildEnv> {
        let version = self
            .runner
            .run(&Cmd::new(Effect::Read, "nix", QUERY_DEADLINE).args(["--version"]))?;
        let system = self.runner.run(
            &Cmd::new(Effect::Read, "nix", QUERY_DEADLINE).args(["config", "show", "system"]),
        )?;
        let sandbox = self.runner.run(
            &Cmd::new(Effect::Read, "nix", QUERY_DEADLINE).args(["config", "show", "sandbox"]),
        )?;
        Ok(BuildEnv {
            nix_version: version.trimmed().to_string(),
            system: system.trimmed().to_string(),
            builders: self.options.builders.clone(),
            substituters: self.options.substituters.clone(),
            max_jobs: self.options.max_jobs.clone(),
            options: self.options.options.clone(),
            signing_key_name: match &self.options.sign_key {
                Some(key) => Some(self.key_name(key)?),
                None => None,
            },
            cache_url: self.options.cache.clone(),
            // "relaxed" is nix's third value and it is not a sandbox.
            sandbox: sandbox.trimmed() == "true",
        })
    }

    /// The NAME of a signing key, out of the key file.
    ///
    /// A nix signing key file is one line, `<name>:<base64 secret>`. Only
    /// the name is read and only the name is kept: the target needs to know
    /// which public key to trust, and nothing else about this file may
    /// leave this function — not into a return value, not into an error
    /// message.
    fn key_name(&self, key: &std::path::Path) -> Result<String> {
        let text = self.files.read_to_string(key)?;
        let Some((name, rest)) = text.trim().split_once(':') else {
            bail!(
                "{} does not look like a nix signing key: one line, `<name>:<base64>`. Make \
                 one with `nix-store --generate-binary-cache-key <name> <secret> <public>`.",
                key.display()
            );
        };
        if name.is_empty() || rest.is_empty() {
            bail!(
                "{} does not look like a nix signing key: one line, `<name>:<base64>`.",
                key.display()
            );
        }
        Ok(name.to_string())
    }

    /// Keep the collector off this release.
    fn protect(&self, release: &ReleaseManifest) -> Result<Vec<PathBuf>> {
        let Some(state) = &self.state else {
            return Ok(Vec::new());
        };
        let dir = state.gcroot_dir(&release.release_id);
        self.files.create_dir_all(&dir)?;
        let mut roots = Vec::new();
        for (id, artifacts) in &release.artifacts {
            let link = dir.join(id);
            self.runner
                .run(&add_root_cmd(&link, &artifacts.toplevel.store_path))?;
            roots.push(link);
        }
        for (id, artifacts) in &release.artifacts {
            // The bundle is its own store path and is NOT in the toplevel's
            // closure — it is a directory of symlinks into it — so a root on
            // the system does not keep it. A provider that is handed a
            // bundle path a collector removed between `build` and the reboot
            // is a guest that does not come up.
            if let Some(bundle) = &artifacts.direct_boot {
                let link = dir.join(direct_boot_key(id));
                self.runner
                    .run(&add_root_cmd(&link, &bundle.bundle_store_path))?;
                roots.push(link);
            }
        }
        for (name, package) in &release.packages {
            let link = dir.join(format!("pkg-{name}"));
            self.runner.run(&add_root_cmd(&link, &package.store_path))?;
            roots.push(link);
        }
        // When this release was made, so that `gc --keep N` can tell the
        // oldest roots from the newest. A release id is a content hash and
        // says nothing about time.
        self.files.write_atomic(
            &dir.join(STAMP),
            format!("{}\n", release.created_at.to_rfc3339()).as_bytes(),
            0o644,
        )?;
        Ok(roots)
    }
}

// ---------------------------------------------------------------------------
// image
// ---------------------------------------------------------------------------

/// Which of a host's three media is wanted.
///
/// One verb and three kinds rather than three verbs, because what differs
/// between them is one derivation path out of the same manifest: an
/// installer ISO, a prebuilt disk, and the bundle a hypervisor loads. What
/// they have in common is everything else — the release says which
/// derivation, the build is the release's and not a fresh evaluation, and
/// the result gets a garbage-collector root so that the file an operator is
/// about to write to a stick is still there when they get to it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImageKind {
    Installer,
    Disk,
    DirectBoot,
}

impl ImageKind {
    pub fn as_str(self) -> &'static str {
        match self {
            ImageKind::Installer => "installer",
            ImageKind::Disk => "disk",
            ImageKind::DirectBoot => "direct-boot",
        }
    }

    pub fn parse(text: &str) -> Result<ImageKind> {
        match text {
            "installer" => Ok(ImageKind::Installer),
            "disk" => Ok(ImageKind::Disk),
            "direct-boot" => Ok(ImageKind::DirectBoot),
            other => bail!(
                "{other:?} is not a kind of medium. This tool builds `installer` (the ISO a \
                 machine is installed from), `disk` (a prebuilt EFI disk image) and \
                 `direct-boot` (the kernel, the initrd and the command line a hypervisor is \
                 handed)."
            ),
        }
    }

    /// What the FILE inside the output is called, by its extension. The
    /// derivations of nixpkgs put their result in a directory next to a
    /// `nix-support` folder, so "the image" is not the out path itself.
    fn extensions(self) -> &'static [&'static str] {
        match self {
            ImageKind::Installer => &["iso"],
            ImageKind::Disk => &["raw", "qcow2", "img", "vhd", "vmdk"],
            // A bundle is three files and stays a directory.
            ImageKind::DirectBoot => &[],
        }
    }
}

impl std::fmt::Display for ImageKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.pad(self.as_str())
    }
}

/// What `image` produced, as it is printed.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct ImageResult {
    pub schema: String,
    pub host: String,
    pub kind: String,
    pub release_id: String,
    /// The derivation's output — a directory for every kind this tool makes.
    pub store_path: String,
    /// The one file inside it that is the medium, or null for a bundle,
    /// which is three.
    pub file: Option<String>,
    pub sha256: Option<String>,
    pub size: Option<u64>,
    /// Where the collector was told to leave it.
    pub gc_root: Option<String>,
    /// Where a copy was linked, if `--out` asked for one.
    pub linked_to: Option<String>,
}

pub const IMAGE_SCHEMA: &str = "meister-deploy/image/1";

/// The derivation this release names for that host and that kind, or the
/// sentence that says why there is none.
pub fn image_drv(release: &ReleaseManifest, host: &str, kind: ImageKind) -> Result<String> {
    let resolved = &release.resolved_fleet;
    let Some(entry) = resolved.hosts.get(host) else {
        bail!(
            "the release {} knows nothing about {host}; it covers {}.",
            release.release_id,
            resolved.evaluated_hosts.join(", ")
        );
    };
    let drv = match kind {
        ImageKind::Installer => entry.build.installer_drv.clone(),
        ImageKind::Disk => entry.build.disk_image_drv.clone(),
        ImageKind::DirectBoot => entry.build.direct_boot_drv.clone(),
    };
    drv.ok_or_else(|| match kind {
        ImageKind::Installer => anyhow::anyhow!(
            "{host} has no installer medium in this release. A host gets one from \
             `lib.mkFleet`, which builds it for every host of a fleet — so a manifest without \
             one was resolved from a flake that does not build this host at all."
        ),
        ImageKind::Disk => anyhow::anyhow!(
            "{host} has no disk image in this release: it boots {}. A `raw-efi` image makes an \
             ESP and installs systemd-boot into it, which is not what a machine whose \
             hypervisor hands it a kernel does with its disk. `--kind direct-boot` is that \
             host's medium.",
            entry.build.boot.mode
        ),
        ImageKind::DirectBoot => anyhow::anyhow!(
            "{host} has no direct-boot bundle in this release: it boots {}. A uefi host reads \
             its own boot menu, so there is nobody outside it to hand a kernel to. `--kind \
             installer` is how that host is first put on a disk.",
            entry.build.boot.mode
        ),
    })
}

impl Builder<'_> {
    /// Build one medium of one host, and say exactly what came out.
    ///
    /// The derivation is the one the RELEASE names, for the same reason
    /// `build` uses the manifest's: a medium that was built from a fresh
    /// evaluation would be a medium nobody can bind to the release an
    /// operator is holding. Nothing is evaluated here.
    pub fn image(
        &self,
        release: &ReleaseManifest,
        host: &str,
        kind: ImageKind,
        out_dir: Option<&std::path::Path>,
    ) -> Result<ImageResult> {
        let drv = image_drv(release, host, kind)?;
        let out = self.build_one(&Derivation {
            what: format!("{host}-{kind}"),
            kind: DrvKind::Package,
            drv,
        })?;

        let file = self.medium_in(&out, kind)?;
        let (sha256, size) = match &file {
            Some(path) => {
                let bytes = self.files.read(std::path::Path::new(path))?;
                (Some(sha256_hex(&bytes)), Some(bytes.len() as u64))
            }
            None => (None, None),
        };

        // A root on the OUT path and not on the file inside it: the file is
        // part of that store object, and the collector counts objects.
        let gc_root = match &self.state {
            Some(state) => {
                let dir = state.gcroot_dir(&release.release_id);
                self.files.create_dir_all(&dir)?;
                let link = dir.join(format!("{host}-{kind}"));
                self.runner.run(&add_root_cmd(&link, &out))?;
                Some(link.display().to_string())
            }
            None => None,
        };

        let linked_to = match out_dir {
            Some(dir) => {
                self.files.create_dir_all(dir)?;
                let name = match (&file, kind) {
                    (Some(path), _) => format!(
                        "{host}-{}",
                        std::path::Path::new(path)
                            .file_name()
                            .map(|n| n.to_string_lossy().into_owned())
                            .unwrap_or_else(|| kind.to_string())
                    ),
                    (None, _) => format!("{host}-{kind}"),
                };
                let link = dir.join(name);
                let target = file.clone().unwrap_or_else(|| out.clone());
                self.files
                    .symlink_atomic(std::path::Path::new(&target), &link)?;
                Some(link.display().to_string())
            }
            None => None,
        };

        Ok(ImageResult {
            schema: IMAGE_SCHEMA.to_string(),
            host: host.to_string(),
            kind: kind.to_string(),
            release_id: release.release_id.clone(),
            store_path: out,
            file,
            sha256,
            size,
            gc_root,
            linked_to,
        })
    }

    /// The one file inside a medium's output directory, by extension.
    ///
    /// Named rather than guessed: an ISO derivation puts its result in
    /// `iso/` beside a `nix-support/` directory, so "the only file in there"
    /// is not an answer, and a tool that printed the wrong path would send
    /// somebody to write a text file to a USB stick. Two candidates is an
    /// error that names both.
    fn medium_in(&self, out: &str, kind: ImageKind) -> Result<Option<String>> {
        let extensions = kind.extensions();
        if extensions.is_empty() {
            return Ok(None);
        }
        let mut found: Vec<PathBuf> = Vec::new();
        let mut stack = vec![PathBuf::from(out)];
        while let Some(dir) = stack.pop() {
            for entry in self.files.list_dir(&dir)? {
                // `Entry::Other` is everything that is neither a regular
                // file nor a symlink, which inside a store output is a
                // directory. A fifo would be walked into and the listing
                // would say so, which is a better answer than a silent skip.
                match self.files.entry(&entry)? {
                    crate::effects::Entry::Other => stack.push(entry),
                    _ => {
                        let matches = entry
                            .extension()
                            .map(|e| extensions.contains(&e.to_string_lossy().as_ref()))
                            .unwrap_or(false);
                        if matches {
                            found.push(entry);
                        }
                    }
                }
            }
        }
        found.sort();
        match found.len() {
            1 => Ok(Some(found[0].display().to_string())),
            0 => bail!(
                "{out} holds no file ending in {}, so this build produced no {kind} medium \
                 anybody could write anywhere.",
                extensions.join(" or ")
            ),
            _ => bail!(
                "{out} holds {} files that could be the {kind} medium ({}); this tool will not \
                 pick one of them for you.",
                found.len(),
                found
                    .iter()
                    .map(|p| p.display().to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        }
    }
}

/// The file that dates a directory of roots.
pub const STAMP: &str = ".created";

/// One release's roots, as `gc` sees them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RootDir {
    pub release_id: String,
    pub path: PathBuf,
    /// When the release was made, from the stamp. `None` for a directory
    /// that carries none — which is never removed, because a directory this
    /// tool cannot date is one it does not know enough about.
    pub created_at: Option<DateTime<Utc>>,
    pub links: Vec<PathBuf>,
}

/// Which releases this state directory protects.
pub fn roots(files: &dyn Files, state: &StateDir) -> Result<Vec<RootDir>> {
    let mut out = Vec::new();
    for dir in files.list_dir(&state.gcroots_dir())? {
        let Some(release_id) = dir.file_name().map(|n| n.to_string_lossy().into_owned()) else {
            continue;
        };
        let stamp = dir.join(STAMP);
        let created_at = files
            .read_to_string(&stamp)
            .ok()
            .and_then(|text| DateTime::parse_from_rfc3339(text.trim()).ok())
            .map(|t| t.with_timezone(&Utc));
        let links = files
            .list_dir(&dir)?
            .into_iter()
            .filter(|path| path.file_name().map(|n| n != STAMP).unwrap_or(false))
            .collect();
        out.push(RootDir {
            release_id,
            path: dir,
            created_at,
            links,
        });
    }
    // Newest last, undated first: `keep N` keeps the tail.
    out.sort_by(|a, b| {
        a.created_at
            .cmp(&b.created_at)
            .then_with(|| a.release_id.cmp(&b.release_id))
    });
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::effects::{FakeClock, MemFiles};
    use crate::fixtures::onebox_enrolled;
    use crate::run::{Matcher, Output, Policy, StrictFake};

    const TOPLEVEL: &str = "/nix/store/oooooooooooooooooooooooooooooooo-nixos-system-box-25.11";
    const DRV: &str = "/nix/store/dddddddddddddddddddddddddddddddd-nixos-system-box-25.11.drv";

    fn one_host() -> ResolvedFleet {
        // The one-box fixture, restricted to `box` alone, so that a test
        // about `build` is not a test about three hosts' worth of argv.
        let mut fleet = onebox_enrolled();
        fleet.hosts.retain(|id, _| id == "box");
        fleet
            .groups
            .retain(|_, group| group.members.iter().any(|m| m == "box"));
        for group in fleet.groups.values_mut() {
            group.members.retain(|m| m == "box");
        }
        fleet
            .services
            .retain(|_, service| service.host.as_ref().map(|h| h == "box").unwrap_or(true));
        fleet.evaluated_hosts = vec!["box".to_string()];
        fleet.partial = false;
        fleet.manifest_id =
            crate::ids::content_id(crate::ids::IdKind::Manifest, &fleet).expect("it hashes");
        fleet
    }

    fn files_with_config(fleet: &ResolvedFleet) -> MemFiles {
        let mut files = MemFiles::new();
        for host in fleet.hosts.values() {
            for path in host.config_artifacts.values() {
                files = files.given(path.clone(), b"[node]\nid = \"box\"\n".to_vec());
            }
        }
        files.given("/keys/fleet.sec", b"fleet-1:c2VjcmV0\n".to_vec())
    }

    /// Every command a green build of `box` runs, in order.
    ///
    /// `sign` says whether a signing command is expected; `signed` says
    /// whether the store reports a signature afterwards. They are two
    /// arguments and not one because the interesting failure is a sign that
    /// ran and left nothing behind.
    /// The four outputs of the one-host fixture, in the order
    /// [`derivations`] lists their derivations: the host, then the packages.
    fn outputs_in_derivation_order() -> Vec<String> {
        vec![
            TOPLEVEL.to_string(),
            "/nix/store/pppppppppppppppppppppppppppppppp-meisterstack".to_string(),
            "/nix/store/cccccccccccccccccccccccccccccccc-cloud-hypervisor".to_string(),
            "/nix/store/gggggggggggggggggggggggggggggggg-guest-tiny".to_string(),
        ]
    }

    /// The same, sorted and deduplicated the way `realise` hands them to
    /// `path-info`, `store sign` and the cache.
    fn measured_paths(fleet: &ResolvedFleet) -> Vec<String> {
        let _ = fleet;
        let mut paths = outputs_in_derivation_order();
        paths.sort();
        paths.dedup();
        paths
    }

    /// What `nix build --json` answers for these derivation/output pairs.
    fn build_json(pairs: &[(String, String)]) -> String {
        let results: Vec<serde_json::Value> = pairs
            .iter()
            .map(|(drv, out)| serde_json::json!({ "drvPath": drv, "outputs": { "out": out } }))
            .collect();
        serde_json::to_string(&results).unwrap()
    }

    fn expect_build(fleet: &ResolvedFleet, sign: bool, signed: bool) -> StrictFake {
        expect_build_into(fleet, sign, signed, None, None)
    }

    /// The same, for a build that verifies its own reproducibility and/or
    /// pushes its release into a cache. Both steps sit at fixed points of
    /// the order `realise` walks — the rebuild right after the build, the
    /// push right after the measurement — and the strict fake is in that
    /// order, which is what makes these tests statements about the order.
    fn expect_build_into(
        fleet: &ResolvedFleet,
        sign: bool,
        signed: bool,
        cache: Option<&str>,
        rebuild: Option<Output>,
    ) -> StrictFake {
        let drvs: Vec<String> = derivations(fleet, &["box".to_string()])
            .into_iter()
            .map(|d| d.drv)
            .collect();
        let outs: Vec<String> = outputs_in_derivation_order();
        let mut fake = StrictFake::new().expect(
            Matcher::prefix("nix", ["path-info", "--json"]),
            Output::stdout("{}"),
        );
        // ONE build over the whole list, answered the way nix answers
        // `--json`: an object per derivation, naming its own `drvPath`.
        // Sorted, because `build_artifacts` sorts and deduplicates what it
        // hands nix.
        let mut sorted: Vec<(String, String)> = drvs
            .iter()
            .cloned()
            .zip(outs.iter().cloned())
            .collect::<Vec<_>>();
        sorted.sort_by(|a, b| a.0.cmp(&b.0));
        fake = fake.expect(
            Matcher::exact(
                "nix",
                [
                    "build".to_string(),
                    "--no-link".to_string(),
                    "--json".to_string(),
                ]
                .into_iter()
                .chain(sorted.iter().map(|(drv, _)| format!("{drv}^*")))
                .collect::<Vec<_>>(),
            ),
            Output::stdout(build_json(&sorted)),
        );
        // --- lane 4C: the rebuild is next to the build it is about ---
        if let Some(reply) = rebuild {
            fake = fake.expect(Matcher::prefix("nix", ["build", "--rebuild"]), reply);
        }
        // --- end lane 4C ---
        if sign {
            fake = fake.expect(
                Matcher::prefix("nix", ["store", "sign", "--recursive", "--key-file"]),
                Output::stdout(""),
            );
        }
        let info: BTreeMap<String, serde_json::Value> = outs
            .iter()
            .map(|path| {
                (
                    path.clone(),
                    serde_json::json!({
                        "narHash": format!("sha256-{}", path.len()),
                        "narSize": 1024,
                        "closureSize": 2048,
                        "signatures": if signed { vec!["fleet-1:abc".to_string()] } else { vec![] },
                    }),
                )
            })
            .collect();
        fake = fake.expect(
            Matcher::prefix("nix", ["path-info", "--json", "--closure-size"]),
            Output::stdout(serde_json::to_string(&info).unwrap()),
        );
        // --- lane 4C: after the measurement, before `build_env` ---
        if let Some(cache) = cache {
            fake = fake.expect(
                Matcher::prefix("nix", ["copy", "--to", cache]),
                Output::stdout(""),
            );
        }
        // --- end lane 4C ---
        fake.expect(
            Matcher::exact("nix", ["--version"]),
            Output::stdout("nix (Nix) 2.35.2\n"),
        )
        .expect(
            Matcher::exact("nix", ["config", "show", "system"]),
            Output::stdout("x86_64-linux\n"),
        )
        .expect(
            Matcher::exact("nix", ["config", "show", "sandbox"]),
            Output::stdout("true\n"),
        )
    }

    #[test]
    fn the_list_of_derivations_is_the_manifests_own() {
        let fleet = onebox_enrolled();
        let hosts = fleet.evaluated_hosts.clone();
        let drvs = derivations(&fleet, &hosts);
        // Three hosts, then the packages. No check derivation in the
        // fixture: its required checks are `units`, `session`, `mounts`,
        // which are about a running host.
        assert_eq!(
            drvs.iter()
                .filter(|d| d.kind == DrvKind::Toplevel)
                .map(|d| d.what.as_str())
                .collect::<Vec<_>>(),
            vec!["box", "n1", "n2"]
        );
        assert_eq!(
            drvs.iter()
                .filter(|d| d.kind == DrvKind::Package)
                .map(|d| d.what.as_str())
                .collect::<Vec<_>>(),
            vec!["meisterstack", "cloud-hypervisor", "guest-tiny"]
        );
        assert!(drvs.iter().all(|d| d.drv.ends_with(".drv")));
        assert!(drvs.iter().all(|d| d.kind != DrvKind::Check));
        // And every one of them is a path the manifest wrote down, not one
        // this tool made up.
        assert_eq!(
            drvs[0].drv, fleet.hosts["box"].build.toplevel_drv,
            "the host's own derivation"
        );
    }

    // ---------------------------------------------------------------
    // The bundle and the verb `image` (M3A position 3)
    // ---------------------------------------------------------------

    #[test]
    fn a_direct_host_gets_its_bundle_built_right_after_its_own_system() {
        let fleet = crate::fixtures::with_direct_host(onebox_enrolled(), "n1");
        let drvs = derivations(&fleet, &["n1".to_string(), "n2".to_string()]);
        let listed: Vec<(&str, DrvKind)> = drvs.iter().map(|d| (d.what.as_str(), d.kind)).collect();
        assert_eq!(listed[0], ("n1", DrvKind::Toplevel));
        assert_eq!(listed[1], ("n1-direct-boot", DrvKind::DirectBoot));
        assert_eq!(listed[2], ("n2", DrvKind::Toplevel));
        assert!(
            !listed.iter().any(|(what, _)| *what == "n2-direct-boot"),
            "a uefi host has no bundle: {listed:?}"
        );
    }

    #[test]
    fn the_release_names_the_derivation_of_each_kind_of_medium() {
        let fleet = crate::fixtures::with_direct_host(onebox_enrolled(), "n1");
        let mut artifacts = crate::fixtures::artifacts_for(&fleet);
        artifacts.get_mut("n1").unwrap().direct_boot =
            Some(crate::fixtures::bundle_for(&fleet, "n1"));
        let release = bind(
            fleet,
            artifacts,
            BTreeMap::new(),
            Vec::new(),
            crate::fixtures::build_env(),
            Vec::new(),
            crate::fixtures::reproducibility(),
            crate::fixtures::at("2026-09-22T11:00:00Z"),
        )
        .expect("binds");

        assert!(
            image_drv(&release, "box", ImageKind::Installer)
                .unwrap()
                .ends_with("nixos-installer-box.drv")
        );
        assert!(
            image_drv(&release, "n1", ImageKind::DirectBoot)
                .unwrap()
                .contains("direct-boot")
        );

        // And the two that do not exist say WHY rather than "null".
        let err = image_drv(&release, "n1", ImageKind::Disk)
            .unwrap_err()
            .to_string();
        assert!(err.contains("it boots direct"), "{err}");
        assert!(err.contains("--kind direct-boot"), "{err}");

        let err = image_drv(&release, "box", ImageKind::DirectBoot)
            .unwrap_err()
            .to_string();
        assert!(err.contains("it boots uefi"), "{err}");
        assert!(err.contains("its own boot menu"), "{err}");

        let err = image_drv(&release, "nowhere", ImageKind::Installer)
            .unwrap_err()
            .to_string();
        assert!(err.contains("knows nothing about nowhere"), "{err}");
    }

    #[test]
    fn a_kind_that_is_not_one_lists_the_three_that_are() {
        let err = ImageKind::parse("usb").unwrap_err().to_string();
        assert!(err.contains("installer"), "{err}");
        assert!(err.contains("direct-boot"), "{err}");
    }

    /// The image inside a nixpkgs image output, which is never the out path
    /// itself: an ISO derivation puts its result in `iso/` beside a
    /// `nix-support/` directory full of text files.
    fn medium_of(files: &MemFiles, out: &str, kind: ImageKind) -> Result<Option<String>> {
        let runner = StrictFake::new();
        let clock = FakeClock::fixed();
        let builder = Builder {
            runner: &runner,
            files,
            clock: &clock,
            options: BuildOptions::default(),
            state: None,
        };
        let found = builder.medium_in(out, kind);
        runner.verify().expect("nothing was run");
        found
    }

    #[test]
    fn the_medium_is_the_one_file_with_the_right_ending() {
        let out = "/nix/store/iiii-nixos-iso";
        // The directories are registered as well: a walk asks what each
        // entry IS, and a test store where nothing is a directory would be
        // a test of a shape no store has.
        let files = MemFiles::new()
            .given_other(format!("{out}/iso"))
            .given_other(format!("{out}/nix-support"))
            .given(format!("{out}/iso/nixos-25.11.iso"), "not really an iso")
            .given(
                format!("{out}/nix-support/hydra-build-products"),
                "file iso ...",
            );
        assert_eq!(
            medium_of(&files, out, ImageKind::Installer).unwrap(),
            Some(format!("{out}/iso/nixos-25.11.iso"))
        );

        // A bundle is three files and stays a directory.
        assert_eq!(medium_of(&files, out, ImageKind::DirectBoot).unwrap(), None);

        // Nothing that could be one is a sentence, not an empty answer.
        let empty = MemFiles::new()
            .given_other(format!("{out}/nix-support"))
            .given(format!("{out}/nix-support/x"), "x");
        let err = medium_of(&empty, out, ImageKind::Installer)
            .unwrap_err()
            .to_string();
        assert!(err.contains("holds no file ending in iso"), "{err}");

        // And two is a sentence that names both rather than a coin toss.
        let two = MemFiles::new()
            .given_other(format!("{out}/iso"))
            .given(format!("{out}/iso/a.iso"), "a")
            .given(format!("{out}/iso/b.iso"), "b");
        let err = medium_of(&two, out, ImageKind::Installer)
            .unwrap_err()
            .to_string();
        assert!(err.contains("a.iso"), "{err}");
        assert!(err.contains("b.iso"), "{err}");
    }

    #[test]
    fn a_required_check_that_is_a_derivation_is_built_and_the_others_are_not() {
        let mut fleet = one_host();
        fleet
            .hosts
            .get_mut("box")
            .unwrap()
            .checks
            .required
            .push("/nix/store/hhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhh-config-box.drv".to_string());
        let drvs = derivations(&fleet, &["box".to_string()]);
        let checks: Vec<&Derivation> = drvs.iter().filter(|d| d.kind == DrvKind::Check).collect();
        assert_eq!(checks.len(), 1);
        assert_eq!(
            checks[0].what, "config-box",
            "the id is the derivation name"
        );
    }

    #[test]
    fn a_build_of_a_managed_host_without_a_key_stops_before_it_starts() {
        let fleet = one_host();
        // A StrictFake with no expectations at all: if this ran one command,
        // the test would fail on the unexpected command instead.
        let runner = StrictFake::new();
        let files = files_with_config(&fleet);
        let clock = FakeClock::fixed();
        let builder = Builder {
            runner: &runner,
            files: &files,
            clock: &clock,
            options: BuildOptions::default(),
            state: None,
        };
        let err = builder.realise(fleet).unwrap_err().to_string();
        runner.verify().unwrap();
        assert!(err.contains("no signing key was given"), "{err}");
        assert!(err.contains("require-sigs"), "{err}");
        assert!(err.contains("--sign-key"), "{err}");
        assert!(err.contains("trustedPublicKeys"), "{err}");
        assert!(runner.calls().is_empty(), "{:?}", runner.calls());
    }

    // --- lane 4C: the cache ---------------------------------------------

    #[test]
    fn a_cache_without_a_signing_key_is_refused_before_anything_is_built() {
        let mut fleet = one_host();
        // A context fleet, so that the MANAGED-host rule is not what
        // refuses: what is under test is the cache's own rule.
        fleet.hosts.get_mut("box").unwrap().deployment = Deployment::Context;
        let runner = StrictFake::new();
        let files = files_with_config(&fleet);
        let clock = FakeClock::fixed();
        let builder = Builder {
            runner: &runner,
            files: &files,
            clock: &clock,
            options: BuildOptions {
                cache: Some("file:///srv/cache".to_string()),
                ..BuildOptions::default()
            },
            state: None,
        };
        let err = builder.realise(fleet).unwrap_err().to_string();
        runner.verify().unwrap();
        assert!(err.contains("file:///srv/cache"), "{err}");
        assert!(err.contains("require-sigs"), "{err}");
        assert!(err.contains("--sign-key"), "{err}");
        assert!(runner.calls().is_empty(), "{:?}", runner.calls());
    }

    #[test]
    fn a_build_with_a_cache_pushes_once_after_signing_and_says_so_in_the_release() {
        let fleet = one_host();
        let fleet_paths = fleet.clone();
        let runner = expect_build_into(&fleet, true, true, Some("file:///srv/cache"), None);
        let files = files_with_config(&fleet);
        let clock = FakeClock::fixed();
        let builder = Builder {
            runner: &runner,
            files: &files,
            clock: &clock,
            options: BuildOptions {
                sign_key: Some(PathBuf::from("/keys/fleet.sec")),
                cache: Some("file:///srv/cache".to_string()),
                ..BuildOptions::default()
            },
            state: None,
        };
        let built = builder.realise(fleet).expect("a green build with a cache");
        runner.verify().unwrap();

        let calls = runner.calls();
        let copies: Vec<&String> = calls.iter().filter(|c| c.starts_with("nix copy")).collect();
        assert_eq!(copies.len(), 1, "one push for the whole release: {calls:?}");
        // And it names every path the release names — the systems AND the
        // packages, because a host that fetches a system from a cache that
        // lacks half its closure has fetched nothing.
        for path in measured_paths(&fleet_paths) {
            assert!(copies[0].contains(&path), "{path} is not in {}", copies[0]);
        }
        // After the signing, because a cache of unsigned paths is a cache
        // every host refuses.
        let signed_at = calls.iter().position(|c| c.contains("store sign")).unwrap();
        let pushed_at = calls
            .iter()
            .position(|c| c.starts_with("nix copy"))
            .unwrap();
        assert!(signed_at < pushed_at, "{calls:?}");

        assert_eq!(
            built.release.build_env.cache_url.as_deref(),
            Some("file:///srv/cache")
        );
        assert_eq!(
            built.release.build_env.signing_key_name.as_deref(),
            Some("fleet-1"),
            "a target has to be told which key to trust"
        );
    }

    #[test]
    fn a_build_without_a_cache_runs_no_copy_at_all() {
        let fleet = one_host();
        // The strict fake has no `nix copy` expectation, so a probe, an
        // empty push or a "does the cache exist" round trip would fail here.
        let runner = expect_build(&fleet, true, true);
        let files = files_with_config(&fleet);
        let clock = FakeClock::fixed();
        let builder = Builder {
            runner: &runner,
            files: &files,
            clock: &clock,
            options: BuildOptions {
                sign_key: Some(PathBuf::from("/keys/fleet.sec")),
                ..BuildOptions::default()
            },
            state: None,
        };
        let built = builder.realise(fleet).expect("a green build");
        runner.verify().unwrap();
        assert!(
            !runner.calls().iter().any(|c| c.starts_with("nix copy")),
            "{:?}",
            runner.calls()
        );
        assert_eq!(built.release.build_env.cache_url, None);
    }

    #[test]
    fn without_the_flag_a_release_says_nobody_checked() {
        let fleet = one_host();
        // The strict fake expects no `--rebuild`, so a probe would fail here.
        let runner = expect_build(&fleet, true, true);
        let files = files_with_config(&fleet);
        let clock = FakeClock::fixed();
        let builder = Builder {
            runner: &runner,
            files: &files,
            clock: &clock,
            options: BuildOptions {
                sign_key: Some(PathBuf::from("/keys/fleet.sec")),
                ..BuildOptions::default()
            },
            state: None,
        };
        let built = builder.realise(fleet).expect("a green build");
        runner.verify().unwrap();
        let repro = &built.release.reproducibility;
        assert!(repro.inputs_pinned, "the tree was locked");
        assert!(!repro.bit_identical_verified);
        assert_eq!(
            repro.method, None,
            "null is what `nobody checked` looks like"
        );
        assert!(repro.differences.is_empty());
    }

    #[test]
    fn a_rebuild_that_matched_is_the_only_thing_that_sets_the_flag() {
        let fleet = one_host();
        let runner = expect_build_into(&fleet, true, true, None, Some(Output::stdout("")));
        let files = files_with_config(&fleet);
        let clock = FakeClock::fixed();
        let builder = Builder {
            runner: &runner,
            files: &files,
            clock: &clock,
            options: BuildOptions {
                sign_key: Some(PathBuf::from("/keys/fleet.sec")),
                verify_reproducible: true,
                ..BuildOptions::default()
            },
            state: None,
        };
        let built = builder.realise(fleet).expect("a green build");
        runner.verify().unwrap();
        let repro = &built.release.reproducibility;
        assert!(repro.bit_identical_verified);
        assert_eq!(repro.method.as_deref(), Some("nix build --rebuild"));
        assert!(repro.differences.is_empty());
    }

    #[test]
    fn a_rebuild_that_differed_is_a_finding_and_not_a_failure() {
        let fleet = one_host();
        let runner = expect_build_into(
            &fleet,
            true,
            true,
            None,
            Some(Output::failing(
                1,
                "error: derivation '/nix/store/dddd-nixos-system-box-25.11.drv' may not be \
                 deterministic: output '/nix/store/oooo-nixos-system-box-25.11' differs",
            )),
        );
        let files = files_with_config(&fleet);
        let clock = FakeClock::fixed();
        let builder = Builder {
            runner: &runner,
            files: &files,
            clock: &clock,
            options: BuildOptions {
                sign_key: Some(PathBuf::from("/keys/fleet.sec")),
                verify_reproducible: true,
                ..BuildOptions::default()
            },
            state: None,
        };
        // A release that is not bit-identical is still a release: what it
        // says about itself is the finding.
        let built = builder
            .realise(fleet)
            .expect("a build that is still a build");
        runner.verify().unwrap();
        let repro = &built.release.reproducibility;
        assert!(!repro.bit_identical_verified);
        assert_eq!(
            repro.method.as_deref(),
            Some("nix build --rebuild"),
            "checked-and-different has to be tellable from not-checked"
        );
        assert_eq!(repro.differences.len(), 1);
        assert!(
            repro.differences[0].starts_with("box ("),
            "{:?}",
            repro.differences
        );
        assert!(
            repro.differences[0].contains("may not be deterministic"),
            "{:?}",
            repro.differences
        );
    }

    #[test]
    fn a_rebuild_that_could_not_be_made_says_so_instead_of_answering_false() {
        let fleet = one_host();
        // Built by hand and not from `expect_build_into`: this build stops
        // AT the rebuild, so a fake that expected the steps after it would
        // fail on the unused expectations rather than on the finding.
        let mut pairs: Vec<(String, String)> = derivations(&fleet, &["box".to_string()])
            .into_iter()
            .map(|d| d.drv)
            .zip(outputs_in_derivation_order())
            .collect();
        pairs.sort_by(|a, b| a.0.cmp(&b.0));
        let runner = StrictFake::new()
            .expect(
                Matcher::prefix("nix", ["path-info", "--json"]),
                Output::stdout("{}"),
            )
            .expect(
                Matcher::prefix("nix", ["build", "--no-link", "--json"]),
                Output::stdout(build_json(&pairs)),
            )
            .expect(
                Matcher::prefix("nix", ["build", "--rebuild"]),
                Output::failing(
                    1,
                    "error: unable to start any build; either increase '--max-jobs' or \
                     enable remote builds",
                ),
            );
        let files = files_with_config(&fleet);
        let clock = FakeClock::fixed();
        let builder = Builder {
            runner: &runner,
            files: &files,
            clock: &clock,
            options: BuildOptions {
                sign_key: Some(PathBuf::from("/keys/fleet.sec")),
                verify_reproducible: true,
                ..BuildOptions::default()
            },
            state: None,
        };
        let err = builder.realise(fleet).unwrap_err().to_string();
        assert!(err.contains("could not be made"), "{err}");
        assert!(err.contains("unable to start any build"), "{err}");
        // And nothing was signed: the refusal came before the key was used.
        assert!(
            !runner.calls().iter().any(|c| c.contains("store sign")),
            "{:?}",
            runner.calls()
        );
    }

    // --- end lane 4C ----------------------------------------------------

    #[test]
    fn a_green_build_binds_what_the_manifest_promised() {
        let fleet = one_host();
        let manifest_id = fleet.manifest_id.clone();
        let runner = expect_build(&fleet, true, true);
        let files = files_with_config(&fleet);
        let clock = FakeClock::fixed();
        let builder = Builder {
            runner: &runner,
            files: &files,
            clock: &clock,
            options: BuildOptions {
                sign_key: Some(PathBuf::from("/keys/fleet.sec")),
                ..BuildOptions::default()
            },
            state: None,
        };
        let built = builder.realise(fleet).expect("a green build");
        runner.verify().unwrap();

        let release = &built.release;
        assert_eq!(release.manifest_id, manifest_id);
        assert_eq!(release.hosts(), vec!["box"]);
        let artifacts = &release.artifacts["box"];
        assert_eq!(artifacts.toplevel.store_path, TOPLEVEL);
        assert_eq!(artifacts.toplevel.nar_size, 1024);
        assert_eq!(artifacts.toplevel.closure_size, 2048);
        assert_eq!(artifacts.toplevel.signatures, vec!["fleet-1:abc"]);
        assert!(artifacts.installer_iso.is_none(), "build makes no image");
        // The three boot fields come from the manifest and are what the
        // reboot class is decided on.
        assert_eq!(
            artifacts.boot.kernel_params_sha256,
            release.resolved_fleet.hosts["box"]
                .build
                .boot
                .kernel_params_sha256
        );
        // The configuration files are measured by content.
        assert_eq!(artifacts.config_files.len(), 3);
        for file in artifacts.config_files.values() {
            assert_eq!(file.sha256, sha256_hex(b"[node]\nid = \"box\"\n"));
        }
        assert_eq!(release.packages.len(), 3);
        assert_eq!(release.build_env.nix_version, "nix (Nix) 2.35.2");
        assert_eq!(release.build_env.system, "x86_64-linux");
        assert!(release.build_env.sandbox);
        // The key's NAME travels; nothing else about the file does.
        assert_eq!(
            release.build_env.signing_key_name.as_deref(),
            Some("fleet-1")
        );
        let text = String::from_utf8(release.to_json().unwrap()).unwrap();
        assert!(!text.contains("c2VjcmV0"), "the key's content stays out");
        assert!(!text.contains("/keys/fleet.sec"), "so does its path");
        // And it is a release this tool reads back.
        ReleaseManifest::from_json(&text, "what this test built").expect("it reads back");
    }

    #[test]
    fn the_key_path_never_reaches_a_printed_line() {
        let cmd = sign_cmd(
            std::path::Path::new("/home/silas/keys/fleet.sec"),
            &[TOPLEVEL.to_string()],
        );
        let line = cmd.line();
        assert!(!line.contains("fleet.sec"), "{line}");
        assert!(line.contains("***"), "{line}");
        assert!(line.contains("--recursive"), "{line}");
        assert!(cmd.described().contains("***"));
        // Even when nix echoes it back in an error.
        assert_eq!(
            cmd.redacted("error: opening /home/silas/keys/fleet.sec: no such file"),
            "error: opening ***: no such file"
        );
    }

    #[test]
    fn a_context_host_needs_no_signature_because_no_closure_travels() {
        // The legacy push copies binaries into a running appliance; there
        // is no `nix copy` and nothing checks a signature. So a build of a
        // context-only fleet without a key is not refused.
        let mut fleet = one_host();
        fleet.hosts.get_mut("box").unwrap().deployment = Deployment::Context;
        fleet.manifest_id =
            crate::ids::content_id(crate::ids::IdKind::Manifest, &fleet).expect("it hashes");
        let runner = expect_build(&fleet, false, false);
        let files = files_with_config(&fleet);
        let clock = FakeClock::fixed();
        let builder = Builder {
            runner: &runner,
            files: &files,
            clock: &clock,
            options: BuildOptions::default(),
            state: None,
        };
        let built = builder
            .realise(fleet)
            .expect("a context host is not refused");
        runner.verify().unwrap();
        assert!(
            built.release.artifacts["box"]
                .toplevel
                .signatures
                .is_empty()
        );
        assert!(built.release.build_env.signing_key_name.is_none());
        assert!(
            !runner.calls().iter().any(|c| c.contains("store sign")),
            "{:?}",
            runner.calls()
        );
    }

    #[test]
    fn a_managed_system_that_carries_no_signature_after_signing_is_refused() {
        // A key WAS given and the store has no signature afterwards: a
        // `nix store sign` that signed something else, a key nix did not
        // accept. The release would name a path no managed host will take.
        let fleet = one_host();
        let runner = expect_build(&fleet, true, false);
        let files = files_with_config(&fleet);
        let clock = FakeClock::fixed();
        let builder = Builder {
            runner: &runner,
            files: &files,
            clock: &clock,
            options: BuildOptions {
                sign_key: Some(PathBuf::from("/keys/fleet.sec")),
                ..BuildOptions::default()
            },
            state: None,
        };
        let err = builder.realise(fleet).unwrap_err().to_string();
        // The three `nix config show` expectations are deliberately left
        // unused: the refusal came before a `build_env` was gathered, which
        // is where it should come.
        assert!(runner.verify().is_err());
        assert!(err.contains("holds no signature for"), "{err}");
        assert!(err.contains("--sign-key"), "{err}");
    }

    #[test]
    fn a_missing_derivation_says_resolve_again_and_names_it() {
        let fleet = one_host();
        let drvs: Vec<String> = derivations(&fleet, &["box".to_string()])
            .into_iter()
            .map(|d| d.drv)
            .collect();
        let mut runner = StrictFake::new().expect(
            Matcher::prefix("nix", ["path-info", "--json"]),
            Output::failing(1, "error: path '/nix/store/dddd…' does not exist"),
        );
        // Then one question per derivation, to name the ones that are gone.
        for drv in &drvs {
            runner = runner.expect(
                Matcher::exact(
                    "nix",
                    ["path-info".to_string(), "--json".to_string(), drv.clone()],
                ),
                if drv.starts_with(DRV) {
                    Output::failing(1, "error: path does not exist")
                } else {
                    Output::stdout("{}")
                },
            );
        }
        let files = files_with_config(&fleet);
        let clock = FakeClock::fixed();
        let builder = Builder {
            runner: &runner,
            files: &files,
            clock: &clock,
            options: BuildOptions {
                sign_key: Some(PathBuf::from("/keys/fleet.sec")),
                ..BuildOptions::default()
            },
            state: None,
        };
        let err = builder.realise(fleet).unwrap_err().to_string();
        runner.verify().unwrap();
        assert!(err.contains("resolve again"), "{err}");
        assert!(err.contains(DRV), "{err}");
        assert!(err.contains("(for box)"), "{err}");
        assert!(err.contains("only re-evaluated"), "{err}");
    }

    #[test]
    fn a_build_that_produced_something_else_is_refused_with_both_paths() {
        let fleet = one_host();
        let drvs: Vec<String> = derivations(&fleet, &["box".to_string()])
            .into_iter()
            .map(|d| d.drv)
            .collect();
        let mut runner = StrictFake::new().expect(
            Matcher::prefix("nix", ["path-info", "--json"]),
            Output::stdout("{}"),
        );
        let mut pairs: Vec<(String, String)> = drvs
            .iter()
            .enumerate()
            .map(|(i, drv)| {
                (
                    drv.clone(),
                    if i == 0 {
                        "/nix/store/somethingelse-nixos-system-box-25.11".to_string()
                    } else {
                        format!("/nix/store/pkg{i}-package")
                    },
                )
            })
            .collect();
        pairs.sort_by(|a, b| a.0.cmp(&b.0));
        runner = runner.expect(
            Matcher::exact(
                "nix",
                [
                    "build".to_string(),
                    "--no-link".to_string(),
                    "--json".to_string(),
                ]
                .into_iter()
                .chain(pairs.iter().map(|(drv, _)| format!("{drv}^*")))
                .collect::<Vec<_>>(),
            ),
            Output::stdout(build_json(&pairs)),
        );
        let files = files_with_config(&fleet);
        let clock = FakeClock::fixed();
        let builder = Builder {
            runner: &runner,
            files: &files,
            clock: &clock,
            options: BuildOptions {
                sign_key: Some(PathBuf::from("/keys/fleet.sec")),
                ..BuildOptions::default()
            },
            state: None,
        };
        let err = builder.realise(fleet).unwrap_err().to_string();
        runner.verify().unwrap();
        assert!(err.contains("somethingelse"), "{err}");
        assert!(err.contains("binds what the manifest evaluated"), "{err}");
        // Nothing was signed: the refusal came before the key was used.
        assert!(
            !runner.calls().iter().any(|c| c.contains("store sign")),
            "{:?}",
            runner.calls()
        );
    }

    #[test]
    fn a_build_of_part_of_a_fleet_is_not_a_release_and_says_what_to_do() {
        let fleet = onebox_enrolled();
        let drv = fleet.hosts["n1"].build.toplevel_drv.clone();
        let out = fleet.hosts["n1"].build.toplevel_out.clone();
        let mut runner = StrictFake::new().expect(
            Matcher::prefix("nix", ["path-info", "--json"]),
            Output::stdout("{}"),
        );
        let mut pairs: Vec<(String, String)> = vec![(drv.clone(), out.clone())];
        for name in ["meisterstack", "cloud_hypervisor", "guest_tiny"] {
            let drv = match name {
                "meisterstack" => fleet.packages.meisterstack.drv.clone(),
                "cloud_hypervisor" => fleet.packages.cloud_hypervisor.drv.clone(),
                _ => fleet.packages.guest_tiny.drv.clone(),
            };
            pairs.push((drv, format!("/nix/store/{name}-out")));
        }
        pairs.sort_by(|a, b| a.0.cmp(&b.0));
        runner = runner.expect(
            Matcher::exact(
                "nix",
                [
                    "build".to_string(),
                    "--no-link".to_string(),
                    "--json".to_string(),
                ]
                .into_iter()
                .chain(pairs.iter().map(|(d, _)| format!("{d}^*")))
                .collect::<Vec<_>>(),
            ),
            Output::stdout(build_json(&pairs)),
        );
        let files = files_with_config(&fleet);
        let clock = FakeClock::fixed();
        let builder = Builder {
            runner: &runner,
            files: &files,
            clock: &clock,
            options: BuildOptions {
                sign_key: Some(PathBuf::from("/keys/fleet.sec")),
                hosts: Some(vec!["n1".to_string()]),
                ..BuildOptions::default()
            },
            state: None,
        };
        let err = builder.realise(fleet).unwrap_err().to_string();
        runner.verify().unwrap();
        assert!(err.contains("built 1 of the manifest's 3 host(s)"), "{err}");
        assert!(err.contains("resolve --hosts n1"), "{err}");
        assert!(
            err.contains(&out),
            "the system it did build is named: {err}"
        );
    }

    #[test]
    fn a_host_the_manifest_never_evaluated_cannot_be_built() {
        let fleet = one_host();
        let runner = StrictFake::new();
        let files = files_with_config(&fleet);
        let clock = FakeClock::fixed();
        let builder = Builder {
            runner: &runner,
            files: &files,
            clock: &clock,
            options: BuildOptions {
                hosts: Some(vec!["n9".to_string()]),
                sign_key: Some(PathBuf::from("/keys/fleet.sec")),
                ..BuildOptions::default()
            },
            state: None,
        };
        let err = builder.realise(fleet).unwrap_err().to_string();
        runner.verify().unwrap();
        assert!(err.contains("knows nothing about n9"), "{err}");
        assert!(err.contains("it evaluated box"), "{err}");
    }

    #[test]
    fn a_configuration_file_that_is_not_in_the_store_is_a_sentence() {
        let fleet = one_host();
        let runner = expect_build(&fleet, false, false);
        // The store has no agent.toml: a build whose closure does not carry
        // the file a unit reads is a build nobody can apply.
        let files = MemFiles::new().given("/keys/fleet.sec", b"fleet-1:c2VjcmV0\n".to_vec());
        let clock = FakeClock::fixed();
        let builder = Builder {
            runner: &runner,
            files: &files,
            clock: &clock,
            options: BuildOptions {
                sign_key: Some(PathBuf::from("/keys/fleet.sec")),
                ..BuildOptions::default()
            },
            state: None,
        };
        let err = builder.realise(fleet).unwrap_err().to_string();
        // The expectations after the configuration step go unused, and that
        // is the point: the refusal came before the signing.
        assert!(runner.verify().is_err());
        assert!(err.contains("is not in the store after the build"), "{err}");
        assert!(err.contains("one derivation's job"), "{err}");
    }

    #[test]
    fn path_info_is_read_in_both_of_the_shapes_nix_produces() {
        let v1 = r#"{"/nix/store/aaa-system":{"narHash":"sha256-abc","narSize":10,
             "closureSize":20,"signatures":["k:sig"],"ca":null}}"#;
        let v2 = r#"{"version":2,"storeDir":"/nix/store","info":{"aaa-system":{
             "narHash":"sha256-abc","narSize":10,"closureSize":20,"signatures":["k:sig"]}}}"#;
        let first = parse_path_info(v1, "v1").unwrap();
        let second = parse_path_info(v2, "v2").unwrap();
        assert_eq!(first, second, "the same answer in two spellings");
        let info = &first["/nix/store/aaa-system"];
        assert_eq!(info.nar_hash, "sha256-abc");
        assert_eq!(info.closure_size, 20);
        assert_eq!(info.signatures, vec!["k:sig"]);
    }

    #[test]
    fn a_path_info_answer_without_a_hash_is_refused_rather_than_guessed() {
        let err = parse_path_info(
            r#"{"/nix/store/aaa-system":{"narSize":10}}"#,
            "a nix that said nothing",
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("says nothing about the contents"), "{err}");
    }

    #[test]
    fn a_dry_run_builds_nothing_and_a_refused_one_is_not_a_success() {
        let fleet = one_host();
        // A dry run may ASK whether the derivations are in the store — that
        // is a read — and may not build them.
        let runner = StrictFake::new().with_policy(Policy::dry_run()).expect(
            Matcher::prefix("nix", ["path-info", "--json"]),
            Output::stdout("{}"),
        );
        let files = files_with_config(&fleet);
        let clock = FakeClock::fixed();
        let builder = Builder {
            runner: &runner,
            files: &files,
            clock: &clock,
            options: BuildOptions {
                sign_key: Some(PathBuf::from("/keys/fleet.sec")),
                ..BuildOptions::default()
            },
            state: None,
        };
        // A dry run is supposed to print the list and stop, which `main`
        // does. If somebody ever calls `realise` under a dry-run policy
        // anyway, the door refuses the build rather than reporting one.
        let err = builder.realise(fleet).unwrap_err().to_string();
        runner.verify().unwrap();
        assert!(err.contains("--dry-run"), "{err}");
        assert!(err.contains("was not run"), "{err}");
        assert!(
            runner.calls().iter().all(|c| !c.contains("nix build")),
            "{:?}",
            runner.calls()
        );
    }

    #[test]
    fn a_release_is_protected_by_a_root_for_every_path_it_names() {
        let fleet = one_host();
        let mut runner = expect_build(&fleet, true, true);
        let state = StateDir::in_repo(std::path::Path::new("/repo"));
        // One root per host and one per package, then the stamp.
        for name in [
            "box",
            "pkg-cloud-hypervisor",
            "pkg-guest-tiny",
            "pkg-meisterstack",
        ] {
            runner = runner.expect(
                Matcher::prefix("nix-store", ["--realise", "--add-root"]),
                Output::stdout(format!("/nix/store/{name}\n")),
            );
        }
        let files = files_with_config(&fleet);
        let clock = FakeClock::fixed();
        let builder = Builder {
            runner: &runner,
            files: &files,
            clock: &clock,
            options: BuildOptions {
                sign_key: Some(PathBuf::from("/keys/fleet.sec")),
                ..BuildOptions::default()
            },
            state: Some(state.clone()),
        };
        let built = builder.realise(fleet).expect("a green build");
        runner.verify().unwrap();
        let dir = state.gcroot_dir(&built.release.release_id);
        assert_eq!(built.roots.len(), 4, "{:?}", built.roots);
        assert!(built.roots.contains(&dir.join("box")));
        assert!(built.roots.contains(&dir.join("pkg-meisterstack")));
        // And the directory is dated, because a release id is a content
        // hash and says nothing about when.
        let stamp = String::from_utf8(files.content(dir.join(STAMP)).unwrap()).unwrap();
        assert!(stamp.starts_with("2026-01-01T00:00:00"), "{stamp}");
    }

    #[test]
    fn the_roots_of_a_directory_are_read_back_newest_last() {
        let files = MemFiles::new()
            .given(
                "/repo/.meister-deploy/gcroots/release-a/.created",
                b"2026-09-01T00:00:00Z\n".to_vec(),
            )
            .given_symlink(
                "/repo/.meister-deploy/gcroots/release-a/box",
                "/nix/store/aaa-system",
            )
            .given(
                "/repo/.meister-deploy/gcroots/release-b/.created",
                b"2026-09-21T00:00:00Z\n".to_vec(),
            )
            .given_symlink(
                "/repo/.meister-deploy/gcroots/release-b/box",
                "/nix/store/bbb-system",
            );
        let state = StateDir::in_repo(std::path::Path::new("/repo"));
        let all = roots(&files, &state).unwrap();
        assert_eq!(
            all.iter()
                .map(|r| r.release_id.as_str())
                .collect::<Vec<_>>(),
            vec!["release-a", "release-b"]
        );
        assert_eq!(all[0].links.len(), 1, "the stamp is not a root");
        assert!(all[0].links[0].ends_with("box"));

        // What is DONE with them is `state::sweep` / `state::carry_out`,
        // which is where the whole retention decision lives; here it is
        // driven directly so that this test stays about the reader.
        let sweep = crate::state::sweep(
            &files,
            &state,
            &all,
            &crate::state::Retention {
                keep: 1,
                ..crate::state::Retention::default()
            },
            crate::fixtures::at("2026-09-22T00:00:00Z"),
        )
        .unwrap();
        assert_eq!(sweep.removals_of("release").len(), 1);
        crate::state::carry_out(&files, &sweep).unwrap();
        assert!(
            !files.exists(std::path::Path::new(
                "/repo/.meister-deploy/gcroots/release-a/box"
            )),
            "the link is gone"
        );
        // And nothing was done to the store path itself: whether it goes
        // is `nix store gc`'s decision, not this tool's.
        assert!(
            !files
                .attempts()
                .iter()
                .any(|a| a.contains("/nix/store/aaa-system")),
            "{:?}",
            files.attempts()
        );
    }
}
