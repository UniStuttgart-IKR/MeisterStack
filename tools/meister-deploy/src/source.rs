// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Which tree this manifest came out of, said precisely enough to come back.
//!
//! A receipt that says "deployed from the operator repository" is worth
//! nothing six months later. What is worth something is a revision and a tree
//! hash, and the honest admission when there is neither.
//!
//! The hard case is a dirty working tree, and it is hard for a reason that is
//! easy to miss: `nix` reading a `git+file://` flake sees only what git
//! tracks. An untracked `profiles/new.nix` is invisible to the evaluation and
//! present in the operator's editor, so the two disagree in silence. This
//! module therefore refuses a dirty tree outright, and `--dev` is the way to
//! say "yes, I know" — at the price of a content snapshot, a secret scan and
//! a `dev:` fingerprint that cannot be mistaken for a revision.

use std::collections::BTreeMap;
use std::path::Path;
use std::time::Duration;

use anyhow::{Result, bail};
use sha2::{Digest, Sha256};

use crate::effects::Files;
use crate::ids::{hex, sha256_hex};
use crate::manifest::{DevMode, FlakeInput, SecretScan, Source};
use crate::run::{Cmd, Effect, Runner};

/// Git answers in milliseconds on any tree this tool will meet; a minute is
/// there for the case where it is answering from a cold network filesystem.
const GIT_DEADLINE: Duration = Duration::from_secs(60);

/// What a dirty tree looked like, before it was refused or snapshotted.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Worktree {
    pub modified: Vec<String>,
    pub untracked: Vec<String>,
}

impl Worktree {
    pub fn is_clean(&self) -> bool {
        self.modified.is_empty() && self.untracked.is_empty()
    }
}

/// Read the repository and say where the manifest comes from.
///
/// `repo` is absolute — a relative one would make `repo_path` in the manifest
/// depend on the directory somebody happened to stand in. `inventory` is
/// relative to it.
pub fn describe(
    runner: &dyn Runner,
    files: &dyn Files,
    repo: &Path,
    inventory: &Path,
    dev: bool,
) -> Result<Source> {
    if !repo.is_absolute() {
        bail!(
            "{} is not an absolute path, and a manifest has to name the tree it came \
             from in a way that does not depend on anybody's working directory.",
            repo.display()
        );
    }
    let rev = git(runner, repo, &["rev-parse", "HEAD"])?;
    // `HEAD^{tree}` and not HEAD: two commits with different messages and the
    // same content build the same system, and the tree hash is what says so.
    let tree = git(runner, repo, &["rev-parse", "HEAD^{tree}"])?;
    let worktree = status(runner, repo)?;

    let inventory_path = inventory.to_string_lossy().into_owned();
    let inventory_bytes = files.read(&repo.join(inventory))?;
    let inventory_sha256 = sha256_hex(&inventory_bytes);
    let flake_lock = read_flake_lock(files, repo)?;

    if worktree.is_clean() {
        return Ok(Source {
            repo_path: repo.to_string_lossy().into_owned(),
            git_rev: Some(rev.clone()),
            tree_hash: Some(tree.clone()),
            dirty: false,
            fingerprint: format!("git:{rev}:{tree}"),
            dev_mode: None,
            flake_lock,
            inventory_path,
            inventory_sha256,
        });
    }

    if !dev {
        bail!("{}", dirty_refusal(repo, &worktree));
    }

    let snapshot = snapshot(runner, files, repo)?;
    if !snapshot.secret_scan.ok {
        bail!(
            "the working tree of {} carries what looks like key material: {}. \
             A --dev resolve copies the whole tree into the nix store, where it is \
             world-readable and stays. Move the keys out of the repository, or commit \
             the tree and resolve without --dev.",
            repo.display(),
            snapshot.secret_scan.hits.join(", ")
        );
    }

    Ok(Source {
        repo_path: repo.to_string_lossy().into_owned(),
        git_rev: Some(rev),
        tree_hash: Some(tree),
        dirty: true,
        // A different namespace on purpose: `dev:` in a receipt means nobody
        // can check this tree out again, and that has to be unmissable.
        fingerprint: format!("dev:{}", snapshot.content_hash),
        dev_mode: Some(snapshot),
        flake_lock,
        inventory_path,
        inventory_sha256,
    })
}

fn dirty_refusal(repo: &Path, worktree: &Worktree) -> String {
    let mut out = format!(
        "the working tree of {} has uncommitted changes, so a manifest resolved from \
         it could not be resolved again.",
        repo.display()
    );
    if !worktree.modified.is_empty() {
        out.push_str(&format!("\n  changed: {}", worktree.modified.join(", ")));
    }
    if !worktree.untracked.is_empty() {
        out.push_str(&format!(
            "\n  untracked: {} — nix would silently ignore these, so the system it \
             builds would not be the one on your disk",
            worktree.untracked.join(", ")
        ));
    }
    out.push_str(
        "\n  Commit them, or resolve with --dev, which records a content snapshot instead.",
    );
    out
}

fn git_cmd(repo: &Path, args: &[&str]) -> Cmd {
    Cmd::new(Effect::Read, "git", GIT_DEADLINE)
        .args(args.iter().copied())
        .cwd(repo)
}

fn git(runner: &dyn Runner, repo: &Path, args: &[&str]) -> Result<String> {
    let out = runner.run(&git_cmd(repo, args))?;
    Ok(out.trimmed().to_string())
}

/// Every command line a [`describe`] would run, in order.
///
/// This is what `--dry-run` prints: the argv itself, not a sentence about it,
/// so that an operator can paste any of these lines and see the same answer
/// this tool would have seen. `a_dry_run_lists_exactly_what_a_real_one_runs`
/// keeps the list and the code from drifting.
pub fn commands(repo: &Path, dev: bool) -> Vec<Cmd> {
    let mut out = vec![
        git_cmd(repo, &["rev-parse", "HEAD"]),
        git_cmd(repo, &["rev-parse", "HEAD^{tree}"]),
        git_cmd(repo, &["status", "--porcelain=v1", "-z"]),
    ];
    if dev {
        out.push(git_cmd(
            repo,
            &["ls-files", "-co", "--exclude-standard", "-z"],
        ));
        out.push(git_cmd(repo, &["status", "--porcelain=v1", "-z"]));
    }
    out
}

/// `--porcelain=v1 -z`: a stable format, and NUL-separated because a path may
/// contain a newline and the non-`-z` form would quote it into something this
/// parser would have to unquote.
fn status(runner: &dyn Runner, repo: &Path) -> Result<Worktree> {
    let out = runner.run(&git_cmd(repo, &["status", "--porcelain=v1", "-z"]))?;
    let mut worktree = Worktree::default();
    let mut entries = out.stdout.split('\0').filter(|e| !e.is_empty());
    while let Some(entry) = entries.next() {
        if entry.len() < 4 {
            continue;
        }
        let code = &entry[..2];
        let path = entry[3..].to_string();
        // A rename or a copy is two NUL-terminated paths; the second one
        // carries no status code and would otherwise be read as a file
        // called "/old/path".
        if code.starts_with('R') || code.starts_with('C') {
            let _ = entries.next();
        }
        if code == "??" {
            worktree.untracked.push(path);
        } else {
            worktree.modified.push(path);
        }
    }
    worktree.modified.sort();
    worktree.untracked.sort();
    Ok(worktree)
}

/// Everything git would show plus everything it would not: `-c` is cached,
/// `-o` is other, `--exclude-standard` drops what `.gitignore` drops. The
/// hash covers path AND content, so moving a file is a different snapshot.
fn snapshot(runner: &dyn Runner, files: &dyn Files, repo: &Path) -> Result<DevMode> {
    let listing = runner.run(&git_cmd(
        repo,
        &["ls-files", "-co", "--exclude-standard", "-z"],
    ))?;
    let mut paths: Vec<String> = listing
        .stdout
        .split('\0')
        .filter(|e| !e.is_empty())
        .map(str::to_string)
        .collect();
    paths.sort();
    paths.dedup();

    let mut hasher = Sha256::new();
    let mut hits = Vec::new();
    for path in &paths {
        let bytes = files.read(&repo.join(path))?;
        // Length-prefixed and NUL-separated, so that "ab" + "c" and "a" +
        // "bc" cannot hash to the same snapshot.
        hasher.update(path.as_bytes());
        hasher.update(b"\0");
        hasher.update(bytes.len().to_string().as_bytes());
        hasher.update(b"\0");
        hasher.update(&bytes);
        if looks_like_a_secret(path, &bytes) {
            hits.push(path.clone());
        }
    }

    let untracked = status(runner, repo)?.untracked;
    Ok(DevMode {
        content_hash: hex(&hasher.finalize()),
        untracked_files: untracked,
        secret_scan: SecretScan {
            ok: hits.is_empty(),
            hits,
        },
    })
}

/// Two rules, and the second one is the one that catches the file nobody
/// named `.key`: anything whose bytes carry a PEM private key header.
fn looks_like_a_secret(path: &str, bytes: &[u8]) -> bool {
    let name = path.rsplit('/').next().unwrap_or(path);
    if name.ends_with(".key") || name == "secrets.key" {
        return true;
    }
    // Only text files are searched, and only the first part of them: a
    // private key header is at the top of a PEM file, and a multi-megabyte
    // binary is not a PEM file.
    let head = &bytes[..bytes.len().min(64 * 1024)];
    let Ok(text) = std::str::from_utf8(head) else {
        return false;
    };
    text.lines().any(|line| line.contains("PRIVATE KEY"))
}

/// The inputs as the lock file pins them. Not the tool's own dependencies —
/// the operator's, because a changed nixpkgs is a changed fleet and the
/// manifest has to say which one it meant.
fn read_flake_lock(files: &dyn Files, repo: &Path) -> Result<BTreeMap<String, FlakeInput>> {
    let path = repo.join("flake.lock");
    if !files.exists(&path) {
        bail!(
            "{} has no flake.lock. Without one, `nix eval` would resolve the inputs \
             against whatever is current today and write a lock file as a side effect, \
             and the manifest could not say what it was built against. Run \
             `nix flake lock` in the repository first.",
            repo.display()
        );
    }
    let text = files.read_to_string(&path)?;
    let lock: serde_json::Value = serde_json::from_str(&text)
        .map_err(|e| anyhow::anyhow!("{} is not valid json: {e}", path.display()))?;

    let nodes = lock
        .get("nodes")
        .and_then(|n| n.as_object())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "{} has no `nodes` object; this is not a flake lock.",
                path.display()
            )
        })?;
    let root_name = lock.get("root").and_then(|r| r.as_str()).unwrap_or("root");
    let root = nodes
        .get(root_name)
        .and_then(|n| n.get("inputs"))
        .and_then(|i| i.as_object());
    let Some(root) = root else {
        // A flake with no inputs at all is unusual but legal.
        return Ok(BTreeMap::new());
    };

    let mut out = BTreeMap::new();
    for (name, target) in root {
        let Some(key) = target.as_str() else {
            bail!(
                "{}: the input {name:?} of the root node is a follows path, and this \
                 tool reads only direct inputs. Say what it follows in the flake, or \
                 report this lock file.",
                path.display()
            );
        };
        let locked = nodes
            .get(key)
            .and_then(|n| n.get("locked"))
            .ok_or_else(|| {
                anyhow::anyhow!("{}: the input {name:?} has no locked node.", path.display())
            })?;
        out.insert(
            name.clone(),
            FlakeInput {
                url: flake_url(locked),
                rev: locked
                    .get("rev")
                    .and_then(|r| r.as_str())
                    .map(str::to_string),
                nar_hash: locked
                    .get("narHash")
                    .and_then(|h| h.as_str())
                    .unwrap_or_default()
                    .to_string(),
            },
        );
    }
    Ok(out)
}

/// The locked input as a flake reference a person can paste. Where the shape
/// is not one of the known ones, the locked node is written out canonically
/// rather than guessed at: an invented url in a manifest is worse than an
/// ugly one.
fn flake_url(locked: &serde_json::Value) -> String {
    let field = |name: &str| {
        locked
            .get(name)
            .and_then(|v| v.as_str())
            .map(str::to_string)
    };
    let kind = field("type").unwrap_or_default();
    match kind.as_str() {
        "github" | "gitlab" | "sourcehut" => {
            let owner = field("owner").unwrap_or_default();
            let repo = field("repo").unwrap_or_default();
            match field("rev") {
                Some(rev) => format!("{kind}:{owner}/{repo}/{rev}"),
                None => format!("{kind}:{owner}/{repo}"),
            }
        }
        "git" | "mercurial" => {
            let url = field("url").unwrap_or_default();
            match field("rev") {
                Some(rev) => format!("{kind}+{url}?rev={rev}"),
                None => format!("{kind}+{url}"),
            }
        }
        "path" => format!("path:{}", field("path").unwrap_or_default()),
        "tarball" | "file" => field("url").unwrap_or_default(),
        "indirect" => {
            let id = field("id").unwrap_or_default();
            match field("rev") {
                Some(rev) => format!("flake:{id}/{rev}"),
                None => format!("flake:{id}"),
            }
        }
        _ => crate::canonical::to_string(locked),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::effects::MemFiles;
    use crate::run::{Matcher, Output, StrictFake};
    use std::path::PathBuf;

    const REV: &str = "f83cd70e0b1d1f0b4c8b9c2a0a1b2c3d4e5f6071";
    const TREE: &str = "8a1c2b3d4e5f60718293a4b5c6d7e8f901234567";

    const LOCK: &str = r#"{
      "nodes": {
        "nixpkgs": {
          "locked": {"lastModified": 1, "narHash": "sha256-aaa=", "owner": "NixOS",
                     "repo": "nixpkgs", "rev": "b6018f87", "type": "github"},
          "original": {"owner": "NixOS", "repo": "nixpkgs", "type": "github"}
        },
        "meisterstack": {
          "locked": {"lastModified": 2, "narHash": "sha256-bbb=",
                     "url": "file:///home/silas/git/MeisterStack", "rev": "f83cd70",
                     "type": "git"},
          "original": {"type": "git", "url": "file:///home/silas/git/MeisterStack"}
        },
        "root": {"inputs": {"nixpkgs": "nixpkgs", "meisterstack": "meisterstack"}}
      },
      "root": "root",
      "version": 7
    }"#;

    fn repo() -> PathBuf {
        PathBuf::from("/home/silas/git/meisterstack-lab")
    }

    fn base_files() -> MemFiles {
        MemFiles::new()
            .given(repo().join("fleet.toml"), "schema = 2\n")
            .given(repo().join("flake.lock"), LOCK)
    }

    fn clean_git() -> StrictFake {
        StrictFake::new()
            .expect(
                Matcher::exact("git", ["rev-parse", "HEAD"]),
                Output::stdout(format!("{REV}\n")),
            )
            .expect(
                Matcher::exact("git", ["rev-parse", "HEAD^{tree}"]),
                Output::stdout(format!("{TREE}\n")),
            )
            .expect(
                Matcher::exact("git", ["status", "--porcelain=v1", "-z"]),
                Output::stdout(""),
            )
    }

    #[test]
    fn a_clean_tree_is_named_by_its_revision_and_its_tree() {
        let runner = clean_git();
        let files = base_files();
        let source = describe(&runner, &files, &repo(), Path::new("fleet.toml"), false).unwrap();
        runner.verify().unwrap();

        assert!(!source.dirty);
        assert_eq!(source.git_rev.as_deref(), Some(REV));
        assert_eq!(source.fingerprint, format!("git:{REV}:{TREE}"));
        assert!(source.dev_mode.is_none());
        assert_eq!(source.inventory_path, "fleet.toml");
        assert_eq!(
            source.inventory_sha256,
            crate::ids::sha256_hex(b"schema = 2\n")
        );
        assert_eq!(source.flake_lock.len(), 2);
        assert_eq!(
            source.flake_lock["nixpkgs"].url,
            "github:NixOS/nixpkgs/b6018f87"
        );
        assert_eq!(
            source.flake_lock["meisterstack"].url,
            "git+file:///home/silas/git/MeisterStack?rev=f83cd70"
        );
        assert_eq!(source.flake_lock["nixpkgs"].nar_hash, "sha256-aaa=");
    }

    #[test]
    fn git_is_asked_inside_the_repository_and_nowhere_else() {
        let runner = clean_git();
        let files = base_files();
        describe(&runner, &files, &repo(), Path::new("fleet.toml"), false).unwrap();
        runner.verify().unwrap();
        // Every read was under the repository that was asked for; nothing
        // resolved relative to whatever directory the operator stood in.
        for path in files.paths() {
            assert!(path.starts_with(repo()), "{}", path.display());
        }
    }

    #[test]
    fn a_dry_run_lists_exactly_what_a_real_one_runs() {
        let runner = clean_git();
        let files = base_files();
        describe(&runner, &files, &repo(), Path::new("fleet.toml"), false).unwrap();
        let listed: Vec<String> = commands(&repo(), false).iter().map(|c| c.line()).collect();
        assert_eq!(runner.calls(), listed);

        let files = base_files().given(repo().join("profiles/new.nix"), "{ }\n");
        let source = dirty_dev(files, "fleet.toml\0profiles/new.nix\0");
        assert!(source.is_ok());
        let listed: Vec<String> = commands(&repo(), true).iter().map(|c| c.line()).collect();
        assert_eq!(listed.len(), 5, "{listed:?}");
    }

    #[test]
    fn a_relative_repository_is_refused() {
        let runner = StrictFake::new();
        let files = MemFiles::new();
        let err = describe(
            &runner,
            &files,
            Path::new("../lab"),
            Path::new("fleet.toml"),
            false,
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("absolute"), "{err}");
    }

    #[test]
    fn a_dirty_tree_is_refused_and_the_untracked_files_are_named() {
        let runner = StrictFake::new()
            .expect(
                Matcher::exact("git", ["rev-parse", "HEAD"]),
                Output::stdout(REV),
            )
            .expect(
                Matcher::exact("git", ["rev-parse", "HEAD^{tree}"]),
                Output::stdout(TREE),
            )
            .expect(
                Matcher::exact("git", ["status", "--porcelain=v1", "-z"]),
                Output::stdout(" M fleet.toml\0?? profiles/new.nix\0"),
            );
        let files = base_files();
        let err = describe(&runner, &files, &repo(), Path::new("fleet.toml"), false)
            .unwrap_err()
            .to_string();
        runner.verify().unwrap();
        assert!(err.contains("changed: fleet.toml"), "{err}");
        assert!(err.contains("untracked: profiles/new.nix"), "{err}");
        assert!(err.contains("nix would silently ignore these"), "{err}");
        assert!(err.contains("--dev"), "{err}");
    }

    #[test]
    fn a_rename_is_one_changed_file_and_not_two() {
        let runner = StrictFake::new()
            .expect(
                Matcher::exact("git", ["rev-parse", "HEAD"]),
                Output::stdout(REV),
            )
            .expect(
                Matcher::exact("git", ["rev-parse", "HEAD^{tree}"]),
                Output::stdout(TREE),
            )
            .expect(
                Matcher::exact("git", ["status", "--porcelain=v1", "-z"]),
                Output::stdout("R  hosts/new.nix\0hosts/old.nix\0"),
            );
        let files = base_files();
        let err = describe(&runner, &files, &repo(), Path::new("fleet.toml"), false)
            .unwrap_err()
            .to_string();
        assert!(err.contains("changed: hosts/new.nix"), "{err}");
        assert!(!err.contains("hosts/old.nix"), "{err}");
    }

    fn dirty_dev(files: MemFiles, listing: &str) -> Result<Source> {
        let runner = StrictFake::new()
            .expect(
                Matcher::exact("git", ["rev-parse", "HEAD"]),
                Output::stdout(REV),
            )
            .expect(
                Matcher::exact("git", ["rev-parse", "HEAD^{tree}"]),
                Output::stdout(TREE),
            )
            .expect(
                Matcher::exact("git", ["status", "--porcelain=v1", "-z"]),
                Output::stdout("?? profiles/new.nix\0"),
            )
            .expect(
                Matcher::exact("git", ["ls-files", "-co", "--exclude-standard", "-z"]),
                Output::stdout(listing),
            )
            .expect(
                Matcher::exact("git", ["status", "--porcelain=v1", "-z"]),
                Output::stdout("?? profiles/new.nix\0"),
            );
        let out = describe(&runner, &files, &repo(), Path::new("fleet.toml"), true);
        let _ = runner.verify();
        out
    }

    #[test]
    fn dev_mode_records_a_snapshot_of_what_is_really_there() {
        let files = base_files().given(repo().join("profiles/new.nix"), "{ }\n");
        let source = dirty_dev(files, "fleet.toml\0profiles/new.nix\0").unwrap();
        assert!(source.dirty);
        assert!(
            source.fingerprint.starts_with("dev:"),
            "{}",
            source.fingerprint
        );
        let dev = source.dev_mode.unwrap();
        assert_eq!(dev.untracked_files, vec!["profiles/new.nix"]);
        assert!(dev.secret_scan.ok);
        assert_eq!(dev.content_hash.len(), 64);
    }

    #[test]
    fn a_changed_byte_is_a_changed_snapshot() {
        let a = dirty_dev(
            base_files().given(repo().join("profiles/new.nix"), "{ }\n"),
            "fleet.toml\0profiles/new.nix\0",
        )
        .unwrap();
        let b = dirty_dev(
            base_files().given(repo().join("profiles/new.nix"), "{ } \n"),
            "fleet.toml\0profiles/new.nix\0",
        )
        .unwrap();
        assert_ne!(a.fingerprint, b.fingerprint);
    }

    #[test]
    fn moving_a_file_is_a_different_snapshot_too() {
        let a = dirty_dev(
            base_files().given(repo().join("a.nix"), "{ }\n"),
            "a.nix\0fleet.toml\0",
        )
        .unwrap();
        let b = dirty_dev(
            base_files().given(repo().join("b.nix"), "{ }\n"),
            "b.nix\0fleet.toml\0",
        )
        .unwrap();
        assert_ne!(a.fingerprint, b.fingerprint, "the path is part of the hash");
    }

    #[test]
    fn a_key_in_the_tree_stops_a_dev_resolve() {
        let files = base_files().given(repo().join("keys/identity.key"), "not really a key");
        let err = dirty_dev(files, "fleet.toml\0keys/identity.key\0")
            .unwrap_err()
            .to_string();
        assert!(err.contains("keys/identity.key"), "{err}");
        assert!(err.contains("nix store"), "{err}");
    }

    #[test]
    fn a_private_key_is_found_whatever_the_file_is_called() {
        let files = base_files().given(
            repo().join("notes.txt"),
            "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaA==\n",
        );
        let err = dirty_dev(files, "fleet.toml\0notes.txt\0")
            .unwrap_err()
            .to_string();
        assert!(err.contains("notes.txt"), "{err}");
    }

    #[test]
    fn a_certificate_is_not_a_secret() {
        let files = base_files().given(
            repo().join("trust/external-ca.crt"),
            "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n",
        );
        let source = dirty_dev(files, "fleet.toml\0trust/external-ca.crt\0").unwrap();
        assert!(source.dev_mode.unwrap().secret_scan.ok);
    }

    #[test]
    fn a_missing_lock_file_says_what_to_run() {
        let runner = clean_git();
        let files = MemFiles::new().given(repo().join("fleet.toml"), "schema = 2\n");
        let err = describe(&runner, &files, &repo(), Path::new("fleet.toml"), false)
            .unwrap_err()
            .to_string();
        assert!(err.contains("nix flake lock"), "{err}");
        assert!(err.contains("side effect"), "{err}");
    }

    #[test]
    fn an_unknown_input_shape_is_written_out_rather_than_guessed_at() {
        let lock = r#"{"nodes":{"odd":{"locked":{"type":"weird","narHash":"sha256-c="}},
                       "root":{"inputs":{"odd":"odd"}}},"root":"root","version":7}"#;
        let runner = clean_git();
        let files = MemFiles::new()
            .given(repo().join("fleet.toml"), "schema = 2\n")
            .given(repo().join("flake.lock"), lock);
        let source = describe(&runner, &files, &repo(), Path::new("fleet.toml"), false).unwrap();
        assert_eq!(
            source.flake_lock["odd"].url,
            r#"{"narHash":"sha256-c=","type":"weird"}"#
        );
    }
}
