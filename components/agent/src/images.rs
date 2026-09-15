// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Getting a base image onto this node.
//!
//! `image create --source <path>` was a catalogue over shared storage that
//! somebody had already filled by hand, and for every new image a person had
//! to copy something to `/mnt/vmstore`. That is the step an alpha may not
//! have any more the moment cloud-init makes stock images bootable.
//!
//! ## The node fetches, not the controller
//!
//! Two models were available. A controller that fetches into the configured
//! shared path is less code and gives a verified answer before anything is
//! placed — but it only works where there IS shared storage, and it is the
//! model that gets thrown away the first time somebody runs a node without
//! any. The node fetching into a cache of its own works with and without
//! shared storage, costs one download per node instead of one per fleet, and
//! is the shape that survives.
//!
//! What it costs is that "is this image usable" stops being a question the
//! cloud can answer by itself. So the node answers it: the outcome of a fetch
//! travels up in the status report, the same road a VM phase takes, and the
//! Image object's phase is what the fleet has learned rather than what one
//! process assumed.
//!
//! ## Content-addressed, and why the name is not enough
//!
//! The bytes live at `<image_dir>/.cache/<sha256>` and the catalogue name is
//! a hard link to them. That is what makes "a second use does not fetch
//! again" a fact rather than a hope: the presence of that file IS the proof
//! that the right bytes are here, and checking it costs one `stat` instead of
//! re-hashing gigabytes on every VM create.
//!
//! The link is what the volume drivers open. All three of them resolve a
//! `base_image` by joining the name onto their own `image_dir`, and none of
//! them has to learn anything about URLs for this to work.
//!
//! ## Nothing half-downloaded is ever usable
//!
//! Into a temporary file, hashed, and only then renamed into the cache. A
//! rename within one directory is atomic, so the cache never holds a file
//! that is not the whole of what its name says it is — and an agent killed
//! mid-download leaves a `.partial` behind and nothing else.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use anyhow::{Context, Result, bail};
use sha2::{Digest, Sha256};

use crate::reconcile::ImageReason;
use tokio::io::AsyncWriteExt;
use tracing::{debug, info, instrument};

/// What a spec says about where a base image comes from.
///
/// Both halves or neither. A URL without a checksum is not a weaker version
/// of this — it is a different thing, one where somebody else chooses what
/// this node boots — and the create edge refuses it before it can get here.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Source {
    /// The catalogue name: what `base_image` says and what the volume drivers
    /// look up under their own image_dir.
    pub name: String,
    pub url: String,
    /// Lowercase hex, 64 characters.
    pub sha256: String,
}

/// What this node has learned about an image, and what it tells the
/// controller.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum State {
    /// The bytes are here and they hash to what the spec said.
    Ready,
    /// They are not, and this is why — in the word a program reads and the
    /// sentence a person reads. A checksum that did not match is in here, and
    /// so is a url that did not answer and a path with nothing at it.
    ///
    /// The word arrived with the reasons round: the four ways an image is
    /// unusable want four different things done about them — put the bytes on
    /// the share, fix the path, fix the checksum, fix the url — and until now
    /// all four reached the catalogue as `Failed` plus prose.
    Failed {
        reason: ImageReason,
        message: String,
    },
}

impl State {
    /// The spelling that goes on the wire; the controller's `ImagePhase`
    /// parses it back.
    pub fn phase(&self) -> &'static str {
        match self {
            State::Ready => "Ready",
            State::Failed { .. } => "Failed",
        }
    }

    /// The word for `ImageStateReport.reason`. `None` for `Ready`, which
    /// needs none.
    pub fn reason(&self) -> Option<ImageReason> {
        match self {
            State::Ready => None,
            State::Failed { reason, .. } => Some(*reason),
        }
    }

    pub fn message(&self) -> &str {
        match self {
            State::Ready => "",
            State::Failed { message, .. } => message,
        }
    }
}

/// What this node has to say about the images it has been asked for.
///
/// Kept in memory and not in the store, and that is the honest shape: it is a
/// statement about this node's disk, the cache on that disk is the truth, and
/// an agent that restarts re-derives every `Ready` from a `stat` the first
/// time each image is used again. A `Failed` is forgotten by a restart, which
/// is right — a checksum that did not match yesterday is worth trying once
/// more, and if it still does not match it is said again immediately.
#[derive(Default)]
pub struct Cache {
    dir: PathBuf,
    known: Mutex<HashMap<String, State>>,
}

/// Where the content-addressed copies live, under the image directory so that
/// the hard link into place stays within one filesystem.
const CACHE_DIR: &str = ".cache";

/// Why a fetch did not end with the right bytes in place, in the two classes
/// the catalogue has to tell apart.
///
/// A type and not a look at the sentence, for the reason every reason in this
/// stack is a word: prose is for a person, and a program that matched on it
/// would break the first time somebody improved the wording. `From` makes
/// every `?` in `ensure_inner` the second class, so the ONE place that is the
/// first class is the one place that has to say so.
enum FetchFailure {
    /// The bytes arrived and are not the bytes the spec named. A different
    /// thing to fix from everything below — the url's content changed, or the
    /// checksum in the spec is wrong — and the class D-H4 was about.
    Mismatch(anyhow::Error),
    /// Everything else: the url did not answer, `curl` is not on the PATH,
    /// the cache could not be written, the link could not be made.
    Broken(anyhow::Error),
}

impl From<anyhow::Error> for FetchFailure {
    fn from(e: anyhow::Error) -> Self {
        Self::Broken(e)
    }
}

impl FetchFailure {
    /// The word for the catalogue and the error for the caller. Both, because
    /// a failed fetch is two statements: `Image.status` learns why, and the
    /// provision that asked for it still has to fail.
    fn split(self) -> (ImageReason, anyhow::Error) {
        match self {
            FetchFailure::Mismatch(e) => (ImageReason::ChecksumMismatch, e),
            FetchFailure::Broken(e) => (ImageReason::FetchFailed, e),
        }
    }
}

impl Cache {
    pub fn new(image_dir: PathBuf) -> Self {
        Self {
            dir: image_dir,
            known: Mutex::default(),
        }
    }

    fn cache_dir(&self) -> PathBuf {
        self.dir.join(CACHE_DIR)
    }

    fn cached(&self, sha256: &str) -> PathBuf {
        self.cache_dir().join(sha256)
    }

    /// What the volume drivers will open: `<image_dir>/<name>`.
    fn linked(&self, name: &str) -> PathBuf {
        self.dir.join(name)
    }

    /// Every image this node has an opinion about, for the status report.
    pub fn report(&self) -> Vec<(String, State)> {
        let known = self.known.lock().unwrap();
        let mut out: Vec<(String, State)> = known
            .iter()
            .map(|(name, state)| (name.clone(), state.clone()))
            .collect();
        // Sorted so two consecutive reports of the same facts are the same
        // message; the tier above compares them.
        out.sort_by(|a, b| a.0.cmp(&b.0));
        out
    }

    fn remember(&self, name: &str, state: State) {
        let previous = self
            .known
            .lock()
            .unwrap()
            .insert(name.to_string(), state.clone());
        // ERROR, not WARN: a base image that cannot be used is not a
        // degradation that heals — every VM naming it fails, every time, until
        // somebody fixes the url, the checksum or the file.
        //
        // Once per CHANGE and not once per look, the same rule `Conditions`
        // follows: a path image is re-checked on every reconcile pass, and a
        // line per pass would bury the pass that first found it.
        if previous.as_ref() == Some(&state) {
            return;
        }
        match &state {
            State::Failed { reason, message } => {
                tracing::error!(image = %name, reason = %reason.as_str(), why = %message,
                                "base image unusable")
            }
            // Only interesting as a RECOVERY: the ordinary road to Ready is a
            // fetch, which has said so itself one line further up.
            State::Ready if matches!(previous, Some(State::Failed { .. })) => {
                info!(image = %name, "base image usable again")
            }
            State::Ready => {}
        }
    }

    /// A base image nobody fetches: say whether the bytes are where this node
    /// would look for them.
    ///
    /// The missing first line of a chain that was otherwise complete. A URL
    /// image is registered here because this node had to GO AND GET it, and
    /// from there the fact travels — `ImageStateReport` on the status road,
    /// `ImageView` at the cluster, `Image.status.nodes[]` and then
    /// `Image.status.phase` at the cloud. A PATH image was fetched by nobody,
    /// so no node ever said anything about it, so the cloud had no evidence
    /// and went on saying `Ready` about a catalogue entry pointing at a file
    /// that is not there. Measured on the fleet, unchanged since 2026-08-29:
    /// `image with a nonexistent source sits in phase 'Ready', not Failed`.
    ///
    /// A `stat`, and deliberately no more. Whether the bytes are the RIGHT
    /// bytes is a question only a checksum answers, and a path image has none
    /// by construction — that is what distinguishes it from a URL image. What
    /// this can say is the half that was missing and is worth everything: the
    /// file is there, or it is not and here is the path that was looked at.
    ///
    /// Level-triggered like everything else this node reports: called on every
    /// provision that names the image AND once per reconcile pass over the
    /// records that name it, so an image restored on shared storage goes back
    /// to `Ready` without anybody creating a VM to prove it.
    pub async fn verify_path(&self, name: &str) {
        let path = self.linked(name);
        let state = match tokio::fs::metadata(&path).await {
            Ok(meta) if meta.is_dir() => State::Failed {
                reason: ImageReason::NotAFile,
                message: format!(
                    "the base image {name} is a directory on this node ({})",
                    path.display()
                ),
            },
            Ok(_) => State::Ready,
            Err(e) => State::Failed {
                reason: ImageReason::NotFound,
                message: format!(
                    "the base image {name} is not on this node: {} ({e}). \
                     It has no url, so nothing here fetches it — the bytes have to be put at \
                     that path, or the image needs a url and a sha256.",
                    path.display()
                ),
            },
        };
        self.remember(name, state);
    }

    /// Make sure this image is on the node, fetching it if it is not.
    ///
    /// Idempotent and cheap on the common path: a `stat` of the cache entry,
    /// and nothing else. The first use of an image pays for the download; no
    /// later one does, on this node or for any other VM.
    #[instrument(skip(self), fields(image = %source.name, sha = %source.sha256))]
    pub async fn ensure(&self, source: &Source) -> Result<()> {
        match self.ensure_inner(source).await {
            Ok(()) => {
                self.remember(&source.name, State::Ready);
                Ok(())
            }
            Err(failure) => {
                let (reason, e) = failure.split();
                self.remember(
                    &source.name,
                    State::Failed {
                        reason,
                        message: format!("{e:#}"),
                    },
                );
                Err(e)
            }
        }
    }

    async fn ensure_inner(&self, source: &Source) -> std::result::Result<(), FetchFailure> {
        check_digest(&source.sha256)?;
        let cached = self.cached(&source.sha256);
        if tokio::fs::metadata(&cached).await.is_ok() {
            // The presence of a file under its own digest IS the proof that
            // the right bytes are here: nothing writes into the cache except
            // through the verify-then-rename below.
            debug!("already cached");
            return Ok(self.link(source, &cached).await?);
        }
        tokio::fs::create_dir_all(self.cache_dir())
            .await
            .with_context(|| format!("creating the image cache {}", self.cache_dir().display()))?;

        // Named after the digest and this process, so two agents on one
        // shared directory — and two fetches of two images in one agent —
        // cannot write into each other's partial file.
        let partial =
            self.cache_dir()
                .join(format!("{}.partial.{}", source.sha256, std::process::id()));
        let fetched = fetch(&source.url, &partial).await;
        // Whatever happened, the partial file is this function's to clean up.
        // An abandoned one is exactly what "a cancelled download leaves
        // nothing usable" is about, and it is never usable in any case: the
        // cache is keyed by digest and a partial file is not under one.
        let digest = match fetched {
            Ok(digest) => digest,
            Err(e) => {
                let _ = tokio::fs::remove_file(&partial).await;
                return Err(e.into());
            }
        };
        if digest != source.sha256 {
            let _ = tokio::fs::remove_file(&partial).await;
            // The one place that is `Mismatch`, so the word does not have to
            // be read back out of this sentence.
            return Err(FetchFailure::Mismatch(anyhow::anyhow!(
                "checksum mismatch for {}: the spec says {} and the bytes at {} hash to {digest}",
                source.name,
                source.sha256,
                source.url
            )));
        }
        // Atomic within one directory, and the only way anything gets into
        // the cache. A second agent that finished the same download first has
        // already put an identical file there; overwriting it with our own is
        // the same bytes either way.
        tokio::fs::rename(&partial, &cached)
            .await
            .with_context(|| format!("publishing {} into the image cache", source.name))?;
        // The size is read BEFORE the log line and not inside it: an await
        // inside a tracing macro's arguments holds a `format_args` across a
        // suspension point, and the whole future stops being Send.
        let bytes = tokio::fs::metadata(&cached).await.map(|m| m.len()).ok();
        info!(?bytes, "base image fetched");
        Ok(self.link(source, &cached).await?)
    }

    /// Put the catalogue name next to the cached bytes.
    ///
    /// A hard link rather than a copy: one inode, so a hundred VMs naming the
    /// same image cost one image, and the volume drivers open a plain file
    /// path exactly as they always have. A symlink would work too and is
    /// worse — the drivers hand these paths to backends that run confined,
    /// and a link that points out of the directory is a different thing to
    /// reason about.
    ///
    /// A filesystem that cannot hard link falls back to a copy: it costs the
    /// space, and it is better than a node that cannot boot anything.
    async fn link(&self, source: &Source, cached: &Path) -> Result<()> {
        let link = self.linked(&source.name);
        // Same inode already? Then this is a second use and there is nothing
        // to do — which is the common path once an image has been used once.
        if let (Ok(a), Ok(b)) = (
            tokio::fs::metadata(&link).await,
            tokio::fs::metadata(cached).await,
        ) {
            use std::os::unix::fs::MetadataExt;
            if a.ino() == b.ino() && a.dev() == b.dev() {
                return Ok(());
            }
        }
        // The name may already point at older bytes — an image re-registered
        // under the same name with a new checksum. The new content wins, and
        // the swap goes through a temporary name so that nothing ever opens a
        // half-replaced path.
        let staged = self
            .dir
            .join(format!(".{}.linking.{}", source.sha256, std::process::id()));
        let _ = tokio::fs::remove_file(&staged).await;
        match tokio::fs::hard_link(cached, &staged).await {
            Ok(()) => {}
            Err(e) => {
                debug!(error = %e, "cannot hard link into the image directory, copying");
                tokio::fs::copy(cached, &staged)
                    .await
                    .with_context(|| format!("copying {} into place", source.name))?;
            }
        }
        tokio::fs::rename(&staged, &link)
            .await
            .with_context(|| format!("putting {} in place at {}", source.name, link.display()))
    }
}

/// A sha256 that is not one is refused before anything is downloaded.
///
/// Not tidiness: the digest names the cache entry, so a value with a slash in
/// it would write outside the cache directory, and one in the wrong case
/// would never match what was computed and would re-download for ever.
fn check_digest(sha256: &str) -> Result<()> {
    if sha256.len() != 64 || !sha256.bytes().all(|b| b.is_ascii_hexdigit()) {
        bail!("sha256 {sha256:?} is not 64 hex characters");
    }
    if sha256.bytes().any(|b| b.is_ascii_uppercase()) {
        bail!("sha256 {sha256:?} must be lowercase");
    }
    Ok(())
}

/// Read the URL into `into`, hashing as it goes; the digest comes back.
///
/// Hashed while streaming rather than by reading the file back, because a
/// cloud image is measured in gigabytes and reading it twice is the kind of
/// cost that only shows up on a slow node.
///
/// `curl` rather than an HTTP client crate, and that is a deliberate trade
/// stated where it is made: this agent already shells out to `nft`, `lvs`,
/// `qemu-img` and `virtiofsd`, so a subprocess is the house pattern; and the
/// alternative is a full TLS-and-redirects HTTP stack in a process whose job
/// is running VMs. `curl` is in the agent's PATH list for the same reason
/// those four are (nix/agent.nix), and its absence is a named error at the
/// point of use.
async fn fetch(url: &str, into: &Path) -> Result<String> {
    use tokio::io::AsyncReadExt;
    use tokio::process::Command;

    let mut child = Command::new("curl")
        // --fail: a 404 is an error and not a file containing the words "not
        // found". --location: cloud image URLs redirect, every time.
        // --silent --show-error: nothing on stdout but the bytes, and the
        // reason on stderr when it goes wrong.
        .args(["--fail", "--location", "--silent", "--show-error", url])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .with_context(|| {
            format!("running curl to fetch {url} - is curl on the agent's PATH? (nix/agent.nix)")
        })?;

    let mut stdout = child.stdout.take().expect("stdout was piped");
    let mut file = tokio::fs::File::create(into)
        .await
        .with_context(|| format!("creating {}", into.display()))?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 256 * 1024];
    loop {
        let n = stdout.read(&mut buf).await.context("reading from curl")?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        file.write_all(&buf[..n])
            .await
            .with_context(|| format!("writing {}", into.display()))?;
    }
    file.flush().await.ok();
    // Durable before it is renamed: the rename is what makes the bytes
    // usable, and a rename that lands before the data does would survive a
    // power cut as a cache entry full of nothing.
    file.sync_all()
        .await
        .with_context(|| format!("syncing {}", into.display()))?;
    drop(file);

    let status = child.wait().await.context("waiting for curl")?;
    if !status.success() {
        let mut said = String::new();
        if let Some(mut stderr) = child.stderr.take() {
            let _ = stderr.read_to_string(&mut said).await;
        }
        let said = said.trim();
        bail!(
            "fetching {url} failed ({status}){}",
            if said.is_empty() {
                String::new()
            } else {
                format!(": {said}")
            }
        );
    }
    Ok(format!("{:x}", hasher.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A cache directory of this test's own, and the guard that removes it.
    ///
    /// The guard comes back first and the caller binds it: the directory used
    /// to be named after the test alone, so two runs on one machine shared
    /// it, and one that crashed left its half-written entries for the next.
    fn scratch(name: &str) -> (tempfile::TempDir, PathBuf) {
        let temp = tempfile::Builder::new()
            .prefix(&format!("meister-image-{name}-"))
            .tempdir()
            .expect("a temp dir");
        let dir = temp.path().to_path_buf();
        (temp, dir)
    }

    fn digest_of(bytes: &[u8]) -> String {
        format!("{:x}", Sha256::digest(bytes))
    }

    /// The digest names the cache entry, so a value that is not a digest is
    /// refused before anything is downloaded. A slash would write outside the
    /// cache directory; the wrong case would never match what is computed and
    /// would re-fetch for ever.
    #[test]
    fn a_checksum_that_is_not_one_is_refused_before_anything_is_fetched() {
        assert!(check_digest(&digest_of(b"hello")).is_ok());
        assert!(check_digest("").is_err());
        assert!(check_digest("deadbeef").is_err(), "too short");
        assert!(check_digest(&"z".repeat(64)).is_err(), "not hex");
        assert!(
            check_digest(&digest_of(b"hello").to_uppercase()).is_err(),
            "case would never match"
        );
        assert!(
            check_digest("../../../etc/passwd_padded_to_sixty_four_characters_aaaaaaaaaaaaa")
                .is_err()
        );
    }

    /// A URL that answers, byte for byte, and a second use that does not
    /// fetch again. `file://` is a real fetch through the same code path a
    /// http one takes — curl reads it the same way — so this exercises the
    /// stream, the hash, the temp file, the rename and the link.
    #[tokio::test]
    async fn an_image_is_fetched_once_and_then_found() {
        let (_temp, dir) = scratch("fetch-once");
        let payload = b"a stock cloud image, in miniature".repeat(64);
        let origin = dir.join("origin.raw");
        std::fs::write(&origin, &payload).unwrap();

        let images = dir.join("images");
        std::fs::create_dir_all(&images).unwrap();
        let cache = Cache::new(images.clone());
        let source = Source {
            name: "ubuntu.raw".into(),
            url: format!("file://{}", origin.display()),
            sha256: digest_of(&payload),
        };

        cache.ensure(&source).await.expect("fetched");
        // Where the volume drivers will look, with the right bytes in it.
        let placed = images.join("ubuntu.raw");
        assert_eq!(std::fs::read(&placed).unwrap(), payload);
        // And in the cache under its own digest, which is what makes the
        // second use free.
        assert!(images.join(CACHE_DIR).join(&source.sha256).exists());
        assert_eq!(
            cache.report(),
            vec![("ubuntu.raw".to_string(), State::Ready)]
        );

        // A second use with the origin GONE: nothing is fetched, because
        // nothing needs to be.
        std::fs::remove_file(&origin).unwrap();
        cache.ensure(&source).await.expect("already here");
        assert_eq!(std::fs::read(&placed).unwrap(), payload);

        // One inode, so a hundred VMs naming this image cost one image.
        use std::os::unix::fs::MetadataExt;
        let a = std::fs::metadata(&placed).unwrap();
        let b = std::fs::metadata(images.join(CACHE_DIR).join(&source.sha256)).unwrap();
        assert_eq!((a.ino(), a.dev()), (b.ino(), b.dev()));
    }

    /// The checksum is what makes a fetched image usable, so bytes that do
    /// not match it leave nothing behind at all — not in the cache, not under
    /// the catalogue name, not as a partial file.
    #[tokio::test]
    async fn a_wrong_checksum_leaves_nothing_usable() {
        let (_temp, dir) = scratch("wrong-sum");
        let origin = dir.join("origin.raw");
        std::fs::write(&origin, b"the wrong bytes entirely").unwrap();

        let images = dir.join("images");
        std::fs::create_dir_all(&images).unwrap();
        let cache = Cache::new(images.clone());
        let claimed = digest_of(b"what the operator thought they were getting");
        let source = Source {
            name: "ubuntu.raw".into(),
            url: format!("file://{}", origin.display()),
            sha256: claimed.clone(),
        };

        let err = cache.ensure(&source).await.expect_err("must not be usable");
        let said = format!("{err:#}");
        assert!(said.contains("checksum mismatch"), "{said}");
        assert!(said.contains(&claimed), "the message names both digests");

        assert!(
            !images.join("ubuntu.raw").exists(),
            "nothing under the name"
        );
        assert!(!images.join(CACHE_DIR).join(&claimed).exists());
        // No partial file left behind either.
        let leftovers: Vec<_> = std::fs::read_dir(images.join(CACHE_DIR))
            .map(|d| d.filter_map(|e| e.ok()).map(|e| e.file_name()).collect())
            .unwrap_or_default();
        assert!(leftovers.is_empty(), "{leftovers:?}");

        // And the node says so, with the reason, for the status report.
        match &cache.report()[..] {
            [(name, State::Failed { reason, message })] => {
                assert_eq!(name, "ubuntu.raw");
                assert!(message.contains("checksum mismatch"), "{message}");
                // And in the word, so the catalogue can tell this apart from
                // a url that did not answer: the fix is a different one.
                assert_eq!(*reason, ImageReason::ChecksumMismatch);
            }
            other => panic!("{other:?}"),
        }
    }

    /// A URL nobody answers is a Failed with the reason, and again nothing
    /// half-written survives it.
    #[tokio::test]
    async fn a_url_that_does_not_answer_leaves_nothing_usable() {
        let (_temp, dir) = scratch("no-answer");
        let images = dir.join("images");
        std::fs::create_dir_all(&images).unwrap();
        let cache = Cache::new(images.clone());
        let source = Source {
            name: "ubuntu.raw".into(),
            url: format!("file://{}", dir.join("nothing-here.raw").display()),
            sha256: digest_of(b"anything"),
        };

        assert!(cache.ensure(&source).await.is_err());
        assert!(!images.join("ubuntu.raw").exists());
        assert!(matches!(
            cache.report()[0].1,
            State::Failed {
                reason: ImageReason::FetchFailed,
                ..
            }
        ));
    }

    /// An image re-registered under the same name with new content: the name
    /// follows the bytes, and the old ones stay in the cache under their own
    /// digest where nothing points at them any more.
    #[tokio::test]
    async fn the_name_follows_the_newest_bytes() {
        let (_temp, dir) = scratch("rebuild");
        let images = dir.join("images");
        std::fs::create_dir_all(&images).unwrap();
        let cache = Cache::new(images.clone());

        let first = b"version one".to_vec();
        let origin = dir.join("origin.raw");
        std::fs::write(&origin, &first).unwrap();
        cache
            .ensure(&Source {
                name: "ubuntu.raw".into(),
                url: format!("file://{}", origin.display()),
                sha256: digest_of(&first),
            })
            .await
            .unwrap();

        let second = b"version two, rather longer".to_vec();
        std::fs::write(&origin, &second).unwrap();
        cache
            .ensure(&Source {
                name: "ubuntu.raw".into(),
                url: format!("file://{}", origin.display()),
                sha256: digest_of(&second),
            })
            .await
            .unwrap();

        assert_eq!(std::fs::read(images.join("ubuntu.raw")).unwrap(), second);
        assert!(images.join(CACHE_DIR).join(digest_of(&first)).exists());
        assert!(images.join(CACHE_DIR).join(digest_of(&second)).exists());
    }
    /// A path image is registered like a fetched one, so the cloud stops
    /// guessing.
    ///
    /// The missing first line of a chain that was otherwise complete. This
    /// node registered only what it had to FETCH, so a path image — somebody
    /// else's file on shared storage — was reported by nobody; the cloud had
    /// no evidence and went on saying `Ready` about a catalogue entry
    /// pointing at nothing. Unchanged on the fleet since 2026-08-29.
    ///
    /// And it is level: the same registry entry follows the file, so an image
    /// restored on shared storage goes back to `Ready` without anybody
    /// creating a VM to prove it.
    #[tokio::test]
    async fn a_path_image_says_whether_its_bytes_are_here() {
        let (_temp, images) = scratch("path");
        let cache = Cache::new(images.clone());

        // Nothing said about an image nobody has looked at. Silence is what
        // an empty `Image.status.nodes[]` means, and it must stay available.
        assert!(cache.report().is_empty());

        cache.verify_path("nixos.raw").await;
        let (name, state) = cache.report().pop().expect("one opinion");
        assert_eq!(name, "nixos.raw");
        let State::Failed {
            reason,
            message: why,
        } = state
        else {
            panic!("a file that is not there is not Ready");
        };
        assert_eq!(reason, ImageReason::NotFound);
        assert!(
            why.contains(images.join("nixos.raw").to_str().unwrap()),
            "the sentence names the path that was looked at: {why}"
        );
        assert!(
            why.contains("no url"),
            "and says why nothing is going to fetch it: {why}"
        );

        // Somebody puts the bytes there. The next look says so — no create,
        // no restart, no second command.
        std::fs::write(images.join("nixos.raw"), b"an image").expect("the bytes");
        cache.verify_path("nixos.raw").await;
        assert_eq!(
            cache.report(),
            vec![("nixos.raw".to_string(), State::Ready)],
            "the registry follows the file"
        );

        // A directory under the name is not an image, and saying `Ready`
        // about one would hand the storage driver a path it cannot open.
        std::fs::remove_file(images.join("nixos.raw")).expect("gone");
        std::fs::create_dir(images.join("nixos.raw")).expect("a directory instead");
        cache.verify_path("nixos.raw").await;
        let State::Failed {
            reason,
            message: why,
        } = cache.report().pop().expect("one").1
        else {
            panic!("a directory is not an image");
        };
        assert!(why.contains("is a directory"), "{why}");
        assert_eq!(reason, ImageReason::NotAFile);
    }
}
