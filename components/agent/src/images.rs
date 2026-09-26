// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Fetch and report base images on this node.
//!
//! Verified downloads are published under `.cache/<uid>-<sha256>` and linked
//! under the catalogue name; legacy sources without a UID use the digest alone.
//! Volume drivers open that catalogue path. Existing cache entries are trusted
//! without rehashing. Downloads stage bytes separately before publication;
//! interrupted downloads can leave unusable partial files.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use sha2::{Digest, Sha256};

use crate::reconcile::ImageReason;
use tokio::io::AsyncWriteExt;
use tracing::{debug, info, instrument};

/// Fetch source with paired URL and checksum, validated at the create edge.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Source {
    /// The catalogue name: what `base_image` says and what the volume drivers
    /// look up under their own image_dir.
    pub name: String,
    pub url: String,
    /// Lowercase hex, 64 characters.
    pub sha256: String,
    /// Image registration identity. Empty legacy and standalone sources use a
    /// digest-only cache key; otherwise the UID separates registrations.
    #[serde(default)]
    pub uid: String,
}

impl Source {
    /// Cache key combining registration identity and the complete digest.
    fn cache_key(&self) -> String {
        match self.uid.is_empty() {
            true => self.sha256.clone(),
            false => format!("{}-{}", self.uid, self.sha256),
        }
    }
}

/// What this node has learned about an image, and what it tells the
/// controller.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum State {
    /// The image is present according to a fetch, path check, or inventory.
    /// Only fetched images necessarily had their expected digest checked.
    Ready,
    /// A failed check with a machine-readable reason and diagnostic message.
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

    /// Machine-readable image reason, absent for Ready.
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

/// In-memory image observations. Restart clears them; later checks reconstruct
/// state from the image directory and trusted cache entries.
#[derive(Default)]
pub struct Cache {
    dir: PathBuf,
    known: Mutex<HashMap<String, Entry>>,
    /// Everything that IS in the image directory, and when that directory
    /// last changed. See [`Cache::take_inventory`].
    inventory: Mutex<Option<Inventory>>,
    /// What a download may cost before it is cut off. See [`Bounds`].
    bounds: Bounds,
}

/// A reading of the image directory, and the mtime it was read at.
struct Inventory {
    /// Directory mtime sampled before scanning so the cached listing never
    /// claims freshness beyond its observation.
    at: std::time::SystemTime,
    /// Sorted catalogue filenames. Drivers resolve these names directly under `image_dir`.
    names: Vec<String>,
}

/// One image's line in this node's opinion, and where the opinion came from.
struct Entry {
    state: State,
    /// Preserve fetch results when a volume record later refers to the same image
    /// by name alone; a path check must not replace a checksum failure.
    fetched: bool,
    /// Digest measured for a path image. Reused while checks remain Ready;
    /// changes to present file contents are not detected until rehashing, normally
    /// after restart or a failed path check.
    digest: Option<String>,
}

/// Where the content-addressed copies live, under the image directory so that
/// the hard link into place stays within one filesystem.
const CACHE_DIR: &str = ".cache";

/// Separate checksum mismatch from other download or publication failures.
enum FetchFailure {
    /// The downloaded digest differs from the requested digest.
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
    /// Separate the status reason from the error returned to the provisioning caller.
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
            inventory: Mutex::default(),
            bounds: Bounds::default(),
        }
    }

    /// Override download bounds for this cache.
    pub fn with_bounds(mut self, bounds: Bounds) -> Self {
        self.bounds = bounds;
        self
    }

    fn cache_dir(&self) -> PathBuf {
        self.dir.join(CACHE_DIR)
    }

    fn cached(&self, key: &str) -> PathBuf {
        self.cache_dir().join(key)
    }

    /// What the volume drivers will open: `<image_dir>/<name>`.
    fn linked(&self, name: &str) -> PathBuf {
        self.dir.join(name)
    }

    /// Inventory regular, non-hidden files, caching by directory mtime once it
    /// is over one second old. A successful walk permits a complete inventory
    /// report; metadata or traversal failure invalidates the cached inventory.
    pub async fn take_inventory(&self) -> bool {
        let at = match tokio::fs::metadata(&self.dir)
            .await
            .and_then(|m| m.modified())
        {
            Ok(at) => at,
            Err(e) => {
                debug!(dir = %self.dir.display(), error = %e,
                       "the image directory cannot be read; saying nothing about it");
                *self.inventory.lock().unwrap() = None;
                return false;
            }
        };
        let settled = std::time::SystemTime::now()
            .duration_since(at)
            .is_ok_and(|age| age > std::time::Duration::from_secs(1));
        if settled
            && self
                .inventory
                .lock()
                .unwrap()
                .as_ref()
                .is_some_and(|held| held.at == at)
        {
            return true;
        }

        let mut entries = match tokio::fs::read_dir(&self.dir).await {
            Ok(entries) => entries,
            Err(e) => {
                debug!(dir = %self.dir.display(), error = %e,
                       "the image directory cannot be listed; saying nothing about it");
                *self.inventory.lock().unwrap() = None;
                return false;
            }
        };
        let mut names = Vec::new();
        loop {
            match entries.next_entry().await {
                Ok(None) => break,
                Ok(Some(entry)) => {
                    let name = entry.file_name().to_string_lossy().into_owned();
                    // Exclude the cache and temporary link names from the catalogue inventory.
                    if name.starts_with('.') {
                        continue;
                    }
                    // Only regular files can satisfy image lookups.
                    if entry.file_type().await.is_ok_and(|t| t.is_file()) {
                        names.push(name);
                    }
                }
                Err(e) => {
                    debug!(dir = %self.dir.display(), error = %e,
                           "the image directory could not be walked to the end");
                    *self.inventory.lock().unwrap() = None;
                    return false;
                }
            }
        }
        names.sort();
        *self.inventory.lock().unwrap() = Some(Inventory { at, names });
        true
    }

    /// Merge explicit image observations with inventory-only Ready entries.
    /// Explicit checks win; inventory entries have no measured digest.
    pub fn report(&self) -> Vec<(String, State, Option<String>)> {
        let known = self.known.lock().unwrap();
        let mut out: Vec<(String, State, Option<String>)> = known
            .iter()
            .map(|(name, entry)| (name.clone(), entry.state.clone(), entry.digest.clone()))
            .collect();
        if let Some(held) = self.inventory.lock().unwrap().as_ref() {
            out.extend(
                held.names
                    .iter()
                    .filter(|name| !known.contains_key(*name))
                    .map(|name| (name.clone(), State::Ready, None)),
            );
        }
        // Sort reports for stable controller comparisons.
        out.sort_by(|a, b| a.0.cmp(&b.0));
        out
    }

    /// Whether this node's opinion about an image came from a fetch. See
    /// [`Entry::fetched`].
    fn was_fetched(&self, name: &str) -> bool {
        self.known
            .lock()
            .unwrap()
            .get(name)
            .is_some_and(|entry| entry.fetched)
    }

    /// Read the remembered digest before replacing a path-image observation.
    /// See `Entry::digest` for its lifetime.
    fn known_digest(&self, name: &str) -> Option<String> {
        self.known
            .lock()
            .unwrap()
            .get(name)
            .and_then(|entry| entry.digest.clone())
    }

    fn remember(&self, name: &str, state: State, fetched: bool, digest: Option<String>) {
        let previous = self
            .known
            .lock()
            .unwrap()
            .insert(
                name.to_string(),
                Entry {
                    state: state.clone(),
                    fetched,
                    digest,
                },
            )
            .map(|entry| entry.state);
        // Log state changes only, avoiding repeated errors on each report.
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

    /// Check a local image path and hash it on the first successful observation.
    /// Reuse a remembered digest while the path remains present; hash failure
    /// still reports Ready without a digest. Previously fetched entries retain
    /// their fetch result and are not checked here.
    pub async fn verify_path(&self, name: &str) {
        // Fetched images retain their checksum-verified fetch result; path probing must not replace it.
        if self.was_fetched(name) {
            return;
        }
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
        let digest = match &state {
            State::Ready => match self.known_digest(name) {
                Some(digest) => Some(digest),
                None => match hash_local_file(&path, self.bounds.deadline).await {
                    Ok(digest) => Some(digest),
                    Err(e) => {
                        // A failed hash leaves a presence-only observation without a digest.
                        debug!(image = %name, error = %e,
                               "the base image could not be hashed; reporting it present \
                                without a digest");
                        None
                    }
                },
            },
            State::Failed { .. } => None,
        };
        self.remember(name, state, false, digest);
    }

    /// Fetch missing content and publish its catalogue link. Existing cache
    /// entries are trusted by path; linking may still require a copy.
    #[instrument(skip(self), fields(image = %source.name, sha = %source.sha256))]
    pub async fn ensure(&self, source: &Source) -> Result<()> {
        match self.ensure_inner(source).await {
            Ok(()) => {
                // Fetched images already carry a verified source checksum; the separate
                // status digest is used to bind path images.
                self.remember(&source.name, State::Ready, true, None);
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
                    true,
                    None,
                );
                Err(e)
            }
        }
    }

    async fn ensure_inner(&self, source: &Source) -> std::result::Result<(), FetchFailure> {
        check_digest(&source.sha256)?;
        check_uid(&source.uid)?;
        let cached = self.cached(&source.cache_key());
        if tokio::fs::metadata(&cached).await.is_ok() {
            // Trust existing cache entries without rehashing their contents.
            debug!("already cached");
            return Ok(self.link(source, &cached).await?);
        }
        tokio::fs::create_dir_all(self.cache_dir())
            .await
            .with_context(|| format!("creating the image cache {}", self.cache_dir().display()))?;

        // Stage by cache key and PID. This is not a cross-host or per-request lock.
        let partial = self.cache_dir().join(format!(
            "{}.partial.{}",
            source.cache_key(),
            std::process::id()
        ));
        let fetched = fetch(&source.url, &partial, &self.bounds).await;
        // Remove the partial after a returned fetch failure. Cancellation may leave it.
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
        // Publish verified bytes with a same-directory rename. Concurrent downloads
        // for this cache key have the same verified content.
        tokio::fs::rename(&partial, &cached)
            .await
            .with_context(|| format!("publishing {} into the image cache", source.name))?;
        // Await metadata before entering the tracing macro to keep format_args
        // out of suspension points and preserve a Send future.
        let bytes = tokio::fs::metadata(&cached).await.map(|m| m.len()).ok();
        info!(?bytes, "base image fetched");
        Ok(self.link(source, &cached).await?)
    }

    /// Publish a catalogue path via a staged hard link, falling back to a copy.
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
        // Replace the catalogue link atomically, including when a new checksum
        // reuses an existing image name.
        let staged = self.dir.join(format!(
            ".{}.linking.{}",
            source.cache_key(),
            std::process::id()
        ));
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

    /// Remove cache files for a registration UID. Remove the catalogue link and
    /// its remembered observation only when its inode matches the recorded cache
    /// inode. Copies made by the hard-link fallback do not match this test.
    pub async fn drop_uid(&self, name: &str, uid: &str) {
        if uid.is_empty() {
            // An empty UID cannot scope a cache removal.
            return;
        }
        let linked = self.linked(name);
        let link_place = place_of(&linked).await;
        let prefix = format!("{uid}-");
        let mut dropped_place = None;
        if let Ok(mut entries) = tokio::fs::read_dir(self.cache_dir()).await {
            while let Ok(Some(entry)) = entries.next_entry().await {
                let fname = entry.file_name().to_string_lossy().into_owned();
                if !fname.starts_with(&prefix) {
                    continue;
                }
                let path = self.cache_dir().join(&fname);
                if dropped_place.is_none() {
                    dropped_place = place_of(&path).await;
                }
                if let Err(e) = tokio::fs::remove_file(&path).await {
                    debug!(image = %name, file = %fname, error = %e,
                           "could not remove a cache file for a dropped image");
                }
            }
        }
        // Remove the catalogue link and status only if the link still targets
        // the dropped registration. A delayed drop must preserve a newer registration.
        if link_place.is_some() && link_place == dropped_place {
            let _ = tokio::fs::remove_file(&linked).await;
            self.known.lock().unwrap().remove(name);
        }
    }
}

/// Read device and inode identity for comparing paths; None means unavailable metadata.
async fn place_of(path: &Path) -> Option<(u64, u64)> {
    use std::os::unix::fs::MetadataExt;
    tokio::fs::metadata(path)
        .await
        .ok()
        .map(|m| (m.dev(), m.ino()))
}

/// Download limits. Defaults impose a 1 KiB/s floor for 60 seconds, a two-hour
/// transfer deadline, and a 64 GiB byte ceiling.
#[derive(Clone, Copy, Debug)]
pub struct Bounds {
    /// Minimum sustained transfer rate over the idle interval.
    pub floor_bytes_per_sec: u64,
    /// How long the transfer may stay under the floor before it is cut.
    pub idle: Duration,
    /// Deadline for the entire transfer, including headers.
    pub deadline: Duration,
    /// Maximum accepted bytes.
    pub max_bytes: u64,
}

impl Default for Bounds {
    fn default() -> Self {
        Self {
            floor_bytes_per_sec: 1024,
            idle: Duration::from_secs(60),
            deadline: Duration::from_secs(2 * 60 * 60),
            max_bytes: 64 * (1 << 30),
        }
    }
}

/// How much longer than its own bound this side waits before it stops
/// believing the bound is being kept. See the deadline in [`fetch`].
const BOUND_GRACE: Duration = Duration::from_secs(30);

/// Build curl arguments for redirects, HTTP failure reporting and download limits.
fn curl_argv(url: &str, bounds: &Bounds) -> Vec<String> {
    vec![
        "--fail".to_string(),
        "--location".to_string(),
        "--silent".to_string(),
        "--show-error".to_string(),
        // The idle cut-off, in curl's own two halves.
        "--speed-limit".to_string(),
        bounds.floor_bytes_per_sec.to_string(),
        "--speed-time".to_string(),
        bounds.idle.as_secs().to_string(),
        // Bound connection setup and transfer together.
        "--max-time".to_string(),
        bounds.deadline.as_secs().to_string(),
        // Curl can only precheck a declared length; drain also enforces the limit
        // against bytes actually received.
        "--max-filesize".to_string(),
        bounds.max_bytes.to_string(),
        url.to_string(),
    ]
}

/// Validate the checksum before using it as a cache path or downloading bytes.
fn check_digest(sha256: &str) -> Result<()> {
    if sha256.len() != 64 || !sha256.bytes().all(|b| b.is_ascii_hexdigit()) {
        bail!("sha256 {sha256:?} is not 64 hex characters");
    }
    if sha256.bytes().any(|b| b.is_ascii_uppercase()) {
        bail!("sha256 {sha256:?} must be lowercase");
    }
    Ok(())
}

/// Accept an empty legacy UID or up to 64 alphanumeric/hyphen characters.
/// Reject path separators before using the UID in cache filenames.
fn check_uid(uid: &str) -> Result<()> {
    if uid.is_empty() {
        // An image registered by a cluster with no cloud above it, or a
        // record written before the field existed. See `Source::uid`.
        return Ok(());
    }
    if uid.len() > 64 || !uid.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') {
        bail!("image uid {uid:?} is not a uid");
    }
    Ok(())
}

/// Hash a local file in fixed-size chunks, bounded by the transfer deadline
/// plus grace. Timing out the future does not cancel kernel filesystem I/O.
async fn hash_local_file(path: &Path, deadline: Duration) -> Result<String> {
    use tokio::io::AsyncReadExt;

    let work = async {
        let mut file = tokio::fs::File::open(path)
            .await
            .with_context(|| format!("opening {}", path.display()))?;
        let mut hasher = Sha256::new();
        let mut buf = vec![0u8; 256 * 1024];
        loop {
            let n = file
                .read(&mut buf)
                .await
                .with_context(|| format!("reading {}", path.display()))?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
        }
        Ok::<String, anyhow::Error>(format!("{:x}", hasher.finalize()))
    };
    match tokio::time::timeout(deadline.saturating_add(BOUND_GRACE), work).await {
        Ok(result) => result,
        Err(_) => bail!(
            "hashing {} did not finish within {}s and was stopped",
            path.display(),
            deadline.as_secs()
        ),
    }
}

/// Stream curl output to a file while hashing, enforce byte/time bounds,
/// and sync completed content before returning its digest.
async fn fetch(url: &str, into: &Path, bounds: &Bounds) -> Result<String> {
    use tokio::io::AsyncReadExt;
    use tokio::process::Command;

    let mut child = Command::new("curl")
        .args(curl_argv(url, bounds))
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

    // Bound the agent's read loop independently of curl's own timeout flags.
    let drained = tokio::time::timeout(
        bounds.deadline.saturating_add(BOUND_GRACE),
        drain(&mut stdout, &mut file, into, bounds.max_bytes),
    )
    .await;
    let digest = match drained {
        Ok(Ok(digest)) => digest,
        Ok(Err(e)) => {
            kill_and_reap(&mut child).await;
            return Err(e);
        }
        Err(_) => {
            kill_and_reap(&mut child).await;
            bail!(
                "fetching {url} did not finish within {}s and was stopped; nothing usable was \
                 written",
                bounds.deadline.as_secs()
            );
        }
    };
    file.flush().await.ok();
    // Durable before it is renamed: the rename is what makes the bytes
    // usable, and a rename that lands before the data does would survive a
    // power cut as a cache entry full of nothing.
    file.sync_all()
        .await
        .with_context(|| format!("syncing {}", into.display()))?;
    drop(file);

    // Bound process reaping even after curl has stopped producing bytes.
    let status = match tokio::time::timeout(BOUND_GRACE, child.wait()).await {
        Ok(status) => status.context("waiting for curl")?,
        Err(_) => {
            kill_and_reap(&mut child).await;
            bail!("curl did not exit after fetching {url} and was stopped");
        }
    };
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
    Ok(digest)
}

/// Enforce the byte ceiling on actual output, independently of curl's limits.
async fn drain(
    stdout: &mut tokio::process::ChildStdout,
    file: &mut tokio::fs::File,
    into: &Path,
    max_bytes: u64,
) -> Result<String> {
    use tokio::io::AsyncReadExt;

    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 256 * 1024];
    let mut written: u64 = 0;
    loop {
        let n = stdout.read(&mut buf).await.context("reading from curl")?;
        if n == 0 {
            break;
        }
        written += n as u64;
        if written > max_bytes {
            bail!(
                "the bytes at this url are past the {max_bytes} byte budget this node fetches \
                 within; the download was stopped"
            );
        }
        hasher.update(&buf[..n]);
        file.write_all(&buf[..n])
            .await
            .with_context(|| format!("writing {}", into.display()))?;
    }
    Ok(format!("{:x}", hasher.finalize()))
}

/// Kill and reap curl on handled transfer failures. Reaping itself has no timeout.
async fn kill_and_reap(child: &mut tokio::process::Child) {
    if let Err(e) = child.start_kill() {
        debug!(error = %e, "curl was already gone when the fetch was stopped");
    }
    if let Err(e) = child.wait().await {
        debug!(error = %e, "reaping the stopped curl");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Isolate each test cache in a temporary directory.
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

    /// Reject malformed checksums before downloading or constructing cache paths.
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

    /// Find curl processes naming this test server's port to detect abandoned downloads.
    fn a_curl_still_runs_for(port: u16) -> bool {
        let marker = format!("127.0.0.1:{port}");
        let Ok(entries) = std::fs::read_dir("/proc") else {
            return false;
        };
        for entry in entries.flatten() {
            let Ok(cmdline) = std::fs::read(entry.path().join("cmdline")) else {
                continue;
            };
            let said = String::from_utf8_lossy(&cmdline);
            if said.contains("curl") && said.contains(&marker) {
                return true;
            }
        }
        false
    }

    /// Curl receives the idle, total-duration and byte limits used by the fetcher.
    #[test]
    fn the_download_argv_carries_every_bound() {
        let bounds = Bounds {
            floor_bytes_per_sec: 1024,
            idle: Duration::from_secs(60),
            deadline: Duration::from_secs(7200),
            max_bytes: 1 << 30,
        };
        let argv = curl_argv("https://images.example/noble.img", &bounds);

        let after = |flag: &str| {
            argv.iter()
                .position(|a| a == flag)
                .and_then(|i| argv.get(i + 1))
                .map(String::as_str)
        };
        assert_eq!(after("--speed-limit"), Some("1024"), "the idle floor");
        assert_eq!(after("--speed-time"), Some("60"), "how long under it");
        assert_eq!(after("--max-time"), Some("7200"), "the whole transfer");
        assert_eq!(after("--max-filesize"), Some("1073741824"), "the budget");

        // Retain the standard HTTP failure, redirect and logging flags.
        for flag in ["--fail", "--location", "--silent", "--show-error"] {
            assert!(argv.iter().any(|a| a == flag), "{flag} is still passed");
        }
        assert_eq!(
            argv.last().map(String::as_str),
            Some("https://images.example/noble.img"),
            "the url is the last word, so no bound can be read as one"
        );
    }

    /// Keep the response open after its headers to exercise the idle timeout, not EOF.
    #[tokio::test]
    async fn a_url_that_stalls_after_its_headers_is_cut_off_and_leaves_no_child() {
        use std::sync::atomic::{AtomicBool, Ordering};

        let (_temp, dir) = scratch("stall");
        let images = dir.join("images");
        std::fs::create_dir_all(&images).unwrap();

        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("a port");
        let port = listener.local_addr().expect("an address").port();
        let stop = std::sync::Arc::new(AtomicBool::new(false));
        let held = stop.clone();
        let server = std::thread::spawn(move || {
            // Keep connections open after sending headers to exercise a stalled transfer
            // rather than an immediate connection-close error.
            listener.set_nonblocking(true).ok();
            let mut kept = Vec::new();
            while !held.load(Ordering::Relaxed) {
                if let Ok((stream, _)) = listener.accept() {
                    use std::io::Write;
                    stream.set_nonblocking(false).ok();
                    let mut stream = stream;
                    let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 1048576\r\n\r\n");
                    let _ = stream.flush();
                    kept.push(stream);
                }
                std::thread::sleep(Duration::from_millis(20));
            }
        });

        let cache = Cache::new(images.clone()).with_bounds(Bounds {
            floor_bytes_per_sec: 1,
            idle: Duration::from_secs(1),
            deadline: Duration::from_secs(5),
            max_bytes: 1 << 20,
        });
        let source = Source {
            name: "ubuntu.raw".into(),
            url: format!("http://127.0.0.1:{port}/ubuntu.raw"),
            sha256: digest_of(b"bytes that never arrive"),
            uid: String::new(),
        };

        let started = std::time::Instant::now();
        let err = cache.ensure(&source).await.expect_err("nothing arrived");
        let waited = started.elapsed();
        stop.store(true, Ordering::Relaxed);
        server.join().ok();

        assert!(
            waited < Duration::from_secs(30),
            "the wait has an end: {waited:?} ({err:#})"
        );
        assert!(
            !a_curl_still_runs_for(port),
            "the download was killed and reaped, not abandoned"
        );
        assert!(
            !images.join("ubuntu.raw").exists(),
            "nothing under the catalogue name"
        );
        let leftovers: Vec<_> = std::fs::read_dir(images.join(CACHE_DIR))
            .map(|d| d.filter_map(|e| e.ok()).map(|e| e.file_name()).collect())
            .unwrap_or_default();
        assert!(leftovers.is_empty(), "and no partial file: {leftovers:?}");
        assert!(matches!(
            cache.report()[0].1,
            State::Failed {
                reason: ImageReason::FetchFailed,
                ..
            }
        ));
    }

    /// Oversized downloads must leave neither a published image nor a partial file.
    #[tokio::test]
    async fn a_body_past_the_byte_budget_is_refused() {
        let (_temp, dir) = scratch("budget");
        let payload = vec![7u8; 4096];
        let origin = dir.join("origin.raw");
        std::fs::write(&origin, &payload).unwrap();

        let images = dir.join("images");
        std::fs::create_dir_all(&images).unwrap();
        let cache = Cache::new(images.clone()).with_bounds(Bounds {
            max_bytes: 512,
            ..Bounds::default()
        });
        let source = Source {
            name: "ubuntu.raw".into(),
            url: format!("file://{}", origin.display()),
            sha256: digest_of(&payload),
            uid: String::new(),
        };

        let err = cache.ensure(&source).await.expect_err("past the budget");
        let said = format!("{err:#}").to_lowercase();
        assert!(
            said.contains("budget") || said.contains("file size"),
            "the refusal names the size: {said}"
        );
        assert!(!images.join("ubuntu.raw").exists());
        let leftovers: Vec<_> = std::fs::read_dir(images.join(CACHE_DIR))
            .map(|d| d.filter_map(|e| e.ok()).map(|e| e.file_name()).collect())
            .unwrap_or_default();
        assert!(leftovers.is_empty(), "{leftovers:?}");
    }

    /// Exercise fetch, hashing, staging, publication and cache reuse through a `file://` URL.
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
            uid: String::new(),
        };

        cache.ensure(&source).await.expect("fetched");
        // Where the volume drivers will look, with the right bytes in it.
        let placed = images.join("ubuntu.raw");
        assert_eq!(std::fs::read(&placed).unwrap(), payload);
        // Sources without a catalogue UID retain the digest-only cache key.
        assert!(images.join(CACHE_DIR).join(&source.sha256).exists());
        assert_eq!(
            cache.report(),
            vec![("ubuntu.raw".to_string(), State::Ready, None)]
        );

        // Cache reuse succeeds after the origin disappears.
        std::fs::remove_file(&origin).unwrap();
        cache.ensure(&source).await.expect("already here");
        assert_eq!(std::fs::read(&placed).unwrap(), payload);

        // One inode, so a hundred VMs naming this image cost one image.
        use std::os::unix::fs::MetadataExt;
        let a = std::fs::metadata(&placed).unwrap();
        let b = std::fs::metadata(images.join(CACHE_DIR).join(&source.sha256)).unwrap();
        assert_eq!((a.ino(), a.dev()), (b.ino(), b.dev()));
    }

    /// Registration UIDs separate cached content even when the catalogue name is reused.
    #[tokio::test]
    async fn two_images_of_one_name_do_not_share_a_cache_entry() {
        let (_temp, dir) = scratch("uid");
        let images = dir.join("images");
        std::fs::create_dir_all(&images).unwrap();
        let cache = Cache::new(images.clone());

        let theirs = b"the image one tenant registered".to_vec();
        let mine = b"what somebody else put under the same name".to_vec();
        let origin = dir.join("origin.raw");

        std::fs::write(&origin, &theirs).unwrap();
        let first = Source {
            name: "ubuntu.raw".into(),
            url: format!("file://{}", origin.display()),
            sha256: digest_of(&theirs),
            uid: "4f3c0000-0000-0000-0000-00000000000a".into(),
        };
        cache.ensure(&first).await.expect("fetched");

        std::fs::write(&origin, &mine).unwrap();
        let second = Source {
            name: "ubuntu.raw".into(),
            url: format!("file://{}", origin.display()),
            sha256: digest_of(&mine),
            uid: "9b210000-0000-0000-0000-00000000000b".into(),
        };
        cache.ensure(&second).await.expect("fetched");

        let entries = |source: &Source| {
            images
                .join(CACHE_DIR)
                .join(format!("{}-{}", source.uid, source.sha256))
        };
        assert!(entries(&first).exists(), "one entry per registration");
        assert!(entries(&second).exists());
        assert_ne!(entries(&first), entries(&second));
        assert!(
            !images.join(CACHE_DIR).join(&first.sha256).exists(),
            "and nothing under the bare digest, which is the namespace they shared"
        );
        // The catalogue name resolves to the replacement content.
        assert_eq!(std::fs::read(images.join("ubuntu.raw")).unwrap(), mine);

        // Repeated fetches reuse the same UID/digest cache entry.
        cache.ensure(&second).await.expect("already here");
        assert_eq!(
            std::fs::read_dir(images.join(CACHE_DIR))
                .unwrap()
                .filter_map(|e| e.ok())
                .count(),
            2
        );
    }

    /// Reject invalid UIDs before using them in cache paths or fetching bytes.
    #[test]
    fn a_uid_that_is_not_one_is_refused_before_anything_is_fetched() {
        assert!(check_uid("4f3c0000-0000-0000-0000-00000000000a").is_ok());
        assert!(check_uid("").is_ok(), "no cloud above this cluster");
        assert!(check_uid("../../etc/passwd").is_err());
        assert!(check_uid("a/b").is_err());
        assert!(check_uid("a.b").is_err(), "a dot is a path component");
        assert!(check_uid(&"a".repeat(65)).is_err());
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
            uid: String::new(),
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
            [(name, State::Failed { reason, message }, _digest)] => {
                assert_eq!(name, "ubuntu.raw");
                assert!(message.contains("checksum mismatch"), "{message}");
                // And in the word, so the catalogue can tell this apart from
                // a url that did not answer: the fix is a different one.
                assert_eq!(*reason, ImageReason::ChecksumMismatch);
            }
            other => panic!("{other:?}"),
        }
    }

    /// Failed connections produce a failure reason and no usable partial image.
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
            uid: String::new(),
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

        // Path verification must preserve an earlier fetch failure for the same catalogue name.
        cache.verify_path("ubuntu.raw").await;
        assert!(matches!(
            cache.report()[0].1,
            State::Failed {
                reason: ImageReason::FetchFailed,
                ..
            }
        ));
    }

    /// Re-registration updates the catalogue link while retaining older cached content.
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
                uid: String::new(),
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
                uid: String::new(),
            })
            .await
            .unwrap();

        assert_eq!(std::fs::read(images.join("ubuntu.raw")).unwrap(), second);
        assert!(images.join(CACHE_DIR).join(digest_of(&first)).exists());
        assert!(images.join(CACHE_DIR).join(digest_of(&second)).exists());
    }

    /// Directory inventory establishes presence; explicit verification retains richer failure evidence.
    #[tokio::test]
    async fn the_inventory_says_what_is_on_the_disk_and_a_look_still_wins() {
        let (_temp, images) = scratch("inventory");
        let cache = Cache::new(images.clone());

        std::fs::write(images.join("nixos.raw"), b"an image").expect("the bytes");
        std::fs::write(images.join("ubuntu.raw"), b"another").expect("the bytes");
        // Neither of these is a catalogue name, and both are shapes this
        // directory really holds: the content-addressed cache, and the hard
        // link a fetch stages before it renames it into place.
        std::fs::create_dir(images.join(CACHE_DIR)).expect("the cache dir");
        std::fs::write(images.join(".abc123.linking.4242"), b"half a link").expect("staged");
        std::fs::create_dir(images.join("not-an-image")).expect("a directory");

        assert!(cache.take_inventory().await, "the directory can be read");
        let mut said: Vec<(String, State, Option<String>)> = cache.report();
        said.sort_by(|a, b| a.0.cmp(&b.0));
        assert_eq!(
            said,
            vec![
                ("nixos.raw".to_string(), State::Ready, None),
                ("ubuntu.raw".to_string(), State::Ready, None),
            ],
            "two files, and nothing that is not one of them — and no digest for either: the \
             inventory only reads the directory, it never looks at a file's bytes"
        );

        // A remembered verification failure takes precedence over file presence.
        cache.remember(
            "ubuntu.raw",
            State::Failed {
                reason: ImageReason::ChecksumMismatch,
                message: "checksum mismatch for ubuntu.raw".into(),
            },
            true,
            None,
        );
        let mut said: Vec<(String, State, Option<String>)> = cache.report();
        said.sort_by(|a, b| a.0.cmp(&b.0));
        assert_eq!(said[0].0, "nixos.raw");
        assert_eq!(said[0].1, State::Ready);
        assert_eq!(said[1].0, "ubuntu.raw");
        assert_eq!(said[1].1.reason(), Some(ImageReason::ChecksumMismatch));
        assert_eq!(said.len(), 2, "one line per name, whatever the sources");

        // An explicitly checked missing image carries its failure reason alongside inventory completeness.
        cache.verify_path("chaos-img-bad.raw").await;
        let said = cache.report();
        let bad = said
            .iter()
            .find(|(name, _, _)| name == "chaos-img-bad.raw")
            .expect("a line");
        assert_eq!(bad.1.reason(), Some(ImageReason::NotFound));

        // Reuse an unchanged directory inventory.
        assert!(cache.take_inventory().await);
        assert_eq!(cache.report().len(), 3);

        // An unreadable catalogue is incomplete; do not infer that its images are absent.
        let gone = Cache::new(images.join("nowhere"));
        assert!(!gone.take_inventory().await);
        assert!(gone.report().is_empty());
    }

    /// Path-image status follows file presence without a fetch or a VM creation.
    #[tokio::test]
    async fn a_path_image_says_whether_its_bytes_are_here() {
        let (_temp, images) = scratch("path");
        let cache = Cache::new(images.clone());

        // Unobserved images produce no status entries.
        assert!(cache.report().is_empty());

        cache.verify_path("nixos.raw").await;
        let (name, state, digest) = cache.report().pop().expect("one opinion");
        assert_eq!(name, "nixos.raw");
        assert_eq!(digest, None, "nothing was there to hash");
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

        // Restore the file and verify that a later check reports Ready with a digest.
        std::fs::write(images.join("nixos.raw"), b"an image").expect("the bytes");
        cache.verify_path("nixos.raw").await;
        assert_eq!(
            cache.report(),
            vec![(
                "nixos.raw".to_string(),
                State::Ready,
                Some(digest_of(b"an image"))
            )],
            "the registry follows the file, and now hashes it"
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

    /// The cached path digest is intentionally stale after an in-place replacement until restart.
    #[tokio::test]
    async fn a_path_images_digest_is_bound_once_and_trusted_after_that() {
        let (_temp, images) = scratch("digest-once");
        let cache = Cache::new(images.clone());

        std::fs::write(images.join("nixos.raw"), b"the original bytes").expect("the bytes");
        cache.verify_path("nixos.raw").await;
        let (_, _, first) = cache.report().pop().expect("one opinion");
        assert_eq!(first, Some(digest_of(b"the original bytes")));

        // The bytes change underneath the same path, without a restart.
        std::fs::write(images.join("nixos.raw"), b"different bytes now").expect("swapped");
        cache.verify_path("nixos.raw").await;
        let (_, state, second) = cache.report().pop().expect("still one opinion");
        assert_eq!(state, State::Ready, "the file is still there");
        assert_eq!(
            second, first,
            "the remembered digest, not a re-hash of the new bytes"
        );

        // A fresh `Cache` — this process's stand-in for a restart — has no
        // memory of the first look and binds to what is actually there now.
        let restarted = Cache::new(images.clone());
        restarted.verify_path("nixos.raw").await;
        let (_, _, after_restart) = restarted.report().pop().expect("one opinion");
        assert_eq!(after_restart, Some(digest_of(b"different bytes now")));
    }

    /// A delayed drop for an old UID must preserve the replacement registration and its link.
    #[tokio::test]
    async fn drop_uid_removes_the_right_registrations_bytes_and_not_a_same_named_others() {
        let (_temp, dir) = scratch("drop-uid");
        let images = dir.join("images");
        std::fs::create_dir_all(&images).unwrap();
        let cache = Cache::new(images.clone());
        let origin = dir.join("origin.raw");

        let old = b"the image that gets deleted".to_vec();
        std::fs::write(&origin, &old).unwrap();
        let old_uid = "4f3c0000-0000-0000-0000-00000000000a";
        let old_source = Source {
            name: "ubuntu.raw".into(),
            url: format!("file://{}", origin.display()),
            sha256: digest_of(&old),
            uid: old_uid.into(),
        };
        cache.ensure(&old_source).await.expect("fetched");
        let old_cache_file = images.join(CACHE_DIR).join(old_source.cache_key());
        assert!(old_cache_file.exists());

        // Fetch a replacement registration before the delayed drop of the old UID.
        let new = b"a completely different image, same name".to_vec();
        std::fs::write(&origin, &new).unwrap();
        let new_uid = "9b210000-0000-0000-0000-00000000000b";
        let new_source = Source {
            name: "ubuntu.raw".into(),
            url: format!("file://{}", origin.display()),
            sha256: digest_of(&new),
            uid: new_uid.into(),
        };
        cache.ensure(&new_source).await.expect("fetched");
        let new_cache_file = images.join(CACHE_DIR).join(new_source.cache_key());
        assert!(new_cache_file.exists());
        assert_eq!(std::fs::read(images.join("ubuntu.raw")).unwrap(), new);

        // The old uid is dropped. Its own cache file goes; the new
        // registration's file, link and reported state are untouched.
        cache.drop_uid("ubuntu.raw", old_uid).await;
        assert!(!old_cache_file.exists(), "the dropped uid's bytes are gone");
        assert!(
            new_cache_file.exists(),
            "a different uid under the same name is not this drop's to touch"
        );
        assert_eq!(
            std::fs::read(images.join("ubuntu.raw")).unwrap(),
            new,
            "the catalogue link still names the current registration"
        );
        assert!(matches!(
            cache.report().iter().find(|(n, _, _)| n == "ubuntu.raw"),
            Some((_, State::Ready, _))
        ));

        // Dropping the uid that IS current removes the link too, and this
        // node's opinion of the name along with it.
        cache.drop_uid("ubuntu.raw", new_uid).await;
        assert!(!new_cache_file.exists());
        assert!(
            !images.join("ubuntu.raw").exists(),
            "the link followed its own bytes out"
        );
        assert!(cache.report().is_empty());
    }

    /// An empty UID must not remove cached images.
    #[tokio::test]
    async fn dropping_an_empty_uid_is_a_no_op() {
        let (_temp, dir) = scratch("drop-uid-empty");
        let images = dir.join("images");
        std::fs::create_dir_all(&images).unwrap();
        let cache = Cache::new(images.clone());
        let origin = dir.join("origin.raw");
        let payload = b"bytes".to_vec();
        std::fs::write(&origin, &payload).unwrap();
        let source = Source {
            name: "ubuntu.raw".into(),
            url: format!("file://{}", origin.display()),
            sha256: digest_of(&payload),
            uid: "4f3c0000-0000-0000-0000-00000000000a".into(),
        };
        cache.ensure(&source).await.expect("fetched");

        cache.drop_uid("ubuntu.raw", "").await;
        assert!(images.join("ubuntu.raw").exists());
        assert!(images.join(CACHE_DIR).join(source.cache_key()).exists());
    }

    /// A path image has no cache entry, so dropping any uid for its name is a
    /// harmless no-op: the file its catalogue name points at is shared
    /// storage this node never wrote to.
    #[tokio::test]
    async fn dropping_a_path_images_uid_touches_nothing() {
        let (_temp, images) = scratch("drop-uid-path");
        std::fs::create_dir_all(&images).unwrap();
        let cache = Cache::new(images.clone());
        std::fs::write(images.join("nixos.raw"), b"somebody else's file").expect("the bytes");
        cache.verify_path("nixos.raw").await;
        assert_eq!(cache.report().len(), 1);

        cache
            .drop_uid("nixos.raw", "4f3c0000-0000-0000-0000-00000000000a")
            .await;

        assert!(
            images.join("nixos.raw").exists(),
            "shared storage, untouched"
        );
        assert_eq!(cache.report().len(), 1, "this node's opinion is unchanged");
    }
}
