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
use std::time::Duration;

use anyhow::{Context, Result, bail};
use sha2::{Digest, Sha256};

use crate::reconcile::ImageReason;
use tokio::io::AsyncWriteExt;
use tracing::{debug, info, instrument};

pub mod egress;
use egress::{EgressPolicy, Pinned};

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
    /// The uid of the `Image` object these bytes were registered as.
    ///
    /// Astra finding S02, 2026-09-23: the cache entry was addressed by the
    /// digest alone and the catalogue NAME is global, so two images that are
    /// the same file to this node are the same cache entry however many
    /// tenants registered them and whatever happened to their objects. The
    /// uid is what makes an entry belong to the registration it was fetched
    /// for: it is minted once, at the cloud, and never reused.
    ///
    /// Empty for a record written before the field existed, and for a
    /// standalone cluster with no cloud above it to mint one. Then the entry
    /// is addressed by the digest exactly as it always was — a cache that
    /// silently stopped matching would re-download every image on the fleet.
    #[serde(default)]
    pub uid: String,
}

impl Source {
    /// What this image is called inside the node's cache.
    ///
    /// The uid and the digest, and neither of them alone: the digest is what
    /// makes the presence of the file proof that these are the right bytes,
    /// and the uid is what keeps one registration's bytes from answering for
    /// another's. The NAME is deliberately not in it — that is the namespace
    /// two tenants share, and sharing it was the finding.
    ///
    /// The whole digest and not a prefix of it, because this is a file name
    /// nobody types: a prefix would buy shorter `ls` output and pay for it
    /// with a collision nobody would ever debug.
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
    known: Mutex<HashMap<String, Entry>>,
    /// Everything that IS in the image directory, and when that directory
    /// last changed. See [`Cache::take_inventory`].
    inventory: Mutex<Option<Inventory>>,
    /// What a download may cost before it is cut off. See [`Bounds`].
    bounds: Bounds,
    /// Where a download may go. See [`egress`]; `Cache::new` allows nothing
    /// until [`Cache::with_egress`] says otherwise (R3-F10).
    egress: EgressPolicy,
}

/// A reading of the image directory, and the mtime it was read at.
struct Inventory {
    /// The directory's mtime BEFORE the read. A list taken after this instant
    /// is never older than it claims to be, which is the direction this has
    /// to be wrong in.
    at: std::time::SystemTime,
    /// The bare file names, sorted. These ARE catalogue names: the cloud
    /// refuses an image whose `metadata.name` is not the file its source
    /// points at (`check_image_name`), and the volume drivers resolve
    /// `base_image` by joining the name onto their own image_dir. So nothing
    /// is translated here, and nothing has to be.
    names: Vec<String>,
}

/// One image's line in this node's opinion, and where the opinion came from.
struct Entry {
    state: State,
    /// This node FETCHED these bytes rather than looked for somebody else's
    /// file: the entry came from [`Cache::ensure`] and not from
    /// [`Cache::verify_path`].
    ///
    /// It is remembered because a volume record names its base image by
    /// catalogue name and nothing else — the url half only ever travels in a
    /// VM spec — so the pass that looks at path images cannot tell the two
    /// apart from the records alone. Re-stating a fetched image as a path one
    /// would replace "the checksum did not match" with "it has no url, so
    /// nothing here fetches it", which is the one sentence that is certainly
    /// wrong about it.
    fetched: bool,
    /// The sha256 of a PATH image's bytes, hashed the first time this entry
    /// went Ready and remembered from then on.
    ///
    /// Astra finding S02, 2026-09-23 (rest a). `None` for a fetched entry
    /// (its digest is `Source::sha256`, already checked at fetch time and not
    /// worth a second statement) and for a path entry this process has not
    /// successfully looked at yet.
    ///
    /// Computed ONCE per process lifetime and never again while the entry
    /// stays Ready: `verify_path` runs on every status report and every
    /// reconcile pass, and hashing a multi-gigabyte image on that schedule
    /// would turn a `stat` into the cost `take_inventory`'s own doc comment
    /// goes out of its way to avoid. The trade this makes is the same one the
    /// fetch cache already makes for its own digest — trusted between looks,
    /// re-earned on a restart — so a file swapped on shared storage is caught
    /// at the next agent restart rather than within one report interval.
    digest: Option<String>,
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
            inventory: Mutex::default(),
            bounds: Bounds::default(),
            egress: EgressPolicy::deny_all(),
        }
    }

    /// The same cache with the operator's egress policy, from
    /// `[images] allowed_sources`. Without it no url image is fetched at all,
    /// which is the safe direction for a cache somebody forgot to configure
    /// (Astra finding R3-F10, 2026-09-25).
    pub fn with_egress(mut self, egress: EgressPolicy) -> Self {
        self.egress = egress;
        self
    }

    /// The same cache with different download bounds.
    ///
    /// A builder call and not a second argument to `new`, for the reason
    /// `Provisioner::with_ceilings` is one: `Bounds::default()` is what every
    /// node runs with, and a caller that says nothing gets it.
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

    /// Read the image directory, unless it has not changed since the last
    /// reading. `true` when the answer can be trusted as complete.
    ///
    /// F16's other half, and the whole of what makes it closable from here:
    /// the node stops waiting to be asked about an image and says what it
    /// HAS. Nothing tells a node about an `Image` that no record of its own
    /// names — `SyncState` carries VMs and there is no image command — so the
    /// only statement that can cover such an image is one about the
    /// directory. With `images_complete` set, the tier above may read the
    /// absence of a name as the absence of the file.
    ///
    /// A `readdir` and no more: no download, no checksum, and no `stat` per
    /// entry either — `read_dir` on Linux answers the file type from the
    /// directory entry itself, so the whole inventory is one syscall's worth
    /// of work. It is cached on the directory's own mtime, so a fleet's
    /// steady state costs one `metadata` call per report.
    ///
    /// The cache is deliberately distrusted for one second after the mtime it
    /// holds: mtimes are coarse, and a file that appears in the same second as
    /// a reading would leave behind exactly the mtime that reading recorded.
    /// Re-reading for a second afterwards costs a `readdir` on a directory
    /// somebody is changing anyway.
    ///
    /// `false` on any failure, and then this node says nothing: a directory
    /// that cannot be read must not become "the file is not there", which is
    /// the one mistake that would make F16 worse rather than better.
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
                    // A name that starts with a dot is not a catalogue name:
                    // the content-addressed cache is `.cache`, and a fetch
                    // stages its hard link as `.<digest>.linking.<pid>` right
                    // here. The cloud cannot mint such a name either — it
                    // refuses `.` and `..` outright and everything with a
                    // separator in it.
                    if name.starts_with('.') {
                        continue;
                    }
                    // Only regular files. A directory under a catalogue name
                    // is not an image (`verify_path` says so in a sentence),
                    // and a `Ready` about one would hand a storage driver a
                    // path it cannot open.
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

    /// Every image this node has an opinion about, for the status report.
    ///
    /// Two sources, and the order between them is the whole of the merge. An
    /// entry in `known` is a LOOK at one named image — a fetch, or the
    /// `verify_path` this node runs for every image its records name — and it
    /// wins, because it can say things the inventory cannot: a checksum that
    /// did not match, a directory under the name, a path with nothing at it.
    /// The inventory adds `Ready` for every file nobody asked about, which is
    /// the half F16 needed.
    ///
    /// The third element is the digest `verify_path` bound, when it has one
    /// (Astra finding S02, 2026-09-23, rest a). `None` for everything the
    /// inventory adds on its own: a file nobody's record names is a file this
    /// node has never been asked to hash, and inventing a look here would
    /// undo the bound `take_inventory` exists to hold.
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
        // Sorted so two consecutive reports of the same facts are the same
        // message; the tier above compares them.
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

    /// The digest already remembered for `name`, if this process has one.
    ///
    /// Read before [`remember`] overwrites the entry, so a path image's
    /// digest survives every look after the first that found one. See
    /// [`Entry::digest`].
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
    /// A `stat`, on every look but the first that finds the bytes there. What
    /// this can say without more is the half that was missing and is worth
    /// everything: the file is there, or it is not and here is the path that
    /// was looked at.
    ///
    /// Level-triggered like everything else this node reports: called on every
    /// provision that names the image AND once per reconcile pass over the
    /// records that name it, so an image restored on shared storage goes back
    /// to `Ready` without anybody creating a VM to prove it.
    ///
    /// ## The digest, and why it is not a `stat`'s cost
    ///
    /// Astra finding S02, 2026-09-23 (rest a). A path image has no checksum
    /// by construction — that is what distinguishes it from a URL image —
    /// so nothing bound the catalogue name to particular bytes until this
    /// existed. The FIRST look that finds the file hashes it and remembers
    /// the digest on the entry; every look after that, on the same entry,
    /// reuses the remembered value rather than hashing again. Re-hashing on
    /// this schedule — every report and every reconcile pass — would turn a
    /// `stat` into exactly the cost `take_inventory`'s own doc comment goes
    /// out of its way to avoid, for a multi-gigabyte image. The cost this
    /// keeps instead: a file swapped on shared storage after this node's
    /// first look is not caught until the agent restarts and looks again,
    /// exactly the trust the content-addressed fetch cache already extends
    /// between uses of its own.
    pub async fn verify_path(&self, name: &str) {
        // An image this node FETCHED is not a path image, whatever a record
        // calls it. See `Entry::fetched`: the digest is what verified those
        // bytes, and a `stat` here could only make the answer vaguer.
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
                        // Not fatal to the look: the file is there, which is
                        // what F16 needed, and an unhashable file is worth a
                        // debug line rather than turning a present image into
                        // a failed one over a statement nothing requires yet.
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

    /// Make sure this image is on the node, fetching it if it is not.
    ///
    /// Idempotent and cheap on the common path: a `stat` of the cache entry,
    /// and nothing else. The first use of an image pays for the download; no
    /// later one does, on this node or for any other VM.
    #[instrument(skip(self), fields(image = %source.name, sha = %source.sha256))]
    pub async fn ensure(&self, source: &Source) -> Result<()> {
        match self.ensure_inner(source).await {
            Ok(()) => {
                // No digest here: `source.sha256` already IS the checked
                // digest of these bytes, so `Image.status.digest` — which
                // exists to bind a PATH image nothing else checks — has
                // nothing to add for one that arrived with its own checksum.
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
        let partial = self.cache_dir().join(format!(
            "{}.partial.{}",
            source.cache_key(),
            std::process::id()
        ));
        let fetched = fetch(&source.url, &partial, &self.bounds, &self.egress).await;
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

    /// Remove this node's cache entry for a deleted image, addressed by uid
    /// and never by name.
    ///
    /// Astra finding S02, 2026-09-23 (rest b). `delete_image` at the cloud
    /// removes the catalogue OBJECT and tells no node anything, so whatever a
    /// node had fetched for it used to sit in `.cache/` and under its name
    /// forever — including across a NAME recycled for an unrelated later
    /// registration, which is exactly the shape a name-keyed removal would
    /// get wrong. `uid` is what makes a removal safe to run by command
    /// instead of by inference: the cloud mints it once and never reuses it,
    /// so a cache entry keyed on it (`Source::cache_key`) can only ever be
    /// the bytes this one registration fetched.
    ///
    /// `name` is read once, before anything is removed, and spent on exactly
    /// one question: does the CATALOGUE LINK under it still point at the uid
    /// being dropped? Same-inode is the proof, the same test `link` runs the
    /// other way to decide a second use needs no work — never a name
    /// comparison, because the name may already belong to a different
    /// registration's bytes by the time this command arrives.
    ///
    /// A path image has no entry here to begin with — see the module doc — so
    /// this is a harmless no-op for one: nothing under `.cache/` is ever keyed
    /// to a path image's uid, and the file its catalogue name points at is
    /// shared storage this node never wrote to and this command does not
    /// touch.
    pub async fn drop_uid(&self, name: &str, uid: &str) {
        if uid.is_empty() {
            // Nothing to scope a removal to. Sweeping the whole cache on an
            // empty uid would be exactly the name-keyed mistake this exists
            // to avoid, just spelled differently.
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
        // The catalogue link and this node's opinion of `name` both go only
        // when the link provably pointed at the bytes just removed — a
        // re-registration under this name that this node already fetched
        // must not lose its link or its `Ready` state to a drop that arrived
        // late for the OLD registration.
        if link_place.is_some() && link_place == dropped_place {
            let _ = tokio::fs::remove_file(&linked).await;
            self.known.lock().unwrap().remove(name);
        }
    }
}

/// The `(dev, ino)` pair that proves two paths are the same file, or `None`
/// if this one could not be looked at. See [`Cache::drop_uid`] and `link`,
/// which runs the same test the other way.
async fn place_of(path: &Path) -> Option<(u64, u64)> {
    use std::os::unix::fs::MetadataExt;
    tokio::fs::metadata(path)
        .await
        .ok()
        .map(|m| (m.dev(), m.ino()))
}

/// What a download may cost before this node stops paying for it.
///
/// Astra finding S15, 2026-09-23: `fetch` ran `curl --fail --location
/// --silent --show-error <url>` with no bound of any kind, and the node's
/// whole command loop sits behind it — `pump` handles one controller command
/// at a time, and the create that reaches here used to hold the global `ops`
/// lock across the transfer. A url that answered its headers and then went
/// quiet took the node with it for as long as the other end cared to hold the
/// socket. These four numbers are what ends that wait.
///
/// Defaults rather than configuration: the cache is built from a directory
/// and nothing else (`Cache::new`, called before the agent has a config to
/// hand it), so the numbers live with the code that uses them and a caller
/// that wants others says so with [`Cache::with_bounds`]. They are chosen to
/// be far outside any honest download on this fleet — a 4 GiB cloud image
/// over a 1 KiB/s link would still finish — and close enough to catch a dead
/// one within a minute.
#[derive(Clone, Copy, Debug)]
pub struct Bounds {
    /// Slower than this for [`Bounds::idle`], and the transfer is over. The
    /// cut-off that actually matters: what a stalled download looks like from
    /// here is a socket that is open and says nothing, and no timeout on the
    /// WHOLE transfer can tell that apart from a big file in time to help.
    pub floor_bytes_per_sec: u64,
    /// How long the transfer may stay under the floor before it is cut.
    pub idle: Duration,
    /// The whole transfer, headers included.
    pub deadline: Duration,
    /// What the file may not grow past. A url that answers with a terabyte is
    /// not a base image, and the node's disk is what pays for finding out —
    /// the same disk the agent's database is on.
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

/// The argv one hop of `fetch` runs, with every bound in it.
///
/// A function of its own so that the bounds can be read off a value in a test
/// instead of off a process nobody can see. `--fail` so a 404 is an error and
/// not a file containing the words "not found", `--silent --show-error` so
/// nothing but the bytes goes to stdout and the reason goes to stderr.
///
/// Astra finding R3-F10, 2026-09-25: `--location` is gone. curl follows no
/// redirect (`--max-redirs 0`) and speaks nothing but http and https
/// (`--proto`, `--proto-redir`); a 3xx is reported back through
/// `--write-out` and its target is vetted by [`egress`] before the next hop
/// is started. `-q` comes first so no `.curlrc` can add a flag back, and
/// `--noproxy '*'` so no proxy variable routes the request somewhere the
/// pinned address does not describe.
fn curl_argv(pinned: &Pinned, bounds: &Bounds, max_time: Duration) -> Vec<String> {
    let mut argv = vec![
        "-q".to_string(),
        "--fail".to_string(),
        "--silent".to_string(),
        "--show-error".to_string(),
        "--proto".to_string(),
        "=http,https".to_string(),
        "--proto-redir".to_string(),
        "=http,https".to_string(),
        "--max-redirs".to_string(),
        "0".to_string(),
        "--noproxy".to_string(),
        "*".to_string(),
        // The idle cut-off, in curl's own two halves.
        "--speed-limit".to_string(),
        bounds.floor_bytes_per_sec.to_string(),
        "--speed-time".to_string(),
        bounds.idle.as_secs().to_string(),
        // And the ceiling on the whole thing, connection included: what is
        // left of the deadline, so redirects cannot add up past it.
        "--max-time".to_string(),
        max_time.as_secs().max(1).to_string(),
        // Only ever a first line of defence: curl decides this from the
        // length the SERVER declared, so a server that declares none walks
        // past it. `drain` counts what arrives.
        "--max-filesize".to_string(),
        bounds.max_bytes.to_string(),
        "--write-out".to_string(),
        format!("%{{stderr}}\n{HOP_MARKER} %{{http_code}} %{{redirect_url}}\n"),
    ];
    // `--resolve` and the canonical url, last: the url is the last word, so
    // no bound can be read as one.
    argv.extend(pinned.curl_args());
    argv
}

/// The line `--write-out` puts on curl's stderr after every transfer.
const HOP_MARKER: &str = "meister-fetch-hop";

/// How many redirects one image fetch follows. Cloud image hosts redirect
/// once or twice to a mirror; a chain longer than this is a loop.
const MAX_REDIRECTS: usize = 5;

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

/// A uid that is not one is refused before anything is downloaded.
///
/// The same reason `check_digest` exists and the same danger: the uid names
/// the cache entry, so a value with a slash or a `..` in it would write
/// outside the cache directory. What the cloud mints is a uuid; what is
/// accepted here is the shape of one and nothing looser.
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

/// Hash a file already on this node's disk, for a path image's first look.
///
/// Astra finding S02, 2026-09-23 (rest a). Streamed in fixed-size chunks
/// exactly like [`drain`] hashes a download, so the whole file is never held
/// in memory at once.
///
/// Under a deadline for the same reason [`fetch`]'s read loop is (Astra
/// finding S15): a path image is, by its own definition, somebody else's
/// file on SHARED storage, and a mount that has wedged would otherwise park
/// this call on a `read` that never returns. `bounds.deadline` is reused
/// rather than given a config key of its own — it is already the "how long
/// may this node wait on bytes it did not ask a server for" number, and a
/// second one next to it would be a second knob nobody has a reason to set
/// differently.
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
async fn fetch(url: &str, into: &Path, bounds: &Bounds, egress: &EgressPolicy) -> Result<String> {
    let started = std::time::Instant::now();
    let mut next = url.to_string();
    for _ in 0..=MAX_REDIRECTS {
        // Astra finding R3-F10, 2026-09-25: every hop, the first one
        // included, is vetted BEFORE curl is started, and curl is then held
        // to the address that was vetted.
        let pinned = egress.vet(&next).await?;
        let left = bounds.deadline.saturating_sub(started.elapsed());
        if left.is_zero() {
            bail!(
                "fetching {url} did not finish within {}s and was stopped; nothing usable was \
                 written",
                bounds.deadline.as_secs()
            );
        }
        match fetch_hop(&pinned, into, bounds, left).await? {
            Hop::Done(digest) => return Ok(digest),
            Hop::Redirect(to) => {
                debug!(from = %pinned.url.canonical(), %to, "the image url redirects");
                next = to;
            }
        }
    }
    bail!("fetching {url} was redirected more than {MAX_REDIRECTS} times and was stopped")
}

/// What one request ended with.
enum Hop {
    Done(String),
    Redirect(String),
}

/// One request, to one vetted address.
async fn fetch_hop(pinned: &Pinned, into: &Path, bounds: &Bounds, left: Duration) -> Result<Hop> {
    use tokio::io::AsyncReadExt;
    use tokio::process::Command;

    let url = pinned.url.canonical();
    let mut command = Command::new("curl");
    command.args(curl_argv(pinned, bounds, left));
    // No proxy from the environment, for the reason `--noproxy` is passed.
    for var in [
        "http_proxy",
        "https_proxy",
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "all_proxy",
        "ALL_PROXY",
        "no_proxy",
        "NO_PROXY",
        "CURL_HOME",
    ] {
        command.env_remove(var);
    }
    let mut child = command
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .with_context(|| {
            format!("running curl to fetch {url} - is curl on the agent's PATH? (nix/agent.nix)")
        })?;

    let mut stdout = child.stdout.take().expect("stdout was piped");
    // Created fresh for every hop: the body of a redirect is not the image.
    let mut file = tokio::fs::File::create(into)
        .await
        .with_context(|| format!("creating {}", into.display()))?;

    // Astra finding S15, 2026-09-23: the read loop is under a deadline of its
    // own and not only under curl's. The three curl bounds are the right
    // first line — they are what can see a slow socket — but they are bounds
    // a DIFFERENT process keeps, and the thing being protected here is this
    // one: a curl that was replaced, wedged in uninterruptible I/O, or stopped
    // would otherwise park the agent's whole command loop on a `read` that
    // never returns.
    let drained = tokio::time::timeout(
        left.saturating_add(BOUND_GRACE),
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

    // Curl has written its last byte by here, so this is a wait for an exit
    // status and not for a transfer — and it is still bounded, because the
    // one thing this function may not do is wait for ever on anything.
    let status = match tokio::time::timeout(BOUND_GRACE, child.wait()).await {
        Ok(status) => status.context("waiting for curl")?,
        Err(_) => {
            kill_and_reap(&mut child).await;
            bail!("curl did not exit after fetching {url} and was stopped");
        }
    };
    let mut said = String::new();
    if let Some(mut stderr) = child.stderr.take() {
        let _ = stderr.read_to_string(&mut said).await;
    }
    let (hop, said) = read_hop(&said);
    if !status.success() {
        bail!(
            "fetching {url} failed ({status}){}",
            if said.is_empty() {
                String::new()
            } else {
                format!(": {said}")
            }
        );
    }
    match hop {
        Some((code, to)) if matches!(code, 301 | 302 | 303 | 307 | 308) && !to.is_empty() => {
            Ok(Hop::Redirect(to))
        }
        Some((code, _)) if (300..400).contains(&code) => {
            bail!("fetching {url} answered {code} and no redirect this node can follow")
        }
        Some(_) => Ok(Hop::Done(digest)),
        None => bail!("curl said nothing about how fetching {url} ended"),
    }
}

/// Split curl's stderr into the `--write-out` line and everything else.
fn read_hop(stderr: &str) -> (Option<(u16, String)>, String) {
    let mut hop = None;
    let mut rest = Vec::new();
    for line in stderr.lines() {
        match line.strip_prefix(HOP_MARKER) {
            Some(tail) => {
                let mut words = tail.split_whitespace();
                let code = words.next().and_then(|c| c.parse::<u16>().ok());
                let to = words.next().unwrap_or("").to_string();
                hop = code.map(|c| (c, to));
            }
            None if !line.trim().is_empty() => rest.push(line.trim()),
            None => {}
        }
    }
    (hop, rest.join(" "))
}

/// Read curl's stdout into the file, hashing as it goes, and stop at the byte
/// budget.
///
/// The budget is counted HERE as well as handed to curl, and the two are not
/// the same check: `--max-filesize` is a decision made from the length the
/// server declared, so a server that declares none — or declares a small one
/// and sends a large one — walks straight past it. This one counts what
/// actually arrived.
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

/// Signal the child and then WAIT for it, on every path out of a failed
/// fetch.
///
/// Both halves, and the second is the one that gets forgotten: a killed
/// process nobody waits for is a zombie until its parent exits, and this
/// parent is an agent that runs for months. Neither error is worth more than
/// a debug line — "the process is already gone" is exactly the outcome that
/// was being asked for.
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

    /// A cache whose egress policy lets it reach the loopback listeners
    /// these tests serve their origins from, and nothing else. Since R3-F10
    /// `Cache::new` fetches from nowhere, and `file://` is refused outright.
    fn test_cache(images: PathBuf) -> Cache {
        Cache::new(images).with_egress(EgressPolicy::any_loopback_for_tests())
    }

    /// Serve `path` over http on a loopback port of its own for the rest of
    /// the test process, and return its url. The file is read per request,
    /// so a test that rewrites or removes it changes what the next fetch
    /// gets (404 when it is gone).
    fn served(path: &Path) -> String {
        let path = path.to_path_buf();
        origin(move |_| match std::fs::read(&path) {
            Ok(body) => ok_response(&body),
            Err(_) => {
                b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_vec()
            }
        })
        .url("/image.raw")
    }

    fn ok_response(body: &[u8]) -> Vec<u8> {
        let mut out = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        )
        .into_bytes();
        out.extend_from_slice(body);
        out
    }

    /// A throwaway http origin on 127.0.0.1: every request is answered by
    /// `respond(path)`, and every accepted connection is counted.
    struct Origin {
        port: u16,
        hits: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    }

    impl Origin {
        fn url(&self, path: &str) -> String {
            format!("http://127.0.0.1:{}{path}", self.port)
        }

        fn hits(&self) -> usize {
            self.hits.load(std::sync::atomic::Ordering::SeqCst)
        }
    }

    fn origin(respond: impl Fn(&str) -> Vec<u8> + Send + 'static) -> Origin {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("a port");
        let port = listener.local_addr().expect("an address").port();
        let hits = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counted = hits.clone();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { continue };
                counted.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                stream.set_read_timeout(Some(Duration::from_secs(5))).ok();
                let mut request = Vec::new();
                let mut buf = [0u8; 1024];
                while !request.windows(4).any(|w| w == b"\r\n\r\n") {
                    match stream.read(&mut buf) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => request.extend_from_slice(&buf[..n]),
                    }
                }
                let text = String::from_utf8_lossy(&request);
                let path = text.split_whitespace().nth(1).unwrap_or("/").to_string();
                let _ = stream.write_all(&respond(&path));
                let _ = stream.flush();
            }
        });
        Origin { port, hits }
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

    /// Whether anything on this machine is still running a curl that names
    /// this port. Only the fetch under test can have started one, so this is
    /// exactly "did the fetch leave its download behind".
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

    /// Every bound is on the command line, and the command line is what the
    /// download actually runs with.
    ///
    /// Astra finding S15, 2026-09-23: this argv used to carry no bound, so a
    /// url that answered its headers and then went quiet held the node's
    /// command loop for as long as the other end wanted. Astra finding
    /// R3-F10, 2026-09-25: and it used to say `--location`, so curl followed
    /// any redirect to any address. The test is on the argv rather than on a
    /// transfer because that is where the bounds are.
    #[test]
    fn the_download_argv_carries_every_bound() {
        let bounds = Bounds {
            floor_bytes_per_sec: 1024,
            idle: Duration::from_secs(60),
            deadline: Duration::from_secs(7200),
            max_bytes: 1 << 30,
        };
        let pinned = Pinned {
            url: common::fetch_url::FetchUrl::parse("https://images.example/noble.img").unwrap(),
            addr: "93.184.215.14".parse().unwrap(),
        };
        let argv = curl_argv(&pinned, &bounds, Duration::from_secs(7000));

        let after = |flag: &str| {
            argv.iter()
                .position(|a| a == flag)
                .and_then(|i| argv.get(i + 1))
                .map(String::as_str)
        };
        assert_eq!(argv.first().map(String::as_str), Some("-q"), "no .curlrc");
        assert_eq!(after("--speed-limit"), Some("1024"), "the idle floor");
        assert_eq!(after("--speed-time"), Some("60"), "how long under it");
        assert_eq!(
            after("--max-time"),
            Some("7000"),
            "what is left of the deadline"
        );
        assert_eq!(after("--max-filesize"), Some("1073741824"), "the budget");
        assert_eq!(after("--max-redirs"), Some("0"), "curl follows nothing");
        assert_eq!(after("--proto"), Some("=http,https"));
        assert_eq!(after("--proto-redir"), Some("=http,https"));
        assert_eq!(after("--noproxy"), Some("*"));
        assert_eq!(
            after("--resolve"),
            Some("images.example:443:93.184.215.14"),
            "pinned to the vetted address"
        );
        assert!(
            !argv.iter().any(|a| a == "--location" || a == "-L"),
            "redirects are followed here, after a check, and never by curl"
        );
        for flag in ["--fail", "--silent", "--show-error"] {
            assert!(argv.iter().any(|a| a == flag), "{flag} is still passed");
        }
        assert_eq!(
            argv.last().map(String::as_str),
            Some("https://images.example:443/noble.img"),
            "the canonical url is the last word, so no bound can be read as one"
        );
    }

    /// A redirect is followed only after its target passes the same check,
    /// and one to a denied target is refused BEFORE a second request is
    /// made: the second listener never sees a connection.
    ///
    /// Astra finding R3-F10, 2026-09-25. The first origin is on a loopback
    /// port this test's policy admits; the target is loopback on a port it
    /// does not, which stands for every address the node may not reach.
    #[tokio::test]
    async fn a_redirect_to_a_denied_address_is_refused_before_it_is_requested() {
        let (_temp, dir) = scratch("redirect");
        let images = dir.join("images");
        std::fs::create_dir_all(&images).unwrap();

        let target = origin(|_| ok_response(b"what the metadata service would say"));
        let to = target.url("/latest/meta-data/");
        let first = origin(move |_| {
            format!(
                "HTTP/1.1 302 Found\r\nLocation: {to}\r\nContent-Length: 0\r\n\
                 Connection: close\r\n\r\n"
            )
            .into_bytes()
        });
        let cache =
            Cache::new(images.clone()).with_egress(EgressPolicy::loopback_for_tests(&[first.port]));
        let source = Source {
            name: "ubuntu.raw".into(),
            url: first.url("/ubuntu.raw"),
            sha256: digest_of(b"anything"),
            uid: String::new(),
        };

        let err = format!("{:#}", cache.ensure(&source).await.expect_err("refused"));
        assert!(err.contains("refused"), "{err}");
        assert_eq!(first.hits(), 1, "the first hop was made");
        assert_eq!(target.hits(), 0, "and the denied one never was: {err}");
        assert!(!images.join("ubuntu.raw").exists());
        let leftovers: Vec<_> = std::fs::read_dir(images.join(CACHE_DIR))
            .map(|d| d.filter_map(|e| e.ok()).map(|e| e.file_name()).collect())
            .unwrap_or_default();
        assert!(leftovers.is_empty(), "{leftovers:?}");
    }

    /// And a redirect to an admitted target is followed, and the bytes at
    /// the end of it are the image.
    #[tokio::test]
    async fn a_redirect_to_an_admitted_address_is_followed() {
        let (_temp, dir) = scratch("redirect-ok");
        let images = dir.join("images");
        std::fs::create_dir_all(&images).unwrap();
        let payload = b"the image, one hop on".to_vec();
        let body = payload.clone();
        let o = origin(move |path| match path {
            "/moved.raw" => ok_response(&body),
            _ => b"HTTP/1.1 301 Moved\r\nLocation: /moved.raw\r\nContent-Length: 0\r\n\
                   Connection: close\r\n\r\n"
                .to_vec(),
        });
        let cache =
            Cache::new(images.clone()).with_egress(EgressPolicy::loopback_for_tests(&[o.port]));
        let source = Source {
            name: "ubuntu.raw".into(),
            url: o.url("/ubuntu.raw"),
            sha256: digest_of(&payload),
            uid: String::new(),
        };
        cache.ensure(&source).await.expect("followed and fetched");
        assert_eq!(std::fs::read(images.join("ubuntu.raw")).unwrap(), payload);
        assert_eq!(o.hits(), 2);
    }

    /// Without a policy nothing is fetched, and the reason names the key.
    #[tokio::test]
    async fn a_cache_with_no_policy_fetches_nothing() {
        let (_temp, dir) = scratch("no-policy");
        let images = dir.join("images");
        std::fs::create_dir_all(&images).unwrap();
        let o = origin(|_| ok_response(b"x"));
        let cache = Cache::new(images.clone());
        let source = Source {
            name: "ubuntu.raw".into(),
            url: o.url("/ubuntu.raw"),
            sha256: digest_of(b"x"),
            uid: String::new(),
        };
        let err = format!("{:#}", cache.ensure(&source).await.expect_err("refused"));
        assert!(err.contains("allowed_sources"), "{err}");
        assert_eq!(o.hits(), 0, "nothing was connected to");
    }

    /// A url that answers its headers and then says nothing: the fetch comes
    /// back inside its bound, nothing usable is left, and the download it
    /// started is not still running.
    ///
    /// Astra finding S15, 2026-09-23. The bound in the test is seconds rather
    /// than the node's hours, which is the only difference between this and
    /// the fleet: a stall is a stall at either scale, and a test that waited
    /// for the real ceiling would be a test nobody runs.
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
            // The headers, and then nothing at all. The stream is KEPT so the
            // socket stays open: dropping it would end the transfer with an
            // error curl reports at once, which is the easy case and not this
            // one.
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

        let cache = test_cache(images.clone()).with_bounds(Bounds {
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

    /// Bytes past the budget are not written out to the end and then judged.
    ///
    /// Astra finding S15, 2026-09-23. Two checks say this, and which of them
    /// speaks depends on the other end: curl refuses a DECLARED length past
    /// the ceiling before a byte moves, and `drain` refuses the bytes that
    /// actually arrive when nobody declared a length. The same refusal either
    /// way, and the second is the one that cannot be talked out of it.
    #[tokio::test]
    async fn a_body_past_the_byte_budget_is_refused() {
        let (_temp, dir) = scratch("budget");
        let payload = vec![7u8; 4096];
        let origin = dir.join("origin.raw");
        std::fs::write(&origin, &payload).unwrap();

        let images = dir.join("images");
        std::fs::create_dir_all(&images).unwrap();
        let cache = test_cache(images.clone()).with_bounds(Bounds {
            max_bytes: 512,
            ..Bounds::default()
        });
        let source = Source {
            name: "ubuntu.raw".into(),
            url: served(&origin),
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

    /// A URL that answers, byte for byte, and a second use that does not
    /// fetch again. A loopback origin is a real http fetch through the whole
    /// road, egress check included, so this exercises the stream, the hash,
    /// the temp file, the rename and the link.
    #[tokio::test]
    async fn an_image_is_fetched_once_and_then_found() {
        let (_temp, dir) = scratch("fetch-once");
        let payload = b"a stock cloud image, in miniature".repeat(64);
        let origin = dir.join("origin.raw");
        std::fs::write(&origin, &payload).unwrap();

        let images = dir.join("images");
        std::fs::create_dir_all(&images).unwrap();
        let cache = test_cache(images.clone());
        let source = Source {
            name: "ubuntu.raw".into(),
            url: served(&origin),
            sha256: digest_of(&payload),
            uid: String::new(),
        };

        cache.ensure(&source).await.expect("fetched");
        // Where the volume drivers will look, with the right bytes in it.
        let placed = images.join("ubuntu.raw");
        assert_eq!(std::fs::read(&placed).unwrap(), payload);
        // And in the cache under its own digest, which is what makes the
        // second use free. The bare digest and not `<uid>-<digest>` because
        // this source carries no uid: a cluster with no cloud above it mints
        // none, and S02's key falls back to what it always was rather than
        // making every node on such a fleet re-download everything.
        assert!(images.join(CACHE_DIR).join(&source.sha256).exists());
        assert_eq!(
            cache.report(),
            vec![("ubuntu.raw".to_string(), State::Ready, None)]
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

    /// Two registrations of one name are two images, and one node's cache
    /// keeps them apart.
    ///
    /// Astra finding S02, 2026-09-23: the cache entry was the digest alone
    /// and the catalogue name is global — one namespace for every tenant on
    /// the fleet — while `delete_image` at the cloud removes the object and
    /// nothing a node holds. So a name deregistered by one tenant and
    /// registered by another was, on the node, the same entry. The uid is
    /// what an image cannot share: it is minted once and never reused.
    #[tokio::test]
    async fn two_images_of_one_name_do_not_share_a_cache_entry() {
        let (_temp, dir) = scratch("uid");
        let images = dir.join("images");
        std::fs::create_dir_all(&images).unwrap();
        let cache = test_cache(images.clone());

        let theirs = b"the image one tenant registered".to_vec();
        let mine = b"what somebody else put under the same name".to_vec();
        let origin = dir.join("origin.raw");

        std::fs::write(&origin, &theirs).unwrap();
        let first = Source {
            name: "ubuntu.raw".into(),
            url: served(&origin),
            sha256: digest_of(&theirs),
            uid: "4f3c0000-0000-0000-0000-00000000000a".into(),
        };
        cache.ensure(&first).await.expect("fetched");

        std::fs::write(&origin, &mine).unwrap();
        let second = Source {
            name: "ubuntu.raw".into(),
            url: served(&origin),
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
        // The name follows the newest bytes, as it always has.
        assert_eq!(std::fs::read(images.join("ubuntu.raw")).unwrap(), mine);

        // Same uid, same digest, same entry: asking twice is asking once.
        cache.ensure(&second).await.expect("already here");
        assert_eq!(
            std::fs::read_dir(images.join(CACHE_DIR))
                .unwrap()
                .filter_map(|e| e.ok())
                .count(),
            2
        );
    }

    /// A uid names a file in the cache directory, so a value that is not one
    /// is refused before anything is downloaded — the same rule and the same
    /// danger as `check_digest`.
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
        let cache = test_cache(images.clone());
        let claimed = digest_of(b"what the operator thought they were getting");
        let source = Source {
            name: "ubuntu.raw".into(),
            url: served(&origin),
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

    /// A URL nobody answers is a Failed with the reason, and again nothing
    /// half-written survives it.
    #[tokio::test]
    async fn a_url_that_does_not_answer_leaves_nothing_usable() {
        let (_temp, dir) = scratch("no-answer");
        let images = dir.join("images");
        std::fs::create_dir_all(&images).unwrap();
        let cache = test_cache(images.clone());
        let source = Source {
            name: "ubuntu.raw".into(),
            url: served(&dir.join("nothing-here.raw")),
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

        // And the pass that looks at PATH images does not overwrite it. A
        // volume record names its base image by catalogue name and carries no
        // url, so that pass reaches this name too — and "it has no url, so
        // nothing here fetches it" is the one sentence that is certainly
        // wrong about an image this node tried to fetch. See `Entry::fetched`.
        cache.verify_path("ubuntu.raw").await;
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
        let cache = test_cache(images.clone());

        let first = b"version one".to_vec();
        let origin = dir.join("origin.raw");
        std::fs::write(&origin, &first).unwrap();
        cache
            .ensure(&Source {
                name: "ubuntu.raw".into(),
                url: served(&origin),
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
                url: served(&origin),
                sha256: digest_of(&second),
                uid: String::new(),
            })
            .await
            .unwrap();

        assert_eq!(std::fs::read(images.join("ubuntu.raw")).unwrap(), second);
        assert!(images.join(CACHE_DIR).join(digest_of(&first)).exists());
        assert!(images.join(CACHE_DIR).join(digest_of(&second)).exists());
    }
    /// The node says what it HAS, not only what it was asked about.
    ///
    /// F16's other half. A path image is somebody else's file, and this node
    /// only ever heard of one through a record that named it — so an `Image`
    /// object nothing on the fleet used was described by nobody, the cloud had
    /// no evidence, and a catalogue entry pointing at nothing went on reading
    /// `Ready`. Nothing can tell a node about such an image: `SyncState`
    /// carries VMs and there is no image command. So the direction is turned
    /// around — the node reads its directory and says the list is complete,
    /// and the tier above may then read a missing name as a missing file.
    ///
    /// What must NOT happen is the inventory talking over a look: a checksum
    /// that did not match and a directory under a catalogue name are things
    /// only a look can say, and a bare `readdir` would flatten both into
    /// `Ready`.
    #[tokio::test]
    async fn the_inventory_says_what_is_on_the_disk_and_a_look_still_wins() {
        let (_temp, images) = scratch("inventory");
        let cache = test_cache(images.clone());

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

        // A LOOK at one of them, and it disagrees with the file being there:
        // the same name, re-registered under a url whose bytes did not match.
        // The look wins, because it is the only one of the two that can say
        // which of the four things is wrong.
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

        // A name a record asked about and that is NOT in the directory: the
        // look says why, and the inventory's completeness is what lets the
        // tier above believe it about an image nobody named at all.
        cache.verify_path("chaos-img-bad.raw").await;
        let said = cache.report();
        let bad = said
            .iter()
            .find(|(name, _, _)| name == "chaos-img-bad.raw")
            .expect("a line");
        assert_eq!(bad.1.reason(), Some(ImageReason::NotFound));

        // A second reading of an unchanged directory is free, and still
        // answers the same.
        assert!(cache.take_inventory().await);
        assert_eq!(cache.report().len(), 3);

        // And a directory that is not there at all: no claim of completeness,
        // and no `Ready` invented for anything. A directory that cannot be
        // read must never become "the file is not there" — that would make
        // F16 worse rather than better.
        let gone = Cache::new(images.join("nowhere"));
        assert!(!gone.take_inventory().await);
        assert!(gone.report().is_empty());
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
        let cache = test_cache(images.clone());

        // Nothing said about an image nobody has looked at. Silence is what
        // an empty `Image.status.nodes[]` means, and it must stay available.
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

        // Somebody puts the bytes there. The next look says so — no create,
        // no restart, no second command — and Astra finding S02, 2026-09-23
        // (rest a): this same first look is what binds the catalogue name to
        // a digest for the first time.
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

    /// A path image's digest is hashed once and trusted afterwards — even
    /// past a swap this process never re-reads for.
    ///
    /// Astra finding S02, 2026-09-23 (rest a). The cost this avoids is real:
    /// `verify_path` runs on every status report and every reconcile pass,
    /// and re-hashing a multi-gigabyte image on that schedule would be worse
    /// than the problem it closes. The trade that buys is stated here rather
    /// than left implicit — a file swapped on shared storage keeps the OLD
    /// digest until this process restarts.
    #[tokio::test]
    async fn a_path_images_digest_is_bound_once_and_trusted_after_that() {
        let (_temp, images) = scratch("digest-once");
        let cache = test_cache(images.clone());

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
        let restarted = test_cache(images.clone());
        restarted.verify_path("nixos.raw").await;
        let (_, _, after_restart) = restarted.report().pop().expect("one opinion");
        assert_eq!(after_restart, Some(digest_of(b"different bytes now")));
    }

    /// A dropped uid loses its cache file and its catalogue link; a
    /// DIFFERENT uid under the same recycled name keeps both.
    ///
    /// Astra finding S02, 2026-09-23 (rest b). `delete_image` at the cloud
    /// only ever removes the catalogue object, so this is the other half:
    /// told a uid, a node removes exactly the bytes it fetched for that uid.
    /// The name is deliberately reused here for a SECOND, later registration
    /// — the shape `Cache::drop_uid`'s own doc comment calls out as the one a
    /// name-keyed removal would get wrong.
    #[tokio::test]
    async fn drop_uid_removes_the_right_registrations_bytes_and_not_a_same_named_others() {
        let (_temp, dir) = scratch("drop-uid");
        let images = dir.join("images");
        std::fs::create_dir_all(&images).unwrap();
        let cache = test_cache(images.clone());
        let origin = dir.join("origin.raw");

        let old = b"the image that gets deleted".to_vec();
        std::fs::write(&origin, &old).unwrap();
        let old_uid = "4f3c0000-0000-0000-0000-00000000000a";
        let old_source = Source {
            name: "ubuntu.raw".into(),
            url: served(&origin),
            sha256: digest_of(&old),
            uid: old_uid.into(),
        };
        cache.ensure(&old_source).await.expect("fetched");
        let old_cache_file = images.join(CACHE_DIR).join(old_source.cache_key());
        assert!(old_cache_file.exists());

        // The name is re-registered — a different tenant, or the same one
        // registering again — before the drop for the OLD uid arrives. This
        // node already fetched the new bytes too, so its link now points at
        // them.
        let new = b"a completely different image, same name".to_vec();
        std::fs::write(&origin, &new).unwrap();
        let new_uid = "9b210000-0000-0000-0000-00000000000b";
        let new_source = Source {
            name: "ubuntu.raw".into(),
            url: served(&origin),
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

    /// An empty uid removes nothing. `check_uid` refuses one everywhere else
    /// a `Source` carries it; this is the same refusal for the road that
    /// does not build one.
    #[tokio::test]
    async fn dropping_an_empty_uid_is_a_no_op() {
        let (_temp, dir) = scratch("drop-uid-empty");
        let images = dir.join("images");
        std::fs::create_dir_all(&images).unwrap();
        let cache = test_cache(images.clone());
        let origin = dir.join("origin.raw");
        let payload = b"bytes".to_vec();
        std::fs::write(&origin, &payload).unwrap();
        let source = Source {
            name: "ubuntu.raw".into(),
            url: served(&origin),
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
        let cache = test_cache(images.clone());
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
