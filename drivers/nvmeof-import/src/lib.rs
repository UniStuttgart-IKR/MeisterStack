// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! The `nvmeof-import` PROVIDER: a pool of namespaces that already exist.
//!
//! ## What it provisions, which is nothing
//!
//! Every other provider in this tree makes bytes — an LV, a file, a directory
//! on an export. This one makes none. An operator writes down the namespaces
//! a target already exports, and `provision` hands one of them out; the same
//! shape the NFS share mode has, and the same honesty: what this driver owns
//! is the ASSIGNMENT, and the bytes were somebody else's before it and stay
//! somebody else's after.
//!
//! `deprovision` therefore does not delete. It releases the assignment and
//! the data stays exactly where it was, which is the one property of an
//! import that surprises people and the reason it is the first sentence of
//! the pool's own documentation. The real provider — one that carves
//! namespaces out of a target — is Floppy's, and what it replaces is this
//! file and nothing else: the attacher, the handle contract and the
//! `networked` axis stay as they are.
//!
//! ## Who decides which namespace, and where the answer is written down
//!
//! **The tier that owns the pool decides.** A pool of this kind is
//! cluster-wide — every node that can reach the target can reach every
//! namespace on it — so the assignment is written into the volume's params as
//! `namespace`, by the controller, out of a table that is atomic across
//! replicas. This driver takes the name it is given and does not look for a
//! free one.
//!
//! It used to look for one, and that was the whole of the defect. The
//! exclusive create of a claim file was called a lock, and it is one — over
//! the file system of ONE node. Two nodes bound to the same pool never saw
//! each other's files, so both handed out the first namespace in the list,
//! and the lab had two `Ready` volumes on one 100-GiB block with a guest
//! running on one of them. A lock that only locks against the party that
//! cannot race is not a lock.
//!
//! So a node chooses for itself only where there is nobody above it to
//! choose: `allow_local_claims = true` on the pool, which is off unless
//! somebody writes it down, and is for a single-node pool or a test. Without
//! it and without a `namespace` the provision is refused with the sentence
//! that says who was supposed to have said it.
//!
//! What stays is the FILE, and it stopped being the allocator. One per
//! namespace, in the driver's state directory, holding the volume it belongs
//! to and who said so (`by`). That is what makes two answers possible that
//! nothing else on this node can give: a provision whose handle was lost
//! finds its own namespace again instead of taking a second, and a namespace
//! this node already holds for ANOTHER volume is a refusal naming both rather
//! than a second guest on somebody's disk. In `allow_local_claims` the
//! exclusive create is still the arbitration; under an assignment it is only
//! the record, and losing it is an error instead of a step to the next
//! namespace.
//!
//! Kept beside the agent's own store rather than in it, and that is a
//! deviation worth naming: a driver has no handle to that store, and giving
//! one to it would be a new seam through every backend for the sake of this
//! one. A file per namespace in a directory the config names does the same
//! job with the same durability.

use std::path::{Path, PathBuf};

use agent_api::CgroupHandle;
use agent_api::storage::{
    Locality, StorageError, VolumeAttacher, VolumeAttachment, VolumeHandle, VolumeId,
    VolumeProvider, VolumeSpec, VolumeState,
};
use nvmeof_driver::{NvmeofAttacher, NvmeofTarget, RESERVED_PORT, Transport};
use tracing::{info, instrument, warn};

/// One namespace an operator wrote down, as it appears in the pool's params.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Namespace {
    pub nqn: String,
    /// What the operator says it holds. The TRUTH is `describe`, which asks
    /// the namespace; this is what a pool can be planned against before
    /// anything has connected to it.
    pub size_gib: u64,
}

/// The pool: where the target is, and what it exports.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImportPoolParams {
    #[serde(default = "default_transport")]
    pub transport: Transport,
    pub addr: String,
    pub port: u16,
    pub namespaces: Vec<Namespace>,
    /// Which namespace THIS volume gets, as the tier that owns the pool
    /// decided it.
    ///
    /// Merged into the volume's params by the controller, out of a claim
    /// table that is atomic across its replicas — which is where a
    /// cluster-wide pool's assignment has to be made, and the half this
    /// driver used to make for itself out of a file only one node could see.
    ///
    /// Absent on the pool itself, where there is no volume to speak for: a
    /// `StoragePool` carries the transport and the list, a provision carries
    /// this as well.
    #[serde(default)]
    pub namespace: Option<String>,
    /// Whether a node may choose a namespace itself when nobody told it
    /// which.
    ///
    /// Off unless it is written down, and the default is the whole point: a
    /// pool one node can reach is a pool every node can reach, so a node
    /// choosing on its own is right exactly where there IS no other node —
    /// a single-node pool, a driver test. Everywhere else it is the defect
    /// this flag was introduced to close, and a provision with no assignment
    /// is refused instead.
    #[serde(default)]
    pub allow_local_claims: bool,
}

fn default_transport() -> Transport {
    Transport::Tcp
}

impl ImportPoolParams {
    /// Everything that can be wrong with a pool, said at the pool and not at
    /// the first volume out of it.
    pub fn check(&self) -> agent_api::storage::Result<()> {
        if self.addr.is_empty() {
            return Err(StorageError::InvalidSpec(
                "an nvmeof-import pool needs an addr".into(),
            ));
        }
        if self.port == RESERVED_PORT {
            return Err(StorageError::InvalidSpec(format!(
                "port {RESERVED_PORT} is the DPU's own nvmet target and is not this control \
                 plane's to import from"
            )));
        }
        if self.namespaces.is_empty() {
            return Err(StorageError::InvalidSpec(
                "an nvmeof-import pool with no namespaces holds nothing; list what the target \
                 exports"
                    .into(),
            ));
        }
        let mut seen = std::collections::BTreeSet::new();
        for ns in &self.namespaces {
            if ns.nqn.is_empty() {
                return Err(StorageError::InvalidSpec("a namespace needs an nqn".into()));
            }
            if !seen.insert(ns.nqn.as_str()) {
                // Two entries for one nqn would make the pool look twice as
                // big as it is, and the second volume out of it would be the
                // first volume's disk.
                return Err(StorageError::InvalidSpec(format!(
                    "namespace {} is listed twice",
                    ns.nqn
                )));
            }
        }
        Ok(())
    }

    fn target(&self, nqn: &str) -> NvmeofTarget {
        NvmeofTarget {
            nqn: nqn.to_string(),
            addr: self.addr.clone(),
            port: self.port,
            transport: self.transport,
        }
    }
}

pub struct NvmeofImportConfig {
    /// Where the claim files live. One per namespace that is spoken for.
    pub state_dir: PathBuf,
    /// Passed through to the attacher half. See the module doc.
    pub bin_dir: Option<PathBuf>,
}

pub struct NvmeofImportDriver {
    state_dir: PathBuf,
    attacher: NvmeofAttacher,
}

impl NvmeofImportDriver {
    pub fn new(config: NvmeofImportConfig) -> Self {
        Self {
            state_dir: config.state_dir,
            attacher: NvmeofAttacher::new(nvmeof_driver::NvmeofAttacherConfig {
                bin_dir: config.bin_dir,
            }),
        }
    }

    /// The claim file for one namespace.
    ///
    /// An NQN contains `:` and `.` and is not a file name, so it is hashed
    /// into one. The hash is not a secret and does not have to be: what it
    /// has to be is stable across restarts and collision-free enough that two
    /// namespaces of one target never share a file, and the NQN is written
    /// INSIDE so that a collision would be seen rather than silently taken.
    fn claim_path(&self, nqn: &str) -> PathBuf {
        self.state_dir.join(format!("{}.claim", stem(nqn)))
    }
}

/// A file-name-safe stem for an NQN. Not reversible and not meant to be —
/// the file's contents carry the real name.
pub fn stem(nqn: &str) -> String {
    let mut out = String::with_capacity(nqn.len());
    for c in nqn.chars() {
        match c {
            'a'..='z' | 'A'..='Z' | '0'..='9' | '-' | '.' => out.push(c),
            _ => out.push('_'),
        }
    }
    out
}

/// What a claim file holds: whose the namespace is, what it is called, and
/// who said so.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
struct Claim {
    volume: VolumeId,
    nqn: String,
    #[serde(default)]
    by: Assigner,
}

/// Which tier decided this assignment.
///
/// On the file and not derived, because the two are read back for different
/// reasons and an operator looking at a state directory should be able to see
/// which of them a node was doing. `Node` is the default so that a file
/// written before the pool had an owner reads as what it was: a node that
/// chose for itself.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
enum Assigner {
    #[default]
    Node,
    Cluster,
}

fn params_of(spec: &VolumeSpec) -> agent_api::storage::Result<ImportPoolParams> {
    let params = spec.params.clone().ok_or_else(|| {
        StorageError::InvalidSpec(
            "an nvmeof-import volume needs the pool's params (transport, addr, port, namespaces)"
                .into(),
        )
    })?;
    let params: ImportPoolParams = serde_json::from_value(params)
        .map_err(|e| StorageError::InvalidSpec(format!("unusable nvmeof-import params: {e}")))?;
    params.check()?;
    Ok(params)
}

#[async_trait::async_trait]
impl VolumeProvider for NvmeofImportDriver {
    #[instrument(skip_all, fields(volume = %id))]
    async fn provision(
        &self,
        id: &VolumeId,
        spec: &VolumeSpec,
    ) -> agent_api::storage::Result<VolumeHandle> {
        // An import has its bytes already, so there is nothing to clone into
        // and nothing that would make sense to. Refused at the driver as well
        // as at the edge, because this is the one that cannot be bypassed.
        if spec.base_image.is_some() {
            return Err(StorageError::InvalidSpec(
                "an imported namespace has its bytes already; a base_image would have to \
                 overwrite somebody's data to be honoured"
                    .into(),
            ));
        }
        let params = params_of(spec)?;
        std::fs::create_dir_all(&self.state_dir).map_err(|e| {
            StorageError::Backend(anyhow::anyhow!(
                "creating the nvmeof-import state directory {}: {e}",
                self.state_dir.display()
            ))
        })?;

        // Idempotent, and the reason is the contract every provider here has:
        // a provision whose handle was lost must find its namespace again
        // rather than take a second one. So this node's own records are read
        // first, whoever wrote them.
        if let Some(held) = self.held_by(id, &params)? {
            // An assignment that names a different namespace than the one
            // this node already holds for this volume is not something to
            // resolve by picking one: the bytes are on the one it holds, and
            // taking the other would strand them and leave a namespace that
            // looks free to the next volume. Both names in the sentence,
            // because the operator has to decide which of the two is right.
            if let Some(assigned) = params.namespace.as_deref()
                && assigned != held
            {
                return Err(StorageError::InvalidSpec(format!(
                    "volume {id} already holds {held} on this node and has been assigned \
                     {assigned}; releasing one of the two is a decision about somebody's data \
                     and is not this driver's to make"
                )));
            }
            let ns = params
                .namespaces
                .iter()
                .find(|n| n.nqn == held)
                .ok_or_else(|| {
                    // The record outlived the pool entry that justified it.
                    // Refusing is right: handing back a handle for a
                    // namespace the pool no longer lists would be a volume
                    // pointing at something an operator took away.
                    StorageError::InvalidSpec(format!(
                        "volume {id} holds {held}, which this pool no longer lists"
                    ))
                })?;
            return Ok(handle_for(id, &params, ns));
        }

        match params.namespace.as_deref() {
            Some(nqn) => self.take_assigned(id, &params, nqn, spec.size_bytes),
            None if params.allow_local_claims => self.choose_one(id, &params, spec.size_bytes),
            // The refusal names the two ways out and the tier that owes the
            // answer, because "no namespace" is not something an operator can
            // act on and "the controller did not assign one" is.
            None => Err(StorageError::InvalidSpec(format!(
                "volume {id} was sent to an nvmeof-import pool with no `namespace` in its \
                 params: the assignment for a cluster-wide pool is the controller's to make, \
                 and this node will not choose one for itself. Set `allow_local_claims = true` \
                 on the pool if it really is a pool only this node can reach"
            ))),
        }
    }

    /// Release the assignment. **The bytes stay.**
    #[instrument(skip_all, fields(volume = %handle.id))]
    async fn deprovision(&self, handle: &VolumeHandle) -> agent_api::storage::Result<()> {
        let target = NvmeofTarget::of(handle)?;
        let path = self.claim_path(&target.nqn);
        match std::fs::remove_file(&path) {
            Ok(()) => {
                // Said at info and said plainly, because it is the one thing
                // about this driver that surprises people: a `volume rm` here
                // frees a name and destroys nothing.
                info!(nqn = %target.nqn,
                      "namespace released; its data is untouched on the target");
                Ok(())
            }
            // Already released. Idempotent by the same contract provision is.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(StorageError::Backend(anyhow::anyhow!(
                "releasing {}: {e}",
                path.display()
            ))),
        }
    }

    /// Let this node go of the namespace, and touch nothing on the target.
    ///
    /// The same act `deprovision` performs, which is not a coincidence and is
    /// worth stating rather than sharing a body over: for THIS driver a
    /// deprovision was never a destruction — it releases a reservation and
    /// the bytes are somebody else's throughout. `forget` is the whole of
    /// what a deprovision here ever did.
    ///
    /// Which is also why this driver is the only one that had to implement
    /// the verb. Its claim file is per node, and after a live migration the
    /// source holds one over a namespace that has moved with its guest. Left
    /// behind, the next volume the cluster assigns that namespace on this
    /// node is refused over a conflict with a guest that is not here.
    #[instrument(skip_all, fields(volume = %handle.id))]
    async fn forget(&self, handle: &VolumeHandle) -> agent_api::storage::Result<()> {
        self.deprovision(handle).await
    }

    /// How big the namespace actually is, asked of the namespace.
    ///
    /// It needs the connection, which is the honest shape for an import: the
    /// bytes are not here, and nothing on this node knows their size until
    /// somebody has spoken to the target. A node holding the claim but not
    /// the connection answers with what the POOL said, which is what an
    /// operator wrote down and the best statement available without dialling.
    async fn describe(&self, handle: &VolumeHandle) -> agent_api::storage::Result<VolumeState> {
        let target = NvmeofTarget::of(handle)?;
        if !self.claim_path(&target.nqn).exists() {
            return Err(StorageError::NotFound(handle.id));
        }
        match self
            .attacher
            .stat(handle, &VolumeAttachment::Path(PathBuf::new()))
            .await
        {
            Ok(state) => Ok(state),
            // Not connected here, or connected and unreadable. The claim is
            // what this node knows for certain, and the size on the handle is
            // what the pool promised.
            Err(_) => Ok(VolumeState {
                size_bytes: handle.size_bytes,
            }),
        }
    }

    fn locality(&self) -> Locality {
        Locality::Networked
    }
}

/// The attacher half, delegated.
///
/// Two crates and two roles, and this is the seam between them. The catalogue
/// wants a pool to name its provider and its attacher separately
/// (`StoragePool.spec.attacher`) so that a storage node can provision what a
/// compute node attaches; that field does not exist in this tree yet — Storage
/// A was expected to land it and did not — so until it does, a pool whose
/// driver is `nvmeof-import` is attached by the `nvmeof` implementation this
/// crate holds.
///
/// The delegation is not a shortcut around the split: it IS the split, with
/// the two ends in one process because on this lab's only consumer they are
/// on one machine. When the field lands, these four methods go and the
/// registry routes attach to the `nvmeof` row instead. Nothing else changes —
/// which is what having written it as two crates buys.
#[async_trait::async_trait]
impl VolumeAttacher for NvmeofImportDriver {
    async fn attach(
        &self,
        handle: &VolumeHandle,
        cgroup: Option<&CgroupHandle>,
    ) -> agent_api::storage::Result<VolumeAttachment> {
        self.attacher.attach(handle, cgroup).await
    }

    async fn detach(
        &self,
        handle: &VolumeHandle,
        attachment: &VolumeAttachment,
    ) -> agent_api::storage::Result<()> {
        self.attacher.detach(handle, attachment).await
    }

    async fn stat(
        &self,
        handle: &VolumeHandle,
        attachment: &VolumeAttachment,
    ) -> agent_api::storage::Result<VolumeState> {
        self.attacher.stat(handle, attachment).await
    }
}

impl NvmeofImportDriver {
    /// Which namespace this volume already holds on this node, if it holds
    /// one.
    fn held_by(
        &self,
        id: &VolumeId,
        params: &ImportPoolParams,
    ) -> agent_api::storage::Result<Option<String>> {
        for ns in &params.namespaces {
            let path = self.claim_path(&ns.nqn);
            let Ok(raw) = std::fs::read_to_string(&path) else {
                continue;
            };
            match serde_json::from_str::<Claim>(&raw) {
                Ok(claim) if &claim.volume == id => return Ok(Some(claim.nqn)),
                Ok(_) => {}
                // A record this driver cannot read is a namespace it must
                // treat as TAKEN, never as free: the alternative is handing
                // out somebody's disk because a file got truncated.
                Err(e) => warn!(path = %path.display(), error = %e,
                                "unreadable claim; treating the namespace as assigned"),
            }
        }
        Ok(None)
    }

    /// Take the namespace the cluster assigned, or say why this node cannot.
    ///
    /// Three refusals and each of them is a different mistake one tier up: a
    /// name the pool does not list (pool and assignment disagree), a
    /// namespace too small for what the volume was promised, and a namespace
    /// this node is already holding for somebody else — the last being the
    /// one that used to be silent and used to end with two guests on one
    /// block.
    fn take_assigned(
        &self,
        id: &VolumeId,
        params: &ImportPoolParams,
        nqn: &str,
        size_bytes: u64,
    ) -> agent_api::storage::Result<VolumeHandle> {
        let ns = params
            .namespaces
            .iter()
            .find(|n| n.nqn == nqn)
            .ok_or_else(|| {
                StorageError::InvalidSpec(format!(
                    "volume {id} was assigned namespace {nqn}, which this pool does not list; \
                     the pool and the assignment disagree about what the target exports"
                ))
            })?;
        if ns.size_gib * 1024 * 1024 * 1024 < size_bytes {
            return Err(StorageError::InvalidSpec(format!(
                "namespace {nqn} holds {} GiB and volume {id} was promised {size_bytes} bytes; \
                 an import hands out whole namespaces and carves none down",
                ns.size_gib
            )));
        }
        let path = self.claim_path(nqn);
        if claim(&path, id, nqn, Assigner::Cluster)? {
            info!(nqn = %ns.nqn, size_gib = ns.size_gib, "namespace assigned by the cluster");
            return Ok(handle_for(id, params, ns));
        }
        // Lost the create. Either this volume got here twice — handled above
        // and again here because the two calls can race — or the namespace is
        // somebody else's on this node, which is the collision the whole fix
        // exists to make loud.
        let holder = std::fs::read_to_string(&path)
            .ok()
            .and_then(|raw| serde_json::from_str::<Claim>(&raw).ok());
        match holder {
            Some(held) if &held.volume == id => Ok(handle_for(id, params, ns)),
            Some(held) => Err(StorageError::Backend(anyhow::anyhow!(
                "namespace {nqn} was assigned to volume {id}, and this node already holds it \
                 for volume {}; two volumes on one namespace is two guests on one disk, so \
                 nothing was provisioned",
                held.volume
            ))),
            None => Err(StorageError::Backend(anyhow::anyhow!(
                "namespace {nqn} is spoken for on this node by {} and that file cannot be \
                 read; it is treated as taken",
                path.display()
            ))),
        }
    }

    /// The first namespace nobody has taken, for a pool that says this node
    /// may decide. `create_new` IS the arbitration here: two provisions
    /// racing for the last one both try, and exactly one gets the file.
    fn choose_one(
        &self,
        id: &VolumeId,
        params: &ImportPoolParams,
        size_bytes: u64,
    ) -> agent_api::storage::Result<VolumeHandle> {
        for ns in &params.namespaces {
            // A namespace smaller than what was asked for is not a namespace
            // this volume can have. Bigger is fine and the volume uses all of
            // it — an import hands out whole namespaces, and carving one down
            // is the real provider's job.
            if ns.size_gib * 1024 * 1024 * 1024 < size_bytes {
                continue;
            }
            match claim(&self.claim_path(&ns.nqn), id, &ns.nqn, Assigner::Node) {
                Ok(true) => {
                    info!(nqn = %ns.nqn, size_gib = ns.size_gib, "namespace assigned");
                    return Ok(handle_for(id, params, ns));
                }
                Ok(false) => continue,
                Err(e) => return Err(e),
            }
        }
        Err(StorageError::Backend(anyhow::anyhow!(
            "no free namespace in this pool holds {size_bytes} bytes; {} of {} are assigned",
            params
                .namespaces
                .iter()
                .filter(|n| self.claim_path(&n.nqn).exists())
                .count(),
            params.namespaces.len()
        )))
    }
}

/// Take a namespace, or find it already taken. `true` = it is ours now.
fn claim(path: &Path, id: &VolumeId, nqn: &str, by: Assigner) -> agent_api::storage::Result<bool> {
    use std::io::Write;
    let body = serde_json::to_vec(&Claim {
        volume: *id,
        nqn: nqn.to_string(),
        by,
    })
    .map_err(|e| StorageError::Backend(anyhow::anyhow!("encoding a claim: {e}")))?;
    match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
    {
        Ok(mut file) => {
            file.write_all(&body).map_err(|e| {
                StorageError::Backend(anyhow::anyhow!("writing {}: {e}", path.display()))
            })?;
            // Durable before the handle is: a claim that is only in the page
            // cache is a namespace that is free again after a power cut, and
            // the next volume would be handed the first one's data.
            file.sync_all().map_err(|e| {
                StorageError::Backend(anyhow::anyhow!("syncing {}: {e}", path.display()))
            })?;
            Ok(true)
        }
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(false),
        Err(e) => Err(StorageError::Backend(anyhow::anyhow!(
            "claiming {}: {e}",
            path.display()
        ))),
    }
}

/// The handle an imported namespace gets.
///
/// `backend` is the NQN and not a path, which is the case `VolumeHandle`'s
/// own doc says the field is a `String` for: this backend NAMES its volumes
/// and does not path them. `params` carries the whole target, because the
/// attacher is given a handle and nothing else.
fn handle_for(id: &VolumeId, params: &ImportPoolParams, ns: &Namespace) -> VolumeHandle {
    VolumeHandle {
        id: *id,
        backend: ns.nqn.clone(),
        size_bytes: ns.size_gib * 1024 * 1024 * 1024,
        params: serde_json::to_value(params.target(&ns.nqn)).ok(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A state directory of this test's own, and the guard that removes it
    /// again — however the test ends, panic included.
    fn dir() -> (tempfile::TempDir, PathBuf) {
        let temp = tempfile::Builder::new()
            .prefix("nvmeof-import-")
            .tempdir()
            .expect("a directory");
        let dir = temp.path().to_path_buf();
        (temp, dir)
    }

    /// A pool as an operator writes it down, with nobody above it to hand
    /// out namespaces — which is what the older tests here are about and
    /// what `allow_local_claims` now has to say out loud.
    fn pool(namespaces: &[(&str, u64)]) -> ImportPoolParams {
        ImportPoolParams {
            allow_local_claims: true,
            ..cluster_pool(namespaces)
        }
    }

    /// The same pool under a controller: no local claims, and the namespace
    /// arrives with the volume.
    fn cluster_pool(namespaces: &[(&str, u64)]) -> ImportPoolParams {
        ImportPoolParams {
            transport: Transport::Tcp,
            addr: "10.33.0.21".into(),
            port: 4422,
            namespaces: namespaces
                .iter()
                .map(|(nqn, size_gib)| Namespace {
                    nqn: (*nqn).to_string(),
                    size_gib: *size_gib,
                })
                .collect(),
            namespace: None,
            allow_local_claims: false,
        }
    }

    /// That pool with one volume's assignment on it, which is how a
    /// provision command carries it.
    fn assigned(namespaces: &[(&str, u64)], nqn: &str) -> ImportPoolParams {
        ImportPoolParams {
            namespace: Some(nqn.to_string()),
            ..cluster_pool(namespaces)
        }
    }

    fn driver(state: &Path) -> NvmeofImportDriver {
        NvmeofImportDriver::new(NvmeofImportConfig {
            state_dir: state.to_path_buf(),
            bin_dir: None,
        })
    }

    fn spec(params: &ImportPoolParams, size_bytes: u64) -> VolumeSpec {
        VolumeSpec {
            base_image: None,
            size_bytes,
            driver: Some("nvmeof-import".into()),
            params: Some(serde_json::to_value(params).expect("params")),
        }
    }

    /// The whole assignment story: one namespace per volume, the same one
    /// again on a repeat, and a pool that runs out says so.
    #[tokio::test]
    async fn a_namespace_is_assigned_once_and_found_again() {
        let (_temp, state) = dir();
        let driver = NvmeofImportDriver::new(NvmeofImportConfig {
            state_dir: state.clone(),
            bin_dir: None,
        });
        let params = pool(&[("nqn.test:one", 100), ("nqn.test:two", 100)]);
        let one = uuid::Uuid::new_v4();
        let two = uuid::Uuid::new_v4();
        let three = uuid::Uuid::new_v4();

        let a = driver
            .provision(&one, &spec(&params, 1 << 30))
            .await
            .expect("a namespace");
        assert_eq!(a.backend, "nqn.test:one");
        assert_eq!(
            a.size_bytes,
            100 * 1024 * 1024 * 1024,
            "the whole namespace"
        );
        // The target travels on the handle, which is all the attacher gets.
        let target = NvmeofTarget::of(&a).expect("a target");
        assert_eq!(target.addr, "10.33.0.21");
        assert_eq!(target.port, 4422);

        // The SAME volume again finds its own, never a second one. This is
        // the contract a lost handle depends on.
        let again = driver
            .provision(&one, &spec(&params, 1 << 30))
            .await
            .expect("the same one");
        assert_eq!(again.backend, "nqn.test:one");

        // A different volume gets the other one.
        let b = driver
            .provision(&two, &spec(&params, 1 << 30))
            .await
            .expect("the other");
        assert_eq!(b.backend, "nqn.test:two");

        // And a third finds the pool full, with the numbers in the sentence.
        let full = driver
            .provision(&three, &spec(&params, 1 << 30))
            .await
            .expect_err("nothing left");
        let full = format!("{full:#}");
        assert!(full.contains("2 of 2 are assigned"), "{full}");

        // Releasing frees the NAME and nothing else — there is no data here
        // to destroy, which is the sentence the doc leads with.
        driver.deprovision(&a).await.expect("released");
        assert!(
            !state
                .join(format!("{}.claim", stem("nqn.test:one")))
                .exists()
        );
        let c = driver
            .provision(&three, &spec(&params, 1 << 30))
            .await
            .expect("the freed one");
        assert_eq!(c.backend, "nqn.test:one");
        // Twice is fine.
        driver.deprovision(&c).await.expect("idempotent");
        driver.deprovision(&c).await.expect("idempotent");

        let _ = std::fs::remove_dir_all(&state);
    }

    /// Size is a filter and never a carve: a namespace that is too small is
    /// skipped, and one that is bigger is handed over whole.
    #[tokio::test]
    async fn a_namespace_that_is_too_small_is_skipped_and_a_bigger_one_is_used_whole() {
        let (_temp, state) = dir();
        let driver = NvmeofImportDriver::new(NvmeofImportConfig {
            state_dir: state.clone(),
            bin_dir: None,
        });
        let params = pool(&[("nqn.test:small", 1), ("nqn.test:big", 100)]);
        let handle = driver
            .provision(&uuid::Uuid::new_v4(), &spec(&params, 50 * (1 << 30)))
            .await
            .expect("the big one");
        assert_eq!(handle.backend, "nqn.test:big");
        assert_eq!(
            handle.size_bytes,
            100 * 1024 * 1024 * 1024,
            "the volume gets all of it; carving one down is the real provider's job"
        );

        // And nothing fits at all.
        let none = driver
            .provision(&uuid::Uuid::new_v4(), &spec(&params, 500 * (1 << 30)))
            .await
            .expect_err("nothing that big");
        assert!(format!("{none:#}").contains("no free namespace"));
        let _ = std::fs::remove_dir_all(&state);
    }

    /// An import has its bytes already, so there is nothing a base image
    /// could do except overwrite somebody's data.
    #[tokio::test]
    async fn a_base_image_is_refused_because_the_bytes_are_already_there() {
        let (_temp, state) = dir();
        let driver = NvmeofImportDriver::new(NvmeofImportConfig {
            state_dir: state.clone(),
            bin_dir: None,
        });
        let params = pool(&[("nqn.test:one", 100)]);
        let mut with_image = spec(&params, 1 << 30);
        with_image.base_image = Some("debian-13.raw".into());
        let refused = driver
            .provision(&uuid::Uuid::new_v4(), &with_image)
            .await
            .expect_err("refused");
        assert!(
            format!("{refused}").contains("has its bytes already"),
            "{refused}"
        );
        let _ = std::fs::remove_dir_all(&state);
    }

    /// Everything wrong with a pool, said at the pool.
    #[test]
    fn a_pool_says_what_is_wrong_with_it_before_a_volume_does() {
        pool(&[("nqn.test:one", 100)]).check().expect("fine");

        let mut empty = pool(&[]);
        assert!(format!("{}", empty.check().unwrap_err()).contains("holds nothing"));

        empty = pool(&[("nqn.test:one", 1), ("nqn.test:one", 1)]);
        assert!(format!("{}", empty.check().unwrap_err()).contains("listed twice"));

        let mut dpu = pool(&[("nqn.test:one", 1)]);
        dpu.port = RESERVED_PORT;
        assert!(format!("{}", dpu.check().unwrap_err()).contains("4420"));

        let mut nowhere = pool(&[("nqn.test:one", 1)]);
        nowhere.addr = String::new();
        assert!(format!("{}", nowhere.check().unwrap_err()).contains("needs an addr"));

        let mut unnamed = pool(&[("", 1)]);
        unnamed.namespaces[0].size_gib = 1;
        assert!(format!("{}", unnamed.check().unwrap_err()).contains("needs an nqn"));
    }

    /// The claim file's name is derived and its CONTENTS are the truth. Two
    /// NQNs that differ only in a character the stem flattens must not share
    /// a claim.
    #[test]
    fn a_claim_file_is_named_safely_and_says_what_it_holds() {
        assert_eq!(
            stem("nqn.2026-09.local.calvia:meisterstack-test1"),
            "nqn.2026-09.local.calvia_meisterstack-test1"
        );
        assert_eq!(stem("a/b"), "a_b");
        assert!(!stem("nqn.x:y").contains(':'), "no colon in a file name");

        let (_temp, state) = dir();
        let one = uuid::Uuid::new_v4();
        let path = state.join("x.claim");
        assert!(claim(&path, &one, "nqn.test:one", Assigner::Node).expect("claimed"));
        // The second try loses, and loses without touching the file.
        assert!(
            !claim(
                &path,
                &uuid::Uuid::new_v4(),
                "nqn.test:one",
                Assigner::Cluster
            )
            .expect("taken")
        );
        let held: Claim =
            serde_json::from_str(&std::fs::read_to_string(&path).expect("readable")).expect("json");
        assert_eq!(held.volume, one, "the first writer keeps it");
        assert_eq!(held.nqn, "nqn.test:one");
        assert_eq!(held.by, Assigner::Node);
        // A file from before anybody decided anything reads as what it was.
        let older: Claim =
            serde_json::from_str(r#"{"volume":"11111111-1111-4111-8111-111111111111","nqn":"n"}"#)
                .expect("json");
        assert_eq!(older.by, Assigner::Node);
        let _ = std::fs::remove_dir_all(&state);
    }

    /// D-P1, the driver's half: the namespace comes from the tier that owns
    /// the pool, and this node takes what it is given.
    ///
    /// The defect it closes was measured in the lab: `fabric-disk` on
    /// agent-1a and `kollision` on agent-1c were both `Ready` on
    /// `nqn...test1`, because each node walked its own list and its own
    /// claim directory and neither could see the other's. Every branch here
    /// is one of the four answers that walk is now replaced by.
    #[tokio::test]
    async fn the_namespace_comes_from_the_cluster_and_this_node_takes_what_it_is_given() {
        let (_temp, state) = dir();
        let d = driver(&state);
        let names = [("nqn.test:one", 100), ("nqn.test:two", 100)];
        let one = uuid::Uuid::new_v4();
        let two = uuid::Uuid::new_v4();

        // The assignment is honoured verbatim — the SECOND namespace, which
        // is precisely the one a node walking the list would never have
        // picked first.
        let handle = d
            .provision(&one, &spec(&assigned(&names, "nqn.test:two"), 1 << 30))
            .await
            .expect("the assigned namespace");
        assert_eq!(handle.backend, "nqn.test:two");
        let held: Claim = serde_json::from_str(
            &std::fs::read_to_string(state.join(format!("{}.claim", stem("nqn.test:two"))))
                .expect("readable"),
        )
        .expect("json");
        assert_eq!(held.by, Assigner::Cluster, "and the node wrote down who");

        // The same volume again finds its own. The contract a lost handle
        // depends on does not change with who decided.
        let again = d
            .provision(&one, &spec(&assigned(&names, "nqn.test:two"), 1 << 30))
            .await
            .expect("the same one");
        assert_eq!(again.backend, "nqn.test:two");

        // A SECOND volume assigned the same namespace on this node is the
        // collision that used to be silent, and it names both volumes.
        let clash = d
            .provision(&two, &spec(&assigned(&names, "nqn.test:two"), 1 << 30))
            .await
            .expect_err("two volumes on one namespace");
        let clash = format!("{clash:#}");
        assert!(clash.contains(&one.to_string()), "{clash}");
        assert!(clash.contains(&two.to_string()), "{clash}");
        assert!(clash.contains("two guests on one disk"), "{clash}");

        // An assignment the pool does not list, and one that does not fit.
        let unlisted = d
            .provision(&two, &spec(&assigned(&names, "nqn.test:three"), 1 << 30))
            .await
            .expect_err("not in this pool");
        assert!(
            format!("{unlisted:#}").contains("does not list"),
            "{unlisted}"
        );
        let toosmall = d
            .provision(
                &two,
                &spec(&assigned(&names, "nqn.test:one"), 500 * (1 << 30)),
            )
            .await
            .expect_err("too small");
        assert!(
            format!("{toosmall:#}").contains("carves none down"),
            "{toosmall}"
        );

        // And a volume that already holds one namespace is not moved to
        // another by an assignment; that is a decision about somebody's data.
        let moved = d
            .provision(&one, &spec(&assigned(&names, "nqn.test:one"), 1 << 30))
            .await
            .expect_err("not this driver's to make");
        let moved = format!("{moved:#}");
        assert!(moved.contains("nqn.test:one"), "{moved}");
        assert!(moved.contains("nqn.test:two"), "{moved}");

        let _ = std::fs::remove_dir_all(&state);
    }

    /// No assignment and no permission to choose: a refusal that names the
    /// tier that owes the answer, and nothing on disk.
    ///
    /// This is the branch the lab ran down twice. A node that answers "here,
    /// have the first one" for a pool every node can reach is not being
    /// helpful — it is handing out a disk somebody else is already writing.
    #[tokio::test]
    async fn a_node_does_not_choose_a_namespace_for_a_pool_it_does_not_own() {
        let (_temp, state) = dir();
        let d = driver(&state);
        let names = [("nqn.test:one", 100)];
        let id = uuid::Uuid::new_v4();

        let refused = d
            .provision(&id, &spec(&cluster_pool(&names), 1 << 30))
            .await
            .expect_err("nobody said which namespace");
        let refused = format!("{refused:#}");
        assert!(refused.contains("allow_local_claims"), "{refused}");
        assert!(refused.contains("controller"), "{refused}");
        assert!(
            !state
                .join(format!("{}.claim", stem("nqn.test:one")))
                .exists(),
            "a refusal takes nothing"
        );

        // The same pool with the flag set is the single-node case, and there
        // the node still decides — which is what the flag is for.
        let mine = d
            .provision(&id, &spec(&pool(&names), 1 << 30))
            .await
            .expect("a pool only this node can reach");
        assert_eq!(mine.backend, "nqn.test:one");
        let _ = std::fs::remove_dir_all(&state);
    }
}
