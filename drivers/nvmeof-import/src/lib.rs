// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Assign existing NVMe-oF namespaces without creating or deleting their data.
//!
//! The controller supplies `namespace` in the volume params. Local allocation
//! is allowed only with `allow_local_claims`; its exclusive claim files arbitrate
//! within one state directory and do not coordinate nodes. Claims record volume
//! ownership for retries and cleanup. Deprovision releases the claim and leaves
//! target data intact; separate attacher operations manage the connection.

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
    /// Configured namespace capacity used before attachment. The provider
    /// description currently falls back to this value when it cannot query a device.
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
    /// Namespace selected by the controller for this volume. Absent on a pool template.
    #[serde(default)]
    pub namespace: Option<String>,
    /// Allow allocation from local claim files when no namespace was assigned.
    /// Use only where one allocator owns the state directory; this is not a cluster lock.
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
                // Duplicate NQNs would overstate capacity and alias volume ownership.
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

    /// Claim filename derived by replacing unsupported NQN characters with `_`.
    /// This normalization is not collision-free; distinct NQNs can share a path.
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

/// Record whether the controller or local allocator chose the namespace.
/// Legacy claims default to local allocation.
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
        // Imported namespaces already contain data; reject base-image initialization.
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

        // Recover an existing claim before allocating so retries reuse the same namespace.
        if let Some(held) = self.held_by(id, &params)? {
            // Reject assignment changes that disagree with this volume's existing claim,
            // preserving ownership of its original data.
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
                    // Reject a claimed namespace that the current pool no longer lists.
                    StorageError::InvalidSpec(format!(
                        "volume {id} holds {held}, which this pool no longer lists"
                    ))
                })?;
            return Ok(handle_for(id, &params, ns));
        }

        match params.namespace.as_deref() {
            Some(nqn) => self.take_assigned(id, &params, nqn, spec.size_bytes),
            None if params.allow_local_claims => self.choose_one(id, &params, spec.size_bytes),
            // Require controller assignment unless local claims are explicitly enabled.
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
                // Report that releasing the claim preserves target data.
                info!(nqn = %target.nqn,
                      "namespace released; its data is untouched on the target");
                Ok(())
            }
            // An absent claim is already released.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(StorageError::Backend(anyhow::anyhow!(
                "releasing {}: {e}",
                path.display()
            ))),
        }
    }

    /// Release the local claim without changing target data, as deprovision does.
    #[instrument(skip_all, fields(volume = %handle.id))]
    async fn forget(&self, handle: &VolumeHandle) -> agent_api::storage::Result<()> {
        self.deprovision(handle).await
    }

    /// Require a local claim, then attempt stat with an empty device path.
    /// On query failure, return the configured handle size without connecting.
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

    /// Find this volume's recorded namespace, including when its handle was lost.
    /// Refuse a claim whose namespace is no longer listed by the pool.
    #[instrument(skip_all, fields(volume = %id))]
    async fn probe(
        &self,
        id: &VolumeId,
        spec: &VolumeSpec,
    ) -> agent_api::storage::Result<Option<VolumeHandle>> {
        let params = params_of(spec)?;
        let Some(held) = self.held_by(id, &params)? else {
            return Ok(None);
        };
        // A claim absent from the current pool is an error, not evidence that
        // its namespace was released.
        let ns = params
            .namespaces
            .iter()
            .find(|n| n.nqn == held)
            .ok_or_else(|| {
                StorageError::InvalidSpec(format!(
                    "volume {id} holds {held}, which this pool no longer lists"
                ))
            })?;
        Ok(Some(handle_for(id, &params, ns)))
    }

    fn locality(&self) -> Locality {
        Locality::Networked
    }
}

/// Delegate connection operations to the NVMe-oF attacher held by this driver.
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
                // Unreadable claims remain occupied; never allocate from uncertain ownership.
                Err(e) => warn!(path = %path.display(), error = %e,
                                "unreadable claim; treating the namespace as assigned"),
            }
        }
        Ok(None)
    }

    /// Claim the controller-assigned namespace locally or report an ownership conflict.
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
        // Resolve a competing claim creation as an idempotent retry or an ownership conflict.
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

    /// Choose an available namespace when local allocation is enabled.
    /// Exclusive file creation arbitrates competing claims in this state directory.
    fn choose_one(
        &self,
        id: &VolumeId,
        params: &ImportPoolParams,
        size_bytes: u64,
    ) -> agent_api::storage::Result<VolumeHandle> {
        for ns in &params.namespaces {
            // Assign only namespaces large enough for the request. Imports expose
            // the whole namespace and do not repartition it.
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
            // Sync claim contents before returning the handle.
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

/// Build an imported-volume handle with the NQN as backend name and target
/// connection parameters for the independent attacher.
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

    /// Pool fixture permitting node-local allocation.
    fn pool(namespaces: &[(&str, u64)]) -> ImportPoolParams {
        ImportPoolParams {
            allow_local_claims: true,
            ..cluster_pool(namespaces)
        }
    }

    /// Pool fixture requiring controller-supplied namespace assignment.
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

    /// Allocate once per volume, reuse on retry and report exhaustion.
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

    /// Skip undersized namespaces and expose larger ones in full.
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

    /// Imported data cannot be initialized from a base image.
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

    /// Check sanitized claim filenames and stored namespace identity.
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

    /// Honor the controller's namespace assignment and reject collisions, invalid
    /// assignments and attempts to move an existing local claim.
    #[tokio::test]
    async fn the_namespace_comes_from_the_cluster_and_this_node_takes_what_it_is_given() {
        let (_temp, state) = dir();
        let d = driver(&state);
        let names = [("nqn.test:one", 100), ("nqn.test:two", 100)];
        let one = uuid::Uuid::new_v4();
        let two = uuid::Uuid::new_v4();

        // Honor the assigned namespace instead of choosing the first pool entry.
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

        // Repeat assignment returns the existing claim.
        let again = d
            .provision(&one, &spec(&assigned(&names, "nqn.test:two"), 1 << 30))
            .await
            .expect("the same one");
        assert_eq!(again.backend, "nqn.test:two");

        // Conflicting local ownership reports both volume IDs.
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

        // Reject changing an existing claim to another namespace.
        let moved = d
            .provision(&one, &spec(&assigned(&names, "nqn.test:one"), 1 << 30))
            .await
            .expect_err("not this driver's to make");
        let moved = format!("{moved:#}");
        assert!(moved.contains("nqn.test:one"), "{moved}");
        assert!(moved.contains("nqn.test:two"), "{moved}");

        let _ = std::fs::remove_dir_all(&state);
    }

    /// Refuse unassigned shared-pool requests unless allow_local_claims explicitly enables local choice.
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

        // The opt-in local pool permits node-side allocation.
        let mine = d
            .provision(&id, &spec(&pool(&names), 1 << 30))
            .await
            .expect("a pool only this node can reach");
        assert_eq!(mine.backend, "nqn.test:one");
        let _ = std::fs::remove_dir_all(&state);
    }
}
