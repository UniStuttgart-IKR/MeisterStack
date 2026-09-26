// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Storage provisioning and attachment contracts.
//!
//! [`VolumeProvider`] owns persistent data; [`VolumeAttacher`] owns the consumer
//! connection and any backend process assigned to the VM's cgroup. Drivers may
//! implement both traits, including when both operations occur on the same node.
//!
//! A volume handle supports at most one live attachment (read-write-once).
//! Detaching a consumer must not delete its volume. Inline VM disks and separate
//! Volume resources use these same operations with different lifecycle owners;
//! see `docs/RESOURCE_LIFECYCLE.md` for agent cleanup guarantees.

use uuid::Uuid;

use crate::CgroupHandle;

pub type VolumeId = Uuid;

/// Snapshot identity supplied from the VolumeSnapshot UID. This UUID alias
/// documents intent but is not type-distinct from VolumeId.
pub type SnapshotId = Uuid;

/// Storage locality shared with scheduling through common::capability;
/// drivers declare it through `VolumeProvider::locality`.
pub use common::capability::Locality;

#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    #[error("volume not found: {0}")]
    NotFound(VolumeId),
    #[error("base image not found: {0}")]
    ImageNotFound(String),
    #[error("invalid volume spec: {0}")]
    InvalidSpec(String),
    /// Backend process startup or exit failure, with diagnostic log text.
    #[error("storage backend process died: {0}")]
    BackendDied(String),
    /// Operation unsupported by this backend, distinct from an attempted operation failing.
    #[error("this backend cannot do that: {0}")]
    Unsupported(String),
    #[error("storage backend failure: {0}")]
    Backend(anyhow::Error),
}

/// Snapshot consistency shared with controllers through capability claims.
/// Drivers report whether copying needs quiesced writers.
pub use common::capability::SnapshotConsistency;

pub type Result<T> = std::result::Result<T, StorageError>;

/// Volume provisioning request. The agent selects driver and forwards
/// driver-specific parameters for backend validation.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct VolumeSpec {
    pub base_image: Option<String>,
    pub size_bytes: u64,
    /// None = the default driver, `filesystem`. A serde default rather than a
    /// required field on purpose: every spec written before storage had more
    /// than one backend goes on meaning what it meant.
    #[serde(default)]
    pub driver: Option<String>,
    #[serde(default)]
    pub params: Option<serde_json::Value>,
}

/// Default volume driver name shared with scheduler capability matching.
pub fn default_volume_driver() -> String {
    common::capability::DEFAULT_VOLUME_DRIVER.to_string()
}

/// Consumer connection to volume data: local path, vhost-user block backend
/// or virtiofs export.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub enum VolumeAttachment {
    /// Block device or file on the host (filesystem, LVM-thin, NFS).
    Path(std::path::PathBuf),
    /// vhost-user-blk socket of a storage backend process (SPDK/Mayastor
    /// style). `memory.shared` follows, exactly as it does for devices — the
    /// backend maps guest memory, and it cannot map what is not shared.
    VhostUserBlk {
        socket: std::path::PathBuf,
        pid: u32,
    },
    /// Virtiofs export mounted by the guest using tag. Requires shared memory
    /// and a VMM filesystem entry rather than a block-disk entry.
    FsShare {
        socket: std::path::PathBuf,
        tag: String,
        pid: u32,
    },
}

impl VolumeAttachment {
    /// Whether the attachment requires shared guest memory.
    pub fn needs_shared_memory(&self) -> bool {
        matches!(
            self,
            VolumeAttachment::VhostUserBlk { .. } | VolumeAttachment::FsShare { .. }
        )
    }

    /// Whether this attachment is a block device the guest can boot from.
    /// A share is a filesystem export and appears nowhere near the disk list.
    pub fn is_block(&self) -> bool {
        !matches!(self, VolumeAttachment::FsShare { .. })
    }

    /// Optional backend PID for attachment liveness and cgroup membership checks.
    pub fn backend_pid(&self) -> Option<u32> {
        match self {
            VolumeAttachment::Path(_) => None,
            VolumeAttachment::VhostUserBlk { pid, .. } | VolumeAttachment::FsShare { pid, .. } => {
                Some(*pid)
            }
        }
    }
}

/// Provisioned data identified independently of a consumer. The handle
/// supports inspection and deletion without a live attachment.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct VolumeHandle {
    /// The control plane's name for the volume.
    pub id: VolumeId,
    /// Provider-specific location or identifier. Derive it from the volume ID
    /// so retries after lost replies recover the same data rather than allocate again.
    pub backend: String,
    pub size_bytes: u64,
    /// Driver parameters retained for independent attachment, including options
    /// such as the virtiofs tag that describe the connection.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub params: Option<serde_json::Value>,
}

impl VolumeHandle {
    /// `backend` as a path, for the backends whose name for a volume is one.
    pub fn path(&self) -> std::path::PathBuf {
        std::path::PathBuf::from(&self.backend)
    }
}

/// Measured state of an existing volume. Absence is reported as StorageError::NotFound.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct VolumeState {
    pub size_bytes: u64,
}

/// Persisted provider handle and consumer attachment. Legacy bare-path
/// and attachment-only records deserialize through `VolumeRepr`; subsequent
/// writes use the current shape.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(from = "VolumeRepr")]
pub struct Volume {
    pub handle: VolumeHandle,
    pub attachment: VolumeAttachment,
    /// Whether detach already succeeded. Persist this across stop/restart
    /// to avoid acting again on a stale attachment PID. The attachment remains
    /// for provider cleanup and path recovery. Legacy records default to false.
    #[serde(default)]
    pub detached: bool,
}

impl Volume {
    /// Construct an attachment whose connection has not been released.
    pub fn attached(handle: VolumeHandle, attachment: VolumeAttachment) -> Self {
        Self {
            handle,
            attachment,
            detached: false,
        }
    }
}

impl Volume {
    pub fn id(&self) -> VolumeId {
        self.handle.id
    }

    pub fn size_bytes(&self) -> u64 {
        self.handle.size_bytes
    }
}

#[derive(serde::Deserialize)]
#[serde(untagged)]
enum VolumeRepr {
    Current {
        handle: VolumeHandle,
        attachment: VolumeAttachment,
        #[serde(default)]
        detached: bool,
    },
    /// Records from before provisioning and attaching came apart: one
    /// attachment, and whatever the backend had made behind it left unsaid.
    Attached {
        id: VolumeId,
        attachment: VolumeAttachment,
        size_bytes: u64,
    },
    /// Pre-attachment records, from the agent's redb store.
    Legacy {
        id: VolumeId,
        path: std::path::PathBuf,
        size_bytes: u64,
    },
}

impl From<VolumeRepr> for Volume {
    fn from(repr: VolumeRepr) -> Self {
        // Recover the backend path from legacy path attachments. LVM teardown
        // needs it to identify the VG; other current backends derive names from IDs.
        let migrate = |id, attachment: VolumeAttachment, size_bytes| Volume {
            // A record from before the flag existed was written by a stop
            // that did not mark anything, so nothing on it had been given
            // back: `false` is the migration and also the truth.
            detached: false,
            handle: VolumeHandle {
                id,
                backend: match &attachment {
                    VolumeAttachment::Path(p) => p.to_string_lossy().into_owned(),
                    _ => String::new(),
                },
                size_bytes,
                // The spec is where params come from, and a re-provision reads
                // it again. Nothing on the teardown path wants them.
                params: None,
            },
            attachment,
        };
        match repr {
            VolumeRepr::Current {
                handle,
                attachment,
                detached,
            } => Volume {
                handle,
                attachment,
                detached,
            },
            VolumeRepr::Attached {
                id,
                attachment,
                size_bytes,
            } => migrate(id, attachment, size_bytes),
            VolumeRepr::Legacy {
                id,
                path,
                size_bytes,
            } => migrate(id, VolumeAttachment::Path(path), size_bytes),
        }
    }
}

/// Persistent-data operations independent of consumers. Backend processes
/// serving a VM belong to VolumeAttacher and its consumer cgroup.
#[async_trait::async_trait]
pub trait VolumeProvider: Send + Sync {
    /// Provision idempotently by ID. If creation succeeded but its handle was
    /// lost, retries must recover the existing volume rather than allocate another.
    async fn provision(&self, id: &VolumeId, spec: &VolumeSpec) -> Result<VolumeHandle>;

    /// Destroy volume data without requiring an attachment. Already absent volumes succeed.
    async fn deprovision(&self, handle: &VolumeHandle) -> Result<()>;

    /// Inspect persistent data without a consumer; absent data returns NotFound.
    async fn describe(&self, handle: &VolumeHandle) -> Result<VolumeState>;

    /// Find provisioned bytes by ID without relying on a saved handle.
    ///
    /// Return a deprovisionable handle when present, or None only when absent.
    /// A crash or failed provision can leave backend data before the agent saves
    /// its handle; a missing handle is therefore not proof of absence. Each
    /// backend must implement this lookup explicitly.
    async fn probe(&self, id: &VolumeId, spec: &VolumeSpec) -> Result<Option<VolumeHandle>>;

    /// Report the backend's locality: NodeLocal, Shared or Networked.
    ///
    /// This is a driver property, not an operator claim on a pool. Implementors
    /// must choose explicitly because placement depends on the answer.
    fn locality(&self) -> Locality;

    // Provider operations act on persistent data without requiring a consumer.
    // Unsupported snapshot operations default to explicit refusal.

    /// Grow to at least `size_bytes`; never shrink. Repeated requests at the
    /// current size must succeed. The provider grows data even without a VMM;
    /// hypervisor resize separately informs an attached guest. Default: Unsupported.
    async fn resize(&self, handle: &VolumeHandle, size_bytes: u64) -> Result<VolumeHandle> {
        let _ = (handle, size_bytes);
        Err(StorageError::Unsupported("resize".into()))
    }

    /// Advertised snapshot support and consistency requirements. None omits
    /// the snapshot capability from this driver's catalogue entry.
    fn snapshot_support(&self) -> Option<SnapshotConsistency> {
        None
    }

    /// Create an ID-addressed snapshot and return its handle. Retries with
    /// the same ID must find the existing snapshot. Consistency follows the
    /// backend's advertised requirements.
    async fn snapshot(&self, handle: &VolumeHandle, id: &SnapshotId) -> Result<VolumeHandle> {
        let _ = (handle, id);
        Err(StorageError::Unsupported("snapshot".into()))
    }

    /// Destroy a snapshot and its data. Idempotent: one that is already gone
    /// is `Ok`.
    async fn drop_snapshot(&self, handle: &VolumeHandle) -> Result<()> {
        let _ = handle;
        Err(StorageError::Unsupported("drop_snapshot".into()))
    }

    /// Find a snapshot without its saved handle. `volume` identifies the
    /// source backend when required, notably the LVM volume group.
    ///
    /// A backend without snapshot support returns None. A snapshot-capable
    /// backend without a probe implementation returns Unsupported, so missing
    /// probe support cannot authorize deletion of its persistent record.
    async fn probe_snapshot(
        &self,
        volume: Option<&VolumeHandle>,
        id: &SnapshotId,
    ) -> Result<Option<VolumeHandle>> {
        let _ = (volume, id);
        match self.snapshot_support() {
            None => Ok(None),
            Some(_) => Err(StorageError::Unsupported("probe_snapshot".into())),
        }
    }

    /// Create a writable volume from a snapshot handle. Requested size must
    /// be at least the snapshot size; reject unknown or invalid size requirements.
    /// The backend may clone or copy according to its capabilities.
    async fn provision_from(
        &self,
        id: &VolumeId,
        snapshot: &VolumeHandle,
        spec: &VolumeSpec,
    ) -> Result<VolumeHandle> {
        let _ = (id, snapshot, spec);
        Err(StorageError::Unsupported("provision_from".into()))
    }

    /// Release node-local bookkeeping without deleting volume data.
    ///
    /// Used after ownership moves elsewhere. Unlike `deprovision`, this may
    /// remove claims such as nvmeof-import reservations but must preserve the
    /// underlying bytes. Idempotent; absent claims succeed. The default has no
    /// bookkeeping to release.
    async fn forget(&self, handle: &VolumeHandle) -> Result<()> {
        let _ = handle;
        Ok(())
    }
}

/// Own consumer connections and their backend processes. Processes belong
/// in the consumer's cgroup from spawn. The handle identifies one RWO
/// attachment; multi-attach would require distinct identities and reference counts.
#[async_trait::async_trait]
pub trait VolumeAttacher: Send + Sync {
    /// Make the volume reachable, and say how.
    async fn attach(
        &self,
        handle: &VolumeHandle,
        cgroup: Option<&CgroupHandle>,
    ) -> Result<VolumeAttachment>;

    /// Release the consumer connection while preserving volume data. The default
    /// does nothing, suitable for attachments without connection resources.
    async fn detach(&self, handle: &VolumeHandle, attachment: &VolumeAttachment) -> Result<()> {
        let _ = (handle, attachment);
        Ok(())
    }

    /// Check attachment usability, distinct from provider-side data existence.
    /// An unavailable backend process can make the connection NotFound while its data remains.
    async fn stat(
        &self,
        handle: &VolumeHandle,
        attachment: &VolumeAttachment,
    ) -> Result<VolumeState>;
}

/// Combined provider/attacher contract used by the agent registry.
/// A single shared instance supplies both capabilities.
pub trait VolumeDriver: VolumeProvider + VolumeAttacher {}

impl<T: VolumeProvider + VolumeAttacher + ?Sized> VolumeDriver for T {}

#[cfg(test)]
mod tests {
    use super::*;

    /// A volume as a record holds it: provisioned somewhere, attached here.
    fn attached(attachment: VolumeAttachment, size_bytes: u64) -> Volume {
        Volume {
            handle: VolumeHandle {
                id: Uuid::nil(),
                backend: "/backend/name".to_string(),
                size_bytes,
                params: None,
            },
            attachment,
            detached: false,
        }
    }

    /// Legacy specs without driver fields retain their defaults.
    #[test]
    fn a_spec_without_a_driver_is_still_a_valid_spec() {
        let spec: VolumeSpec = serde_json::from_str(r#"{"base_image":"a.raw","size_bytes":10}"#)
            .expect("today's spec parses");
        assert_eq!(spec.driver, None);
        assert_eq!(spec.params, None);
        assert_eq!(default_volume_driver(), "filesystem");
    }

    #[test]
    fn a_spec_may_name_a_driver_and_hand_it_params() {
        let spec: VolumeSpec = serde_json::from_str(
            r#"{"base_image":null,"size_bytes":1,"driver":"lvm-thin","params":{"pool":"vg0/thin"}}"#,
        )
        .unwrap();
        assert_eq!(spec.driver.as_deref(), Some("lvm-thin"));
        assert_eq!(spec.params.unwrap()["pool"], "vg0/thin");
    }

    /// Decode legacy path-only volume records without losing persisted ownership.
    #[test]
    fn a_pre_attachment_record_loads_as_a_path() {
        let legacy = r#"{"id":"00000000-0000-0000-0000-000000000001",
                         "path":"/var/lib/meister/volumes/x.raw","size_bytes":42}"#;
        let vol: Volume = serde_json::from_str(legacy).expect("legacy record loads");
        assert_eq!(vol.size_bytes(), 42);
        assert_eq!(vol.handle.backend, "/var/lib/meister/volumes/x.raw");
        match vol.attachment {
            VolumeAttachment::Path(p) => {
                assert_eq!(
                    p,
                    std::path::PathBuf::from("/var/lib/meister/volumes/x.raw")
                )
            }
            other => panic!("legacy path became {other:?}"),
        }
    }

    /// And it is written back in the new shape, so one restart migrates the
    /// store without anything having to be told to.
    #[test]
    fn a_loaded_record_is_written_back_in_the_current_shape() {
        let legacy = r#"{"id":"00000000-0000-0000-0000-000000000001",
                         "path":"/x.raw","size_bytes":42}"#;
        let vol: Volume = serde_json::from_str(legacy).unwrap();
        let round: serde_json::Value = serde_json::to_value(&vol).unwrap();
        assert_eq!(round["attachment"]["Path"], "/x.raw");
        assert!(round.get("path").is_none());
        assert!(
            round.get("size_bytes").is_none(),
            "it lives on the handle now"
        );
        assert_eq!(round["handle"]["backend"], "/x.raw");
        // and the current shape reads back unchanged
        let again: Volume = serde_json::from_value(round).unwrap();
        assert!(matches!(again.attachment, VolumeAttachment::Path(_)));
        assert_eq!(again.size_bytes(), 42);
    }

    #[test]
    fn a_vhost_user_volume_round_trips_and_asks_for_shared_memory() {
        let vol = attached(
            VolumeAttachment::VhostUserBlk {
                socket: "/run/blk.sock".into(),
                pid: 7,
            },
            1,
        );
        assert!(vol.attachment.needs_shared_memory());
        let json = serde_json::to_string(&vol).unwrap();
        let back: Volume = serde_json::from_str(&json).unwrap();
        match back.attachment {
            VolumeAttachment::VhostUserBlk { socket, pid } => {
                assert_eq!(socket, std::path::PathBuf::from("/run/blk.sock"));
                assert_eq!(pid, 7);
            }
            other => panic!("{other:?}"),
        }
        assert!(!VolumeAttachment::Path("/x".into()).needs_shared_memory());
    }

    /// Round-trip filesystem shares through the current persisted volume representation.
    #[test]
    fn a_share_round_trips_through_the_migrating_repr() {
        let vol = attached(
            VolumeAttachment::FsShare {
                socket: "/run/fs.sock".into(),
                tag: "share".into(),
                pid: 11,
            },
            0,
        );
        let json = serde_json::to_string(&vol).unwrap();
        let back: Volume = serde_json::from_str(&json).unwrap();
        match back.attachment {
            VolumeAttachment::FsShare { socket, tag, pid } => {
                assert_eq!(socket, std::path::PathBuf::from("/run/fs.sock"));
                assert_eq!(tag, "share");
                assert_eq!(pid, 11);
            }
            other => panic!("{other:?}"),
        }
    }

    /// Convert legacy attachment records into handles retaining the backend path
    /// needed for later deletion, including LVM volume-group lookup.
    #[test]
    fn a_pre_handle_record_loads_and_keeps_the_path_its_backend_needs() {
        let attached = r#"{"id":"00000000-0000-0000-0000-000000000001",
                           "attachment":{"Path":"/dev/vg0/vm-x"},
                           "size_bytes":4096}"#;
        let vol: Volume = serde_json::from_str(attached).expect("a pre-handle record loads");
        assert_eq!(vol.handle.backend, "/dev/vg0/vm-x");
        assert_eq!(vol.size_bytes(), 4096);
        assert!(vol.handle.params.is_none());
        assert_eq!(vol.handle.path(), std::path::PathBuf::from("/dev/vg0/vm-x"));
    }

    /// Legacy share records need no invented backend path because the share
    /// directory is derived from the volume ID.
    #[test]
    fn a_migrated_share_record_keeps_no_path_and_needs_none() {
        let attached = r#"{"id":"00000000-0000-0000-0000-000000000001",
                           "attachment":{"FsShare":{"socket":"/run/x.sock",
                                                    "tag":"share","pid":11}},
                           "size_bytes":0}"#;
        let vol: Volume = serde_json::from_str(attached).unwrap();
        assert!(vol.handle.backend.is_empty());
        assert_eq!(
            vol.id(),
            Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap()
        );
        assert!(vol.attachment.backend_pid() == Some(11));
    }

    /// Round-trip volume handles independently of attachments.
    #[test]
    fn a_handle_round_trips_without_an_attachment_anywhere_in_it() {
        let handle = VolumeHandle {
            id: Uuid::nil(),
            backend: "/dev/vg0/vm-x".into(),
            size_bytes: 8,
            params: Some(serde_json::json!({"kind": "share", "tag": "data"})),
        };
        let json = serde_json::to_value(&handle).unwrap();
        assert!(json.get("attachment").is_none());
        let back: VolumeHandle = serde_json::from_value(json).unwrap();
        assert_eq!(back.backend, "/dev/vg0/vm-x");
        assert_eq!(back.params.unwrap()["tag"], "data");

        // No params is the ordinary case and must not become `null` on disk.
        let plain = VolumeHandle {
            id: Uuid::nil(),
            backend: "/x.raw".into(),
            size_bytes: 1,
            params: None,
        };
        let json = serde_json::to_value(&plain).unwrap();
        assert!(json.get("params").is_none());
        assert!(
            serde_json::from_value::<VolumeHandle>(json)
                .unwrap()
                .params
                .is_none()
        );
    }

    /// Filesystem shares require shared memory and are not block devices.
    #[test]
    fn a_share_needs_shared_memory_and_is_not_a_block_device() {
        let share = VolumeAttachment::FsShare {
            socket: "/run/fs.sock".into(),
            tag: "share".into(),
            pid: 11,
        };
        assert!(share.needs_shared_memory());
        assert!(!share.is_block());
        assert!(VolumeAttachment::Path("/a.raw".into()).is_block());
        assert!(
            VolumeAttachment::VhostUserBlk {
                socket: "/s".into(),
                pid: 1
            }
            .is_block()
        );
    }

    /// Liveness is asked of a volume exactly as it is asked of a device: a
    /// pid, or nothing to ask about.
    #[test]
    fn only_a_backend_served_volume_has_a_pid() {
        assert_eq!(VolumeAttachment::Path("/a.raw".into()).backend_pid(), None);
        assert_eq!(
            VolumeAttachment::VhostUserBlk {
                socket: "/s".into(),
                pid: 9
            }
            .backend_pid(),
            Some(9)
        );
        assert_eq!(
            VolumeAttachment::FsShare {
                socket: "/s".into(),
                tag: "t".into(),
                pid: 11
            }
            .backend_pid(),
            Some(11)
        );
    }

    /// Unsupported snapshot operations return the typed Unsupported error;
    /// capability discovery also reports no snapshot support.
    #[tokio::test]
    async fn a_backend_that_says_nothing_about_snapshots_cannot_take_one() {
        struct Plain;

        #[async_trait::async_trait]
        impl VolumeProvider for Plain {
            fn locality(&self) -> Locality {
                Locality::NodeLocal
            }
            async fn provision(&self, id: &VolumeId, spec: &VolumeSpec) -> Result<VolumeHandle> {
                Ok(VolumeHandle {
                    id: *id,
                    backend: format!("/plain/{id}"),
                    size_bytes: spec.size_bytes,
                    params: None,
                })
            }
            async fn deprovision(&self, _: &VolumeHandle) -> Result<()> {
                Ok(())
            }
            async fn describe(&self, h: &VolumeHandle) -> Result<VolumeState> {
                Ok(VolumeState {
                    size_bytes: h.size_bytes,
                })
            }
            async fn probe(&self, _: &VolumeId, _: &VolumeSpec) -> Result<Option<VolumeHandle>> {
                Ok(None)
            }
        }

        let plain = Plain;
        assert!(plain.snapshot_support().is_none());
        // A backend that cannot snapshot holds no snapshots, so the default
        // `probe_snapshot` is the honest `None` rather than a refusal — see
        // Astra finding S13, 2026-09-23.
        assert!(
            plain
                .probe_snapshot(None, &Uuid::nil())
                .await
                .expect("a backend with no snapshots answers")
                .is_none()
        );

        let handle = VolumeHandle {
            id: Uuid::nil(),
            backend: "/plain/x".into(),
            size_bytes: 1,
            params: None,
        };
        let spec = VolumeSpec {
            base_image: None,
            size_bytes: 1,
            driver: None,
            params: None,
        };
        for refusal in [
            plain.snapshot(&handle, &Uuid::nil()).await.err(),
            plain.drop_snapshot(&handle).await.err(),
            plain
                .provision_from(&Uuid::nil(), &handle, &spec)
                .await
                .err(),
        ] {
            let e = refusal.expect("a backend that cannot, refusing");
            assert!(
                matches!(e, StorageError::Unsupported(_)),
                "the variant is what the tier above branches on: {e:?}"
            );
        }

        // Snapshot consistency values round-trip through the shared wire spellings.
        for c in [
            SnapshotConsistency::Atomic,
            SnapshotConsistency::NeedsQuiesce,
        ] {
            assert_eq!(SnapshotConsistency::parse(c.as_str()), Some(c));
        }
        assert_eq!(SnapshotConsistency::Atomic.as_str(), "atomic");
        assert_eq!(SnapshotConsistency::NeedsQuiesce.as_str(), "needs-quiesce");
        assert_eq!(SnapshotConsistency::parse("maybe"), None);
    }
}
