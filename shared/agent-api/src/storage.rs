// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Storage as the agent sees it: a volume is created for one VM, lives as
//! long as that VM's record, and reaches the VMM as an attachment.
//!
//! # Where this form ends
//!
//! A volume here has no life of its own. It is named inside a VM spec, it is
//! created by the node the VM was scheduled onto, and `destroy` runs when
//! that VM is torn down — there is no `Volume` object in etcd, nothing to
//! attach to a second VM, and nothing that survives the node. That is the
//! whole of what this file models, deliberately: every backend below it
//! (files, LVM-thin, a share) is local to the node, so a volume that outlived
//! its node would be a promise the storage cannot keep.
//!
//! The next form is the one Mayastor and SPDK are built for: a Volume as a
//! first-class resource with its own lifecycle, replicated across storage
//! nodes, attached and detached over a network protocol (NVMe-oF, iSCSI) and
//! served into the guest by a vhost-user-blk backend. The seam for it is
//! already here and is exactly one variant wide: `VhostUserBlk` is what such
//! a backend hands over, and `needs_shared_memory` is the one thing the
//! hypervisor has to be told about it. What is missing is above this file —
//! a Volume resource, a scheduler that places replicas, a controller that
//! attaches a volume to a node rather than creating one on it.
//!
//! Until that exists, this is enough, and it is enough for a reason worth
//! writing down: a VM's disk lives where the VM runs, so a node that is up
//! can always start its own VMs, and a node that is gone takes nothing with
//! it that another node was relying on. Live migration is what first needs
//! more than that, and it is what should force the change.

use uuid::Uuid;

use crate::CgroupHandle;

pub type VolumeId = Uuid;

#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    #[error("volume not found: {0}")]
    NotFound(VolumeId),
    #[error("base image not found: {0}")]
    ImageNotFound(String),
    #[error("invalid volume spec: {0}")]
    InvalidSpec(String),
    /// A backend process (virtiofsd, a vhost-user-blk daemon) died or never
    /// came up. Separate from `Backend` for the same reason `DeviceError`
    /// separates it: it names a process, and the message carries its log.
    #[error("storage backend process died: {0}")]
    BackendDied(String),
    #[error("storage backend failure: {0}")]
    Backend(anyhow::Error),
}

pub type Result<T> = std::result::Result<T, StorageError>;

/// What the guest is asked for. `driver` and `params` are the same two fields
/// a device spec carries, and for the same reason: the agent routes on the
/// driver name and hands the params through untouched, so a backend can take
/// options nothing between here and it has to know about.
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

/// The default when a spec names no driver — the mirror of
/// `device::default_device_driver`, and the reason today's specs stay valid.
///
/// The string itself lives in `common::capability` because the scheduler one
/// tier up needs the same one: a volume asking for the default constrains
/// nothing, and the two halves saying that differently would strand VMs.
pub fn default_volume_driver() -> String {
    common::capability::DEFAULT_VOLUME_DRIVER.to_string()
}

/// How the created volume reaches the VMM. The mirror image of
/// `DeviceAttachment`: either the host hands over something the hypervisor can
/// open by path, or a backend process is speaking vhost-user and what is
/// handed over is its socket.
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
    /// A virtiofs export: virtiofsd speaks vhost-user-fs on `socket`, and the
    /// guest mounts it with `mount -t virtiofs <tag> …`. Needs shared memory
    /// like every vhost-user attachment.
    ///
    /// Not a block device, and the one place that matters is the VMM config:
    /// this is a `fs` entry, not a disk, so `is_block` is what the two call
    /// sites that care ask rather than matching the variant themselves.
    FsShare {
        socket: std::path::PathBuf,
        tag: String,
        pid: u32,
    },
}

impl VolumeAttachment {
    /// Whether this attachment needs the guest's memory to be shareable. One
    /// named predicate, because the answer has to be the same for volumes and
    /// devices and the hypervisor driver asks it of both.
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

    /// The pid of the backend process serving this volume, if there is one.
    ///
    /// The mirror of the match the reconciler runs over device attachments,
    /// and it exists so that liveness is asked the same way of both halves of
    /// a VM: a backend that is no longer in the VM's cgroup slice is a dead
    /// backend, whether it was serving a GPU or a share.
    pub fn backend_pid(&self) -> Option<u32> {
        match self {
            VolumeAttachment::Path(_) => None,
            VolumeAttachment::VhostUserBlk { pid, .. } | VolumeAttachment::FsShare { pid, .. } => {
                Some(*pid)
            }
        }
    }
}

/// A created volume, as the record remembers it.
///
/// Read through `VolumeRepr` so that records written before volumes had an
/// attachment kind still load: a bare `path` was the only thing a volume
/// could be then, and it means `Path` now. Written in the current shape
/// always — one restart migrates the store, and nothing has to be told to.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(from = "VolumeRepr")]
pub struct Volume {
    pub id: VolumeId,
    pub attachment: VolumeAttachment,
    pub size_bytes: u64,
}

#[derive(serde::Deserialize)]
#[serde(untagged)]
enum VolumeRepr {
    Current {
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
        match repr {
            VolumeRepr::Current {
                id,
                attachment,
                size_bytes,
            } => Volume {
                id,
                attachment,
                size_bytes,
            },
            VolumeRepr::Legacy {
                id,
                path,
                size_bytes,
            } => Volume {
                id,
                attachment: VolumeAttachment::Path(path),
                size_bytes,
            },
        }
    }
}

/// The storage backend behind a volume.
///
/// Shaped like `DeviceDriver`, and for the reasons that trait states: a
/// backend process belongs in the VM's cgroup slice from the moment it is
/// spawned (`cgroup`), and teardown has to reach a backend the agent did not
/// itself start (`attachment`, read back off the record after a restart). A
/// driver that spawns nothing ignores both.
#[async_trait::async_trait]
pub trait BlockDriver: Send + Sync {
    async fn create(
        &self,
        id: &VolumeId,
        spec: &VolumeSpec,
        cgroup: Option<&CgroupHandle>,
    ) -> Result<Volume>;

    /// Destroy the volume AND its data. Must be idempotent: destroying an
    /// already-gone volume is Ok.
    async fn destroy(&self, id: &VolumeId, attachment: &VolumeAttachment) -> Result<()>;

    /// Liveness probe: Ok if the volume behind this attachment is still
    /// present and usable, NotFound otherwise.
    async fn get(&self, id: &VolumeId, attachment: &VolumeAttachment) -> Result<Volume>;

    /// Stop the backend process serving this volume, keeping the data.
    ///
    /// What `stop` needs and `destroy` is too much for: a stopped VM keeps
    /// its volumes but must not keep a virtiofsd running for a VM that is not
    /// there. A driver whose volumes are plain paths has no process to stop
    /// and says so by doing nothing.
    async fn detach(&self, id: &VolumeId, attachment: &VolumeAttachment) -> Result<()> {
        let _ = (id, attachment);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The whole point of the serde defaults: a spec written before storage
    /// had a driver field means exactly what it meant.
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

    /// A record from before the attachment split still loads, and loads as
    /// what it was: a path. Without this the agent's store would drop the
    /// record on the next restart — `Store::list` skips what it cannot decode
    /// — and the VM would go on running with nobody left who knows about it.
    #[test]
    fn a_pre_attachment_record_loads_as_a_path() {
        let legacy = r#"{"id":"00000000-0000-0000-0000-000000000001",
                         "path":"/var/lib/meister/volumes/x.raw","size_bytes":42}"#;
        let vol: Volume = serde_json::from_str(legacy).expect("legacy record loads");
        assert_eq!(vol.size_bytes, 42);
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
        // and the current shape reads back unchanged
        let again: Volume = serde_json::from_value(round).unwrap();
        assert!(matches!(again.attachment, VolumeAttachment::Path(_)));
    }

    #[test]
    fn a_vhost_user_volume_round_trips_and_asks_for_shared_memory() {
        let vol = Volume {
            id: Uuid::nil(),
            attachment: VolumeAttachment::VhostUserBlk {
                socket: "/run/blk.sock".into(),
                pid: 7,
            },
            size_bytes: 1,
        };
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

    /// The third form, through the same untagged migration the other two go
    /// through. `VolumeRepr::Current` carries it because it carries whatever
    /// `VolumeAttachment` is — which is the whole reason the enum extension
    /// is not a store break.
    #[test]
    fn a_share_round_trips_through_the_migrating_repr() {
        let vol = Volume {
            id: Uuid::nil(),
            attachment: VolumeAttachment::FsShare {
                socket: "/run/fs.sock".into(),
                tag: "share".into(),
                pid: 11,
            },
            size_bytes: 0,
        };
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

    /// A share is a vhost-user backend, so the VM's memory has to be
    /// shareable; and it is not a disk, so it has no business in the disk
    /// list. Both answers come from here rather than from a match at each
    /// call site.
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
}
